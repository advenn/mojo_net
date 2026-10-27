"""`Document`: JSON text parsed into one flat tree, and `parse`, which
builds it, strictly (RFC 8259):

- one value, with optional whitespace (space, tab, LF, CR) around it and
  nothing else: no byte order mark, comments, trailing commas, single
  quotes, NaN or Infinity;
- numbers in RFC 8259's grammar only (no leading zeros, `+`, `.5` or
  `5.`), kept as their text and read on demand;
- strings in UTF-8 (RFC 3629, strictly: no overlong forms, no encoded
  surrogates), with no control characters; the escapes are the eight
  short ones and `\\uXXXX`, a surrogate pair joined into one character;
  a lone surrogate is refused, since UTF-8 cannot hold it;
- no key twice in one object (RFC 8259 leaves the meaning open, and
  parsers that disagree on it disagree on what a document says);
- the input's size and the nesting depth under `Limits`. The parser keeps
  its own stack, so no depth can overflow the call stack. A document
  takes up to about 7 times its input in memory (12 bytes a node, and a
  node can be 2 input bytes, `0,`), so the size limit bounds memory too.

Nodes are numbered in pre-order: the root is 0, and each array's or
object's members follow it, each with its own. An object's members are
pairs of nodes, the key (a string) then the value. The accessors take a
node's number (`n`, the root by default); one out of range raises
MISSING, and one of another kind TYPE.
- **Navigation:** `count(n)` is an array's length or an object's number
  of pairs; `child(n, k)` the number of array element `k`; `key(n, i)` and
  `val(n, i)` an object's pair `i`; `get(n, key)` (None when absent) and
  `member(n, key)` (MISSING when absent) the value for a key; `next(n)`
  the node after `n` and everything in it (its next sibling, if any).
- **Scalars:** `text(n)` and `view(n)` for strings, and numbers as their
  text; `int(n)` for numbers written as integers that fit an Int;
  `float(n)` for any number, correctly rounded; `bool(n)`; `is_null(n)`.
- **Output:** `json(n)` and `write_json(n, out)`: a node as compact JSON
  text, numbers as written in the input.

To walk an array: `var c = doc.child(n, 0)`, then `c = doc.next(c)`; an
object: key `c = n + 1`, its value `c + 1`, the next key `doc.next(c + 1)`.
"""

from std.collections import Optional
from std.sys import get_defined_bool

from .error import JsonError
from .siphash import siphash13
from .text import plain_run, utf8_length, write_quoted

comptime DEFAULT_MAX_DEPTH = 128
comptime DEFAULT_MAX_SIZE = 64 * 1024 * 1024
comptime MAX_SIZE = (1 << 31) - 1
"""The largest input any `Limits` allows (nodes keep 32-bit offsets)."""

comptime _NULL: UInt8 = 0
comptime _FALSE: UInt8 = 1
comptime _TRUE: UInt8 = 2
comptime _INT: UInt8 = 3
"""A number written as an integer: no fraction, no exponent."""
comptime _NUM: UInt8 = 4
comptime _STR: UInt8 = 5
comptime _ARR: UInt8 = 6
comptime _OBJ: UInt8 = 7

comptime _QUOTE: UInt8 = 34
comptime _BACKSLASH: UInt8 = 92
comptime _COMMA: UInt8 = 44
comptime _COLON: UInt8 = 58
comptime _LBRACKET: UInt8 = 91
comptime _RBRACKET: UInt8 = 93
comptime _LBRACE: UInt8 = 123
comptime _RBRACE: UInt8 = 125
comptime _MINUS: UInt8 = 45

comptime _PAIRWISE = 16
"""Objects with at most this many pairs are checked for a repeated key
pair by pair; larger ones through their keys' hashes."""

comptime _BUCKETED = 16384
"""Objects with at least this many pairs sort their key hashes through
buckets first."""

comptime _FAULTS = get_defined_bool["MOJO_NET_FAULTS"]()
"""In fault-seam test builds, key hashes keep 8 bits only, so that keys
share hashes and the comparisons within a hash are tested (and the
buckets of `_sort_hashed`, with the bits on top)."""


@inline(.always)
def _key_hash(key: Span[UInt8, _]) -> UInt64:
    var h = siphash13(0x243F6A8885A308D3, 0x13198A2E03707344, key)  # (pi's bits: any fixed key)
    comptime if _FAULTS:
        var t = h >> 56
        return (t << 56) | t  # (256 hashes, in 256 buckets)
    return h

comptime E_NODE = "json: no such node in the document"
comptime E_END = "json: the input ends where a value is due"


struct Kind(Equatable, TrivialRegisterPassable, Writable):
    """What a node is."""

    var _b: UInt8

    comptime NULL = Kind(0)
    comptime BOOL = Kind(1)
    comptime NUMBER = Kind(2)
    comptime STRING = Kind(3)
    comptime ARRAY = Kind(4)
    comptime OBJECT = Kind(5)

    def __init__(out self, b: UInt8):
        self._b = b

    def __eq__(self, other: Self) -> Bool:
        return self._b == other._b

    def write_to(self, mut writer: Some[Writer]):
        var names: List[StaticString] = ["null", "bool", "number", "string", "array", "object"]
        writer.write(names[Int(self._b)] if Int(self._b) < len(names) else "unknown")


@inline(.always)
def _kind(tag: UInt8) -> Kind:
    if tag == _NULL:
        return Kind.NULL
    if tag <= _TRUE:
        return Kind.BOOL
    if tag <= _NUM:
        return Kind.NUMBER
    if tag == _STR:
        return Kind.STRING
    if tag == _ARR:
        return Kind.ARRAY
    return Kind.OBJECT


@fieldwise_init
struct _Node(Copyable, TrivialRegisterPassable):
    var tag: UInt8
    var a: UInt32
    """A string's or number's offset in `_data`; an array's length, an
    object's number of pairs."""
    var b: UInt32
    """A string's or number's length; an array's or object's subtree
    size, itself included."""


struct Limits(TrivialRegisterPassable):
    """Bounds on what `parse` accepts; past one it raises LIMIT."""

    var max_depth: Int
    """Arrays and objects open at once."""
    var max_size: Int
    """Input bytes (at most `MAX_SIZE`, whatever this says)."""

    def __init__(out self, *, max_depth: Int = DEFAULT_MAX_DEPTH, max_size: Int = DEFAULT_MAX_SIZE):
        self.max_depth = max_depth
        self.max_size = max_size


struct Document(Copyable, Movable, Writable):
    """Parsed JSON text (see the module docs)."""

    var _nodes: List[_Node]
    var _data: List[UInt8]
    """Strings, unescaped, and numbers' text, back to back."""
    var _stack: List[UInt32]
    """While parsing: the arrays and objects open."""
    var _keys: List[UInt32]
    var _hashed: List[UInt128]
    """While parsing: an object's key nodes, and their hashes (high 64
    bits) with their places in `_keys`, for the repeated-key check."""
    var _spare: List[UInt128]
    var _counts: List[UInt32]

    def __init__(out self):
        """An empty document (no nodes); `parse` fills it."""
        self._nodes = List[_Node]()
        self._data = List[UInt8]()
        self._stack = List[UInt32]()
        self._keys = List[UInt32]()
        self._hashed = List[UInt128]()
        self._spare = List[UInt128]()
        self._counts = List[UInt32]()

    def nodes(self) -> Int:
        """How many nodes the document has (0 while empty)."""
        return len(self._nodes)

    def clear(mut self):
        """Empty, keeping the buffers' capacity."""
        self._nodes.clear()
        self._data.clear()

    # ---- parsing -----------------------------------------------------------

    def parse(mut self, data: Span[UInt8, _], limits: Limits = Limits()) raises JsonError:
        """Replace the contents with `data` parsed, reusing the buffers.
        On an error the document is left empty."""
        self.clear()
        self._stack.clear()
        try:
            self._parse(data, limits)
        except e:
            self.clear()
            raise e^

    def parse(mut self, text: StringSlice, limits: Limits = Limits()) raises JsonError:
        self.parse(text.as_bytes(), limits)

    def _parse(mut self, data: Span[UInt8, _], limits: Limits) raises JsonError:
        var n = len(data)
        if n > min(limits.max_size, MAX_SIZE):
            raise JsonError(JsonError.LIMIT, "json: the input is over the size limit", 0)
        var p = data.unsafe_ptr()
        var i = _ws(data, 0)
        while True:
            # A value starts at i.
            if i >= n:
                raise JsonError(JsonError.SYNTAX, E_END, i)
            var c = p[unsafe_offset=i]
            if c == _LBRACE or c == _LBRACKET:
                if len(self._stack) >= limits.max_depth:
                    raise JsonError(JsonError.LIMIT, "json: nested deeper than the depth limit", i)
                var obj = c == _LBRACE
                self._stack.append(UInt32(len(self._nodes)))
                self._nodes.append(_Node(_OBJ if obj else _ARR, 0, 0))
                i = _ws(data, i + 1)
                if i < n and p[unsafe_offset=i] == (_RBRACE if obj else _RBRACKET):
                    i += 1
                    self._close()
                elif obj:
                    i = self._key(data, i)
                    continue
                else:
                    continue
            elif c == _QUOTE:
                i = self._string(data, i)
            elif c == 116:  # t
                i = _literal(data, i, "true")
                self._nodes.append(_Node(_TRUE, 0, 0))
            elif c == 102:  # f
                i = _literal(data, i, "false")
                self._nodes.append(_Node(_FALSE, 0, 0))
            elif c == 110:  # n
                i = _literal(data, i, "null")
                self._nodes.append(_Node(_NULL, 0, 0))
            elif c == _MINUS or _is_digit(c):
                i = self._number(data, i)
            else:
                raise JsonError(JsonError.SYNTAX, "json: not a JSON value", i)
            # A value ended before i: what may follow it.
            while True:
                i = _ws(data, i)
                var depth = len(self._stack)
                if depth == 0:
                    if i != n:
                        raise JsonError(JsonError.SYNTAX, "json: more after the value", i)
                    return
                var top = Int(self._stack[depth - 1])
                self._nodes[top].a += 1
                if i >= n:
                    raise JsonError(JsonError.SYNTAX, "json: the input ends inside an array or object", i)
                var d = p[unsafe_offset=i]
                if self._nodes[top].tag == _ARR:
                    if d == _COMMA:
                        i = _ws(data, i + 1)
                        break
                    if d != _RBRACKET:
                        raise JsonError(JsonError.SYNTAX, "json: expected ',' or ']'", i)
                    self._close()
                else:
                    if d == _COMMA:
                        i = self._key(data, _ws(data, i + 1))
                        break
                    if d != _RBRACE:
                        raise JsonError(JsonError.SYNTAX, "json: expected ',' or '}'", i)
                    self._check_keys(top, i)
                    self._close()
                i += 1

    @inline(.always)
    def _close(mut self):
        var top = Int(self._stack.pop())
        self._nodes[top].b = UInt32(len(self._nodes) - top)

    def _key(mut self, data: Span[UInt8, _], i: Int) raises JsonError -> Int:
        """An object's key and its ':' at `i`; returns where the value is."""
        var n = len(data)
        if i >= n or data[i] != _QUOTE:
            raise JsonError(JsonError.SYNTAX, "json: expected a key (a string)", i)
        var j = _ws(data, self._string(data, i))
        if j >= n or data[j] != _COLON:
            raise JsonError(JsonError.SYNTAX, "json: expected ':' after a key", j)
        return _ws(data, j + 1)

    def _string(mut self, data: Span[UInt8, _], i: Int) raises JsonError -> Int:
        """The string whose '"' is at `i`, unescaped into `_data`; returns
        the index after its closing '"'."""
        var n = len(data)
        var p = data.unsafe_ptr()
        var start = len(self._data)
        var j = i + 1
        while True:
            var k = plain_run(data, j)
            if k > j:
                self._data.extend(data[j:k])
            if k >= n:
                raise JsonError(JsonError.SYNTAX, "json: the input ends inside a string", n)
            var b = p[unsafe_offset=k]
            if b == _QUOTE:
                var size = len(self._data) - start
                self._nodes.append(_Node(_STR, UInt32(start), UInt32(size)))
                return k + 1
            if b == _BACKSLASH:
                j = self._escape(data, k)
            elif b >= 0x80:
                var m = k
                while m < n and p[unsafe_offset=m] >= 0x80:
                    var length = utf8_length(data, m)
                    if length == 0:
                        raise JsonError(JsonError.SYNTAX, "json: a string is not UTF-8", m)
                    m += length
                self._data.extend(data[k:m])
                j = m
            else:
                raise JsonError(JsonError.SYNTAX, "json: a control character in a string", k)

    def _escape(mut self, data: Span[UInt8, _], k: Int) raises JsonError -> Int:
        """The escape whose '\\' is at `k`; returns the index after it."""
        var n = len(data)
        if k + 1 >= n:
            raise JsonError(JsonError.SYNTAX, "json: the input ends inside a string", n)
        var e = data[k + 1]
        var b: UInt8
        if e == _QUOTE or e == _BACKSLASH or e == 47:  # '/'
            b = e
        elif e == 98:  # b
            b = 0x08
        elif e == 102:  # f
            b = 0x0C
        elif e == 110:  # n
            b = 0x0A
        elif e == 114:  # r
            b = 0x0D
        elif e == 116:  # t
            b = 0x09
        elif e == 117:  # u
            var u = _hex4(data, k + 2)
            var j = k + 6
            if u >= 0xDC00 and u <= 0xDFFF:
                raise JsonError(JsonError.SYNTAX, "json: a lone surrogate in a string", k)
            if u >= 0xD800 and u <= 0xDBFF:
                if j + 1 >= n or data[j] != _BACKSLASH or data[j + 1] != 117:
                    raise JsonError(JsonError.SYNTAX, "json: a lone surrogate in a string", k)
                var lo = _hex4(data, j + 2)
                if lo < 0xDC00 or lo > 0xDFFF:
                    raise JsonError(JsonError.SYNTAX, "json: a lone surrogate in a string", k)
                u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00)
                j += 6
            _put_utf8(self._data, u)
            return j
        else:
            raise JsonError(JsonError.SYNTAX, "json: an invalid escape in a string", k)
        self._data.append(b)
        return k + 2

    def _number(mut self, data: Span[UInt8, _], start: Int) raises JsonError -> Int:
        """The number at `start`, checked against the grammar and kept as
        text; returns the index after it."""
        var n = len(data)
        var p = data.unsafe_ptr()
        var i = start
        if p[unsafe_offset=i] == _MINUS:
            i += 1
        if i >= n or not _is_digit(p[unsafe_offset=i]):
            raise JsonError(JsonError.SYNTAX, "json: a number needs digits", i)
        if p[unsafe_offset=i] == 48:
            i += 1
        else:
            while i < n and _is_digit(p[unsafe_offset=i]):
                i += 1
        var tag = _INT
        if i < n and p[unsafe_offset=i] == 46:  # '.'
            i += 1
            if i >= n or not _is_digit(p[unsafe_offset=i]):
                raise JsonError(JsonError.SYNTAX, "json: a fraction needs digits", i)
            while i < n and _is_digit(p[unsafe_offset=i]):
                i += 1
            tag = _NUM
        if i < n and (p[unsafe_offset=i] == 101 or p[unsafe_offset=i] == 69):  # e E
            i += 1
            if i < n and (p[unsafe_offset=i] == 43 or p[unsafe_offset=i] == _MINUS):
                i += 1
            if i >= n or not _is_digit(p[unsafe_offset=i]):
                raise JsonError(JsonError.SYNTAX, "json: an exponent needs digits", i)
            while i < n and _is_digit(p[unsafe_offset=i]):
                i += 1
            tag = _NUM
        self._nodes.append(_Node(tag, UInt32(len(self._data)), UInt32(i - start)))
        self._data.extend(data[start:i])
        return i

    # ---- repeated keys -----------------------------------------------------

    def _check_keys(mut self, obj: Int, at: Int) raises JsonError:
        """Refuse a key that object `obj` (closing at `at`) has twice.

        Up to `_PAIRWISE` pairs, every two keys are compared (lengths
        first, then 16 bytes at a time), at most 15 comparisons per key.
        Beyond, each key is hashed once (`siphash13`, in input order), the
        (hash, key) values are sorted, and only keys with the same hash are
        compared: the time is bounded by the keys' bytes plus a sort of
        16-byte values, whatever the keys are."""
        var pairs = Int(self._nodes[obj].a)
        if pairs < 2:
            return
        self._keys.clear()
        var c = obj + 1
        for _ in range(pairs):
            self._keys.append(UInt32(c))
            c = c + 1 + self._size(c + 1)
        if pairs <= _PAIRWISE:
            for x in range(pairs):
                for y in range(x + 1, pairs):
                    if self._same_key(Int(self._keys[x]), Int(self._keys[y])):
                        raise JsonError(JsonError.SYNTAX, "json: an object has a key twice", at)
            return
        self._hashed.clear()
        for i in range(pairs):
            var h = _key_hash(self._span(Int(self._keys[i])))
            self._hashed.append((UInt128(h) << 64) | UInt128(i))
        self._sort_hashed()
        var start = 0
        for x in range(1, pairs + 1):
            if x < pairs and (self._hashed[x] >> 64) == (self._hashed[start] >> 64):
                continue
            # [start, x) share one hash: compare their keys.
            for u in range(start, x):
                for v in range(u + 1, x):
                    var ku = Int(self._keys[Int(self._hashed[u] & 0xFFFFFFFF)])
                    var kv = Int(self._keys[Int(self._hashed[v] & 0xFFFFFFFF)])
                    if self._same_key(ku, kv):
                        raise JsonError(JsonError.SYNTAX, "json: an object has a key twice", at)
            start = x

    def _sort_hashed(mut self):
        """Sort `_hashed`: into buckets by the hashes' top 16 bits (one
        pass), then each bucket by `sort`. Never slower than `sort` alone,
        whatever the hashes; 300,000 keys parse in 31 ms instead of 79."""
        var n = len(self._hashed)
        if n < _BUCKETED:
            sort(self._hashed)
            return
        self._counts.resize(65537, 0)
        for b in range(65537):
            self._counts[b] = 0
        for r in self._hashed:
            self._counts[Int(r >> 112) + 1] += 1
        for b in range(65536):
            self._counts[b + 1] += self._counts[b]
        self._spare.resize(n, 0)
        for r in self._hashed:
            var b = Int(r >> 112)
            self._spare[Int(self._counts[b])] = r
            self._counts[b] += 1
        swap(self._hashed, self._spare)
        var start = 0  # (each count is now its bucket's end)
        for b in range(65536):
            var end = Int(self._counts[b])
            if end - start > 1:
                sort(Span(self._hashed)[start:end])
            start = end

    def _same_key(self, x: Int, y: Int) -> Bool:
        """Whether string nodes `x` and `y` hold the same bytes."""
        var a = self._nodes[x]
        var b = self._nodes[y]
        if a.b != b.b:
            return False
        var p = self._data.unsafe_ptr()
        var i = Int(a.a)
        var j = Int(b.a)
        var n = Int(a.b)
        var k = 0
        while k + 16 <= n:
            if not (p.unsafe_load[width=16](i + k) == p.unsafe_load[width=16](j + k)):
                return False
            k += 16
        while k < n:
            if p[unsafe_offset=i + k] != p[unsafe_offset=j + k]:
                return False
            k += 1
        return True

    # ---- reading -----------------------------------------------------------

    @inline(.always)
    def _check(self, n: Int) raises JsonError:
        if n < 0 or n >= len(self._nodes):
            raise JsonError(JsonError.MISSING, E_NODE)

    @inline(.always)
    def _size(self, n: Int) -> Int:
        """Nodes in `n`'s subtree."""
        var node = self._nodes[n]
        return Int(node.b) if node.tag >= _ARR else 1

    def _span(self, n: Int) -> Span[UInt8, origin_of(self._data)]:
        var node = self._nodes[n]
        return Span(self._data)[Int(node.a) : Int(node.a) + Int(node.b)]

    def kind(self, n: Int = 0) raises JsonError -> Kind:
        self._check(n)
        return _kind(self._nodes[n].tag)

    def is_null(self, n: Int = 0) raises JsonError -> Bool:
        self._check(n)
        return self._nodes[n].tag == _NULL

    def count(self, n: Int = 0) raises JsonError -> Int:
        """An array's length, or an object's number of pairs."""
        self._check(n)
        if self._nodes[n].tag < _ARR:
            raise JsonError(JsonError.TYPE, "json: not an array or object")
        return Int(self._nodes[n].a)

    def child(self, n: Int, k: Int) raises JsonError -> Int:
        """The node number of element `k` of array `n`. O(k)."""
        self._check(n)
        if self._nodes[n].tag != _ARR:
            raise JsonError(JsonError.TYPE, "json: not an array")
        if k < 0 or k >= Int(self._nodes[n].a):
            raise JsonError(JsonError.MISSING, "json: no such element in the array")
        var c = n + 1
        for _ in range(k):
            c += self._size(c)
        return c

    def next(self, n: Int) raises JsonError -> Int:
        """The node after `n` and everything in it: its next sibling, when
        it has one."""
        self._check(n)
        return n + self._size(n)

    def key(self, n: Int, i: Int) raises JsonError -> Int:
        """The key node of object `n`'s pair `i`. O(i)."""
        self._check(n)
        if self._nodes[n].tag != _OBJ:
            raise JsonError(JsonError.TYPE, "json: not an object")
        if i < 0 or i >= Int(self._nodes[n].a):
            raise JsonError(JsonError.MISSING, "json: no such pair in the object")
        var c = n + 1
        for _ in range(i):
            c = c + 1 + self._size(c + 1)
        return c

    def val(self, n: Int, i: Int) raises JsonError -> Int:
        """The value node of object `n`'s pair `i`. O(i)."""
        return self.key(n, i) + 1

    def get(self, n: Int, key: StringSlice) raises JsonError -> Optional[Int]:
        """The value node of object `n` for `key`, if it has that key."""
        self._check(n)
        if self._nodes[n].tag != _OBJ:
            raise JsonError(JsonError.TYPE, "json: not an object")
        var want = key.as_bytes()
        var p = self._data.unsafe_ptr()
        var q = want.unsafe_ptr()
        var c = n + 1
        for _ in range(Int(self._nodes[n].a)):
            var k = self._nodes[c]
            if Int(k.b) == len(want):
                var same = True
                var at = Int(k.a)
                for i in range(len(want)):
                    if p[unsafe_offset=at + i] != q[unsafe_offset=i]:
                        same = False
                        break
                if same:
                    return c + 1
            c = c + 1 + self._size(c + 1)
        return None

    def member(self, n: Int, key: StringSlice) raises JsonError -> Int:
        """The value node of object `n` for `key`; MISSING without it."""
        var v = self.get(n, key)
        if not v:
            raise JsonError(JsonError.MISSING, "json: no such key in the object")
        return v.value()

    def view(self, n: Int = 0) raises JsonError -> StringSlice[origin_of(self._data)]:
        """A string's text, or a number's as written, without copying."""
        self._check(n)
        var tag = self._nodes[n].tag
        if tag != _STR and tag != _INT and tag != _NUM:
            raise JsonError(JsonError.TYPE, "json: not a string or number")
        return StringSlice(unsafe_from_utf8=self._span(n))

    def text(self, n: Int = 0) raises JsonError -> String:
        """A string's text, or a number's as written."""
        return String(self.view(n))

    def int(self, n: Int = 0) raises JsonError -> Int:
        """A number written as an integer (no fraction or exponent); RANGE
        past Int's range, TYPE for other numbers."""
        self._check(n)
        var tag = self._nodes[n].tag
        if tag != _INT:
            if tag == _NUM:
                raise JsonError(JsonError.TYPE, "json: the number is not written as an integer")
            raise JsonError(JsonError.TYPE, "json: not a number")
        var s = self._span(n)
        var neg = s[0] == _MINUS
        var limit: UInt64 = (UInt64(1) << 63) if neg else UInt64(Int.MAX)
        var v: UInt64 = 0
        for i in range(1 if neg else 0, len(s)):
            var d = UInt64(s[i] - 48)
            if v > (limit - d) // 10:
                raise JsonError(JsonError.RANGE, "json: the integer is out of Int's range")
            v = v * 10 + d
        if neg:
            return Int(0 - v) if v != (UInt64(1) << 63) else Int.MIN
        return Int(v)

    def float(self, n: Int = 0) raises JsonError -> Float64:
        """Any number, correctly rounded to the nearest Float64 (one too
        small for a Float64 reads as 0 or a subnormal); RANGE past
        Float64's range, where it would be an infinity."""
        self._check(n)
        var tag = self._nodes[n].tag
        if tag != _INT and tag != _NUM:
            raise JsonError(JsonError.TYPE, "json: not a number")
        var x: Float64
        try:
            x = atof(StringSlice(unsafe_from_utf8=self._span(n)))
        except:
            raise JsonError(JsonError.RANGE, "json: the number does not read as a Float64")
        if x - x != 0:
            raise JsonError(JsonError.RANGE, "json: the number is out of Float64's range")
        return x

    def bool(self, n: Int = 0) raises JsonError -> Bool:
        self._check(n)
        var tag = self._nodes[n].tag
        if tag != _TRUE and tag != _FALSE:
            raise JsonError(JsonError.TYPE, "json: not a boolean")
        return tag == _TRUE

    # ---- output ------------------------------------------------------------

    def write_json(self, n: Int, mut out: List[UInt8]) raises JsonError:
        """Append node `n` and everything in it as compact JSON text."""
        self._check(n)
        var end = n + self._size(n)
        # Per open array or object: the nodes still to write (an object's
        # keys and values both count), whether it is an object, and whether
        # nothing of it is written yet.
        var left = List[Int]()
        var objects = List[Bool]()
        var first = List[Bool]()
        for i in range(n, end):
            var depth = len(left)
            if depth > 0:
                var t = depth - 1
                if objects[t] and left[t] % 2 == 1:  # (a value, after its key)
                    out.append(_COLON)
                elif not first[t]:
                    out.append(_COMMA)
                first[t] = False
                left[t] -= 1
            var node = self._nodes[i]
            if node.tag >= _ARR:
                var obj = node.tag == _OBJ
                out.append(_LBRACE if obj else _LBRACKET)
                if node.a > 0:
                    left.append(Int(node.a) * (2 if obj else 1))
                    objects.append(obj)
                    first.append(True)
                    continue
                out.append(_RBRACE if obj else _RBRACKET)
            elif node.tag == _STR:
                _ = write_quoted(out, self._span(i), validate=False)
            elif node.tag == _INT or node.tag == _NUM:
                out.extend(self._span(i))
            elif node.tag == _TRUE:
                out.extend("true".as_bytes())
            elif node.tag == _FALSE:
                out.extend("false".as_bytes())
            else:
                out.extend("null".as_bytes())
            while len(left) > 0 and left[len(left) - 1] == 0:
                _ = left.pop()
                _ = first.pop()
                out.append(_RBRACE if objects.pop() else _RBRACKET)

    def json(self, n: Int = 0) raises JsonError -> String:
        """Node `n` as compact JSON text."""
        var out = List[UInt8]()
        self.write_json(n, out)
        return String(unsafe_from_utf8=Span(out))

    def write_to(self, mut writer: Some[Writer]):
        """The whole document as compact JSON text ("" while empty)."""
        if len(self._nodes) == 0:
            return
        try:
            writer.write(self.json(0))
        except:
            pass


def parse(data: Span[UInt8, _], limits: Limits = Limits()) raises JsonError -> Document:
    """`data` parsed into a new `Document` (see the module docs)."""
    var doc = Document()
    doc.parse(data, limits)
    return doc^


def parse(text: StringSlice, limits: Limits = Limits()) raises JsonError -> Document:
    return parse(text.as_bytes(), limits)


@inline(.always)
def _is_digit(c: UInt8) -> Bool:
    return c >= 48 and c <= 57


@inline(.always)
def _ws(data: Span[UInt8, _], start: Int) -> Int:
    """The index of the first byte at or after `start` that is not JSON
    whitespace (space, tab, LF, CR)."""
    var p = data.unsafe_ptr()
    var n = len(data)
    var i = start
    while i < n:
        var c = p[unsafe_offset=i]
        if c > 32 or (c != 32 and c != 10 and c != 13 and c != 9):
            break
        i += 1
    return i


def _literal(data: Span[UInt8, _], i: Int, word: StaticString) raises JsonError -> Int:
    var w = word.as_bytes()
    if i + len(w) > len(data):
        raise JsonError(JsonError.SYNTAX, "json: not a JSON value", i)
    for k in range(len(w)):
        if data[i + k] != w[k]:
            raise JsonError(JsonError.SYNTAX, "json: not a JSON value", i)
    return i + len(w)


def _hex4(data: Span[UInt8, _], i: Int) raises JsonError -> Int:
    """The four hex digits at `i` (a \\u escape's)."""
    if i + 4 > len(data):
        raise JsonError(JsonError.SYNTAX, "json: a \\u escape needs four hex digits", i)
    var v = 0
    for k in range(4):
        var c = data[i + k]
        var d: Int
        if c >= 48 and c <= 57:
            d = Int(c) - 48
        elif c >= 97 and c <= 102:
            d = Int(c) - 87
        elif c >= 65 and c <= 70:
            d = Int(c) - 55
        else:
            raise JsonError(JsonError.SYNTAX, "json: a \\u escape needs four hex digits", i)
        v = v * 16 + d
    return v


def _put_utf8(mut out: List[UInt8], u: Int):
    """Append code point `u` (not a surrogate) as UTF-8."""
    if u < 0x80:
        out.append(UInt8(u))
    elif u < 0x800:
        out.append(UInt8(0xC0 | (u >> 6)))
        out.append(UInt8(0x80 | (u & 0x3F)))
    elif u < 0x10000:
        out.append(UInt8(0xE0 | (u >> 12)))
        out.append(UInt8(0x80 | ((u >> 6) & 0x3F)))
        out.append(UInt8(0x80 | (u & 0x3F)))
    else:
        out.append(UInt8(0xF0 | (u >> 18)))
        out.append(UInt8(0x80 | ((u >> 12) & 0x3F)))
        out.append(UInt8(0x80 | ((u >> 6) & 0x3F)))
        out.append(UInt8(0x80 | (u & 0x3F)))
