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

from std.bit import count_leading_zeros, count_trailing_zeros
from std.collections import Optional
from std.memory import bitcast, pack_bits
from std.sys import get_defined_bool

from .error import JsonError
from .number import read_float
from .siphash import siphash13
from .text import is_plain, utf8_length_at, write_quoted

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


struct Dialect(TrivialRegisterPassable):
    """What `parse` accepts beyond RFC 8259, strictly read; nothing by
    default. `Dialect.python()` accepts what Python's json module reads,
    for the Python binding (python/mojson) and for text Python wrote."""

    var repeated_keys: Bool
    """A key twice in one object (both pairs are kept, in order)."""
    var constants: Bool
    """`NaN`, `Infinity` and `-Infinity`: numbers (not integers) whose
    text is the word; `float()` reads them as NaN and the infinities."""
    var lone_surrogates: Bool
    """A `\\uD800`-`\\uDFFF` escape outside a pair, and a surrogate
    encoded in the input as UTF-8 would encode it (ED A0 80 to ED BF BF):
    kept in the string as those three bytes (WTF-8), which is then not
    UTF-8. Python decodes them with "surrogatepass"."""
    var control_characters: Bool
    """Control characters in strings, unescaped (Python's strict=False)."""

    def __init__(
        out self,
        *,
        repeated_keys: Bool = False,
        constants: Bool = False,
        lone_surrogates: Bool = False,
        control_characters: Bool = False,
    ):
        self.repeated_keys = repeated_keys
        self.constants = constants
        self.lone_surrogates = lone_surrogates
        self.control_characters = control_characters

    @staticmethod
    def python(control_characters: Bool = False) -> Self:
        """Python's json.loads: repeated keys, the constants and lone
        surrogates; control characters with `strict=False`."""
        return Self(repeated_keys=True, constants=True, lone_surrogates=True, control_characters=control_characters)


comptime _V = 32
"""Input bytes a scan for a string's end, or past whitespace, looks at
at once."""
comptime _VBits = DType.uint32
"""`_V` comparisons packed into one integer."""

comptime _SLACK = 64
"""Bytes `_data` holds past the input's length while parsing, and past its
text after: strings unescaped and numbers' text never take more bytes than
the input, so with this slack a scan can store whole vectors, and read 8
bytes past any key, unchecked. They count in the list's length, so that
AddressSanitizer's container checks see no access past it."""

comptime _PROBES = 16
"""Slots a key may probe in `_check_keys`'s table before the object is
checked by sorting instead (keys chosen to share the public hash)."""

comptime _PARTITIONED = 4096
"""Objects with more pairs split their keys into 256 buckets by hash
before the table, so that each bucket's table stays in cache."""

comptime _RUN = 8
"""Keys of one large object that share a cheap hash are compared pair by
pair up to this many; a longer run goes through SipHash (`_check_run`)."""

comptime _BytePtr = Pointer[UInt8, MutAnyOrigin]
comptime _NodePtr = Pointer[_Node, MutAnyOrigin]


struct _Fail(Movable):
    """Where a parse failed, and why: what `Document.parse` raises. It
    carries the dialect's switches too, since every check that can fail
    has it at hand, and the switches are read only where a strict parse
    would fail."""

    var kind: Int
    var message: StaticString
    var offset: Int
    var constants: Bool
    var surrogates: Bool
    var controls: Bool

    def __init__(out self, dialect: Dialect):
        self.kind = 0
        self.message = ""
        self.offset = -1
        self.constants = dialect.constants
        self.surrogates = dialect.lone_surrogates
        self.controls = dialect.control_characters

    @no_inline
    def fail(mut self, message: StaticString, offset: Int, kind: Int = JsonError.SYNTAX) -> Int:
        """Record the failure; -1, for the caller to return."""
        self.kind = kind
        self.message = message
        self.offset = offset
        return -1


@fieldwise_init
struct _Open(Copyable, TrivialRegisterPassable):
    """An array or object open around the one being parsed: its node and
    its members so far."""

    var node: Int
    var count: Int


comptime SPAN_SLACK = 32
"""Bytes that can be read past the end of any span `Document.visit` hands
a `Visitor` (the document's buffer has room after its text), so that a
visitor can load whole vectors and mask off what lies past the span."""


trait Visitor:
    """What `Document.visit` calls, node by node in document order. The
    spans are the document's own bytes, valid while it is unchanged:
    strings unescaped, numbers as written (`integer`: no fraction or
    exponent); each can be read `SPAN_SLACK` bytes past its end."""

    def null(mut self) raises:
        ...

    def boolean(mut self, value: Bool) raises:
        ...

    def number(mut self, text: Span[UInt8, ImmutAnyOrigin], integer: Bool) raises:
        ...

    def string(mut self, text: Span[UInt8, ImmutAnyOrigin]) raises:
        ...

    def key(mut self, text: Span[UInt8, ImmutAnyOrigin]) raises:
        ...

    def begin_array(mut self, count: Int) raises:
        ...

    def end_array(mut self) raises:
        ...

    def begin_object(mut self, count: Int) raises:
        """An object of `count` pairs: `key` then the value, each pair."""
        ...

    def end_object(mut self) raises:
        ...


trait Handler:
    """What `Document.scan` calls, value by value in document order, as it
    reads: no document is built. The spans are valid during the call
    only: strings unescaped, numbers as written (`integer`: no fraction
    or exponent); each can be read `SPAN_SLACK` bytes past its end. An
    array's or object's size comes at its end. Each method returns False
    to stop the scan (a failure of the handler's own)."""

    def null(mut self) -> Bool:
        ...

    def boolean(mut self, value: Bool) -> Bool:
        ...

    def number(mut self, text: Span[UInt8, ImmutAnyOrigin], integer: Bool) -> Bool:
        ...

    def string(mut self, text: Span[UInt8, ImmutAnyOrigin]) -> Bool:
        ...

    def key(mut self, text: Span[UInt8, ImmutAnyOrigin]) -> Bool:
        """An object's key; its value follows."""
        ...

    def begin_array(mut self) -> Bool:
        ...

    def end_array(mut self, count: Int) -> Bool:
        """The array of `count` values just read."""
        ...

    def begin_object(mut self) -> Bool:
        ...

    def end_object(mut self, count: Int) -> Bool:
        """The object of `count` pairs just read."""
        ...


struct Document(Copyable, Movable, Writable):
    """Parsed JSON text (see the module docs)."""

    var _nodes: List[_Node]
    var _data: List[UInt8]
    """Strings, unescaped, and numbers' text, back to back."""
    var _stack: List[_Open]
    """While parsing: the arrays and objects open around the innermost."""
    var _keys: List[UInt32]
    """While parsing: the key nodes of the objects open, outermost first."""
    var _table: List[UInt64]
    var _hashed: List[UInt128]
    var _run: List[UInt128]
    """While checking an object for a repeated key: its keys' hashes (high
    64 bits) with their places among its keys (`_check_keys`): a table,
    and, when its keys collide there, sorted lists."""
    var _spare: List[UInt128]
    var _counts: List[UInt32]

    def __init__(out self):
        """An empty document (no nodes); `parse` fills it."""
        self._nodes = List[_Node]()
        self._data = List[UInt8]()
        self._stack = List[_Open]()
        self._keys = List[UInt32]()
        self._table = List[UInt64]()
        self._hashed = List[UInt128]()
        self._run = List[UInt128]()
        self._spare = List[UInt128]()
        self._counts = List[UInt32]()

    def __init__(out self, *, copy: Self):
        """A copy, with the room past its text that `SPAN_SLACK` promises
        (`_data` holds it)."""
        self._nodes = copy._nodes.copy()
        self._data = copy._data.copy()
        self._stack = List[_Open]()
        self._keys = List[UInt32]()
        self._table = List[UInt64]()
        self._hashed = List[UInt128]()
        self._run = List[UInt128]()
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

    def parse(mut self, data: Span[UInt8, _], limits: Limits = Limits(), dialect: Dialect = Dialect()) raises JsonError:
        """Replace the contents with `data` parsed, reusing the buffers.
        On an error the document is left empty."""
        self.clear()
        self._stack.clear()
        self._keys.clear()
        try:
            self._parse(data, limits, dialect)
        except e:
            self.clear()
            raise e^

    def parse(mut self, text: StringSlice, limits: Limits = Limits(), dialect: Dialect = Dialect()) raises JsonError:
        self.parse(text.as_bytes(), limits, dialect)

    def scan[H: Handler](
        mut self, data: Span[UInt8, _], mut handler: H, limits: Limits = Limits(), dialect: Dialect = Dialect()
    ) raises JsonError -> Bool:
        """Read `data` as `parse` does, accepting and refusing the same
        texts with the same errors, but call `handler` for each value as
        it is read instead of building the document: one pass, with no
        nodes. The document is left empty; its buffers serve as scratch
        (a string's unescaped text, and, for a dialect that refuses
        repeated keys, the keys of the objects open). False when a
        handler call returned False, which ends the scan at once."""
        self.clear()
        self._stack.clear()
        self._keys.clear()
        var n = len(data)
        if n > min(limits.max_size, MAX_SIZE):
            raise JsonError(JsonError.LIMIT, "json: the input is over the size limit", 0)
        var err = _Fail(dialect)
        var r: Int
        if dialect.repeated_keys:
            r = self._scan_events[False](data.unsafe_ptr(), n, limits.max_depth, handler, err)
        else:
            r = self._scan_events[True](data.unsafe_ptr(), n, limits.max_depth, handler, err)
        self.clear()
        self._stack.clear()
        self._keys.clear()
        if r == -1:
            raise JsonError(err.kind, err.message, err.offset)
        return r == 0

    def _parse(mut self, data: Span[UInt8, _], limits: Limits, dialect: Dialect) raises JsonError:
        """One pass over `data`. Nodes and `_data` are written through raw
        pointers: `_data` gets the input's length first (strings unescaped
        and numbers' text never take more), plus `_SLACK` so that scans
        store whole vectors; `_nodes` grows on demand, checked once per
        value for the two nodes (a key and a value) written before the
        next check. The innermost open array or object is kept in `top`,
        the ones around it in `_stack`. While the scan runs, each list's
        length covers all it may write (`_nodes` its capacity, `_data` the
        input plus `_SLACK`); their lengths are set once, at the end, and
        `_data` keeps its `_SLACK` (`SPAN_SLACK`)."""
        var n = len(data)
        if n > min(limits.max_size, MAX_SIZE):
            raise JsonError(JsonError.LIMIT, "json: the input is over the size limit", 0)
        var err = _Fail(dialect)
        var r: Int
        if dialect.repeated_keys:
            r = self._scan[False](data.unsafe_ptr(), n, limits.max_depth, err)
        else:
            r = self._scan[True](data.unsafe_ptr(), n, limits.max_depth, err)
        if r < 0:
            raise JsonError(err.kind, err.message, err.offset)

    @no_inline
    def _scan[keys: Bool](mut self, p: Pointer[UInt8, _], n: Int, max_depth: Int, mut err: _Fail) -> Int:
        """`_parse`'s pass: 0, or -1 with `err` set. It raises nothing, so
        that no error is built on the paths that succeed; each check that
        fails returns `err.fail(...)`. Few values stay live across it (the
        innermost open array or object is `top` and `count`; while open,
        an object's node holds where its keys start in `_keys`), so that
        they fit in registers."""
        self._data.reserve(n + _SLACK)
        self._data.resize(unsafe_uninit_length=n + _SLACK)
        var dp = self._data.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()
        var dn = 0
        if self._nodes.capacity() < n // 16 + 16:
            self._nodes.reserve(n // 16 + 16)
        self._nodes.resize(unsafe_uninit_length=self._nodes.capacity())
        var np = self._nodes.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()
        var nlim = self._nodes.capacity() - 2
        var nn = 0
        var top = -1  # (none open)
        var count = 0
        var i = _skip_ws(p, 0, n)
        while True:
            # A value starts at i.
            if nn > nlim:
                np = _grow(self._nodes, nn)
                nlim = self._nodes.capacity() - 2
            if i >= n:
                return err.fail(E_END, i)
            var c = p[unsafe_offset=i]
            if c == _QUOTE:
                var s0 = dn
                i = _string(p, n, i, dp, dn, err)
                if i < 0:
                    return -1
                np[unsafe_offset=nn] = _Node(_STR, UInt32(s0), UInt32(dn - s0))
                nn += 1
            elif c == _LBRACE or c == _LBRACKET:
                if (len(self._stack) + 1 if top >= 0 else 0) >= max_depth:
                    return err.fail("json: nested deeper than the depth limit", i, JsonError.LIMIT)
                var obj = c == _LBRACE
                if top >= 0:
                    self._stack.append(_Open(top, count))
                top = nn
                count = 0
                np[unsafe_offset=nn] = _Node(_OBJ if obj else _ARR, UInt32(len(self._keys)), 1)
                nn += 1
                i = _skip_ws(p, i + 1, n)
                if i < n and p[unsafe_offset=i] == (_RBRACE if obj else _RBRACKET):
                    i += 1
                    np[unsafe_offset=top].a = 0
                    top, count = self._outer()
                elif obj:
                    comptime if keys:
                        self._keys.append(UInt32(nn))
                    i = _key(p, n, i, np, nn, dp, dn, err)
                    if i < 0:
                        return -1
                    continue
                else:
                    continue
            elif c == _MINUS or _is_digit(c):
                var s0 = dn
                var tag = _INT
                i = _number(p, n, i, dp, dn, tag, err)
                if i < 0:
                    return -1
                np[unsafe_offset=nn] = _Node(tag, UInt32(s0), UInt32(dn - s0))
                nn += 1
            elif c == 116:  # t
                if i + 4 > n or _load4(p, i) != 0x65757274:  # "true"
                    return err.fail("json: not a JSON value", i)
                i += 4
                np[unsafe_offset=nn] = _Node(_TRUE, 0, 0)
                nn += 1
            elif c == 102:  # f
                if i + 5 > n or _load4(p, i + 1) != 0x65736C61:  # "alse"
                    return err.fail("json: not a JSON value", i)
                i += 5
                np[unsafe_offset=nn] = _Node(_FALSE, 0, 0)
                nn += 1
            elif c == 110:  # n
                if i + 4 > n or _load4(p, i) != 0x6C6C756E:  # "null"
                    return err.fail("json: not a JSON value", i)
                i += 4
                np[unsafe_offset=nn] = _Node(_NULL, 0, 0)
                nn += 1
            else:
                var s0 = dn
                i = _constant(p, n, i, dp, dn, err)
                if i < 0:
                    return -1
                np[unsafe_offset=nn] = _Node(_NUM, UInt32(s0), UInt32(dn - s0))
                nn += 1
            # A value ended before i: what may follow it.
            while True:
                if top < 0:
                    i = _skip_ws(p, i, n)
                    if i != n:
                        return err.fail("json: more after the value", i)
                    self._nodes.resize(unsafe_uninit_length=nn)
                    self._data.resize(unsafe_uninit_length=dn + _SLACK)
                    return 0
                count += 1
                i = _skip_ws(p, i, n)
                if i >= n:
                    return err.fail("json: the input ends inside an array or object", i)
                var d = p[unsafe_offset=i]
                var obj = np[unsafe_offset=top].tag == _OBJ
                if d == _COMMA:
                    i = _skip_ws(p, i + 1, n)
                    if obj:
                        comptime if keys:
                            self._keys.append(UInt32(nn))
                        i = _key(p, n, i, np, nn, dp, dn, err)
                        if i < 0:
                            return -1
                    break
                if obj:
                    if d != _RBRACE:
                        return err.fail("json: expected ',' or '}'", i)
                    comptime if keys:
                        var first = Int(np[unsafe_offset=top].a)
                        if count > 1:
                            var kp = self._keys.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]().unsafe_offset(first)
                            if self._check_keys(np, dp, kp, count, i, err) < 0:
                                return -1
                        self._keys.resize(unsafe_uninit_length=first)
                elif d != _RBRACKET:
                    return err.fail("json: expected ',' or ']'", i)
                np[unsafe_offset=top].a = UInt32(count)
                np[unsafe_offset=top].b = UInt32(nn - top)
                top, count = self._outer()
                i += 1

    @no_inline
    def _scan_events[
        keys: Bool, H: Handler
    ](mut self, p: Pointer[UInt8, _], n: Int, max_depth: Int, mut h: H, mut err: _Fail) -> Int:
        """`scan`'s pass, `_scan`'s grammar with `h` called where `_scan`
        writes a node: 0; -1 with `err` set; -2 when `h` stopped it. The
        innermost open array or object is `top_obj`, `count` and (`keys`)
        `first`, its keys' start in `_keys`; the ones around it are in
        `_stack`, as `_Open(first * 2 + is_object, count)`. With `keys`,
        `_nodes` holds the open objects' keys (their texts at the start of
        `_data`), so that `_check_keys` reads them as it reads a
        document's; every other text is written at the end of those and
        dropped after its call."""
        self._data.reserve(n + _SLACK)
        self._data.resize(unsafe_uninit_length=n + _SLACK)
        var dp = self._data.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()
        var dn = 0
        comptime if keys:
            if self._nodes.capacity() < 64:
                self._nodes.reserve(64)
        self._nodes.resize(unsafe_uninit_length=self._nodes.capacity())
        var np = self._nodes.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()
        var nlim = self._nodes.capacity() - 1
        var nn = 0
        var depth = 0
        var top_obj = False
        var count = 0
        var first = 0
        var i = _skip_ws(p, 0, n)
        while True:
            # A value starts at i.
            if i >= n:
                return err.fail(E_END, i)
            var c = p[unsafe_offset=i]
            if c == _QUOTE:
                var s0 = dn
                i = _string(p, n, i, dp, dn, err)
                if i < 0:
                    return -1
                if not h.string(Span[UInt8, ImmutAnyOrigin](unsafe_ptr=dp.unsafe_offset(s0), length=dn - s0)):
                    return -2
                dn = s0
            elif c == _LBRACE or c == _LBRACKET:
                if depth >= max_depth:
                    return err.fail("json: nested deeper than the depth limit", i, JsonError.LIMIT)
                var obj = c == _LBRACE
                if depth > 0:
                    self._stack.append(_Open(first * 2 + Int(top_obj), count))
                depth += 1
                top_obj = obj
                count = 0
                comptime if keys:
                    first = len(self._keys)
                if not (h.begin_object() if obj else h.begin_array()):
                    return -2
                i = _skip_ws(p, i + 1, n)
                if i < n and p[unsafe_offset=i] == (_RBRACE if obj else _RBRACKET):
                    i += 1
                    if not (h.end_object(0) if obj else h.end_array(0)):
                        return -2
                    depth -= 1
                    if depth > 0:
                        var o = self._stack.unsafe_ptr()[unsafe_offset=len(self._stack) - 1]
                        self._stack.resize(unsafe_uninit_length=len(self._stack) - 1)
                        top_obj = (o.node & 1) == 1
                        first = o.node >> 1
                        count = o.count
                elif obj:
                    i = self._event_key[keys](p, n, i, h, dp, dn, np, nn, nlim, err)
                    if i < 0:
                        return i
                    continue
                else:
                    continue
            elif c == _MINUS or _is_digit(c):
                var s0 = dn
                var tag = _INT
                i = _number(p, n, i, dp, dn, tag, err)
                if i < 0:
                    return -1
                if not h.number(Span[UInt8, ImmutAnyOrigin](unsafe_ptr=dp.unsafe_offset(s0), length=dn - s0), tag == _INT):
                    return -2
                dn = s0
            elif c == 116:  # t
                if i + 4 > n or _load4(p, i) != 0x65757274:  # "true"
                    return err.fail("json: not a JSON value", i)
                i += 4
                if not h.boolean(True):
                    return -2
            elif c == 102:  # f
                if i + 5 > n or _load4(p, i + 1) != 0x65736C61:  # "alse"
                    return err.fail("json: not a JSON value", i)
                i += 5
                if not h.boolean(False):
                    return -2
            elif c == 110:  # n
                if i + 4 > n or _load4(p, i) != 0x6C6C756E:  # "null"
                    return err.fail("json: not a JSON value", i)
                i += 4
                if not h.null():
                    return -2
            else:
                var s0 = dn
                i = _constant(p, n, i, dp, dn, err)
                if i < 0:
                    return -1
                if not h.number(Span[UInt8, ImmutAnyOrigin](unsafe_ptr=dp.unsafe_offset(s0), length=dn - s0), False):
                    return -2
                dn = s0
            # A value ended before i: what may follow it.
            while True:
                if depth == 0:
                    i = _skip_ws(p, i, n)
                    if i != n:
                        return err.fail("json: more after the value", i)
                    return 0
                count += 1
                i = _skip_ws(p, i, n)
                if i >= n:
                    return err.fail("json: the input ends inside an array or object", i)
                var d = p[unsafe_offset=i]
                if d == _COMMA:
                    i = _skip_ws(p, i + 1, n)
                    if top_obj:
                        i = self._event_key[keys](p, n, i, h, dp, dn, np, nn, nlim, err)
                        if i < 0:
                            return i
                    break
                if top_obj:
                    if d != _RBRACE:
                        return err.fail("json: expected ',' or '}'", i)
                    comptime if keys:
                        if count > 1:
                            var kp = self._keys.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]().unsafe_offset(first)
                            if self._check_keys(np, dp, kp, count, i, err) < 0:
                                return -1
                        # This object's keys go: their nodes and texts.
                        nn = Int(self._keys.unsafe_ptr()[unsafe_offset=first])
                        dn = Int(np[unsafe_offset=nn].a)
                        self._keys.resize(unsafe_uninit_length=first)
                    if not h.end_object(count):
                        return -2
                elif d != _RBRACKET:
                    return err.fail("json: expected ',' or ']'", i)
                elif not h.end_array(count):
                    return -2
                depth -= 1
                if depth > 0:
                    var o = self._stack.unsafe_ptr()[unsafe_offset=len(self._stack) - 1]
                    self._stack.resize(unsafe_uninit_length=len(self._stack) - 1)
                    top_obj = (o.node & 1) == 1
                    first = o.node >> 1
                    count = o.count
                i += 1

    @inline(.always)
    def _event_key[
        keys: Bool, H: Handler
    ](
        mut self,
        p: Pointer[UInt8, _],
        n: Int,
        i: Int,
        mut h: H,
        dp: _BytePtr,
        mut dn: Int,
        mut np: _NodePtr,
        mut nn: Int,
        mut nlim: Int,
        mut err: _Fail,
    ) -> Int:
        """`_key` for `scan`: the key at `i` to `h`, its text kept (as a
        node, for `_check_keys`) with `keys`; where its value starts, -1
        (`err`) or -2 (stopped)."""
        if i >= n or p[unsafe_offset=i] != _QUOTE:
            return err.fail("json: expected a key (a string)", i)
        var s0 = dn
        var j = _string(p, n, i, dp, dn, err)
        if j < 0:
            return -1
        if not h.key(Span[UInt8, ImmutAnyOrigin](unsafe_ptr=dp.unsafe_offset(s0), length=dn - s0)):
            return -2
        comptime if keys:
            if nn > nlim:
                np = _grow(self._nodes, nn)
                nlim = self._nodes.capacity() - 1
            np[unsafe_offset=nn] = _Node(_STR, UInt32(s0), UInt32(dn - s0))
            self._keys.append(UInt32(nn))
            nn += 1
        else:
            dn = s0
        j = _skip_ws(p, j, n)
        if j >= n or p[unsafe_offset=j] != _COLON:
            return err.fail("json: expected ':' after a key", j)
        return _skip_ws(p, j + 1, n)

    @inline(.always)
    def _outer(mut self) -> Tuple[Int, Int]:
        """The array or object around the one just closed, and its count
        (-1 for none)."""
        var depth = len(self._stack)
        if depth == 0:
            return (-1, 0)
        var o = self._stack.unsafe_ptr()[unsafe_offset=depth - 1]
        self._stack.resize(unsafe_uninit_length=depth - 1)
        return (o.node, o.count)

    # ---- repeated keys -----------------------------------------------------

    def _check_keys(
        mut self, np: _NodePtr, dp: _BytePtr, kp: Pointer[UInt32, MutAnyOrigin], pairs: Int, at: Int, mut err: _Fail
    ) -> Int:
        """Refuse (-1: `err`) a key that the object whose `pairs` key nodes
        are at `kp` (closing at `at`) has twice.

        Each key gets a cheap hash of its length and its first and last 8
        bytes (`_fingerprint`), which equal keys share. Up to `_PAIRWISE`
        pairs, every two hashes are compared, and the keys' bytes where the
        hashes are equal: at most 15 comparisons per key. Beyond, the keys
        go into an open-addressing table of at least twice their number,
        probed linearly and compared only where the hashes are equal. The
        hash is public, so keys can be chosen to collide; a key that probes
        more than `_PROBES` slots ends the table, and the object goes
        through `_check_sorted` instead. So the time is bounded by the
        keys' bytes (each compared with at most `_PROBES` others) plus,
        for such keys only, a sort of 16-byte values."""
        if pairs <= _PAIRWISE:
            var h = Array[UInt64, _PAIRWISE](uninitialized=True)
            var hp = h.unsafe_ptr()
            var x = 0
            while x < pairs:
                var k = np[unsafe_offset=Int(kp[unsafe_offset=x])]
                var f = _fingerprint(dp, Int(k.a), Int(k.b))
                var y = 0
                while y < x:
                    if hp[unsafe_offset=y] == f and _same_key(np, dp, Int(kp[unsafe_offset=x]), Int(kp[unsafe_offset=y])):
                        return err.fail("json: an object has a key twice", at)
                    y += 1
                hp[unsafe_offset=x] = f
                x += 1
            return 0
        self._hashed.clear()
        for x in range(pairs):
            var k = np[unsafe_offset=Int(kp[unsafe_offset=x])]
            self._hashed.append((UInt128(_fingerprint(dp, Int(k.a), Int(k.b))) << 64) | UInt128(x))
        var hp = self._hashed.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()
        if pairs <= _PARTITIONED:
            var r = self._table_check(np, dp, kp, hp, pairs, at, err)
            if r != 1:
                return r
            return self._check_sorted(np, dp, kp, pairs, at, err)
        # Into 256 buckets by the hashes' top 8 bits first, so that each
        # bucket's table stays in cache.
        self._counts.resize(257, 0)
        for b in range(257):
            self._counts[b] = 0
        for x in range(pairs):
            self._counts[Int(hp[unsafe_offset=x] >> 120) + 1] += 1
        for b in range(256):
            self._counts[b + 1] += self._counts[b]
        self._spare.resize(pairs, 0)
        for x in range(pairs):
            var r = hp[unsafe_offset=x]
            var b = Int(r >> 120)
            self._spare[Int(self._counts[b])] = r
            self._counts[b] += 1
        var sp = self._spare.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()
        var start = 0  # (each count is now its bucket's end)
        for b in range(256):
            var end = Int(self._counts[b])
            var r = self._table_check(np, dp, kp, sp.unsafe_offset(start), end - start, at, err)
            if r == 1:
                return self._check_sorted(np, dp, kp, pairs, at, err)
            if r < 0:
                return -1
            start = end
        return 0

    def _table_check(
        mut self,
        np: _NodePtr,
        dp: _BytePtr,
        kp: Pointer[UInt32, MutAnyOrigin],
        hp: Pointer[UInt128, MutAnyOrigin],
        count: Int,
        at: Int,
        mut err: _Fail,
    ) -> Int:
        """The `count` keys whose (hash, place) values are at `hp`, through
        the table: 0, -1 for a repeated key (`err`), or 1 when a key probed
        more than `_PROBES` slots (the caller sorts instead)."""
        if count < 2:
            return 0
        var size = 1 << (64 - Int(count_leading_zeros(UInt64(2 * count - 1))))
        self._table.clear()
        self._table.resize(size, 0)
        var tp = self._table.unsafe_ptr()
        var mask = size - 1
        for i in range(count):
            var r = hp[unsafe_offset=i]
            var h = UInt64(r >> 64)
            var x = Int(r & 0xFFFFFFFF)
            var kx = Int(kp[unsafe_offset=x])
            var tag = h & 0xFFFFFFFF00000000
            var slot = Int(h) & mask
            var probes = 0
            while True:
                var e = tp[unsafe_offset=slot]
                if e == 0:
                    tp[unsafe_offset=slot] = tag | UInt64(x + 1)
                    break
                if (e & 0xFFFFFFFF00000000) == tag:
                    var ky = Int(kp[unsafe_offset=Int(e & 0xFFFFFFFF) - 1])
                    if _same_key(np, dp, kx, ky):
                        return err.fail("json: an object has a key twice", at)
                probes += 1
                if probes > _PROBES:
                    return 1
                slot = (slot + 1) & mask
        return 0

    def _check_sorted(
        mut self, np: _NodePtr, dp: _BytePtr, kp: Pointer[UInt32, MutAnyOrigin], pairs: Int, at: Int, mut err: _Fail
    ) -> Int:
        """`_check_keys` for keys that collide in the table: the (cheap
        hash, key) values sorted, and keys compared only within a run of
        one hash: pair by pair in a run of up to `_RUN`; a longer run goes
        through `_check_run` and SipHash. The time is bounded by the keys'
        bytes plus sorts of 16-byte values, whatever the keys are."""
        self._hashed.clear()
        for x in range(pairs):
            var k = np[unsafe_offset=Int(kp[unsafe_offset=x])]
            self._hashed.append((UInt128(_fingerprint(dp, Int(k.a), Int(k.b))) << 64) | UInt128(x))
        _sort_hashed(self._hashed, self._spare, self._counts)
        var start = 0
        for x in range(1, pairs + 1):
            if x < pairs and (self._hashed[x] >> 64) == (self._hashed[start] >> 64):
                continue
            # [start, x) share one cheap hash.
            if x - start > _RUN:
                if self._check_run(np, dp, kp, start, x, at, err) < 0:
                    return -1
            else:
                for u in range(start, x):
                    for v in range(u + 1, x):
                        var ku = Int(kp[unsafe_offset=Int(self._hashed[u] & 0xFFFFFFFF)])
                        var kv = Int(kp[unsafe_offset=Int(self._hashed[v] & 0xFFFFFFFF)])
                        if _same_key(np, dp, ku, kv):
                            return err.fail("json: an object has a key twice", at)
            start = x
        return 0

    def _check_run(
        mut self,
        np: _NodePtr,
        dp: _BytePtr,
        kp: Pointer[UInt32, MutAnyOrigin],
        start: Int,
        end: Int,
        at: Int,
        mut err: _Fail,
    ) -> Int:
        """The keys `_hashed[start:end]`, which share one cheap hash: each
        hashed once with SipHash (`_key_hash`), sorted, and compared only
        within one SipHash, where a group of k keys costs whoever builds
        it about 2^(64(k-1)/k) evaluations."""
        self._run.clear()
        for r in range(start, end):
            var x = self._hashed[r] & 0xFFFFFFFF
            var k = np[unsafe_offset=Int(kp[unsafe_offset=Int(x)])]
            var key = Span[UInt8, MutAnyOrigin](unsafe_ptr=dp.unsafe_offset(Int(k.a)), length=Int(k.b))
            self._run.append((UInt128(_key_hash(key)) << 64) | x)
        _sort_hashed(self._run, self._spare, self._counts)
        var count = end - start
        var s = 0
        for x in range(1, count + 1):
            if x < count and (self._run[x] >> 64) == (self._run[s] >> 64):
                continue
            for u in range(s, x):
                for v in range(u + 1, x):
                    var ku = Int(kp[unsafe_offset=Int(self._run[u] & 0xFFFFFFFF)])
                    var kv = Int(kp[unsafe_offset=Int(self._run[v] & 0xFFFFFFFF)])
                    if _same_key(np, dp, ku, kv):
                        return err.fail("json: an object has a key twice", at)
            s = x
        return 0

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
        Float64's range, where it would be an infinity. Read by
        `json.number.read_float`, else (more than 19 digits, subnormals)
        by Mojo's `atof`."""
        self._check(n)
        var tag = self._nodes[n].tag
        if tag != _INT and tag != _NUM:
            raise JsonError(JsonError.TYPE, "json: not a number")
        var t = self._span(n)
        if tag == _NUM and t[len(t) - 1] > 57:  # (NaN, Infinity: Dialect.constants)
            if t[0] == 78:
                return FloatLiteral.nan
            return FloatLiteral.negative_infinity if t[0] == _MINUS else FloatLiteral.infinity
        var x: Float64 = 0
        if read_float[padded=True](t, x):  # (`_data` has room past every span)
            if x - x != 0:
                raise JsonError(JsonError.RANGE, "json: the number is out of Float64's range")
            return x
        try:
            x = atof(StringSlice(unsafe_from_utf8=t))
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

    def visit[V: Visitor](self, mut v: V, n: Int = 0) raises:
        """Call `v` for node `n` and everything in it, in document order:
        `begin_array(count)`, the elements, `end_array()`;
        `begin_object(count)`, then `key` and the value of each pair,
        `end_object()`. MISSING for no such node; `v`'s errors pass
        through, and the walk stops there. Its stack is inline up to 64
        levels, so a walk allocates nothing below that."""
        self._check(n)
        var end = n + self._size(n)
        var np = self._nodes.unsafe_ptr()
        var dp = self._data.unsafe_ptr().unsafe_origin_cast[ImmutAnyOrigin]()
        # Per open array or object: its nodes still to visit (an object's
        # keys and values both count) times 2, plus 1 for an object.
        var inline = Array[Int, 64](uninitialized=True)
        var ip = inline.unsafe_ptr()
        var spill = List[Int]()
        var depth = 0
        for i in range(n, end):
            var is_key = False
            if depth > 0:
                var t = ip[unsafe_offset=depth - 1] if depth <= 64 else spill[depth - 65]
                is_key = (t & 1) == 1 and (t >> 1) % 2 == 0
                t -= 2
                if depth <= 64:
                    ip[unsafe_offset=depth - 1] = t
                else:
                    spill[depth - 65] = t
            var node = np[unsafe_offset=i]
            var tag = node.tag
            if is_key:
                v.key(Span[UInt8, ImmutAnyOrigin](unsafe_ptr=dp.unsafe_offset(Int(node.a)), length=Int(node.b)))
            elif tag >= _ARR:
                var obj = tag == _OBJ
                if obj:
                    v.begin_object(Int(node.a))
                else:
                    v.begin_array(Int(node.a))
                if node.a > 0:
                    var t = (Int(node.a) * (2 if obj else 1)) * 2 + (1 if obj else 0)
                    if depth < 64:
                        ip[unsafe_offset=depth] = t
                    else:
                        spill.append(t)
                    depth += 1
                    continue
                if obj:
                    v.end_object()
                else:
                    v.end_array()
            elif tag == _STR:
                v.string(Span[UInt8, ImmutAnyOrigin](unsafe_ptr=dp.unsafe_offset(Int(node.a)), length=Int(node.b)))
            elif tag == _INT or tag == _NUM:
                v.number(
                    Span[UInt8, ImmutAnyOrigin](unsafe_ptr=dp.unsafe_offset(Int(node.a)), length=Int(node.b)),
                    tag == _INT,
                )
            elif tag == _NULL:
                v.null()
            else:
                v.boolean(tag == _TRUE)
            while depth > 0:
                var t = ip[unsafe_offset=depth - 1] if depth <= 64 else spill[depth - 65]
                if (t >> 1) != 0:
                    break
                if depth > 64:
                    _ = spill.pop()
                depth -= 1
                if (t & 1) == 1:
                    v.end_object()
                else:
                    v.end_array()

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


def parse(data: Span[UInt8, _], limits: Limits = Limits(), dialect: Dialect = Dialect()) raises JsonError -> Document:
    """`data` parsed into a new `Document` (see the module docs)."""
    var doc = Document()
    doc.parse(data, limits, dialect)
    return doc^


def parse(text: StringSlice, limits: Limits = Limits(), dialect: Dialect = Dialect()) raises JsonError -> Document:
    return parse(text.as_bytes(), limits, dialect)


@inline(.always)
def _is_digit(c: UInt8) -> Bool:
    return c >= 48 and c <= 57


@inline(.always)
def _load4(p: Pointer[UInt8, _], i: Int) -> UInt32:
    """The four bytes at `p + i`, little-endian."""
    return bitcast[DType.uint32, 1](p.unsafe_load[width=4](i))


@inline(.always)
def _skip_ws(p: Pointer[UInt8, _], i: Int, n: Int) -> Int:
    """The index of the first byte at or after `i` that is not JSON
    whitespace (space, tab, LF, CR): at once for no whitespace or one
    space, the common cases, else `_skip_ws_run`."""
    if i < n:
        var c = p[unsafe_offset=i]
        if c > 32:
            return i
        if c == 32 and i + 1 < n and p[unsafe_offset=i + 1] > 32:
            return i + 1
    return _skip_ws_run(p, i, n)


def _skip_ws_run(p: Pointer[UInt8, _], start: Int, n: Int) -> Int:
    """`_skip_ws`, `_V` bytes compared at once (indentation)."""
    var i = start
    while i + _V <= n:
        var v = p.unsafe_load[width=_V](i)
        var ws = (
            v.eq(SIMD[DType.uint8, _V](32))
            | v.eq(SIMD[DType.uint8, _V](10))
            | v.eq(SIMD[DType.uint8, _V](13))
            | v.eq(SIMD[DType.uint8, _V](9))
        )
        var other = ~pack_bits[_VBits](ws)
        if other != 0:
            return i + Int(count_trailing_zeros(other))
        i += _V
    while i < n:
        var c = p[unsafe_offset=i]
        if c > 32 or (c != 32 and c != 10 and c != 13 and c != 9):
            break
        i += 1
    return i


@inline(.always)
def _copy(dp: _BytePtr, o: Int, p: Pointer[UInt8, _], j: Int, count: Int, n: Int):
    """`count` bytes from `p + j` (input of length `n`) to `dp + o`, a
    vector at a time while the input has one to read (`dp` has `_SLACK`
    bytes past them)."""
    var k = 0
    while k < count:
        if j + k + _V <= n:
            dp.unsafe_store(o + k, p.unsafe_load[width=_V](j + k))
            k += _V
        else:
            dp[unsafe_offset=o + k] = p[unsafe_offset=j + k]
            k += 1


@inline(.always)
def _key(
    p: Pointer[UInt8, _], n: Int, i: Int, np: _NodePtr, mut nn: Int, dp: _BytePtr, mut dn: Int, mut err: _Fail
) -> Int:
    """An object's key and its ':' at `i`; returns where the value is
    (-1: `err`)."""
    if i >= n or p[unsafe_offset=i] != _QUOTE:
        return err.fail("json: expected a key (a string)", i)
    var s0 = dn
    var j = _string(p, n, i, dp, dn, err)
    if j < 0:
        return -1
    j = _skip_ws(p, j, n)
    np[unsafe_offset=nn] = _Node(_STR, UInt32(s0), UInt32(dn - s0))
    nn += 1
    if j >= n or p[unsafe_offset=j] != _COLON:
        return err.fail("json: expected ':' after a key", j)
    return _skip_ws(p, j + 1, n)


@no_inline
def _grow[T: Copyable & Deinitable](mut list: List[T], length: Int) -> Pointer[T, MutAnyOrigin]:
    """Twice the room in `list`, its first `length` items kept, and its
    length its new capacity (the parser writes through the pointer
    returned, and sets the length at the end)."""
    list.resize(unsafe_uninit_length=length)
    list.reserve(max(2 * list.capacity(), 16))
    list.resize(unsafe_uninit_length=list.capacity())
    return list.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()


@inline(.always)
def _string(p: Pointer[UInt8, _], n: Int, i: Int, dp: _BytePtr, mut dn: Int, mut err: _Fail) -> Int:
    """The string whose '"' is at `i`, unescaped into `dp + dn` (`dn`
    advanced past it); returns the index after its closing '"' (-1:
    `err`).

    Plain bytes (printable ASCII but '"' and '\\') go a vector at a time:
    each vector is stored whole, then the count advances to its first
    other byte, which `_SLACK` makes safe."""
    var j = i + 1
    var o = dn
    while True:
        if j + _V <= n:
            var v = p.unsafe_load[width=_V](j)
            dp.unsafe_store(o, v)
            var special = (
                (v - SIMD[DType.uint8, _V](0x20)).ge(SIMD[DType.uint8, _V](0x60))
                | v.eq(SIMD[DType.uint8, _V](_QUOTE))
                | v.eq(SIMD[DType.uint8, _V](_BACKSLASH))
            )
            var bits = pack_bits[_VBits](special)
            if bits == 0:
                j += _V
                o += _V
                continue
            var k = Int(count_trailing_zeros(bits))
            j += k
            o += k
        else:
            while j < n and is_plain(p[unsafe_offset=j]):
                dp[unsafe_offset=o] = p[unsafe_offset=j]
                j += 1
                o += 1
            if j >= n:
                return err.fail("json: the input ends inside a string", n)
        var b = p[unsafe_offset=j]
        if b == _QUOTE:
            dn = o
            return j + 1
        if b == _BACKSLASH:
            j = _escape(p, n, j, dp, o, err)
            if j < 0:
                return -1
        elif b >= 0x80:
            var m = _utf8_run(p, n, j, err.surrogates)
            if m < 0:
                return err.fail("json: a string is not UTF-8", -m - 1)
            _copy(dp, o, p, j, m - j, n)
            o += m - j
            j = m
        elif err.controls:
            dp[unsafe_offset=o] = b
            o += 1
            j += 1
        else:
            return err.fail("json: a control character in a string", j)


@no_inline
def _utf8_run(p: Pointer[UInt8, _], n: Int, start: Int, surrogates: Bool) -> Int:
    """Where the run of bytes >= 0x80 at `start` ends, each sequence in it
    valid UTF-8 (or, with `surrogates`, a surrogate in UTF-8's form, ED A0
    80 to ED BF BF); -1 - the index of the first that is not."""
    var m = start
    while m < n and p[unsafe_offset=m] >= 0x80:
        var length = utf8_length_at(p, n, m)
        if length == 0:
            if (
                surrogates
                and p[unsafe_offset=m] == 0xED
                and m + 2 < n
                and p[unsafe_offset=m + 1] >= 0xA0
                and p[unsafe_offset=m + 1] <= 0xBF
                and (p[unsafe_offset=m + 2] & 0xC0) == 0x80
            ):
                length = 3
            else:
                return -1 - m
        m += length
    return m


def _escape(p: Pointer[UInt8, _], n: Int, k: Int, dp: _BytePtr, mut o: Int, mut err: _Fail) -> Int:
    """The escape whose '\\' is at `k`, its character written at `dp + o`
    (`o` advanced); returns the index after it (-1: `err`)."""
    if k + 1 >= n:
        return err.fail("json: the input ends inside a string", n)
    var e = p[unsafe_offset=k + 1]
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
        var u = _hex4(p, n, k + 2, err)
        if u < 0:
            return -1
        var j = k + 6
        if u >= 0xDC00 and u <= 0xDFFF:
            if not err.surrogates:
                return err.fail("json: a lone surrogate in a string", k)
        elif u >= 0xD800 and u <= 0xDBFF:
            # A pair, or (Dialect.lone_surrogates) the high one alone, the
            # escape after it read on its own.
            if j + 1 >= n or p[unsafe_offset=j] != _BACKSLASH or p[unsafe_offset=j + 1] != 117:
                if not err.surrogates:
                    return err.fail("json: a lone surrogate in a string", k)
            else:
                var lo = _hex4(p, n, j + 2, err)
                if lo < 0:
                    return -1
                if lo >= 0xDC00 and lo <= 0xDFFF:
                    u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00)
                    j += 6
                elif not err.surrogates:
                    return err.fail("json: a lone surrogate in a string", k)
        _put_utf8(dp, o, u)
        return j
    else:
        return err.fail("json: an invalid escape in a string", k)
    dp[unsafe_offset=o] = b
    o += 1
    return k + 2


@inline(.always)
def _digits(p: Pointer[UInt8, _], n: Int, start: Int) -> Int:
    """The index of the first byte at or after `start` that is not a
    digit: eight bytes tested at once (a byte b is a digit when b ^ '0'
    is at most 9; adding 0x76 sets the top bit of any larger one, and the
    carries it makes only reach bytes above the first non-digit)."""
    var i = start
    while i + 8 <= n:
        var t = bitcast[DType.uint64, 1](p.unsafe_load[width=8](i)) ^ 0x3030303030303030
        var m = ((t + 0x7676767676767676) | t) & 0x8080808080808080
        if m != 0:
            return i + (Int(count_trailing_zeros(m)) >> 3)
        i += 8
    while i < n and _is_digit(p[unsafe_offset=i]):
        i += 1
    return i


@inline(.always)
def _number(
    p: Pointer[UInt8, _], n: Int, start: Int, dp: _BytePtr, mut dn: Int, mut tag: UInt8, mut err: _Fail
) -> Int:
    """The number at `start`, checked against the grammar and copied to
    `dp + dn` as text (`dn` advanced, `tag` _INT or _NUM); returns the
    index after it (-1: `err`)."""
    var i = start
    if p[unsafe_offset=i] == _MINUS:
        i += 1
    if i >= n or not _is_digit(p[unsafe_offset=i]):
        if err.constants and i < n and p[unsafe_offset=i] == 73:  # -Infinity
            tag = _NUM
            return _constant(p, n, start, dp, dn, err)
        return err.fail("json: a number needs digits", i)
    if p[unsafe_offset=i] == 48:
        i += 1
    else:
        i = _digits(p, n, i + 1)
    if i < n and p[unsafe_offset=i] == 46:  # '.'
        i += 1
        if i >= n or not _is_digit(p[unsafe_offset=i]):
            return err.fail("json: a fraction needs digits", i)
        i = _digits(p, n, i + 1)
        tag = _NUM
    if i < n and (p[unsafe_offset=i] | 0x20) == 101:  # e E
        i += 1
        if i < n and (p[unsafe_offset=i] == 43 or p[unsafe_offset=i] == _MINUS):
            i += 1
        if i >= n or not _is_digit(p[unsafe_offset=i]):
            return err.fail("json: an exponent needs digits", i)
        i = _digits(p, n, i + 1)
        tag = _NUM
    _copy(dp, dn, p, start, i - start, n)
    dn += i - start
    return i


@no_inline
def _constant(p: Pointer[UInt8, _], n: Int, i: Int, dp: _BytePtr, mut dn: Int, mut err: _Fail) -> Int:
    """`NaN`, `Infinity` or `-Infinity` at `i` (`Dialect.constants`),
    copied to `dp + dn`; returns the index after it. Anything else is not
    a JSON value."""
    if err.constants:
        var words: List[StaticString] = ["NaN", "Infinity", "-Infinity"]
        for w in words:
            var b = w.as_bytes()
            if i + len(b) <= n:
                var same = True
                for k in range(len(b)):
                    if p[unsafe_offset=i + k] != b[k]:
                        same = False
                        break
                if same:
                    for k in range(len(b)):
                        dp[unsafe_offset=dn + k] = b[k]
                    dn += len(b)
                    return i + len(b)
    return err.fail("json: not a JSON value", i)


def _hex4(p: Pointer[UInt8, _], n: Int, i: Int, mut err: _Fail) -> Int:
    """The four hex digits at `i` (a \\u escape's), or -1 (`err`)."""
    if i + 4 > n:
        return err.fail("json: a \\u escape needs four hex digits", i)
    var v = 0
    for k in range(4):
        var c = p[unsafe_offset=i + k]
        var d: Int
        if c >= 48 and c <= 57:
            d = Int(c) - 48
        elif c >= 97 and c <= 102:
            d = Int(c) - 87
        elif c >= 65 and c <= 70:
            d = Int(c) - 55
        else:
            return err.fail("json: a \\u escape needs four hex digits", i)
        v = v * 16 + d
    return v


@inline(.always)
def _put_utf8(dp: _BytePtr, mut o: Int, u: Int):
    """Write code point `u` (not a surrogate) as UTF-8 at `dp + o`."""
    if u < 0x80:
        dp[unsafe_offset=o] = UInt8(u)
        o += 1
    elif u < 0x800:
        dp[unsafe_offset=o] = UInt8(0xC0 | (u >> 6))
        dp[unsafe_offset=o + 1] = UInt8(0x80 | (u & 0x3F))
        o += 2
    elif u < 0x10000:
        dp[unsafe_offset=o] = UInt8(0xE0 | (u >> 12))
        dp[unsafe_offset=o + 1] = UInt8(0x80 | ((u >> 6) & 0x3F))
        dp[unsafe_offset=o + 2] = UInt8(0x80 | (u & 0x3F))
        o += 3
    else:
        dp[unsafe_offset=o] = UInt8(0xF0 | (u >> 18))
        dp[unsafe_offset=o + 1] = UInt8(0x80 | ((u >> 12) & 0x3F))
        dp[unsafe_offset=o + 2] = UInt8(0x80 | ((u >> 6) & 0x3F))
        dp[unsafe_offset=o + 3] = UInt8(0x80 | (u & 0x3F))
        o += 4


@inline(.always)
def _fingerprint(dp: _BytePtr, start: Int, size: Int) -> UInt64:
    """A cheap hash of the key of `size` bytes at `dp + start`, of its
    length and its first and last 8 bytes, so that equal keys have equal
    ones (`dp` has 8 bytes to read past any key: `_SLACK`)."""
    var a = bitcast[DType.uint64, 1](dp.unsafe_load[width=8](start))
    var b: UInt64 = 0
    if size >= 8:
        b = bitcast[DType.uint64, 1](dp.unsafe_load[width=8](start + size - 8))
    else:
        a &= (UInt64(1) << UInt64(8 * size)) - 1
    var h = (a ^ UInt64(size)) * 0x9E3779B97F4A7C15
    h = (h ^ (h >> 29) ^ b) * 0xBF58476D1CE4E5B9
    h ^= h >> 32
    comptime if _FAULTS:
        var t = h >> 56
        return (t << 56) | t  # (256 hashes, as `_key_hash`)
    return h


def _same_key(np: _NodePtr, dp: _BytePtr, x: Int, y: Int) -> Bool:
    """Whether string nodes `x` and `y` hold the same bytes."""
    var a = np[unsafe_offset=x]
    var b = np[unsafe_offset=y]
    if a.b != b.b:
        return False
    var i = Int(a.a)
    var j = Int(b.a)
    var n = Int(a.b)
    var k = 0
    while k + 16 <= n:
        if not (dp.unsafe_load[width=16](i + k) == dp.unsafe_load[width=16](j + k)):
            return False
        k += 16
    while k < n:
        if dp[unsafe_offset=i + k] != dp[unsafe_offset=j + k]:
            return False
        k += 1
    return True


def _sort_hashed(mut v: List[UInt128], mut spare: List[UInt128], mut counts: List[UInt32]):
    """Sort `v`: into buckets by the values' top 16 bits (one pass), then
    each bucket by `sort`. Never slower than `sort` alone, whatever the
    values; 300,000 keys parse in 31 ms instead of 79."""
    var n = len(v)
    if n < _BUCKETED:
        sort(v)
        return
    counts.resize(65537, 0)
    for b in range(65537):
        counts[b] = 0
    for r in v:
        counts[Int(r >> 112) + 1] += 1
    for b in range(65536):
        counts[b + 1] += counts[b]
    spare.resize(n, 0)
    for r in v:
        var b = Int(r >> 112)
        spare[Int(counts[b])] = r
        counts[b] += 1
    swap(v, spare)
    var start = 0  # (each count is now its bucket's end)
    for b in range(65536):
        var end = Int(counts[b])
        if end - start > 1:
            sort(Span(v)[start:end])
        start = end
