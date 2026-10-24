"""RESP, the Redis serialization protocol (RESP2 and RESP3), sans-I/O:
commands built into a `ByteBuffer`, and replies parsed into `Value`, a flat
tree. ("RESP3 specification", redis/redis-specifications.)

Each value starts with a type byte:
- **Lines:** a simple string (`+`), a simple error (`-`), an integer (`:`),
  and RESP3's null (`_`), boolean (`#t`, `#f`), double (`,`, with `inf`,
  `-inf` and `nan`) and big number (`(`). The rest of the line, up to CRLF,
  is the value.
- **Bulk values:** a bulk string (`$`), and RESP3's blob error (`!`) and
  verbatim string (`=`, whose first four bytes name its format: `txt:`).
  The line gives the length; that many bytes and CRLF follow.
- **Aggregates:** an array (`*`), and RESP3's map (`%`), set (`~`) and push
  (`>`). The line gives the element count (a map's counts pairs); the
  elements follow.
- **RESP2's nulls,** `$-1` and `*-1`, are read as RESP3's null.
- **Attributes** (`|`, RESP3) are metadata before a value, shaped like a
  map: they are parsed, checked and dropped.
- **Streamed strings and aggregates** (`$?`, `*?`, ...) are refused
  (`Unsupported`): no server sends them.

`RespParser` reads replies as they arrive, resuming where the input ran
out (see `docs/redis.md`); a value that breaks the protocol or a limit
raises `InvalidData`. Commands are arrays of bulk strings (`Args`,
`write_command`), so an argument can hold any byte.
"""

from std.bit import count_trailing_zeros
from std.collections import Optional
from std.memory import pack_bits

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError

# Type bytes.
comptime _SIMPLE: UInt8 = 43  # '+'
comptime _ERROR: UInt8 = 45  # '-'
comptime _INTEGER: UInt8 = 58  # ':'
comptime _BULK: UInt8 = 36  # '$'
comptime _ARRAY: UInt8 = 42  # '*'
comptime _NULL: UInt8 = 95  # '_'
comptime _BOOLEAN: UInt8 = 35  # '#'
comptime _DOUBLE: UInt8 = 44  # ','
comptime _BIG_NUMBER: UInt8 = 40  # '('
comptime _BLOB_ERROR: UInt8 = 33  # '!'
comptime _VERBATIM: UInt8 = 61  # '='
comptime _MAP: UInt8 = 37  # '%'
comptime _SET: UInt8 = 126  # '~'
comptime _ATTRIBUTE: UInt8 = 124  # '|'
comptime _PUSH: UInt8 = 62  # '>'

comptime _CR: UInt8 = 13
comptime _LF: UInt8 = 10
comptime _MINUS: UInt8 = 45
comptime _PLUS: UInt8 = 43
comptime _DOT: UInt8 = 46
comptime _COLON: UInt8 = 58
comptime _QUESTION: UInt8 = 63

comptime DEFAULT_MAX_BULK = 512 * 1024 * 1024
"""512 MiB: the longest string a server keeps (its proto-max-bulk-len)."""
comptime DEFAULT_MAX_ELEMENTS = (1 << 32) - 1
comptime DEFAULT_MAX_DEPTH = 64
comptime DEFAULT_MAX_LINE = 64 * 1024

comptime MAX_ARG = 512 * 1024 * 1024
"""The longest argument a server reads (its proto-max-bulk-len)."""
comptime MAX_COMMAND = 1024 * 1024 * 1024
"""The longest command a server reads (its client-query-buffer-limit)."""

comptime E_PROTOCOL = "redis: malformed reply"
comptime E_LIMIT = "redis: reply over a limit"
comptime E_STREAMED = "redis: streamed RESP3 values are not supported"
comptime E_NOT = "redis: the value is not of that kind"
comptime E_NODE = "redis: no such node in the value"


@fieldwise_init
struct Kind(Equatable, TrivialRegisterPassable, Writable):
    """What a node of a `Value` is: RESP3's type byte."""

    var _b: UInt8

    comptime SIMPLE = Kind(_SIMPLE)
    """A simple string: one line (`+OK`)."""
    comptime ERROR = Kind(_ERROR)
    """A simple error: one line, its first word the code (`-ERR ...`)."""
    comptime INTEGER = Kind(_INTEGER)
    comptime BULK = Kind(_BULK)
    """A bulk string: any bytes."""
    comptime ARRAY = Kind(_ARRAY)
    comptime NULL = Kind(_NULL)
    """RESP3's null, and RESP2's null bulk string and null array."""
    comptime BOOLEAN = Kind(_BOOLEAN)
    comptime DOUBLE = Kind(_DOUBLE)
    comptime BIG_NUMBER = Kind(_BIG_NUMBER)
    comptime BLOB_ERROR = Kind(_BLOB_ERROR)
    """An error of any bytes."""
    comptime VERBATIM = Kind(_VERBATIM)
    """A string with its format (`txt`, `mkd`)."""
    comptime MAP = Kind(_MAP)
    comptime SET = Kind(_SET)
    comptime PUSH = Kind(_PUSH)
    """Out-of-band data (pub/sub messages, invalidations), never a reply."""

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self._b == other._b

    def is_aggregate(self) -> Bool:
        return _is_aggregate(self._b)

    def is_error(self) -> Bool:
        return self._b == _ERROR or self._b == _BLOB_ERROR

    def write_to(self, mut writer: Some[Writer]):
        var b = self._b
        if b == _SIMPLE:
            writer.write("SIMPLE")
        elif b == _ERROR:
            writer.write("ERROR")
        elif b == _INTEGER:
            writer.write("INTEGER")
        elif b == _BULK:
            writer.write("BULK")
        elif b == _ARRAY:
            writer.write("ARRAY")
        elif b == _NULL:
            writer.write("NULL")
        elif b == _BOOLEAN:
            writer.write("BOOLEAN")
        elif b == _DOUBLE:
            writer.write("DOUBLE")
        elif b == _BIG_NUMBER:
            writer.write("BIG_NUMBER")
        elif b == _BLOB_ERROR:
            writer.write("BLOB_ERROR")
        elif b == _VERBATIM:
            writer.write("VERBATIM")
        elif b == _MAP:
            writer.write("MAP")
        elif b == _SET:
            writer.write("SET")
        else:
            writer.write("PUSH")


@inline(.always)
def _is_aggregate(b: UInt8) -> Bool:
    return b == _ARRAY or b == _MAP or b == _SET or b == _PUSH or b == _ATTRIBUTE


@inline(.always)
def _has_bytes(b: UInt8) -> Bool:
    """Whether a node of this type keeps bytes in `_data`."""
    return (
        b == _BULK
        or b == _SIMPLE
        or b == _ERROR
        or b == _BLOB_ERROR
        or b == _VERBATIM
        or b == _DOUBLE
        or b == _BIG_NUMBER
    )


struct Value(Copyable, Movable, Writable):
    """A RESP value: one node, or an aggregate and everything in it.

    Nodes are numbered in pre-order: the root is 0, and each aggregate's
    elements follow it, each with its own. The accessors take a node's
    number (`n`, the root by default); a number out of range raises
    `InvalidInput`, and a node of another kind `InvalidData`.
    - **Navigation:** `count(n)` is an aggregate's size (a map's in pairs);
      `child(n, k)` the number of its element `k`; `key(n, i)` and
      `val(n, i)` a map's pair `i`; `get(n, key)` the value for a key.
    - **Strings:** `text(n)` and `bytes(n)`, for strings and errors (a
      verbatim string without its format), and as text for numbers too.
    - **Numbers:** `int(n)` for integers, booleans (0 or 1), big numbers and
      strings holding a decimal integer; `float(n)` for doubles, integers
      and strings holding a number; `bool(n)` for booleans and the
      integers 0 and 1, which RESP2 sends in their place."""

    var _kind: List[UInt8]
    var _x: List[Int]
    """Per node: where its bytes start in `_data`; an integer's or a
    boolean's value; an aggregate's element count (a map's: twice its
    pairs)."""
    var _y: List[Int]
    """Per node: its bytes' length; an aggregate's subtree size, itself
    included."""
    var _data: List[UInt8]

    def __init__(out self):
        self._kind = List[UInt8]()
        self._x = List[Int]()
        self._y = List[Int]()
        self._data = List[UInt8]()

    def clear(mut self):
        """Empty, keeping the buffers' capacity."""
        self._kind.clear()
        self._x.clear()
        self._y.clear()
        self._data.clear()

    def nodes(self) -> Int:
        """How many nodes the value has (0 while empty)."""
        return len(self._kind)

    # ---- building (the parser) ---------------------------------------------

    @inline(.always)
    def _add(mut self, kind: UInt8, x: Int, y: Int):
        self._kind.append(kind)
        self._x.append(x)
        self._y.append(y)

    def _add_bytes(mut self, kind: UInt8, b: Span[UInt8, _]):
        self._add(kind, len(self._data), len(b))
        self._data.extend(b)

    def _truncate(mut self, nodes: Int, data: Int):
        """Drop the nodes from `nodes` on, and the bytes from `data` on."""
        self._kind.resize(nodes, 0)
        self._x.resize(nodes, 0)
        self._y.resize(nodes, 0)
        self._data.resize(data, 0)

    # ---- reading -----------------------------------------------------------

    @inline(.always)
    def _check(self, n: Int) raises IoError:
        if n < 0 or n >= len(self._kind):
            raise IoError.of_kind(E_NODE, ErrorKind.InvalidInput)

    @inline(.always)
    def _size(self, n: Int) -> Int:
        """Nodes in `n`'s subtree."""
        return self._y[n] if _is_aggregate(self._kind[n]) else 1

    def _span(self, n: Int) -> Span[UInt8, origin_of(self._data)]:
        var start = self._x[n]
        return Span(self._data)[start : start + self._y[n]]

    def kind(self, n: Int = 0) raises IoError -> Kind:
        self._check(n)
        return Kind(self._kind[n])

    def is_null(self, n: Int = 0) raises IoError -> Bool:
        self._check(n)
        return self._kind[n] == _NULL

    def is_error(self, n: Int = 0) raises IoError -> Bool:
        self._check(n)
        return self._kind[n] == _ERROR or self._kind[n] == _BLOB_ERROR

    def count(self, n: Int = 0) raises IoError -> Int:
        """An aggregate's size: its elements, or a map's pairs."""
        self._check(n)
        var k = self._kind[n]
        if not _is_aggregate(k):
            raise IoError.of_kind(E_NOT, ErrorKind.InvalidData)
        return self._x[n] // 2 if k == _MAP else self._x[n]

    def child(self, n: Int, k: Int) raises IoError -> Int:
        """The node number of element `k` of aggregate `n` (a map's elements
        alternate: key, value). O(k)."""
        self._check(n)
        if not _is_aggregate(self._kind[n]):
            raise IoError.of_kind(E_NOT, ErrorKind.InvalidData)
        if k < 0 or k >= self._x[n]:
            raise IoError.of_kind(E_NODE, ErrorKind.InvalidInput)
        var c = n + 1
        for _ in range(k):
            c += self._size(c)
        return c

    def next(self, n: Int) raises IoError -> Int:
        """The node after `n`'s subtree: its next sibling, when it has one."""
        self._check(n)
        return n + self._size(n)

    def key(self, n: Int, i: Int) raises IoError -> Int:
        """The key of map `n`'s pair `i`."""
        if self.kind(n) != Kind.MAP:
            raise IoError.of_kind(E_NOT, ErrorKind.InvalidData)
        return self.child(n, 2 * i)

    def val(self, n: Int, i: Int) raises IoError -> Int:
        """The value of map `n`'s pair `i`."""
        if self.kind(n) != Kind.MAP:
            raise IoError.of_kind(E_NOT, ErrorKind.InvalidData)
        return self.child(n, 2 * i + 1)

    def get(self, n: Int, key: StringSlice) raises IoError -> Optional[Int]:
        """The value of map `n` for a string key, if it has one."""
        if self.kind(n) != Kind.MAP:
            raise IoError.of_kind(E_NOT, ErrorKind.InvalidData)
        var want = key.as_bytes()
        var c = n + 1
        for _ in range(self._x[n] // 2):
            var b = self._kind[c]
            if b == _BULK or b == _SIMPLE or b == _VERBATIM:
                var have = self._text_span(c)
                if len(have) == len(want):
                    var same = True
                    for i in range(len(want)):
                        if have[i] != want[i]:
                            same = False
                            break
                    if same:
                        return c + 1
            c += self._size(c)
            c += self._size(c)
        return None

    def _text_span(self, n: Int) -> Span[UInt8, origin_of(self._data)]:
        """A string node's bytes (a verbatim string's without its format)."""
        var s = self._span(n)
        if self._kind[n] == _VERBATIM:
            return s[4:]
        return s

    def bytes(self, n: Int = 0) raises IoError -> List[UInt8]:
        """A string's or an error's bytes (a verbatim string's without its
        format)."""
        self._check(n)
        var b = self._kind[n]
        if b == _BULK or b == _SIMPLE or b == _VERBATIM or b == _ERROR or b == _BLOB_ERROR:
            return List[UInt8](self._text_span(n))
        raise IoError.of_kind(E_NOT, ErrorKind.InvalidData)

    def text(self, n: Int = 0) raises IoError -> String:
        """A string or an error (UTF-8, invalid bytes replaced), or a number
        or boolean as text: "1" and "0" for true and false, as RESP2 sends
        them."""
        self._check(n)
        var b = self._kind[n]
        if _has_bytes(b):
            return String(from_utf8_lossy=self._text_span(n))
        if b == _INTEGER or b == _BOOLEAN:
            return String(self._x[n])
        raise IoError.of_kind(E_NOT, ErrorKind.InvalidData)

    def format(self, n: Int = 0) raises IoError -> String:
        """A verbatim string's format: "txt", "mkd", ..."""
        if self.kind(n) != Kind.VERBATIM:
            raise IoError.of_kind(E_NOT, ErrorKind.InvalidData)
        return String(from_utf8_lossy=self._span(n)[:3])

    def error_code(self, n: Int = 0) raises IoError -> String:
        """An error's code: its first word (ERR, WRONGTYPE, NOAUTH, ...)."""
        if not self.is_error(n):
            raise IoError.of_kind(E_NOT, ErrorKind.InvalidData)
        var s = self._span(n)
        var end = 0
        while end < len(s) and s[end] != 32:
            end += 1
        return String(from_utf8_lossy=s[:end])

    def int(self, n: Int = 0) raises IoError -> Int:
        """An integer; a boolean as 0 or 1; a big number or a string that
        holds a decimal integer within Int's range."""
        self._check(n)
        var b = self._kind[n]
        if b == _INTEGER or b == _BOOLEAN:
            return self._x[n]
        if b == _BULK or b == _SIMPLE or b == _VERBATIM or b == _BIG_NUMBER:
            return _decimal(self._text_span(n), E_NOT)
        raise IoError.of_kind(E_NOT, ErrorKind.InvalidData)

    def float(self, n: Int = 0) raises IoError -> Float64:
        """A double ("inf", "-inf" and "nan" included), an integer, or a
        big number or string that holds a number (RESP2 sends doubles as
        bulk strings). A number past a Float64's range raises."""
        self._check(n)
        var b = self._kind[n]
        if b == _INTEGER:
            return Float64(self._x[n])
        if b == _DOUBLE or b == _BULK or b == _SIMPLE or b == _VERBATIM or b == _BIG_NUMBER:
            var t = self._text_span(n)
            if not (_is_double(t) or (b == _BIG_NUMBER and _is_big(t))):
                raise IoError.of_kind(E_NOT, ErrorKind.InvalidData)
            var x: Float64
            try:
                x = atof(String(from_utf8_lossy=t))
            except:
                raise IoError.of_kind(E_NOT, ErrorKind.InvalidData)
            if (x == 0 or x * 0 != 0) and _nonzero_digit(t) and x == x:  # (past the range: an infinity or 0)
                raise IoError.of_kind("redis: number out of range for a float", ErrorKind.InvalidData)
            return x
        raise IoError.of_kind(E_NOT, ErrorKind.InvalidData)

    def bool(self, n: Int = 0) raises IoError -> Bool:
        """A boolean, or the integer 0 or 1 that RESP2 sends for one."""
        self._check(n)
        var b = self._kind[n]
        if b == _BOOLEAN or (b == _INTEGER and (self._x[n] == 0 or self._x[n] == 1)):
            return self._x[n] != 0
        raise IoError.of_kind(E_NOT, ErrorKind.InvalidData)

    # ---- rendering ---------------------------------------------------------

    def write_to(self, mut writer: Some[Writer]):
        """A canonical rendering, for tests and debugging: `+OK`, `-ERR x`,
        `:5`, `"bytes"` (escaped), `_`, `#t`, `,1.5`, `(123`, `!"err"`,
        `=txt:"text"`, `*[a b]`, `%{k v}`, `~[a]`, `>[a]`."""
        if len(self._kind) == 0:
            writer.write("(empty)")
            return
        _ = self._render(0, writer)

    def _render(self, n: Int, mut writer: Some[Writer]) -> Int:
        """Render node `n`; return the node after its subtree."""
        var b = self._kind[n]
        if _is_aggregate(b):
            var open = "%{" if b == _MAP else (
                "~[" if b == _SET else (">[" if b == _PUSH else "*[")
            )
            writer.write(open)
            var c = n + 1
            for i in range(self._x[n]):
                if i > 0:
                    writer.write(" ")
                c = self._render(c, writer)
            writer.write("}" if b == _MAP else "]")
            return c
        if b == _INTEGER:
            writer.write(":", self._x[n])
        elif b == _BOOLEAN:
            writer.write("#t" if self._x[n] != 0 else "#f")
        elif b == _NULL:
            writer.write("_")
        elif b == _SIMPLE or b == _ERROR or b == _DOUBLE or b == _BIG_NUMBER:
            writer.write(chr(Int(b)))
            _escape(writer, self._span(n), quoted=False)
        elif b == _BULK:
            _escape(writer, self._span(n), quoted=True)
        elif b == _BLOB_ERROR:
            writer.write("!")
            _escape(writer, self._span(n), quoted=True)
        else:  # VERBATIM
            var s = self._span(n)
            writer.write("=")
            _escape(writer, s[:3], quoted=False)
            writer.write(":")
            _escape(writer, s[4:], quoted=True)
        return n + 1


def _escape(mut writer: Some[Writer], s: Span[UInt8, _], *, quoted: Bool):
    """Printable ASCII as is, `"` and `\\` escaped when quoted, other bytes
    as `\\xHH`."""
    comptime digits = "0123456789abcdef"
    if quoted:
        writer.write('"')
    for c in s:
        if quoted and (c == 34 or c == 92):
            writer.write("\\", chr(Int(c)))
        elif c >= 32 and c <= 126:
            writer.write(chr(Int(c)))
        else:
            var d = digits.as_bytes()
            writer.write("\\x", chr(Int(d[Int(c >> 4)])), chr(Int(d[Int(c & 15)])))
    if quoted:
        writer.write('"')


# ---- number syntax ----------------------------------------------------------


comptime _W = 32
"""Bytes compared at once when searching for a line's end."""


@inline(.always)
def _find_lf(data: ImmSpan[UInt8, _], start: Int) -> Int:
    """Where the first LF at or after `start` is, or -1: a block of `_W`
    bytes compared at once, the first match a count of trailing zeros (the
    last block overlaps the one before rather than run past the end)."""
    var p = data.unsafe_ptr()
    var n = len(data)
    var i = start
    if n < _W:
        while i < n:
            if p[unsafe_offset=i] == _LF:
                return i
            i += 1
        return -1
    while i < n:
        var base = min(i, n - _W)
        var bits = pack_bits[DType.uint32](p.unsafe_load[width=_W](base).eq(SIMD[DType.uint8, _W](_LF))) >> UInt32(
            i - base
        )
        if bits != 0:
            return i + Int(count_trailing_zeros(bits))
        i = base + _W
    return -1


@inline(.always)
def _is_digit(c: UInt8) -> Bool:
    return c >= 48 and c <= 57


def _decimal(s: Span[UInt8, _], op: StaticString) raises IoError -> Int:
    """A decimal integer within Int's range, written as servers write
    them: an optional `-`, then digits without leading zeros."""
    var neg = len(s) > 0 and s[0] == _MINUS
    var i = 1 if neg else 0
    if i >= len(s) or (s[i] == 48 and len(s) > i + 1) or (neg and s[i] == 48):
        raise IoError.of_kind(op, ErrorKind.InvalidData)
    var limit: UInt64 = (UInt64(1) << 63) if neg else UInt64(Int.MAX)
    var v: UInt64 = 0
    var p = s.unsafe_ptr()
    while i < len(s):
        var c = p[unsafe_offset=i]
        if not _is_digit(c):
            raise IoError.of_kind(op, ErrorKind.InvalidData)
        var d = UInt64(c - 48)
        if v > (limit - d) // 10:
            raise IoError.of_kind(op, ErrorKind.InvalidData)
        v = v * 10 + d
        i += 1
    if neg:
        return Int.MIN if v == (UInt64(1) << 63) else -Int(v)
    return Int(v)


def _is_big(s: Span[UInt8, _]) -> Bool:
    """A big number: an optional `-`, then digits."""
    var i = 1 if len(s) > 0 and s[0] == _MINUS else 0
    if i >= len(s):
        return False
    while i < len(s):
        if not _is_digit(s[i]):
            return False
        i += 1
    return True


def _is_word(s: Span[UInt8, _], at: Int, word: StaticString) -> Bool:
    var w = word.as_bytes()
    if len(s) - at != len(w):
        return False
    for i in range(len(w)):
        if s[at + i] != w[i]:
            return False
    return True


def _is_double(s: Span[UInt8, _]) -> Bool:
    """A double as servers write one: `inf`, `-inf`, `nan`, or an optional
    sign, digits with an optional fraction, and an optional exponent."""
    var i = 0
    if i < len(s) and (s[i] == _MINUS or s[i] == _PLUS):
        i += 1
    if _is_word(s, i, "inf") or _is_word(s, 0, "nan"):
        return True
    var digits = 0
    while i < len(s) and _is_digit(s[i]):
        i += 1
        digits += 1
    if i < len(s) and s[i] == _DOT:
        i += 1
        while i < len(s) and _is_digit(s[i]):
            i += 1
            digits += 1
    if digits == 0:
        return False
    if i < len(s) and (s[i] == 101 or s[i] == 69):  # e, E
        i += 1
        if i < len(s) and (s[i] == _MINUS or s[i] == _PLUS):
            i += 1
        var exponent = 0
        while i < len(s) and _is_digit(s[i]):
            i += 1
            exponent += 1
        if exponent == 0:
            return False
    return i == len(s)


def _nonzero_digit(s: Span[UInt8, _]) -> Bool:
    """Whether a number's text has a non-zero digit before any exponent."""
    for c in s:
        if c == 101 or c == 69:
            return False
        if c >= 49 and c <= 57:
            return True
    return False


def _length(s: Span[UInt8, _], null: Bool) raises IoError -> Int:
    """A length or count; -1 (a RESP2 null) where `null` allows it."""
    if len(s) == 1 and s[0] == _QUESTION:
        raise IoError.of_kind(E_STREAMED, ErrorKind.Unsupported)
    if null and len(s) == 2 and s[0] == _MINUS and s[1] == 49:
        return -1
    if len(s) > 0 and s[0] == _MINUS:
        raise IoError.of_kind(E_PROTOCOL, ErrorKind.InvalidData)
    return _decimal(s, E_PROTOCOL)


# ---- parsing ----------------------------------------------------------------


@fieldwise_init
struct Limits(TrivialRegisterPassable):
    """What a reply may hold; past it, `InvalidData` from the header
    alone."""

    var max_bulk: Int
    """The longest bulk string, blob error or verbatim string."""
    var max_elements: Int
    """The most elements in one aggregate (a map's: twice its pairs)."""
    var max_depth: Int
    """The deepest nesting of aggregates (attributes included)."""
    var max_line: Int
    """The longest line, type byte and CRLF included."""

    def __init__(out self):
        self.max_bulk = DEFAULT_MAX_BULK
        self.max_elements = DEFAULT_MAX_ELEMENTS
        self.max_depth = DEFAULT_MAX_DEPTH
        self.max_line = DEFAULT_MAX_LINE


struct RespParser(Copyable, Movable):
    """Parses replies from a `ByteBuffer`, resuming where the input ran out.

    `parse(rx)` consumes what it reads and returns True once a whole value
    is in hand, which `take` then moves out. Partial state persists: the
    nodes complete so far, a stack of the aggregates still open, and the
    bytes of a bulk value still to come, which are copied out of `rx` as
    they arrive. So `rx` keeps at most one unfinished line."""

    var limits: Limits
    var _value: Value
    """The value being parsed."""
    var _open: List[Int]
    """The node of each aggregate still open, outermost first."""
    var _left: List[Int]
    """How many elements each still needs."""
    var _mark: List[Int]
    """`_data`'s length when each opened (to drop an attribute)."""
    var _bulk: Int
    """Payload bytes of the bulk value under way still to come (then its
    CRLF); -1 when none is under way."""
    var _scanned: Int
    """Bytes of `rx` searched for a line's end without finding one."""

    def __init__(out self, limits: Limits = Limits()):
        self.limits = limits
        self._value = Value()
        self._open = List[Int]()
        self._left = List[Int]()
        self._mark = List[Int]()
        self._bulk = -1
        self._scanned = 0

    def in_value(self) -> Bool:
        """Whether a value is partly parsed."""
        return self._value.nodes() > 0 or len(self._open) > 0 or self._bulk >= 0

    def take(mut self, mut into: Value):
        """Move the value `parse` completed into `into`, which keeps it; the
        parser goes on with `into`'s old buffers, cleared."""
        swap(self._value, into)
        self._value.clear()

    def parse(mut self, mut rx: ByteBuffer) raises IoError -> Bool:
        """Read from `rx` until a whole value is parsed (True) or the input
        runs out (False), consuming what was read."""
        var at = 0
        var whole = self._scan(rx.readable_span(), at)
        rx.consume(at)
        return whole

    def _scan(mut self, data: ImmSpan[UInt8, _], mut at: Int) raises IoError -> Bool:
        """Parse `data` from `at`, leaving `at` after what was read. The
        common cases (a bulk string whose bytes are all here, an integer)
        take the short path; the rest go through `_line`."""
        var p = data.unsafe_ptr()
        var n = len(data)
        while True:
            if self._bulk >= 0:
                if not self._bulk_bytes(data, at):
                    return False
                if self._done():
                    return True
                continue
            var lf = _find_lf(data, at + self._scanned)
            if lf < 0:
                if n - at >= self.limits.max_line:  # (it can only grow past the limit)
                    raise IoError.of_kind(E_LIMIT, ErrorKind.InvalidData)
                self._scanned = n - at
                return False
            self._scanned = 0
            if lf + 1 - at > self.limits.max_line:
                raise IoError.of_kind(E_LIMIT, ErrorKind.InvalidData)
            if lf - at < 2 or p[unsafe_offset=lf - 1] != _CR:  # (at least a type byte and CR)
                raise IoError.of_kind(E_PROTOCOL, ErrorKind.InvalidData)
            var t = p[unsafe_offset=at]
            var end = lf - 1  # (the CR)
            if t == _BULK or t == _INTEGER:
                # digits only, without a leading zero (or "0" alone), and
                # few enough not to overflow: else the general path
                var i = at + 1
                var v = 0
                var plain = end - i >= 1 and end - i <= 18 and (p[unsafe_offset=i] != 48 or end - i == 1)
                while plain and i < end:
                    var d = p[unsafe_offset=i]
                    if d < 48 or d > 57:
                        plain = False
                    else:
                        v = v * 10 + Int(d) - 48
                    i += 1
                if plain and t == _INTEGER:
                    self._value._add(_INTEGER, v, 0)
                    at = lf + 1
                    if self._done():
                        return True
                    continue
                if plain and v <= self.limits.max_bulk and lf + 1 + v + 2 <= n:  # (all of it here)
                    var body = lf + 1
                    if p[unsafe_offset=body + v] != _CR or p[unsafe_offset=body + v + 1] != _LF:
                        raise IoError.of_kind(E_PROTOCOL, ErrorKind.InvalidData)
                    self._value._add_bytes(_BULK, data[body : body + v])
                    at = body + v + 2
                    if self._done():
                        return True
                    continue
            var line = data[at + 1 : end]
            at = lf + 1
            if self._line(t, line, data, at):
                return True

    def _line(
        mut self, t: UInt8, line: ImmSpan[UInt8, _], data: ImmSpan[UInt8, _], mut at: Int
    ) raises IoError -> Bool:
        """Act on a line of type `t` (`at` is just past it, in `data`). True
        when it completed the value."""
        if t == _BULK or t == _BLOB_ERROR or t == _VERBATIM:
            var size = _length(line, null=t == _BULK)
            if size == -1:
                self._value._add(_NULL, 0, 0)
                return self._done()
            if size > self.limits.max_bulk:
                raise IoError.of_kind(E_LIMIT, ErrorKind.InvalidData)
            if t == _VERBATIM and size < 4:  # (its format, and ':')
                raise IoError.of_kind(E_PROTOCOL, ErrorKind.InvalidData)
            self._value._add(t, len(self._value._data), size)
            self._bulk = size
            if not self._bulk_bytes(data, at):
                return False  # (its bytes are still to come)
            return self._done()
        if _is_aggregate(t):
            var count = _length(line, null=t == _ARRAY)
            if count == -1:
                self._value._add(_NULL, 0, 0)
                return self._done()
            var pairs = t == _MAP or t == _ATTRIBUTE
            if count > (self.limits.max_elements // 2 if pairs else self.limits.max_elements):
                raise IoError.of_kind(E_LIMIT, ErrorKind.InvalidData)
            if len(self._open) >= self.limits.max_depth:
                raise IoError.of_kind(E_LIMIT, ErrorKind.InvalidData)
            if t == _PUSH and self._value.nodes() > 0:  # (out of band: never inside a value)
                raise IoError.of_kind(E_PROTOCOL, ErrorKind.InvalidData)
            var elements = 2 * count if pairs else count
            var node = self._value.nodes()
            if elements == 0:
                if t == _ATTRIBUTE:
                    return False  # (no metadata at all)
                self._value._add(t, 0, 1)
                return self._done()
            self._value._add(t, elements, 1)
            self._open.append(node)
            self._left.append(elements)
            self._mark.append(len(self._value._data))
            return False
        if t == _INTEGER:
            self._value._add(t, _decimal(line, E_PROTOCOL), 0)
        elif t == _SIMPLE or t == _ERROR:
            for c in line:
                if c == _CR:
                    raise IoError.of_kind(E_PROTOCOL, ErrorKind.InvalidData)
            self._value._add_bytes(t, line)
        elif t == _NULL:
            if len(line) != 0:
                raise IoError.of_kind(E_PROTOCOL, ErrorKind.InvalidData)
            self._value._add(t, 0, 0)
        elif t == _BOOLEAN:
            if len(line) != 1 or (line[0] != 116 and line[0] != 102):  # t, f
                raise IoError.of_kind(E_PROTOCOL, ErrorKind.InvalidData)
            self._value._add(t, 1 if line[0] == 116 else 0, 0)
        elif t == _DOUBLE:
            if not _is_double(line):
                raise IoError.of_kind(E_PROTOCOL, ErrorKind.InvalidData)
            self._value._add_bytes(t, line)
        elif t == _BIG_NUMBER:
            if not _is_big(line):
                raise IoError.of_kind(E_PROTOCOL, ErrorKind.InvalidData)
            self._value._add_bytes(t, line)
        else:
            raise IoError.of_kind(E_PROTOCOL, ErrorKind.InvalidData)
        return self._done()

    def _bulk_bytes(mut self, data: ImmSpan[UInt8, _], mut at: Int) raises IoError -> Bool:
        """Copy what has come of the bulk value under way; True once it and
        its CRLF are complete."""
        if self._bulk > 0:
            var n = min(self._bulk, len(data) - at)
            if n == 0:
                return False
            self._value._data.extend(data[at : at + n])
            at += n
            self._bulk -= n
            if self._bulk > 0:
                return False
        if len(data) - at < 2:
            return False
        var p = data.unsafe_ptr()
        if p[unsafe_offset=at] != _CR or p[unsafe_offset=at + 1] != _LF:
            raise IoError.of_kind(E_PROTOCOL, ErrorKind.InvalidData)
        at += 2
        self._bulk = -1
        var node = self._value.nodes() - 1
        if self._value._kind[node] == _VERBATIM and self._value._data[self._value._x[node] + 3] != _COLON:
            raise IoError.of_kind(E_PROTOCOL, ErrorKind.InvalidData)
        return True

    def _done(mut self) -> Bool:
        """A node is complete: count it toward its aggregate, closing every
        aggregate that it completes. True when the whole value is."""
        while len(self._open) > 0:
            var top = len(self._open) - 1
            var left = self._left.unsafe_get(top) - 1
            self._left.unsafe_set(top, left)
            if left > 0:
                return False
            var node = self._open.pop()
            _ = self._left.pop()
            var mark = self._mark.pop()
            if self._value._kind[node] == _ATTRIBUTE:  # (metadata: no element of what holds it)
                self._value._truncate(node, mark)
                return False
            self._value._y[node] = self._value.nodes() - node
        return True


# ---- commands ---------------------------------------------------------------


struct Args(Copyable, Movable, Sized):
    """A command and its arguments, each sent as a bulk string: any bytes,
    never spliced into a line. The first is the command's name."""

    var _data: List[UInt8]
    var _at: List[Int]
    """Where each argument starts in `_data` (it ends where the next one
    starts)."""

    def __init__(out self):
        self._data = List[UInt8]()
        self._at = List[Int]()

    def __init__[*Ts: Writable](out self, *args: *Ts):
        """Each argument in its text form: `Args("SET", "k", 5)`."""
        self._data = List[UInt8]()
        self._at = List[Int]()
        comptime for i in range(args.__len__()):
            self.add(args[i])

    def __len__(self) -> Int:
        return len(self._at)

    def add_text(mut self, arg: StringSlice):
        self._at.append(len(self._data))
        self._data.extend(arg.as_bytes())

    def add_bytes(mut self, arg: Span[UInt8, _]):
        self._at.append(len(self._data))
        self._data.extend(arg)

    def add[T: Writable](mut self, value: T):
        """Any writable value, in its text form (an `Int`, a `Float64`, a
        string)."""
        self.add_text(String(value))

    def arg(self, i: Int) -> Span[UInt8, origin_of(self._data)]:
        var end = self._at[i + 1] if i + 1 < len(self._at) else len(self._data)
        return Span(self._data)[self._at[i] : end]

    def is_named(self, i: Int, name: StaticString) -> Bool:
        """Whether argument `i` is `name`, ASCII case aside (`name` in
        upper case)."""
        if i >= len(self._at):
            return False
        var a = self.arg(i)
        var w = name.as_bytes()
        if len(a) != len(w):
            return False
        for k in range(len(w)):
            var c = a[k]
            if c >= 97 and c <= 122:
                c -= 32
            if c != w[k]:
                return False
        return True


@inline(.always)
def _digits(v: Int) -> Int:
    var n = 1
    var x = v
    while x >= 10:
        x //= 10
        n += 1
    return n


def _put_header(mut out: ByteBuffer, t: UInt8, v: Int) raises IoError:
    """`t`, then `v` in decimal, then CRLF (room already made)."""
    var n = _digits(v)
    var w = out.writable_span()
    w[0] = t
    var x = v
    for i in range(n, 0, -1):
        w[i] = UInt8(48 + x % 10)
        x //= 10
    w[n + 1] = _CR
    w[n + 2] = _LF
    out.commit(n + 3)


def write_command(mut out: ByteBuffer, args: Args) raises IoError:
    """A command: an array of bulk strings, written whole or not at all.
    `InvalidInput` for no arguments, an argument over `MAX_ARG`, or a
    command over `MAX_COMMAND` (a server would close the connection);
    `OutOfMemory` when it does not fit `out`."""
    var count = len(args)
    if count == 0:
        raise IoError.of_kind("redis: a command needs a name", ErrorKind.InvalidInput)
    var size = 1 + _digits(count) + 2
    for i in range(count):
        var a = len(args.arg(i))
        if a > MAX_ARG:
            raise IoError.of_kind("redis: argument too long", ErrorKind.InvalidInput)
        size += 1 + _digits(a) + 2 + a + 2
    if size > MAX_COMMAND:
        raise IoError.of_kind("redis: command too long", ErrorKind.InvalidInput)
    out.ensure_writable(size)
    _put_header(out, _ARRAY, count)
    for i in range(count):
        var a = args.arg(i)
        _put_header(out, _BULK, len(a))
        out.write_bytes(a)
        out.write_byte(_CR)
        out.write_byte(_LF)
