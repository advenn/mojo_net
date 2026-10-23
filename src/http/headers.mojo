"""HTTP fields (RFC 9110 5): an ordered, case-insensitive multimap of
header (or trailer) field lines, and the field syntax helpers the parser
shares.

`Headers` keeps every field line in the order it was added, with its name
in the case it was given (some HTTP/1.1 peers do care), and looks names up
ASCII-case-insensitively. A name may repeat (`Set-Cookie`, list-based
fields): `get` returns the first value, `find` and `get_all` reach the
rest, and `combined` joins them as RFC 9110 5.3 allows (never do that for
`Set-Cookie`, RFC 6265 3).

Values are bytes on the wire. RFC 9110 5.5 allows obs-text (0x80..0xFF),
which need not be UTF-8, so each value has two views: `value_bytes` and
`get_bytes` give the exact bytes; `value` and `get` give a string that is
those same bytes when they are UTF-8 (practically always) and otherwise a
lossy copy in which each invalid sequence became U+FFFD. `encode` writes
the exact bytes.

Validation: `add` and `set` take a token name (5.1) and a value made of
field-vchar, SP and HTAB (5.5), and raise `InvalidInput` for anything else,
CR, LF and NUL included, so a field can never smuggle a line break into a
message. Leading and trailing whitespace is not part of a value (5.5) and
is trimmed. Lookups take any string: a name that is not a token matches
nothing.

Storage: every name and value lives in one byte arena and each field is a
record of offsets into it, so a message's fields cost two buffers whatever
their count, and `clear()` keeps both for the next message. Replaced and
removed fields leave garbage in the arena, compacted once it outweighs the
live bytes.
"""

from std.memory import unsafe_memcpy

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError

comptime _HTAB: UInt8 = 9
comptime _LF: UInt8 = 10
comptime _CR: UInt8 = 13
comptime _SP: UInt8 = 32
comptime _DQUOTE: UInt8 = 34
comptime _COMMA: UInt8 = 44
comptime _COLON: UInt8 = 58
comptime _BACKSLASH: UInt8 = 92

# tchar (RFC 9110 5.6.2) as a 128-bit set: bit b of _TCHAR_LO for b < 64,
# bit b - 64 of _TCHAR_HI. tests/http/test_headers.mojo rebuilds both from
# the RFC's list.
comptime _TCHAR_LO: UInt64 = 0x03FF6CFA00000000
comptime _TCHAR_HI: UInt64 = 0x57FFFFFFC7FFFFFE

comptime _COMPACT_MIN = 4096
"""Garbage bytes below which the arena is never compacted."""

comptime _MIN_ARENA = 256
"""The smallest arena allocated."""


# ---- field syntax -------------------------------------------------------------


@inline(.always)
def is_tchar(b: UInt8) -> Bool:
    """A token character (RFC 9110 5.6.2): ALPHA, DIGIT or one of
    ``!#$%&'*+-.^_`|~``."""
    if b < 64:
        return ((_TCHAR_LO >> UInt64(b)) & 1) != 0
    if b < 128:
        return ((_TCHAR_HI >> UInt64(b - 64)) & 1) != 0
    return False


def is_token(s: Span[UInt8, _]) -> Bool:
    """`s` is a token: one or more tchars (methods, field names, codings)."""
    if len(s) == 0:
        return False
    for b in s:
        if not is_tchar(b):
            return False
    return True


@inline(.always)
def is_field_byte(b: UInt8) -> Bool:
    """A byte allowed in a field value (RFC 9110 5.5): VCHAR, obs-text, SP
    or HTAB. The rest are controls (NUL, CR, LF, DEL, ...), which this
    library never accepts from a peer or sends."""
    return (b >= 0x20 and b != 0x7F) or b == _HTAB


@inline(.always)
def is_ows(b: UInt8) -> Bool:
    return b == _SP or b == _HTAB


@inline(.always)
def lower_ascii(b: UInt8) -> UInt8:
    if b >= 65 and b <= 90:
        return b + 32
    return b


def eq_ignore_case(a: Span[UInt8, _], b: Span[UInt8, _]) -> Bool:
    """ASCII-case-insensitive equality (only A-Z fold; other bytes, UTF-8
    included, must match exactly)."""
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        var x = a[i]
        var y = b[i]
        if x != y and lower_ascii(x) != lower_ascii(y):
            return False
    return True


@fieldwise_init
struct Bounds(Sized, TrivialRegisterPassable):
    """A half-open byte range `[start, end)`."""

    var start: Int
    var end: Int

    @inline(.always)
    def __len__(self) -> Int:
        return self.end - self.start


def trim_ows(s: Span[UInt8, _]) -> Bounds:
    """`s` without leading and trailing SP/HTAB, as a range of `s`."""
    var lo = 0
    var hi = len(s)
    while lo < hi and is_ows(s[lo]):
        lo += 1
    while hi > lo and is_ows(s[hi - 1]):
        hi -= 1
    return Bounds(lo, hi)


def next_element(s: Span[UInt8, _], mut pos: Int) -> Optional[Bounds]:
    """The next non-empty element of the comma-separated list `s` (RFC 9110
    5.6.1) at or after `pos`, trimmed of OWS; `pos` moves past it. Commas
    inside quoted strings do not split. Empty elements (`a, ,b`) are
    skipped, as recipients must. None at the end of the list."""
    var n = len(s)
    while pos < n:
        var start = pos
        var quoted = False
        while pos < n:
            var b = s[pos]
            if quoted:
                if b == _BACKSLASH:
                    pos += 1  # quoted-pair: skip the escaped byte
                elif b == _DQUOTE:
                    quoted = False
            elif b == _DQUOTE:
                quoted = True
            elif b == _COMMA:
                break
            pos += 1
        var end = min(pos, n)
        if pos < n:
            pos += 1  # past the comma
        var t = trim_ows(s[start:end])
        if len(t) > 0:
            return Bounds(start + t.start, start + t.end)
    return None


comptime _SCAN = 32
"""Bytes checked per SIMD step in `_is_ascii`."""


def _is_ascii(s: Span[UInt8, _]) -> Bool:
    """No byte of `s` has the high bit set (OR-reduced a block at a time)."""
    var p = s.unsafe_ptr()
    var n = len(s)
    var i = 0
    var acc = SIMD[DType.uint8, _SCAN](0)
    while i + _SCAN <= n:
        acc |= p.unsafe_load[width=_SCAN](i)
        i += _SCAN
    var tail: UInt8 = acc.reduce_or()
    while i < n:
        tail |= p[unsafe_offset=i]
        i += 1
    return tail < 0x80


def _is_utf8(s: Span[UInt8, _]) -> Bool:
    try:
        _ = StringSlice(from_utf8=s)
        return True
    except:
        return False


# ---- Headers ------------------------------------------------------------------


@fieldwise_init
struct _Field(Copyable, TrivialRegisterPassable):
    """Offsets into `Headers._data`. `text` is `value` when the value bytes
    are UTF-8, else a lossy UTF-8 copy stored after them."""

    var name: Int
    var name_len: Int
    var value: Int
    var value_len: Int
    var text: Int
    var text_len: Int

    @inline(.always)
    def stored(self) -> Int:
        """Arena bytes this field owns."""
        var n = self.name_len + self.value_len
        if self.text != self.value:
            n += self.text_len
        return n


struct Headers(Copyable, Defaultable, Movable, Sized, Writable):
    """Ordered, case-insensitive HTTP fields (see the module docs)."""

    var _data: List[UInt8]
    """The arena. Its length is its capacity: the first `_used` bytes hold
    the names and values (like `ByteBuffer`, appends are a bounds check and
    a copy)."""
    var _used: Int
    var _fields: List[_Field]
    var _garbage: Int
    """Arena bytes no field refers to any more."""

    def __init__(out self):
        self._data = List[UInt8]()
        self._used = 0
        self._fields = List[_Field]()
        self._garbage = 0

    def __init__(out self, *, capacity: Int):
        """Room for `capacity` fields of average size without regrowing."""
        self._data = List[UInt8](unsafe_uninit_length=max(capacity, 0) * 32)
        self._used = 0
        self._fields = List[_Field](capacity=capacity)
        self._garbage = 0

    def __init__(out self, *, copy: Self):
        """A compact copy (garbage is not copied)."""
        self = Self(capacity=len(copy._fields))
        for f in copy._fields:
            self._push(
                copy._bytes(f.name, f.name_len),
                copy._bytes(f.value, f.value_len),
                utf8=f.text == f.value,
            )

    # ---- size -------------------------------------------------------------

    @inline(.always)
    def __len__(self) -> Int:
        """The number of field lines."""
        return len(self._fields)

    @inline(.always)
    def is_empty(self) -> Bool:
        return len(self._fields) == 0

    def clear(mut self):
        """Remove every field, keeping the allocated capacity."""
        self._used = 0
        self._fields.clear()
        self._garbage = 0

    def encoded_len(self) -> Int:
        """The bytes `encode` appends: `name: value` plus CRLF per field."""
        var n = 0
        for f in self._fields:
            n += f.name_len + f.value_len + 4
        return n

    # ---- adding -----------------------------------------------------------

    def add(mut self, name: StringSlice, value: StringSlice) raises IoError:
        """Append a field line (an existing `name` gets another line).
        `InvalidInput` if `name` is not a token or `value` holds a control
        byte; the value's leading and trailing whitespace is trimmed."""
        var n = name.as_bytes()
        var v = value.as_bytes()
        var t = Self._checked(n, v, "Headers.add")
        self._push(n, v[t.start : t.end], utf8=True)

    def set(mut self, name: StringSlice, value: StringSlice) raises IoError:
        """Replace every `name` field with one line holding `value`, at the
        position of the first one (at the end if there was none). Validated
        as `add`; on `InvalidInput` nothing changes."""
        var n = name.as_bytes()
        var v = value.as_bytes()
        var t = Self._checked(n, v, "Headers.set")
        var first = self._find(n, 0)
        if first < 0:
            self._push(n, v[t.start : t.end], utf8=True)
            return
        _ = self._drop_after(n, first + 1)
        var f = self._fields[first]
        self._garbage += f.stored()
        var nv = self._store(n, v[t.start : t.end], utf8=True)
        self._fields[first] = nv
        self._maybe_compact()

    @staticmethod
    def _checked(
        name: Span[UInt8, _], value: Span[UInt8, _], op: StaticString
    ) raises IoError -> Bounds:
        if not is_token(name):
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        for b in value:
            if not is_field_byte(b):
                raise IoError.of_kind(op, ErrorKind.InvalidInput)
        return trim_ows(value)

    @inline(.always)
    def _reserve(mut self, n: Int):
        """Room for `n` more arena bytes."""
        if self._used + n > len(self._data):
            self._grow(n)

    @no_inline
    def _grow(mut self, n: Int):
        var cap = max(self._used + n, 2 * len(self._data), _MIN_ARENA)
        var data = List[UInt8](unsafe_uninit_length=cap)
        if self._used > 0:
            unsafe_memcpy(
                dest=data.unsafe_ptr(),
                src=self._data.unsafe_ptr(),
                count=self._used,
            )
        self._data = data^

    @inline(.always)
    def _append(mut self, s: Span[UInt8, _]) -> Int:
        """Copy `s` (never a view of the arena) to the end of the arena and
        return where it starts."""
        var at = self._used
        var n = len(s)
        if n > 0:
            self._reserve(n)
            unsafe_memcpy(
                dest=self._data.unsafe_ptr().unsafe_offset(at),
                src=s.unsafe_ptr(),
                count=n,
            )
            self._used = at + n
        return at

    def _store(
        mut self, name: Span[UInt8, _], value: Span[UInt8, _], *, utf8: Bool
    ) -> _Field:
        """Copy `name` and `value` into the arena (they are already valid)
        and return the record; the caller places it. `utf8` says the value
        is known to be UTF-8 (ASCII, or from a string); otherwise it is
        checked, and a lossy copy is stored for the string view."""
        self._reserve(len(name) + len(value))
        var at = self._append(name)
        var vat = self._append(value)
        if utf8 or _is_ascii(value) or _is_utf8(value):
            return _Field(at, len(name), vat, len(value), vat, len(value))
        var text = String(from_utf8_lossy=value)
        var tat = self._append(text.as_bytes())
        return _Field(at, len(name), vat, len(value), tat, text.byte_length())

    @inline(.always)
    def _adopt(mut self, raw: Span[UInt8, _]) -> Int:
        """Copy a block of received field lines into the arena in one go
        and return where it starts, so the parser can record fields as
        offsets into it (`_push_at`) instead of copying each one. The
        bytes around the names and values (": ", CR LF) stay in the arena
        until the next `clear()`; they are not counted as garbage."""
        return self._append(raw)

    @inline(.always)
    def _push_at(mut self, name: Int, name_len: Int, value: Int, value_len: Int, *, utf8: Bool):
        """Append a field whose name and value are already in the arena
        (see `_adopt`) and valid. `utf8`: the value has no byte above 0x7F;
        otherwise it is checked, and a lossy copy is stored for the string
        view."""
        if utf8 or _is_utf8(self._bytes(value, value_len)):
            self._fields.append(_Field(name, name_len, value, value_len, value, value_len))
            return
        var text = String(from_utf8_lossy=self._bytes(value, value_len))
        var tat = self._append(text.as_bytes())
        self._fields.append(_Field(name, name_len, value, value_len, tat, text.byte_length()))

    @inline(.always)
    def _push(mut self, name: Span[UInt8, _], value: Span[UInt8, _], *, utf8: Bool):
        """Append a field whose name and value are already valid: the
        parser's entry point, after it checked the bytes itself (`utf8`:
        it saw no byte above 0x7F)."""
        var f = self._store(name, value, utf8=utf8)
        self._fields.append(f)

    # ---- removing ---------------------------------------------------------

    def remove(mut self, name: StringSlice) -> Int:
        """Remove every `name` field; return how many there were."""
        var n = self._drop_after(name.as_bytes(), 0)
        self._maybe_compact()
        return n

    def _drop_after(mut self, name: Span[UInt8, _], start: Int) -> Int:
        """Remove the `name` fields at index `start` or later, keeping the
        order of the rest. No compaction (callers may hold an index)."""
        var keep = start
        var dropped = 0
        for i in range(start, len(self._fields)):
            var f = self._fields[i]
            if eq_ignore_case(self._bytes(f.name, f.name_len), name):
                self._garbage += f.stored()
                dropped += 1
            else:
                self._fields[keep] = f
                keep += 1
        self._fields.resize(keep, _Field(0, 0, 0, 0, 0, 0))
        return dropped

    def _maybe_compact(mut self):
        if self._garbage < _COMPACT_MIN or self._garbage * 2 < self._used:
            return
        var live = self._used - self._garbage
        var data = List[UInt8](unsafe_uninit_length=max(live, _MIN_ARENA))
        var dst = data.unsafe_ptr()
        var src = self._data.unsafe_ptr()
        var at = 0
        for i in range(len(self._fields)):
            var f = self._fields[i]
            var nat = at
            unsafe_memcpy(dest=dst.unsafe_offset(at), src=src.unsafe_offset(f.name), count=f.name_len)
            at += f.name_len
            var vat = at
            unsafe_memcpy(dest=dst.unsafe_offset(at), src=src.unsafe_offset(f.value), count=f.value_len)
            at += f.value_len
            var tat = vat
            if f.text != f.value:
                tat = at
                unsafe_memcpy(dest=dst.unsafe_offset(at), src=src.unsafe_offset(f.text), count=f.text_len)
                at += f.text_len
            self._fields[i] = _Field(nat, f.name_len, vat, f.value_len, tat, f.text_len)
        self._data = data^
        self._used = at
        self._garbage = 0

    # ---- lookup -----------------------------------------------------------

    @inline(.always)
    def _bytes(self, at: Int, n: Int) -> Span[UInt8, origin_of(self._data)]:
        return Span(self._data)[at : at + n]

    @inline(.always)
    def _text(self, at: Int, n: Int) -> StringSlice[origin_of(self._data)]:
        return StringSlice(unsafe_from_utf8=Span(self._data)[at : at + n])

    def _find(self, name: Span[UInt8, _], start: Int) -> Int:
        for i in range(max(start, 0), len(self._fields)):
            var f = self._fields[i]
            if f.name_len == len(name) and eq_ignore_case(
                self._bytes(f.name, f.name_len), name
            ):
                return i
        return -1

    def find(self, name: StringSlice, start: Int = 0) -> Optional[Int]:
        """The index of the first `name` field at `start` or later."""
        var i = self._find(name.as_bytes(), start)
        if i < 0:
            return None
        return i

    def contains(self, name: StringSlice) -> Bool:
        return self._find(name.as_bytes(), 0) >= 0

    def count(self, name: StringSlice) -> Int:
        """How many field lines are named `name`."""
        var n = 0
        var i = self._find(name.as_bytes(), 0)
        while i >= 0:
            n += 1
            i = self._find(name.as_bytes(), i + 1)
        return n

    def get(self, name: StringSlice) -> Optional[StringSlice[origin_of(self._data)]]:
        """The first `name` value as a string, or None."""
        var i = self._find(name.as_bytes(), 0)
        if i < 0:
            return None
        var f = self._fields[i]
        return self._text(f.text, f.text_len)

    def get_bytes(self, name: StringSlice) -> Optional[Span[UInt8, origin_of(self._data)]]:
        """The first `name` value's exact bytes, or None."""
        var i = self._find(name.as_bytes(), 0)
        if i < 0:
            return None
        var f = self._fields[i]
        return self._bytes(f.value, f.value_len)

    def get_all(self, name: StringSlice) -> List[String]:
        """Every `name` value, in order."""
        var out = List[String]()
        var i = self._find(name.as_bytes(), 0)
        while i >= 0:
            var f = self._fields[i]
            out.append(String(self._text(f.text, f.text_len)))
            i = self._find(name.as_bytes(), i + 1)
        return out^

    def combined(self, name: StringSlice) -> Optional[String]:
        """Every `name` value joined with ", " (RFC 9110 5.3), or None.
        Only for list-based fields: never for `Set-Cookie`."""
        var i = self._find(name.as_bytes(), 0)
        if i < 0:
            return None
        var out = String()
        var first = True
        while i >= 0:
            var f = self._fields[i]
            if not first:
                out += ", "
            out += self._text(f.text, f.text_len)
            first = False
            i = self._find(name.as_bytes(), i + 1)
        return out^

    def has_token(self, name: StringSlice, token: StringSlice) -> Bool:
        """Whether any element of the comma-separated `name` fields equals
        `token`, ignoring ASCII case (`Connection: close`, `Expect:
        100-continue`). Elements compare whole: `chunked;q=1` is not
        `chunked`."""
        var tok = token.as_bytes()
        var i = self._find(name.as_bytes(), 0)
        while i >= 0:
            var f = self._fields[i]
            var v = self._bytes(f.value, f.value_len)
            var pos = 0
            while True:
                var e = next_element(v, pos)
                if not e:
                    break
                var b = e.value()
                if eq_ignore_case(v[b.start : b.end], tok):
                    return True
            i = self._find(name.as_bytes(), i + 1)
        return False

    # ---- by index ---------------------------------------------------------

    def _at(self, i: Int, op: StaticString) raises IoError -> _Field:
        if i < 0 or i >= len(self._fields):
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        return self._fields[i]

    def name(self, i: Int) raises IoError -> StringSlice[origin_of(self._data)]:
        """Field line `i`'s name, as given. `InvalidInput` out of range."""
        var f = self._at(i, "Headers.name")
        return self._text(f.name, f.name_len)

    def value(self, i: Int) raises IoError -> StringSlice[origin_of(self._data)]:
        """Field line `i`'s value as a string (lossy if not UTF-8)."""
        var f = self._at(i, "Headers.value")
        return self._text(f.text, f.text_len)

    def value_bytes(self, i: Int) raises IoError -> Span[UInt8, origin_of(self._data)]:
        """Field line `i`'s exact value bytes."""
        var f = self._at(i, "Headers.value_bytes")
        return self._bytes(f.value, f.value_len)

    # ---- output -----------------------------------------------------------

    def encode(self, mut out: ByteBuffer) raises IoError:
        """Append `name: value` CRLF per field line (exact bytes, in order).
        The blank line that ends a head is the caller's. `OutOfMemory`
        (and nothing appended) if `out` cannot hold them all."""
        var total = self.encoded_len()
        out.ensure_writable(total)
        var dst = out.writable_span().unsafe_ptr()
        var src = self._data.unsafe_ptr()
        var at = 0
        for f in self._fields:
            unsafe_memcpy(
                dest=dst.unsafe_offset(at),
                src=src.unsafe_offset(f.name),
                count=f.name_len,
            )
            at += f.name_len
            dst[unsafe_offset=at] = _COLON
            dst[unsafe_offset=at + 1] = _SP
            at += 2
            unsafe_memcpy(
                dest=dst.unsafe_offset(at),
                src=src.unsafe_offset(f.value),
                count=f.value_len,
            )
            at += f.value_len
            dst[unsafe_offset=at] = _CR
            dst[unsafe_offset=at + 1] = _LF
            at += 2
        out.commit(total)

    def write_to(self, mut writer: Some[Writer]):
        """`name: value` CRLF per field line (values as strings)."""
        for f in self._fields:
            writer.write(
                self._text(f.name, f.name_len),
                ": ",
                self._text(f.text, f.text_len),
                "\r\n",
            )
