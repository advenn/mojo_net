"""HTTP/1.1 message heads (RFC 9112 2-5), sans-I/O: `HeadParser` finds a
head in received bytes and parses it into a `RequestHead` or a
`ResponseHead`; both heads also encode themselves.

Incremental: call `request` (or `response`) with the unconsumed bytes each
time more arrive, the same prefix plus whatever came since. It returns None
until the blank line that ends the head is in, resuming its scan where the
previous call stopped, so the total work is linear in the head size however
the bytes are split. Then it parses the head once and returns how many
bytes it took; the bytes after it (a body, a pipelined request) are the
caller's, and the parser is ready for the next head.

Strictness (docs/http.md, "Strictness"). Requests are parsed strictly:
- CRLF line endings; a bare LF or a bare CR is refused;
- one SP between the request-line's parts, a token method, a request target
  of visible ASCII, and `HTTP/<digit>.<digit>` (case-sensitive);
- field names are tokens with no whitespace before the colon; values hold
  no control bytes (CR, LF, NUL and DEL included);
- obs-fold (a line starting with SP/HTAB) and whitespace before the first
  field line are refused.
Responses follow the same rules with the two leniencies RFC 9112 allows and
old servers need: a bare LF ends a line (2.2), and obs-fold is replaced by
a single SP (5.2). Leading empty lines before either start line are skipped
(2.2). A status code must be 100..599; the reason phrase may be empty or
missing, and is decoded lossily (it carries no meaning).

Limits (`Limits`) bound the start line, the whole head (leading empty lines
included) and the number of field lines, and are checked as bytes arrive,
so a peer cannot make the caller buffer more than `max_head` bytes.

Errors raise `InvalidData`, with an `op` naming the rule broken (the `E_*`
constants). After an error the stream is unusable. `error_status()` gives
the status a server answers a bad request with: 414 for an over-long
request line, 431 for an over-large head or too many fields, else 400.
"""

from std.bit import count_trailing_zeros
from std.memory import pack_bits

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError

from .headers import Headers, is_field_byte, is_ows, is_tchar, is_token
from .types import Version, check_status

comptime _HTAB: UInt8 = 9
comptime _LF: UInt8 = 10
comptime _CR: UInt8 = 13
comptime _SP: UInt8 = 32
comptime _COLON: UInt8 = 58

comptime _SCAN = 32
"""Bytes compared per SIMD step."""

comptime E_REQUEST_LINE = "http: bad request line"
comptime E_STATUS_LINE = "http: bad status line"
comptime E_FIELD_LINE = "http: bad field line"
comptime E_FIELD_VALUE = "http: bad field value"
comptime E_BARE_LF = "http: bare LF"
comptime E_OBS_FOLD = "http: obs-fold"
comptime E_LEADING_WS = "http: whitespace before the first field line"
comptime E_START_LINE_TOO_LONG = "http: start line too long"
comptime E_HEAD_TOO_LARGE = "http: head too large"
comptime E_TOO_MANY_FIELDS = "http: too many field lines"


# ---- limits and heads -----------------------------------------------------------


struct Limits(TrivialRegisterPassable):
    """Bounds on one message head. Every count is in bytes except
    `max_fields`."""

    var max_head: Int
    """The whole head: leading empty lines, the start line, the field lines
    and the blank line that ends it."""
    var max_start_line: Int
    """The request line or status line, without its line ending."""
    var max_fields: Int
    """Field lines (obs-fold continuation lines count too)."""

    comptime DEFAULT_MAX_HEAD = 64 * 1024
    comptime DEFAULT_MAX_START_LINE = 8 * 1024
    comptime DEFAULT_MAX_FIELDS = 100

    def __init__(
        out self,
        *,
        max_head: Int = Self.DEFAULT_MAX_HEAD,
        max_start_line: Int = Self.DEFAULT_MAX_START_LINE,
        max_fields: Int = Self.DEFAULT_MAX_FIELDS,
    ):
        self.max_head = max_head
        self.max_start_line = max_start_line
        self.max_fields = max_fields


struct RequestHead(Copyable, Defaultable, Movable, Writable):
    """A request line and its header fields."""

    var method: String
    var target: String
    """The request target as sent: origin-form (`/path?query`),
    absolute-form, authority-form (CONNECT) or `*` (OPTIONS)."""
    var version: Version
    var headers: Headers

    def __init__(out self):
        self.method = String()
        self.target = String()
        self.version = Version.HTTP_1_1
        self.headers = Headers()

    def __init__(
        out self,
        method: StringSlice,
        target: StringSlice,
        version: Version = Version.HTTP_1_1,
    ):
        self.method = String(method)
        self.target = String(target)
        self.version = version
        self.headers = Headers()

    def encoded_len(self) -> Int:
        return (
            self.method.byte_length()
            + self.target.byte_length()
            + 12
            + self.headers.encoded_len()
            + 2
        )

    def encode(self, mut out: ByteBuffer) raises IoError:
        """Append the head in wire format, blank line included.
        `InvalidInput` (nothing appended) unless the method is a token and
        the target is visible ASCII; `OutOfMemory` if `out` is too small."""
        var m = self.method.as_bytes()
        var t = self.target.as_bytes()
        if not is_token(m) or not _is_target(t) or not _version_ok(self.version):
            raise IoError.of_kind("RequestHead.encode", ErrorKind.InvalidInput)
        out.ensure_writable(self.encoded_len())
        out.write_bytes(m)
        out.write_byte(_SP)
        out.write_bytes(t)
        out.write_byte(_SP)
        _write_version(self.version, out)
        _write_crlf(out)
        self.headers.encode(out)
        _write_crlf(out)

    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            self.method, " ", self.target, " ", self.version, "\r\n", self.headers, "\r\n"
        )


struct ResponseHead(Copyable, Defaultable, Movable, Writable):
    """A status line and its header fields."""

    var version: Version
    var status: Int
    var reason: String
    var headers: Headers

    def __init__(out self):
        self.version = Version.HTTP_1_1
        self.status = 200
        self.reason = String()
        self.headers = Headers()

    def __init__(
        out self,
        status: Int,
        reason: StringSlice = "",
        version: Version = Version.HTTP_1_1,
    ):
        self.version = version
        self.status = status
        self.reason = String(reason)
        self.headers = Headers()

    def encoded_len(self) -> Int:
        return 13 + self.reason.byte_length() + 2 + self.headers.encoded_len() + 2

    def encode(self, mut out: ByteBuffer) raises IoError:
        """Append the head in wire format, blank line included.
        `InvalidInput` (nothing appended) unless `100 <= status <= 599` and
        the reason holds no control bytes; `OutOfMemory` if `out` is too
        small."""
        check_status(self.status, "ResponseHead.encode")
        var r = self.reason.as_bytes()
        for b in r:
            if not is_field_byte(b):
                raise IoError.of_kind("ResponseHead.encode", ErrorKind.InvalidInput)
        if not _version_ok(self.version):
            raise IoError.of_kind("ResponseHead.encode", ErrorKind.InvalidInput)
        out.ensure_writable(self.encoded_len())
        _write_version(self.version, out)
        out.write_byte(_SP)
        out.write_byte(UInt8(48 + self.status // 100))
        out.write_byte(UInt8(48 + self.status // 10 % 10))
        out.write_byte(UInt8(48 + self.status % 10))
        out.write_byte(_SP)
        out.write_bytes(r)
        _write_crlf(out)
        self.headers.encode(out)
        _write_crlf(out)

    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            self.version, " ", self.status, " ", self.reason, "\r\n", self.headers, "\r\n"
        )


@inline(.always)
def _version_ok(v: Version) -> Bool:
    return v.major >= 0 and v.major <= 9 and v.minor >= 0 and v.minor <= 9


def _write_version(v: Version, mut out: ByteBuffer) raises IoError:
    for b in "HTTP/".as_bytes():
        out.write_byte(b)
    out.write_byte(UInt8(48 + v.major))
    out.write_byte(UInt8(46))
    out.write_byte(UInt8(48 + v.minor))


@inline(.always)
def _write_crlf(mut out: ByteBuffer) raises IoError:
    out.write_byte(_CR)
    out.write_byte(_LF)


# ---- byte classes and scanning ----------------------------------------------------
#
# The scans test 32 bytes at a time and turn the comparison into a bitmask
# (`pack_bits`), so the first match is a count of trailing zeros. A block
# that would run past the end of `data` is loaded from `len(data) - 32`
# instead and its mask shifted, so no load leaves the buffer and short lines
# need no byte-by-byte tail. Buffers under 32 bytes are scanned byte by byte.

comptime _V = SIMD[DType.uint8, _SCAN]
comptime _M = SIMD[DType.bool, _SCAN]


@inline(.always)
def _is_target_byte(b: UInt8) -> Bool:
    """VCHAR: a request target is visible ASCII (RFC 3986 characters; raw
    UTF-8 or controls are refused)."""
    return b > 0x20 and b < 0x7F


def _is_target(s: Span[UInt8, _]) -> Bool:
    if len(s) == 0:
        return False
    for b in s:
        if not _is_target_byte(b):
            return False
    return True


@inline(.always)
def _tchar_mask(v: _V) -> _M:
    """`is_tchar` for 32 bytes at once (tests/http/test_parse.mojo compares
    the two on every byte value)."""
    var alpha = ((v | _V(0x20)) - _V(0x61)).lt(_V(26))
    var digit = (v - _V(0x30)).lt(_V(10))
    var r1 = (v - _V(0x23)).lt(_V(5))  # # $ % & '
    var r2 = (v - _V(0x2A)).lt(_V(2))  # * +
    var r3 = (v - _V(0x2D)).lt(_V(2))  # - .
    var r4 = (v - _V(0x5E)).lt(_V(3))  # ^ _ `
    var e = v.eq(_V(0x21)) | v.eq(_V(0x7C)) | v.eq(_V(0x7E))  # ! | ~
    return alpha | digit | r1 | r2 | r3 | r4 | e


@inline(.always)
def _lf_v(v: _V) -> _M:
    return v.eq(_V(_LF))


@inline(.always)
def _lf_b(b: UInt8) -> Bool:
    return b == _LF


@inline(.always)
def _not_tchar_v(v: _V) -> _M:
    return ~_tchar_mask(v)


@inline(.always)
def _not_tchar_b(b: UInt8) -> Bool:
    return not is_tchar(b)


@inline(.always)
def _not_target_v(v: _V) -> _M:
    return ~(v - _V(0x21)).lt(_V(0x5E))


@inline(.always)
def _not_target_b(b: UInt8) -> Bool:
    return not _is_target_byte(b)


@inline(.always)
def _first[
    stop_v: def(_V) thin -> _M, stop_b: def(UInt8) thin -> Bool
](data: ImmSpan[UInt8, _], lo: Int, hi: Int) -> Int:
    """The first index in `[lo, hi)` whose byte `stop_v` / `stop_b` (the
    same predicate, vector and scalar) matches, else `hi`."""
    var p = data.unsafe_ptr()
    var n = len(data)
    var i = lo
    if n < _SCAN:
        while i < hi and not stop_b(p[unsafe_offset=i]):
            i += 1
        return i
    while i < hi:
        var base = min(i, n - _SCAN)
        var bits = pack_bits[DType.uint32](
            stop_v(p.unsafe_load[width=_SCAN](base))
        ) >> UInt32(i - base)
        if bits != 0:
            return min(i + Int(count_trailing_zeros(bits)), hi)
        i = base + _SCAN
    return hi


@inline(.always)
def _value_class(data: ImmSpan[UInt8, _], lo: Int, hi: Int) -> Int:
    """-1 if `data[lo:hi]` holds a byte no field value may (a control other
    than HTAB, or DEL), else 1 if it holds one above 0x7F, else 0."""
    var p = data.unsafe_ptr()
    var n = len(data)
    if n < _SCAN:
        var high = False
        for i in range(lo, hi):
            var b = p[unsafe_offset=i]
            if not is_field_byte(b):
                return -1
            high = high or b >= 0x80
        return 1 if high else 0
    var i = lo
    var high: UInt32 = 0
    while i < hi:
        var base = min(i, n - _SCAN)
        var v = p.unsafe_load[width=_SCAN](base)
        var shift = UInt32(i - base)
        var bad = pack_bits[DType.uint32](
            (v.lt(_V(0x20)) & v.ne(_V(_HTAB))) | v.eq(_V(0x7F))
        ) >> shift
        var hb = pack_bits[DType.uint32](v.ge(_V(0x80))) >> shift
        var room = base + _SCAN - i
        if hi - i < room:
            var keep = (UInt32(1) << UInt32(hi - i)) - 1
            bad &= keep
            hb &= keep
        if bad != 0:
            return -1
        high |= hb
        i = base + _SCAN
    return 1 if high != 0 else 0


@inline(.always)
def _is_digit(b: UInt8) -> Bool:
    return b >= 48 and b <= 57


def _version_at(data: ImmSpan[UInt8, _], at: Int) -> Optional[Version]:
    """`HTTP/<digit>.<digit>` at `data[at:at+8]` (the caller checked there
    are 8 bytes), case-sensitive (RFC 9112 2.3)."""
    var p = data.unsafe_ptr()
    if (
        p[unsafe_offset=at] != 72  # H
        or p[unsafe_offset=at + 1] != 84  # T
        or p[unsafe_offset=at + 2] != 84  # T
        or p[unsafe_offset=at + 3] != 80  # P
        or p[unsafe_offset=at + 4] != 47  # /
        or not _is_digit(p[unsafe_offset=at + 5])
        or p[unsafe_offset=at + 6] != 46  # .
        or not _is_digit(p[unsafe_offset=at + 7])
    ):
        return None
    return Version(
        Int(p[unsafe_offset=at + 5]) - 48, Int(p[unsafe_offset=at + 7]) - 48
    )


# ---- the parser -----------------------------------------------------------------


struct HeadParser(Copyable, Movable):
    """Finds and parses one message head at a time (see the module docs).
    `for_requests()` is strict; `for_responses()` adds RFC 9112's two
    leniencies."""

    var _limits: Limits
    var _lenient: Bool
    var _scanned: Int
    """Bytes of the current input already searched for the head's end."""
    var _line: Int
    """Start of the line the scan is in."""
    var _start: Int
    """Start of the start line, after any leading empty lines; -1 until it
    has begun."""
    var _ends: List[Int]
    """The LF of each line from the start line on, as the scan finds them
    (the parse then needs no second search); kept across heads. In
    fields-only mode it starts with -1, standing for a start line that
    ends just before the input."""
    var _fields_only: Bool
    var _status: Int

    def __init__(out self, *, lenient: Bool, limits: Limits, fields_only: Bool = False):
        self._limits = limits
        self._lenient = lenient
        self._scanned = 0
        self._line = 0
        self._start = -1
        self._ends = List[Int](capacity=32)
        self._fields_only = fields_only
        self._status = 0
        self.reset()

    @staticmethod
    def for_requests(limits: Limits = Limits()) -> HeadParser:
        return HeadParser(lenient=False, limits=limits)

    @staticmethod
    def for_responses(limits: Limits = Limits()) -> HeadParser:
        return HeadParser(lenient=True, limits=limits)

    @staticmethod
    def for_trailers(*, lenient: Bool, limits: Limits) -> HeadParser:
        """A parser for field sections without a start line: the trailer
        section of a chunked body (`fields`). The section ends at the first
        empty line, which may be the first line (no trailers)."""
        return HeadParser(lenient=lenient, limits=limits, fields_only=True)

    def reset(mut self):
        """Forget a partial scan (the input was replaced)."""
        self._scanned = 0
        self._line = 0
        self._ends.clear()
        if self._fields_only:
            self._start = 0
            self._ends.append(-1)
        else:
            self._start = -1

    def error_status(self) -> Int:
        """The status for the last error a request caused (400, 414 or 431),
        or 0 if none."""
        return self._status

    def _fail(mut self, status: Int, op: StaticString) -> IoError:
        self._status = status
        return IoError.of_kind(op, ErrorKind.InvalidData)

    # ---- finding the end ------------------------------------------------

    def _find_end(mut self, data: ImmSpan[UInt8, _]) raises IoError -> Int:
        """Where the head in `data` ends (just past its blank line), or -1
        if it is not complete yet. Checks the limits on everything scanned.

        The error does not depend on how the input was split: lines are
        checked in order, each against `max_head` first (the only limit
        that can be decided before a line is complete, and decided
        identically then), then its line ending, then the start-line or
        field-count limit."""
        var p = data.unsafe_ptr()
        var n = len(data)
        var lim = self._limits
        var i = self._scanned
        while True:
            var lf = _first[_lf_v, _lf_b](data, i, n)
            if lf == n:
                self._scanned = n
                if n >= lim.max_head:
                    # The next LF is at index n or later, so the head ends
                    # past max_head whatever arrives.
                    raise self._fail(431, E_HEAD_TOO_LARGE)
                return -1
            if lf + 1 > lim.max_head:
                raise self._fail(431, E_HEAD_TOO_LARGE)
            var end = lf
            if end > self._line and p[unsafe_offset=end - 1] == _CR:
                end -= 1
            elif not self._lenient:
                raise self._fail(400, E_BARE_LF)
            var empty = end == self._line
            if self._start < 0:
                if not empty:  # else a leading empty line, skipped
                    if end - self._line > lim.max_start_line:
                        raise self._fail(414, E_START_LINE_TOO_LONG)
                    self._start = self._line
                    self._ends.append(lf)
            elif empty:
                self._ends.append(lf)
                return lf + 1
            else:
                self._ends.append(lf)
                if len(self._ends) - 1 > lim.max_fields:
                    raise self._fail(431, E_TOO_MANY_FIELDS)
            self._line = lf + 1
            i = lf + 1

    # ---- public entry points --------------------------------------------

    def request(
        mut self, data: ImmSpan[UInt8, _], mut head: RequestHead
    ) raises IoError -> Optional[Int]:
        """Parse a request head from the start of `data` into `head`: None
        if it is not complete yet, else the bytes it took. `head` is
        unspecified after None or an error."""
        var end = self._find_end(data)
        if end < 0:
            return None
        self._parse_request_line(data, head)
        head.headers.clear()
        self._parse_fields(data, head.headers)
        self.reset()
        return end

    def response(
        mut self, data: ImmSpan[UInt8, _], mut head: ResponseHead
    ) raises IoError -> Optional[Int]:
        """Parse a response head from the start of `data` into `head`, as
        `request` does."""
        var end = self._find_end(data)
        if end < 0:
            return None
        self._parse_status_line(data, head)
        head.headers.clear()
        self._parse_fields(data, head.headers)
        self.reset()
        return end

    def fields(
        mut self, data: ImmSpan[UInt8, _], mut headers: Headers
    ) raises IoError -> Optional[Int]:
        """Parse a field section (see `for_trailers`) from the start of
        `data`, appending its fields to `headers`: None if it is not
        complete yet, else the bytes it took, its blank line included."""
        var end = self._find_end(data)
        if end < 0:
            return None
        self._parse_fields(data, headers)
        self.reset()
        return end

    # ---- start lines ----------------------------------------------------

    @inline(.always)
    def _start_end(self, data: ImmSpan[UInt8, _]) -> Int:
        """End of the start line's content (its LF, less a CR)."""
        var lf = self._ends[0]
        if data.unsafe_ptr()[unsafe_offset=lf - 1] == _CR:
            return lf - 1  # lf > start: the start line is not empty
        return lf

    def _parse_request_line(
        mut self, data: ImmSpan[UInt8, _], mut head: RequestHead
    ) raises IoError:
        var p = data.unsafe_ptr()
        var start = self._start
        var end = self._start_end(data)
        var m = _first[_not_tchar_v, _not_tchar_b](data, start, end)
        if m == start or m >= end or p[unsafe_offset=m] != _SP:
            raise self._fail(400, E_REQUEST_LINE)
        var t = m + 1
        var te = _first[_not_target_v, _not_target_b](data, t, end)
        if te == t or te >= end or p[unsafe_offset=te] != _SP or end - (te + 1) != 8:
            raise self._fail(400, E_REQUEST_LINE)
        var v = _version_at(data, te + 1)
        if not v:
            raise self._fail(400, E_REQUEST_LINE)
        head.method = String(StringSlice(unsafe_from_utf8=data[start:m]))
        head.target = String(StringSlice(unsafe_from_utf8=data[t:te]))
        head.version = v.value()

    def _parse_status_line(
        mut self, data: ImmSpan[UInt8, _], mut head: ResponseHead
    ) raises IoError:
        var p = data.unsafe_ptr()
        var start = self._start
        var end = self._start_end(data)
        if end - start < 12 or p[unsafe_offset=start + 8] != _SP:
            raise self._fail(400, E_STATUS_LINE)
        var v = _version_at(data, start)
        if not v:
            raise self._fail(400, E_STATUS_LINE)
        var status = 0
        for k in range(3):
            var b = p[unsafe_offset=start + 9 + k]
            if not _is_digit(b):
                raise self._fail(400, E_STATUS_LINE)
            status = status * 10 + Int(b) - 48
        if status < 100 or status > 599:
            raise self._fail(400, E_STATUS_LINE)
        var r = start + 12
        if r < end:
            if p[unsafe_offset=r] != _SP or _value_class(data, r + 1, end) < 0:
                raise self._fail(400, E_STATUS_LINE)
            r += 1
        head.version = v.value()
        head.status = status
        head.reason = String(from_utf8_lossy=data[r:end])

    # ---- field lines ----------------------------------------------------

    @inline(.always)
    def _line_start(self, k: Int) -> Int:
        return self._ends[k - 1] + 1

    @inline(.always)
    def _content_end(self, data: ImmSpan[UInt8, _], k: Int) -> Int:
        """End of line `k`'s content: its LF, less a CR. Only for a line
        that is not empty, so the byte before the LF is in it."""
        var lf = self._ends[k]
        if data.unsafe_ptr()[unsafe_offset=lf - 1] == _CR:
            return lf - 1
        return lf

    def _parse_fields(
        mut self, data: ImmSpan[UInt8, _], mut headers: Headers
    ) raises IoError:
        """Parse the field lines the scan found (`_ends[1:-1]`; the last
        entry is the blank line) into `headers`. Line endings were checked
        by `_find_end`."""
        var p = data.unsafe_ptr()
        var last = len(self._ends) - 1
        if last < 2:
            return  # no field lines
        # One copy of all the field lines; fields are then offsets into it
        # (arena offset = base + index in data).
        var first = self._line_start(1)
        var base = headers._adopt(data[first : self._ends[last]]) - first
        var k = 1
        while k < last:
            var ls = self._line_start(k)
            var le = self._content_end(data, k)
            var b0 = p[unsafe_offset=ls]
            if b0 == _SP or b0 == _HTAB:
                # A continuation line here has no field before it (one after
                # a field is consumed by the look-ahead below).
                if k == 1:
                    raise self._fail(400, E_LEADING_WS)
                raise self._fail(400, E_OBS_FOLD)
            var c = _first[_not_tchar_v, _not_tchar_b](data, ls, le)
            if c == ls or c >= le or p[unsafe_offset=c] != _COLON:
                raise self._fail(400, E_FIELD_LINE)
            var vs = c + 1
            while vs < le and is_ows(p[unsafe_offset=vs]):
                vs += 1
            var ve = le
            while ve > vs and is_ows(p[unsafe_offset=ve - 1]):
                ve -= 1
            var cls = _value_class(data, vs, ve)
            if cls < 0:
                raise self._fail(400, E_FIELD_VALUE)
            k += 1
            if k < last:
                var nb = p[unsafe_offset=self._line_start(k)]
                if nb == _SP or nb == _HTAB:
                    if not self._lenient:
                        raise self._fail(400, E_OBS_FOLD)
                    k = self._fold(data, k, last, vs, ve, data[ls:c], headers)
                    continue
            headers._push_at(base + ls, c - ls, base + vs, ve - vs, utf8=cls == 0)

    def _fold(
        mut self,
        data: ImmSpan[UInt8, _],
        first: Int,
        last: Int,
        vs: Int,
        ve: Int,
        name: ImmSpan[UInt8, _],
        mut headers: Headers,
    ) raises IoError -> Int:
        """obs-fold in a response (RFC 9112 5.2): join the value at
        `data[vs:ve]` and the continuation lines from line `first` with one
        SP each (an empty piece adds nothing), push the field, and return
        the next line's index."""
        var p = data.unsafe_ptr()
        var value = List[UInt8](capacity=ve - vs + 64)
        value.extend(data[vs:ve])
        var k = first
        while k < last:
            var ls = self._line_start(k)
            var b0 = p[unsafe_offset=ls]
            if b0 != _SP and b0 != _HTAB:
                break
            var le = self._content_end(data, k)
            var s = ls
            while s < le and is_ows(p[unsafe_offset=s]):
                s += 1
            var e = le
            while e > s and is_ows(p[unsafe_offset=e - 1]):
                e -= 1
            if _value_class(data, s, e) < 0:
                raise self._fail(400, E_FIELD_VALUE)
            if e > s:
                if len(value) > 0:
                    value.append(_SP)
                value.extend(data[s:e])
            k += 1
        headers._push(name, Span(value), utf8=False)
        return k
