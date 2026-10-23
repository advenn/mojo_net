"""HTTP/1.1 message bodies (RFC 9112 6-7), sans-I/O: how a message's body
is framed (`request_framing`, `response_framing`), decoding a received body
(`BodyDecoder`: Content-Length, chunked with trailers, or up to the end of
the connection), and encoding chunks.

Decoding is caller-buffered, like `HeadParser`. `decode(data, trailers)`
takes the unconsumed received bytes and returns a `Piece`: how many of
them the caller may now drop, and where the body data among them is (a
range of `data`, not a copy). Call it again after dropping them. When it
consumed nothing and is not done, it needs more input. Each call returns
at most one range of data. Chunk-size lines and the trailer section are
scanned incrementally, so the work is linear however the input is split.

Framing (RFC 9112 6.3), strict where a lenient reading enables request
smuggling:
- A request with Transfer-Encoding and Content-Length is refused, as is
  Transfer-Encoding in an HTTP/1.0 request. Its codings must be exactly
  `chunked`: `InvalidData` (400) unless they end in a single `chunked`,
  `Unsupported` (501) for other codings before it, which this library
  does not decode.
- In a response, Transfer-Encoding wins over Content-Length; codings that
  do not end in `chunked`, or Transfer-Encoding in HTTP/1.0, mean the body
  runs until the connection closes.
- Content-Length is one or more digits. Repeated values must all be equal
  (`42, 42` is 42); anything else is `InvalidData`.
- Responses to HEAD, 1xx, 204 and 304 have no body; a 2xx to CONNECT turns
  the connection into a tunnel.

Chunked decoding: the size is hex (at most 15 significant digits),
extensions must be well formed and are then ignored, and the trailer
section follows the field rules. Requests need CRLF everywhere; responses
may use a bare LF (as for heads). `BodyLimits` bound a chunk-size line and
the trailer section. Errors raise `InvalidData` naming the rule (`E_*`);
`error_status()` gives a server's answer (400, or 431 for oversized
trailers).
"""

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError

from .headers import (
    Bounds,
    Headers,
    eq_ignore_case,
    is_ows,
    is_tchar,
    next_element,
)
from .parse import E_BARE_LF, HeadParser, Limits, RequestHead, ResponseHead, _first, _lf_b, _lf_v

comptime _HTAB: UInt8 = 9
comptime _LF: UInt8 = 10
comptime _CR: UInt8 = 13
comptime _SP: UInt8 = 32
comptime _DQUOTE: UInt8 = 34
comptime _SEMI: UInt8 = 59
comptime _EQ: UInt8 = 61
comptime _BACKSLASH: UInt8 = 92

comptime E_CONTENT_LENGTH = "http: bad Content-Length"
comptime E_TE_AND_CL = "http: Transfer-Encoding with Content-Length"
comptime E_TE_HTTP10 = "http: Transfer-Encoding in HTTP/1.0"
comptime E_TE_CODINGS = "http: bad Transfer-Encoding"
comptime E_TE_UNSUPPORTED = "http: unsupported transfer coding"
comptime E_CHUNK_SIZE = "http: bad chunk size"
comptime E_CHUNK_EXT = "http: bad chunk extension"
comptime E_CHUNK_LINE_TOO_LONG = "http: chunk-size line too long"
comptime E_CHUNK_DATA_END = "http: no line end after chunk data"
comptime E_UNEXPECTED_EOF = "http: body ended early"

comptime _MAX_CL_DIGITS = 18
"""Content-Length digits accepted (10^18 - 1 fits an Int)."""
comptime _MAX_CHUNK_DIGITS = 15
"""Significant hex digits of a chunk size (under 2^60)."""


# ---- framing ----------------------------------------------------------------------


@fieldwise_init
struct BodyKind(Equatable, TrivialRegisterPassable, Writable):
    var _v: UInt8

    comptime NONE = BodyKind(0)
    """No body."""
    comptime LENGTH = BodyKind(1)
    """Exactly `Framing.length` bytes (Content-Length)."""
    comptime CHUNKED = BodyKind(2)
    """The chunked transfer coding, then trailers."""
    comptime CLOSE = BodyKind(3)
    """Everything until the connection closes (responses only)."""
    comptime TUNNEL = BodyKind(4)
    """No HTTP body: after a 2xx to CONNECT the connection is a tunnel."""

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self._v == other._v

    def write_to(self, mut writer: Some[Writer]):
        if self._v == 0:
            writer.write("NONE")
        elif self._v == 1:
            writer.write("LENGTH")
        elif self._v == 2:
            writer.write("CHUNKED")
        elif self._v == 3:
            writer.write("CLOSE")
        else:
            writer.write("TUNNEL")


@fieldwise_init
struct Framing(TrivialRegisterPassable, Writable):
    """How a message's body is delimited."""

    var kind: BodyKind
    var length: Int
    """The byte count for `LENGTH`, else 0."""

    @staticmethod
    @inline(.always)
    def none() -> Framing:
        return Framing(BodyKind.NONE, 0)

    @staticmethod
    @inline(.always)
    def of_length(n: Int) -> Framing:
        return Framing(BodyKind.LENGTH, n)

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.kind)
        if self.kind == BodyKind.LENGTH:
            writer.write("(", self.length, ")")


def content_length(headers: Headers) raises IoError -> Optional[Int]:
    """The Content-Length of a message, or None without one. Several field
    lines or a list are accepted when all values are equal (RFC 9110 8.6:
    `42, 42` is 42). `InvalidData` for anything but digits (at most 18),
    for differing values, or for an empty value."""
    var i = headers.find("content-length")
    if not i:
        return None
    var value = -1
    var at = i.value()
    while True:
        var v = headers.value_bytes(at)
        var pos = 0
        var any = False
        while True:
            var e = next_element(v, pos)
            if not e:
                break
            var b = e.value()
            if len(b) > _MAX_CL_DIGITS:
                raise IoError.of_kind(E_CONTENT_LENGTH, ErrorKind.InvalidData)
            var n = 0
            for k in range(b.start, b.end):
                var c = v[k]
                if c < 48 or c > 57:
                    raise IoError.of_kind(E_CONTENT_LENGTH, ErrorKind.InvalidData)
                n = n * 10 + Int(c) - 48
            if value >= 0 and n != value:
                raise IoError.of_kind(E_CONTENT_LENGTH, ErrorKind.InvalidData)
            value = n
            any = True
        if not any:  # an empty value, or only commas
            raise IoError.of_kind(E_CONTENT_LENGTH, ErrorKind.InvalidData)
        var nxt = headers.find("content-length", at + 1)
        if not nxt:
            return value
        at = nxt.value()


@fieldwise_init
struct _Codings(TrivialRegisterPassable):
    var count: Int
    var chunked: Int
    """How many of them are `chunked`."""
    var last_chunked: Bool


def _transfer_codings(headers: Headers) raises IoError -> Optional[_Codings]:
    """The transfer codings of every Transfer-Encoding line, in order
    (RFC 9112 6.1): each a token with optional `;name=value` parameters.
    None without the field; `InvalidData` for bad syntax, an empty list, or
    parameters on `chunked`."""
    var i = headers.find("transfer-encoding")
    if not i:
        return None
    var c = _Codings(0, 0, False)
    var at = i.value()
    while True:
        var v = headers.value_bytes(at)
        var pos = 0
        while True:
            var e = next_element(v, pos)
            if not e:
                break
            var b = e.value()
            var k = b.start
            while k < b.end and is_tchar(v[k]):
                k += 1
            if k == b.start:
                raise IoError.of_kind(E_TE_CODINGS, ErrorKind.InvalidData)
            var is_chunked = eq_ignore_case(v[b.start : k], "chunked".as_bytes())
            var params = _parameters(v, k, b.end)
            if params < 0 or (is_chunked and params > 0):
                raise IoError.of_kind(E_TE_CODINGS, ErrorKind.InvalidData)
            c.count += 1
            if is_chunked:
                c.chunked += 1
            c.last_chunked = is_chunked
        var nxt = headers.find("transfer-encoding", at + 1)
        if not nxt:
            break
        at = nxt.value()
    if c.count == 0:
        raise IoError.of_kind(E_TE_CODINGS, ErrorKind.InvalidData)
    return c


def _parameters(v: Span[UInt8, _], start: Int, end: Int) -> Int:
    """Parameters `*( OWS ";" OWS token "=" ( token / quoted-string ) )` in
    `v[start:end]` (RFC 9110 5.6.6): how many, or -1 if malformed."""
    var n = 0
    var k = start
    while True:
        while k < end and is_ows(v[k]):
            k += 1
        if k == end:
            return n
        if v[k] != _SEMI:
            return -1
        k += 1
        while k < end and is_ows(v[k]):
            k += 1
        var t = k
        while k < end and is_tchar(v[k]):
            k += 1
        if k == t or k == end or v[k] != _EQ:
            return -1
        k += 1
        var q = _token_or_quoted(v, k, end)
        if q < 0:
            return -1
        k = q
        n += 1


def _token_or_quoted(v: Span[UInt8, _], start: Int, end: Int) -> Int:
    """The end of a token or quoted-string at `v[start:]`, or -1."""
    var k = start
    if k < end and v[k] == _DQUOTE:
        k += 1
        while k < end:
            var b = v[k]
            if b == _DQUOTE:
                return k + 1
            if b == _BACKSLASH:
                k += 1
                if k == end or not _is_quoted_pair_byte(v[k]):
                    return -1
            elif not _is_qdtext(b):
                return -1
            k += 1
        return -1
    var t = k
    while k < end and is_tchar(v[k]):
        k += 1
    return k if k > t else -1


@inline(.always)
def _is_qdtext(b: UInt8) -> Bool:
    """qdtext (RFC 9110 5.6.4): HTAB, SP, VCHAR but DQUOTE and backslash,
    obs-text."""
    return b == _HTAB or b == _SP or b == 0x21 or (b >= 0x23 and b <= 0x5B) or (
        b >= 0x5D and b != 0x7F
    )


@inline(.always)
def _is_quoted_pair_byte(b: UInt8) -> Bool:
    """What may follow a backslash: HTAB, SP, VCHAR, obs-text."""
    return b == _HTAB or (b >= 0x20 and b != 0x7F)


def request_framing(head: RequestHead) raises IoError -> Framing:
    """How a request's body is delimited (RFC 9112 6.3; see the module
    docs). `InvalidData` (answer 400) or `Unsupported` (answer 501)."""
    var te = _transfer_codings(head.headers)
    if te:
        if not head.version.at_least_1_1():
            raise IoError.of_kind(E_TE_HTTP10, ErrorKind.InvalidData)
        if head.headers.contains("content-length"):
            raise IoError.of_kind(E_TE_AND_CL, ErrorKind.InvalidData)
        var c = te.value()
        if not c.last_chunked or c.chunked > 1:
            raise IoError.of_kind(E_TE_CODINGS, ErrorKind.InvalidData)
        if c.count > 1:
            raise IoError.of_kind(E_TE_UNSUPPORTED, ErrorKind.Unsupported)
        return Framing(BodyKind.CHUNKED, 0)
    var cl = content_length(head.headers)
    if cl:
        return Framing.of_length(cl.value())
    return Framing.none()


def response_framing(
    head: ResponseHead, request_method: StringSlice
) raises IoError -> Framing:
    """How a response's body is delimited, given the method of the request
    it answers (RFC 9112 6.3; see the module docs). `InvalidData` if the
    framing is malformed: the client must close the connection."""
    var s = head.status
    if request_method == "HEAD" or (s >= 100 and s < 200) or s == 204 or s == 304:
        return Framing.none()
    if request_method == "CONNECT" and s >= 200 and s < 300:
        return Framing(BodyKind.TUNNEL, 0)
    var te = _transfer_codings(head.headers)
    if te:
        var c = te.value()
        if c.chunked > 1:
            raise IoError.of_kind(E_TE_CODINGS, ErrorKind.InvalidData)
        if head.version.at_least_1_1() and c.last_chunked:
            return Framing(BodyKind.CHUNKED, 0)
        return Framing(BodyKind.CLOSE, 0)
    var cl = content_length(head.headers)
    if cl:
        return Framing.of_length(cl.value())
    return Framing(BodyKind.CLOSE, 0)


# ---- decoding ---------------------------------------------------------------------


struct BodyLimits(TrivialRegisterPassable):
    """Bounds on a chunked body's framing (body sizes are the caller's)."""

    var max_chunk_line: Int
    """A chunk-size line with its extensions, without the line ending."""
    var max_trailers: Int
    """The trailer section, its blank line included."""
    var max_trailer_fields: Int

    comptime DEFAULT_MAX_CHUNK_LINE = 4096
    comptime DEFAULT_MAX_TRAILERS = 16 * 1024
    comptime DEFAULT_MAX_TRAILER_FIELDS = 100

    def __init__(
        out self,
        *,
        max_chunk_line: Int = Self.DEFAULT_MAX_CHUNK_LINE,
        max_trailers: Int = Self.DEFAULT_MAX_TRAILERS,
        max_trailer_fields: Int = Self.DEFAULT_MAX_TRAILER_FIELDS,
    ):
        self.max_chunk_line = max_chunk_line
        self.max_trailers = max_trailers
        self.max_trailer_fields = max_trailer_fields


@fieldwise_init
struct Piece(TrivialRegisterPassable, Writable):
    """One `decode` step: drop `consumed` bytes of the input after using
    the body data at `data[start : start + len]` (inside them)."""

    var consumed: Int
    var start: Int
    var len: Int

    def write_to(self, mut writer: Some[Writer]):
        writer.write("Piece(", self.consumed, ", ", self.start, ", ", self.len, ")")


comptime _SIZE = 0
comptime _DATA = 1
comptime _DATA_END = 2
comptime _TRAILERS = 3
comptime _DONE = 4


struct BodyDecoder(Copyable, Movable):
    """Decodes one received body (see the module docs)."""

    var _kind: BodyKind
    var _lenient: Bool
    var _limits: BodyLimits
    var _remaining: Int
    """LENGTH: bytes left. CHUNKED: bytes left in the current chunk."""
    var _state: Int
    var _scanned: Int
    """CHUNKED: bytes of the current chunk-size line already searched."""
    var _trailers: HeadParser
    var _done: Bool
    var _status: Int

    def __init__(
        out self, framing: Framing, *, lenient: Bool, limits: BodyLimits = BodyLimits()
    ):
        """A decoder for a body framed as `framing`. `lenient` is for
        response bodies (bare LF line endings). TUNNEL is decoded like
        CLOSE: everything is data."""
        self._kind = framing.kind
        self._lenient = lenient
        self._limits = limits
        self._remaining = framing.length if framing.kind == BodyKind.LENGTH else 0
        self._state = _SIZE
        self._scanned = 0
        self._trailers = HeadParser.for_trailers(
            lenient=lenient,
            limits=Limits(
                max_head=limits.max_trailers, max_fields=limits.max_trailer_fields
            ),
        )
        self._done = framing.kind == BodyKind.NONE or (
            framing.kind == BodyKind.LENGTH and framing.length == 0
        )
        self._status = 0

    @inline(.always)
    def is_done(self) -> Bool:
        """The whole body (and its trailers) has been decoded."""
        return self._done

    def remaining(self) -> Optional[Int]:
        """Body bytes still expected, when known (LENGTH)."""
        if self._kind == BodyKind.LENGTH:
            return self._remaining
        return None

    def error_status(self) -> Int:
        """The status a server answers the last error with: 431 for an
        oversized trailer section, else 400; 0 if none."""
        return self._status

    def _fail(mut self, op: StaticString) -> IoError:
        self._status = 400
        return IoError.of_kind(op, ErrorKind.InvalidData)

    def finish(mut self) raises IoError:
        """The connection closed (no more input). Ends a CLOSE body;
        `UnexpectedEof` if any other body is incomplete."""
        if self._done:
            return
        if self._kind == BodyKind.CLOSE or self._kind == BodyKind.TUNNEL:
            self._done = True
            return
        self._status = 400
        raise IoError.of_kind(E_UNEXPECTED_EOF, ErrorKind.UnexpectedEof)

    def decode(
        mut self, data: ImmSpan[UInt8, _], mut trailers: Headers
    ) raises IoError -> Piece:
        """Decode from the start of `data` (the unconsumed input); trailer
        fields are appended to `trailers`. See the module docs."""
        if self._done:
            return Piece(0, 0, 0)
        var n = len(data)
        if self._kind == BodyKind.LENGTH:
            var k = min(self._remaining, n)
            self._remaining -= k
            self._done = self._remaining == 0
            return Piece(k, 0, k)
        if self._kind != BodyKind.CHUNKED:  # CLOSE, TUNNEL
            return Piece(n, 0, n)
        return self._chunked(data, trailers)

    def _chunked(
        mut self, data: ImmSpan[UInt8, _], mut trailers: Headers
    ) raises IoError -> Piece:
        var p = data.unsafe_ptr()
        var n = len(data)
        var at = 0  # consumed so far
        while True:
            if self._state == _DATA:
                var k = min(self._remaining, n - at)
                self._remaining -= k
                if self._remaining == 0:
                    self._state = _DATA_END
                return Piece(at + k, at, k)
            if self._state == _DATA_END:
                if at == n:
                    return Piece(at, 0, 0)
                var b = p[unsafe_offset=at]
                if b == _LF and self._lenient:
                    at += 1
                elif b == _CR:
                    if at + 1 == n:
                        return Piece(at, 0, 0)
                    if p[unsafe_offset=at + 1] != _LF:
                        raise self._fail(E_CHUNK_DATA_END)
                    at += 2
                else:
                    raise self._fail(E_CHUNK_DATA_END)
                self._state = _SIZE
                continue
            if self._state == _SIZE:
                var line = self._size_line(data, at)
                if line < 0:
                    return Piece(at, 0, 0)
                at = line
                continue
            if self._state == _TRAILERS:
                var r: Optional[Int]
                try:
                    r = self._trailers.fields(data[at:], trailers)
                except e:
                    self._status = self._trailers.error_status()
                    raise e
                if not r:
                    return Piece(at, 0, 0)
                self._state = _DONE
                self._done = True
                return Piece(at + r.value(), 0, 0)
            return Piece(at, 0, 0)  # _DONE

    def _size_line(mut self, data: ImmSpan[UInt8, _], line: Int) raises IoError -> Int:
        """Parse the chunk-size line at `data[line:]`: where the next state
        starts (past its LF), or -1 until the line is complete."""
        var p = data.unsafe_ptr()
        var n = len(data)
        var lim = self._limits.max_chunk_line
        var lf = _first[_lf_v, _lf_b](data, line + self._scanned, n)
        if lf == n:
            self._scanned = n - line
            if n - line > lim + 1:  # even a CR before the coming LF leaves too much
                raise self._fail(E_CHUNK_LINE_TOO_LONG)
            return -1
        self._scanned = 0
        var end = lf
        var cr = end > line and p[unsafe_offset=end - 1] == _CR
        if cr:
            end -= 1
        if end - line > lim:
            raise self._fail(E_CHUNK_LINE_TOO_LONG)
        if not cr and not self._lenient:
            raise self._fail(E_BARE_LF)
        var k = line
        var size = 0
        var digits = 0
        while k < end:
            var d = _hex(p[unsafe_offset=k])
            if d < 0:
                break
            if digits > 0 or d > 0:
                digits += 1
            size = size * 16 + d
            k += 1
            if digits > _MAX_CHUNK_DIGITS:
                raise self._fail(E_CHUNK_SIZE)
        if k == line:
            raise self._fail(E_CHUNK_SIZE)
        if not self._chunk_ext(data, k, end):
            raise self._fail(E_CHUNK_EXT)
        if size == 0:
            self._state = _TRAILERS
        else:
            self._remaining = size
            self._state = _DATA
        return lf + 1

    def _chunk_ext(self, data: ImmSpan[UInt8, _], start: Int, end: Int) -> Bool:
        """`*( BWS ";" BWS name [ BWS "=" BWS value ] )` in `data[start:end]`
        (RFC 9112 7.1.1); a response may also end in whitespace."""
        var k = start
        while True:
            var ws = k
            while k < end and is_ows(data[k]):
                k += 1
            if k == end:
                return k == ws or self._lenient
            if data[k] != _SEMI:
                return False
            k += 1
            while k < end and is_ows(data[k]):
                k += 1
            var t = k
            while k < end and is_tchar(data[k]):
                k += 1
            if k == t:
                return False
            var after = k
            while k < end and is_ows(data[k]):
                k += 1
            if k < end and data[k] == _EQ:
                k += 1
                while k < end and is_ows(data[k]):
                    k += 1
                var q = _token_or_quoted(data, k, end)
                if q < 0:
                    return False
                k = q
            else:
                k = after


@inline(.always)
def _hex(b: UInt8) -> Int:
    if b >= 48 and b <= 57:
        return Int(b) - 48
    var l = b | 0x20
    if l >= 97 and l <= 102:
        return Int(l) - 87
    return -1


# ---- encoding ---------------------------------------------------------------------


def encode_chunk(data: Span[UInt8, _], mut out: ByteBuffer) raises IoError:
    """Append one chunk: its size in hex, CRLF, the data, CRLF. Empty data
    appends nothing (a zero-size chunk would end the body). `OutOfMemory`
    (nothing appended) if `out` cannot hold it."""
    var n = len(data)
    if n == 0:
        return
    var digits = 0
    var v = n
    while v > 0:
        digits += 1
        v >>= 4
    out.ensure_writable(digits + 2 + n + 2)
    for i in range(digits - 1, -1, -1):
        var d = (n >> (4 * i)) & 15
        out.write_byte(UInt8(48 + d) if d < 10 else UInt8(87 + d))
    out.write_byte(_CR)
    out.write_byte(_LF)
    out.write_bytes(data)
    out.write_byte(_CR)
    out.write_byte(_LF)


def encode_last_chunk(trailers: Headers, mut out: ByteBuffer) raises IoError:
    """Append the end of a chunked body: `0` CRLF, the trailer fields, and
    the blank line."""
    out.ensure_writable(3 + trailers.encoded_len() + 2)
    out.write_byte(48)
    out.write_byte(_CR)
    out.write_byte(_LF)
    trailers.encode(out)
    out.write_byte(_CR)
    out.write_byte(_LF)
