"""HTTP/1.1 connections as sans-I/O codecs (design contract 1):
`ServerConnection` is the server side of one connection, `ClientConnection`
the client side. Both implement `bytes.codec.Codec`: the driver feeds the
bytes it receives, drains events, and sends what `poll_transmit` hands out.

Events are owned values (`ServerEvent`, `ClientEvent`): a `HEAD`, the body
as `DATA` pieces, then `END` with the trailers (empty if none). A message
without a body still gets its `END`. `DATA` comes out as soon as body bytes
arrive, so its pieces depend on how the input was split; their
concatenation and every other event do not (contract rule 4, refined for
byte streams).

**ServerConnection**
- One request at a time: the next request is parsed only once the current
  one's response has ended. Pipelined requests wait in the receive buffer;
  when it is full, `feed_capacity()` is 0 until the response ends, so the
  driver stops reading (backpressure). This is where the codec departs from
  contract rule 5, which assumes a codec never waits on its application.
- Requests are checked after parsing: HTTP/1.x only (505 otherwise), and
  exactly one Host in HTTP/1.1, at most one in HTTP/1.0 (RFC 9112 3.2).
- `send_response(head)` picks the framing. It uses the head's
  Content-Length if there is one. Otherwise it sends chunked to an
  HTTP/1.1 client (adding `Transfer-Encoding: chunked`) and close-delimited
  to an HTTP/1.0 client. HEAD requests and 1xx/204/304 get no body (body
  bytes sent for a HEAD request are dropped). Then `send_body(data)` and
  `end_response(trailers)`. The status line always
  says HTTP/1.1 (RFC 9112 2.3), with the registered reason phrase if the
  head has none.
- `send_continue()` answers `Expect: 100-continue`; `send_informational`
  sends other 1xx responses. Both are no-ops for HTTP/1.0 clients, which
  must not get 1xx responses.
- Persistence (RFC 9112 9.3): HTTP/1.1 keeps the connection unless either
  side sends `Connection: close`; HTTP/1.0 needs `Connection: keep-alive`.
  The codec adds `Connection: close` (or `keep-alive` for a 1.0 client) as
  needed. A response that ends before its request body closes the
  connection: the rest of the body is not read.
- A 101 answering an Upgrade request, or a 2xx answering CONNECT, ends HTTP
  on the connection once its head is queued: `is_upgraded()`, and
  `take_remaining()` returns the bytes received after the request.
- A malformed request poisons the input side (rule 6). `error_status()` is
  the status to answer with (400, 414, 431, 501 or 505), which
  `send_error()` sends before the connection closes.
- `should_close()`: once `poll_transmit` has handed everything out, the
  driver closes the connection.

**ClientConnection**
- `send_request(head)` takes its framing from the head:
  `Transfer-Encoding: chunked`, Content-Length, or no body. HTTP/1.1
  requests need exactly one Host. Then `send_body` and `end_request`.
  Requests may be pipelined, up to `max_in_flight` (default 1);
  responses are matched to them in order.
- Events: `INFORMATIONAL` heads (1xx other than 101), then the final
  response's `HEAD`, `DATA` and `END`. `UPGRADE` reports a 101 answering
  an Upgrade request, or a 2xx answering CONNECT; then `take_remaining()`.
- Closing: a response that does not keep the connection makes it closing
  (`should_close()`); requests still in flight are lost (`unanswered()`).
  EOF before any byte of a response raises `UnexpectedEof` with
  `E_NO_RESPONSE`, so a client knows the server never saw (or never
  answered) the request and may retry an idempotent one.
"""

from bytes.buffer import ByteBuffer
from bytes.codec import Codec
from linux import ErrorKind, IoError
from linux.time import Instant

from .body import (
    E_UNEXPECTED_EOF,
    BodyDecoder,
    BodyKind,
    BodyLimits,
    Framing,
    Piece,
    content_length,
    encode_chunk,
    encode_last_chunk,
    request_framing,
    response_framing,
)
from .headers import Headers, eq_ignore_case, is_field_byte, next_element
from .parse import HeadParser, Limits, RequestHead, ResponseHead
from .types import Version, check_status, reason

comptime E_VERSION = "http: unsupported HTTP version"
comptime E_HOST = "http: missing or repeated Host"
comptime E_NO_RESPONSE = "http: connection closed before a response"
comptime E_UNSOLICITED = "http: response without a request"
comptime E_BAD_101 = "http: 101 without an upgrade request"

comptime _CR: UInt8 = 13
comptime _LF: UInt8 = 10

# input phases
comptime _HEAD = 0
"""Waiting for a head."""
comptime _BODY = 1
"""Decoding a body."""
comptime _WAIT = 2
"""Server: the request is complete; waiting for its response to end."""
comptime _UPGRADED = 3
"""No longer HTTP."""
comptime _CLOSED = 4
"""No more messages: input is ignored."""

# output phases
comptime _OUT_NONE = 0
"""Nothing to send: no request awaits a response (server), no request is
being written (client)."""
comptime _OUT_PENDING = 1
"""Server: a request awaits its response."""
comptime _OUT_BODY = 2
"""A head was sent; its body is being written."""


# ---- events -----------------------------------------------------------------------


@fieldwise_init
struct EventKind(Equatable, TrivialRegisterPassable, Writable):
    var _v: UInt8

    comptime HEAD = EventKind(0)
    comptime DATA = EventKind(1)
    comptime END = EventKind(2)
    comptime INFORMATIONAL = EventKind(3)
    """Client: a 1xx response other than 101; the final one follows."""
    comptime UPGRADE = EventKind(4)
    """Client: a 101 to an Upgrade request or a 2xx to CONNECT; HTTP ends."""

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self._v == other._v

    def write_to(self, mut writer: Some[Writer]):
        if self._v == 0:
            writer.write("HEAD")
        elif self._v == 1:
            writer.write("DATA")
        elif self._v == 2:
            writer.write("END")
        elif self._v == 3:
            writer.write("INFORMATIONAL")
        else:
            writer.write("UPGRADE")


struct ServerEvent(Movable, Writable):
    """What a `ServerConnection` received: `HEAD` (`head`, `framing`),
    `DATA` (`data`), `END` (`trailers`)."""

    var kind: EventKind
    var head: Optional[RequestHead]
    var framing: Framing
    var data: List[UInt8]
    var trailers: Headers

    def __init__(out self, kind: EventKind):
        self.kind = kind
        self.head = None
        self.framing = Framing.none()
        self.data = List[UInt8]()
        self.trailers = Headers()

    def take_head(mut self) raises IoError -> RequestHead:
        """Move the head out (`HEAD` events). `InvalidInput` otherwise."""
        if not self.head:
            raise IoError.of_kind("ServerEvent.take_head", ErrorKind.InvalidInput)
        return self.head.take()

    def take_data(mut self) -> List[UInt8]:
        var out = List[UInt8]()
        swap(out, self.data)
        return out^

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.kind)
        if self.kind == EventKind.HEAD and self.head:
            ref h = self.head.value()
            writer.write(" ", h.method, " ", h.target, " ", h.version, " ", self.framing)
        elif self.kind == EventKind.DATA:
            writer.write(" ", String(from_utf8_lossy=Span(self.data)))
        elif self.kind == EventKind.END and len(self.trailers) > 0:
            writer.write(" ", self.trailers)


struct ClientEvent(Movable, Writable):
    """What a `ClientConnection` received: `INFORMATIONAL`, `HEAD` and
    `UPGRADE` (`head`, and `framing` for `HEAD`), `DATA` (`data`), `END`
    (`trailers`)."""

    var kind: EventKind
    var head: Optional[ResponseHead]
    var framing: Framing
    var data: List[UInt8]
    var trailers: Headers

    def __init__(out self, kind: EventKind):
        self.kind = kind
        self.head = None
        self.framing = Framing.none()
        self.data = List[UInt8]()
        self.trailers = Headers()

    def take_head(mut self) raises IoError -> ResponseHead:
        if not self.head:
            raise IoError.of_kind("ClientEvent.take_head", ErrorKind.InvalidInput)
        return self.head.take()

    def take_data(mut self) -> List[UInt8]:
        var out = List[UInt8]()
        swap(out, self.data)
        return out^

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.kind)
        if self.head:
            ref h = self.head.value()
            writer.write(" ", h.status, " ", h.version)
            if self.kind == EventKind.HEAD:
                writer.write(" ", self.framing)
        elif self.kind == EventKind.DATA:
            writer.write(" ", String(from_utf8_lossy=Span(self.data)))
        elif self.kind == EventKind.END and len(self.trailers) > 0:
            writer.write(" ", self.trailers)


# ---- shared -----------------------------------------------------------------------


def _persistent(version: Version, headers: Headers) -> Bool:
    """Whether a message lets the connection persist (RFC 9112 9.3)."""
    if headers.has_token("connection", "close"):
        return False
    if version.at_least_1_1():
        return True
    return headers.has_token("connection", "keep-alive")


def _only_chunked(headers: Headers) raises IoError -> Bool:
    """The Transfer-Encoding fields name exactly one coding, `chunked`."""
    var n = 0
    var chunked = False
    var i = headers.find("transfer-encoding")
    while i:
        var v = headers.value_bytes(i.value())
        var pos = 0
        while True:
            var e = next_element(v, pos)
            if not e:
                break
            var b = e.value()
            n += 1
            chunked = eq_ignore_case(v[b.start : b.end], "chunked".as_bytes())
        i = headers.find("transfer-encoding", i.value() + 1)
    return n == 1 and chunked


@inline(.always)
def _crlf(mut out: ByteBuffer) raises IoError:
    out.write_byte(_CR)
    out.write_byte(_LF)


def _write_str(mut out: ByteBuffer, s: StringSlice) raises IoError:
    out.write_bytes(s.as_bytes())


def _status_line(mut out: ByteBuffer, status: Int, phrase: StringSlice) raises IoError:
    """`HTTP/1.1 <status> <phrase>` CRLF; the registered phrase if `phrase`
    is empty."""
    _write_str(out, "HTTP/1.1 ")
    out.write_byte(UInt8(48 + status // 100))
    out.write_byte(UInt8(48 + status // 10 % 10))
    out.write_byte(UInt8(48 + status % 10))
    out.write_byte(32)
    if phrase.byte_length() > 0:
        _write_str(out, phrase)
    else:
        _write_str(out, reason(status))
    _crlf(out)


# ---- ServerConnection ---------------------------------------------------------------


struct ServerConnection(Codec, Copyable):
    """The server side of one HTTP/1.1 connection (see the module docs)."""

    comptime Event = ServerEvent

    comptime DEFAULT_MAX_BUFFERED = Limits.DEFAULT_MAX_HEAD + 16 * 1024

    var _rx: ByteBuffer
    var _tx: ByteBuffer
    var _parser: HeadParser
    var _body_limits: BodyLimits
    var _body: BodyDecoder
    var _trailers: Headers
    var _in: Int
    var _eof: Bool
    var _failed: Optional[IoError]
    var _status: Int
    var _deadline: Optional[Instant]
    # the request being answered
    var _method: String
    var _version: Version
    var _keep: Bool
    var _upgrade: Bool
    var _req_done: Bool
    # its response
    var _out: Int
    var _resp_kind: BodyKind
    var _resp_left: Int
    var _resp_close: Bool
    var _closing: Bool

    def __init__(
        out self,
        *,
        limits: Limits = Limits(),
        body_limits: BodyLimits = BodyLimits(),
        max_buffered: Int = Self.DEFAULT_MAX_BUFFERED,
    ) raises IoError:
        """`max_buffered` bounds the received bytes held (`feed_capacity()`
        is the room left): at least a maximal head, trailer section and
        chunk-size line, else `InvalidInput`."""
        if (
            max_buffered < limits.max_head
            or max_buffered < body_limits.max_trailers
            or max_buffered < body_limits.max_chunk_line + 2
        ):
            raise IoError.of_kind("ServerConnection.__init__", ErrorKind.InvalidInput)
        self._rx = ByteBuffer(max_size=max_buffered)
        self._tx = ByteBuffer()
        self._parser = HeadParser.for_requests(limits)
        self._body_limits = body_limits
        self._body = BodyDecoder(Framing.none(), lenient=False, limits=body_limits)
        self._trailers = Headers()
        self._in = _HEAD
        self._eof = False
        self._failed = None
        self._status = 0
        self._deadline = None
        self._method = String()
        self._version = Version.HTTP_1_1
        self._keep = True
        self._upgrade = False
        self._req_done = True
        self._out = _OUT_NONE
        self._resp_kind = BodyKind.NONE
        self._resp_left = 0
        self._resp_close = False
        self._closing = False

    # ---- receive ---------------------------------------------------------

    def _poison(mut self, e: IoError, status: Int) -> IoError:
        """Fail the input side (rule 6) and return the error to raise."""
        self._failed = e
        self._status = status
        return e

    def feed(mut self, data: Span[UInt8, _]) raises IoError:
        if self._failed:
            raise self._failed.value()
        if self._eof:
            raise IoError.of_kind("ServerConnection.feed", ErrorKind.InvalidInput)
        if self._in == _CLOSED:
            return  # no more requests are read
        if len(data) > self._rx.max_writable():
            raise self._poison(IoError.of_kind("ServerConnection.feed", ErrorKind.OutOfMemory), 0)
        self._rx.write_bytes(data)

    def feed_capacity(self) -> Int:
        """The room left in the receive buffer (unbounded once input is
        ignored). Can be 0 while a response is pending: see the module
        docs."""
        if self._in == _CLOSED:
            return Int.MAX
        return self._rx.max_writable()

    def feed_eof(mut self) raises IoError:
        if self._failed:
            raise self._failed.value()
        self._eof = True

    def next_event(mut self) raises IoError -> Optional[ServerEvent]:
        if self._failed:
            raise self._failed.value()
        while True:
            if self._in == _HEAD:  # (after _WAIT: the response has ended)
                return self._next_head()
            if self._in == _BODY:
                var r = self._next_body()
                if r:
                    return r^
                if self._in == _BODY:
                    return None
                continue
            return None  # _WAIT (one request at a time), _UPGRADED, _CLOSED

    def _next_head(mut self) raises IoError -> Optional[ServerEvent]:
        var head = RequestHead()
        var got: Optional[Int]
        try:
            got = self._parser.request(self._rx.readable_span(), head)
        except e:
            raise self._poison(e, self._parser.error_status())
        if not got:
            if self._eof:
                if _only_line_ends(self._rx.readable_span()):
                    self._in = _CLOSED  # closed between requests
                    return None
                raise self._poison(IoError.of_kind(E_UNEXPECTED_EOF, ErrorKind.UnexpectedEof), 400)
            return None
        self._rx.consume(got.value())
        if head.version.major != 1:
            raise self._poison(IoError.of_kind(E_VERSION, ErrorKind.InvalidData), 505)
        var hosts = head.headers.count("host")
        if hosts > 1 or (hosts == 0 and head.version.at_least_1_1()):
            raise self._poison(IoError.of_kind(E_HOST, ErrorKind.InvalidData), 400)
        var framing: Framing
        try:
            framing = request_framing(head)
        except e:
            raise self._poison(e, 501 if e.kind == ErrorKind.Unsupported else 400)
        self._method = head.method
        self._version = head.version
        self._keep = _persistent(head.version, head.headers)
        self._upgrade = head.headers.contains("upgrade") and head.headers.has_token(
            "connection", "upgrade"
        )
        self._body = BodyDecoder(framing, lenient=False, limits=self._body_limits)
        self._req_done = False
        self._out = _OUT_PENDING
        self._in = _BODY
        var ev = ServerEvent(EventKind.HEAD)
        ev.head = head^
        ev.framing = framing
        return ev^

    def _next_body(mut self) raises IoError -> Optional[ServerEvent]:
        """The next DATA or END event, or None with `_in` still `_BODY`
        when more input is needed (or a phase change to look at)."""
        while True:
            var piece: Piece
            try:
                piece = self._body.decode(self._rx.readable_span(), self._trailers)
            except e:
                raise self._poison(e, self._body.error_status())
            if piece.len > 0:
                var ev = ServerEvent(EventKind.DATA)
                ev.data = List[UInt8](self._rx.readable_span()[piece.start : piece.start + piece.len])
                self._rx.consume(piece.consumed)
                return ev^
            self._rx.consume(piece.consumed)
            if self._body.is_done():
                self._req_done = True
                self._in = _WAIT
                var ev = ServerEvent(EventKind.END)
                swap(ev.trailers, self._trailers)
                return ev^
            if piece.consumed == 0:
                if self._eof:
                    try:
                        self._body.finish()
                    except e:
                        raise self._poison(e, 400)
                    continue
                return None

    def error_status(self) -> Int:
        """The status for the last input error (400, 414, 431, 501, 505),
        or 0."""
        return self._status

    # ---- send ------------------------------------------------------------

    def _misuse(self, op: StaticString) -> IoError:
        return IoError.of_kind(op, ErrorKind.InvalidInput)

    def send_continue(mut self) raises IoError:
        """`100 Continue`, for a request with `Expect: 100-continue` whose
        body the application wants (RFC 9110 10.1.1). A no-op for an
        HTTP/1.0 client. `InvalidInput` unless a request awaits its
        response."""
        if self._out != _OUT_PENDING:
            raise self._misuse("ServerConnection.send_continue")
        if self._version.at_least_1_1():
            _status_line(self._tx, 100, "Continue")
            _crlf(self._tx)

    def send_informational(mut self, head: ResponseHead) raises IoError:
        """A 1xx response other than 101 (103 Early Hints, say) before the
        final one. A no-op for an HTTP/1.0 client."""
        if self._out != _OUT_PENDING or head.status < 100 or head.status > 199 or head.status == 101:
            raise self._misuse("ServerConnection.send_informational")
        _check_reason(head.reason, "ServerConnection.send_informational")
        if self._version.at_least_1_1():
            self._tx.ensure_writable(16 + head.reason.byte_length() + head.headers.encoded_len() + 2)
            _status_line(self._tx, head.status, head.reason)
            head.headers.encode(self._tx)
            _crlf(self._tx)

    def send_response(mut self, head: ResponseHead) raises IoError:
        """Queue the final response's head (see the module docs for the
        framing and headers it adds). `InvalidInput` (nothing queued) unless
        a request awaits its response and the head is valid for it: a
        status of 101 or 200..599, 101 only for an Upgrade request, no
        Content-Length or Transfer-Encoding on 204 or a 2xx to CONNECT, and
        Transfer-Encoding only as `chunked` to an HTTP/1.1 client."""
        comptime op = "ServerConnection.send_response"
        if self._out != _OUT_PENDING:
            raise self._misuse(op)
        var status = head.status
        if status != 101 and (status < 200 or status > 599):
            raise self._misuse(op)
        _check_reason(head.reason, op)
        var has_te = head.headers.contains("transfer-encoding")
        var cl: Optional[Int]
        try:
            cl = content_length(head.headers)
        except:
            raise self._misuse(op)
        var connect_ok = self._method == "CONNECT" and status >= 200 and status < 300
        var switch = status == 101 or connect_ok
        if status == 101 and not self._upgrade:
            raise self._misuse(op)
        if (status == 204 or switch) and (has_te or cl):
            raise self._misuse(op)
        if has_te and (cl or not _only_chunked(head.headers) or not self._version.at_least_1_1()):
            raise self._misuse(op)
        var kind: BodyKind
        var add_te = False
        if switch or self._method == "HEAD" or status == 204 or status == 304:
            kind = BodyKind.NONE
        elif has_te:
            kind = BodyKind.CHUNKED
        elif cl:
            kind = BodyKind.LENGTH
        elif self._version.at_least_1_1():
            kind = BodyKind.CHUNKED
            add_te = True
        else:
            kind = BodyKind.CLOSE
        var close = (
            not self._keep
            or kind == BodyKind.CLOSE
            or head.headers.has_token("connection", "close")
        ) and not switch
        var add_close = close and not head.headers.has_token("connection", "close")
        var add_keep = not close and not switch and not self._version.at_least_1_1()
        self._tx.ensure_writable(
            16 + head.reason.byte_length() + head.headers.encoded_len() + 64
        )
        _status_line(self._tx, status, head.reason)
        head.headers.encode(self._tx)
        if add_te:
            _write_str(self._tx, "Transfer-Encoding: chunked\r\n")
        if add_close:
            _write_str(self._tx, "Connection: close\r\n")
        if add_keep:
            _write_str(self._tx, "Connection: keep-alive\r\n")
        _crlf(self._tx)
        if switch:
            self._out = _OUT_NONE
            self._in = _UPGRADED
            return
        self._out = _OUT_BODY
        self._resp_kind = kind
        self._resp_left = cl.value() if (kind == BodyKind.LENGTH) else 0
        self._resp_close = close

    def send_body(mut self, data: Span[UInt8, _]) raises IoError:
        """Queue body bytes. For a HEAD request they are dropped, so a GET
        handler can answer HEAD unchanged. `InvalidInput` (nothing queued)
        outside a response, past its Content-Length, or for a 204 or 304."""
        comptime op = "ServerConnection.send_body"
        if self._out != _OUT_BODY:
            raise self._misuse(op)
        var n = len(data)
        if self._resp_kind == BodyKind.LENGTH:
            if n > self._resp_left:
                raise self._misuse(op)
            self._tx.write_bytes(data)
            self._resp_left -= n
        elif self._resp_kind == BodyKind.CHUNKED:
            encode_chunk(data, self._tx)
        elif self._resp_kind == BodyKind.CLOSE:
            self._tx.write_bytes(data)
        elif n > 0 and self._method != "HEAD":
            raise self._misuse(op)

    def end_response(mut self, trailers: Headers = Headers()) raises IoError:
        """End the response (with trailer fields, for a chunked one).
        `InvalidInput` outside a response, if its Content-Length is not
        reached, or for trailers on a body that is not chunked."""
        comptime op = "ServerConnection.end_response"
        if self._out != _OUT_BODY:
            raise self._misuse(op)
        if self._resp_kind == BodyKind.LENGTH and self._resp_left > 0:
            raise self._misuse(op)
        if len(trailers) > 0 and self._resp_kind != BodyKind.CHUNKED:
            raise self._misuse(op)
        if self._resp_kind == BodyKind.CHUNKED:
            encode_last_chunk(trailers, self._tx)
        self._out = _OUT_NONE
        if self._resp_close or not self._req_done or self._failed:
            self._closing = True
            self._in = _CLOSED
            self._rx.clear()
        elif self._in == _WAIT:
            self._in = _HEAD

    def send_error(mut self, status: Int) raises IoError:
        """A minimal response with `status` (usually `error_status()`),
        `Content-Length: 0` and `Connection: close`; the connection then
        closes. `InvalidInput` while a response is being sent."""
        if self._out == _OUT_BODY:
            raise self._misuse("ServerConnection.send_error")
        check_status(status, "ServerConnection.send_error")
        _status_line(self._tx, status, "")
        _write_str(self._tx, "Content-Length: 0\r\nConnection: close\r\n\r\n")
        self._out = _OUT_NONE
        self._closing = True
        self._in = _CLOSED
        self._rx.clear()

    def poll_transmit(mut self, mut out: ByteBuffer) raises IoError -> Int:
        var n = min(len(self._tx), out.max_writable())
        if n == 0:
            return 0
        out.write_bytes(self._tx.readable_span()[0:n])
        self._tx.consume(n)
        return n

    def pending_transmit(self) -> Int:
        """Bytes queued for sending."""
        return len(self._tx)

    # ---- state -----------------------------------------------------------

    def should_close(self) -> Bool:
        """Whether the driver closes the connection once everything queued
        is sent: a response or `send_error` ended it, the input failed, or
        the peer finished sending with no request left to answer."""
        if self._closing or self._failed:
            return True
        return self._eof and self._out == _OUT_NONE and (self._in == _HEAD or self._in == _CLOSED)

    def is_upgraded(self) -> Bool:
        return self._in == _UPGRADED

    def take_remaining(mut self) -> List[UInt8]:
        """The received bytes not consumed as HTTP (after an upgrade: the
        start of the new protocol). Empties the receive buffer."""
        var out = List[UInt8](self._rx.readable_span())
        self._rx.clear()
        return out^

    # ---- time ------------------------------------------------------------

    def set_deadline(mut self, at: Optional[Instant]):
        """Arm (or with None, disarm) a deadline, for example for the next
        request's head (a slow client); `handle_timeout` raises `TimedOut`
        once at or after it. The driver then answers 408 or closes."""
        self._deadline = at

    def next_deadline(self) -> Optional[Instant]:
        return self._deadline

    def handle_timeout(mut self, now: Instant) raises IoError:
        if self._deadline and now >= self._deadline.value():
            self._deadline = None
            raise IoError.of_kind("ServerConnection.handle_timeout", ErrorKind.TimedOut)


def _only_line_ends(data: Span[UInt8, _]) -> Bool:
    for b in data:
        if b != _CR and b != _LF:
            return False
    return True


def _check_reason(phrase: StringSlice, op: StaticString) raises IoError:
    for b in phrase.as_bytes():
        if not is_field_byte(b):
            raise IoError.of_kind(op, ErrorKind.InvalidInput)


# ---- ClientConnection ---------------------------------------------------------------


@fieldwise_init
struct _Sent(Copyable, Movable):
    """A request whose response has not ended."""

    var method: String
    var upgrade: Bool
    var close: Bool


struct ClientConnection(Codec, Copyable):
    """The client side of one HTTP/1.1 connection (see the module docs)."""

    comptime Event = ClientEvent

    comptime DEFAULT_MAX_BUFFERED = Limits.DEFAULT_MAX_HEAD + 16 * 1024

    var _rx: ByteBuffer
    var _tx: ByteBuffer
    var _parser: HeadParser
    var _body_limits: BodyLimits
    var _body: BodyDecoder
    var _trailers: Headers
    var _in: Int
    var _eof: Bool
    var _failed: Optional[IoError]
    var _deadline: Optional[Instant]
    var _flight: List[_Sent]
    var _max_in_flight: Int
    var _resp_keep: Bool
    var _seen: Bool
    """Bytes of the awaited response have arrived."""
    var _out: Int
    var _req_kind: BodyKind
    var _req_left: Int
    var _closing: Bool

    def __init__(
        out self,
        *,
        limits: Limits = Limits(),
        body_limits: BodyLimits = BodyLimits(),
        max_buffered: Int = Self.DEFAULT_MAX_BUFFERED,
        max_in_flight: Int = 1,
    ) raises IoError:
        if (
            max_buffered < limits.max_head
            or max_buffered < body_limits.max_trailers
            or max_buffered < body_limits.max_chunk_line + 2
            or max_in_flight < 1
        ):
            raise IoError.of_kind("ClientConnection.__init__", ErrorKind.InvalidInput)
        self._rx = ByteBuffer(max_size=max_buffered)
        self._tx = ByteBuffer()
        self._parser = HeadParser.for_responses(limits)
        self._body_limits = body_limits
        self._body = BodyDecoder(Framing.none(), lenient=True, limits=body_limits)
        self._trailers = Headers()
        self._in = _HEAD
        self._eof = False
        self._failed = None
        self._deadline = None
        self._flight = List[_Sent]()
        self._max_in_flight = max_in_flight
        self._resp_keep = True
        self._seen = False
        self._out = _OUT_NONE
        self._req_kind = BodyKind.NONE
        self._req_left = 0
        self._closing = False

    # ---- send ------------------------------------------------------------

    def _misuse(self, op: StaticString) -> IoError:
        return IoError.of_kind(op, ErrorKind.InvalidInput)

    def send_request(mut self, head: RequestHead) raises IoError:
        """Queue a request head; its framing comes from the head (see the
        module docs). `InvalidInput` (nothing queued) if the connection is
        closing or failed, a request is still being written, `max_in_flight`
        requests await responses, or the head is invalid: not HTTP/1.0 or
        1.1, a Host count wrong for its version, Transfer-Encoding other
        than `chunked` or together with Content-Length, or a bad method or
        target."""
        comptime op = "ClientConnection.send_request"
        if (
            self._closing
            or self._failed
            or self._in == _UPGRADED
            or self._out != _OUT_NONE
            or len(self._flight) >= self._max_in_flight
        ):
            raise self._misuse(op)
        var v = head.version
        if v.major != 1 or v.minor > 1:
            raise self._misuse(op)
        var hosts = head.headers.count("host")
        if hosts > 1 or (hosts == 0 and v.at_least_1_1()):
            raise self._misuse(op)
        var has_te = head.headers.contains("transfer-encoding")
        var cl: Optional[Int]
        try:
            cl = content_length(head.headers)
        except:
            raise self._misuse(op)
        if has_te and (cl or not _only_chunked(head.headers) or not v.at_least_1_1()):
            raise self._misuse(op)
        head.encode(self._tx)  # validates the method and target
        self._req_kind = BodyKind.CHUNKED if has_te else (
            BodyKind.LENGTH if cl else BodyKind.NONE
        )
        self._req_left = cl.value() if (cl and not has_te) else 0
        var close = not _persistent(v, head.headers)
        var upgrade = head.headers.contains("upgrade") and head.headers.has_token(
            "connection", "upgrade"
        )
        self._flight.append(_Sent(head.method, upgrade, close))
        self._out = _OUT_BODY
        if close:
            self._closing = True  # no requests after this one

    def send_body(mut self, data: Span[UInt8, _]) raises IoError:
        """Queue request body bytes. `InvalidInput` outside a request, past
        its Content-Length, or for a request without a body."""
        comptime op = "ClientConnection.send_body"
        if self._out != _OUT_BODY:
            raise self._misuse(op)
        var n = len(data)
        if self._req_kind == BodyKind.LENGTH:
            if n > self._req_left:
                raise self._misuse(op)
            self._tx.write_bytes(data)
            self._req_left -= n
        elif self._req_kind == BodyKind.CHUNKED:
            encode_chunk(data, self._tx)
        elif n > 0:
            raise self._misuse(op)

    def end_request(mut self, trailers: Headers = Headers()) raises IoError:
        """End the request (with trailers, for a chunked one). `InvalidInput`
        outside a request, short of its Content-Length, or for trailers on
        a body that is not chunked."""
        comptime op = "ClientConnection.end_request"
        if self._out != _OUT_BODY:
            raise self._misuse(op)
        if self._req_kind == BodyKind.LENGTH and self._req_left > 0:
            raise self._misuse(op)
        if len(trailers) > 0 and self._req_kind != BodyKind.CHUNKED:
            raise self._misuse(op)
        if self._req_kind == BodyKind.CHUNKED:
            encode_last_chunk(trailers, self._tx)
        self._out = _OUT_NONE

    def poll_transmit(mut self, mut out: ByteBuffer) raises IoError -> Int:
        var n = min(len(self._tx), out.max_writable())
        if n == 0:
            return 0
        out.write_bytes(self._tx.readable_span()[0:n])
        self._tx.consume(n)
        return n

    def pending_transmit(self) -> Int:
        return len(self._tx)

    # ---- receive ---------------------------------------------------------

    def _poison(mut self, e: IoError) -> IoError:
        self._failed = e
        return e

    def feed(mut self, data: Span[UInt8, _]) raises IoError:
        if self._failed:
            raise self._failed.value()
        if self._eof:
            raise IoError.of_kind("ClientConnection.feed", ErrorKind.InvalidInput)
        if self._in == _CLOSED:
            return
        if len(data) > self._rx.max_writable():
            raise self._poison(IoError.of_kind("ClientConnection.feed", ErrorKind.OutOfMemory))
        self._rx.write_bytes(data)

    def feed_capacity(self) -> Int:
        if self._in == _CLOSED:
            return Int.MAX
        return self._rx.max_writable()

    def feed_eof(mut self) raises IoError:
        if self._failed:
            raise self._failed.value()
        self._eof = True

    def next_event(mut self) raises IoError -> Optional[ClientEvent]:
        if self._failed:
            raise self._failed.value()
        while True:
            if self._in == _HEAD:
                return self._next_head()
            if self._in == _BODY:
                var r = self._next_body()
                if r:
                    return r^
                if self._in == _BODY:
                    return None
                continue
            return None  # _UPGRADED, _CLOSED

    def _next_head(mut self) raises IoError -> Optional[ClientEvent]:
        if len(self._flight) == 0:
            if len(self._rx) > 0:
                raise self._poison(IoError.of_kind(E_UNSOLICITED, ErrorKind.InvalidData))
            if self._eof:
                self._in = _CLOSED
            return None
        if len(self._rx) > 0:
            self._seen = True
        var head = ResponseHead()
        var got: Optional[Int]
        try:
            got = self._parser.response(self._rx.readable_span(), head)
        except e:
            raise self._poison(e)
        if not got:
            if self._eof:
                if not self._seen:
                    raise self._poison(IoError.of_kind(E_NO_RESPONSE, ErrorKind.UnexpectedEof))
                raise self._poison(IoError.of_kind(E_UNEXPECTED_EOF, ErrorKind.UnexpectedEof))
            return None
        self._rx.consume(got.value())
        var status = head.status
        if status >= 100 and status < 200 and status != 101:
            var ev = ClientEvent(EventKind.INFORMATIONAL)
            ev.head = head^
            return ev^
        ref sent = self._flight[0]
        if status == 101:
            if not sent.upgrade:
                raise self._poison(IoError.of_kind(E_BAD_101, ErrorKind.InvalidData))
            return self._upgraded(head^)
        var framing: Framing
        try:
            framing = response_framing(head, sent.method)
        except e:
            raise self._poison(e)
        if framing.kind == BodyKind.TUNNEL:
            return self._upgraded(head^)
        self._resp_keep = (
            _persistent(head.version, head.headers)
            and not sent.close
            and framing.kind != BodyKind.CLOSE
        )
        self._body = BodyDecoder(framing, lenient=True, limits=self._body_limits)
        self._in = _BODY
        var ev = ClientEvent(EventKind.HEAD)
        ev.head = head^
        ev.framing = framing
        return ev^

    def _upgraded(mut self, var head: ResponseHead) -> ClientEvent:
        _ = self._flight.pop(0)
        self._in = _UPGRADED
        self._closing = True  # no more HTTP requests
        var ev = ClientEvent(EventKind.UPGRADE)
        ev.head = head^
        return ev^

    def _next_body(mut self) raises IoError -> Optional[ClientEvent]:
        while True:
            var piece: Piece
            try:
                piece = self._body.decode(self._rx.readable_span(), self._trailers)
            except e:
                raise self._poison(e)
            if piece.len > 0:
                var ev = ClientEvent(EventKind.DATA)
                ev.data = List[UInt8](self._rx.readable_span()[piece.start : piece.start + piece.len])
                self._rx.consume(piece.consumed)
                return ev^
            self._rx.consume(piece.consumed)
            if self._body.is_done():
                _ = self._flight.pop(0)
                self._seen = False
                if self._resp_keep:
                    self._in = _HEAD
                else:
                    self._closing = True
                    self._in = _CLOSED
                    self._rx.clear()
                var ev = ClientEvent(EventKind.END)
                swap(ev.trailers, self._trailers)
                return ev^
            if piece.consumed == 0:
                if self._eof:
                    try:
                        self._body.finish()
                    except e:
                        raise self._poison(e)
                    continue
                return None

    # ---- state -----------------------------------------------------------

    def is_idle(self) -> Bool:
        """Reusable now: no request is in flight or being written, and the
        connection is not closing or failed (a pool checks this, then
        `idle_state()` on the socket)."""
        return (
            self._in == _HEAD
            and len(self._flight) == 0
            and self._out == _OUT_NONE
            and not self._closing
            and not self._failed
            and not self._eof
        )

    def unanswered(self) -> Int:
        """Requests sent whose responses have not ended."""
        return len(self._flight)

    def should_close(self) -> Bool:
        """The connection cannot carry more requests: it is closing,
        failed, upgraded, or the server finished sending."""
        return self._closing or Bool(self._failed) or self._eof

    def is_upgraded(self) -> Bool:
        return self._in == _UPGRADED

    def take_remaining(mut self) -> List[UInt8]:
        """The received bytes not consumed as HTTP (after an upgrade: the
        start of the new protocol). Empties the receive buffer."""
        var out = List[UInt8](self._rx.readable_span())
        self._rx.clear()
        return out^

    # ---- time ------------------------------------------------------------

    def set_deadline(mut self, at: Optional[Instant]):
        self._deadline = at

    def next_deadline(self) -> Optional[Instant]:
        return self._deadline

    def handle_timeout(mut self, now: Instant) raises IoError:
        if self._deadline and now >= self._deadline.value():
            self._deadline = None
            raise IoError.of_kind("ClientConnection.handle_timeout", ErrorKind.TimedOut)
