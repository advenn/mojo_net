"""HTTP/1.1 connections as sans-I/O codecs (design contract 1):
`ServerConnection` is the server side of one connection, `ClientConnection`
the client side. Both implement `bytes.codec.Codec`: the driver feeds the
bytes it receives, drains events, and sends what `poll_transmit` hands out.

Events are owned values (`ServerEvent`, `ClientEvent`): a `HEAD`, the body
as `DATA` pieces, then `END` with the trailers (empty if none). A message
without a body still gets its `END`. `DATA` comes out as soon as body bytes
arrive, so its pieces depend on how the input was split; their
concatenation and every other event do not (contract rule 4, refined for
byte streams). `next_event()` returns a new event; `poll(ev)` fills one the
caller keeps, reusing its head, header arena and buffers, which is what a
server's hot loop wants. The events box their head and trailers in
one-element lists: in Mojo 1.2 an `Optional` of a large struct is slow to
destroy (CLAUDE.md).

**ServerConnection**
- One request at a time: the next request is parsed only once the current
  one's response has ended. Pipelined requests wait in the receive buffer;
  when it is full, `feed_capacity()` is 0 until the response ends, so the
  driver stops reading (backpressure). This is where the codec departs from
  contract rule 5, which assumes a codec never waits on its application.
- Requests are checked after parsing: HTTP/1.x only (505 otherwise); one
  Host in HTTP/1.1 and at most one in HTTP/1.0, with a valid value (RFC
  9112 3.2); no Content-Length or Transfer-Encoding on CONNECT, whose
  following bytes are the tunnel's (RFC 9110 9.3.6).
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
  needed, never next to a contradicting field of the application's.
- A response may go out before its request has fully arrived. The
  request's remaining events still come (an application that answered may
  ignore them). Answering before the body has arrived keeps the connection
  only if what is left is a known length of at most 256 KiB, which the
  codec goes on reading; otherwise (a chunked or larger rest, or a body the
  client may withhold because it waited for a 100 Continue that never
  came) the response says `Connection: close` and the connection closes
  after it (RFC 9110 10.1.1).
- A 101 answering an HTTP/1.1 Upgrade request, or a 2xx answering CONNECT,
  ends HTTP on the connection once its head is queued: `is_upgraded()`,
  and `take_remaining()` returns the bytes received after the request. The
  request body must have been read first.
- A malformed request poisons the input side (rule 6). `error_status()` is
  the status to answer with (400, 414, 431, 501 or 505), which
  `send_error()` sends before the connection closes.
- `close_gracefully()` (a server shutting down): the request in progress
  gets the last response on the connection, which says `Connection: close`
  if its head has not gone out yet; requests after it are not read. An
  idle connection (nothing received since the last response) closes at
  once.
- `should_close()`: once `poll_transmit` has handed everything out, the
  driver closes the connection. If `input_pending()`, the client may
  still be sending (input was left unread), and the driver should close
  in stages, as RFC 9112 9.6 describes: shut down its write side, and
  read and drop input until the client's end, or for a while. A reset
  from closing at once can erase the response before the client reads
  it.

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
  from its head on (`should_close()`); requests still in flight are lost
  (`unanswered()`). So do bytes left over after the last response (RFC
  9112 6.3: never taken as a response; stray line ends are dropped) and a
  response with both Transfer-Encoding and Content-Length (possible
  smuggling).
  EOF before any byte of a response raises `UnexpectedEof` with
  `E_NO_RESPONSE`, so a client knows the server never saw (or never
  answered) the request and may retry an idempotent one.
"""

from std.memory import unsafe_memcpy

from bytes.buffer import ByteBuffer
from bytes.codec import Codec
from linux import ErrorKind, IoError
from linux.time import Instant

from .body import (
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
comptime E_PARTIAL = "http: connection closed in a message head"
comptime E_CONNECT_BODY = "http: CONNECT with a body"

comptime _DRAIN_LIMIT = 256 * 1024
"""The request body a server keeps reading after an early response
(answered before the body ended) to keep the connection; beyond this it
closes instead."""

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
    """What a `ServerConnection` received: `HEAD` (`take_head()`,
    `framing`), `DATA` (`data`), `END` (`take_trailers()`). The head and
    trailers are boxed in one-element lists to keep the event small: a
    large struct inside an `Optional` is slow to destroy in Mojo 1.2."""

    var kind: EventKind
    var framing: Framing
    var data: List[UInt8]
    var _head: List[RequestHead]
    var _trailers: List[Headers]

    def __init__(out self, kind: EventKind):
        self.kind = kind
        self.framing = Framing.none()
        self.data = List[UInt8]()
        self._head = List[RequestHead]()
        self._trailers = List[Headers]()

    def has_head(self) -> Bool:
        return len(self._head) > 0

    def head(ref self) raises IoError -> ref [self._head[0]] RequestHead:
        """The head, borrowed (`HEAD` events). `InvalidInput` otherwise."""
        if self.kind != EventKind.HEAD or len(self._head) == 0:
            raise IoError.of_kind("ServerEvent.head", ErrorKind.InvalidInput)
        return self._head[0]

    def take_head(mut self) raises IoError -> RequestHead:
        """Move the head out (`HEAD` events). `InvalidInput` otherwise."""
        if self.kind != EventKind.HEAD or len(self._head) == 0:
            raise IoError.of_kind("ServerEvent.take_head", ErrorKind.InvalidInput)
        return self._head.pop()

    def take_trailers(mut self) -> Headers:
        """The trailer fields of an `END` event (empty if none)."""
        if self.kind != EventKind.END or len(self._trailers) == 0:
            return Headers()
        return self._trailers.pop()

    def take_data(mut self) -> List[UInt8]:
        var out = List[UInt8]()
        swap(out, self.data)
        return out^

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.kind)
        if self.kind == EventKind.HEAD and len(self._head) > 0:
            ref h = self._head[0]
            writer.write(" ", h.method, " ", h.target, " ", h.version, " ", self.framing)
        elif self.kind == EventKind.DATA:
            writer.write(" ", String(from_utf8_lossy=Span(self.data)))
        elif self.kind == EventKind.END and len(self._trailers) > 0 and len(self._trailers[0]) > 0:
            writer.write(" ", self._trailers[0])


struct ClientEvent(Movable, Writable):
    """What a `ClientConnection` received: `INFORMATIONAL`, `HEAD` and
    `UPGRADE` (`head()` / `take_head()`, and `framing` for `HEAD`), `DATA`
    (`data`), `END` (`take_trailers()`). The head and trailers are boxed in
    one-element lists to keep the event small (see `ServerEvent`)."""

    var kind: EventKind
    var framing: Framing
    var data: List[UInt8]
    var _head: List[ResponseHead]
    var _trailers: List[Headers]

    def __init__(out self, kind: EventKind):
        self.kind = kind
        self.framing = Framing.none()
        self.data = List[UInt8]()
        self._head = List[ResponseHead]()
        self._trailers = List[Headers]()

    @inline(.always)
    def _has_head(self) -> Bool:
        return (
            self.kind == EventKind.HEAD
            or self.kind == EventKind.INFORMATIONAL
            or self.kind == EventKind.UPGRADE
        ) and len(self._head) > 0

    def head(ref self) raises IoError -> ref [self._head[0]] ResponseHead:
        """The head, borrowed (`INFORMATIONAL`, `HEAD`, `UPGRADE`).
        `InvalidInput` otherwise."""
        if not self._has_head():
            raise IoError.of_kind("ClientEvent.head", ErrorKind.InvalidInput)
        return self._head[0]

    def take_head(mut self) raises IoError -> ResponseHead:
        """Move the head out. `InvalidInput` for an event without one."""
        if not self._has_head():
            raise IoError.of_kind("ClientEvent.take_head", ErrorKind.InvalidInput)
        return self._head.pop()

    def take_trailers(mut self) -> Headers:
        """The trailer fields of an `END` event (empty if none)."""
        if self.kind != EventKind.END or len(self._trailers) == 0:
            return Headers()
        return self._trailers.pop()

    def take_data(mut self) -> List[UInt8]:
        var out = List[UInt8]()
        swap(out, self.data)
        return out^

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.kind)
        if self._has_head():
            ref h = self._head[0]
            writer.write(" ", h.status, " ", h.version)
            if self.kind == EventKind.HEAD:
                writer.write(" ", self.framing)
        elif self.kind == EventKind.DATA:
            writer.write(" ", String(from_utf8_lossy=Span(self.data)))
        elif self.kind == EventKind.END and len(self._trailers) > 0 and len(self._trailers[0]) > 0:
            writer.write(" ", self._trailers[0])


# ---- shared -----------------------------------------------------------------------


def _persistent(version: Version, headers: Headers) -> Bool:
    """Whether a message lets the connection persist (RFC 9112 9.3)."""
    if headers.has_token("connection", "close"):
        return False
    if version.at_least_1_1():
        return True
    return headers.has_token("connection", "keep-alive")


@fieldwise_init
struct _Summary(TrivialRegisterPassable):
    """What one pass over a head's fields finds for framing and
    persistence (the rest of a request's fields are the application's)."""

    var hosts: Int
    var host_at: Int
    """The index of the (last) Host field."""
    var cls: Int
    """Content-Length field lines."""
    var cl_at: Int
    var has_cl: Bool
    var has_te: Bool
    var has_upgrade: Bool
    var conn_close: Bool
    var conn_keep_alive: Bool
    var conn_upgrade: Bool
    var expect_continue: Bool


def _summarize(headers: Headers) -> _Summary:
    var s = _Summary(0, -1, 0, -1, False, False, False, False, False, False, False)
    for i in range(len(headers._fields)):
        var f = headers._fields[i]
        var name = headers._bytes(f.name, f.name_len)
        var n = len(name)
        if n == 4:
            if eq_ignore_case(name, "host".as_bytes()):
                s.hosts += 1
                s.host_at = i
        elif n == 10:
            if eq_ignore_case(name, "connection".as_bytes()):
                var v = headers._bytes(f.value, f.value_len)
                var pos = 0
                while True:
                    var e = next_element(v, pos)
                    if not e:
                        break
                    var b = e.value()
                    var t = v[b.start : b.end]
                    if eq_ignore_case(t, "close".as_bytes()):
                        s.conn_close = True
                    elif eq_ignore_case(t, "keep-alive".as_bytes()):
                        s.conn_keep_alive = True
                    elif eq_ignore_case(t, "upgrade".as_bytes()):
                        s.conn_upgrade = True
        elif n == 14:
            if eq_ignore_case(name, "content-length".as_bytes()):
                s.has_cl = True
                s.cls += 1
                s.cl_at = i
        elif n == 17:
            if eq_ignore_case(name, "transfer-encoding".as_bytes()):
                s.has_te = True
        elif n == 7:
            if eq_ignore_case(name, "upgrade".as_bytes()):
                s.has_upgrade = True
        elif n == 6:
            if eq_ignore_case(name, "expect".as_bytes()):
                var v = headers._bytes(f.value, f.value_len)
                var pos = 0
                while True:
                    var e = next_element(v, pos)
                    if not e:
                        break
                    var b = e.value()
                    if eq_ignore_case(v[b.start : b.end], "100-continue".as_bytes()):
                        s.expect_continue = True
    return s


def _valid_host(v: Span[UInt8, _]) -> Bool:
    """A Host field value (RFC 9112 3.2, RFC 3986 3.2.2): empty, or
    uri-host [ ":" port ], where uri-host is an IP literal in brackets or a
    reg-name (unreserved, percent-encoded or sub-delims bytes)."""
    var n = len(v)
    var i = 0
    if n > 0 and v[0] == 91:  # "["
        i = 1
        while i < n and v[i] != 93:  # "]"
            var c = v[i]
            if not (_is_hex(c) or c == 58 or c == 46 or c == 118 or c == 86):  # : . v V
                return False
            i += 1
        if i == n or i == 1:
            return False
        i += 1
    else:
        while i < n and v[i] != 58:  # up to ":"
            var c = v[i]
            if c == 37:  # "%" HEXDIG HEXDIG
                if i + 2 >= n or not _is_hex(v[i + 1]) or not _is_hex(v[i + 2]):
                    return False
                i += 3
                continue
            if not _is_reg_name_byte(c):
                return False
            i += 1
    if i < n:
        if v[i] != 58:
            return False
        for k in range(i + 1, n):
            if v[k] < 48 or v[k] > 57:
                return False
    return True


@inline(.always)
def _is_hex(c: UInt8) -> Bool:
    return (c >= 48 and c <= 57) or ((c | 0x20) >= 97 and (c | 0x20) <= 102)


@inline(.always)
def _is_reg_name_byte(c: UInt8) -> Bool:
    """unreserved and sub-delims (RFC 3986 2.2, 2.3)."""
    if (c >= 48 and c <= 57) or ((c | 0x20) >= 97 and (c | 0x20) <= 122):
        return True
    return (
        c == 45 or c == 46 or c == 95 or c == 126  # - . _ ~
        or c == 33 or c == 36 or c == 38 or c == 39  # ! $ & '
        or c == 40 or c == 41 or c == 42 or c == 43  # ( ) * +
        or c == 44 or c == 59 or c == 61  # , ; =
    )


def _content_length(headers: Headers, s: _Summary) raises IoError -> Optional[Int]:
    """`content_length` with a fast path for the usual single field of
    digits (lists, repeats and errors go through the general one)."""
    if not s.has_cl:
        return None
    if s.cls == 1:
        var f = headers._fields[s.cl_at]
        var v = headers._bytes(f.value, f.value_len)
        if len(v) >= 1 and len(v) <= 18:
            var n = 0
            var digits = True
            for b in v:
                if b < 48 or b > 57:
                    digits = False
                    break
                n = n * 10 + Int(b) - 48
            if digits:
                return n
    return content_length(headers)


@inline(.always)
def _keeps(version: Version, s: _Summary) -> Bool:
    """`_persistent` from a summary."""
    if s.conn_close:
        return False
    return version.at_least_1_1() or s.conn_keep_alive


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
    is empty. One bounds check and copy (it runs once per response)."""
    if phrase.byte_length() > 0:
        _status_line_bytes(out, status, phrase.as_bytes())
    else:
        _status_line_bytes(out, status, reason(status).as_bytes())


def _status_line_bytes(mut out: ByteBuffer, status: Int, phrase: Span[UInt8, _]) raises IoError:
    var n = 13 + len(phrase) + 2
    out.ensure_writable(n)
    var dst = out.writable_span().unsafe_ptr()
    var lead = "HTTP/1.1 ".as_bytes()
    unsafe_memcpy(dest=dst, src=lead.unsafe_ptr(), count=9)
    dst[unsafe_offset=9] = UInt8(48 + status // 100)
    dst[unsafe_offset=10] = UInt8(48 + status // 10 % 10)
    dst[unsafe_offset=11] = UInt8(48 + status % 10)
    dst[unsafe_offset=12] = 32
    unsafe_memcpy(dest=dst.unsafe_offset(13), src=phrase.unsafe_ptr(), count=len(phrase))
    dst[unsafe_offset=13 + len(phrase)] = _CR
    dst[unsafe_offset=14 + len(phrase)] = _LF
    out.commit(n)


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
    var _expect: Bool
    """The request expects 100-continue."""
    var _continued: Bool
    """100 Continue was sent."""
    var _answered: Bool
    """Its response ended before its END event was delivered."""
    # its response
    var _out: Int
    var _resp_kind: BodyKind
    var _resp_left: Int
    var _resp_close: Bool
    var _closing: Bool
    var _draining: Bool
    """`close_gracefully()` was called: no request after the current one."""
    var _unread: Bool
    """The connection closed with input left unread (`input_pending()`)."""

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
            or max_buffered - 2 < body_limits.max_chunk_line
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
        self._expect = False
        self._continued = False
        self._answered = False
        self._out = _OUT_NONE
        self._resp_kind = BodyKind.NONE
        self._resp_left = 0
        self._resp_close = False
        self._closing = False
        self._draining = False
        self._unread = False

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
        """The next event, if one is ready (the `Codec` interface). `poll`
        does the same into an event the caller reuses, which saves an
        allocation or two per request."""
        var ev = ServerEvent(EventKind.END)
        if self.poll(ev):
            return ev^
        return None

    def poll(mut self, mut ev: ServerEvent) raises IoError -> Bool:
        """Fill `ev` with the next event and return True, or return False
        when none is ready (`ev` is then unchanged). `ev`'s buffers are
        reused: a head left in it (not taken) is parsed over, its data and
        trailers are refilled."""
        if self._failed:
            raise self._failed.value()
        while True:
            if self._in == _HEAD:  # (after _WAIT: the response has ended)
                return self._poll_head(ev)
            if self._in == _BODY:
                if self._poll_body(ev):
                    return True
                if self._in == _BODY:
                    return False
                continue
            return False  # _WAIT (one request at a time), _UPGRADED, _CLOSED

    def _poll_head(mut self, mut ev: ServerEvent) raises IoError -> Bool:
        if len(ev._head) == 0:
            ev._head.append(RequestHead())
        ref head = ev._head[0]
        var got: Optional[Int]
        try:
            got = self._parser.request(self._rx.readable_span(), head)
        except e:
            raise self._poison(e, self._parser.error_status())
        if not got:
            if self._eof:
                if _only_line_ends(self._rx.readable_span()):
                    self._in = _CLOSED  # closed between requests
                    return False
                raise self._poison(IoError.of_kind(E_PARTIAL, ErrorKind.UnexpectedEof), 400)
            return False
        self._rx.consume(got.value())
        if head.version.major != 1:
            raise self._poison(IoError.of_kind(E_VERSION, ErrorKind.InvalidData), 505)
        var sum = _summarize(head.headers)
        if sum.hosts > 1 or (sum.hosts == 0 and head.version.at_least_1_1()):
            raise self._poison(IoError.of_kind(E_HOST, ErrorKind.InvalidData), 400)
        if sum.hosts == 1:
            var f = head.headers._fields[sum.host_at]
            if not _valid_host(head.headers._bytes(f.value, f.value_len)):
                raise self._poison(IoError.of_kind(E_HOST, ErrorKind.InvalidData), 400)
        if head.method == "CONNECT" and (sum.has_cl or sum.has_te):
            # A CONNECT request has no content (RFC 9110 9.3.6): what follows
            # its head belongs to the tunnel, so framing fields are refused.
            raise self._poison(IoError.of_kind(E_CONNECT_BODY, ErrorKind.InvalidData), 400)
        var framing = Framing.none()
        if sum.has_cl or sum.has_te:
            try:
                framing = request_framing(head)
            except e:
                raise self._poison(e, 501 if e.kind == ErrorKind.Unsupported else 400)
        self._method = head.method
        self._version = head.version
        self._keep = _keeps(head.version, sum)
        # Upgrade is ignored in HTTP/1.0 (RFC 9110 7.8), which gets no 1xx.
        self._upgrade = sum.has_upgrade and sum.conn_upgrade and head.version.at_least_1_1()
        self._expect = sum.expect_continue and head.version.at_least_1_1()
        self._continued = False
        self._answered = False
        self._body.restart(framing)
        self._out = _OUT_PENDING
        self._in = _BODY
        ev.kind = EventKind.HEAD
        ev.framing = framing
        return True

    def _poll_body(mut self, mut ev: ServerEvent) raises IoError -> Bool:
        """The next DATA or END event into `ev`, or False with `_in` still
        `_BODY` when more input is needed (or a phase change to look at)."""
        while True:
            var piece: Piece
            try:
                piece = self._body.decode(self._rx.readable_span(), self._trailers)
            except e:
                raise self._poison(e, self._body.error_status())
            if piece.len > 0:
                ev.kind = EventKind.DATA
                ev.data.clear()
                ev.data.extend(self._rx.readable_span()[piece.start : piece.start + piece.len])
                self._rx.consume(piece.consumed)
                return True
            self._rx.consume(piece.consumed)
            if self._body.is_done():
                # One request at a time: wait for its response to end, unless
                # it already has.
                if self._answered and self._draining:
                    self._closing = True  # it was the last one
                    self._unread = len(self._rx) > 0
                    self._in = _CLOSED
                    self._rx.clear()
                else:
                    self._in = _HEAD if self._answered else _WAIT
                self._answered = False
                ev.kind = EventKind.END
                if len(ev._trailers) == 0:
                    ev._trailers.append(Headers())
                swap(ev._trailers[0], self._trailers)
                self._trailers.clear()  # the event's old trailers, emptied for reuse
                return True
            if piece.consumed == 0:
                if self._eof:
                    try:
                        self._body.finish()
                    except e:
                        raise self._poison(e, 400)
                    continue
                return False

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
            self._continued = True

    def send_informational(mut self, head: ResponseHead) raises IoError:
        """A 1xx response other than 101 (103 Early Hints, say) before the
        final one. A no-op for an HTTP/1.0 client."""
        if self._out != _OUT_PENDING or head.status < 100 or head.status > 199 or head.status == 101:
            raise self._misuse("ServerConnection.send_informational")
        _check_reason(head.reason, "ServerConnection.send_informational")
        var sum = _summarize(head.headers)
        if sum.has_cl or sum.has_te:  # never on a 1xx (RFC 9110 8.6, RFC 9112 6.1)
            raise self._misuse("ServerConnection.send_informational")
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
        var sum = _summarize(head.headers)
        var has_te = sum.has_te
        var cl: Optional[Int]
        try:
            cl = _content_length(head.headers, sum)
        except:
            raise self._misuse(op)
        var connect_ok = self._method == "CONNECT" and status >= 200 and status < 300
        var switch = status == 101 or connect_ok
        if status == 101 and not self._upgrade:
            raise self._misuse(op)
        if switch and not self._body.is_done():
            # The rest of the request body would reach the new protocol.
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
            or self._draining
            or kind == BodyKind.CLOSE
            or sum.conn_close
            or not self._can_drain()
        ) and not switch
        var add_close = close and not sum.conn_close
        var add_keep = (
            not close
            and not switch
            and not self._version.at_least_1_1()
            and not sum.conn_keep_alive
        )
        self._tx.ensure_writable(
            16 + head.reason.byte_length() + head.headers.encoded_len() + 64
        )
        _status_line(self._tx, status, head.reason)
        if add_close and sum.conn_keep_alive:
            # The application's keep-alive no longer holds: drop its
            # Connection fields rather than send contradictory ones.
            head.headers._encode_except(self._tx, "connection")
        else:
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

    def _can_drain(self) -> Bool:
        """Whether the connection survives a response sent now: true once
        the request body has arrived, or when what is left of it is a known
        length within `_DRAIN_LIMIT` that the client will send (it did not
        wait for a 100 Continue it never got)."""
        if self._body.is_done():
            return True
        if self._expect and not self._continued:
            return False  # the client may never send it
        var left = self._body.remaining()
        return Bool(left) and left.value() <= _DRAIN_LIMIT

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
        var head_req = self._method == "HEAD"
        if len(trailers) > 0 and self._resp_kind != BodyKind.CHUNKED and not head_req:
            raise self._misuse(op)  # (trailers for HEAD are dropped, like its body)
        if self._resp_kind == BodyKind.CHUNKED:
            encode_last_chunk(trailers, self._tx)
        self._out = _OUT_NONE
        if self._resp_close or self._failed:
            self._closing = True
            # unread: the rest of this request, or what came after it
            self._unread = self._in != _WAIT or len(self._rx) > 0
            self._in = _CLOSED
            self._rx.clear()
        elif self._in == _WAIT:
            self._in = _HEAD
        else:
            # The rest of the request (body, END) is still to come: read it,
            # then go on with the next request.
            self._answered = True

    def send_error(mut self, status: Int) raises IoError:
        """A minimal response with `status` (usually `error_status()`, and
        always 400..599), `Content-Length: 0` and `Connection: close`; the
        connection then closes. `InvalidInput` for another status or while
        a response is being sent."""
        if self._out == _OUT_BODY or status < 400 or status > 599:
            raise self._misuse("ServerConnection.send_error")
        _status_line(self._tx, status, "")
        _write_str(self._tx, "Content-Length: 0\r\nConnection: close\r\n\r\n")
        self._out = _OUT_NONE
        self._closing = True
        self._unread = True  # what the client sends is not followed
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

    def buffered(self) -> Int:
        """Received bytes held and not yet consumed: a partial head, say
        (a driver's timeout tells an idle connection from a slow request
        this way)."""
        return len(self._rx)

    # ---- state -----------------------------------------------------------

    def close_gracefully(mut self):
        """Take no request after the current one (a server shutting down).
        A response being sent is the last: the connection closes after it.
        A request waiting for its response, or still arriving, gets the
        last one, with `Connection: close`. An idle connection, with
        nothing received since its last response but line ends, closes at
        once (`should_close()`). Calling it again changes nothing."""
        self._draining = True
        if self._out == _OUT_BODY:
            self._resp_close = True
        elif (
            self._out == _OUT_NONE
            and self._in == _HEAD
            and _only_line_ends(self._rx.readable_span())
        ):
            self._closing = True
            self._in = _CLOSED
            self._rx.clear()

    def input_pending(self) -> Bool:
        """Whether the client may still be sending when the connection
        closes: input was left unread (a request answered before its body
        arrived, requests pipelined after the last response, a malformed
        request). Then close in stages (see the module docs)."""
        return self._unread or Bool(self._failed)

    def should_close(self) -> Bool:
        """Whether the driver closes the connection once everything queued
        is sent: a response or `send_error` ended it, the input failed, or
        the peer finished sending with no request left to answer."""
        if self._closing or self._failed:
            return True
        # After EOF, bytes still buffered may hold a request to answer: poll
        # first (it either delivers one or finds the input ended).
        return self._eof and self._out == _OUT_NONE and (
            (self._in == _HEAD and len(self._rx) == 0) or self._in == _CLOSED
        )

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
            or max_buffered - 2 < body_limits.max_chunk_line
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
        if len(self._flight) == 0 and len(self._rx) > 0:
            self._discard_strays()
        if (
            self._closing
            or self._failed
            or self._eof
            or self._in == _UPGRADED
            or self._in == _CLOSED
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
        var upgrade = (
            v.at_least_1_1()  # a 101 never answers HTTP/1.0 (RFC 9110 7.8, 15.2)
            and head.headers.contains("upgrade")
            and head.headers.has_token("connection", "upgrade")
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
        """The next event, if one is ready (the `Codec` interface); `poll`
        does the same into an event the caller reuses."""
        var ev = ClientEvent(EventKind.END)
        if self.poll(ev):
            return ev^
        return None

    def poll(mut self, mut ev: ClientEvent) raises IoError -> Bool:
        """Fill `ev` with the next event and return True, or return False
        when none is ready (`ev` is then unchanged). `ev`'s buffers are
        reused, as for `ServerConnection.poll`."""
        if self._failed:
            raise self._failed.value()
        while True:
            if self._in == _HEAD:
                return self._poll_head(ev)
            if self._in == _BODY:
                if self._poll_body(ev):
                    return True
                if self._in == _BODY:
                    return False
                continue
            return False  # _UPGRADED, _CLOSED

    def _discard_strays(mut self):
        """Bytes received with no request in flight: line ends are dropped
        (some servers end a message with an extra CRLF); anything else means
        the connection is out of step, so it closes (RFC 9112 6.3: such data
        is never taken as a response)."""
        if _only_line_ends(self._rx.readable_span()):
            self._rx.clear()
        else:
            self._rx.clear()
            self._closing = True
            self._in = _CLOSED

    def _poll_head(mut self, mut ev: ClientEvent) raises IoError -> Bool:
        if len(self._flight) == 0:
            if len(self._rx) > 0:
                if not _only_line_ends(self._rx.readable_span()):
                    raise self._poison(IoError.of_kind(E_UNSOLICITED, ErrorKind.InvalidData))
                self._rx.clear()
            if self._eof:
                self._in = _CLOSED
            return False
        if not self._seen and len(self._rx) > 0 and not _only_line_ends(self._rx.readable_span()):
            self._seen = True  # (stray line ends do not start a response)
        if len(ev._head) == 0:
            ev._head.append(ResponseHead())
        ref head = ev._head[0]
        var got: Optional[Int]
        try:
            got = self._parser.response(self._rx.readable_span(), head)
        except e:
            raise self._poison(e)
        if not got:
            if self._eof:
                if not self._seen:
                    raise self._poison(IoError.of_kind(E_NO_RESPONSE, ErrorKind.UnexpectedEof))
                raise self._poison(IoError.of_kind(E_PARTIAL, ErrorKind.UnexpectedEof))
            return False
        self._rx.consume(got.value())
        var status = head.status
        if status >= 100 and status < 200 and status != 101:
            ev.kind = EventKind.INFORMATIONAL
            return True
        ref sent = self._flight[0]
        if status == 101:
            if not sent.upgrade:
                raise self._poison(IoError.of_kind(E_BAD_101, ErrorKind.InvalidData))
            self._upgraded()
            ev.kind = EventKind.UPGRADE
            return True
        var framing: Framing
        try:
            framing = response_framing(head, sent.method)
        except e:
            raise self._poison(e)
        if framing.kind == BodyKind.TUNNEL:
            self._upgraded()
            ev.kind = EventKind.UPGRADE
            return True
        var sum = _summarize(head.headers)
        self._resp_keep = (
            _keeps(head.version, sum)
            and not sent.close
            and framing.kind != BodyKind.CLOSE
            # Transfer-Encoding with Content-Length may be smuggling
            # (RFC 9112 6.3): read this response, then close.
            and not (sum.has_te and sum.has_cl)
        )
        if not self._resp_keep:
            self._closing = True  # no requests after this one
        self._body.restart(framing)
        self._in = _BODY
        ev.kind = EventKind.HEAD
        ev.framing = framing
        return True

    def _upgraded(mut self):
        _ = self._flight.pop(0)
        self._in = _UPGRADED
        self._closing = True  # no more HTTP requests

    def _poll_body(mut self, mut ev: ClientEvent) raises IoError -> Bool:
        while True:
            var piece: Piece
            try:
                piece = self._body.decode(self._rx.readable_span(), self._trailers)
            except e:
                raise self._poison(e)
            if piece.len > 0:
                ev.kind = EventKind.DATA
                ev.data.clear()
                ev.data.extend(self._rx.readable_span()[piece.start : piece.start + piece.len])
                self._rx.consume(piece.consumed)
                return True
            self._rx.consume(piece.consumed)
            if self._body.is_done():
                _ = self._flight.pop(0)
                self._seen = False
                if self._resp_keep:
                    self._in = _HEAD
                    if len(self._flight) == 0 and len(self._rx) > 0:
                        self._discard_strays()
                else:
                    self._closing = True
                    self._in = _CLOSED
                    self._rx.clear()
                ev.kind = EventKind.END
                if len(ev._trailers) == 0:
                    ev._trailers.append(Headers())
                swap(ev._trailers[0], self._trailers)
                self._trailers.clear()
                return True
            if piece.consumed == 0:
                if self._eof:
                    try:
                        self._body.finish()
                    except e:
                        raise self._poison(e)
                    continue
                return False

    # ---- state -----------------------------------------------------------

    def is_idle(self) -> Bool:
        """Reusable now: no request is in flight or being written, and the
        connection is not closing or failed (a pool checks this, then
        `idle_state()` on the socket)."""
        return (
            self._in == _HEAD
            and len(self._flight) == 0
            and self._out == _OUT_NONE
            and len(self._rx) == 0
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
