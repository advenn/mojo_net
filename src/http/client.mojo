"""A blocking HTTP/1.1 client over `net` and `tls`: `Client` sends requests
to `http://` and `https://` URLs and reads whole responses, keeping
connections alive in a small pool. It drives
`http.connection.ClientConnection` over a `TcpStream`, or a `TlsStream`;
`client` and `server` are the only `http` modules that do I/O.

    var client = Client()
    var r = client.get("https://example.com/")
    print(r.status, r.text())

- URLs: `http://host[:port][/path][?query]` and `https://...`
  (`Url.parse`), with IPv6 literals in brackets; user info in the
  authority is `InvalidInput`, and a fragment is dropped.
- HTTPS (docs/tls.md, milestone H8): the server's certificate must be valid
  for the URL's host (or IP address), under the `tls` package's policy and
  the trust given to `Client(tls=...)` (system roots by default). ALPN
  offers `http/1.1`. A TLS failure raises the `IoError` inside the
  `TlsError` (`PermissionDenied` for a refused certificate);
  `last_tls_error()` says why. The OpenSSL context is built on the first
  `https://` request, so plain HTTP never loads OpenSSL.
- A TLS connection that ends without close_notify (RFC 9112 9.8): a
  response complete by its Content-Length or its last chunk stands; one
  delimited by the end of the connection does not (`UnexpectedEof`), since
  an attacker can cut a TLS connection short.
- One deadline per request (`timeout`, default 30 s) covers name
  resolution, connecting (Happy Eyeballs), sending and receiving, also a
  response that keeps trickling in.
- Request bodies of any size are streamed to the socket in pieces while
  the connection is watched for the response (RFC 9112 9.5), so a server
  that answers early (a 413) is heard and a full-duplex one cannot
  deadlock the request. An early response below 300 that keeps the
  connection does not stop the body: it is sent to the end first. One that
  closes, or a 3xx/4xx/5xx, stops it; its status says the body was not
  taken.
- When sending fails (the server reset the connection), a response it
  sent before is returned only if it is complete by its own framing
  (Content-Length or chunked): a response delimited by the close cannot be
  told from one the reset cut short, so the send error is raised.
- Responses are read whole, up to `max_body` bytes (default 16 MiB);
  `InvalidData` beyond, and the connection is dropped. At most 32 1xx
  responses may come before the final one.
- Headers: the client sends Host (unless the caller gives one),
  User-Agent (likewise), and Content-Length when there is a body or the
  method usually has one (POST, PUT, PATCH). The caller's headers follow,
  in order. A caller's Content-Length or Transfer-Encoding is refused
  (`InvalidInput`): the client frames the body.
- Connections are kept per scheme, host and port, at most `max_idle_per_host` of
  them and `max_idle_conns` in all (the oldest goes first), and reused only
  after `max_idle` at most, if `idle_state()` still says EMPTY and the
  codec holds nothing unread; connections idle longer are closed whichever
  host they are for. A reused connection can still turn out closed by the
  server (a race no check avoids). If that happens before any byte of the
  response, or the server answers 408 (it timed the idle connection out
  as the request arrived), an idempotent request (GET, HEAD, OPTIONS,
  TRACE, PUT, DELETE) is sent again, once, on a new connection.
- Not done: redirects (a 3xx is returned as is), cookies, content codings,
  CONNECT and upgrades (a request with an `Upgrade` field: `InvalidInput`),
  proxies.
"""

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError
from linux.consts import POLLERR, POLLHUP, POLLIN, POLLOUT
from linux.poll import wait_ready
from linux.time import Deadline, Duration, Instant
from net.addr import IpAddr
from net.blocking import IdleState
from net.resolver import Resolver
from net.tcp import TcpStream
from tls import Category, ClientConfig, ClientContext, TlsError
from tls.stream import TlsStream
from tls.target import Target

from .connection import E_NO_RESPONSE, ClientConnection, ClientEvent, EventKind
from .headers import Headers, is_token, lower_ascii
from .parse import RequestHead
from .sse import SseEvent, SseParser
from .types import Version

comptime _READ_SIZE = 64 * 1024
comptime _WRITE_PIECE = 64 * 1024
"""Body bytes handed to the codec at a time, so a body of any size is
streamed without a copy of all of it."""
comptime _MAX_INFORMATIONAL = 32
"""1xx responses accepted before the final one."""


# ---- URLs -------------------------------------------------------------------------


struct Url(Copyable, Movable, Writable):
    """An `http://` or `https://` URL split for a request."""

    var tls: Bool
    """https."""
    var host: String
    """The host name or IP literal, IPv6 without its brackets."""
    var port: UInt16
    var target: String
    """The request target: path and query, at least "/"."""

    def __init__(out self, host: StringSlice, port: UInt16, target: StringSlice, tls: Bool = False):
        self.tls = tls
        self.host = String(host)
        self.port = port
        self.target = String(target)

    @staticmethod
    def parse(text: StringSlice) raises IoError -> Url:
        """`http[s]://host[:port][/path][?query][#fragment]` (ports 80 and
        443 by default). `InvalidInput` for anything malformed: another
        scheme, user info, an empty host or one with characters outside
        letters, digits and `-._~`, a port outside 1..65535, or bytes in the
        path that are not visible ASCII (percent-encode them first)."""
        comptime op = "Url.parse"
        var b = text.as_bytes()
        var n = len(b)
        var sep = -1
        for i in range(n - 2):
            if b[i] == 58 and b[i + 1] == 47 and b[i + 2] == 47:  # "://"
                sep = i
                break
        if sep <= 0:
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        var scheme = String()
        for i in range(sep):
            scheme += chr(Int(lower_ascii(b[i])))
        if scheme != "http" and scheme != "https":
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        var tls = scheme == "https"
        var a = sep + 3
        var e = a
        while e < n and b[e] != 47 and b[e] != 63 and b[e] != 35:  # / ? #
            e += 1
        var host_lo = a
        var host_hi = e
        var port = 443 if tls else 80
        if a < e and b[a] == 91:  # "[" IPv6 literal "]"
            var close = a
            while close < e and b[close] != 93:
                close += 1
            if close == e:
                raise IoError.of_kind(op, ErrorKind.InvalidInput)
            host_lo = a + 1
            host_hi = close
            for i in range(host_lo, host_hi):
                var c = b[i]
                if not (_is_hex(c) or c == 58 or c == 46):  # hex, ":", "." (v4-mapped)
                    raise IoError.of_kind(op, ErrorKind.InvalidInput)
            # ... and an IPv6 address: `[127.0.0.1]` or `[1234]` would
            # otherwise reach the resolver, or connect over IPv4, while a
            # URL check elsewhere saw an IPv6 literal.
            var v6: Bool
            try:
                v6 = IpAddr.parse(StringSlice(unsafe_from_utf8=b[host_lo:host_hi])).is_ipv6()
            except:
                v6 = False
            if not v6:
                raise IoError.of_kind(op, ErrorKind.InvalidInput)
            if close + 1 < e:
                if b[close + 1] != 58:
                    raise IoError.of_kind(op, ErrorKind.InvalidInput)
                port = _port(b, close + 2, e)
        else:
            var colon = -1
            for i in range(a, e):
                if b[i] == 64:  # "@": user info
                    raise IoError.of_kind(op, ErrorKind.InvalidInput)
                if b[i] == 58:
                    colon = i
                    break
            if colon >= 0:
                host_hi = colon
                port = _port(b, colon + 1, e)
            for i in range(host_lo, host_hi):
                if not _is_host_byte(b[i]):
                    raise IoError.of_kind(op, ErrorKind.InvalidInput)
        if host_hi <= host_lo or port < 1:
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        var f = e
        while f < n and b[f] != 35:  # up to the fragment
            f += 1
        var target = String()
        if e == f or b[e] == 63:
            target = "/"
        for i in range(e, f):
            var c = b[i]
            if c <= 0x20 or c >= 0x7F:
                raise IoError.of_kind(op, ErrorKind.InvalidInput)
        target += String(StringSlice(unsafe_from_utf8=b[e:f]))
        return Url(StringSlice(unsafe_from_utf8=b[host_lo:host_hi]), UInt16(port), target, tls)

    def authority(self) -> String:
        """The Host field value: the host (IPv6 in brackets) and the port
        unless it is the scheme's (80, or 443 for https)."""
        var out = String()
        if self.host.find(":") >= 0:
            out += "[" + self.host + "]"
        else:
            out += self.host
        if self.port != (UInt16(443) if self.tls else UInt16(80)):
            out += String(":", self.port)
        return out^

    def write_to(self, mut writer: Some[Writer]):
        writer.write("https://" if self.tls else "http://", self.authority(), self.target)


@inline(.always)
def _is_hex(c: UInt8) -> Bool:
    return (c >= 48 and c <= 57) or ((c | 0x20) >= 97 and (c | 0x20) <= 102)


@inline(.always)
def _is_host_byte(c: UInt8) -> Bool:
    """reg-name characters this client accepts: letters, digits, -._~"""
    return (
        (c >= 48 and c <= 57)
        or ((c | 0x20) >= 97 and (c | 0x20) <= 122)
        or c == 45
        or c == 46
        or c == 95
        or c == 126
    )


def _port(b: Span[UInt8, _], lo: Int, hi: Int) raises IoError -> Int:
    if hi <= lo or hi - lo > 5:
        raise IoError.of_kind("Url.parse", ErrorKind.InvalidInput)
    var p = 0
    for i in range(lo, hi):
        var c = b[i]
        if c < 48 or c > 57:
            raise IoError.of_kind("Url.parse", ErrorKind.InvalidInput)
        p = p * 10 + Int(c) - 48
    if p < 1 or p > 65535:
        raise IoError.of_kind("Url.parse", ErrorKind.InvalidInput)
    return p


# ---- responses --------------------------------------------------------------------


struct Response(Movable, Writable):
    """A whole response."""

    var status: Int
    var reason: String
    var version: Version
    var headers: Headers
    var body: List[UInt8]
    var trailers: Headers

    def __init__(out self):
        self.status = 0
        self.reason = String()
        self.version = Version.HTTP_1_1
        self.headers = Headers()
        self.body = List[UInt8]()
        self.trailers = Headers()

    def text(self) -> String:
        """The body as a string (lossy for bytes that are not UTF-8)."""
        return String(from_utf8_lossy=Span(self.body))

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.version, " ", self.status, " ", self.reason, " (", len(self.body), " bytes)")


struct StreamedResponse(Movable, Writable):
    """A response whose body is read as it arrives (`Client.stream`). It
    owns its connection: dropping it closes the connection (the way to
    cancel a stream), and `Client.release` pools a finished one."""

    var status: Int
    var reason: String
    var version: Version
    var headers: Headers
    var trailers: Headers
    """Set once the body has ended."""
    var _conn: List[_Conn]
    """The connection (one element), until released."""
    var _ev: ClientEvent
    var _buf: List[UInt8]
    var _piece: List[UInt8]
    """Body bytes received but not yet read, from `_off` on."""
    var _off: Int
    var _done: Bool
    var _idle: Duration
    var _total: Deadline

    def __init__(out self, var r: Response, var conn: List[_Conn], idle: Duration, total: Deadline):
        self.status = r.status
        self.reason = r.reason
        self.version = r.version
        self.headers = Headers()
        swap(self.headers, r.headers)
        self.trailers = Headers()
        self._conn = conn^
        self._ev = ClientEvent(EventKind.END)
        self._buf = List[UInt8](length=_READ_SIZE, fill=0)
        self._piece = List[UInt8]()
        self._off = 0
        self._done = False
        self._idle = idle
        self._total = total

    def read(mut self, buf: MutSpan[UInt8, _]) raises IoError -> Int:
        """Body bytes into `buf` as they arrive: how many, 0 at the end (or
        for an empty `buf`). `TimedOut` after `idle_timeout` without any, or
        past `total`; the transport's error if the connection fails. A
        body delimited by the end of a TLS connection must end with
        close_notify (`UnexpectedEof` otherwise: RFC 9112 9.8)."""
        if len(buf) == 0:
            return 0
        while True:
            var left = len(self._piece) - self._off
            if left > 0:
                var n = min(left, len(buf))
                for i in range(n):
                    buf[i] = self._piece[self._off + i]
                self._off += n
                return n
            if self._done or len(self._conn) == 0:
                return 0
            ref c = self._conn[0]
            if c.codec.poll(self._ev):
                if self._ev.kind == EventKind.DATA:
                    swap(self._piece, self._ev.data)
                    self._off = 0
                elif self._ev.kind == EventKind.END:
                    self.trailers = self._ev.take_trailers()
                    self._done = True
                else:  # (no 1xx or switch after the final head)
                    raise IoError.of_kind("StreamedResponse.read", ErrorKind.InvalidData)
                continue
            var deadline = Deadline.after(self._idle).earliest(self._total)
            if self._total.is_expired():
                raise IoError.of_kind("StreamedResponse.read", ErrorKind.TimedOut)
            c.stream.set_deadline(deadline)
            var room = min(_READ_SIZE, c.codec.feed_capacity())
            var n = c.stream.read(Span(self._buf)[0:room])
            if n == 0:
                c.codec.feed_eof()
            else:
                c.codec.feed(Span(self._buf)[0:n])

    def read_all(mut self, max_bytes: Int = 16 * 1024 * 1024) raises IoError -> List[UInt8]:
        """The rest of the body; `InvalidData` past `max_bytes`."""
        var out = List[UInt8]()
        var buf = List[UInt8](length=16384, fill=0)
        while True:
            var n = self.read(Span(buf))
            if n == 0:
                return out^
            if len(out) + n > max_bytes:
                raise IoError.of_kind("StreamedResponse.read_all", ErrorKind.InvalidData)
            out.extend(Span(buf)[0:n])

    def is_done(self) -> Bool:
        """Whether the body has been read to its end."""
        return self._done and self._off >= len(self._piece)

    def limit_total(mut self, deadline: Deadline):
        """Make the rest of the body due by `deadline` too (the earlier of
        it and the one the stream has): for a caller whose own deadline
        covers reading this body, such as an error's."""
        self._total = self._total.earliest(deadline)

    def last_tls_error(self) -> Optional[TlsError]:
        if len(self._conn) == 0:
            return None
        return self._conn[0].stream.failure.copy()

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.version, " ", self.status, " ", self.reason, " (streamed)")


struct EventStream(Movable):
    """Server-sent events from a streamed response (`http.sse`):

        var r = client.stream("POST", url, headers, body)
        if r.status != 200: ...                 # an error body, not events
        var events = EventStream(r^)
        var ev = SseEvent()
        while events.next(ev):
            print(ev.event, ev.data)

    `InvalidData` if the response is not `text/event-stream`."""

    var response: StreamedResponse
    var parser: SseParser
    var _buf: List[UInt8]

    def __init__(out self, var response: StreamedResponse) raises IoError:
        var ct = response.headers.get("content-type")
        var ok = False
        if ct:
            # The media type, parameters after ";" aside (RFC 9110 8.3.1).
            var v = String(ct.value()).lower()
            var semi = v.find(";")
            var media = String(v[byte=0:semi]) if semi >= 0 else v
            ok = media.strip() == "text/event-stream"
        if not ok:
            raise IoError.of_kind("EventStream", ErrorKind.InvalidData)
        self.response = response^
        self.parser = SseParser()
        self._buf = List[UInt8](length=16384, fill=0)

    def next(mut self, mut ev: SseEvent) raises IoError -> Bool:
        """The next event into `ev`; False once the stream has ended."""
        while True:
            if self.parser.poll(ev):
                return True
            var room = min(len(self._buf), self.parser.feed_capacity())
            if room <= 0:
                return False
            var n = self.response.read(Span(self._buf)[0:room])
            if n == 0:
                self.parser.feed_eof()
                return self.parser.poll(ev)
            self.parser.feed(Span(self._buf)[0:n])

    def last_event_id(self) -> String:
        """For a reconnection's Last-Event-ID."""
        return self.parser.last_event_id()


# ---- the client ------------------------------------------------------------------


struct _Stream(Movable):
    """A connection's transport: plain TCP, or TLS over it. Each call
    raises a plain `IoError`; a TLS failure's reason is kept in `failure`."""

    var _plain: List[TcpStream]
    """One stream, or none (a one-element List: Optional of a large struct
    is slow in Mojo 1.2, CLAUDE.md)."""
    var _tls: List[TlsStream]
    var failure: Optional[TlsError]

    def __init__(out self, var tcp: TcpStream):
        self._plain = List[TcpStream]()
        self._plain.append(tcp^)
        self._tls = List[TlsStream]()
        self.failure = None

    def __init__(out self, var tls: TlsStream):
        self._plain = List[TcpStream]()
        self._tls = List[TlsStream]()
        self._tls.append(tls^)
        self.failure = None

    def _io(mut self, var e: TlsError) -> IoError:
        var io = e.io
        self.failure = e^
        return io

    def set_deadline(mut self, deadline: Deadline):
        if len(self._tls) > 0:
            self._tls[0].set_deadline(deadline)
        else:
            self._plain[0].set_deadline(deadline)

    def read(mut self, buf: MutSpan[UInt8, _]) raises IoError -> Int:
        if len(self._plain) > 0:
            return self._plain[0].read(buf)
        try:
            return self._tls[0].read(buf)
        except e:
            raise self._io(e^)

    def try_read(mut self, buf: MutSpan[UInt8, _]) raises IoError -> Optional[Int]:
        if len(self._plain) > 0:
            return self._plain[0].try_read(buf)
        try:
            return self._tls[0].try_read(buf)
        except e:
            raise self._io(e^)

    def try_write(mut self, buf: Span[UInt8, _]) raises IoError -> Optional[Int]:
        if len(self._plain) > 0:
            return self._plain[0].try_write(buf)
        try:
            return self._tls[0].try_write(buf)
        except e:
            raise self._io(e^)

    def wait(mut self, events: Int16, deadline: Deadline) raises IoError -> Int16:
        """Wait for the socket to be ready for `events`. For TLS, plaintext
        already decrypted counts as readable, and queued ciphertext is sent
        first: waiting to read with ciphertext unsent could deadlock."""
        if len(self._plain) > 0:
            return wait_ready(self._plain[0], events, deadline, "Client.request")
        if events & Int16(POLLIN) and self._tls[0].buffered():
            return Int16(POLLIN)
        var want = events
        var flushed: Bool
        try:
            flushed = self._tls[0].flush_ready()
        except e:
            raise self._io(e^)
        if not flushed:
            want = want | Int16(POLLOUT)
        return wait_ready(self._tls[0].tcp(), want, deadline, "Client.request")

    def truncated(self) -> Bool:
        """Whether a TLS connection ended without close_notify."""
        return Bool(self.failure) and self.failure.value().category == Category.TRUNCATED

    def is_reusable(mut self) -> Bool:
        """For the pool: nothing arrived while idle (TLS's own messages
        aside) and the connection was not closed."""
        if len(self._plain) > 0:
            return self._plain[0].idle_state() == IdleState.EMPTY
        return self._tls[0].is_reusable()


struct _Conn(Movable):
    """A connection and its protocol state, pooled together."""

    var key: String
    var stream: _Stream
    var codec: ClientConnection
    var idle_since: Instant

    def __init__(out self, key: String, var stream: _Stream) raises IoError:
        self.key = key
        self.stream = stream^
        self.codec = ClientConnection()
        self.idle_since = Instant.now()


def _idempotent(method: StringSlice) -> Bool:
    return (
        method == "GET"
        or method == "HEAD"
        or method == "OPTIONS"
        or method == "TRACE"
        or method == "PUT"
        or method == "DELETE"
    )


def _retryable(e: IoError) -> Bool:
    """A failure that means the server closed the connection without seeing
    or answering the request (only meaningful before any response byte)."""
    if e.kind == ErrorKind.UnexpectedEof and e.op == E_NO_RESPONSE:
        return True
    return (
        e.kind == ErrorKind.ConnectionReset
        or e.kind == ErrorKind.BrokenPipe
        or e.kind == ErrorKind.ConnectionAborted
    )


struct Client(Movable):
    """A blocking HTTP/1.1 client with a keep-alive pool (see the module
    docs). Not for use from several threads at once."""

    var timeout: Duration
    """The deadline for each whole request."""
    var max_body: Int
    var max_idle_per_host: Int
    var max_idle_conns: Int
    """Idle connections kept in all, whatever their host."""
    var max_idle: Duration
    """How long a pooled connection may sit idle and still be reused."""
    var user_agent: String
    var _tls_config: ClientConfig
    var _tls: List[ClientContext]
    """Built on the first https request (one element), then shared."""
    var _tls_error: Optional[TlsError]
    var _resolver: Resolver
    var _pool: List[_Conn]
    var _buf: List[UInt8]
    var _ev: ClientEvent
    """Reused for every event (`ClientConnection.poll`)."""
    var _head_only: Bool
    """`stream`: a response counts as come at its final head."""

    def __init__(
        out self,
        *,
        timeout: Duration = Duration.from_secs(30),
        max_body: Int = 16 * 1024 * 1024,
        max_idle_per_host: Int = 4,
        max_idle_conns: Int = 32,
        max_idle: Duration = Duration.from_secs(60),
        user_agent: StringSlice = "mojo-net",
        var tls: ClientConfig = ClientConfig(),
    ) raises IoError:
        """`InvalidInput` for a zero timeout or a negative limit. `tls` is
        the trust for https (system roots by default); its ALPN list is
        replaced by `http/1.1`."""
        if not (Duration.ZERO < timeout) or max_body < 0 or max_idle_per_host < 0 or max_idle_conns < 0:
            raise IoError.of_kind("Client.__init__", ErrorKind.InvalidInput)
        self.timeout = timeout
        self.max_body = max_body
        self.max_idle_per_host = max_idle_per_host
        self.max_idle_conns = max_idle_conns
        self.max_idle = max_idle
        self.user_agent = String(user_agent)
        tls.alpn = ["http/1.1"]
        self._tls_config = tls^
        self._tls = List[ClientContext]()
        self._tls_error = None
        self._resolver = Resolver.system()
        self._pool = List[_Conn]()
        self._buf = List[UInt8](length=_READ_SIZE, fill=0)
        self._ev = ClientEvent(EventKind.END)
        self._head_only = False

    # ---- requests --------------------------------------------------------

    def get(mut self, url: StringSlice) raises IoError -> Response:
        return self.request("GET", url)

    def head(mut self, url: StringSlice) raises IoError -> Response:
        return self.request("HEAD", url)

    def post(
        mut self, url: StringSlice, body: Span[UInt8, _], content_type: StringSlice
    ) raises IoError -> Response:
        var h = Headers()
        h.add("Content-Type", content_type)
        return self.request("POST", url, h, body)

    def request(
        mut self,
        method: StringSlice,
        url: StringSlice,
        headers: Headers = Headers(),
        body: Span[UInt8, _] = Span[UInt8, ImmStaticOrigin](),
    ) raises IoError -> Response:
        """Send `method` to `url` with `headers` and `body`, and read the
        whole response. Errors: `InvalidInput` for a bad URL, method or
        header set; `TimedOut` past the deadline; `InvalidData` for a
        malformed response or one over `max_body`; the transport's errors."""
        var kept = List[_Conn]()
        return self._perform(method, url, headers, body, kept, False)

    def stream(
        mut self,
        method: StringSlice,
        url: StringSlice,
        headers: Headers = Headers(),
        body: Span[UInt8, _] = Span[UInt8, ImmStaticOrigin](),
        *,
        idle_timeout: Duration = Duration.from_secs(60),
        total: Duration = Duration.MAX,
    ) raises IoError -> StreamedResponse:
        """Send the request as `request` does, and return as soon as the
        response's head has come (within `timeout`): read the body as it
        arrives with `StreamedResponse.read`, for streamed tokens or
        server-sent events (`EventStream`). Each read waits at most
        `idle_timeout` for more of the body, and all of it must come
        within `total` (no limit by default). Dropping the response closes
        the connection, which is how a client cancels; `release` gives a
        finished one back to the pool."""
        if not (Duration.ZERO < idle_timeout):
            raise IoError.of_kind("Client.stream", ErrorKind.InvalidInput)
        var kept = List[_Conn]()
        var r = self._perform(method, url, headers, body, kept, True)
        var d = Deadline.none() if total == Duration.MAX else Deadline.after(total)
        return StreamedResponse(r^, kept^, idle_timeout, d)

    def release(mut self, var r: StreamedResponse):
        """Return a streamed response's connection to the pool, if its body
        was read to the end and the connection is fit for reuse (dropping
        the response closes it instead)."""
        if len(r._conn) == 0 or not r._done:
            return
        var c = r._conn.pop()
        if c.codec.is_idle():
            self._checkin(c^)

    def _perform(
        mut self,
        method: StringSlice,
        url: StringSlice,
        headers: Headers,
        body: Span[UInt8, _],
        mut kept: List[_Conn],
        head_only: Bool,
    ) raises IoError -> Response:
        """`request`, or with `head_only`, up to the final head: the
        connection then goes to `kept` with the rest of the response."""
        comptime op = "Client.request"
        var u = Url.parse(url)
        if (
            not is_token(method.as_bytes())
            or method == "CONNECT"
            or headers.contains("upgrade")  # (the docs promise it: no protocol switch)
            or headers.contains("content-length")
            or headers.contains("transfer-encoding")
            or headers.count("host") > 1
        ):
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        var head = RequestHead(method, u.target)
        if not headers.contains("host"):
            head.headers.add("Host", u.authority())
        if not headers.contains("user-agent") and self.user_agent.byte_length() > 0:
            head.headers.add("User-Agent", self.user_agent)
        if len(body) > 0 or method == "POST" or method == "PUT" or method == "PATCH":
            head.headers.add("Content-Length", String(len(body)))
        for i in range(len(headers)):
            head.headers._push(
                headers.name(i).as_bytes(), headers.value_bytes(i), utf8=False
            )
        var deadline = Deadline.after(self.timeout)
        # (TC17: one TLS context per Client, so the scheme is all the pool
        # key needs to keep TLS and plain connections apart.)
        var key = String("https " if u.tls else "http ", u.host, " ", u.port)
        var retried = False
        while True:
            var reused = False
            var conn = self._checkout(key)
            if conn:
                reused = True
            else:
                conn = _Conn(key, self._connect(u, deadline))
            var c = conn.take()
            var started = False
            self._head_only = head_only
            try:
                var r = self._exchange(c, head, body, deadline, started)
                self._head_only = False
                if reused and r.status == 408 and not retried and _idempotent(method):
                    # The server timed the idle connection out as the
                    # request arrived (it never ran it): once more, anew.
                    retried = True
                    continue
                if head_only:
                    kept.append(c^)
                elif c.codec.is_idle():
                    self._checkin(c^)
                return r^
            except e:
                self._head_only = False
                if c.stream.failure:
                    self._tls_error = c.stream.failure.value().copy()
                # (A reused TLS connection the server ended without
                # close_notify before any response byte is one it dropped.)
                if reused and not started and not retried and _idempotent(method) and (_retryable(e) or c.stream.truncated()):
                    retried = True
                    continue
                raise e

    def _connect(mut self, u: Url, deadline: Deadline) raises IoError -> _Stream:
        """A new connection to `u`'s host: TCP, then for https a verified
        handshake within the same deadline. For https the host must be a
        name or address TLS can check (`tls.target`), before any DNS query
        or connection."""
        if u.tls:
            try:
                _ = Target(u.host)
            except e:
                raise IoError.of_kind("Client.request", ErrorKind.InvalidInput)
        var tcp = TcpStream.connect_host_deadline(u.host, u.port, deadline, self._resolver)
        if not u.tls:
            return _Stream(tcp^)
        try:
            if len(self._tls) == 0:
                self._tls.append(self._tls_config.build())
            return _Stream(TlsStream.handshake(tcp^, self._tls[0], u.host, deadline))
        except e:
            var io = e.io
            self._tls_error = e^
            raise io

    def last_tls_error(self) -> Optional[TlsError]:
        """Why the last TLS failure happened (category, verify code,
        OpenSSL's text), for the `IoError` a request raised."""
        return self._tls_error.copy()

    def _exchange(
        mut self,
        mut c: _Conn,
        head: RequestHead,
        body: Span[UInt8, _],
        deadline: Deadline,
        mut started: Bool,
    ) raises IoError -> Response:
        """One request and its response on `c`. `started` turns True once a
        response byte has arrived (after which nothing is retried).

        The body goes out in pieces while the connection is watched for the
        response (RFC 9112 9.5): a server that answers before the body ends
        (a 413, say) is heard, and one that streams its response while the
        body arrives (an echo) is read from as it writes, so neither can
        deadlock the request. A response that completes before the request
        does is returned, and the connection, now out of step, is not kept.
        """
        c.stream.set_deadline(deadline)
        c.codec.send_request(head)
        var out = ByteBuffer()
        var sent = 0
        var ended = False
        var informational = 0
        var r = Response()
        var answered = False  # (an early 2xx that keeps the connection)
        while True:
            if deadline.is_expired():
                raise IoError.of_kind("Client.request", ErrorKind.TimedOut)
            if len(out) == 0:
                if c.codec.pending_transmit() == 0:
                    if sent < len(body):
                        var k = min(_WRITE_PIECE, len(body) - sent)
                        c.codec.send_body(body[sent : sent + k])
                        sent += k
                    elif not ended:
                        c.codec.end_request()
                        ended = True
                _ = c.codec.poll_transmit(out)
                if len(out) == 0:
                    break  # the whole request is out
            var wrote: Optional[Int]
            try:
                wrote = c.stream.try_write(out.readable_span())
            except e:
                if answered:
                    raise e  # (the body was cut short after all)
                # The server may have answered, then closed (an early 413):
                # what it sent before is still readable.
                if self._after_write_error(c, r, started, informational, deadline):
                    return r^
                raise e
            if wrote:
                out.consume(wrote.value())
                continue
            var events = POLLOUT if answered else (POLLIN | POLLOUT)
            var rev = c.stream.wait(Int16(events), deadline)
            if not answered and rev & Int16(POLLIN | POLLHUP | POLLERR):
                if self._read_ready(c, r, started, informational, deadline):
                    if r.status < 300 and not c.codec.should_close():
                        # The server took the request and keeps the
                        # connection: send it the rest of the body (RFC 9112
                        # 9.5 stops only for a server that is closing).
                        answered = True
                        continue
                    return r^
        if answered:
            return r^
        while True:
            if self._absorb(c, r, informational):
                return r^
            if deadline.is_expired():
                # The stream's deadline bounds each wait; this bounds a
                # response that keeps trickling in (or a flood of 1xx).
                raise IoError.of_kind("Client.request", ErrorKind.TimedOut)
            var room = min(_READ_SIZE, c.codec.feed_capacity())
            var n = c.stream.read(Span(self._buf)[0:room])
            if n == 0:
                c.codec.feed_eof()
            else:
                started = True
                c.codec.feed(Span(self._buf)[0:n])

    def _read_ready(
        mut self,
        mut c: _Conn,
        mut r: Response,
        mut started: Bool,
        mut informational: Int,
        deadline: Deadline,
    ) raises IoError -> Bool:
        """Read what has arrived without waiting, into `r`: True once the
        response is complete. The deadline is checked on every pass, so a
        response that keeps coming during the upload cannot outlast it."""
        while True:
            if deadline.is_expired():
                raise IoError.of_kind("Client.request", ErrorKind.TimedOut)
            var got = c.stream.try_read(Span(self._buf)[0 : min(_READ_SIZE, c.codec.feed_capacity())])
            if not got:
                return self._absorb(c, r, informational)
            if got.value() == 0:
                c.codec.feed_eof()
                return self._absorb(c, r, informational)
            started = True
            c.codec.feed(Span(self._buf)[0 : got.value()])
            if self._absorb(c, r, informational):
                return True

    def _after_write_error(
        mut self,
        mut c: _Conn,
        mut r: Response,
        mut started: Bool,
        mut informational: Int,
        deadline: Deadline,
    ) raises IoError -> Bool:
        """After sending failed: read what the server sent before (waiting
        for it, up to the deadline), into `r`. True only for a response that
        completes by its own framing; the end of the input is not taken as
        the end of a response, since a reset may have cut it short."""
        while True:
            if self._absorb(c, r, informational):
                return True
            if deadline.is_expired():
                return False
            var got: Optional[Int]
            try:
                got = c.stream.try_read(Span(self._buf)[0 : min(_READ_SIZE, c.codec.feed_capacity())])
            except:
                return False  # (the reset itself: nothing more to read)
            if not got:
                try:
                    _ = c.stream.wait(Int16(POLLIN), deadline)
                except:
                    return False
                continue
            if got.value() == 0:
                return False
            started = True
            c.codec.feed(Span(self._buf)[0 : got.value()])

    def _absorb(
        mut self, mut c: _Conn, mut r: Response, mut informational: Int
    ) raises IoError -> Bool:
        """Move the codec's events into `r`: True at the response's END."""
        while c.codec.poll(self._ev):
            ref ev = self._ev
            if ev.kind == EventKind.HEAD:
                ref h = ev.head()
                r.status = h.status
                r.reason = h.reason
                r.version = h.version
                swap(r.headers, h.headers)
                if self._head_only:
                    return True  # (the body stays in the codec, for the stream)
            elif ev.kind == EventKind.DATA:
                if len(r.body) + len(ev.data) > self.max_body:
                    raise IoError.of_kind("Client.request", ErrorKind.InvalidData)
                r.body.extend(Span(ev.data))
            elif ev.kind == EventKind.END:
                r.trailers = ev.take_trailers()
                return True
            elif ev.kind == EventKind.UPGRADE:
                raise IoError.of_kind("Client.request", ErrorKind.InvalidData)
            else:  # INFORMATIONAL: skipped, but not without end
                informational += 1
                if informational > _MAX_INFORMATIONAL:
                    raise IoError.of_kind("Client.request", ErrorKind.InvalidData)
        return False

    # ---- the pool --------------------------------------------------------

    def _checkout(mut self, key: String) -> Optional[_Conn]:
        """The most recently returned idle connection for `key` that still
        looks reusable. Connections idle past `max_idle`, for any key, and
        stale ones for `key` are dropped (closed) on the way."""
        var now = Instant.now()
        var i = len(self._pool) - 1
        while i >= 0:
            if self.max_idle < now - self._pool[i].idle_since:
                _ = self._pool.pop(i)
            i -= 1
        i = len(self._pool) - 1
        while i >= 0:
            if self._pool[i].key == key:
                var c = self._pool.pop(i)
                if c.stream.is_reusable():
                    return c^
            i -= 1
        return None

    def _checkin(mut self, var c: _Conn):
        var same = 0
        for i in range(len(self._pool)):
            if self._pool[i].key == c.key:
                same += 1
        if same >= self.max_idle_per_host or self.max_idle_conns == 0:
            return  # dropped: closed
        while len(self._pool) >= self.max_idle_conns:
            _ = self._pool.pop(0)  # (the longest idle: closed)
        c.idle_since = Instant.now()
        self._pool.append(c^)

    def idle_connections(self) -> Int:
        """Connections kept for reuse."""
        return len(self._pool)

    def close_idle(mut self):
        """Close every pooled connection."""
        self._pool.clear()
