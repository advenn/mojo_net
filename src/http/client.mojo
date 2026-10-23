"""A blocking HTTP/1.1 client over `net`: `Client` sends requests to
`http://` URLs and reads whole responses, keeping connections alive in a
small pool. It drives `http.connection.ClientConnection` over a
`TcpStream`; `client` and `server` are the only `http` modules that do I/O.

    var client = Client()
    var r = client.get("http://example.com/")
    print(r.status, r.text())

- URLs: `http://host[:port][/path][?query]` (`Url.parse`), with IPv6
  literals in brackets. `https` raises `Unsupported` (no TLS yet), user
  info in the authority `InvalidInput`; a fragment is dropped.
- One deadline per request (`timeout`, default 30 s) covers name
  resolution, connecting (Happy Eyeballs), sending and receiving.
- Responses are read whole, up to `max_body` bytes (default 16 MiB);
  `InvalidData` beyond, and the connection is dropped.
- Headers: the client sends Host (unless the caller gives one),
  User-Agent (likewise), and Content-Length when there is a body or the
  method usually has one (POST, PUT, PATCH). The caller's headers follow,
  in order. A caller's Content-Length or Transfer-Encoding is refused
  (`InvalidInput`): the client frames the body.
- Connections are kept per host and port, at most `max_idle_per_host` of
  them, and reused only after `max_idle` at most, if `idle_state()` still
  says EMPTY. A reused connection can still turn out closed by the server
  (a race no check avoids). If that happens before any byte of the
  response, an idempotent request (GET, HEAD, OPTIONS, TRACE, PUT, DELETE)
  is sent again, once, on a new connection.
- Not done: redirects (a 3xx is returned as is), cookies, content codings,
  CONNECT and upgrades (`InvalidInput`), proxies.
"""

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError
from linux.time import Deadline, Duration, Instant
from net.blocking import IdleState
from net.resolver import Resolver
from net.tcp import TcpStream

from .connection import E_NO_RESPONSE, ClientConnection, EventKind
from .headers import Headers, is_token, lower_ascii
from .parse import RequestHead
from .types import Version

comptime _READ_SIZE = 64 * 1024


# ---- URLs -------------------------------------------------------------------------


struct Url(Copyable, Movable, Writable):
    """An `http://` URL split for a request."""

    var host: String
    """The host name or IP literal, IPv6 without its brackets."""
    var port: UInt16
    var target: String
    """The request target: path and query, at least "/"."""

    def __init__(out self, host: StringSlice, port: UInt16, target: StringSlice):
        self.host = String(host)
        self.port = port
        self.target = String(target)

    @staticmethod
    def parse(text: StringSlice) raises IoError -> Url:
        """`http://host[:port][/path][?query][#fragment]`. `Unsupported`
        for https, `InvalidInput` for anything else malformed: another
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
        if scheme == "https":
            raise IoError.of_kind(op, ErrorKind.Unsupported)
        if scheme != "http":
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        var a = sep + 3
        var e = a
        while e < n and b[e] != 47 and b[e] != 63 and b[e] != 35:  # / ? #
            e += 1
        var host_lo = a
        var host_hi = e
        var port = 80
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
        return Url(StringSlice(unsafe_from_utf8=b[host_lo:host_hi]), UInt16(port), target)

    def authority(self) -> String:
        """The Host field value: the host (IPv6 in brackets) and the port
        unless it is 80."""
        var out = String()
        if self.host.find(":") >= 0:
            out += "[" + self.host + "]"
        else:
            out += self.host
        if self.port != 80:
            out += String(":", self.port)
        return out^

    def write_to(self, mut writer: Some[Writer]):
        writer.write("http://", self.authority(), self.target)


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


# ---- the client ------------------------------------------------------------------


struct _Conn(Movable):
    """A connection and its protocol state, pooled together."""

    var key: String
    var stream: TcpStream
    var codec: ClientConnection
    var idle_since: Instant

    def __init__(out self, key: String, var stream: TcpStream) raises IoError:
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
    var max_idle: Duration
    """How long a pooled connection may sit idle and still be reused."""
    var user_agent: String
    var _resolver: Resolver
    var _pool: List[_Conn]
    var _buf: List[UInt8]

    def __init__(
        out self,
        *,
        timeout: Duration = Duration.from_secs(30),
        max_body: Int = 16 * 1024 * 1024,
        max_idle_per_host: Int = 4,
        max_idle: Duration = Duration.from_secs(60),
        user_agent: StringSlice = "mojo-net",
    ) raises IoError:
        """`InvalidInput` for a zero timeout or a negative limit."""
        if not (Duration.ZERO < timeout) or max_body < 0 or max_idle_per_host < 0:
            raise IoError.of_kind("Client.__init__", ErrorKind.InvalidInput)
        self.timeout = timeout
        self.max_body = max_body
        self.max_idle_per_host = max_idle_per_host
        self.max_idle = max_idle
        self.user_agent = String(user_agent)
        self._resolver = Resolver.system()
        self._pool = List[_Conn]()
        self._buf = List[UInt8](length=_READ_SIZE, fill=0)

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
        comptime op = "Client.request"
        var u = Url.parse(url)
        if (
            not is_token(method.as_bytes())
            or method == "CONNECT"
            or headers.contains("content-length")
            or headers.contains("transfer-encoding")
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
        var key = String(u.host, " ", u.port)
        var retried = False
        while True:
            var reused = False
            var conn = self._checkout(key)
            if conn:
                reused = True
            else:
                conn = _Conn(
                    key,
                    TcpStream.connect_host_deadline(u.host, u.port, deadline, self._resolver),
                )
            var c = conn.take()
            var started = False
            try:
                var r = self._exchange(c, head, body, deadline, started)
                if c.codec.is_idle():
                    self._checkin(c^)
                return r^
            except e:
                if reused and not started and not retried and _idempotent(method) and _retryable(e):
                    retried = True
                    continue
                raise e

    def _exchange(
        mut self,
        mut c: _Conn,
        head: RequestHead,
        body: Span[UInt8, _],
        deadline: Deadline,
        mut started: Bool,
    ) raises IoError -> Response:
        """One request and its response on `c`. `started` turns True once a
        response byte has arrived (after which nothing is retried)."""
        c.stream.set_deadline(deadline)
        c.codec.send_request(head)
        if len(body) > 0:
            c.codec.send_body(body)
        c.codec.end_request()
        var out = ByteBuffer()
        while c.codec.poll_transmit(out) > 0:
            c.stream.write_all(out.readable_span())
            out.clear()
        var r = Response()
        while True:
            while True:
                var got = c.codec.next_event()
                if not got:
                    break
                var ev = got.take()
                if ev.kind == EventKind.HEAD:
                    var h = ev.take_head()
                    r.status = h.status
                    r.reason = h.reason
                    r.version = h.version
                    swap(r.headers, h.headers)
                elif ev.kind == EventKind.DATA:
                    if len(r.body) + len(ev.data) > self.max_body:
                        raise IoError.of_kind("Client.request", ErrorKind.InvalidData)
                    r.body.extend(Span(ev.data))
                elif ev.kind == EventKind.END:
                    swap(r.trailers, ev.trailers)
                    return r^
                elif ev.kind == EventKind.UPGRADE:
                    raise IoError.of_kind("Client.request", ErrorKind.InvalidData)
                # INFORMATIONAL: skipped
            var room = min(_READ_SIZE, c.codec.feed_capacity())
            var n = c.stream.read(Span(self._buf)[0:room])
            if n == 0:
                c.codec.feed_eof()
            else:
                started = True
                c.codec.feed(Span(self._buf)[0:n])

    # ---- the pool --------------------------------------------------------

    def _checkout(mut self, key: String) -> Optional[_Conn]:
        """The most recently returned idle connection for `key` that still
        looks reusable; stale ones are dropped (closed) on the way."""
        var i = len(self._pool) - 1
        var now = Instant.now()
        while i >= 0:
            if self._pool[i].key == key:
                var c = self._pool.pop(i)
                if (
                    not (self.max_idle < now - c.idle_since)
                    and c.stream.idle_state() == IdleState.EMPTY
                ):
                    return c^
            i -= 1
        return None

    def _checkin(mut self, var c: _Conn):
        var same = 0
        for i in range(len(self._pool)):
            if self._pool[i].key == c.key:
                same += 1
        if same >= self.max_idle_per_host:
            return  # dropped: closed
        c.idle_since = Instant.now()
        self._pool.append(c^)

    def idle_connections(self) -> Int:
        """Connections kept for reuse."""
        return len(self._pool)

    def close_idle(mut self):
        """Close every pooled connection."""
        self._pool.clear()
