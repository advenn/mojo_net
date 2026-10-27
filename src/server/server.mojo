"""The HTTP/1.1 server: `Server[H: Handler]` runs one edge-triggered epoll
loop over a listener and its connections, with one
`http.connection.ServerConnection` per connection, and calls the
application's `Handler` once per complete request (docs/server.md).

    struct Hello(Handler):
        def __init__(out self):
            pass

        def handle(mut self, req: Request, mut res: Response) raises:
            res.text(200, "Hello, world!\\n")

    def main() raises:
        var server = Server(Hello())
        server.bind(SocketAddr.parse("127.0.0.1:8080"))
        server.run()

The loop, per connection:
- Output first: what the codec hands out is written until the socket would
  block. While it is pending nothing is read, so a client that does not
  read cannot make the server buffer without limit (backpressure); after
  `write_timeout` without progress the connection is dropped.
- Then input: read what fits the codec (`feed_capacity`), feed it, and
  drain the events. A request's head starts it (413 at once if its
  Content-Length is over `max_body`; `100 Continue` for an
  `Expect: 100-continue` otherwise), its body is collected up to
  `max_body`, and at its END the handler runs and its response is sent.
  Pipelined requests are answered in order.
- Timeouts are checked by a sweep a few times a second: `header_timeout`
  for a request head that has started (408), `idle_timeout` between
  requests (closed quietly), `read_timeout` while a body arrives (408),
  `write_timeout` while output waits. The last two restart only when a
  window's worth of progress has passed (`min_rate` times the timeout,
  15 KB for 30 s at 512 B/s), so a client cannot hold a connection by
  dripping a byte at a time. A write timeout aborts the connection (RST),
  so the kernel does not go on sending what was queued.
- Fairness: a connection gets a slice per turn (64 KiB moved, or 128
  requests answered), then waits for the next turn, which does not wait
  for readiness: one busy client cannot keep the loop from the others.
- A malformed request is answered with its status (400, 414, 431, 501,
  505) and the connection closes; a handler that raises gets a 500.
- Streaming (the `Handler` hooks): a request body can go to the handler
  piece by piece (`on_body`; `body_cut` if it never completes), and a
  response body can come from it while less than `_HIGH_WATER` of output
  is queued (`produce`; `stream_ended` once it is over). A stream with
  nothing to send pauses until its connection is woken (`Server.wake`,
  `Handler.take_wakes`); a client that leaves a paused stream ends it.
- Server-sent events: `res.event_stream()` is a stream with the event
  stream's fields; while it is paused, a comment line goes out every
  `heartbeat`, so that proxies and clients do not time it out.
- Accepting pauses at `max_connections`, and for 100 ms on EMFILE.
- Lingering close (RFC 9112 9.6): when the server ends a connection
  whose client may still be sending (input was left unread:
  `ServerConnection.input_pending()`), it shuts down its write side and
  reads and drops the client's input until its end, or for at most
  `linger_timeout`, before closing. Closing at once would reset the
  connection, and a reset can destroy the last response before the
  client reads it. Other connections close at once.
- TLS (`serve_tls`, S7): each connection runs a `tls.TlsServer` between
  the socket and the codec, with ALPN `http/1.1`. Accepting never waits
  for TLS: a connection gets its `TlsServer`, and counts as a handshake,
  only once its first record (the ClientHello) has arrived whole, which
  must happen within `tls_hello_timeout` of accept; until then it holds
  no OpenSSL state, so sockets that send nothing, or a byte, take no
  handshake's place. Handshakes are then admitted in arrival order
  (`tls_max_handshakes` at once, at most `tls_handshake_rate` begun a
  second; the others wait, unread). While some wait, a handshake that has
  waited `tls_client_wait` for its client since it was admitted (the
  server's flight sent, the client silent) gives its place up and is
  closed, oldest first. Each has one deadline from accept
  that progress does not extend (`tls_handshake_timeout`), and the
  connection's other timeouts and `min_rate` count plaintext. A graceful close sends close_notify; a
  timeout or an error does not, and after a failure only the alert
  OpenSSL queued goes out. A request whose host is not the name the
  client asked for in SNI gets 421. The certificate and key files are
  checked every `tls_reload_check`: when they change, a new context
  serves new connections (live ones keep theirs), and a failed reload
  keeps the old one, saying why on stderr, as it does when the
  certificate's renewal is due.
- Graceful shutdown (`shutdown()`): the connections already queued are
  accepted and the listener closed; idle connections close, requests in
  progress get their responses (the last on their connections, saying
  `Connection: close`), and whatever is left closes after
  `shutdown_timeout`. `stopped()` says when no connection is left.
  `stop_on(stop)` begins one on SIGTERM or SIGINT, or when a worker's
  supervisor asks (`server.process`); a second signal closes everything
  at once.
"""

from bytes.buffer import ByteBuffer
from http.connection import EventKind, ServerConnection, ServerEvent
from http.headers import Headers, eq_ignore_case, is_field_byte
from http.parse import Limits, RequestHead, ResponseHead
from http.types import Version, reason as _phrase
from std.memory import unsafe_memcpy
from std.os import unsetenv

from linux import Epoll, ErrorKind, IoError
from linux.errno import Errno
from linux.abi import EpollEvent
from linux.consts import EPOLLERR, EPOLLET, EPOLLHUP, EPOLLIN, EPOLLOUT, EPOLLRDHUP
from linux.probe import pregrow_fd_table, raise_nofile_limit
from linux.time import Duration, Instant
from net.addr import SocketAddr
from net.socket import Shutdown
from net.tcp import TcpAccepted, TcpListener, TcpStream
from linux.fs import stat_path
from tls import Category, TlsError, TlsEvent, TlsEventKind, TlsServer
from tls import ServerConfig as TlsConfig
from tls import ServerContext as TlsContext

from .date import DateCache
from .process import Stop, _log

comptime _LISTENER: UInt64 = UInt64.MAX
comptime _STOP: UInt64 = UInt64.MAX - 1
comptime _PAUSE = Duration.from_millis(100)
comptime _READ_CHUNK = 64 * 1024
comptime _HEARTBEAT = ":\n"
"""A paused event stream's heartbeat: an empty comment line."""
comptime _HIGH_WATER = 64 * 1024
"""Output a connection may queue before it stops answering the pipelined
requests it has buffered (backpressure); below it, responses are batched
into one write."""
comptime _SLICE_BYTES = 64 * 1024
comptime _SLICE_REQUESTS = 128
"""A connection's slice of one turn: bytes read and written, or requests
answered. Then it waits for the next turn (fairness)."""
comptime _KEEP = 16 * 1024
"""Capacity each buffer of an idle connection may keep; larger ones are
given back when it goes idle (so an idle connection holds about 100 KiB
at most, whatever it was once sent or asked for)."""
comptime _MAX_BUFFERED_BODY = 63 * 1024 * 1024
"""The largest body a handler may answer without streaming (the codec's
output buffer holds 64 MiB); a larger one gets a 500."""
comptime _SLOT_BITS = 24
comptime _MAX_CONNECTIONS = (1 << _SLOT_BITS) - (1 << 16)
"""Connection ids keep the slot in their low 24 bits (with room for what a
shutdown accepts past the cap)."""

# connection states
comptime _WAITING = 0
"""Between requests: waiting for (the rest of) a head."""
comptime _BODY = 1
"""A request's head arrived; its body is being read."""
comptime _PRODUCING = 2
"""A streamed response is being produced (`Handler.produce`)."""
comptime _LINGERING = 3
"""Closing: the write side is shut down, input is read and dropped until
its end (lingering close)."""


# ---- configuration ------------------------------------------------------------------


struct ServerConfig(Copyable, Movable):
    """How a `Server` behaves (docs/server.md)."""

    var max_connections: Int
    var max_body: Int
    """The largest request body accepted (413 beyond)."""
    var header_timeout: Duration
    """From a connection's start, or a request head's first byte, to the
    end of that head (408 after)."""
    var idle_timeout: Duration
    """How long a kept-alive connection may wait for its next request."""
    var read_timeout: Duration
    """The longest wait for more of a request body (408 after)."""
    var write_timeout: Duration
    """The longest wait for a client to take more of its response."""
    var linger_timeout: Duration
    """How long a closing connection reads and drops the client's input
    before it is closed anyway (see the module docs)."""
    var shutdown_timeout: Duration
    """How long `shutdown()` lets requests in progress finish before it
    closes what is left."""
    var min_rate: Int
    """The slowest, in bytes a second, a request body may arrive and
    waiting output be taken: `read_timeout` and `write_timeout` restart
    only once `min_rate` times the timeout has passed (0: on any
    progress)."""
    var reuseport: Bool
    """Bind with SO_REUSEPORT, for one server process per core."""
    var server_name: String
    """The Server field of every response; none if empty."""
    var limits: Limits
    """Request head limits (`http.parse.Limits`)."""
    var heartbeat: Duration
    """How long a paused event stream (`Response.event_stream`) may send
    nothing before a comment line goes out (`Duration.ZERO`: never)."""
    var tls_hello_timeout: Duration
    """TLS: from accept until the client's first record (its ClientHello)
    has arrived whole; until then the connection holds no TLS state."""
    var tls_handshake_timeout: Duration
    """TLS: from accept to the end of the handshake, whatever progress is
    made on the way (TS8)."""
    var tls_max_handshakes: Int
    """TLS: handshakes under way at once (TS7); connections whose
    ClientHello came beyond it wait, unread, in arrival order."""
    var tls_handshake_rate: Int
    """TLS: handshakes begun in a second at most (TS7; 0: no limit); the
    others wait for the next second."""
    var tls_client_wait: Duration
    """TLS: while ClientHellos wait for admission, how long an admitted
    handshake may wait for its client (a round trip and its checks) before
    it is closed to make room: clients that send a ClientHello and go
    quiet would otherwise hold every place until their deadline."""
    var tls_reload_check: Duration
    """TLS: how often the certificate and key files are checked for a
    change (TS12; `Duration.ZERO`: never)."""

    def __init__(
        out self,
        *,
        max_connections: Int = 10000,
        max_body: Int = 1024 * 1024,
        header_timeout: Duration = Duration.from_secs(10),
        idle_timeout: Duration = Duration.from_secs(60),
        read_timeout: Duration = Duration.from_secs(30),
        write_timeout: Duration = Duration.from_secs(30),
        linger_timeout: Duration = Duration.from_secs(2),
        shutdown_timeout: Duration = Duration.from_secs(10),
        min_rate: Int = 512,
        reuseport: Bool = False,
        server_name: StringSlice = "",
        limits: Limits = Limits(),
        heartbeat: Duration = Duration.from_secs(15),
        tls_hello_timeout: Duration = Duration.from_secs(5),
        tls_handshake_timeout: Duration = Duration.from_secs(10),
        tls_max_handshakes: Int = 1024,
        tls_handshake_rate: Int = 1000,
        tls_reload_check: Duration = Duration.from_secs(10),
        tls_client_wait: Duration = Duration.from_secs(1),
    ):
        self.max_connections = max_connections
        self.max_body = max_body
        self.header_timeout = header_timeout
        self.idle_timeout = idle_timeout
        self.read_timeout = read_timeout
        self.write_timeout = write_timeout
        self.linger_timeout = linger_timeout
        self.shutdown_timeout = shutdown_timeout
        self.min_rate = min_rate
        self.reuseport = reuseport
        self.server_name = String(server_name)
        self.limits = limits
        self.heartbeat = heartbeat
        self.tls_hello_timeout = tls_hello_timeout
        self.tls_handshake_timeout = tls_handshake_timeout
        self.tls_max_handshakes = tls_max_handshakes
        self.tls_handshake_rate = tls_handshake_rate
        self.tls_reload_check = tls_reload_check
        self.tls_client_wait = tls_client_wait

    def _sweep_every(self) -> Duration:
        """How often timeouts (and heartbeats, and the TLS files) are
        checked: a quarter of the shortest one, at most a second, at least
        10 ms."""
        var t = min(
            min(min(self.header_timeout, self.idle_timeout), self.linger_timeout),
            min(min(self.read_timeout, self.write_timeout), min(self.tls_handshake_timeout, self.tls_hello_timeout)),
        )
        if Duration.ZERO < self.heartbeat:
            t = min(t, self.heartbeat)
        if Duration.ZERO < self.tls_reload_check:
            t = min(t, self.tls_reload_check)
        var q = Duration.from_nanos(t.as_nanos() // 4)
        return max(min(q, Duration.from_secs(1)), Duration.from_millis(10))


# ---- requests and responses ------------------------------------------------------------


struct Request(Movable):
    """A whole request, as a handler gets it."""

    var method: String
    var target: String
    """The request target: `/path?query`, `*` (OPTIONS) or `host:port`
    (CONNECT). An absolute-form target (`http://host/path?query`, which a
    server must accept) is kept as its path and query, its authority in
    `host()`."""
    var version: Version
    var headers: Headers
    var body: List[UInt8]
    var trailers: Headers
    var peer: SocketAddr
    """The client's address."""
    var id: UInt64
    """The connection's id, for `Server.wake` (and `Handler.take_wakes`):
    it names this connection while it lives, and is not reused before 2^40
    connections."""
    var _authority: String
    """The authority of an absolute-form target, or empty."""

    def __init__(out self, peer: SocketAddr, id: UInt64 = 0):
        self.method = String()
        self.target = String()
        self.version = Version.HTTP_1_1
        self.headers = Headers()
        self.body = List[UInt8]()
        self.trailers = Headers()
        self.peer = peer
        self.id = id
        self._authority = String()

    def host(self) -> String:
        """The host the request is for: the authority of an absolute-form
        target, which replaces Host (RFC 9112 3.2.2), else the Host field
        ("" if none, as HTTP/1.0 allows)."""
        if self._authority.byte_length() > 0:
            return self._authority
        var h = self.headers.get("host")
        return String(h.value()) if h else String()

    def path(self) -> StringSlice[origin_of(self.target)]:
        """The target up to its query ("?"), raw: not percent-decoded, so
        compare decoded segments (as `Router` does) when access depends on
        the path."""
        var q = self.target.find("?")
        if q < 0:
            return StringSlice(self.target)
        return StringSlice(self.target)[byte=0:q]

    def query(self) -> StringSlice[origin_of(self.target)]:
        """The target after its "?", or empty."""
        var q = self.target.find("?")
        if q < 0:
            return StringSlice(self.target)[byte=0:0]
        return StringSlice(self.target)[byte = q + 1 :]

    def text(self) -> String:
        """The body as a string (lossy for bytes that are not UTF-8)."""
        return String(from_utf8_lossy=Span(self.body))


struct Response(Movable):
    """What a handler answers. The server adds Date, Content-Length (the
    body's length, unless the handler set Content-Length itself) and the
    configured Server field."""

    var status: Int
    var reason: String
    """Empty for the registered phrase."""
    var headers: Headers
    var body: List[UInt8]
    var _stream: Bool
    var _events: Bool
    """An event stream: heartbeats while it is paused."""

    def __init__(out self):
        self.status = 200
        self.reason = String()
        self.headers = Headers()
        self.body = List[UInt8]()
        self._stream = False
        self._events = False

    def stream(mut self):
        """Make this a streamed response: the head goes out now (chunked,
        unless the handler set Content-Length), then the body comes from
        `Handler.produce`, piece by piece, as the client takes it. `body`
        is ignored."""
        self._stream = True

    def event_stream(mut self) raises IoError:
        """Make this a stream of server-sent events (the WHATWG standard):
        `Content-Type: text/event-stream`, `Cache-Control: no-cache`, and
        `X-Accel-Buffering: no` (so that nginx passes each event on at
        once), then `stream()`. `produce` writes events with
        `http.sse.write_event` (`write_comment` for comments). While the
        stream is paused, a comment line goes out every
        `ServerConfig.heartbeat`, between lines (never inside one), so
        that proxies and clients keep it open. A Content-Length set by the
        handler stops the heartbeats, which would break its framing."""
        self.headers.set("Content-Type", "text/event-stream")
        self.headers.set("Cache-Control", "no-cache")
        self.headers.set("X-Accel-Buffering", "no")
        self._events = True
        self.stream()

    def retry_later(mut self, status: Int, delay: Duration, body: StringSlice = "") raises IoError:
        """Answer `status` (429 Too Many Requests, 503 Service Unavailable)
        with `Retry-After`: `delay` in seconds, rounded up (RFC 9110
        10.2.3), and a text body (the status's phrase if `body` is empty).
        `InvalidInput` for a status that is not 3xx, 4xx or 5xx."""
        if status < 300 or status > 599:
            raise IoError.of_kind("Response.retry_later", ErrorKind.InvalidInput)
        var ns = delay.as_nanos()
        var secs = ns // 1_000_000_000 + (1 if ns % 1_000_000_000 > 0 else 0)
        if body.byte_length() > 0:
            self.text(status, body)
        else:
            self.text(status, String(_phrase(status), "\n"))
        self.headers.set("Retry-After", String(secs))

    def text(
        mut self,
        status: Int,
        body: StringSlice,
        content_type: StringSlice = "text/plain; charset=utf-8",
    ) raises IoError:
        """Answer `status` with a text body."""
        self.bytes(status, body.as_bytes(), content_type)

    def bytes(
        mut self, status: Int, body: Span[UInt8, _], content_type: StringSlice
    ) raises IoError:
        """Answer `status` with `body`, typed `content_type`."""
        self.status = status
        self.headers.set("Content-Type", content_type)
        self.body.clear()
        self.body.extend(body)

    def _reset(mut self):
        self.status = 200
        self.reason = String()
        self.headers.clear()
        self.body.clear()
        self._stream = False
        self._events = False


trait Handler(Deinitable, Movable):
    """The application: one `handle` call per complete request, and, with
    the defaulted hooks, streamed request bodies and streamed responses.
    No method may block: the loop serves every connection of the
    process."""

    def handle(mut self, req: Request, mut res: Response) raises:
        """Fill `res` for `req` (it starts as an empty 200), or call
        `res.stream()`. An error it raises is answered with 500."""
        ...

    def stream_request(mut self, req: Request) raises -> Bool:
        """Called at a request's head: True to take its body as it arrives
        (`on_body`), unbuffered and without `max_body`; `handle` follows at
        its end with `req.body` empty. False (the default) buffers it. An
        error answers 500 (as from `on_body`)."""
        return False

    def on_body(mut self, req: Request, data: Span[UInt8, _]) raises:
        """A piece of a streamed request body. An error answers 500 at once
        and the rest of the request is ignored: read and dropped if it is
        short, else the connection closes after the 500."""
        pass

    def body_cut(mut self, req: Request):
        """A body taken with `stream_request` will not complete, so
        `handle` will not be called: the client left, stalled or sent a
        malformed body, `on_body` raised, or a shutdown closed the
        connection. Release what `stream_request` set up (an open file)."""
        pass

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        """Append more of a streamed response's body to `out` (empty when
        called): True while more will come, False at its end. Appending
        nothing and returning True pauses the stream until `Server.wake`
        (or `take_wakes`) names its connection. An error ends the
        connection (the response is under way)."""
        return False

    def take_wakes(mut self) -> List[UInt64]:
        """Connection ids (`Request.id`) whose paused streams to resume,
        collected by the handler since the last call. The server asks after
        every call into the handler."""
        return List[UInt64]()

    def stream_ended(mut self, req: Request, finished: Bool):
        """A response made with `res.stream()` is over; called once for
        each. `finished`: its whole body was handed to the connection (it
        may still be on its way), or it had none (HEAD, 204, 304).
        Otherwise it was cut: the client left, `produce` raised, the head
        was refused, or a shutdown timed out. Release what the stream held
        here (open files, subscriptions)."""
        pass

    def shutting_down(mut self):
        """Called once when the server begins a graceful shutdown. Streams
        last until `shutdown_timeout` unless they end: a handler with
        long-lived ones (server-sent events) ends them here, by waking them
        (`take_wakes` is asked after this call) so that `produce` returns
        False."""
        pass


# ---- one connection ---------------------------------------------------------------------


struct _Conn(Movable):
    var stream: TcpStream
    var http: ServerConnection
    var ev: ServerEvent
    var out: ByteBuffer
    """What the codec handed out that the socket has not taken yet."""
    var req: Request
    var res: Response
    var state: Int
    var first: Bool
    """No request has been answered on this connection yet."""
    var head_started: Bool
    var deadline: Instant
    """When the current state times out."""
    var blocked: Bool
    """Output is waiting for the socket."""
    var write_deadline: Instant
    var rejected: Bool
    """The current request was answered early (413); its body is ignored."""
    var streamed: Bool
    """The current request's body goes to `Handler.on_body`."""
    var paused: Bool
    """The streamed response waits for a wake."""
    var beating: Bool
    """The streamed response is an event stream that gets heartbeats."""
    var line_open: Bool
    """The stream's last byte did not end a line (no heartbeat now)."""
    var last_out: Instant
    """When the stream last sent something (its head, body, a heartbeat)."""
    var hangup: Bool
    """Epoll reported that the peer closed or half-closed (sticky)."""
    var eof: Bool
    """The end of the client's input was read."""
    var refused: Bool
    """The codec refused the handler's last head (a 500 went instead)."""
    var moved: Int
    var answered_now: Int
    """This turn's slice so far: bytes read and written, requests answered."""
    var again: Bool
    """The slice is used up: serve the connection again next turn."""
    var body_open: Bool
    """A body taken with `stream_request` is under way (`body_cut` is owed
    if it does not complete)."""
    var body_window: Int
    """Body bytes read since `deadline` was last set (min_rate)."""
    var writing: Bool
    """Output is waiting to be taken."""
    var write_window: Int
    """Bytes taken since `write_deadline` was last set (min_rate)."""
    var tls: List[TlsServer]
    """TLS between the socket and the codec: one element, or none (boxed:
    an `Optional` of it would cost a copy per use, CLAUDE.md)."""
    var tls_plain: ByteBuffer
    """The codec's output that TLS has not taken yet."""
    var tls_in: List[UInt8]
    """Plaintext TLS delivered that the codec has not taken yet."""
    var tls_in_off: Int
    var handshaking: Bool
    """The TLS handshake is under way (counted by the server, TS7)."""
    var established_now: Bool
    """The handshake ended in this service (the server uncounts it)."""
    var tls_deadline: Instant
    """When the handshake must have ended (TS8)."""
    var sni: String
    """The name the client asked for, once established ("" for none)."""
    var notified: Bool
    """close_notify is queued (or the connection never got that far)."""
    var stop_after_handshake: Bool
    """A shutdown came during the handshake: once it ends, take in what
    arrived with it, then stop taking requests."""
    var tls_eof: Bool
    """The end of the client's ciphertext was fed to TLS."""
    var tls_wanted: Bool
    """TLS, not begun yet: the first record is still coming (`hello`), or
    it came and the server has not admitted the handshake yet."""
    var hello: List[UInt8]
    """The client's first record as it arrives (TLS, before admission)."""
    var hello_ready: Bool
    """That record is whole: the server may admit the handshake."""
    var tls_waiting: Bool
    """It is in the server's queue of handshakes to admit."""
    var hello_deadline: Instant
    """When the first record must have arrived whole."""

    def __init__(
        out self,
        var stream: TcpStream,
        peer: SocketAddr,
        id: UInt64,
        config: ServerConfig,
        max_buffered: Int,
        now: Instant,
        tls: Bool,
    ) raises IoError:
        self.stream = stream^
        self.http = ServerConnection(limits=config.limits, max_buffered=max_buffered)
        self.ev = ServerEvent(EventKind.END)
        self.out = ByteBuffer()
        self.req = Request(peer, id)
        self.res = Response()
        self.state = _WAITING
        self.first = True
        self.head_started = False
        self.deadline = now + config.header_timeout
        self.blocked = False
        self.write_deadline = now
        self.rejected = False
        self.streamed = False
        self.paused = False
        self.beating = False
        self.line_open = False
        self.last_out = now
        self.hangup = False
        self.eof = False
        self.refused = False
        self.moved = 0
        self.answered_now = 0
        self.again = False
        self.body_open = False
        self.body_window = 0
        self.writing = False
        self.write_window = 0
        self.handshaking = False
        self.tls = List[TlsServer]()
        self.tls_plain = ByteBuffer()
        self.tls_in = List[UInt8]()
        self.tls_in_off = 0
        self.established_now = False
        self.tls_deadline = now + config.tls_handshake_timeout
        self.sni = String()
        self.notified = False
        self.stop_after_handshake = False
        self.tls_eof = False
        self.tls_wanted = tls
        self.hello = List[UInt8]()
        self.hello_ready = False
        self.tls_waiting = False
        self.hello_deadline = now + min(config.tls_hello_timeout, config.tls_handshake_timeout)

    def _read_hello(mut self, mut chunk: List[UInt8]) raises -> Optional[Int]:
        """Read the client's first record into `hello`, and no further
        (None: it is not whole yet, or now it is (`hello_ready`); 0: the
        client left). Anything but a TLS handshake record of at most
        2^14 bytes (plaintext HTTP, SSLv2's hello) is refused at once."""
        while not self.hello_ready:
            var have = len(self.hello)
            var need = 5
            if have >= 5:
                need = 5 + (Int(self.hello[3]) << 8 | Int(self.hello[4]))
            var got = self.stream.try_read(Span(chunk)[0 : need - have])
            if not got:
                return None
            if got.value() == 0:
                return 0
            self.moved += got.value()
            self.hello.extend(Span(chunk)[0 : got.value()])
            if have < 5 and len(self.hello) >= 5:
                var n = Int(self.hello[3]) << 8 | Int(self.hello[4])
                if self.hello[0] != 22 or self.hello[1] != 3 or n > 16384:
                    raise Error("tls: the first record is not a TLS handshake record")
            if len(self.hello) >= 5 and len(self.hello) == 5 + (Int(self.hello[3]) << 8 | Int(self.hello[4])):
                self.hello_ready = True
        return None

    def __deinit__(deinit self):
        if len(self.tls) > 0:
            self.tls[0].wipe(self.tls_in)  # (TB18: plaintext the codec never took)

    def start_tls(mut self, var tls: TlsServer) raises:
        """The handshake is admitted: TLS takes the first record, and the
        connection counts as a handshake from now on (if that raises, it
        never did)."""
        self.tls.append(tls^)
        self.tls_wanted = False
        self.hello_ready = False
        var hello = List[UInt8]()
        swap(hello, self.hello)
        self.tls[0].feed(Span(hello))
        self.handshaking = True

    def _recv(mut self, mut chunk: List[UInt8], room: Int) raises -> Optional[Int]:
        """Input for the codec, at most `room` bytes into `chunk`: what the
        socket has, or with TLS the plaintext (None: nothing now; 0: the
        end). With TLS it reads ciphertext until a record yields data, the
        socket would block, or the slice is used up (`again`); records
        without data count against the slice too."""
        if self.tls_wanted:
            return self._read_hello(chunk)
        if len(self.tls) == 0:
            var got = self.stream.try_read(Span(chunk)[0:room])
            if got:
                self.moved += got.value()
            return got
        while True:
            if self.tls_in_off < len(self.tls_in):
                var n = min(room, len(self.tls_in) - self.tls_in_off)
                unsafe_memcpy(dest=chunk.unsafe_ptr(), src=self.tls_in.unsafe_ptr().unsafe_offset(self.tls_in_off), count=n)
                self.tls_in_off += n
                if self.tls_in_off == len(self.tls_in):
                    self.tls[0].wipe(self.tls_in)  # (TB18: plaintext the codec has taken)
                    self.tls_in.clear()
                    self.tls_in_off = 0
                return n
            var ev: Optional[TlsEvent]
            try:
                ev = self.tls[0].next_event()
            except e:
                if e.category != Category.TRUNCATED:
                    raise e
                return 0  # (the client left without close_notify: its input ends)
            if ev:
                var kind = ev.value().kind
                if kind == TlsEventKind.DATA:
                    swap(self.tls_in, ev.value().data)
                    self.tls_in_off = 0
                elif kind == TlsEventKind.ESTABLISHED:
                    self.handshaking = False
                    self.established_now = True
                    self.sni = self.tls[0].server_name()
                else:
                    return 0  # CLOSED: the client's close_notify
                continue
            if self.tls_eof or self.tls[0].is_closed():
                return 0  # (asked again after the end: still the end)
            if self.moved >= _SLICE_BYTES:
                self.again = True  # (the socket may hold more: no edge would say so)
                return None
            var cap = min(self.tls[0].feed_capacity(), len(chunk))
            if cap == 0:
                self.again = True
                return None
            var got = self.stream.try_read(Span(chunk)[0:cap])
            if not got:
                return None
            if got.value() == 0:
                self.tls_eof = True
                self.tls[0].feed_eof()
                continue
            self.moved += got.value()
            self.tls[0].feed(Span(chunk)[0 : got.value()])

    def _fill(mut self) raises -> Int:
        """Move output into `out`: the codec's, or with TLS its ciphertext
        (the codec's output goes into TLS while less than `_HIGH_WATER` of
        ciphertext waits)."""
        if len(self.tls) == 0:
            return self.http.poll_transmit(self.out)
        while self.tls[0].pending_transmit() < _HIGH_WATER:
            if len(self.tls_plain) == 0 and self.http.poll_transmit(self.tls_plain) == 0:
                break
            var n = self.tls[0].write(self.tls_plain.readable_span())
            self.tls_plain.consume(n)
            if n == 0:
                break
        return self.tls[0].poll_transmit(self.out)

    def queued(self) -> Int:
        """Output produced and not yet taken by the socket."""
        var n = len(self.out) + self.http.pending_transmit()
        if len(self.tls) > 0:
            n += len(self.tls_plain) + self.tls[0].pending_transmit()
        return n

    def flush_alert(mut self):
        """After a TLS failure, what OpenSSL queued (its alert) is sent, if
        the socket takes it at once (TS10)."""
        if len(self.tls) == 0:
            return
        try:
            if len(self.out) == 0:
                _ = self.tls[0].poll_transmit(self.out)
        except:
            return
        try:
            if len(self.out) > 0:
                _ = self.stream.try_write(self.out.readable_span())
        except:
            pass

    def service[H: Handler](
        mut self,
        mut handler: H,
        config: ServerConfig,
        date: DateCache,
        mut chunk: List[UInt8],
        now: Instant,
        hangup: Bool,
    ) raises -> Bool:
        """Run the connection until its socket would block, or its slice of
        this turn is used up (`again`): False once it is finished (the codec
        says close, or the peer is gone). `hangup`: the readiness event
        says the peer closed or half-closed."""
        if hangup:
            self.hangup = True
        self.moved = 0
        self.answered_now = 0
        while True:
            if not self.flush(config, now):
                return True  # wait for the next writable edge
            if self.state == _LINGERING:
                return self.linger(chunk)
            if self.stop_after_handshake and not self.handshaking and not self.tls_wanted:
                self.stop_after_handshake = False
                self.absorb(chunk, config, now)
                self.http.close_gracefully()
            if self.http.should_close():
                if not self.notified:
                    # (TS10) A graceful end sends close_notify, after the
                    # response: flush it first. Never during a handshake.
                    self.notified = True
                    if len(self.tls) > 0 and self.tls[0].is_established() and not self.tls[0].is_closed():
                        try:
                            self.tls[0].close()
                        except:
                            pass
                        continue
                var stay = not self.eof and self.http.input_pending()
                if not stay and not self.eof:
                    # Bytes that came after the last read (a request
                    # pipelined behind a closing one) would make close()
                    # send a reset: look once more.
                    var late = self.stream.try_read(Span(chunk))
                    stay = Bool(late) and late.value() > 0
                if not stay:
                    return False  # nothing more is coming: close now
                self.stream.shutdown(Shutdown.WRITE)  # (after the response)
                self.state = _LINGERING
                self.deadline = now + config.linger_timeout
                return self.linger(chunk)
            if self.moved >= _SLICE_BYTES or self.answered_now >= _SLICE_REQUESTS:
                self.again = True  # the others' turn
                return True
            if self.state == _PRODUCING:
                if not self.paused and self.produce(handler, config, now):
                    continue  # more body went out: flush it
            elif self.dispatch(handler, config, date, now) or self.queued() > 0:
                continue  # output came (a response, a 100 Continue): flush it first
            # Only a paused stream reads while _PRODUCING (one that has
            # something to send loops above), and a client that leaves it,
            # or half-closes, ends it.
            var room = min(len(chunk), self.http.feed_capacity())
            if room == 0:
                # Pipelined input fills the codec, so the end of input
                # cannot be read: the hangup flag tells it instead.
                return not (self.state == _PRODUCING and self.hangup)
            var got = self._recv(chunk, room)
            if not got:
                if self.queued() > 0:
                    continue  # TLS queued output (its handshake): flush it
                if self.again:
                    return True  # (the slice ran out inside _recv)
                return True  # wait for the next readable edge
            if got.value() == 0:
                self.eof = True
                self.http.feed_eof()
                if self.state == _PRODUCING:
                    return False  # nobody left to stream to
            else:
                var n = got.value()
                self.http.feed(Span(chunk)[0:n])
                if self.state == _WAITING and not self.head_started and self.http.head_begun():
                    self.head_started = True
                    self.deadline = now + config.header_timeout
                elif self.state == _BODY:
                    self.body_window += n
                    if _enough(self.body_window, config.read_timeout, config.min_rate):
                        self.deadline = now + config.read_timeout  # progress
                        self.body_window = 0

    def absorb(mut self, mut chunk: List[UInt8], config: ServerConfig, now: Instant) raises:
        """Feed the codec what has arrived, without serving it: a shutdown
        reads first, so that a request already sent counts as in progress
        when it stops taking requests."""
        while self.state != _LINGERING and not self.eof:
            var room = min(len(chunk), self.http.feed_capacity())
            if room == 0:
                return
            var got = self._recv(chunk, room)
            if not got:
                return
            if got.value() == 0:
                self.eof = True
                self.http.feed_eof()
                return
            self.http.feed(Span(chunk)[0 : got.value()])
            if self.state == _WAITING and not self.head_started and self.http.head_begun():
                self.head_started = True
                self.deadline = now + config.header_timeout

    def linger(mut self, mut chunk: List[UInt8]) raises IoError -> Bool:
        """Read and drop input until the socket would block (True: wait for
        more, or for the linger timeout), the slice is used up (True, and
        `again`) or the client's input ends (False: close)."""
        while True:
            var got = self.stream.try_read(Span(chunk))
            if not got:
                return True
            if got.value() == 0:
                return False
            self.moved += got.value()
            if self.moved >= _SLICE_BYTES:
                self.again = True
                return True

    def flush(mut self, config: ServerConfig, now: Instant) raises -> Bool:
        """Write queued output until the socket would block: False if some
        is still waiting (the write timeout runs from the first stall, and
        `min_rate` from when the output began to wait)."""
        while True:
            if len(self.out) == 0 and self._fill() == 0:
                self.blocked = False
                self.writing = False
                if self.state == _WAITING:
                    self._give_back()
                return True
            if not self.writing:
                self.writing = True  # output begins to wait
                self.write_deadline = now + config.write_timeout
                self.write_window = 0
            var sent = self.stream.try_write(self.out.readable_span())
            if not sent:
                self.blocked = True  # (the sweep holds it to write_deadline)
                return False
            self.out.consume(sent.value())
            self.moved += sent.value()
            self.write_window += sent.value()
            if _enough(self.write_window, config.write_timeout, config.min_rate):
                self.write_deadline = now + config.write_timeout  # progress
                self.write_window = 0
            self.blocked = False

    def _give_back(mut self) raises:
        """Drop buffers an idle connection grew past `_KEEP`."""
        if self.out.capacity() > _KEEP:
            self.out = ByteBuffer()
        self.http.trim(_KEEP)
        if self.tls_plain.capacity() > _KEEP:
            self.tls_plain = ByteBuffer()
        if self.tls_in.capacity() > _KEEP:
            self.tls_in = List[UInt8]()

    def dispatch[H: Handler](
        mut self, mut handler: H, config: ServerConfig, date: DateCache, now: Instant
    ) raises -> Bool:
        """Drain the codec's events, collecting and answering requests, until
        `_HIGH_WATER` of output is queued (True: flush it before answering
        more) or more input is needed (False). That is the backpressure for
        pipelined requests: those already buffered wait, unanswered, while
        the client is slow to take what came before; below the mark,
        responses go out together in one write."""
        while True:
            var got: Bool
            try:
                got = self.http.poll(self.ev)
            except:
                self.cut_body(handler)
                if not self.rejected:  # (else it was answered already)
                    var status = self.http.error_status()
                    try:
                        self.http.send_error(status if status >= 400 else 400, date.current())
                    except:
                        pass  # (its response went out already: the codec closes after it)
                return True  # the codec now closes, after what it sends
            if not got:
                return False
            if self.ev.kind == EventKind.HEAD:
                if self.start(handler, config, date, now):
                    return True  # answered at once (413, or a hook failed)
            elif self.ev.kind == EventKind.DATA:
                if self.rejected:
                    continue
                if self.streamed:
                    var ok = True
                    try:
                        handler.on_body(self.req, Span(self.ev.data))
                    except:
                        ok = False
                    if not ok:
                        self.cut_body(handler)
                        self.fail(config, date)
                        return True
                    continue
                if len(self.req.body) + len(self.ev.data) > config.max_body:
                    self.reject(config, date)
                    return True
                self.req.body.extend(Span(self.ev.data))
            else:  # END
                var answered = not self.rejected
                self.first = False
                self.body_open = False  # complete: `handle` comes
                if answered:
                    swap(self.req.trailers, self.ev._trailers[0])
                    self.answered_now += 1
                    if self.answer(handler, config, date):
                        self.state = _PRODUCING  # until produce says the end
                        self.paused = False
                        self.last_out = now
                        self.line_open = False
                        return True
                self.waiting(config, now)
                if answered and (
                    self.queued() >= _HIGH_WATER
                    or self.answered_now >= _SLICE_REQUESTS
                ):
                    return True

    def cut_body[H: Handler](mut self, mut handler: H):
        """The streamed body under way will not complete: tell the handler
        (once)."""
        if self.body_open:
            self.body_open = False
            handler.body_cut(self.req)

    def waiting(mut self, config: ServerConfig, now: Instant):
        """Between requests again: the idle timeout, or the header one if
        the next head has begun."""
        self.state = _WAITING
        self.rejected = False
        # (Line ends before a request line are no head: RFC 9112 2.2.)
        self.head_started = self.http.head_begun()
        var t = config.header_timeout if self.head_started else config.idle_timeout
        self.deadline = now + t
        if self.req.body.capacity() > _KEEP:
            self.req.body = List[UInt8]()
        if self.res.body.capacity() > _KEEP:
            self.res.body = List[UInt8]()
        if self.req.headers._data.capacity() > _KEEP:
            self.req.headers = Headers()
        if self.res.headers._data.capacity() > _KEEP:
            self.res.headers = Headers()
        if self.ev.data.capacity() > _KEEP:
            self.ev.data = List[UInt8]()
        if len(self.ev._head) > 0 and self.ev._head[0].headers._data.capacity() > _KEEP:
            self.ev._head[0].headers = Headers()

    def produce[H: Handler](
        mut self, mut handler: H, config: ServerConfig, now: Instant
    ) raises -> Bool:
        """Pull streamed body from the handler while the output is under
        `_HIGH_WATER`: True if some went out (flush it), False if the stream
        paused (nothing to send until a wake). At the stream's end the
        response is ended and the connection goes back to its requests."""
        var sent = False
        while self.queued() < _HIGH_WATER:
            self.res.body.clear()
            var more = handler.produce(self.req, self.res.body)
            var n = len(self.res.body)
            if n > 0:
                self.http.send_body(Span(self.res.body))
                sent = True
                self.last_out = now
                var last = self.res.body[n - 1]
                self.line_open = last != 10 and last != 13
            if not more:
                self.http.end_response()
                self.waiting(config, now)
                handler.stream_ended(self.req, True)
                return True
            if len(self.res.body) == 0:
                self.paused = True
                return sent
        return sent

    def start[H: Handler](
        mut self, mut handler: H, config: ServerConfig, date: DateCache, now: Instant
    ) raises -> Bool:
        """A request head arrived: move it into `req`. True if it was
        answered at once (a body over `max_body`, or a failing hook)."""
        ref h = self.ev.head()
        swap(self.req.method, h.method)
        swap(self.req.target, h.target)
        self.req.version = h.version
        swap(self.req.headers, h.headers)
        self.req.body.clear()
        self.req.trailers.clear()
        if not _origin_form(self.req):
            self.rejected = True
            self.http.send_error(400, date.current())
            return True
        if self.sni.byte_length() > 0 and not _same_host(self.req.host(), self.sni):
            # (TS6) Not the name the client asked for: 421 Misdirected
            # Request, and the connection closes after it.
            self.rejected = True
            self.http.send_error(421, date.current())
            return True
        self.rejected = False
        self.state = _BODY
        self.deadline = now + config.read_timeout
        self.body_window = 0
        self.body_open = False
        var ok = True
        try:
            self.streamed = handler.stream_request(self.req)
        except:
            ok = False
        if not ok:
            self.fail(config, date)
            return True
        self.body_open = self.streamed
        var length = self.ev.framing.length
        if not self.streamed and length > config.max_body:
            self.reject(config, date)
            return True
        if self.req.version.at_least_1_1() and self.req.headers.has_token("expect", "100-continue"):
            self.http.send_continue()
        return False

    def fail(mut self, config: ServerConfig, date: DateCache) raises:
        """A hook raised before the request ended: answer 500; the rest of
        the request is ignored."""
        self.rejected = True
        self.res._reset()
        self.res.text(500, "Internal Server Error\n")
        _ = self.send(config, date)

    def reject(mut self, config: ServerConfig, date: DateCache) raises:
        """Answer 413 before the body ends; its rest is then ignored (the
        codec reads a short one and closes after a long one)."""
        self.rejected = True
        self.res._reset()
        self.res.text(413, "Request body too large\n")
        _ = self.send(config, date)

    def answer[H: Handler](
        mut self, mut handler: H, config: ServerConfig, date: DateCache
    ) raises -> Bool:
        """Run the handler and send its response: True if it is a stream
        whose body is still to come."""
        self.res._reset()
        var failed = False
        try:
            handler.handle(self.req, self.res)
        except:
            failed = True
        if failed:
            if self.res._stream:
                handler.stream_ended(self.req, False)  # (it may hold something)
            self.res._reset()
            self.res.text(500, "Internal Server Error\n")
        var streaming = self.send(config, date)
        if self.res._stream and not streaming:
            handler.stream_ended(self.req, not self.refused)  # nothing to stream
        return streaming

    def send(mut self, config: ServerConfig, date: DateCache) raises -> Bool:
        """Queue `res` with the fields the server adds. If the codec refuses
        the handler's head (an invalid field combination), a 500 goes out
        instead. A streamed response gets its head only (the codec chunks
        it, unless the handler gave a Content-Length): True then, unless
        it has no body to stream (HEAD, 204, 304)."""
        var head = ResponseHead(self.res.status, self.res.reason)
        swap(head.headers, self.res.headers)
        var has = _scan(head.headers)
        # The server's own fields are valid by construction: pushed as is.
        if not has.date:
            head.headers._push("Date".as_bytes(), date.current().as_bytes(), utf8=True)
        if config.server_name.byte_length() > 0 and not has.server:
            head.headers._push("Server".as_bytes(), config.server_name.as_bytes(), utf8=True)
        var s = head.status
        var bodiless = (s >= 100 and s < 200) or s == 204 or s == 304
        var streaming = self.res._stream and not bodiless and self.req.method != "HEAD"
        # What the server cannot send as asked gets a 500: no upgrades or
        # tunnels (the connection stays HTTP), and a buffered body must fit
        # the codec and match the handler's Content-Length.
        var invalid = s == 101 or (self.req.method == "CONNECT" and s >= 200 and s < 300)
        if not invalid and not self.res._stream and not bodiless and self.req.method != "HEAD":
            if len(self.res.body) > _MAX_BUFFERED_BODY:
                invalid = True
            elif has.framing:
                var declared = _declared_length(head.headers)
                invalid = Bool(declared) and declared.value() != len(self.res.body)
        if not bodiless and not has.framing:
            if not self.res._stream:
                _push_decimal(head.headers, "Content-Length", len(self.res.body))
            elif not streaming and self.req.version.at_least_1_1():
                # HEAD: the fields its GET gets (RFC 9110 9.3.2), where the
                # codec would chunk the body
                head.headers._push("Transfer-Encoding".as_bytes(), "chunked".as_bytes(), utf8=True)
        var refused = invalid
        if not refused:
            try:
                self.http.send_response(head)
            except:
                refused = True
        self.refused = refused
        if refused:
            var fallback = ResponseHead(500)
            fallback.headers.add("Date", date.current())
            fallback.headers.add("Content-Length", "0")
            self.http.send_response(fallback)
        elif streaming:
            swap(head.headers, self.res.headers)
            self.beating = self.res._events and not has.framing
            return True  # the body comes from produce
        elif not bodiless and not self.res._stream:
            self.http.send_body(Span(self.res.body))
        self.http.end_response()
        swap(head.headers, self.res.headers)  # keep the allocation for the next one
        return False


@fieldwise_init
struct _Has(TrivialRegisterPassable):
    var date: Bool
    var server: Bool
    var framing: Bool
    """Content-Length or Transfer-Encoding."""


def _scan(headers: Headers) -> _Has:
    """Which of the fields the server adds a handler set already."""
    var h = _Has(False, False, False)
    for i in range(len(headers._fields)):
        var f = headers._fields[i]
        var name = headers._bytes(f.name, f.name_len)
        var n = len(name)
        if n == 4:
            h.date = h.date or eq_ignore_case(name, "date".as_bytes())
        elif n == 6:
            h.server = h.server or eq_ignore_case(name, "server".as_bytes())
        elif n == 14:
            h.framing = h.framing or eq_ignore_case(name, "content-length".as_bytes())
        elif n == 17:
            h.framing = h.framing or eq_ignore_case(name, "transfer-encoding".as_bytes())
    return h


def _push_decimal(mut headers: Headers, name: StringSlice, n: Int):
    """Push the field `name: <n in decimal>` (n >= 0) without a String."""
    var buf = Array[UInt8, 20](fill=0)
    var digits = 0
    var v = n
    while True:
        digits += 1
        v //= 10
        if v == 0:
            break
    v = n
    for i in range(digits - 1, -1, -1):
        buf[i] = UInt8(48 + v % 10)
        v //= 10
    headers._push(name.as_bytes(), Span(buf)[0:digits], utf8=True)


def _declared_length(headers: Headers) -> Optional[Int]:
    """The Content-Length a handler set, if it is plain digits (anything
    else the codec refuses)."""
    var v = headers.get_bytes("content-length")
    if not v or len(v.value()) == 0 or len(v.value()) > 18:
        return None
    var n = 0
    for b in v.value():
        if b < 48 or b > 57:
            return None
        n = n * 10 + Int(b) - 48
    return n


def _enough(window: Int, timeout: Duration, min_rate: Int) -> Bool:
    """Whether `window` bytes of progress renew a `timeout`: any progress
    without a `min_rate`, else `min_rate` times the timeout's seconds (at
    least 1 byte)."""
    if min_rate <= 0:
        return window > 0
    var need = max(min_rate * Int(timeout.as_nanos() // 1_000_000) // 1000, 1)
    return window >= need


def _same_host(host: String, sni: String) -> Bool:
    """Whether the request's host (a Host field or an authority, perhaps
    with a port and a trailing dot) is the SNI name; an absent host is no
    claim. Compared without case, as names are."""
    if host.byte_length() == 0:
        return True
    var b = host.as_bytes()
    var end = len(b)
    if b[0] == UInt8(ord("[")):
        return False  # (an IPv6 literal: SNI never carries one)
    var colon = host.rfind(":")
    if colon >= 0:
        end = colon
    if end > 0 and b[end - 1] == UInt8(ord(".")):
        end -= 1
    if end != sni.byte_length():
        return False
    var n = sni.as_bytes()
    for i in range(end):
        var c = b[i]
        if c >= UInt8(ord("A")) and c <= UInt8(ord("Z")):
            c += 32
        if c != n[i]:
            return False
    return True


struct _FileId(Copyable, Movable, Equatable):
    """What says a file changed: its inode, size and modification time."""

    var ino: UInt64
    var size: UInt64
    var sec: Int64
    var nsec: UInt32

    def __init__(out self, path: String):
        self.ino = 0
        self.size = 0
        self.sec = 0
        self.nsec = 0
        try:
            var st = stat_path(path)
            self.ino = st.ino
            self.size = st.size
            self.sec = st.mtime_sec
            self.nsec = st.mtime_nsec
        except:
            pass  # (gone for now: a change, if it was there before)

    def __eq__(self, other: _FileId) -> Bool:
        return self.ino == other.ino and self.size == other.size and self.sec == other.sec and self.nsec == other.nsec


def _origin_form(mut req: Request) -> Bool:
    """An absolute-form target becomes its path and query, its authority
    kept for `host()` and put in the Host field, which the server must
    ignore then (RFC 9112 3.2.2): so a handler, or a proxy it passes the
    fields to, sees the host that was checked. False if that cannot be done
    (the request is refused)."""
    req._authority = String()
    var t = req.target.as_bytes()
    if len(t) == 0 or t[0] == 47 or req.method == "CONNECT":  # "/", or authority-form
        return True
    var at = req.target.find("://")
    if at < 0:
        return True  # "*"
    var i = at + 3
    while i < len(t) and t[i] != 47 and t[i] != 63:  # to "/" or "?"
        i += 1
    req._authority = String(req.target[byte = at + 3 : i])
    var rest = String(req.target[byte=i:])
    req.target = rest^ if rest.startswith("/") else String("/", rest)
    if req._authority.byte_length() > 0:
        try:
            req.headers.set("Host", req._authority)
        except:
            return False
    return True


# ---- the server -------------------------------------------------------------------------


struct Server[H: Handler](Movable):
    """An HTTP/1.1 server running `handler` (see the module docs)."""

    var handler: Self.H
    """The application; reachable between `step`s (tests read its state)."""
    var config: ServerConfig
    var _listener: Optional[TcpListener]
    var _ep: Epoll
    var _conns: List[Optional[_Conn]]
    var _free: List[Int]
    var _live: Int
    var _events: List[EpollEvent]
    var _chunk: List[UInt8]
    var _date: DateCache
    var _paused_until: Optional[Instant]
    var _backlog: Bool
    """Accepting stopped at `max_connections` with connections waiting."""
    var _next_sweep: Instant
    var _now: Instant
    """The clock as read after the last wait (one read per turn)."""
    var _ids: List[UInt64]
    """Per slot: the id of its current connection."""
    var _next_id: UInt64
    """The number the next connection's id carries (above its slot)."""
    var _again: List[Int]
    """Slots to serve in the next turn, which then does not wait for
    readiness: woken streams, and connections whose slice ran out."""
    var _serving: List[Int]
    """The slots this turn serves from `_again` (reused)."""
    var _max_buffered: Int
    """Each codec's receive buffer: room for a head of `limits.max_head`."""
    var _stopping: Bool
    """`shutdown()` was called."""
    var _stop_deadline: Instant
    var _stop: Optional[Stop]
    """What asks for the shutdown (`stop_on`)."""
    var _tls: List[TlsContext]
    """With `serve_tls`: the context new connections get (one element)."""
    var _tls_config: List[TlsConfig]
    var _tls_files: List[_FileId]
    """The certificate's and the key's, when the context was built."""
    var _next_reload: Instant
    var _reload_failed: Bool
    """The last reload failed: the next check tries again."""
    var _next_alarm: Instant
    var _handshakes: Int
    """TLS handshakes under way."""
    var _rate_start: Instant
    var _rate_count: Int
    """TLS handshakes begun since `_rate_start` (a one-second window)."""
    var _tls_queue: List[Int]
    var _tls_queue_ids: List[UInt64]
    """Connections whose ClientHello came, waiting to be admitted, in
    arrival order (slot and id: a slot may be reused)."""
    var _admitted: List[Int]
    var _admitted_ids: List[UInt64]
    var _admitted_at: List[Instant]
    """Handshakes in admission order, from `_admitted_head` on (entries
    whose handshake ended are skipped when met): the oldest is the first
    to give its place up (`tls_client_wait`)."""
    var _admitted_head: Int

    def __init__(out self, var handler: Self.H, config: ServerConfig = ServerConfig()) raises IoError:
        """`InvalidInput` for a configuration that cannot work: a
        `server_name` that is no valid field value, `max_connections` out of
        1..16 million or so, or inconsistent `limits`."""
        comptime op = "Server"
        for b in config.server_name.as_bytes():
            if not is_field_byte(b) or b == 9:  # (also no tab)
                raise IoError.of_kind(op, ErrorKind.InvalidInput)
        if config.max_connections < 1 or config.max_connections > _MAX_CONNECTIONS or config.min_rate < 0:
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        if config.tls_max_handshakes < 1 or config.tls_handshake_rate < 0 or not (Duration.ZERO < config.tls_client_wait):
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        self._max_buffered = max(
            ServerConnection.DEFAULT_MAX_BUFFERED, config.limits.max_head + 16 * 1024
        )
        _ = ServerConnection(limits=config.limits, max_buffered=self._max_buffered)  # (checks them)
        self.handler = handler^
        self.config = config.copy()
        self._listener = None
        self._ep = Epoll.new()
        self._conns = List[Optional[_Conn]]()
        self._free = List[Int]()
        self._live = 0
        self._events = List[EpollEvent](capacity=1024)
        self._chunk = List[UInt8](length=_READ_CHUNK, fill=0)
        self._date = DateCache()
        self._paused_until = None
        self._backlog = False
        self._next_sweep = Instant.now()
        self._now = self._next_sweep
        self._ids = List[UInt64]()
        self._next_id = 1
        self._again = List[Int]()
        self._serving = List[Int]()
        self._stopping = False
        self._stop_deadline = self._now
        self._stop = None
        self._tls = List[TlsContext]()
        self._tls_config = List[TlsConfig]()
        self._tls_files = List[_FileId]()
        self._next_reload = self._now
        self._reload_failed = False
        self._next_alarm = self._now
        self._handshakes = 0
        self._rate_start = self._now
        self._rate_count = 0
        self._tls_queue = List[Int]()
        self._tls_queue_ids = List[UInt64]()
        self._admitted = List[Int]()
        self._admitted_ids = List[UInt64]()
        self._admitted_at = List[Instant]()
        self._admitted_head = 0

    def bind(mut self, addr: SocketAddr) raises IoError:
        """Listen on `addr` (port 0 picks one: see `local_addr`), with
        SO_REUSEPORT if the configuration asks. Raises the fd limit and
        pre-grows the fd table first (docs/spikes.md)."""
        _ = raise_nofile_limit()
        var l = TcpListener.bind_reuseport(addr) if self.config.reuseport else TcpListener.bind(addr)
        _ = pregrow_fd_table(l)
        self._ep.add(l, UInt32(EPOLLIN | EPOLLET), _LISTENER)
        self._listener = l^

    def serve_tls(mut self, config: TlsConfig) raises TlsError:
        """Serve HTTPS: every connection accepted from now on runs a TLS
        handshake first (docs/server.md, "TLS"). ALPN is `http/1.1`,
        whatever `config.alpn` says, since that is all the server speaks.
        `SSLKEYLOGFILE` is removed from the environment first, so that no
        libssl writes session secrets there (TS11). Raises what
        `tls.ServerConfig.build` raises."""
        _ = unsetenv("SSLKEYLOGFILE")
        var c = config.copy()
        c.alpn = ["http/1.1"]
        var ctx = c.build(sharing=self._tls[0]) if len(self._tls) > 0 else c.build()
        self._tls.clear()
        self._tls.append(ctx^)
        self._tls_files = [_FileId(c.certificate), _FileId(c.key)]
        self._reload_failed = False
        self._tls_config.clear()
        self._tls_config.append(c^)
        self._next_reload = Instant.now() + self.config.tls_reload_check
        self._alarm(Instant.now())

    def tls_context(self) -> Optional[TlsContext]:
        """The TLS context new connections get, if `serve_tls` was called."""
        if len(self._tls) == 0:
            return None
        return self._tls[0].copy()

    def handshakes(self) -> Int:
        """TLS handshakes under way (admitted, not established yet)."""
        return self._handshakes

    def tls_waiting(self) -> Int:
        """TLS connections whose ClientHello came, waiting to be admitted."""
        var n = 0
        for i in range(len(self._tls_queue)):
            var slot = self._tls_queue[i]
            if self._ids[slot] == self._tls_queue_ids[i] and self._conns[slot] and self._conns[slot].value().tls_waiting:
                n += 1
        return n

    def _reload(mut self, now: Instant):
        """(TS12) When the certificate or key file changed, build a new
        context for new connections; on failure keep the old one."""
        ref c = self._tls_config[0]
        var files: List[_FileId] = [_FileId(c.certificate), _FileId(c.key)]
        var changed = not (files[0] == self._tls_files[0] and files[1] == self._tls_files[1])
        if not changed and not self._reload_failed:
            return
        self._tls_files = files^
        try:
            var ctx = c.build(sharing=self._tls[0])  # (one OpenSSL library context, however many reloads)
            self._tls[0] = ctx^
            self._reload_failed = False
            _log(String("tls: reloaded ", c.certificate))
            self._next_alarm = now
            self._alarm(now)
        except e:
            # Tried again at every check until it works: what fixes it (a
            # chmod, fds freed) need not change what `_FileId` compares.
            if changed or not self._reload_failed:
                _log(String("tls: the reload failed, the previous certificate serves on: ", e))
            self._reload_failed = True

    def _alarm(mut self, now: Instant):
        """Say on stderr, once a day, that the certificate's renewal is
        due (less than a third of its lifetime left: TS12)."""
        if len(self._tls) == 0 or now < self._next_alarm:
            return
        self._next_alarm = now + Duration.from_secs(86400)
        try:
            if self._tls[0].renewal_due():
                _log(String("tls: renew the certificate, it expires in ", self._tls[0].expires_in() // 3600, " hours: ", self._tls_config[0].certificate))
        except:
            pass

    def local_addr(self) raises IoError -> SocketAddr:
        """The address the listener is bound to."""
        if not self._listener:
            raise IoError.of_kind("Server.local_addr", ErrorKind.NotConnected)
        return self._listener.value().local_addr()

    def connections(self) -> Int:
        """Open connections."""
        return self._live

    def wake(mut self, id: UInt64):
        """Resume the paused stream of connection `id` (`Request.id`). It is
        served in the next turn, which then does not wait for readiness. An
        id whose connection has closed, or whose stream is not paused, is
        ignored."""
        var slot = Int(id & ((1 << _SLOT_BITS) - 1))
        if slot >= len(self._conns) or not self._conns[slot] or self._ids[slot] != id:
            return
        ref c = self._conns[slot].value()
        if c.state == _PRODUCING and c.paused:
            c.paused = False
            self._again.append(slot)

    def _take_wakes(mut self):
        var ids = self.handler.take_wakes()
        for i in range(len(ids)):
            self.wake(ids[i])

    def queued_output(self) -> Int:
        """Response bytes produced and not yet taken by the sockets, over
        all connections. Backpressure keeps it to about one response per
        connection whose client is slow to read."""
        var n = 0
        for i in range(len(self._conns)):
            if self._conns[i]:
                n += self._conns[i].value().queued()
        return n

    def run(mut self) raises IoError:
        """Serve until a graceful shutdown has finished (`shutdown()`), or
        the process ends."""
        while not self.stopped():
            self.step(Duration.from_secs(1))

    def shutdown(mut self):
        """Begin a graceful shutdown (see the module docs); `step` or `run`
        carries it out. Calling it again changes nothing."""
        if self._stopping:
            return
        self._stopping = True
        var now = Instant.now()
        self._now = now
        self._stop_deadline = now + self.config.shutdown_timeout
        if self._listener:
            # Connections the kernel has queued may have sent requests:
            # take them before closing the listener resets them.
            self._accept(now, limit=False)
            try:
                self._ep.delete(self._listener.value())
            except:
                pass
            self._listener = None
        self._paused_until = None
        self._backlog = False
        self.handler.shutting_down()
        self._take_wakes()
        for slot in range(len(self._conns)):
            if not self._conns[slot]:
                continue
            if self._conns[slot].value().handshaking or self._conns[slot].value().tls_wanted:
                # (TS10) Its handshake finishes under its deadline; what
                # comes with its end is taken in, then no more.
                self._conns[slot].value().stop_after_handshake = True
                continue
            # First take in what has arrived (a request sent but not yet
            # read is in progress), then stop taking requests.
            var ok = True
            try:
                self._conns[slot].value().absorb(self._chunk, self.config, now)
            except:
                ok = False
            if not ok:
                self._close(slot)
                continue
            self._conns[slot].value().http.close_gracefully()
            self._serve(slot, now)

    def stopped(self) -> Bool:
        """A graceful shutdown has finished: no connection is left."""
        return self._stopping and self._live == 0

    def stop_on(mut self, var stop: Stop) raises IoError:
        """Shut down when `stop` asks (`server.process.Stop`): gracefully at
        the first request (SIGTERM, SIGINT, or the supervisor of a worker),
        and at once, closing every connection, at a signal after it. `run`
        then returns when the shutdown has finished."""
        self._ep.add(stop.signals, UInt32(EPOLLIN), _STOP)
        if stop.lifeline:
            self._ep.add(stop.lifeline.value(), UInt32(EPOLLIN | EPOLLRDHUP), _STOP)
        self._stop = stop^

    def _close_all(mut self):
        for slot in range(len(self._conns)):
            if self._conns[slot]:
                self._close(slot)

    def step(mut self, timeout: Duration) raises IoError:
        """One turn of the loop: wait up to `timeout` for readiness, serve
        what is ready, accept new connections, check timeouts. `run` calls
        it forever; a test or an embedding program can call it itself."""
        if not self._listener and not self._stopping:
            raise IoError.of_kind("Server.step", ErrorKind.NotConnected)
        # The wait is timed from the last turn's clock reading: close enough
        # for timeouts, and it saves a syscall (every clock read is one).
        var wait = min(timeout, self._next_sweep - self._now)
        if self._paused_until:
            wait = min(wait, self._paused_until.value() - self._now)
        if self._stopping and self._live > 0:
            wait = min(wait, self._stop_deadline - self._now)
        if len(self._again) > 0:
            wait = Duration.ZERO
        elif len(self._tls_queue) > 0 and self._handshakes < self.config.tls_max_handshakes:
            wait = min(wait, max(Duration.ZERO, self._rate_start + Duration.from_secs(1) - self._now))
        elif len(self._tls_queue) > 0:
            var oldest = self._oldest_admitted()
            if oldest:
                wait = min(wait, max(Duration.ZERO, oldest.value() + self.config.tls_client_wait - self._now))
        var n = self._ep.wait(self._events, Optional[Duration](wait))
        var now = Instant.now()
        self._now = now
        self._date.refresh(now)
        var accept_now = False
        var asked = False
        for i in range(n):
            var key = self._events[i].data()
            if key == _LISTENER:
                accept_now = True
                continue
            if key == _STOP:
                asked = True
                continue
            var slot = Int(key)
            if slot >= len(self._conns) or not self._conns[slot]:
                continue  # closed earlier in this batch
            var hup = self._events[i].events() & UInt32(EPOLLRDHUP | EPOLLHUP | EPOLLERR)
            self._serve(slot, now, hup != 0)
        # Streams woken since the last turn, and connections whose slice
        # ran out. What serving them adds waits for the next turn, so
        # neither a handler that keeps waking a stream nor a busy client
        # can keep the loop from its sockets.
        if len(self._again) > 0:
            swap(self._serving, self._again)
            for i in range(len(self._serving)):
                var slot = self._serving[i]
                if slot < len(self._conns) and self._conns[slot]:
                    self._serve(slot, now)
            self._serving.clear()
        if self._paused_until and now >= self._paused_until.value():
            self._paused_until = None
            accept_now = True  # the edge may have come while paused
        if (accept_now or self._backlog) and self._listener:
            self._accept(now)
        if len(self._tls_queue) > 0:
            self._admit(now)
        if asked and self._stop:
            var what = self._stop.value().requested()
            if what != Stop.NONE:
                self.shutdown()
            if what == Stop.NOW:
                self._close_all()
        if self._stopping and now >= self._stop_deadline:
            self._close_all()  # what is left after shutdown_timeout
        if now >= self._next_sweep:
            self._sweep(now)
            self._next_sweep = now + self.config._sweep_every()
            if len(self._tls_queue) > 0:
                self._admit(now)  # (the sweep may have freed handshakes)

    def _serve(mut self, slot: Int, now: Instant, hangup: Bool = False):
        var alive: Bool
        try:
            alive = self._conns[slot].value().service(
                self.handler, self.config, self._date, self._chunk, now, hangup
            )
        except:
            alive = False  # reset, broken pipe, a TLS failure: drop it
            self._conns[slot].value().flush_alert()
        if self._conns[slot].value().established_now:
            self._conns[slot].value().established_now = False
            self._handshakes -= 1
        self._take_wakes()
        if not alive:
            self._close(slot)
        elif self._conns[slot].value().hello_ready and not self._conns[slot].value().tls_waiting:
            self._conns[slot].value().tls_waiting = True
            self._tls_queue.append(slot)
            self._tls_queue_ids.append(self._ids[slot])
        elif self._conns[slot].value().again:
            self._conns[slot].value().again = False
            self._again.append(slot)  # its slice ran out: next turn

    def _close(mut self, slot: Int):
        ref c = self._conns[slot].value()
        if c.handshaking:
            c.handshaking = False
            self._handshakes -= 1
        if c.state == _PRODUCING or c.body_open:
            if c.state == _PRODUCING:
                self.handler.stream_ended(c.req, False)  # its stream is cut
            if c.body_open:
                c.body_open = False
                self.handler.body_cut(c.req)  # its body will not complete
            self._take_wakes()
        try:
            self._ep.delete(self._conns[slot].value().stream)
        except:
            pass
        self._conns[slot] = None  # closes the stream
        self._free.append(slot)
        self._live -= 1

    def _accept(mut self, now: Instant, limit: Bool = True):
        """Accept what the listener has queued: up to `max_connections`, or
        all of it if not `limit` (a shutdown takes everything queued)."""
        self._backlog = False
        while True:
            if limit and self._live >= self.config.max_connections:
                self._backlog = True  # take the rest when one closes
                return
            var acc: Optional[TcpAccepted]
            try:
                acc = self._listener.value().try_accept()
            except e:
                if _passed_on(e.errno):
                    continue  # that connection's network error: the next
                # out of fds or memory: try again a little later (the
                # edge-triggered listener would not say so again)
                self._paused_until = now + _PAUSE
                return
            if not acc:
                return
            var a = acc.take()
            var peer = a.addr
            var stream = a^.into_stream()
            var slot: Int
            if len(self._free) > 0:
                slot = self._free.pop()
            else:
                slot = len(self._conns)
                self._conns.append(None)
                self._ids.append(0)
            var id = (self._next_id << UInt64(_SLOT_BITS)) | UInt64(slot)
            self._next_id += 1
            self._ids[slot] = id
            try:
                self._ep.add(stream, UInt32(EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET), UInt64(slot))
                self._conns[slot] = _Conn(stream^, peer, id, self.config, self._max_buffered, now, len(self._tls) > 0)
                self._live += 1
            except:
                self._free.append(slot)  # (the stream closes here)

    def _admit(mut self, now: Instant):
        """(TS7) Begin the waiting handshakes, in arrival order, while
        `tls_max_handshakes` and `tls_handshake_rate` allow: each one's
        `TlsServer` takes its first record, and it is served again."""
        var i = 0
        while i < len(self._tls_queue):
            var slot = self._tls_queue[i]
            if self._ids[slot] != self._tls_queue_ids[i] or not self._conns[slot] or not self._conns[slot].value().tls_waiting:
                i += 1  # (closed meanwhile)
                continue
            if self._handshakes >= self.config.tls_max_handshakes and not self._evict_stalled(now):
                break
            if now - self._rate_start >= Duration.from_secs(1):
                self._rate_start = now
                self._rate_count = 0
            if self.config.tls_handshake_rate > 0 and self._rate_count >= self.config.tls_handshake_rate:
                break  # (the next second: `step` wakes for it)
            i += 1
            ref c = self._conns[slot].value()
            c.tls_waiting = False
            var ok = True
            var tls = List[TlsServer]()
            try:
                tls.append(TlsServer(self._tls[0]))
            except:
                ok = False  # (out of memory)
            if ok:
                try:
                    c.start_tls(tls.pop())
                except:
                    ok = False  # (its first record refused)
            self._rate_count += 1
            if not ok:
                self._conns[slot].value().flush_alert()
                self._close(slot)
                continue
            self._handshakes += 1
            if len(self._admitted) - self._admitted_head > 2 * (self._handshakes + 64):
                self._prune_admitted()  # (amortized: ended handshakes leave)
            self._admitted.append(slot)
            self._admitted_ids.append(self._ids[slot])
            self._admitted_at.append(now)
            self._serve(slot, now)
        if i > 0:
            var rest = List[Int]()
            var rest_ids = List[UInt64]()
            for k in range(i, len(self._tls_queue)):
                rest.append(self._tls_queue[k])
                rest_ids.append(self._tls_queue_ids[k])
            self._tls_queue = rest^
            self._tls_queue_ids = rest_ids^

    def _oldest_admitted(mut self) -> Optional[Instant]:
        """When the oldest handshake under way was admitted (entries whose
        handshake ended are dropped on the way)."""
        while self._admitted_head < len(self._admitted):
            var slot = self._admitted[self._admitted_head]
            if self._ids[slot] == self._admitted_ids[self._admitted_head] and self._conns[slot] and self._conns[slot].value().handshaking:
                return self._admitted_at[self._admitted_head]
            self._admitted_head += 1
        self._admitted.clear()
        self._admitted_ids.clear()
        self._admitted_at.clear()
        self._admitted_head = 0
        return None

    def _evict_stalled(mut self, now: Instant) -> Bool:
        """Close the oldest handshake under way if it has waited
        `tls_client_wait` since its admission (the server's flight went out
        then: what is left is the client's turn): True if one was."""
        var oldest = self._oldest_admitted()
        if not oldest or now - oldest.value() < self.config.tls_client_wait:
            return False
        var slot = self._admitted[self._admitted_head]
        self._admitted_head += 1
        if self._admitted_head > 1024 and self._admitted_head * 2 > len(self._admitted):
            self._prune_admitted()
        self._close(slot)  # (no alert: as at its deadline, TS8)
        return True

    def _prune_admitted(mut self):
        """Keep only the handshakes still under way, in order."""
        var s = List[Int]()
        var ids = List[UInt64]()
        var at = List[Instant]()
        for k in range(self._admitted_head, len(self._admitted)):
            var slot = self._admitted[k]
            if self._ids[slot] == self._admitted_ids[k] and self._conns[slot] and self._conns[slot].value().handshaking:
                s.append(slot)
                ids.append(self._admitted_ids[k])
                at.append(self._admitted_at[k])
        self._admitted = s^
        self._admitted_ids = ids^
        self._admitted_at = at^
        self._admitted_head = 0

    def _sweep(mut self, now: Instant):
        """Apply the timeouts (see the module docs), and check the TLS
        files."""
        if len(self._tls) > 0:
            if Duration.ZERO < self.config.tls_reload_check and now >= self._next_reload:
                self._next_reload = now + self.config.tls_reload_check
                self._reload(now)
            self._alarm(now)
        for slot in range(len(self._conns)):
            if not self._conns[slot]:
                continue
            ref c = self._conns[slot].value()
            if (c.handshaking or c.hello_ready) and now >= c.tls_deadline:
                self._close(slot)  # (TS8: no alert, no close_notify)
                continue
            if c.tls_wanted and not c.hello_ready:
                if now >= c.hello_deadline:
                    self._close(slot)  # (its first record never came whole)
                continue
            if c.blocked:
                if now >= c.write_deadline:
                    # Abort: a graceful close would leave the kernel sending
                    # what is queued (up to a send buffer) at the slow
                    # client's pace, long after the connection is gone here.
                    try:
                        c.stream.socket().set_linger(Duration.ZERO)
                    except:
                        pass
                    self._close(slot)
                continue
            if c.state == _PRODUCING:
                if (
                    c.paused
                    and c.beating
                    and not c.line_open
                    and Duration.ZERO < self.config.heartbeat
                    and now - c.last_out >= self.config.heartbeat
                ):
                    self._beat(slot, now)
                continue
            if now < c.deadline:
                continue
            if c.state == _LINGERING or c.rejected or (c.state == _WAITING and not c.head_started):
                # done lingering, answered already (an early 413), or idle:
                # close quietly
                self._close(slot)
                continue
            c.cut_body(self.handler)
            self._take_wakes()  # (wakes close nothing)
            var answered = False
            try:
                self._conns[slot].value().http.send_error(408, self._date.current())
                answered = True
            except:
                pass  # a response is under way: just close
            if answered:
                self._serve(slot, now)  # flush the 408; it then closes
            else:
                self._close(slot)

    def _beat(mut self, slot: Int, now: Instant):
        """A heartbeat for a paused event stream: one comment line, which
        clients ignore, then a flush."""
        ref c = self._conns[slot].value()
        c.last_out = now
        var ok = True
        try:
            c.http.send_body(_HEARTBEAT.as_bytes())
        except:
            ok = False
        if ok:
            self._serve(slot, now)
        else:
            self._close(slot)


def _passed_on(e: Errno) -> Bool:
    """A network error accept(2) passes on from the connection it would
    have returned; the queue behind it is fine (accept(2), "Error
    handling")."""
    return (
        e == Errno.EPROTO
        or e == Errno.ENETDOWN
        or e == Errno.ENOPROTOOPT
        or e == Errno.EHOSTDOWN
        or e == Errno.ENONET
        or e == Errno.EHOSTUNREACH
        or e == Errno.EOPNOTSUPP
        or e == Errno.ENETUNREACH
    )
