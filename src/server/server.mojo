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
  requests (closed quietly), `read_timeout` without progress while a body
  arrives (408), `write_timeout` without progress while output waits.
- A malformed request is answered with its status (400, 414, 431, 501,
  505) and the connection closes; a handler that raises gets a 500.
- Accepting pauses at `max_connections`, and for 100 ms on EMFILE.
"""

from bytes.buffer import ByteBuffer
from http.connection import EventKind, ServerConnection, ServerEvent
from http.headers import Headers, eq_ignore_case
from http.parse import Limits, RequestHead, ResponseHead
from http.types import Version
from linux import Epoll, ErrorKind, IoError
from linux.abi import EpollEvent
from linux.consts import EPOLLET, EPOLLIN, EPOLLOUT, EPOLLRDHUP
from linux.probe import pregrow_fd_table, raise_nofile_limit
from linux.time import Duration, Instant
from net.addr import SocketAddr
from net.tcp import TcpAccepted, TcpListener, TcpStream

from .date import DateCache

comptime _LISTENER: UInt64 = UInt64.MAX
comptime _PAUSE = Duration.from_millis(100)
comptime _READ_CHUNK = 64 * 1024
comptime _HIGH_WATER = 64 * 1024
"""Output a connection may queue before it stops answering the pipelined
requests it has buffered (backpressure); below it, responses are batched
into one write."""

# connection states
comptime _WAITING = 0
"""Between requests: waiting for (the rest of) a head."""
comptime _BODY = 1
"""A request's head arrived; its body is being read."""


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
    var reuseport: Bool
    """Bind with SO_REUSEPORT, for one server process per core."""
    var server_name: String
    """The Server field of every response; none if empty."""
    var limits: Limits
    """Request head limits (`http.parse.Limits`)."""

    def __init__(
        out self,
        *,
        max_connections: Int = 10000,
        max_body: Int = 1024 * 1024,
        header_timeout: Duration = Duration.from_secs(10),
        idle_timeout: Duration = Duration.from_secs(60),
        read_timeout: Duration = Duration.from_secs(30),
        write_timeout: Duration = Duration.from_secs(30),
        reuseport: Bool = False,
        server_name: StringSlice = "",
        limits: Limits = Limits(),
    ):
        self.max_connections = max_connections
        self.max_body = max_body
        self.header_timeout = header_timeout
        self.idle_timeout = idle_timeout
        self.read_timeout = read_timeout
        self.write_timeout = write_timeout
        self.reuseport = reuseport
        self.server_name = String(server_name)
        self.limits = limits

    def _sweep_every(self) -> Duration:
        """How often timeouts are checked: a quarter of the shortest one,
        at most a second, at least 10 ms."""
        var t = min(
            min(self.header_timeout, self.idle_timeout),
            min(self.read_timeout, self.write_timeout),
        )
        var q = Duration.from_nanos(t.as_nanos() // 4)
        return max(min(q, Duration.from_secs(1)), Duration.from_millis(10))


# ---- requests and responses ------------------------------------------------------------


struct Request(Movable):
    """A whole request, as a handler gets it."""

    var method: String
    var target: String
    """The request target as sent (`/path?query` for most requests)."""
    var version: Version
    var headers: Headers
    var body: List[UInt8]
    var trailers: Headers
    var peer: SocketAddr
    """The client's address."""

    def __init__(out self, peer: SocketAddr):
        self.method = String()
        self.target = String()
        self.version = Version.HTTP_1_1
        self.headers = Headers()
        self.body = List[UInt8]()
        self.trailers = Headers()
        self.peer = peer

    def path(self) -> StringSlice[origin_of(self.target)]:
        """The target up to its query ("?"), for an origin-form target."""
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

    def __init__(out self):
        self.status = 200
        self.reason = String()
        self.headers = Headers()
        self.body = List[UInt8]()

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


trait Handler(Deinitable, Movable):
    """The application: one `handle` call per complete request."""

    def handle(mut self, req: Request, mut res: Response) raises:
        """Fill `res` for `req` (it starts as an empty 200). It must not
        block: the loop serves every connection of the process. An error it
        raises is answered with 500."""
        ...


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

    def __init__(out self, var stream: TcpStream, peer: SocketAddr, config: ServerConfig, now: Instant) raises IoError:
        self.stream = stream^
        self.http = ServerConnection(limits=config.limits)
        self.ev = ServerEvent(EventKind.END)
        self.out = ByteBuffer()
        self.req = Request(peer)
        self.res = Response()
        self.state = _WAITING
        self.first = True
        self.head_started = False
        self.deadline = now + config.header_timeout
        self.blocked = False
        self.write_deadline = now
        self.rejected = False

    def service[H: Handler](
        mut self,
        mut handler: H,
        config: ServerConfig,
        date: DateCache,
        mut chunk: List[UInt8],
        now: Instant,
    ) raises -> Bool:
        """Run the connection until its socket would block: False once it
        is finished (the codec says close, or the peer is gone)."""
        while True:
            if not self.flush(config, now):
                return True  # wait for the next writable edge
            if self.http.should_close():
                return False
            if self.dispatch(handler, config, date, now) or self.http.pending_transmit() > 0:
                continue  # output came (a response, a 100 Continue): flush it first
            var room = min(len(chunk), self.http.feed_capacity())
            if room == 0:
                return True
            var got = self.stream.try_read(Span(chunk)[0:room])
            if not got:
                return True  # wait for the next readable edge
            if got.value() == 0:
                self.http.feed_eof()
            else:
                self.http.feed(Span(chunk)[0 : got.value()])
                if self.state == _WAITING and not self.head_started:
                    self.head_started = True
                    self.deadline = now + config.header_timeout
                elif self.state == _BODY:
                    self.deadline = now + config.read_timeout  # progress

    def flush(mut self, config: ServerConfig, now: Instant) raises IoError -> Bool:
        """Write queued output until the socket would block: False if some
        is still waiting (the write timeout runs from the first stall)."""
        while True:
            if len(self.out) == 0 and self.http.poll_transmit(self.out) == 0:
                self.blocked = False
                return True
            var sent = self.stream.try_write(self.out.readable_span())
            if not sent:
                if not self.blocked:
                    self.blocked = True
                    self.write_deadline = now + config.write_timeout
                return False
            self.out.consume(sent.value())
            self.blocked = False  # progress

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
                var status = self.http.error_status()
                self.http.send_error(status if status >= 400 else 400)
                return True  # the codec now closes after it
            if not got:
                return False
            if self.ev.kind == EventKind.HEAD:
                if self.start(config, date, now):
                    return True  # answered at once (413)
            elif self.ev.kind == EventKind.DATA:
                if self.rejected:
                    continue
                if len(self.req.body) + len(self.ev.data) > config.max_body:
                    self.reject(config, date)
                    return True
                if self.state == _BODY:
                    self.deadline = now + config.read_timeout  # progress
                self.req.body.extend(Span(self.ev.data))
            else:  # END
                var answered = not self.rejected
                if answered:
                    swap(self.req.trailers, self.ev._trailers[0])
                    self.answer(handler, config, date)
                self.state = _WAITING
                self.first = False
                self.head_started = self.http.buffered() > 0
                var t = config.header_timeout if self.head_started else config.idle_timeout
                self.deadline = now + t
                if answered and self.http.pending_transmit() + len(self.out) >= _HIGH_WATER:
                    return True

    def start(mut self, config: ServerConfig, date: DateCache, now: Instant) raises -> Bool:
        """A request head arrived: move it into `req`. True if it was
        answered at once (a body over `max_body`)."""
        ref h = self.ev.head()
        swap(self.req.method, h.method)
        swap(self.req.target, h.target)
        self.req.version = h.version
        swap(self.req.headers, h.headers)
        self.req.body.clear()
        self.req.trailers.clear()
        self.rejected = False
        self.state = _BODY
        self.deadline = now + config.read_timeout
        var length = self.ev.framing.length
        if length > config.max_body:
            self.reject(config, date)
            return True
        if self.req.version.at_least_1_1() and self.req.headers.has_token("expect", "100-continue"):
            self.http.send_continue()
        return False

    def reject(mut self, config: ServerConfig, date: DateCache) raises:
        """Answer 413 before the body ends; its rest is then ignored (the
        codec reads a short one and closes after a long one)."""
        self.rejected = True
        self.res._reset()
        self.res.text(413, "Request body too large\n")
        self.send(config, date)

    def answer[H: Handler](
        mut self, mut handler: H, config: ServerConfig, date: DateCache
    ) raises:
        self.res._reset()
        var failed = False
        try:
            handler.handle(self.req, self.res)
        except:
            failed = True
        if failed:
            self.res._reset()
            self.res.text(500, "Internal Server Error\n")
        self.send(config, date)

    def send(mut self, config: ServerConfig, date: DateCache) raises:
        """Queue `res` with the fields the server adds. If the codec refuses
        the handler's head (an invalid field combination), a 500 goes out
        instead."""
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
        if not bodiless and not has.framing:
            _push_decimal(head.headers, "Content-Length", len(self.res.body))
        var refused = False
        try:
            self.http.send_response(head)
        except:
            refused = True
        if refused:
            var fallback = ResponseHead(500)
            fallback.headers.add("Date", date.current())
            fallback.headers.add("Content-Length", "0")
            self.http.send_response(fallback)
        elif not bodiless:
            self.http.send_body(Span(self.res.body))
        self.http.end_response()
        swap(head.headers, self.res.headers)  # keep the allocation for the next one


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

    def __init__(out self, var handler: Self.H, config: ServerConfig = ServerConfig()) raises IoError:
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

    def bind(mut self, addr: SocketAddr) raises IoError:
        """Listen on `addr` (port 0 picks one: see `local_addr`), with
        SO_REUSEPORT if the configuration asks. Raises the fd limit and
        pre-grows the fd table first (docs/spikes.md)."""
        _ = raise_nofile_limit()
        var l = TcpListener.bind_reuseport(addr) if self.config.reuseport else TcpListener.bind(addr)
        _ = pregrow_fd_table(l)
        self._ep.add(l, UInt32(EPOLLIN | EPOLLET), _LISTENER)
        self._listener = l^

    def local_addr(self) raises IoError -> SocketAddr:
        """The address the listener is bound to."""
        if not self._listener:
            raise IoError.of_kind("Server.local_addr", ErrorKind.NotConnected)
        return self._listener.value().local_addr()

    def connections(self) -> Int:
        """Open connections."""
        return self._live

    def queued_output(self) -> Int:
        """Response bytes produced and not yet taken by the sockets, over
        all connections. Backpressure keeps it to about one response per
        connection whose client is slow to read."""
        var n = 0
        for i in range(len(self._conns)):
            if self._conns[i]:
                ref c = self._conns[i].value()
                n += len(c.out) + c.http.pending_transmit()
        return n

    def run(mut self) raises IoError:
        """Serve until the process ends."""
        while True:
            self.step(Duration.from_secs(1))

    def step(mut self, timeout: Duration) raises IoError:
        """One turn of the loop: wait up to `timeout` for readiness, serve
        what is ready, accept new connections, check timeouts. `run` calls
        it forever; a test or an embedding program can call it itself."""
        if not self._listener:
            raise IoError.of_kind("Server.step", ErrorKind.NotConnected)
        # The wait is timed from the last turn's clock reading: close enough
        # for timeouts, and it saves a syscall (every clock read is one).
        var wait = min(timeout, self._next_sweep - self._now)
        if self._paused_until:
            wait = min(wait, self._paused_until.value() - self._now)
        var n = self._ep.wait(self._events, Optional[Duration](wait))
        var now = Instant.now()
        self._now = now
        self._date.refresh(now)
        var accept_now = False
        for i in range(n):
            var key = self._events[i].data()
            if key == _LISTENER:
                accept_now = True
                continue
            var slot = Int(key)
            if slot >= len(self._conns) or not self._conns[slot]:
                continue  # closed earlier in this batch
            self._serve(slot, now)
        if self._paused_until and now >= self._paused_until.value():
            self._paused_until = None
            accept_now = True  # the edge may have come while paused
        if accept_now or self._backlog:
            self._accept(now)
        if now >= self._next_sweep:
            self._sweep(now)
            self._next_sweep = now + self.config._sweep_every()

    def _serve(mut self, slot: Int, now: Instant):
        var alive: Bool
        try:
            alive = self._conns[slot].value().service(
                self.handler, self.config, self._date, self._chunk, now
            )
        except:
            alive = False  # reset, broken pipe: drop the connection
        if not alive:
            self._close(slot)

    def _close(mut self, slot: Int):
        try:
            self._ep.delete(self._conns[slot].value().stream)
        except:
            pass
        self._conns[slot] = None  # closes the stream
        self._free.append(slot)
        self._live -= 1

    def _accept(mut self, now: Instant):
        self._backlog = False
        while True:
            if self._live >= self.config.max_connections:
                self._backlog = True  # take the rest when one closes
                return
            var acc: Optional[TcpAccepted]
            try:
                acc = self._listener.value().try_accept()
            except e:
                if e.kind == ErrorKind.TooManyFiles:
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
            try:
                self._ep.add(stream, UInt32(EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET), UInt64(slot))
                self._conns[slot] = _Conn(stream^, peer, self.config, now)
                self._live += 1
            except:
                self._free.append(slot)  # (the stream closes here)

    def _sweep(mut self, now: Instant):
        """Apply the timeouts (see the module docs)."""
        for slot in range(len(self._conns)):
            if not self._conns[slot]:
                continue
            ref c = self._conns[slot].value()
            if c.blocked:
                if now >= c.write_deadline:
                    self._close(slot)
                continue
            if now < c.deadline:
                continue
            if c.state == _WAITING and not c.head_started:
                self._close(slot)  # idle: close quietly
                continue
            var answered = False
            try:
                c.http.send_error(408)
                answered = True
            except:
                pass  # a response is under way: just close
            if answered:
                self._serve(slot, now)  # flush the 408; it then closes
            else:
                self._close(slot)
