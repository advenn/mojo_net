"""An HTTP/1.1 server answering every request with "Hello, world!": any
number of connections on one thread, with `linux.Epoll` (edge-triggered)
and one sans-I/O `ServerConnection` per connection. For several cores, run
one per core with REUSEPORT=1 on the same address.

    pixi run mojo run -I src examples/http/hello_server.mojo [ADDR] [MAX_CONNS]
    curl -v http://127.0.0.1:8080/

ADDR defaults to 127.0.0.1:8080 (port 0 picks one; the bound address is
printed). MAX_CONNS > 0 exits once that many connections have closed.

The loop follows the readiness-loop rules in docs/net.md (see
examples/net/epoll_echo.mojo). The codec does the HTTP: keep-alive,
pipelining (requests are answered one at a time, in order), request
bodies (read and dropped here), HEAD, Expect: 100-continue, and error
responses for malformed requests. Output that does not fit the socket
waits for the next writable edge, and the connection reads nothing more
until it is flushed. A request blocked behind it stays in the codec's
bounded buffer.
"""

from std.os import getenv
from std.sys import argv, exit, stderr

from bytes.buffer import ByteBuffer
from http.connection import EventKind, ServerConnection, ServerEvent
from http.parse import ResponseHead
from linux import Epoll, ErrorKind, IoError
from linux.abi import EpollEvent
from linux.consts import EPOLLET, EPOLLIN, EPOLLOUT, EPOLLRDHUP
from linux.probe import pregrow_fd_table, raise_nofile_limit
from linux.time import Duration, Instant
from net.addr import SocketAddr
from net.tcp import TcpAccepted, TcpListener, TcpStream

comptime USAGE = "usage: hello_server [ADDR] [MAX_CONNS]"
comptime LISTENER: UInt64 = UInt64.MAX
comptime PAUSE = Duration.from_millis(100)
comptime BODY = "Hello, world!\n"


struct Conn(Movable):
    var stream: TcpStream
    var http: ServerConnection
    var ev: ServerEvent
    """Reused for every event, so a request allocates almost nothing."""
    var out: ByteBuffer
    """Bytes the codec handed out that the socket has not taken yet."""

    def __init__(out self, var stream: TcpStream) raises IoError:
        self.stream = stream^
        self.http = ServerConnection()
        self.ev = ServerEvent(EventKind.END)
        self.out = ByteBuffer()


def respond(mut c: Conn, hello: ResponseHead) raises IoError:
    """Drain the codec's events and answer each complete request."""
    while True:
        var got: Bool
        try:
            got = c.http.poll(c.ev)
        except:
            var status = c.http.error_status()
            c.http.send_error(status if status != 0 else 400)  # then it closes
            return
        if not got:
            return
        if c.ev.kind == EventKind.HEAD:
            if c.ev.head().headers.has_token("expect", "100-continue"):
                c.http.send_continue()
        elif c.ev.kind == EventKind.END:
            c.http.send_response(hello)
            c.http.send_body(BODY.as_bytes())
            c.http.end_response()


def service(mut c: Conn, mut chunk: List[UInt8], hello: ResponseHead) raises IoError -> Bool:
    """Serve until the socket would block; False once the connection is
    finished."""
    while True:
        while True:  # flush first; while output is blocked, read nothing
            if len(c.out) == 0 and c.http.poll_transmit(c.out) == 0:
                break
            var sent = c.stream.try_write(c.out.readable_span())
            if not sent:
                return True  # wait for the next writable edge
            c.out.consume(sent.value())
        if c.http.should_close():
            return False
        var room = min(len(chunk), c.http.feed_capacity())
        if room == 0:
            return True  # the codec holds a request it cannot answer yet
        var got = c.stream.try_read(Span(chunk)[0:room])
        if not got:
            return True  # wait for the next readable edge
        if got.value() == 0:
            c.http.feed_eof()
        else:
            c.http.feed(Span(chunk)[0 : got.value()])
        respond(c, hello)


def parse_addr(text: String) -> Optional[SocketAddr]:
    try:
        return SocketAddr.parse(text)
    except:
        print("bad address '", text, "': expected IP:PORT, for example 127.0.0.1:8080", sep="", file=stderr)
        print(USAGE, file=stderr)
        return None


def main() raises:
    var args = argv()
    var parsed = parse_addr(String(args[1]) if len(args) > 1 else String("127.0.0.1:8080"))
    if not parsed:
        exit(2)
    var addr = parsed.take()
    var max_conns = atol(args[2]) if len(args) > 2 else 0

    var hello = ResponseHead(200)
    hello.headers.add("Content-Type", "text/plain")
    hello.headers.add("Content-Length", String(StringSlice(BODY).byte_length()))

    var fds = raise_nofile_limit()
    var listener = TcpListener.bind_reuseport(addr) if getenv("REUSEPORT") == "1" else TcpListener.bind(addr)
    _ = pregrow_fd_table(listener)
    var ep = Epoll.new()
    ep.add(listener, UInt32(EPOLLIN | EPOLLET), LISTENER)
    print("hello_server listening on", listener.local_addr(), "with up to", fds, "fds")

    var conns = List[Optional[Conn]]()
    var free = List[Int]()
    var chunk = List[UInt8](length=16 * 1024, fill=0)
    var closed = 0
    var paused_until: Optional[Instant] = None
    var events = List[EpollEvent](capacity=1024)
    while max_conns == 0 or closed < max_conns:
        var timeout: Optional[Duration] = None
        if paused_until:
            timeout = paused_until.value() - Instant.now()
        var n = ep.wait(events, timeout)
        var accept_now = False
        if paused_until and Instant.now() >= paused_until.value():
            paused_until = None
            accept_now = True
        for i in range(n):
            var key = events[i].data()
            if key == LISTENER:
                accept_now = True
                continue
            var slot = Int(key)
            var alive: Bool
            try:
                alive = service(conns[slot].value(), chunk, hello)
            except:
                alive = False  # reset, broken pipe: drop the connection
            if not alive:
                ep.delete(conns[slot].value().stream)
                conns[slot] = None  # closes the stream
                free.append(slot)
                closed += 1
        if accept_now and not paused_until:
            while True:
                var acc: Optional[TcpAccepted]
                try:
                    acc = listener.try_accept()
                except e:
                    if e.kind == ErrorKind.TooManyFiles:
                        paused_until = Instant.now() + PAUSE
                        break
                    raise e
                if not acc:
                    break
                var stream = acc.take().into_stream()
                var slot: Int
                if len(free) > 0:
                    slot = free.pop()
                else:
                    slot = len(conns)
                    conns.append(None)
                ep.add(stream, UInt32(EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET), UInt64(slot))
                conns[slot] = Conn(stream^)
    print("hello_server: served", closed, "connections")
