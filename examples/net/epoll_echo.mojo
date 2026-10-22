"""Readiness-loop echo server: any number of connections on one thread with
`linux.Epoll` (edge-triggered) and the nonblocking `try_*` calls, without
a runtime. For several cores, run one per core with REUSEPORT=1 on the same
address (the kernel spreads connections across them).

    pixi run mojo run -I src examples/net/epoll_echo.mojo [ADDR] [MAX_CONNS]
    REUSEPORT=1 pixi run mojo run -I src examples/net/epoll_echo.mojo 127.0.0.1:7878

ADDR defaults to 127.0.0.1:7878 (port 0 picks one; the bound address is
printed). MAX_CONNS > 0 exits once that many connections have closed.

It follows the rules for readiness-loop servers in docs/net.md:
- every socket is registered once, edge-triggered, for input and output;
- accept, read and write each loop until they return None (an edge is
  reported once);
- output that does not fit waits for the next writable edge, and reading
  stops while output is pending, so a client that does not read cannot
  make the server buffer without limit;
- the fd limit is raised and the fd table pre-grown at startup; on EMFILE
  accepting pauses for 100 ms instead of spinning on the listener.
"""

from std.os import getenv
from std.sys import argv, exit, stderr

from bytes.buffer import ByteBuffer
from linux import Epoll, ErrorKind, IoError
from linux.abi import EpollEvent
from linux.consts import EPOLLET, EPOLLIN, EPOLLOUT, EPOLLRDHUP
from linux.probe import pregrow_fd_table, raise_nofile_limit
from linux.time import Duration, Instant
from net.addr import SocketAddr
from net.tcp import TcpAccepted, TcpListener, TcpStream

comptime USAGE = "usage: epoll_echo [ADDR] [MAX_CONNS]"
comptime LISTENER: UInt64 = UInt64.MAX
comptime MAX_PENDING = 1024 * 1024
comptime PAUSE = Duration.from_millis(100)


struct Conn(Movable):
    var stream: TcpStream
    var out: ByteBuffer
    """Bytes read and not yet echoed."""

    def __init__(out self, var stream: TcpStream):
        self.stream = stream^
        self.out = ByteBuffer()


def parse_addr(text: String) -> Optional[SocketAddr]:
    try:
        return SocketAddr.parse(text)
    except:
        print("bad address '", text, "': expected IP:PORT, for example 127.0.0.1:7878 or [::1]:7878", sep="", file=stderr)
        print("(a server binds an IP address: for localhost use 127.0.0.1 or [::1])", file=stderr)
        print(USAGE, file=stderr)
        return None


def service(mut c: Conn) raises IoError -> Bool:
    """Echo until the socket would block; False once the connection is
    finished (EOF or an error)."""
    var chunk = List[UInt8](length=16 * 1024, fill=0)
    while True:
        # Flush pending output first; while it is blocked, read nothing.
        while len(c.out) > 0:
            var sent = c.stream.try_write(c.out.readable_span())
            if not sent:
                return True  # wait for the next writable edge
            c.out.consume(sent.value())
        if len(c.out) >= MAX_PENDING:
            return True
        var got = c.stream.try_read(Span(chunk))
        if not got:
            return True  # wait for the next readable edge
        if got.value() == 0:
            return False  # EOF
        c.out.write_bytes(Span(chunk)[0 : got.value()])


def main() raises:
    var args = argv()
    var parsed = parse_addr(String(args[1]) if len(args) > 1 else String("127.0.0.1:7878"))
    if not parsed:
        exit(2)
    var addr = parsed.take()
    var max_conns = atol(args[2]) if len(args) > 2 else 0

    var fds = raise_nofile_limit()
    var listener = TcpListener.bind_reuseport(addr) if getenv("REUSEPORT") == "1" else TcpListener.bind(addr)
    _ = pregrow_fd_table(listener)  # 65536 slots: plenty, and no more
    var ep = Epoll.new()
    ep.add(listener, UInt32(EPOLLIN | EPOLLET), LISTENER)
    print("epoll_echo listening on", listener.local_addr(), "with up to", fds, "fds")

    var conns = List[Optional[Conn]]()
    var free = List[Int]()
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
            accept_now = True  # the edge may have come while paused
        for i in range(n):
            var key = events[i].data()
            if key == LISTENER:
                accept_now = True
                continue
            var slot = Int(key)
            var alive: Bool
            try:
                alive = service(conns[slot].value())
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
    print("epoll_echo: served", closed, "connections")
