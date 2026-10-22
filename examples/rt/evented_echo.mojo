"""Evented TCP echo server on `rt.evented`: any number of concurrent
connections on one thread (compare examples/net/echo_server.mojo, the blocking
one-at-a-time version).

    pixi run mojo run -I src examples/rt/evented_echo.mojo [ADDR] [MAX_CONNS]

ADDR defaults to 127.0.0.1:7878 (port 0 picks a free one; the bound address
is printed). MAX_CONNS > 0 starts a graceful shutdown once that many
connections have closed (handy for scripted demos); the default 0 serves
forever.

What the library does for this handler:
- one receive per readiness edge into a pooled buffer, lent to `on_data`;
- the echo is staged (`conn.write`) and sent as one send when the callback
  returns;
- backpressure: a client that sends without reading makes the write queue
  pass the high-water mark, so reading pauses until it drains, and TCP
  flow control pushes back on the client;
- idle connections are closed after 30 s (one lazily re-armed timer per
  connection, not one per read);
- shutdown stops accepting, closes idle connections and lets busy ones
  finish their current echo.

Try it: `nc 127.0.0.1 7878`, or many at once with
`spikes/epoll_echo/out/client --port 7878 --active 100 --duration 5`.
"""

from std.sys import argv, exit, stderr

from bytes.buffer import ByteBuffer
from linux import IoError
from net.addr import SocketAddr
from rt.evented import CloseReason, Conn, ConnConfig, ConnHandler, ServerConfig, TcpServer
from rt.core import Loop
from rt.event_loop import EventLoop

comptime IDLE_NS = 30 * 1_000_000_000


struct Closed(Movable):
    var count: Int

    def __init__(out self):
        self.count = 0


struct Echo(ConnHandler, Copyable):
    """One copy per connection. State shared by all of them goes through a
    pointer to something that outlives the server (here: `Closed` in
    main)."""

    var closed: Pointer[Closed, MutUntrackedOrigin]

    def __init__(out self, closed: Pointer[Closed, MutUntrackedOrigin]):
        self.closed = closed

    def on_open(mut self, mut conn: Conn) raises IoError:
        var peer = conn.peer_addr()
        if peer:
            print("open", peer.value())

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        conn.write(input.readable_span())
        input.clear()

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        self.closed[].count += 1
        print("close", reason)


comptime USAGE = "usage: evented_echo [ADDR] [MAX_CONNS]"


def parse_addr(text: String) -> Optional[SocketAddr]:
    """ADDR from the command line: a numeric IP:PORT. A bad one is a usage
    error, explained on stderr (None: the caller exits 2)."""
    try:
        return SocketAddr.parse(text)
    except:
        print("bad address '", text, "': expected IP:PORT, for example 127.0.0.1:7878 or [::1]:7878", sep="", file=stderr)
        print("(numeric addresses only: host names such as localhost are not resolved yet, so use 127.0.0.1)", file=stderr)
        print(USAGE, file=stderr)
        return None


def main() raises:
    var args = argv()
    var parsed = parse_addr(String(args[1]) if len(args) > 1 else String("127.0.0.1:7878"))
    if not parsed:
        exit(2)
    var addr = parsed.take()
    var max_conns = atol(args[2]) if len(args) > 2 else 0

    var closed = Closed()
    var cp = Pointer(to=closed).unsafe_origin_cast[MutUntrackedOrigin]()
    var ev = EventLoop()
    var srv = TcpServer[Echo].listen(
        ev.loop, addr, Echo(cp), ServerConfig(conn=ConnConfig(idle_timeout_ns=IDLE_NS))
    )
    while not srv.is_listening():
        if srv.error():
            raise Error("listen failed: ", srv.error().value())
        ev.run_once(0)
    print("evented_echo listening on", srv.local_addr().value())
    var shutting_down = False
    while not srv.is_closed():
        ev.run_once(100 * 1_000_000)
        if max_conns > 0 and closed.count >= max_conns and not shutting_down:
            print("served", closed.count, "connections; shutting down")
            srv.shutdown(ev.loop, 5 * 1_000_000_000)
            shutting_down = True
    print("stats:", srv.stats())
