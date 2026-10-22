"""Echo server on `net.evented` (TcpServer + ConnHandler) for the M2 gate:
the same flags and output lines as `spikes/epoll_echo/server.mojo`, so
`spikes/epoll_echo/client.mojo` and `bench.py` drive it unchanged.

    pixi run mojo build -I src -I bench -I spikes/epoll_echo bench/rt_echo_server.mojo -o bench/out/rt_echo_server
    taskset -c 2 bench/out/rt_echo_server --port 7000 [--stats-ms 500] [--swap] [--backlog 4096]

- The handler is the obvious one: `conn.write(input.readable_span())`
  (copy into the staged output buffer, sent when the callback returns).
  `--swap` hands the received buffer itself to the send instead (zero
  copy).
- Built on `BenchLoop[CountingDriver]` (bench_common.mojo), which counts
  every syscall for the STATS line; `-D BENCH_STOCK_LOOP=1` uses rt's
  `EventLoop` itself (syscall counters then print 0).
- RLIMIT_NOFILE is raised to the hard limit before the loop starts, so the
  loop's fd-table pre-grow covers 10k+ connections.
"""

from std.sys import size_of

from bytes.buffer import ByteBuffer
from linux import IoError, sys
from linux.consts import RLIMIT_NOFILE
from linux.probe import Rlimit, nofile_limit, raise_nofile_limit, set_rlimit
from net.addr import SocketAddr
from net.evented import CloseReason, Conn, ConnHandler, ServerConfig, TcpServer
from rt.core import Loop
from rt.event_loop import EventLoop

from bench_common import (
    STOCK_LOOP,
    AppPtr,
    AppStats,
    BenchLoop,
    CountingDriver,
    Ticker,
)
from echo_util import Args, emit, getpid


struct Echo(ConnHandler, Copyable):
    var app: AppPtr
    var swap_buffers: Bool

    def __init__(out self, app: AppPtr, swap_buffers: Bool):
        self.app = app
        self.swap_buffers = swap_buffers

    def on_open(mut self, mut conn: Conn) raises IoError:
        self.app[].open += 1
        self.app[].accepted += 1

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        var n = input.readable()
        self.app[].bytes_in += n
        self.app[].bytes_out += n
        if self.swap_buffers:
            var b = ByteBuffer()
            swap(b, input)
            conn.send(b^)
        else:
            conn.write(input.readable_span())
            input.clear()

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        self.app[].open -= 1
        self.app[].closes += 1
        if reason.is_error():
            self.app[].resets += 1


def _listen_line(srv: TcpServer[Echo], soft: UInt64, hard: UInt64, swap_buffers: Bool) -> String:
    return String(
        "LISTEN ", srv.local_addr().value(),
        " pid=", getpid(),
        " nofile_soft=", soft,
        " nofile_hard=", hard,
        " server=rt-evented",
        " swap=", swap_buffers,
        " stock_loop=", STOCK_LOOP,
    )


def main() raises:
    var args = Args()
    args.validate(
        ["--host", "--port", "--stats-ms", "--backlog", "--nofile"],
        ["--swap", "--quiet"],
    )
    var host = args.string("--host", "127.0.0.1")
    var port = args.int("--port", 0)
    var stats_ms = args.int("--stats-ms", 1000)
    var backlog = args.int("--backlog", 4096)
    var nofile = args.int("--nofile", 0)
    var swap_buffers = args.flag("--swap")
    var quiet = args.flag("--quiet")

    var lim = nofile_limit()
    var soft: UInt64
    if nofile > 0:
        set_rlimit(RLIMIT_NOFILE, Rlimit(UInt64(nofile), lim.max))
        soft = UInt64(nofile)
    else:
        soft = raise_nofile_limit(lim.max)

    var app = AppStats.zero()
    var ap = Pointer(to=app).unsafe_origin_cast[MutUntrackedOrigin]()
    var addr = SocketAddr.parse(String(host, ":", port))
    var cfg = ServerConfig(backlog=backlog)
    var ticker = Ticker(stats_ms * 1_000_000, ap, quiet)

    comptime if STOCK_LOOP:
        var ev = EventLoop()
        var srv = TcpServer[Echo].listen(ev.loop, addr, Echo(ap, swap_buffers), cfg)
        while not srv.is_listening():
            if srv.error():
                raise Error(srv.error().value())
            ev.run_once(0)
        emit(_listen_line(srv, soft, lim.max, swap_buffers))
        ticker.start(ev.loop)
        ev.run()
        sys.keep_alive(srv)
    else:
        var ev = BenchLoop[CountingDriver]()
        var srv = TcpServer[Echo].listen(ev.loop, addr, Echo(ap, swap_buffers), cfg)
        while not srv.is_listening():
            if srv.error():
                raise Error(srv.error().value())
            ev.run_once(0)
        emit(_listen_line(srv, soft, lim.max, swap_buffers))
        ticker.counts = Pointer(to=ev.driver.n).unsafe_origin_cast[MutUntrackedOrigin]()
        ticker.clock = ev.driver.clock_cell()
        ticker.start(ev.loop)
        ev.run()
        sys.keep_alive(srv)
    sys.keep_alive(ticker)
    sys.keep_alive(app)
