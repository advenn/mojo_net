"""Echo server directly on the raw `rt` API (no `net.evented`): listen,
multishot accept, recv -> send the same buffer back -> recv again. It has no
per-connection state at all (the completion's `c.fd` is the connection),
so the gap between this server and `rt_echo_server` is what `net.evented`
costs, and the gap between this one and `spikes/epoll_echo/server.mojo` is
what the rt completion layer costs. Same flags and output as the spike
server.

    pixi run mojo build -I src -I bench -I spikes/epoll_echo bench/rt_raw_echo_server.mojo -o bench/out/rt_raw_echo_server
"""

from linux import IoError, sys
from linux.consts import RLIMIT_NOFILE
from linux.probe import Rlimit, nofile_limit, raise_nofile_limit, set_rlimit
from net.addr import SocketAddr
from rt.core import Completion, FdId, Loop, Target
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


struct Raw(Movable):
    var app: AppPtr
    var listener: FdId
    var failed: Int
    var t_accept: Target
    var t_recv: Target
    var t_sent: Target
    var t_closed: Target

    def __init__(out self, app: AppPtr):
        self.app = app
        self.listener = FdId.null()
        self.failed = 0
        self.t_accept = Target(on_accept, 0)
        self.t_recv = Target(on_recv, 0)
        self.t_sent = Target(on_sent, 0)
        self.t_closed = Target(on_closed, 0)

    def bind_targets(mut self):
        var ctx = Int(Pointer(to=self))
        self.t_accept = Target(on_accept, ctx)
        self.t_recv = Target(on_recv, ctx)
        self.t_sent = Target(on_sent, ctx)
        self.t_closed = Target(on_closed, ctx)


@always_inline
def _st(ctx: Int) -> ref[MutUntrackedOrigin] Raw:
    return Pointer[Raw, MutUntrackedOrigin](unsafe_from_address=ctx)[]


def on_listen(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    if not c.ok():
        s.failed = c.res
        lp.stop()
        return
    s.listener = c.fd
    _ = lp.accept(c.fd, s.t_accept)


def on_accept(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    if not c.ok():
        return
    s.app[].open += 1
    s.app[].accepted += 1
    _ = lp.recv(c.fd, s.t_recv)


def on_recv(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    if c.res > 0:
        s.app[].bytes_in += c.res
        _ = lp.send(c.fd, c.take_buf(), s.t_sent)
        _ = lp.recv(c.fd, s.t_recv)
        return
    if c.res < 0 and not c.canceled():
        s.app[].resets += 1
    if c.has_buf():
        lp.recycle(c.take_buf())
    if not c.canceled():
        _ = lp.close(c.fd, s.t_closed)


def on_sent(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    if c.res > 0:
        s.app[].bytes_out += c.res
    if c.has_buf():
        lp.recycle(c.take_buf())


def on_closed(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.app[].open -= 1
    s.app[].closes += 1


def main() raises:
    var args = Args()
    args.validate(
        ["--host", "--port", "--stats-ms", "--backlog", "--nofile"], ["--quiet"]
    )
    var host = args.string("--host", "127.0.0.1")
    var port = args.int("--port", 0)
    var stats_ms = args.int("--stats-ms", 1000)
    var backlog = args.int("--backlog", 4096)
    var nofile = args.int("--nofile", 0)
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
    var raw = Raw(ap)
    raw.bind_targets()
    var ctx = Int(Pointer(to=raw))
    var addr = SocketAddr.parse(String(host, ":", port)).to_raw()
    var ticker = Ticker(stats_ms * 1_000_000, ap, quiet)

    comptime if STOCK_LOOP:
        var ev = EventLoop()
        _ = ev.loop.listen(addr, Target(on_listen, ctx), backlog=backlog)
        while raw.listener.is_null() and raw.failed == 0:
            ev.run_once(0)
        if raw.failed != 0:
            raise Error("listen failed: ", raw.failed)
        var local = SocketAddr.from_raw(ev.loop.local_addr(raw.listener).value())
        emit(String("LISTEN ", local, " pid=", getpid(), " nofile_soft=", soft, " server=rt-raw stock_loop=True"))
        ticker.start(ev.loop)
        ev.run()
    else:
        var ev = BenchLoop[CountingDriver]()
        _ = ev.loop.listen(addr, Target(on_listen, ctx), backlog=backlog)
        while raw.listener.is_null() and raw.failed == 0:
            ev.run_once(0)
        if raw.failed != 0:
            raise Error("listen failed: ", raw.failed)
        var local = SocketAddr.from_raw(ev.loop.local_addr(raw.listener).value())
        emit(String("LISTEN ", local, " pid=", getpid(), " nofile_soft=", soft, " server=rt-raw stock_loop=False"))
        ticker.counts = Pointer(to=ev.driver.n).unsafe_origin_cast[MutUntrackedOrigin]()
        ticker.clock = ev.driver.clock_cell()
        ticker.start(ev.loop)
        ev.run()
    sys.keep_alive(ticker)
    sys.keep_alive(raw)
    sys.keep_alive(app)
