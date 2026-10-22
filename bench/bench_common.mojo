"""Shared pieces of the M2 benchmark servers (bench/README.md).

- `CountingDriver`: the production `EpollDriver` with a counter per call, so
  syscalls per message are measured exactly, as the M1 spike did (this host
  has no strace or perf). A counter increment is ~1 ns next to a ~5 us
  message; `-D BENCH_STOCK_LOOP=1` builds the servers on rt's own
  `EventLoop` instead, to check that the counting costs nothing.
- `BenchLoop[D]`: `rt.event_loop.EventLoop`'s run loop, generic over the
  driver so it can run on `CountingDriver`. It mirrors event_loop.mojo
  line for line (dispatch rounds, wait computation, one clock read per
  iteration); keep the two in sync.
- `Ticker`: prints the `STATS` line `spikes/epoll_echo/bench.py` parses,
  from a loop timer every `--stats-ms`.

Benchmark code, not library code: it touches `Completion._target`, which
only a run loop may use.
"""

from std.sys import is_defined

from bytes.buffer import ByteBuffer
from linux import IoError, Instant
from linux.abi import RawSockaddr
from linux.errno import Errno
from rt.core import Completion, Loop, Target
from rt.driver import Driver, ReadyEvent
from rt.epoll_driver import EpollDriver
from rt.event_loop import DISPATCH_ROUNDS, NEAR_TIMER_NS, EventLoop

from echo_util import emit

comptime STOCK_LOOP = is_defined["BENCH_STOCK_LOOP"]()
comptime _EAGAIN = -Int(Errno.EAGAIN.value)


@fieldwise_init
struct SysCounts(TrivialRegisterPassable):
    var recvs: Int
    var recv_eagain: Int
    var sends: Int
    var send_eagain: Int
    var send_partial: Int
    var waits: Int
    var events: Int
    var accept_calls: Int
    var ctls: Int
    var closes: Int
    var setsockopts: Int
    var other: Int
    var clock_reads: Int

    @staticmethod
    def zero() -> Self:
        return Self(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    def syscalls(self) -> Int:
        return (
            self.recvs + self.sends + self.waits + self.accept_calls + self.ctls
            + self.closes + self.setsockopts + self.other + self.clock_reads
        )


struct CountingDriver(Driver):
    var inner: EpollDriver
    var n: SysCounts

    def __init__(out self, var inner: EpollDriver):
        self.inner = inner^
        self.n = SysCounts.zero()

    @staticmethod
    def create() raises IoError -> Self:
        return Self(EpollDriver.create())

    @inline(.always)
    def now(self) -> Instant:
        return self.inner.now()  # counted by BenchLoop (self is immutable here)

    def socket(mut self, family: Int, type_: Int) -> Int:
        self.n.other += 1
        return self.inner.socket(family, type_)

    @inline(.always)
    def set_int_option(mut self, fd: Int32, level: Int, name: Int, value: Int32) -> Int:
        self.n.setsockopts += 1
        return self.inner.set_int_option(fd, level, name, value)

    def bind(mut self, fd: Int32, addr: RawSockaddr) -> Int:
        self.n.other += 1
        return self.inner.bind(fd, addr)

    def listen(mut self, fd: Int32, backlog: Int) -> Int:
        self.n.other += 1
        return self.inner.listen(fd, backlog)

    def local_addr(mut self, fd: Int32, mut addr: RawSockaddr) -> Int:
        self.n.other += 1
        return self.inner.local_addr(fd, addr)

    @inline(.always)
    def accept(mut self, fd: Int32, mut peer: RawSockaddr) -> Int:
        self.n.accept_calls += 1
        return self.inner.accept(fd, peer)

    def connect(mut self, fd: Int32, addr: RawSockaddr) -> Int:
        self.n.other += 1
        return self.inner.connect(fd, addr)

    def socket_error(mut self, fd: Int32) -> Int:
        self.n.other += 1
        return self.inner.socket_error(fd)

    @inline(.always)
    def recv(mut self, fd: Int32, mut buf: ByteBuffer) -> Int:
        self.n.recvs += 1
        var r = self.inner.recv(fd, buf)
        if r == _EAGAIN:
            self.n.recv_eagain += 1
        return r

    @inline(.always)
    def send(mut self, fd: Int32, buf: ByteBuffer) -> Int:
        self.n.sends += 1
        var r = self.inner.send(fd, buf)
        if r == _EAGAIN:
            self.n.send_eagain += 1
        elif r >= 0 and r < buf.readable():
            self.n.send_partial += 1
        return r

    def shutdown(mut self, fd: Int32, how: Int) -> Int:
        self.n.other += 1
        return self.inner.shutdown(fd, how)

    @inline(.always)
    def close(mut self, fd: Int32) -> Int:
        self.n.closes += 1
        return self.inner.close(fd)

    @inline(.always)
    def register(mut self, fd: Int32, token: UInt64) -> Int:
        self.n.ctls += 1
        return self.inner.register(fd, token)

    @inline(.always)
    def deregister(mut self, fd: Int32) -> Int:
        self.n.ctls += 1
        return self.inner.deregister(fd)

    def wait(mut self, timeout_ns: Int, mut out: List[ReadyEvent]) raises IoError:
        self.n.waits += 1
        var before = len(out)
        self.inner.wait(timeout_ns, out)
        self.n.events += len(out) - before


struct BenchLoop[D: Driver & Deinitable](Movable):
    """`rt.event_loop.EventLoop` over an explicit driver (see module doc)."""

    var loop: Loop
    var driver: Self.D
    var _events: List[ReadyEvent]
    var clock_reads: Int

    def __init__(out self) raises IoError:
        self.driver = Self.D.create()
        self.loop = Loop(self.driver.now())
        self._events = List[ReadyEvent](capacity=1024)
        self.clock_reads = 1

    def __deinit__(deinit self):
        self.loop.close_all(self.driver)

    def _dispatch(mut self):
        for _ in range(DISPATCH_ROUNDS):
            self.loop.flush(self.driver)
            if not self.loop.has_ready():
                return
            var batch = self.loop.take_ready()
            while len(batch) > 0:
                var c = batch.pop()
                var t = c._target
                t.call(t.ctx, self.loop, c^)

    def run_once(mut self, timeout_ns: Int = -1) raises IoError:
        self._dispatch()
        var wait = timeout_ns
        if (
            self.loop.has_ready()
            or self.loop.has_submitted()
            or self.loop.stopped()
            or self.loop.pending_ops() == 0
        ):
            wait = 0
        else:
            self.loop._prune_timers()
            var next = self.loop.next_timer_ns()
            if next:
                var until = next.value() - self.loop.now().as_nanos()
                if until < NEAR_TIMER_NS:
                    self.clock_reads += 1
                    until = next.value() - self.driver.now().as_nanos()
                until = max(0, until)
                wait = until if wait < 0 else min(wait, until)
        self._events.clear()
        self.driver.wait(wait, self._events)
        self.clock_reads += 1
        self.loop.set_now(self.driver.now())
        for i in range(len(self._events)):
            self.loop.on_ready(self.driver, self._events[i])
        self.loop.expire_timers()
        self._dispatch()

    def run(mut self) raises IoError:
        while not self.loop.stopped() and (
            self.loop.pending_ops() > 0 or self.loop.has_ready()
        ):
            self.run_once()
        self.loop._clear_stop()


@fieldwise_init
struct AppStats(TrivialRegisterPassable):
    """What the servers count themselves (in their callbacks)."""

    var open: Int
    var accepted: Int
    var closes: Int
    var resets: Int
    var bytes_in: Int
    var bytes_out: Int

    @staticmethod
    def zero() -> Self:
        return Self(0, 0, 0, 0, 0, 0)


comptime AppPtr = Pointer[AppStats, MutUntrackedOrigin]
comptime CountsPtr = Pointer[SysCounts, MutUntrackedOrigin]
comptime ClockPtr = Pointer[Int, MutUntrackedOrigin]


def stats_line(
    tag: StaticString, a: AppStats, n: SysCounts, clock_reads: Int
) -> String:
    var c = n
    c.clock_reads = clock_reads
    return String(
        tag,
        " mono_ns=", Instant.now().as_nanos(),
        " open=", a.open,
        " accepted=", a.accepted,
        " closes=", a.closes,
        " resets=", a.resets,
        " waits=", c.waits,
        " events=", c.events,
        " recvs=", c.recvs,
        " recv_eagain=", c.recv_eagain,
        " sends=", c.sends,
        " send_eagain=", c.send_eagain,
        " send_partial=", c.send_partial,
        " accept_calls=", c.accept_calls,
        " ctls=", c.ctls,
        " setsockopts=", c.setsockopts,
        " clock_reads=", c.clock_reads,
        " syscalls=", c.syscalls(),
        " bytes_in=", a.bytes_in,
        " bytes_out=", a.bytes_out,
    )


struct Ticker(Movable):
    """Prints STATS every `period_ns` from a loop timer. The target is built
    once (by `start`) and re-armed from the stored copy."""

    var period_ns: Int
    var app: AppPtr
    var counts: Optional[CountsPtr]
    var clock: Optional[ClockPtr]
    var target: Target
    var quiet: Bool

    def __init__(out self, period_ns: Int, app: AppPtr, quiet: Bool):
        self.period_ns = period_ns
        self.app = app
        self.counts = None
        self.clock = None
        self.target = Target(_on_tick, 0)
        self.quiet = quiet

    def start(mut self, mut lp: Loop):
        self.target = Target(_on_tick, Int(Pointer(to=self)))
        _ = lp.timeout_ns(self.period_ns, self.target)


def _on_tick(ctx: Int, mut lp: Loop, var c: Completion):
    ref t = Pointer[Ticker, MutUntrackedOrigin](unsafe_from_address=ctx)[]
    if not t.quiet:
        var n = SysCounts.zero()
        var clk = 0
        if t.counts:
            n = t.counts.value()[]
        if t.clock:
            clk = t.clock.value()[]
        emit(stats_line("STATS", t.app[], n, clk))
    _ = lp.timeout_ns(t.period_ns, t.target)
