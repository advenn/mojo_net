"""Shared pieces of the M2 benchmark servers (bench/rt/README.md).

- `CountingDriver`: the production `EpollDriver` with a counter per call, so
  syscalls per message are measured exactly, as the M1 spike did (this host
  has no strace or perf). A counter increment is ~1 ns next to a ~5 us
  message; `-D BENCH_STOCK_LOOP=1` builds the servers on rt's own
  `EventLoop` instead, to check that the counting costs nothing.
- `BenchLoop[D]`: rt's own run loop (`rt.event_loop.EventLoopOf[D]`) over
  driver `D`, so the benchmarks measure exactly the code that ships.
  `CountingDriver` counts clock reads in a heap cell (`clock_cell()`),
  because `Driver.now` takes `self` immutably.
- `Ticker`: prints the `STATS` line `spikes/epoll_echo/bench.py` parses,
  from a loop timer every `--stats-ms`.

Benchmark code, not library code: it touches `Completion._target`, which
only a run loop may use.
"""

from std.memory.alloc import unsafe_alloc
from std.sys import is_defined

from bytes.buffer import ByteBuffer
from linux import IoError, Instant
from linux.abi import RawSockaddr
from linux.errno import Errno
from rt.core import Completion, Loop, Target
from rt.driver import Driver, ReadyEvent
from rt.epoll_driver import EpollDriver
from rt.event_loop import EventLoop, EventLoopOf

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
    var _clock: Pointer[Int, MutUntrackedOrigin]
    """Clock reads, in its own heap cell: `now(self)` is immutable."""

    def __init__(out self, var inner: EpollDriver):
        self.inner = inner^
        self.n = SysCounts.zero()
        self._clock = unsafe_alloc[Int](1)
        self._clock[] = 0

    def __deinit__(deinit self):
        self._clock.unsafe_free()

    @inline(.always)
    def clock_cell(self) -> Pointer[Int, MutUntrackedOrigin]:
        return self._clock

    @staticmethod
    def create() raises IoError -> Self:
        return Self(EpollDriver.create())

    @inline(.always)
    def now(self) -> Instant:
        self._clock[] += 1
        return self.inner.now()

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


comptime BenchLoop[D: Driver] = EventLoopOf[D]
"""rt's own run loop over driver `D` (no copy to keep in sync)."""


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
