"""User-space cost per echoed message of the rt loop and of rt.evented,
with the kernel taken out: `NullDriver` is a `Driver` whose sockets are
fake and whose "clients" answer every echo instantly. It reproduces the
readiness pattern of the 10k spike at saturation (an edge per message, one
short read, one full send, ~1000 events per wait) without a single syscall,
so the time per message is exactly the loop's own work.

    pixi run mojo build -I src -I bench/rt -I spikes/epoll_echo bench/rt/rt_microbench.mojo -o bench/rt/out/rt_microbench
    bench/rt/out/rt_microbench [--conns 1000] [--msgs 2000000] [--size 64] [--mode raw|evented|both]
        [--thrash BYTES]   # each fake syscall dirties BYTES of a 32 MiB array,
                           # standing in for the kernel's cache footprint

This is how the per-layer user-time numbers in bench/rt/README.md were found
(this host has no perf; perf_event_paranoid is 3).
"""

from linux.abi import Timespec
from linux.time import clock_gettime

from bytes.buffer import ByteBuffer
from linux import Errno, IoError, Instant
from linux.abi import RawSockaddr
from net.addr import SocketAddr
from rt.evented import CloseReason, Conn, ConnHandler, ServerConfig, TcpServer
from rt.core import Completion, FdId, Loop, Target
from rt.driver import READ_READY, WRITE_READY, Driver, ReadyEvent

from bench_common import BenchLoop
from echo_util import Args

comptime _EAGAIN = -Int(Errno.EAGAIN.value)
comptime CLOCK_THREAD_CPUTIME_ID = 3


def thread_cpu_ns() -> Int:
    """This thread's CPU time: time spent descheduled (the host is shared)
    does not count."""
    var ts = Timespec(0, 0)
    _ = clock_gettime(CLOCK_THREAD_CPUTIME_ID, ts)
    return ts.sec * 1_000_000_000 + ts.nsec
comptime _BASE: Int32 = 100
comptime JUNK_BYTES = 32 * 1024 * 1024


struct NullDriver(Driver):
    var now_ns: Int
    var next_fd: Int32
    var to_accept: Int
    var listener: Int32
    var listener_token: UInt64
    var size: Int
    var pending: List[Bool]
    var tokens: List[UInt64]
    var ready: List[Int32]
    var recvs: Int
    var sends: Int
    var waits: Int
    var thrash: Int
    """Bytes of `junk` each fake recv/send writes (64-byte stride), to
    stand in for the kernel's own cache footprint per syscall."""
    var junk: List[UInt8]
    var junk_at: Int

    def __init__(out self):
        self.now_ns = 1_000_000_000
        self.next_fd = _BASE
        self.to_accept = 0
        self.listener = -1
        self.listener_token = 0
        self.size = 64
        self.pending = []
        self.tokens = []
        self.ready = []
        self.recvs = 0
        self.sends = 0
        self.waits = 0
        self.thrash = 0
        self.junk = []
        self.junk_at = 0

    @always_inline
    def _pollute(mut self):
        if self.thrash == 0:
            return
        if len(self.junk) == 0:
            self.junk = List[UInt8](length=JUNK_BYTES, fill=0)
        var p = self.junk.unsafe_ptr()
        var at = self.junk_at
        for i in range(0, self.thrash, 64):
            p[unsafe_offset=(at + i) % JUNK_BYTES] += 1
        self.junk_at = (at + self.thrash) % JUNK_BYTES

    @staticmethod
    def create() raises IoError -> Self:
        return Self()

    def now(self) -> Instant:
        return Instant(nanos=self.now_ns)

    def _new_fd(mut self) -> Int32:
        var fd = self.next_fd
        self.next_fd += 1
        self.pending.append(False)
        self.tokens.append(0)
        return fd

    def socket(mut self, family: Int, type_: Int) -> Int:
        var fd = self._new_fd()
        self.listener = fd
        return Int(fd)

    def set_int_option(mut self, fd: Int32, level: Int, name: Int, value: Int32) -> Int:
        return 0

    def bind(mut self, fd: Int32, addr: RawSockaddr) -> Int:
        return 0

    def listen(mut self, fd: Int32, backlog: Int) -> Int:
        return 0

    def local_addr(mut self, fd: Int32, mut addr: RawSockaddr) -> Int:
        try:
            addr = SocketAddr.parse("127.0.0.1:9").to_raw()
        except:
            pass
        return 0

    def accept(mut self, fd: Int32, mut peer: RawSockaddr) -> Int:
        if self.to_accept == 0:
            return _EAGAIN
        self.to_accept -= 1
        var c = self._new_fd()
        self.pending[Int(c - _BASE)] = True  # the client's first message
        self.ready.append(c)
        return Int(c)

    def connect(mut self, fd: Int32, addr: RawSockaddr) -> Int:
        return -Int(Errno.ENOSYS.value)

    def socket_error(mut self, fd: Int32) -> Int:
        return 0

    @inline(.always)
    def recv(mut self, fd: Int32, mut buf: ByteBuffer) -> Int:
        self.recvs += 1
        self._pollute()
        var i = Int(fd - _BASE)
        if not self.pending[i]:
            return _EAGAIN
        self.pending[i] = False
        var n = min(self.size, buf.writable())
        try:
            buf.commit(n)
        except:
            pass
        return n

    @inline(.always)
    def send(mut self, fd: Int32, buf: ByteBuffer) -> Int:
        self.sends += 1
        self._pollute()
        # The client reads the echo and answers at once: the next wait
        # reports a read edge for this fd.
        self.pending[Int(fd - _BASE)] = True
        self.ready.append(fd)
        return buf.readable()

    def shutdown(mut self, fd: Int32, how: Int) -> Int:
        return 0

    def close(mut self, fd: Int32) -> Int:
        return 0

    def register(mut self, fd: Int32, token: UInt64) -> Int:
        self.tokens[Int(fd - _BASE)] = token
        if fd == self.listener:
            self.listener_token = token
        return 0

    def deregister(mut self, fd: Int32) -> Int:
        return 0

    def wait(mut self, timeout_ns: Int, mut out: List[ReadyEvent]) raises IoError:
        self.waits += 1
        self.now_ns += 1000
        if self.to_accept > 0:
            out.append(ReadyEvent(self.listener_token, READ_READY))
        var n = min(len(self.ready), 1024)
        for i in range(n):
            var fd = self.ready[i]
            out.append(ReadyEvent(self.tokens[Int(fd - _BASE)], READ_READY | WRITE_READY))
        if n == len(self.ready):
            self.ready.clear()
        else:
            var rest = List[Int32](capacity=len(self.ready) - n)
            for i in range(n, len(self.ready)):
                rest.append(self.ready[i])
            self.ready = rest^


# ---- raw rt echo (as bench/rt/rt_raw_echo_server.mojo) ----------------------------


struct Raw(Movable):
    var msgs: Int
    var t_accept: Target
    var t_recv: Target
    var t_sent: Target

    def __init__(out self):
        self.msgs = 0
        self.t_accept = Target(on_accept, 0)
        self.t_recv = Target(on_recv, 0)
        self.t_sent = Target(on_sent, 0)

    def bind_targets(mut self):
        var ctx = Int(Pointer(to=self))
        self.t_accept = Target(on_accept, ctx)
        self.t_recv = Target(on_recv, ctx)
        self.t_sent = Target(on_sent, ctx)


@always_inline
def _st(ctx: Int) -> ref[MutUntrackedOrigin] Raw:
    return Pointer[Raw, MutUntrackedOrigin](unsafe_from_address=ctx)[]


def on_listen(ctx: Int, mut lp: Loop, var c: Completion):
    _ = lp.accept(c.fd, _st(ctx).t_accept)


def on_accept(ctx: Int, mut lp: Loop, var c: Completion):
    if c.ok():
        _ = lp.recv(c.fd, _st(ctx).t_recv)


def on_recv(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    if c.res > 0:
        s.msgs += 1
        _ = lp.send(c.fd, c.take_buf(), s.t_sent)
        _ = lp.recv(c.fd, s.t_recv)


def on_sent(ctx: Int, mut lp: Loop, var c: Completion):
    if c.has_buf():
        lp.recycle(c.take_buf())


# ---- rt.evented echo ----------------------------------------------------------


struct Echo(ConnHandler, Copyable):
    var msgs: Pointer[Int, MutUntrackedOrigin]

    def __init__(out self, msgs: Pointer[Int, MutUntrackedOrigin]):
        self.msgs = msgs

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        self.msgs[] += 1
        conn.write(input.readable_span())
        input.clear()


def bench_raw(conns: Int, msgs: Int, size: Int, thrash: Int) raises -> Float64:
    var ev = BenchLoop[NullDriver]()
    ev.driver.thrash = thrash
    ev.driver.to_accept = conns
    ev.driver.size = size
    var raw = Raw()
    raw.bind_targets()
    _ = ev.loop.listen(SocketAddr.parse("127.0.0.1:0").to_raw(), Target(on_listen, Int(Pointer(to=raw))))
    while raw.msgs < conns:  # warm up: every connection accepted and echoing
        ev.run_once(0)
    var m0 = raw.msgs
    var t0 = thread_cpu_ns()
    while raw.msgs - m0 < msgs:
        ev.run_once(0)
    var dt = thread_cpu_ns() - t0
    var n = raw.msgs - m0
    print(
        "raw     ", n, "msgs", Float64(dt) / Float64(n), "ns/msg",
        " events/wait", Float64(n) / Float64(ev.driver.waits),
    )
    return Float64(dt) / Float64(n)


def bench_evented(conns: Int, msgs: Int, size: Int, thrash: Int) raises -> Float64:
    var ev = BenchLoop[NullDriver]()
    ev.driver.thrash = thrash
    ev.driver.to_accept = conns
    ev.driver.size = size
    var count = 0
    var cp = Pointer(to=count).unsafe_origin_cast[MutUntrackedOrigin]()
    var srv = TcpServer[Echo].listen(ev.loop, SocketAddr.parse("127.0.0.1:0"), Echo(cp))
    while count < conns:
        ev.run_once(0)
    var m0 = count
    var t0 = thread_cpu_ns()
    while count - m0 < msgs:
        ev.run_once(0)
    var dt = thread_cpu_ns() - t0
    var n = count - m0
    print("evented ", n, "msgs", Float64(dt) / Float64(n), "ns/msg", " conns", srv.connections())
    return Float64(dt) / Float64(n)


def main() raises:
    var args = Args()
    args.validate(["--conns", "--msgs", "--size", "--mode", "--reps", "--thrash"], [])
    var conns = args.int("--conns", 1000)
    var msgs = args.int("--msgs", 2_000_000)
    var size = args.int("--size", 64)
    var reps = args.int("--reps", 3)
    var mode = args.string("--mode", "both")
    var thrash = args.int("--thrash", 0)
    var best_raw = Float64.MAX
    var best_ev = Float64.MAX
    for _ in range(reps):
        if mode == "raw" or mode == "both":
            best_raw = min(best_raw, bench_raw(conns, msgs, size, thrash))
        if mode == "evented" or mode == "both":
            best_ev = min(best_ev, bench_evented(conns, msgs, size, thrash))
    print("BEST raw", best_raw, "evented", best_ev, "ns/msg (thread CPU time, min of", reps, ")")
