"""Many concurrent echo transfers through the event loop on the simulated
network, with faults: byte-stream integrity, no stalls, exactly-once
completions, and bit-for-bit replay of the same seed.

Each transfer: a client connects, sends `size` pattern bytes in random
chunks (at most two sends outstanding), shuts down its write side, and
checks that the echo it reads back is exactly what it sent. The server
echoes every received chunk (recv -> send -> recv) and closes at EOF. A
virtual 60 s deadline per transfer gives up on connects that never complete
(dropped SYNs); hitting it in any other phase is a stall, i.e. a lost edge.

Built only with -D MOJO_TCP_SIM=1. `MOJO_TCP_SIM_SEED=<n>` picks the seed of
the big runs (printed in their summary line) to explore or replay."""

from std.collections import Dict
from std.sys import is_defined
from std.testing import TestSuite, assert_equal, assert_true

from bytes.buffer import ByteBuffer
from linux import Errno, Instant
from linux.abi import RawSockaddr
from linux.consts import SHUT_WR
from net.addr import Ipv4Addr, SocketAddr
from rt.core import Completion, FdId, Loop, OpId, Target
from rt.event_loop import EventLoop
from rt.sim import FAULT_KINDS, SimConfig, SimDriver, SimFaults, fault_name

comptime ECANCELED = -Int(Errno.ECANCELED.value)
comptime DEADLINE_NS = 60_000_000_000
comptime MAX_CHUNK = 64 * 1024

comptime P_CONNECTING = 1
comptime P_RUNNING = 2
comptime P_CLOSING = 3
comptime P_DONE = 4

comptime R_NONE = 0
comptime R_OK = 1
comptime R_FAILED = 2
comptime R_GAVE_UP = 3


@always_inline
def sim(mut ev: EventLoop) -> ref[ev.driver] SimDriver:
    return rebind[SimDriver](ev.driver)


@always_inline
def mix64(mut x: UInt64) -> UInt64:
    x += 0x9E3779B97F4A7C15
    var z = x
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
    z = (z ^ (z >> 27)) * 0x94D049BB133111EB
    return z ^ (z >> 31)


@always_inline
def pattern(id: Int, off: Int) -> UInt8:
    """Byte `off` of transfer `id`: depends on every bit of the offset, so a
    lost, duplicated or reordered chunk is detected."""
    var x = (
        UInt64(off) * 0x9E3779B97F4A7C15 ^ UInt64(id + 1) * 0xC2B2AE3D27D4EB4F
    )
    x ^= x >> 32
    x ^= x >> 13
    return UInt8(x & 0xFF)


@fieldwise_init
struct Client(Copyable, Movable):
    var size: Int
    var sent: Int
    var acked: Int
    var got: Int
    var fd: FdId
    var connect_op: OpId
    var timer_op: OpId
    var phase: Int
    var result: Int
    var err: Int
    var sends: Int
    var shut: Bool
    var bad: Bool
    var stalled: Bool
    var timer_done: Bool
    var counted: Bool
    var rng: UInt64
    var inflight: List[Int]
    """Sizes of the outstanding sends, oldest first."""


struct World(Movable):
    var clients: List[Client]
    var servers: List[FdId]
    var listener: FdId
    var addr: RawSockaddr
    var t: List[Target]
    var next: Int
    var finished: Int
    var concurrency: Int
    var server_bytes: Int
    var log_hash: UInt64
    var log_count: Int
    var finals: Dict[UInt64, Int]
    var dup_completions: Int
    var unexpected: List[String]

    def __init__(
        out self, n: Int, concurrency: Int, max_size: Int, seed: UInt64
    ):
        self.clients = []
        var r = seed ^ 0xA5A5_5A5A_1234_4321
        for i in range(n):
            var size = Int(mix64(r) % UInt64(max_size + 1))
            if i % 17 == 0:
                size = Int(mix64(r) % 64)  # some tiny ones, including 0
            self.clients.append(
                Client(
                    size,
                    0,
                    0,
                    0,
                    FdId.null(),
                    OpId.null(),
                    OpId.null(),
                    0,
                    R_NONE,
                    0,
                    0,
                    False,
                    False,
                    False,
                    False,
                    False,
                    mix64(r),
                    [],
                )
            )
        self.servers = []
        self.listener = FdId.null()
        self.addr = RawSockaddr()
        self.t = []
        self.next = 0
        self.finished = 0
        self.concurrency = concurrency
        self.server_bytes = 0
        self.log_hash = 0xCBF29CE484222325
        self.log_count = 0
        self.finals = Dict[UInt64, Int]()
        self.dup_completions = 0
        self.unexpected = []


@always_inline
def _w(ctx: Int) -> ref[MutUntrackedOrigin] World:
    return Pointer[World, MutUntrackedOrigin](unsafe_from_address=ctx)[]


def note(mut w: World, lp: Loop, c: Completion):
    """Fold the completion into the log hash and check exactly-once."""
    var words = [
        UInt64(c.kind.v),
        c.tag,
        UInt64(c.res),
        UInt64(Int(c.more)),
        UInt64(lp.now().as_nanos()),
    ]
    for i in range(len(words)):
        w.log_hash = (w.log_hash ^ words[i]) * 0x100000001B3
        w.log_hash ^= w.log_hash >> 29
    w.log_count += 1
    if not c.more:
        var k = c.op.raw
        if k in w.finals:
            w.dup_completions += 1
        else:
            w.finals[k] = 1


comptime T_ACCEPT = 0
comptime T_SRECV = 1
comptime T_SSENT = 2
comptime T_SCLOSED = 3
comptime T_CONNECT = 4
comptime T_CSENT = 5
comptime T_CRECV = 6
comptime T_CSHUT = 7
comptime T_CCLOSED = 8
comptime T_TIMER = 9
comptime T_CANCEL = 10
comptime T_LCLOSED = 11


def start_client(mut w: World, mut lp: Loop, i: Int):
    var tag = UInt64(i)
    w.clients[i].phase = P_CONNECTING
    w.clients[i].connect_op = lp.connect(w.addr, w.t[T_CONNECT], tag)
    w.clients[i].timer_op = lp.timeout_ns(DEADLINE_NS, w.t[T_TIMER], tag)


def start_more(mut w: World, mut lp: Loop):
    var active = w.next - w.finished
    while w.next < len(w.clients) and active < w.concurrency:
        start_client(w, lp, w.next)
        w.next += 1
        active += 1


def finish_check(mut w: World, mut lp: Loop, i: Int):
    ref cl = w.clients[i]
    if cl.phase != P_DONE or not cl.timer_done or cl.counted:
        return
    cl.counted = True
    w.finished += 1
    start_more(w, lp)
    if w.finished == len(w.clients):
        _ = lp.close(w.listener, w.t[T_LCLOSED])


def chunk(id: Int, off: Int, n: Int) -> ByteBuffer:
    var b = ByteBuffer()
    try:
        b = ByteBuffer(capacity=n)
        var sp = b.writable_span()
        for k in range(n):
            sp[k] = pattern(id, off + k)
        b.commit(n)
    except:
        pass
    return b^


def fill(mut w: World, mut lp: Loop, i: Int):
    while (
        w.clients[i].phase == P_RUNNING
        and w.clients[i].sends < 2
        and w.clients[i].sent < w.clients[i].size
    ):
        var r = mix64(w.clients[i].rng)
        var cap = MAX_CHUNK
        if r % 4 == 0:
            cap = 64
        elif r % 4 == 1:
            cap = 4096
        var n = min(
            w.clients[i].size - w.clients[i].sent,
            1 + Int((r >> 8) % UInt64(cap)),
        )
        var b = chunk(i, w.clients[i].sent, n)
        w.clients[i].sent += n
        w.clients[i].sends += 1
        w.clients[i].inflight.append(n)
        _ = lp.send(w.clients[i].fd, b^, w.t[T_CSENT], UInt64(i))
    if (
        w.clients[i].phase == P_RUNNING
        and not w.clients[i].shut
        and w.clients[i].acked == w.clients[i].size
    ):
        w.clients[i].shut = True
        _ = lp.shutdown(w.clients[i].fd, SHUT_WR, w.t[T_CSHUT], UInt64(i))


def close_client(mut w: World, mut lp: Loop, i: Int, result: Int, err: Int):
    if w.clients[i].phase != P_RUNNING:
        return
    w.clients[i].phase = P_CLOSING
    w.clients[i].result = result
    w.clients[i].err = err
    _ = lp.close(w.clients[i].fd, w.t[T_CCLOSED], UInt64(i))


# ---- server ---------------------------------------------------------------------


def on_listen(ctx: Int, mut lp: Loop, var c: Completion):
    ref w = _w(ctx)
    note(w, lp, c)
    if not c.ok():
        w.unexpected.append("listen " + String(c.res))
        return
    w.listener = c.fd
    w.addr = lp.local_addr(c.fd).value().copy()
    _ = lp.accept(c.fd, w.t[T_ACCEPT])
    start_more(w, lp)


def on_accept(ctx: Int, mut lp: Loop, var c: Completion):
    ref w = _w(ctx)
    note(w, lp, c)
    if not c.ok():
        if c.res != ECANCELED:
            w.unexpected.append("accept " + String(c.res))
        return
    var tag = UInt64(len(w.servers))
    w.servers.append(c.fd)
    _ = lp.recv(c.fd, w.t[T_SRECV], tag)


def on_srecv(ctx: Int, mut lp: Loop, var c: Completion):
    ref w = _w(ctx)
    note(w, lp, c)
    if c.res > 0:
        w.server_bytes += c.res
        _ = lp.send(c.fd, c.buf.take(), w.t[T_SSENT], c.tag)
        return
    if c.res != ECANCELED:
        _ = lp.close(c.fd, w.t[T_SCLOSED], c.tag)  # EOF or reset


def on_ssent(ctx: Int, mut lp: Loop, var c: Completion):
    ref w = _w(ctx)
    note(w, lp, c)
    if c.buf:
        lp.recycle(c.buf.take())
    if c.res >= 0:
        _ = lp.recv(c.fd, w.t[T_SRECV], c.tag)
    elif c.res != ECANCELED:
        _ = lp.close(c.fd, w.t[T_SCLOSED], c.tag)


def on_sclosed(ctx: Int, mut lp: Loop, var c: Completion):
    note(_w(ctx), lp, c)


def on_lclosed(ctx: Int, mut lp: Loop, var c: Completion):
    note(_w(ctx), lp, c)


# ---- client ---------------------------------------------------------------------


def on_connect(ctx: Int, mut lp: Loop, var c: Completion):
    ref w = _w(ctx)
    note(w, lp, c)
    var i = Int(c.tag)
    if not c.ok():
        w.clients[i].phase = P_DONE
        if w.clients[i].result == R_NONE:
            w.clients[i].result = R_FAILED
            w.clients[i].err = c.res
        if not w.clients[i].timer_done:
            _ = lp.cancel(w.clients[i].timer_op, w.t[T_CANCEL], c.tag)
        finish_check(w, lp, i)
        return
    w.clients[i].fd = c.fd
    w.clients[i].phase = P_RUNNING
    _ = lp.recv(c.fd, w.t[T_CRECV], c.tag)
    fill(w, lp, i)


def on_csent(ctx: Int, mut lp: Loop, var c: Completion):
    ref w = _w(ctx)
    note(w, lp, c)
    var i = Int(c.tag)
    w.clients[i].sends -= 1
    # Sends complete FIFO, each with its whole buffer written and handed back.
    var expect = w.clients[i].inflight.pop(0)
    if c.res >= 0 and c.res != expect:
        w.unexpected.append(
            "send "
            + String(i)
            + " res "
            + String(c.res)
            + " != "
            + String(expect)
        )
    if c.res >= 0 and (not c.buf or c.buf.value().readable() != 0):
        w.unexpected.append(
            "send " + String(i) + ": buffer not handed back consumed"
        )
    if c.res < 0:
        if c.res != ECANCELED:
            close_client(w, lp, i, R_FAILED, c.res)
        return
    w.clients[i].acked += c.res
    fill(w, lp, i)


def on_cshut(ctx: Int, mut lp: Loop, var c: Completion):
    ref w = _w(ctx)
    note(w, lp, c)
    if c.res < 0 and c.res != ECANCELED:
        close_client(w, lp, Int(c.tag), R_FAILED, c.res)


def on_crecv(ctx: Int, mut lp: Loop, var c: Completion):
    ref w = _w(ctx)
    note(w, lp, c)
    var i = Int(c.tag)
    if c.res > 0:
        var sp = c.buf.value().readable_span()
        var off = w.clients[i].got
        if off + len(sp) > w.clients[i].sent:
            w.clients[i].bad = True  # echoed more than was ever sent
        for k in range(len(sp)):
            if sp[k] != pattern(i, off + k):
                w.clients[i].bad = True
                break
        w.clients[i].got += c.res
        lp.recycle(c.buf.take())
        if w.clients[i].phase == P_RUNNING:
            _ = lp.recv(c.fd, w.t[T_CRECV], c.tag)
        return
    if c.res == 0:
        var whole = (
            w.clients[i].got == w.clients[i].size
            and w.clients[i].acked == w.clients[i].size
        )
        close_client(w, lp, i, R_OK if whole else R_FAILED, 0 if whole else -1)
    elif c.res != ECANCELED:
        close_client(w, lp, i, R_FAILED, c.res)


def on_cclosed(ctx: Int, mut lp: Loop, var c: Completion):
    ref w = _w(ctx)
    note(w, lp, c)
    var i = Int(c.tag)
    w.clients[i].phase = P_DONE
    if not w.clients[i].timer_done:
        _ = lp.cancel(w.clients[i].timer_op, w.t[T_CANCEL], c.tag)
    finish_check(w, lp, i)


def on_timer(ctx: Int, mut lp: Loop, var c: Completion):
    ref w = _w(ctx)
    note(w, lp, c)
    var i = Int(c.tag)
    w.clients[i].timer_done = True
    if c.res == 0:  # the deadline passed
        var ph = w.clients[i].phase
        if ph == P_CONNECTING:
            w.clients[i].result = R_GAVE_UP
            _ = lp.cancel(w.clients[i].connect_op, w.t[T_CANCEL], c.tag)
        elif ph == P_RUNNING:
            w.clients[i].stalled = True
            close_client(w, lp, i, R_GAVE_UP, 0)
    finish_check(w, lp, i)


def on_cancel(ctx: Int, mut lp: Loop, var c: Completion):
    note(_w(ctx), lp, c)


# ---- runner ---------------------------------------------------------------------


struct Outcome(Movable, Writable):
    var seed: UInt64
    var n: Int
    var ok: Int
    var failed: Int
    var gave_up: Int
    var stalled: Int
    var bad: Int
    var dup: Int
    var unfinished: Int
    var unexpected: Int
    var trace: UInt64
    var log_hash: UInt64
    var log_count: Int
    var virtual_ns: Int
    var real_ms: Int
    var pending_ops: Int
    var open_fds: Int
    var open_sockets: Int
    var bytes: Int
    var faults: List[Int]
    var stats: String

    def __init__(out self):
        self.seed = 0
        self.n = 0
        self.ok = 0
        self.failed = 0
        self.gave_up = 0
        self.stalled = 0
        self.bad = 0
        self.dup = 0
        self.unfinished = 0
        self.unexpected = 0
        self.trace = 0
        self.log_hash = 0
        self.log_count = 0
        self.virtual_ns = 0
        self.real_ms = 0
        self.pending_ops = 0
        self.open_fds = 0
        self.open_sockets = 0
        self.bytes = 0
        self.faults = []
        self.stats = ""

    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            "seed=",
            self.seed,
            " n=",
            self.n,
            " ok=",
            self.ok,
            " failed=",
            self.failed,
            " gave_up=",
            self.gave_up,
            " stalled=",
            self.stalled,
            " bad=",
            self.bad,
            " dup=",
            self.dup,
            " unfinished=",
            self.unfinished,
            " unexpected=",
            self.unexpected,
            " bytes=",
            self.bytes,
            " completions=",
            self.log_count,
            " virtual_ms=",
            self.virtual_ns // 1_000_000,
            " real_ms=",
            self.real_ms,
            "\n      ",
            self.stats,
        )


def run_world(
    seed: UInt64,
    n: Int,
    concurrency: Int,
    max_size: Int,
    faults: SimFaults,
    config: SimConfig = SimConfig(),
) raises -> Outcome:
    """Run `n` transfers; `seed` 0 keeps the driver's (environment) seed."""
    var real0 = Instant.now().as_nanos()
    var ev = EventLoop()
    if seed != 0:
        sim(ev).set_seed(seed)
    sim(ev).faults = faults
    sim(ev).config = config
    var out = Outcome()
    out.seed = sim(ev).seed()
    var w = World(n, concurrency, max_size, out.seed)
    var ctx = Int(Pointer(to=w))
    w.t = [
        Target(on_accept, ctx),
        Target(on_srecv, ctx),
        Target(on_ssent, ctx),
        Target(on_sclosed, ctx),
        Target(on_connect, ctx),
        Target(on_csent, ctx),
        Target(on_crecv, ctx),
        Target(on_cshut, ctx),
        Target(on_cclosed, ctx),
        Target(on_timer, ctx),
        Target(on_cancel, ctx),
        Target(on_lclosed, ctx),
    ]
    var t0 = sim(ev).now().as_nanos()
    _ = ev.loop.listen(
        SocketAddr(Ipv4Addr.LOCALHOST, 0).to_raw(), Target(on_listen, ctx)
    )
    ev.run()
    out.n = n
    for i in range(n):
        ref cl = w.clients[i]
        if cl.result == R_OK:
            out.ok += 1
            if cl.got != cl.size or cl.acked != cl.size:
                out.bad += 1
        elif cl.result == R_FAILED:
            out.failed += 1
        elif cl.result == R_GAVE_UP:
            out.gave_up += 1
        if cl.stalled:
            out.stalled += 1
        if cl.bad or cl.got > cl.acked + 2 * MAX_CHUNK:
            out.bad += 1
        if not cl.counted:
            out.unfinished += 1
        out.bytes += cl.got
    out.dup = w.dup_completions
    out.unexpected = len(w.unexpected)
    for i in range(len(w.unexpected)):
        print("      unexpected:", w.unexpected[i])
    out.trace = sim(ev).trace_hash()
    out.log_hash = w.log_hash
    out.log_count = w.log_count
    out.virtual_ns = sim(ev).now().as_nanos() - t0
    out.pending_ops = ev.loop.pending_ops()
    out.open_fds = ev.loop.open_fds()
    out.open_sockets = sim(ev).open_sockets()
    out.faults = sim(ev).stats.faults.copy()
    out.stats = String(sim(ev).stats)
    out.real_ms = (Instant.now().as_nanos() - real0) // 1_000_000
    return out^


def check_clean(o: Outcome) raises:
    """What must hold under any faults."""
    assert_equal(o.unfinished, 0)
    assert_equal(o.bad, 0)
    assert_equal(o.stalled, 0)
    assert_equal(o.dup, 0)
    assert_equal(o.unexpected, 0)
    assert_equal(o.pending_ops, 0)
    assert_equal(o.open_fds, 0)
    assert_equal(o.open_sockets, 0)


# ---- tests ----------------------------------------------------------------------


def test_transfers_without_faults_all_succeed() raises:
    var o = run_world(11, 40, 8, 256 * 1024, SimFaults())
    print("     ", o)
    check_clean(o)
    assert_equal(o.ok, 40)


def test_200_transfers_under_benign_faults_all_succeed() raises:
    """Faults that never fail a connection: every byte must arrive."""
    var o = run_world(0, 200, 16, 1 << 20, SimFaults.benign(0.2))
    print("     ", o)
    check_clean(o)
    assert_equal(o.ok, 200)
    assert_equal(o.failed + o.gave_up, 0)


def test_200_transfers_under_all_faults_keep_integrity() raises:
    """Every fault, including resets, aborted accepts and lost SYNs: what
    arrives is always an exact prefix, nothing stalls or leaks."""
    var f = SimFaults.all(0.15, 0.0)
    f.random_reset = 0.0005
    f.accept_abort = 0.05
    f.drop_syn = 0.05
    var o = run_world(0, 200, 16, 1 << 20, f)
    print("     ", o)
    check_clean(o)
    assert_equal(o.ok + o.failed + o.gave_up, 200)
    assert_true(o.ok >= 100)
    assert_true(o.failed > 0)
    assert_true(o.gave_up > 0)  # dropped SYNs, given up by the deadline
    for k in range(FAULT_KINDS):
        if o.faults[k] == 0:
            print("      fault never injected:", fault_name(k))
        assert_true(o.faults[k] > 0)


def test_small_buffers_and_tiny_event_batches() raises:
    """4 KiB socket buffers (constant EAGAIN / partial writes) and at most
    two events per wait (the rest stay on the ready list)."""
    var cfg = SimConfig(sndbuf=4096, rcvbuf=4096, max_events=2)
    var o = run_world(21, 60, 12, 256 * 1024, SimFaults.benign(0.2), cfg)
    print("     ", o)
    check_clean(o)
    assert_equal(o.ok, 60)


def test_zero_latency_network() raises:
    """Everything is delivered at the same virtual instant."""
    var cfg = SimConfig(latency_ns=0, jitter_ns=0)
    var o = run_world(31, 40, 8, 256 * 1024, SimFaults.benign(0.2), cfg)
    print("     ", o)
    check_clean(o)
    assert_equal(o.ok, 40)
    assert_equal(o.virtual_ns, 0)


def test_same_seed_same_trace_and_completion_log() raises:
    var f = SimFaults.all(0.2, 0.0)
    f.random_reset = 0.001
    f.accept_abort = 0.05
    f.drop_syn = 0.05
    var a = run_world(1234, 40, 8, 256 * 1024, f)
    var b = run_world(1234, 40, 8, 256 * 1024, f)
    print("     ", a)
    check_clean(a)
    assert_equal(a.trace, b.trace)
    assert_equal(a.log_hash, b.log_hash)
    assert_equal(a.log_count, b.log_count)
    assert_equal(a.virtual_ns, b.virtual_ns)
    assert_equal(a.ok, b.ok)
    var c = run_world(1235, 40, 8, 256 * 1024, f)
    assert_true(c.trace != a.trace)
    assert_true(c.log_hash != a.log_hash)


def test_different_seeds_differ_even_without_faults() raises:
    """Jitter alone changes delivery times, hence the trace."""
    var a = run_world(5, 10, 4, 64 * 1024, SimFaults())
    var b = run_world(6, 10, 4, 64 * 1024, SimFaults())
    check_clean(a)
    check_clean(b)
    assert_equal(a.ok, 10)
    assert_equal(b.ok, 10)
    assert_true(a.trace != b.trace)


def main() raises:
    comptime assert is_defined["MOJO_TCP_SIM"](), "build with -D MOJO_TCP_SIM=1"
    TestSuite.discover_tests[__functions_in_module()]().run()
