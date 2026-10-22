"""The event loop (rt.core.Loop through rt.event_loop.EventLoop) on the
simulated network: echo, virtual time, resets, refused and abandoned
connects, listener teardown, flow control and deadlock detection.

Built only with -D MOJO_TCP_SIM=1 (the `_sim.mojo` suffix). Callbacks follow
tests/rt/test_loop_echo.mojo: every Target is built once and stored."""

from std.sys import is_defined
from std.testing import TestSuite, assert_equal, assert_true

from bytes.buffer import ByteBuffer
from linux import Errno, Instant
from linux.abi import RawSockaddr
from linux.consts import SHUT_WR
from net.addr import Ipv4Addr, SocketAddr
from rt.core import Completion, FdId, Loop, OpId, Target
from rt.event_loop import EventLoop
from rt.sim import SimDriver, SYS_SEND

comptime LAT = 50_000
comptime ECONNRESET = -Int(Errno.ECONNRESET.value)
comptime ECONNREFUSED = -Int(Errno.ECONNREFUSED.value)
comptime ECANCELED = -Int(Errno.ECANCELED.value)
comptime EPIPE = -Int(Errno.EPIPE.value)


def localhost(port: Int = 0) -> RawSockaddr:
    return SocketAddr(Ipv4Addr.LOCALHOST, UInt16(port)).to_raw()


@always_inline
def sim(mut ev: EventLoop) -> ref[ev.driver] SimDriver:
    """The SimDriver behind `ev` (a compile error outside sim builds)."""
    return rebind[SimDriver](ev.driver)


def sim_loop() raises -> EventLoop:
    """An EventLoop on the simulator with exact timing (no jitter)."""
    var ev = EventLoop()
    sim(ev).set_seed(99)
    sim(ev).config.latency_ns = LAT
    sim(ev).config.jitter_ns = 0
    return ev^


def payload(n: Int) -> ByteBuffer:
    var b = ByteBuffer()
    try:
        b = ByteBuffer(capacity=n)
        var sp = b.writable_span()
        for i in range(n):
            sp[i] = UInt8((i * 7 + 3) & 0xFF)
        b.commit(n)
    except:
        pass
    return b^


def has(log: List[String], line: String) -> Bool:
    for i in range(len(log)):
        if log[i] == line:
            return True
    return False


def count(log: List[String], line: String) -> Int:
    var n = 0
    for i in range(len(log)):
        if log[i] == line:
            n += 1
    return n


def dump(log: List[String]):
    for i in range(len(log)):
        print("   ", log[i])


struct S(Movable):
    """Shared scenario state; each test uses the fields it needs."""

    var listener: FdId
    var server: FdId
    var client: FdId
    var clients: List[FdId]
    var op: OpId
    var t0: Int
    var n: Int
    var bytes: Int
    var bad: Bool
    var log: List[String]
    var t: List[Target]

    def __init__(out self):
        self.listener = FdId.null()
        self.server = FdId.null()
        self.client = FdId.null()
        self.clients = []
        self.op = OpId.null()
        self.t0 = 0
        self.n = 0
        self.bytes = 0
        self.bad = False
        self.log = []
        self.t = []


@always_inline
def _st(ctx: Int) -> ref[MutUntrackedOrigin] S:
    return Pointer[S, MutUntrackedOrigin](unsafe_from_address=ctx)[]


def ms(lp: Loop, s: S) -> Int:
    """Virtual microseconds since the scenario started."""
    return (lp.now().as_nanos() - s.t0) // 1000


def on_ignore(ctx: Int, mut lp: Loop, var c: Completion):
    pass


def on_log(ctx: Int, mut lp: Loop, var c: Completion):
    _st(ctx).log.append(String(c.kind.name()) + " " + String(c.res))


# ---- echo ---------------------------------------------------------------------

comptime E_ACCEPT = 0
comptime E_SRECV = 1
comptime E_SSENT = 2
comptime E_CONNECT = 3
comptime E_CRECV = 4
comptime E_CLOSED = 5
comptime E_LOG = 6


def echo_listen(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("listen " + String(c.res))
    s.listener = c.fd
    _ = lp.accept(c.fd, s.t[E_ACCEPT])
    _ = lp.connect(lp.local_addr(c.fd).value(), s.t[E_CONNECT])


def echo_accept(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("accept " + String(c.res) + " @" + String(ms(lp, s)))
    if c.ok():
        s.server = c.fd
        _ = lp.recv(c.fd, s.t[E_SRECV])


def echo_srecv(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("srecv " + String(c.res))
    if c.res <= 0:
        _ = lp.close(c.fd, s.t[E_CLOSED])
        return
    _ = lp.send(c.fd, c.take_buf(), s.t[E_SSENT])
    _ = lp.recv(c.fd, s.t[E_SRECV])


def echo_ssent(ctx: Int, mut lp: Loop, var c: Completion):
    _st(ctx).log.append("ssent " + String(c.res))


def echo_connect(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("connect " + String(c.res) + " @" + String(ms(lp, s)))
    if not c.ok():
        return
    s.client = c.fd
    var b = ByteBuffer()
    try:
        b.write_bytes(String("ping").as_bytes())
    except:
        pass
    _ = lp.send(c.fd, b^, s.t[E_LOG])
    _ = lp.recv(c.fd, s.t[E_CRECV])


def echo_crecv(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("crecv " + String(c.res) + " @" + String(ms(lp, s)))
    if c.res == 4:
        var sp = c.buf.readable_span()
        s.bad = not (
            Int(sp[0]) == ord("p")
            and Int(sp[1]) == ord("i")
            and Int(sp[3]) == ord("g")
        )
        lp.recycle(c.take_buf())
    _ = lp.close(c.fd, s.t[E_CLOSED])


def echo_closed(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("close " + String(c.res))
    s.n += 1
    if s.n == 2:
        _ = lp.close(s.listener, s.t[E_LOG])


def test_echo_on_virtual_time() raises:
    var ev = sim_loop()
    var s = S()
    var ctx = Int(Pointer(to=s))
    s.t0 = sim(ev).now().as_nanos()
    s.t = [
        Target(echo_accept, ctx),
        Target(echo_srecv, ctx),
        Target(echo_ssent, ctx),
        Target(echo_connect, ctx),
        Target(echo_crecv, ctx),
        Target(echo_closed, ctx),
        Target(on_log, ctx),
    ]
    _ = ev.loop.listen(localhost(), Target(echo_listen, ctx))
    ev.run()
    dump(s.log)
    assert_true(not s.bad)
    # Handshake: the client is connected after one round trip, the server
    # accepts half a round trip later, and the echo takes one more.
    assert_true(has(s.log, "connect 0 @100"))
    assert_true(has(s.log, "accept 0 @150"))
    assert_true(has(s.log, "crecv 4 @200"))
    assert_equal(count(s.log, "close 0"), 3)  # server, client, listener
    assert_true(s.log[len(s.log) - 2].startswith("accept -125"))
    assert_equal(ev.loop.pending_ops(), 0)
    assert_equal(ev.loop.open_fds(), 0)
    assert_equal(sim(ev).open_sockets(), 0)


# ---- virtual time ----------------------------------------------------------------


def on_timer(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("timer " + String(c.res) + " @" + String(ms(lp, s)))


def test_ten_second_timeout_completes_instantly() raises:
    var ev = sim_loop()
    var s = S()
    var ctx = Int(Pointer(to=s))
    s.t0 = sim(ev).now().as_nanos()
    var real0 = Instant.now().as_nanos()
    _ = ev.loop.timeout_ns(10_000_000_000, Target(on_timer, ctx))
    ev.run()
    var real_ms = (Instant.now().as_nanos() - real0) // 1_000_000
    dump(s.log)
    assert_true(has(s.log, "timer 0 @10000000"))
    assert_equal(sim(ev).now().as_nanos() - s.t0, 10_000_000_000)
    assert_true(real_ms < 1000)


# ---- resets --------------------------------------------------------------------

comptime R_ACCEPT = 0
comptime R_TIMER = 1
comptime R_CONNECT = 2
comptime R_CSENT = 3
comptime R_CRECV = 4
comptime R_CSENT2 = 5
comptime R_LOG = 6


def rst_listen(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.listener = c.fd
    _ = lp.accept(c.fd, s.t[R_ACCEPT])
    _ = lp.connect(lp.local_addr(c.fd).value(), s.t[R_CONNECT])


def rst_accept(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    if not c.ok():
        s.log.append("accept " + String(c.res))
        return
    s.server = c.fd
    # Never read: close after the client's data has arrived.
    _ = lp.timeout_ns(1_000_000, s.t[R_TIMER])


def rst_timer(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("server closes with unread data")
    _ = lp.close(s.server, s.t[R_LOG])


def rst_connect(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.client = c.fd
    _ = lp.send(c.fd, payload(100), s.t[R_CSENT])
    _ = lp.recv(c.fd, s.t[R_CRECV])


def rst_csent(ctx: Int, mut lp: Loop, var c: Completion):
    _st(ctx).log.append("csent " + String(c.res))


def rst_crecv(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("crecv " + String(c.res))
    # The connection is dead; the next send must fail, not hang.
    _ = lp.send(c.fd, payload(10), s.t[R_CSENT2])


def rst_csent2(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("csent2 " + String(c.res))
    _ = lp.close(s.client, s.t[R_LOG])
    _ = lp.close(s.listener, s.t[R_LOG])


def test_close_with_unread_data_resets_the_peer() raises:
    var ev = sim_loop()
    var s = S()
    var ctx = Int(Pointer(to=s))
    s.t = [
        Target(rst_accept, ctx),
        Target(rst_timer, ctx),
        Target(rst_connect, ctx),
        Target(rst_csent, ctx),
        Target(rst_crecv, ctx),
        Target(rst_csent2, ctx),
        Target(on_log, ctx),
    ]
    _ = ev.loop.listen(localhost(), Target(rst_listen, ctx))
    ev.run()
    dump(s.log)
    assert_true(has(s.log, "csent 100"))
    assert_true(has(s.log, "crecv " + String(ECONNRESET)))
    assert_true(has(s.log, "csent2 " + String(EPIPE)))
    assert_equal(ev.loop.pending_ops(), 0)
    assert_equal(ev.loop.open_fds(), 0)
    assert_equal(sim(ev).open_sockets(), 0)


def on_conn_log(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("connect " + String(c.res) + " @" + String(ms(lp, s)))
    if c.ok():
        _ = lp.close(c.fd, s.t[0])


def test_connect_refused() raises:
    var ev = sim_loop()
    var s = S()
    var ctx = Int(Pointer(to=s))
    s.t0 = sim(ev).now().as_nanos()
    s.t = [Target(on_log, ctx)]
    _ = ev.loop.connect(localhost(9), Target(on_conn_log, ctx))
    ev.run()
    dump(s.log)
    assert_true(has(s.log, "connect " + String(ECONNREFUSED) + " @100"))
    assert_equal(ev.loop.open_fds(), 0)
    assert_equal(sim(ev).open_sockets(), 0)
    assert_equal(sim(ev).stats.connects_failed, 1)


# ---- abandoned connect ------------------------------------------------------------


def drop_timer(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("timer " + String(c.res) + " @" + String(ms(lp, s)))
    _ = lp.cancel(s.op, s.t[0])


def drop_cancel(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("cancel " + String(c.res))


def test_dropped_syn_gives_up_by_timeout_and_cancel() raises:
    var ev = sim_loop()
    sim(ev).faults.drop_syn = 1.0
    var s = S()
    var ctx = Int(Pointer(to=s))
    s.t0 = sim(ev).now().as_nanos()
    s.t = [Target(drop_cancel, ctx)]
    s.op = ev.loop.connect(localhost(4242), Target(on_conn_log, ctx))
    _ = ev.loop.timeout_ns(3_000_000_000, Target(drop_timer, ctx))
    ev.run()
    dump(s.log)
    assert_equal(len(s.log), 3)
    assert_equal(s.log[0], "timer 0 @3000000")
    assert_equal(s.log[1], "connect " + String(ECANCELED) + " @3000000")
    assert_equal(s.log[2], "cancel 0")
    assert_equal(ev.loop.open_fds(), 0)
    assert_equal(sim(ev).open_sockets(), 0)


# ---- listener teardown --------------------------------------------------------------

comptime L_CONNECT = 0
comptime L_CRECV = 1
comptime L_LOG = 2


def lq_listen(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.listener = c.fd
    var addr = lp.local_addr(c.fd).value().copy()
    for _ in range(3):
        _ = lp.connect(addr, s.t[L_CONNECT])


def lq_connect(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("connect " + String(c.res))
    if not c.ok():
        return
    s.clients.append(c.fd)
    _ = lp.recv(c.fd, s.t[L_CRECV])
    if len(s.clients) == 3:
        # All three wait in the accept queue (nobody accepts): close it.
        _ = lp.close(s.listener, s.t[L_LOG])


def lq_crecv(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("crecv " + String(c.res))
    _ = lp.close(c.fd, s.t[L_LOG])


def test_listener_close_resets_queued_peers() raises:
    var ev = sim_loop()
    var s = S()
    var ctx = Int(Pointer(to=s))
    s.t = [Target(lq_connect, ctx), Target(lq_crecv, ctx), Target(on_log, ctx)]
    _ = ev.loop.listen(localhost(), Target(lq_listen, ctx))
    ev.run()
    dump(s.log)
    assert_equal(count(s.log, "connect 0"), 3)
    assert_equal(count(s.log, "crecv " + String(ECONNRESET)), 3)
    assert_equal(ev.loop.open_fds(), 0)
    assert_equal(sim(ev).open_sockets(), 0)


# ---- flow control through the proactor --------------------------------------------

comptime F_ACCEPT = 0
comptime F_SRECV = 1
comptime F_CONNECT = 2
comptime F_CSENT = 3
comptime F_SHUT = 4
comptime F_LOG = 5
comptime BIG = 1 << 20


def fc_listen(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.listener = c.fd
    _ = lp.accept(c.fd, s.t[F_ACCEPT])
    _ = lp.connect(lp.local_addr(c.fd).value(), s.t[F_CONNECT])


def fc_accept(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    if c.ok():
        _ = lp.recv(c.fd, s.t[F_SRECV])


def fc_srecv(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    if c.res > 0:
        var sp = c.buf.readable_span()
        for i in range(len(sp)):
            if sp[i] != UInt8(((s.bytes + i) * 7 + 3) & 0xFF):
                s.bad = True
        s.bytes += c.res
        lp.recycle(c.take_buf())
        _ = lp.recv(c.fd, s.t[F_SRECV])
        return
    s.log.append("srecv " + String(c.res) + " after " + String(s.bytes))
    _ = lp.close(c.fd, s.t[F_LOG])
    _ = lp.close(s.listener, s.t[F_LOG])


def fc_connect(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.client = c.fd
    _ = lp.send(c.fd, payload(BIG), s.t[F_CSENT])


def fc_csent(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("csent " + String(c.res))
    _ = lp.shutdown(c.fd, SHUT_WR, s.t[F_SHUT])


def fc_shut(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("shutdown " + String(c.res))
    _ = lp.close(c.fd, s.t[F_LOG])


def test_one_large_send_through_small_buffers() raises:
    var ev = sim_loop()
    sim(ev).config.sndbuf = 4096
    sim(ev).config.rcvbuf = 8192
    var s = S()
    var ctx = Int(Pointer(to=s))
    s.t = [
        Target(fc_accept, ctx),
        Target(fc_srecv, ctx),
        Target(fc_connect, ctx),
        Target(fc_csent, ctx),
        Target(fc_shut, ctx),
        Target(on_log, ctx),
    ]
    _ = ev.loop.listen(localhost(), Target(fc_listen, ctx))
    ev.run()
    dump(s.log)
    assert_true(has(s.log, "csent " + String(BIG)))
    assert_true(has(s.log, "srecv 0 after " + String(BIG)))
    assert_true(not s.bad)
    assert_equal(ev.loop.open_fds(), 0)
    # 1 MiB through a 12 KiB window: many partial writes, each resumed by
    # a WRITE_READY edge.
    print("    ", sim(ev).stats)
    assert_true(sim(ev).stats.syscalls[SYS_SEND] > 50)


# ---- deadlock ------------------------------------------------------------------


def dl_listen(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    _ = lp.accept(c.fd, s.t[0])


def test_deadlock_raises_instead_of_hanging() raises:
    var ev = sim_loop()
    var s = S()
    var ctx = Int(Pointer(to=s))
    s.t = [Target(on_log, ctx)]
    _ = ev.loop.listen(localhost(), Target(dl_listen, ctx))
    var raised = False
    try:
        ev.run()  # an accept nobody will ever satisfy
    except e:
        raised = True
        assert_equal(String(e.op), "SimDriver.wait: deadlock")
    assert_true(raised)
    assert_equal(ev.loop.pending_ops(), 1)


def main() raises:
    comptime assert is_defined["MOJO_TCP_SIM"](), "build with -D MOJO_TCP_SIM=1"
    TestSuite.discover_tests[__functions_in_module()]().run()
