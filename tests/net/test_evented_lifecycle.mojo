"""net.evented lifetimes on loopback: idle timeouts (lazy reset), managed
timers, graceful server shutdown with active and idle clients, the grace
abort of a connection that cannot drain, and leaks (handler state freed
exactly once, no fd left in the loop or in /proc/self/fd).

Python (test-only) lists /proc/self/fd as an independent oracle.
"""

from std.python import Python
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from linux import IoError, Instant
from net.addr import SocketAddr
from net.evented import (
    CloseReason,
    Conn,
    ConnConfig,
    ConnHandler,
    ConnRef,
    ServerConfig,
    TcpServer,
    dial,
)
from rt.core import Loop, OpId
from rt.event_loop import EventLoop

comptime MS = 1_000_000
comptime GUARD_NS = 30_000 * MS


# ---- plumbing ----------------------------------------------------------------


struct Counters(Movable):
    var opened: Int
    var closed: Int
    var dropped: Int
    var reasons: List[UInt8]

    def __init__(out self):
        self.opened = 0
        self.closed = 0
        self.dropped = 0
        self.reasons = []

    def count(self, code: UInt8) -> Int:
        var n = 0
        for r in self.reasons:
            if r == code:
                n += 1
        return n


comptime KPtr = Pointer[Counters, MutUntrackedOrigin]


def kptr(mut k: Counters) -> KPtr:
    return Pointer(to=k).unsafe_origin_cast[MutUntrackedOrigin]()


def start[H: ConnHandler & Copyable](
    mut ev: EventLoop, var proto: H, cfg: ServerConfig = ServerConfig()
) raises -> TcpServer[H]:
    var srv = TcpServer[H].listen(ev.loop, SocketAddr.parse("127.0.0.1:0"), proto^, cfg)
    for _ in range(100):
        if srv.is_listening():
            return srv^
        if srv.error():
            raise Error("listen failed: ", srv.error().value())
        ev.run_once(0)
    raise Error("server never started listening")


def run_until_closed[H: ConnHandler](mut ev: EventLoop, mut refs: List[ConnRef[H]]) raises:
    var t0 = Instant.now()
    while True:
        var open = 0
        for i in range(len(refs)):
            if not refs[i].is_closed():
                open += 1
        if open == 0:
            return
        if (Instant.now() - t0).as_nanos() > GUARD_NS:
            raise Error(open, " client(s) still open after the guard")
        ev.run_once(5 * MS)


def drain(mut ev: EventLoop) raises:
    var t0 = Instant.now()
    while ev.loop.pending_ops() > 0 or ev.loop.has_ready():
        if (Instant.now() - t0).as_nanos() > GUARD_NS:
            raise Error("loop did not drain: ", ev.loop.pending_ops(), " ops pending")
        ev.run_once(5 * MS)


def wait_no_conns[H: ConnHandler & Copyable](mut ev: EventLoop, srv: TcpServer[H]) raises:
    var t0 = Instant.now()
    while srv.connections() > 0:
        if (Instant.now() - t0).as_nanos() > GUARD_NS:
            raise Error(srv.connections(), " server connection(s) still open")
        ev.run_once(5 * MS)


def run_for(mut ev: EventLoop, ns: Int) raises:
    var t0 = ev.loop.now()
    while (ev.loop.now() - t0).as_nanos() < ns:
        ev.run_once(2 * MS)


def proc_fds() raises -> Int:
    var os = Python.import_module("os")
    return Int(py=Python.evaluate("len")(os.listdir("/proc/self/fd")))


# ---- handlers ----------------------------------------------------------------


struct EchoH(ConnHandler, Copyable):
    var k: KPtr

    def __init__(out self, k: KPtr):
        self.k = k

    def __init__(out self, *, copy: Self):
        self.k = copy.k

    def __deinit__(deinit self):
        self.k[].dropped += 1

    def on_open(mut self, mut conn: Conn) raises IoError:
        self.k[].opened += 1

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        conn.write(input.readable_span())
        input.clear()

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        self.k[].closed += 1
        self.k[].reasons.append(reason.code)


struct FloodH(ConnHandler, Copyable):
    """Answers any input with `size` bytes: a reply that cannot drain if the
    peer does not read."""

    var k: KPtr
    var size: Int

    def __init__(out self, k: KPtr, size: Int):
        self.k = k
        self.size = size

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        input.clear()
        var b = ByteBuffer(capacity=self.size)
        var chunk = List[UInt8](length=64 * 1024, fill=UInt8(ord("z")))
        while b.readable() < self.size:
            b.write_bytes(Span(chunk)[0 : min(len(chunk), self.size - b.readable())])
        conn.send(b^)

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        self.k[].closed += 1
        self.k[].reasons.append(reason.code)


struct Watcher(ConnHandler):
    """Records when it opened and closed (loop time); optionally sends one
    byte every `tick_ns`, `ticks` times, then closes; optionally starts
    with reading paused and resumes after `resume_ns`."""

    var tick_ns: Int
    var ticks: Int
    var sent: Int
    var echoed: Int
    var resume_ns: Int
    var opened_at: Int
    var closed_at: Int
    var got: Int
    var reason: CloseReason

    def __init__(out self, tick_ns: Int = 0, ticks: Int = 0, resume_ns: Int = 0):
        self.tick_ns = tick_ns
        self.ticks = ticks
        self.sent = 0
        self.echoed = 0
        self.resume_ns = resume_ns
        self.opened_at = 0
        self.closed_at = 0
        self.got = 0
        self.reason = CloseReason.of(CloseReason.NONE)

    def on_open(mut self, mut conn: Conn) raises IoError:
        self.opened_at = conn.now().as_nanos()
        if self.tick_ns > 0:
            _ = conn.set_timer(self.tick_ns, 1)
        if self.resume_ns > 0:
            conn.pause_reading()
            conn.write("x")
            _ = conn.set_timer(self.resume_ns, 2)

    def on_timer(mut self, mut conn: Conn, tag: UInt64) raises IoError:
        if tag == 2:
            conn.resume_reading()
            return
        conn.write("t")
        self.sent += 1

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        self.got += input.readable()
        if self.tick_ns > 0:
            self.echoed += input.readable()
            if self.echoed >= self.ticks:
                conn.close()
            else:
                _ = conn.set_timer(self.tick_ns, 1)
        input.clear()

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        self.closed_at = lp.now().as_nanos()
        self.reason = reason


struct Pinger(ConnHandler):
    var size: Int
    var done: Int
    var got: Int
    var bad: Int
    var reason: CloseReason

    def __init__(out self, size: Int):
        self.size = size
        self.done = 0
        self.got = 0
        self.bad = 0
        self.reason = CloseReason.of(CloseReason.NONE)

    @inline(.always)
    def _byte(self, i: Int) -> UInt8:
        return UInt8((self.done * 31 + i) % 251)

    def _send(mut self, mut conn: Conn) raises IoError:
        ref o = conn.out()
        for i in range(self.size):
            o.write_byte(self._byte(i))

    def on_open(mut self, mut conn: Conn) raises IoError:
        self._send(conn)

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        var sp = input.readable_span()
        var finished = False
        for i in range(len(sp)):
            if finished or sp[i] != self._byte(self.got):
                self.bad += 1
            self.got += 1
            if self.got == self.size:
                self.got = 0
                self.done += 1
                finished = True
        input.clear()
        if finished:
            self._send(conn)  # forever, until the server closes

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        self.reason = reason


struct Timers(ConnHandler):
    """Arms tags 1, 2, 3 and a far timer 9; cancels 2; closes on 3."""

    var fired: List[UInt64]
    var reason: CloseReason

    def __init__(out self):
        self.fired = []
        self.reason = CloseReason.of(CloseReason.NONE)

    def on_open(mut self, mut conn: Conn) raises IoError:
        _ = conn.set_timer(5 * MS, 1)
        var two = conn.set_timer(10 * MS, 2)
        _ = conn.set_timer(20 * MS, 3)
        _ = conn.set_timer(60_000 * MS, 9)  # must not hold the loop open
        conn.cancel_timer(two)

    def on_timer(mut self, mut conn: Conn, tag: UInt64) raises IoError:
        self.fired.append(tag)
        if tag == 3:
            conn.close()

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        input.clear()

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        self.reason = reason


# ---- tests -------------------------------------------------------------------


def test_idle_timeout_closes_only_the_idle_connection() raises:
    var k = Counters()
    var ev = EventLoop()
    var idle = 100 * MS
    var srv = start(ev, EchoH(kptr(k)), ServerConfig(conn=ConnConfig(idle_timeout_ns=idle)))
    var addr = srv.local_addr().value()
    var refs = List[ConnRef[Watcher]]()
    refs.append(dial(ev.loop, addr, Watcher()))  # never sends
    # Sends every 30 ms for 300 ms: always active, so never idle (the
    # server's single lazy timer re-arms instead of firing).
    refs.append(dial(ev.loop, addr, Watcher(tick_ns=30 * MS, ticks=10)))
    run_until_closed(ev, refs)
    ref quiet = refs[0].handler()
    var lived = quiet.closed_at - quiet.opened_at
    assert_true(lived >= idle, String("closed too early: ", lived))
    assert_true(lived < idle + 1_000 * MS, String("closed too late: ", lived))
    assert_equal(quiet.reason.code, CloseReason.PEER)  # the server's FIN
    ref busy = refs[1].handler()
    assert_equal(busy.echoed, 10)
    assert_equal(busy.reason.code, CloseReason.LOCAL)
    assert_true(busy.closed_at - busy.opened_at >= 300 * MS)
    wait_no_conns(ev, srv)
    srv.shutdown(ev.loop)
    drain(ev)
    assert_equal(srv.stats().idle_closed, 1)
    assert_equal(k.count(CloseReason.IDLE), 1)
    assert_equal(ev.loop.open_fds(), 0)


def test_set_idle_timeout_from_handler_and_timers() raises:
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, EchoH(kptr(k)))
    var refs = List[ConnRef[Timers]]()
    refs.append(dial(ev.loop, srv.local_addr().value(), Timers()))
    var t0 = Instant.now()
    run_until_closed(ev, refs)
    ref t = refs[0].handler()
    assert_equal(len(t.fired), 2)
    assert_equal(t.fired[0], 1)
    assert_equal(t.fired[1], 3)
    assert_equal(t.reason.code, CloseReason.LOCAL)
    wait_no_conns(ev, srv)
    srv.shutdown(ev.loop)
    drain(ev)  # the 60 s timer was canceled at close: this returns at once
    assert_true((Instant.now() - t0).as_nanos() < 5_000 * MS)
    assert_equal(ev.loop.pending_ops(), 0)


def test_shutdown_with_active_and_idle_clients() raises:
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, EchoH(kptr(k)))
    var addr = srv.local_addr().value()
    var busy = List[ConnRef[Pinger]]()
    var quiet = List[ConnRef[Watcher]]()
    for i in range(20):
        busy.append(dial(ev.loop, addr, Pinger(size=64 + 32 * i)))
    for _ in range(10):
        quiet.append(dial(ev.loop, addr, Watcher()))
    run_for(ev, 50 * MS)
    assert_equal(srv.connections(), 30)
    var t0 = ev.loop.now()
    srv.shutdown(ev.loop, 10_000 * MS)
    run_until_closed(ev, busy)
    run_until_closed(ev, quiet)
    drain(ev)
    var took = (ev.loop.now() - t0).as_nanos()
    assert_true(took < 2_000 * MS, String("drain waited for the grace period: ", took))
    assert_true(srv.is_closed())
    for i in range(20):
        ref p = busy[i].handler()
        assert_true(p.done > 0)
        assert_equal(p.bad, 0)  # every echo complete and intact
        # EOF, or a reset if the server closed with a ping still unread.
        assert_true(p.reason.code == CloseReason.PEER or p.reason.code == CloseReason.ERROR)
    for i in range(10):
        assert_equal(quiet[i].handler().reason.code, CloseReason.PEER)
    var st = srv.stats()
    assert_equal(st.accepted, 30)
    assert_equal(st.closed, 30)
    assert_equal(k.count(CloseReason.SHUTDOWN), 30)
    assert_equal(ev.loop.open_fds(), 0)
    assert_equal(ev.loop.pending_ops(), 0)
    # The listener is gone: a new dial is refused.
    var late = List[ConnRef[Watcher]]()
    late.append(dial(ev.loop, addr, Watcher()))
    run_until_closed(ev, late)
    assert_equal(late[0].handler().reason.code, CloseReason.CONNECT_FAILED)


def test_shutdown_grace_aborts_connection_that_cannot_drain() raises:
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, FloodH(kptr(k), 16 * 1024 * 1024))
    var refs = List[ConnRef[Watcher]]()
    # Sends one byte and does not read for 0.5 s: 16 MiB cannot drain.
    refs.append(dial(ev.loop, srv.local_addr().value(), Watcher(resume_ns=500 * MS)))
    run_for(ev, 50 * MS)
    var t0 = ev.loop.now()
    var grace = 200 * MS
    srv.shutdown(ev.loop, grace)
    wait_no_conns(ev, srv)
    var took = (ev.loop.now() - t0).as_nanos()
    assert_true(took >= grace, String("aborted before the grace period: ", took))
    assert_true(took < grace + 1_000 * MS, String("abort came late: ", took))
    assert_equal(k.count(CloseReason.SHUTDOWN), 1)
    run_until_closed(ev, refs)
    # The client got part of the reply, then the abort (reset or EOF).
    assert_true(refs[0].handler().got < 16 * 1024 * 1024)
    drain(ev)
    assert_true(srv.is_closed())
    assert_equal(ev.loop.open_fds(), 0)


def test_no_fd_or_state_leaks_over_many_connections() raises:
    _ = proc_fds()  # warm up Python's own descriptors
    var before = proc_fds()
    var k = Counters()
    var dropped_clients = 0
    var rounds = 10
    var per_round = 50
    if True:
        var ev = EventLoop()
        var srv = start(ev, EchoH(kptr(k)))
        var addr = srv.local_addr().value()
        for _ in range(rounds):
            var refs = List[ConnRef[Watcher]]()
            for _ in range(per_round):
                refs.append(dial(ev.loop, addr, Watcher(tick_ns=1 * MS, ticks=3)))
            run_until_closed(ev, refs)
            for i in range(per_round):
                assert_equal(refs[i].handler().echoed, 3)
            dropped_clients += len(refs)
        wait_no_conns(ev, srv)
        srv.shutdown(ev.loop)
        drain(ev)
        assert_equal(ev.loop.open_fds(), 0)
        assert_equal(ev.loop.pending_ops(), 0)
        var st = srv.stats()
        assert_equal(st.accepted, rounds * per_round)
        assert_equal(st.closed, rounds * per_round)
        _ = srv^
        _ = ev^  # closes the epoll fd
    # Every server-side handler was destroyed exactly once (plus the
    # prototype), so every connection state was freed exactly once.
    assert_equal(k.opened, rounds * per_round)
    assert_equal(k.closed, rounds * per_round)
    assert_equal(k.dropped, rounds * per_round + 1)
    assert_equal(dropped_clients, rounds * per_round)
    assert_equal(proc_fds(), before)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
