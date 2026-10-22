"""Epoll-backend robustness tests for the rt event loop (real kernel only;
the backend-agnostic contract lives in test_loop_contract.mojo).

- EMFILE: with RLIMIT_NOFILE lowered in-process, a connection storm must
  pause accepting (bounded loop iterations, no busy-spin on the readable
  listener), resume when fds are closed, and again once the limit is back.
- 10k idle connections (each with a parked recv) plus echo on a subset:
  everything completes, and neither the active phase nor closing every fd
  degrades with the number of idle connections.
- fd hygiene: /proc/self/fd is unchanged after connect/accept/close churn,
  refused connects and canceled half-open connects; the fd table is
  pre-grown when the loop starts (docs/spikes.md, fd-table stall).
"""

from std.os import listdir
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from linux import Instant
from linux.abi import RawSockaddr, Rlimit
from linux.consts import RLIMIT_NOFILE, SHUT_WR
from linux.probe import nofile_limit, raise_nofile_limit, set_rlimit
from net.addr import SocketAddr
from net.tcp import TcpStream
from rt.core import Completion, FdId, Loop, OpId, OpKind
from rt.event_loop import EventLoop

from test_loop_harness import (
    ECANCELED,
    ECONNREFUSED,
    MS,
    SEC,
    Ctx,
    Harness,
    Script,
    bind,
    bytes_buf,
    count_open_fds,
    loopback,
    mismatch,
    pattern_buf,
    rs,
    run,
    text_of,
)

comptime LIS: UInt64 = 1
comptime ACC: UInt64 = 2
comptime CON: UInt64 = 3
comptime CR: UInt64 = 4
comptime SR: UInt64 = 5
comptime CS: UInt64 = 6
comptime SS: UInt64 = 7
comptime END: UInt64 = 8
comptime CAN: UInt64 = 9
comptime TMO: UInt64 = 10


def _ns(lp: Loop) -> Int:
    return lp.now().as_nanos()


def _fd_numbers() raises -> List[Int]:
    var out = List[Int]()
    var names = listdir("/proc/self/fd")
    for i in range(len(names)):
        out.append(atol(names[i]))
    return out^


def _fdsize() raises -> Int:
    """`FDSize:` of /proc/self/status: slots in this process's fd table."""
    var f = open("/proc/self/status", "r")
    var text = f.read()
    f.close()
    var lines = text.split("\n")
    for i in range(len(lines)):
        if lines[i].startswith("FDSize:"):
            return atol(String(lines[i][byte=7:]).strip())
    raise Error("no FDSize line")


# ---- fd table ------------------------------------------------------------------


def test_loop_start_pregrows_fd_table() raises:
    var want = min(Int(nofile_limit().cur), 65536)
    var ev = EventLoop()
    var size = _fdsize()
    _ = ev.loop.open_fds()
    if want < 256:
        print("    (skipped: test_loop_start_pregrows_fd_table: RLIMIT_NOFILE", want, ")")
        return
    assert_true(size >= want, String("FDSize ", size, " < ", want))


# ---- EMFILE --------------------------------------------------------------------


struct Emfile(Script):
    var listener: FdId
    var accepted: List[FdId]
    var accept_end: Int
    var closed: Int

    def __init__(out self):
        self.listener = FdId.null()
        self.accepted = []
        self.accept_end = 1
        self.closed = 0

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == LIS:
            h.expect(c.ok(), "listen " + rs(c.res))
            self.listener = c.fd
        elif c.tag == ACC:
            if c.more:
                self.accepted.append(c.fd)
            else:
                self.accept_end = c.res
        elif c.tag == END:
            self.closed += 1


def _window(mut ev: EventLoop, ns: Int) raises -> Int:
    """Run iterations for `ns` of loop time (each waits at most 50 ms);
    returns how many there were."""
    var t0 = _ns(ev.loop)
    var n = 0
    while _ns(ev.loop) - t0 < ns:
        ev.run_once(50 * MS)
        n += 1
    return n


def test_emfile_pauses_accepting_without_spinning() raises:
    # Everything stays in this function: `x` must be a local whose address
    # escaped (bind). Behind a `mut` argument it would be noalias, and the
    # compiler may keep its fields in registers across `run_once` although
    # callbacks change them through the bound address.
    comptime N = 40
    var orig = nofile_limit()
    var ev = EventLoop()
    var x = Ctx[Emfile](Emfile())
    bind(x)
    _ = x.h.listen(ev.loop, loopback(), LIS)
    for _ in range(100):
        if not x.s.listener.is_null():
            break
        ev.run_once(10 * MS)
    assert_false(x.s.listener.is_null())
    var addr = SocketAddr.from_raw(ev.loop.local_addr(x.s.listener).value())
    # The clients connect before the limit drops; the kernel completes the
    # handshakes into the accept queue while the loop is not running.
    var clients = List[TcpStream]()
    for _ in range(N):
        clients.append(TcpStream.connect(addr))
    # Room for about 10 more fds (holes in the fd numbers count too).
    var nums = _fd_numbers()
    var maxfd = 0
    for i in range(len(nums)):
        maxfd = max(maxfd, nums[i])
    var open_now = len(nums) - 1  # minus the listing's own fd
    var limit = maxfd + 1 + 10
    var room = limit - open_now
    var first = 0
    var second = 0
    var iters = 0
    var iters2 = 0
    var failed: Optional[Error] = None
    set_rlimit(RLIMIT_NOFILE, Rlimit(UInt64(limit), orig.max))
    try:
        # Nothing here may open an fd behind the loop's back (no listdir,
        # no print(flush=True)) until the limit is restored.
        _ = x.h.accept(ev.loop, x.s.listener, ACC)
        iters = _window(ev, 400 * MS)
        first = len(x.s.accepted)
        # Closing 3 connections frees 3 fds: accepting resumes at once, not
        # only on the retry timer.
        for i in range(3):
            _ = x.h.close(ev.loop, x.s.accepted[i], END)
        iters2 = _window(ev, 60 * MS)
        second = len(x.s.accepted)
    except e:
        failed = e
    # The limit is back; the retry timer resumes the rest.
    set_rlimit(RLIMIT_NOFILE, orig)
    if failed:
        raise failed.value()
    var t0 = _ns(ev.loop)
    while len(x.s.accepted) < N and _ns(ev.loop) - t0 < 3 * SEC:
        ev.run_once(50 * MS)
    var third = len(x.s.accepted)
    print("    emfile: room", room, "accepted", first, "then", second, "then", third,
          "| iterations", iters, "in 400 ms,", iters2, "in 60 ms")
    assert_true(first >= 1 and first <= room, String("accepted ", first, " with room for ", room))
    assert_true(first < N, "the fd limit did not bite")
    # A busy-spinning accept would run thousands of iterations here.
    assert_true(iters <= 40, String("busy-spin: ", iters, " iterations in 400 ms"))
    assert_equal(second, first + 3)
    assert_equal(third, N)
    # Clean up; run() must return promptly (the internal resume timer is
    # not a pending op).
    for i in range(3, len(x.s.accepted)):
        _ = x.h.close(ev.loop, x.s.accepted[i], END)
    _ = x.h.close(ev.loop, x.s.listener, END)
    var t1 = _ns(ev.loop)
    ev.run()
    assert_true(_ns(ev.loop) - t1 < 50 * MS, "run() waited for an internal timer")
    assert_equal(x.s.accept_end, ECANCELED)
    assert_equal(x.s.closed, N + 1)
    x.h.assert_ok()
    assert_equal(ev.loop.pending_ops(), 0)
    assert_equal(ev.loop.open_fds(), 0)
    _ = clients^


# ---- 10k idle connections --------------------------------------------------------


struct Idle(Script):
    var n: Int
    var wave: Int
    var active: Int
    var rounds: Int
    var listener: FdId
    var addr: RawSockaddr
    var clients: List[FdId]
    var servers: List[FdId]
    var launched: Int
    var round_of: List[Int]
    var msgs: Int
    var bad: Int
    var closed: Int
    var closing: Bool
    var t_start: Int
    var t_connected: Int
    var t_active: Int
    var t_closed: Int
    """Wall-clock marks (loop time only advances between iterations)."""

    def __init__(out self, n: Int, active: Int, rounds: Int):
        self.n = n
        self.wave = 1000
        self.active = active
        self.rounds = rounds
        self.listener = FdId.null()
        self.addr = RawSockaddr()
        self.clients = []
        self.servers = []
        self.launched = 0
        self.round_of = []
        self.msgs = 0
        self.bad = 0
        self.closed = 0
        self.closing = False
        self.t_start = 0
        self.t_connected = 0
        self.t_active = 0
        self.t_closed = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        h.keep_recs = False
        self.t_start = Instant.now().as_nanos()
        _ = h.listen(lp, loopback(), LIS, backlog=4096)

    def _launch_wave(mut self, mut h: Harness, mut lp: Loop):
        var k = min(self.wave, self.n - self.launched)
        for _ in range(k):
            _ = h.connect(lp, self.addr, CON)
        self.launched += k

    def _progress(mut self, mut h: Harness, mut lp: Loop):
        if len(self.clients) != self.launched or len(self.servers) != self.launched:
            return
        if self.launched < self.n:
            self._launch_wave(h, lp)
            return
        if self.t_connected == 0:
            self.t_connected = Instant.now().as_nanos()
            for i in range(self.active):
                self.round_of.append(0)
                _ = h.send(lp, self.clients[i], pattern_buf(64, i), CS | (UInt64(i) << 8))
                _ = h.recv(lp, self.clients[i], CR | (UInt64(i) << 8))

    def _close_all(mut self, mut h: Harness, mut lp: Loop):
        self.closing = True
        self.t_active = Instant.now().as_nanos()
        for i in range(len(self.servers)):
            _ = h.close(lp, self.servers[i], END)
        for i in range(len(self.clients)):
            _ = h.close(lp, self.clients[i], END)
        _ = h.close(lp, self.listener, END)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        var tag = c.tag & 0xFF
        var i = Int(c.tag >> 8)
        if tag == LIS:
            self.listener = c.fd
            self.addr = lp.local_addr(c.fd).value().copy()
            _ = h.accept(lp, c.fd, ACC)
            self._launch_wave(h, lp)
        elif tag == ACC:
            if c.more:
                self.servers.append(c.fd)
                _ = h.recv(lp, c.fd, SR)  # parked on every idle connection
                self._progress(h, lp)
            else:
                h.expect(c.res == ECANCELED, "accept end " + rs(c.res))
        elif tag == CON:
            h.expect(c.ok(), "connect " + rs(c.res))
            if c.ok():
                self.clients.append(c.fd)
            self._progress(h, lp)
        elif tag == SR:
            if c.res > 0:
                _ = h.send(lp, c.fd, c.buf.take(), SS)
                _ = h.recv(lp, c.fd, SR)
            elif not self.closing:
                h.fail("server recv " + rs(c.res))
        elif tag == SS:
            if c.buf:
                lp.recycle(c.buf.take())
        elif tag == CR:
            if c.res <= 0:
                if not self.closing:
                    h.fail("client recv " + rs(c.res))
                return
            if c.res != 64 or mismatch(c.buf.value().readable_span(), i, 0) >= 0:
                self.bad += 1
            lp.recycle(c.buf.take())
            self.msgs += 1
            self.round_of[i] += 1
            if self.round_of[i] < self.rounds:
                _ = h.send(lp, self.clients[i], pattern_buf(64, i), CS | (UInt64(i) << 8))
                _ = h.recv(lp, self.clients[i], c.tag)
            elif self.msgs == self.active * self.rounds:
                self._close_all(h, lp)
        elif tag == CS:
            h.expect(c.res == 64, "client send " + rs(c.res))
        elif tag == END:
            self.closed += 1
            if self.closed == 2 * self.n + 1:
                self.t_closed = Instant.now().as_nanos()
                h.finish(lp)


def test_10k_idle_connections_with_active_subset() raises:
    comptime N = 10_000
    var lim = nofile_limit()
    if lim.max < UInt64(2 * N + 1000):
        print("    (skipped: test_10k_idle_connections_with_active_subset: RLIMIT_NOFILE hard limit", lim.max, ")")
        return
    _ = raise_nofile_limit(UInt64(2 * N + 1000))
    var ev = EventLoop()  # after raising: the fd table is pre-grown to fit
    var x = Ctx[Idle](Idle(N, 100, 50))
    run(ev, x, watchdog_ns=60 * SEC)
    x.h.assert_ok()
    assert_equal(len(x.s.clients), N)
    assert_equal(len(x.s.servers), N)
    assert_equal(x.s.msgs, 100 * 50)
    assert_equal(x.s.bad, 0)
    var connect_ms = (x.s.t_connected - x.s.t_start) // MS
    var active_us = (x.s.t_active - x.s.t_connected) // 1000
    var close_ms = (x.s.t_closed - x.s.t_active) // MS
    print("    10k: connect", connect_ms, "ms; 5000 round trips with", N, "idle:", active_us, "us;",
          "closing", 2 * N + 1, "fds:", close_ms, "ms")
    # Generous bounds: with 10k parked receives, a round trip must not cost
    # anything proportional to the idle connections (~10-30 us here), and
    # closing must stay O(1) per fd (an O(fds) scan per close took seconds).
    assert_true(active_us < 5000 * 400, "active phase too slow with idle connections")
    assert_true(close_ms < 2500, String("closing 20k fds took ", close_ms, " ms"))
    assert_equal(ev.loop.open_fds(), 0)


# ---- fd leaks --------------------------------------------------------------------


struct Churn(Script):
    """Connect/echo/close cycles, refused connects, and connects left
    half-open by a full accept queue and then canceled."""

    var cycles: Int
    var cycle: Int
    var listener: FdId
    var addr: RawSockaddr
    var client: FdId
    var server: FdId
    var ends: Int
    var refused_left: Int
    var dead_addr: RawSockaddr
    var full_listener: FdId
    var pending: List[OpId]
    var stuck_connected: List[FdId]
    var canceled: Int
    var phase: Int

    def __init__(out self):
        self.cycles = 200
        self.cycle = 0
        self.listener = FdId.null()
        self.addr = RawSockaddr()
        self.client = FdId.null()
        self.server = FdId.null()
        self.ends = 0
        self.refused_left = 20
        self.dead_addr = RawSockaddr()
        self.full_listener = FdId.null()
        self.pending = []
        self.stuck_connected = []
        self.canceled = 0
        self.phase = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.listen(lp, loopback(), LIS)

    def _cycle(mut self, mut h: Harness, mut lp: Loop):
        self.ends = 0
        _ = h.connect(lp, self.addr, CON)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if self.phase == 0:
            self._echo_phase(h, lp, c^)
        elif self.phase == 1:
            self._refused_phase(h, lp, c^)
        else:
            self._halfopen_phase(h, lp, c^)

    def _echo_phase(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == LIS:
            self.listener = c.fd
            self.addr = lp.local_addr(c.fd).value().copy()
            _ = h.accept(lp, c.fd, ACC)
            self._cycle(h, lp)
        elif c.tag == ACC:
            if c.more:
                self.server = c.fd
                _ = h.recv(lp, c.fd, SR)
        elif c.tag == CON:
            h.expect(c.ok(), "connect " + rs(c.res))
            self.client = c.fd
            _ = h.send_text(lp, c.fd, "ping", CS)
            _ = h.shutdown(lp, c.fd, SHUT_WR, CS)
            _ = h.recv(lp, c.fd, CR)
        elif c.tag == SR:
            if c.res > 0:
                _ = h.send(lp, c.fd, c.buf.take(), SS)
                _ = h.recv(lp, c.fd, SR)
            else:
                _ = h.close(lp, c.fd, END)
        elif c.tag == SS:
            if c.buf:
                lp.recycle(c.buf.take())
        elif c.tag == CR:
            if c.res > 0:
                lp.recycle(c.buf.take())
                _ = h.recv(lp, c.fd, CR)
            else:
                _ = h.close(lp, c.fd, END)
        elif c.tag == END:
            self.ends += 1
            if self.ends == 2:
                self.cycle += 1
                if self.cycle < self.cycles:
                    self._cycle(h, lp)
                else:
                    # Keep the listener's address, close it: refused connects.
                    self.dead_addr = self.addr.copy()
                    self.phase = 1
                    _ = h.close(lp, self.listener, LIS)

    def _refused_phase(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == ACC:
            return  # the accept ending with ECANCELED
        if c.tag == LIS or c.tag == CON:
            if c.tag == CON:
                h.expect(c.res == ECONNREFUSED, "connect to a closed port: " + rs(c.res))
                self.refused_left -= 1
            if self.refused_left > 0:
                _ = h.connect(lp, self.dead_addr, CON)
            else:
                # Phase 2: a listener with a tiny backlog that never accepts.
                self.phase = 2
                _ = h.listen(lp, loopback(), LIS, backlog=1)

    def _halfopen_phase(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == LIS:
            self.full_listener = c.fd
            var a = lp.local_addr(c.fd).value().copy()
            # The accept queue holds ~2; later SYNs are dropped and those
            # connects stay in SYN_SENT.
            for _ in range(6):
                self.pending.append(h.connect(lp, a, CON))
            _ = h.timeout(lp, 200 * MS, TMO)
        elif c.tag == CON:
            if c.ok():
                self.stuck_connected.append(c.fd)
            elif c.res == ECANCELED:
                self.canceled += 1
            else:
                h.fail("half-open connect: " + rs(c.res))
        elif c.tag == TMO:
            for i in range(len(self.pending)):
                if not h.done(self.pending[i]):
                    _ = h.cancel(lp, self.pending[i], CAN)
            for i in range(len(self.stuck_connected)):
                _ = h.close(lp, self.stuck_connected[i], END)
            _ = h.close(lp, self.full_listener, END)
            h.finish(lp)


def test_no_fd_leak_after_churn_refusals_and_canceled_connects() raises:
    var ev = EventLoop()
    var before = count_open_fds()
    var x = Ctx[Churn](Churn())
    run(ev, x)
    x.h.assert_ok()
    assert_equal(x.s.cycle, x.s.cycles)
    assert_equal(x.s.refused_left, 0)
    assert_true(x.s.canceled >= 1, "precondition: a connect was left half-open")
    var after = count_open_fds()  # while `ev` (its epoll fd) is still alive
    assert_equal(ev.loop.open_fds(), 0)
    assert_equal(after, before)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
