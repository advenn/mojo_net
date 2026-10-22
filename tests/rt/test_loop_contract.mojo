"""Backend-agnostic contract suite for the rt event loop (docs/rt.md, contracts
2-5 of docs/design.md).

Only the public `rt` API is used, so the file runs unchanged on every
backend: `tools/run_tests.sh` runs `*_contract.mojo` files on epoll and
again on the simulator (`-D MOJO_TCP_SIM=1`). Every op goes through the
instrumented harness (`test_loop_harness.mojo`), which checks each
completion against the contract invariants (exactly once, no re-entrancy,
per-fd per-direction FIFO, buffers handed back, two-phase cancel, close
ordering, EBADF after close). The tests below add the scenario-specific
expectations. Port 0 everywhere; each test takes well under a second.
"""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from linux.abi import RawSockaddr
from linux.consts import SHUT_WR
from linux.probe import raise_nofile_limit
from rt.core import RECV_CHUNK, Completion, FdId, Loop, OpId, OpKind
from rt.event_loop import EventLoop

from test_loop_harness import (
    EBADF,
    EBUSY,
    ECANCELED,
    ECONNREFUSED,
    ECONNRESET,
    ENOENT,
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

# Script tags (each script interprets its own).
comptime LIS: UInt64 = 1
comptime ACC: UInt64 = 2
comptime CON: UInt64 = 3
comptime CR: UInt64 = 4
comptime SR: UInt64 = 5
comptime CS: UInt64 = 6
comptime SS: UInt64 = 7
comptime SH: UInt64 = 8
comptime CL: UInt64 = 9
comptime PST: UInt64 = 10
comptime TMO: UInt64 = 11
comptime CAN: UInt64 = 12
comptime STALE: UInt64 = 13
comptime END: UInt64 = 14
comptime LCL: UInt64 = 15
comptime CS0: UInt64 = 16
comptime ACC2: UInt64 = 17
comptime CR2: UInt64 = 18
comptime CAN2: UInt64 = 19
comptime TMO2: UInt64 = 20
comptime CON2: UInt64 = 21
comptime CS2: UInt64 = 22
comptime PST2: UInt64 = 23
comptime CAN3: UInt64 = 24
comptime CAN4: UInt64 = 25
comptime CAN5: UInt64 = 26
comptime LIS2: UInt64 = 27


def _loop_ns(lp: Loop) -> Int:
    return lp.now().as_nanos()


# ---- post ----------------------------------------------------------------------


struct PostOrder(Script):
    var order: List[UInt64]

    def __init__(out self):
        self.order = []

    def start(mut self, mut h: Harness, mut lp: Loop):
        for i in range(50):
            _ = h.post(lp, UInt64(i))

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        self.order.append(c.tag)
        if c.tag < 50 and c.tag % 10 == 0:
            for k in range(3):
                _ = h.post(lp, 1000 + c.tag * 10 + UInt64(k))
        if len(self.order) == 65:
            h.finish(lp)


def test_post_completes_in_submission_order_never_inline() raises:
    var ev = EventLoop()
    var x = Ctx[PostOrder](PostOrder())
    run(ev, x)
    x.h.assert_ok()
    var want = List[UInt64]()
    for i in range(50):
        want.append(UInt64(i))
    for t in range(0, 50, 10):
        for k in range(3):
            want.append(UInt64(1000 + t * 10 + k))
    assert_equal(len(x.s.order), len(want))
    for i in range(len(want)):
        assert_equal(x.s.order[i], want[i])
    assert_equal(ev.loop.pending_ops(), 0)


# ---- timers --------------------------------------------------------------------


struct TimerOrder(Script):
    var delays: List[Int]
    var fired: List[UInt64]

    def __init__(out self):
        self.delays = [30, 10, 20, 10, 0, 10, 5, 30, 0, 20]
        self.fired = []

    def start(mut self, mut h: Harness, mut lp: Loop):
        for i in range(len(self.delays)):
            _ = h.timeout(lp, self.delays[i] * MS, UInt64(i))

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        h.expect(c.res == 0, "timeout res " + rs(c.res))
        self.fired.append(c.tag)
        if len(self.fired) == len(self.delays):
            h.finish(lp)


def test_timers_fire_in_deadline_order_and_ties_fifo() raises:
    var ev = EventLoop()
    var x = Ctx[TimerOrder](TimerOrder())
    run(ev, x)
    x.h.assert_ok()  # also: none fired before its deadline
    # Stable sort of the indices by delay = deadline order, ties FIFO.
    var want = List[UInt64]()
    for d in [0, 5, 10, 20, 30]:
        for i in range(len(x.s.delays)):
            if x.s.delays[i] == d:
                want.append(UInt64(i))
    assert_equal(len(x.s.fired), len(want))
    for i in range(len(want)):
        assert_equal(x.s.fired[i], want[i])


struct TimerStorm(Script):
    var n: Int
    var delay_of: List[Int]
    var fired: List[Int]

    def __init__(out self, n: Int):
        self.n = n
        self.delay_of = []
        self.fired = []

    def start(mut self, mut h: Harness, mut lp: Loop):
        h.keep_recs = False
        for i in range(self.n):
            var d = (i * 7919) % 40  # ms; many ties, many firing together
            self.delay_of.append(d)
            _ = h.timeout(lp, d * MS, UInt64(i))

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        self.fired.append(Int(c.tag))
        if len(self.fired) == self.n:
            h.finish(lp)


def test_timer_storm_fires_each_once_in_deadline_order() raises:
    var ev = EventLoop()
    var x = Ctx[TimerStorm](TimerStorm(5000))
    run(ev, x)
    x.h.assert_ok()  # exactly once, none early
    assert_equal(len(x.s.fired), x.s.n)
    for k in range(1, len(x.s.fired)):
        var a = x.s.fired[k - 1]
        var b = x.s.fired[k]
        var da = x.s.delay_of[a]
        var db = x.s.delay_of[b]
        assert_true(da < db or (da == db and a < b), String("timer ", b, " fired after ", a))


struct ZeroTimer(Script):
    var fired: Int

    def __init__(out self):
        self.fired = 0

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        self.fired += 1
        h.expect(c.res == 0, "timeout(0) res " + rs(c.res))
        if self.fired == 1:
            _ = h.timeout(lp, 0, TMO2)  # submitted from a callback


def test_timeout_zero_fires_on_the_next_iteration() raises:
    var ev = EventLoop()
    var x = Ctx[ZeroTimer](ZeroTimer())
    bind(x)
    var t0 = _loop_ns(ev.loop)
    _ = x.h.timeout(ev.loop, 0, TMO)
    # One iteration (bounded at 2 s in case the loop wrongly waits).
    ev.run_once(2 * SEC)
    assert_equal(x.s.fired, 1)
    ev.run_once(2 * SEC)
    assert_equal(x.s.fired, 2)
    assert_true(_loop_ns(ev.loop) - t0 < SEC, "a zero timeout waited")
    x.h.assert_ok()
    assert_equal(ev.loop.pending_ops(), 0)


# ---- cancel --------------------------------------------------------------------


struct CancelRecv(Script):
    var r: OpId
    var c: OpId
    var client: FdId
    var server: FdId
    var got: String
    var closed: Int

    def __init__(out self):
        self.r = OpId.null()
        self.c = OpId.null()
        self.client = FdId.null()
        self.server = FdId.null()
        self.got = ""
        self.closed = 0

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.client = h.pairs[i].client
        self.server = h.pairs[i].server
        self.r = h.recv(lp, self.client, CR)  # parks: no data yet
        _ = h.post(lp, PST)  # cancel from a later batch

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == PST:
            self.c = h.cancel(lp, self.r, CAN)
        elif c.tag == CR:
            h.expect(c.res == ECANCELED, "canceled recv res " + rs(c.res))
            h.expect(self.c.raw != 0 and not h.done(self.c), "cancel completed before its target")
        elif c.tag == CAN:
            h.expect(c.res == 0, "cancel res " + rs(c.res))
            # The connection still works and the recv slot is free again.
            _ = h.send_text(lp, self.server, "abc", SS)
            _ = h.recv(lp, self.client, CR2)
        elif c.tag == CR2:
            self.got = text_of(c)
            if c.buf:
                lp.recycle(c.buf.take())
            _ = h.close(lp, self.client, END)
            _ = h.close(lp, self.server, END)
        elif c.tag == END:
            self.closed += 1
            if self.closed == 2:
                h.finish(lp)

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.open_pair(lp)


def test_cancel_pending_recv_two_phase() raises:
    var ev = EventLoop()
    var x = Ctx[CancelRecv](CancelRecv())
    run(ev, x)
    x.h.assert_ok()
    assert_equal(x.h.res_of(x.s.r), ECANCELED)
    assert_equal(x.h.res_of(x.s.c), 0)
    assert_true(x.h.seq_of(x.s.r) < x.h.seq_of(x.s.c))
    assert_equal(x.s.got, "abc")
    assert_equal(ev.loop.open_fds(), 0)


struct CancelFinished(Script):
    var p: OpId
    var cans: List[OpId]

    def __init__(out self):
        self.p = OpId.null()
        self.cans = []

    def start(mut self, mut h: Harness, mut lp: Loop):
        self.p = h.post(lp, PST)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == PST:
            self.cans.append(h.cancel(lp, self.p, CAN))  # already finished
            self.cans.append(h.cancel(lp, OpId.of(5, 999), CAN))  # never existed
            self.cans.append(h.cancel(lp, OpId.null(), CAN))
        elif c.tag == CAN:
            h.expect(c.res == ENOENT, "cancel of a finished op: " + rs(c.res))
            var all_done = True
            for i in range(len(self.cans)):
                if not h.done(self.cans[i]):
                    all_done = False
            if all_done:
                h.finish(lp)


def test_cancel_of_finished_or_unknown_op_is_enoent() raises:
    var ev = EventLoop()
    var x = Ctx[CancelFinished](CancelFinished())
    run(ev, x)
    x.h.assert_ok()
    assert_equal(len(x.s.cans), 3)
    for i in range(3):
        assert_equal(x.h.res_of(x.s.cans[i]), ENOENT)
    assert_equal(x.h.res_of(x.s.p), 0)


struct CancelTimeout(Script):
    var t: OpId
    var z: OpId
    var c1: OpId
    var c2: OpId
    var n: Int

    def __init__(out self):
        self.t = OpId.null()
        self.z = OpId.null()
        self.c1 = OpId.null()
        self.c2 = OpId.null()
        self.n = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        self.t = h.timeout(lp, 10 * SEC, TMO)
        self.z = h.timeout(lp, 0, TMO2)
        _ = h.post(lp, PST)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        self.n += 1
        if c.tag == PST:
            self.c1 = h.cancel(lp, self.t, CAN)
        elif c.tag == TMO2:
            h.expect(c.res == 0, "timeout(0) res " + rs(c.res))
            self.c2 = h.cancel(lp, self.z, CAN2)  # it already fired
        if self.n == 5:  # post, both timeouts, both cancels
            h.finish(lp)


def test_cancel_timeout_and_fired_timeout() raises:
    var ev = EventLoop()
    var x = Ctx[CancelTimeout](CancelTimeout())
    var t0 = _loop_ns(ev.loop)
    run(ev, x)
    x.h.assert_ok()
    assert_equal(x.h.res_of(x.s.t), ECANCELED)
    assert_equal(x.h.res_of(x.s.c1), 0)
    assert_true(x.h.seq_of(x.s.t) < x.h.seq_of(x.s.c1))
    assert_equal(x.h.res_of(x.s.z), 0)
    assert_equal(x.h.res_of(x.s.c2), ENOENT)
    assert_true(_loop_ns(ev.loop) - t0 < 5 * SEC, "waited for a canceled timer")


struct CancelSameBatch(Script):
    """Ops canceled in the batch that submitted them."""

    var ids: List[OpId]
    var cans: List[OpId]
    var recv_i: Int
    var timeout_i: Int
    var accept_i: Int
    var client: FdId
    var server: FdId
    var got: String
    var closed: Int
    var stage2: Bool

    def __init__(out self):
        self.ids = []
        self.cans = []
        self.recv_i = -1
        self.timeout_i = -1
        self.accept_i = -1
        self.client = FdId.null()
        self.server = FdId.null()
        self.got = ""
        self.closed = 0
        self.stage2 = False

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.open_pair(lp)
        _ = h.listen(lp, loopback(), LIS)

    def _maybe_stage2(mut self, mut h: Harness, mut lp: Loop):
        if self.stage2 or len(self.cans) < 5:
            return
        for i in range(len(self.cans)):
            if not h.done(self.cans[i]):
                return
        self.stage2 = True
        # The canceled recv freed the fd's recv slot.
        _ = h.recv(lp, self.client, CR2)
        _ = h.send_text(lp, self.server, "z", SS)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.client = h.pairs[i].client
        self.server = h.pairs[i].server
        var r = h.recv(lp, self.client, CR)
        self.recv_i = len(self.ids)
        self.ids.append(r)
        self.cans.append(h.cancel(lp, r, CAN))
        var t = h.timeout(lp, 5 * SEC, TMO)
        self.timeout_i = len(self.ids)
        self.ids.append(t)
        self.cans.append(h.cancel(lp, t, CAN))
        var p = h.post(lp, PST)
        self.ids.append(p)
        self.cans.append(h.cancel(lp, p, CAN))
        var s = h.send_text(lp, self.client, "x", CS)
        self.ids.append(s)
        self.cans.append(h.cancel(lp, s, CAN))

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == LIS:
            h.expect(c.ok(), "listen " + rs(c.res))
            var a = h.accept(lp, c.fd, ACC)
            self.accept_i = len(self.ids)
            self.ids.append(a)
            self.cans.append(h.cancel(lp, a, CAN))
            _ = h.close(lp, c.fd, END)
        elif c.tag == CR2:
            self.got = text_of(c)
            if c.buf:
                lp.recycle(c.buf.take())
            _ = h.close(lp, self.client, END)
            _ = h.close(lp, self.server, END)
        elif c.tag == END:
            self.closed += 1
            if self.closed == 3:
                h.finish(lp)
        self._maybe_stage2(h, lp)


def test_cancel_of_op_submitted_in_same_batch() raises:
    var ev = EventLoop()
    var x = Ctx[CancelSameBatch](CancelSameBatch())
    run(ev, x)
    x.h.assert_ok()  # each pair is consistent: (ECANCELED, 0) or (result, ENOENT)
    assert_equal(len(x.s.ids), 5)
    # A recv, a timeout and an accept cannot have finished: they were canceled.
    for i in [x.s.recv_i, x.s.timeout_i, x.s.accept_i]:
        assert_equal(x.h.res_of(x.s.ids[i]), ECANCELED)
        assert_equal(x.h.res_of(x.s.cans[i]), 0)
    assert_equal(x.s.got, "z")
    assert_equal(ev.loop.open_fds(), 0)


# ---- close -----------------------------------------------------------------------


struct CloseCancels(Script):
    var client: FdId
    var server: FdId
    var listener: FdId
    var nsends: Int
    var ok_sends: Int
    var canceled_sends: Int
    var sent_bytes: Int
    var got: Int
    var bad_data: Bool
    var ends: Int
    var accept_res: Int

    def __init__(out self):
        self.client = FdId.null()
        self.server = FdId.null()
        self.listener = FdId.null()
        self.nsends = 256
        self.ok_sends = 0
        self.canceled_sends = 0
        self.sent_bytes = 0
        self.got = 0
        self.bad_data = False
        self.ends = 0
        self.accept_res = 1

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.open_pair(lp)
        _ = h.listen(lp, loopback(), LIS)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.client = h.pairs[i].client
        self.server = h.pairs[i].server
        # 16 MiB cannot fit in the kernel's buffers while nobody reads, so
        # most sends are still queued when the close comes.
        _ = h.recv(lp, self.client, CR)
        for k in range(self.nsends):
            _ = h.send(lp, self.client, pattern_buf(65536, 1, k * 65536), CS)
        _ = h.close(lp, self.client, CL)
        _ = h.recv(lp, self.server, SR)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == CR:
            h.expect(c.res == ECANCELED, "pending recv at close: " + rs(c.res))
        elif c.tag == CS:
            if c.res >= 0:
                self.ok_sends += 1
                self.sent_bytes += c.res
            else:
                h.expect(c.res == ECANCELED, "pending send at close: " + rs(c.res))
                self.canceled_sends += 1
        elif c.tag == CL:
            h.expect(c.res == 0, "close " + rs(c.res))
        elif c.tag == SR:
            if c.res > 0:
                if mismatch(c.buf.value().readable_span(), 1, self.got) >= 0:
                    self.bad_data = True
                self.got += c.res
                lp.recycle(c.buf.take())
                _ = h.recv(lp, self.server, SR)
            else:
                h.expect(c.res == 0, "server recv after peer close: " + rs(c.res))
                _ = h.close(lp, self.server, END)
        elif c.tag == LIS:
            self.listener = c.fd
            _ = h.accept(lp, c.fd, ACC)
            _ = h.post(lp, PST)  # close it once the accept is parked
        elif c.tag == PST:
            _ = h.close(lp, self.listener, END)
        elif c.tag == ACC:
            h.expect(not c.more, "accept on an idle listener produced a connection")
            self.accept_res = c.res
        elif c.tag == END:
            self.ends += 1
            if self.ends == 2:
                h.finish(lp)


def test_close_cancels_pending_ops_before_completing() raises:
    var ev = EventLoop()
    var x = Ctx[CloseCancels](CloseCancels())
    run(ev, x)
    x.h.assert_ok()  # ordering: every canceled op before its close; buffers back
    assert_equal(x.s.ok_sends + x.s.canceled_sends, x.s.nsends)
    assert_true(x.s.canceled_sends > 0, "no send was pending at close")
    assert_equal(x.s.accept_res, ECANCELED)
    assert_false(x.s.bad_data, "server received corrupted data")
    # Completed sends reached the peer; a canceled one may have gone out
    # partly before the close.
    assert_true(x.s.got >= x.s.sent_bytes, "completed sends were lost")
    assert_true(x.s.got <= x.s.nsends * 65536)
    assert_equal(ev.loop.open_fds(), 0)


struct StaleFd(Script):
    var listener: FdId
    var addr: RawSockaddr
    var c1: FdId
    var c2: FdId
    var servers: List[FdId]
    var stale_done: Int
    var fresh: String
    var ends: Int
    var reused: Bool

    def __init__(out self):
        self.listener = FdId.null()
        self.addr = RawSockaddr()
        self.c1 = FdId.null()
        self.c2 = FdId.null()
        self.servers = []
        self.stale_done = 0
        self.fresh = ""
        self.ends = 0
        self.reused = False

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.listen(lp, loopback(), LIS)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == LIS:
            self.listener = c.fd
            self.addr = lp.local_addr(c.fd).value().copy()
            _ = h.accept(lp, c.fd, ACC)
            _ = h.connect(lp, self.addr, CON)
        elif c.tag == ACC:
            if c.more:
                self.servers.append(c.fd)
                _ = h.recv(lp, c.fd, SR)
                if len(self.servers) == 2:
                    _ = h.close(lp, self.listener, END)
        elif c.tag == CON:
            h.expect(c.ok(), "connect " + rs(c.res))
            self.c1 = c.fd
            _ = h.close(lp, self.c1, CL)
        elif c.tag == CL:
            h.expect(c.res == 0, "close " + rs(c.res))
            _ = h.connect(lp, self.addr, CON2)  # reuses c1's slot
        elif c.tag == CON2:
            h.expect(c.ok(), "connect " + rs(c.res))
            self.c2 = c.fd
            self.reused = self.c2.slot() == self.c1.slot() and self.c2 != self.c1
            # Every op on the stale id fails with EBADF (the harness checks
            # it), however the new occupant of the slot is doing.
            _ = h.recv(lp, self.c1, STALE)
            _ = h.send_text(lp, self.c1, "stale", STALE)
            _ = h.shutdown(lp, self.c1, SHUT_WR, STALE)
            _ = h.accept(lp, self.c1, STALE)
            _ = h.close(lp, self.c1, STALE)
            _ = h.send_text(lp, self.c2, "fresh", CS)
            _ = h.recv(lp, self.c2, CR)
        elif c.tag == STALE:
            h.expect(c.res == EBADF, String("op on a stale fd: ", c.kind, " ", rs(c.res)))
            self.stale_done += 1
        elif c.tag == SR:
            if c.res > 0:
                self.fresh += text_of(c)
                lp.recycle(c.buf.take())
                _ = h.recv(lp, c.fd, SR)
            else:
                _ = h.close(lp, c.fd, END)
                if c.fd != self.servers[0] or len(self.servers) == 1:
                    pass
        elif c.tag == CR:
            h.expect(c.res == 0, "client 2 recv: expected EOF, got " + rs(c.res))
            _ = h.close(lp, self.c2, END)
        elif c.tag == END:
            self.ends += 1
            # listener, two server ends, c2
            if self.ends == 4:
                h.finish(lp)
        if self.fresh == "fresh" and len(self.servers) == 2:
            self.fresh = "fresh!"  # once: close the server end that got it
            _ = h.close(lp, self.servers[1], END)


def test_ops_on_stale_fd_fail_ebadf_after_slot_reuse() raises:
    var ev = EventLoop()
    var x = Ctx[StaleFd](StaleFd())
    run(ev, x)
    x.h.assert_ok()
    assert_true(x.s.reused, "precondition: the new socket reuses the closed slot")
    assert_equal(x.s.stale_done, 5)
    assert_equal(x.s.fresh, "fresh!")
    assert_equal(ev.loop.open_fds(), 0)


struct DoubleRecv(Script):
    var client: FdId
    var server: FdId
    var r1: OpId
    var r2: OpId
    var a2_res: Int
    var a1_res: Int
    var got: String
    var ends: Int

    def __init__(out self):
        self.client = FdId.null()
        self.server = FdId.null()
        self.r1 = OpId.null()
        self.r2 = OpId.null()
        self.a2_res = 1
        self.a1_res = 1
        self.got = ""
        self.ends = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.open_pair(lp)
        _ = h.listen(lp, loopback(), LIS)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.client = h.pairs[i].client
        self.server = h.pairs[i].server
        self.r1 = h.recv(lp, self.client, CR)
        self.r2 = h.recv(lp, self.client, CR2)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == CR2:
            h.expect(c.res == EBUSY, "second recv on one fd: " + rs(c.res))
            _ = h.send_text(lp, self.server, "hi", SS)
        elif c.tag == CR:
            self.got = text_of(c)
            if c.buf:
                lp.recycle(c.buf.take())
            _ = h.close(lp, self.client, END)
            _ = h.close(lp, self.server, END)
        elif c.tag == LIS:
            _ = h.accept(lp, c.fd, ACC)
            _ = h.accept(lp, c.fd, ACC2)
            _ = h.close(lp, c.fd, END)
        elif c.tag == ACC2:
            self.a2_res = c.res
        elif c.tag == ACC:
            self.a1_res = c.res
        elif c.tag == END:
            self.ends += 1
            if self.ends == 3:
                h.finish(lp)


def test_second_recv_or_accept_on_one_fd_is_ebusy() raises:
    var ev = EventLoop()
    var x = Ctx[DoubleRecv](DoubleRecv())
    run(ev, x)
    x.h.assert_ok()
    assert_equal(x.h.res_of(x.s.r2), EBUSY)
    assert_equal(x.s.got, "hi")  # the first recv was unaffected
    assert_equal(x.s.a2_res, EBUSY)
    assert_equal(x.s.a1_res, ECANCELED)


# ---- data transfer ---------------------------------------------------------------


struct EchoSizes(Script):
    var sizes: List[Int]
    var i: Int
    var got: Int
    var client: FdId
    var server: FdId
    var ends: Int
    var bad: Int
    var zero_sends: Int

    def __init__(out self):
        self.sizes = [0, 1, 2, 3, 100, 0, 1460, 4096, 16383, 16384, 16385, 65535, 65536, 200000, 1 << 20, 3 << 20]
        self.i = 0
        self.got = 0
        self.client = FdId.null()
        self.server = FdId.null()
        self.ends = 0
        self.bad = 0
        self.zero_sends = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.open_pair(lp)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.client = h.pairs[i].client
        self.server = h.pairs[i].server
        _ = h.recv(lp, self.server, SR)
        _ = h.recv(lp, self.client, CR)
        self._next(h, lp)

    def _next(mut self, mut h: Harness, mut lp: Loop):
        # A 0-byte send completes with 0 and its buffer; nothing arrives.
        while self.i < len(self.sizes) and self.sizes[self.i] == 0:
            _ = h.send(lp, self.client, ByteBuffer(), CS0)
            self.i += 1
        if self.i == len(self.sizes):
            _ = h.shutdown(lp, self.client, SHUT_WR, SH)
            return
        self.got = 0
        _ = h.send(lp, self.client, pattern_buf(self.sizes[self.i], self.i), CS)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == SR:
            if c.res > 0:
                _ = h.send(lp, self.server, c.buf.take(), SS)  # echo the buffer itself
                _ = h.recv(lp, self.server, SR)
            else:
                h.expect(c.res == 0, "server recv " + rs(c.res))
                _ = h.close(lp, self.server, END)
        elif c.tag == SS:
            h.expect(c.res > 0, "echo send " + rs(c.res))
            if c.buf:
                lp.recycle(c.buf.take())
        elif c.tag == CS0:
            h.expect(c.res == 0, "0-byte send " + rs(c.res))
            self.zero_sends += 1
        elif c.tag == CS:
            h.expect(c.res > 0, "send " + rs(c.res))
        elif c.tag == CR:
            if c.res > 0:
                if self.i >= len(self.sizes):
                    h.fail("data after the last message")
                    return
                if mismatch(c.buf.value().readable_span(), self.i, self.got) >= 0:
                    self.bad += 1
                self.got += c.res
                lp.recycle(c.buf.take())
                if self.got > self.sizes[self.i]:
                    h.fail("echo returned more than was sent")
                elif self.got == self.sizes[self.i]:
                    self.i += 1
                    self._next(h, lp)
                _ = h.recv(lp, self.client, CR)
            else:
                h.expect(c.res == 0, "client recv " + rs(c.res))
                h.expect(self.i == len(self.sizes), "EOF before the last echo")
                _ = h.close(lp, self.client, END)
        elif c.tag == END:
            self.ends += 1
            if self.ends == 2:
                h.finish(lp)


def test_echo_of_many_sizes_including_zero() raises:
    var ev = EventLoop()
    var x = Ctx[EchoSizes](EchoSizes())
    run(ev, x)
    x.h.assert_ok()
    assert_equal(x.s.i, len(x.s.sizes))
    assert_equal(x.s.bad, 0)
    assert_equal(x.s.zero_sends, 2)
    assert_equal(ev.loop.open_fds(), 0)


struct BigTransfer(Script):
    var total: Int
    var nsends: Int
    var sends_done: Int
    var got: Int
    var bad: Int
    var client: FdId
    var server: FdId
    var ends: Int
    var server_eof_at: Int

    def __init__(out self):
        self.total = 32 << 20
        self.nsends = 0
        self.sends_done = 0
        self.got = 0
        self.bad = 0
        self.client = FdId.null()
        self.server = FdId.null()
        self.ends = 0
        self.server_eof_at = -1

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.open_pair(lp)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.client = h.pairs[i].client
        self.server = h.pairs[i].server
        # Every send queued at once, of mixed sizes: the kernel takes a few
        # MiB, so most sends wait and many writes are partial.
        var sizes = [65536, 1, 1000, 131072, 7, 300000, 16384, 4095]
        var off = 0
        var k = 0
        while off < self.total:
            var n = min(sizes[k % len(sizes)], self.total - off)
            _ = h.send(lp, self.client, pattern_buf(n, 5, off), CS)
            off += n
            k += 1
        self.nsends = k
        _ = h.recv(lp, self.server, SR)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == CS:
            h.expect(c.ok(), "send " + rs(c.res))
            self.sends_done += 1
            if self.sends_done == self.nsends:
                _ = h.shutdown(lp, self.client, SHUT_WR, SH)
                _ = h.recv(lp, self.client, CR)
        elif c.tag == SR:
            if c.res > 0:
                if mismatch(c.buf.value().readable_span(), 5, self.got) >= 0:
                    self.bad += 1
                self.got += c.res
                lp.recycle(c.buf.take())
                _ = h.recv(lp, self.server, SR)
            else:
                h.expect(c.res == 0, "server recv " + rs(c.res))
                self.server_eof_at = self.got
                _ = h.close(lp, self.server, END)
        elif c.tag == SH:
            h.expect(c.res == 0, "shutdown " + rs(c.res))
        elif c.tag == CR:
            h.expect(c.res == 0, "client recv: expected EOF, got " + rs(c.res))
            _ = h.close(lp, self.client, END)
        elif c.tag == END:
            self.ends += 1
            if self.ends == 2:
                h.finish(lp)


def test_large_transfer_arrives_intact_and_in_order() raises:
    var ev = EventLoop()
    var x = Ctx[BigTransfer](BigTransfer())
    run(ev, x)
    x.h.assert_ok()
    assert_equal(x.s.server_eof_at, x.s.total)
    assert_equal(x.s.bad, 0)
    assert_true(x.s.nsends > 100)
    assert_equal(ev.loop.open_fds(), 0)


struct ShutdownAfterSends(Script):
    """A shutdown(SHUT_WR) right behind a send the kernel cannot take at once:
    the FIN must follow the data, not cut it off."""

    var total: Int
    var got: Int
    var bad: Int
    var client: FdId
    var server: FdId
    var eof_at: Int
    var send_res: Int
    var ends: Int

    def __init__(out self):
        self.total = 8 << 20
        self.got = 0
        self.bad = 0
        self.client = FdId.null()
        self.server = FdId.null()
        self.eof_at = -1
        self.send_res = 0
        self.ends = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.open_pair(lp)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.client = h.pairs[i].client
        self.server = h.pairs[i].server
        _ = h.send(lp, self.client, pattern_buf(self.total, 9), CS)
        _ = h.shutdown(lp, self.client, SHUT_WR, SH)
        _ = h.recv(lp, self.server, SR)
        _ = h.recv(lp, self.client, CR)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == CS:
            self.send_res = c.res
        elif c.tag == SH:
            h.expect(c.res == 0, "shutdown " + rs(c.res))
        elif c.tag == SR:
            if c.res > 0:
                if mismatch(c.buf.value().readable_span(), 9, self.got) >= 0:
                    self.bad += 1
                self.got += c.res
                lp.recycle(c.buf.take())
                _ = h.recv(lp, self.server, SR)
            else:
                self.eof_at = self.got
                _ = h.close(lp, self.server, END)
        elif c.tag == CR:
            h.expect(c.res == 0, "client recv: expected EOF, got " + rs(c.res))
            _ = h.close(lp, self.client, END)
        elif c.tag == END:
            self.ends += 1
            if self.ends == 2:
                h.finish(lp)


def test_shutdown_write_waits_for_queued_sends() raises:
    var ev = EventLoop()
    var x = Ctx[ShutdownAfterSends](ShutdownAfterSends())
    run(ev, x)
    x.h.assert_ok()  # includes: the shutdown completed after the send (FIFO)
    assert_equal(x.s.send_res, x.s.total)
    assert_equal(x.s.eof_at, x.s.total)
    assert_equal(x.s.bad, 0)


struct HalfClose(Script):
    var client: FdId
    var server: FdId
    var s_got: String
    var c_got: String
    var late_res: Int
    var eof2_res: Int
    var ends: Int

    def __init__(out self):
        self.client = FdId.null()
        self.server = FdId.null()
        self.s_got = ""
        self.c_got = ""
        self.late_res = 0
        self.eof2_res = 1
        self.ends = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.open_pair(lp)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.client = h.pairs[i].client
        self.server = h.pairs[i].server
        _ = h.send_text(lp, self.client, "hello", CS)
        _ = h.shutdown(lp, self.client, SHUT_WR, SH)
        _ = h.recv(lp, self.server, SR)
        _ = h.recv(lp, self.client, CR)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == SR:
            if c.res > 0:
                self.s_got += text_of(c)
                lp.recycle(c.buf.take())
                _ = h.recv(lp, self.server, SR)
            else:
                h.expect(c.res == 0, "server recv " + rs(c.res))
                # The client's FIN does not stop the server from answering.
                _ = h.send_text(lp, self.server, "world", SS)
                _ = h.recv(lp, self.server, SR2)
        elif c.tag == SR2:
            self.eof2_res = c.res  # EOF again: it is sticky
            _ = h.close(lp, self.server, END)
        elif c.tag == SS:
            h.expect(c.res == 5, "server send " + rs(c.res))
        elif c.tag == CR:
            if c.res > 0:
                self.c_got += text_of(c)
                lp.recycle(c.buf.take())
                _ = h.recv(lp, self.client, CR)
            else:
                h.expect(c.res == 0, "client recv " + rs(c.res))
                _ = h.send_text(lp, self.client, "late", CS2)
        elif c.tag == CS2:
            self.late_res = c.res  # after our own SHUT_WR: an error, buffer back
            _ = h.close(lp, self.client, END)
        elif c.tag == END:
            self.ends += 1
            if self.ends == 2:
                h.finish(lp)


comptime SR2: UInt64 = 40


def test_half_close_peer_sees_eof_and_can_still_send() raises:
    var ev = EventLoop()
    var x = Ctx[HalfClose](HalfClose())
    run(ev, x)
    x.h.assert_ok()
    assert_equal(x.s.s_got, "hello")
    assert_equal(x.s.c_got, "world")
    assert_equal(x.s.eof2_res, 0)
    assert_true(x.s.late_res < 0, "send after SHUT_WR succeeded")


struct FinWithData(Script):
    """The spike's lost-EOF bug: data and FIN arrive together (the client
    sends and shuts down at once), before the server reads. A short read
    must not end reading: the server has to see the data and then EOF."""

    var rounds: Int
    var round: Int
    var listener: FdId
    var addr: RawSockaddr
    var client: FdId
    var server: FdId
    var n: Int
    var s_got: Int
    var bad: Int
    var round_ends: Int
    var eofs: Int

    def __init__(out self):
        self.rounds = 60
        self.round = 0
        self.listener = FdId.null()
        self.addr = RawSockaddr()
        self.client = FdId.null()
        self.server = FdId.null()
        self.n = 0
        self.s_got = 0
        self.bad = 0
        self.round_ends = 0
        self.eofs = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.listen(lp, loopback(), LIS)

    def _size(self) -> Int:
        if self.round % 5 == 4:
            return 100_000  # several chunks, all after read_closed is known
        return 1 if self.round % 2 == 0 else 3000

    def _begin(mut self, mut h: Harness, mut lp: Loop):
        self.n = self._size()
        self.s_got = 0
        self.round_ends = 0
        _ = h.connect(lp, self.addr, CON)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == LIS:
            self.listener = c.fd
            self.addr = lp.local_addr(c.fd).value().copy()
            _ = h.accept(lp, c.fd, ACC)
            self._begin(h, lp)
        elif c.tag == CON:
            h.expect(c.ok(), "connect " + rs(c.res))
            self.client = c.fd
            _ = h.send(lp, self.client, pattern_buf(self.n, self.round), CS)
            _ = h.shutdown(lp, self.client, SHUT_WR, SH)
            _ = h.recv(lp, self.client, CR)
        elif c.tag == ACC:
            if not c.more:
                h.expect(c.res == ECANCELED, "accept end " + rs(c.res))
                return
            self.server = c.fd
            var mode = self.round % 3
            if mode == 0:
                _ = h.recv(lp, self.server, SR)
            elif mode == 1:
                _ = h.post(lp, PST)
            else:
                _ = h.timeout(lp, 2 * MS, TMO)  # data and FIN surely there
        elif c.tag == PST or c.tag == TMO:
            _ = h.recv(lp, self.server, SR)
        elif c.tag == SR:
            if c.res > 0:
                if mismatch(c.buf.value().readable_span(), self.round, self.s_got) >= 0:
                    self.bad += 1
                self.s_got += c.res
                lp.recycle(c.buf.take())
                _ = h.recv(lp, self.server, SR)
            else:
                h.expect(c.res == 0, "server recv " + rs(c.res))
                h.expect(self.s_got == self.n, String("round ", self.round, ": EOF after ", self.s_got, " of ", self.n))
                self.eofs += 1
                _ = h.close(lp, self.server, END)
        elif c.tag == CR:
            h.expect(c.res == 0, "client recv " + rs(c.res))
            _ = h.close(lp, self.client, END)
        elif c.tag == END:
            self.round_ends += 1
            if self.round_ends == 2:
                self.round += 1
                if self.round < self.rounds:
                    self._begin(h, lp)
                else:
                    _ = h.close(lp, self.listener, LCL)
        elif c.tag == LCL:
            h.finish(lp)


def test_fin_arriving_with_data_is_not_lost() raises:
    var ev = EventLoop()
    var x = Ctx[FinWithData](FinWithData())
    run(ev, x)
    x.h.assert_ok()
    assert_equal(x.s.round, x.s.rounds)
    assert_equal(x.s.eofs, x.s.rounds)
    assert_equal(x.s.bad, 0)
    assert_equal(ev.loop.open_fds(), 0)


struct ResetOnUnread(Script):
    var client: FdId
    var server: FdId
    var recv_res: Int
    var send2_res: Int
    var ends: Int

    def __init__(out self):
        self.client = FdId.null()
        self.server = FdId.null()
        self.recv_res = 1
        self.send2_res = 1
        self.ends = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.open_pair(lp)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.client = h.pairs[i].client
        self.server = h.pairs[i].server
        _ = h.recv(lp, self.client, CR)  # parked until the reset
        _ = h.send(lp, self.client, pattern_buf(200_000, 3), CS)
        _ = h.recv(lp, self.server, SR)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == CS:
            # All of it buffered, or cut off by the reset.
            h.expect(c.res == 200_000 or c.res < 0, "send " + rs(c.res))
        elif c.tag == SR:
            h.expect(c.res > 0, "server recv " + rs(c.res))
            if c.buf:
                lp.recycle(c.buf.take())
            _ = h.timeout(lp, 20 * MS, TMO)  # let the rest arrive, unread
        elif c.tag == TMO:
            _ = h.close(lp, self.server, END)  # unread data: the kernel sends RST
        elif c.tag == CR:
            self.recv_res = c.res
            _ = h.send_text(lp, self.client, "after", CS2)
        elif c.tag == CS2:
            self.send2_res = c.res
            _ = h.close(lp, self.client, END)
        elif c.tag == END:
            self.ends += 1
            if self.ends == 2:
                h.finish(lp)


def test_peer_close_with_unread_data_resets_connection() raises:
    var ev = EventLoop()
    var x = Ctx[ResetOnUnread](ResetOnUnread())
    run(ev, x)
    x.h.assert_ok()  # includes: the failed send handed its buffer back
    assert_equal(x.s.recv_res, ECONNRESET)
    assert_true(x.s.send2_res < 0, "send after a reset succeeded")


struct Refused(Script):
    var addr: RawSockaddr
    var n: Int
    var i: Int
    var leaks: Int
    var refused: Int

    def __init__(out self):
        self.addr = RawSockaddr()
        self.n = 20
        self.i = 0
        self.leaks = 0
        self.refused = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.listen(lp, loopback(), LIS)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == LIS:
            self.addr = lp.local_addr(c.fd).value().copy()
            _ = h.close(lp, c.fd, LCL)  # nothing listens there any more
        elif c.tag == LCL:
            _ = h.connect(lp, self.addr, CON)
        elif c.tag == CON:
            if c.res == ECONNREFUSED:
                self.refused += 1
            else:
                h.fail("connect to a closed port: " + rs(c.res))
                if c.ok():
                    _ = h.close(lp, c.fd, CL)
            if lp.open_fds() != 0:
                self.leaks += 1
            self.i += 1
            if self.i < self.n:
                _ = h.connect(lp, self.addr, CON)
            else:
                h.finish(lp)


def test_connect_refused_reports_econnrefused_without_leak() raises:
    var ev = EventLoop()
    var x = Ctx[Refused](Refused())
    run(ev, x)
    x.h.assert_ok()
    assert_equal(x.s.refused, x.s.n)
    assert_equal(x.s.leaks, 0)
    assert_equal(ev.loop.open_fds(), 0)


struct Storm(Script):
    var n: Int
    var listener: FdId
    var accepted: Int
    var connected: Int
    var conns: List[FdId]
    var closing: Bool
    var closed: Int
    var no_peer: Int

    def __init__(out self, n: Int):
        self.n = n
        self.listener = FdId.null()
        self.accepted = 0
        self.connected = 0
        self.conns = []
        self.closing = False
        self.closed = 0
        self.no_peer = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.listen(lp, loopback(), LIS, backlog=4096)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == LIS:
            self.listener = c.fd
            _ = h.accept(lp, c.fd, ACC)
            var addr = lp.local_addr(c.fd).value().copy()
            for _ in range(self.n):
                _ = h.connect(lp, addr, CON)
        elif c.tag == ACC:
            if c.more:
                self.accepted += 1
                if not lp.peer_addr(c.fd):
                    self.no_peer += 1
                self.conns.append(c.fd)
            else:
                h.expect(c.res == ECANCELED, "accept end " + rs(c.res))
        elif c.tag == CON:
            h.expect(c.ok(), "connect " + rs(c.res))
            if c.ok():
                self.connected += 1
                self.conns.append(c.fd)
        elif c.tag == CL:
            self.closed += 1
            if self.closed == len(self.conns) + 1:
                h.finish(lp)
        if not self.closing and self.accepted == self.n and self.connected == self.n:
            self.closing = True
            _ = h.close(lp, self.listener, CL)
            for i in range(len(self.conns)):
                _ = h.close(lp, self.conns[i], CL)


def test_accept_storm_of_2000_connections() raises:
    _ = raise_nofile_limit(16384)
    var ev = EventLoop()
    var x = Ctx[Storm](Storm(2000))
    run(ev, x)
    x.h.assert_ok()
    assert_equal(x.s.accepted, 2000)
    assert_equal(x.s.connected, 2000)
    assert_equal(x.s.no_peer, 0)
    assert_equal(ev.loop.open_fds(), 0)


struct ConcurrentEcho(Script):
    """Many connections, each with many sends queued at once, echoed by the
    server: per-fd FIFO under interleaving."""

    var n: Int
    var msgs: Int
    var clients: List[FdId]
    var got: List[Int]
    var want: List[Int]
    var bad: Int
    var ends: Int
    var paired: Int

    def __init__(out self, n: Int, msgs: Int):
        self.n = n
        self.msgs = msgs
        self.clients = []
        self.got = []
        self.want = []
        self.bad = 0
        self.ends = 0
        self.paired = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        for _ in range(self.n):
            _ = h.open_pair(lp)
            self.got.append(0)
            self.want.append(0)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        var client = h.pairs[i].client
        var server = h.pairs[i].server
        # Tag low bits carry the pair index.
        var off = 0
        for k in range(self.msgs):
            var size = 1 + (k * 7919 + i * 104729) % 20000
            _ = h.send(lp, client, pattern_buf(size, i, off), CS | (UInt64(i) << 8))
            off += size
        self.want[i] = off
        _ = h.shutdown(lp, client, SHUT_WR, SH | (UInt64(i) << 8))
        _ = h.recv(lp, client, CR | (UInt64(i) << 8))
        _ = h.recv(lp, server, SR | (UInt64(i) << 8))

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        var i = Int(c.tag >> 8)
        var tag = c.tag & 0xFF
        if tag == SR:
            if c.res > 0:
                _ = h.send(lp, c.fd, c.buf.take(), SS | (UInt64(i) << 8))
                _ = h.recv(lp, c.fd, c.tag)
            else:
                h.expect(c.res == 0, "server recv " + rs(c.res))
                _ = h.close(lp, c.fd, END)
        elif tag == SS:
            if c.buf:
                lp.recycle(c.buf.take())
        elif tag == CR:
            if c.res > 0:
                if mismatch(c.buf.value().readable_span(), i, self.got[i]) >= 0:
                    self.bad += 1
                self.got[i] += c.res
                lp.recycle(c.buf.take())
                _ = h.recv(lp, c.fd, c.tag)
            else:
                h.expect(c.res == 0, "client recv " + rs(c.res))
                h.expect(self.got[i] == self.want[i], "short echo")
                _ = h.close(lp, c.fd, END)
        elif tag == END:
            self.ends += 1
            if self.ends == 2 * self.n:
                h.finish(lp)


def test_concurrent_connections_each_fifo() raises:
    var ev = EventLoop()
    var x = Ctx[ConcurrentEcho](ConcurrentEcho(48, 24))
    run(ev, x)
    x.h.assert_ok()
    assert_equal(x.s.bad, 0)
    for i in range(x.s.n):
        assert_equal(x.s.got[i], x.s.want[i])
    assert_equal(ev.loop.open_fds(), 0)


# ---- regressions (review of rt.core) -----------------------------------------------


struct CanceledTimerLast(Script):
    var t: OpId

    def __init__(out self):
        self.t = OpId.null()

    def start(mut self, mut h: Harness, mut lp: Loop):
        self.t = h.timeout(lp, 10 * SEC, TMO)
        _ = h.post(lp, PST)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == PST:
            _ = h.cancel(lp, self.t, CAN)


def test_canceled_timer_does_not_delay_run_exit() raises:
    """Regression: once the last op completed, run_once still slept until
    the deadline of a canceled timer whose heap entry was left behind (lazy
    deletion), so run() returned 10 s late."""
    var ev = EventLoop()
    var x = Ctx[CanceledTimerLast](CanceledTimerLast())
    var t0 = _loop_ns(ev.loop)
    run(ev, x, watchdog_ns=0)
    x.h.assert_ok()
    assert_equal(x.h.res_of(x.s.t), ECANCELED)
    assert_true(_loop_ns(ev.loop) - t0 < SEC, "run() waited for a canceled timer")


struct ManyCanceledTimers(Script):
    var n: Int
    var done: Int
    var peak: Int

    def __init__(out self, n: Int):
        self.n = n
        self.done = 0
        self.peak = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        h.keep_recs = False
        _ = h.post(lp, PST)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == PST:
            # A timeout per "request", canceled when the request finishes.
            for _ in range(self.n):
                var t = h.timeout(lp, 60 * SEC, TMO)
                _ = h.cancel(lp, t, CAN)
        elif c.tag == CAN:
            self.done += 1
            self.peak = max(self.peak, lp.timer_entries())
            if self.done == self.n:
                h.finish(lp)


def test_canceled_timers_do_not_accumulate() raises:
    """Regression: canceled timeouts left their heap entries until the
    deadline passed, so a timeout per request grew the heap without bound."""
    var ev = EventLoop()
    var x = Ctx[ManyCanceledTimers](ManyCanceledTimers(20_000))
    run(ev, x)
    x.h.assert_ok()
    assert_true(x.s.peak < 5000, String("timer heap grew to ", x.s.peak))
    assert_true(ev.loop.timer_entries() < 5000)


struct RecycledBigBuffer(Script):
    var client: FdId
    var server: FdId
    var got: Int
    var biggest: Int
    var ends: Int

    def __init__(out self):
        self.client = FdId.null()
        self.server = FdId.null()
        self.got = 0
        self.biggest = 0
        self.ends = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.open_pair(lp)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.client = h.pairs[i].client
        self.server = h.pairs[i].server
        try:
            lp.recycle(ByteBuffer(capacity=4 << 20))  # e.g. a send buffer
        except:
            pass
        _ = h.send(lp, self.client, pattern_buf(1 << 20, 2), CS)
        _ = h.shutdown(lp, self.client, SHUT_WR, SH)
        _ = h.timeout(lp, 10 * MS, TMO)  # let it all arrive: big reads if allowed

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == TMO:
            _ = h.recv(lp, self.server, SR)
        elif c.tag == SR:
            if c.res > 0:
                self.biggest = max(self.biggest, c.res)
                self.got += c.res
                lp.recycle(c.buf.take())
                _ = h.recv(lp, self.server, SR)
            else:
                _ = h.close(lp, self.server, END)
                _ = h.close(lp, self.client, END)
        elif c.tag == END:
            self.ends += 1
            if self.ends == 2:
                h.finish(lp)


def test_recycled_large_buffer_does_not_enlarge_receives() raises:
    """Regression: `recycle` pooled any buffer of at least RECV_CHUNK bytes,
    so a recycled 4 MiB send buffer was reused for a receive that returned
    far more than RECV_CHUNK (and the pool could pin GiBs)."""
    var ev = EventLoop()
    var x = Ctx[RecycledBigBuffer](RecycledBigBuffer())
    run(ev, x)
    x.h.assert_ok()  # also checks res <= RECV_CHUNK on every recv
    assert_equal(x.s.got, 1 << 20)
    assert_true(x.s.biggest <= RECV_CHUNK)


struct CancelHeadSend(Script):
    """A write shutdown queued behind a send that is canceled while partly
    written must run at once: nothing else will make the write queue move
    (the peer is not reading, so no writable edge comes)."""

    var client: FdId
    var server: FdId
    var send_id: OpId
    var left: Int
    var sh_res: Int
    var got: Int
    var ends: Int

    def __init__(out self):
        self.client = FdId.null()
        self.server = FdId.null()
        self.send_id = OpId.null()
        self.left = -1
        self.sh_res = 1
        self.got = 0
        self.ends = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.open_pair(lp)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.client = h.pairs[i].client
        self.server = h.pairs[i].server
        self.send_id = h.send(lp, self.client, pattern_buf(32 << 20, 4), CS)
        _ = h.shutdown(lp, self.client, SHUT_WR, SH)
        _ = h.post(lp, PST)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == PST:
            _ = h.cancel(lp, self.send_id, CAN)
        elif c.tag == CS:
            h.expect(c.res == ECANCELED, "send " + rs(c.res))
            if c.buf:
                self.left = c.buf.value().readable()  # the unsent rest
        elif c.tag == SH:
            self.sh_res = c.res
            _ = h.recv(lp, self.server, SR)  # only now start reading
        elif c.tag == SR:
            if c.res > 0:
                if mismatch(c.buf.value().readable_span(), 4, self.got) >= 0:
                    h.fail("corrupted data")
                self.got += c.res
                lp.recycle(c.buf.take())
                _ = h.recv(lp, self.server, SR)
            else:
                h.expect(c.res == 0, "server recv " + rs(c.res))
                _ = h.close(lp, self.server, END)
                _ = h.close(lp, self.client, END)
        elif c.tag == END:
            self.ends += 1
            if self.ends == 2:
                h.finish(lp)


def test_cancel_of_partly_sent_head_lets_queued_shutdown_run() raises:
    var ev = EventLoop()
    var x = Ctx[CancelHeadSend](CancelHeadSend())
    run(ev, x)
    x.h.assert_ok()
    assert_equal(x.s.sh_res, 0)
    assert_true(x.s.left > 0, "precondition: the send was still in progress")
    # The peer got exactly the bytes that left before the cancel, then EOF.
    assert_equal(x.s.got, (32 << 20) - x.s.left)


struct FarTimer(Script):
    var t: OpId
    var fired_res: Int

    def __init__(out self):
        self.t = OpId.null()
        self.fired_res = 1

    def start(mut self, mut h: Harness, mut lp: Loop):
        self.t = h.timeout(lp, Int.MAX, TMO)  # "never"
        _ = h.timeout(lp, 5 * MS, TMO2)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == TMO2:
            _ = h.cancel(lp, self.t, CAN)
        elif c.tag == TMO:
            self.fired_res = c.res
        elif c.tag == CAN:
            h.finish(lp)


def test_huge_timeout_saturates_instead_of_firing() raises:
    """Regression: timeout_ns(Int.MAX) overflowed the deadline into the past
    and fired at once."""
    var ev = EventLoop()
    var x = Ctx[FarTimer](FarTimer())
    run(ev, x)
    x.h.assert_ok()
    assert_equal(x.s.fired_res, ECANCELED)


# ---- stop and teardown -------------------------------------------------------------


struct Stopper(Script):
    var listener: FdId
    var accept_res: Int

    def __init__(out self):
        self.listener = FdId.null()
        self.accept_res = 1

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.listen(lp, loopback(), LIS)
        _ = h.post(lp, PST)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == LIS:
            self.listener = c.fd
            _ = h.accept(lp, c.fd, ACC)  # pending: nobody connects
        elif c.tag == PST:
            lp.stop()
        elif c.tag == ACC:
            self.accept_res = c.res
        elif c.tag == LCL:
            h.finish(lp)


def test_stop_inside_callback_makes_run_return() raises:
    var ev = EventLoop()
    var x = Ctx[Stopper](Stopper())
    var t0 = _loop_ns(ev.loop)
    run(ev, x)  # returns although the accept is pending
    assert_true(_loop_ns(ev.loop) - t0 < 5 * SEC, "run() did not return promptly after stop()")
    x.h.assert_ok(allow_pending=True)
    assert_true(ev.loop.pending_ops() > 0)
    assert_equal(x.s.accept_res, 1)  # still pending
    # The loop is usable again: clean up and run to completion.
    _ = x.h.close(ev.loop, x.s.listener, LCL)
    ev.run()
    x.h.assert_ok()
    assert_equal(x.s.accept_res, ECANCELED)
    assert_equal(ev.loop.pending_ops(), 0)


struct DropWithPending(Script):
    var paired: Bool

    def __init__(out self):
        self.paired = False

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.open_pair(lp)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.paired = True
        _ = h.recv(lp, h.pairs[i].client, CR)
        _ = h.send(lp, h.pairs[i].server, pattern_buf(1000, 1), SS)
        _ = h.listen(lp, loopback(), LIS)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == LIS:
            _ = h.accept(lp, c.fd, ACC)
            lp.stop()
        elif c.tag == CR:
            if c.buf:
                lp.recycle(c.buf.take())
            _ = h.recv(lp, c.fd, CR)


def _drop_scenario() raises -> Int:
    var ev = EventLoop()
    var x = Ctx[DropWithPending](DropWithPending())
    run(ev, x)
    x.h.assert_ok(allow_pending=True)
    assert_true(x.s.paired)
    var during = count_open_fds()
    assert_equal(ev.loop.open_fds(), 3)  # client, server, listener
    assert_true(ev.loop.pending_ops() > 0)
    return during  # `ev` is dropped here, with ops pending


def test_eventloop_drop_closes_every_fd() raises:
    var before = count_open_fds()
    var during = _drop_scenario()
    var after = count_open_fds()
    assert_true(during >= before)
    assert_equal(after, before)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
