"""Contract tests for the multishot receive (`Loop.recv_multi`, with
`pause_recv` / `resume_recv`), on every backend (epoll and the simulator).
The harness checks every completion: data only in `more=True` chunks of
exactly `res` bytes, one final completion (EOF / error / ECANCELED) without
data, nothing after it, no re-entrancy."""

from std.testing import TestSuite, assert_equal, assert_true

from linux.consts import SHUT_WR
from rt.core import Completion, FdId, Loop, OpId
from rt.event_loop import EventLoop

from test_loop_harness import (
    EBUSY,
    ECANCELED,
    MS,
    Ctx,
    Harness,
    Script,
    mismatch,
    pattern_buf,
    rs,
    run,
)

comptime CS: UInt64 = 1
comptime SR: UInt64 = 2
comptime SH: UInt64 = 3
comptime END: UInt64 = 4
comptime TMO: UInt64 = 5
comptime CAN: UInt64 = 6
comptime SR2: UInt64 = 7
comptime CL: UInt64 = 8


struct MultiTransfer(Script):
    """8 MiB in mixed sends, read by ONE recv_multi: intact, in order, then
    EOF as the final completion."""

    var total: Int
    var nsends: Int
    var sends_done: Int
    var got: Int
    var chunks: Int
    var bad: Int
    var final_res: Int
    var client: FdId
    var server: FdId
    var ends: Int

    def __init__(out self):
        self.total = 8 << 20
        self.nsends = 0
        self.sends_done = 0
        self.got = 0
        self.chunks = 0
        self.bad = 0
        self.final_res = 1
        self.client = FdId.null()
        self.server = FdId.null()
        self.ends = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.open_pair(lp)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.client = h.pairs[i].client
        self.server = h.pairs[i].server
        var sizes = [65536, 1, 1000, 131072, 7, 300000, 16384, 4095]
        var off = 0
        var k = 0
        while off < self.total:
            var n = min(sizes[k % len(sizes)], self.total - off)
            _ = h.send(lp, self.client, pattern_buf(n, 9, off), CS)
            off += n
            k += 1
        self.nsends = k
        _ = h.recv_multi(lp, self.server, SR)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == CS:
            h.expect(c.ok(), "send " + rs(c.res))
            self.sends_done += 1
            if self.sends_done == self.nsends:
                _ = h.shutdown(lp, self.client, SHUT_WR, SH)
        elif c.tag == SR:
            if c.more:
                if mismatch(c.buf.readable_span(), 9, self.got) >= 0:
                    self.bad += 1
                self.got += c.res
                self.chunks += 1
                lp.recycle(c.take_buf())
            else:
                self.final_res = c.res
                _ = h.close(lp, self.server, END)
                _ = h.close(lp, self.client, END)
        elif c.tag == END:
            self.ends += 1
            if self.ends == 2:
                h.finish(lp)


def test_recv_multi_large_transfer_then_eof() raises:
    var ev = EventLoop()
    var x = Ctx[MultiTransfer](MultiTransfer())
    run(ev, x)
    x.h.assert_ok()
    assert_equal(x.s.got, x.s.total)
    assert_equal(x.s.bad, 0)
    assert_equal(x.s.final_res, 0)  # EOF ends the multishot
    assert_true(x.s.chunks > 10)
    assert_equal(ev.loop.open_fds(), 0)


struct PauseResume(Script):
    """While paused, no chunk is produced even as the peer keeps sending;
    after resume everything arrives, in order."""

    var client: FdId
    var server: FdId
    var op: OpId
    var phase: Int
    var got: Int
    var chunks_while_paused: Int
    var bad: Int
    var total: Int
    var ends: Int

    def __init__(out self):
        self.client = FdId.null()
        self.server = FdId.null()
        self.op = OpId.null()
        self.phase = 0
        self.got = 0
        self.chunks_while_paused = 0
        self.bad = 0
        self.total = 4 * 1000
        self.ends = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.open_pair(lp)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.client = h.pairs[i].client
        self.server = h.pairs[i].server
        _ = h.send(lp, self.client, pattern_buf(1000, 3, 0), CS)
        self.op = h.recv_multi(lp, self.server, SR)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == SR:
            if c.more:
                if self.phase == 1:
                    self.chunks_while_paused += 1
                if mismatch(c.buf.readable_span(), 3, self.got) >= 0:
                    self.bad += 1
                self.got += c.res
                lp.recycle(c.take_buf())
                if self.phase == 0 and self.got >= 1000:
                    # Pause, then let the peer send 3000 more bytes while
                    # nothing may be read.
                    self.phase = 1
                    lp.pause_recv(self.server)
                    _ = h.send(lp, self.client, pattern_buf(3000, 3, 1000), CS)
                    _ = h.timeout(lp, 30 * MS, TMO)
                elif self.phase == 2 and self.got == self.total:
                    _ = h.shutdown(lp, self.client, SHUT_WR, SH)
            else:
                h.expect(c.res == 0, "final " + rs(c.res))
                _ = h.close(lp, self.server, END)
                _ = h.close(lp, self.client, END)
        elif c.tag == TMO:
            self.phase = 2
            lp.resume_recv(self.server)
        elif c.tag == END:
            self.ends += 1
            if self.ends == 2:
                h.finish(lp)


def test_recv_multi_pause_produces_nothing_resume_delivers_rest() raises:
    var ev = EventLoop()
    var x = Ctx[PauseResume](PauseResume())
    run(ev, x)
    x.h.assert_ok()
    assert_equal(x.s.chunks_while_paused, 0)
    assert_equal(x.s.got, x.s.total)
    assert_equal(x.s.bad, 0)
    assert_equal(ev.loop.open_fds(), 0)


struct CancelBusyClose(Script):
    """cancel ends a multishot recv (ECANCELED, then cancel 0); a plain recv
    while one is armed gets EBUSY; close ends an armed one before close's
    own completion (the harness checks the order)."""

    var client: FdId
    var server: FdId
    var first: OpId
    var first_final: Int
    var cancel_res: Int
    var busy_res: Int
    var second_final: Int
    var ends: Int

    def __init__(out self):
        self.client = FdId.null()
        self.server = FdId.null()
        self.first = OpId.null()
        self.first_final = 1
        self.cancel_res = 1
        self.busy_res = 1
        self.second_final = 1
        self.ends = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.open_pair(lp)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.client = h.pairs[i].client
        self.server = h.pairs[i].server
        self.first = h.recv_multi(lp, self.server, SR)
        _ = h.cancel(lp, self.first, CAN)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == SR:
            self.first_final = c.res
        elif c.tag == CAN:
            self.cancel_res = c.res
            # Re-arm, then try a plain recv on the same fd (EBUSY), then
            # close with the second multishot still armed.
            _ = h.recv_multi(lp, self.server, SR2)
            _ = h.recv(lp, self.server, CS)
            _ = h.close(lp, self.server, CL)
        elif c.tag == CS:
            self.busy_res = c.res
        elif c.tag == SR2:
            self.second_final = c.res
        elif c.tag == CL:
            _ = h.close(lp, self.client, END)
        elif c.tag == END:
            h.finish(lp)


def test_recv_multi_cancel_busy_and_close() raises:
    var ev = EventLoop()
    var x = Ctx[CancelBusyClose](CancelBusyClose())
    run(ev, x)
    x.h.assert_ok()
    assert_equal(x.s.first_final, ECANCELED)
    assert_equal(x.s.cancel_res, 0)
    assert_equal(x.s.busy_res, EBUSY)
    assert_equal(x.s.second_final, ECANCELED)
    assert_equal(ev.loop.open_fds(), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
