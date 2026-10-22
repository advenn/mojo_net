"""Event-loop rules checked with exact syscall counts and injected errors
(the `linux.fault` seam: this file is built with -D MOJO_NET_FAULTS=1).

- Syscall budget (docs/rt.md, epoll rules from the spike): a request/
  response costs one recv and one send per side, with no EAGAIN probe read,
  no epoll_ctl per op, and a bounded number of clock reads per wait.
- EINTR on recv/send/accept is retried transparently; close is never
  retried (Linux has released the fd even on EINTR).
- Accept under EMFILE pauses: a bounded number of accept syscalls while
  the error persists, and accepting resumes once it clears.
- A failed registration drops that one connection and accepting goes on.

An injected error is returned without issuing the syscall. An injected
EINTR on close therefore leaves that socket open in the kernel (leaked for
the rest of this process); the loop has forgotten it either way.

Scripts that read harness state between `run_once` calls keep `x` a local
of the test function (see test_loop_epoll.mojo for why).
"""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from linux import Errno, fault
from linux.consts import SHUT_WR
from linux.nr import (
    SYS_accept4,
    SYS_clock_gettime,
    SYS_close,
    SYS_connect,
    SYS_epoll_ctl,
    SYS_epoll_pwait,
    SYS_epoll_pwait2,
    SYS_recvfrom,
    SYS_sendto,
)
from rt.core import Completion, FdId, Loop, OpId, OpKind
from rt.event_loop import EventLoop

from test_loop_harness import (
    ECANCELED,
    MS,
    SEC,
    Ctx,
    Harness,
    Script,
    bind,
    loopback,
    mismatch,
    pattern_buf,
    rs,
    run,
)

comptime LIS: UInt64 = 1
comptime ACC: UInt64 = 2
comptime CON: UInt64 = 3
comptime CR: UInt64 = 4
comptime SR: UInt64 = 5
comptime CS: UInt64 = 6
comptime SS: UInt64 = 7
comptime END: UInt64 = 8


def _waits() -> Int:
    return fault.calls(SYS_epoll_pwait) + fault.calls(SYS_epoll_pwait2)


# ---- syscall budget ------------------------------------------------------------


struct PingPong(Script):
    var client: FdId
    var server: FdId
    var warm: Int
    var m: Int
    var i: Int
    var recvs: Int
    var sends: Int
    var ctls: Int
    var waits: Int
    var clocks: Int
    var connects: Int
    var bad: Int
    var ends: Int

    def __init__(out self, m: Int):
        self.client = FdId.null()
        self.server = FdId.null()
        self.warm = 10
        self.m = m
        self.i = 0
        self.recvs = -1
        self.sends = -1
        self.ctls = -1
        self.waits = -1
        self.clocks = -1
        self.connects = -1
        self.bad = 0
        self.ends = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        fault.clear()
        _ = h.open_pair(lp)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.connects = fault.calls(SYS_connect)
        self.client = h.pairs[i].client
        self.server = h.pairs[i].server
        _ = h.recv(lp, self.server, SR)
        self._ping(h, lp)

    def _ping(mut self, mut h: Harness, mut lp: Loop):
        _ = h.send(lp, self.client, pattern_buf(64, self.i), CS)
        _ = h.recv(lp, self.client, CR)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == SR:
            if c.res > 0:
                _ = h.send(lp, self.server, c.take_buf(), SS)  # echo
                _ = h.recv(lp, self.server, SR)
            else:
                _ = h.close(lp, self.server, END)
        elif c.tag == SS:
            if c.has_buf():
                lp.recycle(c.take_buf())
        elif c.tag == CR:
            if c.res <= 0:
                h.fail("client recv " + rs(c.res))
                return
            if c.res != 64 or mismatch(c.buf.readable_span(), self.i, 0) >= 0:
                self.bad += 1
            lp.recycle(c.take_buf())
            self.i += 1
            if self.i == self.warm:
                fault.clear()  # steady state from here
            if self.i == self.warm + self.m:
                self.recvs = fault.calls(SYS_recvfrom)
                self.sends = fault.calls(SYS_sendto)
                self.ctls = fault.calls(SYS_epoll_ctl)
                self.waits = _waits()
                self.clocks = fault.calls(SYS_clock_gettime)
                _ = h.shutdown(lp, self.client, SHUT_WR, CS)
                _ = h.close(lp, self.client, END)
                return
            self._ping(h, lp)
        elif c.tag == END:
            self.ends += 1
            if self.ends == 2:
                h.finish(lp)


def test_request_response_costs_one_recv_and_one_send_per_side() raises:
    var ev = EventLoop()
    var x = Ctx[PingPong](PingPong(1000))
    run(ev, x)
    x.h.assert_ok()
    var m = x.s.m
    print("    budget:", m, "round trips:", x.s.recvs, "recv,", x.s.sends, "send,", x.s.ctls,
          "epoll_ctl,", x.s.waits, "waits,", x.s.clocks, "clock reads")
    assert_equal(x.s.bad, 0)
    # Each round trip: client send, server recv, server send, client recv.
    assert_equal(x.s.sends, 2 * m)
    assert_equal(x.s.recvs, 2 * m)  # no EAGAIN probe reads
    assert_equal(x.s.ctls, 0)  # registered once; no EPOLL_CTL_MOD per op
    # The clock is read once per loop iteration (after the wait), never per
    # event or per op; the only timer (the harness watchdog) is far away.
    assert_true(x.s.clocks <= x.s.waits + 2, "more than one clock read per iteration")
    assert_equal(x.s.connects, 1)  # connect issued once (EINPROGRESS)
    fault.clear()


# ---- EINTR ---------------------------------------------------------------------


struct EintrEcho(Script):
    """Ping-pong of 1000-byte messages, so there are plenty of recv and send
    calls for the EINTR schedule to hit."""

    var client: FdId
    var server: FdId
    var msgs: Int
    var k: Int
    var got: Int
    var bad: Int
    var ends: Int
    var listener: FdId

    def __init__(out self):
        self.client = FdId.null()
        self.server = FdId.null()
        self.msgs = 30
        self.k = 0
        self.got = 0
        self.bad = 0
        self.ends = 0
        self.listener = FdId.null()

    def start(mut self, mut h: Harness, mut lp: Loop):
        fault.clear()
        _ = h.listen(lp, loopback(), LIS)

    def _ping(mut self, mut h: Harness, mut lp: Loop):
        _ = h.send(lp, self.client, pattern_buf(1000, 7, self.k * 1000), CS)
        _ = h.recv(lp, self.client, CR)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == LIS:
            self.listener = c.fd
            try:
                fault.inject(SYS_accept4, Errno.EINTR, times=2)
                fault.inject(SYS_recvfrom, Errno.EINTR, skip=1, every=3, times=4)
                fault.inject(SYS_sendto, Errno.EINTR, every=2, times=4)
            except:
                h.fail("fault.inject")
            _ = h.accept(lp, c.fd, ACC)
            _ = h.connect(lp, lp.local_addr(c.fd).value(), CON)
        elif c.tag == ACC:
            if c.more:
                self.server = c.fd
                _ = h.recv(lp, c.fd, SR)
                _ = h.close(lp, self.listener, END)
        elif c.tag == CON:
            h.expect(c.ok(), "connect " + rs(c.res))
            self.client = c.fd
            self._ping(h, lp)
        elif c.tag == CS:
            h.expect(c.res >= 0, "send/shutdown " + rs(c.res))
        elif c.tag == SR:
            if c.res > 0:
                _ = h.send(lp, c.fd, c.take_buf(), SS)
                _ = h.recv(lp, c.fd, SR)
            else:
                h.expect(c.res == 0, "server recv " + rs(c.res))
                _ = h.close(lp, c.fd, END)
        elif c.tag == SS:
            h.expect(c.res > 0, "echo " + rs(c.res))
            if c.has_buf():
                lp.recycle(c.take_buf())
        elif c.tag == CR:
            if c.res > 0:
                if mismatch(c.buf.readable_span(), 7, self.got) >= 0:
                    self.bad += 1
                self.got += c.res
                lp.recycle(c.take_buf())
                if self.got == (self.k + 1) * 1000:
                    self.k += 1
                    if self.k == self.msgs:
                        _ = h.shutdown(lp, c.fd, SHUT_WR, CS)
                    else:
                        _ = h.send(lp, self.client, pattern_buf(1000, 7, self.k * 1000), CS)
                _ = h.recv(lp, c.fd, CR)
            else:
                h.expect(c.res == 0, "client recv " + rs(c.res))
                _ = h.close(lp, c.fd, END)
        elif c.tag == END:
            self.ends += 1
            if self.ends == 3:
                h.finish(lp)


def test_eintr_on_recv_send_accept_is_retried() raises:
    var ev = EventLoop()
    var x = Ctx[EintrEcho](EintrEcho())
    run(ev, x)
    var left = fault.pending()
    fault.clear()
    x.h.assert_ok()
    assert_equal(left, 0)  # every planned EINTR was hit
    assert_equal(x.s.got, x.s.msgs * 1000)
    assert_equal(x.s.bad, 0)


struct CloseEintr(Script):
    var close_calls: Int
    var close_res: Int
    var ends: Int
    var server: FdId
    var client: FdId

    def __init__(out self):
        self.close_calls = -1
        self.close_res = 1
        self.ends = 0
        self.server = FdId.null()
        self.client = FdId.null()

    def start(mut self, mut h: Harness, mut lp: Loop):
        fault.clear()
        _ = h.open_pair(lp)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.server = h.pairs[i].server
        self.client = h.pairs[i].client
        _ = h.post(lp, SS)  # after the fixture's listener close went out

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == SS:
            fault.clear()
            try:
                fault.inject(SYS_close, Errno.EINTR, times=1)
            except:
                h.fail("fault.inject")
            _ = h.close(lp, self.client, CS)
        elif c.tag == CS:
            self.close_res = c.res
            self.close_calls = fault.calls(SYS_close)
            _ = h.close(lp, self.server, END)
        elif c.tag == END:
            h.finish(lp)


def test_close_eintr_is_success_and_never_retried() raises:
    var ev = EventLoop()
    var x = Ctx[CloseEintr](CloseEintr())
    run(ev, x)
    fault.clear()
    x.h.assert_ok()
    assert_equal(x.s.close_res, 0)
    assert_equal(x.s.close_calls, 1)  # a retry could close a reused fd number
    assert_equal(ev.loop.open_fds(), 0)


# ---- accept under fd exhaustion ------------------------------------------------


struct AcceptEmfile(Script):
    var listener: FdId
    var accepted: List[FdId]
    var conns: List[FdId]
    var ends: Int
    var n: Int

    def __init__(out self, n: Int):
        self.listener = FdId.null()
        self.accepted = []
        self.conns = []
        self.ends = 0
        self.n = n

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == LIS:
            self.listener = c.fd
            var a = lp.local_addr(c.fd).value().copy()
            for _ in range(self.n):
                _ = h.connect(lp, a, CON)
        elif c.tag == ACC:
            if c.more:
                self.accepted.append(c.fd)
        elif c.tag == CON:
            h.expect(c.ok(), "connect " + rs(c.res))
            if c.ok():
                self.conns.append(c.fd)
        elif c.tag == END:
            self.ends += 1


def _window(mut ev: EventLoop, ns: Int) raises -> Int:
    var t0 = ev.loop.now().as_nanos()
    var n = 0
    while ev.loop.now().as_nanos() - t0 < ns:
        ev.run_once(50 * MS)
        n += 1
    return n


def test_accept_emfile_pauses_with_bounded_syscalls_then_resumes() raises:
    comptime N = 20
    comptime K = 5
    fault.clear()
    var ev = EventLoop()
    var x = Ctx[AcceptEmfile](AcceptEmfile(N))
    bind(x)
    _ = x.h.listen(ev.loop, loopback(), LIS)
    _ = _window(ev, 50 * MS)  # all N connected (they sit in the accept queue)
    assert_equal(len(x.s.conns), N)
    fault.clear()
    fault.inject(SYS_accept4, Errno.EMFILE, skip=K, times=-1)
    _ = x.h.accept(ev.loop, x.s.listener, ACC)
    var iters = _window(ev, 400 * MS)
    var calls = fault.calls(SYS_accept4)
    var paused_at = len(x.s.accepted)
    fault.clear()  # the "fds" are back; the retry timer resumes accepting
    _ = _window(ev, 250 * MS)
    var resumed = len(x.s.accepted)
    print("    emfile (injected): accepted", paused_at, "with", calls, "accept4 calls and", iters,
          "iterations in 400 ms; then", resumed)
    assert_equal(paused_at, K)
    # K successes, then one EMFILE per retry tick (100 ms): never a spin.
    assert_true(calls <= K + 1 + 5, String(calls, " accept4 calls while paused"))
    assert_true(iters <= 40, String(iters, " iterations while paused"))
    assert_equal(resumed, N)
    for i in range(len(x.s.accepted)):
        _ = x.h.close(ev.loop, x.s.accepted[i], END)
    for i in range(len(x.s.conns)):
        _ = x.h.close(ev.loop, x.s.conns[i], END)
    _ = x.h.close(ev.loop, x.s.listener, END)
    ev.run()
    x.h.assert_ok()
    assert_equal(x.s.ends, 2 * N + 1)
    assert_equal(ev.loop.open_fds(), 0)


# ---- registration failure ------------------------------------------------------


struct RegisterFails(Script):
    var listener: FdId
    var accepted: Int
    var addr_ok: Bool
    var client_res: List[Int]
    var conns: List[FdId]
    var n: Int
    var done: Int

    def __init__(out self):
        self.listener = FdId.null()
        self.accepted = 0
        self.addr_ok = False
        self.client_res = []
        self.conns = []
        self.n = 3
        self.done = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        fault.clear()
        _ = h.listen(lp, loopback(), LIS)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        if c.tag == LIS:
            self.listener = c.fd
            for _ in range(self.n):
                _ = h.connect(lp, lp.local_addr(c.fd).value(), CON)
            _ = h.post(lp, SS)  # once the connects (and their epoll_ctl) went out
        elif c.tag == SS:
            # The next registration is the first accepted socket's: fail it.
            try:
                fault.inject(SYS_epoll_ctl, Errno.ENOMEM, times=1)
            except:
                h.fail("fault.inject")
            _ = h.accept(lp, self.listener, ACC)
        elif c.tag == CON:
            self.client_res.append(c.res)
            if c.ok():
                self.conns.append(c.fd)
                _ = h.recv(lp, c.fd, CR)
        elif c.tag == ACC:
            if c.more:
                self.accepted += 1
                self.conns.append(c.fd)
        elif c.tag == CR:
            # The connection whose accepted end could not be registered was
            # closed by the loop: its client sees EOF (or a reset).
            self.done += 1
            if c.has_buf():
                lp.recycle(c.take_buf())
        if self.done == 1 and self.accepted == self.n - 1:
            self.done = 2
            for i in range(len(self.conns)):
                _ = h.close(lp, self.conns[i], END)
            _ = h.close(lp, self.listener, END)
            h.finish(lp)


def test_failed_registration_drops_one_connection_and_accept_goes_on() raises:
    var ev = EventLoop()
    var x = Ctx[RegisterFails](RegisterFails())
    run(ev, x)
    var left = fault.pending()
    fault.clear()
    x.h.assert_ok()
    assert_equal(left, 0)
    assert_equal(len(x.s.client_res), 3)
    assert_equal(x.s.accepted, 2)
    assert_equal(ev.loop.open_fds(), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
