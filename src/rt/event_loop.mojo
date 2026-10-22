"""`EventLoop`: a `Loop` plus its comptime-selected `Driver`, and the run
loop that drives them (docs/rt.md).

`-D MOJO_TCP_SIM=1` selects the in-memory simulator (`rt.sim.SimDriver`);
otherwise the loop runs on the kernel through epoll.
"""

from std.sys import is_defined

from linux import IoError

from .core import Completion, Loop
from .driver import Driver, ReadyEvent
from .epoll_driver import EpollDriver
from .sim import SimDriver

comptime Backend: Driver = SimDriver if is_defined["MOJO_TCP_SIM"]() else EpollDriver
comptime NEAR_TIMER_NS = 10_000_000
"""A timer due sooner than this (from the iteration's clock reading) makes
the loop read the clock again before waiting."""
comptime DISPATCH_ROUNDS = 4
"""Dispatch/flush rounds per iteration before the loop polls again, so
callbacks that keep producing immediate completions cannot starve I/O."""


struct EventLoop(Movable):
    var loop: Loop
    var driver: Backend
    var _events: List[ReadyEvent]

    def __init__(out self) raises IoError:
        self.driver = Backend.create()
        self.loop = Loop(self.driver.now())
        self._events = List[ReadyEvent](capacity=1024)

    def __deinit__(deinit self):
        self.loop.close_all(self.driver)

    def _dispatch(mut self):
        """Run every queued completion, then flush what the callbacks
        submitted; repeat while that produced immediate completions."""
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
        """One iteration: dispatch, wait for readiness (at most `timeout_ns`,
        < 0 = until something happens), apply it, fire timers, dispatch.

        It does not block when there is nothing to wait for: completions or
        submissions are queued, `stop()` was called, or no op is pending."""
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
                # Measured from the iteration's clock reading; only a near
                # deadline is worth a second clock read (a far one fires at
                # most this iteration's dispatch time late, as in libuv).
                var until = next.value() - self.loop.now().as_nanos()
                if until < NEAR_TIMER_NS:
                    until = next.value() - self.driver.now().as_nanos()
                until = max(0, until)
                wait = until if wait < 0 else min(wait, until)
        self._events.clear()
        self.driver.wait(wait, self._events)
        self.loop.set_now(self.driver.now())
        for i in range(len(self._events)):
            self.loop.on_ready(self.driver, self._events[i])
        self.loop.expire_timers()
        self._dispatch()

    def run(mut self) raises IoError:
        """Iterate until `stop()` is called or no op is pending. A stop
        request is consumed when `run()` returns, so it can be called again
        (pending ops stay pending in between)."""
        while not self.loop.stopped() and (
            self.loop.pending_ops() > 0 or self.loop.has_ready()
        ):
            self.run_once()
        self.loop._clear_stop()
