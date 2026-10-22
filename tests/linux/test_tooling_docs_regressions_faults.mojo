"""Regression tests (review group "tooling-docs") for linux-layer branches
that the live host never takes, driven through the syscall fault seam
(built with -D MOJO_NET_FAULTS=1 because of the `_faults.mojo` suffix).

- Epoll.wait's epoll_pwait2 -> epoll_pwait fallback (ENOSYS/EPERM, the
  seccomp/Docker path): it switches permanently, serves the same call, and
  no other errno falls back.
- probe classification: io_uring per errno, has_epoll_pwait2 under
  ENOSYS/EPERM, cpu_count's bounded mask growth on EINVAL.
- EINTR retries in EventFd.add/signal, EventFd.drain, Epoll's epoll_ctl
  wrappers and probe's procfs reader.
- EINTR retries in poll_until, wait_ready and sleep under real signals,
  proven by syscall counts (a retry test that only checks timing passes
  even when the signal landed before the syscall and nothing was
  retried), with the first signal deliberately landing early.

Every test starts with `fault.clear()`: the plan is process-global, and a
rule left by a test that failed midway must not leak into the next one.
"""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Errno, ErrorKind, IoError, OwnedFd, check, fault, sys
from linux.abi import EpollEvent, Pollfd
from linux.consts import (
    AF_UNIX,
    AT_PAGESZ,
    CLOCK_MONOTONIC,
    EPOLLIN,
    POLLIN,
    SIGALRM,
    SIGEV_THREAD_ID,
    SOCK_CLOEXEC,
    SOCK_STREAM,
)
from linux.epoll import Epoll
from linux.eventfd import EventFd
from linux.nr import (
    SYS_clock_nanosleep,
    SYS_epoll_ctl,
    SYS_epoll_pwait,
    SYS_epoll_pwait2,
    SYS_gettid,
    SYS_io_uring_setup,
    SYS_openat,
    SYS_ppoll,
    SYS_read,
    SYS_sched_getaffinity,
    SYS_timer_create,
    SYS_timer_delete,
    SYS_timer_settime,
    SYS_write,
)
from linux.poll import poll_until, ppoll, wait_ready
from linux.probe import (
    IoUringSupport,
    auxv_lookup,
    cpu_count,
    has_epoll_pwait2,
    page_size,
    probe_io_uring,
)
from linux.syscall import err_of, is_err, syscall0, syscall1, syscall3, syscall4
from linux.time import Deadline, Duration, Instant, sleep

comptime IN = UInt32(EPOLLIN)


# ---- helpers -----------------------------------------------------------------


def _ms(n: Int) -> Duration:
    return Duration.from_millis(n)


def _pair() raises -> Tuple[OwnedFd, OwnedFd]:
    var fds = Array[Int32, 2](fill=-1)
    _ = check(
        "socketpair",
        sys.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds),
    )
    return (OwnedFd(unsafe_from_raw=fds[0]), OwnedFd(unsafe_from_raw=fds[1]))


def _events(n: Int) -> List[EpollEvent]:
    return List[EpollEvent](capacity=n)


def _spin(d: Duration):
    """Busy-wait without any interruptible syscall: this thread reaches its
    blocking call late, so a signal due meanwhile is handled before it."""
    var t = Instant.now()
    while t.elapsed() < d:
        pass


struct _SignalBurst:
    """`count` SIGALRMs aimed at this thread, `gap_ms` apart, the first one
    `first_ms` from now (test-only; the library installs no handlers).

    - One-shot POSIX timers with SIGEV_THREAD_ID: a process-directed signal
      (setitimer, kill) may be taken by any runtime thread that does not
      block it, and would then interrupt nothing.
    - The handler is CPython's C-level one (installed without SA_RESTART
      through Python interop), so the interrupted syscall fails with EINTR.
    - Several signals: if this thread is delayed past the first one (CPU
      throttling, VM steal), it is handled before the blocking call starts
      and a later one still interrupts the call.
    - A bounded burst: a wait that wrongly restarted its full timeout after
      EINTR still ends (and fails its timing check) instead of hanging."""

    var timers: List[Int32]
    var signal: PythonObject
    var counter: PythonObject

    def __init__(
        out self, first_ms: Int, count: Int = 5, gap_ms: Int = 20
    ) raises:
        self.signal = Python.import_module("signal")
        self.counter = Python.evaluate("[0]")
        var make = Python.evaluate(
            "lambda c: (lambda s, f: c.__setitem__(0, c[0] + 1))"
        )
        _ = self.signal.signal(SIGALRM, make(self.counter))
        self.timers = List[Int32]()
        var tid = syscall0(SYS_gettid)
        for _ in range(count):
            # struct sigevent (64 bytes): sigev_value at 0, sigev_signo at
            # 8, sigev_notify at 12, _tid at 16.
            var sev = Array[Int32, 16](fill=0)
            sev[2] = Int32(SIGALRM)
            sev[3] = Int32(SIGEV_THREAD_ID)
            sev[4] = Int32(tid)
            var id: Int32 = -1
            _ = check(
                "timer_create",
                syscall3(
                    SYS_timer_create,
                    CLOCK_MONOTONIC,
                    Int(Pointer(to=sev)),
                    Int(Pointer(to=id)),
                ),
            )
            sys.keep_alive(sev)
            self.timers.append(id)
        for i in range(count):
            # struct itimerspec: it_interval (0: one-shot), it_value.
            var spec = Array[Int, 4](fill=0)
            var ns = (first_ms + i * gap_ms) * 1_000_000
            spec[2] = ns // 1_000_000_000
            spec[3] = ns % 1_000_000_000
            _ = check(
                "timer_settime",
                syscall4(
                    SYS_timer_settime,
                    Int(self.timers[i]),
                    0,
                    Int(Pointer(to=spec)),
                    0,
                ),
            )
            sys.keep_alive(spec)

    def stop(mut self) raises -> Int:
        """Delete the timers, run the pending Python handler, restore
        SIG_DFL. Returns how often the handler ran: CPython coalesces
        signals that arrive before it runs, so this is >= 1 when any
        arrived, not the number of signals."""
        for t in self.timers:
            _ = check("timer_delete", syscall1(SYS_timer_delete, Int(t)))
        self.timers.clear()
        _ = Python.evaluate("[i for i in range(3)]")  # runs pending handlers
        _ = self.signal.signal(SIGALRM, self.signal.SIG_DFL)
        return Int(py=self.counter[0])

    def __deinit__(deinit self):
        # A test that raised before stop(): disarm what is left.
        for t in self.timers:
            _ = syscall1(SYS_timer_delete, Int(t))


# ---- Epoll.wait: epoll_pwait2 -> epoll_pwait fallback (F16) ------------------


def test_wait_falls_back_on_enosys_and_eperm_in_same_call() raises:
    for e in [Errno.ENOSYS, Errno.EPERM]:
        fault.clear()
        var ep = Epoll.new()
        var ev = EventFd.new()
        ep.add(ev, IN, 0xABCD)
        ev.signal()
        var evs = _events(4)
        fault.clear()
        fault.inject(SYS_epoll_pwait2, e, times=1)
        # The same call is served by epoll_pwait: the event is not lost and
        # the caller never sees ENOSYS/EPERM. (Bounded timeouts everywhere
        # here: a regression must fail, not hang.)
        assert_equal(ep.wait(evs, Duration.from_secs(5)), 1, String(e))
        assert_equal(len(evs), 1)
        assert_equal(evs[0].data(), UInt64(0xABCD))
        assert_false(ep.uses_pwait2(), "must switch permanently")
        assert_equal(fault.calls(SYS_epoll_pwait2), 1)
        assert_equal(fault.calls(SYS_epoll_pwait), 1)
        assert_equal(fault.pending(), 0)
        # Later calls go straight to epoll_pwait.
        assert_equal(ev.drain(), UInt64(1))
        assert_equal(ep.wait(evs, Duration.ZERO), 0)
        assert_equal(fault.calls(SYS_epoll_pwait2), 1)
        assert_equal(fault.calls(SYS_epoll_pwait), 2)
        sys.keep_alive(ev)  # registered fds must outlive the waits


def test_wait_other_pwait2_errors_raise_without_fallback() raises:
    fault.clear()
    var ep = Epoll.new()
    var evs = _events(4)
    for e in [Errno.EINVAL, Errno.EFAULT, Errno.EBADF]:
        fault.clear()
        fault.inject(SYS_epoll_pwait2, e, times=1)
        var raised = False
        try:
            _ = ep.wait(evs, Duration.ZERO)
        except err:
            raised = True
            assert_equal(String(err.op), "epoll_pwait2")
            assert_true(err.errno == e, String(err))
        assert_true(raised, String(e, " must raise"))
        assert_true(ep.uses_pwait2(), String(e, " must not fall back"))
        assert_equal(fault.calls(SYS_epoll_pwait), 0)
        assert_equal(len(evs), 0)
    # Still on epoll_pwait2 afterwards.
    fault.clear()
    assert_equal(ep.wait(evs, Duration.ZERO), 0)
    assert_equal(fault.calls(SYS_epoll_pwait2), 1)
    assert_equal(fault.calls(SYS_epoll_pwait), 0)


def test_wait_pwait2_eintr_returns_zero_keeps_pwait2() raises:
    fault.clear()
    var ep = Epoll.new()
    var evs = _events(4)
    fault.inject(SYS_epoll_pwait2, Errno.EINTR, times=1)
    assert_equal(ep.wait(evs, Duration.ZERO), 0)
    assert_equal(len(evs), 0)
    assert_true(ep.uses_pwait2())
    assert_equal(fault.calls(SYS_epoll_pwait), 0)
    # And on the fallback path EINTR is 0 events too.
    ep.disable_pwait2()
    fault.clear()
    fault.inject(SYS_epoll_pwait, Errno.EINTR, times=1)
    assert_equal(ep.wait(evs, Duration.ZERO), 0)
    assert_equal(fault.calls(SYS_epoll_pwait), 1)
    assert_equal(fault.calls(SYS_epoll_pwait2), 0)


# ---- probe classification (F54) ----------------------------------------------


def _io_uring_under(e: Errno) raises -> IoUringSupport:
    fault.clear()
    fault.inject(SYS_io_uring_setup, e, times=1)
    var got = probe_io_uring()
    assert_equal(fault.pending(), 0)
    return got


def test_probe_io_uring_classifies_every_errno() raises:
    fault.clear()
    # EINVAL: reachable (zero entries rejected before allocating anything).
    assert_true(_io_uring_under(Errno.EINVAL) == IoUringSupport.Available)
    # ENOSYS: not compiled in.
    assert_true(_io_uring_under(Errno.ENOSYS) == IoUringSupport.NotCompiled)
    # EPERM (io_uring_disabled, Docker's seccomp) and anything else: Disabled.
    assert_true(_io_uring_under(Errno.EPERM) == IoUringSupport.Disabled)
    assert_true(_io_uring_under(Errno.EACCES) == IoUringSupport.Disabled)
    assert_true(_io_uring_under(Errno.ENOMEM) == IoUringSupport.Disabled)


def test_has_epoll_pwait2_follows_the_probe_errno() raises:
    for e in [Errno.ENOSYS, Errno.EPERM, Errno.EINVAL]:
        fault.clear()
        fault.inject(SYS_epoll_pwait2, e, times=1)
        assert_false(has_epoll_pwait2(), String(e))
        assert_equal(fault.pending(), 0)
    # EBADF (the epfd of -1) is the "implemented" answer.
    fault.clear()
    fault.inject(SYS_epoll_pwait2, Errno.EBADF, times=1)
    assert_true(has_epoll_pwait2())


def test_cpu_count_grows_mask_on_einval() raises:
    fault.clear()
    var live = cpu_count()
    fault.clear()
    fault.inject(SYS_sched_getaffinity, Errno.EINVAL, times=3)
    assert_equal(cpu_count(), live)  # 16 -> 32 -> 64 -> 128 words
    assert_equal(fault.calls(SYS_sched_getaffinity), 4)
    assert_equal(fault.pending(), 0)


def test_cpu_count_gives_up_after_bounded_growth() raises:
    fault.clear()
    fault.inject(SYS_sched_getaffinity, Errno.EINVAL, times=-1)
    var kind = ErrorKind.Other
    var errno = Errno(0)
    try:
        _ = cpu_count()
    except e:
        kind = e.kind
        errno = e.errno
    assert_equal(kind, ErrorKind.InvalidInput)
    assert_true(errno == Errno.EINVAL)
    # 16, 32, ..., 65536 words: 13 attempts, then the error.
    assert_equal(fault.calls(SYS_sched_getaffinity), 13)
    # Other errors are not retried.
    fault.clear()
    fault.inject(SYS_sched_getaffinity, Errno.EPERM, times=1)
    kind = ErrorKind.Other
    try:
        _ = cpu_count()
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.PermissionDenied)
    assert_equal(fault.calls(SYS_sched_getaffinity), 1)


# ---- EINTR retries in eventfd, epoll_ctl, procfs reads (F55) -----------------


def test_eventfd_add_retries_eintr() raises:
    fault.clear()
    var e = EventFd.new()
    fault.inject(SYS_write, Errno.EINTR, times=2)
    assert_true(e.add(5))  # nothing was added by the interrupted writes
    assert_equal(fault.calls(SYS_write), 3)
    assert_equal(fault.pending(), 0)
    assert_equal(e.drain(), UInt64(5))


def test_eventfd_signal_retries_eintr() raises:
    # signal() discards add()'s Bool: an EINTR turned into False would be a
    # silently lost cross-thread wakeup.
    fault.clear()
    var e = EventFd.new()
    fault.inject(SYS_write, Errno.EINTR, times=3)
    e.signal()
    assert_equal(fault.calls(SYS_write), 4)
    assert_equal(e.drain(), UInt64(1))


def test_eventfd_drain_eintr_returns_zero_and_keeps_count() raises:
    fault.clear()
    var e = EventFd.new()
    assert_true(e.add(5))
    fault.inject(SYS_read, Errno.EINTR, times=1)
    assert_equal(e.drain(), UInt64(0))  # interrupted: nothing taken
    assert_equal(e.drain(), UInt64(5))
    assert_equal(fault.calls(SYS_read), 2)


def test_epoll_ctl_retries_eintr() raises:
    fault.clear()
    var ep = Epoll.new()
    var e = EventFd.new()
    fault.inject(SYS_epoll_ctl, Errno.EINTR, times=2)
    ep.add(e, IN, 7)
    assert_equal(fault.calls(SYS_epoll_ctl), 3)
    fault.inject(SYS_epoll_ctl, Errno.EINTR, times=1)
    ep.modify(e, IN, 8)
    fault.inject(SYS_epoll_ctl, Errno.EINTR, times=1)
    e.signal()
    var evs = _events(4)
    assert_equal(ep.wait(evs, Duration.ZERO), 1)
    assert_equal(evs[0].data(), UInt64(8))  # the modify really happened
    ep.delete(e)
    assert_equal(fault.calls(SYS_epoll_ctl), 7)
    assert_equal(fault.pending(), 0)
    assert_equal(ep.wait(evs, Duration.ZERO), 0)  # and so did the delete
    sys.keep_alive(e)


def test_procfs_read_retries_eintr() raises:
    fault.clear()
    var expect = page_size()
    fault.clear()
    fault.inject(SYS_openat, Errno.EINTR, times=2)
    fault.inject(SYS_read, Errno.EINTR, times=2)
    var v = auxv_lookup(UInt64(AT_PAGESZ))
    assert_true(Bool(v))
    assert_equal(Int(v.value()), expect)
    assert_equal(fault.calls(SYS_openat), 3)
    assert_true(fault.calls(SYS_read) >= 3)
    assert_equal(fault.pending(), 0)


# ---- EINTR retries under real signals, counted (F53) -------------------------


def test_raw_ppoll_eintr_even_when_the_first_signal_is_early() raises:
    # Control: this thread reaches ppoll after the first signal (handled in
    # user space); a later signal of the burst still interrupts it.
    fault.clear()
    var p = _pair()
    var fds = [Pollfd(p[0].raw_fd(), Int16(POLLIN), 0)]
    var burst = _SignalBurst(first_ms=10, count=10)
    _spin(_ms(25))
    var t = Instant.now()
    var r = ppoll(Span(fds), Duration.from_secs(2))
    var el = t.elapsed()
    sys.keep_alive(p)
    assert_true(burst.stop() >= 1)
    assert_true(is_err(r) and Errno(err_of(r)) == Errno.EINTR, String(r))
    assert_true(el < Duration.from_secs(1), String("not interrupted: ", el))


def test_poll_until_really_retries_eintr() raises:
    fault.clear()
    var p = _pair()
    var fds = [Pollfd(p[0].raw_fd(), Int16(POLLIN), 0)]
    var burst = _SignalBurst(first_ms=10, count=8)  # 10..150 ms
    _spin(_ms(25))  # late: the first signal lands before the wait
    fault.clear()
    var t = Instant.now()
    var n = poll_until(Span(fds), Deadline.after(_ms(200)), "poll")
    var el = t.elapsed()
    var polls = fault.calls(SYS_ppoll)
    sys.keep_alive(p)
    assert_true(burst.stop() >= 1)
    assert_equal(n, 0)
    assert_true(el >= _ms(200), String("early: ", el))
    assert_true(el < _ms(450), String("late: ", el))
    assert_true(polls >= 2, String(polls, " ppoll: no EINTR was retried"))


def test_wait_ready_eintr_recomputes_remaining_time_counted() raises:
    # Deadline 400 ms, signals at 250/270/290 ms. Not retrying ends at
    # ~250 ms, restarting the full timeout at >= ~690 ms.
    fault.clear()
    var p = _pair()
    var burst = _SignalBurst(first_ms=250, count=3)
    fault.clear()
    var t = Instant.now()
    var kind = ErrorKind.Other
    try:
        _ = wait_ready(p[0], Int16(POLLIN), Deadline.after(_ms(400)), "read")
    except e:
        kind = e.kind
    var el = t.elapsed()
    var polls = fault.calls(SYS_ppoll)
    sys.keep_alive(p)
    assert_true(burst.stop() >= 1)
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(el >= _ms(400), String("early: ", el))
    assert_true(el < _ms(600), String("late: ", el))
    assert_true(polls >= 2, String(polls, " ppoll: no EINTR was retried"))


def test_sleep_really_resumes_after_eintr() raises:
    fault.clear()
    var burst = _SignalBurst(first_ms=10, count=8)  # 10..150 ms
    _spin(_ms(25))
    fault.clear()
    var t = Instant.now()
    sleep(_ms(200))
    var el = t.elapsed()
    var naps = fault.calls(SYS_clock_nanosleep)
    assert_true(burst.stop() >= 1)
    assert_true(el >= _ms(200), String("early: ", el))
    assert_true(el < _ms(450), String("late: ", el))
    assert_true(naps >= 2, String(naps, " clock_nanosleep: no EINTR retried"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
