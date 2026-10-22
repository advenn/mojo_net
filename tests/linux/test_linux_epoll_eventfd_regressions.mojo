"""Regressions for the linux-epoll-eventfd review group.

F33: `Epoll.wait(events, timeout_ns: Int)` used a signed-ns sentinel where
any negative value means "wait forever", so `deadline_ns - now_ns` for a
deadline already in the past blocked forever and timers stopped firing.
`Epoll.wait` now takes the library's saturating types, a relative
`Optional[Duration]` or an absolute `Deadline` (with or without the caller's
`now`); the Int form is deprecated and unchanged.

A wait that wrongly blocks forever must fail, not hang the suite. Every
test that waits on an idle set therefore registers a *backstop* in the same
epoll set: a one-shot timerfd (test-only) that becomes readable after a
delay (`SAFETY`, unless the test needs a shorter one). A wait that should
have polled or timed out instead wakes on the backstop, so it returns 1
event (data `BACKSTOP`) late and the assertions fail. The same backstop
proves that the "forever" forms really block: on an idle set the backstop's
event is their only way out. No signals, helper processes or Python are
involved.
"""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import OwnedFd, check, sys
from linux.abi import EpollEvent
from linux.consts import CLOCK_MONOTONIC, EPOLLIN, TFD_CLOEXEC, TFD_NONBLOCK
from linux.epoll import Epoll
from linux.eventfd import EventFd
from linux.nr import SYS_timerfd_create, SYS_timerfd_settime
from linux.syscall import syscall2, syscall4
from linux.time import Deadline, Duration, Instant

comptime IN = UInt32(EPOLLIN)
comptime MS = 1_000_000
comptime BACKSTOP = UInt64(0xBAC5_7095)
comptime BLOCK_MS = 150
"""How long the "forever" forms are left blocked before the backstop."""
comptime SAFETY = Duration.from_secs(3)
"""Backstop for waits that must not block: far beyond any expected wait."""


def _events_buf(cap: Int) -> List[EpollEvent]:
    return List[EpollEvent](capacity=cap)


def _elapsed_ns(t0: Instant) -> Int:
    return (Instant.now() - t0).as_nanos()


def _backstop(ep: Epoll) raises -> OwnedFd:
    """A disarmed CLOEXEC timerfd on CLOCK_MONOTONIC, registered in `ep`
    with data `BACKSTOP`. The caller owns it and deletes it from `ep`."""
    var r = check(
        "timerfd_create",
        syscall2(SYS_timerfd_create, CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK),
    )
    var fd = OwnedFd(unsafe_from_raw=Int32(r))
    ep.add(fd, IN, BACKSTOP)
    return fd^


def _arm(fd: OwnedFd, after: Duration) raises:
    """Fire once, `after` from now. Re-arming also clears an expiry that was
    not read yet (timerfd_settime resets the tick count)."""
    # struct itimerspec: it_interval (zero: one-shot), then it_value.
    var spec = Array[Int, 4](fill=0)
    var ns = after.as_nanos()
    spec[2] = ns // 1_000_000_000
    spec[3] = ns % 1_000_000_000
    _ = check(
        "timerfd_settime",
        syscall4(
            SYS_timerfd_settime, Int(fd.raw_fd()), 0, Int(Pointer(to=spec)), 0
        ),
    )
    sys.keep_alive(spec)  # only its address reached the kernel


# ---- F33: a missed deadline polls, it never waits forever ---------------------


def _check_missed_deadline_polls(mut ep: Epoll) raises:
    """Each wait must poll once and return 0 at once. One that blocks wakes
    on the backstop instead: 1 event, seconds late."""
    var evs = _events_buf(4)
    var now = Instant.now()
    var missed = Deadline.at(now - Duration.from_millis(1))
    var long_ago = Deadline.at(Instant(nanos=Int.MIN))
    var t0 = Instant.now()
    # Absolute form, with the caller's clock reading.
    assert_equal(ep.wait(evs, missed, now), 0, "Deadline 1ms ago, now")
    assert_equal(len(evs), 0)
    assert_equal(ep.wait(evs, long_ago, now), 0, "Deadline at Int.MIN, now")
    assert_equal(ep.wait(evs, Deadline.at(now), now), 0, "Deadline == now")
    # Absolute form reading CLOCK_MONOTONIC.
    assert_equal(ep.wait(evs, missed), 0, "Deadline 1ms ago, clock")
    assert_equal(ep.wait(evs, long_ago), 0, "Deadline at Int.MIN, clock")
    # The failure scenario: an M2 loop computes "until - now" for an `until`
    # that has already passed. With Instant arithmetic it saturates at ZERO.
    var until = now - Duration.from_millis(1)
    assert_true((until - now).is_zero())
    assert_equal(ep.wait(evs, until - now), 0, "until - now")
    assert_equal(ep.wait(evs, missed.remaining(now)), 0, "remaining(now)")
    var dt = _elapsed_ns(t0)
    assert_true(dt < 1000 * MS, "a missed deadline blocked instead of polling")


def test_missed_deadline_polls_instead_of_waiting_forever() raises:
    var ep = Epoll.new()
    var e = EventFd.new()
    ep.add(e, IN, 7)  # registered but never signaled
    var bs = _backstop(ep)
    for fallback in range(2):
        if fallback == 1:
            ep.disable_pwait2()  # same on the millisecond epoll_pwait path
        _arm(bs, SAFETY)
        _check_missed_deadline_polls(ep)
    assert_false(ep.uses_pwait2())
    ep.delete(bs)  # contract 5: delete before close
    ep.delete(e)


def test_missed_deadline_still_reports_ready_events() raises:
    # Polling once (not returning early without a syscall) means readiness
    # that is already there wins over the expired deadline.
    var ep = Epoll.new()
    var e = EventFd.new()
    ep.add(e, IN, 0xD00D)
    var bs = _backstop(ep)
    var evs = _events_buf(4)
    for fallback in range(2):
        if fallback == 1:
            ep.disable_pwait2()
        _arm(bs, SAFETY)
        e.signal()
        var now = Instant.now()
        var missed = Deadline.at(now - Duration.from_secs(5))
        assert_equal(ep.wait(evs, missed, now), 1)
        assert_equal(evs[0].events(), IN)
        assert_equal(evs[0].data(), UInt64(0xD00D))
        assert_equal(ep.wait(evs, missed), 1)
        assert_equal(ep.wait(evs, Duration.ZERO), 1)
        assert_equal(e.drain(), UInt64(1))
        assert_equal(ep.wait(evs, missed, now), 0, "idle set, missed deadline")
    ep.delete(bs)
    ep.delete(e)


# ---- the typed forms keep the documented meanings -----------------------------


def _check_future_deadline(mut ep: Epoll, bs: OwnedFd, d: Duration) raises:
    _arm(bs, SAFETY)
    var evs = _events_buf(4)
    var t0 = Instant.now()
    assert_equal(ep.wait(evs, Deadline.after_from(t0, d), t0), 0)
    var dt = _elapsed_ns(t0)
    assert_true(dt >= d.as_nanos(), "woke before the deadline")
    assert_true(dt < d.as_nanos() + 2000 * MS, "deadline far too late")
    t0 = Instant.now()
    assert_equal(ep.wait(evs, Deadline.after_from(t0, d)), 0)
    dt = _elapsed_ns(t0)
    assert_true(dt >= d.as_nanos(), "woke before the deadline (clock form)")
    assert_true(dt < d.as_nanos() + 2000 * MS, "deadline far too late (clock)")
    t0 = Instant.now()
    assert_equal(ep.wait(evs, d), 0)
    dt = _elapsed_ns(t0)
    assert_true(dt >= d.as_nanos(), "woke before the relative timeout")
    assert_true(dt < d.as_nanos() + 2000 * MS, "timeout far too late")


def test_future_deadline_and_timeout_wait_until_due() raises:
    var ep = Epoll.new()
    var e = EventFd.new()
    ep.add(e, IN, 7)  # registered but never signaled
    var bs = _backstop(ep)
    _check_future_deadline(ep, bs, Duration.from_millis(30))
    _check_future_deadline(ep, bs, Duration.from_micros(1500))
    ep.disable_pwait2()
    _check_future_deadline(ep, bs, Duration.from_millis(30))
    # On epoll_pwait 1.5ms rounds up to 2ms.
    _check_future_deadline(ep, bs, Duration.from_micros(1500))
    ep.delete(bs)
    ep.delete(e)


comptime _N_FOREVER_FORMS = 7


def _wait_forever_form(
    mut ep: Epoll, mut evs: List[EpollEvent], form: Int, now: Instant
) raises -> Int:
    """Every spelling of "no timeout" that the typed overloads accept."""
    if form == 0:
        return ep.wait(evs, None)
    if form == 1:
        var none: Optional[Duration] = None
        return ep.wait(evs, none)
    if form == 2:
        return ep.wait(evs, Duration.MAX)  # ~292 years, "practically forever"
    if form == 3:
        return ep.wait(evs, Deadline.none(), now)
    if form == 4:
        return ep.wait(evs, Deadline.none())
    if form == 5:
        return ep.wait(evs, Deadline.at(Instant(nanos=Int.MAX)), now)
    # now + MAX overflows the clock range: after_from() gives none().
    return ep.wait(evs, Deadline.after_from(now, Duration.MAX), now)


def test_forever_forms_block_until_an_event() raises:
    # They must block: not poll, not time out early, and not be rejected
    # (Duration.MAX must pass both kernel paths without EINVAL and without
    # being truncated into a short or negative Int). On an idle set the
    # only way out is the backstop's event, BLOCK_MS later.
    var ep = Epoll.new()
    var e = EventFd.new()
    ep.add(e, IN, 7)  # registered but never signaled
    var bs = _backstop(ep)
    var evs = _events_buf(4)
    for fallback in range(2):
        if fallback == 1:
            ep.disable_pwait2()
        for form in range(_N_FOREVER_FORMS):
            var what = String(t"form {form}, fallback {fallback}")
            _arm(bs, Duration.from_millis(BLOCK_MS))
            var t0 = Instant.now()
            var n = _wait_forever_form(ep, evs, form, t0)
            var dt = _elapsed_ns(t0)
            assert_equal(n, 1, what + ": returned without the backstop")
            assert_equal(evs[0].data(), BACKSTOP, what)
            assert_true(dt >= (BLOCK_MS - 20) * MS, what + ": returned early")
    assert_false(ep.uses_pwait2())
    ep.delete(bs)
    ep.delete(e)


def test_forever_forms_return_ready_events_at_once() raises:
    # Single-threaded: signal first, then each "forever" form returns at once.
    var ep = Epoll.new()
    var e = EventFd.new()
    ep.add(e, IN, 0xE0E0)
    var bs = _backstop(ep)
    var evs = _events_buf(4)
    for fallback in range(2):
        if fallback == 1:
            ep.disable_pwait2()
        _arm(bs, SAFETY)
        e.signal()
        var t0 = Instant.now()
        for form in range(_N_FOREVER_FORMS):
            assert_equal(_wait_forever_form(ep, evs, form, t0), 1)
            assert_equal(evs[0].events(), IN)
            assert_equal(evs[0].data(), UInt64(0xE0E0))
        assert_true(_elapsed_ns(t0) < 1000 * MS)
        assert_equal(e.drain(), UInt64(1))
        assert_equal(ep.wait(evs, Duration.ZERO), 0, "idle set, ZERO")
    assert_false(ep.uses_pwait2())
    ep.delete(bs)
    ep.delete(e)


def test_typed_wait_keeps_capacity_contract() raises:
    # The typed overloads share the old body: capacity 0 is EINVAL and the
    # list is left empty, the count is len(events), the buffer is reused.
    var ep = Epoll.new()
    var e = EventFd.new()
    ep.add(e, IN, 1)
    e.signal()
    var empty = List[EpollEvent]()
    var raised = False
    try:
        _ = ep.wait(empty, Duration.ZERO)
    except err:
        raised = True
        assert_true(String(err).find("capacity 0") >= 0)
    assert_true(raised, "capacity 0 must raise")
    assert_equal(len(empty), 0)
    raised = False
    try:
        _ = ep.wait(empty, Deadline.none(), Instant.now())
    except err:
        raised = True
    assert_true(raised, "capacity 0 must raise (Deadline form)")
    var evs = _events_buf(4)
    var cap = evs.capacity()
    assert_equal(ep.wait(evs, Duration.ZERO), 1)
    assert_equal(len(evs), 1)
    assert_equal(evs.capacity(), cap)
    ep.delete(e)


def test_deprecated_int_timeout_is_unchanged() raises:
    # Backward compatibility: existing callers of the Int form still build
    # (with a deprecation warning) and keep its exact meaning, including the
    # hazard that motivated F33: a negative value waits forever.
    var ep = Epoll.new()
    var e = EventFd.new()
    ep.add(e, IN, 3)
    var bs = _backstop(ep)
    var evs = _events_buf(4)
    for fallback in range(2):
        if fallback == 1:
            ep.disable_pwait2()
        _arm(bs, SAFETY)
        assert_equal(ep.wait(evs, 0), 0)  # 0 polls
        var t0 = Instant.now()
        assert_equal(ep.wait(evs, 20 * MS), 0)
        assert_true(_elapsed_ns(t0) >= 20 * MS, "woke before the timeout")
        _arm(bs, Duration.from_millis(BLOCK_MS))
        t0 = Instant.now()
        assert_equal(ep.wait(evs, -1_000_000), 1)  # negative means forever
        assert_equal(evs[0].data(), BACKSTOP)
        assert_true(_elapsed_ns(t0) >= (BLOCK_MS - 20) * MS)
        _arm(bs, Duration.ZERO)  # disarm (and clear the expiry)
        e.signal()
        assert_equal(ep.wait(evs, -1), 1)
        assert_equal(evs[0].data(), UInt64(3))
        assert_equal(e.drain(), UInt64(1))
    assert_false(ep.uses_pwait2())
    ep.delete(bs)
    ep.delete(e)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
