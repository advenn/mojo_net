from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Errno, check, sys
from linux.abi import Timespec
from linux.consts import CLOCK_MONOTONIC, SIGALRM, SIGEV_THREAD_ID
from linux.nr import (
    SYS_gettid,
    SYS_timer_create,
    SYS_timer_delete,
    SYS_timer_settime,
)
from linux.syscall import err_of, is_err, syscall0, syscall1, syscall3, syscall4
from linux.time import (
    Clock,
    Deadline,
    Duration,
    Instant,
    MonotonicClock,
    clock_nanosleep,
    sleep,
    sleep_until,
)

comptime NS = 1
comptime US = 1_000
comptime MS = 1_000_000
comptime SEC = 1_000_000_000


def _ns(n: Int) -> Duration:
    return Duration.from_nanos(n)


def _at(n: Int) -> Instant:
    return Instant(nanos=n)


# ---- signal helpers (test-only: the library never installs handlers) ------


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


# ---- Duration ---------------------------------------------------------------


def test_duration_constructors() raises:
    assert_equal(Duration.from_secs(2).as_nanos(), 2 * SEC)
    assert_equal(Duration.from_millis(1500).as_nanos(), 1500 * MS)
    assert_equal(Duration.from_micros(7).as_nanos(), 7 * US)
    assert_equal(Duration.from_nanos(42).as_nanos(), 42)
    assert_true(Duration.ZERO.is_zero())
    assert_equal(Duration.MAX.as_nanos(), Int.MAX)


def test_duration_negative_inputs_clamp_to_zero() raises:
    assert_true(Duration.from_nanos(-1) == Duration.ZERO)
    assert_true(Duration.from_micros(-1) == Duration.ZERO)
    assert_true(Duration.from_millis(-5) == Duration.ZERO)
    assert_true(Duration.from_secs(Int.MIN) == Duration.ZERO)


def test_duration_constructor_overflow_saturates() raises:
    var max_secs = Int.MAX // SEC
    assert_equal(Duration.from_secs(max_secs).as_nanos(), max_secs * SEC)
    assert_true(Duration.from_secs(max_secs + 1) == Duration.MAX)
    assert_true(Duration.from_secs(Int.MAX) == Duration.MAX)
    assert_true(Duration.from_millis(Int.MAX) == Duration.MAX)
    assert_true(Duration.from_micros(Int.MAX) == Duration.MAX)
    var max_ms = Int.MAX // MS
    assert_equal(Duration.from_millis(max_ms).as_nanos(), max_ms * MS)
    assert_true(Duration.from_millis(max_ms + 1) == Duration.MAX)


def test_duration_add_saturates() raises:
    assert_true(_ns(3) + _ns(4) == _ns(7))
    assert_true(Duration.MAX + _ns(1) == Duration.MAX)
    assert_true(Duration.MAX + Duration.MAX == Duration.MAX)
    assert_true(_ns(Int.MAX - 1) + _ns(1) == Duration.MAX)
    assert_true(_ns(Int.MAX - 5) + _ns(10) == Duration.MAX)
    var d = Duration.from_millis(1)
    d += Duration.from_millis(2)
    assert_true(d == Duration.from_millis(3))


def test_duration_sub_saturates_at_zero() raises:
    assert_true(
        Duration.from_millis(2) - Duration.from_millis(1)
        == Duration.from_millis(1)
    )
    assert_true(
        Duration.from_millis(1) - Duration.from_millis(2) == Duration.ZERO
    )
    assert_true(Duration.ZERO - Duration.MAX == Duration.ZERO)
    assert_true(Duration.MAX - Duration.MAX == Duration.ZERO)
    var d = Duration.from_millis(1)
    d -= Duration.from_secs(1)
    assert_true(d.is_zero())


def test_duration_mul() raises:
    assert_true(Duration.from_millis(3) * 4 == Duration.from_millis(12))
    assert_true(Duration.MAX * 2 == Duration.MAX)
    assert_true(Duration.from_secs(1) * 0 == Duration.ZERO)
    assert_true(Duration.from_secs(1) * -3 == Duration.ZERO)
    assert_true(Duration.from_secs(1) * (Int.MAX // SEC + 1) == Duration.MAX)
    assert_true(Duration.ZERO * Int.MAX == Duration.ZERO)


def test_duration_floor_accessors() raises:
    var d = _ns(1_999_999_999)
    assert_equal(d.as_secs(), 1)
    assert_equal(d.as_millis(), 1999)
    assert_equal(d.as_micros(), 1_999_999)
    assert_equal(d.subsec_nanos(), 999_999_999)
    assert_equal(_ns(999).as_micros(), 0)
    assert_true(abs(Duration.from_millis(1500).as_secs_f64() - 1.5) < 1e-12)


def test_as_millis_ceil_rounds_up() raises:
    assert_equal(Duration.ZERO.as_millis_ceil(), 0)
    assert_equal(_ns(1).as_millis_ceil(), 1)
    assert_equal(_ns(999_999).as_millis_ceil(), 1)
    assert_equal(_ns(MS).as_millis_ceil(), 1)
    assert_equal(_ns(MS + 1).as_millis_ceil(), 2)
    assert_equal(Duration.from_secs(3).as_millis_ceil(), 3000)
    # No overflow at the top of the range (Int.MAX is not a multiple of 1ms).
    assert_equal(Duration.MAX.as_millis_ceil(), Int.MAX // MS + 1)
    assert_true(Duration.MAX.as_millis_ceil() > 0)


def test_duration_timespec_roundtrip() raises:
    var ts = (Duration.from_secs(3) + _ns(5)).as_timespec()
    assert_equal(ts.sec, 3)
    assert_equal(ts.nsec, 5)
    var big = Duration.MAX.as_timespec()
    assert_equal(big.sec, Int.MAX // SEC)
    assert_true(big.nsec >= 0 and big.nsec < SEC)
    assert_true(
        Duration.from_timespec(Timespec(3, 5)) == Duration.from_secs(3) + _ns(5)
    )


def test_duration_from_unnormalized_timespec() raises:
    # nsec >= 1e9 carries; negative totals clamp to zero.
    assert_true(
        Duration.from_timespec(Timespec(1, 1_500_000_000))
        == Duration.from_millis(2500)
    )
    assert_true(
        Duration.from_timespec(Timespec(1, -500_000_000))
        == Duration.from_millis(500)
    )
    assert_true(Duration.from_timespec(Timespec(-1, 5)) == Duration.ZERO)
    assert_true(
        Duration.from_timespec(Timespec(-1, 2_000_000_000))
        == Duration.from_secs(1)
    )
    assert_true(
        Duration.from_timespec(Timespec(Int.MIN, Int.MAX)) == Duration.ZERO
    )
    assert_true(
        Duration.from_timespec(Timespec(Int.MAX, Int.MAX)) == Duration.MAX
    )
    assert_true(Duration.from_timespec(Timespec(0, -1)) == Duration.ZERO)


def test_duration_ordering() raises:
    var a = Duration.from_millis(1)
    var b = Duration.from_millis(2)
    assert_true(a < b)
    assert_true(a <= b)
    assert_true(b > a)
    assert_true(b >= a)
    assert_true(a != b)
    assert_true(a == Duration.from_micros(1000))
    assert_false(a < a)
    assert_true(a <= a)
    assert_true(Duration.ZERO < Duration.MAX)


def test_duration_write() raises:
    assert_equal(String(Duration.ZERO), "0s")
    assert_equal(String(Duration.from_secs(2)), "2s")
    assert_equal(String(Duration.from_millis(1500)), "1500ms")
    assert_equal(String(Duration.from_micros(3)), "3us")
    assert_equal(String(_ns(7)), "7ns")
    assert_equal(String(_ns(1_000_001)), "1000001ns")


# ---- Instant ----------------------------------------------------------------


def test_instant_is_monotonic() raises:
    var prev = Instant.now()
    for _ in range(20_000):
        var t = Instant.now()
        assert_true(t >= prev)
        prev = t
    assert_true(prev.as_nanos() > 0)


def test_instant_matches_python_monotonic_clock() raises:
    # Python's time.monotonic_ns() reads CLOCK_MONOTONIC through libc: an
    # independent oracle for the raw syscall path.
    var time = Python.import_module("time")
    var before = Int(py=time.monotonic_ns())
    var t = Instant.now()
    var after = Int(py=time.monotonic_ns())
    assert_true(before <= t.as_nanos())
    assert_true(t.as_nanos() <= after)


def test_instant_arithmetic() raises:
    assert_true(_at(100) + _ns(50) == _at(150))
    assert_true(_at(100) - _ns(50) == _at(50))
    assert_true(_at(150) - _at(100) == _ns(50))
    assert_true(_at(150).duration_since(_at(100)) == _ns(50))
    assert_true(_at(5) - _at(-5) == _ns(10))
    var t = _at(0)
    t += _ns(9)
    t -= _ns(4)
    assert_true(t == _at(5))


def test_instant_arithmetic_saturates() raises:
    assert_true(_at(Int.MAX - 1) + _ns(10) == _at(Int.MAX))
    assert_true(_at(0) + Duration.MAX == _at(Int.MAX))
    assert_true(_at(Int.MIN + 1) - _ns(10) == _at(Int.MIN))
    assert_true(_at(Int.MIN) - Duration.MAX == _at(Int.MIN))
    # Earlier-is-later saturates to zero; range overflow saturates to MAX.
    assert_true(_at(100) - _at(150) == Duration.ZERO)
    assert_true(_at(100) - _at(100) == Duration.ZERO)
    assert_true(_at(Int.MAX) - _at(Int.MIN) == Duration.MAX)
    assert_true(_at(Int.MAX) - _at(-1) == Duration.MAX)
    assert_true(_at(Int.MAX - 1) - _at(-1) == Duration.MAX)
    assert_true(_at(Int.MAX - 1) - _at(0) == _ns(Int.MAX - 1))


def test_instant_timespec_floors() raises:
    var ts = _at(3 * SEC + 7).as_timespec()
    assert_equal(ts.sec, 3)
    assert_equal(ts.nsec, 7)
    var neg = _at(-1).as_timespec()
    assert_equal(neg.sec, -1)
    assert_equal(neg.nsec, 999_999_999)


def test_instant_elapsed_after_sleep() raises:
    var t = Instant.now()
    sleep(Duration.from_millis(5))
    var e = t.elapsed()
    assert_true(e >= Duration.from_millis(5))
    assert_true(Instant.now() >= t + e)


# ---- Deadline ---------------------------------------------------------------


def test_deadline_none_never_expires() raises:
    var d = Deadline.none()
    assert_true(d.is_none())
    assert_false(d.is_expired(_at(Int.MAX)))
    assert_false(d.is_expired())
    assert_false(d.remaining(_at(Int.MAX)))
    assert_false(d.remaining())
    assert_false(d.instant())
    assert_equal(String(d), "Deadline(none)")


def test_deadline_at_expiry_boundary() raises:
    var d = Deadline.at(_at(1000))
    assert_false(d.is_none())
    assert_true(d.remaining(_at(400)).value() == _ns(600))
    assert_false(d.is_expired(_at(999)))
    assert_true(d.remaining(_at(999)).value() == _ns(1))
    # Expired exactly at the deadline: remaining is ZERO iff expired.
    assert_true(d.is_expired(_at(1000)))
    assert_true(d.remaining(_at(1000)).value() == Duration.ZERO)
    assert_true(d.is_expired(_at(5000)))
    assert_true(d.remaining(_at(5000)).value() == Duration.ZERO)
    assert_true(d.remaining(_at(Int.MIN)).value() == Duration.MAX)
    assert_true(d.instant().value() == _at(1000))


def test_deadline_after_overflow_becomes_none() raises:
    assert_true(Deadline.after_from(_at(10), Duration.MAX).is_none())
    assert_true(Deadline.after(Duration.MAX).is_none())
    var edge = Deadline.after_from(_at(Int.MAX - 10), _ns(10))
    assert_false(edge.is_none())
    assert_true(edge.instant().value() == _at(Int.MAX))
    assert_true(Deadline.after_from(_at(Int.MAX - 10), _ns(11)).is_none())
    var zero = Deadline.after_from(_at(77), Duration.ZERO)
    assert_true(zero.is_expired(_at(77)))


def test_deadline_after_real_clock() raises:
    var d = Deadline.after(Duration.from_millis(40))
    var left = d.remaining().value()
    assert_true(left <= Duration.from_millis(40))
    assert_true(left > Duration.ZERO)
    assert_false(d.is_expired())
    sleep(Duration.from_millis(45))
    assert_true(d.is_expired())
    assert_true(d.remaining().value() == Duration.ZERO)


def test_deadline_earliest_and_eq() raises:
    var none = Deadline.none()
    var a = Deadline.at(_at(10))
    var b = Deadline.at(_at(20))
    assert_true(none.earliest(a) == a)
    assert_true(a.earliest(none) == a)
    assert_true(a.earliest(b) == a)
    assert_true(b.earliest(a) == a)
    assert_true(none.earliest(none).is_none())
    assert_true(none == Deadline.none())
    assert_true(a != b)
    assert_true(a != none)
    assert_true(Deadline.at(_at(10)) == a)


# ---- Clock seam -------------------------------------------------------------


@fieldwise_init
struct FakeClock(Clock, TrivialRegisterPassable):
    var t: Int

    def now(self) -> Instant:
        return Instant(nanos=self.t)


def _age[C: Clock](clock: C, since: Instant) -> Duration:
    return clock.now() - since


def test_clock_seam() raises:
    var fake = FakeClock(1_000)
    assert_true(_age(fake, _at(400)) == _ns(600))
    var d = Deadline.after(fake, _ns(5))
    assert_true(d == Deadline.at(_at(1_005)))
    assert_false(d.is_expired(FakeClock(1_004).now()))
    assert_true(d.is_expired(FakeClock(1_005).now()))
    var real = MonotonicClock()
    var t = real.now()
    assert_true(_age(real, t) >= Duration.ZERO)
    assert_true(real.now() >= t)


# ---- sleep ------------------------------------------------------------------


def test_sleep_accuracy() raises:
    var t = Instant.now()
    sleep(Duration.from_millis(30))
    var e = t.elapsed()
    assert_true(e >= Duration.from_millis(30))
    assert_true(e < Duration.from_millis(30 + 250))


def test_sleep_zero_and_past_return_immediately() raises:
    var t = Instant.now()
    sleep(Duration.ZERO)
    sleep_until(t - Duration.from_secs(1))
    sleep_until(_at(0))
    sleep_until(_at(-5))
    sleep_until(_at(Int.MIN))
    assert_true(t.elapsed() < Duration.from_millis(20))


def test_sleep_until_absolute() raises:
    var target = Instant.now() + Duration.from_millis(20)
    sleep_until(target)
    assert_true(Instant.now() >= target)


def test_raw_clock_nanosleep_is_interrupted_by_signal() raises:
    # Control for the next test: proves the harness really produces EINTR
    # (a relative raw sleep returns early with -EINTR).
    var burst = _SignalBurst(first_ms=30, count=10)
    var ts = Duration.from_secs(2).as_timespec()
    var t = Instant.now()
    var r = clock_nanosleep(CLOCK_MONOTONIC, 0, ts)
    var e = t.elapsed()
    assert_true(burst.stop() >= 1)
    assert_true(is_err(r) and Errno(err_of(r)) == Errno.EINTR)
    assert_true(e < Duration.from_secs(1))


def test_sleep_resumes_after_eintr() raises:
    var burst = _SignalBurst(first_ms=50)  # 50..130 ms
    var t = Instant.now()
    sleep(Duration.from_millis(200))
    var e = t.elapsed()
    assert_true(burst.stop() >= 1)
    assert_true(e >= Duration.from_millis(200))
    assert_true(e < Duration.from_millis(200 + 250))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
