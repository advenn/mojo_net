"""Monotonic time: `Duration`, `Instant`, `Deadline`, the `Clock` seam, sleep.

Everything is integer nanoseconds in an `Int` (about 292 years of range), so
timeout math is exact and never touches floating point. All arithmetic
saturates instead of wrapping: a huge timeout must turn into "practically
forever", never into a negative (already expired) one.

The clock is CLOCK_MONOTONIC read through the raw `clock_gettime` syscall,
not the vDSO (that would mean parsing the vDSO ELF). One `Instant.now()`
costs about 120 ns: 116-118 ns measured in docs/spikes.md, about 9x the
vDSO's 13 ns. That is small next to a blocking call that a deadline
guards, but an event loop should read the clock once per loop iteration
(after the wait), not once per event or operation. `Clock` is the
determinism seam from docs/design.md: the Sim backend implements it with
virtual time, so code that takes a `Clock` must not call `Instant.now()`.
"""

from std.os import abort

from .abi import Timespec
from .consts import CLOCK_MONOTONIC, CLOCK_REALTIME, TIMER_ABSTIME
from .errno import Errno
from .error import IoError
from .nr import SYS_clock_gettime, SYS_clock_nanosleep
from .syscall import err_of, is_err, syscall2, syscall4

comptime NANOS_PER_MICRO = 1_000
comptime NANOS_PER_MILLI = 1_000_000
comptime NANOS_PER_SEC = 1_000_000_000


@inline(.always)
def _sat_mul(v: Int, k: Int) -> Int:
    """`v * k` for `k > 0`, clamped to `[0, Int.MAX]`."""
    if v <= 0:
        return 0
    if v > Int.MAX // k:
        return Int.MAX
    return v * k


# ---- raw wrappers ------------------------------------------------------------


@inline(.always)
def clock_gettime(clock: Int, mut ts: Timespec) -> Int:
    return syscall2(SYS_clock_gettime, clock, Int(Pointer(to=ts)))


@inline(.always)
def clock_nanosleep(clock: Int, flags: Int, ref req: Timespec) -> Int:
    """Raw `clock_nanosleep` with a NULL remainder (callers use
    `TIMER_ABSTIME`, so the remainder is never needed)."""
    return syscall4(SYS_clock_nanosleep, clock, flags, Int(Pointer(to=req)), 0)


# ---- Duration ----------------------------------------------------------------


struct Duration(Comparable, TrivialRegisterPassable, Writable):
    """A non-negative span of time in nanoseconds.

    Construction clamps negative inputs to zero and arithmetic saturates at
    `ZERO` and `MAX`, so `a - b` with `b > a` is `ZERO` (like Rust's
    `saturating_sub`) and `MAX` behaves as "forever".
    """

    var _ns: Int

    comptime ZERO = Duration(nanos=0)
    comptime MAX = Duration(nanos=Int.MAX)

    @inline(.always)
    def __init__(out self, *, nanos: Int):
        self._ns = nanos if nanos > 0 else 0

    @staticmethod
    @inline(.always)
    def from_nanos(ns: Int) -> Duration:
        return Duration(nanos=ns)

    @staticmethod
    @inline(.always)
    def from_micros(us: Int) -> Duration:
        return Duration(nanos=_sat_mul(us, NANOS_PER_MICRO))

    @staticmethod
    @inline(.always)
    def from_millis(ms: Int) -> Duration:
        return Duration(nanos=_sat_mul(ms, NANOS_PER_MILLI))

    @staticmethod
    @inline(.always)
    def from_secs(s: Int) -> Duration:
        return Duration(nanos=_sat_mul(s, NANOS_PER_SEC))

    @staticmethod
    def from_timespec(ts: Timespec) -> Duration:
        """Exact for any field values: `nsec` outside `[0, 1e9)` carries
        into seconds, a negative total clamps to `ZERO`, overflow saturates
        at `MAX`."""
        var carry = ts.nsec // NANOS_PER_SEC  # floor division
        var n = ts.nsec - carry * NANOS_PER_SEC  # now in [0, 1e9)
        if carry > 0 and ts.sec > Int.MAX - carry:
            return Duration.MAX
        if carry < 0 and ts.sec < Int.MIN - carry:
            return Duration.ZERO
        var s = ts.sec + carry
        if s < 0:
            return Duration.ZERO
        return Duration.from_secs(s) + Duration(nanos=n)

    @inline(.always)
    def as_nanos(self) -> Int:
        return self._ns

    @inline(.always)
    def as_micros(self) -> Int:
        """Truncated (floor)."""
        return self._ns // NANOS_PER_MICRO

    @inline(.always)
    def as_millis(self) -> Int:
        """Truncated (floor)."""
        return self._ns // NANOS_PER_MILLI

    @inline(.always)
    def as_millis_ceil(self) -> Int:
        """Rounded up, for millisecond timeout APIs (`epoll_wait`): rounding
        down would wake before the deadline and spin with a 0 ms timeout.
        Callers passing an `int` timeout must still clamp to `Int32.MAX`."""
        var q = self._ns // NANOS_PER_MILLI
        return q + 1 if self._ns % NANOS_PER_MILLI != 0 else q

    @inline(.always)
    def as_secs(self) -> Int:
        """Truncated (floor)."""
        return self._ns // NANOS_PER_SEC

    @inline(.always)
    def subsec_nanos(self) -> Int:
        return self._ns % NANOS_PER_SEC

    def as_secs_f64(self) -> Float64:
        return Float64(self.as_secs()) + Float64(self.subsec_nanos()) / 1e9

    @inline(.always)
    def as_timespec(self) -> Timespec:
        """A normalized timespec (0 <= nsec < 1e9), valid for the kernel."""
        return Timespec(self.as_secs(), self.subsec_nanos())

    @inline(.always)
    def is_zero(self) -> Bool:
        return self._ns == 0

    @inline(.always)
    def __add__(self, rhs: Self) -> Self:
        if self._ns > Int.MAX - rhs._ns:
            return Self.MAX
        return Duration(nanos=self._ns + rhs._ns)

    @inline(.always)
    def __sub__(self, rhs: Self) -> Self:
        """Saturates at `ZERO`."""
        return Duration(nanos=self._ns - rhs._ns)

    @inline(.always)
    def __iadd__(mut self, rhs: Self):
        self = self + rhs

    @inline(.always)
    def __isub__(mut self, rhs: Self):
        self = self - rhs

    @inline(.always)
    def __mul__(self, k: Int) -> Self:
        """Saturates at `MAX`; a negative factor gives `ZERO`."""
        return Duration(nanos=_sat_mul(self._ns, k) if k > 0 else 0)

    @inline(.always)
    def __lt__(self, rhs: Self) -> Bool:
        return self._ns < rhs._ns

    @inline(.always)
    def __eq__(self, rhs: Self) -> Bool:
        return self._ns == rhs._ns

    def write_to(self, mut writer: Some[Writer]):
        """Exact, in the largest unit that divides the value (`1500us`)."""
        if self._ns == 0:
            writer.write("0s")
        elif self._ns % NANOS_PER_SEC == 0:
            writer.write(self._ns // NANOS_PER_SEC, "s")
        elif self._ns % NANOS_PER_MILLI == 0:
            writer.write(self._ns // NANOS_PER_MILLI, "ms")
        elif self._ns % NANOS_PER_MICRO == 0:
            writer.write(self._ns // NANOS_PER_MICRO, "us")
        else:
            writer.write(self._ns, "ns")


# ---- wall-clock time -----------------------------------------------------------


def unix_time_ns() -> Int:
    """CLOCK_REALTIME now: nanoseconds since 1970-01-01T00:00:00Z. For
    showing the time (an HTTP Date field); measure durations with `Instant`,
    since this clock jumps when the system time is set. Aborts as
    `Instant.now()` does if the clock cannot be read."""
    var ts = Timespec(0, 0)
    var r = clock_gettime(CLOCK_REALTIME, ts)
    if is_err(r):
        abort("clock_gettime(CLOCK_REALTIME) failed")
    return ts.sec * NANOS_PER_SEC + ts.nsec


# ---- Instant -----------------------------------------------------------------


struct Instant(Comparable, TrivialRegisterPassable, Writable):
    """A point on a monotonic clock, in nanoseconds since an unspecified
    origin (boot, for CLOCK_MONOTONIC). Only differences between instants of
    the same clock mean anything. `+`/`-` with a `Duration` saturate at the
    ends of the `Int` range."""

    var _ns: Int

    @inline(.always)
    def __init__(out self, *, nanos: Int):
        """For `Clock` implementations (Sim) and tests."""
        self._ns = nanos

    @staticmethod
    def now() -> Instant:
        """CLOCK_MONOTONIC now.

        The syscall can only fail with EFAULT/EINVAL, impossible for a stack
        timespec and a clock every Linux has, or by a seccomp policy that
        forbids reading the clock; nothing sensible can continue then, so
        this aborts instead of making every caller handle an error."""
        var ts = Timespec(0, 0)
        var r = clock_gettime(CLOCK_MONOTONIC, ts)
        if is_err(r):
            abort("clock_gettime(CLOCK_MONOTONIC) failed")
        return Instant(nanos=ts.sec * NANOS_PER_SEC + ts.nsec)

    @inline(.always)
    def as_nanos(self) -> Int:
        return self._ns

    def as_timespec(self) -> Timespec:
        """Absolute timespec for `TIMER_ABSTIME` calls (floored division, so
        negative instants still give `0 <= nsec < 1e9`)."""
        var s = self._ns // NANOS_PER_SEC
        return Timespec(s, self._ns - s * NANOS_PER_SEC)

    @inline(.always)
    def duration_since(self, earlier: Self) -> Duration:
        """`self - earlier`, `ZERO` if `earlier` is later."""
        return self - earlier

    def elapsed(self) -> Duration:
        """Time since `self` on CLOCK_MONOTONIC (use `clock.now() - t` with
        an injected clock)."""
        return Instant.now() - self

    @inline(.always)
    def __add__(self, d: Duration) -> Self:
        if self._ns > Int.MAX - d._ns:
            return Instant(nanos=Int.MAX)
        return Instant(nanos=self._ns + d._ns)

    @inline(.always)
    def __sub__(self, d: Duration) -> Self:
        if self._ns < Int.MIN + d._ns:
            return Instant(nanos=Int.MIN)
        return Instant(nanos=self._ns - d._ns)

    @inline(.always)
    def __iadd__(mut self, d: Duration):
        self = self + d

    @inline(.always)
    def __isub__(mut self, d: Duration):
        self = self - d

    @inline(.always)
    def __sub__(self, earlier: Self) -> Duration:
        """Saturates at `ZERO` (earlier is later) and `MAX` (range overflow)."""
        if earlier._ns >= self._ns:
            return Duration.ZERO
        if earlier._ns < 0 and self._ns > Int.MAX + earlier._ns:
            return Duration.MAX
        return Duration(nanos=self._ns - earlier._ns)

    @inline(.always)
    def __lt__(self, rhs: Self) -> Bool:
        return self._ns < rhs._ns

    @inline(.always)
    def __eq__(self, rhs: Self) -> Bool:
        return self._ns == rhs._ns

    def write_to(self, mut writer: Some[Writer]):
        writer.write("Instant(", self._ns, "ns)")


# ---- Clock -------------------------------------------------------------------


trait Clock:
    """Source of `Instant`s. The real one is `MonotonicClock`; the Sim
    backend supplies virtual time so timeouts replay deterministically."""

    def now(self) -> Instant:
        ...


@fieldwise_init
struct MonotonicClock(Clock, Defaultable, TrivialRegisterPassable):
    """CLOCK_MONOTONIC: never jumps (NTP slews it, settimeofday does not
    move it), does not count suspend."""

    @inline(.always)
    def now(self) -> Instant:
        return Instant.now()


# ---- Deadline ----------------------------------------------------------------


struct Deadline(Equatable, TrivialRegisterPassable, Writable):
    """An optional absolute expiry time. `Deadline.none()` never expires.

    A deadline is absolute (not a relative timeout) so retry loops
    (EINTR, partial I/O, spurious wakeups) recompute what is left instead of
    restarting the full timeout. "Expired" means `now >= at`, so
    `remaining(now)` is `Duration.ZERO` exactly when `is_expired(now)`.
    """

    var _at: Int
    """Instant nanoseconds; ignored when not `_finite`."""
    var _finite: Bool

    @inline(.always)
    def __init__(out self, *, at_nanos: Int, finite: Bool):
        """Prefer `none()` / `at()` / `after()`."""
        self._at = at_nanos
        self._finite = finite

    @staticmethod
    @inline(.always)
    def none() -> Deadline:
        return Deadline(at_nanos=0, finite=False)

    @staticmethod
    @inline(.always)
    def at(t: Instant) -> Deadline:
        return Deadline(at_nanos=t._ns, finite=True)

    @staticmethod
    def after_from(now: Instant, d: Duration) -> Deadline:
        """`now + d`; if that overflows the clock range the deadline is
        `none()`: "after 292 years" is forever, and a saturated finite value
        would still be armed as a (useless) timer."""
        if now._ns > Int.MAX - d._ns:
            return Deadline.none()
        return Deadline.at(now + d)

    @staticmethod
    def after(d: Duration) -> Deadline:
        """`d` from now on CLOCK_MONOTONIC."""
        return Deadline.after_from(Instant.now(), d)

    @staticmethod
    def after[C: Clock](clock: C, d: Duration) -> Deadline:
        """`d` from `clock.now()` (Sim or other injected clocks)."""
        return Deadline.after_from(clock.now(), d)

    @inline(.always)
    def is_none(self) -> Bool:
        return not self._finite

    def instant(self) -> Optional[Instant]:
        if not self._finite:
            return None
        return Instant(nanos=self._at)

    @inline(.always)
    def is_expired(self, now: Instant) -> Bool:
        return self._finite and now._ns >= self._at

    def is_expired(self) -> Bool:
        return self._finite and Instant.now()._ns >= self._at

    def remaining(self, now: Instant) -> Optional[Duration]:
        """None if infinite, `ZERO` if expired, else the time left."""
        if not self._finite:
            return None
        return Instant(nanos=self._at) - now

    def remaining(self) -> Optional[Duration]:
        if not self._finite:
            return None
        return self.remaining(Instant.now())

    def earliest(self, other: Self) -> Self:
        """The sooner of two deadlines (`none()` is later than any)."""
        if not self._finite:
            return other
        if not other._finite:
            return self
        return self if self._at <= other._at else other

    @inline(.always)
    def __eq__(self, rhs: Self) -> Bool:
        if not self._finite or not rhs._finite:
            return self._finite == rhs._finite
        return self._at == rhs._at

    def write_to(self, mut writer: Some[Writer]):
        if not self._finite:
            writer.write("Deadline(none)")
        else:
            writer.write("Deadline(", self._at, "ns)")


# ---- sleep -------------------------------------------------------------------


def sleep_until(t: Instant) raises IoError:
    """Sleep until CLOCK_MONOTONIC reaches `t`.

    Uses `TIMER_ABSTIME`, so EINTR (a signal handler ran) is handled by
    simply sleeping again on the same absolute time: no drift and no
    remaining-time bookkeeping. An instant at or before the clock's origin
    returns at once (the kernel rejects negative timespecs).
    """
    if t._ns <= 0:
        return
    var ts = t.as_timespec()
    while True:
        var r = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, ts)
        if r == 0:
            return
        var e = Errno(err_of(r))
        if e == Errno.EINTR:
            continue
        raise IoError.from_errno("clock_nanosleep", e)


def sleep(d: Duration) raises IoError:
    """Sleep at least `d` on CLOCK_MONOTONIC, resuming after signals.
    `Duration.MAX` sleeps (practically) forever."""
    if d.is_zero():
        return
    sleep_until(Instant.now() + d)
