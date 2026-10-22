"""epoll(7): readiness notification for many descriptors.

`Epoll` owns the epoll descriptor (always CLOEXEC). Each registration carries a
64-bit `data` value that the kernel hands back verbatim with every event; the
event loop stores op/slab ids there, never pointers (Mojo moves values).

Waiting prefers `epoll_pwait2` (Linux 5.11), whose timeout is a nanosecond
`timespec`, so sub-millisecond timer deadlines are honored. If it fails with
ENOSYS (no such syscall) or EPERM (seccomp profiles that predate it, such as
older Docker defaults), that `Epoll` falls back permanently to `epoll_pwait`,
with the timeout rounded *up* to whole milliseconds so a wait never returns
before its deadline. No signal mask is passed: the library installs no signal
handlers, and the fallback is per instance because `linux` keeps no global
mutable state.

The free functions are raw wrappers (`>= 0` or `-errno`) for hot paths that
classify errors themselves; `Epoll` methods raise `IoError`.

Timeouts: `Epoll.wait` takes the typed forms used everywhere else in the
library, a relative `Optional[Duration]` (`None` = forever, as in
`poll.ppoll`) or an absolute `Deadline` (as in `poll.poll_until` and the
streams). Both are saturating, so a deadline that has already passed becomes
a zero timeout, never "wait forever". Signed nanosecond `Int`s, where any
negative value means forever, appear only in the raw `epoll_pwait2` /
`epoll_timeout_ms`; the old `Epoll.wait(events, timeout_ns: Int)` is
deprecated because `deadline_ns - now_ns` turns a missed deadline into an
infinite wait.
"""

from std.sys import CompilationTarget, size_of

from .abi import EpollEvent, Timespec
from .consts import EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD
from .errno import Errno
from .error import IoError, check
from .fd import AsFd, OwnedFd
from .nr import (
    SYS_epoll_create1,
    SYS_epoll_ctl,
    SYS_epoll_pwait,
    SYS_epoll_pwait2,
)
from .sys import keep_alive
from .syscall import err_of, is_err, syscall1, syscall4, syscall6
from .time import Deadline, Duration, Instant

# Kernel `sigset_t` size (64 signals) on x86_64 and aarch64. Ignored while the
# mask pointer is NULL, but passed correctly anyway.
comptime _SIGSET_SIZE = 8

comptime MAX_TIMEOUT_MS = 0x7FFF_FFFF
"""Largest `epoll_pwait` timeout (C `int` milliseconds, about 24.8 days)."""

comptime EP_MAX_EVENTS = 0x7FFF_FFFF // size_of[EpollEvent]()
"""Kernel upper bound on `maxevents` (`INT_MAX / sizeof(epoll_event)`)."""


@inline(.always)
def _addr[T: AnyType](ref x: T) -> Int:
    return Int(Pointer(to=x))


# ---- raw wrappers --------------------------------------------------------


@inline(.always)
def epoll_create1(flags: Int) -> Int:
    return syscall1(SYS_epoll_create1, flags)


@inline(.always)
def epoll_ctl[
    E: AsFd, F: AsFd
](epfd: E, op: Int, fd: F, ref event: EpollEvent) -> Int:
    """`event` must be valid even for EPOLL_CTL_DEL (pre-2.6.9 kernels
    dereferenced it; passing one costs nothing)."""
    return syscall4(
        SYS_epoll_ctl, Int(epfd.raw_fd()), op, Int(fd.raw_fd()), _addr(event)
    )


@inline(.always)
def epoll_pwait[
    E: AsFd
](epfd: E, events: MutSpan[EpollEvent, _], timeout_ms: Int) -> Int:
    """Millisecond timeout (`-1` infinite); `len(events)` is `maxevents`."""
    return syscall6(
        SYS_epoll_pwait,
        Int(epfd.raw_fd()),
        Int(events.unsafe_ptr()),
        len(events),
        timeout_ms,
        0,
        _SIGSET_SIZE,
    )


def epoll_pwait2[
    E: AsFd
](epfd: E, events: MutSpan[EpollEvent, _], timeout_ns: Int) -> Int:
    """Nanosecond timeout; `timeout_ns < 0` passes a NULL timespec (wait
    forever). `len(events)` is `maxevents`."""
    if timeout_ns < 0:
        return syscall6(
            SYS_epoll_pwait2,
            Int(epfd.raw_fd()),
            Int(events.unsafe_ptr()),
            len(events),
            0,
            0,
            _SIGSET_SIZE,
        )
    var ts = Timespec(timeout_ns // 1_000_000_000, timeout_ns % 1_000_000_000)
    var r = syscall6(
        SYS_epoll_pwait2,
        Int(epfd.raw_fd()),
        Int(events.unsafe_ptr()),
        len(events),
        _addr(ts),
        0,
        _SIGSET_SIZE,
    )
    keep_alive(ts)  # only its address reached the kernel
    return r


def epoll_timeout_ms(timeout_ns: Int) -> Int:
    """Convert a nanosecond timeout to `epoll_pwait` milliseconds.

    Negative means infinite (`-1`), 0 stays 0, anything else rounds *up* so
    the fallback never wakes before the deadline. Values beyond
    `MAX_TIMEOUT_MS` are clamped (an early wake after ~24.8 days is harmless:
    callers recompute deadlines after every wait)."""
    if timeout_ns < 0:
        return -1
    if timeout_ns >= MAX_TIMEOUT_MS * 1_000_000:
        return MAX_TIMEOUT_MS
    return (timeout_ns + 999_999) // 1_000_000


# ---- owner ---------------------------------------------------------------


struct Epoll(AsFd, Movable, Writable):
    """An epoll instance.

    Level-triggered by default; pass `EPOLLET` / `EPOLLONESHOT` in `events`
    for edge-triggered or one-shot registrations. Always `delete` an fd before
    closing it (design contract 5): epoll tracks the open file, not the fd
    number, so a closed-but-duplicated fd would keep reporting.

    Registering does not keep the fd's owner alive. Mojo destroys a value
    right after its last use, and closing an fd silently drops it from the
    set, so whoever registers an fd must own it (a slab, a struct field) or
    `sys.keep_alive` it until it is deleted.
    """

    var _fd: OwnedFd
    var _pwait2: Bool

    def __init__(out self, var fd: OwnedFd):
        """Adopt an existing epoll descriptor."""
        self._fd = fd^
        self._pwait2 = True

    @staticmethod
    def new() raises IoError -> Epoll:
        """A new epoll instance with EPOLL_CLOEXEC."""
        var r = check("epoll_create1", epoll_create1(EPOLL_CLOEXEC))
        return Epoll(OwnedFd(unsafe_from_raw=Int32(r)))

    @inline(.always)
    def raw_fd(self) -> Int32:
        return self._fd.raw_fd()

    def into_fd(deinit self) -> OwnedFd:
        return self._fd^

    def close(deinit self) raises IoError:
        """Close and report errors (the destructor ignores them)."""
        self._fd^.close()

    @inline(.always)
    def uses_pwait2(self) -> Bool:
        """False once this instance fell back to `epoll_pwait`."""
        return self._pwait2

    @inline(.always)
    def disable_pwait2(mut self):
        """Use `epoll_pwait` (millisecond timeouts) from now on, as after
        ENOSYS/EPERM. For tests, and for sandboxes whose seccomp policy kills
        the process instead of failing an unknown syscall."""
        self._pwait2 = False

    def _ctl[
        F: AsFd
    ](
        self, name: StaticString, op: Int, fd: F, events: UInt32, data: UInt64
    ) raises IoError:
        var ev = EpollEvent(events, data)
        while True:
            var r = epoll_ctl(self._fd, op, fd, ev)
            if not is_err(r):
                return
            var e = Errno(err_of(r))
            # epoll_ctl does not sleep interruptibly today; if it ever did, a
            # failed op has no effect, so retrying is safe.
            if e != Errno.EINTR:
                raise IoError.from_errno(name, e)

    def add[F: AsFd](self, fd: F, events: UInt32, data: UInt64) raises IoError:
        """Register `fd`. EEXIST if already registered (even when a one-shot
        registration is disarmed: re-arm with `modify`)."""
        self._ctl("epoll_ctl(ADD)", EPOLL_CTL_ADD, fd, events, data)

    def modify[
        F: AsFd
    ](self, fd: F, events: UInt32, data: UInt64) raises IoError:
        """Replace the interest set and data of a registered `fd` (ENOENT if
        not registered). Re-arms EPOLLONESHOT registrations."""
        self._ctl("epoll_ctl(MOD)", EPOLL_CTL_MOD, fd, events, data)

    def delete[F: AsFd](self, fd: F) raises IoError:
        """Unregister `fd` (ENOENT if not registered)."""
        self._ctl("epoll_ctl(DEL)", EPOLL_CTL_DEL, fd, 0, 0)

    def wait(
        mut self, mut events: List[EpollEvent], timeout: Optional[Duration]
    ) raises IoError -> Int:
        """Wait for readiness; return the number of events.

        `timeout` is relative: `None` waits forever, `Duration.ZERO` polls
        without blocking, `Duration.MAX` is "practically forever". Compute it
        with `Duration`/`Instant` arithmetic (`until - now` saturates at
        `ZERO`), or pass a `Deadline` to the other overloads.

        `events.capacity()` is the maximum number of events (create it with
        `List[EpollEvent](capacity=n)`); on return `len(events)` is the count
        and the buffer is never reallocated.

        Returns 0 on timeout *and* when a signal interrupted the wait
        (EINTR), so callers loop and recompute their deadline. More ready fds
        than capacity are reported by later calls (level-triggered fds
        rotate, so none starves).
        """
        return self._wait_ns(
            events, timeout.value().as_nanos() if timeout else -1
        )

    def wait(
        mut self, mut events: List[EpollEvent], deadline: Deadline, now: Instant
    ) raises IoError -> Int:
        """`wait(events, deadline.remaining(now))`: wait until an event or
        until `deadline`, measured from the caller's clock reading `now` (an
        event loop reads its `Clock` once per turn and passes that).

        `Deadline.none()` waits forever. A deadline at or before `now` polls
        once without blocking: ready events still win, and a missed deadline
        never turns into an infinite wait. Like the relative form it returns
        0 on timeout and on EINTR; loop until `deadline.is_expired(now)` with
        a fresh `now`.
        """
        return self.wait(events, deadline.remaining(now))

    def wait(
        mut self, mut events: List[EpollEvent], deadline: Deadline
    ) raises IoError -> Int:
        """`wait(events, deadline, Instant.now())`, reading CLOCK_MONOTONIC.
        Code that takes an injected `Clock` must use the `now` overload."""
        return self.wait(events, deadline.remaining())

    @deprecated(
        "signed-ns timeouts turn a missed deadline (deadline_ns - now_ns < 0)"
        " into an infinite wait; use wait(events, Optional[Duration]) (None"
        " = forever) or wait(events, deadline, now)"
    )
    def wait(
        mut self, mut events: List[EpollEvent], timeout_ns: Int
    ) raises IoError -> Int:
        """Deprecated raw form: `timeout_ns < 0` waits forever, 0 polls.
        Behaves exactly as before; kept so existing callers still build."""
        return self._wait_ns(events, timeout_ns)

    def _wait_ns(
        mut self, mut events: List[EpollEvent], timeout_ns: Int
    ) raises IoError -> Int:
        """The shared body: `timeout_ns < 0` waits forever (the raw
        `epoll_pwait2` convention). Private so that no new public caller
        does signed-ns arithmetic against it."""
        comptime if CompilationTarget.is_x86():
            comptime assert size_of[EpollEvent]() == 12, "packed epoll_event"
        else:
            comptime assert size_of[EpollEvent]() == 16, "epoll_event"
        var cap = min(events.capacity(), EP_MAX_EVENTS)
        if cap <= 0:
            events.clear()
            raise IoError.from_errno("epoll_wait(capacity 0)", Errno.EINVAL)
        # The kernel writes up to `cap` entries straight into the List's
        # contiguous buffer; EpollEvent is plain data, so exposing the
        # not-yet-written tail briefly is harmless.
        events.resize(unsafe_uninit_length=cap)
        var r = 0
        if self._pwait2:
            r = epoll_pwait2(self._fd, Span(events), timeout_ns)
            if is_err(r):
                var e = Errno(err_of(r))
                if e == Errno.ENOSYS or e == Errno.EPERM:
                    self._pwait2 = False
        var name: StaticString = "epoll_pwait2"
        if not self._pwait2:
            name = "epoll_pwait"
            r = epoll_pwait(
                self._fd, Span(events), epoll_timeout_ms(timeout_ns)
            )
        if is_err(r):
            events.shrink(0)
            var e = Errno(err_of(r))
            if e == Errno.EINTR:
                return 0
            raise IoError.from_errno(name, e)
        events.shrink(r)
        return r

    def write_to(self, mut writer: Some[Writer]):
        writer.write("Epoll(", self._fd.raw_fd(), ")")
