"""Readiness waiting with ppoll(2): the blocking layer's "wait until the fd
is ready or the deadline passes" primitive.

ppoll (not poll: aarch64 has no `poll` syscall) takes a relative timespec
with nanosecond resolution and a NULL sigmask here, so the library never
touches the signal mask. Blocking I/O follows the pattern from
docs/design.md: try the syscall, on EAGAIN `wait_ready`, retry. Because the
deadline is absolute, every EINTR or early wakeup recomputes what is left
instead of restarting the full timeout.

Error conditions on the fd (POLLERR, POLLHUP, POLLRDHUP) are *returned*, not
raised: usually they mean "the next syscall will not block", and that
syscall (recv, send, getsockopt(SO_ERROR)) yields the precise errno
(ECONNRESET vs ECONNREFUSED vs EOF). Only POLLNVAL (fd not open) raises.

Caveat: POLLERR is also reported while the socket's *error queue* is
non-empty (IP_RECVERR/ICMP reports, MSG_ZEROCOPY completions, timestamps).
Then recv/send may still return EAGAIN and SO_ERROR may be 0, so a caller
that loops "wait, retry" must not treat POLLERR as progress: read SO_ERROR,
and if nothing is pending either drain the queue (recvmsg MSG_ERRQUEUE) or
wait without the error condition. `net.blocking` does this (review F01).
"""

from .abi import Pollfd
from .consts import POLLNVAL
from .errno import Errno
from .error import ErrorKind, IoError
from .fd import AsFd
from .nr import SYS_ppoll
from .sys import keep_alive
from .syscall import err_of, syscall5
from .time import Deadline, Duration

# Size of the kernel's sigset_t (64 signals) on x86_64 and aarch64. Only
# checked when a sigmask is passed; we always pass NULL.
comptime _KERNEL_SIGSET_SIZE = 8


@inline(.always)
def ppoll(fds: MutSpan[Pollfd, _], timeout: Optional[Duration]) -> Int:
    """Raw `ppoll(fds, nfds, timeout, NULL, 8)`: count of ready entries,
    0 on timeout, or `-errno`. `None` waits forever; `Duration.ZERO` only
    checks. Entries with a negative fd are ignored by the kernel (their
    `revents` is 0).

    The `Pollfd` entries hold raw fd numbers: the caller must keep their
    owners alive across the call (`sys.keep_alive(owner)` after it).
    """
    if timeout:
        # The kernel writes the unslept time back into this copy.
        var ts = timeout.value().as_timespec()
        var r = syscall5(
            SYS_ppoll,
            Int(fds.unsafe_ptr()),
            len(fds),
            Int(Pointer(to=ts)),
            0,
            _KERNEL_SIGSET_SIZE,
        )
        keep_alive(ts)  # only its address reached the kernel
        return r
    return syscall5(
        SYS_ppoll, Int(fds.unsafe_ptr()), len(fds), 0, 0, _KERNEL_SIGSET_SIZE
    )


def poll_until(
    fds: MutSpan[Pollfd, _], deadline: Deadline, op: StaticString
) raises IoError -> Int:
    """Wait until an entry is ready or `deadline` passes; returns the number
    of ready entries (`revents` set), 0 once the deadline has passed.

    EINTR (a signal handler ran) and wakeups before the deadline retry with
    the recomputed remaining time. An already expired deadline still polls
    once with a zero timeout, so readiness that is already there wins.
    Raises only for ppoll's own failures (ENOMEM, EINVAL when `len(fds)`
    exceeds RLIMIT_NOFILE), tagged with `op`.
    """
    while True:
        var r = ppoll(fds, deadline.remaining())
        if r > 0:
            return r
        if r == 0:
            if deadline.is_expired():
                return 0
            continue
        var e = Errno(err_of(r))
        if e == Errno.EINTR:
            continue
        raise IoError.from_errno(op, e)


def wait_ready[
    F: AsFd
](
    fd: F, events: Int16, deadline: Deadline, op: StaticString
) raises IoError -> Int16:
    """Block until `fd` reports any of `events` (POLLIN, POLLOUT, ...) or an
    error condition, and return `revents`.

    - POLLERR / POLLHUP / POLLRDHUP are returned to the caller, who then
      performs the real syscall to learn the precise errno. POLLERR can also
      mean only "error queue non-empty", with nothing for recv/send to
      report: see the module doc before looping on it.
    - POLLNVAL (the descriptor is not open) raises `IoError` kind `Closed`
      (errno EBADF), as does a negative descriptor, which ppoll would
      silently ignore and so wait until the deadline.
    - Deadline passed with nothing ready raises `IoError.of_kind(op,
      ErrorKind.TimedOut)`.
    """
    var raw = fd.raw_fd()
    if raw < 0:
        raise IoError.from_errno(op, Errno.EBADF)
    var pfd = Array[Pollfd, 1](fill=Pollfd(raw, events, 0))
    if poll_until(Span(pfd), deadline, op) == 0:
        raise IoError.of_kind(op, ErrorKind.TimedOut)
    var rev = pfd[0].revents
    if (Int(rev) & POLLNVAL) != 0:
        raise IoError.from_errno(op, Errno.EBADF)
    return rev
