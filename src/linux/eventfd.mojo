"""eventfd(2): a 64-bit kernel counter used as a wakeup source.

The event loop registers a nonblocking `EventFd` with epoll; another thread
`signal()`s it to wake a blocked `Epoll.wait`, and the loop `drain()`s it.
Plain `read`/`write` are correct here: an eventfd is not a socket, so there is
no SIGPIPE to suppress and no `send` flags to pass.
"""

from .consts import EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE
from .errno import Errno
from .error import IoError, check
from .fd import AsFd, OwnedFd
from .nr import SYS_eventfd2, SYS_read, SYS_write
from .sys import keep_alive
from .syscall import err_of, is_err, syscall2, syscall3

comptime EVENTFD_MAX: UInt64 = 0xFFFF_FFFF_FFFF_FFFE
"""Largest counter value; adding past it blocks or fails with EAGAIN."""


@inline(.always)
def _addr[T: AnyType](ref x: T) -> Int:
    return Int(Pointer(to=x))


# ---- raw wrappers --------------------------------------------------------


@inline(.always)
def eventfd2(initval: UInt32, flags: Int) -> Int:
    return syscall2(SYS_eventfd2, Int(initval), flags)


@inline(.always)
def eventfd_read[F: AsFd](fd: F, mut value: UInt64) -> Int:
    """Read (and reset, or decrement in semaphore mode) the counter."""
    return syscall3(SYS_read, Int(fd.raw_fd()), _addr(value), 8)


@inline(.always)
def eventfd_write[F: AsFd](fd: F, value: UInt64) -> Int:
    """Add `value` to the counter (`0xFFFF_FFFF_FFFF_FFFF` is EINVAL)."""
    var v = value
    var r = syscall3(SYS_write, Int(fd.raw_fd()), _addr(v), 8)
    keep_alive(v)  # only its address reached the kernel
    return r


# ---- owner ---------------------------------------------------------------


struct EventFd(AsFd, Movable, Writable):
    """An eventfd counter (always CLOEXEC).

    Readable (EPOLLIN) while the counter is non-zero, writable (EPOLLOUT)
    while at least 1 can be added.
    """

    var _fd: OwnedFd

    def __init__(out self, var fd: OwnedFd):
        """Adopt an existing eventfd descriptor."""
        self._fd = fd^

    @staticmethod
    def new(
        nonblocking: Bool = True, semaphore: Bool = False
    ) raises IoError -> EventFd:
        """A new counter starting at 0. Nonblocking by default, which is what
        an event loop wants: `drain` never sleeps and `signal` never blocks.
        With `semaphore`, each `drain` takes 1 instead of the whole count."""
        var flags = EFD_CLOEXEC
        if nonblocking:
            flags |= EFD_NONBLOCK
        if semaphore:
            flags |= EFD_SEMAPHORE
        var r = check("eventfd2", eventfd2(0, flags))
        return EventFd(OwnedFd(unsafe_from_raw=Int32(r)))

    @inline(.always)
    def raw_fd(self) -> Int32:
        return self._fd.raw_fd()

    def into_fd(deinit self) -> OwnedFd:
        return self._fd^

    def close(deinit self) raises IoError:
        """Close and report errors (the destructor ignores them)."""
        self._fd^.close()

    def add(self, value: UInt64) raises IoError -> Bool:
        """Add `value` to the counter. False if that would pass `EVENTFD_MAX`
        on a nonblocking eventfd (EAGAIN); a blocking one waits for a read.
        `0xFFFF_FFFF_FFFF_FFFF` raises EINVAL. EINTR is retried: nothing was
        added, and a lost wakeup would be a bug."""
        while True:
            var r = eventfd_write(self._fd, value)
            if not is_err(r):
                return True
            var e = Errno(err_of(r))
            if e == Errno.EAGAIN:
                return False
            if e != Errno.EINTR:
                raise IoError.from_errno("eventfd_write", e)

    def signal(self) raises IoError:
        """Wake whoever polls this eventfd (add 1). A saturated counter
        (EAGAIN) already guarantees a pending wakeup, so it is not an error."""
        _ = self.add(1)

    def drain(self) raises IoError -> UInt64:
        """Read the counter and reset it to 0 (semaphore mode: take 1).

        Returns 0 if nothing was pending (EAGAIN on a nonblocking eventfd) or
        a signal interrupted a blocking read (EINTR); callers that need a
        non-zero value loop.
        """
        var v: UInt64 = 0
        var r = eventfd_read(self._fd, v)
        if is_err(r):
            var e = Errno(err_of(r))
            if e == Errno.EAGAIN or e == Errno.EINTR:
                return 0
            raise IoError.from_errno("eventfd_read", e)
        return v

    def write_to(self, mut writer: Some[Writer]):
        writer.write("EventFd(", self._fd.raw_fd(), ")")
