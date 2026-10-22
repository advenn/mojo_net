"""Owned file descriptors."""

from .consts import F_DUPFD_CLOEXEC, F_GETFD, F_GETFL, F_SETFL, FD_CLOEXEC, O_NONBLOCK
from .errno import Errno
from .error import IoError, check
from .nr import SYS_close, SYS_fcntl
from .syscall import err_of, is_err, syscall1, syscall3


trait AsFd:
    """Something that holds an open descriptor for at least as long as it is
    borrowed. Syscall wrappers take `AsFd` owners, not raw numbers, so the
    owner cannot be destroyed (closing the fd) before the syscall runs."""

    def raw_fd(self) -> Int32:
        ...


@fieldwise_init
struct RawFd(AsFd, TrivialRegisterPassable, Writable):
    """A descriptor number nobody owns through this value (stdio, an fd being
    adopted, ...). The caller guarantees it stays open while used."""

    var fd: Int32

    @inline(.always)
    def raw_fd(self) -> Int32:
        return self.fd

    def write_to(self, mut writer: Some[Writer]):
        writer.write("RawFd(", self.fd, ")")


struct OwnedFd(AsFd, Movable, Writable):
    """Sole owner of a file descriptor; closes it when destroyed.

    Not copyable: use `try_clone` for a second descriptor (dup with CLOEXEC).
    `close()` reports errors; the destructor ignores them (like Rust's
    `OwnedFd`). Close is never retried on EINTR: Linux has already released
    the descriptor, and retrying could close a reused number.
    """

    var _fd: Int32

    @inline(.always)
    def __init__(out self, *, unsafe_from_raw: Int32):
        """Take ownership of an open descriptor nobody else will close."""
        self._fd = unsafe_from_raw

    def __deinit__(deinit self):
        _ = syscall1(SYS_close, Int(self._fd))

    @inline(.always)
    def raw_fd(self) -> Int32:
        """The descriptor number, still owned by `self`.

        Do not write `syscall(owner.raw_fd())` on an owner whose last use is
        that expression: the owner is destroyed before the syscall runs.
        Pass the owner itself to `linux.sys` wrappers instead."""
        return self._fd

    def into_raw(deinit self) -> Int32:
        """Release ownership without closing."""
        return self._fd

    def close(deinit self) raises IoError:
        """Close and report errors. EINTR counts as closed."""
        var r = syscall1(SYS_close, Int(self._fd))
        if is_err(r) and Errno(err_of(r)) != Errno.EINTR:
            raise IoError.from_errno("close", Errno(err_of(r)))

    def try_clone(self) raises IoError -> OwnedFd:
        """A new descriptor for the same open file, with CLOEXEC set."""
        var r = check(
            "fcntl(F_DUPFD_CLOEXEC)",
            syscall3(SYS_fcntl, Int(self._fd), F_DUPFD_CLOEXEC, 0),
        )
        return OwnedFd(unsafe_from_raw=Int32(r))

    def is_nonblocking(self) raises IoError -> Bool:
        var fl = check(
            "fcntl(F_GETFL)", syscall3(SYS_fcntl, Int(self._fd), F_GETFL, 0)
        )
        return (fl & O_NONBLOCK) != 0

    def set_nonblocking(self, on: Bool) raises IoError:
        var fl = check(
            "fcntl(F_GETFL)", syscall3(SYS_fcntl, Int(self._fd), F_GETFL, 0)
        )
        var want = (fl | O_NONBLOCK) if on else (fl & ~O_NONBLOCK)
        if want != fl:
            _ = check(
                "fcntl(F_SETFL)",
                syscall3(SYS_fcntl, Int(self._fd), F_SETFL, want),
            )

    def is_cloexec(self) raises IoError -> Bool:
        var fl = check(
            "fcntl(F_GETFD)", syscall3(SYS_fcntl, Int(self._fd), F_GETFD, 0)
        )
        return (fl & FD_CLOEXEC) != 0

    def write_to(self, mut writer: Some[Writer]):
        writer.write("OwnedFd(", self._fd, ")")
