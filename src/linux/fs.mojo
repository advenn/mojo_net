"""Files with raw syscalls: whole small files (`read_file`: configuration
such as /etc/resolv.conf and /etc/hosts, and procfs entries), and opening
files beneath a directory without leaving it (`open_dir`, `open_beneath`,
`stat_fd`, `pread`), which is what a static file server needs.

No libc on the I/O path holds for files too: the stdlib's `open` goes
through libc.
"""

from .abi import OpenHow, Statx
from .consts import (
    AT_EMPTY_PATH,
    AT_FDCWD,
    O_CLOEXEC,
    O_NONBLOCK,
    O_PATH,
    O_RDONLY,
    RESOLVE_BENEATH,
    RESOLVE_NO_MAGICLINKS,
    S_IFDIR,
    S_IFMT,
    S_IFREG,
    STATX_BASIC_STATS,
)
from .errno import Errno
from .error import ErrorKind, IoError, check
from .fd import AsFd, OwnedFd
from .nr import SYS_openat, SYS_openat2, SYS_pread64, SYS_statx
from .sys import keep_alive, read
from .syscall import err_of, is_err, syscall4, syscall5

comptime DEFAULT_MAX_FILE = 16 * 1024 * 1024
"""Default cap of `read_file`: config files are far smaller."""


@inline(.always)
def _openat(path: Span[UInt8, _], flags: Int) -> Int:
    """`path` must be NUL-terminated."""
    return syscall4(SYS_openat, AT_FDCWD, Int(path.unsafe_ptr()), flags, 0)


def read_file(
    path: StringSlice,
    op: StaticString,
    max_bytes: Int = DEFAULT_MAX_FILE,
) raises IoError -> List[UInt8]:
    """The whole file at `path` (O_RDONLY | O_CLOEXEC; EINTR retried).

    Errors carry `op`: a missing file is `NotFound` (ENOENT), unreadable
    `PermissionDenied`; a file longer than `max_bytes` raises `InvalidData`
    without returning a prefix. A path containing a NUL byte is
    `InvalidInput`."""
    var cpath = List[UInt8](capacity=path.byte_length() + 1)
    for b in path.as_bytes():
        if b == 0:
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        cpath.append(b)
    cpath.append(0)
    var r: Int
    while True:
        r = _openat(Span(cpath), O_RDONLY | O_CLOEXEC)
        if not (is_err(r) and Errno(err_of(r)) == Errno.EINTR):
            break
    var fd = OwnedFd(unsafe_from_raw=Int32(check(op, r)))
    var out = List[UInt8]()
    var chunk = List[UInt8](length=64 * 1024, fill=0)
    while True:
        var n = read(fd, Span(chunk))
        if is_err(n):
            var e = Errno(err_of(n))
            if e == Errno.EINTR:
                continue
            raise IoError.from_errno(op, e)
        if n == 0:
            return out^
        if len(out) + n > max_bytes:
            raise IoError.of_kind(op, ErrorKind.InvalidData)
        out.extend(Span(chunk)[0:n])



# ---- files beneath a directory ------------------------------------------------


def _cpath(path: StringSlice, op: StaticString) raises IoError -> List[UInt8]:
    """`path` NUL-terminated; a NUL inside it is `InvalidInput`."""
    var out = List[UInt8](capacity=path.byte_length() + 1)
    for b in path.as_bytes():
        if b == 0:
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        out.append(b)
    out.append(0)
    return out^


def open_dir(path: StringSlice) raises IoError -> OwnedFd:
    """A handle on the directory at `path` (O_PATH | O_CLOEXEC), for
    `open_beneath`; `NotFound`, or `InvalidInput` if it is not a
    directory."""
    comptime op = "open_dir"
    var cpath = _cpath(path, op)
    var r: Int
    while True:
        r = syscall4(SYS_openat, AT_FDCWD, Int(cpath.unsafe_ptr()), O_PATH | O_CLOEXEC, 0)
        if not (is_err(r) and Errno(err_of(r)) == Errno.EINTR):
            break
    keep_alive(cpath)
    var fd = OwnedFd(unsafe_from_raw=Int32(check(op, r)))
    if not is_dir(stat_fd(fd)):
        raise IoError.of_kind(op, ErrorKind.InvalidInput)
    return fd^


def open_beneath[F: AsFd](dir: F, path: StringSlice) raises IoError -> OwnedFd:
    """Open `path` for reading, relative to the directory `dir`, never
    leaving it: openat2 with RESOLVE_BENEATH (no "..", absolute path or
    symlink out of it) and RESOLVE_NO_MAGICLINKS (no /proc links). Opened
    O_NONBLOCK, so that a FIFO cannot block the caller (check the type
    with `stat_fd`; reading a regular file never waits on that flag).
    `NotFound` for a missing file, `PermissionDenied`, and EXDEV
    (`InvalidInput`) for a path that would leave `dir`."""
    comptime op = "openat2"
    var cpath = _cpath(path, op)
    var how = OpenHow(
        UInt64(O_RDONLY | O_CLOEXEC | O_NONBLOCK), 0, UInt64(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)
    )
    var r: Int
    while True:
        r = syscall4(SYS_openat2, Int(dir.raw_fd()), Int(cpath.unsafe_ptr()), Int(Pointer(to=how)), 24)
        if not (is_err(r) and Errno(err_of(r)) == Errno.EINTR):
            break
    keep_alive(cpath)
    keep_alive(how)
    if is_err(r) and Errno(err_of(r)) == Errno.EXDEV:
        raise IoError.of_kind(op, ErrorKind.InvalidInput)
    return OwnedFd(unsafe_from_raw=Int32(check(op, r)))


def stat_fd[F: AsFd](fd: F) raises IoError -> Statx:
    """The metadata of the open file `fd` (statx with AT_EMPTY_PATH)."""
    var st = Statx()
    var empty = List[UInt8](length=1, fill=0)
    var r = syscall5(
        SYS_statx, Int(fd.raw_fd()), Int(empty.unsafe_ptr()), AT_EMPTY_PATH, STATX_BASIC_STATS, Int(Pointer(to=st))
    )
    keep_alive(empty)
    keep_alive(st)
    _ = check("statx", r)
    return st^


def is_dir(st: Statx) -> Bool:
    return Int(st.mode) & S_IFMT == S_IFDIR


def is_regular(st: Statx) -> Bool:
    return Int(st.mode) & S_IFMT == S_IFREG


def pread[F: AsFd](fd: F, buf: MutSpan[UInt8, _], offset: Int) raises IoError -> Int:
    """Read up to `len(buf)` bytes at `offset` (EINTR retried): the count,
    0 at the end of the file."""
    while True:
        var r = syscall4(SYS_pread64, Int(fd.raw_fd()), Int(buf.unsafe_ptr()), len(buf), offset)
        if not is_err(r):
            return r
        var e = Errno(err_of(r))
        if e != Errno.EINTR:
            raise IoError.from_errno("pread", e)
