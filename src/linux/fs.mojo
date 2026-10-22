"""Reading small files with raw syscalls (openat/read/close): configuration
such as /etc/resolv.conf and /etc/hosts, and procfs entries.

No libc on the I/O path holds for files too: the stdlib's `open` goes
through libc. Only whole-file reads of bounded size are offered.
"""

from .consts import AT_FDCWD, O_CLOEXEC, O_RDONLY
from .errno import Errno
from .error import ErrorKind, IoError, check
from .fd import OwnedFd
from .nr import SYS_openat
from .sys import read
from .syscall import err_of, is_err, syscall4

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
