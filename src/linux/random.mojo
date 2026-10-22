"""Kernel randomness through getrandom(2), for values a remote party must
not guess (DNS query IDs) and for seeds.

Flags 0: it reads the urandom pool and blocks only until that pool has been
initialized once after boot. EINTR and short reads are retried.
"""

from .errno import Errno
from .error import IoError
from .nr import SYS_getrandom
from .syscall import err_of, is_err, syscall3


def fill_random(buf: MutSpan[UInt8, _]) raises IoError:
    """Fill `buf` with random bytes (op "getrandom")."""
    var off = 0
    while off < len(buf):
        var r = syscall3(
            SYS_getrandom, Int(buf.unsafe_ptr()) + off, len(buf) - off, 0
        )
        if is_err(r):
            var e = Errno(err_of(r))
            if e == Errno.EINTR:
                continue
            raise IoError.from_errno("getrandom", e)
        off += r


def random_u64() raises IoError -> UInt64:
    var b = List[UInt8](length=8, fill=0)
    fill_random(Span(b))
    var v: UInt64 = 0
    for i in range(8):
        v = (v << 8) | UInt64(b[i])
    return v
