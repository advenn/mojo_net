"""Linux system layer: raw syscalls, ABI mirrors, errno, owned fds, clocks,
readiness waits, epoll/eventfd and kernel probing.

This package knows nothing about TCP or async. It must not import `rt` or
`net`. Only `syscall.mojo` contains inline assembly. `linux.fault` is
deliberately not re-exported: it exists only in `-D MOJO_NET_FAULTS=1` test
builds.
"""

from .epoll import Epoll
from .errno import Errno
from .error import ErrorKind, IoError, check
from .eventfd import EventFd
from .fd import AsFd, OwnedFd, RawFd
from .poll import wait_ready
from .time import Clock, Deadline, Duration, Instant, MonotonicClock
