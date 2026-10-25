"""Signals as data: thread masks (rt_sigprocmask) and signalfds.

The library installs no signal handlers. A program that wants signals
blocks them and reads them from a `SignalFd`, which an epoll loop can
watch. Blocking must hold in every thread, though: a process-directed
signal (`kill`) goes to any thread that does not block it, and there the
Mojo runtime's handler ends the process (SIGTERM, SIGINT, SIGHUP). The
runtime starts its threads before `main`, with the mask the process was
started with, so blocking in `main` is too late: block first, then re-run
the program (`linux.process.Exec.this_program().exec()`), whose threads
inherit the mask. docs/spikes.md has the measurements.

Signals 32 and 33 belong to glibc, which the Mojo runtime runs on: thread
cancellation and `setuid`/`setgid` across threads, which waits until every
thread has handled signal 33. As glibc's own `sigprocmask` does, `block`,
`set_mask` and `SignalFd.new` leave them out of any set they are given, so
that blocking "every signal" cannot hang a later `setuid`.
"""

from .abi import SignalfdSiginfo
from .consts import SFD_CLOEXEC, SFD_NONBLOCK, SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK
from .errno import Errno
from .error import IoError, check
from .fd import AsFd, OwnedFd
from .nr import SYS_read, SYS_rt_sigprocmask, SYS_signalfd4
from .sys import keep_alive
from .syscall import err_of, is_err, syscall3, syscall4

comptime _SIGSET_SIZE = 8
"""The kernel's sigset size on x86_64 and aarch64 (64 signals)."""


@fieldwise_init
struct SignalSet(Equatable, TrivialRegisterPassable, Writable):
    """A set of signals 1..64, as the kernel's sigset: bit n-1 is signal n."""

    var bits: UInt64

    @staticmethod
    def empty() -> SignalSet:
        return SignalSet(0)

    @staticmethod
    def of(*signals: Int) -> SignalSet:
        var s = SignalSet(0)
        for sig in signals:
            s = s.with_signal(sig)
        return s

    def with_signal(self, sig: Int) -> SignalSet:
        """This set plus `sig` (1..64; others are ignored)."""
        if sig < 1 or sig > 64:
            return self
        return SignalSet(self.bits | (UInt64(1) << UInt64(sig - 1)))

    def contains(self, sig: Int) -> Bool:
        if sig < 1 or sig > 64:
            return False
        return (self.bits >> UInt64(sig - 1)) & 1 == 1

    def includes(self, other: SignalSet) -> Bool:
        """Every signal of `other` is in this set."""
        return other.bits & ~self.bits == 0

    def __eq__(self, other: SignalSet) -> Bool:
        return self.bits == other.bits

    def write_to(self, mut writer: Some[Writer]):
        writer.write("SignalSet(")
        var first = True
        for sig in range(1, 65):
            if self.contains(sig):
                if not first:
                    writer.write(",")
                writer.write(sig)
                first = False
        writer.write(")")


comptime _LIBC_SIGNALS: UInt64 = (UInt64(1) << 31) | (UInt64(1) << 32)
"""Signals 32 (SIGCANCEL) and 33 (SIGSETXID): glibc's own (module docs)."""


def _sigprocmask(how: Int, set: SignalSet) raises IoError -> SignalSet:
    var new = set.bits & ~_LIBC_SIGNALS if how != SIG_UNBLOCK else set.bits
    var old: UInt64 = 0
    var r = syscall4(
        SYS_rt_sigprocmask, how, Int(Pointer(to=new)), Int(Pointer(to=old)), _SIGSET_SIZE
    )
    keep_alive(new)
    keep_alive(old)
    _ = check("rt_sigprocmask", r)
    return SignalSet(old)


def block(set: SignalSet) raises IoError -> SignalSet:
    """Block `set` in the calling thread (only), less glibc's signals 32 and
    33 (module docs); returns its mask before."""
    return _sigprocmask(SIG_BLOCK, set)


def unblock(set: SignalSet) raises IoError -> SignalSet:
    """Unblock `set` in the calling thread; returns its mask before."""
    return _sigprocmask(SIG_UNBLOCK, set)


def set_mask(set: SignalSet) raises IoError -> SignalSet:
    """Make `set`, less glibc's signals 32 and 33 (module docs), the calling
    thread's mask; returns the mask before."""
    return _sigprocmask(SIG_SETMASK, set)


def blocked() raises IoError -> SignalSet:
    """The calling thread's mask."""
    return block(SignalSet.empty())


struct SignalFd(AsFd, Movable, Writable):
    """A signalfd for a set of signals (CLOEXEC, nonblocking): readable
    (EPOLLIN) while one of them is pending for the process or the reading
    thread. The signals must be blocked, in every thread, or they are
    delivered instead of queued (see the module docs)."""

    var _fd: OwnedFd

    def __init__(out self, var fd: OwnedFd):
        self._fd = fd^

    @staticmethod
    def new(set: SignalSet) raises IoError -> SignalFd:
        """A signalfd for `set`, less glibc's signals 32 and 33 (module
        docs)."""
        var bits = set.bits & ~_LIBC_SIGNALS
        var r = syscall4(
            SYS_signalfd4, -1, Int(Pointer(to=bits)), _SIGSET_SIZE, SFD_CLOEXEC | SFD_NONBLOCK
        )
        keep_alive(bits)
        return SignalFd(OwnedFd(unsafe_from_raw=Int32(check("signalfd4", r))))

    @inline(.always)
    def raw_fd(self) -> Int32:
        return self._fd.raw_fd()

    def take(self) raises IoError -> Int:
        """Dequeue one pending signal of the set: its number, or 0 if none
        is pending."""
        var info = SignalfdSiginfo()
        while True:
            var r = syscall3(SYS_read, Int(self._fd.raw_fd()), Int(Pointer(to=info)), 128)
            keep_alive(info)
            if not is_err(r):
                return Int(info.signo)
            var e = Errno(err_of(r))
            if e == Errno.EAGAIN:
                return 0
            if e != Errno.EINTR:
                raise IoError.from_errno("read(signalfd)", e)

    def write_to(self, mut writer: Some[Writer]):
        writer.write("SignalFd(", self._fd.raw_fd(), ")")
