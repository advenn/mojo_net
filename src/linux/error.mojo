"""The error type shared by every layer (linux, rt, net).

`IoError` carries a portable `ErrorKind`, the raw `Errno` (or `Errno(0)` for
errors that did not come from the kernel, such as deadline expiry), and the
name of the operation that failed. All public APIs raise `IoError`; internal
hot paths pass raw `-errno` integers and convert at the boundary with `check`.

`TimedOut` has two causes that need opposite handling, so never retry on
`kind == TimedOut` alone; ask `IoError.is_deadline()`:
- library deadline expiry (errno 0, from `wait_ready` and everything built
  on it): the expiry changed nothing on the fd; set a new deadline and
  carry on;
- kernel `ETIMEDOUT` (SYN retries exhausted, `TCP_USER_TIMEOUT`, unanswered
  keepalive probes): the kernel aborted the connection. It is dead: the next
  read sees EOF and the next write EPIPE. Close it.
"""

from .errno import Errno
from .syscall import err_of, is_err


@fieldwise_init
struct ErrorKind(TrivialRegisterPassable, Equatable, Writable):
    """Portable error category (modelled on Rust's `io::ErrorKind`)."""

    var _v: UInt8

    comptime Other = ErrorKind(0)
    comptime WouldBlock = ErrorKind(1)
    comptime Interrupted = ErrorKind(2)
    comptime TimedOut = ErrorKind(3)
    """A library deadline expired (errno 0: the fd is unchanged and usable)
    or the kernel timed the connection out (errno ETIMEDOUT: it is dead).
    Distinguish them with `IoError.is_deadline()` before retrying."""
    comptime ConnectionRefused = ErrorKind(4)
    comptime ConnectionReset = ErrorKind(5)
    comptime ConnectionAborted = ErrorKind(6)
    comptime BrokenPipe = ErrorKind(7)
    comptime NotConnected = ErrorKind(8)
    comptime AlreadyConnected = ErrorKind(9)
    comptime InProgress = ErrorKind(10)
    comptime AddrInUse = ErrorKind(11)
    comptime AddrNotAvailable = ErrorKind(12)
    comptime NetworkUnreachable = ErrorKind(13)
    comptime NetworkDown = ErrorKind(14)
    comptime HostUnreachable = ErrorKind(15)
    comptime InvalidInput = ErrorKind(16)
    comptime PermissionDenied = ErrorKind(17)
    comptime NotFound = ErrorKind(18)
    comptime TooManyFiles = ErrorKind(19)
    comptime OutOfMemory = ErrorKind(20)
    comptime Unsupported = ErrorKind(21)
    comptime UnexpectedEof = ErrorKind(22)
    comptime WriteZero = ErrorKind(23)
    comptime Canceled = ErrorKind(24)
    comptime Closed = ErrorKind(25)
    comptime InvalidData = ErrorKind(26)
    """The peer sent bytes that violate the protocol (vs InvalidInput: a bad
    argument from our caller)."""

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self._v == other._v

    def name(self) -> StaticString:
        if self._v == 1:
            return "WouldBlock"
        if self._v == 2:
            return "Interrupted"
        if self._v == 3:
            return "TimedOut"
        if self._v == 4:
            return "ConnectionRefused"
        if self._v == 5:
            return "ConnectionReset"
        if self._v == 6:
            return "ConnectionAborted"
        if self._v == 7:
            return "BrokenPipe"
        if self._v == 8:
            return "NotConnected"
        if self._v == 9:
            return "AlreadyConnected"
        if self._v == 10:
            return "InProgress"
        if self._v == 11:
            return "AddrInUse"
        if self._v == 12:
            return "AddrNotAvailable"
        if self._v == 13:
            return "NetworkUnreachable"
        if self._v == 14:
            return "NetworkDown"
        if self._v == 15:
            return "HostUnreachable"
        if self._v == 16:
            return "InvalidInput"
        if self._v == 17:
            return "PermissionDenied"
        if self._v == 18:
            return "NotFound"
        if self._v == 19:
            return "TooManyFiles"
        if self._v == 20:
            return "OutOfMemory"
        if self._v == 21:
            return "Unsupported"
        if self._v == 22:
            return "UnexpectedEof"
        if self._v == 23:
            return "WriteZero"
        if self._v == 24:
            return "Canceled"
        if self._v == 25:
            return "Closed"
        if self._v == 26:
            return "InvalidData"
        return "Other"

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.name())

    @staticmethod
    def of(e: Errno) -> ErrorKind:
        """Classify an errno."""
        if e == Errno.EAGAIN:
            return Self.WouldBlock
        if e == Errno.EINTR:
            return Self.Interrupted
        if e == Errno.ETIMEDOUT:
            return Self.TimedOut
        if e == Errno.ECONNREFUSED:
            return Self.ConnectionRefused
        if e == Errno.ECONNRESET:
            return Self.ConnectionReset
        if e == Errno.ECONNABORTED:
            return Self.ConnectionAborted
        if e == Errno.EPIPE:
            return Self.BrokenPipe
        if e == Errno.ENOTCONN:
            return Self.NotConnected
        if e == Errno.EISCONN:
            return Self.AlreadyConnected
        if e == Errno.EINPROGRESS or e == Errno.EALREADY:
            return Self.InProgress
        if e == Errno.EADDRINUSE:
            return Self.AddrInUse
        if e == Errno.EADDRNOTAVAIL:
            return Self.AddrNotAvailable
        if e == Errno.ENETUNREACH:
            return Self.NetworkUnreachable
        if e == Errno.ENETDOWN:
            return Self.NetworkDown
        if e == Errno.EHOSTUNREACH or e == Errno.EHOSTDOWN:
            return Self.HostUnreachable
        if (
            e == Errno.EINVAL
            or e == Errno.EAFNOSUPPORT
            or e == Errno.ENAMETOOLONG
        ):
            return Self.InvalidInput
        if e == Errno.EACCES or e == Errno.EPERM:
            return Self.PermissionDenied
        if e == Errno.ENOENT:
            return Self.NotFound
        if e == Errno.EMFILE or e == Errno.ENFILE:
            return Self.TooManyFiles
        if e == Errno.ENOMEM or e == Errno.ENOBUFS:
            return Self.OutOfMemory
        if (
            e == Errno.EOPNOTSUPP
            or e == Errno.ENOPROTOOPT
            or e == Errno.EPROTONOSUPPORT
            or e == Errno.ENOSYS
        ):
            return Self.Unsupported
        if e == Errno.ECANCELED:
            return Self.Canceled
        if e == Errno.EBADF:
            return Self.Closed
        return Self.Other


@fieldwise_init
struct IoError(Copyable, ImplicitlyCopyable, Movable, Writable):
    """An I/O failure: what kind, which errno (0 if none), during which op.

    Passed in memory, not in registers: as `TrivialRegisterPassable`, Mojo
    1.2 split its `op` pointer into bytes in every typed-raise result, so
    each raising call cost its success path ~85 instructions (the error
    built without a branch, then reassembled by the caller); in memory a
    success is a flag test (HR3, bench/http/README.md)."""

    var kind: ErrorKind
    var errno: Errno
    var op: StaticString

    @staticmethod
    @inline(.always)
    def from_errno(op: StaticString, e: Errno) -> IoError:
        return IoError(ErrorKind.of(e), e, op)

    @staticmethod
    @inline(.always)
    def of_kind(op: StaticString, kind: ErrorKind) -> IoError:
        """An error that did not come from the kernel (deadline, EOF, ...).
        `of_kind(op, ErrorKind.TimedOut)` is how deadline expiry is raised
        (see `is_deadline`)."""
        return IoError(kind, Errno(0), op)

    @inline(.always)
    def is_deadline(self) -> Bool:
        """True for a library-side deadline expiry: kind `TimedOut` with
        errno 0, as raised by `wait_ready` and the blocking `net` streams.
        The expiry itself changes nothing on the fd, which may be used
        again with a new deadline (a composite operation may still have
        moved a prefix first; see the `net` module docs).

        False for every kernel error, including `ETIMEDOUT` (also kind
        `TimedOut`): that means the kernel aborted the connection
        (`TCP_USER_TIMEOUT`, failed keepalive probes, SYN retries
        exhausted), so retrying on it only yields EOF or `BrokenPipe`.
        """
        return self.kind == ErrorKind.TimedOut and self.errno.value == 0

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.op, ": ", self.kind)
        if self.errno.value != 0:
            writer.write(" (", self.errno, ")")


@inline(.always)
def check(op: StaticString, ret: Int) raises IoError -> Int:
    """Return `ret` unchanged, or raise the `IoError` it encodes."""
    if is_err(ret):
        raise IoError.from_errno(op, Errno(err_of(ret)))
    return ret
