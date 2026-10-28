"""Typed wrappers over raw syscalls (socket, fd and file calls).

Each wrapper returns the raw kernel result (`>= 0`, or `-errno`).

Lifetimes: Mojo destroys a value right after its last use. In
`fcntl(owner.raw_fd(), ...)` the owner would be destroyed (closing the fd)
before the syscall runs. So wrappers take the fd *owner* (`AsFd`, borrowed
for the whole call) and memory as `Span`/`ref` arguments, never raw numbers
or addresses produced by the caller. Use `RawFd` only for descriptors that
nothing owns. Higher layers should call these
wrappers, never `syscallN` with a hand-made address.

`Msghdr` holds raw addresses (iovecs, control buffers, names); callers of
`sendmsg`/`recvmsg` must keep those buffers alive across the call (use
`keep_alive` after the call).

SIGPIPE policy. The library installs no signal handlers and leaves the
signal mask alone (but for the length of a `linux.signal.write_no_sigpipe`
call), so SIGPIPE keeps its default action: it kills the whole process
(docs/spikes.md). The kernel raises it, along with EPIPE, from every
write path that cannot carry `MSG_NOSIGNAL`:
- `write`/`writev` on a socket, or on a pipe/FIFO whose read end is closed;
- `sendfile`/`splice`/`vmsplice` into a socket or pipe (they take no
  `MSG_*` flags).
Therefore:
- sockets: `send`/`sendto`/`sendmsg` with `MSG_NOSIGNAL` only (all of
  `net` does this);
- pipes/FIFOs (`pipe2`): `write` only while this process itself holds the
  read end open (wakeup pipes), or when the application has chosen to block
  or ignore SIGPIPE; else (stderr, a log pipe) `signal.write_no_sigpipe`;
- `writev`, `sendfile`, `splice` and `vmsplice` deliberately have no
  wrappers, although `linux.nr` defines some of their numbers. Adding one
  (e.g. a sendfile static-file path for the HTTP server) goes the way
  docs/design.md records for `write_no_sigpipe`: block SIGPIPE in the
  calling thread (`rt_sigprocmask`), consume the one raised with
  `rt_sigtimedwait` before unblocking (the libpq approach; a write's
  SIGPIPE is thread-directed), or keep the call off sockets and pipes.
`tests/linux/test_linux_core_regressions.mojo` pins this policy.
"""

from .abi import Mmsghdr, Msghdr, SockaddrStorage
from .fd import AsFd
from .nr import (
    SYS_accept4,
    SYS_bind,
    SYS_close,
    SYS_connect,
    SYS_dup3,
    SYS_fcntl,
    SYS_getpeername,
    SYS_getsockname,
    SYS_getsockopt,
    SYS_ioctl,
    SYS_listen,
    SYS_pipe2,
    SYS_read,
    SYS_recvfrom,
    SYS_recvmmsg,
    SYS_recvmsg,
    SYS_sendmmsg,
    SYS_sendmsg,
    SYS_sendto,
    SYS_setsockopt,
    SYS_shutdown,
    SYS_socket,
    SYS_socketpair,
    SYS_write,
)
from .syscall import syscall1, syscall2, syscall3, syscall4, syscall5, syscall6


@inline(.always)
def keep_alive[T: AnyType](ref x: T):
    """Mark `x` as used at this point.

    Mojo destroys values right after their last use. When only a raw address
    of `x` reached the kernel (e.g. inside a `Msghdr`), call this after the
    syscall so `x` provably outlives it.
    """
    pass


@inline(.always)
def _addr[T: AnyType](ref x: T) -> Int:
    return Int(Pointer(to=x))


# ---- descriptors ---------------------------------------------------------


@inline(.always)
def close(fd: Int32) -> Int:
    """Close a raw descriptor. Owned descriptors close via `OwnedFd`."""
    return syscall1(SYS_close, Int(fd))


@inline(.always)
def fcntl[F: AsFd](fd: F, cmd: Int, arg: Int = 0) -> Int:
    return syscall3(SYS_fcntl, Int(fd.raw_fd()), cmd, arg)


@inline(.always)
def dup3[F: AsFd](oldfd: F, newfd: Int32, flags: Int) -> Int:
    return syscall3(SYS_dup3, Int(oldfd.raw_fd()), Int(newfd), flags)


@inline(.always)
def pipe2(mut fds: Array[Int32, 2], flags: Int) -> Int:
    return syscall2(SYS_pipe2, _addr(fds), flags)


@inline(.always)
def ioctl_int[F: AsFd](fd: F, request: Int, mut value: Int32) -> Int:
    """ioctl whose argument is a pointer to an int (FIONREAD, SIOCOUTQ...)."""
    return syscall3(SYS_ioctl, Int(fd.raw_fd()), request, _addr(value))


@inline(.always)
def ioctl_ref[F: AsFd, T: AnyType](fd: F, request: Int, mut arg: T) -> Int:
    """ioctl whose argument is a pointer to `arg`, which the kernel may read
    and write (a struct such as `abi.Ifreq` for SIOCGIFINDEX). `T` must be
    the ABI mirror that `request` expects."""
    return syscall3(SYS_ioctl, Int(fd.raw_fd()), request, _addr(arg))


@inline(.always)
def read[F: AsFd](fd: F, buf: MutSpan[UInt8, _]) -> Int:
    return syscall3(SYS_read, Int(fd.raw_fd()), Int(buf.unsafe_ptr()), len(buf))


@inline(.always)
def write[F: AsFd](fd: F, buf: Span[UInt8, _]) -> Int:
    """Plain write(2). It raises SIGPIPE, which kills the process, on a
    socket and on a pipe/FIFO whose read end is closed (see "SIGPIPE policy"
    in the module doc). On sockets use `send` with `MSG_NOSIGNAL`; on pipes
    write only while the read end is known to be open."""
    return syscall3(SYS_write, Int(fd.raw_fd()), Int(buf.unsafe_ptr()), len(buf))


# ---- sockets -------------------------------------------------------------


@inline(.always)
def socket(domain: Int, type_: Int, protocol: Int) -> Int:
    return syscall3(SYS_socket, domain, type_, protocol)


@inline(.always)
def socketpair(
    domain: Int, type_: Int, protocol: Int, mut fds: Array[Int32, 2]
) -> Int:
    return syscall4(SYS_socketpair, domain, type_, protocol, _addr(fds))


@inline(.always)
def bind[F: AsFd, T: AnyType](fd: F, ref addr: T, addrlen: Int) -> Int:
    return syscall3(SYS_bind, Int(fd.raw_fd()), _addr(addr), addrlen)


@inline(.always)
def connect[F: AsFd, T: AnyType](fd: F, ref addr: T, addrlen: Int) -> Int:
    return syscall3(SYS_connect, Int(fd.raw_fd()), _addr(addr), addrlen)


@inline(.always)
def listen[F: AsFd](fd: F, backlog: Int) -> Int:
    return syscall2(SYS_listen, Int(fd.raw_fd()), backlog)


@inline(.always)
def accept4[F: AsFd](
    fd: F, mut addr: SockaddrStorage, mut addrlen: UInt32, flags: Int
) -> Int:
    """`addrlen` must hold the capacity on entry (size_of SockaddrStorage)."""
    return syscall4(SYS_accept4, Int(fd.raw_fd()), _addr(addr), _addr(addrlen), flags)


@inline(.always)
def getsockname[F: AsFd](fd: F, mut addr: SockaddrStorage, mut addrlen: UInt32) -> Int:
    return syscall3(SYS_getsockname, Int(fd.raw_fd()), _addr(addr), _addr(addrlen))


@inline(.always)
def getpeername[F: AsFd](fd: F, mut addr: SockaddrStorage, mut addrlen: UInt32) -> Int:
    return syscall3(SYS_getpeername, Int(fd.raw_fd()), _addr(addr), _addr(addrlen))


@inline(.always)
def setsockopt[F: AsFd, T: AnyType](
    fd: F, level: Int, name: Int, ref value: T, optlen: Int
) -> Int:
    return syscall5(SYS_setsockopt, Int(fd.raw_fd()), level, name, _addr(value), optlen)


@inline(.always)
def getsockopt[F: AsFd, T: AnyType](
    fd: F, level: Int, name: Int, mut value: T, mut optlen: UInt32
) -> Int:
    """`optlen` must hold the capacity of `value` on entry."""
    return syscall5(
        SYS_getsockopt, Int(fd.raw_fd()), level, name, _addr(value), _addr(optlen)
    )


@inline(.always)
def shutdown[F: AsFd](fd: F, how: Int) -> Int:
    return syscall2(SYS_shutdown, Int(fd.raw_fd()), how)


@inline(.always)
def send[F: AsFd](fd: F, buf: Span[UInt8, _], flags: Int) -> Int:
    """Pass `MSG_NOSIGNAL` in `flags` for sockets (higher layers always do)."""
    return syscall6(
        SYS_sendto, Int(fd.raw_fd()), Int(buf.unsafe_ptr()), len(buf), flags, 0, 0
    )


@inline(.always)
def recv[F: AsFd](fd: F, buf: MutSpan[UInt8, _], flags: Int) -> Int:
    return syscall6(
        SYS_recvfrom, Int(fd.raw_fd()), Int(buf.unsafe_ptr()), len(buf), flags, 0, 0
    )


@inline(.always)
def sendto[F: AsFd, T: AnyType](
    fd: F, buf: Span[UInt8, _], flags: Int, ref addr: T, addrlen: Int
) -> Int:
    return syscall6(
        SYS_sendto,
        Int(fd.raw_fd()),
        Int(buf.unsafe_ptr()),
        len(buf),
        flags,
        _addr(addr),
        addrlen,
    )


@inline(.always)
def recvfrom[F: AsFd](
    fd: F,
    buf: MutSpan[UInt8, _],
    flags: Int,
    mut addr: SockaddrStorage,
    mut addrlen: UInt32,
) -> Int:
    return syscall6(
        SYS_recvfrom,
        Int(fd.raw_fd()),
        Int(buf.unsafe_ptr()),
        len(buf),
        flags,
        _addr(addr),
        _addr(addrlen),
    )


@inline(.always)
def sendmsg[F: AsFd](fd: F, ref msg: Msghdr, flags: Int) -> Int:
    return syscall3(SYS_sendmsg, Int(fd.raw_fd()), _addr(msg), flags)


@inline(.always)
def recvmsg[F: AsFd](fd: F, mut msg: Msghdr, flags: Int) -> Int:
    return syscall3(SYS_recvmsg, Int(fd.raw_fd()), _addr(msg), flags)


@inline(.always)
def sendmmsg[F: AsFd](fd: F, msgs: MutSpan[Mmsghdr, _], flags: Int) -> Int:
    """Messages sent (at least 1), or -errno if the first one failed. The
    headers point at buffers and addresses by raw address: keep their
    owners alive across the call."""
    return syscall4(
        SYS_sendmmsg, Int(fd.raw_fd()), Int(msgs.unsafe_ptr()), len(msgs), flags
    )


@inline(.always)
def recvmmsg[F: AsFd](fd: F, msgs: MutSpan[Mmsghdr, _], flags: Int) -> Int:
    """Messages received, or -errno if none was; no timeout (the socket's
    blocking mode decides). Keep the buffers' owners alive across the
    call."""
    return syscall5(
        SYS_recvmmsg,
        Int(fd.raw_fd()),
        Int(msgs.unsafe_ptr()),
        len(msgs),
        flags,
        0,
    )
