"""L2 blocking Unix-domain streams: `UnixListener`, `UnixStream`.

Same model and deadline semantics as `net.tcp`, built on the same
`net.blocking` primitives (nonblocking socket, try -> EAGAIN -> ppoll until
the deadline -> retry, EINTR retried, MSG_NOSIGNAL, CLOEXEC everywhere),
for AF_UNIX SOCK_STREAM sockets bound to a filesystem pathname or a Linux
abstract name (`net.addr.UnixAddr`).

Connecting differs from TCP. An AF_UNIX connect either completes at once or
waits for room in the listener's backlog; a nonblocking one fails with
EAGAIN and nothing stays in progress, so readiness of our own socket would
never say when to retry. So `connect` runs on a still-blocking socket and
lets the kernel wait: SO_SNDTIMEO (the connect timeout for AF_UNIX) is set
to the time left before each attempt. Nothing is in progress after EINTR
either, so unlike TCP the connect is simply re-issued with the recomputed
remaining time. The kernel rounds SO_SNDTIMEO up to a scheduler tick (1-10
ms). Afterwards SO_SNDTIMEO is cleared and the socket made O_NONBLOCK.

Pathname listeners create a socket file that nobody removes automatically:
`bind` fails with `AddrInUse` while it exists, so unlink it when done (and
before rebinding a stale path).

The module does not import `rt` (blocking layer).
"""

from std.sys import size_of

from linux import AsFd, Errno, ErrorKind, IoError
from linux import sys
from linux.abi import Timeval
from linux.consts import MSG_PEEK, SO_SNDTIMEO, SOL_SOCKET
from linux.syscall import err_of, is_err
from linux.time import Deadline, Duration

from .addr import RawSockaddr, UnixAddr
from .blocking import (
    DEFAULT_BACKLOG,
    DEFAULT_READ_TO_END_MAX,
    accept_with_deadline,
    adopt_stream_socket,
    recv_exact_with_deadline,
    recv_to_end_with_deadline,
    recv_vectored_with_deadline,
    recv_with_deadline,
    send_all_with_deadline,
    send_vectored_with_deadline,
    send_with_deadline,
)
from .reader import Read
from .socket import Domain, Shutdown, SockType, Socket


# ---- connect -----------------------------------------------------------------


def _set_send_timeout(sock: Socket, d: Duration) raises IoError:
    """SO_SNDTIMEO = `d` rounded up to whole microseconds. Zero means "no
    timeout" to the kernel, which is exactly what clearing it needs."""
    var us = (d.as_nanos() + 999) // 1000
    var tv = Timeval(us // 1_000_000, us % 1_000_000)
    var r = sys.setsockopt(
        sock, SOL_SOCKET, SO_SNDTIMEO, tv, size_of[Timeval]()
    )
    if is_err(r):
        raise IoError.from_errno("setsockopt(SO_SNDTIMEO)", Errno(err_of(r)))


def _connect_unix(addr: UnixAddr, deadline: Deadline) raises IoError -> Socket:
    """A connected, nonblocking AF_UNIX stream socket (see the module docs
    for why the connect itself blocks in the kernel)."""
    var sock = Socket.new(Domain.UNIX, SockType.STREAM)
    var raw = addr.to_raw()
    var timed = not deadline.is_none()
    while True:
        if timed:
            var left = deadline.remaining().value()
            if left.is_zero():
                # Expired: one attempt that does not wait at all.
                sock.set_nonblocking(True)
            else:
                _set_send_timeout(sock, left)
        var r = sys.connect(sock, raw.storage, raw.socklen())
        if r == 0:
            break
        var e = Errno(err_of(r))
        if e == Errno.EINTR:
            continue
        if e == Errno.EAGAIN and timed:
            raise IoError.of_kind("connect", ErrorKind.TimedOut)
        raise IoError.from_errno("connect", e)
    if timed:
        _set_send_timeout(sock, Duration.ZERO)
    sock.set_nonblocking(True)
    return sock^


def _unix_addr(raw: RawSockaddr) raises IoError -> UnixAddr:
    """`UnixAddr.from_raw`, with a zero length read as unnamed."""
    if raw.len == 0:
        return UnixAddr.unnamed()
    return UnixAddr.from_raw(raw)


# ---- UnixStream --------------------------------------------------------------


struct UnixStream(AsFd, Movable, Read, Writable):
    """A connected AF_UNIX stream with blocking reads and writes bounded by
    per-direction deadlines (semantics as `net.tcp.TcpStream`)."""

    var _sock: Socket
    var _rd: Deadline
    var _wr: Deadline

    @inline(.always)
    def __init__(out self, *, var nonblocking_socket: Socket):
        """Wrap a socket that is already O_NONBLOCK (no syscall)."""
        self._sock = nonblocking_socket^
        self._rd = Deadline.none()
        self._wr = Deadline.none()

    # ---- connecting ----------------------------------------------------------

    @staticmethod
    def connect(addr: UnixAddr) raises IoError -> UnixStream:
        """Connect, waiting as long as the listener's backlog is full. A
        missing pathname raises `NotFound`, a name nobody listens on
        `ConnectionRefused`, an unnamed address `InvalidInput`."""
        return UnixStream.connect_deadline(addr, Deadline.none())

    @staticmethod
    def connect_timeout(
        addr: UnixAddr, timeout: Duration
    ) raises IoError -> UnixStream:
        """Connect, raising `TimedOut` if the backlog stays full for
        `timeout`. A zero timeout raises `InvalidInput`."""
        if timeout.is_zero():
            raise IoError.of_kind("connect", ErrorKind.InvalidInput)
        return UnixStream.connect_deadline(addr, Deadline.after(timeout))

    @staticmethod
    def connect_deadline(
        addr: UnixAddr, deadline: Deadline
    ) raises IoError -> UnixStream:
        """Connect, raising `TimedOut` at `deadline` (an expired one makes
        one attempt that does not wait)."""
        return UnixStream(nonblocking_socket=_connect_unix(addr, deadline))

    @staticmethod
    def pair() raises IoError -> UnixStreamPair:
        """Two connected, unnamed streams (socketpair), both nonblocking and
        CLOEXEC."""
        var p = Socket.pair(Domain.UNIX, SockType.STREAM, nonblocking=True)
        return UnixStreamPair(
            UnixStream(nonblocking_socket=p.first.take()),
            UnixStream(nonblocking_socket=p.second.take()),
        )

    # ---- ownership -----------------------------------------------------------

    @staticmethod
    def from_socket(var sock: Socket) raises IoError -> UnixStream:
        """Adopt a connected AF_UNIX stream socket. Anything but a
        non-listening AF_UNIX SOCK_STREAM socket raises `InvalidInput` (op
        "UnixStream.from_socket"; the socket is closed). Sets FD_CLOEXEC and
        O_NONBLOCK (shared with every dup of the descriptor)."""
        return UnixStream(
            nonblocking_socket=adopt_stream_socket(
                sock^, unix=True, listener=False, op="UnixStream.from_socket"
            )
        )

    @inline(.always)
    def into_socket(deinit self) -> Socket:
        """The L1 socket, still O_NONBLOCK."""
        return self._sock^

    @inline(.always)
    def socket(ref self) -> ref[self._sock] Socket:
        """The L1 socket (`peer_cred`, buffer sizes, ...). Keep it
        O_NONBLOCK."""
        return self._sock

    @inline(.always)
    def raw_fd(self) -> Int32:
        return self._sock.raw_fd()

    def try_clone(self) raises IoError -> UnixStream:
        """A second handle to the same connection; deadlines are per handle
        and the clone starts with a copy (see `TcpStream.try_clone`)."""
        var s = UnixStream(nonblocking_socket=self._sock.try_clone())
        s._rd = self._rd
        s._wr = self._wr
        return s^

    def close(deinit self) raises IoError:
        self._sock^.close()

    # ---- deadlines -----------------------------------------------------------

    @inline(.always)
    def set_read_deadline(mut self, deadline: Deadline):
        self._rd = deadline

    @inline(.always)
    def set_write_deadline(mut self, deadline: Deadline):
        self._wr = deadline

    @inline(.always)
    def set_deadline(mut self, deadline: Deadline):
        self._rd = deadline
        self._wr = deadline

    @inline(.always)
    def read_deadline(self) -> Deadline:
        return self._rd

    @inline(.always)
    def write_deadline(self) -> Deadline:
        return self._wr

    # ---- I/O -----------------------------------------------------------------

    def read(self, buf: MutSpan[UInt8, _]) raises IoError -> Int:
        """Bytes read; 0 means EOF or an empty `buf`."""
        return recv_with_deadline(self._sock, buf, 0, self._rd, "read")

    def read_exact(self, buf: MutSpan[UInt8, _]) raises IoError:
        """Fill `buf`; EOF first raises `UnexpectedEof`."""
        recv_exact_with_deadline(self._sock, buf, self._rd, "read")

    def read_to_end(
        self, mut out: List[UInt8], max_bytes: Int = DEFAULT_READ_TO_END_MAX
    ) raises IoError -> Int:
        """Append everything up to EOF to `out`, at most `max_bytes` (more
        raises `InvalidData` with exactly `max_bytes` appended); the read
        deadline bounds the whole call (see `TcpStream.read_to_end`)."""
        return recv_to_end_with_deadline(
            self._sock, out, self._rd, "read", max_bytes
        )

    def read_vectored[
        o: MutOrigin
    ](self, bufs: Span[MutSpan[UInt8, o], _]) raises IoError -> Int:
        return recv_vectored_with_deadline(self._sock, bufs, self._rd, "read")

    def peek(self, buf: MutSpan[UInt8, _]) raises IoError -> Int:
        """Like `read`, leaving the data queued (MSG_PEEK)."""
        return recv_with_deadline(self._sock, buf, MSG_PEEK, self._rd, "peek")

    def write(self, buf: Span[UInt8, _]) raises IoError -> Int:
        return send_with_deadline(self._sock, buf, self._wr, "write")

    def write_all(self, buf: Span[UInt8, _]) raises IoError:
        send_all_with_deadline(self._sock, buf, self._wr, "write")

    def write_vectored[
        mut: Bool, //, o: Origin[mut=mut]
    ](self, bufs: Span[Span[UInt8, o], _]) raises IoError -> Int:
        return send_vectored_with_deadline(self._sock, bufs, self._wr, "write")

    def shutdown(self, how: Shutdown) raises IoError:
        """As `TcpStream.shutdown`: `WRITE` makes the peer read EOF after the
        queued data; `READ` discards nothing (queued data can still be read)
        and only makes reads on an empty queue return 0 at once. Unlike TCP,
        `READ` here also makes the peer's later writes fail with
        `BrokenPipe` (EPIPE)."""
        self._sock.shutdown(how)

    # ---- addresses -----------------------------------------------------------

    def local_addr(self) raises IoError -> UnixAddr:
        """Usually unnamed for a connecting client."""
        return self._sock.local_unix_addr()

    def peer_addr(self) raises IoError -> UnixAddr:
        return self._sock.peer_unix_addr()

    def write_to(self, mut writer: Some[Writer]):
        writer.write("UnixStream(fd=", self._sock.raw_fd(), ")")


struct UnixStreamPair(Movable):
    """Both ends of `UnixStream.pair`. Each is an `Optional` so the ends can
    move to separate owners: `var a = p.first.take()`."""

    var first: Optional[UnixStream]
    var second: Optional[UnixStream]

    @inline(.always)
    def __init__(out self, var first: UnixStream, var second: UnixStream):
        self.first = first^
        self.second = second^


@fieldwise_init
struct UnixAccepted(Movable):
    """What `UnixListener.accept` returns: the stream and the peer's address
    (usually unnamed). `var s = acc^.into_stream()` takes the stream."""

    var stream: UnixStream
    var addr: UnixAddr

    @inline(.always)
    def into_stream(deinit self) -> UnixStream:
        return self.stream^


# ---- UnixListener ------------------------------------------------------------


struct UnixListener(AsFd, Movable, Writable):
    """A listening AF_UNIX stream socket whose `accept` waits up to its
    deadline."""

    var _sock: Socket
    var _deadline: Deadline

    @inline(.always)
    def __init__(out self, *, var nonblocking_socket: Socket):
        self._sock = nonblocking_socket^
        self._deadline = Deadline.none()

    @staticmethod
    def bind(
        addr: UnixAddr, backlog: Int = DEFAULT_BACKLOG
    ) raises IoError -> UnixListener:
        """socket + bind + listen. An existing pathname raises `AddrInUse`
        (remove stale socket files first); `UnixAddr.unnamed()` autobinds
        to a kernel-chosen abstract name (see `local_addr`)."""
        var sock = Socket.new(Domain.UNIX, SockType.STREAM, nonblocking=True)
        sock.bind_unix(addr)
        sock.listen(backlog)
        return UnixListener(nonblocking_socket=sock^)

    @staticmethod
    def from_socket(var sock: Socket) raises IoError -> UnixListener:
        """Adopt a bound, listening AF_UNIX stream socket (inherited, socket
        activation). Anything else raises `InvalidInput` (op
        "UnixListener.from_socket"; the socket is closed) before any
        connection is accepted. Sets FD_CLOEXEC and O_NONBLOCK."""
        return UnixListener(
            nonblocking_socket=adopt_stream_socket(
                sock^, unix=True, listener=True, op="UnixListener.from_socket"
            )
        )

    def accept(self) raises IoError -> UnixAccepted:
        """Wait (up to the accept deadline) for a connection. EINTR and
        ECONNABORTED retry; EMFILE/ENFILE raise `TooManyFiles`; once the
        listener was shut down and its queue is empty, `InvalidInput`
        (EINVAL) (see `net.blocking.accept_with_deadline`)."""
        var peer = RawSockaddr()
        var sock = accept_with_deadline(self._sock, peer, self._deadline)
        return UnixAccepted(
            UnixStream(nonblocking_socket=sock^), _unix_addr(peer)
        )

    @inline(.always)
    def set_deadline(mut self, deadline: Deadline):
        self._deadline = deadline

    @inline(.always)
    def deadline(self) -> Deadline:
        return self._deadline

    def local_addr(self) raises IoError -> UnixAddr:
        return self._sock.local_unix_addr()

    @inline(.always)
    def socket(ref self) -> ref[self._sock] Socket:
        return self._sock

    @inline(.always)
    def into_socket(deinit self) -> Socket:
        return self._sock^

    @inline(.always)
    def raw_fd(self) -> Int32:
        return self._sock.raw_fd()

    def try_clone(self) raises IoError -> UnixListener:
        var l = UnixListener(nonblocking_socket=self._sock.try_clone())
        l._deadline = self._deadline
        return l^

    def close(deinit self) raises IoError:
        """Closes the socket; a pathname's file stays (unlink it)."""
        self._sock^.close()

    def write_to(self, mut writer: Some[Writer]):
        writer.write("UnixListener(fd=", self._sock.raw_fd(), ")")
