"""L2 UDP: `UdpSocket`, datagrams in two modes, blocking with per-direction
deadlines, or nonblocking for readiness loops.

    var sock = UdpSocket.bind(SocketAddr.parse("0.0.0.0:5353"))
    sock.set_read_deadline(Deadline.after(Duration.from_secs(2)))
    var buf = List[UInt8](length=1500, fill=0)
    var d = sock.recv_from(Span(buf))           # waits up to the deadline
    _ = sock.send_to(Span(buf)[: d.len], d.sender)

Datagrams are not a stream:
- **Whole or nothing.** Each send is one datagram, sent completely or not
  at all. One larger than the protocol allows (65507 payload bytes over
  IPv4) raises (EMSGSIZE). An empty datagram is valid and arrives with
  length 0: there is no EOF.
- **One per receive.** A receive returns one datagram. When it is longer
  than the buffer, the rest is discarded, and `Datagram.truncated()` says
  so (the receive passes MSG_TRUNC, so `size` is the full length): it is
  never silent. A receive into an empty buffer drops a datagram; a peek
  into one reads the next datagram's size.
- **No guarantees.** Delivery, order and uniqueness are not guaranteed;
  protocols on top deal with loss.

Two modes:
- **Blocking.** `send_to` / `recv_from` (and `send` / `recv` once
  connected) wait up to the write / read deadline. As in `net.tcp`,
  deadlines are absolute `linux.time.Deadline`s that apply until changed;
  expiry raises `TimedOut` (`is_deadline()`) and leaves the socket usable;
  EINTR retries; data already queued wins over an expired deadline.
- **Nonblocking.** `try_send_to` / `try_recv_from` / `try_send` /
  `try_recv` / `try_peek_from` never wait and ignore deadlines: None
  instead of EAGAIN. The socket is always O_NONBLOCK; register it with
  `linux.Epoll` and drain until None after each edge.

Connected sockets (`connect`): the kernel fixes the destination, drops
datagrams from any other sender, and reports ICMP errors. After a "port
unreachable" the next send or receive raises `ConnectionRefused`. An
unconnected socket never sees ICMP errors.

Every socket is CLOEXEC and O_NONBLOCK, and sends pass MSG_NOSIGNAL. L1
options (TTL, TOS, buffer sizes, ...) are on `socket()`.
This module does not import `rt` (blocking layer).
"""

from linux import AsFd, Errno, ErrorKind, IoError, sys
from linux.consts import MSG_NOSIGNAL, MSG_PEEK, MSG_TRUNC, POLLIN, POLLOUT
from linux.syscall import err_of
from linux.time import Deadline, Duration

from .addr import IpAddr, Ipv4Addr, RawSockaddr, SocketAddr
from .blocking import _Waiter, _set_cloexec
from .socket import Domain, SockType, Socket


@fieldwise_init
struct Datagram(TrivialRegisterPassable, Writable):
    """What a receive returns."""

    var len: Int
    """Bytes stored in the buffer: `min(size, len(buf))`."""
    var size: Int
    """The datagram's full length; larger than `len` when it was
    truncated."""
    var sender: SocketAddr
    """Who sent it (on a dual-stack IPv6 socket, IPv4 senders appear
    IPv4-mapped: see `ip().to_canonical()`)."""

    @inline(.always)
    def truncated(self) -> Bool:
        """The datagram did not fit: its last `size - len` bytes are lost."""
        return self.size > self.len

    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            "Datagram(len=", self.len, ", size=", self.size, ", sender=",
            self.sender, ")",
        )


# ---- the syscalls ------------------------------------------------------------


@inline(.always)
def _datagram(r: Int, buf_len: Int, raw: RawSockaddr) -> Datagram:
    var sender: SocketAddr
    try:
        sender = SocketAddr.from_raw(raw)
    except:
        sender = SocketAddr(IpAddr(Ipv4Addr(0, 0, 0, 0)), 0)
    return Datagram(min(r, buf_len), r, sender)


def _recv(
    sock: Socket,
    buf: MutSpan[UInt8, _],
    flags: Int,
    deadline: Deadline,
    op: StaticString,
) raises IoError -> Datagram:
    """One recvfrom(MSG_TRUNC | `flags`) that waits up to `deadline`."""
    var w = _Waiter(POLLIN, Errno.ENOTCONN)
    while True:
        var raw = RawSockaddr()
        var r = sys.recvfrom(sock, buf, flags | MSG_TRUNC, raw.storage, raw.len)
        if r >= 0:
            w.progressed()
            return _datagram(r, len(buf), raw)
        var e = Errno(err_of(r))
        if e == Errno.EAGAIN:
            w.wait(sock, deadline, op)
        elif e != Errno.EINTR:
            raise IoError.from_errno(op, e)


def _try_recv(
    sock: Socket, buf: MutSpan[UInt8, _], flags: Int, op: StaticString
) raises IoError -> Optional[Datagram]:
    """One recvfrom(MSG_TRUNC | `flags`) that never waits: None on
    EAGAIN."""
    while True:
        var raw = RawSockaddr()
        var r = sys.recvfrom(sock, buf, flags | MSG_TRUNC, raw.storage, raw.len)
        if r >= 0:
            return _datagram(r, len(buf), raw)
        var e = Errno(err_of(r))
        if e == Errno.EAGAIN:
            return None
        if e != Errno.EINTR:
            raise IoError.from_errno(op, e)


@inline(.always)
def _sendto(sock: Socket, buf: Span[UInt8, _], dest: Optional[SocketAddr]) -> Int:
    if dest:
        var raw = dest.value().to_raw()
        return sys.sendto(sock, buf, MSG_NOSIGNAL, raw.storage, raw.socklen())
    return sys.send(sock, buf, MSG_NOSIGNAL)


def _send(
    sock: Socket,
    buf: Span[UInt8, _],
    dest: Optional[SocketAddr],
    deadline: Deadline,
    op: StaticString,
) raises IoError -> Int:
    """One datagram (to `dest`, or the connected peer) that waits up to
    `deadline` for buffer space."""
    var w = _Waiter(POLLOUT, Errno.EPIPE)
    while True:
        var r = _sendto(sock, buf, dest)
        if r >= 0:
            w.progressed()
            return r
        var e = Errno(err_of(r))
        if e == Errno.EAGAIN:
            w.wait(sock, deadline, op)
        elif e != Errno.EINTR:
            raise IoError.from_errno(op, e)


def _try_send(
    sock: Socket, buf: Span[UInt8, _], dest: Optional[SocketAddr], op: StaticString
) raises IoError -> Optional[Int]:
    while True:
        var r = _sendto(sock, buf, dest)
        if r >= 0:
            return r
        var e = Errno(err_of(r))
        if e == Errno.EAGAIN:
            return None
        if e != Errno.EINTR:
            raise IoError.from_errno(op, e)


# ---- UdpSocket ---------------------------------------------------------------


struct UdpSocket(AsFd, Movable, Writable):
    """A UDP socket with blocking and nonblocking datagram I/O (see the
    module docs). Methods take `self` immutably except the deadline
    setters. Not copyable; `try_clone` makes a second handle."""

    var _sock: Socket
    var _rd: Deadline
    var _wr: Deadline

    @inline(.always)
    def __init__(out self, *, var nonblocking_socket: Socket):
        """Wrap a UDP socket that is already O_NONBLOCK (no syscall). Use
        `from_socket` for anything else."""
        self._sock = nonblocking_socket^
        self._rd = Deadline.none()
        self._wr = Deadline.none()

    # ---- creation ------------------------------------------------------------

    @staticmethod
    def bind(addr: SocketAddr) raises IoError -> UdpSocket:
        """A socket bound to `addr`; port 0 picks a free port (read it back
        with `local_addr`). `0.0.0.0` / `[::]` receive on every address. An
        IPv6 socket keeps the system's IPV6_V6ONLY default; build it with
        L1 and `from_socket` to choose."""
        var sock = Socket.new(
            Domain.for_address(addr), SockType.DGRAM, nonblocking=True
        )
        sock.bind(addr)
        return UdpSocket(nonblocking_socket=sock^)

    @staticmethod
    def bind_reuseport(addr: SocketAddr) raises IoError -> UdpSocket:
        """`bind` with SO_REUSEPORT: several sockets (one per process or
        thread, same user) share the address, and the kernel spreads
        datagrams across them by a hash of the sender's address and
        port."""
        var sock = Socket.new(
            Domain.for_address(addr), SockType.DGRAM, nonblocking=True
        )
        sock.set_reuse_port(True)
        sock.bind(addr)
        return UdpSocket(nonblocking_socket=sock^)

    @staticmethod
    def from_socket(var sock: Socket) raises IoError -> UdpSocket:
        """Adopt an AF_INET/AF_INET6 SOCK_DGRAM socket (socket activation, a
        tuned L1 socket), else `InvalidInput` (op "UdpSocket.from_socket";
        the socket is closed). Sets FD_CLOEXEC and O_NONBLOCK."""
        comptime op = "UdpSocket.from_socket"
        var ok: Bool
        try:
            var d = sock.domain()
            ok = (d == Domain.IPV4 or d == Domain.IPV6) and (
                sock.socket_type() == SockType.DGRAM
            )
        except e:
            if e.errno == Errno.ENOTSOCK:
                raise IoError(ErrorKind.InvalidInput, e.errno, op)
            raise IoError(e.kind, e.errno, op)
        if not ok:
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        _set_cloexec(sock)
        sock.set_nonblocking(True)
        return UdpSocket(nonblocking_socket=sock^)

    def connect(self, addr: SocketAddr) raises IoError:
        """Fix the peer: `send` / `recv` then talk to `addr` only, datagrams
        from anyone else are dropped, and ICMP errors are reported. Sends
        no packet; it only fails for local reasons (no route,
        `NetworkUnreachable`). Calling it again changes the peer."""
        self._sock.connect(addr)

    @inline(.always)
    def into_socket(deinit self) -> Socket:
        """The L1 socket, still O_NONBLOCK."""
        return self._sock^

    @inline(.always)
    def socket(ref self) -> ref[self._sock] Socket:
        """The L1 socket, for options (`set_ttl`, `set_tos`,
        `set_recv_buffer_size`, ...). Keep it O_NONBLOCK."""
        return self._sock

    @inline(.always)
    def raw_fd(self) -> Int32:
        """The descriptor, still owned by `self` (see `OwnedFd.raw_fd`)."""
        return self._sock.raw_fd()

    def try_clone(self) raises IoError -> UdpSocket:
        """A second handle (F_DUPFD_CLOEXEC) to the same socket; it starts
        with a copy of this handle's deadlines. Two handles receiving share
        the queue: each datagram goes to one of them."""
        var s = UdpSocket(nonblocking_socket=self._sock.try_clone())
        s._rd = self._rd
        s._wr = self._wr
        return s^

    def close(deinit self) raises IoError:
        """Close and report errors (dropping the socket ignores them)."""
        self._sock^.close()

    # ---- deadlines -----------------------------------------------------------

    @inline(.always)
    def set_read_deadline(mut self, deadline: Deadline):
        """Bound every later blocking receive; `Deadline.none()` removes
        it."""
        self._rd = deadline

    @inline(.always)
    def set_write_deadline(mut self, deadline: Deadline):
        """Bound every later blocking send; `Deadline.none()` removes it."""
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

    # ---- blocking I/O --------------------------------------------------------

    def send_to(self, buf: Span[UInt8, _], addr: SocketAddr) raises IoError -> Int:
        """Send `buf` as one datagram to `addr`, waiting up to the write
        deadline for buffer space; returns `len(buf)`."""
        return _send(self._sock, buf, addr, self._wr, "send_to")

    def send(self, buf: Span[UInt8, _]) raises IoError -> Int:
        """Send `buf` as one datagram to the connected peer (`connect`
        first, else `InvalidInput`/EDESTADDRREQ)."""
        return _send(self._sock, buf, None, self._wr, "send")

    def recv_from(self, buf: MutSpan[UInt8, _]) raises IoError -> Datagram:
        """Wait (up to the read deadline) for one datagram and copy what
        fits into `buf`."""
        return _recv(self._sock, buf, 0, self._rd, "recv_from")

    def recv(self, buf: MutSpan[UInt8, _]) raises IoError -> Datagram:
        """`recv_from` for a connected socket (only its peer's datagrams
        arrive)."""
        return _recv(self._sock, buf, 0, self._rd, "recv")

    def peek_from(self, buf: MutSpan[UInt8, _]) raises IoError -> Datagram:
        """Like `recv_from`, but the datagram stays queued (MSG_PEEK). With
        an empty `buf` it reads the next datagram's size (`size`) without
        copying anything."""
        return _recv(self._sock, buf, MSG_PEEK, self._rd, "peek_from")

    # ---- nonblocking I/O -----------------------------------------------------

    def try_send_to(
        self, buf: Span[UInt8, _], addr: SocketAddr
    ) raises IoError -> Optional[Int]:
        """One datagram to `addr` without waiting: `len(buf)`, or None when
        the send buffer is full."""
        return _try_send(self._sock, buf, addr, "send_to")

    def try_send(self, buf: Span[UInt8, _]) raises IoError -> Optional[Int]:
        """`try_send_to` to the connected peer."""
        return _try_send(self._sock, buf, None, "send")

    def try_recv_from(
        self, buf: MutSpan[UInt8, _]
    ) raises IoError -> Optional[Datagram]:
        """One datagram without waiting, or None when none is queued."""
        return _try_recv(self._sock, buf, 0, "recv_from")

    def try_recv(self, buf: MutSpan[UInt8, _]) raises IoError -> Optional[Datagram]:
        """`try_recv_from` for a connected socket."""
        return _try_recv(self._sock, buf, 0, "recv")

    def try_peek_from(
        self, buf: MutSpan[UInt8, _]
    ) raises IoError -> Optional[Datagram]:
        """`peek_from` without waiting."""
        return _try_recv(self._sock, buf, MSG_PEEK, "peek_from")

    # ---- options and addresses -----------------------------------------------

    def set_broadcast(self, on: Bool) raises IoError:
        """Allow sends to broadcast addresses (SO_BROADCAST)."""
        self._sock.set_broadcast(on)

    def broadcast(self) raises IoError -> Bool:
        return self._sock.broadcast()

    def local_addr(self) raises IoError -> SocketAddr:
        return self._sock.local_addr()

    def peer_addr(self) raises IoError -> SocketAddr:
        """The connected peer (`NotConnected` if `connect` was not
        called)."""
        return self._sock.peer_addr()

    def write_to(self, mut writer: Some[Writer]):
        writer.write("UdpSocket(fd=", self._sock.raw_fd(), ")")
