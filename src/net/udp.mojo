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

Multicast: bind the group's port (usually on the wildcard address), then
`join_multicast_v4` / `join_multicast_v6`; senders choose the interface,
TTL / hops and loopback with the `set_multicast_*` calls. Linux delivers
to a wildcard-bound socket the datagrams of every group that any socket on
the host joined on that port (IP_MULTICAST_ALL, on by default): turn it
off with `socket().set_multicast_all_v4(False)` to hear only this
socket's groups.

Every socket is CLOEXEC and O_NONBLOCK, and sends pass MSG_NOSIGNAL. L1
options (TTL, TOS, buffer sizes, ...) are on `socket()`.
This module does not import `rt` (blocking layer).
"""

from std.memory import unsafe_memcpy
from std.sys import size_of

from linux import AsFd, Errno, ErrorKind, IoError, sys
from linux.abi import Iovec, Mmsghdr, Msghdr, SockaddrStorage
from linux.consts import IOV_MAX, MSG_NOSIGNAL, MSG_PEEK, MSG_TRUNC, POLLIN, POLLOUT
from linux.syscall import err_of
from linux.time import Deadline, Duration

from .addr import IpAddr, Ipv4Addr, Ipv6Addr, RawSockaddr, SocketAddr
from .blocking import _Waiter, _set_cloexec
from .dial import _literal
from .resolver import Resolver
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


# ---- batches -----------------------------------------------------------------


comptime MAX_BATCH = IOV_MAX
"""The most datagrams one batch call moves (the kernel's UIO_MAXIOV)."""


struct DatagramBatch(Movable, Sized):
    """Up to `capacity()` datagrams of up to `max_datagram()` bytes each,
    for `UdpSocket.recv_batch` / `send_batch` (recvmmsg / sendmmsg: one
    syscall for many datagrams). The batch owns every buffer, address and
    kernel header and reuses them, so a batch call allocates nothing.

    Receiving replaces the contents: datagram `i` is `payload(i)` (what was
    stored), `datagram(i)` (`len`, `size`, `sender`; `size > len` when it
    was truncated). Sending: `push` copies each datagram in (with its
    destination, or none for a connected socket); a send moves the ones not
    sent yet, and `sent()` counts the progress, also after an error.
    `clear` empties it for reuse."""

    var _slot: Int
    var _data: List[UInt8]
    var _lens: List[Int]
    var _sizes: List[Int]
    var _names: List[SockaddrStorage]
    var _namelens: List[UInt32]
    var _iov: List[Iovec]
    var _hdrs: List[Mmsghdr]
    var _count: Int
    var _sent: Int

    def __init__(out self, capacity: Int, max_datagram: Int = 2048) raises IoError:
        """`InvalidInput` unless `1 <= capacity <= MAX_BATCH` and
        `1 <= max_datagram <= 65535`. Allocates `capacity * max_datagram`
        bytes once."""
        if capacity < 1 or capacity > MAX_BATCH or max_datagram < 1 or max_datagram > 65535:
            raise IoError.of_kind("DatagramBatch.__init__", ErrorKind.InvalidInput)
        self._slot = max_datagram
        self._data = List[UInt8](length=capacity * max_datagram, fill=0)
        self._lens = List[Int](length=capacity, fill=0)
        self._sizes = List[Int](length=capacity, fill=0)
        self._names = List[SockaddrStorage](capacity=capacity)
        self._namelens = List[UInt32](length=capacity, fill=0)
        self._iov = List[Iovec](capacity=capacity)
        self._hdrs = List[Mmsghdr](capacity=capacity)
        for _ in range(capacity):
            self._names.append(SockaddrStorage.zeroed())
            self._iov.append(Iovec(0, 0))
            self._hdrs.append(Mmsghdr(Msghdr(0, 0, 0, 0, 0, 0, 0), 0))
        self._count = 0
        self._sent = 0

    @inline(.always)
    def __len__(self) -> Int:
        """Datagrams held (received, or pushed for sending)."""
        return self._count

    @inline(.always)
    def capacity(self) -> Int:
        return len(self._lens)

    @inline(.always)
    def max_datagram(self) -> Int:
        return self._slot

    @inline(.always)
    def sent(self) -> Int:
        """How many of the pushed datagrams have been sent."""
        return self._sent

    @inline(.always)
    def clear(mut self):
        self._count = 0
        self._sent = 0

    def payload(self, i: Int) raises IoError -> Span[UInt8, origin_of(self._data)]:
        """Datagram `i`'s bytes (as stored: at most `max_datagram()`).
        Valid until the next call that changes the batch."""
        self._check(i, "DatagramBatch.payload")
        return Span(self._data)[i * self._slot : i * self._slot + self._lens[i]]

    def datagram(self, i: Int) raises IoError -> Datagram:
        """Datagram `i`'s length, full size and sender (for a pushed one,
        its destination; unspecified for a connected socket's)."""
        self._check(i, "DatagramBatch.datagram")
        var raw = RawSockaddr(storage=self._names[i].copy(), len=self._namelens[i])
        return _datagram(self._sizes[i], self._slot, raw)

    def push(mut self, data: Span[UInt8, _], dest: SocketAddr) raises IoError:
        """Queue `data` as one datagram to `dest`. `InvalidInput` when the
        batch is full or `data` is longer than `max_datagram()`."""
        var raw = dest.to_raw()
        self._push(data, raw.storage.copy(), UInt32(raw.socklen()))

    def push(mut self, data: Span[UInt8, _]) raises IoError:
        """Queue `data` as one datagram to a connected socket's peer."""
        self._push(data, SockaddrStorage.zeroed(), 0)

    def _push(
        mut self, data: Span[UInt8, _], var name: SockaddrStorage, namelen: UInt32
    ) raises IoError:
        if self._count == self.capacity() or len(data) > self._slot:
            raise IoError.of_kind("DatagramBatch.push", ErrorKind.InvalidInput)
        var i = self._count
        if len(data) > 0:
            unsafe_memcpy(
                dest=self._data.unsafe_ptr().unsafe_offset(i * self._slot),
                src=data.unsafe_ptr(),
                count=len(data),
            )
        self._lens[i] = len(data)
        self._sizes[i] = len(data)
        self._names[i] = name^
        self._namelens[i] = namelen
        self._count += 1

    @inline(.always)
    def _check(self, i: Int, op: StaticString) raises IoError:
        if i < 0 or i >= self._count:
            raise IoError.of_kind(op, ErrorKind.InvalidInput)

    def _header(mut self, i: Int, length: Int, namelen: UInt32):
        """Point header `i` at slot `i` (`length` bytes) and name `i`."""
        var base = Int(self._data.unsafe_ptr()) + i * self._slot
        self._iov[i] = Iovec(base, UInt(length))
        var name = 0
        if namelen > 0:
            name = Int(self._names.unsafe_ptr().unsafe_offset(i))
        self._hdrs[i] = Mmsghdr(
            Msghdr(
                name,
                namelen,
                Int(self._iov.unsafe_ptr().unsafe_offset(i)),
                1,
                0,
                0,
                0,
            ),
            0,
        )

    def _recv(mut self, sock: Socket) -> Int:
        """One recvmmsg into every slot: datagrams received, or -errno."""
        self._count = 0
        self._sent = 0
        var cap = self.capacity()
        for i in range(cap):
            self._header(i, self._slot, UInt32(size_of[SockaddrStorage]()))
        var r = sys.recvmmsg(sock, Span(self._hdrs), MSG_TRUNC)
        if r <= 0:
            return r
        for i in range(r):
            var size = Int(self._hdrs[i].len)
            self._sizes[i] = size
            self._lens[i] = min(size, self._slot)
            self._namelens[i] = self._hdrs[i].hdr.namelen
        self._count = r
        return r

    def _send(mut self, sock: Socket) -> Int:
        """One sendmmsg of the datagrams not sent yet: how many it sent, or
        -errno."""
        for i in range(self._sent, self._count):
            self._header(i, self._lens[i], self._namelens[i])
        return sys.sendmmsg(
            sock, Span(self._hdrs)[self._sent : self._count], MSG_NOSIGNAL
        )


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

    @staticmethod
    def connect_host(
        host: StringSlice, port: UInt16, timeout: Duration
    ) raises IoError -> UdpSocket:
        """A socket connected to `host:port` (a name or an IP literal),
        resolving within `timeout`; see `connect_host_deadline`."""
        if timeout.is_zero():
            raise IoError.of_kind("connect", ErrorKind.InvalidInput)
        return UdpSocket.connect_host_deadline(
            host, port, Deadline.after(timeout)
        )

    @staticmethod
    def connect_host_deadline(
        host: StringSlice, port: UInt16, deadline: Deadline
    ) raises IoError -> UdpSocket:
        """`connect_host_deadline` with the system configuration (read only
        when `host` is not an IP literal)."""
        var literal = _literal(host, port)
        if literal:
            return UdpSocket._connected_to(literal.value())
        return UdpSocket.connect_host_deadline(
            host, port, deadline, Resolver.system()
        )

    @staticmethod
    def connect_host_deadline(
        host: StringSlice, port: UInt16, deadline: Deadline, resolver: Resolver
    ) raises IoError -> UdpSocket:
        """A socket connected to `host:port`: the name is resolved with
        `resolver` by `deadline`, and the first address in RFC 6724 order
        (usable ones first) is used, from an ephemeral local port of its
        family. UDP has no handshake to race, so unlike
        `TcpStream.connect_host` there is no Happy Eyeballs: to fail over,
        a caller tries the next address of `Resolver.lookup_ip` itself.
        `localhost` gives ::1 first (RFC 6724 ranks it highest), so a server
        that listens on 127.0.0.1 only shows up as `ConnectionRefused` on
        the first receive."""
        var literal = _literal(host, port)
        if literal:
            return UdpSocket._connected_to(literal.value())
        var ips = resolver.lookup_ip(host, deadline)
        return UdpSocket._connected_to(SocketAddr(ips[0], port))

    @staticmethod
    def _connected_to(addr: SocketAddr) raises IoError -> UdpSocket:
        var sock = Socket.new(
            Domain.for_address(addr), SockType.DGRAM, nonblocking=True
        )
        sock.connect(addr)
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

    # ---- batches -----------------------------------------------------------

    def recv_batch(self, mut batch: DatagramBatch) raises IoError -> Int:
        """Wait (up to the read deadline) for a datagram, then take it and
        every other queued one, up to `batch.capacity()`, in one recvmmsg.
        Returns how many (at least 1); they replace the batch's contents."""
        var w = _Waiter(POLLIN, Errno.ENOTCONN)
        while True:
            var r = batch._recv(self._sock)
            if r >= 0:
                w.progressed()
                return r
            var e = Errno(err_of(r))
            if e == Errno.EAGAIN:
                w.wait(self._sock, self._rd, "recv_batch")
            elif e != Errno.EINTR:
                raise IoError.from_errno("recv_batch", e)

    def try_recv_batch(self, mut batch: DatagramBatch) raises IoError -> Int:
        """`recv_batch` without waiting: 0 (and an empty batch) when nothing
        is queued."""
        while True:
            var r = batch._recv(self._sock)
            if r >= 0:
                return r
            var e = Errno(err_of(r))
            if e == Errno.EAGAIN:
                return 0
            if e != Errno.EINTR:
                raise IoError.from_errno("recv_batch", e)

    def send_batch(self, mut batch: DatagramBatch) raises IoError -> Int:
        """Send every pushed datagram not sent yet, in as few sendmmsg calls
        as the kernel allows, waiting (up to the write deadline) for buffer
        space; returns `len(batch)`. A datagram that fails (EMSGSIZE, a
        refusal on a connected socket) raises; `batch.sent()` says how many
        went out before it."""
        var w = _Waiter(POLLOUT, Errno.EPIPE)
        while batch._sent < batch._count:
            var r = batch._send(self._sock)
            if r >= 0:
                batch._sent += r
                w.progressed()
                continue
            var e = Errno(err_of(r))
            if e == Errno.EAGAIN:
                w.wait(self._sock, self._wr, "send_batch")
            elif e != Errno.EINTR:
                raise IoError.from_errno("send_batch", e)
        return batch._sent

    def try_send_batch(self, mut batch: DatagramBatch) raises IoError -> Int:
        """Send what fits without waiting; returns `batch.sent()` (call
        again when writable until it equals `len(batch)`)."""
        while batch._sent < batch._count:
            var r = batch._send(self._sock)
            if r >= 0:
                batch._sent += r
                continue
            var e = Errno(err_of(r))
            if e == Errno.EAGAIN:
                break
            if e != Errno.EINTR:
                raise IoError.from_errno("send_batch", e)
        return batch._sent

    # ---- multicast ---------------------------------------------------------

    def join_multicast_v4(
        self, group: Ipv4Addr, interface: Ipv4Addr = Ipv4Addr(0, 0, 0, 0)
    ) raises IoError:
        """Receive `group`'s datagrams on the interface with address
        `interface` (0.0.0.0: chosen by route). Bind the group's port
        first; see `Socket.join_multicast_v4` and `set_multicast_all_v4`."""
        self._sock.join_multicast_v4(group, interface)

    def leave_multicast_v4(
        self, group: Ipv4Addr, interface: Ipv4Addr = Ipv4Addr(0, 0, 0, 0)
    ) raises IoError:
        self._sock.leave_multicast_v4(group, interface)

    def join_multicast_v6(self, group: Ipv6Addr, interface: UInt32 = 0) raises IoError:
        """Receive `group`'s datagrams on the interface with index
        `interface` (`net.addr.if_nametoindex`)."""
        self._sock.join_multicast_v6(group, interface)

    def leave_multicast_v6(self, group: Ipv6Addr, interface: UInt32 = 0) raises IoError:
        self._sock.leave_multicast_v6(group, interface)

    def set_multicast_ttl_v4(self, ttl: Int) raises IoError:
        """How many hops IPv4 multicast sent from here may travel (default
        1: the local network)."""
        self._sock.set_multicast_ttl_v4(ttl)

    def set_multicast_loop_v4(self, on: Bool) raises IoError:
        """Whether this host's own listeners get the IPv4 multicast sent
        from here (default on)."""
        self._sock.set_multicast_loop_v4(on)

    def set_multicast_if_v4(self, interface: Ipv4Addr) raises IoError:
        """Send IPv4 multicast from the interface with this address."""
        self._sock.set_multicast_if_v4(interface)

    def set_multicast_hops_v6(self, hops: Int) raises IoError:
        self._sock.set_multicast_hops_v6(hops)

    def set_multicast_loop_v6(self, on: Bool) raises IoError:
        self._sock.set_multicast_loop_v6(on)

    def set_multicast_if_v6(self, interface: UInt32) raises IoError:
        """Send IPv6 multicast from the interface with this index."""
        self._sock.set_multicast_if_v6(interface)

    def local_addr(self) raises IoError -> SocketAddr:
        return self._sock.local_addr()

    def peer_addr(self) raises IoError -> SocketAddr:
        """The connected peer (`NotConnected` if `connect` was not
        called)."""
        return self._sock.peer_addr()

    def write_to(self, mut writer: Some[Writer]):
        writer.write("UdpSocket(fd=", self._sock.raw_fd(), ")")
