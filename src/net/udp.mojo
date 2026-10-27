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

`shutdown_read()` wakes receivers: blocking receives then never wait (they
return what is queued or raise `NotConnected`).

Connected sockets (`connect`): the kernel fixes the destination, drops
datagrams from any other sender, and reports ICMP errors (`connect` also
discards what was queued before it). After a "port
unreachable" the next send or receive raises `ConnectionRefused`. An
unconnected socket sees no ICMP errors (unless IP_RECVERR / IPV6_RECVERR
was turned on through `socket()`: then they are queued for the error
queue, which this module does not read).

Servers on a wildcard address (`0.0.0.0`, `[::]`): a reply sent with
`send_to` leaves from the address the route back chooses, which on a host
with several addresses (secondary IPs, VIPs, IPv6 temporary addresses,
127.0.0.x) may not be the one the client sent to, and a connected client
drops it. `receive_destination()` makes `recv_from_to` report each
datagram's destination (`Arrival.local`), and `send_from` replies from it.
A reply can also fail for reasons the sender controls (a forged source,
port 0, a broadcast address): a server should drop that datagram, not
stop.

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
from linux.abi import (
    CMSG_DATA_OFFSET,
    Cmsghdr,
    In6Pktinfo,
    InPktinfo,
    Iovec,
    Mmsghdr,
    Msghdr,
    SockaddrStorage,
    cmsg_align,
    cmsg_len,
    cmsg_space,
    hton32,
    ntoh32,
)
from linux.consts import (
    IOV_MAX,
    IP_PKTINFO,
    IPPROTO_IP,
    IPPROTO_IPV6,
    IPV6_PKTINFO,
    IPV6_RECVPKTINFO,
    IPPROTO_UDP,
    IPPROTO_UDPLITE,
    MSG_DONTWAIT,
    MSG_NOSIGNAL,
    MSG_PEEK,
    MSG_TRUNC,
    POLLIN,
    POLLOUT,
    SHUT_RD,
)
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
    var w = _Waiter(POLLIN, Errno.ENOTCONN, rdhup_ends=True)
    while True:
        var raw = RawSockaddr()
        var r = sys.recvfrom(
            sock, buf, flags | MSG_TRUNC | MSG_DONTWAIT, raw.storage, raw.len
        )
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
        var r = sys.recvfrom(
            sock, buf, flags | MSG_TRUNC | MSG_DONTWAIT, raw.storage, raw.len
        )
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
        return sys.sendto(
            sock, buf, MSG_NOSIGNAL | MSG_DONTWAIT, raw.storage, raw.socklen()
        )
    return sys.send(sock, buf, MSG_NOSIGNAL | MSG_DONTWAIT)


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


# ---- destinations (PKTINFO) ---------------------------------------------------


@fieldwise_init
struct Arrival(Copyable, Movable, Writable):
    """What `recv_from_to` returns: the datagram, and the address it was
    sent to."""

    var datagram: Datagram
    var local: Optional[IpAddr]
    """The datagram's destination: the one of this host's addresses the
    sender chose (or a multicast or broadcast address), IPv4-mapped on an
    IPv6 socket as `Datagram.sender` is. None when the kernel reported
    none (`UdpSocket.receive_destination` was not turned on)."""
    var interface: UInt32
    """The index of the interface it came in on (0 if not reported)."""

    def write_to(self, mut writer: Some[Writer]):
        writer.write("Arrival(", self.datagram, ", local=")
        if self.local:
            writer.write(self.local.value())
        else:
            writer.write("None")
        writer.write(", interface=", self.interface, ")")


comptime _CONTROL_WORDS = 16
"""The control buffer for PKTINFO, in 8-byte words (cmsg data must be
8-aligned): 128 bytes, room for both IP_PKTINFO (32) and IPV6_PKTINFO
(40)."""


def _recv_to_once(
    sock: Socket, buf: MutSpan[UInt8, _]
) -> Tuple[Int, Optional[Arrival]]:
    """One recvmsg(MSG_TRUNC | MSG_DONTWAIT) with a control buffer: the
    raw result, and the arrival when it is not an error."""
    var raw = RawSockaddr()
    var control = Array[UInt64, _CONTROL_WORDS](fill=0)
    var iov = Iovec(Int(buf.unsafe_ptr()), UInt(len(buf)))
    var msg = Msghdr(
        Int(Pointer(to=raw.storage)),
        raw.len,
        Int(Pointer(to=iov)),
        1,
        Int(Pointer(to=control)),
        UInt(_CONTROL_WORDS * 8),
        0,
    )
    var r = sys.recvmsg(sock, msg, MSG_TRUNC | MSG_DONTWAIT)
    sys.keep_alive(iov)
    sys.keep_alive(raw)
    sys.keep_alive(control)
    if r < 0:
        return (r, Optional[Arrival](None))
    raw.len = msg.namelen
    var local: Optional[IpAddr] = None
    var interface = UInt32(0)
    # The control messages: only within what the kernel wrote, each
    # header's length checked before its data is read.
    var n = min(Int(msg.controllen), _CONTROL_WORDS * 8)
    var base = Pointer(to=control).unsafe_bitcast[UInt8]()
    var off = 0
    while off + CMSG_DATA_OFFSET <= n:
        var h = base.unsafe_offset(off).unsafe_bitcast[Cmsghdr]()[].copy()
        var clen = Int(h.len)
        if clen < CMSG_DATA_OFFSET or clen > n - off:
            break
        var data = base.unsafe_offset(off + CMSG_DATA_OFFSET)
        if (
            Int(h.level) == IPPROTO_IP
            and Int(h.type) == IP_PKTINFO
            and clen >= cmsg_len(size_of[InPktinfo]())
        ):
            var info = data.unsafe_bitcast[InPktinfo]()[].copy()
            local = IpAddr(Ipv4Addr(bits=ntoh32(info.addr)))
            interface = UInt32(info.ifindex)
        elif (
            Int(h.level) == IPPROTO_IPV6
            and Int(h.type) == IPV6_PKTINFO
            and clen >= cmsg_len(size_of[In6Pktinfo]())
        ):
            var info = data.unsafe_bitcast[In6Pktinfo]()[].copy()
            local = IpAddr(Ipv6Addr.from_octets(info.addr))
            interface = UInt32(info.ifindex)
        off += cmsg_align(clen)
    return (r, Optional(Arrival(_datagram(r, len(buf), raw), local, interface)))


def _recv_to(
    sock: Socket, buf: MutSpan[UInt8, _], deadline: Deadline, op: StaticString
) raises IoError -> Arrival:
    """`_recv_to_once` that waits up to `deadline`."""
    var w = _Waiter(POLLIN, Errno.ENOTCONN, rdhup_ends=True)
    while True:
        var t = _recv_to_once(sock, buf)
        if t[0] >= 0:
            w.progressed()
            return t[1].value().copy()
        var e = Errno(err_of(t[0]))
        if e == Errno.EAGAIN:
            w.wait(sock, deadline, op)
        elif e != Errno.EINTR:
            raise IoError.from_errno(op, e)


def _try_recv_to(
    sock: Socket, buf: MutSpan[UInt8, _], op: StaticString
) raises IoError -> Optional[Arrival]:
    while True:
        var t = _recv_to_once(sock, buf)
        if t[0] >= 0:
            return t[1].copy()
        var e = Errno(err_of(t[0]))
        if e == Errno.EAGAIN:
            return None
        if e != Errno.EINTR:
            raise IoError.from_errno(op, e)


def _send_from_once(
    sock: Socket,
    buf: Span[UInt8, _],
    dest: SocketAddr,
    local: IpAddr,
    interface: UInt32,
) -> Int:
    """One sendmsg(MSG_NOSIGNAL | MSG_DONTWAIT) to `dest` from `local`.
    An IPv6 `dest` (the form an IPv6 socket's senders have, IPv4 ones
    mapped) takes IPV6_PKTINFO, an IPv4 one IP_PKTINFO; -EINVAL when
    `local` is IPv6 and `dest` IPv4."""
    var control = Array[UInt64, _CONTROL_WORDS](fill=0)
    var base = Pointer(to=control).unsafe_bitcast[UInt8]()
    var clen: Int
    if dest.is_ipv6():
        base.unsafe_bitcast[Cmsghdr]()[] = Cmsghdr(
            UInt(cmsg_len(size_of[In6Pktinfo]())),
            Int32(IPPROTO_IPV6),
            Int32(IPV6_PKTINFO),
        )
        base.unsafe_offset(CMSG_DATA_OFFSET).unsafe_bitcast[In6Pktinfo]()[] = (
            In6Pktinfo(local.v6().octets(), Int32(interface))
        )
        clen = cmsg_space(size_of[In6Pktinfo]())
    else:
        var v4 = local.to_canonical().as_v4()
        if not v4:
            return -Int(Errno.EINVAL.value)
        base.unsafe_bitcast[Cmsghdr]()[] = Cmsghdr(
            UInt(cmsg_len(size_of[InPktinfo]())),
            Int32(IPPROTO_IP),
            Int32(IP_PKTINFO),
        )
        base.unsafe_offset(CMSG_DATA_OFFSET).unsafe_bitcast[InPktinfo]()[] = (
            InPktinfo(Int32(interface), hton32(v4.value().bits()), 0)
        )
        clen = cmsg_space(size_of[InPktinfo]())
    var raw = dest.to_raw()
    var iov = Iovec(Int(buf.unsafe_ptr()), UInt(len(buf)))
    var msg = Msghdr(
        Int(Pointer(to=raw.storage)),
        UInt32(raw.socklen()),
        Int(Pointer(to=iov)),
        1,
        Int(Pointer(to=control)),
        UInt(clen),
        0,
    )
    var r = sys.sendmsg(sock, msg, MSG_NOSIGNAL | MSG_DONTWAIT)
    sys.keep_alive(iov)
    sys.keep_alive(raw)
    sys.keep_alive(control)
    return r


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
    destination, or none for a connected socket); a send moves the pending
    ones, `sent()` counts the progress, also after an error, and `skip()`
    gives up on a datagram that keeps failing. `clear` empties it for
    reuse."""

    var _slot: Int
    var _data: List[UInt8]
    var _lens: List[Int]
    var _sizes: List[Int]
    var _names: List[SockaddrStorage]
    var _namelens: List[UInt32]
    var _iov: List[Iovec]
    var _hdrs: List[Mmsghdr]
    var _count: Int
    var _next: Int
    """Index of the next datagram to send."""
    var _sent: Int
    var _dirty: Int
    """Headers `[0, _dirty)` are not in receive form: the kernel wrote
    their name lengths (a receive), or a send pointed them at payloads.
    The rest still are, as `__init__` built them: their pointers never
    change (the lists are never resized, and moving the batch keeps their
    buffers), so a receive rebuilds only these."""

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
        self._next = 0
        self._sent = 0
        self._dirty = capacity

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
    def pending(self) -> Int:
        """How many pushed datagrams are still to send (after an error,
        the failing one comes first)."""
        return self._count - self._next

    def skip(mut self) raises IoError:
        """Give up on the next datagram to send (the one a send just failed
        on), so the next `send_batch` goes on with the rest. `InvalidInput`
        when nothing is pending."""
        if self._next >= self._count:
            raise IoError.of_kind("DatagramBatch.skip", ErrorKind.InvalidInput)
        self._next += 1

    @inline(.always)
    def clear(mut self):
        self._count = 0
        self._next = 0
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
        self._next = 0
        self._sent = 0
        for i in range(self._dirty):
            self._header(i, self._slot, UInt32(size_of[SockaddrStorage]()))
        self._dirty = 0
        var r = sys.recvmmsg(sock, Span(self._hdrs), MSG_TRUNC | MSG_DONTWAIT)
        if r <= 0:
            return r
        self._dirty = r
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
        for i in range(self._next, self._count):
            self._header(i, self._lens[i], self._namelens[i])
        self._dirty = max(self._dirty, self._count)
        return sys.sendmmsg(
            sock,
            Span(self._hdrs)[self._next : self._count],
            MSG_NOSIGNAL | MSG_DONTWAIT,
        )


def _discard_queued(sock: Socket):
    """Drop every datagram queued (MSG_TRUNC into one byte: each costs one
    call), until nothing is left or a pending error ends it."""
    var b = List[UInt8](length=1, fill=0)
    while True:
        var r = sys.recv(sock, Span(b), MSG_TRUNC | MSG_DONTWAIT)
        if r >= 0:
            continue
        if Errno(err_of(r)) != Errno.EINTR:
            return


comptime _UDP_GRO = 104
"""(linux/udp.h) Receive-side coalescing: several datagrams of one flow
come out of one receive, their segment size in a control message."""


def _gro_on(sock: Socket) raises IoError -> Bool:
    """Whether UDP_GRO is on (ENOPROTOOPT: a kernel without it, so off)."""
    try:
        return sock.get_option_int(IPPROTO_UDP, _UDP_GRO) != 0
    except e:
        if e.errno == Errno.ENOPROTOOPT:
            return False
        raise e


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
        with `local_addr`). `0.0.0.0` / `[::]` receive on every address; to
        answer from the address each datagram came to (a host with several
        addresses), turn on `receive_destination` and reply with
        `send_from`. An IPv6 socket keeps the system's IPV6_V6ONLY default;
        build it with L1 and `from_socket` to choose."""
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
        """Adopt an AF_INET/AF_INET6 SOCK_DGRAM UDP (or UDP-Lite) socket
        (socket activation, a tuned L1 socket), else `InvalidInput` (op
        "UdpSocket.from_socket"; the socket is closed). A socket with
        UDP_GRO on is refused too: the kernel then hands over several
        datagrams as one receive, with nothing in the return value to say
        so. Sets FD_CLOEXEC and O_NONBLOCK."""
        comptime op = "UdpSocket.from_socket"
        var ok: Bool
        try:
            var d = sock.domain()
            ok = (d == Domain.IPV4 or d == Domain.IPV6) and (
                sock.socket_type() == SockType.DGRAM
            )
            # Other datagram protocols (ICMP "ping" sockets, ...) ignore
            # MSG_TRUNC, which would make truncation silent.
            var proto = sock.protocol().value
            ok = ok and (proto == IPPROTO_UDP or proto == IPPROTO_UDPLITE)
            ok = ok and not _gro_on(sock)
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
        `NetworkUnreachable`). Calling it again changes the peer.

        Datagrams queued before the call are discarded: the kernel filters
        only what arrives after it, so on a socket bound first, anyone's
        datagram sent in between would otherwise come out of `recv` as if
        from the peer. (The source address of a datagram can be forged:
        "from the peer" means "claims to be".)"""
        self._sock.connect(addr)
        _discard_queued(self._sock)

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

    def receive_destination(self, on: Bool = True) raises IoError:
        """Have the kernel report each datagram's destination address,
        which `recv_from_to` returns (IP_PKTINFO on an IPv4 socket,
        IPV6_RECVPKTINFO on an IPv6 one, which reports IPv4 traffic as
        mapped addresses).

        A socket bound to a wildcard address on a host with several
        addresses needs it to answer correctly: a reply sent with
        `send_to` leaves from whichever address the route back picks,
        and a connected client drops a reply that is not from the address
        it sent to. `send_from(payload, a.datagram.sender, a.local.value())`
        replies from the right one."""
        if self._sock.domain() == Domain.IPV6:
            self._sock.set_option_int(IPPROTO_IPV6, IPV6_RECVPKTINFO, Int(on))
        else:
            self._sock.set_option_int(IPPROTO_IP, IP_PKTINFO, Int(on))

    def recv_from_to(self, buf: MutSpan[UInt8, _]) raises IoError -> Arrival:
        """`recv_from`, plus the address the datagram was sent to and the
        interface it came in on (`receive_destination` must be on, else
        `local` is None)."""
        return _recv_to(self._sock, buf, self._rd, "recv_from_to")

    def try_recv_from_to(
        self, buf: MutSpan[UInt8, _]
    ) raises IoError -> Optional[Arrival]:
        """`recv_from_to` without waiting: None when nothing is queued."""
        return _try_recv_to(self._sock, buf, "recv_from_to")

    def send_from(
        self,
        buf: Span[UInt8, _],
        dest: SocketAddr,
        local: IpAddr,
        interface: UInt32 = 0,
    ) raises IoError -> Int:
        """`send_to` with `local` as the source address (one of this
        host's unicast addresses; usually `Arrival.local`), through
        `interface` (0: by route). Waits up to the write deadline for
        buffer space. A `local` the host does not have raises
        (`AddrNotAvailable` or `InvalidInput`), and so does a multicast or
        broadcast one: answer a datagram sent to a group or a broadcast
        address with `send_to`."""
        var w = _Waiter(POLLOUT, Errno.EPIPE)
        while True:
            var r = _send_from_once(self._sock, buf, dest, local, interface)
            if r >= 0:
                w.progressed()
                return r
            var e = Errno(err_of(r))
            if e == Errno.EAGAIN:
                w.wait(self._sock, self._wr, "send_from")
            elif e != Errno.EINTR:
                raise IoError.from_errno("send_from", e)

    def try_send_from(
        self,
        buf: Span[UInt8, _],
        dest: SocketAddr,
        local: IpAddr,
        interface: UInt32 = 0,
    ) raises IoError -> Optional[Int]:
        """`send_from` without waiting: None when the send buffer is
        full."""
        while True:
            var r = _send_from_once(self._sock, buf, dest, local, interface)
            if r >= 0:
                return r
            var e = Errno(err_of(r))
            if e == Errno.EAGAIN:
                return None
            if e != Errno.EINTR:
                raise IoError.from_errno("send_from", e)

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
        """One datagram without waiting, or None when none is queued. After
        `shutdown_read` it answers None forever while epoll reports the
        socket readable with EPOLLRDHUP (`net.blocking`'s module docs)."""
        return _try_recv(self._sock, buf, 0, "recv_from")

    def try_recv(self, buf: MutSpan[UInt8, _]) raises IoError -> Optional[Datagram]:
        """`try_recv_from` for a connected socket."""
        return _try_recv(self._sock, buf, 0, "recv")

    def try_peek_from(
        self, buf: MutSpan[UInt8, _]
    ) raises IoError -> Optional[Datagram]:
        """`peek_from` without waiting."""
        return _try_recv(self._sock, buf, MSG_PEEK, "peek_from")

    def shutdown_read(self) raises IoError:
        """Stop blocking receives on this socket and every handle of it:
        once nothing is queued they raise `NotConnected` instead of waiting
        (datagrams that arrive later are still queued and readable). This
        is how one thread wakes another that is blocked in `recv_from` on a
        `try_clone` of the socket. Linux applies it on an unconnected socket
        too while reporting ENOTCONN, which is therefore not raised."""
        var r = sys.shutdown(self._sock, SHUT_RD)
        if r < 0:
            var e = Errno(err_of(r))
            if e != Errno.ENOTCONN:
                raise IoError.from_errno("shutdown", e)

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
        var w = _Waiter(POLLIN, Errno.ENOTCONN, rdhup_ends=True)
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
        """Send every pending datagram, in as few sendmmsg calls as the
        kernel allows, waiting (up to the write deadline) for buffer space;
        returns `batch.sent()`.

        A datagram that fails (EMSGSIZE, an unreachable or wrong-family
        destination, a broadcast without SO_BROADCAST) raises: `sent()`
        counts what went out, `pending()` what is left with the failing one
        first, and `skip()` drops it so that calling again sends the rest.
        An ICMP refusal on a connected socket is different: sendmmsg
        reports the datagrams it sent and drops that error, so it usually
        shows up on the next receive rather than here."""
        var w = _Waiter(POLLOUT, Errno.EPIPE)
        while batch._next < batch._count:
            var r = batch._send(self._sock)
            if r >= 0:
                batch._next += r
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
        again when writable while `batch.pending()` is not 0). Errors as for
        `send_batch`."""
        while batch._next < batch._count:
            var r = batch._send(self._sock)
            if r >= 0:
                batch._next += r
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
