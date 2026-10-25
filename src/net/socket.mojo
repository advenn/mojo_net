"""L1 sockets: a socket2-style `Socket` with typed setters/getters for the
commonly needed options, applying no policy.

Coverage: the typed methods cover the SOL_SOCKET basics, TCP tuning and
keepalive, and the IP/IPv6 TOS/TTL/V6ONLY options. Everything else
(SO_BROADCAST, multicast membership, IP_FREEBIND, IP_BIND_ADDRESS_NO_PORT,
SO_PASSCRED, ...) is reachable only through the raw escape hatches
`set_option_int`/`get_option_int` and `set_option_bytes`/`get_option_bytes`,
which check nothing beyond the C int range and name failures plain
"setsockopt"/"getsockopt"; some of those constants are not in `linux.consts`
yet.

Time-valued options take `linux.time.Duration` and round it up to the unit
the kernel stores (seconds for SO_LINGER, TCP_DEFER_ACCEPT and keepalive
timing, milliseconds for TCP_USER_TIMEOUT), so a bare number can never be
read in the wrong unit.

Each method is one syscall (a few typed setters validate first, or issue one
call per kernel option) and reports the kernel's answer as is:
- EINTR raises kind `Interrupted` and EAGAIN raises `WouldBlock`. L1 never
  retries and never waits; the blocking streams (L2) add try -> classify ->
  ppoll -> retry with deadlines.
- Every descriptor is created with CLOEXEC (`socket`/`socketpair` with
  SOCK_CLOEXEC, `accept4`), so a fork+exec elsewhere cannot leak it.
- Every send passes MSG_NOSIGNAL, so writing to a peer that went away raises
  `BrokenPipe`/`ConnectionReset` instead of SIGPIPE killing the process.

Lifetimes: methods hand `self._fd` (the owner) and `Span`s to the
`linux.sys` wrappers, never raw numbers, and `keep_alive` whatever only
reached the kernel as an address (iovec arrays, `Msghdr`).

The module does not import `rt` (blocking layer).
"""

from std.sys import size_of

from linux import AsFd, Errno, ErrorKind, IoError, OwnedFd, check
from linux import sys
from linux.abi import (
    IpMreqn,
    Ipv6Mreq,
    Iovec,
    Linger,
    Msghdr,
    Ucred,
    hton32,
    ntoh32,
)
from linux.time import NANOS_PER_SEC, Duration
from linux.consts import (
    IP_ADD_MEMBERSHIP,
    IP_DROP_MEMBERSHIP,
    IP_MULTICAST_ALL,
    IP_MULTICAST_IF,
    IP_MULTICAST_LOOP,
    IP_MULTICAST_TTL,
    IPV6_ADD_MEMBERSHIP,
    IPV6_DROP_MEMBERSHIP,
    IPV6_MULTICAST_ALL,
    IPV6_MULTICAST_HOPS,
    IPV6_MULTICAST_IF,
    IPV6_MULTICAST_LOOP,
    IPV6_UNICAST_HOPS,
    AF_INET,
    AF_INET6,
    AF_UNIX,
    IF_NAMESIZE,
    IOV_MAX,
    IP_TOS,
    IP_TTL,
    IPPROTO_IP,
    IPPROTO_IPV6,
    IPPROTO_TCP,
    IPPROTO_UDP,
    IPV6_TCLASS,
    IPV6_V6ONLY,
    MSG_NOSIGNAL,
    MSG_PEEK,
    SHUT_RD,
    SHUT_RDWR,
    SHUT_WR,
    SO_ACCEPTCONN,
    SO_BINDTODEVICE,
    SO_BROADCAST,
    SO_DOMAIN,
    SO_ERROR,
    SO_INCOMING_CPU,
    SO_KEEPALIVE,
    SO_LINGER,
    SO_MARK,
    SO_PEERCRED,
    SO_PROTOCOL,
    SO_RCVBUF,
    SO_RCVLOWAT,
    SO_REUSEADDR,
    SO_REUSEPORT,
    SO_SNDBUF,
    SO_TYPE,
    SOCK_CLOEXEC,
    SOCK_DGRAM,
    SOCK_NONBLOCK,
    SOCK_RAW,
    SOCK_SEQPACKET,
    SOCK_STREAM,
    SOL_SOCKET,
    TCP_CONGESTION,
    TCP_CORK,
    TCP_DEFER_ACCEPT,
    TCP_FASTOPEN,
    TCP_INFO,
    TCP_KEEPCNT,
    TCP_KEEPIDLE,
    TCP_KEEPINTVL,
    TCP_MAXSEG,
    TCP_NODELAY,
    TCP_NOTSENT_LOWAT,
    TCP_QUICKACK,
    TCP_SYNCNT,
    TCP_USER_TIMEOUT,
    TCPI_BITS_DELIVERY_RATE_APP_LIMITED,
    TCPI_BITS_FASTOPEN_CLIENT_FAIL,
    TCPI_BITS_RCV_WSCALE,
    TCPI_BITS_SND_WSCALE,
    TCPI_OFF_ADVMSS,
    TCPI_OFF_ATO,
    TCPI_OFF_BACKOFF,
    TCPI_OFF_BUSY_TIME,
    TCPI_OFF_BYTES_ACKED,
    TCPI_OFF_BYTES_RECEIVED,
    TCPI_OFF_BYTES_RETRANS,
    TCPI_OFF_BYTES_SENT,
    TCPI_OFF_CA_STATE,
    TCPI_OFF_DATA_SEGS_IN,
    TCPI_OFF_DATA_SEGS_OUT,
    TCPI_OFF_DELIVERED,
    TCPI_OFF_DELIVERED_CE,
    TCPI_OFF_DELIVERY_RATE,
    TCPI_OFF_DELIVERY_RATE_APP_LIMITED,
    TCPI_OFF_DSACK_DUPS,
    TCPI_OFF_FACKETS,
    TCPI_OFF_FASTOPEN_CLIENT_FAIL,
    TCPI_OFF_LAST_ACK_RECV,
    TCPI_OFF_LAST_ACK_SENT,
    TCPI_OFF_LAST_DATA_RECV,
    TCPI_OFF_LAST_DATA_SENT,
    TCPI_OFF_LOST,
    TCPI_OFF_MAX_PACING_RATE,
    TCPI_OFF_MIN_RTT,
    TCPI_OFF_NOTSENT_BYTES,
    TCPI_OFF_OPTIONS,
    TCPI_OFF_PACING_RATE,
    TCPI_OFF_PMTU,
    TCPI_OFF_PROBES,
    TCPI_OFF_RCV_MSS,
    TCPI_OFF_RCV_OOOPACK,
    TCPI_OFF_RCV_RTT,
    TCPI_OFF_RCV_SPACE,
    TCPI_OFF_RCV_SSTHRESH,
    TCPI_OFF_RCV_WSCALE,
    TCPI_OFF_REORD_SEEN,
    TCPI_OFF_REORDERING,
    TCPI_OFF_RETRANS,
    TCPI_OFF_RETRANSMITS,
    TCPI_OFF_RTO,
    TCPI_OFF_RTT,
    TCPI_OFF_RTTVAR,
    TCPI_OFF_RWND_LIMITED,
    TCPI_OFF_SACKED,
    TCPI_OFF_SEGS_IN,
    TCPI_OFF_SEGS_OUT,
    TCPI_OFF_SND_CWND,
    TCPI_OFF_SND_MSS,
    TCPI_OFF_SND_SSTHRESH,
    TCPI_OFF_SND_WND,
    TCPI_OFF_SND_WSCALE,
    TCPI_OFF_SNDBUF_LIMITED,
    TCPI_OFF_STATE,
    TCPI_OFF_TOTAL_RETRANS,
    TCPI_OFF_UNACKED,
    TCPI_SHIFT_DELIVERY_RATE_APP_LIMITED,
    TCPI_SHIFT_FASTOPEN_CLIENT_FAIL,
    TCPI_SHIFT_RCV_WSCALE,
    TCPI_SHIFT_SND_WSCALE,
)
from linux.nr import SYS_getsockopt, SYS_setsockopt
from linux.syscall import syscall5

from .addr import Ipv4Addr, Ipv6Addr, RawSockaddr, SocketAddr, UnixAddr

# Kernel limits (include/net/tcp.h). Checked up front so `set_tcp_keepalive`
# never leaves a socket half-configured when the second or third option
# would be rejected.
comptime MAX_TCP_KEEPIDLE = 32767
"""Seconds."""
comptime MAX_TCP_KEEPINTVL = 32767
"""Seconds."""
comptime MAX_TCP_KEEPCNT = 127

comptime TCP_CA_NAME_MAX = 16
"""Congestion-control name buffer, NUL included (include/net/tcp.h): the
kernel silently truncates longer names, so `set_tcp_congestion` rejects
them."""

comptime TCP_INFO_CAPACITY = 512
"""Bytes `tcp_info()` asks for: more than any kernel's `struct tcp_info`
today (232 on 5.15, 248 on 6.12), so newer fields stay readable via
`TcpInfo.raw()`."""

# Vectored calls up to this many buffers build their iovec array on the
# stack; larger ones (up to IOV_MAX) allocate.
comptime _IOV_STACK = 16


# ---- small typed values ------------------------------------------------------


@fieldwise_init
struct Domain(Equatable, TrivialRegisterPassable, Writable):
    """Address family (`AF_*`) for `Socket.new`."""

    var value: Int

    comptime IPV4 = Domain(AF_INET)
    comptime IPV6 = Domain(AF_INET6)
    comptime UNIX = Domain(AF_UNIX)

    @staticmethod
    @inline(.always)
    def for_address(addr: SocketAddr) -> Domain:
        """IPV4 or IPV6, matching `addr`."""
        return Domain(addr.family())

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self.value == other.value

    def write_to(self, mut writer: Some[Writer]):
        if self.value == AF_INET:
            writer.write("IPV4")
        elif self.value == AF_INET6:
            writer.write("IPV6")
        elif self.value == AF_UNIX:
            writer.write("UNIX")
        else:
            writer.write("Domain(", self.value, ")")


@fieldwise_init
struct SockType(Equatable, TrivialRegisterPassable, Writable):
    """Socket type (`SOCK_*`, without creation flags: CLOEXEC is always
    added and NONBLOCK is a separate argument)."""

    var value: Int

    comptime STREAM = SockType(SOCK_STREAM)
    comptime DGRAM = SockType(SOCK_DGRAM)
    comptime SEQPACKET = SockType(SOCK_SEQPACKET)
    comptime RAW = SockType(SOCK_RAW)

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self.value == other.value

    def write_to(self, mut writer: Some[Writer]):
        if self.value == SOCK_STREAM:
            writer.write("STREAM")
        elif self.value == SOCK_DGRAM:
            writer.write("DGRAM")
        elif self.value == SOCK_SEQPACKET:
            writer.write("SEQPACKET")
        elif self.value == SOCK_RAW:
            writer.write("RAW")
        else:
            writer.write("SockType(", self.value, ")")


@fieldwise_init
struct Protocol(Equatable, TrivialRegisterPassable, Writable):
    """Protocol number (`IPPROTO_*`); `DEFAULT` (0) lets the kernel pick the
    family's default for the type (TCP for IP streams, UDP for IP
    datagrams)."""

    var value: Int

    comptime DEFAULT = Protocol(0)
    comptime TCP = Protocol(IPPROTO_TCP)
    comptime UDP = Protocol(IPPROTO_UDP)

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self.value == other.value

    def write_to(self, mut writer: Some[Writer]):
        if self.value == IPPROTO_TCP:
            writer.write("TCP")
        elif self.value == IPPROTO_UDP:
            writer.write("UDP")
        else:
            writer.write("Protocol(", self.value, ")")


@fieldwise_init
struct Shutdown(Equatable, TrivialRegisterPassable):
    """Which half of a connection `shutdown` closes."""

    var value: Int

    comptime READ = Shutdown(SHUT_RD)
    """Stops reading: once already-queued data is consumed, `recv` returns 0.
    Linux TCP does not tell the peer and keeps accepting (and queueing) data
    it sends; nothing is reset. To stop a peer, close or use `BOTH`."""
    comptime WRITE = Shutdown(SHUT_WR)
    """Sends FIN after queued data: the peer's `recv` returns 0 (EOF)."""
    comptime BOTH = Shutdown(SHUT_RDWR)

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self.value == other.value


@fieldwise_init
struct TcpKeepalive(Equatable, TrivialRegisterPassable, Writable):
    """TCP keepalive timing. Only takes effect while SO_KEEPALIVE is on
    (`set_keepalive(True)`).

    The kernel stores whole seconds: `set_tcp_keepalive` rounds `idle` and
    `interval` up (so 1500 ms becomes 2 s and `tcp_keepalive()` reads back
    2 s), and a time that rounds to 0 s or beyond 32767 s raises
    `InvalidInput`."""

    var idle: Duration
    """Idle time before the first probe (TCP_KEEPIDLE, 1..32767 s)."""
    var interval: Duration
    """Time between unanswered probes (TCP_KEEPINTVL, 1..32767 s)."""
    var count: Int
    """Unanswered probes before the connection is reset (TCP_KEEPCNT,
    1..127)."""

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return (
            self.idle == other.idle
            and self.interval == other.interval
            and self.count == other.count
        )

    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            "TcpKeepalive(idle=",
            self.idle,
            ", interval=",
            self.interval,
            ", count=",
            self.count,
            ")",
        )


# ---- results that hold a socket ----------------------------------------------


@fieldwise_init
struct Accepted[A: Copyable & Deinitable](Movable):
    """An accepted connection and its peer address.

    Mojo cannot move one field out of a value (or a move-only element out of
    a tuple), so use the fields in place or consume the result:
    `var peer = acc.addr; var conn = acc^.into_socket()`."""

    var socket: Socket
    var addr: Self.A

    @inline(.always)
    def into_socket(deinit self) -> Socket:
        return self.socket^


struct SocketPair(Movable):
    """Both ends of `Socket.pair`. Each end is an `Optional` so both can be
    moved to separate owners (`var a = p.first.take()`; Mojo cannot move a
    plain field out of a value); `p.first.value()` borrows in place."""

    var first: Optional[Socket]
    var second: Optional[Socket]

    @inline(.always)
    def __init__(out self, var first: Socket, var second: Socket):
        self.first = first^
        self.second = second^


# ---- tcp_info ----------------------------------------------------------------


struct TcpInfo(Copyable, Movable, Writable):
    """`struct tcp_info` (getsockopt TCP_INFO) as raw bytes plus accessors at
    offsets generated from <linux/tcp.h> (`linux.consts.TCPI_OFF_*`).

    The kernel copies `min(asked, its sizeof)` bytes, so the struct grows
    with kernel versions; `size()` says how many bytes arrived and accessors
    for fields beyond it return 0. Every field here exists since Linux 5.5.
    Times: `rto`, `ato`, `rtt`, `rttvar`, `min_rtt`, `rcv_rtt`, `busy_time`,
    `rwnd_limited`, `sndbuf_limited` are microseconds; `last_*` are
    milliseconds ago. Rates are bytes per second. Sizes: `snd_cwnd` and
    `snd_ssthresh` are in segments, `*_mss`, `pmtu`, `rcv_space`,
    `notsent_bytes`, `snd_wnd` in bytes."""

    var _buf: Array[UInt8, TCP_INFO_CAPACITY]
    var _len: Int

    def __init__(out self):
        self._buf = Array[UInt8, TCP_INFO_CAPACITY](fill=0)
        self._len = 0

    @inline(.always)
    def size(self) -> Int:
        """Bytes of `struct tcp_info` the kernel filled."""
        return self._len

    def raw(ref self) -> Span[UInt8, origin_of(self._buf)]:
        """The bytes the kernel filled, for fields without an accessor."""
        return Span(self._buf)[0 : self._len]

    @inline(.always)
    def _u8(self, off: Int) -> UInt8:
        return self._buf[off] if off < self._len else 0

    @inline(.always)
    def _bits(self, off: Int, shift: Int, bits: Int) -> UInt8:
        return (self._u8(off) >> UInt8(shift)) & UInt8((1 << bits) - 1)

    @inline(.always)
    def _u32(self, off: Int) -> UInt32:
        """Host order (little endian on x86_64 and aarch64)."""
        if off + 4 > self._len:
            return 0
        var v: UInt32 = 0
        for i in range(4):
            v |= UInt32(self._buf[off + i]) << UInt32(8 * i)
        return v

    @inline(.always)
    def _u64(self, off: Int) -> UInt64:
        if off + 8 > self._len:
            return 0
        var v: UInt64 = 0
        for i in range(8):
            v |= UInt64(self._buf[off + i]) << UInt64(8 * i)
        return v

    def state(self) -> UInt8:
        """`linux.consts.TCP_ESTABLISHED`, `TCP_LISTEN`, ..."""
        return self._u8(TCPI_OFF_STATE)

    def ca_state(self) -> UInt8:
        """`linux.consts.TCP_CA_Open`, ..."""
        return self._u8(TCPI_OFF_CA_STATE)

    def retransmits(self) -> UInt8:
        return self._u8(TCPI_OFF_RETRANSMITS)

    def probes(self) -> UInt8:
        return self._u8(TCPI_OFF_PROBES)

    def backoff(self) -> UInt8:
        return self._u8(TCPI_OFF_BACKOFF)

    def options(self) -> UInt8:
        """TCPI_OPT_* bits (TIMESTAMPS=1, SACK=2, WSCALE=4, ECN=8, ...)."""
        return self._u8(TCPI_OFF_OPTIONS)

    def snd_wscale(self) -> UInt8:
        return self._bits(
            TCPI_OFF_SND_WSCALE, TCPI_SHIFT_SND_WSCALE, TCPI_BITS_SND_WSCALE
        )

    def rcv_wscale(self) -> UInt8:
        return self._bits(
            TCPI_OFF_RCV_WSCALE, TCPI_SHIFT_RCV_WSCALE, TCPI_BITS_RCV_WSCALE
        )

    def delivery_rate_app_limited(self) -> Bool:
        return (
            self._bits(
                TCPI_OFF_DELIVERY_RATE_APP_LIMITED,
                TCPI_SHIFT_DELIVERY_RATE_APP_LIMITED,
                TCPI_BITS_DELIVERY_RATE_APP_LIMITED,
            )
            != 0
        )

    def fastopen_client_fail(self) -> UInt8:
        return self._bits(
            TCPI_OFF_FASTOPEN_CLIENT_FAIL,
            TCPI_SHIFT_FASTOPEN_CLIENT_FAIL,
            TCPI_BITS_FASTOPEN_CLIENT_FAIL,
        )

    def rto(self) -> UInt32:
        return self._u32(TCPI_OFF_RTO)

    def ato(self) -> UInt32:
        return self._u32(TCPI_OFF_ATO)

    def snd_mss(self) -> UInt32:
        return self._u32(TCPI_OFF_SND_MSS)

    def rcv_mss(self) -> UInt32:
        return self._u32(TCPI_OFF_RCV_MSS)

    def unacked(self) -> UInt32:
        return self._u32(TCPI_OFF_UNACKED)

    def sacked(self) -> UInt32:
        return self._u32(TCPI_OFF_SACKED)

    def lost(self) -> UInt32:
        return self._u32(TCPI_OFF_LOST)

    def retrans(self) -> UInt32:
        return self._u32(TCPI_OFF_RETRANS)

    def fackets(self) -> UInt32:
        return self._u32(TCPI_OFF_FACKETS)

    def last_data_sent(self) -> UInt32:
        return self._u32(TCPI_OFF_LAST_DATA_SENT)

    def last_ack_sent(self) -> UInt32:
        """Always 0: the kernel does not track it."""
        return self._u32(TCPI_OFF_LAST_ACK_SENT)

    def last_data_recv(self) -> UInt32:
        return self._u32(TCPI_OFF_LAST_DATA_RECV)

    def last_ack_recv(self) -> UInt32:
        return self._u32(TCPI_OFF_LAST_ACK_RECV)

    def pmtu(self) -> UInt32:
        return self._u32(TCPI_OFF_PMTU)

    def rcv_ssthresh(self) -> UInt32:
        return self._u32(TCPI_OFF_RCV_SSTHRESH)

    def rtt(self) -> UInt32:
        """Smoothed RTT in microseconds."""
        return self._u32(TCPI_OFF_RTT)

    def rttvar(self) -> UInt32:
        return self._u32(TCPI_OFF_RTTVAR)

    def snd_ssthresh(self) -> UInt32:
        return self._u32(TCPI_OFF_SND_SSTHRESH)

    def snd_cwnd(self) -> UInt32:
        return self._u32(TCPI_OFF_SND_CWND)

    def advmss(self) -> UInt32:
        return self._u32(TCPI_OFF_ADVMSS)

    def reordering(self) -> UInt32:
        return self._u32(TCPI_OFF_REORDERING)

    def rcv_rtt(self) -> UInt32:
        return self._u32(TCPI_OFF_RCV_RTT)

    def rcv_space(self) -> UInt32:
        return self._u32(TCPI_OFF_RCV_SPACE)

    def total_retrans(self) -> UInt32:
        return self._u32(TCPI_OFF_TOTAL_RETRANS)

    def pacing_rate(self) -> UInt64:
        return self._u64(TCPI_OFF_PACING_RATE)

    def max_pacing_rate(self) -> UInt64:
        return self._u64(TCPI_OFF_MAX_PACING_RATE)

    def bytes_acked(self) -> UInt64:
        return self._u64(TCPI_OFF_BYTES_ACKED)

    def bytes_received(self) -> UInt64:
        return self._u64(TCPI_OFF_BYTES_RECEIVED)

    def segs_out(self) -> UInt32:
        return self._u32(TCPI_OFF_SEGS_OUT)

    def segs_in(self) -> UInt32:
        return self._u32(TCPI_OFF_SEGS_IN)

    def notsent_bytes(self) -> UInt32:
        return self._u32(TCPI_OFF_NOTSENT_BYTES)

    def min_rtt(self) -> UInt32:
        return self._u32(TCPI_OFF_MIN_RTT)

    def data_segs_in(self) -> UInt32:
        return self._u32(TCPI_OFF_DATA_SEGS_IN)

    def data_segs_out(self) -> UInt32:
        return self._u32(TCPI_OFF_DATA_SEGS_OUT)

    def delivery_rate(self) -> UInt64:
        return self._u64(TCPI_OFF_DELIVERY_RATE)

    def busy_time(self) -> UInt64:
        return self._u64(TCPI_OFF_BUSY_TIME)

    def rwnd_limited(self) -> UInt64:
        return self._u64(TCPI_OFF_RWND_LIMITED)

    def sndbuf_limited(self) -> UInt64:
        return self._u64(TCPI_OFF_SNDBUF_LIMITED)

    def delivered(self) -> UInt32:
        return self._u32(TCPI_OFF_DELIVERED)

    def delivered_ce(self) -> UInt32:
        return self._u32(TCPI_OFF_DELIVERED_CE)

    def bytes_sent(self) -> UInt64:
        return self._u64(TCPI_OFF_BYTES_SENT)

    def bytes_retrans(self) -> UInt64:
        return self._u64(TCPI_OFF_BYTES_RETRANS)

    def dsack_dups(self) -> UInt32:
        return self._u32(TCPI_OFF_DSACK_DUPS)

    def reord_seen(self) -> UInt32:
        return self._u32(TCPI_OFF_REORD_SEEN)

    def rcv_ooopack(self) -> UInt32:
        return self._u32(TCPI_OFF_RCV_OOOPACK)

    def snd_wnd(self) -> UInt32:
        return self._u32(TCPI_OFF_SND_WND)

    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            "TcpInfo(state=",
            self.state(),
            ", ca_state=",
            self.ca_state(),
            ", rtt=",
            self.rtt(),
            "us, rttvar=",
            self.rttvar(),
            "us, min_rtt=",
            self.min_rtt(),
            "us, rto=",
            self.rto(),
            "us, snd_cwnd=",
            self.snd_cwnd(),
            ", total_retrans=",
            self.total_retrans(),
            ", notsent_bytes=",
            self.notsent_bytes(),
            ", delivery_rate=",
            self.delivery_rate(),
            ")",
        )


# ---- module-local syscall wrappers -------------------------------------------


@inline(.always)
def _setsockopt_bytes[
    F: AsFd
](fd: F, level: Int, name: Int, value: Span[UInt8, _]) -> Int:
    """setsockopt with a byte buffer (possibly empty: `sys.setsockopt` needs
    a value to point at)."""
    return syscall5(
        SYS_setsockopt,
        Int(fd.raw_fd()),
        level,
        name,
        Int(value.unsafe_ptr()),
        len(value),
    )


@inline(.always)
def _getsockopt_bytes[
    F: AsFd
](
    fd: F, level: Int, name: Int, buf: MutSpan[UInt8, _], mut optlen: UInt32
) -> Int:
    """`optlen` must hold `len(buf)` on entry; the kernel stores the length
    it wrote."""
    return syscall5(
        SYS_getsockopt,
        Int(fd.raw_fd()),
        level,
        name,
        Int(buf.unsafe_ptr()),
        Int(Pointer(to=optlen)),
    )


@inline(.always)
def _invalid(op: StaticString) -> IoError:
    return IoError.of_kind(op, ErrorKind.InvalidInput)


@inline(.always)
def _c_int(value: Int, op: StaticString) raises IoError -> Int32:
    """`value` as a C int; out of range raises `InvalidInput` instead of
    silently truncating to some other valid value."""
    if value < Int(Int32.MIN) or value > Int(Int32.MAX):
        raise _invalid(op)
    return Int32(value)


@inline(.always)
def _c_nonneg(value: Int, op: StaticString) raises IoError -> Int32:
    if value < 0 or value > Int(Int32.MAX):
        raise _invalid(op)
    return Int32(value)


@inline(.always)
def _secs_ceil(d: Duration) -> Int:
    """`d` in whole seconds, rounded up (never below the requested time),
    clamped to a C int: `Duration.MAX` means "practically forever"."""
    var ns = d.as_nanos()
    var s = ns // NANOS_PER_SEC
    if ns % NANOS_PER_SEC != 0:
        s += 1
    return min(s, Int(Int32.MAX))


@inline(.always)
def _millis_ceil(d: Duration) -> Int:
    """`d` in milliseconds, rounded up and clamped to a C int."""
    return min(d.as_millis_ceil(), Int(Int32.MAX))


def _check_c_name(
    name: Span[UInt8, _], cap: Int, op: StaticString
) raises IoError:
    """A name the kernel reads as a C string from a `cap`-byte buffer (NUL
    included): longer ones, and ones with a NUL byte, would be silently cut
    to a different name, so both raise `InvalidInput`."""
    if len(name) >= cap:
        raise _invalid(op)
    for i in range(len(name)):
        if name[i] == 0:
            raise _invalid(op)


@inline(.always)
def _cloexec_flags(nonblocking: Bool) -> Int:
    """Creation flags for socket/socketpair/accept4: always CLOEXEC."""
    return SOCK_CLOEXEC | (SOCK_NONBLOCK if nonblocking else 0)


# ---- Socket ------------------------------------------------------------------


struct Socket(AsFd, Movable, Writable):
    """An owned socket descriptor with one method per syscall/option.

    Not copyable; `try_clone` dups (with CLOEXEC). Dropping closes the fd
    (errors ignored); `close()` reports them."""

    var _fd: OwnedFd

    @inline(.always)
    def __init__(out self, var fd: OwnedFd):
        """Adopt `fd` (from fd passing, systemd activation, `into_fd`, ...);
        the caller vouches that it is a socket.

        L1 applies no policy: descriptor flags (FD_CLOEXEC, O_NONBLOCK) are
        left exactly as inherited, so an fd passed in without CLOEXEC stays
        inheritable across exec. The L2 `from_socket` constructors
        (`TcpStream`, `TcpListener`, `UnixListener`, ...) set CLOEXEC."""
        self._fd = fd^

    # ---- creation and ownership ----------------------------------------------

    @staticmethod
    def new(
        domain: Domain,
        type_: SockType,
        protocol: Protocol = Protocol.DEFAULT,
        *,
        nonblocking: Bool = False,
    ) raises IoError -> Socket:
        """`socket(domain, type | SOCK_CLOEXEC [| SOCK_NONBLOCK], protocol)`.
        An unsupported family (IPv6 disabled) raises `InvalidInput`
        (EAFNOSUPPORT)."""
        var flags = type_.value | _cloexec_flags(nonblocking)
        var r = check("socket", sys.socket(domain.value, flags, protocol.value))
        return Socket(OwnedFd(unsafe_from_raw=Int32(r)))

    @staticmethod
    def pair(
        domain: Domain,
        type_: SockType,
        protocol: Protocol = Protocol.DEFAULT,
        *,
        nonblocking: Bool = False,
    ) raises IoError -> SocketPair:
        """`socketpair` (only `Domain.UNIX` supports it), both ends
        CLOEXEC."""
        var fds = Array[Int32, 2](fill=-1)
        var flags = type_.value | _cloexec_flags(nonblocking)
        _ = check(
            "socketpair",
            sys.socketpair(domain.value, flags, protocol.value, fds),
        )
        return SocketPair(
            Socket(OwnedFd(unsafe_from_raw=fds[0])),
            Socket(OwnedFd(unsafe_from_raw=fds[1])),
        )

    @staticmethod
    @inline(.always)
    @deprecated(
        "adopt with `Socket(fd^)`, like `Epoll(fd^)` and `EventFd(fd^)`"
    )
    def from_owned_fd(var fd: OwnedFd) -> Socket:
        """Same as `Socket(fd^)`, which is the spelling to use."""
        return Socket(fd^)

    @inline(.always)
    def into_fd(deinit self) -> OwnedFd:
        """Give up the `Socket` wrapper, keeping the descriptor open (the
        same name as `Epoll.into_fd` and `EventFd.into_fd`). Adopt it back
        with `Socket(fd^)`."""
        return self._fd^

    @inline(.always)
    @deprecated("use `into_fd()`, like `Epoll.into_fd` and `EventFd.into_fd`")
    def into_owned_fd(deinit self) -> OwnedFd:
        """Same as `into_fd`, which is the spelling to use."""
        return self._fd^

    @inline(.always)
    def raw_fd(self) -> Int32:
        """The descriptor, still owned by `self` (see `OwnedFd.raw_fd`)."""
        return self._fd.raw_fd()

    def try_clone(self) raises IoError -> Socket:
        """A second descriptor for the same socket (F_DUPFD_CLOEXEC). Both
        share options, file status flags (O_NONBLOCK) and the connection."""
        return Socket(self._fd.try_clone())

    def close(deinit self) raises IoError:
        """Close and report errors (EINTR counts as closed, never retried)."""
        self._fd^.close()

    # ---- addresses and connection setup --------------------------------------

    def bind(self, addr: SocketAddr) raises IoError:
        var raw = addr.to_raw()
        _ = check("bind", sys.bind(self._fd, raw.storage, raw.socklen()))

    def bind_unix(self, addr: UnixAddr) raises IoError:
        """Binding a pathname creates the socket file (EADDRINUSE if it
        exists; the caller unlinks it when done). `UnixAddr.unnamed()`
        autobinds to a kernel-chosen abstract name."""
        var raw = addr.to_raw()
        _ = check("bind", sys.bind(self._fd, raw.storage, raw.socklen()))

    def listen(self, backlog: Int) raises IoError:
        """The kernel caps `backlog` at net.core.somaxconn (negative values
        mean that cap too); values beyond a C int are clamped first so they
        cannot wrap to something small."""
        var b = min(backlog, Int(Int32.MAX))
        _ = check("listen", sys.listen(self._fd, max(b, Int(Int32.MIN))))

    def accept(
        self, *, nonblocking: Bool = False
    ) raises IoError -> Accepted[SocketAddr]:
        """`accept4(SOCK_CLOEXEC [| SOCK_NONBLOCK])` on an IP listener.

        Linux accepted sockets never inherit O_NONBLOCK from the listener;
        `nonblocking` decides. A nonblocking listener with nothing pending
        raises `WouldBlock`; a signal raises `Interrupted` (call again). A
        connection reset while queued may surface as `ConnectionAborted`.

        Only for IP listeners: on any other family (AF_UNIX) the kernel has
        already dequeued the connection when its address turns out not to
        be IP, so it is closed (the client sees EOF) and `InvalidInput`
        raised. Use `accept_unix` there.
        """
        var raw = RawSockaddr()
        var r = check(
            "accept4",
            sys.accept4(
                self._fd, raw.storage, raw.len, _cloexec_flags(nonblocking)
            ),
        )
        var s = Socket(OwnedFd(unsafe_from_raw=Int32(r)))
        return Accepted[SocketAddr](s^, SocketAddr.from_raw(raw))

    def accept_unix(
        self, *, nonblocking: Bool = False
    ) raises IoError -> Accepted[UnixAddr]:
        """`accept` for AF_UNIX listeners; the peer is usually unnamed."""
        var raw = RawSockaddr()
        var r = check(
            "accept4",
            sys.accept4(
                self._fd, raw.storage, raw.len, _cloexec_flags(nonblocking)
            ),
        )
        var s = Socket(OwnedFd(unsafe_from_raw=Int32(r)))
        return Accepted[UnixAddr](s^, _unix_from_raw(raw))

    def connect(self, addr: SocketAddr) raises IoError:
        """`connect(2)`, reported as is:

        - Nonblocking socket: EINPROGRESS raises kind `InProgress`; the
          handshake continues. Wait until the socket is writable
          (`linux.poll.wait_ready(sock, POLLOUT, deadline, op)`), then
          `take_error()`: `None` means connected, otherwise it is the
          failure (`ConnectionRefused`, `TimedOut`, ...).
        - Blocking socket interrupted by a signal: kind `Interrupted`. The
          attempt continues in the kernel: wait for writable and
          `take_error()` exactly as for `InProgress`.

        Do not call `connect` again to learn the outcome of a pending TCP
        attempt. While the handshake runs, a second call raises `InProgress`
        (EALREADY) on a nonblocking socket and waits again on a blocking
        one. Once the attempt has succeeded it returns normally (only a
        third call raises `AlreadyConnected`). Once it has failed it raises
        that failure, or `ConnectionAborted` if `take_error()` already
        consumed it, and resets the socket, so the call after that starts a
        new attempt.
        """
        var raw = addr.to_raw()
        _ = check("connect", sys.connect(self._fd, raw.storage, raw.socklen()))

    def connect_unix(self, addr: UnixAddr) raises IoError:
        """`connect(2)` to a Unix address. A missing pathname raises
        `NotFound`, a pathname or name nobody listens on
        `ConnectionRefused`, and a full backlog `WouldBlock` (nonblocking)
        or blocks.

        Unlike TCP, nothing stays in progress: when this raises (including
        `Interrupted` and `WouldBlock`) the socket is still unconnected, and
        the way to retry is to call `connect_unix` again. Do NOT use the
        TCP recovery from `connect` here: an unconnected AF_UNIX stream
        socket polls writable (POLLOUT|POLLHUP) at once with no pending
        error, so `take_error()` returns `None` although nothing is
        connected; `peer_unix_addr()` (`NotConnected`) tells the truth."""
        var raw = addr.to_raw()
        _ = check("connect", sys.connect(self._fd, raw.storage, raw.socklen()))

    def local_addr(self) raises IoError -> SocketAddr:
        """getsockname of an IP socket (`InvalidInput` on other families)."""
        var raw = RawSockaddr()
        _ = check(
            "getsockname", sys.getsockname(self._fd, raw.storage, raw.len)
        )
        return SocketAddr.from_raw(raw)

    def peer_addr(self) raises IoError -> SocketAddr:
        """getpeername; `NotConnected` before the connection exists."""
        var raw = RawSockaddr()
        _ = check(
            "getpeername", sys.getpeername(self._fd, raw.storage, raw.len)
        )
        return SocketAddr.from_raw(raw)

    def local_unix_addr(self) raises IoError -> UnixAddr:
        var raw = RawSockaddr()
        _ = check(
            "getsockname", sys.getsockname(self._fd, raw.storage, raw.len)
        )
        return _unix_from_raw(raw)

    def peer_unix_addr(self) raises IoError -> UnixAddr:
        var raw = RawSockaddr()
        _ = check(
            "getpeername", sys.getpeername(self._fd, raw.storage, raw.len)
        )
        return _unix_from_raw(raw)

    def shutdown(self, how: Shutdown) raises IoError:
        """`NotConnected` on an unconnected stream socket."""
        _ = check("shutdown", sys.shutdown(self._fd, how.value))

    def take_error(self) raises IoError -> Optional[IoError]:
        """Read and clear the pending socket error (SO_ERROR): the outcome of
        a nonblocking/interrupted connect, or an asynchronous failure (ICMP,
        RST). `None` when there is none."""
        var v = self._get_int(SOL_SOCKET, SO_ERROR, "getsockopt(SO_ERROR)")
        if v == 0:
            return None
        return IoError.from_errno("SO_ERROR", Errno(Int32(v)))

    # ---- I/O -----------------------------------------------------------------

    @inline(.always)
    def send(self, buf: Span[UInt8, _]) raises IoError -> Int:
        """Bytes queued (may be fewer than `len(buf)`). MSG_NOSIGNAL: a
        closed peer raises `BrokenPipe`/`ConnectionReset`, no SIGPIPE."""
        return check("send", sys.send(self._fd, buf, MSG_NOSIGNAL))

    @inline(.always)
    def send_with_flags(
        self, buf: Span[UInt8, _], flags: Int
    ) raises IoError -> Int:
        """`send` with extra MSG_* flags (MSG_NOSIGNAL is always added)."""
        return check("send", sys.send(self._fd, buf, flags | MSG_NOSIGNAL))

    @inline(.always)
    def recv(self, buf: MutSpan[UInt8, _]) raises IoError -> Int:
        """Bytes received; 0 means EOF on a stream (or an empty datagram).
        A peer's abortive close raises `ConnectionReset`."""
        return check("recv", sys.recv(self._fd, buf, 0))

    @inline(.always)
    def recv_with_flags(
        self, buf: MutSpan[UInt8, _], flags: Int
    ) raises IoError -> Int:
        """With MSG_TRUNC on a datagram socket the result is the full
        datagram length, which may exceed `len(buf)`."""
        return check("recv", sys.recv(self._fd, buf, flags))

    @inline(.always)
    def peek(self, buf: MutSpan[UInt8, _]) raises IoError -> Int:
        """Like `recv` but leaves the data queued (MSG_PEEK)."""
        return check("recv(MSG_PEEK)", sys.recv(self._fd, buf, MSG_PEEK))

    def send_to(
        self, buf: Span[UInt8, _], addr: SocketAddr
    ) raises IoError -> Int:
        var raw = addr.to_raw()
        return check(
            "sendto",
            sys.sendto(self._fd, buf, MSG_NOSIGNAL, raw.storage, raw.socklen()),
        )

    def send_to_unix(
        self, buf: Span[UInt8, _], addr: UnixAddr
    ) raises IoError -> Int:
        var raw = addr.to_raw()
        return check(
            "sendto",
            sys.sendto(self._fd, buf, MSG_NOSIGNAL, raw.storage, raw.socklen()),
        )

    def recv_from(
        self, buf: MutSpan[UInt8, _]
    ) raises IoError -> Tuple[Int, Optional[SocketAddr]]:
        """(bytes, sender). On an IP datagram socket (UDP, ...) the sender
        is always set.

        It is `None` when the kernel reports no sender, which is the case on
        every stream socket (TCP, Unix): `recv_from` then behaves exactly
        like `recv`, 0 meaning EOF. It is also `None` when the sender is
        not an IP address (use `recv_from_unix` on Unix sockets). Nothing
        raises once the kernel has handed over the data, so code shared
        between UDP and TCP never loses bytes here."""
        return self._recv_from(buf, 0, "recvfrom")

    def peek_from(
        self, buf: MutSpan[UInt8, _]
    ) raises IoError -> Tuple[Int, Optional[SocketAddr]]:
        """`recv_from` with MSG_PEEK: the data stays queued."""
        return self._recv_from(buf, MSG_PEEK, "recvfrom(MSG_PEEK)")

    def recv_from_unix(
        self, buf: MutSpan[UInt8, _]
    ) raises IoError -> Tuple[Int, UnixAddr]:
        """(bytes, sender) on a Unix datagram socket; an unbound sender is
        `UnixAddr.unnamed()`."""
        var raw = RawSockaddr()
        var n = check(
            "recvfrom", sys.recvfrom(self._fd, buf, 0, raw.storage, raw.len)
        )
        return (n, _unix_from_raw(raw))

    def _recv_from(
        self, buf: MutSpan[UInt8, _], flags: Int, op: StaticString
    ) raises IoError -> Tuple[Int, Optional[SocketAddr]]:
        var raw = RawSockaddr()
        var n = check(
            op, sys.recvfrom(self._fd, buf, flags, raw.storage, raw.len)
        )
        return (n, _ip_sender(raw))

    def send_vectored[
        mut: Bool, //, o: Origin[mut=mut]
    ](self, bufs: Span[Span[UInt8, o], _]) raises IoError -> Int:
        """Gather-send `bufs` in order with one sendmsg(MSG_NOSIGNAL).

        Returns the bytes queued, possibly fewer than the total (a partial
        send can stop inside any buffer). Empty buffers are skipped (they
        carry no bytes, so this changes nothing about what is sent), and at
        most IOV_MAX (1024) non-empty buffers are passed, like Rust's
        `write_vectored`: the result then simply counts less, and stream
        callers loop as for any partial send. (On a datagram socket that
        would cut the datagram short, so keep datagrams within IOV_MAX
        non-empty buffers.) 0 therefore means every buffer was empty.

        Build `bufs` from spans that share one origin, for example
        `var v = List[Span[UInt8, origin_of(a, b)]](); v.append(a); ...` or
        slices of one buffer (`Span(buf)[0:4]`)."""
        return self.send_vectored_with_flags(bufs, 0)

    def send_vectored_with_flags[
        mut: Bool, //, o: Origin[mut=mut]
    ](self, bufs: Span[Span[UInt8, o], _], flags: Int) raises IoError -> Int:
        """`send_vectored` with extra MSG_* flags (MSG_NOSIGNAL is always
        added)."""
        var n = _nonempty_iov_count(bufs)
        var r: Int
        if n <= _IOV_STACK:
            var iov = Array[Iovec, _IOV_STACK](fill=Iovec(0, 0))
            var k = 0
            for i in range(len(bufs)):
                if k == n:
                    break
                if len(bufs[i]) != 0:
                    iov[k] = Iovec(
                        Int(bufs[i].unsafe_ptr()), UInt(len(bufs[i]))
                    )
                    k += 1
            r = _sendmsg_iov(self._fd, Span(iov)[0:n], flags | MSG_NOSIGNAL)
            sys.keep_alive(iov)
        else:
            var iov = List[Iovec](capacity=n)
            for i in range(len(bufs)):
                if len(iov) == n:
                    break
                if len(bufs[i]) != 0:
                    iov.append(
                        Iovec(Int(bufs[i].unsafe_ptr()), UInt(len(bufs[i])))
                    )
            r = _sendmsg_iov(self._fd, Span(iov), flags | MSG_NOSIGNAL)
            sys.keep_alive(iov)
        sys.keep_alive(bufs)
        return check("sendmsg", r)

    def recv_vectored[
        o: MutOrigin
    ](self, bufs: Span[MutSpan[UInt8, o], _]) raises IoError -> Int:
        """Scatter-receive into `bufs` in order with one recvmsg; filled
        front to back. 0 means EOF (or that every buffer is empty). Empty
        buffers are skipped and at most IOV_MAX (1024) non-empty ones are
        used, so empty buffers in front never turn pending data into a
        false EOF."""
        return self.recv_vectored_with_flags(bufs, 0)[0]

    def recv_vectored_with_flags[
        o: MutOrigin
    ](
        self, bufs: Span[MutSpan[UInt8, o], _], flags: Int
    ) raises IoError -> Tuple[Int, Int]:
        """(bytes, msg_flags): msg_flags carries MSG_TRUNC when a datagram
        did not fit (the excess is discarded)."""
        var n = _nonempty_iov_count(bufs)
        var r: Int
        var mflags: Int
        if n <= _IOV_STACK:
            var iov = Array[Iovec, _IOV_STACK](fill=Iovec(0, 0))
            var k = 0
            for i in range(len(bufs)):
                if k == n:
                    break
                if len(bufs[i]) != 0:
                    iov[k] = Iovec(
                        Int(bufs[i].unsafe_ptr()), UInt(len(bufs[i]))
                    )
                    k += 1
            var res = _recvmsg_iov(self._fd, Span(iov)[0:n], flags)
            sys.keep_alive(iov)
            r = res[0]
            mflags = res[1]
        else:
            var iov = List[Iovec](capacity=n)
            for i in range(len(bufs)):
                if len(iov) == n:
                    break
                if len(bufs[i]) != 0:
                    iov.append(
                        Iovec(Int(bufs[i].unsafe_ptr()), UInt(len(bufs[i])))
                    )
            var res = _recvmsg_iov(self._fd, Span(iov), flags)
            sys.keep_alive(iov)
            r = res[0]
            mflags = res[1]
        sys.keep_alive(bufs)
        return (check("recvmsg", r), mflags)

    # ---- raw option escape hatches -------------------------------------------

    def set_option_int(self, level: Int, name: Int, value: Int) raises IoError:
        """setsockopt with a C int; `value` outside the int range raises
        `InvalidInput`."""
        var v = _c_int(value, "setsockopt")
        _ = check(
            "setsockopt",
            sys.setsockopt(self._fd, level, name, v, size_of[Int32]()),
        )

    def get_option_int(self, level: Int, name: Int) raises IoError -> Int:
        return self._get_int(level, name, "getsockopt")

    def set_option_bytes(
        self, level: Int, name: Int, value: Span[UInt8, _]
    ) raises IoError:
        """setsockopt with `value` as the raw option bytes (may be empty)."""
        _ = check("setsockopt", _setsockopt_bytes(self._fd, level, name, value))

    def get_option_bytes(
        self, level: Int, name: Int, buf: MutSpan[UInt8, _]
    ) raises IoError -> Int:
        """getsockopt into `buf`; returns how many bytes of `buf` hold the
        option, never more than `len(buf)`, so `buf[0:n]` is always in
        bounds. Most options are simply cut to `len(buf)`. A few (netlink
        NETLINK_LIST_MEMBERSHIPS, ...) succeed while reporting a longer
        length than fits and copy only what fits, possibly nothing; use
        `get_option_bytes_with_len` to detect that and retry with a buffer
        of the reported size."""
        return self.get_option_bytes_with_len(level, name, buf)[0]

    def get_option_bytes_with_len(
        self, level: Int, name: Int, buf: MutSpan[UInt8, _]
    ) raises IoError -> Tuple[Int, Int]:
        """(bytes of `buf` holding the option, at most `len(buf)`; the
        length the kernel reported). A reported length above `len(buf)`
        means the option did not fit and `buf` holds an incomplete (for
        some options, untouched) prefix."""
        var n = UInt32(len(buf))
        _ = check(
            "getsockopt", _getsockopt_bytes(self._fd, level, name, buf, n)
        )
        return (min(Int(n), len(buf)), Int(n))

    @inline(.always)
    def _set_int(
        self, level: Int, name: Int, value: Int32, op: StaticString
    ) raises IoError:
        _ = check(
            op, sys.setsockopt(self._fd, level, name, value, size_of[Int32]())
        )

    @inline(.always)
    def _get_int(
        self, level: Int, name: Int, op: StaticString
    ) raises IoError -> Int:
        var v: Int32 = 0
        var n = UInt32(size_of[Int32]())
        _ = check(op, sys.getsockopt(self._fd, level, name, v, n))
        return Int(v)

    @inline(.always)
    def _set_bool(
        self, level: Int, name: Int, on: Bool, op: StaticString
    ) raises IoError:
        self._set_int(level, name, Int32(1) if on else Int32(0), op)

    @inline(.always)
    def _get_bool(
        self, level: Int, name: Int, op: StaticString
    ) raises IoError -> Bool:
        return self._get_int(level, name, op) != 0

    # ---- SOL_SOCKET options --------------------------------------------------

    def set_reuse_address(self, on: Bool) raises IoError:
        """SO_REUSEADDR: bind a listener while old connections on its port
        are in TIME_WAIT."""
        self._set_bool(SOL_SOCKET, SO_REUSEADDR, on, "setsockopt(SO_REUSEADDR)")

    def reuse_address(self) raises IoError -> Bool:
        return self._get_bool(
            SOL_SOCKET, SO_REUSEADDR, "getsockopt(SO_REUSEADDR)"
        )

    def set_reuse_port(self, on: Bool) raises IoError:
        """SO_REUSEPORT: several sockets (same effective uid) bind one port
        and the kernel load-balances among them. Set before `bind`."""
        self._set_bool(SOL_SOCKET, SO_REUSEPORT, on, "setsockopt(SO_REUSEPORT)")

    def reuse_port(self) raises IoError -> Bool:
        return self._get_bool(
            SOL_SOCKET, SO_REUSEPORT, "getsockopt(SO_REUSEPORT)"
        )

    def set_broadcast(self, on: Bool) raises IoError:
        """SO_BROADCAST: allow sending datagrams to a broadcast address
        (255.255.255.255 or a subnet's); without it such sends fail with
        EACCES (`PermissionDenied`)."""
        self._set_bool(SOL_SOCKET, SO_BROADCAST, on, "setsockopt(SO_BROADCAST)")

    def broadcast(self) raises IoError -> Bool:
        return self._get_bool(
            SOL_SOCKET, SO_BROADCAST, "getsockopt(SO_BROADCAST)"
        )

    def set_keepalive(self, on: Bool) raises IoError:
        """SO_KEEPALIVE; timing comes from `set_tcp_keepalive` or the
        net.ipv4.tcp_keepalive_* sysctls."""
        self._set_bool(SOL_SOCKET, SO_KEEPALIVE, on, "setsockopt(SO_KEEPALIVE)")

    def keepalive(self) raises IoError -> Bool:
        return self._get_bool(
            SOL_SOCKET, SO_KEEPALIVE, "getsockopt(SO_KEEPALIVE)"
        )

    def set_linger(self, timeout: Optional[Duration]) raises IoError:
        """SO_LINGER: what closing the socket does with data not yet sent.

        - `None` (the default): close returns at once; the kernel keeps
          sending the queued data in the background, then the FIN.
        - `Duration.ZERO`: abortive close. It returns at once, discards the
          queued data and sends RST (the peer gets `ConnectionReset`).
        - Longer: close BLOCKS the calling thread until the queued data and
          the FIN are acknowledged, for at most this long (rounded up to
          whole seconds, the kernel's unit). On Linux this applies to every
          close of the socket: `close()`, dropping the `Socket` or a stream
          that owns it, and nonblocking sockets too, so every L2 stream
          (all O_NONBLOCK) is affected. No read/write deadline bounds it. A
          peer that stops reading (zero window) therefore stalls the
          closing thread for the whole time, and on an event loop it stalls
          every connection on that loop.

        On L2 streams and anything an event loop drives, use only `None` or
        `Duration.ZERO`. To make sure the peer got everything, use
        `shutdown(Shutdown.WRITE)` and then read to EOF under a deadline,
        rather than a lingering close."""
        var l = Linger(0, 0)
        if timeout:
            l = Linger(1, Int32(_secs_ceil(timeout.value())))
        _ = check(
            "setsockopt(SO_LINGER)",
            sys.setsockopt(
                self._fd, SOL_SOCKET, SO_LINGER, l, size_of[Linger]()
            ),
        )

    @deprecated(
        "pass a Duration: `set_linger(Duration.ZERO)` for an abortive close,"
        " `set_linger(Duration.from_secs(n))` for a (blocking) lingering one"
    )
    def set_linger(self, seconds: Int) raises IoError:
        """`set_linger` in whole seconds, kept for existing callers: 0 is an
        abortive close, more blocks every close (see the `Duration`
        overload). Negative or beyond a C int raises `InvalidInput`."""
        var s = _c_nonneg(seconds, "setsockopt(SO_LINGER)")
        self.set_linger(Duration.from_secs(Int(s)))

    def linger(self) raises IoError -> Optional[Duration]:
        """`None` when off; otherwise the linger time (whole seconds, so
        `Duration.ZERO` means abortive close)."""
        var l = Linger(0, 0)
        var n = UInt32(size_of[Linger]())
        _ = check(
            "getsockopt(SO_LINGER)",
            sys.getsockopt(self._fd, SOL_SOCKET, SO_LINGER, l, n),
        )
        if l.onoff == 0:
            return None
        return Duration.from_secs(Int(l.linger))

    def set_recv_buffer_size(self, size: Int) raises IoError:
        """SO_RCVBUF. The kernel stores `2 * min(size, net.core.rmem_max)`
        (at least ~2 KiB) to cover bookkeeping overhead, so
        `recv_buffer_size()` reads back the doubled value. Setting it also
        locks the size: TCP receive-buffer autotuning is disabled for this
        socket, which usually hurts throughput on high-BDP paths. Set before
        `listen`/`connect` for the window scale to account for it. Negative
        raises `InvalidInput`."""
        self._set_int(
            SOL_SOCKET,
            SO_RCVBUF,
            _c_nonneg(size, "setsockopt(SO_RCVBUF)"),
            "setsockopt(SO_RCVBUF)",
        )

    def recv_buffer_size(self) raises IoError -> Int:
        return self._get_int(SOL_SOCKET, SO_RCVBUF, "getsockopt(SO_RCVBUF)")

    def set_send_buffer_size(self, size: Int) raises IoError:
        """SO_SNDBUF; same doubling (cap net.core.wmem_max) and
        autotuning-disabling caveats as `set_recv_buffer_size`."""
        self._set_int(
            SOL_SOCKET,
            SO_SNDBUF,
            _c_nonneg(size, "setsockopt(SO_SNDBUF)"),
            "setsockopt(SO_SNDBUF)",
        )

    def send_buffer_size(self) raises IoError -> Int:
        return self._get_int(SOL_SOCKET, SO_SNDBUF, "getsockopt(SO_SNDBUF)")

    def set_recv_lowat(self, bytes: Int) raises IoError:
        """SO_RCVLOWAT: a blocking `recv` waits until at least `bytes` are
        queued (or EOF, an error, a signal or SO_RCVTIMEO). On TCP,
        readiness (poll/epoll POLLIN) waits for it too; AF_UNIX readiness
        ignores it. 0 is stored as 1. On TCP the kernel caps it at half the
        largest receive buffer (and may grow the buffer to fit), so read
        back `recv_lowat()`. Negative raises `InvalidInput`."""
        self._set_int(
            SOL_SOCKET,
            SO_RCVLOWAT,
            _c_nonneg(bytes, "setsockopt(SO_RCVLOWAT)"),
            "setsockopt(SO_RCVLOWAT)",
        )

    def recv_lowat(self) raises IoError -> Int:
        return self._get_int(SOL_SOCKET, SO_RCVLOWAT, "getsockopt(SO_RCVLOWAT)")

    def set_mark(self, mark: UInt32) raises IoError:
        """SO_MARK (fwmark for policy routing/netfilter). Needs CAP_NET_ADMIN
        or CAP_NET_RAW: raises `PermissionDenied` otherwise."""
        self._set_int(SOL_SOCKET, SO_MARK, Int32(mark), "setsockopt(SO_MARK)")

    def mark(self) raises IoError -> UInt32:
        return UInt32(
            Int32(self._get_int(SOL_SOCKET, SO_MARK, "getsockopt(SO_MARK)"))
        )

    def set_bind_device(self, name: StringSlice) raises IoError:
        """SO_BINDTODEVICE: only use interface `name`; empty unbinds. Longer
        than 15 bytes, or containing a NUL byte (the kernel would bind to
        the part before it: "lo\\0x" would bind "lo"), raises `InvalidInput`.
        Unprivileged processes may bind an unbound socket (Linux >= 5.7);
        rebinding needs CAP_NET_RAW (`PermissionDenied`). Unknown names
        raise `NotFound` (ENODEV)."""
        self.set_bind_device(name.as_bytes())

    def set_bind_device(self, name: Span[UInt8, _]) raises IoError:
        comptime op = "setsockopt(SO_BINDTODEVICE)"
        _check_c_name(name, IF_NAMESIZE, op)
        var r = _setsockopt_bytes(self._fd, SOL_SOCKET, SO_BINDTODEVICE, name)
        if r == -Int(Errno.ENODEV.value):
            raise IoError(ErrorKind.NotFound, Errno.ENODEV, op)
        _ = check(op, r)

    def bind_device(self) raises IoError -> Optional[String]:
        """The bound interface name, or `None` when not bound."""
        var buf = Array[UInt8, IF_NAMESIZE](fill=0)
        var n = UInt32(IF_NAMESIZE)
        _ = check(
            "getsockopt(SO_BINDTODEVICE)",
            _getsockopt_bytes(
                self._fd, SOL_SOCKET, SO_BINDTODEVICE, Span(buf), n
            ),
        )
        var k = 0
        while k < Int(n) and k < IF_NAMESIZE and buf[k] != 0:
            k += 1
        if k == 0:
            return None
        return String(from_utf8_lossy=Span(buf)[0:k])

    def set_incoming_cpu(self, cpu: Int) raises IoError:
        """SO_INCOMING_CPU: steer this socket to listeners in a SO_REUSEPORT
        group whose CPU matches (and read back which CPU handled it)."""
        self._set_int(
            SOL_SOCKET,
            SO_INCOMING_CPU,
            _c_int(cpu, "setsockopt(SO_INCOMING_CPU)"),
            "setsockopt(SO_INCOMING_CPU)",
        )

    def incoming_cpu(self) raises IoError -> Int:
        """-1 until a CPU is recorded."""
        return self._get_int(
            SOL_SOCKET, SO_INCOMING_CPU, "getsockopt(SO_INCOMING_CPU)"
        )

    def socket_type(self) raises IoError -> SockType:
        return SockType(
            self._get_int(SOL_SOCKET, SO_TYPE, "getsockopt(SO_TYPE)")
        )

    def domain(self) raises IoError -> Domain:
        return Domain(
            self._get_int(SOL_SOCKET, SO_DOMAIN, "getsockopt(SO_DOMAIN)")
        )

    def protocol(self) raises IoError -> Protocol:
        """The resolved protocol (`TCP` for an IP stream created with
        `DEFAULT`)."""
        return Protocol(
            self._get_int(SOL_SOCKET, SO_PROTOCOL, "getsockopt(SO_PROTOCOL)")
        )

    def is_listener(self) raises IoError -> Bool:
        """SO_ACCEPTCONN: whether `listen` was called."""
        return self._get_bool(
            SOL_SOCKET, SO_ACCEPTCONN, "getsockopt(SO_ACCEPTCONN)"
        )

    def peer_cred(self) raises IoError -> Ucred:
        """SO_PEERCRED: pid/uid/gid of the peer process at connect (or
        socketpair) time. Meaningful only for connected AF_UNIX sockets.

        A socket without peer credentials (TCP, UDP, an unconnected Unix
        socket) reports pid 0 and uid = gid = 0xFFFFFFFF (`UInt32.MAX`,
        the C value -1, which is never a real id). Check for that, not for
        the overflow id 65534 (/proc/sys/kernel/overflowuid): the overflow
        ids appear only for a real peer whose ids have no mapping in this
        process's user namespace."""
        var c = Ucred(0, 0, 0)
        var n = UInt32(size_of[Ucred]())
        _ = check(
            "getsockopt(SO_PEERCRED)",
            sys.getsockopt(self._fd, SOL_SOCKET, SO_PEERCRED, c, n),
        )
        return c^

    # ---- nonblocking (fcntl) -------------------------------------------------

    def set_nonblocking(self, on: Bool) raises IoError:
        """O_NONBLOCK via fcntl. It is a file status flag: `try_clone`
        duplicates share it."""
        self._fd.set_nonblocking(on)

    def nonblocking(self) raises IoError -> Bool:
        return self._fd.is_nonblocking()

    # ---- IPPROTO_TCP options -------------------------------------------------

    def set_nodelay(self, on: Bool) raises IoError:
        """TCP_NODELAY: disable Nagle (send small segments at once)."""
        self._set_bool(IPPROTO_TCP, TCP_NODELAY, on, "setsockopt(TCP_NODELAY)")

    def nodelay(self) raises IoError -> Bool:
        return self._get_bool(
            IPPROTO_TCP, TCP_NODELAY, "getsockopt(TCP_NODELAY)"
        )

    def set_tcp_keepalive(self, ka: TcpKeepalive) raises IoError:
        """TCP_KEEPIDLE, TCP_KEEPINTVL and TCP_KEEPCNT. Values outside the
        kernel's ranges (see `TcpKeepalive`) raise `InvalidInput` before
        anything is changed. Does not turn SO_KEEPALIVE on."""
        comptime op = "setsockopt(TCP_KEEPALIVE)"
        # Whole seconds, rounded up; _secs_ceil clamps at Int32.MAX, which
        # is still above the kernel maxima, so huge values are rejected.
        var idle = _secs_ceil(ka.idle)
        var interval = _secs_ceil(ka.interval)
        if idle < 1 or idle > MAX_TCP_KEEPIDLE:
            raise _invalid(op)
        if interval < 1 or interval > MAX_TCP_KEEPINTVL:
            raise _invalid(op)
        if ka.count < 1 or ka.count > MAX_TCP_KEEPCNT:
            raise _invalid(op)
        self._set_int(
            IPPROTO_TCP,
            TCP_KEEPIDLE,
            Int32(idle),
            "setsockopt(TCP_KEEPIDLE)",
        )
        self._set_int(
            IPPROTO_TCP,
            TCP_KEEPINTVL,
            Int32(interval),
            "setsockopt(TCP_KEEPINTVL)",
        )
        self._set_int(
            IPPROTO_TCP, TCP_KEEPCNT, Int32(ka.count), "setsockopt(TCP_KEEPCNT)"
        )

    def tcp_keepalive(self) raises IoError -> TcpKeepalive:
        """Current values (the sysctl defaults until set)."""
        return TcpKeepalive(
            Duration.from_secs(
                self._get_int(
                    IPPROTO_TCP, TCP_KEEPIDLE, "getsockopt(TCP_KEEPIDLE)"
                )
            ),
            Duration.from_secs(
                self._get_int(
                    IPPROTO_TCP, TCP_KEEPINTVL, "getsockopt(TCP_KEEPINTVL)"
                )
            ),
            self._get_int(IPPROTO_TCP, TCP_KEEPCNT, "getsockopt(TCP_KEEPCNT)"),
        )

    def set_tcp_user_timeout(self, timeout: Optional[Duration]) raises IoError:
        """TCP_USER_TIMEOUT: how long transmitted data may stay unacknowledged
        (or zero-window probes go unanswered) before the kernel drops the
        connection with ETIMEDOUT. The kernel checks it when a retransmit or
        probe timer fires, so the abort can come somewhat later.

        `None` restores the system default. A time is rounded up to whole
        milliseconds (the kernel's unit) and clamped at Int32.MAX ms (about
        24.8 days). `Duration.ZERO` raises `InvalidInput`: the kernel would
        read 0 as "system default", which is not a zero timeout."""
        comptime op = "setsockopt(TCP_USER_TIMEOUT)"
        var ms = 0
        if timeout:
            if timeout.value().is_zero():
                raise _invalid(op)
            ms = _millis_ceil(timeout.value())
        self._set_int(IPPROTO_TCP, TCP_USER_TIMEOUT, Int32(ms), op)

    def tcp_user_timeout(self) raises IoError -> Optional[Duration]:
        """`None` while the system default applies."""
        var ms = self._get_int(
            IPPROTO_TCP, TCP_USER_TIMEOUT, "getsockopt(TCP_USER_TIMEOUT)"
        )
        if ms <= 0:
            return None
        return Duration.from_millis(ms)

    def set_quickack(self, on: Bool) raises IoError:
        """TCP_QUICKACK: ACK immediately instead of delaying. Not sticky: the
        kernel may leave quickack mode on its own later."""
        self._set_bool(
            IPPROTO_TCP, TCP_QUICKACK, on, "setsockopt(TCP_QUICKACK)"
        )

    def quickack(self) raises IoError -> Bool:
        return self._get_bool(
            IPPROTO_TCP, TCP_QUICKACK, "getsockopt(TCP_QUICKACK)"
        )

    def set_cork(self, on: Bool) raises IoError:
        """TCP_CORK: hold partial segments until uncorked (or 200 ms)."""
        self._set_bool(IPPROTO_TCP, TCP_CORK, on, "setsockopt(TCP_CORK)")

    def cork(self) raises IoError -> Bool:
        return self._get_bool(IPPROTO_TCP, TCP_CORK, "getsockopt(TCP_CORK)")

    def set_notsent_lowat(self, bytes: Int) raises IoError:
        """TCP_NOTSENT_LOWAT: report writable only while fewer than `bytes`
        are queued but unsent (0 = use net.ipv4.tcp_notsent_lowat).
        Negative raises `InvalidInput`."""
        self._set_int(
            IPPROTO_TCP,
            TCP_NOTSENT_LOWAT,
            _c_nonneg(bytes, "setsockopt(TCP_NOTSENT_LOWAT)"),
            "setsockopt(TCP_NOTSENT_LOWAT)",
        )

    def notsent_lowat(self) raises IoError -> Int:
        return self._get_int(
            IPPROTO_TCP, TCP_NOTSENT_LOWAT, "getsockopt(TCP_NOTSENT_LOWAT)"
        )

    def set_defer_accept(self, timeout: Duration) raises IoError:
        """TCP_DEFER_ACCEPT on a listener: wake `accept` only once data
        arrived (or the time passed). `Duration.ZERO` disables. The time is
        rounded up to whole seconds; the kernel then stores a SYN-ACK
        retransmit count, so `defer_accept()` reads back the time rounded up
        to that schedule (1, 3, 7, 15, 31, ... s; 5 s reads back 7 s)."""
        self._set_int(
            IPPROTO_TCP,
            TCP_DEFER_ACCEPT,
            Int32(_secs_ceil(timeout)),
            "setsockopt(TCP_DEFER_ACCEPT)",
        )

    def defer_accept(self) raises IoError -> Duration:
        """`Duration.ZERO` when disabled."""
        return Duration.from_secs(
            self._get_int(
                IPPROTO_TCP, TCP_DEFER_ACCEPT, "getsockopt(TCP_DEFER_ACCEPT)"
            )
        )

    def set_fastopen(self, queue_len: Int) raises IoError:
        """TCP_FASTOPEN on a listener (before or after `listen`): accept data
        in SYNs, with at most `queue_len` pending TFO requests. Servers also
        need bit 2 of net.ipv4.tcp_fastopen for it to take effect. Negative
        raises `InvalidInput`."""
        self._set_int(
            IPPROTO_TCP,
            TCP_FASTOPEN,
            _c_nonneg(queue_len, "setsockopt(TCP_FASTOPEN)"),
            "setsockopt(TCP_FASTOPEN)",
        )

    def fastopen(self) raises IoError -> Int:
        return self._get_int(
            IPPROTO_TCP, TCP_FASTOPEN, "getsockopt(TCP_FASTOPEN)"
        )

    def set_tcp_mss(self, bytes: Int) raises IoError:
        """TCP_MAXSEG: cap the maximum segment size, before `connect` or
        `listen` (the announced MSS follows it). 0 removes the cap. The
        kernel accepts 88..32767; anything else raises `InvalidInput`."""
        self._set_int(
            IPPROTO_TCP,
            TCP_MAXSEG,
            _c_nonneg(bytes, "setsockopt(TCP_MAXSEG)"),
            "setsockopt(TCP_MAXSEG)",
        )

    def tcp_mss(self) raises IoError -> Int:
        """The MSS in use once connected. Before that: the cap if one was
        set, otherwise the 536-byte default."""
        return self._get_int(IPPROTO_TCP, TCP_MAXSEG, "getsockopt(TCP_MAXSEG)")

    def set_syn_retries(self, count: Int) raises IoError:
        """TCP_SYNCNT: SYN retransmissions before `connect` gives up with
        `TimedOut`, overriding net.ipv4.tcp_syn_retries. That bounds how
        long the kernel keeps trying (with the 1 s initial timeout doubling,
        3 retries give up after about 15 s). 1..127; anything else raises
        `InvalidInput`."""
        self._set_int(
            IPPROTO_TCP,
            TCP_SYNCNT,
            _c_int(count, "setsockopt(TCP_SYNCNT)"),
            "setsockopt(TCP_SYNCNT)",
        )

    def syn_retries(self) raises IoError -> Int:
        """The value set, or the net.ipv4.tcp_syn_retries default."""
        return self._get_int(IPPROTO_TCP, TCP_SYNCNT, "getsockopt(TCP_SYNCNT)")

    def set_tcp_congestion(self, name: StringSlice) raises IoError:
        """TCP_CONGESTION: the congestion-control algorithm ("cubic",
        "reno", "bbr", ...). Empty, longer than 15 bytes, or containing a
        NUL byte raises `InvalidInput` (the kernel would silently use a cut
        name). An algorithm that is not available raises `NotFound`; one
        outside net.ipv4.tcp_allowed_congestion_control needs
        CAP_NET_ADMIN (`PermissionDenied`)."""
        self.set_tcp_congestion(name.as_bytes())

    def set_tcp_congestion(self, name: Span[UInt8, _]) raises IoError:
        comptime op = "setsockopt(TCP_CONGESTION)"
        if len(name) == 0:
            raise _invalid(op)
        _check_c_name(name, TCP_CA_NAME_MAX, op)
        _ = check(
            op, _setsockopt_bytes(self._fd, IPPROTO_TCP, TCP_CONGESTION, name)
        )

    def tcp_congestion(self) raises IoError -> String:
        """The algorithm in use (the system default until set)."""
        var buf = Array[UInt8, TCP_CA_NAME_MAX](fill=0)
        var n = UInt32(TCP_CA_NAME_MAX)
        _ = check(
            "getsockopt(TCP_CONGESTION)",
            _getsockopt_bytes(
                self._fd, IPPROTO_TCP, TCP_CONGESTION, Span(buf), n
            ),
        )
        var k = 0
        while k < Int(n) and k < TCP_CA_NAME_MAX and buf[k] != 0:
            k += 1
        return String(from_utf8_lossy=Span(buf)[0:k])

    def tcp_info(self) raises IoError -> TcpInfo:
        """TCP_INFO snapshot (state, RTT, cwnd, retransmits, ...).
        `Unsupported` on non-TCP sockets."""
        var info = TcpInfo()
        var n = UInt32(TCP_INFO_CAPACITY)
        _ = check(
            "getsockopt(TCP_INFO)",
            _getsockopt_bytes(
                self._fd, IPPROTO_TCP, TCP_INFO, Span(info._buf), n
            ),
        )
        info._len = min(Int(n), TCP_INFO_CAPACITY)
        return info^

    # ---- IP / IPv6 options ---------------------------------------------------

    def set_only_v6(self, on: Bool) raises IoError:
        """IPV6_V6ONLY on an AF_INET6 socket, before `bind`: `False` makes
        `[::]` also accept IPv4 (as ::ffff:a.b.c.d); the default comes from
        net.ipv6.bindv6only."""
        self._set_bool(IPPROTO_IPV6, IPV6_V6ONLY, on, "setsockopt(IPV6_V6ONLY)")

    def only_v6(self) raises IoError -> Bool:
        return self._get_bool(
            IPPROTO_IPV6, IPV6_V6ONLY, "getsockopt(IPV6_V6ONLY)"
        )

    def set_tos(self, tos: Int) raises IoError:
        """IP_TOS (IPv4 DSCP/ECN byte, 0..255; `InvalidInput` outside it,
        where the kernel would keep only the low byte). On TCP sockets the
        kernel keeps the two ECN bits to itself."""
        if tos < 0 or tos > 255:
            raise _invalid("setsockopt(IP_TOS)")
        self._set_int(IPPROTO_IP, IP_TOS, Int32(tos), "setsockopt(IP_TOS)")

    def tos(self) raises IoError -> Int:
        return self._get_int(IPPROTO_IP, IP_TOS, "getsockopt(IP_TOS)")

    def set_tclass_v6(self, tclass: Int) raises IoError:
        """IPV6_TCLASS (traffic class, 0..255; -1 = default). On TCP sockets
        the kernel keeps the ECN bits to itself."""
        self._set_int(
            IPPROTO_IPV6,
            IPV6_TCLASS,
            _c_int(tclass, "setsockopt(IPV6_TCLASS)"),
            "setsockopt(IPV6_TCLASS)",
        )

    def tclass_v6(self) raises IoError -> Int:
        return self._get_int(
            IPPROTO_IPV6, IPV6_TCLASS, "getsockopt(IPV6_TCLASS)"
        )

    def set_ttl(self, ttl: Int) raises IoError:
        """IP_TTL for unicast IPv4 (1..255; -1 restores the route default)."""
        self._set_int(
            IPPROTO_IP,
            IP_TTL,
            _c_int(ttl, "setsockopt(IP_TTL)"),
            "setsockopt(IP_TTL)",
        )

    def ttl(self) raises IoError -> Int:
        return self._get_int(IPPROTO_IP, IP_TTL, "getsockopt(IP_TTL)")

    def set_unicast_hops_v6(self, hops: Int) raises IoError:
        """IPV6_UNICAST_HOPS, the IPv6 TTL (1..255; -1 restores the route
        default)."""
        self._set_int(
            IPPROTO_IPV6,
            IPV6_UNICAST_HOPS,
            _c_int(hops, "setsockopt(IPV6_UNICAST_HOPS)"),
            "setsockopt(IPV6_UNICAST_HOPS)",
        )

    def unicast_hops_v6(self) raises IoError -> Int:
        return self._get_int(
            IPPROTO_IPV6, IPV6_UNICAST_HOPS, "getsockopt(IPV6_UNICAST_HOPS)"
        )

    # ---- multicast -----------------------------------------------------------

    def join_multicast_v4(
        self, group: Ipv4Addr, interface: Ipv4Addr = Ipv4Addr(0, 0, 0, 0)
    ) raises IoError:
        """IP_ADD_MEMBERSHIP: receive datagrams sent to `group` on the
        interface whose address is `interface` (0.0.0.0: the one the
        routing table picks for the group). The socket must be bound to the
        group's port. `InvalidInput` for a non-multicast group; a second
        join of the same group and interface is `AddrInUse`."""
        self._mreq_v4(
            IP_ADD_MEMBERSHIP, group, interface, "setsockopt(IP_ADD_MEMBERSHIP)"
        )

    def leave_multicast_v4(
        self, group: Ipv4Addr, interface: Ipv4Addr = Ipv4Addr(0, 0, 0, 0)
    ) raises IoError:
        """IP_DROP_MEMBERSHIP: undo `join_multicast_v4` (closing the socket
        also does)."""
        self._mreq_v4(
            IP_DROP_MEMBERSHIP,
            group,
            interface,
            "setsockopt(IP_DROP_MEMBERSHIP)",
        )

    def _mreq_v4(
        self, name: Int, group: Ipv4Addr, interface: Ipv4Addr, op: StaticString
    ) raises IoError:
        var m = IpMreqn(hton32(group.to_bits()), hton32(interface.to_bits()), 0)
        _ = check(
            op,
            sys.setsockopt(self._fd, IPPROTO_IP, name, m, size_of[IpMreqn]()),
        )

    def join_multicast_v6(
        self, group: Ipv6Addr, interface: UInt32 = 0
    ) raises IoError:
        """IPV6_ADD_MEMBERSHIP: receive datagrams sent to `group` on the
        interface with index `interface` (`if_nametoindex`; 0: the kernel's
        choice, which a link-local group such as ff02::/16 needs spelled
        out). The socket must be bound to the group's port."""
        self._mreq_v6(
            IPV6_ADD_MEMBERSHIP,
            group,
            interface,
            "setsockopt(IPV6_ADD_MEMBERSHIP)",
        )

    def leave_multicast_v6(
        self, group: Ipv6Addr, interface: UInt32 = 0
    ) raises IoError:
        """IPV6_DROP_MEMBERSHIP: undo `join_multicast_v6`."""
        self._mreq_v6(
            IPV6_DROP_MEMBERSHIP,
            group,
            interface,
            "setsockopt(IPV6_DROP_MEMBERSHIP)",
        )

    def _mreq_v6(
        self, name: Int, group: Ipv6Addr, interface: UInt32, op: StaticString
    ) raises IoError:
        var m = Ipv6Mreq(group.octets(), interface)
        _ = check(
            op,
            sys.setsockopt(
                self._fd, IPPROTO_IPV6, name, m, size_of[Ipv6Mreq]()
            ),
        )

    def set_multicast_ttl_v4(self, ttl: Int) raises IoError:
        """IP_MULTICAST_TTL: how far IPv4 multicast travels (0..255; the
        default 1 stays on the local network)."""
        self._set_int(
            IPPROTO_IP,
            IP_MULTICAST_TTL,
            _c_int(ttl, "setsockopt(IP_MULTICAST_TTL)"),
            "setsockopt(IP_MULTICAST_TTL)",
        )

    def multicast_ttl_v4(self) raises IoError -> Int:
        return self._get_int(
            IPPROTO_IP, IP_MULTICAST_TTL, "getsockopt(IP_MULTICAST_TTL)"
        )

    def set_multicast_loop_v4(self, on: Bool) raises IoError:
        """IP_MULTICAST_LOOP: deliver this socket's IPv4 multicast to
        listeners on this host too (on by default). It governs the local
        copy of what goes out a real interface; multicast sent on the
        loopback interface reaches local listeners through the interface
        itself, whatever this says."""
        self._set_bool(
            IPPROTO_IP, IP_MULTICAST_LOOP, on, "setsockopt(IP_MULTICAST_LOOP)"
        )

    def multicast_loop_v4(self) raises IoError -> Bool:
        return self._get_bool(
            IPPROTO_IP, IP_MULTICAST_LOOP, "getsockopt(IP_MULTICAST_LOOP)"
        )

    def set_multicast_if_v4(self, interface: Ipv4Addr) raises IoError:
        """IP_MULTICAST_IF: send IPv4 multicast from the interface with this
        address (0.0.0.0: by the routing table)."""
        var m = IpMreqn(0, hton32(interface.to_bits()), 0)
        _ = check(
            "setsockopt(IP_MULTICAST_IF)",
            sys.setsockopt(
                self._fd, IPPROTO_IP, IP_MULTICAST_IF, m, size_of[IpMreqn]()
            ),
        )

    def set_multicast_all_v4(self, on: Bool) raises IoError:
        """IP_MULTICAST_ALL. Linux's default (on) delivers to a socket bound
        to a wildcard address the datagrams of every group joined by any
        socket on this host for that port, not only its own memberships;
        off restricts it to the groups this socket joined."""
        self._set_bool(
            IPPROTO_IP, IP_MULTICAST_ALL, on, "setsockopt(IP_MULTICAST_ALL)"
        )

    def multicast_all_v4(self) raises IoError -> Bool:
        return self._get_bool(
            IPPROTO_IP, IP_MULTICAST_ALL, "getsockopt(IP_MULTICAST_ALL)"
        )

    def set_multicast_hops_v6(self, hops: Int) raises IoError:
        """IPV6_MULTICAST_HOPS (0..255; -1 restores the default, 1)."""
        self._set_int(
            IPPROTO_IPV6,
            IPV6_MULTICAST_HOPS,
            _c_int(hops, "setsockopt(IPV6_MULTICAST_HOPS)"),
            "setsockopt(IPV6_MULTICAST_HOPS)",
        )

    def multicast_hops_v6(self) raises IoError -> Int:
        return self._get_int(
            IPPROTO_IPV6, IPV6_MULTICAST_HOPS, "getsockopt(IPV6_MULTICAST_HOPS)"
        )

    def set_multicast_loop_v6(self, on: Bool) raises IoError:
        """IPV6_MULTICAST_LOOP: deliver this socket's IPv6 multicast locally
        too (on by default)."""
        self._set_bool(
            IPPROTO_IPV6,
            IPV6_MULTICAST_LOOP,
            on,
            "setsockopt(IPV6_MULTICAST_LOOP)",
        )

    def multicast_loop_v6(self) raises IoError -> Bool:
        return self._get_bool(
            IPPROTO_IPV6, IPV6_MULTICAST_LOOP, "getsockopt(IPV6_MULTICAST_LOOP)"
        )

    def set_multicast_if_v6(self, interface: UInt32) raises IoError:
        """IPV6_MULTICAST_IF: send IPv6 multicast from the interface with
        this index (0: the kernel's choice)."""
        self._set_int(
            IPPROTO_IPV6,
            IPV6_MULTICAST_IF,
            Int32(interface),
            "setsockopt(IPV6_MULTICAST_IF)",
        )

    def multicast_if_v6(self) raises IoError -> UInt32:
        return UInt32(
            self._get_int(
                IPPROTO_IPV6, IPV6_MULTICAST_IF, "getsockopt(IPV6_MULTICAST_IF)"
            )
        )

    def set_multicast_all_v6(self, on: Bool) raises IoError:
        """IPV6_MULTICAST_ALL: as `set_multicast_all_v4`, for IPv6 groups."""
        self._set_bool(
            IPPROTO_IPV6,
            IPV6_MULTICAST_ALL,
            on,
            "setsockopt(IPV6_MULTICAST_ALL)",
        )

    def multicast_all_v6(self) raises IoError -> Bool:
        return self._get_bool(
            IPPROTO_IPV6, IPV6_MULTICAST_ALL, "getsockopt(IPV6_MULTICAST_ALL)"
        )

    def write_to(self, mut writer: Some[Writer]):
        writer.write("Socket(fd=", self._fd.raw_fd(), ")")


# ---- helpers -----------------------------------------------------------------


def _unix_from_raw(raw: RawSockaddr) raises IoError -> UnixAddr:
    """Like `UnixAddr.from_raw`, but a zero length (recvfrom from an unbound
    datagram sender) is the unnamed address."""
    if raw.len == 0:
        return UnixAddr.unnamed()
    return UnixAddr.from_raw(raw)


def _ip_sender(raw: RawSockaddr) -> Optional[SocketAddr]:
    """The sender `recvfrom` reported, if it is an IP address. Never raises:
    the data is already consumed, so failing here would lose it."""
    var fam = raw.family()
    if raw.len == 0 or (fam != AF_INET and fam != AF_INET6):
        return None
    try:
        return SocketAddr.from_raw(raw)
    except:
        return None


@inline(.always)
def _nonempty_iov_count[
    mut: Bool, //, o: Origin[mut=mut]
](bufs: Span[Span[UInt8, o], _]) -> Int:
    """How many iovecs the vectored calls pass: the non-empty buffers, at
    most IOV_MAX. Skipping empty ones keeps byte placement identical and
    means IOV_MAX empty buffers in front cannot hide later data (the kernel
    would see 0 bytes and report EOF or a zero-length send)."""
    var n = 0
    for i in range(len(bufs)):
        if len(bufs[i]) != 0:
            n += 1
            if n == IOV_MAX:
                break
    return n


@inline(.always)
def _sendmsg_iov[F: AsFd](fd: F, iov: Span[Iovec, _], flags: Int) -> Int:
    """sendmsg of `iov` with no name/control. `iov` (a borrowed span) and
    the buffers it points at must outlive the call; callers keep_alive."""
    var msg = Msghdr(0, 0, Int(iov.unsafe_ptr()), UInt(len(iov)), 0, UInt(0), 0)
    var r = sys.sendmsg(fd, msg, flags)
    sys.keep_alive(iov)
    return r


@inline(.always)
def _recvmsg_iov[
    F: AsFd
](fd: F, iov: Span[Iovec, _], flags: Int) -> Tuple[Int, Int]:
    """(raw result, msg_flags)."""
    var msg = Msghdr(0, 0, Int(iov.unsafe_ptr()), UInt(len(iov)), 0, UInt(0), 0)
    var r = sys.recvmsg(fd, msg, flags)
    sys.keep_alive(iov)
    return (r, Int(msg.flags))
