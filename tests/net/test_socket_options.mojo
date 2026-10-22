"""Option round trips for net.socket: every typed setter/getter, kernel
quirks (buffer doubling, TCP_DEFER_ACCEPT rounding, ECN bits), privileged
options (tolerating EPERM) and invalid inputs."""

from std.os import getenv
from std.sys import size_of
from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_true,
)

from linux import Errno, ErrorKind, IoError, OwnedFd, check
from linux import sys
from linux.abi import SockaddrIn6
from linux.consts import (
    AF_INET6,
    IPPROTO_TCP,
    SO_RCVBUF,
    SO_REUSEADDR,
    SO_TYPE,
    SOCK_CLOEXEC,
    SOCK_DGRAM,
    SOCK_STREAM,
    SOL_SOCKET,
    TCP_NODELAY,
    TCP_USER_TIMEOUT,
)
from linux.time import Duration
from linux.syscall import err_of, is_err
from net.addr import SocketAddr
from net.socket import (
    MAX_TCP_KEEPCNT,
    MAX_TCP_KEEPIDLE,
    MAX_TCP_KEEPINTVL,
    Domain,
    SockType,
    Socket,
    SocketPair,
    TcpKeepalive,
)


def _tcp() raises -> Socket:
    return Socket.new(Domain.IPV4, SockType.STREAM)


def _ipv6(test: StaticString, need_loopback: Bool = True) raises -> Bool:
    """Whether this host has IPv6 (with `need_loopback`: a usable [::1]),
    decided with raw syscalls, not with the code under test. Only
    EAFNOSUPPORT from socket(AF_INET6) or EADDRNOTAVAIL from bind([::1]:0)
    mean "no IPv6"; any other failure raises, so a regression is never
    reported as a skip. Without IPv6 this prints a visible skip line (which
    tools/run_tests.sh shows and counts) and the test returns early, unless
    MOJO_TCP_REQUIRE_IPV6=1 turns it into a failure."""
    var why: StaticString
    var r = sys.socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0)
    if is_err(r) and Errno(err_of(r)) == Errno.EAFNOSUPPORT:
        why = "socket(AF_INET6): EAFNOSUPPORT"
    else:
        var fd = OwnedFd(
            unsafe_from_raw=Int32(check("socket(AF_INET6)", r))
        )
        if not need_loopback:
            return True
        var sa = SockaddrIn6(
            UInt16(AF_INET6), 0, 0, Array[UInt8, 16](fill=0), 0
        )
        sa.addr[15] = 1  # [::1]:0
        var b = sys.bind(fd, sa, size_of[SockaddrIn6]())
        if not is_err(b):
            return True
        if Errno(err_of(b)) != Errno.EADDRNOTAVAIL:
            _ = check("bind([::1]:0)", b)
        why = "bind([::1]:0): EADDRNOTAVAIL"
    if getenv("MOJO_TCP_REQUIRE_IPV6") == "1":
        raise Error(test, ": no IPv6 (", why, ") but MOJO_TCP_REQUIRE_IPV6=1")
    print(String("    (skipped: ", test, ": no IPv6, ", why, ")"))
    return False


def _tcp_pair() raises -> SocketPair:
    var l = Socket.new(Domain.IPV4, SockType.STREAM)
    l.bind(SocketAddr.parse("127.0.0.1:0"))
    l.listen(4)
    var c = Socket.new(Domain.IPV4, SockType.STREAM)
    c.connect(l.local_addr())
    return SocketPair(c^, l.accept().into_socket())


def _proc_int(path: StringSlice) raises -> Int:
    with open(path, "r") as f:
        return Int(f.read().strip())


def _expect_invalid(kind: ErrorKind, raised: Bool) raises:
    assert_true(raised, "expected InvalidInput, nothing raised")
    assert_equal(kind, ErrorKind.InvalidInput)


# ---- booleans ----------------------------------------------------------------


def test_bool_options_round_trip() raises:
    var s = _tcp()
    assert_false(s.reuse_address())
    s.set_reuse_address(True)
    assert_true(s.reuse_address())
    s.set_reuse_address(False)
    assert_false(s.reuse_address())

    assert_false(s.reuse_port())
    s.set_reuse_port(True)
    assert_true(s.reuse_port())
    s.set_reuse_port(False)
    assert_false(s.reuse_port())

    assert_false(s.keepalive())
    s.set_keepalive(True)
    assert_true(s.keepalive())
    s.set_keepalive(False)
    assert_false(s.keepalive())

    assert_false(s.nodelay())
    s.set_nodelay(True)
    assert_true(s.nodelay())
    s.set_nodelay(False)
    assert_false(s.nodelay())

    assert_false(s.cork())
    s.set_cork(True)
    assert_true(s.cork())
    s.set_cork(False)
    assert_false(s.cork())


def test_quickack_on_connected_socket() raises:
    var tp = _tcp_pair()
    ref c = tp.first.value()
    c.set_quickack(False)
    assert_false(c.quickack())
    c.set_quickack(True)
    assert_true(c.quickack())


def test_nonblocking_round_trip() raises:
    var s = _tcp()
    assert_false(s.nonblocking())
    s.set_nonblocking(True)
    assert_true(s.nonblocking())
    s.set_nonblocking(True)  # idempotent
    assert_true(s.nonblocking())
    s.set_nonblocking(False)
    assert_false(s.nonblocking())
    # O_NONBLOCK is a file status flag: shared with a clone.
    var dup = s.try_clone()
    s.set_nonblocking(True)
    assert_true(dup.nonblocking())


def test_reuse_port_lets_two_listeners_share_a_port() raises:
    var a = _tcp()
    a.set_reuse_port(True)
    a.bind(SocketAddr.parse("127.0.0.1:0"))
    a.listen(4)
    var b = _tcp()
    b.set_reuse_port(True)
    b.bind(a.local_addr())
    b.listen(4)
    assert_equal(b.local_addr(), a.local_addr())


def test_only_v6_round_trip() raises:
    # Option tests need AF_INET6 sockets, not a usable [::1].
    if not _ipv6("test_only_v6_round_trip", need_loopback=False):
        return
    var s = Socket.new(Domain.IPV6, SockType.STREAM)
    s.set_only_v6(True)
    assert_true(s.only_v6())
    s.set_only_v6(False)
    assert_false(s.only_v6())
    # IPV6_V6ONLY is not an IPv4 option.
    var v4 = _tcp()
    var raised = False
    try:
        _ = v4.only_v6()
    except e:
        raised = True
        assert_equal(String(e.op), "getsockopt(IPV6_V6ONLY)")
    assert_true(raised)


# ---- keepalive, linger -------------------------------------------------------


def _ka(idle: Int, interval: Int, count: Int) -> TcpKeepalive:
    return TcpKeepalive(
        idle=Duration.from_secs(idle),
        interval=Duration.from_secs(interval),
        count=count,
    )


def test_tcp_keepalive_round_trip() raises:
    var s = _tcp()
    var ka = _ka(30, 5, 4)
    s.set_tcp_keepalive(ka)
    assert_equal(s.tcp_keepalive(), ka)
    # Setting the timing does not turn SO_KEEPALIVE on (no hidden policy).
    assert_false(s.keepalive())
    var edges = _ka(MAX_TCP_KEEPIDLE, MAX_TCP_KEEPINTVL, MAX_TCP_KEEPCNT)
    s.set_tcp_keepalive(edges)
    assert_equal(s.tcp_keepalive(), edges)
    var ones = _ka(1, 1, 1)
    s.set_tcp_keepalive(ones)
    assert_equal(s.tcp_keepalive(), ones)
    assert_equal(String(ones), "TcpKeepalive(idle=1s, interval=1s, count=1)")


def test_tcp_keepalive_rejects_out_of_range_without_partial_update() raises:
    var s = _tcp()
    var good = _ka(60, 10, 3)
    s.set_tcp_keepalive(good)
    var bad: List[TcpKeepalive] = [
        _ka(0, 10, 3),
        _ka(MAX_TCP_KEEPIDLE + 1, 10, 3),
        _ka(-5, 10, 3),  # a negative Duration clamps to zero
        # A valid idle with a bad interval/count must not change idle.
        _ka(99, 0, 3),
        _ka(99, MAX_TCP_KEEPINTVL + 1, 3),
        _ka(99, 10, 0),
        _ka(99, 10, MAX_TCP_KEEPCNT + 1),
        _ka(99, 10, Int(1) << 40),
        # Just past the maximum rounds up out of range.
        TcpKeepalive(
            idle=Duration.from_secs(MAX_TCP_KEEPIDLE) + Duration.from_nanos(1),
            interval=Duration.from_secs(10),
            count=3,
        ),
        TcpKeepalive(
            idle=Duration.MAX, interval=Duration.from_secs(10), count=3
        ),
    ]
    for ka in bad:
        var raised = False
        var kind = ErrorKind.Other
        try:
            s.set_tcp_keepalive(ka)
        except e:
            raised = True
            kind = e.kind
        _expect_invalid(kind, raised)
        assert_equal(s.tcp_keepalive(), good)


def test_linger_round_trip() raises:
    var s = _tcp()
    assert_false(Bool(s.linger()))
    s.set_linger(Duration.ZERO)
    assert_equal(s.linger().value(), Duration.ZERO)
    s.set_linger(Duration.from_secs(5))
    assert_equal(s.linger().value(), Duration.from_secs(5))
    # Rounded up to whole seconds, never down to an abortive 0.
    s.set_linger(Duration.from_millis(1))
    assert_equal(s.linger().value(), Duration.from_secs(1))
    s.set_linger(Duration.from_millis(2500))
    assert_equal(s.linger().value(), Duration.from_secs(3))
    # "Forever" clamps to the largest C int of seconds.
    s.set_linger(Duration.MAX)
    assert_equal(s.linger().value(), Duration.from_secs(Int(Int32.MAX)))
    s.set_linger(None)
    assert_false(Bool(s.linger()))
    var off: Optional[Duration] = None
    s.set_linger(Duration.from_secs(2))
    s.set_linger(off)
    assert_false(Bool(s.linger()))


# ---- buffer sizes ------------------------------------------------------------


def test_buffer_sizes_are_doubled_by_the_kernel() raises:
    var rmax = _proc_int("/proc/sys/net/core/rmem_max")
    var wmax = _proc_int("/proc/sys/net/core/wmem_max")
    var s = _tcp()
    s.set_recv_buffer_size(8192)
    assert_equal(s.recv_buffer_size(), 2 * min(8192, rmax))
    s.set_send_buffer_size(16384)
    assert_equal(s.send_buffer_size(), 2 * min(16384, wmax))
    # Above the sysctl cap: clamped to the cap, then doubled. The request
    # must fit a C int (hosts tuned for 100G set the caps near INT_MAX),
    # and the kernel also clamps to INT_MAX / 2 so the doubled value fits.
    var int_max = Int(Int32.MAX)
    s.set_recv_buffer_size(min(rmax * 4, int_max))
    assert_equal(s.recv_buffer_size(), 2 * min(rmax, int_max // 2))
    s.set_send_buffer_size(min(wmax * 4, int_max))
    assert_equal(s.send_buffer_size(), 2 * min(wmax, int_max // 2))
    # Tiny: raised to the kernel minimum (a couple of KiB), not 2 bytes.
    s.set_recv_buffer_size(1)
    var tiny = s.recv_buffer_size()
    assert_true(tiny >= 2048 and tiny < 8192, String("min rcvbuf ", tiny))
    s.set_send_buffer_size(0)
    assert_true(s.send_buffer_size() >= 2048)
    # The raw escape hatch sees the same value.
    assert_equal(s.get_option_int(SOL_SOCKET, SO_RCVBUF), tiny)


def test_buffer_sizes_reject_negative() raises:
    var s = _tcp()
    var before = s.recv_buffer_size()
    var bad: List[Int] = [-1, Int(Int32.MAX) + 1]
    for v in bad:
        var raised = False
        var kind = ErrorKind.Other
        try:
            s.set_recv_buffer_size(v)
        except e:
            raised = True
            kind = e.kind
        _expect_invalid(kind, raised)
        raised = False
        kind = ErrorKind.Other
        try:
            s.set_send_buffer_size(v)
        except e:
            raised = True
            kind = e.kind
        _expect_invalid(kind, raised)
    assert_equal(s.recv_buffer_size(), before)


# ---- TCP integer options -----------------------------------------------------


def test_tcp_user_timeout_round_trip() raises:
    var s = _tcp()
    assert_false(Bool(s.tcp_user_timeout()))
    s.set_tcp_user_timeout(Duration.from_millis(12345))
    assert_equal(s.tcp_user_timeout().value(), Duration.from_millis(12345))
    s.set_tcp_user_timeout(Duration.from_secs(30))
    assert_equal(s.get_option_int(IPPROTO_TCP, TCP_USER_TIMEOUT), 30_000)
    # Rounded up to whole milliseconds.
    s.set_tcp_user_timeout(Duration.from_micros(1500))
    assert_equal(s.tcp_user_timeout().value(), Duration.from_millis(2))
    s.set_tcp_user_timeout(Duration.MAX)
    assert_equal(
        s.tcp_user_timeout().value(), Duration.from_millis(Int(Int32.MAX))
    )
    s.set_tcp_user_timeout(None)
    assert_false(Bool(s.tcp_user_timeout()))
    assert_equal(s.get_option_int(IPPROTO_TCP, TCP_USER_TIMEOUT), 0)
    # A zero timeout is not "the system default": rejected, nothing changed.
    s.set_tcp_user_timeout(Duration.from_secs(7))
    var raised = False
    var kind = ErrorKind.Other
    try:
        s.set_tcp_user_timeout(Duration.ZERO)
    except e:
        raised = True
        kind = e.kind
    _expect_invalid(kind, raised)
    assert_equal(s.tcp_user_timeout().value(), Duration.from_secs(7))


def test_notsent_lowat_round_trip() raises:
    var s = _tcp()
    s.set_notsent_lowat(16384)
    assert_equal(s.notsent_lowat(), 16384)
    s.set_notsent_lowat(1)
    assert_equal(s.notsent_lowat(), 1)
    var raised = False
    var kind = ErrorKind.Other
    try:
        s.set_notsent_lowat(-1)
    except e:
        raised = True
        kind = e.kind
    _expect_invalid(kind, raised)
    assert_equal(s.notsent_lowat(), 1)


def test_defer_accept_rounds_to_retransmit_schedule() raises:
    var l = _tcp()
    l.bind(SocketAddr.parse("127.0.0.1:0"))
    l.listen(4)
    assert_equal(l.defer_accept(), Duration.ZERO)
    # (set, read back) in seconds: the kernel keeps a SYN-ACK retransmit
    # count.
    var cases: List[Tuple[Int, Int]] = [
        (1, 1),
        (2, 3),
        (3, 3),
        (5, 7),
        (7, 7),
        (8, 15),
        (0, 0),
    ]
    for c in cases:
        l.set_defer_accept(Duration.from_secs(c[0]))
        assert_equal(
            l.defer_accept(), Duration.from_secs(c[1]), String("set ", c[0])
        )
    # Sub-second times round up to 1 s instead of disabling the option.
    l.set_defer_accept(Duration.from_millis(1))
    assert_equal(l.defer_accept(), Duration.from_secs(1))
    l.set_defer_accept(Duration.ZERO)
    assert_equal(l.defer_accept(), Duration.ZERO)


def test_fastopen_queue_length() raises:
    var l = _tcp()
    l.bind(SocketAddr.parse("127.0.0.1:0"))
    assert_equal(l.fastopen(), 0)
    l.set_fastopen(16)  # before listen
    assert_equal(l.fastopen(), 16)
    l.listen(8)
    l.set_fastopen(32)  # and on the listener
    assert_equal(l.fastopen(), 32)
    var raised = False
    var kind = ErrorKind.Other
    try:
        l.set_fastopen(-1)
    except e:
        raised = True
        kind = e.kind
    _expect_invalid(kind, raised)
    # A connected socket is neither CLOSE nor LISTEN: EINVAL.
    var tp = _tcp_pair()
    raised = False
    kind = ErrorKind.Other
    try:
        tp.first.value().set_fastopen(4)
    except e:
        raised = True
        kind = e.kind
    _expect_invalid(kind, raised)


# ---- SOL_SOCKET integers, privileged options ---------------------------------


def test_mark_tolerates_eperm() raises:
    var s = _tcp()
    assert_equal(s.mark(), 0)
    try:
        s.set_mark(0xDEADBEEF)
    except e:
        assert_equal(e.kind, ErrorKind.PermissionDenied)
        assert_equal(e.errno, Errno.EPERM)
        print("    note: test_mark_tolerates_eperm: EPERM path only")
        return
    # Privileged run: the full 32-bit value round trips (not sign-mangled).
    assert_equal(s.mark(), 0xDEADBEEF)


def test_bind_device() raises:
    var s = _tcp()
    assert_false(Bool(s.bind_device()))
    # Too long for IFNAMSIZ: rejected before the kernel.
    var raised = False
    var kind = ErrorKind.Other
    try:
        s.set_bind_device("a-very-long-ifname")
    except e:
        raised = True
        kind = e.kind
    _expect_invalid(kind, raised)
    # Unknown interface: NotFound (ENODEV), checked before privileges.
    kind = ErrorKind.Other
    try:
        s.set_bind_device("nosuchif0")
    except e:
        kind = e.kind
        assert_equal(e.errno, Errno.ENODEV)
    assert_equal(kind, ErrorKind.NotFound)
    try:
        s.set_bind_device("lo")
    except e:
        assert_equal(e.kind, ErrorKind.PermissionDenied)
        print("    note: test_bind_device: EPERM path only (not bound)")
        return
    assert_equal(s.bind_device().value(), "lo")
    try:
        s.set_bind_device("")
    except e:
        # Unbinding a bound socket needs CAP_NET_RAW.
        assert_equal(e.kind, ErrorKind.PermissionDenied)
        return
    assert_false(Bool(s.bind_device()))


def test_incoming_cpu_round_trip() raises:
    var s = _tcp()
    assert_equal(s.incoming_cpu(), -1)
    s.set_incoming_cpu(0)
    assert_equal(s.incoming_cpu(), 0)
    s.set_incoming_cpu(-1)
    assert_equal(s.incoming_cpu(), -1)
    var raised = False
    var kind = ErrorKind.Other
    try:
        s.set_incoming_cpu(Int(Int32.MAX) + 1)
    except e:
        raised = True
        kind = e.kind
    _expect_invalid(kind, raised)


# ---- IP / IPv6 ---------------------------------------------------------------


def test_tos_round_trip_and_tcp_ecn_bits() raises:
    var t = _tcp()
    assert_equal(t.tos(), 0)
    t.set_tos(0x10)  # IPTOS_LOWDELAY
    assert_equal(t.tos(), 0x10)
    # TCP owns the two ECN bits: they are dropped from the setting.
    t.set_tos(0xB9)
    assert_equal(t.tos(), 0xB8)
    var u = Socket.new(Domain.IPV4, SockType.DGRAM)
    u.set_tos(0xB9)
    assert_equal(u.tos(), 0xB9)
    var raised = False
    var kind = ErrorKind.Other
    try:
        t.set_tos(Int(1) << 33)
    except e:
        raised = True
        kind = e.kind
    _expect_invalid(kind, raised)


def test_tclass_v6_round_trip() raises:
    if not _ipv6("test_tclass_v6_round_trip", need_loopback=False):
        return
    var s = Socket.new(Domain.IPV6, SockType.DGRAM)
    s.set_tclass_v6(0x28)
    assert_equal(s.tclass_v6(), 0x28)
    s.set_tclass_v6(-1)  # back to the default
    assert_equal(s.tclass_v6(), 0)
    var raised = False
    var kind = ErrorKind.Other
    try:
        s.set_tclass_v6(256)
    except e:
        raised = True
        kind = e.kind
    _expect_invalid(kind, raised)  # kernel EINVAL


def test_ttl_round_trip_and_range() raises:
    var s = _tcp()
    var default_ttl = s.ttl()
    assert_true(default_ttl >= 1 and default_ttl <= 255)
    s.set_ttl(42)
    assert_equal(s.ttl(), 42)
    s.set_ttl(255)
    assert_equal(s.ttl(), 255)
    s.set_ttl(-1)  # route default again
    assert_equal(s.ttl(), default_ttl)
    var bad: List[Int] = [0, 256]
    for v in bad:
        var raised = False
        var kind = ErrorKind.Other
        try:
            s.set_ttl(v)
        except e:
            raised = True
            kind = e.kind
        _expect_invalid(kind, raised)


# ---- raw escape hatches ------------------------------------------------------


def test_raw_int_options() raises:
    var s = _tcp()
    s.set_option_int(SOL_SOCKET, SO_REUSEADDR, 1)
    assert_true(s.reuse_address())
    assert_equal(s.get_option_int(SOL_SOCKET, SO_REUSEADDR), 1)
    s.set_option_int(IPPROTO_TCP, TCP_NODELAY, 1)
    assert_true(s.nodelay())
    assert_equal(s.get_option_int(SOL_SOCKET, SO_TYPE), SOCK_STREAM)
    # Values beyond a C int would truncate: rejected.
    var raised = False
    var kind = ErrorKind.Other
    try:
        s.set_option_int(SOL_SOCKET, SO_REUSEADDR, Int(1) << 32)
    except e:
        raised = True
        kind = e.kind
    _expect_invalid(kind, raised)
    # Unknown option: ENOPROTOOPT.
    kind = ErrorKind.Other
    try:
        _ = s.get_option_int(SOL_SOCKET, 9999)
    except e:
        kind = e.kind
        assert_equal(e.errno, Errno.ENOPROTOOPT)
    assert_equal(kind, ErrorKind.Unsupported)


def test_raw_byte_options() raises:
    var s = Socket.new(Domain.IPV4, SockType.DGRAM)
    var buf = List[UInt8](length=4, fill=0xFF)
    assert_equal(s.get_option_bytes(SOL_SOCKET, SO_TYPE, Span(buf)), 4)
    var v = (
        Int(buf[0])
        | (Int(buf[1]) << 8)
        | (Int(buf[2]) << 16)
        | (Int(buf[3]) << 24)
    )
    assert_equal(v, SOCK_DGRAM)
    var one = List[UInt8](length=4, fill=0)
    one[0] = 1
    s.set_option_bytes(SOL_SOCKET, SO_REUSEADDR, Span(one))
    assert_true(s.reuse_address())
    # Too short for an int option: EINVAL.
    var raised = False
    var kind = ErrorKind.Other
    try:
        s.set_option_bytes(SOL_SOCKET, SO_REUSEADDR, Span(one)[0:2])
    except e:
        raised = True
        kind = e.kind
    _expect_invalid(kind, raised)
    # An empty value is passed through (SO_BINDTODEVICE: unbind).
    s.set_option_bytes(SOL_SOCKET, 25, List[UInt8]())  # SO_BINDTODEVICE
    assert_false(Bool(s.bind_device()))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
