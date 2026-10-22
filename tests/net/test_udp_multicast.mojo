"""`UdpSocket` multicast: IPv4 delivery over loopback, leaving a group,
Linux's IP_MULTICAST_ALL default (a wildcard-bound socket hears every
group joined on its port) and how to turn it off, the TTL / loop / ALL
options, invalid groups, and IPv6 membership and options (delivery only
where the host routes IPv6 multicast)."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError, sys
from linux.time import Deadline, Duration, Instant
from net.addr import Ipv4Addr, Ipv6Addr, SocketAddr, if_nametoindex
from net.socket import Domain, SockType, Socket
from net.udp import Datagram, UdpSocket

comptime GROUP4 = "239.255.42.99"
comptime GROUP6 = "ff12::4242"


def _lo4() -> Ipv4Addr:
    return Ipv4Addr(127, 0, 0, 1)


def _receiver(port: Int = 0, reuse: Bool = False) raises -> UdpSocket:
    var s = Socket.new(Domain.IPV4, SockType.DGRAM)
    s.set_reuse_address(reuse)
    s.bind(SocketAddr.parse(String("0.0.0.0:", port)))
    return UdpSocket.from_socket(s^)


def _sender() raises -> UdpSocket:
    var s = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
    s.set_multicast_if_v4(_lo4())
    return s^


def _got_within(s: UdpSocket, ms: Int) raises -> Int:
    """Datagrams received within `ms` milliseconds."""
    var buf = List[UInt8](length=64, fill=0)
    var n = 0
    var t = Instant.now()
    while t.elapsed() < Duration.from_millis(ms):
        if s.try_recv_from(Span(buf)):
            n += 1
    return n


def test_ipv4_group_delivery_and_leave() raises:
    var r = _receiver()
    var port = r.local_addr().port()
    var group = Ipv4Addr.parse(GROUP4)
    r.join_multicast_v4(group, _lo4())
    var s = _sender()
    var dest = SocketAddr.parse(String(GROUP4, ":", port))
    _ = s.send_to(String("one").as_bytes(), dest)
    r.set_read_deadline(Deadline.after(Duration.from_secs(5)))
    var buf = List[UInt8](length=16, fill=0)
    var d = r.recv_from(Span(buf))
    assert_equal(String(from_utf8_lossy=Span(buf)[0 : d.len]), "one")
    assert_equal(d.sender, s.local_addr())
    r.leave_multicast_v4(group, _lo4())
    _ = s.send_to(String("two").as_bytes(), dest)
    assert_equal(_got_within(r, 100), 0)


def test_multicast_all_default_and_off() raises:
    # Two wildcard-bound sockets share a port; only `a` joins the group.
    var a = _receiver(reuse=True)
    var port = a.local_addr().port()
    var b = _receiver(Int(port), reuse=True)
    a.join_multicast_v4(Ipv4Addr.parse(GROUP4), _lo4())
    var s = _sender()
    var dest = SocketAddr.parse(String(GROUP4, ":", port))
    assert_true(b.socket().multicast_all_v4())  # Linux's default
    _ = s.send_to(String("all").as_bytes(), dest)
    assert_equal(_got_within(a, 100), 1)
    assert_equal(_got_within(b, 100), 1)  # b hears a's group
    b.socket().set_multicast_all_v4(False)
    _ = s.send_to(String("own").as_bytes(), dest)
    assert_equal(_got_within(a, 100), 1)
    assert_equal(_got_within(b, 100), 0)


def test_ipv4_options_and_errors() raises:
    var s = _sender()
    assert_equal(s.socket().multicast_ttl_v4(), 1)  # the default
    s.set_multicast_ttl_v4(5)
    assert_equal(s.socket().multicast_ttl_v4(), 5)
    assert_true(s.socket().multicast_loop_v4())
    s.set_multicast_loop_v4(False)
    assert_false(s.socket().multicast_loop_v4())
    var kinds = List[String]()
    try:
        s.set_multicast_ttl_v4(256)
    except e:
        kinds.append(String(e.kind))
    var r = _receiver()
    try:
        r.join_multicast_v4(Ipv4Addr(10, 0, 0, 1), _lo4())  # not a group
    except e:
        kinds.append(String(e.kind))
    r.join_multicast_v4(Ipv4Addr.parse(GROUP4), _lo4())
    try:
        r.join_multicast_v4(Ipv4Addr.parse(GROUP4), _lo4())  # twice
    except e:
        kinds.append(String(e.kind))
    assert_equal(len(kinds), 3)
    assert_equal(kinds[0], "InvalidInput")
    assert_equal(kinds[1], "InvalidInput")
    assert_equal(kinds[2], "AddrInUse")


def test_ipv6_membership_options_and_delivery() raises:
    var r: UdpSocket
    try:
        r = UdpSocket.bind(SocketAddr.parse("[::]:0"))
    except:
        print("    (skipped: test_ipv6_membership_options_and_delivery: no IPv6)")
        return
    var lo = if_nametoindex("lo")
    var group = Ipv6Addr.parse(GROUP6)
    r.join_multicast_v6(group, lo)
    var s = UdpSocket.bind(SocketAddr.parse("[::1]:0"))
    s.set_multicast_hops_v6(3)
    assert_equal(s.socket().multicast_hops_v6(), 3)
    s.set_multicast_loop_v6(False)
    assert_false(s.socket().multicast_loop_v6())
    s.set_multicast_loop_v6(True)
    s.set_multicast_if_v6(lo)
    assert_equal(s.socket().multicast_if_v6(), lo)
    s.socket().set_unicast_hops_v6(7)
    assert_equal(s.socket().unicast_hops_v6(), 7)
    var port = r.local_addr().port()
    var routed = True
    try:
        _ = s.send_to(String("six").as_bytes(), SocketAddr.parse(String("[", GROUP6, "]:", port)))
    except e:
        routed = False  # no IPv6 multicast route on this host
    if routed:
        r.set_read_deadline(Deadline.after(Duration.from_secs(5)))
        var buf = List[UInt8](length=8, fill=0)
        assert_equal(r.recv_from(Span(buf)).len, 3)
    else:
        print("    note: IPv6 multicast is not routed on this host; membership and options checked, delivery not")
    r.leave_multicast_v6(group, lo)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
