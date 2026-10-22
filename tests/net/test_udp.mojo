"""`net.udp.UdpSocket`: datagram semantics (whole datagrams, reported
truncation, empty datagrams, peeking sizes), the blocking mode with
deadlines, the nonblocking `try_*` mode (and an edge-triggered loop),
connected sockets (filtering, ICMP refusals), dual-stack senders, adoption
and options."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Epoll, ErrorKind, IoError, sys
from linux.abi import EpollEvent
from linux.consts import EPOLLET, EPOLLIN
from linux.time import Deadline, Duration, Instant
from net.addr import SocketAddr
from net.resolv import Hosts, ResolvConf
from net.resolver import Resolver
from net.socket import Domain, SockType, Socket
from net.udp import Datagram, UdpSocket


def _guard() -> Deadline:
    return Deadline.after(Duration.from_secs(10))


def _bytes(n: Int, fill: Int = 7) -> List[UInt8]:
    return List[UInt8](length=n, fill=UInt8(fill))


def _bound(addr: StringSlice = "127.0.0.1:0") raises -> UdpSocket:
    var s = UdpSocket.bind(SocketAddr.parse(addr))
    s.set_deadline(_guard())
    return s^


def _ipv6_loopback() -> Bool:
    try:
        _ = UdpSocket.bind(SocketAddr.parse("[::1]:0"))
        return True
    except:
        return False


def _kind_of_recv(s: UdpSocket, mut buf: List[UInt8]) -> String:
    try:
        _ = s.recv(Span(buf))
        return "ok"
    except e:
        return String(e.kind)


# ---- datagram semantics ------------------------------------------------------


def test_round_trip_and_sender() raises:
    var a = _bound()
    var b = _bound()
    assert_equal(a.send_to(String("ping").as_bytes(), b.local_addr()), 4)
    var buf = _bytes(64, 0)
    var d = b.recv_from(Span(buf))
    assert_equal(d.len, 4)
    assert_false(d.truncated())
    assert_equal(d.sender, a.local_addr())
    assert_equal(String(from_utf8_lossy=Span(buf)[0:4]), "ping")
    _ = b.send_to(Span(buf)[0 : d.len], d.sender)
    assert_equal(a.recv_from(Span(buf)).len, 4)


def test_round_trip_ipv6() raises:
    if not _ipv6_loopback():
        print("    (skipped: test_round_trip_ipv6: no IPv6 loopback)")
        return
    var a = _bound("[::1]:0")
    var b = _bound("[::1]:0")
    _ = a.send_to(String("v6").as_bytes(), b.local_addr())
    var buf = _bytes(8, 0)
    var d = b.recv_from(Span(buf))
    assert_equal(d.len, 2)
    assert_equal(d.sender, a.local_addr())


def test_truncation_is_reported_and_the_rest_dropped() raises:
    var a = _bound()
    var b = _bound()
    _ = a.send_to(Span(_bytes(100, 1)), b.local_addr())
    _ = a.send_to(Span(_bytes(3, 2)), b.local_addr())
    var small = _bytes(10, 0)
    var d = b.recv_from(Span(small))
    assert_equal(d.len, 10)
    assert_equal(d.size, 100)
    assert_true(d.truncated())
    var next = b.recv_from(Span(small))  # the next datagram, intact
    assert_equal(next.len, 3)
    assert_false(next.truncated())
    assert_equal(Int(small[0]), 2)


def test_empty_datagram_is_not_eof() raises:
    var a = _bound()
    var b = _bound()
    _ = a.send_to(Span(List[UInt8]()), b.local_addr())
    _ = a.send_to(String("after").as_bytes(), b.local_addr())
    var buf = _bytes(16, 0)
    var d = b.recv_from(Span(buf))
    assert_equal(d.len, 0)
    assert_equal(d.size, 0)
    assert_equal(b.recv_from(Span(buf)).len, 5)


def test_peek_reads_the_size_and_leaves_the_datagram() raises:
    var a = _bound()
    var b = _bound()
    _ = a.send_to(Span(_bytes(1234, 3)), b.local_addr())
    var none = List[UInt8]()
    var p = b.peek_from(Span(none))  # size only, nothing copied
    assert_equal(p.size, 1234)
    assert_equal(p.len, 0)
    var buf = _bytes(p.size, 0)
    var d = b.recv_from(Span(buf))
    assert_equal(d.len, 1234)
    assert_false(d.truncated())


def test_too_big_datagram_raises() raises:
    var a = _bound()
    var b = _bound()
    var kind = String()
    var errno = 0
    try:
        _ = a.send_to(Span(_bytes(70000)), b.local_addr())
    except e:
        kind = String(e.kind)
        errno = Int(e.errno.value)
    assert_true(kind.byte_length() > 0)
    assert_equal(errno, 90)  # EMSGSIZE


# ---- blocking mode -----------------------------------------------------------


def test_deadline_expiry_leaves_the_socket_usable() raises:
    var a = _bound()
    var b = _bound()
    b.set_read_deadline(Deadline.after(Duration.from_millis(50)))
    var buf = _bytes(16, 0)
    var expired = False
    var t = Instant.now()
    try:
        _ = b.recv_from(Span(buf))
    except e:
        expired = e.is_deadline()
    assert_true(expired)
    assert_true(t.elapsed() >= Duration.from_millis(45))
    _ = a.send_to(String("late").as_bytes(), b.local_addr())
    b.set_read_deadline(_guard())
    assert_equal(b.recv_from(Span(buf)).len, 4)


def test_queued_datagram_beats_an_expired_deadline() raises:
    var a = _bound()
    var b = _bound()
    _ = a.send_to(String("x").as_bytes(), b.local_addr())
    var t = Instant.now()
    while t.elapsed() < Duration.from_millis(20):
        pass  # let loopback deliver
    b.set_read_deadline(Deadline.after(Duration.ZERO))
    var buf = _bytes(4, 0)
    assert_equal(b.recv_from(Span(buf)).len, 1)


# ---- nonblocking mode --------------------------------------------------------


def test_try_calls_never_wait() raises:
    var a = _bound()
    var b = _bound()
    var buf = _bytes(16, 0)
    assert_false(b.try_recv_from(Span(buf)))
    assert_false(b.try_peek_from(Span(buf)))
    assert_equal(a.try_send_to(String("now").as_bytes(), b.local_addr()).value(), 3)
    var t = Instant.now()
    var got: Optional[Datagram] = None
    while not got and t.elapsed() < Duration.from_secs(2):
        got = b.try_recv_from(Span(buf))
    assert_equal(got.value().len, 3)
    assert_false(b.try_recv_from(Span(buf)))


def test_edge_triggered_loop_drains_every_datagram() raises:
    var a = _bound()
    var b = _bound()
    var ep = Epoll.new()
    ep.add(b, UInt32(EPOLLIN | EPOLLET), 1)
    for i in range(5):
        _ = a.send_to(Span(_bytes(i + 1, i)), b.local_addr())
    var sizes = List[Int]()
    var events = List[EpollEvent](capacity=4)
    var t = Instant.now()
    var buf = _bytes(16, 0)
    while len(sizes) < 5 and t.elapsed() < Duration.from_secs(2):
        _ = ep.wait(events, Optional(Duration.from_millis(100)))
        while True:
            var d = b.try_recv_from(Span(buf))
            if not d:
                break
            sizes.append(d.value().len)
    assert_equal(len(sizes), 5)
    for i in range(5):
        assert_equal(sizes[i], i + 1)  # loopback keeps order
    ep.delete(b)


# ---- connected sockets -------------------------------------------------------


def test_connected_socket_hears_only_its_peer() raises:
    var b = _bound()
    var c = _bound()
    var stranger = _bound()
    c.connect(b.local_addr())
    assert_equal(c.peer_addr(), b.local_addr())
    _ = stranger.send_to(String("noise").as_bytes(), c.local_addr())
    _ = b.send_to(String("peer").as_bytes(), c.local_addr())
    var buf = _bytes(16, 0)
    var d = c.recv(Span(buf))
    assert_equal(String(from_utf8_lossy=Span(buf)[0 : d.len]), "peer")
    assert_equal(c.send(String("back").as_bytes()), 4)
    assert_equal(b.recv_from(Span(buf)).len, 4)


def test_connected_socket_reports_icmp_refusal() raises:
    var gone = _bound()
    var closed = gone.local_addr()
    gone^.close()
    var c = _bound()
    c.connect(closed)
    _ = c.send(String("anyone?").as_bytes())
    var buf = _bytes(16, 0)
    assert_equal(_kind_of_recv(c, buf), "ConnectionRefused")


def test_send_without_a_peer_raises() raises:
    var a = _bound()
    var raised = False
    try:
        _ = a.send(String("to whom").as_bytes())
    except e:
        raised = Int(e.errno.value) == 89  # EDESTADDRREQ
    assert_true(raised)


# ---- dual stack, adoption, options -------------------------------------------


def test_dual_stack_reports_ipv4_senders_mapped() raises:
    if not _ipv6_loopback():
        print("    (skipped: test_dual_stack_reports_ipv4_senders_mapped: no IPv6)")
        return
    var raw = Socket.new(Domain.IPV6, SockType.DGRAM)
    raw.set_only_v6(False)
    raw.bind(SocketAddr.parse("[::]:0"))
    var b = UdpSocket.from_socket(raw^)
    b.set_deadline(_guard())
    var a = _bound()
    var port = b.local_addr().port()
    _ = a.send_to(String("v4").as_bytes(), SocketAddr.parse(String("127.0.0.1:", port)))
    var buf = _bytes(8, 0)
    var d = b.recv_from(Span(buf))
    assert_true(d.sender.is_ipv6())
    assert_equal(String(d.sender.ip().to_canonical()), "127.0.0.1")


def test_from_socket_checks_and_prepares() raises:
    var tcp = Socket.new(Domain.IPV4, SockType.STREAM)
    var kind = String()
    try:
        _ = UdpSocket.from_socket(tcp^)
    except e:
        kind = String(e.kind)
    assert_equal(kind, "InvalidInput")
    var blocking = Socket.new(Domain.IPV4, SockType.DGRAM)
    blocking.bind(SocketAddr.parse("127.0.0.1:0"))
    var u = UdpSocket.from_socket(blocking^)
    assert_true(u.socket().nonblocking())
    var buf = _bytes(4, 0)
    assert_false(u.try_recv_from(Span(buf)))  # does not block


def test_options() raises:
    var a = _bound()
    assert_false(a.broadcast())
    a.set_broadcast(True)
    assert_true(a.broadcast())
    var x = UdpSocket.bind_reuseport(SocketAddr.parse("127.0.0.1:0"))
    var y = UdpSocket.bind_reuseport(x.local_addr())
    assert_equal(y.local_addr(), x.local_addr())
    var kind = String()
    try:
        _ = UdpSocket.bind(x.local_addr())
    except e:
        kind = String(e.kind)
    assert_equal(kind, "AddrInUse")
    var c = a.try_clone()
    assert_equal(c.local_addr(), a.local_addr())
    sys.keep_alive(x)  # both must still be bound for the AddrInUse check
    sys.keep_alive(y)


def test_connect_host_by_literal_and_name() raises:
    var srv = _bound()
    var port = srv.local_addr().port()
    var lit = UdpSocket.connect_host("127.0.0.1", port, Duration.from_secs(2))
    assert_equal(lit.peer_addr(), srv.local_addr())
    var c = ResolvConf()
    c.nameservers.append(SocketAddr.parse("127.0.0.1:9"))  # never asked
    var r = Resolver(c^, Hosts.parse("127.0.0.1 echo.test\n"))
    var named = UdpSocket.connect_host_deadline("echo.test", port, _guard(), r)
    named.set_deadline(_guard())
    assert_equal(named.peer_addr(), srv.local_addr())
    _ = named.send(String("hi").as_bytes())
    var buf = _bytes(8, 0)
    var d = srv.recv_from(Span(buf))
    assert_equal(d.sender, named.local_addr())
    var kind = String()
    try:
        _ = UdpSocket.connect_host_deadline("missing.test", port, _guard(), r)
    except e:
        kind = String(e.kind)
    assert_true(kind == "NotFound" or kind == "TimedOut" or kind == "Other")
    var zero = String()
    try:
        _ = UdpSocket.connect_host("127.0.0.1", port, Duration.ZERO)
    except e:
        zero = String(e.kind)
    assert_equal(zero, "InvalidInput")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
