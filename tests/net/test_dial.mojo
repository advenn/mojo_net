"""`net.dial` / `TcpStream.connect_host`: `HostPort` parsing, literals,
Happy Eyeballs v2 (a refused address moves on at once, a black-holed one
after the attempt delay, IPv4 waits only the resolution delay for a slow
AAAA, late answers join the race), the shared deadline, error choice, and
lookup failures.

A black hole is a loopback listener whose accept queue is full: Linux drops
the SYNs of further connections, so their connect hangs."""

from std.os import listdir
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError, sys
from linux.time import Deadline, Duration, Instant
from net.addr import SocketAddr
from net.dial import ATTEMPT_DELAY, HostPort, dial_tcp
from net.resolv import Hosts, ResolvConf
from net.resolver import Resolver
from net.socket import Domain, SockType, Socket
from net.tcp import TcpListener, TcpStream
from fake_dns import FakeDns


def _secs(s: Int) -> Deadline:
    return Deadline.after(Duration.from_secs(s))


def _ipv6_loopback() -> Bool:
    try:
        _ = TcpListener.bind(SocketAddr.parse("[::1]:0"))
        return True
    except:
        return False


struct _BlackHole(Movable):
    """A listener on `addr` whose accept queue is full, plus the stuck
    connections that fill it."""

    var listener: TcpListener
    var fillers: List[Socket]

    def __init__(out self, addr: SocketAddr) raises:
        self.listener = TcpListener.bind(addr, backlog=0)
        self.fillers = List[Socket]()
        var target = self.listener.local_addr().to_raw()
        for _ in range(3):
            var s = Socket.new(Domain.IPV4, SockType.STREAM, nonblocking=True)
            _ = sys.connect(s, target.storage, target.socklen())
            self.fillers.append(s^)
        # Let the handshakes that fit complete.
        var t = Instant.now()
        while t.elapsed() < Duration.from_millis(50):
            pass

    def port(self) raises -> UInt16:
        return self.listener.local_addr().port()

    def stop(deinit self):
        pass


def _resolver_with(hosts: StringSlice) raises -> Resolver:
    var c = ResolvConf()
    c.nameservers.append(SocketAddr.parse("127.0.0.1:9"))
    return Resolver(c^, Hosts.parse(hosts))


# ---- host:port ---------------------------------------------------------------


def test_host_port_parse() raises:
    var hp = HostPort.parse("db.internal:5432")
    assert_equal(hp.host, "db.internal")
    assert_equal(Int(hp.port), 5432)
    var v6 = HostPort.parse("[::1]:443")
    assert_equal(v6.host, "::1")
    assert_equal(String(v6), "[::1]:443")
    assert_equal(String(HostPort.parse("127.0.0.1:0")), "127.0.0.1:0")
    var bad: List[String] = ["", "host", "host:", ":80", "::1:80", "[::1]", "[::1]80", "[::1]:", "h:65536", "h:8x", "h:123456", "[]:80"]
    for b in bad:
        var kind = String()
        try:
            _ = HostPort.parse(b)
        except e:
            kind = String(e.kind)
        assert_equal(kind, "InvalidInput", b)


# ---- literals and localhost --------------------------------------------------


def test_literals_connect_directly() raises:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = l.local_addr().port()
    var s = TcpStream.connect_host("127.0.0.1", port, Duration.from_secs(5))
    assert_equal(String(s.peer_addr()), String("127.0.0.1:", port))
    assert_true(s.socket().nodelay())
    if _ipv6_loopback():
        var l6 = TcpListener.bind(SocketAddr.parse("[::1]:0"))
        var p6 = l6.local_addr().port()
        _ = TcpStream.connect_host("::1", p6, Duration.from_secs(5))
        _ = TcpStream.connect_host("[::1]", p6, Duration.from_secs(5))
        sys.keep_alive(l6)
    var d = TcpStream.connect_host_deadline("127.0.0.1", port, _secs(5))
    assert_equal(String(d.peer_addr()), String("127.0.0.1:", port))
    var h = TcpStream.connect_host_deadline("localhost", port, _secs(5))
    assert_equal(String(h.peer_addr()), String("127.0.0.1:", port))
    var kind = String()
    try:
        _ = TcpStream.connect_host("127.0.0.1", port, Duration.ZERO)
    except e:
        kind = String(e.kind)
    assert_equal(kind, "InvalidInput")
    sys.keep_alive(l)


def test_localhost_falls_back_to_ipv4_at_once() raises:
    # The listener is IPv4 only: ::1 is refused (or IPv6 is off) and the
    # 127.0.0.1 attempt starts without waiting for the attempt delay.
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = l.local_addr().port()
    var t = Instant.now()
    var s = TcpStream.connect_host("localhost", port, Duration.from_secs(5))
    assert_true(t.elapsed() < Duration.from_millis(100))
    assert_equal(String(s.peer_addr()), String("127.0.0.1:", port))


# ---- racing ------------------------------------------------------------------
    sys.keep_alive(l)


def test_black_hole_costs_one_attempt_delay() raises:
    var live = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = live.local_addr().port()
    var hole = _BlackHole(SocketAddr.parse(String("127.0.0.2:", port)))
    var r = _resolver_with("127.0.0.2 he.test\n127.0.0.1 he.test\n")
    var t = Instant.now()
    var s = TcpStream.connect_host_deadline("he.test", port, _secs(5), r)
    var took = t.elapsed()
    assert_equal(String(s.peer_addr()), String("127.0.0.1:", port))
    assert_true(took >= ATTEMPT_DELAY - Duration.from_millis(10))
    assert_true(took < Duration.from_millis(700))
    sys.keep_alive(live)
    hole^.stop()


def test_refused_address_moves_on_at_once() raises:
    var live = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = live.local_addr().port()
    # Nothing listens on 127.0.0.2 at this port: an immediate RST.
    var r = _resolver_with("127.0.0.2 re.test\n127.0.0.1 re.test\n")
    var t = Instant.now()
    var s = TcpStream.connect_host_deadline("re.test", port, _secs(5), r)
    assert_true(t.elapsed() < Duration.from_millis(100))
    assert_equal(String(s.peer_addr()), String("127.0.0.1:", port))
    sys.keep_alive(live)


def test_a_failure_starts_the_next_attempt_while_others_run() raises:
    # hole (hangs) -> at 250 ms a refused address fails at once -> the live
    # one starts right away instead of 250 ms later.
    var live = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = live.local_addr().port()
    var hole = _BlackHole(SocketAddr.parse(String("127.0.0.2:", port)))
    var r = _resolver_with("127.0.0.2 k.test\n127.0.0.3 k.test\n127.0.0.1 k.test\n")
    var t = Instant.now()
    var s = TcpStream.connect_host_deadline("k.test", port, _secs(5), r)
    var took = t.elapsed()
    assert_equal(String(s.peer_addr()), String("127.0.0.1:", port))
    assert_true(took >= ATTEMPT_DELAY - Duration.from_millis(10))
    assert_true(took < Duration.from_millis(450))
    sys.keep_alive(live)
    hole^.stop()


def test_ipv6_goes_first_when_both_connect() raises:
    if not _ipv6_loopback():
        print("    (skipped: test_ipv6_goes_first_when_both_connect: no IPv6 loopback)")
        return
    var l4 = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = l4.local_addr().port()
    var l6 = TcpListener.bind(SocketAddr.parse(String("[::1]:", port)))
    var r = _resolver_with("127.0.0.1 both.test\n::1 both.test\n")
    var s = TcpStream.connect_host_deadline("both.test", port, _secs(5), r)
    assert_equal(String(s.peer_addr()), String("[::1]:", port))
    sys.keep_alive(l4)
    sys.keep_alive(l6)


def test_every_address_refused_is_connection_refused() raises:
    var probe = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = probe.local_addr().port()
    probe^.close()
    var r = _resolver_with("127.0.0.2 no.test\n127.0.0.3 no.test\n")
    var kind = String()
    var op = String()
    try:
        _ = TcpStream.connect_host_deadline("no.test", port, _secs(5), r)
    except e:
        kind = String(e.kind)
        op = String(e.op)
    assert_equal(kind, "ConnectionRefused")
    assert_equal(op, "connect")


def test_deadline_covers_the_whole_race() raises:
    var hole = _BlackHole(SocketAddr.parse("127.0.0.2:0"))
    var port = hole.port()
    var r = _resolver_with("127.0.0.2 hole.test\n")
    var t = Instant.now()
    var expired = False
    try:
        _ = TcpStream.connect_host_deadline(
            "hole.test", port, Deadline.after(Duration.from_millis(300)), r
        )
    except e:
        expired = e.is_deadline()
    var took = t.elapsed()
    assert_true(expired)
    assert_true(took >= Duration.from_millis(290) and took < Duration.from_millis(600))
    hole^.stop()


# ---- with DNS ----------------------------------------------------------------


def test_dns_names_connect() raises:
    var dns = FakeDns()
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = l.local_addr().port()
    var r = dns.resolver()
    var s = TcpStream.connect_host_deadline("loop.test", port, _secs(5), r)
    assert_equal(String(s.peer_addr()), String("127.0.0.1:", port))
    sys.keep_alive(l)
    dns^.stop()


def test_slow_aaaa_costs_only_the_resolution_delay() raises:
    # A answers at once, AAAA after 2 s: IPv4 starts after ~50 ms.
    var dns = FakeDns()
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = l.local_addr().port()
    var r = dns.resolver(timeout_secs=5)
    var t = Instant.now()
    var s = TcpStream.connect_host_deadline("slowaaaa.test", port, _secs(5), r)
    var took = t.elapsed()
    assert_equal(String(s.peer_addr()), String("127.0.0.1:", port))
    assert_true(took >= Duration.from_millis(45) and took < Duration.from_millis(500))
    sys.keep_alive(l)
    dns^.stop()


def test_late_answers_join_the_race() raises:
    # AAAA (::1) answers at once but is refused; A (127.0.0.1) arrives
    # after 0.3 s and wins.
    var dns = FakeDns()
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = l.local_addr().port()
    var r = dns.resolver(timeout_secs=5)
    var t = Instant.now()
    var s = TcpStream.connect_host_deadline("slowa.test", port, _secs(5), r)
    var took = t.elapsed()
    assert_equal(String(s.peer_addr()), String("127.0.0.1:", port))
    assert_true(took >= Duration.from_millis(280) and took < Duration.from_millis(900))
    sys.keep_alive(l)
    dns^.stop()


def test_lookup_failures_are_resolve_errors() raises:
    var dns = FakeDns()
    var r = dns.resolver()
    var kind = String()
    var op = String()
    try:
        _ = TcpStream.connect_host_deadline("nx.test", 80, _secs(5), r)
    except e:
        kind = String(e.kind)
        op = String(e.op)
    assert_equal(kind, "NotFound")
    assert_equal(op, "resolve")
    dns^.stop()


def _fd_count() raises -> Int:
    return len(listdir("/proc/self/fd"))


def _attempt_kind(
    host: StringSlice, port: UInt16, deadline: Deadline, r: Resolver
) -> String:
    try:
        _ = TcpStream.connect_host_deadline(host, port, deadline, r)
        return "ok"
    except e:
        return String(e.kind)


def test_no_descriptor_leaks() raises:
    # Every path closes what it opened: success through DNS, a refused
    # address before a live one, NXDOMAIN, TC then TCP, a silent server
    # hitting the deadline, and a black hole hitting it.
    var dns = FakeDns()
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = l.local_addr().port()
    var hole = _BlackHole(SocketAddr.parse("127.0.0.2:0"))
    var hole_port = hole.port()
    var r = dns.resolver()
    var hosts = _resolver_with(
        "127.0.0.2 re.test\n127.0.0.1 re.test\n127.0.0.2 hole.test\n"
    )
    var before = -1
    for round in range(31):
        if round == 1:
            before = _fd_count()  # after one warm-up round
        assert_equal(_attempt_kind("loop.test", port, _secs(5), r), "ok")
        _ = l.accept()
        assert_equal(_attempt_kind("re.test", port, _secs(5), hosts), "ok")
        _ = l.accept()
        assert_equal(_attempt_kind("nx.test", port, _secs(5), r), "NotFound")
        _ = r.lookup_ip("big.test", _secs(5))
        var quick = Deadline.after(Duration.from_millis(30))
        assert_equal(_attempt_kind("drop.test", port, quick, r), "TimedOut")
        var short = Deadline.after(Duration.from_millis(30))
        assert_equal(_attempt_kind("hole.test", hole_port, short, hosts), "TimedOut")
    assert_equal(_fd_count(), before)
    sys.keep_alive(l)
    hole^.stop()
    dns^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
