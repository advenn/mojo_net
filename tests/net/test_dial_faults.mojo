"""The resolver and Happy Eyeballs through the syscall fault seam (built
with -D MOJO_NET_FAULTS=1 because of the `_faults.mojo` suffix): EINTR,
spurious EAGAIN and injected ICMP refusals in the DNS exchange, EINTR and
unreachable networks on connect, and EMFILE, which must raise instead of
being taken for a failed server or address."""

from std.testing import TestSuite, assert_equal, assert_true

from linux import Errno, ErrorKind, IoError, fault, sys
from linux.nr import SYS_connect, SYS_recvfrom, SYS_sendto, SYS_socket
from linux.time import Deadline, Duration, Instant
from net.addr import IpAddr, SocketAddr
from net.resolv import Hosts, ResolvConf
from net.resolver import Resolver
from net.tcp import TcpListener, TcpStream
from fake_dns import FakeDns


def _secs(s: Int) -> Deadline:
    return Deadline.after(Duration.from_secs(s))


def _set(ips: List[IpAddr]) -> String:
    var texts = List[String]()
    for ip in ips:
        texts.append(String(ip))
    sort(texts)
    var out = String()
    for i in range(len(texts)):
        if i > 0:
            out += " "
        out += texts[i]
    return out


def _hosts_resolver(table: StringSlice) raises -> Resolver:
    var c = ResolvConf()
    c.nameservers.append(SocketAddr.parse("127.0.0.1:9"))
    return Resolver(c^, Hosts.parse(table))


def test_lookup_retries_eintr_without_failing_over() raises:
    fault.clear()
    var dns = FakeDns()
    var r = dns.resolver()
    fault.clear()
    fault.inject(SYS_recvfrom, Errno.EINTR, times=3)
    fault.inject(SYS_sendto, Errno.EINTR, times=2)
    var got = _set(r.lookup_ip("ok.test", _secs(5)))
    fault.clear()
    assert_equal(got, "192.0.2.1 2001:db8::1")
    assert_equal(dns.count(1, "ok.test"), 0)  # server 0 answered both
    dns^.stop()


def test_lookup_waits_through_spurious_eagain() raises:
    fault.clear()
    var dns = FakeDns()
    var r = dns.resolver()
    fault.clear()
    fault.inject(SYS_recvfrom, Errno.EAGAIN, times=2)
    var got = _set(r.lookup_ip("ok.test", _secs(5)))
    fault.clear()
    assert_equal(got, "192.0.2.1 2001:db8::1")
    dns^.stop()


def test_injected_icmp_refusal_moves_to_the_next_server() raises:
    fault.clear()
    var dns = FakeDns()
    var r = dns.resolver(timeout_secs=5)
    fault.clear()
    fault.inject(SYS_recvfrom, Errno.ECONNREFUSED, times=1)
    var t = Instant.now()
    var got = _set(r.lookup_ip("ok.test", _secs(10)))
    fault.clear()
    assert_equal(got, "192.0.2.1 2001:db8::1")
    assert_true(t.elapsed() < Duration.from_secs(2))  # no timeout waited
    assert_true(dns.count(1, "ok.test") >= 1)
    dns^.stop()


def test_emfile_in_a_lookup_raises() raises:
    fault.clear()
    var dns = FakeDns()
    var r = dns.resolver()
    fault.clear()
    fault.inject(SYS_socket, Errno.EMFILE, times=1)
    var kind = String()
    try:
        _ = r.lookup_ip("ok.test", _secs(5))
    except e:
        kind = String(e.kind)
    fault.clear()
    assert_equal(kind, "TooManyFiles")
    dns^.stop()


def test_dial_never_reissues_a_connect_after_eintr() raises:
    # EINTR counts as "in progress", so connect is never issued twice for an
    # address. An injected EINTR is a connect that never started (the seam
    # skips the syscall): the attempt must end with NotConnected, not pass
    # for connected because the socket polls writable, and the next
    # address still gets its turn.
    fault.clear()
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = l.local_addr().port()
    var only = _hosts_resolver("127.0.0.1 eintr.test\n")
    fault.clear()
    fault.inject(SYS_connect, Errno.EINTR, times=1)
    var kind = String()
    try:
        _ = TcpStream.connect_host_deadline("eintr.test", port, _secs(5), only)
    except e:
        kind = String(e.kind)
    var connects = fault.calls(SYS_connect)
    fault.clear()
    assert_equal(kind, "NotConnected")
    assert_equal(connects, 1)
    var two = _hosts_resolver("127.0.0.1 eintr2.test\n127.0.0.1 eintr2.test\n")
    fault.inject(SYS_connect, Errno.EINTR, times=1)
    var s = TcpStream.connect_host_deadline("eintr2.test", port, _secs(5), two)
    var connects2 = fault.calls(SYS_connect)
    fault.clear()
    assert_equal(String(s.peer_addr()), String("127.0.0.1:", port))
    assert_equal(connects2, 2)  # one per address
    sys.keep_alive(l)


def test_dial_moves_past_an_unreachable_address_at_once() raises:
    fault.clear()
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = l.local_addr().port()
    var r = _hosts_resolver("127.0.0.2 un.test\n127.0.0.1 un.test\n")
    fault.clear()
    fault.inject(SYS_connect, Errno.ENETUNREACH, times=1)
    var t = Instant.now()
    var s = TcpStream.connect_host_deadline("un.test", port, _secs(5), r)
    var took = t.elapsed()
    fault.clear()
    assert_equal(String(s.peer_addr()), String("127.0.0.1:", port))
    assert_true(took < Duration.from_millis(100))
    # With nothing else to try, the error surfaces.
    var only = _hosts_resolver("127.0.0.1 one.test\n")
    fault.inject(SYS_connect, Errno.ENETUNREACH, times=1)
    var kind = String()
    try:
        _ = TcpStream.connect_host_deadline("one.test", port, _secs(5), only)
    except e:
        kind = String(e.kind)
    fault.clear()
    assert_equal(kind, "NetworkUnreachable")
    sys.keep_alive(l)


def test_emfile_in_a_dial_raises() raises:
    fault.clear()
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = l.local_addr().port()
    var r = _hosts_resolver("127.0.0.1 mf.test\n")
    fault.clear()
    fault.inject(SYS_socket, Errno.EMFILE, times=1)
    var kind = String()
    try:
        _ = TcpStream.connect_host_deadline("mf.test", port, _secs(5), r)
    except e:
        kind = String(e.kind)
    fault.clear()
    assert_equal(kind, "TooManyFiles")
    sys.keep_alive(l)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
