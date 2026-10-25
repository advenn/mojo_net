"""`net.resolver`: lookups against a scripted DNS server (`fake_dns`): both
families in parallel, NODATA/NXDOMAIN, CNAMEs, TCP after truncation,
EDNS(0), failover on SERVFAIL/REFUSED/FORMERR/garbage/ICMP/timeouts,
forged packets, the search list, deadlines, `use-vc`; plus literals, the
hosts file, `localhost` (RFC 6761), the address order, and one live lookup
through the system configuration (skipped without a working resolver)."""

from std.python import Python
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError
from linux.time import Deadline, Duration, Instant
from net.addr import IpAddr, SocketAddr
from net.resolv import Hosts, ResolvConf
from net.resolver import Resolver, precedence, sort_addresses
from net.socket import Domain, SockType, Socket
from fake_dns import FakeDns


def _secs(s: Int) -> Deadline:
    return Deadline.after(Duration.from_secs(s))


def _set(ips: List[IpAddr]) -> String:
    """Sorted and space-separated, for order-free comparisons."""
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


def _kind(r: Resolver, name: StringSlice, deadline: Deadline) -> String:
    try:
        _ = r.lookup_ip(name, deadline)
        return "ok"
    except e:
        return String(e.kind)


# ---- answers -----------------------------------------------------------------


def test_both_families_are_asked() raises:
    var dns = FakeDns()
    var r = dns.resolver()
    assert_equal(_set(r.lookup_ip("ok.test", _secs(5))), "192.0.2.1 2001:db8::1")
    assert_equal(_set(r.lookup_ip("OK.Test.", _secs(5))), "192.0.2.1 2001:db8::1")
    assert_equal(_set(r.lookup_ip("ok.test", _secs(5), want_v6=False)), "192.0.2.1")
    assert_equal(_set(r.lookup_ip("ok.test", _secs(5), want_v4=False)), "2001:db8::1")
    assert_equal(_set(r.lookup_ip("v4only.test", _secs(5))), "192.0.2.4")
    dns^.stop()


def test_nodata_and_nxdomain_are_not_found() raises:
    var dns = FakeDns()
    var r = dns.resolver()
    assert_equal(_kind(r, "nodata.test", _secs(5)), "NotFound")
    assert_equal(_kind(r, "nx.test", _secs(5)), "NotFound")
    assert_equal(_kind(r, "v4only.test", _secs(5)), "ok")
    dns^.stop()


def test_cname_chain_is_followed() raises:
    var dns = FakeDns()
    var r = dns.resolver()
    assert_equal(_set(r.lookup_ip("cname.test", _secs(5))), "192.0.2.7")
    dns^.stop()


def test_truncated_answer_is_asked_again_over_tcp() raises:
    var dns = FakeDns()
    var r = dns.resolver()
    var ips = r.lookup_ip("big.test", _secs(5))
    assert_equal(len(ips), 40)
    dns^.stop()


def test_edns0_fits_a_large_answer_in_udp() raises:
    # The server closes TCP for this name, so success proves UDP.
    var dns = FakeDns()
    var c = dns.conf()
    c.edns0 = True
    var r = Resolver(c^, Hosts())
    assert_equal(len(r.lookup_ip("edns.test", _secs(5))), 30)
    var plain = dns.resolver()
    assert_false(_kind(plain, "edns.test", _secs(5)) == "ok")
    dns^.stop()


def test_use_vc_asks_over_tcp() raises:
    var dns = FakeDns()
    var c = dns.conf()
    c.use_tcp = True
    var r = Resolver(c^, Hosts())
    assert_equal(_set(r.lookup_ip("ok.test", _secs(5))), "192.0.2.1 2001:db8::1")
    assert_equal(len(r.lookup_ip("big.test", _secs(5))), 40)


# ---- failover ----------------------------------------------------------------
    dns^.stop()


def test_server_failures_move_to_the_next_server_at_once() raises:
    var dns = FakeDns()
    var r = dns.resolver(timeout_secs=5)
    var names: List[String] = ["servfail.test", "refused.test", "formerr.test", "garbage.test"]
    for n in names:
        var t = Instant.now()
        assert_equal(_set(r.lookup_ip(n, _secs(10))), "192.0.2.9", n)
        assert_true(t.elapsed() < Duration.from_secs(2), n)  # no timeout waited
    dns^.stop()


def test_closed_port_moves_on_without_waiting() raises:
    var dns = FakeDns()
    var probe = Socket.new(Domain.IPV4, SockType.DGRAM)
    probe.bind(SocketAddr.parse("127.0.0.1:0"))
    var closed = probe.local_addr()
    probe^.close()
    var c = ResolvConf()
    c.nameservers.append(closed)  # ICMP port unreachable: ECONNREFUSED
    c.nameservers.append(dns.server(1))
    c.timeout = Duration.from_secs(5)
    var r = Resolver(c^, Hosts())
    var t = Instant.now()
    assert_equal(_set(r.lookup_ip("ok.test", _secs(10))), "192.0.2.1 2001:db8::1")
    assert_true(t.elapsed() < Duration.from_secs(2))
    dns^.stop()


def test_silent_server_times_out_then_the_next_answers() raises:
    var dns = FakeDns()
    var r = dns.resolver(timeout_secs=1)
    var t = Instant.now()
    assert_equal(_set(r.lookup_ip("drop0.test", _secs(10))), "192.0.2.9")
    assert_true(t.elapsed() >= Duration.from_millis(900))
    assert_true(t.elapsed() < Duration.from_secs(3))
    dns^.stop()


def test_every_server_silent_is_timed_out() raises:
    var dns = FakeDns()
    var r = dns.resolver(timeout_secs=1)
    var t = Instant.now()
    assert_equal(_kind(r, "drop.test", _secs(20)), "TimedOut")
    var took = t.elapsed()
    assert_true(took >= Duration.from_millis(1900) and took < Duration.from_secs(5))
    dns^.stop()


def test_deadline_bounds_the_lookup() raises:
    var dns = FakeDns()
    var r = dns.resolver(timeout_secs=5)
    var t = Instant.now()
    var kind = String()
    var expired = False
    try:
        _ = r.lookup_ip("drop.test", Deadline.after(Duration.from_millis(300)))
    except e:
        kind = String(e.kind)
        expired = e.is_deadline()
    assert_equal(kind, "TimedOut")
    assert_true(expired)
    assert_true(t.elapsed() < Duration.from_secs(1))


# ---- forgery, parallelism, search --------------------------------------------
    dns^.stop()


def test_forged_answers_are_ignored() raises:
    # A wrong-ID packet and a wrong-question packet arrive first.
    var dns = FakeDns()
    var r = dns.resolver()
    assert_equal(_set(r.lookup_ip("spoof.test", _secs(5))), "192.0.2.14")
    dns^.stop()


def test_a_and_aaaa_run_in_parallel() raises:
    var dns = FakeDns()
    var r = dns.resolver()
    var t = Instant.now()
    assert_equal(_set(r.lookup_ip("slow.test", _secs(5))), "192.0.2.13 2001:db8::13")
    # A takes 0.3 s and AAAA 0.4 s: in parallel ~0.4 s, one after the
    # other ~0.7 s.
    var took = t.elapsed()
    assert_true(took >= Duration.from_millis(350) and took < Duration.from_millis(600))
    dns^.stop()


def test_search_list() raises:
    var dns = FakeDns()
    var c = dns.conf()
    c.search.append("svc.test")
    var r = Resolver(c^, Hosts())
    assert_equal(_set(r.lookup_ip("db", _secs(5))), "192.0.2.20")  # db.svc.test
    assert_equal(_set(r.lookup_ip("db.svc.test.", _secs(5))), "192.0.2.20")
    assert_equal(_kind(r, "nx", _secs(5)), "NotFound")  # nx.svc.test, then nx


# ---- without DNS -------------------------------------------------------------
    dns^.stop()


def test_literals_hosts_and_localhost_need_no_server() raises:
    var c = ResolvConf()
    c.nameservers.append(SocketAddr.parse("127.0.0.1:9"))  # never asked
    var hosts = Hosts.parse("10.1.2.3 db.local\n::1 v6.local\n")
    var r = Resolver(c^, hosts^)
    assert_equal(_set(r.lookup_ip("192.0.2.55", _secs(1))), "192.0.2.55")
    assert_equal(_set(r.lookup_ip("2001:db8::55", _secs(1))), "2001:db8::55")
    assert_equal(_set(r.lookup_ip("DB.local", _secs(1))), "10.1.2.3")
    assert_equal(_set(r.lookup_ip("localhost", _secs(1))), "127.0.0.1 ::1")
    assert_equal(_set(r.lookup_ip("api.LOCALHOST.", _secs(1))), "127.0.0.1 ::1")
    assert_equal(_set(r.lookup_ip("localhost", _secs(1), want_v6=False)), "127.0.0.1")
    assert_equal(_kind(r, "v6.local", _secs(1)), "ok")
    # Listed with IPv6 only, asked for IPv4: DNS is asked, as glibc's files
    # source answers NOTFOUND for the family (here the "server" refuses).
    var only4 = String()
    try:
        _ = r.lookup_ip("v6.local", _secs(1), want_v6=False)
    except e:
        only4 = String(e.kind)
    assert_equal(only4, "Other")
    assert_equal(_kind(r, "bad..name", _secs(1)), "InvalidInput")
    assert_equal(_kind(r, "", _secs(1)), "InvalidInput")


# ---- order -------------------------------------------------------------------


def test_policy_precedence() raises:
    assert_equal(precedence(IpAddr.parse("::1")), 50)
    assert_equal(precedence(IpAddr.parse("2600::1")), 40)
    assert_equal(precedence(IpAddr.parse("192.0.2.1")), 35)
    assert_equal(precedence(IpAddr.parse("2002:c000:201::1")), 30)
    assert_equal(precedence(IpAddr.parse("2001:0:4136:e378::1")), 5)
    assert_equal(precedence(IpAddr.parse("fd00::1")), 3)
    assert_equal(precedence(IpAddr.parse("fec0::1")), 1)
    assert_equal(precedence(IpAddr.parse("::192.0.2.1")), 1)


def test_sort_by_precedence_keeps_answer_order_otherwise() raises:
    var ips = List[IpAddr]()
    for t in ["fd00::1", "2600::5", "::1", "2002::1", "2600::4", "2001::1"]:
        ips.append(IpAddr.parse(t))
    sort_addresses(ips)  # one family: no route probes
    var out = String()
    for ip in ips:
        out += String(ip) + " "
    assert_equal(out, "::1 2600::5 2600::4 2002::1 2001::1 fd00::1 ")


# ---- the real configuration --------------------------------------------------


def test_live_lookup_through_the_system_configuration() raises:
    var socket = Python.import_module("socket")
    var known = False
    try:
        _ = socket.getaddrinfo("example.com", 443)
        known = True
    except:
        pass
    if not known:
        print("    (skipped: test_live_lookup_through_the_system_configuration: getaddrinfo cannot resolve example.com)")
        return
    var r = Resolver.system()
    var ips = r.lookup_ip("example.com", _secs(10))
    assert_true(len(ips) > 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
