"""Regression tests for the second net review (name resolution).

- D1: a hosts file over 16 MiB (merged ad-block lists) was read as empty,
  so every name in it went to DNS. It is now read whole, of any size.
- D3: a name ending in two dots was queried as if it had none
  (`localhost..` went to DNS); it is now refused, as glibc refuses it.
- D4: an answer handled after the deadline could still start a new
  exchange (a retry without EDNS, or over TCP); none starts now.
- D5: nameserver lines take IPv4 in inet_aton's forms (`127.1`, octal,
  hex), as glibc reads them, checked against Python's `socket.inet_aton`
  (glibc's).
- D6: `options no-tld-query` and `no-aaaa` are implemented.
- D7: option values are read as atoi reads them and then clamped
  (`ndots:1000000` is 15, `attempts:3,` is 3), not dropped.
- D8: a name the hosts file lists only in the other family is looked up in
  DNS (glibc's files source answers NOTFOUND for that family).
- D9: IPv4-mapped addresses (::ffff:0:0/96) have RFC 6724's precedence 35.
- D11: a TTL with the top bit set counts as 0 (RFC 2181 section 8).
- D12: an extended RCODE in the OPT record (BADVERS, 16) is a failure, not
  an empty NOERROR.

D2 (a stream of strays kept a lookup past its deadline) counts syscalls:
test_net_dns_regressions_faults.mojo.
"""

from std.os import makedirs, remove, rmdir
from std.python import Python
from std.testing import TestSuite, assert_equal, assert_false, assert_true
from std.time import sleep

from linux.nr import SYS_getpid
from linux.syscall import syscall0
from linux.time import Deadline, Duration
from net.addr import IpAddr
from net.dns import TYPE_A, build_query, parse_response
from net.resolv import Hosts, ResolvConf, search_names
from net.resolver import Resolver, precedence
from fake_dns import FakeDns


def _secs(n: Int) -> Deadline:
    return Deadline.after(Duration.from_secs(n))


def _joined(ips: List[IpAddr]) -> String:
    var out = String()
    for i in range(len(ips)):
        if i > 0:
            out += " "
        out += String(ips[i])
    return out^


def _kind(r: Resolver, host: StringSlice) -> String:
    try:
        _ = r.lookup_ip(host, _secs(2))
        return "ok"
    except e:
        return String(e.kind)


# ---- D1 ------------------------------------------------------------------------


def test_d1_a_hosts_file_past_16_mib_is_read() raises:
    var dir = String("build/test_d1_", syscall0(SYS_getpid))
    makedirs(dir, exist_ok=True)
    var path = dir + "/hosts"
    var filler = String("# ") + String("x") * 120 + "\n"
    var text = String()
    for _ in range(140_000):  # (about 17 MiB of comments)
        text += filler
    text += "10.9.8.7 big.hosts.test\n"
    with open(path, "w") as f:
        f.write(text)
    var hosts = Hosts.load(path)
    remove(path)
    rmdir(dir)
    assert_true(text.byte_length() > 16 * 1024 * 1024)
    assert_equal(_joined(hosts.lookup("big.hosts.test")), "10.9.8.7")


# ---- D3 ------------------------------------------------------------------------


def test_d3_two_trailing_dots_are_not_a_name() raises:
    var c = ResolvConf()
    assert_equal(len(search_names("foo..", c)), 0)
    assert_equal(len(search_names("localhost..", c)), 0)
    assert_equal(search_names("foo.", c)[0], "foo")  # (one is an absolute name)
    var dns = FakeDns()
    var r = dns.resolver()
    assert_equal(_kind(r, "localhost.."), "InvalidInput")
    assert_equal(_kind(r, "ok.test.."), "InvalidInput")
    # (a DNS answer would have been NotFound; `count` cannot ask about
    # `localhost` names, which the resolver answers itself)
    assert_equal(dns.count(0, "ok.test"), 0)
    dns^.stop()


# ---- D4 ------------------------------------------------------------------------


def test_d4_no_new_exchange_after_the_deadline() raises:
    var dns = FakeDns()
    var c = dns.conf()
    c.edns0 = True  # (noedns.test answers FORMERR to a query with OPT)
    var r = Resolver(c^, Hosts())
    var deadline = Deadline.after(Duration.from_millis(200))
    var lk = r.start("noedns.test", deadline, want_v6=False)
    sleep(0.5)  # (the FORMERR waits in the socket; the deadline passes)
    lk.advance(deadline)
    assert_true(lk.is_done())
    assert_equal(dns.count(0, "noedns.test"), 1, "a retry without EDNS went out after the deadline")
    dns^.stop()


# ---- D5 ------------------------------------------------------------------------


def _nameserver_of(token: StringSlice) -> String:
    """What a `nameserver token` line reads as, or "-" when it is skipped."""
    var c = ResolvConf.parse(String("nameserver ", token, "\nnameserver 192.0.2.250\n"))
    var first = String(c.nameservers[0].ip())
    return "-" if first == "192.0.2.250" else first


def test_d5_nameserver_lines_take_inet_aton_forms() raises:
    assert_equal(_nameserver_of("127.1"), "127.0.0.1")
    assert_equal(_nameserver_of("10.0.0.01"), "10.0.0.1")
    assert_equal(_nameserver_of("0x7f.0.0.2"), "127.0.0.2")
    assert_equal(_nameserver_of("010.1"), "8.0.0.1")
    assert_equal(_nameserver_of("3232235777"), "192.168.1.1")
    assert_equal(_nameserver_of("1.2.3.4.5"), "-")
    assert_equal(_nameserver_of("256.1"), "-")
    assert_equal(_nameserver_of("08.1.1.1"), "-")
    assert_equal(_nameserver_of("1.2.3."), "-")
    assert_equal(_nameserver_of("4294967296"), "-")
    # Against glibc's inet_aton (Python's socket.inet_aton), on random
    # tokens of digits, hex letters, x and dots.
    var py = Python.evaluate(
        """
import random, socket
def cases(n, seed):
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        t = ''.join(rng.choice('0123456789...xXabfAF') for _ in range(rng.randint(1, 14)))
        try:
            v = socket.inet_ntoa(socket.inet_aton(t))
        except OSError:
            v = '-'
        out.append((t, v))
    return out
""",
        file=True,
        name="d5",
    )
    var cases = py.cases(4000, 7)
    var accepted = 0
    for i in range(Int(py=cases.__len__())):
        var token = String(py=cases[i][0])
        var want = String(py=cases[i][1])
        assert_equal(_nameserver_of(token), want, token)
        if want != "-":
            accepted += 1
    assert_true(accepted > 100, String("only ", accepted, " tokens parsed"))


# ---- D6 ------------------------------------------------------------------------


def test_d6_no_tld_query_and_no_aaaa() raises:
    var c = ResolvConf.parse("search corp.example\noptions no-tld-query no-aaaa\n")
    assert_true(c.no_tld_query and c.no_aaaa)
    var names = search_names("db", c)
    assert_equal(len(names), 1)
    assert_equal(names[0], "db.corp.example")
    assert_equal(len(search_names("db.x", c)), 2)  # (has a dot: tried as it is)
    var bare = ResolvConf.parse("options no-tld-query\n")
    assert_equal(search_names("db", bare)[0], "db")  # (no search list: as glibc)
    var dns = FakeDns()
    var conf = dns.conf()
    conf.no_aaaa = True
    var r = Resolver(conf^, Hosts.parse("2001:db8::5 h6.test\n"))
    assert_equal(_joined(r.lookup_ip("ok.test", _secs(5))), "192.0.2.1")
    assert_equal(dns.count(0, "ok.test"), 1)  # (the A query only)
    assert_equal(_joined(r.lookup_ip("h6.test", _secs(5))), "2001:db8::5")
    dns^.stop()


# ---- D7 ------------------------------------------------------------------------


def test_d7_option_values_are_clamped_not_dropped() raises:
    var c = ResolvConf.parse("options ndots:1000000 timeout:1000000 attempts:3,\n")
    assert_equal(c.ndots, 15)
    assert_equal(c.timeout, Duration.from_secs(30))
    assert_equal(c.attempts, 3)
    var d = ResolvConf.parse("options ndots:5, timeout:0 attempts:x\n")
    assert_equal(d.ndots, 5)
    assert_equal(d.timeout, Duration.from_secs(1))
    assert_equal(d.attempts, 2)  # (no digit: the default)


# ---- D8 ------------------------------------------------------------------------


def test_d8_hosts_without_the_family_asks_dns() raises:
    var dns = FakeDns()
    var r = Resolver(dns.conf(), Hosts.parse("2001:db8::99 v4only.test\n"))
    assert_equal(_joined(r.lookup_ip("v4only.test", _secs(5), want_v6=False)), "192.0.2.4")
    assert_equal(_joined(r.lookup_ip("v4only.test", _secs(5), want_v4=False)), "2001:db8::99")
    assert_equal(_joined(r.lookup_ip("v4only.test", _secs(5))), "2001:db8::99")  # (listed: no DNS)
    dns^.stop()


# ---- D9 ------------------------------------------------------------------------


def test_d9_ipv4_mapped_has_ipv4_precedence() raises:
    assert_equal(precedence(IpAddr.parse("::ffff:192.0.2.1")), 35)
    assert_equal(precedence(IpAddr.parse("192.0.2.1")), 35)
    assert_equal(precedence(IpAddr.parse("2001:db8::1")), 40)
    assert_equal(precedence(IpAddr.parse("::1")), 50)


# ---- D11 and D12: crafted answers ------------------------------------------------


def _answer(query: List[UInt8], ttl: UInt32, opt_rcode: Int) -> List[UInt8]:
    """A NOERROR answer to `query` with one A record (192.0.2.33, TTL `ttl`),
    and an OPT record with `opt_rcode` as its extended RCODE byte when it is
    not negative."""
    var r = query.copy()
    r[2] = 0x81  # QR RD
    r[3] = 0x80  # RA, RCODE 0
    r[7] = 1  # ancount
    r[11] = 1 if opt_rcode >= 0 else 0
    var rr: List[UInt8] = [0xC0, 0x0C, 0, 1, 0, 1]
    rr.append(UInt8(ttl >> 24))
    rr.append(UInt8((ttl >> 16) & 0xFF))
    rr.append(UInt8((ttl >> 8) & 0xFF))
    rr.append(UInt8(ttl & 0xFF))
    rr.extend([0, 4, 192, 0, 2, 33])
    r.extend(rr^)
    if opt_rcode >= 0:
        var opt: List[UInt8] = [0, 0, 41, 0x04, 0xD0, UInt8(opt_rcode), 0, 0, 0, 0, 0]
        r.extend(opt^)
    return r^


def test_d11_a_ttl_with_the_top_bit_set_is_zero() raises:
    var q = build_query(0x1234, "ttl.test", TYPE_A)
    var big = parse_response(Span(_answer(q, 0x80000000, -1)), Span(q))
    assert_equal(Int(big.value().ttl), 0)
    assert_equal(len(big.value().addrs), 1)
    var fine = parse_response(Span(_answer(q, 0x7FFFFFFF, -1)), Span(q))
    assert_equal(Int(fine.value().ttl), 0x7FFFFFFF)


def test_d12_an_extended_rcode_is_a_failure() raises:
    var q = build_query(0x4321, "ext.test", TYPE_A)
    var badvers = parse_response(Span(_answer(q, 60, 1)), Span(q))
    assert_equal(badvers.value().rcode, 16)
    assert_equal(len(badvers.value().addrs), 0)
    var plain = parse_response(Span(_answer(q, 60, 0)), Span(q))
    assert_equal(plain.value().rcode, 0)
    assert_equal(len(plain.value().addrs), 1)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
