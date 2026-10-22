"""Regression tests for the review of the TCP client (resolver, DNS codec,
Happy Eyeballs, presets):

- R1: a truncated answer whose TCP retry never completes no longer stalls
  the other query or a connection race (the TCP exchange is nonblocking).
- R2: an answer found before the deadline is returned, not dropped as
  TimedOut.
- R3: a lame referral (NOERROR, no answer, AA and RA clear, no SOA) moves
  to the next server; an authoritative NODATA does not.
- R4: no query is sent after the deadline.
- R5: with edns0, FORMERR is retried without the OPT record.
- R6: compression-pointer chains are capped per name.
- R7: unreadable configuration files mean the defaults.
- R8: in a connection race, the earliest-started finished attempt wins.
- R9: queued addresses follow RFC 6724 precedence within a family.
- R10: detect_dead_peers computes TCP_USER_TIMEOUT from the kernel's
  rounded keepalive times.
- R11: HostPort.parse rejects brackets inside the host."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError, sys
from linux.abi import Pollfd
from linux.consts import POLLOUT
from linux.time import Deadline, Duration, Instant
from net.addr import IpAddr, SocketAddr
from net.dial import HostPort, _Attempt, _Errors, _insert_by_precedence, _settle
from net.dns import TYPE_A, build_query, encode_name, parse_response
from net.resolv import Hosts, ResolvConf
from net.resolver import Resolver
from net.socket import Domain, SockType, Socket, TcpKeepalive
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


# ---- R1 ----------------------------------------------------------------------


def test_r1_tcp_retry_does_not_stall_the_other_query() raises:
    # A: TC, and TCP never answers. AAAA answers at once and must survive.
    var dns = FakeDns()
    var c = ResolvConf()
    c.nameservers.append(dns.server(0))
    c.timeout = Duration.from_secs(1)
    c.attempts = 1  # one TCP try for A: the lookup ends when it times out
    var r = Resolver(c^, Hosts())
    var t = Instant.now()
    assert_equal(_set(r.lookup_ip("tcblack.test", _secs(10))), "2001:db8::5")
    assert_true(t.elapsed() < Duration.from_millis(1600))
    dns^.stop()


def test_r1_tcp_retry_does_not_stall_a_connection_race() raises:
    # A answers 127.0.0.1 at once; AAAA is truncated and its TCP retry
    # hangs. The connection must not wait for that retry.
    var dns = FakeDns()
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = l.local_addr().port()
    var r = dns.resolver(timeout_secs=3)
    var t = Instant.now()
    var s = TcpStream.connect_host_deadline("tcstall.test", port, _secs(5), r)
    assert_equal(String(s.peer_addr()), String("127.0.0.1:", port))
    assert_true(t.elapsed() < Duration.from_millis(400))
    sys.keep_alive(l)
    dns^.stop()


# ---- R2 ----------------------------------------------------------------------


def test_r2_found_addresses_survive_the_deadline() raises:
    # AAAA comes after 2 s; with a 1 s deadline the A answer is the result.
    var dns = FakeDns()
    var r = dns.resolver(timeout_secs=5)
    var t = Instant.now()
    assert_equal(_set(r.lookup_ip("slowaaaa.test", Deadline.after(Duration.from_secs(1)))), "127.0.0.1")
    var took = t.elapsed()
    assert_true(took >= Duration.from_millis(950) and took < Duration.from_millis(1500))
    dns^.stop()


# ---- R3 ----------------------------------------------------------------------


def test_r3_lame_referral_moves_to_the_next_server() raises:
    var dns = FakeDns()
    var r = dns.resolver()
    assert_equal(_set(r.lookup_ip("lame.test", _secs(5))), "192.0.2.30")
    # An authoritative NODATA (AA set, SOA given) is an answer, not lame.
    var kind = String()
    try:
        _ = r.lookup_ip("authnodata.test", _secs(5))
    except e:
        kind = String(e.kind)
    assert_equal(kind, "NotFound")
    dns^.stop()


# ---- R4 ----------------------------------------------------------------------


def test_r4_no_query_after_the_deadline() raises:
    # Server 0 is silent until the 300 ms deadline; server 1 must never be
    # asked, and neither must the search domains.
    var dns = FakeDns()
    var c = dns.conf(timeout_secs=1, attempts=3)
    for i in range(5):
        c.search.append(String("d", i, ".test"))
    var r = Resolver(c^, Hosts())
    var kind = String()
    try:
        _ = r.lookup_ip("drop.test", Deadline.after(Duration.from_millis(300)))
    except e:
        kind = String(e.kind)
    assert_equal(kind, "TimedOut")
    assert_equal(dns.count(0, "drop.test"), 2)  # A and AAAA, once
    assert_equal(dns.count(1, "drop.test"), 0)
    assert_equal(dns.count(0, "drop.test.d0.test"), 0)
    dns^.stop()


# ---- R5 ----------------------------------------------------------------------


def test_r5_formerr_to_edns_is_retried_without_it() raises:
    var dns = FakeDns()
    var c = dns.conf()
    c.edns0 = True
    var r = Resolver(c^, Hosts())
    assert_equal(_set(r.lookup_ip("noedns.test", _secs(5))), "192.0.2.78")
    dns^.stop()


# ---- R6 ----------------------------------------------------------------------


def _pointer_chain_answer(q: List[UInt8], hops: Int) raises -> List[UInt8]:
    """A response whose A record's owner name is reached through `hops`
    chained pointers (kept inside the RDATA of an unknown record)."""
    var b = List[UInt8]()
    b.append(q[0])
    b.append(q[1])
    for v in [0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]:
        b.append(UInt8(v))
    for i in range(12, len(q)):
        b.append(q[i])
    # Record 1: type 99 whose rdata holds the chain p0 -> question name,
    # p1 -> p0, ...
    b.append(0)  # root owner
    for v in [0, 99, 0, 1, 0, 0, 0, 1]:
        b.append(UInt8(v))
    b.append(UInt8((2 * hops) >> 8))
    b.append(UInt8((2 * hops) & 0xFF))
    var prev = 12
    var last = 12
    for _ in range(hops):
        var here = len(b)
        b.append(UInt8(0xC0 | (prev >> 8)))
        b.append(UInt8(prev & 0xFF))
        prev = here
        last = here
    # Record 2: the A record, owner = pointer to the last link.
    b.append(UInt8(0xC0 | (last >> 8)))
    b.append(UInt8(last & 0xFF))
    for v in [0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]:
        b.append(UInt8(v))
    return b^


def test_r6_pointer_chains_are_capped() raises:
    var q = build_query(0x4242, "chain.test", TYPE_A)
    var short = _pointer_chain_answer(q, 3)
    var ok = parse_response(Span(short), Span(q))
    assert_equal(len(ok.value().addrs), 1)
    var long = _pointer_chain_answer(q, 40)
    var kind = String()
    try:
        _ = parse_response(Span(long), Span(q))
    except e:
        kind = String(e.kind)
    assert_equal(kind, "InvalidData")


# ---- R7 ----------------------------------------------------------------------


def test_r7_unreadable_config_means_defaults() raises:
    # A directory opens but cannot be read (EISDIR).
    var c = ResolvConf.load("/etc")
    assert_equal(len(c.nameservers), 2)  # 127.0.0.1 and ::1
    assert_equal(len(Hosts.load("/etc")), 0)
    _ = Resolver.system()  # never raises


# ---- R8 ----------------------------------------------------------------------


def test_r8_earliest_finished_attempt_wins() raises:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var addr = l.local_addr()
    var attempts = List[_Attempt]()
    for _ in range(2):
        var s = Socket.new(Domain.IPV4, SockType.STREAM)
        s.connect(addr)
        attempts.append(_Attempt(s^, addr))
    var fds = List[Pollfd]()
    fds.append(Pollfd(attempts[0].sock.raw_fd(), Int16(POLLOUT), Int16(POLLOUT)))
    fds.append(Pollfd(attempts[1].sock.raw_fd(), Int16(POLLOUT), Int16(POLLOUT)))
    var errors = _Errors()
    var winner = _settle(attempts, Span(fds), errors)
    assert_equal(winner.value(), 0)
    sys.keep_alive(l)


# ---- R9 ----------------------------------------------------------------------


def test_r9_queue_follows_rfc6724_precedence() raises:
    var q = List[SocketAddr]()
    for t in ["fd00::1", "2001::1", "2600::1", "2002::1", "2600::2", "::1"]:
        _insert_by_precedence(q, SocketAddr(IpAddr.parse(t), 80))
    var out = String()
    for a in q:
        out += String(a.ip()) + " "
    assert_equal(out, "::1 2600::1 2600::2 2002::1 2001::1 fd00::1 ")


# ---- R10 ---------------------------------------------------------------------


def test_r10_user_timeout_uses_the_rounded_keepalive() raises:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = TcpStream.connect(l.local_addr())
    c.detect_dead_peers(TcpKeepalive(Duration.from_millis(1500), Duration.from_millis(1500), 3))
    # The kernel keeps 2 s / 2 s / 3: the user timeout is 2 + 2 x 3 = 8 s.
    assert_equal(c.socket().tcp_user_timeout().value(), Duration.from_secs(8))
    sys.keep_alive(l)


# ---- R11 ---------------------------------------------------------------------


def test_r11_host_port_rejects_brackets_in_the_host() raises:
    var bad: List[String] = ["[[::1]:80", "a]:80", "[a[b]:80", "[a]b]:80"]
    for b in bad:
        var kind = String()
        try:
            _ = HostPort.parse(b)
        except e:
            kind = String(e.kind)
        assert_equal(kind, "InvalidInput", b)
    assert_equal(HostPort.parse("[::1]:80").host, "::1")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
