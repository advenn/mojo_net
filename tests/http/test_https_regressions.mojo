"""Regression tests for the TLS review's findings in `http.Client` (TR,
2026-10-26; tests/tls/test_tls_regressions.mojo has the rest). Each fails
on the code before its fix."""

from std.testing import TestSuite, assert_equal, assert_false

from http.client import Client
from linux import ErrorKind, IoError
from linux.time import Duration
from net.addr import SocketAddr
from net.resolv import Hosts, ResolvConf
from net.resolver import Resolver
from net.tcp import TcpListener
from net.udp import UdpSocket


def test_a_name_tls_cannot_check_is_refused_before_any_io() raises:
    """Hosts `tls.target` refuses (TC4: numeric-looking names that are no
    strict IP literal): the client looked them up and connected before the
    TLS layer refused them, which sent the name to a DNS server and opened
    a connection to whatever came back. Now nothing is sent."""
    var dns = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var conf = ResolvConf()
    conf.nameservers.append(dns.local_addr())
    conf.timeout = Duration.from_millis(300)
    conf.attempts = 1
    var c = Client(timeout=Duration.from_secs(3))
    c._resolver = Resolver(conf^, Hosts())  # (the only server: the socket above)
    var names: List[String] = ["127.1", "0x7f.0.0.1", "host.123", "010.0.0.1"]
    for n in names:
        var e = _request_error(c, String("https://", n, ":", l.local_addr().port(), "/"))
        assert_equal(e.kind, ErrorKind.InvalidInput, n)
    var buf = List[UInt8](length=512, fill=0)
    assert_false(Bool(dns.try_recv(Span(buf))), "a DNS query was sent")
    assert_false(Bool(l.try_accept()), "a connection was made")


def _request_error(mut c: Client, url: String) raises -> IoError:
    try:
        _ = c.get(url)
    except e:
        return e
    raise Error(String("the request to ", url, " was made"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
