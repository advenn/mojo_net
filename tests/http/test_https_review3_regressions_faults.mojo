"""Regression tests for the third TLS review's findings in `http.Client`
(TR3, 2026-10-27; tests/tls/test_tls_review3_regressions*.mojo has the
rest), built with -D MOJO_NET_FAULTS=1. Each fails on the code before its
fix."""

from std.testing import TestSuite, assert_equal

from http.client import Client
from http.headers import Headers
from linux import Errno, fault
from linux.nr import SYS_sendto
from linux.time import Duration
from tls import ClientConfig, Trust
from http_peer import HttpPeer


def test_int2_an_early_200_over_tls_gets_the_whole_body() raises:
    """INT-2: a server that answers 200 before the body ends and keeps the
    connection must still get all of it (RFC 9112 9.5). Over TLS the last
    records could still wait in the stream when the request loop saw "the
    whole request is out" (`try_write` takes plaintext; the socket may not
    take all of its ciphertext): the response was returned, the connection
    pooled with output unsent and dropped at the next checkout, so the
    server read a cut body while the caller saw a 200. The body is large
    enough for the 200 to arrive while it is still going out, and every
    second send is refused with EAGAIN, so the last records wait about
    half the time (without the seam, only when the socket's buffer is
    full just then)."""
    fault.clear()
    var peer = HttpPeer(tls=True)
    var c = Client(timeout=Duration.from_secs(30), tls=ClientConfig(trust=Trust.ca_file(peer.ca())))
    var big = List[UInt8](length=32 * 1024 * 1024 + 517, fill=0x62)
    fault.inject(SYS_sendto, Errno.EAGAIN, times=-1, every=2)
    for i in range(6):
        var r = c.request("PUT", peer.url("/early-ok"), Headers(), Span(big))
        assert_equal(r.text(), "ok")
        assert_equal(c.get(peer.url("/early-got")).text(), String(len(big)), String("upload ", i))
    fault.clear()
    peer^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
