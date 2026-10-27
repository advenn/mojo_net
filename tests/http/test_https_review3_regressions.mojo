"""Regression tests for the third TLS review's findings in `http.Client`
that need no fault seam (TR3, 2026-10-27; the others are in
test_https_review3_regressions_faults.mojo). Each fails on the code before
its fix."""

from std.testing import TestSuite, assert_equal

from http.client import Client
from linux import ErrorKind
from linux.time import Duration
from tls import ClientConfig, Trust
from http_peer import HttpPeer


def test_api1_clients_can_share_one_context() raises:
    """API-1: each client built its own TLS context, with an OpenSSL of its
    own (a process can hold about 330): clients now take one built
    already, and share its trust store and OpenSSL. Its ALPN must be
    http/1.1 alone, as the client's own would be."""
    var peer = HttpPeer(tls=True)
    var ctx = ClientConfig(trust=Trust.ca_file(peer.ca()), alpn=["http/1.1"]).build()
    var a = Client(timeout=Duration.from_secs(20), tls_context=ctx.copy())
    var b = Client(timeout=Duration.from_secs(20), tls_context=ctx.copy())
    assert_equal(a.get(peer.url("/hello")).text(), "hello")
    assert_equal(b.get(peer.url("/hello")).text(), "hello")
    var h2 = ClientConfig(trust=Trust.ca_file(peer.ca()), alpn=["h2"]).build()
    var kind = ErrorKind.Other
    try:
        _ = Client(tls_context=h2^)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)
    peer^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
