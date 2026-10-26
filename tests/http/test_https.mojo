"""`http.Client` over TLS (milestone H8; docs/tls.md): Python's http.server
behind Python's `ssl` (tests/http/http_peer.py --tls) with a throwaway PKI.
The routes of tests/http/test_client.mojo, over https: bodies, keep-alive
reuse (TLS 1.3 session tickets arrive while a connection is idle), the
retry of a dropped connection, early answers to uploads; the ends of a TLS
connection (RFC 9112 9.8); and refused certificates."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from http.client import Client, Url
from http.headers import Headers
from linux import ErrorKind, IoError
from linux.time import Duration
from tls import Category, ClientConfig, Trust
from http_peer import HttpPeer


def _client(peer: HttpPeer) raises -> Client:
    return Client(timeout=Duration.from_secs(20), tls=ClientConfig(trust=Trust.ca_file(peer.ca())))


def _error(mut c: Client, url: String) raises -> IoError:
    try:
        _ = c.get(url)
    except e:
        return e
    raise Error(String("GET ", url, " succeeded"))


def test_https_urls() raises:
    var u = Url.parse("https://example.com/a?b")
    assert_true(u.tls)
    assert_equal(Int(u.port), 443)
    assert_equal(u.authority(), "example.com")
    assert_equal(String(u), "https://example.com/a?b")
    var p = Url.parse("HTTPS://h:8443")
    assert_equal(p.authority(), "h:8443")
    assert_equal(Url.parse("https://h:80/").authority(), "h:80")
    assert_equal(Url.parse("http://h:443/").authority(), "h:443")
    assert_false(Url.parse("http://h/").tls)


def test_get_over_tls() raises:
    var peer = HttpPeer(tls=True)
    var c = _client(peer)
    var r = c.get(peer.url("/hello"))
    assert_equal(r.status, 200)
    assert_equal(r.text(), "hello")
    var named = c.get(peer.named_url("/hello"))  # (the name, not the address)
    assert_equal(named.text(), "hello")
    var ch = c.get(peer.url("/chunked"))
    assert_equal(ch.text(), "Wikipedia")
    assert_equal(String(ch.trailers.get("x-sum").value()), "2")
    var big = c.get(peer.url("/big?n=3000000"))
    assert_equal(len(big.body), 3000000)
    var h = c.head(peer.url("/hello"))
    assert_equal(len(h.body), 0)
    peer^.stop()


def test_bodies_over_tls() raises:
    var peer = HttpPeer(tls=True)
    var c = _client(peer)
    var body = List[UInt8](length=2 * 1024 * 1024 + 7, fill=0x61)
    var r = c.post(peer.url("/echo"), Span(body), "application/octet-stream")
    assert_equal(len(r.body), len(body))
    assert_true(r.body == body)
    var h = Headers()
    var duplex = c.request("PUT", peer.url("/echo-stream"), h, Span(body))
    assert_equal(len(duplex.body), len(body))
    var reject = c.request("PUT", peer.url("/reject-hold"), h, Span(body))
    assert_equal(reject.status, 413)
    peer^.stop()


def test_keep_alive_over_tls() raises:
    """Session tickets reach an idle connection after its first response;
    they are TLS's own messages, so it is still reused."""
    var peer = HttpPeer(tls=True)
    var c = _client(peer)
    var first = c.get(peer.url("/conn")).text()
    for _ in range(3):
        assert_equal(c.get(peer.url("/conn")).text(), first)
    assert_equal(c.idle_connections(), 1)
    # The scheme is part of the pool key: http:// to the same host and port
    # gets a plain connection of its own (which the TLS server refuses),
    # never the pooled TLS one.
    var e = _error(c, String("http://127.0.0.1:", peer.port, "/conn"))
    assert_true(e.kind != ErrorKind.PermissionDenied, String(e))
    assert_equal(c.get(peer.url("/conn")).text(), first)  # (still pooled)
    var plain = HttpPeer()
    _ = c.get(plain.url("/hello"))
    assert_equal(c.idle_connections(), 2)
    plain^.stop()
    peer^.stop()


def test_server_closing_an_idle_connection() raises:
    """The server ends an idle connection with close_notify: the next
    request, a POST (never retried), must go on a new connection."""
    from std.time import sleep

    var peer = HttpPeer(tls=True)
    var c = _client(peer)
    assert_equal(c.get(peer.url("/bye-later")).text(), "ok")
    assert_equal(c.idle_connections(), 1)
    sleep(0.6)
    var body = List[UInt8]("still here".as_bytes())
    var r = c.post(peer.url("/echo"), Span(body), "text/plain")
    assert_equal(r.text(), "still here")
    peer^.stop()


def test_dropped_tls_connection_is_retried() raises:
    """The server reads a second request and closes without answering and
    without close_notify: before any response byte, a retry."""
    var peer = HttpPeer(tls=True)
    var c = _client(peer)
    assert_equal(c.get(peer.url("/flaky")).text(), "ok")
    assert_equal(c.get(peer.url("/flaky")).text(), "ok")
    var stale = c.get(peer.url("/stale408"))
    assert_equal(stale.text(), "ok")
    assert_equal(c.get(peer.url("/stale408")).text(), "ok")
    peer^.stop()


def test_ends_of_a_tls_connection() raises:
    """RFC 9112 9.8: a framed response stands without close_notify; one
    delimited by the close needs it."""
    var peer = HttpPeer(tls=True)
    var c = _client(peer)
    assert_equal(c.get(peer.url("/close")).text(), "bye")  # (Content-Length, then a bare close)
    assert_equal(c.get(peer.url("/http10-notify")).text(), "old style")
    var e = _error(c, peer.url("/http10"))
    assert_equal(e.kind, ErrorKind.UnexpectedEof, String(e))
    assert_equal(c.last_tls_error().value().category, Category.TRUNCATED)
    peer^.stop()


def test_refused_certificates() raises:
    var peer = HttpPeer(tls=True)
    # System roots (or another CA) do not trust the test CA.
    var other = Client(timeout=Duration.from_secs(10), tls=ClientConfig(trust=Trust.ca_file(peer.pki + "/other.pem")))
    var e = _error(other, peer.url("/hello"))
    assert_equal(e.kind, ErrorKind.PermissionDenied, String(e))
    var why = other.last_tls_error().value().copy()
    assert_equal(why.category, Category.UNTRUSTED)
    assert_equal(why.verify_code, 20)
    # A certificate for another name, by address and by name.
    var wrong_peer = HttpPeer(tls=True, cert="wrong_host")
    var c = _client(peer)
    var by_ip = _error(c, wrong_peer.url("/hello"))
    assert_equal(by_ip.kind, ErrorKind.PermissionDenied, String(by_ip))
    assert_equal(c.last_tls_error().value().category, Category.IP_MISMATCH)
    var by_name = _error(c, wrong_peer.named_url("/hello"))
    assert_equal(by_name.kind, ErrorKind.PermissionDenied, String(by_name))
    assert_equal(c.last_tls_error().value().category, Category.HOST_MISMATCH)
    assert_equal(c.idle_connections(), 0)
    wrong_peer^.stop()
    # Plain HTTP to a TLS port: the server's reply is not HTTP.
    var plain = Client(timeout=Duration.from_secs(5))
    var mixed = _error(plain, String("http://127.0.0.1:", peer.port, "/hello"))
    assert_true(mixed.kind != ErrorKind.PermissionDenied, String(mixed))
    peer^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
