"""`http.client`: URL parsing, and `Client` against Python's http.server
(tests/http/http_peer.py): bodies by length, chunked with trailers and to
the close; HEAD; the headers it sends; keep-alive reuse and what is not
pooled; the retry of an idempotent request on a connection the server
dropped (and no retry for POST); the deadline; `max_body`; errors."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from http.client import Client, Response, Url
from http.headers import Headers
from linux import ErrorKind, IoError
from linux.time import Duration
from http_peer import HttpPeer


def _kind(e: IoError) -> String:
    return String(e.kind)


# ---- URLs -------------------------------------------------------------------------


def test_url_parsing() raises:
    var u = Url.parse("http://example.com/a/b?c=d#frag")
    assert_equal(u.host, "example.com")
    assert_equal(Int(u.port), 80)
    assert_equal(u.target, "/a/b?c=d")
    assert_equal(u.authority(), "example.com")
    assert_equal(Url.parse("HTTP://h").target, "/")
    assert_equal(Url.parse("http://h?x=1").target, "/?x=1")
    assert_equal(Url.parse("http://h#f").target, "/")
    var p = Url.parse("http://h.example:8080/")
    assert_equal(Int(p.port), 8080)
    assert_equal(p.authority(), "h.example:8080")
    var v6 = Url.parse("http://[::1]:9000/x")
    assert_equal(v6.host, "::1")
    assert_equal(Int(v6.port), 9000)
    assert_equal(v6.authority(), "[::1]:9000")
    assert_equal(String(v6), "http://[::1]:9000/x")
    assert_equal(Url.parse("http://[2001:db8::1]/").authority(), "[2001:db8::1]")
    var kinds = List[String]()
    for bad in [
        "ftp://h/",
        "h/path",
        "://h",
        "http://",
        "http:///x",
        "http://user:pw@h/",
        "http://h:0/",
        "http://h:65536/",
        "http://h:80x/",
        "http://h:/",
        "http://h h/",
        "http://[::1/",
        "http://[::1]x/",
        "http://[zz::1]/",
        "http://h/a b",
        "http://h/\x7f",
        "http://h/é",
    ]:
        try:
            _ = Url.parse(bad)
            kinds.append(String("ok ", bad))
        except e:
            kinds.append(_kind(e))
    for k in kinds:
        assert_equal(k, "InvalidInput")
    # https parses since H8 (tests/http/test_https.mojo has the rest).
    var https = Url.parse("https://example.com/")
    assert_true(https.tls)
    assert_equal(Int(https.port), 443)


# ---- against http.server --------------------------------------------------------------


def test_get_head_and_bodies() raises:
    var peer = HttpPeer()
    var c = Client()
    var r = c.get(peer.url("/hello"))
    assert_equal(r.status, 200)
    assert_equal(r.reason, "OK")
    assert_equal(r.text(), "hello")
    assert_equal(String(r.headers.get("content-type").value()), "text/plain")
    var h = c.head(peer.url("/hello"))
    assert_equal(h.status, 200)
    assert_equal(len(h.body), 0)
    assert_equal(String(h.headers.get("content-length").value()), "5")
    var ch = c.get(peer.url("/chunked"))
    assert_equal(ch.text(), "Wikipedia")
    assert_equal(String(ch.trailers.get("x-sum").value()), "2")
    var old = c.get(peer.url("/http10"))  # to the close
    assert_equal(old.text(), "old style")
    assert_equal(old.version.minor, 0)
    var missing = c.get(peer.url("/nope"))
    assert_equal(missing.status, 404)
    assert_equal(missing.text(), "not found")
    peer^.stop()


def test_the_headers_sent() raises:
    var peer = HttpPeer()
    var c = Client(user_agent="test-agent/1")
    var h = Headers()
    h.add("X-Custom", "value one")
    h.add("Accept", "*/*")
    var r = c.request("GET", peer.url("/headers"), h)
    var lines = r.text()
    assert_true(lines.find(String("Host: 127.0.0.1:", peer.port, "\n")) >= 0, lines)
    assert_true(lines.find("User-Agent: test-agent/1\n") >= 0, lines)
    assert_true(lines.find("X-Custom: value one\n") >= 0, lines)
    assert_true(lines.find("Content-Length") < 0, lines)  # none for a GET
    var own = Headers()
    own.add("Host", "virtual.example")
    var v = c.request("GET", peer.url("/headers"), own)
    assert_true(v.text().find("Host: virtual.example\n") >= 0)
    peer^.stop()


def test_bodies_sent() raises:
    var peer = HttpPeer()
    var c = Client()
    var r = c.post(peer.url("/echo"), "ping".as_bytes(), "text/plain")
    assert_equal(r.text(), "ping")
    assert_equal(String(r.headers.get("x-method").value()), "POST")
    var big = List[UInt8](length=200000, fill=0x61)
    var e = c.request("PUT", peer.url("/echo"), Headers(), Span(big))
    assert_equal(len(e.body), 200000)
    var empty = c.request("PUT", peer.url("/echo"))  # Content-Length: 0
    assert_equal(len(empty.body), 0)
    assert_equal(empty.status, 200)
    peer^.stop()


def test_keep_alive_reuse() raises:
    var peer = HttpPeer()
    var c = Client()
    var first = c.get(peer.url("/conn")).text()
    assert_equal(c.idle_connections(), 1)
    for _ in range(5):
        assert_equal(c.get(peer.url("/conn")).text(), first)  # same connection
    _ = c.get(peer.url("/close"))  # Connection: close: not pooled
    assert_equal(c.idle_connections(), 0)
    var after = c.get(peer.url("/conn")).text()
    assert_true(after != first)
    c.close_idle()
    assert_equal(c.idle_connections(), 0)
    var fresh = c.get(peer.url("/conn")).text()
    assert_true(fresh != after)
    peer^.stop()


def test_dropped_connection_is_retried_for_idempotent_requests() raises:
    var peer = HttpPeer()
    var c = Client()
    # /flaky answers the first request on a connection and drops later ones.
    var a = c.get(peer.url("/flaky"))  # connection 1, pooled
    assert_equal(a.text(), "ok")
    var b = c.get(peer.url("/flaky"))  # 1 is dropped; sent again on 2
    assert_equal(b.text(), "ok")
    assert_equal(c.idle_connections(), 1)  # 2, pooled
    var kind = String()
    try:
        _ = c.post(peer.url("/flaky"), "x".as_bytes(), "text/plain")  # 2 is dropped
    except e:
        kind = String(e.kind, " ", e.op)
    assert_equal(kind, "UnexpectedEof http: connection closed before a response")  # POST is not retried
    assert_equal(c.idle_connections(), 0)
    var p = c.post(peer.url("/flaky"), "x".as_bytes(), "text/plain")  # a new connection
    assert_equal(p.text(), "ok")
    peer^.stop()


def test_deadline_and_body_limit() raises:
    var peer = HttpPeer()
    var slow = Client(timeout=Duration.from_millis(300))
    var timed_out = False
    try:
        _ = slow.get(peer.url("/slow"))
    except e:
        timed_out = e.is_deadline()
    assert_true(timed_out)
    var small = Client(max_body=1000)
    assert_equal(len(small.get(peer.url("/big?n=1000")).body), 1000)
    var kind = String()
    try:
        _ = small.get(peer.url("/big?n=5000"))
    except e:
        kind = _kind(e)
    assert_equal(kind, "InvalidData")
    assert_equal(len(small.get(peer.url("/big?n=10")).body), 10)  # recovers
    peer^.stop()


def test_errors() raises:
    var c = Client(timeout=Duration.from_secs(2))
    var kinds = List[String]()
    try:
        _ = c.get("http://127.0.0.1:1/")  # nothing listens
    except e:
        kinds.append(_kind(e))
    var h = Headers()
    h.add("Content-Length", "3")
    try:
        _ = c.request("POST", "http://127.0.0.1:1/", h)
    except e:
        kinds.append(_kind(e))
    try:
        _ = c.request("CONNECT", "http://127.0.0.1:1/")
    except e:
        kinds.append(_kind(e))
    try:
        _ = c.request("BAD METHOD", "http://127.0.0.1:1/")
    except e:
        kinds.append(_kind(e))
    assert_equal(len(kinds), 4)
    assert_equal(kinds[0], "ConnectionRefused")
    for i in range(1, 4):
        assert_equal(kinds[i], "InvalidInput")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
