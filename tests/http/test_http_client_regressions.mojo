"""Regression tests for the independent review of the http package: the
`Client` findings (R-B<n>), against misbehaving routes of
tests/http/http_peer.py. The codec-level ones are in
test_http_regressions.mojo."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from http.client import Client
from http.headers import Headers
from linux import ErrorKind, IoError
from linux.time import Duration, Instant
from http_peer import HttpPeer


def _wait(d: Duration):
    var t = Instant.now()
    while t.elapsed() < d:
        pass


def test_RB1_unsolicited_bytes_never_answer_the_next_request() raises:
    var peer = HttpPeer()
    var c = Client()
    assert_equal(c.get(peer.url("/left")).text(), "first")
    assert_equal(c.idle_connections(), 0)  # was pooled with "EVIL!" unread
    assert_equal(c.get(peer.url("/hello")).text(), "hello")  # was "EVIL!"
    var h = c.head(peer.url("/head0"))  # then a stray "0\r\n\r\n"
    assert_equal(h.status, 200)
    assert_equal(c.idle_connections(), 0)
    assert_equal(c.get(peer.url("/hello")).text(), "hello")  # was InvalidData
    peer^.stop()


def test_RB3_the_deadline_bounds_a_response_that_keeps_coming() raises:
    var peer = HttpPeer()
    var c = Client(timeout=Duration.from_millis(500))
    var t = Instant.now()
    var deadline = False
    try:
        _ = c.get(peer.url("/drip"))  # a byte every 100 ms for 5 s
    except e:
        deadline = e.is_deadline()
    assert_true(deadline)
    assert_true(t.elapsed() < Duration.from_secs(2), String(t.elapsed()))
    var flood = Client(timeout=Duration.from_secs(3))
    t = Instant.now()
    var kind = String()
    try:
        _ = flood.get(peer.url("/1xx"))  # 100 Continue for 5 s
    except e:
        kind = String(e.kind)
    assert_equal(kind, "InvalidData")  # a bounded number of 1xx
    assert_true(t.elapsed() < Duration.from_secs(2), String(t.elapsed()))
    peer^.stop()


def test_RB7_bodies_are_sent_while_the_response_is_read() raises:
    var peer = HttpPeer()
    var c = Client(timeout=Duration.from_secs(20), max_body=64 * 1024 * 1024)
    var big = List[UInt8](length=32 * 1024 * 1024, fill=0x61)
    var echo = c.request("PUT", peer.url("/echo-stream"), Headers(), Span(big))
    assert_equal(len(echo.body), len(big))  # was a write deadlock (TimedOut)
    var t = Instant.now()
    var r = c.request("PUT", peer.url("/reject-hold"), Headers(), Span(big))
    assert_equal(r.status, 413)  # was TimedOut while writing
    assert_true(t.elapsed() < Duration.from_secs(4), String(t.elapsed()))
    assert_equal(c.idle_connections(), 0)  # its request never ended: not kept
    peer^.stop()


def test_RB12_bodies_beyond_64_MiB() raises:
    var peer = HttpPeer()
    var c = Client(timeout=Duration.from_secs(60))
    var big = List[UInt8](length=80 * 1024 * 1024, fill=0x62)
    var r = c.request("PUT", peer.url("/count"), Headers(), Span(big))
    assert_equal(r.text(), String(len(big)))  # was OutOfMemory
    peer^.stop()


def test_RB13_expired_connections_of_every_host_are_closed() raises:
    var peer = HttpPeer()
    var c = Client(max_idle=Duration.from_millis(50))
    _ = c.get(peer.url("/hello"))
    assert_equal(c.idle_connections(), 1)
    _wait(Duration.from_millis(200))
    _ = c.get(String("http://localhost:", peer.port, "/hello"))  # another key
    assert_equal(c.idle_connections(), 1)  # was 2: the expired one stayed
    peer^.stop()


def test_RB_duplicate_caller_host_is_refused_before_connecting() raises:
    var c = Client(timeout=Duration.from_millis(200))
    var h = Headers()
    h.add("Host", "a")
    h.add("Host", "b")
    var kind = String()
    try:
        _ = c.request("GET", "http://192.0.2.1/", h)  # unroutable: no time spent
    except e:
        kind = String(e.kind)
    assert_equal(kind, "InvalidInput")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
