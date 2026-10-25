"""Regression tests for the second http review: the `Client` findings, against
scripted routes of tests/http/http_peer.py. (The first review's are in
test_http_client_regressions.mojo; this review's codec findings are in
test_http_codec_regressions.mojo.)

- K1: when sending the body failed (the server reset the connection), a
  response delimited by the close was returned as whole: a reset can cut
  such a response short, and nothing tells the two apart. Only a response
  complete by its own framing is returned now; else the send error.
- K2: any early response stopped the upload, even a 200 that keeps the
  connection, so the server got part of the body and the caller could not
  tell. Below 300 and keeping the connection, the body is now sent whole.
- K3: while a body was being sent, reading the response ignored the
  deadline until EAGAIN, so a flood ran on to `max_body`.
- K4: idle connections were limited per host only; one per distinct host
  piled up (a crawler reached EMFILE). `max_idle_conns` bounds them all,
  the oldest going first.
- K5: a bracketed host had to be made of hex digits, `:` and `.` only, so
  `[127.0.0.1]` and `[1234]` passed for IPv6 literals.
- K6: a request with an `Upgrade` field was sent, though the client does
  not switch protocols (the docs said `InvalidInput`).
- K7: a 408 on a reused connection (the server's idle timeout racing the
  request, which it never ran) was returned; an idempotent request is now
  sent once more on a new connection.
"""

from std.testing import TestSuite, assert_equal, assert_true

from http.client import Client, Url
from http.headers import Headers
from linux import ErrorKind
from linux.time import Duration, Instant
from http_peer import HttpPeer


# ---- K1 ------------------------------------------------------------------------


def test_k1_a_reset_during_the_upload_is_an_error_unless_whole() raises:
    var peer = HttpPeer()
    var c = Client(timeout=Duration.from_secs(10))
    var big = List[UInt8](length=256 * 1024 * 1024, fill=0x61)
    for i in range(3):
        var outcome: String
        try:
            var r = c.request("PUT", peer.url("/rst-closedelim"), Headers(), Span(big))
            outcome = String(r.status, " ", r.text())  # was "200 PARTIAL"
        except e:
            outcome = String(e.kind)
        assert_true(outcome == "ConnectionReset" or outcome == "BrokenPipe", String(i, ": ", outcome))
    # A response whole by its Content-Length is still returned.
    var framed = c.request("PUT", peer.url("/rst-framed"), Headers(), Span(big))
    assert_equal(framed.status, 413)
    assert_equal(framed.text(), "full")
    peer^.stop()


# ---- K2 ------------------------------------------------------------------------


def test_k2_an_early_200_that_keeps_the_connection_gets_the_whole_body() raises:
    var peer = HttpPeer()
    var c = Client(timeout=Duration.from_secs(20))
    var big = List[UInt8](length=32 * 1024 * 1024, fill=0x62)
    var r = c.request("PUT", peer.url("/early-ok"), Headers(), Span(big))
    assert_equal(r.text(), "ok")
    assert_equal(c.idle_connections(), 1)  # (the request ended: kept)
    assert_equal(c.get(peer.url("/early-got")).text(), String(len(big)))  # was a few MiB
    peer^.stop()


# ---- K3 ------------------------------------------------------------------------


def test_k3_the_deadline_holds_while_an_upload_is_flooded() raises:
    var peer = HttpPeer()
    var c = Client(timeout=Duration.from_millis(50), max_body=512 * 1024 * 1024)
    var big = List[UInt8](length=64 * 1024 * 1024, fill=0x63)
    var t = Instant.now()
    var kind = String()
    try:
        _ = c.request("PUT", peer.url("/flood"), Headers(), Span(big))
    except e:
        kind = String(e.kind)
    var took = t.elapsed()
    assert_equal(kind, "TimedOut")  # (InvalidData at max_body, before)
    assert_true(took < Duration.from_millis(300), String(took))
    peer^.stop()


# ---- K4 ------------------------------------------------------------------------


def test_k4_idle_connections_are_bounded_in_all() raises:
    var a = HttpPeer()
    var b = HttpPeer()
    var d = HttpPeer()
    var c = Client(max_idle_conns=2)
    assert_equal(c.get(a.url("/conn")).text(), "1")
    assert_equal(c.get(b.url("/conn")).text(), "1")
    assert_equal(c.get(d.url("/conn")).text(), "1")
    assert_equal(c.idle_connections(), 2)  # was 3
    assert_equal(c.get(a.url("/conn")).text(), "2")  # (the oldest went)
    assert_equal(c.get(d.url("/conn")).text(), "1")  # (still kept)
    var none = Client(max_idle_conns=0)
    _ = none.get(a.url("/hello"))
    assert_equal(none.idle_connections(), 0)
    var refused = False
    try:
        _ = Client(max_idle_conns=-1)
    except e:
        refused = e.kind == ErrorKind.InvalidInput
    assert_true(refused)
    a^.stop()
    b^.stop()
    d^.stop()


# ---- K5 ------------------------------------------------------------------------


def test_k5_bracketed_hosts_are_ipv6_literals() raises:
    var bad: List[String] = [
        "http://[127.0.0.1]/",
        "http://[1234]/",
        "http://[::1::2]/",
        "http://[]/",
        "http://[1.2.3.4.5]:80/",
        "http://[12345::]/",
    ]
    for i in range(len(bad)):
        var kind = String("accepted")
        try:
            _ = Url.parse(bad[i])
        except e:
            kind = String(e.kind)
        assert_equal(kind, "InvalidInput", bad[i])
    var u = Url.parse("http://[::1]:8080/x")
    assert_equal(u.host, "::1")
    assert_equal(Int(u.port), 8080)
    assert_equal(Url.parse("http://[::ffff:127.0.0.1]/").host, "::ffff:127.0.0.1")
    assert_equal(Url.parse("http://[2001:DB8::a]/").host, "2001:DB8::a")


# ---- K6 ------------------------------------------------------------------------


def test_k6_a_request_with_upgrade_is_refused() raises:
    var peer = HttpPeer()
    var c = Client(timeout=Duration.from_secs(5))
    var h = Headers()
    h.add("Connection", "Upgrade")
    h.add("Upgrade", "websocket")
    var kind = String("sent")
    try:
        _ = c.request("GET", peer.url("/hello"), h)
    except e:
        kind = String(e.kind)
    assert_equal(kind, "InvalidInput")  # (was sent: 200 "hello")
    assert_equal(c.idle_connections(), 0)  # (refused before connecting)
    peer^.stop()


# ---- K7 ------------------------------------------------------------------------


def test_k7_a_408_on_a_reused_connection_is_retried_once() raises:
    var peer = HttpPeer()
    var c = Client(timeout=Duration.from_secs(5))
    assert_equal(c.get(peer.url("/stale408")).text(), "ok")
    var r = c.get(peer.url("/stale408"))  # reused: 408, then anew
    assert_equal(r.status, 200)  # was 408
    assert_equal(r.text(), "ok")
    # A POST is not sent again: its 408 is returned.
    var empty = List[UInt8]()
    var p = c.post(peer.url("/stale408"), Span(empty), "text/plain")
    assert_equal(p.status, 408)
    peer^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
