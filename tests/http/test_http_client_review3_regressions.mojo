"""Regression tests for the third http review (HR3, 2026-10-27; docs/http.md,
"Review"): the client, against Python's http.server
(tests/http/http_peer.py).

- CLI-1: `stream()` with a body stopped reading once a 2xx head came during
  the upload, so a server that answers as it reads (an echo) filled both
  directions and the request timed out. The body that comes meanwhile is
  now read and held (up to `max_body`).
- CLI-2: `release` pooled a connection another `Client` made, verified
  under that client's trust.
- CLI-3: a `StreamedResponse` did not keep its failure: after a reset, the
  next `read` saw the kernel's 0 and ended a close-delimited body cleanly.
- CLI-4: the retry after a dropped reused connection took another pooled
  one, which the server had dropped too.
- CLI-5: a body read to its last byte was not `is_done()`, so `release`
  closed its connection.
- CLI-6: `last_tls_error()` kept an earlier request's reason.
- And: a body under a transfer coding other than chunked (`gzip,
  chunked`) was delivered still coded; a Content-Length over `max_body`
  waited for the body; `Accept-Encoding: identity` by default; a caller's
  `TE` other than `trailers` refused; per-request `timeout` and
  `max_body`; errors that name their reason; an `EventStream`'s
  connection given back to the pool.
"""

from std.testing import TestSuite, assert_equal, assert_false, assert_true
from std.time import perf_counter_ns

from http.client import (
    E_FRAMING_FIELD,
    E_TOO_LARGE,
    E_URL_PORT,
    E_URL_SCHEME,
    E_URL_USERINFO,
    Client,
    EventStream,
    StreamedResponse,
    Url,
)
from http.body import E_TE_UNSUPPORTED
from http.headers import Headers
from http.sse import SseEvent
from linux import ErrorKind, IoError
from linux.time import Duration
from tls import ClientConfig, Trust
from http_peer import HttpPeer


def _request_error(mut c: Client, method: StringSlice, url: String, headers: Headers = Headers()) raises -> IoError:
    try:
        _ = c.request(method, url, headers)
    except e:
        return e
    raise Error(String("no error from ", url))


def _read_error(mut s: StreamedResponse) raises -> IoError:
    var buf = List[UInt8](length=4096, fill=0)
    try:
        while s.read(Span(buf)) > 0:
            pass
    except e:
        return e
    raise Error("the body ended without an error")


# ---- CLI-1 ---------------------------------------------------------------------


def test_cli1_a_streamed_upload_reads_an_echo_as_it_comes() raises:
    """/echo-stream answers at once and echoes each piece it reads. 32 MiB
    each way is more than both directions' socket buffers hold: before,
    the client waited only to write, and timed out."""
    comptime N = 32 * 1024 * 1024
    var peer = HttpPeer()
    var c = Client(timeout=Duration.from_secs(15), max_body=64 * 1024 * 1024)
    var body = List[UInt8](length=N, fill=UInt8(ord("e")))
    var s = c.stream("PUT", peer.url("/echo-stream"), Headers(), Span(body))
    assert_equal(s.status, 200)
    var got = s.read_all(2 * N)
    assert_equal(len(got), N)
    assert_true(s.is_done())
    c.release(s^)
    assert_equal(c.idle_connections(), 1)
    peer^.stop()


def test_cli1_what_is_held_meanwhile_is_bounded_by_max_body() raises:
    var peer = HttpPeer()
    var c = Client(timeout=Duration.from_secs(15), max_body=1024 * 1024)
    var body = List[UInt8](length=32 * 1024 * 1024, fill=UInt8(ord("e")))
    var failed = False
    try:
        _ = c.stream("PUT", peer.url("/echo-stream"), Headers(), Span(body))
    except e:
        failed = True
        assert_true(e.kind == ErrorKind.InvalidData, String(e))
        assert_equal(String(e.op), String(E_TOO_LARGE))
    assert_true(failed)
    peer^.stop()


# ---- CLI-2 ---------------------------------------------------------------------


def test_cli2_release_keeps_another_clients_connection_out() raises:
    var peer = HttpPeer(tls=True)
    var a = Client(timeout=Duration.from_secs(20), tls=ClientConfig(trust=Trust.ca_file(peer.ca())))
    var b = Client(timeout=Duration.from_secs(20), tls=ClientConfig(trust=Trust.ca_file(peer.pki + "/other.pem")))  # (it would refuse this peer)
    var s = a.stream("GET", peer.url("/hello"))
    _ = s.read_all()
    b.release(s^)
    assert_equal(b.idle_connections(), 0)
    var t = a.stream("GET", peer.url("/hello"))
    _ = t.read_all()
    a.release(t^)
    assert_equal(a.idle_connections(), 1)
    peer^.stop()


# ---- CLI-3 ---------------------------------------------------------------------


def test_cli3_a_stream_keeps_its_failure() raises:
    """/partial-rst: a close-delimited body, "partial", then a reset."""
    var peer = HttpPeer()
    var c = Client()
    var s = c.stream("GET", peer.url("/partial-rst"))
    var buf = List[UInt8](length=64, fill=0)
    assert_equal(s.read(Span(buf)), 7)
    var first = _read_error(s)
    assert_true(first.kind == ErrorKind.ConnectionReset, String(first))
    var again = _read_error(s)  # (before: the kernel's 0 ended the body cleanly)
    assert_true(again.kind == ErrorKind.ConnectionReset, String(again))
    assert_false(s.is_done())
    peer^.stop()


# ---- CLI-4 ---------------------------------------------------------------------


def test_cli4_the_retry_takes_a_new_connection() raises:
    """/flaky drops each connection's second request. Two pooled
    connections: the request takes one, which drops it; the retry took the
    other, dropped as well."""
    var peer = HttpPeer()
    var c = Client()
    var one = c.stream("GET", peer.url("/flaky"))
    var two = c.stream("GET", peer.url("/flaky"))
    _ = one.read_all()
    _ = two.read_all()
    c.release(one^)
    c.release(two^)
    assert_equal(c.idle_connections(), 2)
    var r = c.get(peer.url("/flaky"))
    assert_equal(r.status, 200)
    peer^.stop()


# ---- CLI-5 ---------------------------------------------------------------------


def test_cli5_a_body_read_to_its_last_byte_is_done() raises:
    var peer = HttpPeer()
    var c = Client()
    var s = c.stream("GET", peer.url("/big?n=1000"))
    var buf = List[UInt8](length=100, fill=0)
    var total = 0
    while total < 1000:
        total += s.read(Span(buf))
    assert_true(s.is_done())
    c.release(s^)
    assert_equal(c.idle_connections(), 1)
    var empty = c.stream("GET", peer.url("/big?n=0"))
    assert_true(empty.is_done())  # (no read needed)
    c.release(empty^)
    assert_equal(c.idle_connections(), 1)
    peer^.stop()


# ---- CLI-6 ---------------------------------------------------------------------


def test_cli6_last_tls_error_is_the_last_requests() raises:
    var tls = HttpPeer(tls=True)
    var plain = HttpPeer()
    var c = Client(timeout=Duration.from_secs(20), tls=ClientConfig(trust=Trust.ca_file(tls.pki + "/other.pem")))
    var e = _request_error(c, "GET", tls.url("/hello"))
    assert_true(e.kind == ErrorKind.PermissionDenied, String(e))
    assert_true(Bool(c.last_tls_error()))
    assert_equal(c.get(plain.url("/hello")).status, 200)
    assert_false(Bool(c.last_tls_error()))
    tls^.stop()
    plain^.stop()


# ---- transfer codings ----------------------------------------------------------


def test_a_body_under_another_coding_is_refused() raises:
    var peer = HttpPeer()
    var c = Client()
    for path in ["/te-gzip", "/te-http10"]:
        var e = _request_error(c, "GET", peer.url(path))
        assert_true(e.kind == ErrorKind.InvalidData, String(path, ": ", e))
        assert_equal(String(e.op), String(E_TE_UNSUPPORTED), path)
    # A HEAD's Transfer-Encoding describes a body that is not sent.
    assert_equal(c.head(peer.url("/te-gzip")).status, 200)
    peer^.stop()


def test_accept_encoding_identity_and_te() raises:
    var peer = HttpPeer()
    var c = Client()
    var lines = c.get(peer.url("/headers")).text()
    assert_true(lines.find("Accept-Encoding: identity\n") >= 0, lines)
    var own = Headers()
    own.add("Accept-Encoding", "gzip")
    var mine = c.request("GET", peer.url("/headers"), own).text()
    assert_true(mine.find("Accept-Encoding: gzip\n") >= 0, mine)
    assert_true(mine.find("identity") < 0, mine)
    var te = Headers()
    te.add("TE", "gzip")
    var e = _request_error(c, "GET", peer.url("/hello"), te)
    assert_true(e.kind == ErrorKind.InvalidInput, String(e))
    assert_equal(String(e.op), String(E_FRAMING_FIELD))
    var trailers = Headers()
    trailers.add("TE", "trailers")
    assert_equal(c.request("GET", peer.url("/hello"), trailers).status, 200)
    peer^.stop()


# ---- limits --------------------------------------------------------------------


def test_a_content_length_over_max_body_fails_at_the_head() raises:
    """/huge-cl announces 1 GiB and sends none of it: refused at once
    (before, the request waited for the body until its deadline)."""
    var peer = HttpPeer()
    var c = Client(timeout=Duration.from_secs(4))
    var t0 = perf_counter_ns()
    var e = _request_error(c, "GET", peer.url("/huge-cl"))
    assert_true(e.kind == ErrorKind.InvalidData, String(e))
    assert_equal(String(e.op), String(E_TOO_LARGE))
    assert_true(perf_counter_ns() - t0 < 2_000_000_000)
    peer^.stop()


def test_per_request_timeout_and_max_body() raises:
    var peer = HttpPeer()
    var c = Client()  # (30 s, 16 MiB)
    var t0 = perf_counter_ns()
    var slow = False
    try:
        _ = c.request("GET", peer.url("/slow"), timeout=Duration.from_millis(300))
    except e:
        slow = e.is_deadline()
    assert_true(slow)
    assert_true(perf_counter_ns() - t0 < 3_000_000_000)
    var big = False
    try:
        _ = c.request("GET", peer.url("/big?n=2000"), max_body=1000)
    except e:
        big = e.kind == ErrorKind.InvalidData
    assert_true(big)
    assert_equal(len(c.request("GET", peer.url("/big?n=2000"), max_body=2000).body), 2000)
    var bad = False
    try:
        _ = c.request("GET", peer.url("/hello"), timeout=Duration.ZERO)
    except e:
        bad = e.kind == ErrorKind.InvalidInput
    assert_true(bad)
    peer^.stop()


# ---- errors --------------------------------------------------------------------


def _url_error(text: StringSlice) raises -> String:
    try:
        _ = Url.parse(text)
    except e:
        assert_true(e.kind == ErrorKind.InvalidInput)
        return String(e.op)
    raise Error(String("accepted ", text))


def test_errors_name_their_reason() raises:
    assert_equal(_url_error("ftp://h/"), String(E_URL_SCHEME))
    assert_equal(_url_error("http://h:99999/"), String(E_URL_PORT))
    assert_equal(_url_error("http://u@h/"), String(E_URL_USERINFO))
    assert_equal(_url_error("http://h:80@evil/"), String(E_URL_USERINFO))


# ---- pooling streams ------------------------------------------------------------


def test_an_event_streams_connection_is_pooled() raises:
    var peer = HttpPeer()
    var c = Client()
    var id1 = c.get(peer.url("/conn")).text()
    var events = EventStream(c.stream("GET", peer.url("/sse?n=3")))
    var ev = SseEvent()
    var n = 0
    while events.next(ev):
        n += 1
    assert_equal(n, 4)  # (3, then [DONE])
    c.release(events^.into_response())
    assert_equal(c.idle_connections(), 1)
    assert_equal(c.get(peer.url("/conn")).text(), id1)
    peer^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
