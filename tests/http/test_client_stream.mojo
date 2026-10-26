"""`Client.stream` and `EventStream` (milestone H7) against Python's
http.server (tests/http/http_peer.py): a body read as it arrives, the idle
and total timeouts, release to the pool, server-sent events over http and
https, and cancellation by dropping the stream, which the server sees."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true
from std.time import perf_counter_ns, sleep

from http.client import Client, EventStream, StreamedResponse
from http.headers import Headers
from http.sse import SseEvent
from linux import ErrorKind, IoError
from linux.time import Duration
from tls import ClientConfig, Trust
from http_peer import HttpPeer


def _read_error(mut s: StreamedResponse) raises -> IoError:
    var buf = List[UInt8](length=4096, fill=0)
    try:
        while s.read(Span(buf)) > 0:
            pass
    except e:
        return e
    raise Error("the body ended without an error")


def test_body_as_it_arrives() raises:
    """/drip sends one byte every 100 ms: the first comes long before the
    last, and each read returns what has arrived."""
    var peer = HttpPeer()
    var c = Client()
    var t0 = perf_counter_ns()
    var s = c.stream("GET", peer.url("/drip"))
    assert_equal(s.status, 200)
    var buf = List[UInt8](length=64, fill=0)
    var n = s.read(Span(buf))
    var first = perf_counter_ns() - t0
    assert_true(n >= 1 and n < 50, String(n))
    assert_true(first < 2_000_000_000, String(first))
    var total = n
    while True:
        var k = s.read(Span(buf))
        if k == 0:
            break
        total += k
    assert_equal(total, 50)
    assert_true(s.is_done())
    c.release(s^)
    assert_equal(c.idle_connections(), 1)
    peer^.stop()


def test_large_body_and_reuse() raises:
    var peer = HttpPeer()
    var c = Client()
    var s = c.stream("GET", peer.url("/big?n=3000000"))
    var body = s.read_all()
    assert_equal(len(body), 3000000)
    c.release(s^)
    var id1 = c.get(peer.url("/conn")).text()
    var again = c.stream("GET", peer.url("/conn"))
    assert_equal(String(unsafe_from_utf8=Span(again.read_all())), id1)  # (the pooled connection)
    c.release(again^)
    assert_equal(c.idle_connections(), 1)
    # Not read to its end: not pooled (the pooled one it took is closed).
    var partial = c.stream("GET", peer.url("/big?n=1000000"))
    var buf = List[UInt8](length=10, fill=0)
    _ = partial.read(Span(buf))
    c.release(partial^)
    assert_equal(c.idle_connections(), 0)
    peer^.stop()


def test_idle_and_total_timeouts() raises:
    var peer = HttpPeer()
    var c = Client()
    var s = c.stream("GET", peer.url("/drip"), idle_timeout=Duration.from_millis(30))
    var e = _read_error(s)
    assert_true(e.is_deadline(), String(e))
    var t = c.stream("GET", peer.url("/drip"), total=Duration.from_millis(350))
    var e2 = _read_error(t)
    assert_true(e2.is_deadline(), String(e2))
    peer^.stop()


def test_server_sent_events() raises:
    var peer = HttpPeer()
    var c = Client()
    var events = EventStream(c.stream("GET", peer.url("/sse?n=5")))
    var ev = SseEvent()
    var got = List[String]()
    while events.next(ev):
        got.append(String(ev.event, " ", ev.id, " ", ev.data))
    assert_equal(len(got), 6)
    assert_equal(got[0], "tick 1 n=1")
    assert_equal(got[1], "message 2 n=2")
    assert_equal(got[4], "tick 5 n=5")
    assert_equal(got[5], "message 5 [DONE]")  # (the ID carries over)
    assert_equal(events.last_event_id(), "5")
    peer^.stop()


def test_server_sent_events_over_https() raises:
    var peer = HttpPeer(tls=True)
    var c = Client(tls=ClientConfig(trust=Trust.ca_file(peer.ca())))
    var events = EventStream(c.stream("GET", peer.url("/sse?n=3")))
    var ev = SseEvent()
    var n = 0
    while events.next(ev):
        n += 1
    assert_equal(n, 4)
    peer^.stop()


def test_cancel_by_dropping() raises:
    """Dropping a stream closes its connection: the server's next write
    fails, and it counts a cancelled stream (no zombie generation)."""
    var peer = HttpPeer()
    var c = Client()
    var events = EventStream(c.stream("GET", peer.url("/sse-forever")))
    var ev = SseEvent()
    for _ in range(3):
        assert_true(events.next(ev))
    _ = events^
    var cancelled = String()
    for _ in range(100):
        sleep(0.02)
        cancelled = c.get(peer.url("/cancelled")).text()
        if cancelled == "1":
            break
    assert_equal(cancelled, "1")
    peer^.stop()


def test_event_stream_needs_its_type() raises:
    var peer = HttpPeer()
    var c = Client()
    var s = c.stream("GET", peer.url("/not-sse"))
    assert_equal(_open_error(s^).kind, ErrorKind.InvalidData)
    # The media type exactly, in any case, with or without parameters.
    var refused: List[String] = ["text/event-streamer", "text/event-stream-x;a=b", "text/events", "%20"]
    for t in refused:
        assert_equal(_open_error(c.stream("GET", peer.url(String("/typed?t=", t)))).kind, ErrorKind.InvalidData, t)
    var taken: List[String] = ["Text/Event-Stream", "text/event-stream;charset=utf-8", "text/event-stream%20;%20charset=utf-8"]
    for t in taken:
        var events = EventStream(c.stream("GET", peer.url(String("/typed?t=", t))))
        var ev = SseEvent()
        assert_true(events.next(ev), t)
        assert_equal(ev.data, "no")
    peer^.stop()


def _open_error(var s: StreamedResponse) raises -> IoError:
    try:
        _ = EventStream(s^)
    except e:
        return e
    raise Error("a body that is not an event stream was read as events")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
