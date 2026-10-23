"""`http.connection.ServerConnection`: requests and bodies as events, one
request at a time with backpressure, response framing and the headers the
codec adds, persistence, early responses, 100-continue and other 1xx,
upgrades and CONNECT, request errors and their statuses, end of input,
send-side misuse, and the same transcript whatever the input split."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from http.body import BodyLimits
from http.connection import EventKind, ServerConnection, ServerEvent
from http.headers import Headers
from http.parse import Limits, RequestHead, ResponseHead
from linux import ErrorKind, IoError
from linux.time import Duration, Instant


def _b(text: StringSlice) -> List[UInt8]:
    """Latin-1, so "\\xff" is one byte (see tests/http/test_parse.mojo)."""
    var out = List[UInt8]()
    for c in text.codepoints():
        out.append(UInt8(Int(c.to_u32())))
    return out^


def _feed(mut s: ServerConnection, text: StringSlice) raises:
    s.feed(Span(_b(text)))


def _events(mut s: ServerConnection) raises IoError -> String:
    """Every event available now, rendered, separated by " / "."""
    var out = String()
    while True:
        var ev = s.next_event()
        if not ev:
            return out^
        if out.byte_length() > 0:
            out += " / "
        out += String(ev.value())


def _sent(mut s: ServerConnection) raises IoError -> String:
    var out = ByteBuffer()
    while s.poll_transmit(out) > 0:
        pass
    return String(from_utf8_lossy=out.readable_span())


def _error(mut s: ServerConnection) -> String:
    """The error the next `next_event` raises, as "<status> <kind> <op>"."""
    try:
        _ = _events(s)
        return "no error"
    except e:
        return String(s.error_status(), " ", e.kind, " ", e.op)


def _ok(mut s: ServerConnection, body: StringSlice = "") raises:
    var r = ResponseHead(200)
    r.headers.add("Content-Length", String(body.byte_length()))
    s.send_response(r)
    s.send_body(body.as_bytes())
    s.end_response()


def _misuse(e: IoError) -> Bool:
    return e.kind == ErrorKind.InvalidInput


# ---- requests -----------------------------------------------------------------------


def test_requests_and_bodies_become_events() raises:
    var s = ServerConnection()
    _feed(s, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_equal(_events(s), "HEAD GET /a HTTP/1.1 NONE / END")
    _ok(s, "hi")
    assert_equal(_sent(s), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
    assert_false(s.should_close())
    _feed(s, "POST /b HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhel")
    assert_equal(_events(s), "HEAD POST /b HTTP/1.1 LENGTH(5) / DATA hel")
    _feed(s, "lo")
    assert_equal(_events(s), "DATA lo / END")
    _ok(s)
    _feed(s, "PUT /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Sum: 9\r\n\r\n")
    assert_equal(_events(s), "HEAD PUT /c HTTP/1.1 CHUNKED / DATA abc / END X-Sum: 9\r\n")


def test_event_payloads_move_out() raises:
    var s = ServerConnection()
    _feed(s, "POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nxyz")
    var first = s.next_event()
    var ev = first.take()
    assert_true(ev.kind == EventKind.HEAD)
    var head = ev.take_head()
    assert_equal(head.target, "/up")
    assert_equal(String(head.headers.get("host").value()), "h")
    var second = s.next_event()
    var d = second.take()
    var data = d.take_data()
    assert_equal(len(data), 3)
    assert_equal(len(d.data), 0)
    var again = False
    try:
        _ = ev.take_head()
    except e:
        again = _misuse(e)
    assert_true(again)


def test_one_request_at_a_time_with_backpressure() raises:
    var s = ServerConnection(limits=Limits(max_head=64), body_limits=BodyLimits(max_trailers=64, max_chunk_line=32), max_buffered=80)
    _feed(s, "GET /1 HTTP/1.1\r\nHost: x\r\n\r\nGET /2 HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_equal(_events(s), "HEAD GET /1 HTTP/1.1 NONE / END")  # /2 waits
    var room = s.feed_capacity()
    assert_equal(room, 80 - 28)  # the second request is held
    _feed(s, String("G") * room)  # the buffer fills up: no more room
    assert_equal(s.feed_capacity(), 0)
    assert_equal(_events(s), "")
    _ok(s)
    assert_equal(_events(s), "HEAD GET /2 HTTP/1.1 NONE / END")
    assert_equal(s.feed_capacity(), 28)  # /2's bytes were consumed
    _ok(s)
    assert_equal(_events(s), "")  # 52 bytes of G: no head yet, under max_head
    _feed(s, String("G") * 12)
    assert_equal(_error(s), String("431 InvalidData http: head too large"))


# ---- responses ----------------------------------------------------------------------


def _one(request: StringSlice) raises -> ServerConnection:
    """A connection that has received `request` and delivered its events."""
    var s = ServerConnection()
    _feed(s, request)
    _ = _events(s)
    return s^


def test_response_framing_and_added_headers() raises:
    # no length from the application: chunked to HTTP/1.1...
    var s = _one("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    s.send_response(ResponseHead(200))
    s.send_body("abc".as_bytes())
    var t = Headers()
    t.add("X-Sum", "1")
    s.end_response(t)
    assert_equal(_sent(s), "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Sum: 1\r\n\r\n")
    assert_false(s.should_close())
    # ...and close-delimited to HTTP/1.0, which then closes
    var o = _one("GET / HTTP/1.0\r\n\r\n")
    o.send_response(ResponseHead(200, "Fine"))
    o.send_body("abc".as_bytes())
    o.end_response()
    assert_equal(_sent(o), "HTTP/1.1 200 Fine\r\nConnection: close\r\n\r\nabc")
    assert_true(o.should_close())
    # the application's own chunked
    var c = _one("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    var h = ResponseHead(201)
    h.headers.add("Transfer-Encoding", "chunked")
    c.send_response(h)
    c.end_response()
    assert_equal(_sent(c), "HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")


def test_responses_without_a_body() raises:
    var s = _one("HEAD /f HTTP/1.1\r\nHost: x\r\n\r\n")
    var h = ResponseHead(200)
    h.headers.add("Content-Length", "1234")  # what GET would send
    s.send_response(h)
    s.send_body("the GET body".as_bytes())  # dropped for HEAD
    s.end_response()
    assert_equal(_sent(s), "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n")
    var nc = _one("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    nc.send_response(ResponseHead(204))
    var refused = False
    try:
        nc.send_body("x".as_bytes())  # a 204 has no body
    except e:
        refused = _misuse(e)
    assert_true(refused)
    for status in [204, 304]:
        var n = _one("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        n.send_response(ResponseHead(status))
        n.end_response()
        assert_equal(_sent(n), String("HTTP/1.1 ", status, " ", "No Content" if status == 204 else "Not Modified", "\r\n\r\n"))
        assert_false(n.should_close())


def test_persistence() raises:
    var c = _one("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    _ok(c)
    assert_equal(_sent(c), "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    assert_true(c.should_close())
    var k = _one("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
    _ok(k)
    assert_equal(_sent(k), "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
    assert_false(k.should_close())
    var a = _one("GET / HTTP/1.1\r\nHost: x\r\n\r\n")  # the application closes
    var h = ResponseHead(200)
    h.headers.add("Connection", "close")
    h.headers.add("Content-Length", "0")
    a.send_response(h)
    a.end_response()
    assert_equal(_sent(a), "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
    assert_true(a.should_close())
    _feed(a, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")  # ignored after the close
    assert_equal(_events(a), "")


def test_early_response_reads_a_small_rest_or_closes() raises:
    # Answered before the body ended: a known rest within 256 KiB is still
    # read (its events delivered) and the connection kept...
    var s = ServerConnection()
    _feed(s, "POST /small HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123")
    assert_equal(_events(s), "HEAD POST /small HTTP/1.1 LENGTH(10) / DATA 0123")
    var r = ResponseHead(413)
    r.headers.add("Content-Length", "0")
    s.send_response(r)
    s.end_response()
    assert_false(s.should_close())
    assert_equal(_sent(s), "HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n")
    _feed(s, "456789GET /next HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_equal(_events(s), "DATA 456789 / END / HEAD GET /next HTTP/1.1 NONE / END")
    # ...a larger or unknown rest closes, and the response says so
    var big = ServerConnection()
    _feed(big, "POST /big HTTP/1.1\r\nHost: x\r\nContent-Length: 10000000\r\n\r\n0123")
    _ = _events(big)
    big.send_response(r)
    big.end_response()
    assert_true(big.should_close())
    assert_equal(_sent(big), "HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    _feed(big, "45678")
    assert_equal(_events(big), "")
    var ch = ServerConnection()
    _feed(ch, "POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n0123\r\n")
    _ = _events(ch)
    ch.send_response(r)
    ch.end_response()
    assert_true(ch.should_close())
    assert_true(_sent(ch).find("Connection: close") >= 0)


def test_full_duplex_response_keeps_alive() raises:
    # Answering while the body arrives (an echo) keeps the connection when
    # the body ends before the response does.
    var s = ServerConnection()
    _feed(s, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nab")
    assert_equal(_events(s), "HEAD POST /echo HTTP/1.1 LENGTH(4) / DATA ab")
    s.send_response(ResponseHead(200))
    s.send_body("ab".as_bytes())
    _feed(s, "cd")
    assert_equal(_events(s), "DATA cd / END")
    s.send_body("cd".as_bytes())
    s.end_response()
    assert_false(s.should_close())
    _feed(s, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_equal(_events(s), "HEAD GET / HTTP/1.1 NONE / END")


def test_continue_and_informational() raises:
    var s = _one("POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n")
    s.send_continue()
    var hints = ResponseHead(103)
    hints.headers.add("Link", "</s.css>; rel=preload")
    s.send_informational(hints)
    assert_equal(_sent(s), "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n")
    var old = _one("POST / HTTP/1.0\r\nContent-Length: 2\r\n\r\n")
    old.send_continue()  # never to HTTP/1.0
    old.send_informational(ResponseHead(103))
    assert_equal(_sent(old), "")
    var kinds = 0
    for status in [101, 200, 99]:
        try:
            s.send_informational(ResponseHead(status))
        except e:
            kinds += Int(_misuse(e))
    assert_equal(kinds, 3)


def test_upgrade_and_connect() raises:
    var s = ServerConnection()
    _feed(s, "GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x81\x05hello")
    assert_equal(_events(s), "HEAD GET /chat HTTP/1.1 NONE / END")
    var h = ResponseHead(101)
    h.headers.add("Upgrade", "websocket")
    h.headers.add("Connection", "Upgrade")
    s.send_response(h)
    assert_true(s.is_upgraded())
    assert_equal(_sent(s), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
    var rest = s.take_remaining()
    assert_equal(len(rest), 7)
    assert_equal(Int(rest[0]), 0x81)
    assert_false(s.should_close())
    var plain = _one("GET / HTTP/1.1\r\nHost: x\r\n\r\n")  # 101 needs an Upgrade request
    var refused = False
    try:
        plain.send_response(ResponseHead(101))
    except e:
        refused = _misuse(e)
    assert_true(refused)
    var t = _one("CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\n")
    var bad = ResponseHead(200)
    bad.headers.add("Content-Length", "0")  # never on a 2xx to CONNECT
    refused = False
    try:
        t.send_response(bad)
    except e:
        refused = _misuse(e)
    assert_true(refused)
    t.send_response(ResponseHead(200))
    assert_true(t.is_upgraded())


# ---- request errors -----------------------------------------------------------------


def test_request_errors_carry_their_status() raises:
    var cases: List[Tuple[String, String]] = [
        ("GET  / HTTP/1.1\r\n\r\n", "400 InvalidData http: bad request line"),
        ("GET / HTTP/2.0\r\nHost: x\r\n\r\n", "505 InvalidData http: unsupported HTTP version"),
        ("GET / HTTP/1.1\r\n\r\n", "400 InvalidData http: missing or repeated Host"),
        ("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", "400 InvalidData http: missing or repeated Host"),
        ("GET / HTTP/1.0\r\nHost: a\r\nhost: b\r\n\r\n", "400 InvalidData http: missing or repeated Host"),
        ("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", "501 Unsupported http: unsupported transfer coding"),
        ("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n", "400 InvalidData http: Transfer-Encoding with Content-Length"),
        ("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", "400 InvalidData http: bad chunk size"),
        (String("GET /", "a" * 9000, " HTTP/1.1\r\n\r\n"), "414 InvalidData http: start line too long"),
        (String("GET / HTTP/1.1\r\n", "X: y\r\n" * 101, "\r\n"), "431 InvalidData http: too many field lines"),
    ]
    for c in cases:
        var s = ServerConnection()
        _feed(s, c[0])
        assert_equal(_error(s), c[1], String(c[0][byte=0 : min(40, c[0].byte_length())]))
        assert_true(s.should_close())
        assert_equal(_error(s), c[1])  # stays failed (rule 6)
        s.send_error(s.error_status())
        assert_true(_sent(s).startswith(String("HTTP/1.1 ", s.error_status(), " ")))


def test_send_error_answers_with_a_closing_response() raises:
    var s = ServerConnection()
    _feed(s, "BAD\r\n\r\n")
    _ = _error(s)
    s.send_error(s.error_status())
    assert_equal(_sent(s), "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    var reject = _one("GET /admin HTTP/1.1\r\nHost: x\r\n\r\n")  # a valid request refused
    assert_false(reject.should_close())
    reject.send_error(403)
    assert_true(reject.should_close())
    assert_equal(_sent(reject), "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    _feed(reject, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")  # ignored
    assert_equal(_events(reject), "")
    var refused = False
    var t = _one("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    t.send_response(ResponseHead(200))
    try:
        t.send_error(500)  # a response is under way: just close
    except e:
        refused = _misuse(e)
    assert_true(refused)


# ---- end of input -------------------------------------------------------------------


def test_end_of_input() raises:
    var s = ServerConnection()
    _feed(s, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    s.feed_eof()  # a client that half-closes after its request
    assert_equal(_events(s), "HEAD GET / HTTP/1.1 NONE / END")
    assert_false(s.should_close())  # the request is still answered
    _ok(s, "x")
    assert_true(s.should_close())
    var clean = ServerConnection()
    _feed(clean, "\r\n")
    clean.feed_eof()  # between requests (line ends left over): no error
    assert_equal(_events(clean), "")
    assert_true(clean.should_close())
    var mid = ServerConnection()
    _feed(mid, "GET / HT")
    mid.feed_eof()
    assert_equal(_error(mid), "400 UnexpectedEof http: connection closed in a message head")
    var body = ServerConnection()
    _feed(body, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 9\r\n\r\nabc")
    body.feed_eof()
    assert_equal(_error(body), "400 UnexpectedEof http: body ended early")
    var late = False
    try:
        body.feed(Span(_b("x")))
    except e:
        late = e.kind == ErrorKind.UnexpectedEof  # poisoned: the same error
    assert_true(late)


# ---- send-side misuse ---------------------------------------------------------------


def test_send_side_misuse_is_refused_without_poisoning() raises:
    var s = ServerConnection()
    var n = 0
    try:
        s.send_response(ResponseHead(200))  # no request yet
    except e:
        n += Int(_misuse(e))
    _feed(s, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    _ = _events(s)
    for status in [100, 600, 99]:
        try:
            s.send_response(ResponseHead(status))
        except e:
            n += Int(_misuse(e))
    try:
        s.send_body("x".as_bytes())  # before the head
    except e:
        n += Int(_misuse(e))
    var bad = ResponseHead(200)
    bad.headers.add("Content-Length", "x")
    try:
        s.send_response(bad)
    except e:
        n += Int(_misuse(e))
    var two = ResponseHead(200)
    two.headers.add("Content-Length", "1")
    two.headers.add("Transfer-Encoding", "chunked")
    try:
        s.send_response(two)
    except e:
        n += Int(_misuse(e))
    var nc = ResponseHead(204)
    nc.headers.add("Content-Length", "0")
    try:
        s.send_response(nc)
    except e:
        n += Int(_misuse(e))
    var cl = ResponseHead(200)
    cl.headers.add("Content-Length", "2")
    s.send_response(cl)
    try:
        s.send_body("abc".as_bytes())  # past the length
    except e:
        n += Int(_misuse(e))
    s.send_body("a".as_bytes())
    try:
        s.end_response()  # short of it
    except e:
        n += Int(_misuse(e))
    var t = Headers()
    t.add("X", "1")
    s.send_body("b".as_bytes())
    try:
        s.end_response(t)  # trailers need chunked
    except e:
        n += Int(_misuse(e))
    s.end_response()
    try:
        s.end_response()
    except e:
        n += Int(_misuse(e))
    assert_equal(n, 12)
    assert_equal(_sent(s), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nab")
    _feed(s, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")  # still usable
    assert_equal(_events(s), "HEAD GET / HTTP/1.1 NONE / END")


# ---- chunking invariance --------------------------------------------------------------


def _serve(input: List[UInt8], step: Int) raises -> String:
    """Feed `input` `step` bytes at a time (0: whole) within
    `feed_capacity()`, answer each request with its body length, and
    return the events and everything sent."""
    var s = ServerConnection(max_buffered=96 * 1024)
    var transcript = String()
    var at = 0
    var got = 0
    var data = String()  # consecutive DATA pieces, merged (rule 4)
    while True:
        while True:
            var ev = s.next_event()
            if not ev:
                break
            if ev.value().kind == EventKind.DATA:
                got += len(ev.value().data)
                data += String(from_utf8_lossy=Span(ev.value().data))
                continue
            if data.byte_length() > 0:
                transcript += String("DATA ", data, " / ")
                data = String()
            transcript += String(ev.value()) + " / "
            if ev.value().kind == EventKind.END:
                var r = ResponseHead(200)
                var body = String("got ", got)
                r.headers.add("Content-Length", String(body.byte_length()))
                s.send_response(r)
                s.send_body(body.as_bytes())
                s.end_response()
                got = 0
        if at == len(input):
            break
        var n = len(input) - at if step == 0 else min(step, len(input) - at)
        n = min(n, s.feed_capacity())
        s.feed(Span(input)[at : at + n])
        at += n
    return transcript + _sent(s)


def test_same_transcript_whatever_the_split() raises:
    var input = _b(
        "\r\nGET /a HTTP/1.1\r\nHost: x\r\n\r\n"
        "POST /b HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world"
        "PUT /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5;e=1\r\nhello\r\n6\r\n world\r\n0\r\nT: 1\r\n\r\n"
        "GET /d HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"
        "GET /e HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        "GET /ignored HTTP/1.1\r\nHost: x\r\n\r\n"
    )
    var whole = _serve(input, 0)
    assert_true(whole.find("got 11") >= 0)
    assert_true(whole.find("/ignored") < 0)
    for step in range(1, 14):
        var t = _serve(input, step)
        assert_equal(t, whole, String("step ", step))


# ---- time -----------------------------------------------------------------------------


def test_deadline() raises:
    var s = ServerConnection()
    assert_false(s.next_deadline())
    var t0 = Instant.now()
    var at = t0 + Duration.from_millis(100)
    s.set_deadline(at)
    assert_true(s.next_deadline().value() == at)
    s.handle_timeout(t0)  # early: nothing
    var timed_out = False
    try:
        s.handle_timeout(at)
    except e:
        timed_out = e.kind == ErrorKind.TimedOut
    assert_true(timed_out)
    assert_false(s.next_deadline())
    _feed(s, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")  # not poisoned
    assert_equal(_events(s), "HEAD GET / HTTP/1.1 NONE / END")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
