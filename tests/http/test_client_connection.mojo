"""`http.connection.ClientConnection`: requests and their bodies on the
wire, response events (Content-Length, chunked with trailers, HEAD, 1xx,
close-delimited), upgrades and CONNECT, persistence and closing,
pipelining matched in order, end of input before and during a response,
protocol errors, request validation, and the same transcript whatever the
response split."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from http.connection import E_BAD_101, E_NO_RESPONSE, E_UNSOLICITED, ClientConnection, ClientEvent, EventKind
from http.headers import Headers
from http.parse import RequestHead, ResponseHead
from http.types import Version
from linux import ErrorKind, IoError


def _b(text: StringSlice) -> List[UInt8]:
    var out = List[UInt8]()
    for c in text.codepoints():
        out.append(UInt8(Int(c.to_u32())))
    return out^


def _get(target: StringSlice = "/", method: StringSlice = "GET") raises IoError -> RequestHead:
    var h = RequestHead(method, target)
    h.headers.add("Host", "example.com")
    return h^


def _sent(mut c: ClientConnection) raises IoError -> String:
    var out = ByteBuffer()
    while c.poll_transmit(out) > 0:
        pass
    return String(from_utf8_lossy=out.readable_span())


def _events(mut c: ClientConnection) raises IoError -> String:
    var out = String()
    while True:
        var ev = c.next_event()
        if not ev:
            return out^
        if out.byte_length() > 0:
            out += " / "
        out += String(ev.value())


def _error(mut c: ClientConnection) -> String:
    try:
        _ = _events(c)
        return "no error"
    except e:
        return String(e.kind, " ", e.op)


def _feed(mut c: ClientConnection, text: StringSlice) raises:
    c.feed(Span(_b(text)))


def _asked(target: StringSlice = "/", method: StringSlice = "GET") raises -> ClientConnection:
    """A connection that has sent one request without a body."""
    var c = ClientConnection()
    c.send_request(_get(target, method))
    c.end_request()
    _ = _sent(c)
    return c^


# ---- requests -----------------------------------------------------------------------


def test_requests_on_the_wire() raises:
    var c = ClientConnection()
    c.send_request(_get("/a?b=1"))
    c.end_request()
    assert_equal(_sent(c), "GET /a?b=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
    _feed(c, "HTTP/1.1 204 No Content\r\n\r\n")
    assert_equal(_events(c), "HEAD 204 HTTP/1.1 NONE / END")
    var p = _get("/up", "POST")
    p.headers.add("Content-Length", "5")
    c.send_request(p)
    c.send_body("hel".as_bytes())
    c.send_body("lo".as_bytes())
    c.end_request()
    assert_equal(_sent(c), "POST /up HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello")
    _feed(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    _ = _events(c)
    var s = _get("/stream", "PUT")
    s.headers.add("Transfer-Encoding", "chunked")
    c.send_request(s)
    c.send_body("abc".as_bytes())
    var t = Headers()
    t.add("X-Sum", "1")
    c.end_request(t)
    assert_equal(_sent(c), "PUT /stream HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Sum: 1\r\n\r\n")


def test_request_validation() raises:
    var bad = List[RequestHead]()
    bad.append(RequestHead("GET", "/"))  # no Host in HTTP/1.1
    var two = _get()
    two.headers.add("host", "b")
    bad.append(two^)
    var gz = _get()
    gz.headers.add("Transfer-Encoding", "gzip")
    bad.append(gz^)
    var both = _get()
    both.headers.add("Transfer-Encoding", "chunked")
    both.headers.add("Content-Length", "3")
    bad.append(both^)
    bad.append(RequestHead("GET", "/", Version(2, 0)))
    var badcl = _get()
    badcl.headers.add("Content-Length", "-1")
    bad.append(badcl^)
    bad.append(RequestHead("G T", "/", Version.HTTP_1_0))
    var n = 0
    for i in range(len(bad)):
        var c = ClientConnection()
        try:
            c.send_request(bad[i])
        except e:
            n += Int(e.kind == ErrorKind.InvalidInput)
        assert_equal(c.pending_transmit(), 0)
    assert_equal(n, 7)
    var ok = ClientConnection()
    ok.send_request(RequestHead("GET", "/", Version.HTTP_1_0))  # 1.0 needs no Host
    ok.end_request()


def test_send_side_misuse() raises:
    var c = ClientConnection()
    var n = 0
    try:
        c.send_body("x".as_bytes())
    except e:
        n += Int(e.kind == ErrorKind.InvalidInput)
    try:
        c.end_request()
    except e:
        n += Int(e.kind == ErrorKind.InvalidInput)
    var p = _get("/", "POST")
    p.headers.add("Content-Length", "2")
    c.send_request(p)
    try:
        c.send_request(_get())  # the first is still being written
    except e:
        n += Int(e.kind == ErrorKind.InvalidInput)
    try:
        c.send_body("abc".as_bytes())
    except e:
        n += Int(e.kind == ErrorKind.InvalidInput)
    try:
        c.end_request()  # short
    except e:
        n += Int(e.kind == ErrorKind.InvalidInput)
    c.send_body("ab".as_bytes())
    c.end_request()
    try:
        c.send_request(_get())  # max_in_flight = 1
    except e:
        n += Int(e.kind == ErrorKind.InvalidInput)
    assert_equal(n, 6)


# ---- responses ----------------------------------------------------------------------


def test_response_bodies() raises:
    var c = _asked()
    _feed(c, "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello")
    assert_equal(_events(c), "HEAD 200 HTTP/1.1 LENGTH(11) / DATA hello")
    _feed(c, " world")
    assert_equal(_events(c), "DATA  world / END")
    assert_true(c.is_idle())
    c.send_request(_get())
    c.end_request()
    _feed(c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\nX-T: 1\r\n\r\n")
    assert_equal(_events(c), "HEAD 200 HTTP/1.1 CHUNKED / DATA Wiki / END X-T: 1\r\n")
    assert_true(c.is_idle())


def test_head_and_no_body_statuses() raises:
    var c = _asked("/f", "HEAD")
    _feed(c, "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n")
    assert_equal(_events(c), "HEAD 200 HTTP/1.1 NONE / END")
    assert_true(c.is_idle())
    var n = _asked()
    _feed(n, "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n")
    assert_equal(_events(n), "HEAD 304 HTTP/1.1 NONE / END")


def test_informational_responses() raises:
    var c = _asked()
    _feed(c, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </s>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    assert_equal(_events(c), "INFORMATIONAL 100 HTTP/1.1 / INFORMATIONAL 103 HTTP/1.1 / HEAD 200 HTTP/1.1 LENGTH(2) / DATA ok / END")


def test_close_delimited_and_closing_responses() raises:
    var c = _asked()
    _feed(c, "HTTP/1.0 200 OK\r\n\r\nall of it")
    assert_equal(_events(c), "HEAD 200 HTTP/1.0 CLOSE / DATA all of it")
    assert_false(c.is_idle())
    c.feed_eof()
    assert_equal(_events(c), "END")
    assert_true(c.should_close())
    var k = _asked()
    _feed(k, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
    assert_equal(_events(k), "HEAD 200 HTTP/1.1 LENGTH(0) / END")
    assert_true(k.should_close())
    assert_false(k.is_idle())
    var refused = False
    try:
        k.send_request(_get())
    except e:
        refused = e.kind == ErrorKind.InvalidInput
    assert_true(refused)
    var a = ClientConnection()  # the client asks to close
    var h = _get()
    h.headers.add("Connection", "close")
    a.send_request(h)
    a.end_request()
    assert_true(a.should_close())
    _feed(a, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    assert_equal(_events(a), "HEAD 200 HTTP/1.1 LENGTH(0) / END")
    _feed(a, "HTTP/1.1 200 OK\r\n\r\n")  # after the last response: ignored
    assert_equal(_events(a), "")
    var ka = ClientConnection()  # HTTP/1.0 keep-alive
    var o = RequestHead("GET", "/", Version.HTTP_1_0)
    o.headers.add("Connection", "keep-alive")
    ka.send_request(o)
    ka.end_request()
    _feed(ka, "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 1\r\n\r\nx")
    assert_equal(_events(ka), "HEAD 200 HTTP/1.0 LENGTH(1) / DATA x / END")
    assert_true(ka.is_idle())


def test_upgrade_and_connect() raises:
    var c = ClientConnection()
    var h = _get("/chat")
    h.headers.add("Upgrade", "websocket")
    h.headers.add("Connection", "Upgrade")
    c.send_request(h)
    c.end_request()
    _feed(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x81\x02hi")
    assert_equal(_events(c), "UPGRADE 101 HTTP/1.1")
    assert_true(c.is_upgraded())
    assert_equal(len(c.take_remaining()), 4)
    assert_true(c.should_close())  # no more HTTP on it
    var p = _asked()
    _feed(p, "HTTP/1.1 101 Switching Protocols\r\n\r\n")
    assert_equal(_error(p), String("InvalidData ", E_BAD_101))
    var t = ClientConnection()
    var ch = RequestHead("CONNECT", "h:443")
    ch.headers.add("Host", "h:443")
    t.send_request(ch)
    t.end_request()
    _feed(t, "HTTP/1.1 200 Connection established\r\n\r\n\x16\x03")
    assert_equal(_events(t), "UPGRADE 200 HTTP/1.1")
    assert_equal(len(t.take_remaining()), 2)
    var r = ClientConnection()  # a refused CONNECT is an ordinary response
    r.send_request(ch)
    r.end_request()
    _feed(r, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 2\r\n\r\nno")
    assert_equal(_events(r), "HEAD 407 HTTP/1.1 LENGTH(2) / DATA no / END")


def test_pipelined_responses_match_in_order() raises:
    var c = ClientConnection(max_in_flight=3)
    c.send_request(_get("/1", "HEAD"))
    c.end_request()
    c.send_request(_get("/2"))
    c.end_request()
    c.send_request(_get("/3"))
    c.end_request()
    assert_equal(c.unanswered(), 3)
    _feed(c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloHTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
    assert_equal(_events(c), "HEAD 200 HTTP/1.1 NONE / END / HEAD 200 HTTP/1.1 LENGTH(5) / DATA hello / END / HEAD 200 HTTP/1.1 LENGTH(0) / END")
    assert_equal(c.unanswered(), 0)
    assert_true(c.should_close())


# ---- end of input and errors ------------------------------------------------------------


def test_end_of_input() raises:
    var c = _asked()
    c.feed_eof()  # nothing came back: safe to retry an idempotent request
    assert_equal(_error(c), String("UnexpectedEof ", E_NO_RESPONSE))
    var m = _asked()
    _feed(m, "HTTP/1.1 200 OK\r\nContent-")
    m.feed_eof()
    assert_equal(_error(m), "UnexpectedEof http: connection closed in a message head")
    var b = _asked()
    _feed(b, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc")
    b.feed_eof()
    assert_equal(_error(b), "UnexpectedEof http: body ended early")
    var idle = ClientConnection()  # the server closes an idle connection
    idle.feed_eof()
    assert_equal(_events(idle), "")
    assert_true(idle.should_close())


def test_protocol_errors() raises:
    var u = ClientConnection()
    _feed(u, "HTTP/1.1 200 OK\r\n\r\n")
    assert_equal(_error(u), String("InvalidData ", E_UNSOLICITED))
    var bad = _asked()
    _feed(bad, "HTTP/1.1 200 OK\r\nContent-Length: 5, 6\r\n\r\n")
    assert_equal(_error(bad), "InvalidData http: bad Content-Length")
    assert_true(bad.should_close())
    var chunk = _asked()
    _feed(chunk, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n")
    assert_equal(_error(chunk), "InvalidData http: bad chunk size")
    assert_equal(_error(chunk), "InvalidData http: bad chunk size")  # stays failed


# ---- chunking invariance --------------------------------------------------------------


def _client_run(input: List[UInt8], step: Int) raises -> String:
    var c = ClientConnection(max_in_flight=4)
    c.send_request(_get("/a"))
    c.end_request()
    c.send_request(_get("/b", "HEAD"))
    c.end_request()
    c.send_request(_get("/c"))
    c.end_request()
    c.send_request(_get("/d"))
    c.end_request()
    var transcript = String()
    var data = String()
    var at = 0
    while True:
        while True:
            var ev = c.next_event()
            if not ev:
                break
            if ev.value().kind == EventKind.DATA:
                data += String(from_utf8_lossy=Span(ev.value().data))
                continue
            if data.byte_length() > 0:
                transcript += String("DATA ", data, " / ")
                data = String()
            transcript += String(ev.value()) + " / "
        if at == len(input):
            c.feed_eof()
            break
        var n = len(input) - at if step == 0 else min(step, len(input) - at)
        n = min(n, c.feed_capacity())
        c.feed(Span(input)[at : at + n])
        at += n
    while True:
        var ev = c.next_event()
        if not ev:
            break
        if ev.value().kind == EventKind.DATA:
            data += String(from_utf8_lossy=Span(ev.value().data))
            continue
        if data.byte_length() > 0:
            transcript += String("DATA ", data, " / ")
            data = String()
        transcript += String(ev.value()) + " / "
    return transcript^


def test_same_transcript_whatever_the_split() raises:
    var input = _b(
        "HTTP/1.1 100 Continue\r\n\r\n"
        "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world"
        "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n"
        "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n5;x=1\nhello\n6\r\n world\r\n0\r\nT: 1\r\n\r\n"
        "HTTP/1.0 200 OK\r\n\r\nuntil the end"
    )
    var whole = _client_run(input, 0)
    assert_true(whole.find("DATA until the end / END") >= 0)
    for step in range(1, 14):
        assert_equal(_client_run(input, step), whole, String("step ", step))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
