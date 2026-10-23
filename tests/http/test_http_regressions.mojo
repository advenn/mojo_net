"""Regression tests for the independent review of the http package (codec
level; the client's are in test_http_client_regressions.mojo). Each test
names the finding it covers: R-B<n> from the review of connections and the
client, R-A<n> from the review of parsing and framing."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from http.body import BodyDecoder, BodyKind, BodyLimits, Framing, Piece, request_framing, response_framing
from http.connection import E_BAD_101, ClientConnection, EventKind, ServerConnection
from http.headers import Headers
from http.parse import RequestHead, ResponseHead
from http.types import Version
from linux import ErrorKind, IoError


def _b(text: StringSlice) -> List[UInt8]:
    """Latin-1, so "\\xff" is one byte."""
    var out = List[UInt8]()
    for c in text.codepoints():
        out.append(UInt8(Int(c.to_u32())))
    return out^


def _srv_events(mut s: ServerConnection) raises IoError -> String:
    var out = String()
    while True:
        var ev = s.next_event()
        if not ev:
            return out^
        if out.byte_length() > 0:
            out += " / "
        out += String(ev.value())


def _cli_events(mut c: ClientConnection) raises IoError -> String:
    var out = String()
    while True:
        var ev = c.next_event()
        if not ev:
            return out^
        if out.byte_length() > 0:
            out += " / "
        out += String(ev.value())


def _srv_sent(mut s: ServerConnection) raises IoError -> String:
    var out = ByteBuffer()
    while s.poll_transmit(out) > 0:
        pass
    return String(from_utf8_lossy=out.readable_span())


def _get(target: StringSlice = "/", version: Version = Version.HTTP_1_1) raises IoError -> RequestHead:
    var h = RequestHead("GET", target, version)
    if version.at_least_1_1():
        h.headers.add("Host", "h")
    return h^


def _asked(target: StringSlice = "/") raises IoError -> ClientConnection:
    var c = ClientConnection()
    c.send_request(_get(target))
    c.end_request()
    var out = ByteBuffer()
    _ = c.poll_transmit(out)
    return c^


def _ok(mut s: ServerConnection, body: StringSlice) raises IoError:
    var r = ResponseHead(200)
    r.headers.add("Content-Length", String(body.byte_length()))
    s.send_response(r)
    s.send_body(body.as_bytes())
    s.end_response()


def _misuse(e: IoError) -> Bool:
    return e.kind == ErrorKind.InvalidInput


# ---- review of connections and the client ----------------------------------------------


def test_RB1_leftover_bytes_after_the_last_response_are_never_a_response() raises:
    var c = _asked("/a")
    c.feed(Span(_b("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nevil")))
    assert_equal(_cli_events(c), "HEAD 200 HTTP/1.1 LENGTH(2) / DATA ok / END")
    assert_false(c.is_idle())  # was True: the next request got "evil"
    assert_true(c.should_close())
    var refused = False
    try:
        c.send_request(_get("/b"))
    except e:
        refused = _misuse(e)
    assert_true(refused)
    # a stray CRLF is not a response either, but it is harmless
    var crlf = _asked()
    crlf.feed(Span(_b("HTTP/1.1 204 No Content\r\n\r\n\r\n")))
    assert_equal(_cli_events(crlf), "HEAD 204 HTTP/1.1 NONE / END")
    assert_true(crlf.is_idle())


def test_RB2_answering_on_the_head_event_keeps_alive() raises:
    var s = ServerConnection()
    s.feed(Span(_b("GET /1 HTTP/1.1\r\nHost: x\r\n\r\nGET /2 HTTP/1.1\r\nHost: x\r\n\r\n")))
    var first = s.next_event()
    assert_true(first.value().kind == EventKind.HEAD)
    _ok(s, "one")  # before the END event was polled
    assert_false(s.should_close())  # was True, without Connection: close
    assert_equal(_srv_events(s), "END / HEAD GET /2 HTTP/1.1 NONE / END")
    _ok(s, "two")
    assert_equal(_srv_sent(s), "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\noneHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo")


def test_RB4_should_close_waits_for_a_buffered_request() raises:
    var s = ServerConnection()
    s.feed(Span(_b("GET /1 HTTP/1.1\r\nHost: x\r\n\r\nGET /2 HTTP/1.1\r\nHost: x\r\n\r\n")))
    s.feed_eof()
    _ = _srv_events(s)
    _ok(s, "a")
    assert_false(s.should_close())  # was True: /2 would go unanswered
    assert_equal(_srv_events(s), "HEAD GET /2 HTTP/1.1 NONE / END")
    _ok(s, "b")
    assert_true(s.should_close())


def test_RB5_no_request_on_a_connection_that_ended() raises:
    var c = ClientConnection()
    c.feed_eof()
    _ = _cli_events(c)
    var refused = False
    try:
        c.send_request(_get())  # was accepted, then never answered
    except e:
        refused = _misuse(e)
    assert_true(refused)
    assert_equal(c.pending_transmit(), 0)


def test_RB6_no_switch_before_the_request_body_is_read() raises:
    var s = ServerConnection()
    s.feed(Span(_b("POST /u HTTP/1.1\r\nHost: x\r\nUpgrade: x\r\nConnection: upgrade\r\nContent-Length: 10\r\n\r\n01234")))
    _ = _srv_events(s)
    var r = ResponseHead(101)
    r.headers.add("Upgrade", "x")
    var refused = False
    try:
        s.send_response(r)
    except e:
        refused = _misuse(e)
    assert_true(refused)
    s.feed(Span(_b("56789NEWPROTO")))
    assert_equal(_srv_events(s), "DATA 56789 / END")
    s.send_response(r)  # now the body is read
    assert_true(s.is_upgraded())
    assert_equal(String(from_utf8_lossy=Span(s.take_remaining())), "NEWPROTO")
    var t = ServerConnection()  # CONNECT has no content (RFC 9110 9.3.6)
    t.feed(Span(_b("CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\nContent-Length: 5\r\n\r\nhello")))
    var status = 0
    try:
        _ = _srv_events(t)
    except:
        status = t.error_status()
    assert_equal(status, 400)


def test_RB8_no_101_for_http_1_0() raises:
    var s = ServerConnection()
    s.feed(Span(_b("GET /u HTTP/1.0\r\nUpgrade: x\r\nConnection: upgrade\r\n\r\n")))
    _ = _srv_events(s)
    var refused = False
    try:
        s.send_response(ResponseHead(101))
    except e:
        refused = _misuse(e)
    assert_true(refused)
    var c = ClientConnection()
    var h = _get("/u", Version.HTTP_1_0)
    h.headers.add("Upgrade", "x")
    h.headers.add("Connection", "upgrade")
    c.send_request(h)
    c.end_request()
    c.feed(Span(_b("HTTP/1.1 101 Switching Protocols\r\n\r\n")))
    var op = String()
    try:
        _ = _cli_events(c)
    except e:
        op = String(e.op)
    assert_equal(op, String(E_BAD_101))


def test_RB9_no_framing_fields_on_1xx_or_204() raises:
    var s = ServerConnection()
    s.feed(Span(_b("GET / HTTP/1.1\r\nHost: x\r\n\r\n")))
    _ = _srv_events(s)
    var n = 0
    var hints = ResponseHead(103)
    hints.headers.add("Content-Length", "5")
    try:
        s.send_informational(hints)
    except e:
        n += Int(_misuse(e))
    var te = ResponseHead(103)
    te.headers.add("Transfer-Encoding", "chunked")
    try:
        s.send_informational(te)
    except e:
        n += Int(_misuse(e))
    for status in [204, 101, 100, 304, 200]:
        try:
            s.send_error(status)  # errors only: 4xx and 5xx
        except e:
            n += Int(_misuse(e))
    assert_equal(n, 7)
    assert_equal(_srv_sent(s), "")


def test_RB10_head_drops_trailers_like_its_body() raises:
    var s = ServerConnection()
    s.feed(Span(_b("HEAD /f HTTP/1.1\r\nHost: x\r\n\r\n")))
    _ = _srv_events(s)
    s.send_response(ResponseHead(200))
    s.send_body("the GET body".as_bytes())
    var t = Headers()
    t.add("X-Checksum", "42")
    s.end_response(t)  # was InvalidInput, leaving the response open
    assert_equal(_srv_sent(s), "HTTP/1.1 200 OK\r\n\r\n")
    assert_false(s.should_close())


def test_RB11_host_values_are_validated() raises:
    for bad in ["a b", "a, b", "a/b", "a@b", "[::1", "x:1:2", "h:8o", "%zz", "\xff\xfe", "[]"]:
        var s = ServerConnection()
        s.feed(Span(_b(String("GET / HTTP/1.1\r\nHost: ", bad, "\r\n\r\n"))))
        var status = 0
        try:
            _ = _srv_events(s)
        except:
            status = s.error_status()
        assert_equal(status, 400, repr(bad))
    for good in ["example.com", "example.com:8080", "127.0.0.1:80", "[::1]", "[::1]:443", "", "a%20b", "x_y-z.~!$&'()*+,;=", "h:"]:
        var s = ServerConnection()
        s.feed(Span(_b(String("GET / HTTP/1.1\r\nHost: ", good, "\r\n\r\n"))))
        assert_equal(_srv_events(s), "HEAD GET / HTTP/1.1 NONE / END", repr(good))


def test_RB14_closing_head_and_connection_lines() raises:
    # a closing response stops new requests as soon as its head is seen
    var c = ClientConnection(max_in_flight=2)
    c.send_request(_get("/1"))
    c.end_request()
    c.feed(Span(_b("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 4\r\n\r\nab")))
    assert_equal(_cli_events(c), "HEAD 200 HTTP/1.1 LENGTH(4) / DATA ab")
    var refused = False
    try:
        c.send_request(_get("/2"))  # was accepted, then lost
    except e:
        refused = _misuse(e)
    assert_true(refused)
    # stray CRLF with nothing in flight: dropped, not an error
    var idle = ClientConnection()
    idle.feed(Span(_b("\r\n")))
    assert_equal(_cli_events(idle), "")
    assert_true(idle.is_idle())
    # one Connection decision on the wire, never contradictory lines
    var s = ServerConnection()
    s.feed(Span(_b("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")))
    _ = _srv_events(s)
    var r = ResponseHead(200)
    r.headers.add("Connection", "keep-alive")
    r.headers.add("Content-Length", "0")
    s.send_response(r)
    s.end_response()
    assert_equal(_srv_sent(s), "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    var o = ServerConnection()
    o.feed(Span(_b("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")))
    _ = _srv_events(o)
    o.send_response(r)
    o.end_response()
    assert_equal(_srv_sent(o), "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n")


def test_RB_te_with_cl_is_read_then_closed() raises:
    var c = _asked()
    c.feed(Span(_b("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n2\r\nok\r\n0\r\n\r\n")))
    assert_equal(_cli_events(c), "HEAD 200 HTTP/1.1 CHUNKED / DATA ok / END")
    assert_false(c.is_idle())  # possible smuggling: not reused
    assert_true(c.should_close())


# ---- review of parsing and framing -------------------------------------------------------


def _chunked_at(text: StringSlice, step: Int, limits: BodyLimits) raises -> String:
    var data = _b(text)
    var dec = BodyDecoder(Framing(BodyKind.CHUNKED, 0), lenient=False, limits=limits)
    var t = Headers()
    var body = String()
    var at = 0
    var avail = 0
    while not dec.is_done():
        avail = min(len(data), avail + step)
        while True:
            var pc: Piece
            try:
                pc = dec.decode(Span(data)[at:avail], t)
            except e:
                return String("err ", e.op)
            body += String(from_utf8_lossy=Span(data)[at + pc.start : at + pc.start + pc.len])
            at += pc.consumed
            if dec.is_done() or (pc.consumed == 0 and pc.len == 0):
                break
        if avail == len(data) and not dec.is_done():
            return String("more ", body)
    return String("ok ", body)


def test_RA1_an_unbounded_chunk_line_limit_does_not_overflow() raises:
    var lim = BodyLimits(max_chunk_line=Int.MAX)
    for step in [1, 2, 3, 100]:
        assert_equal(_chunked_at("5\r\nhello\r\n0\r\n\r\n", step, lim), "ok hello", String(step))
    # and the guards that compare against it
    var ok = False
    try:
        _ = ServerConnection(body_limits=BodyLimits(max_chunk_line=Int.MAX))
    except e:
        ok = _misuse(e)
    assert_true(ok)
    ok = False
    try:
        _ = ClientConnection(body_limits=BodyLimits(max_chunk_line=Int.MAX))
    except e:
        ok = _misuse(e)
    assert_true(ok)


def test_RA2_transfer_parameters_allow_whitespace_around_equals() raises:
    for te in ["gzip;q = 1, chunked", "gzip;q =1, chunked", "gzip;q= 1, chunked", "gzip;q\t=\t\"a b\", chunked"]:
        var resp = ResponseHead(200)
        resp.headers.add("Transfer-Encoding", te)
        assert_equal(String(response_framing(resp, "GET")), "CHUNKED", te)
        var req = RequestHead("POST", "/")
        req.headers.add("Host", "h")
        req.headers.add("Transfer-Encoding", te)
        var kind = String()
        try:
            _ = request_framing(req)
        except e:
            kind = String(e.kind)
        assert_equal(kind, "Unsupported", te)  # 501, not a 400 for bad syntax


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
