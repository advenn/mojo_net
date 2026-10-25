"""Regression tests for the second http review: the parser, the header map
and both connection codecs (sans-I/O, no sockets).

- P1: request targets are checked by form (RFC 9112 3.2): absolute-form
  only for http(s), with a host and no user info, its authority checked as
  Host is; authority-form only for CONNECT; `*` only for OPTIONS. Before,
  any visible ASCII passed, and `http://evil.example#@good.example/` gave
  the server's `host()` an unchecked value.
- P2: a fragment (`#`) in a request target is refused.
- P3: a `HeadParser` given a shorter input than it scanned raises instead
  of reading past it.
- P4: limits a connection cannot work with (`max_head` 0, negatives) are
  refused at construction instead of failing every request.
- P5: `Headers(capacity=...)` takes any number as a hint (a negative one
  aborted the process).
- P6: status codes 600..999 were refused, and the response with them;
  RFC 9110 15 has a client treat such a code as a 5xx.
- C1: a receive buffer of nothing but line ends was rescanned from its
  first byte on every read (quadratic: 9.7 s for 256 KiB of CRLFs).
- C2: a refused CONNECT or Upgrade closes the connection, so what follows
  its head is never served as the next request.
- C3: `take_remaining` starts the parsers over.
- C4: bytes after the last response close the client connection quietly,
  however the input is split.
- C5: `send_error` is refused once the request was answered.
- C6: `input_pending()` sees input that arrives after the close is decided.
- C7: a refused `send_request` keeps an upgraded connection's bytes.
- C8: a 101 while the request body is still being sent is refused.
- C9: a response after the input failed (once the request was whole) says
  `Connection: close`.
- C10: framing fields with an empty element are refused.
- C11: a response whose major version is not 1 is refused.
- C12: a reused event carries no stale data from an earlier one.
"""

from std.testing import TestSuite, assert_equal, assert_false, assert_true
from std.time import perf_counter_ns

from bytes import ByteBuffer
from http.connection import ClientConnection, ClientEvent, EventKind, ServerConnection, ServerEvent
from http.headers import Headers
from http.parse import HeadParser, Limits, RequestHead, ResponseHead
from http.types import is_server_error
from linux import ErrorKind


def _b(text: StringSlice) -> List[UInt8]:
    var out = List[UInt8]()
    for c in text.codepoints():
        out.append(UInt8(Int(c.to_u32())))
    return out^


def _sent(mut c: ServerConnection) raises -> String:
    var out = ByteBuffer()
    _ = c.poll_transmit(out)
    return String(from_utf8_lossy=out.readable_span())


def _sent_c(mut c: ClientConnection) raises -> String:
    var out = ByteBuffer()
    _ = c.poll_transmit(out)
    return String(from_utf8_lossy=out.readable_span())


def _server_outcome(request: StringSlice) raises -> String:
    """What a server codec makes of `request`: "HEAD <target>" or the
    error status."""
    var c = ServerConnection()
    c.feed(request.as_bytes())
    var ev = ServerEvent(EventKind.END)
    try:
        if c.poll(ev) and ev.kind == EventKind.HEAD:
            return String("HEAD ", ev.head().target)
        return "nothing"
    except:
        return String(c.error_status())


# ---- P1, P2 --------------------------------------------------------------------


def test_p1_p2_request_targets_by_form() raises:
    var refused: List[String] = [
        "GET http://evil.example#@good.example/ HTTP/1.1\r\nHost: good.example\r\n\r\n",
        "GET x/y://evil.example/admin HTTP/1.1\r\nHost: h\r\n\r\n",
        "GET gopher://internal:70/x HTTP/1.1\r\nHost: h\r\n\r\n",
        "GET http:///admin HTTP/1.1\r\nHost: h\r\n\r\n",
        "GET http://user@victim.example/ HTTP/1.1\r\nHost: h\r\n\r\n",
        "GET http://<b>/ HTTP/1.1\r\nHost: h\r\n\r\n",
        "GET http://:80/ HTTP/1.1\r\nHost: h\r\n\r\n",
        "GET foo HTTP/1.1\r\nHost: h\r\n\r\n",
        "GET :443 HTTP/1.1\r\nHost: h\r\n\r\n",
        "GET example.com:443 HTTP/1.1\r\nHost: h\r\n\r\n",
        "GET * HTTP/1.1\r\nHost: h\r\n\r\n",
        "CONNECT /x HTTP/1.1\r\nHost: h\r\n\r\n",
        "CONNECT example.com HTTP/1.1\r\nHost: h\r\n\r\n",
        "CONNECT u@example.com:443 HTTP/1.1\r\nHost: h\r\n\r\n",
        "CONNECT [::1] HTTP/1.1\r\nHost: h\r\n\r\n",
        "CONNECT [::1]: HTTP/1.1\r\nHost: h\r\n\r\n",
        "GET /a#b HTTP/1.1\r\nHost: h\r\n\r\n",
        "GET /public#/../admin HTTP/1.1\r\nHost: h\r\n\r\n",
    ]
    for i in range(len(refused)):
        assert_equal(_server_outcome(refused[i]), "400", refused[i])
    assert_equal(_server_outcome("GET /a?b=c HTTP/1.1\r\nHost: h\r\n\r\n"), "HEAD /a?b=c")
    assert_equal(_server_outcome("GET http://good.example/a?b HTTP/1.1\r\nHost: x\r\n\r\n"), "HEAD http://good.example/a?b")
    assert_equal(_server_outcome("GET HTTPS://[::1]:8443 HTTP/1.1\r\nHost: x\r\n\r\n"), "HEAD HTTPS://[::1]:8443")
    assert_equal(_server_outcome("OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n"), "HEAD *")
    assert_equal(_server_outcome("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"), "HEAD example.com:443")
    assert_equal(_server_outcome("CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n"), "HEAD [::1]:443")


# ---- P3, P4, P5 ----------------------------------------------------------------


def test_p3_a_shorter_input_raises() raises:
    var p = HeadParser.for_responses()
    var head = ResponseHead()
    var text = _b("HTTP/1.1 200 OK\r\nContent-Length: 1")
    assert_false(p.response(Span(text), head))
    var short = Span(text)[0:5]
    var kind = ErrorKind.Other
    try:
        _ = p.response(short, head)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)


def test_p4_unworkable_limits_are_refused() raises:
    var bad: List[Limits] = [Limits(max_head=0), Limits(max_fields=-1), Limits(max_start_line=-1)]
    for i in range(len(bad)):
        var server = False
        try:
            _ = ServerConnection(limits=bad[i])
        except e:
            server = e.kind == ErrorKind.InvalidInput
        var client = False
        try:
            _ = ClientConnection(limits=bad[i])
        except e:
            client = e.kind == ErrorKind.InvalidInput
        assert_true(server and client, String("limits ", i))
    _ = ServerConnection(limits=Limits(max_head=1, max_fields=0, max_start_line=0))


def test_p5_headers_capacity_is_a_hint() raises:
    var a = Headers(capacity=-1)
    a.add("X", "1")
    var b = Headers(capacity=Int.MAX)
    b.add("Y", "2")
    assert_equal(len(a) + len(b), 2)


def test_p6_status_codes_up_to_999_are_server_errors() raises:
    var c = ClientConnection()
    var req = RequestHead("GET", "/")
    req.headers.add("Host", "h")
    c.send_request(req)
    c.end_request()
    c.feed(Span(_b("HTTP/1.1 600 Odd\r\nContent-Length: 2\r\n\r\nok")))
    var ev = ClientEvent(EventKind.END)
    assert_true(c.poll(ev) and ev.kind == EventKind.HEAD)  # (InvalidData before)
    assert_equal(ev.head().status, 600)
    assert_true(is_server_error(600) and is_server_error(999))
    assert_true(c.poll(ev) and ev.kind == EventKind.DATA)


# ---- C1 ------------------------------------------------------------------------


def test_c1_line_ends_are_scanned_once() raises:
    comptime HEAD = 256 * 1024
    var s = ServerConnection(limits=Limits(max_head=HEAD), max_buffered=HEAD + 16 * 1024)
    var ev = ServerEvent(EventKind.END)
    var t0 = perf_counter_ns()
    var failed = False
    var begun = 0
    var crlf = _b("\r\n")
    try:
        for _ in range(HEAD // 2 + 1):
            s.feed(Span(crlf))
            _ = s.poll(ev)
            if s.head_begun():
                begun += 1
    except:
        failed = True
    var server_ns = perf_counter_ns() - t0
    assert_equal(begun, 0)
    assert_true(failed)  # (431 at the limit)
    assert_equal(s.error_status(), 431)
    var c = ClientConnection(limits=Limits(max_head=HEAD), max_buffered=HEAD + 16 * 1024)
    var req = RequestHead("GET", "/")
    req.headers.add("Host", "h")
    c.send_request(req)
    c.end_request()
    var cev = ClientEvent(EventKind.END)
    t0 = perf_counter_ns()
    try:
        for _ in range(HEAD // 2 + 1):
            c.feed(Span(crlf))
            _ = c.poll(cev)
    except:
        pass
    var client_ns = perf_counter_ns() - t0
    # Quadratic, these took 9.7 s and about 3 s; linear, a few milliseconds.
    assert_true(server_ns < 1_000_000_000, String("server: ", server_ns // 1_000_000, " ms"))
    assert_true(client_ns < 1_000_000_000, String("client: ", client_ns // 1_000_000, " ms"))
    # And a head that does begin is still seen at once.
    var t = ServerConnection()
    t.feed(Span(_b("\r\n\r\nG")))
    _ = t.poll(ev)
    assert_true(t.head_begun())


# ---- C2 ------------------------------------------------------------------------


def _refused_switch(request: StringSlice, status: Int) raises -> Tuple[Bool, String, Bool]:
    """(should_close, what was sent, whether a second HEAD came) after a
    `status` answer to `request`, which a GET /admin follows."""
    var c = ServerConnection()
    c.feed(request.as_bytes())
    c.feed(Span(_b("GET /admin HTTP/1.1\r\nHost: h\r\n\r\n")))
    var ev = ServerEvent(EventKind.END)
    assert_true(c.poll(ev) and ev.kind == EventKind.HEAD)
    while c.poll(ev):
        if ev.kind == EventKind.END:
            break
    var r = ResponseHead()
    r.status = status
    r.headers.add("Content-Length", "0")
    c.send_response(r)
    c.end_response()
    var again = False
    while c.poll(ev):
        if ev.kind == EventKind.HEAD:
            again = True
    return (c.should_close(), _sent(c), again)


def test_c2_a_refused_connect_or_upgrade_closes() raises:
    var connect = _refused_switch("CONNECT internal:443 HTTP/1.1\r\nHost: internal:443\r\n\r\n", 403)
    assert_true(connect[0])
    assert_true("Connection: close" in connect[1])
    assert_false(connect[2], "the bytes after a refused CONNECT were served")
    var upgrade = _refused_switch("GET /ws HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", 426)
    assert_true(upgrade[0])
    assert_false(upgrade[2], "the bytes after a refused upgrade were served")


# ---- C3 ------------------------------------------------------------------------


def test_c3_take_remaining_starts_the_parsers_over() raises:
    var c = ClientConnection()
    var req = RequestHead("GET", "/")
    req.headers.add("Host", "h")
    c.send_request(req)
    c.end_request()
    c.feed(Span(_b("HTTP/1.1 200 OK\r\nContent-Le")))
    var ev = ClientEvent(EventKind.END)
    _ = c.poll(ev)  # (part of a head scanned)
    _ = c.take_remaining()
    c.feed(Span(_b("HTTP/1.1 204 No Content\r\n\r\n")))
    assert_true(c.poll(ev))  # (False before: the parser resumed its old scan)
    assert_equal(ev.head().status, 204)
    var s = ServerConnection()
    s.feed(Span(_b("GET /a HTTP/1.1\r\nHo")))
    var sev = ServerEvent(EventKind.END)
    _ = s.poll(sev)
    _ = s.take_remaining()
    s.feed(Span(_b("GET /b HTTP/1.1\r\nHost: h\r\n\r\n")))
    assert_true(s.poll(sev))
    assert_equal(sev.head().target, "/b")


# ---- C4 ------------------------------------------------------------------------


def _client_after(pieces: List[String]) raises -> String:
    var c = ClientConnection()
    var req = RequestHead("GET", "/")
    req.headers.add("Host", "h")
    c.send_request(req)
    c.end_request()
    var ev = ClientEvent(EventKind.END)
    var out = String()
    try:
        for i in range(len(pieces)):
            c.feed(pieces[i].as_bytes())
            while c.poll(ev):
                out += String(ev.kind, " ")
    except e:
        out += String("error ", e.kind, " ")
    out += String("close=", c.should_close())
    return out^


def test_c4_leftovers_close_quietly_however_split() raises:
    var whole: List[String] = ["HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokXY"]
    var split: List[String] = ["HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", "XY"]
    assert_equal(_client_after(whole), _client_after(split))
    assert_equal(_client_after(split), "HEAD DATA END close=True")


# ---- C5, C6, C9 ----------------------------------------------------------------


def _answered_early() raises -> ServerConnection:
    """A connection whose POST was answered (200, keep-alive) before its
    5-byte body arrived."""
    var c = ServerConnection()
    c.feed(Span(_b("POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nab")))
    var ev = ServerEvent(EventKind.END)
    assert_true(c.poll(ev) and ev.kind == EventKind.HEAD)
    _ = c.poll(ev)
    var r = ResponseHead()
    r.status = 200
    r.headers.add("Content-Length", "5")
    c.send_response(r)
    c.send_body(Span(_b("early")))
    c.end_response()
    return c^


def test_c5_send_error_is_refused_once_answered() raises:
    var c = _answered_early()
    c.feed_eof()  # (the body never ends)
    var ev = ServerEvent(EventKind.END)
    try:
        _ = c.poll(ev)
    except:
        pass
    var refused = False
    try:
        c.send_error(400)
    except e:
        refused = e.kind == ErrorKind.InvalidInput
    assert_true(refused)
    var sent = _sent(c)
    assert_false("400" in sent, sent)
    # The 408 to an idle connection still goes out.
    var idle = ServerConnection()
    idle.send_error(408)
    assert_true("408" in _sent(idle))


def test_c6_input_after_the_close_still_counts_as_pending() raises:
    var c = ServerConnection()
    c.feed(Span(_b("GET /1 HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n")))
    var ev = ServerEvent(EventKind.END)
    while c.poll(ev):
        pass
    var r = ResponseHead()
    r.status = 200
    r.headers.add("Content-Length", "0")
    c.send_response(r)
    c.end_response()
    assert_false(c.input_pending())
    c.feed(Span(_b("GET /2 HTTP/1.1\r\nHost: h\r\n\r\n")))  # (one read later)
    assert_true(c.input_pending())


def test_c9_a_response_after_failed_input_says_close() raises:
    var c = ServerConnection()
    c.feed(Span(_b("GET /x HTTP/1.1\r\nHost: h\r\n\r\n")))
    var ev = ServerEvent(EventKind.END)
    assert_true(c.poll(ev) and ev.kind == EventKind.HEAD)
    assert_true(c.poll(ev) and ev.kind == EventKind.END)
    # The request is whole, then the input fails (more than the buffer
    # holds); the response still goes out, and must say it is the last.
    var flood = List[UInt8](length=c.feed_capacity() + 1, fill=65)
    var failed = False
    try:
        c.feed(Span(flood))
    except:
        failed = True
    assert_true(failed)
    var r = ResponseHead()
    r.status = 200
    r.headers.add("Content-Length", "1")
    c.send_response(r)
    c.send_body(Span(_b("x")))
    c.end_response()
    var sent = _sent(c)
    assert_true("Connection: close" in sent, sent)
    assert_true(c.should_close())


# ---- C7, C8, C11 ---------------------------------------------------------------


def _client_sent(method: StringSlice, extra: StringSlice) raises -> ClientConnection:
    var c = ClientConnection()
    var req = RequestHead(method, "/")
    req.headers.add("Host", "h")
    if extra.byte_length() > 0:
        req.headers.add("Connection", "Upgrade")
        req.headers.add("Upgrade", extra)
    c.send_request(req)
    return c^


def test_c7_a_refused_send_keeps_the_upgraded_bytes() raises:
    var c = _client_sent("GET", "x")
    c.end_request()
    c.feed(Span(_b("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: x\r\n\r\nNEWPROTO")))
    var ev = ClientEvent(EventKind.END)
    assert_true(c.poll(ev) and ev.kind == EventKind.UPGRADE)
    var refused = False
    try:
        var again = RequestHead("GET", "/")
        again.headers.add("Host", "h")
        c.send_request(again)
    except e:
        refused = e.kind == ErrorKind.InvalidInput
    assert_true(refused)
    assert_equal(String(from_utf8_lossy=Span(c.take_remaining())), "NEWPROTO")


def test_c8_a_switch_before_the_body_is_sent_is_refused() raises:
    var c = ClientConnection()
    var req = RequestHead("POST", "/")
    req.headers.add("Host", "h")
    req.headers.add("Content-Length", "10")
    req.headers.add("Connection", "Upgrade")
    req.headers.add("Upgrade", "x")
    c.send_request(req)
    c.send_body(Span(_b("01234")))
    c.feed(Span(_b("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: x\r\n\r\n")))
    var ev = ClientEvent(EventKind.END)
    var kind = ErrorKind.Other
    try:
        _ = c.poll(ev)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidData)


def test_c11_a_major_version_other_than_1_is_refused() raises:
    var c = _client_sent("GET", "")
    c.end_request()
    c.feed(Span(_b("HTTP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")))
    var ev = ClientEvent(EventKind.END)
    var kind = ErrorKind.Other
    try:
        _ = c.poll(ev)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidData)


# ---- C10 -----------------------------------------------------------------------


def test_c10_framing_fields_with_empty_elements() raises:
    var cases: List[String] = [
        "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: \r\n\r\n",
        "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: ,\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked,\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5,\r\n\r\nhello",
        "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: ,5\r\n\r\nhello",
    ]
    for i in range(len(cases)):
        assert_equal(_server_outcome(cases[i]), "400", cases[i])


# ---- C12 -----------------------------------------------------------------------


def test_c12_reused_events_carry_no_stale_data() raises:
    var s = ServerConnection()
    s.feed(Span(_b("POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc")))
    var ev = ServerEvent(EventKind.END)
    assert_true(s.poll(ev) and ev.kind == EventKind.HEAD)
    assert_true(s.poll(ev) and ev.kind == EventKind.DATA)
    assert_true(s.poll(ev) and ev.kind == EventKind.END)
    assert_equal(len(ev.data), 0)
    var r = ResponseHead()
    r.status = 204
    s.send_response(r)
    s.end_response()
    s.feed(Span(_b("GET /b HTTP/1.1\r\nHost: h\r\n\r\n")))
    assert_true(s.poll(ev) and ev.kind == EventKind.HEAD)
    assert_equal(len(ev.data), 0)
    var c = _client_sent("GET", "")
    c.end_request()
    c.feed(Span(_b("HTTP/1.1 103 Early Hints\r\nLink: </s>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")))
    var cev = ClientEvent(EventKind.END)
    cev.data.append(1)
    assert_true(c.poll(cev) and cev.kind == EventKind.INFORMATIONAL)
    assert_equal(len(cev.data), 0)
    assert_true(c.poll(cev) and cev.kind == EventKind.HEAD)
    assert_true(c.poll(cev) and cev.kind == EventKind.DATA)
    assert_true(c.poll(cev) and cev.kind == EventKind.END)
    assert_equal(len(cev.data), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
