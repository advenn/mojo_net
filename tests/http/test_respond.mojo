"""`ServerConnection._respond` (SR2 PERF-7, PERF-8), the server's way to
send a head: its Date and Server lines come encoded, and the body's
length as a number, where `send_response` takes them as fields of the
head (and parses the length back). A differential test: over requests
(versions, HEAD, Connection fields), statuses, handler fields and body
lengths, the bytes queued must be the same both ways, and so must the
codec's state after the response (what it frames, whether it closes);
and `_respond` refuses a length beside the head's own framing field."""

from std.random import random_ui64, seed
from std.testing import TestSuite, assert_equal, assert_true

from bytes.buffer import ByteBuffer
from http.connection import ServerConnection
from http.parse import ResponseHead
from linux import ErrorKind, IoError

comptime _DATE = "Tue, 28 Oct 2026 10:00:00 GMT"


def _requests() -> List[String]:
    var r = List[String]()
    r.append("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    r.append("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    r.append("GET / HTTP/1.0\r\n\r\n")
    r.append("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
    r.append("HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
    r.append("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc")
    return r^


def _rand(n: Int) -> Int:
    return Int(random_ui64(0, UInt64(n - 1)))


def _waiting(request: StringSlice) raises -> ServerConnection:
    """A codec whose request has arrived whole and awaits its response."""
    var s = ServerConnection()
    s.feed(request.as_bytes())
    while True:
        var ev = s.next_event()
        if not ev:
            break
    return s^


def _drain(mut s: ServerConnection) raises -> String:
    var out = ByteBuffer()
    while s.poll_transmit(out) > 0:
        pass
    return String(from_utf8_lossy=out.readable_span())


def _fields(pick: Int, mut head: ResponseHead) raises:
    """The handler's fields: a few of a pool, by the bits of `pick`."""
    if pick & 1:
        head.headers.add("Content-Type", "text/plain; charset=utf-8")
    if pick & 2:
        head.headers.add("X-Request", "abc-123")
    if pick & 4:
        head.headers.add("Connection", "close")
    if pick & 8:
        head.headers.add("Connection", "keep-alive")
    if pick & 16:
        head.headers.add("Cache-Control", "no-cache, no-store")
    if pick & 32:
        head.headers.add("Set-Cookie", "a=1; Path=/")


def _one(request: StringSlice, status: Int, pick: Int, length: Int, server: StringSlice) raises -> String:
    """The same response both ways: "" if they agree, else what differs."""
    # the old way: the server's fields pushed into the head
    var a = _waiting(request)
    var ha = ResponseHead(status)
    _fields(pick, ha)
    ha.headers._push("Date".as_bytes(), _DATE.as_bytes(), utf8=True)
    if server.byte_length() > 0:
        ha.headers._push("Server".as_bytes(), server.as_bytes(), utf8=True)
    var bodiless = status == 204 or status == 304
    if not bodiless:
        ha.headers._push("Content-Length".as_bytes(), String(length).as_bytes(), utf8=True)
    var ra = String("ok")
    try:
        a.send_response(ha)
    except e:
        ra = String(e.kind)
    # the new way
    var b = _waiting(request)
    var hb = ResponseHead(status)
    _fields(pick, hb)
    var lines = String("Date: ", _DATE, "\r\n")
    if server.byte_length() > 0:
        lines += String("Server: ", server, "\r\n")
    var rb = String("ok")
    try:
        b._respond(hb, lines.as_bytes(), -1 if bodiless else length)
    except e:
        rb = String(e.kind)
    if ra != rb:
        return String("outcome ", ra, " vs ", rb)
    var sa = _drain(a)
    var sb = _drain(b)
    if sa != sb:
        return String("bytes:\n", sa, "\nvs\n", sb)
    if ra != "ok":
        return ""
    # the same framing after it: the body is taken, then the end
    var body = List[UInt8](length=length, fill=0x61)
    var ba = String("ok")
    var bb = String("ok")
    try:
        a.send_body(Span(body))
        a.end_response()
    except e:
        ba = String(e.kind)
    try:
        b.send_body(Span(body))
        b.end_response()
    except e:
        bb = String(e.kind)
    if ba != bb:
        return String("body ", ba, " vs ", bb)
    if _drain(a) != _drain(b) or a.should_close() != b.should_close():
        return "after the body"
    return ""


def test_respond_matches_send_response() raises:
    seed(28)
    var requests = _requests()
    var statuses = [200, 201, 204, 304, 404, 500]
    var lengths = [0, 1, 5, 9, 10, 99, 100, 1000, 123456789]
    for _ in range(3000):
        var request = requests[_rand(len(requests))]
        var status = statuses[_rand(len(statuses))]
        var pick = _rand(64)
        var length = lengths[_rand(len(lengths))]
        var server = "mojo" if _rand(2) == 0 else ""
        var diff = _one(request, status, pick, length, server)
        assert_equal(diff, "", String(request, " ", status, " fields ", pick, " length ", length, " ", server))


def test_respond_refuses_a_length_beside_framing() raises:
    for field in ["Content-Length", "Transfer-Encoding"]:
        var s = _waiting("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        var h = ResponseHead(200)
        h.headers.add(field, "chunked" if field == "Transfer-Encoding" else "3")
        var refused = False
        try:
            s._respond(h, "".as_bytes(), 3)
        except e:
            refused = e.kind == ErrorKind.InvalidInput
        assert_true(refused, field)
        assert_equal(_drain(s), "")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
