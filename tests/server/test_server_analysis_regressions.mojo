"""Regression tests for the 2026-11 analysis of the stack (six read-only
analysts, each checked by a skeptic), for `server`. Each test fails on the
code before its change.

- form-query-cookies: no query, form or cookie decoding; now
  `Request.query_params()`, `form()`, `cookies()` and `Response.set_cookie`
  (on `http.form`, tested against Python in tests/http/test_form.mojo).
- router-hooks-route-blind: the router matched paths only in `handle`,
  after the body, so the documented place to refuse before an upload
  (`admit`) saw only the raw target: a check of `req.path()` there let
  "/%70rivate" through to the route "/private". Now the router matches at
  the head: its own 400/404/405 go before the body, and a route's `admit`
  and `body_limit` see the decoded route.
- handler-errors-always-500: an error raised deep in a handler (a body
  that does not parse) could become a 4xx only through a `try` at each
  call or by matching it in `failed`, and an error `failed` turned into a
  400 was still logged as a server error. Now `raise res.fail(400, msg)`
  answers for itself, unlogged and without `failed`; and an error that
  `failed` maps to another status is not logged.

The client runs in this process between the server's turns; stderr goes
to a pipe while the server runs."""

from std.testing import TestSuite, assert_equal, assert_true

from linux import sys
from linux.consts import O_CLOEXEC, O_NONBLOCK
from linux.error import check
from linux.fd import OwnedFd, RawFd
from linux.time import Duration
from net.addr import SocketAddr
from net.tcp import TcpStream
from http.form import Pairs, SetCookie
from server import Handler, Params, Request, Response, Router, Server, ServerConfig

comptime _TURN = Duration.from_millis(20)


struct App(Handler):
    var asked: List[String]
    """The paths `failed` was asked about."""
    var ended: List[Bool]
    """`stream_ended`'s `finished`, per stream."""

    def __init__(out self):
        self.asked = List[String]()
        self.ended = List[Bool]()

    def handle(mut self, req: Request, mut res: Response) raises:
        var path = req.path()
        if path == "/json":
            raise res.fail(400, "bad JSON!")
        if path == "/number":
            raise res.fail(422, "id is no number!")
        if path == "/stream":
            res.stream()
            raise res.fail(400, "no stream!")
        if path == "/not-an-error":
            raise res.fail(200, "x")  # (not 4xx or 5xx: the usual 500)
        if path == "/q":
            var q: Pairs
            try:
                q = req.query_params()
            except e:
                raise res.fail(400, String("bad query: ", e))
            var c = req.cookies()
            res.text(200, String(q.get("a").or_else(""), "|", q.get("b").or_else(""), "|", c.get("sid").or_else(""), "|", c.get("theme").or_else(""), "!"))
            var cookie = SetCookie("seen", "1")
            cookie.http_only = True
            res.set_cookie(cookie)
            return
        if path == "/mapped" or path == "/boom":
            raise Error(String("boom at ", path))
        res.text(200, "ok!")

    def failed(mut self, req: Request, error: Error, mut res: Response) raises:
        self.asked.append(String(req.path()))
        if req.path() == "/mapped":
            res.text(400, "mapped!\n")

    def stream_ended(mut self, req: Request, finished: Bool):
        self.ended.append(finished)


def _pipe() raises -> Tuple[OwnedFd, OwnedFd]:
    var fds = Array[Int32, 2](fill=-1)
    _ = check("pipe2", sys.pipe2(fds, O_CLOEXEC | O_NONBLOCK))
    return (OwnedFd(unsafe_from_raw=fds[0]), OwnedFd(unsafe_from_raw=fds[1]))


def _ask(mut s: Server[App], c: TcpStream, path: StringSlice, end: StringSlice) raises -> String:
    """GET `path` on the client's connection; the response, read turn by
    turn until it ends with `end`."""
    c.write_all(String("GET ", path, " HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
    var got = String()
    var buf = List[UInt8](length=4096, fill=0)
    for _ in range(100):
        s.step(_TURN)
        while True:
            var n = c.try_read(Span(buf))
            if not n or n.value() == 0:
                break
            got += String(from_utf8_lossy=Span(buf)[0 : n.value()])
        if got.endswith(end):
            return got^
    raise Error(String(path, ": no complete response: ", got))


def test_a_handler_answers_its_own_failure() raises:
    var saved = OwnedFd(unsafe_from_raw=Int32(check("dup", sys.fcntl(RawFd(2), 1030, 10))))  # F_DUPFD_CLOEXEC
    var p = _pipe()
    _ = check("dup3", sys.dup3(p[1], 2, 0))
    var s = Server(App(), ServerConfig())
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = TcpStream.connect(s.local_addr())
    var got = List[String]()
    try:
        got.append(_ask(s, c, "/json", "bad JSON!\n"))
        got.append(_ask(s, c, "/number", "id is no number!\n"))
        got.append(_ask(s, c, "/stream", "no stream!\n"))
        got.append(_ask(s, c, "/mapped", "mapped!\n"))
        got.append(_ask(s, c, "/boom", "Internal Server Error\n"))
        got.append(_ask(s, c, "/not-an-error", "Internal Server Error\n"))
    except e:
        _ = check("dup3", sys.dup3(saved, 2, 0))  # (so that the failure shows)
        raise e^
    _ = check("dup3", sys.dup3(saved, 2, 0))
    var json = got[0]
    var number = got[1]
    var stream = got[2]
    var mapped = got[3]
    var boom = got[4]
    var not_an_error = got[5]
    var buf = List[UInt8](length=65536, fill=0)
    var n = sys.read(p[0], Span(buf))
    var log = String(from_utf8_lossy=Span(buf)[0 : max(n, 0)])
    assert_true(json.startswith("HTTP/1.1 400 Bad Request\r\n"), json)
    assert_true("content-type: text/plain; charset=utf-8\r\n" in json.lower(), json)
    assert_true(number.startswith("HTTP/1.1 422 "), number)
    assert_true(stream.startswith("HTTP/1.1 400 Bad Request\r\n"), stream)
    assert_true(mapped.startswith("HTTP/1.1 400 Bad Request\r\n"), mapped)
    assert_true(boom.startswith("HTTP/1.1 500 "), boom)
    assert_true(not_an_error.startswith("HTTP/1.1 500 "), not_an_error)
    # `failed` is asked only about what the handler did not answer itself.
    assert_equal(len(s.handler.asked), 3, String(len(s.handler.asked)))
    assert_equal(s.handler.asked[0], "/mapped")
    assert_equal(s.handler.asked[1], "/boom")
    assert_equal(s.handler.asked[2], "/not-an-error")
    # The stream begun before the failure was ended, as cut.
    assert_equal(len(s.handler.ended), 1)
    assert_true(not s.handler.ended[0])
    # Only what stayed a 500 is logged: the first is /boom (at most a line
    # a second, so a line for /mapped or the others would have come first).
    assert_true(log.startswith("mojo_net: server: GET /boom: boom at /boom\n"), log)
    _ = c^


def test_query_cookies_and_set_cookie() raises:
    var s = Server(App(), ServerConfig(log_errors=False))
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = TcpStream.connect(s.local_addr())
    c.write_all("GET /q?a=1&b=x+y%21 HTTP/1.1\r\nHost: x\r\nCookie: sid=abc; theme=dark\r\n\r\n".as_bytes())
    var got = _read(s, c, "!")
    assert_true(got.startswith("HTTP/1.1 200 OK\r\n"), got)
    assert_true("\r\nSet-Cookie: seen=1; HttpOnly\r\n" in got, got)
    assert_true(got.endswith("1|x y!|abc|dark!"), got)
    c.write_all("GET /q?a=%zz HTTP/1.1\r\nHost: x\r\n\r\n".as_bytes())
    var bad = _read(s, c, "\n")
    assert_true(bad.startswith("HTTP/1.1 400 Bad Request\r\n") and "bad query" in bad, bad)
    _ = c^


struct Site(Handler):
    var admitted: Int
    """Requests the application's own `admit` saw."""

    def __init__(out self):
        self.admitted = 0

    def handle(mut self, req: Request, mut res: Response) raises:
        res.text(404, "nothing here!\n")

    def admit(mut self, req: Request, mut res: Response) raises -> Bool:
        self.admitted += 1
        return True


def private(mut app: Site, req: Request, params: Params, mut res: Response) raises:
    res.text(200, "secret!\n")


def key_needed(mut app: Site, req: Request, params: Params, mut res: Response) raises -> Bool:
    if req.headers.get("x-key"):
        return True
    res.text(401, "key needed!\n")
    return False


def upload(mut app: Site, req: Request, params: Params, mut res: Response) raises:
    res.text(200, String(len(req.body), " bytes!\n"))


def _site_ask(mut s: Server[Router[Site]], c: TcpStream, request: StringSlice) raises -> String:
    c.write_all(request.as_bytes())
    var got = String()
    var buf = List[UInt8](length=4096, fill=0)
    for _ in range(100):
        s.step(_TURN)
        while True:
            var n = c.try_read(Span(buf))
            if not n:
                break
            if n.value() == 0:
                return got + "<EOF>"
            got += String(from_utf8_lossy=Span(buf)[0 : n.value()])
        if _complete(got):
            return got^
    raise Error(String("no complete response: ", got))


def _complete(got: String) -> Bool:
    """A whole response: its head, and the body its Content-Length says."""
    var end = got.find("\r\n\r\n")
    if end < 0:
        return False
    var at = got.lower().find("\r\ncontent-length: ")
    if at < 0 or at > end:
        return False
    var digits = String()
    for ch in got[byte = at + 18 : end].codepoint_slices():
        if ch < "0" or ch > "9":
            break
        digits += ch
    try:
        return got.byte_length() - (end + 4) >= atol(digits)
    except:
        return False


def test_the_router_matches_at_the_head() raises:
    var r = Router(Site())
    r.get("/private", private, admit=key_needed)
    r.post("/upload", upload, body_limit=10)
    r.post("/big", upload)
    var s = Server(r^, ServerConfig(log_errors=False))
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = TcpStream.connect(s.local_addr())
    # The route's admit sees the decoded route, however the path is spelled.
    var raw = _site_ask(s, c, "GET /%70rivate HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true(raw.startswith("HTTP/1.1 401 "), raw)
    var keyed = _site_ask(s, c, "GET /%70rivate HTTP/1.1\r\nHost: x\r\nX-Key: 1\r\n\r\n")
    assert_true(keyed.startswith("HTTP/1.1 200 ") and keyed.endswith("secret!\n"), keyed)
    # A route's body limit is its own.
    var small = _site_ask(s, c, "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
    assert_true(small.endswith("5 bytes!\n"), small)
    var c2 = TcpStream.connect(s.local_addr())
    var over = _site_ask(s, c2, "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world")
    assert_true(over.startswith("HTTP/1.1 413 "), over)
    var c3 = TcpStream.connect(s.local_addr())
    var big = _site_ask(s, c3, "POST /big HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world")
    assert_true(big.endswith("11 bytes!\n"), big)
    # The router's own answers come at the head: a 405 for a 10 MB upload
    # is sent before any of its body (none is sent here).
    var c4 = TcpStream.connect(s.local_addr())
    c4.write_all("PUT /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 10000000\r\n\r\n".as_bytes())
    var early = String()
    var buf = List[UInt8](length=4096, fill=0)
    for _ in range(50):
        s.step(_TURN)
        var n = c4.try_read(Span(buf))
        if n and n.value() > 0:
            early += String(from_utf8_lossy=Span(buf)[0 : n.value()])
            break
    assert_true(early.startswith("HTTP/1.1 405 "), early)
    # The application's admit saw every request first.
    assert_equal(s.handler.app.admitted, 6)
    _ = c^
    _ = c2^
    _ = c3^
    _ = c4^


def _read(mut s: Server[App], c: TcpStream, end: StringSlice) raises -> String:
    var got = String()
    var buf = List[UInt8](length=4096, fill=0)
    for _ in range(100):
        s.step(_TURN)
        while True:
            var n = c.try_read(Span(buf))
            if not n or n.value() == 0:
                break
            got += String(from_utf8_lossy=Span(buf)[0 : n.value()])
        if got.endswith(end) and "\r\n\r\n" in got:
            return got^
    raise Error(String("no complete response: ", got))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
