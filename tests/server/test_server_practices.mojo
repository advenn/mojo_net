"""The second review's best practices for the server (SR2, 2026-10-28):
- `Handler.admit` answers at a request's head, before its body and
  before `100 Continue` (I-3), and `Handler.body_limit` sets a body limit
  per request;
- `max_body_memory` bounds the buffered bodies of all connections: 503
  with Retry-After beyond it (I-2);
- `Handler.failed` maps an error to another answer, and errors are logged
  on stderr, at most a line a second (I-1);
- `Handler.completed` sees every request once, the server's own answers
  and cut streams included (I-4);
- `max_requests` and `max_connection_age` end long-lived connections
  (I-5), and `request_timeout` bounds a buffered body (I-9);
- `drain_delay` keeps serving, with `Connection: close`, before a
  shutdown closes the listener (I-8);
- CONNECT gets 501 (I-17), `Response.redirect`, and `Router` passing the
  new hooks on."""

from std.collections import Dict
from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, sys
from linux.consts import O_CLOEXEC, O_NONBLOCK
from linux.error import check
from linux.fd import OwnedFd, RawFd
from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import Exchange, Handler, Params, Request, Response, Router, Server, ServerConfig


struct App(Handler):
    var log: List[String]
    """One line per `completed`."""
    var pieces: Dict[UInt64, Int]
    var shutting: Int
    var stop_asked: Bool

    def __init__(out self):
        self.log = List[String]()
        self.pieces = Dict[UInt64, Int]()
        self.shutting = 0
        self.stop_asked = False

    def admit(mut self, req: Request, mut res: Response) raises -> Bool:
        if req.path() == "/private" and not req.headers.contains("authorization"):
            res.text(401, "who are you?\n")
            return False
        if req.path() == "/admit-raises":
            raise Error("admit broke")
        return True

    def body_limit(mut self, req: Request) -> Int:
        if req.path() == "/big":
            return 4 * 1024 * 1024
        return -1

    def handle(mut self, req: Request, mut res: Response) raises:
        var path = req.path()
        if path == "/boom":
            raise Error("boom\x1b[31m")
        if path == "/json":
            raise Error("bad json")
        if path == "/stream" or path == "/hold":
            self.pieces[req.id] = 0
            res.stream()
            return
        if path == "/shutdown":
            self.stop_asked = True
        res.text(200, String(len(req.body)))

    def failed(mut self, req: Request, error: Error, mut res: Response) raises:
        if req.path() == "/json":
            res.text(400, String("bad request: ", error, "\n"))

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        if req.path() == "/hold":
            return True  # paused until the client leaves
        var n = self.pieces[req.id]
        if n == 3:
            _ = self.pieces.pop(req.id)
            return False
        self.pieces[req.id] = n + 1
        out.extend("abc".as_bytes())
        return True

    def completed(mut self, req: Request, done: Exchange):
        self.log.append(
            String(
                req.method, " ", req.path(), " ", done.status, " sent=", done.sent, " received=",
                done.received, " finished=", done.finished, " server=", done.by_server,
            )
        )

    def shutting_down(mut self):
        self.shutting += 1


comptime _CLIENT = """
import http.client, socket, sys, time
port = int(sys.argv[1]); mode = sys.argv[2]
out = []
def raw():
    return socket.create_connection(("127.0.0.1", port), timeout=10)
def read_all(s):
    d = b""
    while True:
        try:
            x = s.recv(65536)
        except (ConnectionResetError, socket.timeout):
            return d
        if not x:
            return d
        d += x
def line(d):
    return d.split(b"\\r\\n")[0].decode()
def status(d):
    return line(d).split(" ")[1]
def get(path, method="GET", body=None, **headers):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body=body, headers=headers); r = c.getresponse(); b = r.read()
    return r, b
if mode == "admit":
    s = raw()
    s.sendall(b"POST /private HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 1000000\\r\\nExpect: 100-continue\\r\\n\\r\\n")
    out.append(line(s.recv(4096)))  # no 100 Continue: refused at the head
    s = raw()
    s.sendall(b"POST /private HTTP/1.1\\r\\nHost: x\\r\\nAuthorization: yes\\r\\nContent-Length: 1000000\\r\\nExpect: 100-continue\\r\\n\\r\\n")
    out.append(line(s.recv(4096)))
    s.sendall(b"x" * 1000000)
    d = s.recv(4096)
    out.append(f"{status(d)} {d.split(b'\\r\\n\\r\\n')[1].decode()}")
elif mode == "limits":
    r, b = get("/big", "POST", body=b"x" * (2 << 20)); out.append(f"{r.status} {b.decode()}")
    try:
        r, b = get("/upload", "POST", body=b"x" * (2 << 20)); out.append(str(r.status))
    except (BrokenPipeError, ConnectionResetError):
        out.append("cut")
elif mode == "budget":
    def head(n=30000):
        x = raw(); x.sendall(b"POST /upload HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: %d\\r\\n\\r\\n" % n + b"x" * 10)
        time.sleep(0.2)
        return x
    def answer(x):
        d = x.recv(4096)
        return f"{status(d)} {d.split(b'\\r\\n\\r\\n')[1].decode().strip()}"
    a = head(); b = head(); c = head()  # 60,000 held: the third is over 64,000
    d = c.recv(4096)
    retry = [l for l in d.split(b"\\r\\n") if l.lower().startswith(b"retry-after:")]
    out.append(f"{status(d)} {retry[0].split(b':')[1].strip().decode() if retry else None}")
    a.sendall(b"x" * 29990); out.append(answer(a))  # done: its share comes back
    b.close()  # gone mid-body: its share comes back too
    time.sleep(0.3)
    d = head(); e = head()
    d.sendall(b"x" * 29990); e.sendall(b"x" * 29990)
    out.append(answer(d)); out.append(answer(e))
    g = head()  # holds 30,000; a chunked body crosses the budget as it grows
    f = raw(); f.sendall(b"POST /upload HTTP/1.1\\r\\nHost: x\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n")
    for _ in range(8):
        try:
            f.sendall(b"1388\\r\\n" + b"y" * 5000 + b"\\r\\n")
        except OSError:
            break
    out.append(status(f.recv(4096)))
elif mode == "errors":
    r, b = get("/boom"); out.append(f"{r.status} {b.decode().strip()}")
    r, b = get("/json"); out.append(f"{r.status} {b.decode().strip()}")
    r, b = get("/admit-raises"); out.append(str(r.status))
elif mode == "cliff":
    a = raw(); a.sendall(b"GET / HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n"); a.recv(4096)
    b = raw(); b.sendall(b"GET / HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")  # waits: one connection at most
    time.sleep(0.3)
    a.close()
    out.append(status(b.recv(4096)))
elif mode == "log-burst":
    for _ in range(3):
        get("/boom")
    time.sleep(1.2)
    get("/boom")
    out.append("done")
elif mode == "access":
    get("/")
    get("/stream")
    try:
        get("/upload", "POST", body=b"x" * (2 << 20))
    except (BrokenPipeError, ConnectionResetError):
        pass
    get("/boom")
    s = raw(); s.sendall(b"CONNECT example.com:443 HTTP/1.1\\r\\nHost: example.com:443\\r\\n\\r\\n"); read_all(s)
    s = raw(); s.sendall(b"POST /upload HTTP/1.1\\r\\nHost: x\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n3\\r\\nabc\\r\\nzz\\r\\n"); read_all(s)
    s = raw(); s.sendall(b"GET /hold HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    h = b""
    while b"\\r\\n\\r\\n" not in h:
        h += s.recv(4096)
    s.close()  # gone with its stream paused: cut
    time.sleep(0.5)
    out.append("done")
elif mode == "max-requests":
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    for _ in range(2):
        c.request("GET", "/"); r = c.getresponse(); r.read()
        out.append(str(r.getheader("Connection")))
elif mode == "age":
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", "/"); r = c.getresponse(); r.read(); out.append(str(r.getheader("Connection")))
    time.sleep(0.5)
    c.request("GET", "/"); r = c.getresponse(); r.read(); out.append(str(r.getheader("Connection")))
elif mode == "request-timeout":
    s = raw(); t = time.time()
    s.sendall(b"POST /upload HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 100\\r\\n\\r\\n")
    s.settimeout(0.1)
    d = b""
    while time.time() - t < 5 and not d:
        try:
            s.sendall(b"x")
            d = s.recv(4096)
        except socket.timeout:
            pass
        except OSError:
            break
    out.append(f"{status(d) if d else None} fast={time.time() - t < 2}")
elif mode == "drain":
    get("/shutdown")
    time.sleep(0.2)
    r, b = get("/"); out.append(f"{r.status} {r.getheader('Connection')}")
    time.sleep(1.5)
    try:
        raw(); out.append("accepted")
    except ConnectionRefusedError:
        out.append("refused")
print("|".join(out), flush=True)
"""


def _run(mode: StaticString, config: ServerConfig = ServerConfig()) raises -> Tuple[String, List[String], Int]:
    """The client's output, the access log, and `shutting_down` calls."""
    var router = Router(App())
    var s = Server(router^, config)
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    var proc = subprocess.Popen(
        Python.list(pysys.executable, "-c", _CLIENT, String(s.local_addr().port()), mode),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    var t = Instant.now()
    var shut = False
    while String(proc.poll()) == "None":
        s.step(Duration.from_millis(5))
        if s.handler.app.stop_asked and not shut:
            shut = True
            s.shutdown()
        if t.elapsed() > Duration.from_secs(60):
            _ = proc.kill()
            raise Error(String("client ", mode, " timed out"))
    var drain = Instant.now()
    while s.connections() > 0 and drain.elapsed() < Duration.from_secs(3):
        s.step(Duration.from_millis(5))
    var out = String(String(py=proc.communicate()[0]).strip())
    return (out^, s.handler.app.log.copy(), s.handler.app.shutting)


def test_admit_refuses_before_the_body() raises:
    assert_equal(_run("admit")[0], "HTTP/1.1 401 Unauthorized|HTTP/1.1 100 Continue|200 1000000")


def test_a_body_limit_per_request() raises:
    assert_equal(_run("limits", ServerConfig(max_body=1024))[0], "200 2097152|413")


def test_buffered_bodies_share_a_budget() raises:
    assert_equal(
        _run("budget", ServerConfig(max_body=40000, max_body_memory=64000))[0],
        "503 1|200 30000|200 30000|200 30000|503",
    )


def test_failed_maps_errors() raises:
    assert_equal(
        _run("errors", ServerConfig(log_errors=False))[0],
        "500 Internal Server Error|400 bad request: bad json|500",
    )


def test_completed_sees_every_request() raises:
    var r = _run("access", ServerConfig(max_body=1024, log_errors=False))
    assert_equal(r[0], "done")
    var log = String()
    for i in range(len(r[1])):
        log += String(r[1][i], "\n")
    assert_equal(
        log,
        String(
            "GET / 200 sent=1 received=0 finished=True server=False\n",
            "GET /stream 200 sent=9 received=0 finished=True server=False\n",
            "POST /upload 413 sent=23 received=0 finished=True server=True\n",
            "GET /boom 500 sent=22 received=0 finished=True server=True\n",
            "CONNECT example.com:443 501 sent=0 received=0 finished=True server=True\n",
            "POST /upload 400 sent=0 received=3 finished=True server=True\n",
            "GET /hold 200 sent=0 received=0 finished=False server=False\n",
        ),
    )


def test_max_requests_and_age_end_connections() raises:
    assert_equal(_run("max-requests", ServerConfig(max_requests=2))[0], "None|close")
    assert_equal(_run("age", ServerConfig(max_connection_age=Duration.from_millis(300)))[0], "None|close")


def test_request_timeout_bounds_a_buffered_body() raises:
    var r = _run(
        "request-timeout",
        ServerConfig(request_timeout=Duration.from_millis(500), read_timeout=Duration.from_secs(10), min_rate=0),
    )
    assert_equal(r[0], "408 fast=True")
    assert_equal(len(r[1]), 1)
    assert_true(r[1][0].startswith("POST /upload 408 sent=0 received="), r[1][0])
    assert_true(r[1][0].endswith(" finished=True server=True"), r[1][0])


def test_drain_delay_serves_before_the_listener_closes() raises:
    var r = _run("drain", ServerConfig(drain_delay=Duration.from_secs(1)))
    assert_equal(r[0], "200 close|refused")
    assert_equal(r[2], 1)


def _pipe() raises -> Tuple[OwnedFd, OwnedFd]:
    var fds = Array[Int32, 2](fill=-1)
    _ = check("pipe2", sys.pipe2(fds, O_CLOEXEC | O_NONBLOCK))
    return (OwnedFd(unsafe_from_raw=fds[0]), OwnedFd(unsafe_from_raw=fds[1]))


def test_errors_are_logged_a_line_a_second() raises:
    # stderr goes to a pipe while the server runs
    var saved = OwnedFd(unsafe_from_raw=Int32(check("dup", sys.fcntl(RawFd(2), 1030, 10))))  # F_DUPFD_CLOEXEC
    var p = _pipe()
    _ = check("dup3", sys.dup3(p[1], 2, 0))
    var r = _run("log-burst")
    var c = _run("cliff", ServerConfig(max_connections=1))
    _ = check("dup3", sys.dup3(saved, 2, 0))
    var buf = List[UInt8](length=65536, fill=0)
    var n = sys.read(p[0], Span(buf))
    var text = String(from_utf8_lossy=Span(buf)[0 : max(n, 0)])
    assert_equal(r[0], "done")
    assert_equal(c[0], "200")
    assert_equal(
        text,
        "mojo_net: server: GET /boom: boom\\x1b[31m\n"
        + "mojo_net: server: GET /boom: boom\\x1b[31m (and 2 more since)\n"
        + "mojo_net: server: accepting paused: max_connections (1) reached\n",
    )


def test_redirect() raises:
    var res = Response()
    res.redirect(303, "/elsewhere?x=1")
    assert_equal(res.status, 303)
    assert_equal(String(res.headers.get("location").value()), "/elsewhere?x=1")
    var refused = False
    try:
        res.redirect(200, "/x")
    except e:
        refused = e.kind == ErrorKind.InvalidInput
    assert_true(refused)
    refused = False
    try:
        res.redirect(302, "/x\r\nSet-Cookie: a=1")
    except:
        refused = True
    assert_true(refused)


def test_text_sets_one_content_type() raises:
    # (the default type is set without checks, SR2 PERF-1: it must still
    # replace an earlier one, and another type is still checked)
    var res = Response()
    res.headers.add("Content-Type", "application/x-old")
    res.text(200, "a")
    assert_equal(res.headers.count("content-type"), 1)
    assert_equal(String(res.headers.get("content-type").value()), "text/plain; charset=utf-8")
    res.text(200, "b", "text/html; charset=utf-8")
    assert_equal(String(res.headers.get("content-type").value()), "text/html; charset=utf-8")
    var refused = False
    try:
        res.text(200, "c", "text/plain\r\nSet-Cookie: a=1")
    except:
        refused = True
    assert_true(refused)


def test_the_router_passes_the_hooks_on() raises:
    var r = Router(App())
    var req = Request(SocketAddr.parse("127.0.0.1:1"))
    req.method = "POST"
    req.target = "/private"
    var res = Response()
    assert_false(r.admit(req, res))
    assert_equal(res.status, 401)
    req.target = "/big"
    assert_equal(r.body_limit(req), 4 * 1024 * 1024)
    req.target = "/json"
    var mapped = Response()
    r.failed(req, Error("x"), mapped)
    assert_equal(mapped.status, 400)
    r.completed(req, Exchange(204, 0, 0, Instant.now(), Instant.now(), True, False))
    assert_equal(len(r.app.log), 1)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
