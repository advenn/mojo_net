"""`server.Server` end to end: the test drives the loop with `step()` while a
Python client (http.client, or raw sockets for what http.client will not
do) runs in a separate process. Requests and keep-alive, HEAD, bodies,
pipelining, Expect: 100-continue, request-body limits, handler errors,
malformed requests, every timeout, and the connection cap."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_true

from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig

comptime _CLIENT = """
import http.client, io, socket, sys, time
port = int(sys.argv[1]); mode = sys.argv[2]
out = []

def raw():
    return socket.create_connection(("127.0.0.1", port), timeout=10)

def read_all(s):
    data = b""
    while True:
        try:
            c = s.recv(65536)
        except (ConnectionResetError, socket.timeout):
            break
        if not c:
            break
        data += c
    return data

def responses(data, n):
    class NoClose(io.BufferedReader):
        def close(self): pass
    class Sock:
        def __init__(self, f): self.f = f
        def makefile(self, mode): return self.f
    f = NoClose(io.BytesIO(data))
    got = []
    for _ in range(n):
        r = http.client.HTTPResponse(Sock(f)); r.begin()
        got.append(f"{r.status} {r.read().decode()}")
    return got

if mode == "basic":
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", "/hello"); r = c.getresponse()
    out.append(f"{r.status} {r.read().decode()} date={r.getheader('Date') is not None} len={r.getheader('Content-Length')}")
    c.request("POST", "/echo", body=b"posted"); r = c.getresponse()
    out.append(f"{r.status} {r.read().decode()} {r.getheader('X-Method')}")
    c.request("PUT", "/echo", body=iter([b"chunked ", b"body"]), encode_chunked=True); r = c.getresponse()
    out.append(f"{r.status} {r.read().decode()}")
    c.request("HEAD", "/hello"); r = c.getresponse()
    out.append(f"{r.status} [{r.read().decode()}] len={r.getheader('Content-Length')}")
    c.request("GET", "/peer"); r = c.getresponse(); a = r.read().decode()
    c.request("GET", "/peer"); r = c.getresponse(); b = r.read().decode()
    out.append(f"kept={a == b}")
    c.request("GET", "/nope"); r = c.getresponse()
    out.append(f"{r.status} {r.read().decode()}")
    c.request("GET", "/boom"); r = c.getresponse()
    out.append(f"{r.status} {r.read().decode().strip()}")
elif mode == "pipeline":
    s = raw()
    s.sendall(b"GET /hello HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n"
              b"POST /echo HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 3\\r\\n\\r\\nabc"
              b"GET /hello HTTP/1.1\\r\\nHost: x\\r\\nConnection: close\\r\\n\\r\\n")
    out += responses(read_all(s), 3)
elif mode == "limits":
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("POST", "/echo", body=b"x" * 100); r = c.getresponse()
    out.append(f"{r.status} {len(r.read())}")
    s = raw()
    s.sendall(b"POST /echo HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 1000000\\r\\n\\r\\n")
    d = read_all(s)
    out.append(d.split(b"\\r\\n")[0].decode())
    s = raw()
    s.sendall(b"POST /echo HTTP/1.1\\r\\nHost: x\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n" + b"40\\r\\n" + b"y" * 64 + b"\\r\\n" + b"40\\r\\n" + b"y" * 64 + b"\\r\\n0\\r\\n\\r\\n")
    d = read_all(s)
    out.append(d.split(b"\\r\\n")[0].decode())
elif mode == "expect":
    s = raw()
    s.sendall(b"POST /echo HTTP/1.1\\r\\nHost: x\\r\\nExpect: 100-continue\\r\\nContent-Length: 5\\r\\n\\r\\n")
    first = s.recv(4096)
    out.append(first.split(b"\\r\\n")[0].decode())
    s.sendall(b"hello")
    out += responses(s.recv(4096), 1)
elif mode == "bad":
    s = raw()
    s.sendall(b"GET  / HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    d = read_all(s)
    out.append(d.split(b"\\r\\n")[0].decode() + f" closed={d.endswith(b'\\r\\n\\r\\n')}")
    s = raw()
    s.sendall(b"GET / HTTP/1.1\\r\\nHost: x\\r\\nX: " + b"v" * 70000 + b"\\r\\n\\r\\n")
    out.append(read_all(s).split(b"\\r\\n")[0].decode())
elif mode == "timeouts":
    t = time.time(); s = raw(); s.sendall(b"GET /hello HT")
    d = read_all(s); out.append(f"{d.split(b'\\r\\n')[0].decode()} after={round(time.time() - t, 1)}")
    t = time.time(); s = raw(); s.sendall(b"POST /echo HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 10\\r\\n\\r\\nabc")
    d = read_all(s); out.append(f"{d.split(b'\\r\\n')[0].decode()} after={round(time.time() - t, 1)}")
    s = raw(); s.sendall(b"GET /hello HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    t = time.time(); d = read_all(s)
    out.append(f"idle closed after={round(time.time() - t, 1)} ok={d.startswith(b'HTTP/1.1 200')}")
    t = time.time(); s = raw(); d = read_all(s)
    out.append(f"silent={d == b''} after={round(time.time() - t, 1)}")
elif mode == "slow_reader":
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.connect(("127.0.0.1", port)); s.sendall(b"GET /big HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    time.sleep(1.5)  # never read while the server waits
    d = read_all(s); out.append(f"cut={len(d) < 8 * 1024 * 1024}")
elif mode == "flood":
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.connect(("127.0.0.1", port))
    s.sendall(b"GET /big HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n" * 20)  # 20 x 8 MiB asked for
    time.sleep(1.0)  # without reading
    s.close()
    out.append("done")
elif mode == "cap":
    # two kept-alive connections fill the cap; a third waits in the backlog
    a = raw(); b = raw()
    for s in (a, b):
        s.sendall(b"GET /hello HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
        out.append(s.recv(4096).split(b"\\r\\n")[0].decode())
    c = raw(); c.settimeout(0.5)
    c.sendall(b"GET /hello HTTP/1.1\\r\\nHost: x\\r\\nConnection: close\\r\\n\\r\\n")
    try:
        c.recv(4096); out.append("third answered at once")
    except socket.timeout:
        out.append("third waits")
    a.close()  # one slot frees: the third is accepted and answered
    c.settimeout(10)
    out.append(read_all(c).split(b"\\r\\n")[0].decode())
    b.close()
print("|".join(out), flush=True)
"""


struct App(Handler):
    var served: Int

    def __init__(out self):
        self.served = 0

    def handle(mut self, req: Request, mut res: Response) raises:
        self.served += 1
        var path = req.path()
        if path == "/hello":
            res.text(200, "hello")
        elif path == "/echo":
            res.bytes(200, Span(req.body), "application/octet-stream")
            res.headers.add("X-Method", req.method)
        elif path == "/peer":
            res.text(200, String(req.peer.port()))
        elif path == "/boom":
            raise Error("boom")
        elif path == "/big":
            var big = List[UInt8](length=8 * 1024 * 1024, fill=0x7A)
            res.bytes(200, Span(big), "application/octet-stream")
        else:
            res.text(404, "not found")


def _run(mode: StaticString, config: ServerConfig = ServerConfig()) raises -> String:
    """Serve `App` while the Python client runs `mode`; its output line."""
    var s = Server(App(), config)
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
    while String(proc.poll()) == "None":
        s.step(Duration.from_millis(5))
        if t.elapsed() > Duration.from_secs(30):
            _ = proc.kill()
            raise Error(String("client ", mode, " timed out"))
    var out = String(py=proc.communicate()[0]).strip()
    for _ in range(20):  # let the server see the last closes
        s.step(Duration.from_millis(5))
    assert_equal(s.connections(), 0, String(mode, ": connections left"))
    return String(out)


def test_requests_keep_alive_head_bodies_errors() raises:
    var got = _run("basic")
    var want = String(
        "200 hello date=True len=5",
        "|200 posted POST",
        "|200 chunked body",
        "|200 [] len=5",
        "|kept=True",
        "|404 not found",
        "|500 Internal Server Error",
    )
    assert_equal(got, want)


def test_pipelined_requests_answered_in_order() raises:
    assert_equal(_run("pipeline"), "200 hello|200 abc|200 hello")


def test_request_body_limit() raises:
    var got = _run("limits", ServerConfig(max_body=100))
    assert_equal(got, "200 100|HTTP/1.1 413 Content Too Large|HTTP/1.1 413 Content Too Large")


def test_expect_100_continue() raises:
    assert_equal(_run("expect"), "HTTP/1.1 100 Continue|200 hello")


def test_malformed_requests_get_their_status() raises:
    assert_equal(_run("bad"), "HTTP/1.1 400 Bad Request closed=True|HTTP/1.1 431 Request Header Fields Too Large")


def test_timeouts() raises:
    var cfg = ServerConfig(
        header_timeout=Duration.from_millis(400),
        idle_timeout=Duration.from_millis(400),
        read_timeout=Duration.from_millis(400),
    )
    var got = _run("timeouts", cfg)
    var parts = got.split("|")
    assert_equal(len(parts), 4, got)
    assert_true(parts[0].startswith("HTTP/1.1 408 Request Timeout after=0.4") or parts[0].startswith("HTTP/1.1 408 Request Timeout after=0.5"), got)
    assert_true(parts[1].startswith("HTTP/1.1 408 Request Timeout after=0.4") or parts[1].startswith("HTTP/1.1 408 Request Timeout after=0.5"), got)
    assert_true(parts[2].startswith("idle closed after=0.4") or parts[2].startswith("idle closed after=0.5"), got)
    assert_true(parts[2].endswith("ok=True"), got)
    assert_true(parts[3].startswith("silent=True after=0.4") or parts[3].startswith("silent=True after=0.5"), got)


def test_a_client_that_does_not_read_is_dropped() raises:
    var got = _run("slow_reader", ServerConfig(write_timeout=Duration.from_millis(300)))
    assert_equal(got, "cut=True")


def test_backpressure_bounds_queued_output() raises:
    # A client that pipelines 20 requests for 8 MiB each and does not read:
    # the server stops reading once output waits, so at most about one
    # response is queued (not 160 MiB).
    var s = Server(App())
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    var proc = subprocess.Popen(
        Python.list(pysys.executable, "-c", _CLIENT, String(s.local_addr().port()), "flood"),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    var peak = 0
    var t = Instant.now()
    while String(proc.poll()) == "None" and t.elapsed() < Duration.from_secs(30):
        s.step(Duration.from_millis(5))
        peak = max(peak, s.queued_output())
    assert_equal(String(py=proc.communicate()[0]).strip(), "done")
    assert_true(peak > 0)
    assert_true(peak <= 9 * 1024 * 1024, String("queued ", peak, " bytes"))
    assert_true(s.handler.served <= 2, String(s.handler.served, " responses made"))


def test_connection_cap_holds_the_rest_back() raises:
    var got = _run("cap", ServerConfig(max_connections=2))
    assert_equal(got, "HTTP/1.1 200 OK|HTTP/1.1 200 OK|third waits|HTTP/1.1 200 OK")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
