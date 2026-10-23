"""Regression tests for the S5 review of the server (resources and the
loop), each checked to fail on the code before its fix:
- one client pipelining without pause froze the loop for every other;
- a streamed request body that was cut got no hook (`body_cut`);
- an early 413 on a drainable body could be followed by a second
  response (408, 400) for the same request;
- a handler's wrong Content-Length, or a 101, dropped the connection
  without a response;
- a stray CRLF after a request turned the idle close into a 408;
- a `max_head` over 80 KiB made every connection fail silently;
- `step()` spun once a shutdown's deadline had passed;
- buffers kept their peak size on idle connections;
- a client dripping a byte at a time held a connection forever, sending
  a body or taking a response (now `min_rate` per timeout window);
- error responses had no Date (RFC 9110 6.6.1);
- an absolute-form target stayed whole in `target`, so `path()` started
  with the authority (now `host()` has it);
- configurations that cannot work were accepted (a `server_name` that
  splits headers, `max_connections` past the id space)."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_true

from http.parse import Limits
from linux import ErrorKind
from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig
from server.server import _WAITING

comptime _CLIENT = """
import http.client, socket, struct, sys, threading, time
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
            return data
        if not c:
            return data
        data += c
def status(data):
    return data.split(b"\\r\\n")[0].decode()
if mode == "hog":
    # A pipelines without pause (and reads every response); B asks once.
    a = raw()
    stop = time.time() + 2.0
    def reader():
        while True:
            try:
                if not a.recv(1 << 20):
                    return
            except OSError:
                return
    threading.Thread(target=reader, daemon=True).start()
    batch = b"GET /hello HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n" * 2000
    def writer():
        while time.time() < stop:
            a.sendall(batch)
    w = threading.Thread(target=writer); w.start()
    time.sleep(0.3)
    t = time.time()
    b = raw()
    b.sendall(b"GET /hello HTTP/1.1\\r\\nHost: x\\r\\nConnection: close\\r\\n\\r\\n")
    got = read_all(b)
    waited = time.time() - t
    w.join()
    a.close()
    out.append(f"B answered={status(got) == 'HTTP/1.1 200 OK'} quick={waited < 0.5}")
elif mode == "cut-body":
    s = raw()  # the client leaves mid-body
    s.sendall(b"PUT /up HTTP/1.1\\r\\nHost: x\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n5\\r\\nhello\\r\\n")
    time.sleep(0.2); s.close()
    s = raw()  # a malformed chunk
    s.sendall(b"PUT /up HTTP/1.1\\r\\nHost: x\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n5\\r\\nhello\\r\\nzz\\r\\n")
    out.append(status(read_all(s)))
    s = raw()  # it stalls past read_timeout
    s.sendall(b"PUT /up HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 10\\r\\n\\r\\nabc")
    out.append(status(read_all(s)))
    s = raw()  # a reset mid-body: only the close sees it
    s.sendall(b"PUT /up HTTP/1.1\\r\\nHost: x\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n5\\r\\nhello\\r\\n")
    time.sleep(0.2)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)); s.close()
    time.sleep(0.2)
    s = raw()  # one that completes: handle, no cut
    s.sendall(b"PUT /up HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 3\\r\\nConnection: close\\r\\n\\r\\nabc")
    out.append(status(read_all(s)))
elif mode == "413-once":
    s = raw()  # the rest never comes: read_timeout passes
    s.sendall(b"POST /hello HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 2000\\r\\n\\r\\n")
    first = s.recv(4096)
    rest = read_all(s)
    out.append(f"{status(first)} then {rest.count(b'HTTP/1.1')} more")
    s = raw()  # part of it, then the end of input
    s.sendall(b"POST /hello HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 2000\\r\\n\\r\\n" + b"x" * 500)
    first = s.recv(4096)
    s.shutdown(socket.SHUT_WR)
    rest = read_all(s)
    out.append(f"{status(first)} then {rest.count(b'HTTP/1.1')} more")
elif mode == "bad-length":
    s = raw()
    s.sendall(b"GET /badlen HTTP/1.1\\r\\nHost: x\\r\\n\\r\\nGET /hello HTTP/1.1\\r\\nHost: x\\r\\nConnection: close\\r\\n\\r\\n")
    got = read_all(s)
    out.append(f"{status(got)} then {got.count(b'HTTP/1.1 200')} answered")
    s = raw()
    s.sendall(b"GET /upgrade HTTP/1.1\\r\\nHost: x\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\n\\r\\n"
              b"GET /hello HTTP/1.1\\r\\nHost: x\\r\\nConnection: close\\r\\n\\r\\n")
    got = read_all(s)
    out.append(f"{status(got)} then {got.count(b'HTTP/1.1 200')} answered")
elif mode == "crlf":
    s = raw()
    s.sendall(b"POST /hello HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 3\\r\\n\\r\\nabc\\r\\n")
    t = time.time()
    got = read_all(s)  # until the server closes
    out.append(f"{got.count(b'HTTP/1.1')} response, 408={b' 408 ' in got}, at idle={time.time() - t > 0.8}")
elif mode == "big-head":
    s = raw()
    s.sendall(b"GET /hello HTTP/1.1\\r\\nHost: x\\r\\nX-Big: " + b"v" * 100000 + b"\\r\\nConnection: close\\r\\n\\r\\n")
    out.append(status(read_all(s)))
elif mode == "drip-body":
    s = raw()
    s.sendall(b"POST /hello HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 100000\\r\\n\\r\\n")
    s.setblocking(False)
    t = time.time(); got = b""
    while time.time() - t < 4 and not got:
        try:
            s.send(b"x")
        except OSError:
            break
        time.sleep(0.1)
        try:
            got = s.recv(4096)
        except BlockingIOError:
            pass
        except OSError:
            break
    out.append(f"{status(got) if got else 'nothing'} soon={time.time() - t < 2.5}")
elif mode == "drip-read":
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.connect(("127.0.0.1", port))
    s.sendall(b"GET /big HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    t = time.time(); total = 0; ended = False
    while time.time() - t < 6:
        # A reset shows in the TCP state at once (recv would first return
        # what is already buffered, 8 KB at this pace); a graceful close
        # would come only after all that was queued had trickled through.
        if s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 1)[0] == 7:  # TCP_CLOSE
            ended = True
            break
        try:
            d = s.recv(16)
        except OSError:
            ended = True
            break
        if not d:
            ended = True
            break
        total += len(d)
        time.sleep(0.1)  # 160 B/s
    out.append(f"cut={ended} soon={time.time() - t < 4.5} partial={total < 8 * 1024 * 1024}")
elif mode == "error-date":
    s = raw()
    s.sendall(b"GET  / HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    got = read_all(s)
    out.append(f"{status(got)} date={b'\\r\\nDate: ' in got}")
elif mode == "absolute":
    s = raw()
    s.sendall(b"GET http://example.com:8080/where?x=1 HTTP/1.1\\r\\nHost: other\\r\\n\\r\\n"
              b"GET http://example.com HTTP/1.1\\r\\nHost: other\\r\\n\\r\\n"
              b"OPTIONS * HTTP/1.1\\r\\nHost: plain\\r\\nConnection: close\\r\\n\\r\\n")
    got = read_all(s)
    out.append(" / ".join(p.split(b"\\r\\n\\r\\n", 1)[1].split(b"HTTP/1.1")[0].decode() for p in got.split(b"HTTP/1.1 200 OK")[1:]))
elif mode == "big-then-idle":
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", "/big", headers={"X-Big": "v" * 50000}); r = c.getresponse(); n = len(r.read())
    time.sleep(0.5)  # kept alive, idle: the test looks at its buffers now
    out.append(f"{r.status} {n}")
    c.close()
print("|".join(out), flush=True)
"""


struct App(Handler):
    var opened: Int
    var cut: Int
    var handled: Int

    def __init__(out self):
        self.opened = 0
        self.cut = 0
        self.handled = 0

    def stream_request(mut self, req: Request) raises -> Bool:
        if req.path() == "/up":
            self.opened += 1
            return True
        return False

    def body_cut(mut self, req: Request):
        self.cut += 1

    def handle(mut self, req: Request, mut res: Response) raises:
        var path = req.path()
        if path == "/up":
            self.handled += 1
            res.text(200, "stored\n")
        elif path == "/badlen":
            res.text(200, "hello")
            res.headers.set("Content-Length", "3")
        elif path == "/upgrade":
            res.status = 101
            res.headers.set("Upgrade", "websocket")
            res.headers.set("Connection", "Upgrade")
        elif path == "/where" or path == "/" or req.target == "*":
            res.text(200, String(req.target, " ", req.path(), " ", req.query(), " ", req.host()))
        elif path == "/big":
            var body = List[UInt8](length=8 * 1024 * 1024, fill=0x61)
            res.bytes(200, Span(body), "application/octet-stream")
        else:
            res.text(200, "hello\n")


@fieldwise_init
struct _Outcome(Movable):
    var out: String
    var longest_step: Duration
    var idle_buffers: Int
    """The largest buffer an idle, used connection held, in bytes of
    capacity (idle: between requests, with no output left to write)."""


def _idle_buffers(s: Server[App]) -> Int:
    var most = 0
    for i in range(len(s._conns)):
        if s._conns[i]:
            ref c = s._conns[i].value()
            if c.state == _WAITING and not c.first and len(c.out) == 0 and c.http.pending_transmit() == 0:
                for n in [
                    c.req.body.capacity(), c.res.body.capacity(), c.out.capacity(),
                    c.http._tx.capacity(), c.http._rx.capacity(), c.req.headers._data.capacity(),
                    c.res.headers._data.capacity(), c.ev.data.capacity(),
                ]:
                    most = max(most, n)
    return most


def _run(mode: StaticString, config: ServerConfig = ServerConfig()) raises -> _Outcome:
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
    var longest = Duration.ZERO
    var idle = 0
    var t = Instant.now()
    while String(proc.poll()) == "None":
        var t0 = Instant.now()
        s.step(Duration.from_millis(5))
        longest = max(longest, t0.elapsed())
        idle = max(idle, _idle_buffers(s))
        if t.elapsed() > Duration.from_secs(60):
            _ = proc.kill()
            raise Error(String("client ", mode, " timed out"))
    var drain = Instant.now()
    while s.connections() > 0 and drain.elapsed() < Duration.from_secs(3):
        s.step(Duration.from_millis(5))
    var out = String(String(py=proc.communicate()[0]).strip())
    assert_equal(s.connections(), 0, String(mode, ": connections left"))
    if mode == "cut-body":
        assert_equal(
            String(s.handler.opened, " opened, ", s.handler.cut, " cut, ", s.handler.handled, " handled"),
            "5 opened, 4 cut, 1 handled",
        )
    return _Outcome(out^, longest, idle)


def test_one_client_cannot_hold_the_loop() raises:
    var r = _run("hog")
    assert_equal(r.out, "B answered=True quick=True")
    assert_true(r.longest_step < Duration.from_millis(200), String(r.longest_step.as_nanos() // 1000000, " ms"))


def test_a_cut_streamed_body_is_reported() raises:
    var short = Duration.from_millis(300)
    var r = _run("cut-body", ServerConfig(read_timeout=short))
    assert_equal(r.out, "HTTP/1.1 400 Bad Request|HTTP/1.1 408 Request Timeout|HTTP/1.1 200 OK")


def test_an_early_413_is_the_only_response() raises:
    var r = _run("413-once", ServerConfig(max_body=1000, read_timeout=Duration.from_millis(300)))
    assert_equal(
        r.out, "HTTP/1.1 413 Content Too Large then 0 more|HTTP/1.1 413 Content Too Large then 0 more"
    )


def test_a_wrong_length_or_a_101_gets_a_500() raises:
    var r = _run("bad-length")
    assert_equal(
        r.out,
        "HTTP/1.1 500 Internal Server Error then 1 answered|HTTP/1.1 500 Internal Server Error then 1 answered",
    )


def test_a_stray_crlf_after_a_request_is_no_head() raises:
    var config = ServerConfig(header_timeout=Duration.from_millis(200), idle_timeout=Duration.from_secs(1))
    assert_equal(_run("crlf", config).out, "1 response, 408=False, at idle=True")


def test_a_larger_max_head_works() raises:
    var config = ServerConfig(limits=Limits(max_head=128 * 1024))
    assert_equal(_run("big-head", config).out, "HTTP/1.1 200 OK")


def test_idle_connections_give_back_large_buffers() raises:
    var r = _run("big-then-idle")
    assert_equal(r.out, String("200 ", 8 * 1024 * 1024))
    assert_true(r.idle_buffers <= 16 * 1024, String("a buffer of ", r.idle_buffers, " bytes held"))


def test_a_dripping_body_times_out() raises:
    var config = ServerConfig(read_timeout=Duration.from_millis(500))  # 256 bytes per window
    assert_equal(_run("drip-body", config).out, "HTTP/1.1 408 Request Timeout soon=True")


def test_a_dripping_reader_is_cut() raises:
    var config = ServerConfig(write_timeout=Duration.from_secs(1))  # 512 bytes per window
    assert_equal(_run("drip-read", config).out, "cut=True soon=True partial=True")


def test_error_responses_carry_a_date() raises:
    assert_equal(_run("error-date").out, "HTTP/1.1 400 Bad Request date=True")


def test_absolute_form_targets() raises:
    assert_equal(
        _run("absolute").out,
        "/where?x=1 /where x=1 example.com:8080 / / /  example.com / * *  plain",
    )


def _refused(config: ServerConfig) -> Bool:
    try:
        _ = Server(App(), config)
        return False
    except e:
        return e.kind == ErrorKind.InvalidInput


def test_configurations_that_cannot_work_are_refused() raises:
    assert_true(_refused(ServerConfig(server_name="mojo\r\nSet-Cookie: x=1")))
    assert_true(_refused(ServerConfig(server_name="a\tb")))
    assert_true(_refused(ServerConfig(max_connections=0)))
    assert_true(_refused(ServerConfig(max_connections=1 << 24)))
    assert_true(_refused(ServerConfig(min_rate=-1)))
    assert_true(not _refused(ServerConfig(server_name="mojo_net/1.0 (linux)")))


def test_steps_after_a_shutdown_still_wait() raises:
    var s = Server(App(), ServerConfig(shutdown_timeout=Duration.from_millis(10)))
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    s.shutdown()
    var t = Instant.now()
    var steps = 0
    while t.elapsed() < Duration.from_millis(300):
        s.step(Duration.from_millis(100))
        steps += 1
    assert_true(steps <= 5, String(steps, " steps"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
