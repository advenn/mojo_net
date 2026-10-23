"""`server.Server` graceful shutdown and lingering close (S3), end to end
against Python clients. A client asks for the shutdown with
`GET /shutdown` (the test then calls `Server.shutdown()`), and checks what
each of its connections sees: idle ones closed, a request in progress
answered with `Connection: close` and the one pipelined after it dropped,
connections the kernel had queued accepted and answered, the listener
gone, a stream ended by `Handler.shutting_down()` or cut at
`shutdown_timeout`. Lingering: a client still sending after its 413 gets
an orderly end of input, not a reset, until `linger_timeout`; one with
nothing left unread is closed at once."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig

comptime _CLIENT = """
import socket, sys, threading, time
port = int(sys.argv[1]); mode = sys.argv[2]
out = []

def raw():
    return socket.create_connection(("127.0.0.1", port), timeout=10)

def read_all(s):
    data = b""
    while True:
        try:
            c = s.recv(65536)
        except ConnectionResetError:
            return data + b"<reset>"
        except socket.timeout:
            return data + b"<timeout>"
        if not c:
            return data
        data += c

def get(s, path):
    s.sendall(b"GET " + path + b" HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    d = b""
    while b"\\r\\n\\r\\n" not in d:
        d += s.recv(4096)
    head, _, body = d.partition(b"\\r\\n\\r\\n")
    n = int([l for l in head.split(b"\\r\\n") if l.lower().startswith(b"content-length:")][0].split(b":")[1])
    while len(body) < n:
        body += s.recv(4096)
    return head.split(b"\\r\\n")[0].decode() + " " + body.decode()

def shutdown():
    s = raw()
    out.append(get(s, b"/shutdown"))
    return s

def refused():
    try:
        raw().close()
        return "accepted"
    except ConnectionRefusedError:
        return "refused"

if mode == "drain":
    idle = raw(); get(idle, b"/hello")  # kept alive, then idle
    silent = raw()  # never sends anything
    up = raw()  # an upload in progress
    up.sendall(b"POST /upload HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 10\\r\\n\\r\\nabc")
    time.sleep(0.2)
    d = shutdown()
    out.append(f"idle {read_all(idle)!r}")
    out.append(f"silent {read_all(silent)!r}")
    out.append(f"shutdown-conn {read_all(d)!r}")
    out.append(refused())
    up.sendall(b"defghij" + b"GET /hello HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")  # the rest, and one more
    got = read_all(up)
    out.append(f"upload {got.count(b'HTTP/1.1')} responses, close={b'Connection: close' in got}, {got.split(b'\\r\\n\\r\\n')[-1].decode()}")
    for s in (idle, silent, d, up):
        s.close()
elif mode == "queued":
    first = raw(); get(first, b"/hello")  # holds the one connection allowed
    waiting = [raw() for _ in range(3)]  # queued by the kernel, not accepted
    for i, s in enumerate(waiting):
        s.sendall(b"GET /hello?" + str(i).encode() + b" HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    time.sleep(0.2)
    first.sendall(b"GET /shutdown HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    read_all(first)
    for s in waiting:
        got = read_all(s)
        out.append(f"{got.split(b'\\r\\n')[0].decode()} close={b'Connection: close' in got}")
        s.close()
    first.close()
elif mode in ("stream-hook", "stream-cut"):
    s = raw()
    s.sendall(b"GET " + (b"/events" if mode == "stream-hook" else b"/stubborn") + b" HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    head = b""
    while b"\\r\\n\\r\\n" not in head:
        head += s.recv(4096)
    d = shutdown()
    rest = head.partition(b"\\r\\n\\r\\n")[2] + read_all(s)
    ended = rest.endswith(b"0\\r\\n\\r\\n")
    out.append(f"{'ended' if ended else 'cut'} {[l.decode() for l in rest.split(b'\\r\\n') if l.startswith(b'data:')]}")
    s.close(); d.close()
elif mode == "close-at-once":
    s = raw()
    s.sendall(b"GET /hello HTTP/1.1\\r\\nHost: x\\r\\nConnection: close\\r\\n\\r\\n")
    got = read_all(s)
    out.append(f"{got.split(b'\\r\\n')[0].decode()} {'reset' if got.endswith(b'<reset>') else 'eof'}")
    s.sendall(b"x")  # to a closed socket: the answer is a reset...
    time.sleep(0.2)
    try:
        s.sendall(b"y")  # ...which fails the next send (after the FIN, recv still says EOF)
        out.append("then no reset")
    except (BrokenPipeError, ConnectionResetError):
        out.append("then reset")
    s.close()
elif mode in ("linger", "linger-timeout"):
    s = raw()
    s.sendall(b"POST /upload HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 50000000\\r\\n\\r\\n")
    sent = {"error": None, "bytes": 0}
    stop = time.time() + (1.0 if mode == "linger" else 5.0)
    def send():
        chunk = b"z" * 65536
        try:
            while time.time() < stop:
                sent["bytes"] += s.send(chunk)
        except OSError as e:
            sent["error"] = (type(e).__name__, time.time())
    th = threading.Thread(target=send); th.start()
    got = read_all(s)  # the 413, then the server's end of output
    t = time.time()
    out.append(f"{got.split(b'\\r\\n')[0].decode()} {'reset' if got.endswith(b'<reset>') else 'eof'}")
    th.join()
    if mode == "linger":
        out.append(f"sender {'ok' if sent['error'] is None else sent['error'][0]}")
    else:
        out.append(f"sender stopped={sent['error'] is not None} soon={sent['error'] is not None and sent['error'][1] - t < 3}")
    s.close()
print("|".join(out), flush=True)
"""


struct App(Handler):
    var want_shutdown: Bool
    var subscribers: List[UInt64]
    var ending: Bool
    var wakes: List[UInt64]
    var shutting: Int
    """Calls of `shutting_down`."""

    def __init__(out self):
        self.want_shutdown = False
        self.subscribers = List[UInt64]()
        self.ending = False
        self.wakes = List[UInt64]()
        self.shutting = 0

    def handle(mut self, req: Request, mut res: Response) raises:
        var path = req.path()
        if path == "/shutdown":
            self.want_shutdown = True
            res.text(200, "bye")
        elif path == "/hello":
            res.text(200, "hello")
        elif path == "/upload":
            res.text(200, String("got ", len(req.body)))
        elif path == "/events":
            self.subscribers.append(req.id)
            res.stream()
        elif path == "/stubborn":
            res.stream()  # never ends on its own
        else:
            res.text(404, "")

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        if req.path() == "/events" and self.ending:
            out.extend("data: bye\r\n".as_bytes())
            return False
        return True  # paused until woken (/stubborn: forever)

    def take_wakes(mut self) -> List[UInt64]:
        var w = List[UInt64]()
        swap(w, self.wakes)
        return w^

    def shutting_down(mut self):
        self.shutting += 1
        self.ending = True
        for i in range(len(self.subscribers)):
            self.wakes.append(self.subscribers[i])


@fieldwise_init
struct _Outcome(Movable):
    var out: String
    """What the client printed."""
    var drained: Duration
    """From `shutdown()` to `stopped()` (zero without a shutdown)."""
    var shutting: Int


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
    var t = Instant.now()
    var shutdown_at = Optional[Instant]()
    var drained = Optional[Duration]()
    while String(proc.poll()) == "None" or (shutdown_at and not s.stopped()):
        s.step(Duration.from_millis(5))
        if s.handler.want_shutdown and not shutdown_at:
            s.shutdown()
            shutdown_at = Instant.now()
        if shutdown_at and not drained and s.stopped():
            drained = shutdown_at.value().elapsed()
        if t.elapsed() > Duration.from_secs(60):
            _ = proc.kill()
            raise Error(String("client ", mode, " timed out"))
    var out = String(String(py=proc.communicate()[0]).strip())
    if shutdown_at:
        assert_true(Bool(drained), String(mode, ": never stopped: ", out))
        return _Outcome(out^, drained.value(), s.handler.shutting)
    for _ in range(40):  # lingering connections end with the client's
        s.step(Duration.from_millis(5))
    assert_equal(s.connections(), 0, String(mode, ": connections left: ", out))
    return _Outcome(out^, Duration.ZERO, s.handler.shutting)


def test_idle_connections_close_and_requests_in_progress_finish() raises:
    var r = _run("drain")
    assert_equal(
        r.out,
        "HTTP/1.1 200 OK bye|idle b''|silent b''|shutdown-conn b''|refused"
        + "|upload 1 responses, close=True, got 10",
    )
    assert_equal(r.shutting, 1)
    assert_true(r.drained < Duration.from_secs(3), String(r.drained.as_nanos() // 1000000, " ms"))


def test_connections_the_kernel_queued_are_answered() raises:
    var r = _run("queued", ServerConfig(max_connections=1))
    assert_equal(r.out, "HTTP/1.1 200 OK close=True|HTTP/1.1 200 OK close=True|HTTP/1.1 200 OK close=True")


def test_shutting_down_ends_streams() raises:
    var r = _run("stream-hook")
    assert_equal(r.out, "HTTP/1.1 200 OK bye|ended ['data: bye']")
    assert_true(r.drained < Duration.from_secs(3), String(r.drained.as_nanos() // 1000000, " ms"))


def test_streams_that_go_on_are_cut_at_the_timeout() raises:
    var r = _run("stream-cut", ServerConfig(shutdown_timeout=Duration.from_millis(500)))
    assert_equal(r.out, "HTTP/1.1 200 OK bye|cut []")
    assert_true(r.drained >= Duration.from_millis(450), String(r.drained.as_nanos() // 1000000, " ms"))
    assert_true(r.drained < Duration.from_secs(3), String(r.drained.as_nanos() // 1000000, " ms"))


def test_a_client_still_sending_gets_its_response_and_an_orderly_end() raises:
    var r = _run("linger", ServerConfig(max_body=1000))
    assert_equal(r.out, "HTTP/1.1 413 Content Too Large eof|sender ok")


def test_a_connection_with_nothing_unread_closes_at_once() raises:
    # no lingering when nothing can be in flight: closed, not half-closed
    var r = _run("close-at-once", ServerConfig(linger_timeout=Duration.from_secs(10)))
    assert_equal(r.out, "HTTP/1.1 200 OK eof|then reset")


def test_lingering_ends_at_its_timeout() raises:
    var r = _run("linger-timeout", ServerConfig(max_body=1000, linger_timeout=Duration.from_millis(300)))
    assert_equal(r.out, "HTTP/1.1 413 Content Too Large eof|sender stopped=True soon=True")


def test_shutdown_without_connections_and_twice() raises:
    var s = Server(App())
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    assert_false(s.stopped())
    s.shutdown()
    assert_true(s.stopped())
    s.shutdown()  # again: no change
    s.run()  # returns at once: the shutdown has finished
    s.step(Duration.from_millis(1))  # still fine without a listener
    assert_equal(s.handler.shutting, 1)
    assert_equal(s.connections(), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
