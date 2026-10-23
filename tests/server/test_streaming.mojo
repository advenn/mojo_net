"""`server.Server` streaming (S2), end to end against Python clients:
request bodies taken piece by piece (`stream_request` / `on_body`) with no
`max_body`; responses produced as the client takes them (`res.stream()` /
`produce`), paced by backpressure, chunked or with the handler's
Content-Length; server-sent events that pause and are woken by another
connection's request (`take_wakes`) or by `Server.wake` between steps;
paused streams that outlive the timeouts, and end when their client leaves
(also behind a full receive buffer); a stream that keeps waking itself;
HEAD on a stream; failing hooks."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_true

from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig

comptime _CLIENT = """
import http.client, socket, sys, time
port = int(sys.argv[1]); mode = sys.argv[2]
out = []
def conn():
    return http.client.HTTPConnection("127.0.0.1", port, timeout=20)
if mode == "upload":
    c = conn()
    body = bytes(range(256)) * (128 * 1024)  # 32 MiB
    c.request("PUT", "/upload", body=iter([body[i:i + 65536] for i in range(0, len(body), 65536)]), encode_chunked=True)
    r = c.getresponse(); out.append(f"{r.status} {r.read().decode()} want={len(body)}:{sum(body) % 1000003}")
    c.request("PUT", "/upload", body=b"small"); r = c.getresponse(); out.append(f"{r.status} {r.read().decode()}")
elif mode == "download":
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    s.connect(("127.0.0.1", port))
    s.sendall(b"GET /download HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    f = s.makefile("rb")
    r = http.client.HTTPResponse(s); r.fp = f; r.begin()
    total = 0
    while True:
        d = r.read(65536)
        if not d:
            break
        total += len(d)
        time.sleep(0.0005)  # a slowish reader
    out.append(f"{r.status} te={r.getheader('Transfer-Encoding')} total={total}")
    c = conn(); c.request("HEAD", "/download"); r = c.getresponse()
    out.append(f"head {r.status} [{r.read().decode()}]")
    c = conn(); c.request("GET", "/sized"); r = c.getresponse(); b = r.read()
    out.append(f"sized te={r.getheader('Transfer-Encoding')} cl={r.getheader('Content-Length')} {len(b)} {set(b) == {0x63}}")
elif mode == "headraw":
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    s.sendall(b"HEAD /download HTTP/1.1\\r\\nHost: x\\r\\n\\r\\nGET /small HTTP/1.1\\r\\nHost: x\\r\\nConnection: close\\r\\n\\r\\n")
    data = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        data += d
    end = data.index(b"\\r\\n\\r\\n") + 4
    rest = data[end:]
    te = b"\\r\\ntransfer-encoding: chunked\\r\\n" in data[:end].lower()
    body = rest.endswith(b"\\r\\n\\r\\nsmall")
    out.append(f"next={rest.startswith(b'HTTP/1.1 200 OK')} body={body} te={te}")
elif mode == "events":
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    s.sendall(b"GET /events HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    head = b""
    while b"\\r\\n\\r\\n" not in head:
        head += s.recv(4096)
    out.append(head.split(b"\\r\\n")[0].decode())
    for msg in ["one", "two"]:
        p = conn(); p.request("POST", "/publish", body=msg.encode()); r = p.getresponse(); r.read()
    p = conn(); p.request("POST", "/close", body=b""); r = p.getresponse(); r.read()
    rest = b""
    while True:
        d = s.recv(4096)
        if not d:
            break
        rest += d
        if rest.endswith(b"0\\r\\n\\r\\n"):
            break
    events = [line for line in rest.split(b"\\r\\n") if line.startswith(b"data:")]
    out.append(" ".join(e.decode() for e in events))
elif mode == "patient":
    # events, with waits far longer than the server's timeouts
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    s.sendall(b"GET /events HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    head = b""
    while b"\\r\\n\\r\\n" not in head:
        head += s.recv(4096)
    time.sleep(1.0)
    p = conn(); p.request("POST", "/publish", body=b"late"); r = p.getresponse(); r.read()
    time.sleep(0.5)
    p = conn(); p.request("POST", "/close", body=b""); r = p.getresponse(); r.read()
    rest = head.split(b"\\r\\n\\r\\n", 1)[1]
    while not rest.endswith(b"0\\r\\n\\r\\n"):
        d = s.recv(4096)
        if not d:
            break
        rest += d
    events = [line for line in rest.split(b"\\r\\n") if line.startswith(b"data:")]
    out.append(" ".join(e.decode() for e in events) + (" ended" if rest.endswith(b"0\\r\\n\\r\\n") else " cut"))
elif mode == "outside":
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    s.sendall(b"GET /events HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    data = b""
    while data.count(b"data:") < 5:
        d = s.recv(4096)
        if not d:
            break
        data += d
    s.close()
    out.append(f"{data.count(b'data:')}")
elif mode == "spin":
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    s.sendall(b"GET /spin HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    head = b""
    while b"\\r\\n\\r\\n" not in head:
        head += s.recv(4096)
    c = conn(); c.request("POST", "/stop", body=b""); r = c.getresponse(); r.read()
    out.append(f"{r.status}")
    rest = head.split(b"\\r\\n\\r\\n", 1)[1]
    while not rest.endswith(b"0\\r\\n\\r\\n"):
        d = s.recv(4096)
        if not d:
            break
        rest += d
    out.append("ended" if rest.endswith(b"0\\r\\n\\r\\n") else "cut")
elif mode == "flood":
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    s.sendall(b"GET /events HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    head = b""
    while b"\\r\\n\\r\\n" not in head:
        head += s.recv(4096)
    # requests pipelined behind the paused stream: more than the server's
    # codec holds (80 KiB), little enough for its socket to take the rest
    s.sendall(b"GET /small HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n" * 3000)
    time.sleep(0.3)
    s.close()  # the end of input sits behind what the server cannot read
    time.sleep(0.3)
    out.append("flooded")
elif mode == "abandon":
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    s.sendall(b"GET /events HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    head = b""
    while b"\\r\\n\\r\\n" not in head:
        head += s.recv(4096)
    s.close()  # gone while the stream is paused
    time.sleep(0.3)
    out.append("left")
elif mode == "failing":
    c = conn(); c.request("PUT", "/upload-fail", body=b"x" * 1000); r = c.getresponse()
    out.append(f"{r.status}")
    c = conn(); c.request("GET", "/produce-fail")
    r = c.getresponse()
    try:
        r.read(); out.append("complete")
    except http.client.IncompleteRead:
        out.append("cut")
print("|".join(out), flush=True)
"""


struct App(Handler):
    var got: Int
    var sum: Int
    var left: Int
    """Bytes of the download still to produce."""
    var subscribers: List[UInt64]
    var queues: List[String]
    """Per subscriber: events waiting to go out."""
    var closing: Bool
    var wakes: List[UInt64]
    var produced_for_head: Int
    var sized_left: Int
    var spins: Int
    var stop: Bool
    var stopped_while_spinning: Bool

    def __init__(out self):
        self.got = 0
        self.sum = 0
        self.left = 0
        self.subscribers = List[UInt64]()
        self.queues = List[String]()
        self.closing = False
        self.wakes = List[UInt64]()
        self.produced_for_head = 0
        self.sized_left = 0
        self.spins = 0
        self.stop = False
        self.stopped_while_spinning = False

    def stream_request(mut self, req: Request) raises -> Bool:
        if req.path() == "/upload" or req.path() == "/upload-fail":
            self.got = 0
            self.sum = 0
            return True
        return False

    def on_body(mut self, req: Request, data: Span[UInt8, _]) raises:
        if req.path() == "/upload-fail":
            raise Error("refused")
        self.got += len(data)
        for b in data:
            self.sum += Int(b)
        self.sum %= 1000003

    def handle(mut self, req: Request, mut res: Response) raises:
        var path = req.path()
        if path == "/upload":
            res.text(200, String("got=", self.got, ":", self.sum))
        elif path == "/download":
            self.left = 32 * 1024 * 1024
            res.headers.add("Content-Type", "application/octet-stream")
            res.stream()
        elif path == "/events":
            self.subscribers.append(req.id)
            self.queues.append(String())
            res.headers.add("Content-Type", "text/event-stream")
            res.stream()
        elif path == "/publish":
            for i in range(len(self.subscribers)):
                self.queues[i] += String("data: ", req.text(), "\r\n")
                self.wakes.append(self.subscribers[i])
            res.status = 204
        elif path == "/close":
            self.closing = True
            for i in range(len(self.subscribers)):
                self.wakes.append(self.subscribers[i])
            res.status = 204
        elif path == "/produce-fail":
            res.stream()
        elif path == "/sized":
            self.sized_left = 1000000
            res.headers.add("Content-Length", "1000000")
            res.stream()
        elif path == "/small":
            res.text(200, "small")
        elif path == "/spin":
            res.stream()
        elif path == "/stop":
            self.stop = True
            self.stopped_while_spinning = self.spins > 0 and self.spins < _VALVE
            res.status = 204
        else:
            res.text(404, "")

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        var path = req.path()
        if req.method == "HEAD":
            self.produced_for_head += 1
        if path == "/download":
            var n = min(self.left, 65536)
            for _ in range(n):
                out.append(0x61)
            self.left -= n
            return self.left > 0
        if path == "/events":
            for i in range(len(self.subscribers)):
                if self.subscribers[i] == req.id:
                    if self.queues[i].byte_length() > 0:
                        out.extend(self.queues[i].as_bytes())
                        self.queues[i] = String()
                    return not self.closing
            return False
        if path == "/produce-fail":
            for _ in range(1000):
                out.append(0x62)
            if len(self.wakes) == 0 and self.got == 0:
                self.got = 1
                return True
            raise Error("producer broke")
        if path == "/sized":
            var n = min(self.sized_left, 65536)
            for _ in range(n):
                out.append(0x63)
            self.sized_left -= n
            return self.sized_left > 0
        if path == "/spin":
            if self.stop or self.spins >= _VALVE:
                return False
            self.spins += 1
            self.wakes.append(req.id)  # nothing yet, but ask again at once
            return True
        return False

    def take_wakes(mut self) -> List[UInt64]:
        var w = List[UInt64]()
        swap(w, self.wakes)
        return w^


comptime _VALVE = 1000000
"""Spins after which `/spin` gives up: long after `/stop` should have come."""


def _start(mode: StaticString, port: String) raises -> PythonObject:
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    return subprocess.Popen(
        Python.list(pysys.executable, "-c", _CLIENT, port, mode),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def _run(mode: StaticString, config: ServerConfig = ServerConfig()) raises -> String:
    var s = Server(App(), config)
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var proc = _start(mode, String(s.local_addr().port()))
    return _finish(s, proc, mode)


def _finish(mut s: Server[App], proc: PythonObject, mode: StaticString) raises -> String:
    """Serve until the client exits: its output, once no connection is
    left open."""
    var peak = 0
    var t = Instant.now()
    while String(proc.poll()) == "None":
        s.step(Duration.from_millis(5))
        peak = max(peak, s.queued_output())
        if t.elapsed() > Duration.from_secs(60):
            _ = proc.kill()
            raise Error(String("client ", mode, " timed out"))
    var out = String(String(py=proc.communicate()[0]).strip())
    for _ in range(20):
        s.step(Duration.from_millis(5))
    assert_equal(s.connections(), 0, String(mode, ": connections left"))
    if mode == "download":
        # paced by the client: never much more than the high-water mark
        assert_true(peak < 1024 * 1024, String("queued ", peak))
        assert_equal(s.handler.produced_for_head, 0)  # HEAD never produces
    if mode == "headraw":
        assert_equal(s.handler.produced_for_head, 0)
    if mode == "spin":
        # /stop was served while the stream kept waking itself
        assert_true(s.handler.stopped_while_spinning, String("spins ", s.handler.spins))
    s.wake(0xFFFFFFFF00000001)  # a stale or unknown id: ignored
    return out^


def test_request_bodies_stream_past_max_body() raises:
    var got = _run("upload", ServerConfig(max_body=1024))  # 32 MiB with a 1 KiB limit
    var parts = got.split("|")
    assert_equal(len(parts), 2, got)
    var first = String(parts[0])
    var want = first[byte = first.find("want=") + 5 :]
    assert_true(first.startswith(String("200 got=", want)), got)
    assert_equal(String(parts[1]), "200 got=5:" + String(ord("s") + ord("m") + ord("a") + ord("l") + ord("l")))


def test_responses_stream_at_the_clients_pace() raises:
    assert_equal(
        _run("download"),
        "200 te=chunked total=33554432|head 200 []|sized te=None cl=1000000 1000000 True",
    )


def test_head_on_a_stream_sends_the_head_only() raises:
    # the next response follows the head at once: no body, no last chunk
    assert_equal(_run("headraw"), "next=True body=True te=True")


def test_events_pause_and_are_woken_by_other_requests() raises:
    assert_equal(_run("events"), "HTTP/1.1 200 OK|data: one data: two")


def test_a_paused_stream_outlives_the_timeouts() raises:
    var short = Duration.from_millis(200)
    var config = ServerConfig(header_timeout=short, idle_timeout=short, read_timeout=short)
    assert_equal(_run("patient", config), "data: late ended")


def test_a_wake_between_steps_is_served_without_waiting() raises:
    var s = Server(App())
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var proc = _start("outside", String(s.local_addr().port()))
    var t = Instant.now()
    while len(s.handler.subscribers) == 0:  # (its stream is then paused)
        s.step(Duration.from_millis(5))
        if t.elapsed() > Duration.from_secs(60):
            _ = proc.kill()
            raise Error("no subscriber")
    var start = Instant.now()
    for k in range(5):
        s.handler.queues[0] += String("data: ", k, "\r\n")
        s.wake(s.handler.subscribers[0])
        s.step(Duration.from_secs(2))  # serves the wake without waiting
    var took = start.elapsed()
    assert_equal(_finish(s, proc, "outside"), "5")
    # had each step waited for readiness first, they would take a second each
    assert_true(took < Duration.from_millis(500), String(took.as_nanos() // 1000000, " ms"))


def test_a_stream_that_keeps_waking_itself_does_not_stall_the_loop() raises:
    assert_equal(_run("spin"), "204|ended")


def test_an_abandoned_paused_stream_is_closed() raises:
    assert_equal(_run("abandon"), "left")  # and no connection is left open


def test_a_client_gone_behind_a_full_buffer_ends_its_stream() raises:
    assert_equal(_run("flood"), "flooded")  # and no connection is left open


def test_failing_hooks() raises:
    assert_equal(_run("failing"), "500|cut")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
