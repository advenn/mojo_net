"""`server.Server` server-sent events (S6), end to end against Python
clients that parse what arrives with tests/http/sse_oracle.py (the
WHATWG algorithm, written independently): `res.event_stream()` and its
fields, events written by `http.sse.write_event`, heartbeats while a
stream is paused (none while it sends, none inside a line, none with a
handler's Content-Length, none on HEAD), a client that leaves, and
`res.retry_later`."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_true

from http.sse import write_comment, write_event
from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig

comptime _CLIENT = """
import http.client, socket, sys, time
sys.path.insert(0, "tests/http")
import sse_oracle
port = int(sys.argv[1]); mode = sys.argv[2]
out = []
def conn():
    return http.client.HTTPConnection("127.0.0.1", port, timeout=20)
def post(path):
    c = conn(); c.request("POST", path, body=b""); r = c.getresponse(); r.read(); c.close()
def open_stream(path, method="GET"):
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    s.sendall(method.encode() + b" " + path.encode() + b" HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    data = b""
    while b"\\r\\n\\r\\n" not in data:
        data += s.recv(4096)
    head, rest = data.split(b"\\r\\n\\r\\n", 1)
    fields = {}
    for line in head.split(b"\\r\\n")[1:]:
        k, v = line.split(b":", 1)
        fields[k.strip().lower().decode()] = v.strip().decode()
    return s, head.split(b"\\r\\n")[0].decode(), fields, rest
def dechunk(raw):
    body, i = b"", 0
    while True:
        j = raw.find(b"\\r\\n", i)
        if j < 0:
            return body, False
        size = int(raw[i:j].split(b";")[0], 16)
        if size == 0:
            return body, True
        if len(raw) < j + 2 + size + 2:
            return body + raw[j + 2:j + 2 + size], False
        body += raw[j + 2:j + 2 + size]
        i = j + 2 + size + 2
def read_for(s, raw, seconds):
    s.settimeout(0.02)
    t = time.time()
    while time.time() - t < seconds:
        try:
            d = s.recv(65536)
            if not d:
                break
            raw += d
        except socket.timeout:
            pass
    s.settimeout(20)
    return raw
def read_to_end(s, raw):
    while not dechunk(raw)[1]:
        d = s.recv(65536)
        if not d:
            break
        raw += d
    return raw
def beats(body):
    return sum(1 for line in body.split(b"\\n") if line == b":")
if mode == "events":
    s, status, f, raw = open_stream("/events")
    out.append(status)
    out.append(f"{f.get('content-type')} {f.get('cache-control')} {f.get('x-accel-buffering')} {f.get('transfer-encoding')}")
    raw = read_for(s, raw, 0.6)  # paused: heartbeats every 100 ms
    quiet = beats(dechunk(raw)[0])
    out.append(f"quiet={2 <= quiet <= 9}:{quiet}")
    post("/publish?one")
    post("/publish?two")
    post("/close")
    body, ended = dechunk(read_to_end(s, raw))
    events, last_id, retry, discarded = sse_oracle.parse(body)
    out.append(f"{events} last={last_id} retry={retry} cut={discarded} ended={ended}")
elif mode == "ticks":
    s, status, f, raw = open_stream("/ticks")
    while dechunk(raw)[0].count(b"data: tick 12\\n") == 0:  # woken every 30 ms
        raw += s.recv(65536)
    busy = beats(dechunk(raw)[0])
    raw = read_for(s, raw, 0.8)  # then quiet: heartbeats every 250 ms
    after = beats(dechunk(raw)[0]) - busy
    post("/close")
    body, ended = dechunk(read_to_end(s, raw))
    events = sse_oracle.parse(body)[0]
    out.append(f"busy={busy} after={1 <= after <= 5}:{after} events={len(events)} ended={ended}")
elif mode == "partial":
    s, status, f, raw = open_stream("/partial")
    raw = read_for(s, raw, 0.4)  # a line left open: no heartbeat inside it
    post("/finish-partial")
    body, ended = dechunk(read_to_end(s, raw))
    out.append(f"{body!r} {ended}")
elif mode == "sized":
    c = conn(); c.request("GET", "/sized-events"); r = c.getresponse()
    time.sleep(0.4)
    post("/finish-sized")
    b = r.read()
    out.append(f"{r.getheader('Content-Length')} {b!r}")
elif mode == "head":
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    s.sendall(b"HEAD /events HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    time.sleep(0.4)  # longer than the heartbeat: nothing may come
    s.sendall(b"GET /small HTTP/1.1\\r\\nHost: x\\r\\nConnection: close\\r\\n\\r\\n")
    data = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        data += d
    end = data.index(b"\\r\\n\\r\\n") + 4
    out.append(f"{b'text/event-stream' in data[:end]} next={data[end:].startswith(b'HTTP/1.1 200 OK')}")
elif mode == "gone":
    s, status, f, raw = open_stream("/events")
    while beats(dechunk(raw)[0]) < 1:
        raw += s.recv(65536)
    s.close()
    time.sleep(0.3)
    out.append("left")
elif mode == "reuse":
    # an event stream, then a plain stream on the same connection: the
    # plain one, paused past several heartbeats, gets none
    c = conn()
    c.request("GET", "/one-event"); r = c.getresponse(); first = r.read()
    c.request("GET", "/plain-paused"); r = c.getresponse()
    time.sleep(0.4)
    post("/finish-plain")
    out.append(f"{first!r} {r.getheader('Content-Type')} {r.read()!r}")
elif mode == "retry":
    for path in ["/busy", "/limited"]:
        c = conn(); c.request("GET", path); r = c.getresponse()
        out.append(f"{r.status} {r.getheader('Retry-After')} {r.read().decode().strip()}")
print("|".join(out), flush=True)
"""


struct App(Handler):
    var subscriber: UInt64
    var queue: List[String]
    var sent: Int
    """Events sent on /events: the last one's ID."""
    var closing: Bool
    var wakes: List[UInt64]
    var tick_id: UInt64
    var ticks_due: Int
    var ticks: Int
    var stage: Int
    """/partial and /sized-events: 0 before the first write, then 1, 2 at the end."""
    var finished: Int
    var cut: Int

    def __init__(out self):
        self.subscriber = 0
        self.queue = List[String]()
        self.sent = 0
        self.closing = False
        self.wakes = List[UInt64]()
        self.tick_id = 0
        self.ticks_due = 0
        self.ticks = 0
        self.stage = 0
        self.finished = 0
        self.cut = 0

    def handle(mut self, req: Request, mut res: Response) raises:
        var path = req.path()
        if path == "/events" or path == "/partial":
            self.subscriber = req.id
            res.event_stream()
        elif path == "/ticks":
            self.tick_id = req.id
            res.event_stream()
        elif path == "/sized-events":
            self.subscriber = req.id
            res.event_stream()
            res.headers.set("Content-Length", "12")
        elif path == "/publish":
            self.queue.append(String(req.target[byte = req.target.find("?") + 1 :]))
            self.wakes.append(self.subscriber)
            res.status = 204
        elif path == "/close":
            self.closing = True
            self.wakes.append(self.subscriber)
            self.wakes.append(self.tick_id)
            res.status = 204
        elif path == "/one-event":
            res.event_stream()
        elif path == "/plain-paused":
            self.subscriber = req.id
            res.headers.set("Content-Type", "application/octet-stream")
            res.stream()
        elif path == "/finish-partial" or path == "/finish-sized" or path == "/finish-plain":
            self.stage = 1
            self.wakes.append(self.subscriber)
            res.status = 204
        elif path == "/busy":
            res.retry_later(503, Duration.from_millis(1500))
        elif path == "/limited":
            res.retry_later(429, Duration.from_secs(3), "slow down")
        elif path == "/small":
            res.text(200, "small")
        else:
            res.text(404, "")

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        var path = req.path()
        if path == "/events":
            for i in range(len(self.queue)):
                self.sent += 1
                write_event(out, self.queue[i], event="pub", id=String(self.sent))
            self.queue.clear()
            return not self.closing
        if path == "/ticks":
            if self.ticks < self.ticks_due:
                self.ticks += 1
                write_event(out, String("tick ", self.ticks))
                if self.ticks == 1:
                    write_comment(out, "a comment the handler wrote")
                return True
            return not self.closing
        if path == "/partial":
            if self.stage == 0:
                out.extend("data: par".as_bytes())  # (a line left open)
                self.stage = 2
                return True
            if self.stage == 1:
                out.extend("t\n\n".as_bytes())
                return False
            return True
        if path == "/one-event":
            write_event(out, "only")
            return False
        if path == "/plain-paused":
            if self.stage == 1:
                out.extend("abc".as_bytes())
                return False
            return True
        if path == "/sized-events":
            if self.stage == 1:
                out.extend("data: abcd\n\n".as_bytes())
                return False
            return True  # paused, past several heartbeats
        return False

    def take_wakes(mut self) -> List[UInt64]:
        var w = List[UInt64]()
        swap(w, self.wakes)
        return w^

    def stream_ended(mut self, req: Request, finished: Bool):
        if finished:
            self.finished += 1
        else:
            self.cut += 1


@fieldwise_init
struct _Result(Movable):
    var report: String
    """What the client printed."""
    var finished: Int
    var cut: Int


def _run(mode: StaticString, heartbeat: Duration = Duration.from_millis(100)) raises -> _Result:
    """Serve `mode`'s client until it exits, then until no connection is
    left open."""
    var s = Server(App(), ServerConfig(heartbeat=heartbeat))
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
    var last_tick = Instant.now()
    while String(proc.poll()) == "None":
        s.step(Duration.from_millis(5))
        # /ticks: a wake every 30 ms, 12 in all, from outside the handler
        if s.handler.tick_id != 0 and s.handler.ticks_due < 12 and last_tick.elapsed() >= Duration.from_millis(30):
            s.handler.ticks_due += 1
            s.wake(s.handler.tick_id)
            last_tick = Instant.now()
        if t.elapsed() > Duration.from_secs(60):
            _ = proc.kill()
            raise Error(String("client ", mode, " timed out"))
    var out = String(String(py=proc.communicate()[0]).strip())
    for _ in range(20):
        s.step(Duration.from_millis(5))
    assert_equal(s.connections(), 0, String(mode, ": connections left"))
    return _Result(out^, s.handler.finished, s.handler.cut)


def test_events_and_heartbeats() raises:
    var r = _run("events")
    var got = r.report.split("|")
    assert_equal(len(got), 4, r.report)
    assert_equal(String(got[0]), "HTTP/1.1 200 OK")
    assert_equal(String(got[1]), "text/event-stream no-cache no chunked")
    assert_true(String(got[2]).startswith("quiet=True"), String(got[2]))
    assert_equal(String(got[3]), "[('pub', 'one', '1'), ('pub', 'two', '2')] last=2 retry=None cut=False ended=True")
    assert_equal(r.finished, 1)
    assert_equal(r.cut, 0)


def test_no_heartbeat_while_a_stream_sends() raises:
    var r = _run("ticks", Duration.from_millis(250))
    var got = r.report
    assert_true(got.startswith("busy=0 after=True"), got)
    assert_true(got.endswith("events=12 ended=True"), got)


def test_no_heartbeat_inside_a_line() raises:
    var r = _run("partial")
    assert_equal(r.report, "b'data: part\\n\\n' True")


def test_no_heartbeat_with_a_content_length() raises:
    var r = _run("sized")
    assert_equal(r.report, "12 b'data: abcd\\n\\n'")


def test_no_heartbeat_on_head() raises:
    var r = _run("head")
    assert_equal(r.report, "True next=True")


def test_no_heartbeat_for_a_later_plain_stream() raises:
    var r = _run("reuse")
    assert_equal(r.report, "b'data: only\\n\\n' application/octet-stream b'abc'")


def test_a_client_that_leaves_ends_the_stream() raises:
    var r = _run("gone")
    assert_equal(r.report, "left")
    assert_equal(r.cut, 1)


def test_retry_later() raises:
    var r = _run("retry")
    assert_equal(r.report, "503 2 Service Unavailable|429 3 slow down")
    var res = Response()
    assert_true(_refused(res, 200))
    assert_true(_refused(res, 600))
    res.retry_later(503, Duration.ZERO)
    assert_equal(String(res.headers.get("retry-after").value()), "0")


def _refused(mut r: Response, status: Int) -> Bool:
    try:
        r.retry_later(status, Duration.from_secs(1))
        return False
    except:
        return True


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
