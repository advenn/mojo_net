"""Regression tests for the second review of the server (SR2, 2026-10-28),
each checked to fail on the code before its fix:
- RTR-1: paths the router cannot route (an encoded "/" or NUL, more than
  128 segments) went to the application's fallback, past every route's
  checks (now 400 and 404, unless `fallback_unroutable`);
- RTR-2: parameters were decoded lossily, so `a%FF` and `a%FE` gave one
  value (now 400);
- RTR-3: `route()` took a name used twice in one pattern, a method that
  is not a token, and text no decoded path can hold;
- RTR-4: `last_params()` kept the last match's parameters after a miss;
- SRV-1: a paused stream to a peer that vanished without FIN or RST was
  never reclaimed (keepalive probes are now on for it);
- SRV-2: `Server.config` was public, so `server_name` could be changed
  past its validation and split every response;
- BP-1: a library log line to a stderr pipe whose reader was gone
  killed the process (SIGPIPE: a TLS reload or renewal note did it);
- SRV-3: `_enough` wrapped for a long timeout times a large `min_rate`,
  and then any progress renewed the timeout;
- BP-2: the idle timer of the next request started when a long response
  was queued, not when it had gone out;
- BP-3: a second `bind` closed the first listener without a word;
- BP-4: a negative `max_body` answered 413 to every request, and a ZERO
  timeout closed connections at the next sweep;
- BP-5: the server's own error answers (400, 408, 505, ...) had no
  `Server` field;
- BP-6, I-6: `Request.number` numbers a connection's requests;
- STA-11: `Request.unix_time` is the second of the response's Date;
- `PRI * HTTP/2.0` (an HTTP/2 client with prior knowledge) gets one 505,
  then an orderly end."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, sys
from linux.consts import O_CLOEXEC, SIGPIPE
from linux.error import check
from linux.fd import OwnedFd, RawFd
from linux.signal import SignalSet, blocked, set_mask, unblock
from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import Handler, Params, Request, Response, Router, Server, ServerConfig
from server.router import ENCODED_SLASH, MALFORMED, NO_ROUTE, TOO_DEEP
from server.process import _log
from server.server import _enough

# ---- the router (RTR-1..4) ----------------------------------------------------------


struct Fallback(Handler):
    var log: List[String]

    def __init__(out self):
        self.log = List[String]()

    def handle(mut self, req: Request, mut res: Response) raises:
        self.log.append(String(req.target))
        res.text(200, "fallback\n")


def deny(mut app: Fallback, req: Request, params: Params, mut res: Response) raises:
    res.text(403, "denied\n")


def user(mut app: Fallback, req: Request, params: Params, mut res: Response) raises:
    res.text(200, String("user ", params["id"]))


def _request(method: StringSlice, target: StringSlice) raises -> Request:
    var r = Request(SocketAddr.parse("127.0.0.1:1"))
    r.method = String(method)
    r.target = String(target)
    return r^


def _call(mut router: Router[Fallback], method: StringSlice, target: StringSlice) raises -> String:
    var res = Response()
    router.handle(_request(method, target), res)
    return String(res.status, " ", String(from_utf8_lossy=Span(res.body)).strip())


def _router() raises -> Router[Fallback]:
    var r = Router(Fallback())
    r.get("/admin/*rest", deny)
    r.get("/users/:id", user)
    return r^


def _deep() -> String:
    var p = String("/admin")
    for _ in range(130):
        p += "/a"
    return p^


def test_unroutable_paths_fail_closed() raises:
    var r = _router()
    assert_equal(_call(r, "GET", "/admin/a%2Fb"), "400 Bad Request")
    assert_equal(_call(r, "GET", "/admin/a%00b"), "400 Bad Request")
    assert_equal(_call(r, "GET", _deep()), "404 Not Found")
    assert_equal(len(r.app.log), 0, "the fallback was asked")
    assert_equal(r.find("GET", "/x%2Fy"), ENCODED_SLASH)
    assert_equal(r.find("GET", _deep()), TOO_DEEP)
    assert_equal(r.find("OPTIONS", "*"), NO_ROUTE)  # (the asterisk form: the application's)
    # opted in: the application gets them
    r.fallback_unroutable = True
    assert_equal(_call(r, "GET", "/admin/a%2Fb"), "200 fallback")
    assert_equal(_call(r, "GET", _deep()), "200 fallback")
    assert_equal(_call(r, "GET", "/admin/%zz"), "400 Bad Request")  # malformed: never
    assert_equal(len(r.app.log), 2)


def test_parameters_must_be_utf8() raises:
    var r = _router()
    assert_equal(_call(r, "GET", "/users/a%FF"), "400 Bad Request")
    assert_equal(_call(r, "GET", "/users/a%FE"), "400 Bad Request")
    assert_equal(_call(r, "GET", "/admin/caf%E9"), "400 Bad Request")  # (a rest, too)
    assert_equal(r.find("GET", "/users/a%C3"), MALFORMED)
    assert_equal(_call(r, "GET", "/users/a%EF%BF%BD"), "200 user a�")  # (U+FFFD itself is fine)
    assert_equal(_call(r, "GET", "/users/j%C3%B6rg"), "200 user jörg")


def _refused(pattern: StringSlice, method: StringSlice = "GET") -> Bool:
    try:
        var r = _router()
        r.route(method, pattern, user)
        return False
    except:
        return True


def test_unusable_patterns_are_refused() raises:
    assert_true(_refused("/orgs/:id/users/:id"))
    assert_true(_refused("/orgs/:id/*id"))
    assert_true(_refused("/x", ""))
    assert_true(_refused("/x", "GE T"))
    assert_true(_refused("/x", "GET\r\n"))
    assert_true(_refused("/caf%C3%A9"))
    assert_true(_refused("/a?b"))
    assert_true(_refused("/a#b"))
    assert_false(_refused("/orgs/:org/users/:id"))
    assert_false(_refused("/x", "PURGE"))


def test_a_miss_clears_the_parameters() raises:
    var r = _router()
    assert_true(r.find("GET", "/users/7") >= 0)
    assert_equal(len(r.last_params()), 1)
    assert_equal(r.find("GET", "/nowhere"), NO_ROUTE)
    assert_equal(len(r.last_params()), 0)
    assert_true(r.find("GET", "/users/7") >= 0)
    assert_equal(r.find("GET", "/users/%zz"), MALFORMED)
    assert_equal(len(r.last_params()), 0)


# ---- configuration (SRV-2, SRV-3, BP-3, BP-4) ----------------------------------------


struct App(Handler):
    var paused: Int

    def __init__(out self):
        self.paused = 0

    def handle(mut self, req: Request, mut res: Response) raises:
        var path = req.path()
        if path == "/n":
            res.text(200, String(req.number))
        elif path == "/time":
            res.text(200, String(req.unix_time))
        elif path == "/poll":
            res.stream()  # a long poll: nothing until a wake, which never comes
        elif path == "/big":
            var body = List[UInt8](length=32 * 1024 * 1024, fill=0x61)
            res.bytes(200, Span(body), "application/octet-stream")
        else:
            res.text(200, "hello\n")

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        self.paused += 1
        return True


def _config_refused(config: ServerConfig) -> Bool:
    try:
        _ = Server(App(), config)
        return False
    except e:
        return e.kind == ErrorKind.InvalidInput


def test_the_configuration_cannot_change_after_validation() raises:
    var s = Server(App(), ServerConfig(server_name="a"))
    var c = s.config()
    c.server_name = String("x\r\nSet-Cookie: e=1")
    assert_equal(s.config().server_name, "a")


def test_a_rate_times_a_long_timeout_does_not_wrap() raises:
    assert_false(_enough(1, Duration.from_secs(10**11), 10**9))
    assert_false(_enough(10**12, Duration.from_secs(10**11), 10**9))
    assert_true(_enough(512 * 30, Duration.from_secs(30), 512))
    assert_false(_enough(512 * 30 - 1, Duration.from_secs(30), 512))


def test_a_log_line_to_a_broken_stderr_is_harmless() raises:
    var before = blocked()
    var saved = OwnedFd(unsafe_from_raw=Int32(check("dup", sys.fcntl(RawFd(2), 1030, 10))))  # F_DUPFD_CLOEXEC
    var fds = Array[Int32, 2](fill=-1)
    _ = check("pipe2", sys.pipe2(fds, O_CLOEXEC))
    var w = OwnedFd(unsafe_from_raw=fds[1])
    _ = OwnedFd(unsafe_from_raw=fds[0])  # (the reader is gone at once)
    _ = check("dup3", sys.dup3(w, 2, 0))
    _ = unblock(SignalSet.of(SIGPIPE))  # (SIGPIPE at its default: it would end the process)
    _log("tls: reloaded cert.pem")  # a plain write(2) would end the process here
    _ = set_mask(before)
    _ = check("dup3", sys.dup3(saved, 2, 0))
    assert_true(True, "alive")


def test_a_second_bind_is_refused() raises:
    var s = Server(App())
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = s.local_addr().port()
    var refused = False
    try:
        s.bind(SocketAddr.parse("127.0.0.1:0"))
    except e:
        refused = e.kind == ErrorKind.InvalidInput
    assert_true(refused)
    assert_equal(s.local_addr().port(), port)  # still listening where it was


def test_settings_that_cannot_work_are_refused() raises:
    assert_true(_config_refused(ServerConfig(max_body=-1)))
    assert_true(_config_refused(ServerConfig(header_timeout=Duration.ZERO)))
    assert_true(_config_refused(ServerConfig(idle_timeout=Duration.ZERO)))
    assert_true(_config_refused(ServerConfig(read_timeout=Duration.ZERO)))
    assert_true(_config_refused(ServerConfig(write_timeout=Duration.ZERO)))
    assert_false(_config_refused(ServerConfig(max_body=0)))
    assert_false(_config_refused(ServerConfig(heartbeat=Duration.ZERO)))  # (never: documented)
    assert_false(_config_refused(ServerConfig(idle_timeout=Duration.MAX)))


# ---- over the wire --------------------------------------------------------------------

comptime _CLIENT = """
import email.utils, http.client, socket, sys, time
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
            return data, "reset"
        except socket.timeout:
            return data, "timeout"
        if not c:
            return data, "eof"
        data += c
def fields(data):
    head = data.split(b"\\r\\n\\r\\n")[0].decode(errors="replace").split("\\r\\n")
    return head[0], {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in head[1:] if ":" in l}
if mode == "numbers":
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    for _ in range(3):
        c.request("GET", "/n"); out.append(c.getresponse().read().decode())
    c2 = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c2.request("GET", "/n"); out.append(c2.getresponse().read().decode())
elif mode == "time":
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", "/time"); r = c.getresponse(); t = int(r.read())
    date = int(email.utils.parsedate_to_datetime(r.getheader("Date")).timestamp())
    out.append(f"same={t == date} near={abs(t - time.time()) < 5}")
elif mode == "errors":
    for req in [b"GET / HTTP/1.1\\r\\n\\r\\n", b"GET / HTTP/3.0\\r\\nHost: x\\r\\n\\r\\n"]:
        s = raw(); s.sendall(req)
        data, end = read_all(s)
        line, f = fields(data)
        out.append(f"{line.split(' ')[1]} {f.get('server')}")
    s = raw(); s.sendall(b"GET / HTTP/1.1\\r\\n")  # a head begun: 408 after the header timeout
    data, end = read_all(s)
    line, f = fields(data)
    out.append(f"{line.split(' ')[1]} {f.get('server')}")
elif mode == "h2":
    s = raw()
    settings = b"\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x00\\x00"
    s.sendall(b"PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n" + settings)
    data, end = read_all(s)
    line, f = fields(data)
    out.append(f"{line} {f.get('connection')} responses={data.count(b'HTTP/1.1 ')} {end}")
elif mode == "poll":
    s = raw()
    s.sendall(b"GET /poll HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    head = b""
    while b"\\r\\n\\r\\n" not in head:
        head += s.recv(4096)
    time.sleep(1.0)  # paused: the server checks its socket meanwhile
    out.append(head.split(b"\\r\\n")[0].decode())
elif mode == "idle-after-flush":
    s = raw()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    s.sendall(b"GET /big HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    data = b""; start = time.time(); want = None
    while want is None or len(data) < want:
        c = s.recv(65536)
        if not c:
            break
        data += c
        if want is None and b"\\r\\n\\r\\n" in data:
            head, _ = data.split(b"\\r\\n\\r\\n", 1)
            n = int([l for l in head.split(b"\\r\\n") if l.lower().startswith(b"content-length:")][0].split(b":")[1])
            want = len(head) + 4 + n
        # 2.4 s for the 32 MiB, far past the 1 s idle timeout; the server's
        # last write comes about 0.3 s before the end (what its send buffer
        # holds, up to 4 MiB)
        lag = len(data) / (32 << 20) * 2.4 - (time.time() - start)
        if lag > 0:
            time.sleep(lag)
    time.sleep(0.2)
    try:
        s.sendall(b"GET /n HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
        r = s.recv(4096)
        out.append(r.split(b"\\r\\n")[0].decode() if r else "closed")
    except OSError:
        out.append("closed")
print("|".join(out), flush=True)
"""


def _run(
    mode: StaticString, config: ServerConfig = ServerConfig(), probe: Bool = False
) raises -> String:
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
    var keepalive = String("none paused")
    var t = Instant.now()
    while String(proc.poll()) == "None":
        s.step(Duration.from_millis(5))
        if probe:
            for i in range(len(s._conns)):
                if s._conns[i] and s._conns[i].value().paused:
                    keepalive = String("keepalive=", s._conns[i].value().stream.socket().keepalive())
        if t.elapsed() > Duration.from_secs(60):
            _ = proc.kill()
            raise Error(String("client ", mode, " timed out"))
    var out = String(String(py=proc.communicate()[0]).strip())
    if probe:
        out += String(" ", keepalive)
    return out^


def test_a_paused_stream_probes_for_a_dead_peer() raises:
    assert_equal(_run("poll", probe=True), "HTTP/1.1 200 OK keepalive=True")


def test_requests_are_numbered_per_connection() raises:
    assert_equal(_run("numbers"), "1|2|3|1")


def test_unix_time_is_the_second_of_the_date() raises:
    assert_equal(_run("time"), "same=True near=True")
    assert_equal(Request(SocketAddr.parse("127.0.0.1:1")).unix_time, 0)


def test_the_servers_own_errors_carry_its_name() raises:
    assert_equal(
        _run("errors", ServerConfig(server_name="sr2", header_timeout=Duration.from_millis(300))),
        "400 sr2|505 sr2|408 sr2",
    )


def test_an_http2_preface_gets_one_505() raises:
    assert_equal(_run("h2"), "HTTP/1.1 505 HTTP Version Not Supported close responses=1 eof")


def test_the_idle_timer_starts_when_the_response_is_out() raises:
    assert_equal(
        _run(
            "idle-after-flush",
            ServerConfig(idle_timeout=Duration.from_secs(1), write_timeout=Duration.from_secs(5), min_rate=0),
        ),
        "HTTP/1.1 200 OK",
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
