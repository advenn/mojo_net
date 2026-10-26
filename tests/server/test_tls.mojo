"""`server.Server` over TLS (S7; rules TS6-TS12 of
docs/research/tls_with_openssl.md), against clients in Python's `ssl`,
which shares no code with the server: requests, close_notify on a
graceful end, ALPN, SNI and the 421 for another host, the handshake
deadline and the ClientHello bound, admission (handshakes at once and per
second), reloading the certificate while connections live, and a
graceful shutdown, with idle connections and with a handshake under way. The PKI is tests/tls/tls_pki.py's."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig
from tls import ServerConfig as TlsConfig

comptime _CLIENT = """
import socket, ssl, sys, time
pki, port, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
out = []
def ctx(alpn=None, verify=True):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.load_verify_locations(pki + "/root.pem")
    if not verify:
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
    if alpn:
        c.set_alpn_protocols(alpn)
    return c
def tls(name="localhost", alpn=None, verify=True):
    raw = socket.create_connection(("127.0.0.1", port), timeout=20)
    return ctx(alpn, verify).wrap_socket(raw, server_hostname=name, suppress_ragged_eofs=False)
def request(s, path="/hello", host="localhost", close=False, body=b""):
    head = f"{'POST' if body else 'GET'} {path} HTTP/1.1\\r\\nHost: {host}\\r\\n"
    if body:
        head += f"Content-Length: {len(body)}\\r\\n"
    if close:
        head += "Connection: close\\r\\n"
    s.sendall(head.encode() + b"\\r\\n" + body)
def response(s):
    data = b""
    while b"\\r\\n\\r\\n" not in data:
        d = s.recv(65536)
        if not d:
            return "EOF", data
        data += d
    head, rest = data.split(b"\\r\\n\\r\\n", 1)
    n = 0
    for line in head.split(b"\\r\\n")[1:]:
        k, v = line.split(b":", 1)
        if k.strip().lower() == b"content-length":
            n = int(v)
    while len(rest) < n:
        rest += s.recv(65536)
    return head.split(b"\\r\\n")[0].decode(), rest[:n]
def to_end(s):
    try:
        while s.recv(65536):
            pass
        return "close_notify"
    except ssl.SSLEOFError:
        return "cut"
    except (ConnectionResetError, OSError) as e:
        return type(e).__name__
def error_of(f):
    try:
        f()
        return "none"
    except ssl.SSLError as e:
        return e.reason or type(e).__name__
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        return type(e).__name__
def peer_serial(s):
    return format(int.from_bytes(__import__("hashlib").sha256(s.getpeercert(True)).digest()[:4], "big"), "x")
if mode == "requests":
    s = tls(alpn=["h2", "http/1.1"])
    out.append(f"{s.version()} {s.selected_alpn_protocol()}")
    for i in range(3):
        request(s)
        out.append(" ".join(map(str, response(s))))
    request(s, "/echo", body=b"x" * 100000)
    st, b = response(s)
    out.append(f"{st} {len(b)}")
    request(s, close=True)
    out.append(response(s)[0])
    out.append(to_end(s))
elif mode == "alpn":
    out.append(error_of(lambda: tls(alpn=["h2"])))
elif mode == "sni":
    s = tls(name="other.test", verify=False)
    try:
        request(s)
        out.append(response(s)[0])
    except (ssl.SSLError, OSError) as e:
        out.append(type(e).__name__)
elif mode == "host":
    s = tls()
    for host in ["localhost:8443", "LOCALHOST.", "localhost"]:
        request(s, host=host)
        out.append(response(s)[0])
    request(s, host="other.example")
    out.append(response(s)[0])
    out.append(to_end(s))
elif mode == "slow":
    # A ClientHello, a byte at a time, slower than the deadline allows.
    b_in, b_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx().wrap_bio(b_in, b_out, server_hostname="localhost")
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = b_out.read()
    raw = socket.create_connection(("127.0.0.1", port), timeout=20)
    t = time.time()
    try:
        for i in range(len(hello)):
            raw.sendall(hello[i:i + 1])
            time.sleep(0.05)
        raw.settimeout(10)
        got = raw.recv(1)
        out.append(f"answered:{len(got)}")
    except (ConnectionResetError, BrokenPipeError):
        out.append("reset")
    out.append(f"after={round(time.time() - t)}")
elif mode == "junk":
    raw = socket.create_connection(("127.0.0.1", port), timeout=20)
    body = bytes([1, 0x02, 0, 0]) + bytes(100 * 1024)
    sent = 0
    try:
        for i in range(0, len(body), 16384):
            part = body[i:i + 16384]
            raw.sendall(bytes([22, 3, 1, len(part) >> 8, len(part) & 0xFF]) + part)
            sent += len(part) + 5
        raw.settimeout(5)
        out.append(f"read:{len(raw.recv(1))}")
    except (ConnectionResetError, BrokenPipeError):
        out.append("reset")
    out.append(f"sent<100k={sent < 100 * 1024}")
elif mode == "idle4":
    # Four connections that never say a word, held until told.
    socks = [socket.create_connection(("127.0.0.1", port), timeout=20) for _ in range(4)]
    print("OPEN", flush=True)
    sys.stdin.readline()
    out.append("held")
elif mode == "reload":
    s = tls()
    request(s)
    out.append(response(s)[0])
    first = peer_serial(s)
    print("SWAP", flush=True)
    sys.stdin.readline()  # (the test replaced the files and waited)
    t = tls()
    request(t)
    out.append(response(t)[0])
    out.append(f"new_cert={peer_serial(t) != first}")
    request(s)  # the first connection lives on, with the old certificate
    out.append(response(s)[0])
    print("BREAK", flush=True)
    sys.stdin.readline()  # (the test broke the files and waited)
    u = tls()
    request(u)
    out.append(response(u)[0])
    out.append(f"kept={peer_serial(u) == peer_serial(t)}")
elif mode == "mid":
    # Stop between the server's flight and our Finished, then send the
    # Finished and a request together.
    b_in, b_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx().wrap_bio(b_in, b_out, server_hostname="localhost")
    raw = socket.create_connection(("127.0.0.1", port), timeout=20)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    raw.sendall(b_out.read())
    while True:
        b_in.write(raw.recv(65536))
        try:
            obj.do_handshake()
            break
        except ssl.SSLWantReadError:
            pass
    print("MID", flush=True)
    sys.stdin.readline()  # (the test began a shutdown)
    obj.write(b"GET /hello HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n")
    raw.sendall(b_out.read())
    got = b""
    done = False
    while not done:
        data = raw.recv(65536)
        if not data:
            break
        b_in.write(data)
        while True:
            try:
                chunk = obj.read(65536)
            except ssl.SSLWantReadError:
                break
            except ssl.SSLZeroReturnError:
                chunk = b""
            if not chunk:  # (close_notify: read() returns b"" from then on)
                done = True
                break
            got += chunk
    head = got.split(b"\\r\\n\\r\\n")[0].decode()
    out.append(head.split("\\r\\n")[0])
    out.append(f"close={'Connection: close' in head}")
elif mode == "shutdown":
    s = tls()
    request(s)
    out.append(response(s)[0])
    print("IDLE", flush=True)
    out.append(to_end(s))
print("|".join(map(str, out)), flush=True)
"""


struct App(Handler):
    def __init__(out self):
        pass

    def handle(mut self, req: Request, mut res: Response) raises:
        if req.path() == "/echo":
            res.bytes(200, Span(req.body), "application/octet-stream")
        else:
            res.text(200, "hello")


def _pki() raises -> String:
    """The test PKI (tests/tls/tls_pki.py), once per process."""
    var os = Python.import_module("os")
    var tempfile = Python.import_module("tempfile")
    var d = String(py=os.path.join(tempfile.gettempdir(), String("mojo_net_server_tls_", Int(py=os.getpid()))))
    if Bool(py=os.path.exists(d + "/root.crl.pem")):
        return d
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    var r = subprocess.run(
        Python.list(pysys.executable, "tests/tls/tls_pki.py", d, "--owner", String(Int(py=os.getpid()))), capture_output=True, text=True
    )
    if Int(py=r.returncode) != 0:
        raise Error(String("tls_pki.py failed: ", String(py=r.stderr)))
    return d


def _tls_config(cert: StringSlice = "good", key: StringSlice = "") raises -> TlsConfig:
    var d = _pki()
    var k = String(key) if key.byte_length() > 0 else String(cert)
    return TlsConfig(certificate=d + "/" + cert + ".chain.pem", key=d + "/" + k + ".key", names=["localhost", "127.0.0.1"])


def _server(config: ServerConfig = ServerConfig(), tls: Optional[TlsConfig] = None) raises -> Server[App]:
    var s = Server(App(), config.copy())
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    s.serve_tls(tls.value().copy() if tls else _tls_config())
    return s^


def _client(mut s: Server[App], mode: StaticString) raises -> PythonObject:
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    return subprocess.Popen(
        Python.list(pysys.executable, "-c", _CLIENT, _pki(), String(s.local_addr().port()), mode),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def _finish(mut s: Server[App], proc: PythonObject, what: StaticString) raises -> String:
    """Serve until the client exits; what it printed last."""
    var t = Instant.now()
    while String(proc.poll()) == "None":
        s.step(Duration.from_millis(5))
        if t.elapsed() > Duration.from_secs(60):
            _ = proc.kill()
            raise Error(String("client ", what, " timed out"))
    var out = String(String(py=proc.communicate()[0]).strip())
    var lines = out.split("\n")
    return String(lines[len(lines) - 1])


def _until_line(mut s: Server[App], proc: PythonObject, want: StringSlice) raises:
    """Serve until the client prints `want` (a line of its own)."""
    var select = Python.import_module("select")
    var t = Instant.now()
    var seen = String()
    while True:
        s.step(Duration.from_millis(5))
        var ready = select.select(Python.list(proc.stdout), Python.list(), Python.list(), 0)[0]
        if Bool(py=ready):
            var line = String(String(py=proc.stdout.readline()).strip())
            if line == want:
                return
            seen += line + "\n"
            if line.byte_length() == 0 and String(proc.poll()) != "None":
                raise Error(String("the client ended before ", want, ": ", seen))
        if t.elapsed() > Duration.from_secs(60):
            _ = proc.kill()
            raise Error(String("no ", want, " from the client"))


def _steps(mut s: Server[App], d: Duration) raises:
    var t = Instant.now()
    while t.elapsed() < d:
        s.step(Duration.from_millis(5))


def _say(proc: PythonObject) raises:
    _ = proc.stdin.write("go\n")
    _ = proc.stdin.flush()


# ---- serving ----------------------------------------------------------------------


def test_requests_over_tls_and_close_notify_at_the_end() raises:
    var s = _server()
    var c = _client(s, "requests")
    var got = _finish(s, c, "requests").split("|")
    assert_equal(String(got[0]), "TLSv1.3 http/1.1")
    for i in range(1, 4):
        assert_equal(String(got[i]), "HTTP/1.1 200 OK b'hello'")
    assert_equal(String(got[4]), "HTTP/1.1 200 OK 100000")
    assert_equal(String(got[5]), "HTTP/1.1 200 OK")
    assert_equal(String(got[6]), "close_notify")  # (TS10: a graceful end)
    _steps(s, Duration.from_millis(100))
    assert_equal(s.connections(), 0)
    assert_equal(s.handshakes(), 0)


def test_an_alpn_offer_of_h2_alone_is_refused() raises:
    var s = _server()
    var c = _client(s, "alpn")
    assert_equal(_finish(s, c, "alpn"), "TLSV1_ALERT_NO_APPLICATION_PROTOCOL")


def test_an_unknown_sni_gets_no_answer() raises:
    var s = _server()
    var c = _client(s, "sni")
    var got = _finish(s, c, "sni")
    assert_false(got.startswith("HTTP/"), got)


def test_a_host_other_than_the_sni_gets_421() raises:
    """TS6: Host may carry a port, a trailing dot and any case; another
    name is misdirected, and the connection then closes."""
    var s = _server()
    var c = _client(s, "host")
    var got = _finish(s, c, "host").split("|")
    assert_equal(String(got[0]), "HTTP/1.1 200 OK")
    assert_equal(String(got[1]), "HTTP/1.1 200 OK")
    assert_equal(String(got[2]), "HTTP/1.1 200 OK")
    assert_equal(String(got[3]), "HTTP/1.1 421 Misdirected Request")
    assert_equal(String(got[4]), "close_notify")


# ---- bounds -------------------------------------------------------------------------


def test_a_slow_handshake_is_cut_at_its_deadline() raises:
    """TS8: a ClientHello dribbled a byte every 50 ms makes progress all
    along, and is still cut at the deadline (1 s here)."""
    var s = _server(ServerConfig(tls_handshake_timeout=Duration.from_secs(1)))
    var c = _client(s, "slow")
    var got = _finish(s, c, "slow").split("|")
    assert_true(String(got[0]) == "answered:0" or String(got[0]) == "reset", String(got[0]))
    var after = atol(String(got[1])[byte=6:])
    assert_true(after >= 1 and after <= 3, String(got[1]))
    assert_equal(s.connections(), 0)


def test_a_client_hello_that_never_ends_is_closed() raises:
    var s = _server()
    var c = _client(s, "junk")
    var got = _finish(s, c, "junk")
    assert_true("read:0" in got or "reset" in got, got)
    _steps(s, Duration.from_millis(50))
    assert_equal(s.connections(), 0)


def test_handshakes_at_once_are_capped() raises:
    """TS7: with room for two handshakes, four silent connections get two
    accepted; the others wait in the kernel's queue, and are taken when
    the first two end."""
    var s = _server(ServerConfig(tls_max_handshakes=2, tls_handshake_timeout=Duration.from_millis(600)))
    var c = _client(s, "idle4")
    _until_line(s, c, "OPEN")
    _steps(s, Duration.from_millis(200))
    assert_equal(s.connections(), 2)
    assert_equal(s.handshakes(), 2)
    _steps(s, Duration.from_millis(700))  # (their deadline: the next two come in)
    assert_equal(s.connections(), 2)
    _say(c)
    _ = _finish(s, c, "idle4")


def test_handshakes_begun_per_second_are_capped() raises:
    var s = _server(ServerConfig(tls_handshake_rate=3, tls_handshake_timeout=Duration.from_secs(5)))
    var c = _client(s, "idle4")
    _until_line(s, c, "OPEN")
    _steps(s, Duration.from_millis(300))
    assert_equal(s.connections(), 3)
    _steps(s, Duration.from_millis(1000))  # (the next second)
    assert_equal(s.connections(), 4)
    _say(c)
    _ = _finish(s, c, "idle4")


# ---- reloading, shutdown ---------------------------------------------------------------


def test_a_changed_certificate_serves_new_connections() raises:
    """TS12: the files replaced (another chain and key) reach the next
    connection within `tls_reload_check`, while a live one keeps its
    certificate; broken files then leave the last good one serving."""
    var os = Python.import_module("os")
    var shutil = Python.import_module("shutil")
    var tempfile = Python.import_module("tempfile")
    var d = _pki()
    var dir = String(py=tempfile.mkdtemp(prefix="mojo_net_reload_"))
    _ = shutil.copyfile(d + "/good.chain.pem", dir + "/cert.pem")
    _ = shutil.copyfile(d + "/good.key", dir + "/key.pem")
    _ = os.chmod(dir + "/key.pem", 0o600)
    var config = TlsConfig(certificate=dir + "/cert.pem", key=dir + "/key.pem", names=["localhost"])
    var s = _server(ServerConfig(tls_reload_check=Duration.from_millis(100)), config^)
    var c = _client(s, "reload")
    _until_line(s, c, "SWAP")
    # Replaced as certbot does: new files, renamed over the old.
    _ = shutil.copyfile(d + "/chained.chain.pem", dir + "/cert.new")
    _ = shutil.copyfile(d + "/chained.key", dir + "/key.new")
    _ = os.chmod(dir + "/key.new", 0o600)
    _ = os.replace(dir + "/key.new", dir + "/key.pem")
    _ = os.replace(dir + "/cert.new", dir + "/cert.pem")
    _steps(s, Duration.from_millis(400))
    _say(c)
    _until_line(s, c, "BREAK")
    var f = Python.import_module("builtins").open(dir + "/cert.pem", "w")
    _ = f.write("not a certificate\n")
    _ = f.close()
    _steps(s, Duration.from_millis(400))
    _say(c)
    var got = _finish(s, c, "reload").split("|")
    assert_equal(String(got[0]), "HTTP/1.1 200 OK")
    assert_equal(String(got[1]), "HTTP/1.1 200 OK")
    assert_equal(String(got[2]), "new_cert=True")
    assert_equal(String(got[3]), "HTTP/1.1 200 OK")
    assert_equal(String(got[4]), "HTTP/1.1 200 OK")
    assert_equal(String(got[5]), "kept=True")
    _ = shutil.rmtree(dir)


def test_a_graceful_shutdown_sends_close_notify_to_idle_connections() raises:
    var s = _server()
    var c = _client(s, "shutdown")
    _until_line(s, c, "IDLE")
    _steps(s, Duration.from_millis(100))
    s.shutdown()
    var got = _finish(s, c, "shutdown").split("|")
    assert_equal(String(got[0]), "HTTP/1.1 200 OK")
    assert_equal(String(got[1]), "close_notify")
    _steps(s, Duration.from_millis(100))
    assert_true(s.stopped())


def test_a_shutdown_lets_a_handshake_under_way_finish() raises:
    """TS10: the handshake ends after the shutdown began, and the request
    that came with its end is answered, as the connection's last."""
    var s = _server()
    var c = _client(s, "mid")
    _until_line(s, c, "MID")
    s.shutdown()
    _steps(s, Duration.from_millis(50))
    assert_equal(s.connections(), 1)
    _say(c)
    var got = _finish(s, c, "mid").split("|")
    assert_equal(String(got[0]), "HTTP/1.1 200 OK")
    assert_equal(String(got[1]), "close=True")
    _steps(s, Duration.from_millis(100))
    assert_true(s.stopped())


def test_the_alpn_list_is_http11_whatever_was_asked() raises:
    var asked = _tls_config()
    asked.alpn = ["h2"]
    var s = _server(tls=asked^)
    var ctx = s.tls_context()
    assert_true(Bool(ctx))
    assert_equal(ctx.value().alpn(), ["http/1.1"])


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
