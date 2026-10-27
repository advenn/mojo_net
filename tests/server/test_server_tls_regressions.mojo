"""Regression tests for the review of HTTPS in `server` (S7).

One per finding of TR2 (docs/tls.md, "Review"), against clients in Python's
`ssl`:

1. Sockets that sent nothing held every handshake's place and accepting
   paused, so a few thousand of them locked every client out. A
   connection now holds no TLS state, and is no handshake, until its first
   record has arrived whole (within `tls_hello_timeout`); accepting never
   waits for TLS, and a ClientHello waiting for admission waits under its
   handshake's deadline.
2. A POST sent right behind the client's Finished was refused as a
   handshake that was too large (the bound counted the data).
3. A reload that failed was tried again only when the file's inode, size
   or mtime changed: a key renamed in at 0644 and then chmodded to 0600
   never loaded.
4. An absolute-form target's authority passed the SNI check while the
   Host field, which a handler or a proxy reads, said another host: the
   field now holds the authority (RFC 9112 3.2.2).
And: what is not a TLS handshake record (plaintext HTTP, SSLv2's hello)
is closed at once, before any OpenSSL state exists."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig
from tls import ServerConfig as TlsConfig

comptime _CLIENT = """
import hashlib, socket, ssl, sys, time
pki, port, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
out = []
def ctx():
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.load_verify_locations(pki + "/root.pem")
    return c
def tls():
    raw = socket.create_connection(("127.0.0.1", port), timeout=20)
    return ctx().wrap_socket(raw, server_hostname="localhost")
def response(s):
    data = b""
    while b"\\r\\n\\r\\n" not in data:
        d = s.recv(65536)
        if not d:
            return "EOF", b""
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
def get(path="/hello", host="localhost"):
    s = tls()
    s.sendall(f"GET {path} HTTP/1.1\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n".encode())
    return response(s)
def serial(s):
    return hashlib.sha256(s.getpeercert(True)).hexdigest()[:8]
if mode == "silent":
    # Silent sockets, more than the handshakes allowed, then a real client.
    socks = [socket.create_connection(("127.0.0.1", port), timeout=20) for _ in range(40)]
    one = [socket.create_connection(("127.0.0.1", port), timeout=20) for _ in range(8)]
    for o in one:
        o.sendall(bytes([22]))  # (a byte of a record, then nothing)
    time.sleep(0.3)
    t = time.time()
    st, body = get()
    out.append(st)
    out.append(f"fast={time.time() - t < 2}")
    print("SERVED", flush=True)
    sys.stdin.readline()  # (the test waited past tls_hello_timeout)
    closed = 0
    for s in socks + one:
        s.settimeout(5)
        try:
            closed += s.recv(1) == b""
        except (ConnectionResetError, OSError):
            closed += 1
    out.append(f"closed={closed}")
elif mode == "hello2":
    # Two connections that send their ClientHello, then wait, held.
    socks = []
    for _ in range(2):
        b_in, b_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx().wrap_bio(b_in, b_out, server_hostname="localhost")
        try:
            obj.do_handshake()
        except ssl.SSLWantReadError:
            pass
        raw = socket.create_connection(("127.0.0.1", port), timeout=20)
        raw.sendall(b_out.read())
        socks.append(raw)
    print("OPEN", flush=True)
    sys.stdin.readline()
    out.append("held")
elif mode == "upload":
    # The Finished and a 100 KB POST in one write, as a TLS 1.3 client may.
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
    body = bytes(range(256)) * 400
    obj.write(f"POST /echo HTTP/1.1\\r\\nHost: localhost\\r\\nContent-Length: {len(body)}\\r\\nConnection: close\\r\\n\\r\\n".encode() + body)
    raw.sendall(b_out.read())
    got = b""
    while True:
        data = raw.recv(65536)
        if not data:
            break
        b_in.write(data)
        try:
            while True:
                chunk = obj.read(65536)
                if not chunk:
                    break
                got += chunk
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLZeroReturnError:
            break
    head, _, rest = got.partition(b"\\r\\n\\r\\n")
    out.append(head.split(b"\\r\\n")[0].decode())
    out.append(f"echoed={rest == body}")
elif mode == "serials":
    # One connection per line from the test: the certificate it got.
    for _ in range(3):
        sys.stdin.readline()
        s = tls()
        out.append(serial(s))
        s.close()
        print("SEEN", flush=True)
    sys.stdin.readline()  # (so that the result is not read with a SEEN)
elif mode == "absolute":
    s = tls()
    s.sendall(b"GET https://localhost/host HTTP/1.1\\r\\nHost: other.example\\r\\n\\r\\n")
    st, body = response(s)
    out.append(f"{st} {body.decode()}")
elif mode == "plain":
    for first in [b"GET / HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n", bytes([0x80, 0x2e, 1, 3, 1]) + bytes(48)]:
        raw = socket.create_connection(("127.0.0.1", port), timeout=20)
        raw.sendall(first)
        raw.settimeout(5)
        t = time.time()
        try:
            got = raw.recv(1)
            out.append(f"read={len(got)}")
        except (ConnectionResetError, OSError):
            out.append("reset")
        out.append(f"at_once={time.time() - t < 1}")
print("|".join(map(str, out)), flush=True)
"""


struct App(Handler):
    def __init__(out self):
        pass

    def handle(mut self, req: Request, mut res: Response) raises:
        if req.path() == "/echo":
            res.bytes(200, Span(req.body), "application/octet-stream")
        elif req.path() == "/host":
            var h = req.headers.get("host")
            var field = String(h.value()) if h else String()
            res.text(200, String("field=", field, " host()=", req.host()))
        else:
            res.text(200, "hello")


def _pki() raises -> String:
    """The test PKI (tests/tls/tls_pki.py), once per process."""
    var os = Python.import_module("os")
    var tempfile = Python.import_module("tempfile")
    var d = String(py=os.path.join(tempfile.gettempdir(), String("mojo_net_server_tlsreg_", Int(py=os.getpid()))))
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


def _server(config: ServerConfig = ServerConfig(), tls: Optional[TlsConfig] = None) raises -> Server[App]:
    var s = Server(App(), config.copy())
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var d = _pki()
    s.serve_tls(tls.value().copy() if tls else TlsConfig(certificate=d + "/good.chain.pem", key=d + "/good.key", names=["localhost"]))
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


def test_1_silent_sockets_take_no_handshake_place() raises:
    """40 silent sockets and 8 that sent one byte, against room for 4
    handshakes: a real client is served at once, none of them counts as a
    handshake, and all of them are closed at `tls_hello_timeout`."""
    var s = _server(ServerConfig(tls_max_handshakes=4, tls_hello_timeout=Duration.from_millis(1500)))
    var c = _client(s, "silent")
    _until_line(s, c, "SERVED")
    assert_equal(s.handshakes(), 0)
    assert_equal(s.tls_waiting(), 0)
    _steps(s, Duration.from_millis(1700))
    assert_equal(s.connections(), 0)
    _say(c)
    var got = _finish(s, c, "silent").split("|")
    assert_equal(String(got[0]), "HTTP/1.1 200 OK")
    assert_equal(String(got[1]), "fast=True")
    assert_equal(String(got[2]), "closed=48")


def test_1_a_waiting_handshake_is_cut_at_its_deadline() raises:
    """A ClientHello that waits for admission (one handshake a second,
    here) waits under the handshake's deadline from accept: it is closed
    at 0.5 s, not admitted when the next second comes."""
    var s = _server(ServerConfig(tls_handshake_rate=1, tls_handshake_timeout=Duration.from_millis(500)))
    var c = _client(s, "hello2")
    _until_line(s, c, "OPEN")
    _steps(s, Duration.from_millis(150))
    assert_equal(s.handshakes(), 1)
    assert_equal(s.tls_waiting(), 1)
    _steps(s, Duration.from_millis(650))  # (both past their deadline; the next second not yet)
    assert_equal(s.connections(), 0)
    assert_equal(s.tls_waiting(), 0)
    _say(c)
    _ = _finish(s, c, "hello2")


def test_2_an_upload_sent_with_the_finished_is_served() raises:
    var s = _server()
    var c = _client(s, "upload")
    var got = _finish(s, c, "upload").split("|")
    assert_equal(String(got[0]), "HTTP/1.1 200 OK")
    assert_equal(String(got[1]), "echoed=True")


def test_3_a_failed_reload_is_tried_again() raises:
    """A new key renamed in at 0644 is refused; once chmodded to 0600
    (which changes no inode, size or mtime) the next check loads it."""
    var os = Python.import_module("os")
    var shutil = Python.import_module("shutil")
    var tempfile = Python.import_module("tempfile")
    var d = _pki()
    var dir = String(py=tempfile.mkdtemp(prefix="mojo_net_reload2_"))
    _ = shutil.copyfile(d + "/good.chain.pem", dir + "/cert.pem")
    _ = shutil.copyfile(d + "/good.key", dir + "/key.pem")
    _ = os.chmod(dir + "/key.pem", 0o600)
    var config = TlsConfig(certificate=dir + "/cert.pem", key=dir + "/key.pem", names=["localhost"])
    var s = _server(ServerConfig(tls_reload_check=Duration.from_millis(100)), config^)
    var c = _client(s, "serials")
    _say(c)
    _until_line(s, c, "SEEN")
    _ = shutil.copyfile(d + "/chained.chain.pem", dir + "/cert.new")
    _ = shutil.copyfile(d + "/chained.key", dir + "/key.new")
    _ = os.chmod(dir + "/key.new", 0o644)
    _ = os.replace(dir + "/key.new", dir + "/key.pem")
    _ = os.replace(dir + "/cert.new", dir + "/cert.pem")
    _steps(s, Duration.from_millis(400))  # (refused: the key is readable by others)
    _say(c)
    _until_line(s, c, "SEEN")
    _ = os.chmod(dir + "/key.pem", 0o600)
    _steps(s, Duration.from_millis(400))
    _say(c)
    _until_line(s, c, "SEEN")
    _say(c)
    var line = _finish(s, c, "serials")
    var got = line.split("|")
    if len(got) != 3:
        raise Error(String("the client said: ", line))
    assert_equal(String(got[0]), String(got[1]))  # (the old one still served)
    assert_true(String(got[2]) != String(got[1]), String(got[2]))  # (then the new one)
    _ = shutil.rmtree(dir)


def test_4_the_host_field_holds_the_absolute_forms_authority() raises:
    var s = _server()
    var c = _client(s, "absolute")
    assert_equal(_finish(s, c, "absolute"), "HTTP/1.1 200 OK field=localhost host()=localhost")


def test_what_is_not_a_tls_record_is_closed_at_once() raises:
    var s = _server()
    var c = _client(s, "plain")
    var got = _finish(s, c, "plain").split("|")
    assert_true(String(got[0]) == "read=0" or String(got[0]) == "reset", String(got[0]))
    assert_equal(String(got[1]), "at_once=True")
    assert_true(String(got[2]) == "read=0" or String(got[2]) == "reset", String(got[2]))
    assert_equal(String(got[3]), "at_once=True")
    _steps(s, Duration.from_millis(50))
    assert_equal(s.connections(), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
