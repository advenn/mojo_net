"""Regression tests for the third TLS review's findings in `server`.

TR3, 2026-10-27 (docs/tls.md, "Review"), against clients in Python's `ssl`.
INT-1. A handshake held its place among `tls_max_handshakes` from its
admission to its end or its deadline (10 s), though the server's work is
done once its flight is out: clients that sent a ClientHello and went
quiet kept every place, so the server began about 1,024 handshakes per
10 s however many it could do. Now, while ClientHellos wait, one that has
waited `tls_client_wait` (1 s) for its client gives its place up."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_true

from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig
from tls import ServerConfig as TlsConfig

comptime _CLIENT = """
import socket, ssl, sys, time
pki, port, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def ctx():
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.load_verify_locations(pki + "/root.pem")
    return c
def hello_conn():
    # A ClientHello, then silence: the server's flight is never answered.
    b_in, b_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx().wrap_bio(b_in, b_out, server_hostname="localhost")
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    raw = socket.create_connection(("127.0.0.1", port), timeout=20)
    raw.sendall(b_out.read())
    return raw
socks = [hello_conn() for _ in range(2)]
print("STALLED", flush=True)
sys.stdin.readline()
t = time.time()
raw = socket.create_connection(("127.0.0.1", port), timeout=20)
s = ctx().wrap_socket(raw, server_hostname="localhost")
s.sendall(b"GET / HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n")
data = b""
while True:
    d = s.recv(65536)
    if not d:
        break
    data += d
print(f"{data.split(b'\\r\\n')[0].decode()}|after={time.time() - t:.1f}", flush=True)
"""


struct App(Handler):
    def __init__(out self):
        pass

    def handle(mut self, req: Request, mut res: Response) raises:
        res.text(200, "hello")


def _pki() raises -> String:
    var os = Python.import_module("os")
    var tempfile = Python.import_module("tempfile")
    var d = String(py=os.path.join(tempfile.gettempdir(), String("mojo_net_server_tls_r3_", Int(py=os.getpid()))))
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


def _server(config: ServerConfig) raises -> Server[App]:
    var s = Server(App(), config.copy())
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var d = _pki()
    s.serve_tls(TlsConfig(certificate=d + "/good.chain.pem", key=d + "/good.key", names=["localhost", "127.0.0.1"]))
    return s^


def _client(mut s: Server[App]) raises -> PythonObject:
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    return subprocess.Popen(
        Python.list(pysys.executable, "-c", _CLIENT, _pki(), String(s.local_addr().port()), "stall"),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def _until_line(mut s: Server[App], proc: PythonObject, want: StringSlice) raises:
    var select = Python.import_module("select")
    var t = Instant.now()
    while True:
        s.step(Duration.from_millis(5))
        var ready = select.select(Python.list(proc.stdout), Python.list(), Python.list(), 0)[0]
        if Bool(py=ready):
            var line = String(String(py=proc.stdout.readline()).strip())
            if line == want:
                return
            if line.byte_length() == 0 and String(proc.poll()) != "None":
                raise Error(String("the client ended before ", want))
        if t.elapsed() > Duration.from_secs(60):
            _ = proc.kill()
            raise Error(String("no ", want, " from the client"))


def _finish(mut s: Server[App], proc: PythonObject) raises -> String:
    var t = Instant.now()
    while String(proc.poll()) == "None":
        s.step(Duration.from_millis(5))
        if t.elapsed() > Duration.from_secs(60):
            _ = proc.kill()
            raise Error("the client timed out")
    var out = String(String(py=proc.communicate()[0]).strip())
    var lines = out.split("\n")
    return String(lines[len(lines) - 1])


def _steps(mut s: Server[App], d: Duration) raises:
    var t = Instant.now()
    while t.elapsed() < d:
        s.step(Duration.from_millis(5))


def test_int1_a_stalled_handshake_gives_its_place_up() raises:
    """Two places, both taken by ClientHellos that are never answered; a
    real client comes after. It waited until a stalled one reached its
    deadline (8 s here); now it is served about `tls_client_wait` after
    the stalled ones were admitted."""
    var s = _server(ServerConfig(tls_max_handshakes=2, tls_handshake_timeout=Duration.from_secs(8)))
    var c = _client(s)
    _until_line(s, c, "STALLED")
    _steps(s, Duration.from_millis(1500))  # (past tls_client_wait, but nobody waits: both kept)
    assert_equal(s.handshakes(), 2)
    assert_equal(s.connections(), 2)
    _ = c.stdin.write("go\n")
    _ = c.stdin.flush()
    var got = _finish(s, c).split("|")
    assert_equal(String(got[0]), "HTTP/1.1 200 OK")
    var after = atof(String(got[1])[byte=6:])
    assert_true(after < 4.0, String(got[1]))


def test_api1_a_reload_keeps_the_openssl_library_context() raises:
    """API-1: each reload built its context with an OpenSSL library context
    of its own, and a process can hold about 330 (3 thread-specific keys
    each): a server whose long-lived connections kept old contexts alive
    across reloads would have run out. A reload now shares the first
    context's."""
    var d = _pki()
    var s = _server(ServerConfig(tls_reload_check=Duration.from_millis(50)))
    var before = s._tls[0]._library()[].libctx
    var os = Python.import_module("os")
    var time = Python.import_module("time")
    for i in range(3):
        var stamp = Python.evaluate("lambda t, i: t + 10 * (i + 1)")(time.time(), i)
        _ = os.utime(d + "/good.chain.pem", Python.tuple(stamp, stamp))  # (a change the check sees)
        var held = s._tls[0].copy()  # (alive, so a new SSL_CTX cannot take its address)
        _steps(s, Duration.from_millis(300))
        assert_true(s._tls[0]._inner[].ctx != held._inner[].ctx, String("no reload ", i))
        assert_equal(s._tls[0]._library()[].libctx, before, String("reload ", i))
        _ = held^
    assert_true(not s._reload_failed)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
