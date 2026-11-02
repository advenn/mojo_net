"""Regression test for the 2026-11 analysis of the stack, for HTTPS in
`server` (finding https-unmeasured-datapath):

- A response went into TLS whole: the loop copied the codec's output into
  a buffer of its own (`tls_plain`), and OpenSSL encrypted up to 256 KB of
  it at once into its write buffer (a memory BIO, which never shrinks, so
  a connection that once sent a large response kept ~340 KB for as long
  as it lived), all of which then moved into the connection's output
  buffer. Now the codec's output goes into TLS a record at a time, from
  the codec's own buffer, while less than 64 KB of ciphertext waits.

Seen through the connection's output buffer, which takes whatever OpenSSL
holds each time: its capacity, sampled at every turn while a client reads
a 4 MiB response slowly, stays under 160 KB (it reached 256 KB and more
before)."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_true

from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig
from tls import ServerConfig as TlsConfig

comptime _CLIENT = """
import socket, ssl, sys, time
pki, port = sys.argv[1], int(sys.argv[2])
c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
c.load_verify_locations(pki + "/root.pem")
raw = socket.create_connection(("127.0.0.1", port), timeout=30)
raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
s = c.wrap_socket(raw, server_hostname="localhost")
s.sendall(b"GET /big HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n")
got = 0
while got < (4 << 20):
    d = s.recv(65536)
    if not d:
        break
    got += len(d)
    time.sleep(0.002)  # (slow: the server's output waits)
print("done", got >= (4 << 20), flush=True)
"""


struct App(Handler):
    var big: List[UInt8]

    def __init__(out self):
        self.big = List[UInt8](length=4 << 20, fill=0x61)

    def handle(mut self, req: Request, mut res: Response) raises:
        res.bytes(200, Span(self.big), "application/octet-stream")


def _pki() raises -> String:
    var os = Python.import_module("os")
    var tempfile = Python.import_module("tempfile")
    var d = String(py=os.path.join(tempfile.gettempdir(), String("mojo_net_server_tls_ar_", Int(py=os.getpid()))))
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    var r = subprocess.run(
        Python.list(pysys.executable, "tests/tls/tls_pki.py", d, "--owner", String(Int(py=os.getpid()))), capture_output=True, text=True
    )
    if Int(py=r.returncode) != 0:
        raise Error(String("tls_pki.py failed: ", String(py=r.stderr)))
    return d


def test_a_large_response_goes_into_tls_a_record_at_a_time() raises:
    var d = _pki()
    var s = Server(App(), ServerConfig(log_errors=False))
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    s.serve_tls(TlsConfig(certificate=d + "/good.chain.pem", key=d + "/good.key", names=["localhost"]))
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    var proc = subprocess.Popen(
        Python.list(pysys.executable, "-c", _CLIENT, d, String(s.local_addr().port())), stdout=subprocess.PIPE, text=True
    )
    var most = 0
    var t = Instant.now()
    while String(proc.poll()) == "None":
        s.step(Duration.from_millis(2))
        for i in range(len(s._conns)):
            if s._conns[i]:
                most = max(most, s._conns[i].value().out.capacity())
        assert_true(t.elapsed() < Duration.from_secs(120), "the client never finished")
    var said = String(String(py=proc.communicate()[0]).strip())
    assert_true(said == "done True", said)
    print("  note: the output buffer peaked at", most // 1024, "KB")
    assert_true(most < 160 * 1024, String("the output buffer reached ", most // 1024, " KB"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
