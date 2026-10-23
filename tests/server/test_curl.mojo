"""Interop with curl (skipped without it): a `Router` with `StaticFiles`,
an echo and a streamed route, driven by `step()` while curl talks to it.
Keep-alive across URLs, POST, chunked uploads, `Expect: 100-continue`
(curl sends it for large bodies), HEAD, ranges, a chunked streamed
response, HTTP/1.0, 405 and 404."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_true

from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import Handler, Params, Request, Response, Router, Server, ServerConfig, StaticFiles

comptime _SETUP = """
import os, sys
root = sys.argv[1]
os.makedirs(os.path.join(root, "pub"), exist_ok=True)
with open(os.path.join(root, "pub", "data.bin"), "wb") as f:
    f.write(bytes((i * 13) % 256 for i in range(300000)))
with open(os.path.join(root, "upload.bin"), "wb") as f:
    f.write(bytes((i * 7) % 256 for i in range(2 * 1024 * 1024)))
"""

comptime _CURL = """
import hashlib, shutil, subprocess, sys
port, root = sys.argv[1], sys.argv[2]
base = f"http://127.0.0.1:{port}"
out = []
def curl(*args):
    r = subprocess.run([shutil.which("curl"), "-s", "-S", "--max-time", "20", *args], capture_output=True)
    return r.stdout, r.returncode
data = open(f"{root}/pub/data.bin", "rb").read()
up = open(f"{root}/upload.bin", "rb").read()
b, rc = curl("-w", "%{num_connects}", "-o", "/dev/null", f"{base}/hello", "-o", "/dev/null", f"{base}/hello", "-o", "/dev/null", f"{base}/files/data.bin")
out.append(f"keepalive connects={b.decode()} rc={rc}")  # per URL: 1, then 0 and 0
b, rc = curl("-d", "posted text", f"{base}/echo")
out.append(f"post {b.decode()}")
b, rc = curl("-H", "Transfer-Encoding: chunked", "--data-binary", f"@{root}/upload.bin", f"{base}/echo")
out.append(f"chunked {hashlib.sha256(b).hexdigest() == hashlib.sha256(up).hexdigest()}")
b, rc = curl("-v", "--data-binary", f"@{root}/upload.bin", "-o", "/dev/null", f"{base}/echo")
r = subprocess.run([shutil.which("curl"), "-s", "-v", "--max-time", "20", "-H", "Expect: 100-continue", "--data-binary", f"@{root}/upload.bin", "-o", "/dev/null", f"{base}/echo"], capture_output=True)
out.append(f"expect {b'100 Continue' in r.stderr} rc={r.returncode}")
b, rc = curl("-I", f"{base}/files/data.bin")
out.append(f"head {b.split(b'\\r\\n')[0].decode()} {b'Content-Length: 300000' in b}")
b, rc = curl("-r", "1000-1999", f"{base}/files/data.bin")
out.append(f"range {b == data[1000:2000]}")
b, rc = curl(f"{base}/files/data.bin")
out.append(f"file {b == data}")
b, rc = curl("--raw", f"{base}/count")
out.append(f"stream raw-chunked={b.startswith(b'2\\r\\n0\\n')}")
b, rc = curl(f"{base}/count")
out.append(f"stream {b.decode().split()[-1]}")
b, rc = curl("-0", "-i", f"{base}/hello")
out.append(f"http1.0 {b.split(b'\\r\\n')[0].decode()} close={b'Connection: close' in b or b'connection: close' in b.lower()}")
b, rc = curl("-i", "-X", "DELETE", f"{base}/hello")
out.append(f"{b.split(b'\\r\\n')[0].decode()} {[l.decode() for l in b.split(b'\\r\\n') if l.lower().startswith(b'allow:')]}")
b, rc = curl("-i", f"{base}/nowhere")
out.append(b.split(b"\\r\\n")[0].decode())
print("|".join(out), flush=True)
"""


struct App(Handler):
    var files: StaticFiles
    var counts: List[UInt64]
    """Connections whose /count stream is under way."""
    var at: List[Int]

    def __init__(out self, var files: StaticFiles):
        self.files = files^
        self.counts = List[UInt64]()
        self.at = List[Int]()

    def handle(mut self, req: Request, mut res: Response) raises:
        res.text(404, "not found\n")

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        if self.files.owns(req):
            return self.files.produce(req, out)
        for i in range(len(self.counts)):
            if self.counts[i] == req.id:
                out.extend(String(self.at[i], "\n").as_bytes())
                self.at[i] += 1
                return self.at[i] <= 1000
        return False

    def stream_ended(mut self, req: Request, finished: Bool):
        self.files.stream_ended(req)
        for i in range(len(self.counts)):
            if self.counts[i] == req.id:
                _ = self.counts.pop(i)
                _ = self.at.pop(i)
                return


def hello(mut app: App, req: Request, params: Params, mut res: Response) raises:
    res.text(200, "hello\n")


def echo(mut app: App, req: Request, params: Params, mut res: Response) raises:
    res.bytes(200, Span(req.body), "application/octet-stream")


def count(mut app: App, req: Request, params: Params, mut res: Response) raises:
    app.counts.append(req.id)
    app.at.append(0)
    res.stream()


def file(mut app: App, req: Request, params: Params, mut res: Response) raises:
    app.files.serve(req, params["path"], res)


def test_curl_against_the_server() raises:
    var shutil = Python.import_module("shutil")
    if String(shutil.which("curl")) == "None":
        print("    (skipped: test_curl_against_the_server: no curl)")
        return
    var os = Python.import_module("os")
    var tempfile = Python.import_module("tempfile")
    var root = String(py=tempfile.mkdtemp(prefix=String("mojo_net_curl_", Int(py=os.getpid()), "_")))
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    _ = subprocess.run(Python.list(pysys.executable, "-c", _SETUP, root), check=True)
    var router = Router(App(StaticFiles.open(String(root, "/pub"))))
    router.get("/hello", hello)
    router.post("/echo", echo)
    router.get("/count", count)
    router.get("/files/*path", file)
    var config = ServerConfig(max_body=8 * 1024 * 1024)
    var s = Server(router^, config)
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var proc = subprocess.Popen(
        Python.list(pysys.executable, "-c", _CURL, String(s.local_addr().port()), root),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    var t = Instant.now()
    while String(proc.poll()) == "None":
        s.step(Duration.from_millis(5))
        if t.elapsed() > Duration.from_secs(120):
            _ = proc.kill()
            _ = shutil.rmtree(root, ignore_errors=True)
            raise Error("curl timed out")
    var drain = Instant.now()
    while s.connections() > 0 and drain.elapsed() < Duration.from_secs(3):
        s.step(Duration.from_millis(5))
    var out = String(String(py=proc.communicate()[0]).strip())
    _ = shutil.rmtree(root)
    assert_equal(
        out,
        "keepalive connects=100 rc=0|post posted text|chunked True|expect True rc=0"
        + "|head HTTP/1.1 200 OK True|range True|file True|stream raw-chunked=True|stream 1000"
        + "|http1.0 HTTP/1.1 200 OK close=True"
        + "|HTTP/1.1 405 Method Not Allowed ['Allow: GET, HEAD, OPTIONS']|HTTP/1.1 404 Not Found",
    )
    assert_equal(s.connections(), 0)
    assert_equal(len(s.handler.app.counts), 0)  # every stream ended


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
