"""Regression tests for the second review of `StaticFiles` (SR2,
2026-10-28), each checked to fail on the code before its fix:
- STA-1: a file rewritten in place while it streamed was sent whole, a
  mix of both versions under the first one's validators (now the
  connection ends short);
- STA-2: a same-size change that kept the modification time kept the
  ETag (stale 304s), and times before 1970 lost their seconds; a file
  changed within the last second or two now gets a weak ETag;
- STA-3: each slow download held 192 KiB of buffers, a third of it the
  64 KiB piece read from the file, zero-filled before each read (now
  16 KiB pieces, read into memory left as it was: 144 KiB);
- STA-4: a FIFO (or a device) was opened for reading before its type was
  known, which released a writer waiting on it;
- STA-5: a directory that can be searched but not listed (0711) answered
  403 instead of serving its index;
- STA-8: list fields in several lines were read from the first line, and
  a date in several lines was used;
- STA-11: Last-Modified could be a second past Date (now
  `Request.unix_time` is that second);
- `X-Content-Type-Options: nosniff`, and `cache_control`, on file
  answers."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_true

from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import Handler, Params, Request, Response, Router, Server, StaticFiles, http_date

comptime _SETUP = """
import os, sys
root = sys.argv[1]
pub = os.path.join(root, "pub")
os.makedirs(os.path.join(pub, "locked"), exist_ok=True)
def put(name, data):
    with open(os.path.join(pub, name), "wb") as f:
        f.write(data)
put("small.txt", b"hello\\n")
put("huge.bin", b"0123456789abcdef" * (2 * 1024 * 1024))  # 32 MiB
put("locked/index.html", b"<h1>locked</h1>")
os.chmod(os.path.join(pub, "locked"), 0o711)
put("neg_a.txt", b"before"); os.utime(os.path.join(pub, "neg_a.txt"), (-100, -100))
put("neg_b.txt", b"before"); os.utime(os.path.join(pub, "neg_b.txt"), (-200, -200))
os.mkfifo(os.path.join(pub, "fifo"))
"""

comptime _CLIENT = """
import http.client, os, socket, subprocess, sys, time
port = int(sys.argv[1]); mode = sys.argv[2]; root = sys.argv[3]
pub = os.path.join(root, "pub")
out = []
c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
def get(path, method="GET", **headers):
    c.request(method, path, headers=headers); r = c.getresponse(); body = r.read()
    return r, body
def raw(request):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(request)
    d = b""
    while True:
        x = s.recv(65536)
        if not x:
            break
        d += x
    return d
def status(data):
    return data.split(b"\\r\\n")[0].split(b" ")[1].decode()
if mode == "rewrite":
    p = os.path.join(pub, "huge.bin"); size = os.path.getsize(p)
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(b"GET /assets/huge.bin HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    d = b""
    while len(d) < 200000:  # (the server reads at most the socket buffers ahead: a few MiB)
        d += s.recv(16384)
    with open(p, "r+b") as f:  # rewritten in place, as cp does
        f.write(b"X" * size)
    while True:
        try:
            x = s.recv(1 << 20)
        except ConnectionResetError:
            break
        if not x:
            break
        d += x
    head, body = d.split(b"\\r\\n\\r\\n", 1)
    if len(body) < size:
        out.append("cut")
    else:
        out.append("mixed" if b"X" in body and b"0123" in body else "whole")
elif mode == "pinned-mtime":
    p = os.path.join(pub, "v.txt")
    with open(p, "wb") as f:
        f.write(b"1.2.3")
    os.utime(p, ns=(10**9, 10**9))
    r, b = get("/assets/v.txt"); etag = r.getheader("ETag")
    time.sleep(0.05)  # (past a clock tick: the change gets another ctime)
    with open(p, "wb") as f:
        f.write(b"1.2.4")
    os.utime(p, ns=(10**9, 10**9))
    r, b = get("/assets/v.txt", **{"If-None-Match": etag})
    out.append(f"{r.status} {b!r}")
elif mode == "negative":
    r, b = get("/plain/neg_a.txt"); a = r.getheader("ETag")
    r, b = get("/plain/neg_b.txt"); z = r.getheader("ETag")
    out.append(f"differ={a != z}")
elif mode == "fresh":
    with open(os.path.join(pub, "fresh.txt"), "wb") as f:
        f.write(b"just written")
    r, b = get("/assets/fresh.txt"); etag = r.getheader("ETag"); lm = r.getheader("Last-Modified")
    out.append(etag[:2])
    r, b = get("/assets/fresh.txt", **{"If-Match": etag}); out.append(str(r.status))
    r, b = get("/assets/fresh.txt", Range="bytes=0-0", **{"If-Range": etag}); out.append(str(r.status))
    r, b = get("/assets/fresh.txt", Range="bytes=0-0", **{"If-Range": lm}); out.append(str(r.status))
elif mode == "fifo":
    w = subprocess.Popen([sys.executable, "-c",
        "import os, signal, sys; signal.alarm(3); os.open(sys.argv[1], os.O_WRONLY); print('opened', flush=True)",
        os.path.join(pub, "fifo")], stdout=subprocess.PIPE, text=True)
    time.sleep(0.3)  # (the writer waits in its open for a reader)
    r, b = get("/assets/fifo")
    time.sleep(0.3)
    opened = w.poll() is not None and "opened" in w.stdout.read()
    w.kill(); w.wait()
    out.append(f"{r.status} {'opened' if opened else 'blocked'}")
elif mode == "traverse-only":
    for p in ["/assets/locked/", "/assets/locked/index.html"]:
        r, b = get(p)
        out.append(str(r.status))
elif mode == "split-lists":
    time.sleep(2.1)  # (strong validators: the files are older than two seconds)
    r, b = get("/assets/small.txt"); etag = r.getheader("ETag"); lm = r.getheader("Last-Modified")
    old = "Sun, 06 Nov 1994 08:49:37 GMT"
    def two(name, a, z):
        return raw(f"GET /assets/small.txt HTTP/1.1\\r\\nHost: x\\r\\n{name}: {a}\\r\\n{name}: {z}\\r\\nConnection: close\\r\\n\\r\\n".encode())
    out.append(status(two("If-None-Match", '"a"', etag)))
    out.append(status(two("If-Match", '"x"', etag)))
    out.append(status(two("If-Modified-Since", lm, lm)))
    out.append(status(two("If-Unmodified-Since", old, old)))
elif mode == "fields":
    r, b = get("/assets/small.txt")
    out.append(f"{r.getheader('X-Content-Type-Options')} {r.getheader('Cache-Control')}")
    r, b = get("/plain/small.txt"); etag = r.getheader("ETag")
    out.append(f"{r.getheader('Cache-Control')}")
    r, b = get("/plain/small.txt", **{"If-None-Match": etag})
    out.append(f"{r.status} {r.getheader('Cache-Control')}")
elif mode == "slow-many":
    socks = []
    for _ in range(8):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        s.connect(("127.0.0.1", port))
        s.sendall(b"GET /assets/huge.bin HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
        socks.append(s)
    end = time.time() + 2.0
    while time.time() < end:  # each takes a little now and then: its output dips under the mark
        for s in socks:
            s.recv(2048)
        time.sleep(0.02)
    for s in socks:
        s.close()
    out.append("done")
print("|".join(out), flush=True)
"""


struct App(Handler):
    var files: StaticFiles
    var plain: StaticFiles

    def __init__(out self, var files: StaticFiles, var plain: StaticFiles):
        self.files = files^
        self.plain = plain^

    def handle(mut self, req: Request, mut res: Response) raises:
        res.text(404, "not routed\n")

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        if self.plain.owns(req):
            return self.plain.produce(req, out)
        return self.files.produce(req, out)

    def stream_ended(mut self, req: Request, finished: Bool):
        self.files.stream_ended(req)
        self.plain.stream_ended(req)


def assets(mut app: App, req: Request, params: Params, mut res: Response) raises:
    app.files.serve(req, params["path"], res)


def plain(mut app: App, req: Request, params: Params, mut res: Response) raises:
    app.plain.serve(req, params["path"], res)


def _root() raises -> String:
    var os = Python.import_module("os")
    var tempfile = Python.import_module("tempfile")
    var root = String(py=tempfile.mkdtemp(prefix=String("mojo_net_static_sr2_", Int(py=os.getpid()), "_")))
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    _ = subprocess.run(Python.list(pysys.executable, "-c", _SETUP, root), check=True)
    return root^


@fieldwise_init
struct _Outcome(Movable):
    var out: String
    var peak: Int
    """The most memory one connection's output buffers held at once (the
    piece, the socket's queue, the codec's)."""


def _run(mode: StaticString) raises -> _Outcome:
    var root = _root()
    var pub = String(root, "/pub")
    var router = Router(
        App(StaticFiles.open(pub), StaticFiles.open(pub, inode_etags=False, cache_control="no-cache"))
    )
    router.get("/assets/*path", assets)
    router.get("/plain/*path", plain)
    var s = Server(router^)
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    var proc = subprocess.Popen(
        Python.list(pysys.executable, "-c", _CLIENT, String(s.local_addr().port()), mode, root),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    var peak = 0
    var t = Instant.now()
    while String(proc.poll()) == "None":
        s.step(Duration.from_millis(5))
        for i in range(len(s._conns)):
            if s._conns[i]:
                ref c = s._conns[i].value()
                peak = max(peak, c.res.body.capacity() + c.out.capacity() + c.http._tx.capacity())
        if t.elapsed() > Duration.from_secs(60):
            _ = proc.kill()
            _ = Python.import_module("shutil").rmtree(root, ignore_errors=True)
            raise Error(String("client ", mode, " timed out"))
    var drain = Instant.now()
    while s.connections() > 0 and drain.elapsed() < Duration.from_secs(3):
        s.step(Duration.from_millis(5))
    var out = String(String(py=proc.communicate()[0]).strip())
    _ = Python.import_module("shutil").rmtree(root, ignore_errors=True)
    assert_equal(s.connections(), 0, String(mode, ": connections left"))
    assert_equal(s.handler.app.files.transfers() + s.handler.app.plain.transfers(), 0, String(mode, ": files left open"))
    return _Outcome(out^, peak)


def test_a_file_rewritten_while_it_streams_is_cut() raises:
    assert_equal(_run("rewrite").out, "cut")


def test_a_change_that_keeps_size_and_mtime_changes_the_etag() raises:
    assert_equal(_run("pinned-mtime").out, "200 b'1.2.4'")


def test_times_before_1970_keep_their_seconds() raises:
    assert_equal(_run("negative").out, "differ=True")


def test_a_fresh_file_has_weak_validators() raises:
    # weak: If-Match (strong) fails, and If-Range by tag or date sends it whole
    assert_equal(_run("fresh").out, "W/|412|200|200")


def test_a_fifo_is_never_opened() raises:
    assert_equal(_run("fifo").out, "404 blocked")


def test_a_searchable_directory_serves_its_index() raises:
    assert_equal(_run("traverse-only").out, "200|200")


def test_fields_in_several_lines() raises:
    assert_equal(_run("split-lists").out, "304|200|200|200")


def test_nosniff_and_cache_control() raises:
    assert_equal(_run("fields").out, "nosniff None|no-cache|304 no-cache")


def test_slow_downloads_hold_little() raises:
    var r = _run("slow-many")
    assert_equal(r.out, "done")
    # (64 KiB queued for the socket, 64 KiB in the codec, and the piece:
    # 16 KiB, where 64 KiB pieces made it 192 KiB)
    assert_true(r.peak <= 160 * 1024, String(r.peak // 1024, " KiB held"))


def test_last_modified_is_the_dates_second_at_most() raises:
    var root = _root()
    var files = StaticFiles.open(String(root, "/pub"))
    var req = Request(SocketAddr.parse("127.0.0.1:1"))
    req.method = "GET"
    req.target = "/small.txt"
    req.unix_time = 1_000_000_000  # (before the file's time: as if it were in the future)
    var res = Response()
    files.serve(req, "small.txt", res)
    _ = Python.import_module("shutil").rmtree(root, ignore_errors=True)
    assert_equal(res.status, 200)
    assert_equal(String(res.headers.get("last-modified").value()), http_date(1_000_000_000))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
