"""`server.StaticFiles` behind a `Router`, against a Python client, over a
scratch directory: files and their types, the index and the redirect to
it, every way out of the directory refused (".." raw and encoded, empty
segments, symlinks out, a FIFO that must not block, an unreadable file),
conditional requests, ranges, large files streamed (and an abandoned one
released), HEAD; plus HTTP-date parsing and the type table."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import (
    Handler,
    Params,
    Request,
    Response,
    Router,
    Server,
    StaticFiles,
    content_type,
    http_date,
    parse_http_date,
)

comptime _SETUP = """
import os, sys
root = sys.argv[1]
os.makedirs(os.path.join(root, "pub", "sub"), exist_ok=True)
def put(name, data):
    with open(os.path.join(root, "pub", name), "wb") as f:
        f.write(data)
put("index.html", b"<h1>home</h1>")
put("small.txt", b"hello\\n")
put("empty.txt", b"")
put("sub/index.html", b"<h1>sub</h1>")
put("sub/page.css", b"body{}")
put("big.bin", bytes((i * 7) % 251 for i in range(1024 * 1024 + 123)))
put("huge.bin", b"0123456789abcdef" * (2 * 1024 * 1024))  # 32 MiB: far more than socket buffers hold
put("secret.txt", b"no")
os.chmod(os.path.join(root, "pub", "secret.txt"), 0)
with open(os.path.join(root, "outside.txt"), "wb") as f:
    f.write(b"outside")
os.symlink("small.txt", os.path.join(root, "pub", "link_in"))
os.symlink(os.path.join(root, "outside.txt"), os.path.join(root, "pub", "link_out"))
os.symlink(root, os.path.join(root, "pub", "dir_out"))
os.mkfifo(os.path.join(root, "pub", "fifo"))
"""

comptime _CLIENT = """
import http.client, os, socket, sys
port = int(sys.argv[1]); mode = sys.argv[2]
out = []
c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
def get(path, method="GET", **headers):
    c.request(method, path, headers=headers); r = c.getresponse(); body = r.read()
    return r, body
def show(path, method="GET", **headers):
    r, body = get(path, method, **headers)
    return f"{r.status} {body[:40].decode(errors='replace')!r}"
if mode == "files":
    r, b = get("/assets/small.txt")
    out.append(f"{r.status} {b!r} {r.getheader('Content-Type')} etag={r.getheader('ETag') is not None} lm={r.getheader('Last-Modified') is not None} {r.getheader('Accept-Ranges')}")
    r, b = get("/assets/")
    out.append(f"{r.status} {b!r} {r.getheader('Content-Type')}")
    r, b = get("/assets/sub")
    out.append(f"{r.status} {r.getheader('Location')}")
    r, b = get("/assets/sub?x=1")
    out.append(f"{r.status} {r.getheader('Location')}")
    out.append(show("/assets/sub/"))
    r, b = get("/assets/sub/page.css")
    out.append(f"{r.status} {r.getheader('Content-Type')}")
    r, b = get("/assets/empty.txt")
    out.append(f"{r.status} len={r.getheader('Content-Length')} {b!r}")
    out.append(show("/assets/link_in"))
    out.append(show("/assets/nope.txt"))
    out.append(show("/assets/small.txt/"))  # a file is no directory
elif mode == "escapes":
    for p in ["/assets/../outside.txt", "/assets/%2e%2e/outside.txt", "/assets/sub/../small.txt",
              "/assets//etc/passwd", "/assets/./small.txt", "/assets/link_out", "/assets/dir_out/outside.txt",
              "/assets/fifo", "/assets/secret.txt"]:
        out.append(show(p).split(" ")[0])
elif mode == "conditional":
    r, b = get("/assets/small.txt"); etag = r.getheader("ETag"); lm = r.getheader("Last-Modified")
    r, b = get("/assets/small.txt", **{"If-None-Match": etag}); out.append(f"{r.status} {b!r} {r.getheader('ETag') == etag}")
    out.append(show("/assets/small.txt", **{"If-None-Match": '"other"'}))
    out.append(show("/assets/small.txt", **{"If-None-Match": '"other", ' + etag}))
    out.append(show("/assets/small.txt", **{"If-None-Match": "*"}))
    out.append(show("/assets/small.txt", **{"If-None-Match": "W/" + etag}))
    out.append(show("/assets/small.txt", **{"If-Modified-Since": lm}))
    out.append(show("/assets/small.txt", **{"If-Modified-Since": "Sun, 06 Nov 1994 08:49:37 GMT"}))
    out.append(show("/assets/small.txt", **{"If-None-Match": '"other"', "If-Modified-Since": lm}))
elif mode == "ranges":
    data = bytes((i * 7) % 251 for i in range(1024 * 1024 + 123)); size = len(data)
    def rng(spec, **h):
        r, b = get("/assets/big.bin", Range=spec, **h)
        return r.status, r.getheader("Content-Range"), b
    s, cr, b = rng("bytes=0-9"); out.append(f"{s} {cr} {b == data[0:10]}")
    s, cr, b = rng("bytes=-5"); out.append(f"{s} {cr} {b == data[-5:]}")
    s, cr, b = rng("bytes=1000-700000"); out.append(f"{s} {cr} {b == data[1000:700001]}")
    s, cr, b = rng(f"bytes={size - 3}-"); out.append(f"{s} {cr} {b == data[-3:]}")
    s, cr, b = rng(f"bytes={size}-"); out.append(f"{s} {cr}")
    s, cr, b = rng("bytes=10-5"); out.append(f"{s} {len(b) == size}")
    s, cr, b = rng("bytes=0-1,5-6"); out.append(f"{s} {len(b) == size}")
    r, b = get("/assets/big.bin"); etag = r.getheader("ETag")
    s, cr, b = rng("bytes=0-0", **{"If-Range": etag}); out.append(f"{s} {cr}")
    s, cr, b = rng("bytes=0-0", **{"If-Range": '"old"'}); out.append(f"{s} {len(b) == size}")
    r, b = get("/assets/empty.txt", Range="bytes=0-0"); out.append(f"{r.status} {b!r}")
elif mode == "big":
    data = bytes((i * 7) % 251 for i in range(1024 * 1024 + 123))
    r, b = get("/assets/big.bin")
    out.append(f"{r.status} len={r.getheader('Content-Length')} same={b == data} {r.getheader('Content-Type')}")
    r, b = get("/assets/big.bin", "HEAD")
    out.append(f"head {r.status} len={r.getheader('Content-Length')} {b!r}")
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
    s.sendall(b"GET /assets/huge.bin HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")
    got = 0
    while got < 100000:
        got += len(s.recv(65536))
    s.close()  # gone mid-file: its stream is cut, and the file must be closed
    out.append("left")
print("|".join(out), flush=True)
"""


struct App(Handler):
    var files: StaticFiles

    def __init__(out self, var files: StaticFiles):
        self.files = files^

    def handle(mut self, req: Request, mut res: Response) raises:
        res.text(404, "not routed\n")

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        return self.files.produce(req, out)

    def stream_ended(mut self, req: Request, finished: Bool):
        self.files.stream_ended(req)


def assets(mut app: App, req: Request, params: Params, mut res: Response) raises:
    app.files.serve(req, params["path"], res)


def _root() raises -> String:
    var os = Python.import_module("os")
    var tempfile = Python.import_module("tempfile")
    var d = String(py=tempfile.mkdtemp(prefix=String("mojo_net_static_", Int(py=os.getpid()), "_")))
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    _ = subprocess.run(Python.list(pysys.executable, "-c", _SETUP, d), check=True)
    return d^


def _run(mode: StaticString) raises -> String:
    var root = _root()
    var router = Router(App(StaticFiles.open(String(root, "/pub"))))
    router.get("/assets/*path", assets)
    var s = Server(router^)
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
    while String(proc.poll()) == "None":
        s.step(Duration.from_millis(5))
        if t.elapsed() > Duration.from_secs(60):
            _ = proc.kill()
            _ = Python.import_module("shutil").rmtree(root, ignore_errors=True)
            raise Error(String("client ", mode, " timed out"))
    # A client that left mid-file is seen when the server's next probe of
    # its zero window draws a reset (TCP's persist timer: about 200 ms).
    var drain = Instant.now()
    while s.connections() > 0 and drain.elapsed() < Duration.from_secs(3):
        s.step(Duration.from_millis(5))
    var out = String(String(py=proc.communicate()[0]).strip())
    _ = Python.import_module("shutil").rmtree(root)  # (before asserting: no leftovers)
    assert_equal(s.connections(), 0, String(mode, ": connections left"))
    assert_equal(s.handler.app.files.transfers(), 0, String(mode, ": files left open"))
    return out^


def test_files_types_index_and_redirects() raises:
    assert_equal(
        _run("files"),
        "200 b'hello\\n' text/plain; charset=utf-8 etag=True lm=True bytes"
        + "|200 b'<h1>home</h1>' text/html; charset=utf-8"
        + "|301 /assets/sub/|301 /assets/sub/?x=1|200 '<h1>sub</h1>'|200 text/css; charset=utf-8"
        + "|200 len=0 b''|200 'hello\\n'|404 'Not Found\\n'|404 'Not Found\\n'",
    )


def test_no_way_out_of_the_directory() raises:
    var os = Python.import_module("os")
    var forbidden = "403" if Int(py=os.getuid()) != 0 else "200"  # (root reads mode 000)
    assert_equal(_run("escapes"), "404|404|404|404|404|404|404|404|" + forbidden)


def test_conditional_requests() raises:
    assert_equal(
        _run("conditional"),
        "304 b'' True|200 'hello\\n'|304 ''|304 ''|304 ''|304 ''|200 'hello\\n'|200 'hello\\n'",
    )


def test_ranges() raises:
    var size = 1024 * 1024 + 123
    assert_equal(
        _run("ranges"),
        String(
            "206 bytes 0-9/", size, " True|206 bytes ", size - 5, "-", size - 1, "/", size, " True",
            "|206 bytes 1000-700000/", size, " True|206 bytes ", size - 3, "-", size - 1, "/", size, " True",
            "|416 bytes */", size, "|200 True|200 True|206 bytes 0-0/", size, "|200 True|200 b''",
        ),
    )


def test_large_files_stream_and_abandoned_ones_close() raises:
    assert_equal(
        _run("big"),
        "200 len=1048699 same=True application/octet-stream|head 200 len=1048699 b''|left",
    )


def test_http_dates() raises:
    var t = 784111777
    assert_equal(http_date(t), "Sun, 06 Nov 1994 08:49:37 GMT")
    assert_equal(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").or_else(-1), t)
    assert_equal(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT").or_else(-1), t)
    assert_equal(parse_http_date("Sun Nov  6 08:49:37 1994").or_else(-1), t)
    assert_equal(parse_http_date("Sun Nov 16 08:49:37 1994").or_else(-1), t + 10 * 86400)
    assert_equal(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT").or_else(-1), 0)
    assert_equal(parse_http_date("Fri, 31 Dec 9999 23:59:59 GMT").or_else(-1), 253402300799)
    for bad in [
        "Sun, 06 Nov 1994 08:49:37 UTC",
        "Sun, 06 Nov 1994 8:49:37 GMT",
        "Sun, 06 Foo 1994 08:49:37 GMT",
        "Sun, 06 Nov 1994 24:00:00 GMT",
        "Sun, 32 Nov 1994 08:49:37 GMT",
        "06 Nov 1994 08:49:37 GMT",
        "",
        "Sunday, 06-Nov-94 08:49:37",
    ]:
        assert_false(Bool(parse_http_date(bad)), bad)
    # RFC 850's two-digit year: not more than 50 years ahead
    var builtins = Python.import_module("builtins")
    var now = Int(py=builtins.int(Python.import_module("time").time()))
    var now_year = atol(http_date(now)[byte=12:16])
    var ahead = (now_year + 49) % 100
    var behind = (now_year + 51) % 100
    var a = http_date(parse_http_date(String("Sunday, 06-Nov-", ahead // 10, ahead % 10, " 08:49:37 GMT")).or_else(0))
    var b = http_date(parse_http_date(String("Sunday, 06-Nov-", behind // 10, behind % 10, " 08:49:37 GMT")).or_else(0))
    assert_equal(atol(a[byte=12:16]), now_year + 49)
    assert_equal(atol(b[byte=12:16]), now_year + 51 - 100)


def test_content_types() raises:
    assert_equal(content_type("a/b/index.HTML"), "text/html; charset=utf-8")
    assert_equal(content_type("app.mjs"), "text/javascript; charset=utf-8")
    assert_equal(content_type("x.tar.gz"), "application/gzip")
    assert_equal(content_type("font.woff2"), "font/woff2")
    assert_equal(content_type("README"), "application/octet-stream")
    assert_equal(content_type("dir.d/file"), "application/octet-stream")
    assert_equal(content_type(".hidden"), "application/octet-stream")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
