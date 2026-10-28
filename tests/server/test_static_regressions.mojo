"""Regression tests for the S5 review of `StaticFiles`, each checked to
fail on the code before its fix:
- If-Match and If-Unmodified-Since were ignored, so a resumed download of
  a changed file got the new bytes (RFC 9110 13.1.1, 13.1.4: 412);
- ENOTDIR, ELOOP and ENXIO opens answered 500 instead of 404;
- the directory redirect echoed the authority of an absolute-form target;
- a Last-Modified in the future was sent as is (RFC 9110 8.8.2.1);
- HEAD with Range got 206 (Range is defined for GET only, RFC 9110 14.2);
- dotfiles were served (now hidden, but for .well-known, unless asked)."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_true

from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import Handler, Params, Request, Response, Router, Server, StaticFiles

comptime _SETUP = """
import os, socket, sys, time
root = sys.argv[1]
pub = os.path.join(root, "pub")
os.makedirs(os.path.join(pub, "sub"), exist_ok=True)
os.makedirs(os.path.join(pub, ".well-known"), exist_ok=True)
os.makedirs(os.path.join(pub, ".git"), exist_ok=True)
def put(name, data):
    with open(os.path.join(pub, name), "wb") as f:
        f.write(data)
put("small.txt", b"hello\\n")
put("sub/index.html", b"<h1>sub</h1>")
put("data.bin", bytes(range(256)) * 4)
put(".env", b"SECRET=1")
put(".git/config", b"[core]")
put(".well-known/acme", b"token")
put("future.txt", b"later")
ten_years = time.time() + 10 * 365 * 86400
os.utime(os.path.join(pub, "future.txt"), (ten_years, ten_years))
os.symlink("loop", os.path.join(pub, "loop"))
u = socket.socket(socket.AF_UNIX); u.bind(os.path.join(pub, "sock"))
"""

comptime _CLIENT = """
import email.utils, http.client, socket, sys, time
port = int(sys.argv[1]); mode = sys.argv[2]
out = []
if mode == "preconditions":
    time.sleep(2.1)  # files changed within a second or two get weak validators
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
if mode == "preconditions":
    r, b = get("/assets/data.bin"); etag = r.getheader("ETag"); lm = r.getheader("Last-Modified")
    old = "Sun, 06 Nov 1994 08:49:37 GMT"
    for h in [{"If-Match": '"nope"'}, {"If-Match": etag}, {"If-Match": "*"}, {"If-Match": "W/" + etag},
              {"If-Unmodified-Since": old}, {"If-Unmodified-Since": lm},
              {"If-Match": etag, "If-Unmodified-Since": old},
              {"Range": "bytes=100-199", "If-Unmodified-Since": old},
              {"Range": "bytes=100-199", "If-Match": '"nope"'},
              {"If-None-Match": etag, "If-Match": '"nope"'}]:
        r, b = get("/assets/data.bin", **h)
        out.append(str(r.status))
elif mode == "errors":
    for p in ["/assets/small.txt/x", "/assets/loop", "/assets/sock"]:
        r, b = get(p)
        out.append(str(r.status))
elif mode == "redirect":
    d = raw(b"GET http://evil.example/assets/sub HTTP/1.1\\r\\nHost: x\\r\\nConnection: close\\r\\n\\r\\n")
    loc = [l for l in d.split(b"\\r\\n") if l.lower().startswith(b"location:")]
    out.append(f"{d.split(b'\\r\\n')[0].decode()} {loc[0].decode() if loc else None}")
elif mode == "future":
    r, b = get("/assets/future.txt")
    lm = email.utils.parsedate_to_datetime(r.getheader("Last-Modified")).timestamp()
    date = email.utils.parsedate_to_datetime(r.getheader("Date")).timestamp()
    out.append(f"{r.status} not-after-date={lm <= date}")
elif mode == "head-range":
    r, b = get("/assets/data.bin", "HEAD", Range="bytes=0-9")
    out.append(f"{r.status} {r.getheader('Content-Length')} {r.getheader('Content-Range')}")
elif mode == "dotfiles":
    for p in ["/assets/.env", "/assets/.git/config", "/assets/.well-known/acme", "/assets/sub/"]:
        r, b = get(p)
        out.append(str(r.status))
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


def _run(mode: StaticString) raises -> String:
    var os = Python.import_module("os")
    var tempfile = Python.import_module("tempfile")
    var root = String(py=tempfile.mkdtemp(prefix=String("mojo_net_static_reg_", Int(py=os.getpid()), "_")))
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    _ = subprocess.run(Python.list(pysys.executable, "-c", _SETUP, root), check=True)
    var router = Router(App(StaticFiles.open(String(root, "/pub"))))
    router.get("/assets/*path", assets)
    var s = Server(router^)
    s.bind(SocketAddr.parse("127.0.0.1:0"))
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
    var out = String(String(py=proc.communicate()[0]).strip())
    var shutil = Python.import_module("shutil")
    _ = shutil.rmtree(root)
    return out^


def test_preconditions_answer_412() raises:
    # If-Match fails or not, then If-Unmodified-Since, then with ranges; a
    # failing If-Match wins over a matching If-None-Match (RFC 9110 13.2.2)
    assert_equal(_run("preconditions"), "412|200|200|412|412|200|200|412|412|412")


def test_unopenable_paths_are_404() raises:
    assert_equal(_run("errors"), "404|404|404")


def test_the_redirect_names_only_the_path() raises:
    assert_equal(_run("redirect"), "HTTP/1.1 301 Moved Permanently Location: /assets/sub/")


def test_last_modified_is_never_in_the_future() raises:
    assert_equal(_run("future"), "200 not-after-date=True")


def test_head_ignores_range() raises:
    assert_equal(_run("head-range"), "200 1024 None")


def test_dotfiles_are_hidden_but_well_known() raises:
    assert_equal(_run("dotfiles"), "404|404|200|200")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
