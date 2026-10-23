"""`server.Router`: patterns (text, `:param`, `*rest`), the most specific
match for the method winning with backtracking, per-segment decoding,
queries and absolute-form targets, HEAD and OPTIONS, 405 with the union of
the allowed methods, the application as the fallback and for the hooks,
malformed patterns refused; a server running a router, over the wire;
and a differential check against a naive matcher (every matching route,
ranked by its segment kinds) over random route sets and paths."""

from std.python import Python
from std.random import random_ui64, seed
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import Handler, Params, Request, Response, Router, Server


struct App(Handler):
    var log: List[String]
    var produced: Int

    def __init__(out self):
        self.log = List[String]()
        self.produced = 0

    def handle(mut self, req: Request, mut res: Response) raises:
        self.log.append(String("fallback ", req.method, " ", req.target))
        res.text(404, "nothing here\n")

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        self.produced += 1
        return False


def _say(name: StringSlice, mut app: App, params: Params, mut res: Response) raises:
    var text = String(name)
    for i in range(len(params)):
        text += String(" ", params.name(i), "=", params.value(i))
    app.log.append(text)
    res.text(200, text)


def root(mut app: App, req: Request, params: Params, mut res: Response) raises:
    _say("root", app, params, res)


def users(mut app: App, req: Request, params: Params, mut res: Response) raises:
    _say("users", app, params, res)


def user(mut app: App, req: Request, params: Params, mut res: Response) raises:
    _say("user", app, params, res)


def me(mut app: App, req: Request, params: Params, mut res: Response) raises:
    _say("me", app, params, res)


def create(mut app: App, req: Request, params: Params, mut res: Response) raises:
    _say("create", app, params, res)


def files(mut app: App, req: Request, params: Params, mut res: Response) raises:
    _say("files", app, params, res)


def options(mut app: App, req: Request, params: Params, mut res: Response) raises:
    _say("options", app, params, res)


def _request(method: StringSlice, target: StringSlice) raises -> Request:
    var r = Request(SocketAddr.parse("127.0.0.1:1"))
    r.method = String(method)
    r.target = String(target)
    return r^


def _call(mut router: Router[App], method: StringSlice, target: StringSlice) raises -> String:
    var res = Response()
    router.handle(_request(method, target), res)
    var out = String(res.status, " ", String(from_utf8_lossy=Span(res.body)).strip())
    var allow = res.headers.get("Allow")
    if allow:
        out += String(" [Allow: ", allow.value(), "]")
    return out^


def _router() raises -> Router[App]:
    var r = Router(App())
    r.get("/", root)
    r.get("/users", users)
    r.post("/users", create)
    r.get("/users/:id", user)
    r.post("/users/me", me)
    r.get("/files/*path", files)
    return r^


def test_patterns_and_params() raises:
    var r = _router()
    assert_equal(_call(r, "GET", "/"), "200 root")
    assert_equal(_call(r, "GET", "/users"), "200 users")
    assert_equal(_call(r, "POST", "/users"), "200 create")
    assert_equal(_call(r, "GET", "/users/42"), "200 user id=42")
    assert_equal(_call(r, "GET", "/files/a/b.txt"), "200 files path=a/b.txt")
    assert_equal(_call(r, "GET", "/files/"), "200 files path=")
    assert_equal(_call(r, "GET", "/files"), "404 nothing here")  # the rest is one segment or more


def test_the_most_specific_route_for_the_method_wins() raises:
    var r = _router()
    assert_equal(_call(r, "POST", "/users/me"), "200 me")
    assert_equal(_call(r, "GET", "/users/me"), "200 user id=me")  # text has no GET: the parameter does
    var b = Router(App())
    b.get("/a/:x/c", user)
    b.get("/a/b/d", me)
    b.get("/a/*rest", files)
    assert_equal(_call(b, "GET", "/a/b/c"), "200 user x=b")  # back from text b to :x
    assert_equal(_call(b, "GET", "/a/b/d"), "200 me")
    assert_equal(_call(b, "GET", "/a/b/e"), "200 files rest=b/e")
    assert_equal(_call(b, "GET", "/a/q/c"), "200 user x=q")


def test_decoding_queries_and_targets() raises:
    var r = _router()
    assert_equal(_call(r, "GET", "/users/j%C3%B6rg"), "200 user id=jörg")
    assert_equal(_call(r, "GET", "/users/a%20b?x=1&y=/z"), "200 user id=a b")
    assert_equal(_call(r, "GET", "/%75sers/1"), "200 user id=1")  # text matches the decoded path
    assert_equal(_call(r, "GET", "/users/%zz"), "400 Bad Request")
    assert_equal(_call(r, "GET", "/users/%4"), "400 Bad Request")
    assert_equal(_call(r, "GET", "/users/a%2Fb"), "404 nothing here")  # an encoded "/" routes nowhere
    assert_equal(_call(r, "GET", "/users/a%00"), "404 nothing here")
    assert_equal(_call(r, "GET", "/users/"), "404 nothing here")  # strict about trailing slashes
    assert_equal(_call(r, "GET", "/users//1"), "404 nothing here")
    assert_equal(_call(r, "GET", "http://example.com:8080/users/7?q"), "200 user id=7")
    assert_equal(_call(r, "GET", "http://example.com"), "200 root")
    assert_equal(_call(r, "GET", "http://example.com?q"), "200 root")
    assert_equal(_call(r, "OPTIONS", "*"), "404 nothing here")


def test_head_options_and_405() raises:
    var r = _router()
    assert_equal(_call(r, "HEAD", "/users/42"), "200 user id=42")
    assert_equal(_call(r, "DELETE", "/users"), "405 Method Not Allowed [Allow: GET, POST, HEAD, OPTIONS]")
    # /users/me matches POST /users/me and GET /users/:id: both are allowed
    assert_equal(_call(r, "DELETE", "/users/me"), "405 Method Not Allowed [Allow: POST, GET, HEAD, OPTIONS]")
    assert_equal(_call(r, "OPTIONS", "/users/me"), "204  [Allow: POST, GET, HEAD, OPTIONS]")
    assert_equal(_call(r, "OPTIONS", "/nowhere"), "404 nothing here")
    r.route("OPTIONS", "/users", options)
    assert_equal(_call(r, "OPTIONS", "/users"), "200 options")


def test_the_application_is_the_fallback_and_gets_the_hooks() raises:
    var r = _router()
    _ = _call(r, "GET", "/nowhere")
    assert_equal(len(r.app.log), 1, "the application was not asked")
    assert_equal(r.app.log[0], "fallback GET /nowhere")
    var out = List[UInt8]()
    _ = r.produce(_request("GET", "/x"), out)
    assert_equal(r.app.produced, 1)


def _refused(pattern: StringSlice, method: StringSlice = "GET") -> Bool:
    try:
        var r = _router()
        r.route(method, pattern, user)
        return False
    except:
        return True


def test_malformed_patterns_are_refused() raises:
    assert_true(_refused("users"))  # no leading "/"
    assert_true(_refused("/users/:id"))  # added twice
    assert_true(_refused("/users/:name/x"))  # :name where another has :id
    assert_true(_refused("/files/*other"))  # *other where another has *path
    assert_true(_refused("/a/*rest/b"))  # the rest not last
    assert_true(_refused("/a/:"))
    assert_true(_refused("/a/*"))
    assert_true(_refused("/a//b"))
    assert_false(_refused("/users/:id", "PUT"))  # another method: fine
    assert_false(_refused("/users/:id/posts"))


# ---- over the wire --------------------------------------------------------------------

comptime _CLIENT = """
import http.client, sys
c = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=10)
out = []
for method, path in [("GET", "/users/42"), ("HEAD", "/users/42"), ("DELETE", "/users"), ("GET", "/nope"), ("GET", "/users/%zz")]:
    c.request(method, path); r = c.getresponse()
    out.append(f"{r.status} {r.read().decode().strip()} {r.getheader('Allow')}")
print("|".join(out), flush=True)
"""


def test_a_server_runs_a_router() raises:
    var server = Server(_router())
    server.bind(SocketAddr.parse("127.0.0.1:0"))
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    var proc = subprocess.Popen(
        Python.list(pysys.executable, "-c", _CLIENT, String(server.local_addr().port())),
        stdout=subprocess.PIPE,
        text=True,
    )
    var t = Instant.now()
    while String(proc.poll()) == "None":
        server.step(Duration.from_millis(5))
        if t.elapsed() > Duration.from_secs(30):
            _ = proc.kill()
            raise Error("client timed out")
    assert_equal(
        String(String(py=proc.communicate()[0]).strip()),
        "200 user id=42 None|200  None|405 Method Not Allowed GET, POST, HEAD, OPTIONS"
        + "|404 nothing here None|400 Bad Request None",
    )


# ---- differential check against a naive matcher ------------------------------------


def _rand(n: Int) -> Int:
    return Int(random_ui64(0, UInt64(n - 1)))


def _naive(
    patterns: List[List[String]],
    methods: List[String],
    method: String,
    path: List[String],
    mut params: String,
) -> Int:
    """Among the routes matching `path` and `method` (HEAD also GET), the
    one with the least sequence of segment kinds (text < param < rest);
    -2 if only other methods match, -1 if nothing does."""
    var best = -1
    var best_kinds = List[Int]()
    var any_method = False
    for r in range(len(patterns)):
        ref p = patterns[r]
        var kinds = List[Int]()
        var ok = True
        var i = 0
        while i < len(p):
            ref seg = p[i]
            if seg.startswith("*"):
                if i >= len(path):
                    ok = False
                kinds.append(2)
                break
            if i >= len(path):
                ok = False
                break
            if seg.startswith(":"):
                if path[i].byte_length() == 0:
                    ok = False
                    break
                kinds.append(1)
            else:
                if seg != path[i]:
                    ok = False
                    break
                kinds.append(0)
            i += 1
        if ok and not (len(p) > 0 and p[len(p) - 1].startswith("*")) and len(p) != len(path):
            ok = False
        if not ok:
            continue
        any_method = True
        if not (methods[r] == method or (method == "HEAD" and methods[r] == "GET")):
            continue
        var better = best < 0
        if not better:
            for k in range(min(len(kinds), len(best_kinds))):
                if kinds[k] != best_kinds[k]:
                    better = kinds[k] < best_kinds[k]
                    break
        if better or (best >= 0 and methods[best] != method and methods[r] == method and kinds == best_kinds):
            best = r
            best_kinds = kinds^
    if best < 0:
        return -2 if any_method else -1
    params = String()
    ref p = patterns[best]
    for i in range(len(p)):
        if p[i].startswith(":"):
            params += String(" ", p[i][byte=1:], "=", path[i])
        elif p[i].startswith("*"):
            var rest = String()
            for j in range(i, len(path)):
                if j > i:
                    rest += "/"
                rest += path[j]
            params += String(" ", p[i][byte=1:], "=", rest)
    return best


def test_against_a_naive_matcher() raises:
    seed(20261023)
    var texts = ["a", "b", "c"]
    var verbs = ["GET", "POST"]
    for _ in range(300):
        var router = Router(App())
        var patterns = List[List[String]]()
        var methods = List[String]()
        for _ in range(1 + _rand(8)):
            var p = List[String]()
            var depth = _rand(4)
            for d in range(depth):
                var k = _rand(10)
                if k < 6:
                    p.append(String(texts[_rand(3)]))
                elif k < 9 or d < depth - 1:
                    p.append(String(":p", d))  # one name per depth: no conflicts
                else:
                    p.append(String("*r", d))
            var text = String()
            for s in p:
                text += String("/", s)
            if text.byte_length() == 0:
                text = "/"
            var m = String(verbs[_rand(2)])
            try:
                router.route(m, text, user)
            except:
                continue  # added twice
            patterns.append(p^)
            methods.append(m)
        for _ in range(40):
            var path = List[String]()
            for _ in range(_rand(5)):
                var k = _rand(10)
                path.append(String(texts[_rand(3)]) if k < 7 else (String("x") if k < 9 else String()))
            if len(path) == 1 and path[0].byte_length() == 0:
                path.clear()  # "/" is the root, no segments
            var target = String()
            for s in path:
                target += String("/", s)
            if target.byte_length() == 0:
                target = "/"
            var method = String(["GET", "POST", "HEAD"][_rand(3)])
            var want_params = String()
            var want = _naive(patterns, methods, method, path, want_params)
            var got = router.find(method, target)
            var got_params = String()
            if got >= 0:
                ref ps = router.last_params()
                for i in range(len(ps)):
                    got_params += String(" ", ps.name(i), "=", ps.value(i))
            var where = String(method, " ", target, " over")
            for r in range(len(patterns)):
                where += String(" ", methods[r], " ", router.pattern(r))
            if got >= 0 and want >= 0:
                assert_equal(router.pattern(got), router.pattern(want), where)
            else:
                assert_equal(got, want, where)
            assert_equal(got_params, want_params, where)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
