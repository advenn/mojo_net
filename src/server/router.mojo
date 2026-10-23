"""Routing (docs/server.md, "Routing"): `Router[A]` sends requests to
functions by method and path pattern, and everything else to the
application `A` itself, a `Handler`: requests no route matches, and every
streaming and shutdown hook.

    def get_user(mut app: App, req: Request, params: Params, mut res: Response) raises:
        res.text(200, String("user ", params["id"]))

    var router = Router(App())
    router.get("/users/:id", get_user)
    var server = Server(router^)

**Patterns** are "/" followed by segments separated by "/":
- text matches the same text in the decoded path;
- ":name" matches one non-empty segment, which `params["name"]` returns;
- "*name", last only, matches the rest of the path, one or more segments
  (an empty one too: "/files/*p" matches "/files/" with p = ""), joined
  by "/".

**Matching.** The path is the request target up to its query (also of an
absolute-form target), split at "/" and percent-decoded segment by
segment, so an encoded "/" never splits one. At each segment, text beats
a parameter, which beats the rest: the most specific pattern wins,
whatever the order routes were added in. A segment that decodes to
something with "/" or NUL in it matches no pattern, and a malformed
percent-encoding gets 400.

**Methods.** When the path matches but the method has no route, the
router answers 405 with `Allow`. HEAD uses the GET route (the server drops
the body), and OPTIONS without a route of its own is answered with 204 and
`Allow`.
"""

from http.headers import Headers

from .server import Handler, Request, Response

comptime _MAX_SEGMENTS = 128
"""Deeper paths match nothing (they go to the application)."""

# segment kinds
comptime _TEXT = 0
comptime _PARAM = 1
comptime _REST = 2


struct Params(Movable, Sized):
    """The parameters of the matched pattern, decoded (lossily, for bytes
    that are not UTF-8)."""

    var _names: List[String]
    var _values: List[String]

    def __init__(out self):
        self._names = List[String]()
        self._values = List[String]()

    def __len__(self) -> Int:
        return len(self._names)

    def get(self, name: StringSlice) -> Optional[String]:
        for i in range(len(self._names)):
            if self._names[i] == name:
                return self._values[i]
        return None

    def __getitem__(self, name: StringSlice) raises -> String:
        """The value of parameter `name`; raises if the pattern has none."""
        var v = self.get(name)
        if not v:
            raise Error("no route parameter ", name)
        return v.value()

    def name(self, i: Int) -> String:
        return self._names[i]

    def value(self, i: Int) -> String:
        return self._values[i]

    def _clear(mut self):
        self._names.clear()
        self._values.clear()


struct _Node(Copyable, Movable):
    var text: String
    """The segment text (for a text child)."""
    var texts: List[Int]
    """Text children."""
    var param: Int
    """The parameter child, or -1."""
    var param_name: String
    var rest: Int
    """The rest-of-path child, or -1."""
    var rest_name: String
    var methods: List[String]
    var routes: List[Int]
    """For a pattern ending here: its methods and their route indexes."""

    def __init__(out self, text: String):
        self.text = text
        self.texts = List[Int]()
        self.param = -1
        self.param_name = String()
        self.rest = -1
        self.rest_name = String()
        self.methods = List[String]()
        self.routes = List[Int]()


@fieldwise_init
struct _Segment(TrivialRegisterPassable):
    var start: Int
    """Offset in the router's decoded-path buffer."""
    var len: Int


def _hex(b: UInt8) -> Int:
    if b >= 48 and b <= 57:
        return Int(b) - 48
    if b >= 65 and b <= 70:
        return Int(b) - 55
    if b >= 97 and b <= 102:
        return Int(b) - 87
    return -1


struct Router[A: Handler](Handler):
    """Routes to functions of the application (see the module docs)."""

    comptime Route = def(mut Self.A, Request, Params, mut Response) raises thin

    var app: Self.A
    """The application: unmatched requests and the streaming hooks go to
    it."""
    var _nodes: List[_Node]
    var _fns: List[Self.Route]
    var _patterns: List[String]
    var _params: Params
    var _path: List[UInt8]
    """The decoded path of the request being matched."""
    var _segments: List[_Segment]
    var _bad: Bool
    """The path's percent-encoding is malformed."""
    var _unroutable: Bool
    """A segment decodes to "/" or NUL, or the path is too deep."""
    var _kinds: List[Int]
    var _values: List[Int]
    var _taken: List[Int]
    """While matching: the kind, segment and node of each step taken."""

    def __init__(out self, var app: Self.A):
        self.app = app^
        self._nodes = List[_Node]()
        self._nodes.append(_Node(String()))
        self._fns = List[Self.Route]()
        self._patterns = List[String]()
        self._params = Params()
        self._path = List[UInt8]()
        self._segments = List[_Segment]()
        self._bad = False
        self._unroutable = False
        self._kinds = List[Int]()
        self._values = List[Int]()
        self._taken = List[Int]()

    # ---- adding routes ---------------------------------------------------------

    def get(mut self, pattern: StringSlice, f: Self.Route) raises:
        self.route("GET", pattern, f)

    def post(mut self, pattern: StringSlice, f: Self.Route) raises:
        self.route("POST", pattern, f)

    def put(mut self, pattern: StringSlice, f: Self.Route) raises:
        self.route("PUT", pattern, f)

    def patch(mut self, pattern: StringSlice, f: Self.Route) raises:
        self.route("PATCH", pattern, f)

    def delete(mut self, pattern: StringSlice, f: Self.Route) raises:
        self.route("DELETE", pattern, f)

    def route(mut self, method: StringSlice, pattern: StringSlice, f: Self.Route) raises:
        """Send `method` requests whose path matches `pattern` to `f`.
        Raises for a malformed pattern, a method and pattern added before,
        or a parameter named differently from one at the same place in
        another pattern."""
        if not pattern.startswith("/"):
            raise Error("route pattern must start with '/': ", pattern)
        var node = 0
        var parts = String(pattern[byte=1:]).split("/")
        var segments = List[String]()
        if not (len(parts) == 1 and parts[0].byte_length() == 0):  # "/" alone: no segments
            for p in parts:
                segments.append(String(p))
        for i in range(len(segments)):
            ref seg = segments[i]
            if seg.startswith(":"):
                var name = String(seg[byte=1:])
                if name.byte_length() == 0:
                    raise Error("route parameter without a name: ", pattern)
                if self._nodes[node].param < 0:
                    self._nodes.append(_Node(String()))
                    self._nodes[node].param = len(self._nodes) - 1
                    self._nodes[node].param_name = name
                elif self._nodes[node].param_name != name:
                    raise Error(
                        "route parameter :", name, " where another pattern has :",
                        self._nodes[node].param_name, ": ", pattern,
                    )
                node = self._nodes[node].param
            elif seg.startswith("*"):
                var name = String(seg[byte=1:])
                if name.byte_length() == 0:
                    raise Error("route wildcard without a name: ", pattern)
                if i != len(segments) - 1:
                    raise Error("route wildcard not last: ", pattern)
                if self._nodes[node].rest < 0:
                    self._nodes.append(_Node(String()))
                    self._nodes[node].rest = len(self._nodes) - 1
                    self._nodes[node].rest_name = name
                elif self._nodes[node].rest_name != name:
                    raise Error(
                        "route wildcard *", name, " where another pattern has *",
                        self._nodes[node].rest_name, ": ", pattern,
                    )
                node = self._nodes[node].rest
            else:
                if seg.byte_length() == 0 and i != len(segments) - 1:
                    raise Error("empty segment in route pattern: ", pattern)
                var found = -1
                for c in self._nodes[node].texts:
                    if self._nodes[c].text == seg:
                        found = c
                        break
                if found < 0:
                    self._nodes.append(_Node(seg))
                    found = len(self._nodes) - 1
                    self._nodes[node].texts.append(found)
                node = found
        for m in self._nodes[node].methods:
            if m == method:
                raise Error("route added twice: ", method, " ", pattern)
        self._nodes[node].methods.append(String(method))
        self._nodes[node].routes.append(len(self._fns))
        self._fns.append(f)
        self._patterns.append(String(pattern))

    # ---- matching --------------------------------------------------------------

    def _split(mut self, target: StringSlice):
        """Decode the path of `target` into `_path` / `_segments`."""
        self._path.clear()
        self._segments.clear()
        self._bad = False
        self._unroutable = False
        var t = target.as_bytes()
        var n = len(t)
        var i = 0
        # absolute-form (RFC 9112 3.2.2): skip the scheme and authority
        if n > 0 and t[0] != 47:  # not "/"
            var s = String(target)
            var at = s.find("://")
            if at < 0:
                self._unroutable = True  # asterisk-form, or not a path
                return
            i = at + 3
            while i < n and t[i] != 47 and t[i] != 63:
                i += 1
            if i >= n or t[i] == 63:
                return  # no path: "/"
        var end = n
        var escaped = False
        for k in range(i, n):
            var b = t[k]
            if b == 63:  # "?"
                end = k
                break
            escaped = escaped or b == 37  # "%"
        if end - i <= 1:
            return  # "/": no segments
        i += 1  # past the first "/"
        if not escaped:
            # The common case: copied as is, the segments are the runs
            # between its slashes.
            self._path.extend(t[i:end])
            var start = 0
            var m = len(self._path)
            for k in range(m + 1):
                if k == m or self._path[k] == 47:
                    self._segments.append(_Segment(start, k - start))
                    start = k + 1
            if len(self._segments) > _MAX_SEGMENTS:
                self._unroutable = True
            return
        while True:
            var start = len(self._path)
            while i < end and t[i] != 47:
                var b = t[i]
                if b == 37:  # "%"
                    if i + 2 >= end or _hex(t[i + 1]) < 0 or _hex(t[i + 2]) < 0:
                        self._bad = True
                        return
                    b = UInt8(_hex(t[i + 1]) * 16 + _hex(t[i + 2]))
                    if b == 47 or b == 0:
                        self._unroutable = True
                    i += 3
                else:
                    i += 1
                self._path.append(b)
            self._segments.append(_Segment(start, len(self._path) - start))
            if len(self._segments) > _MAX_SEGMENTS:
                self._unroutable = True
                return
            if i >= end:
                return
            i += 1  # past "/"

    @inline(.always)
    def _segment_is(self, s: _Segment, text: String) -> Bool:
        """Whether segment `s` of the path is `text`."""
        var tb = text.as_bytes()
        if len(tb) != s.len:
            return False
        for k in range(s.len):
            if self._path[s.start + k] != tb[k]:
                return False
        return True

    @inline(.always)
    def _serves(self, node: Int, method: StringSlice) -> Bool:
        """A pattern ending at `node` has a route for `method` (HEAD: or
        GET; "" stands for any method)."""
        ref n = self._nodes[node]
        if method.byte_length() == 0:
            return len(n.methods) > 0
        return self._route_at(node, method) >= 0 or (
            method == "HEAD" and self._route_at(node, "GET") >= 0
        )

    def _walk(mut self, node: Int, seg: Int, method: StringSlice) -> Int:
        """The node the most specific match for `method` ends at: text
        children first, then the parameter, then the rest, depth first,
        backtracking (-1 if none). `_kinds` and `_values` hold its steps."""
        if seg == len(self._segments):
            return node if self._serves(node, method) else -1
        var s = self._segments[seg]
        for k in range(len(self._nodes[node].texts)):
            var c = self._nodes[node].texts[k]
            if self._segment_is(s, self._nodes[c].text):
                self._step(_TEXT, seg, c)
                var r = self._walk(c, seg + 1, method)
                if r >= 0:
                    return r
                self._unstep()
        var p = self._nodes[node].param
        if p >= 0 and s.len > 0:
            self._step(_PARAM, seg, p)
            var r = self._walk(p, seg + 1, method)
            if r >= 0:
                return r
            self._unstep()
        var rest = self._nodes[node].rest
        if rest >= 0 and self._serves(rest, method):
            self._step(_REST, seg, rest)
            return rest
        return -1

    @inline(.always)
    def _step(mut self, kind: Int, seg: Int, node: Int):
        self._kinds.append(kind)
        self._values.append(seg)
        self._taken.append(node)

    @inline(.always)
    def _unstep(mut self):
        _ = self._kinds.pop()
        _ = self._values.pop()
        _ = self._taken.pop()

    def _all_methods(self, node: Int, seg: Int, mut out: List[String]):
        """Add to `out` the methods of every pattern matching the path from
        `node` on (for Allow)."""
        if seg == len(self._segments):
            for m in self._nodes[node].methods:
                _add_unique(out, m)
            return
        var s = self._segments[seg]
        for c in self._nodes[node].texts:
            if self._segment_is(s, self._nodes[c].text):
                self._all_methods(c, seg + 1, out)
        var p = self._nodes[node].param
        if p >= 0 and s.len > 0:
            self._all_methods(p, seg + 1, out)
        var rest = self._nodes[node].rest
        if rest >= 0:
            for m in self._nodes[rest].methods:
                _add_unique(out, m)

    def _fill_params(mut self):
        """Name the parameters of the match just found."""
        self._params._clear()
        var node = 0
        for k in range(len(self._kinds)):
            var seg = self._values[k]
            var kind = self._kinds[k]
            if kind == _PARAM:
                var s = self._segments[seg]
                self._params._names.append(self._nodes[node].param_name)
                self._params._values.append(
                    String(from_utf8_lossy=Span(self._path)[s.start : s.start + s.len])
                )
            elif kind == _REST:
                var text = List[UInt8]()
                for j in range(seg, len(self._segments)):
                    if j > seg:
                        text.append(47)
                    var s = self._segments[j]
                    text.extend(Span(self._path)[s.start : s.start + s.len])
                self._params._names.append(self._nodes[node].rest_name)
                self._params._values.append(String(from_utf8_lossy=Span(text)))
            node = self._taken[k]

    @inline(.always)
    def _route_at(self, node: Int, method: StringSlice) -> Int:
        ref n = self._nodes[node]
        for i in range(len(n.methods)):
            if _same(n.methods[i].as_bytes(), method.as_bytes()):
                return n.routes[i]
        return -1

    def _allow(self) -> String:
        """The Allow value for the path last split: the methods of every
        pattern it matches, with HEAD for GET and OPTIONS."""
        var methods = List[String]()
        self._all_methods(0, 0, methods)
        var get = False
        for m in methods:
            get = get or m == "GET"
        if get:
            _add_unique(methods, "HEAD")
        _add_unique(methods, "OPTIONS")
        var out = String()
        for i in range(len(methods)):
            if i > 0:
                out += ", "
            out += methods[i]
        return out^

    def find(mut self, method: StringSlice, target: StringSlice) -> Int:
        """The route index `method` and `target` go to (its parameters then
        in `last_params()`), or -1 (no pattern matches), -2 (one does, not
        for this method), -3 (malformed path)."""
        self._split(target)
        if self._bad:
            return -3
        if self._unroutable:
            return -1
        self._kinds.clear()
        self._values.clear()
        self._taken.clear()
        var end = self._walk(0, 0, method)
        if end < 0:
            self._kinds.clear()
            self._values.clear()
            self._taken.clear()
            return -2 if self._walk(0, 0, "") >= 0 else -1
        var r = self._route_at(end, method)
        if r < 0:
            r = self._route_at(end, "GET")  # (HEAD)
        self._fill_params()
        return r

    def last_params(self) -> ref [self._params] Params:
        return self._params

    def pattern(self, route: Int) -> String:
        """The pattern route `route` was added with."""
        return self._patterns[route]

    # ---- Handler -----------------------------------------------------------------

    def handle(mut self, req: Request, mut res: Response) raises:
        var r = self.find(req.method, req.target)
        if r >= 0:
            var f = self._fns[r]
            f(self.app, req, self._params, res)
            return
        if r == -3:
            res.text(400, "Bad Request\n")
            return
        if r == -2:
            var allow = self._allow()
            if req.method == "OPTIONS":
                res.status = 204
                res.headers.add("Allow", allow)
                return
            res.text(405, "Method Not Allowed\n")
            res.headers.add("Allow", allow)
            return
        self.app.handle(req, res)

    def stream_request(mut self, req: Request) raises -> Bool:
        return self.app.stream_request(req)

    def on_body(mut self, req: Request, data: Span[UInt8, _]) raises:
        self.app.on_body(req, data)

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        return self.app.produce(req, out)

    def take_wakes(mut self) -> List[UInt64]:
        return self.app.take_wakes()

    def shutting_down(mut self):
        self.app.shutting_down()


def _add_unique(mut out: List[String], m: String):
    for x in out:
        if x == m:
            return
    out.append(m)


@inline(.always)
def _same(a: Span[UInt8, _], b: Span[UInt8, _]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True
