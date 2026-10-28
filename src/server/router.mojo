"""Routing (docs/server.md, "Routing"): `Router[A]` sends requests to
functions by method and path pattern, and everything else to the
application `A` itself, a `Handler`: requests no route matches, and every
other hook (admission, streaming, errors, completion, shutdown). A
wrapper of a `Handler` must pass each hook on like this: one it leaves
out falls back to the trait's default without a word.

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
whatever the order routes were added in. Parameters are the decoded
bytes, which must be UTF-8.

**Paths no pattern can take** are answered by the router, so that no
route's checks are skipped by a crafted path (SR2 RTR-1): 400 for a
malformed percent-encoding, a parameter that is not UTF-8, or a segment
that decodes to something with "/" or NUL in it; 404 for more than 128
segments. With `fallback_unroutable` set, the last two go to the
application instead (a proxy that forwards paths as they came). A path
no pattern matches goes to the application.

**Methods.** When the path matches but the method has no route, the
router answers 405 with `Allow`. HEAD uses the GET route (the server drops
the body), and OPTIONS without a route of its own is answered with 204 and
`Allow`.
"""

from http.headers import Headers, is_token

from .server import Exchange, Handler, Request, Response

comptime _MAX_SEGMENTS = 128
"""Deeper paths match nothing (404)."""

comptime NO_ROUTE = -1
"""`Router.find`: no pattern matches (the application answers)."""
comptime NO_METHOD = -2
"""`Router.find`: a pattern matches, not for this method (405)."""
comptime MALFORMED = -3
"""`Router.find`: a malformed percent-encoding, or a parameter that is
not UTF-8 (400)."""
comptime ENCODED_SLASH = -4
"""`Router.find`: a segment decodes to something with "/" or NUL in it
(400)."""
comptime TOO_DEEP = -5
"""`Router.find`: more than 128 segments (404)."""

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
    var fallback_unroutable: Bool
    """Send requests whose paths have a segment that decodes to "/" or
    NUL, or more than 128 segments, to the application rather than
    answering 400 or 404 (the default)."""
    var _bad: Bool
    """The path's percent-encoding is malformed."""
    var _unroutable: Int
    """0, or why no pattern can match the path: NO_ROUTE (not a path: the
    asterisk form), ENCODED_SLASH or TOO_DEEP."""
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
        self.fallback_unroutable = False
        self._bad = False
        self._unroutable = 0
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
        Raises for a method that is not a token, a malformed pattern (a
        text segment with "%", "?" or "#" in it, which no decoded path
        holds; a name used twice in it), a method and pattern added
        before, or a parameter named differently from one at the same
        place in another pattern."""
        if method.byte_length() == 0 or not is_token(method.as_bytes()):
            raise Error("route method is not a token: '", method, "'")
        if not pattern.startswith("/"):
            raise Error("route pattern must start with '/': ", pattern)
        var node = 0
        var names = List[String]()
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
                _new_name(names, name, pattern)
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
                _new_name(names, name, pattern)
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
                for b in seg.as_bytes():
                    if b == 37 or b == 63 or b == 35:  # "%", "?", "#"
                        raise Error("route text no path can match: ", pattern)
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
        self._unroutable = 0
        var t = target.as_bytes()
        var n = len(t)
        var i = 0
        # absolute-form (RFC 9112 3.2.2): skip the scheme and authority
        if n > 0 and t[0] != 47:  # not "/"
            var s = String(target)
            var at = s.find("://")
            if at < 0:
                self._unroutable = NO_ROUTE  # asterisk-form, or not a path
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
                self._unroutable = TOO_DEEP
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
                    if (b == 47 or b == 0) and self._unroutable == 0:
                        self._unroutable = ENCODED_SLASH
                    i += 3
                else:
                    i += 1
                self._path.append(b)
            self._segments.append(_Segment(start, len(self._path) - start))
            if len(self._segments) > _MAX_SEGMENTS:
                self._unroutable = TOO_DEEP
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

    def _fill_params(mut self) -> Bool:
        """Name the parameters of the match just found: False if one is not
        UTF-8 (decoded lossily, distinct paths would give one value: SR2
        RTR-2)."""
        self._params._clear()
        var node = 0
        for k in range(len(self._kinds)):
            var seg = self._values[k]
            var kind = self._kinds[k]
            if kind == _PARAM:
                var s = self._segments[seg]
                self._params._names.append(self._nodes[node].param_name)
                try:
                    self._params._values.append(
                        String(StringSlice(from_utf8=Span(self._path)[s.start : s.start + s.len]))
                    )
                except:
                    self._params._clear()
                    return False
            elif kind == _REST:
                # (the segments lie one after another in `_path`, each
                # "/" between them dropped: one "/" back between each)
                var text = List[UInt8]()
                for j in range(seg, len(self._segments)):
                    if j > seg:
                        text.append(47)
                    var s = self._segments[j]
                    text.extend(Span(self._path)[s.start : s.start + s.len])
                self._params._names.append(self._nodes[node].rest_name)
                try:
                    self._params._values.append(String(StringSlice(from_utf8=Span(text))))
                except:
                    self._params._clear()
                    return False
            node = self._taken[k]
        return True

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
        in `last_params()`; empty for anything else), or NO_ROUTE,
        NO_METHOD, MALFORMED, ENCODED_SLASH or TOO_DEEP."""
        self._params._clear()
        self._split(target)
        if self._bad:
            return MALFORMED
        if self._unroutable != 0:
            return self._unroutable
        self._kinds.clear()
        self._values.clear()
        self._taken.clear()
        var end = self._walk(0, 0, method)
        if end < 0:
            self._kinds.clear()
            self._values.clear()
            self._taken.clear()
            return NO_METHOD if self._walk(0, 0, "") >= 0 else NO_ROUTE
        var r = self._route_at(end, method)
        if r < 0:
            r = self._route_at(end, "GET")  # (HEAD)
        if not self._fill_params():
            return MALFORMED
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
        if (r == ENCODED_SLASH or r == TOO_DEEP) and self.fallback_unroutable:
            r = NO_ROUTE
        if r == MALFORMED or r == ENCODED_SLASH:
            res.text(400, "Bad Request\n")
            return
        if r == TOO_DEEP:
            res.text(404, "Not Found\n")
            return
        if r == NO_METHOD:
            var allow = self._allow()
            if req.method == "OPTIONS":
                res.status = 204
                res.headers.add("Allow", allow)
                return
            res.text(405, "Method Not Allowed\n")
            res.headers.add("Allow", allow)
            return
        self.app.handle(req, res)

    def admit(mut self, req: Request, mut res: Response) raises -> Bool:
        return self.app.admit(req, res)

    def stream_request(mut self, req: Request) raises -> Bool:
        return self.app.stream_request(req)

    def body_limit(mut self, req: Request) -> Int:
        return self.app.body_limit(req)

    def on_body(mut self, req: Request, data: Span[UInt8, _]) raises:
        self.app.on_body(req, data)

    def body_cut(mut self, req: Request):
        self.app.body_cut(req)

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        return self.app.produce(req, out)

    def take_wakes(mut self) -> List[UInt64]:
        return self.app.take_wakes()

    def stream_ended(mut self, req: Request, finished: Bool):
        self.app.stream_ended(req, finished)

    def shutting_down(mut self):
        self.app.shutting_down()

    def failed(mut self, req: Request, error: Error, mut res: Response) raises:
        self.app.failed(req, error, res)

    def completed(mut self, req: Request, done: Exchange):
        self.app.completed(req, done)


def _new_name(mut names: List[String], name: String, pattern: StringSlice) raises:
    """Add `name` to the names of `pattern`'s parameters: raises if it is
    there (`params[name]` would return the first, SR2 RTR-3)."""
    for n in names:
        if n == name:
            raise Error("route parameter named twice: ", pattern)
    names.append(name)


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
