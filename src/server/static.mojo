"""Static files (docs/server.md, "Static files"): `StaticFiles` answers
requests with the files of one directory, from a route, and no path
leaves that directory.

    struct App(Handler):
        var files: StaticFiles

        def handle(mut self, req: Request, mut res: Response) raises:
            res.text(404, "not found\\n")

        def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
            return self.files.produce(req, out)

        def stream_ended(mut self, req: Request, finished: Bool):
            self.files.stream_ended(req)

    def assets(mut app: App, req: Request, params: Params, mut res: Response) raises:
        app.files.serve(req, params["path"], res)

    var router = Router(App(StaticFiles.open("./public")))
    router.get("/assets/*path", assets)

- **Paths.** The path given (a route's decoded rest) is checked first: no
  empty, "." or ".." segment, and no NUL (404). The kernel then keeps the
  open beneath the directory (openat2 with RESOLVE_BENEATH): no symlink
  out of it either. Only regular files are served; a FIFO or a device is
  a 404 (and is opened nonblocking, so it cannot stall the loop).
- **Directories** serve their index file (`index.html`), after a 301 to
  the path with a trailing "/" when it has none. There are no listings.
- **Responses** carry Content-Type (from the extension), Content-Length,
  Last-Modified, an ETag (size and modification time, as nginx makes
  them) and `Accept-Ranges: bytes`.
- **Conditional requests** (RFC 9110 13): If-None-Match, else
  If-Modified-Since, answer 304.
- **Ranges** (RFC 9110 14): one byte range gets 206 with Content-Range,
  and an unsatisfiable one 416; several ranges, or an If-Range that does
  not match, get the whole file.
- **Bodies** up to 64 KiB are read whole. Larger ones are streamed
  (`res.stream()`) in 64 KiB pieces as the client takes them, which is
  why the application passes `produce` and `stream_ended` on (for the
  requests `owns` says are its). Reads are blocking reads (pread): a file
  that is not in the page cache stalls the loop while the disk reads it.
"""

from std.collections import Dict

from linux import ErrorKind, IoError
from linux.fd import OwnedFd
from linux.fs import is_dir, is_regular, open_beneath, open_dir, pread, stat_fd
from http.headers import next_element

from .date import http_date, parse_http_date
from .server import Request, Response

comptime _SMALL = 64 * 1024
"""Files up to this size are read whole."""
comptime _PIECE = 64 * 1024
"""What one `produce` call reads of a larger file."""


def content_type(name: StringSlice) -> StaticString:
    """The media type for a file name's extension (case-insensitive);
    `application/octet-stream` when unknown."""
    var dot = -1
    var b = name.as_bytes()
    for i in range(len(b) - 1, -1, -1):
        if b[i] == 46:  # "."
            dot = i
            break
        if b[i] == 47:  # "/"
            break
    if dot < 0:
        return "application/octet-stream"
    var ext = String(name[byte = dot + 1 :]).lower()
    if ext == "html" or ext == "htm":
        return "text/html; charset=utf-8"
    if ext == "css":
        return "text/css; charset=utf-8"
    if ext == "js" or ext == "mjs":
        return "text/javascript; charset=utf-8"
    if ext == "json" or ext == "map":
        return "application/json"
    if ext == "txt":
        return "text/plain; charset=utf-8"
    if ext == "md":
        return "text/markdown; charset=utf-8"
    if ext == "csv":
        return "text/csv; charset=utf-8"
    if ext == "xml":
        return "application/xml"
    if ext == "svg":
        return "image/svg+xml"
    if ext == "png":
        return "image/png"
    if ext == "jpg" or ext == "jpeg":
        return "image/jpeg"
    if ext == "gif":
        return "image/gif"
    if ext == "webp":
        return "image/webp"
    if ext == "avif":
        return "image/avif"
    if ext == "ico":
        return "image/vnd.microsoft.icon"
    if ext == "wasm":
        return "application/wasm"
    if ext == "woff":
        return "font/woff"
    if ext == "woff2":
        return "font/woff2"
    if ext == "ttf":
        return "font/ttf"
    if ext == "otf":
        return "font/otf"
    if ext == "pdf":
        return "application/pdf"
    if ext == "mp4":
        return "video/mp4"
    if ext == "webm":
        return "video/webm"
    if ext == "mp3":
        return "audio/mpeg"
    if ext == "ogg":
        return "audio/ogg"
    if ext == "wav":
        return "audio/wav"
    if ext == "zip":
        return "application/zip"
    if ext == "gz":
        return "application/gzip"
    if ext == "tar":
        return "application/x-tar"
    return "application/octet-stream"


def _hex(mut out: String, v: Int):
    var digits = "0123456789abcdef"
    if v == 0:
        out += "0"
        return
    var tmp = List[UInt8]()
    var x = v
    while x > 0:
        tmp.append(digits.as_bytes()[x % 16])
        x //= 16
    for i in range(len(tmp) - 1, -1, -1):
        out += chr(Int(tmp[i]))


def _safe(path: StringSlice) -> Bool:
    """No empty, "." or ".." segment and no NUL ("" itself is the root)."""
    if path.byte_length() == 0:
        return True
    for seg in path.split("/"):
        if seg.byte_length() == 0 or seg == "." or seg == "..":
            return False
        for b in seg.as_bytes():
            if b == 0:
                return False
    return True


def _opaque(tag: StringSlice) -> StringSlice[tag.origin]:
    """An entity tag without its weakness prefix (for weak comparison)."""
    if tag.startswith("W/"):
        return tag[byte=2:]
    return tag


def _none_match(header: StringSlice, etag: StringSlice) -> Bool:
    """If-None-Match `header` names `etag` (weak comparison) or is "*"."""
    var h = header.as_bytes()
    var pos = 0
    while True:
        var e = next_element(h, pos)
        if not e:
            return False
        var b = e.value()
        var item = StringSlice(unsafe_from_utf8=h[b.start : b.end])
        if item == "*" or _opaque(item) == _opaque(etag):
            return True


struct _Transfer(Movable):
    var file: OwnedFd
    var offset: Int
    var end: Int
    """Exclusive."""

    def __init__(out self, var file: OwnedFd, offset: Int, end: Int):
        self.file = file^
        self.offset = offset
        self.end = end


@fieldwise_init
struct _Range(TrivialRegisterPassable):
    var first: Int
    var last: Int
    """Inclusive; first > last: no satisfiable range (416)."""


def _range(header: StringSlice, size: Int) -> Optional[_Range]:
    """The one byte range of a Range `header` for a representation of
    `size` bytes, None to send the whole (malformed, several ranges, or
    an empty file), or a first > last range if unsatisfiable."""
    var h = String(header.strip())
    if not h.startswith("bytes=") or size == 0:
        return None
    var spec = String(h[byte=6:].strip())
    if spec.find(",") >= 0:
        return None  # several ranges: the whole file is allowed
    var dash = spec.find("-")
    if dash < 0:
        return None
    var a = String(spec[byte=0:dash].strip())
    var z = String(spec[byte = dash + 1 :].strip())
    for c in a.as_bytes():
        if c < 48 or c > 57:
            return None
    for c in z.as_bytes():
        if c < 48 or c > 57:
            return None
    if a.byte_length() > 18 or z.byte_length() > 18:
        return None  # (no overflow)
    if a.byte_length() == 0:
        if z.byte_length() == 0:
            return None
        var n: Int
        try:
            n = atol(z)
        except:
            return None
        if n == 0:
            return _Range(1, 0)  # a zero suffix: unsatisfiable
        return _Range(max(size - n, 0), size - 1)
    var first: Int
    var last = size - 1
    try:
        first = atol(a)
        if z.byte_length() > 0:
            last = min(atol(z), size - 1)
            if atol(z) < first:
                return None  # invalid: ignored
    except:
        return None
    if first >= size:
        return _Range(1, 0)
    return _Range(first, last)


struct StaticFiles(Movable):
    """The files of one directory, served by `serve` (see the module
    docs)."""

    var _root: OwnedFd
    var index: String
    """The file a directory serves."""
    var _transfers: List[Optional[_Transfer]]
    var _free: List[Int]
    var _by_id: Dict[UInt64, Int]

    def __init__(out self, var root: OwnedFd, index: String):
        self._root = root^
        self.index = index
        self._transfers = List[Optional[_Transfer]]()
        self._free = List[Int]()
        self._by_id = Dict[UInt64, Int]()

    @staticmethod
    def open(root: StringSlice, index: StringSlice = "index.html") raises IoError -> StaticFiles:
        """Serve the directory at `root` (`NotFound`, or `InvalidInput` if
        it is not one)."""
        return StaticFiles(open_dir(root), String(index))

    def owns(self, req: Request) -> Bool:
        """Whether `req`'s response is a file this streams."""
        return req.id in self._by_id

    def transfers(self) -> Int:
        """Files being streamed now."""
        return len(self._by_id)

    def serve(mut self, req: Request, path: StringSlice, mut res: Response) raises:
        """Answer `req` with the file at `path`, relative to the directory
        and decoded (a route's `*rest` parameter; "" for the directory
        itself). GET and HEAD only (405 otherwise)."""
        if req.method != "GET" and req.method != "HEAD":
            res.text(405, "Method Not Allowed\n")
            res.headers.set("Allow", "GET, HEAD")
            return
        # One trailing "/" names a directory ("sub/"): checked without it.
        var dir_only = path.endswith("/")
        var rel = path[byte = 0 : path.byte_length() - 1] if dir_only else path
        if not _safe(rel) or (dir_only and rel.byte_length() == 0):
            res.text(404, "Not Found\n")
            return
        var name = String(rel) if rel.byte_length() > 0 else String(".")
        var file: OwnedFd
        try:
            file = open_beneath(self._root, name)
        except e:
            self._refuse(e, res)
            return
        var st = stat_fd(file)
        if is_dir(st):
            var p = req.path()
            if not p.endswith("/"):
                var to = String(p, "/")
                var q = req.query()
                if q.byte_length() > 0:
                    to += String("?", q)
                res.text(301, "Moved Permanently\n")
                res.headers.set("Location", to)
                return
            name = String(self.index) if rel.byte_length() == 0 else String(rel, "/", self.index)
            try:
                file = open_beneath(self._root, name)
            except e:
                self._refuse(e, res)
                return
            st = stat_fd(file)
        elif dir_only:
            res.text(404, "Not Found\n")  # a file is no directory
            return
        if not is_regular(st):
            res.text(404, "Not Found\n")
            return
        var size = Int(st.size)
        var etag = String("\"")
        _hex(etag, size)
        etag += "-"
        _hex(etag, Int(st.mtime_sec))
        etag += "."
        _hex(etag, Int(st.mtime_nsec))
        etag += "\""
        var modified = Int(st.mtime_sec)
        res.headers.set("ETag", etag)
        res.headers.set("Last-Modified", http_date(modified))
        res.headers.set("Accept-Ranges", "bytes")
        # conditional requests (RFC 9110 13.2.2): If-None-Match first
        var inm = req.headers.get("if-none-match")
        var not_modified = False
        if inm:
            not_modified = _none_match(inm.value(), etag)
        else:
            var ims = req.headers.get("if-modified-since")
            if ims:
                var since = parse_http_date(String(ims.value()).strip())
                not_modified = Bool(since) and modified <= since.value()
        if not_modified:
            res.status = 304
            return
        var first = 0
        var last = size - 1
        var partial = False
        var rh = req.headers.get("range")
        if rh:
            var ok = True
            var ir = req.headers.get("if-range")
            if ir:
                var v = String(ir.value()).strip()
                if v.startswith("\"") or v.startswith("W/"):
                    ok = v == etag  # strong comparison
                else:
                    var when = parse_http_date(v)
                    ok = Bool(when) and when.value() == modified
            var r = _range(rh.value(), size) if ok else Optional[_Range](None)
            if r:
                if r.value().first > r.value().last:
                    res.text(416, "Range Not Satisfiable\n")
                    res.headers.set("Content-Range", String("bytes */", size))
                    return
                first = r.value().first
                last = r.value().last
                partial = True
        var length = last - first + 1 if size > 0 else 0
        res.status = 206 if partial else 200
        res.headers.set("Content-Type", content_type(name))
        if partial:
            res.headers.set("Content-Range", String("bytes ", first, "-", last, "/", size))
        if length <= _SMALL:
            res.body.clear()
            res.body.resize(length, 0)
            var got = 0
            while got < length:
                var n = pread(file, Span(res.body)[got:length], first + got)
                if n == 0:
                    break  # (shrank since statx)
                got += n
            res.body.resize(got, 0)
            return
        res.headers.set("Content-Length", String(length))
        res.stream()
        if req.method == "HEAD":
            return  # (nothing to stream: `stream_ended` comes at once)
        var t = _Transfer(file^, first, last + 1)
        var slot: Int
        if len(self._free) > 0:
            slot = self._free.pop()
            self._transfers[slot] = t^
        else:
            slot = len(self._transfers)
            self._transfers.append(t^)
        self._by_id[req.id] = slot

    def _refuse(self, e: IoError, mut res: Response) raises:
        if e.kind == ErrorKind.PermissionDenied:
            res.text(403, "Forbidden\n")
        elif e.kind == ErrorKind.NotFound or e.kind == ErrorKind.InvalidInput:
            res.text(404, "Not Found\n")  # (InvalidInput: it would leave the directory)
        else:
            raise e

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        """The next piece of the file `req` streams: True while more is to
        come (see `Handler.produce`)."""
        var slot = self._by_id.get(req.id)
        if not slot:
            return False
        var i = slot.value()
        ref t = self._transfers[i].value()
        var want = min(_PIECE, t.end - t.offset)
        var start = len(out)
        out.resize(start + want, 0)
        var n = pread(t.file, Span(out)[start : start + want], t.offset)
        out.resize(start + n, 0)
        if n == 0:
            self._release(req)
            raise Error("file shorter than when it was opened")
        t.offset += n
        if t.offset >= t.end:
            self._release(req)
            return False
        return True

    def stream_ended(mut self, req: Request):
        """Release the file `req` streamed, if any (see
        `Handler.stream_ended`)."""
        self._release(req)

    def _release(mut self, req: Request):
        var slot = self._by_id.pop(req.id, -1)
        if slot >= 0:
            self._transfers[slot] = None  # closes the file
            self._free.append(slot)
