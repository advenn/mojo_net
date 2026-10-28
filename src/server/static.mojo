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
  empty, "." or ".." segment, and no NUL (404); dotfiles (`.env`, `.git/`)
  are 404 too, but for `.well-known`, unless `dotfiles` is set. Hiding
  them is a convenience, not a boundary: a link with another name, or a
  vfat short name (`GIT~1`), still reaches them, so keep secrets out of
  the directory. The kernel then keeps the lookup beneath the directory
  (openat2 with RESOLVE_BENEATH): no symlink out of it either.
- **Only regular files** are served: a path is looked up without being
  opened (O_PATH), and a FIFO, socket or device is a 404 that never runs
  a driver or opens a FIFO's end. A regular file is then opened for
  reading (403 if it cannot be).
- **The directory** is the one `open` found, held open: renaming another
  tree over it, or flipping a symlink to it (a `current -> releases/N`
  deploy), is not seen until the files are opened again. Symlinks inside
  it are followed on every request.
- **Directories** serve their index file (`index.html`), after a 301 to
  the path with a trailing "/" when it has none. There are no listings.
- **Responses** carry Content-Type (from the extension), Content-Length,
  Last-Modified (never later than the response's Date, RFC 9110
  8.8.2.1), an ETag, `Accept-Ranges: bytes`, `X-Content-Type-Options:
  nosniff` (no browser runs a text file as a script) and, when set,
  `cache_control`. The ETag names the size, the modification time and
  (unless `inode_etags` is off) the inode and status-change time; it is
  weak for a file changed within the last second or two.
- **Conditional requests** (RFC 9110 13.2.2, in its order): If-Match
  (strong comparison), else If-Unmodified-Since, failing answer 412; then
  If-None-Match (weak), else If-Modified-Since, answer 304. A list may
  come in several field lines; a date in several is ignored.
- **Ranges** (RFC 9110 14), for GET only: one byte range gets 206 with
  Content-Range, and an unsatisfiable one 416; several ranges, or an
  If-Range that does not match, get the whole file.
- **Changes.** A body is the version its head describes: a file that
  changes between its lookup and its read is looked up again, and one
  that changes or shrinks while it streams ends the connection short of
  its Content-Length, so the client sees an incomplete body rather than
  a mix of two versions.
- **Bodies** up to 64 KiB are read whole. Larger ones are streamed
  (`res.stream()`) in 16 KiB pieces as the client takes them (a slow
  client's download holds about 144 KiB of buffers), which is
  why the application passes `produce` and `stream_ended` on (for the
  requests `owns` says are its). Reads are blocking reads (pread): a file
  that is not in the page cache stalls the loop while the disk reads it.
"""

from std.collections import Dict

from linux import ErrorKind, IoError
from linux.abi import Statx
from linux.errno import Errno
from linux.fd import OwnedFd
from linux.fs import (
    is_dir,
    is_regular,
    open_beneath,
    open_beneath_path,
    open_dir,
    pread,
    same_file,
    stat_fd,
)
from linux.time import NANOS_PER_SEC, unix_time_ns
from http.headers import next_element

from .date import http_date, parse_http_date
from .server import Request, Response

comptime _SMALL = 64 * 1024
"""Files up to this size are read whole."""
comptime _PIECE = 16 * 1024
"""What one `produce` call reads of a larger file. The server asks again
while less than its high-water mark (64 KiB) is queued, so larger pieces
save no syscalls that matter, and each slow client holds its piece's
buffer as long as it downloads (SR2 STA-3: 64 KiB pieces made the
buffers of a slow download 192 KiB; now 144)."""
comptime _CHECK_EVERY = 256 * 1024
"""How often (in bytes read) a streamed file is checked for a change, as
well as after its last piece."""
comptime _TRIES = 3
"""Lookups of a file that changes between its lookup and its read."""


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


def _hex(mut out: String, v: UInt64):
    """`v` in lowercase hex. A negative number goes in as its two's
    complement (`UInt64(Int64)`), so distinct values stay distinct."""
    var digits = "0123456789abcdef".as_bytes()
    var tmp = Array[UInt8, 16](fill=0)
    var n = 0
    var x = v
    while True:
        tmp[15 - n] = digits[Int(x & 15)]
        n += 1
        x >>= 4
        if x == 0:
            break
    out += StringSlice(unsafe_from_utf8=Span(tmp)[16 - n : 16])


def _etag(st: Statx, inode: Bool, weak: Bool) -> String:
    """The entity tag of the version `st` describes: its size and
    modification time, as nginx makes them, plus (`inode`) its inode and
    status-change time, which user space cannot set: a rewrite that keeps
    the size and the modification time (`cp -p`, `rsync -t`, reproducible
    builds with fixed times) still changes the tag (SR2 STA-2)."""
    var out = String("W/\"") if weak else String("\"")
    _hex(out, UInt64(st.size))
    out += "-"
    _hex(out, UInt64(st.mtime_sec))
    out += "."
    _hex(out, UInt64(st.mtime_nsec))
    if inode:
        out += "-"
        _hex(out, st.ino)
        out += "."
        _hex(out, UInt64(st.ctime_sec))
        out += "."
        _hex(out, UInt64(st.ctime_nsec))
    out += "\""
    return out^


def _same_version(a: Statx, b: Statx) -> Bool:
    """`b` describes the file `a` does, unchanged: the same file, size,
    modification and status-change times (any write changes the last)."""
    return (
        same_file(a, b)
        and a.size == b.size
        and a.mtime_sec == b.mtime_sec
        and a.mtime_nsec == b.mtime_nsec
        and a.ctime_sec == b.ctime_sec
        and a.ctime_nsec == b.ctime_nsec
    )


def _safe(path: StringSlice, dotfiles: Bool) -> Bool:
    """No empty, "." or ".." segment and no NUL ("" itself is the root);
    unless `dotfiles`, no segment starting with "." but `.well-known`."""
    if path.byte_length() == 0:
        return True
    for seg in path.split("/"):
        if seg.byte_length() == 0 or seg == "." or seg == "..":
            return False
        if seg.startswith(".") and not dotfiles and not (seg == ".well-known"):
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


def _strong_match(header: StringSlice, etag: StringSlice) -> Bool:
    """If-Match `header` names `etag` (strong comparison: a weak tag never
    matches) or is "*"."""
    var h = header.as_bytes()
    var pos = 0
    while True:
        var e = next_element(h, pos)
        if not e:
            return False
        var b = e.value()
        var item = StringSlice(unsafe_from_utf8=h[b.start : b.end])
        if item == "*" or (not item.startswith("W/") and item == etag):
            return True


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
    var version: Statx
    """The file as the response's head describes it."""
    var offset: Int
    var end: Int
    """Exclusive."""
    var check_at: Int
    """The offset past which the file is checked again."""

    def __init__(out self, var file: OwnedFd, var version: Statx, offset: Int, end: Int):
        self.file = file^
        self.version = version^
        self.offset = offset
        self.end = end
        self.check_at = offset + _CHECK_EVERY


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
    var dotfiles: Bool
    """Serve files and directories whose names start with "." (`.env`,
    `.git/`); `.well-known` is served either way."""
    var inode_etags: Bool
    """ETags name the inode and status-change time too (the default), so
    that every change gives a new tag. Off, they are nginx's (size and
    modification time), the same on replicas that hold copies of one tree
    with its times kept: then a change that keeps both is served stale
    to a client that revalidates (304)."""
    var cache_control: String
    """A Cache-Control value for every file (`no-cache` for pages that
    must be revalidated, `public, max-age=31536000, immutable` for assets
    with hashed names), or empty for none: then caches guess a freshness
    from the file's age (RFC 9111 4.2.2), about a tenth of it."""
    var _transfers: List[Optional[_Transfer]]
    var _free: List[Int]
    var _by_id: Dict[UInt64, Int]

    def __init__(
        out self,
        var root: OwnedFd,
        index: String,
        dotfiles: Bool = False,
        inode_etags: Bool = True,
        cache_control: String = String(),
    ):
        self._root = root^
        self.index = index
        self.dotfiles = dotfiles
        self.inode_etags = inode_etags
        self.cache_control = cache_control
        self._transfers = List[Optional[_Transfer]]()
        self._free = List[Int]()
        self._by_id = Dict[UInt64, Int]()

    @staticmethod
    def open(
        root: StringSlice,
        index: StringSlice = "index.html",
        dotfiles: Bool = False,
        inode_etags: Bool = True,
        cache_control: StringSlice = "",
    ) raises IoError -> StaticFiles:
        """Serve the directory at `root` (`NotFound`, or `InvalidInput` if
        it is not one). Raises `Unsupported` or `PermissionDenied` where
        openat2 is missing (Linux before 5.6) or refused (an old seccomp
        profile), which every request needs: there is no fallback to an
        unconfined open (SR2 STA-6)."""
        var dir = open_dir(root)
        _ = open_beneath_path(dir, ".")
        return StaticFiles(dir^, String(index), dotfiles, inode_etags, String(cache_control))

    def owns(self, req: Request) -> Bool:
        """Whether `req`'s response is a file this streams."""
        return req.id in self._by_id

    def transfers(self) -> Int:
        """Files being streamed now."""
        return len(self._by_id)

    def serve(mut self, req: Request, path: StringSlice, mut res: Response) raises:
        """Answer `req` with the file at `path`, relative to the directory
        and decoded (a route's `*rest` parameter; "" for the directory
        itself). GET and HEAD only (405 otherwise). Raises (so the server
        answers 500) for a file that keeps changing between its lookup and
        its read."""
        if req.method != "GET" and req.method != "HEAD":
            res.text(405, "Method Not Allowed\n")
            res.headers.set("Allow", "GET, HEAD")
            return
        # One trailing "/" names a directory ("sub/"): checked without it.
        var dir_only = path.endswith("/")
        var rel = path[byte = 0 : path.byte_length() - 1] if dir_only else path
        if not _safe(rel, self.dotfiles) or (dir_only and rel.byte_length() == 0):
            res.text(404, "Not Found\n")
            return
        for _ in range(_TRIES):
            if self._serve(req, rel, dir_only, res):
                return
        raise Error("file changed while it was read")

    def _look(self, name: String) raises IoError -> Statx:
        """What `name` is, found without opening it (no device driver
        runs, no FIFO end opens, and a directory needs only search
        permission: SR2 STA-4, STA-5)."""
        return stat_fd(open_beneath_path(self._root, name))

    def _serve(mut self, req: Request, rel: StringSlice, dir_only: Bool, mut res: Response) raises -> Bool:
        """`serve`, once: False if the file changed between its lookup and
        its read (look again)."""
        var name = String(rel) if rel.byte_length() > 0 else String(".")
        var st: Statx
        try:
            st = self._look(name)
        except e:
            self._refuse(e, res)
            return True
        if is_dir(st):
            var p = req.path()
            if not p.endswith("/"):
                var to = String(p, "/")
                var q = req.query()
                if q.byte_length() > 0:
                    to += String("?", q)
                res.text(301, "Moved Permanently\n")
                res.headers.set("Location", to)
                return True
            name = String(self.index) if rel.byte_length() == 0 else String(rel, "/", self.index)
            try:
                st = self._look(name)
            except e:
                self._refuse(e, res)
                return True
        elif dir_only:
            res.text(404, "Not Found\n")  # a file is no directory
            return True
        if not is_regular(st):
            res.text(404, "Not Found\n")
            return True
        # Opened for reading only now that it is known to be a regular
        # file (an unreadable one is 403 whatever the request).
        var file: OwnedFd
        try:
            file = open_beneath(self._root, name)
        except e:
            self._refuse(e, res)
            return True
        var now = req.unix_time if req.unix_time > 0 else Int(unix_time_ns() // NANOS_PER_SEC)
        var size = Int(st.size)
        # Changed in this second or the last: another change within the
        # same clock tick could keep every time and the size, so the ETag is
        # weak and a date matches no If-Range (Apache's rule; SR2 STA-2).
        var fresh = max(Int(st.mtime_sec), Int(st.ctime_sec)) >= now - 1
        var etag = _etag(st, self.inode_etags, fresh)
        # Never later than the response's Date (RFC 9110 8.8.2.1): a future
        # modification time is replaced by it (SR2 STA-11).
        var modified = min(Int(st.mtime_sec), now)
        # Preconditions, in RFC 9110 13.2.2's order: If-Match, else
        # If-Unmodified-Since (412 when they fail)... Lists may come in
        # several field lines (RFC 9110 5.3); a date in several is invalid,
        # ignored (13.1.3, 13.1.4; SR2 STA-8).
        var im = req.headers.combined("if-match")
        var failed = False
        if im:
            failed = not _strong_match(im.value(), etag)
        elif req.headers.count("if-unmodified-since") == 1:
            var before = parse_http_date(String(req.headers.get("if-unmodified-since").value()).strip())
            failed = Bool(before) and modified > before.value()
        if failed:
            self._describe(res, etag, modified)
            res.text(412, "Precondition Failed\n")
            return True
        # ...then If-None-Match, else If-Modified-Since (304)
        var inm = req.headers.combined("if-none-match")
        var not_modified = False
        if inm:
            not_modified = _none_match(inm.value(), etag)
        elif req.headers.count("if-modified-since") == 1:
            var since = parse_http_date(String(req.headers.get("if-modified-since").value()).strip())
            not_modified = Bool(since) and modified <= since.value()
        if not_modified:
            self._describe(res, etag, modified)
            res.status = 304
            return True
        var first = 0
        var last = size - 1
        var partial = False
        # (Range is defined for GET only; in several lines it is several
        # ranges, and the whole file may be sent)
        if req.method == "GET" and req.headers.count("range") == 1:
            var ok = True
            var irs = req.headers.count("if-range")
            if irs > 1:
                ok = False
            elif irs == 1:
                var v = String(req.headers.get("if-range").value()).strip()
                if v.startswith("\"") or v.startswith("W/"):
                    ok = not fresh and v == etag  # strong comparison
                else:
                    var when = parse_http_date(v)
                    ok = not fresh and Bool(when) and when.value() == modified
            var r = _range(req.headers.get("range").value(), size) if ok else Optional[_Range](None)
            if r:
                if r.value().first > r.value().last:
                    self._describe(res, etag, modified)
                    res.text(416, "Range Not Satisfiable\n")
                    res.headers.set("Content-Range", String("bytes */", size))
                    return True
                first = r.value().first
                last = r.value().last
                partial = True
        var length = last - first + 1 if size > 0 else 0
        if length > 0 and req.method == "GET":
            if length <= _SMALL:
                res.body.resize(unsafe_uninit_length=length)
                var got = 0
                while got < length:
                    var n = pread(file, Span(res.body)[got:length], first + got)
                    if n == 0:
                        break  # (shrank since statx)
                    got += n
                # The bytes read are the version described, unchanged (SR2
                # STA-1, STA-9): else look again.
                if got < length or not _same_version(st, stat_fd(file)):
                    res.body.clear()
                    return False
            elif not _same_version(st, stat_fd(file)):
                return False
        else:
            res.body.clear()  # (HEAD, or nothing to send)
        self._describe(res, etag, modified)
        res.status = 206 if partial else 200
        res.headers.set("Content-Type", content_type(name))
        res.headers.set("X-Content-Type-Options", "nosniff")
        if partial:
            res.headers.set("Content-Range", String("bytes ", first, "-", last, "/", size))
        res.headers.set("Content-Length", String(length))
        if length <= _SMALL or req.method != "GET":
            return True
        res.stream()
        var t = _Transfer(file^, st^, first, last + 1)
        var slot: Int
        if len(self._free) > 0:
            slot = self._free.pop()
            self._transfers[slot] = t^
        else:
            slot = len(self._transfers)
            self._transfers.append(t^)
        self._by_id[req.id] = slot
        return True

    def _describe(self, mut res: Response, etag: String, modified: Int) raises:
        """The fields every answer about the file carries (a 304 too, RFC
        9110 15.4.5)."""
        res.headers.set("ETag", etag)
        res.headers.set("Last-Modified", http_date(modified))
        res.headers.set("Accept-Ranges", "bytes")
        if self.cache_control.byte_length() > 0:
            res.headers.set("Cache-Control", self.cache_control)

    def _refuse(self, e: IoError, mut res: Response) raises:
        if e.kind == ErrorKind.PermissionDenied:
            res.text(403, "Forbidden\n")
        elif (
            e.kind == ErrorKind.NotFound
            or e.kind == ErrorKind.InvalidInput  # it would leave the directory
            or e.errno == Errno.ENOTDIR  # a file in the middle of the path
            or e.errno == Errno.ELOOP  # a symlink loop
            or e.errno == Errno.ENXIO  # a socket
            or e.errno == Errno.ENODEV  # a device without a driver
            or e.errno == Errno.ENAMETOOLONG
        ):
            res.text(404, "Not Found\n")
        else:
            raise e

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        """The next piece of the file `req` streams: True while more is to
        come (see `Handler.produce`). Raises, so the connection ends short
        of its Content-Length, if the file shrank or changed since its
        head was sent: a client then sees an incomplete body, never one
        made of two versions under the first one's validators (SR2
        STA-1)."""
        var slot = self._by_id.get(req.id)
        if not slot:
            return False
        var i = slot.value()
        ref t = self._transfers[i].value()
        var want = min(_PIECE, t.end - t.offset)
        var start = len(out)
        out.resize(unsafe_uninit_length=start + want)
        var n: Int
        try:
            n = pread(t.file, Span(out)[start : start + want], t.offset)
        except e:
            out.resize(start, 0)
            self._release(req)
            raise e
        out.resize(start + n, 0)
        if n == 0:
            self._release(req)
            raise Error("file shorter than when it was opened")
        t.offset += n
        var end = t.offset >= t.end
        if end or t.offset >= t.check_at:
            t.check_at = t.offset + _CHECK_EVERY
            if not _same_version(t.version, stat_fd(t.file)):
                out.resize(start, 0)
                self._release(req)
                raise Error("file changed while it was sent")
        if end:
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
