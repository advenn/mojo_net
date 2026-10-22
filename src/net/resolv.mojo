"""Local resolver configuration, read the way glibc reads it:
`/etc/resolv.conf` (`ResolvConf`), `/etc/hosts` (`Hosts`), and the list of
names a lookup tries for a host (`search_names`). Parsing never fails:
like glibc, it skips what it does not understand.

resolv.conf (resolv.conf(5)):
- `nameserver ADDR`: an IPv4 or IPv6 address (port 53; an IPv6 zone such
  as `fe80::1%eth0` is allowed). Only the first `MAX_NAMESERVERS` (3)
  count. With none, 127.0.0.1 and ::1 are used, as glibc and Go do.
- `search D1 D2 ...` and `domain D`: the search list; the last such line
  wins. Without one, the domain part of the host name (what follows its
  first `.`) is used, if it has one. At most `MAX_SEARCH` domains count.
- `options`: `ndots:N` (0..15, default 1), `timeout:N` seconds per query
  (1..30, default 5), `attempts:N` rounds over the servers (1..5, default
  2), `rotate`, `edns0`, `use-vc` (TCP only). Values out of range are
  clamped. Other options (`single-request`, `trust-ad`, ...) are ignored:
  lookups already use a separate socket per query type, which is what
  `single-request-reopen` works around.
- Lines starting with `#` or `;` are comments. The LOCALDOMAIN and
  RES_OPTIONS environment overrides are not read.

hosts (hosts(5)): `ADDR NAME [ALIASES...]`; `#` starts a comment anywhere
on a line; names compare ignoring ASCII case; lines with an address that
does not parse are skipped. A name's addresses keep file order. Only
`files` then `dns` is implemented (no other NSS sources: `myhostname`,
`mdns`, ...).
"""

from std.collections import Dict

from linux import ErrorKind, IoError
from linux.fs import read_file
from linux.probe import uname, uts_string
from linux.time import Duration

from .addr import IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6
from .dns import is_valid_name

comptime DNS_PORT: UInt16 = 53
comptime MAX_NAMESERVERS = 3
comptime MAX_SEARCH = 32
comptime DEFAULT_NDOTS = 1
comptime MAX_NDOTS = 15
comptime DEFAULT_TIMEOUT_SECS = 5
comptime MAX_TIMEOUT_SECS = 30
comptime DEFAULT_ATTEMPTS = 2
comptime MAX_ATTEMPTS = 5

comptime RESOLV_CONF = "/etc/resolv.conf"
comptime HOSTS = "/etc/hosts"


# ---- text helpers ------------------------------------------------------------


@inline(.always)
def _is_space(b: UInt8) -> Bool:
    return b == 32 or b == 9 or b == 13 or b == 11 or b == 12


def _fields(line: Span[UInt8, _]) -> List[String]:
    """Whitespace-separated fields of one line."""
    var out = List[String]()
    var i = 0
    var n = len(line)
    while i < n:
        while i < n and _is_space(line[i]):
            i += 1
        var start = i
        while i < n and not _is_space(line[i]):
            i += 1
        if i > start:
            out.append(String(from_utf8_lossy=line[start:i]))
    return out^


def _lines(text: Span[UInt8, _]) -> List[Tuple[Int, Int]]:
    """(start, end) of each `\\n`-separated line."""
    var out = List[Tuple[Int, Int]]()
    var start = 0
    for i in range(len(text)):
        if text[i] == 10:
            out.append((start, i))
            start = i + 1
    if start < len(text):
        out.append((start, len(text)))
    return out^


def _lower_name(name: StringSlice) -> String:
    """ASCII-lowercased, without one trailing `.`."""
    var b = name.as_bytes()
    var n = len(b)
    if n > 0 and b[n - 1] == 46:
        n -= 1
    var out = List[UInt8](capacity=n)
    for i in range(n):
        var c = b[i]
        out.append(c + 32 if c >= 65 and c <= 90 else c)
    return String(from_utf8_lossy=Span(out))


def _parse_int(s: StringSlice) -> Optional[Int]:
    """A non-negative decimal of at most 6 digits."""
    var b = s.as_bytes()
    if len(b) == 0 or len(b) > 6:
        return None
    var v = 0
    for c in b:
        if c < 48 or c > 57:
            return None
        v = v * 10 + Int(c - 48)
    return v


def _clamp(v: Int, lo: Int, hi: Int) -> Int:
    return max(lo, min(v, hi))


# ---- resolv.conf -------------------------------------------------------------


struct ResolvConf(Copyable, Movable):
    """What `/etc/resolv.conf` says (see the module docs). Build one by hand
    to point a resolver elsewhere (tests use a local server on a high
    port)."""

    var nameservers: List[SocketAddr]
    var search: List[String]
    """Domains, lowercase, without trailing dots."""
    var ndots: Int
    var timeout: Duration
    """Per query and server; each attempt waits this long."""
    var attempts: Int
    var rotate: Bool
    var edns0: Bool
    var use_tcp: Bool

    def __init__(out self):
        """The defaults, with no nameservers yet."""
        self.nameservers = List[SocketAddr]()
        self.search = List[String]()
        self.ndots = DEFAULT_NDOTS
        self.timeout = Duration.from_secs(DEFAULT_TIMEOUT_SECS)
        self.attempts = DEFAULT_ATTEMPTS
        self.rotate = False
        self.edns0 = False
        self.use_tcp = False

    @staticmethod
    def parse(text: StringSlice, hostname: StringSlice = "") -> ResolvConf:
        """Parse resolv.conf text. `hostname` supplies the default search
        domain when the text has no `search` or `domain` line."""
        var conf = ResolvConf()
        var have_search = False
        var b = text.as_bytes()
        for se in _lines(b):
            var line = b[se[0] : se[1]]
            if len(line) == 0 or line[0] == 35 or line[0] == 59:
                continue
            var f = _fields(line)
            if len(f) == 0:
                continue
            if f[0] == "nameserver" and len(f) > 1:
                if len(conf.nameservers) < MAX_NAMESERVERS:
                    var ns = _nameserver(f[1])
                    if ns:
                        conf.nameservers.append(ns.value())
            elif (f[0] == "search" or f[0] == "domain") and len(f) > 1:
                have_search = True
                conf.search.clear()
                var last = len(f) if f[0] == "search" else 2
                for i in range(1, last):
                    var d = _lower_name(f[i])
                    if is_valid_name(d) and len(conf.search) < MAX_SEARCH:
                        conf.search.append(d^)
            elif f[0] == "options":
                for i in range(1, len(f)):
                    conf._option(f[i])
        if len(conf.nameservers) == 0:
            conf.nameservers.append(
                SocketAddr(IpAddr(Ipv4Addr(127, 0, 0, 1)), DNS_PORT)
            )
            conf.nameservers.append(
                SocketAddr(IpAddr(Ipv6Addr.from_bits(1)), DNS_PORT)
            )
        if not have_search:
            var h = hostname.as_bytes()
            for i in range(len(h)):
                if h[i] == 46:
                    var d = _lower_name(String(from_utf8_lossy=h[i + 1 :]))
                    if is_valid_name(d):
                        conf.search.append(d^)
                    break
        return conf^

    @staticmethod
    def load(path: StringSlice = RESOLV_CONF) raises IoError -> ResolvConf:
        """Read and parse `path`; a missing file gives the defaults (local
        nameservers). The host name comes from uname(2)."""
        var host = String()
        try:
            host = uts_string(uname().nodename)
        except:
            pass
        var text: List[UInt8]
        try:
            text = read_file(path, "read(resolv.conf)")
        except e:
            if e.kind != ErrorKind.NotFound:
                raise e
            return ResolvConf.parse("", host)
        return ResolvConf.parse(String(from_utf8_lossy=Span(text)), host)

    def _option(mut self, opt: StringSlice):
        var b = opt.as_bytes()
        var colon = -1
        for i in range(len(b)):
            if b[i] == 58:
                colon = i
                break
        if colon < 0:
            if opt == "rotate":
                self.rotate = True
            elif opt == "edns0":
                self.edns0 = True
            elif opt == "use-vc" or opt == "usevc" or opt == "tcp":
                self.use_tcp = True
            return
        var key = String(from_utf8_lossy=b[:colon])
        var v = _parse_int(String(from_utf8_lossy=b[colon + 1 :]))
        if not v:
            return
        if key == "ndots":
            self.ndots = _clamp(v.value(), 0, MAX_NDOTS)
        elif key == "timeout":
            self.timeout = Duration.from_secs(
                _clamp(v.value(), 1, MAX_TIMEOUT_SECS)
            )
        elif key == "attempts":
            self.attempts = _clamp(v.value(), 1, MAX_ATTEMPTS)


def _nameserver(text: StringSlice) -> Optional[SocketAddr]:
    """An address on port 53, or None. An IPv6 zone (`%eth0`) is kept as
    the scope id."""
    try:
        return SocketAddr(IpAddr.parse(text), DNS_PORT)
    except:
        pass
    try:
        return SocketAddr(
            SocketAddrV6.parse(String("[", text, "]:53"), resolve_zone=True)
        )
    except:
        return None


# ---- hosts -------------------------------------------------------------------


struct Hosts(Copyable, Movable, Sized):
    """The name-to-address table of a hosts file."""

    var _table: Dict[String, List[IpAddr]]

    def __init__(out self):
        self._table = Dict[String, List[IpAddr]]()

    @staticmethod
    def parse(text: StringSlice) -> Hosts:
        var hosts = Hosts()
        var b = text.as_bytes()
        for se in _lines(b):
            var end = se[1]
            for i in range(se[0], se[1]):
                if b[i] == 35:  # '#' starts a comment anywhere
                    end = i
                    break
            var f = _fields(b[se[0] : end])
            if len(f) < 2:
                continue
            var ip: IpAddr
            try:
                ip = IpAddr.parse(f[0])
            except:
                continue
            for i in range(1, len(f)):
                var name = _lower_name(f[i])
                if name.byte_length() == 0:
                    continue
                var known = hosts._table.get(name)
                var addrs = known.take() if known else List[IpAddr]()
                addrs.append(ip)
                hosts._table[name^] = addrs^
        return hosts^

    @staticmethod
    def load(path: StringSlice = HOSTS) raises IoError -> Hosts:
        """Read and parse `path`; a missing file is an empty table."""
        try:
            var text = read_file(path, "read(hosts)")
            return Hosts.parse(String(from_utf8_lossy=Span(text)))
        except e:
            if e.kind != ErrorKind.NotFound:
                raise e
            return Hosts()

    def lookup(self, name: StringSlice) -> List[IpAddr]:
        """The addresses for `name` (any case, one trailing `.` allowed),
        in file order; empty if it is not listed."""
        var found = self._table.get(_lower_name(name))
        if found:
            return found.take()
        return List[IpAddr]()

    def __len__(self) -> Int:
        """How many names are listed."""
        return len(self._table)


# ---- search list -------------------------------------------------------------


def search_names(name: StringSlice, conf: ResolvConf) -> List[String]:
    """The names a lookup of `name` tries, in order (resolv.conf(5)):
    - a name ending in `.` is absolute: only itself;
    - with at least `ndots` dots, the name itself first, then with each
      search domain appended;
    - with fewer, the search domains first, then the name itself.
    Candidates that are not valid DNS names (too long, ...) are left out."""
    var out = List[String]()
    var b = name.as_bytes()
    if len(b) > 0 and b[len(b) - 1] == 46:
        var bare = _lower_name(name)
        if is_valid_name(bare):
            out.append(bare^)
        return out^
    var bare = _lower_name(name)
    var dots = 0
    for c in b:
        if c == 46:
            dots += 1
    var suffixed = List[String]()
    for d in conf.search:
        var cand = String(bare, ".", d)
        if is_valid_name(cand):
            suffixed.append(cand^)
    var itself_ok = is_valid_name(bare)
    if dots >= conf.ndots:
        if itself_ok:
            out.append(bare.copy())
        for s in suffixed:
            out.append(s.copy())
    else:
        for s in suffixed:
            out.append(s.copy())
        if itself_ok:
            out.append(bare.copy())
    return out^
