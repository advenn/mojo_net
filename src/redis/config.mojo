"""Connection settings for `redis.client`: where the server is, who
connects, and which database and protocol the connection uses. Built in
code, or parsed from a URI, as redis-py and go-redis read them:

    redis://[[user]:password@][host][:port][/database][?name=value&...]
    unix://[[user]:password@]/path/to/socket[?name=value&...]

- Every part is percent-decoded; an IPv6 address goes in brackets.
- A password alone (`redis://:secret@host`, or `redis://secret@host` as
  redis-cli reads it) is the default user's (`requirepass`); with a user
  name, an ACL user's.
- `rediss://` (TLS) is refused (`Unsupported`): `net` has no TLS yet.
- Parameters: `db`, `protocol` (2 or 3), `client_name`, `connect_timeout`
  (whole seconds), and `user` and `password` (for `unix://`, where the
  part before the path is awkward). A parameter given twice takes its last
  value; any other is refused (`InvalidInput`), not ignored.
"""

from linux import ErrorKind, IoError
from linux.time import Duration

from .resp import Limits

comptime DEFAULT_PORT = 6379
comptime DEFAULT_CONNECT_TIMEOUT = Duration.from_secs(10)

comptime E_URI = "redis: malformed URI"


struct Config(Copyable, Movable):
    """Where to connect, and how (see the module docs)."""

    var host: String
    """A name, an address, or (an absolute path) a Unix socket's."""
    var port: Int
    var user: String
    """An ACL user; empty for the default user."""
    var password: String
    """Empty: no authentication."""
    var database: Int
    """The database index SELECTed after connecting (0 needs none)."""
    var client_name: String
    """What CLIENT LIST shows; empty for none."""
    var protocol: Int
    """3: RESP3 (`HELLO 3`; RESP2 when the server has no HELLO). 2: RESP2,
    for proxies that only pass it."""
    var connect_timeout: Duration
    """Bounds `connect`: name resolution, the connection, authentication
    and the setup commands. `Duration.ZERO`: no limit."""
    var keepalive: Bool
    """For TCP: keepalive probes and a user timeout, so that a server that
    vanished is noticed in about a minute (`net.blocking.detect_dead_peers`).
    The user timeout also ends a connection whose server stops reading for
    a minute while the client has data queued for it: a large pipeline
    into a server busy in a long script. Turn it off for such work."""
    var limits: Limits
    """What a reply may hold (`redis.resp.Limits`)."""

    def __init__(
        out self,
        host: String = "localhost",
        *,
        port: Int = DEFAULT_PORT,
        user: String = "",
        password: String = "",
        database: Int = 0,
        client_name: String = "",
        protocol: Int = 3,
        connect_timeout: Duration = DEFAULT_CONNECT_TIMEOUT,
        keepalive: Bool = True,
        limits: Limits = Limits(),
    ):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.client_name = client_name
        self.protocol = protocol
        self.connect_timeout = connect_timeout
        self.keepalive = keepalive
        self.limits = limits

    def is_unix(self) -> Bool:
        """Whether `host` is a Unix socket's path."""
        return self.host.startswith("/")

    def check(self) raises IoError:
        """`InvalidInput` for settings no connection can have: a port out
        of range, a negative database, a protocol other than 2 or 3, a NUL
        in a string, or a user without a password."""
        if not self.is_unix() and (self.port < 1 or self.port > 65535):
            raise IoError.of_kind("redis: invalid port", ErrorKind.InvalidInput)
        if self.database < 0:
            raise IoError.of_kind("redis: invalid database", ErrorKind.InvalidInput)
        if self.protocol != 2 and self.protocol != 3:
            raise IoError.of_kind("redis: the protocol is 2 or 3", ErrorKind.InvalidInput)
        if self.user.byte_length() > 0 and self.password.byte_length() == 0:
            raise IoError.of_kind("redis: a user needs a password", ErrorKind.InvalidInput)
        for s in [self.host, self.user, self.password, self.client_name]:
            for b in s.as_bytes():
                if b == 0:
                    raise IoError.of_kind("redis: NUL byte in a setting", ErrorKind.InvalidInput)
        for b in self.client_name.as_bytes():
            if b == 32 or b < 32 or b == 127:  # (CLIENT SETNAME refuses spaces and controls)
                raise IoError.of_kind("redis: invalid client name", ErrorKind.InvalidInput)

    @staticmethod
    def parse(uri: StringSlice) raises IoError -> Config:
        """A configuration from a URI (see the module docs). `InvalidInput`
        for a malformed one or an unknown parameter, `Unsupported` for
        TLS."""
        var b = uri.as_bytes()
        var c = Config()
        var unix = False
        var start: Int
        if _starts(b, "redis://"):
            start = 8
        elif _starts(b, "unix://"):
            start = 7
            unix = True
        elif _starts(b, "rediss://"):
            raise IoError.of_kind("redis: TLS (rediss://) is not supported", ErrorKind.Unsupported)
        else:
            raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
        var n = len(b)
        var query = _find(b, ord("?"), start, n)
        var end = query if query >= 0 else n
        # [user[:password]@] (an @ inside them must be percent-encoded)
        var limit = end
        if not unix:
            var slash = _find(b, ord("/"), start, end)
            limit = slash if slash >= 0 else end
        var at = _find(b, ord("@"), start, limit)
        if unix:  # (the path follows the @, and may hold one itself)
            var slash = _find(b, ord("/"), start, end)
            if at >= 0 and slash >= 0 and slash < at:
                at = -1
        var rest = start
        if at >= 0:
            if not unix and _find(b, ord("@"), at + 1, limit) >= 0:
                raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
            var colon = _find(b, ord(":"), start, at)
            if colon >= 0:
                c.user = _decode(b[start:colon])
                c.password = _decode(b[colon + 1 : at])
            else:
                c.password = _decode(b[start:at])  # (a password alone, as redis-cli reads it)
            rest = at + 1
        if unix:
            c.host = _decode(b[rest:end])
            if not c.host.startswith("/"):
                raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
        else:
            var slash = _find(b, ord("/"), rest, end)
            var authority_end = slash if slash >= 0 else end
            var port_at = -1
            if rest < authority_end and Int(b[rest]) == ord("["):
                var close = _find(b, ord("]"), rest, authority_end)
                if close < 0:
                    raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
                c.host = _decode(b[rest + 1 : close])
                if c.host.byte_length() == 0:
                    raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
                if close + 1 < authority_end:
                    if Int(b[close + 1]) != ord(":"):
                        raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
                    port_at = close + 2
            else:
                var colon = _find(b, ord(":"), rest, authority_end)
                var host_end = colon if colon >= 0 else authority_end
                if colon >= 0:
                    port_at = colon + 1
                if host_end > rest:
                    c.host = _decode(b[rest:host_end])
            if port_at >= 0:
                c.port = _port(b[port_at:authority_end])
            if slash >= 0 and slash + 1 < end:
                c.database = _number(b[slash + 1 : end])
        if query >= 0:
            var i = query + 1
            while i < n:
                var amp = _find(b, ord("&"), i, n)
                var stop = amp if amp >= 0 else n
                if stop > i:
                    var eq = _find(b, ord("="), i, stop)
                    if eq < 0:
                        raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
                    c._apply(_decode(b[i:eq]), b[eq + 1 : stop])
                i = stop + 1
        return c^

    def _apply(mut self, name: String, raw: Span[UInt8, _]) raises IoError:
        if name == "db":
            self.database = _number(raw)
        elif name == "protocol":
            self.protocol = _number(raw)
            if self.protocol != 2 and self.protocol != 3:
                raise IoError.of_kind("redis: the protocol is 2 or 3", ErrorKind.InvalidInput)
        elif name == "client_name":
            self.client_name = _decode(raw)
        elif name == "connect_timeout":
            self.connect_timeout = Duration.from_secs(_number(raw))
        elif name == "user":
            self.user = _decode(raw)
        elif name == "password":
            self.password = _decode(raw)
        else:
            raise IoError.of_kind("redis: unknown URI parameter", ErrorKind.InvalidInput)


def _starts(b: Span[UInt8, _], prefix: StringSlice) -> Bool:
    var p = prefix.as_bytes()
    if len(b) < len(p):
        return False
    for i in range(len(p)):
        if b[i] != p[i]:
            return False
    return True


def _find(b: Span[UInt8, _], c: Int, start: Int, end: Int) -> Int:
    for i in range(start, end):
        if Int(b[i]) == c:
            return i
    return -1


def _hex_value(c: UInt8) -> Int:
    if c >= 48 and c <= 57:
        return Int(c) - 48
    if c >= 65 and c <= 70:
        return Int(c) - 55
    if c >= 97 and c <= 102:
        return Int(c) - 87
    return -1


def _decode(b: Span[UInt8, _]) raises IoError -> String:
    """Percent-decoded, as UTF-8 (`InvalidInput` for a bad escape, invalid
    UTF-8 or a NUL)."""
    var out = List[UInt8](capacity=len(b))
    var i = 0
    while i < len(b):
        if Int(b[i]) == ord("%"):
            if i + 2 >= len(b):
                raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
            var hi = _hex_value(b[i + 1])
            var lo = _hex_value(b[i + 2])
            if hi < 0 or lo < 0:
                raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
            out.append(UInt8(hi * 16 + lo))
            i += 3
        else:
            out.append(b[i])
            i += 1
    for x in out:
        if x == 0:
            raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
    try:
        return String(from_utf8=Span(out))
    except:
        raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)


def _number(b: Span[UInt8, _]) raises IoError -> Int:
    """A decimal number of at most 9 digits."""
    if len(b) == 0 or len(b) > 9:
        raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
    var n = 0
    for c in b:
        if c < 48 or c > 57:
            raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
        n = n * 10 + Int(c) - 48
    return n


def _port(b: Span[UInt8, _]) raises IoError -> Int:
    var p = _number(b)
    if p < 1 or p > 65535:
        raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
    return p
