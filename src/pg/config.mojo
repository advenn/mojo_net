"""Connection settings for `pg.client`: where the server is, who connects,
and how long opening a session may take. Built in code, or parsed from a
libpq-style connection URI:

    postgresql://[user[:password]@][host][:port][/database][?name=value&...]

The URI follows libpq ("Connection URIs" in the PostgreSQL documentation):
- the scheme is `postgresql://` or `postgres://`;
- every part is percent-decoded;
- an IPv6 address goes in brackets;
- `host` can be an absolute directory, the Unix socket's
  (`%2Fvar%2Frun%2Fpostgresql`, or `?host=/var/run/postgresql`).

Parameters known here:
- `host`, `port`, `user`, `password`, `dbname`;
- `application_name`;
- `connect_timeout`, in whole seconds (0 means none);
- `options`, the server's command-line switches, such as
  `-c search_path=app`;
- `sslmode`: `disable`, `allow` or `prefer`, which all connect in cleartext
  here. The values that require TLS are refused with `Unsupported`, and so
  is `ssl=true` (libpq's name for `sslmode=require` in JDBC-style URIs);
- `channel_binding`: `disable` or `prefer`; `gssencmode`: `disable`,
  `allow` or `prefer` (`require`: `Unsupported`);
- `client_encoding`: UTF8 only, which the session always uses;
- `require_auth`: comma-separated methods (`password`, `md5`,
  `scram-sha-256`, `none`), or the same list with each method prefixed by
  `!` to exclude it.

Anything else is refused (`InvalidInput`) rather than ignored, and so is a
list of hosts (`Unsupported`), which libpq would try in turn. As in libpq,
a parameter given twice takes its last value, and an empty `host=` means
the default.

What libpq does that is not done here: environment variables (PGHOST and
the others), the password file, and service files.
"""

from linux import ErrorKind, IoError
from linux.time import Duration

from .connection import DEFAULT_MAX_MESSAGE, AuthMethods, Startup

comptime DEFAULT_PORT = 5432
comptime DEFAULT_CONNECT_TIMEOUT = Duration.from_secs(30)
comptime DEFAULT_STATEMENT_CACHE = 256

comptime E_URI = "pg: invalid connection URI"
comptime E_TLS = "pg: TLS is not supported (sslmode, channel_binding)"
comptime E_HOSTS = "pg: a list of hosts is not supported"


struct Config(Copyable, Movable):
    """Where and how to connect (see the module docs)."""

    var host: String
    """A host name or IP address for TCP, or an absolute directory that
    holds the server's Unix socket (`<host>/.s.PGSQL.<port>`)."""
    var port: Int
    var user: String
    var password: String
    var database: String
    """Empty: the server's default, the database named like the user."""
    var application_name: String
    var connect_timeout: Duration
    """For everything up to the open session: name resolution, connecting,
    startup and authentication. `Duration.ZERO`: no limit."""
    var allow: AuthMethods
    """The authentication a server may ask for (libpq's `require_auth`)."""
    var max_message: Int
    var statement_cache: Int
    """How many prepared statements the client keeps per connection (the
    least recently used goes first); 0 for none, as PgBouncer's
    transaction pooling needs."""
    var keepalive: Bool
    """For TCP: keepalive probes and a user timeout, so that a server that
    vanished (power loss, a NAT or load balancer dropping the flow) is
    noticed in about a minute (`net.blocking.detect_dead_peers`). The user
    timeout also ends a session whose server stops reading for a minute
    while the client has data queued for it: a large pipeline or COPY into
    a backend waiting on a lock. Turn it off for such work."""
    var _params: List[String]

    def __init__(
        out self,
        user: String,
        *,
        host: String = "localhost",
        port: Int = DEFAULT_PORT,
        password: String = "",
        database: String = "",
        application_name: String = "",
        connect_timeout: Duration = DEFAULT_CONNECT_TIMEOUT,
        allow: AuthMethods = AuthMethods.ALL,
        max_message: Int = DEFAULT_MAX_MESSAGE,
        statement_cache: Int = DEFAULT_STATEMENT_CACHE,
        keepalive: Bool = True,
    ):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.application_name = application_name
        self.connect_timeout = connect_timeout
        self.allow = allow
        self.max_message = max_message
        self.statement_cache = statement_cache
        self.keepalive = keepalive
        self._params = List[String]()

    def set(mut self, name: String, value: String):
        """A run-time parameter for the session, sent in the startup
        message (see `Startup.set`); a second `set` of the same name
        (in any case) replaces the first."""
        for i in range(0, len(self._params), 2):
            if self._params[i].lower() == name.lower():
                self._params[i + 1] = value
                return
        self._params.append(name)
        self._params.append(value)

    def _has(self, name: StringSlice) -> Bool:
        for i in range(0, len(self._params), 2):
            if self._params[i].lower() == String(name).lower():
                return True
        return False

    def is_unix(self) -> Bool:
        """Whether `host` names a Unix socket directory."""
        return self.host.startswith("/")

    def socket_path(self) -> String:
        """The Unix socket's path, for a `host` that is a directory."""
        return String(self.host, "/.s.PGSQL.", self.port)

    def startup(self) raises IoError -> Startup:
        """The codec's settings for a session with this configuration.

        Three run-time parameters are added unless the caller set them,
        since the client's reading of values depends on them, whatever the
        role or the server would choose: `DateStyle=ISO` (the text of
        dates and timestamps), `extra_float_digits=3` (floats in text keep
        every bit) and `bytea_output=hex`. A DateStyle whose output format
        is not ISO raises `InvalidInput`."""
        for i in range(0, len(self._params), 2):
            if self._params[i].lower() == "datestyle" and not self._params[i + 1].upper().startswith("ISO"):
                raise IoError.of_kind("pg: DateStyle must start with ISO", ErrorKind.InvalidInput)
        var s = Startup(
            self.user,
            database=self.database,
            password=self.password,
            application_name=self.application_name,
            allow=self.allow,
            max_message=self.max_message,
        )
        for i in range(0, len(self._params), 2):
            s.set(self._params[i], self._params[i + 1])
        if not self._has("DateStyle"):
            s.set("DateStyle", "ISO")
        if not self._has("extra_float_digits"):
            s.set("extra_float_digits", "3")
        if not self._has("bytea_output"):
            s.set("bytea_output", "hex")
        return s^

    @staticmethod
    def parse(uri: StringSlice) raises IoError -> Config:
        """A configuration from a connection URI (see the module docs).
        `InvalidInput` for a malformed one or an unknown parameter,
        `Unsupported` for TLS requirements or a list of hosts."""
        var b = uri.as_bytes()
        var start: Int
        if _starts(b, "postgresql://"):
            start = 13
        elif _starts(b, "postgres://"):
            start = 11
        else:
            raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
        var n = len(b)
        var query = _find(b, ord("?"), start, n)
        var end = query if query >= 0 else n
        var slash = _find(b, ord("/"), start, end)
        var authority_end = slash if slash >= 0 else end
        var c = Config("")
        # user[:password]@ (an @ inside them must be percent-encoded)
        var at = _find(b, ord("@"), start, authority_end)
        var host_start = start
        if at >= 0:
            if _find(b, ord("@"), at + 1, authority_end) >= 0:
                raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
            var colon = _find(b, ord(":"), start, at)
            if colon >= 0:
                c.user = _decode(b[start:colon])
                c.password = _decode(b[colon + 1 : at])
            else:
                c.user = _decode(b[start:at])
            host_start = at + 1
        # host[:port], with [IPv6]
        if _find(b, ord(","), host_start, authority_end) >= 0:
            raise IoError.of_kind(E_HOSTS, ErrorKind.Unsupported)
        var host_end = authority_end
        var port_at = -1
        if host_start < authority_end and Int(b[host_start]) == ord("["):
            var close = _find(b, ord("]"), host_start, authority_end)
            if close < 0:
                raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
            c.host = _decode(b[host_start + 1 : close])
            if c.host.byte_length() == 0:  # ("[]": no address)
                raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
            if close + 1 < authority_end:
                if Int(b[close + 1]) != ord(":"):
                    raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
                port_at = close + 2
        else:
            var colon = _find(b, ord(":"), host_start, authority_end)
            if colon >= 0:
                host_end = colon
                port_at = colon + 1
            if host_end > host_start:
                c.host = _decode(b[host_start:host_end])
        if port_at >= 0:
            c.port = _port(b[port_at:authority_end])
        if slash >= 0 and slash + 1 < end:
            c.database = _decode(b[slash + 1 : end])
        if query >= 0:
            var i = query + 1
            while i < n:
                var amp = _find(b, ord("&"), i, n)
                var stop = amp if amp >= 0 else n
                if stop > i:
                    var eq = _find(b, ord("="), i, stop)
                    if eq < 0:
                        raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
                    c._apply(_decode(b[i:eq]), _decode(b[eq + 1 : stop]))
                i = stop + 1
        if c.user.byte_length() == 0:
            raise IoError.of_kind("pg: no user in the connection URI", ErrorKind.InvalidInput)
        return c^

    def _apply(mut self, name: String, value: String) raises IoError:
        if name == "host":
            if value.find(",") >= 0:
                raise IoError.of_kind(E_HOSTS, ErrorKind.Unsupported)
            self.host = value if value.byte_length() > 0 else String("localhost")  # (empty: the default)
        elif name == "port":
            self.port = _port(value.as_bytes())
        elif name == "user":
            self.user = value
        elif name == "password":
            self.password = value
        elif name == "dbname":
            self.database = value
        elif name == "application_name":
            self.application_name = value
        elif name == "connect_timeout":
            var secs = _number(value.as_bytes())
            self.connect_timeout = Duration.from_secs(secs)
        elif name == "options":
            self.set("options", value)
        elif name == "sslmode":
            if not (value == "disable" or value == "allow" or value == "prefer"):
                raise IoError.of_kind(E_TLS, ErrorKind.Unsupported)
        elif name == "channel_binding":
            if not (value == "disable" or value == "prefer"):
                raise IoError.of_kind(E_TLS, ErrorKind.Unsupported)
        elif name == "gssencmode":
            if value == "require":
                raise IoError.of_kind("pg: GSSAPI encryption is not supported", ErrorKind.Unsupported)
            if not (value == "disable" or value == "allow" or value == "prefer"):
                raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
        elif name == "client_encoding":  # (always UTF8 here)
            var v = value.lower()
            if not (v == "utf8" or v == "utf-8" or v == "unicode"):
                raise IoError.of_kind("pg: client_encoding is always UTF8", ErrorKind.Unsupported)
        elif name == "ssl":  # (libpq: ssl=true is sslmode=require, for JDBC URIs)
            if value == "true":
                raise IoError.of_kind(E_TLS, ErrorKind.Unsupported)
            raise IoError.of_kind(E_URI, ErrorKind.InvalidInput)
        elif name == "require_auth":
            self.allow = _require_auth(value)
        elif name == "statement_cache_capacity":  # (pgx's name)
            self.statement_cache = _number(value.as_bytes())
        else:
            raise IoError.of_kind("pg: unknown connection parameter", ErrorKind.InvalidInput)


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


def _require_auth(value: StringSlice) raises IoError -> AuthMethods:
    """libpq's `require_auth`: methods the server may use, or (each with
    "!") the ones it may not."""
    var names = value.split(",")
    var negated = 0
    var bits = AuthMethods(0)
    for i in range(len(names)):
        var given = String(names[i])
        var neg = given.startswith("!")
        if neg:
            negated += 1
        var name = String(given[byte=1:]) if neg else given
        var m: AuthMethods
        if name == "password":
            m = AuthMethods.PASSWORD
        elif name == "md5":
            m = AuthMethods.MD5
        elif name == "scram-sha-256":
            m = AuthMethods.SCRAM_SHA_256
        elif name == "none":
            m = AuthMethods.TRUST
        else:
            raise IoError.of_kind("pg: unknown method in require_auth", ErrorKind.InvalidInput)
        bits = bits | m
    if negated != 0 and negated != len(names):
        raise IoError.of_kind("pg: require_auth mixes methods with !methods", ErrorKind.InvalidInput)
    if negated > 0:
        return AuthMethods(AuthMethods.ALL._bits & ~bits._bits)
    return bits
