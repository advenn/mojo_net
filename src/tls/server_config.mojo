"""Server configuration: `ServerConfig` builds an immutable `ServerContext`
(one OpenSSL `SSL_CTX`), shared by every connection accepted with it
(docs/tls.md; rules TS1-TS6, TS12 and TS14 of
docs/research/tls_with_openssl.md).

**Policy**, set explicitly and read back as a client's is (`tls.config`):
TLS 1.2 or later, Mozilla's intermediate profile, the same key exchange
groups (none finite-field: TS2), security level 2, no compression, no
renegotiation. And for a server: no session tickets and no session cache,
so no resumption (TS4: `SSL_OP_NO_TICKET` with no tickets issued, never
the option alone); no early data (TS14); no client certificates; exactly
the chain configured is sent (`SSL_MODE_NO_AUTO_CHAIN`, TS3). The one knob
makes it stricter: `tls13_only` (Mozilla's modern profile, TD7).

**Credentials** (TS3): a PEM chain, the leaf first, and an unencrypted
PEM key, both read by libssl at build. The key file must be the user's
and readable by nobody else (mode 0600 or 0400), or root's and at most
readable by its group (0640), as PostgreSQL requires. An encrypted key is
refused, never prompted for. The build also fails, saying why, if the key
does not match the leaf, the leaf has expired or is not valid yet, or it
does not cover every name in `names`. The certificate type sets the
handshake's cost: an ECDSA P-256 leaf signs some 15 times faster than an
RSA 2048 one (docs/research/tls_with_openssl.md).

**Names** (TS6): the DNS names and IP addresses the server answers for.
A client that sends SNI must ask for one of the DNS names, or its
connection fails when the handshake ends; a client connecting by IP
address sends no SNI and is served. Names are exact: a wildcard
certificate serves the names listed.

**ALPN** (TS5): the protocols the server speaks, in its preference order.
A client that offers ALPN without one of them gets a fatal
no_application_protocol alert, which RFC 9325 asks for against
cross-protocol attacks (ALPACA); a client that offers none is served. An
empty list refuses every client that offers ALPN.

**Reloading** (TS12): build a new context from the files and use it for
new connections; each connection keeps the context it began with. A
failed build leaves the old one to serve. `renewal_due()` says when less
than a third of the leaf's lifetime is left.
"""

from std.memory import ArcPointer
from std.os.path import exists

from linux import ErrorKind, IoError
from linux.abi import Statx
from linux.fs import is_regular, stat_path
from linux.nr import SYS_geteuid
from linux.syscall import syscall0

from .config import HOST_FLAGS, _check, _configure, _cs, alpn_wire
from .consts import SSL_FILETYPE_PEM
from .error import Category, TlsError, tls_error
from .ffi import (
    SEAM_CHAIN,
    SEAM_CTX_NEW,
    SEAM_KEY,
    SEAM_KEY_MATCH,
    SEAM_LEAF,
    SEAM_TIME,
    Library,
    Obj,
    alpn_select,
    buf,
    i32_out,
    in_buf,
    seam,
)
from .target import Target


struct ServerConfig(Copyable, Movable):
    """What a TLS server presents and accepts. `build()` makes the context."""

    var certificate: String
    """The PEM chain file: the leaf, then the intermediates (no root)."""
    var key: String
    """The PEM private key file (unencrypted; see the module docs for its
    permissions)."""
    var names: List[String]
    """The DNS names and IP addresses served: the leaf must cover each,
    and a client's SNI must be one of the DNS names."""
    var alpn: List[String]
    """Application protocols, in preference order."""
    var tls13_only: Bool
    """Refuse TLS 1.2 (Mozilla's modern profile)."""

    def __init__(
        out self,
        *,
        certificate: String,
        key: String,
        var names: List[String],
        var alpn: List[String] = List[String](),
        tls13_only: Bool = False,
    ):
        self.certificate = certificate
        self.key = key
        self.names = names^
        self.alpn = alpn^
        self.tls13_only = tls13_only

    def build(self) raises TlsError -> ServerContext:
        """Load OpenSSL, make and configure an `SSL_CTX` with the
        credentials, and refuse it if any setting did not take or any
        check fails."""
        var lib: ArcPointer[Library]
        try:
            lib = Library.load()
        except e:
            raise TlsError(e, Category.LIBRARY, "")
        return ServerContext(_ServerContext(lib, self))


struct _ServerContext(Movable):
    var lib: ArcPointer[Library]
    var ctx: Obj
    var names: List[String]
    """Normalized (`tls.target`)."""
    var dns: List[String]
    """The DNS names among them: what SNI may ask for."""
    var alpn: List[String]
    var prefs: List[UInt8]
    """The ALPN callback's argument: the wire list's length (two bytes,
    big-endian), then the list. Never changed: libssl holds its address."""
    var passwd: List[UInt8]
    """An empty C string: libssl's default password, so that an encrypted
    key fails to load instead of prompting on the terminal."""
    var certificate: String
    var key: String
    var lifetime: Int
    """The leaf's validity period, in seconds."""
    var tls13_only: Bool
    """For the gate, which checks the version again (OpenSSL's minimum
    is the first layer)."""

    def __init__(out self, lib: ArcPointer[Library], config: ServerConfig) raises TlsError:
        ref L = lib[]
        if len(config.names) == 0:
            raise tls_error("tls: a server needs at least one name", ErrorKind.InvalidInput, Category.INPUT)
        var targets = List[Target]()
        var names = List[String]()
        var dns = List[String]()
        for n in config.names:
            try:
                targets.append(Target(n))
            except e:
                raise TlsError(e, Category.INPUT, n)
            names.append(targets[len(targets) - 1].name)
            if not targets[len(targets) - 1].is_ip:
                dns.append(targets[len(targets) - 1].name)
        var wire = alpn_wire(config.alpn)
        if len(wire) > 65535:
            raise tls_error("tls: the ALPN list is too long", ErrorKind.InvalidInput, Category.INPUT)
        var prefs = List[UInt8](capacity=len(wire) + 2)
        prefs.append(UInt8(len(wire) >> 8))
        prefs.append(UInt8(len(wire) & 0xFF))
        prefs.extend(Span(wire))
        if config.certificate.byte_length() == 0 or config.key.byte_length() == 0:
            raise tls_error("tls: a server needs a certificate file and a key file", ErrorKind.InvalidInput, Category.INPUT)
        _check_key_file(config.key)
        var passwd = List[UInt8](length=1, fill=0)
        L.ERR_clear_error()
        var ctx = L.SSL_CTX_new_ex(L.libctx, 0, L.TLS_server_method())
        if seam(SEAM_CTX_NEW) != 0 and ctx != 0:
            L.SSL_CTX_free(ctx)
            ctx = 0
        if ctx == 0:
            raise tls_error("tls: SSL_CTX_new_ex failed", ErrorKind.OutOfMemory, Category.LIBRARY, L.drain_errors())
        # Configured before `self` holds it, and freed here on any failure
        # (Mojo 1.2 skips `__deinit__` when `__init__` raises early).
        var lifetime: Int
        try:
            _configure(L, ctx, server=True, tls13_only=config.tls13_only)
            L.SSL_CTX_set_default_passwd_cb_userdata(ctx, buf(passwd))
            _load_credentials(L, ctx, config.certificate, config.key)
            lifetime = _check_leaf(L, ctx, targets)
            L.SSL_CTX_set_alpn_select_cb(ctx, alpn_select, Int(prefs.unsafe_ptr()))
            var left = L.drain_errors()
            if left.byte_length() > 0:
                raise tls_error("tls: OpenSSL reported an error while configuring", ErrorKind.Other, Category.LIBRARY, left)
        except e:
            L.SSL_CTX_free(ctx)
            raise e^
        self.lib = lib
        self.ctx = ctx
        self.names = names^
        self.dns = dns^
        self.alpn = config.alpn.copy()
        self.prefs = prefs^
        self.passwd = passwd^
        self.certificate = config.certificate
        self.key = config.key
        self.lifetime = lifetime
        self.tls13_only = config.tls13_only

    def __deinit__(deinit self):
        if self.ctx != 0:
            self.lib[].SSL_CTX_free(self.ctx)


struct ServerContext(Copyable, Movable, Writable):
    """A built server configuration (one `SSL_CTX`, never changed again:
    TB3). Copies share it; each connection keeps it alive."""

    var _inner: ArcPointer[_ServerContext]

    def __init__(out self, var inner: _ServerContext):
        self._inner = ArcPointer(inner^)

    def _library(self) -> ArcPointer[Library]:
        """For `tls.server` only (see `ClientContext._library`)."""
        return self._inner[].lib

    def _ssl_ctx(self) -> Obj:
        return self._inner[].ctx

    def _tls13_only(self) -> Bool:
        return self._inner[].tls13_only

    def _serves(self, name: String) -> Bool:
        """Whether `name` (normalized) is one of the DNS names."""
        for n in self._inner[].dns:
            if n == name:
                return True
        return False

    def names(self) -> List[String]:
        return self._inner[].names.copy()

    def alpn(self) -> List[String]:
        return self._inner[].alpn.copy()

    def certificate(self) -> String:
        """The chain file it was built from."""
        return self._inner[].certificate

    def lifetime(self) -> Int:
        """The leaf's validity period, in seconds."""
        return self._inner[].lifetime

    def expires_in(self) raises TlsError -> Int:
        """Seconds until the leaf expires (negative once it has)."""
        ref L = self._inner[].lib[]
        var leaf = L.SSL_CTX_get0_certificate(self._inner[].ctx)
        if leaf == 0:
            raise tls_error("tls: the context holds no certificate", ErrorKind.Other, Category.LIBRARY)
        return _seconds(L, 0, L.X509_get0_notAfter(leaf))

    def renewal_due(self) raises TlsError -> Bool:
        """Less than a third of the leaf's lifetime is left (TS12's alarm:
        renew, then reload)."""
        return self.expires_in() * 3 < self.lifetime()

    def write_to(self, mut writer: Some[Writer]):
        ref L = self._inner[].lib[]
        writer.write(L.version, " (", L.path, "), certificate: ", self._inner[].certificate, ", names:")
        for n in self._inner[].names:
            writer.write(" ", n)


def _octal(mode: Int) -> String:
    return String(chr(48 + ((mode >> 6) & 7)), chr(48 + ((mode >> 3) & 7)), chr(48 + (mode & 7)))


def _check_key_file(path: String) raises TlsError:
    """TS3: a regular file, readable by its owner (this user, or root and
    its group) and nobody else."""
    var st: Statx
    try:
        st = stat_path(path)
    except e:
        raise TlsError(e, Category.CREDENTIALS, path)
    if not is_regular(st):
        raise tls_error("tls: the key is not a regular file", ErrorKind.InvalidInput, Category.CREDENTIALS, path)
    var mode = Int(st.mode) & 0o777
    var owner = Int(st.uid)
    var allowed: Int
    if owner == 0:
        allowed = 0o640  # root's: its group may read
    elif owner == syscall0(SYS_geteuid):
        allowed = 0o600
    else:
        raise tls_error(
            "tls: the key file belongs to another user", ErrorKind.PermissionDenied, Category.CREDENTIALS, String(path, " (owner ", owner, ")")
        )
    if mode & ~allowed != 0:
        raise tls_error(
            "tls: other users can read or change the key file (chmod 600 it)",
            ErrorKind.PermissionDenied,
            Category.CREDENTIALS,
            String(path, " (mode ", _octal(mode), ")"),
        )


def _load_credentials(L: Library, ctx: Obj, certificate: String, key: String) raises TlsError:
    """The chain, then the key, then the check that they match (TS3)."""
    if not exists(certificate):
        raise tls_error("tls: the certificate file does not exist", ErrorKind.NotFound, Category.CREDENTIALS, certificate)
    var c = _cs(certificate, "tls: certificate file path")
    var ok = L.SSL_CTX_use_certificate_chain_file(ctx, buf(c)) == 1 and seam(SEAM_CHAIN) == 0
    _ = c^
    if not ok:
        raise tls_error("tls: the certificate chain did not load", ErrorKind.InvalidData, Category.CREDENTIALS, certificate + ": " + L.drain_errors())
    var k = _cs(key, "tls: key file path")
    ok = L.SSL_CTX_use_PrivateKey_file(ctx, buf(k), SSL_FILETYPE_PEM) == 1 and seam(SEAM_KEY) == 0
    _ = k^
    if not ok:
        raise tls_error(
            "tls: the private key did not load (not a key, a key that does not match the certificate, or an encrypted key, which is not supported)",
            ErrorKind.InvalidData,
            Category.CREDENTIALS,
            key + ": " + L.drain_errors(),
        )
    if L.SSL_CTX_check_private_key(ctx) != 1 or seam(SEAM_KEY_MATCH) != 0:
        raise tls_error("tls: the private key does not match the certificate", ErrorKind.InvalidData, Category.CREDENTIALS, key + ": " + L.drain_errors())


def _seconds(L: Library, start: Obj, end: Obj) raises TlsError -> Int:
    """`end` - `start` in seconds (`start` 0: now)."""
    var days = List[Int32](length=1, fill=0)
    var secs = List[Int32](length=1, fill=0)
    if L.ASN1_TIME_diff(i32_out(days), i32_out(secs), start, end) != 1 or seam(SEAM_TIME) != 0:
        raise tls_error("tls: reading the certificate's validity failed", ErrorKind.Other, Category.LIBRARY, L.drain_errors())
    return Int(days[0]) * 86400 + Int(secs[0])


def _check_leaf(L: Library, ctx: Obj, targets: List[Target]) raises TlsError -> Int:
    """The leaf is valid now and covers every configured name; returns its
    lifetime in seconds."""
    var leaf = L.SSL_CTX_get0_certificate(ctx) if seam(SEAM_LEAF) == 0 else 0
    if leaf == 0:
        raise tls_error("tls: no certificate was loaded", ErrorKind.InvalidData, Category.CREDENTIALS)
    var not_before = L.X509_get0_notBefore(leaf)
    var not_after = L.X509_get0_notAfter(leaf)
    if _seconds(L, 0, not_before) > 0:
        raise tls_error("tls: the certificate is not valid yet", ErrorKind.InvalidData, Category.EXPIRED)
    if _seconds(L, 0, not_after) <= 0:
        raise tls_error("tls: the certificate has expired", ErrorKind.InvalidData, Category.EXPIRED)
    for t in targets:
        if t.is_ip:
            if L.X509_check_ip(leaf, in_buf(Span(t.ip)), len(t.ip), HOST_FLAGS) != 1:
                raise tls_error("tls: the certificate does not cover a configured address", ErrorKind.InvalidInput, Category.IP_MISMATCH, t.name)
        else:
            var name = _cs(t.name, "tls: name")
            var ok = L.X509_check_host(leaf, buf(name), t.name.byte_length(), HOST_FLAGS, 0) == 1
            _ = name^
            if not ok:
                raise tls_error("tls: the certificate does not cover a configured name", ErrorKind.InvalidInput, Category.HOST_MISMATCH, t.name)
    return _seconds(L, not_before, not_after)
