"""Client configuration: `ClientConfig` builds an immutable `ClientContext`
(one OpenSSL `SSL_CTX`), shared by every connection made from it
(docs/tls.md; rules TC1-TC3, TC8, TC11-TC13, TC15, TC16 and TB3 of
docs/research/tls_with_openssl.md).

**Trust** (TC1, TC2): system roots or a CA file you give, never both; no
"accept self-signed" switch (list a self-signed certificate as its own CA)
and no partial chains. System roots are found in this order, and the first
that applies is the only one used: `SSL_CERT_FILE` (it must load), then
`SSL_CERT_DIR` (it must exist and hold files), then the loaded OpenSSL's
default file (in its OPENSSLDIR: the conda-forge `ca-certificates`
bundle), then the distribution bundles Go looks for. A store with no CA in
it is refused when the context is built, naming the file.

**Policy**, set explicitly and read back, because a configuration loaded
by something else in the process still reaches a new context (T0):
TLS 1.2 or later; security level 2; TLS 1.2 ciphers limited to Mozilla's
intermediate profile (ECDHE with AES-GCM or ChaCha20-Poly1305), TLS 1.3's
three suites; groups X25519MLKEM768 (post-quantum hybrid), X25519, P-256,
P-384; strict X.509 checks; no compression, no renegotiation, no session
cache (no resumption), verification of the peer always on with no
callback. None of it can be loosened: the configuration has no such knob.
"""

from std.ffi import c_int, c_uint
from std.memory import ArcPointer
from std.os import getenv, listdir
from std.os.path import exists, isdir

from linux import ErrorKind, IoError

from .consts import (
    SSL_CTRL_CLEAR_MODE,
    SSL_CTRL_GET_MAX_PROTO_VERSION,
    SSL_CTRL_GET_MIN_PROTO_VERSION,
    SSL_CTRL_GET_SESS_CACHE_MODE,
    SSL_CTRL_MODE,
    SSL_CTRL_SET_GROUPS_LIST,
    SSL_CTRL_SET_MAX_PROTO_VERSION,
    SSL_CTRL_SET_MIN_PROTO_VERSION,
    SSL_CTRL_SET_SESS_CACHE_MODE,
    SSL_CTRL_SET_SIGALGS_LIST,
    SSL_MODE_AUTO_RETRY,
    SSL_MODE_NO_AUTO_CHAIN,
    SSL_MODE_RELEASE_BUFFERS,
    SSL_OP_CLEANSE_PLAINTEXT,
    SSL_OP_ENABLE_MIDDLEBOX_COMPAT,
    SSL_OP_NO_COMPRESSION,
    SSL_OP_NO_RENEGOTIATION,
    SSL_OP_NO_RX_CERTIFICATE_COMPRESSION,
    SSL_OP_NO_TICKET,
    SSL_OP_NO_TX_CERTIFICATE_COMPRESSION,
    SSL_SESS_CACHE_OFF,
    SSL_VERIFY_PEER,
    TLS1_2_VERSION,
    TLS1_3_VERSION,
    X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,
    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,
    X509_LU_X509,
    X509_V_FLAG_PARTIAL_CHAIN,
    X509_V_FLAG_TRUSTED_FIRST,
    X509_V_FLAG_X509_STRICT,
)
from .error import Category, TlsError, tls_error
from .ffi import (
    SEAM_ALPN_SET,
    SEAM_CTX_NEW,
    SEAM_EARLY,
    SEAM_LOAD_VERIFY,
    SEAM_READBACK,
    SEAM_TICKETS,
    Library,
    Obj,
    buf,
    c_string,
    from_c_string,
    seam,
)


comptime SECURITY_LEVEL = 2
comptime TLS12_CIPHERS = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
"""Mozilla's intermediate profile (guidelines 6.0)."""
comptime TLS13_SUITES = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
comptime GROUPS = "X25519MLKEM768:X25519:P-256:P-384"
comptime SIGALGS = "ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:RSA+SHA256:RSA+SHA384:RSA+SHA512"
"""SHA-2 and EdDSA only (no SHA-1, no MD5)."""
comptime OPTIONS: UInt64 = (
    SSL_OP_NO_COMPRESSION
    | SSL_OP_NO_RENEGOTIATION
    | SSL_OP_ENABLE_MIDDLEBOX_COMPAT
    | SSL_OP_CLEANSE_PLAINTEXT
    | SSL_OP_NO_TX_CERTIFICATE_COMPRESSION
    | SSL_OP_NO_RX_CERTIFICATE_COMPRESSION
)
"""Exactly the options a context has (TC13). CLEANSE_PLAINTEXT makes
OpenSSL wipe its own copies of plaintext when it frees them (TB18): with
RELEASE_BUFFERS it frees its read buffer after every idle read.
Certificate compression (RFC 8879) is off both ways: this OpenSSL has no
compressor built in, but one that had would turn it on unasked, and a
decompressor is more code a peer's bytes reach."""
comptime MODES = SSL_MODE_AUTO_RETRY | SSL_MODE_RELEASE_BUFFERS
comptime SERVER_OPTIONS: UInt64 = OPTIONS | SSL_OP_NO_TICKET
"""A server's: no session tickets, alongside `SSL_CTX_set_num_tickets(0)`
(TS4: the option alone makes TLS 1.3 tickets stateful, with a cache)."""
comptime SERVER_MODES = MODES | SSL_MODE_NO_AUTO_CHAIN
"""A server sends exactly the chain it was given (TS3)."""
comptime VERIFY_FLAGS: UInt64 = X509_V_FLAG_X509_STRICT | X509_V_FLAG_TRUSTED_FIRST
comptime HOST_FLAGS: c_uint = X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT

comptime _SYSTEM_BUNDLES: List[StaticString] = [
    "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu, Gentoo, Arch
    "/etc/pki/tls/certs/ca-bundle.crt",  # Fedora, RHEL 6
    "/etc/ssl/ca-bundle.pem",  # openSUSE
    "/etc/pki/tls/cacert.pem",  # OpenELEC
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # CentOS, RHEL 7
    "/etc/ssl/cert.pem",  # Alpine
]
"""Go's list (crypto/x509/root_linux.go), last in the search."""


struct Trust(Copyable, Movable, Writable):
    """Which CA certificates a client trusts (TC2): the system's, or the
    ones in a file you give, which then replace the system's. An empty
    path is refused when the context is built: it never means the
    system's (a variable left unset must not widen the trust)."""

    var _ca_file: String
    var _system: Bool

    @staticmethod
    def system() -> Trust:
        return Trust(String(), True)

    @staticmethod
    def ca_file(path: StringSlice) -> Trust:
        """Trust exactly the certificates in the PEM file at `path`."""
        return Trust(String(path), False)

    def __init__(out self, ca_file: String):
        """`ca_file`, as `Trust.ca_file`."""
        self._ca_file = ca_file
        self._system = False

    def __init__(out self, ca_file: String, system: Bool):
        self._ca_file = ca_file
        self._system = system

    def is_system(self) -> Bool:
        return self._system

    def write_to(self, mut writer: Some[Writer]):
        if self.is_system():
            writer.write("system roots")
        else:
            writer.write("CA file ", self._ca_file)


struct ClientConfig(Copyable, Movable):
    """What a TLS client verifies and offers. `build()` makes the context."""

    var trust: Trust
    var alpn: List[String]
    """Application protocols offered, in preference order (empty: no ALPN).
    After the handshake the server's choice must be none or one of these."""

    def __init__(out self, *, var trust: Trust = Trust.system(), var alpn: List[String] = List[String]()):
        self.trust = trust^
        self.alpn = alpn^

    def build(self) raises TlsError -> ClientContext:
        """Load OpenSSL (once per call: share the returned context), make
        and configure an `SSL_CTX`, and refuse it if any setting did not
        take or the trust store is empty."""
        var lib: ArcPointer[Library]
        try:
            lib = Library.load()
        except e:
            raise TlsError(e, Category.LIBRARY, "")
        return ClientContext(_Context(lib, self))


struct _Context(Movable):
    var lib: ArcPointer[Library]
    var ctx: Obj
    var anchors: Int
    """CA certificates loaded (0 for a directory store, which loads lazily)."""
    var trust_source: String
    var alpn: List[String]

    def __init__(out self, lib: ArcPointer[Library], config: ClientConfig) raises TlsError:
        ref L = lib[]
        L.ERR_clear_error()
        var ctx = L.SSL_CTX_new_ex(L.libctx, 0, L.TLS_client_method())
        if seam(SEAM_CTX_NEW) != 0 and ctx != 0:
            L.SSL_CTX_free(ctx)
            ctx = 0
        if ctx == 0:
            raise tls_error("tls: SSL_CTX_new_ex failed", ErrorKind.OutOfMemory, Category.LIBRARY, L.drain_errors())
        # The context is configured before `self` holds it, and freed here
        # on any failure: Mojo 1.2 skips `__deinit__` when `__init__`
        # raises before a field's last assignment (CLAUDE.md).
        var loaded: _Loaded
        try:
            _configure(L, ctx)
            _set_alpn(L, ctx, config.alpn)
            loaded = _load_trust(L, ctx, config.trust)
            var left = L.drain_errors()
            if left.byte_length() > 0:
                raise tls_error("tls: OpenSSL reported an error while configuring", ErrorKind.Other, Category.LIBRARY, left)
        except e:
            L.SSL_CTX_free(ctx)
            raise e^
        self.lib = lib
        self.ctx = ctx
        self.anchors = loaded.anchors
        self.trust_source = loaded.source.copy()
        self.alpn = config.alpn.copy()

    def __deinit__(deinit self):
        if self.ctx != 0:
            self.lib[].SSL_CTX_free(self.ctx)


struct ClientContext(Copyable, Movable, Writable):
    """A built client configuration (one `SSL_CTX`, never changed again:
    TB3). Copies share it; each connection keeps it alive."""

    var _inner: ArcPointer[_Context]

    def __init__(out self, var inner: _Context):
        self._inner = ArcPointer(inner^)

    def _library(self) -> ArcPointer[Library]:
        """For `tls.client` only: the context is read-only once built
        (TB3), so nothing outside the package gets the OpenSSL handles."""
        return self._inner[].lib

    def _ssl_ctx(self) -> Obj:
        return self._inner[].ctx

    def alpn(self) -> List[String]:
        return self._inner[].alpn.copy()

    def anchors(self) -> Int:
        """How many CA certificates the store holds (0 for SSL_CERT_DIR)."""
        return self._inner[].anchors

    def trust_source(self) -> String:
        """Where the CA certificates came from (a file or a directory)."""
        return self._inner[].trust_source

    def write_to(self, mut writer: Some[Writer]):
        ref L = self._inner[].lib[]
        writer.write(L.version, " (", L.path, "), trust: ", self._inner[].trust_source)


def _cs(s: StringSlice, op: StaticString) raises TlsError -> List[UInt8]:
    """`c_string`, raising `TlsError` (an embedded NUL is `InvalidInput`)."""
    try:
        return c_string(s, op)
    except e:
        raise TlsError(e, Category.INPUT, String(s))


def _check(ok: Bool, what: StaticString, L: Library) raises TlsError:
    if not ok:
        raise tls_error(what, ErrorKind.Other, Category.LIBRARY, L.drain_errors())


def _configure(L: Library, ctx: Obj, server: Bool = False, tls13_only: Bool = False) raises TlsError:
    """Every policy knob, set explicitly and read back (TC8, TC11-TC13,
    TC16; for a server, TS1-TS4 and TS14)."""
    var floor = TLS1_3_VERSION if tls13_only else TLS1_2_VERSION
    _check(L.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, floor, 0) == 1, "tls: setting the version floor failed", L)
    _check(L.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, 0, 0) == 1, "tls: setting the version ceiling failed", L)
    _check(L.SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, 0) == floor, "tls: the version floor did not take", L)
    _check(L.SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MAX_PROTO_VERSION, 0, 0) == 0, "tls: the version ceiling did not take", L)
    L.SSL_CTX_set_security_level(ctx, c_int(SECURITY_LEVEL))
    _check(L.SSL_CTX_get_security_level(ctx) == SECURITY_LEVEL, "tls: the security level did not take", L)
    var ciphers = _cs(TLS12_CIPHERS, "tls: ciphers")
    _check(L.SSL_CTX_set_cipher_list(ctx, buf(ciphers)) == 1, "tls: setting the TLS 1.2 ciphers failed", L)
    var suites = _cs(TLS13_SUITES, "tls: suites")
    _check(L.SSL_CTX_set_ciphersuites(ctx, buf(suites)) == 1, "tls: setting the TLS 1.3 suites failed", L)
    var groups = _cs(GROUPS, "tls: groups")
    _check(L.SSL_CTX_ctrl_str(ctx, SSL_CTRL_SET_GROUPS_LIST, 0, buf(groups)) == 1, "tls: setting the key exchange groups failed", L)
    var sigalgs = _cs(SIGALGS, "tls: sigalgs")
    _check(L.SSL_CTX_ctrl_str(ctx, SSL_CTRL_SET_SIGALGS_LIST, 0, buf(sigalgs)) == 1, "tls: setting the signature algorithms failed", L)
    _ = ciphers^
    _ = suites^
    _ = groups^
    _ = sigalgs^
    var options = SERVER_OPTIONS if server else OPTIONS
    _ = L.SSL_CTX_clear_options(ctx, UInt64.MAX)
    _ = L.SSL_CTX_set_options(ctx, options)
    _check(L.SSL_CTX_get_options(ctx) == options and seam(SEAM_READBACK) == 0, "tls: the options did not take", L)
    var modes = SERVER_MODES if server else MODES
    _ = L.SSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_MODE, -1, 0)
    _check(L.SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, modes, 0) == modes, "tls: the modes did not take", L)
    _ = L.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, SSL_SESS_CACHE_OFF, 0)
    _check(L.SSL_CTX_ctrl(ctx, SSL_CTRL_GET_SESS_CACHE_MODE, 0, 0) == SSL_SESS_CACHE_OFF, "tls: the session cache did not turn off", L)
    # A client verifies the server; a server asks for no client certificate.
    var verify = c_int(0) if server else SSL_VERIFY_PEER
    L.SSL_CTX_set_verify(ctx, verify, 0)
    _check(L.SSL_CTX_get_verify_mode(ctx) == verify, "tls: the verify mode did not take", L)
    if server:
        _check(L.SSL_CTX_set_num_tickets(ctx, 0) == 1, "tls: turning session tickets off failed", L)
        var tickets = L.SSL_CTX_get_num_tickets(ctx) if seam(SEAM_TICKETS) == 0 else 2
        _check(tickets == 0, "tls: session tickets did not turn off", L)
        var early = L.SSL_CTX_get_max_early_data(ctx) if seam(SEAM_EARLY) == 0 else 16384
        _check(early == 0, "tls: early data is not off", L)
    var param = L.SSL_CTX_get0_param(ctx)
    _check(param != 0, "tls: no verify parameters", L)
    _ = L.X509_VERIFY_PARAM_clear_flags(param, UInt64.MAX)
    _check(L.X509_VERIFY_PARAM_set_flags(param, VERIFY_FLAGS) == 1, "tls: setting the verify flags failed", L)
    var flags = L.X509_VERIFY_PARAM_get_flags(param)
    _check(flags == VERIFY_FLAGS and flags & X509_V_FLAG_PARTIAL_CHAIN == 0, "tls: the verify flags did not take", L)
    L.X509_VERIFY_PARAM_set_hostflags(param, HOST_FLAGS)
    _check(L.X509_VERIFY_PARAM_get_hostflags(param) == HOST_FLAGS, "tls: the host-name flags did not take", L)


def alpn_wire(protocols: List[String]) raises TlsError -> List[UInt8]:
    """The ALPN list in wire format (a length byte, then the name, each)."""
    var out = List[UInt8]()
    for i in range(len(protocols)):
        var p = protocols[i].as_bytes()
        if len(p) == 0 or len(p) > 255:
            raise tls_error("tls: an ALPN protocol name must be 1 to 255 bytes", ErrorKind.InvalidInput, Category.INPUT)
        out.append(UInt8(len(p)))
        out.extend(p)
    return out^


def _set_alpn(L: Library, ctx: Obj, protocols: List[String]) raises TlsError:
    if len(protocols) == 0:
        return
    var wire = alpn_wire(protocols)
    # SSL_CTX_set_alpn_protos returns 0 on success (TC15).
    _check(L.SSL_CTX_set_alpn_protos(ctx, buf(wire), c_uint(len(wire))) == 0 and seam(SEAM_ALPN_SET) == 0, "tls: setting the ALPN list failed", L)
    _ = wire^


@fieldwise_init
struct _Loaded(Movable):
    var anchors: Int
    var source: String


def _anchors(L: Library, ctx: Obj) -> Int:
    """The certificates in the store (CRLs are objects too, not anchors)."""
    var store = L.SSL_CTX_get_cert_store(ctx)
    if store == 0:
        return 0
    var objects = L.X509_STORE_get0_objects(store)
    if objects == 0:
        return 0
    var n = 0
    for i in range(Int(L.OPENSSL_sk_num(objects))):
        var obj = L.OPENSSL_sk_value(objects, c_int(i))
        if obj != 0 and L.X509_OBJECT_get_type(obj) == X509_LU_X509:
            n += 1
    return n


def _load_file(L: Library, ctx: Obj, path: String) raises TlsError -> _Loaded:
    if not exists(path):
        raise tls_error("tls: the CA file does not exist", ErrorKind.NotFound, Category.NO_TRUST_STORE, path)
    var p = _cs(path, "tls: CA file path")
    var ok = L.SSL_CTX_load_verify_file(ctx, buf(p)) == 1 and seam(SEAM_LOAD_VERIFY) == 0
    _ = p^
    if not ok:
        raise tls_error("tls: the CA file did not load", ErrorKind.InvalidData, Category.NO_TRUST_STORE, path + ": " + L.drain_errors())
    var n = _anchors(L, ctx)
    if n == 0:
        raise tls_error("tls: the CA file holds no certificate", ErrorKind.InvalidData, Category.NO_TRUST_STORE, path)
    return _Loaded(n, path)


def _load_trust(L: Library, ctx: Obj, trust: Trust) raises TlsError -> _Loaded:
    """The trust store, in TC1's order; never empty."""
    if not trust.is_system():
        if trust._ca_file.byte_length() == 0:
            raise tls_error("tls: the CA file path is empty (for the system roots, use Trust.system())", ErrorKind.InvalidInput, Category.INPUT)
        return _load_file(L, ctx, trust._ca_file)
    var file = getenv("SSL_CERT_FILE")
    if file.byte_length() > 0:
        return _load_file(L, ctx, file)  # exactly that file, no fallback
    var dir = getenv("SSL_CERT_DIR")
    if dir.byte_length() > 0:
        var entries: List[String]
        try:
            entries = listdir(dir) if isdir(dir) else List[String]()
        except:
            entries = List[String]()
        if len(entries) == 0:
            raise tls_error("tls: SSL_CERT_DIR is missing or empty", ErrorKind.NotFound, Category.NO_TRUST_STORE, dir)
        var d = _cs(dir, "tls: SSL_CERT_DIR")
        var ok = L.SSL_CTX_load_verify_dir(ctx, buf(d)) == 1 and seam(SEAM_LOAD_VERIFY) == 0
        _ = d^
        if not ok:
            raise tls_error("tls: SSL_CERT_DIR did not load", ErrorKind.InvalidData, Category.NO_TRUST_STORE, dir + ": " + L.drain_errors())
        return _Loaded(0, dir)
    var default = from_c_string(L.X509_get_default_cert_file())
    if default.byte_length() > 0 and exists(default):
        return _load_file(L, ctx, default)
    for i in range(len(materialize[_SYSTEM_BUNDLES]())):
        var p = String(materialize[_SYSTEM_BUNDLES]()[i])
        if exists(p):
            return _load_file(L, ctx, p)
    raise tls_error("tls: no system CA bundle found (install ca-certificates, or set SSL_CERT_FILE)", ErrorKind.NotFound, Category.NO_TRUST_STORE, default)
