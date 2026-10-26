"""`tls.ServerConfig`: what a server context refuses to be built from, and
what it is once built, read back from OpenSSL (T2; rules TS1-TS4, TS11,
TS12 and TS14 of docs/research/tls_with_openssl.md)."""

from std.os import setenv, unsetenv
from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from linux import ErrorKind
from tls import Category, ServerConfig, ServerContext, TlsClient, TlsError, TlsServer
from tls.config import SERVER_MODES, SERVER_OPTIONS
from tls.consts import (
    SSL_CTRL_GET_MIN_PROTO_VERSION,
    SSL_CTRL_GET_SESS_CACHE_MODE,
    SSL_CTRL_MODE,
    SSL_SESS_CACHE_OFF,
    TLS1_2_VERSION,
    TLS1_3_VERSION,
)
from tls_util import ServerDriver, client_peer, listener, opts, pki, serving, trusting


def _error(config: ServerConfig) raises -> TlsError:
    try:
        _ = config.build()
    except e:
        return e^
    raise Error("the context was built")


def _config(cert: StringSlice, key: StringSlice, names: List[String] = ["localhost"]) raises -> ServerConfig:
    var d = pki()
    return ServerConfig(certificate=d + "/" + cert + ".chain.pem", key=d + "/" + key + ".key", names=names.copy())


def _scratch_key(source: StringSlice, mode: Int) raises -> String:
    """A copy of the PKI's `source` key with `mode`, in a scratch directory."""
    var os = Python.import_module("os")
    var shutil = Python.import_module("shutil")
    var tempfile = Python.import_module("tempfile")
    var d = tempfile.mkdtemp(prefix="mojo_net_key_")
    var p = String(py=os.path.join(d, "copy.key"))
    _ = shutil.copyfile(pki() + "/" + source + ".key", p)
    _ = os.chmod(p, mode)
    return p


# ---- refused ------------------------------------------------------------------


def test_names_and_alpn_are_checked() raises:
    var d = pki()
    var e = _error(ServerConfig(certificate=d + "/good.chain.pem", key=d + "/good.key", names=[]))
    assert_equal(e.category, Category.INPUT, String(e))
    e = _error(ServerConfig(certificate=d + "/good.chain.pem", key=d + "/good.key", names=["bad name"]))
    assert_equal(e.category, Category.INPUT, String(e))
    e = _error(ServerConfig(certificate=d + "/good.chain.pem", key=d + "/good.key", names=["*.wild.test"]))
    assert_equal(e.category, Category.INPUT, String(e))
    e = _error(ServerConfig(certificate=d + "/good.chain.pem", key=d + "/good.key", names=["localhost"], alpn=[""]))
    assert_equal(e.category, Category.INPUT, String(e))
    e = _error(ServerConfig(certificate="", key=d + "/good.key", names=["localhost"]))
    assert_equal(e.category, Category.INPUT, String(e))


def test_missing_files_are_refused() raises:
    var d = pki()
    var e = _error(ServerConfig(certificate=d + "/none.pem", key=d + "/good.key", names=["localhost"]))
    assert_equal(e.category, Category.CREDENTIALS, String(e))
    assert_equal(e.io.kind, ErrorKind.NotFound)
    e = _error(ServerConfig(certificate=d + "/good.chain.pem", key=d + "/none.key", names=["localhost"]))
    assert_equal(e.category, Category.CREDENTIALS, String(e))
    assert_equal(e.io.kind, ErrorKind.NotFound)
    e = _error(ServerConfig(certificate=d + "/good.chain.pem", key=d, names=["localhost"]))  # (a directory)
    assert_equal(e.category, Category.CREDENTIALS, String(e))


def test_a_key_that_does_not_match_is_refused() raises:
    """TS3: another EC key, and a key of another type (RSA for an ECDSA
    leaf, which libssl files under another slot without complaint)."""
    for key in ["wrong_host", "rsa"]:
        var e = _error(_config("good", key))
        assert_equal(e.category, Category.CREDENTIALS, String(key, ": ", e))
        assert_true("does not match" in String(e) or "did not load" in String(e), String(e))


def test_an_expired_or_future_leaf_is_refused() raises:
    var e = _error(_config("expired", "expired"))
    assert_equal(e.category, Category.EXPIRED, String(e))
    assert_true("expired" in String(e), String(e))
    e = _error(_config("future", "future"))
    assert_equal(e.category, Category.EXPIRED, String(e))
    assert_true("not valid yet" in String(e), String(e))


def test_a_leaf_that_does_not_cover_every_name_is_refused() raises:
    var e = _error(_config("good", "good", ["localhost", "example.com"]))
    assert_equal(e.category, Category.HOST_MISMATCH, String(e))
    assert_true("example.com" in String(e), String(e))
    e = _error(_config("good", "good", ["10.9.9.9"]))
    assert_equal(e.category, Category.IP_MISMATCH, String(e))
    e = _error(_config("cn_only", "cn_only"))  # (no subject CN fallback)
    assert_equal(e.category, Category.HOST_MISMATCH, String(e))
    e = _error(_config("wildcard", "wildcard", ["a.b.wild.test"]))  # (one label only)
    assert_equal(e.category, Category.HOST_MISMATCH, String(e))
    _ = _config("wildcard", "wildcard", ["a.wild.test"]).build()


def test_a_weak_key_is_refused() raises:
    """Security level 2: RSA 1024 does not load."""
    var e = _error(_config("rsa1024", "rsa1024"))
    assert_equal(e.category, Category.CREDENTIALS, String(e))
    assert_true("too small" in String(e), String(e))


def test_a_key_others_can_read_is_refused() raises:
    """TS3: the key must be readable by its owner alone (root's may be
    readable by its group)."""
    var d = pki()
    for mode in [0o644, 0o640, 0o604, 0o660, 0o620]:
        var k = _scratch_key("good", mode)
        var e = _error(ServerConfig(certificate=d + "/good.chain.pem", key=k, names=["localhost"]))
        assert_equal(e.category, Category.CREDENTIALS, String(oct(mode), ": ", e))
        assert_equal(e.io.kind, ErrorKind.PermissionDenied)
    for mode in [0o600, 0o400]:
        var k = _scratch_key("good", mode)
        _ = ServerConfig(certificate=d + "/good.chain.pem", key=k, names=["localhost"]).build()


def oct(mode: Int) -> String:
    return String("0", (mode >> 6) & 7, (mode >> 3) & 7, mode & 7)


def test_an_encrypted_key_is_refused_without_a_prompt() raises:
    """TS3: libssl's default password callback reads the passphrase from
    the controlling terminal. The app runs on a pseudo-terminal of its own
    (`pty.fork`): it must say REFUSED at once, never ask."""
    var os = Python.import_module("os")
    var subprocess = Python.import_module("subprocess")
    var tempfile = Python.import_module("tempfile")
    var d = pki()
    var enc = String(py=os.path.join(tempfile.mkdtemp(prefix="mojo_net_enc_"), "enc.key"))
    var made = subprocess.run(
        Python.list("openssl", "pkey", "-in", d + "/good.key", "-aes256", "-passout", "pass:secret", "-out", enc), capture_output=True
    )
    assert_equal(Int(py=made.returncode), 0)
    _ = os.chmod(enc, 0o600)
    var exe = String(py=os.path.join(tempfile.gettempdir(), String("encrypted_key_app_", Int(py=os.getpid()))))
    var built = subprocess.run(
        Python.list("mojo", "build", "-I", "src", "tests/tls/encrypted_key_app.mojo", "-o", exe), capture_output=True, text=True
    )
    if Int(py=built.returncode) != 0:
        raise Error(String("building the app failed: ", String(py=built.stderr)))
    var sys = Python.import_module("sys")
    if not Bool(py=Python.evaluate("lambda p: 'tests/tls' in p")(sys.path)):
        _ = sys.path.insert(0, "tests/tls")
    var out = String(py=Python.import_module("on_tty").run(Python.list(exe, d + "/good.chain.pem", enc), 60))
    _ = os.remove(exe)
    assert_false("pass phrase" in out.lower() or "password" in out.lower(), out)
    assert_true("REFUSED unusable certificate or key" in out, out)


# ---- built --------------------------------------------------------------------


def test_the_policy_reads_back() raises:
    """TS1, TS4, TS14: every option exactly (so no kTLS, tickets off,
    compression and renegotiation off), no tickets issued, no session
    cache, no client certificates, no early data, the chain sent as given."""
    for i in range(2):
        var ctx = serving(tls13_only=i == 1)
        ref L = ctx._library()[]
        var h = ctx._ssl_ctx()
        assert_equal(L.SSL_CTX_get_options(h), SERVER_OPTIONS)
        assert_equal(L.SSL_CTX_ctrl(h, SSL_CTRL_MODE, 0, 0), SERVER_MODES)
        assert_equal(L.SSL_CTX_ctrl(h, SSL_CTRL_GET_SESS_CACHE_MODE, 0, 0), SSL_SESS_CACHE_OFF)
        assert_equal(L.SSL_CTX_get_num_tickets(h), 0)
        assert_equal(Int(L.SSL_CTX_get_max_early_data(h)), 0)
        assert_equal(Int(L.SSL_CTX_get_verify_mode(h)), 0)
        assert_equal(L.SSL_CTX_ctrl(h, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, 0), TLS1_3_VERSION if i == 1 else TLS1_2_VERSION)
        assert_equal(Int(L.SSL_CTX_get_security_level(h)), 2)
        _ = ctx  # (alive past the calls: the handle alone does not keep it)


def test_an_intermediate_in_the_chain_file_is_sent() raises:
    var ctx = serving(cert="chained", names=["localhost"])
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "hello")
    var d = ServerDriver(l, ctx)
    _ = d.serve()
    assert_equal(c.expect("REPLY"), "REPLY echo:ping")
    c^.stop()


def test_lifetime_and_renewal() raises:
    """TS12's alarm: renewal is due once less than a third of the lifetime
    is left."""
    var good = serving()
    assert_equal(good.lifetime(), 2 * 86400)
    var left = good.expires_in()
    assert_true(left > 2 * 86400 - 3600 and left <= 2 * 86400, String(left))
    assert_false(good.renewal_due())
    var soon = serving(cert="soon", names=["localhost"])
    assert_equal(soon.lifetime(), 48 * 3600)
    assert_true(soon.expires_in() <= 3600 and soon.expires_in() > 3000, String(soon.expires_in()))
    assert_true(soon.renewal_due())
    assert_equal(soon.names(), ["localhost"])


def test_reloading_keeps_live_connections() raises:
    """TS12: a connection keeps the context it began with when a new one
    is built (and the old copy dropped); the new one serves new
    connections."""
    var cctx = trusting()
    var old = serving()
    var c1 = TlsClient(cctx, "localhost")
    var s1 = TlsServer(old)
    var new = serving(cert="chained", names=["localhost"])
    old = new.copy()  # (the first context's last copy is now s1's)
    _exchange(c1, s1)
    assert_true(c1.is_established() and s1.is_established())
    var c2 = TlsClient(cctx, "localhost")
    var s2 = TlsServer(old)
    _exchange(c2, s2)
    assert_true(c2.is_established() and s2.is_established())


def _exchange(mut c: TlsClient, mut s: TlsServer) raises:
    var a = ByteBuffer()
    var b = ByteBuffer()
    for _ in range(10):
        _ = c.poll_transmit(a)
        if len(a) > 0:
            s.feed(a.readable_span())
            a.clear()
        _ = s.poll_transmit(b)
        if len(b) > 0:
            c.feed(b.readable_span())
            b.clear()
        while c.next_event():
            pass
        while s.next_event():
            pass


def test_no_key_log_file_is_written() raises:
    """TS11: a libssl built with `enable-sslkeylog` writes every session's
    secrets to SSLKEYLOGFILE. With it set, a handshake writes nothing."""
    var os = Python.import_module("os")
    var tempfile = Python.import_module("tempfile")
    var log = String(py=os.path.join(tempfile.mkdtemp(prefix="mojo_net_keylog_"), "keys.log"))
    _ = setenv("SSLKEYLOGFILE", log, True)
    var cctx = trusting()
    var sctx = serving()
    var c = TlsClient(cctx, "localhost")
    var s = TlsServer(sctx)
    _exchange(c, s)
    _ = unsetenv("SSLKEYLOGFILE")
    assert_true(c.is_established())
    assert_false(Bool(py=os.path.exists(log)), "SSLKEYLOGFILE was written")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
