"""ClientConfig and the trust store (TC1, TC2, TC15): where CA certificates
come from, that a store is never empty, and that SSL_CERT_FILE has no
fallback. Each test restores the variables it sets."""

from std.os import getenv, setenv, unsetenv
from std.python import Python
from std.testing import TestSuite, assert_equal, assert_true

from linux import ErrorKind
from tls import Category, ClientConfig, ClientContext, TlsError, Trust
from tls.config import alpn_wire
from tls_util import Peer, connect, connect_error, pki, trusting


def _build_error(config: ClientConfig) raises -> TlsError:
    try:
        _ = config.build()
    except e:
        return e^
    raise Error("the configuration built")


struct _Env:
    """Sets variables for a test and puts the old values back."""

    var names: List[String]
    var old: List[String]
    var had: List[Bool]

    def __init__(out self):
        self.names = List[String]()
        self.old = List[String]()
        self.had = List[Bool]()

    def set(mut self, name: StringSlice, value: StringSlice):
        self._save(name)
        _ = setenv(String(name), String(value), True)

    def unset(mut self, name: StringSlice):
        self._save(name)
        _ = unsetenv(String(name))

    def _save(mut self, name: StringSlice):
        var py_os = String(getenv(String(name)))
        self.names.append(String(name))
        self.old.append(py_os)
        self.had.append(py_os.byte_length() > 0)

    def restore(mut self):
        for i in reversed(range(len(self.names))):
            if self.had[i]:
                _ = setenv(self.names[i], self.old[i], True)
            else:
                _ = unsetenv(self.names[i])


def _scratch(name: StringSlice) raises -> String:
    var os = Python.import_module("os")
    var d = pki() + "/" + name
    _ = os.makedirs(d, exist_ok=True)
    return d


def test_system_roots() raises:
    var env = _Env()
    env.unset("SSL_CERT_FILE")
    env.unset("SSL_CERT_DIR")
    var ctx = ClientConfig().build()
    assert_true(ctx.anchors() > 50, String(ctx.anchors(), " anchors from ", ctx.trust_source()))
    assert_true(ctx.trust_source().endswith(".pem"), ctx.trust_source())
    env.restore()


def test_ca_file_replaces_the_system_roots() raises:
    var ctx = trusting()
    assert_equal(ctx.anchors(), 1)
    assert_equal(ctx.trust_source(), pki() + "/root.pem")


def test_missing_ca_file() raises:
    var e = _build_error(ClientConfig(trust=Trust.ca_file("/nonexistent/ca.pem")))
    assert_equal(e.category, Category.NO_TRUST_STORE)
    assert_equal(e.io.kind, ErrorKind.NotFound)


def test_ca_file_without_certificates() raises:
    var empty = _scratch("cfg") + "/empty.pem"
    var f = Python.import_module("builtins").open(empty, "w")
    _ = f.close()
    var paths: List[String] = [empty, pki() + "/root.key"]
    for p in paths:
        var e = _build_error(ClientConfig(trust=Trust.ca_file(p)))
        assert_equal(e.category, Category.NO_TRUST_STORE, String(e))


def test_nul_in_a_path() raises:
    var e = _build_error(ClientConfig(trust=Trust.ca_file("/etc/ssl\x00/x.pem")))
    assert_true(e.category == Category.INPUT or e.category == Category.NO_TRUST_STORE, String(e))


def test_ssl_cert_file() raises:
    var env = _Env()
    env.set("SSL_CERT_FILE", pki() + "/root.pem")
    var ctx = ClientConfig().build()
    assert_equal(ctx.anchors(), 1)
    var peer = Peer("echo")
    var s = connect(peer, ctx)
    s^.close()
    peer^.stop()
    env.restore()


def test_ssl_cert_file_has_no_fallback() raises:
    var env = _Env()
    env.set("SSL_CERT_FILE", "/nonexistent/bundle.pem")
    var e = _build_error(ClientConfig())
    assert_equal(e.category, Category.NO_TRUST_STORE)
    assert_equal(e.io.kind, ErrorKind.NotFound)
    env.restore()


def test_ssl_cert_dir() raises:
    var env = _Env()
    env.unset("SSL_CERT_FILE")
    var empty = _scratch("emptydir")
    env.set("SSL_CERT_DIR", empty)
    assert_equal(_build_error(ClientConfig()).category, Category.NO_TRUST_STORE)
    env.set("SSL_CERT_DIR", "/nonexistent/certs")
    assert_equal(_build_error(ClientConfig()).category, Category.NO_TRUST_STORE)
    # A hashed directory (openssl rehash) is a store, loaded as needed.
    var dir = _scratch("hashed")
    var shutil = Python.import_module("shutil")
    var subprocess = Python.import_module("subprocess")
    _ = shutil.copyfile(pki() + "/root.pem", dir + "/root.pem")
    _ = subprocess.run(Python.list("openssl", "rehash", dir), check=True, capture_output=True)
    env.set("SSL_CERT_DIR", dir)
    var ctx = ClientConfig().build()
    assert_equal(ctx.trust_source(), dir)
    var peer = Peer("echo")
    var s = connect(peer, ctx)
    s^.close()
    peer^.stop()
    env.restore()


def test_alpn_wire_format() raises:
    var wire = alpn_wire(["h2", "http/1.1"])
    var want: List[UInt8] = [2, UInt8(ord("h")), UInt8(ord("2")), 8]
    want.extend("http/1.1".as_bytes())
    assert_true(wire == want)
    var bad: List[List[String]] = [[""], ["h2", ""], [String("x") * 256]]
    for b in bad:
        var e = _build_error(ClientConfig(trust=Trust.ca_file(pki() + "/root.pem"), alpn=b.copy()))
        assert_equal(e.category, Category.INPUT, String(e))
    assert_equal(len(alpn_wire([String("y") * 255])), 256)


def test_contexts_are_independent() raises:
    var a = trusting()
    var b = trusting("other")
    var peer = Peer("echo", ["count=2"])
    var s = connect(peer, a)
    s^.close()
    assert_equal(connect_error(peer.port, b, "localhost").category, Category.UNTRUSTED)
    peer^.stop()
    _ = a^
    _ = b^


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
