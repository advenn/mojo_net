"""A hostile OpenSSL configuration that tries what the first one
(tests/tls/test_hostile_config.mojo) does not: extra trust (VerifyCAFile
naming an unrelated CA) and weakening options (unsafe legacy
renegotiation, ignoring an end without close_notify, kTLS), loaded into
the process before `tls` (TR review: a coverage gap, not a defect found;
OpenSSL refuses certificate commands in `system_default`, which this
shows rather than assumes). One configuration per process, hence its own
file."""

from std.os import setenv
from std.python import Python
from std.testing import TestSuite, assert_equal, assert_true

from tls import Category
from tls_util import Peer, connect, opts, pki, read_error, refused, trusting


def _load_hostile_config() raises -> String:
    var cnf = pki() + "/hostile_trust.cnf"
    var text = String(
        "openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_sect\n",
        "[ssl_sect]\nsystem_default = system_default_sect\n[system_default_sect]\n",
        "VerifyCAFile = ", pki(), "/other.pem\n",
        "Options = UnsafeLegacyRenegotiation,IgnoreUnexpectedEOF,KTLS,-NoRenegotiation\n",
        "MinProtocol = TLSv1\nCipherString = ALL:@SECLEVEL=0\n",
    )
    var builtins = Python.import_module("builtins")
    var f = builtins.open(cnf, "w")
    _ = f.write(text)
    _ = f.close()
    _ = setenv("OPENSSL_CONF", cnf, True)
    var ssl = Python.import_module("ssl")  # (loads it into the process's OpenSSL)
    # The contrast: it did load. A context Python makes now has the
    # option it asks for, which OpenSSL leaves off by default.
    var c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    assert_true(Bool(py=(c.options & ssl.OP_IGNORE_UNEXPECTED_EOF) != 0), "the hostile configuration did not load")
    return cnf


def test_extra_trust_and_options_do_not_take() raises:
    _ = _load_hostile_config()
    var ctx = trusting()  # (build() reads every setting back)
    # A certificate from the CA the configuration names is not trusted.
    var other = Peer("echo", opts("cert=by_other"))
    refused(other, ctx, "localhost", Category.UNTRUSTED)
    other^.stop()
    # An end without close_notify is still a truncation.
    var cut = Peer("truncate")
    var s = connect(cut, ctx)
    s.write_all("go\n".as_bytes())
    var got = List[UInt8]()
    var e = read_error(s, got)
    assert_equal(e.category, Category.TRUNCATED, String(e))
    cut^.stop()
    # And the ordinary connection is the ordinary one.
    var good = Peer("echo")
    var t = connect(good, ctx)
    assert_equal(t.version(), "TLSv1.3")
    t^.close()
    good^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
