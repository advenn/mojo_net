"""A hostile OpenSSL configuration that tries what the first one
(tests/tls/test_hostile_config.mojo) does not: extra trust (VerifyCAFile
naming an unrelated CA) and weakening options (unsafe legacy
renegotiation, ignoring an end without close_notify, kTLS; for a server,
session tickets and a finite-field group), loaded into the process before
`tls` (TR review: a coverage gap, not a defect found;
OpenSSL refuses certificate commands in `system_default`, which this
shows rather than assumes). One configuration per process, hence its own
file."""

from std.os import setenv
from std.python import Python
from std.testing import TestSuite, assert_equal, assert_true

from tls import Category
from tls.config import SERVER_OPTIONS
from tls_util import Peer, ServerDriver, client_peer, connect, listener, opts, pki, read_error, refused, serving, trusting


def _load_hostile_config() raises -> String:
    var cnf = pki() + "/hostile_trust.cnf"
    var text = String(
        "openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_sect\n",
        "[ssl_sect]\nsystem_default = system_default_sect\n[system_default_sect]\n",
        "VerifyCAFile = ", pki(), "/other.pem\n",
        "Options = UnsafeLegacyRenegotiation,IgnoreUnexpectedEOF,KTLS,-NoRenegotiation,-NoTicket\n",
        "MinProtocol = TLSv1\nCipherString = ALL:@SECLEVEL=0\nNumTickets = 4\nGroups = ffdhe2048:X25519\n",
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


def test_a_server_context_does_not_take_them_either() raises:
    """T2: the same configuration, which also asks for four session
    tickets, tickets back on and a finite-field group first: the server's
    options read back exactly, and a client gets no ticket and no
    resumption."""
    _ = _load_hostile_config()
    var ctx = serving()
    ref L = ctx._library()[]
    assert_equal(L.SSL_CTX_get_options(ctx._ssl_ctx()), SERVER_OPTIONS)
    assert_equal(L.SSL_CTX_get_num_tickets(ctx._ssl_ctx()), 0)
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "reconnect")
    var d = ServerDriver(l, ctx)
    _ = d.serve()
    var d2 = ServerDriver(l, ctx)
    _ = d2.serve()
    assert_equal(c.expect("TICKET"), "TICKET False")
    assert_equal(c.expect("REUSED"), "REUSED False")
    assert_true(d.tls.group() != "ffdhe2048", d.tls.group())
    c^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
