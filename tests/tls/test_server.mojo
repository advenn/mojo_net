"""`tls.TlsServer` against clients that share none of its code: Python's
`ssl` (tests/tls/tls_client_peer.py) and `openssl s_client` (T2; rules
TS1-TS6, TS8-TS10 and TS14 of docs/research/tls_with_openssl.md). Each
test serves one or two connections on a fresh listener while the client
runs in a child process, then compares what both sides saw."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from tls import Category, TlsError
from tls.engine import CLIENT_HELLO_LIMIT, FEED_LIMIT
from tls_util import ClientProc, ServerDriver, client_peer, listener, opts, s_client, serving




def _failure(mut d: ServerDriver) raises -> TlsError:
    var e = d.serve()
    if not e:
        raise Error("the connection ended without a failure")
    return e.take()


def test_a_python_client_is_served_over_tls13() raises:
    var ctx = serving()
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "hello")
    var d = ServerDriver(l, ctx)
    var e = d.serve()
    assert_false(Bool(e), String(e.value()) if e else "")
    var ok = c.expect("OK")
    assert_true(ok.startswith("OK TLSv1.3 TLS_"), ok)
    assert_equal(c.expect("TICKET"), "TICKET False")  # (TS4: no ticket)
    assert_equal(c.expect("REPLY"), "REPLY echo:ping")
    assert_equal(c.expect("CLOSED"), "CLOSED")
    assert_equal(d.tls.version(), "TLSv1.3")
    assert_equal(d.tls.server_name(), "localhost")
    assert_equal(d.tls.alpn(), "")
    assert_equal(d.tls.group(), "X25519MLKEM768")
    c^.stop()


def test_tls12_uses_an_intermediate_profile_suite() raises:
    var ctx = serving()
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "hello", opts("max=1.2"))
    var d = ServerDriver(l, ctx)
    _ = d.serve()
    var ok = c.expect("OK")
    assert_true(ok.startswith("OK TLSv1.2 ECDHE-ECDSA-"), ok)
    assert_true("GCM" in ok or "CHACHA20" in ok, ok)
    assert_equal(c.expect("REPLY"), "REPLY echo:ping")
    c^.stop()


def test_tls11_is_refused() raises:
    var ctx = serving()
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "hello", opts("min=1.1", "max=1.1"))
    var d = ServerDriver(l, ctx)
    var e = _failure(d)
    assert_equal(e.category, Category.PROTOCOL, String(e))
    var seen = c.expect("ERROR")
    assert_true("PROTOCOL_VERSION" in seen or "VERSION" in seen, seen)
    c^.stop()


def test_tls13_only_refuses_tls12() raises:
    var ctx = serving(tls13_only=True)
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "hello", opts("max=1.2"))
    var d = ServerDriver(l, ctx)
    var e = _failure(d)
    assert_equal(e.category, Category.PROTOCOL, String(e))
    _ = c.expect("ERROR")
    c^.stop()


def test_alpn_picks_the_servers_protocol() raises:
    var ctx = serving(alpn=["http/1.1"])
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "hello", opts("alpn=h2,http/1.1"))
    var d = ServerDriver(l, ctx)
    _ = d.serve()
    assert_true(c.expect("OK").endswith(" http/1.1"))
    assert_equal(d.tls.alpn(), "http/1.1")
    c^.stop()


def test_an_alpn_offer_without_a_common_protocol_is_refused_with_an_alert() raises:
    """TS5: a client offering only h2 gets no_application_protocol."""
    var ctx = serving(alpn=["http/1.1"])
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "hello", opts("alpn=h2"))
    var d = ServerDriver(l, ctx)
    var e = _failure(d)
    assert_equal(e.category, Category.ALPN, String(e))
    var seen = c.expect("ERROR")
    assert_true("NO_APPLICATION_PROTOCOL" in seen, seen)
    c^.stop()


def test_a_client_without_alpn_is_served() raises:
    var ctx = serving(alpn=["http/1.1"])
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "hello")
    var d = ServerDriver(l, ctx)
    _ = d.serve()
    assert_true(c.expect("OK").endswith(" -"))
    c^.stop()


def test_an_empty_alpn_list_refuses_every_offer() raises:
    var ctx = serving(alpn=[])
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "hello", opts("alpn=http/1.1"))
    var d = ServerDriver(l, ctx)
    var e = _failure(d)
    assert_equal(e.category, Category.ALPN, String(e))
    c^.stop()


def test_an_unknown_sni_is_refused_before_any_data() raises:
    """TS6: the client asks for a name the server does not serve (it skips
    its own checks, so the handshake ends): the server fails at its gate,
    and the client's request gets no answer."""
    var ctx = serving()
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "hello", opts("name=other.test", "verify=none"))
    var d = ServerDriver(l, ctx)
    var e = _failure(d)
    assert_equal(e.category, Category.HOST_MISMATCH, String(e))
    assert_true("other.test" in e.detail, String(e))
    var rest = c.rest()
    assert_false("REPLY echo" in rest, rest)
    c^.stop()


def test_sni_is_normalized_and_an_ip_client_sends_none() raises:
    var ctx = serving()
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "hello", opts("name=LocalHost", "verify=none"))
    var d = ServerDriver(l, ctx)
    _ = d.serve()
    assert_equal(d.tls.server_name(), "localhost")
    assert_equal(c.expect("REPLY"), "REPLY echo:ping")
    c^.stop()
    var c2 = client_peer(Int(l.local_addr().port()), "hello", opts("name=127.0.0.1"))
    var d2 = ServerDriver(l, ctx)
    _ = d2.serve()
    assert_equal(d2.tls.server_name(), "")
    assert_equal(c2.expect("REPLY"), "REPLY echo:ping")
    c2^.stop()


def test_no_ticket_and_no_resumption() raises:
    """TS4: no session ticket is issued, and a second connection offering
    the first one's session gets a full handshake."""
    var ctx = serving()
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "reconnect")
    var d = ServerDriver(l, ctx)
    _ = d.serve()
    var d2 = ServerDriver(l, ctx)
    _ = d2.serve()
    assert_equal(c.expect("TICKET"), "TICKET False")
    assert_equal(c.expect("REUSED"), "REUSED False")
    c^.stop()


def test_an_end_without_close_notify_is_a_truncation() raises:
    var ctx = serving()
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "hello", opts("close=abrupt"))
    var d = ServerDriver(l, ctx)
    var e = _failure(d)
    assert_equal(e.category, Category.TRUNCATED, String(e))
    c^.stop()


def test_a_client_hello_that_never_ends_is_cut_at_the_limit() raises:
    """TS8: 100 KiB of a ClientHello claiming 128 KiB; the server stops at
    CLIENT_HELLO_LIMIT, where OpenSSL alone would read on."""
    var ctx = serving()
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "junk")
    var d = ServerDriver(l, ctx)
    var e = _failure(d)
    assert_equal(e.category, Category.RESOURCE, String(e))
    assert_true(d.received <= CLIENT_HELLO_LIMIT + FEED_LIMIT, String(d.received))
    c^.stop()


def test_finite_field_groups_are_refused() raises:
    """TS2: a client offering only ffdhe2048 (TLS 1.3) gets no handshake."""
    var ctx = serving()
    var l = listener()
    var c = ClientProc(command=s_client(Int(l.local_addr().port()), "-groups", "ffdhe2048", "-servername", "localhost"))
    var d = ServerDriver(l, ctx)
    var e = _failure(d)
    assert_equal(e.category, Category.PROTOCOL, String(e))
    var out = c.rest()
    assert_true("alert" in out or "error" in out, out)
    c^.stop()


def test_tls12_suites_outside_the_profile_are_refused() raises:
    """TS1: DHE, static RSA and CBC suites get no handshake, even from a
    server with an RSA certificate."""
    var ctx = serving(cert="rsa")
    var suites: List[String] = ["DHE-RSA-AES128-GCM-SHA256", "AES128-GCM-SHA256", "ECDHE-RSA-AES128-SHA", "ECDHE-RSA-AES128-SHA256"]
    for suite in suites:
        var l = listener()
        var c = ClientProc(command=s_client(Int(l.local_addr().port()), "-tls1_2", "-cipher", suite, "-servername", "localhost"))
        var d = ServerDriver(l, ctx)
        var e = _failure(d)
        assert_equal(e.category, Category.PROTOCOL, String(suite, ": ", e))
        c^.stop()
    # And an RSA certificate does serve ECDHE-RSA with AES-GCM.
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "hello", opts("max=1.2"))
    var d = ServerDriver(l, ctx)
    _ = d.serve()
    assert_true(c.expect("OK").startswith("OK TLSv1.2 ECDHE-RSA-AES"))
    c^.stop()


def test_tls13_ccm_suites_are_refused() raises:
    var ctx = serving()
    var l = listener()
    var c = ClientProc(command=s_client(Int(l.local_addr().port()), "-tls1_3", "-ciphersuites", "TLS_AES_128_CCM_SHA256", "-servername", "localhost"))
    var d = ServerDriver(l, ctx)
    var e = _failure(d)
    assert_equal(e.category, Category.PROTOCOL, String(e))
    c^.stop()


def test_renegotiation_is_refused() raises:
    """TS1: TLS 1.2 renegotiation (s_client's R) is answered with
    no_renegotiation; the client gives up, and the line it sends next is
    never served."""
    var ctx = serving()
    var l = listener()
    var c = ClientProc(command=s_client(Int(l.local_addr().port()), "-tls1_2", "-servername", "localhost"), stdin=["hello\n", "R\n", "after\n"])
    var d = ServerDriver(l, ctx)
    var e = _failure(d)
    assert_equal(e.category, Category.PROTOCOL, String(e))
    var out = c.rest()
    assert_true("echo:hello" in out, out)
    assert_true("RENEGOTIATING" in out and "no renegotiation" in out, out)
    assert_false("echo:after" in out, out)
    c^.stop()


def test_the_server_closes_first() raises:
    """TS10: close_notify from the server after its answer; the client's
    in reply ends the connection cleanly."""
    var ctx = serving()
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "hello", opts("close=wait"))
    var d = ServerDriver(l, ctx)
    var e = d.serve(close_after=1)
    assert_false(Bool(e), String(e.value()) if e else "")
    assert_equal(c.expect("REPLY"), "REPLY echo:ping")
    assert_equal(c.expect("SERVER_CLOSED"), "SERVER_CLOSED")
    assert_true(d.tls.is_closed())
    c^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
