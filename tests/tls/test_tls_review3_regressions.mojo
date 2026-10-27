"""Regression tests for the third TLS review's findings (TR3, 2026-10-27;
docs/tls.md, "Review"). Each fails on the code before its fix; those that
need a fault seam are in test_tls_review3_regressions_faults.mojo, and the
HTTP client's in tests/http/test_https_review3_regressions_faults.mojo."""

from std.ffi import OwnedDLHandle, c_int
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer

from tls import Category, ClientConfig, ClientContext, ServerConfig, TlsClient, TlsServer, Trust
from tls.consts import (
    SSL_CTRL_SET_MAX_PROTO_VERSION,
    SSL_CTRL_SET_TLSEXT_HOSTNAME,
    SSL_OP_NO_RENEGOTIATION,
    TLS1_2_VERSION,
    TLSEXT_NAMETYPE_host_name,
)
from tls.engine import CLIENT_QUIET_LIMIT
from tls.client import dns_within
from tls.target import Target
from tls_pair import Pair, flow, flow_c
from tls_util import Peer, connect, connect_error, opts, pki, serving, trusting


def _echo_ok(mut peer: Peer, name: StringSlice) raises:
    """A verified connection to `peer` as `name` that carries data."""
    var s = connect(peer, trusting(), name)
    s.write_all("ping\n".as_bytes())
    var buf = List[UInt8](length=16, fill=0)
    var n = s.read(Span(buf))
    assert_equal(String(unsafe_from_utf8=Span(buf)[0:n]), "echo:ping\n")
    s^.close()


# ---- VER-1 ---------------------------------------------------------------------


def test_ver1_a_wildcard_does_not_reach_a_name_its_ca_excludes() raises:
    """VER-1: root -> intermediate (excludes DNS:secret.wild.test) -> leaf
    (DNS:*.wild.test). OpenSSL checks the constraint against the SAN as
    written, which the exclusion does not cover, so the leaf was accepted
    as secret.wild.test: Go's CVE-2025-61727. Now the gate refuses it."""
    var peer = Peer("echo", opts("cert=nc_wild"))
    var e = connect_error(peer.port, trusting(), "secret.wild.test")
    assert_equal(e.category, Category.HOST_MISMATCH, String(e))
    assert_true("excludes" in String(e), String(e))
    peer^.stop()
    var upper = Peer("echo", opts("cert=nc_wild"))
    e = connect_error(upper.port, trusting(), "SECRET.Wild.Test.")  # (the same name)
    assert_equal(e.category, Category.HOST_MISMATCH, String(e))
    upper^.stop()


def test_ver1_names_the_constraints_allow_still_connect() raises:
    """The check refuses only the excluded name: the same wildcard leaf
    serves its other names, and a wildcard under a CA that only permits
    names (a wildcard within them matches only names within them) is not
    refused at all."""
    var other = Peer("echo", opts("cert=nc_wild"))
    _echo_ok(other, "public.wild.test")
    other^.stop()
    var permitted = Peer("echo", opts("cert=nc_perm_wild"))
    _echo_ok(permitted, "secret.wild.test")
    permitted^.stop()
    # OpenSSL itself refuses the excluded name written out (48).
    var exact = Peer("echo", opts("cert=nc_exact"))
    var e = connect_error(exact.port, trusting(), "secret.wild.test")
    assert_equal(e.category, Category.UNTRUSTED, String(e))
    assert_equal(e.verify_code, 48, String(e))
    exact^.stop()


def test_ver1_subtree_matching() raises:
    """`dns_within` against RFC 5280 4.2.1.10 (and OpenSSL's nc_dns)."""
    var cases: List[Tuple[String, String, Bool]] = [
        ("secret.wild.test", "secret.wild.test", True),
        ("a.secret.wild.test", "secret.wild.test", True),
        ("xsecret.wild.test", "secret.wild.test", False),
        ("wild.test", "secret.wild.test", False),
        ("secret.wild.test", "SECRET.Wild.TEST", True),
        ("a.wild.test", ".wild.test", True),
        ("wild.test", ".wild.test", False),
        ("anything.test", "", True),
        ("secret.wild.test", "test", True),
        ("secret.wild.test", "est", False),
    ]
    for c in cases:
        assert_equal(dns_within(c[0].as_bytes(), c[1].as_bytes()), c[2], String(c[0], " in ", c[1]))


# ---- VER-3 ---------------------------------------------------------------------


def test_ver3_an_ipv4_mapped_address_is_its_ipv4_identity() raises:
    """VER-3: `::ffff:127.0.0.1` reaches 127.0.0.1 (a dual-stack socket
    sends to the IPv4 address), but the identity checked was the 16-byte
    form: a certificate for IP:127.0.0.1 was refused, and a constraint
    excluding 127.0.0.0/8 would not have applied to it. Now it is the
    4-byte IPv4 address, as Go's net.IP.Equal has it."""
    var t = Target("::ffff:127.0.0.1")
    assert_true(t.is_ip)
    assert_equal(len(t.ip), 4)
    assert_equal(Int(t.ip[0]), 127)
    assert_equal(Int(t.ip[3]), 1)
    var peer = Peer("echo")
    _echo_ok(peer, "::ffff:127.0.0.1")  # (good: IP:127.0.0.1, IP:::1)
    peer^.stop()


# ---- VER-4 ---------------------------------------------------------------------


def test_ver4_a_trust_mark_makes_an_anchor_as_documented() raises:
    """VER-4: no partial chains (TC2) holds for plain certificates: an
    intermediate alone in the CA file is no anchor. A TRUSTED CERTIFICATE
    block marked for serverAuth (`openssl x509 -addtrust serverAuth
    -trustout`) is one, since OpenSSL honours the file's own trust marks
    (and its distrust marks): docs/tls.md says so now. This pins both."""
    var plain = Peer("echo", opts("cert=chained", "nochain=1"))
    var e = connect_error(plain.port, trusting("inter"), "localhost")
    assert_equal(e.category, Category.UNTRUSTED, String(e))
    plain^.stop()
    var marked = Peer("echo", opts("cert=chained", "nochain=1"))
    var s = connect(marked, trusting("inter.trusted"), "localhost")
    s^.close()
    marked^.stop()


# ---- ENG-1 ---------------------------------------------------------------------


def _replies_after_one_feed(behind_finished: Bool) raises -> Tuple[Int, String]:
    """1,300 requested key updates (27 bytes each), fed to the server in
    one `feed_capacity()` piece: what the server queued to send, and how it
    failed."""
    var p = Pair()
    if behind_finished:
        _ = p.c.poll_transmit(p.a)  # (ClientHello)
        flow(p.a, p.s, p.got)
        _ = p.s.poll_transmit(p.b)
        flow_c(p.b, p.c)  # (the client is established, its Finished queued)
        p.b.clear()
    else:
        p.handshake()
    for _ in range(1300):
        p.key_update(True)
    _ = p.c.poll_transmit(p.a)
    var n = min(len(p.a), p.s.feed_capacity())
    assert_true(n >= 30000, String(n))
    p.s.feed(p.a.readable_span()[0:n])
    var why = String()
    try:
        while p.s.next_event():
            pass
    except e:
        why = String(e)
    return (p.s.pending_transmit(), why)


def test_eng1_the_quiet_budget_holds_within_one_feed() raises:
    """ENG-1: the client's quiet budget (4 KiB, about 150 key updates) was
    checked once a whole feed was read, and OpenSSL reads every record in
    its read BIO in one call, answering each key update: one 32 KiB feed
    got 1,213 of them answered (about 21 ms of a server core) before the
    connection failed, and the 32 KB of replies went out after the
    failure. Records now go to OpenSSL one at a time, the budget checked
    after each; the same holds for key updates behind the Finished."""
    for behind in [False, True]:
        var r = _replies_after_one_feed(behind)
        assert_true("without any data" in r[1], String(behind, ": ", r[1]))
        assert_true(r[0] <= CLIENT_QUIET_LIMIT + 512, String(behind, ": ", r[0], " bytes queued"))


# ---- ENG-2 ---------------------------------------------------------------------

comptime _ClearOptions = def(Int, UInt64) thin abi("C") -> UInt64
comptime _Renegotiate = def(Int) thin abi("C") -> c_int
comptime _SetCipherList = def(Int, Pointer[UInt8, MutAnyOrigin]) thin abi("C") -> c_int
comptime _SSL_CTRL_SET_MAX_SEND_FRAGMENT: c_int = 52


def _records(data: Span[UInt8, _]) -> List[Tuple[Int, Int]]:
    """(content type, length with header) of each whole record in `data`."""
    var out = List[Tuple[Int, Int]]()
    var i = 0
    while i + 5 <= len(data):
        var n = 5 + (Int(data[i + 3]) << 8 | Int(data[i + 4]))
        if i + n > len(data):
            break
        out.append((Int(data[i]), n))
        i += n
    return out^


def test_eng2_a_split_handshake_message_waits_rather_than_fails() raises:
    """ENG-2: once a record holding the start of a peer's handshake message
    has been read (a TLS 1.2 renegotiation ClientHello split into 512-byte
    records here), OpenSSL can neither encrypt nor send close_notify until
    the rest arrives. `write` failed the connection with a protocol error
    ("SSL_get_error 2"), and `close` claimed close_notify was sent when it
    was not, so the peer saw a cut. Now `write` takes nothing and says it
    waits for input, `has_unread_input()` holds, and close_notify goes once
    the message has ended (after the server's no_renegotiation alert)."""
    var c = TlsClient(ClientConfig(trust=Trust.ca_file(pki() + "/root.pem"), alpn=["http/1.1"]).build(), "localhost")
    var s = TlsServer(serving(alpn=["http/1.1"]))
    ref L = s._e._lib[]
    _ = L.SSL_ctrl(s._e._ssl, SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_2_VERSION, 0)  # (renegotiation is TLS 1.2's)
    var a = ByteBuffer()
    var b = ByteBuffer()
    var got = 0
    for _ in range(10):
        _ = c.poll_transmit(a)
        flow(a, s, got)
        _ = s.poll_transmit(b)
        flow_c(b, c)
    assert_true(c.is_established() and s.is_established())
    assert_equal(s.version(), "TLSv1.2")
    # The client renegotiates, with libssl directly (tls never does).
    var h = OwnedDLHandle(L.path)
    var clear = h.get_symbol[NoneType]("SSL_clear_options")
    var reneg = h.get_symbol[NoneType]("SSL_renegotiate")
    var ciphers = h.get_symbol[NoneType]("SSL_set_cipher_list")
    assert_true(Bool(clear) and Bool(reneg) and Bool(ciphers))
    var clear_addr = Int(clear.value())
    var reneg_addr = Int(reneg.value())
    var ciphers_addr = Int(ciphers.value())
    _ = Pointer(to=clear_addr).unsafe_bitcast[_ClearOptions]()[](c._e._ssl, SSL_OP_NO_RENEGOTIATION)
    _ = L.SSL_ctrl(c._e._ssl, _SSL_CTRL_SET_MAX_SEND_FRAGMENT, 512, 0)
    # A ClientHello of more than 512 bytes (ALPN goes in the first one only):
    # every cipher suite, and a long server name.
    var all = List[UInt8]("ALL:COMPLEMENTOFALL:@SECLEVEL=0".as_bytes())
    all.append(0)
    assert_equal(Pointer(to=ciphers_addr).unsafe_bitcast[_SetCipherList]()[](c._e._ssl, all.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()), 1)
    var name = List[UInt8]((String("a") * 63 + "." + String("b") * 63 + "." + String("c") * 63 + "." + String("d") * 61).as_bytes())  # (253 bytes)
    name.append(0)
    _ = L.SSL_ctrl_str(c._e._ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, name.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]())
    _ = len(all) + len(name)
    assert_equal(Pointer(to=reneg_addr).unsafe_bitcast[_Renegotiate]()[](c._e._ssl), 1)
    _ = L.SSL_do_handshake(c._e._ssl)  # (queues the ClientHello)
    a.clear()
    _ = c.poll_transmit(a)
    var recs = _records(a.readable_span())
    assert_true(len(recs) >= 2, String(len(recs), " records"))
    var first = recs[0][1]
    s.feed(a.readable_span()[0:first])
    assert_true(s.has_unread_input(), "the message in progress went unseen")
    var x = List[UInt8]("x".as_bytes())
    assert_equal(s.write(Span(x)), 0)
    assert_true(s.wants_input())
    s.close()
    b.clear()
    _ = s.poll_transmit(b)
    assert_equal(len(_records(b.readable_span())), 0, "close_notify cannot go yet")
    s.feed(a.readable_span()[first:])
    assert_false(s.has_unread_input())
    b.clear()
    _ = s.poll_transmit(b)
    var alerts = 0
    for r in _records(b.readable_span()):
        if r[0] == 21:
            alerts += 1
    assert_equal(alerts, 2, "no_renegotiation, then close_notify")
    _ = h^


# ---- API-1 ---------------------------------------------------------------------


def test_api1_contexts_can_share_one_openssl() raises:
    """API-1: every `build()` loads OpenSSL into a library context of its
    own, 3 of the process's 1,024 thread-specific keys each, so about 330
    live contexts used them all up (and other code needing one failed with
    them). `build(sharing=...)` builds on another context's OpenSSL: 400
    of them, and a server's, hold one library context, and connect."""
    var first = trusting()
    var all = List[ClientContext]()
    for _ in range(400):
        all.append(ClientConfig(trust=Trust.ca_file(pki() + "/root.pem")).build(sharing=first))
    for c in all:
        assert_equal(c._library()[].libctx, first._library()[].libctx)
    var server = TlsServer(serving(alpn=[]))
    var shared = ServerConfig(
        certificate=pki() + "/good.chain.pem", key=pki() + "/good.key", names=["localhost"]
    ).build(sharing=first)
    assert_equal(shared._library()[].libctx, first._library()[].libctx)
    _ = server^
    var peer = Peer("echo")
    var s = connect(peer, all[399], "localhost")
    s^.close()
    peer^.stop()
    _ = all^


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
