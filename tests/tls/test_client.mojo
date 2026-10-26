"""TlsStream and TlsClient against a TLS server in Python's `ssl` module
(tests/tls/tls_peer.py) with a throwaway PKI (tests/tls/tls_pki.py): what
is accepted, and every certificate, version and cipher that must be
refused, with its category and OpenSSL's verify code (TC9, TC18)."""

from std.testing import TestSuite, assert_equal, assert_true
from std.time import perf_counter_ns

from bytes.buffer import ByteBuffer
from linux import ErrorKind
from linux.time import Deadline, Duration
from net.addr import SocketAddr
from net.tcp import TcpStream
from tls import Category, ClientContext, TlsClient, TlsError, TlsEventKind
from tls.client import FEED_LIMIT
from tls.ffi import buf
from tls.stream import TlsStream
from tls_util import Peer, connect, connect_error, ipv6_loopback, opts, pattern, read_all, read_error, refused, trusting


def _echo(mut s: TlsStream, line: StringSlice) raises -> List[UInt8]:
    s.write_all(line.as_bytes())
    return read_all(s)


def _expect_echo(got: List[UInt8], line: StringSlice, big: Int = 0) raises:
    var want = List[UInt8]("echo:".as_bytes())
    want.extend(line.as_bytes())
    want.extend(Span(pattern(big)))
    assert_equal(len(got), len(want))
    assert_true(got == want, "echoed bytes differ")


# ---- accepted -----------------------------------------------------------


def test_dns_name_tls13() raises:
    var peer = Peer("echo")
    var s = connect(peer, trusting())
    assert_equal(s.version(), "TLSv1.3")
    assert_equal(s.group(), "X25519MLKEM768")
    assert_equal(s.alpn(), "")
    _expect_echo(_echo(s, "ping\n"), "ping\n")
    var buf = List[UInt8](length=16, fill=0)
    assert_equal(s.read(Span(buf)), 0)  # (and again: the end stays)
    assert_equal(peer.expect("SNI"), "SNI localhost")
    _ = peer.expect("OK TLSv1.3")
    s^.close()
    peer^.stop()


def test_name_is_normalized() raises:
    var peer = Peer("echo")
    var s = connect(peer, trusting(), "LocalHost.")
    _expect_echo(_echo(s, "x\n"), "x\n")
    assert_equal(peer.expect("SNI"), "SNI localhost")
    s^.close()
    peer^.stop()


def test_ipv4_address_without_sni() raises:
    var peer = Peer("echo")
    var s = connect(peer, trusting(), "127.0.0.1")
    _expect_echo(_echo(s, "v4\n"), "v4\n")
    assert_equal(peer.expect("SNI"), "SNI -")  # (RFC 6066: no SNI for an address)
    s^.close()
    peer^.stop()


def test_ipv6_address() raises:
    if not ipv6_loopback("test_ipv6_address"):
        return
    var peer = Peer("echo", opts("host=::1"))
    var s = connect(peer, trusting(), "::1")
    _expect_echo(_echo(s, "v6\n"), "v6\n")
    assert_equal(peer.expect("SNI"), "SNI -")
    s^.close()
    peer^.stop()


def test_tls12_ecdsa() raises:
    var peer = Peer("echo", opts("max=1.2"))
    var s = connect(peer, trusting())
    assert_equal(s.version(), "TLSv1.2")
    assert_true(s.cipher().startswith("ECDHE-ECDSA-"), s.cipher())
    _expect_echo(_echo(s, "12\n"), "12\n")
    s^.close()
    peer^.stop()


def test_tls12_rsa() raises:
    var peer = Peer("echo", opts("max=1.2", "cert=rsa"))
    var s = connect(peer, trusting())
    assert_equal(s.version(), "TLSv1.2")
    assert_true(s.cipher().startswith("ECDHE-RSA-"), s.cipher())
    _expect_echo(_echo(s, "rsa\n"), "rsa\n")
    s^.close()
    peer^.stop()


def test_chain_through_an_intermediate() raises:
    var peer = Peer("echo", opts("cert=chained"))
    var s = connect(peer, trusting())
    _expect_echo(_echo(s, "chain\n"), "chain\n")
    s^.close()
    peer^.stop()


def test_wildcard_one_label() raises:
    var peer = Peer("echo", opts("cert=wildcard"))
    var s = connect(peer, trusting(), "a.wild.test")
    _expect_echo(_echo(s, "w\n"), "w\n")
    s^.close()
    peer^.stop()


def test_alpn_chosen() raises:
    var peer = Peer("echo", opts("alpn=h2,http/1.1"))
    var s = connect(peer, trusting(alpn=["http/1.1"]))
    assert_equal(s.alpn(), "http/1.1")
    _ = peer.expect("OK TLSv1.3 http/1.1")
    s^.close()
    peer^.stop()


def test_alpn_server_without_it() raises:
    var peer = Peer("echo")
    var s = connect(peer, trusting(alpn=["h2", "http/1.1"]))
    assert_equal(s.alpn(), "")  # (no ALPN is allowed: the caller decides)
    s^.close()
    peer^.stop()


def test_one_context_many_connections() raises:
    var ctx = trusting()
    var peer = Peer("echo", opts("count=3"))
    for i in range(3):
        var s = connect(peer, ctx)
        var line = String("n", i, "\n")
        _expect_echo(_echo(s, line), line)
        s^.close()
    peer^.stop()


# ---- refused: the certificate ------------------------------------------


def test_wrong_host() raises:
    var peer = Peer("echo", opts("cert=wrong_host"))
    refused(peer, trusting(), "localhost", Category.HOST_MISMATCH, 62)
    peer^.stop()


def test_subject_cn_is_never_checked() raises:
    var peer = Peer("echo", opts("cert=cn_only"))
    refused(peer, trusting(), "localhost", Category.HOST_MISMATCH, 62)
    peer^.stop()


def test_wildcard_limits() raises:
    var peer = Peer("echo", opts("cert=wildcard", "count=3"))
    refused(peer, trusting(), "b.a.wild.test", Category.HOST_MISMATCH, 62)  # (one label only)
    refused(peer, trusting(), "wild.test", Category.HOST_MISMATCH, 62)
    refused(peer, trusting(), "a.other.test", Category.HOST_MISMATCH, 62)
    peer^.stop()


def test_partial_wildcard() raises:
    var peer = Peer("echo", opts("cert=partial_wild"))
    refused(peer, trusting(), "ab.wild.test", Category.HOST_MISMATCH, 62)
    peer^.stop()


def test_ip_mismatch() raises:
    var peer = Peer("echo", opts("cert=wrong_host"))
    refused(peer, trusting(), "127.0.0.1", Category.IP_MISMATCH, 64)
    peer^.stop()


def test_ip_spelt_as_a_dns_name() raises:
    var peer = Peer("echo", opts("cert=ip_as_dns"))
    refused(peer, trusting(), "127.0.0.1", Category.IP_MISMATCH, 64)
    peer^.stop()


def test_expired() raises:
    var peer = Peer("echo", opts("cert=expired"))
    refused(peer, trusting(), "localhost", Category.EXPIRED, 10)
    peer^.stop()


def test_not_yet_valid() raises:
    var peer = Peer("echo", opts("cert=future"))
    refused(peer, trusting(), "localhost", Category.EXPIRED, 9)
    peer^.stop()


def test_self_signed() raises:
    var peer = Peer("echo", opts("cert=self_signed"))
    refused(peer, trusting(), "localhost", Category.UNTRUSTED, 18)
    peer^.stop()


def test_unrelated_ca() raises:
    var peer = Peer("echo")
    refused(peer, trusting("other"), "localhost", Category.UNTRUSTED, 20)
    peer^.stop()


def test_missing_intermediate() raises:
    var peer = Peer("echo", opts("cert=chained", "nochain=1"))
    refused(peer, trusting(), "localhost", Category.UNTRUSTED, 20)  # (no AIA fetching)
    peer^.stop()


def test_intermediate_that_is_no_ca() raises:
    var peer = Peer("echo", opts("cert=bad_ca"))
    refused(peer, trusting(), "localhost", Category.UNTRUSTED)
    peer^.stop()


def test_trusting_the_leaf_is_not_enough() raises:
    # PARTIAL_CHAIN is off: a trusted leaf that is not a CA does not anchor.
    var peer = Peer("echo")
    refused(peer, trusting("good"), "localhost", Category.UNTRUSTED)
    peer^.stop()


def test_client_auth_only_certificate() raises:
    var peer = Peer("echo", opts("cert=client_only"))
    refused(peer, trusting(), "localhost", Category.UNTRUSTED, 26)
    peer^.stop()


def test_rsa_1024() raises:
    var peer = Peer("echo", opts("cert=rsa1024", "seclevel=0"))
    refused(peer, trusting(), "localhost", Category.WEAK, 66)
    peer^.stop()


def test_sha1_signature() raises:
    var peer = Peer("echo", opts("cert=sha1", "seclevel=0"))
    refused(peer, trusting(), "localhost", Category.WEAK, 68)
    peer^.stop()


# ---- refused: the protocol ---------------------------------------------


def test_tls11() raises:
    var peer = Peer("echo", opts("min=1.1", "max=1.1", "seclevel=0"))
    refused(peer, trusting(), "localhost", Category.PROTOCOL)
    peer^.stop()


def test_rsa_key_exchange_cbc_cipher() raises:
    var peer = Peer("echo", opts("max=1.2", "cert=rsa", "ciphers=AES128-SHA"))
    refused(peer, trusting(), "localhost", Category.PROTOCOL)
    peer^.stop()


def test_not_tls_at_all() raises:
    var peer = Peer("garbage")
    var e = connect_error(peer.port, trusting(), "localhost")
    assert_equal(e.category, Category.PROTOCOL, String(e))
    peer^.stop()


def test_handshake_deadline() raises:
    var peer = Peer("silent")
    var e = connect_error(peer.port, trusting(), "localhost", Duration.from_millis(300))
    assert_true(e.is_deadline(), String(e))
    peer^.stop()


def _client_error(ctx: ClientContext, name: StringSlice) raises -> TlsError:
    try:
        _ = TlsClient(ctx, name)
    except e:
        return e^
    raise Error(String("accepted the name ", repr(String(name))))


def test_invalid_name_before_any_io() raises:
    var ctx = trusting()
    var names: List[String] = ["", "a..b", "*.x", "127.1", "a b", "x\x00y", "-", "-a.test", "a-.test", "a.test-"]
    for n in names:
        assert_equal(_client_error(ctx, n).category, Category.INPUT)
        if n.byte_length() > 0:  # (an empty server_name means "the host")
            # Through the stream: refused before connecting (port 1 would
            # refuse the connection instead).
            var e = connect_error(1, ctx, n)
            assert_equal(e.category, Category.INPUT, String(e))


# ---- endings and data ---------------------------------------------------


def test_truncation_is_an_error() raises:
    var peer = Peer("truncate")
    var s = connect(peer, trusting())
    s.write_all("go\n".as_bytes())
    var got = List[UInt8]()
    var e = read_error(s, got)
    assert_equal(e.category, Category.TRUNCATED, String(e))
    assert_equal(e.io.kind, ErrorKind.UnexpectedEof)
    assert_equal(String(unsafe_from_utf8=Span(got)), "partial")  # (what came before is delivered)
    var again = read_error(s, got)  # (the failure stays)
    assert_equal(again.category, Category.TRUNCATED)
    assert_equal(len(got), 7)
    peer^.stop()


def test_close_notify_without_reading() raises:
    var peer = Peer("hello")
    var s = connect(peer, trusting())
    assert_equal(String(unsafe_from_utf8=Span(read_all(s))), "hello")
    s^.close()
    peer^.stop()


def test_large_download() raises:
    comptime N = 5 * 1024 * 1024 + 17
    var peer = Peer("echo", opts("big=5242897"))
    var s = connect(peer, trusting())
    _expect_echo(_echo(s, "big\n"), "big\n", N)
    s^.close()
    peer^.stop()


def test_large_upload_and_our_close_notify() raises:
    comptime N = 5 * 1024 * 1024 + 3
    var peer = Peer("sink")
    var s = connect(peer, trusting())
    s.write_all(Span(pattern(N)))
    s^.close()
    assert_equal(peer.expect("GOT"), String("GOT ", N, " close_notify"))
    peer^.stop()


def test_close_after_upload_loses_nothing() raises:
    """Closing must not reset the connection while sent data is still
    queued: the server's TLS 1.3 session tickets sit unread in an
    upload-only client's receive buffer, and Linux answers the close of a
    socket with unread input with a reset, dropping what is not yet
    delivered. The sink has a small receive window and waits before
    reading, so much of the upload is still unsent when `close` is called."""
    comptime N = 8 * 1024 * 1024 + 5
    var peer = Peer("sink", opts("delay=0.5", "rcvbuf=32768"))
    var s = connect(peer, trusting())
    s.write_all(Span(pattern(N)))
    s^.close()
    assert_equal(peer.expect("GOT"), String("GOT ", N, " close_notify"))
    peer^.stop()


def test_close_waits_at_most_its_linger() raises:
    """A server that neither ends the connection nor stops sending does
    not hold `close` past its linger."""
    var quiet = Peer("stall")
    var s = connect(quiet, trusting())
    var t0 = perf_counter_ns()
    s^.close(linger=Duration.from_millis(200))
    var took = perf_counter_ns() - t0
    assert_true(took >= 150_000_000 and took < 2_000_000_000, String(took))
    quiet^.stop()
    var talker = Peer("echo", opts("big=100000000"))
    var t = connect(talker, trusting())
    t.write_all("go\n".as_bytes())
    t0 = perf_counter_ns()
    t^.close(linger=Duration.from_secs(30))  # (cut after _LINGER_MAX bytes, long before)
    took = perf_counter_ns() - t0
    assert_true(took < 5_000_000_000, String(took))
    _ = talker.expect("SERVER_ERROR")  # (cut while sending, not read to its end)
    talker^.stop()


def test_any_receive_size_gives_the_same_data() raises:
    """Rule 4: however the ciphertext is cut, the plaintext is the same."""
    comptime BIG = 200000
    var sizes: List[Int] = [1, 2, 5, 13, 512, 4096, FEED_LIMIT]
    var peer = Peer("echo", opts("big=200000", String("count=", len(sizes))))
    var ctx = trusting()
    for size in sizes:
        var tls = TlsClient(ctx, "localhost")
        var tcp = TcpStream.connect_timeout(_loopback(peer.port), Duration.from_secs(10))
        var out = ByteBuffer()
        var buf = List[UInt8](length=size, fill=0)
        var data = List[UInt8]()
        var kinds = List[Int]()
        _ = tls.write("cut\n".as_bytes())  # (kept until established: TC10)
        var done = False
        while not done:
            while tls.has_transmit():
                _ = tls.poll_transmit(out)
                tcp.write_all(out.readable_span())
                out.clear()
            var room = min(size, tls.feed_capacity())
            var n = tcp.read(Span(buf)[0:room])
            if n == 0:
                tls.feed_eof()
            else:
                tls.feed(Span(buf)[0:n])
            while True:
                var ev = tls.next_event()
                if not ev:
                    break
                kinds.append(ev.value().kind.value)
                if ev.value().kind == TlsEventKind.DATA:
                    data.extend(Span(ev.value().data))
                elif ev.value().kind == TlsEventKind.CLOSED:
                    done = True
        assert_equal(kinds[0], TlsEventKind.ESTABLISHED.value)
        assert_equal(kinds[len(kinds) - 1], TlsEventKind.CLOSED.value)
        _expect_echo(data, "cut\n", BIG)
        tls.close()
    peer^.stop()


def _stale_error(ctx: ClientContext) raises:
    """Leave an error in this thread's OpenSSL error queue, as other code in
    the process might (an invalid cipher list on a scratch context)."""
    ref L = ctx.library()[]
    var scratch = L.SSL_CTX_new_ex(L.libctx, 0, L.TLS_client_method())
    var bogus = List[UInt8]("bogus".as_bytes())
    bogus.append(0)
    assert_equal(L.SSL_CTX_set_cipher_list(scratch, buf(bogus)), 0)
    L.SSL_CTX_free(scratch)
    assert_true(L.ERR_peek_error() != 0, "no error was queued")


def test_stale_openssl_errors_are_ignored() raises:
    """TB6: the error queue is cleared before each call, so an error left by
    someone else neither fails a good connection (SSL_get_error would read
    it as SSL_ERROR_SSL) nor shows up in a failure's detail."""
    var ctx = trusting()
    var peer = Peer("echo", opts("big=100000", "count=2"))
    _stale_error(ctx)
    var s = connect(peer, ctx)
    _stale_error(ctx)
    s.write_all("stale\n".as_bytes())
    _stale_error(ctx)
    _expect_echo(read_all(s), "stale\n", 100000)
    s^.close()
    var bad = trusting("other")
    _stale_error(bad)
    var e = connect_error(peer.port, bad, "localhost")
    assert_equal(e.category, Category.UNTRUSTED)
    assert_true(not ("cipher" in String(e)), String(e))
    peer^.stop()


def test_feeding_without_draining_is_bounded() raises:
    """Rule 5 and TB17: undelivered plaintext counts against the feed room,
    so a driver that feeds without draining gets room 0, not a growing
    queue; after a drain the room is back."""
    var peer = Peer("echo", opts("big=300000"))
    var tls = TlsClient(trusting(), "localhost")
    var tcp = TcpStream.connect_timeout(_loopback(peer.port), Duration.from_secs(10))
    tcp.set_deadline(Deadline.after(Duration.from_secs(10)))
    var out = ByteBuffer()
    var buf = List[UInt8](length=FEED_LIMIT, fill=0)
    _ = tls.write("x\n".as_bytes())
    var established = False
    var fed = 0
    while tls.feed_capacity() > 0:
        while tls.has_transmit():
            _ = tls.poll_transmit(out)
            tcp.write_all(out.readable_span())
            out.clear()
        var n = tcp.read(Span(buf)[0 : tls.feed_capacity()])
        assert_true(n > 0, "the server ended early")
        tls.feed(Span(buf)[0:n])
        if established:
            fed += n
        elif tls.is_established():
            established = True
            while tls.next_event():  # (drain the handshake's events once)
                pass
    assert_true(fed > 0)
    var held = 0
    while True:
        var ev = tls.next_event()
        if not ev:
            break
        held += len(ev.value().data)
    assert_true(held > 0 and held <= FEED_LIMIT, String(held, " bytes held"))
    assert_true(tls.feed_capacity() > 0)
    peer^.stop()


def _loopback(port: Int) raises -> SocketAddr:
    return SocketAddr.parse(String("127.0.0.1:", port))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
