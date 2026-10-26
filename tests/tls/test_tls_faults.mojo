"""The `tls` package's fault seams (built with -D MOJO_NET_FAULTS=1; gate
TG6): each OpenSSL call failing, `SSL_get_error` saying each code, and each
part of the connection gate (TC9) coming out wrong although OpenSSL passed
it. Every case must fail with its category, latch, and leave the server
without application data (TC10). Each test starts with `fault.clear()`."""

from std.testing import TestSuite, assert_equal, assert_true

from linux import Errno, ErrorKind, fault
from linux.time import Deadline, Duration
from tls import Category, ClientConfig, TlsClient, TlsError, Trust
from tls.ffi import (
    SEAM_ALPN,
    SEAM_ALPN_SET,
    SEAM_BIO_NEW,
    SEAM_BIO_WRITE,
    SEAM_CHECK_HOST,
    SEAM_CHECK_IP,
    SEAM_CTX_NEW,
    SEAM_HANDSHAKE,
    SEAM_LIBCTX,
    SEAM_LOAD_VERIFY,
    SEAM_PEER_CERT,
    SEAM_PEERNAME,
    SEAM_READ,
    SEAM_READBACK,
    SEAM_REUSED,
    SEAM_SET_HOST,
    SEAM_SNI,
    SEAM_SSL_NEW,
    SEAM_VERIFY_RESULT,
    SEAM_VERSION,
    SEAM_VERSION_LOW,
    SEAM_WBIO_NEW,
    SEAM_WRITE,
)
from tls.stream import TlsStream
from tls_util import Peer, connect, connect_error, opts, pki, read_error, trusting


def _build_error(config: ClientConfig) raises -> TlsError:
    try:
        _ = config.build()
    except e:
        return e^
    raise Error("the context built")


def _client_error(name: StringSlice) raises -> TlsError:
    var ctx = trusting()
    try:
        _ = TlsClient(ctx, name)
    except e:
        return e^
    raise Error("the client was made")


def _feed_error(mut tls: TlsClient, data: Span[UInt8, _]) raises -> TlsError:
    try:
        tls.feed(data)
    except e:
        return e^
    raise Error("feed succeeded")


def _event_error(mut tls: TlsClient) raises -> TlsError:
    try:
        _ = tls.next_event()
    except e:
        return e^
    raise Error("next_event succeeded")


def _write_error(mut s: TlsStream, data: Span[UInt8, _]) raises -> TlsError:
    try:
        s.write_all(data)
    except e:
        return e^
    raise Error("write_all succeeded")


def _ca() -> ClientConfig:
    try:
        return ClientConfig(trust=Trust.ca_file(pki() + "/root.pem"))
    except:
        return ClientConfig()


def test_library_and_context_failures() raises:
    fault.clear()
    fault.inject(SEAM_VERSION, Errno.EIO)
    var e = _build_error(_ca())
    assert_equal(e.category, Category.LIBRARY, String(e))
    assert_equal(e.io.kind, ErrorKind.Unsupported)  # (3.4 is refused: TL3)
    fault.inject(SEAM_CTX_NEW, Errno.EIO)
    assert_equal(_build_error(_ca()).category, Category.LIBRARY)
    fault.inject(SEAM_READBACK, Errno.EIO)
    var r = _build_error(_ca())
    assert_equal(r.category, Category.LIBRARY)
    assert_true("did not take" in String(r), String(r))
    assert_equal(fault.pending(), 0)
    _ = _ca().build()  # (and afterwards all is well)


def test_connection_object_failures() raises:
    fault.clear()
    var ctx = trusting()
    fault.inject(SEAM_SSL_NEW, Errno.EIO)
    var e = _client_error("localhost")
    assert_equal(e.category, Category.RESOURCE, String(e))
    assert_equal(e.io.kind, ErrorKind.OutOfMemory)
    fault.inject(SEAM_BIO_NEW, Errno.EIO)
    assert_equal(_client_error("localhost").category, Category.RESOURCE)
    var tls = TlsClient(ctx, "localhost")
    fault.inject(SEAM_BIO_WRITE, Errno.EIO)
    assert_equal(_feed_error(tls, "x".as_bytes()).category, Category.RESOURCE)
    assert_equal(_event_error(tls).category, Category.RESOURCE)  # (latched)
    assert_equal(fault.pending(), 0)


def test_more_setup_failures() raises:
    """The calls that had no seam until the review (TR): each fails with
    its category, and LeakSanitizer (`pixi run tls-asan`) finds nothing
    left behind by any of them."""
    fault.clear()
    fault.inject(SEAM_WBIO_NEW, Errno.EIO)
    assert_equal(_client_error("localhost").category, Category.RESOURCE)
    fault.inject(SEAM_SNI, Errno.EIO)
    assert_equal(_client_error("localhost").category, Category.LIBRARY)
    fault.inject(SEAM_SET_HOST, Errno.EIO)
    assert_equal(_client_error("localhost").category, Category.LIBRARY)
    fault.inject(SEAM_SET_HOST, Errno.EIO)
    assert_equal(_client_error("127.0.0.1").category, Category.LIBRARY)
    fault.inject(SEAM_ALPN_SET, Errno.EIO)
    var alpn: List[String] = ["http/1.1"]
    assert_equal(_build_error(ClientConfig(trust=Trust.ca_file(pki() + "/root.pem"), alpn=alpn^)).category, Category.LIBRARY)
    fault.inject(SEAM_LOAD_VERIFY, Errno.EIO)
    assert_equal(_build_error(_ca()).category, Category.NO_TRUST_STORE)
    fault.inject(SEAM_LIBCTX, Errno(1))
    assert_equal(_build_error(_ca()).category, Category.LIBRARY)
    fault.inject(SEAM_LIBCTX, Errno(2))
    assert_equal(_build_error(_ca()).category, Category.LIBRARY)
    assert_equal(fault.pending(), 0)
    _ = _ca().build()  # (and afterwards all is well)


def test_every_handshake_error_code() raises:
    """Whatever SSL_get_error says during the handshake, other than
    WANT_READ, the connection fails as a protocol error and the server
    sees the handshake fail."""
    fault.clear()
    var codes: List[Int] = [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 99]
    var peer = Peer("echo", opts(String("count=", len(codes))))
    var ctx = trusting()
    for code in codes:
        # skip=1: not the ClientHello, but the first call with server bytes.
        fault.inject(SEAM_HANDSHAKE, Errno(Int32(code)), skip=1)
        var e = connect_error(peer.port, ctx, "localhost")
        assert_equal(e.category, Category.PROTOCOL, String("code ", code, ": ", e))
        _ = peer.handshake_failed()
    assert_equal(fault.pending(), 0)
    peer^.stop()


def test_every_read_error_code() raises:
    fault.clear()
    var codes: List[Int] = [1, 3, 4, 5, 7, 8, 9, 10, 11, 12, 99]
    var peer = Peer("echo", opts(String("count=", len(codes))))
    var ctx = trusting()
    for code in codes:
        var s = connect(peer, ctx)
        fault.inject(SEAM_READ, Errno(Int32(code)))
        s.write_all("x\n".as_bytes())
        var got = List[UInt8]()
        var e = read_error(s, got)
        assert_equal(e.category, Category.PROTOCOL, String("code ", code, ": ", e))
        assert_equal(len(got), 0)
        var again = read_error(s, got)
        assert_equal(again.category, Category.PROTOCOL)
    assert_equal(fault.pending(), 0)
    peer^.stop()


def test_zero_return_from_a_read_is_the_end() raises:
    fault.clear()
    var peer = Peer("echo")
    var s = connect(peer, trusting())
    fault.inject(SEAM_READ, Errno(6))  # (SSL_ERROR_ZERO_RETURN: close_notify)
    s.write_all("x\n".as_bytes())
    var buf = List[UInt8](length=64, fill=0)
    assert_equal(s.read(Span(buf)), 0)
    peer^.stop()


def test_every_write_error_code() raises:
    fault.clear()
    var codes: List[Int] = [1, 2, 3, 4, 5, 6, 99]
    var peer = Peer("sink", opts(String("count=", len(codes))))
    var ctx = trusting()
    for code in codes:
        var s = connect(peer, ctx)
        fault.inject(SEAM_WRITE, Errno(Int32(code)))
        var e = _write_error(s, "never sent".as_bytes())
        assert_equal(e.category, Category.PROTOCOL, String("code ", code, ": ", e))
        var got = List[UInt8]()
        assert_equal(read_error(s, got).category, Category.PROTOCOL)  # (latched)
        _ = s^
        var line = peer.expect("GOT")
        assert_true(line.startswith("GOT 0 "), line)  # (nothing reached the server)
    assert_equal(fault.pending(), 0)
    peer^.stop()


def _gate(seam: Int, value: Errno, name: StringSlice, category: Category, alpn: List[String] = List[String]()) raises:
    """With `seam` firing once, the connection must fail with `category`
    and the server must never complete its handshake."""
    fault.clear()
    var peer = Peer("echo", opts("alpn=http/1.1"))
    fault.inject(seam, value)
    var e = connect_error(peer.port, trusting(alpn=alpn), name)
    assert_equal(e.category, category, String(e))
    assert_equal(fault.pending(), 0)
    _ = peer.handshake_failed()  # (no Finished, no data: TC10)
    peer^.stop()


def test_gate_no_certificate() raises:
    _gate(SEAM_PEER_CERT, Errno.EIO, "localhost", Category.NO_PEER_CERT)


def test_gate_verify_result() raises:
    _gate(SEAM_VERIFY_RESULT, Errno(10), "localhost", Category.EXPIRED)
    _gate(SEAM_VERIFY_RESULT, Errno(20), "localhost", Category.UNTRUSTED)
    _gate(SEAM_VERIFY_RESULT, Errno(62), "localhost", Category.HOST_MISMATCH)


def test_gate_host_check() raises:
    _gate(SEAM_CHECK_HOST, Errno.EIO, "localhost", Category.HOST_MISMATCH)


def test_gate_matched_name() raises:
    _gate(SEAM_PEERNAME, Errno.EIO, "localhost", Category.HOST_MISMATCH)


def test_gate_ip_check() raises:
    _gate(SEAM_CHECK_IP, Errno.EIO, "127.0.0.1", Category.IP_MISMATCH)


def test_gate_version() raises:
    _gate(SEAM_VERSION_LOW, Errno.EIO, "localhost", Category.PROTOCOL)


def test_gate_resumption() raises:
    _gate(SEAM_REUSED, Errno.EIO, "localhost", Category.PROTOCOL)


def test_gate_alpn_not_offered() raises:
    _gate(SEAM_ALPN, Errno.EIO, "localhost", Category.ALPN, ["http/1.1"])


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
