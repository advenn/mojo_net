"""The server side's fault seams (built with -D MOJO_NET_FAULTS=1; gate
TG6): each OpenSSL call a server context makes failing, and each part of
the server's gate coming out wrong although OpenSSL passed it. Every case
fails with its category, and a refused connection delivers none of the
client's data. LeakSanitizer (`pixi run tls-asan`) finds nothing left
behind by any of them. Each test starts with `fault.clear()`."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from linux import Errno, ErrorKind, fault
from tls import Category, ServerConfig, TlsClient, TlsError, TlsEventKind, TlsServer
from tls.ffi import (
    SEAM_ALPN,
    SEAM_CHAIN,
    SEAM_CTX_NEW,
    SEAM_EARLY,
    SEAM_KEY,
    SEAM_KEY_MATCH,
    SEAM_LEAF,
    SEAM_READBACK,
    SEAM_REUSED,
    SEAM_SERVER_NAME,
    SEAM_SSL_NEW,
    SEAM_TICKETS,
    SEAM_TIME,
    SEAM_VERSION_LOW,
)
from tls_util import pki, serving, trusting


def _config() raises -> ServerConfig:
    var d = pki()
    return ServerConfig(certificate=d + "/good.chain.pem", key=d + "/good.key", names=["localhost"], alpn=["http/1.1"])


def _build_error(config: ServerConfig) raises -> TlsError:
    try:
        _ = config.build()
    except e:
        return e^
    raise Error("the context built")


def test_server_context_failures() raises:
    fault.clear()
    var cases: List[Tuple[Int, Int]] = [
        (SEAM_CTX_NEW, Category.LIBRARY.value),
        (SEAM_READBACK, Category.LIBRARY.value),
        (SEAM_TICKETS, Category.LIBRARY.value),
        (SEAM_EARLY, Category.LIBRARY.value),
        (SEAM_CHAIN, Category.CREDENTIALS.value),
        (SEAM_KEY, Category.CREDENTIALS.value),
        (SEAM_KEY_MATCH, Category.CREDENTIALS.value),
        (SEAM_LEAF, Category.CREDENTIALS.value),
        (SEAM_TIME, Category.LIBRARY.value),
    ]
    for c in cases:
        fault.inject(c[0], Errno.EIO)
        var e = _build_error(_config())
        assert_equal(e.category.value, c[1], String("seam ", c[0], ": ", e))
        assert_equal(fault.pending(), 0)
    _ = _config().build()  # (and afterwards all is well)


def test_a_server_connection_object_failure() raises:
    fault.clear()
    var ctx = serving()
    fault.inject(SEAM_SSL_NEW, Errno.EIO)
    var kind = ErrorKind.Other
    try:
        _ = TlsServer(ctx)
    except e:
        kind = e.io.kind
    assert_equal(kind, ErrorKind.OutOfMemory)


def _refused(seam: Int, skip: Int, category: Category) raises:
    """With `seam` firing once (after `skip` calls: the client's gate makes
    the same call first), the server must fail with `category` and
    deliver none of the client's data."""
    fault.clear()
    var cctx = trusting(alpn=["http/1.1"])
    var sctx = serving()
    var c = TlsClient(cctx, "localhost")
    var s = TlsServer(sctx)
    _ = c.write("GET / HTTP/1.1\r\n\r\n".as_bytes())  # (sent once the client is established)
    fault.inject(seam, Errno.EIO, skip=skip)
    var a = ByteBuffer()
    var b = ByteBuffer()
    var failure: Optional[TlsError] = None
    var data = 0
    for _ in range(10):
        _ = c.poll_transmit(a)
        if len(a) > 0:
            try:
                s.feed(a.readable_span())
            except:
                pass
            a.clear()
        try:
            _ = s.poll_transmit(b)
        except:
            pass
        if len(b) > 0:
            try:
                c.feed(b.readable_span())
            except:
                pass
            b.clear()
        try:
            while c.next_event():
                pass
        except:
            pass
        try:
            while True:
                var ev = s.next_event()
                if not ev:
                    break
                if ev.value().kind == TlsEventKind.DATA:
                    data += len(ev.value().data)
        except e:
            failure = e^
            break
    assert_true(Bool(failure), String("seam ", seam, ": the server did not fail"))
    assert_equal(failure.value().category, category, String(failure.value()))
    assert_equal(data, 0)
    assert_false(s.is_established())
    assert_equal(fault.pending(), 0)


def test_gate_version() raises:
    _refused(SEAM_VERSION_LOW, 1, Category.PROTOCOL)


def test_gate_resumption() raises:
    _refused(SEAM_REUSED, 1, Category.PROTOCOL)


def test_gate_alpn_not_ours() raises:
    _refused(SEAM_ALPN, 1, Category.ALPN)


def test_gate_server_name() raises:
    _refused(SEAM_SERVER_NAME, 0, Category.HOST_MISMATCH)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
