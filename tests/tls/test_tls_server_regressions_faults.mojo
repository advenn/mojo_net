"""Regression test for the review of the TLS server side (T2), built with
-D MOJO_NET_FAULTS=1: a `tls13_only` server's gate checks the version
again (finding 4), so that the TLS 1.3 floor does not rest on OpenSSL's
minimum alone. The seam makes `SSL_version` say TLS 1.2 although the
handshake was TLS 1.3. Each test starts with `fault.clear()`."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from linux import Errno, fault
from tls import Category, ServerContext, TlsClient, TlsError, TlsEventKind, TlsServer
from tls.ffi import SEAM_VERSION_LOW
from tls_util import serving, trusting


def _serve(sctx: ServerContext) raises -> Tuple[Int, Optional[TlsError]]:
    """A client that sends a request once established, against a server on
    `sctx`, with the seam saying TLS 1.2 at the server's gate (the
    client's gate makes the same call first): the data the server
    delivered, and how it failed."""
    var c = TlsClient(trusting(alpn=["http/1.1"]), "localhost")
    var s = TlsServer(sctx)
    _ = c.write("GET / HTTP/1.1\r\n\r\n".as_bytes())
    fault.inject(SEAM_VERSION_LOW, Errno(0x0303), skip=1)
    var a = ByteBuffer()
    var b = ByteBuffer()
    var data = 0
    var failure: Optional[TlsError] = None
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
    return (data, failure^)


def test_4_tls13_only_checks_the_version_again() raises:
    fault.clear()
    var refused = _serve(serving(tls13_only=True))
    assert_true(Bool(refused[1]), "the server did not fail")
    assert_equal(refused[1].value().category, Category.PROTOCOL, String(refused[1].value()))
    assert_true("TLS 1.3" in String(refused[1].value()), String(refused[1].value()))
    assert_equal(refused[0], 0)
    assert_equal(fault.pending(), 0)
    # (TLS 1.2 is fine for a server that allows it)
    fault.clear()
    var served = _serve(serving())
    assert_false(Bool(served[1]), String(served[1].value()) if served[1] else "")
    assert_true(served[0] > 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
