"""Post-handshake messages from `openssl s_server` (tests/tls/s_server_peer.py
drives its k, K, r and P commands; gate TG4): key updates, a renegotiation
request, and plaintext injected into the stream."""

from std.testing import TestSuite, assert_equal, assert_true

from linux.time import Deadline, Duration
from tls import Category, TlsError
from tls.stream import TlsStream
from tls_util import Peer, connect, trusting

comptime _SCRIPT = "tests/tls/s_server_peer.py"


def _read_until(mut s: TlsStream, want: StringSlice, mut got: List[UInt8]) raises TlsError -> Bool:
    """Read into `got` until it holds `want` (True) or the stream ends."""
    var buf = List[UInt8](length=4096, fill=0)
    while not (want in String(from_utf8_lossy=Span(got))):
        var n = s.read(Span(buf))
        if n == 0:
            return False
        got.extend(Span(buf)[0:n])
    return True


def _failure(mut s: TlsStream, mut got: List[UInt8]) raises -> TlsError:
    var buf = List[UInt8](length=4096, fill=0)
    try:
        while True:
            var n = s.read(Span(buf))
            if n == 0:
                break
            got.extend(Span(buf)[0:n])
    except e:
        return e^
    raise Error("the stream ended cleanly")


def test_key_updates() raises:
    """TLS 1.3 KeyUpdate, with and without a request for one back: the
    client keeps reading, answers the request with its own KeyUpdate
    (OpenSSL queues it while reading: TB9), and its data still arrives."""
    var peer = Peer("keyupdate", script=_SCRIPT)
    var s = connect(peer, trusting())
    s.set_deadline(Deadline.after(Duration.from_secs(20)))
    var got = List[UInt8]()
    assert_true(_read_until(s, "two\n", got))
    assert_equal(String(from_utf8_lossy=Span(got)), "one\ntwo\n")
    s.write_all("back\n".as_bytes())
    assert_equal(peer.expect("STEP"), "STEP back")
    got.clear()
    assert_true(_read_until(s, "three\n", got))
    s.write_all("done\n".as_bytes())
    assert_equal(peer.expect("STEP"), "STEP done")
    # s_server quits without close_notify: a truncation, not a clean end.
    var e = _failure(s, got)
    assert_equal(e.category, Category.TRUNCATED, String(e))
    assert_equal(peer.expect("CLIENTHELLOS"), "CLIENTHELLOS 1")
    assert_equal(peer.expect("KEYUPDATES_RECEIVED"), "KEYUPDATES_RECEIVED 1")  # (one asked for, one sent)
    peer^.stop()


def test_renegotiation_is_never_done() raises:
    """TLS 1.2 HelloRequest: renegotiation is off (SSL_OP_NO_RENEGOTIATION),
    so the client never sends a second ClientHello. s_server answers the
    refusal with a fatal alert, which the client reports as a protocol
    error after the data before it."""
    var peer = Peer("renego", script=_SCRIPT)
    var s = connect(peer, trusting())
    assert_equal(s.version(), "TLSv1.2")
    s.set_deadline(Deadline.after(Duration.from_secs(20)))
    var got = List[UInt8]()
    var e = _failure(s, got)
    assert_equal(e.category, Category.PROTOCOL, String(e))
    assert_true(String(from_utf8_lossy=Span(got)).startswith("one\n"))
    assert_equal(peer.expect("CLIENTHELLOS"), "CLIENTHELLOS 1")
    peer^.stop()


def test_plaintext_in_the_stream() raises:
    """Bytes outside any record (s_server's P) end the connection with a
    protocol error; what came before them is delivered, nothing after."""
    var peer = Peer("plaintext", script=_SCRIPT)
    var s = connect(peer, trusting())
    s.set_deadline(Deadline.after(Duration.from_secs(20)))
    var got = List[UInt8]()
    var e = _failure(s, got)
    assert_equal(e.category, Category.PROTOCOL, String(e))
    assert_equal(String(from_utf8_lossy=Span(got)), "one\n")
    peer^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
