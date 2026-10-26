"""TlsClient as a state machine, without a server: what it sends first,
how it bounds and latches, and what it refuses to do before a handshake
(TB8, TB13, TB17, TC10; rules 5-7 of `bytes.codec`)."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from linux import ErrorKind
from tls import Category, ClientConfig, TlsClient, TlsError, Trust
from tls.client import FEED_LIMIT
from tls_util import trusting


def _drain(mut tls: TlsClient) raises -> List[UInt8]:
    var out = ByteBuffer()
    _ = tls.poll_transmit(out)
    return List[UInt8](out.readable_span())


def _contains(hay: List[UInt8], needle: StringSlice) -> Bool:
    var n = needle.as_bytes()
    for i in range(len(hay) - len(n) + 1):
        var ok = True
        for j in range(len(n)):
            if hay[i + j] != n[j]:
                ok = False
                break
        if ok:
            return True
    return False


def _event_error(mut tls: TlsClient) raises -> TlsError:
    """`next_event` must raise; that error."""
    try:
        while tls.next_event():
            pass
    except e:
        return e^
    raise Error("next_event did not raise")


def _feed_error(mut tls: TlsClient, data: Span[UInt8, _]) raises -> TlsError:
    try:
        tls.feed(data)
    except e:
        return e^
    raise Error("feed did not raise")


def _write_error(mut tls: TlsClient) raises -> TlsError:
    try:
        _ = tls.write("x".as_bytes())
    except e:
        return e^
    raise Error("write did not raise")


def test_client_hello_is_queued_at_once() raises:
    var tls = TlsClient(trusting(alpn=["h2", "http/1.1"]), "Example.TEST")
    assert_true(tls.has_transmit())
    var hello = _drain(tls)
    assert_false(tls.has_transmit())
    # A handshake record (22), legacy version 3.1, holding a ClientHello (1).
    assert_equal(hello[0], 22)
    assert_equal(hello[1], 3)
    assert_equal(hello[2], 1)
    assert_equal(Int(hello[3]) * 256 + Int(hello[4]), len(hello) - 5)
    assert_equal(hello[5], 1)
    assert_true(_contains(hello, "example.test"), "SNI carries the normalized name")
    assert_true(_contains(hello, "http/1.1"), "ALPN is offered")
    assert_false(tls.is_established())
    assert_true(not tls.next_event())


def test_no_sni_for_an_address() raises:
    var tls = TlsClient(trusting(), "127.0.0.1")
    var hello = _drain(tls)
    assert_false(_contains(hello, "127.0.0.1"))
    var v6 = TlsClient(trusting(), "::1")
    assert_false(_contains(_drain(v6), "::1"))


def test_poll_transmit_respects_the_room_in_out() raises:
    var tls = TlsClient(trusting(), "localhost")
    var total = 0
    var pieces = 0
    while True:
        var out = ByteBuffer(max_size=10)
        var n = tls.poll_transmit(out)
        assert_equal(n, len(out))
        assert_true(n <= 10)
        if n == 0:
            break
        total += n
        pieces += 1
    assert_true(total > 100 and pieces > 10, String(total, " bytes in ", pieces))
    # Appending never touches what `out` already holds (rule 7).
    var tls2 = TlsClient(trusting(), "localhost")
    var out = ByteBuffer()
    out.write_bytes("keep".as_bytes())
    var n = tls2.poll_transmit(out)
    assert_equal(len(out), 4 + n)
    assert_equal(String(unsafe_from_utf8=out.readable_span()[0:4]), "keep")


def test_garbage_fails_and_latches() raises:
    var tls = TlsClient(trusting(), "localhost")
    _ = _drain(tls)
    tls.feed("HTTP/1.1 200 OK\r\n\r\n".as_bytes())  # (the failure surfaces in next_event)
    var e = _event_error(tls)
    assert_equal(e.category, Category.PROTOCOL, String(e))
    assert_equal(e.io.kind, ErrorKind.InvalidData)
    # It stays, everywhere, without touching OpenSSL again.
    assert_equal(_event_error(tls).category, Category.PROTOCOL)
    assert_equal(_feed_error(tls, "more".as_bytes()).category, Category.PROTOCOL)
    assert_equal(_write_error(tls).category, Category.PROTOCOL)
    assert_equal(tls.feed_capacity(), 0)
    assert_false(tls.is_established())
    # The alert OpenSSL queued is still there to send.
    var alert = _drain(tls)
    assert_true(len(alert) == 0 or alert[0] == 21, "an alert record, if any")


def test_record_overflow() raises:
    var tls = TlsClient(trusting(), "localhost")
    _ = _drain(tls)
    var rec: List[UInt8] = [22, 3, 3, 0x48, 0x01]  # (a record of 18433 bytes: too long)
    tls.feed(Span(rec))
    assert_equal(_event_error(tls).category, Category.PROTOCOL)


def test_end_during_the_handshake() raises:
    var tls = TlsClient(trusting(), "localhost")
    _ = _drain(tls)
    tls.feed_eof()
    var e = _event_error(tls)
    assert_equal(e.category, Category.TRUNCATED, String(e))
    assert_equal(e.io.kind, ErrorKind.UnexpectedEof)
    assert_equal(tls.feed_capacity(), 0)


def test_end_inside_a_record() raises:
    var tls = TlsClient(trusting(), "localhost")
    _ = _drain(tls)
    var rec: List[UInt8] = [22, 3, 3, 0, 40, 2, 0]  # (a ServerHello cut short)
    tls.feed(Span(rec))
    assert_true(not tls.next_event())
    tls.feed_eof()
    assert_equal(_event_error(tls).category, Category.TRUNCATED)


def test_feeding_more_than_the_capacity() raises:
    var tls = TlsClient(trusting(), "localhost")
    assert_equal(tls.feed_capacity(), FEED_LIMIT)
    var big = List[UInt8](length=FEED_LIMIT + 1, fill=22)
    var e = _feed_error(tls, Span(big))
    assert_equal(e.category, Category.RESOURCE)
    assert_equal(e.io.kind, ErrorKind.OutOfMemory)
    assert_equal(_event_error(tls).category, Category.RESOURCE)  # (input was lost: poisoned)


def test_nothing_is_sent_before_the_handshake() raises:
    var tls = TlsClient(trusting(), "localhost")
    _ = _drain(tls)
    assert_equal(tls.write("secret".as_bytes()), 6)  # (kept, not encrypted: TC10)
    assert_false(tls.has_transmit())
    tls.close()  # (no close_notify during a handshake: TB13)
    assert_false(tls.has_transmit())


def test_write_takes_at_most_the_transmit_limit_early() raises:
    from tls.client import TRANSMIT_LIMIT

    var tls = TlsClient(trusting(), "localhost")
    var big = List[UInt8](length=TRANSMIT_LIMIT + 100, fill=1)
    assert_equal(tls.write(Span(big)), TRANSMIT_LIMIT)
    assert_equal(tls.write(Span(big)), 0)


def test_empty_feed_is_nothing() raises:
    var tls = TlsClient(trusting(), "localhost")
    _ = _drain(tls)
    var empty = List[UInt8]()
    tls.feed(Span(empty))
    assert_true(not tls.next_event())
    assert_false(tls.has_transmit())


def test_feed_after_eof() raises:
    var tls = TlsClient(trusting(), "localhost")
    tls.feed_eof()
    var e = _feed_error(tls, "x".as_bytes())
    assert_true(e.category == Category.TRUNCATED or e.io.kind == ErrorKind.InvalidInput, String(e))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
