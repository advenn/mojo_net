"""Regression tests for the review of the TLS server side (T2), one per
finding (docs/tls.md, "Review"):

1. Key updates between bytes of data kept the quiet budget from ever
   running out (data reset it), so a client could keep a server core busy:
   each key update it asks for costs the server about 25 times its bytes
   of data. The budget (`CLIENT_QUIET_LIMIT` from a client) is now over
   the whole connection, and counts what came with the end of the
   handshake too.
2. The ClientHello bound counted the data a TLS 1.3 client sends behind
   its Finished, so an upload that came with the end of the handshake was
   refused as "too large".
3. The TLS 1.2 path of a refused gate had no test (there the server's
   Finished is still queued when the gate refuses).
And certificate compression, which a libssl built with a compressor would
turn on unasked: off both ways.

Live clients are libssl itself, as in tests/tls/test_server_pair.mojo, and
Python's `ssl` (tests/tls/tls_client_peer.py)."""

from std.ffi import OwnedDLHandle, c_int
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from tls import Category, TlsClient, TlsError, TlsEventKind, TlsServer
from tls.config import OPTIONS
from tls.consts import SSL_OP_NO_RX_CERTIFICATE_COMPRESSION, SSL_OP_NO_TX_CERTIFICATE_COMPRESSION
from tls.engine import CLIENT_HELLO_LIMIT, CLIENT_QUIET_LIMIT, FEED_LIMIT
from tls_util import ServerDriver, client_peer, listener, opts, pattern, serving, trusting

comptime _KeyUpdate = def(Int, c_int) thin abi("C") -> c_int


def _key_update_fn(path: String) raises -> _KeyUpdate:
    """libssl's `SSL_key_update` (test code may bind what `tls` does not)."""
    var h = OwnedDLHandle(path)
    var p = h.get_symbol[NoneType]("SSL_key_update")
    if not p:
        raise Error("no SSL_key_update")
    var addr = Int(p.value())
    return Pointer(to=addr).unsafe_bitcast[_KeyUpdate]()[]


def _drop(mut src: ByteBuffer, n: Int):
    try:
        src.consume(n)
    except:
        pass


def _flow(mut src: ByteBuffer, mut dst: TlsServer, mut got: Int) raises TlsError:
    """Move `src` into the server, as much as it takes, counting the data
    it delivers."""
    while len(src) > 0 and dst.feed_capacity() > 0:
        var n = min(len(src), dst.feed_capacity())
        dst.feed(src.readable_span()[0:n])
        _drop(src, n)
        while True:
            var ev = dst.next_event()
            if not ev:
                break
            if ev.value().kind == TlsEventKind.DATA:
                got += len(ev.value().data)


def _flow_c(mut src: ByteBuffer, mut dst: TlsClient) raises TlsError:
    while len(src) > 0 and dst.feed_capacity() > 0:
        var n = min(len(src), dst.feed_capacity())
        dst.feed(src.readable_span()[0:n])
        _drop(src, n)
    while dst.next_event():
        pass


struct _Pair(Movable):
    var c: TlsClient
    var s: TlsServer
    var a: ByteBuffer
    """Client to server."""
    var b: ByteBuffer
    """Server to client."""
    var got: Int
    """Data the server delivered."""

    def __init__(out self) raises:
        self.c = TlsClient(trusting(), "localhost")
        self.s = TlsServer(serving(alpn=[]))
        self.a = ByteBuffer()
        self.b = ByteBuffer()
        self.got = 0

    def handshake(mut self) raises:
        for _ in range(20):
            _ = self.c.poll_transmit(self.a)
            _flow(self.a, self.s, self.got)
            _ = self.s.poll_transmit(self.b)
            _flow_c(self.b, self.c)
        assert_true(self.c.is_established() and self.s.is_established())

    def to_server(mut self) raises TlsError:
        _ = self.c.poll_transmit(self.a)
        _flow(self.a, self.s, self.got)
        _ = self.s.poll_transmit(self.b)
        self.b.clear()  # (the server's replies: the client would read them)

    def key_update(mut self, requested: Bool) raises:
        ref L = self.c._e._lib[]
        var f = _key_update_fn(L.path)
        assert_equal(f(self.c._e._ssl, c_int(1 if requested else 0)), 1)
        _ = L.SSL_do_handshake(self.c._e._ssl)  # (queues it)


def _flood(every: Int, requested: Bool) raises -> String:
    """Key updates with one byte of data after every `every`: how the
    server failed ("" if it took 5,000 of them)."""
    var p = _Pair()
    p.handshake()
    var one = List[UInt8](length=1, fill=120)
    for i in range(5000):
        p.key_update(requested)
        if (i + 1) % every == 0:
            _ = p.c.write(Span(one))
        try:
            p.to_server()
        except e:
            assert_equal(e.category, Category.PROTOCOL, String(e))
            assert_true("without any data" in String(e), String(e))
            return String("failed after ", i + 1)
    return ""


def test_1_key_updates_between_data_bytes_fail() raises:
    """Within the budget's worth of key updates (27 bytes each), whatever
    data comes between them."""
    var limit = CLIENT_QUIET_LIMIT // 27 + 10
    for every in [100, 10, 2]:
        for requested in [True, False]:
            var how = _flood(every, requested)
            assert_true(how.byte_length() > 0, String("every ", every, ": 5,000 key updates were taken"))
            var n = atol(String(how.split(" ")[2]))
            assert_true(n <= limit, String(how, ", every ", every))


def test_1_key_updates_behind_the_finished_count() raises:
    """Queued behind the client's Finished, in the same flight: they are
    counted from the moment the server is established."""
    var p = _Pair()
    _ = p.c.poll_transmit(p.a)  # (ClientHello)
    _flow(p.a, p.s, p.got)
    _ = p.s.poll_transmit(p.b)  # (the server's flight)
    _flow_c(p.b, p.c)  # (the client is established, its Finished queued)
    assert_true(p.c.is_established())
    for _ in range(400):  # (10,800 bytes)
        p.key_update(True)
    var failed = False
    try:
        p.to_server()
    except e:
        assert_true("without any data" in String(e), String(e))
        failed = True
    assert_true(failed)


def test_1_honest_traffic_stays_within_the_budget() raises:
    """16 KiB records, records of one byte, and a key update now and then
    (one per 64 KiB): never refused, all delivered."""
    var p = _Pair()
    p.handshake()
    var big = pattern(16384)
    var want = 0
    for i in range(256):
        assert_equal(p.c.write(Span(big)), len(big))
        want += len(big)
        if i % 4 == 3:
            p.key_update(True)
        p.to_server()
    var one = List[UInt8](length=1, fill=7)
    for _ in range(3000):
        assert_equal(p.c.write(Span(one)), 1)
        want += 1
        p.to_server()
    for _ in range(50):  # (and a few key updates with no data between)
        p.key_update(False)
    p.to_server()
    assert_equal(p.got, want)


def test_1_data_earns_little_budget() raises:
    """4 MiB of data adds 1 KiB to the budget (a byte per 4 KiB): the
    1,000 key updates that follow it (27 KB) still fail."""
    var p = _Pair()
    p.handshake()
    var big = pattern(16384)
    for _ in range(256):
        assert_equal(p.c.write(Span(big)), len(big))
        p.to_server()
    var failed = 0
    for i in range(1000):
        p.key_update(True)
        try:
            p.to_server()
        except e:
            assert_true("without any data" in String(e), String(e))
            failed = i + 1
            break
    assert_true(failed > 0, "1,000 key updates were taken after the data")
    assert_true(failed <= (CLIENT_QUIET_LIMIT + 1024) // 27 + 10, String(failed))


def test_2_data_behind_the_finished_is_not_handshake() raises:
    """A TLS 1.3 client's first 64 KiB, sent right behind its Finished
    and fed in `feed_capacity()` pieces, are all delivered."""
    for size in [40000, 65536, 200000]:
        var p = _Pair()
        var body = pattern(size)
        var taken = 0
        while taken < size:  # (kept until the client is established)
            var n = p.c.write(Span(body)[taken:])
            if n == 0:
                break
            taken += n
        for _ in range(20):
            _ = p.c.poll_transmit(p.a)
            _flow(p.a, p.s, p.got)
            _ = p.s.poll_transmit(p.b)
            _flow_c(p.b, p.c)
            while taken < size:
                var n = p.c.write(Span(body)[taken:])
                if n == 0:
                    break
                taken += n
        assert_true(p.s.is_established(), String(size))
        assert_equal(p.got, size)


def test_2_a_handshake_unfinished_past_the_limit_still_fails() raises:
    """A ClientHello that never ends (a 128 KiB message, then zeros) is
    cut once the limit is passed: OpenSSL reads at most the limit plus one
    feed."""
    var s = TlsServer(serving(alpn=[]))
    var first: List[UInt8] = [22, 3, 1, 0x40, 0x00, 1, 0x02, 0, 0]  # (a 16 KiB record: ClientHello, 128 KiB)
    first.extend(List[UInt8](length=0x4000 - 4, fill=0))
    var more: List[UInt8] = [22, 3, 1, 0x40, 0x00]
    more.extend(List[UInt8](length=0x4000, fill=0))
    var fed = 0
    var failure: Optional[TlsError] = None
    var k = 0
    while k < 16 and not failure:
        var record = first.copy() if k == 0 else more.copy()
        var off = 0
        while off < len(record) and not failure:
            var n = min(len(record) - off, s.feed_capacity())
            assert_true(n > 0)
            try:
                s.feed(Span(record)[off : off + n])
                while s.next_event():
                    pass
            except e:
                failure = e^
            fed += n
            off += n
        k += 1
    assert_true(Bool(failure), String("fed ", fed))
    assert_equal(failure.value().category, Category.RESOURCE, String(failure.value()))
    assert_true("handshake is too large" in String(failure.value()), String(failure.value()))
    assert_true(fed <= CLIENT_HELLO_LIMIT + FEED_LIMIT, String(fed))


def test_3_tls12_an_unknown_sni_never_completes() raises:
    """At TLS 1.2 the server's Finished is still queued when the gate
    refuses: it never goes out, so the client never completes."""
    var ctx = serving()
    var l = listener()
    var c = client_peer(Int(l.local_addr().port()), "hello", opts("max=1.2", "name=other.test", "verify=none"))
    var d = ServerDriver(l, ctx)
    var e = d.serve()
    assert_true(Bool(e), "the server did not fail")
    assert_equal(e.value().category, Category.HOST_MISMATCH, String(e.value()))
    var rest = c.rest()
    assert_true(rest.startswith("ERROR"), rest)
    assert_false("OK " in rest, rest)
    c^.stop()


def test_certificate_compression_is_off_both_ways() raises:
    var both = SSL_OP_NO_TX_CERTIFICATE_COMPRESSION | SSL_OP_NO_RX_CERTIFICATE_COMPRESSION
    assert_equal(OPTIONS & both, both)
    var sctx = serving()
    var cctx = trusting()
    ref L = sctx._library()[]
    assert_equal(L.SSL_CTX_get_options(sctx._ssl_ctx()) & both, both)
    assert_equal(L.SSL_CTX_get_options(cctx._ssl_ctx()) & both, both)
    _ = sctx
    _ = cctx


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
