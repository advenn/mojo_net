"""A TLS client and server of this package joined in memory (not a test
file itself): `Pair` moves every byte by hand, so a test decides what each
side is fed and when. The client may call libssl directly for what `tls`
never does (`key_update`: a test may bind what `tls` does not)."""

from std.ffi import OwnedDLHandle, c_int
from std.testing import assert_equal, assert_true

from bytes.buffer import ByteBuffer
from tls import TlsClient, TlsError, TlsEventKind, TlsServer
from tls_util import serving, trusting

comptime KeyUpdate = def(Int, c_int) thin abi("C") -> c_int


def key_update_fn(path: String) raises -> KeyUpdate:
    """libssl's `SSL_key_update` (test code may bind what `tls` does not)."""
    var h = OwnedDLHandle(path)
    var p = h.get_symbol[NoneType]("SSL_key_update")
    if not p:
        raise Error("no SSL_key_update")
    var addr = Int(p.value())
    return Pointer(to=addr).unsafe_bitcast[KeyUpdate]()[]


def drop(mut src: ByteBuffer, n: Int):
    try:
        src.consume(n)
    except:
        pass


def flow(mut src: ByteBuffer, mut dst: TlsServer, mut got: Int) raises TlsError:
    """Move `src` into the server, as much as it takes, counting the data
    it delivers."""
    while len(src) > 0 and dst.feed_capacity() > 0:
        var n = min(len(src), dst.feed_capacity())
        dst.feed(src.readable_span()[0:n])
        drop(src, n)
        while True:
            var ev = dst.next_event()
            if not ev:
                break
            if ev.value().kind == TlsEventKind.DATA:
                got += len(ev.value().data)


def flow_c(mut src: ByteBuffer, mut dst: TlsClient) raises TlsError:
    while len(src) > 0 and dst.feed_capacity() > 0:
        var n = min(len(src), dst.feed_capacity())
        dst.feed(src.readable_span()[0:n])
        drop(src, n)
    while dst.next_event():
        pass


struct Pair(Movable):
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
            flow(self.a, self.s, self.got)
            _ = self.s.poll_transmit(self.b)
            flow_c(self.b, self.c)
        assert_true(self.c.is_established() and self.s.is_established())

    def to_server(mut self) raises TlsError:
        _ = self.c.poll_transmit(self.a)
        flow(self.a, self.s, self.got)
        _ = self.s.poll_transmit(self.b)
        self.b.clear()  # (the server's replies: the client would read them)

    def key_update(mut self, requested: Bool) raises:
        ref L = self.c._e._lib[]
        var f = key_update_fn(L.path)
        assert_equal(f(self.c._e._ssl, c_int(1 if requested else 0)), 1)
        _ = L.SSL_do_handshake(self.c._e._ssl)  # (queues it)
