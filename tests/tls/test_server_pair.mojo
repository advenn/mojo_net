"""`TlsClient` and `TlsServer` against each other in one process, with
every byte between them under a seed (T2; gate TG5's "after T2" form, in
docs/research/tls_with_openssl.md): seeded split points in both
directions, then seeded damage (a flipped bit, a lost, repeated or
inserted byte, or a cut), in the handshake or the data.

The oracle needs no TLS knowledge. When nothing more moves, the
connection ends (each side gets the end of its input). Then each side
has either received exactly the other's bytes, or failed after receiving
a prefix of them; it never received bytes the other did not send, and the
exchange settled within an iteration bound. MOJO_NET_TLS_SEEDS=<n> runs
more seeds (200 by default) and MOJO_NET_TLS_SEED=<first> replays from
one; a failure names its seed.

Also: a KeyUpdate flood from the client (made with libssl's
`SSL_key_update`, which the `tls` package does not bind) fails the
server's connection, whether or not the server's replies are sent (TS9)."""

from std.ffi import OwnedDLHandle, c_int
from std.os import getenv
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from tls import Category, ClientContext, ServerContext, TlsClient, TlsError, TlsEventKind, TlsServer
from tls.engine import FEED_LIMIT
from tls_util import pattern, serving, trusting

comptime _C_BYTES = 20000
comptime _S_BYTES = 70000
comptime _STEPS = 50000

comptime _NONE = 0
comptime _FLIP = 1
comptime _DROP = 2
comptime _DUP = 3
comptime _INSERT = 4
comptime _CUT = 5


struct Rng(Movable):
    """A xorshift64* generator: the seed decides every choice."""

    var s: UInt64

    def __init__(out self, seed: Int):
        self.s = UInt64(seed) * 0x9E3779B97F4A7C15 + 1

    def next(mut self) -> UInt64:
        self.s ^= self.s >> 12
        self.s ^= self.s << 25
        self.s ^= self.s >> 27
        return self.s * 0x2545F4914F6CDD1D

    def below(mut self, n: Int) -> Int:
        return Int(self.next() % UInt64(max(n, 1)))


struct Damage(Movable):
    var kind: Int
    var to_server: Bool
    var at: Int
    """Offset in that direction's byte stream."""
    var bit: Int
    var done: Bool

    def __init__(out self, kind: Int, to_server: Bool, at: Int, bit: Int):
        self.kind = kind
        self.to_server = to_server
        self.at = at
        self.bit = bit
        self.done = False


struct Side(Movable):
    """What one side received, and how it ended."""

    var got: List[UInt8]
    var closed: Bool
    var failure: Optional[TlsError]
    var moved: Int
    """Ciphertext moved toward this side so far."""
    var eof: Bool

    def __init__(out self):
        self.got = List[UInt8]()
        self.closed = False
        self.failure = None
        self.moved = 0
        self.eof = False


def _is_prefix(got: List[UInt8], want: List[UInt8]) -> Bool:
    if len(got) > len(want):
        return False
    for i in range(len(got)):
        if got[i] != want[i]:
            return False
    return True


def _piece(mut src: ByteBuffer, mut rng: Rng, mut dmg: Damage, to_server: Bool, mut side: Side, room: Int) raises -> List[UInt8]:
    """A seeded piece of `src` (at most `room` bytes), with the damage
    applied if it falls in it."""
    var out = List[UInt8]()
    var n = min(len(src), room, 1 + rng.below(3000 if rng.below(4) == 0 else 300))
    if n <= 0:
        return out^
    out.extend(src.readable_span()[0:n])
    src.consume(n)
    var start = side.moved
    side.moved += n
    if dmg.done or dmg.kind == _CUT or dmg.to_server != to_server or dmg.at < start or dmg.at >= start + n:
        return out^
    dmg.done = True
    var i = dmg.at - start
    if dmg.kind == _FLIP:
        out[i] ^= UInt8(1 << dmg.bit)
    elif dmg.kind == _DROP:
        _ = out.pop(i)
    elif dmg.kind == _DUP:
        out.insert(i, out[i])
    elif dmg.kind == _INSERT:
        out.insert(i, UInt8(dmg.bit * 37 + 1))
    return out^


def _drain_client(mut c: TlsClient, mut side: Side, want: Int) -> Int:
    """Deliver the client's events; returns how many."""
    var n = 0
    try:
        while True:
            var ev = c.next_event()
            if not ev:
                break
            n += 1
            var k = ev.value().kind
            if k == TlsEventKind.DATA:
                side.got.extend(Span(ev.value().data))
                if len(side.got) == want:
                    c.close()
            elif k == TlsEventKind.CLOSED:
                side.closed = True
    except e:
        if not side.failure:
            side.failure = e^
    return n


def _drain_server(mut s: TlsServer, mut side: Side, mut ready: Bool) -> Int:
    var n = 0
    try:
        while True:
            var ev = s.next_event()
            if not ev:
                break
            n += 1
            var k = ev.value().kind
            if k == TlsEventKind.ESTABLISHED:
                ready = True
            elif k == TlsEventKind.DATA:
                side.got.extend(Span(ev.value().data))
            elif k == TlsEventKind.CLOSED:
                side.closed = True
    except e:
        if not side.failure:
            side.failure = e^
    return n


def _end_client(mut c: TlsClient, mut side: Side):
    if side.eof:
        return
    side.eof = True
    try:
        c.feed_eof()
    except:
        pass


def _end_server(mut s: TlsServer, mut side: Side):
    if side.eof:
        return
    side.eof = True
    try:
        s.feed_eof()
    except:
        pass


def _run(seed: Int, kind: Int, cctx: ClientContext, sctx: ServerContext) raises -> String:
    """One connection under `seed`; raises if the oracle breaks, else says
    how it ended ("clean", "failed" or "whole")."""
    var rng = Rng(seed)
    var c_msg = pattern(_C_BYTES)
    var s_msg = List[UInt8](capacity=_S_BYTES)
    for i in range(_S_BYTES):
        s_msg.append(UInt8((i * 7 + 3) % 253))
    var dmg = Damage(kind, rng.below(2) == 0, rng.below(6000), rng.below(8))
    var label = String("seed ", seed, " damage ", kind, " at ", dmg.at, " toward the ", "server" if dmg.to_server else "client")
    var c = TlsClient(cctx, "localhost")
    var s = TlsServer(sctx)
    var cs = Side()  # (the client's: what it received)
    var ss = Side()
    var to_s = ByteBuffer()
    var to_c = ByteBuffer()
    var c_off = 0
    var s_off = 0
    var s_ready = False
    var idle = 0
    var settled = False
    for _ in range(_STEPS):
        var moved = 0
        try:  # (the client writes from the start: kept until established)
            if c_off < len(c_msg):
                var n = c.write(Span(c_msg)[c_off:])
                c_off += n
                moved += n
        except:
            pass
        try:
            if s_ready and s_off < len(s_msg):
                var n = s.write(Span(s_msg)[s_off:])
                s_off += n
                moved += n
                if s_off == len(s_msg):
                    s.close()
        except:
            pass
        try:
            moved += c.poll_transmit(to_s)
        except:
            pass
        try:
            moved += s.poll_transmit(to_c)
        except:
            pass
        if dmg.kind == _CUT and dmg.to_server and ss.moved >= dmg.at:
            to_s.clear()
            _end_server(s, ss)
        if dmg.kind == _CUT and not dmg.to_server and cs.moved >= dmg.at:
            to_c.clear()
            _end_client(c, cs)
        if len(to_s) > 0 and not ss.eof:
            var piece = _piece(to_s, rng, dmg, True, ss, min(s.feed_capacity(), dmg.at - ss.moved if dmg.kind == _CUT and dmg.to_server else FEED_LIMIT))
            moved += len(piece)
            try:
                s.feed(Span(piece))
            except:
                pass
        if len(to_c) > 0 and not cs.eof:
            var piece = _piece(to_c, rng, dmg, False, cs, min(c.feed_capacity(), dmg.at - cs.moved if dmg.kind == _CUT and not dmg.to_server else FEED_LIMIT))
            moved += len(piece)
            try:
                c.feed(Span(piece))
            except:
                pass
        moved += _drain_client(c, cs, len(s_msg))
        moved += _drain_server(s, ss, s_ready)
        idle = idle + 1 if moved == 0 else 0
        if idle >= 3:
            settled = True
            break
    assert_true(settled, String(label, ": still moving after ", _STEPS, " steps"))
    # Nothing moves: the connection ends.
    _end_client(c, cs)
    _end_server(s, ss)
    _ = _drain_client(c, cs, len(s_msg))
    _ = _drain_server(s, ss, s_ready)
    # The oracle.
    assert_true(_is_prefix(ss.got, c_msg), String(label, ": the server received bytes the client did not send"))
    assert_true(_is_prefix(cs.got, s_msg), String(label, ": the client received bytes the server did not send"))
    if cs.failure:
        assert_true(cs.failure.value().category != Category.INPUT, String(label, ": ", cs.failure.value()))
    if ss.failure:
        assert_true(ss.failure.value().category != Category.INPUT, String(label, ": ", ss.failure.value()))
    var whole = len(ss.got) == len(c_msg) and len(cs.got) == len(s_msg) and cs.closed and ss.closed
    var failed = Bool(cs.failure) or Bool(ss.failure)
    if kind == _NONE:
        if failed:
            raise Error(String(label, ": a side failed: ", String(cs.failure.value()) if cs.failure else String(ss.failure.value())))
        assert_true(whole, String(label, ": incomplete: ", len(ss.got), " and ", len(cs.got), " bytes"))
        return "clean"
    assert_true(failed or whole, String(label, ": neither failed nor completed"))
    # Whatever was cut short is a failure, never a clean end.
    if not whole:
        assert_true(failed, String(label, ": cut short without a failure"))
    return "failed" if failed else "whole"


def test_split_points_never_change_the_data() raises:
    var cctx = trusting()
    var sctx = serving(alpn=[])
    for seed in range(1, 41):
        assert_equal(_run(seed, _NONE, cctx, sctx), "clean")


def test_damage_never_changes_the_data() raises:
    var seeds = 200
    var first = 1
    if getenv("MOJO_NET_TLS_SEEDS").byte_length() > 0:
        seeds = atol(getenv("MOJO_NET_TLS_SEEDS"))
    if getenv("MOJO_NET_TLS_SEED").byte_length() > 0:
        first = atol(getenv("MOJO_NET_TLS_SEED"))
    var cctx = trusting()
    var sctx = serving(alpn=[])
    var failed = 0
    var whole = 0
    for seed in range(first, first + seeds):
        var r = _run(seed, _FLIP + (seed % 5), cctx, sctx)
        if r == "failed":
            failed += 1
        else:
            whole += 1
    print(String("    note: ", seeds, " seeds from ", first, ": ", failed, " failed cleanly, ", whole, " complete and intact"))
    assert_true(failed * 2 > seeds, "most damage must be detected")


# ---- a KeyUpdate flood (TS9) ---------------------------------------------------

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


def _flow(mut src: ByteBuffer, mut dst: TlsServer) raises TlsError:
    while len(src) > 0 and dst.feed_capacity() > 0:
        var n = min(len(src), dst.feed_capacity())
        dst.feed(src.readable_span()[0:n])
        _drop(src, n)


def _flow_c(mut src: ByteBuffer, mut dst: TlsClient) raises TlsError:
    while len(src) > 0 and dst.feed_capacity() > 0:
        var n = min(len(src), dst.feed_capacity())
        dst.feed(src.readable_span()[0:n])
        _drop(src, n)


def _flood_error(drain: Bool) raises -> TlsError:
    var cctx = trusting()
    var sctx = serving(alpn=[])
    var c = TlsClient(cctx, "localhost")
    var s = TlsServer(sctx)
    var a = ByteBuffer()
    var b = ByteBuffer()
    for _ in range(20):
        _ = c.poll_transmit(a)
        _flow(a, s)
        _ = s.poll_transmit(b)
        _flow_c(b, c)
        while c.next_event():
            pass
        while s.next_event():
            pass
    assert_true(c.is_established() and s.is_established())
    ref L = cctx._library()[]
    var key_update = _key_update_fn(L.path)
    for i in range(12000):
        assert_equal(key_update(c._e._ssl, 1), 1)  # (SSL_KEY_UPDATE_REQUESTED)
        _ = L.SSL_do_handshake(c._e._ssl)  # (sends it)
        _ = c.poll_transmit(a)
        try:
            _flow(a, s)
            while s.next_event():
                pass
        except e:
            print(String("    note: the server failed after ", i + 1, " key updates"))
            return e^
        if drain:
            _ = s.poll_transmit(b)
            b.clear()
    _ = cctx
    raise Error("12,000 key updates were taken")


def test_a_key_update_flood_fails_the_server_connection() raises:
    """Each KeyUpdate asks for one back, and carries no data: the server
    fails once CLIENT_QUIET_LIMIT has arrived without data. Its replies, the same
    size as the requests, stay below OUTPUT_LIMIT until then even when the
    driver sends none of them."""
    var drained = _flood_error(True)
    assert_equal(drained.category, Category.PROTOCOL, String(drained))
    assert_true("without any data" in String(drained), String(drained))
    var kept = _flood_error(False)
    assert_true(kept.category == Category.PROTOCOL or kept.category == Category.RESOURCE, String(kept))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
