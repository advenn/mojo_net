"""net.evented on loopback: echo with 100 concurrent clients, MiB payloads
with backpressure, half-close, dial + request/response through a codec,
handler-initiated close, pipelined input redelivered after pause/resume,
input limits, raising handlers, failed and canceled dials.

Every client is evented too and runs on the same loop as the server, so a
test is one thread and its outcome is deterministic. Each wait is bounded
by a wall-clock guard, so a regression fails instead of hanging.
"""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError, Instant
from net.addr import SocketAddr
from net.codec import LineCodec
from net.evented import (
    CloseReason,
    Conn,
    ConnConfig,
    ConnHandler,
    ConnRef,
    ServerConfig,
    TcpServer,
    dial,
)
from rt.core import Loop
from rt.event_loop import EventLoop

comptime MS = 1_000_000
comptime GUARD_NS = 30_000 * MS
comptime MiB = 1024 * 1024


# ---- shared test plumbing ----------------------------------------------------


struct Counters(Movable):
    """Server-side observations, written by handlers through a pointer."""

    var opened: Int
    var closed: Int
    var dropped: Int
    var reasons: List[UInt8]
    var kinds: List[ErrorKind]

    def __init__(out self):
        self.opened = 0
        self.closed = 0
        self.dropped = 0
        self.reasons = []
        self.kinds = []

    def count(self, code: UInt8) -> Int:
        var n = 0
        for r in self.reasons:
            if r == code:
                n += 1
        return n


comptime KPtr = Pointer[Counters, MutUntrackedOrigin]


def kptr(mut k: Counters) -> KPtr:
    return Pointer(to=k).unsafe_origin_cast[MutUntrackedOrigin]()


def _record(k: KPtr, reason: CloseReason):
    k[].closed += 1
    k[].reasons.append(reason.code)
    if reason.is_error():
        k[].kinds.append(reason.err.kind)


def start[H: ConnHandler & Copyable](
    mut ev: EventLoop, var proto: H, cfg: ServerConfig = ServerConfig()
) raises -> TcpServer[H]:
    var srv = TcpServer[H].listen(ev.loop, SocketAddr.parse("127.0.0.1:0"), proto^, cfg)
    for _ in range(100):
        if srv.is_listening():
            return srv^
        if srv.error():
            raise Error("listen failed: ", srv.error().value())
        ev.run_once(0)
    raise Error("server never started listening")


def port_of[H: ConnHandler & Copyable](srv: TcpServer[H]) -> SocketAddr:
    return srv.local_addr().value()


def run_until_closed[H: ConnHandler](mut ev: EventLoop, mut refs: List[ConnRef[H]]) raises:
    var t0 = Instant.now()
    while True:
        var open = 0
        for i in range(len(refs)):
            if not refs[i].is_closed():
                open += 1
        if open == 0:
            return
        if (Instant.now() - t0).as_nanos() > GUARD_NS:
            raise Error(open, " client(s) still open after the guard")
        ev.run_once(5 * MS)


def drain(mut ev: EventLoop) raises:
    """Run until no op is pending (bounded)."""
    var t0 = Instant.now()
    while ev.loop.pending_ops() > 0 or ev.loop.has_ready():
        if (Instant.now() - t0).as_nanos() > GUARD_NS:
            raise Error("loop did not drain: ", ev.loop.pending_ops(), " ops pending")
        ev.run_once(5 * MS)


def wait_no_conns[H: ConnHandler & Copyable](mut ev: EventLoop, srv: TcpServer[H]) raises:
    """Clients closing first does not mean the server has processed their
    FIN yet: wait for the server side too."""
    var t0 = Instant.now()
    while srv.connections() > 0:
        if (Instant.now() - t0).as_nanos() > GUARD_NS:
            raise Error(srv.connections(), " server connection(s) still open")
        ev.run_once(5 * MS)


def shutdown_and_drain[H: ConnHandler & Copyable](
    mut ev: EventLoop, srv: TcpServer[H], grace_ns: Int = 5_000 * MS, wait: Bool = True
) raises:
    if wait:
        wait_no_conns(ev, srv)
    srv.shutdown(ev.loop, grace_ns)
    drain(ev)
    assert_true(srv.is_closed())
    assert_equal(ev.loop.open_fds(), 0)
    assert_equal(ev.loop.pending_ops(), 0)


def _pattern(off: Int) -> UInt8:
    return UInt8(off % 251)


# ---- handlers ----------------------------------------------------------------


struct EchoH(ConnHandler, Copyable):
    var k: KPtr

    def __init__(out self, k: KPtr):
        self.k = k

    def __init__(out self, *, copy: Self):
        self.k = copy.k

    def __deinit__(deinit self):
        self.k[].dropped += 1

    def on_open(mut self, mut conn: Conn) raises IoError:
        self.k[].opened += 1

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        conn.write(input.readable_span())
        input.clear()

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        _record(self.k, reason)


struct Pinger(ConnHandler):
    """Ping-pong: one `size`-byte message at a time, each byte checked;
    closes after `rounds` echoes (never, if rounds < 0)."""

    var size: Int
    var rounds: Int
    var done: Int
    var got: Int
    var bad: Int
    var opened: Bool
    var reason: CloseReason

    def __init__(out self, size: Int, rounds: Int):
        self.size = size
        self.rounds = rounds
        self.done = 0
        self.got = 0
        self.bad = 0
        self.opened = False
        self.reason = CloseReason.of(CloseReason.NONE)

    @inline(.always)
    def _byte(self, i: Int) -> UInt8:
        return UInt8((self.done * 31 + i) % 251)

    def _send(mut self, mut conn: Conn) raises IoError:
        ref o = conn.out()
        for i in range(self.size):
            o.write_byte(self._byte(i))

    def on_open(mut self, mut conn: Conn) raises IoError:
        self.opened = True
        self._send(conn)

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        var sp = input.readable_span()
        var finished = False
        for i in range(len(sp)):
            if finished or sp[i] != self._byte(self.got):
                self.bad += 1
            self.got += 1
            if self.got == self.size:
                self.got = 0
                self.done += 1
                finished = True
        input.clear()
        if finished:
            if self.rounds >= 0 and self.done >= self.rounds:
                conn.close()
            else:
                self._send(conn)

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        self.reason = reason


struct Bulk(ConnHandler):
    """Sends `total` patterned bytes (respecting `is_writable`/`on_drain`),
    then half-closes; checks every echoed byte. Reading starts paused for
    `pause_ns`, so the server's output backs up."""

    var total: Int
    var sent: Int
    var received: Int
    var bad: Int
    var pause_ns: Int
    var drains: Int
    var max_queued: Int
    var pat: List[UInt8]
    var reason: CloseReason

    comptime CHUNK = 64 * 1024

    def __init__(out self, total: Int, pause_ns: Int):
        self.total = total
        self.sent = 0
        self.received = 0
        self.bad = 0
        self.pause_ns = pause_ns
        self.drains = 0
        self.max_queued = 0
        self.pat = List[UInt8](capacity=Self.CHUNK + 251)
        for i in range(Self.CHUNK + 251):
            self.pat.append(_pattern(i))
        self.reason = CloseReason.of(CloseReason.NONE)

    def _fill(mut self, mut conn: Conn) raises IoError:
        while self.sent < self.total and conn.is_writable():
            var n = min(Self.CHUNK, self.total - self.sent)
            var at = self.sent % 251
            conn.write(Span(self.pat)[at : at + n])
            self.sent += n
            self.max_queued = max(self.max_queued, conn.queued())
        if self.sent == self.total:
            conn.shutdown_write()

    def on_open(mut self, mut conn: Conn) raises IoError:
        if self.pause_ns > 0:
            conn.pause_reading()
            _ = conn.set_timer(self.pause_ns, 1)
        self._fill(conn)

    def on_drain(mut self, mut conn: Conn) raises IoError:
        self.drains += 1
        self._fill(conn)

    def on_timer(mut self, mut conn: Conn, tag: UInt64) raises IoError:
        conn.resume_reading()

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        var sp = input.readable_span()
        var base = self.received
        for i in range(len(sp)):
            if sp[i] != _pattern(base + i):
                self.bad += 1
        self.received += len(sp)
        input.clear()

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        self.reason = reason


struct CollectH(ConnHandler, Copyable):
    """Answers only after the peer's EOF (writes on a half-closed socket)."""

    var k: KPtr
    var data: List[UInt8]

    def __init__(out self, k: KPtr):
        self.k = k
        self.data = []

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        for b in input.readable_span():
            self.data.append(b)
        input.clear()

    def on_eof(mut self, mut conn: Conn) raises IoError:
        conn.write("got:")
        conn.write(Span(self.data))
        conn.close()

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        _record(self.k, reason)


struct HalfCloser(ConnHandler):
    var msg: String
    var got: String
    var reason: CloseReason

    def __init__(out self, msg: String):
        self.msg = msg
        self.got = ""
        self.reason = CloseReason.of(CloseReason.NONE)

    def on_open(mut self, mut conn: Conn) raises IoError:
        conn.write(self.msg)
        conn.shutdown_write()

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        self.got += String(from_utf8_lossy=input.readable_span())
        input.clear()

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        self.reason = reason


def _text(line: List[UInt8]) -> String:
    return String(from_utf8_lossy=Span(line))


struct LineServer(ConnHandler, Copyable):
    """A sans-I/O codec on the evented driver (codec.mojo rule 5): PING ->
    PONG, QUIT -> BYE then close, BAD -> raise (protocol violation)."""

    var codec: LineCodec
    var k: KPtr

    def __init__(out self, k: KPtr) raises:
        self.codec = LineCodec(max_line_length=1024, max_buffered=4096)
        self.k = k

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        while input.readable() > 0 and not conn.is_closing():
            var n = min(input.readable(), self.codec.feed_capacity())
            self.codec.feed(input.readable_span()[0:n])
            input.consume(n)
            while True:
                var ev = self.codec.next_event()
                if not ev:
                    break
                var line = _text(ev.value())
                if line == "PING":
                    self.codec.send_line(String("PONG").as_bytes())
                elif line == "QUIT":
                    self.codec.send_line(String("BYE").as_bytes())
                    conn.close()  # the reply below still goes out first
                    break
                elif line == "BAD":
                    raise IoError.of_kind("LineServer", ErrorKind.InvalidData)
                else:
                    self.codec.send_line(String("ERR ", line).as_bytes())
        _ = self.codec.poll_transmit(conn.out())

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        _record(self.k, reason)


struct Script(ConnHandler):
    """Sends `script`, collects everything until EOF."""

    var script: String
    var got: String
    var opened: Bool
    var reason: CloseReason

    def __init__(out self, script: String):
        self.script = script
        self.got = ""
        self.opened = False
        self.reason = CloseReason.of(CloseReason.NONE)

    def on_open(mut self, mut conn: Conn) raises IoError:
        self.opened = True
        conn.write(self.script)

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        self.got += String(from_utf8_lossy=input.readable_span())
        input.clear()

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        self.reason = reason


struct OneLineAtATime(ConnHandler, Copyable):
    """Handles one line per callback, then pauses for 1 ms: the rest of a
    pipelined batch must be redelivered after resume_reading()."""

    var k: KPtr

    def __init__(out self, k: KPtr):
        self.k = k

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        var nl = input.find(UInt8(ord("\n")))
        if not nl:
            return  # partial line: keep it
        var n = nl.value() + 1
        conn.write("ok:")
        conn.write(input.readable_span()[0:n])
        input.consume(n)
        conn.pause_reading()
        _ = conn.set_timer(1 * MS)

    def on_timer(mut self, mut conn: Conn, tag: UInt64) raises IoError:
        conn.resume_reading()

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        _record(self.k, reason)


struct FramesH(ConnHandler, Copyable):
    """Consumes complete lines only; leaves a partial line unconsumed."""

    var k: KPtr

    def __init__(out self, k: KPtr):
        self.k = k

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        while True:
            var nl = input.find(UInt8(ord("\n")))
            if not nl:
                return
            input.consume(nl.value() + 1)
            conn.write("line\n")

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        _record(self.k, reason)


# ---- tests -------------------------------------------------------------------


def test_echo_100_concurrent_clients() raises:
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, EchoH(kptr(k)))
    var addr = port_of(srv)
    var refs = List[ConnRef[Pinger]]()
    for i in range(100):
        refs.append(dial(ev.loop, addr, Pinger(size=100 + i, rounds=20)))
    run_until_closed(ev, refs)
    for i in range(100):
        ref h = refs[i].handler()
        assert_equal(h.done, 20)
        assert_equal(h.bad, 0)
        assert_equal(h.reason.code, CloseReason.LOCAL)
    shutdown_and_drain(ev, srv)
    var st = srv.stats()
    assert_equal(st.accepted, 100)
    assert_equal(st.closed, 100)
    assert_equal(st.errors, 0)
    assert_equal(k.opened, 100)
    assert_equal(k.closed, 100)
    assert_equal(k.count(CloseReason.PEER), 100)  # each client closed first
    _ = srv^
    _ = refs^
    assert_equal(k.dropped, 101)  # 100 connection handlers + the prototype


def test_large_payload_with_backpressure() raises:
    var k = Counters()
    var ev = EventLoop()
    var cfg = ServerConfig(conn=ConnConfig(write_high_water=64 * 1024))
    var srv = start(ev, EchoH(kptr(k)), cfg)
    var total = 24 * MiB
    var refs = List[ConnRef[Bulk]]()
    refs.append(
        dial(
            ev.loop,
            port_of(srv),
            Bulk(total, pause_ns=150 * MS),
            ConnConfig(read_backpressure=False),
        )
    )
    run_until_closed(ev, refs)
    ref b = refs[0].handler()
    assert_equal(b.sent, total)
    assert_equal(b.received, total)
    assert_equal(b.bad, 0)
    assert_true(b.drains > 0, "client writer never waited for on_drain")
    # The client's own queue stayed near its high-water mark (256 KiB + one
    # chunk), not the whole payload.
    assert_true(b.max_queued <= 256 * 1024 + 64 * 1024, String(b.max_queued))
    assert_equal(b.reason.code, CloseReason.PEER)
    shutdown_and_drain(ev, srv)
    var st = srv.stats()
    assert_true(st.bp_pauses > 0, "server never paused reading: " + String(st))
    assert_equal(st.errors, 0)
    assert_equal(k.count(CloseReason.PEER), 1)


def test_half_close_server_answers_after_eof() raises:
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, CollectH(kptr(k)))
    var refs = List[ConnRef[HalfCloser]]()
    refs.append(dial(ev.loop, port_of(srv), HalfCloser("abc")))
    refs.append(dial(ev.loop, port_of(srv), HalfCloser("")))
    run_until_closed(ev, refs)
    assert_equal(refs[0].handler().got, "got:abc")
    assert_equal(refs[1].handler().got, "got:")
    # The server finished writing after the client's FIN, then closed; the
    # client then saw EOF.
    assert_equal(refs[0].handler().reason.code, CloseReason.PEER)
    shutdown_and_drain(ev, srv)
    assert_equal(k.count(CloseReason.PEER), 2)


def test_dial_request_response_and_handler_initiated_close() raises:
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, LineServer(kptr(k)))
    var refs = List[ConnRef[Script]]()
    refs.append(dial(ev.loop, port_of(srv), Script("PING\nPING\nwhat\nQUIT\nPING\n")))
    run_until_closed(ev, refs)
    ref s = refs[0].handler()
    assert_true(s.opened)
    # QUIT: the server answers BYE, closes, and ignores what follows.
    assert_equal(s.got, "PONG\nPONG\nERR what\nBYE\n")
    assert_equal(s.reason.code, CloseReason.PEER)
    shutdown_and_drain(ev, srv)
    assert_equal(k.count(CloseReason.LOCAL), 1)


def test_lingering_close_avoids_reset_on_unread_input() raises:
    """QUIT followed by 256 KiB the server never parses: when it closes,
    most of that is still unread in its kernel buffer. A plain close() of
    such a socket sends RST (which can erase the client's unread copy of
    BYE); the default lingering close sends FIN, discards input until the
    client's EOF, then closes."""
    var tail = String("x") * (256 * 1024)
    for lingering in range(2):
        var k = Counters()
        var ev = EventLoop()
        var cfg = ServerConfig(conn=ConnConfig(lingering_close=lingering == 1))
        var srv = start(ev, LineServer(kptr(k)), cfg)
        var refs = List[ConnRef[Script]]()
        refs.append(dial(ev.loop, port_of(srv), Script(String("QUIT\n") + tail)))
        run_until_closed(ev, refs)
        ref s = refs[0].handler()
        assert_equal(s.got, "BYE\n")
        if lingering == 1:
            assert_equal(s.reason.code, CloseReason.PEER)  # FIN, not RST
        else:
            assert_equal(s.reason.code, CloseReason.ERROR)
            assert_true(s.reason.err.kind == ErrorKind.ConnectionReset)
        shutdown_and_drain(ev, srv)
        assert_equal(k.count(CloseReason.LOCAL), 1)


def test_raising_handler_aborts_connection() raises:
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, LineServer(kptr(k)))
    var refs = List[ConnRef[Script]]()
    refs.append(dial(ev.loop, port_of(srv), Script("PING\nBAD\nPING\n")))
    run_until_closed(ev, refs)
    # The reply to the first PING was staged in the same callback that
    # raised: abort drops it. The client sees the close (EOF or reset).
    assert_equal(refs[0].handler().got, "")
    shutdown_and_drain(ev, srv)
    assert_equal(srv.stats().errors, 1)
    assert_equal(k.count(CloseReason.ERROR), 1)
    assert_equal(len(k.kinds), 1)
    assert_true(k.kinds[0] == ErrorKind.InvalidData)


def test_pipelined_input_redelivered_after_resume() raises:
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, OneLineAtATime(kptr(k)))
    var refs = List[ConnRef[HalfCloser]]()
    refs.append(dial(ev.loop, port_of(srv), HalfCloser("a\nbb\nccc\nd\ne")))
    run_until_closed(ev, refs)
    # One line per callback, in order; the trailing partial "e" is dropped
    # at EOF.
    assert_equal(refs[0].handler().got, "ok:a\nok:bb\nok:ccc\nok:d\n")
    shutdown_and_drain(ev, srv)


def test_unconsumed_input_over_limit_closes() raises:
    var k = Counters()
    var ev = EventLoop()
    var cfg = ServerConfig(conn=ConnConfig(max_input=1024))
    var srv = start(ev, FramesH(kptr(k)), cfg)
    var refs = List[ConnRef[Script]]()
    var ok_line = String("x\n")
    var long_line = String("y") * 4096
    refs.append(dial(ev.loop, port_of(srv), Script(ok_line)))
    refs.append(dial(ev.loop, port_of(srv), Script(long_line)))
    # The first client never closes by itself (it waits for EOF): close it
    # once it got its answer.
    var t0 = Instant.now()
    while refs[0].handler().got != "line\n":
        assert_true((Instant.now() - t0).as_nanos() < GUARD_NS)
        ev.run_once(5 * MS)
    refs[0].close(ev.loop)
    run_until_closed(ev, refs)
    shutdown_and_drain(ev, srv)
    assert_equal(k.count(CloseReason.ERROR), 1)
    assert_true(k.kinds[0] == ErrorKind.InvalidData)


def test_dial_refused_reports_connect_failed() raises:
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, EchoH(kptr(k)))
    var addr = port_of(srv)
    shutdown_and_drain(ev, srv)  # nothing listens on `addr` any more
    var refs = List[ConnRef[Script]]()
    refs.append(dial(ev.loop, addr, Script("x")))
    run_until_closed(ev, refs)
    ref s = refs[0].handler()
    assert_false(s.opened)
    assert_equal(s.reason.code, CloseReason.CONNECT_FAILED)
    assert_true(s.reason.err.kind == ErrorKind.ConnectionRefused)
    drain(ev)
    assert_equal(ev.loop.open_fds(), 0)


def test_close_before_connect_completes() raises:
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, EchoH(kptr(k)))
    var refs = List[ConnRef[Script]]()
    refs.append(dial(ev.loop, port_of(srv), Script("x")))
    refs[0].close(ev.loop)  # same loop turn as the connect
    run_until_closed(ev, refs)
    assert_false(refs[0].handler().opened)
    assert_equal(refs[0].reason().code, CloseReason.LOCAL)
    shutdown_and_drain(ev, srv)


def test_write_from_outside_a_callback() raises:
    """A DB-driver style caller: write through the ConnRef between loop
    turns, then flush."""
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, LineServer(kptr(k)))
    var refs = List[ConnRef[Script]]()
    refs.append(dial(ev.loop, port_of(srv), Script("")))
    var t0 = Instant.now()
    while not refs[0].is_connected():
        assert_true((Instant.now() - t0).as_nanos() < GUARD_NS)
        ev.run_once(5 * MS)
    var c = refs[0].conn(ev.loop)
    c.write("PING\nQUIT\n")
    c.flush()
    run_until_closed(ev, refs)
    assert_equal(refs[0].handler().got, "PONG\nBYE\n")
    shutdown_and_drain(ev, srv)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
