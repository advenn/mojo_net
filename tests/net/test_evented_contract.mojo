"""Backend-agnostic contract of `net.evented`: only public API (EventLoop,
net.evented, net.addr, net.codec), no epoll, /proc or Python, and every
duration measured on the loop's clock, so the same file runs on the epoll
backend and on the in-memory simulator (`*_contract.mojo` files run once
per backend; `-D MOJO_TCP_SIM=1` selects the simulator).

Covered: concurrent echo, a multi-MiB transfer under backpressure,
half-close, request/response with a codec and a handler-initiated close,
pipelined input redelivered after pause/resume, idle timeout, managed
timers, refused and canceled dials, and graceful shutdown with active and
idle clients.
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
comptime GUARD_NS = 60_000 * MS
"""Wall-clock backstop: a broken test fails instead of hanging."""


# ---- plumbing ----------------------------------------------------------------


struct Counters(Movable):
    var opened: Int
    var closed: Int
    var dropped: Int
    var reasons: List[UInt8]

    def __init__(out self):
        self.opened = 0
        self.closed = 0
        self.dropped = 0
        self.reasons = []

    def count(self, code: UInt8) -> Int:
        var n = 0
        for r in self.reasons:
            if r == code:
                n += 1
        return n


comptime KPtr = Pointer[Counters, MutUntrackedOrigin]


def kptr(mut k: Counters) -> KPtr:
    return Pointer(to=k).unsafe_origin_cast[MutUntrackedOrigin]()


def start[H: ConnHandler & Copyable](
    mut ev: EventLoop, var proto: H, cfg: ServerConfig = ServerConfig()
) raises -> TcpServer[H]:
    var srv = TcpServer[H].listen(ev.loop, SocketAddr.parse("127.0.0.1:0"), proto^, cfg)
    for _ in range(1000):
        if srv.is_listening():
            return srv^
        if srv.error():
            raise Error("listen failed: ", srv.error().value())
        ev.run_once(1 * MS)
    raise Error("server never started listening")


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


def wait_no_conns[H: ConnHandler & Copyable](mut ev: EventLoop, srv: TcpServer[H]) raises:
    var t0 = Instant.now()
    while srv.connections() > 0:
        if (Instant.now() - t0).as_nanos() > GUARD_NS:
            raise Error(srv.connections(), " server connection(s) still open")
        ev.run_once(5 * MS)


def drain(mut ev: EventLoop) raises:
    var t0 = Instant.now()
    while ev.loop.pending_ops() > 0 or ev.loop.has_ready():
        if (Instant.now() - t0).as_nanos() > GUARD_NS:
            raise Error("loop did not drain: ", ev.loop.pending_ops(), " ops pending")
        ev.run_once(5 * MS)


def finish[H: ConnHandler & Copyable](mut ev: EventLoop, srv: TcpServer[H]) raises:
    """Wait for the server side to close, shut down, drain, check leaks."""
    wait_no_conns(ev, srv)
    srv.shutdown(ev.loop, 5_000 * MS)
    drain(ev)
    assert_true(srv.is_closed())
    assert_equal(ev.loop.open_fds(), 0)
    assert_equal(ev.loop.pending_ops(), 0)


def run_for(mut ev: EventLoop, ns: Int) raises:
    var t0 = ev.loop.now()
    while (ev.loop.now() - t0).as_nanos() < ns:
        ev.run_once(2 * MS)


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
        self.k[].closed += 1
        self.k[].reasons.append(reason.code)


struct Pinger(ConnHandler):
    var size: Int
    var rounds: Int
    var done: Int
    var got: Int
    var bad: Int
    var reason: CloseReason

    def __init__(out self, size: Int, rounds: Int):
        self.size = size
        self.rounds = rounds
        self.done = 0
        self.got = 0
        self.bad = 0
        self.reason = CloseReason.of(CloseReason.NONE)

    @inline(.always)
    def _byte(self, i: Int) -> UInt8:
        return UInt8((self.done * 31 + i) % 251)

    def _send(mut self, mut conn: Conn) raises IoError:
        ref o = conn.out()
        for i in range(self.size):
            o.write_byte(self._byte(i))

    def on_open(mut self, mut conn: Conn) raises IoError:
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
    var total: Int
    var sent: Int
    var received: Int
    var bad: Int
    var pause_ns: Int
    var drains: Int
    var pat: List[UInt8]
    var reason: CloseReason

    comptime CHUNK = 16 * 1024

    def __init__(out self, total: Int, pause_ns: Int):
        self.total = total
        self.sent = 0
        self.received = 0
        self.bad = 0
        self.pause_ns = pause_ns
        self.drains = 0
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
    var data: List[UInt8]

    def __init__(out self):
        self.data = []

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        for b in input.readable_span():
            self.data.append(b)
        input.clear()

    def on_eof(mut self, mut conn: Conn) raises IoError:
        conn.write("got:")
        conn.write(Span(self.data))
        conn.close()


struct Script(ConnHandler):
    """Sends `script` (then FIN if `half_close`), collects until EOF."""

    var script: String
    var half_close: Bool
    var got: String
    var opened: Bool
    var reason: CloseReason

    def __init__(out self, script: String, half_close: Bool = False):
        self.script = script
        self.half_close = half_close
        self.got = ""
        self.opened = False
        self.reason = CloseReason.of(CloseReason.NONE)

    def on_open(mut self, mut conn: Conn) raises IoError:
        self.opened = True
        conn.write(self.script)
        if self.half_close:
            conn.shutdown_write()

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        self.got += String(from_utf8_lossy=input.readable_span())
        input.clear()

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        self.reason = reason


struct LineServer(ConnHandler, Copyable):
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
                var line = String(from_utf8_lossy=Span(ev.value()))
                if line == "PING":
                    self.codec.send_line(String("PONG").as_bytes())
                elif line == "QUIT":
                    self.codec.send_line(String("BYE").as_bytes())
                    conn.close()
                    break
                else:
                    self.codec.send_line(String("ERR ", line).as_bytes())
        _ = self.codec.poll_transmit(conn.out())

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        self.k[].closed += 1
        self.k[].reasons.append(reason.code)


struct OneLineAtATime(ConnHandler, Copyable):
    def __init__(out self):
        pass

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        var nl = input.find(UInt8(ord("\n")))
        if not nl:
            return
        var n = nl.value() + 1
        conn.write("ok:")
        conn.write(input.readable_span()[0:n])
        input.consume(n)
        conn.pause_reading()
        _ = conn.set_timer(1 * MS)

    def on_timer(mut self, mut conn: Conn, tag: UInt64) raises IoError:
        conn.resume_reading()


struct Watcher(ConnHandler):
    """Records open/close loop times; optionally ticks one byte every
    `tick_ns`, `ticks` times (each echoed), then closes."""

    var tick_ns: Int
    var ticks: Int
    var echoed: Int
    var opened_at: Int
    var closed_at: Int
    var reason: CloseReason

    def __init__(out self, tick_ns: Int = 0, ticks: Int = 0):
        self.tick_ns = tick_ns
        self.ticks = ticks
        self.echoed = 0
        self.opened_at = 0
        self.closed_at = 0
        self.reason = CloseReason.of(CloseReason.NONE)

    def on_open(mut self, mut conn: Conn) raises IoError:
        self.opened_at = conn.now().as_nanos()
        if self.tick_ns > 0:
            _ = conn.set_timer(self.tick_ns, 1)

    def on_timer(mut self, mut conn: Conn, tag: UInt64) raises IoError:
        conn.write("t")

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        self.echoed += input.readable()
        input.clear()
        if self.tick_ns > 0:
            if self.echoed >= self.ticks:
                conn.close()
            else:
                _ = conn.set_timer(self.tick_ns, 1)

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        self.closed_at = lp.now().as_nanos()
        self.reason = reason


struct Timers(ConnHandler):
    var fired: List[UInt64]

    def __init__(out self):
        self.fired = []

    def on_open(mut self, mut conn: Conn) raises IoError:
        _ = conn.set_timer(5 * MS, 1)
        var two = conn.set_timer(10 * MS, 2)
        _ = conn.set_timer(20 * MS, 3)
        _ = conn.set_timer(600_000 * MS, 9)
        conn.cancel_timer(two)

    def on_timer(mut self, mut conn: Conn, tag: UInt64) raises IoError:
        self.fired.append(tag)
        if tag == 3:
            conn.close()

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        input.clear()


# ---- tests -------------------------------------------------------------------


def test_contract_concurrent_echo() raises:
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, EchoH(kptr(k)))
    var addr = srv.local_addr().value()
    var refs = List[ConnRef[Pinger]]()
    for i in range(50):
        refs.append(dial(ev.loop, addr, Pinger(size=1 + 37 * i, rounds=10)))
    run_until_closed(ev, refs)
    for i in range(50):
        assert_equal(refs[i].handler().done, 10)
        assert_equal(refs[i].handler().bad, 0)
        assert_equal(refs[i].handler().reason.code, CloseReason.LOCAL)
    finish(ev, srv)
    assert_equal(srv.stats().accepted, 50)
    assert_equal(k.count(CloseReason.PEER), 50)
    _ = srv^
    assert_equal(k.dropped, 51)  # every handler destroyed once (+ prototype)


def test_contract_bulk_transfer_with_backpressure() raises:
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, EchoH(kptr(k)), ServerConfig(conn=ConnConfig(write_high_water=32 * 1024)))
    var total = 8 * 1024 * 1024
    var refs = List[ConnRef[Bulk]]()
    refs.append(
        dial(
            ev.loop,
            srv.local_addr().value(),
            Bulk(total, pause_ns=50 * MS),
            ConnConfig(write_high_water=128 * 1024, read_backpressure=False),
        )
    )
    run_until_closed(ev, refs)
    ref b = refs[0].handler()
    assert_equal(b.sent, total)
    assert_equal(b.received, total)
    assert_equal(b.bad, 0)
    assert_true(b.drains > 0)
    assert_equal(b.reason.code, CloseReason.PEER)
    finish(ev, srv)
    assert_true(srv.stats().bp_pauses > 0)
    assert_equal(srv.stats().errors, 0)


def test_contract_half_close() raises:
    var ev = EventLoop()
    var srv = start(ev, CollectH())
    var refs = List[ConnRef[Script]]()
    refs.append(dial(ev.loop, srv.local_addr().value(), Script("abc", half_close=True)))
    refs.append(dial(ev.loop, srv.local_addr().value(), Script("", half_close=True)))
    run_until_closed(ev, refs)
    assert_equal(refs[0].handler().got, "got:abc")
    assert_equal(refs[1].handler().got, "got:")
    assert_equal(refs[0].handler().reason.code, CloseReason.PEER)
    finish(ev, srv)


def test_contract_request_response_and_server_close() raises:
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, LineServer(kptr(k)))
    var refs = List[ConnRef[Script]]()
    refs.append(dial(ev.loop, srv.local_addr().value(), Script("PING\nx\nQUIT\nPING\n")))
    run_until_closed(ev, refs)
    assert_equal(refs[0].handler().got, "PONG\nERR x\nBYE\n")
    assert_equal(refs[0].handler().reason.code, CloseReason.PEER)
    finish(ev, srv)
    assert_equal(k.count(CloseReason.LOCAL), 1)


def test_contract_pipelined_redelivery() raises:
    var ev = EventLoop()
    var srv = start(ev, OneLineAtATime())
    var refs = List[ConnRef[Script]]()
    refs.append(dial(ev.loop, srv.local_addr().value(), Script("a\nbb\nccc\n", half_close=True)))
    run_until_closed(ev, refs)
    assert_equal(refs[0].handler().got, "ok:a\nok:bb\nok:ccc\n")
    finish(ev, srv)


def test_contract_idle_timeout() raises:
    var k = Counters()
    var ev = EventLoop()
    var idle = 100 * MS
    var srv = start(ev, EchoH(kptr(k)), ServerConfig(conn=ConnConfig(idle_timeout_ns=idle)))
    var refs = List[ConnRef[Watcher]]()
    refs.append(dial(ev.loop, srv.local_addr().value(), Watcher()))
    refs.append(dial(ev.loop, srv.local_addr().value(), Watcher(tick_ns=30 * MS, ticks=8)))
    run_until_closed(ev, refs)
    ref quiet = refs[0].handler()
    var lived = quiet.closed_at - quiet.opened_at
    assert_true(lived >= idle, String("closed too early: ", lived))
    assert_true(lived < idle + 1_000 * MS, String("closed too late: ", lived))
    assert_equal(quiet.reason.code, CloseReason.PEER)
    assert_equal(refs[1].handler().echoed, 8)
    assert_equal(refs[1].handler().reason.code, CloseReason.LOCAL)
    finish(ev, srv)
    assert_equal(srv.stats().idle_closed, 1)
    assert_equal(k.count(CloseReason.IDLE), 1)


def test_contract_timers() raises:
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, EchoH(kptr(k)))
    var refs = List[ConnRef[Timers]]()
    refs.append(dial(ev.loop, srv.local_addr().value(), Timers()))
    run_until_closed(ev, refs)
    ref t = refs[0].handler()
    assert_equal(len(t.fired), 2)
    assert_equal(t.fired[0], 1)
    assert_equal(t.fired[1], 3)
    finish(ev, srv)  # the 600 s timer was canceled at close


def test_contract_refused_and_canceled_dials() raises:
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, EchoH(kptr(k)))
    var addr = srv.local_addr().value()
    var refs = List[ConnRef[Script]]()
    refs.append(dial(ev.loop, addr, Script("x")))
    refs[0].close(ev.loop)  # before the handshake completes
    run_until_closed(ev, refs)
    assert_false(refs[0].handler().opened)
    assert_equal(refs[0].reason().code, CloseReason.LOCAL)
    finish(ev, srv)
    var late = List[ConnRef[Script]]()
    late.append(dial(ev.loop, addr, Script("x")))  # nothing listens now
    run_until_closed(ev, late)
    assert_false(late[0].handler().opened)
    assert_equal(late[0].reason().code, CloseReason.CONNECT_FAILED)
    assert_true(late[0].reason().err.kind == ErrorKind.ConnectionRefused)
    drain(ev)
    assert_equal(ev.loop.open_fds(), 0)


def test_contract_graceful_shutdown_with_active_and_idle_clients() raises:
    var k = Counters()
    var ev = EventLoop()
    var srv = start(ev, EchoH(kptr(k)))
    var addr = srv.local_addr().value()
    var busy = List[ConnRef[Pinger]]()
    var quiet = List[ConnRef[Watcher]]()
    for i in range(10):
        busy.append(dial(ev.loop, addr, Pinger(size=100 + 50 * i, rounds=-1)))
    for _ in range(5):
        quiet.append(dial(ev.loop, addr, Watcher()))
    run_for(ev, 50 * MS)
    assert_equal(srv.connections(), 15)
    var t0 = ev.loop.now()
    srv.shutdown(ev.loop, 10_000 * MS)
    run_until_closed(ev, busy)
    run_until_closed(ev, quiet)
    drain(ev)
    assert_true((ev.loop.now() - t0).as_nanos() < 2_000 * MS)
    assert_true(srv.is_closed())
    for i in range(10):
        assert_true(busy[i].handler().done > 0)
        assert_equal(busy[i].handler().bad, 0)
    for i in range(5):
        assert_equal(quiet[i].handler().reason.code, CloseReason.PEER)
    assert_equal(srv.stats().closed, 15)
    assert_equal(k.count(CloseReason.SHUTDOWN), 15)
    assert_equal(ev.loop.open_fds(), 0)
    assert_equal(ev.loop.pending_ops(), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
