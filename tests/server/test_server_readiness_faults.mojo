"""Reads per request (2026-11 analysis, perf finding read-until-eagain):
after a read shorter than it asked for, the socket is drained, so the
server waits for the next readable edge instead of reading again to find
nothing. Before, every keep-alive request cost a recv that returned
EAGAIN after its response, and every event a woken stream sent did too.

The counts come from the fault seam's syscall counters (nothing is
injected), with the client in this process between the server's turns.
The other tests are the cases the shortcut must not break: input split
across edges, pipelined requests, a request that comes with its FIN (no
edge of its own for the FIN: the sticky hangup reads on), and a paused
stream whose client half-closes."""

from std.testing import TestSuite, assert_equal, assert_true

from linux import fault
from linux.nr import SYS_recvfrom
from linux.time import Duration
from net.addr import SocketAddr
from net.socket import Shutdown
from net.tcp import TcpStream
from server import Handler, Request, Response, Server

comptime _GET = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
comptime _TURN = Duration.from_millis(20)


struct App(Handler):
    var ids: List[UInt64]
    var events: Int
    """Events waiting for the stream (one is sent per wake)."""
    var ended: Int
    var finished: Bool

    def __init__(out self):
        self.ids = List[UInt64]()
        self.events = 0
        self.ended = 0
        self.finished = False

    def handle(mut self, req: Request, mut res: Response) raises:
        if req.path() == "/events":
            self.ids.append(req.id)
            res.event_stream()
        else:
            res.text(200, "ok")

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        if self.events > 0:
            self.events -= 1
            out.extend("data: x\n\n".as_bytes())
        return True  # (nothing appended: paused until woken)

    def stream_ended(mut self, req: Request, finished: Bool):
        self.ended += 1
        self.finished = finished


def _connected(mut s: Server[App]) raises -> TcpStream:
    """A client whose connection the server has accepted and served once
    (its first edge)."""
    var c = TcpStream.connect(s.local_addr())
    for _ in range(3):
        s.step(_TURN)
    assert_equal(s.connections(), 1)
    return c^


def _read_until(mut s: Server[App], c: TcpStream, end: StringSlice, want: Int = 1) raises -> String:
    """What the client reads, turn by turn, until `end` has come `want`
    times or the server closed the connection."""
    var got = String()
    var buf = List[UInt8](length=4096, fill=0)
    for _ in range(100):
        while True:
            var n = c.try_read(Span(buf))
            if not n:
                break
            if n.value() == 0:
                return got + "<EOF>"
            got += String(from_utf8_lossy=Span(buf)[0 : n.value()])
        if got.count(end) >= want:
            return got^
        s.step(_TURN)
    return got^


def test_a_keep_alive_request_reads_the_socket_once() raises:
    fault.clear()
    var s = Server(App())
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = _connected(s)
    var reads = 0
    comptime N = 20
    for i in range(N):
        c.write_all(_GET.as_bytes())
        var before = fault.calls(SYS_recvfrom)
        s.step(_TURN)  # (the request is queued: this turn reads and answers it)
        reads += fault.calls(SYS_recvfrom) - before
        var got = _read_until(s, c, "\r\n\r\nok")
        assert_true(got.endswith("\r\n\r\nok"), String(i, ": ", got))
    _ = c^
    # One recv per request: the one that found it. The code before read
    # once more after each response, and found nothing (2 per request).
    assert_true(reads <= N + 1, String(reads, " server reads for ", N, " requests"))


def test_a_woken_stream_sends_without_reading() raises:
    fault.clear()
    var s = Server(App())
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = _connected(s)
    c.write_all("GET /events HTTP/1.1\r\nHost: x\r\n\r\n".as_bytes())
    _ = _read_until(s, c, "\r\n\r\n")  # the head: the stream is paused
    assert_equal(len(s.handler.ids), 1)
    var reads = 0
    comptime N = 10
    for i in range(N):
        s.handler.events = 1
        s.wake(s.handler.ids[0])
        var before = fault.calls(SYS_recvfrom)
        s.step(_TURN)  # sends the event, and pauses again
        reads += fault.calls(SYS_recvfrom) - before
        var got = _read_until(s, c, "data: x\n\n")
        assert_equal(got.count("data: x\n\n"), 1, String(i, ": ", got))  # (one chunk)
    # Nothing came from the client, and no edge said so: no read at all.
    assert_equal(reads, 0)
    c.shutdown(Shutdown.WRITE)  # the client leaves: the stream is cut
    var rest = _read_until(s, c, "<EOF>")
    assert_true(rest.endswith("<EOF>"), rest)
    assert_equal(s.handler.ended, 1)
    assert_true(not s.handler.finished)


def test_a_request_split_across_edges_is_answered() raises:
    fault.clear()
    var s = Server(App())
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = _connected(s)
    c.write_all("GET / HTTP/1.1\r\nHo".as_bytes())
    s.step(_TURN)  # a short read: drained, nothing to answer yet
    c.write_all("st: x\r\n".as_bytes())
    s.step(_TURN)
    c.write_all("\r\n".as_bytes())
    var got = _read_until(s, c, "\r\n\r\nok")
    assert_true(got.startswith("HTTP/1.1 200 OK\r\n") and got.endswith("\r\n\r\nok"), got)


def test_pipelined_requests_in_one_read_are_all_answered() raises:
    fault.clear()
    var s = Server(App())
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = _connected(s)
    c.write_all(String(_GET, _GET, _GET).as_bytes())
    var got = _read_until(s, c, "\r\n\r\nok", want=3)
    assert_equal(got.count("HTTP/1.1 200 OK\r\n"), 3, got)


def test_a_request_with_its_fin_is_answered_and_closed() raises:
    """The FIN comes in the same edge as the request: the read that takes
    the request is short, and only the sticky hangup reads on to the
    EOF (no later edge would)."""
    fault.clear()
    var s = Server(App())
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = _connected(s)
    c.write_all(_GET.as_bytes())
    c.shutdown(Shutdown.WRITE)
    var got = _read_until(s, c, "<EOF>")
    assert_true(got.startswith("HTTP/1.1 200 OK\r\n") and got.endswith("\r\n\r\nok<EOF>"), got)
    for _ in range(3):
        s.step(_TURN)
    assert_equal(s.connections(), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
