"""A small HTTP/1.1 load generator for servers that answer every request
with the same response (examples/http/hello_server.mojo, say). It does not
use the http package: it learns the response's size from one request,
then counts bytes, so it measures the server and not our own parser.

    pixi run mojo run -I src bench/http/load.mojo HOST:PORT [CONNS] [SECONDS] [PIPELINE]

CONNS keep-alive connections (default 50) on one thread with edge-triggered
epoll, each with PIPELINE requests in flight (default 1), for SECONDS
(default 5). Prints requests per second and, per round trip, the median and
99th-percentile latency.
"""

from std.sys import argv, exit, stderr

from linux import Epoll, IoError
from linux.abi import EpollEvent
from linux.consts import EPOLLET, EPOLLIN, EPOLLOUT, EPOLLRDHUP
from linux.time import Deadline, Duration, Instant
from net.addr import SocketAddr
from net.tcp import TcpStream

comptime REQUEST = "GET / HTTP/1.1\r\nHost: bench\r\n\r\n"


def response_size(addr: SocketAddr) raises -> Int:
    """Send one request and work out the whole response's size from its
    head (Content-Length)."""
    var s = TcpStream.connect(addr)
    s.set_deadline(Deadline.after(Duration.from_secs(5)))
    s.write_all(REQUEST.as_bytes())
    var got = List[UInt8]()
    var buf = List[UInt8](length=4096, fill=0)
    while True:
        var n = s.read(Span(buf))
        if n == 0:
            raise Error("closed before a response")
        got.extend(Span(buf)[0:n])
        var text = String(from_utf8_lossy=Span(got))
        var end = text.find("\r\n\r\n")
        if end >= 0:
            var lower = text[byte=0:end].lower()
            var at = lower.find("content-length:")
            if at < 0:
                raise Error("the response has no Content-Length")
            var line_end = lower.find("\r\n", at)
            var cl = atol(String(lower[byte = at + 15 : line_end if line_end >= 0 else end]).strip())
            return end + 4 + cl


struct Conn(Movable):
    var stream: TcpStream
    var pending: Int
    """Response bytes still expected for the requests in flight."""
    var sent_at: Instant

    def __init__(out self, var stream: TcpStream):
        self.stream = stream^
        self.pending = 0
        self.sent_at = Instant.now()


def main() raises:
    var args = argv()
    if len(args) < 2:
        print("usage: load HOST:PORT [CONNS] [SECONDS] [PIPELINE]", file=stderr)
        exit(2)
        return
    var addr = SocketAddr.parse(String(args[1]))
    var nconns = atol(args[2]) if len(args) > 2 else 50
    var secs = atol(args[3]) if len(args) > 3 else 5
    var depth = atol(args[4]) if len(args) > 4 else 1
    var size = response_size(addr)
    var burst = String()
    for _ in range(depth):
        burst += REQUEST
    var ep = Epoll.new()
    var conns = List[Conn]()
    for i in range(nconns):
        var s = TcpStream.connect(addr)
        ep.add(s, UInt32(EPOLLIN | EPOLLRDHUP | EPOLLET), UInt64(i))
        conns.append(Conn(s^))
    var buf = List[UInt8](length=256 * 1024, fill=0)
    var lat = List[Int](capacity=1 << 20)
    var done = 0
    var start = Instant.now()
    var stop = start + Duration.from_secs(secs)
    for i in range(nconns):
        conns[i].stream.write_all(burst.as_bytes())
        conns[i].pending = size * depth
        conns[i].sent_at = Instant.now()
    var events = List[EpollEvent](capacity=1024)
    while Instant.now() < stop:
        var n = ep.wait(events, Optional[Duration](Duration.from_millis(100)))
        for k in range(n):
            ref c = conns[Int(events[k].data())]
            while True:
                var got = c.stream.try_read(Span(buf))
                if not got:
                    break
                if got.value() == 0:
                    raise Error("the server closed a connection")
                c.pending -= got.value()
                if c.pending == 0:
                    var now = Instant.now()
                    lat.append((now - c.sent_at).as_nanos())
                    done += depth
                    c.stream.write_all(burst.as_bytes())
                    c.pending = size * depth
                    c.sent_at = now
                elif c.pending < 0:
                    raise Error("more bytes than the responses")
    var elapsed = Instant.now() - start
    sort(lat)
    var p50 = lat[len(lat) // 2] if len(lat) > 0 else 0
    var p99 = lat[len(lat) * 99 // 100] if len(lat) > 0 else 0
    var rps = Float64(done) / (Float64(elapsed.as_nanos()) / 1e9)
    print(
        "conns", nconns, "pipeline", depth, ":", Int(rps), "req/s,",
        "round trip p50", p50 // 1000, "us, p99", p99 // 1000, "us,",
        done, "requests,", size, "B responses",
    )
