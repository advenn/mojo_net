"""Minimal HTTP/1.1 keep-alive "Hello, World!" server on `rt.evented`, for
the HTTP comparison in bench/rt/README.md (the readable version is
examples/rt/http_hello.mojo; bench/rt/rust_http is the same program on tokio).

    pixi run mojo build -I src -I bench/rt -I spikes/epoll_echo bench/rt/http_hello.mojo -o bench/rt/out/http_hello
    taskset -c 2 bench/rt/out/http_hello --port 8080 [--stats-ms 1000]

Per connection: find the end of each request head (CRLFCRLF), answer it
with a fixed response, keep the connection open. Pipelining-safe: every
complete head in the input is answered in order within one callback (one
`send` for the whole batch), and a partial head stays unconsumed until the
rest arrives. `Connection: close` and HTTP/1.0 requests are answered with
`Connection: close` and the connection is closed after the reply. A head
over 8 KiB gets 431. Request bodies are not supported (this is a
benchmark responder, not an HTTP implementation).
"""

from bytes.buffer import ByteBuffer
from linux import IoError, sys
from linux.consts import RLIMIT_NOFILE
from linux.probe import nofile_limit, raise_nofile_limit
from net.addr import SocketAddr
from rt.evented import CloseReason, Conn, ConnHandler, ServerConfig, TcpServer
from rt.core import Loop

from bench_common import AppPtr, AppStats, BenchLoop, CountingDriver, Ticker
from echo_util import Args, emit, getpid

comptime RESPONSE: StaticString = (
    "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\nHello, World!"
)
comptime CLOSE_RESPONSE: StaticString = (
    "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n"
    "Connection: close\r\n\r\nHello, World!"
)
comptime TOO_LARGE: StaticString = (
    "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n"
    "Connection: close\r\n\r\n"
)
comptime HEAD_END: StaticString = "\r\n\r\n"
comptime MAX_HEAD = 8192


@inline(.always)
def _lower(b: UInt8) -> UInt8:
    return b | 0x20 if b >= 65 and b <= 90 else b


def _ieq_at(h: Span[UInt8, _], at: Int, word: StaticString) -> Bool:
    var w = word.as_bytes()
    if at + len(w) > len(h):
        return False
    for i in range(len(w)):
        if _lower(h[at + i]) != w[i]:
            return False
    return True


def _crlf(h: Span[UInt8, _], start: Int) -> Int:
    var i = start
    while i + 1 < len(h):
        if h[i] == 13 and h[i + 1] == 10:
            return i
        i += 1
    return len(h)


def wants_close(head: Span[UInt8, _]) -> Bool:
    """HTTP/1.0 request line, or a `Connection` header containing `close`
    (case-insensitive)."""
    var eol = _crlf(head, 0)
    if eol >= 8 and _ieq_at(head, eol - 8, "http/1.0"):
        return True
    var i = eol + 2
    while i < len(head):
        var e = _crlf(head, i)
        if _ieq_at(head, i, "connection:"):
            var j = i + 11
            while j + 5 <= e:
                if _ieq_at(head, j, "close"):
                    return True
                j += 1
        i = e + 2
    return False


struct Hello(ConnHandler, Copyable):
    var app: AppPtr

    def __init__(out self, app: AppPtr):
        self.app = app

    def on_open(mut self, mut conn: Conn) raises IoError:
        self.app[].open += 1
        self.app[].accepted += 1

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        while True:
            var end = input.find(HEAD_END.as_bytes())
            if not end:
                if input.readable() > MAX_HEAD:
                    conn.write(TOO_LARGE)
                    input.clear()
                    conn.close()
                return
            var n = end.value() + 4
            var close = wants_close(input.readable_span()[0:n])
            input.consume(n)
            self.app[].bytes_in += 1  # requests
            if close:
                conn.write(CLOSE_RESPONSE)
                input.clear()
                conn.close()
                return
            conn.write(RESPONSE)

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        self.app[].open -= 1
        self.app[].closes += 1


def main() raises:
    var args = Args()
    args.validate(["--host", "--port", "--stats-ms", "--backlog"], ["--quiet"])
    var host = args.string("--host", "127.0.0.1")
    var port = args.int("--port", 8080)
    var stats_ms = args.int("--stats-ms", 1000)
    var backlog = args.int("--backlog", 4096)
    var quiet = args.flag("--quiet")
    _ = raise_nofile_limit(nofile_limit().max)

    var app = AppStats.zero()
    var ap = Pointer(to=app).unsafe_origin_cast[MutUntrackedOrigin]()
    var ev = BenchLoop[CountingDriver]()
    var srv = TcpServer[Hello].listen(
        ev.loop, SocketAddr.parse(String(host, ":", port)), Hello(ap), ServerConfig(backlog=backlog)
    )
    while not srv.is_listening():
        if srv.error():
            raise Error(srv.error().value())
        ev.run_once(0)
    emit(String("LISTEN ", srv.local_addr().value(), " pid=", getpid(), " server=mojo-http"))
    var ticker = Ticker(stats_ms * 1_000_000, ap, quiet)
    ticker.counts = Pointer(to=ev.driver.n).unsafe_origin_cast[MutUntrackedOrigin]()
    ticker.clock = ev.driver.clock_cell()
    ticker.start(ev.loop)
    ev.run()
    sys.keep_alive(srv)
    sys.keep_alive(ticker)
    sys.keep_alive(app)
