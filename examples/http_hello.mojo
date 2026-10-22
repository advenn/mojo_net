"""A minimal HTTP/1.1 keep-alive "Hello, World!" server on `net.evented`.

    pixi run mojo run -I src examples/http_hello.mojo [ADDR]
    curl -v http://127.0.0.1:8080/

ADDR defaults to 127.0.0.1:8080. bench/http_hello.mojo is the same handler
with benchmark counters (results in bench/README.md).

The protocol logic is one `on_data` callback:
- `input` holds everything received and not yet consumed, so a request
  head split across reads simply waits until its CRLFCRLF arrives;
- every complete head in `input` is answered, in order, in the same
  callback: pipelined requests cost one `send` for the whole batch;
- `Connection: close` (or HTTP/1.0) gets `Connection: close` and the
  connection closes after the reply; the default lingering close sends FIN
  and drains input first, so the client cannot lose the reply to an RST;
- a head over 8 KiB gets 431 and the connection closes.
Request bodies are not supported: this shows the connection layer, it is
not an HTTP implementation. Idle keep-alive connections close after 60 s.
"""

from std.sys import argv

from bytes.buffer import ByteBuffer
from linux import IoError
from net.addr import SocketAddr
from net.evented import Conn, ConnConfig, ConnHandler, ServerConfig, TcpServer
from rt.event_loop import EventLoop

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
comptime IDLE_NS = 60 * 1_000_000_000


@inline(.always)
def _lower(b: UInt8) -> UInt8:
    return b | 0x20 if b >= 65 and b <= 90 else b


def _ieq_at(h: Span[UInt8, _], at: Int, word: StaticString) -> Bool:
    """`h[at:]` starts with the lowercase `word`, ignoring ASCII case."""
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
    """HTTP/1.0 request line, or a `Connection` header containing `close`."""
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


@fieldwise_init
struct Hello(ConnHandler, Copyable):
    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        while True:
            var end = input.find(HEAD_END.as_bytes())
            if not end:
                if input.readable() > MAX_HEAD:
                    conn.write(TOO_LARGE)
                    input.clear()
                    conn.close()
                return  # wait for the rest of the head
            var n = end.value() + 4
            var close = wants_close(input.readable_span()[0:n])
            input.consume(n)
            if close:
                conn.write(CLOSE_RESPONSE)
                input.clear()
                conn.close()
                return
            conn.write(RESPONSE)


def main() raises:
    var args = argv()
    var addr = SocketAddr.parse(args[1] if len(args) > 1 else "127.0.0.1:8080")
    var ev = EventLoop()
    var srv = TcpServer[Hello].listen(
        ev.loop, addr, Hello(), ServerConfig(conn=ConnConfig(idle_timeout_ns=IDLE_NS), backlog=4096)
    )
    while not srv.is_listening():
        if srv.error():
            raise Error("listen failed: ", srv.error().value())
        ev.run_once(0)
    print("http_hello listening on http://" + String(srv.local_addr().value()) + "/")
    ev.run()
