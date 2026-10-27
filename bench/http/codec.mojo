"""Per-request CPU of the HTTP codecs, in one process (no sockets, no
server): the work `http` itself does for each request and response.

    pixi run mojo build -I src bench/http/codec.mojo -o build/bench_codec && build/bench_codec [ROUNDS [SHAPE]]

Server side (`ServerConnection`): each request is fed, polled to its END,
answered with a 13-byte "hello, world!" (Content-Length, as the server's
plaintext route), and the response taken out. Client side
(`ClientConnection`): a request sent, a typical response fed and polled to
its END. Shapes: `wrk` (a two-line GET, what the server benchmark sends),
`browser` (a GET with a browser's 14 header fields, cookies included),
`post` (a 64-byte JSON body), and `pipelined` (`wrk` 16 at a time in one
feed, server side only: the client sends one request at a time). Prints
ns per request, the best of ROUNDS (default 7) rounds of 200,000, so a run
on a loaded machine still reads near its quiet floor
(bench/server/README.md: measure at quiet moments). SHAPE (`wrk`,
`browser`, `post`, `pipelined`, `client`) runs one shape only, for a
profile:

    valgrind --tool=callgrind --callgrind-out-file=build/cg.wrk build/bench_codec 1 wrk
    pixi run -e bench python3 bench/server/profile.py --analyze build/cg.wrk --requests 200000
"""

from std.sys import argv

from bytes.buffer import ByteBuffer
from http.connection import ClientConnection, ClientEvent, EventKind, ServerConnection, ServerEvent
from http.parse import RequestHead, ResponseHead
from linux.time import Duration, Instant

comptime N = 200_000

comptime WRK = "GET /plaintext HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"
comptime BROWSER = (
    "GET /static/app.js?v=3 HTTP/1.1\r\n"
    "Host: www.example.com\r\n"
    "Connection: keep-alive\r\n"
    "sec-ch-ua: \"Chromium\";v=\"130\", \"Not?A_Brand\";v=\"99\"\r\n"
    "sec-ch-ua-mobile: ?0\r\n"
    "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n"
    "sec-ch-ua-platform: \"Linux\"\r\n"
    "Accept: */*\r\n"
    "Sec-Fetch-Site: same-origin\r\n"
    "Sec-Fetch-Mode: no-cors\r\n"
    "Sec-Fetch-Dest: script\r\n"
    "Referer: https://www.example.com/\r\n"
    "Accept-Encoding: gzip, deflate, br, zstd\r\n"
    "Accept-Language: en-US,en;q=0.9\r\n"
    "Cookie: session=4f1c2a9e7b3d4c5e8f6a; theme=dark; _ga=GA1.1.123456789.1700000000\r\n"
    "\r\n"
)
comptime POST = (
    "POST /v1/items HTTP/1.1\r\n"
    "Host: api.example.com\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 64\r\n"
    "\r\n"
    "{\"name\":\"widget\",\"count\":12,\"tags\":[\"a\",\"b\"],\"ok\":true,\"n\":100}\n"  # (64 bytes)
)
comptime RESPONSE = (
    "HTTP/1.1 200 OK\r\n"
    "Date: Mon, 27 Oct 2026 12:00:00 GMT\r\n"
    "Server: example\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 13\r\n"
    "Cache-Control: no-store\r\n"
    "X-Request-Id: 8b1f2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d\r\n"
    "Vary: Accept-Encoding\r\n"
    "\r\n"
    "hello, world!"
)


def _server(request: StringSlice, per_feed: Int) raises -> Int:
    """ns for N requests, `per_feed` of them in each feed."""
    var conn = ServerConnection()
    var ev = ServerEvent(EventKind.END)
    var out = ByteBuffer()
    var one = List[UInt8](request.as_bytes())
    var batch = List[UInt8]()
    for _ in range(per_feed):
        batch.extend(Span(one))
    var body = List[UInt8]("hello, world!".as_bytes())
    var answered = 0
    var t = Instant.now()
    while answered < N:
        conn.feed(Span(batch))
        var left = per_feed
        while left > 0:
            if not conn.poll(ev):
                raise Error("the request did not end")
            if ev.kind == EventKind.END:
                var r = ResponseHead(200)
                r.headers.add("Content-Length", "13")
                conn.send_response(r)
                conn.send_body(Span(body))
                conn.end_response()
                while conn.poll_transmit(out) > 0:
                    out.clear()
                left -= 1
                answered += 1
    return Int((t.elapsed()).as_nanos())


def _client(per_feed: Int) raises -> Int:
    """ns for N exchanges (`ClientConnection` sends one request at a time:
    `per_feed` is 1)."""
    var conn = ClientConnection()
    var ev = ClientEvent(EventKind.END)
    var out = ByteBuffer()
    var one = List[UInt8](RESPONSE.as_bytes())
    var batch = List[UInt8]()
    for _ in range(per_feed):
        batch.extend(Span(one))
    var done = 0
    var t = Instant.now()
    while done < N:
        for _ in range(per_feed):
            var h = RequestHead("GET", "/v1/items/42")
            h.headers.add("Host", "api.example.com")
            conn.send_request(h)
            conn.end_request()
        while conn.poll_transmit(out) > 0:
            out.clear()
        conn.feed(Span(batch))
        var left = per_feed
        while left > 0:
            if not conn.poll(ev):
                raise Error("the response did not end")
            if ev.kind == EventKind.END:
                left -= 1
                done += 1
    return Int((t.elapsed()).as_nanos())


def main() raises:
    var args = argv()
    var rounds = atol(args[1]) if len(args) > 1 else 7
    var only = String(args[2]) if len(args) > 2 else String()
    var keys: List[String] = ["wrk", "browser", "post", "pipelined", "client"]
    var names: List[String] = ["server wrk", "server browser", "server post", "server pipelined x16", "client response"]
    var best = List[Int](length=len(names), fill=Int.MAX)
    for _ in range(rounds):
        for i in range(len(names)):
            if only.byte_length() > 0 and keys[i] != only:
                continue
            var ns: Int
            if i == 0:
                ns = _server(WRK, 1)
            elif i == 1:
                ns = _server(BROWSER, 1)
            elif i == 2:
                ns = _server(POST, 1)
            elif i == 3:
                ns = _server(WRK, 16)
            else:
                ns = _client(1)
            best[i] = min(best[i], ns)
    for i in range(len(names)):
        if best[i] < Int.MAX:
            print(String(names[i], ": ", Float64(best[i]) / Float64(N), " ns/request"))
