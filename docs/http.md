# http: the HTTP/1.1 library

HTTP/1.1 for Mojo on Linux, per RFC 9110 (semantics) and RFC 9112 (message syntax). It provides:
- message types and a header map;
- a sans-I/O parser and serializer, with body framing;
- connection state machines for both sides, implementing the `Codec` contract;
- a blocking client over `net`.

It is the base of the HTTP server (roadmap step 3). Package rules and the shared contracts are in `docs/design.md`; the transport is `net` (`docs/net.md`).

**Status: H1–H6 done.** Core types, the header map, the head parser, body framing, the connection codecs and a blocking client, independently reviewed and tuned. Next is the HTTP server (roadmap step 3), which builds on `ServerConnection`.

## Scope
**In scope:**
- HTTP/1.1 and HTTP/1.0 peers, both directions;
- persistent connections and pipelining;
- `Content-Length`, chunked (with trailers) and close-delimited bodies;
- 1xx responses, `Expect: 100-continue`, HEAD / 204 / 304;
- `Upgrade` and CONNECT, handed over as a raw stream;
- a blocking `http://` client with a keep-alive pool, connect-by-name and deadlines.

**Out of scope for now:**
- TLS (`https://`): `net` has no TLS yet.
- HTTP/2 and HTTP/3.
- Content codings (gzip, br). Bodies are delivered as sent, with the coding headers.
- Cookie jars, caches and proxies.

**Sans-I/O.** Every protocol module parses and builds bytes and never touches a socket or a clock (design contract 1). So the same code runs under a blocking stream, an epoll loop or a test that feeds byte arrays. Only `http.client` and `http.server` import `net`; `tools/check_imports.py` enforces it.

## Strictness
The parser is strict where leniency enables request smuggling or response splitting, and lenient only where RFC 9112 allows it and real peers need it.
- **Line endings.**
  - Requests need CRLF.
  - Responses may use a bare LF (RFC 9112 2.2 allows it; some old servers send it).
  - A bare CR is invalid everywhere.
- **Fields.**
  - A field name is a token, and no whitespace is allowed before the colon (RFC 9112 5.1).
  - Values may hold no control bytes. CR, LF and NUL are refused, never replaced.
  - obs-fold: refused in requests; replaced by SP in responses (RFC 9112 5.2).
  - Whitespace before the first field line is refused.
- **Framing (RFC 9112 6).**
  - A request with both `Transfer-Encoding` and `Content-Length` is refused.
  - A request whose transfer codings do not end in `chunked` is refused (501 for an unknown coding, 400 otherwise).
  - `Content-Length` values that differ are refused. Identical repeats (`42, 42`) collapse to one.
  - `Transfer-Encoding` in an HTTP/1.0 message makes its framing faulty: a request is refused, and a response is read to close.
- **Limits** (configurable): the whole head, the number of fields, chunk-size digits, chunk extensions and trailers are bounded, so a peer cannot make a parser buffer without end.

A server-side parse error carries the status to answer with (400, 414, 431, 501 or 505), and the connection is then closed.

## Using the client
```mojo
from http.client import Client
from http.headers import Headers
from linux.time import Duration


def main() raises:
    var client = Client(timeout=Duration.from_secs(10))  # per request, DNS included
    var r = client.get("http://example.com/")
    print(r.status, r.reason, r.headers.get("content-type").value())
    print(r.text())

    var h = Headers()
    h.add("Accept", "application/json")
    var p = client.request("POST", "http://127.0.0.1:8080/items", h, "{}".as_bytes())
    print(p.status)  # same host and port again: the connection is reused
```

- **Errors are `IoError`s:**
  - `InvalidInput` for a bad URL, method or header;
  - `Unsupported` for https;
  - `TimedOut` past the deadline (`e.is_deadline()`);
  - `InvalidData` for a malformed response, or one larger than `max_body`;
  - otherwise the transport's error, for example `ConnectionRefused`.
- **Status codes are not errors:** a 404 is a `Response` with `status == 404`.
- **What the client sends:** it sets Host, User-Agent and Content-Length. It refuses a caller's Content-Length or Transfer-Encoding, because it frames the body itself.
- **Retries:** if a reused connection was closed before any byte of the response, an idempotent request (GET, HEAD, OPTIONS, TRACE, PUT, DELETE) is sent again on a new connection, once. Other methods raise, because the server may have acted on them.

## Using the server codec
`ServerConnection` does HTTP for one connection and no I/O. The driver feeds it what the socket reads and sends what it hands out. This is the loop of `examples/http/hello_server.mojo` (edge-triggered epoll) without the epoll part:

```mojo
var conn = ServerConnection()
var ev = ServerEvent(EventKind.END)  # reused: its buffers are refilled
var out = ByteBuffer()
while True:
    while conn.poll(ev):  # raises on a malformed request: answer conn.error_status()
        if ev.kind == EventKind.HEAD:
            ref req = ev.head()  # method, target, version, headers
        elif ev.kind == EventKind.DATA:
            pass  # a piece of the request body: ev.data
        else:  # END: the request is complete
            var r = ResponseHead(200)
            r.headers.add("Content-Length", "2")
            conn.send_response(r)
            conn.send_body("ok".as_bytes())
            conn.end_response()
    while conn.poll_transmit(out) > 0:
        stream.write_all(out.readable_span())
        out.clear()
    if conn.should_close():
        break
    var n = stream.read(Span(buf)[0 : min(len(buf), conn.feed_capacity())])
    if n == 0:
        conn.feed_eof()
    else:
        conn.feed(Span(buf)[0:n])
```

- **The codec frames responses:**
  - With Content-Length, the body must match it.
  - Without one, it adds `Transfer-Encoding: chunked`, or closes after the body for an HTTP/1.0 client.
  - It adds `Connection: close` when the connection will close.
- **One request at a time:** the next request's events come after `end_response`.
- **`poll(ev)` or `next_event()`:** `poll` reuses one event, so a hot loop allocates almost nothing per request. `next_event()` returns a new one (the `Codec` interface).
- **Errors:** after a malformed request, `send_error(conn.error_status())` answers 400, 414, 431, 501 or 505 and the connection closes.

## Modules
| Module | What |
|---|---|
| `types` | `Version`, method names (`GET`, ...), status classes, `check_status`, `reason` (the IANA registry's phrases) |
| `headers` | `Headers`: ordered, case-insensitive multimap with validated adds, `get` / `get_all` / `combined` / `has_token`, exact bytes and a string view for obs-text, wire encoding. Also the field-syntax helpers the parser uses (`is_token`, `next_element`, ...) |
| `parse` | `HeadParser`: incremental, limit-checked parsing of request and response heads into `RequestHead` / `ResponseHead`, which also encode themselves; `Limits`; the `E_*` rule names errors carry |
| `body` | `request_framing` / `response_framing` (RFC 9112 6.3) and `content_length`; `BodyDecoder`: Content-Length, chunked with trailers, or to the end of the connection, returning ranges of the caller's input (`Piece`); `encode_chunk` / `encode_last_chunk` |
| `connection` | `ServerConnection` and `ClientConnection`: one HTTP/1.1 connection each side as a `Codec` (events `HEAD` / `DATA` / `END`, plus `INFORMATIONAL` and `UPGRADE` for clients); framing and persistence headers on what they send |
| `client` | `Client`: blocking requests to `http://` URLs with one deadline each, whole responses up to `max_body`, a keep-alive pool and a safe retry; `Url`, `Response`. Not re-exported from `http` (it imports `net`) |

## Milestones
- **H1: core types and the header map.** Done.
  - The `http` package and its import rule: sans-I/O except `client` / `server`.
  - `Headers`: one byte arena plus offset records, so a message's fields cost two buffers and `clear()` reuses them. Garbage from `set` / `remove` is compacted once it outweighs the live bytes.
  - Tested against the RFC 9110 grammar (tchar, field bytes) and Python's `HTTPStatus`, with a randomized model check and planted bugs.
  - Measured: 10 typical request fields stored in ~190 ns, a lookup ~30 ns, encoding ~110 ns.
- **H2: message-head parser.** Done.
  - `HeadParser.request` / `response` take the unconsumed bytes and return None until the head is complete. The scan resumes where it stopped, so the work is linear however the bytes are split: a 60 KB head fed one byte per call costs 25 ns per call.
  - The strictness rules above, and limits on the whole head, the start line and the field count, checked as bytes arrive. Errors name the rule broken, and requests carry the status to answer (400, 414 or 431). The limit errors do not depend on how the input was split.
  - Scans test 32 bytes per step with SIMD masks (LF search, token and target checks, value validation), and the field lines are copied into the header arena once, with fields recorded as offsets.
  - Tested rule by rule, and differentially against `tests/http/head_oracle.py`, an independent Python implementation from the RFC ABNF: 20,000 generated and mutated heads, each parsed whole and in random pieces. Every bug planted in the mutation runs (over 30, before and after the SIMD rewrite) is caught.
  - Measured on an i5-1145G7, owned heads included: picohttpparser's 705-byte benchmark request in ~510 ns (1.4 GB/s), a 215-byte response with 7 fields in ~285 ns, a minimal request in ~125 ns; large heads at 4.4 GB/s.
- **H3: body framing.** Done.
  - `request_framing` / `response_framing`: the RFC 9112 6.3 decision, with the strictness rules above. A request answers 400 (`InvalidData`) or 501 (`Unsupported`, for codings other than `chunked`).
  - `BodyDecoder` is caller-buffered like `HeadParser`. Each `decode` returns a `Piece`: the bytes to drop, and where the body data lies among them. Data is never copied by the decoder and comes out as it arrives, also in the middle of a chunk.
  - Chunked: hex sizes (at most 15 significant digits), validated extensions, line ends as for heads (bare LF in responses only), and trailers through `HeadParser.for_trailers`. A chunk-size line is scanned incrementally. Its limit, like the trailer limits, gives the same error however the input is split.
  - Tested by decision tables and rule cases, every case at feed sizes 1 to 9, and differentially against `tests/http/chunked_oracle.py`, an independent Python decoder: 20,000 generated and mutated bodies, decoded whole and in random pieces. All 28 planted bugs are caught.
  - Measured: ~55 ns of framing per chunk, whatever its size.
- **H4: connection codecs.** Done.
  - Both implement `Codec`. Events are a `HEAD`, the body as `DATA` pieces, then `END` with the trailers. `DATA` comes out as soon as body bytes arrive. Contract rule 4 is refined for byte streams: the pieces depend on the split, but their concatenation and every other event do not.
  - `ServerConnection`:
    - **One request at a time.** Pipelined requests wait in the bounded receive buffer, and `feed_capacity()` falls to 0 until the response ends (backpressure).
    - **Request checks:** HTTP/1.x only (505); the Host count per RFC 9112 3.2 (400).
    - **Response framing:** the application's Content-Length, or else chunked (HTTP/1.1) or close-delimited (HTTP/1.0). No body for HEAD and 1xx/204/304. `Connection: close` or `keep-alive` is added as persistence needs.
    - **Early responses:** a response that ends before its request body closes the connection. A full-duplex echo keeps it.
    - **Continue and 1xx:** `send_continue` and 1xx responses; a no-op for HTTP/1.0 clients.
    - **Switching:** 101 to an Upgrade request and 2xx to CONNECT hand the connection over (`take_remaining`).
    - **Errors:** a malformed request carries its status (400, 414, 431, 501, 505), and `send_error` answers it.
  - `ClientConnection`:
    - **Requests** are validated (version, Host count, `chunked`-only Transfer-Encoding) and framed from their heads. Pipelining is optional (`max_in_flight`), with responses matched in order, so HEAD and CONNECT frame correctly.
    - **Events:** 1xx are `INFORMATIONAL`; 101 needs an Upgrade request.
    - **Closing:** a closing response makes the connection unusable for more requests.
    - **EOF** before any response byte raises `E_NO_RESPONSE`, which tells a client it may retry an idempotent request.
  - Tested per behaviour on both sides, and for the same merged transcript at feed sizes 1 to 13 over mixed pipelined exchanges. A 34-mutant run over the two codecs checks the tests.
- **H5: blocking client.** Done.
  - `Client.request(method, url, headers, body)`, plus `get`, `head` and `post`, returning a whole `Response` (status, headers, body, trailers).
  - **URLs:** `Url.parse` takes `http://` only (https is `Unsupported`), with IPv6 literals and no user info.
  - **Deadline:** one per request, covering DNS, Happy Eyeballs, sending and receiving.
  - **Body limit:** `max_body`; past it, `InvalidData`.
  - **Headers it adds:** Host, User-Agent and Content-Length unless the caller gives them. A caller's framing headers are refused.
  - **Pool:** per host and port, at most `max_idle_per_host` connections, each reused within `max_idle` and only if `idle_state()` is EMPTY.
  - **Retry:** if a reused connection is dropped before any response byte (`E_NO_RESPONSE`, reset, broken pipe), an idempotent request is sent again, once, on a new connection. Other methods are not.
  - **Tested** against Python's `http.server` (`tests/http/http_peer.py`): bodies by length, chunked with trailers and to the close; HEAD; the headers sent; reuse and what is not pooled; the retry, through a route that drops second requests; the deadline; `max_body`; errors.
  - **The server codec** is tested the other way round: `tests/http/test_server_interop.mojo` drives `ServerConnection` over a socket for Python's `http.client` (keep-alive, both request framings, HEAD, close) and for raw pipelined requests read back by Python's response parser.
  - **Example:** `examples/http/http_get.mojo`.
- **H6: polish.** Done.
  - **Review.** Two independent reviews, one of parsing and framing, one of the connections and the client, found 17 issues (3 and 14). All are fixed, with regression tests in `tests/http/test_http_regressions.mojo` and `test_http_client_regressions.mojo`, each of which fails on the old code. The parser held up against the known request-smuggling vectors. The most serious issues:
    - The client pooled a connection while its codec still held unread bytes, so later responses went to the wrong requests. Leftovers now close the connection (RFC 9112 6.3).
    - Answering a bodiless request on its HEAD event ended keep-alive.
    - The client's deadline did not bound a response that keeps trickling in, nor a stream of 1xx responses.
    - The client wrote a whole body before reading, so a full-duplex server deadlocked it and an early 413 was missed; bodies of 64 MiB or more failed. Bodies are now streamed while the response is watched for.
    - Host values were not validated, a 101 could switch before the request body was read, and `max_chunk_line = Int.MAX` overflowed a limit check.
    - Early responses now keep the connection when the rest of the body is short (256 KiB at most, read by the codec), and otherwise say `Connection: close`.
  - **Performance.**
    - **Cause:** in Mojo 1.2, destroying an `Optional` of a large struct costs 100–260 ns (CLAUDE.md), and `next_event` paid that on every call.
    - **Changes:** events now box their head and trailers, and `poll(ev)` refills one event, reusing its buffers. One pass over a head's fields decides framing and persistence. The status line is written in one step, and a single Content-Length is parsed directly.
    - **Result:** the server codec's work per request went from about 2 µs to about 0.7 µs.
    - **End to end:** measured with `examples/http/hello_server.mojo` and `bench/http/load.mojo` on one core each of a 4-core laptop:

      | Load | Throughput | CPU per request, vs a server writing canned bytes |
      |---|---|---|
      | 50 keep-alive connections | ~141k req/s | ~6.8 µs vs ~6.1 µs |
      | 16 pipelined per connection | over 1M req/s | ~0.97 µs vs ~0.46 µs |
  - **Interop:** the client against Python's `http.server`, the server codec against Python's `http.client` and its response parser; the guide above; the examples `http_get` and `hello_server`.
- **Later:** a streaming response API on the client, redirects, content codings, TLS (with `net`).
