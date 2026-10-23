# http: the HTTP/1.1 library

HTTP/1.1 for Mojo on Linux, per RFC 9110 (semantics) and RFC 9112 (message syntax). It provides:
- message types and a header map;
- a sans-I/O parser and serializer, with body framing;
- connection state machines for both sides, implementing the `Codec` contract;
- a blocking client over `net`.

It is the base of the HTTP server (roadmap step 3). Package rules and the shared contracts are in `docs/design.md`; the transport is `net` (`docs/net.md`).

**Status: active.** H1 (core types, header map), H2 (head parser) and H3 (body framing) are done; H4 (connection codecs) is next.

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

## Modules
| Module | What |
|---|---|
| `types` | `Version`, method names (`GET`, ...), status classes, `check_status`, `reason` (the IANA registry's phrases) |
| `headers` | `Headers`: ordered, case-insensitive multimap with validated adds, `get` / `get_all` / `combined` / `has_token`, exact bytes and a string view for obs-text, wire encoding. Also the field-syntax helpers the parser uses (`is_token`, `next_element`, ...) |
| `parse` | `HeadParser`: incremental, limit-checked parsing of request and response heads into `RequestHead` / `ResponseHead`, which also encode themselves; `Limits`; the `E_*` rule names errors carry |
| `body` | `request_framing` / `response_framing` (RFC 9112 6.3) and `content_length`; `BodyDecoder`: Content-Length, chunked with trailers, or to the end of the connection, returning ranges of the caller's input (`Piece`); `encode_chunk` / `encode_last_chunk` |

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
- **H4: connection codecs.** `ClientConnection` and `ServerConnection` implementing `Codec`: keep-alive, pipelining, 1xx, HEAD / 204 / 304, `Connection: close`, upgrades.
- **H5: blocking client.** `Url`, a keep-alive pool checked with `idle_state()`, `connect_host`, one deadline per request, bounded and streaming bodies; `http://` only.
- **H6: polish.** Interop against Python's `http.server` and `http.client`, examples, the guide, an independent review, performance.
