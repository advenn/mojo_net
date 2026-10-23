# http: the HTTP/1.1 library

HTTP/1.1 for Mojo on Linux, per RFC 9110 (semantics) and RFC 9112 (message syntax). It provides:
- message types and a header map;
- a sans-I/O parser and serializer, with body framing;
- connection state machines for both sides, implementing the `Codec` contract;
- a blocking client over `net`.

It is the base of the HTTP server (roadmap step 3). Package rules and the shared contracts are in `docs/design.md`; the transport is `net` (`docs/net.md`).

**Status: active.** H1 (core types, header map) is done; H2 (parser) is next.

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

## Milestones
- **H1: core types and the header map.** Done.
  - The `http` package and its import rule: sans-I/O except `client` / `server`.
  - `Headers`: one byte arena plus offset records, so a message's fields cost two buffers and `clear()` reuses them. Garbage from `set` / `remove` is compacted once it outweighs the live bytes.
  - Tested against the RFC 9110 grammar (tchar, field bytes) and Python's `HTTPStatus`, with a randomized model check and planted bugs.
  - Measured: 10 typical request fields stored in ~190 ns, a lookup ~30 ns, encoding ~110 ns.
- **H2: message-head parser.** Incremental (resumes the end-of-head scan where it stopped), limits, the strictness rules above; fuzzed with random splits and mutations, and benchmarked.
- **H3: body framing.** Content-Length, chunked with trailers, close-delimited; the RFC 9112 6.3 rules.
- **H4: connection codecs.** `ClientConnection` and `ServerConnection` implementing `Codec`: keep-alive, pipelining, 1xx, HEAD / 204 / 304, `Connection: close`, upgrades.
- **H5: blocking client.** `Url`, a keep-alive pool checked with `idle_state()`, `connect_host`, one deadline per request, bounded and streaming bodies; `http://` only.
- **H6: polish.** Interop against Python's `http.server` and `http.client`, examples, the guide, an independent review, performance.
