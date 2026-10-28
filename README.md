# mojo_net

> **Warning: this is an AI-generated project, and not all of it has been reviewed. Use it at your own risk.**
>
> The code, tests and documentation were written by an AI (Claude) at the direction of the maintainer. The tests compare it with independent implementations, and planted bugs show that the tests catch them. The TLS code has had two internal reviews, also by AI, but no human expert's (`docs/tls.md`). Read [SECURITY.md](SECURITY.md) before relying on it.

Native Mojo networking libraries for Linux (x86_64 and aarch64, kernel 5.15+):
- raw syscalls, with no libc on the I/O path;
- sockets;
- TLS through OpenSSL (never a TLS of our own);
- an HTTP/1.1 library, and an HTTP/1.1 server;
- a PostgreSQL driver and a Redis client, building on the same layers.

| Package | What | Status |
|---|---|---|
| `linux` | raw syscalls (inline asm), ABI mirrors, errno and `IoError`, fds, clocks, poll/epoll/eventfd, probing | stable |
| `bytes` | `ByteBuffer`, base64, and the sans-I/O `Codec` contract that protocol codecs implement | stable |
| `crypto` | SHA-256, MD5, HMAC-SHA-256, PBKDF2 and a constant-time comparison, for authentication protocols (no ciphers) | done for `pg` |
| `json` | strict JSON (RFC 8259): a parser into a flat document with typed accessors, a writer that checks structure, shortest round-trip floats (Ryū); no lenient modes, no repeated keys ([docs/json.md](docs/json.md)) | done (J1) |
| `llm` | clients for model APIs: OpenAI-compatible chat and embeddings (OpenAI, vLLM, SGLang, Ollama, `max serve`) and Anthropic's Messages, streamed token by token, with tool calls and the official SDKs' retries ([docs/llm.md](docs/llm.md)) | L1 done; tested against a fake API |
| `net` | the TCP/UDP library: addresses, every socket option, TCP/Unix streams with deadlines, connect by name, buffered frame reads, UDP sockets (blocking, nonblocking, batched, multicast) ([docs/net.md](docs/net.md)) | TCP client and UDP stable |
| `tls` | TLS 1.2/1.3 through OpenSSL 3.5: a verifying client (system roots or a CA file, names and IP addresses, ALPN) and a server (a certificate chain, SNI, ALPN, no resumption), each a sans-I/O state machine, and a blocking client stream; no knob loosens verification ([docs/tls.md](docs/tls.md)) | client and server done (T1, T2); not yet reviewed by a TLS expert |
| `http` | HTTP/1.1: a sans-I/O head parser, body framing and connection codecs for both sides, server-sent events, and a blocking `http://` and `https://` client with a keep-alive pool and streamed responses ([docs/http.md](docs/http.md)) | done |
| `server` | an HTTP/1.1 server: one epoll loop per process, a `Handler` trait, timeouts and backpressure, streamed bodies and server-sent events, HTTPS through `tls` with certificate reloading, graceful shutdown on SIGTERM; supervised worker processes on one port with SO_REUSEPORT; a router and static files ([docs/server.md](docs/server.md)) | done through S7 |
| `pg` | a PostgreSQL driver: a sans-I/O protocol codec, authentication up to SCRAM-SHA-256, a blocking client with parameters, binary types, a statement cache, transactions, LISTEN/NOTIFY and a pool ([docs/pg.md](docs/pg.md)) | done (P7: reviewed); no TLS or COPY yet |
| `redis` | a Redis client: a sans-I/O RESP2/RESP3 codec with typed replies, a blocking client with pipelines, transactions and typed helpers ([docs/redis.md](docs/redis.md)) | in progress: R3 of 6 done |
| `rt` | an experimental completion-based event loop ([docs/rt.md](docs/rt.md)) | frozen |

Imports point downward only (`linux` ← `bytes` ← `net` ← `rt`, `net` ← `tls`, and `net` ← `http` ← `server`, with `tls` under both; `crypto` and `json` import only the standard library, `llm` builds on `http` and `json`, `pg` builds on it and `net`, and `redis` on `net`), and only `rt` may import `rt`. The protocol code of `http`, `pg`, `redis` and `tls` is sans-I/O: only their client (or stream) modules import `net`. `tls` is the only package that calls C, OpenSSL's libssl, loaded at run time. CI checks these rules. Design, package rules and shared contracts: [docs/design.md](docs/design.md).

## Use
The libraries (all but `rt`) are one conda package, `mojo-net`. It is not published, and it is not meant for production use. Build it with `pixi run package`; `output/` is then a conda channel that another pixi project can install it from:

```toml
[workspace]
channels = ["file:///path/to/mojo_net/output", "https://conda.modular.com/max", "conda-forge"]
platforms = ["linux-64", "linux-aarch64"]

[dependencies]
mojo = ">=1.2,<1.3"
mojo-net = "0.1.*"
```

The package holds sources, which the compiler finds with no `-I`. CI also keeps each build as a workflow artifact. Without the package, put `src/` on the include path instead (`mojo run -I src ...`). The APIs of `linux`, `bytes` and `net` are stable (`api/*.txt`; see "Stability" in `docs/design.md`).

```mojo
from linux.time import Deadline, Duration
from net.tcp import TcpStream


def main() raises:
    # Host names resolve without libc; IPv6 and IPv4 race (Happy Eyeballs).
    var conn = TcpStream.connect_host("localhost", 7878, Duration.from_secs(3))
    conn.set_deadline(Deadline.after(Duration.from_secs(5)))
    conn.write_all("ping\n".as_bytes())
    var reply = List[UInt8](length=5, fill=0)
    conn.read_exact(Span(reply))
    print(String(from_utf8_lossy=Span(reply)), end="")
```

More in `examples/net/`:
- a blocking echo server and client;
- a Unix-socket echo;
- a tiny netcat;
- a Redis `PING`, with sans-I/O RESP encoding and parsing;
- a readiness-loop echo server: edge-triggered epoll and `try_read` / `try_write`, with no runtime;
- a UDP echo server (blocking, or an epoll loop with batched `recvmmsg` / `sendmmsg`) and a UDP ping client.

In `examples/pg/`: `query`, which runs SQL against PostgreSQL from a `postgresql://` URI and prints each result; `listen`, which waits for notifications on a channel. In `examples/redis/`: `cli`, which runs one command against a Redis or Valkey server and prints the reply; `transfer`, which moves an amount between two balances with WATCH and a transaction.

And in `examples/http/`: `http_get`, a small `curl` built on `http.client.Client`; `sse_events`, which prints a URL's server-sent events as they arrive (as from an LLM API); `hello_server`, an epoll server driving one `ServerConnection` per connection (over 1M pipelined requests per second on one core). In `examples/server/`: `hello`, the same on `server.Server`; `sse_tokens`, tokens streamed as server-sent events the way an OpenAI-compatible server sends them; `workers`, one supervised worker process per CPU on one port, stopped gracefully by SIGTERM or Ctrl-C; `files`, a static file server.

## Benchmark
`server` against Go (`net/http` and fasthttp), Rust (hyper) and nginx, on TechEmpower's plaintext test (`GET /plaintext` → `Hello, World!`), loaded by wrk over loopback:
- each server in its fastest usual form: Go with PGO, fasthttp with one process per CPU, hyper with fat LTO and `target-cpu=native`;
- each run 60 s long, one server at a time, the whole set twice (the second time in reverse order);
- one laptop, an i5-1145G7 (4 cores, 8 threads), on 2026-10-28, with a desktop session sharing the machine.

Requests per second, the mean of the two runs:

| Scenario | mojo `server` | hyper | fasthttp | nginx | Go `net/http` |
|---|---|---|---|---|---|
| 1 CPU, 64 keep-alive connections | 168k | 172k | 162k | 156k | 82k |
| 1 CPU, 256 connections, 16 pipelined | 1,185k | 1,193k | 1,123k | 200k | 103k |
| 1 CPU, 1024 keep-alive connections | 144k | 146k | 123k | 141k | 67k |
| 4 CPUs, 256 keep-alive connections | 350k | 340k | 317k | 322k | 154k |
| 4 CPUs, 256 connections, 16 pipelined | 2,153k | 2,073k | 1,950k | 403k | 180k |

- **Keep-alive:** mojo, hyper, fasthttp and nginx are within a few percent of each other; the runs' ranges overlap (the first one-CPU run shared the machine with other work). Most of each request's time there is the kernel's loopback TCP, the same for every server. With 4 CPUs, wrk itself was the limit (87–92% of its CPU).
- **Pipelined:** mojo takes 0.84 µs of CPU a request on one CPU, hyper 0.83, and fasthttp 0.88; on 4 CPUs mojo is ahead. nginx and `net/http` gain little from pipelining.
- **A day earlier,** before the `http` and `server` reviews, mojo was 30–37% behind hyper pipelined (762k against 1,169k on one CPU): its own code did twice hyper's work, mostly in the handling of header fields. Those reviews took it from 9,644 user-space instructions a request to 4,227 (hyper: 4,565).

### How it is measured
- **The test:** `GET /plaintext` → `200 OK`, `Hello, World!` as `text/plain`, with Content-Length, Date and Server: 127 to 161 bytes a response depending on the server. Each server uses its smallest idiomatic handler (mojo: a `server.Handler` calling `res.text`; Go: a `ServeMux` route; fasthttp: a request handler; hyper: `http1` with `pipeline_flush` and a `service_fn`; nginx: `return 200`). `bench-server check` sends each one request and then 16 pipelined, on 1 and 4 CPUs, and checks every answer before anything is measured.
- **The load:** wrk, 4 threads, closed-loop over loopback, keep-alive for the whole run: `wrk -t4 -c<connections> -d60s --timeout 10s --latency`, plus a Lua script (`bench/server/pipeline.lua`) that sends 16 requests in each write for the pipelined rows. The connections per scenario are in the table above (64, 256 or 1024).
- **No shared cores:** the server and wrk are each pinned with `taskset` to separate physical cores, read from the CPU topology. wrk gets cores 0 and 1 (4 hardware threads); a one-CPU server gets one hardware thread with its sibling left idle; a four-CPU server gets two whole cores (4 hardware threads, at the lower all-core clock). Multi-CPU servers run their usual way: mojo as one worker process per CPU with its own SO_REUSEPORT listener (`run_workers`), fasthttp prefork, hyper one tokio `current_thread` runtime per CPU, nginx one worker per CPU, Go one process with `GOMAXPROCS`.
- **One run at a time:** for each server and scenario, the machine first idles 15 s, and waits longer while other work uses more than 1 CPU; then the server starts afresh, is warmed up for 5 s with the same load (thrown away), measured for 60 s, and stopped. Each scenario runs the five servers in turn; the second rep runs them in the reverse order, and the tables show the mean of the two reps.
- **What is recorded per run:** requests per second and latency percentiles from wrk; the server's CPU per request (user + system time of every process in its process group, from `/proc`, which on loopback includes the kernel's TCP work for its sockets); wrk's own CPU (near 100% the client, not the server, is the limit); the CPU time the rest of the machine used ("others"); and the server CPUs' clock and the package temperature, sampled every second. The mean latency comes from Little's law (connections × requests a write / req/s), since wrk's own percentiles are wrong for pipelined runs.
- **The profile:** separately, `bench-profile` runs mojo and hyper under valgrind's callgrind (16 connections × 16 pipelined, one CPU) and counts user-space instructions a request, by file, function and line.
- **Caveats:** one laptop with the client on the same machine, over loopback; wrk is closed-loop, so its latencies leave out the queueing an open-loop client would see; a desktop session shared the machine; the `powersave` governor with turbo, so the clock moves with temperature (recorded per run).

The method in full, every run's numbers, the full profile and how to run it all yourself (`pixi run -e bench bench-server build`, `check`, `run`) are in [bench/server/README.md](bench/server/README.md). How the gap was found and closed, with every hot spot's file and line: [bench/server/why_mojo_is_slower.note](bench/server/why_mojo_is_slower.note).

## Develop
Everything runs through [pixi](https://pixi.sh):

```bash
pixi run test             # every tests/**/test_*.mojo, plus the ABI layout check
pixi run test net/        # only files whose path contains "net/"
pixi run ci               # import rules + stable API + tests + no-libc check + example builds
pixi run package          # the conda package, built and tested in a fresh environment
```

GitHub CI runs `ci` and `package` on x86_64 and on a real aarch64 machine.

`CLAUDE.md` lists the repository rules and the Mojo 1.2 pitfalls found so far.

## License
[Apache License 2.0](LICENSE). The software is provided "as is", without warranties or conditions of any kind (section 7 of the license).
