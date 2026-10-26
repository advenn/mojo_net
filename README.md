# mojo_net

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
| `net` | the TCP/UDP library: addresses, every socket option, TCP/Unix streams with deadlines, connect by name, buffered frame reads, UDP sockets (blocking, nonblocking, batched, multicast) ([docs/net.md](docs/net.md)) | TCP client and UDP stable |
| `tls` | TLS 1.2/1.3 through OpenSSL 3.5: a verifying client (system roots or a CA file, names and IP addresses, ALPN) as a sans-I/O state machine, and a blocking stream; no knob loosens verification ([docs/tls.md](docs/tls.md)) | client done (T1); not yet reviewed by a TLS expert |
| `http` | HTTP/1.1: a sans-I/O head parser, body framing and connection codecs for both sides, server-sent events, and a blocking `http://` and `https://` client with a keep-alive pool and streamed responses ([docs/http.md](docs/http.md)) | done |
| `server` | an HTTP/1.1 server: one epoll loop per process, a `Handler` trait, timeouts and backpressure, streamed bodies and server-sent events, graceful shutdown on SIGTERM; supervised worker processes on one port with SO_REUSEPORT; a router and static files ([docs/server.md](docs/server.md)) | done through S5 |
| `pg` | a PostgreSQL driver: a sans-I/O protocol codec, authentication up to SCRAM-SHA-256, a blocking client with parameters, binary types, a statement cache, transactions, LISTEN/NOTIFY and a pool ([docs/pg.md](docs/pg.md)) | done (P7: reviewed); no TLS or COPY yet |
| `redis` | a Redis client: a sans-I/O RESP2/RESP3 codec with typed replies, a blocking client with pipelines, transactions and typed helpers ([docs/redis.md](docs/redis.md)) | in progress: R3 of 6 done |
| `rt` | an experimental completion-based event loop ([docs/rt.md](docs/rt.md)) | frozen |

Imports point downward only (`linux` ← `bytes` ← `net` ← `rt`, `net` ← `tls`, and `net` ← `http` ← `server`; `crypto` imports only the standard library, `pg` builds on it and `net`, and `redis` on `net`), and only `rt` may import `rt`. The protocol code of `http`, `pg`, `redis` and `tls` is sans-I/O: only their client (or stream) modules import `net`. `tls` is the only package that calls C, OpenSSL's libssl, loaded at run time. CI checks these rules. Design, package rules and shared contracts: [docs/design.md](docs/design.md).

## Use
The libraries (all but `rt`) are one conda package, `mojo-net`, which is not published yet. Build it with `pixi run package`; `output/` is then a conda channel that another pixi project can install it from:

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
