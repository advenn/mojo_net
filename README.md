# mojo_net

Native Mojo networking libraries for Linux (x86_64 and aarch64, kernel 5.15+):
- raw syscalls, with no libc on the I/O path;
- sockets;
- an HTTP/1.1 library, and an HTTP/1.1 server;
- a PostgreSQL driver, in progress, building on the same layers.

| Package | What | Status |
|---|---|---|
| `linux` | raw syscalls (inline asm), ABI mirrors, errno and `IoError`, fds, clocks, poll/epoll/eventfd, probing | stable |
| `bytes` | `ByteBuffer`, base64, and the sans-I/O `Codec` contract that protocol codecs implement | stable |
| `crypto` | SHA-256, MD5, HMAC-SHA-256, PBKDF2 and a constant-time comparison, for authentication protocols (no ciphers) | done for `pg` |
| `net` | the TCP/UDP library: addresses, every socket option, TCP/Unix streams with deadlines, connect by name, buffered frame reads, UDP sockets (blocking, nonblocking, batched, multicast) ([docs/net.md](docs/net.md)) | TCP client and UDP stable |
| `http` | HTTP/1.1: a sans-I/O head parser, body framing and connection codecs for both sides, and a blocking client with a keep-alive pool ([docs/http.md](docs/http.md)) | done |
| `server` | an HTTP/1.1 server: one epoll loop per process, a `Handler` trait, timeouts and backpressure, streamed bodies and server-sent events, graceful shutdown on SIGTERM; supervised worker processes on one port with SO_REUSEPORT; a router and static files ([docs/server.md](docs/server.md)) | done through S5 |
| `pg` | a PostgreSQL driver: a sans-I/O protocol codec, authentication up to SCRAM-SHA-256, a blocking client ([docs/pg.md](docs/pg.md)) | in progress: the codec, a blocking client and parameters are done (P4 of 7) |
| `rt` | an experimental completion-based event loop ([docs/rt.md](docs/rt.md)) | frozen |

Imports point downward only (`linux` ← `bytes` ← `net` ← `rt`, and `net` ← `http` ← `server`; `crypto` imports only the standard library, and `pg` builds on it and `net`), and only `rt` may import `rt`. The protocol code of `http` and `pg` is sans-I/O: only their client modules import `net`. CI checks these rules. Design, package rules and shared contracts: [docs/design.md](docs/design.md).

## Use
There is no published package yet. Pin the same Mojo as `pixi.toml`, and put `src/` on the include path (`mojo run -I src ...`).

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

In `examples/pg/`: `query`, which runs SQL against PostgreSQL from a `postgresql://` URI and prints each result.

And in `examples/http/`: `http_get`, a small `curl` built on `http.client.Client`; `hello_server`, an epoll server driving one `ServerConnection` per connection (over 1M pipelined requests per second on one core). In `examples/server/`: `hello`, the same on `server.Server`; `workers`, one supervised worker process per CPU on one port, stopped gracefully by SIGTERM or Ctrl-C; `files`, a static file server.

## Develop
Everything runs through [pixi](https://pixi.sh):

```bash
pixi run test             # every tests/**/test_*.mojo, plus the ABI layout check
pixi run test net/        # only files whose path contains "net/"
pixi run ci               # import rules + tests + no-libc check + example builds
```

`CLAUDE.md` lists the repository rules and the Mojo 1.2 pitfalls found so far.
