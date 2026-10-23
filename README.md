# mojo_net

Native Mojo networking libraries for Linux (x86_64 and aarch64, kernel 5.15+):
- raw syscalls, with no libc on the I/O path;
- sockets;
- an HTTP/1.1 library (in progress), and the layers that an HTTP server and database drivers will build on.

| Package | What | Status |
|---|---|---|
| `linux` | raw syscalls (inline asm), ABI mirrors, errno and `IoError`, fds, clocks, poll/epoll/eventfd, probing | stable |
| `bytes` | `ByteBuffer` and the sans-I/O `Codec` contract that protocol codecs implement | stable |
| `net` | the TCP/UDP library: addresses, every socket option, TCP/Unix streams with deadlines, connect by name, buffered frame reads, UDP sockets (blocking, nonblocking, batched, multicast) ([docs/net.md](docs/net.md)) | TCP client and UDP stable |
| `http` | HTTP/1.1: a sans-I/O head parser, body framing and connection codecs for both sides, and a blocking client with a keep-alive pool ([docs/http.md](docs/http.md)) | in progress |
| `rt` | an experimental completion-based event loop ([docs/rt.md](docs/rt.md)) | frozen |

Imports point downward only (`linux` ← `bytes` ← `net` ← `rt`, and `net` ← `http`), and only `rt` may import `rt`. `http`'s protocol code is sans-I/O: only its client and server modules import `net`. CI checks these rules. Design, package rules and shared contracts: [docs/design.md](docs/design.md).

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

And in `examples/http/`: `http_get`, a small `curl` built on `http.client.Client`.

## Develop
Everything runs through [pixi](https://pixi.sh):

```bash
pixi run test             # every tests/**/test_*.mojo, plus the ABI layout check
pixi run test net/        # only files whose path contains "net/"
pixi run ci               # import rules + tests + no-libc check + example builds
```

`CLAUDE.md` lists the repository rules and the Mojo 1.2 pitfalls found so far.
