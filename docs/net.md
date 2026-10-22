# net: the TCP/socket library

Sockets for Mojo on Linux. It provides:
- addresses;
- every socket option;
- blocking TCP and Unix streams with deadlines;
- building blocks for servers that run their own readiness loop.

It is the transport under the planned HTTP library, HTTP server and database drivers. Package rules and the shared contracts (sans-I/O codecs, errors, fds, determinism seams) are in `docs/design.md`.

**Status: active.** M1 is done; M2 (TCP v1) is done for clients (items 1–5, and item 6 except packaging and a real aarch64 run). The client API is stable (see "v1 client API").

## Scope
**In scope:**
- addresses;
- every socket option;
- blocking TCP/Unix streams with deadlines;
- nonblocking access for callers that run their own readiness loop (`linux.Epoll`);
- buffered reading;
- DNS resolution and connect-by-name.

**Out of scope: an async runtime** (event loop, executor, timers, scheduling, io_uring proactor, simulation). That is the separate, frozen `rt` package (`docs/rt.md`). `net` never imports it, and `tools/check_imports.py` enforces that.

**How a concurrent server uses this library without a runtime:**
- Make sockets nonblocking and drive them from a readiness loop (epoll, edge-triggered).
- For multi-core, run N processes on one port with `SO_REUSEPORT`, as nginx does.

The M1 spike's raw-epoll server shows this is enough. It held 11k connections at C/tokio throughput, using 123–159 B of user memory per connection. The rules it found are listed below.

## Modules
| Module | What |
|---|---|
| `addr` | `Ipv4Addr`, `Ipv6Addr`, `IpAddr`, `SocketAddr`/`V4`/`V6`, `UnixAddr`, `if_nametoindex` |
| `socket` | L1: `Socket` and every socket option, no policy |
| `blocking`, `tcp`, `unix` | L2: `TcpStream`, `TcpListener`, `UnixStream`, `UnixListener` and friends |
| `udp` | `UdpSocket`: datagrams, blocking with per-direction deadlines or nonblocking (`try_*`); truncation reported (`Datagram`), connected sockets with ICMP errors |
| `reader` | `BufReader`: bounded, all-or-nothing frame reads over any `Read` stream (`TcpStream`, `UnixStream`) |
| `dial` | `dial_tcp` / `TcpStream.connect_host`: connect by host name with Happy Eyeballs v2 (RFC 8305); `HostPort` parses `host:port` |
| `resolver` | `Resolver`: host names to addresses (literals, /etc/hosts, `localhost`, DNS over UDP with TCP fallback); `Lookup`, the same as an incremental state machine |
| `resolv` | `/etc/resolv.conf` (`ResolvConf`), `/etc/hosts` (`Hosts`) and the search list (`search_names`), parsed as glibc does |
| `dns` | DNS messages, sans-I/O: A/AAAA queries (optionally EDNS(0)) and defensive response parsing that ignores forged or unrelated packets (RFC 5452) |
| `buffer`, `codec` | re-exports of `bytes.buffer` and `bytes.codec` |

## Using the client
```mojo
from linux.time import Deadline, Duration
from net import BufReader, TcpStream

var conn = TcpStream.connect_host("db.internal", 5432, Duration.from_secs(5))
conn.detect_dead_peers()            # long-lived (pooled) connections
var r = BufReader(conn^)
r.stream().set_deadline(Deadline.after(Duration.from_secs(10)))
r.stream().write_all(request)
var reply = r.read_until("\r\n".as_bytes(), max_bytes=64 * 1024)
```
- **Connecting.**
  - `connect_host(host, port, timeout)`: a name or an IP literal. It resolves without libc and races IPv6 and IPv4 (Happy Eyeballs v2); the timeout covers both resolution and connecting.
  - `connect_timeout(SocketAddr, timeout)` when you already have an address.
  - Pools keep one `Resolver` (`Resolver.system()`) and call `connect_host_deadline(..., resolver)`, so the config files are read once.
- **Deadlines** are absolute and per direction, and bound waiting only. A `BufReader` frame read that times out loses nothing: call it again with a new deadline.
- **Framing.** `BufReader` gives bounded frame reads: `read_until`, `read_line`, `read_exact`, and the zero-copy `fill_until` + `buffer()` + `consume`. A `max_bytes` overflow is `InvalidData`; EOF inside a frame is `UnexpectedEof`; a clean EOF returns None.
- **Pools.** Call `detect_dead_peers()` once per connection. Before reusing one, check that `idle_state()` is EMPTY and, with a `BufReader`, that `buffer()` is empty. Otherwise discard it, or read the pending data if the protocol pushes (Postgres LISTEN).
- **Errors** (`IoError.kind`):
  - `TimedOut`: `is_deadline()` is true when our own deadline passed, false for the kernel's ETIMEDOUT (keepalive or user timeout);
  - `ConnectionRefused`; `ConnectionReset` / `BrokenPipe` (the peer went away);
  - `NotFound` with op "resolve" (no such host);
  - `UnexpectedEof`;
  - `InvalidData` (a limit or the protocol);
  - `InvalidInput` (a bad argument).
- **Readiness loops** use `try_read` / `try_write` / `try_accept`, which return None instead of waiting (see the rules below).
- **Cost** (x86_64, Mojo 1.2.0):
  - `connect_host("127.0.0.1")` takes 16 µs, the same as connecting to a `SocketAddr`; `"localhost"` takes 29 µs, including the refused `::1` attempt.
  - Resolution: hosts-file names in 8 µs (glibc `getaddrinfo`: 36 µs, since it re-reads the files every call). A DNS lookup costs one round trip, like glibc (4.1 ms against 4.3 ms here; A and AAAA in parallel).
  - `BufReader` framing has ~25 ns of overhead per frame plus a SIMD scan (6.4 GB/s on 1 KiB lines, zero-copy). `read_line` adds one allocation per line (~40 ns).

## v1 client API
These names and their documented behavior are stable for v1.
- **Changes are additive.** A replacement first ships beside the old name, which stays working with a deprecation warning (as `Epoll.wait(timeout_ns)` and `set_linger(Int)` did).
- **Internal names** (with a leading `_`) are not part of it.

| Area | API |
|---|---|
| Connecting | `TcpStream.connect` / `connect_timeout` / `connect_deadline` (an address); `connect_host` / `connect_host_deadline` (a name or literal, Happy Eyeballs; optionally with a `Resolver`); `net.dial.HostPort` |
| Streams | `TcpStream` and `UnixStream`: `read`, `read_exact`, `read_to_end`, `read_vectored`, `peek`, `write`, `write_all`, `write_vectored`, `shutdown`; `set_read_deadline` / `set_write_deadline` / `set_deadline` and their getters; `try_read`, `try_write`, `idle_state`; `local_addr`, `peer_addr`, `socket`, `try_clone`, `from_socket`, `into_socket`, `close`. TCP only: `detect_dead_peers` |
| Listeners | `TcpListener` / `UnixListener`: `bind` (TCP also `bind_reuseport`), `accept`, `try_accept`, `set_deadline` / `deadline`, `local_addr`, `socket`, `try_clone`, `from_socket`, `into_socket`, `close` |
| Framing | `BufReader[S: Read]` (the `Read` trait): `stream`, `into_parts`, `buffer`, `consume`, `capacity`, `max_size`, `fill`, `fill_until`, `read_until`, `read_line`, `read_exact`, `read` |
| Resolution | `Resolver` (`system`, `lookup_ip`, `start`), `Lookup`, `net.resolv.ResolvConf` / `Hosts` / `search_names`; the `net.dns` message helpers |
| Errors | `IoError{kind, errno, op}`: the kinds under "Using the client" |

## L2 blocking contract (as built in M1)
- **Nonblocking internally.** Every op is: try once → on EAGAIN `wait_ready` (ppoll) → retry. EINTR retries.
- **Deadlines.** They are absolute and per direction (`set_read_deadline` / `set_write_deadline` / `set_deadline`), and apply to every later op. Expiry raises `TimedOut` and leaves the stream usable.
  - A deadline limits *waiting*, not work: data that is already available wins over an expired deadline.
- **POLLERR.** POLLERR caused only by the error queue is not progress; review finding F01 was a busy-spin from exactly that.
- **Connect.**
  - TCP connect is never re-issued after EINTR: wait for writable, then read `SO_ERROR`.
  - AF_UNIX connect timeouts use `SO_SNDTIMEO`.
- **Return types.** `accept` returns a struct (`TcpAccepted`), not a tuple (see the Mojo move rules in `CLAUDE.md`).

## Rules for readiness-loop servers (from the 10k spike, `docs/spikes.md`)
- **API:**
  - streams: `try_read` / `try_write`;
  - listeners: `try_accept`;
  - `TcpListener.bind_reuseport` for one process per core;
  - `linux.probe.raise_nofile_limit` and `pregrow_fd_table` at startup.
  - `examples/net/epoll_echo.mojo` follows every rule below.
- **Syscall budget: 2 syscalls per message.**
  - Register once, edge-triggered, with no `EPOLL_CTL_MOD` per operation.
  - Read and write until EAGAIN.
  - Drain accept until EAGAIN.
  - Batch ~1024 events per wait.
- **Sticky read-closed.** Once RDHUP/HUP/ERR has been seen, read to EOF or EAGAIN. Otherwise a FIN that arrives with data is lost.
- **Pre-grow the fd table at startup** with `linux.probe.pregrow_fd_table(listener)`. Every Mojo process is multi-threaded, so otherwise each fd-table doubling stalls 20–40 ms under load.
- **EMFILE.** Pause accepting rather than spin on a readable listener. Log with raw `write(2)`.

## Milestones
- **M1: foundation and blocking transport (with `linux` and `bytes`). Done.**
  - **Scope:**
    - syscalls, ABI, errors, fds;
    - addresses;
    - a socket2-style `Socket`;
    - L2 TCP/Unix with deadlines;
    - time, poll, probe, epoll, eventfd;
    - the fault seam;
    - `Codec` + `ByteBuffer`;
    - examples.
  - **Review:** a 5-lens adversarial review confirmed and fixed 49 issues.
  - **Spike:** 11k connections at C/tokio speed.
- **M2: TCP v1.**
  1. **Buffered reader.** Done: `net.reader.BufReader`.
     - `read_until(delim, max)`, `read_line`, `read_exact`;
     - zero-copy `fill`/`fill_until` + `buffer()` + `consume`;
     - pipelined leftovers are kept, and `into_parts` hands them back.
     - Every frame read is all or nothing, so a deadline that expires mid-frame loses nothing.
  2. **DNS stub resolver**, blocking and pure Mojo:
     - the wire codec (`net.dns`): done, fuzzed and ASan-clean;
     - `/etc/hosts` and `resolv.conf` (search, ndots, timeout, attempts, rotate, edns0, use-vc) and the search list (`net.resolv`): done, checked against glibc's getaddrinfo;
     - the resolver (`net.resolver`): done.
       - A and AAAA in parallel on separate connected UDP sockets, with random IDs; forged packets are ignored.
       - TCP after truncation; EDNS(0) and `use-vc` on request.
       - Failover on SERVFAIL/REFUSED/FORMERR/malformed answers/ICMP refusals at once, and on timeouts.
       - Tested against a scripted DNS server.
  3. **`connect_host(name, port, timeout)`** with Happy Eyeballs v2 (RFC 8305). Done (`net.dial`).
     - Connections start while DNS still runs; IPv4 waits at most 50 ms for a pending AAAA.
     - Families alternate, IPv6 first; a new attempt every 250 ms, or at once when one fails; the first to connect wins.
     - One deadline covers resolution and connecting.
  4. **Client presets for DB drivers.** Done.
     - `TcpStream.detect_dead_peers()`: keepalive (30 s idle, 10 s interval, 3 probes) and a `TCP_USER_TIMEOUT` of the same total, so a vanished peer fails the next I/O within about a minute.
     - `idle_state()`: EMPTY / DATA / CLOSED, without waiting or consuming, for pools checking a connection before reuse.
  5. **Nonblocking access for readiness loops.** Done.
     - `try_read`/`try_write` on both streams, `try_accept` on both listeners: `None` instead of waiting.
     - `TcpListener.bind_reuseport`, `linux.probe.raise_nofile_limit`, fd-table pre-growth.
     - `examples/net/epoll_echo.mojo` puts them together. Under load it ran 200 concurrent connections, 10k verified echoes in 0.21 s, and held a client that does not read to bounded memory.
  6. **v1 polish:**
     - **Done:**
       - the client guide and the v1 client API above;
       - an independent review of the client code, with all findings fixed under regression tests;
       - fault-seam and descriptor-leak tests;
       - every test and example cross-compiles for aarch64 (`pixi run aarch64-check`);
       - Mojo 1.2.0 GA.
     - **Left:**
       - a rattler-build recipe (modular-community);
       - running the suite on a real aarch64 host.
- **M3: UDP**, in two modes like TCP:
  - sync: blocking `send_to` / `recv_from` with deadlines;
  - async: nonblocking `try_*` calls for readiness loops (`linux.Epoll`), which a future runtime can build on.
  1. **`UdpSocket`.** Done.
     - Both modes; truncation is never silent (`Datagram.size`); empty datagrams; peeking a datagram's size.
     - Connected sockets filter senders and report ICMP refusals.
     - `bind_reuseport`, `from_socket`, `SO_BROADCAST`.
  2. Multicast (IPv4 and IPv6 groups, TTL/hops, loop, interface).
  3. Batched I/O (`sendmmsg` / `recvmmsg`) for throughput.
  4. Examples, docs, API review.
- **Later:** sendfile, vectored helpers, TLS integration points.
