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

## Using UDP
```mojo
from linux.time import Deadline, Duration
from net import UdpSocket

# A client: connected, so only the server's replies arrive and ICMP errors
# surface (ConnectionRefused).
var sock = UdpSocket.connect_host("ntp.internal", 123, Duration.from_secs(2))
sock.set_read_deadline(Deadline.after(Duration.from_secs(1)))
_ = sock.send(request)
var buf = List[UInt8](length=1500, fill=0)
var d = sock.recv(Span(buf))        # d.len bytes in buf; d.truncated()?
```
- **Two modes, as for TCP.**
  - Blocking: `send_to` / `recv_from` (`send` / `recv` once connected) wait up to the per-direction deadlines.
  - Nonblocking: `try_*` returns None instead of waiting, for readiness loops.
  - Batched: `DatagramBatch` with `recv_batch` / `send_batch` moves up to 1024 datagrams per syscall, in both modes.
- **Datagrams are whole.** A receive returns one datagram. One longer than the buffer is cut, and `Datagram.size > len` says so, so it is never silent. Empty datagrams are valid; there is no EOF. A peek into an empty buffer tells the next datagram's size.
- **Servers.**
  - `UdpSocket.bind(addr)`, plus `bind_reuseport` for one socket per core.
  - Reply with `send_to(payload, d.sender)`. Bound to a wildcard address on a host with several addresses, turn on `receive_destination()` and reply with `send_from(payload, a.datagram.sender, a.local.value())` from `recv_from_to`'s `Arrival`: otherwise the reply leaves from whichever address the route back picks, and a connected client drops it.
  - A reply can fail for reasons the sender controls (port 0, a broadcast source, a forged one): drop that datagram and go on, never stop.
  - `connect` discards what was queued before it; after it, every datagram claims to be from the peer.
  - `examples/net/udp_echo.mojo` shows a blocking loop and an edge-triggered batched loop.
- **Multicast:** `join_multicast_v4` / `v6` on a socket bound to the group's port. Mind `IP_MULTICAST_ALL`.
- **Names:** `UdpSocket.connect_host` resolves without libc and uses the first address in RFC 6724 order. There is no Happy Eyeballs for UDP: try the next `Resolver.lookup_ip` address to fail over.
- **Errors:**
  - `TimedOut` (`is_deadline()`);
  - `ConnectionRefused` on a connected socket after ICMP "port unreachable";
  - EMSGSIZE for a datagram too large to send;
  - `PermissionDenied` for a broadcast without `set_broadcast(True)`.

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
| UDP (M3, stable with this release) | `UdpSocket`: `bind`, `bind_reuseport`, `connect_host` / `connect_host_deadline`, `connect`, `from_socket`, `into_socket`, `try_clone`, `shutdown_read`, `close`; `send_to`, `send`, `recv_from`, `recv`, `peek_from` and their `try_*` forms; `recv_batch` / `try_recv_batch` / `send_batch` / `try_send_batch`; deadlines; `set_broadcast`; multicast `join_*` / `leave_*` / `set_multicast_*`; `Datagram`, `DatagramBatch` |

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
       - Mojo 1.2.0 GA;
       - the conda package (`pixi run package`, a rattler-build recipe), and the API frozen under `pixi run api-check` (docs/design.md, "Packaging" and "Stability");
       - the suite on a real aarch64 host: GitHub CI runs `ci` and `package` on `ubuntu-24.04-arm` as well as on x86_64.
     - **Not planned:** publishing the package (modular-community or elsewhere). The code carries no quality guarantee and is not meant for production (docs/design.md).
- **M3: UDP**, in two modes like TCP:
  - sync: blocking `send_to` / `recv_from` with deadlines;
  - async: nonblocking `try_*` calls for readiness loops (`linux.Epoll`), which a future runtime can build on.
  1. **`UdpSocket`.** Done.
     - Both modes; truncation is never silent (`Datagram.size`); empty datagrams; peeking a datagram's size.
     - Connected sockets filter senders and report ICMP refusals.
     - `bind_reuseport`, `from_socket`, `SO_BROADCAST`.
  2. **Multicast.** Done.
     - `join_multicast_v4` / `v6` and `leave_*`; TTL / hops, loop and interface on the sender.
     - Linux's `IP_MULTICAST_ALL` default (a wildcard-bound socket hears every group joined on its port) is documented and can be switched off.
     - L1 has every option, including IPv6 unicast hops.
     - IPv4 delivery is tested over loopback. IPv6 is tested for membership and options, and for delivery where the host routes IPv6 multicast.
  3. **Batched I/O.** Done.
     - `DatagramBatch` with `recv_batch` / `send_batch` and their `try_*` forms: one `recvmmsg` / `sendmmsg` for up to 1024 datagrams.
     - The batch owns every buffer and header, so a call allocates nothing.
     - Truncation is reported per datagram; `sent()` tracks progress, also after an error, and `skip()` moves past a datagram that keeps failing.
     - On a connected socket, `sendmmsg` absorbs ICMP refusals that arrive during a batch; they surface on the next receive.
     - Measured on loopback (a loaded 4-core host, 64-byte datagrams, batches of 64): 13–20% faster end to end. On loopback the kernel's per-datagram work dominates (~2 µs: the send also runs the receive path). Batching saves only the syscall overhead (~120–250 ns per datagram), and its gain is larger on real NICs.
     - **Later:** UDP GSO/GRO (`UDP_SEGMENT`, `UDP_GRO`, one route lookup for many segments) is the next throughput lever.
  4. **Examples, docs, API.** Done.
     - An independent review found 5 issues, all fixed with regression tests (`tests/net/test_net_udp_regressions.mojo`):
       - a spin in blocking receives after `shutdown(READ)`, which now raise `NotConnected`; `shutdown_read()` wakes blocked receivers;
       - `skip()` for a stuck batch;
       - the batch-refusal docs;
       - `from_socket` accepting non-UDP datagram sockets;
       - the ping example's address fail-over.
     - `examples/net/udp_echo.mojo`: blocking, or an epoll loop with batches.
     - `examples/net/udp_ping.mojo`: by name, RTT and loss.
     - `UdpSocket.connect_host`, the guide above, and the UDP rows of the API table.
- **Second review (2026-10-25)** of `linux`, `bytes` and `net`, by four independent reviewers (the syscall layer; buffers, addresses, socket options and buffered reads; the streams and dialing; DNS). Nothing critical or high; every finding was reproduced, then fixed under a regression test that fails on the old code, or documented:
  - **`linux`** (`tests/linux/test_linux_fs_signal_process_regressions*.mojo`):
    - `open_beneath` retries EAGAIN, which openat2 answers with RESOLVE_BENEATH whenever a ".." lookup races a rename anywhere on the host (static files failed at random with a 500); bounded, since a write lease's EAGAIN lasts.
    - `block`, `set_mask`, `SignalFd.new` and `spawn`'s child mask leave glibc's signals 32 and 33 out, as glibc's sigprocmask does: blocking "every signal" hung a `setuid` in another thread.
    - `all_threads_block` skips a thread that ended mid-read (ESRCH) and reads `SigBlk:` only at a line start (a thread named `SigBlk:ffffffff` passed for one that blocks everything).
    - `stat_fd` retries EINTR; the affinity calls handle more than 1024 CPUs; a test checks that every `pkg.module.name` a docstring cites exists.
  - **`bytes`** (`tests/bytes/test_bytes_buffer_regressions.mojo`): a `ByteBuffer` kept full at its cap and drained in small pieces memmoved nearly all of it per refill (288 µs a byte at 4 MiB). It now grows once to twice the cap there, so compaction always reclaims more than it moves; the readable bytes still never pass the cap. The codec contract's rules 6, 7 and 10 now say what every codec does.
  - **`net` addresses and options** (`tests/net/test_net_socket_unixaddr_regressions.mojo`, `test_net_addr_regressions.mojo`): `set_tos` refuses values the kernel would truncate; a pathname starting with `@` or `(` no longer prints like an abstract name or `(unnamed)`; `Ipv6Addr.segment` aborts on an index outside 0..7 in every build.
  - **Streams** (`tests/net/test_net_streams_regressions.mojo`):
    - A wait that reports readiness while the syscall cannot progress goes edge-triggered after the first such wakeup: an AF_UNIX peek behind out-of-band data spun at full CPU until the deadline, or forever.
    - A `UnixListener` shut down with SHUT_RD ends `accept` with EINVAL instead of spinning (the F01 fix covered SHUT_RDWR).
    - An AF_UNIX writer waiting for room retries every 250 ms, so a shutdown of its send side raises `BrokenPipe`, as for TCP, where it used to wait until its deadline.
    - Documented: the dead-peer user timeout also aborts a live peer that stops reading for a minute with data queued (pg and redis enable it by default), and a `try_*` None alongside EPOLLHUP/EPOLLRDHUP means the endpoint is finished.
  - **DNS** (`tests/net/test_net_dns_regressions*.mojo`):
    - A hosts file over 16 MiB was read as empty; it is now read whole.
    - One `advance` reads at most 64 datagrams a query, so a stream of strays cannot keep a lookup past its deadline; no retry (without EDNS, or over TCP) starts after the deadline.
    - A name ending in two dots is refused (`localhost..` went to DNS).
    - Closer to glibc: nameserver lines take inet_aton's forms (checked against glibc's inet_aton through Python), option values are clamped atoi-style, `no-tld-query` and `no-aaaa` work, and a name the hosts file lists only in the other family is looked up in DNS.
    - RFC fixes: IPv4-mapped addresses have precedence 35; a TTL with its top bit set is 0; an extended RCODE (BADVERS) is a failure.
    - Documented: `Resolver.system()` reads the configuration once.
- **Third review (2026-10-27)** of `net` and the syscall layer under it, by four independent reviewers (DNS and dialing as an attacker sees them; TCP and Unix streams, sockets, addresses and the buffered reader; UDP; the syscall layer). Nothing critical or high. Every finding was reproduced by a regression test that fails on the old code (`tests/net/test_net_review3_regressions.mojo`, `tests/linux/test_linux_review3_regressions*.mojo`), and each test was checked against a planted copy of the bug:
  - **A TCP connect could connect to itself** (two reviewers found it). A connect to a local port nothing listens on, in the ephemeral range, can pick that very port as its source; the SYN answers itself, and the stream reads back its own writes. Both connect paths now refuse it as `ConnectionRefused` (local address equal to peer address, as Go checks). The test pins the source port with `IP_LOCAL_PORT_RANGE`.
  - **Deadlines rested on O_NONBLOCK**, a flag every duplicate of the descriptor shares: a clone set blocking made deadline-bounded reads wait in the kernel, and `try_recv_batch` wait for a full batch. Every L2 send and receive now passes MSG_DONTWAIT.
  - **Dialing**:
    - A hostile zone could answer with thousands of addresses, and a dial kept every attempt open (a socket per 250 ms until its deadline, enough to exhaust the process's descriptors). Now at most 32 addresses per family are tried, repeats once, and at most 8 attempts stay open (the oldest is abandoned when the next is due).
    - Answers of 0.0.0.0 or :: (hosts files use 0.0.0.0 to block a name) connected to this host; they are skipped. `::` had RFC 6724 precedence 40, above IPv4; it is 1.
  - **DNS**: a truncated answer and the EDNS fallback each restarted a try's timer, so a server answering every leg late chained one try to four timeouts; a try now lasts at most two (UDP, then one TCP leg, Go's rule). resolv.conf lines are taken as glibc takes them: a keyword at the start of the line followed by a space or tab, and a nameserver value with a trailing CR (a CRLF file) rejected.
  - **Adoption**: `TcpListener.from_socket` and `TcpStream.from_socket` took SCTP stream sockets (every accept then dropped its connection); they require TCP or MPTCP. `UdpSocket.from_socket` took a socket with UDP_GRO on, whose receives merge datagrams silently.
  - **`idle_state()`** said EMPTY with out-of-band input pending (an AF_UNIX MSG_OOB byte, TCP urgent data), which a peek skips; a zero-timeout poll now finds it.
  - **UDP**:
    - A server bound to a wildcard address could not reply from the address a datagram came to, so on a host with several addresses a connected client dropped its replies. `receive_destination`, `recv_from_to` (an `Arrival`: the datagram, its destination address and interface) and `send_from` do it with IP_PKTINFO / IPV6_PKTINFO.
    - `connect` kept datagrams queued before it, which then came out of `recv` as if from the peer; it now discards them.
    - `examples/net/udp_echo.mojo` stopped on one crafted datagram (a reply to port 0 is EINVAL); it drops what it cannot answer.
    - A batch receive rewrote every header (up to 1024) each call; it now rewrites those the last call changed.
  - **The syscall layer**:
    - `open_beneath` and `read_file` open with O_NOCTTY: a session leader without a terminal (a container's PID 1) that opened a terminal device took it as its controlling terminal (a hangup then sends SIGHUP).
    - The clone child issues raw syscalls even in fault-seam builds, where `syscallN` went through the Mojo runtime's global lookup.
    - The aarch64 `svc` clobbers include the SVE predicates and FFR, which the kernel zeroes (hardening; no current code keeps a value there).
  - **Documented**:
    - an AF_UNIX writer in a readiness loop gets no event after its peer's shutdown(SHUT_RD);
    - L1 `recv_from` cuts long datagrams silently;
    - an unconnected UDP socket sees ICMP errors once IP_RECVERR is on;
    - DNS compression chains end by the pointer and length caps, not by pointing backward.
- **Later:** sendfile, vectored helpers, TLS integration points.
