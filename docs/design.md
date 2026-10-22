# Design

A native Mojo TCP/socket library for Linux. It is the foundation for an HTTP library, an HTTP server and database drivers. Requirements: correct socket semantics, reliability, speed.

## Scope
**In scope:**
- raw syscalls;
- addresses;
- every socket option;
- blocking TCP/Unix streams with deadlines;
- nonblocking access for callers that run their own readiness loop (`linux.Epoll`);
- buffered reading;
- DNS resolution and connect-by-name;
- the sans-I/O codec contract that protocol libraries build on.

**Out of scope: an async runtime** (event loop, executor, timers, scheduling, io_uring proactor, simulation). That is a separate, heavy project. An experimental one grew here during M2 and was moved to its own repository, `mojo_rt` (git tag `runtime-snapshot` marks the last commit that contained it). It is frozen until Mojo's async/await stabilizes, because Mojo's async design ("the compiler generates coroutines, the library schedules them") will shape any runtime API. Sockets and syscalls don't depend on it.

**How a concurrent server uses this library without a runtime:**
- Make sockets nonblocking and drive them from a readiness loop (epoll, edge-triggered).
- For multi-core, run N processes on one port with `SO_REUSEPORT`, as nginx does.

The M1 spike's raw-epoll server shows this is enough. It held 11k connections at C/tokio throughput, using 123–159 B of user memory per connection. The rules it found are listed below.

## Fixed decisions
- **Platform:** Linux only, x86_64 and aarch64; kernel 5.15 LTS or newer.
- **No libc on the I/O path:** every syscall is inline asm in `src/linux/syscall.mojo`. Any control-plane exception needs an explicit, documented decision.
- **Toolchain:**
  - Mojo is pinned exactly (currently `1.2.0rc2`, moving to `1.2.0` GA).
  - The library ships as source, with the constraint `>=1.2,<1.3`.
  - No private or underscore stdlib APIs, and no nightly-only spellings.

## Packages (dependencies point downward only)
| Package | Role | May import |
|---|---|---|
| `linux` | raw syscalls, ABI mirrors, errno, `IoError`, fds, clock, poll/epoll/eventfd wrappers, probing | std only |
| `bytes` | `ByteBuffer`: owned buffers that codecs read from and append to | `linux` |
| `net` | addresses, socket options (L1), blocking TCP/Unix (L2), codec contract; next: buffered reader, DNS, connect-by-name | `linux`, `bytes` |

## Contracts
1. **Sans-I/O protocols.** Codecs (HTTP, Postgres, RESP, DNS, TLS) never call read or write, so the same codec runs over blocking streams or any event loop.
   - The interface is the `net.codec.Codec` trait; its docstring has the full rules:
     - `feed(bytes)`, at most `feed_capacity()` bytes per call;
     - `feed_eof()`;
     - `next_event()` until it returns None;
     - `poll_transmit(out)`, which appends to a `ByteBuffer` the driver owns;
     - `next_deadline()` and `handle_timeout(now)`.
   - `feed` copies what it keeps.
2. **Errors.** One `IoError{kind, errno, op}` everywhere. Public APIs `raise IoError`; internals pass `-errno`.
3. **Determinism seam.** Syscall results can be injected through `linux.fault`. It is compiled only with `-D MOJO_TCP_FAULTS=1` and costs nothing otherwise. The clock seam is `linux.time.Clock`.
4. **Fds.** Every fd is created with CLOEXEC, and owned by exactly one `OwnedFd`. Wrappers borrow the owner (`AsFd`) so it outlives the syscall (see `CLAUDE.md`).

## L2 blocking contract (as built in M1)
- **Nonblocking internally.** Every op is: try once → on EAGAIN `wait_ready` (ppoll) → retry. EINTR retries.
- **Deadlines.** They are absolute and per direction (`set_read_deadline` / `set_write_deadline` / `set_deadline`), and apply to every later op. Expiry raises `TimedOut` and leaves the stream usable.
  - A deadline limits *waiting*, not work.
- **POLLERR.** POLLERR caused only by the error queue is not progress; review finding F01 was a busy-spin from exactly that.
- **Connect.** TCP connect is never re-issued after EINTR. AF_UNIX connect timeouts use `SO_SNDTIMEO`.
- **Return types.** `accept` returns a struct (`TcpAccepted`), not a tuple.

## Rules for readiness-loop servers (from the 10k spike, `docs/spikes.md`)
- **Syscall budget.** Register once, edge-triggered; read and write to EAGAIN; drain accept until EAGAIN; batch ~1024 events per wait. That is 2 syscalls per message, with no `EPOLL_CTL_MOD` per operation.
- **Sticky read-closed.** Once RDHUP/HUP/ERR has been seen, read to EOF or EAGAIN. Otherwise a FIN that arrives with data is lost.
- **Pre-grow the fd table at startup** with `linux.probe.pregrow_fd_table(listener)`. Every Mojo process is multi-threaded, so each fd-table doubling otherwise stalls 20–40 ms under load.
- **EMFILE.** Pause accepting rather than spin on a readable listener. Log with raw `write(2)`.

## Milestones
- **M1: foundation and blocking transport. Done.**
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
  1. **Buffered reader** over blocking streams: `read_until(delim, max)`, `read_exact`, `peek`, keeping pipelined leftovers.
  2. **DNS stub resolver**, blocking and pure Mojo:
     - reads `/etc/hosts` and `resolv.conf` (search, ndots, timeout, attempts);
     - UDP A/AAAA queries with random ids, TCP fallback on truncation;
     - response validation, and a fuzzed parser.
  3. **`connect_host(name, port, timeout)`** with Happy Eyeballs v2 (RFC 8305).
  4. **Client presets for DB drivers:** keepalive + `TCP_USER_TIMEOUT`, and a stale-connection check.
  5. **Nonblocking stream access** (`try_read`/`try_write`) for external readiness loops, plus server helpers (`SO_REUSEPORT` listeners, fd-table pre-growth, `RLIMIT_NOFILE`).
  6. **v1 polish:**
     - a README with examples;
     - a rattler-build recipe (modular-community);
     - CI on real aarch64;
     - an API review and freeze.
- **Later:** UDP API, sendfile, vectored helpers, TLS integration points.
