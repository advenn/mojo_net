# Design

Native Mojo networking for Linux: the foundation for an HTTP library, an HTTP
server and database drivers. Requirements: many concurrent connections,
reliability, speed.

## Fixed decisions
- **Platform:** Linux only, x86_64 and aarch64.
- **Kernel:** at least 5.15 LTS. epoll is the guaranteed backend. io_uring is a probed fast path at 6.1-level features, because it is blocked by default in Docker/containerd seccomp and disabled on RHEL.
- **No libc on the I/O path.** Every syscall is inline asm in `src/linux/syscall.mojo`. Control-plane exceptions (for example `pthread_create`) need an explicit, documented decision.
- **Toolchain:** Mojo pinned exactly (currently `1.2.0rc2`, moving to `1.2.0` GA). Ship as source with the constraint `>=1.2,<1.3`. Use no private or underscore stdlib APIs, and no nightly-only spellings.
- **No async/await syntax yet.** Mojo marks it unstable. The runtime (event loop, timers, wakers, executor hooks) is built now so an `__async` executor can plug in later.

## Packages (one repo; dependencies point downward only)
| Package | Role | May import |
|---|---|---|
| `linux` | raw syscalls, ABI mirrors, errno, `IoError`, fds, clock, poll/epoll wrappers | std only |
| `bytes` | `ByteBuffer` (owned buffers moved through `rt` ops and filled by codecs) | `linux` |
| `rt` | event loop (epoll, io_uring and Sim backends), timers, buffer pools, wakers, mailbox | `linux`, `bytes` |
| `net` | addresses, socket options, blocking TCP/Unix, evented `TcpConn`/`Listener`/`Dialer`, DNS | `linux`, `bytes`, `rt` |

The blocking parts of `net` must not import `rt`.

## Contracts (fixed before the code that needs them)
1. **Sans-I/O protocols.** Codecs (HTTP, Postgres, RESP, DNS, TLS) never call read or write, so the same codec runs over blocking streams, the event loop, or a future executor. The interface is the `net.codec.Codec` trait (its docstring has the full rules): `feed(bytes)` with at most `feed_capacity()` bytes per call (a larger receive is fed in pieces, draining in between), `feed_eof()`, then `next_event()` until None, which yields owned events; `poll_transmit(out)`, which appends pending output to a `ByteBuffer` the driver owns; `next_deadline()` and `handle_timeout(now)`. `feed` copies what it keeps, because receive buffers are only lent (contract 4). An evented driver moves the filled `out` buffer into its send op and gets it back at completion, so no staging buffer is needed.
2. **Completion contract**, which every `rt` backend honors:
   - Every op completes exactly once; multishot completions carry `more`.
   - Cancel is two-phase: the target still completes, with its real result or `Canceled`.
   - Completions are FIFO per fd and per direction.
   - Results are `-errno` integers internally.
   - Completions are never re-entrant from submit.
3. **Op ids** are 64 bits: 32-bit slab index plus 32-bit generation. They fit io_uring `user_data`. Stale ids are rejected. Completion targets are `{thin fn, ctx}`; raw pointers never go into kernel user data, because Mojo moves values.
4. **Buffers.** Blocking code may borrow `Span`s. Evented code never borrows: receive buffers are loop-owned and lent to the callback, and send buffers are moved in and returned at completion.
5. **fd lifetime.** A loop-registered fd is closed only after its ops complete. Always `EPOLL_CTL_DEL` before close.
6. **Threading.** A loop is confined to its thread. No global mutable state in `linux`/`rt`, no work stealing. Cross-loop traffic goes only through a mailbox plus a waker.
7. **Determinism seams.** Clock, randomness, readiness order and syscall results are injectable, so a Sim backend can replay failures by seed.
   - Syscall results already are, through `linux.fault`: compiled only with `-D MOJO_TCP_FAULTS=1`, with zero cost otherwise. It holds process-global, test-only state, an explicit exception to contract 6.
   - The clock, randomness and readiness-order seams are implemented by the simulator `rt.sim.SimDriver` (virtual time, one seeded generator, shuffled readiness). It replays a run from `MOJO_TCP_SIM_SEED`, and `test_*_contract.mojo` files run on both backends.
   - The clock seam is `linux.time.Clock`.
   - L2 blocking waits (ppoll) always use the real monotonic clock.
8. **Errors.** One `IoError{kind, errno, op}` everywhere. Public APIs use `raises IoError`; internals pass `-errno`.

## L2 blocking contract (as built in M1)
- **Nonblocking internally.** Every op is: try once → on EAGAIN `wait_ready` (ppoll) → retry. EINTR retries.
- **Deadlines.** They are absolute, per direction (`set_read_deadline` / `set_write_deadline` / `set_deadline`), and apply to every later op. Expiry raises `TimedOut` and leaves the stream usable.
  - A deadline limits *waiting*, not work: data that is already available wins over an expired deadline.
- **POLLERR.** POLLERR caused only by the error queue is not treated as progress; review finding F01 was a busy-spin from exactly that.
- **Connect.** TCP connect is never re-issued after EINTR (wait for writable, then `SO_ERROR`). AF_UNIX connect timeouts use `SO_SNDTIMEO`.
- **Return types.** `accept` returns a struct (`TcpAccepted`), not a tuple (see the Mojo move rules in `CLAUDE.md`).

## Milestones
- **M1: foundation and blocking transport. Done.**
  - **Scope:**
    - syscalls, ABI, errors, fds;
    - addresses;
    - a socket2-style `Socket`;
    - L2 TCP/Unix with deadlines;
    - time, poll, probe, epoll, eventfd;
    - the fault seam;
    - the sans-I/O `Codec` + `ByteBuffer`;
    - examples.
  - **Verification:**
    - 32 test files plus the ABI check, stable over repeated runs;
    - the no-libc check passes;
    - every test file and example cross-compiles for aarch64.
  - **Review:** a 5-lens adversarial review found 62 issues, confirmed 49 (all fixed, with regression tests) and rejected 13.
  - **Spike** (`docs/spikes.md`): one Mojo thread on raw epoll held 11k connections at C/tokio throughput (~180k msgs/s on loopback, ≈5 µs server CPU per message, ~95% of it kernel), using 123–159 B per connection versus tokio's 4.9 KB.
- **M2: `rt` event loop on epoll** (gates all HTTP-server work).
  - Completion contract; Sim backend; one contract test suite run against both backends.
  - Timing wheel, buffer pool, mailbox; minimal evented TCP.
  - Gate: ≥80% of tokio `current_thread`. Measure it as **server CPU ns/msg at saturation** (3 client processes, ≥3 interleaved runs, sibling-CPU load recorded), not as single-client msgs/s. Also ≥10k connections.
  - **Rules from the spike** (each needs a test):
    - **Syscall budget.** Keep it at 2 syscalls per message: register once, edge-triggered; read and write to EAGAIN; drain accept until EAGAIN; batch ~1024 events per wait. No `EPOLL_CTL_MOD` per op, no EAGAIN probe read, no clock read per event.
    - **Sticky `read_closed`.** Once RDHUP/HUP/ERR has been seen (even while reading is paused), read to EOF or EAGAIN. Otherwise a FIN that arrives together with data is lost (tokio's READ_CLOSED rule).
    - **Pre-grow the fd table at loop start** (`dup3` to the expected max fd, then close). Otherwise fd-table doublings in this always multi-threaded process stall 20–40 ms under load and overflow the accept queue.
    - **Clock.** Read it once per loop iteration. A raw `clock_gettime` costs ~117 ns; the vDSO costs ~13 ns.
    - **Slab.** Grow it in fixed chunks (stable addresses); don't double one `List`. Receive buffers stay loop-owned.
    - **EMFILE.** Pause accepting and resume on close or on a tick; never spin on a readable listener. Log with raw `write(2)`.
  - **Ends with the threads-vs-processes decision.** Spike evidence:
    - `pthread_create` threads run Mojo code safely (allocation, raises, print, raw syscalls, atomics, ASan-clean).
    - The proposed exception covers only `pthread_create`, `pthread_join` and `pthread_attr_{init,setstacksize,destroy}`.
    - The runtime pool is 1 + |affinity mask| threads, fixed at exec, so process-per-core must set affinity before exec.
- **M3:** multi-core runtime, io_uring backend, DNS stub resolver, Happy Eyeballs, client features for DB drivers.
- **M4:** hardening (soak tests, fuzzing, sanitizers), docs, packaging.
