# Design

`mojo_net` is a set of native Mojo networking libraries for Linux, kept in one repository. The roadmap is what lightbug gave up: 1. TCP, 2. an HTTP library, 3. an HTTP server. Database drivers build on the same layers. Requirements: correct socket semantics, reliability, speed.

## One repo, separate libraries
**Why one repo.** The packages share:
- one toolchain pin;
- one CI;
- the same low-level layers.

So a Mojo upgrade, or a change in a shared layer, lands in every package in one commit. There is no package manager to wire separate repos together yet, and precompiled Mojo packages only load on the compiler that built them, so everything builds from source together.

**What stays separate.** Sharing a repo does not merge scopes:
- Each library has its own document, scope, status and milestones (`docs/<pkg>.md`).
- Each depends only on the layers below it.
- One library's goals never gate another's. The TCP library is not blocked on runtime performance.
- The import rules below are checked in CI (`pixi run import-check`).

## Packages (dependencies point downward only)
| Package | Role | Status | May import |
|---|---|---|---|
| `linux` | raw syscalls, ABI mirrors, errno, `IoError`, fds, clock, poll/epoll/eventfd wrappers, probing (including fd-table pre-growth) | stable (M1) | `std` only |
| `bytes` | `ByteBuffer`, base64, and the sans-I/O `Codec` contract (contract 1) with the reference `LineCodec` | stable (M1) | `linux` |
| `crypto` | hashes and MACs for authentication protocols: SHA-256, MD5, HMAC-SHA-256, PBKDF2, constant-time comparison (no ciphers) | done for `pg` (P1) | `std` only |
| `net` | the TCP/UDP library (`docs/net.md`): addresses, socket options (L1), blocking TCP/Unix with deadlines and nonblocking `try_*` calls (L2), buffered frame reads (`BufReader`), DNS and connect-by-name (Happy Eyeballs), UDP | TCP client (M2) and UDP (M3) done; packaging left | `linux`, `bytes` |
| `http` | the HTTP/1.1 library (`docs/http.md`): message types, the header map, the sans-I/O head parser, body framing, server and client connection codecs, and a blocking client | H1–H6 done | `linux`, `bytes`; `net` only in `http.client` |
| `server` | the HTTP/1.1 server (`docs/server.md`): one epoll loop per process over `ServerConnection`s, a `Handler` trait, timeouts, backpressure, streaming; SO_REUSEPORT for multi-core | S1–S5 done | `linux`, `bytes`, `net`, `http` |
| `pg` | the PostgreSQL driver (`docs/pg.md`): a sans-I/O protocol 3.0 codec, authentication up to SCRAM-SHA-256, a blocking client | P1–P5 done (the codec, a blocking client, parameters, types and a statement cache); P6 next | `linux`, `bytes`, `crypto`; `net` only in `pg.client` |
| `rt` | experimental completion-based event loop (`docs/rt.md`): epoll and simulator backends, timers, slab, mailbox, `rt.evented` connections | **frozen** until Mojo's async/await stabilizes | `linux`, `bytes`, `net` |

- **Nothing outside `rt` imports `rt`.** `rt` builds on `net`, never the reverse.
- **The same rules cover all code.** They apply to `tests/<pkg>`, `examples/<pkg>` and `bench/<pkg>`. `spikes/` (M1 evidence) follows `net`'s rules.
- **Protocol libraries** (`http`, `pg`, and later database drivers) each get `src/<pkg>`, `tests/<pkg>`, `examples/<pkg>`, `docs/<pkg>.md`, and an entry in `ALLOWED` in `tools/check_imports.py`.
  - Their protocol logic is a sans-I/O codec built on `bytes` (contract 1).
  - Their transport uses `net`, from named modules only: `SANS_IO` in `tools/check_imports.py` lists the `src/<pkg>` modules that may import `net` (for `http`: `client.mojo`).

## Fixed decisions
- **Platform:** Linux only, x86_64 and aarch64.
- **Kernel:** 5.15 LTS or newer. epoll is the guaranteed readiness backend. io_uring (6.1-level features) is only a probed option (`linux.probe`), because Docker/containerd's default seccomp profile blocks it and RHEL disables it.
- **No libc on the I/O path:**
  - Every syscall is inline asm in `src/linux/syscall.mojo`.
  - Control-plane exceptions (for example `pthread_create`) need an explicit, documented decision.
  - `pixi run nolibc-check` enforces it.
- **Toolchain:**
  - Mojo is pinned exactly: `1.2.0`, from Modular's stable channel (`https://conda.modular.com/max`).
  - Packages ship as source, with the constraint `>=1.2,<1.3`.
  - No private or underscore stdlib APIs (the test-only `linux.fault` is the one exception), and no nightly-only spellings.
- **Signals are data, not handlers.** The library installs no signal handlers.
  - A program that wants a signal blocks it and reads it from a signalfd (`linux.signal`).
  - The block must hold in every thread, and the Mojo runtime starts its threads before `main` with the exec-time mask. So the library blocks the signal and executes the program again when some thread does not block it (`server.process`; measured in `docs/spikes.md`).
  - Child processes are clone3 + execve (`linux.process.spawn`), with only raw syscalls on memory prepared beforehand in between, since a forked copy of a threaded process must not allocate.
- **No async/await yet.** Mojo marks it unstable.
  - The libraries expose blocking APIs, plus nonblocking building blocks for callers that run their own readiness loop.
  - An async runtime waits for Mojo's async design ("the compiler generates coroutines, the library schedules them"), which will shape its API. That is why `rt` is frozen.

## Contracts
Code comments cite these by number, so keep the numbering stable. Contracts 2, 3 and 6 concern event loops (`rt`, or any loop built on `linux.Epoll`).

1. **Sans-I/O protocols.** Codecs (HTTP, Postgres, RESP, DNS, TLS) never call read or write, so the same codec runs over blocking streams, a readiness loop, the event loop or a future executor.
   - The interface is the `bytes.codec.Codec` trait (re-exported as `net.codec`); its docstring has the full rules:
     - `feed(bytes)`, at most `feed_capacity()` bytes per call (a larger receive is fed in pieces, draining in between);
     - `feed_eof()`;
     - `next_event()` until it returns None, which yields owned events;
     - `poll_transmit(out)`, which appends pending output to a `ByteBuffer` the driver owns;
     - `next_deadline()` and `handle_timeout(now)`.
   - `feed` copies what it keeps, because receive buffers are only lent (contract 4).
   - Events are invariant under any input split (rule 4), except that a byte stream (an HTTP body) may be delivered in different pieces as it arrives: only their concatenation is invariant.
2. **Completions.** Every `rt` backend honors these:
   - Every op completes exactly once; multishot completions carry `more`.
   - Cancel is two-phase: the target still completes, with its real result or `Canceled`.
   - Completions are FIFO per fd and per direction.
   - Results are `-errno` integers internally.
   - Completions are never re-entrant from submit.
3. **Op ids.**
   - **Layout.** 64 bits: a 32-bit slab index plus a 32-bit generation. They fit io_uring `user_data`, and stale ids are rejected.
   - **Targets.** Completion targets are `{thin fn, ctx}`.
   - **No raw pointers in kernel user data**, because Mojo moves values.
4. **Buffers.**
   - Blocking code may borrow `Span`s.
   - Evented code never borrows:
     - receive buffers are loop-owned and lent to the callback;
     - send buffers are moved in and returned at completion.
   - An evented driver moves a codec's filled `out` buffer into its send op, so no staging buffer is needed.
5. **fd lifetime.**
   - Every fd is created with CLOEXEC and owned by exactly one `OwnedFd`. Wrappers borrow the owner (`AsFd`) so it outlives the syscall (see `CLAUDE.md`).
   - A loop-registered fd is closed only after its ops complete.
   - Always `EPOLL_CTL_DEL` before close.
6. **Threading.**
   - A loop is confined to its thread.
   - No global mutable state in `linux`/`rt`, and no work stealing.
   - Cross-loop traffic goes only through a mailbox plus a waker.
7. **Determinism seams.** Clock, randomness, readiness order and syscall results are injectable, so failures replay.
   - **Syscall results** go through `linux.fault`:
     - compiled only with `-D MOJO_NET_FAULTS=1`, and zero-cost otherwise;
     - it holds process-global, test-only state, an explicit exception to contract 6.
   - **The clock seam** is `linux.time.Clock`. L2 blocking waits (ppoll) always use the real monotonic clock.
   - **The event loop's clock, randomness and readiness order** come from the simulator `rt.sim.SimDriver`:
     - virtual time, one seeded generator, shuffled readiness;
     - a run replays from `MOJO_NET_SIM_SEED`.
8. **Errors.**
   - One `IoError{kind, errno, op}` everywhere.
   - Public APIs `raise IoError`; internals pass `-errno`.
   - `InvalidData` means the peer broke the protocol; `InvalidInput` means the caller passed a bad argument.

## Documents
- `docs/net.md`: the TCP library. Covers its scope, the L2 blocking contract, the rules for readiness-loop servers, and milestones.
- `docs/http.md`: the HTTP/1.1 library. Covers its scope, the parser's strictness rules, and milestones.
- `docs/server.md`: the HTTP server. Covers its model (one loop per process), behaviour and milestones.
- `docs/pg.md`: the PostgreSQL driver. Covers its scope, decisions (authentication, no TLS yet, errors) and milestones.
- `docs/rt.md`: the frozen runtime. Covers how contracts 2–7 are realised, the simulator, and the M2 gate.
- `docs/spikes.md`: measured facts. Covers threads, the Mojo runtime, callbacks, and the 10k-connection epoll spike.
