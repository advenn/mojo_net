# rt: the event-loop runtime (M2)

`rt` is the runtime half of a Rust-style async stack: reactor, timers, completions and executor hooks. It knows nothing about protocols; `net.evented` builds connections on it. The completion contracts 2–7 in `docs/design.md` are normative. This file describes how they are realised.

## Shape
```
EventLoop                      one per thread; never shared
 ├─ loop: Loop  (rt.core)      backend-independent: ops, fds, queues, timers, pool,
 │    │                        and the readiness proactor itself
 │    ├─ ops: Slab[Op]         OpId = gen:32 | slot:32; fixed-size chunks, stable addresses
 │    ├─ fds: Slab[FdEntry]    FdId likewise; the loop OWNS every fd it registered
 │    ├─ submitted / ready     FIFO queues (io_uring-style SQ / CQ)
 │    ├─ timers: TimerHeap     (deadline, seq, op), lazy deletion + compaction
 │    ├─ pool                  recycled RECV_CHUNK receive buffers
 │    └─ now                   read once per iteration
 └─ driver: Backend            comptime-selected `Driver` (rt.driver)
      EpollDriver   kernel: edge-triggered epoll + raw syscalls   (default)
      SimDriver     in-memory TCP + virtual clock                 (-D MOJO_TCP_SIM=1)
```

**Split.**
- **`Loop`** holds the proactor logic: readiness flags, optimistic I/O, sticky `read_closed`, send queues, accept batching, two-phase cancel.
- **A `Driver`** supplies only syscalls, a readiness source and a clock.

So the simulator tests the *same* proactor code that runs in production. Callbacks receive `mut Loop` and submit into it. `EventLoop` flushes submissions to the driver after each dispatch batch, so a callback never runs inside a submit. io_uring (M3) will be a backend that bypasses the readiness proactor.

**Selection.**
- **Mechanism.** `comptime Backend: Driver = SimDriver if is_defined["MOJO_TCP_SIM"]() else EpollDriver` is static dispatch with no runtime cost.
- **Test access.** The alias has the *trait* type, so a test reaches simulator-only members with `rebind[SimDriver](ev.driver)`. That compiles only in sim builds.

## Completions
```mojo
comptime CompleteFn = def(Int, mut Loop, var Completion) thin -> None
struct Target(TrivialRegisterPassable): call: CompleteFn, ctx: Int   # 16 bytes
struct Completion(Movable):
    op: OpId; kind: OpKind; tag: UInt64     # tag: caller-chosen routing word
    res: Int                                # >= 0 result, < 0 is -errno (-ECANCELED if canceled)
    more: Bool                              # multishot: another completion will follow
    fd: FdId                                # the fd the op ran on, or what accept/listen/connect produced
    buf: Optional[ByteBuffer]               # recv: the data; send: the buffer handed back
```
- **Exactly once.** Every op completes exactly once (a multishot op: any number of `more=True`, then one final completion). `tests/rt/test_loop_harness.mojo` checks this and the other invariants on every op in the contract suite.
- **Never inside submit.** An optimistic completion is queued and dispatched later.
- **`ctx`** is a word the submitter owns, typically the address of a heap handler.
- **Targets are data.** Mojo cannot use a function as a value from inside itself, or from any function in a reference cycle with it. Build Targets once at setup and store them; `net.evented` keeps one `Target(_dispatch[H], ctx)` per connection and routes on `c.kind`.
- **State behind `ctx` must not also be a `mut` argument of the frame that runs the loop.** The compiler treats `mut` as exclusive and may cache its fields across `run_once`, so it misses what callbacks wrote through `ctx`. Keep handler state on the heap, or take its address in the function that runs the loop.
- **Receive buffers.** A recv moves a pooled buffer (at most `RECV_CHUNK` bytes) to the handler, which returns it with `loop.recycle(buf^)`. Only buffers of exactly `RECV_CHUNK` capacity are pooled; others are freed.
- **Send buffers.** `send` writes *all* readable bytes, finishing partial writes itself, and hands the buffer back in the completion. A failed or canceled send hands back the bytes it did not send.

## Ops
| op | completes when | res |
|---|---|---|
| `listen(addr)` | socket bound and listening (`c.fd`; `local_addr(fd)` has the real port) | 0 / -errno |
| `connect(addr)` | handshake done (`c.fd`) or failed (socket already closed) | 0 / -errno |
| `accept(listener)` multishot | each connection, registered, TCP_NODELAY on (`c.fd`) | 0, or a fatal -errno |
| `recv(fd)` single-shot | data (`c.buf`), EOF (res 0) or error | bytes / 0 / -errno |
| `send(fd, buf)` | all bytes written, or error | bytes / -errno |
| `shutdown(fd, how)` | SHUT_WR / SHUT_RDWR: after the earlier sends have gone out | 0 / -errno |
| `close(fd)` | every pending op on fd has completed (ECANCELED); deregistered and closed | 0 / -errno |
| `timeout_at` / `timeout_ns` | deadline reached (saturates, never overflows) | 0 |
| `cancel(op)` | after the target completes (two-phase) | 0, or -ENOENT if already done |
| `post(target)` | next dispatch | 0 |

**Run loop.**
- `run()` returns when `stop()` is called or no op is pending, and it clears the stop request.
- `run_once` never blocks when completions or submissions are queued, a stop was requested, or nothing is pending.

## Epoll rules (from the 10k spike, `docs/spikes.md`)
- **Registration.** Register once with `EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLET`. The `readable`/`writable` flags are set by edges and cleared by EAGAIN or a short transfer.
- **Sticky `read_closed`.** It is set by RDHUP, HUP, ERR or EOF; once set, reads run to EOF or EAGAIN.
- **Syscall budget.** 2 syscalls per message: recv + send, with zero `epoll_ctl`. This is verified by `tests/rt/test_loop_faults.mojo`, which counts syscalls through the fault seam.
- **Accept.** Batches of `ACCEPT_BATCH`, then the fd is rescanned on the next turn. On EMFILE/ENFILE/ENOBUFS/ENOMEM the listener pauses until any close or a 100 ms timer fires; it never spins.
- **Fd table.** It is pre-grown at startup with `fcntl(F_DUPFD_CLOEXEC, limit-1)`, then that fd is closed. This never clobbers an open fd, unlike `dup3`.
- **Clock.** Read once per iteration; a second read happens only when a timer is due within 10 ms.

## Simulator (`rt.sim.SimDriver`)
- **What it models.** Linux nonblocking TCP plus edge-triggered epoll semantics, entirely in memory:
  - segments delivered after latency plus seeded jitter, so a stream is never reordered;
  - flow control with partial writes;
  - FIN, RST and ECONNRESET-then-EPIPE;
  - a backlog-full listener that refuses or drops SYNs;
  - fds that are never reused.
- **Virtual time.** It only moves inside `wait`, which never sleeps. Waiting forever with nothing scheduled raises `SimDriver.wait: deadlock` instead of hanging.
- **Determinism.** One seeded generator drives everything. Replay a run with `MOJO_TCP_SIM_SEED=<n>`, and use `trace_hash()` to assert that a replay matches.
- **Faults** (`SimDriver.faults`, probabilities): short read/write, spurious EAGAIN, spurious edges, shuffled readiness order, accept EMFILE bursts, accept abort, random reset, dropped SYN.
  - Every fault stays within the kernel contract an edge-triggered proactor relies on. If a call reports less than is available, the fd goes back on the ready list.
  - `SimFaults.benign(p)` enables the six faults that never fail a connection; `SimFaults.all(p, fatal)` enables the rest too.
- **More detail:** see the module docstring of `src/rt/sim.mojo`.

## Test files
| file | what it runs on |
|---|---|
| `test_*_contract.mojo` | both backends (the runner builds the file twice) |
| `test_*_sim.mojo` | the simulator only |
| `test_*_faults.mojo` | epoll with the syscall fault seam |
| other `tests/rt/test_*.mojo` | epoll |

## Cross-thread mailbox (`rt.mailbox`)
A bounded lock-free MPSC queue with an eventfd wakeup that is coalesced through an atomic pending flag. Producers hold trivially copyable `Sender`s. Shared state lives in raw memory, which matters because of the cross-thread `mut self` pitfall in `CLAUDE.md`. It is tested with 4 pthread producers × 50k messages, checking FIFO per producer. Wiring it into `EventLoop` waits for the threads-vs-processes decision.

## Not yet
- io_uring (M3).
- multishot recv, vectored send, sendfile.
- A "readable(fd)" op for foreign fds (eventfd, signalfd), needed to wire the mailbox into the loop.
