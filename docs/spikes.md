# Spikes: pthreads, runtime threads, `{thin fn, ctx}` callbacks

> **Note (after the refocus).** References below to `rt` and "M2/M3" mean the experimental event-loop runtime. It has since moved to the separate `mojo_rt` repo (git tag `runtime-snapshot`). The measurements stand. The epoll-spike rules (syscall budget, sticky read-closed, fd-table pre-growth, EMFILE handling) apply to any readiness-loop server built on this library; `docs/design.md` lists them.

These are time-boxed M1 spikes that feed the M2/M3 decisions in `design.md`: the threads-vs-processes choice, the `pthread_create` control-plane exception, and the completion-target layout. The code is in `spikes/`. Nothing in `src/` depends on it.

Reproduce everything with one command (it builds into `spikes/out/` and exits non-zero on any failure):

```bash
pixi run bash spikes/run_spikes.sh
```

**Environment of every number below:**
- Mojo `1.2.0rc2 (2016d0cd)` on Linux `6.12.111+deb13-amd64` x86_64 (Debian 13), glibc 2.41.
- CPU: Intel i5-1145G7, 4 cores / 8 threads, 8 CPUs online.
- aarch64 was **only compiled, not run**. All three spikes build with `mojo build --target-triple aarch64-unknown-linux-gnu --target-cpu generic --emit object` (an ELF aarch64 relocatable). This host has no qemu or aarch64 toolchain.

## Answers in one table

| Question | Answer |
|---|---|
| Can Mojo code run on `pthread_create` threads? | **Yes.** On a foreign thread these all work: List/String/Dict allocation, cross-thread free, typed and generic raise/catch, `print`, raw syscalls, `Atomic`, pinning with raw `sched_setaffinity`. There were no crashes, exit hangs or leaks in 20 runs of the full spike, 200 + 100 exit-with-live-thread runs, and an ASAN build. |
| C-callable fn pointer spelling | `def(OpaquePointer[MutAnyOrigin]) thin abi("C") -> OpaquePointer[MutAnyOrigin]` |
| Idle threads in a Mojo 1.2 process | **1 + (CPUs in the affinity mask at exec)**: 9 here. The workers already exist at main's first statement, are named `🔥 ThreadN`, and use 0 CPU when idle. No thread appeared lazily in any stage. |
| Can the pool be shrunk? | Yes, but only **before exec**: `taskset -c 0` gives 2 threads in total. `MODULAR_ENABLE_AFFINITY=1` gives 1 worker per physical core, each pinned to one CPU. |
| `{thin fn, ctx}` targets with mixed handler types | **Works.** `Target` is 16 bytes and `TrivialRegisterPassable`. `_on_event[H]` monomorphizes per handler type, and all instantiations share one fn type. |
| Indirect-call cost | About **0.6–0.9 ns** over a direct non-inlined call when the target is predictable, and about **+5 ns** when it is unpredictable (2 targets in random order). This is noise next to a syscall. |
| Surprise: signal handlers | Runtime startup installs handlers for signals 1–8, 10–12, 15, 24, 25 and 31. SIGUSR1 is effectively a no-op handler **without SA_RESTART**, so `tgkill(SIGUSR1)` gives deterministic EINTR in tests. |

---

## 1. pthreads (`spikes/pthread_spike.mojo`)

### What it does

`main` creates N=4 threads, each with a heap context (`OwnedPointer[ThreadCtx]`) whose address is the `void* arg`. Every result is checked in `main` after `pthread_join`:

**On each thread:**
- **Heap churn:** 200k `List[Int]` appends, 10k `String`s and a 1000-entry `Dict[String, Int]`. It also fills a 10k-element `List` that **main** frees after the join (a cross-thread free).
- **Errors:** `raise IoError.from_errno(..., EAGAIN)` is caught as a typed error. A generic `raise Error("generic error from thread ", i)` goes through a raising call chain and arrives with its message intact.
- **Output:** `print` from the thread.
- **Raw syscalls:** `gettid` differs from the main thread's, and `getpid` equals main's pid.
- **Pinning:** a raw `sched_setaffinity(0, ...)` to one CPU, read back with `sched_getaffinity`, and `getcpu()` equals the target immediately afterwards (migrating yourself is synchronous).
- **Bad mask:** a mask that contains only an absent CPU (1023) returns `EINVAL`.
- **Atomics:** 1M contended `Atomic[Int64].fetch_add` per thread. The total must be exactly 4,000,000, and it was.

**In `main` and the process as a whole:**
- **Thread attributes:** thread 0 uses a `pthread_attr_t` with a 256 KiB stack. `pthread_attr_setstacksize(1024)` returns `EINVAL` (22).
- **Task count:** `/proc/self/task` holds `base + 4` while the threads run and returns to `base` afterwards.
- **Leak check:** 200 rounds × 4 create/join. Each pair takes 12–19 µs, and VmRSS grows by 12–16 KB over 800 threads (allocator noise, not per-thread growth).
- **EINTR:** see "EINTR, by accident" below.
- **Exit with a live thread** (`SPIKE_EXIT=detached-sleep|detached-busy`): main returns while a thread is blocked in `clock_nanosleep`, or is busy allocating Strings. The process exits with status 0 in about 10 ms. Failures: **0/200 runs for each mode, plus 0/100 under `taskset -c 0`**.

**Run configurations:** a built binary, 20 consecutive runs, `taskset -c 0` (all 4 threads pinned to CPU 0), `taskset -c 2,5`, `mojo run` (JIT), and `mojo build --sanitize address`. All passed: `PTHREAD SPIKE: PASS`. ASAN reported no errors, though create+join slows to 95–736 µs and RSS grows by about 5 MB over 800 threads. That growth appears only under ASAN.

**Excerpt from the built binary:**
```text
main tid 1944249 tasks at start 9 allowed cpus 8
  ok   tasks while running = base + N (13)
  [thread 2 ] tid 1894068 pinned to cpu 2 -> running on 2 | list_sum 19999900000
  ok   atomic counter exact: 4000000
   800 create+join in 15531 us ( 19 us each); VmRSS 30316 kB -> 30332 kB
  ok   tasks back to base after rounds (9)
  blocking read(pipe): EINTR seen 2 after 2 SIGUSR1; final read = 1
  blocking ppoll: EINTR seen 2 after 2 SIGUSR1; final read = 1
PTHREAD SPIKE: PASS
```

### Spellings that work (copy these)

```mojo
from std.ffi import external_call

comptime ThreadEntry = def(OpaquePointer[MutAnyOrigin]) thin abi("C") -> OpaquePointer[MutAnyOrigin]

def thread_main(arg: OpaquePointer[MutAnyOrigin]) abi("C") -> OpaquePointer[MutAnyOrigin]:
    var ctx = arg.unsafe_bitcast[ThreadCtx]()   # ctx: Pointer[ThreadCtx, MutAnyOrigin]
    _body(ctx[])                                # ordinary non-raising Mojo code
    return arg

# Exactly ONE wrapper per C symbol; void* as Int so NULL is expressible.
def pthread_create(mut thread: UInt64, attr_addr: Int, entry: ThreadEntry,
                   ctx: OpaquePointer[MutAnyOrigin]) -> Int32:
    return external_call["pthread_create", Int32](Int(Pointer(to=thread)), attr_addr, entry, ctx)

def pthread_join(thread: UInt64, retval_addr: Int) -> Int32:
    return external_call["pthread_join", Int32](thread, retval_addr)

# Context word from a heap owner, which must outlive pthread_join:
var ctx = OwnedPointer(ThreadCtx(...))
var arg = OpaquePointer[MutAnyOrigin](unsafe_from_address=Int(ctx.ptr()))
```

**Other details that were verified:**
- **Typed nullable pointer:** `Optional[OpaquePointer[MutAnyOrigin]]` is 8 bytes with `None` as NULL, and it works as a nullable `void*` argument to `external_call`. `Pointer(to=tid)` can be passed directly as `pthread_t*`.
- **`Int` instead of a pointer:** `def entry(arg: Int) abi("C") -> Int` also works as the entry, because `void*` and `long` use the same registers on both LP64 ABIs. `OpaquePointer` is clearer.
- **Pointers stored in structs** need `MutUntrackedOrigin`, for example `Pointer[Shared, MutUntrackedOrigin]`.
- **Atomics:** `Atomic[Int64](0)`, `.fetch_add(1)`, `.load()`, `.store(1)` (from `std.atomic`).
- **pthread return codes:** the functions return 0 or a **positive** errno. They do not use -1/errno, so `check()` does not apply directly.
- **Raw `sched_getaffinity`** returns the number of bytes written; glibc's wrapper returns 0.

### What failed, with exact compiler text

Every row is a file in `spikes/expected_failures/`. `bash spikes/check_expected_failures.sh` asserts each one still fails with this exact text.

| Attempt | Error |
|---|---|
| Two `external_call["pthread_join", Int32]` sites with `(UInt64, Int)` and `(Int32, Int)` arguments | `error: existing function with conflicting signature`, then `failed to legalize operation 'pop.external_call'`. It fails at LLVM lowering, not at parse time, and the source location points into `std/ffi`. `UInt64` and `Int` for the same parameter did **not** conflict. Fix: one wrapper per symbol. |
| `def entry(arg: Int) abi("C") raises -> Int` | `'abi("C")' function may not be marked 'raises'; remove 'raises' or use 'abi("Mojo")'`. The C entry must catch everything. |
| `var f: def(Int) thin abi("C") -> Int = plain_mojo_def` | `cannot implicitly convert 'def entry(arg: Int) thin -> Int' value to 'F'` |
| `comptime F = def(Int) abi("C") -> Int` (no `thin`) | `cannot implicitly convert 'def entry(arg: Int) abi("C") thin -> Int' value to 'F'`. Without `thin` it is a closure type, not a bare C pointer. |
| `OpaquePointer[MutAnyOrigin](unsafe_from_address=0)` | `constraint failed: Pointer is non-nullable. To construct a null pointer, use Optional[Pointer]...` |
| A struct field `Pointer[T, MutAnyOrigin]` | `struct fields cannot expose AnyOrigin in their type`. The compiler's note suggests `UntrackedOrigin`. |

**A silent hazard that does not fail:** `external_call["pthread_create", ...](..., plain_mojo_def, ...)` with a **non**-`abi("C")` def compiles and, with an `Int` argument, even runs. `external_call` does not check the ABI. The only check is converting the function to the `ThreadEntry` type, so always pass the function through a parameter of that type, as the wrapper above does.

### EINTR, by accident

The Mojo runtime installs a SIGUSR1 handler with flags `SA_ONSTACK` only, so there is no `SA_RESTART`. The spike blocks a pthread in a raw `read` on a pipe, then in `ppoll`, and sends `tgkill(pid, tid, SIGUSR1)` from main:
- Both syscalls return `-EINTR`.
- The thread retries and completes once a byte is written.
- The process survives.

This makes EINTR paths deterministically testable in `tests/`: block a helper thread, then `tgkill` it with SIGUSR1. It depends on runtime behavior, so a test should first assert the disposition, which `runtime_threads_spike` shows how to read with raw `rt_sigaction`.

### Recommendation: the control-plane exception

Approve exactly these: `pthread_create`, `pthread_join` and `pthread_attr_{init,setstacksize,destroy}`, plus `pthread_setname_np` if thread names are wanted. Put them in one module with exactly one `external_call` wrapper per symbol. Do pinning, tids and everything else with raw syscalls from inside the thread, which works as shown.

Raw `clone(2)` was **not tested**. I expect it to be unsafe: a raw clone has no glibc TLS or stack guard, and the runtime's allocator and `print` run on glibc threads. That expectation is reasoning, not a measurement.

---

## 2. Runtime threads (`spikes/runtime_threads_spike.mojo`)

Threads are counted from `/proc/self/task` with raw `openat` + `getdents64` into a stack buffer. The first count is the first statement of `main` and allocates nothing. Thread names come from `/proc/self/task/<tid>/comm`.

**Measure built binaries only.** `mojo run` JIT-executes inside the compiler process: it also shows 9 tasks, but some are the compiler's own (`mojo` ×2), and VmRSS is 275 MB.

**Built binary on 8 CPUs** (from `spikes/run_spikes.sh`):

| Stage | Tasks | Names | VmRSS |
|---|---|---|---|
| 0: first statement of `main` | 9 | (counted only) | |
| 1: after `print` | 9 | `runtime_threads`, `🔥 Thread0` … `🔥 Thread7` | 10.1 MB |
| 2: after a 100k List and a 1k Dict | 9 | same | 12.2 MB |
| 3: after raise/catch `Error` and String | 9 | same | 12.2 MB |
| 4: after `std.testing` asserts + `TestSuite.run()` | 9 | same | 12.2 MB |
| 5: after a 1 s idle sleep | 9 | same; **0 CPU ticks** used during the second | 12.2 MB |
| 6: after one `pthread_create` + join | 9 | same | 12.3 MB |
| 7–8: after `Python.import_module("os")`, then +200 ms (`SPIKE_PYTHON=1`) | 9 | same | +7 MB |

**Pool size follows the affinity mask inherited at exec:**

| Launch | Tasks at main | Workers |
|---|---|---|
| (all 8 CPUs) | 9 | 8, unpinned (`Cpus_allowed_list: 0-7`) |
| `taskset -c 0-3` | 5 | 4 |
| `taskset -c 0-1` | 3 | 2 |
| `taskset -c 0` or `taskset -c 5` | 2 | 1 |
| `MODULAR_ENABLE_AFFINITY=1` | 5 | 4 (one per physical core), worker *i* pinned to CPU *i* |

**What the counts show:**
- **Eager creation.** The workers exist before `main`. In the stdlib source (`builtin/_startup.mojo` in a nightly checkout; the 1.2.0rc2 source is not on disk), the startup wrapper calls `KGEN_CompilerRT_AsyncRT_GetOrCreateCPUDevice` before the user's main, which is consistent with the count. No later stage created more threads. Python interop starts none either.
- **Names are set late.** A worker names itself `🔥 ThreadN` only when it first runs; until then it shows the process name. Under `taskset -c 0` the single worker stays unnamed until main sleeps.
- **Idle cost.** Workers sleep: 0 utime+stime ticks over 1 s. RSS at stage 1 is 10.1–10.2 MB with 8 workers and 9.0–10.2 MB with 1, so the per-worker RSS is within run-to-run noise (under about 0.2 MB each).
- **Configuration.** `runtime.worker_stack_size_mb`, `MODULAR_THREAD_BUSY_WAIT_US` and `MODULAR_ENABLE_AFFINITY` appear as strings in `libKGENCompilerRTShared.so`. Only the last was tried. No env var for the worker count was found.

**What this means for process-per-core:**
- **Cost.** Each process costs about 10 MB RSS plus `1 + |mask|` threads. With N processes each inheriting the full mask, that is N × (nproc + 1) threads: 72 on this machine, idle but real (scheduler state, stacks, `/proc` noise).
- **The fix.** Start every worker process with its affinity already restricted to its core. Use `sched_setaffinity` in the parent between fork and exec, or `taskset`. That leaves 2 threads per process. Calling `sched_setaffinity` inside the child's `main` is too late, because the pool already exists.
- **Thread-per-core** in one process pays for the pool once, which matters little since the pool sits idle.

### Signal dispositions installed by the runtime

These come from raw `rt_sigaction(sig, NULL, &old, 8)`:

```text
signals with handlers (SigCgt): 1 2 3 4 5 6 7 8 10 11 12 15 24 25 31 33
  sig 1,2,3,4,5,6,7,8,11,12,15,24,25,31: SA_SIGINFO SA_ONSTACK SA_NODEFER SA_RESETHAND
  sig 10 (SIGUSR1): SA_ONSTACK
  sig 33 (glibc SIGSETXID): SA_SIGINFO SA_ONSTACK SA_RESTART
```

**Behavior observed by sending each signal to an idle process:**
- SIGTERM, SIGINT and SIGHUP terminate it with exit status 143, 130 and 129: the handler runs once, then the default action.
- **SIGUSR1 does not terminate it.** It continued and exited 0.
- SIGPIPE (13) keeps its default action, so `MSG_NOSIGNAL` is still mandatory.

The library itself still installs no handlers. M2 decisions affected by this:
- **Graceful shutdown via `signalfd`** must block SIGTERM/SIGINT first. I expect blocked signals to go to the signalfd rather than the runtime's handler, but **this was not tested**.
- **SIGUSR1 cannot be used as a default-terminate signal.**

---

## 3. Callbacks: `{thin fn, ctx}` (`spikes/callback_spike.mojo`)

### Shape that works (copy this)

```mojo
comptime CompletionFn = def(Int, mut Loop, Int) thin -> None   # (ctx, loop, -errno/result)
comptime DropFn = def(Int) thin -> None

@fieldwise_init
struct Target(TrivialRegisterPassable):   # size_of == 16; size_of[CompletionFn] == 8
    var call: CompletionFn                # NOT `fn`: still a reserved word
    var ctx: Int

trait Handler(Movable):
    def on_event(mut self, mut loop: Loop, res: Int): ...

def _on_event[H: Handler](ctx: Int, mut loop: Loop, res: Int):
    Pointer[H, MutUntrackedOrigin](unsafe_from_address=ctx)[].on_event(loop, res)

def _drop[H: Handler & Deinitable](ctx: Int):
    var owner = OwnedPointer[H](unsafe_from_opaque_pointer=OpaquePointer[MutAnyOrigin](unsafe_from_address=ctx))
    _ = owner^

# Adopt a heap handler behind a ctx word (the slab owns it until _drop):
var owner = OwnedPointer(h^)
var ctx = Int(owner.ptr())
_ = owner^.unsafe_take_allocation().unsafe_leak()
var t = Target(_on_event[H], ctx)       # a generic instantiation is a runtime fn value
var p = Target(plain_add, Int(Pointer(to=some_int)))   # so is a plain def

# Dispatch while callbacks get `mut loop`: copy the 16-byte target out first.
var t = self.table[slot]
t.call(t.ctx, self, res)
```

### What the spike checks

All checks pass (`CALLBACK SPIKE: PASS`):
- **Mixed handlers in one table.** It holds `Counter` (Ints), `Recorder` (owns a `List[Int]` and a `String`) and a plain `def plain_add` whose ctx is an `Int` address. 31 completions are dispatched, with correct per-handler results.
- **A handler enqueues during dispatch.** On `res == 7` the `Recorder` handler calls `loop.complete(self.slot, 8)` while the loop is dispatching. The follow-up runs FIFO at the tail of the queue (`1;2;…;10;8;`).
- **Exactly-once drop.** The `HandlerSlab` owns type-erased handlers through `{Target, DropFn}`. Dropping the slab runs each handler's `__deinit__` exactly once (2 drops), and none run while the slab is alive.

**Other spellings that were verified:**
- A non-capturing nested `def` can be returned as a thin fn value.
- An unbound method works as `def(mut Counter, Int) thin -> None = Counter.on_event`.
- A non-raising def converts to a `def(...) thin raises -> None` slot.

**Spellings that fail** (`spikes/expected_failures/`):

| Attempt | Error |
|---|---|
| A capturing closure (`{mut total}`) into `CompletionFn` | `cannot implicitly convert 'def(ctx: Int, res: Int) -> None' value to 'CompletionFn'`. State belongs in ctx. |
| A raising def into a non-raising slot | `cannot implicitly convert 'def r(ctx: Int, res: Int) raises thin -> None' value to 'CompletionFn'` |
| A field named `fn` | `expected name for 'var' declaration` … `escape keyword 'fn' with backticks to use it as an identifier` |
| A generic `OwnedPointer[H]` destroyed with only `H: Movable` | `'op' abandoned without being explicitly destroyed: Use into_inner() ... or unsafe_take_allocation()`. Add a `Deinitable` bound. |

### Cost

Each variant makes 10M calls. Ranges are ns/call over 6 runs: 5 of a built binary (4 of them pinned with `taskset -c 3`) and 1 under `mojo run`:

| Variant | ns/call |
|---|---|
| 1. direct, inlinable method | ≈0 (LLVM folded the loop) |
| 2. direct call to an `@no_inline` def | 0.94–1.33 |
| 3. `_on_event[H]` called directly (static dispatch) | ≈0 (inlined and folded) |
| 4. indirect, one target | 1.79–2.28 |
| 5. indirect, 2 handler types alternating | 1.81–2.22 |
| 6a. direct, with an xorshift index (baseline for 6b) | 2.6–3.3 |
| 6b. indirect, 8 slots, xorshift order (2 targets at random) | 7.4–8.6 |

The targets are built at runtime from `getpid()` so they cannot be constant-folded.

**Reading:**
- A well-predicted indirect completion call costs about **0.6–0.9 ns** more than a direct non-inlined call.
- An unpredictable one costs about **5 ns** more, from branch mispredicts.
- Both are irrelevant next to a syscall (≥100 ns) or an epoll round.

So `{thin fn, ctx}` costs nothing measurable, and handler genericity can stay at registration (`_on_event[H]`) rather than at the loop type.

---

## Gotchas found while doing this (Mojo 1.2.0rc2)

1. **`String.splitlines()` also splits on `\t`.** `"a:\t1\nb:\t2\n".splitlines()` returns 4 parts. It splits on `\t \n \v \f \r \x1c \x1d \x1e` and U+0085, but not on space or `\x1f`. Python does not split on `\t`. **Do not use it for HTTP or `/proc` parsing**; use `split("\n")`.
2. **`TestSuite.run()` parses argv** and raises `invalid argument: python (expected '--only' or '--skip')` on anything else. Pass test-program options via environment variables.
3. **`mojo build --sanitize thread` is unusable on this host.** Even hello-world aborts with exit 134 from the runtime's bundled tcmalloc: `MmapAligned() failed - unable to allocate with tag (... size=1073741824, alignment=1073741824)`, then `CHECK in Alloc: FATAL ERROR: Out of memory`. `--sanitize address` works.
4. **Deprecations hit on the way:**
   - `alloc[T](n)` warns: use the `Layout`-based `alloc` or `OwnedPointer`.
   - `OwnedPointer.unsafe_ptr()` warns; use `.ptr()`.
   - `UnsafePointer` warns; use `Pointer`.
   - `.bitcast` warns; use `.unsafe_bitcast`.
   - `init_pointee_move` no longer exists on `Pointer`.
5. **`Atomic` takes a type, not a DType:** `Atomic[Int64]`. `Atomic[DType.int64]` fails with `'Atomic' parameter 'T' has 'Deinitable & Movable' type, but value has type 'DType'`.
6. **`Int(String, base=16)` does not exist** (`unexpected keyword argument 'base'`).
7. **Lifetimes in the procfs reader.** My first draft wrote `syscall3(SYS_read, Int(fd.raw_fd()), Int(buf.unsafe_ptr()), len(buf))` in a read loop. On the last iteration that expression would be the last use of `buf` (and of `fd`), which is the CLAUDE.md last-use bug. No failure was observed; I caught it in review. The spike helpers use `sys.read(fd, Span(buf))`.
8. **`/proc/self/task` races.** It can list a thread that is gone by the time its `comm` is read. This was seen once as ENOENT, probably a just-joined pthread, because `pthread_join` returns when the kernel clears the tid futex, before the task is reaped. It was not reproduced afterwards. Tests that count threads should poll and tolerate ENOENT.
9. **The `O_DIRECTORY` value differs by arch:** x86_64 `0o200000`, aarch64 `0o40000`. It is not in `linux.consts` yet. The spike defines it module-locally next to `SYS_getdents64` (217 / 61) and `SYS_getcpu` (309 / 168).

## Files

**Spike programs:**
- `spikes/pthread_spike.mojo`: spike 1. `SPIKE_EXIT=detached-sleep|detached-busy` selects the exit modes.
- `spikes/runtime_threads_spike.mojo`: spike 2. `SPIKE_PYTHON=1` adds the Python stage.
- `spikes/callback_spike.mojo`: spike 3.

**Helpers and scripts:**
- `spikes/spike_util.mojo`: raw-syscall procfs helpers (`count_tasks`, `list_tasks`, `thread_comm`, `status_field`, `cpu_ticks`, `getcpu`, `gettid`).
- `spikes/expected_failures/*.mojo` and `spikes/check_expected_failures.sh`: the compile failures above, each asserted to keep failing with the quoted text.
- `spikes/run_spikes.sh`: builds and runs everything.

---

## 10k-connection epoll spike

This is the M1 spike "10k connections on one core" (`spikes/epoll_echo/`). It asks whether one Mojo thread, using raw syscalls only, can hold 10k idle plus 1k busy TCP connections on epoll, and what that costs next to C and tokio.

The spike has these parts:
- `server.mojo`: an edge-triggered (ET) echo server. It is built the way M2's `rt` loop will be: a slab plus `generation << 32 | slot` tokens, one registration per socket, and a loop-owned read buffer.
- `baseline.c`: the same algorithm in C.
- `tokio_echo/`: an idiomatic tokio `current_thread` echo server, the reference for the M2 gate.
- `client.mojo`: a single-threaded epoll load generator.
- `bench.py`: the harness that pins the processes, samples `/proc` and merges results.
- `check_echo.py` and `bench.py emfile`: correctness checks.
- `syscall_cost.mojo` and `fdtable_grow.c`: cost microbenchmarks.

### Answers in one table

| Question | Answer |
|---|---|
| Can one Mojo thread hold 10k idle + 1k active connections? | **Yes.** 11,000 of 11,000 established in all 45 runs of the final matrix, with 0 errors: no echo mismatches, resets or lost idle connections. Connecting all 11k takes 0.2–0.37 s, apart from the fd-table stall below and two unexplained slow tokio runs. |
| Throughput (1k active, ping-pong) | **About 180k msgs/s for 64 B and for 1 KiB**, for all three servers. Mojo ≈ C ≈ tokio within run-to-run noise (medians below). |
| Server CPU per message | Best runs: **≈ 4.8–5.5 µs** for Mojo and C, 5.1–5.8 µs for tokio. About 95% of it is kernel. Mojo user code is **0.17–0.22 µs/msg**; C is 0.23–0.26 and tokio 0.52–0.67. |
| Latency | Under load, p50 ≈ 5.3 ms and p99 ≈ 8–9 ms. That is queueing: 1000 messages in flight at 185k/s gives 5.4 ms by Little's law. Unloaded (1 active connection, 10,999 idle) p50 is **10 µs** for all three servers and p99 is 19–23 µs. |
| Syscalls per message | **2.00** at saturation: recv + send, with one `epoll_wait` per ~990 events. **2.6–2.8** when the server outruns a single client (1–2 events per wait). With `--strict-eagain` it is 3.00, which costs +0.2–0.35 µs/msg. |
| Memory per connection | **Mojo: 123–159 B/conn** of RSS (48-byte slot). C: 58 B. tokio: **4.9 KB** (a 4 KiB buffer per task). The kernel adds **≈ 3.6 KB per socket** (host-wide Slab growth), which dwarfs every userspace number. |
| Limits | None was hit at 11k (22k sockets on loopback). RLIMIT_NOFILE is soft = hard = 524288 and `fs.nr_open` is 1073741816. The ephemeral ports 32768–60999 give 28,232 connections per destination address. `somaxconn` is 4096. |
| Bugs found | (1) Lost EOF: the "short read means drained" shortcut never saw a FIN whose edge was already consumed. It is fixed in both servers, with a regression test. (2) Every Mojo process is multi-threaded, so each fd-table doubling stalls `accept4` for 17–47 ms (an RCU grace period). That overflowed the accept queue in 9 of 12 connect bursts. `--prealloc-fds` fixes it (0 of 12). (3) `print(..., flush=True)` segfaults when no fd is free. |

**Environment:**
- Host: the same as the spikes above (i5-1145G7, 4 cores / 8 threads, Linux 6.12.111, Mojo 1.2.0rc2), plus gcc 14.2 `-O2` and rustc 1.96.1 with tokio 1.52.3 (`--release`, LTO).
- Pinning: the server runs on CPU 2 with `taskset -c 2`, so the Mojo runtime starts only 2 threads. Clients run on CPUs 3, 1 and 0, so no client shares a physical core with the server.
- Noise: the host is a desktop running IDEs, a browser and other agents' builds, and the server's SMT sibling (CPU 6) was 4–48% busy during runs. Every configuration ran 3 times, interleaving Mojo, C and tokio, and the tables give the median and the range. Throughput differences smaller than the range are noise.
- `nf_conntrack` is loaded (Docker), so every loopback packet goes through conntrack. That inflates the absolute kernel cost for all servers equally.
- aarch64 was compiled only, not run: `server.mojo`, `client.mojo` and `syscall_cost.mojo` all build with `--target-triple aarch64-unknown-linux-gnu --emit object`.

### Reproduce

```bash
pixi run bash spikes/epoll_echo/run.sh build     # Mojo (mojo build), C (gcc -O2), tokio (cargo --offline)
pixi run bash spikes/epoll_echo/run.sh check     # check_echo.py (all servers) + EMFILE check
pixi run bash spikes/epoll_echo/run.sh matrix --reps 3 --servers mojo,c,tokio --no-strict   # final tables (~16 min)
pixi run bash spikes/epoll_echo/run.sh matrix --reps 3   # mojo,c incl. --strict-eagain runs
pixi run bash spikes/epoll_echo/run.sh burst --reps 6    # accept-burst / fd-table stall
pixi run bash spikes/epoll_echo/run.sh cost              # syscall_cost + fdtable_grow
# by hand:
taskset -c 2 spikes/epoll_echo/out/server --port 7000 [--prealloc-fds 32768]
taskset -c 3 spikes/epoll_echo/out/client --port 7000 --idle 10000 --active 1000 --size 64 --duration 10
```

Each matrix run writes its full results to `spikes/epoll_echo/out/matrix-*.json`. That includes per-run `/proc` samples, server counter deltas and per-CPU busy fractions. The tables below come from `matrix-20261021-180753.json`, and the `--strict-eagain` rows from `matrix-20261021-174419.json`.

### What the server does

The server's design follows the brief and anticipates M2:
- **Slab and tokens.**
  - Per-connection state is a `List[Slot]`; a `Slot` is 48 bytes and is printed as `slot_bytes` at startup.
  - The epoll data is `generation << 32 | slot`, and freeing a slot bumps its generation. An event still queued in the same `epoll_wait` batch for a closed, reused slot is then dropped as stale.
- **One registration per socket.** Each socket is registered once with `EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLET`, as mio does. There is no `epoll_ctl` per message: `ctls` stays 0 in the steady-state window.
- **Reads.**
  - One loop-owned 64 KiB buffer. Reading continues until EAGAIN, or until a short read; on a TCP stream a short read means the queue was empty.
  - The short-read shortcut is skipped once RDHUP/HUP/ERR has been seen (the sticky `read_closed` flag, as tokio's `READ_CLOSED`).
- **Writes.**
  - The server sends directly; on a partial send it queues the rest in the slot, retries until EAGAIN, and lets `EPOLLOUT` finish.
  - With more than 256 KiB queued, reading pauses and is resumed by hand after the queue drains, because ET does not re-report data that is already buffered.
  - The sent prefix of the queue is compacted, so a slow reader cannot grow the queue without bound.
  - A FIN that arrives while output is queued is honored after the queue drains.
- **Accept.**
  - `accept4(NONBLOCK|CLOEXEC)` with no peer address, until EAGAIN.
  - EMFILE/ENFILE/ENOBUFS/ENOMEM are logged and **pause** accepting, instead of spinning on a still-readable listener. Accepting resumes after a close or on the next 500 ms tick.
  - RLIMIT_NOFILE is raised to the hard limit; `--nofile N` lowers it for the EMFILE test.
- **Counters.** Every syscall is counted, and the server prints a `STATS` line every 500 ms. That is how syscalls per message are measured exactly: there is no strace or perf on this host.

The C baseline is the same algorithm in C. The tokio server is idiomatic code: a task per connection, `read` then `write_all`, and a 4 KiB buffer per task.

**Correctness checks** (`check_echo.py`, all pass for all three servers):
- 200 concurrent byte-exact echoes of random sizes from 1 B to 256 KiB.
- 16 MiB to a slow reader. This exercises pause/resume: `pauses=11`, `send_eagain=11`.
- 8 MiB followed by a half-close.
- 200 rounds of data + FIN sent before the first read.
- An RST while output is queued.
- 1000 connect/close cycles, ending with `open=0`.

`bench.py emfile` runs the servers at `--nofile 64` with 104 clients. The Mojo and C servers log `EMFILE, pausing accepts (open=59)`, keep echoing on the 59 accepted connections, then log `resumed`. They end with `open=0` and serve a fresh client afterwards.

### Results (11k connections: 10k idle + 1k active, 10 s, median (min–max) of 3 runs)

| server | size | client procs | msgs/s | server CPU ns/msg | p50 / p99 µs | syscalls/msg |
|---|---|---|---|---|---|---|
| mojo | 64 | 1 | 179,039 (153,833–190,403) | 4,929 (4,815–5,820) | 5374 / 8782 | 2.57 |
| c | 64 | 1 | 184,408 (156,772–186,845) | 4,875 (4,843–5,468) | 5374 / 7995 | 2.63 |
| tokio | 64 | 1 | 181,791 (132,009–183,773) | 5,316 (5,225–7,203) | 5505 / 7864 | n/a |
| mojo | 1024 | 1 | 180,227 (133,504–181,941) | 4,961 (4,942–6,772) | 5505 / 7930 | 2.76 |
| c | 1024 | 1 | 182,470 (139,205–182,897) | 5,096 (4,975–6,753) | 5439 / 7864 | 2.53 |
| tokio | 1024 | 1 | 153,694 (128,506–180,339) | 6,130 (5,122–7,391) | 5767 / 13500 | n/a |
| mojo | 64 | 3 | 186,266 (137,750–188,579) | 5,332 (5,236–7,234) | 5243 / 8782 | 2.00 |
| c | 64 | 3 | 180,825 (138,871–191,125) | 5,452 (5,169–7,332) | 5308 / 9175 | 2.00 |
| tokio | 64 | 3 | 172,786 (131,763–180,072) | 5,742 (5,491–7,548) | 5571 / 9437 | n/a |
| mojo | 1024 | 3 | 153,184 (139,210–182,313) | 6,577 (5,438–7,232) | 6029 / 13107 | 2.00 |
| c | 1024 | 3 | 177,249 (132,264–180,897) | 5,591 (5,459–7,602) | 5505 / 8192 | 2.00 |
| tokio | 1024 | 3 | 161,335 (141,741–170,722) | 6,144 (5,798–6,987) | 5898 / 10617 | n/a |
| mojo `--strict-eagain` | 64 | 3 | 173,826 (132,497–184,572) | 5,672 (5,387–7,377) | 5505 / 9306 | 3.00 |
| c `--strict-eagain` | 64 | 3 | 182,150 (135,235–183,669) | 5,448 (5,359–7,380) | 5439 / 8192 | 3.00 |

**Unloaded latency (1 active + 10,999 idle, 64 B, 1 client):**

| server | msgs/s | p50 / p99 µs | syscalls/msg |
|---|---|---|---|
| mojo | 95,203 (92,690–101,867) | 10 / 20 | 3.02 |
| c | 99,069 (98,875–102,541) | 10 / 19 | 3.02 |
| tokio | 89,899 (80,689–100,956) | 10 / 23 | n/a |

**How to read this:**
- **One client is client-bound.** The single client ran at 93–99% of its CPU while the server ran at 88–97%. Three client processes saturate the server (99–100% CPU) without raising msgs/s, because the whole loopback system tops out near 185–190k msgs/s on this host. The fair comparison is therefore **server CPU ns/msg**, not msgs/s.
- **Ranking.** Taking the best run of each, Mojo, C and tokio come out at 4.8, 4.8 and 5.2 µs/msg (64 B, 1 client) and at 5.2, 5.2 and 5.5 µs/msg (64 B, 3 clients).
- **The `--strict-eagain` rows** come from the earlier matrix, `matrix-20261021-174419.json`. That matrix also ran the default server: 182,910 msgs/s and 5,336 ns/msg for Mojo, and 188,366 and 5,272 for C. Those binaries predate the `read_closed` fix, but the fix only gates the shortcut, which strict mode never takes.
- **1 KiB costs barely more than 64 B.** The cost is per packet, not per byte. The 1 KiB/3-client Mojo median (6.6 µs) comes from runs where CPU 6 was 36–38% busy; its best run (5.4 µs) equals C's.

**Memory** (`VmRSS` of the server; the kernel figure is host-wide `/proc/meminfo` Slab):

| | 0 connections | 11k connections (idle, after the load) | per connection |
|---|---|---|---|
| Mojo | 8.7–11.5 MiB (once 15.8 in an earlier run) | 10.0–12.8 MiB: RssFile ≈ 5.5 MiB (runtime libraries), RssAnon ≈ 4.8–5.3 MiB | 123–159 B |
| C | 1.7–1.8 MiB | 2.3–2.5 MiB | 58 B |
| tokio | 2.0–2.2 MiB | 53.1–53.3 MiB | 4,866 B |
| kernel | | Slab +3.5–3.8 KB per socket (2 sockets per connection on loopback) | ≈ 3.6 KB per server socket |

**Notes on memory:**
- The Mojo and C slots are the same 48 bytes. The extra ~70–100 B/conn in Mojo is most likely `List` growth: the List allocates, moves and frees, and the allocator keeps the freed buffers resident. glibc `realloc` grows large blocks with `mremap` instead.
- Mojo's RSS before any connection exists varies between runs (8.7–11.5 MiB, and once 15.8 MiB). That variation comes from the runtime, not from the server's data.
- Kernel socket memory is ~25–30× the userspace state. Per-connection userspace buffers, which is tokio's idiom, are what make a server's memory explode.

### Where the time goes

**Syscall costs** (`syscall_cost.mojo`, pinned to CPU 2, 3 runs, ranges):

| Operation | Cost |
|---|---|
| `getpid` (bare syscall entry/exit; eIBRS mitigations) | 91 ns |
| `clock_gettime` raw syscall (`linux.time.Instant.now`) | 116–118 ns |
| `clock_gettime` vDSO (`std.time.perf_counter_ns`) | 12.6–13.2 ns |
| `recv` on an empty TCP socket (EAGAIN) | 156–163 ns |
| `epoll_pwait2` timeout 0, 10k idle fds registered | 142–146 ns |
| TCP loopback hop: `send` 64 B + `recv` it, same thread, hot connection | 3.64–3.69 µs |
| same, 1 KiB | 3.66–3.70 µs |
| fd-table doubling (`dup3` to fd 64…16384), 1 thread | 1–27 µs |
| fd-table doubling, 2 threads (any Mojo process) | **20–39 ms** |

**Server cost per message at saturation (≈ 5.2–5.3 µs at best for 64 B):**
- **User code ≈ 0.2 µs (3–4%).** That is all the Mojo code: event dispatch, the generation check, slab indexing and counters.
- **Two syscall crossings ≈ 0.2 µs.**
- **TCP stack work ≈ 4.8 µs, the rest.**
  - On loopback, `send` runs TCP output and also the *peer socket's* TCP input in softirq on the sender's CPU, and that includes waking the client's epoll waiter.
  - So the server's `send` pays for the client's receive path, and the client's `send` pays for the server's.
  - One hop on a hot connection is 3.7 µs. The extra ~1.3 µs/msg in the echo comes from cross-CPU wakeups (IPIs to the client cores), cache misses over 1000 rotating sockets, and conntrack.
- **`epoll_wait`** costs about 0.15 µs per wait. At saturation that is ~0.15 ns/msg (990 events per wait). When one client cannot keep the server busy it is ~0.1 µs/msg (0.55–0.8 waits per message), and the server then sleeps and wakes per batch.
- **Strict EAGAIN** costs one extra `recv` per message (+1 syscall, measured +0.18–0.34 µs/msg), which matches the 160 ns microbenchmark.
- **The client's clock** costs one raw `clock_gettime` per message (117 ns of client CPU). The vDSO would take 13 ns.

### Two bugs and one hazard found

1. **Lost EOF in the short-read shortcut (fixed).**
   - When data and FIN arrive together, which happens if the client sends then calls `shutdown(SHUT_WR)` before the server reads, ET delivers one event with `EPOLLIN|EPOLLRDHUP`. The read returns the data short, and the shortcut stops reading.
   - No further edge ever comes, so the server sat in CLOSE-WAIT forever. The same happens when a FIN arrives while reading is paused for backpressure.
   - This was seen once as a hang in the 8 MiB half-close check. `check_fin_with_data` then reproduced it deterministically on both old servers (`iteration 0: no EOF after 1 of 1 bytes`).
   - The fix is a sticky `read_closed` flag, set by RDHUP/HUP/ERR even while reading is paused. Once it is set, reads run to EOF or EAGAIN. This is tokio's READ_CLOSED rule. **`rt` must implement the same rule.**
2. **The fd-table growth stall (multi-threaded processes).**
   - The kernel doubles a process's fd table when an fd number reaches its size: 64, 128, …, 8192. If the `files_struct` is shared by more than one thread, `expand_fdtable()` calls `synchronize_rcu()` first.
   - A **Mojo process always has runtime worker threads** (spike 2), so the `accept4` that allocates fd 8192 blocks for an RCU grace period. `fdtable_grow.c` shows 20–39 ms with 2 threads and 1–27 µs with 1.
   - During an 11k connect burst from 3 clients, a stall overflows the 4096-entry accept queue. The kernel drops the SYNs (`TcpExt ListenOverflows` +339…+769), the clients retry after the 1 s SYN timeout, and connecting takes **1.2 s instead of 0.2 s**.
   - Results of `bench.py burst`, two sessions of 6 runs each:

     | server | bursts with overflows |
     |---|---|
     | Mojo | **9 of 12** |
     | Mojo with `--prealloc-fds 32768` | 0 of 12 |
     | C | 0 of 12 |
     | tokio (1 thread) | 0 of 6 |

   - `--prealloc-fds 32768` does one `dup3(listener, 32767)` plus `close` at startup, which costs one ~25 ms stall up front; the table never shrinks.
   - A single client connects too slowly to fill the queue during one stall, so the matrix runs showed it only with 3 clients.
   - tokio also had two slow connect phases in the matrix (1.0 s and 2.3 s, 2 of 18 runs). That cannot be this stall, since tokio is single-threaded. It was not investigated.
3. **`print(..., flush=True)` segfaults when the process has no free fd.**
   - Mojo 1.2.0rc2 crashes in `fclose(NULL)`, apparently because the flush path needs a new descriptor. That happened on the server's first EMFILE log line.
   - A plain `print` and an uncaught `raise` work at EMFILE.
   - The spike logs through `echo_util.emit`, a raw `write(2)` loop. **Any `rt`/`net` logging must avoid `print(flush=True)`.**

### What M2 must do to beat this

1. **Keep this syscall shape. It is the whole budget.**
   - Kernel work is ~95% of the per-message cost, and a syscall crossing alone is 0.09–0.16 µs. The rt must not add syscalls per message:
     - no `epoll_ctl(MOD)` per operation (a oneshot/re-arm design would add one or more per message);
     - no EAGAIN probe read: use the short-read rule *with* the sticky read-closed flag;
     - no clock read per event.
   - Register once, read and write to EAGAIN, drain `accept` until EAGAIN, and batch 1024 events per wait.
2. **The gate is reachable.**
   - tokio `current_thread` measured at 92–100% of this spike's throughput and used 5.2–6.1 µs/msg; its user time is ~0.55 µs/msg.
   - "≥ 80% of tokio" therefore allows M2 about **1.25× tokio's CPU/msg**, roughly 6.5–7.5 µs/msg. That leaves ~1.5 µs/msg for the completion contract (op slab, completion dispatch through `{thin fn, ctx}`, which costs ~1–8 ns per spike 3, timers and buffer pools) on top of this spike's 0.2 µs.
   - Measure the gate as server CPU ns/msg at saturation (3 client processes): single-client msgs/s measures the client. Use ≥ 3 interleaved runs, and record sibling-CPU load.
3. **Timers: read the clock once per loop iteration** (after `epoll_wait`), not per event or per op. A raw `clock_gettime` costs 117 ns, 9× the vDSO. Decide whether `linux.time` gets a vDSO reader (that means parsing the vDSO ELF from `AT_SYSINFO_EHDR`). At one read per loop turn it does not matter; at one read per op it costs 2% here.
4. **Pre-grow the fd table at loop or server start** (`dup3` to the expected maximum, or to RLIMIT_NOFILE − 1 capped to something sane, then `close`). Otherwise a multi-threaded Mojo process stalls 20–40 ms in whatever syscall creates fd 2^k, while it is under load. This belongs in `rt` (or `net`'s listener setup), with a test.
5. **Buffers: keep the design's loop-owned receive buffers.** A per-connection buffer is what made tokio cost 4.9 KB/conn (53 MiB at 11k, 704 MiB if it were 64 KiB). A 48-byte slot plus ~3.6 KB of kernel memory per socket is the floor. Grow the slab in fixed chunks (stable addresses, no copy-on-grow) rather than as one doubling `List`. That also avoids moving every live slot.
6. **Handle EMFILE as here:** pause accepting, then resume on close or on a tick (never spin on the readable listener), and log through raw `write(2)`.
7. **What is left after epoll is io_uring (M3).**
   - On loopback the TCP stack dominates, so even zero-crossing I/O (multishot recv with provided buffers plus batched sends, one `io_uring_enter` per loop turn) can save at most the ~0.2–0.4 µs/msg of crossings and wakeups: about 5–10% here.
   - Do not expect io_uring to multiply loopback throughput. Real-NIC traffic (interrupts, GRO) needs its own measurement.

### Files

- `spikes/epoll_echo/server.mojo`, `client.mojo`, `echo_util.mojo` (flags, histogram, tokens, `emit`).
- `spikes/epoll_echo/baseline.c`, `tokio_echo/` (Cargo project; builds offline from cached crates).
- `spikes/epoll_echo/bench.py`: the `matrix`, `one`, `burst` and `emfile` commands. `check_echo.py`: the correctness checks. `run.sh`: build plus the commands above.
- `spikes/epoll_echo/syscall_cost.mojo`, `fdtable_grow.c`: the cost microbenchmarks.
- `spikes/epoll_echo/out/`: build output and `matrix-*.json` results.
