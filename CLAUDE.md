# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`mojo_net` is a monorepo of native Mojo networking libraries for Linux. The roadmap is: 1. TCP, 2. an HTTP library, 3. an HTTP server, plus database drivers on the same layers.

**Scope.** One repo does not mean one project:
- Each library has its own doc, status and milestones.
- Work on one library must not gate or leak into another.
- Package status:
  - `linux`, `bytes`: shared base layers;
  - `net`: the TCP library, the active work;
  - `rt`: an experimental event-loop runtime, **frozen** until Mojo's async/await stabilizes. Keep it compiling and green; add no features unless the user unfreezes it.

**Docs:**
- `docs/design.md`: packages, import rules and the numbered contracts that code comments cite. Read it before changing any package.
- Per-library docs: `docs/net.md` (scope, L2 contract, readiness-loop rules, milestones) and `docs/rt.md`.
- `docs/spikes.md`: measured facts (threads, the Mojo runtime, callbacks, the 10k-connection epoll spike).

## Commands
Run everything through pixi (`~/.pixi/bin/pixi`). The Mojo toolchain is pinned in `pixi.toml`.

```bash
pixi run test                      # every tests/**/test_*.mojo, plus the ABI layout check
pixi run test net/                 # only files whose path contains "net/" (no ABI check)
pixi run ci                        # import-check + test + nolibc-check + examples-check: what CI must run
pixi run mojo run -I src tests/linux/test_sys.mojo                      # one file
pixi run mojo run -D MOJO_NET_FAULTS=1 -I src tests/net/test_tcp_faults.mojo   # one fault-seam file
pixi run mojo run -D MOJO_NET_SIM=1 -I src tests/rt/test_loop_contract.mojo     # one file on the rt simulator
pixi run import-check              # package import rules (tools/check_imports.py)
pixi run examples-check            # build every examples/<pkg>/*.mojo
pixi run aarch64-check             # cross-compile every test and example for aarch64 (~12 min; not in ci)
pixi run abi-check                 # constants + struct layouts vs this host's C headers
pixi run nolibc-check              # no libc socket/poll/epoll symbols on the I/O path
pixi run gen                       # regenerate src/linux/{nr,consts,errno}.mojo from headers
pixi run spikes                    # re-run the M1 spikes
pixi run bench build               # rt benchmarks (bench/rt/README.md)
```

**Test runner (`tools/run_tests.sh`):**
- Each test file ends with `def main() raises: TestSuite.discover_tests[__functions_in_module()]().run()`; `mojo test` no longer exists.
- A file fails if it runs 0 tests, because TestSuite exits 0 in that case.
- Files named `test_*_faults.mojo` (and only those) are built with `-D MOJO_NET_FAULTS=1`.
- Files named `test_*_contract.mojo` run twice: on epoll, then on the `rt` in-memory simulator (`-D MOJO_NET_SIM=1`). Files named `test_*_sim.mojo` run on the simulator only. Replay a simulator run with `MOJO_NET_SIM_SEED=<n>`.
- Each file has a timeout: `MOJO_NET_TEST_TIMEOUT`, default 600 s.
- `MOJO_NET_REQUIRE_IPV6=1` turns "no IPv6 loopback" skips into failures.

**Test-only Python:** some tests use the pixi env's Python as an oracle (`ipaddress`) or as a peer process. It is never used in `src/`.

## Layout and rules
- **Packages:** imports only point downward: `rt → net → bytes → linux`. `linux` imports only `std`.
  - Nothing outside `rt` imports `rt`.
  - `pixi run import-check` enforces these rules for `src/`, `tests/`, `examples/`, `bench/` and `spikes/`.
  - A new library gets an entry in `ALLOWED` in `tools/check_imports.py`.
  - Per-package directories:
    - `src/<pkg>`, `tests/<pkg>`, `examples/<pkg>`, `bench/<pkg>`;
    - `docs/<pkg>.md`.
  - `src/linux`: the syscall layer.
  - `src/bytes`: `ByteBuffer`, and the sans-I/O `Codec` trait (`bytes.codec`, contract 1).
  - `src/net`: sockets.
  - `src/rt` (frozen): `core` (Loop + proactor), `driver` (trait), `epoll_driver`, `sim` (simulator), `event_loop`, `timers`, `slab`, `mailbox`, `evented` (`TcpServer[H]`/`dial[H]` connections driving a `ConnHandler`).
- **`net` modules:**
  - `addr`: addresses.
  - `socket`: L1, every socket option, no policy.
  - `blocking`, `tcp`, `unix`: L2 blocking streams. Nonblocking internally: try → EAGAIN → `wait_ready` → retry, with absolute per-direction deadlines.
  - `reader`: the `Read` trait and `BufReader`. Frame reads are bounded (`max_bytes`, `max_size`) and all or nothing: on any error nothing is consumed.
  - `dns` (sans-I/O DNS messages), `resolv` (resolv.conf, hosts, search list), `resolver` (`Resolver.lookup_ip`, `Lookup`): name resolution without libc.
  - `dial`: `TcpStream.connect_host` (Happy Eyeballs v2 over `Lookup`) and `HostPort`.
  - Long-lived connections: `TcpStream.detect_dead_peers()` (keepalive + `TCP_USER_TIMEOUT`) and `idle_state()` (in `blocking`, on both streams).
  - Readiness loops: `try_read` / `try_write` / `try_accept` never wait (None instead); `TcpListener.bind_reuseport`; see `examples/net/epoll_echo.mojo`.
  - `buffer` / `codec`: re-exports of `bytes.buffer` / `bytes.codec`.
- **Syscalls:**
  - All of them go through `linux/syscall.mojo` (the only inline asm), via the typed wrappers in `linux/sys.mojo` or module-local wrappers.
  - Never call libc for I/O (`external_call["socket"...]` etc.); `nolibc-check` enforces this.
  - The one private-stdlib use is `linux/fault.mojo` (`std.ffi._Global`). It is compiled only under `-D MOJO_NET_FAULTS=1` and is deliberately not re-exported from `linux`.
- **Generated files:**
  - `src/linux/nr.mojo`, `consts.mojo` and `errno.mojo` are generated from kernel/C headers. Don't edit them; add names to `tools/gen_syscall_nr.py` / `tools/gen_abi.py` and run `pixi run gen`.
  - A syscall must exist on both x86_64 and aarch64; the generator rejects it otherwise (aarch64 has no `poll`, `epoll_wait`, `accept`, `open`, `pipe`).
- **ABI mirrors:** every mirror struct lives in `linux/abi.mojo` and is listed in `STRUCTS` in `tools/gen_abi.py`, which is how the layout check verifies it.
- **Errors:**
  - Public APIs `raise IoError` (typed raises), built with `check(op, ret)` or `IoError.from_errno` / `IoError.of_kind`. Internals pass raw `-errno` ints.
  - `InvalidData` means the peer broke the protocol; `InvalidInput` means our caller passed a bad argument.
- **Signals:**
  - Send on sockets with `send`/`sendmsg` plus `MSG_NOSIGNAL`, never `write`/`writev`.
  - The library installs no signal handlers. Note that the Mojo runtime itself installs some (see `docs/spikes.md`).
- **Fds:** create every fd with CLOEXEC (`SOCK_CLOEXEC`, `accept4`, `F_DUPFD_CLOEXEC`).
- **Logging in library code:** use raw `write(2)`, never `print(..., flush=True)`, which segfaults when no fd is free (EMFILE).
- **Tests:**
  - Use port 0, pid-unique abstract socket names, and scratch subdirectories, so files can run in parallel.
  - Every fault test starts with `fault.clear()`.
  - Regression tests for review findings live in `tests/*/test_<group>_regressions*.mojo`.
  - Shared test helpers are modules not named `test_*` (`tests/net/reader_script.mojo`, `tests/net/fake_dns.mojo`). A helper that owns a peer process must be stopped explicitly at the end of the test (`dns^.stop()`): Mojo destroys values right after their last use, which would kill the peer early.

## Mojo 1.2 pitfalls found in this codebase
- **Lifetimes (critical).** Mojo destroys a value right after its last use. In `sys.fcntl(owner.raw_fd(), ...)` the `OwnedFd` is destroyed, and the fd closed, *before* the syscall runs. So:
  - Pass the owner itself (`AsFd`) to `linux.sys` wrappers.
  - Pass memory as `Span`/`ref`.
  - When only a raw address reaches the kernel (for example inside a `Msghdr`), call `sys.keep_alive(x)` after the syscall.
  - Registering an fd with epoll does **not** keep its owner alive: whoever registers must own the fd until `EPOLL_CTL_DEL`.
  - The regression test is `tests/linux/test_sys.mojo::test_owner_outlives_syscall_when_last_use`.
- **ABI structs:**
  - Use `Array[UInt8, N]` for C arrays, never `SIMD`. SIMD is aligned to its full width, which made `sockaddr_in6` 48 bytes.
  - A struct with `Array` fields can't be `TrivialRegisterPassable`; use `(Copyable, Movable)`.
  - Mojo has no packed structs, so `EpollEvent` is stored as 32-bit words to match x86_64's packed layout.
  - Struct pointer fields need `MutUntrackedOrigin`.
- **Moves:**
  - A move-only element can't be moved out of a `Tuple`, and `var x = s.field^` only works inside a `deinit self` method. So APIs return small structs (`TcpAccepted`, `SocketPair` with `Optional` fields + `take()`) instead of tuples.
  - A list literal of mutable `Span`s over one buffer fails the aliasing check; use `append` or `ImmSpan`.
- **Function values (critical for callbacks).** A function cannot take its own address, or the address of any function in a reference cycle with it, as a value.
  - `Target(on_recv, ctx)` inside `on_recv` fails with "function instantiation in parameter domain that recursively requires itself".
  - Build every callback value (`rt`'s `Target`) once, outside the cycle (at registration), store it as data, and re-arm with the stored value.
  - Generic trampolines such as `_dispatch[H]`, referenced only from a setup function, are fine.
- **`mut` is exclusive (critical).** The compiler may cache a `mut` argument's fields, or write a stale copy back. So:
  - **Threads.** Never mutate a struct through `mut self` from two threads, even with atomic field access. An early `rt.mailbox` lost a committed CAS this way. Put cross-thread state in raw memory (`std.memory.alloc.unsafe_alloc`, `MutUntrackedOrigin` pointers) and touch it only through atomic pointer ops from methods that take `self` immutably, as `rt.mailbox.Sender` does.
  - **Loop state.** Don't hold a struct as a `mut` argument in a frame that runs a loop while callbacks reach it through a raw address (`ctx`). The compiler may read stale fields across `run_once`. Keep handler state on the heap, or take its address in the function that runs the loop.
- **Comptime backend alias:** `comptime Backend: Driver = A if cond else B` has the trait type, so members beyond the trait are invisible through it. Tests reach simulator-only members with `rebind[SimDriver](ev.driver)`.
- **Typed raises:** inside a `try` whose calls raise `IoError`, you can't `raise Error(...)`.
- **Comptime arrays:** a comptime `Array` of non-`ImplicitlyCopyable` values can't be indexed at runtime; use if-chains.
- **FFI:** declare each `external_call` C symbol with exactly one signature (spike-only code). A C-callable fn pointer is spelled `def(OpaquePointer[MutAnyOrigin]) thin abi("C") -> OpaquePointer[MutAnyOrigin]`, and function-typed parameters are spelled `def(T) thin -> R`.
- **Stdlib traps:**
  - `String.splitlines()` also splits on `\t` (verified on 1.2.0rc2); use `split("\n")`. This matters for HTTP parsing.
  - `TestSuite.run()` rejects unknown argv, and its times are in milliseconds.
  - Memory copies are spelled `unsafe_memcpy` / `unsafe_memmove`.
- **Runtime threads:** every Mojo process starts 1 + (CPUs in its affinity mask) runtime threads before `main`. Because a process is always multi-threaded, each kernel fd-table doubling stalls the fd-creating syscall for 20–40 ms. Long-running servers must pre-grow the fd table with `linux.probe.pregrow_fd_table(listener)` (see `docs/spikes.md`).
- **`assert_equal`** needs identical types (`Int(buf[i])` vs `ord("x")`).
- **Spellings to use:** `def` only (no `fn`), `comptime` (no `alias`), `Self.T` for struct parameters, `std.` import prefix, `@inline(.always)`, and `Layout[T](count=n)` (not the nightly-only `length=`).
