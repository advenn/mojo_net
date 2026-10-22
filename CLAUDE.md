# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

A native Mojo TCP/socket library for Linux. It is the foundation for a future HTTP library, an HTTP server and database drivers.

**Scope:** this repo is the socket library, not an async runtime. Keep runtime work (event loops, executors, schedulers, io_uring proactors) out of it. The experimental runtime that grew here lives in the separate `mojo_rt` repo; the git tag `runtime-snapshot` marks the last commit that contained it. A concurrent server drives nonblocking sockets from its own readiness loop (`linux.Epoll`, edge-triggered) and runs one process per core with `SO_REUSEPORT` (see `docs/design.md`).
- Architecture, scope, contracts and milestones: `docs/design.md`. Read it before changing `net`.
- Measured facts (threads, runtime, callbacks, the 10k-connection epoll spike): `docs/spikes.md`.

## Commands
Run everything through pixi (`~/.pixi/bin/pixi`). The Mojo toolchain is pinned in `pixi.toml`.

```bash
pixi run test                      # every tests/**/test_*.mojo, plus the ABI layout check
pixi run test net/                 # only files whose path contains "net/" (no ABI check)
pixi run ci                        # test + nolibc-check: what CI must run
pixi run mojo run -I src tests/linux/test_sys.mojo                      # one file
pixi run mojo run -D MOJO_TCP_FAULTS=1 -I src tests/net/test_tcp_faults.mojo   # one fault-seam file
pixi run abi-check                 # constants + struct layouts vs this host's C headers
pixi run nolibc-check              # no libc socket/poll/epoll symbols on the I/O path
pixi run gen                       # regenerate src/linux/{nr,consts,errno}.mojo from headers
pixi run spikes                    # re-run the M1 spikes
```

**Test runner (`tools/run_tests.sh`):**
- Each test file ends with `def main() raises: TestSuite.discover_tests[__functions_in_module()]().run()`; `mojo test` no longer exists.
- A file fails if it runs 0 tests, because TestSuite exits 0 in that case.
- Files named `test_*_faults.mojo` (and only those) are built with `-D MOJO_TCP_FAULTS=1`.
- Each file has a timeout: `MOJO_TCP_TEST_TIMEOUT`, default 600 s.
- `MOJO_TCP_REQUIRE_IPV6=1` turns "no IPv6 loopback" skips into failures.

**Test-only Python:** some tests use the pixi env's Python as an oracle (`ipaddress`) or as a peer process. It is never used in `src/`.

## Layout and rules
- **Packages:** imports only point downward: `net → bytes → linux`. `linux` imports only `std`.
  - `src/linux`: the syscall layer.
  - `src/bytes`: `ByteBuffer`.
  - `src/net`: sockets.
- **`net` modules:**
  - `addr`: addresses.
  - `socket`: L1, every socket option, no policy.
  - `blocking`, `tcp`, `unix`: L2 blocking streams. Nonblocking internally: try → EAGAIN → `wait_ready` → retry, with absolute per-direction deadlines.
  - `buffer` / `codec`: `ByteBuffer` (re-exported from `bytes`) and the sans-I/O `Codec` trait.
- **Syscalls:**
  - All of them go through `linux/syscall.mojo` (the only inline asm), via the typed wrappers in `linux/sys.mojo` or module-local wrappers.
  - Never call libc for I/O (`external_call["socket"...]` etc.); `nolibc-check` enforces this.
  - The one private-stdlib use is `linux/fault.mojo` (`std.ffi._Global`). It is compiled only under `-D MOJO_TCP_FAULTS=1` and is deliberately not re-exported from `linux`.
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
- **Function values:** a function cannot take its own address, or the address of any function in a reference cycle with it, as a value. Storing `on_recv` as a callback inside `on_recv` fails with "function instantiation in parameter domain that recursively requires itself". Build callback values once at setup and store them as data.
- **`mut` is exclusive:** the compiler may cache a `mut` argument's fields, or write a stale copy back. So:
  - never mutate a struct through `mut self` from two threads, even with atomic field access. Use raw memory (`std.memory.alloc.unsafe_alloc`, `MutUntrackedOrigin` pointers) and atomic pointer ops from methods that take `self` immutably;
  - don't hold a struct as a `mut` argument while code reaches it through a raw address.
  
  Both bit the experimental runtime (now in `mojo_rt`).
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
