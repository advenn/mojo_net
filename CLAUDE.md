# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`mojo_net` is a monorepo of native Mojo networking libraries for Linux. The roadmap is: 1. TCP, 2. an HTTP library, 3. an HTTP server, plus database drivers on the same layers.

**Scope.** One repo does not mean one project:
- Each library has its own doc, status and milestones.
- Work on one library must not gate or leak into another.
- Package status:
  - `linux`, `bytes`: shared base layers;
  - `net`: the TCP/UDP library (client side done; API stable, packaged);
  - `http`: the HTTP/1.1 library, done through H6 (`docs/http.md`);
  - `server`: the HTTP server (roadmap step 3), done through S5 (`docs/server.md`);
  - `pg`: the PostgreSQL driver (`docs/pg.md`), done through P7: P1, `crypto` (hashes and MACs for authentication) and `bytes.base64`; P2, the sans-I/O session codec; P3, the blocking client (`pg.client`, `pg.config`); P4, the extended protocol (parameters, prepared statements); P5, binary types and a statement cache; P6, transactions, notifications and a pool; P7, three independent reviews and their fixes;
  - `redis`: the Redis client (`docs/redis.md`). Done: R1, the sans-I/O RESP2/RESP3 codec; R2, the blocking client (`redis.client`, `redis.config`); R3, pipelines, transactions and typed helpers. Parked, by the user's priorities;
  - `tls`: TLS through OpenSSL 3.5, the active work (`docs/tls.md`). Done: T0, the spike (`docs/spikes.md`); T1, the verifying client. Next: H8, `https://` in `http.Client`. TLS only through OpenSSL, never our own (the user's decision; the rules, cited in code as TL/TC/TB/TS/TA/TG, are in `docs/research/tls_with_openssl.md`);
  - `rt`: an experimental event-loop runtime, **frozen** until Mojo's async/await stabilizes. Keep it compiling and green; add no features unless the user unfreezes it.

**Docs:**
- `docs/design.md`: packages, import rules and the numbered contracts that code comments cite. Read it before changing any package.
- Per-library docs: `docs/net.md` (scope, L2 contract, readiness-loop rules, milestones), `docs/http.md` (scope, strictness rules, milestones), `docs/server.md` (model, behaviour, milestones), `docs/pg.md` and `docs/redis.md` (scope, decisions, milestones), and `docs/rt.md`.
- `docs/spikes.md`: measured facts (threads, the Mojo runtime, callbacks, the 10k-connection epoll spike).

## Commands
Run everything through pixi (`~/.pixi/bin/pixi`). The Mojo toolchain is pinned in `pixi.toml`.

```bash
pixi run test                      # every tests/**/test_*.mojo, plus the ABI layout check
pixi run test net/                 # only files whose path contains "net/" (no ABI check)
pixi run ci                        # import-check + api-check + test + nolibc-check + examples-check: what CI must run
pixi run mojo run -I src tests/linux/test_sys.mojo                      # one file
pixi run mojo run -D MOJO_NET_FAULTS=1 -I src tests/net/test_tcp_faults.mojo   # one fault-seam file
pixi run mojo run -D MOJO_NET_SIM=1 -I src tests/rt/test_loop_contract.mojo     # one file on the rt simulator
pixi run import-check              # package import rules (tools/check_imports.py)
pixi run api-check                 # linux, bytes, net public API vs api/*.txt (tools/check_api.py)
pixi run api-update                # accept a deliberate API change (say why in the commit)
pixi run package                   # conda package (conda.recipe/), built and tested by rattler-build
pixi run examples-check            # build every examples/<pkg>/*.mojo
pixi run aarch64-check             # cross-compile every test and example for aarch64 (~12 min; not in ci)
pixi run abi-check                 # constants + struct layouts vs this host's C headers
pixi run nolibc-check              # no libc socket/poll/epoll symbols on the I/O path
pixi run gen                       # regenerate src/linux/{nr,consts,errno}.mojo from headers
pixi run spikes                    # re-run the M1 spikes
pixi run spike-tls                 # the TLS-through-OpenSSL spike (T0): fails if a recorded fact changed
pixi run tls-check                 # tls: FFI in one module, binding allowlist, forbidden names, symbol versions, constants
pixi run tls-asan                  # the tls tests under ASan + LeakSanitizer (in ci)
pixi run tls-freshness             # pixi.lock's openssl / ca-certificates vs conda-forge (daily workflow, not ci)
pixi run gen-tls                   # regenerate src/tls/consts.mojo from the OpenSSL headers
pixi run bench build               # rt benchmarks (bench/rt/README.md)
pixi run -e bench bench-server run  # HTTP server vs nginx, Go, hyper under wrk (bench/server/README.md)
```

**Stability and packaging** (`docs/design.md`):
- `linux`, `bytes` and `net` are stable: changes are additive, and `api-check` fails on any change to their public API until `api-update` records it. Rename or remove only after a replacement has shipped beside the old name, deprecated.
- `mojo-net` is one noarch conda package of sources (every library but `rt`) in `$PREFIX/lib/mojo/<pkg>/`, for `mojo-compiler >=1.2,<1.3`; its version is `pixi.toml`'s. `conda.recipe/test_package.mojo` runs in a fresh environment against the installed package. A new library goes into the recipe's list and that test.
- Not published yet. The user's goal (2026-10-26) is to open-source it under a permissive licence, with a warning that it is AI-generated and not fully reviewed, once the AI-stack milestones are done. Confirm with the user before making the repository public or publishing a package; the conda name `mojo-net` (importing `net`) collides with a published community package.
- GitHub CI (`.github/workflows/ci.yml`) runs `ci` and `package` on x86_64 and on a real aarch64 runner (`ubuntu-24.04-arm`).

**Test runner (`tools/run_tests.sh`):**
- Each test file ends with `def main() raises: TestSuite.discover_tests[__functions_in_module()]().run()`; `mojo test` no longer exists.
- A file fails if it runs 0 tests, because TestSuite exits 0 in that case.
- Files named `test_*_faults.mojo` (and only those) are built with `-D MOJO_NET_FAULTS=1`.
- Files named `test_*_contract.mojo` run twice: on epoll, then on the `rt` in-memory simulator (`-D MOJO_NET_SIM=1`). Files named `test_*_sim.mojo` run on the simulator only. Replay a simulator run with `MOJO_NET_SIM_SEED=<n>`.
- Each file has a timeout: `MOJO_NET_TEST_TIMEOUT`, default 600 s.
- `MOJO_NET_REQUIRE_IPV6=1` turns "no IPv6 loopback" skips into failures.

**Test-only Python:** some tests use the pixi env's Python as an oracle (`ipaddress`) or as a peer process. It is never used in `src/`.

**Test-only PostgreSQL:** `postgresql` from conda-forge, for `tests/pg/test_client.mojo`. Those tests skip without `initdb` or as root; `MOJO_NET_REQUIRE_PG=1` makes that an error.

**Test-only TLS peers:** `tests/tls/tls_pki.py` makes a throwaway PKI per process with the `openssl` command (a watcher removes it when the process ends); `tls_peer.py` is a server in Python's `ssl`, `s_server_peer.py` drives `openssl s_server`, and `tls_mitm.py` damages traffic by seed. They run as child processes, never in-process: an in-process `ssl` would load OpenSSL's config into the library `tls` uses (`test_hostile_config.mojo` does that on purpose). Peer output is read with a 30 s limit (`peer_io.py`); a long run passes `quiet=1`, since unread output fills the pipe and blocks the peer.

**Test-only Valkey:** `valkey-server` from conda-forge (BSD-licensed; it speaks Redis's protocol), for `tests/redis/test_client.mojo`. Those tests skip without it; `MOJO_NET_REQUIRE_REDIS=1` makes that an error.

## Layout and rules
- **Packages:** imports only point downward: `rt → net → bytes → linux`, `http → net → bytes → linux`, `tls → net`, and `pg` and `redis` on `net`, `bytes`, `linux` (`pg` also on `crypto`). `linux` and `crypto` import only `std`.
  - Nothing outside `rt` imports `rt`.
  - `http` is sans-I/O: in `src/http`, only `client.mojo` may import `net` (`SANS_IO` in `tools/check_imports.py`).
  - `server` (the HTTP server, roadmap step 3) builds on `http` and `net`.
  - `pixi run import-check` enforces these rules for `src/`, `tests/`, `examples/`, `bench/` and `spikes/`.
  - A new library gets an entry in `ALLOWED` in `tools/check_imports.py`.
  - Per-package directories:
    - `src/<pkg>`, `tests/<pkg>`, `examples/<pkg>`, `bench/<pkg>`;
    - `docs/<pkg>.md`.
  - `src/linux`: the syscall layer. `fs` reads small files and opens files beneath a directory (`open_beneath`: openat2 with RESOLVE_BENEATH; `stat_fd`: statx; `pread`). Processes and signals: `signal` (`SignalSet`, thread masks, `SignalFd`) and `process` (`Exec`; `spawn` with clone3, or clone(2) where seccomp refuses clone3, then execve, with an optional child `signal_mask`; `Child` held by a pidfd; `reap_others` for PID 1; affinity; `threads`; `all_threads_block`). `probe.cpu_quota` reads a cgroup v2 `cpu.max`.
  - `src/bytes`: `ByteBuffer`, the sans-I/O `Codec` trait (`bytes.codec`, contract 1), and `base64` (RFC 4648; strict decoding). A `ByteBuffer`'s readable bytes never pass `max_size()`, but its capacity may reach `2 * max_size()` when it is kept full at the cap while drained in small pieces (so compaction stays amortized); `writable()` is bounded by both.
  - `src/pg`: PostgreSQL, sans-I/O except `client.mojo` (`SANS_IO`). `message` (the protocol 3.0 wire format: builders that refuse NULs, backend bodies checked once on arrival, `ServerMessage`, `Column`, `BackendKey`), `auth` (`md5_password`, `ScramClient`), `connection` (`PgConnection`, the `Codec` for one session: authentication inside it, limited by `Startup.allow`; `query()` queues a simple Query, `execute()`/`prepare()`/`execute_prepared()` the extended protocol, each request whole or not at all and pipelined one cycle per Sync; `poll(ev)` refills a reused `PgEvent`; after a CopyFail in an extended cycle, the extra Sync waits in the line of cycles for the ReadyForQuery it may draw; before AuthenticationOk, libpq's message bounds). `message.Params` holds parameter values (text, binary, NULL) and their declared types; the builders write whole or nothing, and refuse messages longer than the server reads. `config` (`Config`, `Config.parse` for libpq-style URIs; `startup()` adds DateStyle=ISO, extra_float_digits=3 and bytea_output=hex, which the text readers rely on), `client` (`Client`: blocking, TCP or Unix socket, one deadline per call, checked before each receive; keepalive on; `query(sql, args...)` and `execute` bind `Writable` arguments as text parameters, `query_params` takes a `Params`, `simple_query` runs scripts; a statement cache prepares each SQL text (with its declared types) once and asks for binary results where `pg.types` reads them; a deadline cancels the query, at the session's peer address, and keeps the session unless the cancel went unconfirmed; `Rows` with typed accessors in either form; transactions and savepoints; `wait_notification`; `check()`, which reads an idle session's input without a round trip; `PgError` with the SQLSTATE, raised by everything in it; not re-exported from `pg`). `pool` (`Pool`: `acquire`/`release`, LIFO reuse of checked sessions). `types` (type OIDs; the binary forms used, those whose text the client writes exactly as the server would; text parsers for dates, timestamps, bytea). `tests/pg/pg_oracle.py` is the backend side in Python (messages, frontend parsing, MD5 and SCRAM with hashlib); `tests/pg/pg_util.mojo` drives a codec with its transcripts. `tests/pg/pg_cluster.py` (started by `pg_server.mojo`) makes a throwaway PostgreSQL per test, with a user per authentication method; stop it whatever happens (a watcher process also stops it once the test process has ended, so a crash leaks no cluster). The P7 review's regression tests are `tests/pg/test_pg_regressions.mojo` (codec, types, URIs) and `test_pg_regressions_client.mojo` (against the server).
  - `src/redis`: Redis, sans-I/O except `client.mojo` (`SANS_IO`). `resp` (`Value`: a reply as one flat tree in pre-order, nodes numbered from the root, with accessors that read across RESP2 and RESP3; `RespParser`: resumable, bulk bytes copied out as they arrive, `Limits` refused from the header alone, attributes dropped; `Args` and `write_command`: commands as arrays of bulk strings, whole or nothing), `connection` (`RespConnection`, the `Codec`: replies pair with commands in order, RESP3 pushes come apart, and SUBSCRIBE and the other commands that would break the pairing are refused; `poll(ev)` swaps the reply into a reused `RespEvent`). `config` (`Config`, `Config.parse` for `redis://` and `unix://` URIs), `client` (`Client`: blocking, TCP or Unix socket, one deadline per call, checked before each receive; `HELLO 3` with AUTH and SETNAME, RESP2's AUTH and CLIENT SETNAME for `protocol=2` or a server without HELLO, then SELECT; `command(args...)` and `command_args(Args)` return the reply's `Value`, and an error reply raises `RedisError` with its code; a passed deadline closes the connection, since Redis cannot cancel; pushes kept for `take_pushes`; `check()` without a round trip; `run(Pipeline)` sends a batch in one write (error replies are values in their place), `transaction(Pipeline)` wraps it in MULTI/EXEC (None when a WATCHed key changed, the queuing error raised on an abort); typed helpers for the common commands; not re-exported from `redis`). `tests/redis/resp_oracle.py` is the server side in Python (replies, rendering, random values, reading commands); `tests/redis/redis_util.mojo` drives a codec with its transcripts as a rule-5 driver. `tests/redis/valkey_server.py` (started by `redis_server.mojo`) makes a throwaway Valkey per test, with ACL users and a watcher; `flood_peer.py` floods pushes and never replies.
  - `src/tls`: TLS through OpenSSL, sans-I/O except `stream.mojo` (and `target.mojo`, which parses addresses with `net.addr`). `ffi` (`Library`: libssl.so.3 opened by absolute path beside the Mojo runtime, version 3.5+ checked, no config file, a private library context; typed function pointers; the only module that calls C; the fault seams `SEAM_*`), `consts` (generated by `tools/gen_tls_consts.py`), `error` (`TlsError`, `Category`), `target` (`Target`: a validated DNS name or IP), `config` (`ClientConfig`, `Trust`, `ClientContext`: every knob set and read back, the trust order, ALPN), `client` (`TlsClient`: memory BIOs, the write BIO is the transmit queue; the six-part gate before ESTABLISHED; failures latch and free the `SSL`; TRUNCATED for an end without close_notify; bounds), `stream` (`TlsStream`: blocking, over `TcpStream`, deadlines; not re-exported). Adding a binding means adding it to `BINDINGS` in `tools/check_tls.py`; any name in its `FORBIDDEN` list fails CI.
  - `src/crypto`: `sha256` (`Sha256`, `sha256`), `md5`, `hmac` (`HmacSha256`, `pbkdf2_hmac_sha256`) and `compare` (`equal_constant_time`). Scalar code for authentication (SCRAM, PostgreSQL's MD5), not bulk hashing; MD5 is broken as a hash. `tests/crypto` checks the RFC vectors and Python's hashlib/hmac.
  - `src/net`: sockets.
  - `src/server`: the HTTP server. `server` (`Server[H: Handler]`, `ServerConfig`, `Request`, `Response`; `step()` runs one loop turn, which is how tests drive it), `date` (`http_date`, `DateCache`) `process` (`Stop`: SIGTERM/SIGINT or a worker's lifeline, given to `Server.stop_on`; `run_workers`: a supervisor that runs the program as N workers on one port) `router` (`Router[A: Handler]`: a segment trie of route functions `def(mut A, Request, Params, mut Response)`; the app is the fallback and gets the hooks) and `static` (`StaticFiles`: openat2 beneath a directory, conditionals, ranges; large files stream, so the app passes `produce` and `stream_ended` on). Streaming goes through the defaulted `Handler` hooks: `stream_request`/`on_body` (and `body_cut` when such a body never completes) for request bodies; `res.stream()` plus `produce` for responses, paused by appending nothing and woken by id (`Request.id`, `Server.wake`, `take_wakes`), with `stream_ended` once each is over. A connection gets a slice per turn (64 KiB or 128 requests; then the `_again` list, like wakes), and the read and write timeouts need `min_rate` per window. `shutdown()` drains gracefully (`stopped()`, the `shutting_down` hook, `shutdown_timeout`), and a close with input left unread lingers (`ServerConnection.input_pending()`). Tests run the loop while a Python client process talks to it.
  - `src/http`: HTTP/1.1. `types` (versions, methods, status codes), `headers` (`Headers`: arena-backed, case-insensitive, ordered; validated adds; exact bytes plus a string view for obs-text), `parse` (`HeadParser`: incremental heads, strict requests, lenient responses, limits; `RequestHead` / `ResponseHead`; `for_trailers` for field sections), `body` (framing decisions, `BodyDecoder` returning ranges of the caller's input, chunk encoding), `connection` (`ServerConnection` / `ClientConnection`: the `Codec`s for one connection; the server answers one request at a time; `poll(ev)` refills a reused event, `next_event()` returns new ones), `client` (`Client`: blocking, pooled, one deadline per request; imports `net`, so not re-exported from `http`). `tests/http/http_peer.py` (started by `http_peer.mojo`) is Python's http.server with test routes. `tests/http/head_oracle.py` and `tests/http/chunked_oracle.py` are the Python references for differential fuzzing; keep them in step with any rule change.
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
  - `udp`: `UdpSocket` (blocking with deadlines, or `try_*`), `Datagram` (truncation via MSG_TRUNC: `size > len`), multicast (`join_multicast_v4`/`v6`; mind `IP_MULTICAST_ALL`), `DatagramBatch` (`recvmmsg`/`sendmmsg`).
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
  - `linux.signal` (`block`, `set_mask`, `SignalFd.new`) and `spawn`'s child mask never include glibc's signals 32 and 33, as glibc's sigprocmask strips them: blocking signal 33 hangs a `setuid` in another thread.
  - Signals are read from a `linux.signal.SignalFd`. That needs them blocked in every thread, and the runtime's threads start before `main` with the exec-time mask: blocking in `main` loses most SIGTERMs to the runtime's handler. `server.process` blocks them, then re-executes the program unless it was started with them blocked and `linux.process.all_threads_block` agrees. The exec-time mask decides: on GitHub's aarch64 runners the probe alone said every thread blocked them while one did not. Under `mojo run` that re-exec compiles the program again, so tests of it run a built binary (`tests/server/test_workers.mojo` builds `tests/server/workers_app.mojo`).
  - Between `clone3` and `execve` (`linux.process.spawn`), the child runs raw syscalls only, on memory laid out before the clone. Keep every heap value alive past the clone (`keep_alive` after it), so that no destructor runs in the child.
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
  - A `PythonObject` is destroyed after its last use too. A `subprocess.Popen` destroyed early runs its `__del__`, which reaps the child if it has ended; that made `tests/linux/test_process.mojo` fail with ECHILD under load. A test that needs the child to stay a zombie keeps the object alive (`_ = p.pid` at the end).
- **A raising `__init__` skips `__deinit__` if a field is assigned again later in it (Mojo 1.2.0).** If `__init__` raises after every field is set, `__deinit__` normally runs. But when some field is assigned again after the raising point (`self.n = 0` early, `self.n = x` later), `self` counts as not fully initialized there, and `__deinit__` is skipped. Fields with their own destructors are still destroyed one by one.
  - **Where it bit:** `tls.config._Context` held its `SSL_CTX` as an `Int` and set `anchors` twice, so a failed configuration leaked the context (LeakSanitizer, `pixi run tls-asan`).
  - **Rule:** a struct that frees a raw handle (an `Int`) in `__deinit__` must free it itself before raising in `__init__`, or build in locals and assign each field once at the end (`_Context`, `Library`, `TlsClient._fail`).
- **Field reassignment in a loop corrupts memory (Mojo 1.2.0 compiler bug).**
  - **Trigger:** a local struct with heap-owning fields (`String`, `List`, ...). After one field's last use, a loop reassigns another field. The heap is corrupted, and the crash comes later, inside the runtime's allocator.
  - **Not affected:** straight-line reassignment, and function arguments (`mut` / `ref`), because only locals get field-wise early destruction.
  - **Workaround:** keep the struct alive past the loop (`_ = x^` after it, or pass it whole to a function).
  - **Found** when a benchmark parsed into a local `ResponseHead` (last use of `headers`) and then reassigned `reason` in a loop.
  - **Repro**, which crashes on 1.2.0: `struct H(Movable)` with `var s: String` and `var l: List[UInt8]`; `var h = H(); h.l.append(1); for _ in range(1000): h.s = String("ab")`.
- **`Optional` of a large struct is slow (Mojo 1.2.0).**
  - **Cost:** `Optional` is a `Variant`. When its destructor is not inlined (a type used across modules), it takes the whole value by value and rebuilds it byte by byte: about 900 instructions for a 256-byte struct, roughly 100–260 ns per `Optional` destroyed, even an empty one. A nested `Optional` inside makes it worse.
  - **Where it bit:** `ServerConnection.next_event()` returned an `Optional` of a 256-byte event on every call, which cost ~2 µs per request.
  - **Workaround:** keep structs that travel in an `Optional` small: box big payloads in a one-element `List` (24 bytes; the same `Optional` then costs ~5 ns). In hot loops, prefer an API that fills a caller-owned value (`poll(mut ev)`) over returning `Optional`.
  - **Diagnosis:** look for `Variant::__deinit__` calls in `mojo build --emit asm` output.
- **Runtime indexes into a wide `SIMD` are slow (Mojo 1.2.0).** SHA-256 with its message schedule in a `SIMD[DType.uint32, 64]`, indexed in a runtime loop, ran at 29 MB/s. Unrolled with `comptime for` (constant indexes, the schedule in an `Array`), it runs at ~260 MB/s, because the values stay in registers (`src/crypto/sha256.mojo`).
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
- **FFI:** only `src/tls/ffi.mojo` may call C in `src/` (`pixi run tls-check`). Declare each `external_call` C symbol with exactly one signature (spike-only code).
  - The standard library declares `dlopen`, `dlsym` and `dlerror` itself (`std.sys._libc`), so declaring them again fails in any program that also uses Python ("existing function with conflicting signature"). Open libraries with `std.ffi.OwnedDLHandle` and turn `get_symbol` addresses into typed `def(...) thin abi("C") -> R` pointers (`docs/spikes.md`, "TLS through OpenSSL").
  - A buffer C writes into goes as a typed mutable pointer (`p.unsafe_origin_cast[MutAnyOrigin]()`), never as an `Int` address: passed as `Int`, the compiler read the buffer back as its zero fill. A span C only reads goes through `tls.ffi.in_buf` (`unsafe_mut_cast[True]()` on its pointer).
  - C objects (`SSL*`) travel as `Int` addresses: Mojo 1.2's pointers cannot be null.
  - Open a C library by absolute path: a bare `dlopen("libssl.so.3")` searches from its caller, and under AddressSanitizer (which intercepts `dlopen`) it loaded the host's OpenSSL instead of the environment's.
  - A C-callable fn pointer is spelled `def(OpaquePointer[MutAnyOrigin]) thin abi("C") -> OpaquePointer[MutAnyOrigin]`, and function-typed parameters are spelled `def(T) thin -> R`.
- **Stdlib traps:**
  - `String.splitlines()` also splits on `\t` (verified on 1.2.0rc2 and 1.2.0); use `split("\n")`. This matters for HTTP parsing.
  - `TestSuite.run()` rejects unknown argv, and its times are in milliseconds.
  - Memory copies are spelled `unsafe_memcpy` / `unsafe_memmove`.
  - In a string literal, `"\xff"` is the code point U+00FF (two UTF-8 bytes), not the byte 0xFF. Tests that need raw bytes build lists, or encode a literal as Latin-1 (`tests/http/test_parse.mojo::_b`).
- **Runtime threads:** every Mojo process starts 1 + (CPUs in its affinity mask) runtime threads before `main`. Because a process is always multi-threaded, each kernel fd-table doubling stalls the fd-creating syscall for 20–40 ms. Long-running servers must pre-grow the fd table with `linux.probe.pregrow_fd_table(listener)` (see `docs/spikes.md`).
- **`assert_equal`** needs identical types (`Int(buf[i])` vs `ord("x")`).
- **Float literals are folded exactly.** `0.1 + 0.2` is computed at compile time as an arbitrary-precision `FloatLiteral`, so it is exactly 0.3, not the Float64 sum 0.30000000000000004. To compare against a runtime float result, write `Float64(0.1) + Float64(0.2)`.
- **Spellings to use:** `def` only (no `fn`), `comptime` (no `alias`), `Self.T` for struct parameters, `std.` import prefix, `@inline(.always)`, and `Layout[T](count=n)` (not the nightly-only `length=`).
