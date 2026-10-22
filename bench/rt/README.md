# bench: the M2 performance gate and the HTTP hello comparison

> **Historical record** of the M2 gate (2026-10-22). Since then the rt-opt changes
> described below have landed in `src/rt` and `bench/rt/rt_opt/` was removed, so
> the `-opt` variants no longer build.
> `rt` is frozen (`docs/rt.md`).

Everything here measures servers built on `rt` + `rt.evented` against tokio
`current_thread` and the M1 spike's raw-epoll Mojo server, with the method
of `docs/spikes.md` ("10k-connection epoll spike").

## Files

| file | what |
|---|---|
| `rt_echo_server.mojo` | echo on `rt.evented` (`TcpServer` + `ConnHandler`, copies into the staged output; `--swap` sends the receive buffer itself) |
| `rt_raw_echo_server.mojo` | echo on the raw `rt` API (no `rt.evented`, no per-connection state) |
| `http_hello.mojo` | HTTP/1.1 keep-alive "Hello, World!" on `rt.evented` (readable twin: `examples/rt/http_hello.mojo`) |
| `rust_http/` | the same HTTP program on tokio `current_thread`, raw `TcpStream`, same parsing |
| `bench_common.mojo` | `CountingDriver` (EpollDriver + a counter per syscall), `BenchLoop[D]` (rt's `EventLoop` run loop over any driver), the `STATS` ticker |
| `rt_microbench.mojo` | the loop's user-space cost per message with the kernel taken out (`NullDriver`, no syscalls) |
| `rt_opt/apply.py` | builds **rt-opt**: a copy of `src/` with the rt changes proposed below (src/rt is not modified) |
| `bench.py` | echo gate harness (imports and reuses `spikes/epoll_echo/bench.py`'s `run_one`) |
| `http_bench.py`, `pipeline.lua` | HTTP harness (wrk) and wrk's pipelining script |
| `run.sh` | build everything into `bench/rt/out/`, run a step |

## Reproduce

```bash
pixi run bash bench/rt/run.sh build                       # Mojo (mojo build), Rust (cargo --release --offline)
python3 bench/rt/bench.py gate --reps 3 --servers rt,rt-opt,rt-raw,rt-raw-opt,mojo,tokio   # ~14 min
python3 bench/rt/bench.py gate --reps 5 --servers rt,rt-opt,tokio,mojo                     # ~15 min
python3 bench/rt/bench.py report bench/rt/out/gate-*.json    # tables below, from the saved runs
python3 bench/rt/bench.py one --server rt --size 64        # one run, full JSON
taskset -c 2 bench/rt/out/rt_microbench --conns 1000       # loop cost without the kernel
taskset -c 2 bench/rt/out/rt_microbench_opt --conns 1000
python3 bench/rt/http_bench.py check                       # HTTP protocol checks (keep-alive, pipelining, split head, close, 431)
python3 bench/rt/http_bench.py run --reps 3                # wrk via `pixi exec --spec wrk`
```

Server names in the tables: **rt** = `rt.evented` echo on today's rt;
**rt-raw** = raw rt API; **-opt** = the same on rt-opt; **mojo** = the M1
spike server (raw epoll, no completion layer); **tokio** = the spike's tokio
`current_thread` echo (task per connection, 4 KiB buffer, `read` +
`write_all`). All except tokio count their syscalls themselves.

## Machine and method

- Intel i5-1145G7 (4 cores / 8 threads; SMT siblings are CPU n and n+4),
  Linux 6.12.111 (Debian 13), Mojo 1.2.0rc2, rustc 1.96.1 + tokio 1.52.3
  (`--release`, LTO), wrk 4.2.0 (conda-forge). `nf_conntrack` is loaded.
- Echo: server pinned to CPU 2 (`taskset`, so the Mojo runtime starts 2
  threads), 3 client processes (`spikes/epoll_echo/client.mojo`) on CPUs 3,
  1, 0; 10,000 idle + 1,000 active connections, ping-pong of one message per
  connection, 10 s, measured over seconds 1-9. Server CPU ns/msg =
  (utime + stime) over the window / messages echoed in it. Runs are
  interleaved (server order rotates every repetition).
- **Noise.** The host was shared with other agents compiling Mojo the whole
  time. CPU 6, the server core's SMT sibling, was 9-99% busy during runs,
  and the per-message cost of *every* server moves with it (the spike's own
  server measured 5.1 us/msg in M1 on a quiet sibling and 8.4-10.9 us here).
  So the tables give medians with ranges, the user/kernel split (user time
  is what the server's code costs; kernel time is the same TCP work for all
  servers and absorbs most of the sibling noise), and a least-squares fit
  of each server's cost against the recorded sibling load.

## Echo results: the M2 gate

**Verdict: FAIL for rt as it is today; PASS with the three rt changes
proposed below, at an idle SMT sibling, but not under the 40-99% sibling
load these runs had.** The gate is rt-based server CPU ns/msg <= 1.25 x
tokio `current_thread`'s.

### Run 2 (`gate-20261022-124228.json`): 5 interleaved repetitions

| server | size B | server CPU ns/msg median (min-max) | msgs/s median | p50 / p99 us | syscalls/msg | user ns/msg median | kernel ns/msg median | RSS B/conn | CPU 6 busy % |
|---|---|---|---|---|---|---|---|---|---|
| rt | 64 | 12,673 (11,255-15,463) | 78,374 | 12,452 / 18,350 | 2.00 | 3,499 | 9,229 | 1,413 | 41-91 |
| rt-opt | 64 | 11,332 (9,775-12,074) | 87,871 | 11,141 / 16,253 | 2.00 | 2,194 | 9,227 | 1,176 | 41-68 |
| mojo (spike) | 64 | 8,596 (8,353-10,322) | 115,330 | 8,520 / 12,845 | 2.00 | 288 | 8,359 | 48 | 61-97 |
| tokio | 64 | 8,812 (7,577-10,853) | 112,806 | 8,651 / 12,976 | n/a | 787 | 8,068 | 4,870 | 37-99 |
| rt | 1024 | 13,026 (12,792-13,549) | 76,294 | 12,976 / 18,350 | 2.00 | 3,392 | 9,770 | 1,530 | 52-63 |
| rt-opt | 1024 | 11,843 (11,448-14,008) | 83,963 | 11,665 / 17,302 | 2.00 | 2,203 | 9,587 | 1,429 | 60-93 |
| mojo (spike) | 1024 | 8,835 (8,441-10,467) | 111,099 | 8,913 / 14,025 | 2.00 | 308 | 8,522 | 39 | 57-94 |
| tokio | 1024 | 9,047 (8,904-11,136) | 110,007 | 9,044 / 13,500 | n/a | 773 | 8,274 | 4,858 | 56-92 |

Gate ratios (median rt ns/msg / median tokio ns/msg; range = per repetition):

| | 64 B | 1 KiB |
|---|---|---|
| rt / tokio | **1.44** (1.43-1.49) FAIL | **1.44** (1.18-1.48) FAIL |
| rt-opt / tokio | **1.29** (1.11-1.30) FAIL | **1.31** (1.26-1.31) FAIL |

### Run 1 (`gate-20261022-122429.json`): 3 repetitions, all six servers

| server | size B | server CPU ns/msg median (min-max) | user ns/msg median | RSS B/conn |
|---|---|---|---|---|
| rt | 64 | 12,484 (10,957-13,895) | 3,392 | 1,603 |
| rt-opt | 64 | 11,360 (7,216-11,738) | 2,240 | 1,365 |
| rt-raw | 64 | 10,797 (7,640-14,886) | 2,401 | 1,122 |
| rt-raw-opt | 64 | 9,652 (7,650-10,262) | 1,196 | 889 |
| mojo (spike) | 64 | 8,751 (8,438-10,302) | 325 | 127 |
| tokio | 64 | 8,700 (7,583-9,186) | 817 | 4,869 |

(1 KiB in the JSON: same order; `python3 bench/rt/bench.py report <json>`.)

### Corrected for sibling load (both runs, least-squares fit)

Every server's ns/msg rises linearly with CPU 6's load (fit residuals
90-470 ns over 8 runs). The intercept estimates an idle sibling and
reproduces M1's quiet-host numbers (spike 5.3 us, tokio 5.9 us, against
4.9-5.8 us in `docs/spikes.md`), so it is a fair comparison:

| server | size B | ns/msg at idle sibling | + per 100% sibling load | user ns/msg at idle | ratio to tokio |
|---|---|---|---|---|---|
| rt | 64 | 7,787 | 8,417 | 2,005 | **1.31 FAIL** |
| rt-opt | 64 | 6,637 | 7,836 | 1,226 | **1.12 PASS** |
| mojo (spike) | 64 | 5,315 | 5,126 | 65 | 0.90 |
| tokio | 64 | 5,926 | 4,685 | 626 | 1.00 |
| rt | 1024 | 7,576 | 9,360 | 1,284 | **1.33 FAIL** |
| rt-opt | 1024 | 6,745 | 8,207 | 1,085 | **1.19 PASS** |
| mojo (spike) | 1024 | 5,219 | 5,595 | 279 | 0.92 |
| tokio | 1024 | 5,678 | 5,916 | 511 | 1.00 |

(rt-raw and rt-raw-opt had 3 runs each; their fits are in the report.)
The rt servers also degrade faster with sibling load than tokio (about 8k vs
5k ns per 100%): SMT contention slows instruction-heavy code most, so
cutting user-space work matters twice.

### Reading
- **Syscall budget kept.** Every rt server makes exactly 2.00 syscalls per
  message at saturation (1 recv, 1 send, one `epoll_pwait` per ~950-1000
  events, no EAGAIN probes, no `epoll_ctl`, 1-2 clock reads per loop turn),
  the same as the spike. So the gap is CPU time, not syscalls.
- **User time is the gap.** At 64 B, user CPU per message is 288-325 ns for
  the spike, 0.79 us for tokio, 2.4 us for rt-raw and 3.4-3.5 us for rt
  (`rt.evented`). Kernel time is the same TCP work for all of them (8-9 us
  here, ~5.3 us at an idle sibling), except that the `rt.evented` servers
  spend 0.6-0.7 us more kernel time than the raw-API ones with the same
  syscalls (run 1): most likely the larger user-space working set evicting
  the kernel's socket data (not measurable here without perf).
- **Memory:** 1.1-1.6 KB per connection for rt servers (rt-opt: 0.9-1.4 KB),
  against 4.9 KB for tokio and 39-127 B for the spike (which has no op
  records). Kernel socket memory (~3.6 KB per socket, M1) dominates all of
  them.
- **Latency** under this load is queueing (1000 messages in flight):
  p50 = 1000 / msgs/s, so it tracks throughput.

## Where the time goes (no profiler: bench/rt/rt_microbench.mojo)

This host has no perf (and `perf_event_paranoid` is 3). `rt_microbench`
runs the loop on a `NullDriver` whose sockets and clients are fake (an edge
per message, a short read, a full send, ~1000 events per wait, like the
saturated echo) and times thread CPU, so it measures the loop's own work
without a syscall. Minimum of repetitions, 1000 connections, ns/msg:

| loop | raw rt API | rt.evented |
|---|---|---|
| rt today | 940-1,040 | 1,150-1,240 |
| rt-opt | 320-400 | 460-525 |

Per-phase timing on the rt snapshot of 11:58 (before rt-opt) showed
flush ~290 ns/msg, callbacks ~195, readiness processing ~195, driver ~5.
Each of those does only a few slab lookups per op, so the slab was the
suspect. Experiments one at a time (A/B alternated, min/median of 5 rounds):

| change | ns/msg (null driver, raw) | kept |
|---|---|---|
| baseline | 715 / 854 | |
| `Op.addr` out of line (Op 248 -> ~136 B) | 535 / 615 (-25%) | yes |
| `FdEntry.peer/local` out of line (352 -> ~104 B) | no CPU change | yes (-270 B RSS/conn) |
| `Deque` ready queue instead of `take_ready` + reverse | +10% | no |
| double-buffered `List[Optional[Completion]]` dispatch | +30% (Optional.take is costly) | no |
| keep the flush id list's capacity | 0% | no |
| slab on raw chunk memory instead of `List[List[Optional[T]]]` | 545 -> 272 (-50%): flush 230->105, callbacks 159->108, readiness 156->56 | yes |

Under a simulated kernel cache footprint (`--thrash 4096`: each fake
syscall dirties 4 KiB of a 32 MiB array) `rt.evented` costs 0.15-0.3 us
more than the raw API; in the real benchmark the difference is about 1 us
of user plus 0.7 us of kernel time.

## Proposed rt changes (not made: src/rt belongs to the rt owner)

All three are applied by `bench/rt/rt_opt/apply.py` (`rt-opt` above); the
public API does not change.

1. **`src/rt/slab.mojo`: store values in raw chunks.** Allocate each chunk
   with `alloc(Layout[T](count=SLAB_CHUNK))^.unsafe_leak()`, keep a
   `List[Bool]` occupancy flag per slot, `insert` with `unsafe_write`,
   `remove` with `unsafe_take_pointee`, read gens/flags with
   `unsafe_get`/`unsafe_set`, and add a `__deinit__` that destroys live
   values and frees the chunks. Same signatures
   (`insert(var T) -> SlabId`, `contains`, `__getitem__`, `remove(id) -> T`,
   `ids`, `__len__`); `__getitem__` returns `ref[MutUntrackedOrigin] T`
   (the current `ref[self]` needs a mutable origin cast). Reference
   implementation: `bench/rt/rt_opt/slab_raw.mojo.txt`. Effect: loop cost -50%.
2. **`src/rt/core.mojo` `Op.addr`:** `Optional[RawSockaddr]` (136 B inline in
   every op, used only by listen/connect) becomes `List[RawSockaddr]` or a
   side table. Effect: -25%.
3. **`src/rt/core.mojo` `FdEntry.peer/local`:** one out-of-line
   `List[RawSockaddr]`. Effect: -270 B per connection.
4. **`src/rt/event_loop.mojo`: driver as a parameter:**
   `struct EventLoop[D: Driver & Deinitable = Backend](Movable)`. Benchmarks
   and tests could then wrap a driver (counting, fault injection) instead of
   copying `run_once`, as `bench_common.BenchLoop` does now (kept in sync by
   hand).
5. Not measured, worth trying next: `Completion.buf` as a plain
   `ByteBuffer` (empty = none) instead of `Optional[ByteBuffer]`. Every
   recv/send completion constructs and takes that Optional, and Optional
   moves were the expensive part above. This changes the public API
   (`c.buf.take()`), so it is the rt owner's call.

## HTTP hello (`http-20261022-124849.json`)

wrk 4.2.0, 3 threads on CPUs 0, 1, 3, 256 connections, 10 s, 3 interleaved
repetitions; server on CPU 2. Both servers pass `http_bench.py check`
(keep-alive, 50 pipelined requests, a head split across writes,
`Connection: close`, 431 for a 9 KB head).

| server | scenario | req/s median (min-max) | p50 / p90 / p99 us | server CPU ns/req | RSS |
|---|---|---|---|---|---|
| Mojo, rt.evented on rt | keep-alive | 136,037 (134,907-136,458) | 1,730 / 2,440 / 3,240 | 7,218 | 22 MB |
| Mojo, rt.evented on rt-opt | keep-alive | 153,362 (149,206-158,186) | 1,490 / 2,280 / 2,950 | 6,421 | 22 MB |
| Rust, tokio current_thread | keep-alive | 169,190 (166,858-169,308) | 1,390 / 1,960 / 2,690 | 5,819 | 4.5 MB |
| Mojo, rt.evented on rt | pipelined x16 | 1,583,033 (1,573,725-1,594,099) | 1,500 / 2,930 / n/a | 622 | 22 MB |
| Mojo, rt.evented on rt-opt | pipelined x16 | 1,757,594 (1,745,230-1,778,159) | 1,320 / 2,580 / n/a | 560 | 22 MB |
| Rust, tokio current_thread | pipelined x16 | 2,065,760 (2,046,259-2,079,151) | 1,120 / 2,120 / 2,990 | 476 | 4.5 MB |

Keep-alive: Mojo on rt reaches 80% of the Rust server's requests/s (rt-opt
91%); per request it costs 1.24x (rt-opt 1.10x) Rust's server CPU. wrk
prints 0 for the pipelined p99 (it records latency per batch), hence n/a.
Pipelined, the per-request cost is mostly parsing and the response copy:
the Mojo responder (scalar byte loops over `Span`s for the
`Connection: close` scan) is not tuned. The Mojo RSS is mostly the runtime
(~10 MB at 0 connections, see M1).

## Caveats
- Shared, noisy host (see Machine and method). Absolute numbers move with
  the sibling load, and only the interleaved ratios and the fit are
  comparable.
- tokio has no syscall counters; its syscalls/msg are not shown.
- `BenchLoop` copies `EventLoop.run_once` as of 2026-10-22 12:00. If rt
  changes its run loop, compare with the `rt-stock` server (built with
  `-D BENCH_STOCK_LOOP=1`: rt's own `EventLoop`, syscall counters print 0).
  `rt-stock` was built but is not in the tables above: on this host, single
  runs cannot resolve the few nanoseconds the counters cost.
