# HTTP server benchmark

`run.py` compares mojo_net's `server` (`plaintext.mojo`) with Go (`net/http` and fasthttp), Rust (hyper) and nginx on TechEmpower's plaintext test: `GET /plaintext` answered with `200` and `Hello, World!`. The load comes from wrk. Every server is built and run in its fastest usual form (below), and everything needed to run it again is in this directory and `pixi.toml`.

## Reproduce
You need Linux on x86_64 (conda-forge has no wrk for aarch64), [pixi](https://pixi.sh), at least 8 hardware threads (or CPUs chosen by hand, below), and network access for the first build. pixi installs the toolchains, pinned by `pixi.lock`: Mojo, Go, Rust, nginx and wrk. Go modules and crates come from `go.sum` and `Cargo.lock`.

```bash
git clone https://github.com/advenn/mojo_net && cd mojo_net
pixi run -e bench bench-server build    # the servers, into bench/server/out/
pixi run -e bench bench-server check    # each answers one request, and 16 pipelined, on 1 and 4 CPUs
pixi run -e bench bench-server run      # 5 scenarios x 5 servers, 60 s each, one at a time: ~35 min
pixi run -e bench bench-server summary bench/server/out/<time>.json
pixi run -e bench bench-profile         # mojo and hyper under callgrind: instructions per request (~3 min)
```

- **Options for `run`:**
  - `--reps 2` runs everything again in the reverse order, which is how the results below were measured (~70 min);
  - `--scenarios 1cpu-pipelined,4cpu-keepalive` and `--servers mojo,hyper` pick a subset;
  - `--duration`, `--warmup` and `--cooldown` set the seconds (60, 5 and 15 by default);
  - `--quiet 1.0` (the default) waits before each run while the machine is busy with more than 1 CPU's worth of other work, for up to `--quiet-wait 1800` seconds. `--quiet 0` never waits.
- **CPUs.** By default the server gets whole cores from the top until it has 4 CPUs, and wrk gets all the other cores. The 1-CPU scenarios use the first of the server's CPUs, with its sibling idle. `--server-cpus 2,3,6,7 --wrk-cpus 0,1,4,5` sets them by hand (`lscpu -e` shows which CPUs share a core).
- **The results file:** a JSON file in `out/`, rewritten after every run. It holds every run's numbers, wrk's raw output, the CPUs, the versions, the server CPUs' clock, and what else the machine was doing before and during each run.
- **For steady numbers:**
  - close what you can and plug a laptop in;
  - the cool-down lets each run start from about the same temperature;
  - `cpupower frequency-set -g performance` (root) takes the governor out of it.
- **The profile** (`profile.py`) runs `plaintext_profile.mojo`, the same server without its signal setup: valgrind cannot load the program `Stop` re-executes. Both servers are built for x86-64-v3 for it, since valgrind has no AVX-512.
- **PGO profiles.** The Go servers are built with the profiles in `go/default.pgo` and `fasthttp/default.pgo`. `pixi run -e bench bench-server pgo` makes them again on your machine (10 s of each scenario).

## The servers and their settings
| Server | Source | Build | How it runs on n CPUs |
|---|---|---|---|
| mojo | `plaintext.mojo` | `mojo build` (`-O3` and the host CPU are its defaults) | n = 1: one process. n > 1: a supervisor and n worker processes, each pinned to one CPU, each with its own SO_REUSEPORT listener (`run_workers`) |
| go | `go/` (`net/http`) | `GOAMD64` at the host's level (v4 here), PGO | one process, `GOMAXPROCS=n`; one listener |
| fasthttp | `fasthttp/` | the same | n = 1: one process, `GOMAXPROCS=1`. n > 1: fasthttp's prefork, n processes with `GOMAXPROCS=1` each, each with its own SO_REUSEPORT listener (as TechEmpower's fasthttp entries run) |
| hyper | `hyper/` (hyper 1.x on tokio) | `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `-C target-cpu=native` (`.cargo/config.toml`) | n threads, each a tokio `current_thread` runtime with its own SO_REUSEPORT listener; `pipeline_flush` on |
| nginx | `NGINX_CONF` in `run.py` | conda-forge's | n workers pinned with `worker_cpu_affinity auto <mask>`, `reuseport`, access log off, `return 200` |

Every server sends `Content-Type`, `Content-Length`, `Date` and `Server` with the 13-byte body: 127 to 161 bytes a response (`check` prints them).

**Settings tried and left out.** Each was alternated with the chosen setting, 10 s runs on one CPU, 2 or 3 rounds:
- **Go's GC.** `GOGC=400`, and `GOGC=off` with `GOMEMLIMIT=1GiB`, made net/http 7% and 10% faster pipelined, but 5% and 2% slower with keep-alive. That is mixed, so the GC keeps Go's default.
- **PGO.** It did nothing measurable for net/http (under 1%) and gave fasthttp 4% to 12%. Both keep it: it is Go's own recommended practice.
- **mimalloc for hyper.** 8% faster pipelined, 7% slower with keep-alive, and glibc's best run beat mimalloc's. Inconclusive, so hyper keeps the system allocator.
- **Pinning hyper's threads**, one per CPU as mojo's workers are: within 1% on 4 CPUs.
- **mojo without bounds checks.** `-D ASSERT=none` turns off the standard library's index checks: 5% faster pipelined (1.32 to 1.25 µs a request), nothing measurable with keep-alive. They stay on, as Rust keeps its own.

## Method
- **Pinning.** The servers and wrk never share a core. On the machine below, CPUs n and n + 4 are the two hardware threads of one core:
  - wrk runs 4 threads on cores 0 and 1 (CPUs 0, 1, 4, 5);
  - a one-CPU server runs on CPU 2, with its sibling, CPU 6, left idle;
  - a four-CPU server runs on cores 2 and 3 (CPUs 2, 3, 6, 7).
- **Sequential runs.** One server runs at a time:
  1. it is started afresh;
  2. it is warmed up for 5 s with the same load;
  3. it is measured for 60 s;
  4. it is stopped, and the machine idles 15 s before the next run. If other work kept it busier than 1 CPU over that time, the next run waits for it.
  
  In each scenario the servers go in the order mojo, go, fasthttp, hyper, nginx; the second rep goes in the reverse order.
- **What is measured:**
  - requests per second and, without pipelining, latency percentiles, from `wrk --latency`; the mean latency in every scenario from Little's law (under Results);
  - the server's CPU per request: user plus system time of every process in its process group, from `/proc`, over the measured 60 s. On loopback this includes the kernel's TCP work for both directions of the server's sockets;
  - wrk's CPU, as a share of its 4 threads: near 100% the client, not the server, is the limit;
  - the server CPUs' clock, sampled each second (`scaling_cur_freq`), and the package temperature;
  - **others:** what the rest of the machine used during the run, in CPUs. It is all busy time (`/proc/stat`) less the server's and wrk's. A run with a high value shared the machine with something else.
- **Caveats:**
  - one laptop, with the client on the same machine, over loopback;
  - wrk is closed-loop: each connection sends its next request (or batch) only after the last answer, so its latencies leave out the queueing an open-loop client would see;
  - the machine was shared with a desktop session (`others` in each result says how much it used).

## Results
Measured on 2026-10-27, 13:30 to 14:37 (`out/20261027-133003.json`):
- **The machine:** an i5-1145G7 laptop (4 cores, 8 threads), Linux 6.12, the `powersave` governor (intel_pstate) with turbo on.
- **Versions:** Mojo 1.2.0, Go 1.27.3 with fasthttp 1.77.0, rustc 1.99.1 with hyper 1.12.0 on tokio 1.54.1, nginx 1.31.8 and wrk 4.2, all from pixi.
- **Conditions:** 2 reps of 60 s, the second in the reverse order. Other work on the machine (a desktop session) used 0.2 to 0.6 CPUs during the runs, and no run had to wait for a quiet machine.
- **Clock and temperature:** the server's CPUs ran at 3.4–3.8 GHz on one CPU and 2.7–3.0 GHz on four (the all-core turbo is lower), at a package temperature of 69–74 °C.

Requests per second are the mean of the two runs, followed by both runs. The mean latency comes from Little's law (below); in the pipelined rows it is per batch of 16. Server CPU is per request.

| Scenario | Server | req/s (both runs) | Mean latency | p50 | p99 | Server CPU | wrk CPU |
|---|---|---|---|---|---|---|---|
| **1 CPU, 64 keep-alive connections** | hyper | **181k** (179k, 184k) | 353 µs | 344 µs | 638 µs | 5.48 µs | 42% |
| | nginx | 175k (174k, 177k) | 365 µs | 363 µs | 522 µs | 5.68 µs | 38% |
| | fasthttp | 164k (161k, 167k) | 391 µs | 392 µs | 985 µs | 6.08 µs | 37% |
| | mojo | 156k (154k, 159k) | 409 µs | 396 µs | 694 µs | 6.36 µs | 34% |
| | go (net/http) | 86k (84k, 88k) | 746 µs | 757 µs | 1.84 ms | 11.60 µs | 17% |
| **1 CPU, 256 connections, 16 pipelined** | hyper | **1169k** (1123k, 1214k) | 3.51 ms | | | 0.85 µs | 24% |
| | fasthttp | 1067k (1052k, 1082k) | 3.84 ms | | | 0.93 µs | 24% |
| | mojo | 762k (754k, 770k) | 5.38 ms | | | 1.31 µs | 15% |
| | nginx | 191k (189k, 194k) | 21.42 ms | | | 5.20 µs | 28% |
| | go (net/http) | 102k (102k, 102k) | 40.24 ms | | | 9.78 µs | 11% |
| **1 CPU, 1024 keep-alive connections** | hyper | **144k** (141k, 148k) | 7.09 ms | 7.04 ms | 9.81 ms | 6.89 µs | 30% |
| | nginx | 141k (139k, 143k) | 7.25 ms | 7.20 ms | 9.78 ms | 7.04 µs | 28% |
| | mojo | 132k (128k, 135k) | 7.79 ms | 7.71 ms | 10.71 ms | 7.56 µs | 26% |
| | fasthttp | 124k (122k, 126k) | 8.26 ms | 8.18 ms | 11.15 ms | 8.03 µs | 28% |
| | go (net/http) | 70k (68k, 72k) | 14.61 ms | 14.14 ms | 23.82 ms | 14.18 µs | 16% |
| **4 CPUs, 256 keep-alive connections** | hyper | **350k** (344k, 356k) | 732 µs | 624 µs | 4.21 ms | 10.68 µs | 92% |
| | nginx | 327k (321k, 333k) | 782 µs | 698 µs | 4.02 ms | 11.72 µs | 89% |
| | fasthttp | 319k (315k, 323k) | 802 µs | 714 µs | 3.91 ms | 12.15 µs | 87% |
| | mojo | 301k (301k, 301k) | 851 µs | 748 µs | 4.48 ms | 12.79 µs | 83% |
| | go (net/http) | 155k (153k, 156k) | 1.66 ms | 1.59 ms | 6.89 ms | 24.89 µs | 44% |
| **4 CPUs, 256 connections, 16 pipelined** | hyper | **2115k** (2091k, 2139k) | 1.94 ms | | | 1.87 µs | 66% |
| | fasthttp | 1967k (1964k, 1971k) | 2.08 ms | | | 2.00 µs | 60% |
| | mojo | 1326k (1319k, 1332k) | 3.09 ms | | | 3.01 µs | 39% |
| | nginx | 410k (407k, 413k) | 9.99 ms | | | 9.71 µs | 62% |
| | go (net/http) | 182k (180k, 185k) | 22.46 ms | | | 21.14 µs | 29% |

What it shows:
- **Without pipelining, the top four are close:** hyper, nginx, fasthttp and mojo take 5.5 to 6.4 µs of CPU a request on one CPU, most of it the kernel's loopback TCP (one recv and one send a request). mojo is 14% behind hyper there (0.9 µs a request). With 1024 connections, mojo is ahead of fasthttp and 8% behind hyper.
- **Go's net/http takes about twice the CPU of the others without pipelining**, and gains little from it: 9.8 µs a request, 7 to 11 times what hyper, fasthttp and mojo take. It writes each response out on its own. Pipelined, it still makes 1.01 `write` calls a request, while its reads drop from 1.99 to 0.13 a request (counted from `/proc/<pid>/io`). fasthttp, in the same language, is in the top group.
- **Pipelined, hyper and fasthttp lead:** 0.85 and 0.93 µs a request, against mojo's 1.31. The gap is all in mojo's own code, most of it in how the HTTP codec handles header fields (below). nginx makes a system call per response, so it gains little.
- **The four-CPU keep-alive runs mostly measure wrk.** It used 83–92% of its 4 threads. The order there follows the CPU per request, but the totals are the client's limit.
- **The four CPUs are 2 cores' 4 hardware threads**, at a lower clock, so the CPU per request is about twice that on one CPU.

**Latency.** wrk is closed-loop: every connection always has exactly one request (or one batch of 16) in flight. By Little's law, the mean latency is then exactly connections × requests per write / requests per second. With keep-alive it is close to wrk's medians: within 4% on one CPU, and up to 17% above them on four CPUs, where the tail is longer (a long tail puts the mean above the median). Pipelined, wrk's percentiles are left out, because they are wrong there. Its coordinated-omission correction (`stats_correct`) adds samples spaced by the time between responses rather than batches. It can put them below the histogram's minimum, where the percentile scan never looks: one run printed a p99 of 0.

## Why mojo is slower
mojo's own code does twice the work of hyper's for each request; the kernel's share is the same. Measured on 2026-10-27:
- **The CPU split:** user and system time from `/proc`, one CPU, the best of 2 runs of 10 s.
- **The instructions:** valgrind's callgrind (`pixi run -e bench bench-profile`, `out/profile-20261027-150833.json`). It counts every user-space instruction by function and source line, for the server on one CPU: 16 connections, 16 pipelined, 342k requests for mojo and 415k for hyper.

| Per request, one CPU | mojo | hyper | fasthttp | nginx |
|---|---|---|---|---|
| keep-alive: user + system | 1.63 + 3.59 µs | 0.97 + 3.57 µs | 1.28 + 4.68 µs | 1.45 + 4.37 µs |
| pipelined: user + system | 0.99 + 0.33 µs | 0.52 + 0.33 µs | 0.56 + 0.35 µs | 1.31 + 3.75 µs |
| pipelined: user-space instructions | 9,644 | 4,565 | (not profiled) | (not profiled) |

**What it is not:**
- **Not the kernel.** mojo's system time per request is hyper's to the hundredth of a µs: the same system calls (one recv and one send a request with keep-alive).
- **Not the event loop.** `server.mojo`, the loop and the handler plumbing, is 7% of mojo's instructions (700 a request).
- **Not memory allocation.** mojo allocates nothing per request: no `malloc` or `free` in its profile. hyper spends 10% of its instructions in them (469 a request).

**Where it goes.** `src/http` takes 5,385 instructions a request, more than all of hyper's work for one (4,565):

| mojo, instructions a request (pipelined) | |
|---|---|
| `http/connection.mojo`: queueing the response, and the checks on both heads | 2,162 |
| `http/headers.mojo`: storing, checking, finding and encoding header fields | 2,019 |
| `http/parse.mojo`: parsing the request head | 1,104 |
| `server/server.mojo`: the loop, `Request` and `Response`, the server's own fields | 699 |
| the standard library: small copies (`memory.mojo`, 647), bounds checks (470), `String` (444), `range` loops (383) and the rest | 2,909 |
| `bytes/buffer.mojo`: the input and output buffers | 609 |
| the rest: `http/body.mojo`, `http/types.mojo`, `linux`, `net` | 142 |

The likely reasons, from the functions and lines that cost the most:
1. **Each head is walked several times.**
   - **The request:** `_find_end` finds the blank line (397 instructions). `_parse_fields` splits the fields and checks every byte (598). `_summarize` reads them again for the framing: Connection, Content-Length, Transfer-Encoding. `_valid_host` parses the Host field (593).
   - **The response:** the handler's `res.text()` adds Content-Type through `Headers.set`. That searches the existing fields without regard to case, then checks every byte of the new one (`set`, `_checked` and `_store`: 1,523 together). The server scans the fields for Date, Server and framing. The codec's `send_response` summarizes them again and parses Content-Length (`_summarize`, 684 for both heads). Then `Headers.encode` and `_status_line_bytes` copy them out (1,147).
   - **Why:** these are `http`'s strictness rules (docs/http.md). Every field is checked where it is parsed or set, and framing is decided from all the fields; this is what keeps request smuggling out. Each layer also checks again what the layer above hands it, rather than trusting it.
   - **hyper:** httparse, its head parser, takes about 270 instructions, and hyper does not parse the Host field. Its standard header names (`CONTENT_TYPE`) are constants, never checked at run time.
2. **The checks go one byte at a time.** The hottest lines in `headers.mojo` are scalar loops: the token check for names (`is_tchar`), the field-byte check for values (`is_field_byte`), and case-folding comparisons (`lower_ascii`). httparse checks bytes with SIMD (SSE4.2 or AVX2). mojo's `_find_end` already uses SIMD, but the field checks do not.
3. **Bounds checks.** Mojo's standard library checks every `Span` and `List` index at run time: 470 instructions a request, 4.9%. Rust checks too, but its iterators skip most checks. Turning them off is worth 5% pipelined (Settings tried, above).
4. **Small copies and loops through the standard library.** `memory.mojo` (copies of a few bytes, 647), `range` loops (383) and `String` building (444) are 15% of the total.

**Leads, not yet tried:**
- Write the server's fields and constant fields straight into the output. Date and Server are already pushed without checks; Content-Type is not.
- Summarize the framing fields while parsing, in the same pass.
- Check field bytes with SIMD, as `_find_end` finds the end of the head.
- Remember a connection's Host field once it has been checked.

The profile is pipelined. With keep-alive, the same code runs once per request, plus one recv and one send: 1.63 µs of user time, against hyper's 0.97.

## Earlier runs
`out/20261025-182428.json` and `out/20261026-182035.json` were 10 s runs (3 reps in a rotating order) of mojo, nginx, Go's net/http and hyper. They were built with Go 1.26.2 and rustc 1.96.1 from the host, without PGO, `target-cpu=native` or `panic = "abort"`, and run on a busier machine. Without fasthttp, the order was the same as above: mojo, nginx and hyper level with keep-alive, hyper ahead pipelined, and net/http at about half. On 2026-10-25, one CPU, 64 keep-alive connections: mojo 152k req/s, nginx 142k, hyper 163k, Go 75k. Pipelined: hyper 918k, mojo 614k.

**Where mojo's time goes** (2026-10-25), against hyper and nginx on one CPU (the best of 2 runs of 8 s; system calls counted with strace on a separate run):

| | User + system per request (keep-alive) | Pipelined | System calls per request (keep-alive; pipelined) |
|---|---|---|---|
| mojo | 1.98 + 5.30 µs | 1.12 + 0.44 µs | 2.04 (recv 1.03, send 1.00); 0.16 (recv 0.10, send 0.06) |
| hyper | 1.25 + 4.94 µs | 0.70 + 0.35 µs | 2.02; 0.13 (recv 0.06, send 0.06) |
| nginx | 1.67 + 5.08 µs | 1.57 + 4.83 µs | 2.02; 1.08 (`writev` 1.01) |

- **The kernel dominates keep-alive:** about 5 µs of loopback TCP a request (a recv and a send), the same for all three.
- **The gap to hyper is user time:** 0.4 µs a request pipelined, 0.7 µs without. That is about what docs/server.md (S5) measured `server` adding over the bare codec (`Request` and `Response`, header scans, the hooks). The profile above (2026-10-27) places most of it in the codec's handling of header fields instead, called from both layers.
- **mojo rarely waits:** 60 `epoll_pwait2` calls for 113k requests, since it reads a connection again after answering it. Pipelined, that costs a little: 37% of its receives find nothing yet (0.6 a batch, where hyper reads once), about 0.03 µs a request.
- **S7 (HTTPS) costs plain HTTP nothing measurable** (2026-10-26). An A/B of the server built from the commit before S7 and from S7 was alternated 8 times on the pipelined scenario: 1.88 µs a request at best before, 1.82 with S7. HTTPS itself is not benchmarked yet.
