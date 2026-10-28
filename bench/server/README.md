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
pixi run -e bench bench-profile --analyze bench/server/out/callgrind.mojo.<time>.1 --requests <n>   # its report again
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
Everything below is what `run.py` does; nothing is done by hand between runs.

### The test
TechEmpower's plaintext test: `GET /plaintext` answered with `200 OK` and the 13 bytes `Hello, World!`, as `text/plain`, with `Content-Length`, `Date` and `Server`. Any other path is a 404. Each server's handler is the smallest idiomatic one for it:
- **mojo** (`plaintext.mojo`): a `Handler` whose `handle` compares `req.path()` and calls `res.text(200, "Hello, World!")`; the server adds Date, Server (`mojo-net`) and Content-Length. 148 bytes a response.
- **go** (`go/main.go`): `net/http` with a `ServeMux` route that sets Content-Type and Server and writes the body. 127 bytes.
- **fasthttp** (`fasthttp/main.go`): a request handler that sets the same fields. 133 bytes.
- **hyper** (`hyper/src/main.rs`): `http1::Builder` with `pipeline_flush(true)` and a `service_fn` building the response with `Full<Bytes>` from a static body. 130 bytes.
- **nginx**: `location = /plaintext { return 200 "Hello, World!"; }`, access log off, keep-alive unbounded (`keepalive_requests 100000000`, `keepalive_timeout 600s`). 161 bytes.

`run.py check` starts each server on 1 and on 4 CPUs, sends one request, then 16 pipelined in one write, and checks that every answer is `HTTP/1.1 200` with the body; it prints each head and its size.

### The scenarios
| Scenario | Server CPUs | Connections | Requests a write | wrk threads |
|---|---|---|---|---|
| `1cpu-keepalive` | 1 | 64 | 1 | 4 |
| `1cpu-pipelined` | 1 | 256 | 16 | 4 |
| `1cpu-1024conns` | 1 | 1024 | 1 | 4 |
| `4cpu-keepalive` | 4 | 256 | 1 | 4 |
| `4cpu-pipelined` | 4 | 256 | 16 | 4 |

Every connection is HTTP/1.1 keep-alive for the whole run. wrk runs as
```bash
taskset -c <wrk CPUs> wrk -t4 -c<connections> -d60s --timeout 10s --latency http://127.0.0.1:<port>/plaintext
```
and for the pipelined scenarios with `-s pipeline.lua ... -- 16`: the script concatenates 16 `GET /plaintext` requests into one buffer, sent in one write, and wrk counts the 16 responses. wrk is closed-loop: a connection sends its next request (or batch) only once the last one is answered, so the number of requests in flight is fixed at connections × requests a write.

### CPUs and pinning
The server and wrk never share a core, so neither steals the other's cycles, caches or hyperthread sibling. `run.py` reads the topology from `/sys/devices/system/cpu/cpu*/topology` (package and core ids) and, by default, gives the server whole cores from the top until it has 4 CPUs and wrk every CPU of the other cores. On the i5-1145G7, CPUs n and n + 4 are one core's two hardware threads, so:
- wrk: 4 threads on cores 0 and 1 (CPUs 0, 1, 4, 5);
- a one-CPU server: CPU 2, with its sibling, CPU 6, left idle (it is one of the server's four, and nothing else runs there);
- a four-CPU server: cores 2 and 3 (CPUs 2, 3, 6, 7): 2 cores' 4 hardware threads, at the lower all-core clock.

Both are started under `taskset -c`. How each server uses its n CPUs is in the table above: mojo runs one process for n = 1, and for n > 1 a supervisor with n worker processes (`run_workers`), each pinned to one CPU with its own SO_REUSEPORT listener; nginx gets an explicit `worker_cpu_affinity` mask (with only `auto`, it would pin workers to CPUs 0, 1, ..., which are wrk's).

### One run
Runs are sequential: one server at a time, nothing else of ours running.
1. **Cool-down and a quiet check.** The machine idles for 15 s (`--cooldown`; 3 s before the first run), and the busy time of every CPU (`/proc/stat`: all but idle and iowait) is measured over it. If other work used more than 1 CPU (`--quiet`), the run waits 5 s at a time until it drops, for up to 30 minutes (`--quiet-wait`); the time waited is recorded. In the runs below no run had to wait.
2. **Start.** The server starts afresh, in a process group of its own, on a free port. `run.py` waits for its `LISTEN` lines (one per worker), then until a TCP connect succeeds.
3. **Warm-up.** wrk runs the scenario's load for 5 s (`--warmup`): caches, page faults, Go's and Rust's lazy setup and the CPU clock settle. Its numbers are thrown away.
4. **Measurement.** wrk runs the same load for 60 s (`--duration`). Around it, `run.py` reads the server group's CPU time and the machine's busy time before and after, and a sampler thread reads the server CPUs' clock (`scaling_cur_freq`) and the package temperature (`x86_pkg_temp`) every second.
5. **Stop.** SIGTERM to the server's process group; SIGKILL to the group after 10 s if needed, and to anything left in it.

Each scenario runs every server in the order mojo, go, fasthttp, hyper, nginx. With `--reps 2` the whole set runs again in the reverse order, so a drift over the hour (temperature, background work) does not always favour the same server. The results are the mean of the two reps, with both shown.

### What is computed
- **Requests per second, and latency percentiles** (p50, p99; keep-alive scenarios only): wrk's own output. Socket errors and non-2xx answers are recorded too (none in the runs below).
- **Mean latency, by Little's law:** requests in flight / throughput = connections × requests a write / req/s. wrk's coordinated-omission correction makes its pipelined percentiles meaningless (see Latency, below), so only this mean is given for those rows.
- **Server CPU per request:** the user + system time (`utime` + `stime` in `/proc/<pid>/stat`) of every process whose process group is the server's, over the measured 60 s, divided by the requests wrk counted. On loopback this includes the kernel's TCP work for the server's sockets in both directions, so it is the server's whole cost, not only its own code.
- **wrk CPU:** wrk's user + system time (`getrusage(RUSAGE_CHILDREN)` around it), as a share of its 4 threads × 60 s. Near 100%, the client is the limit, not the server: the four-CPU keep-alive rows are like that.
- **Others:** what the rest of the machine used during the run, in CPUs: all busy time less the server's and wrk's. A high value means the run shared the machine with other work.
- **Clock and temperature:** the mean, minimum and maximum of the per-second samples.

All of it, with wrk's raw output, the CPUs used, the load average, and the versions (CPU model, kernel, governor, Mojo, Go and `GOAMD64`, fasthttp, rustc, hyper and tokio from `Cargo.lock`, nginx, wrk), goes to `out/<time>.json`, rewritten after every run. `run.py summary out/<time>.json` prints the table.

### The profile
Time says how fast; `profile.py` says where the time goes. It runs mojo (`plaintext_profile.mojo`, the same server without signal setup, which valgrind cannot follow through a re-execution) and hyper under valgrind's callgrind, both built for x86-64-v3 (valgrind has no AVX-512) with line tables, on one CPU: 3 s of wrk to warm up, its counters zeroed, 10 s of 16 connections × 16 pipelined, then a dump. Instructions counted divided by requests answered gives instructions a request, by object, file, function and line. They count user space only: the kernel's share is the same for every server (Why mojo was slower, below). Instructions are not time (hyper's may retire faster), which is why both are reported.

### Caveats
- One laptop, with the client on the same machine, over loopback: no network, NIC or interrupt costs, and the kernel's loopback TCP is a large share of every request.
- wrk is closed-loop, so its latencies leave out the queueing an open-loop client (many independent users) would see.
- The machine was shared with a desktop session (`others` in each result says how much it used), and runs on a laptop's `powersave` governor with turbo: the clock moves with temperature and load (recorded per run).
- Each server runs in its fastest usual form, not tuned beyond that (Settings tried and left out, above).

## Results
Measured on 2026-10-28, 10:57 to 12:04 (`out/20261028-105727.json`), after the http and server reviews (HR3, SR2):
- **The machine:** an i5-1145G7 laptop (4 cores, 8 threads), Linux 6.12, the `powersave` governor (intel_pstate) with turbo on.
- **Versions:** Mojo 1.2.0, Go 1.27.3 with fasthttp 1.77.0, rustc 1.99.1 with hyper 1.12.0 on tokio 1.54.1, nginx 1.31.8 and wrk 4.2, all from pixi: the same as on 2026-10-27.
- **Conditions:** 2 reps of 60 s, the second in the reverse order. Other work on the machine (a desktop session) used 0.2 to 0.9 CPUs during the runs, and no run had to wait for a quiet machine. The first rep of the one-CPU keep-alive scenario was the noisiest (0.6 to 0.9 CPUs of other work, a lower clock): every server ran 6% to 17% slower in it than in the second rep, so that row's ranges are wide.
- **Clock and temperature:** the server's CPUs ran at 3.2–3.8 GHz on one CPU and 2.6–3.0 GHz on four (the all-core turbo is lower), at a package temperature of 71–80 °C.

Requests per second are the mean of the two runs, followed by both runs. The mean latency comes from Little's law (below); in the pipelined rows it is per batch of 16. Server CPU is per request.

| Scenario | Server | req/s (both runs) | Mean latency | p50 | p99 | Server CPU | wrk CPU |
|---|---|---|---|---|---|---|---|
| **1 CPU, 64 keep-alive connections** | hyper | **172k** (162k, 183k) | 373 µs | 360 µs | 612 µs | 5.77 µs | 41% |
| | mojo | 168k (153k, 183k) | 384 µs | 368 µs | 749 µs | 5.94 µs | 40% |
| | fasthttp | 162k (154k, 169k) | 397 µs | 398 µs | 992 µs | 6.16 µs | 37% |
| | nginx | 156k (142k, 171k) | 413 µs | 394 µs | 764 µs | 6.40 µs | 37% |
| | go (net/http) | 82k (78k, 86k) | 782 µs | 793 µs | 2.08 ms | 12.07 µs | 17% |
| **1 CPU, 256 connections, 16 pipelined** | hyper | **1193k** (1186k, 1199k) | 3.43 ms | | | 0.83 µs | 24% |
| | mojo | 1185k (1106k, 1265k) | 3.47 ms | | | 0.84 µs | 26% |
| | fasthttp | 1123k (1119k, 1128k) | 3.65 ms | | | 0.88 µs | 24% |
| | nginx | 200k (197k, 203k) | 20.47 ms | | | 4.96 µs | 29% |
| | go (net/http) | 103k (103k, 104k) | 39.69 ms | | | 9.64 µs | 12% |
| **1 CPU, 1024 keep-alive connections** | hyper | **146k** (145k, 147k) | 7.01 ms | 6.97 ms | 9.95 ms | 6.80 µs | 29% |
| | mojo | 144k (141k, 146k) | 7.12 ms | 7.05 ms | 11.09 ms | 6.91 µs | 32% |
| | nginx | 141k (140k, 143k) | 7.25 ms | 7.24 ms | 9.43 ms | 7.03 µs | 28% |
| | fasthttp | 123k (122k, 124k) | 8.31 ms | 8.23 ms | 10.89 ms | 8.07 µs | 28% |
| | go (net/http) | 67k (63k, 71k) | 15.45 ms | 15.03 ms | 23.71 ms | 14.96 µs | 16% |
| **4 CPUs, 256 keep-alive connections** | mojo | **350k** (349k, 351k) | 731 µs | 612 µs | 3.57 ms | 10.83 µs | 92% |
| | hyper | 340k (338k, 343k) | 752 µs | 628 µs | 4.25 ms | 10.92 µs | 91% |
| | nginx | 322k (320k, 323k) | 796 µs | 703 µs | 4.33 ms | 11.86 µs | 88% |
| | fasthttp | 317k (317k, 317k) | 808 µs | 722 µs | 3.60 ms | 12.26 µs | 87% |
| | go (net/http) | 154k (153k, 154k) | 1.66 ms | 1.60 ms | 6.54 ms | 25.11 µs | 45% |
| **4 CPUs, 256 connections, 16 pipelined** | mojo | **2153k** (2151k, 2155k) | 1.90 ms | | | 1.83 µs | 67% |
| | hyper | 2073k (2058k, 2088k) | 1.98 ms | | | 1.90 µs | 66% |
| | fasthttp | 1950k (1938k, 1961k) | 2.10 ms | | | 2.02 µs | 60% |
| | nginx | 403k (401k, 405k) | 10.16 ms | | | 9.87 µs | 63% |
| | go (net/http) | 180k (180k, 181k) | 22.71 ms | | | 21.34 µs | 29% |

What it shows:
- **mojo caught up with hyper.** Pipelined on one CPU it takes 0.84 µs of CPU a request against hyper's 0.83, where it took 1.31 against 0.85 a day earlier (Earlier runs, below): the codec and server work of HR3 and SR2 (`why_mojo_is_slower.note`). On four CPUs it is ahead pipelined (2153k against 2073k, with 4% less CPU a request), and on one CPU without pipelining it is within 2% of hyper.
- **Without pipelining, the top four are within a few percent:** hyper, mojo, fasthttp and nginx take 5.8 to 6.4 µs of CPU a request on one CPU, most of it the kernel's loopback TCP (one recv and one send a request). In the quieter second rep, mojo and hyper were even: 183,059 and 183,042 req/s, 5.41 and 5.43 µs a request. With 1024 connections, mojo is 1% behind hyper and ahead of nginx and fasthttp.
- **Go's net/http takes about twice the CPU of the others without pipelining**, and gains little from it: 9.6 µs a request pipelined, 11 times what hyper and mojo take. It writes each response out on its own (1.01 `write` calls a request pipelined, counted from `/proc/<pid>/io` on 2026-10-27). fasthttp, in the same language, is in the top group.
- **nginx makes a system call per response**, so it gains little from pipelining.
- **The four-CPU keep-alive runs mostly measure wrk.** It used 87–92% of its 4 threads; the order there follows the CPU per request, but the totals are the client's limit.
- **The four CPUs are 2 cores' 4 hardware threads**, at a lower clock, so the CPU per request is about twice that on one CPU.

**Latency.** wrk is closed-loop: every connection always has exactly one request (or one batch of 16) in flight. By Little's law, the mean latency is then exactly connections × requests per write / requests per second. With keep-alive it is close to wrk's medians: within 5% on one CPU, and up to 20% above them on four CPUs, where the tail is longer (a long tail puts the mean above the median). Pipelined, wrk's percentiles are left out, because they are wrong there. Its coordinated-omission correction (`stats_correct`) adds samples spaced by the time between responses rather than batches. It can put them below the histogram's minimum, where the percentile scan never looks: one run printed a p99 of 0.

## Why mojo was slower (2026-10-27)
This is what the profile showed before the http and server reviews (HR3, SR2), which closed the gap (Results, above). It is kept for what it found and how; `why_mojo_is_slower.note` has what changed.

mojo's own code did twice the work of hyper's for each request; the kernel's share was the same. Measured on 2026-10-27:
- **The CPU split:** user and system time from `/proc`, one CPU, the best of 2 runs of 10 s.
- **The instructions:** valgrind's callgrind (`pixi run -e bench bench-profile`, `out/profile-20261027-150833.json`). It counts every user-space instruction by function and source line, for the server on one CPU: 16 connections, 16 pipelined, 342k requests for mojo and 415k for hyper.

| Per request, one CPU | mojo | hyper | fasthttp | nginx |
|---|---|---|---|---|
| keep-alive: user + system | 1.63 + 3.59 µs | 0.97 + 3.57 µs | 1.28 + 4.68 µs | 1.45 + 4.37 µs |
| pipelined: user + system | 0.99 + 0.33 µs | 0.52 + 0.33 µs | 0.56 + 0.35 µs | 1.31 + 3.75 µs |
| pipelined: user-space instructions | 9,644 | 4,565 | (not profiled) | (not profiled) |

**Update, 2026-10-28** (the http review HR3, then the server review SR2; `out/profile-20261028-020523.json`, both servers in one run): mojo now takes **4,227** user-space instructions a request pipelined, against hyper's 4,565 (unchanged). By file: `src/http/connection.mojo` 1,097, `parse.mojo` 875, `server.mojo` 823, `headers.mojo` 295, bounds checks 150. What changed is in `why_mojo_is_slower.note`. The wrk runs of the same day (Results, above) show it as time: 0.84 µs of CPU a request pipelined, against hyper's 0.83.

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

**Leads** ([why_mojo_is_slower.note](why_mojo_is_slower.note) has them in detail, with every hot spot's file and line, the baseline to compare against, and what must not change):
- Done in SR2: the server's Date and Server lines go to the codec encoded once a second, with the body's length as a number, and the default Content-Type is set without checks.
- Still open: summarize the framing fields while parsing, in the same pass.
- Check field bytes with SIMD, as `_find_end` finds the end of the head.
- Remember a connection's Host field once it has been checked.

The profile is pipelined. With keep-alive, the same code ran once per request, plus one recv and one send: 1.63 µs of user time, against hyper's 0.97 (2026-10-27).

## Earlier runs
**2026-10-27, before HR3 and SR2** (`out/20261027-133003.json`; the same machine, versions and method, other work 0.2 to 0.6 CPUs). Requests per second, the mean of 2 reps of 60 s, with the CPU a request where it matters:
- 1 CPU, 64 keep-alive connections: hyper 181k, nginx 175k, fasthttp 164k, mojo 156k (6.36 µs, against hyper's 5.48), go 86k.
- 1 CPU, 16 pipelined: hyper 1169k (0.85 µs), fasthttp 1067k, mojo 762k (1.31 µs), nginx 191k, go 102k.
- 1 CPU, 1024 connections: hyper 144k, nginx 141k, mojo 132k, fasthttp 124k, go 70k.
- 4 CPUs, keep-alive: hyper 350k, nginx 327k, fasthttp 319k, mojo 301k, go 155k (wrk at 83–92%).
- 4 CPUs, 16 pipelined: hyper 2115k, fasthttp 1967k, mojo 1326k (3.01 µs), nginx 410k, go 182k.

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
