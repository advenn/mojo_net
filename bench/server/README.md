# HTTP server benchmark

`run.py` compares mojo_net's `server` (`plaintext.mojo`) with nginx, Go's `net/http` and Rust's hyper on TechEmpower's plaintext test: `GET /plaintext` answered with `200` and `Hello, World!`. The load comes from wrk.

```bash
pixi run -e bench bench-server build    # the Mojo, Go and hyper servers (Go and cargo from the host)
pixi run -e bench bench-server check    # each answers one request, and 16 pipelined
pixi run -e bench bench-server run      # 5 scenarios x 4 servers x 3 reps, 10 s each
pixi run -e bench bench-server summary bench/server/out/<time>.json
```

The `bench` environment adds wrk and nginx from conda-forge (x86_64 only: conda-forge has no wrk for aarch64).

## Method
- **The same work.** Every server sends `Content-Type`, `Content-Length`, `Date` and `Server` with the 13-byte body, 127 to 161 bytes a response (`check` prints them).
- **Each server in its usual per-core form:**
  - **mojo:** one process; on several CPUs, a supervisor and one worker per CPU, each pinned to it (`run_workers`, SO_REUSEPORT).
  - **nginx:** one worker per CPU, pinned with `worker_cpu_affinity auto <mask>`; access log off. Without the mask, `auto` pins the workers to CPUs 0, 1, ... whatever affinity nginx started with, which put them on wrk's CPUs.
  - **Go:** `GOMAXPROCS` set to the CPUs, one listener.
  - **hyper 1.x:** one thread per CPU, each a tokio `current_thread` runtime with its own SO_REUSEPORT listener, and `pipeline_flush` on.
- **Pinning.** The servers and wrk never share a core. CPUs n and n + 4 are the two hardware threads of one core on this machine.
  - wrk (4 threads) runs on cores 0 and 1 (CPUs 0, 1, 4, 5).
  - A one-CPU server runs on CPU 2, with its sibling, CPU 6, left out.
  - A four-CPU server runs on cores 2 and 3 (CPUs 2, 3, 6, 7).
- **Each run** starts the server afresh, warms it up for 2 s with the same load, then measures for 10 s. The reps go round the servers in a rotating order.
- **What is measured:**
  - requests per second and latency percentiles, from `wrk --latency`;
  - the server's CPU per request: user plus system time of every process in its process group, from `/proc`, over the measured 10 s. On loopback this includes the kernel's TCP work for both directions of the server's sockets;
  - wrk's CPU, as a share of its 4 threads: near 100% the client, not the server, is the limit.
- **Caveats:**
  - one laptop, with the client on the same machine, over loopback;
  - wrk is closed-loop: each connection sends its next request (or batch) only after the last answer, so its latencies leave out queueing that an open-loop client would see;
  - the machine was shared with a desktop session (see the load in each result).

## Results
Measured on 2026-10-25 (`out/20261025-182428.json`):
- an i5-1145G7 (4 cores, 8 threads), Linux 6.12;
- Mojo 1.2.0, nginx 1.31.8, Go 1.26.2, hyper 1.12 on tokio 1.54 (rustc 1.96.1), wrk 4.2;
- a load average from 3.2 to 11.2 (median 6.1) around the runs, from a desktop session and the benchmark itself.

The medians of 3 runs, with the range of throughput:

| Scenario | Server | req/s (median; min–max) | p50 | p99 | Server CPU per request | wrk CPU |
|---|---|---|---|---|---|---|
| 1 CPU, 64 keep-alive connections | mojo | 152k; 136k–153k | 402 µs | 970 µs | 6.51 µs | 34% |
| | nginx | 142k; 141k–155k | 402 µs | 2.17 ms | 6.94 µs | 37% |
| | Go | 75k; 70k–78k | 860 µs | 2.12 ms | 13.24 µs | 17% |
| | hyper | 163k; 157k–164k | 369 µs | 692 µs | 6.14 µs | 40% |
| 1 CPU, 256 connections, 16 pipelined | mojo | 614k; 535k–701k | 3.62 ms | 9.78 ms | 1.62 µs | 16% |
| | nginx | 159k; 144k–165k | 13.98 ms | 49.59 ms | 6.23 µs | 25% |
| | Go | 86k; 78k–87k | 30.20 ms | 84.02 ms | 11.52 µs | 11% |
| | hyper | 918k; 871k–961k | 2.41 ms | 5.10 ms | 1.07 µs | 22% |
| 1 CPU, 1024 keep-alive connections | mojo | 117k; 100k–118k | 8.44 ms | 13.01 ms | 8.40 µs | 27% |
| | nginx | 116k; 99k–121k | 8.36 ms | 13.49 ms | 8.43 µs | 28% |
| | Go | 59k; 54k–61k | 16.72 ms | 25.82 ms | 16.79 µs | 15% |
| | hyper | 123k; 96k–130k | 8.04 ms | 11.52 ms | 7.98 µs | 29% |
| 4 CPUs, 256 keep-alive connections | mojo | 283k; 258k–308k | 706 µs | 4.89 ms | 12.67 µs | 77% |
| | nginx | 283k; 245k–293k | 680 µs | 5.71 ms | 12.16 µs | 78% |
| | Go | 131k; 113k–134k | 1.82 ms | 9.03 ms | 28.37 µs | 40% |
| | hyper | 290k; 258k–301k | 647 µs | 6.36 ms | 11.10 µs | 78% |
| 4 CPUs, 256 connections, 16 pipelined | mojo | 1335k; 1255k–1343k | 1.64 ms | 3.56 ms | 2.96 µs | 41% |
| | nginx | 406k; 395k–418k | 5.43 ms | 16.29 ms | 9.76 µs | 59% |
| | Go | 164k; 148k–179k | 32.69 ms | 161.63 ms | 23.15 µs | 27% |
| | hyper | 1782k; 1507k–1813k | 1.21 ms | 5.34 ms | 2.16 µs | 56% |

What it shows:
- **Without pipelining, mojo, nginx and hyper are level:** 6.1 to 6.9 µs of CPU a request on one CPU, most of it the kernel's (below). Go's `net/http` takes twice that.
- **Pipelined, hyper leads:** 1.07 µs a request against mojo's 1.62. nginx makes a system call per response (`writev`, below). Go gains little from pipelining (it was not traced).
- **The four-CPU keep-alive runs measure wrk, not the servers.** wrk used 77–80% of its 4 threads, and mojo, nginx and hyper all stopped at about 285k. Telling them apart there needs more client CPU than this machine has to spare. The four CPUs are 2 cores, so each hardware thread runs at about half speed and the CPU per request doubles.

**Re-run on 2026-10-26, after TLS came into `server` (T2, S7)** (`out/20261026-182035.json`; same machine and versions, a load of 2.7 to 3 at the start):

| Scenario | mojo | nginx | Go | hyper |
|---|---|---|---|---|
| 1 CPU, 64 keep-alive | 119k; 8.29 µs | 127k; 7.82 µs | 62k; 16.12 µs | 132k; 7.51 µs |
| 1 CPU, 256 conns, 16 pipelined | 516k; 1.91 µs | 137k; 7.21 µs | 70k; 14.17 µs | 737k; 1.34 µs |
| 1 CPU, 1024 keep-alive | 96k; 10.28 µs | 98k; 10.06 µs | 48k; 20.71 µs | 102k; 9.66 µs |
| 4 CPUs, 256 keep-alive | 242k; 13.88 µs | 257k; 12.74 µs | 109k; 30.00 µs | 258k; 11.38 µs |
| 4 CPUs, 256 conns, 16 pipelined | 1151k; 3.40 µs | 371k; 10.34 µs | 143k; 25.43 µs | 1546k; 2.25 µs |

(median requests a second; server CPU per request.) Every server was slower than the day before, on a busier machine; the order is the same. mojo's own keep-alive runs spread widely (111k to 141k).
- **S7 costs plain HTTP nothing measurable.** An A/B of the benchmark server built from the commit before S7 and from S7, alternated 8 times on the pipelined scenario (6 s each): 1.88 µs a request at best before, 1.82 with S7 (medians 1.92 and 1.89). A first A/B with fewer runs, at a load of 4 to 7, had suggested 20% more; with more runs it was noise. The TLS code adds 130 KB to the binary.
- HTTPS is not benchmarked yet.

**Where mojo's time goes**, against hyper and nginx on one CPU (the best of 2 runs of 8 s; system calls counted with strace on a separate run):

| | User + system per request (keep-alive) | Pipelined | System calls per request (keep-alive; pipelined) |
|---|---|---|---|
| mojo | 1.98 + 5.30 µs | 1.12 + 0.44 µs | 2.04 (recv 1.03, send 1.00); 0.16 (recv 0.10, send 0.06) |
| hyper | 1.25 + 4.94 µs | 0.70 + 0.35 µs | 2.02; 0.13 (recv 0.06, send 0.06) |
| nginx | 1.67 + 5.08 µs | 1.57 + 4.83 µs | 2.02; 1.08 (`writev` 1.01) |

- **The kernel dominates keep-alive:** about 5 µs of loopback TCP a request (a recv and a send), the same for all three.
- **The gap to hyper is user time:** 0.4 µs a request pipelined, 0.7 µs without. That is about what docs/server.md (S5) measured `server` adding over the bare codec (`Request` and `Response`, header scans, the hooks), so the codec itself is about level with hyper, and the server layer is where to look.
- **mojo rarely waits:** 60 `epoll_pwait2` calls for 113k requests, since it reads a connection again after answering it. Pipelined, that costs a little: 37% of its receives find nothing yet (0.6 a batch, where hyper reads once), about 0.03 µs a request.
