#!/usr/bin/env python3
"""HTTP hello comparison: bench/http_hello.mojo (net.evented) against
bench/rust_http (tokio current_thread, raw TcpStream, the same parsing),
loaded with wrk. Same pinning as the echo gate: server on CPU 2, wrk's
threads on CPUs 3, 1, 0.

    python3 bench/http_bench.py check             # protocol checks only
    python3 bench/http_bench.py run [--reps 3] [--duration 10] [--conns 256]

For each run: requests/s and latency percentiles from wrk --latency, and
server CPU ns per request from /proc utime+stime over the wrk run. Two
scenarios: keep-alive (one request in flight per connection, like most
benchmarks) and pipelined (16 requests per write, bench/pipeline.lua).
wrk comes from conda-forge through `pixi exec --spec wrk`.
"""

import argparse
import glob
import json
import os
import re
import shutil
import socket
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
SERVERS = {
    "mojo": [os.path.join(OUT, "http_hello"), "--port", "0"],
    "mojo-opt": [os.path.join(OUT, "http_hello_opt"), "--port", "0"],
    "rust": [os.path.join(OUT, "tokio-target", "release", "rust_http"), "--port", "0"],
}
SERVER_CPU = "2"
CLIENT_CPUS = "0,1,3"
CLK_TCK = os.sysconf("SC_CLK_TCK")


def wrk_path():
    w = shutil.which("wrk")
    if w:
        return w
    found = glob.glob(os.path.expanduser("~/.cache/rattler/cache/cached-envs-v0/wrk-*/bin/wrk"))
    if found:
        return found[0]
    out = subprocess.run(["pixi", "exec", "--spec", "wrk", "sh", "-c", "command -v wrk"],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


def cpu_ticks(pid):
    with open(f"/proc/{pid}/stat") as f:
        rest = f.read().rsplit(")", 1)[1].split()
    return int(rest[11]) + int(rest[12])


def start(kind):
    p = subprocess.Popen(["taskset", "-c", SERVER_CPU] + SERVERS[kind],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    line = p.stdout.readline()
    m = re.search(r"LISTEN [\d.]+:(\d+) pid=(\d+)", line)
    if not m:
        p.kill()
        raise RuntimeError(f"{kind}: no LISTEN line: {line!r}")
    return p, int(m.group(1)), int(m.group(2))


def to_us(v):
    m = re.match(r"([\d.]+)(us|ms|s)", v)
    x = float(m.group(1))
    return x * {"us": 1, "ms": 1e3, "s": 1e6}[m.group(2)]


def parse_wrk(text):
    r = {"raw": text}
    m = re.search(r"(\d+) requests in ([\d.]+)(\w+)", text)
    r["requests"] = int(m.group(1))
    r["rps"] = float(re.search(r"Requests/sec:\s+([\d.]+)", text).group(1))
    for pct in ("50", "75", "90", "99"):
        m = re.search(rf"^\s+{pct}%\s+(\S+)", text, re.M)
        r[f"p{pct}_us"] = to_us(m.group(1)) if m else None
    m = re.search(r"Non-2xx or 3xx responses: (\d+)", text)
    r["non2xx"] = int(m.group(1)) if m else 0
    m = re.search(r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)", text)
    r["sock_errors"] = sum(int(x) for x in m.groups()) if m else 0
    return r


def run_one(kind, scenario, conns, duration, wrk):
    p, port, pid = start(kind)
    try:
        time.sleep(0.3)
        argv = ["taskset", "-c", CLIENT_CPUS, wrk, "-t3", f"-c{conns}", f"-d{duration}s", "--latency"]
        if scenario == "pipelined":
            argv += ["-s", os.path.join(HERE, "pipeline.lua")]
        argv.append(f"http://127.0.0.1:{port}/")
        if scenario == "pipelined":
            argv += ["--", "16"]
        c0, t0 = cpu_ticks(pid), time.monotonic()
        out = subprocess.run(argv, capture_output=True, text=True, timeout=duration + 60).stdout
        c1, t1 = cpu_ticks(pid), time.monotonic()
        rss = int(re.search(r"VmRSS:\s+(\d+)", open(f"/proc/{pid}/status").read()).group(1))
    finally:
        p.kill()
        p.wait()
    r = parse_wrk(out)
    cpu_s = (c1 - c0) / CLK_TCK
    r.update(server=kind, scenario=scenario, conns=conns, cpu_util=cpu_s / (t1 - t0),
             cpu_ns_per_req=cpu_s * 1e9 / max(1, r["requests"]), rss_kb=rss)
    return r


def http_check(kind):
    """Protocol checks over a real socket: keep-alive, pipelining, a head
    split across writes, Connection: close, oversized head."""
    p, port, _ = start(kind)
    ok = True
    try:
        resp = (b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\nHello, World!")
        req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"

        def recv_n(s, n):
            b = b""
            while len(b) < n:
                d = s.recv(n - len(b))
                if not d:
                    break
                b += d
            return b

        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(req)
        ok &= recv_n(s, len(resp)) == resp
        s.sendall(req * 50)  # pipelined
        ok &= recv_n(s, 50 * len(resp)) == resp * 50
        s.sendall(req[:7])  # split head
        time.sleep(0.05)
        s.sendall(req[7:])
        ok &= recv_n(s, len(resp)) == resp
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Close\r\n\r\n")
        body = b""
        while True:
            d = s.recv(4096)
            if not d:
                break
            body += d
        ok &= body.endswith(b"Hello, World!") and b"Connection: close" in body
        s.close()
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"GET / HTTP/1.1\r\n" + b"X: " + b"a" * 9000)
        got = b""
        while True:
            d = s.recv(4096)
            if not d:
                break
            got += d
        ok &= got.startswith(b"HTTP/1.1 431")
        s.close()
    finally:
        p.kill()
        p.wait()
    print(f"{kind}: HTTP checks {'PASS' if ok else 'FAIL'}")
    return ok


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    r = sub.add_parser("run")
    r.add_argument("--reps", type=int, default=3)
    r.add_argument("--duration", type=int, default=10)
    r.add_argument("--conns", type=int, default=256)
    r.add_argument("--servers", default="mojo,mojo-opt,rust")
    r.add_argument("--scenarios", default="keepalive,pipelined")
    args = ap.parse_args()
    kinds = ["mojo", "mojo-opt", "rust"] if args.cmd == "check" else args.servers.split(",")
    if not all(http_check(k) for k in kinds):
        sys.exit(1)
    if args.cmd == "check":
        return
    wrk = wrk_path()
    runs = []
    print("| server | scenario | rep | req/s | p50 us | p99 us | server CPU ns/req | server CPU | errors |")
    print("|---|---|---|---|---|---|---|---|---|")
    for rep in range(args.reps):
        for scenario in args.scenarios.split(","):
            order = kinds[rep % len(kinds):] + kinds[: rep % len(kinds)]
            for kind in order:
                x = run_one(kind, scenario, args.conns, args.duration, wrk)
                x["rep"] = rep
                runs.append(x)
                print(f"| {kind} | {scenario} | {rep} | {x['rps']:,.0f} | {x['p50_us']:.0f} | {x['p99_us']:.0f} "
                      f"| {x['cpu_ns_per_req']:,.0f} | {100 * x['cpu_util']:.0f}% | {x['non2xx'] + x['sock_errors']} |",
                      flush=True)
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, f"http-{time.strftime('%Y%m%d-%H%M%S')}.json")
    with open(path, "w") as f:
        json.dump([{k: v for k, v in x.items() if k != "raw"} for x in runs], f, indent=1)
    print()
    def lat(xs, key):
        v = [x[key] for x in xs if x[key]]
        return f"{statistics.median(v):,.0f}" if v else "n/a"  # wrk prints 0 for pipelined p99

    print("| server | scenario | req/s median (min-max) | p50 / p90 / p99 us (medians) | server CPU ns/req median (min-max) |")
    print("|---|---|---|---|---|")
    for scenario in args.scenarios.split(","):
        for kind in kinds:
            xs = [x for x in runs if x["server"] == kind and x["scenario"] == scenario]
            rps = [x["rps"] for x in xs]
            ns = [x["cpu_ns_per_req"] for x in xs]
            print(f"| {kind} | {scenario} | {statistics.median(rps):,.0f} ({min(rps):,.0f}-{max(rps):,.0f}) "
                  f"| {lat(xs, 'p50_us')} / {lat(xs, 'p90_us')} / {lat(xs, 'p99_us')} "
                  f"| {statistics.median(ns):,.0f} ({min(ns):,.0f}-{max(ns):,.0f}) |")
    print("saved", path)


if __name__ == "__main__":
    main()
