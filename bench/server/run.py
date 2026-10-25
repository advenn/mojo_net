#!/usr/bin/env python3
"""The HTTP server benchmark: bench/server/plaintext.mojo (mojo_net's
`server`) against nginx, Go's net/http and hyper, on TechEmpower's plaintext
test (GET /plaintext -> "Hello, World!"), loaded with wrk. README.md has the
method and the results.

    pixi run -e bench bench-server build     # the four servers, into bench/server/out/
    pixi run -e bench bench-server check     # each answers, one request and 16 pipelined
    pixi run -e bench bench-server run [--reps 3] [--duration 10]
                                       [--scenarios a,b] [--servers mojo,nginx]

Every server and every wrk run is pinned (taskset): the server to the
scenario's CPUs, wrk to others, so they never share a core. Each run starts
the server afresh, warms it up for 2 s, then measures for --duration
seconds: requests/s and latency percentiles from wrk --latency, the
server's CPU per request (user + system time of every process in its
process group, from /proc), and wrk's own CPU, which shows when the client
rather than the server is the limit. Reps go round the servers in a
rotating order, so a burst of load from elsewhere on the machine does not
fall on one server only. Results go to bench/server/out/<time>.json.
"""

import argparse
import json
import os
import platform
import resource
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(HERE, "out")
CLK_TCK = os.sysconf("SC_CLK_TCK")
PIPELINE_LUA = os.path.join(HERE, "pipeline.lua")
HYPER_BIN = os.path.join(OUT, "hyper-target", "release", "hyper_plaintext")

# (name, server CPUs, server workers, wrk CPUs, wrk threads, connections, pipelined)
# CPU n and n + 4 are the two threads of one core on this machine (lscpu -e):
# one-CPU servers run on CPU 2 with its sibling 6 left out, and wrk gets
# cores 0 and 1.
SCENARIOS = [
    ("1cpu-keepalive", "2", 1, "0,1,4,5", 4, 64, 1),
    ("1cpu-pipelined", "2", 1, "0,1,4,5", 4, 256, 16),
    ("1cpu-1024conns", "2", 1, "0,1,4,5", 4, 1024, 1),
    ("4cpu-keepalive", "2,3,6,7", 4, "0,1,4,5", 4, 256, 1),
    ("4cpu-pipelined", "2,3,6,7", 4, "0,1,4,5", 4, 256, 16),
]
SERVERS = ("mojo", "nginx", "go", "hyper")

NGINX_CONF = """\
worker_processes {workers};
worker_cpu_affinity auto {mask};
daemon off;
master_process on;
pid {dir}/nginx.pid;
error_log {dir}/error.log warn;
events {{ worker_connections 8192; }}
http {{
    access_log off;
    keepalive_requests 100000000;
    client_body_temp_path {dir}/body;
    proxy_temp_path {dir}/proxy;
    fastcgi_temp_path {dir}/fastcgi;
    uwsgi_temp_path {dir}/uwsgi;
    scgi_temp_path {dir}/scgi;
    server {{
        listen 127.0.0.1:{port} reuseport backlog=4096;
        location = /plaintext {{
            default_type text/plain;
            return 200 "Hello, World!";
        }}
    }}
}}
"""


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _mask(cpus):
    """nginx's CPU mask for a taskset list ("2,3" -> "1100"): without one,
    `auto` pins workers to CPUs 0, 1, ... whatever the affinity it was
    started with, which would put them on wrk's CPUs."""
    bits = {int(c) for c in cpus.split(",")}
    return "".join("1" if i in bits else "0" for i in range(max(bits), -1, -1))


def server_command(kind, port, workers, cpus):
    """The argv, environment and number of "LISTEN" lines of one server."""
    addr = "127.0.0.1:%d" % port
    env = dict(os.environ)
    if kind == "mojo":
        env["WORKERS"] = "0" if workers == 1 else str(workers)  # (one process, no supervisor)
        return [os.path.join(OUT, "plaintext"), addr], env, workers
    if kind == "go":
        env["GOMAXPROCS"] = str(workers)
        return [os.path.join(OUT, "go_plaintext"), addr], env, 1
    if kind == "hyper":
        env["WORKERS"] = str(workers)
        return [HYPER_BIN, addr], env, 1
    if kind == "nginx":
        d = os.path.join(OUT, "nginx")
        os.makedirs(d, exist_ok=True)
        conf = os.path.join(d, "nginx.conf")
        with open(conf, "w") as f:
            f.write(NGINX_CONF.format(workers=workers, dir=d, port=port, mask=_mask(cpus)))
        return [shutil.which("nginx"), "-p", d, "-c", conf], env, 0
    raise ValueError(kind)


class Server:
    """A server in a process group of its own, pinned to `cpus`."""

    def __init__(self, kind, cpus, workers):
        self.kind = kind
        self.port = free_port()
        argv, env, lines = server_command(kind, self.port, workers, cpus)
        self.p = subprocess.Popen(
            ["taskset", "-c", cpus] + argv,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        try:
            for _ in range(lines):
                line = self.p.stdout.readline()
                if not line.startswith("LISTEN"):
                    raise RuntimeError("%s: expected LISTEN, got %r" % (kind, line))
            self._wait_connectable()
        except BaseException:
            self.stop()
            raise
        if lines == 0:
            time.sleep(0.5)  # (nginx: let every worker take its listener)

    def _wait_connectable(self):
        end = time.time() + 30
        while time.time() < end:
            if self.p.poll() is not None:
                raise RuntimeError("%s exited: %s" % (self.kind, self.p.stdout.read()))
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("%s: no connection in 30 s" % self.kind)

    def cpu_ticks(self):
        """User + system ticks of every process in the server's group."""
        total = 0
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open("/proc/%s/stat" % pid) as f:
                    rest = f.read().rsplit(")", 1)[1].split()
            except OSError:
                continue
            if int(rest[2]) == self.p.pid:  # (pgrp)
                total += int(rest[11]) + int(rest[12])
        return total

    def stop(self):
        if self.p.poll() is None:
            os.killpg(self.p.pid, signal.SIGTERM)
            try:
                self.p.wait(10)
            except subprocess.TimeoutExpired:
                os.killpg(self.p.pid, signal.SIGKILL)
                self.p.wait()
        try:
            os.killpg(self.p.pid, signal.SIGKILL)  # (anything left in the group)
        except ProcessLookupError:
            pass


def wrk(port, cpus, threads, conns, pipelined, seconds):
    url = "http://127.0.0.1:%d/plaintext" % port
    cmd = ["taskset", "-c", cpus, shutil.which("wrk"), "-t%d" % threads, "-c%d" % conns, "-d%ds" % seconds, "--latency"]
    if pipelined > 1:
        cmd += ["-s", PIPELINE_LUA, url, "--", str(pipelined)]
    else:
        cmd += [url]
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    r = subprocess.run(cmd, capture_output=True, text=True)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    if r.returncode != 0:
        raise RuntimeError("wrk failed: " + r.stdout + r.stderr)
    out = parse_wrk(r.stdout)
    out["wrk_cpu_s"] = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)
    return out


def to_us(v):
    for unit, scale in (("us", 1.0), ("ms", 1e3), ("s", 1e6)):
        if v.endswith(unit):
            return float(v[: -len(unit)]) * scale
    raise ValueError(v)


def parse_wrk(text):
    r = {"raw": text, "errors": 0, "non2xx": 0, "latency_us": {}}
    for line in text.splitlines():
        words = line.split()
        if line.startswith("Requests/sec:"):
            r["rps"] = float(words[1])
        elif "requests in" in line:
            r["requests"] = int(words[0])
        elif line.strip().startswith("Socket errors:"):
            r["errors"] = sum(int(w.strip(",")) for w in words[2:] if w.strip(",").isdigit())
        elif line.strip().startswith("Non-2xx"):
            r["non2xx"] = int(words[-1])
        elif len(words) == 2 and words[0] in ("50%", "75%", "90%", "99%"):
            r["latency_us"][words[0]] = to_us(words[1])
    if "rps" not in r:
        raise RuntimeError("cannot read wrk's output:\n" + text)
    return r


def run_one(kind, scenario, seconds):
    name, cpus, workers, wcpus, threads, conns, pipelined = scenario
    load = os.getloadavg()[0]
    s = Server(kind, cpus, workers)
    try:
        wrk(s.port, wcpus, threads, conns, pipelined, 2)  # (warm-up)
        t0 = s.cpu_ticks()
        r = wrk(s.port, wcpus, threads, conns, pipelined, seconds)
        t1 = s.cpu_ticks()
    finally:
        s.stop()
    r["server_cpu_s"] = (t1 - t0) / CLK_TCK
    r["server_us_per_req"] = r["server_cpu_s"] * 1e6 / max(r["requests"], 1)
    r["wrk_cpu_share"] = r["wrk_cpu_s"] / (seconds * threads)
    r["load"] = load
    r.pop("raw")
    return r


def build(_args):
    os.makedirs(OUT, exist_ok=True)
    steps = [
        ["mojo", "build", "-I", "src", "bench/server/plaintext.mojo", "-o", "bench/server/out/plaintext"],
        ["go", "build", "-C", "bench/server/go", "-o", os.path.join(OUT, "go_plaintext"), "."],
        ["cargo", "build", "--release", "--manifest-path", "bench/server/hyper/Cargo.toml"],
    ]
    env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(OUT, "hyper-target"))
    for step in steps:
        print("+", " ".join(step), flush=True)
        subprocess.run(step, cwd=ROOT, env=env, check=True)


def _exchange(port, payload, responses):
    """Send `payload`, read until `responses` responses with their bodies."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as c:
        c.sendall(payload)
        data = b""
        while data.count(b"Hello, World!") < responses:
            chunk = c.recv(65536)
            if not chunk:
                break
            data += chunk
    return data


def check(args):
    req = b"GET /plaintext HTTP/1.1\r\nHost: bench\r\n\r\n"
    failed = False
    for kind in args.servers:
        s = Server(kind, "2", 1)
        try:
            one = _exchange(s.port, req, 1)
            many = _exchange(s.port, req * 16, 16)
        finally:
            s.stop()
        head = one.split(b"\r\n\r\n", 1)[0].decode()
        ok = one.startswith(b"HTTP/1.1 200") and one.endswith(b"\r\n\r\nHello, World!") and many.count(b"HTTP/1.1 200") == 16
        failed |= not ok
        print("%s %s: %d bytes a response" % ("ok  " if ok else "FAIL", kind, len(one)))
        print("     " + head.replace("\r\n", "\n     "))
    sys.exit(1 if failed else 0)


def versions():
    def first_line(cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
            return (r.stdout + r.stderr).strip().splitlines()[0]
        except (OSError, IndexError):
            return "?"

    return {
        "cpu": first_line(["sh", "-c", "grep -m1 'model name' /proc/cpuinfo"]),
        "kernel": platform.release(),
        "mojo": first_line(["mojo", "--version"]),
        "nginx": first_line(["nginx", "-v"]),
        "go": first_line(["go", "version"]),
        "rustc": first_line(["rustc", "--version"]),
        "wrk": first_line(["wrk", "--version"]),
    }


def run(args):
    scenarios = [s for s in SCENARIOS if not args.scenarios or s[0] in args.scenarios]
    results = {"versions": versions(), "duration_s": args.duration, "runs": []}
    print(json.dumps(results["versions"], indent=1), flush=True)
    for rep in range(args.reps):
        for scenario in scenarios:
            order = list(args.servers)
            k = rep % len(order)
            for kind in order[k:] + order[:k]:
                r = run_one(kind, scenario, args.duration)
                r.update(server=kind, scenario=scenario[0], rep=rep)
                results["runs"].append(r)
                print(
                    "%-15s %-6s rep %d: %9.0f req/s  p50 %7.0f us  p99 %7.0f us  server %.2f us/req  wrk %3.0f%%  load %.1f%s"
                    % (scenario[0], kind, rep, r["rps"], r["latency_us"].get("50%", 0), r["latency_us"].get("99%", 0),
                       r["server_us_per_req"], 100 * r["wrk_cpu_share"], r["load"],
                       "  ERRORS %d non-2xx %d" % (r["errors"], r["non2xx"]) if r["errors"] or r["non2xx"] else ""),
                    flush=True,
                )
    path = os.path.join(OUT, time.strftime("%Y%m%d-%H%M%S") + ".json")
    with open(path, "w") as f:
        json.dump(results, f, indent=1)
    print("\nwrote", path)
    summary(results)


def summary(results):
    print("\n| Scenario | Server | req/s (median; min–max) | p50 | p99 | server CPU per request | wrk CPU |")
    print("|---|---|---|---|---|---|---|")
    seen = []
    for r in results["runs"]:
        if (r["scenario"], r["server"]) not in seen:
            seen.append((r["scenario"], r["server"]))
    for scenario, kind in seen:
        rs = [r for r in results["runs"] if r["scenario"] == scenario and r["server"] == kind]
        rps = [r["rps"] for r in rs]
        med = lambda xs: statistics.median(xs)
        print("| %s | %s | %s; %s–%s | %s | %s | %.2f µs | %.0f%% |" % (
            scenario, kind, _k(med(rps)), _k(min(rps)), _k(max(rps)),
            _t(med([r["latency_us"]["50%"] for r in rs])), _t(med([r["latency_us"]["99%"] for r in rs])),
            med([r["server_us_per_req"] for r in rs]), 100 * med([r["wrk_cpu_share"] for r in rs])))


def _k(x):
    return "%.0fk" % (x / 1000)


def _t(us):
    return "%.0f µs" % us if us < 1000 else "%.2f ms" % (us / 1000)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build")
    c = sub.add_parser("check")
    c.add_argument("--servers", type=lambda s: s.split(","), default=list(SERVERS))
    r = sub.add_parser("run")
    r.add_argument("--reps", type=int, default=3)
    r.add_argument("--duration", type=int, default=10)
    r.add_argument("--scenarios", type=lambda s: s.split(","), default=[])
    r.add_argument("--servers", type=lambda s: s.split(","), default=list(SERVERS))
    s = sub.add_parser("summary")
    s.add_argument("file")
    args = ap.parse_args()
    if args.cmd == "summary":
        with open(args.file) as f:
            summary(json.load(f))
        return
    {"build": build, "check": check, "run": run}[args.cmd](args)


if __name__ == "__main__":
    main()
