#!/usr/bin/env python3
"""The HTTP server benchmark: bench/server/plaintext.mojo (mojo_net's
`server`) against Go (net/http and fasthttp), Rust (hyper) and nginx, on
TechEmpower's plaintext test (GET /plaintext -> "Hello, World!"), loaded
with wrk. README.md has the method, the results and how to reproduce them.

    pixi run -e bench bench-server build     # the servers, into bench/server/out/
    pixi run -e bench bench-server check     # each answers, one request and 16 pipelined
    pixi run -e bench bench-server run [--reps 1] [--duration 60] [--warmup 5] [--cooldown 15]
                                       [--scenarios a,b] [--servers mojo,go]
                                       [--server-cpus 2,3,6,7 --wrk-cpus 0,1,4,5]
    pixi run -e bench bench-server pgo       # refresh the Go servers' PGO profiles (default.pgo)
    pixi run -e bench bench-server summary bench/server/out/<time>.json

Every server and every wrk run is pinned (taskset): the server to the
scenario's CPUs, wrk to the others, so they never share a core. The CPUs
come from the machine's topology (`layout()`), or from --server-cpus and
--wrk-cpus. Runs are sequential: one server at a time, each started afresh,
warmed up for --warmup seconds, measured for --duration seconds, then
stopped, with --cooldown seconds of idle before the next, so that each
starts from about the same temperature. A rep goes through the servers in
the order of --servers; with --reps 2 or more, every other rep goes in the
reverse order. Each run records requests/s and latency percentiles (wrk
--latency), the server's CPU per request (user + system time of every
process in its group, from /proc), wrk's own CPU (near 100% the client, not
the server, is the limit), and the server CPUs' clock and the package
temperature, sampled each second. Results go to bench/server/out/<time>.json.
"""

import argparse
import glob
import json
import os
import platform
import re
import resource
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(HERE, "out")
CLK_TCK = os.sysconf("SC_CLK_TCK")
PIPELINE_LUA = os.path.join(HERE, "pipeline.lua")
HYPER_BIN = os.path.join(OUT, "hyper-target", "release", "hyper_plaintext")

# (name, server CPUs, connections, requests per write)
SCENARIOS = [
    ("1cpu-keepalive", 1, 64, 1),
    ("1cpu-pipelined", 1, 256, 16),
    ("1cpu-1024conns", 1, 1024, 1),
    ("4cpu-keepalive", 4, 256, 1),
    ("4cpu-pipelined", 4, 256, 16),
]
SERVERS = ("mojo", "go", "fasthttp", "hyper", "nginx")
GO_SERVERS = {"go": "go", "fasthttp": "fasthttp"}  # (kind: directory under bench/server)

NGINX_CONF = """\
worker_processes {workers};
worker_cpu_affinity auto {mask};
worker_rlimit_nofile 65536;
daemon off;
master_process on;
pid {dir}/nginx.pid;
error_log {dir}/error.log warn;
events {{ worker_connections 8192; }}
http {{
    access_log off;
    keepalive_requests 100000000;
    keepalive_timeout 600s;
    tcp_nodelay on;
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


def cores():
    """The physical cores this process may use, each a sorted list of its
    CPUs (hardware threads), ordered by their first CPU."""
    by_core = {}
    for cpu in sorted(os.sched_getaffinity(0)):
        topo = "/sys/devices/system/cpu/cpu%d/topology/" % cpu
        try:
            key = tuple(int(open(topo + f).read()) for f in ("physical_package_id", "core_id"))
        except OSError:
            key = (0, cpu)
        by_core.setdefault(key, []).append(cpu)
    return sorted(by_core.values())


def layout(server_cpus=None, wrk_cpus=None):
    """(server CPUs, wrk CPUs). By default the server gets whole cores from
    the top until it has 4 CPUs (so the 1-CPU scenarios run on one hardware
    thread with its siblings idle), and wrk every CPU of the other cores."""
    cs = cores()
    if not server_cpus:
        server, taken = [], 0
        while len(server) < 4 and taken < len(cs) - 1:
            taken += 1
            server = sorted(c for core in cs[-taken:] for c in core)[:4]
        server_cpus = server
    if not wrk_cpus:
        wrk_cpus = sorted(c for core in cs for c in core if not set(core) & set(server_cpus))
    if len(server_cpus) < 4 or not wrk_cpus or set(server_cpus) & set(wrk_cpus):
        sys.exit("need 4 server CPUs and at least one other core for wrk; got server %s, wrk %s "
                 "(set --server-cpus and --wrk-cpus)" % (server_cpus, wrk_cpus))
    return server_cpus, wrk_cpus


def _cpulist(cpus):
    return ",".join(str(c) for c in cpus)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _mask(cpus):
    """nginx's CPU mask for a CPU list ([2, 3] -> "1100"): without one,
    `auto` pins workers to CPUs 0, 1, ... whatever the affinity it was
    started with, which would put them on wrk's CPUs."""
    return "".join("1" if i in cpus else "0" for i in range(max(cpus), -1, -1))


def server_command(kind, port, cpus):
    """The argv, environment and number of "LISTEN" lines of one server."""
    workers = len(cpus)
    addr = "127.0.0.1:%d" % port
    env = dict(os.environ)
    if kind == "mojo":
        env["WORKERS"] = "0" if workers == 1 else str(workers)  # (one process, no supervisor)
        return [os.path.join(OUT, "plaintext"), addr], env, workers
    if kind == "go":
        env["GOMAXPROCS"] = str(workers)
        return [os.path.join(OUT, "go_plaintext"), addr], env, 1
    if kind == "fasthttp":
        env["WORKERS"] = str(workers)
        return [os.path.join(OUT, "fasthttp_plaintext"), addr], env, workers
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

    def __init__(self, kind, cpus, env=None):
        self.kind = kind
        self.port = free_port()
        argv, base, lines = server_command(kind, self.port, cpus)
        base.update(env or {})
        self.p = subprocess.Popen(
            ["taskset", "-c", _cpulist(cpus)] + argv,
            env=base,
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

    def _group(self):
        n = 0
        for pid in os.listdir("/proc"):
            try:
                with open("/proc/%s/stat" % pid) as f:
                    rest = f.read().rsplit(")", 1)[1].split()
            except (OSError, IndexError):
                continue
            n += int(rest[2]) == self.p.pid and rest[0] != "Z"
        return n

    def stop(self):
        if self.p.poll() is None:
            os.killpg(self.p.pid, signal.SIGTERM)
            try:
                self.p.wait(10)
            except subprocess.TimeoutExpired:
                os.killpg(self.p.pid, signal.SIGKILL)
                self.p.wait()
        end = time.time() + 5
        while self._group() and time.time() < end:  # (workers ending on their own SIGTERM)
            time.sleep(0.05)
        try:
            os.killpg(self.p.pid, signal.SIGKILL)  # (anything left in the group)
        except ProcessLookupError:
            pass


def _read_int(path):
    try:
        with open(path) as f:
            return int(f.read())
    except (OSError, ValueError):
        return None


def _pkg_temp_path():
    for z in sorted(os.listdir("/sys/class/thermal")) if os.path.isdir("/sys/class/thermal") else []:
        try:
            if open("/sys/class/thermal/%s/type" % z).read().strip() == "x86_pkg_temp":
                return "/sys/class/thermal/%s/temp" % z
        except OSError:
            pass
    return None


class Sampler(threading.Thread):
    """Each second while a run lasts: the mean clock of `cpus` (MHz) and the
    CPU package's temperature (°C), where sysfs has them."""

    def __init__(self, cpus):
        super().__init__(daemon=True)
        self.cpus = cpus
        self.temp = _pkg_temp_path()
        self.mhz, self.celsius = [], []
        self.done = threading.Event()

    def run(self):
        while not self.done.wait(1.0):
            f = [_read_int("/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq" % c) for c in self.cpus]
            f = [x for x in f if x]
            if f:
                self.mhz.append(sum(f) / len(f) / 1000)
            t = _read_int(self.temp) if self.temp else None
            if t:
                self.celsius.append(t / 1000)

    def result(self):
        self.done.set()
        self.join()
        r = {}
        if self.mhz:
            r["server_mhz"] = {"mean": statistics.mean(self.mhz), "min": min(self.mhz), "max": max(self.mhz)}
        if self.celsius:
            r["pkg_celsius"] = {"mean": statistics.mean(self.celsius), "max": max(self.celsius)}
        return r


def busy_ticks():
    """Busy ticks of every CPU together, from /proc/stat (all but idle and
    iowait; softirq included, which this kernel also charges to the task it
    interrupted)."""
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:9]]
    return sum(v) - v[3] - v[4]


def quiet(args, first):
    """The cool-down before a run: --cooldown seconds idle, then, while the
    machine's own load (everything running, since nothing of ours is) is
    above --quiet CPUs, 5 s more at a time, up to --quiet-wait seconds.
    Returns the load of the last window, in CPUs, and the seconds waited."""
    window = max(args.cooldown, 3) if not first else 3
    waited = 0
    while True:
        b0 = busy_ticks()
        time.sleep(window)
        background = (busy_ticks() - b0) / CLK_TCK / window
        if args.quiet <= 0 or background <= args.quiet or waited >= args.quiet_wait:
            return background, waited
        if waited == 0:
            print("  waiting: the machine is using %.1f CPUs (--quiet %.1f)" % (background, args.quiet), flush=True)
        waited += window
        window = 5


def wrk(port, cpus, conns, pipelined, seconds):
    url = "http://127.0.0.1:%d/plaintext" % port
    threads = min(len(cpus), conns)
    cmd = ["taskset", "-c", _cpulist(cpus), shutil.which("wrk"), "-t%d" % threads, "-c%d" % conns,
           "-d%ds" % seconds, "--timeout", "10s", "--latency"]
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
    out["wrk_threads"] = threads
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


def run_one(kind, scenario, cpus, wrk_cpus, args):
    name, n, conns, pipelined = scenario
    load = os.getloadavg()[0]
    s = Server(kind, cpus[:n])
    try:
        if args.warmup > 0:
            wrk(s.port, wrk_cpus, conns, pipelined, args.warmup)
        t0 = s.cpu_ticks()
        b0 = busy_ticks()
        sampler = Sampler(cpus[:n])
        sampler.start()
        r = wrk(s.port, wrk_cpus, conns, pipelined, args.duration)
        r.update(sampler.result())
        t1 = s.cpu_ticks()
        b1 = busy_ticks()
    finally:
        s.stop()
    r["server_cpus"] = _cpulist(cpus[:n])
    r["server_cpu_s"] = (t1 - t0) / CLK_TCK
    r["server_us_per_req"] = r["server_cpu_s"] * 1e6 / max(r["requests"], 1)
    r["server_cpu_share"] = r["server_cpu_s"] / (args.duration * n)
    r["wrk_cpu_share"] = r["wrk_cpu_s"] / (args.duration * r["wrk_threads"])
    # (what else ran meanwhile, in CPUs: all busy time less the server's and wrk's)
    r["others_cpus"] = max(0.0, ((b1 - b0) - (t1 - t0)) / CLK_TCK - r["wrk_cpu_s"]) / args.duration
    r["load"] = load
    return r


def goamd64():
    """The highest GOAMD64 level this CPU has (as -C target-cpu=native and
    Mojo's default compile for the host CPU)."""
    try:
        flags = set(re.search(r"^flags\s*:(.*)$", open("/proc/cpuinfo").read(), re.M).group(1).split())
    except (OSError, AttributeError):
        return None
    if platform.machine() != "x86_64":
        return None
    if {"avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl"} <= flags:
        return "v4"
    if {"avx2", "bmi1", "bmi2", "f16c", "fma", "lzcnt", "movbe"} <= flags:
        return "v3"
    if {"cx16", "popcnt", "sse4_2", "ssse3"} <= flags:
        return "v2"
    return "v1"


def build_env():
    env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(OUT, "hyper-target"))
    level = goamd64()
    if level:
        env["GOAMD64"] = level
    return env


def build(_args):
    os.makedirs(OUT, exist_ok=True)
    steps = [
        ([shutil.which("mojo"), "build", "-I", "src", "bench/server/plaintext.mojo", "-o", "bench/server/out/plaintext"], ROOT),
        (["go", "build", "-trimpath", "-o", os.path.join(OUT, "go_plaintext"), "."], os.path.join(HERE, "go")),
        (["go", "build", "-trimpath", "-o", os.path.join(OUT, "fasthttp_plaintext"), "."], os.path.join(HERE, "fasthttp")),
        (["cargo", "build", "--release", "--locked"], os.path.join(HERE, "hyper")),  # (.cargo/config.toml there)
    ]
    env = build_env()
    print("+ GOAMD64=%s" % env.get("GOAMD64", ""), flush=True)
    for step, cwd in steps:
        print("+ (cd %s) %s" % (os.path.relpath(cwd, ROOT), " ".join(step)), flush=True)
        subprocess.run(step, cwd=cwd, env=env, check=True)


def pgo(args):
    """Refresh each Go server's default.pgo: build it without a profile, run
    it under each scenario's load with a CPU profile, merge the profiles,
    and rebuild with them (`go build` reads default.pgo in the main
    package's directory). The profiles are committed, as Go's PGO guide
    advises, so a build needs no profiling run."""
    os.makedirs(OUT, exist_ok=True)
    server_cpus, wrk_cpus = layout(args.server_cpus, args.wrk_cpus)
    env = build_env()
    for kind in args.servers:
        d = os.path.join(HERE, GO_SERVERS[kind])
        exe = os.path.join(OUT, "%s_plaintext" % kind)
        subprocess.run(["go", "build", "-trimpath", "-pgo=off", "-o", exe, "."], cwd=d, env=env, check=True)
        profiles = []
        for scenario in SCENARIOS:
            path = os.path.join(OUT, "%s-%s.pprof" % (kind, scenario[0]))
            s = Server(kind, server_cpus[: scenario[1]], env={"CPUPROFILE": path})
            try:
                wrk(s.port, wrk_cpus, scenario[2], scenario[3], args.seconds)
            finally:
                s.stop()
            profiles += sorted(glob.glob(path + ".*"))  # (one a process: <path>.<pid>)
        merged = os.path.join(d, "default.pgo")
        subprocess.run(["go", "tool", "pprof", "-proto"] + profiles, cwd=d, env=env, check=True,
                       stdout=open(merged, "wb"))
        for p in profiles:
            os.remove(p)
        print("wrote", os.path.relpath(merged, ROOT), flush=True)
    build(args)


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
    server_cpus, _ = layout(args.server_cpus, args.wrk_cpus)
    failed = False
    for kind in args.servers:
        for n in (1, 4):
            s = Server(kind, server_cpus[:n])
            try:
                one = _exchange(s.port, req, 1)
                many = _exchange(s.port, req * 16, 16)
            finally:
                s.stop()
            head = one.split(b"\r\n\r\n", 1)[0].decode()
            ok = one.startswith(b"HTTP/1.1 200") and one.endswith(b"\r\n\r\nHello, World!") and many.count(b"HTTP/1.1 200") == 16
            failed |= not ok
            print("%s %s on %d CPU%s: %d bytes a response" % ("ok  " if ok else "FAIL", kind, n, "s" if n > 1 else "", len(one)))
            if n == 1:
                print("     " + head.replace("\r\n", "\n     "))
    sys.exit(1 if failed else 0)


def _first_line(cmd, cwd=ROOT):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        return (r.stdout + r.stderr).strip().splitlines()[0]
    except (OSError, IndexError):
        return "?"


def _locked(path, names):
    """Versions of `names` in a Cargo.lock or go.mod."""
    found = {}
    try:
        text = open(path).read()
    except OSError:
        return found
    for name in names:
        m = re.search(r'name = "%s"\nversion = "([^"]+)"' % re.escape(name), text) or \
            re.search(r"^\s*(?:require\s+)?%s v(\S+)" % re.escape(name), text, re.M)
        if m:
            found[name] = m.group(1)
    return found


def versions(server_cpus, wrk_cpus):
    governor = _first_line(["cat", "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor" % server_cpus[0]])
    return {
        "cpu": _first_line(["sh", "-c", "grep -m1 'model name' /proc/cpuinfo"]),
        "kernel": platform.release(),
        "governor": governor,
        "server_cpus": _cpulist(server_cpus),
        "wrk_cpus": _cpulist(wrk_cpus),
        "mojo": _first_line(["mojo", "--version"]),
        "nginx": _first_line(["nginx", "-v"]),
        "go": _first_line(["go", "version"]),
        "goamd64": goamd64(),
        "fasthttp": _locked(os.path.join(HERE, "fasthttp", "go.mod"), ["github.com/valyala/fasthttp"]),
        "rustc": _first_line(["rustc", "--version"]),
        "hyper": _locked(os.path.join(HERE, "hyper", "Cargo.lock"), ["hyper", "tokio", "mimalloc"]),
        "wrk": _first_line(["wrk", "--version"]),
    }


def run(args):
    server_cpus, wrk_cpus = layout(args.server_cpus, args.wrk_cpus)
    scenarios = [s for s in SCENARIOS if not args.scenarios or s[0] in args.scenarios]
    results = {
        "versions": versions(server_cpus, wrk_cpus),
        "duration_s": args.duration,
        "warmup_s": args.warmup,
        "cooldown_s": args.cooldown,
        "runs": [],
    }
    print(json.dumps(results["versions"], indent=1), flush=True)
    path = os.path.join(OUT, time.strftime("%Y%m%d-%H%M%S") + ".json")
    first = True
    for rep in range(args.reps):
        order = list(args.servers) if rep % 2 == 0 else list(reversed(args.servers))
        for scenario in scenarios:
            for kind in order:
                background, waited = quiet(args, first)
                first = False
                start = time.strftime("%Y-%m-%d %H:%M:%S")
                r = run_one(kind, scenario, server_cpus, wrk_cpus, args)
                r.update(server=kind, scenario=scenario[0], rep=rep, start=start,
                         background_cpus=background, waited_s=waited)
                results["runs"].append(r)
                with open(path, "w") as f:  # (after every run: a stopped run keeps what it measured)
                    json.dump(results, f, indent=1)
                print(
                    "%-15s %-8s rep %d: %9.0f req/s  p50 %7.0f us  p99 %7.0f us  server %.2f us/req  wrk %3.0f%%  %4.0f MHz  %3.0f C  others %.1f CPUs%s"
                    % (scenario[0], kind, rep, r["rps"], r["latency_us"].get("50%", 0), r["latency_us"].get("99%", 0),
                       r["server_us_per_req"], 100 * r["wrk_cpu_share"], r.get("server_mhz", {}).get("mean", 0),
                       r.get("pkg_celsius", {}).get("mean", 0), r["others_cpus"],
                       "  ERRORS %d non-2xx %d" % (r["errors"], r["non2xx"]) if r["errors"] or r["non2xx"] else ""),
                    flush=True,
                )
    print("\nwrote", path)
    summary(results)


def mean_latency_us(r):
    """The mean latency of a request (or of a pipelined batch), by Little's
    law: wrk is closed-loop, with one request or batch in flight on every
    connection, so it is connections x requests per write / requests per
    second."""
    _, _, conns, pipelined = [s for s in SCENARIOS if s[0] == r["scenario"]][0]
    return conns * pipelined / r["rps"] * 1e6


def summary(results):
    """The medians of each scenario and server. Pipelined, wrk's percentiles
    are left out: its coordinated-omission correction (stats_correct) spaces
    the samples it adds by the interval between responses, not batches, and
    can put them below the histogram's minimum, where its percentile scan
    never looks (one such run printed a p99 of 0)."""
    print("\n| Scenario | Server | req/s | Mean latency | p50 | p99 | Server CPU per request | wrk CPU | Server clock | Others |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    seen = []
    for r in results["runs"]:
        if (r["scenario"], r["server"]) not in seen:
            seen.append((r["scenario"], r["server"]))
    med = statistics.median
    for scenario, kind in seen:
        rs = [r for r in results["runs"] if r["scenario"] == scenario and r["server"] == kind]
        rps = [r["rps"] for r in rs]
        mhz = [r["server_mhz"]["mean"] for r in rs if "server_mhz" in r]
        others = [r["others_cpus"] for r in rs if "others_cpus" in r]
        pipelined = [s for s in SCENARIOS if s[0] == scenario][0][3] > 1
        pct = lambda p: "–" if pipelined else _t(med([r["latency_us"][p] for r in rs]))
        print("| %s | %s | %s | %s | %s | %s | %.2f µs | %.0f%% | %s | %s |" % (
            scenario, kind, _k(med(rps)) + ("; %s–%s" % (_k(min(rps)), _k(max(rps))) if len(rps) > 1 else ""),
            _t(med([mean_latency_us(r) for r in rs])), pct("50%"), pct("99%"),
            med([r["server_us_per_req"] for r in rs]), 100 * med([r["wrk_cpu_share"] for r in rs]),
            "%.1f GHz" % (med(mhz) / 1000) if mhz else "?", "%.1f CPUs" % max(others) if others else "?"))


def _k(x):
    return "%.0fk" % (x / 1000)


def _t(us):
    return "%.0f µs" % us if us < 1000 else "%.2f ms" % (us / 1000)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build")
    cpus = argparse.ArgumentParser(add_help=False)
    cpus.add_argument("--server-cpus", type=lambda s: [int(c) for c in s.split(",")], default=None,
                      help="4 CPUs for the server (the 1-CPU scenarios use the first)")
    cpus.add_argument("--wrk-cpus", type=lambda s: [int(c) for c in s.split(",")], default=None)
    c = sub.add_parser("check", parents=[cpus])
    c.add_argument("--servers", type=lambda s: s.split(","), default=list(SERVERS))
    p = sub.add_parser("pgo", parents=[cpus])
    p.add_argument("--servers", type=lambda s: s.split(","), default=list(GO_SERVERS))
    p.add_argument("--seconds", type=int, default=10, help="profiled seconds per scenario")
    r = sub.add_parser("run", parents=[cpus])
    r.add_argument("--reps", type=int, default=1)
    r.add_argument("--duration", type=int, default=60)
    r.add_argument("--warmup", type=int, default=5)
    r.add_argument("--cooldown", type=int, default=15)
    r.add_argument("--quiet", type=float, default=1.0,
                   help="before each run, wait while the machine uses more CPUs than this (0: never wait)")
    r.add_argument("--quiet-wait", type=int, default=1800, help="the longest wait, in seconds, before running anyway")
    r.add_argument("--scenarios", type=lambda s: s.split(","), default=[])
    r.add_argument("--servers", type=lambda s: s.split(","), default=list(SERVERS))
    s = sub.add_parser("summary")
    s.add_argument("file")
    args = ap.parse_args()
    # (SIGTERM as an exception, so that a stopped run still stops its server and wrk)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    if args.cmd == "summary":
        with open(args.file) as f:
            summary(json.load(f))
        return
    {"build": build, "check": check, "run": run, "pgo": pgo}[args.cmd](args)


if __name__ == "__main__":
    main()
