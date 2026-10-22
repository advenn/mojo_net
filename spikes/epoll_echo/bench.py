#!/usr/bin/env python3
"""Orchestrates the 10k-connection epoll spike (docs/spikes.md).

For every scenario it starts a server (the Mojo one or the C baseline),
pinned with taskset, and one or more client processes (client.mojo) pinned
to other cores. All clients start their load at the same CLOCK_MONOTONIC
instant. While they run, the script samples from /proc:
- the server's VmRSS with 0 connections, mid-load, and with all connections
  open after the load (`--hold`);
- the server's CPU time (utime/stime) over the steady-state window;
- the server's own syscall counters (its STATS lines, every 500 ms) over
  the same window.
Then it merges the clients' RESULT and HIST lines.

Usage (after spikes/epoll_echo/run.sh has built out/server, out/client and
out/baseline):

    python3 spikes/epoll_echo/bench.py matrix      # the spike's runs
    python3 spikes/epoll_echo/bench.py emfile      # EMFILE handling check
    python3 spikes/epoll_echo/bench.py one --server mojo --size 64 \
        --idle 10000 --active 1000 --clients 1 --duration 10

Test/benchmark tooling only: Python is used here as a harness, never on the
measured I/O path.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
BIN = {
    "mojo": os.path.join(OUT, "server"),
    "c": os.path.join(OUT, "baseline"),
    # Optional: tokio current_thread (spikes/epoll_echo/tokio_echo), built by
    # run.sh when cargo and the crates are available offline.
    "tokio": os.path.join(OUT, "tokio-target", "release", "tokio_echo"),
}
CLIENT = os.path.join(OUT, "client")
CLK_TCK = os.sysconf("SC_CLK_TCK")

# CPU topology of the reference host (i5-1145G7): SMT siblings are (n, n+4).
# The server gets core 2, and clients get cores 3, 1 and 0, so no client
# shares a physical core with the server.
SERVER_CPU = "2"
CLIENT_CPUS = ["3", "1", "0"]

# ---- histogram (same layout as echo_util.mojo) -------------------------------

SUB = 64


def hist_upper(idx):
    if idx < SUB:
        return idx
    shift = (idx - SUB) // SUB
    m = (idx - SUB) % SUB + SUB
    return ((m + 1) << shift) - 1


def merged_percentile(counts, total, p, vmax):
    if total == 0:
        return 0
    rank = max(1, int(total * p / 100.0 + 0.999999))
    seen = 0
    for idx in sorted(counts):
        seen += counts[idx]
        if seen >= rank:
            return min(hist_upper(idx), vmax)
    return vmax


# ---- /proc -------------------------------------------------------------------


def rss_kb(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return -1


def status_fields(pid, names):
    out = {}
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            k, _, v = line.partition(":")
            if k in names:
                out[k] = v.strip()
    return out


def cpu_ticks(pid):
    """(utime, stime) in clock ticks for the whole process."""
    with open(f"/proc/{pid}/stat") as f:
        s = f.read()
    rest = s[s.rindex(")") + 2 :].split()
    return int(rest[11]), int(rest[12])  # fields 14 and 15


def cpu_times():
    """Per-CPU (busy, total) jiffies from /proc/stat."""
    out = {}
    with open("/proc/stat") as f:
        for line in f:
            if line.startswith("cpu") and line[3].isdigit():
                p = line.split()
                v = [int(x) for x in p[1:]]
                idle = v[3] + v[4]  # idle + iowait
                out[int(p[0][3:])] = (sum(v[:8]) - idle, sum(v[:8]))
    return out


def cpu_busy(a, b):
    return {
        c: round((b[c][0] - a[c][0]) / max(1, b[c][1] - a[c][1]), 2) for c in sorted(b)
    }


def meminfo(names=("Slab", "SUnreclaim", "MemAvailable")):
    out = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, _, v = line.partition(":")
            if k in names:
                out[k] = int(v.split()[0])
    return out


def sockstat():
    with open("/proc/net/sockstat") as f:
        for line in f:
            if line.startswith("TCP:"):
                p = line.split()
                return {p[i]: int(p[i + 1]) for i in range(1, len(p) - 1, 2)}
    return {}


def kv(line):
    return dict(m.groups() for m in re.finditer(r"(\w+)=(\S+)", line))


# ---- processes ---------------------------------------------------------------


class Proc:
    """A child whose stdout lines are collected by a thread."""

    def __init__(self, argv, cpu=None):
        if cpu is not None:
            argv = ["taskset", "-c", cpu] + argv
        self.argv = argv
        self.p = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        self.lines = []
        self.t = threading.Thread(target=self._pump, daemon=True)
        self.t.start()

    def _pump(self):
        for line in self.p.stdout:
            self.lines.append((time.monotonic_ns(), line.rstrip("\n")))

    def wait_line(self, prefix, timeout):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            for _, l in self.lines:
                if l.startswith(prefix):
                    return l
            if self.p.poll() is not None and not self.t.is_alive():
                break
            time.sleep(0.01)
        raise RuntimeError(
            f"no {prefix!r} line from {self.argv}: {self.lines[-10:]}"
        )

    def find(self, prefix):
        return [l for _, l in self.lines if l.startswith(prefix)]

    def kill(self):
        if self.p.poll() is None:
            self.p.kill()
        self.p.wait()
        self.t.join(timeout=2)


def start_server(kind, extra=()):
    stats = [] if kind == "tokio" else ["--stats-ms", "500"]
    srv = Proc([BIN[kind], "--port", "0", *stats, *extra], SERVER_CPU)
    line = srv.wait_line("LISTEN ", 10)
    m = re.search(r"LISTEN [\d.]+:(\d+) pid=(\d+)", line)
    port, pid = int(m.group(1)), int(m.group(2))
    return srv, port, pid, line


def stats_near(srv, t_ns, tag="STATS"):
    """The server STATS line whose mono_ns is closest to `t_ns`."""
    best = None
    for l in srv.find(tag):
        d = kv(l)
        dt = abs(int(d["mono_ns"]) - t_ns)
        if best is None or dt < best[0]:
            best = (dt, d)
    return best[1] if best else None


def run_one(kind, size, idle, active, nclients, duration, extra_server=(), hold=3, lead=6.0):
    srv, port, pid, listen_line = start_server(kind, extra_server)
    clients = []
    try:
        time.sleep(0.5)
        threads0 = status_fields(pid, {"Threads"}).get("Threads")
        rss0 = rss_kb(pid)
        sock0 = sockstat()
        mem0 = meminfo()
        start_at = time.monotonic_ns() + int(lead * 1e9)
        for i in range(nclients):
            ci = idle // nclients + (1 if i < idle % nclients else 0)
            ca = active // nclients + (1 if i < active % nclients else 0)
            clients.append(
                Proc(
                    [
                        CLIENT,
                        "--port", str(port),
                        "--idle", str(ci),
                        "--active", str(ca),
                        "--size", str(size),
                        "--duration", str(duration),
                        "--start-at-ns", str(start_at),
                        "--hold", str(hold),
                        "--tag", f"c{i}",
                    ],
                    CLIENT_CPUS[i % len(CLIENT_CPUS)],
                )
            )
        connected = [c.wait_line("CONNECTED", lead + 30) for c in clients]
        late = time.monotonic_ns() > start_at
        # Steady-state window: skip the first and last second of the load.
        t1 = start_at + int(1e9)
        t2 = start_at + int((duration - 1) * 1e9)
        while time.monotonic_ns() < t1:
            time.sleep(0.005)
        cpu1, w1 = cpu_ticks(pid), time.monotonic_ns()
        cl_cpu1 = [cpu_ticks(c.p.pid) for c in clients]
        all1 = cpu_times()
        while time.monotonic_ns() < start_at + int(duration * 1e9 / 2):
            time.sleep(0.005)
        rss_load = rss_kb(pid)
        while time.monotonic_ns() < t2:
            time.sleep(0.005)
        cpu2, w2 = cpu_ticks(pid), time.monotonic_ns()
        cl_cpu2 = [cpu_ticks(c.p.pid) for c in clients]
        all2 = cpu_times()
        # During --hold: all connections open, no traffic.
        while time.monotonic_ns() < start_at + int((duration + 1.5) * 1e9):
            time.sleep(0.005)
        rss_conn = rss_kb(pid)
        sock_conn = sockstat()
        mem_conn = meminfo()
        st_hold = status_fields(pid, {"VmRSS", "RssAnon", "RssFile", "VmHWM", "Threads"})
        for c in clients:
            c.p.wait(timeout=duration + hold + 60)
            c.t.join(timeout=5)
        time.sleep(1.0)  # let the server process the resets
        rss_after = rss_kb(pid)
        st_lines = srv.find("STATS")
        open_after = kv(st_lines[-1]).get("open") if st_lines else None
    finally:
        srv.kill()
        for c in clients:
            c.kill()

    results = [kv(c.find("RESULT")[0]) for c in clients]
    counts, total, vmax = {}, 0, 0
    for c in clients:
        h = c.find("HIST")[0]
        for part in h.split(" ", 2)[2].split(","):
            if part:
                i, n = part.split(":")
                counts[int(i)] = counts.get(int(i), 0) + int(n)
                total += int(n)
    for r in results:
        vmax = max(vmax, int(r["max_ns"]))
    s1, s2 = stats_near(srv, t1), stats_near(srv, t2)
    cpu_s = (w2 - w1) / 1e9
    if s1 and s2:
        d = {k: int(s2[k]) - int(s1[k]) for k in s1 if k not in ("mono_ns",) and s1[k].lstrip("-").isdigit()}
        win_s = (int(s2["mono_ns"]) - int(s1["mono_ns"])) / 1e9
        msgs_win = d["bytes_in"] / size
    else:  # tokio: no counters; use the clients' rate over the CPU window
        d = None
        win_s = cpu_s
        msgs_win = sum(int(r["msgs_per_s"]) for r in results) * cpu_s

    def per_msg(k):
        return d[k] / max(1, msgs_win) if d else None

    utime = (cpu2[0] - cpu1[0]) / CLK_TCK
    stime = (cpu2[1] - cpu1[1]) / CLK_TCK
    cl_cpu = [
        ((b[0] - a[0]) + (b[1] - a[1])) / CLK_TCK / cpu_s for a, b in zip(cl_cpu1, cl_cpu2)
    ]
    out = {
        "server": kind,
        "server_args": list(extra_server),
        "size": size,
        "idle": idle,
        "active": active,
        "clients": nclients,
        "duration_s": duration,
        "listen": listen_line,
        "late_start": late,
        "connected": connected,
        "established": sum(int(r["established"]) for r in results),
        "connect_failed": sum(int(r["connect_failed"]) for r in results),
        "connect_ms_max": max(int(r["connect_ms"]) for r in results),
        "msgs": sum(int(r["msgs"]) for r in results),
        "msgs_per_s": sum(int(r["msgs_per_s"]) for r in results),
        "p50_us": merged_percentile(counts, total, 50, vmax) / 1e3,
        "p99_us": merged_percentile(counts, total, 99, vmax) / 1e3,
        "p999_us": merged_percentile(counts, total, 99.9, vmax) / 1e3,
        "max_us": vmax / 1e3,
        "errors": sum(
            int(r["mismatches"]) + int(r["resets"]) + int(r["idle_lost"])
            for r in results
        ),
        "still_open": sum(int(r["still_open"]) for r in results),
        "server_threads": threads0,
        "rss0_kb": rss0,
        "rss_load_kb": rss_load,
        "rss_conn_kb": rss_conn,
        "rss_after_close_kb": rss_after,
        "open_after_close": open_after,
        "hold_status": st_hold,
        "bytes_per_conn": (rss_conn - rss0) * 1024 / max(1, idle + active),
        # Kernel side, whole host (noisy: other processes allocate too). Both
        # ends of every connection live on this host: 2 sockets per conn.
        "meminfo0": mem0,
        "meminfo_conn": mem_conn,
        "kernel_slab_kb_per_socket": (mem_conn["Slab"] - mem0["Slab"]) / max(1, 2 * (idle + active)),
        "sockstat0": sock0,
        "sockstat_conn": sock_conn,
        "server_cpu_util": (utime + stime) / cpu_s,
        "server_user_frac": utime / max(1e-9, utime + stime),
        "client_cpu_util": cl_cpu,
        # Busy fraction of every CPU over the window. CPU 6 is the server
        # core's SMT sibling: when other work runs there, the server slows.
        "cpu_busy": cpu_busy(all1, all2),
        "win_s": win_s,
        "server_msgs_per_s_window": msgs_win / win_s,
        "syscalls_per_msg": per_msg("syscalls"),
        "recvs_per_msg": per_msg("recvs"),
        "sends_per_msg": per_msg("sends"),
        "waits_per_msg": per_msg("waits"),
        "events_per_wait": d["events"] / max(1, d["waits"]) if d else None,
        "recv_eagain_per_msg": per_msg("recv_eagain"),
        "cpu_ns_per_msg": (utime + stime) * 1e9 / max(1, msgs_win) * (win_s / cpu_s),
        "server_delta": d,
        "results": results,
    }
    return out


def label(r):
    extra = " " + " ".join(r["server_args"]) if r["server_args"] else ""
    return f"{r['server']}{extra}"


def opt(v, f):
    return "n/a" if v is None else format(v, f)


def fmt_row(r):
    busy = r.get("cpu_busy", {})
    return (
        f"| {label(r)} | {r['size']} | {r['active']} | {r['clients']} "
        f"| {r['established']}/{r['idle'] + r['active']} "
        f"| {r['msgs_per_s']:,} | {r['p50_us']:.0f} | {r['p99_us']:.0f} | {r['max_us']:.0f} "
        f"| {r['errors']} | {100 * r['server_cpu_util']:.0f}% ({100 * r['server_user_frac']:.0f}% user) "
        f"| {opt(r['syscalls_per_msg'], '.2f')} | {opt(r['events_per_wait'], '.0f')} | {r['cpu_ns_per_msg']:.0f} "
        f"| {r['rss0_kb'] / 1024:.1f} → {r['rss_conn_kb'] / 1024:.1f} MiB ({r['bytes_per_conn']:.0f} B/conn) "
        f"| {100 * busy.get(6, 0):.0f}% |"
    )


HEADER = (
    "| server | size B | active | client procs | established | msgs/s | p50 µs | p99 µs | max µs "
    "| errors | server CPU | syscalls/msg | events/wait | server CPU ns/msg | server RSS 0 → 11k "
    "| CPU 6 busy |\n"
    "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"
)


def median(xs):
    xs = sorted(xs)
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def summary(runs):
    """Median (min-max) per configuration over the repetitions."""
    groups = {}
    for r in runs:
        key = (label(r), r["size"], r["active"], r["clients"])
        groups.setdefault(key, []).append(r)
    lines = [
        "| server | size B | active | client procs | runs | msgs/s median (min-max) "
        "| server CPU ns/msg median (min-max) | p50 / p99 µs (median run) | syscalls/msg | errors |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for key, rs in groups.items():
        mps = [r["msgs_per_s"] for r in rs]
        ns = [r["cpu_ns_per_msg"] for r in rs]
        mid = sorted(rs, key=lambda r: r["msgs_per_s"])[len(rs) // 2]
        lines.append(
            f"| {key[0]} | {key[1]} | {key[2]} | {key[3]} | {len(rs)} "
            f"| {median(mps):,.0f} ({min(mps):,}-{max(mps):,}) "
            f"| {median(ns):,.0f} ({min(ns):,.0f}-{max(ns):,.0f}) "
            f"| {mid['p50_us']:.0f} / {mid['p99_us']:.0f} "
            f"| {opt(rs[0]['syscalls_per_msg'] and median([r['syscalls_per_msg'] for r in rs]), '.2f')} "
            f"| {sum(r['errors'] for r in rs)} |"
        )
    return "\n".join(lines)


def save(name, results):
    path = os.path.join(OUT, f"{name}-{time.strftime('%Y%m%d-%H%M%S')}.json")
    with open(path, "w") as f:
        json.dump(results, f, indent=1)
    return path


def matrix(args):
    """The spike's runs; Mojo and C alternate so slow drift in background
    load hits both."""
    plan = []
    total = args.idle + args.active
    kinds = args.servers.split(",")
    for ncl in (1, 3):
        for size in (64, 1024):
            for kind in kinds:
                plan.append((kind, size, args.idle, args.active, ncl, ()))
    if args.strict:
        for kind in kinds:
            if kind != "tokio":
                plan.append((kind, 64, args.idle, args.active, 3, ("--strict-eagain",)))
    for kind in kinds:  # unloaded latency: one busy connection
        plan.append((kind, 64, total - 1, 1, 1, ()))
    runs = []
    print(HEADER, flush=True)
    for rep in range(args.reps):
        for kind, size, idle, active, ncl, extra in plan:
            r = run_one(kind, size, idle, active, ncl, args.duration, extra)
            r["rep"] = rep
            runs.append(r)
            print(fmt_row(r), flush=True)
    path = save("matrix", runs)
    print()
    print(summary(runs))
    print("saved", path)


def one(args):
    extra = tuple(args.server_arg or ())
    r = run_one(args.server, args.size, args.idle, args.active, args.clients, args.duration, extra)
    print(HEADER)
    print(fmt_row(r))
    print(json.dumps({k: v for k, v in r.items() if k not in ("results",)}, indent=1))


def tcpext():
    """TcpExt counters from /proc/net/netstat (host-wide)."""
    with open("/proc/net/netstat") as f:
        lines = f.read().split("\n")
    for i in range(0, len(lines) - 1, 2):
        if lines[i].startswith("TcpExt:"):
            return dict(zip(lines[i].split()[1:], map(int, lines[i + 1].split()[1:])))
    return {}


def burst(args):
    """Connect phase only: 3 clients open 11001 idle connections at once.
    Counts listen-queue overflows (each one is a SYN or handshake ACK the
    kernel dropped, retried by the client after a 1 s timeout). Compares the
    Mojo server with and without --prealloc-fds against the C server."""
    configs = [("mojo", ()), ("mojo", ("--prealloc-fds", "32768")), ("c", ())]
    if os.path.exists(BIN["tokio"]):
        configs.append(("tokio", ()))
    rows = {i: [] for i in range(len(configs))}
    for rep in range(args.reps):
        for i, (kind, extra) in enumerate(configs):
            srv, port, pid, _ = start_server(kind, extra)
            time.sleep(0.3)
            a = tcpext()
            cl = [
                Proc([CLIENT, "--port", str(port), "--idle", "3667", "--active", "0",
                      "--duration", "1", "--tag", f"c{j}"], CLIENT_CPUS[j])
                for j in range(3)
            ]
            lines = [c.wait_line("CONNECTED", 30) for c in cl]
            b = tcpext()
            for c in cl:
                c.kill()
            srv.kill()
            ms = max(int(kv(l)["connect_ms"]) for l in lines)
            est = sum(int(kv(l)["established"]) for l in lines)
            ov = b["ListenOverflows"] - a["ListenOverflows"]
            rows[i].append((ms, ov, est))
            print(f"{kind} {' '.join(extra)}: connect {ms} ms, {ov} listen overflows, {est} established", flush=True)
    print("| server | runs | runs with overflows | connect ms (each run) |")
    print("|---|---|---|---|")
    for i, (kind, extra) in enumerate(configs):
        r = rows[i]
        print(f"| {kind} {' '.join(extra)} | {len(r)} | {sum(1 for x in r if x[1] > 0)} "
              f"| {', '.join(str(x[0]) for x in r)} |")


def emfile(args):
    """Server limited to --nofile 64 (about 59 connections), client opens 100
    idle + 4 active. The server must log the exhaustion, keep serving what it
    accepted, resume after the client resets everything, and then serve a
    fresh client."""
    ok = True
    for kind in ("mojo", "c"):
        srv, port, pid, _ = start_server(kind, ("--nofile", "64"))
        try:
            c1 = Proc([CLIENT, "--port", str(port), "--idle", "100", "--active", "4",
                       "--size", "64", "--duration", "2", "--connect-timeout", "10"], CLIENT_CPUS[0])
            c1.p.wait(timeout=60)
            c1.t.join(timeout=5)
            r1 = kv(c1.find("RESULT")[0])
            time.sleep(1.5)  # a stats tick: the server retries accept
            mid = kv(srv.find("STATS")[-1])
            c2 = Proc([CLIENT, "--port", str(port), "--idle", "0", "--active", "2",
                       "--size", "64", "--duration", "1"], CLIENT_CPUS[0])
            c2.p.wait(timeout=60)
            c2.t.join(timeout=5)
            r2 = kv(c2.find("RESULT")[0])
            time.sleep(1.0)
            end = kv(srv.find("STATS")[-1])
            alive = srv.p.poll() is None
        finally:
            srv.kill()
        log = [l for _, l in srv.lines if l.startswith("accept:")]
        checks = {
            "server alive": alive,
            "logged pause": any("pausing accepts" in l for l in log),
            "logged resume": any("resumed" in l for l in log),
            "accept_exhausted > 0": int(end["accept_exhausted"]) > 0,
            "client1 established 104 (kernel backlog)": r1["established"] == "104",
            "client1 got echoes on accepted conns": int(r1["msgs"]) > 0,
            "no fd left open after client1": mid["open"] == "0",
            "fresh client served": int(r2["msgs"]) > 0 and r2["resets"] == "0",
        }
        print(f"== EMFILE check, {kind} server (--nofile 64)")
        print("  server log:", log)
        print("  client1:", {k: r1[k] for k in ("established", "msgs", "resets", "idle_lost", "mismatches")})
        print("  client2:", {k: r2[k] for k in ("established", "msgs", "resets", "mismatches")})
        print("  server end:", {k: end[k] for k in ("open", "accepted", "accept_exhausted", "resets", "closes")})
        for k, v in checks.items():
            print(f"  {'ok  ' if v else 'FAIL'} {k}")
            ok &= bool(v)
    print("EMFILE CHECK:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("matrix")
    m.add_argument("--idle", type=int, default=10000)
    m.add_argument("--active", type=int, default=1000)
    m.add_argument("--duration", type=int, default=10)
    m.add_argument("--reps", type=int, default=1)
    m.add_argument("--servers", default="mojo,c", help="comma list of mojo,c,tokio")
    m.add_argument("--no-strict", dest="strict", action="store_false",
                   help="skip the --strict-eagain runs")
    o = sub.add_parser("one")
    o.add_argument("--server", choices=("mojo", "c", "tokio"), default="mojo")
    o.add_argument("--size", type=int, default=64)
    o.add_argument("--idle", type=int, default=10000)
    o.add_argument("--active", type=int, default=1000)
    o.add_argument("--clients", type=int, default=1)
    o.add_argument("--duration", type=int, default=10)
    o.add_argument("--server-arg", action="append")
    sub.add_parser("emfile")
    b = sub.add_parser("burst")
    b.add_argument("--reps", type=int, default=5)
    args = ap.parse_args()
    if args.cmd == "matrix":
        matrix(args)
    elif args.cmd == "one":
        one(args)
    elif args.cmd == "burst":
        burst(args)
    else:
        sys.exit(emfile(args))


if __name__ == "__main__":
    main()
