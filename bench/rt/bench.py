#!/usr/bin/env python3
"""M2 gate harness: the rt-based echo servers against tokio current_thread
and the M1 spike's raw-epoll Mojo server, measured exactly like the spike
(docs/spikes.md, "10k-connection epoll spike").

It imports spikes/epoll_echo/bench.py and reuses its `run_one`: server
pinned to CPU 2 (taskset), clients on CPUs 3, 1, 0, all clients starting
at one CLOCK_MONOTONIC instant, server CPU from /proc utime+stime over the
steady-state window (second 1 to second duration-1), syscall counts from
the server's own STATS lines, RSS before/with all connections open.

    python3 bench/rt/bench.py gate [--reps 3] [--sizes 64,1024] [--duration 10]
        [--servers rt,rt-raw,mojo,tokio,rt-stock]
    python3 bench/rt/bench.py one --server rt --size 64 [--clients 3]

Results: bench/rt/out/gate-*.json plus a markdown summary on stdout.
Test/benchmark tooling only (Python is never on the measured I/O path).
"""

import argparse
import importlib.util
import json
import os
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(HERE, "out")
SPIKE = os.path.join(ROOT, "spikes", "epoll_echo")

_spec = importlib.util.spec_from_file_location("spike_bench", os.path.join(SPIKE, "bench.py"))
spike = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(spike)

spike.BIN.update(
    {
        # rt.evented TcpServer + ConnHandler (copying echo), counting driver.
        "rt": os.path.join(OUT, "rt_echo_server"),
        # Same, built with -D BENCH_STOCK_LOOP=1: rt's EventLoop, no counters.
        "rt-stock": os.path.join(OUT, "rt_echo_server_stock"),
        # Raw rt API, no rt.evented layer, counting driver.
        "rt-raw": os.path.join(OUT, "rt_raw_echo_server"),
        # The two above on rt with the proposed changes (bench/rt/rt_opt/).
        "rt-opt": os.path.join(OUT, "rt_echo_server_opt"),
        "rt-raw-opt": os.path.join(OUT, "rt_raw_echo_server_opt"),
        # The M1 spike server (raw epoll, no completion layer), rebuilt.
        "mojo": os.path.join(OUT, "spike_server"),
        "tokio": os.path.join(OUT, "tokio-target", "release", "tokio_echo"),
    }
)
spike.CLIENT = os.path.join(OUT, "client")


def med(xs):
    return statistics.median(xs) if xs else float("nan")


def summarize(runs, sizes, kinds):
    lines = [
        "| server | size B | runs | server CPU ns/msg median (min-max) | msgs/s median (min-max) "
        "| p50 / p99 us (median run) | syscalls/msg | user % | B/conn | CPU 6 busy % | errors |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for size in sizes:
        for kind in kinds:
            rs = [r for r in runs if r["server"] == kind and r["size"] == size]
            if not rs:
                continue
            ns = [r["cpu_ns_per_msg"] for r in rs]
            mps = [r["msgs_per_s"] for r in rs]
            mid = sorted(rs, key=lambda r: r["cpu_ns_per_msg"])[len(rs) // 2]
            sc = [r["syscalls_per_msg"] for r in rs if r["syscalls_per_msg"]]
            b6 = [100 * busy6(r) for r in rs]
            sc_txt = f"{med(sc):.2f}" if sc else "n/a"
            lines.append(
                f"| {kind} | {size} | {len(rs)} | {med(ns):,.0f} ({min(ns):,.0f}-{max(ns):,.0f}) "
                f"| {med(mps):,.0f} ({min(mps):,}-{max(mps):,}) "
                f"| {mid['p50_us']:.0f} / {mid['p99_us']:.0f} | {sc_txt} "
                f"| {100 * med([r['server_user_frac'] for r in rs]):.0f} "
                f"| {med([r['bytes_per_conn'] for r in rs]):,.0f} "
                f"| {min(b6):.0f}-{max(b6):.0f} "
                f"| {sum(r['errors'] for r in rs)} |"
            )
    return "\n".join(lines)


def gate(runs, sizes, base="tokio", cand="rt", limit=1.25):
    lines = [
        f"| size B | {cand} ns/msg (median) | {base} ns/msg (median) | ratio (median) "
        f"| ratio range (per rep) | gate <= {limit} |",
        "|---|---|---|---|---|---|",
    ]
    ok = True
    for size in sizes:
        a = [r for r in runs if r["server"] == cand and r["size"] == size]
        b = [r for r in runs if r["server"] == base and r["size"] == size]
        if not a or not b:
            continue
        ma, mb = med([r["cpu_ns_per_msg"] for r in a]), med([r["cpu_ns_per_msg"] for r in b])
        per_rep = []
        for rep in sorted({r["rep"] for r in a}):
            ra = [r["cpu_ns_per_msg"] for r in a if r["rep"] == rep]
            rb = [r["cpu_ns_per_msg"] for r in b if r["rep"] == rep]
            if ra and rb:
                per_rep.append(ra[0] / rb[0])
        ratio = ma / mb
        passed = ratio <= limit
        ok &= passed
        lines.append(
            f"| {size} | {ma:,.0f} | {mb:,.0f} | {ratio:.3f} "
            f"| {min(per_rep):.3f}-{max(per_rep):.3f} | {'PASS' if passed else 'FAIL'} |"
        )
    return ok, "\n".join(lines)


def cmd_gate(args):
    kinds = args.servers.split(",")
    sizes = [int(s) for s in args.sizes.split(",")]
    runs = []
    print(spike.HEADER, flush=True)
    for rep in range(args.reps):
        for size in sizes:
            # Rotate the order every repetition, so slow drift in background
            # load does not always hit the same server.
            order = kinds[rep % len(kinds):] + kinds[: rep % len(kinds)]
            for kind in order:
                r = spike.run_one(kind, size, args.idle, args.active, args.clients, args.duration)
                r["rep"] = rep
                runs.append(r)
                print(spike.fmt_row(r), flush=True)
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, f"gate-{time.strftime('%Y%m%d-%H%M%S')}.json")
    with open(path, "w") as f:
        json.dump(runs, f, indent=1)
    print()
    print(summarize(runs, sizes, kinds))
    print()
    ok, table = gate(runs, sizes)
    print(table)
    for extra in ("rt-opt", "rt-raw", "rt-raw-opt"):
        if extra in kinds:
            print()
            print(gate(runs, sizes, cand=extra)[1])
    print()
    print("M2 GATE (rt CPU ns/msg <= 1.25 x tokio current_thread):", "PASS" if ok else "FAIL")
    print("saved", path)


def busy6(r):
    b = r["cpu_busy"]
    return b.get(6, b.get("6", 0))


def split(runs, sizes, kinds, quiet=None):
    """User vs kernel CPU per message (medians): user time is what the
    server's own code costs; kernel time is the TCP stack, the same work
    for every server but inflated by load on the SMT sibling (CPU 6)."""
    lines = [
        "| server | size B | runs | user ns/msg median (min-max) | kernel ns/msg median (min-max) | total ns/msg median |",
        "|---|---|---|---|---|---|",
    ]
    for size in sizes:
        for kind in kinds:
            rs = [r for r in runs if r["server"] == kind and r["size"] == size]
            if quiet is not None:
                rs = [r for r in rs if busy6(r) <= quiet]
            if not rs:
                continue
            us = [r["cpu_ns_per_msg"] * r["server_user_frac"] for r in rs]
            ks = [r["cpu_ns_per_msg"] * (1 - r["server_user_frac"]) for r in rs]
            lines.append(
                f"| {kind} | {size} | {len(rs)} | {med(us):,.0f} ({min(us):,.0f}-{max(us):,.0f}) "
                f"| {med(ks):,.0f} ({min(ks):,.0f}-{max(ks):,.0f}) | {med([r['cpu_ns_per_msg'] for r in rs]):,.0f} |"
            )
    return "\n".join(lines)


def _fit(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx if sxx else 0.0
    a = my - b * mx
    resid = (sum((y - a - b * x) ** 2 for x, y in zip(xs, ys)) / max(1, n - 2)) ** 0.5
    return a, b, resid


def idle_fit(runs, sizes, kinds, base="tokio", limit=1.25):
    """Least-squares fit of ns/msg against CPU 6's busy fraction per server:
    the intercept estimates the cost on an idle SMT sibling, which the
    shared host never offered for long."""
    lines = [
        "| server | size B | runs | ns/msg at idle sibling | + per 100% sibling load | fit residual | user ns/msg at idle | ratio to tokio at idle |",
        "|---|---|---|---|---|---|---|---|",
    ]
    est = {}
    for size in sizes:
        for kind in kinds:
            rs = [r for r in runs if r["server"] == kind and r["size"] == size]
            if len(rs) < 3:
                continue
            xs = [busy6(r) for r in rs]
            a, b, e = _fit(xs, [r["cpu_ns_per_msg"] for r in rs])
            au, _, _ = _fit(xs, [r["cpu_ns_per_msg"] * r["server_user_frac"] for r in rs])
            est[(kind, size)] = (len(rs), a, b, e, au)
        for kind in kinds:
            if (kind, size) not in est:
                continue
            n, a, b, e, au = est[(kind, size)]
            ratio = a / est[(base, size)][1] if (base, size) in est else float("nan")
            verdict = "" if kind == base else (" PASS" if ratio <= limit else " FAIL")
            lines.append(f"| {kind} | {size} | {n} | {a:,.0f} | {b:,.0f} | {e:,.0f} | {au:,.0f} | {ratio:.2f}{verdict} |")
    return "\n".join(lines)


def cmd_report(args):
    runs = []
    for path in args.files:
        with open(path) as f:
            runs += json.load(f)
    sizes = sorted({r["size"] for r in runs})
    kinds = [k for k in ("rt", "rt-opt", "rt-raw", "rt-raw-opt", "rt-stock", "mojo", "tokio")
             if any(r["server"] == k for r in runs)]
    print(summarize(runs, sizes, kinds))
    print()
    print(split(runs, sizes, kinds))
    print()
    print(f"Runs with CPU 6 (the server core's SMT sibling) at most {args.quiet:.0%} busy:")
    print(split(runs, sizes, kinds, quiet=args.quiet))
    for cand in kinds:
        if cand.startswith("rt"):
            print()
            print(gate(runs, sizes, cand=cand)[1])
    print()
    print("Fit against sibling load (all runs given):")
    print(idle_fit(runs, sizes, kinds))


def cmd_one(args):
    r = spike.run_one(args.server, args.size, args.idle, args.active, args.clients, args.duration)
    print(spike.HEADER)
    print(spike.fmt_row(r))
    keep = ("cpu_ns_per_msg", "msgs_per_s", "syscalls_per_msg", "events_per_wait",
            "server_user_frac", "bytes_per_conn", "cpu_busy", "server_delta")
    print(json.dumps({k: r[k] for k in keep}, indent=1))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gate")
    g.add_argument("--reps", type=int, default=3)
    g.add_argument("--sizes", default="64,1024")
    g.add_argument("--servers", default="rt,rt-raw,mojo,tokio")
    rp = sub.add_parser("report")
    rp.add_argument("files", nargs="+")
    rp.add_argument("--quiet", type=float, default=0.3)
    o = sub.add_parser("one")
    o.add_argument("--server", default="rt")
    o.add_argument("--size", type=int, default=64)
    for p in (g, o):
        p.add_argument("--idle", type=int, default=10000)
        p.add_argument("--active", type=int, default=1000)
        p.add_argument("--clients", type=int, default=3)
        p.add_argument("--duration", type=int, default=10)
    args = ap.parse_args()
    if args.cmd == "gate":
        cmd_gate(args)
    elif args.cmd == "report":
        cmd_report(args)
    else:
        cmd_one(args)


if __name__ == "__main__":
    sys.exit(main())
