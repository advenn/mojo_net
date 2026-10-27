#!/usr/bin/env python3
"""Where each server's user time goes: mojo (plaintext_profile.mojo) and
hyper under valgrind's callgrind, which counts the instructions every
function and source line runs. README.md ("Why mojo is slower") has what
it found.

    pixi run -e bench bench-profile [--servers mojo,hyper] [--seconds 10]
                                    [--connections 16] [--pipelined 16]

Each server is built for x86-64-v3 (valgrind has no AVX-512) with line
tables, run on one CPU under callgrind, warmed up for 3 s with wrk, its
counters zeroed, loaded for --seconds, and dumped. The instructions
counted, divided by the requests wrk saw answered, are per request; they
are user space only (the kernel's share is the same for every server:
README.md). Each run prints its totals by object, source file and
function, and the results go to bench/server/out/profile-<time>.json (the
callgrind files stay in out/ for callgrind_annotate or kcachegrind).
"""

import argparse
import collections
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time

import run as bench

HERE = bench.HERE
OUT = bench.OUT
ROOT = bench.ROOT
MOJO_BIN = os.path.join(OUT, "plaintext_profile")
HYPER_TARGET = os.path.join(OUT, "hyper-profile-target")
HYPER_BIN = os.path.join(HYPER_TARGET, "release", "hyper_plaintext")


def build(servers):
    env = dict(os.environ)
    if "mojo" in servers:
        subprocess.run(["mojo", "build", "-I", "src", "--target-cpu", "x86-64-v3", "--debug-level", "line-tables",
                        "bench/server/plaintext_profile.mojo", "-o", MOJO_BIN], cwd=ROOT, check=True)
    if "hyper" in servers:
        env.update(RUSTFLAGS="-C target-cpu=x86-64-v3", CARGO_PROFILE_RELEASE_DEBUG="line-tables-only",
                   CARGO_TARGET_DIR=HYPER_TARGET)
        subprocess.run(["cargo", "build", "--release", "--locked"], cwd=os.path.join(HERE, "hyper"), env=env, check=True)


def callgrind(kind, args, server_cpu, wrk_cpus, stamp):
    """Run one server under callgrind: (callgrind file, requests counted)."""
    binary = {"mojo": MOJO_BIN, "hyper": HYPER_BIN}[kind]
    port = bench.free_port()
    out = os.path.join(OUT, "callgrind.%s.%s" % (kind, stamp))
    env = dict(os.environ, WORKERS="0" if kind == "mojo" else "1")
    p = subprocess.Popen(["taskset", "-c", str(server_cpu), "valgrind", "--tool=callgrind",
                          "--callgrind-out-file=" + out, binary, "127.0.0.1:%d" % port],
                         env=env, stdout=subprocess.DEVNULL, stderr=open(out + ".log", "w"), start_new_session=True)
    try:
        end = time.time() + 60
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                if time.time() > end or p.poll() is not None:
                    raise RuntimeError("%s did not start under valgrind: see %s.log" % (kind, out))
                time.sleep(0.5)
        threads = min(2, len(wrk_cpus))
        def load(seconds):
            url = "http://127.0.0.1:%d/plaintext" % port
            cmd = ["taskset", "-c", bench._cpulist(wrk_cpus), "wrk", "-t%d" % threads, "-c%d" % args.connections,
                   "-d%ds" % seconds, "--timeout", "10s"]
            cmd += ["-s", bench.PIPELINE_LUA, url, "--", str(args.pipelined)] if args.pipelined > 1 else [url]
            text = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
            return int(re.search(r"(\d+) requests in", text).group(1))
        load(3)
        subprocess.run(["callgrind_control", "-z", str(p.pid)], capture_output=True, check=True)
        n = load(args.seconds)
        subprocess.run(["callgrind_control", "-d", str(p.pid)], capture_output=True, check=True)
        time.sleep(1)
    finally:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait()
    return out + ".1", n


def self_costs(path):
    """Instructions by (object, function) and by (file, line), each counted
    where it ran (self cost), from a callgrind out file."""
    names = {"fn": {}, "ob": {}, "fl": {}}

    def resolve(kind, val):
        m = re.match(r"\((\d+)\)(?: (.*))?", val)
        if not m:
            return val
        if m.group(2) is not None:
            names[kind][m.group(1)] = m.group(2)
        return names[kind].get(m.group(1), val)

    by_fn, by_line = collections.Counter(), collections.Counter()
    fn = ob = fl = None
    line_no, after_calls = 0, False
    for line in open(path, errors="replace"):
        line = line.rstrip("\n")
        if not line or line[0] == "#":
            continue
        key, eq, val = line.partition("=")
        if eq and key in ("ob", "fl", "fi", "fe", "fn", "cob", "cfi", "cfl", "cfn", "calls"):
            if key == "ob":
                ob = resolve("ob", val)
            elif key in ("fl", "fi", "fe"):
                fl = resolve("fl", val)
            elif key == "fn":
                fn = resolve("fn", val)
            elif key in ("cob", "cfi", "cfl", "cfn"):
                resolve({"cob": "ob", "cfn": "fn"}.get(key, "fl"), val)
            else:
                after_calls = True
            continue
        parts = line.split()
        if len(parts) < 2 or not parts[1].isdigit():
            continue
        pos = parts[0]
        if pos[0] in "+-" and pos[1:].isdigit():
            line_no += int(pos)
        elif pos.isdigit():
            line_no = int(pos)
        elif pos != "*":
            continue
        if after_calls:  # (the inclusive cost of a call: counted in the callee)
            after_calls = False
            continue
        by_fn[(ob, fn)] += int(parts[1])
        by_line[(fl, line_no)] += int(parts[1])
    return by_fn, by_line


def _short_file(f):
    f = f or "?"
    for marker in ("mojo_tcp/", "mojo_net/", "stdlib/", "/src/", "registry/src/"):
        if marker in f:
            return f.split(marker, 1)[-1]
    return f


def report(kind, path, n, top):
    by_fn, by_line = self_costs(path)
    total = sum(by_fn.values())
    by_ob, by_file = collections.Counter(), collections.Counter()
    for (o, _), c in by_fn.items():
        by_ob[(o or "?").split("/")[-1]] += c
    for (f, _), c in by_line.items():
        by_file[_short_file(f)] += c
    per = lambda c: c / n
    print("\n%s: %d requests, %.0f instructions a request" % (kind, n, per(total)))
    for title, counter in (("object", by_ob), ("source file", by_file)):
        print("  by %s:" % title)
        for name, c in counter.most_common(top):
            print("    %7.0f  %5.1f%%  %s" % (per(c), 100 * c / total, name))
    print("  by function:")
    for (o, f), c in by_fn.most_common(top):
        print("    %7.0f  %5.1f%%  %s" % (per(c), 100 * c / total, (f or "?")[:110]))
    return {
        "requests": n,
        "instructions_per_request": per(total),
        "by_object": {k: per(c) for k, c in by_ob.most_common(top)},
        "by_file": {k: per(c) for k, c in by_file.most_common(top)},
        "by_function": [[f, per(c)] for (o, f), c in by_fn.most_common(top)],
        "by_line": [["%s:%d" % (_short_file(f), l), per(c)] for (f, l), c in by_line.most_common(top)],
        "callgrind_file": os.path.relpath(path, ROOT),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--servers", type=lambda s: s.split(","), default=["mojo", "hyper"])
    ap.add_argument("--seconds", type=int, default=10)
    ap.add_argument("--connections", type=int, default=16)
    ap.add_argument("--pipelined", type=int, default=16)
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--no-build", action="store_true")
    args = ap.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    os.makedirs(OUT, exist_ok=True)
    if not args.no_build:
        build(args.servers)
    server_cpus, wrk_cpus = bench.layout()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    results = {"versions": bench.versions(server_cpus, wrk_cpus), "connections": args.connections,
               "pipelined": args.pipelined, "seconds": args.seconds, "servers": {}}
    for kind in args.servers:
        path, n = callgrind(kind, args, server_cpus[0], wrk_cpus, stamp)
        results["servers"][kind] = report(kind, path, n, args.top)
    path = os.path.join(OUT, "profile-%s.json" % stamp)
    with open(path, "w") as f:
        json.dump(results, f, indent=1)
    print("\nwrote", path)


if __name__ == "__main__":
    main()
