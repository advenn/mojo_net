#!/usr/bin/env python3
"""The cost check: user-space instructions per request of the HTTP codecs
(bench/http/codec.mojo) under valgrind's callgrind, against a base commit
built and counted the same way on the same machine. A rise of more than
--tolerance percent in any shape fails, naming it; a fall of more says so,
so that the gain gets recorded (bench/http/README.md).

The HR3 and SR2 reviews took the server's codec from ~8,300 to ~4,800
instructions a request; nothing guarded that until this (2026-11 analysis,
finding perf-budget-gate). Instructions, unlike time, do not change with
the load on the machine, and the base is counted beside the head, so the
check holds on a shared runner. Startup is cancelled out: each shape runs
with one round and with two, and their difference is one round of
bench/http/codec.mojo's N requests.

    python3 tools/check_perf.py [--base REV] [--tolerance 3] [--shapes wrk,browser,client]

x86_64 only (callgrind; Mojo builds for x86-64-v3, since valgrind has no
AVX-512). CI runs it on every push to main against the commit before it
(.github/workflows/perf.yml); `pixi run -e perf perf-check` runs it here
against HEAD~1, or --base.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = "bench/http/codec.mojo"
N = 200_000  # (requests a round: codec.mojo's N)


def build(tree, out):
    """Build the codec benchmark of `tree` into `out`: False if that tree
    has none."""
    if not os.path.exists(os.path.join(tree, BENCH)):
        return False
    subprocess.run(
        ["mojo", "build", "-I", os.path.join(tree, "src"), "--target-cpu", "x86-64-v3",
         "--debug-level", "line-tables", os.path.join(tree, BENCH), "-o", out],
        check=True, cwd=tree,
    )
    return True


def instructions(exe, rounds, shape, work):
    """Every instruction callgrind counts in one run."""
    out = os.path.join(work, "cg.%s.%d" % (shape, rounds))
    subprocess.run(
        ["valgrind", "--tool=callgrind", "--callgrind-out-file=" + out, exe, str(rounds), shape],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    with open(out) as f:
        for line in f:
            m = re.match(r"(?:summary|totals):\s+(\d+)", line)
            if m:
                return int(m.group(1))
    raise RuntimeError("no totals in " + out)


def per_request(exe, shape, work):
    return (instructions(exe, 2, shape, work) - instructions(exe, 1, shape, work)) / N


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", default="HEAD~1", help="the commit to compare with")
    ap.add_argument("--tolerance", type=float, default=3.0, help="percent")
    ap.add_argument("--shapes", type=lambda s: s.split(","), default=["wrk", "browser", "client"])
    args = ap.parse_args()
    base = subprocess.run(["git", "rev-parse", "--verify", args.base + "^{commit}"], cwd=ROOT,
                          capture_output=True, text=True)
    if base.returncode != 0:
        print("skip: no base commit %s here (a shallow clone?)" % args.base)
        return 0
    rev = base.stdout.strip()
    work = tempfile.mkdtemp(prefix="mojo_net_perf_")
    tree = os.path.join(work, "base")
    try:
        subprocess.run(["git", "worktree", "add", "--detach", "--quiet", tree, rev], cwd=ROOT, check=True)
        head_exe, base_exe = os.path.join(work, "head"), os.path.join(work, "base_exe")
        build(ROOT, head_exe)
        if not build(tree, base_exe):
            print("skip: %s has no %s" % (rev[:12], BENCH))
            return 0
        failed = False
        print("instructions a request, %s (base) -> this tree, tolerance %.1f%%" % (rev[:12], args.tolerance))
        for shape in args.shapes:
            b = per_request(base_exe, shape, work)
            h = per_request(head_exe, shape, work)
            change = (h - b) / b * 100
            verdict = "ok  "
            if change > args.tolerance:
                verdict, failed = "FAIL", True
            elif change < -args.tolerance:
                verdict = "gain"  # (record it in bench/http/README.md)
            print("%s %-8s %8.0f -> %8.0f  %+.1f%%" % (verdict, shape, b, h, change), flush=True)
        return 1 if failed else 0
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", tree], cwd=ROOT, capture_output=True)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
