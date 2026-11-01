#!/usr/bin/env python3
"""Request smuggling, checked against another implementation: random
request streams, built from the variations that desync front ends and
back ends (Content-Length and Transfer-Encoding together, twice, or
malformed; chunk sizes, extensions and line ends; obs-fold; bare CR and
LF), are read by our server codec (tools/smuggling/codec.mojo) and by Go's
net/http (tools/smuggling/go). Where both read a request, they must agree
on its method, target and body length, request after request: a
disagreement is where one side's request boundary is not the other's,
which is what smuggling exploits. Where one refuses what the other reads,
nothing is passed on through it, so that is counted, not failed.

The cross-check HR2 ran once (30,000 heads against llhttp and Go;
docs/http.md) was not kept, and HR3 rewrote the code it cleared (2026-11
analysis). This keeps it.

    pixi run -e bench smuggling-check [--streams 20000] [--seed N]

Weekly in .github/workflows/fuzz.yml (Go comes from the bench
environment, linux-64 only)."""

import argparse
import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

METHODS = ["GET", "POST", "PUT"]
TARGETS = ["/", "/a", "/b?x=1", "/c%20d"]
ENDS = ["\r\n"] * 40 + ["\n", "\r"]


def _cl(r, n):
    return r.choice([
        "Content-Length: %d" % n,
        "Content-Length:%d" % n,
        "Content-Length: %d " % n,
        "Content-Length: +%d" % n,
        "Content-Length: %d, %d" % (n, n),
        "Content-Length: %d, %d" % (n, n + 1),
        "Content-Length: 0%d" % n,
        "content-length: %d" % n,
        "Content-Length : %d" % n,
        "Content-Length: %x" % n,
        "Content-Length:\t%d" % n,
    ])


def _te(r):
    return r.choice([
        "Transfer-Encoding: chunked",
        "Transfer-Encoding: Chunked",
        "Transfer-Encoding:  chunked",
        "Transfer-Encoding: chunked ",
        "Transfer-Encoding: chunked, identity",
        "Transfer-Encoding: identity, chunked",
        "Transfer-Encoding: gzip, chunked",
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding: chunk",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding:\tchunked",
        "Transfer-Encoding: \"chunked\"",
        "Transfer_Encoding: chunked",
        "Transfer-Encoding:\r\n chunked",  # (obs-fold)
    ])


def _chunked(r, data):
    out = ""
    i = 0
    while i < len(data):
        n = min(len(data) - i, r.randint(1, 4))
        size = r.choice(["%x" % n] * 6 + ["%X" % n, "0%x" % n, "%x " % n, "%x;a=b" % n, "%x;a" % n,
                                          "0x%x" % n, "%x\t" % n, "+%x" % n])
        out += size + r.choice(ENDS) + data[i:i + n] + r.choice(ENDS)
        i += n
    last = r.choice(["0", "0", "0", "00", "0;x=y", "0 "])
    out += last + r.choice(ENDS)
    if r.random() < 0.2:
        out += r.choice(["X-Trailer: 1", "Content-Length: 5", "bad trailer"]) + r.choice(ENDS)
    out += r.choice(ENDS)
    return out


def _request(r):
    method = r.choice(METHODS)
    target = r.choice(TARGETS)
    version = r.choice(["HTTP/1.1"] * 8 + ["HTTP/1.0", "HTTP/1.2"])
    end = r.choice(ENDS)
    lines = ["%s %s %s" % (method, target, version), "Host: x"]
    data = "".join(r.choice("abcdefgh") for _ in range(r.randint(0, 9)))
    framing = r.random()
    body = ""
    if framing < 0.35:
        lines.append(_cl(r, len(data)))
        body = data
    elif framing < 0.6:
        lines.append(_te(r))
        body = _chunked(r, data)
    elif framing < 0.85:  # both, in either order, as smuggling tries
        both = [_cl(r, r.choice([len(data), len(data) + 3, 0])), _te(r)]
        r.shuffle(both)
        lines += both
        body = _chunked(r, data) if r.random() < 0.7 else data
    else:
        if r.random() < 0.5:
            lines.append(_cl(r, len(data)))
            lines.append(_cl(r, r.choice([len(data), len(data) + 1])))
        body = data if r.random() < 0.5 else ""
    if r.random() < 0.05:
        lines.insert(r.randint(1, len(lines)), r.choice(["X: a\x00b", "X:\x7f", " X: folded", "X: a\rb", "Bad Name: 1"]))
    return end.join(lines) + end + end + body


def streams(seed, count):
    r = random.Random(seed)
    return ["".join(_request(r) for _ in range(r.randint(1, 3))) for _ in range(count)]


def _run(cmd, cwd=ROOT):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("%s failed:\n%s%s" % (" ".join(cmd), p.stdout[-2000:], p.stderr[-2000:]))
    return p.stdout


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--streams", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=int(os.environ.get("MOJO_NET_FUZZ_SEED") or 1))
    ap.add_argument("--examples", type=int, default=0, help="print this many streams that only one side refused")
    args = ap.parse_args()
    work = tempfile.mkdtemp(prefix="mojo_net_smuggling_")
    data = streams(args.seed, args.streams)
    path = os.path.join(work, "streams.hex")
    with open(path, "w") as f:
        for s in data:
            f.write(s.encode("latin-1").hex() + "\n")
    _run(["go", "build", "-o", os.path.join(work, "go_reader"), "."], cwd=os.path.join(HERE, "go"))
    _run(["mojo", "build", "-I", "src", "tools/smuggling/codec.mojo", "-o", os.path.join(work, "codec")])
    ours = _run([os.path.join(work, "codec"), path]).split("\n")
    go = _run([os.path.join(work, "go_reader"), path]).split("\n")
    agree = refused_ours = refused_go = both_refused = 0
    bad = []
    only = {"ours": [], "go": []}
    for i, s in enumerate(data):
        a = ours[i].split("|") if ours[i] else []
        b = go[i].split("|") if go[i] else []
        a_reqs = [x for x in a if x not in ("error", "close")]
        b_reqs = [x for x in b if x != "error"]
        common = min(len(a_reqs), len(b_reqs))
        if a_reqs[:common] != b_reqs[:common]:
            bad.append((i, s, ours[i], go[i]))
            continue
        a_err, b_err = "error" in a, "error" in b
        if a_err and b_err:
            both_refused += 1
        elif a_err:
            refused_ours += 1
            only["ours"].append((s, ours[i], go[i]))
        elif b_err:
            refused_go += 1
            only["go"].append((s, ours[i], go[i]))
        else:
            agree += 1
    print("seed %d, %d streams: %d read alike, %d refused by both, %d refused by ours only, %d by Go only, %d disagree"
          % (args.seed, len(data), agree, both_refused, refused_ours, refused_go, len(bad)))
    for side in ("ours", "go"):
        for s, a, b in only[side][: args.examples]:
            print("refused by %s only: %r\n  ours: %s\n  go:   %s" % (side, s, a, b))
    for i, s, a, b in bad[:10]:
        print("DISAGREE stream %d: %r\n  ours: %s\n  go:   %s" % (i, s, a, b))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
