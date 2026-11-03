"""Heavy JSON workloads: real documents of 0.2 to 1.2 GB, and an hour of
JSON Lines, read (`loads`) and written (`dumps`) by Python's JSON
libraries, each library in a process of its own.

    python3 bench/json/heavy.py list
    python3 bench/json/heavy.py fetch [NAME...]       # download, check, unpack (about 2 GB down, 8 GB on disk)
    python3 bench/json/heavy.py run [NAME...] [--libs json,orjson,mojson] [--repeat 2] [--core 3]

`pixi run -e pyjson bench-json-heavy run` does the same with mojson built
from this repository (build/python); any other Python with the libraries
installed runs this file as it is (the mojson wheel from TestPyPI, say).

**The datasets** (`DATASETS`) are real data of different shapes, each
pinned: a URL at a fixed version and a checksum of the download (the
source's own where it publishes one: Zenodo's MD5, Hugging Face's
SHA-256), then the SHA-256 and size of the unpacked file. They are
fetched into `--dir` (default: build/big in this repository, else data/
beside this file), never committed. Six come from the benchmarks of
JSONPath engines (JSONSki, rsonpath); the rest are a chat dataset, a
GeoJSON file and GH Archive's event log.

**What a run measures**, per dataset and library, in a child process
(memory-capped with systemd-run where it is available, pinned to one core
with `--core`):
- `loads`: the file's bytes to Python objects, the best of `--repeat`
  (JSON Lines: every line, one call each);
- `dumps`: those objects back to text with the library's defaults, best of
  `--repeat` (orjson and msgspec write compact bytes, json and mojson
  json's own format, a str);
- the process's peak memory (the input included);
- **a check of the result by the standard library alone:** SHA-256 over
  `json.dumps` of the result, piece by piece (each member of the root, and
  each item of a large list, one `json.dumps` each, so that no whole text
  is held), the same for every library. Equal hashes mean equal objects
  (key order included). The hash of each library's own `dumps` text is
  kept too: mojson's must be json's.

Times are wall-clock seconds of the call alone. The machine's load, the
memory it has free and the cap are printed first: on a shared machine,
compare libraries within one run, not across runs.
"""

import argparse
import gc
import gzip
import hashlib
import json
import os
import platform
import resource
import shutil
import subprocess
import sys
import time
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
DEFAULT_DIR = os.path.join(_REPO, "build", "big") if os.path.exists(os.path.join(_REPO, "pixi.toml")) else os.path.join(_HERE, "data")

_ZENODO = "https://zenodo.org/records/%s/files/%s?download=1"

# name: (file, url, download checksum, unpacked sha256, unpacked size,
#        format, licence and source, shape)
DATASETS = {
    "bestbuy": (
        "bestbuy_large_record.json",
        _ZENODO % ("7607865", "bestbuy_large_record.json.gz"),
        "md5:7dda2d915ec48afce81dccaa4428173e",
        "8eee3043d6d0a11cecb43e169f70fae83c68efa7fe4a5508aa2192f717c45617", 1044619305, "json",
        "CC-BY-4.0; Zenodo 7607865 (JSONSki's BestBuy dataset)",
        "product records from BestBuy's API: ~160 keys each, mostly null",
    ),
    "walmart": (
        "walmart_large_record.json",
        _ZENODO % ("7607882", "walmart_large_record.json.gz"),
        "md5:f976edd6092c69dee51972ee34c39388",
        "ebad2cf96871a1c2277c2a19dcc5818f9c2aed063bc8a56459f378024c5a6e14", 995350329, "json",
        "CC-BY-4.0; Zenodo 7607882",
        "product records from Walmart's API",
    ),
    "twitter": (
        "twitter_large_record.json",
        _ZENODO % ("7607891", "twitter_large_record.json.gz"),
        "md5:8cc7a20acb8acf320e7412d9717d5e7e",
        "2357e2bdba1d621a20c2278a88bdec592e93c680de17d8403d9e3018c7539da6", 842634887, "json",
        "CC-BY-4.0; Zenodo 7607891",
        "tweets from Twitter's developer API: nested objects, large ids, text",
    ),
    "wiki": (
        "wiki_large_record.json",
        _ZENODO % ("7607884", "wiki_large_record.json.gz"),
        "md5:126c9fec15714ee43d93f87c461337a5",
        "1abea7979812edc38651a631b11faf64f1eb5a61e2ee875b4e4d4f7b15a8cea9", 1098988355, "json",
        "CC-BY-4.0; Zenodo 7607884",
        "Wikipedia entities",
    ),
    "nspl": (
        "nspl_large_record.json",
        _ZENODO % ("7607878", "nspl_large_record.json.gz"),
        "md5:1d45897c4b9f59d2d41060198a716cac",
        "174978fd3d7692dbf641c00c80b34e3ff81f0d3d4602c89ee231b989e6a30dd3", 1210219151, "json",
        "CC-BY-4.0; Zenodo 7607878 (the UK's National Statistics Postcode Lookup)",
        "UK postcodes",
    ),
    "gmaps": (
        "google_map_large_record.json",
        _ZENODO % ("8395641", "google_map_large_record.json.gz"),
        "md5:735f6fa3f8d2c48a521cff817911833c",
        "cdbc090edf4faeea80d917e3a2ff618fb0a42626eeac5a4521dae471e4f53574", 1136069010, "json",
        "CC-BY-4.0; Zenodo 8395641 (rsonpath's datasets)",
        "Google Maps directions",
    ),
    "sharegpt": (
        "ShareGPT_V3_unfiltered_cleaned_split.json",
        "https://huggingface.co/datasets/anon8231489123/ShareGPT_Vicuna_unfiltered/resolve/"
        "192ab2185289094fc556ec8ce5ce1e8e587154ca/ShareGPT_V3_unfiltered_cleaned_split.json",
        "sha256:35f0e213ce091ed9b9af2a1f0755e9d39f9ccec34ab281cd4ca60d70f6479ba4",
        "35f0e213ce091ed9b9af2a1f0755e9d39f9ccec34ab281cd4ca60d70f6479ba4", 672837942, "json",
        "Apache-2.0; Hugging Face anon8231489123/ShareGPT_Vicuna_unfiltered",
        "chat conversations: long text in many languages",
    ),
    "citylots": (
        "citylots.json",
        "https://raw.githubusercontent.com/zemirco/sf-city-lots-json/33c27c137784a96d0fbd7f329dceda6cc7f49fa3/citylots.json",
        "sha256:cd0d4a4a2e7629618902a54c92514f7a14761994dd7800e489ab98b96628f2bc",
        "cd0d4a4a2e7629618902a54c92514f7a14761994dd7800e489ab98b96628f2bc", 189778220, "json",
        "San Francisco's open data (City Lots), as GeoJSON by github.com/zemirco/sf-city-lots-json",
        "GeoJSON parcels: nearly all floats",
    ),
    "gharchive": (
        "gharchive-2024-03-12-15.json",
        "https://data.gharchive.org/2024-03-12-15.json.gz",
        "sha256:43bc27c450c7f93b36f01247405ae3bdfaaea2eed6e1ab804ad453a65fe55093",
        "a822f3eaee3820b8d299a1aa515fbbb0aef8f202aecd1e52b89b06384f1a90d8", 1111136175, "jsonl",
        "GitHub's public events, archived by GH Archive (gharchive.org)",
        "JSON Lines: one GitHub event a line (an hour of them)",
    ),
}

LIBS = ["json", "orjson", "mojson", "ujson", "msgspec", "simdjson"]
DEFAULT_LIBS = ["json", "orjson", "mojson"]


# ---- fetching ----------------------------------------------------------------


def _hasher(checksum):
    algo, _, want = checksum.partition(":")
    return hashlib.new(algo), want


def _download(url, dest, checksum):
    """`url` to `dest`, its checksum checked as it streams; three tries."""
    for attempt in range(3):
        h, want = _hasher(checksum)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "mojson-heavy-bench"})
            with urllib.request.urlopen(req, timeout=60) as r, open(dest + ".part", "wb") as f:
                total = int(r.headers.get("Content-Length") or 0)
                got, shown = 0, -1
                while True:
                    chunk = r.read(1 << 20)
                    if not chunk:
                        break
                    f.write(chunk)
                    h.update(chunk)
                    got += len(chunk)
                    pct = got * 100 // total if total else -1
                    if pct // 10 != shown // 10:
                        shown = pct
                        print("    %s: %.0f MB%s" % (os.path.basename(dest), got / 1e6, " (%d%%)" % pct if total else ""), flush=True)
        except OSError as e:
            print("    attempt %d failed: %s" % (attempt + 1, e))
            continue
        if want != "PENDING" and h.hexdigest() != want:
            os.remove(dest + ".part")
            raise SystemExit("    %s: checksum %s, expected %s" % (url, h.hexdigest(), want))
        os.replace(dest + ".part", dest)
        return h.hexdigest()
    raise SystemExit("    %s: download failed" % url)


def _sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 22)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def fetch(names, d, keep, verify):
    os.makedirs(d, exist_ok=True)
    for name in names:
        fname, url, checksum, sha, size, *_ = DATASETS[name]
        path = os.path.join(d, fname)
        if os.path.exists(path) and (size is None or os.path.getsize(path) == size):
            note = ""
            if verify:
                digest = _sha256_of(path)
                if digest != sha:
                    raise SystemExit("%-10s %s: sha256 %s, expected %s" % (name, path, digest, sha))
                note = ", sha256 checked"
            print("%-10s %s: there (%.0f MB%s)" % (name, path, os.path.getsize(path) / 1e6, note))
            continue
        print("%-10s fetching %s" % (name, url), flush=True)
        if shutil.disk_usage(d).free < 3 << 30:
            raise SystemExit("    less than 3 GB free in " + d)
        gz = url.split("?")[0].endswith(".gz")
        got = _download(url, path + (".gz" if gz else ""), checksum)
        if checksum.endswith("PENDING"):
            print("    download %s:%s (not pinned yet)" % (checksum.split(":")[0], got))
        if gz:
            h = hashlib.sha256()
            with gzip.open(path + ".gz", "rb") as src, open(path + ".part", "wb") as dst:
                while True:
                    chunk = src.read(1 << 22)
                    if not chunk:
                        break
                    dst.write(chunk)
                    h.update(chunk)
            os.replace(path + ".part", path)
            if not keep:
                os.remove(path + ".gz")
            digest = h.hexdigest()
        else:
            digest = _sha256_of(path)
        n = os.path.getsize(path)
        if sha is not None and (digest != sha or n != size):
            os.remove(path)
            raise SystemExit("    %s: unpacked to sha256 %s, %d bytes; expected %s, %d" % (fname, digest, n, sha, size))
        print("    %s: %d bytes, sha256 %s%s" % (fname, n, digest, "" if sha else " (not pinned yet)"), flush=True)


# ---- one library, one dataset (the child process) -----------------------------


def _codec(lib):
    """(version, loads, dumps or None) of a library."""
    if lib == "json":
        return "py" + platform.python_version(), json.loads, json.dumps
    m = __import__(lib)
    version = getattr(m, "__version__", "")
    if lib == "msgspec":
        return version, m.json.decode, m.json.encode
    if lib == "simdjson":
        return version, m.loads, None  # (its dumps is json's)
    return version, m.loads, m.dumps


class _Fingerprint:
    """SHA-256 over the standard library's `json.dumps` of a value, piece
    by piece, so that no whole text of a large value is held at once: the
    root's members, and the items of lists of more than 1,000 (records)
    down to depth 3, one `json.dumps` call each; anything else whole."""

    def __init__(self):
        self.h = hashlib.sha256()

    def add(self, o, depth=0):
        t = type(o)
        split = (t is dict or t is list) and (depth == 0 or (depth < 3 and len(o) > 1000))
        if split and t is dict:
            self.h.update(b"{")
            for k, v in o.items():
                self.h.update(json.dumps(k).encode("utf-8", "surrogatepass"))
                self.add(v, depth + 1)
            self.h.update(b"}")
        elif split:
            self.h.update(b"[")
            for v in o:
                self.add(v, depth + 1)
            self.h.update(b"]")
        else:
            self.h.update(json.dumps(o).encode("utf-8", "surrogatepass"))
            self.h.update(b"\n")


def _text_sha(out, h):
    """Feed a dumps result (str or bytes) to `h` in pieces, as UTF-8."""
    if isinstance(out, (bytes, bytearray)):
        h.update(out)
        return
    for i in range(0, len(out), 1 << 24):
        h.update(out[i:i + (1 << 24)].encode("utf-8", "surrogatepass"))


def _peak_mb():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def _best(fn, arg, repeat):
    best = None
    out = None
    for _ in range(repeat):
        out = None
        gc.collect()
        t = time.perf_counter()
        out = fn(arg)
        t = time.perf_counter() - t
        best = t if best is None else min(best, t)
    return out, best


def child(lib, path, fmt, repeat, core):
    if core is not None:
        os.sched_setaffinity(0, {core})
    version, loads, dumps = _codec(lib)
    with open(path, "rb") as f:
        data = f.read()
    r = {"lib": lib, "version": version}
    if fmt == "jsonl":
        lines = data.split(b"\n")
        if lines and not lines[-1]:
            lines.pop()
        del data
        r["records"] = len(lines)
        obj, r["loads_s"] = _best(lambda ls: [loads(x) for x in ls], lines, repeat)
        del lines
    else:
        obj, r["loads_s"] = _best(loads, data, repeat)
        del data
    r["peak_mb_loads"] = round(_peak_mb())
    if dumps is not None:
        if fmt == "jsonl":
            out, r["dumps_s"] = _best(lambda os_: [dumps(o) for o in os_], obj, repeat)
            h = hashlib.sha256()
            n = 0
            for piece in out:
                _text_sha(piece, h)
                h.update(b"\n")
                n += len(piece) + 1
        else:
            out, r["dumps_s"] = _best(dumps, obj, repeat)
            h = hashlib.sha256()
            _text_sha(out, h)
            n = len(out)
        r["out_mb"] = round(n / 1e6, 1)
        r["out_sha256"] = h.hexdigest()
        del out
    r["peak_mb"] = round(_peak_mb())
    fp = _Fingerprint()
    if fmt == "jsonl":
        for o in obj:
            fp.add(o)
    else:
        fp.add(obj)
    r["result_sha256"] = fp.h.hexdigest()
    print(json.dumps(r), flush=True)


# ---- the run -----------------------------------------------------------------


def _mem_available():
    try:
        for line in open("/proc/meminfo"):
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    except OSError:
        pass
    return None


def _cap_bytes(cap):
    if cap == "auto":
        avail = _mem_available()
        return None if avail is None else max(1 << 30, min(8 << 30, avail - (1 << 30)))
    if cap == "none":
        return None
    units = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}
    return int(float(cap[:-1]) * units[cap[-1].upper()]) if cap[-1].upper() in units else int(cap)


def _systemd_ok():
    if shutil.which("systemd-run") is None:
        return False
    return subprocess.run(["systemd-run", "--user", "--scope", "-q", "true"], capture_output=True).returncode == 0


def _available(lib):
    """Whether `lib` is installed: found, not imported, since the runs are
    in children (mojson up to 0.1.4 changed its children's environment
    when imported)."""
    import importlib.util

    return lib == "json" or importlib.util.find_spec(lib) is not None


def run(names, d, libs, repeat, cap, core, out):
    cap_b = _cap_bytes(cap)
    capped = cap_b is not None and _systemd_ok()
    print("python    %s on %s, %d CPUs, load average %.2f" % (platform.python_version(), platform.machine(), os.cpu_count(), os.getloadavg()[0]))
    avail = _mem_available()
    try:
        cpu = [l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")][0]
    except (OSError, IndexError):
        cpu = platform.processor()
    print("machine   %s%s" % (cpu, ", %.1f GB memory available" % (avail / 1e9) if avail else ""))
    print("each run  in its own process%s%s, best of %d" % (
        ", memory capped at %.1f GB" % (cap_b / (1 << 30)) if capped else " (no memory cap)",
        ", on core %d" % core if core is not None else "", repeat))
    missing = [l for l in libs if not _available(l)]
    libs = [l for l in libs if l not in missing]
    if missing:
        print("not installed: %s" % ", ".join(missing))
    results = []
    for name in names:
        fname, _, _, _, _, fmt, licence, shape = DATASETS[name]
        path = os.path.join(d, fname)
        if not os.path.exists(path):
            print("\n== %s: not fetched (heavy.py fetch %s)" % (name, name))
            continue
        print("\n== %s: %s (%.0f MB%s)" % (name, shape, os.path.getsize(path) / 1e6, ", JSON Lines" if fmt == "jsonl" else ""), flush=True)
        rows = []
        for lib in libs:
            cmd = [sys.executable, os.path.abspath(__file__), "_child", lib, path, fmt, str(repeat), "-" if core is None else str(core)]
            if capped:
                cmd = ["systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=%d" % cap_b, "-p", "MemorySwapMax=0"] + cmd
            p = subprocess.run(cmd, capture_output=True, text=True)
            lines = [l for l in p.stdout.splitlines() if l.startswith("{")]
            if p.returncode != 0 or not lines:
                why = "killed: over the memory cap" if p.returncode in (137, -9) else "failed (exit %d): %s" % (p.returncode, (p.stderr.strip().splitlines() or [""])[-1][:120])
                rows.append({"lib": lib, "failed": why})
            else:
                rows.append(json.loads(lines[-1]))
            _print_row(rows[-1], rows)
        for r in rows:
            r["dataset"] = name
        results.extend(rows)
    _summary(results, names, libs)
    if out:
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with open(out, "w") as f:
            json.dump({"python": platform.python_version(), "machine": platform.machine(), "repeat": repeat,
                       "cap_bytes": cap_b if capped else None, "core": core, "results": results}, f, indent=1)
        print("\nresults: " + out)


def _print_row(r, rows):
    if len(rows) == 1:
        print("  %-9s %-10s %8s %8s %8s %8s  %s" % ("library", "version", "loads s", "dumps s", "peak MB", "out MB", "result (by json.dumps) / dumps text"))
    if "failed" in r:
        print("  %-9s %s" % (r["lib"], r["failed"]), flush=True)
        return
    ref = next((x for x in rows if x.get("lib") == "json" and "failed" not in x), None)
    if r["lib"] == "json":
        same = "(the reference)"
    elif ref is None:
        same = "(no json result to compare)"
    else:
        same = "same as json" if r["result_sha256"] == ref["result_sha256"] else "DIFFERS from json"
        if "out_sha256" in r:
            same += ", json's text" if r["out_sha256"] == ref.get("out_sha256") else ", own format"
    print("  %-9s %-10s %8.2f %8s %8d %8s  %s" % (
        r["lib"], r["version"][:10], r["loads_s"], "%.2f" % r["dumps_s"] if "dumps_s" in r else "-",
        r["peak_mb"], "%.0f" % r["out_mb"] if "out_mb" in r else "-", same), flush=True)


def _summary(results, names, libs):
    done = [n for n in names if any(r.get("dataset") == n for r in results)]
    if len(done) < 2:
        return
    for title, key, fmt in (("loads, s", "loads_s", "%.2f"), ("dumps, s", "dumps_s", "%.2f"), ("peak memory, MB", "peak_mb", "%d")):
        print("\n%s" % title)
        print("  %-10s" % "" + "".join("%10s" % l for l in libs))
        for n in done:
            row = []
            for l in libs:
                r = next((x for x in results if x.get("dataset") == n and x["lib"] == l), None)
                if r is None:
                    cell = ""
                elif "failed" in r:
                    cell = r["failed"].split(":")[0].split(" ")[0]  # killed / failed
                else:
                    cell = fmt % r[key] if key in r else "-"
                row.append("%10s" % cell)
            print("  %-10s" % n + "".join(row))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "_child":
        lib, path, fmt, repeat, core = sys.argv[2:7]
        return child(lib, path, fmt, int(repeat), None if core == "-" else int(core))
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["list", "fetch", "run"])
    ap.add_argument("names", nargs="*", help="datasets (default: all)")
    ap.add_argument("--dir", default=os.environ.get("MOJSON_HEAVY_DIR", DEFAULT_DIR), help="where the datasets are (default %(default)s)")
    ap.add_argument("--libs", default=",".join(DEFAULT_LIBS), help="comma-separated, from %s, or 'all' (default %%(default)s)" % ",".join(LIBS))
    ap.add_argument("--repeat", type=int, default=1, help="best of N calls (default 1)")
    ap.add_argument("--cap", default="auto", help="memory limit per process: 'auto' (free memory less 1 GB, at most 8 GB), e.g. 6G, or 'none'")
    ap.add_argument("--core", type=int, help="pin each process to this CPU core")
    ap.add_argument("--out", help="also write the results to this JSON file")
    ap.add_argument("--keep", action="store_true", help="fetch: keep the .gz downloads")
    ap.add_argument("--verify", action="store_true", help="fetch: check the SHA-256 of files already there")
    a = ap.parse_args()
    names = a.names or list(DATASETS)
    unknown = [n for n in names if n not in DATASETS]
    if unknown:
        ap.error("unknown datasets: %s (see 'list')" % ", ".join(unknown))
    if a.command == "list":
        for n, (fname, url, _, _, size, fmt, licence, shape) in DATASETS.items():
            there = os.path.exists(os.path.join(a.dir, fname))
            print("%-10s %-6s %s%s\n           %s\n           %s" % (n, fmt, shape, "" if not there else "  [fetched]", licence, url))
        return
    if a.command == "fetch":
        return fetch(names, a.dir, a.keep, a.verify)
    libs = LIBS if a.libs == "all" else a.libs.split(",")
    bad = [l for l in libs if l not in LIBS]
    if bad:
        ap.error("unknown libraries: %s" % ", ".join(bad))
    run(names, a.dir, libs, a.repeat, a.cap, a.core, a.out)


if __name__ == "__main__":
    main()
