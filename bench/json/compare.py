"""Python's JSON libraries on the corpus (corpus.py) and the AI payloads
(payloads.py): `loads` into Python objects, `dumps` back, and, for the
libraries that have one, a parse that builds no Python objects (a lazy
document), which is the work `json.Document.parse` does in Mojo.

    pixi run -e pyjson bench-json-compare        (all of them, mojson built)
    python3 bench/json/compare.py <dir> [name...]

Each library found is measured; the missing are skipped. mojson is
imported from build/python (`pixi run mojson-build`) when it is there. Times are the
thread's CPU time, the best of 7 samples of at least 0.1 s each (the
machine is shared: pin with `taskset -c N` and watch the load). Every
library gets the input as bytes, as a server receives it.
"""

import importlib
import os
import sys
import time

_BUILT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "build", "python")
if os.path.isdir(os.path.join(_BUILT, "mojson")):
    sys.path.insert(0, _BUILT)

NAMES = ["chunk", "chat_completion", "tools_request", "embeddings", "github", "twitter", "citm_catalog", "canada", "recipe_book"]


def _try(name):
    try:
        return importlib.import_module(name)
    except ImportError:
        return None


def loaders():
    out = []
    import json

    out.append(("json", json.loads))
    for mod, fn in (("simplejson", "loads"), ("ujson", "loads"), ("rapidjson", "loads"), ("orjson", "loads")):
        m = _try(mod)
        if m:
            out.append((mod, getattr(m, fn)))
    m = _try("msgspec")
    if m:
        out.append(("msgspec", m.json.decode))
    m = _try("simdjson")
    if m:
        out.append(("simdjson", m.loads))
    m = _try("yyjson")
    if m:
        out.append(("yyjson", m.loads))
    m = _try("mojson")
    if m:
        out.append(("mojson", m.loads))
    return out


def lazy_parsers():
    """Parsers that build a document of their own, no Python objects."""
    out = []
    m = _try("simdjson")
    if m:
        p = m.Parser()
        out.append(("simdjson.Parser", lambda b, p=p: p.parse(b)))
    m = _try("cysimdjson")
    if m:
        p = m.JSONParser()
        out.append(("cysimdjson", lambda b, p=p: p.parse(b)))
    m = _try("yyjson")
    if m:
        out.append(("yyjson.Document", m.Document))
    m = _try("mojson")
    if m and hasattr(m, "Document"):
        out.append(("mojson.Document", m.Document))
    return out


def dumpers():
    out = []
    import json

    out.append(("json", json.dumps))
    for mod in ("simplejson", "ujson", "rapidjson", "orjson", "yyjson", "mojson"):
        m = _try(mod)
        if m:
            out.append((mod, m.dumps))
    m = _try("msgspec")
    if m:
        out.append(("msgspec", m.json.encode))
    return out


def best(fn, arg, samples=7, floor=0.1):
    """Seconds per call: the best of `samples` runs of at least `floor` s."""
    n = 1
    while True:
        t = time.thread_time()
        for _ in range(n):
            fn(arg)
        dt = time.thread_time() - t
        if dt >= floor:
            break
        n *= 2 if dt < floor / 4 else 1 + int(floor / max(dt, 1e-9))
    times = [dt / n]
    for _ in range(samples - 1):
        t = time.thread_time()
        for _ in range(n):
            fn(arg)
        times.append((time.thread_time() - t) / n)
    return min(times)


def _fmt(sec, size):
    if sec < 1e-3:
        return "%9.2f us %6.0f MB/s" % (sec * 1e6, size / sec / 1e6)
    return "%9.3f ms %6.0f MB/s" % (sec * 1e3, size / sec / 1e6)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    d = sys.argv[1]
    names = sys.argv[2:] or NAMES
    load, lazy, dump = loaders(), lazy_parsers(), dumpers()
    import json

    for name in names:
        with open(os.path.join(d, name + ".json"), "rb") as f:
            data = f.read()
        obj = json.loads(data)
        print("== %s (%d bytes)" % (name, len(data)))
        for lib, fn in load:
            try:
                ok = fn(data) == obj
            except Exception as e:
                print("  loads  %-16s failed: %s" % (lib, e))
                continue
            print("  loads  %-16s %s%s" % (lib, _fmt(best(fn, data), len(data)), "" if ok else "  (differs)"))
        for lib, fn in lazy:
            print("  parse  %-16s %s" % (lib, _fmt(best(fn, data), len(data))))
        for lib, fn in dump:
            try:
                out = fn(obj)
            except Exception as e:
                print("  dumps  %-16s failed: %s" % (lib, e))
                continue
            back = json.loads(out)
            print("  dumps  %-16s %s%s" % (lib, _fmt(best(fn, obj), len(out)), "" if back == obj else "  (differs)"))
        sys.stdout.flush()


if __name__ == "__main__":
    main()
