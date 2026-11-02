"""`json` on the corpus and the AI-shaped payloads (bench/json/corpus.py
and payloads.py write them): parsing each into a reused `Document`,
rendering it back with `write_json`, and, for the embeddings, reading
every float and writing them all again with `Writer` (shortest
round-trip).

    pixi run bench-json [name...]

Times are the thread's CPU time, the best of 7 samples of at least 0.1 s
each, as bench/json/compare.py measures Python's libraries.
"""

from std.ffi import external_call
from std.sys import argv

from json import Document, Writer

comptime NAMES: List[StaticString] = [
    "chunk", "chat_completion", "tools_request", "embeddings", "github", "twitter", "citm_catalog", "canada", "recipe_book"
]


@fieldwise_init
struct _Timespec(Copyable, Movable):
    var sec: Int
    var nsec: Int


def thread_ns() -> Int:
    """The calling thread's CPU time (CLOCK_THREAD_CPUTIME_ID), in ns."""
    var ts = _Timespec(0, 0)
    _ = external_call["clock_gettime", Int32](Int32(3), Pointer(to=ts))
    return ts.sec * 1_000_000_000 + ts.nsec


def _read(path: String) raises -> List[UInt8]:
    with open(path, "r") as f:
        return f.read_bytes()


def _fmt(ns: Float64, size: Int) -> String:
    var mbs = Float64(size) / ns * 1000
    if ns < 1_000_000:
        return String(round(ns / 1000, 2), " us ", Int(mbs), " MB/s")
    return String(round(ns / 1_000_000, 3), " ms ", Int(mbs), " MB/s")


def _run(op: Int, k: Int, mut doc: Document, data: Span[UInt8, _], mut out: List[UInt8]) raises -> Int:
    """`k` parses (`op` 0) or renderings (1); the thread CPU ns taken."""
    var t = thread_ns()
    for _ in range(k):
        if op == 0:
            doc.parse(data)
        else:
            out.clear()
            doc.write_json(0, out)
    return thread_ns() - t


def best(op: Int, mut doc: Document, data: Span[UInt8, _], mut out: List[UInt8]) raises -> Float64:
    """Nanoseconds per call: the best of 7 samples of at least 0.1 s."""
    var k = 1
    while True:
        var dt = _run(op, k, doc, data, out)
        if dt >= 100_000_000:
            break
        k = k * 2 if dt < 25_000_000 else k + k * (100_000_000 - dt) // max(dt, 1) + 1
    var b = Float64(1e30)
    for _ in range(7):
        b = min(b, Float64(_run(op, k, doc, data, out)) / Float64(k))
    return b


def main() raises:
    var args = argv()
    var dir = String(args[1]) if len(args) > 1 else String("build/bench_json")
    var names = List[String]()
    for i in range(2, len(args)):
        names.append(String(args[i]))
    if len(names) == 0:
        for n in materialize[NAMES]():
            names.append(String(n))
    var doc = Document()
    var out = List[UInt8]()
    for name in names:
        var data = _read(dir + "/" + name + ".json")
        var p = best(0, doc, Span(data), out)
        var w = best(1, doc, Span(data), out)
        print("==", name, "(", len(data), "bytes )")
        print("  parse  mojo Document  ", _fmt(p, len(data)))
        print("  write  mojo write_json", _fmt(w, len(out)))
        if name == "embeddings":
            # Every embedding value read as a Float64, then written again.
            var floats = List[Float64]()
            var t = thread_ns()
            var items = doc.member(0, "data")
            var item = doc.child(items, 0)
            for _ in range(doc.count(items)):
                var vec = doc.member(item, "embedding")
                var c = doc.child(vec, 0)
                for _ in range(doc.count(vec)):
                    floats.append(doc.float(c))
                    c += 1
                item = doc.next(item)
            var read_ns = Float64(thread_ns() - t) / Float64(len(floats))
            var wr = Writer(capacity=len(data))
            t = thread_ns()
            wr.begin_array()
            for x in floats:
                wr.float(x)
            wr.end_array()
            var write_ns = Float64(thread_ns() - t) / Float64(len(floats))
            print("  floats", len(floats), ": float()", round(read_ns, 1), "ns each, Writer.float", round(write_ns, 1), "ns each")
