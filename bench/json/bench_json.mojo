"""`json` on AI-shaped payloads (bench/json/payloads.py writes them):
parsing each into a reused `Document`, rendering it back with
`write_json`, and, for the embeddings, reading every float and writing
them all again with `Writer` (shortest round-trip).

    pixi run bench-json
"""

from std.python import Python
from std.sys import argv
from std.time import perf_counter_ns

from json import Document, Writer


def _read(path: String) raises -> List[UInt8]:
    var data = Python.import_module("builtins").open(path, "rb").read()
    var out = List[UInt8](capacity=Int(py=data.__len__()))
    for b in data:
        out.append(UInt8(Int(py=b)))
    return out^


def _best(times: List[Float64]) -> Float64:
    var b = times[0]
    for t in times:
        b = min(b, t)
    return b


def main() raises:
    var dir = String(argv()[1]) if len(argv()) > 1 else String("build/bench_json")
    var doc = Document()
    var out = List[UInt8]()
    for name in ["chunk", "chat_completion", "tools_request", "embeddings"]:
        var data = _read(dir + "/" + name + ".json")
        var n = max(1, 20_000_000 // len(data))
        var parse_t = List[Float64]()
        var write_t = List[Float64]()
        for _ in range(5):
            var t = perf_counter_ns()
            for _ in range(n):
                doc.parse(Span(data))
            parse_t.append(Float64(perf_counter_ns() - t) / Float64(n))
            t = perf_counter_ns()
            for _ in range(n):
                out.clear()
                doc.write_json(0, out)
            write_t.append(Float64(perf_counter_ns() - t) / Float64(n))
        var p = _best(parse_t)
        print(
            "mojo   ", name, " ", len(data), "bytes  parse", p / 1000, "us (", Float64(len(data)) / p * 1000, "MB/s )  write_json",
            _best(write_t) / 1000, "us",
        )
        if name == "embeddings":
            # Every embedding value read as a Float64, then written again.
            var floats = List[Float64]()
            var t = perf_counter_ns()
            var items = doc.member(0, "data")
            var item = doc.child(items, 0)
            for _ in range(doc.count(items)):
                var vec = doc.member(item, "embedding")
                var c = doc.child(vec, 0)
                for _ in range(doc.count(vec)):
                    floats.append(doc.float(c))
                    c += 1
                item = doc.next(item)
            var read_ns = Float64(perf_counter_ns() - t) / Float64(len(floats))
            var w = Writer(capacity=len(data))
            t = perf_counter_ns()
            w.begin_array()
            for x in floats:
                w.float(x)
            w.end_array()
            var write_ns = Float64(perf_counter_ns() - t) / Float64(len(floats))
            print("mojo    embeddings floats:", len(floats), " float()", read_ns, "ns each, Writer.float", write_ns, "ns each")
