"""Regression tests for the review of `json` (J1).

- **The repeated-key check's cost.** A merge sort of the keys by their
  bytes made one 259 MB object with 7M keys under a shared prefix take
  17.5 s, about 29 times its parse. Keys are now hashed once (SipHash-1-3)
  and only keys with one hash are compared. The tests bound the time
  against the same strings in an array.
- **Memory:** a document can take about 7 times its input, so the default
  size limit is now 64 MiB.
- `json.siphash` against Python's own bytes hash, which is SipHash-1-3
  under a zero key when PYTHONHASHSEED=0 (in a child process).
"""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_true
from std.time import perf_counter_ns

from json import DEFAULT_MAX_SIZE, JsonError, Limits, Document, parse
from json.siphash import siphash, siphash13


def _nibble(c: UInt8) -> UInt8:
    return c - 87 if c >= 97 else c - 48


def _unhex(s: Span[UInt8, _]) -> List[UInt8]:
    var out = List[UInt8](capacity=len(s) // 2)
    for i in range(0, len(s) - 1, 2):
        out.append(_nibble(s[i]) * 16 + _nibble(s[i + 1]))
    return out^


def test_siphash13_matches_python() raises:
    var py = Python.import_module("builtins")
    var os = Python.import_module("os")
    var subprocess = Python.import_module("subprocess")
    var sys = Python.import_module("sys")
    var env = py.dict(os.environ)
    env["PYTHONHASHSEED"] = "0"
    var code = "import sys; sys.path.insert(0, 'tests/json'); import json_oracle; print(json_oracle.siphash_cases(1, 3000))"
    var r = subprocess.run(py.list([sys.executable, "-c", code]), env=env, capture_output=True, text=True, check=True)
    var n = 0
    for line in String(r.stdout).split("\n"):
        var parts = line.split(" ")
        if len(parts) != 2:
            continue
        var data = _unhex(parts[0].as_bytes())
        var want: UInt64 = 0
        for c in parts[1].as_bytes():
            want = want * 16 + UInt64(_nibble(c))
        assert_equal(siphash13(0, 0, Span(data)), want, String(line))
        n += 1
    assert_equal(n, 3000)


def test_siphash24_reference_vectors() raises:
    """The paper's vectors: key 00..0f, messages 00..(n-1)."""
    var k0: UInt64 = 0x0706050403020100
    var k1: UInt64 = 0x0F0E0D0C0B0A0908
    var msg = List[UInt8]()
    assert_equal(siphash[2, 4](k0, k1, Span(msg)), 0x726FDB47DD0E0E31)
    for i in range(15):
        msg.append(UInt8(i))
    assert_equal(siphash[2, 4](k0, k1, Span(msg)), 0xA129CA6149BE45E5)


def _best_parse_ns(text: String) raises -> Int:
    var doc = Document()
    var best = Int.MAX
    for _ in range(3):
        var t = perf_counter_ns()
        doc.parse(text)
        best = min(best, Int(perf_counter_ns() - t))
    return best


def _keys(n: Int, prefix: String, width: Int, as_object: Bool) -> String:
    var s = String("{" if as_object else "[")
    for i in range(n):
        if i > 0:
            s += ","
        var digits = String(i)
        s += '"' + prefix
        for _ in range(width - digits.byte_length()):
            s += "0"
        s += digits + ('":0' if as_object else '"')
    s += "}" if as_object else "]"
    return s^


def test_many_keys_cost_bounded() raises:
    """300,000 keys with a 24-byte shared prefix: the object's parse stays
    within a few times the same strings' parse in an array (the merge
    sort took about 29 times at 7M keys, more as the keys grow)."""
    var prefix = String("aaaaaaaaaaaaaaaaaaaaaaaa")
    var obj = _keys(300000, prefix, 8, True)
    var arr = _keys(300000, prefix, 8, False)
    var t_obj = _best_parse_ns(obj)
    var t_arr = _best_parse_ns(arr)
    print("300k keys: object", t_obj // 1000000, "ms, array", t_arr // 1000000, "ms")
    assert_true(t_obj < 8 * t_arr, String("object ", t_obj, " ns vs array ", t_arr, " ns"))
    # And a repeat among them is still found.
    var dup = String(obj[byte = : obj.byte_length() - 1]) + ',"' + prefix + '00123456":1}'
    var kind = 0
    try:
        _ = parse(dup)
    except e:
        kind = e.kind
    assert_equal(kind, JsonError.SYNTAX)


def test_long_equal_length_keys_cost_bounded() raises:
    """16 keys (the pair by pair check) of 1 MiB, the same length and the
    same bytes but the last: compared 16 bytes at a time."""
    var body = String()
    for _ in range(1024 * 1024 - 2):
        body += "x"
    var obj = String("{")
    var arr = String("[")
    for i in range(16):
        if i > 0:
            obj += ","
            arr += ","
        var key = String('"', body, chr(97 + i), '"')
        obj += key + ":0"
        arr += key
    obj += "}"
    arr += "]"
    var t_obj = _best_parse_ns(obj)
    var t_arr = _best_parse_ns(arr)
    print("16 keys of 1 MiB: object", t_obj // 1000000, "ms, array", t_arr // 1000000, "ms")
    assert_true(t_obj < 8 * t_arr, String("object ", t_obj, " ns vs array ", t_arr, " ns"))


def test_default_size_limit() raises:
    assert_equal(DEFAULT_MAX_SIZE, 64 * 1024 * 1024)
    var big = List[UInt8](length=DEFAULT_MAX_SIZE + 1, fill=32)
    var e = JsonError(0, "")
    try:
        _ = parse(Span(big))
    except err:
        e = err^
    assert_equal(e.kind, JsonError.LIMIT)
    assert_equal(e.offset, 0)
    # Raised, the limit lets it through to the grammar (all whitespace).
    try:
        _ = parse(Span(big), Limits(max_size=DEFAULT_MAX_SIZE + 1))
    except err:
        e = err^
    assert_equal(e.kind, JsonError.SYNTAX)
    assert_equal(e.offset, DEFAULT_MAX_SIZE + 1)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
