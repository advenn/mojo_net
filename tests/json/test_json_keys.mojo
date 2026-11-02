"""The repeated-key check's paths in a normal build (J2): objects of up to
16 pairs compared pair by pair, larger ones through a table of cheap
hashes (in 256 buckets past 4,096 pairs), and keys chosen to share the
cheap hash (one length, the same first and last 8 bytes), which overflow
the table's probes and go through the sort and SipHash. Each path must
find a repeat, and accept distinct keys, in time bounded against the same
strings in an array. (`test_json_keys_faults.mojo` drives the same paths
with 8-bit hashes, against the oracle.)"""

from std.testing import TestSuite, assert_equal, assert_true
from std.time import perf_counter_ns

from json import Document, JsonError, parse


def _best_parse_ns(text: String) raises -> Int:
    var doc = Document()
    var best = Int.MAX
    for _ in range(3):
        var t = perf_counter_ns()
        doc.parse(text)
        best = min(best, Int(perf_counter_ns() - t))
    return best


def _keys(n: Int, head: String, tail: String, as_object: Bool, repeat: Int = -1) -> String:
    """`n` keys `head` + 8 digits + `tail`, in an object or (the strings
    alone) an array; key `repeat` written again at the end."""
    var s = String("{" if as_object else "[")
    for i in range(n + (1 if repeat >= 0 else 0)):
        if i > 0:
            s += ","
        var digits = String(i if i < n else repeat)
        s += '"' + head
        for _ in range(8 - digits.byte_length()):
            s += "0"
        s += digits + tail + ('":0' if as_object else '"')
    s += "}" if as_object else "]"
    return s^


def _kind(text: String) -> Int:
    try:
        _ = parse(text)
    except e:
        return e.kind
    return 0


def test_every_size_finds_a_repeat() raises:
    for n in [2, 3, 16, 17, 100, 4096, 4097, 20000]:
        for tail in [String(""), String("zzzzzzzz")]:
            assert_equal(_kind(_keys(n, "k", tail, True)), 0, String(n))
            for at in [0, n // 2, n - 1]:
                assert_equal(_kind(_keys(n, "k", tail, True, at)), JsonError.SYNTAX, String(n, " ", at))


def test_colliding_cheap_hashes_bounded() raises:
    """Keys of one length with the same first and last 8 bytes share the
    cheap hash: every key collides in the table, which gives up after
    `_PROBES` slots; the sort and SipHash take over, about 10 times an
    array's parse (a pair by pair check of 200,000 keys would take
    minutes)."""
    for n in [64, 5000, 200000]:
        var obj = _keys(n, "aaaaaaaa", "zzzzzzzz", True)
        var arr = _keys(n, "aaaaaaaa", "zzzzzzzz", False)
        assert_equal(_kind(obj), 0)
        assert_equal(_kind(_keys(n, "aaaaaaaa", "zzzzzzzz", True, n // 3)), JsonError.SYNTAX)
        if n == 200000:
            var t_obj = _best_parse_ns(obj)
            var t_arr = _best_parse_ns(arr)
            print("200k colliding keys: object", t_obj // 1000000, "ms, array", t_arr // 1000000, "ms")
            assert_true(t_obj < 20 * t_arr, String("object ", t_obj, " ns vs array ", t_arr, " ns"))


def test_distinct_keys_bounded() raises:
    var obj = _keys(300000, "", "", True)
    var arr = _keys(300000, "", "", False)
    var t_obj = _best_parse_ns(obj)
    var t_arr = _best_parse_ns(arr)
    print("300k keys: object", t_obj // 1000000, "ms, array", t_arr // 1000000, "ms")
    assert_true(t_obj < 8 * t_arr, String("object ", t_obj, " ns vs array ", t_arr, " ns"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
