"""The repeated-key check with colliding hashes. Fault-seam builds
(`-D MOJO_NET_FAULTS=1`, which the runner passes to `*_faults.mojo` files)
keep 8 bits of each key's hash, so objects past the pair by pair check
put many keys under one hash, and the comparisons within a hash decide;
objects of 20,000 pairs take the bucketed sort.
The verdicts must match tests/json/json_oracle.py (Python's json with a
repeated-key hook). This file uses no `linux.fault` seam (`json` imports
only `std`), so there is nothing to clear."""

from std.python import Python, PythonObject
from std.sys import get_defined_bool
from std.testing import TestSuite, assert_equal, assert_true

from json import Document


def _nibble(c: UInt8) -> UInt8:
    return c - 87 if c >= 97 else c - 48


def _unhex(s: Span[UInt8, _]) -> List[UInt8]:
    var out = List[UInt8](capacity=len(s) // 2)
    for i in range(0, len(s) - 1, 2):
        out.append(_nibble(s[i]) * 16 + _nibble(s[i + 1]))
    return out^


def test_colliding_hashes_match_the_oracle() raises:
    comptime assert get_defined_bool["MOJO_NET_FAULTS"](), "build with -D MOJO_NET_FAULTS=1"
    var sys = Python.import_module("sys")
    _ = sys.path.insert(0, "tests/json")
    var text = String(Python.import_module("json_oracle").objects(3, 300))
    var doc = Document()
    var refused = 0
    var bad = 0
    for line in text.split("\n"):
        var b = line.as_bytes()
        var sp = 0
        while b[sp] != 32:
            sp += 1
        var data = _unhex(b[:sp])
        var want_ok = b[sp + 1] == 111
        var ok = True
        try:
            doc.parse(Span(data))
        except:
            ok = False
        if ok != want_ok:
            bad += 1
        if not ok:
            refused += 1
    assert_equal(bad, 0)
    assert_true(refused > 50 and refused < 250)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
