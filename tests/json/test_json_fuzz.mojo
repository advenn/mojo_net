"""Differential tests of `json.parse` against tests/json/json_oracle.py:
Python's json, made as strict (repeated keys, NaN and Infinity, lone
surrogates refused; numbers kept as text). Generated documents, most of
them mutated (bytes changed, cut, repeated, tokens planted: bad UTF-8,
surrogate escapes, stray brackets, leading zeros, BOMs), must be accepted
or refused as the oracle does, and an accepted one must render to the
oracle's compact text byte for byte. Numbers must read as Python reads
them: `float` to the same bits, `int` to the same value."""

from std.memory import bitcast
from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_true

from json import Document, JsonError, parse

comptime CASES = 4000


def _oracle() raises -> PythonObject:
    var sys = Python.import_module("sys")
    _ = sys.path.insert(0, "tests/json")
    return Python.import_module("json_oracle")


def _nibble(c: UInt8) -> UInt8:
    return c - 87 if c >= 97 else c - 48


def _unhex(s: Span[UInt8, _]) -> List[UInt8]:
    var out = List[UInt8](capacity=len(s) // 2)
    for i in range(0, len(s) - 1, 2):
        out.append(_nibble(s[i]) * 16 + _nibble(s[i + 1]))
    return out^


def _same(a: Span[UInt8, _], b: Span[UInt8, _]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def _differential(seed: Int) raises:
    var text = String(_oracle().fuzz(seed, CASES))
    var doc = Document()
    var out = List[UInt8]()
    var bad = 0
    var accepted = 0
    for line in text.split("\n"):
        var b = line.as_bytes()
        var sp = 0
        while b[sp] != 32:
            sp += 1
        var data = _unhex(b[:sp])
        var want_ok = b[sp + 1] == 111  # "ok ..." or "err"
        var ok = True
        var err = String()
        try:
            doc.parse(Span(data))
        except e:
            ok = False
            err = String(e)
        if ok != want_ok:
            if bad < 5:
                print("verdict differs:", String(line)[byte = : min(len(b), 400)], "->", "accepted" if ok else err)
            bad += 1
            continue
        if not ok:
            continue
        accepted += 1
        out.clear()
        doc.write_json(0, out)
        var want = _unhex(b[sp + 4 :])
        if not _same(Span(out), Span(want)):
            if bad < 5:
                print("rendering differs:", String(line)[byte = : min(len(b), 400)])
                print("  got:", String(unsafe_from_utf8=Span(out)) if len(out) <= 400 else String("(", len(out), " bytes)"))
            bad += 1
    assert_equal(bad, 0)
    assert_true(accepted > CASES // 4)


def test_differential_seed_1() raises:
    _differential(1)


def test_differential_seed_2() raises:
    _differential(2)


def test_differential_seed_3() raises:
    _differential(3)


def test_numbers() raises:
    var text = String(_oracle().numbers(7, 30000))
    var bad = 0
    for line in text.split("\n"):
        var parts = line.split(" ")
        var data = _unhex(parts[0].as_bytes())
        var doc = parse(Span(data))
        var fkind = 0
        var x = 0.0
        try:
            x = doc.float()
        except e:
            fkind = e.kind
        if parts[1] == "range":
            if fkind != JsonError.RANGE:
                bad += 1
        else:
            var bits: UInt64 = 0
            for c in parts[1].as_bytes():
                bits = bits * 16 + UInt64(_nibble(c))
            if fkind != 0 or bitcast[DType.uint64](x) != bits:
                if bad < 5:
                    print("float differs:", line)
                bad += 1
        var ikind = 0
        var v = 0
        try:
            v = doc.int()
        except e:
            ikind = e.kind
        if parts[2] == "type":
            if ikind != JsonError.TYPE:
                bad += 1
        elif parts[2] == "range":
            if ikind != JsonError.RANGE:
                bad += 1
        elif ikind != 0 or String(v) != parts[2]:
            if bad < 5:
                print("int differs:", line)
            bad += 1
    assert_equal(bad, 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
