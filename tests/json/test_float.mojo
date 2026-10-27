"""`json.ryu`: shortest round-trip digits in ECMAScript's layout, against
tests/json/float_oracle.py (Python's repr: David Gay's dtoa, another
algorithm), on hard cases and on random doubles of several kinds; each
text must also read back as the same double through Mojo's `atof`."""

from std.memory import bitcast
from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_true

from json import JsonError, format_float, write_float
from json.ryu import MAX_FLOAT_LENGTH, Shortest, shortest


def _oracle() raises -> PythonObject:
    var sys = Python.import_module("sys")
    _ = sys.path.insert(0, "tests/json")
    return Python.import_module("float_oracle")


def _nibble(c: UInt8) -> UInt64:
    return UInt64(c - 87) if c >= 97 else UInt64(c - 48)


def _same(a: Span[UInt8, _], b: Span[UInt8, _]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def _check(text: String) raises -> Int:
    """Each line is "<16 hex digits of the bits> <expected text>"."""
    var n = 0
    var bad = 0
    var out = List[UInt8](capacity=32)
    for line in text.split("\n"):
        var b = line.as_bytes()
        if len(b) == 0:
            continue
        var bits: UInt64 = 0
        for i in range(16):
            bits = bits * 16 + _nibble(b[i])
        var x = bitcast[DType.float64](bits)
        out.clear()
        write_float(out, x)
        var got = String(unsafe_from_utf8=Span(out))
        if not _same(Span(out), b[17:]) or len(out) > MAX_FLOAT_LENGTH:
            if bad < 10:
                print("mismatch:", line, "got", got)
            bad += 1
        elif bitcast[DType.uint64](atof(got)) != bits:
            if bad < 10:
                print("does not read back:", line)
            bad += 1
        n += 1
    assert_equal(bad, 0)
    return n


def test_hard_cases() raises:
    var n = _check(String(_oracle().hard()))
    assert_true(n > 6000)


def test_random_bits() raises:
    _ = _check(String(_oracle().batch(1, 300000, "bits")))


def test_random_decimals() raises:
    _ = _check(String(_oracle().batch(2, 200000, "decimal")))


def test_random_integers() raises:
    _ = _check(String(_oracle().batch(3, 100000, "int")))


def test_random_subnormals() raises:
    _ = _check(String(_oracle().batch(4, 100000, "subnormal")))


def test_layout_matches_javascript() raises:
    """Written from JavaScript's own outputs (`String(x)`), independently of
    the oracle's layout code."""
    assert_equal(format_float(1e21), "1e+21")
    assert_equal(format_float(1e20), "100000000000000000000")
    assert_equal(format_float(123456789012345680000.0), "123456789012345680000")
    assert_equal(format_float(1e-7), "1e-7")
    assert_equal(format_float(1.5e-7), "1.5e-7")
    assert_equal(format_float(1e-6), "0.000001")
    assert_equal(format_float(1.5e-6), "0.0000015")
    assert_equal(format_float(123e-20), "1.23e-18")
    assert_equal(format_float(1.5), "1.5")
    assert_equal(format_float(100.0), "100")
    assert_equal(format_float(-2.5), "-2.5")
    assert_equal(format_float(5e-324), "5e-324")
    assert_equal(format_float(1.7976931348623157e308), "1.7976931348623157e+308")
    assert_equal(format_float(9007199254740992.0), "9007199254740992")
    assert_equal(format_float(Float64(0.1) + Float64(0.2)), "0.30000000000000004")
    assert_equal(format_float(1e300), "1e+300")
    assert_equal(format_float(0.0), "0")
    # The one difference from JavaScript: the sign of zero is kept.
    assert_equal(format_float(-0.0), "-0")


def test_shortest_digits() raises:
    assert_true(shortest(1.5) == Shortest(False, 15, -1))
    assert_true(shortest(-1.5) == Shortest(True, 15, -1))
    assert_true(shortest(100.0) == Shortest(False, 1, 2))
    assert_true(shortest(0.0) == Shortest(False, 0, 0))
    assert_true(shortest(-0.0) == Shortest(True, 0, 0))
    assert_true(shortest(5e-324) == Shortest(False, 5, -324))
    assert_true(shortest(1.7976931348623157e308) == Shortest(False, 17976931348623157, 292))


def test_refuses_nan_and_infinities() raises:
    var inf = Float64.MAX * 2
    for x in [inf, -inf, inf - inf]:
        var out = List[UInt8]()
        var kind = 0
        try:
            write_float(out, x)
        except e:
            kind = e.kind
        assert_equal(kind, JsonError.USAGE)
        assert_equal(len(out), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
