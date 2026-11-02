"""`json.number.read_float` against Python's float() (number_oracle.py):
random digits and doubles written every way, integers around 2^53 (the
round to even), short decimals over the whole exponent range, and the
edges of the subnormal and the overflow ranges. A text read_float takes
must read to the same bits; the others (more than 19 digits, subnormals)
must be few, and `Document.float` (its fallback, `atof`) must read them to
the same bits too."""

from std.memory import bitcast
from std.python import Python
from std.testing import TestSuite, assert_equal, assert_true

from json import Document, Dialect, read_float


def _hex(x: Float64) -> String:
    var b = bitcast[DType.uint64, 1](x)
    var digits = String("0123456789abcdef")
    var out = String()
    for k in range(15, -1, -1):
        var d = Int((b >> UInt64(4 * k)) & 15)
        out += digits[byte=d]
    return out^


def _run(seed: Int, n: Int) raises:
    var sys = Python.import_module("sys")
    _ = sys.path.insert(0, "tests/json")
    var text = String(Python.import_module("number_oracle").cases(seed, n))
    var doc = Document()
    var bad = 0
    var taken = 0
    var count = 0
    for line in text.split("\n"):
        var sp = line.find(" ")
        var t = String(line[byte=0:sp])
        var want = String(line[byte = sp + 1 :])
        count += 1
        var x: Float64 = 0
        if read_float(t.as_bytes(), x):
            taken += 1
            if _hex(x) != want:
                bad += 1
                if bad < 10:
                    print("read_float", t, _hex(x), "want", want)
        # Padded, with digits after the text that must not be read as its.
        var padded = List[UInt8](t.as_bytes())
        for _ in range(8):
            padded.append(55)  # '7'
        var z: Float64 = 0
        var took = read_float[padded=True](Span(padded)[: t.byte_length()], z)
        var x2: Float64 = 0
        if took != read_float(t.as_bytes(), x2) or (took and _hex(z) != want):
            bad += 1
            if bad < 10:
                print("read_float[padded]", t, _hex(z), "want", want)
        # Through a document: read_float, or the fallback.
        doc.parse(t)
        var y: Float64 = 0
        try:
            y = doc.float()
        except:
            y = FloatLiteral.negative_infinity if t.startswith("-") else FloatLiteral.infinity  # (RANGE: past Float64)
        if _hex(y) != want:
            bad += 1
            if bad < 10:
                print("Document.float", t, _hex(y), "want", want)
    print(count, "texts,", taken, "read by read_float")
    assert_equal(bad, 0)
    # (The generator leans on more than 19 digits and on subnormals, which
    # are the fallback's: about 84% are read_float's.)
    assert_true(taken > count * 3 // 4)


def test_against_python_seed_1() raises:
    _run(1, 100000)


def test_against_python_seed_2() raises:
    _run(2, 100000)


def test_not_numbers_refused() raises:
    var x: Float64 = 7
    for t in ["", "-", "1x", "1e", "1e+", "1.", ".5", "1.5.5", "NaN", "Infinity", "--1", "-e5"]:
        assert_true(not read_float(String(t).as_bytes(), x), t)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
