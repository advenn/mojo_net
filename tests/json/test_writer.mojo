"""`json.Writer`: strings escaped exactly as Python's json.dumps escapes
them (ensure_ascii=False) and read back by Python's strict reader, the
structure checks (each misuse raises USAGE and leaves the text as it
was), numbers, documents copied in, and random structures that our parser
and Python's must both read back as written."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from json import JsonError, Writer, parse


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


def _hex(s: Span[UInt8, _]) -> String:
    comptime digits = "0123456789abcdef"
    var out = String()
    for b in s:
        out += digits[byte = Int(b >> 4)]
        out += digits[byte = Int(b & 15)]
    return out^


def _same(a: Span[UInt8, _], b: Span[UInt8, _]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def _text(w: Writer) -> String:
    return String(unsafe_from_utf8=w.as_bytes())


def test_example_from_the_docs() raises:
    var w = Writer()
    w.begin_object()
    w.key("model")
    w.string("m")
    w.key("messages")
    w.begin_array()
    w.begin_object()
    w.key("role")
    w.string("user")
    w.end_object()
    w.end_array()
    w.key("temperature")
    w.float(0.2)
    w.end_object()
    assert_true(w.is_complete())
    var body = w.take()
    assert_equal(String(unsafe_from_utf8=Span(body)), '{"model":"m","messages":[{"role":"user"}],"temperature":0.2}')
    assert_false(w.is_complete())
    assert_equal(len(w.as_bytes()), 0)


def test_strings_match_python() raises:
    var o = _oracle()
    var text = String(o.strings(5, 3000))
    var bad = 0
    for line in text.split("\n"):
        var raw = _unhex(line.as_bytes())
        var w = Writer()
        w.string(StringSlice(unsafe_from_utf8=Span(raw)))
        var out = w.take()
        var want = String(o.dumps_hex(line))
        if _hex(Span(out)) != want:
            if bad < 5:
                print("escaping differs for", line, ":", String(unsafe_from_utf8=Span(out)))
            bad += 1
        elif String(o.loads_hex(want)) != String(line):
            bad += 1
        elif not _same(parse(Span(out)).view().as_bytes(), Span(raw)):
            bad += 1
    assert_equal(bad, 0)


def test_numbers() raises:
    var w = Writer()
    w.begin_array()
    for v in [0, 1, -1, 10, -10, 1234567890, Int.MAX, Int.MIN]:
        w.int(v)
    w.float(-0.0)
    w.float(1.5)
    w.float(1e21)
    w.float(5e-324)
    w.end_array()
    assert_equal(
        _text(w),
        "[0,1,-1,10,-10,1234567890,9223372036854775807,-9223372036854775808,-0,1.5,1e+21,5e-324]",
    )
    var doc = parse(w.as_bytes())
    assert_equal(doc.int(doc.child(0, 7)), Int.MIN)


def _usage(mut w: Writer, call: String) -> Bool:
    """Whether `call` raises USAGE, leaving the text as it was."""
    var before = _text(w)
    var kind = 0
    try:
        if call == "key":
            w.key("k")
        elif call == "int":
            w.int(1)
        elif call == "string":
            w.string("s")
        elif call == "null":
            w.null()
        elif call == "begin_object":
            w.begin_object()
        elif call == "begin_array":
            w.begin_array()
        elif call == "end_object":
            w.end_object()
        elif call == "end_array":
            w.end_array()
        elif call == "take":
            _ = w.take()
        elif call == "nan":
            w.float(Float64.MAX * 2 - Float64.MAX * 2)
        elif call == "inf":
            w.float(Float64.MAX * 2)
        elif call == "bad_utf8":
            var b: List[UInt8] = [0x61, 0xFF]
            w.string(StringSlice(unsafe_from_utf8=Span(b)))
        elif call == "bad_utf8_key":
            var b: List[UInt8] = [0xC0, 0x80]
            w.key(StringSlice(unsafe_from_utf8=Span(b)))
    except e:
        kind = e.kind
    return kind == JsonError.USAGE and _text(w) == before


def test_structure_is_checked() raises:
    var w = Writer()
    for call in ["key", "end_object", "end_array", "take", "nan", "inf", "bad_utf8"]:
        assert_true(_usage(w, call), call)
    w.begin_object()
    for call in ["int", "string", "null", "begin_array", "begin_object", "end_array", "take", "bad_utf8_key"]:
        assert_true(_usage(w, call), call)
    w.key("a")
    for call in ["key", "end_object", "end_array", "take", "nan", "bad_utf8"]:
        assert_true(_usage(w, call), call)
    w.begin_array()
    for call in ["key", "end_object", "take"]:
        assert_true(_usage(w, call), call)
    w.int(1)
    assert_true(_usage(w, "bad_utf8"))
    w.string("x")  # (no comma left over from the refused string)
    w.end_array()
    w.end_object()
    for call in ["int", "begin_array", "key", "end_object", "string"]:
        assert_true(_usage(w, call), call)
    assert_equal(_text(w), '{"a":[1,"x"]}')
    var w2 = Writer()
    w2.int(5)
    assert_true(_usage(w2, "int"))
    assert_equal(String(unsafe_from_utf8=Span(w2.take())), "5")


def test_documents_copied_in() raises:
    var doc = parse('{"a": [1, {"b": "\\n"}], "c": null}')
    var w = Writer()
    w.begin_array()
    w.document(doc)
    w.document(doc, doc.member(0, "a"))
    w.document(doc, doc.member(0, "c"))
    var kind = 0
    try:
        w.document(doc, 99)
    except e:
        kind = e.kind
    assert_equal(kind, JsonError.MISSING)
    w.end_array()
    assert_equal(_text(w), '[{"a":[1,{"b":"\\n"}],"c":null},[1,{"b":"\\n"}],null]')


struct _Rng(Movable):
    var s: UInt64

    def __init__(out self, seed: UInt64):
        self.s = seed

    def below(mut self, n: Int) -> Int:
        self.s += 0x9E3779B97F4A7C15
        var z = self.s
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB
        return Int((z ^ (z >> 31)) % UInt64(n))


def _random_value(mut w: Writer, mut rng: _Rng, depth: Int) raises:
    var r = rng.below(10)
    if depth > 6 or r < 5:
        var s = rng.below(6)
        if s == 0:
            w.int(rng.below(2000000) - 1000000)
        elif s == 1:
            w.float(Float64(rng.below(1000000)) / Float64(rng.below(999) + 1))
        elif s == 2:
            w.string(String("s\n\"", rng.below(100), "é\t"))
        elif s == 3:
            w.bool(rng.below(2) == 0)
        elif s == 4:
            w.null()
        else:
            w.string("")
    elif r < 8:
        w.begin_array()
        for _ in range(rng.below(5)):
            _random_value(w, rng, depth + 1)
        w.end_array()
    else:
        w.begin_object()
        for i in range(rng.below(5)):
            w.key(String("k", i))
            _random_value(w, rng, depth + 1)
        w.end_object()


def test_random_structures_read_back() raises:
    var o = _oracle()
    var rng = _Rng(11)
    var w = Writer()
    for _ in range(2000):
        _random_value(w, rng, 0)
        var out = w.take()
        var doc = parse(Span(out))
        assert_equal(doc.json(), String(unsafe_from_utf8=Span(out)))
        var want = String(o.expect(Python.import_module("builtins").bytes.fromhex(_hex(Span(out)))))
        assert_equal(want, "ok " + _hex(Span(out)))


def test_deep_nesting_and_reuse() raises:
    var w = Writer(capacity=4096)
    for _ in range(2000):
        w.begin_array()
    for _ in range(2000):
        w.end_array()
    assert_true(w.is_complete())
    assert_equal(len(w.as_bytes()), 4000)
    w.clear()
    w.null()
    assert_equal(_text(w), "null")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
