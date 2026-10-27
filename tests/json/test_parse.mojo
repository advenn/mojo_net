"""`json.parse` and `Document`: the hand-written RFC 8259 cases in
tests/json/json_oracle.py (each labelled by hand, and checked there to
agree with Python's json made strict), error kinds and offsets, the
limits, and every accessor."""

from std.memory import bitcast
from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from json import DEFAULT_MAX_DEPTH, Document, JsonError, Kind, Limits, parse


def _oracle() raises -> PythonObject:
    var sys = Python.import_module("sys")
    _ = sys.path.insert(0, "tests/json")
    return Python.import_module("json_oracle")


def _bytes(o: PythonObject) raises -> List[UInt8]:
    var out = List[UInt8]()
    for b in o:
        out.append(UInt8(Int(py=b)))
    return out^


def _error(data: Span[UInt8, _], limits: Limits = Limits()) -> JsonError:
    """The error parsing `data` raises (kind 0 if it parses)."""
    try:
        _ = parse(data, limits)
    except e:
        return e^
    return JsonError(0, "parsed")


def _error(text: StringSlice, limits: Limits = Limits()) -> JsonError:
    return _error(text.as_bytes(), limits)


def test_hand_written_cases() raises:
    var cases = _oracle().CASES
    var bad = 0
    for item in cases:
        var data = _bytes(item[0])
        var want = Bool(py=item[1])
        var e = _error(Span(data))
        var got = e.kind == 0
        if got != want:
            print("wrong verdict:", item[0], "accepted" if got else String("refused: ", e))
            bad += 1
        elif not got:
            assert_true(e.kind == JsonError.SYNTAX, String(item[0]))
    assert_equal(bad, 0)


def test_error_offsets() raises:
    var e = _error("[1,]")
    assert_equal(e.kind, JsonError.SYNTAX)
    assert_equal(e.offset, 3)
    e = _error('{"a":1,"a":2}')
    assert_equal(e.offset, 12)  # (the '}' of the object with the key twice)
    e = _error('"abc')
    assert_equal(e.offset, 4)
    e = _error("  ")
    assert_equal(e.offset, 2)
    e = _error("[1] x")
    assert_equal(e.offset, 4)
    e = _error('["a\x01"]')
    assert_equal(e.offset, 3)
    assert_equal(String(_error("[1,]")), "json: not a JSON value (at byte 3)")


def test_depth_limit() raises:
    for obj in [False, True]:
        var ok = String()
        for _ in range(DEFAULT_MAX_DEPTH):
            ok += '{"k":' if obj else "["
        ok += "0"
        for _ in range(DEFAULT_MAX_DEPTH):
            ok += "}" if obj else "]"
        var doc = parse(ok)
        assert_equal(doc.nodes(), DEFAULT_MAX_DEPTH * (2 if obj else 1) + 1)
        var deep = ("[" if not obj else '{"k":') + ok + ("]" if not obj else "}")
        var e = _error(deep)
        assert_equal(e.kind, JsonError.LIMIT)
        assert_equal(e.offset, DEFAULT_MAX_DEPTH * (5 if obj else 1))
    # Far past any call stack: refused at the limit, not by a crash.
    var huge = String()
    for _ in range(1_000_000):
        huge += "["
    assert_equal(_error(huge).kind, JsonError.LIMIT)
    assert_equal(_error("[[1]]", Limits(max_depth=1)).kind, JsonError.LIMIT)
    assert_equal(_error("[1]", Limits(max_depth=1)).kind, 0)
    assert_equal(_error("1", Limits(max_depth=0)).kind, 0)
    assert_equal(_error("[]", Limits(max_depth=0)).kind, JsonError.LIMIT)


def test_size_limit() raises:
    assert_equal(_error("[1, 2]", Limits(max_size=6)).kind, 0)
    var e = _error("[1, 2] ", Limits(max_size=6))
    assert_equal(e.kind, JsonError.LIMIT)
    assert_equal(e.offset, 0)


def test_kinds_and_navigation() raises:
    var doc = parse(' {"a": [1, -2.5e3, "x", true, false, null, {}, []], "b": {"c": {"d": 7}}, "e": "\\u00e9"} ')
    assert_equal(doc.kind(), Kind.OBJECT)
    assert_equal(doc.count(), 3)
    var a = doc.member(0, "a")
    assert_equal(a, 2)
    assert_equal(doc.kind(a), Kind.ARRAY)
    assert_equal(doc.count(a), 8)
    var want: List[Kind] = [Kind.NUMBER, Kind.NUMBER, Kind.STRING, Kind.BOOL, Kind.BOOL, Kind.NULL, Kind.OBJECT, Kind.ARRAY]
    var c = doc.child(a, 0)
    for k in range(8):
        assert_equal(doc.child(a, k), c)
        assert_equal(doc.kind(c), want[k])
        c = doc.next(c)
    assert_equal(c, doc.key(0, 1))
    assert_equal(doc.text(doc.key(0, 1)), "b")
    var d = doc.member(doc.member(doc.val(0, 1), "c"), "d")
    assert_equal(doc.int(d), 7)
    assert_equal(doc.text(doc.member(0, "e")), "é")
    assert_false(doc.get(0, "z"))
    assert_equal(doc.get(0, "e").value(), doc.val(0, 2))
    assert_equal(doc.count(doc.child(a, 6)), 0)
    assert_equal(doc.next(0), doc.nodes())
    # Iterating an object's pairs: key c, value c + 1, next key next(c + 1).
    var keys = String()
    var k = 1
    for _ in range(doc.count()):
        keys += doc.text(k)
        k = doc.next(k + 1)
    assert_equal(keys, "abe")


def _kind_of_error(doc: Document, what: String, n: Int) -> Int:
    try:
        if what == "count":
            _ = doc.count(n)
        elif what == "child":
            _ = doc.child(n, 0)
        elif what == "key":
            _ = doc.key(n, 0)
        elif what == "get":
            _ = doc.get(n, "a")
        elif what == "text":
            _ = doc.text(n)
        elif what == "int":
            _ = doc.int(n)
        elif what == "float":
            _ = doc.float(n)
        elif what == "bool":
            _ = doc.bool(n)
        elif what == "kind":
            _ = doc.kind(n)
        elif what == "next":
            _ = doc.next(n)
    except e:
        return e.kind
    return 0


def test_accessor_errors() raises:
    var doc = parse('[{"a": 1}, "s", 1.5, true, null, [2]]')
    # node numbers: 0 [ ; 1 { ; 2 "a" ; 3 1 ; 4 "s" ; 5 1.5 ; 6 true ; 7 null ; 8 [ ; 9 2
    for what in ["count", "child", "key", "get", "text", "int", "float", "bool", "kind", "next"]:
        assert_equal(_kind_of_error(doc, what, -1), JsonError.MISSING)
        assert_equal(_kind_of_error(doc, what, 10), JsonError.MISSING)
    assert_equal(_kind_of_error(doc, "count", 4), JsonError.TYPE)
    assert_equal(_kind_of_error(doc, "child", 1), JsonError.TYPE)
    assert_equal(_kind_of_error(doc, "key", 0), JsonError.TYPE)
    assert_equal(_kind_of_error(doc, "get", 8), JsonError.TYPE)
    assert_equal(_kind_of_error(doc, "text", 6), JsonError.TYPE)
    assert_equal(_kind_of_error(doc, "int", 4), JsonError.TYPE)
    assert_equal(_kind_of_error(doc, "int", 5), JsonError.TYPE)
    assert_equal(_kind_of_error(doc, "float", 7), JsonError.TYPE)
    assert_equal(_kind_of_error(doc, "bool", 7), JsonError.TYPE)
    var kind = 0
    try:
        _ = doc.child(8, 1)
    except e:
        kind = e.kind
    assert_equal(kind, JsonError.MISSING)
    kind = 0
    try:
        _ = doc.member(1, "b")
    except e:
        kind = e.kind
    assert_equal(kind, JsonError.MISSING)
    assert_true(doc.bool(6))
    assert_true(doc.is_null(7))
    assert_false(doc.is_null(6))
    assert_equal(doc.text(5), "1.5")
    assert_equal(doc.view(4), "s")


def _int_error(text: StaticString) raises -> Int:
    var doc = parse(text)
    try:
        _ = doc.int()
    except e:
        return e.kind
    return 0


def test_integers() raises:
    assert_equal(parse("9223372036854775807").int(), Int.MAX)
    assert_equal(parse("-9223372036854775808").int(), Int.MIN)
    assert_equal(parse("-0").int(), 0)
    assert_equal(parse("0").int(), 0)
    assert_equal(parse("-1").int(), -1)
    assert_equal(_int_error("9223372036854775808"), JsonError.RANGE)
    assert_equal(_int_error("-9223372036854775809"), JsonError.RANGE)
    assert_equal(_int_error("99999999999999999999"), JsonError.RANGE)
    assert_equal(_int_error("1.0"), JsonError.TYPE)
    assert_equal(_int_error("1e2"), JsonError.TYPE)


def test_floats() raises:
    assert_equal(parse("1.5").float(), 1.5)
    assert_equal(parse("-2.5e-3").float(), -0.0025)
    assert_equal(parse("7").float(), 7.0)
    assert_equal(bitcast[DType.uint64](parse("-0").float()), UInt64(1) << 63)
    assert_equal(parse("1e-400").float(), 0.0)
    assert_equal(parse("4.9e-324").float(), 5e-324)
    assert_equal(parse("1.7976931348623157e308").float(), 1.7976931348623157e308)
    for t in ["1e400", "-1e400", "1.8e308"]:
        var kind = 0
        try:
            _ = parse(t).float()
        except e:
            kind = e.kind
        assert_equal(kind, JsonError.RANGE)


def test_strings() raises:
    var doc = parse('["\\"\\\\\\/\\b\\f\\n\\r\\t", "\\u0000", "\\ud83d\\ude00\\u00E9", "plain"]')
    var want: List[UInt8] = [34, 92, 47, 8, 12, 10, 13, 9]
    var got = doc.view(1).as_bytes()
    assert_equal(len(got), len(want))
    for i in range(len(want)):
        assert_equal(got[i], want[i])
    assert_equal(len(doc.view(2).as_bytes()), 1)
    assert_equal(doc.text(3), "😀é")
    assert_equal(doc.text(4), "plain")
    # Long runs, past the 16-byte scan, with the special byte at each place.
    for n in range(40):
        var s = String('"')
        for _ in range(n):
            s += "a"
        s += 'é\\n"'
        assert_equal(parse(s).text().byte_length(), n + 3)


def test_reuse_and_failure_leaves_empty() raises:
    var doc = Document()
    doc.parse('{"a": [1, 2, 3]}')
    assert_equal(doc.nodes(), 6)
    doc.parse("[true]")
    assert_equal(doc.nodes(), 2)
    assert_true(doc.bool(1))
    var kind = 0
    try:
        doc.parse("[1, 2")
    except e:
        kind = e.kind
    assert_equal(kind, JsonError.SYNTAX)
    assert_equal(doc.nodes(), 0)
    assert_equal(String(doc), "")
    doc.parse(" {} ")
    assert_equal(String(doc), "{}")


def test_large_objects_repeated_keys() raises:
    """Past the pair-by-pair check: keys sorted, a repeat found anywhere."""
    for n in [17, 100, 1000]:
        var s = String("{")
        for i in range(n):
            if i > 0:
                s += ","
            s += String('"k', (i * 7919) % n, '":', i)
        s += "}"
        var doc = parse(s)
        assert_equal(doc.count(), n)
        for at in [0, n // 2, n - 1]:
            var t = String("{")
            for i in range(n):
                if i > 0:
                    t += ","
                t += String('"k', (i * 7919) % n, '":', i)
            t += String(',"k', (at * 7919) % n, '":0}')
            assert_equal(_error(t).kind, JsonError.SYNTAX)
    # Keys that are prefixes of each other are different keys.
    _ = parse('{"a":1,"ab":2,"abc":3,"":4,"b":5,"ba":6,"aa":7,"a\\u0000":8,"c":9,"d":10,"e":11,"f":12,"g":13,"h":14,"i":15,"j":16,"k":17,"l":18}')


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
