"""`Document.scan` against `Document.parse` and `visit`: the same texts
accepted and refused, with the same errors, and the same values handed
over in the same order, in every dialect. The texts: the fuzz cases of
tests/json/json_oracle.py (generated documents, most of them mutated),
hand cases at the edges, and deep and wide ones. Then what is `scan`'s
own: a handler that stops it, and the limits."""

from std.os import getenv
from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from json import Dialect, Document, Handler, JsonError, Limits, Visitor


def _env(name: StaticString, default: Int) raises -> Int:
    var v = getenv(name)
    return atol(v) if v.byte_length() > 0 else default


def _nibble(c: UInt8) -> UInt8:
    return c - 87 if c >= 97 else c - 48


def _unhex(s: Span[UInt8, _]) -> List[UInt8]:
    var out = List[UInt8](capacity=len(s) // 2)
    for i in range(0, len(s) - 1, 2):
        out.append(_nibble(s[i]) * 16 + _nibble(s[i + 1]))
    return out^


def _log(mut out: List[UInt8], tag: String, text: Span[UInt8, _]):
    out.extend(tag.as_bytes())
    out.extend(String(len(text)).as_bytes())
    out.append(58)
    out.extend(text)
    out.append(59)


struct Recorder(Handler):
    """Every call, written down; stops after `stop_after` calls when that
    is not -1."""

    var out: List[UInt8]
    var calls: Int
    var stop_after: Int

    def __init__(out self, stop_after: Int = -1):
        self.out = List[UInt8]()
        self.calls = 0
        self.stop_after = stop_after

    def _go(mut self) -> Bool:
        self.calls += 1
        return self.stop_after < 0 or self.calls <= self.stop_after

    def null(mut self) -> Bool:
        self.out.extend("n;".as_bytes())
        return self._go()

    def boolean(mut self, value: Bool) -> Bool:
        self.out.extend(("t;" if value else "f;").as_bytes())
        return self._go()

    def number(mut self, text: Span[UInt8, ImmutAnyOrigin], integer: Bool) -> Bool:
        _log(self.out, "I" if integer else "N", text)
        # (SPAN_SLACK bytes past it can be read)
        _ = text.unsafe_ptr().unsafe_load[width=32](len(text))
        return self._go()

    def string(mut self, text: Span[UInt8, ImmutAnyOrigin]) -> Bool:
        _log(self.out, "S", text)
        _ = text.unsafe_ptr().unsafe_load[width=32](len(text))
        return self._go()

    def key(mut self, text: Span[UInt8, ImmutAnyOrigin]) -> Bool:
        _log(self.out, "K", text)
        return self._go()

    def begin_array(mut self) -> Bool:
        self.out.extend("[".as_bytes())
        return self._go()

    def end_array(mut self, count: Int) -> Bool:
        self.out.extend(("]" + String(count) + ";").as_bytes())
        return self._go()

    def begin_object(mut self) -> Bool:
        self.out.extend("{".as_bytes())
        return self._go()

    def end_object(mut self, count: Int) -> Bool:
        self.out.extend(("}" + String(count) + ";").as_bytes())
        return self._go()


struct VisitRecorder(Visitor):
    """The same log from `visit`, whose sizes come first: kept on a stack
    and written at the end, where `scan` gives them."""

    var out: List[UInt8]
    var sizes: List[Int]

    def __init__(out self):
        self.out = List[UInt8]()
        self.sizes = List[Int]()

    def null(mut self) raises:
        self.out.extend("n;".as_bytes())

    def boolean(mut self, value: Bool) raises:
        self.out.extend(("t;" if value else "f;").as_bytes())

    def number(mut self, text: Span[UInt8, ImmutAnyOrigin], integer: Bool) raises:
        _log(self.out, "I" if integer else "N", text)

    def string(mut self, text: Span[UInt8, ImmutAnyOrigin]) raises:
        _log(self.out, "S", text)

    def key(mut self, text: Span[UInt8, ImmutAnyOrigin]) raises:
        _log(self.out, "K", text)

    def begin_array(mut self, count: Int) raises:
        self.out.extend("[".as_bytes())
        self.sizes.append(count)

    def end_array(mut self) raises:
        self.out.extend(("]" + String(self.sizes.pop()) + ";").as_bytes())

    def begin_object(mut self, count: Int) raises:
        self.out.extend("{".as_bytes())
        self.sizes.append(count)

    def end_object(mut self) raises:
        self.out.extend(("}" + String(self.sizes.pop()) + ";").as_bytes())


def _outcome_parse(text: Span[UInt8, _], dialect: Dialect, limits: Limits) raises -> String:
    var doc = Document()
    try:
        doc.parse(text, limits, dialect)
    except e:
        return "error " + String(e.kind) + " " + String(e.offset) + " " + e.message
    var v = VisitRecorder()
    doc.visit(v)
    return "ok " + String(unsafe_from_utf8=v.out)


def _outcome_scan(mut doc: Document, text: Span[UInt8, _], dialect: Dialect, limits: Limits) -> String:
    try:
        var r = Recorder()
        if not doc.scan(text, r, limits, dialect):
            return "stopped"
        return "ok " + String(unsafe_from_utf8=r.out)
    except e:
        return "error " + String(e.kind) + " " + String(e.offset) + " " + e.message


def _dialects() -> List[Dialect]:
    return [Dialect(), Dialect.python(), Dialect.python(control_characters=True)]


def _same_everywhere(mut doc: Document, text: Span[UInt8, _], limits: Limits = Limits()) raises -> Int:
    """Compare in every dialect; how many dialects accepted the text."""
    var accepted = 0
    for d in _dialects():
        var want = _outcome_parse(text, d, limits)
        var got = _outcome_scan(doc, text, d, limits)
        if got != want:
            print("text:", String(unsafe_from_utf8=Span(text)[: min(len(text), 300)]))
            print("parse:", want)
            print("scan: ", got)
        assert_equal(got, want)
        if want.startswith("ok"):
            accepted += 1
    return accepted


def test_fuzz_cases() raises:
    """The oracle's generated and mutated documents, in every dialect: the
    same outcome, value for value, error for error."""
    var sys = Python.import_module("sys")
    _ = sys.path.insert(0, "tests/json")
    var oracle = Python.import_module("json_oracle")
    var seed = 31 + _env("MOJO_NET_FUZZ_SEED", 0)
    var cases = 4000 * _env("MOJO_NET_FUZZ_SCALE", 1)
    var lines = String(oracle.fuzz(seed, cases)).split("\n")
    var doc = Document()
    var accepted = 0
    var total = 0
    for line in lines:
        var parts = line.split(" ")
        if len(parts) < 2:
            continue
        var text = _unhex(parts[0].as_bytes())
        accepted += _same_everywhere(doc, text)
        total += 1
    print("   ", total, "texts, accepted", accepted, "times in 3 dialects")
    assert_true(total >= 3000)
    assert_true(accepted > total // 2)


def test_hand_cases() raises:
    """Edges: empty containers at every depth, repeated keys (refused by
    the strict dialect only, whatever their nesting), escapes, constants,
    numbers, and text that ends anywhere."""
    var doc = Document()
    var texts: List[String] = [
        "[]", "{}", "[[]]", "[{}]", '{"a":{}}', '{"a":[]}', "[[],[[]],{}]", " [ ] ", "0", "-0.0e+1", '""',
        '"\\u00e9\\ud83d\\ude00\\n"', "[1,2,3]", '{"a":1,"b":2}', '{"a":1,"a":2}', '{"a":{"b":1,"b":2}}',
        '{"a":{"b":1},"b":{"a":1}}', '[{"x":1,"y":2},{"x":3,"x":4}]', '{"a":1,"b":{"c":{"d":1,"d":2}},"e":1}',
        "NaN", "[Infinity,-Infinity,NaN]", '"\\ud800"', '"a\tb"', "[1,]", '{"a":1,}', '{"a" 1}', "[1 2]",
        "tru", "nul", "[", '{"a":', '"abc', "1e", "01", "[true,false,null]", '{"":"","\\u0000":1}',
        '{"k1":1,"k2":2,"k3":3,"k4":4,"k5":5,"k6":6,"k7":7,"k8":8,"k9":9,"k10":10,"k11":11,"k12":12,'
        + '"k13":13,"k14":14,"k15":15,"k16":16,"k17":17,"k1":0}',
    ]
    for t in texts:
        _ = _same_everywhere(doc, t.as_bytes())
        # And every prefix: the input ends anywhere.
        var b = t.as_bytes()
        for k in range(len(b)):
            _ = _same_everywhere(doc, b[:k])


def test_wide_and_deep() raises:
    """Objects with many keys (the hashed and the sorted key checks, a
    repeat at the start, middle and end), nesting to the limit and past
    it, and objects inside objects whose keys repeat across levels."""
    var doc = Document()
    for size in [17, 100, 5000]:
        for repeat in [-1, 0, size // 2, size - 1]:
            var t = String("{")
            for i in range(size):
                if i > 0:
                    t += ","
                var name = repeat if i == size - 1 and repeat >= 0 else i
                t += '"key' + String(name) + '":{"key' + String(i) + '":[' + String(i) + "]}"
            t += "}"
            _ = _same_everywhere(doc, t.as_bytes())
    for depth in [1, 10, 63, 64, 65, 200]:
        var t = String("")
        for _ in range(depth):
            t += '{"a":['
        t += "1"
        for _ in range(depth):
            t += "]}"
        _ = _same_everywhere(doc, t.as_bytes(), Limits(max_depth=128))


def test_stop() raises:
    """A handler that returns False ends the scan at once: no more calls,
    False returned, the document empty and ready for the next scan."""
    var doc = Document()
    var text = '{"a":[1,"x",{"b":null}],"c":true}'.as_bytes()
    var full = Recorder()
    assert_true(doc.scan(text, full))
    for k in range(full.calls):
        var r = Recorder(stop_after=k)
        assert_false(doc.scan(text, r))
        assert_equal(r.calls, k + 1)
        assert_equal(doc.nodes(), 0)
    var again = Recorder()
    assert_true(doc.scan(text, again))
    assert_true(again.out == full.out)


def test_limits() raises:
    """The size and depth limits, as `parse` applies them."""
    var doc = Document()
    var text = "[[[1]]]".as_bytes()
    var r = Recorder()
    var kinds = List[Int]()
    for limits in [Limits(max_depth=2), Limits(max_size=3)]:
        try:
            _ = doc.scan(text, r, limits)
            kinds.append(-1)
        except e:
            kinds.append(e.kind)
    assert_equal(kinds[0], JsonError.LIMIT)
    assert_equal(kinds[1], JsonError.LIMIT)
    assert_true(doc.scan(text, r, Limits(max_depth=3)))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
