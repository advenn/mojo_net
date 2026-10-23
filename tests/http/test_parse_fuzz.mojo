"""Differential fuzzing of `http.parse.HeadParser` against
tests/http/head_oracle.py, an independent Python implementation of the same
rules written from RFC 9112's ABNF. The oracle generates valid request and
response heads, mutates most of them (special bytes, deletions,
duplications, truncation, case flips) and sometimes picks tiny limits; the
parser must give the same outcome, error rule and status included, both
when it sees all the input at once and when it gets growing prefixes cut
at random points."""

from std.python import Python
from std.testing import TestSuite, assert_equal, assert_true

from http.parse import HeadParser, Limits, RequestHead, ResponseHead
from linux import IoError

comptime CASES = 20000


struct _Rng(Movable):
    var s: UInt64

    def __init__(out self, seed: UInt64):
        self.s = seed

    def next(mut self) -> UInt64:
        self.s += 0x9E3779B97F4A7C15
        var z = self.s
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB
        return z ^ (z >> 31)

    def below(mut self, n: Int) -> Int:
        return Int(self.next() % UInt64(n))


def _nibble(c: UInt8) -> UInt8:
    if c >= 97:
        return c - 87
    return c - 48


def _unhex(s: StringSlice) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b) - 1, 2):
        out.append(_nibble(b[i]) * 16 + _nibble(b[i + 1]))
    return out^


def _hex(s: Span[UInt8, _]) -> String:
    comptime digits = "0123456789abcdef"
    var out = String()
    for b in s:
        out += digits[byte = Int(b >> 4)]
        out += digits[byte = Int(b & 15)]
    return out^


def _canon_request(n: Int, head: RequestHead) raises IoError -> String:
    var s = String("ok ", n, " ", head.method, "|", head.target, "|")
    s += String(head.version.major, ".", head.version.minor, " ")
    for i in range(len(head.headers)):
        if i > 0:
            s += ";"
        s += String(head.headers.name(i), "=", _hex(head.headers.value_bytes(i)))
    return s^


def _canon_response(n: Int, head: ResponseHead) raises IoError -> String:
    var s = String("ok ", n, " ", head.version.major, ".", head.version.minor, "|")
    s += String(head.status, "|", _hex(head.reason.as_bytes()), " ")
    for i in range(len(head.headers)):
        if i > 0:
            s += ";"
        s += String(head.headers.name(i), "=", _hex(head.headers.value_bytes(i)))
    return s^


def _step(
    request: Bool, mut p: HeadParser, data: Span[UInt8, _]
) raises -> Optional[String]:
    """One parse call: None for "more", else the canonical outcome."""
    try:
        if request:
            var head = RequestHead()
            var n = p.request(data, head)
            if n:
                return _canon_request(n.value(), head)
        else:
            var head = ResponseHead()
            var n = p.response(data, head)
            if n:
                return _canon_response(n.value(), head)
        return None
    except e:
        return String("err ", p.error_status(), " ", e.op)


def _whole(request: Bool, limits: Limits, data: Span[UInt8, _]) raises -> String:
    var p = HeadParser(lenient=not request, limits=limits)
    var r = _step(request, p, data)
    return r.value() if r else String("more")


def _split(
    request: Bool, limits: Limits, data: Span[UInt8, _], mut rng: _Rng
) raises -> String:
    var p = HeadParser(lenient=not request, limits=limits)
    var k = 0
    while True:
        k = min(len(data), k + 1 + rng.below(8))
        var r = _step(request, p, data[0:k])
        if r:
            return r.value()
        if k == len(data):
            return "more"


def _field(line: String, mut pos: Int) -> String:
    """The next "|"-separated field of `line` from `pos`."""
    var bar = line.find("|", pos)
    var out = String(line[byte=pos:bar])
    pos = bar + 1
    return out^


def test_parser_matches_the_reference_on_mutated_heads() raises:
    var sys = Python.import_module("sys")
    _ = sys.path.insert(0, "tests/http")
    var oracle = Python.import_module("head_oracle")
    var rng = _Rng(2026)
    var oks = 0
    for seed in range(CASES):
        var line = String(oracle.case(seed))
        var pos = 0
        var kind = _field(line, pos)
        var max_head = atol(_field(line, pos))
        var max_start = atol(_field(line, pos))
        var max_fields = atol(_field(line, pos))
        var data = _unhex(_field(line, pos))
        var want = String(line[byte=pos:])
        var limits = Limits(max_head=max_head, max_start_line=max_start, max_fields=max_fields)
        var request = kind == "R"
        var got = _whole(request, limits, Span(data))
        var split = _split(request, limits, Span(data), rng)
        if got != want or split != want:
            print("case", seed, kind, max_head, max_start, max_fields)
            print("  input   ", _hex(Span(data)))
            print("  expected", want)
            print("  whole   ", got)
            print("  split   ", split)
        assert_equal(got, want, String("case ", seed))
        assert_equal(split, want, String("case ", seed, " split"))
        if want.startswith("ok"):
            oks += 1
    assert_true(oks > CASES // 4)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
