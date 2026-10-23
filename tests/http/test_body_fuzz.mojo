"""Differential fuzzing of chunked decoding (`http.body.BodyDecoder`)
against tests/http/chunked_oracle.py, an independent Python decoder written
from RFC 9112's ABNF. The oracle generates valid chunked bodies (sizes,
extensions, trailers, a pipelined message after them), mutates most of
them and sometimes picks tiny limits; the decoder must give the same
outcome, delivering the same body bytes before it, both with all the input
at once and when the input arrives in random pieces."""

from std.python import Python
from std.testing import TestSuite, assert_equal, assert_true

from http.body import BodyDecoder, BodyKind, BodyLimits, Framing, Piece
from http.headers import Headers
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


def _field(line: String, mut pos: Int) -> String:
    var bar = line.find("|", pos)
    var out = String(line[byte=pos:bar])
    pos = bar + 1
    return out^


def _run(
    request: Bool, limits: BodyLimits, data: Span[UInt8, _], mut rng: _Rng, whole: Bool
) raises -> String:
    """Decode `data` as it arrives (all at once, or in random pieces) and
    describe the outcome as the oracle does."""
    var dec = BodyDecoder(Framing(BodyKind.CHUNKED, 0), lenient=not request, limits=limits)
    var trailers = Headers()
    var body = List[UInt8]()
    var at = 0  # consumed
    var avail = len(data) if whole else 0
    while True:
        if not whole and avail < len(data):
            avail = min(len(data), avail + 1 + rng.below(9))
        while True:
            var pc: Piece
            try:
                pc = dec.decode(data[at:avail], trailers)
            except e:
                return String("err ", dec.error_status(), " ", e.op, " ", _hex(Span(body)))
            body.extend(data[at + pc.start : at + pc.start + pc.len])
            at += pc.consumed
            if dec.is_done():
                var fields = String()
                for i in range(len(trailers)):
                    if i > 0:
                        fields += ";"
                    fields += String(trailers.name(i), "=", _hex(trailers.value_bytes(i)))
                return String("ok ", at, " ", _hex(Span(body)), " ", fields)
            if pc.consumed == 0 and pc.len == 0:
                break  # needs more input
        if avail == len(data):
            return String("more ", _hex(Span(body)))


def test_decoder_matches_the_reference_on_mutated_bodies() raises:
    var sys = Python.import_module("sys")
    _ = sys.path.insert(0, "tests/http")
    var oracle = Python.import_module("chunked_oracle")
    var rng = _Rng(77)
    var oks = 0
    for seed in range(CASES):
        var line = String(oracle.case(seed))
        var pos = 0
        var kind = _field(line, pos)
        var max_line = atol(_field(line, pos))
        var max_trailers = atol(_field(line, pos))
        var max_fields = atol(_field(line, pos))
        var data = _unhex(_field(line, pos))
        var want = String(line[byte=pos:])
        var limits = BodyLimits(
            max_chunk_line=max_line, max_trailers=max_trailers, max_trailer_fields=max_fields
        )
        var request = kind == "R"
        var got = _run(request, limits, Span(data), rng, True)
        var split = _run(request, limits, Span(data), rng, False)
        if got != want or split != want:
            print("case", seed, kind, max_line, max_trailers, max_fields)
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
