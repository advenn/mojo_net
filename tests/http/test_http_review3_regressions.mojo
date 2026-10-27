"""Regression tests for the third http review (HR3, 2026-10-27; docs/http.md,
"Review"): the sans-I/O parts, no sockets.

- PAR-1: `SseParser` searched a line still arriving from its first byte on
  every feed, so a server sending one long line a byte at a time (1-byte
  chunks) made the client do quadratic work: 256 KiB took about 3.4e10
  byte visits. The search now resumes where it stopped.
- PAR-2: `retry-after-ms` wrapped past Int's nanoseconds
  (`18446744073710` read as 0.45 ms), and a `Retry-After` with leading
  zeros past 10 digits read as "forever" instead of its value.

And guards for the codec's cost work (PERF): every predicate rewritten for
speed is checked against its old definition, kept here as the reference,
exhaustively where the domain is small, else on 50,000 random inputs; the
encoders against the bytes they wrote before.
"""

from std.testing import TestSuite, assert_equal, assert_true
from std.time import perf_counter_ns

from bytes.buffer import ByteBuffer
from http.connection import _is_reg_name_byte, _valid_host
from http.headers import Headers, eq_ignore_case, eq_lower, is_field_byte, is_tchar, is_token, lower_ascii
from http.parse import HeadParser, RequestHead, ResponseHead
from http.retry import retry_after
from http.sse import SseEvent, SseParser
from http.types import Version
from linux.time import Duration


# ---- PAR-1 ---------------------------------------------------------------------


def test_par1_a_line_arriving_a_byte_at_a_time_is_searched_once() raises:
    comptime N = 256 * 1024
    var p = SseParser()
    p.feed("data: ".as_bytes())
    var one = List[UInt8](length=1, fill=UInt8(ord("x")))
    var t0 = perf_counter_ns()
    for _ in range(N):
        p.feed(Span(one))
    p.feed("\n\n".as_bytes())
    var ns = perf_counter_ns() - t0
    var ev = SseEvent()
    assert_true(p.poll(ev))
    assert_equal(ev.data.byte_length(), N)
    # Quadratic, this took tens of seconds; linear, a few milliseconds.
    assert_true(ns < 1_000_000_000, String(ns // 1_000_000, " ms"))


def test_par1_split_line_ends_still_split_lines() raises:
    """The resumed search keeps every way a line can end: LF, CR, and a
    CRLF split across feeds."""
    var p = SseParser()
    var parts: List[String] = ["da", "ta: a", "b\r", "\n\r", "\nda", "ta: c\r", "\r", "data: d", "e", "\n", "\n"]
    for s in parts:
        p.feed(s.as_bytes())
    var ev = SseEvent()
    assert_true(p.poll(ev))
    assert_equal(ev.data, String("ab"))
    assert_true(p.poll(ev))
    assert_equal(ev.data, String("c"))
    assert_true(p.poll(ev))
    assert_equal(ev.data, String("de"))


# ---- PAR-2 ---------------------------------------------------------------------


def _wait(name: StaticString, value: StaticString) raises -> Duration:
    var h = Headers()
    h.add(name, value)
    var got = retry_after(h, 784111777)
    if not got:
        raise Error(String("no delay read from ", value))
    return got.value()


def test_par2_a_huge_retry_after_ms_does_not_wrap() raises:
    var forever = Duration.from_secs(Int(UInt32.MAX))
    assert_equal(_wait("retry-after-ms", "18446744073710"), forever)  # (wrapped to 448 µs)
    assert_equal(_wait("retry-after-ms", "9300000000000"), forever)  # (wrapped below zero: 0)
    assert_equal(_wait("retry-after-ms", "99999999999999999999999.5"), forever)  # (was refused: over 15 bytes)
    assert_equal(_wait("retry-after-ms", "4294967294999.5"), Duration.from_nanos(4294967294999 * 1_000_000 + 500_000))
    assert_equal(_wait("retry-after-ms", "000000000000000001500"), Duration.from_millis(1500))


def test_par2_leading_zeros_in_retry_after_are_not_digits_of_the_value() raises:
    assert_equal(_wait("Retry-After", "00000000005"), Duration.from_secs(5))  # (was 136 years)
    assert_equal(_wait("Retry-After", "0"), Duration.from_secs(0))
    assert_equal(_wait("Retry-After", "0000000000000"), Duration.from_secs(0))
    assert_equal(_wait("Retry-After", "4294967295"), Duration.from_secs(Int(UInt32.MAX)))
    assert_equal(_wait("Retry-After", "99999999999"), Duration.from_secs(Int(UInt32.MAX)))  # (11 digits: "forever")


# ---- PERF: the rewritten predicates against their old definitions -------------


def _old_eq_ignore_case(a: Span[UInt8, _], b: Span[UInt8, _]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        var x = a[i]
        var y = b[i]
        if x != y and lower_ascii(x) != lower_ascii(y):
            return False
    return True


def _old_is_reg_name_byte(c: UInt8) -> Bool:
    if (c >= 48 and c <= 57) or ((c | 0x20) >= 97 and (c | 0x20) <= 122):
        return True
    return (
        c == 45 or c == 46 or c == 95 or c == 126
        or c == 33 or c == 36 or c == 38 or c == 39
        or c == 40 or c == 41 or c == 42 or c == 43
        or c == 44 or c == 59 or c == 61
    )


def _old_is_hex(c: UInt8) -> Bool:
    return (c >= 48 and c <= 57) or ((c | 0x20) >= 97 and (c | 0x20) <= 102)


def _old_valid_host(v: Span[UInt8, _]) -> Bool:
    var n = len(v)
    var i = 0
    if n > 0 and v[0] == 91:
        i = 1
        while i < n and v[i] != 93:
            var c = v[i]
            if not (_old_is_hex(c) or c == 58 or c == 46 or c == 118 or c == 86):
                return False
            i += 1
        if i == n or i == 1:
            return False
        i += 1
    else:
        while i < n and v[i] != 58:
            var c = v[i]
            if c == 37:
                if i + 2 >= n or not _old_is_hex(v[i + 1]) or not _old_is_hex(v[i + 2]):
                    return False
                i += 3
                continue
            if not _old_is_reg_name_byte(c):
                return False
            i += 1
    if i < n:
        if v[i] != 58:
            return False
        for k in range(i + 1, n):
            if v[k] < 48 or v[k] > 57:
                return False
    return True


struct _Rng(Movable):
    var s: UInt64

    def __init__(out self, seed: UInt64):
        self.s = seed

    def next(mut self) -> Int:
        self.s ^= self.s << 13
        self.s ^= self.s >> 7
        self.s ^= self.s << 17
        return Int(self.s >> 1)


def test_perf_eq_ignore_case_is_the_old_one() raises:
    """Every byte pair, then random strings over letters, their neighbours
    around the case bit, and high bytes."""
    var a = List[UInt8](length=1, fill=0)
    var b = List[UInt8](length=1, fill=0)
    for x in range(256):
        for y in range(256):
            a[0] = UInt8(x)
            b[0] = UInt8(y)
            assert_equal(eq_ignore_case(Span(a), Span(b)), _old_eq_ignore_case(Span(a), Span(b)), String(x, " ", y))
    var alphabet: List[UInt8] = [64, 65, 90, 91, 96, 97, 122, 123, 45, 13, 32, 0xC1, 0xE1, 48]
    var rng = _Rng(0x9E3779B97F4A7C15)
    for _ in range(50_000):
        var n = rng.next() % 12
        var s = List[UInt8]()
        var u = List[UInt8]()
        for _ in range(n):
            var c = alphabet[rng.next() % len(alphabet)]
            s.append(c)
            u.append(c ^ 0x20 if rng.next() % 3 == 0 else c)  # (the case bit flipped, letter or not)
        if rng.next() % 4 == 0 and n > 0:
            u[rng.next() % n] = alphabet[rng.next() % len(alphabet)]
        assert_equal(eq_ignore_case(Span(s), Span(u)), _old_eq_ignore_case(Span(s), Span(u)))


def test_perf_eq_lower_is_exact_for_field_bytes() raises:
    """`eq_lower` against `eq_ignore_case` for every field byte against
    every byte a literal may hold (lowercase letters, digits, `-`)."""
    var lits: List[StaticString] = [
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
        "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "-",
    ]
    var one = List[UInt8](length=1, fill=0)
    for x in range(256):
        if not is_field_byte(UInt8(x)):
            continue
        one[0] = UInt8(x)
        for lit in lits:
            assert_equal(eq_lower(Span(one), lit), eq_ignore_case(Span(one), lit.as_bytes()), String(x, " ", lit))
    assert_true(eq_lower("Content-Length".as_bytes(), "content-length"))
    assert_true(not eq_lower("Content-Lengtx".as_bytes(), "content-length"))
    assert_true(not eq_lower("Content-Length ".as_bytes(), "content-length"))


def test_perf_byte_classes_are_the_old_ones() raises:
    for c in range(256):
        var b = UInt8(c)
        assert_equal(_is_reg_name_byte(b), _old_is_reg_name_byte(b), String(c))
        var one: List[UInt8] = [b]
        assert_equal(is_token(Span(one)), is_tchar(b), String(c))


def test_perf_valid_host_is_the_old_one() raises:
    """Every byte at every position of a set of hosts, then random strings
    over the bytes that matter (brackets, colons, percent signs, hex)."""
    var hosts: List[String] = ["a", "ab:80", "localhost:8080", "[::1]:8080", "[v1.x]", "%41b", "h:", ":80", "", "a%4", "[]", "x:1:2"]
    for h in hosts:
        var base = List[UInt8](h.as_bytes())
        assert_equal(_valid_host(Span(base)), _old_valid_host(Span(base)), h)
        for at in range(len(base)):
            for c in range(256):
                var v = base.copy()
                v[at] = UInt8(c)
                assert_equal(_valid_host(Span(v)), _old_valid_host(Span(v)), String(h, " @", at, " = ", c))
    var alphabet: List[UInt8] = [91, 93, 58, 37, 48, 57, 65, 70, 71, 97, 102, 103, 46, 118, 45, 126, 33, 61, 64, 47, 32, 0xFF]
    var rng = _Rng(20261027)
    for _ in range(50_000):
        var n = rng.next() % 14
        var v = List[UInt8]()
        for _ in range(n):
            v.append(alphabet[rng.next() % len(alphabet)])
        assert_equal(_valid_host(Span(v)), _old_valid_host(Span(v)))


def test_perf_heads_encode_as_before() raises:
    """The head encoders now store in one pass: the bytes are those the
    write-by-write versions produced (built here by hand)."""
    var req = RequestHead("PATCH", "/a?b=c", Version.HTTP_1_0)
    req.headers.add("Host", "h")
    req.headers.add("X-Long", "v" * 100)
    var out = ByteBuffer()
    req.encode(out)
    var want = String("PATCH /a?b=c HTTP/1.0\r\nHost: h\r\nX-Long: ", "v" * 100, "\r\n\r\n")
    assert_equal(String(from_utf8_lossy=out.readable_span()), want)
    assert_equal(len(out), req.encoded_len())
    var res = ResponseHead(404, "Nope")
    res.headers.add("A", "1")
    var r = ByteBuffer()
    _ = r.write_bytes("x".as_bytes())  # (after bytes already there)
    res.encode(r)
    assert_equal(String(from_utf8_lossy=r.readable_span()), String("xHTTP/1.1 404 Nope\r\nA: 1\r\n\r\n"))
    var bare = ResponseHead(599)
    var s = ByteBuffer()
    bare.encode(s)
    assert_equal(String(from_utf8_lossy=s.readable_span()), String("HTTP/1.1 599 \r\n\r\n"))


def test_perf_a_reused_head_takes_each_requests_method_and_target() raises:
    """The parser keeps a reused head's method and target when the bytes
    are the same: each change, at the end, in length or to a prefix, must
    still come through."""
    var p = HeadParser.for_requests()
    var head = RequestHead()
    var lines: List[String] = ["GET /a", "GET /b", "GET /ab", "GET /a", "POST /a", "PUT /a", "PUT /a", "GET /"]
    for line in lines:
        var raw = List[UInt8]((line + " HTTP/1.1\r\nHost: h\r\n\r\n").as_bytes())
        var got = p.request(Span(raw), head)
        assert_true(Bool(got))
        var want = line.split(" ")
        assert_equal(head.method, String(want[0]))
        assert_equal(head.target, String(want[1]))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
