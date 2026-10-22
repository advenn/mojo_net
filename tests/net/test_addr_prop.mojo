"""Property tests for net.addr with a seeded PRNG (deterministic).

- Random IPv6 values biased toward zero runs (and IPv4-mapped values):
  format then parse is the identity; the text is canonical per RFC 5952
  (checked against an independent brute-force compressor); the exploded and
  uppercase spellings parse to the same value.
- Random IPv4 and socket addresses: text and kernel-form round trips.
- Random junk around the address alphabet never crashes the parsers, and
  anything accepted formats to text that parses back to the same value.
"""

from std.testing import TestSuite, assert_equal, assert_true

from linux import ErrorKind
from net.addr import (
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    SocketAddr,
    SocketAddrV4,
    SocketAddrV6,
)

comptime N_V6 = 50_000
comptime N_V4 = 5_000
comptime N_JUNK = 50_000


struct Rng(Movable):
    """The splitmix64 generator: tiny, fast, fully determined by the seed."""

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


def rand_v6(mut r: Rng) -> Ipv6Addr:
    """Zero-heavy segments plus forced zero runs, so ties, runs at either end
    and single zeros are all common."""
    var mode = r.below(16)
    if mode == 0:
        return Ipv4Addr.from_bits(
            UInt32(r.next() & 0xFFFFFFFF)
        ).to_ipv6_mapped()
    if mode == 1:
        return Ipv6Addr(hi=r.next(), lo=r.next())
    var seg = Array[UInt16, 8](fill=0)
    for k in range(8):
        var c = r.below(4)
        if c == 2:
            seg[k] = UInt16(r.below(17))  # small, sometimes 0x10
        elif c == 3:
            seg[k] = UInt16(r.next() & 0xFFFF)
    if r.below(2) == 0:
        var start = r.below(8)
        var length = 1 + r.below(8 - start)
        for k in range(start, start + length):
            seg[k] = 0
    if r.below(8) == 0:
        seg[r.below(8)] = 0xFFFF
    return Ipv6Addr.from_segments(seg)


def hex4(v: UInt16, pad: Bool, upper: Bool) -> String:
    var digits = "0123456789ABCDEF" if upper else "0123456789abcdef"
    var out = String()
    var started = False
    for shift in [12, 8, 4, 0]:
        var d = Int((v >> UInt16(shift)) & 0xF)
        if pad or started or d != 0 or shift == 0:
            out += String(digits[byte=d])
            started = True
    return out^


def exploded(a: Ipv6Addr, upper: Bool) -> String:
    var out = String()
    for k in range(8):
        if k > 0:
            out += ":"
        out += hex4(a.segment(k), True, upper)
    return out^


def reference_compressed(a: Ipv6Addr) -> String:
    """Brute force RFC 5952 4.2: over every all-zero span of >= 2 groups,
    compress the longest one, the earliest on ties (4.2.3; note this is not
    always the shortest text: "::6:0:0:6:0:7" beats "0:0:6::6:0:7")."""
    var best_start = -1
    var best_end = -1
    for start in range(8):
        for end in range(start + 2, 9):
            var all_zero = True
            for k in range(start, end):
                if a.segment(k) != 0:
                    all_zero = False
            if all_zero and end - start > best_end - best_start:
                best_start = start
                best_end = end
    var t = String()
    if best_start < 0:
        for k in range(8):
            if k > 0:
                t += ":"
            t += hex4(a.segment(k), False, False)
        return t^
    for k in range(best_start):
        if k > 0:
            t += ":"
        t += hex4(a.segment(k), False, False)
    t += "::"
    for k in range(best_end, 8):
        if k > best_end:
            t += ":"
        t += hex4(a.segment(k), False, False)
    return t^


def test_v6_format_parse_identity() raises:
    var r = Rng(0xC0FFEE)
    var mapped = 0
    var compressed = 0
    for _ in range(N_V6):
        var a = rand_v6(r)
        var s = String(a)
        var b = Ipv6Addr.parse(s)
        assert_equal(b, a, String("round trip of ", s))
        assert_true(s.byte_length() <= 39, s)
        if a.is_ipv4_mapped():
            mapped += 1
            var v4 = a.to_ipv4_mapped().value()
            assert_equal(s, String("::ffff:", v4))
        else:
            assert_equal(s, reference_compressed(a))
        if s.find("::") >= 0:
            compressed += 1
        # Other spellings of the same value.
        assert_equal(Ipv6Addr.parse(exploded(a, False)), a)
        assert_equal(Ipv6Addr.parse(exploded(a, True)), a)
        assert_equal(Ipv6Addr.parse(s.upper()), a)
        # Binary forms.
        assert_equal(Ipv6Addr.from_octets(a.octets()), a)
        assert_equal(Ipv6Addr.from_segments(a.segments()), a)
        assert_equal(Ipv6Addr.from_bits(a.to_bits()), a)
    # The generator really exercised both branches.
    assert_true(mapped > N_V6 // 32, String("mapped=", mapped))
    assert_true(compressed > N_V6 // 2, String("compressed=", compressed))


def test_v4_and_socket_roundtrips() raises:
    var r = Rng(42)
    for _ in range(N_V4):
        var a = Ipv4Addr.from_bits(UInt32(r.next() & 0xFFFFFFFF))
        var s = String(a)
        assert_equal(Ipv4Addr.parse(s), a)
        assert_equal(IpAddr.parse(s), IpAddr(a))
        var port = UInt16(r.next() & 0xFFFF)
        var sa = SocketAddrV4(a, port)
        assert_equal(SocketAddrV4.parse(String(sa)), sa)
        assert_equal(SocketAddrV4.from_raw(sa.to_raw()), sa)
        assert_equal(
            SocketAddr.from_raw(SocketAddr(sa).to_raw()), SocketAddr(sa)
        )

        var b = rand_v6(r)
        var scope = UInt32(r.next() & 0xFFFFFFFF) if r.below(2) == 0 else 0
        var flow = UInt32(r.next() & 0xFFFFF)
        var s6 = SocketAddrV6(b, port, flow, scope)
        var t = String(s6)
        var p = SocketAddrV6.parse(t)
        # flowinfo is not part of the text form.
        assert_equal(p, SocketAddrV6(b, port, 0, scope), t)
        assert_equal(SocketAddr.parse(t), SocketAddr(p))
        assert_equal(SocketAddrV6.from_raw(s6.to_raw()), s6)
        assert_equal(
            SocketAddr.from_raw(SocketAddr(s6).to_raw()), SocketAddr(s6)
        )
        assert_equal(IpAddr.parse(String(b)), IpAddr(b))


def junk(mut r: Rng) -> List[UInt8]:
    """Mutations of valid addresses plus random strings over the address
    alphabet (and a few arbitrary bytes)."""
    comptime alphabet = "0123456789abcdefABCDEF:.[]%x "
    var out = List[UInt8]()
    var mode = r.below(3)
    if mode == 0:
        var n = r.below(48)
        for _ in range(n):
            if r.below(32) == 0:
                out.append(UInt8(r.below(256)))
            else:
                out.append(alphabet.as_bytes()[r.below(alphabet.byte_length())])
        return out^
    var base: String
    if mode == 1:
        base = String(rand_v6(r))
        if r.below(2) == 0:
            base = String("[", base, "]:", r.below(70000))
    else:
        base = String(Ipv4Addr.from_bits(UInt32(r.next() & 0xFFFFFFFF)))
        if r.below(2) == 0:
            base = String(base, ":", r.below(70000))
    for c in base.as_bytes():
        out.append(c)
    var edits = 1 + r.below(3)
    for _ in range(edits):
        var op = r.below(3)
        var pos = r.below(len(out) + 1)
        var c = alphabet.as_bytes()[r.below(alphabet.byte_length())]
        if op == 0:
            out.insert(pos, c)
        elif op == 1 and pos < len(out):
            _ = out.pop(pos)
        elif pos < len(out):
            out[pos] = c
    return out^


def test_junk_never_crashes_and_accepts_only_round_trippable() raises:
    var r = Rng(7)
    var accepted = 0
    for _ in range(N_JUNK):
        var b = junk(r)
        var sp = Span(b)
        var ip: Optional[IpAddr] = None
        try:
            ip = IpAddr.parse_ascii(sp)
        except e:
            assert_true(e.kind == ErrorKind.InvalidInput)
        if ip:
            accepted += 1
            assert_equal(IpAddr.parse(String(ip.value())), ip.value())
        var sa: Optional[SocketAddr] = None
        try:
            sa = SocketAddr.parse_ascii(sp)
        except e:
            assert_true(e.kind == ErrorKind.InvalidInput)
        if sa:
            accepted += 1
            assert_equal(SocketAddr.parse(String(sa.value())), sa.value())
    # Mutations keep a fair share valid, so both paths ran.
    assert_true(accepted > N_JUNK // 20, String("accepted=", accepted))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
