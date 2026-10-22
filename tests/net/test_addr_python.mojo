"""Differential tests of net.addr against CPython's `ipaddress` (and
`socket.if_nameindex`) through Mojo's Python interop.

Each test sends one newline-joined batch to Python and compares line by line,
so tens of thousands of cases cost a few interop calls. The embedded
interpreter is the pixi env's CPython; no MOJO_PYTHON_LIBRARY is needed there.

Known, handled differences:
- CPython < 3.13 prints IPv4-mapped addresses as `::ffff:102:304`; RFC 5952
  section 5 (and we) use `::ffff:1.2.3.4`. The oracle formats mapped
  addresses explicitly and, on >= 3.13, asserts CPython agrees.
- CPython >= 3.13 answers `is_loopback` etc. for IPv4-mapped addresses with
  the IPv4 answer, and so does our `IpAddr`; `Ipv6Addr`'s predicates follow
  Rust (`::ffff:127.0.0.1` is not IPv6 loopback). Mapped addresses are
  compared through their IPv4 address.
- `is_private` differs by design (CPython includes many special ranges), so
  only "RFC 1918 implies CPython private" is checked.
- CPython accepts `%scope` in IPv6Address; zones are excluded here (they
  belong to SocketAddrV6 and are tested in test_addr.mojo).
"""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_true

from net.addr import IpAddr, Ipv4Addr, Ipv6Addr, if_nametoindex

comptime N_FMT = 30_000
comptime N_PARSE = 40_000
comptime N_PRED = 20_000

comptime ORACLE = """
import ipaddress, socket, sys

MAPPED_DOTTED = sys.version_info >= (3, 13)

def canon6(a):
    m = a.ipv4_mapped
    if m is None:
        return str(a)
    s = "::ffff:" + str(m)
    if MAPPED_DOTTED and str(a) != s:
        raise AssertionError("CPython changed mapped formatting: " + str(a))
    return s

def v6(line):
    hi, lo = line.split(",")
    return ipaddress.IPv6Address((int(hi, 16) << 64) | int(lo, 16))

def fmt6(blob):
    return "\\n".join(canon6(v6(l)) for l in blob.split("\\n"))

def parse_any(blob):
    out = []
    for s in blob.split("\\n"):
        try:
            a = ipaddress.ip_address(s)
        except ValueError:
            out.append("ERR")
            continue
        out.append("4 " + str(a) if a.version == 4 else "6 " + canon6(a))
    return "\\n".join(out)

def flags(a):
    return "".join("1" if x else "0" for x in (
        a.is_loopback, a.is_multicast, a.is_unspecified, a.is_link_local,
        a.is_private))

def preds6(blob):
    out = []
    for l in blob.split("\\n"):
        a = v6(l)
        out.append(flags(a.ipv4_mapped) if a.ipv4_mapped else flags(a))
    return "\\n".join(out)

def preds4(blob):
    return "\\n".join(flags(ipaddress.IPv4Address(int(l, 16)))
                     for l in blob.split("\\n"))

def ifaces():
    return "\\n".join("%d %s" % (i, n) for i, n in socket.if_nameindex())

def version():
    return sys.version.split()[0]
"""


struct Rng(Movable):
    """The splitmix64 generator: deterministic for a given seed."""

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


def oracle() raises -> PythonObject:
    return Python.evaluate(ORACLE, file=True, name="addr_oracle")


def rand_v6(mut r: Rng) -> Ipv6Addr:
    var mode = r.below(12)
    if mode == 0:
        return Ipv4Addr.from_bits(
            UInt32(r.next() & 0xFFFFFFFF)
        ).to_ipv6_mapped()
    if mode == 1:
        return Ipv6Addr(hi=r.next(), lo=r.next())
    if mode == 2:
        # Special prefixes the predicates care about.
        var prefixes: List[UInt16] = [
            0xFE80,
            0xFEBF,
            0xFEC0,
            0xFF02,
            0xFC00,
            0x0,
        ]
        var p = prefixes[r.below(len(prefixes))]
        return Ipv6Addr(
            hi=(UInt64(p) << 48) | (r.next() >> 16 if r.below(2) == 0 else 0),
            lo=UInt64(r.below(3)),
        )
    var seg = Array[UInt16, 8](fill=0)
    for k in range(8):
        var c = r.below(4)
        if c == 2:
            seg[k] = UInt16(r.below(17))
        elif c == 3:
            seg[k] = UInt16(r.next() & 0xFFFF)
    if r.below(2) == 0:
        var start = r.below(8)
        var length = 1 + r.below(8 - start)
        for k in range(start, start + length):
            seg[k] = 0
    return Ipv6Addr.from_segments(seg)


def halves(a: Ipv6Addr) -> String:
    var bits = a.to_bits()
    return String(
        hex(UInt64(bits >> 64)), ",", hex(UInt64(bits & 0xFFFFFFFFFFFFFFFF))
    )


def hex_group(v: UInt16, mut r: Rng) -> String:
    """`v` in hex with random case and 0-3 extra leading zeros (max 4)."""
    var digits = "0123456789abcdef" if r.below(2) == 0 else "0123456789ABCDEF"
    var body = String()
    var started = False
    for shift in [12, 8, 4, 0]:
        var d = Int((v >> UInt16(shift)) & 0xF)
        if started or d != 0 or shift == 0:
            body += String(digits[byte=d])
            started = True
    var pad = r.below(5 - body.byte_length())
    return String("0") * pad + body


def spell_v6(a: Ipv6Addr, mut r: Rng) -> String:
    """A random valid RFC 4291 spelling: any zero run (even one group) may be
    `::`, groups may have leading zeros, the tail may be dotted IPv4."""
    var seg = a.segments()
    var groups = 8
    var tail = String()
    if r.below(4) == 0:
        var lo = UInt32(seg[6]) << 16 | UInt32(seg[7])
        tail = String(Ipv4Addr.from_bits(lo))
        groups = 6
    # Pick a random zero run among the leading `groups` groups.
    var zs = -1
    var ze = -1
    if r.below(3) != 0:
        var tries = 0
        while tries < 8:
            tries += 1
            var s = r.below(groups)
            if seg[s] != 0:
                continue
            var e = s + 1
            while e < groups and seg[e] == 0 and r.below(4) != 0:
                e += 1
            zs = s
            ze = e
            break
    var out = String()
    var k = 0
    var need_colon = False
    while k < groups:
        if k == zs:
            out += "::"
            k = ze
            need_colon = False
            continue
        if need_colon:
            out += ":"
        out += hex_group(seg[k], r)
        need_colon = True
        k += 1
    if tail.byte_length() > 0:
        if need_colon:
            out += ":"
        out += tail
    return out^


def mutate(var s: String, mut r: Rng) -> String:
    comptime alphabet = "0123456789abcdefABCDEFg:.:.x "
    var b = List[UInt8]()
    for c in s.as_bytes():
        b.append(c)
    var edits = 1 + r.below(3)
    for _ in range(edits):
        var op = r.below(4)
        var pos = r.below(len(b) + 1)
        var c = alphabet.as_bytes()[r.below(alphabet.byte_length())]
        if op == 0:
            b.insert(pos, c)
        elif op == 1 and pos < len(b):
            _ = b.pop(pos)
        elif op == 2 and pos < len(b):
            b[pos] = c
        elif pos < len(b):
            # Duplicate a byte (":" -> "::", "." -> "..", "1" -> "11").
            b.insert(pos, b[pos])
    return String(StringSlice(unsafe_from_utf8=Span(b)))


def candidate(mut r: Rng) -> String:
    var mode = r.below(6)
    if mode == 0:
        comptime alphabet = "0123456789abcdefABCDEF:::...g "
        var n = r.below(46)
        var b = List[UInt8]()
        for _ in range(n):
            b.append(alphabet.as_bytes()[r.below(alphabet.byte_length())])
        return String(StringSlice(unsafe_from_utf8=Span(b)))
    if mode == 1 or mode == 2:
        return spell_v6(rand_v6(r), r)
    if mode == 3:
        return mutate(spell_v6(rand_v6(r), r), r)
    var v4 = String(Ipv4Addr.from_bits(UInt32(r.next() & 0xFFFFFFFF)))
    if mode == 4:
        return v4^
    return mutate(v4^, r)


def ours_parse(s: String) -> String:
    try:
        var a = IpAddr.parse(s)
        return String("4 " if a.is_ipv4() else "6 ", a)
    except:
        return "ERR"


def flags(
    loopback: Bool,
    multicast: Bool,
    unspecified: Bool,
    link_local: Bool,
    private: Bool,
) -> String:
    var out = String()
    for x in [loopback, multicast, unspecified, link_local, private]:
        out += "1" if x else "0"
    return out^


def v4_flags(a: Ipv4Addr) -> String:
    return flags(
        a.is_loopback(),
        a.is_multicast(),
        a.is_unspecified(),
        a.is_link_local(),
        a.is_private(),
    )


def v6_flags(a: Ipv6Addr) -> String:
    # Unique-local (fc00::/7) is CPython-private; ours has no is_private.
    return flags(
        a.is_loopback(),
        a.is_multicast(),
        a.is_unspecified(),
        a.is_unicast_link_local(),
        a.is_unique_local(),
    )


def compare_flags(ours: String, theirs: StringSlice) -> Bool:
    """Exact match on the first four flags; for the last, ours implies
    CPython's (RFC 1918 / fc00::/7 are inside CPython's private set)."""
    for k in range(4):
        if ours.as_bytes()[k] != theirs.as_bytes()[k]:
            return False
    return not (ours.as_bytes()[4] == 0x31 and theirs.as_bytes()[4] == 0x30)


def test_python_version_and_mapped_formatting() raises:
    var py = oracle()
    var ver = String(py=py.version())
    print("CPython", ver)
    # Both sides agree on the RFC 5952 section 5 form whatever the version.
    var a = Ipv6Addr.parse("::ffff:1.2.3.4")
    assert_equal(String(py=py.fmt6(halves(a))), "::ffff:1.2.3.4")
    assert_equal(String(a), "::ffff:1.2.3.4")


def test_format_matches_cpython() raises:
    var r = Rng(0x5EED)
    var addrs = List[Ipv6Addr](capacity=N_FMT)
    var blob = String()
    for i in range(N_FMT):
        var a = rand_v6(r)
        addrs.append(a)
        if i > 0:
            blob += "\n"
        blob += halves(a)
    var theirs = String(py=oracle().fmt6(blob))
    var lines = theirs.split("\n")
    assert_equal(len(lines), N_FMT)
    var mismatches = 0
    for i in range(N_FMT):
        var ours = String(addrs[i])
        if ours != String(lines[i]):
            mismatches += 1
            if mismatches <= 10:
                print(
                    "format mismatch:",
                    halves(addrs[i]),
                    "ours",
                    ours,
                    "cpython",
                    lines[i],
                )
    assert_equal(mismatches, 0)


def test_parse_matches_cpython() raises:
    var r = Rng(0xD1FF)
    var cands = List[String](capacity=N_PARSE)
    var blob = String()
    for i in range(N_PARSE):
        var c = candidate(r)
        if i > 0:
            blob += "\n"
        blob += c
        cands.append(c^)
    var theirs = String(py=oracle().parse_any(blob))
    var lines = theirs.split("\n")
    assert_equal(len(lines), N_PARSE)
    var mismatches = 0
    var accepted4 = 0
    var accepted6 = 0
    for i in range(N_PARSE):
        var ours = ours_parse(cands[i])
        if ours.startswith("4"):
            accepted4 += 1
        elif ours.startswith("6"):
            accepted6 += 1
        if ours != String(lines[i]):
            mismatches += 1
            if mismatches <= 10:
                print(
                    "parse mismatch: '",
                    cands[i],
                    "' ours ",
                    ours,
                    " cpython ",
                    lines[i],
                    sep="",
                )
    assert_equal(mismatches, 0)
    # Both outcomes are well represented, so the comparison has teeth.
    var rejected = N_PARSE - accepted4 - accepted6
    print("accepted v4", accepted4, "v6", accepted6, "rejected", rejected)
    assert_true(accepted4 > N_PARSE // 20)
    assert_true(accepted6 > N_PARSE // 5)
    assert_true(rejected > N_PARSE // 5)


def test_predicates_match_cpython() raises:
    var r = Rng(0xF1A6)
    var blob6 = String()
    var blob4 = String()
    var a6 = List[Ipv6Addr](capacity=N_PRED)
    var a4 = List[Ipv4Addr](capacity=N_PRED)
    for i in range(N_PRED):
        var a = rand_v6(r)
        a6.append(a)
        # IPv4 biased toward the special /8s and /16s.
        var bits = UInt32(r.next() & 0xFFFFFFFF)
        var tops: List[UInt32] = [0, 10, 127, 169, 172, 192, 224, 239, 255]
        if r.below(2) == 0:
            bits = (tops[r.below(len(tops))] << 24) | (bits & 0xFFFFFF)
            if r.below(3) == 0:
                var seconds: List[UInt32] = [254, 16, 31, 32, 168, 255, 0]
                bits = (bits & 0xFF00FFFF) | (
                    seconds[r.below(len(seconds))] << 16
                )
        if r.below(16) == 0:
            bits = 0xFFFFFFFF if r.below(2) == 0 else 0
        var v4 = Ipv4Addr.from_bits(bits)
        a4.append(v4)
        if i > 0:
            blob6 += "\n"
            blob4 += "\n"
        blob6 += halves(a)
        blob4 += hex(bits)
    var py = oracle()
    var t6 = String(py=py.preds6(blob6)).split("\n")
    var t4 = String(py=py.preds4(blob4)).split("\n")
    assert_equal(len(t6), N_PRED)
    assert_equal(len(t4), N_PRED)
    var mismatches = 0
    for i in range(N_PRED):
        var m = a6[i].to_ipv4_mapped()
        var ours6 = v4_flags(m.value()) if m else v6_flags(a6[i])
        if not compare_flags(ours6, t6[i]):
            mismatches += 1
            if mismatches <= 10:
                print("v6 predicate mismatch:", a6[i], ours6, t6[i])
        var ours4 = v4_flags(a4[i])
        if not compare_flags(ours4, t4[i]):
            mismatches += 1
            if mismatches <= 10:
                print("v4 predicate mismatch:", a4[i], ours4, t4[i])
    assert_equal(mismatches, 0)


def test_if_nametoindex_matches_cpython() raises:
    var lines = String(py=oracle().ifaces()).split("\n")
    assert_true(len(lines) >= 1)
    var saw_lo = False
    for line in lines:
        var parts = line.split(" ")
        var idx = UInt32(Int(String(parts[0])))
        var name = String(parts[1])
        assert_equal(if_nametoindex(name), idx, name)
        if name == "lo":
            saw_lo = True
    assert_true(saw_lo)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
