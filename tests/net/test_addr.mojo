"""Unit tests for net.addr: text vectors, predicates, kernel-form encoding and
decoding, and kernel round trips over loopback / Unix sockets."""

from std.os import getenv, remove
from std.sys import size_of
from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_true,
)

from linux import Errno, ErrorKind, IoError, OwnedFd, check
from linux import sys
from linux.abi import SockaddrIn6
from linux.consts import (
    AF_INET,
    AF_INET6,
    AF_UNIX,
    IPPROTO_IPV6,
    IPV6_V6ONLY,
    SOCK_CLOEXEC,
    SOCK_DGRAM,
    SOCK_STREAM,
)
from linux.nr import SYS_getpid
from linux.syscall import err_of, is_err, syscall0
from net.addr import (
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    RawSockaddr,
    SocketAddr,
    SocketAddrV4,
    SocketAddrV6,
    UnixAddr,
    if_nametoindex,
)


# ---- helpers ---------------------------------------------------------------


def _v4_rejects(s: StringSlice) -> Bool:
    try:
        _ = Ipv4Addr.parse(s)
    except e:
        return e.kind == ErrorKind.InvalidInput
    return False


def _v6_rejects(s: StringSlice) -> Bool:
    try:
        _ = Ipv6Addr.parse(s)
    except e:
        return e.kind == ErrorKind.InvalidInput
    return False


def _sa_rejects(s: StringSlice, resolve: Bool = False) -> Bool:
    try:
        _ = SocketAddr.parse(s, resolve_zone=resolve)
    except e:
        return e.kind == ErrorKind.InvalidInput
    return False


def _kind_of_sa_error(s: StringSlice) -> ErrorKind:
    try:
        _ = SocketAddr.parse(s, resolve_zone=True)
    except e:
        return e.kind
    return ErrorKind.Other


def _decode_rejects(raw: RawSockaddr) -> Bool:
    try:
        _ = SocketAddr.from_raw(raw)
    except e:
        return e.kind == ErrorKind.InvalidInput
    return False


def _unix_decode_rejects(raw: RawSockaddr) -> Bool:
    try:
        _ = UnixAddr.from_raw(raw)
    except e:
        return e.kind == ErrorKind.InvalidInput
    return False


def _byte(raw: RawSockaddr, off: Int) -> Int:
    return Int(
        Pointer(to=raw.storage).unsafe_bitcast[UInt8]().unsafe_offset(off)[]
    )


def _sock(family: Int, type_: Int) raises IoError -> OwnedFd:
    var r = check("socket", sys.socket(family, type_ | SOCK_CLOEXEC, 0))
    return OwnedFd(unsafe_from_raw=Int32(r))


def _sockname(fd: OwnedFd) raises IoError -> RawSockaddr:
    var raw = RawSockaddr()
    _ = check("getsockname", sys.getsockname(fd, raw.storage, raw.len))
    return raw^


# ---- IPv4 text ---------------------------------------------------------------


def test_v4_valid_vectors() raises:
    var cases: List[StaticString] = [
        "0.0.0.0",
        "255.255.255.255",
        "127.0.0.1",
        "1.2.3.4",
        "10.0.0.255",
        "192.168.100.200",
        "9.99.199.249",
    ]
    for s in cases:
        var a = Ipv4Addr.parse(s)
        assert_equal(String(a), String(s))
    assert_equal(Ipv4Addr.parse("1.2.3.4").bits(), 0x01020304)
    assert_equal(Ipv4Addr.parse("255.255.255.255").bits(), 0xFFFFFFFF)


def test_v4_invalid_vectors() raises:
    var cases: List[StaticString] = [
        "",
        "1",
        "127.1",
        "1.2.3",
        "1.2.3.4.5",
        "1.2.3.4.",
        ".1.2.3.4",
        "1..2.3",
        "1.2..3.4",
        "256.0.0.0",
        "1.2.3.256",
        "999.1.1.1",
        "1000.1.1.1",
        "01.2.3.4",
        "1.2.3.04",
        "00.0.0.0",
        "0.0.0.00",
        "001.2.3.4",
        "+1.2.3.4",
        "-1.2.3.4",
        " 1.2.3.4",
        "1.2.3.4 ",
        "1.2.3.4\n",
        "1.2. 3.4",
        "0x1.2.3.4",
        "0x7f.0.0.1",
        "1.2.3.a",
        "1.2.3.4:80",
        "1.2.3.4/24",
        "١.2.3.4",
        "1.2.3.4\x00",
        "::1",
        "1.2.3.-0",
        "4294967295",
        "1.2.3.0000",
    ]
    for s in cases:
        assert_true(_v4_rejects(s), String("accepted invalid IPv4: '", s, "'"))
    assert_false(_v4_rejects("1.2.3.4"))  # the helper itself works


def test_v4_parse_ascii_raw_bytes() raises:
    var ok: List[UInt8] = [0x31, 0x2E, 0x32, 0x2E, 0x33, 0x2E, 0x34]
    assert_equal(Ipv4Addr.parse_ascii(Span(ok)), Ipv4Addr(1, 2, 3, 4))
    var bad: List[UInt8] = [0x31, 0x2E, 0x32, 0x2E, 0x33, 0x2E, 0xB4]
    var raised = False
    try:
        _ = Ipv4Addr.parse_ascii(Span(bad))
    except e:
        raised = e.kind == ErrorKind.InvalidInput
        assert_equal(String(e.op), "Ipv4Addr.parse")
    assert_true(raised)


def test_v4_constructors_and_octets() raises:
    var a = Ipv4Addr(192, 168, 1, 77)
    assert_equal(a.bits(), 0xC0A8014D)
    assert_equal(a.to_bits(), a.bits())
    assert_equal(Ipv4Addr.from_bits(0xC0A8014D), a)
    var o = a.octets()
    assert_equal(o[0], 192)
    assert_equal(o[3], 77)
    assert_equal(Ipv4Addr.from_octets(o), a)
    assert_equal(String(Ipv4Addr.LOCALHOST), "127.0.0.1")
    assert_equal(String(Ipv4Addr.UNSPECIFIED), "0.0.0.0")
    assert_equal(String(Ipv4Addr.BROADCAST), "255.255.255.255")
    assert_equal(repr(a), "Ipv4Addr(192.168.1.77)")
    assert_true(Ipv4Addr(1, 2, 3, 4) < Ipv4Addr(1, 2, 3, 5))
    assert_true(Ipv4Addr(1, 2, 3, 4) <= Ipv4Addr(1, 2, 3, 4))
    assert_true(Ipv4Addr(2, 0, 0, 0) > Ipv4Addr(1, 255, 255, 255))
    assert_true(Ipv4Addr(1, 2, 3, 4) != Ipv4Addr(4, 3, 2, 1))
    assert_equal(
        hash(Ipv4Addr(1, 2, 3, 4)), hash(Ipv4Addr.from_bits(0x01020304))
    )


def test_v4_predicates() raises:
    assert_true(Ipv4Addr.LOCALHOST.is_loopback())
    assert_true(Ipv4Addr(127, 255, 255, 255).is_loopback())
    assert_false(Ipv4Addr(128, 0, 0, 1).is_loopback())
    assert_true(Ipv4Addr.UNSPECIFIED.is_unspecified())
    assert_false(Ipv4Addr(0, 0, 0, 1).is_unspecified())
    assert_true(Ipv4Addr(10, 1, 2, 3).is_private())
    assert_true(Ipv4Addr(172, 16, 0, 0).is_private())
    assert_true(Ipv4Addr(172, 31, 255, 255).is_private())
    assert_false(Ipv4Addr(172, 32, 0, 0).is_private())
    assert_false(Ipv4Addr(172, 15, 255, 255).is_private())
    assert_true(Ipv4Addr(192, 168, 0, 1).is_private())
    assert_false(Ipv4Addr(192, 169, 0, 1).is_private())
    assert_false(Ipv4Addr(11, 0, 0, 1).is_private())
    assert_true(Ipv4Addr(169, 254, 10, 1).is_link_local())
    assert_false(Ipv4Addr(169, 255, 0, 1).is_link_local())
    assert_true(Ipv4Addr(224, 0, 0, 1).is_multicast())
    assert_true(Ipv4Addr(239, 255, 255, 255).is_multicast())
    assert_false(Ipv4Addr(240, 0, 0, 0).is_multicast())
    assert_false(Ipv4Addr(223, 255, 255, 255).is_multicast())
    assert_true(Ipv4Addr.BROADCAST.is_broadcast())
    assert_false(Ipv4Addr(255, 255, 255, 254).is_broadcast())
    assert_true(Ipv4Addr(192, 0, 2, 1).is_documentation())
    assert_true(Ipv4Addr(198, 51, 100, 1).is_documentation())
    assert_true(Ipv4Addr(203, 0, 113, 255).is_documentation())
    assert_false(Ipv4Addr(203, 0, 114, 0).is_documentation())


# ---- IPv6 text ---------------------------------------------------------------


def test_v6_rfc5952_examples() raises:
    # (input, canonical): RFC 5952 sections 2, 4 and 5.
    # Flattened (input, canonical) pairs.
    var cases: List[StaticString] = [
        # Section 2.1-2.3: equivalent spellings of one address.
        "2001:db8:0:0:1:0:0:1",
        "2001:db8::1:0:0:1",
        "2001:0db8:0:0:1:0:0:1",
        "2001:db8::1:0:0:1",
        "2001:db8::1:0:0:1",
        "2001:db8::1:0:0:1",
        "2001:db8::0:1:0:0:1",
        "2001:db8::1:0:0:1",
        "2001:0db8::1:0:0:1",
        "2001:db8::1:0:0:1",
        "2001:db8:0:0:1::1",
        "2001:db8::1:0:0:1",
        "2001:db8:0000:0:1::1",
        "2001:db8::1:0:0:1",
        "2001:DB8:0:0:1::1",
        "2001:db8::1:0:0:1",
        "2001:db8:aaaa:bbbb:cccc:dddd:eeee:0001",
        "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1",
        "2001:db8:aaaa:bbbb:cccc:dddd:eeee:001",
        "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1",
        "2001:db8:aaaa:bbbb:cccc:dddd:eeee:01",
        "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1",
        "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1",
        "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1",
        "2001:db8:aaaa:bbbb:cccc:dddd::1",
        "2001:db8:aaaa:bbbb:cccc:dddd:0:1",
        "2001:db8:aaaa:bbbb:cccc:dddd:0:1",
        "2001:db8:aaaa:bbbb:cccc:dddd:0:1",
        "2001:db8:0:0:0::1",
        "2001:db8::1",
        "2001:db8:0:0::1",
        "2001:db8::1",
        "2001:db8:0::1",
        "2001:db8::1",
        "2001:db8::1",
        "2001:db8::1",
        "2001:db8::aaaa:0:0:1",
        "2001:db8::aaaa:0:0:1",
        "2001:db8:0:0:aaaa::1",
        "2001:db8::aaaa:0:0:1",
        "2001:db8::AAAA",
        "2001:db8::aaaa",
        "2001:db8::aAaA",
        "2001:db8::aaaa",
        # 4.1 leading zeros; 4.2.1 shorten maximally.
        "2001:0db8::0001",
        "2001:db8::1",
        "2001:db8:0:0:0:0:2:1",
        "2001:db8::2:1",
        # 4.2.2 never compress a single 16-bit 0 field.
        "2001:db8:0:1:1:1:1:1",
        "2001:db8:0:1:1:1:1:1",
        "2001:db8::1:1:1:1:1",
        "2001:db8:0:1:1:1:1:1",
        # 4.2.3 longest run wins; first one on ties.
        "2001:0:0:1:0:0:0:1",
        "2001:0:0:1::1",
        "2001:db8:0:0:1:0:0:1",
        "2001:db8::1:0:0:1",
        "1:0:0:2:0:0:3:4",
        "1::2:0:0:3:4",
        "0:0:1:0:0:1:0:0",
        "::1:0:0:1:0:0",
        "1:0:1:0:1:0:1:0",
        "1:0:1:0:1:0:1:0",
        # 5: IPv4-mapped in mixed notation.
        "::ffff:192.0.2.1",
        "::ffff:192.0.2.1",
        "0:0:0:0:0:ffff:c000:0201",
        "::ffff:192.0.2.1",
        "::FFFF:c000:201",
        "::ffff:192.0.2.1",
        "::ffff:0:0",
        "::ffff:0.0.0.0",
        "::ffff:ffff:ffff",
        "::ffff:255.255.255.255",
        # IPv4-compatible and other embeddings are plain hex.
        "::192.0.2.1",
        "::c000:201",
        "::ffff:0:192.0.2.1",
        "::ffff:0:c000:201",
        "64:ff9b::192.0.2.33",
        "64:ff9b::c000:221",
        # Edges.
        "::",
        "::",
        "::1",
        "::1",
        "1::",
        "1::",
        "0:0:0:0:0:0:0:0",
        "::",
        "0000:0000:0000:0000:0000:0000:0000:0000",
        "::",
        "0:0:0:0:0:0:0:1",
        "::1",
        "1:0:0:0:0:0:0:0",
        "1::",
        "1:2:3:4:5:6:7::",
        "1:2:3:4:5:6:7:0",
        "::2:3:4:5:6:7:8",
        "0:2:3:4:5:6:7:8",
        "1:2:3:4:5:6:7:8",
        "1:2:3:4:5:6:7:8",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "1:2:3:4:5:6:1.2.3.4",
        "1:2:3:4:5:6:102:304",
        "1:2:3:4:5::1.2.3.4",
        "1:2:3:4:5:0:102:304",
        "::0.0.0.0",
        "::",
        "::0.0.0.1",
        "::1",
        "fe80::1",
        "fe80::1",
        "ff02::1:ff00:1",
        "ff02::1:ff00:1",
    ]
    for k in range(0, len(cases), 2):
        var a = Ipv6Addr.parse(cases[k])
        assert_equal(
            String(a), String(cases[k + 1]), String("input ", cases[k])
        )
        # The canonical form parses back to the same value.
        assert_equal(Ipv6Addr.parse(cases[k + 1]), a)


def test_v6_invalid_vectors() raises:
    var cases: List[StaticString] = [
        "",
        ":",
        ":::",
        "::::",
        ":::1",
        "1:::",
        "1:::2",
        "1::2::3",
        "::1::",
        "12345::",
        "::12345",
        "00000::",
        "1:2:3:4:5:6:7:8:9",
        "1:2:3:4:5:6:7",
        "1:2:3:4:5:6:7:8::",
        "::1:2:3:4:5:6:7:8",
        "1::2:3:4:5:6:7:8",
        "1:2:3:4:5:6:7::8",
        ":1::",
        ":1:2:3:4:5:6:7:8",
        "1:2:3:4:5:6:7:8:",
        "1::2:",
        "1:",
        ":1",
        "::ffff:1.2.3",
        "::ffff:1.2.3.4.5",
        "::ffff:1.2.3.256",
        "::ffff:01.2.3.4",
        "::ffff:1.2.3.04",
        "::1.2.3.4:5",
        "::1.2.3.4::",
        "1.2.3.4",
        "1.2.3.4::",
        "1.2.3.4:1::",
        "1:2:3:4:5:6:7:1.2.3.4",
        "1:2:3:4:5:6::1.2.3.4",
        "::12345.1.1.1",
        "::a.2.3.4",
        "::.1.2.3",
        "::1.2.3.",
        "g::",
        "::g",
        "::0x1",
        "0x1::",
        "::-1",
        "::+1",
        " ::1",
        "::1 ",
        "::1\n",
        ":: 1",
        "[::1]",
        "fe80::1%3",
        "fe80::1%eth0",
        "::1/128",
        "1:2:3:4:5:6:7:8%1",
        "::ffff:1.2.3.4%1",
        "１::",
        "::\x00",
        "fffff::1",
        "1:2:3:4:5:6:7:8:1.2.3.4",
        "::1.2.3.4.5",
        ":::1.2.3.4",
        "1::2::1.2.3.4",
        "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255:",
        "0000:0000:0000:0000:0000:0000:0000:0000:0000",
    ]
    for s in cases:
        assert_true(_v6_rejects(s), String("accepted invalid IPv6: '", s, "'"))
    assert_false(_v6_rejects("1::"))  # the helper itself works


def test_v6_longest_valid_text() raises:
    # 45 bytes: the longest valid textual form (and the parser's cap).
    var s = "0000:0000:0000:0000:0000:ffff:255.255.255.255"
    assert_equal(s.byte_length(), 45)
    assert_equal(String(Ipv6Addr.parse(s)), "::ffff:255.255.255.255")
    assert_true(_v6_rejects("0000:0000:0000:0000:0000:ffff:255.255.255.2555"))
    assert_true(_v6_rejects("00000:0000:0000:0000:0000:ffff:255.255.255.255"))


def test_v6_accessors() raises:
    var a = Ipv6Addr(0x2001, 0xDB8, 0, 0, 0x8, 0x800, 0x200C, 0x417A)
    var seg = a.segments()
    assert_equal(seg[0], 0x2001)
    assert_equal(seg[7], 0x417A)
    assert_equal(a.segment(4), 0x8)
    assert_equal(Ipv6Addr.from_segments(seg), a)
    var o = a.octets()
    assert_equal(o[0], 0x20)
    assert_equal(o[1], 0x01)
    assert_equal(o[2], 0x0D)
    assert_equal(o[3], 0xB8)
    assert_equal(o[15], 0x7A)
    assert_equal(Ipv6Addr.from_octets(o), a)
    var bits = a.to_bits()
    assert_equal(Ipv6Addr.from_bits(bits), a)
    assert_true((bits >> 112) == 0x2001)
    assert_equal(String(a), "2001:db8::8:800:200c:417a")
    assert_equal(repr(a), "Ipv6Addr(2001:db8::8:800:200c:417a)")
    assert_true(Ipv6Addr.parse("::1") < Ipv6Addr.parse("::2"))
    assert_true(Ipv6Addr.parse("::ffff") < Ipv6Addr.parse("1::"))
    assert_true(Ipv6Addr.parse("1::1") > Ipv6Addr.parse("1::"))
    assert_equal(
        hash(Ipv6Addr.parse("fe80::1")),
        hash(Ipv6Addr(0xFE80, 0, 0, 0, 0, 0, 0, 1)),
    )


def test_v6_predicates_and_mapping() raises:
    assert_true(Ipv6Addr.LOCALHOST.is_loopback())
    assert_true(Ipv6Addr.UNSPECIFIED.is_unspecified())
    assert_false(Ipv6Addr.LOCALHOST.is_unspecified())
    assert_false(Ipv6Addr.parse("::2").is_loopback())
    assert_false(Ipv6Addr.parse("::ffff:127.0.0.1").is_loopback())
    assert_true(Ipv6Addr.parse("ff02::1").is_multicast())
    assert_true(Ipv6Addr.parse("ff00::").is_multicast())
    assert_false(Ipv6Addr.parse("fe00::").is_multicast())
    assert_true(Ipv6Addr.parse("fe80::1").is_unicast_link_local())
    assert_true(Ipv6Addr.parse("febf:ffff::").is_unicast_link_local())
    assert_false(Ipv6Addr.parse("fec0::").is_unicast_link_local())
    assert_false(Ipv6Addr.parse("fe7f::").is_unicast_link_local())
    assert_true(Ipv6Addr.parse("fc00::1").is_unique_local())
    assert_true(Ipv6Addr.parse("fdff::1").is_unique_local())
    assert_false(Ipv6Addr.parse("fe00::1").is_unique_local())
    assert_true(Ipv6Addr.parse("2001:db8::1").is_documentation())
    assert_false(Ipv6Addr.parse("2001:db9::1").is_documentation())

    var m = Ipv6Addr.parse("::ffff:10.1.2.3")
    assert_true(m.is_ipv4_mapped())
    var v4 = m.to_ipv4_mapped()
    assert_true(Bool(v4))
    assert_equal(v4.value(), Ipv4Addr(10, 1, 2, 3))
    assert_equal(Ipv4Addr(10, 1, 2, 3).to_ipv6_mapped(), m)
    assert_equal(Ipv6Addr.from_ipv4_mapped(Ipv4Addr(10, 1, 2, 3)), m)
    assert_false(Bool(Ipv6Addr.parse("::10.1.2.3").to_ipv4_mapped()))
    assert_false(Bool(Ipv6Addr.parse("1::ffff:10.1.2.3").to_ipv4_mapped()))
    assert_false(Ipv6Addr.parse("::fffe:10.1.2.3").is_ipv4_mapped())


# ---- IpAddr ------------------------------------------------------------------


def test_ipaddr() raises:
    var a = IpAddr.parse("10.0.0.1")
    assert_true(a.is_ipv4())
    assert_equal(a.v4(), Ipv4Addr(10, 0, 0, 1))
    assert_equal(String(a), "10.0.0.1")
    var b = IpAddr.parse("::ffff:10.0.0.1")
    assert_true(b.is_ipv6())
    assert_equal(String(b), "::ffff:10.0.0.1")
    # Rust semantics: v4 != its mapped form; to_canonical folds it.
    assert_true(a != b)
    assert_equal(b.to_canonical(), a)
    assert_true(b.to_canonical().is_ipv4())
    assert_equal(a.to_canonical(), a)
    assert_equal(IpAddr.parse("::1").to_canonical(), IpAddr(Ipv6Addr.LOCALHOST))
    assert_equal(a.v6(), b.v6())
    var c: IpAddr = Ipv4Addr.LOCALHOST
    assert_true(c.is_loopback())
    var d: IpAddr = Ipv6Addr.LOCALHOST
    assert_true(d.is_loopback())
    assert_true(IpAddr.parse("0.0.0.0").is_unspecified())
    assert_true(IpAddr.parse("::").is_unspecified())
    assert_true(IpAddr.parse("224.1.1.1").is_multicast())
    assert_true(IpAddr.parse("ff0e::1").is_multicast())
    # IpAddr predicates classify IPv4-mapped addresses by their IPv4
    # address (review F23); Ipv6Addr's stay strict (see test_ipv6 above).
    assert_true(IpAddr.parse("::ffff:127.0.0.1").is_loopback())
    assert_true(hash(a) != hash(b))
    assert_equal(repr(a), "IpAddr(10.0.0.1)")
    var bad: List[StaticString] = [
        "",
        "1.2.3",
        "1.2.3.4:80",
        "::1%1",
        "[::1]",
        "x",
    ]
    for s in bad:
        var raised = False
        try:
            _ = IpAddr.parse(s)
        except e:
            raised = e.kind == ErrorKind.InvalidInput
        assert_true(raised, String("accepted ", s))


# ---- socket addresses --------------------------------------------------------


def test_socketaddr_valid_roundtrip() raises:
    var cases: List[StaticString] = [
        "0.0.0.0:0",
        "127.0.0.1:80",
        "255.255.255.255:65535",
        "[::]:0",
        "[::1]:443",
        "[fe80::1%3]:80",
        "[::ffff:1.2.3.4]:8080",
        "[2001:db8::1%4294967295]:65535",
        "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535",
    ]
    for s in cases:
        var a = SocketAddr.parse(s)
        assert_equal(String(a), String(s))
        assert_equal(SocketAddr.parse(String(a)), a)
    var v6 = SocketAddr.parse("[fe80::1%3]:80")
    assert_true(v6.is_ipv6())
    assert_equal(v6.v6().scope_id(), 3)
    assert_equal(v6.port(), 80)
    assert_equal(v6.family(), AF_INET6)
    # Zone 0 means "none" and is not printed; long hex forms canonicalize.
    assert_equal(String(SocketAddr.parse("[fe80::1%0]:1")), "[fe80::1]:1")
    assert_equal(String(SocketAddr.parse("[FE80:0:0::0001]:1")), "[fe80::1]:1")
    var v4 = SocketAddr.parse("10.1.2.3:9")
    assert_true(v4.is_ipv4())
    assert_equal(v4.family(), AF_INET)
    assert_equal(v4.v4(), SocketAddrV4(Ipv4Addr(10, 1, 2, 3), 9))
    assert_equal(SocketAddrV4.parse("10.1.2.3:9"), v4.v4())
    assert_equal(
        SocketAddrV6.parse("[::1]:7"), SocketAddrV6(Ipv6Addr.LOCALHOST, 7)
    )
    # The longest text form fits the formatter's buffer.
    var longest = SocketAddrV6(
        Ipv6Addr(
            0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFE
        ),
        65535,
        0,
        4294967295,
    )
    assert_equal(
        String(longest),
        "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe%4294967295]:65535",
    )


def test_socketaddr_invalid_vectors() raises:
    var cases: List[StaticString] = [
        "",
        ":",
        ":80",
        "1.2.3.4",
        "1.2.3.4:",
        "1.2.3.4:65536",
        "1.2.3.4:99999",
        "1.2.3.4:4294967376",
        "1.2.3.4:080",
        "1.2.3.4:00",
        "1.2.3.4:-1",
        "1.2.3.4:+80",
        "1.2.3.4: 80",
        "1.2.3.4:80 ",
        "1.2.3.4:0x50",
        "1.2.3.4:80:80",
        "1.2.3.4%3:80",
        "127.1:80",
        "::1:80",
        "[::1]",
        "[::1]:",
        "[::1]80",
        "[::1]:65536",
        "[::1]:080",
        "[::1]:80:80",
        "[1.2.3.4]:80",
        "[]:80",
        "[::1%]:80",
        "[::1%x]:80",
        "[::1%-1]:80",
        "[::1%+1]:80",
        "[::1%01]:80",
        "[::1%4294967296]:80",
        "[::1%3%4]:80",
        "[[::1]]:80",
        "[::1]]:80",
        "[::1:80",
        "::1]:80",
        " [::1]:80",
        "[ ::1]:80",
        "[::1 ]:80",
        "[::1%lo]:80",
        "[fe80::1%eth0]:80",
    ]
    for s in cases:
        assert_true(
            _sa_rejects(s), String("accepted invalid SocketAddr: '", s, "'")
        )
    assert_false(_sa_rejects("[::1]:1"))  # the helper itself works
    assert_false(_sa_rejects("1.2.3.4:1"))
    # Family-specific parsers reject the other family.
    var v4_ok = True
    try:
        _ = SocketAddrV4.parse("[::1]:80")
    except e:
        v4_ok = e.kind != ErrorKind.InvalidInput
    assert_false(v4_ok, "SocketAddrV4 accepted [::1]:80")
    var v6_ok = True
    try:
        _ = SocketAddrV6.parse("1.2.3.4:80")
    except e:
        v6_ok = e.kind != ErrorKind.InvalidInput
    assert_false(v6_ok, "SocketAddrV6 accepted 1.2.3.4:80")


def test_socketaddr_accessors() raises:
    var a = SocketAddr(IpAddr(Ipv4Addr(1, 2, 3, 4)), 5)
    assert_equal(String(a), "1.2.3.4:5")
    assert_equal(a.ip(), IpAddr(Ipv4Addr(1, 2, 3, 4)))
    a.set_port(6)
    assert_equal(a.port(), 6)
    var b = SocketAddr(SocketAddrV6(Ipv6Addr.parse("fe80::1"), 8, 0x12345, 9))
    assert_equal(b.v6().flowinfo(), 0x12345)
    # Switching family drops flowinfo and scope id.
    b.set_ip(IpAddr(Ipv4Addr.LOCALHOST))
    assert_true(b.is_ipv4())
    assert_equal(String(b), "127.0.0.1:8")
    b.set_ip(IpAddr(Ipv6Addr.LOCALHOST))
    assert_equal(b.v6().scope_id(), 0)
    assert_equal(b.v6().flowinfo(), 0)
    assert_equal(String(b), "[::1]:8")
    # Same family keeps them.
    var c = SocketAddrV6(Ipv6Addr.parse("fe80::1"), 8, 7, 9)
    var cs = SocketAddr(c)
    cs.set_ip(IpAddr(Ipv6Addr.parse("fe80::2")))
    assert_equal(cs.v6().scope_id(), 9)
    assert_equal(cs.v6().flowinfo(), 7)
    var v6 = SocketAddrV6(Ipv6Addr.LOCALHOST, 1)
    v6.set_flowinfo(3)
    v6.set_scope_id(4)
    v6.set_port(2)
    v6.set_ip(Ipv6Addr.UNSPECIFIED)
    assert_equal(String(v6), "[::%4]:2")
    assert_equal(repr(v6), "SocketAddrV6([::%4]:2, flowinfo=3)")
    var v4 = SocketAddrV4(Ipv4Addr.LOCALHOST, 1)
    v4.set_ip(Ipv4Addr.BROADCAST)
    v4.set_port(65535)
    assert_equal(repr(v4), "SocketAddrV4(255.255.255.255:65535)")
    # v4 vs v6-mapped socket addresses differ.
    assert_true(
        SocketAddr.parse("1.2.3.4:5") != SocketAddr.parse("[::ffff:1.2.3.4]:5")
    )
    assert_equal(
        SocketAddr.parse("[::ffff:1.2.3.4]:5").ip().to_canonical(),
        IpAddr(Ipv4Addr(1, 2, 3, 4)),
    )


# ---- kernel form -------------------------------------------------------------


def test_raw_v4_bytes() raises:
    var raw = SocketAddr.parse("1.2.3.4:258").to_raw()
    assert_equal(raw.socklen(), 16)
    assert_equal(raw.family(), AF_INET)
    assert_equal(_byte(raw, 2), 0x01)  # port, network order
    assert_equal(_byte(raw, 3), 0x02)
    assert_equal(_byte(raw, 4), 1)
    assert_equal(_byte(raw, 7), 4)
    for i in range(8, 16):
        assert_equal(_byte(raw, i), 0)
    assert_equal(SocketAddr.from_raw(raw), SocketAddr.parse("1.2.3.4:258"))
    assert_equal(SocketAddrV4.from_raw(raw), SocketAddrV4.parse("1.2.3.4:258"))


def test_raw_v6_bytes() raises:
    var a = SocketAddrV6(
        Ipv6Addr.parse("2001:db8::ff"), 0xABCD, 0x12345, 0x01020304
    )
    var raw = a.to_raw()
    assert_equal(raw.socklen(), 28)
    assert_equal(raw.family(), AF_INET6)
    assert_equal(_byte(raw, 2), 0xAB)
    assert_equal(_byte(raw, 3), 0xCD)
    # flowinfo is network order.
    assert_equal(_byte(raw, 4), 0x00)
    assert_equal(_byte(raw, 5), 0x01)
    assert_equal(_byte(raw, 6), 0x23)
    assert_equal(_byte(raw, 7), 0x45)
    assert_equal(_byte(raw, 8), 0x20)
    assert_equal(_byte(raw, 9), 0x01)
    assert_equal(_byte(raw, 23), 0xFF)
    # scope_id is host order.
    var sin6 = Pointer(to=raw.storage).unsafe_bitcast[SockaddrIn6]()
    assert_equal(sin6[].scope_id, 0x01020304)
    var back = SocketAddrV6.from_raw(raw)
    assert_equal(back, a)
    assert_equal(back.flowinfo(), 0x12345)
    assert_equal(SocketAddr.from_raw(raw), SocketAddr(a))


def test_raw_decode_rejects_garbage() raises:
    # Fresh buffer: AF_UNSPEC.
    assert_true(_decode_rejects(RawSockaddr()))
    var raw = SocketAddr.parse("1.2.3.4:5").to_raw()
    raw.len = 15
    assert_true(_decode_rejects(raw))
    raw.len = 0
    assert_true(_decode_rejects(raw))
    raw.len = 129
    assert_true(_decode_rejects(raw))
    raw.len = 0xFFFFFFFF
    assert_true(_decode_rejects(raw))
    raw.len = 128  # longer than sockaddr_in but within storage: accepted
    assert_equal(String(SocketAddr.from_raw(raw)), "1.2.3.4:5")
    var raw6 = SocketAddr.parse("[::1]:5").to_raw()
    raw6.len = 27
    assert_true(_decode_rejects(raw6))
    raw6.len = 24  # RFC 2133 sockaddr_in6 without scope id
    assert_true(_decode_rejects(raw6))
    raw6.len = 16
    assert_true(_decode_rejects(raw6))
    var odd = RawSockaddr()
    odd.storage.family = 999
    odd.len = 28
    assert_true(_decode_rejects(odd))
    odd.storage.family = UInt16(AF_UNIX)
    assert_true(_decode_rejects(odd))
    # Family-specific decoders reject the other family.
    var v4raw = SocketAddr.parse("1.2.3.4:5").to_raw()
    var raised = False
    try:
        _ = SocketAddrV6.from_raw(v4raw)
    except e:
        raised = e.kind == ErrorKind.InvalidInput
    assert_true(raised)
    raised = False
    try:
        _ = SocketAddrV4.from_raw(SocketAddr.parse("[::1]:5").to_raw())
    except e:
        raised = e.kind == ErrorKind.InvalidInput
    assert_true(raised)
    assert_true(_unix_decode_rejects(v4raw))


def test_raw_reset_and_parts() raises:
    var raw = SocketAddr.parse("[::1]:5").to_raw()
    raw.reset()
    assert_equal(raw.socklen(), RawSockaddr.capacity())
    assert_equal(raw.family(), 0)
    var raw2 = RawSockaddr(storage=raw.storage.copy(), len=7)
    assert_equal(raw2.socklen(), 7)
    assert_equal(RawSockaddr.capacity(), 128)


# ---- Unix addresses ----------------------------------------------------------


def test_unix_constructors() raises:
    var p = UnixAddr.from_pathname("/run/x.sock")
    assert_true(p.is_pathname())
    assert_equal(len(p.name()), 11)
    assert_equal(String(p), "/run/x.sock")
    assert_equal(p.socklen(), 2 + 11 + 1)
    var a = UnixAddr.from_abstract_name("svc")
    assert_true(a.is_abstract())
    assert_equal(a.socklen(), 2 + 1 + 3)
    assert_equal(String(a), "@svc")
    var u = UnixAddr.unnamed()
    assert_true(u.is_unnamed())
    assert_equal(u.socklen(), 2)
    assert_equal(String(u), "(unnamed)")
    assert_equal(len(u.name()), 0)
    assert_true(p != a)
    assert_true(UnixAddr.from_pathname("svc") != a)
    assert_equal(UnixAddr.from_abstract_name("svc"), a)
    assert_equal(hash(UnixAddr.from_abstract_name("svc")), hash(a))
    assert_true(hash(UnixAddr.from_pathname("svc")) != hash(a))
    # Empty abstract name is distinct from unnamed (socklen 3 vs 2).
    var e = UnixAddr.from_abstract_name("")
    assert_true(e.is_abstract())
    assert_equal(e.socklen(), 3)
    assert_true(e != u)
    # Abstract names may hold NULs and arbitrary bytes; display escapes them.
    var bytes: List[UInt8] = [0x00, 0x41, 0xFF, 0x5C, 0x0A]
    var b = UnixAddr.from_abstract_name(Span(bytes))
    assert_equal(len(b.name()), 5)
    assert_equal(String(b), "@\\x00A\\xff\\x5c\\x0a")
    assert_equal(repr(a), "UnixAddr(@svc)")
    var c = a.copy()
    assert_equal(c, a)


def test_unix_limits() raises:
    var ok = String("/") + String("a") * 106
    assert_equal(ok.byte_length(), 107)
    var p = UnixAddr.from_pathname(ok)
    assert_equal(p.socklen(), 110)
    var too_long = ok + "b"
    var raised = False
    try:
        _ = UnixAddr.from_pathname(too_long)
    except e:
        raised = e.kind == ErrorKind.InvalidInput
    assert_true(raised, "108-byte pathname accepted")
    raised = False
    try:
        _ = UnixAddr.from_pathname("")
    except e:
        raised = e.kind == ErrorKind.InvalidInput
    assert_true(raised, "empty pathname accepted")
    raised = False
    try:
        _ = UnixAddr.from_pathname("/tmp/a\x00b")
    except e:
        raised = e.kind == ErrorKind.InvalidInput
    assert_true(raised, "NUL in pathname accepted")
    var abs_ok = String("x") * 107
    assert_equal(UnixAddr.from_abstract_name(abs_ok).socklen(), 110)
    raised = False
    try:
        _ = UnixAddr.from_abstract_name(abs_ok + "x")
    except e:
        raised = e.kind == ErrorKind.InvalidInput
    assert_true(raised, "108-byte abstract name accepted")


def test_unix_raw_encoding() raises:
    var raw = UnixAddr.from_pathname("/a").to_raw()
    assert_equal(raw.family(), AF_UNIX)
    assert_equal(raw.socklen(), 5)
    assert_equal(_byte(raw, 2), 0x2F)
    assert_equal(_byte(raw, 3), 0x61)
    assert_equal(_byte(raw, 4), 0)
    assert_equal(UnixAddr.from_raw(raw), UnixAddr.from_pathname("/a"))
    var araw = UnixAddr.from_abstract_name("ab").to_raw()
    assert_equal(araw.socklen(), 5)
    assert_equal(_byte(araw, 2), 0)
    assert_equal(_byte(araw, 3), 0x61)
    assert_equal(_byte(araw, 4), 0x62)
    assert_equal(UnixAddr.from_raw(araw), UnixAddr.from_abstract_name("ab"))
    var uraw = UnixAddr.unnamed().to_raw()
    assert_equal(uraw.socklen(), 2)
    assert_true(UnixAddr.from_raw(uraw).is_unnamed())
    # A pathname ends at the first NUL even if the length says more.
    raw.len = 20
    assert_equal(UnixAddr.from_raw(raw), UnixAddr.from_pathname("/a"))
    # Without its NUL (length excludes it) the path still decodes.
    raw.len = 4
    assert_equal(UnixAddr.from_raw(raw), UnixAddr.from_pathname("/a"))
    # 108-byte path without NUL (Linux accepts it) decodes; encodes as 110.
    var full = RawSockaddr()
    full.storage.family = UInt16(AF_UNIX)
    var p = Pointer(to=full.storage).unsafe_bitcast[UInt8]()
    for i in range(108):
        p.unsafe_offset(2 + i)[] = 0x7A
    full.len = 110
    var long = UnixAddr.from_raw(full)
    assert_true(long.is_pathname())
    assert_equal(len(long.name()), 108)
    assert_equal(long.socklen(), 110)
    assert_equal(UnixAddr.from_raw(long.to_raw()), long)
    # The kernel reports that path with length 111: it NUL-terminates it
    # past sun_path (review F02). Bytes past sun_path are never read.
    full.len = 111
    assert_equal(UnixAddr.from_raw(full), long)
    # Garbage.
    full.len = 129
    assert_true(_unix_decode_rejects(full))
    full.len = 1
    assert_true(_unix_decode_rejects(full))
    full.len = 0
    assert_true(_unix_decode_rejects(full))
    assert_true(_unix_decode_rejects(RawSockaddr()))
    assert_true(_decode_rejects(uraw))


# ---- kernel round trips ------------------------------------------------------


def _ipv6(test: StaticString, need_loopback: Bool = True) raises -> Bool:
    """Whether this host has IPv6 (with `need_loopback`: a usable [::1]),
    decided with raw syscalls, not with the code under test. Only
    EAFNOSUPPORT from socket(AF_INET6) or EADDRNOTAVAIL from bind([::1]:0)
    mean "no IPv6"; any other failure raises, so a regression is never
    reported as a skip. Without IPv6 this prints a visible skip line (which
    tools/run_tests.sh shows and counts) and the test returns early, unless
    MOJO_TCP_REQUIRE_IPV6=1 turns it into a failure."""
    var why: StaticString
    var r = sys.socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0)
    if is_err(r) and Errno(err_of(r)) == Errno.EAFNOSUPPORT:
        why = "socket(AF_INET6): EAFNOSUPPORT"
    else:
        var fd = OwnedFd(
            unsafe_from_raw=Int32(check("socket(AF_INET6)", r))
        )
        if not need_loopback:
            return True
        var sa = SockaddrIn6(
            UInt16(AF_INET6), 0, 0, Array[UInt8, 16](fill=0), 0
        )
        sa.addr[15] = 1  # [::1]:0
        var b = sys.bind(fd, sa, size_of[SockaddrIn6]())
        if not is_err(b):
            return True
        if Errno(err_of(b)) != Errno.EADDRNOTAVAIL:
            _ = check("bind([::1]:0)", b)
        why = "bind([::1]:0): EADDRNOTAVAIL"
    if getenv("MOJO_TCP_REQUIRE_IPV6") == "1":
        raise Error(test, ": no IPv6 (", why, ") but MOJO_TCP_REQUIRE_IPV6=1")
    print(String("    (skipped: ", test, ": no IPv6, ", why, ")"))
    return False



def test_kernel_roundtrip_v4() raises:
    var fd = _sock(AF_INET, SOCK_STREAM)
    var raw = SocketAddr.parse("127.0.0.1:0").to_raw()
    _ = check("bind", sys.bind(fd, raw.storage, raw.socklen()))
    var got = _sockname(fd)
    assert_equal(got.socklen(), 16)
    var a = SocketAddr.from_raw(got)
    assert_true(a.is_ipv4())
    assert_equal(a.ip(), IpAddr(Ipv4Addr.LOCALHOST))
    assert_true(a.port() != 0)
    # Re-encoding the decoded address yields the kernel's bytes.
    var again = a.to_raw()
    for i in range(16):
        assert_equal(_byte(again, i), _byte(got, i))


def test_kernel_roundtrip_v6() raises:
    if not _ipv6("test_kernel_roundtrip_v6"):
        return
    var fd = _sock(AF_INET6, SOCK_STREAM)
    var raw = SocketAddr.parse("[::1]:0").to_raw()
    _ = check("bind", sys.bind(fd, raw.storage, raw.socklen()))
    var got = _sockname(fd)
    assert_equal(got.socklen(), 28)
    var a = SocketAddr.from_raw(got)
    assert_true(a.is_ipv6())
    assert_equal(a.ip(), IpAddr(Ipv6Addr.LOCALHOST))
    assert_true(a.port() != 0)
    assert_equal(a.v6().scope_id(), 0)
    var again = a.to_raw()
    for i in range(28):
        assert_equal(_byte(again, i), _byte(got, i))


def test_kernel_accept_peer_matches_client() raises:
    # accept4's peer address equals the client's own getsockname, over v4
    # and v6 loopback.
    var addrs: List[StaticString] = ["127.0.0.1:0"]
    if _ipv6("test_kernel_accept_peer_matches_client (v6 half)"):
        addrs.append("[::1]:0")
    for s in addrs:
        var local = SocketAddr.parse(s)
        var lfd = _sock(local.family(), SOCK_STREAM)
        var lraw = local.to_raw()
        _ = check("bind", sys.bind(lfd, lraw.storage, lraw.socklen()))
        _ = check("listen", sys.listen(lfd, 4))
        var bound = SocketAddr.from_raw(_sockname(lfd))
        var cfd = _sock(local.family(), SOCK_STREAM)
        var craw = bound.to_raw()
        _ = check("connect", sys.connect(cfd, craw.storage, craw.socklen()))
        var peer = RawSockaddr()
        var afd = OwnedFd(
            unsafe_from_raw=Int32(
                check(
                    "accept4",
                    sys.accept4(lfd, peer.storage, peer.len, SOCK_CLOEXEC),
                )
            )
        )
        assert_true(afd.is_cloexec())
        var client = SocketAddr.from_raw(_sockname(cfd))
        assert_equal(SocketAddr.from_raw(peer), client)
        var cpeer = RawSockaddr()
        _ = check("getpeername", sys.getpeername(cfd, cpeer.storage, cpeer.len))
        assert_equal(SocketAddr.from_raw(cpeer), bound)


def test_kernel_dual_stack_peer_is_ipv4_mapped() raises:
    # A v4 client of a dual-stack v6 listener shows up as ::ffff:a.b.c.d.
    # It needs AF_INET6 sockets, not a usable [::1].
    if not _ipv6("test_kernel_dual_stack_peer_is_ipv4_mapped", False):
        return
    var lfd = _sock(AF_INET6, SOCK_STREAM)
    var off: Int32 = 0
    _ = check(
        "setsockopt", sys.setsockopt(lfd, IPPROTO_IPV6, IPV6_V6ONLY, off, 4)
    )
    var lraw = SocketAddr.parse("[::]:0").to_raw()
    _ = check("bind", sys.bind(lfd, lraw.storage, lraw.socklen()))
    _ = check("listen", sys.listen(lfd, 4))
    var port = SocketAddr.from_raw(_sockname(lfd)).port()
    var cfd = _sock(AF_INET, SOCK_STREAM)
    var craw = SocketAddr(IpAddr(Ipv4Addr.LOCALHOST), port).to_raw()
    _ = check("connect", sys.connect(cfd, craw.storage, craw.socklen()))
    var peer = RawSockaddr()
    var afd = OwnedFd(
        unsafe_from_raw=Int32(
            check(
                "accept4",
                sys.accept4(lfd, peer.storage, peer.len, SOCK_CLOEXEC),
            )
        )
    )
    assert_true(afd.raw_fd() >= 0)
    var p = SocketAddr.from_raw(peer)
    assert_true(p.is_ipv6())
    assert_true(p.v6().ip().is_ipv4_mapped())
    assert_equal(p.ip().to_canonical(), IpAddr(Ipv4Addr.LOCALHOST))
    var client = SocketAddr.from_raw(_sockname(cfd))
    assert_equal(p.port(), client.port())
    assert_true(String(p).startswith("[::ffff:127.0.0.1]:"))


def test_kernel_unix_abstract_and_unnamed() raises:
    var pid = syscall0(SYS_getpid)
    var name = String("mojo_tcp.test_addr.", pid)
    var fd = _sock(AF_UNIX, SOCK_STREAM)
    var want = UnixAddr.from_abstract_name(name)
    var raw = want.to_raw()
    _ = check("bind", sys.bind(fd, raw.storage, raw.socklen()))
    var got = UnixAddr.from_raw(_sockname(fd))
    assert_equal(got, want)
    assert_equal(String(got), String("@", name))
    # Unbound and socketpair sockets are unnamed.
    var fresh = _sock(AF_UNIX, SOCK_STREAM)
    assert_true(UnixAddr.from_raw(_sockname(fresh)).is_unnamed())
    var fds = Array[Int32, 2](fill=-1)
    _ = check(
        "socketpair",
        sys.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds),
    )
    var a = OwnedFd(unsafe_from_raw=fds[0])
    var b = OwnedFd(unsafe_from_raw=fds[1])
    assert_true(UnixAddr.from_raw(_sockname(a)).is_unnamed())
    assert_true(UnixAddr.from_raw(_sockname(b)).is_unnamed())
    # Binding the unnamed address autobinds: the kernel picks a 5-hex-digit
    # abstract name.
    var auto = _sock(AF_UNIX, SOCK_DGRAM)
    var uraw = UnixAddr.unnamed().to_raw()
    _ = check("bind", sys.bind(auto, uraw.storage, uraw.socklen()))
    var bound = UnixAddr.from_raw(_sockname(auto))
    assert_true(bound.is_abstract())
    assert_equal(len(bound.name()), 5)


def test_kernel_unix_pathname() raises:
    var pid = syscall0(SYS_getpid)
    var paths: List[String] = [
        String("/tmp/mojo_tcp_addr_", pid, ".sock"),
        # Longest allowed: 107 bytes + NUL fills sun_path.
        String("/tmp/mojo_tcp_addr_", pid, "_"),
    ]
    paths[1] = paths[1] + String("L") * (107 - paths[1].byte_length())
    assert_equal(paths[1].byte_length(), 107)
    for path in paths:
        try:
            remove(path)
        except:
            pass
        var fd = _sock(AF_UNIX, SOCK_STREAM)
        var want = UnixAddr.from_pathname(path)
        var raw = want.to_raw()
        _ = check("bind", sys.bind(fd, raw.storage, raw.socklen()))
        var got_raw = _sockname(fd)
        var got = UnixAddr.from_raw(got_raw)
        remove(path)
        assert_equal(got, want)
        assert_equal(String(got), path)
        assert_equal(got_raw.socklen(), want.socklen())


# ---- interface names ---------------------------------------------------------


def test_if_nametoindex() raises:
    var lo = if_nametoindex("lo")
    assert_true(lo > 0)
    var a = SocketAddr.parse("[fe80::1%lo]:80", resolve_zone=True)
    assert_equal(a.v6().scope_id(), lo)
    assert_equal(String(a), String("[fe80::1%", lo, "]:80"))
    assert_equal(
        SocketAddrV6.parse("[fe80::1%lo]:80", resolve_zone=True).scope_id(), lo
    )
    # Numeric zones never hit the kernel, even when resolving.
    assert_equal(
        SocketAddr.parse("[fe80::1%7]:80", resolve_zone=True).v6().scope_id(), 7
    )
    # Unknown interface: NotFound (ENODEV), not InvalidInput.
    var raised = False
    try:
        _ = if_nametoindex("nosuchif9")
    except e:
        raised = e.kind == ErrorKind.NotFound and e.errno == Errno.ENODEV
    assert_true(raised)
    assert_true(
        _kind_of_sa_error("[fe80::1%nosuchif9]:80") == ErrorKind.NotFound
    )
    # Malformed names are rejected before any syscall.
    var bad: List[String] = ["", String("x") * 16, "lo\x00"]
    for name in bad:
        raised = False
        try:
            _ = if_nametoindex(name)
        except e:
            raised = e.kind == ErrorKind.InvalidInput
        assert_true(raised, String("accepted interface name '", name, "'"))
    # Name-like zones that are malformed numbers stay InvalidInput.
    assert_true(_sa_rejects("[fe80::1%01]:80", True))
    assert_true(_sa_rejects("[fe80::1%4294967296]:80", True))
    assert_true(_sa_rejects("[fe80::1%]:80", True))
    assert_true(
        _sa_rejects(String("[fe80::1%", String("x") * 16, "]:80"), True)
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
