"""`net.dns`: query layout, name rules, and response parsing (answers, CNAME
chains in any order, NODATA/NXDOMAIN/TC, the RFC 5452 acceptance rules that
ignore forged or unrelated packets, compression-pointer and length attacks),
plus a mutation fuzz run that must never crash."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError
from bytes.codec import escape_bytes
from net.addr import IpAddr
from net.dns import (
    MAX_CNAME_HOPS,
    RCODE_FORMERR,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    RCODE_SERVFAIL,
    TYPE_A,
    TYPE_AAAA,
    TYPE_CNAME,
    DnsAnswer,
    build_query,
    encode_name,
    is_valid_name,
    parse_response,
    read_name,
    tcp_frame,
)
from reader_script import Rng


# ---- a tiny message builder --------------------------------------------------


struct Msg(Movable):
    var b: List[UInt8]

    def __init__(out self, query: List[UInt8], flags: UInt16, ancount: Int):
        """A response header for `query` (same ID) plus its question."""
        self.b = List[UInt8]()
        self.b.append(query[0])
        self.b.append(query[1])
        self.u16(flags)
        self.u16(1)
        self.u16(UInt16(ancount))
        self.u16(0)
        self.u16(0)
        for i in range(12, len(query)):
            self.b.append(query[i])

    def u8(mut self, v: Int):
        self.b.append(UInt8(v))

    def u16(mut self, v: UInt16):
        self.b.append(UInt8(v >> 8))
        self.b.append(UInt8(v & 0xFF))

    def u32(mut self, v: UInt32):
        self.u16(UInt16(v >> 16))
        self.u16(UInt16(v & 0xFFFF))

    def name(mut self, text: StringSlice) raises:
        encode_name(text, self.b)

    def ptr(mut self, at: Int):
        self.u16(UInt16(0xC000 | at))

    def rr_head(mut self, rtype: UInt16, ttl: UInt32, rdlen: Int):
        self.u16(rtype)
        self.u16(1)  # IN
        self.u32(ttl)
        self.u16(UInt16(rdlen))

    def a(mut self, owner: StringSlice, a: Int, b: Int, c: Int, d: Int, ttl: UInt32 = 300) raises:
        self.name(owner)
        self.rr_head(TYPE_A, ttl, 4)
        for v in [a, b, c, d]:
            self.u8(v)

    def cname(mut self, owner: StringSlice, target: StringSlice) raises:
        self.name(owner)
        var t = List[UInt8]()
        encode_name(target, t)
        self.rr_head(TYPE_CNAME, 300, len(t))
        self.b.extend(t^)


comptime OK = UInt16(0x8180)  # QR RD RA, NOERROR


def _q(name: StringSlice, qtype: UInt16 = TYPE_A) raises -> List[UInt8]:
    return build_query(0xBEEF, name, qtype)


def _addrs(ans: DnsAnswer) -> String:
    var out = String()
    for i in range(len(ans.addrs)):
        if i > 0:
            out += ","
        out += String(ans.addrs[i])
    return out


def _parse(m: Msg, q: List[UInt8]) raises -> DnsAnswer:
    var r = parse_response(Span(m.b), Span(q))
    if not r:
        raise Error("rejected a valid response")
    return r.take()


def _kind_of_parse(b: List[UInt8], q: List[UInt8]) -> String:
    """"none", "ok" or the error kind's name."""
    try:
        var r = parse_response(Span(b), Span(q))
        return "ok" if r else "none"
    except e:
        return String(e.kind)


# ---- queries and names -------------------------------------------------------


def test_query_layout() raises:
    var q = build_query(0x1234, "Db.Example.COM.", TYPE_AAAA)
    assert_equal(
        escape_bytes(Span(q)),
        "\\x124\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00"
        + "\\x02db\\x07example\\x03com\\x00\\x00\\x1c\\x00\\x01",
    )
    var e = build_query(1, "a", TYPE_A, edns=True)
    # ARCOUNT 1, then an OPT record: root name, type 41, payload 1232.
    assert_equal(Int(e[11]), 1)
    assert_equal(
        escape_bytes(Span(e)[len(e) - 11 :]),
        "\\x00\\x00)\\x04\\xd0\\x00\\x00\\x00\\x00\\x00\\x00",
    )


def test_name_rules() raises:
    var long_label = String()
    for _ in range(63):
        long_label += "a"
    # 253 characters is the longest name (255 bytes in wire form).
    var longest = String(long_label, ".", long_label, ".", long_label, ".")
    var too_long = longest.copy()
    for _ in range(61):
        longest += "b"
    for _ in range(62):
        too_long += "b"
    assert_equal(longest.byte_length(), 253)
    var ok: List[String] = [
        "a", "a.", "x-y.example", "_sip._tcp.example.com", "123.example",
        long_label, longest, String(longest, "."),
    ]
    for n in ok:
        assert_true(is_valid_name(n), n)
    var bad: List[String] = [
        "", ".", "..", "a..b", ".a", "a b", "a/b", "ä.example", "-a.example",
        "a-.example", "a.b..", String(long_label, "a"), too_long,
    ]
    for n in bad:
        assert_false(is_valid_name(n), n)
    var out = List[UInt8]()
    out.append(7)
    try:
        encode_name("bad..name", out)
    except:
        pass
    assert_equal(len(out), 1)  # unchanged on error


def test_read_name_follows_backward_pointers() raises:
    var m = List[UInt8]()
    for _ in range(12):
        m.append(0)
    encode_name("example.com", m)  # at 12
    var at = len(m)
    m.append(3)
    for c in String("www").as_bytes():
        m.append(c)
    m.append(0xC0)
    m.append(12)
    var name = List[UInt8]()
    var end = read_name(Span(m), at, name)
    assert_equal(end, len(m))
    var want = List[UInt8]()
    encode_name("www.example.com", want)
    assert_equal(escape_bytes(Span(name)), escape_bytes(Span(want)))


# ---- answers -----------------------------------------------------------------


def test_a_and_aaaa_answers() raises:
    var q = _q("db.test")
    var m = Msg(q, OK, 2)
    m.a("db.test", 192, 0, 2, 1, ttl=60)
    m.ptr(12)  # compressed owner name
    m.rr_head(TYPE_A, 30, 4)
    for v in [192, 0, 2, 2]:
        m.u8(v)
    var ans = _parse(m, q)
    assert_equal(ans.rcode, RCODE_NOERROR)
    assert_equal(_addrs(ans), "192.0.2.1,192.0.2.2")
    assert_equal(Int(ans.ttl), 30)

    var q6 = _q("db.test", TYPE_AAAA)
    var m6 = Msg(q6, OK, 1)
    m6.ptr(12)
    m6.rr_head(TYPE_AAAA, 10, 16)
    m6.u16(0x2001)
    m6.u16(0x0DB8)
    for _ in range(5):
        m6.u16(0)
    m6.u16(1)
    assert_equal(_addrs(_parse(m6, q6)), "2001:db8::1")


def test_cname_chain_in_any_order() raises:
    var q = _q("www.test")
    var m = Msg(q, OK, 4)
    m.a("real.test", 198, 51, 100, 7)  # the address comes first
    m.cname("mid.test", "real.test")
    m.a("other.test", 203, 0, 113, 9)  # not on the chain
    m.cname("www.test", "mid.test")
    assert_equal(_addrs(_parse(m, q)), "198.51.100.7")


def test_cname_loops_and_long_chains_are_invalid() raises:
    var q = _q("a.test")
    var m = Msg(q, OK, 2)
    m.cname("a.test", "b.test")
    m.cname("b.test", "a.test")
    assert_equal(_kind_of_parse(m.b, q), "InvalidData")
    var hops = MAX_CNAME_HOPS + 1
    var l = Msg(q, OK, hops)
    l.cname("a.test", "n0.test")
    for i in range(hops - 1):
        l.cname(String("n", i, ".test"), String("n", i + 1, ".test"))
    assert_equal(_kind_of_parse(l.b, q), "InvalidData")


def test_records_for_other_names_types_and_classes_are_skipped() raises:
    var q = _q("db.test")
    var m = Msg(q, OK, 3)
    m.a("elsewhere.test", 10, 0, 0, 1)
    m.name("db.test")  # class CH
    m.u16(TYPE_A)
    m.u16(3)
    m.u32(300)
    m.u16(4)
    for v in [10, 0, 0, 2]:
        m.u8(v)
    m.a("DB.TEST", 10, 0, 0, 3)  # case does not matter
    assert_equal(_addrs(_parse(m, q)), "10.0.0.3")
    # An A record in an AAAA answer is not an IPv6 address.
    var q6 = _q("db.test", TYPE_AAAA)
    var m6 = Msg(q6, OK, 1)
    m6.a("db.test", 10, 0, 0, 4)
    var ans = _parse(m6, q6)
    assert_equal(len(ans.addrs), 0)


def test_rcodes_nodata_and_truncation() raises:
    var q = _q("x.test")
    var nx = Msg(q, OK | UInt16(RCODE_NXDOMAIN), 0)
    assert_equal(_parse(nx, q).rcode, RCODE_NXDOMAIN)
    var sf = Msg(q, OK | UInt16(RCODE_SERVFAIL), 0)
    assert_equal(_parse(sf, q).rcode, RCODE_SERVFAIL)
    var nodata = Msg(q, OK, 0)
    var ans = _parse(nodata, q)
    assert_equal(ans.rcode, RCODE_NOERROR)
    assert_equal(len(ans.addrs), 0)
    var tc = Msg(q, OK | UInt16(0x0200), 0)
    tc.b.append(0xFF)  # whatever follows a TC header is not parsed
    assert_true(_parse(tc, q).truncated)
    # FORMERR without a question section is accepted as FORMERR.
    var fe = List[UInt8]()
    for v in [0xBE, 0xEF, 0x81, 0x81, 0, 0, 0, 0, 0, 0, 0, 0]:
        fe.append(UInt8(v))
    assert_equal(_parse_raw(fe, q).rcode, RCODE_FORMERR)


def _parse_raw(b: List[UInt8], q: List[UInt8]) raises -> DnsAnswer:
    var r = parse_response(Span(b), Span(q))
    if not r:
        raise Error("rejected")
    return r.take()


# ---- what is not an answer ---------------------------------------------------


def test_unrelated_and_forged_packets_are_ignored() raises:
    var q = _q("db.test")
    var good = Msg(q, OK, 1)
    good.a("db.test", 192, 0, 2, 1)
    assert_equal(_kind_of_parse(good.b, q), "ok")

    var wrong_id = good.b.copy()
    wrong_id[1] ^= 1
    var not_response = good.b.copy()
    not_response[2] &= 0x7F  # QR clear
    var other_opcode = good.b.copy()
    other_opcode[2] |= 0x10  # opcode 2
    var other_name = Msg(_q("dc.test"), OK, 0)
    var other_type = Msg(_q("db.test", TYPE_AAAA), OK, 0)
    var two_questions = good.b.copy()
    two_questions[5] = 2
    var short = good.b.copy()
    short.shrink(11)
    assert_equal(_kind_of_parse(wrong_id, q), "none")
    assert_equal(_kind_of_parse(not_response, q), "none")
    assert_equal(_kind_of_parse(other_opcode, q), "none")
    assert_equal(_kind_of_parse(other_name.b, q), "none")
    assert_equal(_kind_of_parse(other_type.b, q), "none")
    assert_equal(_kind_of_parse(two_questions, q), "none")
    assert_equal(_kind_of_parse(short, q), "none")
    # The same question in other letter case is still the question.
    var upper = good.b.copy()
    upper[13] = UInt8(ord("D"))
    assert_equal(_kind_of_parse(upper, q), "ok")


# ---- malformed responses -----------------------------------------------------


def test_pointer_attacks_are_invalid_data() raises:
    var q = _q("db.test")
    var self_ptr = Msg(q, OK, 1)
    var here = len(self_ptr.b)
    self_ptr.ptr(here)  # points at itself
    self_ptr.rr_head(TYPE_A, 1, 4)
    for v in [1, 2, 3, 4]:
        self_ptr.u8(v)
    assert_equal(_kind_of_parse(self_ptr.b, q), "InvalidData")

    var forward = Msg(q, OK, 1)
    forward.ptr(len(forward.b) + 2)
    forward.rr_head(TYPE_A, 1, 4)
    for v in [1, 2, 3, 4]:
        forward.u8(v)
    assert_equal(_kind_of_parse(forward.b, q), "InvalidData")

    var reserved = Msg(q, OK, 1)
    reserved.u8(0x40)  # reserved label type
    assert_equal(_kind_of_parse(reserved.b, q), "InvalidData")

    # A name that grows past 255 bytes through pointers.
    var big = Msg(q, OK, 1)
    var prev = -1
    for _ in range(5):
        var at = len(big.b)
        big.u8(63)
        for _ in range(63):
            big.u8(ord("x"))
        if prev < 0:
            big.u8(0)
        else:
            big.ptr(prev)
        prev = at
    big.ptr(prev)
    big.rr_head(TYPE_A, 1, 4)
    for v in [1, 2, 3, 4]:
        big.u8(v)
    big.b[7] = 1
    assert_equal(_kind_of_parse(big.b, q), "InvalidData")


def test_bad_lengths_are_invalid_data() raises:
    var q = _q("db.test")
    var rd = Msg(q, OK, 1)
    rd.name("db.test")
    rd.rr_head(TYPE_A, 1, 200)  # rdata runs past the end
    rd.u8(1)
    assert_equal(_kind_of_parse(rd.b, q), "InvalidData")
    var a5 = Msg(q, OK, 1)
    a5.name("db.test")
    a5.rr_head(TYPE_A, 1, 5)
    for v in [1, 2, 3, 4, 5]:
        a5.u8(v)
    assert_equal(_kind_of_parse(a5.b, q), "InvalidData")
    var count = Msg(q, OK, 3)  # ANCOUNT says 3, one record follows
    count.a("db.test", 1, 2, 3, 4)
    assert_equal(_kind_of_parse(count.b, q), "InvalidData")


def test_every_truncation_is_handled() raises:
    var q = _q("www.test")
    var m = Msg(q, OK, 2)
    m.cname("www.test", "real.test")
    m.a("real.test", 198, 51, 100, 7)
    for n in range(len(m.b)):
        var cut = m.b.copy()
        cut.shrink(n)
        var k = _kind_of_parse(cut, q)
        if n < 12 + 14:  # header + question: not a response to q
            assert_equal(k, "none")
        else:
            assert_true(k == "InvalidData" or k == "ok", String(n, ": ", k))
    assert_equal(_kind_of_parse(m.b, q), "ok")


def test_mutation_fuzz_never_crashes() raises:
    var q = _q("www.test")
    var m = Msg(q, OK, 3)
    m.cname("www.test", "real.test")
    m.a("real.test", 198, 51, 100, 7)
    m.ptr(12)
    m.rr_head(TYPE_A, 9, 4)
    for v in [1, 2, 3, 4]:
        m.u8(v)
    var rng = Rng(0xD45)
    var seen_ok = 0
    var seen_invalid = 0
    for _ in range(200_000):
        var b = m.b.copy()
        var edits = 1 + rng.below(4)
        for _ in range(edits):
            var what = rng.below(3)
            if what == 0 and len(b) > 0:
                b[rng.below(len(b))] = UInt8(rng.below(256))
            elif what == 1 and len(b) > 1:
                b.shrink(rng.below(len(b)))
            else:
                b.append(UInt8(rng.below(256)))
        var k = _kind_of_parse(b, q)
        if k == "ok":
            seen_ok += 1
        elif k == "InvalidData":
            seen_invalid += 1
        elif k != "none":
            raise Error("unexpected kind ", k)
    assert_true(seen_ok > 0 and seen_invalid > 0)


def test_tcp_frame_prefix() raises:
    var q = _q("a.test")
    var f = tcp_frame(Span(q))
    assert_equal(Int(f[0]) * 256 + Int(f[1]), len(q))
    assert_equal(len(f), len(q) + 2)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
