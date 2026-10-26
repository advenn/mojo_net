"""The `tls.target` module: which server names are accepted, how they are
normalized, and the octets of addresses, checked against Python's
`ipaddress` (TC4, TC5)."""

from std.python import Python
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from tls import Target


def _accepts(name: StringSlice) -> Bool:
    try:
        _ = Target(name)
        return True
    except:
        return False


def _refused(name: StringSlice) raises:
    assert_false(_accepts(name), String("accepted ", repr(String(name))))


def test_names_accepted_and_normalized() raises:
    var cases: List[List[String]] = [
        ["localhost", "localhost"],
        ["LocalHost.", "localhost"],
        ["EXAMPLE.com", "example.com"],
        ["a-b.c_d.test", "a-b.c_d.test"],
        ["xn--bcher-kva.example", "xn--bcher-kva.example"],
        ["1a.example", "1a.example"],
        ["example.123a", "example.123a"],
        ["a.", "a"],
        [String("a") * 63 + ".test", String("a") * 63 + ".test"],
    ]
    for c in cases:
        var t = Target(c[0])
        assert_equal(t.name, c[1])
        assert_false(t.is_ip)
        assert_equal(len(t.ip), 0)
    # 253 bytes in all is the limit (with a trailing dot, 254).
    var long = String("a") * 61
    var n253 = long + "." + long + "." + long + "." + long + "." + String("b") * 5
    assert_equal(n253.byte_length(), 253)
    assert_equal(Target(n253).name, n253)
    assert_equal(Target(n253 + ".").name, n253)


def test_names_refused() raises:
    var bad: List[String] = [
        "", ".", "..", ".a", "a..b", "a..", "a.0x", "a b", "*", "*.example", "a*.example",
        "-", "-a", "a-", "a.-b", "a.b-", "ex ample", "exa\tmple", "a\x00b", "ünicode.test",
        "a/b", "a:b", "a@b", "[::1]", "a%b", "127.1", "0x7f.0.0.1", "010.0.0.1", "1.2.3.4.",
        "1.2.3.256", "example.123", "example.0x1f", "4294967295", "fe80::1%eth0",
        String("a") * 64 + ".test",
    ]
    for b in bad:
        _refused(b)
    var long = String("a") * 61
    _refused(long + "." + long + "." + long + "." + long + "." + String("b") * 6)  # (254)


def test_addresses_match_python() raises:
    var ipaddress = Python.import_module("ipaddress")
    var addrs: List[String] = [
        "127.0.0.1", "0.0.0.0", "255.255.255.255", "10.1.2.3",
        "::1", "::", "2001:db8::1", "fe80::1", "::ffff:192.0.2.1", "2001:DB8:0:0:8:800:200C:417A",
    ]
    for a in addrs:
        var t = Target(a)
        assert_true(t.is_ip, a)
        assert_equal(t.name, a)
        var packed = ipaddress.ip_address(a).packed
        assert_equal(len(t.ip), Int(py=Python.evaluate("len")(packed)))
        for i in range(len(t.ip)):
            assert_equal(Int(t.ip[i]), Int(py=packed[i]))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
