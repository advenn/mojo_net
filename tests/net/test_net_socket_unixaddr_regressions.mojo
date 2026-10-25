"""Regression tests for the second net review (socket options, UnixAddr).

- B2: `set_tos` took any C int, and the kernel kept only its low byte:
  `set_tos(440)` set 184 (EF). Outside 0..255 it now raises `InvalidInput`.
- B5: a pathname starting with `@` printed exactly like an abstract name,
  and one reading `(unnamed)` like an unnamed address. Their first byte is
  now escaped.

B6 (`Ipv6Addr.segment` out of range) is a death test, in
test_net_addr_regressions.mojo.
"""

from std.testing import TestSuite, assert_equal, assert_true

from linux import ErrorKind
from net.addr import UnixAddr
from net.socket import Domain, SockType, Socket


def test_b2_set_tos_refuses_what_the_kernel_would_truncate() raises:
    var s = Socket.new(Domain.IPV4, SockType.DGRAM)
    s.set_tos(0xB8)
    assert_equal(s.tos(), 0xB8)
    s.set_tos(0)
    s.set_tos(255)
    var bad: List[Int] = [256, 440, -1, 2147483647, -2147483648]
    for i in range(len(bad)):
        var refused = False
        try:
            s.set_tos(bad[i])
        except e:
            refused = e.kind == ErrorKind.InvalidInput
        assert_true(refused, String("set_tos(", bad[i], ")"))
        assert_equal(s.tos(), 255, "a refused value changes nothing")


def test_b5_pathnames_never_print_as_abstract_or_unnamed() raises:
    var at_path = UnixAddr.from_pathname("@sock")
    var abstract = UnixAddr.from_abstract_name("sock")
    assert_equal(String(abstract), "@sock")
    assert_equal(String(at_path), "\\x40sock")
    assert_equal(String(UnixAddr.from_pathname("(unnamed)")), "\\x28unnamed)")
    assert_equal(String(UnixAddr.unnamed()), "(unnamed)")
    # Only the first byte: elsewhere `@` and `(` are plain.
    assert_equal(String(UnixAddr.from_pathname("/run/a@b(c)")), "/run/a@b(c)")
    assert_equal(String(UnixAddr.from_abstract_name("@x")), "@@x")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
