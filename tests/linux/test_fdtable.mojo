"""linux.probe.pregrow_fd_table: grows the fd table without touching fds."""

from std.sys import size_of
from std.testing import TestSuite, assert_equal, assert_true

from linux import OwnedFd, RawFd, check
from linux import sys
from linux.abi import Rlimit
from linux.consts import AF_INET, F_GETFD, RLIMIT_NOFILE, SO_TYPE, SOCK_CLOEXEC, SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET
from linux.probe import get_rlimit, pregrow_fd_table, set_rlimit


def _fdsize() raises -> Int:
    """FDSize from /proc/self/status: the current fd table capacity."""
    var text = String(open("/proc/self/status", "r").read())
    for line in text.split("\n"):
        if line.startswith("FDSize:"):
            return Int(String(line[byte=7:].strip()))
    return -1


def _sock(type_: Int) raises -> OwnedFd:
    return OwnedFd(unsafe_from_raw=Int32(check("socket", sys.socket(AF_INET, type_ | SOCK_CLOEXEC, 0))))


def test_grows_the_table() raises:
    var s = _sock(SOCK_STREAM)
    var used = pregrow_fd_table(s, 4096)
    var lim = get_rlimit(RLIMIT_NOFILE).cur
    if lim < 4096:
        print("    (skipped: test_grows_the_table: RLIMIT_NOFILE", lim, "< 4096)")
        return
    assert_true(used >= 4095)
    assert_true(_fdsize() >= 4096)


def test_never_clobbers_an_open_fd() raises:
    # Regression (found in the rt event loop): dup3(fd, limit-1) closed an
    # application fd sitting at that number. With a 1024 soft limit the
    # target is 1023: park a datagram socket exactly there.
    var old = get_rlimit(RLIMIT_NOFILE)
    set_rlimit(RLIMIT_NOFILE, Rlimit(1024, old.max))
    var dgram = _sock(SOCK_DGRAM)
    var parked = Int32(1023)
    _ = check("dup3", sys.dup3(dgram, parked, SOCK_CLOEXEC))
    var still_open = False
    var ty: Int32 = 0
    var used = 0
    try:
        var s = _sock(SOCK_STREAM)
        used = pregrow_fd_table(s)
        still_open = sys.fcntl(RawFd(parked), F_GETFD) >= 0
        var tl = UInt32(size_of[Int32]())
        _ = check("getsockopt", sys.getsockopt(RawFd(parked), SOL_SOCKET, SO_TYPE, ty, tl))
    finally:
        _ = sys.close(parked)
        set_rlimit(RLIMIT_NOFILE, old)
    assert_true(still_open)
    assert_equal(Int(ty), SOCK_DGRAM)
    assert_equal(used, -1)  # 1023 was taken and nothing free above it


def test_small_limit_is_a_noop() raises:
    var s = _sock(SOCK_STREAM)
    assert_equal(pregrow_fd_table(s, 100), -1)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
