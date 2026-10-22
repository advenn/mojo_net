"""EpollDriver specifics (epoll-only)."""

from std.sys import size_of
from std.testing import TestSuite, assert_equal, assert_true

from linux import OwnedFd, RawFd, check
from linux import sys
from linux.abi import Rlimit
from linux.consts import AF_INET, F_GETFD, RLIMIT_NOFILE, SO_TYPE, SOCK_CLOEXEC, SOCK_DGRAM, SOL_SOCKET
from linux.probe import get_rlimit, set_rlimit
from rt.event_loop import EventLoop


def test_fd_table_pregrow_never_clobbers_an_open_fd() raises:
    # Regression: the pre-grow used dup3(ep, limit-1), which silently closed
    # an application fd sitting at that number. With a 1024 soft limit the
    # pre-grow target is 1023, so park a datagram socket exactly there.
    var old = get_rlimit(RLIMIT_NOFILE)
    set_rlimit(RLIMIT_NOFILE, Rlimit(1024, old.max))
    var sock = OwnedFd(unsafe_from_raw=Int32(check("socket", sys.socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0))))
    var parked = Int32(1023)
    _ = check("dup3", sys.dup3(sock, parked, SOCK_CLOEXEC))
    var still_open = False
    var ty: Int32 = 0
    try:
        var ev = EventLoop()
        _ = ev.loop.pending_ops()
        # Still open, and still our datagram socket.
        still_open = sys.fcntl(RawFd(parked), F_GETFD) >= 0
        var tl = UInt32(size_of[Int32]())
        _ = check("getsockopt", sys.getsockopt(RawFd(parked), SOL_SOCKET, SO_TYPE, ty, tl))
    finally:
        _ = sys.close(parked)
        set_rlimit(RLIMIT_NOFILE, old)
    assert_true(still_open)
    assert_equal(Int(ty), SOCK_DGRAM)
    _ = sock^


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
