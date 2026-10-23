"""`linux.signal`: signal sets, the calling thread's mask, and a signalfd
that receives a blocked signal (sent to this thread with tgkill, so no
other thread of the process can take it) and works in epoll."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Epoll
from linux.abi import EpollEvent
from linux.consts import EPOLLIN, SIGINT, SIGTERM, SIGUSR2
from linux.nr import SYS_getpid, SYS_gettid, SYS_tgkill
from linux.signal import SignalFd, SignalSet, block, blocked, set_mask, unblock
from linux.syscall import syscall0, syscall3
from linux.time import Duration


def test_signal_sets() raises:
    var s = SignalSet.of(SIGINT, SIGTERM)
    assert_true(s.contains(SIGINT))
    assert_true(s.contains(SIGTERM))
    assert_false(s.contains(SIGUSR2))
    assert_false(s.contains(0))
    assert_false(s.contains(65))
    assert_equal(s.bits, UInt64((1 << (SIGINT - 1)) | (1 << (SIGTERM - 1))))
    assert_true(s.with_signal(SIGUSR2).includes(s))
    assert_false(s.includes(s.with_signal(SIGUSR2)))
    assert_true(s.includes(SignalSet.empty()))
    assert_equal(s.with_signal(64).with_signal(99).bits >> 63, UInt64(1))
    assert_equal(String(s), "SignalSet(2,15)")
    assert_true(SignalSet.of(SIGTERM, SIGINT) == s)


def test_the_calling_threads_mask() raises:
    var before = blocked()
    var mask = SignalSet.of(SIGUSR2)
    _ = block(mask)
    assert_true(blocked().contains(SIGUSR2))
    var was = unblock(mask)
    assert_true(was.contains(SIGUSR2))
    assert_false(blocked().contains(SIGUSR2) and not before.contains(SIGUSR2))
    _ = set_mask(before)
    assert_true(blocked() == before)


def test_a_signalfd_receives_a_blocked_signal() raises:
    var before = blocked()
    var mask = SignalSet.of(SIGUSR2)
    _ = block(mask)
    var sfd = SignalFd.new(mask)
    assert_equal(sfd.take(), 0)  # nothing pending
    var ep = Epoll.new()
    ep.add(sfd, UInt32(EPOLLIN), 7)
    var events = List[EpollEvent](capacity=4)
    assert_equal(ep.wait(events, Optional[Duration](Duration.ZERO)), 0)
    # thread-directed: pending for this thread, which blocks it
    _ = syscall3(SYS_tgkill, syscall0(SYS_getpid), syscall0(SYS_gettid), SIGUSR2)
    assert_equal(ep.wait(events, Optional[Duration](Duration.from_secs(5))), 1)
    assert_equal(events[0].data(), 7)
    assert_equal(sfd.take(), SIGUSR2)
    assert_equal(sfd.take(), 0)  # taken once
    _ = set_mask(before)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
