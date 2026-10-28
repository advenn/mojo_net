"""`linux.signal`: signal sets, the calling thread's mask, a signalfd
that receives a blocked signal (sent to this thread with tgkill, so no
other thread of the process can take it) and works in epoll, and
`write_no_sigpipe` to a pipe whose reader is gone (SR2 BP-1: the
server's log lines killed a process whose stderr pipe had closed)."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Epoll
from linux.abi import EpollEvent
from linux import sys
from linux.abi import Timespec
from linux.consts import EPOLLIN, O_CLOEXEC, SIGINT, SIGPIPE, SIGTERM, SIGUSR2
from linux.errno import Errno
from linux.error import check
from linux.fd import OwnedFd
from linux.nr import SYS_getpid, SYS_gettid, SYS_rt_sigtimedwait, SYS_tgkill
from linux.signal import SignalFd, SignalSet, block, blocked, set_mask, unblock, write_no_sigpipe
from linux.syscall import syscall0, syscall3, syscall4
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


def _broken_pipe() raises -> OwnedFd:
    """The write end of a pipe whose read end is closed."""
    var fds = Array[Int32, 2](fill=-1)
    _ = check("pipe2", sys.pipe2(fds, O_CLOEXEC))
    _ = OwnedFd(unsafe_from_raw=fds[0])  # (closed at once)
    return OwnedFd(unsafe_from_raw=fds[1])


def _take_sigpipe() -> Int:
    """Consume a SIGPIPE pending for this thread (which must block it): the
    signal, or -EAGAIN if none is."""
    var set = UInt64(1) << UInt64(SIGPIPE - 1)
    var zero = Timespec(0, 0)
    var r = syscall4(SYS_rt_sigtimedwait, Int(Pointer(to=set)), 0, Int(Pointer(to=zero)), 8)
    sys.keep_alive(set)
    sys.keep_alive(zero)
    return r


def test_write_no_sigpipe_to_a_pipe_without_reader() raises:
    var before = blocked()
    var w = _broken_pipe()
    # SIGPIPE unblocked, at its default action: a plain write would end the
    # process here.
    _ = unblock(SignalSet.of(SIGPIPE))
    var r = write_no_sigpipe(w, "log line\n".as_bytes())
    var after = blocked()
    _ = block(SignalSet.of(SIGPIPE))
    var left = _take_sigpipe()  # (none left behind to come later)
    _ = set_mask(before)
    assert_equal(r, -Int(Errno.EPIPE.value))
    assert_false(after.contains(SIGPIPE), "the mask was not restored")
    assert_equal(left, -Int(Errno.EAGAIN.value))
    # a writable pipe is written as by write(2)
    var fds = Array[Int32, 2](fill=-1)
    _ = check("pipe2", sys.pipe2(fds, O_CLOEXEC))
    var rd = OwnedFd(unsafe_from_raw=fds[0])
    var wr = OwnedFd(unsafe_from_raw=fds[1])
    assert_equal(write_no_sigpipe(wr, "abc".as_bytes()), 3)
    var buf = List[UInt8](length=8, fill=0)
    assert_equal(sys.read(rd, Span(buf)), 3)


def test_write_no_sigpipe_leaves_a_blocked_sigpipe_to_its_thread() raises:
    # A thread that blocks SIGPIPE itself gets its SIGPIPE pending, as from
    # write(2): its own to take.
    var before = blocked()
    _ = block(SignalSet.of(SIGPIPE))
    var w = _broken_pipe()
    var r = write_no_sigpipe(w, "x".as_bytes())
    var still = blocked().contains(SIGPIPE)
    var taken = _take_sigpipe()
    _ = set_mask(before)
    assert_equal(r, -Int(Errno.EPIPE.value))
    assert_true(still)
    assert_equal(taken, SIGPIPE)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
