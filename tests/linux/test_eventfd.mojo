from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Errno, ErrorKind, OwnedFd, RawFd, check
from linux import sys
from linux.abi import EpollEvent
from linux.consts import (
    EFD_CLOEXEC,
    EPOLLET,
    EPOLLIN,
    EPOLLOUT,
    F_GETFD,
    F_GETFL,
    FD_CLOEXEC,
    O_NONBLOCK,
)
from linux.epoll import Epoll
from linux.eventfd import (
    EVENTFD_MAX,
    EventFd,
    eventfd2,
    eventfd_read,
    eventfd_write,
)
from linux.syscall import err_of, is_err

comptime IN = UInt32(EPOLLIN)
comptime OUT = UInt32(EPOLLOUT)
comptime ET = UInt32(EPOLLET)


# ---- creation and lifecycle -----------------------------------------------


def test_default_is_cloexec_and_nonblocking() raises:
    var e = EventFd.new()
    var fd = check("fcntl", sys.fcntl(e, F_GETFD))
    assert_true((fd & FD_CLOEXEC) != 0)
    var fl = check("fcntl", sys.fcntl(e, F_GETFL))
    assert_true((fl & O_NONBLOCK) != 0)


def test_blocking_mode_is_still_cloexec() raises:
    var e = EventFd.new(nonblocking=False)
    assert_true((check("fcntl", sys.fcntl(e, F_GETFD)) & FD_CLOEXEC) != 0)
    assert_equal(check("fcntl", sys.fcntl(e, F_GETFL)) & O_NONBLOCK, 0)
    # A pending count makes even a blocking read return at once.
    e.signal()
    assert_equal(e.drain(), UInt64(1))


def test_close_and_into_fd() raises:
    var e = EventFd.new()
    var n = e.raw_fd()
    var owned = e^.into_fd()
    assert_equal(owned.raw_fd(), n)
    var e2 = EventFd(owned^)  # adopt it back
    assert_equal(e2.raw_fd(), n)
    e2^.close()
    var r = sys.fcntl(RawFd(n), F_GETFD)
    assert_true(is_err(r) and Errno(err_of(r)) == Errno.EBADF)


def test_raw_initval_and_adopt() raises:
    var r = check("eventfd2", eventfd2(5, EFD_CLOEXEC))
    var e = EventFd(OwnedFd(unsafe_from_raw=Int32(r)))
    # Blocking (no EFD_NONBLOCK) but the counter starts at 5.
    assert_equal(e.drain(), UInt64(5))


# ---- counter semantics ----------------------------------------------------


def test_drain_empty_is_zero() raises:
    var e = EventFd.new()
    assert_equal(e.drain(), UInt64(0))
    assert_equal(e.drain(), UInt64(0))


def test_signals_accumulate_and_drain_resets() raises:
    var e = EventFd.new()
    e.signal()
    e.signal()
    e.signal()
    assert_equal(e.drain(), UInt64(3))
    assert_equal(e.drain(), UInt64(0))
    e.signal()
    assert_equal(e.drain(), UInt64(1))


def test_add_sums_values() raises:
    var e = EventFd.new()
    assert_true(e.add(5))
    assert_true(e.add(7))
    assert_true(e.add(0))  # legal, changes nothing
    assert_equal(e.drain(), UInt64(12))
    assert_true(e.add(0))
    assert_equal(e.drain(), UInt64(0))  # adding 0 does not make it readable


def test_add_all_ones_is_einval() raises:
    var e = EventFd.new()
    var raised = False
    try:
        _ = e.add(0xFFFF_FFFF_FFFF_FFFF)
    except err:
        raised = True
        assert_true(err.errno == Errno.EINVAL)
        assert_true(err.kind == ErrorKind.InvalidInput)
        assert_equal(String(err.op), "eventfd_write")
    assert_true(raised)
    assert_equal(e.drain(), UInt64(0))  # nothing was added


def test_saturation_is_not_an_error_for_signal() raises:
    var e = EventFd.new()
    assert_true(e.add(EVENTFD_MAX - 1))
    assert_true(e.add(1))  # exactly at the maximum
    assert_false(e.add(1))  # would overflow: EAGAIN -> False
    e.signal()  # EAGAIN ignored: a wakeup is already pending
    assert_false(e.add(EVENTFD_MAX))
    assert_equal(e.drain(), EVENTFD_MAX)
    assert_true(e.add(EVENTFD_MAX))  # room again after the drain
    assert_equal(e.drain(), EVENTFD_MAX)
    assert_equal(e.drain(), UInt64(0))


def test_semaphore_mode_takes_one_at_a_time() raises:
    var e = EventFd.new(semaphore=True)
    assert_true(e.add(3))
    assert_equal(e.drain(), UInt64(1))
    assert_equal(e.drain(), UInt64(1))
    e.signal()
    assert_equal(e.drain(), UInt64(1))
    assert_equal(e.drain(), UInt64(1))
    assert_equal(e.drain(), UInt64(0))


def test_raw_wrappers_need_eight_bytes() raises:
    # The kernel rejects short buffers, which is why the wrappers always pass
    # a whole UInt64.
    var e = EventFd.new()
    var four = List[UInt8](length=4, fill=1)
    var w = sys.write(e, Span(four))
    assert_true(is_err(w) and Errno(err_of(w)) == Errno.EINVAL)
    assert_equal(check("eventfd_write", eventfd_write(e, 9)), 8)
    var r = sys.read(e, Span(four))
    assert_true(is_err(r) and Errno(err_of(r)) == Errno.EINVAL)
    var v: UInt64 = 0
    assert_equal(check("eventfd_read", eventfd_read(e, v)), 8)
    assert_equal(v, UInt64(9))
    var again = eventfd_read(e, v)
    assert_true(is_err(again) and Errno(err_of(again)) == Errno.EAGAIN)


# ---- readiness ------------------------------------------------------------


def test_epoll_readiness_follows_counter() raises:
    var ep = Epoll.new()
    var e = EventFd.new()
    ep.add(e, IN | OUT, 77)
    var evs = List[EpollEvent](capacity=4)
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].events(), OUT)  # empty: writable, not readable
    e.signal()
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].events(), IN | OUT)
    assert_true(e.add(EVENTFD_MAX - 1))  # now saturated: not writable
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].events(), IN)
    assert_equal(e.drain(), EVENTFD_MAX)
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].events(), OUT)
    assert_equal(evs[0].data(), UInt64(77))
    sys.keep_alive(e)  # registered fds must outlive the waits


def test_edge_triggered_every_signal_is_an_edge() raises:
    # Why an edge-triggered waker is safe: each write wakes epoll again even
    # while the counter is still non-zero, so no signal() is lost.
    var ep = Epoll.new()
    var e = EventFd.new()
    ep.add(e, IN | ET, 1)
    var evs = List[EpollEvent](capacity=4)
    assert_equal(ep.wait(evs, 0), 0)
    e.signal()
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(ep.wait(evs, 0), 0)  # not drained, no new edge
    e.signal()
    assert_equal(ep.wait(evs, 0), 1)  # new write, new edge
    assert_equal(e.drain(), UInt64(2))
    assert_equal(ep.wait(evs, 0), 0)
    sys.keep_alive(e)  # registered fds must outlive the waits


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
