"""`UdpSocket` through the syscall fault seam (built with -D MOJO_NET_FAULTS=1
because of the `_faults.mojo` suffix): EINTR retries in both modes,
spurious EAGAIN makes the blocking calls wait and the `try_*` calls return
None, and nothing is lost or duplicated."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Errno, fault
from linux.nr import SYS_ppoll, SYS_recvfrom, SYS_sendto
from linux.time import Deadline, Duration, Instant
from net.addr import SocketAddr
from net.udp import Datagram, UdpSocket


def _bound() raises -> UdpSocket:
    var s = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
    s.set_deadline(Deadline.after(Duration.from_secs(10)))
    return s^


def _settle():
    var t = Instant.now()
    while t.elapsed() < Duration.from_millis(20):
        pass  # let loopback deliver


def test_eintr_is_retried_in_both_modes() raises:
    fault.clear()
    var a = _bound()
    var b = _bound()
    fault.clear()
    fault.inject(SYS_sendto, Errno.EINTR, times=2)
    assert_equal(a.send_to(String("one").as_bytes(), b.local_addr()), 3)
    assert_equal(fault.calls(SYS_sendto), 3)
    fault.clear()
    fault.inject(SYS_recvfrom, Errno.EINTR, times=2)
    var buf = List[UInt8](length=8, fill=0)
    assert_equal(b.recv_from(Span(buf)).len, 3)
    fault.clear()
    _ = a.send_to(String("two!").as_bytes(), b.local_addr())
    _settle()
    fault.clear()
    fault.inject(SYS_recvfrom, Errno.EINTR, times=1)
    var d = b.try_recv_from(Span(buf))
    fault.clear()
    assert_equal(d.value().len, 4)


def test_spurious_eagain_waits_or_returns_none() raises:
    fault.clear()
    var a = _bound()
    var b = _bound()
    _ = a.send_to(String("queued").as_bytes(), b.local_addr())
    _settle()
    var buf = List[UInt8](length=8, fill=0)
    fault.clear()
    fault.inject(SYS_recvfrom, Errno.EAGAIN, times=1)
    assert_false(b.try_recv_from(Span(buf)))  # None, and nothing consumed
    var d = b.recv_from(Span(buf))  # the datagram is still there
    fault.clear()
    assert_equal(d.len, 6)
    fault.inject(SYS_recvfrom, Errno.EAGAIN, times=1)
    _ = a.send_to(String("later").as_bytes(), b.local_addr())
    var e = b.recv_from(Span(buf))  # EAGAIN, a poll, then the datagram
    var polls = fault.calls(SYS_ppoll)
    fault.clear()
    assert_equal(e.len, 5)
    assert_true(polls >= 1)
    assert_false(b.try_recv_from(Span(buf)))  # exactly one each


def test_send_eagain_waits_for_space() raises:
    fault.clear()
    var a = _bound()
    var b = _bound()
    fault.clear()
    fault.inject(SYS_sendto, Errno.EAGAIN, times=1)
    assert_false(a.try_send_to(String("x").as_bytes(), b.local_addr()))
    fault.inject(SYS_sendto, Errno.EAGAIN, times=1)
    assert_equal(a.send_to(String("yz").as_bytes(), b.local_addr()), 2)
    fault.clear()
    var buf = List[UInt8](length=8, fill=0)
    assert_equal(b.recv_from(Span(buf)).len, 2)  # only the one that was sent
    assert_false(b.try_recv_from(Span(buf)))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
