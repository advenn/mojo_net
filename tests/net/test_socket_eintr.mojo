"""EINTR paths of net.socket: L1 reports `Interrupted` and never retries.

A signal must interrupt a blocking syscall of *this* thread, with a handler
installed without SA_RESTART:
- The handler is CPython's C-level one (`signal.signal` through Python
  interop; CPython uses `sa_flags = SA_ONSTACK`, no SA_RESTART). The
  library itself never installs handlers; only this test does.
- SIGALRM comes from a POSIX timer with SIGEV_THREAD_ID aimed at our tid, so
  no other runtime thread can absorb it. It repeats every 20 ms, so a tick
  that lands before the syscall blocks cannot make the test hang.
- SO_RCVTIMEO/SO_SNDTIMEO are backstops: if no signal ever interrupted the
  call, it fails with WouldBlock/InProgress after 3 s instead of hanging.
"""

from std.python import Python, PythonObject
from std.sys import size_of
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Errno, ErrorKind, IoError, check
from linux import sys
from linux.abi import Timeval
from linux.consts import (
    CLOCK_MONOTONIC,
    POLLOUT,
    SIGALRM,
    SIGEV_THREAD_ID,
    SO_RCVTIMEO,
    SO_SNDTIMEO,
    SOL_SOCKET,
)
from linux.nr import (
    SYS_gettid,
    SYS_timer_create,
    SYS_timer_delete,
    SYS_timer_settime,
)
from linux.poll import wait_ready
from linux.syscall import syscall0, syscall1, syscall3, syscall4
from linux.time import Deadline, Duration
from net.addr import SocketAddr
from net.socket import Domain, SockType, Socket, SocketPair


struct _AlarmStorm:
    """CPython's SIGALRM handler plus a repeating timer aimed at this
    thread. `stop()` deletes the timer and restores SIG_DFL."""

    var timer: Int32
    var signal: PythonObject

    def __init__(out self, period_ms: Int = 20) raises:
        self.signal = Python.import_module("signal")
        _ = self.signal.signal(SIGALRM, Python.evaluate("lambda *a: None"))
        # struct sigevent (64 bytes): sigev_value at 0, sigev_signo at 8,
        # sigev_notify at 12, _tid at 16.
        var sev = Array[Int32, 16](fill=0)
        sev[2] = Int32(SIGALRM)
        sev[3] = Int32(SIGEV_THREAD_ID)
        sev[4] = Int32(syscall0(SYS_gettid))
        self.timer = -1
        _ = check(
            "timer_create",
            syscall3(
                SYS_timer_create,
                CLOCK_MONOTONIC,
                Int(Pointer(to=sev)),
                Int(Pointer(to=self.timer)),
            ),
        )
        sys.keep_alive(sev)
        # struct itimerspec: it_interval, it_value (timespec each).
        var spec = Array[Int, 4](fill=0)
        spec[1] = period_ms * 1_000_000
        spec[3] = period_ms * 1_000_000
        _ = check(
            "timer_settime",
            syscall4(
                SYS_timer_settime, Int(self.timer), 0, Int(Pointer(to=spec)), 0
            ),
        )
        sys.keep_alive(spec)

    def stop(mut self) raises:
        _ = check("timer_delete", syscall1(SYS_timer_delete, Int(self.timer)))
        # Runs the pending (no-op) Python handler, then restores SIG_DFL.
        _ = self.signal.signal(SIGALRM, self.signal.SIG_DFL)


def _set_timeout(s: Socket, name: Int, secs: Int) raises:
    """SO_RCVTIMEO/SO_SNDTIMEO take a struct timeval."""
    var tv = Timeval(secs, 0)
    var r = sys.setsockopt(s, SOL_SOCKET, name, tv, size_of[Timeval]())
    _ = check("setsockopt", r)


def _expect_interrupted(raised: Bool, kind: ErrorKind, errno: Errno) raises:
    assert_true(raised, "the call was not interrupted")
    assert_equal(kind, ErrorKind.Interrupted)
    assert_equal(errno, Errno.EINTR)


def test_blocking_recv_is_interrupted_not_retried() raises:
    var p = Socket.pair(Domain.UNIX, SockType.STREAM)
    ref rx = p.second.value()
    _set_timeout(rx, SO_RCVTIMEO, 3)
    var buf = List[UInt8](length=8, fill=0)
    var storm = _AlarmStorm()
    var raised = False
    var kind = ErrorKind.Other
    var errno = Errno(0)
    try:
        _ = rx.recv(Span(buf))
    except e:
        raised = True
        kind = e.kind
        errno = e.errno
    storm.stop()
    _expect_interrupted(raised, kind, errno)
    # Nothing was lost: the socket works normally afterwards.
    _ = p.first.value().send(String("after").as_bytes())
    assert_equal(rx.recv(Span(buf)), 5)


def test_blocking_accept_is_interrupted() raises:
    var l = Socket.new(Domain.IPV4, SockType.STREAM)
    l.bind(SocketAddr.parse("127.0.0.1:0"))
    l.listen(4)
    _set_timeout(l, SO_RCVTIMEO, 3)
    var storm = _AlarmStorm()
    var raised = False
    var kind = ErrorKind.Other
    var errno = Errno(0)
    try:
        _ = l.accept()
    except e:
        raised = True
        kind = e.kind
        errno = e.errno
    storm.stop()
    _expect_interrupted(raised, kind, errno)
    # Calling accept again is the right recovery for accept.
    var c = Socket.new(Domain.IPV4, SockType.STREAM)
    c.connect(l.local_addr())
    var acc = l.accept()
    assert_equal(acc.addr, c.local_addr())


def test_interrupted_connect_completes_via_poll_and_take_error() raises:
    # A listener with backlog 0 queues one connection; with that slot taken
    # the kernel drops our SYN, so a blocking connect waits for the SYN
    # retransmit (~1 s) and the timer interrupts it first.
    var l = Socket.new(Domain.IPV4, SockType.STREAM)
    l.bind(SocketAddr.parse("127.0.0.1:0"))
    l.listen(0)
    var to = l.local_addr()
    var first = Socket.new(Domain.IPV4, SockType.STREAM)
    first.connect(to)
    var c = Socket.new(Domain.IPV4, SockType.STREAM)
    _set_timeout(c, SO_SNDTIMEO, 3)
    var storm = _AlarmStorm()
    var raised = False
    var kind = ErrorKind.Other
    var errno = Errno(0)
    try:
        c.connect(to)
    except e:
        raised = True
        kind = e.kind
        errno = e.errno
    storm.stop()
    _expect_interrupted(raised, kind, errno)
    # Documented recovery: do not call connect again; free the queue slot,
    # wait for writable, then read SO_ERROR.
    var a1 = l.accept().into_socket()
    var rev = wait_ready(
        c, Int16(POLLOUT), Deadline.after(Duration.from_secs(10)), "wait"
    )
    assert_true((Int(rev) & POLLOUT) != 0)
    assert_false(Bool(c.take_error()))
    assert_equal(c.peer_addr(), to)
    var a2 = l.accept()
    assert_equal(a2.addr, c.local_addr())
    _ = c.send(String("late").as_bytes())
    var buf = List[UInt8](length=8, fill=0)
    assert_equal(a2.socket.recv(Span(buf)), 4)
    sys.keep_alive(first)
    sys.keep_alive(a1)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
