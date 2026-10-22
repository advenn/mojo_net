from std.python import Python, PythonObject
from std.sys import size_of
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import AsFd, Errno, ErrorKind, IoError, OwnedFd, RawFd, check, sys
from linux.abi import Pollfd, SockaddrIn, SockaddrStorage, hton16, hton32
from linux.consts import (
    AF_INET,
    AF_UNIX,
    CLOCK_MONOTONIC,
    MSG_NOSIGNAL,
    POLLERR,
    POLLHUP,
    POLLIN,
    POLLNVAL,
    POLLOUT,
    POLLRDHUP,
    SHUT_WR,
    SIGALRM,
    SIGEV_THREAD_ID,
    SO_ERROR,
    SOCK_CLOEXEC,
    SOCK_NONBLOCK,
    SOCK_STREAM,
    SOL_SOCKET,
)
from linux.poll import poll_until, ppoll, wait_ready
from linux.nr import (
    SYS_gettid,
    SYS_timer_create,
    SYS_timer_delete,
    SYS_timer_settime,
)
from linux.syscall import err_of, is_err, syscall0, syscall1, syscall3, syscall4
from linux.time import Deadline, Duration, Instant

comptime IN = Int16(POLLIN)
comptime OUT = Int16(POLLOUT)


def _pair() raises -> Tuple[OwnedFd, OwnedFd]:
    var fds = Array[Int32, 2](fill=-1)
    _ = check(
        "socketpair",
        sys.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds),
    )
    return (OwnedFd(unsafe_from_raw=fds[0]), OwnedFd(unsafe_from_raw=fds[1]))


def _has(rev: Int16, flag: Int) -> Bool:
    return (Int(rev) & flag) != 0


def _ms(n: Int) -> Duration:
    return Duration.from_millis(n)


def _expect_kind[
    F: AsFd
](fd: F, events: Int16, deadline: Deadline, kind: ErrorKind) raises -> IoError:
    """Run wait_ready expecting an IoError of `kind`; return it."""
    try:
        _ = wait_ready(fd, events, deadline, "test-op")
    except e:
        assert_true(e.kind == kind, String("got ", e))
        assert_equal(String(e.op), "test-op")
        return e
    assert_true(False, "wait_ready did not raise")
    return IoError.of_kind("unreachable", ErrorKind.Other)


# ---- signal helpers (test-only: the library never installs handlers) ------


struct _SignalBurst:
    """`count` SIGALRMs aimed at this thread, `gap_ms` apart, the first one
    `first_ms` from now (test-only; the library installs no handlers).

    - One-shot POSIX timers with SIGEV_THREAD_ID: a process-directed signal
      (setitimer, kill) may be taken by any runtime thread that does not
      block it, and would then interrupt nothing.
    - The handler is CPython's C-level one (installed without SA_RESTART
      through Python interop), so the interrupted syscall fails with EINTR.
    - Several signals: if this thread is delayed past the first one (CPU
      throttling, VM steal), it is handled before the blocking call starts
      and a later one still interrupts the call.
    - A bounded burst: a wait that wrongly restarted its full timeout after
      EINTR still ends (and fails its timing check) instead of hanging."""

    var timers: List[Int32]
    var signal: PythonObject
    var counter: PythonObject

    def __init__(
        out self, first_ms: Int, count: Int = 5, gap_ms: Int = 20
    ) raises:
        self.signal = Python.import_module("signal")
        self.counter = Python.evaluate("[0]")
        var make = Python.evaluate(
            "lambda c: (lambda s, f: c.__setitem__(0, c[0] + 1))"
        )
        _ = self.signal.signal(SIGALRM, make(self.counter))
        self.timers = List[Int32]()
        var tid = syscall0(SYS_gettid)
        for _ in range(count):
            # struct sigevent (64 bytes): sigev_value at 0, sigev_signo at
            # 8, sigev_notify at 12, _tid at 16.
            var sev = Array[Int32, 16](fill=0)
            sev[2] = Int32(SIGALRM)
            sev[3] = Int32(SIGEV_THREAD_ID)
            sev[4] = Int32(tid)
            var id: Int32 = -1
            _ = check(
                "timer_create",
                syscall3(
                    SYS_timer_create,
                    CLOCK_MONOTONIC,
                    Int(Pointer(to=sev)),
                    Int(Pointer(to=id)),
                ),
            )
            sys.keep_alive(sev)
            self.timers.append(id)
        for i in range(count):
            # struct itimerspec: it_interval (0: one-shot), it_value.
            var spec = Array[Int, 4](fill=0)
            var ns = (first_ms + i * gap_ms) * 1_000_000
            spec[2] = ns // 1_000_000_000
            spec[3] = ns % 1_000_000_000
            _ = check(
                "timer_settime",
                syscall4(
                    SYS_timer_settime,
                    Int(self.timers[i]),
                    0,
                    Int(Pointer(to=spec)),
                    0,
                ),
            )
            sys.keep_alive(spec)

    def stop(mut self) raises -> Int:
        """Delete the timers, run the pending Python handler, restore
        SIG_DFL. Returns how often the handler ran: CPython coalesces
        signals that arrive before it runs, so this is >= 1 when any
        arrived, not the number of signals."""
        for t in self.timers:
            _ = check("timer_delete", syscall1(SYS_timer_delete, Int(t)))
        self.timers.clear()
        _ = Python.evaluate("[i for i in range(3)]")  # runs pending handlers
        _ = self.signal.signal(SIGALRM, self.signal.SIG_DFL)
        return Int(py=self.counter[0])

    def __deinit__(deinit self):
        # A test that raised before stop(): disarm what is left.
        for t in self.timers:
            _ = syscall1(SYS_timer_delete, Int(t))


# ---- raw ppoll --------------------------------------------------------------


def test_ppoll_writable_and_not_readable() raises:
    var p = _pair()
    var fds = [Pollfd(p[0].raw_fd(), IN | OUT, 0)]
    var r = ppoll(Span(fds), Duration.ZERO)
    sys.keep_alive(p)
    assert_equal(r, 1)
    assert_true(_has(fds[0].revents, POLLOUT))
    assert_false(_has(fds[0].revents, POLLIN))


def test_ppoll_zero_timeout_on_idle_returns_zero() raises:
    var p = _pair()
    var fds = [Pollfd(p[0].raw_fd(), IN, 0)]
    var t = Instant.now()
    var r = ppoll(Span(fds), Duration.ZERO)
    sys.keep_alive(p)
    assert_equal(r, 0)
    assert_equal(Int(fds[0].revents), 0)
    assert_true(t.elapsed() < _ms(20))


def test_ppoll_readable_after_send() raises:
    var p = _pair()
    _ = check("send", sys.send(p[1], String("x").as_bytes(), MSG_NOSIGNAL))
    var fds = [Pollfd(p[0].raw_fd(), IN, 0)]
    var r = ppoll(Span(fds), None)
    sys.keep_alive(p)
    assert_equal(r, 1)
    assert_equal(Int(fds[0].revents), POLLIN)


def test_ppoll_timeout_elapses() raises:
    var p = _pair()
    var fds = [Pollfd(p[0].raw_fd(), IN, 0)]
    var t = Instant.now()
    var r = ppoll(Span(fds), _ms(40))
    var e = t.elapsed()
    sys.keep_alive(p)
    assert_equal(r, 0)
    assert_true(e >= _ms(40))
    assert_true(e < _ms(40 + 250))


def test_ppoll_multiple_entries_negative_fd_ignored() raises:
    var p = _pair()
    var fds = [
        Pollfd(p[0].raw_fd(), IN, 0),
        Pollfd(p[1].raw_fd(), OUT, 0),
        Pollfd(-1, IN | OUT, 0),
    ]
    var r = ppoll(Span(fds), Duration.ZERO)
    sys.keep_alive(p)
    assert_equal(r, 1)
    assert_equal(Int(fds[0].revents), 0)
    assert_true(_has(fds[1].revents, POLLOUT))
    assert_equal(Int(fds[2].revents), 0)


def test_ppoll_unopened_fd_reports_pollnval() raises:
    # Above RLIMIT_NOFILE on any sane box, so it can never be open.
    var fds = [Pollfd(Int32(1 << 30), IN, 0)]
    var r = ppoll(Span(fds), Duration.ZERO)
    assert_equal(r, 1)
    assert_equal(Int(fds[0].revents), POLLNVAL)


def test_ppoll_huge_timeout_is_accepted() raises:
    # Duration.MAX turns into a ~292-year timespec; the kernel must accept
    # it (no EINVAL) and return at once because the fd is ready.
    var p = _pair()
    var fds = [Pollfd(p[0].raw_fd(), OUT, 0)]
    var r = ppoll(Span(fds), Duration.MAX)
    sys.keep_alive(p)
    assert_equal(r, 1)


def test_ppoll_raw_returns_eintr_on_signal() raises:
    # Control for the retry tests below: a handled signal really interrupts
    # ppoll with -EINTR in this harness.
    var p = _pair()
    var fds = [Pollfd(p[0].raw_fd(), IN, 0)]
    var burst = _SignalBurst(first_ms=30, count=10)
    var t = Instant.now()
    var r = ppoll(Span(fds), Duration.from_secs(2))
    var e = t.elapsed()
    sys.keep_alive(p)
    assert_true(burst.stop() >= 1)
    assert_true(is_err(r) and Errno(err_of(r)) == Errno.EINTR)
    assert_true(e < Duration.from_secs(1))


# ---- poll_until -------------------------------------------------------------


def test_poll_until_returns_zero_at_deadline() raises:
    var p = _pair()
    var fds = [Pollfd(p[0].raw_fd(), IN, 0)]
    var t = Instant.now()
    var n = poll_until(Span(fds), Deadline.after(_ms(30)), "poll")
    var e = t.elapsed()
    sys.keep_alive(p)
    assert_equal(n, 0)
    assert_true(e >= _ms(30))
    assert_true(e < _ms(30 + 250))


def test_poll_until_counts_ready_entries() raises:
    var p = _pair()
    _ = check("send", sys.send(p[1], String("x").as_bytes(), MSG_NOSIGNAL))
    var fds = [Pollfd(p[0].raw_fd(), IN, 0), Pollfd(p[1].raw_fd(), OUT, 0)]
    var n = poll_until(Span(fds), Deadline.none(), "poll")
    sys.keep_alive(p)
    assert_equal(n, 2)


def test_poll_until_eintr_keeps_waiting() raises:
    var p = _pair()
    var fds = [Pollfd(p[0].raw_fd(), IN, 0)]
    var burst = _SignalBurst(first_ms=50)  # 50..130 ms
    var t = Instant.now()
    var n = poll_until(Span(fds), Deadline.after(_ms(200)), "poll")
    var e = t.elapsed()
    sys.keep_alive(p)
    assert_true(burst.stop() >= 1)
    assert_equal(n, 0)
    assert_true(e >= _ms(200))


# ---- wait_ready -------------------------------------------------------------


def test_wait_ready_writable() raises:
    var p = _pair()
    var rev = wait_ready(p[0], OUT, Deadline.after(_ms(500)), "write")
    assert_true(_has(rev, POLLOUT))
    assert_false(_has(rev, POLLIN))
    sys.keep_alive(p)


def test_wait_ready_readable_infinite_deadline() raises:
    var p = _pair()
    _ = check("send", sys.send(p[1], String("hi").as_bytes(), MSG_NOSIGNAL))
    var rev = wait_ready(p[0], IN, Deadline.none(), "read")
    assert_equal(Int(rev), POLLIN)
    sys.keep_alive(p)


def test_wait_ready_times_out_within_tolerance() raises:
    var p = _pair()
    var t = Instant.now()
    var err = _expect_kind(
        p[0], IN, Deadline.after(_ms(100)), ErrorKind.TimedOut
    )
    var e = t.elapsed()
    sys.keep_alive(p)
    assert_true(err.errno == Errno(0))
    assert_true(e >= _ms(100))
    assert_true(e < _ms(100 + 250))


def test_wait_ready_expired_deadline_still_reports_readiness() raises:
    var p = _pair()
    var past = Deadline.at(Instant.now() - Duration.from_secs(1))
    # Nothing ready: times out without waiting.
    var t = Instant.now()
    _ = _expect_kind(p[0], IN, past, ErrorKind.TimedOut)
    assert_true(t.elapsed() < _ms(20))
    # Already ready: readiness wins over the expired deadline.
    var rev = wait_ready(p[0], OUT, past, "write")
    assert_true(_has(rev, POLLOUT))
    sys.keep_alive(p)


def test_wait_ready_returns_promptly_when_data_arrives() raises:
    # A child process writes one byte ~100 ms later into our socket (its
    # stdout is a dup of p[1]); the wait must end then, not at the deadline.
    var p = _pair()
    var subprocess = Python.import_module("subprocess")
    var argv = Python.list("/bin/sh", "-c", "sleep 0.1; printf x")
    var t = Instant.now()
    var child = subprocess.Popen(argv, stdout=Int(p[1].raw_fd()))
    var rev = wait_ready(
        p[0], IN, Deadline.after(Duration.from_secs(10)), "read"
    )
    var e = t.elapsed()
    _ = child.wait()
    assert_true(_has(rev, POLLIN))
    assert_true(e >= _ms(50))  # it really waited for the child
    assert_true(e < Duration.from_secs(3))
    var buf = List[UInt8](length=4, fill=0)
    assert_equal(check("recv", sys.recv(p[0], Span(buf), 0)), 1)
    assert_equal(Int(buf[0]), ord("x"))
    sys.keep_alive(p)


def test_wait_ready_eintr_recomputes_remaining_time() raises:
    # Deadline 400 ms, signals at 250, 270 and 290 ms. Not retrying would
    # end at ~250 ms; restarting the full timeout would end at >= ~690 ms.
    var p = _pair()
    var burst = _SignalBurst(first_ms=250, count=3)
    var t = Instant.now()
    _ = _expect_kind(p[0], IN, Deadline.after(_ms(400)), ErrorKind.TimedOut)
    var e = t.elapsed()
    sys.keep_alive(p)
    assert_true(burst.stop() >= 1)
    assert_true(e >= _ms(400))
    assert_true(e < _ms(600), String("elapsed ", e))


def test_wait_ready_eintr_infinite_deadline_then_data() raises:
    # Signals at 50..110 ms, data at ~150 ms, no deadline: EINTR must not
    # leak out and the wait must end on the data.
    var p = _pair()
    var subprocess = Python.import_module("subprocess")
    var argv = Python.list("/bin/sh", "-c", "sleep 0.15; printf y")
    var child = subprocess.Popen(argv, stdout=Int(p[1].raw_fd()))
    var burst = _SignalBurst(first_ms=50, count=4)
    var rev = wait_ready(p[0], IN, Deadline.none(), "read")
    _ = child.wait()
    assert_true(burst.stop() >= 1)
    assert_true(_has(rev, POLLIN))
    sys.keep_alive(p)


def test_wait_ready_pollhup_after_peer_close() raises:
    var p = _pair()
    var a = p[0].try_clone()
    _ = p^  # closes both original ends; `a` keeps the read side open
    var t = Instant.now()
    var rev = wait_ready(a, IN, Deadline.after(Duration.from_secs(5)), "read")
    assert_true(t.elapsed() < Duration.from_secs(1))
    assert_true(_has(rev, POLLHUP))
    assert_true(_has(rev, POLLIN))
    # The caller learns the precise outcome from the syscall itself: EOF.
    var buf = List[UInt8](length=4, fill=0)
    assert_equal(check("recv", sys.recv(a, Span(buf), 0)), 0)


def test_wait_ready_pollrdhup_on_peer_shutdown() raises:
    var p = _pair()
    _ = check("shutdown", sys.shutdown(p[1], SHUT_WR))
    var rev = wait_ready(
        p[0],
        Int16(POLLIN | POLLRDHUP),
        Deadline.after(Duration.from_secs(5)),
        "read",
    )
    assert_true(_has(rev, POLLRDHUP))
    assert_true(_has(rev, POLLIN))
    assert_false(_has(rev, POLLHUP))  # half-close only: p[0] can still send
    sys.keep_alive(p)


def _loopback(port_be: UInt16) -> SockaddrIn:
    return SockaddrIn(
        UInt16(AF_INET), port_be, hton32(0x7F000001), Array[UInt8, 8](fill=0)
    )


def test_wait_ready_pollerr_on_refused_connect() raises:
    # Bound but not listening: a connect to it is answered with RST.
    var holder = OwnedFd(
        unsafe_from_raw=Int32(
            check("socket", sys.socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0))
        )
    )
    _ = check("bind", sys.bind(holder, _loopback(0), size_of[SockaddrIn]()))
    var ss = SockaddrStorage.zeroed()
    var sl = UInt32(size_of[SockaddrStorage]())
    _ = check("getsockname", sys.getsockname(holder, ss, sl))
    # sin_port is bytes 2..3 of the sockaddr (network order) = _pad[0..1].
    var port_be = UInt16(ss._pad[0]) | (UInt16(ss._pad[1]) << 8)
    var c = OwnedFd(
        unsafe_from_raw=Int32(
            check(
                "socket",
                sys.socket(
                    AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0
                ),
            )
        )
    )
    var r = sys.connect(c, _loopback(port_be), size_of[SockaddrIn]())
    assert_true(is_err(r) and Errno(err_of(r)) == Errno.EINPROGRESS)
    var rev = wait_ready(
        c, OUT, Deadline.after(Duration.from_secs(5)), "connect"
    )
    assert_true(_has(rev, POLLERR))
    # Returned, not raised: SO_ERROR carries the precise errno.
    var soerr: Int32 = 0
    var sl2 = UInt32(4)
    _ = check("getsockopt", sys.getsockopt(c, SOL_SOCKET, SO_ERROR, soerr, sl2))
    assert_true(Errno(soerr) == Errno.ECONNREFUSED)
    sys.keep_alive(holder)


def test_wait_ready_unopened_fd_raises_closed() raises:
    var err = _expect_kind(
        RawFd(Int32(1 << 30)), IN, Deadline.none(), ErrorKind.Closed
    )
    assert_true(err.errno == Errno.EBADF)


def test_wait_ready_closed_fd_raises_closed() raises:
    var p = _pair()
    var raw = p[0].raw_fd()
    _ = p^  # both ends closed; `raw` now names nothing
    var err = _expect_kind(
        RawFd(raw), IN, Deadline.after(Duration.from_secs(2)), ErrorKind.Closed
    )
    assert_true(err.errno == Errno.EBADF)


def test_wait_ready_negative_fd_raises_instead_of_hanging() raises:
    # ppoll ignores negative fds, so without the check this would wait
    # forever on an infinite deadline.
    var t = Instant.now()
    var err = _expect_kind(RawFd(-1), IN, Deadline.none(), ErrorKind.Closed)
    assert_true(err.errno == Errno.EBADF)
    assert_true(t.elapsed() < _ms(20))


def _fresh_tcp() raises -> OwnedFd:
    return OwnedFd(
        unsafe_from_raw=Int32(
            check("socket", sys.socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0))
        )
    )


def test_wait_ready_owner_outlives_wait() raises:
    # Regression for Mojo's eager destruction: the owner passed in (here a
    # temporary) must stay open for the whole wait. If it were destroyed
    # first, ppoll would see a closed fd (POLLNVAL -> Closed).
    var rev = wait_ready(_fresh_tcp(), OUT, Deadline.after(_ms(500)), "wait")
    assert_true(_has(rev, POLLOUT) or _has(rev, POLLHUP))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
