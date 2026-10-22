"""Regression tests for the linux layer (review group "tooling-docs").


- `ErrorKind.of` classifies every errno it names, and `ErrorKind.name()`
  spells every kind; higher layers (accept back-off, connect retry, HTTP
  error mapping) branch on these kinds.
- An eventfd wakes an `Epoll.wait` that is *already blocked* with no
  timeout (the M2 mailbox relies on it), for epoll_pwait2 and the
  epoll_pwait fallback, level- and edge-triggered. The waker is a python3
  child process (test-only) holding the eventfd; a thread-directed SIGALRM
  5 s later ends a wait that is never woken, so a regression fails instead
  of hanging.
"""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Errno, ErrorKind, IoError, check, sys
from linux.abi import EpollEvent
from linux.consts import (
    CLOCK_MONOTONIC,
    EPOLLET,
    EPOLLIN,
    SIGALRM,
    SIGEV_THREAD_ID,
)
from linux.epoll import Epoll
from linux.eventfd import EventFd
from linux.nr import (
    SYS_gettid,
    SYS_timer_create,
    SYS_timer_delete,
    SYS_timer_settime,
)
from linux.syscall import syscall0, syscall1, syscall3, syscall4
from linux.time import Duration, Instant

comptime IN = UInt32(EPOLLIN)
comptime ET = UInt32(EPOLLET)


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


# ---- ErrorKind (F56) ---------------------------------------------------------


def _kind_is(e: Errno, want: ErrorKind) raises:
    var got = ErrorKind.of(e)
    assert_true(got == want, String(e, " -> ", got, ", want ", want))
    var err = IoError.from_errno("op", e)
    assert_true(err.kind == want and err.errno == e, String(err))


def test_error_kind_table_is_complete() raises:
    # One row per errno that ErrorKind.of names (every branch).
    _kind_is(Errno.EAGAIN, ErrorKind.WouldBlock)
    _kind_is(Errno.EWOULDBLOCK, ErrorKind.WouldBlock)
    _kind_is(Errno.EINTR, ErrorKind.Interrupted)
    _kind_is(Errno.ETIMEDOUT, ErrorKind.TimedOut)
    _kind_is(Errno.ECONNREFUSED, ErrorKind.ConnectionRefused)
    _kind_is(Errno.ECONNRESET, ErrorKind.ConnectionReset)
    _kind_is(Errno.ECONNABORTED, ErrorKind.ConnectionAborted)
    _kind_is(Errno.EPIPE, ErrorKind.BrokenPipe)
    _kind_is(Errno.ENOTCONN, ErrorKind.NotConnected)
    _kind_is(Errno.EISCONN, ErrorKind.AlreadyConnected)
    _kind_is(Errno.EINPROGRESS, ErrorKind.InProgress)
    _kind_is(Errno.EALREADY, ErrorKind.InProgress)
    _kind_is(Errno.EADDRINUSE, ErrorKind.AddrInUse)
    _kind_is(Errno.EADDRNOTAVAIL, ErrorKind.AddrNotAvailable)
    _kind_is(Errno.ENETUNREACH, ErrorKind.NetworkUnreachable)
    _kind_is(Errno.ENETDOWN, ErrorKind.NetworkDown)
    _kind_is(Errno.EHOSTUNREACH, ErrorKind.HostUnreachable)
    _kind_is(Errno.EHOSTDOWN, ErrorKind.HostUnreachable)
    _kind_is(Errno.EINVAL, ErrorKind.InvalidInput)
    _kind_is(Errno.EAFNOSUPPORT, ErrorKind.InvalidInput)
    _kind_is(Errno.ENAMETOOLONG, ErrorKind.InvalidInput)
    _kind_is(Errno.EACCES, ErrorKind.PermissionDenied)
    _kind_is(Errno.EPERM, ErrorKind.PermissionDenied)
    _kind_is(Errno.ENOENT, ErrorKind.NotFound)
    _kind_is(Errno.EMFILE, ErrorKind.TooManyFiles)
    _kind_is(Errno.ENFILE, ErrorKind.TooManyFiles)
    _kind_is(Errno.ENOMEM, ErrorKind.OutOfMemory)
    _kind_is(Errno.ENOBUFS, ErrorKind.OutOfMemory)
    _kind_is(Errno.EOPNOTSUPP, ErrorKind.Unsupported)
    _kind_is(Errno.ENOTSUP, ErrorKind.Unsupported)
    _kind_is(Errno.ENOPROTOOPT, ErrorKind.Unsupported)
    _kind_is(Errno.EPROTONOSUPPORT, ErrorKind.Unsupported)
    _kind_is(Errno.ENOSYS, ErrorKind.Unsupported)
    _kind_is(Errno.ECANCELED, ErrorKind.Canceled)
    _kind_is(Errno.EBADF, ErrorKind.Closed)
    # Errnos without a category stay Other.
    _kind_is(Errno.EIO, ErrorKind.Other)
    _kind_is(Errno.ENOSPC, ErrorKind.Other)
    _kind_is(Errno.EPROTO, ErrorKind.Other)
    _kind_is(Errno(0), ErrorKind.Other)
    _kind_is(Errno(4095), ErrorKind.Other)


def test_error_kind_names_are_exact_and_distinct() raises:
    var kinds: List[ErrorKind] = [
        ErrorKind.Other,
        ErrorKind.WouldBlock,
        ErrorKind.Interrupted,
        ErrorKind.TimedOut,
        ErrorKind.ConnectionRefused,
        ErrorKind.ConnectionReset,
        ErrorKind.ConnectionAborted,
        ErrorKind.BrokenPipe,
        ErrorKind.NotConnected,
        ErrorKind.AlreadyConnected,
        ErrorKind.InProgress,
        ErrorKind.AddrInUse,
        ErrorKind.AddrNotAvailable,
        ErrorKind.NetworkUnreachable,
        ErrorKind.NetworkDown,
        ErrorKind.HostUnreachable,
        ErrorKind.InvalidInput,
        ErrorKind.PermissionDenied,
        ErrorKind.NotFound,
        ErrorKind.TooManyFiles,
        ErrorKind.OutOfMemory,
        ErrorKind.Unsupported,
        ErrorKind.UnexpectedEof,
        ErrorKind.WriteZero,
        ErrorKind.Canceled,
        ErrorKind.Closed,
        ErrorKind.InvalidData,
    ]
    var names: List[String] = [
        "Other",
        "WouldBlock",
        "Interrupted",
        "TimedOut",
        "ConnectionRefused",
        "ConnectionReset",
        "ConnectionAborted",
        "BrokenPipe",
        "NotConnected",
        "AlreadyConnected",
        "InProgress",
        "AddrInUse",
        "AddrNotAvailable",
        "NetworkUnreachable",
        "NetworkDown",
        "HostUnreachable",
        "InvalidInput",
        "PermissionDenied",
        "NotFound",
        "TooManyFiles",
        "OutOfMemory",
        "Unsupported",
        "UnexpectedEof",
        "WriteZero",
        "Canceled",
        "Closed",
        "InvalidData",
    ]
    assert_equal(len(kinds), len(names))
    for i in range(len(kinds)):
        assert_equal(String(kinds[i].name()), names[i])
        assert_equal(String(kinds[i]), names[i])  # write_to spells name()
        for j in range(i):
            assert_false(kinds[i] == kinds[j], names[i])
    # IoError's text carries the kind's name and the errno.
    assert_equal(
        String(IoError.from_errno("connect", Errno.ENETUNREACH)),
        String("connect: NetworkUnreachable (", Errno.ENETUNREACH, ")"),
    )


# ---- eventfd wakes an already-blocked Epoll.wait (F59) -----------------------

comptime _WAKER = (
    "import os, sys, time\n"
    "fd = int(sys.argv[1])\n"
    "time.sleep(0.1)\n"
    "os.write(fd, (1).to_bytes(8, sys.byteorder))\n"
)


def _reap(child: PythonObject) raises:
    try:
        _ = child.wait(timeout=30)
        return
    except:
        pass  # subprocess.TimeoutExpired
    _ = child.kill()
    _ = child.wait()
    raise Error("python waker did not exit within 30 s")


def test_eventfd_wakes_blocked_wait_from_another_process() raises:
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    for fallback in range(2):
        for edge in range(2):
            var what = String(
                "epoll_pwait" if fallback == 1 else "epoll_pwait2",
                " ET" if edge == 1 else " LT",
            )
            var ep = Epoll.new()
            if fallback == 1:
                ep.disable_pwait2()
            var e = EventFd.new()
            ep.add(e, IN | (ET if edge == 1 else UInt32(0)), 0xE0E0)
            var evs = List[EpollEvent](capacity=4)
            var fd = Int(e.raw_fd())
            var child = subprocess.Popen(
                Python.list(pysys.executable, "-c", _WAKER, String(fd)),
                pass_fds=Python.list(fd),
            )
            # Backstop: a wait nobody wakes ends with EINTR (0 events).
            var backstop = _SignalBurst(first_ms=5000, count=1)
            var t0 = Instant.now()
            var n = ep.wait(evs, None)  # no timeout: blocks until the write
            var dt = t0.elapsed()
            _ = backstop.stop()
            _reap(child)
            assert_equal(n, 1, String(what, ": not woken"))
            # It really blocked (the child writes >= 100 ms after spawn)...
            assert_true(dt >= Duration.from_millis(50), String(what, " ", dt))
            # ...and woke on the write, not on the backstop.
            assert_true(dt < Duration.from_millis(4500), String(what, " ", dt))
            assert_equal(evs[0].events(), IN)
            assert_equal(evs[0].data(), UInt64(0xE0E0))
            assert_equal(e.drain(), UInt64(1))
            assert_equal(ep.wait(evs, Duration.ZERO), 0)
            sys.keep_alive(e)  # registered fds must outlive the waits


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
