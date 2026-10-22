"""EINTR paths of net.tcp: L2 never lets `Interrupted` escape and never lets
a signal shorten or restart a deadline.

L2 sockets are nonblocking, so the syscalls a signal can interrupt are the
ppoll waits (and only those). The storm below interrupts them every 20 ms:
- The handler is CPython's C-level one (`signal.signal` through Python
  interop; CPython installs it without SA_RESTART). The library itself
  never installs handlers; only this test does.
- SIGALRM comes from a POSIX timer with SIGEV_THREAD_ID aimed at our tid,
  so no other runtime thread can absorb it, and it repeats, so a tick that
  lands outside the wait cannot make the test pass vacuously for long.
- Peers that must act while we block are python3 child processes
  (test-only), spawned before the storm starts.
- Proof that signals really interrupted the waits: CPython coalesces
  signals into one pending flag, so its handler cannot count them. Instead
  this file is built with the fault seam (`_faults.mojo` suffix) purely to
  count syscalls; it installs no rules. One wait is one ppoll unless a
  signal interrupts it, so `fault.calls(SYS_ppoll)` well above 1 shows the
  waits were interrupted and resumed.
Deterministic counterparts with injected EINTR (exact syscall counts) are in
test_tcp_faults.mojo.
"""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_true

from linux import Errno, ErrorKind, IoError, check, fault
from linux import sys
from linux.consts import CLOCK_MONOTONIC, SIGALRM, SIGEV_THREAD_ID
from linux.nr import (
    SYS_connect,
    SYS_getpid,
    SYS_gettid,
    SYS_ppoll,
    SYS_timer_create,
    SYS_timer_delete,
    SYS_timer_settime,
)
from linux.syscall import syscall0, syscall1, syscall3, syscall4
from linux.time import Deadline, Duration, Instant
from net.addr import SocketAddr, UnixAddr
from net.socket import Shutdown
from net.tcp import TcpListener, TcpStream
from net.unix import UnixListener, UnixStream


struct _AlarmStorm:
    """CPython's SIGALRM handler plus a repeating timer aimed at this
    thread. Starting it clears the fault plan; `stop()` deletes the timer,
    restores SIG_DFL and returns how many ppoll calls ran meanwhile."""

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
        fault.clear()

    def stop(mut self) raises -> Int:
        var polls = fault.calls(SYS_ppoll)
        _ = check("timer_delete", syscall1(SYS_timer_delete, Int(self.timer)))
        # Runs the pending (no-op) Python handler, then restores SIG_DFL.
        _ = self.signal.signal(SIGALRM, self.signal.SIG_DFL)
        return polls


comptime _PEER = (
    "import socket, sys, time\n"
    "mode, port = sys.argv[1], int(sys.argv[2])\n"
    "s = socket.create_connection(('127.0.0.1', port))\n"
    "s.settimeout(30)\n"
    "if mode == 'late_send':\n"
    "    time.sleep(0.2)\n"
    "    s.sendall(b'late')\n"
    "    s.recv(1)\n"
    "elif mode == 'sink_echo':\n"
    "    time.sleep(0.1)\n"
    "    data = bytearray()\n"
    "    while True:\n"
    "        b = s.recv(1 << 16)\n"
    "        if not b:\n"
    "            break\n"
    "        data += b\n"
    "    s.sendall(data)\n"
    "s.close()\n"
)


def _spawn_peer(mode: String, port: Int) raises -> PythonObject:
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    return subprocess.Popen(
        Python.list(pysys.executable, "-c", _PEER, mode, String(port))
    )


def _reap(child: PythonObject, failed: Bool = False) raises:
    """Wait (bounded) for a peer child. One that is still running after 30 s
    is killed and reaped, and the test fails: it never leaves a zombie or a
    stray process behind, and never waits forever. `failed`: the test
    already failed, so kill the child at once (its error is the one to
    report)."""
    if failed:
        _ = child.kill()
    try:
        _ = child.wait(timeout=30)
        return
    except:
        pass  # subprocess.TimeoutExpired
    _ = child.kill()
    _ = child.wait()
    raise Error("python peer did not exit within 30 s")


def _ms(n: Int) -> Duration:
    return Duration.from_millis(n)


def _guard() -> Deadline:
    """Backstop for waits on a python peer: if the child cannot start or
    dies before connecting, accept fails with TimedOut instead of waiting
    forever (Deadline.none() never expires and EINTR never ends a wait)."""
    return Deadline.after(Duration.from_secs(10))


def _accept_or_reap(l: TcpListener, child: PythonObject) raises -> TcpStream:
    """`l.accept()` bounded by the listener's deadline; if it fails (the peer
    never connected), reap the child and fail with a readable message."""
    var msg: String
    try:
        return l.accept().into_stream()
    except e:
        msg = String(e)
    _reap(child, failed=True)
    raise Error("accept failed (did the python peer start?): ", msg)


def test_read_deadline_is_exact_under_signal_storm() raises:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    var buf = List[UInt8](length=8, fill=0)
    var storm = _AlarmStorm()
    var t = Instant.now()
    c.set_read_deadline(Deadline.after(_ms(300)))
    var kind = ErrorKind.Other
    try:
        _ = c.read(Span(buf))
    except e:
        kind = e.kind
    var el = t.elapsed()
    var polls = storm.stop()
    # Not Interrupted, not early (EINTR does not end the wait), not late
    # (EINTR does not restart the full timeout).
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(polls >= 5, String("only ", polls, " ppoll calls"))
    assert_true(el >= _ms(300), String("early: ", el))
    assert_true(el < _ms(600), String("late: ", el))
    sys.keep_alive(s)


def test_accept_and_read_complete_under_signal_storm() raises:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    l.set_deadline(_guard())  # a peer that never connects fails, not hangs
    var child = _spawn_peer("late_send", Int(l.local_addr().port()))
    var storm = _AlarmStorm()
    var ok = True
    var got: String
    try:
        var s = l.accept().into_stream()  # waits for the child to start
        s.set_deadline(_guard())
        var buf = List[UInt8](length=4, fill=0)
        s.read_exact(Span(buf))  # data arrives ~200 ms later
        got = String(from_utf8_lossy=Span(buf))
        s.shutdown(Shutdown.WRITE)
    except e:
        ok = False
        got = String(e)
    var polls = storm.stop()
    _reap(child, failed=not ok)
    assert_true(ok, got)
    assert_equal(got, "late")
    assert_true(polls >= 4, String("only ", polls, " ppoll calls"))


def test_connect_timeout_is_exact_under_signal_storm() raises:
    # Full accept queue: SYNs are dropped (see test_tcp.mojo).
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"), backlog=0)
    var addr = l.local_addr()
    var queued = TcpStream.connect(addr)
    var storm = _AlarmStorm()
    var t = Instant.now()
    var kind = ErrorKind.Other
    try:
        _ = TcpStream.connect_timeout(addr, _ms(300))
    except e:
        kind = e.kind
    var el = t.elapsed()
    var polls = storm.stop()
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(polls >= 5, String("only ", polls, " ppoll calls"))
    assert_true(el >= _ms(300), String("early: ", el))
    assert_true(el < _ms(600), String("late: ", el))
    sys.keep_alive(queued)
    sys.keep_alive(l)


def test_write_all_completes_under_signal_storm() raises:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    l.set_deadline(_guard())  # a peer that never connects fails, not hangs
    var child = _spawn_peer("sink_echo", Int(l.local_addr().port()))
    var s = _accept_or_reap(l, child)
    s.socket().set_send_buffer_size(8192)
    s.set_deadline(Deadline.after(Duration.from_secs(30)))
    var data = List[UInt8](capacity=1 << 20)
    for i in range(1 << 20):
        data.append(UInt8(i % 253))
    var storm = _AlarmStorm()
    var ok = True
    var msg = String()
    var back = List[UInt8]()
    try:
        s.write_all(Span(data))  # the child starts reading after 100 ms
        s.shutdown(Shutdown.WRITE)
        _ = s.read_to_end(back)
    except e:
        ok = False
        msg = String(e)
    var polls = storm.stop()
    _reap(child, failed=not ok)
    assert_true(ok, msg)
    assert_true(polls >= 3, String("only ", polls, " ppoll calls"))
    assert_equal(len(back), len(data))
    for i in range(len(data)):
        if back[i] != data[i]:
            assert_true(False, String("mismatch at ", i))


def test_unix_connect_resumes_with_remaining_time_under_signal_storm() raises:
    # AF_UNIX connect really blocks in the kernel (full backlog), so here
    # the signals interrupt connect itself. L2 must re-issue it (safe for
    # AF_UNIX) with the *remaining* time: re-arming the full timeout after
    # every 20 ms signal would never time out.
    var addr = UnixAddr.from_abstract_name(
        String("mojo_net_eintr_", syscall0(SYS_getpid))
    )
    var l = UnixListener.bind(addr, backlog=0)
    var first = UnixStream.connect(addr)  # takes the only slot
    var storm = _AlarmStorm()
    var t = Instant.now()
    var kind = ErrorKind.Other
    try:
        _ = UnixStream.connect_timeout(addr, _ms(300))
    except e:
        kind = e.kind
    var el = t.elapsed()
    var connects = fault.calls(SYS_connect)
    _ = storm.stop()
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(connects >= 5, String("only ", connects, " connect calls"))
    assert_true(el >= _ms(300), String("early: ", el))
    assert_true(el < _ms(600), String("late: ", el))
    sys.keep_alive(first)
    sys.keep_alive(l)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
