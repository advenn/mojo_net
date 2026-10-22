"""Regression tests for the net-blocking review findings (F01, F04, F19,
F21, F35) on the production syscalls. The deterministic fault-seam
counterparts (exact syscall counts) are in
test_net_blocking_regressions_faults.mojo.

- F01: a non-empty socket error queue (here: one MSG_ZEROCOPY completion)
  makes ppoll report POLLERR, level-triggered, while recv/send keep saying
  EAGAIN. Waits must neither spin nor ignore their deadline. A shut-down
  AF_UNIX listener (POLLIN|POLLHUP while accept says EAGAIN) is the same
  class. Before the fix these tests spun forever; `_Watchdog` turns such a
  hang into a failed run (SIGALRM, default action) instead of a stuck
  suite. "Did not spin" is measured as this thread's CPU time.
- F04: `read_to_end` caps what it appends (default 64 MiB) and checks the
  deadline between chunks.
- F19/F21: `from_socket` validates family/type/listening state before any
  connection is consumed, and sets FD_CLOEXEC.
- F35: pins the `shutdown(READ)` semantics the docs now describe.

Peers that must act while we block are python3 child processes
(test-only), as in test_tcp.mojo.
"""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import AsFd, Errno, ErrorKind, IoError, OwnedFd, check
from linux import sys
from linux.abi import Timespec
from linux.consts import (
    CLOCK_MONOTONIC,
    F_GETFD,
    F_SETFD,
    FD_CLOEXEC,
    MSG_ERRQUEUE,
    MSG_ZEROCOPY,
    O_CLOEXEC,
    POLLERR,
    SIGALRM,
    SIGEV_THREAD_ID,
    SO_ZEROCOPY,
    SOL_SOCKET,
)
from linux.nr import SYS_gettid, SYS_timer_create, SYS_timer_delete
from linux.nr import SYS_timer_settime
from linux.poll import wait_ready
from linux.syscall import syscall0, syscall1, syscall3, syscall4
from linux.time import Deadline, Duration, Instant, clock_gettime
from net.addr import SocketAddr, UnixAddr
from net.socket import Domain, Shutdown, SockType, Socket
from net.tcp import TcpListener, TcpStream
from net.unix import UnixListener, UnixStream

comptime MiB = 1024 * 1024

# CLOCK_THREAD_CPUTIME_ID (same value on x86_64 and aarch64; not in
# linux.consts, which only carries what the library uses).
comptime _CLOCK_THREAD_CPUTIME_ID = 3


# ---- helpers -----------------------------------------------------------------


def _ms(n: Int) -> Duration:
    return Duration.from_millis(n)


def _lo() raises -> SocketAddr:
    return SocketAddr.parse("127.0.0.1:0")


def _guard() -> Deadline:
    return Deadline.after(Duration.from_secs(10))


def _cpu() -> Duration:
    """CPU time consumed by this thread so far."""
    var ts = Timespec(0, 0)
    _ = clock_gettime(_CLOCK_THREAD_CPUTIME_ID, ts)
    return Duration.from_timespec(ts)


def _text(buf: List[UInt8]) -> String:
    return String(from_utf8_lossy=Span(buf))


def _fd_flags[F: AsFd](f: F) raises -> Int:
    return check("fcntl(F_GETFD)", sys.fcntl(f, F_GETFD))


def _clear_cloexec[F: AsFd](f: F) raises:
    _ = check("fcntl(F_SETFD)", sys.fcntl(f, F_SETFD, 0))
    assert_equal(_fd_flags(f) & FD_CLOEXEC, 0)


struct _Watchdog:
    """Kills the process with SIGALRM (default action: terminate; neither
    the library nor the Mojo runtime handles it) unless `stop()` runs within
    `secs`. Turns a busy-spin regression into a failed test run."""

    var timer: Int32

    def __init__(out self, secs: Int = 20) raises:
        # struct sigevent: sigev_signo at 8, sigev_notify at 12, _tid at 16.
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
        var spec = Array[Int, 4](fill=0)  # it_interval 0: one shot
        spec[2] = secs
        _ = check(
            "timer_settime",
            syscall4(
                SYS_timer_settime, Int(self.timer), 0, Int(Pointer(to=spec)), 0
            ),
        )
        sys.keep_alive(spec)

    def stop(mut self) raises:
        _ = check("timer_delete", syscall1(SYS_timer_delete, Int(self.timer)))


comptime _PEER = (
    "import socket, sys, time\n"
    "mode, port = sys.argv[1], int(sys.argv[2])\n"
    "s = socket.create_connection(('127.0.0.1', port))\n"
    "s.settimeout(30)\n"
    "if mode == 'late_send':\n"
    "    time.sleep(0.3)\n"
    "    s.sendall(b'late')\n"
    "    s.recv(1)\n"
    "elif mode == 'slow_count':\n"
    "    n = 0\n"
    "    while True:\n"
    "        time.sleep(0.005)\n"
    "        b = s.recv(16384)\n"
    "        if not b:\n"
    "            break\n"
    "        n += len(b)\n"
    "    s.sendall(str(n).encode())\n"
    "elif mode == 'send_n':\n"
    "    n = int(sys.argv[3])\n"
    "    chunk = b'z' * (1 << 20)\n"
    "    while n > 0:\n"
    "        k = min(n, len(chunk))\n"
    "        s.sendall(chunk[:k])\n"
    "        n -= k\n"
    "s.close()\n"
)


def _spawn_peer(
    mode: String, port: Int, arg: String = "0"
) raises -> PythonObject:
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    return subprocess.Popen(
        Python.list(pysys.executable, "-c", _PEER, mode, String(port), arg)
    )


def _start_zerocopy(s: TcpStream) raises -> Bool:
    """Send 100 bytes with MSG_ZEROCOPY from `s` and wait until the kernel
    queued the completion: `s` then reports POLLERR (SO_ERROR stays 0) until
    someone reads MSG_ERRQUEUE. The peer's kernel ACKs without the peer
    reading. False (test skipped) if the kernel lacks SO_ZEROCOPY."""
    try:
        s.socket().set_option_int(SOL_SOCKET, SO_ZEROCOPY, 1)
    except e:
        print("    skip: SO_ZEROCOPY unsupported:", e)
        return False
    var payload = List[UInt8](length=100, fill=65)
    assert_equal(s.socket().send_with_flags(Span(payload), MSG_ZEROCOPY), 100)
    # events 0: only POLLERR/POLLHUP can end this wait.
    var rev = wait_ready(s, Int16(0), _guard(), "errqueue")
    assert_true((Int(rev) & POLLERR) != 0)
    assert_false(Bool(s.socket().take_error()))
    _ = payload^
    return True


def _drain_errqueue(s: TcpStream) raises:
    var eb = List[UInt8](length=64, fill=0)
    _ = s.socket().recv_with_flags(Span(eb), MSG_ERRQUEUE)


# ---- F01: error-queue POLLERR must not defeat the wait -----------------------


def test_f01_errqueue_read_times_out_without_spinning() raises:
    var dog = _Watchdog()
    var l = TcpListener.bind(_lo())
    l.set_deadline(_guard())
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    if not _start_zerocopy(s):
        dog.stop()
        return
    s.set_read_deadline(Deadline.after(_ms(300)))
    var buf = List[UInt8](length=64, fill=0)
    var t = Instant.now()
    var cpu0 = _cpu()
    var kind = ErrorKind.Other
    try:
        _ = s.read(Span(buf))
    except e:
        kind = e.kind
    var spent = _cpu() - cpu0
    var took = t.elapsed()
    dog.stop()
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(took >= _ms(300))
    assert_true(took < _ms(2000), String("took ", took))
    assert_true(spent < _ms(100), String("spun: ", spent, " CPU"))
    # The completion is still queued (the library never drains it).
    var rev = wait_ready(s, Int16(0), Deadline.after(Duration.ZERO), "probe")
    assert_true((Int(rev) & POLLERR) != 0)
    sys.keep_alive(c)


def test_f01_errqueue_read_wakes_when_data_arrives() raises:
    # The wait falls back to edge-triggered epoll, which still wakes at once
    # for new data (no polling interval, no CPU burnt meanwhile).
    var dog = _Watchdog()
    var l = TcpListener.bind(_lo())
    l.set_deadline(_guard())
    var child = _spawn_peer("late_send", Int(l.local_addr().port()))
    var s = l.accept().into_stream()
    if not _start_zerocopy(s):
        _ = child.kill()
        _ = child.wait()
        dog.stop()
        return
    s.set_read_deadline(_guard())
    var buf = List[UInt8](length=16, fill=0)
    var t = Instant.now()
    var cpu0 = _cpu()
    var n = s.read(Span(buf))
    var spent = _cpu() - cpu0
    var took = t.elapsed()
    dog.stop()
    s^.close()
    _ = child.wait()
    assert_equal(n, 4)
    assert_equal(String(from_utf8_lossy=Span(buf)[0:4]), "late")
    assert_true(took < _ms(3000), String("took ", took))
    assert_true(spent < _ms(100), String("spun: ", spent, " CPU"))


def test_f01_errqueue_write_all_waits_for_space() raises:
    # write_all to a slow reader with a completion pending: before the fix
    # every wait for buffer space spun at 100% CPU.
    var dog = _Watchdog(30)
    var l = TcpListener.bind(_lo())
    l.set_deadline(_guard())
    var child = _spawn_peer("slow_count", Int(l.local_addr().port()))
    var s = l.accept().into_stream()
    s.socket().set_send_buffer_size(4096)
    if not _start_zerocopy(s):
        _ = child.kill()
        _ = child.wait()
        dog.stop()
        return
    s.set_deadline(Deadline.after(Duration.from_secs(20)))
    var data = List[UInt8](length=512 * 1024, fill=7)
    var t = Instant.now()
    var cpu0 = _cpu()
    s.write_all(Span(data))
    var spent = _cpu() - cpu0
    var took = t.elapsed()
    s.shutdown(Shutdown.WRITE)
    var back = List[UInt8]()
    _ = s.read_to_end(back, 64)
    dog.stop()
    _ = child.wait()
    assert_equal(_text(back), String(100 + len(data)))
    assert_true(took > _ms(20))  # it really had to wait
    assert_true(spent * 4 < took, String("spun: ", spent, " CPU in ", took))


def test_f01_errqueue_drained_restores_plain_waits() raises:
    # The documented remedy: after reading MSG_ERRQUEUE, POLLERR is gone.
    var l = TcpListener.bind(_lo())
    l.set_deadline(_guard())
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    if not _start_zerocopy(s):
        return
    _drain_errqueue(s)
    var kind = ErrorKind.Other
    try:
        _ = wait_ready(s, Int16(0), Deadline.after(Duration.ZERO), "probe")
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.TimedOut)
    s.set_read_deadline(Deadline.after(_ms(50)))
    var buf = List[UInt8](length=8, fill=0)
    kind = ErrorKind.Other
    try:
        _ = s.read(Span(buf))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.TimedOut)
    sys.keep_alive(c)


def test_f01_shut_down_unix_listener_accept_raises() raises:
    # A shut-down AF_UNIX listener reports POLLIN|POLLHUP while accept says
    # EAGAIN: before the fix accept spun forever, even past its deadline.
    var dog = _Watchdog()
    var l = UnixListener.bind(UnixAddr.unnamed())
    var c = UnixStream.connect(l.local_addr())
    l.socket().shutdown(Shutdown.BOTH)
    # A connection queued before the shutdown is still handed out ...
    var s = l.accept().into_stream()
    s.write_all(String("hi").as_bytes())
    var buf = List[UInt8](length=2, fill=0)
    c.set_read_deadline(_guard())
    c.read_exact(Span(buf))
    assert_equal(_text(buf), "hi")
    # ... then accept fails like a shut-down TCP listener's, at once, with
    # no deadline set at all.
    var t = Instant.now()
    var kind = ErrorKind.Other
    var errno = Errno(0)
    try:
        _ = l.accept()
    except e:
        kind = e.kind
        errno = e.errno
    dog.stop()
    assert_equal(kind, ErrorKind.InvalidInput)
    assert_true(errno == Errno.EINVAL)
    assert_true(t.elapsed() < _ms(1000))


def test_f01_shut_down_tcp_listener_accept_raises() raises:
    # Parity: the kernel itself fails a shut-down TCP listener's accept.
    var l = TcpListener.bind(_lo())
    l.socket().shutdown(Shutdown.READ)
    var kind = ErrorKind.Other
    try:
        _ = l.accept()
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)


# ---- F04: read_to_end cap and deadline ---------------------------------------


def test_f04_read_to_end_default_cap_is_64mib() raises:
    # Compiles against the old signature too: before the fix it returned
    # 64 MiB + 1 bytes.
    var l = TcpListener.bind(_lo())
    l.set_deadline(_guard())
    var child = _spawn_peer(
        "send_n", Int(l.local_addr().port()), String(64 * MiB + 1)
    )
    var s = l.accept().into_stream()
    s.set_read_deadline(Deadline.after(Duration.from_secs(20)))
    var out = List[UInt8]()
    var kind = ErrorKind.Other
    try:
        _ = s.read_to_end(out)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidData)
    assert_equal(len(out), 64 * MiB)
    assert_true(out.capacity() <= 64 * MiB)
    # The byte past the cap was only peeked: it is still there, then EOF.
    var one = List[UInt8](length=4, fill=0)
    assert_equal(s.read(Span(one)), 1)
    assert_equal(Int(one[0]), ord("z"))
    assert_equal(s.read(Span(one)), 0)
    _ = child.wait()


def test_f04_read_to_end_explicit_cap() raises:
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    a.set_read_deadline(_guard())
    # Exactly at the cap, then EOF: success.
    b.write_all(String("0123456789").as_bytes())
    b.shutdown(Shutdown.WRITE)
    var out = List[UInt8]()
    assert_equal(a.read_to_end(out, 10), 10)
    assert_equal(_text(out), "0123456789")

    var q = UnixStream.pair()
    var x = q.first.take()
    var y = q.second.take()
    x.set_read_deadline(_guard())
    y.write_all(String("0123456789ABCDE").as_bytes())
    y^.close()
    var got: List[UInt8] = [UInt8(ord(">"))]  # an existing prefix stays
    var kind = ErrorKind.Other
    var op = String()
    try:
        _ = x.read_to_end(got, 10)
    except e:
        kind = e.kind
        op = String(e.op)
    assert_equal(kind, ErrorKind.InvalidData)
    assert_equal(op, "read")
    assert_equal(_text(got), ">0123456789")
    # No speculative 8 KiB chunk past the cap.
    assert_true(got.capacity() < 1024, String(got.capacity()))
    var rest = List[UInt8](length=16, fill=0)
    assert_equal(x.read(Span(rest)), 5)
    assert_equal(String(from_utf8_lossy=Span(rest)[0:5]), "ABCDE")

    # Zero cap: EOF is fine, any byte is too many; negative is a caller bug.
    var r = UnixStream.pair()
    var m = r.first.take()
    var n = r.second.take()
    m.set_read_deadline(_guard())
    n.write_all(String("!").as_bytes())
    kind = ErrorKind.Other
    try:
        _ = m.read_to_end(out, 0)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidData)
    kind = ErrorKind.Other
    try:
        _ = m.read_to_end(out, -1)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)
    var one = List[UInt8](length=1, fill=0)
    assert_equal(m.read(Span(one)), 1)
    n^.close()
    var before = len(out)
    assert_equal(m.read_to_end(out, 0), 0)
    assert_equal(len(out), before)


def test_f04_read_to_end_checks_deadline_between_chunks() raises:
    # 64 KiB are queued, so every recv could make progress without blocking:
    # before the fix an expired deadline did not stop the loop until the
    # queue ran dry. Now only the first chunk (8 KiB) is read.
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    var data = List[UInt8](length=64 * 1024, fill=1)
    b.set_write_deadline(_guard())
    b.write_all(Span(data))
    a.set_read_deadline(Deadline.after(Duration.ZERO))
    var out = List[UInt8]()
    var kind = ErrorKind.Other
    try:
        _ = a.read_to_end(out, Int.MAX)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(len(out) > 0, "the first recv still runs (readiness wins)")
    assert_true(len(out) < len(data), String("read ", len(out)))
    # Nothing was lost: the rest is still queued.
    a.set_read_deadline(_guard())
    b^.close()
    var rest = List[UInt8]()
    assert_equal(a.read_to_end(rest), len(data) - len(out))


def test_f04_read_to_end_large_stream_with_cap_off() raises:
    # Int.MAX removes the cap (and the capacity math must not overflow).
    var l = TcpListener.bind(_lo())
    l.set_deadline(_guard())
    var child = _spawn_peer(
        "send_n", Int(l.local_addr().port()), String(3 * MiB + 17)
    )
    var s = l.accept().into_stream()
    s.set_read_deadline(Deadline.after(Duration.from_secs(20)))
    var out = List[UInt8]()
    assert_equal(s.read_to_end(out, Int.MAX), 3 * MiB + 17)
    assert_equal(len(out), 3 * MiB + 17)
    assert_equal(Int(out[len(out) - 1]), ord("z"))
    _ = child.wait()


# ---- F19: from_socket validates what it adopts --------------------------------


def _kind_op(e: IoError) -> String:
    return String(e.kind, " ", e.op)


def test_f19_tcp_listener_rejects_unix_listener_without_consuming() raises:
    var raw = Socket.new(Domain.UNIX, SockType.STREAM)
    raw.bind_unix(UnixAddr.unnamed())
    raw.listen(4)
    var addr = raw.local_unix_addr()
    var c = UnixStream.connect(addr)
    var got = String()
    try:
        _ = TcpListener.from_socket(raw.try_clone())
    except e:
        got = _kind_op(e)
    assert_equal(got, "InvalidInput TcpListener.from_socket")
    # The connection is still queued: the right wrapper accepts it.
    var l = UnixListener.from_socket(raw^)
    l.set_deadline(_guard())
    var s = l.accept().into_stream()
    s.write_all(String("ok").as_bytes())
    var buf = List[UInt8](length=2, fill=0)
    c.set_read_deadline(_guard())
    c.read_exact(Span(buf))
    assert_equal(_text(buf), "ok")


def test_f19_from_socket_rejects_wrong_family_type_or_state() raises:
    var tcp_l = Socket.new(Domain.IPV4, SockType.STREAM)
    tcp_l.bind(_lo())
    tcp_l.listen(4)
    var port_addr = tcp_l.local_addr()
    var got = String()

    try:
        _ = UnixListener.from_socket(tcp_l.try_clone())
    except e:
        got = _kind_op(e)
    assert_equal(got, "InvalidInput UnixListener.from_socket")

    got = String()
    try:
        _ = TcpStream.from_socket(tcp_l.try_clone())
    except e:
        got = _kind_op(e)
    assert_equal(got, "InvalidInput TcpStream.from_socket")

    got = String()
    try:
        _ = TcpListener.from_socket(Socket.new(Domain.IPV4, SockType.DGRAM))
    except e:
        got = _kind_op(e)
    assert_equal(got, "InvalidInput TcpListener.from_socket")

    got = String()
    var unl = Socket.new(Domain.IPV4, SockType.STREAM)
    unl.bind(_lo())
    try:  # bound but never listened
        _ = TcpListener.from_socket(unl^)
    except e:
        got = _kind_op(e)
    assert_equal(got, "InvalidInput TcpListener.from_socket")

    var tcp_c = Socket.new(Domain.IPV4, SockType.STREAM)
    tcp_c.connect(port_addr)
    got = String()
    try:
        _ = UnixStream.from_socket(tcp_c^)
    except e:
        got = _kind_op(e)
    assert_equal(got, "InvalidInput UnixStream.from_socket")

    var pr = Socket.pair(Domain.UNIX, SockType.STREAM)
    got = String()
    try:
        _ = TcpStream.from_socket(pr.first.take())
    except e:
        got = _kind_op(e)
    assert_equal(got, "InvalidInput TcpStream.from_socket")

    var sp = Socket.pair(Domain.UNIX, SockType.SEQPACKET)
    got = String()
    try:
        _ = UnixStream.from_socket(sp.first.take())
    except e:
        got = _kind_op(e)
    assert_equal(got, "InvalidInput UnixStream.from_socket")

    # Not a socket at all.
    var fds = Array[Int32, 2](fill=-1)
    _ = check("pipe2", sys.pipe2(fds, O_CLOEXEC))
    var w = OwnedFd(unsafe_from_raw=fds[1])
    var errno = Errno(0)
    got = String()
    try:
        _ = TcpStream.from_socket(Socket(OwnedFd(unsafe_from_raw=fds[0])))
    except e:
        got = _kind_op(e)
        errno = e.errno
    assert_equal(got, "InvalidInput TcpStream.from_socket")
    assert_true(errno == Errno.ENOTSOCK)
    sys.keep_alive(w)
    sys.keep_alive(tcp_l)


# ---- F21: adopted descriptors become CLOEXEC ----------------------------------


def test_f21_from_socket_sets_cloexec() raises:
    var raw_l = Socket.new(Domain.IPV4, SockType.STREAM)
    raw_l.bind(_lo())
    raw_l.listen(4)
    _clear_cloexec(raw_l)  # as inherited across exec
    var l = TcpListener.from_socket(raw_l^)
    assert_true((_fd_flags(l) & FD_CLOEXEC) != 0)
    l.set_deadline(_guard())

    var raw_c = Socket.new(Domain.IPV4, SockType.STREAM)
    raw_c.connect(l.local_addr())
    _clear_cloexec(raw_c)
    var c = TcpStream.from_socket(raw_c^)
    assert_true((_fd_flags(c) & FD_CLOEXEC) != 0)
    assert_true(c.socket().nonblocking())

    var raw_ul = Socket.new(Domain.UNIX, SockType.STREAM)
    raw_ul.bind_unix(UnixAddr.unnamed())
    raw_ul.listen(4)
    _clear_cloexec(raw_ul)
    var ul = UnixListener.from_socket(raw_ul^)
    assert_true((_fd_flags(ul) & FD_CLOEXEC) != 0)

    var pr = Socket.pair(Domain.UNIX, SockType.STREAM)
    var end = pr.first.take()
    _clear_cloexec(end)
    var us = UnixStream.from_socket(end^)
    assert_true((_fd_flags(us) & FD_CLOEXEC) != 0)
    sys.keep_alive(pr)
    sys.keep_alive(l)  # the listener must outlive the connect above


# ---- F35: shutdown(READ) semantics as documented -------------------------------


def test_f35_tcp_shutdown_read_delivers_queued_and_later_data() raises:
    var l = TcpListener.bind(_lo())
    l.set_deadline(_guard())
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    s.set_read_deadline(_guard())
    c.write_all(String("before").as_bytes())
    var buf = List[UInt8](length=16, fill=0)
    # Let "before" arrive, then shut the read side.
    _ = s.peek(Span(buf))
    s.shutdown(Shutdown.READ)
    assert_equal(s.read(Span(buf)), 6)  # queued data is not discarded
    assert_equal(String(from_utf8_lossy=Span(buf)[0:6]), "before")
    var t = Instant.now()
    assert_equal(s.read(Span(buf)), 0)  # empty: 0 at once, no waiting
    assert_true(t.elapsed() < _ms(1000))
    # The peer is not told: its writes succeed, and the data is delivered.
    assert_equal(c.write(String("after").as_bytes()), 5)
    var got = 0
    var t2 = Instant.now()
    while got == 0 and t2.elapsed() < Duration.from_secs(5):
        got = s.read(Span(buf))
    assert_equal(got, 5)
    assert_equal(String(from_utf8_lossy=Span(buf)[0:5]), "after")


def test_f35_unix_shutdown_read_breaks_peer_writes() raises:
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    a.set_read_deadline(_guard())
    b.write_all(String("queued").as_bytes())
    a.shutdown(Shutdown.READ)
    var buf = List[UInt8](length=16, fill=0)
    assert_equal(a.read(Span(buf)), 6)
    assert_equal(String(from_utf8_lossy=Span(buf)[0:6]), "queued")
    assert_equal(a.read(Span(buf)), 0)
    var kind = ErrorKind.Other
    try:
        _ = b.write(String("x").as_bytes())
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.BrokenPipe)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
