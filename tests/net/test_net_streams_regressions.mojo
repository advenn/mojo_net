"""Regression tests for the second net review (blocking streams).

- S1: a wait that kept reporting readiness while the syscall could not
  progress spun at full CPU until the deadline (forever without one): an
  AF_UNIX peek when the only queued byte is out-of-band data. Such waits now
  go edge-triggered after the first wakeup that let nothing progress.
- S2: a `UnixListener` shut down with SHUT_RD reports POLLIN|POLLRDHUP and
  no POLLHUP, and its accept spun (the F01 fix covered SHUT_RDWR only). It
  now raises `InvalidInput` (EINVAL) at once, like a blocking accept.
- S3: a `UnixStream` writer waiting for room was not woken when its send
  side was shut down (by the peer's SHUT_RD, or by another handle's
  SHUT_WR): AF_UNIX reports nothing then, while the send answers EPIPE. The
  wait is now cut into slices with a send in between, so it raises
  `BrokenPipe`, as TCP does.
"""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_true

from linux import ErrorKind
from linux.abi import Timespec
from linux.consts import MSG_OOB
from linux.time import Deadline, Duration, Instant, clock_gettime
from net.addr import UnixAddr
from net.socket import Shutdown
from net.unix import UnixListener, UnixStream

comptime _CLOCK_THREAD_CPUTIME_ID = 3


def _cpu() -> Duration:
    """CPU time used by this thread so far."""
    var ts = Timespec(0, 0)
    _ = clock_gettime(_CLOCK_THREAD_CPUTIME_ID, ts)
    return Duration.from_timespec(ts)


def _ms(n: Int) -> Duration:
    return Duration.from_millis(n)


def _send_oob(s: UnixStream) raises -> Bool:
    """Queue one out-of-band byte; False where AF_UNIX has no MSG_OOB
    (a kernel without CONFIG_AF_UNIX_OOB)."""
    var x = List[UInt8](length=1, fill=88)
    try:
        _ = s.socket().send_with_flags(Span(x), MSG_OOB)
        return True
    except:
        print("    (skipped: AF_UNIX MSG_OOB unsupported on this kernel)")
        return False


# ---- S1 ------------------------------------------------------------------------


def test_s1_peek_behind_out_of_band_data_waits_without_spinning() raises:
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    if not _send_oob(a):
        return
    b.set_read_deadline(Deadline.after(_ms(1000)))
    var buf = List[UInt8](length=16, fill=0)
    var c0 = _cpu()
    var kind = ErrorKind.Other
    try:
        _ = b.peek(Span(buf))
    except e:
        kind = e.kind
    var used = _cpu() - c0
    assert_equal(kind, ErrorKind.TimedOut)
    # It burned the whole second before the fix.
    assert_true(used < _ms(200), String("peek used ", used, " of CPU"))
    # The stream still works: ordinary data arrives and is peeked.
    a.write_all(String("hello").as_bytes())
    b.set_read_deadline(Deadline.after(_ms(5000)))
    var n = b.peek(Span(buf))
    assert_true(n >= 1)


def test_s1_read_to_end_at_its_cap_behind_out_of_band_data() raises:
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    a.write_all(String("abcd").as_bytes())  # (exactly the cap)
    if not _send_oob(a):
        return
    b.set_read_deadline(Deadline.after(_ms(1000)))
    var out = List[UInt8]()
    var c0 = _cpu()
    var kind = ErrorKind.Other
    try:
        _ = b.read_to_end(out, max_bytes=4)  # (peeks once at the cap)
    except e:
        kind = e.kind
    var used = _cpu() - c0
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(used < _ms(200), String("read_to_end used ", used, " of CPU"))
    _ = a^  # (alive until here: closing it would end the stream instead)


# ---- S2 ------------------------------------------------------------------------


def test_s2_unix_listener_shut_down_for_reading_ends_accept() raises:
    var l = UnixListener.bind(UnixAddr.unnamed())
    l.socket().shutdown(Shutdown.READ)
    l.set_deadline(Deadline.after(_ms(3000)))
    var t = Instant.now()
    var c0 = _cpu()
    var kind = ErrorKind.Other
    try:
        _ = l.accept()
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)  # (TimedOut, after spinning, before)
    assert_true(t.elapsed() < _ms(1000))
    assert_true(_cpu() - c0 < _ms(200))


# ---- S3 ------------------------------------------------------------------------

comptime _PEER = (
    "import socket, sys, time\n"
    "s = socket.socket(fileno=int(sys.argv[1]))\n"
    "time.sleep(0.3)\n"
    "s.shutdown(socket.SHUT_RD if sys.argv[2] == 'rd' else socket.SHUT_WR)\n"
    "time.sleep(10)\n"
)


def _shutdown_later(fd: Int32, how: String) raises -> PythonObject:
    """A child process that shuts down the socket `fd` (shared with it) after
    0.3 s: its read side ("rd") or its write side ("wr")."""
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    return subprocess.Popen(
        Python.list(pysys.executable, "-c", _PEER, String(fd), how),
        pass_fds=Python.tuple(Int(fd)),
    )


def _blocked_writer_sees_the_shutdown(how: String) raises:
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    var chunk = List[UInt8](length=65536, fill=1)
    while a.try_write(Span(chunk)):
        pass  # (fill the buffers: the next write must wait)
    # "rd": the peer stops reading. "wr": another handle of our own socket
    # shuts down our write side.
    var child = _shutdown_later(b.raw_fd() if how == "rd" else a.raw_fd(), how)
    a.set_write_deadline(Deadline.after(_ms(5000)))
    var t = Instant.now()
    var kind = ErrorKind.Other
    try:
        a.write_all(Span(chunk))
    except e:
        kind = e.kind
    var took = t.elapsed()
    _ = child.kill()
    _ = child.wait()
    assert_equal(kind, ErrorKind.BrokenPipe, how)  # (TimedOut after 5 s before)
    assert_true(took < _ms(2000), String(how, ": took ", took))
    _ = b^


def test_s3_unix_writer_sees_the_peer_stop_reading() raises:
    _blocked_writer_sees_the_shutdown("rd")


def test_s3_unix_writer_sees_its_write_side_shut_by_another_handle() raises:
    _blocked_writer_sees_the_shutdown("wr")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
