"""Deterministic regression tests for F01 (net-blocking review) through the
syscall fault seam (built with -D MOJO_TCP_FAULTS=1 because of the
`_faults.mojo` suffix).

F01: every net.blocking retry loop was `syscall -> EAGAIN -> wait -> retry`
with the deadline consulted only when ppoll itself timed out. Readiness that
ppoll keeps reporting while the syscall keeps saying EAGAIN therefore spun
forever, past any deadline. Two ways to get there:
- Injected EAGAIN on a socket that really is ready (data queued, buffer
  space, a pending connection): ppoll returns at once, the syscall "fails".
  With an already expired deadline, the loop must now stop after exactly
  one wakeup that let nothing progress: 2 syscalls, 1 ppoll. Before the fix
  it ran through every injected EAGAIN and then succeeded.
- A real MSG_ZEROCOPY completion on the error queue (POLLERR, SO_ERROR 0):
  exact counts show the switch to one private edge-triggered epoll instance
  and that the wait then really blocks. Before the fix: an endless
  ppoll/recv loop (`_Watchdog` turns that into a failed run).

Each test calls `fault.clear()` right before the operation under test.
"""

from std.testing import TestSuite, assert_equal, assert_true

from linux import Errno, ErrorKind, IoError, check, fault
from linux import sys
from linux.consts import (
    CLOCK_MONOTONIC,
    MSG_ZEROCOPY,
    POLLERR,
    POLLIN,
    POLLOUT,
    SIGALRM,
    SIGEV_THREAD_ID,
    SO_ZEROCOPY,
    SOL_SOCKET,
)
from linux.nr import (
    SYS_accept4,
    SYS_epoll_create1,
    SYS_epoll_ctl,
    SYS_epoll_pwait,
    SYS_epoll_pwait2,
    SYS_gettid,
    SYS_ppoll,
    SYS_recvfrom,
    SYS_recvmsg,
    SYS_sendmsg,
    SYS_sendto,
    SYS_timer_create,
    SYS_timer_delete,
    SYS_timer_settime,
)
from linux.poll import wait_ready
from linux.syscall import syscall0, syscall1, syscall3, syscall4
from linux.time import Deadline, Duration, Instant
from net.addr import SocketAddr
from net.tcp import TcpListener, TcpStream


def _guard() -> Deadline:
    return Deadline.after(Duration.from_secs(10))


def _expired() -> Deadline:
    return Deadline.after(Duration.ZERO)


@fieldwise_init
struct _Conn(Movable):
    var l: TcpListener
    var c: TcpStream
    var s: TcpStream


def _conn() raises -> _Conn:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    l.set_deadline(_guard())
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    c.set_deadline(_guard())
    s.set_deadline(_guard())
    return _Conn(l^, c^, s^)


def _readable(conn: _Conn) raises:
    """Queue one byte for `conn.s` and wait until it is readable."""
    conn.c.write_all(String("x").as_bytes())
    _ = wait_ready(conn.s, Int16(POLLIN), _guard(), "setup")


struct _Watchdog:
    """SIGALRM (default action: terminate) unless `stop()` runs in time."""

    var timer: Int32

    def __init__(out self, secs: Int = 20) raises:
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
        var spec = Array[Int, 4](fill=0)
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


def _kind_of_timed_out(kind: ErrorKind) raises:
    assert_true(kind == ErrorKind.TimedOut, String("got ", kind))


# ---- injected EAGAIN on a ready socket ----------------------------------------


def test_read_spurious_readiness_stops_at_expired_deadline() raises:
    var conn = _conn()
    _readable(conn)
    conn.s.set_read_deadline(_expired())
    var buf = List[UInt8](length=8, fill=0)
    fault.clear()
    fault.inject(SYS_recvfrom, Errno.EAGAIN, times=1000)
    var kind = ErrorKind.Other
    try:
        _ = conn.s.read(Span(buf))
    except e:
        kind = e.kind
    var recvs = fault.calls(SYS_recvfrom)
    var polls = fault.calls(SYS_ppoll)
    fault.clear()
    _kind_of_timed_out(kind)
    assert_equal(recvs, 2)  # try, wait (ready at once), retry: no progress
    assert_equal(polls, 1)
    # Nothing was consumed.
    conn.s.set_read_deadline(_guard())
    assert_equal(conn.s.read(Span(buf)), 1)


def test_peek_and_read_exact_spurious_readiness() raises:
    var conn = _conn()
    _readable(conn)
    conn.s.set_read_deadline(_expired())
    var buf = List[UInt8](length=1, fill=0)
    fault.clear()
    fault.inject(SYS_recvfrom, Errno.EAGAIN, times=1000)
    var kind = ErrorKind.Other
    try:
        _ = conn.s.peek(Span(buf))
    except e:
        kind = e.kind
    _kind_of_timed_out(kind)
    assert_equal(fault.calls(SYS_recvfrom), 2)
    fault.clear()
    fault.inject(SYS_recvfrom, Errno.EAGAIN, times=1000)
    kind = ErrorKind.Other
    try:
        conn.s.read_exact(Span(buf))
    except e:
        kind = e.kind
    _kind_of_timed_out(kind)
    assert_equal(fault.calls(SYS_recvfrom), 2)
    fault.clear()
    fault.inject(SYS_recvfrom, Errno.EAGAIN, times=1000)
    kind = ErrorKind.Other
    var out = List[UInt8]()
    try:
        _ = conn.s.read_to_end(out)
    except e:
        kind = e.kind
    _kind_of_timed_out(kind)
    assert_equal(fault.calls(SYS_recvfrom), 2)
    assert_equal(len(out), 0)
    fault.clear()


def test_write_spurious_readiness_stops_at_expired_deadline() raises:
    var conn = _conn()
    conn.s.set_write_deadline(_expired())
    fault.clear()
    fault.inject(SYS_sendto, Errno.EAGAIN, times=1000)
    var kind = ErrorKind.Other
    try:
        _ = conn.s.write(String("abc").as_bytes())
    except e:
        kind = e.kind
    var sends = fault.calls(SYS_sendto)
    var polls = fault.calls(SYS_ppoll)
    fault.clear()
    _kind_of_timed_out(kind)
    assert_equal(sends, 2)
    assert_equal(polls, 1)
    fault.inject(SYS_sendto, Errno.EAGAIN, times=1000)
    kind = ErrorKind.Other
    try:
        conn.s.write_all(String("abc").as_bytes())
    except e:
        kind = e.kind
    _kind_of_timed_out(kind)
    assert_equal(fault.calls(SYS_sendto), 2)
    fault.clear()


def test_vectored_spurious_readiness_stops_at_expired_deadline() raises:
    var conn = _conn()
    _readable(conn)
    conn.s.set_deadline(_expired())
    var a = List[UInt8](length=4, fill=0)
    var mspans = List[Span[UInt8, origin_of(a)]]()
    mspans.append(a)
    fault.clear()
    fault.inject(SYS_recvmsg, Errno.EAGAIN, times=1000)
    var kind = ErrorKind.Other
    try:
        _ = conn.s.read_vectored(mspans)
    except e:
        kind = e.kind
    _kind_of_timed_out(kind)
    assert_equal(fault.calls(SYS_recvmsg), 2)
    assert_equal(fault.calls(SYS_ppoll), 1)
    fault.clear()
    var hello = List[UInt8](length=5, fill=104)
    var spans = List[Span[UInt8, origin_of(hello)]]()
    spans.append(hello)
    fault.inject(SYS_sendmsg, Errno.EAGAIN, times=1000)
    kind = ErrorKind.Other
    try:
        _ = conn.s.write_vectored(Span(spans))
    except e:
        kind = e.kind
    _kind_of_timed_out(kind)
    assert_equal(fault.calls(SYS_sendmsg), 2)
    assert_equal(fault.calls(SYS_ppoll), 1)
    fault.clear()


def test_accept_spurious_readiness_stops_at_expired_deadline() raises:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = TcpStream.connect(l.local_addr())
    _ = wait_ready(l, Int16(POLLIN), _guard(), "setup")
    l.set_deadline(_expired())
    fault.clear()
    fault.inject(SYS_accept4, Errno.EAGAIN, times=1000)
    var kind = ErrorKind.Other
    try:
        _ = l.accept()
    except e:
        kind = e.kind
    var accepts = fault.calls(SYS_accept4)
    var polls = fault.calls(SYS_ppoll)
    fault.clear()
    _kind_of_timed_out(kind)
    assert_equal(accepts, 2)
    assert_equal(polls, 1)
    # The connection is still queued.
    l.set_deadline(_guard())
    var s = l.accept().into_stream()
    sys.keep_alive(c)
    sys.keep_alive(s)


# ---- a real error-queue POLLERR -------------------------------------------------


def _start_zerocopy(conn: _Conn) raises -> Bool:
    try:
        conn.s.socket().set_option_int(SOL_SOCKET, SO_ZEROCOPY, 1)
    except e:
        print("    skip: SO_ZEROCOPY unsupported:", e)
        return False
    var payload = List[UInt8](length=100, fill=65)
    assert_equal(
        conn.s.socket().send_with_flags(Span(payload), MSG_ZEROCOPY), 100
    )
    var rev = wait_ready(conn.s, Int16(0), _guard(), "errqueue")
    assert_true((Int(rev) & POLLERR) != 0)
    _ = payload^
    return True


def test_errqueue_read_switches_to_edge_triggered_wait() raises:
    var dog = _Watchdog()
    var conn = _conn()
    if not _start_zerocopy(conn):
        dog.stop()
        return
    conn.s.set_read_deadline(Deadline.after(Duration.from_millis(200)))
    var buf = List[UInt8](length=8, fill=0)
    fault.clear()
    var t = Instant.now()
    var kind = ErrorKind.Other
    try:
        _ = conn.s.read(Span(buf))
    except e:
        kind = e.kind
    var took = t.elapsed()
    var recvs = fault.calls(SYS_recvfrom)
    var polls = fault.calls(SYS_ppoll)
    var creates = fault.calls(SYS_epoll_create1)
    var ctls = fault.calls(SYS_epoll_ctl)
    var waits = fault.calls(SYS_epoll_pwait2) + fault.calls(SYS_epoll_pwait)
    fault.clear()
    dog.stop()
    _kind_of_timed_out(kind)
    assert_true(took >= Duration.from_millis(200))
    # try -> ppoll (POLLERR only) -> retry, EAGAIN: switch -> epoll_create1,
    # epoll_ctl(ADD) -> wait (reports the current POLLERR once) -> retry,
    # EAGAIN -> wait blocks until the deadline. Slack for stray wakeups.
    assert_equal(polls, 1)
    assert_equal(creates, 1)
    assert_equal(ctls, 1)
    assert_true(recvs >= 3 and recvs <= 5, String("recvs ", recvs))
    assert_true(waits >= 2 and waits <= 4, String("waits ", waits))


def test_errqueue_write_switches_to_edge_triggered_wait() raises:
    var dog = _Watchdog()
    var conn = _conn()
    conn.s.socket().set_send_buffer_size(4096)
    if not _start_zerocopy(conn):
        dog.stop()
        return
    # Fill the send path (the client never reads) until a write would block.
    var junk = List[UInt8](length=64 * 1024, fill=1)
    conn.s.set_write_deadline(_expired())
    try:
        while True:
            _ = conn.s.write(Span(junk))
    except e:
        assert_true(e.kind == ErrorKind.TimedOut, String(e))
    conn.s.set_write_deadline(Deadline.after(Duration.from_millis(200)))
    fault.clear()
    var kind = ErrorKind.Other
    try:
        conn.s.write_all(Span(junk))
    except e:
        kind = e.kind
    var polls = fault.calls(SYS_ppoll)
    var creates = fault.calls(SYS_epoll_create1)
    var sends = fault.calls(SYS_sendto)
    fault.clear()
    dog.stop()
    _kind_of_timed_out(kind)
    assert_true(polls <= 2, String("polls ", polls))
    assert_equal(creates, 1)
    assert_true(sends <= 8, String("sends ", sends))


def test_errqueue_edge_setup_failure_is_reported() raises:
    # No descriptor left for the epoll instance: the read reports it (tagged
    # with its op) instead of spinning.
    var dog = _Watchdog()
    var conn = _conn()
    if not _start_zerocopy(conn):
        dog.stop()
        return
    var buf = List[UInt8](length=8, fill=0)
    fault.clear()
    fault.inject(SYS_epoll_create1, Errno.EMFILE)
    var kind = ErrorKind.Other
    var op = String()
    try:
        _ = conn.s.read(Span(buf))
    except e:
        kind = e.kind
        op = String(e.op)
    var recvs = fault.calls(SYS_recvfrom)
    var polls = fault.calls(SYS_ppoll)
    fault.clear()
    dog.stop()
    assert_true(kind == ErrorKind.TooManyFiles, String(kind))
    assert_equal(op, "read")
    assert_equal(recvs, 2)
    assert_equal(polls, 1)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
