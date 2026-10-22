"""Deterministic error paths of net.tcp and net.unix via the syscall fault
seam (built with -D MOJO_NET_FAULTS=1 because of the `_faults.mojo` suffix).

An injected error is returned *without* issuing the syscall, so nothing
happens in the kernel: an injected EAGAIN on recv consumes nothing, an
injected EINTR on connect means the kernel never saw the connect. Exact
`fault.calls(nr)` counts prove how often L2 retried. net.unix shares the
engine in net.tcp, so its fault paths are covered here too (its AF_UNIX
specific connect rule included).

The plan is process-global and every test runs in one process. Each test
therefore calls `fault.clear()` twice: first thing, so rules left armed by
an earlier test that failed midway cannot break this test's setup (and
blame it), and again right before the operation under test, so setup
syscalls are not counted.
"""

from std.os import listdir
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Errno, ErrorKind, IoError, fault, sys
from linux.nr import (
    SYS_accept4,
    SYS_connect,
    SYS_getpeername,
    SYS_getpid,
    SYS_ppoll,
    SYS_recvfrom,
    SYS_recvmsg,
    SYS_sendmsg,
    SYS_sendto,
    SYS_setsockopt,
    SYS_socket,
)
from linux.syscall import syscall0
from linux.time import Deadline, Duration
from net.addr import SocketAddr, UnixAddr
from net.tcp import TcpListener, TcpStream
from net.unix import UnixListener, UnixStream


def _guard() -> Deadline:
    return Deadline.after(Duration.from_secs(10))


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


def _bytes(s: StringSlice) -> List[UInt8]:
    var out = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        out.append(b)
    return out^


def _text(buf: List[UInt8], n: Int) -> String:
    return String(from_utf8_lossy=Span(buf)[0:n])


def _fd_count() raises -> Int:
    return len(listdir("/proc/self/fd"))


def _abstract(tag: StaticString) raises IoError -> UnixAddr:
    """An abstract name unique to this process (tests may run in parallel)."""
    return UnixAddr.from_abstract_name(
        String("mojo_net_faults_", syscall0(SYS_getpid), "_", tag)
    )


# ---- read --------------------------------------------------------------------


def test_read_retries_eintr() raises:
    fault.clear()
    var conn = _conn()
    conn.s.write_all(String("hi").as_bytes())
    var buf = List[UInt8](length=8, fill=0)
    fault.clear()
    fault.inject(SYS_recvfrom, Errno.EINTR, times=2)
    assert_equal(conn.c.read(Span(buf)), 2)
    assert_equal(fault.calls(SYS_recvfrom), 3)
    assert_equal(fault.pending(), 0)
    assert_equal(_text(buf, 2), "hi")


def test_read_eagain_waits_then_retries() raises:
    fault.clear()
    var conn = _conn()
    conn.s.write_all(String("data").as_bytes())
    var buf = List[UInt8](length=8, fill=0)
    fault.clear()
    fault.inject(SYS_recvfrom, Errno.EAGAIN, times=1)
    assert_equal(conn.c.read(Span(buf)), 4)
    assert_equal(fault.calls(SYS_recvfrom), 2)
    assert_equal(fault.calls(SYS_ppoll), 1)  # data was there: one quick poll


def test_peek_retries_eintr_and_keeps_data() raises:
    fault.clear()
    var conn = _conn()
    conn.s.write_all(String("xyz").as_bytes())
    var buf = List[UInt8](length=8, fill=0)
    fault.clear()
    fault.inject(SYS_recvfrom, Errno.EINTR, times=1)
    assert_equal(conn.c.peek(Span(buf)), 3)
    assert_equal(fault.calls(SYS_recvfrom), 2)
    assert_equal(conn.c.read(Span(buf)), 3)
    assert_equal(_text(buf, 3), "xyz")


def test_read_exact_zero_byte_recv_is_unexpected_eof() raises:
    fault.clear()
    var conn = _conn()
    conn.s.write_all(String("abc").as_bytes())
    var buf = List[UInt8](length=3, fill=0)
    fault.clear()
    fault.inject_short(SYS_recvfrom, 0, times=1)  # looks like EOF
    var kind = ErrorKind.Other
    try:
        conn.c.read_exact(Span(buf))
    except e:
        kind = e.kind
        assert_equal(String(e.op), "read")
    assert_equal(kind, ErrorKind.UnexpectedEof)


def test_read_exact_loops_over_short_reads() raises:
    fault.clear()
    var conn = _conn()
    conn.s.write_all(String("0123456789").as_bytes())
    var buf = List[UInt8](length=10, fill=0)
    fault.clear()
    fault.inject_short(SYS_recvfrom, 3, times=-1)
    conn.c.read_exact(Span(buf))
    assert_equal(fault.calls(SYS_recvfrom), 4)  # 3 + 3 + 3 + 1
    assert_equal(_text(buf, 10), "0123456789")


def test_poll_failure_raises_with_operation_name() raises:
    fault.clear()
    var conn = _conn()
    var buf = List[UInt8](length=8, fill=0)
    fault.clear()
    fault.inject(SYS_ppoll, Errno.ENOMEM, times=1)
    var kind = ErrorKind.Other
    try:
        _ = conn.c.read(Span(buf))
    except e:
        kind = e.kind
        assert_equal(String(e.op), "read")
        assert_equal(e.errno, Errno.ENOMEM)
    assert_equal(kind, ErrorKind.OutOfMemory)


def test_recv_errors_are_classified() raises:
    fault.clear()
    var conn = _conn()
    var buf = List[UInt8](length=8, fill=0)
    fault.clear()
    fault.inject(SYS_recvfrom, Errno.ECONNRESET, times=1)
    var kind = ErrorKind.Other
    try:
        _ = conn.c.read(Span(buf))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.ConnectionReset)
    assert_equal(fault.calls(SYS_recvfrom), 1)  # errors are not retried


# ---- write -------------------------------------------------------------------


def test_write_all_loops_over_short_sends() raises:
    fault.clear()
    var conn = _conn()
    fault.clear()
    fault.inject_short(SYS_sendto, 3, times=-1)
    conn.c.write_all(String("hello world!!").as_bytes())  # 13 bytes
    assert_equal(fault.calls(SYS_sendto), 5)  # 3+3+3+3+1
    fault.clear()
    var buf = List[UInt8](length=13, fill=0)
    conn.s.read_exact(Span(buf))
    assert_equal(_text(buf, 13), "hello world!!")


def test_write_all_zero_progress_raises_write_zero() raises:
    fault.clear()
    var conn = _conn()
    fault.clear()
    fault.inject_short(SYS_sendto, 0, times=1)
    var kind = ErrorKind.Other
    try:
        conn.c.write_all(String("abc").as_bytes())
    except e:
        kind = e.kind
        assert_equal(String(e.op), "write")
    assert_equal(kind, ErrorKind.WriteZero)
    assert_equal(fault.calls(SYS_sendto), 1)  # no spinning


def test_write_retries_eintr_and_eagain() raises:
    fault.clear()
    var conn = _conn()
    fault.clear()
    fault.inject(SYS_sendto, Errno.EINTR, times=1)
    fault.inject(SYS_sendto, Errno.EAGAIN, skip=1, times=1)
    assert_equal(conn.c.write(String("ok").as_bytes()), 2)
    assert_equal(fault.calls(SYS_sendto), 3)
    assert_equal(fault.calls(SYS_ppoll), 1)  # only EAGAIN waits
    assert_equal(fault.pending(), 0)
    var buf = List[UInt8](length=2, fill=0)
    conn.s.read_exact(Span(buf))
    assert_equal(_text(buf, 2), "ok")


def test_send_errors_are_classified() raises:
    fault.clear()
    var conn = _conn()
    fault.clear()
    fault.inject(SYS_sendto, Errno.EPIPE, times=1)
    var kind = ErrorKind.Other
    try:
        conn.c.write_all(String("x").as_bytes())
    except e:
        kind = e.kind
        assert_equal(String(e.op), "write")
    assert_equal(kind, ErrorKind.BrokenPipe)
    fault.clear()
    fault.inject(SYS_sendto, Errno.ECONNRESET, times=1)
    kind = ErrorKind.Other
    try:
        _ = conn.c.write(String("x").as_bytes())
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.ConnectionReset)


def test_vectored_io_retries_eintr_and_eagain() raises:
    fault.clear()
    var conn = _conn()
    var a = _bytes("head:")
    var b = _bytes("body")
    var bufs = List[Span[UInt8, origin_of(a, b)]]()
    bufs.append(a)
    bufs.append(b)
    fault.clear()
    fault.inject(SYS_sendmsg, Errno.EAGAIN, times=1)
    fault.inject(SYS_sendmsg, Errno.EINTR, skip=1, times=1)
    assert_equal(conn.c.write_vectored(Span(bufs)), 9)
    assert_equal(fault.calls(SYS_sendmsg), 3)
    var x = List[UInt8](length=5, fill=0)
    var y = List[UInt8](length=4, fill=0)
    var rbufs = List[Span[UInt8, origin_of(x, y)]]()
    rbufs.append(x)
    rbufs.append(y)
    fault.clear()
    fault.inject(SYS_recvmsg, Errno.EINTR, times=1)
    assert_equal(conn.s.read_vectored(rbufs), 9)
    assert_equal(fault.calls(SYS_recvmsg), 2)
    assert_equal(_text(x, 5), "head:")
    assert_equal(_text(y, 4), "body")
    # Errors keep their kind but carry the L2 operation name.
    fault.clear()
    fault.inject(SYS_sendmsg, Errno.EPIPE, times=1)
    var kind = ErrorKind.Other
    try:
        _ = conn.c.write_vectored(Span(bufs))
    except e:
        kind = e.kind
        assert_equal(String(e.op), "write")
    assert_equal(kind, ErrorKind.BrokenPipe)


# ---- accept ------------------------------------------------------------------


def test_accept_retries_econnaborted_and_eintr() raises:
    fault.clear()
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    l.set_deadline(_guard())
    var c = TcpStream.connect(l.local_addr())
    fault.clear()
    fault.inject(SYS_accept4, Errno.ECONNABORTED, times=2)
    fault.inject(SYS_accept4, Errno.EINTR, skip=2, times=1)
    var acc = l.accept()
    assert_equal(fault.calls(SYS_accept4), 4)
    assert_equal(fault.pending(), 0)
    assert_equal(acc.addr, c.local_addr())


def test_accept_emfile_enfile_raise_too_many_files() raises:
    fault.clear()
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    l.set_deadline(_guard())
    var c = TcpStream.connect(l.local_addr())
    var errnos: List[Errno] = [Errno.EMFILE, Errno.ENFILE]
    for e in errnos:
        fault.clear()
        fault.inject(SYS_accept4, e, times=1)
        var kind = ErrorKind.Other
        var got = Errno(0)
        try:
            _ = l.accept()
        except err:
            kind = err.kind
            got = err.errno
            assert_equal(String(err.op), "accept")
        assert_equal(kind, ErrorKind.TooManyFiles)
        assert_equal(got, e)
        assert_equal(fault.calls(SYS_accept4), 1)  # raised, not retried
    # The connection stayed queued.
    fault.clear()
    var acc = l.accept()
    assert_equal(acc.addr, c.local_addr())


def test_accept_closes_stream_when_nodelay_fails() raises:
    fault.clear()
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    l.set_deadline(_guard())
    var c = TcpStream.connect(l.local_addr())
    c.set_read_deadline(_guard())
    var before = _fd_count()
    fault.clear()
    fault.inject(SYS_setsockopt, Errno.ENOMEM, times=1)
    var kind = ErrorKind.Other
    try:
        _ = l.accept()
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.OutOfMemory)
    assert_equal(fault.calls(SYS_accept4), 1)
    assert_equal(_fd_count(), before)  # the accepted socket was closed
    fault.clear()
    var buf = List[UInt8](length=1, fill=0)
    assert_equal(c.read(Span(buf)), 0)  # the peer saw it close
    sys.keep_alive(l)


# ---- connect -----------------------------------------------------------------


def test_tcp_connect_eintr_is_never_reissued() raises:
    fault.clear()
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var errnos: List[Errno] = [Errno.EINTR, Errno.EINPROGRESS]
    for e in errnos:
        var before = _fd_count()
        fault.clear()
        fault.inject(SYS_connect, e, times=1)
        var kind = ErrorKind.Other
        try:
            _ = TcpStream.connect_timeout(l.local_addr(), Duration.from_secs(5))
        except err:
            kind = err.kind
            assert_equal(String(err.op), "connect")
        # The injected error means the kernel never saw a connect: the socket
        # polls HUP, SO_ERROR is 0 and there is no peer. L2 must report that
        # instead of calling connect again (or spinning).
        assert_equal(kind, ErrorKind.NotConnected)
        assert_equal(fault.calls(SYS_connect), 1)
        assert_equal(_fd_count(), before)
    sys.keep_alive(l)


def test_tcp_connect_resumes_after_poll_eintr() raises:
    fault.clear()
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    fault.clear()
    fault.inject(SYS_ppoll, Errno.EINTR, times=1)
    var c = TcpStream.connect(l.local_addr())
    assert_equal(fault.calls(SYS_connect), 1)
    assert_equal(fault.calls(SYS_ppoll), 2)
    assert_equal(c.peer_addr(), l.local_addr())


def test_tcp_connect_spurious_wakeup_waits_again() raises:
    fault.clear()
    # SO_ERROR 0 but no peer yet (getpeername ENOTCONN) without HUP/ERR is a
    # spurious wakeup: wait again, do not fail and do not reconnect.
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    fault.clear()
    fault.inject(SYS_getpeername, Errno.ENOTCONN, times=1)
    var c = TcpStream.connect(l.local_addr())
    assert_equal(fault.calls(SYS_connect), 1)
    assert_equal(fault.calls(SYS_getpeername), 2)
    assert_equal(fault.calls(SYS_ppoll), 2)
    assert_equal(c.peer_addr(), l.local_addr())


def test_tcp_connect_failures_close_the_socket() raises:
    fault.clear()
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    l.set_deadline(_guard())
    var before = _fd_count()
    fault.clear()
    fault.inject(SYS_socket, Errno.EMFILE, times=1)
    var kind = ErrorKind.Other
    try:
        _ = TcpStream.connect(l.local_addr())
    except e:
        kind = e.kind
        assert_equal(String(e.op), "socket")
    assert_equal(kind, ErrorKind.TooManyFiles)
    # Connected, then TCP_NODELAY fails: the stream must not leak.
    fault.clear()
    fault.inject(SYS_setsockopt, Errno.ENOMEM, times=1)
    kind = ErrorKind.Other
    try:
        _ = TcpStream.connect(l.local_addr())
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.OutOfMemory)
    fault.clear()
    assert_equal(_fd_count(), before)
    var s = l.accept().into_stream()
    s.set_read_deadline(_guard())
    var buf = List[UInt8](length=1, fill=0)
    assert_equal(s.read(Span(buf)), 0)  # that connection was closed


# ---- net.unix ------------------------------------------------------------------


def test_unix_connect_eintr_is_reissued() raises:
    fault.clear()
    # Unlike TCP, an interrupted AF_UNIX connect leaves nothing in progress,
    # so L2 issues it again.
    var a = _abstract("eintr")
    var l = UnixListener.bind(a)
    fault.clear()
    fault.inject(SYS_connect, Errno.EINTR, times=2)
    var c = UnixStream.connect_timeout(a, Duration.from_secs(5))
    assert_equal(fault.calls(SYS_connect), 3)
    l.set_deadline(_guard())
    var s = l.accept().into_stream()
    c.write_all(String("u").as_bytes())
    var buf = List[UInt8](length=1, fill=0)
    s.set_read_deadline(_guard())
    s.read_exact(Span(buf))
    assert_equal(_text(buf, 1), "u")


def test_unix_connect_eagain_with_deadline_is_timeout() raises:
    fault.clear()
    var a = _abstract("eagain")
    var l = UnixListener.bind(a)
    var before = _fd_count()
    fault.clear()
    fault.inject(SYS_connect, Errno.EAGAIN, times=1)
    var kind = ErrorKind.Other
    try:
        _ = UnixStream.connect_timeout(a, Duration.from_secs(5))
    except e:
        kind = e.kind
        assert_equal(String(e.op), "connect")
    assert_equal(kind, ErrorKind.TimedOut)
    assert_equal(fault.calls(SYS_connect), 1)
    fault.clear()
    assert_equal(_fd_count(), before)
    sys.keep_alive(l)


def test_unix_accept_retries_and_reports_emfile() raises:
    fault.clear()
    var a = _abstract("accept")
    var l = UnixListener.bind(a)
    l.set_deadline(_guard())
    var c = UnixStream.connect(a)
    fault.clear()
    fault.inject(SYS_accept4, Errno.EMFILE, times=1)
    var kind = ErrorKind.Other
    try:
        _ = l.accept()
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.TooManyFiles)
    fault.clear()
    fault.inject(SYS_accept4, Errno.ECONNABORTED, times=1)
    var acc = l.accept()
    assert_equal(fault.calls(SYS_accept4), 2)
    assert_true(acc.addr.is_unnamed())
    sys.keep_alive(c)


def test_unix_write_all_loops_over_short_sends() raises:
    fault.clear()
    var p = UnixStream.pair()
    var x = p.first.take()
    var y = p.second.take()
    y.set_read_deadline(_guard())
    fault.clear()
    fault.inject_short(SYS_sendto, 2, times=-1)
    x.write_all(String("abcde").as_bytes())
    assert_equal(fault.calls(SYS_sendto), 3)
    fault.clear()
    var buf = List[UInt8](length=5, fill=0)
    y.read_exact(Span(buf))
    assert_equal(_text(buf, 5), "abcde")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
