"""Tests for net.unix (L2 blocking AF_UNIX streams): pathname and abstract
listeners, socketpairs, deadlines, connect with a full backlog, EOF/reset
and fd hygiene.

Same single-thread strategy as test_tcp.mojo: `_pump` interleaves both ends
by polling, and a python3 child (test-only, given one socketpair end via
pass_fds) is the peer when a transfer must block. Abstract names include
our pid and pathnames live in a fresh temp dir, so parallel test runs never
collide.

Full backlog: an AF_UNIX listener with backlog 0 queues one connection;
the next connect waits in the kernel (unix_wait_for_peer) until there is
room, which is how connect timeouts are exercised. EINTR during that wait is
covered by test_tcp_eintr_faults.mojo, injected faults by
test_tcp_faults.mojo.
"""

from std.os import listdir, remove, rmdir
from std.python import Python, PythonObject
from std.tempfile import mkdtemp
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import AsFd, Errno, ErrorKind, IoError, check
from linux import sys
from linux.consts import (
    F_GETFD,
    FD_CLOEXEC,
    POLLIN,
    POLLOUT,
    SO_SNDTIMEO,
    SOL_SOCKET,
)
from linux.nr import SYS_getpid
from linux.poll import wait_ready
from linux.syscall import syscall0
from linux.time import Deadline, Duration, Instant
from net.addr import UnixAddr
from net.socket import Domain, Shutdown, SockType, Socket
from net.unix import UnixAccepted, UnixListener, UnixStream, UnixStreamPair

comptime MiB = 1024 * 1024


# ---- helpers -----------------------------------------------------------------


def _ms(n: Int) -> Duration:
    return Duration.from_millis(n)


def _guard() -> Deadline:
    return Deadline.after(Duration.from_secs(10))


def _pid() -> Int:
    return syscall0(SYS_getpid)


def _socket_dir(prefix: String, longest_name: StaticString) raises -> String:
    """A fresh temp dir in which `dir + "/" + name` fits sun_path for names
    no longer than `longest_name`. mkdtemp honors $TMPDIR, which can be long
    (CI per-job dirs, Bazel); then fall back to /tmp, so the test exercises
    the socket instead of failing in UnixAddr.from_pathname."""
    var extra = 1 + longest_name.byte_length()
    var dir = mkdtemp(prefix=prefix)
    if dir.byte_length() + extra <= UnixAddr.MAX_PATHNAME:
        return dir
    rmdir(dir)
    dir = mkdtemp(prefix=prefix, dir=String("/tmp"))
    if dir.byte_length() + extra > UnixAddr.MAX_PATHNAME:
        rmdir(dir)
        raise Error("no temp dir short enough for a socket path: ", dir)
    return dir


def _abstract(tag: StaticString) raises IoError -> UnixAddr:
    return UnixAddr.from_abstract_name(
        String("mojo_tcp_unix_", _pid(), "_", tag)
    )


def _pattern(n: Int, seed: Int = 0) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(UInt8((i * 11 + seed * 5 + 1) % 253))
    return out^


def _text(buf: List[UInt8]) -> String:
    return String(from_utf8_lossy=Span(buf))


def _same(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def _fd_count() raises -> Int:
    return len(listdir("/proc/self/fd"))


def _fd_flags[F: AsFd](f: F) raises -> Int:
    return check("fcntl(F_GETFD)", sys.fcntl(f, F_GETFD))


def _ready[F: AsFd](f: F, events: Int) raises -> Bool:
    var kind = ErrorKind.Other
    var failed = False
    try:
        _ = wait_ready(f, Int16(events), Deadline.after(Duration.ZERO), "probe")
    except e:
        failed = True
        kind = e.kind
    if failed and kind != ErrorKind.TimedOut:
        raise Error("probe failed: ", kind)
    return not failed


def _pump(
    src: UnixStream, dst: UnixStream, data: List[UInt8]
) raises -> List[UInt8]:
    """Single-threaded transfer that never blocks (see test_tcp.mojo)."""
    var n = len(data)
    var got = List[UInt8](capacity=n)
    var chunk = List[UInt8](length=64 * 1024, fill=0)
    var off = 0
    var t = Instant.now()
    while off < n or len(got) < n:
        if t.elapsed() > Duration.from_secs(20):
            raise Error("pump stalled")
        if off < n and _ready(src, POLLOUT):
            var k = src.write(Span(data)[off:n])
            assert_true(k > 0 and k <= n - off)
            off += k
        if len(got) < n and _ready(dst, POLLIN):
            var k = dst.read(Span(chunk))
            assert_true(k > 0, "unexpected EOF in pump")
            for i in range(k):
                got.append(chunk[i])
    return got^


def _drain(mut s: UnixStream, mut got: List[UInt8]) raises:
    """Read until 100 ms pass without data."""
    var buf = List[UInt8](length=64 * 1024, fill=0)
    while True:
        s.set_read_deadline(Deadline.after(_ms(100)))
        var k = 0
        var kind = ErrorKind.Other
        var failed = False
        try:
            k = s.read(Span(buf))
        except e:
            failed = True
            kind = e.kind
        if failed:
            if kind == ErrorKind.TimedOut:
                return
            raise Error("drain failed: ", kind)
        if k == 0:
            return
        for i in range(k):
            got.append(buf[i])


def _echo_check(mut c: UnixStream, mut s: UnixStream) raises:
    c.set_deadline(_guard())
    s.set_deadline(_guard())
    c.write_all(String("ping over unix").as_bytes())
    var buf = List[UInt8](length=14, fill=0)
    s.read_exact(Span(buf))
    assert_equal(_text(buf), "ping over unix")
    s.write_all(Span(buf))
    var back = List[UInt8](length=14, fill=0)
    c.read_exact(Span(back))
    assert_equal(_text(back), "ping over unix")


# ---- listeners and addresses -------------------------------------------------


def test_pathname_listener_echo() raises:
    var dir = _socket_dir("mojo_tcp_l2unix_", "missing.sock")
    var path = dir + "/echo.sock"
    try:
        _pathname_body(dir, path)
    finally:
        try:
            remove(path)
        except:
            pass
        rmdir(dir)


def _pathname_body(dir: String, path: String) raises:
    var addr = UnixAddr.from_pathname(path)
    var l = UnixListener.bind(addr)
    assert_equal(l.local_addr(), addr)
    assert_true(l.socket().nonblocking())
    assert_true(l.socket().is_listener())
    assert_true((_fd_flags(l) & FD_CLOEXEC) != 0)
    l.set_deadline(_guard())
    var c = UnixStream.connect(addr)
    var acc = l.accept()
    assert_true(acc.addr.is_unnamed())  # the client never bound
    var s = acc^.into_stream()
    assert_equal(c.peer_addr(), addr)
    assert_true(c.local_addr().is_unnamed())
    assert_equal(s.local_addr(), addr)
    _echo_check(c, s)
    # The socket file outlives the listener: binding again is AddrInUse,
    # even after the listener is closed.
    l^.close()
    var kind = ErrorKind.Other
    try:
        _ = UnixListener.bind(addr)
    except e:
        kind = e.kind
        assert_equal(String(e.op), "bind")
    assert_equal(kind, ErrorKind.AddrInUse)
    # A stale socket file nobody listens on: refused. A missing path: NotFound.
    kind = ErrorKind.Other
    try:
        _ = UnixStream.connect(addr)
    except e:
        kind = e.kind
        assert_equal(String(e.op), "connect")
    assert_equal(kind, ErrorKind.ConnectionRefused)
    kind = ErrorKind.Other
    try:
        _ = UnixStream.connect_timeout(
            UnixAddr.from_pathname(dir + "/missing.sock"), Duration.from_secs(1)
        )
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.NotFound)


def test_abstract_listener_echo() raises:
    var addr = _abstract("echo")
    var l = UnixListener.bind(addr)
    assert_equal(l.local_addr(), addr)
    l.set_deadline(_guard())
    var c = UnixStream.connect(addr)
    var s = l.accept().into_stream()
    assert_equal(c.peer_addr(), addr)
    _echo_check(c, s)
    # Abstract names vanish with the socket: rebinding works after close.
    l^.close()
    var again = UnixListener.bind(addr)
    assert_equal(again.local_addr(), addr)
    # And nobody listening on a name: refused.
    var kind = ErrorKind.Other
    try:
        _ = UnixStream.connect(_abstract("nobody"))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.ConnectionRefused)


def test_autobind_listener() raises:
    var l = UnixListener.bind(UnixAddr.unnamed())
    var a = l.local_addr()
    assert_true(a.is_abstract())  # kernel-chosen name ("@" + 5 hex digits)
    assert_equal(len(a.name()), 5)
    l.set_deadline(_guard())
    var c = UnixStream.connect(a)
    var s = l.accept().into_stream()
    _echo_check(c, s)


def test_connect_to_unnamed_is_invalid() raises:
    var kind = ErrorKind.Other
    try:
        _ = UnixStream.connect(UnixAddr.unnamed())
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)


def test_listener_from_socket() raises:
    var addr = _abstract("adopt")
    var raw = Socket.new(Domain.UNIX, SockType.STREAM)
    raw.bind_unix(addr)
    raw.listen(4)
    var l = UnixListener.from_socket(raw^)
    assert_true(l.socket().nonblocking())
    l.set_deadline(_guard())
    var c1 = Socket.new(Domain.UNIX, SockType.STREAM)
    c1.connect_unix(addr)
    var c = UnixStream.from_socket(c1^)
    assert_true(c.socket().nonblocking())
    var s = l.accept().into_stream()
    _echo_check(c, s)
    var back = c^.into_socket()
    assert_true(back.nonblocking())


# ---- connected stream properties ---------------------------------------------


def test_connected_stream_defaults() raises:
    var addr = _abstract("defaults")
    var l = UnixListener.bind(addr)
    var c = UnixStream.connect_timeout(addr, Duration.from_secs(5))
    var s = l.accept().into_stream()
    assert_true(c.socket().nonblocking())
    assert_true(s.socket().nonblocking())
    assert_true((_fd_flags(c) & FD_CLOEXEC) != 0)
    assert_true((_fd_flags(s) & FD_CLOEXEC) != 0)
    # The connect timeout (SO_SNDTIMEO) does not linger on the socket.
    var tv = List[UInt8](length=16, fill=0xFF)
    assert_equal(
        c.socket().get_option_bytes(SOL_SOCKET, SO_SNDTIMEO, Span(tv)), 16
    )
    for i in range(16):
        assert_equal(Int(tv[i]), 0)
    # Peer credentials through the L1 socket.
    assert_equal(Int(s.socket().peer_cred().pid), _pid())
    assert_equal(Int(c.socket().peer_cred().pid), _pid())
    assert_true(String(c).startswith("UnixStream(fd="))
    assert_true(String(l).startswith("UnixListener(fd="))


def test_pair_echo_many_sizes() raises:
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    assert_true(a.socket().nonblocking())
    assert_true(b.socket().nonblocking())
    assert_true((_fd_flags(a) & FD_CLOEXEC) != 0)
    assert_true(a.local_addr().is_unnamed())
    assert_true(b.peer_addr().is_unnamed())
    var sizes: List[Int] = [1, 3, 212_992, 212_993, 1 * MiB]
    for i in range(len(sizes)):
        var data = _pattern(sizes[i], i)
        var there = _pump(a, b, data)
        assert_true(_same(there, data), String("a->b size ", sizes[i]))
        var back = _pump(b, a, there)
        assert_true(_same(back, data), String("b->a size ", sizes[i]))


def test_zero_byte_operations() raises:
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    a.set_deadline(_guard())
    var empty = List[UInt8]()
    assert_equal(a.write(Span(empty)), 0)
    a.write_all(Span(empty))
    assert_equal(a.read(Span(empty)), 0)
    a.read_exact(Span(empty))
    assert_false(_ready(b, POLLIN))  # nothing was sent
    sys.keep_alive(a)  # (else `a` closes early and b reads EOF)


def test_large_write_all_to_python_child() raises:
    # The child gets one end of a socketpair and echoes everything after
    # EOF; our write_all of 4 MiB must block repeatedly until it drains.
    var p = UnixStream.pair()
    var mine = p.first.take()
    var theirs = p.second.take()
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    var script = (
        "import socket, sys\n"
        "s = socket.socket(fileno=int(sys.argv[1]))\n"
        "s.settimeout(30)\n"
        "data = bytearray()\n"
        "while True:\n"
        "    b = s.recv(1 << 16)\n"
        "    if not b:\n"
        "        break\n"
        "    data += b\n"
        "s.sendall(data)\n"
        "s.close()\n"
    )
    var fd = Int(theirs.raw_fd())
    var child = subprocess.Popen(
        Python.list(pysys.executable, "-c", script, String(fd)),
        pass_fds=Python.list(fd),
    )
    theirs^.close()  # the child holds its own copy
    mine.set_deadline(Deadline.after(Duration.from_secs(30)))
    var data = _pattern(4 * MiB, 2)
    mine.write_all(Span(data))
    mine.shutdown(Shutdown.WRITE)
    var back = List[UInt8]()
    var n = mine.read_to_end(back)
    _ = child.wait()
    assert_equal(n, 4 * MiB)
    assert_true(_same(back, data))


# ---- deadlines ---------------------------------------------------------------


def test_read_deadline_expires_and_stream_stays_usable() raises:
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    a.set_read_deadline(Deadline.after(_ms(150)))
    var buf = List[UInt8](length=8, fill=0)
    var t = Instant.now()
    var kind = ErrorKind.Other
    try:
        _ = a.read(Span(buf))
    except e:
        kind = e.kind
        assert_equal(String(e.op), "read")
        assert_equal(e.errno, Errno(0))
    var el = t.elapsed()
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(el >= _ms(150), String("early: ", el))
    assert_true(el < _ms(400), String("late: ", el))
    b.write_all(String("fine").as_bytes())
    a.set_read_deadline(_guard())
    var four = List[UInt8](length=4, fill=0)
    a.read_exact(Span(four))
    assert_equal(_text(four), "fine")


def test_write_deadline_expires_when_peer_never_reads() raises:
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    var data = _pattern(4 * MiB, 4)
    a.set_write_deadline(Deadline.after(_ms(150)))
    var t = Instant.now()
    var kind = ErrorKind.Other
    try:
        a.write_all(Span(data))
    except e:
        kind = e.kind
        assert_equal(String(e.op), "write")
    var el = t.elapsed()
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(el >= _ms(150), String("early: ", el))
    assert_true(el < _ms(400), String("late: ", el))
    # Usable afterwards: the peer sees an exact prefix, then the marker.
    var got = List[UInt8]()
    _drain(b, got)
    a.set_write_deadline(_guard())
    a.write_all(String("TAIL").as_bytes())
    _drain(b, got)
    var n = len(got)
    assert_true(n > 4)
    assert_equal(String(from_utf8_lossy=Span(got)[n - 4 : n]), "TAIL")
    for i in range(n - 4):
        if got[i] != data[i]:
            assert_true(False, String("mismatch at ", i))


def test_accept_deadline_expires() raises:
    var addr = _abstract("acceptdl")
    var l = UnixListener.bind(addr)
    l.set_deadline(Deadline.after(_ms(120)))
    var t = Instant.now()
    var kind = ErrorKind.Other
    try:
        _ = l.accept()
    except e:
        kind = e.kind
        assert_equal(String(e.op), "accept")
    var el = t.elapsed()
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(el >= _ms(120), String("early: ", el))
    assert_true(el < _ms(400), String("late: ", el))
    var c = UnixStream.connect(addr)
    _ = l.accept()  # pending connection wins over the expired deadline
    sys.keep_alive(c)


def test_connect_timeout_with_full_backlog() raises:
    var addr = _abstract("backlog")
    var l = UnixListener.bind(addr, backlog=0)
    var first = UnixStream.connect(addr)  # takes the only slot
    var t = Instant.now()
    var kind = ErrorKind.Other
    try:
        _ = UnixStream.connect_timeout(addr, _ms(200))
    except e:
        kind = e.kind
        assert_equal(String(e.op), "connect")
        assert_equal(e.errno, Errno(0))
    var el = t.elapsed()
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(el >= _ms(200), String("early: ", el))
    assert_true(el < _ms(450), String("late: ", el))
    # An expired deadline makes one attempt that does not wait.
    t = Instant.now()
    kind = ErrorKind.Other
    try:
        _ = UnixStream.connect_deadline(addr, Deadline.after(Duration.ZERO))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(t.elapsed() < _ms(100))
    # Zero timeout is a caller bug.
    kind = ErrorKind.Other
    try:
        _ = UnixStream.connect_timeout(addr, Duration.ZERO)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)
    # Room again: the same call succeeds, and the stream works.
    l.set_deadline(_guard())
    var s1 = l.accept().into_stream()
    var c = UnixStream.connect_timeout(addr, Duration.from_secs(5))
    var s2 = l.accept().into_stream()
    _echo_check(c, s2)
    sys.keep_alive(first)
    sys.keep_alive(s1)


# ---- EOF, reset, half-close, peek, clone -------------------------------------


def test_half_close_and_eof() raises:
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    a.set_deadline(_guard())
    b.set_deadline(_guard())
    a.write_all(String("question").as_bytes())
    a.shutdown(Shutdown.WRITE)
    var q = List[UInt8]()
    assert_equal(b.read_to_end(q), 8)
    assert_equal(_text(q), "question")
    b.write_all(String("answer").as_bytes())
    b^.close()
    var ans = List[UInt8]()
    assert_equal(a.read_to_end(ans), 6)
    assert_equal(_text(ans), "answer")
    var buf = List[UInt8](length=2, fill=0)
    assert_equal(a.read(Span(buf)), 0)
    var kind = ErrorKind.Other
    try:
        a.read_exact(Span(buf))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.UnexpectedEof)
    # Peer gone: writing raises (no SIGPIPE thanks to MSG_NOSIGNAL).
    kind = ErrorKind.Other
    try:
        a.write_all(String("x").as_bytes())
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.BrokenPipe)


def test_close_with_unread_data_resets_peer() raises:
    # AF_UNIX: closing with unread data in our receive queue sets
    # ECONNRESET on the peer.
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    a.write_all(String("never read").as_bytes())
    b^.close()
    a.set_read_deadline(_guard())
    var buf = List[UInt8](length=4, fill=0)
    var kind = ErrorKind.Other
    try:
        _ = a.read(Span(buf))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.ConnectionReset)


def test_peek_does_not_consume() raises:
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    b.write_all(String("peekaboo").as_bytes())
    a.set_read_deadline(_guard())
    var four = List[UInt8](length=4, fill=0)
    assert_equal(a.peek(Span(four)), 4)
    assert_equal(a.peek(Span(four)), 4)
    assert_equal(_text(four), "peek")
    var all = List[UInt8](length=8, fill=0)
    a.read_exact(Span(all))
    assert_equal(_text(all), "peekaboo")
    a.set_read_deadline(Deadline.after(_ms(60)))
    var kind = ErrorKind.Other
    try:
        _ = a.peek(Span(four))
    except e:
        kind = e.kind
        assert_equal(String(e.op), "peek")
    assert_equal(kind, ErrorKind.TimedOut)
    sys.keep_alive(b)  # (else `b` closes early and peek sees EOF)


def test_try_clone_is_independent() raises:
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    var d = Deadline.after(Duration.from_secs(9))
    a.set_write_deadline(d)
    var a2 = a.try_clone()
    assert_equal(a2.write_deadline(), d)
    a2.set_write_deadline(Deadline.none())
    assert_equal(a.write_deadline(), d)
    a2.write_all(String("one").as_bytes())
    a.write_all(String("two").as_bytes())
    b.set_read_deadline(_guard())
    var six = List[UInt8](length=6, fill=0)
    b.read_exact(Span(six))
    assert_equal(_text(six), "onetwo")
    a^.close()
    b.write_all(String("ok").as_bytes())
    a2.set_read_deadline(_guard())
    var two = List[UInt8](length=2, fill=0)
    a2.read_exact(Span(two))
    assert_equal(_text(two), "ok")


# ---- hygiene -----------------------------------------------------------------


def test_no_fd_leak_over_2000_cycles() raises:
    var addr = _abstract("leak")
    var l = UnixListener.bind(addr)
    l.set_deadline(_guard())
    var full = _abstract("leakfull")
    var lf = UnixListener.bind(full, backlog=0)
    var blocker = UnixStream.connect(full)
    var before = _fd_count()
    for _ in range(2000):
        var c = UnixStream.connect(addr)
        var acc = l.accept()
        _ = c^
        _ = acc^
    for _ in range(200):
        var p = UnixStream.pair()
        _ = p^
    # Error paths: count the outcomes, so a helper that stopped producing
    # its error (someone listening on the name, a freed backlog slot)
    # cannot turn these loops into success paths unnoticed.
    var nobody = _abstract("leaknobody")
    var refused = 0
    var other = String()
    for _ in range(200):
        try:
            _ = UnixStream.connect(nobody)
        except e:
            if e.kind == ErrorKind.ConnectionRefused:
                refused += 1
            else:
                other = String(e)
    var timed_out = 0
    for _ in range(20):
        try:
            _ = UnixStream.connect_deadline(full, Deadline.after(Duration.ZERO))
        except e:
            if e.kind == ErrorKind.TimedOut:
                timed_out += 1
            else:
                other = String(e)
    var after = _fd_count()
    assert_equal(refused, 200, other)
    assert_equal(timed_out, 20, other)
    assert_equal(after, before)
    sys.keep_alive(l)
    sys.keep_alive(lf)
    sys.keep_alive(blocker)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
