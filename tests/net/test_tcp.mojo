"""Tests for net.tcp (L2 blocking TCP) over loopback.

Concurrency without threads: a single-threaded test cannot let a peer read
while `write_all` blocks. Two deterministic approaches are used:
- Small transfers interleave both ends by hand: `_pump` writes only while
  the sender polls writable and reads only while the receiver polls
  readable, so neither side ever blocks, yet every `write` really is
  partial once the buffers fill.
- Transfers that must block (4 MiB `write_all`, a slow reader) use a
  python3 child process (test-only) as the peer. It runs in its own
  process, so it makes progress while we block in ppoll; it reads until
  EOF and only then echoes, so neither side can deadlock on full buffers.

Unreachable peers: a listener with backlog 0 and one queued connection has
a full accept queue, and Linux then drops further SYNs
(`tcp_conn_request`: `sk_acceptq_is_full` -> drop), so a connect to it
stays in SYN_SENT until the SYN retransmit (1 s) and beyond: a reliable
local "never answers" address. A port that is bound but not listening
refuses (RST).

Deadline tolerances are generous (+250 ms) for loaded CI machines; the
lower bounds are strict.
"""

from std.os import getenv, listdir
from std.python import Python, PythonObject
from std.sys import size_of
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import AsFd, Errno, ErrorKind, IoError, OwnedFd, check
from linux import sys
from linux.abi import SockaddrIn6
from linux.consts import (
    AF_INET6,
    F_GETFD,
    FD_CLOEXEC,
    POLLIN,
    POLLOUT,
    SOCK_CLOEXEC,
    SOCK_STREAM,
)
from linux.poll import wait_ready
from linux.syscall import err_of, is_err
from linux.time import Deadline, Duration, Instant
from net.addr import SocketAddr
from net.socket import Domain, Shutdown, SockType, Socket
from net.tcp import TcpAccepted, TcpListener, TcpStream

comptime MiB = 1024 * 1024


# ---- helpers -----------------------------------------------------------------


def _ms(n: Int) -> Duration:
    return Duration.from_millis(n)


def _lo() raises -> SocketAddr:
    return SocketAddr.parse("127.0.0.1:0")


def _guard() -> Deadline:
    """Backstop so a broken test fails with TimedOut instead of hanging."""
    return Deadline.after(Duration.from_secs(10))


@fieldwise_init
struct _Conn(Movable):
    """A listener plus one connected (client, server) stream pair."""

    var l: TcpListener
    var c: TcpStream
    var s: TcpStream


def _conn(rcvbuf: Int = 0) raises -> _Conn:
    """Connected pair over 127.0.0.1. `rcvbuf > 0` sets SO_RCVBUF on the
    listener first, so the accepted socket inherits it before the window is
    negotiated."""
    var l = TcpListener.bind(_lo())
    if rcvbuf > 0:
        l.socket().set_recv_buffer_size(rcvbuf)
    l.set_deadline(_guard())
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    return _Conn(l^, c^, s^)


def _pattern(n: Int, seed: Int = 0) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(UInt8((i * 7 + seed * 13 + 3) % 251))
    return out^


def _bytes(s: StringSlice) -> List[UInt8]:
    var out = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        out.append(b)
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


def _ready[F: AsFd](f: F, events: Int) raises -> Bool:
    """Whether `f` reports `events` right now (zero-timeout poll)."""
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
    src: TcpStream, dst: TcpStream, data: List[UInt8]
) raises -> List[UInt8]:
    """Move `data` from `src` to `dst` in one thread without blocking: write
    only while `src` polls writable, read only while `dst` polls readable.
    Returns what `dst` received."""
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


def _fd_count() raises -> Int:
    return len(listdir("/proc/self/fd"))


def _ipv6(test: StaticString, need_loopback: Bool = True) raises -> Bool:
    """Whether this host has IPv6 (with `need_loopback`: a usable [::1]),
    decided with raw syscalls, not with the code under test. Only
    EAFNOSUPPORT from socket(AF_INET6) or EADDRNOTAVAIL from bind([::1]:0)
    mean "no IPv6"; any other failure raises, so a regression is never
    reported as a skip. Without IPv6 this prints a visible skip line (which
    tools/run_tests.sh shows and counts) and the test returns early, unless
    MOJO_NET_REQUIRE_IPV6=1 turns it into a failure."""
    var why: StaticString
    var r = sys.socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0)
    if is_err(r) and Errno(err_of(r)) == Errno.EAFNOSUPPORT:
        why = "socket(AF_INET6): EAFNOSUPPORT"
    else:
        var fd = OwnedFd(
            unsafe_from_raw=Int32(check("socket(AF_INET6)", r))
        )
        if not need_loopback:
            return True
        var sa = SockaddrIn6(
            UInt16(AF_INET6), 0, 0, Array[UInt8, 16](fill=0), 0
        )
        sa.addr[15] = 1  # [::1]:0
        var b = sys.bind(fd, sa, size_of[SockaddrIn6]())
        if not is_err(b):
            return True
        if Errno(err_of(b)) != Errno.EADDRNOTAVAIL:
            _ = check("bind([::1]:0)", b)
        why = "bind([::1]:0): EADDRNOTAVAIL"
    if getenv("MOJO_NET_REQUIRE_IPV6") == "1":
        raise Error(test, ": no IPv6 (", why, ") but MOJO_NET_REQUIRE_IPV6=1")
    print(String("    (skipped: ", test, ": no IPv6, ", why, ")"))
    return False


def _nonlocal_bind() raises -> Bool:
    """net.ipv4.ip_nonlocal_bind=1 (load balancers, keepalived hosts) lets
    a socket bind any IPv4 address, so binding TEST-NET-1 then succeeds."""
    with open("/proc/sys/net/ipv4/ip_nonlocal_bind", "r") as f:
        return Int(f.read().strip()) != 0


def _fd_flags[F: AsFd](f: F) raises -> Int:
    return check("fcntl(F_GETFD)", sys.fcntl(f, F_GETFD))


@fieldwise_init
struct _Blackhole(Movable):
    """A loopback address whose accept queue is full: SYNs are dropped."""

    var l: TcpListener
    var queued: TcpStream
    var addr: SocketAddr


def _blackhole() raises -> _Blackhole:
    var l = TcpListener.bind(_lo(), backlog=0)
    var addr = l.local_addr()
    var queued = TcpStream.connect(addr)  # takes the only queue slot
    return _Blackhole(l^, queued^, addr)


def _closed_port() raises -> Tuple[Socket, SocketAddr]:
    """Bound, not listening: connects are refused, and holding the socket
    keeps the port from being reused by someone else."""
    var s = Socket.new(Domain.IPV4, SockType.STREAM)
    s.bind(_lo())
    var a = s.local_addr()
    return (s^, a)


# python3 peer (test-only), run as `python3 -c _PEER mode port`.
comptime _PEER = (
    "import socket, sys, time\n"
    "mode, port = sys.argv[1], int(sys.argv[2])\n"
    "s = socket.create_connection(('127.0.0.1', port))\n"
    "s.settimeout(30)\n"
    "if mode in ('sink_echo', 'slow_sink_echo'):\n"
    "    slow = mode == 'slow_sink_echo'\n"
    "    data = bytearray()\n"
    "    while True:\n"
    "        if slow:\n"
    "            time.sleep(0.002)\n"
    "        b = s.recv(16384 if slow else 1 << 20)\n"
    "        if not b:\n"
    "            break\n"
    "        data += b\n"
    "    s.sendall(data)\n"
    "elif mode == 'late_send':\n"
    "    time.sleep(float(sys.argv[3]))\n"
    "    s.sendall(b'late')\n"
    "    s.recv(1)\n"
    "s.close()\n"
)


def _spawn_peer(
    mode: String, port: Int, arg: String = ""
) raises -> PythonObject:
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    if arg.byte_length() > 0:
        return subprocess.Popen(
            Python.list(pysys.executable, "-c", _PEER, mode, String(port), arg)
        )
    return subprocess.Popen(
        Python.list(pysys.executable, "-c", _PEER, mode, String(port))
    )


# ---- listener and stream setup -----------------------------------------------


def test_listener_defaults() raises:
    var l = TcpListener.bind(_lo())
    var a = l.local_addr()
    assert_true(a.port() != 0)
    assert_true(a.ip().is_loopback())
    assert_true(l.socket().reuse_address())
    assert_true(l.socket().nonblocking())
    assert_true(l.socket().is_listener())
    assert_true((_fd_flags(l) & FD_CLOEXEC) != 0)
    assert_true(l.deadline().is_none())
    assert_true(String(l).startswith("TcpListener(fd="))


def test_connect_accept_defaults() raises:
    var l = TcpListener.bind(_lo())
    var c = TcpStream.connect(l.local_addr())
    var acc = l.accept()
    assert_equal(acc.addr, c.local_addr())
    var s = acc^.into_stream()
    assert_equal(c.peer_addr(), l.local_addr())
    assert_equal(s.local_addr(), l.local_addr())
    assert_equal(s.peer_addr(), c.local_addr())
    # Both ends: nonblocking internally, CLOEXEC, TCP_NODELAY on.
    assert_true(c.socket().nonblocking())
    assert_true(s.socket().nonblocking())
    assert_true((_fd_flags(c) & FD_CLOEXEC) != 0)
    assert_true((_fd_flags(s) & FD_CLOEXEC) != 0)
    assert_true(c.socket().nodelay())
    assert_true(s.socket().nodelay())
    assert_true(c.read_deadline().is_none())
    assert_true(c.write_deadline().is_none())
    assert_true(String(c).startswith("TcpStream(fd="))


def test_ipv6_loopback_echo() raises:
    if not _ipv6("test_ipv6_loopback_echo"):
        return
    var l = TcpListener.bind(SocketAddr.parse("[::1]:0"))
    assert_true(l.local_addr().is_ipv6())
    l.set_deadline(_guard())
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    assert_true(c.peer_addr().is_ipv6())
    c.write_all(String("v6").as_bytes())
    var buf = List[UInt8](length=2, fill=0)
    s.read_exact(Span(buf))
    assert_equal(_text(buf), "v6")


def test_bind_errors() raises:
    var a = TcpListener.bind(_lo())
    # SO_REUSEADDR does not let two listeners share a port on Linux.
    var kind = ErrorKind.Other
    try:
        _ = TcpListener.bind(a.local_addr())
    except e:
        kind = e.kind
        assert_equal(String(e.op), "bind")
    assert_equal(kind, ErrorKind.AddrInUse)
    # TEST-NET-1 is not local: EADDRNOTAVAIL, unless the host allows
    # binding non-local addresses (then the bind must simply work).
    var testnet = SocketAddr.parse("192.0.2.1:0")
    if _nonlocal_bind():
        var nl = TcpListener.bind(testnet)
        assert_equal(nl.local_addr().ip(), testnet.ip())
    else:
        kind = ErrorKind.Other
        try:
            _ = TcpListener.bind(testnet)
        except e:
            kind = e.kind
        assert_equal(kind, ErrorKind.AddrNotAvailable)
    sys.keep_alive(a)


def test_from_socket_and_into_socket() raises:
    # An L1 listener with SO_REUSEPORT, adopted by L2.
    var raw = Socket.new(Domain.IPV4, SockType.STREAM)
    raw.set_reuse_port(True)
    raw.bind(_lo())
    raw.listen(8)
    assert_false(raw.nonblocking())
    var l = TcpListener.from_socket(raw^)
    assert_true(l.socket().nonblocking())
    assert_true(l.socket().reuse_port())
    # An L1 blocking client, adopted by L2: options other than O_NONBLOCK
    # are left alone (TCP_NODELAY stays off).
    var c1 = Socket.new(Domain.IPV4, SockType.STREAM)
    c1.connect(l.local_addr())
    var c = TcpStream.from_socket(c1^)
    assert_true(c.socket().nonblocking())
    assert_false(c.socket().nodelay())
    var s = l.accept().into_stream()
    c.write_all(String("adopted").as_bytes())
    var buf = List[UInt8](length=7, fill=0)
    s.read_exact(Span(buf))
    assert_equal(_text(buf), "adopted")
    # Back to L1: still nonblocking, same descriptor.
    var fd = s.raw_fd()
    var back = s^.into_socket()
    assert_equal(back.raw_fd(), fd)
    assert_true(back.nonblocking())
    var l1 = l^.into_socket()
    assert_true(l1.is_listener())


# ---- echo --------------------------------------------------------------------


def test_echo_many_sizes_interleaved() raises:
    var conn = _conn()
    var sizes: List[Int] = [
        1,
        2,
        7,
        100,
        1460,
        4096,
        65535,
        65536,
        65537,
        300_000,
        1 * MiB,
    ]
    for i in range(len(sizes)):
        var data = _pattern(sizes[i], i)
        var there = _pump(conn.c, conn.s, data)
        assert_true(_same(there, data), String("c->s size ", sizes[i]))
        var back = _pump(conn.s, conn.c, there)
        assert_true(_same(back, data), String("s->c size ", sizes[i]))


def test_zero_byte_operations_do_not_block() raises:
    var conn = _conn()
    conn.c.set_deadline(_guard())  # a blocking bug fails instead of hanging
    var empty = List[UInt8]()
    assert_equal(conn.c.write(Span(empty)), 0)
    conn.c.write_all(Span(empty))
    var nothing = List[UInt8]()
    assert_equal(conn.c.read(Span(nothing)), 0)  # no data queued, still 0
    conn.c.read_exact(Span(nothing))
    assert_equal(conn.c.peek(Span(nothing)), 0)
    var bufs = List[Span[UInt8, origin_of(empty)]]()
    bufs.append(Span(empty))
    bufs.append(Span(empty))
    assert_equal(conn.c.write_vectored(Span(bufs)), 0)
    var t = Instant.now()
    # Nothing was sent: the server has no data.
    assert_false(_ready(conn.s, POLLIN))
    assert_true(t.elapsed() < Duration.from_secs(1))


def test_write_is_partial_instead_of_blocking() raises:
    # Nobody reads: one write of 4 MiB queues what fits and returns.
    var conn = _conn(rcvbuf=4096)
    conn.c.socket().set_send_buffer_size(4096)
    conn.c.set_write_deadline(_guard())
    var data = _pattern(4 * MiB)
    var n = conn.c.write(Span(data))
    assert_true(n > 0 and n < 4 * MiB, String("wrote ", n))
    # Exactly that prefix arrives.
    var got = List[UInt8](length=n, fill=0)
    conn.s.set_read_deadline(_guard())
    conn.s.read_exact(Span(got))
    for i in range(n):
        if got[i] != data[i]:
            assert_true(False, String("mismatch at ", i))


def test_write_vectored_partial_prefix() raises:
    var conn = _conn(rcvbuf=4096)
    conn.c.socket().set_send_buffer_size(4096)
    conn.c.set_write_deadline(_guard())
    var whole = _pattern(2 * MiB, 5)
    var bufs = List[Span[UInt8, origin_of(whole)]]()
    bufs.append(Span(whole)[0:10])
    bufs.append(Span(whole)[10 : 1 * MiB])
    bufs.append(Span(whole)[1 * MiB : 2 * MiB])
    var n = conn.c.write_vectored(Span(bufs))
    assert_true(n > 10 and n < 2 * MiB, String("wrote ", n))
    var got = List[UInt8](length=n, fill=0)
    conn.s.set_read_deadline(_guard())
    conn.s.read_exact(Span(got))
    for i in range(n):
        if got[i] != whole[i]:
            assert_true(False, String("mismatch at ", i))


def test_read_vectored_scatters_in_order() raises:
    var conn = _conn()
    conn.c.write_all(String("headbody!").as_bytes())
    var a = List[UInt8](length=4, fill=0)
    var b = List[UInt8](length=16, fill=0)
    var bufs = List[Span[UInt8, origin_of(a, b)]]()
    bufs.append(a)
    bufs.append(b)
    conn.s.set_read_deadline(_guard())
    var n = conn.s.read_vectored(bufs)
    assert_equal(n, 9)
    assert_equal(_text(a), "head")
    assert_equal(String(from_utf8_lossy=Span(b)[0:5]), "body!")


def test_write_all_4mib_to_python_sink_echo() raises:
    # Our send buffer is tiny, so write_all goes through many partial sends
    # and EAGAIN waits while the child drains; then the child echoes all.
    var l = TcpListener.bind(_lo())
    l.set_deadline(_guard())
    var child = _spawn_peer("sink_echo", Int(l.local_addr().port()))
    var s = l.accept().into_stream()
    s.socket().set_send_buffer_size(64 * 1024)
    s.set_deadline(Deadline.after(Duration.from_secs(30)))
    var data = _pattern(4 * MiB, 9)
    s.write_all(Span(data))
    s.shutdown(Shutdown.WRITE)
    var back = List[UInt8]()
    var n = s.read_to_end(back)
    _ = child.wait()
    assert_equal(n, 4 * MiB)
    assert_true(_same(back, data))


def test_write_all_to_slow_python_reader() raises:
    # The child reads at most 16 KiB every 2 ms and our send buffer is
    # tiny: write_all must wait for space many times and lose nothing. (A
    # tiny receive buffer on the child would add zero-window probing, which
    # backs off to hundreds of ms per stall.)
    var l = TcpListener.bind(_lo())
    l.set_deadline(_guard())
    var child = _spawn_peer("slow_sink_echo", Int(l.local_addr().port()))
    var s = l.accept().into_stream()
    s.socket().set_send_buffer_size(4096)
    s.set_deadline(Deadline.after(Duration.from_secs(30)))
    var data = _pattern(512 * 1024, 3)
    var t = Instant.now()
    s.write_all(Span(data))
    s.shutdown(Shutdown.WRITE)
    var back = List[UInt8]()
    _ = s.read_to_end(back)
    _ = child.wait()
    assert_true(t.elapsed() > _ms(20))  # it really had to wait
    assert_true(_same(back, data))


# ---- deadlines ---------------------------------------------------------------


def test_read_deadline_expires_and_stream_stays_usable() raises:
    var conn = _conn()
    conn.c.set_read_deadline(Deadline.after(_ms(150)))
    var buf = List[UInt8](length=16, fill=0)
    var t = Instant.now()
    var kind = ErrorKind.Other
    var errno = Errno(-1)
    try:
        _ = conn.c.read(Span(buf))
    except e:
        kind = e.kind
        errno = e.errno
        assert_equal(String(e.op), "read")
    var el = t.elapsed()
    assert_equal(kind, ErrorKind.TimedOut)
    assert_equal(errno, Errno(0))
    assert_true(el >= _ms(150), String("early: ", el))
    assert_true(el < _ms(400), String("late: ", el))
    # The deadline applies to every later read too...
    t = Instant.now()
    kind = ErrorKind.Other
    try:
        _ = conn.c.peek(Span(buf))
    except e:
        kind = e.kind
        assert_equal(String(e.op), "peek")
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(t.elapsed() < _ms(100))  # already expired: no waiting
    # ...but data that is already there wins over an expired deadline.
    conn.s.write_all(String("ok").as_bytes())
    _ = wait_ready(conn.c, Int16(POLLIN), _guard(), "test")
    assert_equal(conn.c.read(Span(buf)), 2)
    # Clearing the deadline makes reads wait again; nothing was lost.
    conn.c.set_read_deadline(Deadline.none())
    conn.s.write_all(String("more").as_bytes())
    var four = List[UInt8](length=4, fill=0)
    conn.c.read_exact(Span(four))
    assert_equal(_text(four), "more")


def test_read_exact_times_out_on_short_data() raises:
    var conn = _conn()
    conn.s.write_all(String("abc").as_bytes())
    conn.c.set_read_deadline(Deadline.after(_ms(100)))
    var buf = List[UInt8](length=5, fill=0)
    var kind = ErrorKind.Other
    try:
        conn.c.read_exact(Span(buf))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.TimedOut)
    assert_equal(String(from_utf8_lossy=Span(buf)[0:3]), "abc")


def test_write_deadline_expires_when_peer_never_reads() raises:
    var conn = _conn(rcvbuf=4096)
    conn.c.socket().set_send_buffer_size(4096)
    var data = _pattern(4 * MiB, 1)
    conn.c.set_write_deadline(Deadline.after(_ms(150)))
    var t = Instant.now()
    var kind = ErrorKind.Other
    try:
        conn.c.write_all(Span(data))
    except e:
        kind = e.kind
        assert_equal(String(e.op), "write")
        assert_equal(e.errno, Errno(0))
    var el = t.elapsed()
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(el >= _ms(150), String("early: ", el))
    assert_true(el < _ms(400), String("late: ", el))
    # The stream is still usable: drain what arrived, append a marker, and
    # check the peer saw an exact prefix of `data` followed by the marker.
    var got = List[UInt8]()
    _drain(conn.s, got)
    conn.c.set_write_deadline(_guard())
    conn.c.write_all(String("TAIL").as_bytes())
    _drain(conn.s, got)
    var n = len(got)
    assert_true(n > 4)
    assert_equal(String(from_utf8_lossy=Span(got)[n - 4 : n]), "TAIL")
    for i in range(n - 4):
        if got[i] != data[i]:
            assert_true(False, String("mismatch at ", i))


def _drain(mut s: TcpStream, mut got: List[UInt8]) raises:
    """Read until 100 ms pass without data (the sender's queue is empty)."""
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


def test_accept_deadline_expires_and_listener_stays_usable() raises:
    var l = TcpListener.bind(_lo())
    l.set_deadline(Deadline.after(_ms(150)))
    var t = Instant.now()
    var kind = ErrorKind.Other
    try:
        _ = l.accept()
    except e:
        kind = e.kind
        assert_equal(String(e.op), "accept")
    var el = t.elapsed()
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(el >= _ms(150), String("early: ", el))
    assert_true(el < _ms(400), String("late: ", el))
    # A pending connection wins over the expired deadline.
    var c = TcpStream.connect(l.local_addr())
    var acc = l.accept()
    assert_equal(acc.addr, c.local_addr())


def test_set_deadline_sets_both() raises:
    var conn = _conn()
    var d = Deadline.after(Duration.from_secs(3))
    conn.c.set_deadline(d)
    assert_equal(conn.c.read_deadline(), d)
    assert_equal(conn.c.write_deadline(), d)
    conn.c.set_write_deadline(Deadline.none())
    assert_equal(conn.c.read_deadline(), d)
    assert_true(conn.c.write_deadline().is_none())


# ---- connect -----------------------------------------------------------------


def test_connect_refused() raises:
    var cp = _closed_port()
    var kind = ErrorKind.Other
    try:
        _ = TcpStream.connect(cp[1])
    except e:
        kind = e.kind
        assert_equal(String(e.op), "connect")
        assert_equal(e.errno, Errno.ECONNREFUSED)
    assert_equal(kind, ErrorKind.ConnectionRefused)
    kind = ErrorKind.Other
    var t = Instant.now()
    try:
        _ = TcpStream.connect_timeout(cp[1], Duration.from_secs(5))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.ConnectionRefused)
    assert_true(t.elapsed() < Duration.from_secs(1))


def test_connect_timeout_to_unanswering_address() raises:
    var bh = _blackhole()
    var t = Instant.now()
    var kind = ErrorKind.Other
    try:
        _ = TcpStream.connect_timeout(bh.addr, _ms(200))
    except e:
        kind = e.kind
        assert_equal(String(e.op), "connect")
        assert_equal(e.errno, Errno(0))
    var el = t.elapsed()
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(el >= _ms(200), String("early: ", el))
    assert_true(el < _ms(450), String("late: ", el))
    # An already expired deadline checks once and gives up at once.
    t = Instant.now()
    kind = ErrorKind.Other
    try:
        _ = TcpStream.connect_deadline(bh.addr, Deadline.after(Duration.ZERO))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.TimedOut)
    assert_true(t.elapsed() < _ms(100))
    # Freeing the queue slot makes the same address answer again.
    _ = bh.l.accept()
    var c = TcpStream.connect_timeout(bh.addr, Duration.from_secs(5))
    assert_equal(c.peer_addr(), bh.addr)
    sys.keep_alive(bh)


def test_connect_timeout_rejects_zero_and_accepts_max() raises:
    var l = TcpListener.bind(_lo())
    var kind = ErrorKind.Other
    try:
        _ = TcpStream.connect_timeout(l.local_addr(), Duration.ZERO)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)
    var c = TcpStream.connect_timeout(l.local_addr(), Duration.MAX)
    assert_true(c.socket().nodelay())
    var acc = l.accept()
    assert_equal(acc.addr, c.local_addr())


def test_connect_to_port_zero_is_refused() raises:
    # Port 0 is never listening: refused at once, not a hang.
    var kind = ErrorKind.Other
    try:
        _ = TcpStream.connect_timeout(
            SocketAddr.parse("127.0.0.1:0"), Duration.from_secs(2)
        )
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.ConnectionRefused)


# ---- EOF, reset, half-close, peek ---------------------------------------------


def test_eof_after_orderly_close() raises:
    var l = TcpListener.bind(_lo())
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    s.write_all(String("bye").as_bytes())
    s^.close()
    c.set_read_deadline(_guard())
    var out = List[UInt8]()
    assert_equal(c.read_to_end(out), 3)
    assert_equal(_text(out), "bye")
    var buf = List[UInt8](length=4, fill=0)
    assert_equal(c.read(Span(buf)), 0)  # EOF is sticky
    assert_equal(c.peek(Span(buf)), 0)
    var kind = ErrorKind.Other
    try:
        c.read_exact(Span(buf))
    except e:
        kind = e.kind
        assert_equal(String(e.op), "read")
    assert_equal(kind, ErrorKind.UnexpectedEof)


def test_reset_after_abortive_close() raises:
    var l = TcpListener.bind(_lo())
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    s.socket().set_linger(0)  # close sends RST
    s^.close()
    c.set_deadline(_guard())
    var buf = List[UInt8](length=4, fill=0)
    var kind = ErrorKind.Other
    try:
        _ = c.read(Span(buf))
    except e:
        kind = e.kind
        assert_equal(String(e.op), "read")
    assert_equal(kind, ErrorKind.ConnectionReset)
    # Writing to the dead connection raises (MSG_NOSIGNAL: no SIGPIPE kills
    # the test process).
    kind = ErrorKind.Other
    try:
        c.write_all(String("anyone?").as_bytes())
    except e:
        kind = e.kind
        assert_equal(String(e.op), "write")
    assert_true(
        kind == ErrorKind.BrokenPipe or kind == ErrorKind.ConnectionReset,
        String(kind),
    )


def test_unread_data_turns_close_into_reset() raises:
    # Closing with unread received data makes Linux send RST, not FIN.
    var l = TcpListener.bind(_lo())
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    c.write_all(String("ignored").as_bytes())
    _ = wait_ready(s, Int16(POLLIN), _guard(), "test")
    s^.close()
    c.set_read_deadline(_guard())
    var buf = List[UInt8](length=4, fill=0)
    var kind = ErrorKind.Other
    try:
        _ = c.read(Span(buf))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.ConnectionReset)


def test_half_close() raises:
    var conn = _conn()
    conn.c.set_deadline(_guard())
    conn.s.set_deadline(_guard())
    conn.c.write_all(String("request").as_bytes())
    conn.c.shutdown(Shutdown.WRITE)
    var req = List[UInt8]()
    assert_equal(conn.s.read_to_end(req), 7)  # sees EOF after the data
    assert_equal(_text(req), "request")
    # The other direction still works.
    conn.s.write_all(String("response").as_bytes())
    conn.s.shutdown(Shutdown.WRITE)
    var resp = List[UInt8]()
    assert_equal(conn.c.read_to_end(resp), 8)
    assert_equal(_text(resp), "response")
    # Writing after our own shutdown(WRITE) is EPIPE.
    var kind = ErrorKind.Other
    try:
        _ = conn.c.write(String("late").as_bytes())
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.BrokenPipe)


def test_shutdown_read_makes_reads_return_eof() raises:
    var conn = _conn()
    conn.c.shutdown(Shutdown.READ)
    conn.c.set_read_deadline(_guard())
    var buf = List[UInt8](length=4, fill=0)
    assert_equal(conn.c.read(Span(buf)), 0)


def test_peek_does_not_consume() raises:
    var conn = _conn()
    conn.s.write_all(String("abcdef").as_bytes())
    conn.c.set_read_deadline(_guard())
    var three = List[UInt8](length=3, fill=0)
    assert_equal(conn.c.peek(Span(three)), 3)
    assert_equal(_text(three), "abc")
    assert_equal(conn.c.peek(Span(three)), 3)
    assert_equal(_text(three), "abc")
    var six = List[UInt8](length=6, fill=0)
    conn.c.read_exact(Span(six))
    assert_equal(_text(six), "abcdef")
    # With nothing queued, peek waits under the read deadline.
    conn.c.set_read_deadline(Deadline.after(_ms(80)))
    var kind = ErrorKind.Other
    try:
        _ = conn.c.peek(Span(three))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.TimedOut)


# ---- try_clone ---------------------------------------------------------------


def test_try_clone_is_independent() raises:
    var l = TcpListener.bind(_lo())
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    var d = Deadline.after(Duration.from_secs(7))
    c.set_read_deadline(d)
    var c2 = c.try_clone()
    assert_true(c2.raw_fd() != c.raw_fd())
    assert_true((_fd_flags(c2) & FD_CLOEXEC) != 0)
    # The clone starts with a copy of the deadlines...
    assert_equal(c2.read_deadline(), d)
    # ...and changing them affects only that handle.
    c2.set_read_deadline(Deadline.after(_ms(50)))
    assert_equal(c.read_deadline(), d)
    var buf = List[UInt8](length=8, fill=0)
    var kind = ErrorKind.Other
    try:
        _ = c2.read(Span(buf))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.TimedOut)
    # Both handles reach the same connection.
    c2.write_all(String("from-c2").as_bytes())
    c.write_all(String("|from-c").as_bytes())
    var got = List[UInt8](length=14, fill=0)
    s.set_read_deadline(_guard())
    s.read_exact(Span(got))
    assert_equal(_text(got), "from-c2|from-c")
    # Closing one handle does not end the connection...
    c^.close()
    s.set_read_deadline(Deadline.after(_ms(80)))
    kind = ErrorKind.Other
    try:
        _ = s.read(Span(buf))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.TimedOut)  # no EOF yet
    s.write_all(String("still").as_bytes())
    c2.set_read_deadline(_guard())
    var five = List[UInt8](length=5, fill=0)
    c2.read_exact(Span(five))
    assert_equal(_text(five), "still")
    # ...closing the last one does.
    c2^.close()
    s.set_read_deadline(_guard())
    assert_equal(s.read(Span(buf)), 0)


def test_listener_try_clone_accepts() raises:
    var l = TcpListener.bind(_lo())
    l.set_deadline(_guard())
    var l2 = l.try_clone()
    assert_equal(l2.deadline(), l.deadline())
    assert_equal(l2.local_addr(), l.local_addr())
    var c = TcpStream.connect(l.local_addr())
    var acc = l2.accept()
    assert_equal(acc.addr, c.local_addr())
    sys.keep_alive(l)


# ---- resource hygiene ----------------------------------------------------------


def test_no_fd_leak_over_5000_cycles() raises:
    var l = TcpListener.bind(_lo())
    l.set_deadline(_guard())
    var addr = l.local_addr()
    var cp = _closed_port()
    var bh = _blackhole()
    var before = _fd_count()
    for _ in range(5000):
        var c = TcpStream.connect(addr)
        var acc = l.accept()
        # RST instead of FIN: no TIME_WAIT pile-up across repeated runs.
        c.socket().set_linger(0)
        _ = c^
        _ = acc^
    # Error paths must close their socket too. Count the outcomes: if a
    # helper stopped producing its error (the closed port started
    # listening, the blackhole's queue slot freed), these loops would
    # quietly run the success path instead.
    var refused = 0
    var other = String()
    for _ in range(200):
        try:
            _ = TcpStream.connect(cp[1])
        except e:
            if e.kind == ErrorKind.ConnectionRefused:
                refused += 1
            else:
                other = String(e)
    var timed_out = 0
    for _ in range(50):
        try:
            _ = TcpStream.connect_deadline(
                bh.addr, Deadline.after(Duration.ZERO)
            )
        except e:
            if e.kind == ErrorKind.TimedOut:
                timed_out += 1
            else:
                other = String(e)
    var after = _fd_count()
    assert_equal(refused, 200, other)
    assert_equal(timed_out, 50, other)
    assert_equal(after, before)
    sys.keep_alive(l)
    sys.keep_alive(cp)
    sys.keep_alive(bh)


def test_close_reports_and_closes() raises:
    var l = TcpListener.bind(_lo())
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    var before = _fd_count()
    c^.close()
    assert_equal(_fd_count(), before - 1)
    s.set_read_deadline(_guard())
    var buf = List[UInt8](length=1, fill=0)
    assert_equal(s.read(Span(buf)), 0)
    l^.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
