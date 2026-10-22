"""Tests for net.socket (L1): creation, addresses, connection setup, I/O and
error reporting over loopback, socketpair and Unix sockets.

Option round trips live in test_socket_options.mojo.
"""

from std.os import getenv, remove, rmdir
from std.sys import size_of
from std.tempfile import mkdtemp
from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_true,
)

from linux import Errno, ErrorKind, IoError, OwnedFd, check
from linux import sys
from linux.abi import SockaddrIn6
from linux.consts import (
    AF_INET6,
    F_GETFD,
    FD_CLOEXEC,
    IOV_MAX,
    MSG_DONTWAIT,
    MSG_TRUNC,
    O_CLOEXEC,
    POLLOUT,
    SIGPIPE,
    SO_TYPE,
    SOCK_CLOEXEC,
    SOCK_STREAM,
    SOL_SOCKET,
    TCP_CLOSE,
    TCP_ESTABLISHED,
    TCP_INFO,
    TCP_LISTEN,
    IPPROTO_TCP,
)
from linux.nr import SYS_getegid, SYS_geteuid, SYS_getpid, SYS_rt_sigaction
from linux.poll import wait_ready
from linux.syscall import err_of, is_err, syscall0, syscall4
from linux.time import Deadline, Duration
from net.addr import IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UnixAddr
from net.socket import (
    Accepted,
    Domain,
    Protocol,
    Shutdown,
    SockType,
    Socket,
    SocketPair,
    TcpInfo,
)


# ---- helpers -----------------------------------------------------------------


def _deadline() -> Deadline:
    return Deadline.after(Duration.from_secs(5))


def _listener(addr: StaticString) raises -> Socket:
    var a = SocketAddr.parse(addr)
    var l = Socket.new(Domain.for_address(a), SockType.STREAM)
    l.bind(a)
    l.listen(16)
    return l^


def _tcp_pair(addr: StaticString) raises -> SocketPair:
    """(client, accepted server end) over loopback."""
    var l = _listener(addr)
    var c = Socket.new(l.domain(), SockType.STREAM)
    c.connect(l.local_addr())
    var acc = l.accept()
    return SocketPair(c^, acc^.into_socket())


def _ipv6(test: StaticString, need_loopback: Bool = True) raises -> Bool:
    """Whether this host has IPv6 (with `need_loopback`: a usable [::1]),
    decided with raw syscalls, not with the code under test. Only
    EAFNOSUPPORT from socket(AF_INET6) or EADDRNOTAVAIL from bind([::1]:0)
    mean "no IPv6"; any other failure raises, so a regression is never
    reported as a skip. Without IPv6 this prints a visible skip line (which
    tools/run_tests.sh shows and counts) and the test returns early, unless
    MOJO_TCP_REQUIRE_IPV6=1 turns it into a failure."""
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
    if getenv("MOJO_TCP_REQUIRE_IPV6") == "1":
        raise Error(test, ": no IPv6 (", why, ") but MOJO_TCP_REQUIRE_IPV6=1")
    print(String("    (skipped: ", test, ": no IPv6, ", why, ")"))
    return False


def _nonlocal_bind() raises -> Bool:
    """net.ipv4.ip_nonlocal_bind=1 (load balancers, keepalived hosts) lets
    a socket bind any IPv4 address, so binding TEST-NET-1 then succeeds."""
    with open("/proc/sys/net/ipv4/ip_nonlocal_bind", "r") as f:
        return Int(f.read().strip()) != 0


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


def _unix_pair() raises -> SocketPair:
    return Socket.pair(Domain.UNIX, SockType.STREAM)


def _bytes(s: StringSlice) -> List[UInt8]:
    var out = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        out.append(b)
    return out^


def _text(buf: List[UInt8], n: Int) -> String:
    return String(from_utf8_lossy=Span(buf)[0:n])


def _recv_text(s: Socket, cap: Int = 256) raises -> String:
    var buf = List[UInt8](length=cap, fill=0)
    var n = s.recv(Span(buf))
    return _text(buf, n)


def _recv_exact(s: Socket, n: Int) raises -> String:
    var buf = List[UInt8](length=n, fill=0)
    var got = 0
    while got < n:
        var r = s.recv(Span(buf)[got:n])
        if r == 0:
            break
        got += r
    return _text(buf, got)


def _closed_port() raises -> Tuple[Socket, SocketAddr]:
    """A bound but not listening loopback socket: connecting to its port
    is refused, and keeping it bound stops anyone else taking the port."""
    var s = Socket.new(Domain.IPV4, SockType.STREAM)
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var a = s.local_addr()
    return (s^, a)


def _fd_flags(s: Socket) raises -> Int:
    return check("fcntl(F_GETFD)", sys.fcntl(s, F_GETFD))


def _pid() -> Int:
    return syscall0(SYS_getpid)


# ---- creation ----------------------------------------------------------------


def test_new_reports_type_domain_protocol() raises:
    var t = Socket.new(Domain.IPV4, SockType.STREAM)
    assert_equal(t.socket_type(), SockType.STREAM)
    assert_equal(t.domain(), Domain.IPV4)
    assert_equal(t.protocol(), Protocol.TCP)
    assert_false(t.is_listener())
    assert_true((_fd_flags(t) & FD_CLOEXEC) != 0)
    assert_false(t.nonblocking())
    var u = Socket.new(Domain.IPV4, SockType.DGRAM)
    assert_equal(u.socket_type(), SockType.DGRAM)
    assert_equal(u.protocol(), Protocol.UDP)
    var x = Socket.new(Domain.UNIX, SockType.SEQPACKET)
    assert_equal(x.socket_type(), SockType.SEQPACKET)
    assert_equal(x.domain(), Domain.UNIX)
    var e = Socket.new(Domain.IPV4, SockType.STREAM, Protocol.TCP)
    assert_equal(e.protocol(), Protocol.TCP)
    assert_equal(String(Domain.IPV6), "IPV6")
    assert_equal(String(SockType.DGRAM), "DGRAM")
    assert_equal(String(Domain(12345)), "Domain(12345)")


def test_new_nonblocking_and_cloexec() raises:
    var s = Socket.new(Domain.IPV4, SockType.STREAM, nonblocking=True)
    assert_true(s.nonblocking())
    assert_true((_fd_flags(s) & FD_CLOEXEC) != 0)
    # SO_TYPE reports the plain type, without SOCK_NONBLOCK/SOCK_CLOEXEC.
    assert_equal(s.socket_type(), SockType.STREAM)


def test_new_invalid_arguments() raises:
    var kind = ErrorKind.Other
    try:
        _ = Socket.new(Domain(4242), SockType.STREAM)
    except e:
        kind = e.kind
        assert_equal(String(e.op), "socket")
    assert_equal(kind, ErrorKind.InvalidInput)  # EAFNOSUPPORT
    kind = ErrorKind.Other
    try:
        _ = Socket.new(Domain.UNIX, SockType.STREAM, Protocol.TCP)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.Unsupported)  # EPROTONOSUPPORT
    kind = ErrorKind.Other
    try:
        _ = Socket.new(Domain.IPV4, SockType(9999))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)


def test_pair_round_trip_and_flags() raises:
    var p = _unix_pair()
    var a = p.first.take()
    var b = p.second.take()
    assert_true((_fd_flags(a) & FD_CLOEXEC) != 0)
    assert_true((_fd_flags(b) & FD_CLOEXEC) != 0)
    assert_false(a.nonblocking())
    assert_equal(a.send(String("ping").as_bytes()), 4)
    assert_equal(_recv_text(b), "ping")
    assert_equal(b.send(String("pong").as_bytes()), 4)
    assert_equal(_recv_text(a), "pong")
    assert_true(a.local_unix_addr().is_unnamed())
    assert_true(b.peer_unix_addr().is_unnamed())
    var q = Socket.pair(Domain.UNIX, SockType.DGRAM, nonblocking=True)
    assert_true(q.first.value().nonblocking())
    assert_true(q.second.value().nonblocking())
    assert_equal(q.first.value().socket_type(), SockType.DGRAM)
    # Only AF_UNIX supports socketpair.
    var kind = ErrorKind.Other
    try:
        _ = Socket.pair(Domain.IPV4, SockType.STREAM)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.Unsupported)  # EOPNOTSUPP


def test_owned_fd_round_trip_and_clone() raises:
    var p = _unix_pair()
    var a = p.first.take()
    var b = p.second.take()
    var raw = a.raw_fd()
    var fd = a^.into_fd()
    assert_equal(fd.raw_fd(), raw)
    assert_true(sys.fcntl(fd, F_GETFD) >= 0)  # still open
    var a2 = Socket(fd^)
    assert_equal(a2.raw_fd(), raw)
    var dup = a2.try_clone()
    assert_true(dup.raw_fd() != raw)
    assert_true((_fd_flags(dup) & FD_CLOEXEC) != 0)
    # Either descriptor reaches the same connection.
    _ = dup.send(String("via-dup").as_bytes())
    assert_equal(_recv_text(b), "via-dup")
    a2^.close()
    _ = dup.send(String("still").as_bytes())
    assert_equal(_recv_text(b), "still")
    dup^.close()
    var buf = List[UInt8](length=4, fill=0)
    assert_equal(b.recv(Span(buf)), 0)  # all descriptors closed: EOF


def test_operations_on_bad_descriptors() raises:
    # A Socket around fd -1 reports EBADF as kind Closed (its destructor's
    # close(-1) fails silently).
    var bad = Socket(OwnedFd(unsafe_from_raw=-1))
    var kind = ErrorKind.Other
    var errno = Errno(0)
    try:
        _ = bad.send(String("x").as_bytes())
    except e:
        kind = e.kind
        errno = e.errno
    assert_equal(kind, ErrorKind.Closed)
    assert_equal(errno, Errno.EBADF)
    # A pipe is not a socket: ENOTSOCK.
    var fds = Array[Int32, 2](fill=-1)
    _ = check("pipe2", sys.pipe2(fds, O_CLOEXEC))
    var w = OwnedFd(unsafe_from_raw=fds[1])
    var r = Socket(OwnedFd(unsafe_from_raw=fds[0]))
    errno = Errno(0)
    try:
        _ = r.socket_type()
    except e:
        errno = e.errno
    assert_equal(errno, Errno.ENOTSOCK)
    sys.keep_alive(w)


# ---- TCP connect / accept ----------------------------------------------------


def _check_connect_accept(addr: StaticString) raises:
    var l = _listener(addr)
    assert_true(l.is_listener())
    var bound = l.local_addr()
    assert_true(bound.port() != 0)
    var c = Socket.new(Domain.for_address(bound), SockType.STREAM)
    c.connect(bound)
    var acc = l.accept()
    var peer = acc.addr
    var srv = acc^.into_socket()
    assert_equal(peer, c.local_addr())
    assert_equal(c.peer_addr(), bound)
    assert_equal(srv.local_addr(), bound)
    assert_equal(srv.peer_addr(), peer)
    assert_false(srv.is_listener())
    assert_equal(c.send(String("hello").as_bytes()), 5)
    assert_equal(_recv_exact(srv, 5), "hello")
    assert_equal(srv.send(String("world!").as_bytes()), 6)
    assert_equal(_recv_exact(c, 6), "world!")


def test_tcp_v4_connect_accept() raises:
    _check_connect_accept("127.0.0.1:0")


def test_tcp_v6_connect_accept() raises:
    if not _ipv6("test_tcp_v6_connect_accept"):
        return
    _check_connect_accept("[::1]:0")


def test_accept4_sets_cloexec_and_nonblock() raises:
    var l = _listener("127.0.0.1:0")
    var a = l.local_addr()
    var c1 = Socket.new(Domain.IPV4, SockType.STREAM)
    c1.connect(a)
    var c2 = Socket.new(Domain.IPV4, SockType.STREAM)
    c2.connect(a)
    var nb = l.accept(nonblocking=True).into_socket()
    assert_true(nb.nonblocking())
    assert_true((_fd_flags(nb) & FD_CLOEXEC) != 0)
    var blk = l.accept().into_socket()
    assert_false(blk.nonblocking())
    assert_true((_fd_flags(blk) & FD_CLOEXEC) != 0)
    # A nonblocking listener does not make accepted sockets nonblocking.
    l.set_nonblocking(True)
    var c3 = Socket.new(Domain.IPV4, SockType.STREAM)
    c3.connect(a)
    var acc = l.accept()
    assert_false(acc.socket.nonblocking())
    sys.keep_alive(c1)
    sys.keep_alive(c2)
    sys.keep_alive(c3)


def test_accept_on_idle_nonblocking_listener_would_block() raises:
    var l = _listener("127.0.0.1:0")
    l.set_nonblocking(True)
    var kind = ErrorKind.Other
    try:
        _ = l.accept()
    except e:
        kind = e.kind
        assert_equal(String(e.op), "accept4")
    assert_equal(kind, ErrorKind.WouldBlock)


def test_accept_on_non_listener_is_invalid() raises:
    var s = Socket.new(Domain.IPV4, SockType.STREAM)
    var kind = ErrorKind.Other
    try:
        _ = s.accept()
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)  # EINVAL


def test_listen_backlog_extremes() raises:
    var backlogs: List[Int] = [0, -1, Int.MAX, Int.MIN, 1 << 32]
    for b in backlogs:
        var s = Socket.new(Domain.IPV4, SockType.STREAM)
        s.bind(SocketAddr.parse("127.0.0.1:0"))
        s.listen(b)
        assert_true(s.is_listener())
        # The listener really accepts (a wrapped backlog of 0 still queues
        # one connection, so connect + accept must work for every value).
        var c = Socket.new(Domain.IPV4, SockType.STREAM)
        c.connect(s.local_addr())
        _ = s.accept()
        sys.keep_alive(c)


def test_bind_addr_in_use() raises:
    var a = Socket.new(Domain.IPV4, SockType.STREAM)
    a.bind(SocketAddr.parse("127.0.0.1:0"))
    a.listen(1)
    var b = Socket.new(Domain.IPV4, SockType.STREAM)
    var kind = ErrorKind.Other
    try:
        b.bind(a.local_addr())
    except e:
        kind = e.kind
        assert_equal(String(e.op), "bind")
    assert_equal(kind, ErrorKind.AddrInUse)
    # Binding twice is EINVAL.
    kind = ErrorKind.Other
    try:
        a.bind(SocketAddr.parse("127.0.0.1:0"))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)


def test_bind_family_mismatch_and_unavailable_addr() raises:
    var v4 = Socket.new(Domain.IPV4, SockType.STREAM)
    var kind = ErrorKind.Other
    try:
        v4.bind(SocketAddr.parse("[::1]:0"))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)  # EINVAL/EAFNOSUPPORT
    # TEST-NET-1 is not a local address: EADDRNOTAVAIL, unless the host
    # allows binding non-local addresses.
    var testnet = SocketAddr.parse("192.0.2.1:0")
    if _nonlocal_bind():
        var nl = Socket.new(Domain.IPV4, SockType.STREAM)
        nl.bind(testnet)
        assert_equal(nl.local_addr().ip(), testnet.ip())
        return
    kind = ErrorKind.Other
    try:
        v4.bind(testnet)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.AddrNotAvailable)


def test_peer_addr_not_connected_and_shutdown_unconnected() raises:
    var s = Socket.new(Domain.IPV4, SockType.STREAM)
    var kind = ErrorKind.Other
    try:
        _ = s.peer_addr()
    except e:
        kind = e.kind
        assert_equal(String(e.op), "getpeername")
    assert_equal(kind, ErrorKind.NotConnected)
    kind = ErrorKind.Other
    try:
        s.shutdown(Shutdown.WRITE)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.NotConnected)
    # An unbound IPv4 socket's local address is 0.0.0.0:0.
    var la = s.local_addr()
    assert_equal(la.ip(), IpAddr(Ipv4Addr.UNSPECIFIED))
    assert_equal(la.port(), 0)
    # local_addr on a Unix socket: wrong family for SocketAddr.
    var p = _unix_pair()
    kind = ErrorKind.Other
    try:
        _ = p.first.value().local_addr()
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)


def test_blocking_connect_refused() raises:
    var cp = _closed_port()
    var c = Socket.new(Domain.IPV4, SockType.STREAM)
    var kind = ErrorKind.Other
    try:
        c.connect(cp[1])
    except e:
        kind = e.kind
        assert_equal(String(e.op), "connect")
    assert_equal(kind, ErrorKind.ConnectionRefused)
    # Nothing pending afterwards: connect already reported it.
    assert_false(Bool(c.take_error()))


def test_nonblocking_connect_refused_via_take_error() raises:
    var cp = _closed_port()
    var c = Socket.new(Domain.IPV4, SockType.STREAM, nonblocking=True)
    var raised = False
    var immediate = False
    var errno = Errno(0)
    try:
        c.connect(cp[1])
    except e:
        raised = True
        immediate = e.kind == ErrorKind.ConnectionRefused  # RST beat return
        errno = e.errno
    assert_true(raised, "connect to a closed port succeeded")
    if not immediate:
        assert_equal(errno, Errno.EINPROGRESS)
    if not immediate:
        var rev = wait_ready(c, Int16(POLLOUT), _deadline(), "wait")
        assert_true((Int(rev) & POLLOUT) != 0)
        var err = c.take_error()
        assert_true(Bool(err))
        assert_equal(err.value().kind, ErrorKind.ConnectionRefused)
        assert_equal(err.value().errno, Errno.ECONNREFUSED)
        assert_equal(String(err.value().op), "SO_ERROR")
    # SO_ERROR is cleared by reading it.
    assert_false(Bool(c.take_error()))


def test_nonblocking_connect_success() raises:
    var l = _listener("127.0.0.1:0")
    var c = Socket.new(Domain.IPV4, SockType.STREAM, nonblocking=True)
    try:
        c.connect(l.local_addr())
    except e:
        assert_equal(e.kind, ErrorKind.InProgress)
    _ = wait_ready(c, Int16(POLLOUT), _deadline(), "wait")
    assert_false(Bool(c.take_error()))
    assert_equal(c.peer_addr(), l.local_addr())
    # Linux: the first connect after the handshake completed reports that
    # completion (returns 0); only the next one is EISCONN. (A failed
    # attempt would instead be reported once and then reset the socket,
    # which is why `connect` documents poll + take_error.)
    c.connect(l.local_addr())
    var kind = ErrorKind.Other
    try:
        c.connect(l.local_addr())
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.AlreadyConnected)
    var srv = l.accept().into_socket()
    _ = c.send(String("nb").as_bytes())
    assert_equal(_recv_exact(srv, 2), "nb")


def test_take_error_none_on_fresh_socket() raises:
    var s = Socket.new(Domain.IPV4, SockType.STREAM)
    assert_false(Bool(s.take_error()))


# ---- Unix sockets ------------------------------------------------------------


def test_unix_pathname_in_temp_dir() raises:
    var dir = _socket_dir("mojo_tcp_sock_", "nope.sock")
    var path = dir + "/s.sock"
    try:
        _unix_pathname_body(dir, path)
    finally:
        try:
            remove(path)
        except:
            pass
        rmdir(dir)


def _unix_pathname_body(dir: String, path: String) raises:
    # Separate function: a `try` whose first call raises IoError cannot also
    # call the asserts (which raise Error).
    var want = UnixAddr.from_pathname(path)
    var l = Socket.new(Domain.UNIX, SockType.STREAM)
    l.bind_unix(want)
    l.listen(4)
    assert_equal(l.local_unix_addr(), want)
    var c = Socket.new(Domain.UNIX, SockType.STREAM)
    c.connect_unix(want)
    var acc = l.accept_unix()
    assert_true(acc.addr.is_unnamed())  # the client never bound
    var srv = acc^.into_socket()
    assert_equal(c.peer_unix_addr(), want)
    assert_true(srv.peer_unix_addr().is_unnamed())
    assert_equal(srv.local_unix_addr(), want)
    _ = c.send(String("over unix").as_bytes())
    assert_equal(_recv_exact(srv, 9), "over unix")
    # The socket file exists now: binding it again is EADDRINUSE.
    var again = Socket.new(Domain.UNIX, SockType.STREAM)
    var kind = ErrorKind.Other
    try:
        again.bind_unix(want)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.AddrInUse)
    # A missing path: ENOENT.
    var missing = Socket.new(Domain.UNIX, SockType.STREAM)
    kind = ErrorKind.Other
    try:
        missing.connect_unix(UnixAddr.from_pathname(dir + "/nope.sock"))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.NotFound)
    # peer_cred through an accepted connection matches this process.
    var cred = srv.peer_cred()
    assert_equal(Int(cred.pid), _pid())


def test_unix_abstract_and_refused() raises:
    var name = String("mojo_tcp.test_socket.", _pid())
    var want = UnixAddr.from_abstract_name(name)
    var l = Socket.new(Domain.UNIX, SockType.STREAM)
    l.bind_unix(want)
    l.listen(4)
    assert_equal(l.local_unix_addr(), want)
    var c = Socket.new(Domain.UNIX, SockType.STREAM)
    c.connect_unix(want)
    assert_equal(c.peer_unix_addr(), want)
    var srv = l.accept_unix().into_socket()
    _ = srv.send(String("abs").as_bytes())
    assert_equal(_recv_exact(c, 3), "abs")
    # An abstract name nobody listens on: ECONNREFUSED.
    var other = Socket.new(Domain.UNIX, SockType.STREAM)
    var kind = ErrorKind.Other
    try:
        other.connect_unix(UnixAddr.from_abstract_name(name + ".none"))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.ConnectionRefused)
    # Autobind via the unnamed address.
    var auto = Socket.new(Domain.UNIX, SockType.DGRAM)
    auto.bind_unix(UnixAddr.unnamed())
    var got = auto.local_unix_addr()
    assert_true(got.is_abstract())
    assert_equal(len(got.name()), 5)


def test_unix_dgram_recv_from_named_and_unnamed() raises:
    var name = String("mojo_tcp.test_socket.dgram.", _pid())
    var rx_addr = UnixAddr.from_abstract_name(name)
    var rx = Socket.new(Domain.UNIX, SockType.DGRAM)
    rx.bind_unix(rx_addr)
    var anon = Socket.new(Domain.UNIX, SockType.DGRAM)
    assert_equal(anon.send_to_unix(String("one").as_bytes(), rx_addr), 3)
    var named = Socket.new(Domain.UNIX, SockType.DGRAM)
    var tx_addr = UnixAddr.from_abstract_name(name + ".tx")
    named.bind_unix(tx_addr)
    assert_equal(named.send_to_unix(String("two!").as_bytes(), rx_addr), 4)
    var buf = List[UInt8](length=16, fill=0)
    var r1 = rx.recv_from_unix(Span(buf))
    assert_equal(r1[0], 3)
    assert_equal(_text(buf, 3), "one")
    assert_true(r1[1].is_unnamed())  # the kernel reports length 0 here
    var r2 = rx.recv_from_unix(Span(buf))
    assert_equal(r2[0], 4)
    assert_equal(r2[1], tx_addr)


# ---- I/O ---------------------------------------------------------------------


def test_send_vectored_three_buffers_with_an_empty_one() raises:
    var p = _unix_pair()
    var a = _bytes("head:")
    var empty = List[UInt8]()
    var b = _bytes("body")
    var bufs = List[Span[UInt8, origin_of(a, empty, b)]]()
    bufs.append(a)
    bufs.append(empty)
    bufs.append(b)
    assert_equal(p.first.value().send_vectored(bufs), 9)
    assert_equal(_recv_exact(p.second.value(), 9), "head:body")
    # Zero buffers: nothing sent, no error.
    var none = List[Span[UInt8, origin_of(a)]]()
    assert_equal(p.first.value().send_vectored(none), 0)


def test_send_vectored_over_tcp_with_slices_of_one_buffer() raises:
    var tp = _tcp_pair("127.0.0.1:0")
    var msg = _bytes("0123456789")
    # A literal of mutable spans would alias; immutable ones are fine.
    var parts: List[ImmSpan[UInt8, origin_of(msg)]] = [
        Span(msg)[0:3],
        Span(msg)[3:3],
        Span(msg)[3:10],
    ]
    assert_equal(tp.first.value().send_vectored(parts), 10)
    assert_equal(_recv_exact(tp.second.value(), 10), "0123456789")


def test_send_vectored_heap_path_and_iov_max_cap() raises:
    var p = _unix_pair()
    var data = List[UInt8](length=IOV_MAX + 100, fill=0)
    for i in range(len(data)):
        data[i] = UInt8(65 + i % 26)
    # 17 buffers: just past the on-stack iovec array.
    var seventeen = List[Span[UInt8, origin_of(data)]]()
    for i in range(17):
        seventeen.append(Span(data)[i : i + 1])
    assert_equal(p.first.value().send_vectored(seventeen), 17)
    assert_equal(_recv_exact(p.second.value(), 17), _text(data, 17))
    # More than IOV_MAX buffers: only the first IOV_MAX are sent (a short
    # write), never EMSGSIZE.
    var many = List[Span[UInt8, origin_of(data)]]()
    for i in range(len(data)):
        many.append(Span(data)[i : i + 1])
    assert_equal(len(many), IOV_MAX + 100)
    assert_equal(p.first.value().send_vectored(many), IOV_MAX)
    var got = _recv_exact(p.second.value(), IOV_MAX)
    assert_equal(got, _text(data, IOV_MAX))


def test_recv_vectored_scatter_and_truncation_flag() raises:
    var p = _unix_pair()
    _ = p.first.value().send(String("abcdefghij").as_bytes())
    var x = List[UInt8](length=3, fill=0)
    var z = List[UInt8]()
    var y = List[UInt8](length=4, fill=0)
    var bufs = List[Span[UInt8, origin_of(x, z, y)]]()
    bufs.append(x)
    bufs.append(z)
    bufs.append(y)
    assert_equal(p.second.value().recv_vectored(bufs), 7)
    assert_equal(_text(x, 3), "abc")
    assert_equal(_text(y, 4), "defg")
    assert_equal(_recv_exact(p.second.value(), 3), "hij")
    # Datagram larger than the buffers: MSG_TRUNC in msg_flags.
    var d = Socket.pair(Domain.UNIX, SockType.DGRAM)
    _ = d.first.value().send(String("0123456789").as_bytes())
    var small = List[UInt8](length=4, fill=0)
    var one = List[Span[UInt8, origin_of(small)]]()
    one.append(small)
    var r = d.second.value().recv_vectored_with_flags(one, 0)
    assert_equal(r[0], 4)
    assert_true((r[1] & MSG_TRUNC) != 0)
    assert_equal(_text(small, 4), "0123")


def test_recv_eof_after_peer_shutdown_write() raises:
    var tp = _tcp_pair("127.0.0.1:0")
    var c = tp.first.take()
    var srv = tp.second.take()
    _ = c.send(String("last").as_bytes())
    c.shutdown(Shutdown.WRITE)
    assert_equal(_recv_exact(srv, 4), "last")
    var buf = List[UInt8](length=8, fill=0)
    assert_equal(srv.recv(Span(buf)), 0)
    assert_equal(srv.recv(Span(buf)), 0)  # EOF is sticky
    # Half-close: the other direction still works.
    _ = srv.send(String("reply").as_bytes())
    assert_equal(_recv_exact(c, 5), "reply")
    # Sending after our own SHUT_WR: EPIPE (no SIGPIPE).
    var kind = ErrorKind.Other
    try:
        _ = c.send(String("x").as_bytes())
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.BrokenPipe)
    # SHUT_RD: recv returns EOF right away.
    srv.shutdown(Shutdown.READ)
    assert_equal(srv.recv(Span(buf)), 0)
    # SHUT_RDWR on the half-closed end still succeeds while srv is open
    # (once srv closes, c reaches TIME_WAIT and shutdown is ENOTCONN).
    c.shutdown(Shutdown.BOTH)
    sys.keep_alive(srv)


def test_peek_leaves_data_queued() raises:
    var p = _unix_pair()
    _ = p.first.value().send(String("abc").as_bytes())
    var buf = List[UInt8](length=8, fill=0)
    assert_equal(p.second.value().peek(Span(buf)), 3)
    assert_equal(_text(buf, 3), "abc")
    assert_equal(p.second.value().peek(Span(buf)[0:1]), 1)
    assert_equal(_recv_text(p.second.value()), "abc")


def test_recv_and_send_would_block_when_nonblocking() raises:
    var p = Socket.pair(Domain.UNIX, SockType.STREAM, nonblocking=True)
    var buf = List[UInt8](length=8, fill=0)
    var kind = ErrorKind.Other
    try:
        _ = p.second.value().recv(Span(buf))
    except e:
        kind = e.kind
        assert_equal(String(e.op), "recv")
        assert_equal(e.errno, Errno.EAGAIN)
    assert_equal(kind, ErrorKind.WouldBlock)
    kind = ErrorKind.Other
    try:
        _ = p.second.value().peek(Span(buf))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.WouldBlock)
    # Fill the send side until EAGAIN: L1 reports it, never waits.
    var chunk = List[UInt8](length=65536, fill=7)
    var sent = 0
    var blocked = False
    for _ in range(10_000):
        try:
            sent += p.first.value().send(Span(chunk))
        except e:
            assert_equal(e.kind, ErrorKind.WouldBlock)
            blocked = True
            break
    assert_true(blocked)
    assert_true(sent > 0)
    # MSG_DONTWAIT on a blocking socket behaves the same.
    var q = _unix_pair()
    kind = ErrorKind.Other
    try:
        _ = q.second.value().recv_with_flags(Span(buf), MSG_DONTWAIT)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.WouldBlock)


def test_udp_send_to_recv_from_peek_from() raises:
    var rx = Socket.new(Domain.IPV4, SockType.DGRAM)
    rx.bind(SocketAddr.parse("127.0.0.1:0"))
    var tx = Socket.new(Domain.IPV4, SockType.DGRAM)
    tx.bind(SocketAddr.parse("127.0.0.1:0"))
    var to = rx.local_addr()
    assert_equal(tx.send_to(String("datagram").as_bytes(), to), 8)
    assert_equal(tx.send_to(List[UInt8](), to), 0)  # empty datagram
    var buf = List[UInt8](length=32, fill=0)
    var pk = rx.peek_from(Span(buf))
    assert_equal(pk[0], 8)
    assert_equal(pk[1].value(), tx.local_addr())
    var r = rx.recv_from(Span(buf))
    assert_equal(r[0], 8)
    assert_equal(_text(buf, 8), "datagram")
    assert_equal(r[1].value(), tx.local_addr())
    var e0 = rx.recv_from(Span(buf))
    assert_equal(e0[0], 0)  # an empty datagram is not EOF
    # MSG_TRUNC: the result is the real datagram length.
    _ = tx.send_to(String("0123456789").as_bytes(), to)
    var small = List[UInt8](length=4, fill=0)
    assert_equal(rx.recv_with_flags(Span(small), MSG_TRUNC), 10)
    # Connected UDP: send/recv without addresses.
    tx.connect(to)
    _ = tx.send(String("conn").as_bytes())
    assert_equal(_recv_text(rx), "conn")


def test_udp_v6_send_to_recv_from() raises:
    if not _ipv6("test_udp_v6_send_to_recv_from"):
        return
    var rx = Socket.new(Domain.IPV6, SockType.DGRAM)
    rx.bind(SocketAddr.parse("[::1]:0"))
    var tx = Socket.new(Domain.IPV6, SockType.DGRAM)
    _ = tx.send_to(String("six").as_bytes(), rx.local_addr())
    var buf = List[UInt8](length=8, fill=0)
    var r = rx.recv_from(Span(buf))
    assert_equal(r[0], 3)
    var from6 = r[1].value()
    assert_true(from6.is_ipv6())
    assert_equal(from6.ip(), IpAddr(Ipv6Addr.LOCALHOST))
    assert_equal(from6.port(), tx.local_addr().port())


# ---- abortive close, SIGPIPE -------------------------------------------------


def test_linger_zero_resets_peer() raises:
    var tp = _tcp_pair("127.0.0.1:0")
    var c = tp.first.take()
    var srv = tp.second.take()
    c.set_linger(Duration.ZERO)
    _ = c.send(String("unread").as_bytes())
    c^.close()  # RST, not FIN
    var buf = List[UInt8](length=16, fill=0)
    var kind = ErrorKind.Other
    var errno = Errno(0)
    try:
        # The queued bytes are discarded by the RST on the receiver too.
        _ = srv.recv(Span(buf))
        _ = srv.recv(Span(buf))
    except e:
        kind = e.kind
        errno = e.errno
    assert_equal(kind, ErrorKind.ConnectionReset)
    assert_equal(errno, Errno.ECONNRESET)


struct _SigpipeDefault:
    """Sets SIGPIPE to SIG_DFL for the test's duration, restoring the old
    action after: with SIG_DFL a send without MSG_NOSIGNAL would kill the
    test process, so surviving proves MSG_NOSIGNAL.

    Kernel `struct sigaction` is handler, flags, restorer, mask (32 bytes on
    x86_64 and aarch64); all zero is SIG_DFL with an empty mask."""

    var old: Array[UInt64, 4]

    def __init__(out self) raises:
        self.old = Array[UInt64, 4](fill=0)
        var dfl = Array[UInt64, 4](fill=0)
        _ = check(
            "rt_sigaction",
            syscall4(
                SYS_rt_sigaction,
                SIGPIPE,
                Int(Pointer(to=dfl)),
                Int(Pointer(to=self.old)),
                8,
            ),
        )
        sys.keep_alive(dfl)

    def restore(mut self) raises:
        _ = check(
            "rt_sigaction",
            syscall4(
                SYS_rt_sigaction, SIGPIPE, Int(Pointer(to=self.old)), 0, 8
            ),
        )


def test_send_to_closed_peer_raises_instead_of_sigpipe() raises:
    var guard = _SigpipeDefault()
    try:
        # Unix stream: every send path after the peer closed is EPIPE.
        var p = _unix_pair()
        var a = p.first.take()
        p.second.take().close()
        var paths = 0
        for i in range(3):
            var kind = ErrorKind.Other
            try:
                if i == 0:
                    _ = a.send(String("x").as_bytes())
                elif i == 1:
                    _ = a.send_with_flags(String("x").as_bytes(), MSG_DONTWAIT)
                else:
                    var d = _bytes("vec")
                    var v = List[Span[UInt8, origin_of(d)]]()
                    v.append(d)
                    _ = a.send_vectored(v)
            except e:
                kind = e.kind
            assert_equal(kind, ErrorKind.BrokenPipe)
            paths += 1
        assert_equal(paths, 3)
        # TCP: the first sends may still be accepted; once the peer's RST
        # arrives the send fails with EPIPE or ECONNRESET.
        var tp = _tcp_pair("127.0.0.1:0")
        var c = tp.first.take()
        tp.second.take().close()
        var kind = ErrorKind.Other
        for _ in range(1000):
            try:
                _ = c.send(String("data").as_bytes())
            except e:
                kind = e.kind
                break
        assert_true(
            kind == ErrorKind.BrokenPipe or kind == ErrorKind.ConnectionReset,
            String("got ", kind),
        )
    finally:
        guard.restore()


# ---- credentials, tcp_info ---------------------------------------------------


def test_peer_cred_matches_this_process() raises:
    var p = _unix_pair()
    var cred = p.first.value().peer_cred()
    assert_equal(Int(cred.pid), _pid())
    assert_equal(Int(cred.uid), syscall0(SYS_geteuid))
    assert_equal(Int(cred.gid), syscall0(SYS_getegid))
    var other = p.second.value().peer_cred()
    assert_equal(Int(other.pid), _pid())


def test_tcp_info_established_after_traffic() raises:
    var tp = _tcp_pair("127.0.0.1:0")
    var c = tp.first.take()
    var srv = tp.second.take()
    var payload = List[UInt8](length=4096, fill=1)
    for _ in range(8):
        _ = c.send(Span(payload))
        _ = _recv_exact(srv, 4096)
        _ = srv.send(String("ack").as_bytes())
        _ = _recv_exact(c, 3)
    var info = c.tcp_info()
    assert_true(info.size() >= 232, String("size ", info.size()))  # 5.15+
    assert_equal(Int(info.state()), TCP_ESTABLISHED)
    assert_equal(Int(info.ca_state()), 0)  # TCP_CA_Open
    assert_true(info.rtt() > 0)
    assert_true(info.min_rtt() > 0)
    assert_true(info.rto() > 0)
    assert_true(info.snd_mss() > 0)
    assert_true(info.snd_cwnd() > 0)
    assert_true(info.pmtu() > 0)
    assert_true(info.segs_out() > 0)
    assert_true(info.bytes_acked() >= 8 * 4096)
    assert_true(info.bytes_received() >= 8 * 3)
    assert_true(info.bytes_sent() >= 8 * 4096)
    assert_true(info.data_segs_out() > 0)
    assert_equal(Int(info.total_retrans()), 0)
    assert_equal(Int(info.notsent_bytes()), 0)
    assert_true(info.snd_wnd() > 0)
    assert_equal(len(info.raw()), info.size())
    assert_true(String(info).startswith("TcpInfo(state=1,"))
    var sinfo = srv.tcp_info()
    assert_equal(Int(sinfo.state()), TCP_ESTABLISHED)
    assert_true(sinfo.bytes_received() >= 8 * 4096)
    sys.keep_alive(c)  # else c closes after its last use: srv in CLOSE_WAIT


def test_tcp_info_other_states_and_non_tcp() raises:
    var fresh = Socket.new(Domain.IPV4, SockType.STREAM)
    assert_equal(Int(fresh.tcp_info().state()), TCP_CLOSE)
    var l = _listener("127.0.0.1:0")
    assert_equal(Int(l.tcp_info().state()), TCP_LISTEN)
    var p = _unix_pair()
    var kind = ErrorKind.Other
    try:
        _ = p.first.value().tcp_info()
    except e:
        kind = e.kind
        assert_equal(String(e.op), "getsockopt(TCP_INFO)")
    assert_equal(kind, ErrorKind.Unsupported)
    # Accessors past the filled size read as 0: a short raw read.
    var t = _tcp_pair("127.0.0.1:0")
    var buf = List[UInt8](length=8, fill=0xEE)
    var n = t.first.value().get_option_bytes(IPPROTO_TCP, TCP_INFO, Span(buf))
    assert_equal(n, 8)
    assert_equal(Int(buf[0]), TCP_ESTABLISHED)
    var empty = TcpInfo()
    assert_equal(empty.size(), 0)
    assert_equal(Int(empty.rtt()), 0)
    assert_equal(Int(empty.state()), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
