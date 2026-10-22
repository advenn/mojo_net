"""Regression tests for the net-socket review findings (net.socket L1).

- F05: a lingering close blocks even nonblocking sockets and destructors.
- F09: `recv_from` on a stream never loses data; `accept` on a non-IP
  listener is documented and pinned.
- F11: time-valued options take `Duration` in one unit system.
- F18: vectored I/O skips empty buffers (no false EOF / zero-length send).
- F24: `get_option_bytes` never reports more than fits in `buf`.
- F25: `set_bind_device` rejects embedded NULs.
- F34: what a second `connect` really does (TCP), and why the TCP recovery
  is wrong for AF_UNIX.
- F36: `peer_cred` without credentials reports uid/gid 0xFFFFFFFF.
- F40: typed TCP_MAXSEG, TCP_SYNCNT, SO_RCVLOWAT, TCP_CONGESTION.
- F42: `Socket.into_fd` / `Socket(fd^)`, the names `Epoll`/`EventFd` use.
"""

from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_true,
)

from linux import ErrorKind, IoError, OwnedFd
from linux import sys
from linux.consts import (
    IPPROTO_TCP,
    POLLHUP,
    POLLOUT,
    SO_TYPE,
    SOL_SOCKET,
    TCP_KEEPIDLE,
    TCP_KEEPINTVL,
    TCP_USER_TIMEOUT,
)
from linux.nr import SYS_getpid
from linux.poll import wait_ready
from linux.syscall import syscall0
from linux.time import Deadline, Duration, Instant
from net.addr import SocketAddr, UnixAddr
from net.socket import (
    Domain,
    Protocol,
    Shutdown,
    SockType,
    Socket,
    SocketPair,
    TcpKeepalive,
)
from net.tcp import TcpListener, TcpStream


# ---- helpers -----------------------------------------------------------------


def _deadline() -> Deadline:
    return Deadline.after(Duration.from_secs(5))


def _tcp_pair(*, nonblocking_client: Bool = False) raises -> SocketPair:
    """(client, accepted server end) over IPv4 loopback."""
    var l = Socket.new(Domain.IPV4, SockType.STREAM)
    l.bind(SocketAddr.parse("127.0.0.1:0"))
    l.listen(4)
    var c = Socket.new(Domain.IPV4, SockType.STREAM)
    c.connect(l.local_addr())
    if nonblocking_client:
        c.set_nonblocking(True)
    return SocketPair(c^, l.accept().into_socket())


def _bytes(s: StringSlice) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def _text(buf: List[UInt8], n: Int) -> String:
    return String(from_utf8_lossy=Span(buf)[0:n])


def _kind_of_bind_device(s: Socket, name: Span[UInt8, _]) -> ErrorKind:
    try:
        s.set_bind_device(name)
        return ErrorKind.Other
    except e:
        return e.kind


def _connect_kind(s: Socket, addr: SocketAddr) -> Optional[ErrorKind]:
    """None when `connect` returned normally."""
    try:
        s.connect(addr)
        return None
    except e:
        return e.kind


def _fill_until_would_block(s: Socket) raises -> Int:
    """Queue bytes on a nonblocking socket until the kernel refuses more."""
    var chunk = List[UInt8](length=65536, fill=0x5A)
    var queued = 0
    while True:
        try:
            queued += s.send(Span(chunk))
        except e:
            if e.kind == ErrorKind.WouldBlock:
                return queued
            raise e


def _unique_abstract(tag: StaticString) raises -> UnixAddr:
    var name = String(
        "mojo_net_net_socket_regress_", tag, "_", syscall0(SYS_getpid)
    )
    return UnixAddr.from_abstract_name(name)


# ---- F05: SO_LINGER > 0 blocks every close -----------------------------------


def _drop(var s: Socket):
    """Destroy `s` here, so the destructor's close is what gets timed."""
    _ = s^


def test_f05_lingering_close_blocks_nonblocking_socket_and_destructor() raises:
    # The doc used to say "a blocking close waits"; Linux makes every close
    # of a lingering socket wait, O_NONBLOCK or not, explicit or destructor.
    # Pinned so the warning in `set_linger` stays true.
    for via_drop in range(2):
        var p = _tcp_pair(nonblocking_client=True)
        var c = p.first.take()
        var srv = p.second.take()  # never reads: the window closes
        assert_true(c.nonblocking())
        assert_true(_fill_until_would_block(c) > 0)
        c.set_linger(Duration.from_millis(900))  # rounds up to 1 s
        assert_equal(c.linger().value(), Duration.from_secs(1))
        var t0 = Instant.now()
        if via_drop == 1:
            _drop(c^)
        else:
            c^.close()
        var took = t0.elapsed()
        assert_true(
            took >= Duration.from_millis(800),
            String("close returned after ", took, " (via_drop=", via_drop, ")"),
        )
        _ = srv.raw_fd()  # the server end stays open (and unread) until here


def test_f05_abortive_and_default_close_return_at_once() raises:
    var cases: List[Optional[Duration]] = [None, Duration.ZERO]
    for c_ in cases:
        var p = _tcp_pair(nonblocking_client=True)
        var c = p.first.take()
        var srv = p.second.take()
        _ = _fill_until_would_block(c)
        c.set_linger(c_)
        var t0 = Instant.now()
        _drop(c^)
        var took = t0.elapsed()
        assert_true(took < Duration.from_millis(500), String(took))
        _ = srv.raw_fd()


def test_f05_deprecated_seconds_overload_still_works() raises:
    var s = Socket.new(Domain.IPV4, SockType.STREAM)
    s.set_linger(0)  # existing callers: abortive close
    assert_equal(s.linger().value(), Duration.ZERO)
    s.set_linger(3)
    assert_equal(s.linger().value(), Duration.from_secs(3))
    var bad: List[Int] = [-1, Int(Int32.MAX) + 1, Int.MIN]
    for v in bad:
        var kind = ErrorKind.Other
        try:
            s.set_linger(v)
        except e:
            kind = e.kind
        assert_equal(kind, ErrorKind.InvalidInput)
    assert_equal(s.linger().value(), Duration.from_secs(3))


# ---- F09: recv_from / peek_from / accept on the wrong kind of socket ---------


def test_f09_recv_from_on_tcp_keeps_the_data() raises:
    # Before: the bytes were dequeued, then SocketAddr.from_raw raised
    # InvalidInput and the count was lost (the next recv got WouldBlock).
    var p = _tcp_pair()
    var c = p.first.take()
    var srv = p.second.take()
    _ = c.send(String("payload").as_bytes())
    var buf = List[UInt8](length=16, fill=0)
    var pk = srv.peek_from(Span(buf))
    assert_equal(pk[0], 7)
    assert_false(Bool(pk[1]))
    var r = srv.recv_from(Span(buf))
    assert_equal(r[0], 7)
    assert_false(Bool(r[1]))  # a stream reports no sender
    assert_equal(_text(buf, 7), "payload")
    # EOF is 0, like recv (it used to raise InvalidInput too).
    c.shutdown(Shutdown.WRITE)
    var eof = srv.recv_from(Span(buf))
    assert_equal(eof[0], 0)
    assert_false(Bool(eof[1]))


def test_f09_recv_from_on_unix_sockets_keeps_the_data() raises:
    var p = Socket.pair(Domain.UNIX, SockType.STREAM)
    _ = p.first.value().send(String("abc").as_bytes())
    var buf = List[UInt8](length=8, fill=0)
    var r = p.second.value().recv_from(Span(buf))
    assert_equal(r[0], 3)
    assert_false(Bool(r[1]))
    assert_equal(_text(buf, 3), "abc")
    # A Unix datagram's sender is not an IP address: None, data kept.
    var d = Socket.pair(Domain.UNIX, SockType.DGRAM)
    _ = d.first.value().send(String("dgram").as_bytes())
    var rd = d.second.value().recv_from(Span(buf))
    assert_equal(rd[0], 5)
    assert_false(Bool(rd[1]))
    assert_equal(_text(buf, 5), "dgram")


def test_f09_recv_from_on_udp_still_reports_the_sender() raises:
    var rx = Socket.new(Domain.IPV4, SockType.DGRAM)
    rx.bind(SocketAddr.parse("127.0.0.1:0"))
    var tx = Socket.new(Domain.IPV4, SockType.DGRAM)
    tx.bind(SocketAddr.parse("127.0.0.1:0"))
    _ = tx.send_to(String("hi").as_bytes(), rx.local_addr())
    var buf = List[UInt8](length=8, fill=0)
    var r = rx.recv_from(Span(buf))
    assert_equal(r[0], 2)
    assert_equal(r[1].value(), tx.local_addr())


def test_f09_accept_on_unix_listener_is_documented_data_loss() raises:
    # Pinned (documented in `accept`): the kernel dequeues the connection
    # before its address can be checked, so it is closed and InvalidInput
    # raised. `accept_unix` is the call for Unix listeners.
    var addr = _unique_abstract("accept")
    var l = Socket.new(Domain.UNIX, SockType.STREAM)
    l.bind_unix(addr)
    l.listen(4)
    var c = Socket.new(Domain.UNIX, SockType.STREAM)
    c.connect_unix(addr)
    var kind = ErrorKind.Other
    try:
        _ = l.accept()
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)
    var buf = List[UInt8](length=4, fill=0)
    assert_equal(c.recv(Span(buf)), 0)  # the accepted end was closed
    # accept_unix works on the same listener.
    var c2 = Socket.new(Domain.UNIX, SockType.STREAM)
    c2.connect_unix(addr)
    var acc = l.accept_unix()
    _ = c2.send(String("ok").as_bytes())
    assert_equal(acc.socket.recv(Span(buf)), 2)


# ---- F11: Durations, one unit system -----------------------------------------


def test_f11_user_timeout_and_keepalive_share_one_unit() raises:
    # The failure scenario: 30 meant 30 s for keepalive but 30 ms for
    # TCP_USER_TIMEOUT. With Durations the same spelling means the same
    # time; the raw kernel values show the units.
    var s = Socket.new(Domain.IPV4, SockType.STREAM)
    s.set_tcp_keepalive(
        TcpKeepalive(
            idle=Duration.from_secs(30),
            interval=Duration.from_secs(5),
            count=3,
        )
    )
    s.set_tcp_user_timeout(Duration.from_secs(30))
    assert_equal(s.get_option_int(IPPROTO_TCP, TCP_KEEPIDLE), 30)
    assert_equal(s.get_option_int(IPPROTO_TCP, TCP_KEEPINTVL), 5)
    assert_equal(s.get_option_int(IPPROTO_TCP, TCP_USER_TIMEOUT), 30_000)
    assert_equal(s.tcp_user_timeout().value(), Duration.from_secs(30))
    assert_equal(s.tcp_keepalive().idle, Duration.from_secs(30))


def test_f11_keepalive_rounds_up_to_whole_seconds() raises:
    var s = Socket.new(Domain.IPV4, SockType.STREAM)
    s.set_tcp_keepalive(
        TcpKeepalive(
            idle=Duration.from_millis(1500),
            interval=Duration.from_nanos(1),
            count=2,
        )
    )
    var ka = s.tcp_keepalive()
    assert_equal(ka.idle, Duration.from_secs(2))
    assert_equal(ka.interval, Duration.from_secs(1))
    assert_equal(ka.count, 2)
    assert_equal(String(ka), "TcpKeepalive(idle=2s, interval=1s, count=2)")


# ---- F18: vectored I/O with empty buffers in front ---------------------------


def test_f18_l1_vectored_skips_leading_empty_buffers() raises:
    # Before: only the first IOV_MAX (1024) iovecs were passed, all empty,
    # so send returned 0 and recv returned 0 (a false EOF) with data queued.
    var p = Socket.pair(Domain.UNIX, SockType.STREAM)
    var data = _bytes("0123456789")
    var out = List[Span[UInt8, origin_of(data)]]()
    for _ in range(1024):
        out.append(Span(data)[0:0])
    out.append(Span(data))
    assert_equal(p.first.value().send_vectored(out), 10)
    var rbuf = List[UInt8](length=10, fill=0)
    var inb = List[Span[UInt8, origin_of(rbuf)]]()
    for _ in range(1024):
        inb.append(Span(rbuf)[0:0])
    inb.append(Span(rbuf))
    assert_equal(p.second.value().recv_vectored(inb), 10)
    assert_equal(_text(rbuf, 10), "0123456789")
    # Only empty buffers: still 0 and no data consumed or sent.
    var none_out = List[Span[UInt8, origin_of(data)]]()
    for _ in range(3):
        none_out.append(Span(data)[0:0])
    assert_equal(p.first.value().send_vectored(none_out), 0)


def test_f18_l1_vectored_byte_placement_with_interleaved_empties() raises:
    # Heap path (> 16 non-empty buffers) with empties between them: every
    # byte still lands in the buffer it belongs to.
    var p = Socket.pair(Domain.UNIX, SockType.STREAM)
    var data = List[UInt8](length=40, fill=0)
    for i in range(len(data)):
        data[i] = UInt8(65 + i % 26)
    var out = List[Span[UInt8, origin_of(data)]]()
    for i in range(20):
        out.append(Span(data)[2 * i : 2 * i])  # empty
        out.append(Span(data)[2 * i : 2 * i + 2])
    assert_equal(p.first.value().send_vectored(out), 40)
    var rbuf = List[UInt8](length=40, fill=0)
    var inb = List[Span[UInt8, origin_of(rbuf)]]()
    for i in range(20):
        inb.append(Span(rbuf)[0:0])
        inb.append(Span(rbuf)[2 * i : 2 * i + 2])
    assert_equal(p.second.value().recv_vectored(inb), 40)
    for i in range(40):
        assert_equal(rbuf[i], data[i])


def test_f18_l1_iov_max_counts_non_empty_buffers() raises:
    # IOV_MAX now caps the non-empty buffers passed: 1024 empties plus 1030
    # one-byte buffers send exactly 1024 bytes.
    var p = Socket.pair(Domain.UNIX, SockType.STREAM)
    var data = List[UInt8](length=1030, fill=0x41)
    var out = List[Span[UInt8, origin_of(data)]]()
    for i in range(1030):
        out.append(Span(data)[i:i])
        out.append(Span(data)[i : i + 1])
    assert_equal(p.first.value().send_vectored(out), 1024)


def test_f18_l2_stream_vectored_skips_leading_empty_buffers() raises:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    l.set_deadline(_deadline())
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    c.set_deadline(_deadline())
    s.set_deadline(_deadline())
    var data = _bytes("abcdefghij")
    var out = List[Span[UInt8, origin_of(data)]]()
    for _ in range(1024):
        out.append(Span(data)[0:0])
    out.append(Span(data))
    assert_equal(c.write_vectored(out), 10)
    var rbuf = List[UInt8](length=10, fill=0)
    var inb = List[Span[UInt8, origin_of(rbuf)]]()
    for _ in range(1024):
        inb.append(Span(rbuf)[0:0])
    inb.append(Span(rbuf))
    var got = 0
    while got < 10:
        var n = s.read_vectored(inb)
        assert_true(n > 0, "read_vectored reported EOF with data pending")
        got += n
        if got < 10:
            # Partial: read the rest plainly (placement is checked above).
            var rest = List[UInt8](length=10 - got, fill=0)
            s.read_exact(Span(rest))
            for i in range(len(rest)):
                rbuf[got + i] = rest[i]
            got = 10
    assert_equal(_text(rbuf, 10), "abcdefghij")


# ---- F24: get_option_bytes never exceeds the buffer --------------------------

comptime _AF_NETLINK = 16
comptime _SOL_NETLINK = 270
comptime _NETLINK_ADD_MEMBERSHIP = 1
comptime _NETLINK_LIST_MEMBERSHIPS = 9


def _netlink_route() -> Optional[Socket]:
    try:
        var s = Socket.new(Domain(_AF_NETLINK), SockType.DGRAM, Protocol(0))
        s.set_option_int(_SOL_NETLINK, _NETLINK_ADD_MEMBERSHIP, 1)
        return s^
    except:
        return None


def test_f24_get_option_bytes_is_clamped_to_the_buffer() raises:
    # NETLINK_LIST_MEMBERSHIPS reports the full membership length (8 bytes
    # here) while copying only whole words that fit. Before, a 1-byte
    # buffer got n = 8, so buf[0:n] was out of bounds.
    var opt = _netlink_route()
    if not opt:
        print("    (skipped: no AF_NETLINK)")
        return
    var s = opt.take()
    for size in range(1, 5):
        var buf = List[UInt8](length=size, fill=0xAB)
        var n = s.get_option_bytes(
            _SOL_NETLINK, _NETLINK_LIST_MEMBERSHIPS, Span(buf)
        )
        assert_true(n <= len(buf), String("n=", n, " len=", size))
        assert_equal(len(Span(buf)[0:n]), n)
        var both = s.get_option_bytes_with_len(
            _SOL_NETLINK, _NETLINK_LIST_MEMBERSHIPS, Span(buf)
        )
        assert_equal(both[0], n)
        assert_true(both[1] > len(buf))  # truncation is detectable
    # Retrying with the reported size gets the whole option: group 1 set.
    var probe = List[UInt8](length=1, fill=0)
    var full = s.get_option_bytes_with_len(
        _SOL_NETLINK, _NETLINK_LIST_MEMBERSHIPS, Span(probe)
    )[1]
    var buf = List[UInt8](length=full, fill=0)
    var r = s.get_option_bytes_with_len(
        _SOL_NETLINK, _NETLINK_LIST_MEMBERSHIPS, Span(buf)
    )
    assert_equal(r[0], full)
    assert_equal(r[1], full)
    assert_equal(Int(buf[0]) & 1, 1)


def test_f24_ordinary_options_report_their_length() raises:
    var s = Socket.new(Domain.IPV4, SockType.STREAM)
    var big = List[UInt8](length=16, fill=0)
    var r = s.get_option_bytes_with_len(SOL_SOCKET, SO_TYPE, Span(big))
    assert_equal(r[0], 4)
    assert_equal(r[1], 4)
    var small = List[UInt8](length=2, fill=0)
    assert_equal(s.get_option_bytes(SOL_SOCKET, SO_TYPE, Span(small)), 2)


# ---- F25: set_bind_device and NUL bytes --------------------------------------


def test_f25_bind_device_rejects_embedded_nul() raises:
    # Before: "lo\0evil" passed the length check and the kernel bound "lo".
    var s = Socket.new(Domain.IPV4, SockType.STREAM)
    var name: List[UInt8] = [108, 111, 0, 101, 118, 105, 108]  # lo\0evil
    assert_equal(_kind_of_bind_device(s, Span(name)), ErrorKind.InvalidInput)
    assert_false(Bool(s.bind_device()))
    var lone: List[UInt8] = [0]
    assert_equal(_kind_of_bind_device(s, Span(lone)), ErrorKind.InvalidInput)
    var trailing: List[UInt8] = [108, 111, 0]
    assert_equal(
        _kind_of_bind_device(s, Span(trailing)), ErrorKind.InvalidInput
    )
    # The StringSlice overload goes through the same check.
    var str_kind = ErrorKind.Other
    try:
        s.set_bind_device(String(from_utf8_lossy=Span(name)))
    except e:
        str_kind = e.kind
    assert_equal(str_kind, ErrorKind.InvalidInput)
    assert_false(Bool(s.bind_device()))
    # A clean name still binds (unprivileged on an unbound socket since
    # Linux 5.7; tolerate EPERM elsewhere).
    var denied = False
    try:
        s.set_bind_device("lo")
    except e:
        if e.kind != ErrorKind.PermissionDenied:
            raise e
        denied = True
    if not denied:
        assert_equal(s.bind_device().value(), "lo")


# ---- F34: connect re-issue semantics -----------------------------------------


def test_f34_tcp_second_connect_reports_failure_then_restarts() raises:
    # The doc used to say a second connect after a failed attempt "silently
    # starts a new one": it reports the failure; only the third restarts.
    var hold = Socket.new(Domain.IPV4, SockType.STREAM)
    hold.bind(SocketAddr.parse("127.0.0.1:0"))  # bound, not listening: RST
    var dead = hold.local_addr()
    var c = Socket.new(Domain.IPV4, SockType.STREAM, nonblocking=True)
    var k1 = _connect_kind(c, dead)
    assert_equal(k1.value(), ErrorKind.InProgress)
    _ = wait_ready(c, Int16(POLLOUT), _deadline(), "connect")
    assert_equal(_connect_kind(c, dead).value(), ErrorKind.ConnectionRefused)
    assert_equal(_connect_kind(c, dead).value(), ErrorKind.InProgress)
    # If take_error() consumed the failure first, connect says Aborted.
    _ = wait_ready(c, Int16(POLLOUT), _deadline(), "connect")
    assert_equal(c.take_error().value().kind, ErrorKind.ConnectionRefused)
    assert_equal(_connect_kind(c, dead).value(), ErrorKind.ConnectionAborted)
    _ = hold.raw_fd()


def test_f34_tcp_second_connect_after_success_returns_normally() raises:
    var l = Socket.new(Domain.IPV4, SockType.STREAM)
    l.bind(SocketAddr.parse("127.0.0.1:0"))
    l.listen(4)
    var to = l.local_addr()
    var c = Socket.new(Domain.IPV4, SockType.STREAM, nonblocking=True)
    var k1 = _connect_kind(c, to)
    if not k1:
        print("    (connect completed at once; nothing to re-issue)")
        return
    assert_equal(k1.value(), ErrorKind.InProgress)
    _ = wait_ready(c, Int16(POLLOUT), _deadline(), "connect")
    assert_false(Bool(_connect_kind(c, to)))  # success, not EISCONN
    assert_equal(_connect_kind(c, to).value(), ErrorKind.AlreadyConnected)
    _ = l.raw_fd()


def test_f34_unix_failed_connect_leaves_nothing_in_progress() raises:
    # Following the TCP recovery (wait for POLLOUT, take_error() None means
    # connected) gives a false "connected" on AF_UNIX: pinned so the
    # connect_unix doc keeps saying "call connect_unix again".
    var addr = _unique_abstract("backlog")
    var l = Socket.new(Domain.UNIX, SockType.STREAM)
    l.bind_unix(addr)
    l.listen(0)
    var first = Socket.new(Domain.UNIX, SockType.STREAM)
    first.connect_unix(addr)  # fills the backlog
    var c = Socket.new(Domain.UNIX, SockType.STREAM, nonblocking=True)
    var kind = ErrorKind.Other
    try:
        c.connect_unix(addr)
    except e:
        kind = e.kind
    if kind != ErrorKind.WouldBlock:
        print("    (skipped: backlog did not fill:", kind, ")")
        return
    var rev = wait_ready(c, Int16(POLLOUT), _deadline(), "connect")
    assert_true((Int(rev) & POLLOUT) != 0)
    assert_true((Int(rev) & POLLHUP) != 0)
    assert_false(Bool(c.take_error()))  # "None" -- yet not connected:
    var peer_kind = ErrorKind.Other
    try:
        _ = c.peer_unix_addr()
    except e:
        peer_kind = e.kind
    assert_equal(peer_kind, ErrorKind.NotConnected)
    # The documented recovery: make room, then simply connect again.
    var acc = l.accept_unix()
    c.connect_unix(addr)
    _ = c.peer_unix_addr()
    _ = first.raw_fd()
    _ = acc.socket.raw_fd()
    _ = l.raw_fd()


# ---- F36: peer_cred without credentials --------------------------------------


def test_f36_peer_cred_without_credentials_is_all_ones() raises:
    var p = _tcp_pair()
    var creds = [p.first.value().peer_cred(), p.second.value().peer_cred()]
    for cred in creds:
        assert_equal(Int(cred.pid), 0)
        assert_equal(cred.uid, UInt32.MAX)
        assert_equal(cred.gid, UInt32.MAX)
    var u = Socket.new(Domain.IPV4, SockType.DGRAM)
    var c = u.peer_cred()
    assert_equal(c.uid, UInt32.MAX)
    assert_equal(c.gid, UInt32.MAX)


# ---- F40: typed options that were only reachable raw -------------------------


def test_f40_tcp_mss_round_trip_and_range() raises:
    var s = Socket.new(Domain.IPV4, SockType.STREAM)
    s.set_tcp_mss(1200)
    assert_equal(s.tcp_mss(), 1200)
    var bad: List[Int] = [10, 87, 32768, -1, Int(Int32.MAX) + 1]
    for v in bad:
        var kind = ErrorKind.Other
        try:
            s.set_tcp_mss(v)
        except e:
            kind = e.kind
        assert_equal(kind, ErrorKind.InvalidInput, String("mss ", v))
    assert_equal(s.tcp_mss(), 1200)
    s.set_tcp_mss(0)  # removes the cap: back to the 536 default
    assert_equal(s.tcp_mss(), 536)


def test_f40_syn_retries_round_trip_and_range() raises:
    var s = Socket.new(Domain.IPV4, SockType.STREAM)
    assert_true(s.syn_retries() >= 1)  # the sysctl default
    s.set_syn_retries(2)
    assert_equal(s.syn_retries(), 2)
    var bad: List[Int] = [0, -1, 128, Int(1) << 40]
    for v in bad:
        var kind = ErrorKind.Other
        try:
            s.set_syn_retries(v)
        except e:
            kind = e.kind
        assert_equal(kind, ErrorKind.InvalidInput, String("syncnt ", v))
    assert_equal(s.syn_retries(), 2)


def test_f40_recv_lowat_round_trip() raises:
    var s = Socket.new(Domain.IPV4, SockType.STREAM)
    s.set_recv_lowat(16)
    assert_equal(s.recv_lowat(), 16)
    s.set_recv_lowat(0)
    assert_equal(s.recv_lowat(), 1)  # the kernel stores 0 as 1
    var kind = ErrorKind.Other
    try:
        s.set_recv_lowat(-1)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)
    # It takes effect on TCP readiness: with lowat 4, 2 queued bytes are not
    # "readable" yet.
    var p = _tcp_pair()
    p.second.value().set_recv_lowat(4)
    _ = p.first.value().send(String("ab").as_bytes())
    var short = Deadline.after(Duration.from_millis(50))
    var timed_out = False
    try:
        _ = wait_ready(p.second.value(), Int16(1), short, "poll")  # POLLIN
    except e:
        timed_out = e.kind == ErrorKind.TimedOut
    assert_true(timed_out)
    _ = p.first.value().send(String("cd").as_bytes())
    _ = wait_ready(p.second.value(), Int16(1), _deadline(), "poll")


def test_f40_tcp_congestion_round_trip_and_validation() raises:
    var s = Socket.new(Domain.IPV4, SockType.STREAM)
    var current = s.tcp_congestion()
    assert_true(current.byte_length() > 0)
    s.set_tcp_congestion(current)  # the default is always allowed
    assert_equal(s.tcp_congestion(), current)
    s.set_tcp_congestion("reno")  # built in and unrestricted
    assert_equal(s.tcp_congestion(), "reno")
    var not_found = ErrorKind.Other
    try:
        s.set_tcp_congestion("nosuchalg")
    except e:
        not_found = e.kind
    assert_true(
        not_found == ErrorKind.NotFound
        or not_found == ErrorKind.PermissionDenied,
        String(not_found),
    )
    var bad: List[List[UInt8]] = [
        List[UInt8](),
        List[UInt8](length=16, fill=97),  # 16 bytes: the kernel cuts to 15
        [114, 101, 0, 110, 111],  # re\0no
    ]
    for b in bad:
        var kind = ErrorKind.Other
        try:
            s.set_tcp_congestion(Span(b))
        except e:
            kind = e.kind
        assert_equal(kind, ErrorKind.InvalidInput)
    assert_equal(s.tcp_congestion(), "reno")


# ---- F42: one name for giving up / adopting the descriptor -------------------


def test_f42_into_fd_and_adopt_with_init() raises:
    var p = Socket.pair(Domain.UNIX, SockType.STREAM)
    var a = p.first.take()
    var b = p.second.take()
    var raw = a.raw_fd()
    var fd: OwnedFd = a^.into_fd()  # same name as Epoll/EventFd.into_fd
    assert_equal(fd.raw_fd(), raw)
    var back = Socket(fd^)
    assert_equal(back.raw_fd(), raw)
    _ = back.send(String("x").as_bytes())
    var buf = List[UInt8](length=1, fill=0)
    assert_equal(b.recv(Span(buf)), 1)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
