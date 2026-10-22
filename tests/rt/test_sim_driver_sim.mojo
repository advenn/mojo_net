"""SimDriver semantics at the Driver level (no event loop): handshake timing,
edge-triggered readiness, EOF/RST/refused paths, ports, flow control, the
virtual clock, deadlock detection, faults and replay determinism.

Built only with -D MOJO_TCP_SIM=1 (the `_sim.mojo` suffix)."""

from std.os import getenv, setenv, unsetenv
from std.sys import is_defined
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from linux import Errno, IoError
from linux.abi import RawSockaddr
from linux.consts import (
    AF_INET,
    AF_INET6,
    SHUT_WR,
    SO_REUSEPORT,
    SO_SNDBUF,
    SOCK_STREAM,
    SOL_SOCKET,
)
from net.addr import Ipv4Addr, Ipv6Addr, SocketAddr
from rt.driver import (
    ERROR,
    HANGUP,
    READ_CLOSED,
    READ_READY,
    WRITE_READY,
    ReadyEvent,
)
from rt.sim import (
    DEFAULT_SIM_SEED,
    FAULT_ACCEPT_ABORT,
    FAULT_ACCEPT_ERROR,
    FAULT_DROP_SYN,
    FAULT_EAGAIN,
    FAULT_SHORT_READ,
    FAULT_SHORT_WRITE,
    FAULT_SPURIOUS_EDGE,
    SIM_FD_BASE,
    SYS_RECV,
    SYS_SEND,
    SimDriver,
    SimFaults,
    sim_seed_from_env,
)

comptime LAT = 50_000


@always_inline
def neg(e: Errno) -> Int:
    return -Int(e.value)


def v4(port: Int) -> RawSockaddr:
    return SocketAddr(Ipv4Addr.LOCALHOST, UInt16(port)).to_raw()


def port_of(raw: RawSockaddr) raises -> Int:
    return Int(SocketAddr.from_raw(raw).port())


def quiet(seed: UInt64 = 7) -> SimDriver:
    """A driver with fixed latency and no jitter: exact timing."""
    var d = SimDriver(seed)
    d.config.latency_ns = LAT
    d.config.jitter_ns = 0
    return d^


def bytes_of(s: String) raises -> ByteBuffer:
    var b = ByteBuffer()
    b.write_bytes(s.as_bytes())
    return b^


def as_text(b: ByteBuffer) -> String:
    # `String(StringSlice(unsafe_from_utf8=...))` returned from a function
    # trips a compiler recursion error on 1.2.0rc2; build it bytewise.
    var out = String()
    var sp = b.readable_span()
    for i in range(len(sp)):
        out += chr(Int(sp[i]))
    return out^


def events(
    mut d: SimDriver, timeout_ns: Int
) raises IoError -> List[ReadyEvent]:
    var out = List[ReadyEvent]()
    d.wait(timeout_ns, out)
    return out^


def mask_of(evs: List[ReadyEvent], token: UInt64) -> UInt32:
    """The reported mask for `token` (0 if absent); fails on duplicates via
    the caller checking `count_of`."""
    var m: UInt32 = 0
    for i in range(len(evs)):
        if evs[i].token == token:
            m |= evs[i].events
    return m


def count_of(evs: List[ReadyEvent], token: UInt64) -> Int:
    var n = 0
    for i in range(len(evs)):
        if evs[i].token == token:
            n += 1
    return n


struct Pair(Movable):
    var listener: Int32
    var client: Int32
    var server: Int32
    var port: Int

    def __init__(out self):
        self.listener = -1
        self.client = -1
        self.server = -1
        self.port = 0


comptime TL: UInt64 = 1
comptime TC: UInt64 = 2
comptime TS: UInt64 = 3


def connected(mut d: SimDriver) raises -> Pair:
    """A listener (token 1), client (token 2) and accepted server side
    (token 3), all registered, every pending edge drained."""
    var p = Pair()
    p.listener = Int32(d.socket(AF_INET, SOCK_STREAM))
    assert_equal(d.bind(p.listener, v4(0)), 0)
    assert_equal(d.listen(p.listener, 16), 0)
    var local = RawSockaddr()
    assert_equal(d.local_addr(p.listener, local), 0)
    p.port = port_of(local)
    assert_equal(d.register(p.listener, TL), 0)
    p.client = Int32(d.socket(AF_INET, SOCK_STREAM))
    assert_equal(d.register(p.client, TC), 0)
    assert_equal(d.connect(p.client, v4(p.port)), neg(Errno.EINPROGRESS))
    var deadline = d.now().as_nanos() + 10 * LAT
    while d.now().as_nanos() < deadline:
        _ = events(d, deadline - d.now().as_nanos())
    var peer = RawSockaddr()
    var s = d.accept(p.listener, peer)
    assert_true(s >= SIM_FD_BASE)
    p.server = Int32(s)
    assert_equal(d.register(p.server, TS), 0)
    _ = events(d, 0)
    return p^


# ---- handshake ---------------------------------------------------------------


def test_handshake_timing_and_edges() raises:
    var d = quiet()
    var t0 = d.now().as_nanos()
    var l = Int32(d.socket(AF_INET, SOCK_STREAM))
    assert_true(Int(l) >= SIM_FD_BASE)
    assert_equal(d.bind(l, v4(0)), 0)
    assert_equal(d.listen(l, 8), 0)
    var local = RawSockaddr()
    assert_equal(d.local_addr(l, local), 0)
    var port = port_of(local)
    assert_true(port >= 32768 and port <= 60999)
    assert_equal(d.register(l, TL), 0)
    var c = Int32(d.socket(AF_INET, SOCK_STREAM))
    assert_equal(d.register(c, TC), 0)
    assert_equal(d.connect(c, v4(port)), neg(Errno.EINPROGRESS))
    assert_equal(d.connect(c, v4(port)), neg(Errno.EALREADY))
    # Nothing is ready yet: a connecting socket reports nothing.
    assert_equal(len(events(d, 0)), 0)
    var peer = RawSockaddr()
    assert_equal(d.accept(l, peer), neg(Errno.EAGAIN))
    # SYN-ACK: the client becomes writable after one round trip.
    var e1 = events(d, -1)
    assert_equal(len(e1), 1)
    assert_equal(e1[0].token, TC)
    assert_equal(e1[0].events, WRITE_READY)
    assert_equal(d.now().as_nanos() - t0, 2 * LAT)
    assert_equal(d.socket_error(c), 0)
    # ACK: the listener becomes readable half a round trip later.
    var e2 = events(d, -1)
    assert_equal(len(e2), 1)
    assert_equal(e2[0].token, TL)
    assert_equal(e2[0].events, READ_READY)
    assert_equal(d.now().as_nanos() - t0, 3 * LAT)
    var s = d.accept(l, peer)
    assert_true(s > Int(c))
    assert_equal(d.accept(l, peer), neg(Errno.EAGAIN))
    # Registering an established socket reports it writable at once.
    assert_equal(d.register(Int32(s), TS), 0)
    var e3 = events(d, 0)
    assert_equal(len(e3), 1)
    assert_equal(e3[0].events, WRITE_READY)
    # Peer address of the accepted socket is the client's local address.
    var ca = RawSockaddr()
    assert_equal(d.local_addr(c, ca), 0)
    assert_equal(port_of(peer), port_of(ca))
    assert_equal(String(SocketAddr.from_raw(peer).ip()), "127.0.0.1")


def test_connect_refused_reports_error_edge() raises:
    var d = quiet()
    var c = Int32(d.socket(AF_INET, SOCK_STREAM))
    assert_equal(d.register(c, TC), 0)
    assert_equal(d.connect(c, v4(9)), neg(Errno.EINPROGRESS))
    var e = events(d, -1)
    assert_equal(len(e), 1)
    assert_true((e[0].events & ERROR) != 0)
    assert_true((e[0].events & HANGUP) != 0)
    assert_true((e[0].events & WRITE_READY) != 0)
    assert_equal(d.socket_error(c), neg(Errno.ECONNREFUSED))
    assert_equal(d.socket_error(c), 0)
    assert_equal(d.stats.connects_failed, 1)
    assert_equal(d.close(c), 0)
    assert_equal(d.close(c), neg(Errno.EBADF))


def test_full_backlog_refuses_or_retries() raises:
    var d = quiet()
    var l = Int32(d.socket(AF_INET, SOCK_STREAM))
    assert_equal(d.bind(l, v4(0)), 0)
    assert_equal(d.listen(l, 0), 0)  # Linux: backlog 0 still queues one
    var local = RawSockaddr()
    _ = d.local_addr(l, local)
    var port = port_of(local)
    var a = Int32(d.socket(AF_INET, SOCK_STREAM))
    var b = Int32(d.socket(AF_INET, SOCK_STREAM))
    _ = d.register(a, 10)
    _ = d.register(b, 11)
    _ = d.connect(a, v4(port))
    _ = d.connect(b, v4(port))
    for _ in range(6):
        _ = events(d, 10 * LAT)
    assert_equal(d.socket_error(a), 0)
    assert_equal(d.socket_error(b), neg(Errno.ECONNREFUSED))
    # Retry mode: the SYN is dropped and retransmitted until room appears.
    d.config.full_backlog_refuses = False
    var c = Int32(d.socket(AF_INET, SOCK_STREAM))
    _ = d.register(c, 12)
    _ = d.connect(c, v4(port))
    _ = events(d, 10 * LAT)
    var peer = RawSockaddr()
    assert_true(d.accept(l, peer) >= SIM_FD_BASE)  # frees the slot
    var t0 = d.now().as_nanos()
    var got = False
    for _ in range(10):
        var e = events(d, 5_000_000_000)
        if mask_of(e, 12) & WRITE_READY != 0:
            got = True
            break
    assert_true(got)
    assert_equal(d.socket_error(c), 0)
    assert_true(d.now().as_nanos() - t0 >= 900_000_000)  # an RTO passed


# ---- data and edge-triggered readiness ----------------------------------------


def test_data_edges_are_edge_triggered() raises:
    var d = quiet()
    var p = connected(d)
    assert_equal(d.send(p.client, bytes_of("hello")), 5)
    assert_equal(len(events(d, 0)), 0)  # still in flight
    var t0 = d.now().as_nanos()
    var e = events(d, -1)
    assert_equal(d.now().as_nanos() - t0, LAT)
    assert_equal(count_of(e, TS), 1)
    assert_equal(mask_of(e, TS), READ_READY | WRITE_READY)
    var buf = ByteBuffer(capacity=64)
    assert_equal(d.recv(p.server, buf), 5)
    assert_equal(as_text(buf), "hello")
    assert_equal(d.recv(p.server, buf), neg(Errno.EAGAIN))
    # No new data, no new edge (edge-triggered).
    assert_equal(len(events(d, 0)), 0)
    # Each new arrival fires again, even before the first is read.
    assert_equal(d.send(p.client, bytes_of("a")), 1)
    _ = events(d, -1)
    assert_equal(d.send(p.client, bytes_of("b")), 1)
    var e2 = events(d, -1)
    assert_equal(count_of(e2, TS), 1)
    buf.clear()
    assert_equal(d.recv(p.server, buf), 2)
    assert_equal(as_text(buf), "ab")


def test_two_sends_in_one_tick_coalesce_into_one_event() raises:
    var d = quiet()
    var p = connected(d)
    assert_equal(d.send(p.client, bytes_of("x")), 1)
    assert_equal(d.send(p.client, bytes_of("y")), 1)
    var e = events(d, -1)
    assert_equal(len(e), 1)
    var buf = ByteBuffer(capacity=64)
    assert_equal(d.recv(p.server, buf), 2)


def test_fin_after_data_then_eof_forever() raises:
    var d = quiet()
    var p = connected(d)
    assert_equal(d.send(p.client, bytes_of("xyz")), 3)
    assert_equal(d.shutdown(p.client, SHUT_WR), 0)
    assert_equal(d.send(p.client, bytes_of("late")), neg(Errno.EPIPE))
    # shutdown wakes the client itself first (Linux: sk_state_change).
    var m: UInt32 = 0
    while m == 0:
        m = mask_of(events(d, -1), TS)
    assert_true((m & READ_READY) != 0 and (m & READ_CLOSED) != 0)
    assert_equal(m & HANGUP, 0)  # the server can still write
    var buf = ByteBuffer(capacity=64)
    assert_equal(d.recv(p.server, buf), 3)
    assert_equal(d.recv(p.server, buf), 0)
    assert_equal(d.recv(p.server, buf), 0)
    # Half-closed: the server still writes to the client.
    assert_equal(d.send(p.server, bytes_of("bye")), 3)
    _ = events(d, -1)
    var cb = ByteBuffer(capacity=64)
    assert_equal(d.recv(p.client, cb), 3)
    assert_equal(as_text(cb), "bye")


def test_close_with_unread_data_resets_peer() raises:
    var d = quiet()
    var p = connected(d)
    assert_equal(d.send(p.server, bytes_of("last words")), 10)
    assert_equal(d.send(p.client, bytes_of("unread")), 6)
    _ = events(d, -1)
    # Server closes without reading: RST after the data it already sent.
    assert_equal(d.deregister(p.server), 0)
    assert_equal(d.close(p.server), 0)
    var e = events(d, -1)
    var m = mask_of(e, TC)
    assert_true((m & ERROR) != 0 and (m & HANGUP) != 0)
    assert_true((m & READ_READY) != 0 and (m & READ_CLOSED) != 0)
    var buf = ByteBuffer(capacity=64)
    assert_equal(d.recv(p.client, buf), 10)  # delivered data stays readable
    assert_equal(as_text(buf), "last words")
    assert_equal(d.recv(p.client, buf), neg(Errno.ECONNRESET))
    assert_equal(d.recv(p.client, buf), 0)
    assert_equal(d.send(p.client, bytes_of("x")), neg(Errno.EPIPE))


def test_send_sees_reset_first_then_epipe() raises:
    var d = quiet()
    var p = connected(d)
    assert_equal(d.send(p.client, bytes_of("unread")), 6)
    _ = events(d, -1)
    _ = d.close(p.server)
    _ = events(d, -1)
    assert_equal(d.send(p.client, bytes_of("x")), neg(Errno.ECONNRESET))
    assert_equal(d.send(p.client, bytes_of("x")), neg(Errno.EPIPE))


def test_data_to_a_closed_socket_is_answered_with_rst() raises:
    var d = quiet()
    var p = connected(d)
    _ = d.close(p.server)  # nothing unread: clean FIN
    var e = events(d, -1)
    assert_true((mask_of(e, TC) & READ_CLOSED) != 0)
    var buf = ByteBuffer(capacity=64)
    assert_equal(d.recv(p.client, buf), 0)
    # The client keeps writing; the closed server answers with RST.
    assert_equal(d.send(p.client, bytes_of("anyone?")), 7)
    var e2 = events(d, -1)  # the data reaches nobody; the RST comes back
    assert_true((mask_of(e2, TC) & ERROR) != 0)
    assert_equal(d.send(p.client, bytes_of("x")), neg(Errno.ECONNRESET))


def test_listener_close_resets_queued_connections() raises:
    var d = quiet()
    var l = Int32(d.socket(AF_INET, SOCK_STREAM))
    _ = d.bind(l, v4(0))
    _ = d.listen(l, 8)
    var local = RawSockaddr()
    _ = d.local_addr(l, local)
    var port = port_of(local)
    var cs = List[Int32]()
    for k in range(3):
        var c = Int32(d.socket(AF_INET, SOCK_STREAM))
        _ = d.register(c, UInt64(100 + k))
        _ = d.connect(c, v4(port))
        cs.append(c)
    for _ in range(4):
        _ = events(d, 10 * LAT)
    for k in range(3):
        assert_equal(d.socket_error(cs[k]), 0)  # connected (queued)
    _ = d.close(l)
    var seen = 0
    for _ in range(4):
        var e = events(d, 10 * LAT)
        for k in range(3):
            if (mask_of(e, UInt64(100 + k)) & ERROR) != 0:
                seen += 1
    assert_equal(seen, 3)
    var buf = ByteBuffer(capacity=16)
    for k in range(3):
        assert_equal(d.recv(cs[k], buf), neg(Errno.ECONNRESET))


def test_explicit_reset_connection_hits_both_ends() raises:
    var d = quiet()
    var p = connected(d)
    assert_true(d.reset_connection(p.client))
    assert_false(d.reset_connection(p.client))
    var e = events(d, 0)
    assert_true((mask_of(e, TC) & ERROR) != 0)
    assert_true((mask_of(e, TS) & ERROR) != 0)
    var buf = ByteBuffer(capacity=16)
    assert_equal(d.recv(p.server, buf), neg(Errno.ECONNRESET))
    assert_equal(d.send(p.client, bytes_of("x")), neg(Errno.ECONNRESET))


# ---- flow control --------------------------------------------------------------


def test_flow_control_partial_write_eagain_and_write_edge() raises:
    var d = quiet()
    d.config.sndbuf = 4096
    d.config.rcvbuf = 4096
    var p = connected(d)
    var big = ByteBuffer(capacity=1 << 20)
    big.commit(1 << 20)
    assert_equal(d.send(p.client, big), 8192)  # sndbuf + peer rcvbuf
    assert_equal(d.send(p.client, big), neg(Errno.EAGAIN))
    var e = events(d, -1)
    assert_equal(mask_of(e, TC), 0)  # the client has no room: no edge
    var buf = ByteBuffer(capacity=1024)
    assert_equal(d.recv(p.server, buf), 1024)
    # A quarter of the capacity must be free before WRITE_READY.
    assert_equal(len(events(d, 0)), 0)
    buf.clear()
    assert_equal(d.recv(p.server, buf), 1024)
    var e2 = events(d, 0)
    assert_equal(mask_of(e2, TC), WRITE_READY)
    assert_equal(d.send(p.client, big), 2048)


def test_so_sndbuf_is_doubled_like_linux() raises:
    var d = quiet()
    d.config.rcvbuf = 4096
    var p = connected(d)
    assert_equal(d.set_int_option(p.client, SOL_SOCKET, SO_SNDBUF, 4096), 0)
    var big = ByteBuffer(capacity=1 << 16)
    big.commit(1 << 16)
    assert_equal(d.send(p.client, big), 8192 + 4096)
    # Unknown options are accepted and ignored.
    assert_equal(d.set_int_option(p.client, 6, 1, 1), 0)
    assert_equal(
        d.set_int_option(Int32(5), SOL_SOCKET, SO_SNDBUF, 1), neg(Errno.EBADF)
    )


# ---- ports, addresses, fds ------------------------------------------------------


def test_bind_conflicts_and_reuseport() raises:
    var d = quiet()
    var a = Int32(d.socket(AF_INET, SOCK_STREAM))
    assert_equal(d.bind(a, v4(8080)), 0)
    assert_equal(d.bind(a, v4(8081)), neg(Errno.EINVAL))
    var b = Int32(d.socket(AF_INET, SOCK_STREAM))
    assert_equal(d.bind(b, v4(8080)), neg(Errno.EADDRINUSE))
    var w = Int32(d.socket(AF_INET, SOCK_STREAM))
    assert_equal(
        d.bind(w, SocketAddr(Ipv4Addr.UNSPECIFIED, 8080).to_raw()),
        neg(Errno.EADDRINUSE),
    )
    _ = d.close(a)
    assert_equal(d.bind(b, v4(8080)), 0)  # free again after close
    # SO_REUSEPORT on both: two listeners share a port.
    var r1 = Int32(d.socket(AF_INET, SOCK_STREAM))
    var r2 = Int32(d.socket(AF_INET, SOCK_STREAM))
    _ = d.set_int_option(r1, SOL_SOCKET, SO_REUSEPORT, 1)
    _ = d.set_int_option(r2, SOL_SOCKET, SO_REUSEPORT, 1)
    assert_equal(d.bind(r1, v4(9000)), 0)
    assert_equal(d.bind(r2, v4(9000)), 0)
    assert_equal(d.listen(r1, 64), 0)
    assert_equal(d.listen(r2, 64), 0)
    for _ in range(20):
        var c = Int32(d.socket(AF_INET, SOCK_STREAM))
        _ = d.connect(c, v4(9000))
    for _ in range(4):
        _ = events(d, 10 * LAT)
    var peer = RawSockaddr()
    var n1 = 0
    var n2 = 0
    while d.accept(r1, peer) >= 0:
        n1 += 1
    while d.accept(r2, peer) >= 0:
        n2 += 1
    assert_equal(n1 + n2, 20)
    assert_true(n1 > 0 and n2 > 0)


def test_wildcard_listener_and_ipv6() raises:
    var d = quiet()
    var l = Int32(d.socket(AF_INET, SOCK_STREAM))
    assert_equal(d.bind(l, SocketAddr(Ipv4Addr.UNSPECIFIED, 7000).to_raw()), 0)
    assert_equal(d.listen(l, 8), 0)
    var c = Int32(d.socket(AF_INET, SOCK_STREAM))
    _ = d.connect(c, v4(7000))
    _ = events(d, 10 * LAT)
    _ = events(d, 10 * LAT)
    assert_equal(d.socket_error(c), 0)
    var l6 = Int32(d.socket(AF_INET6, SOCK_STREAM))
    assert_equal(d.bind(l6, SocketAddr(Ipv6Addr.LOCALHOST, 0).to_raw()), 0)
    assert_equal(d.listen(l6, 8), 0)
    var local = RawSockaddr()
    assert_equal(d.local_addr(l6, local), 0)
    var la = SocketAddr.from_raw(local)
    assert_true(la.is_ipv6())
    assert_equal(String(la.ip()), "::1")
    var c6 = Int32(d.socket(AF_INET6, SOCK_STREAM))
    assert_equal(d.connect(c6, v4(7000)), neg(Errno.EAFNOSUPPORT))
    assert_equal(d.connect(c6, local), neg(Errno.EINPROGRESS))
    for _ in range(4):
        _ = events(d, 10 * LAT)
    var peer = RawSockaddr()
    assert_true(d.accept(l6, peer) >= SIM_FD_BASE)
    assert_equal(String(SocketAddr.from_raw(peer).ip()), "::1")


def test_fds_are_never_reused() raises:
    var d = quiet()
    var a = d.socket(AF_INET, SOCK_STREAM)
    _ = d.close(Int32(a))
    var b = d.socket(AF_INET, SOCK_STREAM)
    assert_true(b > a)
    var buf = ByteBuffer(capacity=8)
    assert_equal(d.recv(Int32(a), buf), neg(Errno.EBADF))
    assert_equal(d.register(Int32(a), 1), neg(Errno.EBADF))
    assert_equal(d.socket(1, SOCK_STREAM), neg(Errno.EAFNOSUPPORT))
    assert_equal(d.open_sockets(), 1)
    assert_equal(d.register(Int32(b), 1), 0)
    assert_equal(d.register(Int32(b), 1), neg(Errno.EEXIST))
    assert_equal(d.deregister(Int32(b)), 0)
    assert_equal(d.deregister(Int32(b)), neg(Errno.ENOENT))


# ---- virtual clock -------------------------------------------------------------


def test_wait_timeout_advances_virtual_time_only() raises:
    var d = quiet()
    var t0 = d.now().as_nanos()
    var e = events(d, 10_000_000_000)
    assert_equal(len(e), 0)
    assert_equal(d.now().as_nanos() - t0, 10_000_000_000)
    _ = events(d, 0)
    assert_equal(d.now().as_nanos() - t0, 10_000_000_000)


def test_wait_forever_with_nothing_scheduled_is_a_deadlock() raises:
    var d = quiet()
    var l = Int32(d.socket(AF_INET, SOCK_STREAM))
    _ = d.bind(l, v4(0))
    _ = d.listen(l, 8)
    _ = d.register(l, TL)
    var raised = False
    try:
        _ = events(d, -1)
    except e:
        raised = True
        assert_equal(String(e.op), "SimDriver.wait: deadlock")
    assert_true(raised)


def test_wait_stops_at_the_earliest_event() raises:
    var d = quiet()
    var p = connected(d)
    _ = d.send(p.client, bytes_of("z"))
    var t0 = d.now().as_nanos()
    var e = events(d, 1_000_000_000)
    assert_equal(len(e), 1)
    assert_equal(d.now().as_nanos() - t0, LAT)


def test_max_events_leaves_the_rest_queued() raises:
    var d = quiet()
    var p = connected(d)
    d.config.max_events = 1
    _ = d.send(p.client, bytes_of("1"))
    _ = d.send(p.server, bytes_of("2"))
    var e1 = events(d, -1)
    assert_equal(len(e1), 1)
    var e2 = events(d, 0)
    assert_equal(len(e2), 1)
    assert_true(e1[0].token != e2[0].token)
    assert_equal(len(events(d, 0)), 0)


# ---- faults keep the edge contract ----------------------------------------------


def test_short_read_fault_rearms_the_edge() raises:
    var d = quiet()
    var p = connected(d)
    d.faults.short_read = 1.0
    var msg = ByteBuffer(capacity=100)
    msg.commit(100)
    assert_equal(d.send(p.client, msg), 100)
    _ = events(d, -1)
    var total = 0
    var rounds = 0
    while total < 100:
        var buf = ByteBuffer(capacity=4096)
        var r = d.recv(p.server, buf)
        assert_true(r > 0 and r < 100)
        total += r
        rounds += 1
        if total < 100:
            # Less than room came back while data remains: an edge follows.
            assert_true((mask_of(events(d, 0), TS) & READ_READY) != 0)
    assert_true(rounds > 1)
    assert_true(d.stats.faults[FAULT_SHORT_READ] > 0)


def test_short_write_and_eagain_faults_rearm_the_edge() raises:
    var d = quiet()
    var p = connected(d)
    d.faults.short_write = 1.0
    var msg = ByteBuffer(capacity=100)
    msg.commit(100)
    var r = d.send(p.client, msg)
    assert_true(r > 0 and r < 100)
    assert_equal(mask_of(events(d, 0), TC) & WRITE_READY, WRITE_READY)
    d.faults.short_write = 0.0
    d.faults.spurious_eagain = 1.0
    assert_equal(d.send(p.client, msg), neg(Errno.EAGAIN))
    assert_equal(mask_of(events(d, 0), TC) & WRITE_READY, WRITE_READY)
    _ = events(d, -1)
    var buf = ByteBuffer(capacity=4096)
    assert_equal(d.recv(p.server, buf), neg(Errno.EAGAIN))
    assert_equal(mask_of(events(d, 0), TS) & READ_READY, READ_READY)
    d.faults.spurious_eagain = 0.0
    assert_equal(d.recv(p.server, buf), r)
    assert_true(d.stats.faults[FAULT_SHORT_WRITE] > 0)
    assert_true(d.stats.faults[FAULT_EAGAIN] >= 2)


def test_spurious_edges_never_claim_a_connecting_socket_writable() raises:
    var d = quiet()
    d.faults.spurious_edges = 1.0
    d.faults.drop_syn = 1.0
    var c = Int32(d.socket(AF_INET, SOCK_STREAM))
    _ = d.register(c, TC)
    _ = d.connect(c, v4(1234))
    for _ in range(50):
        var e = events(d, 1000)
        assert_equal(mask_of(e, TC) & WRITE_READY, 0)
    assert_true(d.stats.faults[FAULT_SPURIOUS_EDGE] > 0)
    assert_true(d.stats.faults[FAULT_DROP_SYN] == 1)
    # The SYN is gone for good: only the application can give up.
    var raised = False
    try:
        _ = events(d, -1)
    except:
        raised = True
    assert_true(raised)


def test_accept_error_bursts_keep_connections_queued() raises:
    var d = quiet()
    var l = Int32(d.socket(AF_INET, SOCK_STREAM))
    _ = d.bind(l, v4(0))
    _ = d.listen(l, 8)
    _ = d.register(l, TL)
    var local = RawSockaddr()
    _ = d.local_addr(l, local)
    var c = Int32(d.socket(AF_INET, SOCK_STREAM))
    _ = d.connect(c, v4(port_of(local)))
    for _ in range(4):
        _ = events(d, 10 * LAT)
    d.faults.accept_error = 1.0
    var peer = RawSockaddr()
    assert_equal(d.accept(l, peer), neg(Errno.EMFILE))
    # The listener goes straight back on the ready list.
    assert_equal(mask_of(events(d, 0), TL), READ_READY)
    d.faults.accept_error = 0.0
    var r = d.accept(l, peer)
    while r == neg(Errno.EMFILE):  # the rest of the burst
        r = d.accept(l, peer)
    assert_true(r >= SIM_FD_BASE)
    assert_true(d.stats.faults[FAULT_ACCEPT_ERROR] == 1)


def test_accept_abort_discards_the_connection_and_resets_its_client() raises:
    var d = quiet()
    var l = Int32(d.socket(AF_INET, SOCK_STREAM))
    _ = d.bind(l, v4(0))
    _ = d.listen(l, 8)
    var local = RawSockaddr()
    _ = d.local_addr(l, local)
    var c = Int32(d.socket(AF_INET, SOCK_STREAM))
    _ = d.register(c, TC)
    _ = d.connect(c, v4(port_of(local)))
    for _ in range(4):
        _ = events(d, 10 * LAT)
    d.faults.accept_abort = 1.0
    var peer = RawSockaddr()
    assert_equal(d.accept(l, peer), neg(Errno.ECONNABORTED))
    d.faults.accept_abort = 0.0
    assert_equal(d.accept(l, peer), neg(Errno.EAGAIN))
    _ = events(d, 10 * LAT)
    var buf = ByteBuffer(capacity=8)
    assert_equal(d.recv(c, buf), neg(Errno.ECONNRESET))
    assert_true(d.stats.faults[FAULT_ACCEPT_ABORT] == 1)


# ---- determinism -------------------------------------------------------------


def scripted_run(seed: UInt64) raises -> Tuple[UInt64, Int, Int]:
    """A fixed program under jitter and faults: (trace, time, bytes)."""
    var d = SimDriver(seed)
    d.faults = SimFaults.all(0.3, 0.01)
    var l = Int32(d.socket(AF_INET, SOCK_STREAM))
    _ = d.bind(l, v4(0))
    _ = d.listen(l, 64)
    _ = d.register(l, 1)
    var local = RawSockaddr()
    _ = d.local_addr(l, local)
    var port = port_of(local)
    var clients = List[Int32]()
    for k in range(8):
        var c = Int32(d.socket(AF_INET, SOCK_STREAM))
        _ = d.register(c, UInt64(10 + k))
        _ = d.connect(c, v4(port))
        clients.append(c)
    var servers = List[Int32]()
    var data = ByteBuffer(capacity=3000)
    data.commit(3000)
    var got = 0
    for _ in range(200):
        var evs = List[ReadyEvent]()
        d.wait(1_000_000, evs)
        var peer = RawSockaddr()
        var a = d.accept(l, peer)
        if a >= 0:
            _ = d.register(Int32(a), UInt64(100 + len(servers)))
            servers.append(Int32(a))
        for k in range(len(clients)):
            _ = d.send(clients[k], data)
        for k in range(len(servers)):
            var buf = ByteBuffer(capacity=2048)
            var r = d.recv(servers[k], buf)
            if r > 0:
                got += r
    return (d.trace_hash(), d.now().as_nanos(), got)


def test_same_seed_replays_exactly_and_seeds_differ() raises:
    var a = scripted_run(42)
    var b = scripted_run(42)
    var c = scripted_run(43)
    assert_equal(a[0], b[0])
    assert_equal(a[1], b[1])
    assert_equal(a[2], b[2])
    assert_true(a[0] != c[0])
    assert_true(a[2] > 0)


def test_seed_comes_from_the_environment() raises:
    var saved = getenv("MOJO_TCP_SIM_SEED")
    _ = setenv("MOJO_TCP_SIM_SEED", "123456789")
    assert_equal(SimDriver.create().seed(), 123456789)
    _ = setenv("MOJO_TCP_SIM_SEED", "not-a-number")
    var h = sim_seed_from_env()
    assert_true(h != DEFAULT_SIM_SEED)
    assert_equal(h, sim_seed_from_env())
    _ = unsetenv("MOJO_TCP_SIM_SEED")
    assert_equal(SimDriver.create().seed(), DEFAULT_SIM_SEED)
    if saved.byte_length() > 0:
        _ = setenv("MOJO_TCP_SIM_SEED", saved)


def test_stats_count_syscalls_and_bytes() raises:
    var d = quiet()
    var p = connected(d)
    var before = d.stats.syscalls[SYS_SEND]
    _ = d.send(p.client, bytes_of("12345"))
    _ = events(d, -1)
    var buf = ByteBuffer(capacity=16)
    _ = d.recv(p.server, buf)
    assert_equal(d.stats.syscalls[SYS_SEND], before + 1)
    assert_true(d.stats.syscalls[SYS_RECV] >= 1)
    assert_equal(d.stats.bytes_sent, 5)
    assert_equal(d.stats.bytes_received, 5)
    assert_true(d.stats.total_syscalls() > 10)
    assert_true(String(d.stats).find("send=") >= 0)


def main() raises:
    comptime assert is_defined["MOJO_TCP_SIM"](), "build with -D MOJO_TCP_SIM=1"
    TestSuite.discover_tests[__functions_in_module()]().run()
