"""Regression tests for the third review of `net` (2026-10-27; docs/net.md,
"Third review"): TCP streams, listeners and dialing.

STR-1 / DNS-2: a TCP connect to a local port that nothing listens on can
meet itself. The kernel may pick that very port as the source, the SYN
answers itself, and the connect succeeds, so the stream reads back its own
writes. The tests make it happen every time by pinning the socket's source
port to the target port with `IP_LOCAL_PORT_RANGE` (Linux 6.3+; skipped on
older kernels).

UDP-5 / SYS-4: deadlines and the `try_*` forms relied on O_NONBLOCK, which
every duplicate of a descriptor shares. A clone set blocking made them wait
in the kernel. The tests clear the flag through a clone, with a 2 s
SO_RCVTIMEO as a guard, so the old code fails after 2 s instead of
hanging.

DNS-1: a name's answer could carry thousands of addresses, and dialing kept
every attempt open: one dial held a socket per 250 ms until its deadline.
Now at most `MAX_ADDRESSES` per family are tried and `MAX_IN_FLIGHT` stay
open.

DNS-4: an answer of 0.0.0.0 or :: connected to this host (hosts files use
0.0.0.0 to block a name), and `::` ranked above IPv4.

DNS-3: a truncated answer and the EDNS fallback each restarted a try's
timer, so a server answering every leg late chained one try to four
timeouts. Now a try lasts at most twice `timeout` (UDP, then one TCP
leg).

DNS-5: resolv.conf took lines glibc ignores (a keyword after blanks, or
followed by a CR) and nameserver values with a trailing CR (a CRLF file),
which glibc rejects.

STR-2: `TcpListener.from_socket` took an SCTP stream listener (a SOCK_STREAM
too); every accept then failed setting TCP_NODELAY and dropped the
connection. UDP-4: `UdpSocket.from_socket` took a socket with UDP_GRO on,
whose receives merge datagrams with nothing in the result to say so.

STR-3: `idle_state()` peeks one byte, and a peek skips out-of-band input:
an AF_UNIX MSG_OOB byte, TCP urgent data. It said EMPTY with input unread,
so a pool would reuse the connection.

UDP-3: `connect` kept what was queued before it, so on a socket bound
first, a stranger's datagram came out of `recv` as if from the peer.

UDP-1: a server bound to a wildcard address replied from whichever address
the route back chose, and a client connected to another of the host's
addresses dropped the reply; no API could fix it. `receive_destination`,
`recv_from_to` and `send_from` (PKTINFO) answer from the address each
datagram came to. 127.0.0.2 is one of this host's addresses (all of
127.0.0.0/8 is local), but the route back to 127.0.0.1 leaves from
127.0.0.1.

UDP-6 (a cost, not a bug): every batch receive rewrote all `capacity()`
headers. It now rewrites only those the last receive or send changed. The
test checks that a batch still receives whole datagrams after it sent
short ones, and long ones after a receive of short ones."""

from std.os import listdir
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError
from linux.abi import Pollfd, Rlimit
from linux import sys
from linux.consts import IPPROTO_IP, IPPROTO_UDP, MSG_NOSIGNAL, MSG_OOB, POLLOUT, RLIMIT_NOFILE, SO_RCVTIMEO, SOL_SOCKET
from linux.probe import get_rlimit, set_rlimit
from linux.time import Deadline, Duration, Instant
from net.addr import IpAddr, SocketAddr
from net.blocking import connect_with_deadline
from net.dial import MAX_ADDRESSES, MAX_IN_FLIGHT, _Attempt, _Errors, _settle, dial_tcp
from net.resolv import Hosts, ResolvConf
from net.resolver import Resolver, precedence
from net.socket import Domain, Protocol, SockType, Socket
from net.blocking import IdleState
from net.tcp import TcpListener, TcpStream
from net.unix import UnixStream
from fake_dns import FakeDns
from net.udp import DatagramBatch, UdpSocket

comptime _IP_LOCAL_PORT_RANGE = 51  # (linux/in.h; Linux 6.3+)


def _free_port() raises -> Int:
    """A loopback port nothing listens on (bound, then released)."""
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    return Int(l.local_addr().port())


def _pinned(port: Int, *, nonblocking: Bool) raises -> Optional[Socket]:
    """An IPv4 stream socket whose connect can only take source port
    `port`, or None where the kernel has no IP_LOCAL_PORT_RANGE."""
    var s = Socket.new(Domain.IPV4, SockType.STREAM, nonblocking=nonblocking)
    var ports = UInt32(port) << 16 | UInt32(port)  # (a u32: high << 16 | low)
    var raw = List[UInt8]()
    for i in range(4):
        raw.append(UInt8((ports >> UInt32(8 * i)) & 0xFF))  # (little-endian)
    try:
        s.set_option_bytes(IPPROTO_IP, _IP_LOCAL_PORT_RANGE, Span(raw))
    except:
        print("skip: no IP_LOCAL_PORT_RANGE (Linux 6.3+)")
        return None
    return s^


def test_str1_connect_to_itself_is_refused() raises:
    for _ in range(3):
        var port = _free_port()
        var s = _pinned(port, nonblocking=True)
        if not s:
            return
        var refused = False
        try:
            connect_with_deadline(
                s.value(),
                SocketAddr.parse(String("127.0.0.1:", port)).to_raw(),
                Deadline.after(Duration.from_secs(5)),
            )
        except e:
            assert_equal(e.kind, ErrorKind.ConnectionRefused, String(e))
            refused = True
        assert_true(refused, "a connect to itself succeeded")


def test_str1_happy_eyeballs_drops_an_attempt_connected_to_itself() raises:
    var port = _free_port()
    var s = _pinned(port, nonblocking=False)
    if not s:
        return
    var target = SocketAddr.parse(String("127.0.0.1:", port))
    s.value().connect(target)  # (blocking: the self-connect completes)
    assert_equal(s.value().local_addr(), s.value().peer_addr())  # (the setup works)
    var fd = s.value().raw_fd()
    var attempts = List[_Attempt]()
    attempts.append(_Attempt(s.take(), target))
    var revents = List[Pollfd]()
    revents.append(Pollfd(fd, Int16(POLLOUT), Int16(POLLOUT)))
    var errors = _Errors()
    var winner = _settle(attempts, Span(revents), errors)
    assert_false(Bool(winner), "an attempt connected to itself won")
    assert_equal(len(attempts), 0)
    assert_true(Bool(errors.first))
    assert_equal(errors.first.value().kind, ErrorKind.ConnectionRefused)


def _le(v: Int, n: Int) -> List[UInt8]:
    var b = List[UInt8]()
    for i in range(n):
        b.append(UInt8((v >> (8 * i)) & 0xFF))
    return b^


def _blocking_with_guard(var sock: Socket) raises:
    """Clear O_NONBLOCK on the open file `sock` shares, and give it a 2 s
    SO_RCVTIMEO (a struct timeval) so a call stuck in the kernel ends."""
    sock.set_nonblocking(False)
    var tv = _le(2, 8)
    tv.extend(_le(0, 8))
    sock.set_option_bytes(SOL_SOCKET, SO_RCVTIMEO, Span(tv))


def _ms_since(t0: Instant) -> Int:
    return Int(Instant.now().duration_since(t0).as_millis())


def test_sys4_a_read_deadline_holds_when_a_clone_is_blocking() raises:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = TcpStream.connect(l.local_addr())
    var peer = l.accept()  # (it never writes)
    _blocking_with_guard(c.try_clone()^.into_socket())
    c.set_read_deadline(Deadline.after(Duration.from_millis(100)))
    var buf = List[UInt8](length=16, fill=0)
    var t0 = Instant.now()
    var timed_out = False
    try:
        _ = c.read(Span(buf))
    except e:
        assert_equal(e.kind, ErrorKind.TimedOut, String(e))
        timed_out = True
    assert_true(timed_out)
    assert_true(_ms_since(t0) < 1000, String("the read took ", _ms_since(t0), " ms"))
    var none = c.try_read(Span(buf))
    assert_false(Bool(none))
    assert_true(_ms_since(t0) < 1000, String("try_read waited: ", _ms_since(t0), " ms"))
    _ = peer^


def test_udp5_try_forms_never_wait_when_a_clone_is_blocking() raises:
    var u = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
    _blocking_with_guard(u.try_clone()^.into_socket())
    var buf = List[UInt8](length=64, fill=0)
    var t0 = Instant.now()
    assert_false(Bool(u.try_recv_from(Span(buf))))
    assert_true(_ms_since(t0) < 1000, String("try_recv_from waited: ", _ms_since(t0), " ms"))
    var tx = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
    _ = tx.send_to("x".as_bytes(), u.local_addr())
    var batch = DatagramBatch(4)
    t0 = Instant.now()
    var n = 0
    for _ in range(100):  # (until the datagram is queued)
        n = u.try_recv_batch(batch)
        if n > 0:
            break
    assert_equal(n, 1)
    assert_true(_ms_since(t0) < 1000, String("try_recv_batch waited for a full batch: ", _ms_since(t0), " ms"))


def _resolver_with(hosts: StringSlice) raises -> Resolver:
    var c = ResolvConf()
    c.nameservers.append(SocketAddr.parse("127.0.0.1:9"))
    return Resolver(c^, Hosts.parse(hosts))


def _black_hole() raises -> Tuple[TcpListener, List[Socket]]:
    """A wildcard listener whose accept queue is full: a connect to any
    127.0.0.x on its port hangs (Linux drops the SYNs)."""
    var l = TcpListener.bind(SocketAddr.parse("0.0.0.0:0"), backlog=0)
    var fillers = List[Socket]()
    var target = SocketAddr.parse(String("127.0.0.1:", l.local_addr().port())).to_raw()
    for _ in range(3):
        var s = Socket.new(Domain.IPV4, SockType.STREAM, nonblocking=True)
        _ = sys.connect(s, target.storage, target.socklen())
        fillers.append(s^)
    var t = Instant.now()
    while t.elapsed() < Duration.from_millis(50):  # (the handshakes that fit)
        pass
    return (l^, fillers^)


def test_dns1_attempts_in_flight_are_capped() raises:
    var hole = _black_hole()
    var port = hole[0].local_addr().port()
    var hosts = String()
    for i in range(2, 40):
        hosts += String("127.0.0.", i, " many.test\n")
    var r = _resolver_with(hosts)
    var saved = get_rlimit(RLIMIT_NOFILE)
    var open_now = len(listdir("/proc/self/fd"))
    set_rlimit(RLIMIT_NOFILE, Rlimit(UInt64(open_now + MAX_IN_FLIGHT + 4), saved.max))
    var kind = ErrorKind.Other
    try:
        _ = dial_tcp(r, "many.test", port, Deadline.after(Duration.from_millis(3500)))
    except e:
        kind = e.kind
    set_rlimit(RLIMIT_NOFILE, saved)
    assert_equal(kind, ErrorKind.TimedOut, "more attempts stayed open than MAX_IN_FLIGHT")
    _ = hole^


def test_dns1_addresses_per_family_are_capped() raises:
    var good = TcpListener.bind(SocketAddr.parse("127.0.0.99:0"))
    var port = good.local_addr().port()
    var hosts = String()
    for i in range(2, 2 + MAX_ADDRESSES):  # (refused: nothing listens there)
        hosts += String("127.0.0.", i, " many.test\n")
    hosts += "127.0.0.99 many.test\n"
    var r = _resolver_with(hosts)
    var kind = ErrorKind.Other
    try:
        _ = dial_tcp(r, "many.test", port, Deadline.after(Duration.from_secs(10)))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.ConnectionRefused, "an address past MAX_ADDRESSES was tried")
    _ = good^


def test_dns1_repeated_answers_are_tried_once() raises:
    """MAX_ADDRESSES repeats of one refused address, then a good one: the
    repeats count once, so the good one is reached."""
    var good = TcpListener.bind(SocketAddr.parse("127.0.0.99:0"))
    var port = good.local_addr().port()
    var hosts = String()
    for _ in range(MAX_ADDRESSES + 4):
        hosts += "127.0.0.2 many.test\n"
    hosts += "127.0.0.99 many.test\n"
    var r = _resolver_with(hosts)
    var s = dial_tcp(r, "many.test", port, Deadline.after(Duration.from_secs(10)))
    assert_equal(s.peer_addr(), SocketAddr.parse(String("127.0.0.99:", port)))
    _ = good^


def test_dns4_unspecified_answers_are_skipped() raises:
    var l = TcpListener.bind(SocketAddr.parse("0.0.0.0:0"))
    var port = l.local_addr().port()
    var r = _resolver_with("0.0.0.0 blocked.test\n:: blocked.test\n")
    var connected = False
    try:
        _ = dial_tcp(r, "blocked.test", port, Deadline.after(Duration.from_secs(3)))
        connected = True
    except:
        pass
    assert_false(connected, "an answer of 0.0.0.0 or :: reached this host")
    _ = l^


def test_dns4_unspecified_ipv6_has_precedence_1() raises:
    assert_equal(precedence(IpAddr.parse("::")), 1)  # (RFC 6724: ::/96)
    assert_equal(precedence(IpAddr.parse("::1")), 50)
    assert_equal(precedence(IpAddr.parse("::ffff:1.2.3.4")), 35)
    assert_equal(precedence(IpAddr.parse("2001:db8::1")), 40)


def test_dns3_a_try_lasts_at_most_two_timeouts() raises:
    """Server 0 answers each leg after 0.9 s: truncated over UDP, FORMERR
    over TCP with EDNS, then truncated again without it. With a timeout of
    1 s the try ends by 2 s and server 1 answers; the old timers chained
    it to 3.6 s."""
    var dns = FakeDns()
    var c = dns.conf(timeout_secs=1, attempts=1)
    c.edns0 = True
    var r = Resolver(c^, Hosts())
    var t0 = Instant.now()
    var got = r.lookup_ip("chain.test", Deadline.after(Duration.from_secs(10)))
    var ms = _ms_since(t0)
    assert_true(len(got) > 0)
    assert_equal(String(got[0]), "192.0.2.50")
    assert_true(ms < 2500, String("the try took ", ms, " ms"))
    dns^.stop()


def test_dns5_resolv_conf_lines_as_glibc_reads_them() raises:
    var c = ResolvConf.parse(
        "nameserver 192.0.2.1\r\n  nameserver 192.0.2.2\n\tnameserver 192.0.2.5\n"
        + "nameserver\r192.0.2.6\nnameserver\t192.0.2.3\nnameserver 192.0.2.4 # x\n"
    )
    assert_equal(len(c.nameservers), 2)
    assert_equal(String(c.nameservers[0]), "192.0.2.3:53")
    assert_equal(String(c.nameservers[1]), "192.0.2.4:53")
    var d = ResolvConf.parse("  search a.test\noptions ndots:3\n")
    assert_equal(len(d.search), 0)
    assert_equal(d.ndots, 3)


def _listening(proto: Int) raises -> Optional[Socket]:
    """A listening IPv4 stream socket of protocol `proto`, or None where the
    kernel has none (a module not loaded, MPTCP off)."""
    try:
        var s = Socket.new(Domain.IPV4, SockType.STREAM, Protocol(proto))
        s.bind(SocketAddr.parse("127.0.0.1:0"))
        s.listen(4)
        return s^
    except:
        return None


def test_str2_only_tcp_and_mptcp_listeners_are_adopted() raises:
    var sctp = _listening(132)
    if sctp:
        var refused = False
        try:
            _ = TcpListener.from_socket(sctp.take())
        except e:
            assert_equal(e.kind, ErrorKind.InvalidInput, String(e))
            refused = True
        assert_true(refused, "an SCTP listener was adopted as TCP")
    else:
        print("skip: no SCTP")
    var mptcp = _listening(262)
    if mptcp:
        _ = TcpListener.from_socket(mptcp.take())  # (accepted)
    else:
        print("skip: no MPTCP")
    var tcp = _listening(6)
    _ = TcpListener.from_socket(tcp.take())


def test_udp4_a_socket_with_gro_is_refused() raises:
    var s = Socket.new(Domain.IPV4, SockType.DGRAM)
    try:
        s.set_option_int(IPPROTO_UDP, 104, 1)  # (UDP_GRO, Linux 5.0+)
    except:
        print("skip: no UDP_GRO")
        return
    s.bind(SocketAddr.parse("127.0.0.1:0"))
    var refused = False
    try:
        _ = UdpSocket.from_socket(s^)
    except e:
        assert_equal(e.kind, ErrorKind.InvalidInput, String(e))
        refused = True
    assert_true(refused, "a UDP socket with GRO on was adopted")
    var plain = Socket.new(Domain.IPV4, SockType.DGRAM)
    _ = UdpSocket.from_socket(plain^)


def _wait_ms(ms: Int):
    var t = Instant.now()
    while t.elapsed() < Duration.from_millis(ms):
        pass


def test_str3_idle_state_sees_out_of_band_input() raises:
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    assert_equal(b.idle_state(), IdleState.EMPTY)
    var one: List[UInt8] = [33]
    assert_equal(sys.send(a, Span(one), MSG_OOB | MSG_NOSIGNAL), 1)
    _wait_ms(20)
    assert_equal(b.idle_state(), IdleState.DATA)
    # TCP urgent data (without SO_OOBINLINE): the same.
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept()
    assert_equal(s.stream.idle_state(), IdleState.EMPTY)
    assert_equal(sys.send(c, Span(one), MSG_OOB | MSG_NOSIGNAL), 1)
    _wait_ms(20)
    assert_equal(s.stream.idle_state(), IdleState.DATA)
    _ = a^  # (the senders stay open: a closed one reads as CLOSED)
    _ = c^


def test_udp3_connect_discards_what_was_queued_before() raises:
    var b = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
    var stranger = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
    var peer = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
    _ = stranger.send_to("x".as_bytes(), b.local_addr())
    _wait_ms(20)
    b.connect(peer.local_addr())
    _ = peer.send_to("p".as_bytes(), b.local_addr())
    var buf = List[UInt8](length=8, fill=0)
    b.set_read_deadline(Deadline.after(Duration.from_secs(2)))
    var d = b.recv_from(Span(buf))
    assert_equal(d.sender, peer.local_addr())
    assert_equal(Int(buf[0]), ord("p"))
    _ = stranger^


def _wildcard_server(family6: Bool) raises -> UdpSocket:
    var s = UdpSocket.bind(SocketAddr.parse("[::]:0" if family6 else "0.0.0.0:0"))
    s.receive_destination()
    s.set_read_deadline(Deadline.after(Duration.from_secs(2)))
    return s^


def _client_to(port: UInt16) raises -> UdpSocket:
    """Bound to 127.0.0.1, connected to 127.0.0.2:`port`."""
    var c = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
    c.connect(SocketAddr.parse(String("127.0.0.2:", port)))
    return c^


def test_udp1_a_wildcard_server_replies_from_the_address_it_was_sent_to() raises:
    for family6 in [False, True]:
        var srv: UdpSocket
        try:
            srv = _wildcard_server(family6)
        except:
            print("skip: no IPv6 socket")
            continue
        var port = srv.local_addr().port()
        var c = _client_to(port)
        c.set_read_deadline(Deadline.after(Duration.from_millis(500)))
        _ = c.send("ping".as_bytes())
        var buf = List[UInt8](length=64, fill=0)
        var a = srv.recv_from_to(Span(buf))
        assert_true(Bool(a.local), String(a))
        assert_equal(String(a.local.value().to_canonical()), "127.0.0.2", String(a))
        assert_true(a.interface > 0, String(a))
        # The old way: the reply leaves from 127.0.0.1, and the client
        # (connected to 127.0.0.2) drops it.
        _ = srv.send_to(Span(buf)[0 : a.datagram.len], a.datagram.sender)
        var lost = False
        try:
            _ = c.recv(Span(buf))
        except e:
            lost = e.is_deadline()
        assert_true(lost, "the reply from the route's address arrived")
        # From the address it was sent to: it arrives.
        _ = srv.send_from(Span(buf)[0:4], a.datagram.sender, a.local.value())
        c.set_read_deadline(Deadline.after(Duration.from_secs(2)))
        var d = c.recv(Span(buf))
        assert_equal(d.len, 4)
        assert_equal(String(d.sender), String("127.0.0.2:", port))


def test_udp1_without_receive_destination_local_is_none() raises:
    var srv = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
    _ = c.send_to("x".as_bytes(), srv.local_addr())
    srv.set_read_deadline(Deadline.after(Duration.from_secs(2)))
    var buf = List[UInt8](length=8, fill=0)
    var a = srv.recv_from_to(Span(buf))
    assert_false(Bool(a.local))
    assert_equal(a.datagram.len, 1)
    assert_equal(a.datagram.sender, c.local_addr())


def test_udp6_a_batch_receives_whole_datagrams_after_a_send() raises:
    var u = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
    var tx = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
    var batch = DatagramBatch(4, 64)
    var one: List[UInt8] = [7]
    _ = tx.send_to(Span(one), u.local_addr())  # (a receive first: the headers in receive form)
    _wait_ms(20)
    assert_equal(u.try_recv_batch(batch), 1)
    batch.clear()
    batch.push(Span(one), tx.local_addr())  # (two 1-byte datagrams sent from the batch)
    batch.push(Span(one), tx.local_addr())
    assert_equal(u.send_batch(batch), 2)
    var big = List[UInt8](length=30, fill=9)  # (then 30-byte ones received into it)
    for _ in range(3):
        _ = tx.send_to(Span(big), u.local_addr())
    _wait_ms(20)
    var n = u.try_recv_batch(batch)
    assert_equal(n, 3)
    for i in range(n):
        assert_equal(batch.datagram(i).len, 30)
        assert_equal(batch.datagram(i).sender, tx.local_addr())
        var got = batch.payload(i)
        for k in range(len(got)):
            assert_equal(Int(got[k]), 9, String("datagram ", i, " byte ", k, " was not stored"))
    for _ in range(4):  # (short ones, then a long one)
        _ = tx.send_to(Span(one), u.local_addr())
    _wait_ms(20)
    assert_equal(u.try_recv_batch(batch), 4)
    var long = List[UInt8](length=64, fill=1)
    _ = tx.send_to(Span(long), u.local_addr())
    _wait_ms(20)
    assert_equal(u.try_recv_batch(batch), 1)
    assert_equal(batch.datagram(0).len, 64)
    assert_false(batch.datagram(0).truncated())


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
