"""Regression tests for the review of `net.udp`:

- U1: after the read side is shut down, blocking receives (`recv_from`,
  `recv_batch`) raise NotConnected at once instead of spinning on a socket
  that polls readable while recv says EAGAIN; queued datagrams still come
  first. `shutdown_read` works on unconnected sockets.
- U2: a datagram that always fails no longer blocks the rest of a batch:
  `skip()` moves past it.
- U3: on a connected socket an ICMP refusal during a batch is absorbed by
  sendmmsg and surfaces on the next receive, as documented.
- U4: `from_socket` rejects datagram sockets that are not UDP (an ICMP
  "ping" socket would make truncation silent)."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError, sys
from linux.consts import IPPROTO_ICMP
from linux.time import Deadline, Duration, Instant
from net.addr import SocketAddr
from net.socket import Domain, Protocol, SockType, Socket
from net.udp import DatagramBatch, UdpSocket


def _bound() raises -> UdpSocket:
    var s = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
    s.set_deadline(Deadline.after(Duration.from_secs(10)))
    return s^


def _settle():
    var t = Instant.now()
    while t.elapsed() < Duration.from_millis(20):
        pass


def test_u1_receives_after_shutdown_read_never_spin() raises:
    var a = _bound()
    var b = _bound()
    _ = a.send_to(String("first").as_bytes(), b.local_addr())
    _settle()
    var waker = b.try_clone()
    waker.shutdown_read()  # unconnected: Linux applies it, says ENOTCONN
    var buf = List[UInt8](length=16, fill=0)
    assert_equal(b.recv_from(Span(buf)).len, 5)  # queued data first
    var kinds = List[String]()
    var t = Instant.now()
    try:
        _ = b.recv_from(Span(buf))
    except e:
        kinds.append(String(e.kind))
    var batch = DatagramBatch(4)
    try:
        _ = b.recv_batch(batch)
    except e:
        kinds.append(String(e.kind))
    assert_true(t.elapsed() < Duration.from_millis(200))  # no spin until the deadline
    assert_equal(len(kinds), 2)
    assert_equal(kinds[0], "NotConnected")
    assert_equal(kinds[1], "NotConnected")
    _ = a.send_to(String("late").as_bytes(), b.local_addr())
    _settle()
    assert_true(b.try_recv_from(Span(buf)))  # still queued and readable


def test_u2_skip_moves_past_a_failing_datagram() raises:
    var a = _bound()
    var b = _bound()
    var out = DatagramBatch(3, 64)
    out.push(String("one").as_bytes(), b.local_addr())
    out.push(String("bad").as_bytes(), SocketAddr.parse("[::1]:9"))  # IPv6 on IPv4
    out.push(String("two").as_bytes(), b.local_addr())
    var kind = String()
    try:
        _ = a.send_batch(out)
    except e:
        kind = String(e.kind)
    assert_true(kind.byte_length() > 0)
    assert_equal(out.sent(), 1)
    assert_equal(out.pending(), 2)
    out.skip()
    assert_equal(a.send_batch(out), 2)
    assert_equal(out.pending(), 0)
    var buf = List[UInt8](length=8, fill=0)
    assert_equal(String(from_utf8_lossy=Span(buf)[0 : b.recv_from(Span(buf)).len]), "one")
    assert_equal(String(from_utf8_lossy=Span(buf)[0 : b.recv_from(Span(buf)).len]), "two")
    var skip_kind = String()
    try:
        out.skip()  # nothing pending
    except e:
        skip_kind = String(e.kind)
    assert_equal(skip_kind, "InvalidInput")


def test_u3_batched_refusal_surfaces_on_receive() raises:
    var gone = _bound()
    var closed = gone.local_addr()
    gone^.close()
    var c = _bound()
    c.connect(closed)
    var out = DatagramBatch(3, 16)
    for _ in range(3):
        out.push(String("x").as_bytes())
    var raised = False
    var sent = 0
    try:
        sent = c.send_batch(out)
    except e:
        raised = e.kind == ErrorKind.ConnectionRefused
    if not raised:
        assert_equal(sent, 3)  # sendmmsg absorbed the refusal
        var buf = List[UInt8](length=4, fill=0)
        var kind = String()
        try:
            _ = c.recv(Span(buf))
        except e:
            kind = String(e.kind)
        assert_equal(kind, "ConnectionRefused")


def test_u4_from_socket_rejects_non_udp_datagram_sockets() raises:
    var ping: Socket
    try:
        ping = Socket.new(Domain.IPV4, SockType.DGRAM, Protocol(IPPROTO_ICMP))
    except:
        print("    (skipped: test_u4_from_socket_rejects_non_udp_datagram_sockets: ICMP sockets not allowed here)")
        return
    var kind = String()
    try:
        _ = UdpSocket.from_socket(ping^)
    except e:
        kind = String(e.kind)
    assert_equal(kind, "InvalidInput")
    var udp = Socket.new(Domain.IPV4, SockType.DGRAM, Protocol.UDP)
    _ = UdpSocket.from_socket(udp^)  # explicit IPPROTO_UDP is fine


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
