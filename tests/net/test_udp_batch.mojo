"""`DatagramBatch` with `UdpSocket.recv_batch` / `send_batch` (recvmmsg /
sendmmsg): round trips across several calls in order, truncation per
datagram, the nonblocking and deadline paths, push validation, connected
sockets, and progress (`sent()`) after a failing datagram."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError, sys
from linux.time import Deadline, Duration, Instant
from net.addr import SocketAddr
from net.udp import MAX_BATCH, Datagram, DatagramBatch, UdpSocket


def _bound() raises -> UdpSocket:
    var s = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
    s.set_deadline(Deadline.after(Duration.from_secs(10)))
    return s^


def _bytes(n: Int, fill: Int) -> List[UInt8]:
    return List[UInt8](length=n, fill=UInt8(fill))


def test_round_trip_across_several_calls_in_order() raises:
    var a = _bound()
    var b = _bound()
    var out = DatagramBatch(32, 256)
    for i in range(20):
        out.push(Span(_bytes(i + 1, i)), b.local_addr())
    assert_equal(a.send_batch(out), 20)
    assert_equal(out.sent(), 20)
    var inb = DatagramBatch(8, 256)
    var seen = 0
    while seen < 20:
        var n = b.recv_batch(inb)
        assert_true(n >= 1 and n <= 8)
        for i in range(n):
            var d = inb.datagram(i)
            assert_equal(d.len, seen + 1)
            assert_equal(d.sender, a.local_addr())
            assert_equal(Int(inb.payload(i)[0]), seen)
            seen += 1
    assert_equal(b.try_recv_batch(inb), 0)
    assert_equal(len(inb), 0)


def test_truncation_is_per_datagram() raises:
    var a = _bound()
    var b = _bound()
    for n in [10, 40, 16]:
        _ = a.send_to(Span(_bytes(n, 1)), b.local_addr())
    var inb = DatagramBatch(4, 16)
    var t = Instant.now()
    var got = 0
    var sizes = List[Int]()
    var lens = List[Int]()
    while got < 3 and t.elapsed() < Duration.from_secs(2):
        var n = b.try_recv_batch(inb)
        for i in range(n):
            sizes.append(inb.datagram(i).size)
            lens.append(inb.datagram(i).len)
        got += n
    assert_equal(len(sizes), 3)
    assert_equal(sizes[0], 10)
    assert_equal(sizes[1], 40)
    assert_equal(sizes[2], 16)
    assert_equal(lens[1], 16)  # truncated to the slot
    assert_true(inb.datagram(1).truncated())
    assert_false(inb.datagram(0).truncated())
    assert_false(inb.datagram(2).truncated())


def test_recv_batch_waits_up_to_the_deadline() raises:
    var b = _bound()
    b.set_read_deadline(Deadline.after(Duration.from_millis(50)))
    var inb = DatagramBatch(4)
    var expired = False
    try:
        _ = b.recv_batch(inb)
    except e:
        expired = e.is_deadline()
    assert_true(expired)


def test_push_and_constructor_validation() raises:
    var kinds = List[String]()
    for args in [(0, 64), (MAX_BATCH + 1, 64), (4, 0), (4, 65536)]:
        try:
            _ = DatagramBatch(args[0], args[1])
        except e:
            kinds.append(String(e.kind))
    var b = DatagramBatch(2, 8)
    var dest = SocketAddr.parse("127.0.0.1:9")
    try:
        b.push(Span(_bytes(9, 0)), dest)  # longer than a slot
    except e:
        kinds.append(String(e.kind))
    b.push(Span(_bytes(8, 0)), dest)
    b.push(Span(_bytes(1, 0)), dest)
    try:
        b.push(Span(_bytes(1, 0)), dest)  # full
    except e:
        kinds.append(String(e.kind))
    try:
        _ = b.payload(2)  # out of range
    except e:
        kinds.append(String(e.kind))
    assert_equal(len(kinds), 7)
    for k in kinds:
        assert_equal(k, "InvalidInput")
    b.clear()
    assert_equal(len(b), 0)
    b.push(Span(_bytes(3, 0)), dest)  # reusable after clear
    assert_equal(len(b), 1)


def test_connected_socket_batches() raises:
    var b = _bound()
    var c = _bound()
    c.connect(b.local_addr())
    var out = DatagramBatch(4, 32)
    for i in range(3):
        out.push(Span(_bytes(5, i)))
    assert_equal(c.send_batch(out), 3)
    var inb = DatagramBatch(4, 32)
    var got = 0
    while got < 3:
        got += b.recv_batch(inb)
    assert_equal(inb.datagram(0).sender, c.local_addr())


def test_progress_survives_a_failing_datagram() raises:
    # [small, too big for IPv4 (EMSGSIZE), small]: one goes out, then the
    # error is raised with sent() == 1.
    var a = _bound()
    var b = _bound()
    var out = DatagramBatch(3, 65535)
    out.push(Span(_bytes(4, 1)), b.local_addr())
    out.push(Span(_bytes(65535, 2)), b.local_addr())
    out.push(Span(_bytes(4, 3)), b.local_addr())
    var errno = 0
    try:
        _ = a.send_batch(out)
    except e:
        errno = Int(e.errno.value)
    assert_equal(errno, 90)  # EMSGSIZE
    assert_equal(out.sent(), 1)
    var buf = _bytes(8, 0)
    assert_equal(b.recv_from(Span(buf)).len, 4)


def test_try_send_batch_reports_progress() raises:
    var a = _bound()
    var b = _bound()
    var out = DatagramBatch(16, 64)
    for _ in range(16):
        out.push(Span(_bytes(32, 9)), b.local_addr())
    var t = Instant.now()
    while a.try_send_batch(out) < 16 and t.elapsed() < Duration.from_secs(2):
        pass
    assert_equal(out.sent(), 16)
    sys.keep_alive(b)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
