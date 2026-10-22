"""Nonblocking access for readiness loops: `try_read` / `try_write` /
`try_accept` (None instead of waiting, EOF, resets, a full send buffer),
an edge-triggered `linux.Epoll` loop that reads until None, and the server
helpers (`TcpListener.bind_reuseport`, `linux.probe.raise_nofile_limit`)."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Epoll, ErrorKind, IoError, sys
from linux.abi import EpollEvent
from linux.consts import EPOLLET, EPOLLIN, EPOLLOUT
from linux.probe import nofile_limit, raise_nofile_limit
from linux.time import Deadline, Duration, Instant
from net.addr import SocketAddr
from net.socket import Shutdown
from net.tcp import TcpListener, TcpStream
from net.unix import UnixStream


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


def _until_some(s: TcpStream, mut buf: List[UInt8]) raises -> Int:
    """Spin on `try_read` until it returns a value (loopback delivery)."""
    var t = Instant.now()
    while True:
        var n = s.try_read(Span(buf))
        if n:
            return n.value()
        if t.elapsed() > Duration.from_secs(2):
            raise Error("try_read never returned")


def test_try_read_none_data_eof() raises:
    var k = _conn()
    var buf = List[UInt8](length=16, fill=0)
    assert_false(k.c.try_read(Span(buf)))  # nothing yet: None, no wait
    k.s.write_all(String("hello").as_bytes())
    assert_equal(_until_some(k.c, buf), 5)
    assert_equal(String(from_utf8_lossy=Span(buf)[0:5]), "hello")
    assert_false(k.c.try_read(Span(buf)))
    k.s.shutdown(Shutdown.WRITE)
    assert_equal(_until_some(k.c, buf), 0)  # EOF
    assert_equal(k.c.try_read(Span(buf)[0:0]).value(), 0)  # empty buffer


def test_try_read_raises_on_reset() raises:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    s.socket().set_linger(Optional(Duration.ZERO))
    s^.close()
    var buf = List[UInt8](length=4, fill=0)
    var kind = String()
    var t = Instant.now()
    while t.elapsed() < Duration.from_secs(2):
        try:
            if c.try_read(Span(buf)):
                break
        except e:
            kind = String(e.kind)
            break
    assert_equal(kind, "ConnectionReset")
    sys.keep_alive(l)


def test_try_write_until_full_then_drain() raises:
    var k = _conn()
    k.c.socket().set_send_buffer_size(4096)
    var chunk = List[UInt8](length=65536, fill=7)
    var queued = 0
    var full = False
    for _ in range(1000):
        var n = k.c.try_write(Span(chunk))
        if not n:
            full = True
            break
        queued += n.value()
    assert_true(full)
    assert_true(queued > 0)
    # The peer drains what was queued; then writing works again.
    var sink = List[UInt8](length=queued, fill=0)
    k.s.read_exact(Span(sink))
    var t = Instant.now()
    var again = False
    while t.elapsed() < Duration.from_secs(2):
        if k.c.try_write(Span(chunk)[0:10]):
            again = True
            break
    assert_true(again)


def test_try_accept() raises:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    assert_false(l.try_accept())
    var c = TcpStream.connect(l.local_addr())
    var t = Instant.now()
    var got = False
    while t.elapsed() < Duration.from_secs(2):
        var acc = l.try_accept()
        if acc:
            var a = acc.take()
            assert_equal(a.addr, c.local_addr())
            assert_true(a.stream.socket().nodelay())
            got = True
            break
    assert_true(got)
    assert_false(l.try_accept())


def test_unix_try_read_and_write() raises:
    var p = UnixStream.pair()
    var x = p.first.take()
    var y = p.second.take()
    var buf = List[UInt8](length=8, fill=0)
    assert_false(x.try_read(Span(buf)))
    assert_equal(y.try_write(String("ab").as_bytes()).value(), 2)
    assert_equal(x.try_read(Span(buf)).value(), 2)
    y^.close()
    assert_equal(x.try_read(Span(buf)).value(), 0)


def test_edge_triggered_loop_reads_until_none() raises:
    # Several writes, one edge: the loop must read until None to see all.
    var k = _conn()
    var ep = Epoll.new()
    ep.add(k.c, UInt32(EPOLLIN | EPOLLET), 1)
    for word in ["one ", "two ", "three"]:
        k.s.write_all(String(word).as_bytes())
    var got = String()
    var events = List[EpollEvent](capacity=8)
    var t = Instant.now()
    while got != "one two three" and t.elapsed() < Duration.from_secs(2):
        _ = ep.wait(events, Optional(Duration.from_millis(100)))
        var buf = List[UInt8](length=3, fill=0)  # small: several reads
        while True:
            var n = k.c.try_read(Span(buf))
            if not n or n.value() == 0:
                break
            got += String(from_utf8_lossy=Span(buf)[0 : n.value()])
    assert_equal(got, "one two three")
    ep.delete(k.c)


def test_bind_reuseport_shares_a_port() raises:
    var a = TcpListener.bind_reuseport(SocketAddr.parse("127.0.0.1:0"))
    var addr = a.local_addr()
    var b = TcpListener.bind_reuseport(addr)
    assert_equal(b.local_addr(), addr)
    assert_true(a.socket().reuse_port() and b.socket().reuse_port())
    var kind = String()
    try:
        _ = TcpListener.bind(addr)  # without SO_REUSEPORT: refused
    except e:
        kind = String(e.kind)
    assert_equal(kind, "AddrInUse")
    # Connections go to either listener; both stay usable.
    for _ in range(4):
        _ = TcpStream.connect(addr)
    sys.keep_alive(a)
    sys.keep_alive(b)


def test_raise_nofile_limit() raises:
    var before = nofile_limit()
    var now = raise_nofile_limit()
    assert_equal(UInt64(now), nofile_limit().cur)
    assert_equal(nofile_limit().cur, before.max)
    assert_equal(raise_nofile_limit(), now)  # idempotent


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
