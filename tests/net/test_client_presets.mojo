"""Long-lived client connections: `detect_dead_peers` (keepalive timing and
TCP_USER_TIMEOUT of the same total) and `idle_state` (EMPTY / DATA /
CLOSED without waiting or consuming) on TCP and Unix streams."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError, sys
from linux.time import Deadline, Duration, Instant
from net.addr import SocketAddr
from net.blocking import DEAD_PEER_KEEPALIVE, IdleState
from net.socket import Shutdown, TcpKeepalive
from net.tcp import TcpListener, TcpStream
from net.unix import UnixStream


@fieldwise_init
struct _Conn(Movable):
    var l: TcpListener
    var c: TcpStream
    var s: TcpStream


def _conn() raises -> _Conn:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    c.set_deadline(Deadline.after(Duration.from_secs(10)))
    s.set_deadline(Deadline.after(Duration.from_secs(10)))
    return _Conn(l^, c^, s^)


def _wait_for(stream: TcpStream, want: IdleState) raises:
    """Spin briefly until loopback delivery makes the state visible."""
    var t = Instant.now()
    while stream.idle_state() != want:
        if t.elapsed() > Duration.from_secs(2):
            raise Error("state never became ", want, ", is ", stream.idle_state())


def test_detect_dead_peers_defaults() raises:
    var k = _conn()
    k.c.detect_dead_peers()
    assert_true(k.c.socket().keepalive())
    assert_equal(k.c.socket().tcp_keepalive(), DEAD_PEER_KEEPALIVE)
    assert_equal(k.c.socket().tcp_user_timeout().value(), Duration.from_secs(60))


def test_detect_dead_peers_custom_and_invalid() raises:
    var k = _conn()
    k.c.detect_dead_peers(TcpKeepalive(Duration.from_secs(5), Duration.from_secs(2), 4))
    assert_equal(k.c.socket().tcp_user_timeout().value(), Duration.from_secs(13))
    var fresh = _conn()
    var kind = String()
    try:
        fresh.c.detect_dead_peers(TcpKeepalive(Duration.from_secs(5), Duration.from_secs(2), 0))
    except e:
        kind = String(e.kind)
    assert_equal(kind, "InvalidInput")
    assert_false(fresh.c.socket().keepalive())  # nothing was changed


def test_idle_state_tcp() raises:
    var k = _conn()
    assert_equal(k.c.idle_state(), IdleState.EMPTY)
    k.s.write_all(String("hi").as_bytes())
    _wait_for(k.c, IdleState.DATA)
    var b = List[UInt8](length=2, fill=0)
    k.c.read_exact(Span(b))  # the check consumed nothing
    assert_equal(String(from_utf8_lossy=Span(b)), "hi")
    assert_equal(k.c.idle_state(), IdleState.EMPTY)
    k.s.shutdown(Shutdown.WRITE)
    _wait_for(k.c, IdleState.CLOSED)


def test_idle_state_after_a_reset() raises:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    s.socket().set_linger(Optional(Duration.ZERO))
    s^.close()  # RST
    _wait_for(c, IdleState.CLOSED)
    sys.keep_alive(l)


def test_idle_state_never_waits() raises:
    var k = _conn()
    var t = Instant.now()
    for _ in range(1000):
        assert_equal(k.c.idle_state(), IdleState.EMPTY)
    assert_true(t.elapsed() < Duration.from_millis(200))


def test_idle_state_unix() raises:
    var p = UnixStream.pair()
    var x = p.first.take()
    var y = p.second.take()
    assert_equal(x.idle_state(), IdleState.EMPTY)
    y.set_write_deadline(Deadline.after(Duration.from_secs(10)))
    y.write_all(String("z").as_bytes())
    assert_equal(x.idle_state(), IdleState.DATA)
    y^.close()
    var b = List[UInt8](length=1, fill=0)
    x.set_read_deadline(Deadline.after(Duration.from_secs(10)))
    _ = x.read(Span(b))
    assert_equal(x.idle_state(), IdleState.CLOSED)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
