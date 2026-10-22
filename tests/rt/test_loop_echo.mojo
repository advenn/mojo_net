"""End-to-end smoke test of the event loop on loopback: listen, accept,
connect, send, recv, close, all driven by completions."""

from std.testing import TestSuite, assert_equal, assert_true

from bytes.buffer import ByteBuffer
from linux import Errno
from linux.abi import RawSockaddr
from net.addr import Ipv4Addr, SocketAddr
from rt.core import Completion, FdId, Loop, OpKind, Target
from rt.event_loop import EventLoop


struct Echo(Movable):
    var listener: FdId
    var server_conn: FdId
    var client: FdId
    var got: String
    var log: List[String]
    # Mojo cannot take a function's own address (or that of a function in a
    # reference cycle) inside it, so every Target is built once by the test
    # and callbacks re-arm with these stored values.
    var t: List[Target]

    def __init__(out self):
        self.listener = FdId.null()
        self.server_conn = FdId.null()
        self.client = FdId.null()
        self.got = ""
        self.log = []
        self.t = []


comptime T_ACCEPT = 0
comptime T_SRECV = 1
comptime T_SSENT = 2
comptime T_CONNECT = 3
comptime T_CSENT = 4
comptime T_CRECV = 5
comptime T_CLOSED = 6
comptime T_LCLOSED = 7


@always_inline
def _st(ctx: Int) -> ref[MutUntrackedOrigin] Echo:
    return Pointer[Echo, MutUntrackedOrigin](unsafe_from_address=ctx)[]


def on_listen(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("listen " + String(c.res))
    if not c.ok():
        lp.stop()
        return
    s.listener = c.fd
    _ = lp.accept(c.fd, s.t[T_ACCEPT])
    _ = lp.connect(lp.local_addr(c.fd).value(), s.t[T_CONNECT])


def on_accept(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("accept " + String(c.res) + (" more" if c.more else ""))
    if not c.ok():
        return
    s.server_conn = c.fd
    _ = lp.recv(c.fd, s.t[T_SRECV])


def on_server_recv(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("srecv " + String(c.res))
    if c.res <= 0:
        _ = lp.close(c.fd, s.t[T_CLOSED])
        return
    # Echo the received buffer straight back.
    _ = lp.send(c.fd, c.buf.take(), s.t[T_SSENT])
    _ = lp.recv(c.fd, s.t[T_SRECV])


def on_server_sent(ctx: Int, mut lp: Loop, var c: Completion):
    _st(ctx).log.append("ssent " + String(c.res))
    if c.buf:
        lp.recycle(c.buf.take())


def on_connect(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("connect " + String(c.res))
    if not c.ok():
        lp.stop()
        return
    s.client = c.fd
    var b = ByteBuffer()
    try:
        b.write_bytes(String("ping").as_bytes())
    except:
        pass
    _ = lp.send(c.fd, b^, s.t[T_CSENT])
    _ = lp.recv(c.fd, s.t[T_CRECV])


def on_client_sent(ctx: Int, mut lp: Loop, var c: Completion):
    _st(ctx).log.append("csent " + String(c.res))


def on_client_recv(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("crecv " + String(c.res))
    if c.res > 0:
        s.got = String(StringSlice(unsafe_from_utf8=c.buf.value().readable_span()))
        lp.recycle(c.buf.take())
    # Close the client; the server sees EOF and closes its side.
    _ = lp.close(c.fd, s.t[T_CLOSED])


def on_closed(ctx: Int, mut lp: Loop, var c: Completion):
    ref s = _st(ctx)
    s.log.append("close " + String(c.res))
    if s.server_conn == c.fd or (not lp.is_open(s.server_conn)):
        if not lp.is_open(s.client):
            _ = lp.close(s.listener, s.t[T_LCLOSED])


def on_listener_closed(ctx: Int, mut lp: Loop, var c: Completion):
    _st(ctx).log.append("lclose " + String(c.res))


def test_echo_roundtrip_and_clean_shutdown() raises:
    var ev = EventLoop()
    var s = Echo()
    var ctx = Int(Pointer(to=s))
    s.t = [
        Target(on_accept, ctx),
        Target(on_server_recv, ctx),
        Target(on_server_sent, ctx),
        Target(on_connect, ctx),
        Target(on_client_sent, ctx),
        Target(on_client_recv, ctx),
        Target(on_closed, ctx),
        Target(on_listener_closed, ctx),
    ]
    _ = ev.loop.listen(SocketAddr(Ipv4Addr.LOCALHOST, 0).to_raw(), Target(on_listen, ctx))
    ev.run()
    for i in range(len(s.log)):
        print("   ", s.log[i])
    assert_equal(s.got, "ping")
    assert_equal(ev.loop.pending_ops(), 0)
    assert_equal(ev.loop.open_fds(), 0)
    # The accept multishot was ended by the listener's close (ECANCELED).
    var saw_cancel = False
    for i in range(len(s.log)):
        if s.log[i] == "accept -125":
            saw_cancel = True
    assert_true(saw_cancel)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
