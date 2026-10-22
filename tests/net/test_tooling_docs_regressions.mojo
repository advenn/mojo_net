"""Regression tests for net (review group "tooling-docs").

- `read_to_end`'s error contract: after `TimedOut` or `ConnectionReset`
  exactly the bytes received so far stay appended (no zero-filled
  speculative tail, no lost prefix), for TCP and Unix streams.
- A peer that resets or closes while an L2 operation is already blocked in
  ppoll: the operation fails (or sees EOF) promptly, not at its deadline.
  For an HTTP server this is the everyday client disconnect mid-response.
- A timed AF_UNIX connect that waits in the kernel for backlog room and
  then succeeds leaves SO_SNDTIMEO cleared and the stream nonblocking.
- `TcpInfo` accessors against an independent decode of the same bytes
  (Python's struct module), plus a fixed anchor for the window-scale
  bitfields (a swap of snd/rcv on both ends is invisible to symmetric
  checks).

Peers that must act while we block are python3 child processes (test-only).
Every wait is bounded, so a regression fails instead of hanging.
"""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError, sys
from linux.consts import SO_SNDTIMEO, SOL_SOCKET
from linux.nr import SYS_getpid
from linux.syscall import syscall0
from linux.time import Deadline, Duration, Instant
from net.addr import SocketAddr, UnixAddr
from net.socket import Domain, SockType, Socket, TcpInfo
from net.tcp import TcpListener, TcpStream
from net.unix import UnixListener, UnixStream

comptime MiB = 1024 * 1024


# ---- helpers -----------------------------------------------------------------


def _ms(n: Int) -> Duration:
    return Duration.from_millis(n)


def _guard() -> Deadline:
    """Backstop so a broken test fails with TimedOut instead of hanging."""
    return Deadline.after(Duration.from_secs(10))


def _text(buf: List[UInt8]) -> String:
    return String(from_utf8_lossy=Span(buf))


def _prefixed() -> List[UInt8]:
    """What the caller already had in `out` before read_to_end."""
    var out = List[UInt8]()
    out.append(UInt8(ord("X")))
    return out^


def _reap(child: PythonObject, failed: Bool = False) raises:
    """Wait (bounded) for a child; kill it at once if the test already
    failed, or after 30 s (then the test fails too)."""
    if failed:
        _ = child.kill()
    try:
        _ = child.wait(timeout=30)
        return
    except:
        pass  # subprocess.TimeoutExpired
    _ = child.kill()
    _ = child.wait()
    raise Error("python peer did not exit within 30 s")


# python3 TCP peer: `python3 -c _TCP_PEER mode port`. Each mode first lets
# us block (0.2 s), then dies in its own way.
comptime _TCP_PEER = (
    "import socket, struct, sys, time\n"
    "mode, port = sys.argv[1], int(sys.argv[2])\n"
    "s = socket.create_connection(('127.0.0.1', port))\n"
    "s.settimeout(30)\n"
    "def rst():\n"
    "    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,"
    " struct.pack('ii', 1, 0))\n"
    "if mode == 'send_then_rst':\n"
    "    s.sendall(b'abc')\n"
    "    s.recv(1)\n"
    "    time.sleep(0.2)\n"
    "    rst()\n"
    "elif mode == 'rst':\n"
    "    time.sleep(0.2)\n"
    "    rst()\n"
    "elif mode == 'fin':\n"
    "    time.sleep(0.2)\n"
    "elif mode == 'read_then_rst':\n"
    "    time.sleep(0.2)\n"
    "    got = 0\n"
    "    while got < 65536:\n"
    "        b = s.recv(65536 - got)\n"
    "        if not b:\n"
    "            break\n"
    "        got += len(b)\n"
    "    rst()\n"
    "s.close()\n"
)

# python3 Unix peer on an inherited socketpair end: `-c _UNIX_PEER mode fd`.
comptime _UNIX_PEER = (
    "import socket, sys, time\n"
    "mode = sys.argv[1]\n"
    "s = socket.socket(fileno=int(sys.argv[2]))\n"
    "s.setblocking(True)\n"
    "s.settimeout(30)\n"
    "if mode == 'send_then_close_unread':\n"
    "    s.sendall(b'abc')\n"
    "    s.recv(1)\n"
    "    time.sleep(0.2)\n"
    "elif mode == 'close':\n"
    "    time.sleep(0.2)\n"
    "elif mode == 'read_then_close':\n"
    "    time.sleep(0.2)\n"
    "    s.recv(65536)\n"
    "s.close()\n"
)


def _spawn(script: StaticString, mode: String, arg: Int) raises -> PythonObject:
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    return subprocess.Popen(
        Python.list(pysys.executable, "-c", script, mode, String(arg))
    )


@fieldwise_init
struct _TcpPeer(Movable):
    var s: TcpStream
    var child: PythonObject


def _tcp_peer(mode: String) raises -> _TcpPeer:
    """An accepted stream whose peer is a python child running `mode`."""
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    l.set_deadline(_guard())  # a child that never connects fails, not hangs
    var child = _spawn(_TCP_PEER, mode, Int(l.local_addr().port()))
    var msg: String
    try:
        var s = l.accept().into_stream()
        s.set_deadline(Deadline.after(Duration.from_secs(5)))
        return _TcpPeer(s^, child)
    except e:
        msg = String(e)
    _reap(child, failed=True)
    raise Error("accept failed (did the python peer start?): ", msg)


@fieldwise_init
struct _UnixPeer(Movable):
    var s: UnixStream
    var child: PythonObject


def _unix_peer(mode: String) raises -> _UnixPeer:
    """One end of a socketpair; a python child running `mode` has the other."""
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    var p = UnixStream.pair()
    var mine = p.first.take()
    var theirs = p.second.take()
    var fd = Int(theirs.raw_fd())
    var child = subprocess.Popen(
        Python.list(pysys.executable, "-c", _UNIX_PEER, mode, String(fd)),
        pass_fds=Python.list(fd),
    )
    theirs^.close()  # the child holds its own copy
    mine.set_deadline(Deadline.after(Duration.from_secs(5)))
    return _UnixPeer(mine^, child)


# ---- read_to_end keeps exactly the prefix on errors (F17) --------------------


def test_read_to_end_timeout_keeps_exact_prefix_tcp() raises:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    l.set_deadline(_guard())
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept().into_stream()
    s.write_all(String("abc").as_bytes())
    var out = _prefixed()
    c.set_read_deadline(Deadline.after(_ms(100)))
    var kind = ErrorKind.Other
    try:
        _ = c.read_to_end(out)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.TimedOut)
    assert_equal(len(out), 4)  # not 4 + a zero-filled chunk, not 1
    assert_equal(_text(out), "Xabc")
    sys.keep_alive(s)


def test_read_to_end_timeout_keeps_exact_prefix_unix() raises:
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    b.write_all(String("abc").as_bytes())
    var out = _prefixed()
    a.set_read_deadline(Deadline.after(_ms(100)))
    var kind = ErrorKind.Other
    try:
        _ = a.read_to_end(out)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.TimedOut)
    assert_equal(len(out), 4)
    assert_equal(_text(out), "Xabc")
    sys.keep_alive(b)


def test_read_to_end_reset_keeps_exact_prefix_tcp() raises:
    var peer = _tcp_peer("send_then_rst")
    var out = _prefixed()
    var kind = ErrorKind.Other
    var msg = String("no error")
    try:
        peer.s.write_all(String("g").as_bytes())  # go: RST in 0.2 s
        _ = peer.s.read_to_end(out)
    except e:
        kind = e.kind
        msg = String(e)
    _reap(peer.child, failed=kind != ErrorKind.ConnectionReset)
    assert_equal(kind, ErrorKind.ConnectionReset, msg)
    assert_equal(len(out), 4)
    assert_equal(_text(out), "Xabc")


def test_read_to_end_reset_keeps_exact_prefix_unix() raises:
    # An AF_UNIX peer that closes with unread data resets us (ECONNRESET).
    var peer = _unix_peer("send_then_close_unread")
    var out = _prefixed()
    var kind = ErrorKind.Other
    var msg = String("no error")
    try:
        peer.s.write_all(String("gz").as_bytes())
        _ = peer.s.read_to_end(out)
    except e:
        kind = e.kind
        msg = String(e)
    _reap(peer.child, failed=kind != ErrorKind.ConnectionReset)
    assert_equal(kind, ErrorKind.ConnectionReset, msg)
    assert_equal(len(out), 4)
    assert_equal(_text(out), "Xabc")


# ---- the peer dies while we are blocked (F58) --------------------------------


def _prompt(el: Duration) raises:
    assert_true(el >= _ms(150), String("did not block first: ", el))
    assert_true(el < Duration.from_secs(2), String("late: ", el))


def test_tcp_write_all_fails_promptly_when_peer_resets_mid_transfer() raises:
    var peer = _tcp_peer("read_then_rst")
    peer.s.socket().set_send_buffer_size(64 * 1024)
    var data = List[UInt8](length=8 * MiB, fill=7)
    var t = Instant.now()
    var kind = ErrorKind.Other
    var msg = String("no error")
    try:
        peer.s.write_all(Span(data))
    except e:
        kind = e.kind
        msg = String(e)
    var el = t.elapsed()
    _reap(peer.child)
    assert_true(
        kind == ErrorKind.ConnectionReset or kind == ErrorKind.BrokenPipe, msg
    )
    _prompt(el)


def test_tcp_read_fails_promptly_when_peer_resets_while_waiting() raises:
    var peer = _tcp_peer("rst")
    var buf = List[UInt8](length=16, fill=0)
    var t = Instant.now()
    var kind = ErrorKind.Other
    var msg: String
    try:
        msg = String("read returned ", peer.s.read(Span(buf)))
    except e:
        kind = e.kind
        msg = String(e)
    var el = t.elapsed()
    _reap(peer.child)
    assert_equal(kind, ErrorKind.ConnectionReset, msg)
    _prompt(el)


def test_tcp_read_sees_eof_promptly_when_peer_closes_while_waiting() raises:
    var peer = _tcp_peer("fin")
    var buf = List[UInt8](length=16, fill=0)
    var t = Instant.now()
    var n = peer.s.read(Span(buf))
    var el = t.elapsed()
    _reap(peer.child)
    assert_equal(n, 0)
    _prompt(el)


def test_unix_write_all_fails_promptly_when_peer_closes_mid_transfer() raises:
    var peer = _unix_peer("read_then_close")
    var data = List[UInt8](length=8 * MiB, fill=7)
    var t = Instant.now()
    var kind = ErrorKind.Other
    var msg = String("no error")
    try:
        peer.s.write_all(Span(data))
    except e:
        kind = e.kind
        msg = String(e)
    var el = t.elapsed()
    _reap(peer.child)
    assert_true(
        kind == ErrorKind.BrokenPipe or kind == ErrorKind.ConnectionReset, msg
    )
    _prompt(el)


def test_unix_read_sees_eof_promptly_when_peer_closes_while_waiting() raises:
    var peer = _unix_peer("close")
    var buf = List[UInt8](length=16, fill=0)
    var t = Instant.now()
    var n = peer.s.read(Span(buf))
    var el = t.elapsed()
    _reap(peer.child)
    assert_equal(n, 0)
    _prompt(el)


# ---- a timed AF_UNIX connect that waited, then succeeded (F57) ---------------

# Gets our listener (backlog 0, its one slot taken) via pass_fds, frees the
# slot 0.15 s later, then serves the connection that was waiting.
comptime _UNIX_ACCEPTER = (
    "import socket, sys, time\n"
    "l = socket.socket(fileno=int(sys.argv[1]))\n"
    "l.setblocking(True)\n"
    "l.settimeout(30)\n"
    "time.sleep(0.15)\n"
    "a, _ = l.accept()\n"
    "b, _ = l.accept()\n"
    "b.sendall(b'hi')\n"
    "b.settimeout(30)\n"
    "b.recv(1)\n"
    "b.close()\n"
    "a.close()\n"
)


def test_unix_connect_timeout_succeeds_when_backlog_frees() raises:
    var addr = UnixAddr.from_abstract_name(
        String("mojo_net_tooling_", syscall0(SYS_getpid), "_backlog")
    )
    var l = UnixListener.bind(addr, backlog=0)
    var first = UnixStream.connect(addr)  # takes the only slot
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    var fd = Int(l.raw_fd())
    var child = subprocess.Popen(
        Python.list(pysys.executable, "-c", _UNIX_ACCEPTER, String(fd)),
        pass_fds=Python.list(fd),
    )
    var t = Instant.now()
    var ok = True
    var msg = String()
    var got = List[UInt8](length=2, fill=0)
    var sndtimeo = List[UInt8](length=16, fill=0xFF)
    var nonblocking = False
    var el = Duration.ZERO
    try:
        var c = UnixStream.connect_timeout(addr, Duration.from_secs(2))
        el = t.elapsed()
        _ = c.socket().get_option_bytes(SOL_SOCKET, SO_SNDTIMEO, Span(sndtimeo))
        nonblocking = c.socket().nonblocking()
        c.set_read_deadline(_guard())
        c.read_exact(Span(got))
    except e:
        ok = False
        msg = String(e)
    _reap(child, failed=not ok)
    assert_true(ok, msg)
    # It really waited in the kernel for the slot, then completed.
    assert_true(el >= _ms(80), String("did not wait: ", el))
    assert_true(el < _ms(1500), String("late: ", el))
    # The connect timeout does not linger: later blocking sends through
    # socket() must not time out.
    for i in range(16):
        assert_equal(Int(sndtimeo[i]), 0, "SO_SNDTIMEO left set")
    assert_true(nonblocking)
    assert_equal(_text(got), "hi")
    sys.keep_alive(first)
    sys.keep_alive(l)


# ---- TcpInfo accessors vs an independent decode (F61) ------------------------

# struct tcp_info from <linux/tcp.h> up to tcpi_snd_wnd (232 bytes, no
# padding: every u64 is 8-aligned), decoded by Python's struct module.
# Byte 6 holds snd_wscale:4 (low nibble), rcv_wscale:4; byte 7 holds
# delivery_rate_app_limited:1, fastopen_client_fail:2 (GCC, little endian).
comptime _TCPI_DECODE = (
    "lambda b: (lambda d: (d.update("
    "snd_wscale=d['wscale'] & 15, rcv_wscale=d['wscale'] >> 4,"
    " delivery_rate_app_limited=d['flags'] & 1,"
    " fastopen_client_fail=(d['flags'] >> 1) & 3), d)[1])(dict(zip(["
    "'state', 'ca_state', 'retransmits', 'probes', 'backoff', 'options',"
    " 'wscale', 'flags',"
    " 'rto', 'ato', 'snd_mss', 'rcv_mss',"
    " 'unacked', 'sacked', 'lost', 'retrans', 'fackets',"
    " 'last_data_sent', 'last_ack_sent', 'last_data_recv', 'last_ack_recv',"
    " 'pmtu', 'rcv_ssthresh', 'rtt', 'rttvar', 'snd_ssthresh', 'snd_cwnd',"
    " 'advmss', 'reordering', 'rcv_rtt', 'rcv_space', 'total_retrans',"
    " 'pacing_rate', 'max_pacing_rate', 'bytes_acked', 'bytes_received',"
    " 'segs_out', 'segs_in', 'notsent_bytes', 'min_rtt', 'data_segs_in',"
    " 'data_segs_out', 'delivery_rate', 'busy_time', 'rwnd_limited',"
    " 'sndbuf_limited', 'delivered', 'delivered_ce', 'bytes_sent',"
    " 'bytes_retrans', 'dsack_dups', 'reord_seen', 'rcv_ooopack', 'snd_wnd'],"
    " __import__('struct').unpack_from("
    "'<8B4I5I4I8I2II4Q2I4IQ3Q2I2Q2III', b))))"
)


def _decode(info: TcpInfo) raises -> PythonObject:
    var raw = Python.list()
    for b in info.raw():
        _ = raw.append(Int(b))
    var builtins = Python.import_module("builtins")
    var decode = Python.evaluate(_TCPI_DECODE)
    return decode(builtins.bytes(raw))


def _field[T: Writable](got: T, d: PythonObject, name: StaticString) raises:
    # Compared as text: some u64 fields (max_pacing_rate) are ~0, which
    # does not fit an Int.
    assert_equal(String(got), String(d[name]), String("tcpi_", name))


def _cross_check(info: TcpInfo) raises:
    assert_true(info.size() >= 232, String("size ", info.size()))
    var d = _decode(info)
    _field(info.state(), d, "state")
    _field(info.ca_state(), d, "ca_state")
    _field(info.retransmits(), d, "retransmits")
    _field(info.probes(), d, "probes")
    _field(info.backoff(), d, "backoff")
    _field(info.options(), d, "options")
    _field(info.snd_wscale(), d, "snd_wscale")
    _field(info.rcv_wscale(), d, "rcv_wscale")
    _field(
        Int(info.delivery_rate_app_limited()), d, "delivery_rate_app_limited"
    )
    _field(info.fastopen_client_fail(), d, "fastopen_client_fail")
    _field(info.rto(), d, "rto")
    _field(info.ato(), d, "ato")
    _field(info.snd_mss(), d, "snd_mss")
    _field(info.rcv_mss(), d, "rcv_mss")
    _field(info.unacked(), d, "unacked")
    _field(info.sacked(), d, "sacked")
    _field(info.lost(), d, "lost")
    _field(info.retrans(), d, "retrans")
    _field(info.fackets(), d, "fackets")
    _field(info.last_data_sent(), d, "last_data_sent")
    _field(info.last_ack_sent(), d, "last_ack_sent")
    _field(info.last_data_recv(), d, "last_data_recv")
    _field(info.last_ack_recv(), d, "last_ack_recv")
    _field(info.pmtu(), d, "pmtu")
    _field(info.rcv_ssthresh(), d, "rcv_ssthresh")
    _field(info.rtt(), d, "rtt")
    _field(info.rttvar(), d, "rttvar")
    _field(info.snd_ssthresh(), d, "snd_ssthresh")
    _field(info.snd_cwnd(), d, "snd_cwnd")
    _field(info.advmss(), d, "advmss")
    _field(info.reordering(), d, "reordering")
    _field(info.rcv_rtt(), d, "rcv_rtt")
    _field(info.rcv_space(), d, "rcv_space")
    _field(info.total_retrans(), d, "total_retrans")
    _field(info.pacing_rate(), d, "pacing_rate")
    _field(info.max_pacing_rate(), d, "max_pacing_rate")
    _field(info.bytes_acked(), d, "bytes_acked")
    _field(info.bytes_received(), d, "bytes_received")
    _field(info.segs_out(), d, "segs_out")
    _field(info.segs_in(), d, "segs_in")
    _field(info.notsent_bytes(), d, "notsent_bytes")
    _field(info.min_rtt(), d, "min_rtt")
    _field(info.data_segs_in(), d, "data_segs_in")
    _field(info.data_segs_out(), d, "data_segs_out")
    _field(info.delivery_rate(), d, "delivery_rate")
    _field(info.busy_time(), d, "busy_time")
    _field(info.rwnd_limited(), d, "rwnd_limited")
    _field(info.sndbuf_limited(), d, "sndbuf_limited")
    _field(info.delivered(), d, "delivered")
    _field(info.delivered_ce(), d, "delivered_ce")
    _field(info.bytes_sent(), d, "bytes_sent")
    _field(info.bytes_retrans(), d, "bytes_retrans")
    _field(info.dsack_dups(), d, "dsack_dups")
    _field(info.reord_seen(), d, "reord_seen")
    _field(info.rcv_ooopack(), d, "rcv_ooopack")
    _field(info.snd_wnd(), d, "snd_wnd")


def _proc_int(path: StringSlice) raises -> Int:
    with open(path, "r") as f:
        return Int(f.read().strip())


def test_tcp_info_accessors_match_an_independent_decode() raises:
    # The server's tiny SO_RCVBUF (set on the listener before the SYN
    # arrives) makes it announce window scale 0, while the client's default
    # buffer announces a positive one: a fixed anchor for the bitfields.
    var l = Socket.new(Domain.IPV4, SockType.STREAM)
    l.set_recv_buffer_size(2048)
    l.bind(SocketAddr.parse("127.0.0.1:0"))
    l.listen(4)
    var c = Socket.new(Domain.IPV4, SockType.STREAM)
    c.connect(l.local_addr())
    var srv = l.accept().into_socket()
    var buf = List[UInt8](length=1024, fill=0)
    var payload = List[UInt8](length=1000, fill=1)
    for _ in range(5):
        _ = c.send(Span(payload))
        var got = 0
        while got < 1000:
            got += srv.recv(Span(buf))
        _ = srv.send(String("ack").as_bytes())
        got = 0
        while got < 3:
            got += c.recv(Span(buf))
    var ci = c.tcp_info()
    var si = srv.tcp_info()
    _cross_check(ci)
    _cross_check(si)
    if _proc_int("/proc/sys/net/ipv4/tcp_window_scaling") == 1:
        assert_true((Int(ci.options()) & 4) != 0, "TCPI_OPT_WSCALE")
        assert_equal(Int(si.rcv_wscale()), 0, "server rcv_wscale")
        assert_true(ci.rcv_wscale() > 0, "client rcv_wscale")
        assert_equal(ci.snd_wscale(), si.rcv_wscale())
        assert_equal(si.snd_wscale(), ci.rcv_wscale())
    sys.keep_alive(c)
    sys.keep_alive(srv)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
