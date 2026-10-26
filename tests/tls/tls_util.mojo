"""Shared helpers for tests/tls (not a test file itself): the test PKI
(tests/tls/tls_pki.py, made once per process in a temporary directory that
a watcher removes when the process ends) and `Peer`, a TLS server
(tests/tls/tls_peer.py) in a child process; for `TlsServer`, `serving`,
`ClientProc` (tests/tls/tls_client_peer.py or a command such as
`openssl s_client`) and `ServerDriver`. End each test with
`peer^.stop()`: Mojo destroys a value right after its last use, which would
kill the peer early."""

from std.os import getenv
from std.python import Python, PythonObject
from std.testing import assert_equal, assert_true

from bytes.buffer import ByteBuffer
from linux.time import Deadline, Duration
from net.addr import SocketAddr
from net.tcp import TcpListener, TcpStream
from tls import (
    Category,
    ClientConfig,
    ClientContext,
    ServerConfig,
    ServerContext,
    TlsClient,
    TlsError,
    TlsEventKind,
    TlsServer,
    Trust,
)
from tls.client import FEED_LIMIT
from tls.stream import TlsStream


def pki() raises -> String:
    """The directory holding the test PKI (made on first use)."""
    var os = Python.import_module("os")
    var tempfile = Python.import_module("tempfile")
    var d = String(py=os.path.join(tempfile.gettempdir(), String("mojo_net_tls_", Int(py=os.getpid()))))
    if Bool(py=os.path.isdir(d)) and Bool(py=os.path.exists(d + "/root.crl.pem")):
        return d
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    var cmd = Python.list(pysys.executable, "tests/tls/tls_pki.py", d, "--owner", String(Int(py=os.getpid())))
    var r = subprocess.run(cmd, capture_output=True, text=True)
    if Int(py=r.returncode) != 0:
        raise Error(String("tls_pki.py failed: ", String(py=r.stderr)))
    return d


def ipv6_loopback(test: StaticString) raises -> Bool:
    """Whether [::1] can be bound (decided by Python, not the code under
    test): only EAFNOSUPPORT and EADDRNOTAVAIL mean "no", and then a skip
    line is printed, unless MOJO_NET_REQUIRE_IPV6=1 makes it a failure."""
    var socket = Python.import_module("socket")
    var errno = Python.import_module("errno")
    var why: String
    try:
        var sk = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        try:
            _ = sk.bind(Python.tuple("::1", 0))
            _ = sk.close()
            return True
        except e:
            _ = sk.close()
            why = String(e)
    except e:
        why = String(e)
    if not ("Errno " + String(Int(py=errno.EADDRNOTAVAIL)) in why or "Errno " + String(Int(py=errno.EAFNOSUPPORT)) in why):
        raise Error(String(test, ": probing IPv6 failed: ", why))
    if getenv("MOJO_NET_REQUIRE_IPV6") == "1":
        raise Error(String(test, ": no IPv6 (", why, ") but MOJO_NET_REQUIRE_IPV6=1"))
    print(String("    (skipped: ", test, ": no IPv6, ", why, ")"))
    return False


def trusting(ca: StringSlice = "root", alpn: List[String] = List[String]()) raises -> ClientContext:
    """A context that trusts only the test CA `ca`."""
    return ClientConfig(trust=Trust.ca_file(pki() + "/" + ca + ".pem"), alpn=alpn.copy()).build()


comptime LINE_TIMEOUT = 30.0
"""Seconds to wait for a helper's next line (tests/tls/peer_io.py)."""


def _lines(proc: PythonObject) raises -> PythonObject:
    var sys = Python.import_module("sys")
    if not Bool(py=Python.evaluate("lambda p: 'tests/tls' in p")(sys.path)):
        _ = sys.path.insert(0, "tests/tls")
    return Python.import_module("peer_io").Lines(proc.stdout)


struct Peer(Movable):
    var proc: PythonObject
    var lines: PythonObject
    var port: Int

    def __init__(out self, mode: StringSlice, opts: List[String] = List[String](), script: StringSlice = "tests/tls/tls_peer.py") raises:
        """Start `script` (tls_peer.py, or s_server_peer.py with a scenario
        for `mode`)."""
        var subprocess = Python.import_module("subprocess")
        var pysys = Python.import_module("sys")
        var cmd = Python.list(pysys.executable, script, pki(), mode)
        for o in opts:
            _ = cmd.append(o)
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        self.lines = _lines(self.proc)
        self.port = 0
        var first = self.line()
        var words = first.split()
        if len(words) != 2 or String(words[0]) != "PORT":
            raise Error(String(script, " did not start"))
        self.port = atol(words[1])

    def line(self) raises -> String:
        """The peer's next line ("" once it has exited); raises after
        `LINE_TIMEOUT` seconds without one."""
        return String(String(py=self.lines.next(LINE_TIMEOUT)).strip())

    def handshake_failed(self) raises -> String:
        """The server's SERVER_ERROR line, which must come before any "OK":
        the server never completed a handshake. Returns the line."""
        while True:
            var l = self.line()
            if l.byte_length() == 0:
                raise Error("tls_peer.py ended without reporting the connection")
            if l.startswith("OK"):
                raise Error(String("the server completed its handshake: ", l))
            if l.startswith("SERVER_ERROR"):
                return l

    def expect(self, prefix: StringSlice) raises -> String:
        """Skip lines until one starting with `prefix`; return it."""
        while True:
            var l = self.line()
            if l.byte_length() == 0:
                raise Error(String("tls_peer.py ended before a line starting with ", prefix))
            if l.startswith(prefix):
                return l

    def __deinit__(deinit self):
        _kill(self.proc)

    def stop(deinit self):
        _kill(self.proc)


struct Proc(Movable):
    """A helper process that prints "PORT <n>" first (tls_mitm.py)."""

    var proc: PythonObject
    var lines: PythonObject
    var port: Int

    def __init__(out self, args: List[String]) raises:
        var subprocess = Python.import_module("subprocess")
        var pysys = Python.import_module("sys")
        var cmd = Python.list(pysys.executable)
        for a in args:
            _ = cmd.append(a)
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        self.lines = _lines(self.proc)
        self.port = 0
        var first = String(String(py=self.lines.next(LINE_TIMEOUT)).strip())
        var words = first.split()
        if len(words) != 2 or String(words[0]) != "PORT":
            raise Error(String(args[0], " did not start"))
        self.port = atol(words[1])

    def expect(self, prefix: StringSlice) raises -> String:
        while True:
            var l = String(String(py=self.lines.next(LINE_TIMEOUT)).strip())
            if l.byte_length() == 0:
                raise Error(String("the helper ended before a line starting with ", prefix))
            if l.startswith(prefix):
                return l

    def __deinit__(deinit self):
        _kill(self.proc)

    def stop(deinit self):
        _kill(self.proc)


def _kill(proc: PythonObject):
    try:
        _ = proc.kill()
        _ = proc.wait()
    except:
        pass


def connect(peer: Peer, ctx: ClientContext, name: StringSlice = "localhost") raises TlsError -> TlsStream:
    """A verified connection to the peer at 127.0.0.1 (or ::1 for an IPv6
    name), expecting a certificate for `name`."""
    var addr = "::1" if name == "::1" else "127.0.0.1"
    return TlsStream.connect_deadline(addr, UInt16(peer.port), ctx, Deadline.after(Duration.from_secs(10)), server_name=name)


def connect_error(
    port: Int, ctx: ClientContext, name: StringSlice, timeout: Duration = Duration.from_secs(10)
) raises -> TlsError:
    """The error a connection to 127.0.0.1:`port` expecting `name` must
    fail with."""
    try:
        _ = TlsStream.connect_deadline("127.0.0.1", UInt16(port), ctx, Deadline.after(timeout), server_name=name)
    except e:
        return e^
    raise Error(String("the connection to ", name, " was accepted"))


def refused(peer: Peer, ctx: ClientContext, name: StringSlice, category: Category, verify_code: Int = -1) raises:
    """The connection must fail with `category` (and `verify_code` unless
    -1), and the server must see the handshake fail: for a certificate the
    client refused, by the alert it sent."""
    var e = connect_error(peer.port, ctx, name)
    assert_equal(e.category, category, String(e))
    if verify_code != -1:
        assert_equal(e.verify_code, verify_code, String(e))
    var seen = peer.handshake_failed()
    if e.is_authentication():
        assert_true("ALERT" in seen, String("the server saw no alert: ", seen))


def read_error(mut s: TlsStream, mut got: List[UInt8]) raises -> TlsError:
    """Read (appending to `got`) until a read fails; that error."""
    var buf = List[UInt8](length=4096, fill=0)
    var n = 1
    try:
        while n > 0:
            n = s.read(Span(buf))
            got.extend(Span(buf)[0:n])
    except e:
        return e^
    raise Error("the stream ended cleanly")


def read_all(mut s: TlsStream) raises TlsError -> List[UInt8]:
    """Everything up to the server's close_notify."""
    var out = List[UInt8]()
    var buf = List[UInt8](length=65536, fill=0)
    while True:
        var n = s.read(Span(buf))
        if n == 0:
            return out^
        out.extend(Span(buf)[0:n])


def pattern(n: Int) -> List[UInt8]:
    """tls_peer.py's pattern: byte i is i % 251."""
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(UInt8(i % 251))
    return out^


def opts(*items: String) -> List[String]:
    var out = List[String]()
    for i in items:
        out.append(i)
    return out^


struct CodecDriver(Movable):
    """`TlsClient` over a `TcpStream`, driven by hand: for tests that
    must not send, or must not drain, as a stream would."""

    var tls: TlsClient
    var tcp: TcpStream
    var buf: List[UInt8]
    var out: ByteBuffer
    var sent: Int
    """Ciphertext handed to the socket."""
    var hello: Int
    """Of which the ClientHello."""

    def __init__(out self, port: Int, ctx: ClientContext) raises:
        self.tls = TlsClient(ctx, "localhost")
        self.tcp = TcpStream.connect_host("127.0.0.1", UInt16(port), Duration.from_secs(5))
        self.tcp.set_deadline(Deadline.after(Duration.from_secs(20)))
        self.buf = List[UInt8](length=FEED_LIMIT, fill=0)
        self.out = ByteBuffer()
        self.sent = 0
        self.hello = 0

    def send(mut self) raises:
        """Everything queued, to the socket (a failed send is ignored: the
        server may have gone)."""
        while self.tls.has_transmit():
            if self.tls.poll_transmit(self.out) == 0:
                break
            try:
                self.tcp.write_all(self.out.readable_span())
            except:
                pass
            self.sent += len(self.out)
            self.out.clear()

    def receive(mut self) raises TlsError -> Bool:
        """One receive into the codec (at most its room): False at the end."""
        var room = min(self.tls.feed_capacity(), len(self.buf))
        if room == 0:
            return False
        var n: Int
        try:
            n = self.tcp.read(Span(self.buf)[0:room])
        except e:
            raise TlsError(e)
        if n == 0:
            self.tls.feed_eof()
            return False
        self.tls.feed(Span(self.buf)[0:n])
        return True

    def handshake(mut self) raises:
        while True:
            self.send()
            if self.hello == 0:
                self.hello = self.sent
            var ev = self.tls.next_event()
            if ev:
                if ev.value().kind == TlsEventKind.ESTABLISHED:
                    return
                continue
            if not self.receive():
                raise Error("the connection ended during the handshake")


# ---- the server side ---------------------------------------------------------


def serving(
    cert: StringSlice = "good",
    names: List[String] = ["localhost", "127.0.0.1"],
    alpn: List[String] = ["http/1.1"],
    tls13_only: Bool = False,
    key: StringSlice = "",
) raises -> ServerContext:
    """A server context with the test PKI's `cert` (its chain file, and its
    key unless `key` names another)."""
    var d = pki()
    var k = String(key) if key.byte_length() > 0 else String(cert)
    return ServerConfig(
        certificate=d + "/" + cert + ".chain.pem", key=d + "/" + k + ".key", names=names.copy(), alpn=alpn.copy(), tls13_only=tls13_only
    ).build()


def listener() raises -> TcpListener:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    l.set_deadline(Deadline.after(Duration.from_secs(30)))
    return l^


def client_peer(port: Int, scenario: StringSlice, opts: List[String] = List[String]()) raises -> ClientProc:
    """tests/tls/tls_client_peer.py with `scenario`."""
    var pysys = Python.import_module("sys")
    var cmd = Python.list(pysys.executable, "tests/tls/tls_client_peer.py", pki(), String(port), scenario)
    for o in opts:
        _ = cmd.append(o)
    return ClientProc(command=cmd)


def s_client(port: Int, *args: String) raises -> PythonObject:
    """`openssl s_client` to 127.0.0.1:`port`, trusting the test root, with
    `args`."""
    var cmd = Python.list("openssl", "s_client", "-connect", String("127.0.0.1:", port), "-CAfile", pki() + "/root.pem")
    for a in args:
        _ = cmd.append(a)
    return cmd


struct ClientProc(Movable):
    """A client in a child process, its output read line by line."""

    var proc: PythonObject
    var lines: PythonObject

    def __init__(out self, *, command: PythonObject, stdin: List[String] = List[String](), gap: Float64 = 0.3) raises:
        """Any command (stderr joins stdout). Each of `stdin` is written to
        it `gap` seconds apart, then its stdin is closed
        (tests/tls/slow_stdin.py: `openssl s_client` takes a command letter
        only when a read starts with it)."""
        var subprocess = Python.import_module("subprocess")
        var pysys = Python.import_module("sys")
        var cmd = Python.list(pysys.executable, "tests/tls/slow_stdin.py", String(gap))
        for p in stdin:
            _ = cmd.append(p)
        _ = cmd.append("--")
        _ = cmd.extend(command)
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.lines = _lines(self.proc)

    def line(self) raises -> String:
        return String(String(py=self.lines.next(LINE_TIMEOUT)).strip())

    def expect(self, prefix: StringSlice) raises -> String:
        """Skip lines until one starting with `prefix`; return it."""
        while True:
            var l = self.line()
            if l.byte_length() == 0:
                raise Error(String("the client ended before a line starting with ", prefix))
            if l.startswith(prefix):
                return l

    def rest(self) raises -> String:
        """Every line left, until it exits (joined with newlines)."""
        var out = String()
        while True:
            var l = self.line()
            if l.byte_length() == 0:
                return out^
            out += l + "\n"

    def __deinit__(deinit self):
        _kill(self.proc)

    def stop(deinit self):
        _kill(self.proc)


struct ServerDriver(Movable):
    """`TlsServer` over an accepted `TcpStream`, driven by hand."""

    var tls: TlsServer
    var tcp: TcpStream
    var buf: List[UInt8]
    var out: ByteBuffer
    var received: Int
    """Ciphertext read from the socket."""
    var ended: Bool

    def __init__(out self, l: TcpListener, ctx: ServerContext) raises:
        """Accept one connection (within the listener's deadline)."""
        self.tcp = l.accept().into_stream()
        self.tcp.set_deadline(Deadline.after(Duration.from_secs(30)))
        self.tls = TlsServer(ctx)
        self.buf = List[UInt8](length=FEED_LIMIT, fill=0)
        self.out = ByteBuffer()
        self.received = 0
        self.ended = False

    def send(mut self) raises TlsError:
        """Everything queued, to the socket (a failed send is ignored: the
        client may have gone)."""
        while self.tls.has_transmit():
            if self.tls.poll_transmit(self.out) == 0:
                break
            try:
                self.tcp.write_all(self.out.readable_span())
            except:
                pass
            self.out.clear()

    def receive(mut self) raises TlsError -> Bool:
        """One receive into the codec (at most its room): False at the end."""
        var room = min(self.tls.feed_capacity(), len(self.buf))
        if room == 0 or self.ended:
            return False
        var n: Int
        try:
            n = self.tcp.read(Span(self.buf)[0:room])
        except e:
            raise TlsError(e)
        if n == 0:
            self.ended = True
            self.tls.feed_eof()
            return False
        self.received += n
        self.tls.feed(Span(self.buf)[0:n])
        return True

    def serve(mut self, close_after: Int = -1) raises -> Optional[TlsError]:
        """Answer each DATA event with "echo:" and its bytes until the
        client's close_notify (answered with ours: None), the end of its
        input, or a failure (its alert sent, then returned). With
        `close_after`, send close_notify after that many answers."""
        var answered = 0
        try:
            while True:
                var ev = self.tls.next_event()
                if ev:
                    if ev.value().kind == TlsEventKind.DATA:
                        var reply = List[UInt8]("echo:".as_bytes())
                        reply.extend(Span(ev.value().data))
                        _ = self.tls.write(Span(reply))
                        answered += 1
                        if answered == close_after:
                            self.tls.close()
                    elif ev.value().kind == TlsEventKind.CLOSED:
                        self.send()
                        return None
                    continue
                self.send()
                if not self.receive() and not self.tls.has_events():
                    _ = self.tls.next_event()  # (raises the failure, if any)
                    return None
        except e:
            self.send()  # (the alert OpenSSL queued, TS10)
            return e^
