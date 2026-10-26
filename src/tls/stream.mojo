"""`TlsStream`: a blocking TLS client stream, `TlsClient` driven over a
`net.TcpStream` (docs/tls.md).

    var ctx = ClientConfig().build()                 # once, shared
    var s = TlsStream.connect("example.com", 443, ctx, Duration.from_secs(10))
    s.write_all(request)
    var n = s.read(buf)                              # 0: the server's close_notify
    s^.close()

Deadlines work as on `TcpStream`: `connect` bounds name resolution, the
TCP connection and the handshake together; afterwards each direction has
its own absolute deadline (`set_read_deadline`, ...), and a passed one
raises an error whose `is_deadline()` is true. A deadline in the middle of
a record leaves the connection unusable: drop it.

`read` returns 0 only after the server's close_notify. A TCP end without
it raises `TRUNCATED` (`UnexpectedEof`), since the data may be cut short
(TB12): a protocol that frames its messages (HTTP with Content-Length)
decides for itself whether to treat that end as clean, and only after a
complete message.
"""

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError
from linux.time import Deadline, Duration
from net.socket import Shutdown
from net.tcp import TcpStream

from .client import FEED_LIMIT, TlsClient, TlsEventKind
from .config import ClientContext
from .error import Category, TlsError, tls_error

comptime _OUT_MAX = 256 * 1024
"""Ciphertext gathered for one send."""
comptime CLOSE_LINGER = Duration.from_secs(2)
"""How long `close` waits, by default, for the server to end the
connection after close_notify."""
comptime _LINGER_MAX = 256 * 1024
"""Bytes `close` discards while it waits (a server still sending is cut)."""


struct TlsStream(Movable, Writable):
    """A TLS connection to a server (see the module docs)."""

    var _tcp: TcpStream
    var _tls: TlsClient
    var _out: ByteBuffer
    """Ciphertext on its way to the socket."""
    var _in: List[UInt8]
    """The receive buffer."""
    var _data: List[UInt8]
    """Plaintext of the last DATA event, from `_data_off` on."""
    var _data_off: Int

    @staticmethod
    def connect(host: StringSlice, port: UInt16, context: ClientContext, timeout: Duration) raises TlsError -> TlsStream:
        """Connect to `host` (a name or an IP literal) and port and complete
        a verified handshake within `timeout`. The certificate must be for
        `host`."""
        if timeout.is_zero():
            raise tls_error("tls: connect timeout is zero", ErrorKind.InvalidInput, Category.INPUT)
        return TlsStream.connect_deadline(host, port, context, Deadline.after(timeout))

    @staticmethod
    def connect_deadline(
        host: StringSlice, port: UInt16, context: ClientContext, deadline: Deadline, server_name: StringSlice = ""
    ) raises TlsError -> TlsStream:
        """`connect` with an absolute deadline. `server_name`, when given,
        is the identity the certificate must match instead of `host` (a
        name reached at an address, for example)."""
        var name = server_name if server_name.byte_length() > 0 else host
        var tls = TlsClient(context, name)  # (checks the name before any I/O)
        var tcp: TcpStream
        try:
            tcp = TcpStream.connect_host_deadline(host, port, deadline)
        except e:
            raise TlsError(e)
        return TlsStream(tcp^, tls^, deadline)

    @staticmethod
    def handshake(var tcp: TcpStream, context: ClientContext, server_name: StringSlice, deadline: Deadline) raises TlsError -> TlsStream:
        """TLS over a connected stream (a proxy tunnel, a tuned socket)."""
        var tls = TlsClient(context, server_name)
        return TlsStream(tcp^, tls^, deadline)

    def __init__(out self, var tcp: TcpStream, var tls: TlsClient, deadline: Deadline) raises TlsError:
        self._tcp = tcp^
        self._tls = tls^
        try:
            self._out = ByteBuffer(max_size=_OUT_MAX)
        except e:
            raise TlsError(e)
        self._in = List[UInt8](length=FEED_LIMIT, fill=0)
        self._data = List[UInt8]()
        self._data_off = 0
        var rd = self._tcp.read_deadline()
        var wr = self._tcp.write_deadline()
        self._tcp.set_deadline(deadline)
        try:
            while True:
                self._flush()
                var ev = self._tls.next_event()
                if ev:
                    if ev.value().kind == TlsEventKind.ESTABLISHED:
                        break
                    continue
                self._receive()
        except e:
            self._alert()
            raise e^
        self._flush()  # (the client Finished)
        self._tcp.set_read_deadline(rd)
        self._tcp.set_write_deadline(wr)

    # ---- I/O ------------------------------------------------------------

    def read(mut self, buf: MutSpan[UInt8, _]) raises TlsError -> Int:
        """Wait for plaintext and copy up to `len(buf)` bytes of it; 0 after
        the server's close_notify (or for an empty `buf`)."""
        if len(buf) == 0:
            return 0
        while True:
            var n = self._take(buf)
            if n > 0:
                return n
            if self._next():
                continue
            if self._tls.is_closed():
                return 0
            self._flush()  # (a key update's reply)
            try:
                self._receive()
            except e:
                self._alert()
                raise e^

    def read_exact(mut self, buf: MutSpan[UInt8, _]) raises TlsError:
        """Fill `buf`; a close_notify first raises `UnexpectedEof`."""
        var got = 0
        while got < len(buf):
            var n = self.read(buf[got:])
            if n == 0:
                raise tls_error("tls: read_exact", ErrorKind.UnexpectedEof, Category.CLOSED)
            got += n

    def write_all(mut self, data: Span[UInt8, _]) raises TlsError:
        """Encrypt and send all of `data` (under the write deadline)."""
        var off = 0
        while off < len(data):
            off += self._tls.write(data[off:])
            self._flush()

    # ---- readiness loops -------------------------------------------------

    def try_read(mut self, buf: MutSpan[UInt8, _]) raises TlsError -> Optional[Int]:
        """For readiness loops, as `TcpStream.try_read`: plaintext without
        waiting, ignoring the read deadline. The bytes copied; 0 after the
        server's close_notify (or for an empty `buf`); None when nothing
        has arrived. Decrypted plaintext can wait here while the socket is
        quiet: check `buffered()` before waiting for the socket to be
        readable."""
        if len(buf) == 0:
            return 0
        while True:
            var n = self._take(buf)
            if n > 0:
                return n
            if self._next():
                continue
            if self._tls.is_closed():
                return 0
            _ = self.flush_ready()  # (a key update's reply)
            var room = min(self._tls.feed_capacity(), len(self._in))
            if room <= 0:
                raise tls_error("tls: the connection cannot take input", ErrorKind.Other, Category.PROTOCOL)
            var got: Optional[Int]
            try:
                got = self._tcp.try_read(Span(self._in)[0:room])
            except e:
                raise TlsError(e)
            if not got:
                return None
            try:
                if got.value() == 0:
                    self._tls.feed_eof()
                else:
                    self._tls.feed(Span(self._in)[0 : got.value()])
            except e:
                self._alert()
                raise e^

    def try_write(mut self, data: Span[UInt8, _]) raises TlsError -> Optional[Int]:
        """For readiness loops, as `TcpStream.try_write`: how many bytes of
        `data` were taken, without waiting and ignoring the write deadline;
        None while earlier ciphertext still waits for the socket. Taken
        bytes may still wait as ciphertext: when the socket is writable,
        call `flush_ready()` (or this again) until `pending_output()` is 0."""
        if not self.flush_ready():
            return None
        if len(data) == 0:
            return 0
        var n = self._tls.write(data)
        _ = self.flush_ready()
        return n

    def flush_ready(mut self) raises TlsError -> Bool:
        """Send queued ciphertext without waiting: True once none is left."""
        while True:
            if len(self._out) == 0:
                if not self._tls.has_transmit():
                    return True
                _ = self._tls.poll_transmit(self._out)
            var got: Optional[Int]
            try:
                got = self._tcp.try_write(self._out.readable_span())
            except e:
                raise TlsError(e)
            if not got:
                return False
            try:
                self._out.consume(got.value())
            except e:
                raise TlsError(e)

    def pending_output(self) -> Int:
        """Ciphertext not yet handed to the socket (an estimate: OpenSSL's
        queue counts as 1 until it is taken)."""
        return len(self._out) + (1 if self._tls.has_transmit() else 0)

    def buffered(self) -> Bool:
        """Whether plaintext (or the server's close_notify) waits here,
        already read from the socket."""
        return len(self._data) - self._data_off > 0 or self._tls.has_events()

    def is_reusable(mut self) -> Bool:
        """For a connection pool, on an idle connection: True when nothing
        has arrived since the last read but TLS's own messages (such as
        TLS 1.3 session tickets, which the server may send late). Data,
        the server's close_notify, the stream's end or any error: False."""
        if self.buffered() or self.pending_output() > 0 or self._tls.is_closed():
            return False
        while True:
            var room = min(self._tls.feed_capacity(), len(self._in))
            if room <= 0:
                return False
            var got: Optional[Int]
            try:
                got = self._tcp.try_read(Span(self._in)[0:room])
            except:
                return False
            if not got:
                return not self._tls.has_events()
            if got.value() == 0:
                return False
            try:
                self._tls.feed(Span(self._in)[0 : got.value()])
            except:
                return False
            if self._tls.has_events() or self._tls.is_closed():
                return False

    def close(deinit self, linger: Duration = CLOSE_LINGER) raises TlsError:
        """Send close_notify, then end the connection without losing what
        was sent. The socket is half-closed (its FIN follows the data) and
        read to the server's end, for at most `linger` and 256 KiB,
        discarding what arrives; then it is closed. The server's
        close_notify is not required (TB13).

        Closing a socket while unread input is in it makes Linux send a
        reset, which drops what was not yet delivered, and a TLS 1.3
        server's session tickets sit unread in the socket of a client that
        only writes. Dropping the stream instead closes the socket at once,
        without close_notify: an abortive end."""
        self._tls.close()
        self._flush()
        try:
            self._tcp.shutdown(Shutdown.WRITE)
            self._tcp.set_read_deadline(Deadline.after(linger))
            var drained = 0
            while drained < _LINGER_MAX:
                var n = self._tcp.read(Span(self._in))
                if n == 0:
                    break
                drained += n
        except:
            pass  # (reset, gone quiet, or still sending: nothing more to save)
        try:
            self._tcp^.close()
        except e:
            raise TlsError(e)

    # ---- deadlines and state --------------------------------------------

    def set_read_deadline(mut self, deadline: Deadline):
        self._tcp.set_read_deadline(deadline)

    def set_write_deadline(mut self, deadline: Deadline):
        self._tcp.set_write_deadline(deadline)

    def set_deadline(mut self, deadline: Deadline):
        self._tcp.set_deadline(deadline)

    def tcp(ref self) -> ref[self._tcp] TcpStream:
        """The TCP stream underneath (for socket options; reading or
        writing it directly breaks the TLS stream)."""
        return self._tcp

    def version(self) -> String:
        return self._tls.version()

    def cipher(self) -> String:
        return self._tls.cipher()

    def group(self) -> String:
        return self._tls.group()

    def alpn(self) -> String:
        """The application protocol the server chose ("" for none)."""
        return self._tls.alpn()

    def write_to(self, mut writer: Some[Writer]):
        writer.write("TlsStream(", self._tls.server_name(), ", ", self._tls.version(), ", ", self._tls.cipher(), ")")

    # ---- inside ---------------------------------------------------------

    def _take(mut self, buf: MutSpan[UInt8, _]) -> Int:
        """Copy plaintext already decrypted into `buf`."""
        var n = min(len(self._data) - self._data_off, len(buf))
        for i in range(n):
            buf[i] = self._data[self._data_off + i]
        self._data_off += n
        return n

    def _next(mut self) raises TlsError -> Bool:
        """Take the next event: True if there was one (DATA kept for
        `_take`; CLOSED answered with our close_notify, best effort)."""
        var ev = self._tls.next_event()
        if not ev:
            return False
        if ev.value().kind == TlsEventKind.DATA:
            swap(self._data, ev.value().data)
            self._data_off = 0
        elif ev.value().kind == TlsEventKind.CLOSED:
            try:
                _ = self.flush_ready()  # (our close_notify in reply)
            except:
                pass
        return True

    def _flush(mut self) raises TlsError:
        """Send every queued byte of ciphertext (waiting, under the write
        deadline)."""
        while len(self._out) > 0 or self._tls.has_transmit():
            if len(self._out) == 0:
                _ = self._tls.poll_transmit(self._out)
            try:
                self._tcp.write_all(self._out.readable_span())
            except e:
                raise TlsError(e)
            self._out.clear()

    def _alert(mut self):
        """After a failure, send the alert OpenSSL queued, if the socket
        takes it at once: best effort, never waiting."""
        if not self._tls.has_transmit():
            return
        try:
            _ = self._tls.poll_transmit(self._out)
        except:
            return
        try:
            _ = self._tcp.try_write(self._out.readable_span())
        except:
            pass
        self._out.clear()

    def _receive(mut self) raises TlsError:
        """One receive into the TLS state machine (EOF included)."""
        var room = min(self._tls.feed_capacity(), len(self._in))
        if room <= 0:
            raise tls_error("tls: the connection cannot take input", ErrorKind.Other, Category.PROTOCOL)
        var n: Int
        try:
            n = self._tcp.read(Span(self._in)[0:room])
        except e:
            raise TlsError(e)
        if n == 0:
            self._tls.feed_eof()
        else:
            self._tls.feed(Span(self._in)[0:n])
