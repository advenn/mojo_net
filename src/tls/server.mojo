"""`TlsServer`: one TLS server connection as a sans-I/O state machine over
OpenSSL memory BIOs (docs/tls.md; rules TS5, TS6, TS8-TS10 of
docs/research/tls_with_openssl.md). The driver moves bytes as for
`TlsClient`, from the first byte the client sends:

    var tls = TlsServer(context)                   # after accept
    loop:
        n = recv(buf)                              # at most feed_capacity()
        if n == 0: tls.feed_eof() else: tls.feed(buf[:n])
        tls.poll_transmit(out); send(out)          # the handshake, alerts
        while ev = tls.next_event(): ...           # ESTABLISHED, DATA, CLOSED
    tls.write(plaintext)
    tls.close()                                    # close_notify

The codec rules, failure latching, endings and bounds are the engine's
(`tls.engine`), shared with the client. A client may send at most
`CLIENT_HELLO_LIMIT` bytes before the handshake ends (TS8): far above any
real ClientHello, far below the 128 KiB OpenSSL would read. Admission
(how many handshakes may start) and the handshake's deadline belong to
the driver, which must refuse before making a `TlsServer` (TS7).

**Established** means: the handshake completed at TLS 1.2 or later, no
session was resumed (none can be: no tickets, no cache), the client's SNI,
if it sent one, is one of the context's DNS names (TS6), and the ALPN
result is one of the context's protocols, or none. Until then no plaintext
is encrypted and no DATA is delivered. An ALPN offer with no protocol in
common fails the handshake itself, with a fatal alert (TS5).

**Closing** (TS10): `close()` sends close_notify once established, never
during a handshake; after a failure, only the alert OpenSSL queued goes
out (`poll_transmit`), and the driver then closes the socket.
"""

from bytes.buffer import ByteBuffer
from linux import ErrorKind

from .consts import TLS1_2_VERSION, TLS1_3_VERSION, TLSEXT_NAMETYPE_host_name
from .engine import (
    CLIENT_HELLO_LIMIT,
    Engine,
    TlsEvent,
    same_bytes,
)
from .error import Category, TlsError, tls_error
from .ffi import SEAM_ALPN, SEAM_REUSED, SEAM_SERVER_NAME, SEAM_VERSION_LOW, from_c_string, seam
from .server_config import ServerContext
from .target import Target

comptime _SHOWN = 64
"""At most this many bytes of a refused SNI go into an error's detail."""


struct TlsServer(Movable):
    """One server connection (see the module docs)."""

    var _context: ServerContext
    """Holds the `SSL_CTX` and the ALPN callback's argument (TB1)."""
    var _e: Engine
    var _sni: String

    def __init__(out self, context: ServerContext) raises TlsError:
        """A connection waiting for its ClientHello."""
        self._context = context.copy()
        self._e = Engine(context._library(), context._ssl_ctx(), server=True, peer=String("the client"), limit=CLIENT_HELLO_LIMIT)
        self._sni = String()
        self._e.start()

    # ---- the driver's side ----------------------------------------------

    def feed_capacity(self) -> Int:
        """How many bytes the next `feed` may carry (rule 5)."""
        return self._e.feed_capacity()

    def feed(mut self, data: Span[UInt8, _]) raises TlsError:
        """Received ciphertext, at most `feed_capacity()` bytes. A failure
        it causes is raised by `next_event`, after the events before it."""
        self._e.feed(data)
        self._after()

    def feed_eof(mut self) raises TlsError:
        """The client's byte stream ended. Unless its close_notify came
        first, `next_event` then raises TRUNCATED."""
        self._e.feed_eof()
        self._after()

    def next_event(mut self) raises TlsError -> Optional[TlsEvent]:
        """The next event; once all are delivered, the failure, if any."""
        return self._e.next_event()

    def poll_transmit(mut self, mut out: ByteBuffer) raises TlsError -> Int:
        """Append queued ciphertext to `out`; returns how many bytes."""
        return self._e.poll_transmit(out)

    def has_events(self) -> Bool:
        return self._e.has_events()

    def has_transmit(self) -> Bool:
        return self._e.has_transmit()

    def pending_transmit(self) -> Int:
        """How much waits to be sent (`poll_transmit`): ciphertext, and
        plaintext written early, once it can be encrypted."""
        return self._e.pending_transmit()

    def has_unread_input(self) -> Bool:
        """Whether the input fed so far ends inside a record, or inside a
        client's handshake message (a key update split across records)."""
        return self._e.has_unread_input()

    def wants_input(self) -> Bool:
        """The last `write` took nothing because OpenSSL is in the middle of
        a client's handshake message: write again after more input."""
        return self._e.wants_input()

    def wipe(self, mut data: List[UInt8]):
        """Zero plaintext taken from a DATA event (`OPENSSL_cleanse`), before
        its buffer is reused or dropped (TB18)."""
        self._e.wipe(data)

    # ---- the application's side -----------------------------------------

    def write(mut self, data: Span[UInt8, _]) raises TlsError -> Int:
        """Encrypt plaintext into records; returns how much was taken (less
        while `TRANSMIT_LIMIT` bytes wait to be sent, or while
        `wants_input()`). Before the connection is established it is kept,
        and sent once it is."""
        return self._e.write(data)

    def close(mut self) raises TlsError:
        """Send close_notify, once, after any plaintext written early (in the
        middle of a client's handshake message, once it ends); nothing
        during the handshake."""
        self._e.close()

    def is_established(self) -> Bool:
        return self._e.is_established()

    def is_closed(self) -> Bool:
        """The client's close_notify arrived."""
        return self._e.is_closed()

    def version(self) -> String:
        return self._e.version

    def cipher(self) -> String:
        return self._e.cipher

    def group(self) -> String:
        return self._e.group

    def alpn(self) -> String:
        """The protocol chosen ("" when the client offered none)."""
        return self._e.alpn

    def server_name(self) -> String:
        """The name the client asked for (SNI), normalized; "" for none."""
        return self._sni

    # ---- the gate -------------------------------------------------------

    def _after(mut self):
        if not self._e.gate_pending():
            return
        try:
            self._gate()
        except e:
            self._e.refuse(e^)
            return
        self._e.open()

    def _gate(mut self) raises TlsError:
        ref L = self._e._lib[]
        var ssl = self._e._ssl
        var forced = seam(SEAM_VERSION_LOW)
        var version = Int(L.SSL_version(ssl)) if forced == 0 else (0x0301 if forced == 1 else forced)
        if version < TLS1_2_VERSION:
            raise tls_error("tls: the client negotiated a version below TLS 1.2", ErrorKind.InvalidData, Category.PROTOCOL)
        if self._context._tls13_only() and version < TLS1_3_VERSION:
            raise tls_error("tls: the client negotiated a version below TLS 1.3, which this server requires", ErrorKind.InvalidData, Category.PROTOCOL)
        if L.SSL_session_reused(ssl) != 0 or seam(SEAM_REUSED) != 0:
            raise tls_error("tls: a session was resumed, though resumption is off", ErrorKind.InvalidData, Category.PROTOCOL)
        var sni = from_c_string(L.SSL_get_servername(ssl, Int32(TLSEXT_NAMETYPE_host_name))) if seam(SEAM_SERVER_NAME) == 0 else String("unknown.invalid")
        if sni.byte_length() > 0:
            var name = String()
            try:
                var t = Target(sni)
                if not t.is_ip:  # (RFC 6066: SNI never carries an address)
                    name = t.name
            except:
                pass
            if name.byte_length() == 0 or not self._context._serves(name):
                raise tls_error("tls: the client asked for a name this server does not serve", ErrorKind.PermissionDenied, Category.HOST_MISMATCH, _shown(sni))
            self._sni = name^
        var chosen = self._e.selected_alpn() if seam(SEAM_ALPN) == 0 else List[UInt8]("h3".as_bytes())
        var alpn = String(from_utf8_lossy=Span(chosen))
        if len(chosen) > 0:
            var known = False
            for p in self._context.alpn():
                if same_bytes(Span(chosen), p.as_bytes()):
                    known = True
            if not known:
                raise tls_error("tls: the protocol chosen is not one this server speaks", ErrorKind.InvalidData, Category.ALPN, alpn)
        self._e.alpn = alpn^


def _shown(s: String) -> String:
    """`s` for a log line: printable ASCII only, cut short (a client's SNI
    is attacker-controlled; TS11)."""
    var out = String()
    var n = 0
    for b in s.as_bytes():
        if n == _SHOWN:
            out += "..."
            break
        out += chr(Int(b)) if b >= 0x21 and b <= 0x7E else "?"
        n += 1
    return out^
