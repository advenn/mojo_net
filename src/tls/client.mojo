"""`TlsClient`: one TLS client connection as a sans-I/O state machine over
OpenSSL memory BIOs (docs/tls.md; rules TB1-TB18 and TC4-TC10 of
docs/research/tls_with_openssl.md).

The driver moves bytes; OpenSSL never touches a socket:

    var tls = TlsClient(context, "example.com")   # queues the ClientHello
    loop:
        tls.poll_transmit(out); send(out)
        n = recv(buf)                              # at most feed_capacity()
        if n == 0: tls.feed_eof() else: tls.feed(buf[:n])
        while ev = tls.next_event(): ...           # ESTABLISHED, DATA, CLOSED
    tls.write(plaintext)                           # returns how much it took
    tls.close()                                    # close_notify

The codec rules, failure latching, endings and bounds are the engine's,
shared with `TlsServer` (`tls.engine` has them); the server may send at
most `HANDSHAKE_LIMIT` bytes before the handshake ends.

**Established** (TC9) means: the handshake completed, the server
presented a certificate, OpenSSL's verify result is `X509_V_OK`, a second,
independent check of that certificate against the expected name
(`X509_check_host`) or address (`X509_check_ip`) passes (and, for a name,
OpenSSL recorded the name it matched), the version is TLS 1.2 or later,
no session was resumed, and the ALPN result is one that was offered (or
none). Until then no plaintext is encrypted and no DATA is delivered
(TC10).
"""

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError

from .config import HOST_FLAGS, ClientContext
from .consts import SSL_CTRL_SET_TLSEXT_HOSTNAME, TLS1_2_VERSION, TLSEXT_NAMETYPE_host_name, X509_V_OK
from .engine import (
    EVENT_COST,
    FEED_LIMIT,
    HANDSHAKE_LIMIT,
    MAX_RECORD,
    OUTPUT_LIMIT,
    QUIET_LIMIT,
    TRANSMIT_LIMIT,
    Engine,
    TlsEvent,
    TlsEventKind,
    same_bytes,
    verify_error,
)
from .error import Category, TlsError, tls_error
from .ffi import (
    SEAM_ALPN,
    SEAM_CHECK_HOST,
    SEAM_CHECK_IP,
    SEAM_PEER_CERT,
    SEAM_PEERNAME,
    SEAM_REUSED,
    SEAM_SET_HOST,
    SEAM_SNI,
    SEAM_VERIFY_RESULT,
    SEAM_VERSION_LOW,
    buf,
    c_string,
    seam,
)
from .target import Target


struct TlsClient(Movable):
    """One client connection (see the module docs)."""

    var _context: ClientContext
    """Holds the `SSL_CTX` and the library (TB1: they outlive the `SSL`)."""
    var _e: Engine
    var _target: Target

    def __init__(out self, context: ClientContext, server_name: StringSlice) raises TlsError:
        """A connection to `server_name`: a DNS name or an IP literal,
        validated by `tls.target` (TC4). The ClientHello is queued at once."""
        var target: Target
        try:
            target = Target(server_name)
        except e:
            raise TlsError(e, Category.INPUT, String(server_name))
        self._context = context.copy()
        self._e = Engine(context._library(), context._ssl_ctx(), server=False, peer=target.name, limit=HANDSHAKE_LIMIT)
        self._target = target^
        try:
            self._set_identity()
        except e:
            raise self._e.fail(e^)  # (frees: see Engine.fail)
        self._e.start()

    def _set_identity(mut self) raises TlsError:
        """The identity the certificate must match (TC5): SNI and a host
        check for a name; an IP check and no SNI for an address."""
        ref L = self._e._lib[]
        var ssl = self._e._ssl
        var param = L.SSL_get0_param(ssl)
        if param == 0:
            raise tls_error("tls: no verify parameters", ErrorKind.Other, Category.LIBRARY, L.drain_errors())
        L.X509_VERIFY_PARAM_set_hostflags(param, HOST_FLAGS)
        if self._target.is_ip:
            if L.X509_VERIFY_PARAM_set1_ip(param, buf(self._target.ip), len(self._target.ip)) != 1 or seam(SEAM_SET_HOST) != 0:
                raise tls_error("tls: setting the expected address failed", ErrorKind.Other, Category.LIBRARY, L.drain_errors())
            return
        var name = _c_name(self._target.name)
        var n = self._target.name.byte_length()
        var sni = L.SSL_ctrl_str(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, buf(name)) if seam(SEAM_SNI) == 0 else 0
        # An explicit length: 0 would mean strlen, and an empty name turns
        # the check off (T0). Target refuses empty names; n > 0 says so.
        var host = n > 0 and L.X509_VERIFY_PARAM_set1_host(param, buf(name), n) == 1 and seam(SEAM_SET_HOST) == 0
        _ = name^
        if sni != 1 or not host:
            raise tls_error("tls: setting the expected host failed", ErrorKind.Other, Category.LIBRARY, L.drain_errors())

    # ---- the driver's side ----------------------------------------------

    def feed_capacity(self) -> Int:
        """How many bytes the next `feed` may carry (rule 5): the room left
        of `FEED_LIMIT` by unread ciphertext and undelivered plaintext, so a
        driver that feeds without draining is refused, not buffered."""
        return self._e.feed_capacity()

    def feed(mut self, data: Span[UInt8, _]) raises TlsError:
        """Received ciphertext, at most `feed_capacity()` bytes: copied into
        OpenSSL and processed as far as it goes. A failure it causes is
        raised by `next_event`, after the events before it."""
        self._e.feed(data)
        self._after()

    def feed_eof(mut self) raises TlsError:
        """The server's byte stream ended. Unless its close_notify came
        first, `next_event` then raises TRUNCATED."""
        self._e.feed_eof()
        self._after()

    def next_event(mut self) raises TlsError -> Optional[TlsEvent]:
        """The next event; once all are delivered, the failure, if any
        (raised again on every later call)."""
        return self._e.next_event()

    def poll_transmit(mut self, mut out: ByteBuffer) raises TlsError -> Int:
        """Append queued ciphertext to `out` (as much as it can take);
        returns how many bytes (rule 7). Plaintext written before the
        connection was established and not yet encrypted (the queue was
        full) is encrypted here as room appears."""
        return self._e.poll_transmit(out)

    def has_events(self) -> Bool:
        """Whether `next_event` has an event to give."""
        return self._e.has_events()

    def has_transmit(self) -> Bool:
        """Whether ciphertext waits to be sent (or plaintext written early
        waits to be encrypted)."""
        return self._e.has_transmit()

    def pending_transmit(self) -> Int:
        """How much waits to be sent (`poll_transmit`): ciphertext, and
        plaintext written early, once it can be encrypted."""
        return self._e.pending_transmit()

    def has_unread_input(self) -> Bool:
        """Whether the input fed so far ends inside a record (the rest of it
        still to come). Told from the record framing itself: OpenSSL may
        have taken the partial record out of its read BIO already."""
        return self._e.has_unread_input()

    # ---- the application's side -----------------------------------------

    def write(mut self, data: Span[UInt8, _]) raises TlsError -> Int:
        """Encrypt plaintext into records; returns how much was taken, less
        than `len(data)` only while `TRANSMIT_LIMIT` bytes wait to be sent
        (send them, then write the rest). Before the connection is
        established it is copied and kept, and encrypted once it is (TC10)."""
        return self._e.write(data)

    def close(mut self) raises TlsError:
        """Send close_notify, once. Data may still arrive until the
        server's close_notify (a CLOSED event). Before the connection is
        established nothing is sent (TB13): drop the connection instead."""
        self._e.close()

    def is_established(self) -> Bool:
        return self._e.is_established()

    def is_closed(self) -> Bool:
        """The server's close_notify arrived."""
        return self._e.is_closed()

    def version(self) -> String:
        """The protocol negotiated ("TLSv1.3"), once established."""
        return self._e.version

    def cipher(self) -> String:
        """The cipher suite ("TLS_AES_128_GCM_SHA256")."""
        return self._e.cipher

    def group(self) -> String:
        """The key exchange group ("X25519MLKEM768")."""
        return self._e.group

    def alpn(self) -> String:
        """The application protocol the server chose ("" for none)."""
        return self._e.alpn

    def server_name(self) -> String:
        """The expected identity, normalized."""
        return self._target.name

    # ---- the gate (TC9) -------------------------------------------------

    def _after(mut self):
        """Run the gate once OpenSSL has completed the handshake."""
        if not self._e.gate_pending():
            return
        try:
            self._gate()
        except e:
            self._e.refuse(e^)
            return
        self._e.open()

    def _gate(mut self) raises TlsError:
        """Any part missing fails the connection, before anything was
        encrypted or delivered."""
        ref L = self._e._lib[]
        var ssl = self._e._ssl
        var cert = L.SSL_get0_peer_certificate(ssl) if seam(SEAM_PEER_CERT) == 0 else 0
        if cert == 0:
            raise tls_error("tls: the server presented no certificate", ErrorKind.PermissionDenied, Category.NO_PEER_CERT)
        var code = Int(L.SSL_get_verify_result(ssl))
        var forced = seam(SEAM_VERIFY_RESULT)
        if forced != 0:
            code = forced
        if code != X509_V_OK:
            raise verify_error(L, code, self._target.name)
        if self._target.is_ip:
            if L.X509_check_ip(cert, buf(self._target.ip), len(self._target.ip), HOST_FLAGS) != 1 or seam(SEAM_CHECK_IP) != 0:
                raise tls_error("tls: the certificate is not for this address", ErrorKind.PermissionDenied, Category.IP_MISMATCH, self._target.name)
        else:
            var name = _c_name(self._target.name)
            var ok = L.X509_check_host(cert, buf(name), self._target.name.byte_length(), HOST_FLAGS, 0) == 1
            _ = name^
            if seam(SEAM_CHECK_HOST) != 0:
                ok = False
            if not ok or L.SSL_get0_peername(ssl) == 0 or seam(SEAM_PEERNAME) != 0:
                raise tls_error("tls: the certificate is not for this host", ErrorKind.PermissionDenied, Category.HOST_MISMATCH, self._target.name)
        var version = Int(L.SSL_version(ssl)) if seam(SEAM_VERSION_LOW) == 0 else 0x0301
        if version < TLS1_2_VERSION:
            raise tls_error("tls: the server negotiated a version below TLS 1.2", ErrorKind.InvalidData, Category.PROTOCOL)
        if L.SSL_session_reused(ssl) != 0 or seam(SEAM_REUSED) != 0:
            raise tls_error("tls: a session was resumed, though resumption is off", ErrorKind.InvalidData, Category.PROTOCOL)
        var chosen = self._e.selected_alpn() if seam(SEAM_ALPN) == 0 else List[UInt8]("h3".as_bytes())
        var alpn = String(from_utf8_lossy=Span(chosen))  # (for display only)
        if len(chosen) > 0:
            var known = False
            for p in self._context.alpn():
                if same_bytes(Span(chosen), p.as_bytes()):  # (bytes, not decoded text)
                    known = True
            if not known:
                raise tls_error("tls: the server chose a protocol that was not offered", ErrorKind.InvalidData, Category.ALPN, alpn)
        self._e.alpn = alpn^


def _c_name(s: String) raises TlsError -> List[UInt8]:
    try:
        return c_string(s, "tls: a name holds a NUL byte")
    except e:
        raise TlsError(e, Category.INPUT, s)
