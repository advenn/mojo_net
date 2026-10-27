"""`Engine`: what a TLS client and a TLS server share (docs/tls.md; rules
TB1-TB18 of docs/research/tls_with_openssl.md): one OpenSSL connection over
two memory BIOs, its records, events, bounds and failure latch. `TlsClient`
and `TlsServer` each hold one and add their side's checks at the end of the
handshake (the gate): until the gate passes, nothing is encrypted and no
DATA is delivered (TC10).

It follows the codec rules of `bytes.codec` (contract 1), with three
differences: errors are `TlsError`s (an `IoError` plus why); OpenSSL draws
random numbers, so the bytes sent differ from run to run (rule 3); and DATA
events split wherever records do, so only their concatenation is invariant
(rule 4's refinement). There are no timers: deadlines belong to the driver.

**Failures latch** (TB8, rule 6). The first failure frees the OpenSSL
connection, and `next_event` raises it once the events before it are
delivered, then on every later call; `feed`, `write` and `close` raise it
too. An alert OpenSSL queued stays queued for the driver to send
(`poll_transmit`); a refused gate queues nothing, its Finished dropped.

**Endings** (TB12, TB13). The peer's close_notify is a CLOSED event and is
answered with ours; input after it is ignored. Input that ends without it
(`feed_eof` first) raises `TRUNCATED` (`UnexpectedEof`), never a clean end,
because data may have been cut off: only a framing layer above, such as an
HTTP Content-Length, can tell a complete message.

**Bounds** (TB17). Unread ciphertext and undelivered plaintext together
stay within `FEED_LIMIT` (`feed_capacity()` says how much room is left;
each undelivered DATA event counts `EVENT_COST` bytes more); the peer may
send at most a handshake limit before the handshake ends (`HANDSHAKE_LIMIT`
for a server's, `CLIENT_HELLO_LIMIT` for a client's); `write` stops taking
plaintext while `TRANSMIT_LIMIT` bytes wait to be sent. A peer cannot make
work without end either: once established, at most `QUIET_LIMIT` bytes may
arrive without any application data in them (session tickets, key
updates), and what reading makes OpenSSL queue to send (key update
replies, alerts) may not take the transmit queue past `OUTPUT_LIMIT`.
Either fails the connection.

**A record at a time.** OpenSSL reads every record in its read BIO in one
call, answering each key update on the way, so a bound checked once a
whole feed is read could be passed by a feed's worth of records. Input is
handed to OpenSSL one record at a time instead, with the bounds checked
after each; what arrives behind the end of the handshake waits for the
gate, then goes the same way.

**In the middle of a peer's handshake message** (a key update or ticket
split across records), OpenSSL can neither encrypt nor send close_notify
until the rest arrives: `write` then takes nothing (`wants_input()` says
why), `close` waits for it, and `has_unread_input()` is true.
"""

from std.ffi import c_int
from std.memory import ArcPointer

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError

from .consts import (
    BIO_C_SET_BUF_MEM_EOF_RETURN,
    SSL_ERROR_SSL,
    SSL_ERROR_SYSCALL,
    SSL_ERROR_WANT_READ,
    SSL_ERROR_ZERO_RETURN,
    TLS1_3_VERSION,
    X509_V_ERR_CA_KEY_TOO_SMALL,
    X509_V_ERR_CA_MD_TOO_WEAK,
    X509_V_ERR_CERT_HAS_EXPIRED,
    X509_V_ERR_CERT_NOT_YET_VALID,
    X509_V_ERR_EE_KEY_TOO_SMALL,
    X509_V_ERR_HOSTNAME_MISMATCH,
    X509_V_ERR_IP_ADDRESS_MISMATCH,
    X509_V_OK,
)
from .error import Category, TlsError, tls_error
from .ffi import (
    SEAM_BIO_NEW,
    SEAM_BIO_WRITE,
    SEAM_HANDSHAKE,
    SEAM_READ,
    SEAM_SSL_NEW,
    SEAM_TRANSMIT_FULL,
    SEAM_WBIO_NEW,
    SEAM_WIPE,
    SEAM_WRITE,
    Library,
    Obj,
    buf,
    from_c_string,
    in_buf,
    is_alpn_refusal,
    out_buf,
    seam,
    size_out,
    u32_out,
)

comptime MAX_RECORD = 16 * 1024
"""TLS's largest plaintext record (RFC 8446 5.1): the unit of reads and writes."""
comptime FEED_LIMIT = 32 * 1024
"""Ciphertext held unread at most: more than one record of any version
(TLS 1.2 allows 2^14 + 2048 bytes of ciphertext per record)."""
comptime HANDSHAKE_LIMIT = 256 * 1024
"""Ciphertext a server may send before the handshake ends (above
OpenSSL's 100 KiB limit on a certificate chain)."""
comptime CLIENT_HELLO_LIMIT = 32 * 1024
"""Ciphertext a client may send before the handshake ends (TS8): its
ClientHello (a second one after a HelloRetryRequest) and Finished, which
take a few KiB, where OpenSSL alone would read 128 KiB of ClientHello.
It is checked after each record: a handshake still unfinished past it
fails, so OpenSSL reads at most it plus one record. What comes behind the
end of the handshake (a TLS 1.3 client's first data, behind its Finished)
is not handshake, and does not count."""
comptime TRANSMIT_LIMIT = 256 * 1024
"""Ciphertext waiting to be sent above which `write` takes no more."""
comptime OUTPUT_LIMIT = TRANSMIT_LIMIT + 2 * MAX_RECORD
"""The transmit queue after reading: `write` fills it to `TRANSMIT_LIMIT`
plus one record at most, so more means the peer provokes output (key
update replies, alerts) faster than it reads it."""
comptime QUIET_LIMIT = 256 * 1024
"""Ciphertext a server may send, once established, that carries no data
(session tickets, key updates, padding), over the whole connection: a
few tickets are normal; a flood of them would keep a reader working past
its deadline. Data does not reset it; each `QUIET_REFILL` bytes of data
add one byte to it."""
comptime CLIENT_QUIET_LIMIT = 4 * 1024
"""The same from a client, which has nothing to send without data but a
rare key update and its close_notify: each key update it asks the server
to answer costs the server about 25 times what its bytes of data would
(a reply, two key derivations), so that a client sending them between
bytes of data would keep a server core busy."""
comptime QUIET_REFILL = 4096
"""Bytes of application data that add a byte to the quiet budget."""
comptime _OVERHEAD_TLS13 = 22
"""A TLS 1.3 record's bytes besides its data: header, content type, tag."""
comptime _OVERHEAD_TLS12 = 29
"""A TLS 1.2 AEAD record's, at most (header, explicit nonce, tag)."""
comptime EVENT_COST = 64
"""Bytes each undelivered DATA event counts against the feed room, on top
of its data: a peer sending tiny records cannot make a driver that does
not drain hold more than about `FEED_LIMIT` in events."""

comptime _HANDSHAKE = 0
comptime _OPEN = 1
comptime _DONE = 2
"""The peer's close_notify arrived."""
comptime _FAILED = 3
comptime _GATE = 4
"""OpenSSL completed the handshake; the owner's checks have not run yet."""


struct TlsEventKind(Equatable, TrivialRegisterPassable, Writable):
    var value: Int

    comptime ESTABLISHED = TlsEventKind(0)
    """The connection passed every check: always the first event."""
    comptime DATA = TlsEventKind(1)
    """Decrypted application data (`TlsEvent.data`)."""
    comptime CLOSED = TlsEventKind(2)
    """The peer sent close_notify: the last event."""

    def __init__(out self, value: Int):
        self.value = value

    def __eq__(self, other: TlsEventKind) -> Bool:
        return self.value == other.value

    def write_to(self, mut writer: Some[Writer]):
        if self.value == 0:
            writer.write("ESTABLISHED")
        elif self.value == 1:
            writer.write("DATA")
        else:
            writer.write("CLOSED")


struct TlsEvent(Movable):
    var kind: TlsEventKind
    var data: List[UInt8]
    """For DATA: the plaintext (owned)."""

    def __init__(out self, kind: TlsEventKind, var data: List[UInt8] = List[UInt8]()):
        self.kind = kind
        self.data = data^


struct Engine(Movable):
    """One connection's OpenSSL state (see the module docs). Its owner
    (`TlsClient`, `TlsServer`) runs the gate when `gate_pending()` and then
    calls `open()`, or `refuse()` with why."""

    var _lib: ArcPointer[Library]
    """The library (TB1: it outlives the `SSL`; the `SSL` holds its own
    reference on the `SSL_CTX`)."""
    var _ssl: Obj
    """Owned, freed once; 0 after a failure (TC10)."""
    var _rbio: Obj
    """The read BIO, owned by `_ssl` (SSL_set0_rbio)."""
    var _wbio: Obj
    """The write BIO, owned by `_ssl`: it is the transmit queue."""
    var _server: Bool
    var _peer: String
    """Who the peer should be, for messages (the expected server name)."""
    var _limit: Int
    """Ciphertext the peer may send before the handshake ends."""
    var _state: Int
    var _eof: Bool
    """The driver called `feed_eof`."""
    var _ended: Bool
    """OpenSSL was told the input ended (after `_stash` is taken)."""
    var _sent_close: Bool
    var _close_pending: Bool
    """`close` was called; close_notify waits for the plaintext written
    early, or for the end of a peer's handshake message."""
    var _write_waits: Bool
    """The last `write` stopped in the middle of a peer's handshake
    message (until the next feed)."""
    var _stash: List[UInt8]
    """Ciphertext that came behind the end of the handshake, held while
    the gate is pending (then taken a record at a time)."""
    var _failed: Optional[TlsError]
    var _events: List[TlsEvent]
    var _next: Int
    """The next undelivered event in `_events`."""
    var _tx: ByteBuffer
    """Ciphertext taken out of `_wbio` when the connection failed (its alert)."""
    var _early: List[UInt8]
    """Plaintext written before the connection was established, from
    `_early_off` on (one buffer, reserved once, so no copy is left
    unwiped)."""
    var _early_off: Int
    var _rbuf: List[UInt8]
    """Where records are decrypted (one record)."""
    var _received: Int
    """Ciphertext fed before the handshake ended."""
    var _held: Int
    """Plaintext in undelivered DATA events, plus `EVENT_COST` each
    (counted against the feed room)."""
    var _quiet: Int
    """Ciphertext taken once established, less what the data records in
    it account for (their data and overhead): what carried no data
    (`QUIET_LIMIT`), records still arriving included."""
    var _quiet_limit: Int
    var _plain: Int
    """Application data delivered (it refills the quiet budget)."""
    var _overhead: Int
    """A data record's bytes besides its data, for the version in use."""
    var _hdr: Int
    """Bytes of the current record's 5-byte header fed so far."""
    var _len: Int
    """That header's length field, as it arrives."""
    var _body: Int
    """Bytes of the current record's body still to come."""
    var version: String
    var cipher: String
    var group: String
    var alpn: String

    def __init__(out self, lib: ArcPointer[Library], ssl_ctx: Obj, *, server: Bool, var peer: String, limit: Int) raises TlsError:
        """A new `SSL` on `ssl_ctx` over two memory BIOs, in the client or
        server state; nothing is queued yet (the owner sets its identity,
        then calls `start()`)."""
        self._lib = lib
        self._ssl = 0
        self._rbio = 0
        self._wbio = 0
        self._server = server
        self._peer = peer^
        self._limit = limit
        self._state = _HANDSHAKE
        self._eof = False
        self._ended = False
        self._sent_close = False
        self._close_pending = False
        self._write_waits = False
        self._stash = List[UInt8]()
        self._failed = None
        self._events = List[TlsEvent]()
        self._next = 0
        self._tx = ByteBuffer()
        self._early = List[UInt8]()
        self._early_off = 0
        self._rbuf = List[UInt8](length=MAX_RECORD, fill=0)
        self._received = 0
        self._held = 0
        self._quiet = 0
        self._quiet_limit = CLIENT_QUIET_LIMIT if server else QUIET_LIMIT
        self._plain = 0
        self._overhead = _OVERHEAD_TLS12
        self._hdr = 0
        self._len = 0
        self._body = 0
        self.version = String()
        self.cipher = String()
        self.group = String()
        self.alpn = String()
        ref L = self._lib[]
        L.ERR_clear_error()
        self._ssl = L.SSL_new(ssl_ctx)
        if seam(SEAM_SSL_NEW) != 0 and self._ssl != 0:
            L.SSL_free(self._ssl)
            self._ssl = 0
        if self._ssl == 0:
            raise self.fail(tls_error("tls: SSL_new failed", ErrorKind.OutOfMemory, Category.RESOURCE, L.drain_errors()))
        # From here every failure goes through fail, which frees _ssl (and
        # the BIOs given to it) and zeroes it: Mojo 1.2 skips `__deinit__`
        # when `__init__` raises before a field's last assignment (CLAUDE.md),
        # so the destructor cannot be relied on here.
        self._rbio = L.BIO_new(L.BIO_s_mem()) if seam(SEAM_BIO_NEW) == 0 else 0
        if self._rbio != 0:
            L.SSL_set0_rbio(self._ssl, self._rbio)
        self._wbio = L.BIO_new(L.BIO_s_mem()) if seam(SEAM_WBIO_NEW) == 0 else 0
        if self._wbio != 0:
            L.SSL_set0_wbio(self._ssl, self._wbio)
        if self._rbio == 0 or self._wbio == 0:
            raise self.fail(tls_error("tls: BIO_new failed", ErrorKind.OutOfMemory, Category.RESOURCE, L.drain_errors()))
        if server:
            L.SSL_set_accept_state(self._ssl)
        else:
            L.SSL_set_connect_state(self._ssl)

    def __deinit__(deinit self):
        ref L = self._lib[]
        L.OPENSSL_cleanse(buf(self._rbuf), len(self._rbuf))  # (TB18)
        _ = len(self._rbuf)  # (the buffer outlives the call)
        if len(self._early) > 0:
            L.OPENSSL_cleanse(buf(self._early), len(self._early))
            _ = len(self._early)
        for i in range(self._next, len(self._events)):  # (undelivered plaintext)
            if len(self._events[i].data) > 0:
                L.OPENSSL_cleanse(buf(self._events[i].data), len(self._events[i].data))
        if self._ssl != 0:
            L.SSL_free(self._ssl)

    def start(mut self) raises TlsError:
        """Begin the handshake (a client queues its ClientHello)."""
        self._pump()
        if self._failed:
            raise self._failed.value().copy()

    # ---- the driver's side ----------------------------------------------

    def feed_capacity(self) -> Int:
        if self._failed or self._eof:
            return 0
        if self._state == _DONE:
            return FEED_LIMIT
        return max(0, FEED_LIMIT - Int(self._lib[].BIO_ctrl_pending(self._rbio)) - self._held - len(self._stash))

    def feed(mut self, data: Span[UInt8, _]) raises TlsError:
        if self._failed:
            raise self._failed.value().copy()
        if self._eof:
            raise tls_error("tls: feed after feed_eof", ErrorKind.InvalidInput, Category.INPUT)
        if len(data) == 0 or self._state == _DONE:
            return  # (after close_notify, input is ignored)
        if len(data) > self.feed_capacity():
            raise self.fail(tls_error("tls: fed more than feed_capacity()", ErrorKind.OutOfMemory, Category.RESOURCE))
        self._take(data)

    def _take(mut self, data: Span[UInt8, _]) raises TlsError:
        """Hand `data` to OpenSSL a record at a time, with all the progress
        each allows and the bounds checked after each (see the module
        docs). What comes while the gate is pending waits in `_stash`; a
        failure, or the peer's close_notify, drops the rest. Raises only
        if the read BIO refuses the bytes (the failure latched too)."""
        ref L = self._lib[]
        var written = List[Int](length=1, fill=0)
        var off = 0
        while off < len(data):
            if self._failed or self._state == _DONE:
                return
            if self._state == _GATE:
                self._stash.extend(data[off:])
                return
            var k = self._record_end(data, off)
            var part = data[off : off + k]
            off += k
            if self._state == _HANDSHAKE:
                self._received += k
            L.ERR_clear_error()
            var rc = L.BIO_write_ex(self._rbio, in_buf(part), k, size_out(written))
            if rc != 1 or written[0] != k or seam(SEAM_BIO_WRITE) != 0:
                raise self.fail(tls_error("tls: BIO_write_ex failed", ErrorKind.OutOfMemory, Category.RESOURCE, L.drain_errors()))
            if self._state == _OPEN:
                self._quiet += k  # (a data record is taken off as it is read)
            self._write_waits = False
            self._frame(part)
            self._pump()
            if self._state == _HANDSHAKE and self._received > self._limit and not self._failed:
                _ = self.fail(tls_error("tls: the peer's handshake is too large", ErrorKind.InvalidData, Category.RESOURCE, String(self._received, " bytes")))
            self._check_quiet()

    def _record_end(self, data: Span[UInt8, _], off: Int) -> Int:
        """Bytes of `data` from `off` to the end of the record under way (by
        `_frame`'s count), or all the rest if it does not end in them."""
        var hdr = self._hdr
        var length = self._len
        var body = self._body
        var i = off
        var n = len(data)
        while i < n:
            if body > 0:
                var k = min(body, n - i)
                body -= k
                i += k
                if body == 0:
                    return i - off
                continue
            if hdr == 3:
                length = Int(data[i]) << 8
            elif hdr == 4:
                length |= Int(data[i])
            hdr += 1
            i += 1
            if hdr == 5:
                hdr = 0
                body = length
                if body == 0:
                    return i - off  # (an empty record ends with its header)
        return n - off

    def _partial(self) -> Int:
        """Bytes fed of the record still arriving (none of it read yet)."""
        if self._body > 0:
            return 5 + self._len - self._body
        return self._hdr

    def _check_quiet(mut self):
        if self._state != _OPEN:
            return
        var quiet = self._quiet - self._partial()
        if quiet > self._quiet_limit + self._plain // QUIET_REFILL:
            _ = self.fail(tls_error("tls: the peer sent too much without any data in it", ErrorKind.InvalidData, Category.PROTOCOL, String(quiet, " bytes")))

    def feed_eof(mut self) raises TlsError:
        if self._eof:
            return
        self._eof = True
        if self._failed or self._state == _DONE or len(self._stash) > 0:
            return  # (with a stash, the end comes after it: `open`)
        self._end_input()

    def _end_input(mut self):
        """(TB12) The BIO holds everything received; reads past it now see
        the end instead of "retry"."""
        self._ended = True
        _ = self._lib[].BIO_ctrl(self._rbio, BIO_C_SET_BUF_MEM_EOF_RETURN, 0, 0)
        self._pump()

    def next_event(mut self) raises TlsError -> Optional[TlsEvent]:
        if self._next < len(self._events):
            var ev = TlsEvent(self._events[self._next].kind)
            swap(ev.data, self._events[self._next].data)
            if ev.kind == TlsEventKind.DATA:
                self._held -= len(ev.data) + EVENT_COST
            self._next += 1
            if self._next == len(self._events):
                self._events.clear()
                self._next = 0
            return ev^
        if self._failed:
            raise self._failed.value().copy()
        return None

    def poll_transmit(mut self, mut out: ByteBuffer) raises TlsError -> Int:
        self._resume_early()
        var total = 0
        try:
            var n = min(len(self._tx), out.max_writable())
            if n > 0:
                out.write_bytes(self._tx.readable_span()[0:n])
                self._tx.consume(n)
                total = n
            if len(self._tx) > 0 or self._wbio == 0:
                return total
            ref L = self._lib[]
            var m = min(Int(L.BIO_ctrl_pending(self._wbio)), out.max_writable())
            if m <= 0:
                return total
            out.ensure_writable(m)
            var got = List[Int](length=1, fill=0)
            if L.BIO_read_ex(self._wbio, out_buf(out.writable_span()), m, size_out(got)) == 1 and got[0] > 0:
                out.commit(got[0])
                total += got[0]
        except e:
            raise TlsError(e, Category.RESOURCE)
        return total

    def has_events(self) -> Bool:
        return self._next < len(self._events)

    def has_transmit(self) -> Bool:
        if len(self._tx) > 0 or (self._state == _OPEN and self._early_left() > 0):
            return True
        return self._wbio != 0 and Int(self._lib[].BIO_ctrl_pending(self._wbio)) > 0

    def has_unread_input(self) -> Bool:
        """Part of a record has arrived (the rest still to come), or OpenSSL
        holds part of a peer's handshake message."""
        if self._hdr > 0 or self._body > 0 or len(self._stash) > 0:
            return True
        return self._state == _OPEN and self._ssl != 0 and self._lib[].SSL_in_init(self._ssl) != 0

    def close_pending(self) -> Bool:
        """`close` was called and close_notify still waits (see `close`)."""
        return self._close_pending and not self._failed

    def wipe(self, mut data: List[UInt8]):
        """Overwrite `data` with zeros (`OPENSSL_cleanse`, which the compiler
        cannot drop as a dead store): for plaintext taken from a DATA event,
        before its buffer is reused or dropped (TB18)."""
        if len(data) > 0:
            _ = seam(SEAM_WIPE)  # (counted by tests)
            self._lib[].OPENSSL_cleanse(buf(data), len(data))
            _ = len(data)  # (the buffer outlives the call)

    def wants_input(self) -> Bool:
        """The last `write` took nothing because OpenSSL is in the middle of
        a peer's handshake message: it goes on once more input is fed."""
        return self._write_waits and not self._failed

    def pending_transmit(self) -> Int:
        """Ciphertext waiting to be sent, plus plaintext written early and
        not yet encrypted (once established)."""
        var n = len(self._tx) + (self._early_left() if self._state == _OPEN else 0)
        if self._wbio != 0:
            n += Int(self._lib[].BIO_ctrl_pending(self._wbio))
        return n

    def _frame(mut self, data: Span[UInt8, _]):
        """Follow the record framing of `data` (5-byte headers whose last
        two bytes give the body's length), for `has_unread_input`."""
        var i = 0
        var n = len(data)
        while i < n:
            if self._body > 0:
                var k = min(self._body, n - i)
                self._body -= k
                i += k
                continue
            if self._hdr == 3:
                self._len = Int(data[i]) << 8
            elif self._hdr == 4:
                self._len |= Int(data[i])
            self._hdr += 1
            i += 1
            if self._hdr == 5:
                self._hdr = 0
                self._body = self._len

    # ---- the application's side -----------------------------------------

    def write(mut self, data: Span[UInt8, _]) raises TlsError -> Int:
        if self._failed:
            raise self._failed.value().copy()
        if self._sent_close or self._close_pending or self._state == _DONE:
            raise tls_error("tls: write after close", ErrorKind.BrokenPipe, Category.CLOSED)
        if self._state != _OPEN:
            var n = min(len(data), max(0, TRANSMIT_LIMIT - len(self._early)))
            if n > 0 and self._early.capacity() < TRANSMIT_LIMIT:
                self._early.reserve(TRANSMIT_LIMIT)  # (once: no copy left unwiped)
            self._early.extend(data[0:n])
            return n
        try:
            self._flush_early()
            if self._early_left() > 0:
                return 0  # (the queue is full: earlier bytes go first)
            return self._encrypt(data)
        except e:
            raise self.fail(e^)

    def close(mut self) raises TlsError:
        """Queue close_notify, after the plaintext written early (and once
        OpenSSL is not in the middle of a peer's handshake message)."""
        if self._failed:
            raise self._failed.value().copy()
        if self._sent_close or self._close_pending or self._state != _OPEN:
            return  # (never during the handshake: TB13)
        self._close_pending = True
        try:
            self._flush_early()
        except e:
            raise self.fail(e^)
        self._try_close()

    def _try_close(mut self):
        """Send the pending close_notify, if nothing written early is left
        and OpenSSL can (it cannot in the middle of a peer's handshake
        message: SSL_shutdown fails, and it is tried again after input)."""
        if not self._close_pending or self._sent_close or self._state != _OPEN or self._early_left() > 0:
            return
        ref L = self._lib[]
        L.ERR_clear_error()
        var rc = L.SSL_shutdown(self._ssl)  # (SSL_get_error is not consulted after it, TB13)
        _ = L.drain_errors()
        if rc >= 0:
            self._sent_close = True
            self._close_pending = False

    def is_established(self) -> Bool:
        return self._state == _OPEN or self._state == _DONE

    def is_closed(self) -> Bool:
        return self._state == _DONE

    # ---- the gate ---------------------------------------------------------

    def gate_pending(self) -> Bool:
        """OpenSSL completed the handshake and the owner's checks have yet
        to run (then `open()` or `refuse()`)."""
        return self._state == _GATE

    def open(mut self):
        """The gate passed: established, then all the progress the input
        already allows."""
        ref L = self._lib[]
        self.version = from_c_string(L.SSL_get_version(self._ssl))
        self.cipher = from_c_string(L.SSL_CIPHER_get_name(L.SSL_get_current_cipher(self._ssl)))
        self.group = from_c_string(L.SSL_get0_group_name(self._ssl))
        self._overhead = _OVERHEAD_TLS13 if Int(L.SSL_version(self._ssl)) == TLS1_3_VERSION else _OVERHEAD_TLS12
        self._state = _OPEN
        self._events.append(TlsEvent(TlsEventKind.ESTABLISHED))
        # What came behind the end of the handshake counts as if fed now:
        # what OpenSSL has not read yet, then the stash, a record at a time.
        self._quiet += Int(L.BIO_ctrl_pending(self._rbio))
        self._pump()
        self._check_quiet()
        if len(self._stash) > 0:
            var stash = List[UInt8]()
            swap(stash, self._stash)
            try:
                self._take(Span(stash))
            except:
                pass  # (latched: `next_event` raises it)
        if self._eof and not self._ended and not self._failed and self._state != _DONE:
            self._end_input()
            self._check_quiet()

    def selected_alpn(self) -> List[UInt8]:
        """The protocol ALPN chose, as the bytes on the wire (empty: none)."""
        ref L = self._lib[]
        var data = List[Int](length=1, fill=0)
        var length = List[UInt32](length=1, fill=0)
        L.SSL_get0_alpn_selected(self._ssl, size_out(data), u32_out(length))
        var out = List[UInt8]()
        if data[0] == 0 or length[0] == 0:
            return out^
        var p = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=data[0])
        for i in range(Int(length[0])):
            out.append(p[unsafe_offset=i])
        return out^

    def refuse(mut self, var e: TlsError):
        """The gate failed: OpenSSL queued our Finished (a client's) or our
        first data-ready flight (a server's), which the peer must not see
        as a completed handshake, so it is dropped."""
        self._drop_transmit()
        _ = self.fail(e^)

    # ---- inside ---------------------------------------------------------

    def fail(mut self, var e: TlsError) -> TlsError:
        """Latch `e` (the first failure stays) and free the connection;
        what OpenSSL queued to send (an alert) moves to `_tx`."""
        if not self._failed:
            self._failed = e.copy()
        self._state = _FAILED
        if self._ssl != 0:
            ref L = self._lib[]
            if self._wbio != 0:
                var pending = Int(L.BIO_ctrl_pending(self._wbio))
                if pending > 0 and pending <= TRANSMIT_LIMIT:
                    try:
                        self._tx.ensure_writable(pending)
                        var got = List[Int](length=1, fill=0)
                        if L.BIO_read_ex(self._wbio, out_buf(self._tx.writable_span()), pending, size_out(got)) == 1:
                            self._tx.commit(got[0])
                    except:
                        pass
            L.SSL_free(self._ssl)
            _ = L.drain_errors()
            self._ssl = 0
            self._rbio = 0
            self._wbio = 0
        if len(self._early) > 0:
            self._lib[].OPENSSL_cleanse(buf(self._early), len(self._early))
            self._early.clear()
            self._early_off = 0
        self._stash.clear()
        self._close_pending = False
        return e^

    def _drop_transmit(mut self):
        """Discard what OpenSSL queued to send."""
        if self._wbio == 0:
            return
        ref L = self._lib[]
        var scratch = List[UInt8](length=4096, fill=0)
        var got = List[Int](length=1, fill=0)
        while Int(L.BIO_ctrl_pending(self._wbio)) > 0:
            if L.BIO_read_ex(self._wbio, buf(scratch), len(scratch), size_out(got)) != 1 or got[0] <= 0:
                break

    def _pump(mut self):
        """All the progress the input allows; a failure latches. It stops
        when the handshake completes, for the owner's gate."""
        if self._failed:
            return
        try:
            if self._state == _HANDSHAKE:
                self._handshake()
            if self._state == _OPEN:
                self._flush_early()  # (before anything reading queues)
                self._read_records()
                self._try_close()
            if self._wbio != 0 and Int(self._lib[].BIO_ctrl_pending(self._wbio)) > OUTPUT_LIMIT:
                raise tls_error("tls: the peer provokes more output than it reads", ErrorKind.InvalidData, Category.RESOURCE)
        except e:
            _ = self.fail(e^)

    def _early_left(self) -> Int:
        return len(self._early) - self._early_off

    def _flush_early(mut self) raises TlsError:
        """Encrypt the plaintext written before the connection was
        established, as far as the transmit queue has room; wiped once all
        of it is."""
        if self._early_left() == 0 or self._state != _OPEN or self._sent_close:
            return
        var early = List[UInt8]()
        swap(early, self._early)  # (moved out: `_encrypt` takes `self`)
        var n: Int
        try:
            n = self._encrypt(Span(early)[self._early_off :])
        except e:
            swap(early, self._early)
            raise e^
        swap(early, self._early)
        self._early_off += n
        if self._early_off == len(self._early):
            self._lib[].OPENSSL_cleanse(buf(self._early), len(self._early))
            _ = len(self._early)
            self._early.clear()
            self._early_off = 0

    def _resume_early(mut self):
        """`_flush_early` for `poll_transmit`: a failure latches."""
        if self._early_left() == 0 or self._failed:
            return
        try:
            self._flush_early()
        except e:
            _ = self.fail(e^)
            return
        self._try_close()

    def _handshake(mut self) raises TlsError:
        ref L = self._lib[]
        L.ERR_clear_error()
        var forced = seam(SEAM_HANDSHAKE)
        var rc = L.SSL_do_handshake(self._ssl) if forced == 0 else c_int(-1)
        if rc == 1:
            self._state = _GATE
            return
        var err = L.SSL_get_error(self._ssl, rc) if forced == 0 else c_int(forced)  # (TB6: right after the call)
        if err == SSL_ERROR_WANT_READ and not self._ended:
            return
        var refused_alpn = self._server and is_alpn_refusal(L.ERR_peek_error())
        var detail = L.drain_errors()
        var code = Int(L.SSL_get_verify_result(self._ssl))
        if code != X509_V_OK:
            raise verify_error(L, code, self._peer)
        if refused_alpn:
            raise tls_error("tls: the client offered no application protocol this server speaks", ErrorKind.InvalidData, Category.ALPN, detail)
        if self._ended:
            raise tls_error("tls: the connection ended during the handshake", ErrorKind.UnexpectedEof, Category.TRUNCATED, detail)
        if err != SSL_ERROR_SSL and err != SSL_ERROR_SYSCALL:
            raise tls_error("tls: the handshake stopped unexpectedly", ErrorKind.Other, Category.PROTOCOL, String("SSL_get_error ", err, " ", detail))
        raise tls_error("tls: the handshake failed", ErrorKind.InvalidData, Category.PROTOCOL, detail)

    def _read_records(mut self) raises TlsError:
        """Decrypt until OpenSSL needs more input (TB9): TLS 1.3 session
        tickets and key updates carry no data, and a key update queues a
        reply in the write BIO."""
        ref L = self._lib[]
        var got = List[Int](length=1, fill=0)
        while True:
            L.ERR_clear_error()
            var forced = seam(SEAM_READ)
            var rc = L.SSL_read_ex(self._ssl, buf(self._rbuf), len(self._rbuf), size_out(got)) if forced == 0 else c_int(0)
            if rc == 1:
                if got[0] > 0:
                    self._events.append(TlsEvent(TlsEventKind.DATA, List[UInt8](Span(self._rbuf)[0 : got[0]])))
                    self._held += got[0] + EVENT_COST
                    self._quiet = max(0, self._quiet - got[0] - self._overhead)  # (one record, read whole)
                    self._plain += got[0]
                continue
            var err = L.SSL_get_error(self._ssl, rc) if forced == 0 else c_int(forced)  # (TB6)
            if err == SSL_ERROR_WANT_READ and not self._ended:
                return
            if err == SSL_ERROR_ZERO_RETURN:
                _ = L.drain_errors()
                if self._early_left() > 0:
                    # Written (and taken) before the handshake, never sent:
                    # say so rather than drop it.
                    raise tls_error("tls: the peer closed before the data written could be sent", ErrorKind.BrokenPipe, Category.CLOSED)
                self._state = _DONE
                self._events.append(TlsEvent(TlsEventKind.CLOSED))
                if not self._sent_close:
                    L.ERR_clear_error()
                    _ = L.SSL_shutdown(self._ssl)  # our close_notify in reply
                    _ = L.drain_errors()
                    self._sent_close = True
                    self._close_pending = False
                return
            var detail = L.drain_errors()
            if self._ended:
                raise tls_error("tls: the connection ended without close_notify", ErrorKind.UnexpectedEof, Category.TRUNCATED, detail)
            if err != SSL_ERROR_SSL and err != SSL_ERROR_SYSCALL:
                raise tls_error("tls: reading stopped unexpectedly", ErrorKind.Other, Category.PROTOCOL, String("SSL_get_error ", err, " ", detail))
            raise tls_error("tls: a record failed", ErrorKind.InvalidData, Category.PROTOCOL, detail)

    def _encrypt(mut self, data: Span[UInt8, _]) raises TlsError -> Int:
        """Encrypt `data` a record at a time while the transmit queue has
        room. A memory BIO takes every write and renegotiation is off, so
        OpenSSL never asks to retry a write (TB11): if it does, the
        connection fails rather than resend from a moved buffer. The one
        exception is WANT_READ in the middle of a peer's handshake message,
        which OpenSSL reports before it starts a record: nothing more is
        taken until input comes (`wants_input`)."""
        ref L = self._lib[]
        var done = List[Int](length=1, fill=0)
        var taken = 0
        while taken < len(data) and Int(L.BIO_ctrl_pending(self._wbio)) < TRANSMIT_LIMIT and seam(SEAM_TRANSMIT_FULL) == 0:
            var n = min(MAX_RECORD, len(data) - taken)
            L.ERR_clear_error()
            var forced = seam(SEAM_WRITE)
            var rc = L.SSL_write_ex(self._ssl, in_buf(data[taken : taken + n]), n, size_out(done)) if forced == 0 else c_int(0)
            if rc != 1:
                var err = L.SSL_get_error(self._ssl, rc) if forced == 0 else c_int(forced)  # (TB6)
                if err == SSL_ERROR_WANT_READ and L.SSL_in_init(self._ssl) != 0:
                    _ = L.drain_errors()
                    self._write_waits = True
                    return taken
                raise tls_error("tls: encrypting a record failed", ErrorKind.Other, Category.PROTOCOL, String("SSL_get_error ", err, " ", L.drain_errors()))
            taken += done[0]
        return taken


def same_bytes(a: Span[UInt8, _], b: Span[UInt8, _]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def verify_error(L: Library, code: Int, expected: String) -> TlsError:
    """A failed verification, with its category (TC18)."""
    var detail = String(from_c_string(L.X509_verify_cert_error_string(code)), " (expected ", expected, ")")
    var category = Category.UNTRUSTED
    if code == X509_V_ERR_CERT_HAS_EXPIRED or code == X509_V_ERR_CERT_NOT_YET_VALID:
        category = Category.EXPIRED
    elif code == X509_V_ERR_HOSTNAME_MISMATCH:
        category = Category.HOST_MISMATCH
    elif code == X509_V_ERR_IP_ADDRESS_MISMATCH:
        category = Category.IP_MISMATCH
    elif code == X509_V_ERR_EE_KEY_TOO_SMALL or code == X509_V_ERR_CA_KEY_TOO_SMALL or code == X509_V_ERR_CA_MD_TOO_WEAK:
        category = Category.WEAK
    return tls_error("tls: the server failed verification", ErrorKind.PermissionDenied, category, detail, code)
