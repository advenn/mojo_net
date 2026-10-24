"""`PgConnection`: the sans-I/O codec for one PostgreSQL session (design
contract 1), from the startup message to Terminate.

The codec runs the startup and authentication exchange by itself: trust,
cleartext password, MD5 or SCRAM-SHA-256 (`pg.auth`), as the server asks
and `Startup.allow` permits. It keeps what the server reports about the
session: ParameterStatus values, BackendKeyData and the transaction status.
The rest comes out as events:
- **READY:** ReadyForQuery. The first one means the session is open; each
  later one ends a query's cycle. `ev.status` is the transaction status.
- **ROW_DESCRIPTION, DATA_ROW, COMMAND_COMPLETE, EMPTY_QUERY:** results, in
  the order the statements ran.
- **ERROR, NOTICE:** an ErrorResponse or NoticeResponse
  (`ev.server_message()`).
  - In a query's cycle, an error ends that Query's statements, and the
    cycle still ends with READY.
  - An error during startup, or a FATAL one at any time, ends the session.
    The server then closes the connection, so EOF after it is no error.
- **NOTIFICATION:** a NOTIFY on a channel the session listens to. It can
  arrive at any time, between queries too.

`query(sql)` queues a Query (the simple protocol) once the session is open.
Queries may be pipelined: each gets its own cycle of events, ending with
READY, in order. `terminate()` queues Terminate; EOF is then the expected
end.

What ends the connection with an error (rule 6):
- **The server broke the protocol** (`InvalidData`): a malformed or
  unexpected message, a message over `Startup.max_message`, AuthenticationOk
  before the SCRAM exchange finished, a wrong SCRAM server signature.
- **Authentication the caller did not allow** (`PermissionDenied`, see
  `AuthMethods`).
- **Authentication this client cannot do** (`Unsupported`): Kerberos,
  GSSAPI, SSPI, or SASL without SCRAM-SHA-256.
- **A password request when no password was given** (`InvalidInput`).
- **COPY TO STDOUT** (`Unsupported`, for now). COPY FROM STDIN is answered
  with CopyFail instead, so the server reports an error and the session
  goes on.
- **EOF while the session is open** (`UnexpectedEof`).

Time: the codec has no timers (`next_deadline` is None). Deadlines belong to
the driver, which on expiry cancels the query (`write_cancel_request` on a
new connection) or closes the connection.
"""

from bytes.base64 import base64_encode
from bytes.buffer import ByteBuffer
from bytes.codec import Codec
from linux import ErrorKind, IoError
from linux.time import Instant

from .auth import SCRAM_SHA_256, ScramClient, md5_password
from .message import (
    AUTH_CLEARTEXT_PASSWORD,
    AUTH_GSS,
    AUTH_GSS_CONTINUE,
    AUTH_KERBEROS_V5,
    AUTH_MD5_PASSWORD,
    AUTH_OK,
    AUTH_SASL,
    AUTH_SASL_CONTINUE,
    AUTH_SASL_FINAL,
    AUTH_SSPI,
    AUTHENTICATION,
    BACKEND_KEY_DATA,
    BackendKey,
    COMMAND_COMPLETE,
    COPY_BOTH_RESPONSE,
    COPY_IN_RESPONSE,
    COPY_OUT_RESPONSE,
    Column,
    DATA_ROW,
    E_COMMAND_COMPLETE,
    EMPTY_QUERY_RESPONSE,
    ERROR_RESPONSE,
    FAILED_TRANSACTION,
    IDLE,
    IN_TRANSACTION,
    NEGOTIATE_PROTOCOL_VERSION,
    NOTICE_RESPONSE,
    NOTIFICATION_RESPONSE,
    Notification,
    PARAMETER_STATUS,
    READY_FOR_QUERY,
    ROW_DESCRIPTION,
    ServerMessage,
    be_i32,
    be_u32,
    check_fields,
    check_notification,
    check_row_description,
    check_string,
    notification,
    read_data_row,
    read_parameter_status,
    row_description,
    rows_affected,
    string_end,
    write_copy_fail,
    write_password,
    write_query,
    write_sasl_initial_response,
    write_sasl_response,
    write_startup,
    write_terminate,
)

comptime DEFAULT_MAX_MESSAGE = 1 << 30
"""1 GiB: no larger message comes from a server, whose own allocations
stop there."""
comptime MIN_NONCE = 16
"""Random bytes a connection needs for its SCRAM nonce, at least."""

comptime E_LENGTH = "pg: message length out of bounds"
comptime E_UNEXPECTED = "pg: unexpected message from the server"
comptime E_AUTH = "pg: malformed authentication request"
comptime E_AUTH_AGAIN = "pg: a second authentication request"
comptime E_SCRAM_INCOMPLETE = "pg: authentication ended before the SCRAM exchange did"
comptime E_NOT_ALLOWED = "pg: the server asks for authentication this connection does not allow"
comptime E_NO_PASSWORD = "pg: the server asks for a password and none was given"
comptime E_AUTH_UNSUPPORTED = "pg: the server asks for unsupported authentication"
comptime E_NO_SCRAM = "pg: the server offers no SCRAM-SHA-256"
comptime E_BACKEND_KEY = "pg: malformed BackendKeyData"
comptime E_READY = "pg: malformed ReadyForQuery"
comptime E_NEGOTIATE = "pg: the server cannot speak protocol 3.0 as asked"
comptime E_COPY_OUT = "pg: COPY TO STDOUT is not supported"
comptime E_EOF = "pg: the server closed the connection"
comptime E_FEED = "pg: fed past feed_capacity()"
comptime E_NO_SESSION = "pg: no open session"
comptime E_STARTUP = "pg: invalid startup settings"

comptime _COPY_REFUSED = "COPY FROM STDIN is not supported by this client"

# Phases of the session.
comptime _AUTHENTICATING = 0
comptime _OPENING = 1
"""Authenticated: ParameterStatus and BackendKeyData until ReadyForQuery."""
comptime _OPEN = 2
comptime _ENDED = 3
"""An error during startup, or a FATAL one: the server closes."""

# Authentication progress (the client's last move).
comptime _SENT_NOTHING = 0
comptime _SENT_PASSWORD = 1
comptime _SENT_SASL_FIRST = 2
comptime _SENT_SASL_FINAL = 3
comptime _SASL_DONE = 4


@fieldwise_init
struct AuthMethods(Equatable, TrivialRegisterPassable, Writable):
    """Which authentication a server may ask for, like libpq's
    `require_auth`. A server asking for another is refused with
    `PermissionDenied`, before any password leaves the client."""

    var _bits: UInt8

    comptime TRUST = AuthMethods(1)
    """No authentication: trust, peer or ident in pg_hba.conf."""
    comptime PASSWORD = AuthMethods(2)
    """The password in cleartext."""
    comptime MD5 = AuthMethods(4)
    comptime SCRAM_SHA_256 = AuthMethods(8)
    comptime ALL = AuthMethods(15)

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self._bits == other._bits

    @inline(.always)
    def __or__(self, other: Self) -> Self:
        return AuthMethods(self._bits | other._bits)

    @inline(.always)
    def allows(self, method: Self) -> Bool:
        return (self._bits & method._bits) == method._bits

    def write_to(self, mut writer: Some[Writer]):
        var names = ["trust", "password", "md5", "scram-sha-256"]
        var first = True
        for i in range(4):
            if self._bits & UInt8(1 << i):
                writer.write("" if first else ",", names[i])
                first = False


struct Startup(Copyable, Movable):
    """What opening a session needs: the user and database, the password
    for whatever authentication the server asks for, and the run-time
    parameters to send. One `Startup` serves any number of connections."""

    var user: String
    var database: String
    """Empty: the server's default, the database named like the user."""
    var password: String
    """Empty: none. A server that asks for one is refused (`InvalidInput`)."""
    var application_name: String
    """Shown in `pg_stat_activity`; empty to send none."""
    var allow: AuthMethods
    var max_message: Int
    """The longest backend message accepted, length field included."""
    var _params: List[String]

    def __init__(
        out self,
        user: String,
        *,
        database: String = "",
        password: String = "",
        application_name: String = "",
        allow: AuthMethods = AuthMethods.ALL,
        max_message: Int = DEFAULT_MAX_MESSAGE,
    ):
        self.user = user
        self.database = database
        self.password = password
        self.application_name = application_name
        self.allow = allow
        self.max_message = max_message
        self._params = List[String]()

    def set(mut self, name: String, value: String):
        """A run-time parameter for the session: "search_path",
        "TimeZone", "statement_timeout", or "options" for command-line
        switches (`-c name=value`). `client_encoding` is always UTF8."""
        self._params.append(name)
        self._params.append(value)


@fieldwise_init
struct EventKind(Equatable, TrivialRegisterPassable, Writable):
    var _v: UInt8

    comptime READY = EventKind(0)
    """ReadyForQuery: the session is open, or a query's cycle ended."""
    comptime ROW_DESCRIPTION = EventKind(1)
    comptime DATA_ROW = EventKind(2)
    comptime COMMAND_COMPLETE = EventKind(3)
    comptime EMPTY_QUERY = EventKind(4)
    """The Query (or one of its statements) was empty."""
    comptime ERROR = EventKind(5)
    comptime NOTICE = EventKind(6)
    comptime NOTIFICATION = EventKind(7)

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self._v == other._v

    def write_to(self, mut writer: Some[Writer]):
        var names = [
            "READY",
            "ROW_DESCRIPTION",
            "DATA_ROW",
            "COMMAND_COMPLETE",
            "EMPTY_QUERY",
            "ERROR",
            "NOTICE",
            "NOTIFICATION",
        ]
        writer.write(names[Int(self._v)])


struct PgEvent(Movable, Writable):
    """One event (see the module docs). `data` is the message's body, and
    the accessors read it for the event's kind. An event is meant to be
    reused (`PgConnection.poll`): its buffers keep their capacity."""

    var kind: EventKind
    var status: UInt8
    """READY: the transaction status, `IDLE`, `IN_TRANSACTION` or
    `FAILED_TRANSACTION` (`pg.message`)."""
    var data: List[UInt8]
    """The message's body (empty for READY and EMPTY_QUERY)."""
    var _at: List[Int]
    """DATA_ROW: each value's start in `data` and its length (-1: NULL)."""

    def __init__(out self):
        self.kind = EventKind.READY
        self.status = 0
        self.data = List[UInt8]()
        self._at = List[Int]()

    def values(self) -> Int:
        """DATA_ROW: how many values the row has."""
        return len(self._at) // 2

    def is_null(self, i: Int) -> Bool:
        """DATA_ROW: whether value `i` is NULL."""
        return self._at[2 * i + 1] < 0

    def value(self, i: Int) -> Span[UInt8, origin_of(self.data)]:
        """DATA_ROW: the bytes of value `i` (empty for NULL), in the
        column's format: text unless the query asked for binary."""
        var start = self._at[2 * i]
        return Span(self.data)[start : start + max(self._at[2 * i + 1], 0)]

    def columns(self) -> List[Column]:
        """ROW_DESCRIPTION: the columns of the rows that follow."""
        return row_description(Span(self.data))

    def tag(self) -> String:
        """COMMAND_COMPLETE: the command tag, such as "INSERT 0 1"."""
        return String(from_utf8_lossy=Span(self.data)[: len(self.data) - 1])

    def rows_affected(self) -> Optional[Int]:
        """COMMAND_COMPLETE: the row count the tag reports, if any."""
        return rows_affected(self.tag())

    def server_message(self) -> ServerMessage:
        """ERROR or NOTICE: the server's fields."""
        return ServerMessage(self.data.copy())

    def notification(self) -> Notification:
        """NOTIFICATION: the channel, payload and sender."""
        return notification(Span(self.data))

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.kind)
        if self.kind == EventKind.READY:
            writer.write(" ", chr(Int(self.status)))
        elif self.kind == EventKind.DATA_ROW:
            for i in range(self.values()):
                if self.is_null(i):
                    writer.write(" NULL")
                else:
                    writer.write(" ", String(from_utf8_lossy=self.value(i)))
        elif self.kind == EventKind.ROW_DESCRIPTION:
            var cols = self.columns()
            for i in range(len(cols)):
                writer.write(" ", cols[i].name, ":", cols[i].type_oid)
        elif self.kind == EventKind.COMMAND_COMPLETE:
            writer.write(" ", self.tag())
        elif self.kind == EventKind.ERROR or self.kind == EventKind.NOTICE:
            writer.write(" ", self.server_message())
        elif self.kind == EventKind.NOTIFICATION:
            writer.write(" ", self.notification())


@inline(.always)
def _is_event(kind: UInt8) -> Bool:
    """Whether a backend message of this type becomes an event."""
    return (
        kind == DATA_ROW
        or kind == READY_FOR_QUERY
        or kind == ROW_DESCRIPTION
        or kind == COMMAND_COMPLETE
        or kind == EMPTY_QUERY_RESPONSE
        or kind == ERROR_RESPONSE
        or kind == NOTICE_RESPONSE
        or kind == NOTIFICATION_RESPONSE
    )


def _is_fatal(fields: Span[UInt8, _]) -> Bool:
    """Whether a checked ErrorResponse body says FATAL or PANIC."""
    var m = ServerMessage(List[UInt8](fields))
    return m.is_fatal()


def _lower(s: StringSlice) -> String:
    return String(s).lower()


def _offers_scram(body: Span[UInt8, _]) raises IoError -> Bool:
    """Whether AuthenticationSASL's mechanism list (from offset 4: strings,
    then an empty one) names SCRAM-SHA-256."""
    var i = 4
    var found = False
    while True:
        if i >= len(body):
            raise IoError.of_kind(E_AUTH, ErrorKind.InvalidData)
        if body[i] == 0:
            if i != len(body) - 1:
                raise IoError.of_kind(E_AUTH, ErrorKind.InvalidData)
            return found
        var end = string_end(body, i, E_AUTH)
        if String(from_utf8_lossy=body[i:end]) == SCRAM_SHA_256:
            found = True
        i = end + 1


struct PgConnection(Codec, Copyable):
    """The codec for one session (see the module docs)."""

    comptime Event = PgEvent

    var _rx: ByteBuffer
    var _tx: ByteBuffer
    var _user: String
    var _password: String
    var _allow: AuthMethods
    var _max_message: Int
    var _nonce: String
    var _scram: List[ScramClient]
    """The SCRAM exchange while it runs (none or one)."""
    var _phase: Int
    var _auth: Int
    var _queries: Int
    """Queries sent whose cycle has not ended (no READY yet)."""
    var _columns: Int
    """The current statement's column count: -1 without a RowDescription."""
    var _status: UInt8
    var _params: List[String]
    """ParameterStatus values: name, value, name, value..."""
    var _key: Optional[BackendKey]
    var _terminated: Bool
    var _eof: Bool
    var _failed: Optional[IoError]
    var _scratch: List[UInt8]
    """The body of the message being handled, when it is no event."""

    def __init__(out self, startup: Startup, nonce: Span[UInt8, _]) raises IoError:
        """Queue the StartupMessage for `startup`. `nonce`: at least
        `MIN_NONCE` bytes from a strong random source (getrandom), fresh for
        each connection; SCRAM's client nonce is made from them.
        `InvalidInput` for a short nonce, an empty user, a parameter set
        twice or reserved (user, database, client_encoding, replication,
        application_name: those have their own settings), a NUL in any
        setting, or `max_message` under 1024."""
        if len(nonce) < MIN_NONCE or startup.user.byte_length() == 0 or startup.max_message < 1024:
            raise IoError.of_kind(E_STARTUP, ErrorKind.InvalidInput)
        var params: List[String] = ["user", startup.user]
        if startup.database.byte_length() > 0:
            params.append("database")
            params.append(startup.database)
        if startup.application_name.byte_length() > 0:
            params.append("application_name")
            params.append(startup.application_name)
        params.append("client_encoding")
        params.append("UTF8")
        for i in range(0, len(startup._params), 2):
            var name = _lower(startup._params[i])
            if name == "replication" or name == "application_name" or name == "database":
                raise IoError.of_kind(E_STARTUP, ErrorKind.InvalidInput)
            for k in range(0, len(params), 2):
                if _lower(params[k]) == name:
                    raise IoError.of_kind(E_STARTUP, ErrorKind.InvalidInput)
            params.append(startup._params[i])
            params.append(startup._params[i + 1])
        self._tx = ByteBuffer()
        write_startup(self._tx, params)
        self._rx = ByteBuffer(max_size=startup.max_message + 1)
        self._user = startup.user
        self._password = startup.password
        self._allow = startup.allow
        self._max_message = startup.max_message
        self._nonce = base64_encode(nonce)
        self._scram = List[ScramClient]()
        self._phase = _AUTHENTICATING
        self._auth = _SENT_NOTHING
        self._queries = 0
        self._columns = -1
        self._status = 0
        self._params = List[String]()
        self._key = None
        self._terminated = False
        self._eof = False
        self._failed = None
        self._scratch = List[UInt8]()

    # ---- the session --------------------------------------------------------

    def is_open(self) -> Bool:
        """Whether the session is open (startup done, not ended or
        terminated), so `query` may be called."""
        return self._phase == _OPEN and not self._terminated

    def is_idle(self) -> Bool:
        """Whether the session is open with no query in flight."""
        return self.is_open() and self._queries == 0

    def pending_queries(self) -> Int:
        """Queries sent whose cycle has not ended yet."""
        return self._queries

    def transaction_status(self) -> UInt8:
        """From the last ReadyForQuery: `IDLE`, `IN_TRANSACTION` or
        `FAILED_TRANSACTION`; 0 before the session is open."""
        return self._status

    def parameter(self, name: StringSlice) -> Optional[String]:
        """The last value the server reported for a parameter
        ("server_version", "TimeZone", "integer_datetimes", ...)."""
        for i in range(0, len(self._params), 2):
            if self._params[i] == name:
                return self._params[i + 1]
        return None

    def backend_key(self) -> Optional[BackendKey]:
        """What a CancelRequest for this session quotes, once the server
        sent it (poolers may not)."""
        return self._key

    def query(mut self, sql: StringSlice) raises IoError:
        """Queue a Query: one or more statements, run in order, whose
        results come as events ending with READY. `InvalidInput`, without
        harm to the session, when it is not open or `sql` holds a NUL."""
        if not self.is_open():
            raise IoError.of_kind(E_NO_SESSION, ErrorKind.InvalidInput)
        write_query(self._tx, sql)
        self._queries += 1

    def terminate(mut self) raises IoError:
        """Queue Terminate (once): the server closes the connection, and
        EOF is then the expected end. Queries queued before it still run."""
        if self._terminated:
            return
        write_terminate(self._tx)
        self._terminated = True

    # ---- the Codec interface --------------------------------------------------

    def _poison(mut self, e: IoError) -> IoError:
        self._failed = e
        return e

    def feed(mut self, data: Span[UInt8, _]) raises IoError:
        if self._failed:
            raise self._failed.value()
        if self._eof:
            raise IoError.of_kind("pg: feed after EOF", ErrorKind.InvalidInput)
        if len(data) > self._rx.max_writable():
            raise self._poison(IoError.of_kind(E_FEED, ErrorKind.OutOfMemory))
        self._rx.write_bytes(data)

    def feed_capacity(self) -> Int:
        return self._rx.max_writable()

    def feed_eof(mut self) raises IoError:
        if self._failed:
            raise self._failed.value()
        self._eof = True

    def next_event(mut self) raises IoError -> Optional[PgEvent]:
        """The next event, if one is ready (the `Codec` interface). `poll`
        does the same into an event the caller reuses."""
        var ev = PgEvent()
        if self.poll(ev):
            return ev^
        return None

    def poll(mut self, mut ev: PgEvent) raises IoError -> Bool:
        """Fill `ev` with the next event and return True, or return False
        when none is ready. `ev`'s buffers are reused."""
        if self._failed:
            raise self._failed.value()
        while True:
            var have = self._rx.readable()
            if have < 5:
                if self._eof:
                    if have == 0 and (self._phase == _ENDED or self._terminated):
                        return False
                    raise self._poison(IoError.of_kind(E_EOF, ErrorKind.UnexpectedEof))
                return False
            var kind = self._rx.readable_span()[0]
            var length = be_i32(self._rx.readable_span(), 1)
            if length < 4 or length > self._max_message:
                raise self._poison(IoError.of_kind(E_LENGTH, ErrorKind.InvalidData))
            if have <= length:
                if self._eof:
                    raise self._poison(IoError.of_kind(E_EOF, ErrorKind.UnexpectedEof))
                return False
            if _is_event(kind):
                ev.data.clear()
                ev.data.extend(self._rx.readable_span()[5 : 1 + length])
            else:
                self._scratch.clear()
                self._scratch.extend(self._rx.readable_span()[5 : 1 + length])
            self._rx.consume(1 + length)
            var produced: Bool
            try:
                produced = self._handle(kind, ev)
            except e:
                raise self._poison(e)
            if produced:
                return True

    def poll_transmit(mut self, mut out: ByteBuffer) raises IoError -> Int:
        var n = min(self._tx.readable(), out.max_writable())
        if n == 0:
            return 0
        out.write_bytes(self._tx.readable_span()[:n])
        self._tx.consume(n)
        return n

    def next_deadline(self) -> Optional[Instant]:
        return None

    def handle_timeout(mut self, now: Instant) raises IoError:
        pass

    # ---- messages -------------------------------------------------------------

    def _handle(mut self, kind: UInt8, mut ev: PgEvent) raises IoError -> Bool:
        """Act on one message; True when it filled `ev`."""
        if kind == DATA_ROW:  # the common case: rows of a statement (_OPEN)
            if self._columns < 0:
                raise IoError.of_kind(E_UNEXPECTED, ErrorKind.InvalidData)
            read_data_row(Span(ev.data), self._columns, ev._at)
            ev.kind = EventKind.DATA_ROW
            return True
        if kind == ERROR_RESPONSE:
            check_fields(Span(ev.data))
            ev.kind = EventKind.ERROR
            self._columns = -1
            if self._phase != _OPEN or _is_fatal(Span(ev.data)):
                self._phase = _ENDED
            return True
        if kind == NOTICE_RESPONSE:
            check_fields(Span(ev.data))
            ev.kind = EventKind.NOTICE
            return True
        if self._phase == _AUTHENTICATING:
            if kind == AUTHENTICATION:
                self._authenticate()
                return False
            if kind == NEGOTIATE_PROTOCOL_VERSION and self._auth == _SENT_NOTHING:
                self._negotiate()
                return False
            raise IoError.of_kind(E_UNEXPECTED, ErrorKind.InvalidData)
        if self._phase == _ENDED:
            raise IoError.of_kind(E_UNEXPECTED, ErrorKind.InvalidData)
        if kind == PARAMETER_STATUS:
            var name = String()
            var value = String()
            read_parameter_status(Span(self._scratch), name, value)
            for i in range(0, len(self._params), 2):
                if self._params[i] == name:
                    self._params[i + 1] = value^
                    return False
            self._params.append(name^)
            self._params.append(value^)
            return False
        if kind == NOTIFICATION_RESPONSE:
            check_notification(Span(ev.data))
            ev.kind = EventKind.NOTIFICATION
            return True
        if self._phase == _OPENING:
            if kind == BACKEND_KEY_DATA:
                var key = Span(self._scratch)
                if len(key) != 8:
                    raise IoError.of_kind(E_BACKEND_KEY, ErrorKind.InvalidData)
                self._key = BackendKey(be_i32(key, 0), be_u32(key, 4))
                return False
            if kind == READY_FOR_QUERY:
                self._ready(ev)
                self._phase = _OPEN
                return True
            raise IoError.of_kind(E_UNEXPECTED, ErrorKind.InvalidData)
        # _OPEN: the results of queries in flight.
        if self._queries == 0:
            raise IoError.of_kind(E_UNEXPECTED, ErrorKind.InvalidData)
        if kind == READY_FOR_QUERY:
            if self._columns >= 0:  # rows without their CommandComplete
                raise IoError.of_kind(E_UNEXPECTED, ErrorKind.InvalidData)
            self._ready(ev)
            self._queries -= 1
            return True
        if kind == ROW_DESCRIPTION:
            self._columns = check_row_description(Span(ev.data))
            ev.kind = EventKind.ROW_DESCRIPTION
            return True
        if kind == COMMAND_COMPLETE:
            check_string(Span(ev.data), E_COMMAND_COMPLETE)
            self._columns = -1
            ev.kind = EventKind.COMMAND_COMPLETE
            return True
        if kind == EMPTY_QUERY_RESPONSE:
            if len(ev.data) != 0:
                raise IoError.of_kind(E_UNEXPECTED, ErrorKind.InvalidData)
            ev.kind = EventKind.EMPTY_QUERY
            return True
        if kind == COPY_IN_RESPONSE:
            write_copy_fail(self._tx, _COPY_REFUSED)
            return False
        if kind == COPY_OUT_RESPONSE or kind == COPY_BOTH_RESPONSE:
            raise IoError.of_kind(E_COPY_OUT, ErrorKind.Unsupported)
        raise IoError.of_kind(E_UNEXPECTED, ErrorKind.InvalidData)

    def _ready(mut self, mut ev: PgEvent) raises IoError:
        if len(ev.data) != 1:
            raise IoError.of_kind(E_READY, ErrorKind.InvalidData)
        var status = ev.data[0]
        if status != IDLE and status != IN_TRANSACTION and status != FAILED_TRANSACTION:
            raise IoError.of_kind(E_READY, ErrorKind.InvalidData)
        self._status = status
        ev.kind = EventKind.READY
        ev.status = status

    def _negotiate(mut self) raises IoError:
        """NegotiateProtocolVersion: the server's newest minor version and
        the protocol options it did not recognize. This client asks for 3.0
        and sends no options, so only an empty list can be accepted."""
        var body = Span(self._scratch)
        if len(body) != 8 or be_i32(body, 0) < 0 or be_i32(body, 4) != 0:
            raise IoError.of_kind(E_NEGOTIATE, ErrorKind.Unsupported)

    def _require(self, method: AuthMethods) raises IoError:
        if not self._allow.allows(method):
            raise IoError.of_kind(E_NOT_ALLOWED, ErrorKind.PermissionDenied)
        if self._password.byte_length() == 0:
            raise IoError.of_kind(E_NO_PASSWORD, ErrorKind.InvalidInput)

    def _authenticate(mut self) raises IoError:
        var body = Span(self._scratch)
        if len(body) < 4:
            raise IoError.of_kind(E_AUTH, ErrorKind.InvalidData)
        var code = be_i32(body, 0)
        if code == AUTH_OK:
            if len(body) != 4:
                raise IoError.of_kind(E_AUTH, ErrorKind.InvalidData)
            if self._auth == _SENT_NOTHING:
                if not self._allow.allows(AuthMethods.TRUST):
                    raise IoError.of_kind(E_NOT_ALLOWED, ErrorKind.PermissionDenied)
            elif self._auth == _SENT_SASL_FIRST or self._auth == _SENT_SASL_FINAL:
                raise IoError.of_kind(E_SCRAM_INCOMPLETE, ErrorKind.InvalidData)
            self._scram.clear()  # (its keys are no longer needed)
            self._phase = _OPENING
            return
        if code == AUTH_SASL_CONTINUE:
            if self._auth != _SENT_SASL_FIRST:
                raise IoError.of_kind(E_UNEXPECTED, ErrorKind.InvalidData)
            var final = self._scram[0].client_final(body[4:])
            write_sasl_response(self._tx, final.as_bytes())
            self._auth = _SENT_SASL_FINAL
            return
        if code == AUTH_SASL_FINAL:
            if self._auth != _SENT_SASL_FINAL:
                raise IoError.of_kind(E_UNEXPECTED, ErrorKind.InvalidData)
            self._scram[0].verify(body[4:])
            self._auth = _SASL_DONE
            return
        if self._auth != _SENT_NOTHING:
            raise IoError.of_kind(E_AUTH_AGAIN, ErrorKind.InvalidData)
        if code == AUTH_CLEARTEXT_PASSWORD:
            if len(body) != 4:
                raise IoError.of_kind(E_AUTH, ErrorKind.InvalidData)
            self._require(AuthMethods.PASSWORD)
            write_password(self._tx, self._password)
            self._auth = _SENT_PASSWORD
        elif code == AUTH_MD5_PASSWORD:
            if len(body) != 8:
                raise IoError.of_kind(E_AUTH, ErrorKind.InvalidData)
            self._require(AuthMethods.MD5)
            write_password(self._tx, md5_password(self._user, self._password, body[4:8]))
            self._auth = _SENT_PASSWORD
        elif code == AUTH_SASL:
            if not _offers_scram(body):
                raise IoError.of_kind(E_NO_SCRAM, ErrorKind.Unsupported)
            self._require(AuthMethods.SCRAM_SHA_256)
            var scram = ScramClient(self._password, self._nonce)
            write_sasl_initial_response(self._tx, SCRAM_SHA_256, scram.client_first().as_bytes())
            self._scram.append(scram^)
            self._auth = _SENT_SASL_FIRST
        elif (
            code == AUTH_KERBEROS_V5
            or code == AUTH_GSS
            or code == AUTH_GSS_CONTINUE
            or code == AUTH_SSPI
            or code == 6  # SCM credentials (before PostgreSQL 9.1)
        ):
            raise IoError.of_kind(E_AUTH_UNSUPPORTED, ErrorKind.Unsupported)
        else:
            raise IoError.of_kind(E_AUTH, ErrorKind.InvalidData)
