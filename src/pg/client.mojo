"""A blocking PostgreSQL client: one session over TCP or a Unix-domain
socket, driving `PgConnection` with a deadline per operation. This is the
only `pg` module that does I/O (`net`); not re-exported from `pg`.

    var db = Client.connect(Config("app", database="shop", password=pw))
    var r = db.query("SELECT id, name FROM users WHERE id > $1 ORDER BY id", 10)
    for i in range(len(r)):
        print(r.text(i, 0), r.text(i, 1))
    _ = db.execute("UPDATE users SET seen = now() WHERE id = $1", 1)
    db^.close()

`query` and `execute` run one statement through the extended protocol,
with its parameters sent as values, so they are never spliced into the
SQL. Each `Writable` argument goes in its text form, and the server reads
it as the type the statement needs; `query_params` takes a `Params` for
NULLs, bytes or declared types. `simple_query` runs scripts of several
statements, without parameters. Results come in text form (`Rows.text`,
`Rows.int`, `Rows.bool`, `Rows.value` for the bytes).

A server error raises `PgError` with the SQLSTATE (`e.code()`) and leaves
the session usable; so does a query cancelled at its deadline.

Deadlines:
- `Config.connect_timeout` bounds `connect`: name resolution, the
  connection, startup and authentication.
- A query's `timeout` bounds it. When it passes, the client sends a
  CancelRequest on a new connection and waits for the server to close
  that connection, as libpq does, so a late cancel cannot hit the next
  query. It then gives the server `CANCEL_GRACE` to end the query's
  cycle. A query that still finished is returned. Otherwise the client
  raises a deadline error (`e.is_deadline()`), with the server's 57014
  error attached when it sent one. If the server does not answer in time,
  the client closes the connection: the next call raises `Closed`.

Anything else that goes wrong closes the connection: a transport error,
the server breaking the protocol, or a FATAL error such as an
administrator's shutdown (57P01).
"""

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError
from linux.random import fill_random
from linux.time import Deadline, Duration
from net.addr import UnixAddr
from net.blocking import recv_with_deadline, send_all_with_deadline
from net.socket import Shutdown, Socket
from net.tcp import TcpStream
from net.unix import UnixStream

from .config import Config
from .connection import EventKind, PgConnection, PgEvent
from .message import BackendKey, Column, Notification, Params, ServerMessage, rows_affected, write_cancel_request

comptime CANCEL_GRACE = Duration.from_secs(5)
"""How long the server gets to end a cancelled query's cycle."""

comptime _RECEIVE = 64 * 1024


struct PgError(Copyable, Movable, Writable):
    """Why a call failed.
    - **The server's error:** `is_server()` is true. `server()` has every
      field, `code()` the SQLSTATE. A cancelled query is one too (57014),
      with `is_deadline()` also true.
    - **Otherwise**, `io` says what failed: the transport, the protocol
      (`InvalidData`), authentication (`PermissionDenied`, `Unsupported`,
      `InvalidInput`), or the deadline (`is_deadline()`)."""

    var io: IoError
    var _server: List[ServerMessage]
    """The server's ErrorResponse, if it sent one (at most one)."""

    def __init__(out self, io: IoError):
        self.io = io
        self._server = List[ServerMessage]()

    def __init__(out self, io: IoError, var server: ServerMessage):
        self.io = io
        self._server = [server^]

    def is_server(self) -> Bool:
        return len(self._server) > 0

    def server(self) -> ServerMessage:
        """The server's error; an empty one when `is_server()` is false."""
        if len(self._server) == 0:
            return ServerMessage(List[UInt8](length=1, fill=0))
        return self._server[0].copy()

    def code(self) -> String:
        """The SQLSTATE of the server's error, or "" when there is none."""
        if len(self._server) == 0:
            return ""
        return self._server[0].code()

    def is_deadline(self) -> Bool:
        """Whether the call's deadline passed (the query was cancelled, or
        the session could not open in time)."""
        return self.io.is_deadline()

    def write_to(self, mut writer: Some[Writer]):
        if len(self._server) > 0:
            writer.write(self._server[0])
            if self.io.is_deadline():
                writer.write(" (deadline)")
        else:
            writer.write(self.io)


comptime _SERVER_ERROR = "pg: the server reported an error"
comptime _CLOSED_BY_SERVER = "pg: the server closed the connection"


struct Rows(Movable, Sized):
    """The result of one statement: its columns, its rows (values in text
    form, unless the column is binary), and its command tag."""

    var columns: List[Column]
    var tag: String
    """The CommandComplete tag, such as "SELECT 3" or "INSERT 0 1"."""
    var _data: List[UInt8]
    """Every row's DataRow body, one after the other."""
    var _at: List[Int]
    """Per value: its start in `_data` and its length (-1: NULL)."""
    var _width: Int

    def __init__(out self):
        self.columns = List[Column]()
        self.tag = String()
        self._data = List[UInt8]()
        self._at = List[Int]()
        self._width = 0

    def __len__(self) -> Int:
        """How many rows."""
        if self._width == 0:
            return 0
        return len(self._at) // (2 * self._width)

    def width(self) -> Int:
        """How many values per row."""
        return self._width

    def _describe(mut self, ev: PgEvent):
        self.columns = ev.columns()
        self._width = len(self.columns)

    def _complete(mut self, ev: PgEvent):
        self.tag = ev.tag()

    def _add(mut self, ev: PgEvent):
        var base = len(self._data)
        self._data.extend(Span(ev.data))
        for i in range(ev.values()):
            self._at.append(base + ev._at[2 * i])
            self._at.append(ev._at[2 * i + 1])

    def is_null(self, row: Int, col: Int) -> Bool:
        return self._at[2 * (row * self._width + col) + 1] < 0

    def value(self, row: Int, col: Int) -> Span[UInt8, origin_of(self._data)]:
        """The bytes of a value (empty for NULL)."""
        var k = 2 * (row * self._width + col)
        var start = self._at[k]
        return Span(self._data)[start : start + max(self._at[k + 1], 0)]

    def text(self, row: Int, col: Int) -> String:
        """A value as text ("" for NULL)."""
        return String(from_utf8_lossy=self.value(row, col))

    def int(self, row: Int, col: Int) raises IoError -> Int:
        """A value of an integer column. `InvalidData` for NULL or a value
        that is no decimal integer."""
        var b = self.value(row, col)
        if self.is_null(row, col) or len(b) == 0 or len(b) > 20:
            raise IoError.of_kind("pg: not an integer value", ErrorKind.InvalidData)
        var neg = Int(b[0]) == ord("-")
        var i = 1 if neg else 0
        if i == len(b):
            raise IoError.of_kind("pg: not an integer value", ErrorKind.InvalidData)
        var n = 0
        while i < len(b):
            var c = b[i]
            if c < 48 or c > 57 or n > (Int.MAX - 9) // 10:
                raise IoError.of_kind("pg: not an integer value", ErrorKind.InvalidData)
            n = n * 10 + Int(c) - 48
            i += 1
        return -n if neg else n

    def bool(self, row: Int, col: Int) raises IoError -> Bool:
        """A value of a boolean column ("t" or "f" in text form)."""
        var b = self.value(row, col)
        if self.is_null(row, col) or len(b) != 1 or (Int(b[0]) != ord("t") and Int(b[0]) != ord("f")):
            raise IoError.of_kind("pg: not a boolean value", ErrorKind.InvalidData)
        return Int(b[0]) == ord("t")

    def rows_affected(self) -> Optional[Int]:
        """The row count in the command tag, if it has one."""
        return rows_affected(self.tag)


struct Client(Movable):
    """One session (see the module docs). Not for use by several threads
    at once."""

    var _sock: Socket
    var _conn: PgConnection
    var _ev: PgEvent
    var _rx: List[UInt8]
    var _tx: ByteBuffer
    var _config: Config
    var _usable: Bool
    var _notices: List[ServerMessage]
    var _notifications: List[Notification]

    def __init__(out self, var sock: Socket, var conn: PgConnection, config: Config):
        self._sock = sock^
        self._conn = conn^
        self._ev = PgEvent()
        self._rx = List[UInt8](length=_RECEIVE, fill=0)
        self._tx = ByteBuffer()
        self._config = config.copy()
        self._usable = True
        self._notices = List[ServerMessage]()
        self._notifications = List[Notification]()

    @staticmethod
    def connect(config: Config) raises PgError -> Client:
        """Open a session: connect, authenticate, and wait until the server
        is ready, all within `config.connect_timeout`. The server's error
        (a wrong password: 28P01, no such database: 3D000) raises with its
        SQLSTATE."""
        var deadline = _deadline(config.connect_timeout)
        var nonce = List[UInt8](length=18, fill=0)
        var c: Client
        try:
            fill_random(Span(nonce))
            var conn = PgConnection(config.startup(), Span(nonce))
            c = Client(_dial(config, deadline), conn^, config)
        except e:
            raise PgError(e)
        c._open(deadline)
        return c^

    def _open(mut self, deadline: Deadline) raises PgError:
        """Run startup and authentication until the first READY."""
        while True:
            var got: Bool
            try:
                got = self._next(deadline)
            except e:
                raise PgError(e)
            if not got:
                raise PgError(IoError.of_kind(_CLOSED_BY_SERVER, ErrorKind.UnexpectedEof))
            if self._ev.kind == EventKind.READY:
                return
            if self._ev.kind == EventKind.ERROR:
                raise PgError(IoError.of_kind(_SERVER_ERROR, ErrorKind.Other), self._ev.server_message())
            self._other()

    # ---- I/O ------------------------------------------------------------------

    def _flush(mut self, deadline: Deadline) raises IoError:
        while self._conn.poll_transmit(self._tx) > 0:
            send_all_with_deadline(self._sock, self._tx.readable_span(), deadline, "pg: send")
            self._tx.clear()

    def _next(mut self, deadline: Deadline) raises IoError -> Bool:
        """The next event into `_ev`; False when the session ended cleanly
        (after a FATAL error or Terminate)."""
        while True:
            if self._conn.poll(self._ev):
                return True
            self._flush(deadline)  # (answers to authentication, CopyFail)
            var room = min(len(self._rx), self._conn.feed_capacity())
            var n = recv_with_deadline(self._sock, Span(self._rx)[:room], 0, deadline, "pg: receive")
            if n == 0:
                self._conn.feed_eof()
                return self._conn.poll(self._ev)
            self._conn.feed(Span(self._rx)[:n])

    def _other(mut self):
        """Keep the event, a notice or a notification, for the caller."""
        if self._ev.kind == EventKind.NOTICE:
            self._notices.append(self._ev.server_message())
        elif self._ev.kind == EventKind.NOTIFICATION:
            self._notifications.append(self._ev.notification())

    def _collect(
        mut self, deadline: Deadline, mut current: Rows, mut results: List[Rows], mut error: List[ServerMessage]
    ) raises IoError:
        """Gather a query's results until its READY. An error is kept in
        `error`; a FATAL one, which ends the session, raises
        `ConnectionAborted`. `current` is the statement under way, kept
        across a deadline so its rows are not lost."""
        while True:
            if not self._next(deadline):
                raise IoError.of_kind(_CLOSED_BY_SERVER, ErrorKind.UnexpectedEof)
            var kind = self._ev.kind
            if kind == EventKind.DATA_ROW:
                current._add(self._ev)
            elif kind == EventKind.ROW_DESCRIPTION:
                current._describe(self._ev)
            elif kind == EventKind.COMMAND_COMPLETE:
                current._complete(self._ev)
                results.append(current^)
                current = Rows()
            elif kind == EventKind.EMPTY_QUERY:
                results.append(current^)
                current = Rows()
            elif kind == EventKind.ERROR:
                error.append(self._ev.server_message())
                if not self._conn.is_open():
                    raise IoError.of_kind(_CLOSED_BY_SERVER, ErrorKind.ConnectionAborted)
            elif kind == EventKind.READY:
                return
            else:
                self._other()

    # ---- queries --------------------------------------------------------------

    def query[*Ts: Writable](
        mut self, sql: StringSlice, *args: *Ts, timeout: Duration = Duration.ZERO
    ) raises PgError -> Rows:
        """Run one statement with `$1`, `$2`, ... bound to `args`, and return
        its rows. Each argument goes in its text form, and the server reads
        it as the type the statement needs, so values are never spliced into
        the SQL. For NULLs, bytes or declared types, fill a `Params` and call
        `query_params`. `timeout`: `Duration.ZERO` for none."""
        var params = Params()
        comptime for i in range(args.__len__()):
            params.add(args[i])
        return self.query_params(sql, params, timeout)

    def execute[*Ts: Writable](
        mut self, sql: StringSlice, *args: *Ts, timeout: Duration = Duration.ZERO
    ) raises PgError -> Int:
        """`query`, returning the number of rows the statement affected (0
        when its tag has no count)."""
        var params = Params()
        comptime for i in range(args.__len__()):
            params.add(args[i])
        return self.query_params(sql, params, timeout).rows_affected().or_else(0)

    def query_params(mut self, sql: StringSlice, params: Params, timeout: Duration = Duration.ZERO) raises PgError -> Rows:
        """Run one statement with `params`, through the extended protocol and
        the unnamed statement: one round trip."""
        self._check_usable()
        try:
            self._conn.execute(sql, params)
        except e:
            raise PgError(e)  # (InvalidInput: the session is unharmed)
        var all = self._results(timeout)
        if len(all) == 0:
            return Rows()
        return all.pop()

    def simple_query(mut self, sql: StringSlice, timeout: Duration = Duration.ZERO) raises PgError -> List[Rows]:
        """Run one or more statements, separated by semicolons, through the
        simple protocol, and return each one's result. No parameters: this
        is for scripts (migrations, several DDL statements). A failing
        statement ends the rest and raises with the server's error."""
        self._check_usable()
        try:
            self._conn.query(sql)
        except e:
            raise PgError(e)  # (a NUL in `sql`: the session is unharmed)
        return self._results(timeout)

    def _check_usable(self) raises PgError:
        if not self.is_usable():
            raise PgError(IoError.of_kind("pg: the connection is closed", ErrorKind.Closed))

    def _results(mut self, timeout: Duration) raises PgError -> List[Rows]:
        """Send what is queued and gather the results until READY."""
        var deadline = _deadline(timeout)
        var current = Rows()
        var results = List[Rows]()
        var error = List[ServerMessage]()
        var sent = False
        try:
            self._flush(deadline)
            sent = True
            self._collect(deadline, current, results, error)
        except e:
            if e.is_deadline() and sent:
                return self._cancelled(e, current, results^, error^)
            self._close_now()
            if len(error) > 0:  # (FATAL)
                raise PgError(e, error[0].copy())
            raise PgError(e)
        if len(error) > 0:
            raise PgError(IoError.of_kind(_SERVER_ERROR, ErrorKind.Other), error[0].copy())
        return results^

    def _cancelled(
        mut self, e: IoError, mut current: Rows, var results: List[Rows], var error: List[ServerMessage]
    ) raises PgError -> List[Rows]:
        """The query's deadline passed after it was sent: cancel it, give the
        server `CANCEL_GRACE` to end its cycle, and report."""
        try:
            self.cancel()
        except:
            pass  # (no cancel: the grace below decides)
        try:
            self._collect(Deadline.after(CANCEL_GRACE), current, results, error)
        except:
            self._close_now()
            if len(error) > 0:
                raise PgError(e, error[0].copy())
            raise PgError(e)
        if len(error) > 0:
            raise PgError(e, error[0].copy())
        return results^  # it finished after all

    # ---- the session ------------------------------------------------------------

    def cancel(self) raises PgError:
        """Ask the server to cancel what this session is running, on a new
        connection, and wait until the server has taken the request (it
        closes that connection). Harmless if nothing runs."""
        var key = self._conn.backend_key()
        if not key:
            raise PgError(IoError.of_kind("pg: the server sent no cancellation key", ErrorKind.Unsupported))
        var deadline = Deadline.after(CANCEL_GRACE)
        try:
            var sock = _dial(self._config, deadline)
            var out = ByteBuffer()
            write_cancel_request(out, key.value())
            send_all_with_deadline(sock, out.readable_span(), deadline, "pg: cancel")
            var buf = List[UInt8](length=64, fill=0)
            while recv_with_deadline(sock, Span(buf), 0, deadline, "pg: cancel") > 0:
                pass
        except e:
            raise PgError(e)

    def parameter(self, name: StringSlice) -> Optional[String]:
        """What the server reported for a parameter ("server_version",
        "TimeZone", ...)."""
        return self._conn.parameter(name)

    def transaction_status(self) -> UInt8:
        """`IDLE`, `IN_TRANSACTION` or `FAILED_TRANSACTION` (`pg.message`)."""
        return self._conn.transaction_status()

    def backend_key(self) -> Optional[BackendKey]:
        return self._conn.backend_key()

    def is_usable(self) -> Bool:
        """Whether the session can take a query: open, not failed."""
        return self._usable and self._conn.is_idle()

    def take_notices(mut self) -> List[ServerMessage]:
        """The notices and warnings received since the last call."""
        var out = self._notices.copy()
        self._notices.clear()
        return out^

    def take_notifications(mut self) -> List[Notification]:
        """The notifications received since the last call (LISTEN)."""
        var out = self._notifications.copy()
        self._notifications.clear()
        return out^

    def _close_now(mut self):
        """End the connection; the socket closes with the `Client`."""
        self._usable = False
        try:
            self._sock.shutdown(Shutdown.BOTH)
        except:
            pass

    def close(var self):
        """End the session (Terminate) and close the connection."""
        if self._usable:
            try:
                self._conn.terminate()
                self._flush(Deadline.after(Duration.from_secs(1)))
            except:
                pass
        self._close_now()


def _deadline(timeout: Duration) -> Deadline:
    if timeout == Duration.ZERO:
        return Deadline.none()
    return Deadline.after(timeout)


def _dial(config: Config, deadline: Deadline) raises IoError -> Socket:
    """A connected socket to the server: its Unix socket for a directory
    `host`, else TCP (by name, Happy Eyeballs)."""
    if config.is_unix():
        var addr = UnixAddr.from_pathname(config.socket_path())
        return UnixStream.connect_deadline(addr, deadline).into_socket()
    if config.port < 1 or config.port > 65535:
        raise IoError.of_kind("pg: invalid port", ErrorKind.InvalidInput)
    return TcpStream.connect_host_deadline(config.host, UInt16(config.port), deadline).into_socket()
