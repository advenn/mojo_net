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
statements, without parameters.

Results: with the statement cache (`Config.statement_cache`), the types
`pg.types` reads in binary form (integers, bool, bytea, uuid, date,
timestamp, ...) come that way, and the rest in text form; without it, or
through `simple_query`, all in text form. `Rows.text` gives the server's
text either way, and the typed accessors (`int`, `float`, `bool`, `bytes`,
`date`, `timestamp`) read both.

The session is opened with the settings these forms rely on: DateStyle
ISO, extra_float_digits 3 (floats keep every bit) and bytea_output hex
(`Config.startup`). A role or server default cannot change them, and a
session switched to another client_encoding is ended (`Unsupported`).

A server error raises `PgError` with the SQLSTATE (`e.code()`) and leaves
the session usable; so does a query cancelled at its deadline.

Deadlines:
- `Config.connect_timeout` bounds `connect`: name resolution, the
  connection, startup and authentication.
- A query's `timeout` bounds it, rows still coming included. When it
  passes, the client sends a CancelRequest on a new connection, to the
  address the session is connected to, and waits for the server to close
  that connection, as libpq does, so a late cancel cannot hit the next
  query. The server gets `CANCEL_GRACE`, the cancel included, to end the
  query's cycle. A query that still finished is returned. Otherwise the
  client raises a deadline error (`e.is_deadline()`), with the server's
  57014 error attached when it sent one. If the server does not answer in
  time, or a cancel went out but was not seen through, the client closes
  the connection: the next call raises `Closed`.

Anything else that goes wrong closes the connection: a transport error,
the server breaking the protocol, or a FATAL error such as an
administrator's shutdown (57P01).
"""

from std.collections import Dict
from std.math import isinf
from std.memory import bitcast

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError
from linux.random import fill_random
from linux.time import Deadline, Duration
from net.addr import SocketAddr, UnixAddr
from net.blocking import (
    DEAD_PEER_KEEPALIVE,
    IdleState,
    detect_dead_peers,
    idle_state,
    recv_with_deadline,
    send_all_with_deadline,
    try_recv,
)
from net.socket import Shutdown, Socket
from net.tcp import TcpStream
from net.unix import UnixStream

from .config import Config
from .connection import EventKind, PgConnection, PgEvent
from .message import (
    BINARY,
    FIELD_ROUTINE,
    be_u32,
    IDLE,
    TEXT,
    BackendKey,
    Column,
    Notification,
    Params,
    ServerMessage,
    rows_affected,
    write_cancel_request,
)
from .types import (
    BOOL,
    BYTEA,
    DATE,
    FLOAT4,
    FLOAT8,
    TIMESTAMP,
    Date,
    binary_date,
    binary_int,
    binary_timestamp_us,
    is_text_like,
    parse_bytea,
    parse_date,
    parse_timestamp_us,
    wants_binary,
    write_binary_as_text,
)

comptime CANCEL_GRACE = Duration.from_secs(5)
"""How long the server gets to end a cancelled query's cycle."""

comptime MAX_NOTICES = 1024
"""Notices kept until `take_notices`; past it, the oldest are dropped."""

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
comptime E_ROLLED_BACK = "pg: the transaction had failed: COMMIT rolled it back"
comptime E_IN_TRANSACTION = "pg: a transaction is already open"
comptime _CLOSED_BY_SERVER = "pg: the server closed the connection"


struct Rows(Movable, Sized):
    """The result of one statement: its columns, its rows, and its command
    tag. Each column's values come in the form `columns[c].format` says:
    binary for the types `pg.types` reads that way (when the statement
    cache asked for them), text otherwise. The typed accessors read either
    form; `value` gives the bytes as they came. A row or column out of
    range raises `InvalidInput`."""

    var columns: List[Column]
    var tag: String
    """The CommandComplete tag, such as "SELECT 3" or "INSERT 0 1"."""
    var _data: List[UInt8]
    """Every row's DataRow body, one after the other."""
    var _at: List[Int]
    """Per value: its start in `_data` and its length (-1: NULL)."""
    var _width: Int
    var _rows: Int
    """(Counted apart: a statement can return rows with no columns.)"""

    def __init__(out self):
        self.columns = List[Column]()
        self.tag = String()
        self._data = List[UInt8]()
        self._at = List[Int]()
        self._width = 0
        self._rows = 0

    def __len__(self) -> Int:
        """How many rows."""
        return self._rows

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
        self._rows += 1

    def _index(self, row: Int, col: Int) raises IoError -> Int:
        """Where value (`row`, `col`) is in `_at`, both checked."""
        if row < 0 or row >= self._rows or col < 0 or col >= self._width:
            raise IoError.of_kind("pg: row or column out of range", ErrorKind.InvalidInput)
        return 2 * (row * self._width + col)

    def _span(self, k: Int) -> Span[UInt8, origin_of(self._data)]:
        var start = self._at[k]
        return Span(self._data)[start : start + max(self._at[k + 1], 0)]

    def is_null(self, row: Int, col: Int) raises PgError -> Bool:
        try:
            return self._at[self._index(row, col) + 1] < 0
        except e:
            raise PgError(e)

    def value(self, row: Int, col: Int) raises PgError -> Span[UInt8, origin_of(self._data)]:
        """The bytes of a value as they came, in the column's form (empty
        for NULL)."""
        try:
            return self._span(self._index(row, col))
        except e:
            raise PgError(e)

    def _binary(self, col: Int) -> Bool:
        """Whether the column's values need binary decoding (a text-like
        type's binary form is its text)."""
        return self.columns[col].format == BINARY and not is_text_like(self.columns[col].type_oid)

    def _present(self, row: Int, col: Int, what: StaticString) raises IoError -> Int:
        """The value's index, checked, and not NULL."""
        var k = self._index(row, col)
        if self._at[k + 1] < 0:
            raise IoError.of_kind(what, ErrorKind.InvalidData)
        return k

    def _text(self, row: Int, col: Int) raises IoError -> String:
        var k = self._index(row, col)
        if self._at[k + 1] < 0:
            return String()
        var v = self._span(k)
        if self._binary(col):
            var out = String()
            write_binary_as_text(out, self.columns[col].type_oid, v)
            return out^
        return String(from_utf8_lossy=v)

    def _int(self, row: Int, col: Int) raises IoError -> Int:
        comptime op = "pg: not an integer value"
        var b = self._span(self._present(row, col, op))
        var oid = self.columns[col].type_oid
        if self._binary(col):
            return binary_int(oid, b)
        if oid == FLOAT4 or oid == FLOAT8:  # (a float is no integer, whatever its value)
            raise IoError.of_kind(op, ErrorKind.InvalidData)
        return _decimal(b, op)

    def _float(self, row: Int, col: Int) raises IoError -> Float64:
        comptime op = "pg: not a number"
        var b = self._span(self._present(row, col, op))
        var oid = self.columns[col].type_oid
        if self._binary(col):
            if oid == FLOAT8 and len(b) == 8:
                return bitcast[DType.float64]((UInt64(be_u32(b, 0)) << 32) | UInt64(be_u32(b, 4)))
            if oid == FLOAT4 and len(b) == 4:
                return Float64(bitcast[DType.float32](be_u32(b, 0)))
            return Float64(binary_int(oid, b))  # (the integer types; others raise)
        var t = String(from_utf8_lossy=b)
        var x: Float64
        try:
            x = atof(t)  # (NaN and the infinities too)
        except:
            raise IoError.of_kind(op, ErrorKind.InvalidData)
        if oid == FLOAT4:
            x = Float64(Float32(x))  # (the text is the shortest that reads back as this float4)
        if (isinf(x) or x == 0) and _nonzero_mantissa(b):  # (a numeric past a float's range)
            raise IoError.of_kind("pg: number out of range for a float", ErrorKind.InvalidData)
        return x

    def _bool(self, row: Int, col: Int) raises IoError -> Bool:
        comptime op = "pg: not a boolean value"
        var b = self._span(self._present(row, col, op))
        if self._binary(col):
            if self.columns[col].type_oid != BOOL or len(b) != 1:
                raise IoError.of_kind(op, ErrorKind.InvalidData)
            return b[0] != 0
        if len(b) != 1 or (Int(b[0]) != ord("t") and Int(b[0]) != ord("f")):
            raise IoError.of_kind(op, ErrorKind.InvalidData)
        return Int(b[0]) == ord("t")

    def _bytes(self, row: Int, col: Int) raises IoError -> List[UInt8]:
        comptime op = "pg: not a bytea value"
        var b = self._span(self._present(row, col, op))
        if self._binary(col):
            if self.columns[col].type_oid != BYTEA:
                raise IoError.of_kind(op, ErrorKind.InvalidData)
            return List[UInt8](b)
        return parse_bytea(b)

    def _date(self, row: Int, col: Int) raises IoError -> Date:
        comptime op = "pg: not a date value"
        var b = self._span(self._present(row, col, op))
        if self._binary(col):
            if self.columns[col].type_oid != DATE:
                raise IoError.of_kind(op, ErrorKind.InvalidData)
            return binary_date(b)
        return parse_date(b)

    def _timestamp(self, row: Int, col: Int) raises IoError -> Int:
        comptime op = "pg: not a timestamp value"
        var b = self._span(self._present(row, col, op))
        if self._binary(col):
            if self.columns[col].type_oid != TIMESTAMP:
                raise IoError.of_kind(op, ErrorKind.InvalidData)
            return binary_timestamp_us(b)
        return parse_timestamp_us(b)

    def text(self, row: Int, col: Int) raises PgError -> String:
        """A value in the server's text form ("" for NULL), whichever form
        it came in (`pg.types`)."""
        try:
            return self._text(row, col)
        except e:
            raise PgError(e)

    def int(self, row: Int, col: Int) raises PgError -> Int:
        """A value of an integer column, or of a numeric or text column
        holding a decimal integer. `InvalidData` for NULL, a float column,
        or anything else."""
        try:
            return self._int(row, col)
        except e:
            raise PgError(e)

    def float(self, row: Int, col: Int) raises PgError -> Float64:
        """A value of a float, integer or numeric column (or any number in
        text form), "NaN" and the infinities included. A numeric beyond a
        float's range raises, as the server's own cast does."""
        try:
            return self._float(row, col)
        except e:
            raise PgError(e)

    def bool(self, row: Int, col: Int) raises PgError -> Bool:
        """A value of a boolean column ("t" or "f" in text form)."""
        try:
            return self._bool(row, col)
        except e:
            raise PgError(e)

    def bytes(self, row: Int, col: Int) raises PgError -> List[UInt8]:
        """A bytea value's bytes."""
        try:
            return self._bytes(row, col)
        except e:
            raise PgError(e)

    def date(self, row: Int, col: Int) raises PgError -> Date:
        """A date value."""
        try:
            return self._date(row, col)
        except e:
            raise PgError(e)

    def timestamp(self, row: Int, col: Int) raises PgError -> Int:
        """A timestamp or timestamptz value, as microseconds since
        1970-01-01 00:00:00: UTC for timestamptz, the wall-clock time taken
        as UTC for a timestamp without a time zone. `Int.MAX` and `Int.MIN`
        stand for 'infinity' and '-infinity'."""
        try:
            return self._timestamp(row, col)
        except e:
            raise PgError(e)

    def rows_affected(self) -> Optional[Int]:
        """The row count in the command tag, if it has one."""
        return rows_affected(self.tag)


@fieldwise_init
struct _Statement(Copyable, Movable):
    """A statement the client prepared (an empty name: a free slot)."""

    var name: String
    var key: String
    """Its key in `_by_sql`: the SQL, and the parameter types declared."""
    var formats: List[Int]
    """Per result column: `BINARY` where `pg.types` reads that form."""
    var used: Int
    """When it was last used, for evicting the least recently used."""


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
    var _statements: List[_Statement]
    var _by_sql: Dict[String, Int]
    """The slot in `_statements` of each prepared SQL text (with its
    declared parameter types, when it has any: `_cache_key`)."""
    var _clock: Int
    var _named: Int
    var _prefix: String
    """Of this session's statement names: "mojo_", then random hex, so that
    they meet no statement prepared already (`PREPARE`, a pooler's)."""
    var _cancel_to: Optional[SocketAddr]
    """Where cancels go: the address the session is connected to (None
    for a Unix socket, whose path is used)."""

    def __init__(
        out self,
        var sock: Socket,
        var conn: PgConnection,
        config: Config,
        cancel_to: Optional[SocketAddr],
        prefix: String,
    ):
        self._sock = sock^
        self._conn = conn^
        self._ev = PgEvent()
        self._rx = List[UInt8](length=_RECEIVE, fill=0)
        self._tx = ByteBuffer()
        self._config = config.copy()
        self._usable = True
        self._notices = List[ServerMessage]()
        self._notifications = List[Notification]()
        self._statements = List[_Statement]()
        self._by_sql = Dict[String, Int]()
        self._clock = 0
        self._named = 0
        self._prefix = prefix
        self._cancel_to = cancel_to

    @staticmethod
    def connect(config: Config) raises PgError -> Client:
        """Open a session: connect, authenticate, and wait until the server
        is ready, all within `config.connect_timeout`. The server's error
        (a wrong password: 28P01, no such database: 3D000) raises with its
        SQLSTATE."""
        var deadline = _deadline(config.connect_timeout)
        var random = List[UInt8](length=18 + 4, fill=0)  # (the SCRAM nonce, the names)
        var c: Client
        try:
            fill_random(Span(random))
            var conn = PgConnection(config.startup(), Span(random)[:18])
            var sock = _dial(config, deadline)
            var cancel_to = Optional[SocketAddr](None)
            if not config.is_unix():
                cancel_to = sock.peer_addr()  # (not the name resolved again: maybe another server)
                if config.keepalive:
                    detect_dead_peers(sock, DEAD_PEER_KEEPALIVE)
            c = Client(sock^, conn^, config, cancel_to, _name_prefix(Span(random)[18:]))
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
            if deadline.is_expired():  # (rows that keep coming never make recv wait)
                raise IoError.of_kind("pg: receive", ErrorKind.TimedOut)
            var room = min(len(self._rx), self._conn.feed_capacity())
            var n = recv_with_deadline(self._sock, Span(self._rx)[:room], 0, deadline, "pg: receive")
            if n == 0:
                self._conn.feed_eof()
                return self._conn.poll(self._ev)
            self._conn.feed(Span(self._rx)[:n])

    def _other(mut self):
        """Keep the event, a notice or a notification, for the caller."""
        if self._ev.kind == EventKind.NOTICE:
            if len(self._notices) >= MAX_NOTICES:
                _ = self._notices.pop(0)
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
                if current.tag == "DISCARD ALL" or current.tag == "DEALLOCATE ALL":
                    self._drop_cache()  # (the server dropped every prepared statement)
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
        """Run one statement with `params` through the extended protocol.

        With the statement cache (`Config.statement_cache`), the first run
        of a SQL text prepares it, which costs a round trip and tells the
        column types. Then every run binds the prepared statement and asks
        for binary results where `pg.types` reads them. Without the cache,
        each run uses the unnamed statement with text results: one round
        trip, as poolers that cannot keep statements need."""
        self._check_usable()
        var deadline = _deadline(timeout)
        if self._config.statement_cache <= 0:
            try:
                self._conn.execute(sql, params)
            except e:
                raise PgError(e)  # (InvalidInput: the session is unharmed)
            var current = Rows()
            return _last(self._cycle(deadline, current))
        var slot = self._statement(sql, params, deadline)
        try:
            return self._run(slot, params, deadline)
        except e:
            # The cached statement went stale, and nothing ran: the server
            # dropped it (26000: a DEALLOCATE behind the cache's back), or
            # the result type changed under its plan (0A000 from
            # RevalidateCachedQuery: DDL). Outside a transaction, prepare
            # it afresh and run once more.
            var code = e.code()
            var stale = code == "26000" or (
                code == "0A000" and e.server().field(FIELD_ROUTINE).or_else("") == "RevalidateCachedQuery"
            )
            if not stale or self.transaction_status() != IDLE or not self.is_usable():
                raise e.copy()
        self._forget(slot, deadline)
        slot = self._statement(sql, params, deadline)
        return self._run(slot, params, deadline)

    def _run(mut self, slot: Int, params: Params, deadline: Deadline) raises PgError -> Rows:
        try:
            self._conn.execute_prepared(self._statements[slot].name, params, Span(self._statements[slot].formats))
        except e:
            raise PgError(e)
        var current = Rows()
        return _last(self._cycle(deadline, current))

    def _statement(mut self, sql: StringSlice, params: Params, deadline: Deadline) raises PgError -> Int:
        """The slot of `sql`'s prepared statement for the types `params`
        declares, prepared now if it is not cached (a round trip; the
        server's error, a syntax error say, is raised and nothing is
        cached)."""
        var declared = _declares_types(params)
        var key = _cache_key(sql, params, declared)
        self._clock += 1
        var found = self._by_sql.get(key)
        if found:
            self._statements[found.value()].used = self._clock
            return found.value()
        self._named += 1
        var name = String(self._prefix, self._named)
        try:
            if declared:
                self._conn.prepare(name, sql, params)
            else:  # (each type left to the server, whatever the count)
                self._conn.prepare(name, sql, Params())
        except e:
            raise PgError(e)
        var described = Rows()
        _ = self._cycle(deadline, described)
        var formats = List[Int](capacity=len(described.columns))
        for i in range(len(described.columns)):
            formats.append(BINARY if wants_binary(described.columns[i].type_oid) else TEXT)
        if len(self._by_sql) >= self._config.statement_cache:
            # (only now: a statement the server refused evicts nothing)
            var oldest = -1
            for i in range(len(self._statements)):
                if self._statements[i].name.byte_length() > 0 and (
                    oldest < 0 or self._statements[i].used < self._statements[oldest].used
                ):
                    oldest = i
            self._forget(oldest, deadline)
        var slot = -1
        for i in range(len(self._statements)):
            if self._statements[i].name.byte_length() == 0:
                slot = i
                break
        if slot < 0:
            slot = len(self._statements)
            self._statements.append(_Statement(name, key, formats^, self._clock))
        else:
            self._statements[slot] = _Statement(name, key, formats^, self._clock)
        self._by_sql[key] = slot
        return slot

    def _forget(mut self, slot: Int, deadline: Deadline) raises PgError:
        """Drop a cached statement, and close it on the server (a round
        trip)."""
        var name = self._statements[slot].name
        try:
            _ = self._by_sql.pop(self._statements[slot].key)
        except:
            pass
        self._statements[slot].name = String()
        self._statements[slot].key = String()
        try:
            self._conn.close_statement(name)
        except e:
            raise PgError(e)
        var none = Rows()
        _ = self._cycle(deadline, none)

    def _drop_cache(mut self):
        """Forget every cached statement, which the server no longer has."""
        self._statements.clear()
        self._by_sql = Dict[String, Int]()

    def cached_statements(self) -> Int:
        """How many prepared statements the cache holds."""
        return len(self._by_sql)

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
        var current = Rows()
        return self._cycle(_deadline(timeout), current)

    def _check_usable(self) raises PgError:
        if not self.is_usable():
            raise PgError(IoError.of_kind("pg: the connection is closed", ErrorKind.Closed))

    def _cycle(mut self, deadline: Deadline, mut current: Rows) raises PgError -> List[Rows]:
        """Send what is queued and gather the results until READY. `current`
        is left with the last RowDescription that no CommandComplete closed
        (a prepared statement's columns)."""
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
        server until `CANCEL_GRACE` from now (the cancel included) to end
        its cycle, and report. A cancel that went out but was not seen
        through could still land, on whatever runs next: waiting for it
        spends the whole grace, so the session is closed below."""
        var grace = Deadline.after(CANCEL_GRACE)
        try:
            self._send_cancel(grace)
        except:
            pass  # (none sent, or not seen through: the grace decides)
        try:
            self._collect(grace, current, results, error)
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
        connection to the address the session is connected to, and wait
        until the server has taken the request: it closes that connection.
        Harmless if nothing runs. Raises when the request could not be
        sent, or was not seen through within `CANCEL_GRACE`."""
        try:
            self._send_cancel(Deadline.after(CANCEL_GRACE))
        except e:
            raise PgError(e)

    def _send_cancel(self, deadline: Deadline) raises IoError:
        """Send a CancelRequest and wait until the server closes that
        connection, or `deadline` passes (`TimedOut`: then the request may
        still land). A send that fails sent nothing: the server acts only
        on all 16 bytes."""
        var key = self._conn.backend_key()
        if not key:
            raise IoError.of_kind("pg: the server sent no cancellation key", ErrorKind.Unsupported)
        var sock: Socket
        if self._cancel_to:
            sock = TcpStream.connect_deadline(self._cancel_to.value(), deadline).into_socket()
        else:
            sock = _dial(self._config, deadline)  # (a Unix socket: its path)
        var out = ByteBuffer()
        write_cancel_request(out, key.value())
        send_all_with_deadline(sock, out.readable_span(), deadline, "pg: cancel")
        var buf = List[UInt8](length=64, fill=0)
        try:
            while recv_with_deadline(sock, Span(buf), 0, deadline, "pg: cancel") > 0:
                pass
        except e:
            if e.is_deadline():
                raise e
            # (a reset is an end too: the server is done with it, as libpq takes it)

    def parameter(self, name: StringSlice) -> Optional[String]:
        """What the server reported for a parameter ("server_version",
        "TimeZone", ...)."""
        return self._conn.parameter(name)

    def transaction_status(self) -> UInt8:
        """`IDLE`, `IN_TRANSACTION` or `FAILED_TRANSACTION` (`pg.message`)."""
        return self._conn.transaction_status()

    def backend_key(self) -> Optional[BackendKey]:
        return self._conn.backend_key()

    # ---- transactions ---------------------------------------------------------

    def begin(mut self, timeout: Duration = Duration.ZERO) raises PgError:
        """Open a transaction (BEGIN). `InvalidInput` when one is open."""
        self._check_usable()
        if self._conn.transaction_status() != IDLE:
            raise PgError(IoError.of_kind(E_IN_TRANSACTION, ErrorKind.InvalidInput))
        _ = self.simple_query("BEGIN", timeout)

    def commit(mut self, timeout: Duration = Duration.ZERO) raises PgError:
        """End the transaction and keep its work (COMMIT). A transaction
        that failed is rolled back by the server instead; then this raises
        (`E_ROLLED_BACK`), with the session idle again."""
        var r = self.simple_query("COMMIT", timeout)
        if len(r) > 0 and r[0].tag == "ROLLBACK":
            raise PgError(IoError.of_kind(E_ROLLED_BACK, ErrorKind.Other))

    def rollback(mut self, timeout: Duration = Duration.ZERO) raises PgError:
        """End the transaction and drop its work (ROLLBACK)."""
        _ = self.simple_query("ROLLBACK", timeout)

    def savepoint(mut self, name: StringSlice) raises PgError:
        """SAVEPOINT `name` (quoted as an identifier: any name is safe)."""
        _ = self.simple_query(String("SAVEPOINT ", quote_identifier(name)))

    def rollback_to(mut self, name: StringSlice) raises PgError:
        """ROLLBACK TO SAVEPOINT `name`: drop the work since it, and leave a
        failed transaction usable again."""
        _ = self.simple_query(String("ROLLBACK TO SAVEPOINT ", quote_identifier(name)))

    def release(mut self, name: StringSlice) raises PgError:
        """RELEASE SAVEPOINT `name`, keeping the work since it."""
        _ = self.simple_query(String("RELEASE SAVEPOINT ", quote_identifier(name)))

    # ---- notifications and health -------------------------------------------------

    def wait_notification(mut self, timeout: Duration) raises PgError -> Optional[Notification]:
        """The next notification on a channel this session LISTENs to: one
        received already (during a query, say), or the first to arrive
        within `timeout` (`Duration.ZERO`: no limit). None when none came:
        the session is unharmed, since no query was in flight."""
        if len(self._notifications) > 0:
            return self._notifications.pop(0)
        self._check_usable()
        var deadline = _deadline(timeout)
        while True:
            var got: Bool
            try:
                got = self._next(deadline)
            except e:
                if e.is_deadline():
                    return None
                self._close_now()
                raise PgError(e)
            if not got:
                self._close_now()
                raise PgError(IoError.of_kind(_CLOSED_BY_SERVER, ErrorKind.ConnectionAborted))
            if self._ev.kind == EventKind.NOTIFICATION:
                return self._ev.notification()
            if self._ev.kind == EventKind.ERROR:  # (FATAL: nothing else comes while idle)
                var message = self._ev.server_message()
                self._close_now()
                raise PgError(IoError.of_kind(_SERVER_ERROR, ErrorKind.ConnectionAborted), message^)
            self._other()

    def check(mut self) -> Bool:
        """Whether the session can still be used, told without a round
        trip. The socket must still be open. Whatever the server sent
        meanwhile (notifications, notices, parameter changes) is read and
        kept. A FATAL error, a terminated backend say, ends the session.
        (For a pool, before handing out a session that sat idle.)"""
        if not self.is_usable():
            return False
        var state = idle_state(self._sock)
        if state == IdleState.EMPTY:
            return True
        if state == IdleState.CLOSED:
            self._close_now()
            return False
        try:  # (DATA: read what is there, without waiting)
            while True:
                while self._conn.poll(self._ev):
                    if self._ev.kind == EventKind.ERROR:  # (FATAL: nothing else comes while idle)
                        self._close_now()
                        return False
                    self._other()
                var room = min(len(self._rx), self._conn.feed_capacity())
                var got = try_recv(self._sock, Span(self._rx)[:room], "pg: receive")
                if not got:
                    break  # (all of it read)
                if got.value() == 0:  # (EOF)
                    self._close_now()
                    return False
                self._conn.feed(Span(self._rx)[: got.value()])
        except:
            self._close_now()
            return False
        return self.is_usable()

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


def quote_identifier(name: StringSlice) -> String:
    """`name` as a quoted SQL identifier, for splicing a table, channel or
    savepoint name into SQL: in double quotes, with each double quote
    inside doubled. (Values go in parameters, never spliced.)"""
    var out = String('"')
    for c in name.codepoint_slices():
        out += '""' if c == '"' else String(c)
    out += '"'
    return out^


def _decimal(b: Span[UInt8, _], op: StaticString) raises IoError -> Int:
    """A decimal integer that fits an Int (int8's range: both ends)."""
    var neg = len(b) > 0 and Int(b[0]) == ord("-")
    var i = 1 if neg else 0
    if i >= len(b):
        raise IoError.of_kind(op, ErrorKind.InvalidData)
    var limit: UInt64 = (UInt64(1) << 63) if neg else UInt64(Int.MAX)
    var n: UInt64 = 0
    while i < len(b):
        var c = b[i]
        if c < 48 or c > 57:
            raise IoError.of_kind(op, ErrorKind.InvalidData)
        var d = UInt64(c - 48)
        if n > (limit - d) // 10:
            raise IoError.of_kind(op, ErrorKind.InvalidData)
        n = n * 10 + d
        i += 1
    if neg:
        return Int.MIN if n == (UInt64(1) << 63) else -Int(n)
    return Int(n)


def _nonzero_mantissa(b: Span[UInt8, _]) -> Bool:
    """Whether a number's text has a non-zero digit before any exponent
    (so it is no zero, and no "Infinity")."""
    for c in b:
        if c == 101 or c == 69:  # (e, E)
            return False
        if c >= 49 and c <= 57:
            return True
    return False


def _declares_types(params: Params) -> Bool:
    for i in range(len(params)):
        if params.type_oid(i) != 0:
            return True
    return False


def _cache_key(sql: StringSlice, params: Params, declared: Bool) -> String:
    """The statement cache's key: the SQL, then (when any is declared) a
    NUL and the parameter types, which no SQL text holds."""
    var key = String(sql)
    if declared:
        key += "\x00"
        for i in range(len(params)):
            key.write(params.type_oid(i), ",")
    return key^


def _name_prefix(random: Span[UInt8, _]) -> String:
    var digits = "0123456789abcdef".as_bytes()
    var out = List[UInt8]()
    out.extend("mojo_".as_bytes())
    for b in random:
        out.append(digits[Int(b >> 4)])
        out.append(digits[Int(b & 15)])
    out.append(UInt8(ord("_")))
    return String(unsafe_from_utf8=Span(out))


def _last(var all: List[Rows]) -> Rows:
    if len(all) == 0:
        return Rows()
    return all.pop()


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
