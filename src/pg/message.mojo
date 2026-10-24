"""The PostgreSQL wire format, protocol 3.0 ("Frontend/Backend Protocol" in
the PostgreSQL documentation: "Message Flow", "Message Formats"), sans-I/O:
frontend messages built into a `ByteBuffer`, and the bodies of backend
messages checked and read.

Every message but the startup packets is a type byte, then an Int32 length
that counts itself and the body (not the type byte), then the body. The
startup packets (StartupMessage, CancelRequest) have no type byte.
Integers are big-endian. Strings end with a NUL, so none may hold one: the
builders refuse it (`InvalidInput`), and a body whose parts do not add up
to its length raises `InvalidData` (the op names the message).

`pg.connection` frames the backend stream and checks each body once, when
it arrives (`check_*`, `read_*`). The accessors that read a checked body
later (`ServerMessage`, `row_description`) therefore do not fail.
"""

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError

comptime PROTOCOL_VERSION = 196608
"""3.0: the major version in the high 16 bits, the minor in the low."""
comptime CANCEL_REQUEST_CODE = 80877102
"""Sent in place of a protocol version to ask for a cancellation."""
comptime MAX_STARTUP_LENGTH = 10000
"""The longest startup packet a server accepts (its MAX_STARTUP_PACKET_LENGTH)."""

# Backend message types.
comptime AUTHENTICATION: UInt8 = 82  # 'R'
comptime BACKEND_KEY_DATA: UInt8 = 75  # 'K'
comptime PARAMETER_STATUS: UInt8 = 83  # 'S'
comptime READY_FOR_QUERY: UInt8 = 90  # 'Z'
comptime ROW_DESCRIPTION: UInt8 = 84  # 'T'
comptime DATA_ROW: UInt8 = 68  # 'D'
comptime COMMAND_COMPLETE: UInt8 = 67  # 'C'
comptime EMPTY_QUERY_RESPONSE: UInt8 = 73  # 'I'
comptime ERROR_RESPONSE: UInt8 = 69  # 'E'
comptime NOTICE_RESPONSE: UInt8 = 78  # 'N'
comptime NOTIFICATION_RESPONSE: UInt8 = 65  # 'A'
comptime NEGOTIATE_PROTOCOL_VERSION: UInt8 = 118  # 'v'
comptime COPY_IN_RESPONSE: UInt8 = 71  # 'G'
comptime COPY_OUT_RESPONSE: UInt8 = 72  # 'H'
comptime COPY_BOTH_RESPONSE: UInt8 = 87  # 'W'
# ... and those of the extended query protocol.
comptime PARSE_COMPLETE: UInt8 = 49  # '1'
comptime BIND_COMPLETE: UInt8 = 50  # '2'
comptime CLOSE_COMPLETE: UInt8 = 51  # '3'
comptime NO_DATA: UInt8 = 110  # 'n'
comptime PARAMETER_DESCRIPTION: UInt8 = 116  # 't'
comptime PORTAL_SUSPENDED: UInt8 = 115  # 's'

# Authentication requests: the Int32 that starts an 'R' body.
comptime AUTH_OK = 0
comptime AUTH_KERBEROS_V5 = 2
comptime AUTH_CLEARTEXT_PASSWORD = 3
comptime AUTH_MD5_PASSWORD = 5
comptime AUTH_GSS = 7
comptime AUTH_GSS_CONTINUE = 8
comptime AUTH_SSPI = 9
comptime AUTH_SASL = 10
comptime AUTH_SASL_CONTINUE = 11
comptime AUTH_SASL_FINAL = 12

# Transaction status in ReadyForQuery.
comptime IDLE: UInt8 = 73  # 'I'
comptime IN_TRANSACTION: UInt8 = 84  # 'T'
comptime FAILED_TRANSACTION: UInt8 = 69  # 'E'

# ErrorResponse / NoticeResponse field types.
comptime FIELD_SEVERITY: UInt8 = 83  # 'S', localized
comptime FIELD_SEVERITY_RAW: UInt8 = 86  # 'V', never localized (9.6+)
comptime FIELD_CODE: UInt8 = 67  # 'C', the SQLSTATE
comptime FIELD_MESSAGE: UInt8 = 77  # 'M'
comptime FIELD_DETAIL: UInt8 = 68  # 'D'
comptime FIELD_HINT: UInt8 = 72  # 'H'
comptime FIELD_POSITION: UInt8 = 80  # 'P', 1-based, in characters
comptime FIELD_INTERNAL_POSITION: UInt8 = 112  # 'p'
comptime FIELD_INTERNAL_QUERY: UInt8 = 113  # 'q'
comptime FIELD_WHERE: UInt8 = 87  # 'W'
comptime FIELD_SCHEMA: UInt8 = 115  # 's'
comptime FIELD_TABLE: UInt8 = 116  # 't'
comptime FIELD_COLUMN: UInt8 = 99  # 'c'
comptime FIELD_DATA_TYPE: UInt8 = 100  # 'd'
comptime FIELD_CONSTRAINT: UInt8 = 110  # 'n'
comptime FIELD_FILE: UInt8 = 70  # 'F'
comptime FIELD_LINE: UInt8 = 76  # 'L'
comptime FIELD_ROUTINE: UInt8 = 82  # 'R'

# Frontend message types.
comptime _QUERY: UInt8 = 81  # 'Q'
comptime _PASSWORD: UInt8 = 112  # 'p', also SASLInitialResponse and SASLResponse
comptime _TERMINATE: UInt8 = 88  # 'X'
comptime _COPY_FAIL: UInt8 = 102  # 'f'
comptime _PARSE: UInt8 = 80  # 'P'
comptime _BIND: UInt8 = 66  # 'B'
comptime _DESCRIBE: UInt8 = 68  # 'D'
comptime _EXECUTE: UInt8 = 69  # 'E'
comptime _SYNC: UInt8 = 83  # 'S'
comptime _CLOSE: UInt8 = 67  # 'C'
comptime _FLUSH: UInt8 = 72  # 'H'

# What a Describe or Close names.
comptime STATEMENT: UInt8 = 83  # 'S': a prepared statement
comptime PORTAL: UInt8 = 80  # 'P': a portal (a bound statement)

# Value formats.
comptime TEXT = 0
comptime BINARY = 1

comptime MAX_PARAMS = 65535
"""The most parameters a statement can have (Bind counts them in 16 bits)."""

comptime _MAX_LENGTH = 0x7FFFFFFF
"""The largest Int32: no message can say it is longer."""


# ---- reading -----------------------------------------------------------------


@inline(.always)
def be_u32(data: Span[UInt8, _], at: Int) -> UInt32:
    """The big-endian UInt32 at `at` (the caller checked the bounds)."""
    return (
        (UInt32(data[at]) << 24)
        | (UInt32(data[at + 1]) << 16)
        | (UInt32(data[at + 2]) << 8)
        | UInt32(data[at + 3])
    )


@inline(.always)
def be_i32(data: Span[UInt8, _], at: Int) -> Int:
    """The big-endian Int32 at `at`, sign extended."""
    return Int(be_u32(data, at).cast[DType.int32]())


@inline(.always)
def be_i16(data: Span[UInt8, _], at: Int) -> Int:
    """The big-endian Int16 at `at`, sign extended."""
    return Int(((UInt16(data[at]) << 8) | UInt16(data[at + 1])).cast[DType.int16]())


def string_end(body: Span[UInt8, _], start: Int, op: StaticString) raises IoError -> Int:
    """The index of the NUL that ends the string at `start`."""
    for i in range(start, len(body)):
        if body[i] == 0:
            return i
    raise IoError.of_kind(op, ErrorKind.InvalidData)


def _text(body: Span[UInt8, _], start: Int, end: Int) -> String:
    return String(from_utf8_lossy=body[start:end])


comptime E_FIELDS = "pg: malformed ErrorResponse or NoticeResponse"
comptime E_ROW_DESCRIPTION = "pg: malformed RowDescription"
comptime E_DATA_ROW = "pg: malformed DataRow"
comptime E_COMMAND_COMPLETE = "pg: malformed CommandComplete"
comptime E_PARAMETER_STATUS = "pg: malformed ParameterStatus"
comptime E_NOTIFICATION = "pg: malformed NotificationResponse"
comptime E_PARAMETER_DESCRIPTION = "pg: malformed ParameterDescription"


def check_fields(body: Span[UInt8, _]) raises IoError:
    """Check an ErrorResponse or NoticeResponse body: fields, each a type
    byte and a string, then the NUL that ends the body."""
    var i = 0
    var n = len(body)
    while i < n and body[i] != 0:
        i = string_end(body, i + 1, E_FIELDS) + 1
    if i != n - 1:
        raise IoError.of_kind(E_FIELDS, ErrorKind.InvalidData)


def check_string(body: Span[UInt8, _], op: StaticString) raises IoError:
    """Check a body that is one string (CommandComplete's tag)."""
    if string_end(body, 0, op) != len(body) - 1:
        raise IoError.of_kind(op, ErrorKind.InvalidData)


def check_row_description(body: Span[UInt8, _]) raises IoError -> Int:
    """Check a RowDescription body; returns its column count."""
    if len(body) < 2:
        raise IoError.of_kind(E_ROW_DESCRIPTION, ErrorKind.InvalidData)
    var count = be_i16(body, 0)
    if count < 0:
        raise IoError.of_kind(E_ROW_DESCRIPTION, ErrorKind.InvalidData)
    var i = 2
    for _ in range(count):
        i = string_end(body, i, E_ROW_DESCRIPTION) + 1
        if len(body) - i < 18:
            raise IoError.of_kind(E_ROW_DESCRIPTION, ErrorKind.InvalidData)
        var format = be_i16(body, i + 16)
        if format != 0 and format != 1:
            raise IoError.of_kind(E_ROW_DESCRIPTION, ErrorKind.InvalidData)
        i += 18
    if i != len(body):
        raise IoError.of_kind(E_ROW_DESCRIPTION, ErrorKind.InvalidData)
    return count


@fieldwise_init
struct Column(Copyable, Movable, Writable):
    """One field of a RowDescription."""

    var name: String
    var table_oid: UInt32
    """The table's OID, or 0 when the value is not a table column."""
    var column: Int
    """The column's attribute number in that table, or 0."""
    var type_oid: UInt32
    var type_size: Int
    """`pg_type.typlen`: negative for variable-width types."""
    var type_modifier: Int
    """Type-specific (`atttypmod`), -1 when there is none."""
    var format: Int
    """0 for text, 1 for binary."""

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.name, " (type ", self.type_oid, ", format ", self.format, ")")


def row_description(body: Span[UInt8, _]) -> List[Column]:
    """The columns of a RowDescription body `check_row_description` accepted."""
    var out = List[Column]()
    var count = be_i16(body, 0)
    var i = 2
    for _ in range(count):
        var end = i
        while body[end] != 0:
            end += 1
        var at = end + 1
        out.append(
            Column(
                _text(body, i, end),
                be_u32(body, at),
                be_i16(body, at + 4),
                be_u32(body, at + 6),
                be_i16(body, at + 10),
                be_i32(body, at + 12),
                be_i16(body, at + 16),
            )
        )
        i = at + 18
    return out^


def read_data_row(body: Span[UInt8, _], columns: Int, mut at: List[Int]) raises IoError:
    """Check a DataRow body of `columns` values and record where each lies
    in it: `at` gets a start and a length per value, the length -1 for
    NULL."""
    var n = len(body)
    if n < 2 or be_i16(body, 0) != columns:
        raise IoError.of_kind(E_DATA_ROW, ErrorKind.InvalidData)
    at.clear()
    var i = 2
    for _ in range(columns):
        if n - i < 4:
            raise IoError.of_kind(E_DATA_ROW, ErrorKind.InvalidData)
        var length = be_i32(body, i)
        i += 4
        if length < -1 or length > n - i:
            raise IoError.of_kind(E_DATA_ROW, ErrorKind.InvalidData)
        at.append(i)
        at.append(length)
        if length > 0:
            i += length
    if i != n:
        raise IoError.of_kind(E_DATA_ROW, ErrorKind.InvalidData)


def read_parameter_status(body: Span[UInt8, _], mut name: String, mut value: String) raises IoError:
    """The name and value of a ParameterStatus body."""
    var end = string_end(body, 0, E_PARAMETER_STATUS)
    var vend = string_end(body, end + 1, E_PARAMETER_STATUS)
    if vend != len(body) - 1 or end == 0:
        raise IoError.of_kind(E_PARAMETER_STATUS, ErrorKind.InvalidData)
    name = _text(body, 0, end)
    value = _text(body, end + 1, vend)


@fieldwise_init
struct Notification(Copyable, Movable, Writable):
    """A NotificationResponse: a NOTIFY on a channel this session listens to."""

    var pid: Int
    """The notifying backend's process ID."""
    var channel: String
    var payload: String

    def write_to(self, mut writer: Some[Writer]):
        writer.write("notification on ", self.channel, " from ", self.pid, ": ", self.payload)


def check_parameter_description(body: Span[UInt8, _]) raises IoError -> Int:
    """Check a ParameterDescription body; returns its parameter count."""
    if len(body) < 2:
        raise IoError.of_kind(E_PARAMETER_DESCRIPTION, ErrorKind.InvalidData)
    var n = Int((UInt16(body[0]) << 8) | UInt16(body[1]))  # (unsigned: up to MAX_PARAMS)
    if len(body) != 2 + 4 * n:
        raise IoError.of_kind(E_PARAMETER_DESCRIPTION, ErrorKind.InvalidData)
    return n


def parameter_types(body: Span[UInt8, _]) -> List[UInt32]:
    """The type OIDs in a ParameterDescription body that
    `check_parameter_description` accepted."""
    var n = (len(body) - 2) // 4
    var out = List[UInt32](capacity=n)
    for i in range(n):
        out.append(be_u32(body, 2 + 4 * i))
    return out^


def check_notification(body: Span[UInt8, _]) raises IoError:
    if len(body) < 6:
        raise IoError.of_kind(E_NOTIFICATION, ErrorKind.InvalidData)
    var end = string_end(body, 4, E_NOTIFICATION)
    if string_end(body, end + 1, E_NOTIFICATION) != len(body) - 1:
        raise IoError.of_kind(E_NOTIFICATION, ErrorKind.InvalidData)


def notification(body: Span[UInt8, _]) -> Notification:
    """The NotificationResponse in a body `check_notification` accepted."""
    var end = 4
    while body[end] != 0:
        end += 1
    return Notification(be_i32(body, 0), _text(body, 4, end), _text(body, end + 1, len(body) - 1))


def rows_affected(tag: StringSlice) -> Optional[Int]:
    """The row count at the end of a CommandComplete tag ("INSERT 0 5",
    "UPDATE 3", "SELECT 2", ...), or None for tags without one
    ("CREATE TABLE")."""
    var b = tag.as_bytes()
    var first = -1
    var space = -1
    for i in range(len(b)):
        if b[i] == 32:
            if first < 0:
                first = i
            space = i
    if space < 0 or space == len(b) - 1:
        return None
    var cmd = String(from_utf8_lossy=b[:first])
    if not (
        cmd == "INSERT"
        or cmd == "UPDATE"
        or cmd == "DELETE"
        or cmd == "SELECT"
        or cmd == "MERGE"
        or cmd == "FETCH"
        or cmd == "MOVE"
        or cmd == "COPY"
    ):
        return None
    var n = 0
    for i in range(space + 1, len(b)):
        if b[i] < 48 or b[i] > 57 or n > (Int.MAX - 9) // 10:
            return None
        n = n * 10 + Int(b[i]) - 48
    return n


struct ServerMessage(Copyable, Movable, Writable):
    """An ErrorResponse or NoticeResponse: severity, SQLSTATE and message,
    plus the optional fields ("Error and Notice Message Fields" in the
    PostgreSQL documentation), kept as the body `check_fields` accepted."""

    var _body: List[UInt8]

    def __init__(out self, var body: List[UInt8]):
        self._body = body^

    def field(self, code: UInt8) -> Optional[String]:
        """The field of type `code` (`FIELD_*`), if the server sent it."""
        var i = 0
        var n = len(self._body)
        while i < n and self._body[i] != 0:
            var end = i + 1
            while self._body[end] != 0:
                end += 1
            if self._body[i] == code:
                return _text(Span(self._body), i + 1, end)
            i = end + 1
        return None

    def _or_empty(self, code: UInt8) -> String:
        return self.field(code).or_else(String())

    def severity(self) -> String:
        """ERROR, FATAL or PANIC for errors; WARNING, NOTICE, DEBUG, INFO or
        LOG for notices. Never localized when the server says (9.6+)."""
        var raw = self.field(FIELD_SEVERITY_RAW)
        if raw:
            return raw.value()
        return self._or_empty(FIELD_SEVERITY)

    def code(self) -> String:
        """The SQLSTATE, such as "23505" for a unique violation."""
        return self._or_empty(FIELD_CODE)

    def message(self) -> String:
        return self._or_empty(FIELD_MESSAGE)

    def detail(self) -> Optional[String]:
        return self.field(FIELD_DETAIL)

    def hint(self) -> Optional[String]:
        return self.field(FIELD_HINT)

    def position(self) -> Optional[String]:
        """Where in the query the error is: a 1-based character index."""
        return self.field(FIELD_POSITION)

    def is_fatal(self) -> Bool:
        """FATAL or PANIC: the server ends the session after it."""
        var s = self.severity()
        return s == "FATAL" or s == "PANIC"

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.severity(), " ", self.code(), ": ", self.message())


# ---- building ----------------------------------------------------------------


def _put_i32(mut out: ByteBuffer, v: Int) raises IoError:
    out.ensure_writable(4)
    var w = out.writable_span()
    w[0] = UInt8((v >> 24) & 0xFF)
    w[1] = UInt8((v >> 16) & 0xFF)
    w[2] = UInt8((v >> 8) & 0xFF)
    w[3] = UInt8(v & 0xFF)
    out.commit(4)


def _put_string(mut out: ByteBuffer, s: Span[UInt8, _]) raises IoError:
    out.write_bytes(s)
    out.write_byte(0)


def _check_string(s: Span[UInt8, _], op: StaticString) raises IoError:
    for b in s:
        if b == 0:
            raise IoError.of_kind(op, ErrorKind.InvalidInput)


def write_startup(mut out: ByteBuffer, params: List[String]) raises IoError:
    """A StartupMessage for protocol 3.0, with `params` as name, value
    pairs (`user` among them). Names must not be empty, no string may hold
    a NUL, and the packet must fit `MAX_STARTUP_LENGTH`; otherwise
    `InvalidInput`, with nothing written."""
    comptime op = "pg: invalid startup parameter"
    if len(params) % 2 != 0:
        raise IoError.of_kind(op, ErrorKind.InvalidInput)
    var n = 4 + 4 + 1
    for i in range(len(params)):
        var b = params[i].as_bytes()
        _check_string(b, op)
        if i % 2 == 0 and len(b) == 0:
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        n += len(b) + 1
    if n > MAX_STARTUP_LENGTH:
        raise IoError.of_kind("pg: startup parameters too long", ErrorKind.InvalidInput)
    _put_i32(out, n)
    _put_i32(out, PROTOCOL_VERSION)
    for i in range(len(params)):
        _put_string(out, params[i].as_bytes())
    out.write_byte(0)


def _header(mut out: ByteBuffer, kind: UInt8, body: Int, op: StaticString) raises IoError:
    if body > _MAX_LENGTH - 4:
        raise IoError.of_kind(op, ErrorKind.InvalidInput)
    out.write_byte(kind)
    _put_i32(out, 4 + body)


def write_password(mut out: ByteBuffer, password: StringSlice) raises IoError:
    """A PasswordMessage: the cleartext password, or the MD5 answer."""
    comptime op = "pg: invalid password"
    var b = password.as_bytes()
    _check_string(b, op)
    _header(out, _PASSWORD, len(b) + 1, op)
    _put_string(out, b)


def write_sasl_initial_response(mut out: ByteBuffer, mechanism: StringSlice, data: Span[UInt8, _]) raises IoError:
    """The SASLInitialResponse: the chosen mechanism and its first message."""
    comptime op = "pg: invalid SASL message"
    var m = mechanism.as_bytes()
    _check_string(m, op)
    _header(out, _PASSWORD, len(m) + 1 + 4 + len(data), op)
    _put_string(out, m)
    _put_i32(out, len(data))
    out.write_bytes(data)


def write_sasl_response(mut out: ByteBuffer, data: Span[UInt8, _]) raises IoError:
    """A SASLResponse: the next message of the exchange."""
    _header(out, _PASSWORD, len(data), "pg: invalid SASL message")
    out.write_bytes(data)


def write_query(mut out: ByteBuffer, sql: StringSlice) raises IoError:
    """A Query (the simple query protocol): one or more statements,
    separated by semicolons. `InvalidInput` for a NUL in `sql`."""
    comptime op = "pg: NUL byte in a query"
    var b = sql.as_bytes()
    _check_string(b, op)
    _header(out, _QUERY, len(b) + 1, "pg: query too long")
    _put_string(out, b)


def write_copy_fail(mut out: ByteBuffer, message: StringSlice) raises IoError:
    """A CopyFail: refuse the COPY FROM STDIN the server started."""
    comptime op = "pg: invalid CopyFail message"
    var b = message.as_bytes()
    _check_string(b, op)
    _header(out, _COPY_FAIL, len(b) + 1, op)
    _put_string(out, b)


def write_terminate(mut out: ByteBuffer) raises IoError:
    """A Terminate: the session ends; the server closes the connection."""
    out.write_byte(_TERMINATE)
    _put_i32(out, 4)


struct Params(Copyable, Movable, Sized):
    """The values of a statement's parameters (`$1`, `$2`, ...), in order.
    Each is NULL, or bytes in text or binary form, with the type OID that
    Parse declares for it. OID 0 lets the server infer the type, as for an
    untyped literal, so a value in text form works for any type it can be
    read as."""

    var _data: List[UInt8]
    var _at: List[Int]
    """Per value: its start in `_data` and its length (-1: NULL)."""
    var _formats: List[Int]
    var _types: List[UInt32]

    def __init__(out self):
        self._data = List[UInt8]()
        self._at = List[Int]()
        self._formats = List[Int]()
        self._types = List[UInt32]()

    def __len__(self) -> Int:
        return len(self._types)

    def add_null(mut self, type_oid: UInt32 = 0):
        self._at.append(len(self._data))
        self._at.append(-1)
        self._formats.append(TEXT)
        self._types.append(type_oid)

    def add_text(mut self, value: StringSlice, type_oid: UInt32 = 0):
        """A value in text form, as the type's input function reads it."""
        self._at.append(len(self._data))
        self._at.append(value.byte_length())
        self._data.extend(value.as_bytes())
        self._formats.append(TEXT)
        self._types.append(type_oid)

    def add_binary(mut self, value: Span[UInt8, _], type_oid: UInt32):
        """A value in the binary form of type `type_oid` (17, bytea: the
        bytes themselves)."""
        self._at.append(len(self._data))
        self._at.append(len(value))
        self._data.extend(value)
        self._formats.append(BINARY)
        self._types.append(type_oid)

    def add[T: Writable](mut self, value: T):
        """Any writable value, in its text form (an `Int`, a `Float64`, a
        `Bool`, a string), with its type left to the server."""
        self.add_text(String(value))

    def type_oid(self, i: Int) -> UInt32:
        return self._types[i]

    def format(self, i: Int) -> Int:
        return self._formats[i]

    def is_null(self, i: Int) -> Bool:
        return self._at[2 * i + 1] < 0

    def value(self, i: Int) -> Span[UInt8, origin_of(self._data)]:
        var start = self._at[2 * i]
        return Span(self._data)[start : start + max(self._at[2 * i + 1], 0)]


def _put_i16(mut out: ByteBuffer, v: Int) raises IoError:
    out.write_byte(UInt8((v >> 8) & 0xFF))
    out.write_byte(UInt8(v & 0xFF))


def write_parse(mut out: ByteBuffer, name: StringSlice, sql: StringSlice, params: Params) raises IoError:
    """A Parse: `sql` (one statement) as the prepared statement `name` (""
    for the unnamed one), with the parameter types `params` declares."""
    comptime op = "pg: invalid Parse"
    var nb = name.as_bytes()
    var qb = sql.as_bytes()
    _check_string(nb, op)
    _check_string(qb, "pg: NUL byte in a query")
    if len(params) > MAX_PARAMS:
        raise IoError.of_kind("pg: too many parameters", ErrorKind.InvalidInput)
    _header(out, _PARSE, len(nb) + 1 + len(qb) + 1 + 2 + 4 * len(params), "pg: query too long")
    _put_string(out, nb)
    _put_string(out, qb)
    _put_i16(out, len(params))
    for i in range(len(params)):
        _put_i32(out, Int(params.type_oid(i)))


def write_bind(
    mut out: ByteBuffer, portal: StringSlice, statement: StringSlice, params: Params, result_formats: Span[Int, _]
) raises IoError:
    """A Bind: portal `portal` ("" for the unnamed one) from the prepared
    statement `statement` with `params`. `result_formats`: one format
    (`TEXT` or `BINARY`) per result column, or a single one for all of
    them, or none for text."""
    comptime op = "pg: invalid Bind"
    var pb = portal.as_bytes()
    var sb = statement.as_bytes()
    _check_string(pb, op)
    _check_string(sb, op)
    var n = len(params)
    if n > MAX_PARAMS or len(result_formats) > MAX_PARAMS:
        raise IoError.of_kind(op, ErrorKind.InvalidInput)
    var same = True
    for f in result_formats:
        if f != TEXT and f != BINARY:
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        same = same and f == result_formats[0]
    # result codes: none for all text, one when all agree, else one each
    var result_codes = 0
    if len(result_formats) > 0:
        if not same:
            result_codes = len(result_formats)
        elif result_formats[0] == BINARY:
            result_codes = 1
    var binary = 0
    for i in range(n):
        binary += params.format(i)
    # format codes: none when all are text, one when all are binary
    var codes = 0 if binary == 0 else (1 if binary == n else n)
    var size = len(pb) + 1 + len(sb) + 1 + 2 + 2 * codes + 2 + 2 + 2 * result_codes
    for i in range(n):
        size += 4 + len(params.value(i))
    _header(out, _BIND, size, "pg: parameters too long")
    _put_string(out, pb)
    _put_string(out, sb)
    _put_i16(out, codes)
    if codes == 1:
        _put_i16(out, BINARY)
    elif codes == n:
        for i in range(n):
            _put_i16(out, params.format(i))
    _put_i16(out, n)
    for i in range(n):
        if params.is_null(i):
            _put_i32(out, -1)
        else:
            var v = params.value(i)
            _put_i32(out, len(v))
            out.write_bytes(v)
    _put_i16(out, result_codes)
    if result_codes == 1:
        _put_i16(out, BINARY)
    elif result_codes > 1:
        for f in result_formats:
            _put_i16(out, f)


def write_describe(mut out: ByteBuffer, kind: UInt8, name: StringSlice) raises IoError:
    """A Describe of a prepared statement (`STATEMENT`: ParameterDescription,
    then RowDescription or NoData) or a portal (`PORTAL`: RowDescription or
    NoData)."""
    var nb = name.as_bytes()
    _check_string(nb, "pg: invalid Describe")
    if kind != STATEMENT and kind != PORTAL:
        raise IoError.of_kind("pg: invalid Describe", ErrorKind.InvalidInput)
    _header(out, _DESCRIBE, 1 + len(nb) + 1, "pg: invalid Describe")
    out.write_byte(kind)
    _put_string(out, nb)


def write_execute(mut out: ByteBuffer, portal: StringSlice, max_rows: Int = 0) raises IoError:
    """An Execute of `portal`: at most `max_rows` rows (0: all of them)."""
    var pb = portal.as_bytes()
    _check_string(pb, "pg: invalid Execute")
    if max_rows < 0 or max_rows > 0x7FFFFFFF:
        raise IoError.of_kind("pg: invalid Execute", ErrorKind.InvalidInput)
    _header(out, _EXECUTE, len(pb) + 1 + 4, "pg: invalid Execute")
    _put_string(out, pb)
    _put_i32(out, max_rows)


def write_close(mut out: ByteBuffer, kind: UInt8, name: StringSlice) raises IoError:
    """A Close of a prepared statement (`STATEMENT`) or a portal (`PORTAL`)."""
    var nb = name.as_bytes()
    _check_string(nb, "pg: invalid Close")
    if kind != STATEMENT and kind != PORTAL:
        raise IoError.of_kind("pg: invalid Close", ErrorKind.InvalidInput)
    _header(out, _CLOSE, 1 + len(nb) + 1, "pg: invalid Close")
    out.write_byte(kind)
    _put_string(out, nb)


def write_sync(mut out: ByteBuffer) raises IoError:
    """A Sync: ends an extended-protocol cycle (the server answers with
    ReadyForQuery, after skipping to it on an error)."""
    out.write_byte(_SYNC)
    _put_i32(out, 4)


def write_flush(mut out: ByteBuffer) raises IoError:
    """A Flush: asks the server to send what it has, without ending the cycle."""
    out.write_byte(_FLUSH)
    _put_i32(out, 4)


@fieldwise_init
struct BackendKey(Equatable, TrivialRegisterPassable, Writable):
    """BackendKeyData: what a CancelRequest for this session must quote."""

    var pid: Int
    """The backend's process ID."""
    var secret: UInt32

    def __eq__(self, other: Self) -> Bool:
        return self.pid == other.pid and self.secret == other.secret

    def write_to(self, mut writer: Some[Writer]):
        writer.write("backend ", self.pid)


def write_cancel_request(mut out: ByteBuffer, key: BackendKey) raises IoError:
    """A CancelRequest, the whole of what is sent on a new connection to
    cancel the query `key`'s session is running (the server answers
    nothing and closes)."""
    _put_i32(out, 16)
    _put_i32(out, CANCEL_REQUEST_CODE)
    _put_i32(out, key.pid)
    _put_i32(out, Int(key.secret))
