"""PostgreSQL's built-in types: their OIDs, which of them this driver asks
for in binary form, and the binary forms it reads (what PostgreSQL's
`*send` functions write). Sans-I/O, like the rest of `pg`.

Binary form is used only where the client can produce exactly the text the
server would, so `Rows.text` reads the same in either form:
- bool, int2, int4, int8, oid;
- bytea (`\\x` and hex, as `bytea_output = hex`, the default);
- uuid;
- date, time and timestamp (ISO, as `DateStyle = ISO`, the default; BC
  years and infinities included);
- text, varchar, bpchar and name.

The rest stays in text form: the floats (PostgreSQL 12 and later print
them shortest and exact, so parsing them loses nothing), timestamptz (whose
text depends on the session's TimeZone), numeric, interval, json, arrays,
and every type this list does not name ("char" too: the server writes its
high bytes as octal escapes, which `write_binary_as_text` also does for a
caller who asks for binary).
"""

from linux import ErrorKind, IoError

from .message import be_i16, be_i32, be_u32

comptime BOOL: UInt32 = 16
comptime BYTEA: UInt32 = 17
comptime CHAR: UInt32 = 18
comptime NAME: UInt32 = 19
comptime INT8: UInt32 = 20
comptime INT2: UInt32 = 21
comptime INT4: UInt32 = 23
comptime TEXT_TYPE: UInt32 = 25
comptime OID: UInt32 = 26
comptime JSON: UInt32 = 114
comptime FLOAT4: UInt32 = 700
comptime FLOAT8: UInt32 = 701
comptime UNKNOWN: UInt32 = 705
comptime BPCHAR: UInt32 = 1042
comptime VARCHAR: UInt32 = 1043
comptime DATE: UInt32 = 1082
comptime TIME: UInt32 = 1083
comptime TIMESTAMP: UInt32 = 1114
comptime TIMESTAMPTZ: UInt32 = 1184
comptime INTERVAL: UInt32 = 1186
comptime NUMERIC: UInt32 = 1700
comptime UUID: UInt32 = 2950
comptime JSONB: UInt32 = 3802

comptime E_VALUE = "pg: malformed binary value"

comptime _USECS_PER_DAY = 86400 * 1000000
comptime _DAYS_1970_TO_2000 = 10957
"""PostgreSQL counts dates and timestamps from 2000-01-01."""


def wants_binary(oid: UInt32) -> Bool:
    """Whether results of type `oid` are asked for in binary form (see the
    module docs)."""
    return (
        oid == INT4
        or oid == INT8
        or oid == TEXT_TYPE
        or oid == VARCHAR
        or oid == BOOL
        or oid == INT2
        or oid == TIMESTAMP
        or oid == DATE
        or oid == UUID
        or oid == BYTEA
        or oid == NAME
        or oid == BPCHAR
        or oid == OID
        or oid == TIME
    )


def is_text_like(oid: UInt32) -> Bool:
    """Types whose binary form is their text: UTF-8 bytes."""
    return oid == TEXT_TYPE or oid == VARCHAR or oid == BPCHAR or oid == NAME


@inline(.always)
def _i64(v: Span[UInt8, _]) -> Int:
    """The big-endian Int64 at the start of `v` (8 bytes, checked by the
    caller)."""
    return Int(((UInt64(be_u32(v, 0)) << 32) | UInt64(be_u32(v, 4))).cast[DType.int64]())


def binary_int(oid: UInt32, v: Span[UInt8, _]) raises IoError -> Int:
    """An int2, int4, int8 or oid in binary form."""
    if oid == INT4 and len(v) == 4:
        return be_i32(v, 0)
    if oid == INT8 and len(v) == 8:
        return _i64(v)
    if oid == INT2 and len(v) == 2:
        return be_i16(v, 0)
    if oid == OID and len(v) == 4:
        return Int(be_u32(v, 0))
    raise IoError.of_kind(E_VALUE, ErrorKind.InvalidData)


@fieldwise_init
struct Date(Equatable, TrivialRegisterPassable, Writable):
    """A calendar date (proleptic Gregorian): `year` is astronomical, so 0
    is 1 BC. `infinite` is 1 or -1 for 'infinity' and '-infinity'."""

    var year: Int
    var month: Int
    var day: Int
    var infinite: Int

    def __eq__(self, other: Self) -> Bool:
        return (
            self.year == other.year
            and self.month == other.month
            and self.day == other.day
            and self.infinite == other.infinite
        )

    @staticmethod
    def from_days(days_since_1970: Int) -> Date:
        """The date `days_since_1970` days after 1970-01-01 (H. Hinnant's
        civil_from_days)."""
        var z = days_since_1970 + 719468
        var era = z // 146097
        var doe = z - era * 146097
        var yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
        var doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
        var mp = (5 * doy + 2) // 153
        var d = doy - (153 * mp + 2) // 5 + 1
        var m = mp + 3 if mp < 10 else mp - 9
        var y = yoe + era * 400 + (1 if m <= 2 else 0)
        return Date(y, m, d, 0)

    def days_since_1970(self) -> Int:
        """The inverse of `from_days` (H. Hinnant's days_from_civil)."""
        var y = self.year - (1 if self.month <= 2 else 0)
        var era = y // 400
        var yoe = y - era * 400
        var mp = self.month - 3 if self.month > 2 else self.month + 9
        var doy = (153 * mp + 2) // 5 + self.day - 1
        var doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
        return era * 146097 + doe - 719468

    def write_to(self, mut writer: Some[Writer]):
        """As PostgreSQL writes it in ISO style: "2024-02-29",
        "0001-01-01 BC", "infinity"."""
        if self.infinite != 0:
            writer.write("infinity" if self.infinite > 0 else "-infinity")
            return
        _write_ymd(writer, self.year, self.month, self.day)
        if self.year <= 0:
            writer.write(" BC")


def _pad(mut writer: Some[Writer], v: Int, width: Int):
    var s = String(v)
    for _ in range(width - s.byte_length()):
        writer.write("0")
    writer.write(s)


def _write_ymd(mut writer: Some[Writer], year: Int, month: Int, day: Int):
    _pad(writer, year if year > 0 else 1 - year, 4)  # (BC years count from 1)
    writer.write("-")
    _pad(writer, month, 2)
    writer.write("-")
    _pad(writer, day, 2)


def _write_time(mut writer: Some[Writer], usecs: Int):
    """HH:MM:SS, then the fraction without trailing zeros."""
    var secs = usecs // 1000000
    var frac = usecs % 1000000
    _pad(writer, secs // 3600, 2)
    writer.write(":")
    _pad(writer, (secs // 60) % 60, 2)
    writer.write(":")
    _pad(writer, secs % 60, 2)
    if frac != 0:
        var digits = 6
        while frac % 10 == 0:
            frac //= 10
            digits -= 1
        writer.write(".")
        _pad(writer, frac, digits)


def binary_date(v: Span[UInt8, _]) raises IoError -> Date:
    """A date in binary form: Int32 days since 2000-01-01."""
    if len(v) != 4:
        raise IoError.of_kind(E_VALUE, ErrorKind.InvalidData)
    var days = be_i32(v, 0)
    if days == 0x7FFFFFFF:
        return Date(0, 0, 0, 1)
    if days == -0x80000000:
        return Date(0, 0, 0, -1)
    return Date.from_days(days + _DAYS_1970_TO_2000)


def binary_time_us(v: Span[UInt8, _]) raises IoError -> Int:
    """A time (without time zone) in binary form: microseconds since
    midnight."""
    if len(v) != 8:
        raise IoError.of_kind(E_VALUE, ErrorKind.InvalidData)
    return _i64(v)


comptime _USECS_1970_TO_2000 = _DAYS_1970_TO_2000 * _USECS_PER_DAY


def binary_timestamp_us(v: Span[UInt8, _]) raises IoError -> Int:
    """A timestamp in binary form, as microseconds since 1970-01-01
    00:00:00. `Int.MAX` and `Int.MIN` stand for 'infinity' and
    '-infinity'. The last 29 years PostgreSQL allows (from 294247 AD) do
    not fit an Int counted from 1970: `InvalidData`."""
    if len(v) != 8:
        raise IoError.of_kind(E_VALUE, ErrorKind.InvalidData)
    var us = _i64(v)
    if us == Int.MAX or us == Int.MIN:
        return us
    if us > Int.MAX - 1 - _USECS_1970_TO_2000:
        raise IoError.of_kind("pg: timestamp out of range for microseconds since 1970", ErrorKind.InvalidData)
    return us + _USECS_1970_TO_2000


def write_timestamp(mut writer: Some[Writer], usecs_since_1970: Int):
    """A timestamp as PostgreSQL writes it in ISO style:
    "2024-02-29 13:45:00.5", "0001-01-01 00:00:00 BC", "infinity"."""
    _write_timestamp(writer, usecs_since_1970, 0)


def _write_timestamp(mut writer: Some[Writer], usecs: Int, epoch_days: Int):
    """`usecs` counted from `epoch_days` days after 1970-01-01 (PostgreSQL's
    own epoch, 2000-01-01, lets its whole range be written)."""
    if usecs == Int.MAX:
        writer.write("infinity")
        return
    if usecs == Int.MIN:
        writer.write("-infinity")
        return
    var days = usecs // _USECS_PER_DAY
    var d = Date.from_days(days + epoch_days)
    _write_ymd(writer, d.year, d.month, d.day)
    writer.write(" ")
    _write_time(writer, usecs - days * _USECS_PER_DAY)
    if d.year <= 0:
        writer.write(" BC")


def write_binary_as_text(mut writer: Some[Writer], oid: UInt32, v: Span[UInt8, _]) raises IoError:
    """A value in binary form of a type `wants_binary` names, written as the
    server would write it in text form."""
    if is_text_like(oid):
        writer.write(String(from_utf8_lossy=v))
    elif oid == INT4 or oid == INT8 or oid == INT2 or oid == OID:
        writer.write(binary_int(oid, v))
    elif oid == CHAR:  # (as charout writes it: NUL as nothing, high bytes in octal)
        if len(v) != 1:
            raise IoError.of_kind(E_VALUE, ErrorKind.InvalidData)
        if v[0] >= 0x80:
            writer.write("\\", Int(v[0] >> 6), Int((v[0] >> 3) & 7), Int(v[0] & 7))
        elif v[0] != 0:
            writer.write(chr(Int(v[0])))
    elif oid == BOOL:
        if len(v) != 1:
            raise IoError.of_kind(E_VALUE, ErrorKind.InvalidData)
        writer.write("t" if v[0] != 0 else "f")
    elif oid == BYTEA:
        var digits = "0123456789abcdef".as_bytes()
        var out = List[UInt8](capacity=2 + 2 * len(v))
        out.append(UInt8(ord("\\")))
        out.append(UInt8(ord("x")))
        for b in v:
            out.append(digits[Int(b >> 4)])
            out.append(digits[Int(b & 15)])
        writer.write(StringSlice(unsafe_from_utf8=Span(out)))
    elif oid == UUID:
        if len(v) != 16:
            raise IoError.of_kind(E_VALUE, ErrorKind.InvalidData)
        var digits = "0123456789abcdef".as_bytes()
        var out = List[UInt8](capacity=36)
        for i in range(16):
            if i == 4 or i == 6 or i == 8 or i == 10:
                out.append(UInt8(ord("-")))
            out.append(digits[Int(v[i] >> 4)])
            out.append(digits[Int(v[i] & 15)])
        writer.write(StringSlice(unsafe_from_utf8=Span(out)))
    elif oid == DATE:
        writer.write(binary_date(v))
    elif oid == TIME:
        _write_time(writer, binary_time_us(v))
    elif oid == TIMESTAMP:
        if len(v) != 8:
            raise IoError.of_kind(E_VALUE, ErrorKind.InvalidData)
        _write_timestamp(writer, _i64(v), _DAYS_1970_TO_2000)
    else:
        raise IoError.of_kind("pg: no text form for this binary value", ErrorKind.Unsupported)


# ---- text forms ----------------------------------------------------------------


comptime E_TEXT = "pg: unexpected text form of a value"
comptime _SPACE: UInt8 = 32
comptime _PLUS: UInt8 = 43
comptime _DASH: UInt8 = 45
comptime _DOT: UInt8 = 46
comptime _COLON: UInt8 = 58
comptime _B: UInt8 = 66
comptime _C: UInt8 = 67
comptime _BACKSLASH: UInt8 = 92
comptime _X: UInt8 = 120


def _digits(t: Span[UInt8, _], mut at: Int, n: Int) raises IoError -> Int:
    """Exactly `n` decimal digits at `at` (advanced past them)."""
    if at + n > len(t):
        raise IoError.of_kind(E_TEXT, ErrorKind.InvalidData)
    var v = 0
    for _ in range(n):
        var c = t[at]
        if c < 48 or c > 57:
            raise IoError.of_kind(E_TEXT, ErrorKind.InvalidData)
        v = v * 10 + Int(c) - 48
        at += 1
    return v


def _expect(t: Span[UInt8, _], mut at: Int, c: UInt8) raises IoError:
    if at >= len(t) or t[at] != c:
        raise IoError.of_kind(E_TEXT, ErrorKind.InvalidData)
    at += 1


def _days_in_month(year: Int, month: Int) -> Int:
    """For an astronomical year (1 BC is year 0, a leap year)."""
    if month == 2:
        return 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28
    if month == 4 or month == 6 or month == 9 or month == 11:
        return 30
    return 31


def _check_day(d: Date) raises IoError:
    if d.day > _days_in_month(d.year, d.month):
        raise IoError.of_kind(E_TEXT, ErrorKind.InvalidData)


def _ymd(t: Span[UInt8, _], mut at: Int) raises IoError -> Date:
    """YYYY-MM-DD, the year with 4 or more digits (and from 1: the text
    counts years BC from 1 too)."""
    var start = at
    while at < len(t) and t[at] >= 48 and t[at] <= 57:
        at += 1
    var width = at - start
    at = start
    if width < 4 or width > 7:
        raise IoError.of_kind(E_TEXT, ErrorKind.InvalidData)
    var year = _digits(t, at, width)
    _expect(t, at, _DASH)
    var month = _digits(t, at, 2)
    _expect(t, at, _DASH)
    var day = _digits(t, at, 2)
    if year < 1 or month < 1 or month > 12 or day < 1 or day > 31:
        raise IoError.of_kind(E_TEXT, ErrorKind.InvalidData)
    return Date(year, month, day, 0)


def _bc(t: Span[UInt8, _], mut at: Int, mut d: Date):
    """A trailing " BC": astronomical years count 1 BC as 0."""
    if len(t) - at == 3 and t[at] == _SPACE and t[at + 1] == _B and t[at + 2] == _C:
        d.year = 1 - d.year
        at += 3


def _is(t: Span[UInt8, _], word: StringSlice) -> Bool:
    var w = word.as_bytes()
    if len(t) != len(w):
        return False
    for i in range(len(w)):
        if t[i] != w[i]:
            return False
    return True


def parse_date(t: Span[UInt8, _]) raises IoError -> Date:
    """A date in the server's ISO text form ("2024-02-29", "0044-03-15 BC",
    "infinity")."""
    if _is(t, "infinity"):
        return Date(0, 0, 0, 1)
    if _is(t, "-infinity"):
        return Date(0, 0, 0, -1)
    var at = 0
    var d = _ymd(t, at)
    _bc(t, at, d)
    if at != len(t):
        raise IoError.of_kind(E_TEXT, ErrorKind.InvalidData)
    _check_day(d)
    return d


def parse_timestamp_us(t: Span[UInt8, _]) raises IoError -> Int:
    """A timestamp or timestamptz in the server's ISO text form, as
    microseconds since 1970-01-01 00:00:00 (UTC when it carries an offset):
    "2024-02-29 13:45:00.5", "2024-02-29 13:45:00+05:30", "infinity"."""
    if _is(t, "infinity"):
        return Int.MAX
    if _is(t, "-infinity"):
        return Int.MIN
    var at = 0
    var d = _ymd(t, at)
    _expect(t, at, _SPACE)
    var h = _digits(t, at, 2)
    _expect(t, at, _COLON)
    var m = _digits(t, at, 2)
    _expect(t, at, _COLON)
    var s = _digits(t, at, 2)
    var us = 0
    if at < len(t) and t[at] == _DOT:
        at += 1
        var n = 0
        while at < len(t) and t[at] >= 48 and t[at] <= 57 and n < 6:
            us = us * 10 + Int(t[at]) - 48
            at += 1
            n += 1
        if n == 0:
            raise IoError.of_kind(E_TEXT, ErrorKind.InvalidData)
        for _ in range(6 - n):
            us *= 10
    var offset = 0
    if at < len(t) and (t[at] == _PLUS or t[at] == _DASH):
        var sign = 1 if t[at] == _PLUS else -1
        at += 1
        var three = at + 2 < len(t) and t[at + 2] >= 48 and t[at + 2] <= 57  # (POSIX zones reach 167 hours)
        offset = _digits(t, at, 3 if three else 2) * 3600
        if at < len(t) and t[at] == _COLON:
            at += 1
            offset += _digits(t, at, 2) * 60
            if at < len(t) and t[at] == _COLON:
                at += 1
                offset += _digits(t, at, 2)
        offset *= sign
    _bc(t, at, d)
    if at != len(t) or h > 23 or m > 59 or s > 59:
        raise IoError.of_kind(E_TEXT, ErrorKind.InvalidData)
    _check_day(d)
    var secs = d.days_since_1970() * 86400 + h * 3600 + m * 60 + s - offset
    # Past what microseconds since 1970 can hold (PostgreSQL goes 29 years
    # beyond), and never onto the infinity sentinels.
    if secs > (Int.MAX - 1 - us) // 1000000 or secs < -(Int.MAX // 1000000 - 1):
        raise IoError.of_kind("pg: timestamp out of range for microseconds since 1970", ErrorKind.InvalidData)
    return secs * 1000000 + us


def parse_bytea(t: Span[UInt8, _]) raises IoError -> List[UInt8]:
    """A bytea in the server's text form: hex ("\\x" then two hex digits
    per byte, `bytea_output = hex`, the default) or escape ("\\\\" for a
    backslash, a backslash and three octal digits for a byte, the other
    bytes as they are)."""
    if len(t) >= 2 and t[0] == _BACKSLASH and t[1] == _X:
        if len(t) % 2 != 0:
            raise IoError.of_kind(E_TEXT, ErrorKind.InvalidData)
        var out = List[UInt8](capacity=(len(t) - 2) // 2)
        for i in range(2, len(t), 2):
            var hi = _hex(t[i])
            var lo = _hex(t[i + 1])
            if hi < 0 or lo < 0:
                raise IoError.of_kind(E_TEXT, ErrorKind.InvalidData)
            out.append(UInt8(hi * 16 + lo))
        return out^
    var out = List[UInt8](capacity=len(t))
    var i = 0
    while i < len(t):
        if t[i] != _BACKSLASH:
            out.append(t[i])
            i += 1
        elif i + 1 < len(t) and t[i + 1] == _BACKSLASH:
            out.append(_BACKSLASH)
            i += 2
        else:
            if i + 3 >= len(t):  # (three octal digits must follow)
                raise IoError.of_kind(E_TEXT, ErrorKind.InvalidData)
            var v = 0
            for k in range(1, 4):
                var c = t[i + k]
                if c < 48 or c > 55:
                    raise IoError.of_kind(E_TEXT, ErrorKind.InvalidData)
                v = v * 8 + Int(c) - 48
            if v > 255:
                raise IoError.of_kind(E_TEXT, ErrorKind.InvalidData)
            out.append(UInt8(v))
            i += 4
    return out^


def _hex(c: UInt8) -> Int:
    if c >= 48 and c <= 57:
        return Int(c) - 48
    if c >= 97 and c <= 102:
        return Int(c) - 87
    if c >= 65 and c <= 70:
        return Int(c) - 55
    return -1
