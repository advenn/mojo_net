"""HTTP dates (RFC 9110 5.6.7): `http_date` formats a Unix time as an
IMF-fixdate, `Sun, 06 Nov 1994 08:49:37 GMT`; `parse_http_date` reads any
of the three forms recipients must accept; `DateCache` keeps the current
date, reformatted at most once a second (every response carries a Date
field)."""

from linux.time import NANOS_PER_SEC, Duration, Instant, unix_time_ns

comptime _DAYS = "SunMonTueWedThuFriSat"
comptime _MONTHS = "JanFebMarAprMayJunJulAugSepOctNovDec"


@fieldwise_init
struct _Civil(TrivialRegisterPassable):
    var year: Int
    var month: Int
    var day: Int


def _civil_from_days(days: Int) -> _Civil:
    """The proleptic Gregorian date `days` after 1970-01-01 (Howard
    Hinnant's algorithm, exact for any Int)."""
    var z = days + 719468
    var era = (z if z >= 0 else z - 146096) // 146097
    var doe = z - era * 146097
    var yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    var doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    var mp = (5 * doy + 2) // 153
    var d = doy - (153 * mp + 2) // 5 + 1
    var m = mp + 3 if mp < 10 else mp - 9
    var y = yoe + era * 400 + (1 if m <= 2 else 0)
    return _Civil(y, m, d)


def _days_from_civil(y: Int, m: Int, d: Int) -> Int:
    """Days from 1970-01-01 to the proleptic Gregorian y-m-d (Hinnant)."""
    var yy = y - 1 if m <= 2 else y
    var era = (yy if yy >= 0 else yy - 399) // 400
    var yoe = yy - era * 400
    var mp = m - 3 if m > 2 else m + 9
    var doy = (153 * mp + 2) // 5 + d - 1
    var doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _num(t: Span[UInt8, _], start: Int, n: Int) -> Int:
    """The n-digit number at `start` ("  6" style space padding allowed
    before the digits), or -1."""
    if start + n > len(t):
        return -1
    var v = 0
    var digits = 0
    for i in range(start, start + n):
        var b = t[i]
        if b == 32 and digits == 0:
            continue
        if b < 48 or b > 57:
            return -1
        v = v * 10 + Int(b) - 48
        digits += 1
    return v if digits > 0 else -1


def _month(t: Span[UInt8, _], start: Int) -> Int:
    """1..12 for the month name at `start`, or -1."""
    if start + 3 > len(t):
        return -1
    var months = _MONTHS.as_bytes()
    for m in range(12):
        if t[start] == months[m * 3] and t[start + 1] == months[m * 3 + 1] and t[start + 2] == months[m * 3 + 2]:
            return m + 1
    return -1


def _is(t: Span[UInt8, _], at: Int, text: StringSlice) -> Bool:
    var b = text.as_bytes()
    if at + len(b) > len(t):
        return False
    for i in range(len(b)):
        if t[at + i] != b[i]:
            return False
    return True


def _clock(t: Span[UInt8, _], at: Int) -> Int:
    """Seconds into the day of "hh:mm:ss" at `at`, or -1."""
    var h = _num(t, at, 2)
    var mi = _num(t, at + 3, 2)
    var sec = _num(t, at + 6, 2)
    if not (_is(t, at + 2, ":") and _is(t, at + 5, ":")):
        return -1
    if h < 0 or h > 23 or mi < 0 or mi > 59 or sec < 0 or sec > 60:
        return -1
    return h * 3600 + mi * 60 + sec


def parse_http_date(text: StringSlice) -> Optional[Int]:
    """The Unix time of an HTTP-date in any of its three forms, which
    recipients must all accept (RFC 9110 5.6.7): IMF-fixdate
    `Sun, 06 Nov 1994 08:49:37 GMT`, RFC 850's `Sunday, 06-Nov-94 08:49:37
    GMT` and asctime's `Sun Nov  6 08:49:37 1994`. None if malformed. An
    RFC 850 two-digit year is the latest year with those digits that is
    not more than 50 years ahead."""
    var t = text.as_bytes()
    var n = len(t)
    var year: Int
    var month: Int
    var day: Int
    var secs: Int
    if n == 29 and _is(t, 3, ", ") and _is(t, 25, " GMT"):  # IMF-fixdate
        if not (_is(t, 7, " ") and _is(t, 11, " ") and _is(t, 16, " ")):
            return None
        day = _num(t, 5, 2)
        month = _month(t, 8)
        year = _num(t, 12, 4)
        secs = _clock(t, 17)
    elif n == 24 and _is(t, 3, " ") and _is(t, 7, " ") and _is(t, 10, " "):  # asctime
        if not (_is(t, 19, " ")):
            return None
        month = _month(t, 4)
        day = _num(t, 8, 2)
        secs = _clock(t, 11)
        year = _num(t, 20, 4)
    else:  # RFC 850: the weekday spelled out, then ", dd-Mon-yy hh:mm:ss GMT"
        var comma = -1
        for i in range(min(n, 10)):
            if t[i] == 44:
                comma = i
                break
        if comma < 6 or n != comma + 24 or not _is(t, comma, ", ") or not _is(t, n - 4, " GMT"):
            return None
        var at = comma + 2
        if not (_is(t, at + 2, "-") and _is(t, at + 6, "-") and _is(t, at + 9, " ")):
            return None
        day = _num(t, at, 2)
        month = _month(t, at + 3)
        var yy = _num(t, at + 7, 2)
        secs = _clock(t, at + 10)
        if yy < 0:
            return None
        var now = _civil_from_days(Int(unix_time_ns() // NANOS_PER_SEC) // 86400).year
        year = (now // 100) * 100 + yy
        if year > now + 50:
            year -= 100
    if day < 1 or day > 31 or month < 1 or year < 0 or secs < 0:
        return None
    return _days_from_civil(year, month, day) * 86400 + secs


def _two(mut out: String, n: Int):
    out += chr(48 + n // 10)
    out += chr(48 + n % 10)


def http_date(unix_secs: Int) -> String:
    """`unix_secs` as an IMF-fixdate (always GMT, the only form a sender may
    generate). Years outside 0..9999 are clamped."""
    var days = unix_secs // 86400
    var sod = unix_secs - days * 86400
    var c = _civil_from_days(days)
    var weekday = (days + 4) % 7  # 1970-01-01 was a Thursday
    if weekday < 0:
        weekday += 7
    var year = min(max(c.year, 0), 9999)
    var out = String()
    out += _DAYS[byte = weekday * 3 : weekday * 3 + 3]
    out += ", "
    _two(out, c.day)
    out += " "
    out += _MONTHS[byte = (c.month - 1) * 3 : (c.month - 1) * 3 + 3]
    out += " "
    _two(out, year // 100)
    _two(out, year % 100)
    out += " "
    _two(out, sod // 3600)
    out += ":"
    _two(out, sod // 60 % 60)
    out += ":"
    _two(out, sod % 60)
    out += " GMT"
    return out^


struct DateCache(Movable):
    """The current HTTP date, reformatted when a new second begins. A
    server refreshes it once per loop turn with the monotonic time it has
    already read (`refresh`), and reads it per response (`current`): the
    wall clock is read at most once a second, since every clock read in
    this library is a real syscall (no vDSO without libc)."""

    var _text: String
    var _next: Instant
    """When (monotonic) the next second begins."""

    def __init__(out self):
        self._text = String()
        self._next = Instant(nanos=Int.MIN)

    def refresh(mut self, now: Instant):
        """Reformat if `now` is in a later second than the cached date."""
        if now < self._next:
            return
        var ns = unix_time_ns()
        var secs = ns // NANOS_PER_SEC
        self._text = http_date(secs)
        self._next = now + Duration.from_nanos(NANOS_PER_SEC - (ns - secs * NANOS_PER_SEC))

    def current(self) -> StringSlice[origin_of(self._text)]:
        """The date as of the last `refresh`."""
        return StringSlice(self._text)

    def get(mut self) -> StringSlice[origin_of(self._text)]:
        """The current date (reads the monotonic clock to know)."""
        self.refresh(Instant.now())
        return StringSlice(self._text)
