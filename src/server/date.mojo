"""HTTP dates (RFC 9110 5.6.7): `http_date` formats a Unix time as an
IMF-fixdate, `Sun, 06 Nov 1994 08:49:37 GMT`, and `DateCache` keeps the
current one, reformatted at most once a second (every response carries a
Date field)."""

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
