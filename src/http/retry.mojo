"""When to try again: `retry_after` reads a 429 or 503 response's
`Retry-After` (RFC 9110 10.2.3), or the `retry-after-ms` that OpenAI's API
sends, and `parse_http_date` reads the HTTP-dates it may hold.

Sans-I/O: the caller passes the time (`now_unix`, seconds since the Unix
epoch), so tests and replays can fix it.
"""

from linux.time import Duration

from .headers import Headers

comptime _MONTHS = "JanFebMarAprMayJunJulAugSepOctNovDec"
comptime _DAYS = "MonTueWedThuFriSatSun"
comptime _LONG_DAYS: List[StaticString] = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def retry_after(headers: Headers, now_unix: Int) -> Optional[Duration]:
    """How long to wait, from the response's headers: `retry-after-ms`
    (a non-negative number of milliseconds, fractions allowed) first, then
    `Retry-After` as delay-seconds or as an HTTP-date (a past date is 0).
    None when neither is there or neither reads (a malformed value is
    ignored, as RFC 9110 lets a recipient do)."""
    var ms = headers.get("retry-after-ms")
    if ms:
        var v = _millis(String(ms.value()))
        if v:
            return v.value()
    var ra = headers.get("retry-after")
    if not ra:
        return None
    var text = String(ra.value()).strip()
    var b = text.as_bytes()
    if len(b) > 0 and _all_digits(b):
        if len(b) > 10:
            return Duration.from_secs(Int(UInt32.MAX))  # (absurdly long: wait "forever")
        return Duration.from_secs(_num(b, 0, len(b)))
    var at = parse_http_date(text)
    if not at:
        return None
    return Duration.from_secs(max(0, at.value() - now_unix))


def parse_http_date(text: StringSlice) -> Optional[Int]:
    """An HTTP-date (RFC 9110 5.6.7) as seconds since the Unix epoch, in
    any of the three forms a recipient must accept: IMF-fixdate
    (`Sun, 06 Nov 1994 08:49:37 GMT`), RFC 850 (`Sunday, 06-Nov-94
    08:49:37 GMT`; a two-digit year from 70 on is 19xx, else 20xx, which is
    RFC 9110's 50-year rule until 2020+50), and asctime (`Sun Nov  6
    08:49:37 1994`). The weekday is checked for its spelling only.
    None for anything else, or an impossible date."""
    var s = String(text).strip()
    var b = s.as_bytes()
    var n = len(b)
    # IMF-fixdate: 29 bytes.
    if n == 29 and b[3] == 44 and b[4] == 32 and _tail_is(b, " GMT"):
        if not _day_name(b[0:3]):
            return None
        var day = _num(b, 5, 2)
        var month = _month(b[8:11])
        var year = _num(b, 12, 4)
        if b[7] != 32 or b[11] != 32 or b[16] != 32:
            return None
        return _clock(b, 17, day, month, year)
    # asctime: 24 bytes, the day padded with a space.
    if n == 24 and b[3] == 32 and b[7] == 32 and b[10] == 32 and b[19] == 32:
        if not _day_name(b[0:3]):
            return None
        var month = _month(b[4:7])
        var day = _num(b, 9, 1) if b[8] == 32 else _num(b, 8, 2)
        var year = _num(b, 20, 4)
        return _clock(b, 11, day, month, year)
    # RFC 850: Weekday, DD-Mon-YY HH:MM:SS GMT
    var comma = s.find(", ")
    if comma > 0 and n == comma + 2 + 22 and _tail_is(b, " GMT"):
        var name = String(s[byte=0:comma])
        var known = False
        for d in materialize[_LONG_DAYS]():
            if name == d:
                known = True
        if not known:
            return None
        var p = comma + 2
        if b[p + 2] != 45 or b[p + 6] != 45 or b[p + 9] != 32:
            return None
        var day = _num(b, p, 2)
        var month = _month(b[p + 3 : p + 6])
        var yy = _num(b, p + 7, 2)
        if yy < 0:
            return None
        var year = 1900 + yy if yy >= 70 else 2000 + yy
        return _clock(b, p + 10, day, month, year)
    return None


def _clock(b: Span[UInt8, _], at: Int, day: Int, month: Int, year: Int) -> Optional[Int]:
    """`HH:MM:SS` at `at`, with the date: seconds since the epoch."""
    if b[at + 2] != 58 or b[at + 5] != 58:
        return None
    var h = _num(b, at, 2)
    var m = _num(b, at + 3, 2)
    var sec = _num(b, at + 6, 2)
    if day < 1 or month < 1 or year < 1970 or h < 0 or h > 23 or m < 0 or m > 59 or sec < 0 or sec > 60:
        return None
    if day > _days_in(month, year):
        return None
    return _days_from_civil(year, month, day) * 86400 + h * 3600 + m * 60 + sec


def _days_in(month: Int, year: Int) -> Int:
    if month == 2:
        var leap = (year % 4 == 0 and year % 100 != 0) or year % 400 == 0
        return 29 if leap else 28
    if month == 4 or month == 6 or month == 9 or month == 11:
        return 30
    return 31


def _days_from_civil(y0: Int, m: Int, d: Int) -> Int:
    """Days since 1970-01-01 (Howard Hinnant's algorithm)."""
    var y = y0 - 1 if m <= 2 else y0
    var era = (y if y >= 0 else y - 399) // 400
    var yoe = y - era * 400
    var mp = m - 3 if m > 2 else m + 9
    var doy = (153 * mp + 2) // 5 + d - 1
    var doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _num(b: Span[UInt8, _], at: Int, count: Int) -> Int:
    """`count` ASCII digits at `at`, or -1."""
    if at < 0 or at + count > len(b):
        return -1
    var v = 0
    for i in range(at, at + count):
        var c = b[i]
        if c < 48 or c > 57:
            return -1
        v = v * 10 + Int(c) - 48
    return v


def _month(b: Span[UInt8, _]) -> Int:
    var names = _MONTHS.as_bytes()
    for i in range(12):
        if b[0] == names[3 * i] and b[1] == names[3 * i + 1] and b[2] == names[3 * i + 2]:
            return i + 1
    return -1


def _day_name(b: Span[UInt8, _]) -> Bool:
    var names = _DAYS.as_bytes()
    for i in range(7):
        if b[0] == names[3 * i] and b[1] == names[3 * i + 1] and b[2] == names[3 * i + 2]:
            return True
    return False


def _tail_is(b: Span[UInt8, _], tail: StaticString) -> Bool:
    var t = tail.as_bytes()
    if len(b) < len(t):
        return False
    for i in range(len(t)):
        if b[len(b) - len(t) + i] != t[i]:
            return False
    return True


def _all_digits(b: Span[UInt8, _]) -> Bool:
    for c in b:
        if c < 48 or c > 57:
            return False
    return True


def _millis(text: String) -> Optional[Duration]:
    """A non-negative decimal number of milliseconds ("1500", "20.5")."""
    var t = text.strip()
    var b = t.as_bytes()
    if len(b) == 0 or len(b) > 15:
        return None
    var whole = 0
    var frac_ns = 0
    var scale = 100_000  # (ns per tenth of a millisecond)
    var dot = False
    var digits = 0
    for c in b:
        if c == 46 and not dot:
            dot = True
            continue
        if c < 48 or c > 57:
            return None
        digits += 1
        if not dot:
            whole = whole * 10 + Int(c) - 48
        elif scale >= 1:
            frac_ns += (Int(c) - 48) * scale
            scale //= 10
    if digits == 0:
        return None
    return Duration.from_nanos(whole * 1_000_000 + frac_ns)
