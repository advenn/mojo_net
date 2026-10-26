"""`http.retry`: HTTP-dates in their three forms against Python's
`email.utils` and `calendar.timegm` on random dates, impossible dates, and
`retry_after` for Retry-After and retry-after-ms."""

from std.python import Python
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from http.headers import Headers
from http.retry import parse_http_date, retry_after
from linux.time import Duration


def test_dates_match_python() raises:
    """3,000 random instants from 1970 to 2068, each in the three forms
    (tests/http/date_cases.py, checked against email.utils there)."""
    var sys = Python.import_module("sys")
    _ = sys.path.insert(0, "tests/http")
    var cases = Python.import_module("date_cases").cases(20261026, 3000)
    for c in cases:
        var text = String(py=c[0])
        var want = Int(py=c[1])
        var got = parse_http_date(text)
        assert_true(Bool(got), String("refused ", repr(text)))
        assert_equal(got.value(), want, text)


def _date(text: String) raises -> Int:
    var got = parse_http_date(text)
    if not got:
        raise Error(String("refused ", repr(text)))
    return got.value()


def _wait(h: Headers, now: Int) raises -> Duration:
    var got = retry_after(h, now)
    if not got:
        raise Error("no delay read")
    return got.value()


def test_the_rfcs_examples() raises:
    assert_equal(_date("Sun, 06 Nov 1994 08:49:37 GMT"), 784111777)
    assert_equal(_date("Sunday, 06-Nov-94 08:49:37 GMT"), 784111777)
    assert_equal(_date("Sun Nov  6 08:49:37 1994"), 784111777)
    assert_equal(_date("Thu, 01 Jan 1970 00:00:00 GMT"), 0)
    assert_equal(_date("Thu, 29 Feb 2024 12:00:00 GMT"), 1709208000)
    assert_equal(_date("Tue, 29 Feb 2000 00:00:00 GMT"), 951782400)  # (divisible by 400: a leap year)
    assert_equal(_date("Sun, 06 Nov 1994 08:49:60 GMT"), 784111800)  # (a leap second, as timegm counts it)
    # RFC 850's two-digit years: 70..99 are 19xx, 00..69 are 20xx.
    assert_equal(_date("Sunday, 22-Dec-69 15:56:42 GMT"), 3154953402)
    assert_equal(_date("Thursday, 01-Jan-70 00:00:00 GMT"), 0)
    assert_equal(_date("Monday, 01-Jan-50 00:00:00 GMT"), 2524608000)


def test_bad_dates() raises:
    var bad: List[String] = [
        "", "Sun, 06 Nov 1994 08:49:37 UTC", "Sun, 31 Nov 1994 08:49:37 GMT", "Sun, 29 Feb 2023 00:00:00 GMT",
        "Sun, 06 Nox 1994 08:49:37 GMT", "Xyz, 06 Nov 1994 08:49:37 GMT", "Sun, 06 Nov 1994 24:00:00 GMT",
        "Sun, 6 Nov 1994 08:49:37 GMT", "Sun,06 Nov 1994 08:49:37 GMT", "Sun, 06 Nov 1969 23:59:59 GMT",
        "Funday, 06-Nov-94 08:49:37 GMT", "Sun Nov 6 08:49:37 1994", "Sun, 06 Nov 1994 08:49:3x GMT", "1994-11-06T08:49:37Z",
        "Mon, 29 Feb 2100 00:00:00 GMT", "Sun, 06 Nov 1994 08:49:61 GMT", "Sun, 06 Nov 1994 08:60:00 GMT",
    ]
    for b in bad:
        assert_false(Bool(parse_http_date(b)), String("accepted ", repr(b)))


def test_retry_after() raises:
    var now = 784111777
    var h = Headers()
    h.add("Retry-After", "120")
    assert_equal(_wait(h, now), Duration.from_secs(120))
    var d = Headers()
    d.add("Retry-After", "Sun, 06 Nov 1994 08:50:37 GMT")
    assert_equal(_wait(d, now), Duration.from_secs(60))
    var past = Headers()
    past.add("Retry-After", "Sun, 06 Nov 1994 08:00:00 GMT")
    assert_equal(_wait(past, now), Duration.from_secs(0))
    var ms = Headers()
    ms.add("retry-after-ms", "1500.5")
    ms.add("Retry-After", "2")
    assert_equal(_wait(ms, now), Duration.from_nanos(1_500_500_000))
    var bad_ms = Headers()
    bad_ms.add("retry-after-ms", "-5")
    bad_ms.add("Retry-After", "3")
    assert_equal(_wait(bad_ms, now), Duration.from_secs(3))
    var junk = Headers()
    junk.add("Retry-After", "soon")
    assert_false(Bool(retry_after(junk, now)))
    assert_false(Bool(retry_after(Headers(), now)))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
