"""`server.date`: `http_date` against Python's `email.utils.formatdate`
(usegmt=True) over the epoch, leap days, century and 400-year rules, 2038
and beyond, and random instants; `DateCache` against the system clock."""

from std.python import Python
from std.testing import TestSuite, assert_equal, assert_true

from server.date import DateCache, http_date


def test_matches_python_formatdate() raises:
    var eu = Python.import_module("email.utils")
    var random = Python.import_module("random")
    var rng = random.Random(9110)
    var times = List[Int]()
    for t in [0, 59, 86399, 86400, 951782400, 951868800, 4107542400, 4107456000, 2147483647, 2147483648, 253402300799, 784111777]:
        times.append(t)  # epoch, 2000-02-29/03-01, 2100-03-01/02-28, 2038, 9999-12-31, RFC 9110's example
    for _ in range(3000):
        times.append(Int(py=rng.randrange(0, 253402300800)))
    for t in times:
        var want = String(py=eu.formatdate(t, usegmt=True))
        assert_equal(http_date(t), want, String(t))
    assert_equal(http_date(784111777), "Sun, 06 Nov 1994 08:49:37 GMT")


def test_cache_follows_the_clock() raises:
    var time = Python.import_module("time")
    var eu = Python.import_module("email.utils")
    var cache = DateCache()
    var before = Int(py=time.time())
    var got = String(cache.get())
    var after = Int(py=time.time())
    var ok = False
    for t in range(before, after + 1):
        if got == String(py=eu.formatdate(t, usegmt=True)):
            ok = True
    assert_true(ok, got)
    assert_equal(String(cache.get()).byte_length(), 29)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
