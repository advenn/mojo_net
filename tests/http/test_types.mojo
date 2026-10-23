"""`http.types`: versions, status classes and checks, and reason phrases
against Python's `http.HTTPStatus` (the IANA registry) as the oracle."""

from std.python import Python
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from http.types import (
    CONNECT,
    DELETE,
    GET,
    HEAD,
    OPTIONS,
    PATCH,
    POST,
    PUT,
    TRACE,
    Version,
    check_status,
    is_client_error,
    is_informational,
    is_redirect,
    is_server_error,
    is_success,
    reason,
)
from linux import ErrorKind, IoError


def test_version() raises:
    assert_true(Version(1, 1) == Version.HTTP_1_1)
    assert_false(Version(1, 0) == Version.HTTP_1_1)
    assert_true(Version.HTTP_1_1.at_least_1_1())
    assert_false(Version.HTTP_1_0.at_least_1_1())
    assert_true(Version(1, 2).at_least_1_1())
    assert_true(Version(2, 0).at_least_1_1())
    assert_false(Version(0, 9).at_least_1_1())
    assert_equal(String(Version.HTTP_1_0), "HTTP/1.0")
    assert_equal(String(Version(1, 1)), "HTTP/1.1")


def test_methods_are_the_rfc_names() raises:
    var all = List[String]()
    for m in [GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH]:
        all.append(String(m))
    var joined = String()
    for m in all:
        joined += m + " "
    assert_equal(joined, "GET HEAD POST PUT DELETE CONNECT OPTIONS TRACE PATCH ")


def test_status_classes_at_the_boundaries() raises:
    for s in range(90, 610):
        var classes = (
            Int(is_informational(s))
            + Int(is_success(s))
            + Int(is_redirect(s))
            + Int(is_client_error(s))
            + Int(is_server_error(s))
        )
        assert_equal(classes, 1 if s >= 100 and s <= 599 else 0)
        var ok = True
        try:
            check_status(s, "test")
        except e:
            assert_true(e.kind == ErrorKind.InvalidInput)
            ok = False
        assert_equal(ok, s >= 100 and s <= 599)
    assert_true(is_informational(199) and is_success(200))
    assert_true(is_success(299) and is_redirect(300))
    assert_true(is_redirect(399) and is_client_error(400))
    assert_true(is_client_error(499) and is_server_error(500))


def test_reason_phrases_match_the_registry() raises:
    var py = Python.import_module("http")
    var known = Python.dict()
    for s in py.HTTPStatus:
        known[s.value] = s.phrase
    var named = 0
    for code in range(100, 600):
        var want = String()
        if code in known and code != 418:  # reserved (RFC 9110 15.5.19)
            want = String(known[code])
        assert_equal(String(reason(code)), want, String("status ", code))
        if want.byte_length() > 0:
            named += 1
    assert_true(named >= 60)
    assert_equal(String(reason(99)), "")
    assert_equal(String(reason(600)), "")
    assert_equal(String(reason(-1)), "")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
