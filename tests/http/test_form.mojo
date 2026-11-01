"""`http.form` (2026-11 analysis, finding form-query-cookies: there was no
query, form or cookie decoding anywhere, and apps wrote their own):
`percent_decode`, `parse_query` and `parse_form` against Python's
`urllib.parse.parse_qsl` (with keep_blank_values and strict UTF-8) as the
oracle, over random strings; where Python accepts a malformed escape as
literal text, ours must refuse it. `parse_cookie` and `SetCookie` by
cases from RFC 6265."""

from std.os import getenv
from std.python import Python, PythonObject
from std.random import random_ui64, seed
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from http.form import Pairs, SetCookie, parse_cookie, parse_form, parse_query, percent_decode
from linux import ErrorKind, IoError


def _env(name: StaticString, default: Int) raises -> Int:
    """A fuzz setting from the environment (the weekly fuzz run,
    tools/fuzz_long.sh): MOJO_NET_FUZZ_SEED shifts the seed,
    MOJO_NET_FUZZ_SCALE multiplies the cases."""
    var v = getenv(name)
    return atol(v) if v.byte_length() > 0 else default


def _rand(n: Int) -> Int:
    return Int(random_ui64(0, UInt64(n - 1)))


def _random_query() -> String:
    var pieces: List[String] = ["a", "b", "=", "&", "+", "%", "%2", "%41", "%c3%a9", "%E2%82", "%ff", "%zz", "é", "x y", "%26", "%3D", "", "0"]
    var s = String()
    for _ in range(_rand(8)):
        s += pieces[_rand(len(pieces))]
    return s^


def _is_hex(c: UInt8) -> Bool:
    return (c >= 48 and c <= 57) or (c >= 65 and c <= 70) or (c >= 97 and c <= 102)


def _malformed(q: String) -> Bool:
    """A "%" not followed by two hex digits."""
    var b = q.as_bytes()
    for i in range(len(b)):
        if b[i] == 37 and (i + 2 >= len(b) or not _is_hex(b[i + 1]) or not _is_hex(b[i + 2])):
            return True
    return False


def test_parse_query_matches_parse_qsl() raises:
    var first = _env("MOJO_NET_FUZZ_SEED", 0)
    var scale = _env("MOJO_NET_FUZZ_SCALE", 1)
    seed(1101 + first)
    var parse = Python.import_module("urllib.parse")
    var checked = 0
    var refused = 0
    for i in range(3000 * scale):
        var q = _random_query()
        var mine: Optional[Pairs] = None
        try:
            mine = parse_query(q)
        except e:
            assert_equal(e.kind, ErrorKind.InvalidData)
        var theirs: PythonObject
        var python_ok = True
        try:
            theirs = parse.parse_qsl(q, keep_blank_values=True, errors="strict")
        except:
            python_ok = False
            theirs = PythonObject(None)
        if not mine:
            # Refused: Python refuses it too (not UTF-8), or it has a
            # malformed escape that Python keeps as text.
            assert_true(not python_ok or _malformed(q), String(i, ": refused ", repr(q)))
            refused += 1
            continue
        assert_true(python_ok, String(i, ": accepted ", repr(q)))
        assert_false(_malformed(q), String(i, ": accepted ", repr(q)))
        ref p = mine.value()
        assert_equal(len(p), Int(py=theirs.__len__()), String(i, ": ", repr(q)))
        for k in range(len(p)):
            assert_equal(p.name(k), String(theirs[k][0]), String(i, ": ", repr(q)))
            assert_equal(p.value(k), String(theirs[k][1]), String(i, ": ", repr(q)))
        checked += 1
    assert_true(checked > 1000 * scale and refused > 300 * scale, String(checked, " checked, ", refused, " refused"))


def test_pairs_by_name_and_limits() raises:
    var p = parse_query("a=1&b=x+y&a=2&flag&c=%E2%82%AC")
    assert_equal(len(p), 5)
    assert_equal(p.get("a").value(), "1")
    assert_equal(len(p.get_all("a")), 2)
    assert_equal(p.get_all("a")[1], "2")
    assert_equal(p.get("b").value(), "x y")
    assert_equal(p.get("flag").value(), "")
    assert_equal(p.get("c").value(), "€")
    assert_false(Bool(p.get("d")))
    var many = String()
    for i in range(1001):
        many += String("k", i, "=v&")
    var over = False
    try:
        _ = parse_query(many)
    except e:
        over = e.kind == ErrorKind.InvalidData
    assert_true(over, "1001 pairs over the default limit")
    assert_equal(len(parse_query(many, limit=2000)), 1001)
    var form = parse_form("name=Ada+Lovelace&lang=mojo".as_bytes())
    assert_equal(form.get("name").value(), "Ada Lovelace")
    assert_equal(percent_decode("a+b%20c"), "a+b c")
    assert_equal(percent_decode("a+b%20c", plus_is_space=True), "a b c")


def test_cookies() raises:
    var c = parse_cookie('sid=abc123; theme="dark";  lang=uz ;bad name=1; x=a,b; =v; empty=')
    assert_equal(len(c), 4)
    assert_equal(c.get("sid").value(), "abc123")
    assert_equal(c.get("theme").value(), "dark")
    assert_equal(c.get("lang").value(), "uz")
    assert_equal(c.get("empty").value(), "")
    assert_false(Bool(c.get("x")))  # ("," is no cookie octet)
    var s = SetCookie("sid", "abc123")
    s.path = "/"
    s.max_age = 3600
    s.secure = True
    s.http_only = True
    s.same_site = "Lax"
    assert_equal(s.text(), "sid=abc123; Path=/; Max-Age=3600; SameSite=Lax; Secure; HttpOnly")
    # Nothing can end the value or add an attribute.
    for bad in ["a;b", "a b", "a\r\nX: 1", 'a"b']:
        var refused = False
        try:
            _ = SetCookie("sid", bad).text()
        except e:
            refused = e.kind == ErrorKind.InvalidInput
        assert_true(refused, repr(bad))
    var path = SetCookie("sid", "1")
    path.path = "/; Domain=evil.example"
    var none = SetCookie("sid", "1")
    none.same_site = "None"
    for bad_cookie in [path.copy(), none.copy(), SetCookie("a b", "1")]:
        var refused = False
        try:
            _ = bad_cookie.text()
        except:
            refused = True
        assert_true(refused, bad_cookie.name)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
