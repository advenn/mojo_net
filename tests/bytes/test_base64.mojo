"""`bytes.base64`: the RFC 4648 section 10 vectors, round trips of random
data, and decoding random strings differentially against Python's
`base64.b64decode(validate=True)`: what it accepts, refuses, and gives."""

from std.python import Python
from std.random import random_ui64, seed
from std.testing import TestSuite, assert_equal, assert_true

from bytes.base64 import base64_decode, base64_encode


def _text(b: List[UInt8]) -> String:
    return String(from_utf8_lossy=Span(b))


def test_rfc_4648_vectors() raises:
    var cases = [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="),
                 ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")]
    for i in range(len(cases)):
        var plain = String(cases[i][0])
        var coded = String(cases[i][1])
        assert_equal(base64_encode(plain.as_bytes()), coded)
        assert_equal(_text(base64_decode(coded)), plain)


def _rand(n: Int) -> Int:
    return Int(random_ui64(0, UInt64(n - 1)))


def test_round_trips_and_python() raises:
    seed(4648)
    var base64 = Python.import_module("base64")
    var builtins = Python.import_module("builtins")
    for _ in range(500):
        var n = _rand(100)
        var data = List[UInt8](capacity=n)
        var l = Python.list()
        for _ in range(n):
            var b = _rand(256)
            data.append(UInt8(b))
            _ = l.append(b)
        var coded = base64_encode(Span(data))
        assert_equal(coded, String(py=base64.b64encode(builtins.bytes(l)).decode()))
        var back = base64_decode(coded)
        assert_equal(len(back), n)
        for i in range(n):
            assert_equal(back[i], data[i])
    var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_ !".as_bytes()
    var accepted = 0
    for _ in range(2000):
        var t = String()
        for _ in range(_rand(13)):
            t += chr(Int(alphabet[_rand(len(alphabet))]))
        var mine: String
        try:
            var d = base64_decode(t)
            mine = String("ok ", len(d))
            accepted += 1
            for b in d:
                mine += String(" ", b)
        except:
            mine = "refused"
        var theirs: String
        try:
            var r = base64.b64decode(t, validate=True)
            theirs = String("ok ", Int(py=builtins.len(r)))
            for x in r:
                theirs += String(" ", Int(py=x))
        except:
            theirs = "refused"
        assert_equal(mine, theirs, t)
    assert_true(accepted > 200 and accepted < 1800, String(accepted))  # both outcomes


def test_every_ascii_character_in_every_position() raises:
    # each of the 128 ASCII characters (so the neighbours of every alphabet
    # range: "@", "[", "`", "{", ".", ":") in each place of a quantum,
    # unpadded and padded, against Python
    var base64 = Python.import_module("base64")
    var builtins = Python.import_module("builtins")
    var accepted = 0
    for base in ["QUJD", "QUI=", "QQ=="]:
        var b = String(base).as_bytes()
        for at in range(4):
            for c in range(128):
                var t = String()
                for k in range(4):
                    t += chr(c) if k == at else chr(Int(b[k]))
                var mine: String
                try:
                    var d = base64_decode(t)
                    mine = String("ok")
                    for x in d:
                        mine += String(" ", x)
                    accepted += 1
                except:
                    mine = "refused"
                var theirs: String
                try:
                    var r = base64.b64decode(t, validate=True)
                    theirs = String("ok")
                    for x in r:
                        theirs += String(" ", Int(py=x))
                except:
                    theirs = "refused"
                assert_equal(mine, theirs, String(base, " ", at, " ", c))
    assert_true(accepted > 600, String(accepted))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
