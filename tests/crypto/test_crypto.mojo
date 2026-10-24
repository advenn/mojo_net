"""`crypto`: SHA-256 (FIPS 180-4), MD5 (RFC 1321), HMAC-SHA-256 (RFC 4231)
and PBKDF2-HMAC-SHA-256 (RFC 7914 section 11) against their published
vectors, then differentially against Python's hashlib and hmac over
random inputs (lengths across block boundaries, random incremental
splits, keys longer than a block); and the constant-time comparison."""

from std.python import Python, PythonObject
from std.random import random_ui64, seed
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from crypto import Md5, Sha256, equal_constant_time, hmac_sha256, md5, pbkdf2_hmac_sha256, sha256


def _hex(d: List[UInt8]) -> String:
    var digits = "0123456789abcdef".as_bytes()
    var out = String()
    for b in d:
        out += chr(Int(digits[Int(b) >> 4]))
        out += chr(Int(digits[Int(b) & 15]))
    return out^


def _bytes(text: StringSlice) -> List[UInt8]:
    var out = List[UInt8]()
    out.extend(text.as_bytes())
    return out^


def _repeat(b: UInt8, n: Int) -> List[UInt8]:
    return List[UInt8](length=n, fill=b)


def _unhex(text: StringSlice) raises -> List[UInt8]:
    var out = List[UInt8]()
    var t = text.as_bytes()
    for i in range(0, len(t), 2):
        out.append(UInt8(atol(String(text[byte = i : i + 2]), base=16)))
    return out^


def test_sha256_vectors() raises:
    assert_equal(_hex(sha256(_bytes(""))), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert_equal(_hex(sha256(_bytes("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    assert_equal(
        _hex(sha256(_bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    )
    assert_equal(
        _hex(sha256(_repeat(0x61, 1000000))),  # a million "a"
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    )


def test_md5_vectors() raises:
    # the RFC 1321 test suite
    assert_equal(_hex(md5(_bytes(""))), "d41d8cd98f00b204e9800998ecf8427e")
    assert_equal(_hex(md5(_bytes("a"))), "0cc175b9c0f1b6a831c399e269772661")
    assert_equal(_hex(md5(_bytes("abc"))), "900150983cd24fb0d6963f7d28e17f72")
    assert_equal(_hex(md5(_bytes("message digest"))), "f96b697d7cb7938d525a2f31aaf161d0")
    assert_equal(_hex(md5(_bytes("abcdefghijklmnopqrstuvwxyz"))), "c3fcd3d76192e4007dfb496cca67e13b")
    assert_equal(
        _hex(md5(_bytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))),
        "d174ab98d277d9f5a5611c2c9f419d9f",
    )
    assert_equal(
        _hex(md5(_bytes("12345678901234567890123456789012345678901234567890123456789012345678901234567890"))),
        "57edf4a22be3c955ac49da2e2107b67a",
    )


def test_hmac_sha256_vectors() raises:
    # RFC 4231 test cases 1-4, 6 and 7 (5 is truncated output, also checked)
    assert_equal(
        _hex(hmac_sha256(_repeat(0x0B, 20), _bytes("Hi There"))),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    )
    assert_equal(
        _hex(hmac_sha256(_bytes("Jefe"), _bytes("what do ya want for nothing?"))),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    )
    assert_equal(
        _hex(hmac_sha256(_repeat(0xAA, 20), _repeat(0xDD, 50))),
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    )
    assert_equal(
        _hex(hmac_sha256(_unhex("0102030405060708090a0b0c0d0e0f10111213141516171819"), _repeat(0xCD, 50))),
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    )
    assert_true(
        _hex(hmac_sha256(_repeat(0x0C, 20), _bytes("Test With Truncation"))).startswith(
            "a3b6167473100ee06e0c796c2955552b"
        )
    )
    assert_equal(
        _hex(hmac_sha256(_repeat(0xAA, 131), _bytes("Test Using Larger Than Block-Size Key - Hash Key First"))),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    )
    assert_equal(
        _hex(
            hmac_sha256(
                _repeat(0xAA, 131),
                _bytes(
                    "This is a test using a larger than block-size key and a larger than block-size data."
                    " The key needs to be hashed before being used by the HMAC algorithm."
                ),
            )
        ),
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    )


def test_pbkdf2_vectors() raises:
    # RFC 7914 section 11
    assert_equal(
        _hex(pbkdf2_hmac_sha256(_bytes("passwd"), _bytes("salt"), 1, 64)),
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        + "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
    )
    assert_equal(
        _hex(pbkdf2_hmac_sha256(_bytes("Password"), _bytes("NaCl"), 80000, 64)),
        "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
        + "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
    )
    for bad in [(0, 32), (1, 0)]:
        var refused = False
        try:
            _ = pbkdf2_hmac_sha256(_bytes("p"), _bytes("s"), bad[0], bad[1])
        except:
            refused = True
        assert_true(refused)


def _rand(n: Int) -> Int:
    return Int(random_ui64(0, UInt64(n - 1)))


def _random_bytes(n: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for _ in range(n):
        out.append(UInt8(_rand(256)))
    return out^


def _py(b: List[UInt8]) raises -> PythonObject:
    var builtins = Python.import_module("builtins")
    var l = Python.list()
    for x in b:
        _ = l.append(Int(x))
    return builtins.bytes(l)


def test_against_hashlib_and_hmac() raises:
    seed(20261024)
    var hashlib = Python.import_module("hashlib")
    var hmac = Python.import_module("hmac")
    for _ in range(300):
        var n = _rand(300)
        var data = _random_bytes(n)
        var pd = _py(data)
        assert_equal(_hex(sha256(Span(data))), String(py=hashlib.sha256(pd).hexdigest()))
        assert_equal(_hex(md5(Span(data))), String(py=hashlib.md5(pd).hexdigest()))
        # the same, fed in random pieces
        var s = Sha256()
        var m = Md5()
        var i = 0
        while i < n:
            var k = min(n - i, 1 + _rand(80))
            s.update(Span(data)[i : i + k])
            m.update(Span(data)[i : i + k])
            i += k
        assert_equal(_hex(s^.digest()), String(py=hashlib.sha256(pd).hexdigest()))
        assert_equal(_hex(m^.digest()), String(py=hashlib.md5(pd).hexdigest()))
        var key = _random_bytes(_rand(200))  # (often past the 64-byte block)
        assert_equal(
            _hex(hmac_sha256(Span(key), Span(data))),
            String(py=hmac.new(_py(key), pd, "sha256").hexdigest()),
        )
    var lengths = [1, 4, 31, 32, 33, 64, 65]
    for iters in range(1, 5):  # (the first rounds, and output block edges)
        for length in lengths:
            var pw = _random_bytes(_rand(100))
            var salt = _random_bytes(_rand(40))
            assert_equal(
                _hex(pbkdf2_hmac_sha256(Span(pw), Span(salt), iters, length)),
                String(py=hashlib.pbkdf2_hmac("sha256", _py(pw), _py(salt), iters, length).hex()),
            )
    for _ in range(40):
        var pw = _random_bytes(_rand(100))
        var salt = _random_bytes(_rand(40))
        var iters = 1 + _rand(50)
        var length = 1 + _rand(100)  # (more than one block of output too)
        assert_equal(
            _hex(pbkdf2_hmac_sha256(Span(pw), Span(salt), iters, length)),
            String(py=hashlib.pbkdf2_hmac("sha256", _py(pw), _py(salt), iters, length).hex()),
        )


def test_every_length_and_key_size() raises:
    # every message length over three blocks (the padding edges at 55 and
    # 56 bytes mod 64 included), and every key size around one and two
    # blocks (a key of 64 bytes is used as is, of 65 hashed first)
    var hashlib = Python.import_module("hashlib")
    var hmac = Python.import_module("hmac")
    var data = List[UInt8](capacity=200)
    for i in range(200):
        data.append(UInt8((i * 37 + 11) % 256))
    for n in range(200):
        var piece = List[UInt8](Span(data)[:n])
        var pd = _py(piece)
        assert_equal(_hex(sha256(Span(piece))), String(py=hashlib.sha256(pd).hexdigest()))
        assert_equal(_hex(md5(Span(piece))), String(py=hashlib.md5(pd).hexdigest()))
    var message = _bytes("what do ya want for nothing?")
    for n in range(140):
        var key = List[UInt8](Span(data)[:n])
        assert_equal(
            _hex(hmac_sha256(Span(key), Span(message))),
            String(py=hmac.new(_py(key), _py(message), "sha256").hexdigest()),
        )


def test_constant_time_compare() raises:
    assert_true(equal_constant_time(_bytes("abc"), _bytes("abc")))
    assert_false(equal_constant_time(_bytes("abc"), _bytes("abd")))
    assert_false(equal_constant_time(_bytes("abc"), _bytes("xbc")))
    assert_false(equal_constant_time(_bytes("abc"), _bytes("ab")))
    assert_true(equal_constant_time(_bytes(""), _bytes("")))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
