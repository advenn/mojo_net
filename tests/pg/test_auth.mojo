"""`pg.auth`: the MD5 answer and SCRAM-SHA-256 against RFC 7677's example
and the Python oracle's server side (hashlib and hmac, `pg_oracle.py`);
then every way an exchange is refused."""

from std.random import random_ui64, seed
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError
from pg.auth import MAX_SCRAM_ITERATIONS, ScramClient, md5_password
from pg_util import hex, oracle


def _rand(n: Int) -> Int:
    return Int(random_ui64(0, UInt64(n - 1)))


def _text(n: Int, ascii_only: Bool) -> String:
    """`n` random characters: printable ASCII, or a mix with non-ASCII."""
    var more = ["é", "ü", "€", "日", "本", "ß", "ø"]
    var out = String()
    for _ in range(n):
        if not ascii_only and _rand(4) == 0:
            out += more[_rand(len(more))]
        else:
            out += chr(0x21 + _rand(94))
    return out^


def _nonce(n: Int) -> String:
    """A random SCRAM nonce: printable ASCII without commas."""
    var out = String()
    while out.byte_length() < n:
        var c = 0x21 + _rand(94)
        if c != 44:
            out += chr(c)
    return out^


def test_md5_answer_matches_the_oracle() raises:
    seed(5)
    var o = oracle()
    for _ in range(50):
        var user = _text(1 + _rand(12), False)
        var password = _text(_rand(20), False)
        var salt = List[UInt8]()
        for _ in range(4):
            salt.append(UInt8(_rand(256)))
        assert_equal(
            md5_password(user, password, Span(salt)),
            String(o.md5_answer(user, password, hex(Span(salt)))),
        )


def test_scram_rfc_7677_example() raises:
    var c = ScramClient("pencil", "rOprNGfwEbeRWgbNEkqO", user="user")
    assert_equal(c.client_first(), "n,,n=user,r=rOprNGfwEbeRWgbNEkqO")
    var final = c.client_final(
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096".as_bytes()
    )
    assert_equal(
        final,
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
    )
    assert_false(c.verified())
    c.verify("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=".as_bytes())
    assert_true(c.verified())


def test_scram_user_names_are_escaped() raises:
    # RFC 5802 5.1: "=" and "," in a saslname become "=3D" and "=2C"
    assert_equal(ScramClient("p", "abc", user="a=b,c").client_first(), "n,,n=a=3Db=2Cc,r=abc")


def test_scram_against_the_oracle() raises:
    seed(7677)
    var o = oracle()
    for i in range(40):
        var password = _text(_rand(30), i % 2 == 0)
        var salt = List[UInt8]()
        for _ in range(1 + _rand(32)):
            salt.append(UInt8(_rand(256)))
        var iterations = 1 + _rand(3000)
        var server = o.ScramServer(password, hex(Span(salt)), iterations, _nonce(1 + _rand(30)))
        var c = ScramClient(password, _nonce(1 + _rand(40)))
        assert_true(c.client_first().startswith("n,,n=,r="))  # PostgreSQL: no user name
        var server_first = String(server.first(c.client_first()))
        var verdict = String(server.final(c.client_final(server_first.as_bytes())))
        assert_true(verdict.startswith("ok|"), String(i, ": ", verdict))
        c.verify(verdict.as_bytes()[3:])
        assert_true(c.verified())
    # with the wrong password, the server sees a bad proof
    var server = o.ScramServer("right", hex("salt"), 4096, "srv")
    var wrong = ScramClient("wrong", "abc")
    var first = String(server.first(wrong.client_first()))
    assert_true(String(server.final(wrong.client_final(first.as_bytes()))).startswith("bad|"))


comptime _FIRST = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"


def _first_fails(server_first: StringSlice) -> String:
    """What `client_final` raises for `server_first` ("" if nothing)."""
    try:
        var c = ScramClient("pencil", "rOprNGfwEbeRWgbNEkqO")
        _ = c.client_final(server_first.as_bytes())
    except e:
        return String(e.kind)
    return ""


def test_scram_refuses_bad_server_first_messages() raises:
    var bad = [
        "r=rOprNGfwEbeRWgbNEkq,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",  # shorter nonce
        "r=rOprNGfwEbeRWgbNEkqO,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",  # ours, not extended
        "r=XOprNGfwEbeRWgbNEkqO%hvY,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",  # not our prefix
        "r=rOprNGfwEbeRWgbNEkqO%h\x7f,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",  # not printable
        "r=rOprNGfwEbeRWgbNEkqO%hvY,i=4096,s=W22ZaJ0SNY7soEsUEjb6gQ==",  # out of order
        "r=rOprNGfwEbeRWgbNEkqO%hvY,s=W22ZaJ0SNY7soEsUEjb6gQ==",  # no count
        "r=rOprNGfwEbeRWgbNEkqO%hvY,s=!!!!,i=4096",  # salt not base64
        "r=rOprNGfwEbeRWgbNEkqO%hvY,s=,i=4096",  # empty salt
        "r=rOprNGfwEbeRWgbNEkqO%hvY,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=0",
        "r=rOprNGfwEbeRWgbNEkqO%hvY,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=",
        "r=rOprNGfwEbeRWgbNEkqO%hvY,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=12a",
        "r=rOprNGfwEbeRWgbNEkqO%hvY,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=-5",
        "",
        "garbage",
    ]
    for i in range(len(bad)):
        assert_equal(_first_fails(bad[i]), "InvalidData", bad[i])
    # an unknown mandatory extension, or more rounds than allowed
    assert_equal(_first_fails(String("m=ext,", _FIRST)), "Unsupported")
    assert_equal(
        _first_fails(String("r=rOprNGfwEbeRWgbNEkqO%hvY,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=", MAX_SCRAM_ITERATIONS + 1)),
        "Unsupported",
    )
    assert_equal(
        _first_fails("r=rOprNGfwEbeRWgbNEkqO%hvY,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=99999999999999999999999999"),
        "Unsupported",
    )
    # optional extensions after the count are ignored
    assert_equal(_first_fails(String(_FIRST, ",x=whatever")), "")


def _final_fails(server_final: StringSlice) -> String:
    try:
        var c = ScramClient("pencil", "rOprNGfwEbeRWgbNEkqO", user="user")
        _ = c.client_final(_FIRST.as_bytes())
        c.verify(server_final.as_bytes())
    except e:
        return String(e.kind)
    return ""


def test_scram_refuses_bad_server_final_messages() raises:
    assert_equal(_final_fails("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="), "")
    assert_equal(_final_fails("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=,ext=1"), "")
    assert_equal(_final_fails("v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="), "InvalidData")  # wrong
    assert_equal(_final_fails("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4"), "InvalidData")  # not base64
    assert_equal(_final_fails("v="), "InvalidData")
    assert_equal(_final_fails("x=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="), "InvalidData")
    assert_equal(_final_fails("e=invalid-proof"), "PermissionDenied")


def _misuse(which: Int) -> String:
    try:
        if which == 0:
            _ = ScramClient("pencil", "")
        elif which == 1:
            _ = ScramClient("pencil", "a,b")
        elif which == 2:
            _ = ScramClient("pencil", "a b")
        elif which == 3:
            _ = ScramClient("pencil", "é")
        elif which == 4:
            var c = ScramClient("pencil", "rOprNGfwEbeRWgbNEkqO")
            c.verify("v=AAAA".as_bytes())  # before client_final
        else:
            var c = ScramClient("pencil", "rOprNGfwEbeRWgbNEkqO")
            _ = c.client_final(_FIRST.as_bytes())
            _ = c.client_final(_FIRST.as_bytes())  # twice
    except e:
        return String(e.kind)
    return ""


def test_scram_misuse_is_invalid_input() raises:
    for which in range(6):
        assert_equal(_misuse(which), "InvalidInput", String(which))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
