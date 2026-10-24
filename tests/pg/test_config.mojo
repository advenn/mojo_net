"""`pg.config`: connection URIs as libpq reads them, the startup settings
they make, and what is refused."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError
from linux.time import Duration
from pg import AuthMethods, PgConnection
from pg.config import Config
from pg_util import nonce, oracle, sent


def test_a_full_uri() raises:
    var c = Config.parse(
        "postgresql://alice:s%40cret%3A@db.example.com:6543/shop?application_name=tests&connect_timeout=7"
        + "&options=-c%20search_path%3Dapp&sslmode=disable"
    )
    assert_equal(c.user, "alice")
    assert_equal(c.password, "s@cret:")
    assert_equal(c.host, "db.example.com")
    assert_equal(c.port, 6543)
    assert_equal(c.database, "shop")
    assert_equal(c.application_name, "tests")
    assert_true(c.connect_timeout == Duration.from_secs(7))
    assert_false(c.is_unix())
    # what the session's startup message carries
    var conn = PgConnection(c.startup(), Span(nonce()))
    assert_equal(
        String(oracle().startup(sent(conn))),
        "196608|user=alice|database=shop|application_name=tests|client_encoding=UTF8|options=-c search_path=app#",
    )


def test_hosts_ports_and_sockets() raises:
    var c = Config.parse("postgres://bob@/")
    assert_equal(c.host, "localhost")
    assert_equal(c.port, 5432)
    assert_equal(c.database, "")
    c = Config.parse("postgresql://bob@[::1]:5433/db")
    assert_equal(c.host, "::1")
    assert_equal(c.port, 5433)
    c = Config.parse("postgresql://bob@[fe80::1%25eth0]/db")
    assert_equal(c.host, "fe80::1%eth0")
    c = Config.parse("postgresql://bob@%2Fvar%2Frun%2Fpostgresql/db")
    assert_equal(c.host, "/var/run/postgresql")
    assert_true(c.is_unix())
    assert_equal(c.socket_path(), "/var/run/postgresql/.s.PGSQL.5432")
    c = Config.parse("postgresql:///db?host=/tmp&user=carol&port=7000&dbname=other&password=pw")
    assert_equal(c.host, "/tmp")
    assert_equal(c.user, "carol")
    assert_equal(c.port, 7000)
    assert_equal(c.database, "other")
    assert_equal(c.password, "pw")
    assert_equal(c.socket_path(), "/tmp/.s.PGSQL.7000")
    c = Config.parse("postgresql://dave@h?connect_timeout=0")
    assert_true(c.connect_timeout == Duration.ZERO)
    assert_equal(c.statement_cache, 256)
    assert_equal(Config.parse("postgresql://dave@h?statement_cache_capacity=0").statement_cache, 0)


def test_require_auth() raises:
    var base = String("postgresql://dave@h/db?require_auth=")
    assert_true(Config.parse(base + "scram-sha-256").allow == AuthMethods.SCRAM_SHA_256)
    assert_true(Config.parse(base + "password,md5").allow == (AuthMethods.PASSWORD | AuthMethods.MD5))
    assert_true(Config.parse(base + "none").allow == AuthMethods.TRUST)
    assert_true(Config.parse(base + "!password,!md5").allow == (AuthMethods.TRUST | AuthMethods.SCRAM_SHA_256))
    assert_true(Config.parse("postgresql://dave@h/db").allow == AuthMethods.ALL)
    assert_true(Bool(Config.parse(base + "md5&sslmode=prefer&channel_binding=prefer").allow == AuthMethods.MD5))


def _refusal(uri: StringSlice) -> String:
    try:
        _ = Config.parse(uri)
    except e:
        return String(e.kind)
    return "accepted"


def test_refusals() raises:
    var invalid = [
        "mysql://x@h/db",
        "x@h/db",  # (no scheme)
        "postgresql://x@h:0/",
        "postgresql://x@h:99999/",
        "postgresql://x@h:12a/",
        "postgresql://x@h:/",
        "postgresql://x@h/d?bogus=1",
        "postgresql://x@h/d?flag",
        "postgresql://x@[::1/d",
        "postgresql://x@[::1]5432/d",
        "postgresql://%ZZ@h",
        "postgresql://x%4@h",
        "postgresql://a%00b@h",
        "postgresql://a%FF@h",
        "postgresql://@h/db",
        "postgresql://h/db",
        "postgresql://x@h/d?require_auth=password,!md5",
        "postgresql://x@h/d?require_auth=gss",
        "postgresql://x@h/d?connect_timeout=abc",
        "postgresql://x@h/d?connect_timeout=-1",
        "postgresql://x@h/d?connect_timeout=99999999999",
        "postgresql://u:p@ss@h/db",
    ]
    for i in range(len(invalid)):
        assert_equal(_refusal(invalid[i]), "InvalidInput", invalid[i])
    var unsupported = [
        "postgresql://x@h/d?sslmode=require",
        "postgresql://x@h/d?sslmode=verify-ca",
        "postgresql://x@h/d?sslmode=verify-full",
        "postgresql://x@h/d?channel_binding=require",
        "postgresql://x@h1,h2/d",
        "postgresql://x@h1:5432,h2:5432/d",
        "postgresql://x@/d?host=a,b",
    ]
    for i in range(len(unsupported)):
        assert_equal(_refusal(unsupported[i]), "Unsupported", unsupported[i])


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
