"""`pg.client` against a real PostgreSQL (`pg_server.mojo`; skipped when
none can run here). Covered:
- every authentication method over TCP and the Unix socket;
- the refusals: a wrong password, a method not allowed, no such database;
- queries and their text values;
- server errors that keep the session usable, and transaction status;
- notices and notifications;
- a large result;
- a deadline that cancels the query;
- COPY FROM STDIN refused;
- a server that ends the session, and one that stops;
- a connect deadline against a server that never answers.

Each test starts its own cluster, and stops it whatever happens."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError
from linux.time import Duration, Instant
from pg import BINARY, FAILED_TRANSACTION, IDLE, IN_TRANSACTION, TEXT, AuthMethods, Params
from pg.client import E_ROLLED_BACK, Client, PgError, Rows
from pg.config import Config
from pg.message import FIELD_CONSTRAINT
from pg.pool import Pool
from pg.types import Date
from pg_server import PgServer, passwords, users


def _connect_error(config: Config) raises -> PgError:
    try:
        var db = Client.connect(config)
        db^.close()
    except e:
        return e.copy()
    raise Error("connected, but it should not have")


def _query_error(mut db: Client, sql: StringSlice, timeout: Duration = Duration.ZERO) raises -> PgError:
    try:
        _ = db.query(sql, timeout=timeout)
    except e:
        return e.copy()
    raise Error(String("no error from ", sql))


def _params_error(mut db: Client, sql: StringSlice, params: Params) raises -> PgError:
    try:
        _ = db.query_params(sql, params)
    except e:
        return e.copy()
    raise Error(String("no error from ", sql))


def _methods(server: PgServer) raises:
    var methods = [AuthMethods.TRUST, AuthMethods.PASSWORD, AuthMethods.MD5, AuthMethods.SCRAM_SHA_256]
    var u = users()
    var p = passwords()
    for i in range(4):
        for unix in [False, True]:
            var config = server.unix(u[i], p[i]) if unix else server.tcp(u[i], p[i])
            config.allow = methods[i]  # only this one, so it is the one the server used
            var db = Client.connect(config)
            assert_equal(db.query("SELECT current_user").text(0, 0), u[i])
            db^.close()


def _refusals(server: PgServer) raises:
    var e = _connect_error(server.tcp("scram", "wrong"))
    assert_true(e.is_server())
    assert_equal(e.code(), "28P01")
    e = _connect_error(server.unix("md5user", "wrong"))
    assert_equal(e.code(), "28P01")
    # a method the caller does not allow: refused before a password is sent
    var cleartext = server.tcp("plain", "plain-pw")
    cleartext.allow = AuthMethods.SCRAM_SHA_256
    e = _connect_error(cleartext)
    assert_false(e.is_server())
    assert_true(e.io.kind == ErrorKind.PermissionDenied)
    # no password, no such database, no such user
    e = _connect_error(server.tcp("scram"))
    assert_true(e.io.kind == ErrorKind.InvalidInput)
    var nodb = server.tcp("trusty")
    nodb.database = "nope"
    assert_equal(_connect_error(nodb).code(), "3D000")
    assert_equal(_connect_error(server.tcp("nobody")).code(), "28000")


def _queries(server: PgServer) raises:
    var db = Client.connect(server.unix("trusty"))
    var r = db.query("SELECT 42::int AS n, 'héllo'::text AS t, NULL::int AS z, true AS b, 1.5::float8 AS f, ''::text AS e")
    assert_equal(len(r), 1)
    assert_equal(r.width(), 6)
    assert_equal(r.columns[1].name, "t")
    assert_equal(r.columns[0].type_oid, 23)  # int4
    assert_equal(r.int(0, 0), 42)
    assert_equal(r.text(0, 1), "héllo")
    assert_true(r.is_null(0, 2))
    assert_true(r.bool(0, 3))
    assert_equal(r.text(0, 4), "1.5")
    assert_false(r.is_null(0, 5))
    assert_equal(r.text(0, 5), "")
    assert_equal(r.tag, "SELECT 1")
    var all = db.simple_query(
        "CREATE TEMP TABLE t (id int PRIMARY KEY, name text); INSERT INTO t VALUES (1, 'a'), (2, 'b'), (3, NULL);"
        + " SELECT * FROM t ORDER BY id"
    )
    assert_equal(len(all), 3)
    assert_equal(all[0].tag, "CREATE TABLE")
    assert_equal(all[1].rows_affected().value(), 3)
    assert_equal(len(all[2]), 3)
    assert_equal(all[2].text(1, 1), "b")
    assert_true(all[2].is_null(2, 1))
    assert_equal(db.execute("UPDATE t SET name = 'x' WHERE id > 1"), 2)
    assert_equal(db.execute("DELETE FROM t WHERE id = 1"), 1)
    assert_equal(db.execute("SELECT 1 WHERE false"), 0)
    assert_equal(db.execute("CREATE TEMP TABLE z (a int)"), 0)  # (a tag without a count)
    assert_equal(db.query("SELECT -2").int(0, 0), -2)
    assert_equal(db.simple_query("SELECT 1; SELECT -3")[1].int(0, 0), -3)
    assert_equal(len(db.simple_query("")), 1)  # an empty query: one empty result
    var big = db.query("SELECT 99999999999999999999::numeric, 'x'")
    var refused = 0
    for col in range(2):
        try:
            _ = big.int(0, col)
        except e:
            refused += Int(e.io.kind == ErrorKind.InvalidData)
    assert_equal(refused, 2)
    db^.close()


def _errors(server: PgServer) raises:
    var db = Client.connect(server.tcp("trusty"))
    var e = _query_error(db, "SELECT * FROM missing")
    assert_equal(e.code(), "42P01")
    assert_equal(e.server().position().value(), "15")
    assert_true(db.is_usable())
    _ = db.execute("CREATE TEMP TABLE u (id int PRIMARY KEY)")
    _ = db.execute("INSERT INTO u VALUES (1)")
    e = _query_error(db, "INSERT INTO u VALUES (1)")
    assert_equal(e.code(), "23505")
    assert_equal(e.server().field(FIELD_CONSTRAINT).value(), "u_pkey")
    # in a transaction, an error fails it until ROLLBACK
    _ = db.execute("BEGIN")
    assert_equal(db.transaction_status(), IN_TRANSACTION)
    assert_equal(_query_error(db, "SELECT 1/0").code(), "22012")
    assert_equal(db.transaction_status(), FAILED_TRANSACTION)
    assert_equal(_query_error(db, "SELECT 1").code(), "25P02")
    _ = db.execute("ROLLBACK")
    assert_equal(db.transaction_status(), IDLE)
    assert_equal(db.query("SELECT 2").int(0, 0), 2)
    # a NUL in the SQL is refused before anything is sent
    e = _query_error(db, "SELECT 1\x00")
    assert_true(e.io.kind == ErrorKind.InvalidInput)
    assert_true(db.is_usable())
    db^.close()


def _notices(server: PgServer) raises:
    var db = Client.connect(server.tcp("trusty"))
    _ = db.execute("DO $$ BEGIN RAISE NOTICE 'hello %', 42; RAISE WARNING 'careful'; END $$")
    var notices = db.take_notices()
    assert_equal(len(notices), 2)
    assert_equal(notices[0].message(), "hello 42")
    assert_equal(notices[1].severity(), "WARNING")
    assert_equal(len(db.take_notices()), 0)
    _ = db.execute("LISTEN jobs")
    _ = db.execute("NOTIFY jobs, 'run 7'")
    var n = db.take_notifications()
    assert_equal(len(n), 1)
    assert_equal(n[0].channel, "jobs")
    assert_equal(n[0].payload, "run 7")
    assert_equal(n[0].pid, db.backend_key().value().pid)
    db^.close()


def _large(server: PgServer) raises:
    var db = Client.connect(server.unix("scram", "pencil é"))
    var r = db.query("SELECT g, md5(g::text) FROM generate_series(1, 100000) g")
    assert_equal(len(r), 100000)
    assert_equal(r.text(0, 1), "c4ca4238a0b923820dcc509a6f75849b")  # md5("1")
    var sum = 0
    for i in range(len(r)):
        sum += r.int(i, 0)
    assert_equal(sum, 5000050000)
    db^.close()


def _deadline(server: PgServer) raises:
    var db = Client.connect(server.tcp("trusty"))
    var t = Instant.now()
    var e = _query_error(db, "SELECT pg_sleep(30)", Duration.from_millis(300))
    assert_true(e.is_deadline())
    assert_equal(e.code(), "57014")  # query_canceled
    assert_true(t.elapsed() < Duration.from_secs(5))
    assert_true(db.is_usable())
    assert_equal(db.query("SELECT 1").int(0, 0), 1)
    assert_equal(len(db.query("SELECT pg_sleep(0.05)", timeout=Duration.from_secs(5))), 1)  # in time
    db.cancel()  # with nothing running: harmless
    assert_equal(db.query("SELECT 3").int(0, 0), 3)
    db^.close()


def _copy_and_parameters(server: PgServer) raises:
    var config = server.tcp("trusty")
    config.application_name = "mojo-tests"
    config.set("search_path", "pg_catalog")
    var db = Client.connect(config)
    assert_true(db.parameter("server_version").value().startswith("18"))
    assert_equal(db.parameter("client_encoding").value(), "UTF8")
    assert_equal(
        db.query("SELECT application_name FROM pg_stat_activity WHERE pid = pg_backend_pid()").text(0, 0),
        "mojo-tests",
    )
    assert_equal(db.query("SHOW search_path").text(0, 0), "pg_catalog")
    assert_equal(db.backend_key().value().pid, db.query("SELECT pg_backend_pid()").int(0, 0))
    _ = db.execute("CREATE TEMP TABLE c (x int)")
    assert_equal(_query_error(db, "COPY c FROM STDIN", Duration.from_secs(20)).code(), "57014")
    var refused = False
    try:
        _ = db.simple_query("COPY c FROM STDIN", Duration.from_secs(20))
    except e:
        refused = e.code() == "57014"
    assert_true(refused)  # (the simple protocol too)
    assert_true(db.is_usable())
    db^.close()


def _ended_by_the_server(server: PgServer) raises:
    var db = Client.connect(server.tcp("trusty"))
    var e = _query_error(db, "SELECT pg_terminate_backend(pg_backend_pid())")
    assert_equal(e.code(), "57P01")
    assert_false(db.is_usable())
    assert_true(_query_error(db, "SELECT 1").io.kind == ErrorKind.Closed)


def _server_stops(server: PgServer) raises:
    var db = Client.connect(server.unix("trusty"))
    assert_equal(db.query("SELECT 1").int(0, 0), 1)
    server.stop()  # (immediate: the backend goes too)
    var e = _query_error(db, "SELECT 1")
    assert_false(db.is_usable())
    assert_false(e.is_deadline())


def _parameters(server: PgServer) raises:
    var db = Client.connect(server.tcp("trusty"))
    assert_equal(db.query("SELECT $1::int + $2::int", 40, 2).int(0, 0), 42)
    assert_equal(db.query("SELECT $1::float8 * 2", 1.25).text(0, 0), "2.5")
    assert_false(db.query("SELECT NOT $1::bool", True).bool(0, 0))
    var evil = "it's'; DROP TABLE pg_class; --"
    assert_equal(db.query("SELECT $1", evil).text(0, 0), evil)  # a value, never SQL
    assert_equal(db.query("SELECT $1 || '!'", "héllo €").text(0, 0), "héllo €!")
    _ = db.execute("CREATE TEMP TABLE p (id int PRIMARY KEY, name text, data bytea)")
    assert_equal(db.execute("INSERT INTO p (id, name) VALUES ($1, $2), ($3, $4)", 1, "a", 2, "b"), 2)
    assert_equal(db.query("SELECT name FROM p WHERE id = $1", 2).text(0, 0), "b")
    # NULL and bytes through Params
    var params = Params()
    params.add(3)
    params.add_null()
    var raw: List[UInt8] = [0, 1, 255]
    params.add_binary(Span(raw), 17)  # bytea
    assert_equal(db.query_params("INSERT INTO p VALUES ($1, $2, $3)", params).rows_affected().value(), 1)
    var r = db.query("SELECT name IS NULL, encode(data, 'hex') FROM p WHERE id = 3")
    assert_true(r.bool(0, 0))
    assert_equal(r.text(0, 1), "0001ff")
    # what the server refuses leaves the session usable
    var one = Params()
    one.add(1)
    assert_equal(_params_error(db, "SELECT $1, $2", one).code(), "08P01")  # 1 value for 2
    var abc = Params()
    abc.add("abc")
    assert_equal(_params_error(db, "SELECT $1::int", abc).code(), "22P02")
    assert_equal(_query_error(db, "SELECT 1; SELECT 2").code(), "42601")  # one statement only
    assert_true(db.is_usable())
    assert_equal(db.query("SELECT count(*) FROM p").int(0, 0), 3)
    db^.close()


def _types(server: PgServer) raises:
    var db = Client.connect(server.unix("trusty"))
    # Each value in binary form, written as text by the client, against the
    # server's own text form of it (simple_query: text).
    var values = [
        "true", "false", "0::int2", "(-32768)::int2", "32767::int2", "2147483647", "(-2147483648)::int4",
        "9223372036854775807::int8", "(-9223372036854775808)::int8", "4294967295::oid", "'\\x00ff10'::bytea",
        "''::bytea", "'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'::uuid", "'2024-02-29'::date", "'0001-01-01'::date",
        "'0001-01-01 BC'::date", "'4713-01-01 BC'::date", "'5874897-12-31'::date", "'infinity'::date",
        "'-infinity'::date", "'00:00:00'::time", "'23:59:59.999999'::time", "'12:00:00.5'::time",
        "'2024-02-29 13:45:00.123'::timestamp", "'0001-01-01 00:00:00 BC'::timestamp",
        "'294276-12-31 23:59:59.999999'::timestamp", "'infinity'::timestamp", "'-infinity'::timestamp",
        "'héllo'::text", "'abc'::varchar(5)", "'ab'::char(4)", "'x'::\"char\"", "'n'::name",
    ]
    for i in range(len(values)):
        var sql = String("SELECT ", values[i])
        var r = db.query(sql)
        assert_equal(r.columns[0].format, BINARY, values[i])
        assert_equal(r.text(0, 0), db.simple_query(sql)[0].text(0, 0), values[i])
    # 2000 random dates and timestamps, each beside its text
    var dates = db.query(
        "SELECT d, d::text FROM (SELECT date '2000-01-01' + (random() * 2000000 - 1000000)::int AS d"
        + " FROM generate_series(1, 2000)) s"
    )
    for i in range(len(dates)):
        assert_equal(dates.text(i, 0), dates.text(i, 1))
        assert_true(dates.date(i, 0) == dates.date(i, 1))
    var stamps = db.query(
        "SELECT t, t::text FROM (SELECT timestamp '2000-01-01' + (random() * 200000 - 100000) * interval '1 day'"
        + " AS t FROM generate_series(1, 2000)) s"
    )
    for i in range(len(stamps)):
        assert_equal(stamps.text(i, 0), stamps.text(i, 1))
        assert_equal(stamps.timestamp(i, 0), stamps.timestamp(i, 1))
    # the typed accessors, in either form
    var r = db.query(
        "SELECT 7::int2, (-7)::int8, 1.5::float8, 'NaN'::float8, '-Infinity'::float4, 2.25::numeric,"
        + " '\\x00ff'::bytea, date '2024-02-29', timestamptz '2024-02-29 13:45:00+05:30', true"
    )
    assert_equal(r.int(0, 0), 7)
    assert_equal(r.int(0, 1), -7)
    assert_equal(r.float(0, 2), 1.5)
    assert_true(r.float(0, 3) != r.float(0, 3))  # NaN
    assert_equal(r.float(0, 4), -Float64.MAX * 10)  # -inf
    assert_equal(r.float(0, 5), 2.25)
    assert_equal(r.columns[2].format, TEXT)  # (floats and numeric stay in text)
    var b = r.bytes(0, 6)
    assert_equal(len(b), 2)
    assert_equal(b[1], 255)
    assert_true(r.date(0, 7) == Date(2024, 2, 29, 0))
    assert_equal(r.columns[8].format, TEXT)  # timestamptz
    assert_equal(r.timestamp(0, 8), (Date(2024, 2, 29, 0).days_since_1970() * 86400 + 8 * 3600 + 15 * 60) * 1000000)
    assert_true(r.bool(0, 9))
    var text_bytes = db.simple_query("SELECT '\\x00ff'::bytea")[0].bytes(0, 0)
    assert_equal(len(text_bytes), 2)
    db^.close()


def _statement_cache(server: PgServer) raises:
    var config = server.tcp("trusty")
    config.statement_cache = 2
    var db = Client.connect(config)
    for _ in range(3):
        assert_equal(db.query("SELECT $1::int + 1", 1).int(0, 0), 2)
    assert_equal(db.cached_statements(), 1)
    _ = db.query("SELECT 2")
    _ = db.query("SELECT $1::int + 1", 1)  # (now SELECT 2 is the least recently used)
    _ = db.query("SELECT 3")  # (evicts SELECT 2)
    assert_equal(db.cached_statements(), 2)
    # The server holds what the cache holds (looked at through simple_query,
    # which uses no prepared statement and so evicts nothing).
    var inspected = db.simple_query("SELECT statement FROM pg_prepared_statements ORDER BY name")
    ref held = inspected[0]
    assert_equal(len(held), 2)
    assert_equal(held.text(0, 0), "SELECT $1::int + 1")
    assert_equal(held.text(1, 0), "SELECT 3")
    # a statement whose result type changes: prepared afresh, once
    _ = db.execute("CREATE TEMP TABLE inv (a int)")
    _ = db.execute("INSERT INTO inv VALUES (1)")
    assert_equal(db.query("SELECT * FROM inv").width(), 1)
    _ = db.execute("ALTER TABLE inv ADD COLUMN b text DEFAULT 'x'")
    var r = db.query("SELECT * FROM inv")
    assert_equal(r.width(), 2)
    assert_equal(r.text(0, 1), "x")
    # inside a transaction it cannot be retried
    _ = db.execute("BEGIN")
    _ = db.query("SELECT * FROM inv")
    _ = db.execute("ALTER TABLE inv ADD COLUMN c int")
    assert_equal(_query_error(db, "SELECT * FROM inv").code(), "0A000")
    _ = db.execute("ROLLBACK")
    assert_equal(db.query("SELECT * FROM inv").width(), 2)
    # evicted statements' slots are reused: the cache does not grow
    for i in range(20):
        _ = db.query(String("SELECT ", i))
    assert_equal(db.cached_statements(), 2)
    assert_equal(len(db._statements), 2)
    # a statement the server refuses is not cached
    var before = db.cached_statements()
    assert_equal(_query_error(db, "SELEC 1").code(), "42601")
    assert_equal(db.cached_statements(), before)
    db^.close()
    # without the cache: the unnamed statement, text results
    var plain = server.tcp("trusty")
    plain.statement_cache = 0
    var p = Client.connect(plain)
    var t = p.query("SELECT $1::int * 2", 21)
    assert_equal(t.int(0, 0), 42)
    assert_equal(t.columns[0].format, TEXT)
    assert_equal(p.cached_statements(), 0)
    assert_equal(p.query("SELECT count(*) FROM pg_prepared_statements").int(0, 0), 0)
    p^.close()


def _count(mut db: Client, sql: StringSlice) raises -> Int:
    return db.query(sql).int(0, 0)


def _transactions(server: PgServer) raises:
    var db = Client.connect(server.tcp("trusty"))
    _ = db.execute("CREATE TEMP TABLE tx (a int)")
    db.begin()
    _ = db.execute("INSERT INTO tx VALUES (1)")
    assert_equal(db.transaction_status(), IN_TRANSACTION)
    db.commit()
    assert_equal(db.transaction_status(), IDLE)
    db.begin()
    _ = db.execute("INSERT INTO tx VALUES (2)")
    db.rollback()
    assert_equal(_count(db, "SELECT count(*) FROM tx"), 1)
    # one at a time
    db.begin()
    var nested = False
    try:
        db.begin()
    except e:
        nested = e.io.kind == ErrorKind.InvalidInput
    assert_true(nested)
    db.rollback()
    # a failed transaction: COMMIT rolls it back, and says so
    db.begin()
    _ = db.execute("INSERT INTO tx VALUES (3)")
    assert_equal(_query_error(db, "SELECT 1/0").code(), "22012")
    var rolled_back = False
    try:
        db.commit()
    except e:
        rolled_back = String(e.io.op) == E_ROLLED_BACK
    assert_true(rolled_back)
    assert_equal(db.transaction_status(), IDLE)
    assert_equal(_count(db, "SELECT count(*) FROM tx"), 1)
    # savepoints, with a name that needs quoting
    var name = 'a b"c'
    db.begin()
    _ = db.execute("INSERT INTO tx VALUES (4)")
    db.savepoint(name)
    _ = db.execute("INSERT INTO tx VALUES (5)")
    assert_equal(_query_error(db, "SELECT 1/0").code(), "22012")
    db.rollback_to(name)  # (the failed part only: the transaction goes on)
    assert_equal(db.transaction_status(), IN_TRANSACTION)
    _ = db.execute("INSERT INTO tx VALUES (6)")
    db.release(name)
    db.commit()
    assert_equal(db.query("SELECT string_agg(a::text, ',' ORDER BY a) FROM tx").text(0, 0), "1,4,6")
    db^.close()


def _notifications(server: PgServer) raises:
    var a = Client.connect(server.tcp("trusty"))
    var b = Client.connect(server.unix("trusty"))
    _ = a.execute("LISTEN jobs")
    _ = b.execute("NOTIFY jobs, 'one'")
    var n = a.wait_notification(Duration.from_secs(10))
    assert_true(Bool(n))
    assert_equal(n.value().channel, "jobs")
    assert_equal(n.value().payload, "one")
    assert_equal(n.value().pid, b.backend_key().value().pid)
    # none within the time: None, and the session goes on
    var t = Instant.now()
    assert_false(Bool(a.wait_notification(Duration.from_millis(200))))
    assert_true(t.elapsed() >= Duration.from_millis(150))
    assert_true(a.is_usable())
    assert_equal(a.query("SELECT 5").int(0, 0), 5)
    # one that came during a query is kept for the next wait
    _ = b.execute("NOTIFY jobs, 'two'")
    var waited = Instant.now()
    while waited.elapsed() < Duration.from_secs(5):
        _ = a.query("SELECT 1")
        if Bool(a.wait_notification(Duration.from_millis(50))):
            break
    assert_true(waited.elapsed() < Duration.from_secs(5))
    a^.close()
    b^.close()


def _pool(server: PgServer) raises:
    var pool = Pool(server.tcp("trusty"), max_idle=2)
    var a = pool.acquire()
    var b = pool.acquire()
    assert_equal(pool.opened(), 2)
    var pid_b = b.backend_key().value().pid
    pool.release(a^)
    pool.release(b^)
    assert_equal(pool.idle(), 2)
    var c = pool.acquire()  # (the last released)
    assert_equal(c.backend_key().value().pid, pid_b)
    assert_equal(pool.opened(), 2)
    assert_equal(c.query("SELECT 2").int(0, 0), 2)
    pool.release(c^)
    # a session ended while it sat in the pool is replaced
    var d = pool.acquire()
    var pid_d = d.backend_key().value().pid
    pool.release(d^)
    var killer = Client.connect(server.unix("trusty"))
    assert_true(killer.query("SELECT pg_terminate_backend($1)", pid_d).bool(0, 0))
    var t = Instant.now()
    while _count(killer, String("SELECT count(*) FROM pg_stat_activity WHERE pid = ", pid_d)) > 0:
        assert_true(t.elapsed() < Duration.from_secs(10))
    var e = pool.acquire()
    assert_true(e.backend_key().value().pid != pid_d)
    assert_equal(e.query("SELECT 3").int(0, 0), 3)
    # a session in a transaction is not pooled, nor one past max_idle
    e.begin()
    var idle = pool.idle()
    pool.release(e^)
    assert_equal(pool.idle(), idle)
    var f = pool.acquire()
    var g = pool.acquire()
    var h = pool.acquire()
    pool.release(f^)
    pool.release(g^)
    pool.release(h^)
    assert_equal(pool.idle(), 2)
    pool.close()
    assert_equal(pool.idle(), 0)
    killer^.close()
    # A backend killed outright sends nothing: its socket just closes. (The
    # server then recovers from a crash, so reconnecting waits for that.)
    var crash = Pool(server.tcp("trusty"), max_idle=2)
    var victim = crash.acquire()
    var pid = victim.backend_key().value().pid
    crash.release(victim^)
    _ = Python.import_module("os").kill(pid, 9)
    var gone = Instant.now()
    while gone.elapsed() < Duration.from_millis(300):
        pass
    var connected = False
    var handed_out_dead = False
    var start = Instant.now()
    while not connected and start.elapsed() < Duration.from_secs(20):
        var acquired = False
        try:
            var after = crash.acquire()  # (first the dead session, which check refuses)
            acquired = True
            var answered = after.query("SELECT 1").int(0, 0) == 1  # (first: a dead session fails here)
            connected = answered and after.backend_key().value().pid != pid
            after^.close()
        except:
            # Connecting may fail during recovery (57P03); a session that
            # acquire handed out must not.
            handed_out_dead = handed_out_dead or acquired
    assert_true(connected)
    assert_false(handed_out_dead)
    crash.close()


def _run(server: PgServer, which: Int) -> String:
    """Body `which` against `server`: "" or why it failed."""
    try:
        if which == 0:
            _methods(server)
        elif which == 1:
            _refusals(server)
        elif which == 2:
            _queries(server)
        elif which == 3:
            _errors(server)
        elif which == 4:
            _notices(server)
        elif which == 5:
            _large(server)
        elif which == 6:
            _deadline(server)
        elif which == 7:
            _copy_and_parameters(server)
        elif which == 8:
            _ended_by_the_server(server)
        elif which == 9:
            _server_stops(server)
        elif which == 10:
            _parameters(server)
        elif which == 11:
            _types(server)
        elif which == 12:
            _statement_cache(server)
        elif which == 13:
            _transactions(server)
        elif which == 14:
            _notifications(server)
        else:
            _pool(server)
    except e:
        return String(e)
    return ""


def _with_server(which: Int) raises:
    var started = PgServer.start()
    if not started:
        return
    var server = started.take()
    var failure = _run(server, which)
    server.stop()
    assert_equal(failure, "")


def test_every_method_over_both_transports() raises:
    _with_server(0)


def test_refusals() raises:
    _with_server(1)


def test_queries() raises:
    _with_server(2)


def test_errors_keep_the_session() raises:
    _with_server(3)


def test_notices_and_notifications() raises:
    _with_server(4)


def test_a_large_result() raises:
    _with_server(5)


def test_a_deadline_cancels_the_query() raises:
    _with_server(6)


def test_copy_and_parameters() raises:
    _with_server(7)


def test_the_server_ends_the_session() raises:
    _with_server(8)


def test_the_server_stops() raises:
    _with_server(9)


def test_parameters() raises:
    _with_server(10)


def test_types() raises:
    _with_server(11)


def test_statement_cache() raises:
    _with_server(12)


def test_transactions() raises:
    _with_server(13)


def test_notifications() raises:
    _with_server(14)


def test_pool() raises:
    _with_server(15)


def test_connect_deadline() raises:
    # a listener that accepts and never answers
    var socket = Python.import_module("socket")
    var listener = socket.socket()
    _ = listener.bind(Python.tuple("127.0.0.1", 0))
    _ = listener.listen(4)
    var port = Int(py=listener.getsockname()[1])
    var config = Config("x", host="127.0.0.1", port=port, connect_timeout=Duration.from_millis(300))
    var t = Instant.now()
    var e = _connect_error(config)
    assert_true(e.is_deadline())
    assert_true(t.elapsed() < Duration.from_secs(3))
    _ = listener.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
