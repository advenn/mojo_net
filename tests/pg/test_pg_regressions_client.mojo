"""Regression tests for the P7 review of `pg`, against a real PostgreSQL
(`pg_server.mojo`; skipped without one), each checked to fail on the code
before its fix:
- the session's DateStyle, extra_float_digits and bytea_output were taken
  from the role or the server, so a role set to SQL dates, 0 float digits
  or escape bytea broke the text forms and float precision;
- a session switched to another client_encoding went on, garbling text;
- "char" values in binary form did not read as the server writes them;
- int() refused int8's extremes in text form, and took float columns;
- bool() took any one-byte binary value; float() refused binary integers,
  read float4 text as a float8, and turned out-of-range numerics into
  infinities;
- a result with no columns had no rows;
- an index past the row or the columns crashed, or read the next row;
- with the statement cache, declared parameter types were not sent;
- DISCARD ALL, DEALLOCATE (ALL or by name) left the cache failing;
- a cancel went to the host name resolved again, not to the session's
  server; a cancel that was not seen through kept the session (it could
  cancel the next statement); a query whose rows kept coming was not
  bounded by its timeout;
- TCP keepalive was off, so a vanished server went unnoticed;
- any 0A000 error ran the statement a second time;
- notices piled up without bound;
- statement names collided with ones already in the session;
- begin() on an ended session said "a transaction is open" (and check(),
  reworked for the receive deadline, still keeps what an idle session
  received);
- Pool.opened() counted connects that failed;
- a COPY FROM STDIN failing before it read (into a view) put every later
  result one query behind."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError
from std.python import Python

from std.time import sleep

from linux.time import Duration, Instant
from net.addr import SocketAddr
from net.blocking import IdleState, idle_state
from pg import Params
from pg.client import MAX_NOTICES, Client, PgError, Rows, quote_identifier
from pg.config import Config
from pg.pool import Pool
from pg_server import PgServer


def _kind(e: PgError) -> String:
    return String(e.io.kind)


def _role_settings(server: PgServer) raises:
    var admin = Client.connect(server.tcp("postgres"))
    _ = admin.execute("ALTER ROLE trusty SET datestyle = 'SQL, DMY'")
    _ = admin.execute("ALTER ROLE trusty SET extra_float_digits = 0")
    _ = admin.execute("ALTER ROLE trusty SET bytea_output = 'escape'")
    admin^.close()
    var db = Client.connect(server.tcp("trusty"))
    assert_true(db.parameter("DateStyle").value().startswith("ISO"))
    # dates and timestamps read in either form, and the text is the server's
    var r = db.query("SELECT now(), date '2024-02-29'")
    _ = r.timestamp(0, 0)
    assert_equal(r.text(0, 1), db.simple_query("SELECT date '2024-02-29'")[0].text(0, 0))
    _ = db.simple_query("SELECT now()")[0].timestamp(0, 0)
    # floats keep every bit
    assert_equal(db.query("SELECT 0.1::float8 + 0.2::float8").float(0, 0), Float64(0.1) + Float64(0.2))
    # bytea reads in text form
    var b = db.simple_query("SELECT '\\x00ff'::bytea")[0].bytes(0, 0)
    assert_equal(len(b), 2)
    assert_equal(b[1], 255)
    db^.close()
    # a DateStyle that is not ISO is refused before connecting
    var german = server.tcp("trusty")
    german.set("DateStyle", "German")
    var refused = False
    try:
        var g = Client.connect(german)
        g^.close()
    except e:
        refused = e.io.kind == ErrorKind.InvalidInput
    assert_true(refused)


def test_the_session_settings_the_driver_relies_on() raises:
    _with_server(0)


def _encoding(server: PgServer) raises:
    var db = Client.connect(server.tcp("trusty"))
    var kind = String()
    try:
        _ = db.execute("SET client_encoding = 'LATIN1'")
    except e:
        kind = _kind(e)
    assert_equal(kind, "Unsupported")  # (the session ends rather than garble text)
    assert_false(db.is_usable())


def test_client_encoding_must_stay_utf8() raises:
    _with_server(1)


def _values(server: PgServer) raises:
    var db = Client.connect(server.unix("trusty"))
    # "char": the server's text in either form
    var sql = 'SELECT \'\'::"char", \'a\'::"char", \'\\303\'::"char"'
    var bin = db.query(sql)
    var txt = db.simple_query(sql)
    for c in range(3):
        assert_equal(bin.text(0, c), txt[0].text(0, c), String(c))
    # int8's extremes in text form
    var ext = db.simple_query("SELECT 9223372036854775807::int8, (-9223372036854775808)::int8, 9223372036854775800::int8")
    assert_equal(ext[0].int(0, 0), Int.MAX)
    assert_equal(ext[0].int(0, 1), Int.MIN)
    assert_equal(ext[0].int(0, 2), 9223372036854775800)
    # int() is for integers: not a float column, whatever its value
    var kinds = List[String]()
    for q in ["SELECT 3::float8", "SELECT 1e16::float8", "SELECT '\\x01'::bytea"]:
        try:
            _ = db.query(q).int(0, 0)
            kinds.append("accepted")
        except e:
            kinds.append(_kind(e))
    assert_equal(String(",").join(kinds), "InvalidData,InvalidData,InvalidData")
    assert_equal(db.query("SELECT sum(x) FROM (VALUES (1::int8), (2)) v(x)").int(0, 0), 3)  # (numeric)
    # bool() is for booleans
    var not_bool = False
    try:
        _ = db.query("SELECT '\\x01'::bytea").bool(0, 0)
    except e:
        not_bool = e.io.kind == ErrorKind.InvalidData
    assert_true(not_bool)
    # float(): binary integers, float4 exactly, and no infinities from numerics
    assert_equal(db.query("SELECT 42::int4").float(0, 0), 42.0)
    assert_equal(db.query("SELECT count(*) FROM generate_series(1, 3)").float(0, 0), 3.0)
    var f4 = db.simple_query("SELECT 0.1::float4")[0].float(0, 0)
    assert_equal(f4, Float64(Float32(0.1)))
    assert_equal(db.query("SELECT 0.1::float4").float(0, 0), f4)
    var ranges = List[String]()
    for q in ["SELECT 1e400::numeric", "SELECT -1e400::numeric", "SELECT 1e-400::numeric"]:
        try:
            _ = db.query(q).float(0, 0)
            ranges.append("accepted")
        except e:
            ranges.append(_kind(e))
    assert_equal(String(",").join(ranges), "InvalidData,InvalidData,InvalidData")
    assert_true(db.query("SELECT 'Infinity'::float8").float(0, 0) > 1e308)
    # a result with no columns still has its rows
    assert_equal(len(db.query("SELECT FROM generate_series(1, 3)")), 3)
    assert_equal(len(db.simple_query("SELECT FROM generate_series(1, 3)")[0]), 3)
    # indexes past the end raise
    var r = db.query("SELECT 1, 2, 3 UNION ALL SELECT 4, 5, 6")
    var out_of_range = 0
    for which in range(4):
        try:
            if which == 0:
                _ = r.int(0, 3)
            elif which == 1:
                _ = r.text(2, 0)
            elif which == 2:
                _ = r.is_null(0, 3)
            else:
                _ = r.value(-1, 0)
        except e:
            out_of_range += Int(e.io.kind == ErrorKind.InvalidInput)
    assert_equal(out_of_range, 4)
    db^.close()


def test_values_read_as_their_types() raises:
    _with_server(2)


def _query_error(mut db: Client, sql: StringSlice, timeout: Duration = Duration.ZERO) raises -> PgError:
    try:
        _ = db.query(sql, timeout=timeout)
    except e:
        return e.copy()
    raise Error(String("no error from ", sql))


def _declared_types(server: PgServer) raises:
    var db = Client.connect(server.tcp("trusty"))  # (the cache on)
    var p = Params()
    var raw: List[UInt8] = [0, 1, 255]
    p.add_binary(Span(raw), 17)
    assert_equal(db.query_params("SELECT $1", p).text(0, 0), "\\x0001ff")
    var as_int = Params()
    as_int.add_text("5", 23)
    assert_equal(db.query_params("SELECT pg_typeof($1)::text", as_int).text(0, 0), "integer")
    var as_text = Params()  # (the same SQL, other types: another statement)
    as_text.add_text("5", 25)
    assert_equal(db.query_params("SELECT pg_typeof($1)::text", as_text).text(0, 0), "text")
    db^.close()


def test_declared_parameter_types_reach_the_server() raises:
    _with_server(3)


def _statement_name(mut db: Client, sql: StringSlice) raises -> String:
    var r = db.simple_query(String("SELECT name FROM pg_prepared_statements WHERE statement = '", sql, "'"))
    return r[0].text(0, 0)


def _discard(server: PgServer) raises:
    var db = Client.connect(server.tcp("trusty"))
    assert_equal(db.query("SELECT 1").int(0, 0), 1)
    _ = db.simple_query("DISCARD ALL")
    assert_equal(db.cached_statements(), 0)  # (emptied with the server's)
    assert_equal(db.query("SELECT 1").int(0, 0), 1)
    _ = db.execute("DEALLOCATE ALL")
    assert_equal(db.query("SELECT 1").int(0, 0), 1)
    assert_equal(db.query("SELECT 1").int(0, 0), 1)
    # in a transaction, where a statement gone missing cannot be retried
    db.begin()
    _ = db.execute("DEALLOCATE ALL")
    assert_equal(db.query("SELECT 1").int(0, 0), 1)
    db.commit()
    _ = db.simple_query(String("DEALLOCATE ", quote_identifier(_statement_name(db, "SELECT 1"))))
    assert_equal(db.query("SELECT 1").int(0, 0), 1)  # (gone behind the cache's back: prepared again)
    db^.close()


def test_the_cache_survives_discard_and_deallocate() raises:
    _with_server(4)


def _cancel_target(server: PgServer) raises:
    # The cancel goes where the session is, not to the name resolved again.
    var db = Client.connect(Config("trusty", host="localhost", port=server.port, database="postgres"))
    db._config.host = "nonexistent.invalid"
    var e = _query_error(db, "SELECT pg_sleep(30)", Duration.from_millis(300))
    assert_equal(e.code(), "57014")
    assert_true(db.is_usable())
    db^.close()
    # A cancel that is not seen through (here a listener that never answers
    # nor closes) may still land later: the session is closed, within one
    # CANCEL_GRACE for the cancel and the query's end together.
    var socket = Python.import_module("socket")
    var silent = socket.socket()
    _ = silent.bind(Python.tuple("127.0.0.1", 0))
    _ = silent.listen(4)
    var port = Int(py=silent.getsockname()[1])
    var d = Client.connect(server.tcp("trusty"))
    d._cancel_to = SocketAddr.parse(String("127.0.0.1:", port))
    var unconfirmed = False
    try:
        d.cancel()  # (with nothing running: it is the confirmation that fails)
    except e:
        unconfirmed = e.is_deadline()
    assert_true(unconfirmed)
    var t = Instant.now()
    try:
        _ = d.query("SELECT pg_sleep(30)", timeout=Duration.from_millis(300))
    except:
        pass
    assert_false(d.is_usable())
    assert_true(t.elapsed() < Duration.from_secs(8))
    _ = silent.close()


def test_cancels_reach_the_session_and_are_seen_through() raises:
    _with_server(5)


def _streaming(server: PgServer) raises:
    var db = Client.connect(server.tcp("trusty"))
    var t = Instant.now()
    var e = _query_error(db, "SELECT repeat('x', 100000) FROM generate_series(1, 5000)", Duration.from_millis(100))
    assert_true(e.is_deadline())
    assert_true(t.elapsed() < Duration.from_secs(6))
    db^.close()


def test_a_timeout_bounds_rows_that_keep_coming() raises:
    _with_server(6)


def _odds(server: PgServer) raises:
    var db = Client.connect(server.tcp("trusty"))
    assert_true(db._sock.keepalive())  # (a vanished server is noticed)
    # only the cached-plan error is retried
    _ = db.execute("CREATE TEMP SEQUENCE s")
    _ = db.execute(
        "CREATE FUNCTION pg_temp.boom() RETURNS int AS $$ BEGIN PERFORM nextval('s');"
        + " RAISE EXCEPTION USING ERRCODE = '0A000', MESSAGE = 'no'; END $$ LANGUAGE plpgsql"
    )
    assert_equal(_query_error(db, "SELECT pg_temp.boom()").code(), "0A000")
    assert_equal(db.query("SELECT last_value FROM s").int(0, 0), 1)
    # notices are capped, the newest kept
    _ = db.execute("DO $$ BEGIN FOR i IN 1..3000 LOOP RAISE NOTICE 'n %', i; END LOOP; END $$")
    var notices = db.take_notices()
    assert_equal(len(notices), MAX_NOTICES)
    assert_equal(notices[len(notices) - 1].message(), "n 3000")
    # statement names of our own kind already in the session
    _ = db.simple_query("PREPARE mojo_1 AS SELECT 1; PREPARE mojo_2 AS SELECT 2; PREPARE mojo_3 AS SELECT 3")
    assert_equal(db.query("SELECT 10").int(0, 0), 10)
    assert_equal(db.query("SELECT 20").int(0, 0), 20)
    assert_equal(db.query("SELECT 30").int(0, 0), 30)
    # begin() on an ended session
    db.begin()
    _ = _query_error(db, "SELECT pg_terminate_backend(pg_backend_pid())")
    var kind = String()
    try:
        db.begin()
    except e:
        kind = _kind(e)
    assert_equal(kind, "Closed")
    # check() reads what an idle session received, without waiting, and
    # keeps both (the deadline that bounds rows must not stop it)
    var listener = Client.connect(server.tcp("trusty"))
    _ = listener.execute("LISTEN jobs")
    var sender = Client.connect(server.tcp("trusty"))
    _ = sender.execute("NOTIFY jobs, 'run'")
    sender^.close()
    var waited = 0
    while idle_state(listener._sock) == IdleState.EMPTY and waited < 500:
        sleep(0.01)
        waited += 1
    assert_true(listener.check())
    var got = listener.take_notifications()
    assert_equal(len(got), 1)
    assert_equal(got[0].payload, "run")
    listener^.close()
    # Pool.opened() counts sessions opened, not attempts
    var socket = Python.import_module("socket")
    var probe = socket.socket()
    _ = probe.bind(Python.tuple("127.0.0.1", 0))
    var free = Int(py=probe.getsockname()[1])
    _ = probe.close()
    var nowhere = server.tcp("trusty")
    nowhere.port = free
    var pool = Pool(nowhere, max_idle=1)
    try:
        var x = pool.acquire()
        x^.close()
    except:
        pass
    assert_equal(pool.opened(), 0)


def test_keepalive_retries_notices_names_begin_and_the_pool() raises:
    _with_server(7)


def _copy_into_a_view(server: PgServer) raises:
    # The COPY fails before reading (42809), so the extra Sync after our
    # CopyFail draws a second ReadyForQuery: it ended the next query's
    # cycle, and every result after it was the previous query's.
    for cache in [10, 0]:
        var config = server.tcp("trusty")
        config.statement_cache = cache
        var db = Client.connect(config)
        _ = db.execute("CREATE TEMP VIEW v AS SELECT 1 AS x")
        var code = String()
        try:
            _ = db.execute("COPY v FROM STDIN")
        except e:
            code = e.code()
        assert_equal(code, "42809")
        for i in range(1, 4):
            var r = db.query("SELECT $1::int", i)
            assert_equal(len(r), 1)
            assert_equal(r.int(0, 0), i)
        assert_true(db.check())
        db^.close()


def test_a_copy_failing_before_it_reads_keeps_the_results_in_step() raises:
    _with_server(8)


def _run(server: PgServer, which: Int) -> String:
    """Body `which` against `server`: "" or why it failed."""
    try:
        if which == 0:
            _role_settings(server)
        elif which == 1:
            _encoding(server)
        elif which == 2:
            _values(server)
        elif which == 3:
            _declared_types(server)
        elif which == 4:
            _discard(server)
        elif which == 5:
            _cancel_target(server)
        elif which == 6:
            _streaming(server)
        elif which == 7:
            _odds(server)
        else:
            _copy_into_a_view(server)
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


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
