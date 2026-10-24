"""`pg.connection`: `PgConnection` driven by transcripts from the Python
oracle (`pg_oracle.py`). Covered:
- the startup settings;
- every authentication method, and each refusal (nothing is sent after one);
- attempts to skip SCRAM's proof;
- the simple query flow and the session's state;
- how a session ends;
- the protocol violations it refuses;
- rule 4 of the Codec contract on whole sessions, and mutated transcripts,
  which must end in events or an `IoError`, never a crash."""

from std.python import Python, PythonObject
from std.random import random_ui64, seed
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from bytes.codec import drive_chunked
from linux import ErrorKind, IoError
from pg import (
    FAILED_TRANSACTION,
    IDLE,
    IN_TRANSACTION,
    AuthMethods,
    BackendKey,
    EventKind,
    PgConnection,
    PgEvent,
    Startup,
)
from pg_util import give, hex, nonce, open_session, oracle, render, sent, unhex


def _s(x: PythonObject) raises -> String:
    return String(x)


def test_startup_sends_the_settings() raises:
    var s = Startup("alice", database="shop", application_name="tests")
    s.set("search_path", "app")
    s.set("options", "-c statement_timeout=5s")
    var c = PgConnection(s, Span(nonce()))
    assert_equal(
        _s(oracle().startup(sent(c))),
        "196608|user=alice|database=shop|application_name=tests|client_encoding=UTF8"
        + "|search_path=app|options=-c statement_timeout=5s#",
    )
    var bare = PgConnection(Startup("bob"), Span(nonce()))
    assert_equal(_s(oracle().startup(sent(bare))), "196608|user=bob|client_encoding=UTF8#")
    assert_equal(sent(bare), "")  # all of it was taken


def _refused(s: Startup, nonce_len: Int = 18) -> Bool:
    try:
        _ = PgConnection(s, Span(List[UInt8](length=nonce_len, fill=1)))
    except e:
        return e.kind == ErrorKind.InvalidInput
    return False


def test_startup_settings_are_checked() raises:
    assert_true(_refused(Startup("alice"), 15))  # a short nonce
    assert_false(_refused(Startup("alice"), 16))
    assert_true(_refused(Startup("")))
    assert_true(_refused(Startup("a\x00b")))
    assert_true(_refused(Startup("alice", database="d\x00")))
    assert_true(_refused(Startup("alice", max_message=1023)))
    for name in ["user", "USER", "database", "client_encoding", "Client_Encoding", "replication", "application_name"]:
        var s = Startup("alice")
        s.set(name, "x")
        assert_true(_refused(s), name)
    var twice = Startup("alice")
    twice.set("search_path", "a")
    twice.set("Search_Path", "b")
    assert_true(_refused(twice))
    var again = Startup("alice")
    again.set("Search_Path", "a")
    again.set("search_path", "b")
    assert_true(_refused(again))
    var nul = Startup("alice")
    nul.set("search_path", "a\x00")
    assert_true(_refused(nul))


def test_trust_and_the_session_state() raises:
    var o = oracle()
    var c = PgConnection(Startup("alice"), Span(nonce()))
    _ = sent(c)
    assert_false(c.is_open())
    assert_equal(c.transaction_status(), 0)
    assert_equal(
        give(
            c,
            _s(o.auth_ok()) + _s(o.parameter("server_version", "18.6")) + _s(o.backend_key(4242, 0xDEADBEEF))
            + _s(o.notice("welcome")) + _s(o.ready("I")),
        ),
        "NOTICE NOTICE 00000: welcome|READY I",
    )
    assert_true(c.is_open())
    assert_true(c.is_idle())
    assert_equal(c.parameter("server_version").value(), "18.6")
    assert_false(Bool(c.parameter("TimeZone")))
    assert_true(c.backend_key().value() == BackendKey(4242, 0xDEADBEEF))
    assert_equal(c.transaction_status(), IDLE)
    # ParameterStatus can come with any result, and replaces the old value
    c.query("SET TIME ZONE 'UTC'")
    assert_equal(
        give(
            c,
            _s(o.command_complete("SET")) + _s(o.parameter("TimeZone", "UTC"))
            + _s(o.parameter("server_version", "18.7")) + _s(o.ready("I")),
        ),
        "COMMAND_COMPLETE SET|READY I",
    )
    assert_equal(c.parameter("TimeZone").value(), "UTC")
    assert_equal(c.parameter("server_version").value(), "18.7")


def test_cleartext_and_md5_passwords() raises:
    var o = oracle()
    var c = PgConnection(Startup("alice", password="s3cret"), Span(nonce()))
    _ = sent(c)
    assert_equal(give(c, _s(o.auth_cleartext())), "")
    assert_equal(_s(o.frontend(sent(c))), String("p:", hex("s3cret"), "00"))
    assert_equal(give(c, _s(o.auth_ok()) + _s(o.session())), "READY I")
    var m = PgConnection(Startup("alice", password="s3cret"), Span(nonce()))
    _ = sent(m)
    assert_equal(give(m, _s(o.auth_md5("01020304"))), "")
    assert_equal(_s(o.frontend(sent(m))), String("p:", hex(_s(o.md5_answer("alice", "s3cret", "01020304"))), "00"))
    assert_equal(give(m, _s(o.auth_ok()) + _s(o.session())), "READY I")


def _scram_session(password: String, server_password: String, iterations: Int) raises -> String:
    """A SCRAM exchange against the oracle's server; what the codec says."""
    var o = oracle()
    var server = o.ScramServer(server_password, hex("NaCl"), iterations, "server-nonce")
    var c = PgConnection(Startup("alice", password=password), Span(nonce()))
    _ = sent(c)
    var got = give(c, _s(o.auth_sasl("SCRAM-SHA-256-PLUS", "SCRAM-SHA-256")))
    if got != "":
        return got
    var initial = _s(o.frontend(sent(c)))
    var client_first = _s(o.sasl_initial(String(initial[byte=2:])))
    if client_first != "n,,n=,r=QkJCQkJCQkJCQkJCQkJCQkJC":  # the nonce bytes, in base64
        return String("client-first ", client_first)
    got = give(c, _s(o.auth_sasl_continue(server.first(client_first))))
    if got != "":
        return got
    var response = _s(o.frontend(sent(c)))
    var verdict = _s(server.final(o.text(String(response[byte=2:]))))
    if not verdict.startswith("ok|"):
        # the server refuses: an error, then it closes
        return give(c, _s(o.error("28P01", "password authentication failed", "FATAL")), eof=True)
    return give(c, _s(o.auth_sasl_final(String(verdict[byte=3:]))) + _s(o.auth_ok()) + _s(o.session()))


def test_scram_sha_256() raises:
    assert_equal(_scram_session("pencil é", "pencil é", 4096), "READY I")
    assert_equal(
        _scram_session("wrong", "pencil", 4096),
        "ERROR FATAL 28P01: password authentication failed",
    )


def _first_request(startup: Startup, request: String) raises -> String:
    """What the codec says to the server's first authentication request,
    and "+sent" if it sent anything after it."""
    var c = PgConnection(startup, Span(nonce()))
    _ = sent(c)
    var got = give(c, request)
    if sent(c) != "":
        got += "+sent"
    return got^


def test_authentication_refusals() raises:
    var o = oracle()
    var not_allowed = "error PermissionDenied: pg: the server asks for authentication this connection does not allow"
    var scram_only = AuthMethods.SCRAM_SHA_256
    # methods the caller did not allow: nothing leaves the client
    assert_equal(_first_request(Startup("a", password="p", allow=scram_only), _s(o.auth_cleartext())), not_allowed)
    assert_equal(_first_request(Startup("a", password="p", allow=scram_only), _s(o.auth_md5("01020304"))), not_allowed)
    assert_equal(
        _first_request(Startup("a", password="p", allow=scram_only | AuthMethods.MD5), _s(o.auth_ok())),
        not_allowed,
    )
    assert_equal(
        _first_request(Startup("a", password="p", allow=AuthMethods.PASSWORD), _s(o.auth_sasl("SCRAM-SHA-256"))),
        not_allowed,
    )
    assert_equal(_first_request(Startup("a", allow=AuthMethods.TRUST), _s(o.auth_ok())), "")
    # a password request without a password
    var no_password = "error InvalidInput: pg: the server asks for a password and none was given"
    assert_equal(_first_request(Startup("a"), _s(o.auth_cleartext())), no_password)
    assert_equal(_first_request(Startup("a"), _s(o.auth_md5("01020304"))), no_password)
    assert_equal(_first_request(Startup("a"), _s(o.auth_sasl("SCRAM-SHA-256"))), no_password)
    # what this client cannot do
    assert_equal(
        _first_request(Startup("a", password="p"), _s(o.auth_sasl("SCRAM-SHA-256-PLUS"))),
        "error Unsupported: pg: the server offers no SCRAM-SHA-256",
    )
    for code in [2, 6, 7, 9]:
        assert_equal(
            _first_request(Startup("a", password="p"), _s(o.auth(code))),
            "error Unsupported: pg: the server asks for unsupported authentication",
        )
    # malformed requests
    var malformed = "error InvalidData: pg: malformed authentication request"
    assert_equal(_first_request(Startup("a", password="p"), _s(o.auth(99))), malformed)
    assert_equal(_first_request(Startup("a", password="p"), _s(o.auth(3, "00"))), malformed)
    assert_equal(_first_request(Startup("a", password="p"), _s(o.auth(5, "0102"))), malformed)
    assert_equal(_first_request(Startup("a", password="p"), _s(o.auth(5, "0102030405"))), malformed)
    assert_equal(_first_request(Startup("a", password="p"), _s(o.auth(0, "00"))), malformed)
    assert_equal(_first_request(Startup("a", password="p"), _s(o.auth(10, hex("SCRAM-SHA-256")))), malformed)


def test_scram_cannot_be_skipped() raises:
    var o = oracle()
    var incomplete = "error InvalidData: pg: authentication ended before the SCRAM exchange did"
    # AuthenticationOk right after the SASL request...
    var c = PgConnection(Startup("alice", password="pencil"), Span(nonce()))
    _ = sent(c)
    assert_equal(give(c, _s(o.auth_sasl("SCRAM-SHA-256")) + _s(o.auth_ok())), incomplete)
    # ...or after the server's first message, before its proof
    var server = o.ScramServer("pencil", hex("NaCl"), 1, "srv")
    c = PgConnection(Startup("alice", password="pencil"), Span(nonce()))
    _ = sent(c)
    _ = give(c, _s(o.auth_sasl("SCRAM-SHA-256")))
    var first = _s(server.first(_s(o.sasl_initial(String(_s(o.frontend(sent(c)))[byte=2:])))))
    assert_equal(give(c, _s(o.auth_sasl_continue(first)) + _s(o.auth_ok())), incomplete)
    # a forged final message
    c = PgConnection(Startup("alice", password="pencil"), Span(nonce()))
    _ = sent(c)
    _ = give(c, _s(o.auth_sasl("SCRAM-SHA-256")))
    _ = sent(c)
    assert_equal(
        give(c, _s(o.auth_sasl_continue(first)) + _s(o.auth_sasl_final("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))),
        "error InvalidData: pg: SCRAM: wrong server signature",
    )
    # the final message without the first, a continue without SASL, a
    # nonce that is not ours extended, a second request
    c = PgConnection(Startup("alice", password="pencil"), Span(nonce()))
    _ = sent(c)
    assert_equal(
        give(c, _s(o.auth_sasl("SCRAM-SHA-256")) + _s(o.auth_sasl_final("v=AAAA"))),
        "error InvalidData: pg: unexpected message from the server",
    )
    c = PgConnection(Startup("alice", password="pencil"), Span(nonce()))
    _ = sent(c)
    assert_equal(give(c, _s(o.auth_sasl_continue(first))), "error InvalidData: pg: unexpected message from the server")
    c = PgConnection(Startup("alice", password="pencil"), Span(nonce()))
    _ = sent(c)
    assert_equal(
        give(c, _s(o.auth_sasl("SCRAM-SHA-256")) + _s(o.auth_sasl_continue("r=someone-else,s=TmFDbA==,i=1"))),
        "error InvalidData: pg: SCRAM: the server's nonce does not extend ours",
    )
    c = PgConnection(Startup("alice", password="pencil"), Span(nonce()))
    _ = sent(c)
    assert_equal(
        give(c, _s(o.auth_cleartext()) + _s(o.auth_md5("01020304"))),
        "error InvalidData: pg: a second authentication request",
    )


def test_startup_errors_end_the_session() raises:
    var o = oracle()
    var c = PgConnection(Startup("alice", password="x"), Span(nonce()))
    _ = sent(c)
    _ = give(c, _s(o.auth_cleartext()))
    _ = sent(c)
    assert_equal(
        give(c, _s(o.error("28P01", "password authentication failed for user alice", "FATAL")), eof=True),
        "ERROR FATAL 28P01: password authentication failed for user alice",
    )
    assert_false(c.is_open())
    var refused = False
    try:
        c.query("SELECT 1")
    except e:
        refused = e.kind == ErrorKind.InvalidInput
    assert_true(refused)
    # after AuthenticationOk too (no such database)
    var d = PgConnection(Startup("alice"), Span(nonce()))
    _ = sent(d)
    assert_equal(
        give(d, _s(o.auth_ok()) + _s(o.error("3D000", "database nope does not exist", "FATAL")), eof=True),
        "ERROR FATAL 3D000: database nope does not exist",
    )
    # nothing may follow
    var late = PgConnection(Startup("alice"), Span(nonce()))
    _ = sent(late)
    assert_equal(
        give(late, _s(o.error("53300", "too many clients", "FATAL")) + _s(o.auth_ok())),
        "ERROR FATAL 53300: too many clients|error InvalidData: pg: unexpected message from the server",
    )
    late = open_session(Startup("alice"))
    assert_equal(
        give(late, _s(o.error("57P01", "bye", "FATAL")) + _s(o.parameter("a", "b"))),
        "ERROR FATAL 57P01: bye|error InvalidData: pg: unexpected message from the server",
    )
    # any error during startup ends it, FATAL or not
    var plain = PgConnection(Startup("alice"), Span(nonce()))
    _ = sent(plain)
    assert_equal(give(plain, _s(o.error("XX000", "odd")), eof=True), "ERROR ERROR XX000: odd")
    assert_false(plain.is_open())


def test_simple_query() raises:
    var o = oracle()
    var c = open_session(Startup("alice"))
    c.query("SELECT id, name FROM t; UPDATE t SET x = 1")
    assert_equal(_s(o.frontend(sent(c))), String("Q:", hex("SELECT id, name FROM t; UPDATE t SET x = 1"), "00"))
    assert_false(c.is_idle())
    assert_equal(c.pending_queries(), 1)
    assert_equal(
        give(
            c,
            _s(o.row_description("id:23", "name:25")) + _s(o.data_row("1", "a")) + _s(o.data_row("2", None))
            + _s(o.data_row("3", "")) + _s(o.command_complete("SELECT 3")) + _s(o.command_complete("UPDATE 2"))
            + _s(o.ready("I")),
        ),
        "ROW_DESCRIPTION id:23 name:25|DATA_ROW 1 a|DATA_ROW 2 NULL|DATA_ROW 3 |COMMAND_COMPLETE SELECT 3"
        + "|COMMAND_COMPLETE UPDATE 2|READY I",
    )
    assert_true(c.is_idle())


def test_event_accessors() raises:
    var o = oracle()
    var c = open_session(Startup("alice"))
    c.query("SELECT ...")
    var data = unhex(
        _s(o.row_description("id:23", "note:25")) + _s(o.data_row("42", None)) + _s(o.command_complete("SELECT 1"))
        + _s(o.notice("careful", "WARNING", "01000")) + _s(o.notification(77, "jobs", "run")) + _s(o.ready("T"))
    )
    c.feed(Span(data))
    var ev = PgEvent()
    assert_true(c.poll(ev))
    assert_true(ev.kind == EventKind.ROW_DESCRIPTION)
    var cols = ev.columns()
    assert_equal(len(cols), 2)
    assert_equal(cols[1].name, "note")
    assert_true(c.poll(ev))
    assert_true(ev.kind == EventKind.DATA_ROW)
    assert_equal(ev.values(), 2)
    assert_false(ev.is_null(0))
    assert_equal(String(from_utf8_lossy=ev.value(0)), "42")
    assert_true(ev.is_null(1))
    assert_equal(len(ev.value(1)), 0)
    assert_true(c.poll(ev))
    assert_true(ev.kind == EventKind.COMMAND_COMPLETE)
    assert_equal(ev.tag(), "SELECT 1")
    assert_equal(ev.rows_affected().value(), 1)
    assert_true(c.poll(ev))
    assert_true(ev.kind == EventKind.NOTICE)
    var m = ev.server_message()
    assert_equal(m.severity(), "WARNING")
    assert_equal(m.code(), "01000")
    assert_true(c.poll(ev))
    assert_true(ev.kind == EventKind.NOTIFICATION)
    var n = ev.notification()
    assert_equal(n.channel, "jobs")
    assert_equal(n.payload, "run")
    assert_equal(n.pid, 77)
    assert_true(c.poll(ev))
    assert_true(ev.kind == EventKind.READY)
    assert_equal(ev.status, IN_TRANSACTION)
    assert_equal(c.transaction_status(), IN_TRANSACTION)
    assert_false(c.poll(ev))
    _ = ev^


def test_errors_end_the_statements_not_the_session() raises:
    var o = oracle()
    var c = open_session(Startup("alice"))
    c.query("BEGIN; SELECT 1/0; SELECT 2")
    assert_equal(
        give(
            c,
            _s(o.command_complete("BEGIN")) + _s(o.row_description("?column?:23"))
            + _s(o.error("22012", "division by zero")) + _s(o.ready("E")),
        ),
        "COMMAND_COMPLETE BEGIN|ROW_DESCRIPTION ?column?:23|ERROR ERROR 22012: division by zero|READY E",
    )
    assert_equal(c.transaction_status(), FAILED_TRANSACTION)
    assert_true(c.is_idle())
    c.query("ROLLBACK")
    assert_equal(give(c, _s(o.command_complete("ROLLBACK")) + _s(o.ready("I"))), "COMMAND_COMPLETE ROLLBACK|READY I")
    assert_equal(c.transaction_status(), IDLE)
    # an error ends its statement: a row after it is a violation
    c.query("SELECT 1/0")
    assert_equal(
        give(c, _s(o.row_description("x:23")) + _s(o.error("22012", "division by zero")) + _s(o.data_row("1"))),
        "ROW_DESCRIPTION x:23|ERROR ERROR 22012: division by zero|error InvalidData: pg: unexpected message from the server",
    )
    # so does CommandComplete; and rows need it before ReadyForQuery
    var d = open_session(Startup("alice"))
    d.query("SELECT 1")
    assert_equal(
        give(d, _s(o.row_description("x:23")) + _s(o.command_complete("SELECT 0")) + _s(o.data_row("1"))),
        "ROW_DESCRIPTION x:23|COMMAND_COMPLETE SELECT 0|error InvalidData: pg: unexpected message from the server",
    )
    var e = open_session(Startup("alice"))
    e.query("SELECT 1")
    assert_equal(
        give(e, _s(o.row_description("x:23")) + _s(o.data_row("1")) + _s(o.ready("I"))),
        "ROW_DESCRIPTION x:23|DATA_ROW 1|error InvalidData: pg: unexpected message from the server",
    )


def test_empty_queries_notifications_and_pipelining() raises:
    var o = oracle()
    var c = open_session(Startup("alice"))
    c.query("")
    assert_equal(_s(o.frontend(sent(c))), "Q:00")
    assert_equal(give(c, _s(o.empty_query()) + _s(o.ready("I"))), "EMPTY_QUERY|READY I")
    # notifications come between queries too
    assert_equal(give(c, _s(o.notification(77, "jobs", "hi"))), "NOTIFICATION notification on jobs from 77: hi")
    assert_true(c.is_idle())
    # two queries in flight, answered in order
    c.query("SELECT 1")
    c.query("SELECT 2")
    assert_equal(c.pending_queries(), 2)
    assert_equal(
        _s(o.frontend(sent(c))),
        String("Q:", hex("SELECT 1"), "00|Q:", hex("SELECT 2"), "00"),
    )
    assert_equal(
        give(
            c,
            _s(o.row_description("a:23")) + _s(o.data_row("1")) + _s(o.command_complete("SELECT 1")) + _s(o.ready("I"))
            + _s(o.row_description("b:23")) + _s(o.data_row("2")) + _s(o.command_complete("SELECT 1")),
        ),
        "ROW_DESCRIPTION a:23|DATA_ROW 1|COMMAND_COMPLETE SELECT 1|READY I|ROW_DESCRIPTION b:23|DATA_ROW 2"
        + "|COMMAND_COMPLETE SELECT 1",
    )
    assert_equal(c.pending_queries(), 1)
    assert_equal(give(c, _s(o.ready("I"))), "READY I")
    assert_true(c.is_idle())


def test_copy() raises:
    var o = oracle()
    var c = open_session(Startup("alice"))
    c.query("COPY t FROM STDIN")
    _ = sent(c)
    assert_equal(give(c, _s(o.copy_in())), "")
    assert_equal(_s(o.frontend(sent(c))), String("f:", hex("COPY FROM STDIN is not supported by this client"), "00"))
    assert_equal(
        give(c, _s(o.error("57014", "COPY from stdin failed")) + _s(o.ready("I"))),
        "ERROR ERROR 57014: COPY from stdin failed|READY I",
    )
    c.query("COPY t TO STDOUT")
    assert_equal(give(c, _s(o.copy_out())), "error Unsupported: pg: COPY TO STDOUT is not supported")


def test_how_sessions_end() raises:
    var o = oracle()
    # FATAL while idle (an administrator's shutdown): EOF after it is clean
    var c = open_session(Startup("alice"))
    assert_equal(
        give(c, _s(o.error("57P01", "terminating connection due to administrator command", "FATAL")), eof=True),
        "ERROR FATAL 57P01: terminating connection due to administrator command",
    )
    assert_false(c.is_open())
    # EOF while open is an error, and it sticks (rule 6)
    var d = open_session(Startup("alice"))
    assert_equal(give(d, "", eof=True), "error UnexpectedEof: pg: the server closed the connection")
    assert_equal(give(d, ""), "error UnexpectedEof: pg: the server closed the connection")
    # EOF inside a message
    var e = open_session(Startup("alice"))
    e.query("SELECT 1")
    var row = _s(o.data_row("1"))
    assert_equal(
        give(e, _s(o.row_description("x:23")) + String(row[byte=0 : row.byte_length() - 2]), eof=True),
        "ROW_DESCRIPTION x:23|error UnexpectedEof: pg: the server closed the connection",
    )
    # Terminate: sent once; queries are refused after it; EOF is the end
    var f = open_session(Startup("alice"))
    f.terminate()
    f.terminate()
    assert_equal(_s(o.frontend(sent(f))), "X:")
    assert_false(f.is_open())
    var refused = False
    try:
        f.query("SELECT 1")
    except err:
        refused = err.kind == ErrorKind.InvalidInput
    assert_true(refused)
    assert_equal(give(f, "", eof=True), "")
    # but not inside a message
    var h = open_session(Startup("alice"))
    h.terminate()
    assert_equal(give(h, String(row[byte=0:6]), eof=True), "error UnexpectedEof: pg: the server closed the connection")
    # queries queued before Terminate still get their results
    var g = open_session(Startup("alice"))
    g.query("SELECT 1")
    g.terminate()
    assert_equal(give(g, _s(o.command_complete("SELECT 0")) + _s(o.ready("I")), eof=True), "COMMAND_COMPLETE SELECT 0|READY I")


def _violation(server: String, query: Bool = True) raises -> String:
    var c = open_session(Startup("alice", max_message=1024))
    if query:
        c.query("SELECT 1")
    return give(c, server)


def test_protocol_violations() raises:
    var o = oracle()
    var unexpected = "error InvalidData: pg: unexpected message from the server"
    assert_equal(_violation(_s(o.data_row("1"))), unexpected)  # no RowDescription
    assert_equal(
        _violation(_s(o.row_description("a:23")) + _s(o.data_row("1", "2"))),
        "ROW_DESCRIPTION a:23|error InvalidData: pg: malformed DataRow",
    )
    assert_equal(_violation(_s(o.ready("I")), query=False), unexpected)  # no query in flight
    assert_equal(_violation(_s(o.command_complete("SELECT 1")), query=False), unexpected)
    assert_equal(_violation(_s(o.backend_key(1, 2))), unexpected)  # only during startup
    assert_equal(_violation(String(hex("Y"), "00000004")), unexpected)  # an unknown type
    assert_equal(_violation(String(hex("C"), "00000003")), "error InvalidData: pg: message length out of bounds")
    # the length alone is enough to refuse: no need to wait for the body
    assert_equal(_violation(String(hex("D"), "00000401")), "error InvalidData: pg: message length out of bounds")
    assert_equal(_violation(_s(o.ready("X"))), "error InvalidData: pg: malformed ReadyForQuery")
    assert_equal(_violation(String(hex("Z"), "00000006", hex("II"))), "error InvalidData: pg: malformed ReadyForQuery")
    assert_equal(_violation(String(hex("I"), "0000000500")), unexpected)  # EmptyQueryResponse with a body
    # during startup
    assert_equal(_first_request(Startup("a"), _s(o.data_row("1"))), unexpected)
    assert_equal(_first_request(Startup("a"), _s(o.ready("I"))), unexpected)
    assert_equal(
        _first_request(Startup("a"), _s(o.negotiate(0, "_pq_.x"))),
        "error Unsupported: pg: the server cannot speak protocol 3.0 as asked",
    )
    assert_equal(  # one option said, none there
        _first_request(Startup("a"), String(hex("v"), "0000000c", "00000000", "00000001")),
        "error Unsupported: pg: the server cannot speak protocol 3.0 as asked",
    )
    assert_equal(_first_request(Startup("a"), _s(o.negotiate(0)) + _s(o.auth_ok()) + _s(o.session())), "READY I")
    assert_equal(  # only before authentication starts
        _first_request(Startup("a", password="p"), _s(o.auth_cleartext()) + _s(o.negotiate(0))),
        "error InvalidData: pg: unexpected message from the server+sent",
    )


def test_feeding_and_sending_rules() raises:
    var o = oracle()
    # feed after EOF; feed past feed_capacity()
    var c = open_session(Startup("alice", max_message=1024))
    c.feed_eof()
    var kind = ErrorKind.Other
    try:
        c.feed("x".as_bytes())
    except e:
        kind = e.kind
    assert_true(kind == ErrorKind.InvalidInput)
    var d = open_session(Startup("alice", max_message=1024))
    assert_equal(d.feed_capacity(), 1025)
    kind = ErrorKind.Other
    try:
        d.feed(Span(List[UInt8](length=2000, fill=0)))
    except e:
        kind = e.kind
    assert_true(kind == ErrorKind.OutOfMemory)
    assert_equal(give(d, ""), "error OutOfMemory: pg: fed past feed_capacity()")  # and it stays failed
    # misuse of the send side does not hurt the session
    var s = PgConnection(Startup("alice"), Span(nonce()))
    var refused = 0
    try:
        s.query("SELECT 1")  # before it is open
    except err:
        refused += Int(err.kind == ErrorKind.InvalidInput)
    _ = sent(s)
    assert_equal(give(s, _s(o.auth_ok()) + _s(o.session())), "READY I")
    try:
        s.query("SELECT \x00")
    except err:
        refused += Int(err.kind == ErrorKind.InvalidInput)
    assert_equal(refused, 2)
    assert_true(s.is_idle())
    assert_equal(sent(s), "")
    # poll_transmit appends no more than the buffer takes, in order
    s.query("SELECT 123456789")
    var small = ByteBuffer(max_size=10)
    assert_equal(s.poll_transmit(small), 10)
    assert_equal(s.poll_transmit(small), 0)
    var rest = ByteBuffer()
    assert_equal(s.poll_transmit(rest), 22 - 10)
    assert_equal(hex(small.readable_span()) + hex(rest.readable_span()), String(hex("Q"), "00000015", hex("SELECT 123456789"), "00"))


def _render(ev: PgEvent) -> String:
    return String(ev)


def test_events_do_not_depend_on_the_split() raises:
    var o = oracle()
    # a whole startup, with notices and parameters on the way
    var startup = unhex(
        _s(o.auth_ok()) + _s(o.notice("hello")) + _s(o.session()) + _s(o.notification(9, "c", "p"))
    )
    var got = drive_chunked[_render](PgConnection(Startup("alice"), Span(nonce())), Span(startup))
    assert_equal(
        String(" | ").join(got),
        "NOTICE NOTICE 00000: hello | READY I | NOTIFICATION notification on c from 9: p | error UnexpectedEof",
    )
    # results of two pipelined queries, ending with the server shutting down
    var c = open_session(Startup("alice"))
    c.query("SELECT 1")
    c.query("SELECT 2")
    _ = sent(c)
    var results = unhex(
        _s(o.row_description("id:23", "name:25")) + _s(o.data_row("1", "a")) + _s(o.data_row("2", None))
        + _s(o.notice("n")) + _s(o.command_complete("SELECT 2")) + _s(o.ready("I"))
        + _s(o.error("42P01", "no such table")) + _s(o.parameter("TimeZone", "UTC")) + _s(o.ready("I"))
        + _s(o.error("57P01", "shutting down", "FATAL"))
    )
    got = drive_chunked[_render](c, Span(results))
    assert_equal(len(got), 9)
    assert_equal(got[8], "ERROR FATAL 57P01: shutting down")
    # a SCRAM exchange (one round, to keep it quick), its server side
    # computed once: the nonce is fixed, so every run sends the same
    var server = o.ScramServer("pencil", hex("NaCl"), 1, "srv")
    var probe = PgConnection(Startup("alice", password="pencil"), Span(nonce()))
    _ = sent(probe)
    _ = give(probe, _s(o.auth_sasl("SCRAM-SHA-256")))
    var first = _s(server.first(_s(o.sasl_initial(String(_s(o.frontend(sent(probe)))[byte=2:])))))
    _ = give(probe, _s(o.auth_sasl_continue(first)))
    var verdict = _s(server.final(o.text(String(_s(o.frontend(sent(probe)))[byte=2:]))))
    assert_true(verdict.startswith("ok|"))
    var scram = unhex(
        _s(o.auth_sasl("SCRAM-SHA-256")) + _s(o.auth_sasl_continue(first))
        + _s(o.auth_sasl_final(String(verdict[byte=3:]))) + _s(o.auth_ok()) + _s(o.session())
    )
    got = drive_chunked[_render](
        PgConnection(Startup("alice", password="pencil"), Span(nonce())), Span(scram), max_pair_len=64
    )
    assert_equal(String(" | ").join(got), "READY I | error UnexpectedEof")


def _rand(n: Int) -> Int:
    return Int(random_ui64(0, UInt64(n - 1)))


def _mutate(data: List[UInt8]) -> List[UInt8]:
    """`data` with a few random bytes changed, dropped or inserted, or cut."""
    var out = data.copy()
    for _ in range(1 + _rand(3)):
        var how = _rand(4)
        var at = _rand(max(len(out), 1))
        if how == 0 and len(out) > 0:
            out[at] = UInt8(_rand(256))
        elif how == 1 and len(out) > 0:
            out[at] ^= UInt8(1 << _rand(8))
        elif how == 2 and len(out) > 0:
            _ = out.pop(at)
        else:
            out.insert(at, UInt8(_rand(256)))
    if _rand(8) == 0:
        out.resize(_rand(len(out) + 1), 0)
    return out^


def test_mutated_transcripts_never_crash() raises:
    seed(2026)
    var o = oracle()
    var startup = unhex(_s(o.auth_md5("01020304")) + _s(o.auth_ok()) + _s(o.session()))
    var results = unhex(
        _s(o.row_description("id:23", "name:25")) + _s(o.data_row("1", "a")) + _s(o.data_row("2", None))
        + _s(o.command_complete("SELECT 2")) + _s(o.notification(9, "c", "p")) + _s(o.ready("I"))
        + _s(o.error("42P01", "no such table", P="15")) + _s(o.ready("E"))
    )
    var outcomes = 0
    var errors = 0
    for round in range(3000):
        var c: PgConnection
        var data: List[UInt8]
        if round % 2 == 0:
            c = PgConnection(Startup("alice", password="pw"), Span(nonce()))
            data = _mutate(startup)
        else:
            c = open_session(Startup("alice"))
            c.query("SELECT 1")
            c.query("SELECT 2")
            data = _mutate(results)
        var got = give(c, hex(Span(data)), eof=round % 3 == 0)
        outcomes += 1
        if got.find("error ") >= 0:
            errors += 1
    assert_equal(outcomes, 3000)
    assert_true(errors > 1000, String(errors))  # (most mutations break something)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
