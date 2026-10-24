"""`pg.connection` and `pg.message`: the extended query protocol, against
the Python oracle (`pg_oracle.py`). Covered:
- what the codec sends (Parse, Bind with each mix of value formats,
  Describe, Execute, Sync, Close), whole or not at all;
- the events of each cycle: the unnamed statement, prepare then execute,
  close;
- an error that skips to Sync, and pipelined cycles;
- the violations refused;
- rule 4 over a whole prepared exchange."""

from std.python import PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.codec import drive_chunked
from linux import ErrorKind, IoError
from pg import BINARY, TEXT, PgConnection, PgEvent, Params, Startup
from pg.message import MAX_PARAMS
from pg_util import give, hex, nonce, open_session, oracle, sent, unhex


def _s(x: PythonObject) raises -> String:
    return String(x)


def _ints(*values: Int) -> Params:
    var p = Params()
    for v in values:
        p.add(v)
    return p^


def test_what_execute_sends() raises:
    var o = oracle()
    var c = open_session(Startup("alice"))
    var p = Params()
    p.add(42)
    p.add("it's; DROP TABLE t")
    p.add_null()
    p.add_text("2024-01-01", 1082)
    c.execute("SELECT $1, $2, $3, $4", p)
    assert_equal(
        _s(o.frontend_text(sent(c))),
        "P |SELECT $1, $2, $3, $4|0,0,0,1082 | B |||t:42,t:it's; DROP TABLE t,NULL,t:2024-01-01|0 | D P  | E |0 | S",
    )
    assert_equal(c.pending_queries(), 1)
    # the value formats: no code when all are text, one when all are
    # binary, one per value when they are mixed; results in binary
    var binary = Params()
    var raw: List[UInt8] = [0, 1, 255]
    binary.add_binary(Span(raw), 17)
    binary.add_binary(Span(raw), 17)
    c.execute("SELECT $1, $2", binary, BINARY)
    assert_equal(_s(o.frontend_text(sent(c))), "P |SELECT $1, $2|17,17 | B ||1|b:0001ff,b:0001ff|1 | D P  | E |0 | S")
    var mixed = Params()
    mixed.add(1)
    mixed.add_binary(Span(raw), 17)
    c.execute("SELECT $1, $2", mixed)
    assert_equal(_s(o.frontend_text(sent(c))), "P |SELECT $1, $2|0,17 | B ||0,1|t:1,b:0001ff|0 | D P  | E |0 | S")
    c.execute("SELECT 1", Params())
    assert_equal(_s(o.frontend_text(sent(c))), "P |SELECT 1| | B ||||0 | D P  | E |0 | S")


def test_an_unnamed_statement_cycle() raises:
    var o = oracle()
    var c = open_session(Startup("alice"))
    c.execute("SELECT $1::int", _ints(42))
    _ = sent(c)
    assert_equal(
        give(
            c,
            _s(o.parse_complete()) + _s(o.bind_complete()) + _s(o.row_description("int4:23"))
            + _s(o.data_row("42")) + _s(o.command_complete("SELECT 1")) + _s(o.ready("I")),
        ),
        "PARSE_COMPLETE|BIND_COMPLETE|ROW_DESCRIPTION int4:23|DATA_ROW 42|COMMAND_COMPLETE SELECT 1|READY I",
    )
    # a statement without rows describes as NO_DATA
    c.execute("UPDATE t SET x = $1", _ints(1))
    assert_equal(
        give(
            c,
            _s(o.parse_complete()) + _s(o.bind_complete()) + _s(o.no_data()) + _s(o.command_complete("UPDATE 3"))
            + _s(o.ready("I")),
        ),
        "PARSE_COMPLETE|BIND_COMPLETE|NO_DATA|COMMAND_COMPLETE UPDATE 3|READY I",
    )
    assert_true(c.is_idle())


def test_prepare_execute_close() raises:
    var o = oracle()
    var c = open_session(Startup("alice"))
    c.prepare("s1", "SELECT name FROM t WHERE id = $1", Params())
    assert_equal(_s(o.frontend_text(sent(c))), "P s1|SELECT name FROM t WHERE id = $1| | D S s1 | S")
    assert_equal(
        give(
            c,
            _s(o.parse_complete()) + _s(o.parameter_description(23)) + _s(o.row_description("name:25"))
            + _s(o.ready("I")),
        ),
        "PARSE_COMPLETE|PARAMETER_DESCRIPTION 23|ROW_DESCRIPTION name:25|READY I",
    )
    c.execute_prepared("s1", _ints(7))
    assert_equal(_s(o.frontend_text(sent(c))), "B |s1||t:7|0 | D P  | E |0 | S")
    assert_equal(
        give(
            c,
            _s(o.bind_complete()) + _s(o.row_description("name:25")) + _s(o.data_row("x"))
            + _s(o.command_complete("SELECT 1")) + _s(o.ready("I")),
        ),
        "BIND_COMPLETE|ROW_DESCRIPTION name:25|DATA_ROW x|COMMAND_COMPLETE SELECT 1|READY I",
    )
    c.close_statement("s1")
    assert_equal(_s(o.frontend_text(sent(c))), "C S s1 | S")
    assert_equal(give(c, _s(o.close_complete()) + _s(o.ready("I"))), "CLOSE_COMPLETE|READY I")
    # a statement without rows: its parameters, then NO_DATA
    c.prepare("s2", "DELETE FROM t WHERE id = $1 AND tag = $2", Params())
    _ = sent(c)
    assert_equal(
        give(c, _s(o.parse_complete()) + _s(o.parameter_description(23, 25)) + _s(o.no_data()) + _s(o.ready("I"))),
        "PARSE_COMPLETE|PARAMETER_DESCRIPTION 23 25|NO_DATA|READY I",
    )
    # the event's types
    var data = unhex(_s(o.parameter_description(20, 1082)))
    var d = open_session(Startup("alice"))
    d.prepare("s3", "SELECT $1, $2", Params())
    d.feed(Span(unhex(_s(o.parse_complete()))))
    d.feed(Span(data))
    var ev = PgEvent()
    assert_true(d.poll(ev))
    assert_true(d.poll(ev))
    var types = ev.parameter_types()
    assert_equal(len(types), 2)
    assert_equal(types[0], 20)
    assert_equal(types[1], 1082)
    _ = ev^


def test_errors_skip_to_sync_and_cycles_pipeline() raises:
    var o = oracle()
    var c = open_session(Startup("alice"))
    var bad = Params()
    bad.add("abc")
    c.execute("SELECT $1::int", bad)
    c.execute("SELECT 2", Params())
    assert_equal(c.pending_queries(), 2)
    _ = sent(c)
    assert_equal(
        give(
            c,
            _s(o.parse_complete()) + _s(o.error("22P02", "invalid input syntax for type integer")) + _s(o.ready("I"))
            + _s(o.parse_complete()) + _s(o.bind_complete()) + _s(o.row_description("?column?:23"))
            + _s(o.data_row("2")) + _s(o.command_complete("SELECT 1")) + _s(o.ready("I")),
        ),
        "PARSE_COMPLETE|ERROR ERROR 22P02: invalid input syntax for type integer|READY I"
        + "|PARSE_COMPLETE|BIND_COMPLETE|ROW_DESCRIPTION ?column?:23|DATA_ROW 2|COMMAND_COMPLETE SELECT 1|READY I",
    )
    assert_true(c.is_idle())


def test_copy_from_stdin_in_an_extended_cycle() raises:
    var o = oracle()
    var c = open_session(Startup("alice"))
    c.execute("COPY t FROM STDIN", Params())
    _ = sent(c)
    assert_equal(
        give(c, _s(o.parse_complete()) + _s(o.bind_complete()) + _s(o.no_data()) + _s(o.copy_in())),
        "PARSE_COMPLETE|BIND_COMPLETE|NO_DATA",
    )
    # In copy-in mode the server skipped our Sync; after the CopyFail it
    # waits for another one.
    assert_equal(_s(o.frontend_text(sent(c))), "f COPY FROM STDIN is not supported by this client | S")
    assert_equal(
        give(c, _s(o.error("57014", "COPY from stdin failed")) + _s(o.ready("I"))),
        "ERROR ERROR 57014: COPY from stdin failed|READY I",
    )
    assert_true(c.is_idle())
    # a simple Query's COPY after it gets the CopyFail alone
    c.query("COPY t FROM STDIN")
    _ = sent(c)
    assert_equal(give(c, _s(o.copy_in())), "")
    assert_equal(_s(o.frontend_text(sent(c))), "f COPY FROM STDIN is not supported by this client")


def _violation(server: String) raises -> String:
    var c = open_session(Startup("alice"))
    c.prepare("s", "SELECT $1", Params())
    return give(c, server)


def test_extended_violations() raises:
    var o = oracle()
    var unexpected = "error InvalidData: pg: unexpected message from the server"
    assert_equal(_violation(String(hex("1"), "0000000500")), unexpected)  # ParseComplete with a body
    assert_equal(
        _violation(_s(o.parse_complete()) + String(hex("t"), "0000000a", "0002", "00000017")),  # 2 types, 1 there
        "PARSE_COMPLETE|error InvalidData: pg: malformed ParameterDescription",
    )
    assert_equal(
        _violation(_s(o.parse_complete()) + String(hex("t"), "0000000e", "0001", "00000017", "00000019")),  # 1, 2 there
        "PARSE_COMPLETE|error InvalidData: pg: malformed ParameterDescription",
    )
    # a statement's description has no rows after it, and needs its columns
    assert_equal(
        _violation(
            _s(o.parse_complete()) + _s(o.parameter_description(23)) + _s(o.row_description("a:23"))
            + _s(o.data_row("1"))
        ),
        "PARSE_COMPLETE|PARAMETER_DESCRIPTION 23|ROW_DESCRIPTION a:23|" + unexpected,
    )
    assert_equal(
        _violation(_s(o.parse_complete()) + _s(o.parameter_description(23)) + _s(o.ready("I"))),
        "PARSE_COMPLETE|PARAMETER_DESCRIPTION 23|" + unexpected,
    )
    # PortalSuspended ends the rows
    assert_equal(
        _violation(_s(o.row_description("a:23")) + _s(o.data_row("1")) + _s(o.portal_suspended()) + _s(o.data_row("2"))),
        "ROW_DESCRIPTION a:23|DATA_ROW 1|PORTAL_SUSPENDED|" + unexpected,
    )
    # nothing in flight
    var idle = open_session(Startup("alice"))
    assert_equal(give(idle, _s(o.bind_complete())), unexpected)


def _refused(which: Int) raises -> String:
    """What a request that cannot be encoded raises, and what was queued."""
    var c = open_session(Startup("alice"))
    var got = String()
    try:
        if which == 0:
            c.execute("SELECT 1\x00", Params())
        elif which == 1:
            var many = Params()
            for i in range(MAX_PARAMS + 1):
                many.add(i)
            c.execute("SELECT 1", many)
        elif which == 2:
            c.prepare("s\x00", "SELECT 1", Params())
        elif which == 3:
            c.execute("SELECT 1", Params(), 2)
        elif which == 4:
            c.close_statement("a\x00b")
        elif which == 5:
            var types = Params()  # (Parse alone: no Bind to check the count)
            for _ in range(MAX_PARAMS + 1):
                types.add_null(23)
            c.prepare("s", "SELECT 1", types)
        else:
            var fresh = PgConnection(Startup("alice"), Span(nonce()))
            fresh.execute("SELECT 1", Params())  # (not open yet)
    except e:
        got = String(e.kind)
    return String(got, " queued=", sent(c), " idle=", c.is_idle())


def test_requests_are_whole_or_refused() raises:
    for which in range(7):
        assert_equal(_refused(which), "InvalidInput queued= idle=True", String(which))


def _render(ev: PgEvent) -> String:
    return String(ev)


def test_events_do_not_depend_on_the_split() raises:
    var o = oracle()
    var c = open_session(Startup("alice"))
    c.prepare("s1", "SELECT id, name FROM t WHERE id > $1", Params())
    c.execute_prepared("s1", _ints(0))
    c.execute("SELECT $1::int", _ints(5))
    _ = sent(c)
    var server = unhex(
        _s(o.parse_complete()) + _s(o.parameter_description(23)) + _s(o.row_description("id:23", "name:25"))
        + _s(o.ready("I")) + _s(o.bind_complete()) + _s(o.row_description("id:23", "name:25"))
        + _s(o.data_row("1", "a")) + _s(o.data_row("2", None)) + _s(o.command_complete("SELECT 2"))
        + _s(o.ready("I")) + _s(o.parse_complete()) + _s(o.error("22P02", "bad")) + _s(o.ready("I"))
    )
    var got = drive_chunked[_render](c, Span(server), max_pair_len=64)
    assert_equal(
        String(" | ").join(got),
        "PARSE_COMPLETE | PARAMETER_DESCRIPTION 23 | ROW_DESCRIPTION id:23 name:25 | READY I | BIND_COMPLETE"
        + " | ROW_DESCRIPTION id:23 name:25 | DATA_ROW 1 a | DATA_ROW 2 NULL | COMMAND_COMPLETE SELECT 2 | READY I"
        + " | PARSE_COMPLETE | ERROR ERROR 22P02: bad | READY I | error UnexpectedEof",
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
