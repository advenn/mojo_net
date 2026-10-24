"""Regression tests for the P7 review of `pg` (no server needed), each
checked to fail on the code before its fix:
- parse_timestamp_us overflowed past the end of the range, and could even
  return the infinity sentinels for a finite timestamp;
- the text parsers took impossible dates ("2024-02-31", year 0) and hours
  past 24:00:00, and refused offsets with 3-digit hours (POSIX zones);
- bytea in escape format (`bytea_output = escape`) was refused;
- "char" in binary form was written as text-like bytes (NUL, invalid
  UTF-8) instead of the way the server writes it;
- the codec took a second RowDescription before CommandComplete, which
  re-sliced the earlier rows;
- Config.parse differed from libpq: empty brackets were a host, an empty
  `host=` was not the default, a repeated `options=` was sent twice, and
  `gssencmode`, `client_encoding` and `ssl=true` were refused as unknown;
- a COPY FROM STDIN that failed before reading (into a view, say) drew a
  second ReadyForQuery for the extra Sync, which ended the next cycle; and
  a cycle took any number of CopyInResponses;
- a message that did not fit the transmit buffer left its type and length
  queued, so the next request went out as the rest of its body;
- before AuthenticationOk, messages up to 1 GiB were taken (libpq: 2000
  bytes for a request, 30000 for an error), and so were notices;
- ParameterStatus names had no bound;
- a failed `poll` left the reused event with the new body under the old
  kind;
- `is_open()` stayed true after the codec failed, and requests were queued;
- messages after a FATAL error were taken;
- EOF after Terminate was clean even with queries unanswered;
- a NUL in the password was refused only when the server asked for it;
- statement names too long for the server's Describe and Close were sent
  (it closes the connection without an error);
- NegotiateProtocolVersion was taken though nothing was asked of it;
- SCRAM user names were written as Latin-1, not UTF-8."""

from std.python import PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError
from pg import EventKind, Params, PgConnection, PgEvent, Startup
from pg.auth import ScramClient
from pg.config import Config
from pg.message import write_query, write_terminate
from pg.types import CHAR, Date, parse_bytea, parse_date, parse_timestamp_us, write_binary_as_text
from pg_util import give, hex, nonce, open_session, oracle, sent, unhex


def _s(x: PythonObject) raises -> String:
    return String(x)


def _ts_refused(text: StringSlice) -> Bool:
    try:
        _ = parse_timestamp_us(text.as_bytes())
    except e:
        return e.kind == ErrorKind.InvalidData
    return False


def _date_refused(text: StringSlice) -> Bool:
    try:
        _ = parse_date(text.as_bytes())
    except e:
        return e.kind == ErrorKind.InvalidData
    return False


def test_timestamps_past_the_range_are_refused_not_wrapped() raises:
    # PostgreSQL's last timestamps do not fit microseconds since 1970: they
    # were wrapped, and one landed on Int.MAX ('infinity')
    assert_true(_ts_refused("294276-12-31 23:59:59.999999+00"))
    assert_true(_ts_refused("294247-01-10 04:00:54.775807+00"))
    assert_true(_ts_refused("294247-01-10 04:00:54.775808+00"))
    assert_true(_ts_refused("294276-12-31 23:59:59.999999"))
    # ... and the end of what fits is still read
    assert_equal(parse_timestamp_us("294247-01-10 04:00:54.775806+00".as_bytes()), Int.MAX - 1)
    assert_equal(parse_timestamp_us("infinity".as_bytes()), Int.MAX)


def test_impossible_dates_and_hours_are_refused() raises:
    for bad in ["2024-02-30", "2024-02-31", "2023-02-29", "2024-04-31", "0000-01-01", "0000-01-01 BC"]:
        assert_true(_date_refused(bad), bad)
    assert_true(parse_date("2024-02-29".as_bytes()) == Date(2024, 2, 29, 0))
    assert_true(parse_date("0001-01-01 BC".as_bytes()) == Date(0, 1, 1, 0))
    for bad in ["2024-02-31 00:00:00", "2024-01-01 24:59:59", "2024-01-01 25:00:00", "2024-01-01 12:60:00",
                "2024-01-01 12:00:60"]:
        assert_true(_ts_refused(bad), bad)


def test_offsets_with_three_digit_hours() raises:
    # SET TimeZone = 'FOO100': "2023-12-27 20:00:00-100" is 2024-01-01 00:00 UTC
    var midnight = parse_timestamp_us("2024-01-01 00:00:00+00".as_bytes())
    assert_equal(parse_timestamp_us("2023-12-27 20:00:00-100".as_bytes()), midnight)
    assert_equal(parse_timestamp_us("2024-01-05 04:00:00+100".as_bytes()), midnight)
    assert_equal(parse_timestamp_us("2024-01-05 04:30:00+100:30".as_bytes()), midnight)


def test_bytea_in_escape_format() raises:
    # bytea_output = escape: "\\" for a backslash, three octal digits for
    # other unprintable bytes, the rest as is
    var b = parse_bytea("\\000\\377a\\\\b".as_bytes())
    assert_equal(len(b), 5)
    assert_equal(b[0], 0)
    assert_equal(b[1], 255)
    assert_equal(Int(b[2]), ord("a"))
    assert_equal(Int(b[3]), ord("\\"))
    assert_equal(Int(b[4]), ord("b"))
    assert_equal(len(parse_bytea("".as_bytes())), 0)
    for bad in ["\\9", "\\0", "\\00", "x\\12", "\\400", "a\\"]:
        var refused = False
        try:
            _ = parse_bytea(String(bad).as_bytes())
        except e:
            refused = True
        assert_true(refused, bad)
    var h = parse_bytea("\\x00ff".as_bytes())  # (hex still)
    assert_equal(len(h), 2)


def _char(byte: Int) raises -> String:
    var out = String()
    var v = List[UInt8]()
    v.append(UInt8(byte))
    write_binary_as_text(out, CHAR, Span(v))
    return out^


def test_char_is_written_as_charout_does() raises:
    # charout: NUL as "", bytes from 0x80 as a backslash and 3 octal digits
    assert_equal(_char(0), "")
    assert_equal(_char(ord("a")), "a")
    assert_equal(_char(0xC3), "\\303")
    assert_equal(_char(0x80), "\\200")


def test_a_second_row_description_needs_command_complete() raises:
    var o = oracle()
    var c = open_session(Startup("alice"))
    c.query("SELECT 1; SELECT 2")
    assert_equal(
        give(
            c,
            _s(o.row_description("a:23", "b:23")) + _s(o.data_row("1", "2")) + _s(o.row_description("x:23", "y:23", "z:23"))
        ),
        "ROW_DESCRIPTION a:23 b:23|DATA_ROW 1 2|error InvalidData: pg: unexpected message from the server",
    )


def _uri_refusal(uri: StringSlice) -> String:
    try:
        _ = Config.parse(uri)
    except e:
        return String(e.kind)
    return "accepted"


def test_uris_as_libpq_reads_them() raises:
    assert_equal(_uri_refusal("postgresql://u@[]/db"), "InvalidInput")
    assert_equal(Config.parse("postgresql://u@h/db?host=").host, "localhost")
    var twice = Config.parse("postgresql://u@h/db?options=-c%20a%3D1&options=-c%20b%3D2")
    var conn = PgConnection(twice.startup(), Span(nonce()))
    var sent_startup = String(oracle().startup(_sent(conn)))
    assert_true(sent_startup.find("options=-c b=2") >= 0, sent_startup)
    assert_true(sent_startup.find("options=-c a=1") < 0, sent_startup)
    for ok in ["gssencmode=disable", "gssencmode=prefer", "gssencmode=allow", "client_encoding=UTF8",
               "client_encoding=utf8", "client_encoding=UTF-8"]:
        assert_equal(_uri_refusal(String("postgresql://u@h/db?", ok)), "accepted", ok)
    for no in ["gssencmode=require", "client_encoding=LATIN1", "ssl=true"]:
        assert_equal(_uri_refusal(String("postgresql://u@h/db?", no)), "Unsupported", no)


def _sent(mut c: PgConnection) raises -> String:
    var out = ByteBuffer()
    _ = c.poll_transmit(out)
    return hex(out.readable_span())


comptime _UNEXPECTED = "error InvalidData: pg: unexpected message from the server"


def _copy_cycle(mut c: PgConnection) raises:
    """An extended COPY FROM STDIN, up to the server's CopyInResponse and
    the CopyFail and Sync it draws."""
    var o = oracle()
    c.execute("COPY v FROM STDIN", Params())
    _ = sent(c)
    assert_equal(
        give(c, _s(o.parse_complete()) + _s(o.bind_complete()) + _s(o.no_data()) + _s(o.copy_in())),
        "PARSE_COMPLETE|BIND_COMPLETE|NO_DATA",
    )
    assert_equal(_s(o.frontend_text(sent(c))), "f COPY FROM STDIN is not supported by this client | S")


def test_a_copy_that_fails_before_reading_draws_two_readys() raises:
    # COPY into a view (42809), COPY FREEZE (55000), a statement trigger: the
    # server raises right after CopyInResponse, its error recovery takes our
    # first Sync, and the extra one draws another ReadyForQuery
    var o = oracle()
    var c = open_session(Startup("alice"))
    _copy_cycle(c)
    assert_equal(
        give(c, _s(o.error("42809", "cannot copy to view")) + _s(o.ready("I")) + _s(o.ready("I"))),
        "ERROR ERROR 42809: cannot copy to view|READY I",
    )
    assert_true(c.is_idle())
    c.query("SELECT 1")
    assert_equal(
        give(c, _s(o.row_description("x:23")) + _s(o.data_row("1")) + _s(o.command_complete("SELECT 1")) + _s(o.ready("I"))),
        "ROW_DESCRIPTION x:23|DATA_ROW 1|COMMAND_COMPLETE SELECT 1|READY I",
    )
    # the stray READY may come once the next query is queued, after a
    # notification
    var d = open_session(Startup("alice"))
    _copy_cycle(d)
    assert_equal(give(d, _s(o.error("55000", "no FREEZE")) + _s(o.ready("I"))), "ERROR ERROR 55000: no FREEZE|READY I")
    d.query("SELECT 1")
    assert_equal(
        give(d, _s(o.notification(7, "c", "p")) + _s(o.ready("I")) + _s(o.command_complete("SELECT 0")) + _s(o.ready("I"))),
        "NOTIFICATION notification on c from 7: p|COMMAND_COMPLETE SELECT 0|READY I",
    )
    # a query pipelined behind the COPY ran before the extra Sync was read
    var e = open_session(Startup("alice"))
    e.execute("COPY v FROM STDIN", Params())
    e.query("SELECT 1")
    _ = sent(e)
    assert_equal(
        give(e, _s(o.parse_complete()) + _s(o.bind_complete()) + _s(o.no_data()) + _s(o.copy_in())),
        "PARSE_COMPLETE|BIND_COMPLETE|NO_DATA",
    )
    assert_equal(
        give(
            e,
            _s(o.error("42809", "cannot copy to view")) + _s(o.ready("I")) + _s(o.command_complete("SELECT 0"))
            + _s(o.ready("I")) + _s(o.ready("I")),
        ),
        "ERROR ERROR 42809: cannot copy to view|READY I|COMMAND_COMPLETE SELECT 0|READY I",
    )
    assert_true(e.is_idle())
    # the usual case (the server read our first Sync in copy-in mode): one
    # READY, and the next cycle's first message says no other is coming
    var f = open_session(Startup("alice"))
    _copy_cycle(f)
    assert_equal(
        give(f, _s(o.error("57014", "COPY from stdin failed")) + _s(o.ready("I"))),
        "ERROR ERROR 57014: COPY from stdin failed|READY I",
    )
    for _ in range(2):
        f.query("SELECT 1")
        assert_equal(give(f, _s(o.command_complete("SELECT 0")) + _s(o.ready("T"))), "COMMAND_COMPLETE SELECT 0|READY T")
    # and a READY no cycle asked for is still refused
    assert_equal(give(f, _s(o.ready("I"))), _UNEXPECTED)


def test_one_copy_in_response_per_cycle() raises:
    var o = oracle()
    var c = open_session(Startup("alice"))
    c.query("COPY t FROM STDIN")
    _ = sent(c)
    assert_equal(give(c, _s(o.copy_in()) + _s(o.copy_in())), _UNEXPECTED)


def test_a_message_that_does_not_fit_is_not_half_written() raises:
    # the type byte and length stayed queued when the body did not fit, and
    # the next request went out as the rest of that body
    var out = ByteBuffer(max_size=16)
    var kind = String()
    try:
        write_query(out, "SELECT 'more than sixteen bytes'")
    except e:
        kind = String(e.kind)
    assert_equal(kind, "OutOfMemory")
    assert_equal(out.readable(), 0)
    var full = ByteBuffer(max_size=8)
    full.write_bytes("1234".as_bytes())
    kind = String()
    try:
        write_terminate(full)
    except e:
        kind = String(e.kind)
    assert_equal(kind, "OutOfMemory")
    assert_equal(full.readable(), 4)


def test_statement_names_the_server_takes() raises:
    # the server reads Describe and Close up to 10000 bytes, and closes the
    # connection without an error past that
    var c = open_session(Startup("alice"))
    var longest = String()
    for _ in range(9994):
        longest += "n"
    var too_long = longest + "n"
    var refused = 0
    try:
        c.prepare(too_long, "SELECT 1", Params())
    except e:
        refused += Int(e.kind == ErrorKind.InvalidInput)
    try:
        c.close_statement(too_long)
    except e:
        refused += Int(e.kind == ErrorKind.InvalidInput)
    assert_equal(refused, 2)
    assert_equal(sent(c), "")
    assert_true(c.is_idle())
    c.prepare(longest, "SELECT 1", Params())
    c.close_statement(longest)
    assert_equal(c.pending_queries(), 2)


def _before_auth(server: String) raises -> String:
    var c = PgConnection(Startup("alice", password="pw"), Span(nonce()))
    _ = sent(c)
    return give(c, server)


def test_messages_before_authentication_ok_are_small() raises:
    # libpq's bounds: 2000 bytes for an authentication request (a SCRAM
    # message of 1 GiB cost tens of GiB to parse), 30000 for an error; and
    # the server sends no notices then
    var o = oracle()
    var too_long = "error InvalidData: pg: message length out of bounds"
    assert_equal(_before_auth(String(hex("R"), "000007d1")), too_long)  # (the header is enough)
    assert_equal(_before_auth(String(hex("E"), "00007531")), too_long)
    assert_equal(_before_auth(_s(o.auth_sasl("SCRAM-SHA-256")) + String(hex("R"), "000007d1")), too_long)
    var filler = String()
    for _ in range(1976):
        filler += "x"
    assert_equal(_before_auth(_s(o.auth_sasl("SCRAM-SHA-256", filler))), "")  # (2000 bytes: taken)
    assert_equal(_before_auth(_s(o.auth_sasl("SCRAM-SHA-256", filler + "x"))), too_long)
    var message = String()
    for _ in range(29972):
        message += "m"
    assert_true(_before_auth(_s(o.error("28P01", message, "FATAL"))).startswith("ERROR FATAL 28P01"))
    assert_equal(_before_auth(_s(o.notice("hello"))), _UNEXPECTED)
    # a smaller max_message bounds them too (a longer one would never fit)
    var small = PgConnection(Startup("alice", password="pw", max_message=1024), Span(nonce()))
    _ = sent(small)
    assert_equal(give(small, String(hex("R"), "000005dc")), too_long)
    # once authenticated, the usual bounds
    var c = PgConnection(Startup("alice"), Span(nonce()))
    _ = sent(c)
    var long_notice = message + message
    assert_equal(
        give(c, _s(o.auth_ok()) + _s(o.notice(long_notice)) + _s(o.session())),
        String("NOTICE NOTICE 00000: ", long_notice, "|READY I"),
    )


def test_reported_parameters_are_bounded() raises:
    # a server reports some 20 parameters; distinct names grew the session's
    # state without end, each one looked up in a list
    var o = oracle()
    var c = open_session(Startup("alice"))
    var many = String()
    for i in range(300):
        many += _s(o.parameter(String("p", i), "v"))
    assert_equal(give(c, many), "error InvalidData: pg: too many parameters reported")
    # one name reported again and again is one
    var d = open_session(Startup("alice"))
    var again = String()
    for i in range(300):
        again += _s(o.parameter("TimeZone", String("UTC", i)))
    assert_equal(give(d, again), "")
    assert_equal(d.parameter("TimeZone").value(), "UTC299")


def test_a_failed_poll_leaves_no_stale_event() raises:
    var o = oracle()
    var c = open_session(Startup("alice"))
    c.query("SELECT 1")
    var ev = PgEvent()
    var head = unhex(_s(o.row_description("a:23")))
    c.feed(Span(head))
    assert_true(c.poll(ev))
    assert_true(ev.kind == EventKind.ROW_DESCRIPTION)
    var row = unhex(_s(o.data_row("1", "2")))  # (two values for one column)
    c.feed(Span(row))
    var raised = False
    try:
        _ = c.poll(ev)
    except e:
        raised = e.kind == ErrorKind.InvalidData
    assert_true(raised)
    # (the DataRow's body, read as a RowDescription, ran past its end)
    assert_false(ev.kind == EventKind.ROW_DESCRIPTION)
    assert_equal(len(ev.data), 0)
    _ = ev^


def test_a_failed_codec_takes_no_requests() raises:
    var c = open_session(Startup("alice"))
    assert_equal(give(c, String(hex("Y"), "00000004")), _UNEXPECTED)
    assert_false(c.is_open())
    assert_false(c.is_idle())
    var kind = String()
    try:
        c.query("SELECT 1")
    except e:
        kind = String(e.kind)
    assert_equal(kind, "InvalidData")  # (what ended it)
    assert_equal(sent(c), "")
    var d = open_session(Startup("alice"))
    d.feed_eof()
    assert_false(d.is_open())


def test_nothing_comes_after_the_end() raises:
    var o = oracle()
    var fatal = _s(o.error("57P01", "terminating connection due to administrator command", "FATAL"))
    var said = "ERROR FATAL 57P01: terminating connection due to administrator command|"
    var c = open_session(Startup("alice"))
    assert_equal(give(c, fatal + _s(o.notice("late"))), String(said, _UNEXPECTED))
    var d = open_session(Startup("alice"))
    assert_equal(give(d, fatal + fatal), String(said, _UNEXPECTED))


def test_eof_after_terminate_needs_the_answers() raises:
    var c = open_session(Startup("alice"))
    c.query("COMMIT")
    c.terminate()
    _ = sent(c)
    assert_equal(give(c, "", eof=True), "error UnexpectedEof: pg: the server closed the connection")


def _refused_startup(startup: Startup) -> Bool:
    try:
        _ = PgConnection(startup, Span(nonce()))
    except e:
        return e.kind == ErrorKind.InvalidInput
    return False


def test_startup_settings_refused_at_once() raises:
    # a NUL in the password was refused only once the server asked for it
    # (or hashed in, and the server said 28P01); protocol options are not
    # spoken here
    assert_true(_refused_startup(Startup("alice", password="pass\x00word")))
    var options = Startup("alice")
    options.set("_pq_.compression", "on")
    assert_true(_refused_startup(options))


def test_negotiate_protocol_version_is_refused() raises:
    # this client asks for 3.0 and no options: there is nothing to negotiate
    var o = oracle()
    var refused = "error InvalidData: pg: NegotiateProtocolVersion, though nothing was negotiated"
    assert_equal(_before_auth(_s(o.negotiate(196608))), refused)
    assert_equal(_before_auth(_s(o.negotiate(196615))), refused)  # (3.7: higher than asked)
    assert_equal(_before_auth(_s(o.negotiate(196608, "_pq_.x"))), refused)
    assert_equal(_before_auth(String(hex("v"), "00000008", "00030000")), refused)  # (malformed)


def test_a_client_encoding_other_than_utf8_ends_the_session() raises:
    # the codec's strings are UTF-8: a server converting to LATIN1 would
    # garble every text value both ways
    var o = oracle()
    var c = open_session(Startup("alice"))
    c.query("SET client_encoding = 'LATIN1'")
    assert_equal(
        give(c, _s(o.parameter("client_encoding", "LATIN1")) + _s(o.command_complete("SET")) + _s(o.ready("I"))),
        "error Unsupported: pg: the server switched client_encoding from UTF8",
    )
    var d = open_session(Startup("alice"))
    d.query("SET client_encoding = 'UTF8'")
    assert_equal(
        give(d, _s(o.parameter("client_encoding", "UTF8")) + _s(o.command_complete("SET")) + _s(o.ready("I"))),
        "COMMAND_COMPLETE SET|READY I",
    )


def test_scram_user_names_are_utf8() raises:
    var s = ScramClient("pw", "nonce", user="é,=")
    assert_equal(s.client_first(), "n,,n=é=2C=3D,r=nonce")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
