"""`pg.message`: the frontend builders, read back by the Python oracle's
parser (`pg_oracle.py`); and the checks of backend bodies on the oracle's
messages, with every truncation, a trailing byte, and each field broken."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError
from pg.message import (
    BackendKey,
    FIELD_CONSTRAINT,
    FIELD_DETAIL,
    FIELD_TABLE,
    MAX_STARTUP_LENGTH,
    ServerMessage,
    check_fields,
    check_notification,
    check_row_description,
    check_string,
    notification,
    read_data_row,
    read_parameter_status,
    row_description,
    rows_affected,
    write_cancel_request,
    write_copy_fail,
    write_password,
    write_query,
    write_sasl_initial_response,
    write_sasl_response,
    write_startup,
    write_terminate,
)
from pg_util import body_of, hex, oracle, unhex


def test_startup_message() raises:
    var out = ByteBuffer()
    var params: List[String] = ["user", "alice", "database", "shop", "options", "-c search_path=x"]
    write_startup(out, params)
    assert_equal(
        String(oracle().startup(hex(out.readable_span()))),
        "196608|user=alice|database=shop|options=-c search_path=x#",
    )


def _refused(kind: ErrorKind, mut out: ByteBuffer, which: Int) raises -> Bool:
    """Whether builder case `which` raises `kind` and writes nothing."""
    try:
        if which == 0:
            write_startup(out, ["user", "a\x00b"])
        elif which == 1:
            write_startup(out, ["", "x"])
        elif which == 2:
            write_startup(out, ["user"])
        elif which == 3:
            write_startup(out, ["user", String("x") * MAX_STARTUP_LENGTH])
        elif which == 4:
            write_query(out, "SELECT 1\x00; DROP TABLE t")
        elif which == 5:
            write_password(out, "pass\x00word")
        elif which == 6:
            write_sasl_initial_response(out, "SCRAM\x00", "x".as_bytes())
        else:
            write_copy_fail(out, "no\x00")
    except e:
        return e.kind == kind and out.readable() == 0
    return False


def test_builders_refuse_nul_and_bad_parameters() raises:
    for which in range(8):
        var out = ByteBuffer()
        assert_true(_refused(ErrorKind.InvalidInput, out, which), String(which))


def test_frontend_messages() raises:
    var out = ByteBuffer()
    write_query(out, "SELECT 1")
    write_password(out, "secret")
    write_sasl_initial_response(out, "SCRAM-SHA-256", "n,,n=,r=abc".as_bytes())
    write_sasl_response(out, "c=biws".as_bytes())
    write_copy_fail(out, "no")
    write_terminate(out)
    assert_equal(
        String(oracle().frontend(hex(out.readable_span()))),
        String(
            "Q:", hex("SELECT 1"), "00|p:", hex("secret"), "00|p:", hex("SCRAM-SHA-256"), "000000000b",
            hex("n,,n=,r=abc"), "|p:", hex("c=biws"), "|f:", hex("no"), "00|X:",
        ),
    )
    var cancel = ByteBuffer()
    write_cancel_request(cancel, BackendKey(4242, 0xDEADBEEF))
    assert_equal(String(oracle().cancel_request(hex(cancel.readable_span()))), "16|80877102|4242|3735928559")


def _fails(body: Span[UInt8, _], which: Int) -> Bool:
    """Whether check `which` refuses `body` with `InvalidData`."""
    var at = List[Int]()
    var name = String()
    var value = String()
    try:
        if which == 0:
            check_fields(body)
        elif which == 1:
            _ = check_row_description(body)
        elif which == 2:
            read_data_row(body, 4, at)
        elif which == 3:
            read_parameter_status(body, name, value)
        elif which == 4:
            check_notification(body)
        else:
            check_string(body, "tag")
    except e:
        return e.kind == ErrorKind.InvalidData
    return False


def _every_cut_fails(whole: List[UInt8], which: Int) raises:
    """`whole` passes check `which`; every proper prefix of it, and it with
    a byte appended, fail."""
    assert_false(_fails(Span(whole), which), String("check ", which, " refused the whole body"))
    for k in range(len(whole)):
        assert_true(_fails(Span(whole)[:k], which), String("check ", which, " took a prefix of ", k))
    var longer = whole.copy()
    longer.append(0)
    assert_true(_fails(Span(longer), which), String("check ", which, " took a trailing byte"))


def test_bodies_refuse_every_truncation() raises:
    var o = oracle()
    _every_cut_fails(body_of(String(o.error("23505", "duplicate key", D="Key (id)=(1) exists."))), 0)
    _every_cut_fails(body_of(String(o.row_description("id:23", "name:25"))), 1)
    _every_cut_fails(body_of(String(o.data_row("1", None, "", "abc"))), 2)
    _every_cut_fails(body_of(String(o.parameter("TimeZone", "UTC"))), 3)
    _every_cut_fails(body_of(String(o.notification(77, "jobs", "42"))), 4)
    _every_cut_fails(body_of(String(o.command_complete("SELECT 1"))), 5)


def test_bodies_refuse_broken_fields() raises:
    var o = oracle()
    # a format code other than 0 and 1; a negative column count
    var rd = body_of(String(o.row_description("id:23")))
    rd[len(rd) - 1] = 2
    assert_true(_fails(Span(rd), 1))
    var neg: List[UInt8] = [0xFF, 0xFF]
    assert_true(_fails(Span(neg), 1))
    # DataRow: a column count that is not the RowDescription's, a length
    # under -1, a length past the end
    var dr = body_of(String(o.data_row("1", "2", "3")))
    assert_true(_fails(Span(dr), 2))  # 3 values, 4 expected
    var bad = body_of(String(o.data_row("1", "2", "3", "4")))
    bad[2] = 0xFF
    bad[3] = 0xFF
    bad[4] = 0xFF
    bad[5] = 0xFE  # -2
    assert_true(_fails(Span(bad), 2))
    bad = body_of(String(o.data_row("1", "2", "3", "4")))
    bad[5] = 9
    assert_true(_fails(Span(bad), 2))
    var minus_two: List[UInt8] = [0, 4]  # four values of length -2, which no bytes follow
    for _ in range(4):
        minus_two.extend([0xFF, 0xFF, 0xFF, 0xFE])
    assert_true(_fails(Span(minus_two), 2))
    # ParameterStatus with an empty name; a tag with a NUL inside
    assert_true(_fails(Span(body_of(String(o.parameter("", "x")))), 3))
    var tag: List[UInt8] = [65, 0, 66, 0]
    assert_true(_fails(Span(tag), 5))


def test_reading_checked_bodies() raises:
    var o = oracle()
    var cols = row_description(Span(body_of(String(o.row_description("id:23", "name:25")))))
    assert_equal(len(cols), 2)
    assert_equal(cols[0].name, "id")
    assert_equal(cols[0].type_oid, 23)
    assert_equal(cols[1].name, "name")
    assert_equal(cols[1].type_oid, 25)
    assert_equal(cols[1].table_oid, 16384)
    assert_equal(cols[1].column, 1)
    assert_equal(cols[1].type_size, -1)
    assert_equal(cols[1].type_modifier, -1)
    assert_equal(cols[1].format, 0)
    var at = List[Int]()
    var row = body_of(String(o.data_row("1", None, "", "abc")))
    read_data_row(Span(row), 4, at)
    assert_equal(len(at), 8)
    assert_equal(at[1], 1)  # "1"
    assert_equal(at[3], -1)  # NULL
    assert_equal(at[5], 0)  # ""
    assert_equal(at[7], 3)
    assert_equal(String(from_utf8_lossy=Span(row)[at[6] : at[6] + 3]), "abc")
    var name = String()
    var value = String()
    read_parameter_status(Span(body_of(String(o.parameter("TimeZone", "Europe/Berlin")))), name, value)
    assert_equal(name, "TimeZone")
    assert_equal(value, "Europe/Berlin")
    var n = notification(Span(body_of(String(o.notification(77, "jobs", "")))))
    assert_equal(n.pid, 77)
    assert_equal(n.channel, "jobs")
    assert_equal(n.payload, "")


def test_rows_affected() raises:
    var tags = ["INSERT 0 5", "UPDATE 3", "DELETE 0", "SELECT 12", "MERGE 2", "COPY 7", "FETCH 1", "MOVE 4"]
    var counts = [5, 3, 0, 12, 2, 7, 1, 4]
    for i in range(len(tags)):
        assert_equal(rows_affected(tags[i]).value(), counts[i], tags[i])
    for tag in ["CREATE TABLE", "BEGIN", "SELECT", "INSERT 0 x", "UPDATE ", "SELECT 99999999999999999999", "LISTEN 5"]:
        assert_false(Bool(rows_affected(tag)), tag)


def test_server_message() raises:
    var o = oracle()
    var m = ServerMessage(
        body_of(String(o.error("23505", "duplicate key", D="Key (id)=(1) exists.", n="t_pkey", t="t")))
    )
    assert_equal(m.severity(), "ERROR")
    assert_equal(m.code(), "23505")
    assert_equal(m.message(), "duplicate key")
    assert_equal(m.detail().value(), "Key (id)=(1) exists.")
    assert_equal(m.field(FIELD_DETAIL).value(), "Key (id)=(1) exists.")
    assert_equal(m.field(FIELD_CONSTRAINT).value(), "t_pkey")
    assert_equal(m.field(FIELD_TABLE).value(), "t")
    assert_false(Bool(m.hint()))
    assert_false(Bool(m.position()))
    assert_false(m.is_fatal())
    assert_equal(String(m), "ERROR 23505: duplicate key")
    assert_true(ServerMessage(body_of(String(o.error("57P01", "bye", "FATAL")))).is_fatal())
    assert_true(ServerMessage(body_of(String(o.error("XX000", "oh", "PANIC")))).is_fatal())
    # severity: the never-localized V wins over a localized S
    var localized: List[UInt8] = [83]
    localized.extend("FEHLER".as_bytes())
    localized.extend([0, 86])
    localized.extend("ERROR".as_bytes())
    localized.extend([0, 0])
    check_fields(Span(localized))
    assert_equal(ServerMessage(localized^).severity(), "ERROR")
    var only_s: List[UInt8] = [83]
    only_s.extend("FATAL".as_bytes())
    only_s.extend([0, 0])
    assert_true(ServerMessage(only_s^).is_fatal())


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
