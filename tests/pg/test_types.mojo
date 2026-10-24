"""`pg.types`: the binary forms read, the text written for them, and the
text forms parsed. Dates and timestamps are checked against Python's
datetime over its whole range (years 1 to 9999), with BC years and the
infinities by hand; the real server checks the same in
`test_client.mojo`."""

from std.python import Python, PythonObject
from std.random import random_ui64, seed
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError
from pg.types import (
    BOOL,
    BYTEA,
    DATE,
    INT2,
    INT4,
    INT8,
    OID,
    TEXT_TYPE,
    TIME,
    TIMESTAMP,
    UUID,
    Date,
    binary_date,
    binary_int,
    binary_timestamp_us,
    parse_bytea_hex,
    parse_date,
    parse_timestamp_us,
    wants_binary,
    write_binary_as_text,
    write_timestamp,
)
from pg_util import unhex


def _rand(n: Int) -> Int:
    return Int(random_ui64(0, UInt64(n - 1)))


def _text(oid: UInt32, hex: StringSlice) raises -> String:
    var out = String()
    write_binary_as_text(out, oid, Span(unhex(hex)))
    return out^


def test_binary_integers_and_their_text() raises:
    assert_equal(binary_int(INT2, Span(unhex("8000"))), -32768)
    assert_equal(binary_int(INT2, Span(unhex("7fff"))), 32767)
    assert_equal(binary_int(INT4, Span(unhex("80000000"))), -2147483648)
    assert_equal(binary_int(INT4, Span(unhex("ffffffff"))), -1)
    assert_equal(binary_int(INT8, Span(unhex("8000000000000000"))), Int.MIN)
    assert_equal(binary_int(INT8, Span(unhex("7fffffffffffffff"))), Int.MAX)
    assert_equal(binary_int(INT8, Span(unhex("fffffffffffffffe"))), -2)
    assert_equal(binary_int(OID, Span(unhex("ffffffff"))), 4294967295)  # (unsigned)
    assert_equal(_text(INT8, "fffffffffffffffe"), "-2")
    assert_equal(_text(BOOL, "01"), "t")
    assert_equal(_text(BOOL, "00"), "f")
    assert_equal(_text(BYTEA, "00ff10"), "\\x00ff10")
    assert_equal(_text(BYTEA, ""), "\\x")
    assert_equal(_text(UUID, "a0eebc999c0b4ef8bb6d6bb9bd380a11"), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
    assert_equal(_text(TEXT_TYPE, "68c3a96c6c6f"), "héllo")
    # wrong lengths are refused
    var refused = 0
    var oids = [INT4, INT8, BOOL, UUID, DATE, TIMESTAMP]
    var values = ["0102", "01", "", "00", "000000", "00"]
    for i in range(len(oids)):
        try:
            _ = _text(oids[i], values[i])
        except e:
            refused += 1
    assert_equal(refused, 6)
    assert_true(wants_binary(INT4) and wants_binary(UUID) and wants_binary(TIMESTAMP))
    assert_false(wants_binary(1184) or wants_binary(701) or wants_binary(1700))  # timestamptz, float8, numeric


def test_dates_against_python() raises:
    seed(1082)
    var datetime = Python.import_module("datetime")
    var epoch = datetime.date(1970, 1, 1).toordinal()
    var lo = Int(py=datetime.date(1, 1, 1).toordinal()) - Int(py=epoch)
    var hi = Int(py=datetime.date(9999, 12, 31).toordinal()) - Int(py=epoch)
    var days: List[Int] = [lo, hi, 0, 10957, 11016, 11017, -25508, -25509, -1, 1]  # (2000-02-29/03-01, 1900)
    for _ in range(3000):
        days.append(lo + _rand(hi - lo + 1))
    for d in days:
        var py = datetime.date.fromordinal(Int(py=epoch) + d)
        var mine = Date.from_days(d)
        assert_equal(String(mine), String(py=py.isoformat()), String(d))
        assert_equal(mine.days_since_1970(), d)
        # the binary form counts from 2000-01-01
        var b = List[UInt8]()
        var since_2000 = d - 10957
        for k in range(4):
            b.append(UInt8((since_2000 >> (24 - 8 * k)) & 0xFF))
        assert_true(binary_date(Span(b)) == mine)
        assert_true(parse_date(String(mine).as_bytes()) == mine)
    # BC, and the infinities
    assert_equal(String(Date.from_days(lo - 1)), "0001-12-31 BC")  # (the day before 0001-01-01)
    assert_equal(String(Date(-4712, 1, 1, 0)), "4713-01-01 BC")
    assert_equal(String(binary_date(Span(unhex("7fffffff")))), "infinity")
    assert_equal(String(binary_date(Span(unhex("80000000")))), "-infinity")
    assert_true(parse_date("0044-03-15 BC".as_bytes()) == Date(-43, 3, 15, 0))
    assert_true(parse_date("infinity".as_bytes()) == Date(0, 0, 0, 1))
    for bad in ["024-01-01", "2024-1-01", "2024-01-1", "2024-00-10", "2024-01-32", "2024-01-01 AD", "now"]:
        var refused = False
        try:
            _ = parse_date(String(bad).as_bytes())
        except e:
            refused = True
        assert_true(refused, bad)


def test_timestamps_against_python() raises:
    seed(1114)
    var datetime = Python.import_module("datetime")
    var lo = -62135596800  # 0001-01-01 00:00:00, in seconds since 1970
    var hi = 253402300799  # 9999-12-31 23:59:59
    var builtins = Python.import_module("builtins")
    for i in range(3000):
        var secs = lo + _rand(hi - lo + 1)
        var frac = 0 if i % 3 == 0 else _rand(1000000)
        var us = secs * 1000000 + frac
        var py = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=builtins.int(us))
        var iso = String(py=py.isoformat(" "))
        if iso.find(".") >= 0:  # PostgreSQL drops the fraction's trailing zeros
            while iso.endswith("0"):
                var shorter = String(iso[byte = 0 : iso.byte_length() - 1])
                iso = shorter^
        var mine = String()
        write_timestamp(mine, us)
        assert_equal(mine, iso, String(us))
        assert_equal(parse_timestamp_us(mine.as_bytes()), us)
        var b = List[UInt8]()
        var since_2000 = us - 10957 * 86400 * 1000000
        for k in range(8):
            b.append(UInt8((since_2000 >> (56 - 8 * k)) & 0xFF))
        assert_equal(binary_timestamp_us(Span(b)), us)
    var out = String()
    write_timestamp(out, -62135596800 * 1000000 - 1)  # one microsecond before 0001-01-01
    assert_equal(out, "0001-12-31 23:59:59.999999 BC")
    out = String()
    write_timestamp(out, Int.MAX)
    assert_equal(out, "infinity")
    # PostgreSQL's last years are written, but do not fit microseconds since 1970
    assert_equal(_text(TIMESTAMP, "7ffffffffffffffe"), "294277-01-09 04:00:54.775806")
    var too_late = False
    var last = unhex("7ffffffffffffffe")
    try:
        _ = binary_timestamp_us(Span(last))
    except e:
        too_late = e.kind == ErrorKind.InvalidData
    assert_true(too_late)
    assert_equal(_text(TIMESTAMP, "8000000000000000"), "-infinity")
    assert_equal(_text(TIME, "0000000000000000"), "00:00:00")
    assert_equal(_text(TIME, "000000141dd75fff"), "23:59:59.999999")
    assert_equal(_text(TIME, "0000000a0ef35120"), "12:00:00.5")


def test_timestamptz_text_and_offsets() raises:
    # timestamptz comes in text form, with the session's offset
    var base = parse_timestamp_us("2024-02-29 13:45:00".as_bytes())
    assert_equal(parse_timestamp_us("2024-02-29 13:45:00+00".as_bytes()), base)
    assert_equal(parse_timestamp_us("2024-02-29 19:15:00+05:30".as_bytes()), base)
    assert_equal(parse_timestamp_us("2024-02-29 10:45:00-03".as_bytes()), base)
    assert_equal(parse_timestamp_us("2024-02-29 13:45:30+00:00:30".as_bytes()), base)
    assert_equal(parse_timestamp_us("2024-02-29 13:45:00.25+00".as_bytes()), base + 250000)
    assert_equal(parse_timestamp_us("infinity".as_bytes()), Int.MAX)
    assert_equal(parse_timestamp_us("-infinity".as_bytes()), Int.MIN)
    var bad = [
        "2024-02-29",
        "2024-02-29 13:45",
        "2024-2-29 13:45:00",
        "2024-02-29T13:45:00",
        "2024-13-01 00:00:00",
        "2024-02-29 13:45:00.",
        "2024-02-29 13:45:00+5",
        "2024-02-29 13:45:00 AD",
        "Thu Feb 29 13:45:00 2024",
        "",
    ]
    for i in range(len(bad)):
        var refused = False
        try:
            _ = parse_timestamp_us(bad[i].as_bytes())
        except e:
            refused = e.kind == ErrorKind.InvalidData
        assert_true(refused, bad[i])


def test_bytea_text_form() raises:
    var b = parse_bytea_hex("\\x00ff10AB".as_bytes())
    assert_equal(len(b), 4)
    assert_equal(b[1], 255)
    assert_equal(b[3], 0xAB)
    assert_equal(len(parse_bytea_hex("\\x".as_bytes())), 0)
    for bad in ["00ff", "\\x0", "\\xzz", "\\001"]:
        var refused = False
        try:
            _ = parse_bytea_hex(String(bad).as_bytes())
        except e:
            refused = True
        assert_true(refused, bad)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
