"""`net.reader.BufReader`: framing (`read_until`, `read_line`, `fill_until`,
`read_exact`, `fill`), limits, EOF, the all-or-nothing rule under expiring
deadlines, chunking invariance over every way of cutting the input into
reads, the read-size and bypass rules, and real streams (Unix pair with a
deadline that expires mid-frame, pipelined requests over TCP loopback,
`into_parts`)."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError
from linux.time import Deadline, Duration
from bytes.buffer import DEFAULT_MAX_SIZE
from net.addr import SocketAddr
from net.reader import DEFAULT_CAPACITY, BufReader, Read
from net.socket import Shutdown
from net.tcp import TcpListener, TcpStream
from net.unix import UnixStream
from reader_script import (
    INPUT,
    Rng,
    Script,
    bytes_of,
    expected_transcript,
    first_difference,
    run_transcript,
)


def _text(b: List[UInt8]) -> String:
    return String(from_utf8_lossy=Span(b))


def _buffered(r: BufReader[Script]) -> String:
    return String(from_utf8_lossy=r.buffer().readable_span())


def _guard() -> Deadline:
    return Deadline.after(Duration.from_secs(10))


def _sizes(*values: Int) -> List[Int]:
    var out = List[Int]()
    for v in values:
        out.append(v)
    return out^


def _check_transcript(var src: Script, capacity: Int, what: String) raises:
    var r = BufReader(src^, capacity=capacity)
    var got = run_transcript(r)
    var diff = first_difference(got, expected_transcript())
    if diff:
        raise Error(what, " capacity=", capacity, ": ", diff)


# ---- framing -----------------------------------------------------------------


def test_transcript_in_one_read() raises:
    _check_transcript(Script(INPUT), DEFAULT_CAPACITY, "one read")


def test_read_until_keeps_the_delimiter_and_the_rest() raises:
    var r = BufReader(Script("ab;cd;ef"))
    var a = r.read_until(UInt8(ord(";")), 16)
    assert_equal(_text(a.value()), "ab;")
    assert_equal(_buffered(r), "cd;ef")
    var b = r.read_until(String(";e").as_bytes(), 16)
    assert_equal(_text(b.value()), "cd;e")
    assert_equal(_buffered(r), "f")


def test_read_line_strips_lf_and_crlf_only() raises:
    var r = BufReader(Script("a\r\nb\nc\rd\n\r\n\n\r\r\n"))
    var want: List[String] = ["a", "b", "c\rd", "", "", "\r"]
    for w in want:
        var line = r.read_line(8)
        assert_equal(_text(line.value()), w)
    assert_false(r.read_line(8))


def test_clean_eof_is_none_or_zero() raises:
    var r = BufReader(Script(""))
    assert_false(r.read_line(8))
    assert_false(r.read_until(String("\r\n").as_bytes(), 8))
    assert_equal(r.fill_until(UInt8(10), 8), 0)
    assert_equal(r.fill(4), 0)
    var buf = List[UInt8](length=4, fill=0)
    assert_equal(r.read(Span(buf)), 0)
    r.read_exact(Span(buf)[0:0])  # empty: no-op


def test_eof_inside_a_frame_keeps_every_byte() raises:
    var r = BufReader(Script("abc"))
    var kinds = List[ErrorKind]()
    var ops = List[String]()
    try:
        _ = r.read_line(8)
    except e:
        kinds.append(e.kind)
        ops.append(String(e.op))
    try:
        _ = r.read_until(String("\r\n\r\n").as_bytes(), 8)
    except e:
        kinds.append(e.kind)
        ops.append(String(e.op))
    var four = List[UInt8](length=4, fill=0)
    try:
        r.read_exact(Span(four))
    except e:
        kinds.append(e.kind)
        ops.append(String(e.op))
    assert_equal(len(kinds), 3)
    for k in kinds:
        assert_equal(k, ErrorKind.UnexpectedEof)
    assert_equal(ops[0], "BufReader.read_line")
    assert_equal(ops[1], "BufReader.read_until")
    assert_equal(ops[2], "BufReader.read_exact")
    assert_equal(_buffered(r), "abc")
    assert_equal(r.fill(10), 3)  # short only at EOF, no raise
    var three = List[UInt8](length=3, fill=0)
    r.read_exact(Span(three))
    assert_equal(_text(three), "abc")


def test_fill_until_leaves_the_frame_for_parsing_in_place() raises:
    var r = BufReader(Script("key=value\nnext\n"))
    var n = r.fill_until(UInt8(10), 32)
    assert_equal(n, 10)
    var line = r.buffer().readable_span()[: n - 1]
    assert_equal(String(from_utf8_lossy=line), "key=value")
    r.consume(n)
    assert_equal(_buffered(r), "next\n")


def test_bufreader_is_itself_a_read() raises:
    var inner = BufReader(Script("a\nbc\n", _sizes(1), List[Int]()), capacity=1)
    var r = BufReader(inner^, capacity=2)
    assert_equal(_text(r.read_line(8).value()), "a")
    assert_equal(_text(r.read_line(8).value()), "bc")
    assert_false(r.read_line(8))


# ---- limits ------------------------------------------------------------------


def test_max_bytes_counts_the_delimiter() raises:
    var r = BufReader(Script("abcd\nab\r\n\r\n"))
    var kinds = List[ErrorKind]()
    try:
        _ = r.read_line(4)  # 5 bytes with the "\n"
    except e:
        kinds.append(e.kind)
    assert_equal(_text(r.read_line(5).value()), "abcd")
    try:
        _ = r.read_until(String("\r\n\r\n").as_bytes(), 5)
    except e:
        kinds.append(e.kind)
    assert_equal(
        _text(r.read_until(String("\r\n\r\n").as_bytes(), 6).value()),
        "ab\r\n\r\n",
    )
    assert_equal(len(kinds), 2)
    assert_equal(kinds[0], ErrorKind.InvalidData)
    assert_equal(kinds[1], ErrorKind.InvalidData)


def test_over_long_frame_fails_before_reading_the_rest() raises:
    var data = List[UInt8]()
    for _ in range(1000):
        data.append(UInt8(ord("x")))
    data.append(10)
    var r = BufReader(Script(data^, _sizes(10), List[Int]()), capacity=10)
    var kind = ErrorKind.Other
    try:
        _ = r.read_line(50)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidData)
    # 50 bytes prove the line is too long: five reads of 10, no more.
    assert_equal(r.stream().calls, 5)
    assert_equal(len(r.buffer()), 50)


def test_requests_that_cannot_fit_fail_before_any_read() raises:
    var r = BufReader(
        Script("0123456789abcdefghijklmnopqrstuv"), capacity=4, max_size=16
    )
    var kinds = List[ErrorKind]()
    try:
        _ = r.fill(17)
    except e:
        kinds.append(e.kind)
    var big = List[UInt8](length=17, fill=0)
    try:
        r.read_exact(Span(big))
    except e:
        kinds.append(e.kind)
    assert_equal(r.stream().calls, 0)
    # A frame that outgrows the buffer: OutOfMemory once it is full.
    try:
        _ = r.read_line(1000)
    except e:
        kinds.append(e.kind)
    assert_equal(len(kinds), 3)
    for k in kinds:
        assert_equal(k, ErrorKind.OutOfMemory)
    assert_equal(len(r.buffer()), 16)
    assert_equal(_buffered(r), "0123456789abcdef")


def test_caller_bugs_are_invalid_input() raises:
    var r = BufReader(Script("abc"))
    var kinds = List[ErrorKind]()
    try:
        _ = r.fill(-1)
    except e:
        kinds.append(e.kind)
    try:
        _ = r.fill_until(UInt8(10), 0)
    except e:
        kinds.append(e.kind)
    try:
        _ = r.fill_until(String("").as_bytes(), 8)
    except e:
        kinds.append(e.kind)
    try:
        _ = r.read_until(
            String("\r\n").as_bytes(), 1
        )  # shorter than the delimiter
    except e:
        kinds.append(e.kind)
    try:
        _ = r.read_line(0)
    except e:
        kinds.append(e.kind)
    try:
        r.consume(1)  # nothing buffered
    except e:
        kinds.append(e.kind)
    try:
        _ = BufReader(Script(""), capacity=0)
    except e:
        kinds.append(e.kind)
    try:
        _ = BufReader(Script(""), capacity=32, max_size=16)
    except e:
        kinds.append(e.kind)
    assert_equal(len(kinds), 8)
    for k in kinds:
        assert_equal(k, ErrorKind.InvalidInput)
    assert_equal(r.stream().calls, 0)


def test_defaults() raises:
    var r = BufReader(Script(""))
    assert_equal(r.capacity(), DEFAULT_CAPACITY)
    assert_equal(r.max_size(), DEFAULT_MAX_SIZE)
    assert_equal(r.buffer().capacity(), 0)  # nothing allocated before a read


# ---- read sizes and plain reads ----------------------------------------------


def test_pipelined_frames_need_no_more_reads() raises:
    var r = BufReader(Script("a\nb\nc\n"))
    assert_equal(_text(r.read_line(8).value()), "a")
    assert_equal(_text(r.read_line(8).value()), "b")
    assert_equal(_text(r.read_line(8).value()), "c")
    assert_equal(r.stream().calls, 1)
    assert_false(r.read_line(8))
    assert_equal(r.stream().calls, 2)


def test_read_serves_buffered_bytes_first() raises:
    var r = BufReader(Script("hello\nworld"))
    assert_equal(_text(r.read_line(8).value()), "hello")
    var buf = List[UInt8](length=3, fill=0)
    assert_equal(r.read(Span(buf)), 3)
    assert_equal(_text(buf), "wor")
    assert_equal(r.read(Span(buf)), 2)
    assert_equal(String(from_utf8_lossy=Span(buf)[0:2]), "ld")
    assert_equal(r.stream().calls, 1)
    assert_equal(r.read(Span(buf)), 0)  # EOF
    assert_equal(r.stream().calls, 2)


def test_large_reads_skip_the_buffer() raises:
    var data = List[UInt8]()
    for i in range(200):
        data.append(UInt8(i))
    var r = BufReader(Script(data^, _sizes(Int.MAX), List[Int]()), capacity=16)
    var big = List[UInt8](length=64, fill=0)
    assert_equal(r.read(Span(big)), 64)
    assert_equal(r.stream().asked[0], 64)  # straight into the caller's buffer
    assert_equal(len(r.buffer()), 0)
    assert_equal(Int(big[63]), 63)
    var small = List[UInt8](length=8, fill=0)
    assert_equal(r.read(Span(small)), 8)
    assert_true(r.stream().asked[1] >= 16)  # one read of at least the read size
    assert_equal(len(r.buffer()), 128)
    assert_equal(Int(small[0]), 64)


def test_reads_ask_for_at_least_the_read_size() raises:
    var r = BufReader(Script(INPUT, _sizes(3), List[Int]()), capacity=1024)
    _ = r.read_line(256)
    for a in r.stream().asked:
        assert_true(a >= 1024)


def test_read_exact_of_a_large_body() raises:
    var data = List[UInt8]()
    for i in range(300_000):
        data.append(UInt8(i % 251))
    var r = BufReader(Script(data^, _sizes(4096), List[Int]()), capacity=1024)
    var body = List[UInt8](length=300_000, fill=0)
    r.read_exact(Span(body))
    for i in range(0, 300_000, 997):
        assert_equal(Int(body[i]), i % 251)
    assert_equal(len(r.buffer()), 0)


# ---- all or nothing ----------------------------------------------------------


def test_expiry_mid_frame_is_retried_without_loss() raises:
    # Reads 2 and 4 expire; each frame read is simply called again.
    var r = BufReader(
        Script("GET / HTTP/1.1\r\n\r\nnext", _sizes(5), _sizes(2, 4)),
        capacity=1,
    )
    var expired = 0
    var head: Optional[List[UInt8]] = None
    while not head:
        try:
            head = r.read_until(String("\r\n\r\n").as_bytes(), 64)
        except e:
            assert_true(e.kind == ErrorKind.TimedOut)
            expired += 1
    assert_equal(expired, 2)
    assert_equal(_text(head.value()), "GET / HTTP/1.1\r\n\r\n")
    assert_equal(_text(r.read_until(UInt8(ord("t")), 8).value()), "next")


def test_transcript_survives_every_read_size() raises:
    var n = len(bytes_of(INPUT))
    for size in range(1, n + 2):
        for cap in [1, 3, 64]:
            _check_transcript(
                Script(INPUT, _sizes(size), List[Int]()),
                cap,
                String("size=", size),
            )


def test_transcript_survives_every_single_cut() raises:
    var n = len(bytes_of(INPUT))
    for cut in range(1, n):
        _check_transcript(
            Script(INPUT, _sizes(cut, Int.MAX), List[Int]()),
            DEFAULT_CAPACITY,
            String("cut=", cut),
        )


def test_transcript_survives_random_cuts_and_expiries() raises:
    var rng = Rng(0x5EED)
    for run in range(300):
        var sizes = List[Int]()
        for _ in range(1 + rng.below(24)):
            sizes.append(1 + rng.below(17))
        var timeouts = List[Int]()
        for call in range(1, 200):
            if rng.below(5) == 0:
                timeouts.append(call)
        var cap = 1 + rng.below(32)
        _check_transcript(
            Script(INPUT, sizes^, timeouts^), cap, String("run=", run)
        )


# ---- real streams ------------------------------------------------------------


def test_unix_deadline_expires_mid_frame_and_the_frame_survives() raises:
    var p = UnixStream.pair()
    var x = p.first.take()
    var y = p.second.take()
    y.set_write_deadline(_guard())
    y.write_all(String("GET / HT").as_bytes())
    var r = BufReader(x^)
    r.stream().set_read_deadline(Deadline.after(Duration.from_millis(50)))
    var expired = False
    try:
        _ = r.read_until(String("\r\n\r\n").as_bytes(), 1024)
    except e:
        expired = e.is_deadline()
    assert_true(expired)
    assert_equal(String(from_utf8_lossy=r.buffer().readable_span()), "GET / HT")
    y.write_all(String("TP/1.1\r\n\r\nnext").as_bytes())
    r.stream().set_read_deadline(_guard())
    var head = r.read_until(String("\r\n\r\n").as_bytes(), 1024)
    assert_equal(_text(head.value()), "GET / HTTP/1.1\r\n\r\n")
    assert_equal(String(from_utf8_lossy=r.buffer().readable_span()), "next")


def test_into_parts_returns_the_stream_and_the_buffered_bytes() raises:
    var p = UnixStream.pair()
    var x = p.first.take()
    var y = p.second.take()
    y.set_write_deadline(_guard())
    y.write_all(String("UPGRADE\r\nframe-bytes").as_bytes())
    var r = BufReader(x^)
    r.stream().set_read_deadline(_guard())
    assert_equal(_text(r.read_line(64).value()), "UPGRADE")
    var parts = r^.into_parts()
    var s = parts.stream.take()
    var left = parts.buffered.take()
    assert_equal(String(from_utf8_lossy=left.readable_span()), "frame-bytes")
    y.write_all(String("!").as_bytes())
    var one = List[UInt8](length=1, fill=0)
    s.read_exact(Span(one))
    assert_equal(_text(one), "!")


def _content_length(head: List[UInt8]) -> Int:
    var text = _text(head)
    var at = text.find("Content-Length: ")
    if at < 0:
        return 0
    var n = 0
    var b = text.as_bytes()
    var i = at + 16
    while i < len(b) and b[i] >= UInt8(ord("0")) and b[i] <= UInt8(ord("9")):
        n = n * 10 + Int(b[i] - UInt8(ord("0")))
        i += 1
    return n


def test_tcp_pipelined_requests() raises:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    l.set_deadline(_guard())
    var c = TcpStream.connect(l.local_addr())
    c.set_deadline(_guard())
    var s = l.accept().into_stream()
    s.set_deadline(_guard())
    c.write_all(
        String(
            "POST /1 HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
            "POST /2 HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
            "GET /3 HTTP/1.1\r\nHost: h\r\n\r\n",
        ).as_bytes()
    )
    c.shutdown(Shutdown.WRITE)
    var r = BufReader(s^)
    var seen = List[String]()
    while True:
        var head = r.read_until(String("\r\n\r\n").as_bytes(), 1024)
        if not head:
            break
        var h = head.take()
        var body = List[UInt8](length=_content_length(h), fill=0)
        r.read_exact(Span(body))
        var first = _text(h)
        seen.append(
            String(first[byte = 0 : first.find("\r\n")], "|", _text(body))
        )
        r.stream().write_all(String("ok;").as_bytes())
    assert_equal(len(seen), 3)
    assert_equal(seen[0], "POST /1 HTTP/1.1|abc")
    assert_equal(seen[1], "POST /2 HTTP/1.1|")
    assert_equal(seen[2], "GET /3 HTTP/1.1|")
    var replies = List[UInt8](length=9, fill=0)
    c.read_exact(Span(replies))
    assert_equal(_text(replies), "ok;ok;ok;")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
