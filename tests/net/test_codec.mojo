"""The sans-I/O contract through its reference codec: LineCodec parsing
(empty lines, CRLF, lone CR, limits, EOF, poisoning), transmit order and
partial transmit, deadlines, chunking invariance over every split of a
200-byte input, and `drive_chunked` catching codecs that break the rules.
One end-to-end test runs two LineCodecs over a real socketpair, with the
test as the I/O driver (the codec itself never touches the fd)."""

from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_true,
)

from linux import ErrorKind, IoError, OwnedFd, check, sys
from linux.consts import AF_UNIX, MSG_NOSIGNAL, SOCK_CLOEXEC, SOCK_STREAM
from linux.time import Instant
from net.buffer import ByteBuffer
from net.codec import Codec, LineCodec, drive_chunked, escape_bytes


# ---- helpers -----------------------------------------------------------------


def _str(data: Span[UInt8, _]) -> String:
    return String(unsafe_from_utf8=data)


def render_line(line: List[UInt8]) -> String:
    return escape_bytes(Span(line))


def _lines(mut c: LineCodec) raises -> List[String]:
    """Drain every available event (escaped)."""
    var out = List[String]()
    while True:
        var ev = c.next_event()
        if not ev:
            return out^
        out.append(escape_bytes(Span(ev.value())))


def _next_kind(mut c: LineCodec) -> String:
    """`"line <escaped>"`, `"none"` or `"error <kind> <op>"`."""
    try:
        var ev = c.next_event()
        if ev:
            return String("line ", escape_bytes(Span(ev.value())))
        return "none"
    except e:
        return String("error ", e.kind, " ", e.op)


def _feed_kind(mut c: LineCodec, data: Span[UInt8, _]) -> String:
    try:
        c.feed(data)
        return "ok"
    except e:
        return String("error ", e.kind, " ", e.op)


def _send_kind(mut c: LineCodec, data: Span[UInt8, _]) -> String:
    try:
        c.send_line(data)
        return "ok"
    except e:
        return String("error ", e.kind, " ", e.op)


def _codec(max_line: Int = 64) raises -> LineCodec:
    return LineCodec(max_line_length=max_line)


def _expect(got: List[String], want: List[String]) raises:
    assert_equal(len(got), len(want))
    for i in range(len(want)):
        assert_equal(got[i], want[i])


struct Rng(Movable):
    """The splitmix64 generator (deterministic, seeded)."""

    var s: UInt64

    def __init__(out self, seed: UInt64):
        self.s = seed

    def next(mut self) -> UInt64:
        self.s += 0x9E3779B97F4A7C15
        var z = self.s
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB
        return z ^ (z >> 31)

    def below(mut self, n: Int) -> Int:
        return Int(self.next() % UInt64(n))


# ---- construction ------------------------------------------------------------


def test_init_validation() raises:
    var bad: List[Tuple[Int, Int]] = [
        (-1, 100),
        (99, 100),
        (0, 1),
        (10, -1),
        (0, Int.MIN),
    ]
    for i in range(len(bad)):
        var kind = ErrorKind.Other
        try:
            _ = LineCodec(max_line_length=bad[i][0], max_buffered=bad[i][1])
        except e:
            kind = e.kind
            assert_equal(String(e.op), "LineCodec.__init__")
        assert_equal(kind, ErrorKind.InvalidInput)
    # Exactly one maximal CRLF line fits: accepted.
    var c = LineCodec(max_line_length=98, max_buffered=100)
    c.feed(String("x" * 98 + "\r\n").as_bytes())
    _expect(_lines(c), [String("x" * 98)])
    # Defaults.
    var d = LineCodec()
    assert_false(Bool(d.next_deadline()))
    assert_equal(d.pending_transmit(), 0)


# ---- receive -----------------------------------------------------------------


def test_lines_empty_lines_and_crlf() raises:
    var c = _codec()
    c.feed("a\nbc\n\n\r\nd\r\n".as_bytes())
    _expect(_lines(c), ["a", "bc", "", "", "d"])
    assert_equal(_next_kind(c), "none")


def test_lone_cr_is_content() raises:
    var c = _codec()
    c.feed("b\rc\n\r\r\n\r\nx\r\ry\n".as_bytes())
    # Only the CR immediately before LF is part of the terminator.
    _expect(_lines(c), ["b\\rc", "\\r", "", "x\\r\\ry"])


def test_binary_bytes_pass_through() raises:
    var c = _codec()
    var data: List[UInt8] = [0, 255, 128, 13, 0, 10, 92, 10]
    c.feed(Span(data))
    _expect(_lines(c), ["\\x00\\xff\\x80\\r\\x00", "\\\\"])


def test_partial_line_waits_for_terminator() raises:
    var c = _codec()
    c.feed("ab".as_bytes())
    assert_equal(_next_kind(c), "none")
    c.feed(Span[UInt8, ImmStaticOrigin]())  # empty feed: no-op
    assert_equal(_next_kind(c), "none")
    c.feed("c\r".as_bytes())
    assert_equal(_next_kind(c), "none")  # CR may still become CRLF
    c.feed("\nde".as_bytes())
    assert_equal(_next_kind(c), "line abc")
    assert_equal(_next_kind(c), "none")
    c.feed("\n".as_bytes())
    assert_equal(_next_kind(c), "line de")


def test_max_line_length_boundaries() raises:
    var c = _codec(4)
    c.feed("abcd\nabcd\r\n\n".as_bytes())
    _expect(_lines(c), ["abcd", "abcd", ""])
    # max + 1 content bytes before LF: rejected.
    var d = _codec(4)
    d.feed("abcde\n".as_bytes())
    assert_equal(_next_kind(d), "error InvalidData LineCodec.next_event")
    # ... also with CRLF (content is still 5).
    var e = _codec(4)
    e.feed("abcde\r\n".as_bytes())
    assert_equal(_next_kind(e), "error InvalidData LineCodec.next_event")
    # Zero max: only empty lines.
    var z = _codec(0)
    z.feed("\n\r\n".as_bytes())
    _expect(_lines(z), ["", ""])
    z.feed("x\n".as_bytes())
    assert_equal(_next_kind(z), "error InvalidData LineCodec.next_event")


def test_over_long_line_detected_before_its_newline() raises:
    var c = _codec(4)
    c.feed("ok\nabcd\r".as_bytes())  # 5 bytes: could still be "abcd\r\n"
    assert_equal(_next_kind(c), "line ok")
    assert_equal(_next_kind(c), "none")
    c.feed("x".as_bytes())  # now certainly longer than 4
    assert_equal(_next_kind(c), "error InvalidData LineCodec.next_event")
    # max + 1 bytes, last not CR: certain at once (no LF needed).
    var d = _codec(4)
    d.feed("abcde".as_bytes())
    assert_equal(_next_kind(d), "error InvalidData LineCodec.next_event")
    # ... so at EOF that is InvalidData, not UnexpectedEof.
    var e = _codec(4)
    e.feed("abcd".as_bytes())
    assert_equal(_next_kind(e), "none")
    e.feed("e".as_bytes())
    e.feed_eof()
    assert_equal(_next_kind(e), "error InvalidData LineCodec.next_event")


def test_error_poisons_the_input_side() raises:
    var c = _codec(2)
    c.feed("abc\nok\n".as_bytes())
    assert_equal(_next_kind(c), "error InvalidData LineCodec.next_event")
    # Same error forever, even though "ok\n" is buffered.
    assert_equal(_next_kind(c), "error InvalidData LineCodec.next_event")
    assert_equal(
        _feed_kind(c, "x\n".as_bytes()),
        "error InvalidData LineCodec.next_event",
    )
    var kind = ErrorKind.Other
    try:
        c.feed_eof()
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidData)
    # The send side still works.
    c.send_line("hi".as_bytes())
    assert_equal(c.pending_transmit(), 3)


def test_feed_beyond_buffer_limit_is_out_of_memory_and_poisons() raises:
    var c = LineCodec(max_line_length=4, max_buffered=8)
    c.feed("a\nb\n".as_bytes())
    assert_equal(
        _feed_kind(c, "12345".as_bytes()),  # 4 buffered + 5 > 8
        "error OutOfMemory LineCodec.feed",
    )
    assert_equal(_next_kind(c), "error OutOfMemory LineCodec.feed")


def test_draining_keeps_buffer_bounded() raises:
    """Rule 5: draining between feeds keeps memory at one partial line plus
    a chunk, so a long stream passes through a small buffer."""
    var c = LineCodec(max_line_length=8, max_buffered=24)
    var total = 0
    for i in range(10_000):
        c.feed(String("line", i % 10, "\n").as_bytes())
        var got = _lines(c)
        assert_equal(len(got), 1)
        total += 1
    assert_equal(total, 10_000)


def test_eof_semantics() raises:
    # Complete lines then EOF: clean end, None forever.
    var c = _codec()
    c.feed("a\n".as_bytes())
    c.feed_eof()
    c.feed_eof()  # idempotent
    assert_equal(_next_kind(c), "line a")
    assert_equal(_next_kind(c), "none")
    assert_equal(_next_kind(c), "none")
    # feed after EOF is misuse.
    assert_equal(
        _feed_kind(c, "b\n".as_bytes()), "error InvalidInput LineCodec.feed"
    )
    # Partial line at EOF: complete lines first, then UnexpectedEof.
    var d = _codec()
    d.feed("x\nyz".as_bytes())
    d.feed_eof()
    assert_equal(_next_kind(d), "line x")
    assert_equal(_next_kind(d), "error UnexpectedEof LineCodec.next_event")
    assert_equal(_next_kind(d), "error UnexpectedEof LineCodec.next_event")
    # A lone trailing CR is a partial line too.
    var e = _codec()
    e.feed("\r".as_bytes())
    e.feed_eof()
    assert_equal(_next_kind(e), "error UnexpectedEof LineCodec.next_event")
    # EOF on an empty stream.
    var f = _codec()
    f.feed_eof()
    assert_equal(_next_kind(f), "none")


def test_byte_at_a_time_long_line_is_linear() raises:
    """200k bytes fed one at a time with a next_event after each: the
    resumable scan keeps this O(n) (a rescan would be ~2e10 byte checks)."""
    comptime N = 200_000
    var c = LineCodec(max_line_length=N, max_buffered=N + 2)
    var one: List[UInt8] = [UInt8(ord("q"))]
    for _ in range(N):
        c.feed(Span(one))
        if c.next_event():
            raise Error("line ended early")
    var nl: List[UInt8] = [10]
    c.feed(Span(nl))
    var ev = c.next_event()
    assert_equal(len(ev.value()), N)
    assert_equal(_next_kind(c), "none")


# ---- chunking invariance -----------------------------------------------------


def _input_200() -> List[UInt8]:
    """200 bytes covering every receive path: empty lines, CRLF, lone CRs,
    CR CR LF, binary bytes, a long line, and lines across every offset."""
    var s = String(
        "hello\n\nworld\r\n\r\nlone\rcr\n\r\r\nPING :irc.example 42\r\n"
    )
    s += "x" * 40 + "\n"
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    var bin: List[UInt8] = [0, 1, 255, 13, 128, 10, 10]
    for i in range(len(bin)):
        out.append(bin[i])
    var k = 0
    while len(out) < 199:
        out.append(UInt8(97 + k % 26))
        k += 1
        if k % 7 == 0:
            out.append(UInt8(13) if k % 14 == 0 else UInt8(32))
        if k % 5 == 0 and len(out) < 199:
            out.append(10)
    out.resize(199, 0)
    out.append(10)
    return out^


def _oracle(data: List[UInt8], max_line: Int) -> List[String]:
    """Independent model of the full transcript: cut at LF, strip one CR
    before it; an over-long line ends it with InvalidData; a leftover
    partial line ends it with InvalidData if already too long (a trailing
    CR does not count yet), else UnexpectedEof."""
    var out = List[String]()
    var start = 0
    for i in range(len(data)):
        if data[i] == 10:
            var end = i
            if end > start and data[end - 1] == 13:
                end -= 1
            if end - start > max_line:
                out.append("error InvalidData")
                return out^
            out.append(escape_bytes(Span(data)[start:end]))
            start = i + 1
    if start < len(data):
        var at_least = len(data) - start
        if data[len(data) - 1] == 13:
            at_least -= 1
        if at_least > max_line:
            out.append("error InvalidData")
        else:
            out.append("error UnexpectedEof")
    return out^


def test_every_split_of_200_bytes_gives_identical_events() raises:
    var input = _input_200()
    assert_equal(len(input), 200)
    var want = _oracle(input, 64)
    assert_true(len(want) >= 15)
    for i in range(len(want)):
        assert_false(want[i].startswith("error"))
    var proto = _codec(64)
    var got = drive_chunked[render_line](proto, Span(input), seed=0xC0DEC)
    _expect(got, want)


def test_every_split_with_over_long_line_errors_identically() raises:
    var s = String("one\ntwo\r\n") + "y" * 30 + "\nnever\n"
    var proto = _codec(16)
    var got = drive_chunked[render_line](proto, s.as_bytes(), seed=7)
    _expect(got, ["one", "two", "error InvalidData"])
    # Over-long tail with no newline at all.
    var t = String("a\n") + "z" * 40
    got = drive_chunked[render_line](proto, t.as_bytes(), seed=8)
    _expect(got, ["a", "error InvalidData"])
    # Boundary: exactly max content plus CR at EOF is a partial line, not
    # an over-long one.
    var u = String("b\n") + "w" * 16 + "\r"
    got = drive_chunked[render_line](proto, u.as_bytes(), seed=9)
    _expect(got, ["b", "error UnexpectedEof"])


def test_every_split_with_truncated_last_line() raises:
    var proto = _codec()
    var got = drive_chunked[render_line](
        proto, "first\r\nsecond\nthi".as_bytes(), seed=3
    )
    _expect(got, ["first", "second", "error UnexpectedEof"])
    # Empty input: no events, clean EOF.
    var empty = List[UInt8]()
    got = drive_chunked[render_line](proto, Span(empty))
    assert_equal(len(got), 0)


def test_random_inputs_are_chunking_invariant() raises:
    """Random short inputs over the alphabet {a, CR, LF} (many empty lines,
    CRLF/CR edge cases) with a small limit: every chunking gives the same
    transcript (drive_chunked), and it equals the independent model."""
    var rng = Rng(0x11E5)
    var errors = 0
    for round in range(60):
        var n = rng.below(40)
        var data = List[UInt8]()
        for _ in range(n):
            var r = rng.below(6)
            data.append(
                UInt8(10) if r <= 1 else (UInt8(13) if r == 2 else UInt8(97))
            )
        if round % 2 == 0:
            data.append(10)  # half the streams end on a line boundary
        var proto = _codec(5)
        var got = drive_chunked[render_line](
            proto,
            Span(data),
            seed=UInt64(round),
            random_rounds=20,
            max_pair_len=40,
        )
        _expect(got, _oracle(data, 5))
        if got and got[len(got) - 1].startswith("error"):
            errors += 1
    assert_true(errors > 10)
    assert_true(errors < 55)  # clean streams are common too


# ---- drive_chunked catches broken codecs ---------------------------------------


struct PerFeedCodec(Codec, Copyable):
    """Broken on purpose: one event per non-empty feed, so its events depend
    on how the input is chunked (violates rule 4)."""

    comptime Event = Int

    var pending: List[Int]

    def __init__(out self):
        self.pending = List[Int]()

    def feed(mut self, data: Span[UInt8, _]) raises IoError:
        if len(data) > 0:
            self.pending.append(len(data))

    def feed_eof(mut self) raises IoError:
        pass

    def next_event(mut self) raises IoError -> Optional[Int]:
        if len(self.pending) == 0:
            return None
        return self.pending.pop(0)

    def poll_transmit(mut self, mut out: ByteBuffer) raises IoError -> Int:
        return 0

    def next_deadline(self) -> Optional[Instant]:
        return None

    def handle_timeout(mut self, now: Instant) raises IoError:
        pass


struct ForgetfulCodec(Codec, Copyable):
    """Broken on purpose: raises once on 'X', then recovers (violates
    rule 6, errors must be terminal)."""

    comptime Event = Int

    var count: Int
    var bad: Bool

    def __init__(out self):
        self.count = 0
        self.bad = False

    def feed(mut self, data: Span[UInt8, _]) raises IoError:
        for b in data:
            if b == UInt8(ord("X")):
                self.bad = True
            self.count += 1

    def feed_eof(mut self) raises IoError:
        pass

    def next_event(mut self) raises IoError -> Optional[Int]:
        if self.bad:
            self.bad = False
            raise IoError.of_kind("Forgetful", ErrorKind.InvalidData)
        return None

    def poll_transmit(mut self, mut out: ByteBuffer) raises IoError -> Int:
        return 0

    def next_deadline(self) -> Optional[Instant]:
        return None

    def handle_timeout(mut self, now: Instant) raises IoError:
        pass


def render_int(v: Int) -> String:
    return String(v)


def test_drive_chunked_rejects_chunk_dependent_codec() raises:
    var proto = PerFeedCodec()
    var msg = String()
    try:
        _ = drive_chunked[render_int](proto, "abcdef".as_bytes())
    except e:
        msg = String(e)
    # Split [0] (empty feed, then everything) still matches; [1] does not.
    assert_equal(
        msg,
        (
            "drive_chunked: split [1] diverged at event 0: whole-input gave"
            " '6', chunked gave '1'"
        ),
    )


def test_drive_chunked_rejects_codec_that_recovers_from_errors() raises:
    var proto = ForgetfulCodec()
    var msg = String()
    try:
        _ = drive_chunked[render_int](proto, "aXb".as_bytes())
    except e:
        msg = String(e)
    assert_true(msg.startswith("drive_chunked: codec not poisoned"))


# ---- transmit ----------------------------------------------------------------


def test_poll_transmit_preserves_order_and_appends() raises:
    var c = _codec()
    c.send_line("one".as_bytes())
    c.send_line("".as_bytes())
    c.send_line("three".as_bytes())
    assert_equal(c.pending_transmit(), 11)
    var out = ByteBuffer()
    out.write_bytes("prev|".as_bytes())  # existing content is untouched
    assert_equal(c.poll_transmit(out), 11)
    assert_equal(_str(out.readable_span()), "prev|one\n\nthree\n")
    assert_equal(c.poll_transmit(out), 0)
    assert_equal(c.pending_transmit(), 0)
    # Interleaved send/poll keeps FIFO order.
    c.send_line("4".as_bytes())
    var out2 = ByteBuffer()
    assert_equal(c.poll_transmit(out2), 2)
    c.send_line("5".as_bytes())
    c.send_line("6".as_bytes())
    assert_equal(c.poll_transmit(out2), 4)
    assert_equal(_str(out2.readable_span()), "4\n5\n6\n")


def test_crlf_output_mode() raises:
    var c = LineCodec(max_line_length=16, crlf=True)
    c.send_line("EHLO x".as_bytes())
    c.send_line("".as_bytes())
    var out = ByteBuffer()
    assert_equal(c.poll_transmit(out), 10)
    assert_equal(_str(out.readable_span()), "EHLO x\r\n\r\n")


def test_partial_transmit_respects_out_capacity() raises:
    var c = _codec()
    c.send_line("abcdefgh".as_bytes())
    c.send_line("ij".as_bytes())
    var out = ByteBuffer(max_size=5)
    out.write_bytes("Z".as_bytes())
    assert_equal(c.poll_transmit(out), 4)  # only 4 of 5 bytes free
    assert_equal(_str(out.readable_span()), "Zabcd")
    assert_equal(c.poll_transmit(out), 0)  # full: nothing lost
    assert_equal(c.pending_transmit(), 8)
    out.consume(5)  # "sent"
    assert_equal(c.poll_transmit(out), 5)
    assert_equal(_str(out.readable_span()), "efgh\n")
    out.clear()
    assert_equal(c.poll_transmit(out), 3)
    assert_equal(_str(out.readable_span()), "ij\n")


def test_send_line_validation_is_all_or_nothing() raises:
    var c = LineCodec(max_line_length=4, max_buffered=10)
    assert_equal(
        _send_kind(c, "a\nb".as_bytes()),
        "error InvalidInput LineCodec.send_line",
    )
    assert_equal(
        _send_kind(c, "a\rb".as_bytes()),
        "error InvalidInput LineCodec.send_line",
    )
    assert_equal(
        _send_kind(c, "abcde".as_bytes()),
        "error InvalidInput LineCodec.send_line",
    )
    assert_equal(c.pending_transmit(), 0)
    assert_equal(_send_kind(c, "abcd".as_bytes()), "ok")  # 5 queued
    assert_equal(_send_kind(c, "efgh".as_bytes()), "ok")  # 10 queued
    assert_equal(
        _send_kind(c, "".as_bytes()), "error OutOfMemory LineCodec.send_line"
    )
    assert_equal(c.pending_transmit(), 10)
    var out = ByteBuffer()
    _ = c.poll_transmit(out)
    assert_equal(_str(out.readable_span()), "abcd\nefgh\n")


def test_round_trip_random_lines() raises:
    """What one LineCodec transmits, another parses back exactly, whatever
    the chunking of the byte stream in between."""
    var rng = Rng(0x7071)
    var tx = LineCodec(max_line_length=50, crlf=True)
    var rx = LineCodec(max_line_length=50)
    var sent = List[String]()
    for _ in range(300):
        var line = List[UInt8]()
        for _ in range(rng.below(51)):
            var b = UInt8(rng.below(256))
            if b == 10 or b == 13:
                b = 32
            line.append(b)
        tx.send_line(Span(line))
        sent.append(escape_bytes(Span(line)))
    var wire = ByteBuffer()
    _ = tx.poll_transmit(wire)
    var got = List[String]()
    while len(wire) > 0:
        var n = min(len(wire), 1 + rng.below(97))
        rx.feed(wire.readable_span()[0:n])
        wire.consume(n)
        var lines = _lines(rx)
        for i in range(len(lines)):
            got.append(lines[i])
    _expect(got, sent)


# ---- time --------------------------------------------------------------------


def test_deadline_and_timeouts() raises:
    var c = _codec()
    assert_false(Bool(c.next_deadline()))
    c.handle_timeout(Instant(nanos=10**15))  # no deadline: no-op
    c.set_deadline(Instant(nanos=1000))
    assert_equal(c.next_deadline().value(), Instant(nanos=1000))
    c.handle_timeout(Instant(nanos=999))  # early wakeup: no-op
    c.handle_timeout(Instant(nanos=0))
    assert_equal(c.next_deadline().value(), Instant(nanos=1000))
    var kind = ErrorKind.Other
    try:
        c.handle_timeout(Instant(nanos=1000))  # at the deadline: expires
    except e:
        kind = e.kind
        assert_equal(String(e.op), "LineCodec.handle_timeout")
    assert_equal(kind, ErrorKind.TimedOut)
    assert_false(Bool(c.next_deadline()))  # fired once, cleared
    c.handle_timeout(Instant(nanos=5000))  # repeated call: no-op
    # Timeouts do not poison: the stream keeps working.
    c.feed("still\n".as_bytes())
    assert_equal(_next_kind(c), "line still")
    # Late call well past the deadline also fires; disarm works.
    c.set_deadline(Instant(nanos=2000))
    c.set_deadline(None)
    c.handle_timeout(Instant(nanos=10**12))
    c.set_deadline(Instant(nanos=-5))
    kind = ErrorKind.Other
    try:
        c.handle_timeout(Instant(nanos=10**12))
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.TimedOut)


# ---- a real driver over a socketpair -----------------------------------------


def test_socketpair_driver_end_to_end() raises:
    """The test is the driver: it moves bytes between kernel and codecs,
    the codecs stay pure. Receives go straight into a ByteBuffer's tail."""
    var fds = Array[Int32, 2](fill=-1)
    _ = check(
        "socketpair",
        sys.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds),
    )
    var a = OwnedFd(unsafe_from_raw=fds[0])
    var b = OwnedFd(unsafe_from_raw=fds[1])
    var client = LineCodec(max_line_length=32, crlf=True)
    var server = LineCodec(max_line_length=32)
    for i in range(50):
        client.send_line(String("msg ", i).as_bytes())
    var out = ByteBuffer()
    _ = client.poll_transmit(out)
    while len(out) > 0:
        var n = check("send", sys.send(a, out.readable_span(), MSG_NOSIGNAL))
        out.consume(n)
    _ = check("shutdown", sys.shutdown(a, 1))  # SHUT_WR: EOF for the server
    var inbuf = ByteBuffer()
    var got = List[String]()
    while True:
        inbuf.ensure_writable(7)  # tiny reads: lines split across recvs
        var w = inbuf.writable_span()
        var n = check("recv", sys.recv(b, w[0:7], 0))
        if n == 0:
            server.feed_eof()
            var rest = _lines(server)
            for i in range(len(rest)):
                got.append(rest[i])
            break
        inbuf.commit(n)
        server.feed(inbuf.readable_span())
        inbuf.clear()
        var lines = _lines(server)
        for i in range(len(lines)):
            got.append(lines[i])
    assert_equal(len(got), 50)
    for i in range(50):
        assert_equal(got[i], String("msg ", i))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
