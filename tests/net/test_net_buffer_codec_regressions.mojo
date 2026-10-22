"""Regression tests for the net-buffer-codec review findings:
- F27: `ByteBuffer.copy()` copies only the readable bytes.
- F06: offsets instead of spans: `byte_at`, and offsets that survive growth.
- F08: rule 4 vs rule 5. `feed_capacity()` lets a driver feed in pieces that
  fit, so the outcome no longer depends on the receive size, and
  `drive_chunked` checks inputs longer than the codec's buffer.
- F13: design.md contract 1 describes the trait that exists, and the
  driver-owned `poll_transmit` buffer moves into a send op (contract 4).
The check-mode half of F06 is in test_net_buffer_codec_regressions_faults.
"""

from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_true,
)

from linux import ErrorKind, IoError, OwnedFd, check, sys
from linux.consts import AF_UNIX, MSG_NOSIGNAL, SOCK_CLOEXEC, SOCK_STREAM
from linux.time import Instant
from bytes.buffer import DEFAULT_MAX_SIZE, ByteBuffer
from net.codec import Codec, LineCodec, drive_chunked, escape_bytes


# ---- helpers -----------------------------------------------------------------


def _str(data: Span[UInt8, _]) -> String:
    return String(unsafe_from_utf8=data)


def render_line(line: List[UInt8]) -> String:
    return escape_bytes(Span(line))


def _expect(got: List[String], want: List[String]) raises:
    assert_equal(len(got), len(want))
    for i in range(len(want)):
        assert_equal(got[i], want[i])


def _repeat(s: String, n: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for _ in range(n):
        for b in s.as_bytes():
            out.append(b)
    return out^


def _rule5_driver(
    proto: LineCodec, input: Span[UInt8, _], recv_size: Int
) raises -> List[String]:
    """What a real driver does with receives of `recv_size` bytes: feed
    each receive in pieces of at most `feed_capacity()`, draining after
    each, then EOF. Transcript like drive_chunked's."""
    var c = proto.copy()
    var out = List[String]()
    try:
        var pos = 0
        while pos < len(input):
            var end = min(len(input), pos + recv_size)
            while pos < end:
                var k = min(end - pos, c.feed_capacity())
                if k <= 0:
                    out.append("stalled")
                    return out^
                c.feed(input[pos : pos + k])
                pos += k
                while True:
                    var ev = c.next_event()
                    if not ev:
                        break
                    out.append(escape_bytes(Span(ev.value())))
        c.feed_eof()
        while True:
            var ev = c.next_event()
            if not ev:
                break
            out.append(escape_bytes(Span(ev.value())))
    except e:
        out.append(String("error ", e.kind))
    return out^


def _kind_of_byte_at(b: ByteBuffer, offset: Int) raises -> ErrorKind:
    var kind = ErrorKind.Other
    try:
        _ = b.byte_at(offset)
    except e:
        assert_equal(String(e.op), "ByteBuffer.byte_at")
        kind = e.kind
    return kind


# ---- F27: copy() is O(readable) ------------------------------------------------


def test_copy_holds_only_the_readable_bytes() raises:
    var a = ByteBuffer(capacity=1024, max_size=4096)
    a.write_bytes("..hello".as_bytes())
    a.consume(2)
    var b = a.copy()
    assert_equal(_str(b.readable_span()), "hello")
    assert_equal(b.capacity(), 5)  # was 1024: the whole capacity copied
    assert_equal(b.read_index(), 0)  # the consumed prefix is not copied
    assert_equal(b.max_size(), 4096)
    # Still independent and fully usable.
    b.write_bytes(" world".as_bytes())
    a.consume(1)
    assert_equal(_str(a.readable_span()), "ello")
    assert_equal(_str(b.readable_span()), "hello world")
    assert_equal(a.capacity(), 1024)


def test_copy_of_large_capacity_buffer_is_small() raises:
    var big = ByteBuffer(capacity=DEFAULT_MAX_SIZE)
    big.write_bytes("0123456789".as_bytes())
    var c = big.copy()
    assert_equal(c.capacity(), 10)  # was 64 MiB
    assert_equal(_str(c.readable_span()), "0123456789")
    # An empty buffer copies without allocating.
    var empty = ByteBuffer(capacity=4096)
    var e = empty.copy()
    assert_equal(e.capacity(), 0)
    assert_true(e.is_empty())
    e.write_byte(7)
    assert_equal(Int(e.byte_at(0)), 7)


def test_codec_copy_keeps_partial_input() raises:
    """A copy of a fed codec (drive_chunked copies codecs) keeps the
    unparsed bytes and nothing else."""
    var c = LineCodec(max_line_length=16)
    c.feed("done\npar".as_bytes())
    assert_equal(escape_bytes(Span(c.next_event().value())), "done")
    var d = c.copy()
    d.feed("tial\n".as_bytes())
    assert_equal(escape_bytes(Span(d.next_event().value())), "partial")
    assert_false(Bool(c.next_event()))  # the original still waits
    c.feed("\n".as_bytes())
    assert_equal(escape_bytes(Span(c.next_event().value())), "par")


# ---- F06: offsets, not spans ---------------------------------------------------


def test_byte_at_reads_relative_to_the_read_index() raises:
    var b = ByteBuffer()
    b.write_bytes("xxabc".as_bytes())
    b.consume(2)
    assert_equal(Int(b.byte_at(0)), ord("a"))
    assert_equal(Int(b.byte_at(2)), ord("c"))
    assert_equal(_kind_of_byte_at(b, 3), ErrorKind.InvalidInput)
    assert_equal(_kind_of_byte_at(b, -1), ErrorKind.InvalidInput)
    var empty = ByteBuffer()
    assert_equal(_kind_of_byte_at(empty, 0), ErrorKind.InvalidInput)


def test_offsets_survive_growth_and_compaction() raises:
    """The codec pattern the docs prescribe: keep an offset from `find`
    across writes that grow (and compact) the buffer, read it back with
    `byte_at`. A span kept the same way would point at freed memory."""
    var b = ByteBuffer(capacity=16)
    b.write_bytes("ab:cdefghijklm".as_bytes())
    b.consume(1)  # "b:cdefghijklm"
    var colon = b.find(UInt8(ord(":"))).value()
    assert_equal(colon, 1)
    var cap = b.capacity()
    b.write_bytes(String("n" * 4096).as_bytes())  # grows: storage moves
    assert_true(b.capacity() > cap)
    assert_equal(Int(b.byte_at(colon)), ord(":"))
    assert_equal(Int(b.byte_at(colon + 1)), ord("c"))
    # Compaction (consume most, then ensure room) keeps offsets too.
    b.consume(4000)
    var at = b.find(UInt8(ord("n"))).value()
    b.ensure_writable(b.capacity() - len(b))
    assert_equal(b.read_index(), 0)
    assert_equal(Int(b.byte_at(at)), ord("n"))


# ---- F08: receive size never changes the outcome -------------------------------


def test_drive_chunked_checks_inputs_longer_than_the_buffer() raises:
    """'abc\\n' * 10 (40 bytes, all valid) through a 16-byte codec: fed
    whole it used to be OutOfMemory while every chunked run gave 10 lines,
    so drive_chunked failed a correct codec."""
    var proto = LineCodec(max_line_length=8, max_buffered=16)
    var input = _repeat("abc\n", 10)
    var got = drive_chunked[render_line](proto, Span(input), seed=0xF08)
    assert_equal(len(got), 10)
    for i in range(10):
        assert_equal(got[i], "abc")


def test_over_long_line_is_invalid_data_for_any_receive_size() raises:
    """Fed whole it used to be OutOfMemory from feed, in small pieces
    InvalidData from next_event."""
    var proto = LineCodec(max_line_length=8, max_buffered=16)
    var s = String("ok\n") + "y" * 30 + "\nnever\n"
    var got = drive_chunked[render_line](proto, s.as_bytes(), seed=0xF09)
    _expect(got, ["ok", "error InvalidData"])
    for recv in [1, 4, 16, 17, 31, 64, 1000]:
        _expect(
            _rule5_driver(proto, s.as_bytes(), recv),
            ["ok", "error InvalidData"],
        )


def test_rule5_driver_gets_every_line_whatever_its_receive_size() raises:
    var proto = LineCodec(max_line_length=8, max_buffered=24)
    var input = List[UInt8]()
    for i in range(500):
        for b in String(
            "l", i % 1000, "\r\n" if i % 3 == 0 else "\n"
        ).as_bytes():
            input.append(b)
    for recv in [1, 7, 23, 24, 25, 100, 4096, len(input)]:
        var got = _rule5_driver(proto, Span(input), recv)
        assert_equal(len(got), 500)
        for i in range(500):
            assert_equal(got[i], String("l", i % 1000))


def test_feed_capacity_reports_the_room_left() raises:
    var c = LineCodec(max_line_length=4, max_buffered=8)
    assert_equal(c.feed_capacity(), 8)
    c.feed("a\nbc".as_bytes())
    assert_equal(c.feed_capacity(), 4)
    assert_equal(escape_bytes(Span(c.next_event().value())), "a")
    assert_false(Bool(c.next_event()))
    assert_equal(c.feed_capacity(), 6)  # only the partial "bc" is held
    # Worst case after a drain: max_line content plus a CR.
    c.feed("cd\r".as_bytes())
    assert_false(Bool(c.next_event()))
    assert_equal(c.feed_capacity(), 8 - 5)
    # Feeding more than the room is still a driver bug: OutOfMemory, poisoned.
    var kind = ErrorKind.Other
    try:
        c.feed("1234".as_bytes())
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.OutOfMemory)
    kind = ErrorKind.Other
    try:
        _ = c.next_event()
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.OutOfMemory)


def test_feed_capacity_after_drain_is_at_least_the_guaranteed_room() raises:
    """Rule 5's progress guarantee on random streams over {a, CR, LF}, fed
    in random pieces that fit: after every drain there is room for at least
    `max_buffered - max_line_length - 1` bytes, and that bound is reached."""
    comptime MAX_LINE = 5
    comptime MAX_BUF = 9
    comptime FLOOR = MAX_BUF - MAX_LINE - 1
    var s: UInt64 = 0xF08F08
    var checks = 0
    var tight = 0
    for _ in range(60):
        var c = LineCodec(max_line_length=MAX_LINE, max_buffered=MAX_BUF)
        var failed = False
        while not failed:
            s = s * 6364136223846793005 + 1442695040888963407
            var room = c.feed_capacity()
            var k = 1 + Int((s >> 40) % UInt64(room))
            var piece = List[UInt8]()
            for j in range(k):
                var r = Int((s >> UInt64(3 * j % 30)) % 7)
                piece.append(
                    UInt8(10) if r
                    <= 1 else (UInt8(13) if r == 2 else UInt8(97))
                )
            try:
                c.feed(Span(piece))
                while c.next_event():
                    pass
            except:
                failed = True  # an over-long line: the stream is over
                continue
            assert_true(c.feed_capacity() >= FLOOR)
            checks += 1
            if c.feed_capacity() == FLOOR:
                tight += 1
            if checks % 50 == 0:
                break
    assert_true(checks > 200)
    assert_true(tight > 0)


struct StuckCodec(Codec, Copyable):
    """Broken on purpose: reports no room although it is drained, so a
    rule-5 driver could never make progress."""

    comptime Event = Int

    var fed: Int

    def __init__(out self):
        self.fed = 0

    def feed(mut self, data: Span[UInt8, _]) raises IoError:
        self.fed += len(data)

    def feed_capacity(self) -> Int:
        return 0 if self.fed >= 2 else 2 - self.fed

    def feed_eof(mut self) raises IoError:
        pass

    def next_event(mut self) raises IoError -> Optional[Int]:
        return None

    def poll_transmit(mut self, mut out: ByteBuffer) raises IoError -> Int:
        return 0

    def next_deadline(self) -> Optional[Instant]:
        return None

    def handle_timeout(mut self, now: Instant) raises IoError:
        pass


struct UnboundedCodec(Codec, Copyable):
    """Uses the trait's default `feed_capacity` (unbounded)."""

    comptime Event = Int

    var n: Int

    def __init__(out self):
        self.n = 0

    def feed(mut self, data: Span[UInt8, _]) raises IoError:
        self.n += len(data)

    def feed_eof(mut self) raises IoError:
        pass

    def next_event(mut self) raises IoError -> Optional[Int]:
        return None

    def poll_transmit(mut self, mut out: ByteBuffer) raises IoError -> Int:
        return 0

    def next_deadline(self) -> Optional[Instant]:
        return None

    def handle_timeout(mut self, now: Instant) raises IoError:
        pass


def render_int(v: Int) -> String:
    return String(v)


def test_drive_chunked_rejects_codec_with_no_room_after_draining() raises:
    var msg = String()
    try:
        _ = drive_chunked[render_int](StuckCodec(), "abcdef".as_bytes())
    except e:
        msg = String(e)
    assert_equal(
        msg,
        (
            "drive_chunked: feed_capacity() is 0 while the codec is drained"
            " and input is left (rule 5: a drained codec must accept at least"
            " one byte)"
        ),
    )


def test_default_feed_capacity_is_unbounded() raises:
    var u = UnboundedCodec()
    assert_equal(u.feed_capacity(), Int.MAX)
    var got = drive_chunked[render_int](u, "anything".as_bytes())
    assert_equal(len(got), 0)


# ---- F13: the documented contract is the implemented one -----------------------


def test_design_contract_1_describes_the_codec_trait() raises:
    """The design doc used to promise `feed(bytes) -> events` and
    `poll_transmit() -> owned buffers`, which is not the trait."""
    var doc = open("docs/design.md", "r").read()
    var line = String()
    for l in doc.split("\n"):
        if l.startswith("1. **Sans-I/O protocols.**"):
            line = String(l)
    assert_true(line.byte_length() > 0)
    for name in [
        "feed(",
        "feed_capacity()",
        "feed_eof()",
        "next_event()",
        "poll_transmit(out)",
        "next_deadline()",
        "handle_timeout(now)",
        "ByteBuffer",
    ]:
        if name not in line:
            raise Error("design.md contract 1 does not mention ", name)
    assert_false("poll_transmit() -> owned buffers" in line)


struct SendOp(Movable):
    """A stand-in for an evented send: owns the buffer while in flight."""

    var buf: ByteBuffer

    def __init__(out self, var buf: ByteBuffer):
        self.buf = buf^

    def complete(deinit self, fd: OwnedFd) raises -> ByteBuffer:
        """Run the send to completion and hand the buffer back."""
        while len(self.buf) > 0:
            var n = check(
                "send", sys.send(fd, self.buf.readable_span(), MSG_NOSIGNAL)
            )
            self.buf.consume(n)
        return self.buf^


def test_poll_transmit_buffer_moves_into_a_send_op() raises:
    """Contract 4 with the current trait: the driver's own buffer is filled
    by `poll_transmit`, moved into the op and returned, without a staging
    buffer or a copy (the storage address does not change)."""
    var fds = Array[Int32, 2](fill=-1)
    _ = check(
        "socketpair",
        sys.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds),
    )
    var a = OwnedFd(unsafe_from_raw=fds[0])
    var b = OwnedFd(unsafe_from_raw=fds[1])
    var codec = LineCodec(max_line_length=32)
    var pool_buf = ByteBuffer(capacity=256)
    var addr = Int(pool_buf.readable_span().unsafe_ptr())
    for round in range(3):
        codec.send_line(String("line ", round).as_bytes())
        assert_equal(codec.poll_transmit(pool_buf), 7)
        pool_buf = SendOp(pool_buf^).complete(a)
        assert_equal(len(pool_buf), 0)
        assert_equal(Int(pool_buf.readable_span().unsafe_ptr()), addr)
    var got = ByteBuffer()
    while len(got) < 21:
        got.ensure_writable(64)
        var n = check("recv", sys.recv(b, got.writable_span(), 0))
        got.commit(n)
    assert_equal(_str(got.readable_span()), "line 0\nline 1\nline 2\n")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
