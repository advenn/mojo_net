"""F06 regression tests: ByteBuffer's span-invalidation check mode.

A span kept across a mutating call is stale, and Mojo 1.2 does not reject
it. In a normal build such a span usually still shows the right bytes (the
storage only moves when the buffer grows), so codec tests cannot see the
bug. Fault builds (this file is built with `-D MOJO_NET_FAULTS=1`) turn on
check mode: calls that may move bytes relocate the storage and poison the
old block, and calls that drop bytes poison them. This file checks that
the mode is on and does that, using only reads that stay inside live
storage, and that code following the rules (LineCodec, drive_chunked, the
recv-into-tail path) behaves exactly as in a normal build.
"""

from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_true,
)

from linux import OwnedFd, check, sys
from linux.consts import AF_UNIX, MSG_NOSIGNAL, SOCK_CLOEXEC, SOCK_STREAM
from bytes.buffer import CHECK_SPANS, POISON, ByteBuffer
from net.codec import LineCodec, drive_chunked, escape_bytes


def _str(data: Span[UInt8, _]) -> String:
    return String(unsafe_from_utf8=data)


def _addr(b: ByteBuffer) -> Int:
    """Address of the storage (the readable span starts at read index)."""
    return Int(b.readable_span().unsafe_ptr()) - b.read_index()


def render_line(line: List[UInt8]) -> String:
    return escape_bytes(Span(line))


def test_check_mode_is_on_in_fault_builds() raises:
    comptime assert CHECK_SPANS, "fault builds must enable span checks"
    assert_equal(Int(POISON), 0xDD)


def test_stale_span_after_consume_reads_poison() raises:
    """consume does not move storage, so the stale span stays inside live
    memory; check mode makes the dropped bytes visibly dead."""
    var b = ByteBuffer(capacity=64)
    b.write_bytes("abcdef".as_bytes())
    var s = b.readable_span()
    b.consume(3)
    for i in range(3):
        assert_equal(s[i], POISON)  # normal build: still 'a', 'b', 'c'
    assert_equal(_str(s[3:6]), "def")  # still readable, untouched
    assert_equal(_str(b.readable_span()), "def")
    # read_bytes consumes too.
    var t = b.readable_span()
    var got = b.read_bytes(2)
    assert_equal(_str(Span(got)), "de")
    assert_equal(t[0], POISON)
    assert_equal(t[1], POISON)
    # clear drops everything readable.
    var u = b.readable_span()
    b.clear()
    assert_equal(u[0], POISON)


def test_every_moving_call_relocates_even_with_room() raises:
    """A normal build moves storage only on growth; check mode moves it on
    every call that may move bytes, so a stale span is caught every time
    (ASAN: heap-use-after-free) instead of only on growth. Indices and
    contents never change."""
    var b = ByteBuffer(capacity=64)
    b.write_bytes("0123456789".as_bytes())
    b.consume(2)

    var before = _addr(b)
    b.ensure_writable(1)  # plenty of room: a normal build does nothing
    assert_true(_addr(b) != before)
    assert_equal(b.capacity(), 64)
    assert_equal(b.read_index(), 2)
    assert_equal(_str(b.readable_span()), "23456789")

    before = _addr(b)
    b.write_byte(UInt8(ord("A")))
    assert_true(_addr(b) != before)

    before = _addr(b)
    b.write_bytes("BC".as_bytes())
    assert_true(_addr(b) != before)

    before = _addr(b)
    var w = b.writable_span()
    w[0] = UInt8(ord("D"))
    b.commit(1)
    assert_true(_addr(b) != before)

    before = _addr(b)
    _ = b.compact()  # declines (8 readable bytes > 2 consumed): still moves
    assert_true(_addr(b) != before)
    assert_equal(b.read_index(), 2)

    before = _addr(b)
    assert_equal(b.discard_read_bytes(), 2)
    assert_true(_addr(b) != before)

    before = _addr(b)
    b.shrink_to(1000)  # no-op size-wise
    assert_true(_addr(b) != before)
    assert_equal(b.capacity(), 64)

    assert_equal(_str(b.readable_span()), "23456789ABCD")
    assert_equal(b.read_index(), 0)


def test_uncommitted_tail_reads_poison() raises:
    """After a relocation the writable tail is poison, so committing bytes
    that were never written shows up."""
    var b = ByteBuffer(capacity=16)
    b.write_bytes("x".as_bytes())
    b.ensure_writable(4)
    var w = b.writable_span()
    for i in range(len(w)):
        assert_equal(w[i], POISON)
    b.commit(2)  # a recv that "returned 2" without writing anything
    assert_equal(b.byte_at(1), POISON)
    assert_equal(b.byte_at(2), POISON)


def test_codec_follows_the_span_rule() raises:
    """LineCodec in check mode: a span held across feed/consume would show
    POISON or garbage in the transcript."""
    var proto = LineCodec(max_line_length=8, max_buffered=16)
    var input = String("ab\r\ncd\n\nefgh\r\nij")
    var got = drive_chunked[render_line](
        proto,
        input.as_bytes(),
        seed=0x5A,
        random_rounds=30,
        max_pair_len=0,
    )
    assert_equal(len(got), 5)
    assert_equal(got[0], "ab")
    assert_equal(got[1], "cd")
    assert_equal(got[2], "")
    assert_equal(got[3], "efgh")
    assert_equal(got[4], "error UnexpectedEof")
    # Longer than the buffer: fed in pieces of feed_capacity().
    var many = String("abc\n" * 12)
    got = drive_chunked[render_line](
        proto, many.as_bytes(), seed=0x5B, random_rounds=10, max_pair_len=0
    )
    assert_equal(len(got), 12)
    for i in range(12):
        assert_equal(got[i], "abc")


def test_transmit_and_recv_into_tail_in_check_mode() raises:
    """The documented I/O patterns (span taken right before the syscall)
    stay correct when every call relocates."""
    var fds = Array[Int32, 2](fill=-1)
    _ = check(
        "socketpair",
        sys.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds),
    )
    var a = OwnedFd(unsafe_from_raw=fds[0])
    var b = OwnedFd(unsafe_from_raw=fds[1])
    var tx = LineCodec(max_line_length=16, crlf=True)
    for i in range(20):
        tx.send_line(String("m", i).as_bytes())
    var out = ByteBuffer()
    _ = tx.poll_transmit(out)
    while len(out) > 0:
        var n = check("send", sys.send(a, out.readable_span(), MSG_NOSIGNAL))
        out.consume(n)
    _ = check("shutdown", sys.shutdown(a, 1))
    var rx = LineCodec(max_line_length=16, max_buffered=24)
    var inbuf = ByteBuffer()
    var got = List[String]()
    while True:
        inbuf.ensure_writable(5)
        var w = inbuf.writable_span()
        var n = check("recv", sys.recv(b, w[0:5], 0))
        if n == 0:
            rx.feed_eof()
            break
        inbuf.commit(n)
        rx.feed(inbuf.readable_span())
        inbuf.clear()
        while True:
            var ev = rx.next_event()
            if not ev:
                break
            got.append(escape_bytes(Span(ev.value())))
    assert_false(Bool(rx.next_event()))
    assert_equal(len(got), 20)
    for i in range(20):
        assert_equal(got[i], String("m", i))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
