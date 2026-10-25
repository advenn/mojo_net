"""ByteBuffer: indices, growth/compaction policy, the hard cap, search and
`read_until`, plus a randomized model check against a plain List and a real
kernel `recv` straight into the writable tail."""

from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_true,
)

from linux import ErrorKind, IoError, OwnedFd, check, sys
from linux.consts import AF_UNIX, MSG_NOSIGNAL, SOCK_CLOEXEC, SOCK_STREAM
from bytes.buffer import DEFAULT_MAX_SIZE, MIN_GROWTH, ByteBuffer


# ---- helpers -----------------------------------------------------------------


def _bytes(s: StringSlice) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def _str(data: Span[UInt8, _]) -> String:
    return String(unsafe_from_utf8=data)


def _assert_content(b: ByteBuffer, expected: StringSlice) raises:
    assert_equal(_str(b.readable_span()), String(expected))
    assert_equal(len(b), expected.byte_length())


def _c(s: StringSlice) -> UInt8:
    return UInt8(ord(s))


def _empty() -> List[UInt8]:
    return List[UInt8]()


def _filled(n: Int, byte: UInt8) -> List[UInt8]:
    return List[UInt8](length=n, fill=byte)


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


def _kind_of_ensure(mut b: ByteBuffer, n: Int) -> ErrorKind:
    try:
        b.ensure_writable(n)
    except e:
        return e.kind
    return ErrorKind.Other


def _kind_of_write(mut b: ByteBuffer, data: Span[UInt8, _]) -> ErrorKind:
    try:
        b.write_bytes(data)
    except e:
        return e.kind
    return ErrorKind.Other


def _kind_of_consume(mut b: ByteBuffer, n: Int) -> ErrorKind:
    try:
        b.consume(n)
    except e:
        return e.kind
    return ErrorKind.Other


def _kind_of_commit(mut b: ByteBuffer, n: Int) -> ErrorKind:
    try:
        b.commit(n)
    except e:
        return e.kind
    return ErrorKind.Other


def _kind_of_read_bytes(mut b: ByteBuffer, n: Int) -> ErrorKind:
    try:
        _ = b.read_bytes(n)
    except e:
        return e.kind
    return ErrorKind.Other


def _read_until_kind(b: ByteBuffer, d: UInt8, max_bytes: Int) -> String:
    """`"<n>"`, `"none"` or `"error <kind> <op>"`."""
    try:
        var r = b.read_until(d, max_bytes)
        if r:
            return String(r.value())
        return "none"
    except e:
        return String("error ", e.kind, " ", e.op)


def _read_until_kind(
    b: ByteBuffer, d: Span[UInt8, _], max_bytes: Int, start: Int = 0
) -> String:
    try:
        var r = b.read_until(d, max_bytes, start)
        if r:
            return String(r.value())
        return "none"
    except e:
        return String("error ", e.kind, " ", e.op)


# ---- construction and sizes --------------------------------------------------


def test_default_is_empty_and_unallocated() raises:
    var b = ByteBuffer()
    assert_equal(len(b), 0)
    assert_true(b.is_empty())
    assert_equal(b.capacity(), 0)
    assert_equal(b.writable(), 0)
    assert_equal(b.max_size(), DEFAULT_MAX_SIZE)
    assert_equal(b.max_writable(), DEFAULT_MAX_SIZE)
    assert_equal(len(b.readable_span()), 0)
    assert_equal(len(b.writable_span()), 0)
    assert_equal(
        String(b),
        "ByteBuffer(readable=0, read_index=0, capacity=0, max_size=67108864)",
    )


def test_init_validation() raises:
    var b = ByteBuffer(capacity=16, max_size=32)
    assert_equal(b.capacity(), 16)
    assert_equal(b.writable(), 16)
    assert_equal(b.max_size(), 32)
    var z = ByteBuffer(capacity=0, max_size=1)
    assert_equal(z.capacity(), 0)
    var bad: List[Tuple[Int, Int]] = [(-1, 10), (11, 10), (0, 0), (0, -5)]
    for i in range(len(bad)):
        var kind = ErrorKind.Other
        try:
            _ = ByteBuffer(capacity=bad[i][0], max_size=bad[i][1])
        except e:
            kind = e.kind
            assert_equal(String(e.op), "ByteBuffer.__init__")
        assert_equal(kind, ErrorKind.InvalidInput)
    var kind = ErrorKind.Other
    try:
        _ = ByteBuffer(max_size=0)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)


def test_negative_arguments_are_invalid_input() raises:
    var b = ByteBuffer()
    b.write_bytes("abc".as_bytes())
    assert_equal(_kind_of_ensure(b, -1), ErrorKind.InvalidInput)
    assert_equal(_kind_of_commit(b, -1), ErrorKind.InvalidInput)
    assert_equal(_kind_of_consume(b, -1), ErrorKind.InvalidInput)
    assert_equal(_kind_of_read_bytes(b, -1), ErrorKind.InvalidInput)
    _assert_content(b, "abc")


# ---- writing, reading, consuming ---------------------------------------------


def test_write_read_round_trip() raises:
    var b = ByteBuffer()
    b.write_bytes("hello ".as_bytes())
    b.write_byte(_c("w"))
    b.write_bytes("orld".as_bytes())
    b.write_bytes(Span(_empty()))  # empty write: no-op
    _assert_content(b, "hello world")
    var head = b.read_bytes(6)
    assert_equal(_str(Span(head)), "hello ")
    _assert_content(b, "world")
    assert_equal(b.read_index(), 6)
    var none = b.read_bytes(0)
    assert_equal(len(none), 0)
    var rest = b.read_bytes(5)
    assert_equal(_str(Span(rest)), "world")
    assert_true(b.is_empty())
    # Draining resets the indices: the whole capacity is writable again.
    assert_equal(b.read_index(), 0)
    assert_equal(b.writable(), b.capacity())


def test_consume_beyond_readable_raises_and_leaves_buffer_intact() raises:
    var b = ByteBuffer()
    b.write_bytes("12345".as_bytes())
    assert_equal(_kind_of_consume(b, 6), ErrorKind.InvalidInput)
    assert_equal(_kind_of_read_bytes(b, 6), ErrorKind.InvalidInput)
    _assert_content(b, "12345")
    b.consume(2)
    _assert_content(b, "345")
    assert_equal(_kind_of_consume(b, 4), ErrorKind.InvalidInput)
    b.consume(0)
    _assert_content(b, "345")
    b.consume(3)
    assert_true(b.is_empty())
    assert_equal(b.read_index(), 0)
    assert_equal(_kind_of_consume(b, 1), ErrorKind.InvalidInput)
    var kind = ErrorKind.Other
    try:
        b.consume(1)
    except e:
        kind = e.kind
        assert_equal(String(e.op), "ByteBuffer.consume")
    assert_equal(kind, ErrorKind.InvalidInput)


def test_commit_bounds() raises:
    var b = ByteBuffer(capacity=8)
    var w = b.writable_span()
    w[0] = _c("x")
    w[1] = _c("y")
    b.commit(2)
    _assert_content(b, "xy")
    assert_equal(b.writable(), 6)
    assert_equal(_kind_of_commit(b, 7), ErrorKind.InvalidInput)
    _assert_content(b, "xy")
    b.commit(0)
    b.commit(6)
    assert_equal(b.writable(), 0)
    assert_equal(_kind_of_commit(b, 1), ErrorKind.InvalidInput)
    assert_equal(len(b), 8)


def test_recv_straight_into_writable_tail() raises:
    """The zero-copy input path: kernel writes into `writable_span()`."""
    var fds = Array[Int32, 2](fill=-1)
    _ = check(
        "socketpair",
        sys.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds),
    )
    var a = OwnedFd(unsafe_from_raw=fds[0])
    var c = OwnedFd(unsafe_from_raw=fds[1])
    var b = ByteBuffer()
    b.write_bytes("pre:".as_bytes())
    b.consume(1)  # read index != 0, so the tail is not at offset 0
    var msg = "kernel bytes".as_bytes()
    assert_equal(check("send", sys.send(a, msg, MSG_NOSIGNAL)), len(msg))
    b.ensure_writable(64)
    assert_true(b.writable() >= 64)
    var got = check("recv", sys.recv(c, b.writable_span(), 0))
    b.commit(got)
    _assert_content(b, "re:kernel bytes")


# ---- growth, compaction, the cap ---------------------------------------------


def test_growth_is_amortized_and_preserves_content() raises:
    var b = ByteBuffer()
    var model = List[UInt8]()
    var reallocs = 0
    var cap = b.capacity()
    for i in range(20_000):
        var v = UInt8(i % 251)
        b.write_byte(v)
        model.append(v)
        if b.capacity() != cap:
            reallocs += 1
            # At least doubling (or the minimum first allocation).
            assert_true(b.capacity() >= max(2 * cap, MIN_GROWTH))
            cap = b.capacity()
    assert_true(reallocs <= 8)  # 256 -> 32768 is 8 allocations
    assert_true(b.capacity() < 2 * len(b) + MIN_GROWTH)
    var s = b.readable_span()
    for i in range(len(model)):
        if s[i] != model[i]:
            raise Error("content mismatch at ", i)


def test_growth_drops_consumed_prefix() raises:
    var b = ByteBuffer()
    var src = List[UInt8]()
    for i in range(200):
        src.append(UInt8(i))
    b.write_bytes(Span(src))
    b.consume(150)
    var cap = b.capacity()
    b.ensure_writable(1000)
    assert_true(b.capacity() > cap)
    assert_equal(b.read_index(), 0)
    assert_equal(len(b), 50)
    assert_true(b.writable() >= 1000)
    var s = b.readable_span()
    for i in range(50):
        assert_equal(Int(s[i]), 150 + i)


def test_ensure_writable_compacts_when_worthwhile() raises:
    var b = ByteBuffer(capacity=256)
    var data = _filled(256, 7)
    data[200] = 42
    b.write_bytes(Span(data))
    b.consume(200)  # 56 readable, 200 reclaimable: moving 56 is cheap
    b.ensure_writable(100)
    assert_equal(b.capacity(), 256)  # compacted, not grown
    assert_equal(b.read_index(), 0)
    assert_equal(len(b), 56)
    assert_equal(Int(b.readable_span()[0]), 42)
    assert_equal(b.writable(), 200)


def test_ensure_writable_grows_instead_of_costly_compaction() raises:
    var b = ByteBuffer(capacity=256)
    b.write_bytes(Span(_filled(256, 1)))
    b.consume(10)  # 246 readable, 10 reclaimable: compaction not worth it
    b.ensure_writable(5)
    assert_equal(b.capacity(), 512)
    assert_equal(b.read_index(), 0)
    assert_equal(len(b), 246)


def test_at_max_size_a_costly_compaction_grows_once_instead() raises:
    var b = ByteBuffer(capacity=256, max_size=256)
    var data = List[UInt8]()
    for i in range(256):
        data.append(UInt8(i))
    b.write_bytes(Span(data))
    b.consume(10)
    # Compacting would move 246 bytes to reclaim 10: it grows once to twice
    # the cap instead (the module docs' exception), keeping the cap on what
    # is readable.
    b.ensure_writable(5)
    assert_equal(b.capacity(), 512)
    assert_equal(b.read_index(), 0)
    assert_equal(Int(b.readable_span()[0]), 10)
    assert_equal(b.writable(), 10)
    # A cheap compaction at the cap still compacts.
    var c = ByteBuffer(capacity=256, max_size=256)
    c.write_bytes(Span(data))
    c.consume(200)
    c.ensure_writable(100)
    assert_equal(c.capacity(), 256)
    assert_equal(c.read_index(), 0)
    assert_equal(b.writable(), 10)
    b.ensure_writable(10)  # exactly fits
    assert_equal(_kind_of_ensure(b, 11), ErrorKind.OutOfMemory)
    assert_equal(len(b), 246)
    assert_equal(Int(b.readable_span()[245]), 255)


def test_max_size_is_a_hard_cap() raises:
    var b = ByteBuffer(max_size=100)
    b.write_bytes(Span(_filled(60, 1)))
    b.write_bytes(Span(_filled(40, 2)))
    assert_equal(len(b), 100)
    assert_true(b.capacity() <= 100)
    assert_equal(b.max_writable(), 0)
    # Failed writes leave the buffer untouched.
    assert_equal(_kind_of_write(b, Span(_filled(1, 3))), ErrorKind.OutOfMemory)
    assert_equal(len(b), 100)
    var kind = ErrorKind.Other
    try:
        b.write_byte(3)
    except e:
        kind = e.kind
        assert_equal(String(e.op), "ByteBuffer.ensure_writable")
    assert_equal(kind, ErrorKind.OutOfMemory)
    # No overflow on absurd requests.
    assert_equal(_kind_of_ensure(b, Int.MAX), ErrorKind.OutOfMemory)
    # Consuming frees room under the cap.
    b.consume(1)
    assert_equal(b.max_writable(), 1)
    b.write_byte(3)
    assert_equal(len(b), 100)
    assert_equal(Int(b.readable_span()[99]), 3)
    assert_equal(Int(b.readable_span()[0]), 1)
    assert_equal(Int(b.readable_span()[59]), 2)
    # A single write larger than the cap fails up front.
    var c = ByteBuffer(max_size=10)
    assert_equal(_kind_of_write(c, Span(_filled(11, 0))), ErrorKind.OutOfMemory)
    assert_equal(c.capacity(), 0)


def test_compact_and_discard_read_bytes() raises:
    var b = ByteBuffer()
    b.write_bytes("0123456789".as_bytes())
    assert_false(b.compact())  # nothing consumed
    b.consume(3)  # 7 readable > 3 reclaimed: not worthwhile
    assert_false(b.compact())
    assert_equal(b.read_index(), 3)
    b.consume(2)  # 5 readable <= 5 reclaimed
    assert_true(b.compact())
    assert_equal(b.read_index(), 0)
    _assert_content(b, "56789")
    b.consume(1)
    assert_equal(b.discard_read_bytes(), 1)
    assert_equal(b.read_index(), 0)
    _assert_content(b, "6789")
    assert_equal(b.discard_read_bytes(), 0)
    _assert_content(b, "6789")


def test_clear_keeps_capacity() raises:
    var b = ByteBuffer()
    b.write_bytes(Span(_filled(1000, 9)))
    b.consume(10)
    var cap = b.capacity()
    b.clear()
    assert_true(b.is_empty())
    assert_equal(b.capacity(), cap)
    assert_equal(b.read_index(), 0)
    assert_equal(b.writable(), cap)


def test_shrink_to() raises:
    var b = ByteBuffer()
    b.write_bytes(Span(_filled(5000, 1)))
    b.consume(4990)
    b.shrink_to(64)
    assert_equal(b.capacity(), 64)
    assert_equal(len(b), 10)
    assert_equal(b.read_index(), 0)
    b.shrink_to(0)  # never below readable()
    assert_equal(b.capacity(), 10)
    b.shrink_to(-3)
    assert_equal(b.capacity(), 10)
    b.shrink_to(1000)  # larger than current: no-op
    assert_equal(b.capacity(), 10)
    assert_equal(Int(b.readable_span()[9]), 1)


def test_copy_is_independent() raises:
    var a = ByteBuffer()
    a.write_bytes("shared".as_bytes())
    a.consume(1)
    var b = a.copy()
    a.write_bytes("!".as_bytes())
    b.consume(2)
    _assert_content(a, "hared!")
    _assert_content(b, "red")


# ---- find --------------------------------------------------------------------


def test_find_byte_at_every_position_across_simd_blocks() raises:
    # Positions on both sides of the 32-byte scan blocks, with a non-zero
    # read index so absolute and relative offsets differ.
    for read_off in range(0, 5):
        for pos in range(0, 130):
            var b = ByteBuffer()
            b.write_bytes(Span(_filled(read_off, _c("x"))))
            var data = _filled(130, _c("a"))
            data[pos] = _c("x")
            b.write_bytes(Span(data))
            b.consume(read_off)
            var f = b.find(_c("x"))
            assert_true(Bool(f))
            assert_equal(f.value(), pos)
            # Searching after the only match finds nothing.
            assert_false(Bool(b.find(_c("x"), pos + 1)))
            # The match itself is found from start == pos.
            assert_equal(b.find(_c("x"), pos).value(), pos)


def test_find_byte_edges() raises:
    var b = ByteBuffer()
    assert_false(Bool(b.find(0)))
    b.write_bytes("abcabc".as_bytes())
    assert_equal(b.find(_c("c")).value(), 2)
    assert_equal(b.find(_c("c"), 3).value(), 5)
    assert_equal(b.find(_c("a"), -10).value(), 0)  # clamped
    assert_false(Bool(b.find(_c("a"), 6)))
    assert_false(Bool(b.find(_c("a"), 1000)))
    assert_false(Bool(b.find(_c("z"))))
    b.consume(1)
    assert_equal(b.find(_c("a")).value(), 2)  # relative to read index
    # Bytes in the writable tail are never matched.
    var c = ByteBuffer(capacity=64)
    var w = c.writable_span()
    for i in range(len(w)):
        w[i] = _c("q")
    c.commit(3)
    w = c.writable_span()  # re-take after the mutating call
    assert_equal(len(w), 61)
    assert_false(Bool(c.find(_c("x"))))
    assert_equal(c.find(_c("q"), 2).value(), 2)
    assert_false(Bool(c.find(_c("q"), 3)))


def test_find_pattern() raises:
    var b = ByteBuffer()
    b.write_bytes("GET / HTTP/1.1\r\nHost: x\r\n\r\nbody".as_bytes())
    assert_equal(b.find("\r\n\r\n".as_bytes()).value(), 23)
    assert_equal(b.find("\r\n".as_bytes()).value(), 14)
    assert_equal(b.find("\r\n".as_bytes(), 15).value(), 23)
    assert_equal(b.find("body".as_bytes()).value(), 27)
    assert_false(Bool(b.find("body!".as_bytes())))
    assert_false(Bool(b.find("\r\n\r\n\r\n".as_bytes())))
    # Empty pattern matches at (clamped) start.
    assert_equal(b.find(Span(_empty()), 5).value(), 5)
    assert_equal(b.find(Span(_empty()), 999).value(), len(b))
    # Overlapping candidates: the first-byte scan must restart correctly.
    var c = ByteBuffer()
    c.write_bytes("aaaab".as_bytes())
    assert_equal(c.find("aab".as_bytes()).value(), 2)
    assert_equal(c.find("aaaab".as_bytes()).value(), 0)
    assert_false(Bool(c.find("aaaaab".as_bytes())))
    c.consume(1)
    assert_equal(c.find("aab".as_bytes()).value(), 1)
    assert_false(Bool(c.find("aaaab".as_bytes())))


def _naive_find(
    hay: List[UInt8], pat: List[UInt8], start: Int
) -> Optional[Int]:
    var n = len(hay)
    var m = len(pat)
    var s = min(max(start, 0), n)
    for i in range(s, n - m + 1):
        var ok = True
        for k in range(m):
            if hay[i + k] != pat[k]:
                ok = False
                break
        if ok:
            return i
    return None


def test_find_matches_brute_force_oracle() raises:
    var rng = Rng(0xF1AD)
    for _ in range(5000):
        var n = rng.below(150)
        var hay = List[UInt8]()
        for _ in range(n):
            hay.append(UInt8(97 + rng.below(3)))  # tiny alphabet: many hits
        var pat = List[UInt8]()
        for _ in range(1 + rng.below(4)):
            pat.append(UInt8(97 + rng.below(3)))
        var lead = rng.below(40)
        var b = ByteBuffer()
        b.write_bytes(Span(_filled(lead, 97)))
        b.write_bytes(Span(hay))
        b.consume(lead)
        var start = rng.below(n + 3) - 1
        var want = _naive_find(hay, pat, start)
        var got = b.find(Span(pat), start)
        assert_equal(Bool(got), Bool(want))
        if want:
            assert_equal(got.value(), want.value())
        # Single-byte search agrees with the same oracle.
        var one: List[UInt8] = [pat[0]]
        var want1 = _naive_find(hay, one, start)
        var got1 = b.find(pat[0], start)
        assert_equal(Bool(got1), Bool(want1))
        if want1:
            assert_equal(got1.value(), want1.value())


# ---- read_until --------------------------------------------------------------


def test_read_until_single_byte_limits() raises:
    var b = ByteBuffer()
    b.write_bytes("abc\ndef".as_bytes())
    assert_equal(_read_until_kind(b, 10, 100), "4")
    assert_equal(_read_until_kind(b, 10, 4), "4")  # frame == limit: ok
    assert_equal(
        _read_until_kind(b, 10, 3),
        "error InvalidData ByteBuffer.read_until(max_bytes)",
    )
    b.consume(4)
    assert_equal(_read_until_kind(b, 10, 100), "none")
    assert_equal(_read_until_kind(b, 10, 4), "none")  # "def" + LF could fit
    assert_equal(
        _read_until_kind(b, 10, 3),  # 3 bytes, no LF: can only exceed 3
        "error InvalidData ByteBuffer.read_until(max_bytes)",
    )
    assert_equal(
        _read_until_kind(b, 10, 0), "error InvalidInput ByteBuffer.read_until"
    )
    assert_equal(
        _read_until_kind(b, 10, -1), "error InvalidInput ByteBuffer.read_until"
    )
    # Delimiter as the very first byte: a 1-byte frame.
    var c = ByteBuffer()
    c.write_bytes("\nx".as_bytes())
    assert_equal(_read_until_kind(c, 10, 1), "1")
    # Empty buffer.
    var e = ByteBuffer()
    assert_equal(_read_until_kind(e, 10, 1), "none")


def test_read_until_multi_byte_delimiter() raises:
    var crlf = "\r\n".as_bytes()
    var b = ByteBuffer()
    b.write_bytes("abc\r".as_bytes())
    assert_equal(_read_until_kind(b, crlf, 100), "none")
    assert_equal(_read_until_kind(b, crlf, 5), "none")  # "\n" next: 5 fits
    assert_equal(
        _read_until_kind(b, crlf, 4),
        "error InvalidData ByteBuffer.read_until(max_bytes)",
    )
    # Resume where a straddling delimiter could start.
    var resume = max(0, len(b) - len(crlf) + 1)
    b.write_bytes("\nrest".as_bytes())
    assert_equal(_read_until_kind(b, crlf, 100, resume), "5")
    assert_equal(_read_until_kind(b, crlf, 5), "5")
    assert_equal(
        _read_until_kind(b, crlf, 4),
        "error InvalidData ByteBuffer.read_until(max_bytes)",
    )
    assert_equal(
        _read_until_kind(b, Span(_empty()), 10),
        "error InvalidInput ByteBuffer.read_until",
    )
    assert_equal(
        _read_until_kind(b, crlf, 1), "error InvalidInput ByteBuffer.read_until"
    )


def test_read_until_across_growth() raises:
    """A frame arriving in growing pieces while the buffer reallocates
    underneath; the resumable `start` offset stays valid throughout."""
    var b = ByteBuffer(capacity=8)
    var frame = List[UInt8]()
    for i in range(3000):
        frame.append(UInt8(65 + i % 26))
    frame.append(_c("\n"))
    # A previous frame in front, consumed, so the read index is not 0.
    b.write_bytes("old\n".as_bytes())
    b.write_bytes(Span(frame)[0:1])
    assert_equal(b.read_until(UInt8(_c("\n")), 4000).value(), 4)
    b.consume(4)
    assert_equal(b.read_index(), 4)
    var start = 0
    var reallocs = 0
    var pos = 1
    var step = 1
    while pos < len(frame):
        var r = b.read_until(UInt8(_c("\n")), 4000, start)
        assert_false(Bool(r))
        start = len(b)
        var end = min(len(frame), pos + step)
        var cap = b.capacity()
        b.write_bytes(Span(frame)[pos:end])
        if b.capacity() != cap:
            reallocs += 1
        pos = end
        step = step * 2 + 1
    assert_true(reallocs >= 3)
    assert_equal(b.read_until(UInt8(_c("\n")), 4000, start).value(), len(frame))
    # Same answer without the resume hint, and the limit still applies.
    assert_equal(b.read_until(UInt8(_c("\n")), len(frame)).value(), len(frame))
    assert_equal(
        _read_until_kind(b, _c("\n"), len(frame) - 1),
        "error InvalidData ByteBuffer.read_until(max_bytes)",
    )
    var got = b.read_bytes(len(frame))
    for i in range(len(frame)):
        assert_equal(got[i], frame[i])
    assert_true(b.is_empty())


# ---- randomized model check ----------------------------------------------------


def test_random_operations_match_list_model() raises:
    """Random mix of every mutating call against a List model, with a small
    cap so OutOfMemory paths are hit often."""
    var rng = Rng(0xB0FF)
    var b = ByteBuffer(max_size=300)
    var model = List[UInt8]()
    var counter = 0
    var oom = 0
    for step in range(30_000):
        var op = rng.below(9)
        if op <= 2:  # write
            var n = rng.below(80)
            var data = List[UInt8]()
            for _ in range(n):
                data.append(UInt8(counter % 256))
                counter += 1
            var fits = len(model) + n <= 300
            var kind = _kind_of_write(b, Span(data))
            if fits:
                assert_equal(kind, ErrorKind.Other)
                for i in range(n):
                    model.append(data[i])
            else:
                assert_equal(kind, ErrorKind.OutOfMemory)
                counter -= n
                oom += 1
        elif op == 3:  # direct write + commit
            var n = rng.below(50)
            var fits = len(model) + n <= 300
            var kind = _kind_of_ensure(b, n)
            if fits:
                assert_equal(kind, ErrorKind.Other)
                var k = rng.below(n + 1)
                var w = b.writable_span()
                for i in range(k):
                    w[i] = UInt8(counter % 256)
                    model.append(UInt8(counter % 256))
                    counter += 1
                b.commit(k)
            else:
                assert_equal(kind, ErrorKind.OutOfMemory)
        elif op <= 5:  # consume / read_bytes
            var n = rng.below(len(model) + 3)
            if n <= len(model):
                if op == 4:
                    b.consume(n)
                else:
                    var got = b.read_bytes(n)
                    for i in range(n):
                        if got[i] != model[i]:
                            raise Error("step ", step, ": read_bytes ", i)
                var rest = List[UInt8]()
                for i in range(n, len(model)):
                    rest.append(model[i])
                model = rest^
            else:
                assert_equal(_kind_of_consume(b, n), ErrorKind.InvalidInput)
        elif op == 6:
            _ = b.compact()
        elif op == 7:
            if rng.below(10) == 0:
                b.clear()
                model.clear()
            else:
                _ = b.discard_read_bytes()
        else:
            b.shrink_to(rng.below(200))
        # Invariants after every step.
        assert_equal(len(b), len(model))
        assert_true(b.capacity() <= 600)
        assert_equal(b.writable(), min(b.capacity() - b.read_index() - len(b), 300 - len(b)))
        var s = b.readable_span()
        for i in range(len(model)):
            if s[i] != model[i]:
                raise Error("step ", step, ": byte ", i, " differs")
    assert_true(oom > 500)  # the cap was really exercised


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
