"""Regression tests for the second bytes review.

- B1: a `ByteBuffer` at its cap, drained and refilled in small pieces,
  compacted on every refill: each memmoved nearly the whole buffer to
  reclaim a byte (288 µs a byte at a 4 MiB cap). It now grows once to twice
  the cap, after which compaction reclaims more than it moves; the readable
  bytes still never pass the cap.
"""

from std.testing import TestSuite, assert_equal, assert_true
from std.time import perf_counter_ns

from bytes import ByteBuffer
from linux import ErrorKind


def _fill(mut b: ByteBuffer, n: Int, start: Int) raises:
    """Append `n` bytes of the sequence 0, 1, ..., 250, 0, ... from `start`."""
    for i in range(n):
        b.write_byte(UInt8((start + i) % 251))


def test_b1_a_full_buffer_drained_in_small_pieces_stays_cheap() raises:
    comptime CAP = 1 << 20
    comptime ROUNDS = 20_000
    var b = ByteBuffer(max_size=CAP)
    _fill(b, CAP, 0)
    assert_equal(b.max_writable(), 0)
    var next_in = CAP
    var next_out = 0
    var t0 = perf_counter_ns()
    for _ in range(ROUNDS):
        assert_equal(Int(b.byte_at(0)), next_out % 251)
        b.consume(1)
        next_out += 1
        b.write_byte(UInt8(next_in % 251))
        next_in += 1
    var took = perf_counter_ns() - t0
    # Each round used to memmove the whole megabyte (0.6 s or more for all).
    assert_true(took < 100_000_000, String("20k rounds took ", took // 1_000_000, " ms"))
    assert_equal(b.capacity(), 2 * CAP)
    assert_equal(len(b), CAP)
    assert_equal(b.max_writable(), 0)
    # Every byte is still there, in order.
    var span = b.readable_span()
    for i in range(len(span)):
        if Int(span[i]) != (next_out + i) % 251:
            assert_equal(Int(span[i]), (next_out + i) % 251, String("byte ", i))


def test_b1_the_readable_bytes_never_pass_the_cap() raises:
    var b = ByteBuffer(max_size=1000)
    _fill(b, 1000, 0)
    b.consume(1)
    b.write_byte(1)  # (grows the storage to 2000)
    assert_equal(b.capacity(), 2000)
    var refused = False
    try:
        b.write_byte(2)
    except e:
        refused = e.kind == ErrorKind.OutOfMemory
    assert_true(refused)
    assert_equal(len(b), 1000)
    # A buffer that never sits at its cap never grows past it.
    var c = ByteBuffer(max_size=1000)
    for _ in range(50):
        _fill(c, 900, 0)
        c.consume(900)
    assert_true(c.capacity() <= 1000)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
