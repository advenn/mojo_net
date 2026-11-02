"""Regression tests for the 2026-11 analysis of the stack, for `tls`
(finding https-unmeasured-datapath; the HTTPS benchmark measured it).
Built with -D MOJO_NET_FAULTS=1, for the seam that counts wipes.

- Every decrypted record got a new `List` (a malloc and, when its reader
  swapped it in, a free per record). Now the reader gives the buffer back
  once it has read it (`recycle`, which wipes it, TB18), and the next
  record goes in it. Seen here through its capacity: after a 16 KB
  record's buffer is given back, a 100-byte record arrives in a buffer
  that holds 16 KB; and through the wipe seam, which counts one wipe for
  each buffer given back.
- The hot calls (BIO and SSL reads and writes) each allocated a one-Int
  out-parameter box per call; now there is one per engine. (No test sees
  an allocation; the data tests below go through every such call.)

`TlsClient` and `TlsServer` talk to each other in this process."""

from std.testing import TestSuite, assert_equal, assert_true

from bytes.buffer import ByteBuffer
from linux import fault
from tls import TlsClient, TlsEventKind, TlsServer
from tls.ffi import SEAM_WIPE
from tls_util import pattern, serving, trusting


struct Pair(Movable):
    var c: TlsClient
    var s: TlsServer
    var to_s: ByteBuffer
    var to_c: ByteBuffer

    def __init__(out self) raises:
        self.c = TlsClient(trusting(), "localhost")
        self.s = TlsServer(serving())
        self.to_s = ByteBuffer()
        self.to_c = ByteBuffer()

    def move(mut self) raises -> Int:
        """One round of bytes each way; how many moved."""
        var moved = self.c.poll_transmit(self.to_s) + self.s.poll_transmit(self.to_c)
        var n = min(len(self.to_s), self.s.feed_capacity())
        if n > 0:
            self.s.feed(self.to_s.readable_span()[0:n])
            self.to_s.consume(n)
            moved += n
        n = min(len(self.to_c), self.c.feed_capacity())
        if n > 0:
            self.c.feed(self.to_c.readable_span()[0:n])
            self.to_c.consume(n)
            moved += n
        return moved


def _established(mut p: Pair) raises:
    var c_ok = False
    var s_ok = False
    for _ in range(100):
        _ = p.move()
        while True:
            var ev = p.c.next_event()
            if not ev:
                break
            c_ok = c_ok or ev.value().kind == TlsEventKind.ESTABLISHED
        while True:
            var ev = p.s.next_event()
            if not ev:
                break
            s_ok = s_ok or ev.value().kind == TlsEventKind.ESTABLISHED
        if c_ok and s_ok:
            return
    raise Error("no handshake")


def _record(mut p: Pair, n: Int) raises -> List[UInt8]:
    """Send `n` bytes from the client; the server's DATA event's buffer
    (one record: n <= 16 KB)."""
    var data = pattern(n)
    assert_equal(p.c.write(Span(data)), n)
    for _ in range(100):
        _ = p.move()
        var ev = p.s.next_event()
        if ev and ev.value().kind == TlsEventKind.DATA:
            var got = List[UInt8]()
            swap(got, ev.value().data)
            assert_equal(len(got), n)
            for i in range(n):
                assert_equal(got[i], data[i], String("byte ", i))
            return got^
    raise Error("no DATA event")


def test_a_record_reuses_the_buffer_given_back() raises:
    fault.clear()
    var p = Pair()
    _established(p)
    var big = _record(p, 16000)
    assert_true(big.capacity() >= 16000)
    var wipes = fault.calls(SEAM_WIPE)
    p.s.recycle(big)
    assert_equal(fault.calls(SEAM_WIPE), wipes + 1, "the buffer given back was not wiped (TB18)")
    assert_equal(len(big), 0)  # (what the caller keeps: an empty buffer)
    var small = _record(p, 100)
    assert_true(small.capacity() >= 16000, String("a new buffer of ", small.capacity(), " bytes"))
    # Given back again, and again used: many records, one buffer.
    for _ in range(50):
        wipes = fault.calls(SEAM_WIPE)
        p.s.recycle(small)
        assert_equal(fault.calls(SEAM_WIPE), wipes + 1)
        small = _record(p, 1000)
        assert_true(small.capacity() >= 16000, String("a new buffer of ", small.capacity(), " bytes"))
    fault.clear()


def test_a_buffer_never_given_back_is_left_alone() raises:
    """A reader that keeps its buffers (any caller that does not call
    `recycle`) gets a fresh one each time, its own data untouched."""
    fault.clear()
    var p = Pair()
    _established(p)
    var first = _record(p, 2000)
    var second = _record(p, 3000)
    assert_equal(len(first), 2000)
    assert_equal(len(second), 3000)
    var want = pattern(2000)
    for i in range(2000):
        assert_equal(first[i], want[i])


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
