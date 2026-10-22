"""TimerHeap unit tests: deadline order, FIFO ties, a randomized comparison
with a sorted reference, and compaction (`take_entries` + `rebuild`)."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from rt.timers import TimerEntry, TimerHeap


struct Rng:
    """Xorshift64*: deterministic, so a failure replays."""

    var s: UInt64

    def __init__(out self, seed: UInt64):
        self.s = seed | 1

    def next(mut self) -> UInt64:
        self.s ^= self.s >> 12
        self.s ^= self.s << 25
        self.s ^= self.s >> 27
        return self.s * 0x2545F4914F6CDD1D

    def below(mut self, n: Int) -> Int:
        return Int(self.next() % UInt64(n))


def _pop_all(mut h: TimerHeap) -> List[TimerEntry]:
    var out = List[TimerEntry]()
    while len(h) > 0:
        out.append(h.pop())
    return out^


def _sorted_ok(entries: List[TimerEntry]) -> Bool:
    for i in range(1, len(entries)):
        if entries[i].before(entries[i - 1]):
            return False
    return True


def test_empty_heap() raises:
    var h = TimerHeap()
    assert_equal(len(h), 0)
    assert_false(Bool(h.peek()))
    h.rebuild(h.take_entries())
    assert_equal(len(h), 0)


def test_pops_in_deadline_order() raises:
    var h = TimerHeap()
    var ds = [50, 10, 40, 20, 30, 0, -5, 100]
    for i in range(len(ds)):
        h.push(ds[i], UInt64(i))
    assert_equal(h.peek().value().deadline_ns, -5)
    var got = _pop_all(h)
    var want = [-5, 0, 10, 20, 30, 40, 50, 100]
    assert_equal(len(got), len(want))
    for i in range(len(want)):
        assert_equal(got[i].deadline_ns, want[i])


def test_equal_deadlines_pop_in_push_order() raises:
    var h = TimerHeap()
    for i in range(100):
        h.push(7 if i % 2 == 0 else 3, UInt64(i))
    var got = _pop_all(h)
    # First every odd op (deadline 3) in push order, then every even one.
    var k = 0
    for i in range(1, 100, 2):
        assert_equal(got[k].op, UInt64(i))
        k += 1
    for i in range(0, 100, 2):
        assert_equal(got[k].op, UInt64(i))
        k += 1


def test_randomized_against_sorted_reference() raises:
    var rng = Rng(0x5EED)
    var h = TimerHeap()
    var ref_list = List[TimerEntry]()  # kept sorted by (deadline, seq)
    var seq: UInt64 = 0
    for step in range(20_000):
        if rng.below(3) != 0 or len(ref_list) == 0:
            # Few distinct deadlines, so ties are common.
            var d = rng.below(64) * 1000
            var op = UInt64(step)
            h.push(d, op)
            seq += 1
            var e = TimerEntry(d, seq, op)
            var at = len(ref_list)
            while at > 0 and e.before(ref_list[at - 1]):
                at -= 1
            ref_list.insert(at, e)
        else:
            var top = h.peek().value()
            var got = h.pop()
            var want = ref_list.pop(0)
            assert_equal(top.op, got.op)
            assert_equal(got.deadline_ns, want.deadline_ns)
            assert_equal(got.op, want.op)
        assert_equal(len(h), len(ref_list))
    var rest = _pop_all(h)
    assert_equal(len(rest), len(ref_list))
    for i in range(len(rest)):
        assert_equal(rest[i].op, ref_list[i].op)


def test_rebuild_after_filtering_keeps_order_and_ties() raises:
    var rng = Rng(42)
    var h = TimerHeap()
    for i in range(5000):
        h.push(rng.below(100), UInt64(i))
    # Drop every third op (as the loop drops canceled timers).
    var entries = h.take_entries()
    assert_equal(len(h), 0)
    var keep = List[TimerEntry]()
    for i in range(len(entries)):
        if entries[i].op % 3 != 0:
            keep.append(entries[i])
    var kept = len(keep)
    h.rebuild(keep^)
    assert_equal(len(h), kept)
    # New pushes still order after older equal deadlines.
    h.push(50, 999_999)
    var got = _pop_all(h)
    assert_equal(len(got), kept + 1)
    assert_true(_sorted_ok(got))
    for i in range(len(got)):
        assert_true(got[i].op % 3 != 0 or got[i].op == 999_999)
    var last50 = -1
    for i in range(len(got)):
        if got[i].deadline_ns == 50:
            last50 = i
    assert_equal(got[last50].op, UInt64(999_999))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
