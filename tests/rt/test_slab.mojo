from std.testing import TestSuite, assert_equal, assert_false, assert_true

from rt.slab import SLAB_CHUNK, Slab, SlabId


struct Tracked(Movable):
    """Counts its own destruction through a shared counter cell."""

    var v: Int
    var drops: Pointer[Int, MutUntrackedOrigin]

    def __init__(out self, v: Int, drops: Pointer[Int, MutUntrackedOrigin]):
        self.v = v
        self.drops = drops

    def __deinit__(deinit self):
        self.drops[] += 1


def test_insert_get_remove() raises:
    var s = Slab[String]()
    var a = s.insert("a")
    var b = s.insert("b")
    assert_equal(len(s), 2)
    assert_true(s.contains(a) and s.contains(b))
    assert_equal(s[a], "a")
    s[b] = "bb"
    assert_equal(s[b], "bb")
    assert_equal(s.remove(a), "a")
    assert_false(s.contains(a))
    assert_equal(len(s), 1)


def test_stale_id_rejected_after_slot_reuse() raises:
    var s = Slab[Int]()
    var a = s.insert(1)
    _ = s.remove(a)
    var b = s.insert(2)
    assert_equal(a.slot(), b.slot())  # same slot reused...
    assert_true(a.gen() != b.gen())  # ...under a new generation
    assert_false(s.contains(a))
    assert_true(s.contains(b))
    assert_equal(s[b], 2)


def test_null_and_out_of_range_ids() raises:
    var s = Slab[Int]()
    assert_false(s.contains(SlabId.null()))
    assert_false(s.contains(SlabId.of(5, 1)))
    _ = s.insert(1)
    assert_false(s.contains(SlabId.of(SLAB_CHUNK * 3, 1)))
    assert_true(SlabId.null().is_null())


def test_addresses_stable_across_growth() raises:
    var s = Slab[Int]()
    var first = s.insert(42)
    var addr = Int(Pointer(to=s[first]))
    var ids = List[SlabId]()
    for i in range(SLAB_CHUNK * 5):
        ids.append(s.insert(i))
    assert_equal(Int(Pointer(to=s[first])), addr)
    assert_equal(s[first], 42)
    for i in range(len(ids)):
        assert_equal(s[ids[i]], i)
    assert_equal(len(s), SLAB_CHUNK * 5 + 1)


def test_values_destroyed_exactly_once() raises:
    var drops = 0
    var cell = Pointer(to=drops).unsafe_origin_cast[MutUntrackedOrigin]()
    do_slab_work(cell)
    # 3 inserted: one removed explicitly (dropped by caller), two dropped with the slab.
    assert_equal(drops, 3)


def do_slab_work(cell: Pointer[Int, MutUntrackedOrigin]) raises:
    var s = Slab[Tracked]()
    var a = s.insert(Tracked(1, cell))
    _ = s.insert(Tracked(2, cell))
    _ = s.insert(Tracked(3, cell))
    var t = s.remove(a)
    assert_equal(cell[], 0)
    _ = t^
    assert_equal(cell[], 1)
    # `s` is used here so Mojo's ASAP destruction cannot drop it (and the
    # two values it still owns) before the asserts above.
    assert_equal(len(s), 2)


def test_ids_lists_live_values() raises:
    var s = Slab[Int]()
    var a = s.insert(10)
    var b = s.insert(20)
    var c = s.insert(30)
    _ = s.remove(b)
    var ids = s.ids()
    assert_equal(len(ids), 2)
    assert_true(ids[0] == a and ids[1] == c)


def test_generation_wraps_without_zero() raises:
    var s = Slab[Int]()
    var id = s.insert(0)
    var slot = id.slot()
    s._gens[slot] = UInt32.MAX
    _ = s.remove(id)
    var again = s.insert(1)
    assert_equal(again.slot(), slot)
    assert_equal(again.gen(), 1)  # skipped 0 so the raw id can never be null


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
