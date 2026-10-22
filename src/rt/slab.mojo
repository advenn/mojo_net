"""Generational slab: stable storage addressed by 64-bit ids.

An id is `generation:32 | slot:32`. Removing a value bumps its slot's
generation, so a stale id (an op that already completed, an fd that was
closed and whose slot was reused) is rejected instead of aliasing the new
occupant. Generations start at 1, so the raw id 0 is never valid.

Values live in fixed-size raw chunks that never move once allocated (the
outer list may grow, but it only holds the chunks' addresses). That is what io_uring
needs in M3: an SQE may point into an op record until its CQE arrives.
"""

from std.hash import Hasher
from std.memory import Layout, alloc

comptime SLAB_CHUNK = 256


@fieldwise_init
struct SlabId(Equatable, Hashable, TrivialRegisterPassable, Writable):
    """`generation:32 | slot:32`. `SlabId(0)` is the null id."""

    var raw: UInt64

    @staticmethod
    @inline(.always)
    def null() -> SlabId:
        return SlabId(0)

    @staticmethod
    @inline(.always)
    def of(slot: Int, gen: UInt32) -> SlabId:
        return SlabId((UInt64(gen) << 32) | UInt64(slot))

    @inline(.always)
    def slot(self) -> Int:
        return Int(self.raw & 0xFFFF_FFFF)

    @inline(.always)
    def gen(self) -> UInt32:
        return UInt32(self.raw >> 32)

    @inline(.always)
    def is_null(self) -> Bool:
        return self.raw == 0

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self.raw == other.raw

    def __hash__[H: Hasher](self, mut hasher: H):
        self.raw.__hash__(hasher)

    def write_to(self, mut writer: Some[Writer]):
        writer.write("#", self.slot(), ".", self.gen())


struct Slab[T: Movable & Deinitable](Movable, Sized):
    """Owns values of `T`; `insert` returns a `SlabId`, `remove` gives the
    value back and invalidates the id.

    Storage is raw: fixed chunks of uninitialized `T` (never moved or freed
    while the slab lives) plus an occupancy flag and a generation per slot.
    This replaced `List[List[Optional[T]]]`, whose Optional construct/take and
    nested bounds checks on every lookup cost about half of the loop's user
    time per message (bench/README.md). A reference from `__getitem__` stays
    valid until that id is removed: growing never moves existing values."""

    var _chunks: List[Int]
    var _used: List[Bool]
    var _gens: List[UInt32]
    var _free: List[Int]
    var _len: Int

    def __init__(out self):
        self._chunks = []
        self._used = []
        self._gens = []
        self._free = []
        self._len = 0

    def __deinit__(deinit self):
        for slot in range(len(self._used)):
            if self._used[slot]:
                _ = Pointer[Self.T, MutUntrackedOrigin](
                    unsafe_from_address=self._chunks[slot // SLAB_CHUNK]
                ).unsafe_offset(slot % SLAB_CHUNK).unsafe_take_pointee()
        for i in range(len(self._chunks)):
            Pointer[Self.T, MutUntrackedOrigin](unsafe_from_address=self._chunks[i]).unsafe_free()

    @inline(.always)
    def __len__(self) -> Int:
        return self._len

    def capacity(self) -> Int:
        return len(self._gens)

    @inline(.always)
    def _ptr(self, slot: Int) -> Pointer[Self.T, MutUntrackedOrigin]:
        return Pointer[Self.T, MutUntrackedOrigin](
            unsafe_from_address=self._chunks.unsafe_get(slot // SLAB_CHUNK)
        ).unsafe_offset(slot % SLAB_CHUNK)

    def _grow(mut self):
        var base = len(self._gens)
        var p = alloc(Layout[Self.T](count=SLAB_CHUNK))^.unsafe_leak()
        self._chunks.append(Int(p))
        for i in range(SLAB_CHUNK):
            self._gens.append(1)
            self._used.append(False)
            self._free.append(base + SLAB_CHUNK - 1 - i)

    @inline(.always)
    def insert(mut self, var value: Self.T) -> SlabId:
        if len(self._free) == 0:
            self._grow()
        var slot = self._free.pop()
        self._ptr(slot).unsafe_write(value^)
        self._used.unsafe_set(slot, True)
        self._len += 1
        return SlabId.of(slot, self._gens.unsafe_get(slot))

    @inline(.always)
    def contains(self, id: SlabId) -> Bool:
        var slot = id.slot()
        if id.is_null() or slot >= len(self._gens):
            return False
        return self._gens.unsafe_get(slot) == id.gen() and self._used.unsafe_get(slot)

    @inline(.always)
    def __getitem__(ref self, id: SlabId) -> ref[self] Self.T:
        """The value for a live id. Check `contains` first: a stale id is a
        caller bug (debug_assert in debug builds). The reference carries the
        slab's own origin, so the slab outlives it (an untracked reference
        let Mojo destroy the slab before the value was read)."""
        debug_assert(self.contains(id), "stale or null SlabId ", id)
        return (
            self._ptr(id.slot())
            .unsafe_mut_cast[origin_of(self).mut]()
            .unsafe_origin_cast[origin_of(self)]()[]
        )

    @inline(.always)
    def remove(mut self, id: SlabId) -> Self.T:
        debug_assert(self.contains(id), "stale or null SlabId ", id)
        var slot = id.slot()
        var v = self._ptr(slot).unsafe_take_pointee()
        self._used.unsafe_set(slot, False)
        var g = self._gens.unsafe_get(slot) + 1
        self._gens.unsafe_set(slot, g if g != 0 else 1)
        self._free.append(slot)
        self._len -= 1
        return v^

    def ids(self) -> List[SlabId]:
        var out = List[SlabId](capacity=self._len)
        for slot in range(len(self._gens)):
            if self._used[slot]:
                out.append(SlabId.of(slot, self._gens[slot]))
        return out^
