"""Spike 3: completion targets as `{thin fn pointer, ctx word}`.

design.md fixes completion targets as `{thin fn, ctx}`. This spike proves:
1. A non-capturing function and a monomorphized generic `_on_event[H]` are
   both values of one thin function type and can sit in one table.
2. `ctx` is the address of a heap handler (`OwnedPointer`), cast back in the
   callback; handlers of different types coexist in one table, and a table
   that owns type-erased handlers can drop each exactly once via a second
   thin fn (`_drop[H]`).
3. A callback can take the loop by `mut` and enqueue follow-up work while
   the loop is dispatching (copy the 16-byte target out first, then call).
4. Cost: 10M indirect calls vs direct calls.

    pixi run mojo run -I src spikes/callback_spike.mojo
    pixi run mojo build -I src spikes/callback_spike.mojo -o spikes/out/callback_spike
"""

from std.benchmark import keep
from std.memory import OwnedPointer
from std.sys import size_of

from linux.nr import SYS_getpid
from linux.syscall import syscall0
from linux.time import Instant

# ---- the target type ---------------------------------------------------------

comptime N_CALLS = 10_000_000


struct Loop(Movable):
    """Stand-in for the rt loop: owns the target table and a run queue."""

    var table: List[Target]
    var queue: List[Tuple[Int, Int]]
    """(slot, result) completions waiting to be dispatched."""
    var dispatched: Int

    def __init__(out self):
        self.table = List[Target]()
        self.queue = List[Tuple[Int, Int]]()
        self.dispatched = 0

    def add(mut self, t: Target) -> Int:
        self.table.append(t)
        return len(self.table) - 1

    def complete(mut self, slot: Int, res: Int):
        self.queue.append((slot, res))

    def run(mut self):
        """Dispatch until the queue is empty. Callbacks may enqueue more."""
        var i = 0
        while i < len(self.queue):
            var slot = self.queue[i][0]
            var res = self.queue[i][1]
            # Copy the target out: the callback gets `mut self`, so no
            # reference into `self.table` may be live across the call.
            var t = self.table[slot]
            t.call(t.ctx, self, res)
            self.dispatched += 1
            i += 1
        self.queue.clear()


comptime CompletionFn = def(Int, mut Loop, Int) thin -> None
"""(ctx, loop, result). Non-raising: results are `-errno` integers."""

comptime DropFn = def(Int) thin -> None


@fieldwise_init
struct Target(TrivialRegisterPassable):
    """16 bytes: what a slab slot stores next to the op id's generation.
    Note: `fn` is still a reserved word, so the field cannot be named `fn`."""

    var call: CompletionFn
    var ctx: Int


# ---- handlers ----------------------------------------------------------------


trait Handler(Movable):
    def on_event(mut self, mut loop: Loop, res: Int):
        ...


struct Counter(Handler):
    var total: Int
    var calls: Int
    var drops: Pointer[Int, MutUntrackedOrigin]

    def __init__(out self, drops: Pointer[Int, MutUntrackedOrigin]):
        self.total = 0
        self.calls = 0
        self.drops = drops

    def __deinit__(deinit self):
        self.drops[] += 1

    def on_event(mut self, mut loop: Loop, res: Int):
        self.total += res
        self.calls += 1


struct Recorder(Handler):
    """A different layout (owns a List and a String) in the same table.
    Re-arms itself once through the loop to prove re-entrant enqueueing."""

    var seen: List[Int]
    var log: String
    var slot: Int
    var drops: Pointer[Int, MutUntrackedOrigin]

    def __init__(out self, drops: Pointer[Int, MutUntrackedOrigin]):
        self.seen = List[Int]()
        self.log = String()
        self.slot = -1
        self.drops = drops

    def __deinit__(deinit self):
        self.drops[] += 1

    def on_event(mut self, mut loop: Loop, res: Int):
        self.seen.append(res)
        self.log += String(res) + ";"
        if res == 7 and self.slot >= 0:
            loop.complete(self.slot, 8)  # follow-up completion, same slot


def _on_event[H: Handler](ctx: Int, mut loop: Loop, res: Int):
    """One instantiation per handler type; all share `CompletionFn`."""
    Pointer[H, MutUntrackedOrigin](unsafe_from_address=ctx)[].on_event(
        loop, res
    )


def _drop[H: Handler & Deinitable](ctx: Int):
    """Rebuild the OwnedPointer from the ctx word and let it destroy `H`."""
    var o = OpaquePointer[MutAnyOrigin](unsafe_from_address=ctx)
    var owner = OwnedPointer[H](unsafe_from_opaque_pointer=o)
    _ = owner^


def plain_add(ctx: Int, mut loop: Loop, res: Int):
    """A plain non-generic callback: ctx is the address of an Int."""
    Pointer[Int, MutUntrackedOrigin](unsafe_from_address=ctx)[] += res


# ---- a table that owns type-erased handlers ---------------------------------


@fieldwise_init
struct Owned(TrivialRegisterPassable):
    var target: Target
    var drop: DropFn


struct HandlerSlab(Movable):
    """Owns heap handlers of any `Handler` type behind ctx words."""

    var entries: List[Owned]

    def __init__(out self):
        self.entries = List[Owned]()

    def adopt[H: Handler & Deinitable](mut self, var h: H) -> Target:
        var owner = OwnedPointer(h^)
        var ctx = Int(owner.ptr())
        # Leak the box into the ctx word; `_drop[H]` takes it back later.
        _ = owner^.unsafe_take_allocation().unsafe_leak()
        var t = Target(_on_event[H], ctx)
        self.entries.append(Owned(t, _drop[H]))
        return t

    def __deinit__(deinit self):
        for e in self.entries:
            e.drop(e.target.ctx)


# ---- benchmark helpers -------------------------------------------------------


struct Acc(Handler):
    var v: Int

    def __init__(out self):
        self.v = 0

    def on_event(mut self, mut loop: Loop, res: Int):
        self.v += res


struct Xor(Handler):
    var v: Int

    def __init__(out self):
        self.v = 0

    def on_event(mut self, mut loop: Loop, res: Int):
        self.v ^= res


@no_inline
def _direct_noinline(mut a: Acc, mut loop: Loop, res: Int):
    a.v += res


@no_inline
def _build_targets(n: Int, ref a: Acc, ref x: Xor) -> List[Target]:
    """Built at runtime from a syscall result so the call targets cannot be
    constant-folded into direct calls."""
    var out = List[Target]()
    var flip = syscall0(SYS_getpid) % 2
    for i in range(n):
        if (i + flip) % 2 == 0:
            out.append(Target(_on_event[Acc], Int(Pointer(to=a))))
        else:
            out.append(Target(_on_event[Xor], Int(Pointer(to=x))))
    return out^


@inline(.always)
def _xorshift(mut s: UInt64) -> UInt64:
    s ^= s << 13
    s ^= s >> 7
    s ^= s << 17
    return s


def _ns_per(start: Instant, n: Int) -> Float64:
    return Float64((Instant.now() - start).as_nanos()) / Float64(n)


def _bench() raises:
    var loop = Loop()
    var a = Acc()
    var x = Xor()

    # 1. direct, inlinable method call
    var t0 = Instant.now()
    for i in range(N_CALLS):
        a.on_event(loop, i)
    keep(a.v)
    var direct_inline = _ns_per(t0, N_CALLS)

    # 2. direct call to a @no_inline function
    t0 = Instant.now()
    for i in range(N_CALLS):
        _direct_noinline(a, loop, i)
    keep(a.v)
    var direct_call = _ns_per(t0, N_CALLS)

    # 3. static generic dispatch (what `_on_event[H]` costs when called directly)
    var actx = Int(Pointer(to=a))
    t0 = Instant.now()
    for i in range(N_CALLS):
        _on_event[Acc](actx, loop, i)
    keep(a.v)
    var static_generic = _ns_per(t0, N_CALLS)

    # 4. indirect, one target (perfectly predicted)
    var one = _build_targets(1, a, x)
    var t = one[0]
    t0 = Instant.now()
    for i in range(N_CALLS):
        t.call(t.ctx, loop, i)
    keep(a.v)
    keep(x.v)
    var indirect_one = _ns_per(t0, N_CALLS)

    # 5. indirect through a table of 2 alternating handler types
    var two = _build_targets(2, a, x)
    t0 = Instant.now()
    for i in range(N_CALLS):
        var e = two[i & 1]
        e.call(e.ctx, loop, i)
    keep(a.v)
    keep(x.v)
    var indirect_two = _ns_per(t0, N_CALLS)

    # 6a. baseline for 6b: same pseudo-random indexing, direct call
    var many = _build_targets(8, a, x)
    var s: UInt64 = 0x9E3779B97F4A7C15
    t0 = Instant.now()
    for i in range(N_CALLS):
        var k = Int(_xorshift(s) & 7)
        _direct_noinline(a, loop, k + i)
    keep(a.v)
    var random_direct = _ns_per(t0, N_CALLS)

    # 6b. indirect, 8 slots, 2 handler types in pseudo-random order
    s = 0x9E3779B97F4A7C15
    t0 = Instant.now()
    for i in range(N_CALLS):
        var k = Int(_xorshift(s) & 7)
        var e = many[k]
        e.call(e.ctx, loop, k + i)
    keep(a.v)
    keep(x.v)
    var random_indirect = _ns_per(t0, N_CALLS)

    print("  calls per variant:", N_CALLS)
    print("  1 direct (inlinable)            ns/call:", direct_inline)
    print("  2 direct @no_inline             ns/call:", direct_call)
    print("  3 _on_event[H] called directly  ns/call:", static_generic)
    print("  4 indirect, 1 target            ns/call:", indirect_one)
    print("  5 indirect, 2 types alternating ns/call:", indirect_two)
    print("  6a direct + xorshift index      ns/call:", random_direct)
    print("  6b indirect, 8 slots, random    ns/call:", random_indirect)
    print("  (checksums", a.v, x.v, ")")


# ---- main --------------------------------------------------------------------


def _check(cond: Bool, what: StaticString) raises:
    if not cond:
        raise Error("CALLBACK SPIKE FAIL: ", what)
    print("  ok  ", what)


def main() raises:
    _check(size_of[CompletionFn]() == 8, "thin fn value is one word")
    _check(size_of[Target]() == 16, "Target {call, ctx} is 16 bytes")

    var drops = 0
    var dp = Pointer[Int, MutUntrackedOrigin](
        unsafe_from_address=Int(Pointer(to=drops))
    )
    var plain_total = 0
    var counter_total: Int
    var counter_calls: Int
    var rec_seen: Int
    var rec_log: String
    var loop = Loop()
    var slab = HandlerSlab()

    # Two handler types plus a plain fn, all in one table.
    var c_slot = loop.add(slab.adopt(Counter(dp)))
    var r_target = slab.adopt(Recorder(dp))
    var r_slot = loop.add(r_target)
    Pointer[Recorder, MutUntrackedOrigin](
        unsafe_from_address=r_target.ctx
    )[].slot = r_slot
    var p_slot = loop.add(Target(plain_add, Int(Pointer(to=plain_total))))

    for i in range(1, 11):
        loop.complete(c_slot, i)
        loop.complete(r_slot, i)
        loop.complete(p_slot, i * 100)
    loop.run()

    ref c = Pointer[Counter, MutUntrackedOrigin](
        unsafe_from_address=loop.table[c_slot].ctx
    )[]
    counter_total = c.total
    counter_calls = c.calls
    ref r = Pointer[Recorder, MutUntrackedOrigin](
        unsafe_from_address=loop.table[r_slot].ctx
    )[]
    rec_seen = len(r.seen)
    rec_log = r.log
    _check(
        counter_total == 55 and counter_calls == 10,
        "Counter via _on_event[Counter]",
    )
    _check(rec_seen == 11, "Recorder via _on_event[Recorder] (10 + 1 re-armed)")
    _check(
        rec_log == "1;2;3;4;5;6;7;8;9;10;8;",
        "re-armed completion queued at the tail (FIFO)",
    )
    _check(plain_total == 5500, "plain non-capturing fn with an Int ctx")
    _check(loop.dispatched == 31, "31 completions dispatched")

    _check(drops == 0, "no handler dropped while the slab lives")
    _ = slab^
    _check(drops == 2, "slab dropped both type-erased handlers exactly once")
    _ = plain_total  # its address is in the table; keep alive until here

    print("benchmark:")
    _bench()
    print("CALLBACK SPIKE: PASS")
