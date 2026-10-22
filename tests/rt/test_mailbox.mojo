"""Mailbox: single-thread semantics plus a real multi-producer run on
pthreads (test-only libc use; the library itself spawns no threads)."""

from std.ffi import external_call
from std.memory import OwnedPointer
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Deadline, Duration, ErrorKind, IoError, wait_ready
from linux.consts import POLLIN
from rt.mailbox import Mailbox, Sender


@fieldwise_init
struct Msg(TrivialRegisterPassable):
    var producer: Int
    var seq: Int


def test_fifo_and_capacity_rounding() raises:
    var mb = Mailbox[Msg](5)
    assert_equal(mb.capacity(), 8)
    for i in range(8):
        assert_true(mb.push(Msg(0, i)))
    assert_false(mb.push(Msg(0, 99)))  # full
    for i in range(8):
        var m = mb.pop()
        assert_true(Bool(m))
        assert_equal(m.value().seq, i)
    assert_false(Bool(mb.pop()))


def test_wraparound_many_times() raises:
    var mb = Mailbox[Msg](4)
    var next = 0
    for round in range(1000):
        for _ in range(3):
            assert_true(mb.push(Msg(0, next)))
            next += 1
        var out = List[Msg]()
        assert_equal(mb.drain(out), 3)
        assert_equal(out[0].seq, next - 3)
        assert_equal(out[2].seq, next - 1)
        _ = round


def test_wake_fd_coalesces_and_rearms() raises:
    var mb = Mailbox[Msg](64)
    # Nothing pushed: not readable.
    var timed_out = False
    try:
        _ = wait_ready(mb.wake_fd(), Int16(POLLIN), Deadline.after(Duration.from_millis(5)), "wait")
    except e:
        timed_out = e.kind == ErrorKind.TimedOut
    assert_true(timed_out)
    for i in range(10):
        _ = mb.push(Msg(0, i))
    _ = wait_ready(mb.wake_fd(), Int16(POLLIN), Deadline.after(Duration.from_millis(100)), "wait")
    var out = List[Msg]()
    assert_equal(mb.drain(out), 10)
    # Drained and pending cleared: a new push signals again.
    _ = mb.push(Msg(0, 10))
    _ = wait_ready(mb.wake_fd(), Int16(POLLIN), Deadline.after(Duration.from_millis(100)), "wait")
    assert_equal(mb.drain(out), 1)


def test_drain_limit_resignals() raises:
    var mb = Mailbox[Msg](64)
    for i in range(10):
        _ = mb.push(Msg(0, i))
    var out = List[Msg]()
    assert_equal(mb.drain(out, 4), 4)
    # Messages remain, so the mailbox must have re-armed its wakeup.
    _ = wait_ready(mb.wake_fd(), Int16(POLLIN), Deadline.after(Duration.from_millis(100)), "wait")
    assert_equal(mb.drain(out), 6)
    assert_equal(out[9].seq, 9)


# ---- multi-producer on real threads (test-only pthread FFI) ---------------

comptime ThreadEntry = def(OpaquePointer[MutAnyOrigin]) thin abi("C") -> OpaquePointer[MutAnyOrigin]

comptime PRODUCERS = 4
comptime PER_PRODUCER = 50_000


struct ProducerCtx(Movable):
    var sender: Sender[Msg]
    """Handle to the test's Mailbox, which outlives the joins."""
    var id: Int
    var full_spins: Int

    def __init__(out self, sender: Sender[Msg], id: Int):
        self.sender = sender
        self.id = id
        self.full_spins = 0


def producer_main(arg: OpaquePointer[MutAnyOrigin]) abi("C") -> OpaquePointer[MutAnyOrigin]:
    var ctx = arg.unsafe_bitcast[ProducerCtx]()
    var tx = ctx[].sender
    var i = 0
    while i < PER_PRODUCER:
        var ok = False
        try:
            ok = tx.push(Msg(ctx[].id, i))
        except:
            return arg
        if ok:
            i += 1
        else:
            ctx[].full_spins += 1
    return arg


def pthread_create(mut thread: UInt64, entry: ThreadEntry, ctx: OpaquePointer[MutAnyOrigin]) -> Int32:
    return external_call["pthread_create", Int32](Int(Pointer(to=thread)), 0, entry, ctx)


def pthread_join(thread: UInt64) -> Int32:
    return external_call["pthread_join", Int32](thread, 0)


def test_multi_producer_fifo_per_producer() raises:
    var mb = Mailbox[Msg](1024)
    var ctxs = List[OwnedPointer[ProducerCtx]]()
    var tids = List[UInt64]()
    for p in range(PRODUCERS):
        ctxs.append(OwnedPointer(ProducerCtx(mb.sender(), p)))
        var tid: UInt64 = 0
        var arg = OpaquePointer[MutAnyOrigin](unsafe_from_address=Int(ctxs[p].ptr()))
        assert_equal(pthread_create(tid, producer_main, arg), 0)
        tids.append(tid)
    var next = List[Int](length=PRODUCERS, fill=0)
    var total = 0
    var out = List[Msg](capacity=1024)
    var wakeups = 0
    while total < PRODUCERS * PER_PRODUCER:
        _ = wait_ready(mb.wake_fd(), Int16(POLLIN), Deadline.after(Duration.from_secs(10)), "consumer wait")
        wakeups += 1
        out.clear()
        _ = mb.drain(out)
        for i in range(len(out)):
            var m = out[i]
            assert_equal(m.seq, next[m.producer])  # FIFO per producer, no loss/dup
            next[m.producer] += 1
        total += len(out)
    for p in range(PRODUCERS):
        assert_equal(pthread_join(tids[p]), 0)
        assert_equal(next[p], PER_PRODUCER)
    assert_false(Bool(mb.pop()))
    # Coalescing: far fewer wakeups than messages.
    assert_true(wakeups < total)
    print("    messages", total, "wakeups", wakeups)
    _ = ctxs^
    _ = mb^


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
