"""Cross-thread mailbox: a bounded MPSC queue plus a coalesced eventfd wakeup.

This is the only sanctioned channel between loops on different threads
(design.md contract 6). The consuming loop owns a `Mailbox`; producers on any
thread hold `Sender`s (cheap, trivially copyable handles) and `push`. The
consumer waits until `wake_fd()` is readable, then calls `drain`.

**Why raw memory.** All shared state lives in raw heap memory that is reached
only through untracked pointers from methods taking `self` immutably. A Mojo
`mut self` is an exclusive borrow: the compiler may cache fields or write a
stale copy of them back. A struct mutated through `mut self` on two threads
therefore loses updates even when every field access is atomic. An earlier
version did exactly that: under `mojo run`, a producer's committed enqueue
index was overwritten by the consumer, and the producer spun forever.

**Queue.** Dmitry Vyukov's bounded MPMC ring, used with a single consumer.
- Each cell has a sequence number.
- A producer claims a slot with a CAS on the enqueue index and publishes the value with a release store of the cell's sequence.
- The consumer reads with acquire.
- No locks, and no allocation after construction.
- The enqueue index, the wake flag and the dequeue index each sit on their own cache line.

**Wakeups are coalesced.**
- Only the producer that flips `pending` from 0 to 1 writes the eventfd, so a burst of pushes costs one syscall.
- The consumer clears `pending` *before* draining, and both sides issue a full fence (Dekker-style). So either the consumer sees the value in this drain, or the producer sees `pending == 0` and signals again: no wakeup is lost.

Messages are trivial values: ids, raw fds, or the address of a heap object whose ownership passes to the consumer. A `Sender` must not outlive its `Mailbox`.
"""

from std.atomic import Atomic, Ordering, fence
from std.bit import next_power_of_two
from std.memory.alloc import unsafe_alloc

from linux import ErrorKind, Errno, EventFd, IoError, RawFd
from linux.eventfd import eventfd_write

comptime _LINE = 8
"""UInt64 words per 64-byte cache line."""
comptime _ENQ = 0
comptime _PENDING = 1 * _LINE
comptime _DEQ = 2 * _LINE
comptime _HDR_WORDS = 3 * _LINE


@fieldwise_init
struct _Ring[T: TrivialRegisterPassable](TrivialRegisterPassable):
    """Raw view of the shared ring (no ownership)."""

    var hdr: Pointer[UInt64, MutUntrackedOrigin]
    var seq: Pointer[UInt64, MutUntrackedOrigin]
    var val: Pointer[Self.T, MutUntrackedOrigin]
    var mask: UInt64
    var wake_fd: Int32

    @inline(.always)
    def _word(self, off: Int) -> Pointer[UInt64, MutUntrackedOrigin]:
        return self.hdr.unsafe_offset(off)

    def enqueue(self, value: Self.T) -> Bool:
        var pos = Atomic[UInt64].load[ordering=Ordering.RELAXED](self._word(_ENQ))
        while True:
            var i = Int(pos & self.mask)
            var seq = Atomic[UInt64].load[ordering=Ordering.ACQUIRE](
                self.seq.unsafe_offset(i)
            )
            var dif = Int64(seq) - Int64(pos)
            if dif == 0:
                if Atomic[UInt64].compare_exchange[
                    DType.uint64,
                    success_ordering=Ordering.RELAXED,
                    failure_ordering=Ordering.RELAXED,
                    weak=True,
                ](self._word(_ENQ), pos, pos + 1):
                    self.val.unsafe_offset(i)[] = value
                    Atomic[UInt64].store[ordering=Ordering.RELEASE](
                        self.seq.unsafe_offset(i), pos + 1
                    )
                    return True
                # The failed CAS reloaded `pos`; retry with it.
            elif dif < 0:
                return False  # full: the consumer has not freed this cell yet
            else:
                pos = Atomic[UInt64].load[ordering=Ordering.RELAXED](self._word(_ENQ))

    def wake(self) raises IoError:
        """Signal the consumer unless a wakeup is already outstanding."""
        fence[ordering=Ordering.SEQUENTIAL]()
        var expected: UInt64 = 0
        if Atomic[UInt64].compare_exchange[
            DType.uint64,
            success_ordering=Ordering.SEQUENTIAL,
            failure_ordering=Ordering.RELAXED,
        ](self._word(_PENDING), expected, 1):
            var r = eventfd_write(RawFd(self.wake_fd), 1)
            if r < 0 and r != -Int(Errno.EAGAIN.value):
                raise IoError.from_errno("Mailbox.wake", Errno(Int32(-r)))

    def pop(self) -> Optional[Self.T]:
        """Consumer only."""
        var pos = self._word(_DEQ)[]
        var i = Int(pos & self.mask)
        var seq = Atomic[UInt64].load[ordering=Ordering.ACQUIRE](
            self.seq.unsafe_offset(i)
        )
        if Int64(seq) - Int64(pos + 1) < 0:
            return None
        var v = self.val.unsafe_offset(i)[]
        self._word(_DEQ)[] = pos + 1
        Atomic[UInt64].store[ordering=Ordering.RELEASE](
            self.seq.unsafe_offset(i), pos + self.mask + 1
        )
        return v


struct Sender[T: TrivialRegisterPassable](TrivialRegisterPassable):
    """The producing end; copy it freely to other threads. Valid only while
    the `Mailbox` it came from is alive."""

    var _ring: _Ring[Self.T]

    def __init__(out self, ring: _Ring[Self.T]):
        self._ring = ring

    def push(self, value: Self.T) raises IoError -> Bool:
        """Enqueue from any thread. False if full (retry, shed load or fall
        back). Raises only if writing the wakeup eventfd fails."""
        if not self._ring.enqueue(value):
            return False
        self._ring.wake()
        return True


struct Mailbox[T: TrivialRegisterPassable](Movable):
    """The consuming end: owns the ring memory and the wakeup eventfd. Use it
    from one thread only (the loop that drains it)."""

    var _ring: _Ring[Self.T]
    var _wake: EventFd

    def __init__(out self, capacity: Int) raises IoError:
        """`capacity` is rounded up to a power of two (at least 2)."""
        if capacity < 1 or capacity > (1 << 30):
            raise IoError.of_kind("Mailbox(capacity)", ErrorKind.InvalidInput)
        var cap = next_power_of_two(max(2, capacity))
        self._wake = EventFd.new(nonblocking=True)
        var hdr = unsafe_alloc[UInt64](_HDR_WORDS, alignment=64)
        for i in range(_HDR_WORDS):
            hdr.unsafe_offset(i)[] = 0
        var seq = unsafe_alloc[UInt64](cap, alignment=64)
        for i in range(cap):
            seq.unsafe_offset(i)[] = UInt64(i)
        var val = unsafe_alloc[Self.T](cap, alignment=64)
        self._ring = _Ring[Self.T](hdr, seq, val, UInt64(cap - 1), self._wake.raw_fd())

    def __deinit__(deinit self):
        self._ring.hdr.unsafe_free()
        self._ring.seq.unsafe_free()
        self._ring.val.unsafe_free()

    @inline(.always)
    def capacity(self) -> Int:
        return Int(self._ring.mask) + 1

    def sender(self) -> Sender[Self.T]:
        return Sender[Self.T](self._ring)

    def push(self, value: Self.T) raises IoError -> Bool:
        """Same as `sender().push(value)`."""
        return self.sender().push(value)

    @inline(.always)
    def wake_fd(self) -> ref[self._wake] EventFd:
        """Readable when messages may be waiting. Register it with the
        consumer's loop, or wait on it with `linux.wait_ready`."""
        return self._wake

    def pop(self) -> Optional[Self.T]:
        """The oldest message, or None if empty (does not touch the wakeup)."""
        return self._ring.pop()

    def drain(self, mut out: List[Self.T], max_items: Int = Int.MAX) raises IoError -> Int:
        """Reset the wakeup, then move up to `max_items` messages into `out`
        (oldest first). Call it whenever `wake_fd()` was readable; a spurious
        empty drain is harmless."""
        _ = self._wake.drain()
        Atomic[UInt64].store[ordering=Ordering.SEQUENTIAL](
            self._ring._word(_PENDING), 0
        )
        fence[ordering=Ordering.SEQUENTIAL]()
        var n = 0
        while n < max_items:
            var v = self._ring.pop()
            if not v:
                break
            out.append(v.value())
            n += 1
        if n == max_items:
            self._ring.wake()  # messages left behind: wake ourselves again
        return n
