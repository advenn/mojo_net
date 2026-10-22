"""Timer queue: a binary min-heap of (deadline, sequence, op id).

Cancellation is lazy: a canceled or completed timeout op simply disappears
from the op slab, and its heap entry is skipped when it surfaces. The loop
counts such stale entries and compacts the heap (`take_entries` + filter +
`rebuild`) once they are the majority, so cancel-heavy timer use (a timeout
per request) cannot grow it without bound. Equal deadlines fire in
submission order (the sequence number breaks ties), which the completion
contract's FIFO rule relies on.

For per-connection idle timeouts, reset lazily: keep the deadline in the
connection and, when the timer fires early, re-arm it for the new deadline.
That keeps one heap entry per connection instead of one per read.
"""


@fieldwise_init
struct TimerEntry(TrivialRegisterPassable):
    var deadline_ns: Int
    var seq: UInt64
    var op: UInt64

    @inline(.always)
    def before(self, other: Self) -> Bool:
        if self.deadline_ns != other.deadline_ns:
            return self.deadline_ns < other.deadline_ns
        return self.seq < other.seq


struct TimerHeap(Movable, Sized):
    var _h: List[TimerEntry]
    var _seq: UInt64

    def __init__(out self):
        self._h = []
        self._seq = 0

    @inline(.always)
    def __len__(self) -> Int:
        return len(self._h)

    def push(mut self, deadline_ns: Int, op: UInt64):
        self._seq += 1
        self._h.append(TimerEntry(deadline_ns, self._seq, op))
        var i = len(self._h) - 1
        while i > 0:
            var p = (i - 1) // 2
            if not self._h[i].before(self._h[p]):
                break
            var t = self._h[i]
            self._h[i] = self._h[p]
            self._h[p] = t
            i = p

    def take_entries(mut self) -> List[TimerEntry]:
        """Remove and return every entry (in heap order, not sorted). With
        `rebuild` this lets the owner drop entries it knows are stale."""
        var out = List[TimerEntry]()
        swap(out, self._h)
        return out^

    def rebuild(mut self, var entries: List[TimerEntry]):
        """Replace the contents with `entries` (from `take_entries`, possibly
        filtered) and restore the heap in O(n). Sequence numbers are kept,
        so equal deadlines still fire in their original submission order."""
        self._h = entries^
        var n = len(self._h)
        var start = n // 2 - 1
        while start >= 0:
            self._sift_down(start)
            start -= 1

    def _sift_down(mut self, var i: Int):
        var n = len(self._h)
        while True:
            var l = 2 * i + 1
            if l >= n:
                return
            var c = l
            if l + 1 < n and self._h[l + 1].before(self._h[l]):
                c = l + 1
            if not self._h[c].before(self._h[i]):
                return
            var t = self._h[i]
            self._h[i] = self._h[c]
            self._h[c] = t
            i = c

    @inline(.always)
    def peek(self) -> Optional[TimerEntry]:
        if len(self._h) == 0:
            return None
        return self._h[0]

    def pop(mut self) -> TimerEntry:
        debug_assert(len(self._h) > 0, "pop from empty TimerHeap")
        var top = self._h[0]
        var last = self._h.pop()
        if len(self._h) > 0:
            self._h[0] = last
            self._sift_down(0)
        return top
