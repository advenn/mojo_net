"""`ByteBuffer`: the owned, growable byte buffer every protocol codec uses.

Layout (SwiftNIO / Netty style), with separate read and write indices:

    0 ........ r ............ w .............. capacity
    | consumed | readable     | writable       |

- Input from the kernel lands directly in the writable tail:
  `ensure_writable(n)`, `recv(buf.writable_span())`, then `commit(got)`.
  No intermediate copy.
- A parser looks at `readable_span()`, finds frames with `find` /
  `read_until`, and drops what it used with `consume(n)` or `read_bytes(n)`.
- Writers append with `write_bytes` / `write_byte`; a sender takes
  `readable_span()` and calls `consume(sent)` after a partial send.

Memory policy:
- Capacity grows on demand (at least doubling, so appends are amortized
  O(1)) and never past `max_size()`. Exceeding the cap raises `OutOfMemory`:
  that is the defence against a peer that sends an unbounded frame.
- Growing copies only the readable bytes and drops the consumed prefix.
- `ensure_writable` compacts in place, instead of growing, only when the
  bytes it moves are no more than the bytes it reclaims. Each consumed byte
  then pays for at most one moved byte, so compaction is amortized O(1)
  per byte and a large unread tail is never memmoved over and over.
- A buffer that becomes empty resets both indices to 0 for free.

Spans: `readable_span()` / `writable_span()` borrow the buffer (their origin
is the buffer's storage), so the buffer outlives them, and Mojo rejects
passing a span of a buffer into a mutating call on the same buffer
(`b.write_bytes(b.readable_span())` does not compile). Mojo 1.2 does *not*
yet reject using a span after a later mutating call (the same hole as a
`Span` of a stdlib `List`), so the rule is: any mutating call
(`ensure_writable`, `write_*`, `commit`, `consume`, `read_bytes`,
`compact`, `discard_read_bytes`, `clear`, `shrink_to`) invalidates every
span taken before it. A stale span reads freed memory after growth.
- Use spans only within one expression or statement (`recv` into
  `writable_span()`, `send` from `readable_span()`, one comparison), and
  take them again after any mutating call.
- Hold *offsets* instead, especially in a codec across `feed`: positions
  relative to the read index, as returned by `find`/`read_until` and read
  back with `byte_at` (or copied with `read_bytes`). Offsets stay valid
  across growth and compaction (not across `consume`).
- Check mode (test builds): with `-D MOJO_TCP_CHECK_SPANS=1`, and in every
  fault build (`-D MOJO_TCP_FAULTS=1`, the test-only define), every call
  that may move bytes (`ensure_writable`, `write_*`, `commit`, `compact`,
  `discard_read_bytes`, `shrink_to`) moves the storage to a fresh
  allocation and fills the old one with `POISON` before freeing it, and
  every call that drops bytes (`consume`, `read_bytes`, `clear`) poisons
  them in place. A stale span then reads `POISON` or freed memory on
  *every* such call instead of only when the buffer happens to grow, and
  under `mojo build --sanitize address` each stale use is a
  heap-use-after-free report. Indices and contents are unchanged, so code
  that follows the rule behaves identically.

Copies: `copy()` duplicates the readable bytes only. The copy has
`capacity() == readable()`, `read_index() == 0` and the same `max_size()`;
the consumed prefix and the writable tail are neither copied nor read.

Backing store: a `List[UInt8]` whose length is the capacity. Growth
allocates with `unsafe_uninit_length` (no zero fill), so the writable tail
holds unspecified bytes until written; readable bytes are always ones that
were written or committed.

This module does no I/O; it imports neither `rt` nor any socket module.
"""

from std.memory import unsafe_memcpy, unsafe_memmove
from std.sys import get_defined_bool

from linux import ErrorKind, IoError

comptime CHECK_SPANS = get_defined_bool[
    "MOJO_TCP_CHECK_SPANS"
]() or get_defined_bool["MOJO_TCP_FAULTS"]()
"""Span-invalidation check mode (see the module docstring). Test builds
only: it reallocates on every write, so it is far slower."""

comptime POISON: UInt8 = 0xDD
"""What check mode writes over storage and bytes that spans must no longer
see."""

comptime DEFAULT_MAX_SIZE = 64 * 1024 * 1024
"""Default hard cap on capacity (64 MiB): large enough for any sane frame,
small enough that a hostile peer cannot exhaust memory through one
connection."""

comptime MIN_GROWTH = 256
"""Smallest capacity allocated on growth, so tiny appends do not realloc
on every call."""

comptime _SCAN_WIDTH = 32
"""Bytes compared per SIMD step in `find` (AVX2 width; LLVM splits it on
narrower targets such as aarch64 NEON)."""


struct ByteBuffer(Copyable, Defaultable, Movable, Sized, Writable):
    """An owned, growable byte buffer with separate read and write indices.

    Invariant: `0 <= _r <= _w <= len(_buf) <= _max`.
    """

    var _buf: List[UInt8]
    """Storage; its length is the capacity."""
    var _r: Int
    """Read index: start of the readable bytes."""
    var _w: Int
    """Write index: end of the readable bytes, start of the writable tail."""
    var _max: Int
    """Hard cap on capacity."""

    # ---- construction --------------------------------------------------------

    def __init__(out self):
        """Empty, no allocation yet, `DEFAULT_MAX_SIZE` cap."""
        self._buf = List[UInt8]()
        self._r = 0
        self._w = 0
        self._max = DEFAULT_MAX_SIZE

    def __init__(
        out self, *, capacity: Int, max_size: Int = DEFAULT_MAX_SIZE
    ) raises IoError:
        """Preallocate `capacity` bytes. Raises `InvalidInput` unless
        `0 <= capacity <= max_size` and `max_size > 0`."""
        if max_size <= 0 or capacity < 0 or capacity > max_size:
            raise IoError.of_kind("ByteBuffer.__init__", ErrorKind.InvalidInput)
        self._buf = List[UInt8](unsafe_uninit_length=capacity)
        self._r = 0
        self._w = 0
        self._max = max_size

    def __init__(out self, *, max_size: Int) raises IoError:
        """Empty, with a custom cap (`max_size > 0`, else `InvalidInput`)."""
        self = ByteBuffer(capacity=0, max_size=max_size)

    def __init__(out self, *, copy: Self):
        """Copy the readable bytes only: O(readable), never reading the
        consumed prefix or the uninitialized writable tail. The copy has
        `capacity() == readable()`, read index 0 and the same cap."""
        var used = copy._w - copy._r
        self._buf = List[UInt8](unsafe_uninit_length=used)
        if used > 0:
            unsafe_memcpy(
                dest=self._buf.unsafe_ptr(),
                src=copy._buf.unsafe_ptr().unsafe_offset(copy._r),
                count=used,
            )
        self._r = 0
        self._w = used
        self._max = copy._max

    # ---- sizes ---------------------------------------------------------------

    @inline(.always)
    def __len__(self) -> Int:
        """Readable bytes."""
        return self._w - self._r

    @inline(.always)
    def readable(self) -> Int:
        """Bytes between the read and write indices."""
        return self._w - self._r

    @inline(.always)
    def is_empty(self) -> Bool:
        return self._w == self._r

    @inline(.always)
    def writable(self) -> Int:
        """Bytes that can be written right now without growing or
        compacting (the length of `writable_span()`)."""
        return len(self._buf) - self._w

    @inline(.always)
    def capacity(self) -> Int:
        return len(self._buf)

    @inline(.always)
    def max_size(self) -> Int:
        return self._max

    @inline(.always)
    def max_writable(self) -> Int:
        """The most bytes that can still be appended before hitting
        `max_size()` (after compacting/growing as needed)."""
        return self._max - (self._w - self._r)

    @inline(.always)
    def read_index(self) -> Int:
        """Bytes consumed since the last compaction (diagnostics/tests)."""
        return self._r

    # ---- views ---------------------------------------------------------------

    @inline(.always)
    def readable_span(self) -> Span[UInt8, origin_of(self._buf)]:
        """The unread bytes. Invalidated by any mutating call: use it at
        once and take it again afterwards (hold offsets, not spans)."""
        return Span(self._buf)[self._r : self._w]

    @inline(.always)
    def writable_span(mut self) -> MutSpan[UInt8, origin_of(self._buf)]:
        """The writable tail (`writable()` bytes, contents unspecified), for a
        `recv` straight into the buffer. Call `ensure_writable(n)` first and
        `commit(got)` after. Invalidated by any mutating call, `commit`
        included: take it again for the next `recv`."""
        return Span(self._buf)[self._w : len(self._buf)]

    @inline(.always)
    def byte_at(self, offset: Int) raises IoError -> UInt8:
        """The readable byte at `offset` from the read index: the span-free
        way to inspect input, for offsets kept across mutating calls.
        `InvalidInput` unless `0 <= offset < readable()`."""
        if offset < 0 or offset >= self._w - self._r:
            raise IoError.of_kind("ByteBuffer.byte_at", ErrorKind.InvalidInput)
        return self._buf.unsafe_ptr()[unsafe_offset=self._r + offset]

    # ---- reserving and committing --------------------------------------------

    @inline(.always)
    def ensure_writable(mut self, n: Int) raises IoError:
        """Make `writable() >= n`, compacting or growing as needed.

        Raises `InvalidInput` for `n < 0` and `OutOfMemory` when the readable
        bytes plus `n` would exceed `max_size()`; the buffer is unchanged
        when it raises."""
        if n <= len(self._buf) - self._w:
            if n < 0:
                raise IoError.of_kind(
                    "ByteBuffer.ensure_writable", ErrorKind.InvalidInput
                )
        else:
            self._make_room(n)
        comptime if CHECK_SPANS:
            self._relocate()

    @no_inline
    def _make_room(mut self, n: Int) raises IoError:
        """Slow path of `ensure_writable`: `writable() < n` here."""
        var used = self._w - self._r
        if n > self._max - used:
            raise IoError.of_kind(
                "ByteBuffer.ensure_writable", ErrorKind.OutOfMemory
            )
        var need = used + n
        var cap = len(self._buf)
        # Compact in place when it suffices and moves no more bytes than it
        # reclaims (amortized against consumption).
        if need <= cap and used <= self._r:
            self._compact()
            return
        var grown = self._max if cap > self._max // 2 else cap * 2
        var new_cap = max(grown, need, MIN_GROWTH)
        if new_cap > self._max:
            new_cap = self._max
        if new_cap <= cap:
            # At the cap and compaction is the only way left (need <= cap).
            self._compact()
            return
        self._realloc(new_cap)

    def _realloc(mut self, new_cap: Int):
        """Move the readable bytes to the front of a fresh `new_cap` block
        (`new_cap >= readable()`)."""
        var used = self._w - self._r
        var fresh = List[UInt8](unsafe_uninit_length=new_cap)
        if used > 0:
            unsafe_memcpy(
                dest=fresh.unsafe_ptr(),
                src=self._buf.unsafe_ptr().unsafe_offset(self._r),
                count=used,
            )
        comptime if CHECK_SPANS:
            _poison(fresh, used, new_cap)
            _poison(self._buf, 0, len(self._buf))
        self._buf = fresh^
        self._r = 0
        self._w = used

    def _relocate(mut self):
        """Check mode: move the storage to a fresh block of the same
        capacity at the same indices, poisoning the old block (and the
        fresh block outside the readable bytes) so stale spans see it."""
        var cap = len(self._buf)
        if cap == 0:
            return
        var fresh = List[UInt8](length=cap, fill=POISON)
        var used = self._w - self._r
        if used > 0:
            unsafe_memcpy(
                dest=fresh.unsafe_ptr().unsafe_offset(self._r),
                src=self._buf.unsafe_ptr().unsafe_offset(self._r),
                count=used,
            )
        _poison(self._buf, 0, cap)
        self._buf = fresh^

    def _compact(mut self):
        """Move the readable bytes to index 0 (may overlap: memmove)."""
        var used = self._w - self._r
        if self._r == 0:
            return
        if used > 0:
            # Source and destination are the same allocation; untrack the
            # origin so the aliasing checker accepts the (overlapping) move.
            var p = self._buf.unsafe_ptr().unsafe_origin_cast[
                MutUntrackedOrigin
            ]()
            unsafe_memmove(dest=p, src=p.unsafe_offset(self._r), count=used)
        self._r = 0
        self._w = used

    @inline(.always)
    def commit(mut self, n: Int) raises IoError:
        """Mark `n` bytes of the writable tail as written (after a `recv`
        into `writable_span()`). `InvalidInput` unless
        `0 <= n <= writable()`."""
        if n < 0 or n > len(self._buf) - self._w:
            raise IoError.of_kind("ByteBuffer.commit", ErrorKind.InvalidInput)
        self._w += n
        comptime if CHECK_SPANS:
            self._relocate()

    # ---- writing -------------------------------------------------------------

    def write_bytes(mut self, data: Span[UInt8, _]) raises IoError:
        """Append `data`. `OutOfMemory` (buffer unchanged) if it would
        exceed `max_size()`."""
        var n = len(data)
        if n == 0:
            return
        self.ensure_writable(n)
        unsafe_memcpy(
            dest=self._buf.unsafe_ptr().unsafe_offset(self._w),
            src=data.unsafe_ptr(),
            count=n,
        )
        self._w += n

    @inline(.always)
    def write_byte(mut self, b: UInt8) raises IoError:
        self.ensure_writable(1)
        self._buf[self._w] = b
        self._w += 1

    # ---- reading -------------------------------------------------------------

    @inline(.always)
    def consume(mut self, n: Int) raises IoError:
        """Drop `n` readable bytes. `InvalidInput` unless
        `0 <= n <= readable()`. Draining the buffer resets both indices."""
        if n < 0 or n > self._w - self._r:
            raise IoError.of_kind("ByteBuffer.consume", ErrorKind.InvalidInput)
        comptime if CHECK_SPANS:
            _poison(self._buf, self._r, self._r + n)
        self._r += n
        if self._r == self._w:
            self._r = 0
            self._w = 0

    def read_bytes(mut self, n: Int) raises IoError -> List[UInt8]:
        """Copy out and consume the first `n` readable bytes.
        `InvalidInput` unless `0 <= n <= readable()`."""
        if n < 0 or n > self._w - self._r:
            raise IoError.of_kind(
                "ByteBuffer.read_bytes", ErrorKind.InvalidInput
            )
        var out = List[UInt8](unsafe_uninit_length=n)
        if n > 0:
            unsafe_memcpy(
                dest=out.unsafe_ptr(),
                src=self._buf.unsafe_ptr().unsafe_offset(self._r),
                count=n,
            )
        self.consume(n)
        return out^

    def clear(mut self):
        """Drop all readable bytes; keeps the capacity."""
        comptime if CHECK_SPANS:
            _poison(self._buf, self._r, self._w)
        self._r = 0
        self._w = 0

    def discard_read_bytes(mut self) -> Int:
        """Unconditionally move the readable bytes to the front, making the
        consumed prefix writable. Returns the bytes reclaimed."""
        var reclaimed = self._r
        self._compact()
        comptime if CHECK_SPANS:
            self._relocate()
        return reclaimed

    def compact(mut self) -> Bool:
        """`discard_read_bytes` only when worthwhile: something was consumed
        and the copy moves no more bytes than it reclaims. Returns whether
        it compacted."""
        var used = self._w - self._r
        comptime if CHECK_SPANS:
            self._relocate()
        if self._r == 0 or used > self._r:
            return False
        self._compact()
        return True

    def shrink_to(mut self, capacity: Int):
        """Release memory: reallocate to `max(capacity, readable())` bytes
        when that is smaller than the current capacity (for long-lived
        connections after one large message). Negative means 0."""
        var target = max(capacity, self._w - self._r)
        if target >= len(self._buf):
            comptime if CHECK_SPANS:
                self._relocate()
            return
        self._realloc(target)

    # ---- searching -----------------------------------------------------------

    def find(self, byte: UInt8, start: Int = 0) -> Optional[Int]:
        """Offset (from the read index) of the first `byte` at or after
        offset `start`, or None. `start` is clamped to `[0, readable()]`."""
        var lo = self._r + min(max(start, 0), self._w - self._r)
        var i = self._find_abs(byte, lo, self._w)
        if i < 0:
            return None
        return i - self._r

    def find(self, pattern: Span[UInt8, _], start: Int = 0) -> Optional[Int]:
        """Offset (from the read index) of the first occurrence of `pattern`
        starting at or after offset `start`, or None. An empty pattern
        matches at `start` (clamped to `[0, readable()]`).

        First-byte scan plus compare: O(readable * len(pattern)) worst case,
        which is fine for protocol delimiters (`\\r\\n\\r\\n` and similar)."""
        var m = len(pattern)
        var lo = self._r + min(max(start, 0), self._w - self._r)
        if m == 0:
            return lo - self._r
        var last = self._w - m  # last absolute index a match can start at
        var first = pattern[0]
        var p = self._buf.unsafe_ptr()
        var q = pattern.unsafe_ptr()
        var i = lo
        while i <= last:
            i = self._find_abs(first, i, last + 1)
            if i < 0:
                return None
            var k = 1
            while k < m and p[unsafe_offset=i + k] == q[unsafe_offset=k]:
                k += 1
            if k == m:
                return i - self._r
            i += 1
        return None

    def _find_abs(self, byte: UInt8, lo: Int, hi: Int) -> Int:
        """Absolute index of `byte` in `_buf[lo:hi]`, or -1. Skips whole
        SIMD blocks without a match, then finishes byte by byte."""
        var p = self._buf.unsafe_ptr()
        var i = lo
        var splat = SIMD[DType.uint8, _SCAN_WIDTH](byte)
        while i + _SCAN_WIDTH <= hi:
            var v = p.unsafe_load[width=_SCAN_WIDTH](i)
            if v.eq(splat).reduce_or():
                break
            i += _SCAN_WIDTH
        while i < hi:
            if p[unsafe_offset=i] == byte:
                return i
            i += 1
        return -1

    def read_until(
        self, delimiter: UInt8, max_bytes: Int, start: Int = 0
    ) raises IoError -> Optional[Int]:
        """Length of the next frame ending with `delimiter` (delimiter
        included), or None if it is not complete yet. Does not consume:
        take the frame with `readable_span()[:n]` / `read_bytes(n)`.

        Raises `InvalidData` when the frame is, or can only become, longer
        than `max_bytes` (op `"ByteBuffer.read_until(max_bytes)"`), so a peer
        cannot make the caller buffer an unbounded frame. `start` resumes a
        search: after None, pass `readable()` to skip bytes already
        scanned (it is clamped like in `find`). `max_bytes < 1` is a caller
        bug: `InvalidInput` (op `"ByteBuffer.read_until"`)."""
        if max_bytes < 1:
            raise IoError.of_kind(
                "ByteBuffer.read_until", ErrorKind.InvalidInput
            )
        var at = self.find(delimiter, start)
        return _frame_len(at, 1, self._w - self._r, max_bytes)

    def read_until(
        self, delimiter: Span[UInt8, _], max_bytes: Int, start: Int = 0
    ) raises IoError -> Optional[Int]:
        """Like the single-byte `read_until` with a multi-byte delimiter.
        After None, resume with `start = max(0, readable() - len(delimiter)
        + 1)` (a delimiter may straddle the old end). A frame over
        `max_bytes` is `InvalidData`; an empty delimiter or `max_bytes <
        len(delimiter)` is `InvalidInput`."""
        var m = len(delimiter)
        if m == 0 or max_bytes < m:
            raise IoError.of_kind(
                "ByteBuffer.read_until", ErrorKind.InvalidInput
            )
        var at = self.find(delimiter, start)
        return _frame_len(at, m, self._w - self._r, max_bytes)

    # ---- formatting ----------------------------------------------------------

    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            "ByteBuffer(readable=",
            self._w - self._r,
            ", read_index=",
            self._r,
            ", capacity=",
            len(self._buf),
            ", max_size=",
            self._max,
            ")",
        )


def _poison(mut buf: List[UInt8], lo: Int, hi: Int):
    """Check mode: overwrite `buf[lo:hi]` with `POISON`."""
    var p = buf.unsafe_ptr()
    for i in range(lo, hi):
        p[unsafe_offset=i] = POISON


@inline(.always)
def _frame_len(
    at: Optional[Int], dlen: Int, readable: Int, max_bytes: Int
) raises IoError -> Optional[Int]:
    """Shared tail of `read_until`: apply the frame limit to a search
    result (`InvalidData` past it). Without a match, `readable >= max_bytes`
    already proves that the frame (which ends after the readable bytes) is
    too long."""
    if at:
        var n = at.value() + dlen
        if n > max_bytes:
            raise IoError.of_kind(
                "ByteBuffer.read_until(max_bytes)", ErrorKind.InvalidData
            )
        return n
    if readable >= max_bytes:
        raise IoError.of_kind(
            "ByteBuffer.read_until(max_bytes)", ErrorKind.InvalidData
        )
    return None
