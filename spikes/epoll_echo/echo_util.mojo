"""Helpers shared by the epoll echo spike's server and client: command-line
flags, a log-linear latency histogram, slab tokens, and small raw syscalls.

Spike code, not library code: nothing in `src/` imports it.
"""

from std.bit import count_leading_zeros
from std.sys import argv

from linux import Errno, RawFd, sys
from linux.nr import SYS_getpid
from linux.syscall import err_of, is_err, syscall0


@inline(.always)
def getpid() -> Int:
    return syscall0(SYS_getpid)


def emit(var line: String):
    """Write `line` + newline to stdout with raw write(2) calls.

    Not `print(..., flush=True)`: in Mojo 1.2.0rc2 that segfaults
    (fclose(NULL)) when the process has no free descriptor, which is exactly
    the moment a server logs EMFILE. Plain write needs no new fd and is
    never buffered, so bench.py sees every line when it is written."""
    line += "\n"
    var b = line.as_bytes()
    var off = 0
    while off < len(b):
        var r = sys.write(RawFd(1), b[off:])
        if is_err(r):
            if Errno(err_of(r)) == Errno.EINTR:
                continue
            return  # stdout gone: nothing useful to do in a benchmark
        off += r


# ---- slab tokens (design contract 3) -----------------------------------------

comptime LISTENER_TOKEN: UInt64 = 0xFFFF_FFFF_FFFF_FFFF
"""epoll data of the listening socket. Slot index 0xFFFFFFFF is never
allocated, so no connection token can collide with it."""

comptime MAX_SLOTS = 0xFFFF_FFFF


@inline(.always)
def token(slot: Int, gen: UInt32) -> UInt64:
    """epoll data for a connection: `generation << 32 | slot index`."""
    return (UInt64(gen) << 32) | UInt64(slot)


@inline(.always)
def token_slot(t: UInt64) -> Int:
    return Int(t & 0xFFFF_FFFF)


@inline(.always)
def token_gen(t: UInt64) -> UInt32:
    return UInt32(t >> 32)


# ---- flags -------------------------------------------------------------------


struct Args(Movable):
    """`--name value` options and bare `--flag`s. Unknown names, a missing
    value or a malformed integer are errors: a typo in a benchmark script must
    not silently run the default configuration."""

    var items: List[String]

    def __init__(out self):
        self.items = List[String]()
        var a = argv()
        for i in range(1, len(a)):
            self.items.append(String(a[i]))

    def validate(self, valued: List[String], flags: List[String]) raises:
        var i = 0
        while i < len(self.items):
            var k = self.items[i]
            var known = False
            for v in valued:
                if v == k:
                    if i + 1 >= len(self.items):
                        raise Error("missing value for ", k)
                    known = True
                    i += 1
            for f in flags:
                if f == k:
                    known = True
            if not known:
                raise Error("unknown argument: ", k)
            i += 1

    def _find(self, name: StaticString) -> Int:
        for i in range(len(self.items)):
            if self.items[i] == name:
                return i
        return -1

    def flag(self, name: StaticString) -> Bool:
        return self._find(name) >= 0

    def string(self, name: StaticString, default: StaticString) -> String:
        var i = self._find(name)
        if i < 0 or i + 1 >= len(self.items):
            return String(default)
        return self.items[i + 1]

    def int(self, name: StaticString, default: Int) raises -> Int:
        var i = self._find(name)
        if i < 0 or i + 1 >= len(self.items):
            return default
        try:
            return Int(self.items[i + 1])
        except:
            raise Error("bad integer for ", name, ": ", self.items[i + 1])


# ---- latency histogram -------------------------------------------------------

comptime _SUB = 64
"""Sub-buckets per power of two: values are kept to within 1/64 (1.6%)."""
comptime _SUB_SHIFT = 6
comptime HIST_BUCKETS = _SUB + (64 - _SUB_SHIFT - 1) * _SUB


@inline(.always)
def hist_index(v: Int) -> Int:
    """Bucket of a non-negative value: exact below 64, then 64 linear
    sub-buckets per octave (the HdrHistogram layout, 2 significant digits)."""
    if v < _SUB:
        return v if v > 0 else 0
    var bits = 64 - Int(count_leading_zeros(v))
    var shift = bits - (_SUB_SHIFT + 1)
    return _SUB + shift * _SUB + ((v >> shift) - _SUB)


@inline(.always)
def hist_upper(idx: Int) -> Int:
    """Largest value that lands in bucket `idx`."""
    if idx < _SUB:
        return idx
    var shift = (idx - _SUB) // _SUB
    var m = (idx - _SUB) % _SUB + _SUB
    return ((m + 1) << shift) - 1


struct Hist(Movable):
    """Fixed-size log-linear histogram of nanosecond latencies. Recording is
    two shifts and an increment, so the load generator can afford one sample
    per message; `percentile` reports a bucket's upper bound (never
    optimistic), capped at the exact maximum."""

    var counts: List[Int]
    var total: Int
    var max: Int
    var min: Int
    var sum: Int

    def __init__(out self):
        self.counts = List[Int](length=HIST_BUCKETS, fill=0)
        self.total = 0
        self.max = 0
        self.min = Int.MAX
        self.sum = 0

    @inline(.always)
    def record(mut self, v: Int):
        var x = v if v > 0 else 0
        self.counts[hist_index(x)] += 1
        self.total += 1
        self.sum += x
        if x > self.max:
            self.max = x
        if x < self.min:
            self.min = x

    def percentile(self, p: Float64) -> Int:
        """Value at or below which `p` percent of the samples fall."""
        if self.total == 0:
            return 0
        var rank = Int(Float64(self.total) * p / 100.0 + 0.999999)
        if rank < 1:
            rank = 1
        var seen = 0
        for i in range(len(self.counts)):
            seen += self.counts[i]
            if seen >= rank:
                return min(hist_upper(i), self.max)
        return self.max

    def write_buckets(self, mut out: String):
        """Non-empty buckets as `index:count,...` for merging across client
        processes (spikes/epoll_echo/bench.py)."""
        var first = True
        for i in range(len(self.counts)):
            if self.counts[i] != 0:
                if not first:
                    out += ","
                out += String(i, ":", self.counts[i])
                first = False
