"""In-memory network simulator `Driver` (selected by `-D MOJO_TCP_SIM=1`).

`SimDriver` behaves like Linux nonblocking TCP sockets plus edge-triggered
epoll, entirely in memory and on a virtual clock, so `rt.core.Loop` runs
unchanged and deterministically in tests (design contract 7). It imports
only `std`, `linux`, `bytes` and `rt` (never `net`).

## Model
- **Fds** are virtual numbers from `SIM_FD_BASE` upward and are never reused
  within a run, so a stale fd is EBADF instead of someone else's socket.
- **Sockets:** AF_INET/AF_INET6 SOCK_STREAM only. Every address is
  reachable; there is no dual-stack, no TIME_WAIT and no SYN backlog other
  than the listen backlog. Ephemeral ports come from 32768-60999.
- **Segments:** each direction of a connection is a FIFO of segments
  (SYN-ACK, ACK, data, FIN, RST) delivered at
  `max(previous delivery, now + latency + jitter)`, so a stream is never
  reordered. Handshake: the SYN reaches the listener after one one-way
  latency; the SYN-ACK makes the client established (WRITE_READY) after two;
  the ACK puts the server side on the accept queue (listener READ_READY)
  after three. No listener, or a full backlog: ECONNREFUSED (SO_ERROR plus
  an ERR|HUP edge) one latency later. With `config.full_backlog_refuses =
  False` a full backlog drops the SYN instead and the client retransmits
  (`syn_rto_ns`, doubling) until `syn_retries`, then fails with ETIMEDOUT.
- **Flow control:** a direction holds at most `sndbuf(sender) +
  rcvbuf(receiver)` bytes (in flight plus unread). `send` takes what fits
  (a partial write) or returns EAGAIN. WRITE_READY is reported once a
  quarter of that capacity is free (like Linux's `sk_stream_min_wspace`).
  SO_SNDBUF/SO_RCVBUF are doubled like Linux does; other options are
  accepted and ignored.
- **Close and reset:** close with unread received data sends RST, otherwise
  FIN (after the data already sent). Data or a SYN-ACK reaching a closed
  socket is answered with RST. Closing a listener resets every connection it
  has not handed out. A socket that receives RST reads what was delivered,
  then ECONNRESET once, then EOF (EOF at once if a FIN came first); send
  returns ECONNRESET once, then EPIPE (Linux's `sock_error`-then-EPIPE).
- **Readiness:** `register` and every state change put the socket on a
  ready list (one entry per fd, FIFO), and `wait` reports each entry with
  the socket's *current* mask, exactly as epoll's ET ready list does
  (entries whose mask is 0 are skipped; at most `config.max_events` per
  wait, the rest stay queued). Masks follow `tcp_poll`: READ_READY for
  data, EOF or reset; READ_CLOSED once the read side is shut; WRITE_READY
  for room or a shut write side; HANGUP when both sides are shut or the
  connection is dead; ERROR while SO_ERROR is set. A new socket in the
  CLOSE state reports WRITE_READY|HANGUP, a connecting one nothing.

## Test access
`EventLoop.driver` has the trait type, so a test (named `test_*_sim.mojo`,
built only with -D MOJO_TCP_SIM=1) reaches the simulator with
`rebind[SimDriver](ev.driver)`, e.g. to set `config`, `faults` or the seed
right after creating the loop and to read `stats` and `trace_hash()`.

## Virtual time
`now()` starts at `SIM_START_NS` and moves only inside `wait`, which never
sleeps: it delivers what is due and, while nothing is ready, jumps to the
next scheduled segment or to `now + timeout`, whichever comes first.
`timeout = 0` only delivers what is already due. `timeout < 0` with nothing
ready and nothing scheduled raises `IoError(Other, "SimDriver.wait:
deadlock")`, because a real program would hang there forever.

## Determinism
All randomness comes from one xoshiro256** generator (seeded through
splitmix64) from `MOJO_TCP_SIM_SEED` (decimal; any other text is hashed) or
`DEFAULT_SIM_SEED`. Probabilities that are 0 or 1 draw nothing, so turning a
fault off does not shift the rest of the stream. With the same seed the same
program sees the same syscall results, delivery times and event order;
`trace_hash()` folds every syscall result and every reported event (with its
virtual time) into 64 bits so tests can assert replay. Reproduce a failing
run with `MOJO_TCP_SIM_SEED=<seed>`.

## Faults (`SimDriver.faults`, probabilities in [0, 1])
Every fault stays inside the kernel contract an edge-triggered proactor
relies on: whenever a call reports less than what is really available
(EAGAIN, a short read, a short write) while readiness still exists, the fd
is put back on the ready list, so a later `wait` reports it again.
- `short_write` (per send): take a random 1..n-1 of the n bytes that would
  fit. Room remains, so a WRITE_READY edge follows (or arrives when the
  reader frees a quarter of the capacity).
- `short_read` (per recv): return a random 1..n-1 of the n bytes that would
  fit. Data remains, so a READ_READY edge follows.
- `spurious_eagain` (per recv with data / send with room): return EAGAIN;
  an edge follows.
- `spurious_edges` (per wait): add one random registered fd to the batch
  with READ_READY and/or WRITE_READY although nothing changed (it may well
  have nothing ready: code must tolerate EAGAIN after any edge). It is only
  added to a wait that returns anyway, so it never hides a deadlock or
  stalls virtual time. A connecting socket only ever gets READ_READY: Linux
  never reports EPOLLOUT for SYN_SENT, and connect completion is detected
  by EPOLLOUT.
- `shuffle` (per wait): shuffle the order of the reported fds.
- `accept_error` (per accept with a queued connection): EMFILE, repeated
  for 1-3 calls; the connections stay queued and the listener stays on the
  ready list.
- `accept_abort` (per accept with a queued connection): ECONNABORTED; the
  head connection is discarded and its client gets RST (accept(2): "a
  connection has been aborted").
- `random_reset` (per send/recv on an established connection): the
  connection is reset at both ends at once (a middlebox RST): both see
  ECONNRESET, data in flight is lost, data already delivered stays readable.
- `drop_syn` (per connect): the SYN is lost and never retransmitted, so the
  connect stays in progress until the application gives up (cancel or
  close). Without a timer of its own the loop then reports a deadlock.
The first six never fail a connection (`SimFaults.benign(p)` enables them);
the last three do (`SimFaults.all(p, fatal)`), so a test that enables them
must accept resets, aborts and timeouts.
Probability 1.0 is for unit tests of single calls: `spurious_eagain` and
`accept_error` at 1.0 starve all progress (every retry fails again).
"""

from std.os import getenv

from bytes.buffer import ByteBuffer
from linux import ErrorKind, Errno, IoError, Instant
from linux.abi import RawSockaddr
from linux.consts import (
    AF_INET,
    AF_INET6,
    SHUT_RD,
    SHUT_RDWR,
    SHUT_WR,
    SO_RCVBUF,
    SO_REUSEADDR,
    SO_REUSEPORT,
    SO_SNDBUF,
    SOCK_STREAM,
    SOL_SOCKET,
)

from .driver import (
    ERROR,
    HANGUP,
    READ_CLOSED,
    READ_READY,
    WRITE_READY,
    Driver,
    ReadyEvent,
)
from .timers import TimerHeap

comptime SIM_FD_BASE = 1_000_000
"""First virtual fd; fds count up from here and are never reused."""
comptime SIM_START_NS = 1_000_000_000_000
"""Virtual time at creation (non-zero, like a real monotonic clock)."""
comptime DEFAULT_SIM_SEED: UInt64 = 0x5EED_2024_0001
comptime SIM_SEED_ENV = "MOJO_TCP_SIM_SEED"

comptime _EPHEMERAL_LO = 32768
comptime _EPHEMERAL_HI = 60999
comptime _SOMAXCONN = 4096
comptime _MIN_SNDBUF = 4608
comptime _MIN_RCVBUF = 2304

# ---- statistics keys ---------------------------------------------------------

comptime SYS_SOCKET = 0
comptime SYS_SETSOCKOPT = 1
comptime SYS_BIND = 2
comptime SYS_LISTEN = 3
comptime SYS_GETSOCKNAME = 4
comptime SYS_ACCEPT = 5
comptime SYS_CONNECT = 6
comptime SYS_SO_ERROR = 7
comptime SYS_RECV = 8
comptime SYS_SEND = 9
comptime SYS_SHUTDOWN = 10
comptime SYS_CLOSE = 11
comptime SYS_REGISTER = 12
comptime SYS_DEREGISTER = 13
comptime SYS_WAIT = 14
comptime SYS_KINDS = 15

comptime FAULT_SHORT_WRITE = 0
comptime FAULT_SHORT_READ = 1
comptime FAULT_EAGAIN = 2
comptime FAULT_SPURIOUS_EDGE = 3
comptime FAULT_SHUFFLE = 4
comptime FAULT_ACCEPT_ERROR = 5
comptime FAULT_ACCEPT_ABORT = 6
comptime FAULT_RESET = 7
comptime FAULT_DROP_SYN = 8
comptime FAULT_KINDS = 9


def sys_name(k: Int) -> StaticString:
    if k == SYS_SOCKET:
        return "socket"
    if k == SYS_SETSOCKOPT:
        return "setsockopt"
    if k == SYS_BIND:
        return "bind"
    if k == SYS_LISTEN:
        return "listen"
    if k == SYS_GETSOCKNAME:
        return "getsockname"
    if k == SYS_ACCEPT:
        return "accept"
    if k == SYS_CONNECT:
        return "connect"
    if k == SYS_SO_ERROR:
        return "so_error"
    if k == SYS_RECV:
        return "recv"
    if k == SYS_SEND:
        return "send"
    if k == SYS_SHUTDOWN:
        return "shutdown"
    if k == SYS_CLOSE:
        return "close"
    if k == SYS_REGISTER:
        return "register"
    if k == SYS_DEREGISTER:
        return "deregister"
    if k == SYS_WAIT:
        return "wait"
    return "?"


def fault_name(k: Int) -> StaticString:
    if k == FAULT_SHORT_WRITE:
        return "short_write"
    if k == FAULT_SHORT_READ:
        return "short_read"
    if k == FAULT_EAGAIN:
        return "spurious_eagain"
    if k == FAULT_SPURIOUS_EDGE:
        return "spurious_edge"
    if k == FAULT_SHUFFLE:
        return "shuffle"
    if k == FAULT_ACCEPT_ERROR:
        return "accept_error"
    if k == FAULT_ACCEPT_ABORT:
        return "accept_abort"
    if k == FAULT_RESET:
        return "random_reset"
    if k == FAULT_DROP_SYN:
        return "drop_syn"
    return "?"


# ---- deterministic randomness -----------------------------------------------


@inline(.always)
def _splitmix(mut x: UInt64) -> UInt64:
    x += 0x9E3779B97F4A7C15
    var z = x
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
    z = (z ^ (z >> 27)) * 0x94D049BB133111EB
    return z ^ (z >> 31)


@inline(.always)
def _rotl(x: UInt64, k: UInt64) -> UInt64:
    return (x << k) | (x >> (64 - k))


struct SimRng(TrivialRegisterPassable):
    """xoshiro256** seeded through splitmix64."""

    var _s0: UInt64
    var _s1: UInt64
    var _s2: UInt64
    var _s3: UInt64

    def __init__(out self, seed: UInt64):
        var x = seed
        self._s0 = _splitmix(x)
        self._s1 = _splitmix(x)
        self._s2 = _splitmix(x)
        self._s3 = _splitmix(x)

    def next(mut self) -> UInt64:
        var r = _rotl(self._s1 * 5, 7) * 9
        var t = self._s1 << 17
        self._s2 ^= self._s0
        self._s3 ^= self._s1
        self._s1 ^= self._s2
        self._s0 ^= self._s3
        self._s2 ^= t
        self._s3 = _rotl(self._s3, 45)
        return r

    def below(mut self, n: Int) -> Int:
        """Uniform in [0, n); 0 (no draw) for n <= 1."""
        if n <= 1:
            return 0
        return Int(self.next() % UInt64(n))

    def unit(mut self) -> Float64:
        """Uniform in [0, 1)."""
        return Float64(self.next() >> 11) * (1.0 / 9007199254740992.0)

    def chance(mut self, p: Float64) -> Bool:
        """True with probability `p`; draws nothing when p <= 0 or p >= 1."""
        if p <= 0.0:
            return False
        if p >= 1.0:
            return True
        return self.unit() < p


def sim_seed_from_env() -> UInt64:
    """`MOJO_TCP_SIM_SEED` as a decimal number (any other text is hashed),
    or `DEFAULT_SIM_SEED` when unset or empty."""
    var s = getenv(SIM_SEED_ENV)
    var b = s.as_bytes()
    if len(b) == 0:
        return DEFAULT_SIM_SEED
    var v: UInt64 = 0
    var digits = True
    for i in range(len(b)):
        var c = b[i]
        if c < 48 or c > 57:
            digits = False
            break
        v = v * 10 + UInt64(c - 48)
    if digits:
        return v
    var h: UInt64 = 0xCBF29CE484222325
    for i in range(len(b)):
        h = (h ^ UInt64(b[i])) * 0x100000001B3
    return h


# ---- configuration -----------------------------------------------------------


struct SimConfig(TrivialRegisterPassable):
    """Network parameters. Buffer sizes apply to sockets created later."""

    var latency_ns: Int
    """One-way delay of every segment."""
    var jitter_ns: Int
    """Extra uniform delay in [0, jitter_ns] per segment (FIFO preserved)."""
    var sndbuf: Int
    var rcvbuf: Int
    var max_events: Int
    """Events reported per wait at most (epoll's maxevents)."""
    var full_backlog_refuses: Bool
    """A SYN to a full backlog is refused (True) or dropped and retried."""
    var syn_retries: Int
    var syn_rto_ns: Int

    def __init__(
        out self,
        *,
        latency_ns: Int = 50_000,
        jitter_ns: Int = 20_000,
        sndbuf: Int = 256 * 1024,
        rcvbuf: Int = 256 * 1024,
        max_events: Int = 1024,
        full_backlog_refuses: Bool = True,
        syn_retries: Int = 6,
        syn_rto_ns: Int = 1_000_000_000,
    ):
        self.latency_ns = latency_ns
        self.jitter_ns = jitter_ns
        self.sndbuf = sndbuf
        self.rcvbuf = rcvbuf
        self.max_events = max_events
        self.full_backlog_refuses = full_backlog_refuses
        self.syn_retries = syn_retries
        self.syn_rto_ns = syn_rto_ns


struct SimFaults(TrivialRegisterPassable):
    """Fault probabilities (see the module docstring for each guarantee)."""

    var short_write: Float64
    var short_read: Float64
    var spurious_eagain: Float64
    var spurious_edges: Float64
    var shuffle: Float64
    var accept_error: Float64
    var accept_abort: Float64
    var random_reset: Float64
    var drop_syn: Float64

    def __init__(
        out self,
        *,
        short_write: Float64 = 0.0,
        short_read: Float64 = 0.0,
        spurious_eagain: Float64 = 0.0,
        spurious_edges: Float64 = 0.0,
        shuffle: Float64 = 0.0,
        accept_error: Float64 = 0.0,
        accept_abort: Float64 = 0.0,
        random_reset: Float64 = 0.0,
        drop_syn: Float64 = 0.0,
    ):
        self.short_write = short_write
        self.short_read = short_read
        self.spurious_eagain = spurious_eagain
        self.spurious_edges = spurious_edges
        self.shuffle = shuffle
        self.accept_error = accept_error
        self.accept_abort = accept_abort
        self.random_reset = random_reset
        self.drop_syn = drop_syn

    @staticmethod
    def benign(p: Float64) -> SimFaults:
        """Every fault that never fails a connection, at probability `p`."""
        return SimFaults(
            short_write=p,
            short_read=p,
            spurious_eagain=p,
            spurious_edges=p,
            shuffle=p,
            accept_error=p,
        )

    @staticmethod
    def all(p: Float64, fatal: Float64) -> SimFaults:
        """`benign(p)` plus the connection-failing faults at `fatal`."""
        var f = SimFaults.benign(p)
        f.accept_abort = fatal
        f.random_reset = fatal
        f.drop_syn = fatal
        return f


struct SimStats(Copyable, Movable, Writable):
    """Counters for tests: syscalls by kind (`SYS_*`), faults injected by
    kind (`FAULT_*`) and bytes moved."""

    var syscalls: List[Int]
    var faults: List[Int]
    var bytes_sent: Int
    """Accepted by send."""
    var bytes_received: Int
    """Returned by recv."""
    var bytes_dropped: Int
    """Lost in flight or unread at close (resets)."""
    var edges: Int
    """Events reported by wait."""
    var accepted: Int
    var connects_failed: Int
    """Refused or timed out."""
    var resets: Int
    """Sockets that were reset."""

    def __init__(out self):
        self.syscalls = List[Int](length=SYS_KINDS, fill=0)
        self.faults = List[Int](length=FAULT_KINDS, fill=0)
        self.bytes_sent = 0
        self.bytes_received = 0
        self.bytes_dropped = 0
        self.edges = 0
        self.accepted = 0
        self.connects_failed = 0
        self.resets = 0

    def total_syscalls(self) -> Int:
        var n = 0
        for k in range(SYS_KINDS):
            n += self.syscalls[k]
        return n

    def total_faults(self) -> Int:
        var n = 0
        for k in range(FAULT_KINDS):
            n += self.faults[k]
        return n

    def write_to(self, mut writer: Some[Writer]):
        writer.write("syscalls:")
        for k in range(SYS_KINDS):
            if self.syscalls[k] > 0:
                writer.write(" ", sys_name(k), "=", self.syscalls[k])
        writer.write("; faults:")
        for k in range(FAULT_KINDS):
            if self.faults[k] > 0:
                writer.write(" ", fault_name(k), "=", self.faults[k])
        writer.write(
            "; bytes sent=",
            self.bytes_sent,
            " received=",
            self.bytes_received,
            " dropped=",
            self.bytes_dropped,
            "; edges=",
            self.edges,
            " accepted=",
            self.accepted,
            " connects_failed=",
            self.connects_failed,
            " resets=",
            self.resets,
        )


# ---- addresses ---------------------------------------------------------------


@fieldwise_init
struct SimAddr(Equatable, TrivialRegisterPassable, Writable):
    """An IP endpoint: v6 bytes 0-7 in `hi`, 8-15 in `lo` (big-endian);
    a v4 address is the low 32 bits of `lo`."""

    var family: Int
    var hi: UInt64
    var lo: UInt64
    var port: Int

    @staticmethod
    def unspecified(family: Int) -> SimAddr:
        return SimAddr(family, 0, 0, 0)

    @staticmethod
    def loopback(family: Int, port: Int) -> SimAddr:
        if family == AF_INET:
            return SimAddr(family, 0, 0x7F000001, port)
        return SimAddr(family, 0, 1, port)

    @inline(.always)
    def is_wildcard(self) -> Bool:
        return self.hi == 0 and self.lo == 0

    @inline(.always)
    def same_ip(self, other: Self) -> Bool:
        return self.hi == other.hi and self.lo == other.lo

    @inline(.always)
    def overlaps(self, other: Self) -> Bool:
        """Same IP, or either one is the wildcard."""
        return self.same_ip(other) or self.is_wildcard() or other.is_wildcard()

    def with_port(self, port: Int) -> SimAddr:
        return SimAddr(self.family, self.hi, self.lo, port)

    def __eq__(self, other: Self) -> Bool:
        return (
            self.family == other.family
            and self.same_ip(other)
            and self.port == other.port
        )

    def write_to(self, mut writer: Some[Writer]):
        if self.family == AF_INET:
            writer.write(
                (self.lo >> 24) & 0xFF,
                ".",
                (self.lo >> 16) & 0xFF,
                ".",
                (self.lo >> 8) & 0xFF,
                ".",
                self.lo & 0xFF,
                ":",
                self.port,
            )
        else:
            writer.write("[", self.hi, ":", self.lo, "]:", self.port)


def _decode(addr: RawSockaddr, mut out: SimAddr) -> Int:
    """Kernel-form sockaddr_in/sockaddr_in6 -> `out`; 0 or -errno. Bytes
    2.. of the storage are `_pad[0..]`."""
    var fam = addr.family()
    var n = addr.socklen()
    ref p = addr.storage._pad
    var port = (Int(p[0]) << 8) | Int(p[1])
    if fam == AF_INET:
        if n < 16:
            return -Int(Errno.EINVAL.value)
        var ip: UInt64 = 0
        for k in range(4):
            ip = (ip << 8) | UInt64(p[2 + k])
        out = SimAddr(AF_INET, 0, ip, port)
        return 0
    if fam == AF_INET6:
        if n < 28:
            return -Int(Errno.EINVAL.value)
        var hi: UInt64 = 0
        var lo: UInt64 = 0
        for k in range(8):
            hi = (hi << 8) | UInt64(p[6 + k])
            lo = (lo << 8) | UInt64(p[14 + k])
        out = SimAddr(AF_INET6, hi, lo, port)
        return 0
    return -Int(Errno.EAFNOSUPPORT.value)


def _encode(a: SimAddr, mut raw: RawSockaddr):
    raw.reset()
    raw.storage.family = UInt16(a.family)
    raw.storage._pad[0] = UInt8((a.port >> 8) & 0xFF)
    raw.storage._pad[1] = UInt8(a.port & 0xFF)
    if a.family == AF_INET:
        for k in range(4):
            raw.storage._pad[2 + k] = UInt8((a.lo >> UInt64(24 - 8 * k)) & 0xFF)
        raw.len = 16
    else:
        for k in range(8):
            raw.storage._pad[6 + k] = UInt8((a.hi >> UInt64(56 - 8 * k)) & 0xFF)
            raw.storage._pad[14 + k] = UInt8(
                (a.lo >> UInt64(56 - 8 * k)) & 0xFF
            )
        raw.len = 28


# ---- sockets -----------------------------------------------------------------

comptime _NEW: UInt8 = 0
comptime _BOUND: UInt8 = 1
comptime _LISTEN: UInt8 = 2
comptime _SYN_SENT: UInt8 = 3
comptime _SYN_RCVD: UInt8 = 4
"""Server side of a handshake in progress (no fd, not yet acceptable)."""
comptime _ESTAB: UInt8 = 5
comptime _CLOSED: UInt8 = 6
"""A connect that failed (refused or timed out)."""

comptime _SEG_SYNACK: UInt8 = 1
comptime _SEG_ACK: UInt8 = 2
comptime _SEG_DATA: UInt8 = 3
comptime _SEG_FIN: UInt8 = 4
comptime _SEG_RST: UInt8 = 5
comptime _SEG_REFUSE: UInt8 = 6
"""RST answering a SYN (no listener / full backlog)."""

comptime _EV_DELIVER = 1
comptime _EV_SYN = 2


@fieldwise_init
struct _Seg(TrivialRegisterPassable):
    var kind: UInt8
    var at: Int
    var len: Int
    """DATA: bytes (taken from the receiver's `fly` buffer)."""


@inline(.always)
def _ev(kind: Int, arg: Int, idx: Int) -> UInt64:
    return (UInt64(kind) << 56) | (UInt64(arg & 0xFF) << 48) | UInt64(idx)


@inline(.always)
def _neg(e: Errno) -> Int:
    return -Int(e.value)


struct _Sock(Movable):
    """One endpoint. Never removed from `SimDriver._socks` (closed ones are
    tombstones), so indices stay valid for in-flight segments."""

    var fd: Int
    """-1 for a server-side connection not yet accepted."""
    var gone: Bool
    """The application no longer owns it (closed, or discarded unaccepted)."""
    var state: UInt8
    var family: Int
    var local: SimAddr
    var remote: SimAddr
    var holds_port: Bool
    var peer: Int
    var listener: Int
    var registered: Bool
    var token: UInt64
    var in_ready: Bool
    var rx: ByteBuffer
    """Delivered, unread bytes."""
    var fly: ByteBuffer
    """Bytes in flight toward this socket (sent by the peer)."""
    var segs: List[_Seg]
    """Segments in flight toward this socket, in delivery order."""
    var seg_head: Int
    var last_at: Int
    var fin_rcvd: Bool
    var rd_shut: Bool
    var wr_shut: Bool
    var reset: Bool
    var rst_sent: Bool
    var err: Int
    """Pending SO_ERROR (positive errno), 0 if none."""
    var sndbuf: Int
    var rcvbuf: Int
    var want_write: Bool
    """A send hit a full buffer: report WRITE_READY when room returns."""
    var reuse_addr: Bool
    var reuse_port: Bool
    var backlog: Int
    var accept_q: List[Int]
    var embryos: List[Int]
    """Listener: every connection not yet accepted (handshaking or queued)."""
    var half_open: Int
    var accept_burst: Int

    def __init__(out self, family: Int, sndbuf: Int, rcvbuf: Int):
        self.fd = -1
        self.gone = False
        self.state = _NEW
        self.family = family
        self.local = SimAddr.unspecified(family)
        self.remote = SimAddr.unspecified(family)
        self.holds_port = False
        self.peer = -1
        self.listener = -1
        self.registered = False
        self.token = 0
        self.in_ready = False
        self.rx = ByteBuffer()
        self.fly = ByteBuffer()
        self.segs = []
        self.seg_head = 0
        self.last_at = 0
        self.fin_rcvd = False
        self.rd_shut = False
        self.wr_shut = False
        self.reset = False
        self.rst_sent = False
        self.err = 0
        self.sndbuf = sndbuf
        self.rcvbuf = rcvbuf
        self.want_write = False
        self.reuse_addr = False
        self.reuse_port = False
        self.backlog = 0
        self.accept_q = []
        self.embryos = []
        self.half_open = 0
        self.accept_burst = 0


def _remove_value(mut l: List[Int], v: Int):
    for k in range(len(l)):
        if l[k] == v:
            _ = l.pop(k)
            return


comptime _TRACE_BASIS: UInt64 = 0xCBF29CE484222325
comptime _TRACE_PRIME: UInt64 = 0x100000001B3


struct SimDriver(Driver):
    """The simulated world: every socket of every simulated host, one
    virtual clock and one random stream.

    `EventLoop.driver` is typed by the `Driver` trait, so tests reach the
    simulator's own members through `rebind[SimDriver](ev.driver)` (a
    compile error unless built with -D MOJO_TCP_SIM=1): set `config`,
    `faults` and the seed before any activity; read `stats`,
    `trace_hash()`, `open_sockets()`; force `reset_connection(fd)`."""

    var config: SimConfig
    var faults: SimFaults
    var stats: SimStats
    var _now: Int
    var _seed: UInt64
    var _rng: SimRng
    var _trace: UInt64
    var _socks: List[_Sock]
    var _fd_idx: List[Int]
    """fd - SIM_FD_BASE -> socket index."""
    var _ports: List[Int]
    """Sockets holding a bound port."""
    var _listeners: List[Int]
    var _events: TimerHeap
    """(time, seq, _ev(kind, arg, socket)): deliveries and SYNs."""
    var _ready: List[Int]
    var _next_port: Int

    def __init__(out self, seed: UInt64 = DEFAULT_SIM_SEED):
        self.config = SimConfig()
        self.faults = SimFaults()
        self.stats = SimStats()
        self._now = SIM_START_NS
        self._seed = seed
        self._rng = SimRng(seed)
        self._trace = _TRACE_BASIS
        self._socks = []
        self._fd_idx = []
        self._ports = []
        self._listeners = []
        self._events = TimerHeap()
        self._ready = []
        self._next_port = _EPHEMERAL_LO

    @staticmethod
    def create() raises IoError -> Self:
        return Self(sim_seed_from_env())

    # ---- test controls -------------------------------------------------------

    def seed(self) -> UInt64:
        return self._seed

    def set_seed(mut self, seed: UInt64):
        """Restart the random stream (call before any activity to replay)."""
        self._seed = seed
        self._rng = SimRng(seed)

    def trace_hash(self) -> UInt64:
        """Rolling hash of every syscall result and reported event."""
        return self._trace

    def scheduled(self) -> Int:
        """Deliveries and SYNs still scheduled (some may be stale)."""
        return len(self._events)

    def open_sockets(self) -> Int:
        """Fds the application still owns (leak checks)."""
        var n = 0
        for k in range(len(self._fd_idx)):
            if not self._socks[self._fd_idx[k]].gone:
                n += 1
        return n

    def reset_connection(mut self, fd: Int32) -> Bool:
        """Reset the connection `fd` belongs to at both ends now (what
        `random_reset` does). False if it is not an established socket."""
        var i = self._lookup(fd)
        if i < 0:
            return False
        return self._abort(i)

    # ---- bookkeeping ---------------------------------------------------------

    @inline(.always)
    def _mix(mut self, w: UInt64):
        var h = (self._trace ^ w) * _TRACE_PRIME
        self._trace = h ^ (h >> 29)

    def _rec(mut self, kind: Int, fd: Int32, res: Int) -> Int:
        self.stats.syscalls[kind] += 1
        self._mix(UInt64(kind))
        self._mix(UInt64(Int(fd)))
        self._mix(UInt64(res))
        return res

    @inline(.always)
    def _fault(mut self, kind: Int):
        self.stats.faults[kind] += 1
        self._mix(UInt64(0xFA17_0000 + kind))

    def _new_sock(mut self, family: Int) -> Int:
        self._socks.append(
            _Sock(family, self.config.sndbuf, self.config.rcvbuf)
        )
        return len(self._socks) - 1

    def _alloc_fd(mut self, i: Int) -> Int:
        var fd = SIM_FD_BASE + len(self._fd_idx)
        self._fd_idx.append(i)
        self._socks[i].fd = fd
        return fd

    def _lookup(self, fd: Int32) -> Int:
        """Socket index of an open fd, or -1."""
        var k = Int(fd) - SIM_FD_BASE
        if k < 0 or k >= len(self._fd_idx):
            return -1
        var i = self._fd_idx[k]
        if self._socks[i].gone:
            return -1
        return i

    def _delay(mut self) -> Int:
        var d = self.config.latency_ns
        if self.config.jitter_ns > 0:
            d += self._rng.below(self.config.jitter_ns + 1)
        return max(d, 0)

    def _push(mut self, dst: Int, kind: UInt8, n: Int):
        """Send a segment toward socket `dst` (FIFO per direction)."""
        var due = self._now + self._delay()
        var at = max(self._socks[dst].last_at, due)
        self._socks[dst].last_at = at
        self._socks[dst].segs.append(_Seg(kind, at, n))
        self._events.push(at, _ev(_EV_DELIVER, 0, dst))

    def _mark(mut self, i: Int):
        """Wake the fd: put it on the ready list (once) if registered."""
        if not self._socks[i].registered or self._socks[i].in_ready:
            return
        self._socks[i].in_ready = True
        self._ready.append(i)

    def _room(self, i: Int) -> Int:
        var p = self._socks[i].peer
        if p < 0:
            return 0
        return (
            self._socks[i].sndbuf
            + self._socks[p].rcvbuf
            - self._socks[p].fly.readable()
            - self._socks[p].rx.readable()
        )

    def _writable(self, i: Int) -> Bool:
        """Room for at least a quarter of the direction's capacity."""
        var p = self._socks[i].peer
        if p < 0:
            return False
        var cap = self._socks[i].sndbuf + self._socks[p].rcvbuf
        var room = self._room(i)
        return room > 0 and room * 4 >= cap

    def _after_block(mut self, i: Int):
        """A send on `i` returned EAGAIN or took less than offered: make
        sure a WRITE_READY edge follows."""
        if self._writable(i):
            self._mark(i)
        else:
            self._socks[i].want_write = True

    def _wake(mut self, i: Int):
        """Report WRITE_READY on `i` if a send blocked and room is back."""
        if self._socks[i].want_write and self._writable(i):
            self._socks[i].want_write = False
            self._mark(i)

    def _wake_writer(mut self, i: Int):
        """Room toward `i` grew: wake its peer if it was blocked."""
        var p = self._socks[i].peer
        if p >= 0:
            self._wake(p)

    def _mask(self, i: Int) -> UInt32:
        """The socket's current readiness, as tcp_poll computes it."""
        ref s = self._socks[i]
        if s.gone:
            return 0
        var st = s.state
        if st == _LISTEN:
            return READ_READY if len(s.accept_q) > 0 else UInt32(0)
        if st == _SYN_SENT or st == _SYN_RCVD:
            return 0
        if st == _NEW or st == _BOUND:
            return WRITE_READY | HANGUP
        var m: UInt32 = 0
        if s.err != 0:
            m |= ERROR
        var rd_done = s.fin_rcvd or s.rd_shut or s.reset
        if s.rx.readable() > 0 or rd_done:
            m |= READ_READY
        if rd_done:
            m |= READ_CLOSED
        if s.wr_shut or s.reset or self._writable(i):
            m |= WRITE_READY
        if s.reset or (rd_done and s.wr_shut):
            m |= HANGUP
        return m

    def _release_port(mut self, i: Int):
        if self._socks[i].holds_port:
            self._socks[i].holds_port = False
            _remove_value(self._ports, i)

    def _port_taken(self, i: Int, a: SimAddr, strict: Bool) -> Bool:
        """Does another socket hold `a`'s port on an overlapping IP?
        `strict` ignores SO_REUSEADDR/SO_REUSEPORT (ephemeral picks)."""
        for k in range(len(self._ports)):
            var j = self._ports[k]
            if j == i:
                continue
            ref s = self._socks[j]
            if s.family != a.family or s.local.port != a.port:
                continue
            if not s.local.overlaps(a):
                continue
            if not strict:
                if s.reuse_port and self._socks[i].reuse_port:
                    continue
                if (
                    s.reuse_addr
                    and self._socks[i].reuse_addr
                    and s.state != _LISTEN
                ):
                    continue
            return True
        return False

    def _ephemeral(mut self, i: Int, a: SimAddr) -> Int:
        var span = _EPHEMERAL_HI - _EPHEMERAL_LO + 1
        for _ in range(span):
            var port = self._next_port
            self._next_port = (
                _EPHEMERAL_LO if port >= _EPHEMERAL_HI else port + 1
            )
            if not self._port_taken(i, a.with_port(port), True):
                return port
        return -1

    def _find_listener(mut self, dst: SimAddr) -> Int:
        """The listener a SYN to `dst` reaches: exact IP before wildcard,
        a random one among SO_REUSEPORT siblings."""
        var exact = List[Int]()
        var wild = List[Int]()
        for k in range(len(self._listeners)):
            var j = self._listeners[k]
            ref s = self._socks[j]
            if s.gone or s.family != dst.family or s.local.port != dst.port:
                continue
            if s.local.same_ip(dst):
                exact.append(j)
            elif s.local.is_wildcard():
                wild.append(j)
        if len(exact) > 0:
            return exact[self._rng.below(len(exact))]
        if len(wild) > 0:
            return wild[self._rng.below(len(wild))]
        return -1

    # ---- connection state changes --------------------------------------------

    def _send_rst(mut self, i: Int):
        if self._socks[i].rst_sent:
            return
        self._socks[i].rst_sent = True
        var p = self._socks[i].peer
        if p >= 0:
            self._push(p, _SEG_RST, 0)

    def _on_reset(mut self, i: Int, e: Errno):
        self._socks[i].reset = True
        if self._socks[i].err == 0:
            self._socks[i].err = Int(e.value)
        self.stats.resets += 1
        self._mark(i)

    def _drop_embryo(mut self, i: Int):
        """A handshaking server-side connection dies silently (Linux drops
        the request sock; the application never sees it)."""
        self._socks[i].gone = True
        self._socks[i].reset = True
        self._socks[i].rst_sent = True
        var l = self._socks[i].listener
        self._socks[i].listener = -1
        if l >= 0 and not self._socks[l].gone:
            self._socks[l].half_open -= 1
            _remove_value(self._socks[l].embryos, i)

    def _fail_connect(mut self, i: Int, e: Errno):
        self._socks[i].state = _CLOSED
        self._socks[i].reset = True
        self._socks[i].rst_sent = True
        self._socks[i].err = Int(e.value)
        self._release_port(i)
        self.stats.connects_failed += 1
        self._mark(i)

    def _abort(mut self, i: Int) -> Bool:
        """Reset both ends of `i`'s connection now."""
        if self._socks[i].state != _ESTAB or self._socks[i].reset:
            return False
        self._socks[i].rst_sent = True
        self._on_reset(i, Errno.ECONNRESET)
        var p = self._socks[i].peer
        if p >= 0 and not self._socks[p].gone and not self._socks[p].reset:
            self._socks[p].rst_sent = True
            if self._socks[p].state == _SYN_RCVD:
                self._drop_embryo(p)
            else:
                self._on_reset(p, Errno.ECONNRESET)
        return True

    def _close(mut self, i: Int):
        var st = self._socks[i].state
        self._socks[i].gone = True
        self._socks[i].registered = False
        self._release_port(i)
        if st == _LISTEN:
            _remove_value(self._listeners, i)
            var kids = self._socks[i].embryos.copy()
            self._socks[i].embryos.clear()
            self._socks[i].accept_q.clear()
            self._socks[i].half_open = 0
            for k in range(len(kids)):
                var e = kids[k]
                self._socks[e].listener = -1
                if not self._socks[e].gone:
                    self._socks[e].gone = True
                    self.stats.bytes_dropped += self._socks[e].rx.readable()
                    self._socks[e].rx = ByteBuffer()
                    self._send_rst(e)
        elif st == _ESTAB and not self._socks[i].reset:
            if self._socks[i].rx.readable() > 0:
                self._send_rst(i)  # unread data: abortive close
            elif not self._socks[i].wr_shut:
                self._socks[i].wr_shut = True
                var p = self._socks[i].peer
                if p >= 0:
                    self._push(p, _SEG_FIN, 0)
        self.stats.bytes_dropped += self._socks[i].rx.readable()
        self._socks[i].rx = ByteBuffer()
        if self._socks[i].seg_head >= len(self._socks[i].segs):
            self._socks[i].segs.clear()
            self._socks[i].seg_head = 0
            self._reap(i)

    # ---- delivery ------------------------------------------------------------

    def _run_due(mut self):
        while True:
            var top = self._events.peek()
            if not top or top.value().deadline_ns > self._now:
                return
            var e = self._events.pop()
            var kind = Int(e.op >> 56)
            var arg = Int((e.op >> 48) & 0xFF)
            var idx = Int(e.op & 0xFFFF_FFFF_FFFF)
            if kind == _EV_DELIVER:
                self._deliver(idx)
            elif kind == _EV_SYN:
                self._on_syn(idx, arg)

    def _deliver(mut self, i: Int):
        while True:
            var head = self._socks[i].seg_head
            if head >= len(self._socks[i].segs):
                break
            var seg = self._socks[i].segs[head]
            if seg.at > self._now:
                break
            self._socks[i].seg_head = head + 1
            self._apply(i, seg)
        if self._socks[i].seg_head >= len(self._socks[i].segs):
            self._socks[i].segs.clear()
            self._socks[i].seg_head = 0
            self._reap(i)

    def _reap(mut self, i: Int):
        """Free a closed socket's buffers once nothing is in flight toward
        it (the tombstone itself stays, so indices remain valid)."""
        if self._socks[i].gone and len(self._socks[i].segs) == 0:
            self._socks[i].rx = ByteBuffer()
            self._socks[i].fly = ByteBuffer()
            self._socks[i].segs = List[_Seg]()

    def _apply(mut self, i: Int, seg: _Seg):
        var gone = self._socks[i].gone
        var alive = not gone and not self._socks[i].reset
        var k = seg.kind
        if k == _SEG_DATA:
            if alive:
                ref s = self._socks[i]
                try:
                    s.rx.write_bytes(s.fly.readable_span()[0 : seg.len])
                    s.fly.consume(seg.len)
                except:
                    pass
                self._mark(i)
            else:
                try:
                    self._socks[i].fly.consume(seg.len)
                except:
                    pass
                self.stats.bytes_dropped += seg.len
                if gone:
                    self._send_rst(i)  # data for a closed socket
                self._wake_writer(i)
        elif k == _SEG_FIN:
            if alive:
                self._socks[i].fin_rcvd = True
                self._mark(i)
        elif k == _SEG_RST:
            if alive:
                if self._socks[i].state == _SYN_RCVD:
                    self._drop_embryo(i)
                else:
                    self._on_reset(i, Errno.ECONNRESET)
        elif k == _SEG_SYNACK:
            if gone:
                self._send_rst(i)  # the client gave up meanwhile
            elif alive and self._socks[i].state == _SYN_SENT:
                self._socks[i].state = _ESTAB
                self._mark(i)
                var p = self._socks[i].peer
                if p >= 0:
                    self._push(p, _SEG_ACK, 0)
        elif k == _SEG_ACK:
            if alive and self._socks[i].state == _SYN_RCVD:
                self._socks[i].state = _ESTAB
                var l = self._socks[i].listener
                if l >= 0:
                    self._socks[l].half_open -= 1
                    self._socks[l].accept_q.append(i)
                    self._mark(l)
        elif k == _SEG_REFUSE:
            if alive and self._socks[i].state == _SYN_SENT:
                self._fail_connect(i, Errno.ECONNREFUSED)

    def _on_syn(mut self, c: Int, attempt: Int):
        if self._socks[c].gone or self._socks[c].state != _SYN_SENT:
            return  # the connect was abandoned before its SYN arrived
        var dst = self._socks[c].remote
        var l = self._find_listener(dst)
        if l < 0:
            self._push(c, _SEG_REFUSE, 0)
            return
        var queued = len(self._socks[l].accept_q) + self._socks[l].half_open
        if queued > self._socks[l].backlog:
            if self.config.full_backlog_refuses:
                self._push(c, _SEG_REFUSE, 0)
            elif attempt >= self.config.syn_retries:
                self._fail_connect(c, Errno.ETIMEDOUT)
            else:
                self._events.push(
                    self._now + (self.config.syn_rto_ns << attempt),
                    _ev(_EV_SYN, attempt + 1, c),
                )
            return
        var e = self._new_sock(dst.family)
        var lport = self._socks[l].local.port
        var client_local = self._socks[c].local
        var snd = self._socks[l].sndbuf
        var rcv = self._socks[l].rcvbuf
        self._socks[e].state = _SYN_RCVD
        self._socks[e].local = dst.with_port(lport)
        self._socks[e].remote = client_local
        self._socks[e].peer = c
        self._socks[e].listener = l
        self._socks[e].sndbuf = snd
        self._socks[e].rcvbuf = rcv
        self._socks[c].peer = e
        self._socks[l].half_open += 1
        self._socks[l].embryos.append(e)
        self._push(c, _SEG_SYNACK, 0)

    def _spurious(mut self, mut out: List[ReadyEvent], start: Int):
        """Add READ_READY and/or WRITE_READY for a random registered fd to
        this wait's batch (merged if the fd is already in it). Only added to
        a wait that returns anyway, so it can neither keep a deadlocked
        program spinning nor stop virtual time from advancing."""
        var n = len(self._fd_idx)
        if n == 0:
            return
        var i = self._fd_idx[self._rng.below(n)]
        if self._socks[i].gone or not self._socks[i].registered:
            return
        var bits = READ_READY
        if self._socks[i].state != _SYN_SENT:
            var pick = self._rng.below(3)
            if pick == 1:
                bits = WRITE_READY
            elif pick == 2:
                bits = READ_READY | WRITE_READY
        var token = self._socks[i].token
        for k in range(start, len(out)):
            if out[k].token == token:
                out[k].events |= bits
                self._fault(FAULT_SPURIOUS_EDGE)
                return
        if len(out) - start < self.config.max_events:
            out.append(ReadyEvent(token, bits))
            self._fault(FAULT_SPURIOUS_EDGE)

    def _collect(mut self, mut out: List[ReadyEvent], start: Int):
        if len(self._ready) == 0:
            return
        var batch = List[Int]()
        swap(batch, self._ready)
        for j in range(len(batch)):
            var i = batch[j]
            if len(out) - start >= self.config.max_events:
                self._ready.append(i)  # stays queued, in order
                continue
            self._socks[i].in_ready = False
            if self._socks[i].gone or not self._socks[i].registered:
                continue
            var m = self._mask(i)
            if m != 0:
                out.append(ReadyEvent(self._socks[i].token, m))

    # ---- Driver --------------------------------------------------------------

    def now(self) -> Instant:
        return Instant(nanos=self._now)

    def socket(mut self, family: Int, type_: Int) -> Int:
        var r: Int
        if family != AF_INET and family != AF_INET6:
            r = _neg(Errno.EAFNOSUPPORT)
        elif (type_ & 0xF) != SOCK_STREAM:
            r = _neg(Errno.EPROTONOSUPPORT)
        else:
            r = self._alloc_fd(self._new_sock(family))
        return self._rec(SYS_SOCKET, -1, r)

    def set_int_option(
        mut self, fd: Int32, level: Int, name: Int, value: Int32
    ) -> Int:
        var i = self._lookup(fd)
        var r = 0
        if i < 0:
            r = _neg(Errno.EBADF)
        elif level == SOL_SOCKET:
            var v = max(Int(value), 0)
            if name == SO_SNDBUF:
                self._socks[i].sndbuf = max(v * 2, _MIN_SNDBUF)
                self._wake(i)
            elif name == SO_RCVBUF:
                self._socks[i].rcvbuf = max(v * 2, _MIN_RCVBUF)
                self._wake_writer(i)
            elif name == SO_REUSEADDR:
                self._socks[i].reuse_addr = v != 0
            elif name == SO_REUSEPORT:
                self._socks[i].reuse_port = v != 0
        return self._rec(SYS_SETSOCKOPT, fd, r)

    def bind(mut self, fd: Int32, addr: RawSockaddr) -> Int:
        return self._rec(SYS_BIND, fd, self._bind(fd, addr))

    def _bind(mut self, fd: Int32, addr: RawSockaddr) -> Int:
        var i = self._lookup(fd)
        if i < 0:
            return _neg(Errno.EBADF)
        if self._socks[i].state != _NEW:
            return _neg(Errno.EINVAL)
        var a = SimAddr.unspecified(self._socks[i].family)
        var r = _decode(addr, a)
        if r < 0:
            return r
        if a.family != self._socks[i].family:
            return _neg(Errno.EAFNOSUPPORT)
        if a.port == 0:
            var port = self._ephemeral(i, a)
            if port < 0:
                return _neg(Errno.EADDRINUSE)
            a = a.with_port(port)
        elif self._port_taken(i, a, False):
            return _neg(Errno.EADDRINUSE)
        self._socks[i].local = a
        self._socks[i].holds_port = True
        self._ports.append(i)
        self._socks[i].state = _BOUND
        return 0

    def listen(mut self, fd: Int32, backlog: Int) -> Int:
        return self._rec(SYS_LISTEN, fd, self._listen(fd, backlog))

    def _listen(mut self, fd: Int32, backlog: Int) -> Int:
        var i = self._lookup(fd)
        if i < 0:
            return _neg(Errno.EBADF)
        var b = min(max(backlog, 0), _SOMAXCONN)
        var st = self._socks[i].state
        if st == _LISTEN:
            self._socks[i].backlog = b
            return 0
        if st == _NEW:  # autobind, like Linux
            var any = SimAddr.unspecified(self._socks[i].family)
            var port = self._ephemeral(i, any)
            if port < 0:
                return _neg(Errno.EADDRINUSE)
            self._socks[i].local = any.with_port(port)
            self._socks[i].holds_port = True
            self._ports.append(i)
            self._socks[i].state = _BOUND
        elif st != _BOUND:
            return _neg(Errno.EINVAL)
        var me = self._socks[i].local
        for k in range(len(self._listeners)):
            ref o = self._socks[self._listeners[k]]
            if (
                o.family == me.family
                and o.local.port == me.port
                and o.local.overlaps(me)
            ):
                if not (o.reuse_port and self._socks[i].reuse_port):
                    return _neg(Errno.EADDRINUSE)
        self._socks[i].state = _LISTEN
        self._socks[i].backlog = b
        self._listeners.append(i)
        self._mark(i)
        return 0

    def local_addr(mut self, fd: Int32, mut addr: RawSockaddr) -> Int:
        var i = self._lookup(fd)
        var r = 0
        if i < 0:
            r = _neg(Errno.EBADF)
        else:
            _encode(self._socks[i].local, addr)
        return self._rec(SYS_GETSOCKNAME, fd, r)

    def accept(mut self, fd: Int32, mut peer: RawSockaddr) -> Int:
        return self._rec(SYS_ACCEPT, fd, self._accept(fd, peer))

    def _accept(mut self, fd: Int32, mut peer: RawSockaddr) -> Int:
        var i = self._lookup(fd)
        if i < 0:
            return _neg(Errno.EBADF)
        if self._socks[i].state != _LISTEN:
            return _neg(Errno.EINVAL)
        var queued = len(self._socks[i].accept_q) > 0
        if self._socks[i].accept_burst > 0:
            self._socks[i].accept_burst -= 1
            if queued:
                self._mark(i)
            return _neg(Errno.EMFILE)
        if queued and self._rng.chance(self.faults.accept_error):
            self._fault(FAULT_ACCEPT_ERROR)
            self._socks[i].accept_burst = self._rng.below(3)
            self._mark(i)
            return _neg(Errno.EMFILE)
        if queued and self._rng.chance(self.faults.accept_abort):
            self._fault(FAULT_ACCEPT_ABORT)
            var e = self._socks[i].accept_q.pop(0)
            _remove_value(self._socks[i].embryos, e)
            self._socks[e].listener = -1
            self._socks[e].gone = True
            self.stats.bytes_dropped += self._socks[e].rx.readable()
            self._socks[e].rx = ByteBuffer()
            self._send_rst(e)
            if len(self._socks[i].accept_q) > 0:
                self._mark(i)
            return _neg(Errno.ECONNABORTED)
        if not queued:
            return _neg(Errno.EAGAIN)
        var e = self._socks[i].accept_q.pop(0)
        _remove_value(self._socks[i].embryos, e)
        self._socks[e].listener = -1
        var nfd = self._alloc_fd(e)
        _encode(self._socks[e].remote, peer)
        self.stats.accepted += 1
        return nfd

    def connect(mut self, fd: Int32, addr: RawSockaddr) -> Int:
        return self._rec(SYS_CONNECT, fd, self._connect(fd, addr))

    def _connect(mut self, fd: Int32, addr: RawSockaddr) -> Int:
        var i = self._lookup(fd)
        if i < 0:
            return _neg(Errno.EBADF)
        var st = self._socks[i].state
        if st == _SYN_SENT:
            return _neg(Errno.EALREADY)
        if st == _ESTAB or st == _LISTEN or st == _SYN_RCVD:
            return _neg(Errno.EISCONN)
        if st == _CLOSED:
            # Reconnecting a socket whose connect failed is not modeled.
            return _neg(Errno.EINVAL)
        var fam = self._socks[i].family
        var dst = SimAddr.unspecified(fam)
        var r = _decode(addr, dst)
        if r < 0:
            return r
        if dst.family != fam:
            return _neg(Errno.EAFNOSUPPORT)
        if dst.is_wildcard():
            dst = SimAddr.loopback(fam, dst.port)
        if not self._socks[i].holds_port:
            var port = self._ephemeral(i, dst)
            if port < 0:
                return _neg(Errno.EADDRNOTAVAIL)
            self._socks[i].local = dst.with_port(port)
            self._socks[i].holds_port = True
            self._ports.append(i)
        elif self._socks[i].local.is_wildcard():
            self._socks[i].local = dst.with_port(self._socks[i].local.port)
        self._socks[i].remote = dst
        self._socks[i].state = _SYN_SENT
        if self._rng.chance(self.faults.drop_syn):
            self._fault(FAULT_DROP_SYN)
        else:
            self._events.push(self._now + self._delay(), _ev(_EV_SYN, 0, i))
        return _neg(Errno.EINPROGRESS)

    def socket_error(mut self, fd: Int32) -> Int:
        var i = self._lookup(fd)
        var r: Int
        if i < 0:
            r = _neg(Errno.EBADF)
        else:
            r = -self._socks[i].err
            self._socks[i].err = 0
        return self._rec(SYS_SO_ERROR, fd, r)

    def recv(mut self, fd: Int32, mut buf: ByteBuffer) -> Int:
        var r = self._recv(fd, buf)
        if r > 0:
            self.stats.bytes_received += r
        return self._rec(SYS_RECV, fd, r)

    def _recv(mut self, fd: Int32, mut buf: ByteBuffer) -> Int:
        var i = self._lookup(fd)
        if i < 0:
            return _neg(Errno.EBADF)
        var st = self._socks[i].state
        if st == _NEW or st == _BOUND or st == _LISTEN:
            return _neg(Errno.ENOTCONN)
        if st == _SYN_SENT:
            return _neg(Errno.EAGAIN)
        if (
            st == _ESTAB
            and not self._socks[i].reset
            and self._rng.chance(self.faults.random_reset)
        ):
            if self._abort(i):
                self._fault(FAULT_RESET)
        var avail = self._socks[i].rx.readable()
        if avail > 0:
            if self._rng.chance(self.faults.spurious_eagain):
                self._fault(FAULT_EAGAIN)
                self._mark(i)
                return _neg(Errno.EAGAIN)
            var room = buf.writable()
            if room <= 0:
                return 0
            var n = min(avail, room)
            if n > 1 and self._rng.chance(self.faults.short_read):
                self._fault(FAULT_SHORT_READ)
                n = 1 + self._rng.below(n - 1)
            try:
                buf.write_bytes(self._socks[i].rx.readable_span()[0:n])
                self._socks[i].rx.consume(n)
            except:
                return _neg(Errno.EFAULT)
            if n < room and self._socks[i].rx.readable() > 0:
                self._mark(i)  # reported less than available: edge again
            self._wake_writer(i)
            return n
        if self._socks[i].fin_rcvd:
            return 0
        if self._socks[i].err != 0:
            var e = self._socks[i].err
            self._socks[i].err = 0
            return -e
        if self._socks[i].reset or self._socks[i].rd_shut:
            return 0
        return _neg(Errno.EAGAIN)

    def send(mut self, fd: Int32, buf: ByteBuffer) -> Int:
        var r = self._send(fd, buf)
        if r > 0:
            self.stats.bytes_sent += r
        return self._rec(SYS_SEND, fd, r)

    def _send(mut self, fd: Int32, buf: ByteBuffer) -> Int:
        var i = self._lookup(fd)
        if i < 0:
            return _neg(Errno.EBADF)
        var st = self._socks[i].state
        if st == _SYN_SENT:
            self._socks[i].want_write = True
            return _neg(Errno.EAGAIN)
        if st == _NEW or st == _BOUND or st == _LISTEN:
            return _neg(Errno.EPIPE)
        if (
            st == _ESTAB
            and not self._socks[i].reset
            and self._rng.chance(self.faults.random_reset)
        ):
            if self._abort(i):
                self._fault(FAULT_RESET)
        if self._socks[i].err != 0:
            var e = self._socks[i].err
            self._socks[i].err = 0
            return -e
        if self._socks[i].reset or self._socks[i].wr_shut:
            return _neg(Errno.EPIPE)
        var n = buf.readable()
        if n == 0:
            return 0
        var room = self._room(i)
        if room <= 0:
            self._socks[i].want_write = True
            return _neg(Errno.EAGAIN)
        if self._rng.chance(self.faults.spurious_eagain):
            self._fault(FAULT_EAGAIN)
            self._after_block(i)
            return _neg(Errno.EAGAIN)
        var k = min(n, room)
        if k > 1 and self._rng.chance(self.faults.short_write):
            self._fault(FAULT_SHORT_WRITE)
            k = 1 + self._rng.below(k - 1)
        var p = self._socks[i].peer
        try:
            self._socks[p].fly.write_bytes(buf.readable_span()[0:k])
        except:
            return _neg(Errno.ENOMEM)
        self._push(p, _SEG_DATA, k)
        if k < n:
            self._after_block(i)
        return k

    def shutdown(mut self, fd: Int32, how: Int) -> Int:
        return self._rec(SYS_SHUTDOWN, fd, self._shutdown(fd, how))

    def _shutdown(mut self, fd: Int32, how: Int) -> Int:
        var i = self._lookup(fd)
        if i < 0:
            return _neg(Errno.EBADF)
        if how != SHUT_RD and how != SHUT_WR and how != SHUT_RDWR:
            return _neg(Errno.EINVAL)
        if self._socks[i].state != _ESTAB or self._socks[i].reset:
            return _neg(Errno.ENOTCONN)
        if how != SHUT_WR:
            self._socks[i].rd_shut = True
        if how != SHUT_RD and not self._socks[i].wr_shut:
            self._socks[i].wr_shut = True
            var p = self._socks[i].peer
            if p >= 0:
                self._push(p, _SEG_FIN, 0)
        self._mark(i)
        return 0

    def close(mut self, fd: Int32) -> Int:
        var i = self._lookup(fd)
        var r = 0
        if i < 0:
            r = _neg(Errno.EBADF)
        else:
            self._close(i)
        return self._rec(SYS_CLOSE, fd, r)

    def register(mut self, fd: Int32, token: UInt64) -> Int:
        var i = self._lookup(fd)
        var r = 0
        if i < 0:
            r = _neg(Errno.EBADF)
        elif self._socks[i].registered:
            r = _neg(Errno.EEXIST)
        else:
            self._socks[i].registered = True
            self._socks[i].token = token
            self._mark(i)  # epoll_ctl(ADD) reports what is already ready
        return self._rec(SYS_REGISTER, fd, r)

    def deregister(mut self, fd: Int32) -> Int:
        var i = self._lookup(fd)
        var r = 0
        if i < 0:
            r = _neg(Errno.EBADF)
        elif not self._socks[i].registered:
            r = _neg(Errno.ENOENT)
        else:
            self._socks[i].registered = False
        return self._rec(SYS_DEREGISTER, fd, r)

    def wait(
        mut self, timeout_ns: Int, mut out: List[ReadyEvent]
    ) raises IoError:
        var start = len(out)
        var deadline = -1
        if timeout_ns > Int.MAX - self._now:
            deadline = Int.MAX
        elif timeout_ns >= 0:
            deadline = self._now + timeout_ns
        while True:
            self._run_due()
            self._collect(out, start)
            if len(out) > start or timeout_ns == 0:
                break
            var top = self._events.peek()
            if not top:
                if deadline < 0:
                    self._mix(0xDEAD10CC)
                    raise IoError.of_kind(
                        "SimDriver.wait: deadlock", ErrorKind.Other
                    )
                self._now = max(self._now, deadline)
                break
            var at = top.value().deadline_ns
            if deadline >= 0 and at > deadline:
                self._now = max(self._now, deadline)
                break
            self._now = max(self._now, at)
        if self._rng.chance(self.faults.spurious_edges):
            self._spurious(out, start)
        var n = len(out) - start
        if n > 1 and self._rng.chance(self.faults.shuffle):
            self._fault(FAULT_SHUFFLE)
            for k in range(n - 1, 0, -1):
                var j = self._rng.below(k + 1)
                var t = out[start + k]
                out[start + k] = out[start + j]
                out[start + j] = t
        self.stats.syscalls[SYS_WAIT] += 1
        self.stats.edges += n
        self._mix(UInt64(SYS_WAIT))
        self._mix(UInt64(self._now))
        for k in range(start, len(out)):
            self._mix(out[k].token)
            self._mix(UInt64(out[k].events))
