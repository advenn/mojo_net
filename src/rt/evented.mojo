"""Evented TCP connections on the `rt` event loop: the layer HTTP servers and
database drivers build on (docs/rt.md).

A protocol is a `ConnHandler`: per-connection state plus callbacks. The
library owns the socket, the receive/send buffers, the read loop, write
queueing with backpressure, timers and teardown; the handler only reacts:

    struct Echo(ConnHandler, Copyable):
        def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
            conn.write(input.readable_span())
            input.clear()

    var ev = EventLoop()
    var srv = TcpServer[Echo].listen(ev.loop, SocketAddr.parse("127.0.0.1:7000"), Echo())
    ev.run()                         # until srv.shutdown(ev.loop) has drained

Server side, `TcpServer[H]` copies a prototype handler for every accepted
connection. Client side, `dial[H]` (or a stored `Dialer[H]`) connects and
drives the same `Conn` abstraction, returning a `ConnRef[H]` handle.

Callbacks (all run on the loop thread, never re-entrantly):
- `on_open(conn)`: connected/accepted. Write a greeting, set timers.
- `on_data(conn, input)`: new bytes. `input` holds everything received and
  not yet consumed: consume what you parsed (`input.consume(n)`); the rest
  is kept and the next chunk is appended to it, so a frame split across
  reads arrives whole. More than `ConnConfig.max_input` unconsumed bytes
  closes the connection (`InvalidData`). The common case (a whole frame per
  read) copies nothing: the loop's pooled receive buffer *is* `input`.
- `on_drain(conn)`: the write queue fell to `write_low_water` after it had
  exceeded `write_high_water`.
- `on_eof(conn)`: the peer shut down its sending side. Default: `close()`
  (graceful: queued writes are flushed first). Override it to keep writing
  on a half-closed connection.
- `on_idle(conn)`: no traffic for `idle_timeout_ns`. Default: `close()`.
- `on_timer(conn, tag)`: a `conn.set_timer` timer fired.
- `on_shutdown(conn)`: the server started a graceful shutdown.
- `on_close(lp, reason)`: the socket is closed; last callback. The handler
  is destroyed exactly once, after every op of the connection completed.
A callback that raises closes the connection at once (`abort`) with
`CloseReason.ERROR` and the raised `IoError`.

Writes are staged: `conn.write(bytes)` / `conn.out()` append to one output
buffer that is handed to the loop as a single send when the callback
returns (or at `conn.flush()`), so a handler that answers several
pipelined requests in one `on_data` costs one `send` syscall.
`conn.send(var buf)` hands over an owned buffer without copying. Sends
complete in order. `conn.queued()` is what is still in flight.

Backpressure: once more than `write_high_water` bytes are queued, reading
pauses (if `read_backpressure`, the default) until the queue drains to
`write_low_water`; TCP flow control then pushes back on the peer, so a
client that does not read cannot grow the server's memory. Handlers can
also `pause_reading()` / `resume_reading()` themselves. Bytes received
while paused are held (at most one receive chunk) and delivered, together
with any unconsumed input, when reading resumes. A full-duplex *client*
that writes more than the peer will buffer before it reads (an echo test)
must set `read_backpressure=False`, or both sides wait for each other.

Closing: `close()` stops delivering input, flushes queued writes, then
(`lingering_close`, the default) sends FIN and reads and discards until
the peer's EOF before closing the socket: closing with unread input makes
the kernel send RST, which can erase the peer's unread copy of our last
reply (RFC 9112 section 9.6; nginx's `lingering_close`). If the peer sent
EOF first, it closes at once. The whole close is bounded by
`close_linger_ns`, then aborted. `abort()` closes now (RST if input is
unread); queued writes are dropped. `shutdown_write()` sends FIN after
queued writes; reading goes on.

Timeouts: `idle_timeout_ns` (config or `conn.set_idle_timeout`) uses the
lazy-reset pattern of `rt/timers.mojo`: activity only stores a timestamp,
and the single armed timer re-arms itself when it fires early.

Starting other operations from a handler:
- Timers: `conn.set_timer(delay_ns, tag)` -> `on_timer(conn, tag)`;
  `conn.cancel_timer(id)`. They are canceled automatically at close, so
  the handler can never be called after `on_close`.
- Another connection (a proxy, a DB driver connecting to a replica):
  `Dialer[H2]` built at setup and stored in the handler, then
  `dialer.dial(conn.loop(), addr, handler2^)`. Mojo cannot take the address
  of a function from inside a reference cycle with it, so a handler of type
  `H` must not call the convenience `dial[H]` for its own type from its
  callbacks; storing a `Dialer[H]` built outside the callbacks breaks the
  cycle (the same rule as rt's stored Targets).
- Raw rt ops: `conn.loop()` is the `Loop`. A raw op's target must stay valid
  until it completes; the handler's address is stable for the connection's
  life but is freed after `on_close`, so cancel raw ops before then (prefer
  the managed timers above).

Graceful server shutdown (`TcpServer.shutdown(lp, grace_ns)`): the listener
closes; every connection gets `on_shutdown` and is closed as soon as it is
idle (nothing queued to send, no unconsumed input), so in-flight responses
finish; after `grace_ns` the remaining connections are aborted. When the
last one has closed, the server has no pending op and `EventLoop.run()`
returns (if nothing else is pending).

Lifetimes: server and connection state live on the heap, owned by the
loop's pending operations. The `TcpServer` / `ConnRef` handles hold a
reference: dropping a handle never stops anything, and state is freed only
when both the handle is gone and every operation completed. Destroying the
`EventLoop` while operations are pending drops them unreported (rt
`close_all`), which leaks the state rather than freeing it under a pending
op.
"""

from std.memory import OwnedPointer

from bytes.buffer import ByteBuffer
from linux import ErrorKind, Errno, IoError, Instant
from linux.consts import SHUT_WR
from rt.core import RECV_CHUNK, CompleteFn, Completion, FdId, Loop, OpId, OpKind, Target

from net.addr import SocketAddr

comptime NANOS_PER_SEC = 1_000_000_000
comptime DEFAULT_HIGH_WATER = 256 * 1024
"""Queued output above which reading pauses (`ConnConfig.write_high_water`)."""
comptime DEFAULT_MAX_INPUT = 1024 * 1024
"""Unconsumed input above which a connection is closed as InvalidData."""
comptime DEFAULT_LINGER_NS = 10 * NANOS_PER_SEC
"""How long a graceful `close()` waits for queued writes before aborting."""
comptime DEFAULT_GRACE_NS = 30 * NANOS_PER_SEC
"""How long `TcpServer.shutdown` waits for busy connections."""
comptime _POOL_KEEP = 4 * RECV_CHUNK
"""Buffers larger than this are freed instead of recycled into the pool."""

# Completion tags (routing within one op kind).
comptime _TAG_DEADLINE: UInt64 = 1
comptime _TAG_REDELIVER: UInt64 = 2
comptime _TAG_USER: UInt64 = 3
comptime _USER_SHIFT = 8
comptime _STAG_SHUTDOWN: UInt64 = 1
comptime _STAG_GRACE: UInt64 = 2

# Server phases.
comptime _STARTING = 0
comptime _LISTENING = 1
comptime _DRAINING = 2
comptime _CLOSED = 3


# ---- public value types ------------------------------------------------------


@fieldwise_init
struct CloseReason(Copyable, ImplicitlyCopyable, Movable, Writable):
    """Why a connection closed: who started it, and the error if any.
    Compare `code` with the constants (`reason.code == CloseReason.IDLE`).
    (Not register-passable: `IoError` no longer is, linux.error.)"""

    var code: UInt8
    var err: IoError
    """Meaningful for `ERROR` and `CONNECT_FAILED`."""

    comptime NONE: UInt8 = 0
    comptime LOCAL: UInt8 = 1
    """The handler called `close()` / `abort()` first."""
    comptime PEER: UInt8 = 2
    """The peer sent EOF first (then the handler, by default, closed)."""
    comptime IDLE: UInt8 = 3
    """The idle timeout expired."""
    comptime SHUTDOWN: UInt8 = 4
    """The server was shut down."""
    comptime ERROR: UInt8 = 5
    """An I/O error (reset, broken pipe), a raising callback, or input past
    `max_input`; see `err`."""
    comptime CONNECT_FAILED: UInt8 = 6
    """`dial` failed (refused, unreachable); `on_open` was never called."""

    @staticmethod
    @inline(.always)
    def of(code: UInt8) -> Self:
        return Self(code, IoError.of_kind("evented.close", ErrorKind.Closed))

    @staticmethod
    @inline(.always)
    def failure(code: UInt8, err: IoError) -> Self:
        return Self(code, err)

    @inline(.always)
    def is_error(self) -> Bool:
        return self.code == Self.ERROR or self.code == Self.CONNECT_FAILED

    def error(self) -> Optional[IoError]:
        if self.is_error():
            return self.err
        return None

    def name(self) -> StaticString:
        if self.code == Self.LOCAL:
            return "local"
        if self.code == Self.PEER:
            return "peer"
        if self.code == Self.IDLE:
            return "idle"
        if self.code == Self.SHUTDOWN:
            return "shutdown"
        if self.code == Self.ERROR:
            return "error"
        if self.code == Self.CONNECT_FAILED:
            return "connect_failed"
        return "none"

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.name())
        if self.is_error():
            writer.write(" (", self.err, ")")


struct ConnConfig(TrivialRegisterPassable):
    """Per-connection limits. All durations are nanoseconds; 0 disables."""

    var idle_timeout_ns: Int
    var write_high_water: Int
    var write_low_water: Int
    var max_input: Int
    var close_linger_ns: Int
    var read_backpressure: Bool
    var lingering_close: Bool

    def __init__(
        out self,
        *,
        idle_timeout_ns: Int = 0,
        write_high_water: Int = DEFAULT_HIGH_WATER,
        write_low_water: Int = -1,
        max_input: Int = DEFAULT_MAX_INPUT,
        close_linger_ns: Int = DEFAULT_LINGER_NS,
        read_backpressure: Bool = True,
        lingering_close: Bool = True,
    ):
        """`write_low_water < 0` means half the high-water mark."""
        self.idle_timeout_ns = max(0, idle_timeout_ns)
        self.write_high_water = max(1, write_high_water)
        self.write_low_water = (
            self.write_high_water // 2 if write_low_water < 0 else min(
                write_low_water, self.write_high_water
            )
        )
        self.max_input = max(1, max_input)
        self.close_linger_ns = max(0, close_linger_ns)
        self.read_backpressure = read_backpressure
        self.lingering_close = lingering_close


struct ServerConfig(TrivialRegisterPassable):
    var conn: ConnConfig
    """Applied to every accepted connection."""
    var backlog: Int
    var reuse_port: Bool
    var max_connections: Int
    """Connections beyond this are closed at once (0: unlimited)."""

    def __init__(
        out self,
        *,
        conn: ConnConfig = ConnConfig(),
        backlog: Int = 1024,
        reuse_port: Bool = False,
        max_connections: Int = 0,
    ):
        self.conn = conn
        self.backlog = backlog
        self.reuse_port = reuse_port
        self.max_connections = max(0, max_connections)


@fieldwise_init
struct ServerStats(TrivialRegisterPassable, Writable):
    var accepted: Int
    var rejected: Int
    """Closed at accept because of `max_connections` or shutdown."""
    var closed: Int
    var active: Int
    var errors: Int
    """Connections that closed with `CloseReason.ERROR`."""
    var idle_closed: Int
    var bp_pauses: Int
    """Times a connection paused reading because of write backpressure."""

    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            "accepted=", self.accepted, " rejected=", self.rejected,
            " closed=", self.closed, " active=", self.active,
            " errors=", self.errors, " idle_closed=", self.idle_closed,
            " bp_pauses=", self.bp_pauses,
        )


# ---- the handler contract ----------------------------------------------------


trait ConnHandler(Deinitable, Movable):
    """Per-connection protocol logic (see the module docstring). Only
    `on_data` is required."""

    def on_open(mut self, mut conn: Conn) raises IoError:
        pass

    def on_data(mut self, mut conn: Conn, mut input: ByteBuffer) raises IoError:
        """`input`: everything received and not yet consumed. Consume what
        you used; keep spans of it only within this call."""
        ...

    def on_drain(mut self, mut conn: Conn) raises IoError:
        pass

    def on_eof(mut self, mut conn: Conn) raises IoError:
        conn.close()

    def on_idle(mut self, mut conn: Conn) raises IoError:
        conn.close()

    def on_timer(mut self, mut conn: Conn, tag: UInt64) raises IoError:
        pass

    def on_shutdown(mut self, mut conn: Conn) raises IoError:
        pass

    def on_close(mut self, mut lp: Loop, reason: CloseReason):
        pass


# ---- connection state --------------------------------------------------------


def _ignore(ctx: Int, mut lp: Loop, var c: Completion):
    """Target of fire-and-forget ops (cancels, closes of rejected fds)."""
    if c.has_buf():
        lp.recycle(c.take_buf())


@inline(.always)
def _ignore_target() -> Target:
    return Target(_ignore, 0)


struct ConnCore(Movable):
    """The type-independent half of a connection; `Conn` is a view of it.
    Fields every message touches come first (grouping only: no measurable
    difference in bench/rt_microbench.mojo)."""

    # ---- hot: read or written for every message --------------------------
    var opened: Bool
    var recv_inflight: Bool
    """A multishot receive (`Loop.recv_multi`) is armed on the fd."""
    var recv_paused: Bool
    """...and paused in the loop (`pause_recv`), for backpressure."""
    var user_paused: Bool
    var bp_paused: Bool
    var above_hwm: Bool
    var peer_eof: Bool
    var closing: Bool
    var abort_req: Bool
    var close_submitted: Bool
    var closed: Bool
    var wshut_req: Bool
    var wshut_submitted: Bool
    var redeliver: Bool
    var redeliver_posted: Bool
    var eof_pending: Bool
    var draining: Bool
    var released: Bool
    var fd: FdId
    var target: Target
    """The connection's ONE completion target: `_dispatch[H]` + its state."""
    var ops: Int
    """Ops submitted with `target` that have not finally completed."""
    var sends: Int
    var queued: Int
    var last_active: Int
    var bytes_in: Int
    var bytes_out: Int
    var inbuf: ByteBuffer
    """Received, not yet consumed input (capacity 0 when there is none)."""
    var out: ByteBuffer
    """Staged output (capacity 0 until the first write after a flush)."""
    var cfg: ConnConfig
    var timer_op: OpId
    var timer_at: Int
    # ---- cold: setup, timers, close ------------------------------------------
    var self_ctx: Int
    var refs: Int
    var connect_op: OpId
    var close_deadline: Int
    var timers: List[OpId]
    var server: Int
    """Address of the owning `_ServerCore` (0: dialed, or unregistered)."""
    var index: Int
    var reason: CloseReason
    var bp_pauses: Int

    def __init__(out self, cfg: ConnConfig):
        self.fd = FdId.null()
        self.target = _ignore_target()
        self.self_ctx = 0
        self.cfg = cfg
        self.inbuf = ByteBuffer()
        self.out = ByteBuffer()
        self.queued = 0
        self.sends = 0
        self.ops = 0
        self.refs = 0
        self.connect_op = OpId.null()
        self.timer_op = OpId.null()
        self.timer_at = 0
        self.close_deadline = 0
        self.last_active = 0
        self.timers = []
        self.server = 0
        self.index = -1
        self.reason = CloseReason.of(CloseReason.NONE)
        self.bp_pauses = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.opened = False
        self.recv_inflight = False
        self.recv_paused = False
        self.user_paused = False
        self.bp_paused = False
        self.above_hwm = False
        self.peer_eof = False
        self.closing = False
        self.abort_req = False
        self.close_submitted = False
        self.closed = False
        self.wshut_req = False
        self.wshut_submitted = False
        self.redeliver = False
        self.redeliver_posted = False
        self.eof_pending = False
        self.draining = False
        self.released = False


@fieldwise_init
struct _ConnState[H: ConnHandler](Movable):
    var core: ConnCore
    var handler: Self.H


@inline(.always)
def _state[H: ConnHandler](ctx: Int) -> ref[MutUntrackedOrigin] _ConnState[H]:
    return Pointer[_ConnState[H], MutUntrackedOrigin](unsafe_from_address=ctx)[]


@inline(.always)
def _core_at(addr: Int) -> ref[MutUntrackedOrigin] ConnCore:
    return Pointer[ConnCore, MutUntrackedOrigin](unsafe_from_address=addr)[]


def _free_conn[H: ConnHandler](ctx: Int):
    var o = OpaquePointer[MutAnyOrigin](unsafe_from_address=ctx)
    var boxed = OwnedPointer[_ConnState[H]](unsafe_from_opaque_pointer=o)
    _ = boxed^


def _conn_release[H: ConnHandler](ctx: Int):
    ref c = _state[H](ctx).core
    c.refs -= 1
    if c.refs == 0:
        _free_conn[H](ctx)


@inline(.always)
def _recycle(mut lp: Loop, var b: ByteBuffer):
    if b.capacity() <= _POOL_KEEP:
        lp.recycle(b^)


@inline(.always)
def _take(mut b: ByteBuffer) -> ByteBuffer:
    """Move `b` out, leaving an empty, unallocated buffer behind."""
    var out = ByteBuffer()
    swap(out, b)
    return out^


@inline(.always)
def _release(mut lp: Loop, mut b: ByteBuffer):
    """Give `b`'s storage back to the pool (idle connections hold none)."""
    if b.capacity() > 0:
        _recycle(lp, _take(b))


@inline(.always)
def _set_reason(mut c: ConnCore, r: CloseReason):
    if c.reason.code == CloseReason.NONE:
        c.reason = r


@inline(.always)
def _fail(mut c: ConnCore, e: IoError):
    _set_reason(c, CloseReason.failure(CloseReason.ERROR, e))
    c.abort_req = True


@inline(.always)
def _has_input(c: ConnCore) -> Bool:
    return c.inbuf.readable() > 0


@inline(.always)
def _can_deliver(c: ConnCore) -> Bool:
    """Callbacks for received input (data, then EOF) may run."""
    return (
        c.opened
        and not c.closing
        and not c.abort_req
        and not c.close_submitted
        and not c.user_paused
        and not c.bp_paused
    )


@inline(.always)
def _wants_read(c: ConnCore) -> Bool:
    """A receive should be armed."""
    return _can_deliver(c) and not c.peer_eof


@inline(.always)
def _staged(c: ConnCore) -> Int:
    return c.out.readable()


def _submit_send(mut c: ConnCore, mut lp: Loop, var b: ByteBuffer):
    var n = b.readable()
    c.sends += 1
    c.queued += n
    c.ops += 1
    _ = lp.send(c.fd, b^, c.target)
    if c.queued > c.cfg.write_high_water and not c.above_hwm:
        c.above_hwm = True
        if c.cfg.read_backpressure and not c.bp_paused:
            c.bp_paused = True
            c.bp_pauses += 1


def _cancel_timers(mut c: ConnCore, mut lp: Loop):
    if not c.timer_op.is_null():
        _ = lp.cancel(c.timer_op, _ignore_target())
        c.timer_op = OpId.null()
    for i in range(len(c.timers)):
        _ = lp.cancel(c.timers[i], _ignore_target())
    c.timers.clear()


def _submit_close(mut c: ConnCore, mut lp: Loop):
    c.close_submitted = True
    c.closing = True
    _set_reason(c, CloseReason.of(CloseReason.LOCAL))
    _release(lp, c.out)
    _cancel_timers(c, lp)
    if c.fd.is_null():
        # Still connecting: cancel the connect; its completion finishes up.
        if not c.connect_op.is_null():
            _ = lp.cancel(c.connect_op, _ignore_target())
        return
    c.ops += 1
    _ = lp.close(c.fd, c.target)


def _arm_timer(mut c: ConnCore, mut lp: Loop):
    """Keep one deadline timer armed at or before the earliest deadline
    (idle, close linger). Lazy: a timer armed earlier than needed stays and
    re-arms itself when it fires."""
    var want = Int.MAX
    if c.cfg.idle_timeout_ns > 0 and not c.closing:
        want = c.last_active + c.cfg.idle_timeout_ns
    if c.closing and c.close_deadline > 0:
        want = min(want, c.close_deadline)
    if want == Int.MAX:
        return
    if not c.timer_op.is_null():
        if c.timer_at <= want:
            return
        _ = lp.cancel(c.timer_op, _ignore_target())
    c.timer_at = want
    c.ops += 1
    c.timer_op = lp.timeout_at(Instant(nanos=want), c.target, _TAG_DEADLINE)


def _pump(mut c: ConnCore, mut lp: Loop):
    """Turn the connection's flags into ops: flush staged output, write
    shutdown, graceful close, re-arm the receive, keep the timer armed."""
    if c.close_submitted or c.closed:
        return
    if c.abort_req:
        _submit_close(c, lp)
        return
    if not c.opened:
        if c.closing:
            _submit_close(c, lp)  # closed while still connecting
        return
    if _staged(c) > 0:
        if c.wshut_submitted:
            c.out.clear()  # written after shutdown_write: dropped
        else:
            _submit_send(c, lp, _take(c.out))
    if c.wshut_req and not c.wshut_submitted and c.sends == 0:
        # rt runs shutdown at once, so wait until every send has completed.
        c.wshut_submitted = True
        c.ops += 1
        _ = lp.shutdown(c.fd, SHUT_WR, c.target)
    if c.draining and not c.closing and c.sends == 0 and not _has_input(c):
        c.closing = True
        _set_reason(c, CloseReason.of(CloseReason.SHUTDOWN))
    if c.closing:
        if c.close_deadline == 0 and c.cfg.close_linger_ns > 0:
            c.close_deadline = lp.now().as_nanos() + c.cfg.close_linger_ns
        if c.sends == 0:
            if not c.cfg.lingering_close or c.peer_eof:
                _submit_close(c, lp)
                return
            # Lingering close: FIN first, then read and discard until the
            # peer's EOF, so input still in flight cannot turn our close
            # into an RST that may erase the peer's unread data (RFC 9112
            # section 9.6). Bounded by `close_linger_ns`.
            if not c.wshut_submitted:
                c.wshut_submitted = True
                c.ops += 1
                _ = lp.shutdown(c.fd, SHUT_WR, c.target)
            _sync_recv(c, lp, True)
        else:
            _sync_recv(c, lp, False)
    else:
        _sync_recv(c, lp, _wants_read(c))
    _arm_timer(c, lp)


@inline(.always)
def _sync_recv(mut c: ConnCore, mut lp: Loop, want: Bool):
    """Make the loop read iff `want`: one multishot receive per connection,
    armed once and then paused/resumed (no op per chunk)."""
    if want:
        if not c.recv_inflight:
            c.recv_inflight = True
            c.recv_paused = False
            c.ops += 1
            _ = lp.recv_multi(c.fd, c.target)
        elif c.recv_paused:
            c.recv_paused = False
            lp.resume_recv(c.fd)
    elif c.recv_inflight and not c.recv_paused:
        c.recv_paused = True
        lp.pause_recv(c.fd)


# ---- Conn: the handler's view ------------------------------------------------


@fieldwise_init
struct Conn(TrivialRegisterPassable):
    """A connection as seen from a callback (or from a `ConnRef`). Cheap to
    copy; valid while the connection's state lives (inside callbacks, or
    while a `ConnRef` is held). Output is staged and sent when the callback
    returns; call `flush()` when writing from outside a callback."""

    var _c: Pointer[ConnCore, MutUntrackedOrigin]
    var _lp: Pointer[Loop, MutUntrackedOrigin]

    @staticmethod
    @inline(.always)
    def _of(mut core: ConnCore, mut lp: Loop) -> Conn:
        return Conn(
            Pointer(to=core).unsafe_origin_cast[MutUntrackedOrigin](),
            Pointer(to=lp).unsafe_origin_cast[MutUntrackedOrigin](),
        )

    # ---- identity --------------------------------------------------------

    @inline(.always)
    def id(self) -> FdId:
        """The loop's id of the socket (null before connect / after close)."""
        return self._c[].fd

    def peer_addr(self) -> Optional[SocketAddr]:
        var raw = self._lp[].peer_addr(self._c[].fd)
        if not raw:
            return None
        try:
            return SocketAddr.from_raw(raw.value())
        except:
            return None

    @inline(.always)
    def loop(self) -> ref[MutUntrackedOrigin] Loop:
        """The event loop, for ops of your own (see the module docstring)."""
        return self._lp[]

    @inline(.always)
    def now(self) -> Instant:
        """Loop time (read once per iteration)."""
        return self._lp[].now()

    # ---- writing ---------------------------------------------------------

    def _check_writable(self) raises IoError:
        """Writes are accepted until the close (or FIN) is actually
        submitted, so a callback may write its last reply after `close()`
        or `shutdown_write()`; after `abort()` they raise."""
        ref c = self._c[]
        if c.abort_req or c.close_submitted or c.closed:
            raise IoError.of_kind("Conn.write", ErrorKind.Closed)
        if c.wshut_submitted:
            raise IoError.of_kind("Conn.write", ErrorKind.BrokenPipe)

    def out(self) raises IoError -> ref[MutUntrackedOrigin] ByteBuffer:
        """The staged output buffer: append to it (e.g. a codec's
        `poll_transmit(conn.out())`); it is sent when the callback returns."""
        self._check_writable()
        ref c = self._c[]
        if c.out.capacity() == 0:
            c.out = self._lp[].take_buffer()
        return c.out

    def write(self, data: Span[UInt8, _]) raises IoError:
        """Append `data` to the staged output (copied)."""
        self.out().write_bytes(data)

    def write(self, s: StringSlice) raises IoError:
        self.out().write_bytes(s.as_bytes())

    def send(self, var buf: ByteBuffer) raises IoError:
        """Queue an owned buffer as its own send (no copy), after anything
        staged so far."""
        self._check_writable()
        ref c = self._c[]
        if not c.opened:
            self.out().write_bytes(buf.readable_span())
            return
        if _staged(c) > 0:
            _submit_send(c, self._lp[], _take(c.out))
        if buf.readable() > 0:
            _submit_send(c, self._lp[], buf^)

    def flush(self):
        """Submit staged output (and any other pending state change) now.
        Callbacks do this automatically when they return."""
        _pump(self._c[], self._lp[])

    @inline(.always)
    def queued(self) -> Int:
        """Bytes staged or in flight (not yet accepted by the kernel)."""
        return self._c[].queued + _staged(self._c[])

    @inline(.always)
    def is_writable(self) -> Bool:
        """False once staged plus in-flight output exceeds the high-water
        mark: stop writing and wait for `on_drain`."""
        return self.queued() <= self._c[].cfg.write_high_water

    # ---- reading ---------------------------------------------------------

    def pause_reading(self):
        self._c[].user_paused = True

    def resume_reading(self):
        ref c = self._c[]
        if c.user_paused:
            c.user_paused = False
            if _has_input(c):
                c.redeliver = True

    @inline(.always)
    def is_reading(self) -> Bool:
        return _wants_read(self._c[])

    @inline(.always)
    def peer_closed(self) -> Bool:
        """The peer's EOF has been seen."""
        return self._c[].peer_eof

    # ---- closing ---------------------------------------------------------

    def shutdown_write(self):
        """Send FIN once queued writes are done; reading continues."""
        self._c[].wshut_req = True

    def close(self):
        """Graceful: stop delivering input, flush queued writes, FIN, wait
        for the peer's EOF (lingering close), then close; forced after
        `close_linger_ns`."""
        ref c = self._c[]
        if not c.closing:
            c.closing = True
            _set_reason(c, CloseReason.of(CloseReason.LOCAL))

    def abort(self):
        """Close now; queued writes are dropped."""
        ref c = self._c[]
        _set_reason(c, CloseReason.of(CloseReason.LOCAL))
        c.abort_req = True

    @inline(.always)
    def is_closing(self) -> Bool:
        ref c = self._c[]
        return c.closing or c.abort_req or c.close_submitted or c.closed

    @inline(.always)
    def is_draining(self) -> Bool:
        """The server is shutting down."""
        return self._c[].draining

    # ---- timers ----------------------------------------------------------

    def set_idle_timeout(self, timeout_ns: Int):
        """Close (via `on_idle`) after `timeout_ns` without traffic in either
        direction; 0 disables. Counts from now."""
        ref c = self._c[]
        c.cfg.idle_timeout_ns = max(0, timeout_ns)
        c.last_active = self._lp[].now().as_nanos()

    def set_timer(self, delay_ns: Int, tag: UInt64 = 0) -> OpId:
        """Call `on_timer(conn, tag)` after `delay_ns` (loop time). `tag`
        must fit in 56 bits. Canceled automatically when the connection
        closes."""
        ref c = self._c[]
        c.ops += 1
        var id = self._lp[].timeout_ns(
            delay_ns, c.target, _TAG_USER | (tag << _USER_SHIFT)
        )
        c.timers.append(id)
        return id

    def cancel_timer(self, id: OpId):
        """Cancel a `set_timer` timer; `on_timer` will not run for it."""
        ref c = self._c[]
        for i in range(len(c.timers)):
            if c.timers[i] == id:
                _ = c.timers.pop(i)
                _ = self._lp[].cancel(id, _ignore_target())
                return

    # ---- counters --------------------------------------------------------

    @inline(.always)
    def bytes_received(self) -> Int:
        return self._c[].bytes_in

    @inline(.always)
    def bytes_sent(self) -> Int:
        return self._c[].bytes_out


# ---- dispatch ----------------------------------------------------------------


def _dispatch[H: ConnHandler](ctx: Int, mut lp: Loop, var c: Completion):
    """The single completion target of every connection of handler type `H`:
    routes on `c.kind`, then lets `_settle` turn state changes into ops."""
    ref st = _state[H](ctx)
    if not c.more:
        st.core.ops -= 1
    var kind = c.kind
    if kind == OpKind.RECV_MULTI or kind == OpKind.RECV:
        _on_recv[H](st, lp, c^)
    elif kind == OpKind.SEND:
        _on_send[H](st, lp, c^)
    elif kind == OpKind.TIMEOUT:
        _on_timeout[H](st, lp, c)
    elif kind == OpKind.CLOSE:
        _on_close_done[H](st, lp)
    elif kind == OpKind.CONNECT:
        _on_connect[H](st, lp, c)
    elif kind == OpKind.POST:
        st.core.redeliver_posted = False
    # SHUTDOWN: nothing to do (an error shows up on the next send or recv).
    _settle[H](ctx, lp)


def _settle[H: ConnHandler](ctx: Int, mut lp: Loop):
    ref st = _state[H](ctx)
    if not st.core.closed:
        _drive[H](st, lp)
        return
    if st.core.ops == 0 and not st.core.released:
        st.core.released = True
        _conn_release[H](ctx)


def _drive[H: ConnHandler](mut st: _ConnState[H], mut lp: Loop):
    """`_pump`, plus the input callbacks that were held while reading was
    paused: unconsumed/held input first, then a pending EOF (EOF never
    overtakes data). At most a few deliveries per call; the rest continues
    at the next dispatch so one connection cannot monopolize the loop."""
    var rounds = 0
    while True:
        _pump(st.core, lp)
        if not _can_deliver(st.core):
            return
        if st.core.redeliver:
            if not _has_input(st.core):
                st.core.redeliver = False
                continue
            if rounds == 4:
                if not st.core.redeliver_posted:
                    st.core.redeliver_posted = True
                    st.core.ops += 1
                    _ = lp.post(st.core.target, _TAG_REDELIVER)
                return
            rounds += 1
            st.core.redeliver = False
            _deliver[H](st, lp)
            continue
        if st.core.eof_pending:
            st.core.eof_pending = False
            _set_reason(st.core, CloseReason.of(CloseReason.PEER))
            var conn = Conn._of(st.core, lp)
            try:
                st.handler.on_eof(conn)
            except e:
                _fail(st.core, e)
            continue
        return


def _deliver[H: ConnHandler](mut st: _ConnState[H], mut lp: Loop):
    """`on_data` with the held input (`core.inbuf`)."""
    var conn = Conn._of(st.core, lp)
    try:
        st.handler.on_data(conn, st.core.inbuf)
    except e:
        _fail(st.core, e)
    _after_input(st.core, lp)


@inline(.always)
def _after_input(mut c: ConnCore, mut lp: Loop):
    var n = c.inbuf.readable()
    if n == 0:
        _release(lp, c.inbuf)
    elif n > c.cfg.max_input:
        _fail(c, IoError.of_kind("evented.max_input", ErrorKind.InvalidData))


def _on_recv[H: ConnHandler](mut st: _ConnState[H], mut lp: Loop, var c: Completion):
    ref core = st.core
    if not c.more:  # the multishot ended (EOF, error, or canceled by close)
        core.recv_inflight = False
        core.recv_paused = False
    if c.res > 0:
        var buf = c.take_buf()
        if core.closing or core.abort_req or core.close_submitted:
            _recycle(lp, buf^)
            return
        core.last_active = lp.now().as_nanos()
        core.bytes_in += c.res
        var deliver = _can_deliver(core) and not core.redeliver
        if not _has_input(core):
            if deliver:
                # Common case: nothing held, so the receive buffer itself is
                # `input`; it is kept only if the handler leaves bytes.
                var conn = Conn._of(core, lp)
                try:
                    st.handler.on_data(conn, buf)
                except e:
                    _fail(st.core, e)
                if buf.readable() > 0:
                    _release(lp, st.core.inbuf)
                    st.core.inbuf = buf^
                    _after_input(st.core, lp)
                else:
                    _recycle(lp, buf^)
                return
            _release(lp, core.inbuf)
            core.inbuf = buf^
        else:
            try:
                core.inbuf.write_bytes(buf.readable_span())
            except:
                _recycle(lp, buf^)
                _fail(core, IoError.of_kind("evented.max_input", ErrorKind.InvalidData))
                return
            _recycle(lp, buf^)
        if deliver:
            _deliver[H](st, lp)
        else:
            core.redeliver = True  # held until reading resumes
    elif c.res == 0:
        # Delivered by `_drive` (right after this), once any held input was.
        core.peer_eof = True
        core.eof_pending = True
    elif not c.canceled():
        _fail(core, IoError.from_errno("recv", c.errno()))


def _on_send[H: ConnHandler](mut st: _ConnState[H], mut lp: Loop, var c: Completion):
    ref core = st.core
    core.sends -= 1
    if c.res > 0:
        core.queued -= c.res
        core.bytes_out += c.res
    if core.sends == 0:
        core.queued = 0
    if c.has_buf():
        _recycle(lp, c.take_buf())
    if c.res < 0:
        if not c.canceled():
            _fail(core, IoError.from_errno("send", c.errno()))
        return
    core.last_active = lp.now().as_nanos()
    if core.above_hwm and core.queued <= core.cfg.write_low_water:
        core.above_hwm = False
        if core.bp_paused:
            core.bp_paused = False
            if _has_input(core):
                core.redeliver = True
        if not (core.closing or core.abort_req or core.close_submitted):
            var conn = Conn._of(core, lp)
            try:
                st.handler.on_drain(conn)
            except e:
                _fail(st.core, e)


def _on_timeout[H: ConnHandler](mut st: _ConnState[H], mut lp: Loop, c: Completion):
    ref core = st.core
    if c.tag == _TAG_DEADLINE:
        if c.op != core.timer_op:
            return  # replaced by an earlier deadline, or canceled
        core.timer_op = OpId.null()
        if c.res < 0 or core.close_submitted:
            return
        var now = lp.now().as_nanos()
        if core.closing:
            if core.close_deadline > 0 and now >= core.close_deadline:
                core.abort_req = True  # linger expired: drop queued writes
            return
        var idle = core.cfg.idle_timeout_ns
        if idle > 0 and now >= core.last_active + idle:
            _set_reason(core, CloseReason.of(CloseReason.IDLE))
            var conn = Conn._of(core, lp)
            try:
                st.handler.on_idle(conn)
            except e:
                _fail(st.core, e)
            if not (st.core.closing or st.core.abort_req):
                # The handler kept the connection: restart the idle clock.
                if st.core.reason.code == CloseReason.IDLE:
                    st.core.reason = CloseReason.of(CloseReason.NONE)
                st.core.last_active = now
        return
    if (c.tag & 0xFF) != _TAG_USER:
        return
    var found = False
    for i in range(len(core.timers)):
        if core.timers[i] == c.op:
            _ = core.timers.pop(i)
            found = True
            break
    if not found or c.res < 0 or core.closing or core.abort_req or core.close_submitted:
        return
    var conn = Conn._of(core, lp)
    try:
        st.handler.on_timer(conn, c.tag >> _USER_SHIFT)
    except e:
        _fail(st.core, e)


def _on_connect[H: ConnHandler](mut st: _ConnState[H], mut lp: Loop, c: Completion):
    ref core = st.core
    core.connect_op = OpId.null()
    if c.ok():
        core.fd = c.fd
        if core.close_submitted:  # closed (or aborted) before it connected
            core.ops += 1
            _ = lp.close(core.fd, core.target)
            return
        core.opened = True
        core.last_active = lp.now().as_nanos()
        var conn = Conn._of(core, lp)
        try:
            st.handler.on_open(conn)
        except e:
            _fail(st.core, e)
        return
    if not c.canceled():
        _set_reason(
            core,
            CloseReason.failure(
                CloseReason.CONNECT_FAILED, IoError.from_errno("connect", c.errno())
            ),
        )
    _finish_close[H](st, lp)


def _on_close_done[H: ConnHandler](mut st: _ConnState[H], mut lp: Loop):
    _finish_close[H](st, lp)


def _finish_close[H: ConnHandler](mut st: _ConnState[H], mut lp: Loop):
    ref core = st.core
    core.closed = True
    core.close_submitted = True
    core.fd = FdId.null()
    _release(lp, core.inbuf)
    _release(lp, core.out)
    _cancel_timers(core, lp)
    if core.server != 0:
        _server_conn_closed(core.server, core, lp)
    st.handler.on_close(lp, st.core.reason)


# ---- dialing -----------------------------------------------------------------


struct ConnRef[H: ConnHandler](Movable):
    """Handle to a dialed connection. It keeps the state's memory alive
    (dropping it never closes the connection), so the handler can be read
    after the connection closed."""

    var _ctx: Int

    def __init__(out self, *, ctx: Int):
        self._ctx = ctx

    def __deinit__(deinit self):
        _conn_release[Self.H](self._ctx)

    def handler(mut self) -> ref[self] Self.H:
        """The handler (results, state). The reference keeps this handle
        alive, hence the state's memory."""
        var p = Pointer(to=_state[Self.H](self._ctx).handler)
        return p.unsafe_origin_cast[origin_of(self)]()[]

    def conn(self, mut lp: Loop) -> Conn:
        """A `Conn` view for writing from outside a callback (then call
        `flush()`). Writes after close raise `Closed`."""
        return Conn._of(_state[Self.H](self._ctx).core, lp)

    def is_connected(self) -> Bool:
        ref c = _state[Self.H](self._ctx).core
        return c.opened and not c.closed

    def is_closed(self) -> Bool:
        return _state[Self.H](self._ctx).core.closed

    def reason(self) -> CloseReason:
        return _state[Self.H](self._ctx).core.reason

    def close(self, mut lp: Loop):
        var c = self.conn(lp)
        c.close()
        c.flush()


struct Dialer[H: ConnHandler](TrivialRegisterPassable):
    """Connects outgoing connections driven by handlers of type `H`. Build
    it once, outside `H`'s callbacks, and store it where callbacks can use
    it (see "Starting other operations" in the module docstring)."""

    var _call: CompleteFn

    def __init__(out self):
        self._call = _dispatch[Self.H]

    def dial(
        self,
        mut lp: Loop,
        addr: SocketAddr,
        var handler: Self.H,
        config: ConnConfig = ConnConfig(),
    ) -> ConnRef[Self.H]:
        """Start connecting; `handler.on_open` runs once connected, or
        `on_close` with `CONNECT_FAILED`."""
        var core = ConnCore(config)
        core.refs = 2  # the ConnRef + the running connection
        var boxed = OwnedPointer(_ConnState[Self.H](core^, handler^))
        var ctx = Int(boxed.ptr())
        _ = boxed^.unsafe_take_allocation().unsafe_leak()
        ref st = _state[Self.H](ctx)
        st.core.self_ctx = ctx
        st.core.target = Target(self._call, ctx)
        st.core.ops = 1
        st.core.connect_op = lp.connect(addr.to_raw(), st.core.target)
        return ConnRef[Self.H](ctx=ctx)


def dial[H: ConnHandler](
    mut lp: Loop, addr: SocketAddr, var handler: H, config: ConnConfig = ConnConfig()
) -> ConnRef[H]:
    """`Dialer[H]().dial(...)`: for setup code and other handlers' callbacks
    (not `H`'s own; see `Dialer`)."""
    return Dialer[H]().dial(lp, addr, handler^, config)


# ---- server ------------------------------------------------------------------

comptime _FreeFn = def(Int) thin -> None


struct _ServerCore(Movable):
    var phase: Int
    var listener: FdId
    var target: Target
    var call: CompleteFn
    """`_dispatch[H]`, stored at setup: accepted connections' target fn."""
    var conns: List[Int]
    """`ConnCore` addresses of the live connections (swap-remove)."""
    var ops: Int
    var refs: Int
    var released: Bool
    var shutdown_req: Bool
    var grace_ns: Int
    var grace_timer: OpId
    var stats: ServerStats
    var local: Optional[SocketAddr]
    var err: Optional[IoError]
    var cfg: ServerConfig
    var free_fn: _FreeFn
    var owner: Int

    def __init__(out self, cfg: ServerConfig, call: CompleteFn, free_fn: _FreeFn):
        self.phase = _STARTING
        self.listener = FdId.null()
        self.target = _ignore_target()
        self.call = call
        self.conns = []
        self.ops = 0
        self.refs = 0
        self.released = False
        self.shutdown_req = False
        self.grace_ns = DEFAULT_GRACE_NS
        self.grace_timer = OpId.null()
        self.stats = ServerStats(0, 0, 0, 0, 0, 0, 0)
        self.local = None
        self.err = None
        self.cfg = cfg
        self.free_fn = free_fn
        self.owner = 0


@fieldwise_init
struct _ServerState[H: ConnHandler & Copyable](Movable):
    var core: _ServerCore
    var proto: Self.H


@inline(.always)
def _srv(addr: Int) -> ref[MutUntrackedOrigin] _ServerCore:
    return Pointer[_ServerCore, MutUntrackedOrigin](unsafe_from_address=addr)[]


@inline(.always)
def _sstate[H: ConnHandler & Copyable](ctx: Int) -> ref[MutUntrackedOrigin] _ServerState[H]:
    return Pointer[_ServerState[H], MutUntrackedOrigin](unsafe_from_address=ctx)[]


def _free_server[H: ConnHandler & Copyable](ctx: Int):
    var o = OpaquePointer[MutAnyOrigin](unsafe_from_address=ctx)
    var boxed = OwnedPointer[_ServerState[H]](unsafe_from_opaque_pointer=o)
    _ = boxed^


def _server_release(saddr: Int):
    ref s = _srv(saddr)
    s.refs -= 1
    if s.refs == 0:
        var f = s.free_fn
        var o = s.owner
        f(o)


def _server_check_done(saddr: Int, mut lp: Loop):
    """Finish a drain once the listener and every connection are closed;
    release the running reference once no server op is pending. May free
    the server: callers must not touch it afterwards."""
    ref s = _srv(saddr)
    if s.phase == _DRAINING and s.listener.is_null() and len(s.conns) == 0:
        s.phase = _CLOSED
        if not s.grace_timer.is_null():
            _ = lp.cancel(s.grace_timer, _ignore_target())
    if s.phase == _CLOSED and s.ops == 0 and not s.released:
        s.released = True
        _server_release(saddr)


def _server_conn_closed(saddr: Int, mut c: ConnCore, mut lp: Loop):
    ref s = _srv(saddr)
    var idx = c.index
    var last = len(s.conns) - 1
    if idx >= 0 and idx <= last:
        if idx != last:
            var moved = s.conns[last]
            s.conns[idx] = moved
            _core_at(moved).index = idx
        _ = s.conns.pop()
    c.server = 0
    c.index = -1
    s.stats.closed += 1
    s.stats.active = len(s.conns)
    s.stats.bp_pauses += c.bp_pauses
    if c.reason.code == CloseReason.ERROR:
        s.stats.errors += 1
    elif c.reason.code == CloseReason.IDLE:
        s.stats.idle_closed += 1
    _server_check_done(saddr, lp)


def _spawn[H: ConnHandler & Copyable](sctx: Int, mut lp: Loop, fd: FdId):
    ref ss = _sstate[H](sctx)
    var core = ConnCore(ss.core.cfg.conn)
    core.fd = fd
    core.refs = 1
    core.opened = True
    core.last_active = lp.now().as_nanos()
    core.server = Int(Pointer(to=ss.core))
    core.index = len(ss.core.conns)
    var boxed = OwnedPointer(_ConnState[H](core^, ss.proto.copy()))
    var ctx = Int(boxed.ptr())
    _ = boxed^.unsafe_take_allocation().unsafe_leak()
    ref st = _state[H](ctx)
    st.core.self_ctx = ctx
    st.core.target = Target(ss.core.call, ctx)
    ss.core.conns.append(Int(Pointer(to=st.core)))
    ss.core.stats.accepted += 1
    ss.core.stats.active = len(ss.core.conns)
    var conn = Conn._of(st.core, lp)
    try:
        st.handler.on_open(conn)
    except e:
        _fail(st.core, e)
    _settle[H](ctx, lp)


def _begin_drain[H: ConnHandler & Copyable](sctx: Int, mut lp: Loop):
    ref s = _sstate[H](sctx).core
    if s.phase == _STARTING:
        s.shutdown_req = True
        return
    if s.phase != _LISTENING:
        return
    s.phase = _DRAINING
    if not s.listener.is_null():
        s.ops += 1
        _ = lp.close(s.listener, s.target)
    if s.grace_ns >= 0:
        s.ops += 1
        s.grace_timer = lp.timeout_ns(s.grace_ns, s.target, _STAG_GRACE)
    var snapshot = s.conns.copy()
    for i in range(len(snapshot)):
        ref core = _core_at(snapshot[i])
        var cctx = core.self_ctx
        ref st = _state[H](cctx)
        st.core.draining = True
        if not (st.core.closing or st.core.abort_req or st.core.close_submitted):
            var conn = Conn._of(st.core, lp)
            try:
                st.handler.on_shutdown(conn)
            except e:
                _fail(st.core, e)
        _settle[H](cctx, lp)


def _abort_all[H: ConnHandler & Copyable](sctx: Int, mut lp: Loop):
    ref s = _sstate[H](sctx).core
    var snapshot = s.conns.copy()
    for i in range(len(snapshot)):
        var cctx = _core_at(snapshot[i]).self_ctx
        ref st = _state[H](cctx)
        _set_reason(st.core, CloseReason.of(CloseReason.SHUTDOWN))
        st.core.abort_req = True
        _settle[H](cctx, lp)


def _on_server[H: ConnHandler & Copyable](ctx: Int, mut lp: Loop, var c: Completion):
    ref ss = _sstate[H](ctx)
    var saddr = Int(Pointer(to=ss.core))
    if not c.more:
        ss.core.ops -= 1
    var kind = c.kind
    if kind == OpKind.ACCEPT:
        if c.ok():
            if ss.core.phase != _LISTENING or (
                ss.core.cfg.max_connections > 0
                and len(ss.core.conns) >= ss.core.cfg.max_connections
            ):
                ss.core.stats.rejected += 1
                _ = lp.close(c.fd, _ignore_target())
            else:
                _spawn[H](ctx, lp, c.fd)
        elif not c.more and not c.canceled():
            ss.core.err = IoError.from_errno("accept", c.errno())
    elif kind == OpKind.LISTEN:
        if c.ok():
            ss.core.listener = c.fd
            var raw = lp.local_addr(c.fd)
            if raw:
                try:
                    ss.core.local = SocketAddr.from_raw(raw.value())
                except:
                    pass
            if ss.core.shutdown_req:
                ss.core.phase = _LISTENING
                _begin_drain[H](ctx, lp)
            else:
                ss.core.phase = _LISTENING
                ss.core.ops += 1
                _ = lp.accept(c.fd, ss.core.target)
        else:
            ss.core.err = IoError.from_errno("listen", c.errno())
            ss.core.phase = _CLOSED
    elif kind == OpKind.CLOSE:
        ss.core.listener = FdId.null()
    elif kind == OpKind.POST and c.tag == _STAG_SHUTDOWN:
        _begin_drain[H](ctx, lp)
    elif kind == OpKind.TIMEOUT and c.tag == _STAG_GRACE:
        if c.op == ss.core.grace_timer:
            ss.core.grace_timer = OpId.null()
            if c.res >= 0:
                _abort_all[H](ctx, lp)
    _server_check_done(saddr, lp)  # may free the server: keep it last


struct TcpServer[H: ConnHandler & Copyable](Movable):
    """A TCP server whose connections are driven by copies of a prototype
    handler. The handle is a reference: dropping it does not stop the
    server (use `shutdown`)."""

    var _sctx: Int
    var _core: Int

    def __init__(out self, *, sctx: Int, core: Int):
        self._sctx = sctx
        self._core = core

    @staticmethod
    def listen(
        mut lp: Loop,
        addr: SocketAddr,
        var proto: Self.H,
        config: ServerConfig = ServerConfig(),
    ) -> Self:
        """Bind and listen on `addr` (port 0: any; see `local_addr` once
        `is_listening`), then accept until `shutdown`. Listening completes
        on the loop's next iteration; a failure shows up in `error()`."""
        var core = _ServerCore(config, _dispatch[Self.H], _free_server[Self.H])
        var boxed = OwnedPointer(_ServerState[Self.H](core^, proto^))
        var ctx = Int(boxed.ptr())
        _ = boxed^.unsafe_take_allocation().unsafe_leak()
        ref ss = _sstate[Self.H](ctx)
        ss.core.owner = ctx
        ss.core.target = Target(_on_server[Self.H], ctx)
        ss.core.refs = 2  # this handle + the running server
        ss.core.ops = 1
        _ = lp.listen(
            addr.to_raw(),
            ss.core.target,
            backlog=config.backlog,
            reuse_port=config.reuse_port,
        )
        return Self(sctx=ctx, core=Int(Pointer(to=ss.core)))

    def __deinit__(deinit self):
        _server_release(self._core)

    def is_listening(self) -> Bool:
        return _srv(self._core).phase == _LISTENING

    def is_closed(self) -> Bool:
        """Listener closed (or never opened) and every connection closed."""
        return _srv(self._core).phase == _CLOSED

    def local_addr(self) -> Optional[SocketAddr]:
        return _srv(self._core).local

    def error(self) -> Optional[IoError]:
        """Why listening or accepting failed, if it did."""
        return _srv(self._core).err

    def connections(self) -> Int:
        return len(_srv(self._core).conns)

    def stats(self) -> ServerStats:
        return _srv(self._core).stats

    def shutdown(self, mut lp: Loop, grace_ns: Int = DEFAULT_GRACE_NS):
        """Graceful shutdown, started at the next dispatch: stop accepting,
        close idle connections, let busy ones finish, abort what is left
        after `grace_ns` (< 0: never). Safe to call from any callback."""
        ref s = _srv(self._core)
        if s.phase == _CLOSED or s.phase == _DRAINING or s.shutdown_req:
            return
        s.grace_ns = grace_ns
        if s.phase == _STARTING:
            s.shutdown_req = True
            return
        s.shutdown_req = True
        s.ops += 1
        _ = lp.post(s.target, _STAG_SHUTDOWN)
