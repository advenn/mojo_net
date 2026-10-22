"""The loop core: ops, completions, fd state and the readiness proactor.

`Loop` holds everything that does not depend on the I/O backend. Callbacks
receive `mut Loop` and submit ops into it; `rt.event_loop.EventLoop` flushes
submissions to a `Driver` after every dispatch batch (io_uring style), so a
callback never runs inside a submit (contract 2).

The proactor turns edge-triggered readiness into completions:
- each fd keeps `readable` / `writable` flags: an edge sets them; EAGAIN or
  a short transfer clears them (the "short read means drained" rule);
- `read_closed` is sticky: once RDHUP/HUP/ERR was seen, reads continue to
  EOF or EAGAIN regardless of the short-read rule (otherwise a FIN that
  arrived together with data is lost; docs/spikes.md);
- a submit on a ready fd performs the syscall at once (optimistic I/O), so a
  request/response exchange costs one recv and one send;
- the write direction is one FIFO queue per fd: sends, and write shutdowns
  (SHUT_WR/SHUT_RDWR), which run only after every byte queued before them;
- EOF (recv returning 0) also sets `read_closed`, so later receives report
  it at once.
Timers are a min-heap with lazy deletion; canceled entries are pruned from
the top before the loop sleeps and compacted once they are the majority.
See docs/rt.md for the op table; tests/rt/test_loop_contract.mojo checks
every rule on every backend.
"""

from std.sys import size_of

from bytes.buffer import ByteBuffer
from linux import Errno, Instant
from linux.abi import RawSockaddr
from linux.consts import (
    IPPROTO_TCP,
    SHUT_RD,
    SO_REUSEADDR,
    SO_REUSEPORT,
    SOCK_STREAM,
    SOL_SOCKET,
    TCP_NODELAY,
    AF_INET,
    AF_INET6,
)

from .driver import ERROR, HANGUP, READ_CLOSED, READ_READY, WRITE_READY, Driver, ReadyEvent
from .slab import Slab, SlabId
from .timers import TimerEntry, TimerHeap

comptime OpId = SlabId
comptime FdId = SlabId

comptime RECV_CHUNK = 16 * 1024
"""Bytes one recv completion delivers at most (pooled buffer size)."""
comptime POOL_MAX = 4096
"""Recycled receive buffers kept; extra ones are freed."""
comptime ACCEPT_BATCH = 64
"""Connections accepted per readiness turn before yielding to other fds."""
comptime ACCEPT_RETRY_NS = 100_000_000
"""How long accepting pauses after EMFILE/ENFILE/ENOBUFS/ENOMEM."""
comptime DEFAULT_BACKLOG = 1024


@fieldwise_init
struct OpKind(Equatable, TrivialRegisterPassable, Writable):
    var v: UInt8

    comptime POST = OpKind(0)
    comptime LISTEN = OpKind(1)
    comptime CONNECT = OpKind(2)
    comptime ACCEPT = OpKind(3)
    comptime RECV = OpKind(4)
    comptime SEND = OpKind(5)
    comptime SHUTDOWN = OpKind(6)
    comptime CLOSE = OpKind(7)
    comptime TIMEOUT = OpKind(8)
    comptime CANCEL = OpKind(9)
    comptime _RESUME_ACCEPT = OpKind(10)
    """Internal: re-enable an accept paused by fd exhaustion."""

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self.v == other.v

    def name(self) -> StaticString:
        if self.v == 0:
            return "post"
        if self.v == 1:
            return "listen"
        if self.v == 2:
            return "connect"
        if self.v == 3:
            return "accept"
        if self.v == 4:
            return "recv"
        if self.v == 5:
            return "send"
        if self.v == 6:
            return "shutdown"
        if self.v == 7:
            return "close"
        if self.v == 8:
            return "timeout"
        if self.v == 9:
            return "cancel"
        return "internal"

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.name())


comptime CompleteFn = def(Int, mut Loop, var Completion) thin -> None


@fieldwise_init
struct Target(TrivialRegisterPassable):
    """Where a completion goes: `call(ctx, loop, completion)`. `ctx` is a
    word the submitter owns (typically a heap handler's address)."""

    var call: CompleteFn
    var ctx: Int


def _nop_complete(ctx: Int, mut loop: Loop, var c: Completion):
    pass


struct Completion(Movable, Writable):
    """The result of one op. `res >= 0` is success (bytes, or 0), `res < 0`
    is `-errno` (`-ECANCELED` when canceled). `more` means a multishot op
    (accept) will complete again. `fd` is the connection an accept, listen or
    connect produced (owned by the loop). `buf` is the received data, or the
    (consumed) buffer a send hands back."""

    var op: OpId
    var kind: OpKind
    var tag: UInt64
    var res: Int
    var more: Bool
    var fd: FdId
    var buf: Optional[ByteBuffer]
    var _target: Target

    def __init__(
        out self,
        op: OpId,
        kind: OpKind,
        tag: UInt64,
        res: Int,
        more: Bool,
        fd: FdId,
        var buf: Optional[ByteBuffer],
        target: Target,
    ):
        self.op = op
        self.kind = kind
        self.tag = tag
        self.res = res
        self.more = more
        self.fd = fd
        self.buf = buf^
        self._target = target

    @inline(.always)
    def ok(self) -> Bool:
        return self.res >= 0

    @inline(.always)
    def errno(self) -> Errno:
        return Errno(Int32(-self.res)) if self.res < 0 else Errno(0)

    @inline(.always)
    def canceled(self) -> Bool:
        return self.res == -Int(Errno.ECANCELED.value)

    def write_to(self, mut writer: Some[Writer]):
        writer.write("Completion(", self.kind, " ", self.op, " res=")
        if self.res < 0:
            writer.write(self.errno())
        else:
            writer.write(self.res)
        if self.more:
            writer.write(" more")
        writer.write(")")


struct Op(Movable):
    var kind: OpKind
    var target: Target
    var tag: UInt64
    var fd: FdId
    var buf: Optional[ByteBuffer]
    var addr: List[RawSockaddr]
    """LISTEN/CONNECT target (empty otherwise): out of line, so the 136-byte
    sockaddr does not bloat every op record."""
    var arg: Int
    """LISTEN: backlog (negative: also SO_REUSEPORT). SHUTDOWN: how.
    TIMEOUT: deadline ns. CANCEL: target op raw id. SEND: bytes sent."""

    def __init__(out self, kind: OpKind, target: Target, tag: UInt64, fd: FdId):
        self.kind = kind
        self.target = target
        self.tag = tag
        self.fd = fd
        self.buf = None
        self.addr = []
        self.arg = 0


struct FdEntry(Movable):
    var raw: Int32
    var registered: Bool
    var readable: Bool
    var writable: Bool
    var read_closed: Bool
    var accept_paused: Bool
    var accept_op: OpId
    var recv_op: OpId
    var connect_op: OpId
    var sends: List[OpId]
    var addr: List[RawSockaddr]
    """Out of line (empty for most fds): the peer of an accepted/connected
    socket, or the bound address of a listener (`addr_is_local`)."""
    var addr_is_local: Bool

    def __init__(out self, raw: Int32):
        self.raw = raw
        self.registered = False
        # Freshly created sockets are assumed ready: optimistic I/O finds out
        # (EAGAIN clears the flag) without waiting for a first edge.
        self.readable = True
        self.writable = True
        self.read_closed = False
        self.accept_paused = False
        self.accept_op = OpId.null()
        self.recv_op = OpId.null()
        self.connect_op = OpId.null()
        self.sends = []
        self.addr = []
        self.addr_is_local = False


@inline(.always)
def _neg(e: Errno) -> Int:
    return -Int(e.value)


@inline(.always)
def _is(res: Int, e: Errno) -> Bool:
    return res == -Int(e.value)


struct Loop(Movable):
    """Backend-independent loop state. Submit ops with the methods below;
    every op completes exactly once through its `Target`."""

    var _ops: Slab[Op]
    var _fds: Slab[FdEntry]
    var _submitted: List[OpId]
    var _ready: List[Completion]
    var _rescan: List[FdId]
    var _paused: List[FdId]
    """Listeners whose accepting is paused by fd exhaustion (so a close
    resumes them without scanning every fd)."""
    var _timers: TimerHeap
    var _stale_timers: Int
    """Heap entries whose timeout op was canceled (compacted lazily)."""
    var _internal: Int
    """Ops in `_ops` the loop made for itself (accept-resume timers); they
    do not count as pending for `run()`."""
    var _pool: List[ByteBuffer]
    var _now: Instant
    var _stopped: Bool

    def __init__(out self, now: Instant):
        self._ops = Slab[Op]()
        self._fds = Slab[FdEntry]()
        self._submitted = []
        self._ready = []
        self._rescan = []
        self._paused = []
        self._timers = TimerHeap()
        self._stale_timers = 0
        self._internal = 0
        self._pool = []
        self._now = now
        self._stopped = False

    # ---- public queries ------------------------------------------------------

    @inline(.always)
    def now(self) -> Instant:
        """Time at the start of this loop iteration (read once per turn)."""
        return self._now

    @inline(.always)
    def pending_ops(self) -> Int:
        """Ops submitted and not yet finally completed."""
        return len(self._ops) - self._internal

    @inline(.always)
    def open_fds(self) -> Int:
        return len(self._fds)

    @inline(.always)
    def is_open(self, fd: FdId) -> Bool:
        return self._fds.contains(fd)

    def peer_addr(self, fd: FdId) -> Optional[RawSockaddr]:
        """Remote address of an accepted or connected socket."""
        if not self._fds.contains(fd):
            return None
        ref e = self._fds[fd]
        if len(e.addr) == 0 or e.addr_is_local:
            return None
        return e.addr[0].copy()

    def local_addr(self, fd: FdId) -> Optional[RawSockaddr]:
        """Bound address of a listener (the real port when bound to 0)."""
        if not self._fds.contains(fd):
            return None
        ref e = self._fds[fd]
        if len(e.addr) == 0 or not e.addr_is_local:
            return None
        return e.addr[0].copy()

    def stop(mut self):
        """Make `EventLoop.run()` return after the current iteration (which
        then does not block waiting for I/O). `run()` clears the request
        when it returns, so the loop can be run again."""
        self._stopped = True

    @inline(.always)
    def _clear_stop(mut self):
        self._stopped = False

    @inline(.always)
    def stopped(self) -> Bool:
        return self._stopped

    # ---- buffers -------------------------------------------------------------

    def take_buffer(mut self) -> ByteBuffer:
        """A cleared buffer with room for `RECV_CHUNK` bytes (pooled)."""
        if len(self._pool) > 0:
            return self._pool.pop()
        try:
            return ByteBuffer(capacity=RECV_CHUNK)
        except:
            return ByteBuffer()

    def recycle(mut self, var buf: ByteBuffer):
        """Give a receive (or any) buffer back to the pool. Only buffers of
        exactly `RECV_CHUNK` bytes are kept (the pool's own size, so a
        recycled multi-MiB send buffer cannot pin memory or make a receive
        larger than `RECV_CHUNK`); others are freed."""
        if len(self._pool) < POOL_MAX and buf.capacity() == RECV_CHUNK:
            buf.clear()
            self._pool.append(buf^)

    # ---- submission ----------------------------------------------------------

    def _submit(mut self, var op: Op) -> OpId:
        var id = self._ops.insert(op^)
        self._submitted.append(id)
        return id

    def post(mut self, target: Target, tag: UInt64 = 0) -> OpId:
        """Complete with res 0 at the next dispatch (never inline)."""
        return self._submit(Op(OpKind.POST, target, tag, FdId.null()))

    def listen(
        mut self,
        addr: RawSockaddr,
        target: Target,
        tag: UInt64 = 0,
        backlog: Int = DEFAULT_BACKLOG,
        reuse_port: Bool = False,
    ) -> OpId:
        """Create a TCP listener (SO_REUSEADDR on) bound to `addr`.
        Completes with `c.fd` = the listener; `local_addr(fd)` has the port."""
        var op = Op(OpKind.LISTEN, target, tag, FdId.null())
        op.addr.append(addr.copy())
        var b = max(1, min(backlog, 65535))
        op.arg = -b if reuse_port else b
        return self._submit(op^)

    def connect(mut self, addr: RawSockaddr, target: Target, tag: UInt64 = 0) -> OpId:
        """Create a TCP socket (TCP_NODELAY on) and connect it. Completes with
        `c.fd` on success; on failure the socket is already closed."""
        var op = Op(OpKind.CONNECT, target, tag, FdId.null())
        op.addr.append(addr.copy())
        return self._submit(op^)

    def accept(mut self, listener: FdId, target: Target, tag: UInt64 = 0) -> OpId:
        """Multishot: completes once per connection (`more=True`, `c.fd` is
        the new socket, TCP_NODELAY on) until canceled, the listener closes,
        or a fatal error. Fd exhaustion pauses accepting, it does not fail."""
        return self._submit(Op(OpKind.ACCEPT, target, tag, listener))

    def recv(mut self, fd: FdId, target: Target, tag: UInt64 = 0) -> OpId:
        """Next chunk of data (`c.buf`, at most RECV_CHUNK bytes; give it
        back with `recycle`), or res 0 at EOF. One recv per fd at a time."""
        return self._submit(Op(OpKind.RECV, target, tag, fd))

    def send(
        mut self, fd: FdId, var buf: ByteBuffer, target: Target, tag: UInt64 = 0
    ) -> OpId:
        """Write all readable bytes of `buf`; completes with the byte count
        and `c.buf` = the consumed buffer. Sends on one fd are FIFO. A send
        that fails or is canceled also hands its buffer back; its readable
        bytes are the part that was not sent."""
        var op = Op(OpKind.SEND, target, tag, fd)
        op.buf = Optional(buf^)
        return self._submit(op^)

    def shutdown(
        mut self, fd: FdId, how: Int, target: Target, tag: UInt64 = 0
    ) -> OpId:
        """`shutdown(2)`. SHUT_WR and SHUT_RDWR join the fd's write queue:
        the FIN follows every send submitted before, and the op completes
        when it was issued. SHUT_RD runs at once."""
        var op = Op(OpKind.SHUTDOWN, target, tag, fd)
        op.arg = how
        return self._submit(op^)

    def close(mut self, fd: FdId, target: Target, tag: UInt64 = 0) -> OpId:
        """Cancel every op pending on `fd` (each completes with ECANCELED,
        before this op), deregister and close it."""
        return self._submit(Op(OpKind.CLOSE, target, tag, fd))

    def timeout_at(mut self, at: Instant, target: Target, tag: UInt64 = 0) -> OpId:
        var op = Op(OpKind.TIMEOUT, target, tag, FdId.null())
        op.arg = at.as_nanos()
        return self._submit(op^)

    def timeout_ns(mut self, delay_ns: Int, target: Target, tag: UInt64 = 0) -> OpId:
        """Complete with res 0 once `delay_ns` has passed (loop time). A
        delay past the end of the clock saturates (never wraps around into
        an immediate expiry)."""
        var now = self._now.as_nanos()
        var d = max(0, delay_ns)
        var at = Int.MAX if d > Int.MAX - now else now + d
        return self.timeout_at(Instant(nanos=at), target, tag)

    def cancel(mut self, op: OpId, target: Target, tag: UInt64 = 0) -> OpId:
        """Two-phase cancel: if `op` is still pending it completes with
        ECANCELED first, then this op completes with 0; if it already
        finished (or never existed) this op completes with -ENOENT. An op
        submitted earlier in the same batch counts as pending unless it
        completed when it started (a post, an optimistic send...)."""
        var c = Op(OpKind.CANCEL, target, tag, FdId.null())
        c.arg = Int(op.raw)
        return self._submit(c^)

    # ---- completion ----------------------------------------------------------

    def _complete(
        mut self,
        id: OpId,
        res: Int,
        more: Bool = False,
        fd: FdId = FdId.null(),
    ):
        """Queue the completion of op `id`; a final one removes the op.
        `c.fd` is `fd` when given (accept/listen/connect results), else the
        fd the op ran on."""
        if more:
            ref op = self._ops[id]
            var cfd = fd if not fd.is_null() else op.fd
            self._ready.append(
                Completion(id, op.kind, op.tag, res, True, cfd, None, op.target)
            )
            return
        var op = self._ops.remove(id)
        var cfd = fd if not fd.is_null() else op.fd
        var buf = op.buf.take() if op.buf else Optional[ByteBuffer](None)
        self._ready.append(
            Completion(id, op.kind, op.tag, res, False, cfd, buf^, op.target)
        )

    def _complete_with_buf(mut self, id: OpId, res: Int, var buf: ByteBuffer):
        var op = self._ops.remove(id)
        self._ready.append(
            Completion(id, op.kind, op.tag, res, False, op.fd, Optional(buf^), op.target)
        )

    def take_ready(mut self) -> List[Completion]:
        """The queued completions, oldest LAST (pop() order); for the
        dispatcher. New completions queue into a fresh list."""
        var batch = List[Completion]()
        swap(batch, self._ready)
        batch.reverse()
        return batch^

    @inline(.always)
    def has_ready(self) -> Bool:
        return len(self._ready) > 0

    @inline(.always)
    def has_submitted(self) -> Bool:
        return len(self._submitted) > 0 or len(self._rescan) > 0

    # ---- flush: hand submitted ops to the driver ----------------------------

    def flush[D: Driver](mut self, mut d: D):
        """Start every submitted op, in submission order."""
        var batch = List[OpId]()
        swap(batch, self._submitted)
        for i in range(len(batch)):
            var id = batch[i]
            if not self._ops.contains(id):
                continue  # canceled before it started
            var kind = self._ops[id].kind
            if kind == OpKind.POST:
                self._complete(id, 0)
            elif kind == OpKind.LISTEN:
                self._start_listen(d, id)
            elif kind == OpKind.CONNECT:
                self._start_connect(d, id)
            elif kind == OpKind.ACCEPT:
                self._start_accept(d, id)
            elif kind == OpKind.RECV:
                self._start_recv(d, id)
            elif kind == OpKind.SEND:
                self._start_send(d, id)
            elif kind == OpKind.SHUTDOWN:
                self._start_shutdown(d, id)
            elif kind == OpKind.CLOSE:
                self._close(d, self._ops[id].fd, id)
            elif kind == OpKind.TIMEOUT:
                self._timers.push(self._ops[id].arg, id.raw)
            elif kind == OpKind.CANCEL:
                self._cancel(d, OpId(UInt64(self._ops[id].arg)), id)
        # Fds whose readiness work was cut short by a batch limit.
        var again = List[FdId]()
        swap(again, self._rescan)
        for i in range(len(again)):
            self._progress(d, again[i])

    # ---- fd lifecycle --------------------------------------------------------

    def _add_fd[D: Driver](mut self, mut d: D, raw: Int32) -> Optional[FdId]:
        """Own `raw` and register it; on failure close it and return None."""
        var id = self._fds.insert(FdEntry(raw))
        var r = d.register(raw, id.raw)
        if r < 0:
            _ = self._fds.remove(id)
            _ = d.close(raw)
            return None
        self._fds[id].registered = True
        return id

    def _drop_fd[D: Driver](mut self, mut d: D, fd: FdId) -> Int:
        """Deregister, close and forget `fd` (its ops must be gone)."""
        var e = self._fds.remove(fd)
        if e.registered:
            _ = d.deregister(e.raw)
        var r = d.close(e.raw)
        if _is(r, Errno.EINTR):
            r = 0  # Linux has released the fd; never retry close.
        # Fd exhaustion may have paused listeners: a freed fd lets them go on.
        if len(self._paused) > 0:
            self._resume_paused_accepts()
        return r

    def _resume_paused_accepts(mut self):
        """Let every paused listener try again (O(paused), never a scan of
        all fds: this runs on every close while any listener is paused)."""
        var paused = List[FdId]()
        swap(paused, self._paused)
        for i in range(len(paused)):
            var fd = paused[i]
            if self._fds.contains(fd) and self._fds[fd].accept_paused:
                self._fds[fd].accept_paused = False
                self._rescan.append(fd)

    def _close[D: Driver](mut self, mut d: D, fd: FdId, close_op: OpId):
        if not self._fds.contains(fd):
            self._complete(close_op, _neg(Errno.EBADF))
            return
        self._cancel_fd_ops(fd)
        self._complete(close_op, self._drop_fd(d, fd))

    def _cancel_fd_ops(mut self, fd: FdId):
        ref e = self._fds[fd]
        var canceled = _neg(Errno.ECANCELED)
        var pending = List[OpId]()
        if not e.connect_op.is_null():
            pending.append(e.connect_op)
            e.connect_op = OpId.null()
        if not e.accept_op.is_null():
            pending.append(e.accept_op)
            e.accept_op = OpId.null()
        if not e.recv_op.is_null():
            pending.append(e.recv_op)
            e.recv_op = OpId.null()
        for i in range(len(e.sends)):
            pending.append(e.sends[i])
        e.sends.clear()
        for i in range(len(pending)):
            self._complete(pending[i], canceled)

    # ---- listen / connect ----------------------------------------------------

    def _start_listen[D: Driver](mut self, mut d: D, id: OpId):
        var addr = self._ops[id].addr[0].copy()
        var arg = self._ops[id].arg
        var raw = d.socket(addr.family(), SOCK_STREAM)
        if raw < 0:
            self._complete(id, raw)
            return
        var fd32 = Int32(raw)
        var r = d.set_int_option(fd32, SOL_SOCKET, SO_REUSEADDR, 1)
        if r >= 0 and arg < 0:
            r = d.set_int_option(fd32, SOL_SOCKET, SO_REUSEPORT, 1)
        if r >= 0:
            r = d.bind(fd32, addr)
        if r >= 0:
            r = d.listen(fd32, arg if arg > 0 else -arg)
        var local = RawSockaddr()
        if r >= 0:
            r = d.local_addr(fd32, local)
        if r < 0:
            _ = d.close(fd32)
            self._complete(id, r)
            return
        var fd = self._add_fd(d, fd32)
        if not fd:
            self._complete(id, _neg(Errno.ENOMEM))
            return
        self._fds[fd.value()].addr.append(local^)
        self._fds[fd.value()].addr_is_local = True
        self._complete(id, 0, fd=fd.value())

    def _start_connect[D: Driver](mut self, mut d: D, id: OpId):
        var addr = self._ops[id].addr[0].copy()
        var raw = d.socket(addr.family(), SOCK_STREAM)
        if raw < 0:
            self._complete(id, raw)
            return
        var fd32 = Int32(raw)
        var fam = addr.family()
        if fam == AF_INET or fam == AF_INET6:
            _ = d.set_int_option(fd32, IPPROTO_TCP, TCP_NODELAY, 1)
        var maybe = self._add_fd(d, fd32)
        if not maybe:
            self._complete(id, _neg(Errno.ENOMEM))
            return
        var fd = maybe.value()
        self._ops[id].fd = fd
        self._fds[fd].addr.append(addr.copy())
        var r = d.connect(fd32, addr)
        if r == 0:
            self._complete(id, 0, fd=fd)
        elif _is(r, Errno.EINPROGRESS) or _is(r, Errno.EINTR):
            # Never re-issue connect: wait for writability, then SO_ERROR.
            self._fds[fd].writable = False
            self._fds[fd].connect_op = id
        else:
            _ = self._drop_fd(d, fd)
            self._complete(id, r)

    def _finish_connect[D: Driver](mut self, mut d: D, fd: FdId):
        var id = self._fds[fd].connect_op
        self._fds[fd].connect_op = OpId.null()
        var err = d.socket_error(self._fds[fd].raw)
        if err == 0:
            self._complete(id, 0, fd=fd)
        else:
            _ = self._drop_fd(d, fd)
            self._complete(id, err)

    # ---- accept --------------------------------------------------------------

    def _start_accept[D: Driver](mut self, mut d: D, id: OpId):
        var fd = self._ops[id].fd
        if not self._fds.contains(fd):
            self._complete(id, _neg(Errno.EBADF))
            return
        if not self._fds[fd].accept_op.is_null():
            self._complete(id, _neg(Errno.EBUSY))
            return
        self._fds[fd].accept_op = id
        self._do_accept(d, fd)

    def _do_accept[D: Driver](mut self, mut d: D, fd: FdId):
        var listen_raw = self._fds[fd].raw
        var n = 0
        while self._fds.contains(fd) and not self._fds[fd].accept_op.is_null():
            if self._fds[fd].accept_paused or not self._fds[fd].readable:
                return
            if n == ACCEPT_BATCH:
                self._rescan.append(fd)  # yield; continue next turn
                return
            var peer = RawSockaddr()
            var r = d.accept(listen_raw, peer)
            if r >= 0:
                n += 1
                var conn32 = Int32(r)
                var fam = peer.family()
                if fam == AF_INET or fam == AF_INET6:
                    _ = d.set_int_option(conn32, IPPROTO_TCP, TCP_NODELAY, 1)
                var conn = self._add_fd(d, conn32)
                if not conn:
                    continue
                self._fds[conn.value()].addr.append(peer^)
                self._complete(self._fds[fd].accept_op, 0, more=True, fd=conn.value())
            elif _is(r, Errno.EAGAIN):
                self._fds[fd].readable = False
                return
            elif (
                _is(r, Errno.EINTR)
                or _is(r, Errno.ECONNABORTED)
                or _is(r, Errno.EPROTO)
                or _is(r, Errno.ENETDOWN)
                or _is(r, Errno.ENOPROTOOPT)
                or _is(r, Errno.EHOSTDOWN)
                or _is(r, Errno.ENONET)
                or _is(r, Errno.EHOSTUNREACH)
                or _is(r, Errno.EOPNOTSUPP)
                or _is(r, Errno.ENETUNREACH)
                or _is(r, Errno.EPERM)
            ):
                # Per accept(2): that connection failed, not the listener.
                # Counted, so a persistent error cannot loop here forever.
                n += 1
                continue
            elif (
                _is(r, Errno.EMFILE)
                or _is(r, Errno.ENFILE)
                or _is(r, Errno.ENOBUFS)
                or _is(r, Errno.ENOMEM)
            ):
                # Out of descriptors/memory: pause (never spin on a readable
                # listener) until an fd is closed or the retry timer fires.
                self._fds[fd].accept_paused = True
                var listed = False
                for i in range(len(self._paused)):
                    if self._paused[i] == fd:
                        listed = True
                if not listed:
                    self._paused.append(fd)
                var t = Op(OpKind._RESUME_ACCEPT, Target(_nop_complete, 0), 0, fd)
                t.arg = self._now.as_nanos() + ACCEPT_RETRY_NS
                var tid = self._ops.insert(t^)
                self._internal += 1
                self._timers.push(self._ops[tid].arg, tid.raw)
                return
            else:
                var id = self._fds[fd].accept_op
                self._fds[fd].accept_op = OpId.null()
                self._complete(id, r)
                return

    # ---- recv ----------------------------------------------------------------

    def _start_recv[D: Driver](mut self, mut d: D, id: OpId):
        var fd = self._ops[id].fd
        if not self._fds.contains(fd):
            self._complete(id, _neg(Errno.EBADF))
            return
        if not self._fds[fd].recv_op.is_null():
            self._complete(id, _neg(Errno.EBUSY))
            return
        self._fds[fd].recv_op = id
        self._do_recv(d, fd)

    def _do_recv[D: Driver](mut self, mut d: D, fd: FdId):
        ref e = self._fds[fd]
        if e.recv_op.is_null() or not (e.readable or e.read_closed):
            return
        var buf = self.take_buffer()
        while True:
            try:
                buf.ensure_writable(RECV_CHUNK)
            except:
                pass
            var room = buf.writable()
            if room == 0:
                # A zero-length recv returns 0, which would read as EOF.
                var id0 = self._fds[fd].recv_op
                self._fds[fd].recv_op = OpId.null()
                self._complete(id0, _neg(Errno.ENOMEM))
                return
            var r = d.recv(self._fds[fd].raw, buf)
            if r > 0:
                ref e2 = self._fds[fd]
                if r < room and not e2.read_closed:
                    e2.readable = False  # short read: drained (edge rearmed)
                var id = e2.recv_op
                e2.recv_op = OpId.null()
                self._complete_with_buf(id, r, buf^)
                return
            if r == 0:
                ref e3 = self._fds[fd]
                # EOF is permanent: later receives report it at once instead
                # of waiting for the RDHUP edge.
                e3.read_closed = True
                var id = e3.recv_op
                e3.recv_op = OpId.null()
                self.recycle(buf^)
                self._complete(id, 0)
                return
            if _is(r, Errno.EINTR):
                continue
            ref e4 = self._fds[fd]
            if _is(r, Errno.EAGAIN):
                e4.readable = False
                self.recycle(buf^)
                return
            var id = e4.recv_op
            e4.recv_op = OpId.null()
            self.recycle(buf^)
            self._complete(id, r)
            return

    # ---- send ----------------------------------------------------------------

    def _start_send[D: Driver](mut self, mut d: D, id: OpId):
        var fd = self._ops[id].fd
        if not self._fds.contains(fd):
            self._complete(id, _neg(Errno.EBADF))
            return
        self._fds[fd].sends.append(id)
        if len(self._fds[fd].sends) == 1:
            self._do_send(d, fd)

    def _start_shutdown[D: Driver](mut self, mut d: D, id: OpId):
        var fd = self._ops[id].fd
        if not self._fds.contains(fd):
            self._complete(id, _neg(Errno.EBADF))
            return
        var how = self._ops[id].arg
        if how != SHUT_RD and len(self._fds[fd].sends) > 0:
            # The write direction is FIFO: the FIN goes out after the bytes
            # of every send submitted before it (`_do_send` runs it).
            self._fds[fd].sends.append(id)
            return
        self._complete(id, d.shutdown(self._fds[fd].raw, how))

    def _do_send[D: Driver](mut self, mut d: D, fd: FdId):
        """Make the fd's write queue progress: sends in order, each written
        completely (partial writes resume on the next writable edge), and
        queued write shutdowns once everything before them is out."""
        while self._fds.contains(fd) and len(self._fds[fd].sends) > 0:
            var id = self._fds[fd].sends[0]
            if self._ops[id].kind == OpKind.SHUTDOWN:
                _ = self._fds[fd].sends.pop(0)
                self._complete(id, d.shutdown(self._fds[fd].raw, self._ops[id].arg))
                continue
            if not self._fds[fd].writable:
                return
            if self._ops[id].buf.value().readable() == 0:
                _ = self._fds[fd].sends.pop(0)
                self._complete(id, self._ops[id].arg)
                continue
            var r = d.send(self._fds[fd].raw, self._ops[id].buf.value())
            if r > 0:
                try:
                    self._ops[id].buf.value().consume(r)
                except:
                    pass
                self._ops[id].arg += r
                if self._ops[id].buf.value().readable() > 0:
                    self._fds[fd].writable = False  # partial write: full
                    return
                continue  # loop completes it via the empty-buffer branch
            if r == 0 or _is(r, Errno.EAGAIN):
                self._fds[fd].writable = False
                return
            if _is(r, Errno.EINTR):
                continue
            _ = self._fds[fd].sends.pop(0)
            self._complete(id, r)

    # ---- cancel --------------------------------------------------------------

    def _cancel[D: Driver](mut self, mut d: D, target: OpId, cancel_op: OpId):
        if not self._ops.contains(target) or target == cancel_op:
            self._complete(cancel_op, _neg(Errno.ENOENT))
            return
        var kind = self._ops[target].kind
        if kind == OpKind._RESUME_ACCEPT:
            self._complete(cancel_op, _neg(Errno.ENOENT))  # not a caller's op
            return
        var fd = self._ops[target].fd
        var canceled = _neg(Errno.ECANCELED)
        if kind == OpKind.TIMEOUT:
            # Its heap entry goes stale with the op (flush pushed it already:
            # the timeout was submitted before this cancel).
            self._note_stale_timer()
        elif self._fds.contains(fd):
            ref e = self._fds[fd]
            if kind == OpKind.RECV and e.recv_op == target:
                e.recv_op = OpId.null()
            elif kind == OpKind.ACCEPT and e.accept_op == target:
                e.accept_op = OpId.null()
            elif kind == OpKind.SEND or kind == OpKind.SHUTDOWN:
                var at = -1
                for i in range(len(e.sends)):
                    if e.sends[i] == target:
                        at = i
                        break
                if at >= 0:
                    _ = e.sends.pop(at)
                    self._complete(target, canceled)
                    self._complete(cancel_op, 0)
                    if at == 0:
                        # A queued shutdown may now be at the head; it does
                        # not wait for writability.
                        self._do_send(d, fd)
                    return
            elif kind == OpKind.CONNECT and e.connect_op == target:
                e.connect_op = OpId.null()
                self._complete(target, canceled)
                _ = self._drop_fd(d, fd)
                self._complete(cancel_op, 0)
                return
        # Not parked anywhere means submitted but not started yet (same
        # flush batch, later index): completing it now removes it from the
        # slab, so flush skips it when its turn comes.
        self._complete(target, canceled)
        self._complete(cancel_op, 0)

    # ---- readiness -----------------------------------------------------------

    def on_ready[D: Driver](mut self, mut d: D, ev: ReadyEvent):
        """Apply one readiness edge and make every op on the fd progress."""
        var fd = FdId(ev.token)
        if not self._fds.contains(fd):
            return  # the fd was closed (and maybe reused) since it fired
        ref e = self._fds[fd]
        var bits = ev.events
        if (bits & READ_READY) != 0:
            e.readable = True
        if (bits & WRITE_READY) != 0:
            e.writable = True
        if (bits & (READ_CLOSED | HANGUP | ERROR)) != 0:
            e.read_closed = True  # sticky: read on to EOF/EAGAIN from now on
            e.readable = True
        if (bits & (HANGUP | ERROR)) != 0:
            e.writable = True  # let pending sends observe the error
        self._progress(d, fd)

    def _progress[D: Driver](mut self, mut d: D, fd: FdId):
        if not self._fds.contains(fd):
            return
        if not self._fds[fd].connect_op.is_null():
            if self._fds[fd].writable:
                self._finish_connect(d, fd)
            return
        if not self._fds[fd].accept_op.is_null():
            self._do_accept(d, fd)
        if self._fds.contains(fd) and not self._fds[fd].recv_op.is_null():
            self._do_recv(d, fd)
        if self._fds.contains(fd) and len(self._fds[fd].sends) > 0:
            self._do_send(d, fd)

    # ---- timers --------------------------------------------------------------

    def next_timer_ns(self) -> Optional[Int]:
        """Absolute deadline of the earliest live-looking timer (call
        `_prune_timers` first to drop canceled ones from the top)."""
        var top = self._timers.peek()
        if not top:
            return None
        return top.value().deadline_ns

    def _prune_timers(mut self):
        """Pop canceled entries off the top of the heap, so the loop never
        sleeps until (or wakes up for) a timer nobody waits for."""
        while True:
            var top = self._timers.peek()
            if not top or self._ops.contains(OpId(top.value().op)):
                return
            _ = self._timers.pop()
            if self._stale_timers > 0:
                self._stale_timers -= 1

    def _note_stale_timer(mut self):
        """A timeout was canceled: its heap entry is now garbage. Rebuild the
        heap without such entries once they are the majority (amortized
        O(1) per cancel), so canceling timers cannot grow it unboundedly."""
        self._stale_timers += 1
        if self._stale_timers >= 1024 and 2 * self._stale_timers > len(self._timers):
            var entries = self._timers.take_entries()
            var keep = List[TimerEntry](capacity=len(entries) - self._stale_timers + 1)
            for i in range(len(entries)):
                if self._ops.contains(OpId(entries[i].op)):
                    keep.append(entries[i])
            self._timers.rebuild(keep^)
            self._stale_timers = 0

    def timer_entries(self) -> Int:
        """Entries in the timer heap, stale ones included (diagnostics)."""
        return len(self._timers)

    def expire_timers(mut self):
        var now = self._now.as_nanos()
        while True:
            var top = self._timers.peek()
            if not top or top.value().deadline_ns > now:
                return
            var id = OpId(self._timers.pop().op)
            if not self._ops.contains(id):
                if self._stale_timers > 0:
                    self._stale_timers -= 1
                continue  # canceled
            var kind = self._ops[id].kind
            if kind == OpKind.TIMEOUT:
                self._complete(id, 0)
            elif kind == OpKind._RESUME_ACCEPT:
                var fd = self._ops[id].fd
                _ = self._ops.remove(id)
                self._internal -= 1
                if self._fds.contains(fd) and self._fds[fd].accept_paused:
                    self._fds[fd].accept_paused = False
                    self._rescan.append(fd)

    @inline(.always)
    def set_now(mut self, now: Instant):
        self._now = now

    # ---- teardown ------------------------------------------------------------

    def close_all[D: Driver](mut self, mut d: D):
        """Close every fd the loop owns (pending ops are dropped unreported)."""
        var ids = self._fds.ids()
        for i in range(len(ids)):
            var e = self._fds.remove(ids[i])
            if e.registered:
                _ = d.deregister(e.raw)
            _ = d.close(e.raw)
