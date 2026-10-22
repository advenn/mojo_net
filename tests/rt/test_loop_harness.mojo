"""Instrumented harness for the rt event-loop tests, plus self-tests showing
that its checks catch violations.

`test_loop_contract.mojo`, `test_loop_epoll.mojo` and `test_loop_faults.mojo`
import it. A test is a `Script` (its state and callbacks) inside a `Ctx`,
which also holds the `Harness`. Every op goes through a `Harness` wrapper
(`h.recv(lp, fd, tag)` ...), which records it; every completion goes through
one trampoline, `_tramp[S]`, which checks it against the completion contract
(docs/design.md contract 2, docs/rt.md) before the script sees it:
- exactly once: one final completion per op; multishot accept may first
  deliver any number of `more=True` completions; nothing after the final;
- never re-entrant: no completion while another callback runs, and none
  inside a submit call (it would arrive before its op was recorded);
- the completion's kind, tag and fd match the submitted op;
- FIFO per fd and direction: sends and write shutdowns complete in
  submission order, and so do receives (EBUSY rejections aside);
- buffers: every send completion hands its buffer back (canceled and failed
  ones too), fully consumed on success; a recv with data carries exactly
  `res` bytes, at most `RECV_CHUNK`;
- cancel is two-phase: the target's final completion comes first; res 0
  means the target was canceled, -ENOENT that it had already finished;
- close: every op submitted on the fd before the close completes before the
  close does, and every op submitted on it afterwards fails with EBADF;
- a timeout never fires before its deadline (loop time).

Only the public `rt` API is used, so the same checks hold on every backend.
Mojo cannot take the address of a function inside itself or inside a
reference cycle, so the one `Target` is built once (`bind`) and stored.

Aliasing hazard (verified on Mojo 1.2.0rc2): callbacks reach the `Ctx`
through the address in `ctx`, behind the compiler's back. A function that
receives the `Ctx` as a `mut`/borrowed *argument* treats it as noalias: if
the address was taken elsewhere (bind in the caller) and the function runs
the loop, it may keep fields in registers across `run_once` and never see
the callbacks' writes, and the compiler may even conclude that the function
leaves the struct unchanged, so the caller reads stale values too. Keep the
`Ctx` a local of the function that runs the loop, or call `bind` inside the
function that runs it (as `run` does).
"""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from linux import Errno, Instant
from linux.abi import RawSockaddr
from linux.consts import SHUT_RD
from net.addr import Ipv4Addr, SocketAddr
from rt.core import RECV_CHUNK, Completion, FdId, Loop, OpId, OpKind, Target
from rt.event_loop import EventLoop

comptime MS = 1_000_000
comptime SEC = 1_000_000_000
comptime WATCHDOG_NS = 20 * SEC
"""A scenario that has not called `h.finish` by then fails (and stops)."""

comptime TAG_FIX: UInt64 = UInt64(1) << 62
"""Tags at or above this belong to the harness (fixtures, watchdog)."""
comptime TAG_WATCHDOG: UInt64 = TAG_FIX | (UInt64(1) << 61)
comptime _STEP_LISTEN: UInt64 = 1
comptime _STEP_ACCEPT: UInt64 = 2
comptime _STEP_CONNECT: UInt64 = 3
comptime _STEP_LCLOSE: UInt64 = 4

comptime ECANCELED = -Int(Errno.ECANCELED.value)
comptime ENOENT = -Int(Errno.ENOENT.value)
comptime EBADF = -Int(Errno.EBADF.value)
comptime EBUSY = -Int(Errno.EBUSY.value)
comptime ECONNREFUSED = -Int(Errno.ECONNREFUSED.value)
comptime ECONNRESET = -Int(Errno.ECONNRESET.value)
comptime EPIPE = -Int(Errno.EPIPE.value)

comptime _MAX_ERRORS = 40


def rs(res: Int) -> String:
    """A result for messages: the number, or the errno name."""
    if res >= 0:
        return String(res)
    return String(Errno(Int32(-res)).name())


def loopback() -> RawSockaddr:
    """127.0.0.1:0 (the kernel or simulator picks the port)."""
    return SocketAddr(Ipv4Addr.LOCALHOST, 0).to_raw()


# ---- data patterns -----------------------------------------------------------


@always_inline
def pat(seed: Int, off: Int) -> UInt8:
    """Byte `off` of stream `seed`: not periodic in any chunk size the loop
    uses, so a lost, duplicated or reordered chunk shows up."""
    return UInt8((off * 7 + seed * 31 + (off >> 9)) % 251)


def pattern_buf(n: Int, seed: Int, start: Int = 0) -> ByteBuffer:
    """`n` bytes of stream `seed` from offset `start`."""
    var b = ByteBuffer()
    if n == 0:
        return b^
    try:
        b.ensure_writable(n)
        var sp = b.writable_span()
        for i in range(n):
            sp[i] = pat(seed, start + i)
        b.commit(n)
    except:
        pass
    return b^


def bytes_buf(s: StringSlice) -> ByteBuffer:
    var b = ByteBuffer()
    try:
        b.write_bytes(s.as_bytes())
    except:
        pass
    return b^


def mismatch(data: Span[UInt8, _], seed: Int, start: Int) -> Int:
    """Index of the first byte of `data` that is not stream `seed` at offset
    `start + i`, or -1."""
    for i in range(len(data)):
        if data[i] != pat(seed, start + i):
            return i
    return -1


def text_of(c: Completion) -> String:
    if not c.buf:
        return ""
    return String(from_utf8_lossy=c.buf.value().readable_span())


# ---- records -----------------------------------------------------------------


@fieldwise_init
struct Rec(Copyable, Movable):
    """One delivered completion."""

    var seq: Int
    var op: UInt64
    var kind: OpKind
    var tag: UInt64
    var res: Int
    var more: Bool
    var fd: UInt64
    var buf_len: Int
    """Readable bytes of `c.buf`; -1 when there was no buffer."""
    var at_ns: Int
    """`loop.now()` at delivery."""


@fieldwise_init
struct OpInfo(Copyable, Movable):
    var id: UInt64
    var kind: OpKind
    var tag: UInt64
    var fd: UInt64
    """The fd the op runs on (0 for post/timeout/listen/connect/cancel)."""
    var sub: Int
    """Submission order."""
    var arg: Int
    """SEND: bytes; TIMEOUT: deadline ns; CANCEL: target id; SHUTDOWN: how."""
    var must_ebadf: Bool
    """Submitted on an fd after its close was submitted."""
    var finals: Int
    var mores: Int
    var final_seq: Int
    var final_res: Int


@fieldwise_init
struct FdInfo(Copyable, Movable):
    var fd: UInt64
    var ops: List[Int]
    var close_sub: Int
    """Submission index of the first close on this fd, -1 if none yet."""
    var last_write_sub: Int
    var last_read_sub: Int


@fieldwise_init
struct Pair(Copyable, Movable):
    """A connected pair made by `open_pair`: the listener is closed as soon
    as its one connection is accepted."""

    var listener: FdId
    var server: FdId
    var client: FdId
    var ready: Bool


def _nop_target(ctx: Int, mut lp: Loop, var c: Completion):
    pass


struct Harness(Movable):
    var t: Target
    """The one target every op uses (set by `bind`)."""
    var ops: List[OpInfo]
    var index: Dict[UInt64, Int]
    var fds: List[FdInfo]
    var fd_index: Dict[UInt64, Int]
    var recs: List[Rec]
    var errors: List[String]
    var n_errors: Int
    var depth: Int
    var in_submit: Bool
    var seq: Int
    var subs: Int
    var watchdog: OpId
    var finished: Bool
    var pairs: List[Pair]
    var keep_recs: Bool

    def __init__(out self):
        self.t = Target(_nop_target, 0)
        self.ops = []
        self.index = {}
        self.fds = []
        self.fd_index = {}
        self.recs = []
        self.errors = []
        self.n_errors = 0
        self.depth = 0
        self.in_submit = False
        self.seq = 0
        self.subs = 0
        self.watchdog = OpId.null()
        self.finished = False
        self.pairs = []
        self.keep_recs = True

    # ---- failures ------------------------------------------------------------

    def fail(mut self, msg: String):
        self.n_errors += 1
        if len(self.errors) < _MAX_ERRORS:
            self.errors.append(msg)

    def expect(mut self, cond: Bool, msg: String):
        if not cond:
            self.fail(msg)

    # ---- bookkeeping ---------------------------------------------------------

    def _fdi(mut self, fd: UInt64) -> Int:
        var got = self.fd_index.get(fd)
        if got:
            return got.value()
        var i = len(self.fds)
        self.fds.append(FdInfo(fd, [], -1, -1, -1))
        self.fd_index[fd] = i
        return i

    def _track(mut self, id: OpId, kind: OpKind, tag: UInt64, fd: UInt64, arg: Int):
        if id.raw in self.index:
            self.fail(String("op id ", id, " handed out twice"))
        var i = len(self.ops)
        self.subs += 1
        var must_ebadf = False
        if fd != 0:
            var f = self._fdi(fd)
            self.fds[f].ops.append(i)
            if self.fds[f].close_sub >= 0:
                must_ebadf = True
            elif kind == OpKind.CLOSE:
                self.fds[f].close_sub = self.subs
        self.ops.append(
            OpInfo(id.raw, kind, tag, fd, self.subs, arg, must_ebadf, 0, 0, -1, 0)
        )
        self.index[id.raw] = i

    def info(self, id: OpId) -> Optional[OpInfo]:
        var i = self.index.get(id.raw)
        if not i:
            return None
        return self.ops[i.value()].copy()

    def res_of(self, id: OpId) -> Int:
        """Final result of `id` (Int.MIN while it is still pending)."""
        var o = self.info(id)
        if not o or o.value().finals == 0:
            return Int.MIN
        return o.value().final_res

    def done(self, id: OpId) -> Bool:
        var o = self.info(id)
        return Bool(o) and o.value().finals > 0

    # ---- submission wrappers -------------------------------------------------

    def post(mut self, mut lp: Loop, tag: UInt64 = 0) -> OpId:
        self.in_submit = True
        var id = lp.post(self.t, tag)
        self.in_submit = False
        self._track(id, OpKind.POST, tag, 0, 0)
        return id

    def timeout(mut self, mut lp: Loop, delay_ns: Int, tag: UInt64 = 0) -> OpId:
        self.in_submit = True
        var id = lp.timeout_ns(delay_ns, self.t, tag)
        self.in_submit = False
        var now = lp.now().as_nanos()
        var d = max(0, delay_ns)
        self._track(id, OpKind.TIMEOUT, tag, 0, Int.MAX if d > Int.MAX - now else now + d)
        return id

    def listen(
        mut self, mut lp: Loop, addr: RawSockaddr, tag: UInt64 = 0, backlog: Int = 1024
    ) -> OpId:
        self.in_submit = True
        var id = lp.listen(addr, self.t, tag, backlog)
        self.in_submit = False
        self._track(id, OpKind.LISTEN, tag, 0, 0)
        return id

    def connect(mut self, mut lp: Loop, addr: RawSockaddr, tag: UInt64 = 0) -> OpId:
        self.in_submit = True
        var id = lp.connect(addr, self.t, tag)
        self.in_submit = False
        self._track(id, OpKind.CONNECT, tag, 0, 0)
        return id

    def accept(mut self, mut lp: Loop, fd: FdId, tag: UInt64 = 0) -> OpId:
        self.in_submit = True
        var id = lp.accept(fd, self.t, tag)
        self.in_submit = False
        self._track(id, OpKind.ACCEPT, tag, fd.raw, 0)
        return id

    def recv(mut self, mut lp: Loop, fd: FdId, tag: UInt64 = 0) -> OpId:
        self.in_submit = True
        var id = lp.recv(fd, self.t, tag)
        self.in_submit = False
        self._track(id, OpKind.RECV, tag, fd.raw, 0)
        return id

    def send(mut self, mut lp: Loop, fd: FdId, var buf: ByteBuffer, tag: UInt64 = 0) -> OpId:
        var n = buf.readable()
        self.in_submit = True
        var id = lp.send(fd, buf^, self.t, tag)
        self.in_submit = False
        self._track(id, OpKind.SEND, tag, fd.raw, n)
        return id

    def send_text(mut self, mut lp: Loop, fd: FdId, s: StringSlice, tag: UInt64 = 0) -> OpId:
        return self.send(lp, fd, bytes_buf(s), tag)

    def shutdown(mut self, mut lp: Loop, fd: FdId, how: Int, tag: UInt64 = 0) -> OpId:
        self.in_submit = True
        var id = lp.shutdown(fd, how, self.t, tag)
        self.in_submit = False
        self._track(id, OpKind.SHUTDOWN, tag, fd.raw, how)
        return id

    def close(mut self, mut lp: Loop, fd: FdId, tag: UInt64 = 0) -> OpId:
        self.in_submit = True
        var id = lp.close(fd, self.t, tag)
        self.in_submit = False
        self._track(id, OpKind.CLOSE, tag, fd.raw, 0)
        return id

    def cancel(mut self, mut lp: Loop, op: OpId, tag: UInt64 = 0) -> OpId:
        self.in_submit = True
        var id = lp.cancel(op, self.t, tag)
        self.in_submit = False
        self._track(id, OpKind.CANCEL, tag, 0, Int(op.raw))
        return id

    # ---- scenario control ----------------------------------------------------

    def arm(mut self, mut lp: Loop, watchdog_ns: Int):
        if watchdog_ns > 0:
            self.watchdog = self.timeout(lp, watchdog_ns, TAG_WATCHDOG)

    def finish(mut self, mut lp: Loop):
        """The scenario is complete: cancel the watchdog so `run()` can
        return once every op has completed."""
        if self.finished:
            return
        self.finished = True
        if not self.watchdog.is_null():
            _ = self.cancel(lp, self.watchdog, TAG_WATCHDOG)

    def open_pair(mut self, mut lp: Loop) -> Int:
        """Start making a connected loopback pair; the script's `on_pair(i)`
        runs once both ends exist (`h.pairs[i].client` / `.server`)."""
        var i = len(self.pairs)
        self.pairs.append(Pair(FdId.null(), FdId.null(), FdId.null(), False))
        _ = self.listen(lp, loopback(), _fix_tag(i, _STEP_LISTEN))
        return i

    def _fixture(mut self, mut lp: Loop, var c: Completion) -> Int:
        """Advance a pair fixture; returns the pair index that just became
        ready, else -1."""
        var i = Int((c.tag >> 4) & 0xFFFF)
        var step = c.tag & 0xF
        if step == _STEP_LISTEN:
            if not c.ok():
                self.fail("pair listen failed: " + rs(c.res))
                lp.stop()
                return -1
            self.pairs[i].listener = c.fd
            _ = self.accept(lp, c.fd, _fix_tag(i, _STEP_ACCEPT))
            var a = lp.local_addr(c.fd)
            if not a:
                self.fail("listener has no local address")
                lp.stop()
                return -1
            _ = self.connect(lp, a.value(), _fix_tag(i, _STEP_CONNECT))
        elif step == _STEP_ACCEPT:
            if c.more:
                if not self.pairs[i].server.is_null():
                    self.fail("pair listener accepted a second connection")
                    return -1
                self.pairs[i].server = c.fd
                _ = self.close(lp, self.pairs[i].listener, _fix_tag(i, _STEP_LCLOSE))
            elif c.res != ECANCELED:
                self.fail("pair accept ended with " + rs(c.res))
                lp.stop()
                return -1
        elif step == _STEP_CONNECT:
            if not c.ok():
                self.fail("pair connect failed: " + rs(c.res))
                lp.stop()
                return -1
            self.pairs[i].client = c.fd
        elif step == _STEP_LCLOSE:
            self.expect(c.res == 0, "pair listener close: " + rs(c.res))
        ref p = self.pairs[i]
        if not p.ready and not p.server.is_null() and not p.client.is_null():
            p.ready = True
            return i
        return -1

    # ---- the checks ----------------------------------------------------------

    def record(mut self, lp: Loop, c: Completion):
        """Check one completion against the contract and record it."""
        self.seq += 1
        var s = self.seq
        var blen = c.buf.value().readable() if c.buf else -1
        if self.keep_recs:
            self.recs.append(
                Rec(s, c.op.raw, c.kind, c.tag, c.res, c.more, c.fd.raw, blen, lp.now().as_nanos())
            )
        var what = String(c)
        if self.depth != 0:
            self.fail("re-entrant completion (inside another callback): " + what)
        if self.in_submit:
            self.fail("completion delivered inside a submit call: " + what)
        var found = self.index.get(c.op.raw)
        if not found:
            self.fail("completion for an op that was never submitted: " + what)
            return
        var i = found.value()
        var o = self.ops[i].copy()
        if c.kind != o.kind:
            self.fail(String("kind mismatch: submitted ", o.kind, ", got ", what))
        if c.tag != o.tag:
            self.fail(String("tag mismatch: submitted ", o.tag, ", got ", c.tag, " ", what))
        if o.finals > 0:
            self.fail("completion after the final one: " + what)
        if c.more:
            if o.kind != OpKind.ACCEPT:
                self.fail("more=True on a single-shot op: " + what)
            if c.res < 0 or c.fd.is_null() or c.fd.raw == o.fd:
                self.fail("accept more=True without a new connection: " + what)
            self.ops[i].mores += 1
            return
        self.ops[i].finals += 1
        self.ops[i].final_seq = s
        self.ops[i].final_res = c.res
        var k = o.kind
        if k == OpKind.RECV or k == OpKind.SEND or k == OpKind.SHUTDOWN or k == OpKind.CLOSE:
            if c.fd.raw != o.fd:
                self.fail("completion fd differs from the op's fd: " + what)
        if o.must_ebadf and c.res != EBADF:
            self.fail("op submitted after its fd's close did not fail with EBADF: " + what)
        # Buffers.
        if k == OpKind.SEND:
            if blen < 0:
                self.fail("send completion without its buffer: " + what)
            elif c.res >= 0 and (blen != 0 or c.res != o.arg):
                self.fail(
                    String("send of ", o.arg, " bytes completed with ", c.res, ", ", blen, " left: ", what)
                )
        elif k == OpKind.RECV:
            if c.res > 0 and (blen != c.res or c.res > RECV_CHUNK):
                self.fail(String("recv res ", c.res, " with ", blen, " buffered bytes: ", what))
            if c.res <= 0 and blen >= 0:
                self.fail("recv without data carries a buffer: " + what)
        elif blen >= 0:
            self.fail("unexpected buffer on: " + what)
        # Results.
        if k == OpKind.POST:
            self.expect(c.res == 0 or c.res == ECANCELED, "post res: " + what)
        elif k == OpKind.TIMEOUT:
            if c.res == 0 and lp.now().as_nanos() < o.arg:
                self.fail(String("timeout fired ", o.arg - lp.now().as_nanos(), " ns early: ", what))
            self.expect(c.res == 0 or c.res == ECANCELED, "timeout res: " + what)
        elif k == OpKind.CANCEL:
            self._check_cancel(o, c.res, s, what)
        elif k == OpKind.CLOSE:
            self._check_close(o, c.res, s, what)
        # FIFO per fd and direction.
        if o.fd != 0 and (k == OpKind.SEND or (k == OpKind.SHUTDOWN and o.arg != SHUT_RD)):
            var f = self._fdi(o.fd)
            if o.sub < self.fds[f].last_write_sub:
                self.fail("write-direction completion out of submission order: " + what)
            self.fds[f].last_write_sub = o.sub
        elif o.fd != 0 and k == OpKind.RECV and c.res != EBUSY:
            var f = self._fdi(o.fd)
            if o.sub < self.fds[f].last_read_sub:
                self.fail("recv completion out of submission order: " + what)
            self.fds[f].last_read_sub = o.sub

    def _check_cancel(mut self, o: OpInfo, res: Int, s: Int, what: String):
        if res != 0 and res != ENOENT:
            self.fail("cancel res must be 0 or ENOENT: " + what)
            return
        var ti = self.index.get(UInt64(o.arg))
        if not ti:
            if res == 0:
                self.fail("cancel of an unknown op reported success: " + what)
            return
        var t = self.ops[ti.value()].copy()
        if t.finals == 0:
            self.fail(
                String("cancel completed (", rs(res), ") while its target ", t.kind, " is still pending")
            )
            return
        if res == 0 and t.final_res != ECANCELED:
            self.fail(String("cancel res 0 but the target completed with ", rs(t.final_res)))

    def _check_close(mut self, o: OpInfo, res: Int, s: Int, what: String):
        if o.must_ebadf:
            return
        var f = self._fdi(o.fd)
        var ids = self.fds[f].ops.copy()
        for j in range(len(ids)):
            var p = self.ops[ids[j]].copy()
            if p.sub < o.sub and p.kind != OpKind.CLOSE and p.finals == 0:
                self.fail(String("close completed before the ", p.kind, " submitted earlier on its fd"))

    def verify(self, allow_pending: Bool = False) -> List[String]:
        var out = self.errors.copy()
        if self.n_errors > len(self.errors):
            out.append(String("... ", self.n_errors - len(self.errors), " more errors"))
        if not allow_pending:
            var n = 0
            for i in range(len(self.ops)):
                if self.ops[i].finals == 0:
                    n += 1
                    if n <= 10:
                        ref o = self.ops[i]
                        out.append(String("op never completed: ", o.kind, " tag=", o.tag, " fd=", o.fd))
            if n > 10:
                out.append(String("... ", n - 10, " more ops never completed"))
        return out^

    def assert_ok(self, allow_pending: Bool = False) raises:
        var errs = self.verify(allow_pending)
        if len(errs) > 0:
            var msg = String("contract violations:")
            for i in range(len(errs)):
                msg += "\n    " + errs[i]
            print(msg)
            raise Error(msg)

    # ---- queries for assertions ----------------------------------------------

    def tags_of(self, kind: OpKind, below: UInt64 = TAG_FIX) -> List[UInt64]:
        """Tags of the final completions of `kind`, in delivery order."""
        var out = List[UInt64]()
        for i in range(len(self.recs)):
            ref r = self.recs[i]
            if r.kind == kind and not r.more and r.tag < below:
                out.append(r.tag)
        return out^

    def seq_of(self, id: OpId) -> Int:
        var o = self.info(id)
        if not o or o.value().finals == 0:
            return -1
        return o.value().final_seq


@always_inline
def _fix_tag(i: Int, step: UInt64) -> UInt64:
    return TAG_FIX | (UInt64(i) << 4) | step


# ---- scripts -----------------------------------------------------------------


trait Script(Deinitable, Movable):
    def start(mut self, mut h: Harness, mut lp: Loop):
        """Submit the scenario's first ops (called before the loop runs)."""
        pass

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        """Every completion with a script tag (below `TAG_FIX`)."""
        ...

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        """`h.pairs[i]` is connected."""
        pass


struct Ctx[S: Script](Movable):
    var h: Harness
    var s: Self.S

    def __init__(out self, var s: Self.S):
        self.h = Harness()
        self.s = s^


def _tramp[S: Script](ctx: Int, mut lp: Loop, var c: Completion):
    ref x = Pointer[Ctx[S], MutUntrackedOrigin](unsafe_from_address=ctx)[]
    x.h.record(lp, c)
    x.h.depth += 1
    if c.tag == TAG_WATCHDOG:
        if c.kind == OpKind.TIMEOUT and c.res == 0:
            x.h.fail("watchdog: the scenario did not finish in time")
            lp.stop()
    elif c.tag >= TAG_FIX:
        var ready = x.h._fixture(lp, c^)
        if ready >= 0:
            x.s.on_pair(x.h, lp, ready)
    else:
        x.s.on(x.h, lp, c^)
    x.h.depth -= 1


def bind[S: Script](mut x: Ctx[S]):
    """Point the harness target at `x` (whose address must not change while
    the loop holds ops for it)."""
    x.h.t = Target(_tramp[S], Int(Pointer(to=x)))


def run[S: Script](mut ev: EventLoop, mut x: Ctx[S], watchdog_ns: Int = WATCHDOG_NS) raises:
    """Bind, arm the watchdog, start the script and run the loop until no
    op is pending (or something called `stop()`)."""
    bind(x)
    x.h.arm(ev.loop, watchdog_ns)
    x.s.start(x.h, ev.loop)
    ev.run()


def count_open_fds() raises -> Int:
    """Entries in /proc/self/fd (the listing's own fd included, so only
    differences matter)."""
    from std.os import listdir

    return len(listdir("/proc/self/fd"))


# ---- self-tests: the checker catches violations ------------------------------


struct _Nothing(Script):
    def __init__(out self):
        pass

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        pass


def _fake(op: OpId, kind: OpKind, tag: UInt64, res: Int, more: Bool, fd: FdId, var buf: Optional[ByteBuffer]) -> Completion:
    return Completion(op, kind, tag, res, more, fd, buf^, Target(_nop_target, 0))


def test_harness_flags_double_completion_and_reentrancy() raises:
    var lp = Loop(Instant(nanos=0))
    var h = Harness()
    var id = h.post(lp, 1)
    h.record(lp, _fake(id, OpKind.POST, 1, 0, False, FdId.null(), None))
    assert_equal(len(h.verify()), 0)
    h.record(lp, _fake(id, OpKind.POST, 1, 0, False, FdId.null(), None))
    assert_equal(len(h.verify()), 1)  # completion after the final one
    var h2 = Harness()
    var id2 = h2.post(lp, 2)
    h2.depth = 1
    h2.record(lp, _fake(id2, OpKind.POST, 2, 0, False, FdId.null(), None))
    assert_equal(len(h2.verify()), 1)  # re-entrant
    var h3 = Harness()
    _ = h3.post(lp, 3)
    assert_equal(len(h3.verify()), 1)  # never completed
    assert_equal(len(h3.verify(allow_pending=True)), 0)


def test_harness_flags_send_fifo_and_missing_buffer() raises:
    var lp = Loop(Instant(nanos=0))
    var h = Harness()
    var fd = FdId(UInt64(0x1_0000_0003))
    var a = h.send(lp, fd, bytes_buf("ab"), 1)
    var b = h.send(lp, fd, bytes_buf("cd"), 2)
    # b before a, and b without its buffer.
    h.record(lp, _fake(b, OpKind.SEND, 2, 2, False, fd, None))
    h.record(lp, _fake(a, OpKind.SEND, 1, 2, False, fd, Optional(ByteBuffer())))
    var errs = h.verify()
    assert_equal(len(errs), 2)


def test_harness_flags_cancel_order_and_close_order() raises:
    var lp = Loop(Instant(nanos=0))
    var h = Harness()
    var fd = FdId(UInt64(0x1_0000_0004))
    var r = h.recv(lp, fd, 1)
    var c = h.cancel(lp, r, 2)
    # Cancel reports success before its target completed.
    h.record(lp, _fake(c, OpKind.CANCEL, 2, 0, False, FdId.null(), None))
    h.record(lp, _fake(r, OpKind.RECV, 1, ECANCELED, False, fd, None))
    assert_equal(len(h.verify()), 1)
    var h2 = Harness()
    var r2 = h2.recv(lp, fd, 1)
    var cl = h2.close(lp, fd, 2)
    var late = h2.recv(lp, fd, 3)
    h2.record(lp, _fake(cl, OpKind.CLOSE, 2, 0, False, fd, None))  # before r2
    h2.record(lp, _fake(r2, OpKind.RECV, 1, ECANCELED, False, fd, None))
    h2.record(lp, _fake(late, OpKind.RECV, 3, 0, False, fd, None))  # not EBADF
    assert_equal(len(h2.verify()), 2)


def test_harness_pair_fixture_runs_clean() raises:
    """The fixture alone: a pair is made, then the script closes both ends."""
    var ev = EventLoop()
    var x = Ctx[_PairOnly](_PairOnly())
    run(ev, x)
    x.h.assert_ok()
    assert_true(x.s.paired)
    assert_equal(ev.loop.open_fds(), 0)
    assert_equal(ev.loop.pending_ops(), 0)


struct _PairOnly(Script):
    var paired: Bool
    var closed: Int

    def __init__(out self):
        self.paired = False
        self.closed = 0

    def start(mut self, mut h: Harness, mut lp: Loop):
        _ = h.open_pair(lp)

    def on_pair(mut self, mut h: Harness, mut lp: Loop, i: Int):
        self.paired = True
        _ = h.close(lp, h.pairs[i].client, 1)
        _ = h.close(lp, h.pairs[i].server, 1)

    def on(mut self, mut h: Harness, mut lp: Loop, var c: Completion):
        self.closed += 1
        h.expect(c.res == 0, "close: " + rs(c.res))
        if self.closed == 2:
            h.finish(lp)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
