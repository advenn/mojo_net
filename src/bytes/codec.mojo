"""The sans-I/O codec contract (docs/design.md, contract 1), a reference
`LineCodec`, and `drive_chunked`, the chunking-invariance checker every
codec's tests should run.

A codec is a pure state machine that turns received bytes into events and
queued messages into bytes to send. It never touches a socket, a clock or
the event loop, so the same codec runs over a blocking stream, the `rt`
event loop, a future async executor, or a test that feeds it byte arrays.
The driver owns all I/O and all time:

    loop:
        n = recv(sock, buf)                  # driver: I/O
        if n == 0: codec.feed_eof(); drain()
        data = buf[:n]
        while data:                          # rule 5: what fits, then drain
            k = min(len(data), codec.feed_capacity())
            codec.feed(data[:k]); data = data[k:]
            drain()
        codec.poll_transmit(out); send(sock, out)
        arm_timer(codec.next_deadline())
    on timer:  codec.handle_timeout(clock.now())
    drain:     while ev = codec.next_event(): handle(ev)

`feed` copies whatever it keeps, since a receive buffer is only lent to it
(design.md contract 4). `out` is a `ByteBuffer` the driver owns: an evented
driver moves it into the send operation and gets it back at completion, so
no staging buffer is needed, and a codec that serializes straight into
`out` writes each outgoing byte once.

Rules every `Codec` follows:
1. **No I/O.** No syscalls, no `rt`, no socket modules. Codec modules import
   only `std`, `linux` (for `IoError`/`Instant`), `bytes.buffer` (for
   `ByteBuffer`, which does no I/O), pure computation (`crypto`, for
   `pg`'s authentication) and other codecs.
2. **No clocks.** Time enters only through `handle_timeout(now)`. A codec
   never calls `Instant.now()`; `next_deadline()` is computed from instants
   it was given.
3. **Deterministic.** Outputs depend only on the sequence of calls and their
   arguments: no global state, no unseeded randomness.
4. **Any chunking.** Input may arrive split at any byte boundary, including
   empty `feed`s. However the stream is cut, a driver that follows rule 5
   gets the same sequence of events (and the same kind of any terminal
   error), whatever its receive size. `drive_chunked` checks it. One
   refinement: a codec may deliver a byte stream (an HTTP body) as data
   events as soon as bytes arrive, so that streaming is not delayed; then
   only the concatenation of consecutive data events is invariant, and a
   check merges them first (`tests/http` does). Such a codec says so.
5. **Feed what fits, then drain.** `feed_capacity()` is how many bytes the
   next `feed` may carry: a codec that bounds its unparsed input reports
   the room left (the default, `Int.MAX`, means unbounded). The driver
   feeds at most that much per call and calls `next_event()` until it
   returns None before feeding more, so a receive larger than the room is
   fed as several pieces with a drain after each. Right after such a drain
   the room is at least 1 byte (a message that could never fit has already
   raised, for example `InvalidData` for an over-long line), so the driver
   always makes progress and its receive size never changes the outcome.
   Feeding more than `feed_capacity()` is a driver bug: a bounded codec
   raises `OutOfMemory` and is poisoned (rule 6), because the input is lost.
6. **Errors on the input side are terminal.** Once `feed`, `feed_eof` or
   `next_event` raises, the stream is unusable: the codec keeps raising an
   error of the same kind from those methods, and the driver closes the
   connection. Two driver mistakes raise without poisoning, since no input
   is lost: misuse of the send side (an invalid outgoing message), and a
   `feed` after `feed_eof` (rule 10).
7. **Transmit is FIFO and append-only.** `poll_transmit(out)` appends queued
   bytes to `out` (never reading or consuming what is already there), in
   the order they were queued, and returns how many it appended. It
   appends at most `out.max_writable()` bytes and keeps the rest queued, so
   0 means nothing is pending only while `out` has room: a driver whose
   `out` is full sends from it before it polls again. Drivers poll after
   every call into the codec.
8. **Deadlines are absolute and re-read.** `next_deadline()` is the earliest
   instant at which `handle_timeout` must be called (None: no timer). It can
   change after any call, so drivers read it again each time.
9. **Timeouts tolerate early and repeated calls.** `handle_timeout(now)`
   with `now` before the deadline is a no-op (timers fire early, wakeups are
   spurious). It may raise `TimedOut`.
10. **EOF is explicit.** `feed_eof()` says the peer finished sending; `feed`
    after it raises `InvalidInput` (without poisoning: rule 6). Complete events are still delivered;
    a partial message then makes `next_event` raise `UnexpectedEof`.
"""

from linux import ErrorKind, IoError
from linux.time import Instant

from .buffer import ByteBuffer

comptime _LF: UInt8 = 10
comptime _CR: UInt8 = 13


# ---- the contract ------------------------------------------------------------


trait Codec(Deinitable, Movable):
    """A sans-I/O protocol state machine (see the module docstring for the
    rules). `Event` is what `next_event` yields: owned values, never views
    into the codec's buffers, so they stay valid while the codec keeps
    parsing. Inside a codec, positions in its own `ByteBuffer`s persist as
    offsets (`find`, `read_until`, `byte_at`), never as spans kept across a
    mutating call such as `feed` (see `bytes.buffer`; fault builds check it)."""

    comptime Event: Deinitable & Movable

    def feed(mut self, data: Span[UInt8, _]) raises IoError:
        """Buffer received bytes (any split, possibly empty), at most
        `feed_capacity()` of them."""
        ...

    def feed_capacity(self) -> Int:
        """How many bytes the next `feed` may carry (rule 5). At least 1
        right after `next_event` returned None, unless the input side has
        failed or ended. The default, `Int.MAX`, is for codecs that accept
        any amount."""
        return Int.MAX

    def feed_eof(mut self) raises IoError:
        """The peer finished sending; no more `feed` calls follow."""
        ...

    def next_event(mut self) raises IoError -> Optional[Self.Event]:
        """The next complete event, or None until more input arrives."""
        ...

    def poll_transmit(mut self, mut out: ByteBuffer) raises IoError -> Int:
        """Append queued outgoing bytes to `out`; return how many."""
        ...

    def next_deadline(self) -> Optional[Instant]:
        """When `handle_timeout` must be called next, if ever."""
        ...

    def handle_timeout(mut self, now: Instant) raises IoError:
        """Run timers due at `now` (no-op before the deadline)."""
        ...


# ---- LineCodec ---------------------------------------------------------------


struct LineCodec(Codec, Copyable):
    """Newline-delimited messages: the reference implementation of `Codec`.

    Receive: a line ends at LF; a CR right before the LF is dropped too
    (CRLF tolerant), any other CR is content. Each event is the line's
    bytes without the terminator (empty lines give empty events). A line
    whose content exceeds `max_line_length` raises `InvalidData` (the peer
    broke the protocol) as soon as that is certain, even before its LF
    arrives, so a peer cannot make the codec buffer an endless line. EOF in
    the middle of a line raises `UnexpectedEof` (strict: a truncated line is
    not delivered).

    Send: `send_line` queues a line plus LF (or CRLF with `crlf=True`);
    `poll_transmit` hands them out in order.

    Time: an optional absolute deadline (`set_deadline`), reported by
    `next_deadline`; `handle_timeout(now)` at or after it raises `TimedOut`
    once and clears it. A timeout does not poison the codec; the
    application decides whether to close.
    """

    comptime Event = List[UInt8]

    comptime DEFAULT_MAX_LINE = 8 * 1024
    comptime DEFAULT_MAX_BUFFERED = 1024 * 1024

    var _rx: ByteBuffer
    var _tx: ByteBuffer
    var _max_line: Int
    var _scanned: Int
    """Bytes of the current partial line already searched for LF, so
    byte-at-a-time input is O(n) overall instead of O(n^2)."""
    var _eof: Bool
    var _crlf: Bool
    var _failed: Optional[IoError]
    var _deadline: Optional[Instant]

    def __init__(
        out self,
        *,
        max_line_length: Int = Self.DEFAULT_MAX_LINE,
        max_buffered: Int = Self.DEFAULT_MAX_BUFFERED,
        crlf: Bool = False,
    ) raises IoError:
        """`max_line_length` bounds line content (terminator excluded);
        `max_buffered` bounds unparsed input (`feed_capacity()` is the room
        left) and queued output, and must hold one maximal line plus CRLF.
        Otherwise `InvalidInput`."""
        if (
            max_buffered < 2
            or max_line_length < 0
            or max_line_length > max_buffered - 2
        ):
            raise IoError.of_kind("LineCodec.__init__", ErrorKind.InvalidInput)
        self._rx = ByteBuffer(max_size=max_buffered)
        self._tx = ByteBuffer(max_size=max_buffered)
        self._max_line = max_line_length
        self._scanned = 0
        self._eof = False
        self._crlf = crlf
        self._failed = None
        self._deadline = None

    # ---- receive ---------------------------------------------------------

    def _fail(mut self, op: StaticString, kind: ErrorKind) -> IoError:
        """Poison the input side (rule 6) and return the error to raise."""
        var e = IoError.of_kind(op, kind)
        self._failed = e
        return e

    def feed(mut self, data: Span[UInt8, _]) raises IoError:
        if self._failed:
            raise self._failed.value()
        if self._eof:
            raise IoError.of_kind("LineCodec.feed", ErrorKind.InvalidInput)
        if len(data) > self._rx.max_writable():
            # The driver ignored feed_capacity() (rule 5). Input that cannot
            # be buffered is lost: the stream is broken.
            raise self._fail("LineCodec.feed", ErrorKind.OutOfMemory)
        self._rx.write_bytes(data)

    def feed_capacity(self) -> Int:
        """`max_buffered` minus the unparsed bytes held. After `next_event`
        returned None at most one partial line of `max_line_length + 1`
        bytes (content plus a CR) is held, so this is then at least
        `max_buffered - max_line_length - 1 >= 1`."""
        return self._rx.max_writable()

    def feed_eof(mut self) raises IoError:
        if self._failed:
            raise self._failed.value()
        self._eof = True

    def next_event(mut self) raises IoError -> Optional[List[UInt8]]:
        if self._failed:
            raise self._failed.value()
        # A frame is content + LF, content + CRLF at most max_line + 2.
        var frame: Optional[Int]
        try:
            frame = self._rx.read_until(
                _LF, self._max_line + 2, start=self._scanned
            )
        except e:
            # Only the frame limit can fail here (InvalidData).
            raise self._fail("LineCodec.next_event", e.kind)
        if not frame:
            var n = len(self._rx)
            self._scanned = n
            # read_until only proves "too long" at max + 2 bytes; a partial
            # line is already too long at max + 1 unless its last byte is a
            # CR that may yet pair with an LF.
            var at_least = n
            if n > 0 and self._rx.byte_at(n - 1) == _CR:
                at_least -= 1
            if at_least > self._max_line:
                raise self._fail("LineCodec.next_event", ErrorKind.InvalidData)
            if self._eof and n > 0:
                raise self._fail(
                    "LineCodec.next_event", ErrorKind.UnexpectedEof
                )
            return None
        var n = frame.value()
        var content = n - 1
        if content > 0 and self._rx.byte_at(content - 1) == _CR:
            content -= 1
        if content > self._max_line:
            raise self._fail("LineCodec.next_event", ErrorKind.InvalidData)
        var line = self._rx.read_bytes(content)
        self._rx.consume(n - content)
        self._scanned = 0
        return line^

    # ---- send ------------------------------------------------------------

    def send_line(mut self, line: Span[UInt8, _]) raises IoError:
        """Queue `line` plus the terminator. All or nothing: `InvalidInput`
        if it is longer than `max_line_length` or contains CR/LF (the peer
        would split or strip it), `OutOfMemory` if the queue is full."""
        if len(line) > self._max_line:
            raise IoError.of_kind("LineCodec.send_line", ErrorKind.InvalidInput)
        for b in line:
            if b == _LF or b == _CR:
                raise IoError.of_kind(
                    "LineCodec.send_line", ErrorKind.InvalidInput
                )
        var term = 2 if self._crlf else 1
        if len(line) + term > self._tx.max_writable():
            raise IoError.of_kind("LineCodec.send_line", ErrorKind.OutOfMemory)
        self._tx.write_bytes(line)
        if self._crlf:
            self._tx.write_byte(_CR)
        self._tx.write_byte(_LF)

    @inline(.always)
    def pending_transmit(self) -> Int:
        """Queued bytes not yet handed out by `poll_transmit`."""
        return len(self._tx)

    def poll_transmit(mut self, mut out: ByteBuffer) raises IoError -> Int:
        var n = min(len(self._tx), out.max_writable())
        if n == 0:
            return 0
        out.write_bytes(self._tx.readable_span()[0:n])
        self._tx.consume(n)
        return n

    # ---- time ------------------------------------------------------------

    def set_deadline(mut self, at: Optional[Instant]):
        """Arm (or with None, disarm) the absolute deadline."""
        self._deadline = at

    def next_deadline(self) -> Optional[Instant]:
        return self._deadline

    def handle_timeout(mut self, now: Instant) raises IoError:
        if self._deadline and now >= self._deadline.value():
            self._deadline = None
            raise IoError.of_kind(
                "LineCodec.handle_timeout", ErrorKind.TimedOut
            )


# ---- testing support: chunking invariance -------------------------------------


struct _SplitMix64(Movable):
    """splitmix64: tiny, fast, fully determined by the seed (no global
    state, unlike `std.random`)."""

    var s: UInt64

    def __init__(out self, seed: UInt64):
        self.s = seed

    def next(mut self) -> UInt64:
        self.s += 0x9E3779B97F4A7C15
        var z = self.s
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB
        return z ^ (z >> 31)

    def below(mut self, n: Int) -> Int:
        """Uniform-ish in `[0, n)` for `n >= 1` (modulo bias is irrelevant
        for test chunk sizes)."""
        return Int(self.next() % UInt64(n))


def escape_bytes(data: Span[UInt8, _]) -> String:
    """Printable ASCII as is, `\\n`, `\\r`, `\\\\` and everything else as
    `\\xHH`: an unambiguous rendering of byte events for transcripts."""
    comptime HEX = "0123456789abcdef"
    var hex = HEX.as_bytes()
    var out = String()
    for b in data:
        if b == _LF:
            out += "\\n"
        elif b == _CR:
            out += "\\r"
        elif b == 92:
            out += "\\\\"
        elif b >= 32 and b < 127:
            out += chr(Int(b))
        else:
            out += "\\x"
            out += chr(Int(hex[Int(b >> 4)]))
            out += chr(Int(hex[Int(b & 15)]))
    return out^


def _drain[
    C: Codec, //, render: def(C.Event) thin -> String
](mut codec: C, mut transcript: List[String]) raises IoError:
    while True:
        var ev = codec.next_event()
        if not ev:
            return
        var e = ev.take()
        transcript.append(render(e))


def _run[
    C: Codec & Copyable, //, render: def(C.Event) thin -> String
](proto: C, input: Span[UInt8, _], cuts: List[Int]) raises -> List[String]:
    """Act as a rule-5 driver whose receives are `input` cut at `cuts`
    (non-decreasing, within `[0, len]`): each receive is fed in pieces of
    at most `feed_capacity()` bytes with a drain after each piece (an empty
    receive is one empty feed), then EOF and a final drain. Returns the
    transcript: rendered events, then `"error <kind>"` if a call raised.
    Also enforces rule 5's progress guarantee (room right after a drain)
    and rule 6: after an input-side error, `next_event` must raise the
    same kind."""
    var codec = proto.copy()
    var t = List[String]()
    var failed = ErrorKind.Other
    var has_failed = False
    var stalled = False
    try:
        var prev = 0
        for i in range(len(cuts) + 1):
            var end = cuts[i] if i < len(cuts) else len(input)
            var pos = prev
            while True:
                var k = max(0, min(end - pos, codec.feed_capacity()))
                if k == 0 and pos < end:
                    stalled = True  # no room right after a drain
                    break
                codec.feed(input[pos : pos + k])
                _drain[render](codec, t)
                pos += k
                if pos >= end:
                    break
            if stalled:
                break
            prev = end
        if not stalled:
            codec.feed_eof()
            _drain[render](codec, t)
    except e:
        t.append(String("error ", e.kind))
        failed = e.kind
        has_failed = True
    if stalled:
        raise Error(
            "drive_chunked: feed_capacity() is ",
            codec.feed_capacity(),
            (
                " while the codec is drained and input is left (rule 5: a"
                " drained codec must accept at least one byte)"
            ),
        )
    if has_failed:
        var again = ErrorKind.Other
        var raised = False
        try:
            _ = codec.next_event()
        except e:
            again = e.kind
            raised = True
        if not raised or again != failed:
            raise Error(
                "drive_chunked: codec not poisoned after error ",
                failed,
                " (next_event ",
                String("raised ", again) if raised else "returned",
                ")",
            )
    return t^


def _cuts_repr(cuts: List[Int]) -> String:
    var s = String("[")
    for i in range(len(cuts)):
        if i > 0:
            s += ", "
        s += String(cuts[i])
    s += "]"
    return s^


def _check_same(expected: List[String], got: List[String], what: String) raises:
    var n = min(len(expected), len(got))
    for k in range(n):
        if expected[k] != got[k]:
            raise Error(
                "drive_chunked: ",
                what,
                " diverged at event ",
                k,
                ": whole-input gave '",
                expected[k],
                "', chunked gave '",
                got[k],
                "'",
            )
    if len(expected) != len(got):
        raise Error(
            "drive_chunked: ",
            what,
            " gave ",
            len(got),
            " transcript entries, whole input gave ",
            len(expected),
        )


def drive_chunked[
    C: Codec & Copyable, //, render: def(C.Event) thin -> String
](
    proto: C,
    input: Span[UInt8, _],
    *,
    seed: UInt64 = 0x5EED,
    random_rounds: Int = 200,
    max_pair_len: Int = 256,
) raises -> List[String]:
    """Check rule 4 (chunking invariance) for a codec on one input.

    Runs a fresh copy of `proto` over `input` received whole (the
    reference), then cut at every single split point, at every pair of
    split points (three chunks, empty ones included) when `len(input) <=
    max_pair_len`, one byte at a time, and in `random_rounds` random
    chunkings from a splitmix64 PRNG seeded with `seed` (with empty feeds
    mixed in). Every run is a rule-5 driver: a received chunk larger than
    `feed_capacity()` is fed in pieces that fit, draining after each, so
    inputs longer than the codec's buffer are checked too. Each run ends
    with `feed_eof()`. Every transcript (rendered events, then `"error
    <kind>"` if the codec raised) must equal the reference, a codec that
    raised must stay poisoned (rule 6), and a drained codec must have room
    for input (rule 5); otherwise this raises an `Error` naming the
    chunking. Returns the reference transcript so the caller can also
    assert what the events are.
    """
    var n = len(input)
    var reference = _run[render](proto, input, List[Int]())
    # Every single split point.
    for i in range(n + 1):
        var cuts: List[Int] = [i]
        _check_same(
            reference,
            _run[render](proto, input, cuts),
            String("split ", _cuts_repr(cuts)),
        )
    # Every pair of split points (O(n^3) total work: bounded by max_pair_len).
    if n <= max_pair_len:
        for i in range(n + 1):
            for j in range(i, n + 1):
                var cuts: List[Int] = [i, j]
                var got = _run[render](proto, input, cuts)
                _check_same(reference, got, String("split ", _cuts_repr(cuts)))
    # One byte at a time.
    var bytewise = List[Int](capacity=n)
    for i in range(1, n):
        bytewise.append(i)
    _check_same(
        reference, _run[render](proto, input, bytewise), String("bytewise")
    )
    # Random chunkings; chunk sizes vary per round so both tiny and large
    # chunks show up, and about 1 in 8 feeds is empty.
    var rng = _SplitMix64(seed)
    for round in range(random_rounds):
        var cuts = List[Int]()
        var max_chunk = rng.below(max(n, 1)) + 1
        var pos = 0
        while pos < n:
            if rng.below(8) != 0:
                pos = min(n, pos + 1 + rng.below(max_chunk))
            cuts.append(pos)
        var got = _run[render](proto, input, cuts)
        _check_same(
            reference,
            got,
            String(
                "random round ",
                round,
                " (seed ",
                seed,
                ") cuts ",
                _cuts_repr(cuts),
            ),
        )
    return reference^
