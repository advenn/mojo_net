"""`RespConnection`: the sans-I/O codec for one connection to a Redis
server (design contract 1).

Commands are queued with `command(args)`, or several at once with
`commands(batch)` (whole or not at all), and pipeline: each reply pairs
with the oldest command still waiting for one. Events:
- **REPLY:** a command's reply (`ev.value`), errors included: an error
  reply is a value like any other, and the connection goes on.
- **PUSH:** RESP3 out-of-band data, which can arrive between any two
  replies and pairs with no command.

Refused (`InvalidInput`), since their replies would not pair with commands
one for one: SUBSCRIBE, PSUBSCRIBE, SSUBSCRIBE and their opposites (a
subscriber runs on a connection of its own), MONITOR, and CLIENT REPLY OFF
or SKIP. After QUIT, nothing more is queued, and EOF after its reply is the
end.

What ends the connection with an error (rule 6):
- **The server broke the protocol** (`InvalidData`): a malformed value, one
  over the `Limits`, or a reply that no command was waiting for.
- **A streamed RESP3 value** (`Unsupported`).
- **EOF with a reply still due,** or inside a value (`UnexpectedEof`).
  EOF with nothing due is the server closing an idle connection: no error.

Time: the codec has no timers (`next_deadline` is None). Deadlines belong to
the driver: a reply that is late cannot be cancelled, so the driver closes
the connection.
"""

from bytes.buffer import ByteBuffer
from bytes.codec import Codec
from linux import ErrorKind, IoError
from linux.time import Instant

from .resp import Args, Kind, Limits, RespParser, Value, write_command

comptime E_EOF = "redis: the server closed the connection"
comptime E_UNPAIRED = "redis: a reply no command was waiting for"
comptime E_FEED = "redis: fed past feed_capacity()"
comptime E_CLOSED = "redis: the connection is closed"
comptime E_SUBSCRIBE = "redis: subscribing needs a connection of its own (a Subscriber)"
comptime E_REPLIES = "redis: commands that stop replies pairing with commands are refused"

def _check_pairs(args: Args) raises IoError:
    """Refuse the commands whose replies would not pair with them one for
    one (see the module docs)."""
    if (
        args.is_named(0, "SUBSCRIBE")
        or args.is_named(0, "PSUBSCRIBE")
        or args.is_named(0, "SSUBSCRIBE")
        or args.is_named(0, "UNSUBSCRIBE")
        or args.is_named(0, "PUNSUBSCRIBE")
        or args.is_named(0, "SUNSUBSCRIBE")
    ):
        raise IoError.of_kind(E_SUBSCRIBE, ErrorKind.InvalidInput)
    if args.is_named(0, "MONITOR") or (
        args.is_named(0, "CLIENT") and args.is_named(1, "REPLY") and (args.is_named(2, "OFF") or args.is_named(2, "SKIP"))
    ):
        raise IoError.of_kind(E_REPLIES, ErrorKind.InvalidInput)


comptime _MAX_QUEUED = 4 << 30
"""The commands queued and not yet sent, at most (`OutOfMemory` past it)."""


@fieldwise_init
struct EventKind(Equatable, TrivialRegisterPassable, Writable):
    var _v: UInt8

    comptime REPLY = EventKind(0)
    """The reply to the oldest command waiting for one."""
    comptime PUSH = EventKind(1)
    """RESP3 out-of-band data, the reply to no command."""

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self._v == other._v

    def write_to(self, mut writer: Some[Writer]):
        writer.write("REPLY" if self._v == 0 else "PUSH")


struct RespEvent(Movable, Writable):
    """One event (see the module docs). Meant to be reused (`poll`): its
    value keeps its buffers' capacity."""

    var kind: EventKind
    var value: Value

    def __init__(out self):
        self.kind = EventKind.REPLY
        self.value = Value()

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.kind, " ", self.value)


struct RespConnection(Codec, Copyable):
    """The codec for one connection (see the module docs)."""

    comptime Event = RespEvent

    var _rx: ByteBuffer
    var _tx: ByteBuffer
    var _request: ByteBuffer
    """Where a batch of commands is built before it joins `_tx`."""
    var _parser: RespParser
    var _pending: Int
    """Commands sent whose reply has not come."""
    var _quit: Bool
    var _eof: Bool
    var _failed: Optional[IoError]

    def __init__(out self, limits: Limits = Limits()) raises IoError:
        """`InvalidInput` for limits below their minimum: a line of 64
        bytes, depth 1, and no negative size."""
        if limits.max_line < 64 or limits.max_depth < 1 or limits.max_bulk < 0 or limits.max_elements < 0:
            raise IoError.of_kind("redis: invalid limits", ErrorKind.InvalidInput)
        # (a bulk value's bytes leave `_rx` as they come: it holds one
        # unfinished line at most, so this much room always takes more)
        self._rx = ByteBuffer(max_size=limits.max_line + 64 * 1024)
        self._tx = ByteBuffer(max_size=_MAX_QUEUED)
        self._request = ByteBuffer(max_size=_MAX_QUEUED)
        self._parser = RespParser(limits)
        self._pending = 0
        self._quit = False
        self._eof = False
        self._failed = None

    # ---- the connection ------------------------------------------------------

    def is_open(self) -> Bool:
        """Whether commands may be queued: no QUIT queued, no EOF, no
        failure."""
        return not self._quit and not self._eof and not self._failed

    def is_idle(self) -> Bool:
        """Open, with no reply due."""
        return self.is_open() and self._pending == 0 and not self._parser.in_value()

    def pending(self) -> Int:
        """Commands sent whose reply has not come yet."""
        return self._pending

    def command(mut self, args: Args) raises IoError:
        """Queue a command, whole or not at all (see `write_command`). Its
        reply comes as a REPLY event, after those of the commands queued
        before it. `InvalidInput`, with nothing queued, for a command
        refused here (see the module docs) or when the connection is not
        open; the error that ended it, once it has failed."""
        self._check_open()
        _check_pairs(args)
        write_command(self._tx, args)
        self._pending += 1
        if args.is_named(0, "QUIT"):
            self._quit = True

    def commands(mut self, batch: List[Args]) raises IoError:
        """Queue several commands as one, whole or not at all: refused, as
        `command` refuses one, if any of them is, with nothing queued.
        Their replies come in their order."""
        self._check_open()
        for i in range(len(batch)):
            _check_pairs(batch[i])
        self._request.clear()
        for i in range(len(batch)):
            write_command(self._request, batch[i])
        self._tx.write_bytes(self._request.readable_span())
        self._pending += len(batch)
        for i in range(len(batch)):
            if batch[i].is_named(0, "QUIT"):
                self._quit = True

    def _check_open(self) raises IoError:
        if self._failed:
            raise self._failed.value()
        if not self.is_open():
            raise IoError.of_kind(E_CLOSED, ErrorKind.InvalidInput)

    # ---- the Codec interface ---------------------------------------------------

    def _poison(mut self, e: IoError) -> IoError:
        self._failed = e
        return e

    def feed(mut self, data: Span[UInt8, _]) raises IoError:
        if self._failed:
            raise self._failed.value()
        if self._eof:
            raise IoError.of_kind("redis: feed after EOF", ErrorKind.InvalidInput)
        if len(data) > self._rx.max_writable():
            raise self._poison(IoError.of_kind(E_FEED, ErrorKind.OutOfMemory))
        self._rx.write_bytes(data)

    def feed_capacity(self) -> Int:
        return self._rx.max_writable()

    def feed_eof(mut self) raises IoError:
        if self._failed:
            raise self._failed.value()
        self._eof = True

    def next_event(mut self) raises IoError -> Optional[RespEvent]:
        """The next event, if one is ready (the `Codec` interface). `poll`
        does the same into an event the caller reuses."""
        var ev = RespEvent()
        if self.poll(ev):
            return ev^
        return None

    def poll(mut self, mut ev: RespEvent) raises IoError -> Bool:
        """Fill `ev` with the next event and return True, or return False
        when none is ready. The value moves into `ev` without a copy, and
        `ev`'s old buffers go back to the parser."""
        if self._failed:
            raise self._failed.value()
        var whole: Bool
        try:
            whole = self._parser.parse(self._rx)
        except e:
            ev.value.clear()
            raise self._poison(e)
        if not whole:
            if self._eof and (self._pending > 0 or self._parser.in_value() or self._rx.readable() > 0):
                ev.value.clear()
                raise self._poison(IoError.of_kind(E_EOF, ErrorKind.UnexpectedEof))
            return False
        self._parser.take(ev.value)
        if ev.value.kind() == Kind.PUSH:
            ev.kind = EventKind.PUSH
            return True
        if self._pending == 0:
            ev.value.clear()
            raise self._poison(IoError.of_kind(E_UNPAIRED, ErrorKind.InvalidData))
        self._pending -= 1
        ev.kind = EventKind.REPLY
        return True

    def poll_transmit(mut self, mut out: ByteBuffer) raises IoError -> Int:
        var n = min(self._tx.readable(), out.max_writable())
        if n == 0:
            return 0
        out.write_bytes(self._tx.readable_span()[:n])
        self._tx.consume(n)
        return n

    def next_deadline(self) -> Optional[Instant]:
        return None

    def handle_timeout(mut self, now: Instant) raises IoError:
        pass
