"""Server-sent events (the WHATWG HTML standard, "Server-sent events",
section 9.2): `SseParser`, a sans-I/O parser for a `text/event-stream`
body, and `write_event` / `write_comment`, its encoder.

The parser follows the standard's algorithm exactly, which is what every
browser and SDK does:
- lines end with CRLF, LF or CR, and may be split anywhere across reads (a
  CR at the end of one read and an LF at the start of the next are one line
  end); a UTF-8 BOM at the very start is skipped;
- `field: value` lines (one space after the colon dropped), `field` lines
  (an empty value), and `:` comments, which are ignored;
- `data` appends a line, `event` sets the type (default "message"), `id`
  sets the ID buffer (ignored when it holds a NUL), `retry` sets the
  reconnection time when it is all ASCII digits; other fields are ignored;
- an empty line makes the ID buffer the last event ID, then dispatches the
  event unless no `data` came; the ID carries over to later events;
- the end of the stream discards an event that was not finished by an
  empty line, as the standard says (`discarded()` tells).

It is a `Codec` (contract 1) without output: `feed` what arrives, then
`next_event` (or `poll(ev)`, which refills a reused event). Bounds: a line
longer than `max_line` or an event with more than `max_data` bytes of data
raises `InvalidData` (the server broke the bounds the client set), and
stays raised.
"""

from bytes.buffer import ByteBuffer
from bytes.codec import Codec
from linux import ErrorKind, IoError
from linux.time import Instant

comptime _LF: UInt8 = 10
comptime _CR: UInt8 = 13
comptime _COLON: UInt8 = 58
comptime _SPACE: UInt8 = 32
comptime DEFAULT_MAX_LINE = 1024 * 1024
comptime DEFAULT_MAX_DATA = 16 * 1024 * 1024


struct SseEvent(Copyable, Movable, Writable):
    """One dispatched event."""

    var event: String
    """Its type: the `event` field, or "message"."""
    var data: String
    """The `data` lines joined with LF (no final LF)."""
    var id: String
    """The last event ID as of this event (it carries over from earlier
    events, as the standard's lastEventId does)."""

    def __init__(out self):
        self.event = String()
        self.data = String()
        self.id = String()

    def write_to(self, mut writer: Some[Writer]):
        writer.write("event=", repr(self.event), " id=", repr(self.id), " data=", repr(self.data))


struct SseParser(Codec, Copyable):
    """Parses one event stream (see the module docs)."""

    comptime Event = SseEvent

    var max_line: Int
    var max_data: Int
    var _buf: ByteBuffer
    """Input not yet split into lines (a line still arriving)."""
    var _skip_lf: Bool
    """The last line ended with a CR: an LF right after belongs to it."""
    var _started: Bool
    """Past the possible BOM."""
    var _data: List[UInt8]
    var _has_data: Bool
    var _type: List[UInt8]
    var _id_buffer: String
    """The last `id` field seen; it becomes `_id` at the next empty line."""
    var _id: String
    var _retry: Int
    var _events: List[SseEvent]
    var _next: Int
    var _failed: Optional[IoError]
    var _eof: Bool
    var _discarded: Bool

    def __init__(out self, *, max_line: Int = DEFAULT_MAX_LINE, max_data: Int = DEFAULT_MAX_DATA) raises IoError:
        """`InvalidInput` unless both bounds are positive."""
        if max_line < 1 or max_data < 1:
            raise IoError.of_kind("SseParser", ErrorKind.InvalidInput)
        self.max_line = max_line
        self.max_data = max_data
        self._buf = ByteBuffer()
        self._skip_lf = False
        self._started = False
        self._data = List[UInt8]()
        self._has_data = False
        self._type = List[UInt8]()
        self._id_buffer = String()
        self._id = String()
        self._retry = -1
        self._events = List[SseEvent]()
        self._next = 0
        self._failed = None
        self._eof = False
        self._discarded = False

    # ---- the codec ---------------------------------------------------------

    def feed(mut self, data: Span[UInt8, _]) raises IoError:
        if self._failed:
            raise self._failed.value()
        if self._eof:
            raise IoError.of_kind("SseParser.feed", ErrorKind.InvalidInput)
        if len(data) == 0:
            return
        if len(data) > self.feed_capacity():
            raise self._fail(ErrorKind.OutOfMemory)
        self._buf.write_bytes(data)
        self._lines()

    def feed_capacity(self) -> Int:
        """Room for the line being received: `max_line` (plus its line end)
        less what of it has arrived."""
        if self._failed or self._eof:
            return 0
        return max(0, self.max_line + 2 - len(self._buf))

    def feed_eof(mut self) raises IoError:
        """The stream ended: an event not finished by an empty line, and a
        line not finished by a line end, are discarded (`discarded()`)."""
        if self._eof:
            return
        self._eof = True
        if self._failed:
            return
        if len(self._buf) > 0 or self._has_data or len(self._type) > 0:
            self._discarded = True
        self._buf.clear()

    def next_event(mut self) raises IoError -> Optional[SseEvent]:
        if self._next < len(self._events):
            var ev = SseEvent()
            swap(ev, self._events[self._next])
            self._advance()
            return ev^
        if self._failed:
            raise self._failed.value()
        return None

    def poll(mut self, mut ev: SseEvent) raises IoError -> Bool:
        """The next event into `ev` (its strings reused): False if none."""
        if self._next < len(self._events):
            swap(ev, self._events[self._next])
            self._advance()
            return True
        if self._failed:
            raise self._failed.value()
        return False

    def poll_transmit(mut self, mut out: ByteBuffer) raises IoError -> Int:
        return 0

    def next_deadline(self) -> Optional[Instant]:
        return None

    def handle_timeout(mut self, now: Instant) raises IoError:
        pass

    # ---- state -------------------------------------------------------------

    def last_event_id(self) -> String:
        """The last event ID so far (sent as Last-Event-ID to resume)."""
        return self._id

    def retry_ms(self) -> Optional[Int]:
        """The reconnection time the server set, in milliseconds."""
        if self._retry < 0:
            return None
        return self._retry

    def discarded(self) -> Bool:
        """Whether the end of the stream cut an event short."""
        return self._discarded

    # ---- inside ------------------------------------------------------------

    def _advance(mut self):
        self._next += 1
        if self._next == len(self._events):
            self._events.clear()
            self._next = 0

    def _fail(mut self, kind: ErrorKind) -> IoError:
        var e = IoError.of_kind("SseParser", kind)
        if not self._failed:
            self._failed = e
        self._buf.clear()
        return e

    def _lines(mut self) raises IoError:
        """Split the buffered input into lines and process each. The buffer
        is moved out meanwhile, so lines are read where they lie while
        `self` changes."""
        var buf = ByteBuffer()
        swap(buf, self._buf)
        self._split(buf)
        swap(buf, self._buf)

    def _split(mut self, mut buf: ByteBuffer) raises IoError:
        var b = buf.readable_span()
        var n = len(b)
        var i = 0
        if not self._started:
            # A BOM (EF BB BF) at the very start is skipped; wait for three
            # bytes before deciding when they could be one.
            var bom: List[UInt8] = [0xEF, 0xBB, 0xBF]
            var k = 0
            while k < min(n, 3) and b[k] == bom[k]:
                k += 1
            if k == min(n, 3) and n < 3:
                return
            self._started = True
            if k == 3:
                i = 3
        if self._skip_lf and i < n:
            if b[i] == _LF:
                i += 1
            self._skip_lf = False
        var start = i
        while i < n:
            var c = b[i]
            if c == _LF or c == _CR:
                if i - start > self.max_line:
                    raise self._fail(ErrorKind.InvalidData)
                self._line(b[start:i])
                if self._failed:
                    raise self._failed.value()
                if c == _CR:
                    if i + 1 < n:
                        if b[i + 1] == _LF:
                            i += 1
                    else:
                        self._skip_lf = True
                i += 1
                start = i
                continue
            i += 1
        if n - start > self.max_line:
            raise self._fail(ErrorKind.InvalidData)
        buf.consume(start)

    def _line(mut self, line: Span[UInt8, _]):
        """One line, by the standard's rules."""
        if len(line) == 0:
            self._dispatch()
            return
        if line[0] == _COLON:
            return  # a comment
        var colon = -1
        for k in range(len(line)):
            if line[k] == _COLON:
                colon = k
                break
        var field = line if colon < 0 else line[0:colon]
        var value = line[0:0]
        if colon >= 0:
            var v = colon + 1
            if v < len(line) and line[v] == _SPACE:
                v += 1
            value = line[v:]
        if _is(field, "data"):
            if len(self._data) + len(value) + 1 > self.max_data:
                _ = self._fail(ErrorKind.InvalidData)
                return
            self._data.extend(value)
            self._data.append(_LF)
            self._has_data = True
        elif _is(field, "event"):
            self._type = List[UInt8](value)
        elif _is(field, "id"):
            for k in range(len(value)):
                if value[k] == 0:
                    return  # (an id with a NUL is ignored)
            self._id_buffer = String(from_utf8_lossy=value)
        elif _is(field, "retry"):
            if len(value) == 0 or len(value) > 15:
                return
            var ms = 0
            for k in range(len(value)):
                var d = value[k]
                if d < 48 or d > 57:
                    return
                ms = ms * 10 + Int(d) - 48
            self._retry = ms

    def _dispatch(mut self):
        self._id = self._id_buffer
        if not self._has_data:
            self._type.clear()
            return
        var ev = SseEvent()
        _ = self._data.pop()  # (the final LF)
        ev.data = String(from_utf8_lossy=Span(self._data))
        ev.event = String(from_utf8_lossy=Span(self._type)) if len(self._type) > 0 else String("message")
        ev.id = self._id
        self._events.append(ev^)
        self._data.clear()
        self._has_data = False
        self._type.clear()


def _is(field: Span[UInt8, _], name: StaticString) -> Bool:
    var n = name.as_bytes()
    if len(field) != len(n):
        return False
    for i in range(len(n)):
        if field[i] != n[i]:
            return False
    return True


# ---- the encoder --------------------------------------------------------------


def write_event(
    mut out: ByteBuffer,
    data: StringSlice,
    *,
    event: StringSlice = "",
    id: StringSlice = "",
    retry_ms: Int = -1,
) raises IoError:
    """Append one event: `retry`, `event` and `id` lines when given, then a
    `data` line per line of `data` (split at CRLF, LF or CR), then the empty
    line that dispatches it. `InvalidInput` (nothing appended) for an
    `event` or `id` with a line end, an `id` with a NUL, or a negative
    `retry_ms` other than -1 (none)."""
    comptime op = "write_event"
    if _has_line_end(event.as_bytes()) or _has_line_end(id.as_bytes()) or retry_ms < -1:
        raise IoError.of_kind(op, ErrorKind.InvalidInput)
    for c in id.as_bytes():
        if c == 0:
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
    var s = String()
    if retry_ms >= 0:
        s += String("retry: ", retry_ms, "\n")
    if event.byte_length() > 0:
        s += "event: " + String(event) + "\n"
    if id.byte_length() > 0:
        s += "id: " + String(id) + "\n"
    var b = data.as_bytes()
    var start = 0
    var i = 0
    while i <= len(b):
        if i == len(b) or b[i] == _LF or b[i] == _CR:
            s += "data: " + String(StringSlice(unsafe_from_utf8=b[start:i])) + "\n"
            if i < len(b) and b[i] == _CR and i + 1 < len(b) and b[i + 1] == _LF:
                i += 1
            start = i + 1
        i += 1
    s += "\n"
    out.write_bytes(s.as_bytes())


def write_comment(mut out: ByteBuffer, text: StringSlice = "") raises IoError:
    """Append a comment line (`:` and the text): ignored by clients, it keeps
    an idle stream alive through proxies (a heartbeat). `InvalidInput` for
    a text with a line end."""
    if _has_line_end(text.as_bytes()):
        raise IoError.of_kind("write_comment", ErrorKind.InvalidInput)
    var s = String(":")
    if text.byte_length() > 0:
        s += " " + String(text)
    s += "\n"
    out.write_bytes(s.as_bytes())


def _has_line_end(b: Span[UInt8, _]) -> Bool:
    for c in b:
        if c == _LF or c == _CR:
            return True
    return False
