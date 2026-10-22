"""`BufReader`: buffered, bounded, frame-at-a-time reads over a blocking
stream.

Protocols read *frames*: a line ending in `\\r\\n`, an HTTP head ending in
`\\r\\n\\r\\n`, a body of known length. A `BufReader` reads the stream in
large chunks into a `ByteBuffer`, hands out one frame per call, and keeps
whatever came after it (a pipelined request, the start of the next reply)
for the next call:

    var r = BufReader(conn^)        # a TcpStream, UnixStream, any `Read`
    r.stream().set_read_deadline(Deadline.after(Duration.from_secs(5)))
    var head = r.read_until("\\r\\n\\r\\n".as_bytes(), max_bytes=16 * 1024)
    if not head:
        return                      # the peer closed between requests
    var body = List[UInt8](length=content_length, fill=0)
    r.read_exact(Span(body))

Rules:
- **Bounded.** Every delimited read takes a `max_bytes` limit, delimiter
  included. A frame that is longer, or can only become longer, raises
  `InvalidData` as soon as that is certain, so a peer cannot make the reader
  buffer without limit. The buffer itself never grows past `max_size`
  (default 64 MiB, like `ByteBuffer`), and a request that could never fit
  raises `OutOfMemory` before anything is read.
- **All or nothing.** `fill`, `fill_until`, `read_until`, `read_line` and
  `read_exact` either complete or consume nothing. On any error (a deadline,
  `UnexpectedEof`, `InvalidData`, a reset) every byte received so far stays
  buffered. A read deadline can expire in the middle of a frame and the same
  call be retried later, with a new deadline, without losing or splitting
  the frame. Only `read` hands bytes out as they arrive.
- **EOF.** A frame read returns None (or 0) at a clean EOF: the peer closed
  with nothing buffered. EOF inside a frame raises `UnexpectedEof`, with the
  partial frame left in `buffer()`. EOF is not remembered: each call asks
  the stream again.
- **Deadlines** are the stream's, set through `stream()`. They are absolute,
  so a frame that needs several reads waits under one deadline. As in
  `net.tcp`, data that is already available is read even after it expires.
- **Zero copy.** `fill` and `fill_until` leave the frame in the buffer: parse
  it in place from `buffer().readable_span()[:n]`, then `consume(n)`.
  `read_until`, `read_line` and `read_exact` copy it out instead.
- **Spans** taken from `buffer()` follow `ByteBuffer`'s rule: any later call
  on the reader invalidates them. Use them at once, or hold offsets.
- **Writes** go to `stream()` directly; the reader buffers only input.
- **Large reads skip the buffer.** `read` into a buffer at least as large as
  the read size goes straight to the stream when nothing is buffered.

`into_parts` hands back the stream and the bytes still buffered, for a
protocol switch (a WebSocket upgrade) or a handover. Before a TLS upgrade
(STARTTLS), check that nothing is buffered: bytes that arrived before the
handshake must not be treated as protected.

This module does not import `rt` (blocking layer).
"""

from std.memory import unsafe_memcpy

from linux import ErrorKind, IoError

from bytes.buffer import DEFAULT_MAX_SIZE, ByteBuffer

comptime DEFAULT_CAPACITY = 8 * 1024
"""Bytes a `BufReader` asks the stream for per read, by default."""

comptime _LF: UInt8 = 10
comptime _CR: UInt8 = 13


trait Read(Deinitable, Movable):
    """A byte stream that `BufReader` can wrap: `TcpStream`, `UnixStream`,
    `BufReader` itself, or anything with the same `read`."""

    def read(mut self, buf: MutSpan[UInt8, _]) raises IoError -> Int:
        """Read at most `len(buf)` bytes, waiting for at least one: returns
        how many, or 0 at EOF (and for an empty `buf`)."""
        ...


struct BufReaderParts[S: Read](Movable):
    """What `BufReader.into_parts` returns: the stream, and the bytes that
    were buffered (they come before anything the stream returns next). Each
    is an `Optional` so they can move to separate owners:
    `var s = parts.stream.take()`."""

    var stream: Optional[Self.S]
    var buffered: Optional[ByteBuffer]

    @inline(.always)
    def __init__(out self, var stream: Self.S, var buffered: ByteBuffer):
        self.stream = stream^
        self.buffered = buffered^


struct BufReader[S: Read](Read):
    """Buffered, bounded reads over a stream `S` (see the module docs)."""

    var _inner: Self.S
    var _buf: ByteBuffer
    var _chunk: Int
    """How many bytes each read asks for, at least."""

    def __init__(out self, var stream: Self.S):
        """Wrap `stream` with the default read size (`DEFAULT_CAPACITY`) and
        buffer cap (`DEFAULT_MAX_SIZE`). Nothing is allocated until the
        first read."""
        self._inner = stream^
        self._buf = ByteBuffer()
        self._chunk = DEFAULT_CAPACITY

    def __init__(
        out self,
        var stream: Self.S,
        *,
        capacity: Int,
        max_size: Int = DEFAULT_MAX_SIZE,
    ) raises IoError:
        """Wrap `stream`, asking it for at least `capacity` bytes per read
        and never buffering more than `max_size`. `InvalidInput` unless
        `0 < capacity <= max_size` (the stream is closed then)."""
        if capacity <= 0 or capacity > max_size:
            raise IoError.of_kind("BufReader.__init__", ErrorKind.InvalidInput)
        self._inner = stream^
        self._buf = ByteBuffer(max_size=max_size)
        self._chunk = capacity

    # ---- the stream and the buffer -------------------------------------------

    @inline(.always)
    def stream(ref self) -> ref[self._inner] Self.S:
        """The wrapped stream, for deadlines and writes. Reading from it
        directly skips the buffered bytes."""
        return self._inner

    def into_parts(deinit self) -> BufReaderParts[Self.S]:
        """The stream and the bytes still buffered."""
        return BufReaderParts[Self.S](self._inner^, self._buf^)

    @inline(.always)
    def buffer(self) -> ref[self._buf] ByteBuffer:
        """The bytes read from the stream and not consumed yet, oldest first
        (read-only: drop them with `consume`)."""
        return self._buf

    @inline(.always)
    def capacity(self) -> Int:
        """The read size: how many bytes each read asks for, at least."""
        return self._chunk

    @inline(.always)
    def max_size(self) -> Int:
        """The most bytes the reader ever buffers."""
        return self._buf.max_size()

    @inline(.always)
    def consume(mut self, n: Int) raises IoError:
        """Drop the first `n` buffered bytes (after parsing them in place).
        `InvalidInput` unless `0 <= n <= len(buffer())`."""
        self._buf.consume(n)

    # ---- framing: all or nothing ---------------------------------------------

    def fill(mut self, n: Int) raises IoError -> Int:
        """Read until at least `n` bytes are buffered; returns how many are
        (fewer than `n` only at EOF). Consumes nothing: look at them in
        `buffer()`. `n > max_size()` raises `OutOfMemory` and a negative `n`
        `InvalidInput`, both before any read."""
        if n < 0:
            raise IoError.of_kind("BufReader.fill", ErrorKind.InvalidInput)
        if n > self._buf.max_size():
            raise IoError.of_kind("BufReader.fill", ErrorKind.OutOfMemory)
        while len(self._buf) < n:
            if self._read_more(n - len(self._buf), "BufReader.fill") == 0:
                break
        return len(self._buf)

    def fill_until(
        mut self, delimiter: UInt8, max_bytes: Int
    ) raises IoError -> Int:
        """Buffer one whole frame ending with `delimiter` and return its
        length, delimiter included; 0 at a clean EOF. The frame stays
        buffered: parse `buffer().readable_span()[:n]`, then `consume(n)`.

        Raises `InvalidData` for a frame longer than `max_bytes`,
        `UnexpectedEof` at EOF inside a frame, `OutOfMemory` if the frame
        outgrows `max_size()`, and `InvalidInput` for `max_bytes < 1`."""
        if max_bytes < 1:
            raise IoError.of_kind(
                "BufReader.fill_until", ErrorKind.InvalidInput
            )
        return self._frame(delimiter, max_bytes, "BufReader.fill_until")

    def fill_until(
        mut self, delimiter: Span[UInt8, _], max_bytes: Int
    ) raises IoError -> Int:
        """`fill_until` with a multi-byte delimiter (`\\r\\n\\r\\n`). An
        empty delimiter or `max_bytes < len(delimiter)` is `InvalidInput`."""
        if len(delimiter) == 0 or max_bytes < len(delimiter):
            raise IoError.of_kind(
                "BufReader.fill_until", ErrorKind.InvalidInput
            )
        return self._frame(delimiter, max_bytes, "BufReader.fill_until")

    def read_until(
        mut self, delimiter: UInt8, max_bytes: Int
    ) raises IoError -> Optional[List[UInt8]]:
        """The next frame ending with `delimiter` (included), or None at a
        clean EOF. Errors as for `fill_until`; nothing is consumed then."""
        if max_bytes < 1:
            raise IoError.of_kind(
                "BufReader.read_until", ErrorKind.InvalidInput
            )
        var n = self._frame(delimiter, max_bytes, "BufReader.read_until")
        if n == 0:
            return None
        return self._buf.read_bytes(n)

    def read_until(
        mut self, delimiter: Span[UInt8, _], max_bytes: Int
    ) raises IoError -> Optional[List[UInt8]]:
        """`read_until` with a multi-byte delimiter."""
        if len(delimiter) == 0 or max_bytes < len(delimiter):
            raise IoError.of_kind(
                "BufReader.read_until", ErrorKind.InvalidInput
            )
        var n = self._frame(delimiter, max_bytes, "BufReader.read_until")
        if n == 0:
            return None
        return self._buf.read_bytes(n)

    def read_line(
        mut self, max_bytes: Int
    ) raises IoError -> Optional[List[UInt8]]:
        """The next line without its ending (`\\n` or `\\r\\n`), or None at a
        clean EOF. `max_bytes` counts the ending. A last line without `\\n`
        is `UnexpectedEof` (protocols end every line); it stays buffered.
        Strict framing (CRLF only) is `read_until("\\r\\n".as_bytes(), ...)`."""
        if max_bytes < 1:
            raise IoError.of_kind("BufReader.read_line", ErrorKind.InvalidInput)
        var n = self._frame(_LF, max_bytes, "BufReader.read_line")
        if n == 0:
            return None
        var keep = n - 1
        if keep > 0 and self._buf.byte_at(keep - 1) == _CR:
            keep -= 1
        var line = self._buf.read_bytes(keep)
        self._buf.consume(n - keep)
        return line^

    def read_exact(mut self, buf: MutSpan[UInt8, _]) raises IoError:
        """Fill `buf` completely. All or nothing: EOF first raises
        `UnexpectedEof` with every byte still buffered. `buf` larger than
        `max_size()` raises `OutOfMemory` before any read (stream it with
        `read` instead)."""
        var n = len(buf)
        if n == 0:
            return
        if n > self._buf.max_size():
            raise IoError.of_kind("BufReader.read_exact", ErrorKind.OutOfMemory)
        while len(self._buf) < n:
            if self._read_more(n - len(self._buf), "BufReader.read_exact") == 0:
                raise IoError.of_kind(
                    "BufReader.read_exact", ErrorKind.UnexpectedEof
                )
        self._take(buf, n)

    # ---- plain reads ---------------------------------------------------------

    def read(mut self, buf: MutSpan[UInt8, _]) raises IoError -> Int:
        """Up to `len(buf)` bytes: buffered ones first, without a read; else
        one read from the stream. Returns 0 at EOF (and for an empty `buf`).
        With nothing buffered, a `buf` of at least `capacity()` bytes is
        read into directly, skipping the copy."""
        var n = len(buf)
        if n == 0:
            return 0
        if len(self._buf) == 0:
            if n >= self._chunk:
                return self._inner.read(buf)
            if self._read_more(n, "BufReader.read") == 0:
                return 0
        var k = min(n, len(self._buf))
        self._take(buf, k)
        return k

    # ---- internals -----------------------------------------------------------

    def _frame(
        mut self, delimiter: UInt8, max_bytes: Int, op: StaticString
    ) raises IoError -> Int:
        """Read until the first frame ending with `delimiter` is buffered and
        return its length; 0 at a clean EOF. Scans each byte once."""
        var start = 0
        while True:
            var at = self._buf.find(delimiter, start)
            if at:
                return _within(at.value() + 1, max_bytes, op)
            start = len(self._buf)
            if start >= max_bytes:
                raise IoError.of_kind(op, ErrorKind.InvalidData)
            if self._read_more(1, op) == 0:
                return _at_eof(start, op)

    def _frame(
        mut self, delimiter: Span[UInt8, _], max_bytes: Int, op: StaticString
    ) raises IoError -> Int:
        """`_frame` for a multi-byte delimiter; each search resumes where a
        delimiter could straddle the previous end of the buffer."""
        var m = len(delimiter)
        var start = 0
        while True:
            var at = self._buf.find(delimiter, start)
            if at:
                return _within(at.value() + m, max_bytes, op)
            var have = len(self._buf)
            if have >= max_bytes:
                # The frame ends after `have` bytes at the earliest.
                raise IoError.of_kind(op, ErrorKind.InvalidData)
            start = max(0, have - m + 1)
            if self._read_more(1, op) == 0:
                return _at_eof(have, op)

    def _read_more(mut self, want: Int, op: StaticString) raises IoError -> Int:
        """One read from the stream into the buffer's free tail, asking for
        at least `max(want, capacity())` bytes where `max_size()` leaves
        room. Returns the bytes read, 0 at EOF. A full buffer raises
        `OutOfMemory` (`op`) without reading."""
        var room = self._buf.max_writable()
        if room <= 0:
            raise IoError.of_kind(op, ErrorKind.OutOfMemory)
        self._buf.ensure_writable(min(max(want, self._chunk), room))
        var got = self._inner.read(self._buf.writable_span())
        self._buf.commit(got)
        return got

    def _take(mut self, buf: MutSpan[UInt8, _], n: Int) raises IoError:
        """Copy the first `n` buffered bytes into `buf` and consume them
        (`n <= len(buf)`, `n <= len(buffer())`)."""
        unsafe_memcpy(
            dest=buf.unsafe_ptr(),
            src=self._buf.readable_span().unsafe_ptr(),
            count=n,
        )
        self._buf.consume(n)


@inline(.always)
def _within(n: Int, max_bytes: Int, op: StaticString) raises IoError -> Int:
    """A complete frame of `n` bytes, or `InvalidData` if over the limit."""
    if n > max_bytes:
        raise IoError.of_kind(op, ErrorKind.InvalidData)
    return n


@inline(.always)
def _at_eof(buffered: Int, op: StaticString) raises IoError -> Int:
    """EOF while looking for a frame: clean (0) only with nothing buffered."""
    if buffered > 0:
        raise IoError.of_kind(op, ErrorKind.UnexpectedEof)
    return 0
