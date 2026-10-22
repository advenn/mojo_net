"""Shared by the BufReader tests (not a test file itself).

- `Script`: a fake stream that serves its data in reads of scripted sizes
  and lets scripted read calls expire like a read deadline.
- A fixed protocol-like transcript (`INPUT`, `run_transcript`,
  `expected_transcript`) that mixes every framing call. It must come out
  the same however the input is cut into reads and wherever a deadline
  expires, since a timed-out call is simply retried."""

from linux import ErrorKind, IoError
from bytes.codec import escape_bytes
from net.reader import BufReader, Read

comptime INPUT = (
    "GET /a HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
    + "PING\r\n"
    + "a;b;"
    + "line one\n"
    + "line\rtwo\r\n"
    + "\r\n"
    + "tail-bytes!"
)
comptime HEAD_END = "\r\n\r\n"
comptime STEPS = 13


struct Script(Read):
    """Serves `data` in reads of `sizes[i]` bytes (the last size repeats),
    then EOF. Read calls whose 1-based number is in `timeouts` raise a
    deadline expiry (`TimedOut`, errno 0) and move nothing. Records every
    call and the size it asked for."""

    var data: List[UInt8]
    var pos: Int
    var sizes: List[Int]
    var served: Int
    var timeouts: List[Int]
    var calls: Int
    var asked: List[Int]

    def __init__(
        out self,
        var data: List[UInt8],
        var sizes: List[Int],
        var timeouts: List[Int],
    ):
        self.data = data^
        self.pos = 0
        self.sizes = sizes^
        self.served = 0
        self.timeouts = timeouts^
        self.calls = 0
        self.asked = List[Int]()

    def __init__(
        out self,
        text: StringSlice,
        var sizes: List[Int],
        var timeouts: List[Int],
    ):
        self = Script(bytes_of(text), sizes^, timeouts^)

    def __init__(out self, text: StringSlice):
        """Everything in the first read."""
        var sizes = List[Int]()
        sizes.append(Int.MAX)
        self = Script(bytes_of(text), sizes^, List[Int]())

    def read(mut self, buf: MutSpan[UInt8, _]) raises IoError -> Int:
        self.calls += 1
        self.asked.append(len(buf))
        for t in self.timeouts:
            if t == self.calls:
                raise IoError.of_kind("read", ErrorKind.TimedOut)
        if len(buf) == 0 or self.pos >= len(self.data):
            return 0
        var size = self.sizes[min(self.served, len(self.sizes) - 1)]
        self.served += 1
        var k = min(len(buf), min(size, len(self.data) - self.pos))
        for j in range(k):
            buf[j] = self.data[self.pos + j]
        self.pos += k
        return k


struct Rng(Movable):
    """splitmix64: deterministic cuts and expiries for the property runs."""

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
        return Int(self.next() % UInt64(n))


def bytes_of(text: StringSlice) -> List[UInt8]:
    var out = List[UInt8](capacity=text.byte_length())
    for b in text.as_bytes():
        out.append(b)
    return out^


def show(tag: StaticString, frame: Optional[List[UInt8]]) -> String:
    if not frame:
        return String(tag, ":None")
    return String(tag, ":", escape_bytes(Span(frame.value())))


def step[S: Read](mut r: BufReader[S], i: Int) raises IoError -> String:
    """Transcript step `i`: one framing call and what it returned."""
    if i == 0:
        return show("until", r.read_until(HEAD_END.as_bytes(), 64))
    if i == 1:
        var body = List[UInt8](length=5, fill=0)
        r.read_exact(Span(body))
        return String("exact:", escape_bytes(Span(body)))
    if i == 2:
        return show("line", r.read_line(16))
    if i == 3:
        return show("until", r.read_until(UInt8(ord(";")), 8))
    if i == 4:
        # Zero copy: the frame stays buffered until consumed.
        var n = r.fill_until(UInt8(ord(";")), 8)
        var seen = escape_bytes(r.buffer().readable_span()[:n])
        r.consume(n)
        return String("fill_until:", n, ":", seen)
    if i == 5 or i == 6 or i == 7:
        return show("line", r.read_line(32))
    if i == 8:
        return String("fill:", r.fill(11))
    if i == 9:
        var rest = List[UInt8](length=11, fill=0)
        r.read_exact(Span(rest))
        return String("exact:", escape_bytes(Span(rest)))
    if i == 10:
        return show("line", r.read_line(8))
    if i == 11:
        return show("until", r.read_until(HEAD_END.as_bytes(), 64))
    return String("fill:", r.fill(1))


def run_transcript[S: Read](mut r: BufReader[S]) raises IoError -> List[String]:
    """Every step in order; a step that times out is retried until it
    completes (the all-or-nothing rule makes that safe)."""
    var out = List[String]()
    for i in range(STEPS):
        var tries = 0
        while True:
            try:
                out.append(step(r, i))
                break
            except e:
                if e.kind != ErrorKind.TimedOut or tries >= 100_000:
                    raise e
                tries += 1
    return out^


def expected_transcript() -> List[String]:
    var want = List[String]()
    want.append(
        "until:GET /a HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 5\\r\\n\\r\\n"
    )
    want.append("exact:hello")
    want.append("line:PING")
    want.append("until:a;")
    want.append("fill_until:2:b;")
    want.append("line:line one")
    want.append("line:line\\rtwo")
    want.append("line:")
    want.append("fill:11")
    want.append("exact:tail-bytes!")
    want.append("line:None")
    want.append("until:None")
    want.append("fill:0")
    return want^


def first_difference(got: List[String], want: List[String]) -> String:
    """ "" if equal, else a description of the first difference."""
    for i in range(min(len(got), len(want))):
        if got[i] != want[i]:
            return String(
                "step ", i, ": got '", got[i], "', want '", want[i], "'"
            )
    if len(got) != len(want):
        return String("got ", len(got), " steps, want ", len(want))
    return String()
