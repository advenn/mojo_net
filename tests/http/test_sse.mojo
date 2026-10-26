"""`http.sse`: the event-stream parser against tests/http/sse_oracle.py, a
reference written from the WHATWG standard's text, on hand-written cases
and on random streams fed in random pieces; chunking invariance
(`drive_chunked`); bounds; and the encoder, whose output must parse back
to what was written."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from bytes.codec import drive_chunked
from http.sse import SseEvent, SseParser, write_comment, write_event
from linux import ErrorKind, IoError


def _oracle() raises -> PythonObject:
    var sys = Python.import_module("sys")
    _ = sys.path.insert(0, "tests/http")
    return Python.import_module("sse_oracle")


def _render(ev: SseEvent) -> String:
    return String(ev)


struct _Run(Movable):
    var events: List[String]
    var last_id: String
    var retry: Int
    var discarded: Bool
    var error: String

    def __init__(out self):
        self.events = List[String]()
        self.last_id = String()
        self.retry = -1
        self.discarded = False
        self.error = String()


def _parse(data: Span[UInt8, _], cuts: List[Int]) raises -> _Run:
    """Feed `data` cut at `cuts` (rule 5: at most feed_capacity at a time,
    draining after each), then the end."""
    var p = SseParser()
    var run = _Run()
    var ev = SseEvent()
    var start = 0
    try:
        for k in range(len(cuts) + 1):
            var stop = cuts[k] if k < len(cuts) else len(data)
            var at = start
            while at < stop:
                var n = min(stop - at, p.feed_capacity())
                p.feed(data[at : at + n])
                at += n
                while p.poll(ev):
                    run.events.append(String(ev))
            start = stop
        p.feed_eof()
        while p.poll(ev):
            run.events.append(String(ev))
    except e:
        run.error = String(e.kind)
    run.last_id = p.last_event_id()
    run.retry = p.retry_ms().value() if p.retry_ms() else -1
    run.discarded = p.discarded()
    return run^


def _expect(o: PythonObject, data: List[UInt8], cuts: List[Int]) raises:
    var py = Python.import_module("builtins")
    var raw = py.bytes(Python.list())
    var ba = py.bytearray()
    for b in data:
        _ = ba.append(Int(b))
    raw = py.bytes(ba)
    var want = o.parse(raw)
    var got = _parse(Span(data), cuts)
    assert_equal(got.error, "", String("parser raised for ", repr(String(from_utf8_lossy=Span(data)))))
    var wanted = want[0]
    var n = Int(py=py.len(wanted))
    assert_equal(len(got.events), n, repr(String(from_utf8_lossy=Span(data))))
    for i in range(n):
        var t = wanted[i]
        var ev = SseEvent()
        ev.event = String(py=t[0])
        ev.data = String(py=t[1])
        ev.id = String(py=t[2])
        assert_equal(got.events[i], String(ev))
    assert_equal(got.last_id, String(py=want[1]))
    assert_equal(got.retry, -1 if want[2] is None else Int(py=want[2]))
    assert_equal(got.discarded, Bool(py=want[3]))


def _bytes(s: StringSlice) -> List[UInt8]:
    return List[UInt8](s.as_bytes())


def test_the_standards_examples() raises:
    var o = _oracle()
    var cases: List[String] = [
        "data: YHOO\ndata: +2\ndata: 10\n\n",
        ": test stream\n\ndata: first event\nid: 1\n\ndata:second event\nid\n\ndata:  third event\n",
        "data\n\ndata\ndata\n\ndata:",
        "data:test\n\ndata: test\n\n",
        "event: add\ndata: 73857293\n\nevent: remove\ndata: 2153\n\nevent: add\ndata: 113411\n\n",
        "data: a\r\ndata: b\r\rdata: c\r\n\r\n",
        "\xef\xbb\xbfdata: bom\n\n",
        "retry: 1500\ndata: x\n\nretry: 15a\n\nretry:\n\n",
        "id: 7\n\ndata: after\n\n",
        "id: a\x00b\ndata: nul\n\n",
        "data: x\nid: 9\n",
        "field-without-colon\nevent\ndata: kept\n\n",
        "data: [DONE]\n\n",
        "event: ping\ndata: {}\n\nevent: content_block_delta\ndata: {\"delta\":\"hi\"}\n\n",
        "",
        "\n\n\n",
        ":only a comment",
    ]
    for c in cases:
        var data = List[UInt8]()
        if c.startswith("\xef\xbb\xbf"):  # (a literal BOM is a code point here: send the bytes)
            data = [0xEF, 0xBB, 0xBF]
            data.extend(c.as_bytes()[6:])
        else:
            data = _bytes(c)
        _expect(o, data, List[Int]())


def test_random_streams_in_random_pieces() raises:
    """Random streams from the oracle's alphabet of lines, line ends
    (CRLF, LF, CR) and fields, fed in random pieces: the same events,
    last ID, retry and end as the reference."""
    var o = _oracle()
    var random = Python.import_module("random")
    var rng = random.Random(20261026)
    var pieces: List[String] = [
        "data: ", "data:", "data", "event: ", "event:", "id: ", "id:", "retry: ", "retry:", ":", "x", "y z", " ",
        "1", "42", "é", "世", "{\"a\":1}", "[DONE]", "\x00", "\n", "\r", "\r\n", "\n\n", "\r\n\r\n",
    ]
    for _ in range(400):
        var s = String()
        var parts = Int(py=rng.randint(1, 40))
        for _ in range(parts):
            s += pieces[Int(py=rng.randrange(len(pieces)))]
        var data = _bytes(s)
        var cuts = List[Int]()
        var at = 0
        while len(data) > 0:
            at += Int(py=rng.randint(1, 8))
            if at >= len(data):
                break
            cuts.append(at)
        _expect(o, data, cuts)


def test_chunking_invariance() raises:
    var input = _bytes("retry: 10\r\nid: 1\r\nevent: e\r\ndata: one\r\ndata: two\r\n\r\n: c\rdata: three\r\rdata: tail")
    var t = drive_chunked[_render](SseParser(), Span(input))
    assert_equal(len(t), 2)


def test_bounds() raises:
    var p = SseParser(max_line=16, max_data=32)
    var long = _bytes("data: 0123456789abcdef\n\n")  # (a 22-byte line)
    var e = _feed_error(p, long)
    assert_equal(String(e.kind), "InvalidData")
    var q = SseParser(max_line=64, max_data=32)
    var big = _bytes("data: 0123456789\ndata: 0123456789\ndata: 0123456789\n\n")
    assert_equal(String(_feed_error(q, big).kind), "InvalidData")
    # A line still arriving is bounded too, before its end comes.
    var r = SseParser(max_line=16, max_data=1024)
    var partial = _bytes("data: 0123456789abcdefghij")
    assert_equal(String(_feed_error(r, partial).kind), "InvalidData")
    assert_false(_builds(0), "max_line=0 accepted")


def _builds(max_line: Int) -> Bool:
    try:
        _ = SseParser(max_line=max_line)
        return True
    except:
        return False


def _feed_error(mut p: SseParser, data: List[UInt8]) raises -> IoError:
    try:
        var at = 0
        while at < len(data):
            var n = min(len(data) - at, p.feed_capacity())
            if n == 0:
                break
            p.feed(Span(data)[at : at + n])
            at += n
            while p.next_event():
                pass
        while p.next_event():
            pass
    except e:
        return e
    raise Error("no error")


def test_encoder_round_trip() raises:
    var out = ByteBuffer()
    write_event(out, "plain")
    write_event(out, "two\nlines\r\nand\rthree", event="update", id="42", retry_ms=2000)
    write_event(out, "", event="empty")
    write_comment(out, "heartbeat")
    write_comment(out)
    write_event(out, "{\"choices\":[]}")
    var p = SseParser()
    p.feed(out.readable_span())
    var got = List[SseEvent]()
    while True:
        var ev = p.next_event()
        if not ev:
            break
        got.append(ev.value().copy())
    assert_equal(len(got), 4)
    assert_equal(got[0].data, "plain")
    assert_equal(got[0].event, "message")
    assert_equal(got[1].data, "two\nlines\nand\nthree")
    assert_equal(got[1].event, "update")
    assert_equal(got[1].id, "42")
    assert_equal(got[2].event, "empty")
    assert_equal(got[2].data, "")
    assert_equal(got[3].id, "42")  # (the ID carries over)
    assert_equal(p.retry_ms().value(), 2000)
    var bad = ByteBuffer()
    var refused = 0
    for args in [("a\nb", ""), ("", "a\rb"), ("", "a\x00b")]:
        try:
            write_event(bad, "x", event=args[0], id=args[1])
        except:
            refused += 1
    assert_equal(refused, 3)
    assert_equal(len(bad), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
