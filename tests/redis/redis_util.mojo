"""Helpers for the tests/redis files: the Python oracle (`resp_oracle.py`,
the server side written independently of src/redis), hex conversions, and
driving a `RespConnection` with whole server transcripts."""

from std.python import Python, PythonObject

from bytes.buffer import ByteBuffer
from linux import IoError
from redis import RespConnection, RespEvent


def oracle() raises -> PythonObject:
    var sys = Python.import_module("sys")
    _ = sys.path.insert(0, "tests/redis")
    return Python.import_module("resp_oracle")


def hex(data: Span[UInt8, _]) -> String:
    var digits = "0123456789abcdef".as_bytes()
    var out = List[UInt8](capacity=2 * len(data))
    for b in data:
        out.append(digits[Int(b >> 4)])
        out.append(digits[Int(b & 15)])
    return String(unsafe_from_utf8=Span(out))


def hex(text: StringSlice) -> String:
    return hex(text.as_bytes())


def _nibble(c: UInt8) raises -> Int:
    if c >= 48 and c <= 57:
        return Int(c) - 48
    if c >= 97 and c <= 102:
        return Int(c) - 87
    raise Error("not a hex digit")


def unhex(text: StringSlice) raises -> List[UInt8]:
    var t = text.as_bytes()
    var out = List[UInt8](capacity=len(t) // 2)
    for i in range(0, len(t), 2):
        out.append(UInt8(_nibble(t[i]) * 16 + _nibble(t[i + 1])))
    return out^


def s(x: PythonObject) raises -> String:
    return String(x)


def sent(mut c: RespConnection) raises -> String:
    """The hex of everything `c` has queued to send."""
    var out = ByteBuffer()
    _ = c.poll_transmit(out)
    return hex(out.readable_span())


def render(err: IoError) -> String:
    return String("error ", err.kind, ": ", err.op)


def give(mut c: RespConnection, server_hex: StringSlice, eof: Bool = False) raises -> String:
    """Feed `c` the server's bytes as a rule-5 driver (at most
    `feed_capacity()` at a time, draining in between), then EOF if `eof`,
    and return its events rendered and joined by "|"; "error <kind>: <op>"
    ends the list if it raised."""
    var data = unhex(server_hex)
    var out = String()
    var ev = RespEvent()
    try:
        var at = 0
        while True:
            while c.poll(ev):
                if out.byte_length() > 0:
                    out += "|"
                out += String(ev)
            if at == len(data):
                break
            var n = min(c.feed_capacity(), len(data) - at)
            c.feed(Span(data)[at : at + n])
            at += n
        if eof:
            c.feed_eof()
            while c.poll(ev):
                if out.byte_length() > 0:
                    out += "|"
                out += String(ev)
    except e:
        if out.byte_length() > 0:
            out += "|"
        out += render(e)
    _ = ev^
    return out^


def expecting(replies: Int) raises -> RespConnection:
    """A connection with `replies` commands sent (PING), waiting for their
    replies."""
    from redis import Args

    var c = RespConnection()
    for _ in range(replies):
        c.command(Args("PING"))
    _ = sent(c)
    return c^
