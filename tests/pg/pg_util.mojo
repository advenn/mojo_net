"""Helpers for the tests/pg files: the Python oracle (`pg_oracle.py`, the
backend side written independently of src/pg), hex conversions, and driving
a `PgConnection` with whole server transcripts."""

from std.python import Python, PythonObject

from bytes.buffer import ByteBuffer
from linux import IoError
from pg import PgConnection, PgEvent, Startup


def oracle() raises -> PythonObject:
    var sys = Python.import_module("sys")
    _ = sys.path.insert(0, "tests/pg")
    return Python.import_module("pg_oracle")


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


def body_of(message_hex: StringSlice) raises -> List[UInt8]:
    """A backend message's body: what follows its type byte and length."""
    var m = unhex(message_hex)
    return List[UInt8](Span(m)[5:])


def nonce() -> List[UInt8]:
    """The fixed nonce bytes the tests use (base64: "QkJC...")."""
    return List[UInt8](length=18, fill=0x42)


def sent(mut c: PgConnection) raises -> String:
    """The hex of everything `c` has queued to send."""
    var out = ByteBuffer()
    _ = c.poll_transmit(out)
    return hex(out.readable_span())


def render(err: IoError) -> String:
    return String("error ", err.kind, ": ", err.op)


def give(mut c: PgConnection, server_hex: StringSlice, eof: Bool = False) raises -> String:
    """Feed `c` the server's bytes (then EOF if `eof`) and return its
    events, rendered and joined by "|"; "error <kind>: <op>" ends the list
    if it raised."""
    var data = unhex(server_hex)
    var out = String()
    var ev = PgEvent()
    try:
        c.feed(Span(data))
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


def open_session(startup: Startup) raises -> PgConnection:
    """A connection whose session is open (trust), with nothing to send."""
    var c = PgConnection(startup, Span(nonce()))
    _ = sent(c)
    var o = oracle()
    var got = give(c, String(o.auth_ok()) + String(o.session()))
    if got != "READY I":
        raise Error(String("open_session: ", got))
    return c^
