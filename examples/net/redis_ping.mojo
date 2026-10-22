"""RESP PING against a local Redis, over `net.tcp`.

    pixi run mojo run -I src examples/net/redis_ping.mojo [ADDR] [MESSAGE]

Sends `PING` (or `PING MESSAGE`) to ADDR (default 127.0.0.1:6379) and prints
the reply: `PONG`, or MESSAGE echoed back as a bulk string.

The protocol side is sans-I/O (docs/design.md, contract 1): `encode_command`
builds bytes and `RespReply.parse` consumes bytes and says whether a whole
reply is there; only `main` touches the socket. A reply that has not fully
arrived simply means "read more", which is how the same codec will run on
the event loop later.
"""

from std.sys import argv, exit, stderr

from linux.time import Deadline, Duration
from net.addr import SocketAddr
from net.tcp import TcpStream


def encode_command(parts: List[String]) -> List[UInt8]:
    """RESP array of bulk strings: *N CRLF ($len CRLF bytes CRLF)*."""
    var s = String("*", len(parts), "\r\n")
    for p in parts:
        s += String("$", p.byte_length(), "\r\n", p, "\r\n")
    var out = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        out.append(b)
    return out^


def _find_crlf(buf: Span[UInt8, _], start: Int) -> Int:
    for i in range(start, len(buf) - 1):
        if buf[i] == 13 and buf[i + 1] == 10:
            return i
    return -1


@fieldwise_init
struct RespReply(Copyable, Movable):
    """One parsed reply: kind is '+', '-', ':' or '$' (nil bulk: '_')."""

    var kind: String
    var text: String

    @staticmethod
    def parse(buf: Span[UInt8, _]) raises -> Optional[RespReply]:
        """A complete reply at the start of `buf`, or None if more bytes are
        needed. Arrays and RESP3 types are out of scope for PING."""
        if len(buf) == 0:
            return None
        var eol = _find_crlf(buf, 1)
        if eol < 0:
            return None
        var kind = String(from_utf8_lossy=buf[0:1])
        var line = String(from_utf8_lossy=buf[1:eol])
        if kind == "+" or kind == "-" or kind == ":":
            return RespReply(kind, line)
        if kind == "$":
            var n = atol(line)
            if n < 0:
                return RespReply("_", "")
            var start = eol + 2
            if len(buf) < start + n + 2:
                return None
            return RespReply(
                "$", String(from_utf8_lossy=buf[start : start + n])
            )
        raise Error("unsupported RESP type: ", kind)


comptime USAGE = "usage: redis_ping [ADDR] [MESSAGE]"


def parse_addr(text: String) -> Optional[SocketAddr]:
    """ADDR from the command line: a numeric IP:PORT. A bad one is a usage
    error, explained on stderr (None: the caller exits 2)."""
    try:
        return SocketAddr.parse(text)
    except:
        print("bad address '", text, "': expected IP:PORT, for example 127.0.0.1:7878 or [::1]:7878", sep="", file=stderr)
        print("(numeric addresses only: host names such as localhost are not resolved yet, so use 127.0.0.1)", file=stderr)
        print(USAGE, file=stderr)
        return None


def main() raises:
    var args = argv()
    var parsed = parse_addr(String(args[1]) if len(args) > 1 else String("127.0.0.1:6379"))
    if not parsed:
        exit(2)
    var addr = parsed.take()
    var cmd: List[String] = ["PING"]
    if len(args) > 2:
        cmd.append(String(args[2]))
    var conn = TcpStream.connect_timeout(addr, Duration.from_secs(2))
    conn.set_deadline(Deadline.after(Duration.from_secs(5)))
    conn.write_all(Span(encode_command(cmd)))
    var buf = List[UInt8]()
    var chunk = List[UInt8](length=4096, fill=0)
    while True:
        var reply = RespReply.parse(Span(buf))
        if reply:
            var r = reply.value().copy()
            if r.kind == "-":
                raise Error("redis error: ", r.text)
            print(r.text)
            return
        var n = conn.read(Span(chunk))
        if n == 0:
            raise Error("redis closed the connection mid-reply")
        for i in range(n):
            buf.append(chunk[i])
