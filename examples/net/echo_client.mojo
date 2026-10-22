"""Blocking TCP echo client for examples/net/echo_server.mojo.

    pixi run mojo run -I src examples/net/echo_client.mojo [ADDR] [MESSAGES]

Connects to ADDR, HOST:PORT with a name or an IP address (default
127.0.0.1:7878), within 3 s with name resolution included, sends
MESSAGES (default 3) lines one at a time and checks that each comes back
byte for byte (`read_exact` under a 5 s read deadline), then half-closes
and confirms the server ends the stream (EOF).
"""

from std.sys import argv, exit, stderr

from linux.time import Deadline, Duration, Instant
from net.dial import HostPort
from net.socket import Shutdown
from net.tcp import TcpStream


comptime USAGE = "usage: echo_client [ADDR] [MESSAGES]"


def parse_target(text: String) -> Optional[HostPort]:
    """ADDR from the command line: HOST:PORT, where HOST is a name or an IP
    address. A bad one is a usage error, explained on stderr (None: the
    caller exits 2)."""
    try:
        return HostPort.parse(text)
    except:
        print("bad address '", text, "': expected HOST:PORT, for example localhost:7878, 127.0.0.1:7878 or [::1]:7878", sep="", file=stderr)
        print(USAGE, file=stderr)
        return None


def main() raises:
    var args = argv()
    var parsed = parse_target(String(args[1]) if len(args) > 1 else String("127.0.0.1:7878"))
    if not parsed:
        exit(2)
    var target = parsed.take()
    var count = atol(args[2]) if len(args) > 2 else 3
    var conn = TcpStream.connect_host(target.host, target.port, Duration.from_secs(3))
    print("connected", conn.local_addr(), "->", conn.peer_addr())
    for i in range(count):
        var msg = String("message ", i, " from echo_client\n")
        var t = Instant.now()
        conn.set_deadline(Deadline.after(Duration.from_secs(5)))
        conn.write_all(msg.as_bytes())
        var back = List[UInt8](length=msg.byte_length(), fill=0)
        conn.read_exact(Span(back))
        var echoed = String(from_utf8_lossy=Span(back))
        if echoed != msg:
            raise Error("echo mismatch: ", repr(echoed))
        print("echoed in", t.elapsed(), ":", echoed, end="")
    conn.shutdown(Shutdown.WRITE)
    var rest = List[UInt8]()
    _ = conn.read_to_end(rest)
    print("server closed the stream;", len(rest), "trailing bytes")
