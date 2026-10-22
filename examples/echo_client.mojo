"""Blocking TCP echo client for examples/echo_server.mojo.

    pixi run mojo run -I src examples/echo_client.mojo [ADDR] [MESSAGES]

Connects (3 s connect timeout) to ADDR (default 127.0.0.1:7878), sends
MESSAGES (default 3) lines one at a time and checks that each comes back
byte for byte (`read_exact` under a 5 s read deadline), then half-closes
and confirms the server ends the stream (EOF).
"""

from std.sys import argv

from linux.time import Deadline, Duration, Instant
from net.addr import SocketAddr
from net.socket import Shutdown
from net.tcp import TcpStream


def main() raises:
    var args = argv()
    var addr = SocketAddr.parse(args[1] if len(args) > 1 else "127.0.0.1:7878")
    var count = atol(args[2]) if len(args) > 2 else 3
    var conn = TcpStream.connect_timeout(addr, Duration.from_secs(3))
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
