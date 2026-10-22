"""A tiny netcat: connect, send the command-line text, print the reply.

    pixi run mojo run -I src examples/net/nc_lite.mojo ADDR [TEXT...]

Connects to ADDR (`localhost:7878`, `[::1]:6379`, ...) with a 3 s connect
timeout, sends TEXT (the remaining arguments joined by spaces, plus "\\n"),
half-closes, and prints whatever comes back until the server closes or 2 s
pass without the reply finishing (a read deadline, not an error: servers
that keep the connection open are fine). Exit status 1 on connect errors.
"""

from std.sys import argv, exit, stderr

from linux import ErrorKind, IoError
from linux.time import Deadline, Duration
from net.dial import HostPort
from net.socket import Shutdown
from net.tcp import TcpStream


comptime USAGE = "usage: nc_lite ADDR [TEXT...]"


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
    if len(args) < 2:
        print(USAGE, file=stderr)
        exit(2)
    var parsed = parse_target(String(args[1]))
    if not parsed:
        exit(2)
    var target = parsed.take()
    var text = String()
    for i in range(2, len(args)):
        if i > 2:
            text += " "
        text += args[i]
    text += "\n"

    var conn: TcpStream
    try:
        conn = TcpStream.connect_host(target.host, target.port, Duration.from_secs(3))
    except e:
        print("nc_lite: cannot connect to", target, "-", e)
        exit(1)
        return
    conn.set_write_deadline(Deadline.after(Duration.from_secs(3)))
    conn.write_all(text.as_bytes())
    conn.shutdown(Shutdown.WRITE)

    conn.set_read_deadline(Deadline.after(Duration.from_secs(2)))
    var reply = List[UInt8]()
    var timed_out = False
    try:
        _ = conn.read_to_end(reply)  # keeps what arrived even on error
    except e:
        if e.kind != ErrorKind.TimedOut:
            print("nc_lite: read failed -", e)
            exit(1)
        timed_out = True
    print(String(from_utf8_lossy=Span(reply)), end="")
    if timed_out:
        print("\n(nc_lite: no EOF within 2 s; stopped reading)")
