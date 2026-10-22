"""UDP ping: send COUNT datagrams to HOST:PORT (an echo server such as
examples/net/udp_echo.mojo) and report each round trip, timeouts, and the
loss rate.

    pixi run mojo run -I src examples/net/udp_ping.mojo HOST:PORT [COUNT]

HOST may be a name (resolved without libc) or an IP literal. The socket is
connected, so only the server's replies are accepted and an ICMP "port
unreachable" ends the run with `ConnectionRefused`. Each reply is matched by
its sequence number; late replies to earlier pings are counted and skipped.
"""

from std.sys import argv, exit, stderr

from linux import IoError
from linux.time import Deadline, Duration, Instant
from net.dial import HostPort
from net.udp import UdpSocket

comptime USAGE = "usage: udp_ping HOST:PORT [COUNT]"


def main() raises:
    var args = argv()
    if len(args) < 2:
        print(USAGE, file=stderr)
        exit(2)
    var target: HostPort
    try:
        target = HostPort.parse(String(args[1]))
    except:
        print("bad address '", args[1], "': expected HOST:PORT, for example localhost:7979", sep="", file=stderr)
        print(USAGE, file=stderr)
        exit(2)
        return
    var count = atol(args[2]) if len(args) > 2 else 5
    var sock = UdpSocket.connect_host(target.host, target.port, Duration.from_secs(3))
    print("udp_ping", sock.peer_addr(), "from", sock.local_addr())
    var buf = List[UInt8](length=1500, fill=0)
    var lost = 0
    var late = 0
    for seq in range(count):
        var msg = String("ping ", seq)
        var t = Instant.now()
        _ = sock.send(msg.as_bytes())
        sock.set_read_deadline(Deadline.after(Duration.from_secs(1)))
        var answered = False
        while not answered:
            try:
                var d = sock.recv(Span(buf))
                if String(from_utf8_lossy=Span(buf)[0 : d.len]) == msg:
                    print("reply", seq, "in", t.elapsed())
                    answered = True
                else:
                    late += 1  # a reply to an earlier ping
            except e:
                if not e.is_deadline():
                    raise e
                print("timeout", seq)
                lost += 1
                break
    print(count, "sent,", count - lost, "answered,", lost, "lost,", late, "late")
