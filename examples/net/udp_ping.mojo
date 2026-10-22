"""UDP ping: send COUNT datagrams to HOST:PORT (an echo server such as
examples/net/udp_echo.mojo) and report each round trip, timeouts, and the
loss rate.

    pixi run mojo run -I src examples/net/udp_ping.mojo HOST:PORT [COUNT]

HOST may be a name (resolved without libc) or an IP literal. Each address
of the name is tried in RFC 6724 order until one does not refuse: UDP has
no handshake, so an ICMP "port unreachable" (`ConnectionRefused` on a
connected socket) is how a client learns that nothing listens there. That
is why `localhost:7979` works against udp_echo's default 127.0.0.1:7979
although ::1 comes first. Replies are matched by sequence number; late
replies to earlier pings are counted and skipped.
"""

from std.sys import argv, exit, stderr

from linux import ErrorKind, IoError
from linux.time import Deadline, Duration, Instant
from net.addr import IpAddr, SocketAddr
from net.dial import HostPort
from net.resolver import Resolver
from net.udp import UdpSocket

comptime USAGE = "usage: udp_ping HOST:PORT [COUNT]"


def open_to(ip: IpAddr, port: UInt16) raises -> UdpSocket:
    var any = SocketAddr.parse("[::]:0") if ip.is_ipv6() else SocketAddr.parse("0.0.0.0:0")
    var sock = UdpSocket.bind(any)
    sock.connect(SocketAddr(ip, port))
    return sock^


def ping(mut sock: UdpSocket, seq: Int, mut late: Int) raises IoError -> Bool:
    """One ping: True if answered within 1 s. A refusal raises."""
    var msg = String("ping ", seq)
    var buf = List[UInt8](length=1500, fill=0)
    var t = Instant.now()
    _ = sock.send(msg.as_bytes())
    sock.set_read_deadline(Deadline.after(Duration.from_secs(1)))
    while True:
        try:
            var d = sock.recv(Span(buf))
            if String(from_utf8_lossy=Span(buf)[0 : d.len]) == msg:
                print("reply", seq, "from", sock.peer_addr(), "in", t.elapsed())
                return True
            late += 1  # a reply to an earlier ping
        except e:
            if not e.is_deadline():
                raise e
            print("timeout", seq)
            return False


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
    var ips = Resolver.system().lookup_ip(target.host, Deadline.after(Duration.from_secs(3)))
    var lost = 0
    var late = 0
    var seq = 0
    for i in range(len(ips)):
        var sock = open_to(ips[i], target.port)
        try:
            while seq < count:
                if not ping(sock, seq, late):
                    lost += 1
                seq += 1
            break
        except e:
            if e.kind != ErrorKind.ConnectionRefused:
                raise e
            print("refused at", SocketAddr(ips[i], target.port), "- trying the next address")
    if seq < count:
        print("udp_ping: every address refused")
        exit(1)
    print(count, "sent,", count - lost, "answered,", lost, "lost,", late, "late")
