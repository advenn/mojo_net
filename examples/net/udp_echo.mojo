"""UDP echo server in either mode: blocking (one datagram at a time, with a
read deadline for idle reporting) or a readiness loop (edge-triggered
epoll, receiving and sending in batches with recvmmsg/sendmmsg).

    pixi run mojo run -I src examples/net/udp_echo.mojo [ADDR] [MODE] [MAX]

ADDR defaults to 127.0.0.1:7979 (port 0 picks one; the bound address is
printed); MODE is `blocking` (default) or `epoll`; MAX > 0 exits after
echoing that many datagrams. Try it with examples/net/udp_ping.mojo.

A reply can fail for reasons the sender controls: a datagram from port 0
cannot be answered (EINVAL), nor one from a broadcast address (EACCES),
and its source can be forged. So a failed reply drops that datagram and
the server goes on; a server that let it raise could be stopped by one
crafted packet.

Bound to a wildcard address (0.0.0.0 or [::]) on a host with several
addresses, a reply leaves from the address the route back chooses, which
may not be the one the client sent to: a connected client then drops it.
`recv_from_to` and `send_from` answer from the address each datagram came
to (`UdpSocket.receive_destination`).
"""

from std.sys import argv, exit, stderr

from linux import Epoll, ErrorKind, IoError
from linux.abi import EpollEvent
from linux.consts import EPOLLET, EPOLLIN
from linux.time import Deadline, Duration
from net.addr import SocketAddr
from net.udp import DatagramBatch, UdpSocket

comptime USAGE = "usage: udp_echo [ADDR] [blocking|epoll] [MAX]"


def parse_addr(text: String) -> Optional[SocketAddr]:
    try:
        return SocketAddr.parse(text)
    except:
        print("bad address '", text, "': expected IP:PORT, for example 127.0.0.1:7979 or [::1]:7979", sep="", file=stderr)
        print("(a server binds an IP address: for localhost use 127.0.0.1 or [::1])", file=stderr)
        print(USAGE, file=stderr)
        return None


def blocking(mut sock: UdpSocket, max: Int) raises -> Int:
    """Echo with recv_from / send_to, waiting at most 10 s per datagram."""
    var buf = List[UInt8](length=65535, fill=0)
    var echoed = 0
    while max == 0 or echoed < max:
        sock.set_read_deadline(Deadline.after(Duration.from_secs(10)))
        try:
            var d = sock.recv_from(Span(buf))
            try:
                _ = sock.send_to(Span(buf)[0 : d.len], d.sender)
                echoed += 1
            except:
                pass  # this one cannot be answered: drop it
        except e:
            if not e.is_deadline():
                raise e
            print("udp_echo: idle for 10 s,", echoed, "echoed so far")
    return echoed


def readiness_loop(sock: UdpSocket, max: Int) raises -> Int:
    """Edge-triggered epoll; each wakeup drains the socket in batches of 64
    and echoes each batch with one sendmmsg."""
    var ep = Epoll.new()
    ep.add(sock, UInt32(EPOLLIN | EPOLLET), 0)
    var events = List[EpollEvent](capacity=8)
    var inb = DatagramBatch(64, 65535)
    var out = DatagramBatch(64, 65535)
    var echoed = 0
    while max == 0 or echoed < max:
        _ = ep.wait(events, Optional[Duration](None))
        while True:  # drain until nothing is queued
            var n = sock.try_recv_batch(inb)
            if n == 0:
                break
            out.clear()
            for i in range(n):
                out.push(inb.payload(i), inb.datagram(i).sender)
            # Blocking here bounds memory: a full send buffer waits. A
            # datagram that cannot be answered is skipped, the rest sent.
            while out.pending() > 0:
                try:
                    _ = sock.send_batch(out)
                except:
                    out.skip()
            echoed += out.sent()
    return echoed


def main() raises:
    var args = argv()
    var parsed = parse_addr(String(args[1]) if len(args) > 1 else String("127.0.0.1:7979"))
    if not parsed:
        exit(2)
    var mode = String(args[2]) if len(args) > 2 else String("blocking")
    var max = atol(args[3]) if len(args) > 3 else 0
    if mode != "blocking" and mode != "epoll":
        print(USAGE, file=stderr)
        exit(2)
    var sock = UdpSocket.bind(parsed.take())
    print("udp_echo (", mode, ") listening on ", sock.local_addr(), sep="")
    var n = blocking(sock, max) if mode == "blocking" else readiness_loop(sock, max)
    print("udp_echo: echoed", n, "datagrams")
