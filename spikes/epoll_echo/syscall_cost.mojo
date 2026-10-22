"""Per-syscall costs on this host, for the epoll spike's analysis.

Feeds the "where time goes" part of docs/spikes.md. Single thread and no
blocking, so it measures the syscall paths themselves and leaves out wakeups
and scheduling:

- getpid: bare syscall entry and exit (includes this CPU's mitigations).
- clock_gettime: as a raw syscall (`linux.time.Instant.now`) and through
  the vDSO (`std.time.perf_counter_ns`).
- recv on an empty nonblocking TCP socket (the EAGAIN that `--strict-eagain`
  pays per message), and epoll_pwait2 with timeout 0 on a set of 10k idle
  sockets.
- One message hop on a loopback TCP pair: send(a) and then recv(b), 64 B and
  1 KiB. Loopback runs the receiver's TCP input inside the sender's send, so
  this is the in-kernel cost of one direction of the echo.

    pixi run mojo build -I src -I spikes/epoll_echo spikes/epoll_echo/syscall_cost.mojo -o spikes/epoll_echo/out/syscall_cost
    taskset -c 2 spikes/epoll_echo/out/syscall_cost
"""

from std.time import perf_counter_ns

from linux import Errno, OwnedFd, check, sys
from linux.abi import EpollEvent
from linux.consts import EPOLLET, EPOLLIN, IPPROTO_TCP, MSG_NOSIGNAL, TCP_NODELAY
from linux.epoll import Epoll
from linux.nr import SYS_getpid
from linux.probe import nofile_limit, raise_nofile_limit
from linux.syscall import err_of, is_err, syscall0
from linux.time import Instant
from net.addr import Ipv4Addr, SocketAddr, SocketAddrV4
from net.socket import Domain, Socket, SockType

from echo_util import emit


def _ns() -> Int:
    return Instant.now().as_nanos()


def _report(name: StaticString, total_ns: Int, n: Int):
    var tenths = total_ns * 10 // n
    emit(String(name, ": ", tenths // 10, ".", tenths % 10, " ns/op (", n, " ops)"))


def _tcp_pair(listener: Socket, addr: SocketAddr, mut out: List[Socket]) raises:
    """Append a connected loopback pair (both nonblocking, NODELAY)."""
    var a = Socket.new(Domain.IPV4, SockType.STREAM)
    a.connect(addr)
    var acc = listener.accept(nonblocking=True)
    var b = acc^.into_socket()
    a.set_nonblocking(True)
    a.set_nodelay(True)
    b.set_nodelay(True)
    out.append(a^)
    out.append(b^)


def _hop(a: Socket, b: Socket, size: Int, n: Int) raises -> Int:
    """`n` times: send `size` bytes on `a`, then read them all from `b`."""
    var out = List[UInt8](length=size, fill=7)
    var inb = List[UInt8](length=64 * 1024, fill=0)
    var t0 = _ns()
    for _ in range(n):
        var s = check("send", sys.send(a, Span(out), MSG_NOSIGNAL))
        if s != size:
            raise Error("short send in microbenchmark")
        var got = 0
        while got < size:
            var r = sys.recv(b, Span(inb), 0)
            if is_err(r):
                if Errno(err_of(r)) == Errno.EAGAIN:
                    continue  # not delivered yet (never seen on loopback)
                _ = check("recv", r)
            got += r
    return _ns() - t0


def main() raises:
    _ = raise_nofile_limit(nofile_limit().max)
    comptime N = 1_000_000

    var t0 = _ns()
    for _ in range(N):
        _ = syscall0(SYS_getpid)
    _report("getpid (raw syscall)", _ns() - t0, N)

    t0 = _ns()
    var acc = 0
    for _ in range(N):
        acc += Instant.now().as_nanos() & 1
    _report("clock_gettime raw syscall (Instant.now)", _ns() - t0, N)

    t0 = _ns()
    for _ in range(N):
        acc += Int(perf_counter_ns()) & 1
    _report("clock_gettime vDSO (std.time.perf_counter_ns)", _ns() - t0, N)

    var listener = Socket.new(Domain.IPV4, SockType.STREAM)
    listener.set_reuse_address(True)
    listener.bind(SocketAddr(SocketAddrV4(Ipv4Addr(127, 0, 0, 1), 0)))
    listener.listen(4096)
    var addr = listener.local_addr()

    var socks = List[Socket]()
    _tcp_pair(listener, addr, socks)
    ref a = socks[0]
    ref b = socks[1]
    var buf = List[UInt8](length=64 * 1024, fill=0)
    t0 = _ns()
    for _ in range(N):
        var r = sys.recv(b, Span(buf), 0)
        if not is_err(r):
            raise Error("expected EAGAIN")
    _report("recv on empty TCP socket (EAGAIN)", _ns() - t0, N)

    # 10k idle registered sockets: epoll_wait cost does not depend on them.
    var ep = Epoll.new()
    var idle = List[Socket]()
    for _ in range(5000):
        _tcp_pair(listener, addr, idle)
    for i in range(len(idle)):
        ep.add(idle[i], UInt32(EPOLLIN | EPOLLET), UInt64(i))
    var events = List[EpollEvent](capacity=1024)
    t0 = _ns()
    for _ in range(N):
        _ = ep.wait(events, 0)
    _report("epoll_pwait2(timeout 0, 10k idle fds registered)", _ns() - t0, N)
    sys.keep_alive(idle)

    comptime M = 200_000
    _ = _hop(a, b, 64, 10_000)  # warm up
    _report("TCP loopback hop 64 B (send + recv)", _hop(a, b, 64, M), M)
    _report("TCP loopback hop 1 KiB (send + recv)", _hop(a, b, 1024, M), M)
    if acc == -1:
        emit("unreachable")
