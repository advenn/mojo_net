"""The production `Driver`: Linux epoll (edge-triggered) and raw syscalls."""

from std.sys import size_of

from bytes.buffer import ByteBuffer
from linux import Duration, Epoll, IoError, Instant, RawFd
from linux import sys
from linux.abi import EpollEvent, RawSockaddr
from linux.consts import (
    EPOLLERR,
    EPOLLET,
    EPOLLHUP,
    EPOLLIN,
    EPOLLOUT,
    EPOLLRDHUP,
    F_DUPFD_CLOEXEC,
    MSG_NOSIGNAL,
    SO_ERROR,
    SOCK_CLOEXEC,
    SOCK_NONBLOCK,
    SOL_SOCKET,
)
from linux.probe import nofile_limit

from .driver import Driver, ReadyEvent

comptime EVENTS_PER_WAIT = 1024
comptime FD_TABLE_PREGROW = 65536
"""Pre-grow the fd table to this many slots (capped by RLIMIT_NOFILE)."""
comptime _WATCH = UInt32(EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET)


def _pregrow_fd_table(fd: RawFd):
    """Make the kernel allocate a large fd table once, now.

    The table doubles when an fd number reaches its size. In a process with
    more than one thread (every Mojo process: the runtime starts its worker
    pool before main) each doubling waits for an RCU grace period, which
    stalls whatever syscall creates the fd for 20-40 ms; under a connection
    burst that overflows the accept queue (docs/spikes.md). dup3 onto a high
    number grows the table in one step; closing it leaves the table large.
    """
    var limit = 1024
    try:
        limit = Int(min(nofile_limit().cur, UInt64(FD_TABLE_PREGROW)))
    except:
        pass
    var high = limit - 1
    if high < 256:
        return
    # F_DUPFD_CLOEXEC takes the lowest *free* fd >= high. dup3(fd, high)
    # would silently close an application fd that is open at `high`.
    var r = sys.fcntl(fd, F_DUPFD_CLOEXEC, high)
    if r >= 0:
        _ = sys.close(Int32(r))


struct EpollDriver(Driver):
    var _ep: Epoll
    var _events: List[EpollEvent]

    def __init__(out self, var ep: Epoll):
        self._ep = ep^
        self._events = List[EpollEvent](capacity=EVENTS_PER_WAIT)

    @staticmethod
    def create() raises IoError -> Self:
        var ep = Epoll.new()
        _pregrow_fd_table(RawFd(ep.raw_fd()))
        return Self(ep^)

    @inline(.always)
    def now(self) -> Instant:
        return Instant.now()

    @inline(.always)
    def socket(mut self, family: Int, type_: Int) -> Int:
        return sys.socket(family, type_ | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)

    @inline(.always)
    def set_int_option(
        mut self, fd: Int32, level: Int, name: Int, value: Int32
    ) -> Int:
        var v = value
        return sys.setsockopt(RawFd(fd), level, name, v, size_of[Int32]())

    @inline(.always)
    def bind(mut self, fd: Int32, addr: RawSockaddr) -> Int:
        return sys.bind(RawFd(fd), addr.storage, addr.socklen())

    @inline(.always)
    def listen(mut self, fd: Int32, backlog: Int) -> Int:
        return sys.listen(RawFd(fd), backlog)

    @inline(.always)
    def local_addr(mut self, fd: Int32, mut addr: RawSockaddr) -> Int:
        addr.reset()
        return sys.getsockname(RawFd(fd), addr.storage, addr.len)

    @inline(.always)
    def accept(mut self, fd: Int32, mut peer: RawSockaddr) -> Int:
        peer.reset()
        return sys.accept4(
            RawFd(fd), peer.storage, peer.len, SOCK_NONBLOCK | SOCK_CLOEXEC
        )

    @inline(.always)
    def connect(mut self, fd: Int32, addr: RawSockaddr) -> Int:
        return sys.connect(RawFd(fd), addr.storage, addr.socklen())

    def socket_error(mut self, fd: Int32) -> Int:
        var err: Int32 = 0
        var len = UInt32(size_of[Int32]())
        var r = sys.getsockopt(RawFd(fd), SOL_SOCKET, SO_ERROR, err, len)
        if r < 0:
            return r
        return -Int(err)

    @inline(.always)
    def recv(mut self, fd: Int32, mut buf: ByteBuffer) -> Int:
        var r = sys.recv(RawFd(fd), buf.writable_span(), 0)
        if r > 0:
            try:
                buf.commit(r)
            except:
                pass
        return r

    @inline(.always)
    def send(mut self, fd: Int32, buf: ByteBuffer) -> Int:
        return sys.send(RawFd(fd), buf.readable_span(), MSG_NOSIGNAL)

    @inline(.always)
    def shutdown(mut self, fd: Int32, how: Int) -> Int:
        return sys.shutdown(RawFd(fd), how)

    @inline(.always)
    def close(mut self, fd: Int32) -> Int:
        return sys.close(fd)

    def register(mut self, fd: Int32, token: UInt64) -> Int:
        try:
            self._ep.add(RawFd(fd), _WATCH, token)
            return 0
        except e:
            return -Int(e.errno.value)

    def deregister(mut self, fd: Int32) -> Int:
        try:
            self._ep.delete(RawFd(fd))
            return 0
        except e:
            return -Int(e.errno.value)

    def wait(mut self, timeout_ns: Int, mut out: List[ReadyEvent]) raises IoError:
        var timeout: Optional[Duration] = None
        if timeout_ns >= 0:
            timeout = Duration.from_nanos(timeout_ns)
        var n = self._ep.wait(self._events, timeout)
        for i in range(n):
            ref ev = self._events[i]
            out.append(ReadyEvent(ev.data(), ev.events()))
