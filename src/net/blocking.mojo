"""Deadline-bounded blocking primitives shared by `net.tcp` and `net.unix`.

They work on any L1 `Socket` that is in nonblocking mode (the L2 streams and
listeners keep theirs O_NONBLOCK). Each operation is (Go's internal/poll)

    try the syscall once -> EAGAIN: wait (fd, events, deadline), retry
                         -> EINTR: retry at once

so the only place that blocks is the wait, bounded by an absolute
`linux.time.Deadline` that is recomputed after every wakeup or signal:
- A deadline bounds *waiting*: an operation that can make progress without
  blocking does so even after the deadline (readiness wins, as in
  `wait_ready`). `Deadline.none()` never expires. Exception:
  `recv_to_end_with_deadline` also checks the deadline between chunks, so a
  peer that never stops sending cannot keep it running past the deadline.
- Expiry raises `IoError` kind `TimedOut` (errno 0) and changes nothing on
  the socket. A composite operation (`recv_exact_with_deadline`,
  `send_all_with_deadline`, `recv_to_end_with_deadline`) may have moved a
  prefix before timing out and does not report how much.
- `Interrupted` never escapes: EINTR retries (a signal neither shortens nor
  restarts a deadline).
- Sends always pass MSG_NOSIGNAL; accepted sockets are CLOEXEC and
  nonblocking.

Wakeups that let nothing progress. The wait is a level-triggered ppoll, and
it also returns for conditions it cannot be asked to ignore (POLLERR,
POLLHUP). When the syscall says EAGAIN again after a wakeup:
- POLLHUP: the endpoint is finished but the call would still block (a
  shut-down AF_UNIX listener reports POLLIN|POLLHUP while accept says
  EAGAIN). Raises: accept `InvalidInput` (EINVAL, what a TCP listener's
  accept returns after shutdown and what a blocking AF_UNIX accept
  returns), recv `NotConnected` (ENOTCONN), send `BrokenPipe` (EPIPE).
- POLLERR: a pending SO_ERROR would have been returned by the syscall
  itself, so this is a non-empty socket *error queue* (MSG_ZEROCOPY
  completions, SO_TIMESTAMPING TX timestamps, IP_RECVERR/IPV6_RECVERR).
  ppoll reports it until someone reads it with MSG_ERRQUEUE, so waiting with
  ppoll would spin. The rest of the operation waits on a private
  edge-triggered epoll instance instead (created only then, closed when the
  operation returns), which wakes only for new events: the operation keeps
  the semantics of a blocking syscall, which ignores the error queue. If that
  instance cannot be created (EMFILE, ENOMEM), the error is raised, tagged
  with `op`. Users of those options should still drain the error queue
  promptly: each such operation pays an extra descriptor and a few syscalls.
- Otherwise (another handle took the data first, ...): wait again, but
  raise `TimedOut` once the deadline has passed, so readiness that keeps
  being reported without progress cannot outlive the deadline.

`op` names the operation in raised errors ("read", "write", "peek", ...).
This module does not import `rt` (blocking layer).
"""

from linux import Epoll, Errno, ErrorKind, IoError, OwnedFd
from linux import sys
from linux.abi import EpollEvent
from linux.consts import (
    EPOLLET,
    F_GETFD,
    F_SETFD,
    FD_CLOEXEC,
    MSG_DONTWAIT,
    MSG_NOSIGNAL,
    MSG_PEEK,
    POLLERR,
    POLLHUP,
    POLLIN,
    POLLOUT,
    POLLRDHUP,
    SOCK_CLOEXEC,
    SOCK_NONBLOCK,
)
from linux.poll import wait_ready
from linux.syscall import err_of, is_err
from linux.time import Deadline, Duration

from .addr import RawSockaddr
from .socket import Domain, SockType, Socket, TcpKeepalive

comptime DEFAULT_BACKLOG = 1024
"""Listen backlog for `bind`; the kernel caps it at net.core.somaxconn
(4096 since Linux 5.4)."""

comptime DEFAULT_READ_TO_END_MAX = 64 * 1024 * 1024
"""Default cap of `read_to_end` (bytes appended per call), the same as
`ByteBuffer`'s default `max_size`: what a peer may make us buffer."""

comptime _READ_CHUNK_MIN = 8 * 1024
comptime _READ_CHUNK_MAX = 1024 * 1024


# ---- waiting -----------------------------------------------------------------


struct _Waiter(Movable):
    """The wait step of one operation's retry loop (see the module docs).

    It remembers what the last wakeup reported (`rev`, and `woke` until the
    syscall makes progress), so the next EAGAIN can tell a harmless race
    from a condition that ppoll would report forever. Once the error queue
    defeats ppoll, `edge` holds the edge-triggered epoll instance used for
    the rest of the operation."""

    var events: Int16
    var hup_errno: Errno
    var rdhup_ends: Bool
    var rev: Int16
    var woke: Bool
    var edge: Optional[Epoll]

    def __init__(
        out self, events: Int, hup_errno: Errno, rdhup_ends: Bool = False
    ):
        """`rdhup_ends`: a wakeup with POLLRDHUP that lets nothing progress
        ends the operation like POLLHUP. Datagram receives need it: after
        shutdown(SHUT_RD) a UDP socket polls readable forever while a
        nonblocking recv keeps saying EAGAIN (a blocking one would return
        0)."""
        self.events = Int16(events | (POLLRDHUP if rdhup_ends else 0))
        self.hup_errno = hup_errno
        self.rdhup_ends = rdhup_ends
        self.rev = 0
        self.woke = False
        self.edge = None

    @inline(.always)
    def progressed(mut self):
        """The syscall moved data (or returned EOF): the last wakeup was
        useful."""
        self.woke = False

    def wait(
        mut self, sock: Socket, deadline: Deadline, op: StaticString
    ) raises IoError:
        """Called after the syscall returned EAGAIN: wait until it may
        progress, or raise."""
        if self.woke:
            # The previous wakeup let nothing progress.
            var rev = Int(self.rev)
            if (rev & POLLHUP) != 0 or (
                self.rdhup_ends and (rev & POLLRDHUP) != 0
            ):
                raise IoError.from_errno(op, self.hup_errno)
            if deadline.is_expired():
                raise IoError.of_kind(op, ErrorKind.TimedOut)
            if (rev & POLLERR) != 0 and not self.edge:
                self.edge = _edge_triggered(sock, self.events, op)
        if self.edge:
            self.rev = _wait_edge(self.edge.value(), deadline, op)
        else:
            self.rev = wait_ready(sock, self.events, deadline, op)
        self.woke = True


def _edge_triggered(
    sock: Socket, events: Int16, op: StaticString
) raises IoError -> Epoll:
    """A private epoll instance with `sock` registered edge-triggered for
    `events` (EPOLLERR/EPOLLHUP are always included by the kernel). The
    registration reports the current state once, so the first wait returns
    at once and the caller retries; after that only new events wake it."""
    try:
        var ep = Epoll.new()
        ep.add(sock, UInt32(Int(events)) | UInt32(EPOLLET), 0)
        return ep^
    except e:
        raise IoError(e.kind, e.errno, op)


def _wait_edge(
    mut ep: Epoll, deadline: Deadline, op: StaticString
) raises IoError -> Int16:
    """Wait on the edge-triggered instance until it reports an event (its
    poll bits, as `revents`) or `deadline` passes (`TimedOut`). EINTR and
    early returns wait again with the recomputed remaining time; an expired
    deadline still checks once without blocking."""
    var evs = List[EpollEvent](capacity=1)
    while True:
        var left = deadline.remaining()
        var n: Int
        try:
            n = ep.wait(evs, left)
        except e:
            raise IoError(e.kind, e.errno, op)
        if n > 0:
            return Int16(Int(evs[0].events()) & 0x7FFF)
        if deadline.is_expired():
            raise IoError.of_kind(op, ErrorKind.TimedOut)


# ---- stream I/O --------------------------------------------------------------


def _recv(
    sock: Socket,
    buf: MutSpan[UInt8, _],
    flags: Int,
    deadline: Deadline,
    op: StaticString,
    mut w: _Waiter,
) raises IoError -> Int:
    while True:
        var r = sys.recv(sock, buf, flags)
        if r >= 0:
            w.progressed()
            return r
        var e = Errno(err_of(r))
        if e == Errno.EAGAIN:
            w.wait(sock, deadline, op)
        elif e != Errno.EINTR:
            raise IoError.from_errno(op, e)


def _send(
    sock: Socket,
    buf: Span[UInt8, _],
    deadline: Deadline,
    op: StaticString,
    mut w: _Waiter,
) raises IoError -> Int:
    while True:
        var r = sys.send(sock, buf, MSG_NOSIGNAL)
        if r >= 0:
            w.progressed()
            return r
        var e = Errno(err_of(r))
        if e == Errno.EAGAIN:
            w.wait(sock, deadline, op)
        elif e != Errno.EINTR:
            raise IoError.from_errno(op, e)


def recv_with_deadline(
    sock: Socket,
    buf: MutSpan[UInt8, _],
    flags: Int,
    deadline: Deadline,
    op: StaticString,
) raises IoError -> Int:
    """One `recv` that waits (up to `deadline`) for data: bytes received, 0
    at EOF. An empty `buf` returns 0 without a syscall (for TCP the kernel
    would also return 0, which is indistinguishable from EOF anyway)."""
    if len(buf) == 0:
        return 0
    var w = _Waiter(POLLIN, Errno.ENOTCONN)
    return _recv(sock, buf, flags, deadline, op, w)


def send_with_deadline(
    sock: Socket, buf: Span[UInt8, _], deadline: Deadline, op: StaticString
) raises IoError -> Int:
    """One `send(MSG_NOSIGNAL)` that waits (up to `deadline`) for buffer
    space: bytes queued, possibly fewer than `len(buf)`. Empty `buf`: 0
    without a syscall."""
    if len(buf) == 0:
        return 0
    var w = _Waiter(POLLOUT, Errno.EPIPE)
    return _send(sock, buf, deadline, op, w)


def recv_exact_with_deadline(
    sock: Socket, buf: MutSpan[UInt8, _], deadline: Deadline, op: StaticString
) raises IoError:
    """Fill `buf` completely; EOF first raises `UnexpectedEof`."""
    var n = len(buf)
    var off = 0
    var w = _Waiter(POLLIN, Errno.ENOTCONN)
    while off < n:
        var k = _recv(sock, buf[off:n], 0, deadline, op, w)
        if k == 0:
            raise IoError.of_kind(op, ErrorKind.UnexpectedEof)
        off += k


def send_all_with_deadline(
    sock: Socket, buf: Span[UInt8, _], deadline: Deadline, op: StaticString
) raises IoError:
    """Send all of `buf`, looping over partial sends. A send that queues 0
    bytes of a non-empty buffer raises `WriteZero` instead of spinning."""
    var n = len(buf)
    var off = 0
    var w = _Waiter(POLLOUT, Errno.EPIPE)
    while off < n:
        var k = _send(sock, buf[off:n], deadline, op, w)
        if k == 0:
            raise IoError.of_kind(op, ErrorKind.WriteZero)
        off += k


def _reserve_for(mut out: List[UInt8], need: Int, have: Int, room: Int):
    """Make `capacity >= need` (`have <= need <= have + room`), doubling so
    appends stay amortized O(1), but never reserving past `have + room` (the
    caller's cap; computed without overflow for `room` near `Int.MAX`)."""
    var cap = out.capacity()
    if cap >= need:
        return
    var target = cap * 2
    if target - have > room:
        target = have + room
    if target < need:
        target = need
    out.reserve(target)


def recv_to_end_with_deadline(
    sock: Socket,
    mut out: List[UInt8],
    deadline: Deadline,
    op: StaticString,
    max_bytes: Int = DEFAULT_READ_TO_END_MAX,
) raises IoError -> Int:
    """Append everything up to EOF to `out`; returns the bytes appended.

    - At most `max_bytes` are appended. A stream with more raises
      `InvalidData` with exactly `max_bytes` appended and the rest unread
      (the byte past the cap is only peeked). `Int.MAX` means no cap; a
      negative `max_bytes` raises `InvalidInput`.
    - The deadline bounds the whole call: besides bounding each wait, it is
      checked before every recv after the first, so data that keeps
      arriving cannot keep the call running past it (`TimedOut`).
    - On an error the bytes received so far stay appended (the speculative
      tail is trimmed). New capacity is not zero-filled."""
    if max_bytes < 0:
        raise IoError.of_kind(op, ErrorKind.InvalidInput)
    var start = len(out)
    var chunk = _READ_CHUNK_MIN
    var w = _Waiter(POLLIN, Errno.ENOTCONN)
    var first = True
    while True:
        if not first and deadline.is_expired():
            raise IoError.of_kind(op, ErrorKind.TimedOut)
        first = False
        var have = len(out)
        var room = max_bytes - (have - start)
        if room == 0:
            # At the cap: only EOF may follow. Peek, so that a byte past the
            # cap stays queued.
            var probe = Array[UInt8, 1](fill=0)
            if _recv(sock, Span(probe), MSG_PEEK, deadline, op, w) == 0:
                return have - start
            raise IoError.of_kind(op, ErrorKind.InvalidData)
        var want = min(chunk, room)
        _reserve_for(out, have + want, have, room)
        out.resize(unsafe_uninit_length=have + want)
        var k: Int
        try:
            k = _recv(sock, Span(out)[have : have + want], 0, deadline, op, w)
        except e:
            out.resize(unsafe_uninit_length=have)
            raise e
        out.resize(unsafe_uninit_length=have + k)
        if k == 0:
            return have - start
        if k == want and chunk < _READ_CHUNK_MAX:
            chunk *= 2


def send_vectored_with_deadline[
    mut: Bool, //, o: Origin[mut=mut]
](
    sock: Socket,
    bufs: Span[Span[UInt8, o], _],
    deadline: Deadline,
    op: StaticString,
) raises IoError -> Int:
    """One gather `sendmsg(MSG_NOSIGNAL)` that waits for buffer space; may
    be partial. All buffers empty: 0 without a syscall."""
    var total = 0
    for b in bufs:
        total += len(b)
    if total == 0:
        return 0
    var w = _Waiter(POLLOUT, Errno.EPIPE)
    while True:
        try:
            return sock.send_vectored(bufs)
        except e:
            if e.errno == Errno.EAGAIN:
                w.wait(sock, deadline, op)
            elif e.errno != Errno.EINTR:
                raise IoError(e.kind, e.errno, op)


def recv_vectored_with_deadline[
    o: MutOrigin
](
    sock: Socket,
    bufs: Span[MutSpan[UInt8, o], _],
    deadline: Deadline,
    op: StaticString,
) raises IoError -> Int:
    """One scatter `recvmsg` that waits for data; 0 at EOF (or when every
    buffer is empty, without a syscall)."""
    var total = 0
    for b in bufs:
        total += len(b)
    if total == 0:
        return 0
    var w = _Waiter(POLLIN, Errno.ENOTCONN)
    while True:
        try:
            return sock.recv_vectored(bufs)
        except e:
            if e.errno == Errno.EAGAIN:
                w.wait(sock, deadline, op)
            elif e.errno != Errno.EINTR:
                raise IoError(e.kind, e.errno, op)


# ---- accept / connect --------------------------------------------------------


def accept_with_deadline(
    listener: Socket, mut peer: RawSockaddr, deadline: Deadline
) raises IoError -> Socket:
    """`accept4(SOCK_CLOEXEC | SOCK_NONBLOCK)` that waits for a connection.

    - EINTR and ECONNABORTED (a queued connection was reset before we took
      it) retry silently: neither says anything about the listener.
    - EMFILE/ENFILE raise `TooManyFiles` and leave the connection queued, so
      the listener stays readable: calling `accept` again at once would
      fail again. The M2 event loop handles this with the reserve-fd trick
      (close a spare descriptor, accept and drop the connection, reopen the
      spare); a blocking server should back off or shed load.
    - A listener that was shut down raises `InvalidInput` (EINVAL) once its
      queue is empty, for TCP (the kernel's answer) and AF_UNIX alike (whose
      nonblocking accept would keep saying EAGAIN; see the module docs).
    `peer` receives the peer address (it is reset before every attempt)."""
    var w = _Waiter(POLLIN, Errno.EINVAL)
    while True:
        peer.reset()
        var r = sys.accept4(
            listener, peer.storage, peer.len, SOCK_CLOEXEC | SOCK_NONBLOCK
        )
        if r >= 0:
            return Socket(OwnedFd(unsafe_from_raw=Int32(r)))
        var e = Errno(err_of(r))
        if e == Errno.EAGAIN:
            w.wait(listener, deadline, "accept")
        elif e != Errno.EINTR and e != Errno.ECONNABORTED:
            raise IoError.from_errno("accept", e)


def try_accept(
    listener: Socket, mut peer: RawSockaddr
) raises IoError -> Optional[Socket]:
    """`accept4(SOCK_CLOEXEC | SOCK_NONBLOCK)` that never waits: the
    connection, or None when none is queued (EAGAIN). EINTR and
    ECONNABORTED retry; EMFILE/ENFILE raise `TooManyFiles` with the
    connection left queued (see `accept_with_deadline`)."""
    while True:
        peer.reset()
        var r = sys.accept4(
            listener, peer.storage, peer.len, SOCK_CLOEXEC | SOCK_NONBLOCK
        )
        if r >= 0:
            return Socket(OwnedFd(unsafe_from_raw=Int32(r)))
        var e = Errno(err_of(r))
        if e == Errno.EAGAIN:
            return None
        if e != Errno.EINTR and e != Errno.ECONNABORTED:
            raise IoError.from_errno("accept", e)


def try_recv(
    sock: Socket, buf: MutSpan[UInt8, _], op: StaticString
) raises IoError -> Optional[Int]:
    """One recv that never waits (the socket is O_NONBLOCK): the bytes read,
    0 at EOF (and for an empty `buf`), or None when nothing is queued
    (EAGAIN). EINTR retries; anything else raises, tagged with `op`."""
    if len(buf) == 0:
        return 0
    while True:
        var r = sys.recv(sock, buf, 0)
        if r >= 0:
            return r
        var e = Errno(err_of(r))
        if e == Errno.EAGAIN:
            return None
        if e != Errno.EINTR:
            raise IoError.from_errno(op, e)


def try_send(
    sock: Socket, buf: Span[UInt8, _], op: StaticString
) raises IoError -> Optional[Int]:
    """One send(MSG_NOSIGNAL) that never waits: the bytes queued (possibly
    fewer than `len(buf)`; 0 for an empty `buf`), or None when the send
    buffer is full (EAGAIN). EINTR retries; a vanished peer raises
    `BrokenPipe` / `ConnectionReset`."""
    if len(buf) == 0:
        return 0
    while True:
        var r = sys.send(sock, buf, MSG_NOSIGNAL)
        if r >= 0:
            return r
        var e = Errno(err_of(r))
        if e == Errno.EAGAIN:
            return None
        if e != Errno.EINTR:
            raise IoError.from_errno(op, e)


def connect_with_deadline(
    sock: Socket, addr: RawSockaddr, deadline: Deadline
) raises IoError:
    """Connect a nonblocking socket: `connect` once, then wait until it is
    writable and read the outcome from SO_ERROR.

    `connect` is issued exactly once. EINTR is treated like EINPROGRESS:
    the attempt continues in the kernel, and a second `connect` would report
    EALREADY/EISCONN or, if the attempt had failed meanwhile, silently start
    a new one. A wakeup that shows neither an error nor a peer (getpeername
    ENOTCONN) waits again, unless ppoll reported HUP/ERR: then the attempt
    is over and raises `NotConnected`; once the deadline has passed it
    raises `TimedOut` instead of waiting again. Timing out leaves the attempt
    running; the caller closes the socket to abort it."""
    var r = sys.connect(sock, addr.storage, addr.socklen())
    if r == 0:
        return
    var e = Errno(err_of(r))
    if e != Errno.EINPROGRESS and e != Errno.EINTR:
        raise IoError.from_errno("connect", e)
    while True:
        var rev = wait_ready(sock, Int16(POLLOUT), deadline, "connect")
        var soerr = sock.take_error()  # SO_ERROR, read and cleared
        if soerr:
            raise IoError.from_errno("connect", soerr.value().errno)
        var name = RawSockaddr()
        var g = sys.getpeername(sock, name.storage, name.len)
        if g == 0:
            return
        var ge = Errno(err_of(g))
        if ge != Errno.ENOTCONN:
            raise IoError.from_errno("connect", ge)
        if (Int(rev) & (POLLHUP | POLLERR)) != 0:
            raise IoError.from_errno("connect", Errno.ENOTCONN)
        if deadline.is_expired():
            raise IoError.of_kind("connect", ErrorKind.TimedOut)


# ---- adopting sockets --------------------------------------------------------


def _set_cloexec(sock: Socket) raises IoError:
    """FD_CLOEXEC on (F_GETFD/F_SETFD; no syscall when it is already set)."""
    var fl = sys.fcntl(sock, F_GETFD)
    if is_err(fl):
        raise IoError.from_errno("fcntl(F_GETFD)", Errno(err_of(fl)))
    if (fl & FD_CLOEXEC) != 0:
        return
    var r = sys.fcntl(sock, F_SETFD, fl | FD_CLOEXEC)
    if is_err(r):
        raise IoError.from_errno("fcntl(F_SETFD)", Errno(err_of(r)))


def adopt_stream_socket(
    var sock: Socket, *, unix: Bool, listener: Bool, op: StaticString
) raises IoError -> Socket:
    """Prepare an adopted socket (fd passing, socket activation, a tuned L1
    socket) for an L2 wrapper, checking first that it is one:

    - SO_DOMAIN AF_UNIX (`unix`) or AF_INET/AF_INET6, SO_TYPE SOCK_STREAM,
      and SO_ACCEPTCONN equal to `listener`. Anything else (or not a
      socket) raises `InvalidInput` tagged with `op` before any connection
      is accepted or any flag changed. Like every failure here, it closes
      `sock` (it was moved in).
    - Then FD_CLOEXEC is set (an inherited descriptor arrives without it,
      and would otherwise leak into every child the program later spawns;
      clear it with `linux.sys.fcntl(s, F_SETFD, 0)` right before an exec
      that should inherit it) and O_NONBLOCK, a file status flag shared with
      every dup of the descriptor."""
    var ok: Bool
    try:
        var d = sock.domain()
        if unix:
            ok = d == Domain.UNIX
        else:
            ok = d == Domain.IPV4 or d == Domain.IPV6
        ok = ok and sock.socket_type() == SockType.STREAM
        ok = ok and sock.is_listener() == listener
    except e:
        if e.errno == Errno.ENOTSOCK:
            raise IoError(ErrorKind.InvalidInput, e.errno, op)
        raise IoError(e.kind, e.errno, op)
    if not ok:
        raise IoError.of_kind(op, ErrorKind.InvalidInput)
    _set_cloexec(sock)
    sock.set_nonblocking(True)
    return sock^


# ---- long-lived connections --------------------------------------------------


comptime DEAD_PEER_KEEPALIVE = TcpKeepalive(
    Duration.from_secs(30), Duration.from_secs(10), 3
)
"""Keepalive for connections that sit idle (database pools): the first
probe after 30 s of silence, then one every 10 s, and the connection is
reset after 3 unanswered probes, so a vanished peer is noticed within about
a minute instead of the system default of over two hours."""


def detect_dead_peers(sock: Socket, keepalive: TcpKeepalive) raises IoError:
    """SO_KEEPALIVE with `keepalive`'s timing, and TCP_USER_TIMEOUT set to
    the same total (idle + interval x count): while sent data is
    unacknowledged, keepalive probes do not run, and without a user
    timeout the kernel retransmits for about 15 minutes (tcp_retries2)
    before giving up. Values outside the kernel's ranges raise
    `InvalidInput` (see `TcpKeepalive`)."""
    sock.set_tcp_keepalive(keepalive)
    sock.set_keepalive(True)
    # The kernel rounds the times up to whole seconds: use what it stored.
    var ka = sock.tcp_keepalive()
    sock.set_tcp_user_timeout(ka.idle + ka.interval * ka.count)


@fieldwise_init
struct IdleState(Equatable, TrivialRegisterPassable, Writable):
    """What an idle stream looks like, from `idle_state`."""

    var value: Int

    comptime EMPTY = IdleState(0)
    """Nothing to read, no FIN or error: as reusable as can be told without
    sending. A peer that vanished silently still looks like this; keepalive
    (`detect_dead_peers`) or the next request finds out."""
    comptime DATA = IdleState(1)
    """Bytes are waiting. For a request/response protocol the stream is out
    of sync (often an error the server sent before closing): discard it.
    Protocols with server push (Postgres LISTEN) read them."""
    comptime CLOSED = IdleState(2)
    """The peer closed (FIN) or reset the stream, or the socket has a
    pending error: discard it."""

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self.value == other.value

    def write_to(self, mut writer: Some[Writer]):
        if self.value == 0:
            writer.write("EMPTY")
        elif self.value == 1:
            writer.write("DATA")
        else:
            writer.write("CLOSED")


def idle_state(sock: Socket) -> IdleState:
    """One recv(MSG_PEEK | MSG_DONTWAIT) of a byte: never waits and
    consumes nothing (a pending socket error is read and cleared)."""
    var b = List[UInt8](length=1, fill=0)
    while True:
        var r = sys.recv(sock, Span(b), MSG_PEEK | MSG_DONTWAIT)
        if r > 0:
            return IdleState.DATA
        if r == 0:
            return IdleState.CLOSED
        var e = Errno(err_of(r))
        if e == Errno.EINTR:
            continue
        if e == Errno.EAGAIN:
            return IdleState.EMPTY
        return IdleState.CLOSED
