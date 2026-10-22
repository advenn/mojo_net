"""L2 blocking TCP: `TcpListener` and `TcpStream` with per-direction
deadlines.

Model (Go's internal/poll): every L2 socket is O_NONBLOCK internally and
each operation is

    try the syscall once -> EAGAIN: wait_ready(fd, events, deadline), retry
                         -> EINTR: retry at once

so the only place that blocks is ppoll, bounded by an absolute deadline that
is recomputed after every wakeup or signal. That gives per-operation
timeouts without SO_RCVTIMEO/SO_SNDTIMEO (jiffy resolution, one value per
socket, and EINTR leaks out of them), and an L2 socket can be handed to an
event loop later without changing its flags.

Deadlines:
- Absolute `linux.time.Deadline`s, stored per stream: one for reads (`read`,
  `read_exact`, `read_to_end`, `read_vectored`, `peek`) and one for writes
  (`write`, `write_all`, `write_vectored`); listeners have one for `accept`.
  They apply to every later operation until changed. `Deadline.none()` (the
  default) never expires.
- A deadline bounds *waiting*: an operation that can make progress without
  blocking does so even after the deadline (readiness wins, as in
  `wait_ready`). `read_to_end` also checks it between chunks, so a peer
  that keeps sending cannot keep it running past the deadline.
- Expiry raises `IoError` kind `TimedOut` (errno 0) and changes nothing on
  the socket: set a new deadline and carry on. A composite operation
  (`read_exact`, `write_all`, `read_to_end`) may have moved a prefix before
  timing out and does not report how much; protocols that cannot
  resynchronize should close the stream.
- A non-empty socket error queue (MSG_ZEROCOPY completions,
  SO_TIMESTAMPING, IP_RECVERR) makes ppoll report POLLERR until it is read
  with MSG_ERRQUEUE; waits then fall back to a private edge-triggered epoll
  instance, so they neither spin nor miss their deadline (see
  `net.blocking`). Drain the queue promptly anyway.

Other policy:
- Sends always pass MSG_NOSIGNAL: a vanished peer raises `BrokenPipe` /
  `ConnectionReset`, never SIGPIPE.
- Every descriptor is CLOEXEC (socket, accept4, F_DUPFD_CLOEXEC), including
  adopted ones: `from_socket` sets FD_CLOEXEC, which an inherited descriptor
  usually lacks.
- `from_socket` checks the family, type and listening state of what it
  adopts and raises `InvalidInput` for anything else, before any connection
  is accepted.
- Connected and accepted streams have TCP_NODELAY on (request/response
  traffic; `socket().set_nodelay(False)` restores Nagle).
- Listeners set SO_REUSEADDR, so a restarted server can bind while old
  connections sit in TIME_WAIT.

`accept` returns a `TcpAccepted` (stream + peer address) rather than a tuple:
Mojo cannot move a non-copyable element out of a tuple.

The deadline-bounded primitives (`recv_with_deadline`, ...) live in
`net.blocking`, shared with `net.unix` (and still importable from here).
This module does not import `rt` (blocking layer).
"""

from linux import AsFd, ErrorKind, IoError
from linux.consts import MSG_PEEK
from linux.time import Deadline, Duration

from .addr import RawSockaddr, SocketAddr
from .blocking import (
    try_accept,
    try_recv,
    try_send,
    DEAD_PEER_KEEPALIVE,
    detect_dead_peers,
    IdleState,
    idle_state,
    DEFAULT_BACKLOG,
    DEFAULT_READ_TO_END_MAX,
    accept_with_deadline,
    adopt_stream_socket,
    connect_with_deadline,
    recv_exact_with_deadline,
    recv_to_end_with_deadline,
    recv_vectored_with_deadline,
    recv_with_deadline,
    send_all_with_deadline,
    send_vectored_with_deadline,
    send_with_deadline,
)
from .dial import dial_tcp
from .reader import Read
from .resolver import Resolver
from .socket import Domain, Shutdown, SockType, Socket, TcpKeepalive


@inline(.always)
def _check_timeout(timeout: Duration, op: StaticString) raises IoError:
    """A zero timeout is a caller bug (Rust's rule): "no time at all" and
    "no timeout" are both plausible readings, so neither is guessed."""
    if timeout.is_zero():
        raise IoError.of_kind(op, ErrorKind.InvalidInput)


# ---- TcpStream ---------------------------------------------------------------


struct TcpStream(AsFd, Movable, Read, Writable):
    """A connected TCP stream with blocking reads and writes bounded by
    per-direction deadlines (see the module docs).

    Methods take `self` immutably: only the deadline setters mutate. Not
    copyable; `try_clone` makes a second handle."""

    var _sock: Socket
    var _rd: Deadline
    var _wr: Deadline

    @inline(.always)
    def __init__(out self, *, var nonblocking_socket: Socket):
        """Wrap a socket that is already O_NONBLOCK (no syscall). Use
        `from_socket` for anything else."""
        self._sock = nonblocking_socket^
        self._rd = Deadline.none()
        self._wr = Deadline.none()

    # ---- connecting ----------------------------------------------------------

    @staticmethod
    def connect(addr: SocketAddr) raises IoError -> TcpStream:
        """Connect with no time limit (the kernel gives up after its SYN
        retries, ~2 min by default, with `TimedOut`). Refused raises
        `ConnectionRefused`."""
        return TcpStream.connect_deadline(addr, Deadline.none())

    @staticmethod
    def connect_timeout(
        addr: SocketAddr, timeout: Duration
    ) raises IoError -> TcpStream:
        """Connect, giving up with `TimedOut` after `timeout`. A zero
        timeout raises `InvalidInput`; `Duration.MAX` means no limit."""
        _check_timeout(timeout, "connect")
        return TcpStream.connect_deadline(addr, Deadline.after(timeout))

    @staticmethod
    def connect_deadline(
        addr: SocketAddr, deadline: Deadline
    ) raises IoError -> TcpStream:
        """Connect, giving up with `TimedOut` at `deadline` (an expired one
        still checks once whether the handshake already completed). The
        socket is closed on every failure."""
        var sock = Socket.new(
            Domain.for_address(addr), SockType.STREAM, nonblocking=True
        )
        connect_with_deadline(sock, addr.to_raw(), deadline)
        sock.set_nodelay(True)
        return TcpStream(nonblocking_socket=sock^)

    @staticmethod
    def connect_host(
        host: StringSlice, port: UInt16, timeout: Duration
    ) raises IoError -> TcpStream:
        """Connect to a host name (or IP literal) and port, giving up with
        `TimedOut` after `timeout`, name resolution included. The system
        configuration (/etc/resolv.conf, /etc/hosts) is read for each call
        that needs it; to reuse it, pass a `Resolver` to
        `connect_host_deadline`. Addresses race with Happy Eyeballs v2
        (`net.dial`). A zero timeout raises `InvalidInput`."""
        _check_timeout(timeout, "connect")
        return TcpStream.connect_host_deadline(
            host, port, Deadline.after(timeout)
        )

    @staticmethod
    def connect_host_deadline(
        host: StringSlice, port: UInt16, deadline: Deadline
    ) raises IoError -> TcpStream:
        """`connect_host` with an absolute deadline; the system configuration
        is read only when `host` is not an IP literal."""
        var sock = dial_tcp(host, port, deadline)
        sock.set_nodelay(True)
        return TcpStream(nonblocking_socket=sock^)

    @staticmethod
    def connect_host_deadline(
        host: StringSlice,
        port: UInt16,
        deadline: Deadline,
        resolver: Resolver,
    ) raises IoError -> TcpStream:
        """`connect_host` with an absolute deadline and a `Resolver` kept by
        the caller (a connection pool, for example)."""
        var sock = dial_tcp(resolver, host, port, deadline)
        sock.set_nodelay(True)
        return TcpStream(nonblocking_socket=sock^)

    # ---- ownership -----------------------------------------------------------

    @staticmethod
    def from_socket(var sock: Socket) raises IoError -> TcpStream:
        """Adopt a connected TCP socket (fd passing, socket activation, a
        tuned L1 socket).

        An AF_INET/AF_INET6 SOCK_STREAM socket that is not listening, else
        `InvalidInput` (op "TcpStream.from_socket"; the socket is closed).
        Sets FD_CLOEXEC and O_NONBLOCK (a file status flag, shared with every
        dup of the descriptor); changes no other option (TCP_NODELAY is left
        as is). See `net.blocking.adopt_stream_socket`."""
        return TcpStream(
            nonblocking_socket=adopt_stream_socket(
                sock^, unix=False, listener=False, op="TcpStream.from_socket"
            )
        )

    @inline(.always)
    def into_socket(deinit self) -> Socket:
        """The L1 socket, still O_NONBLOCK (call `set_nonblocking(False)` for
        L1 blocking semantics)."""
        return self._sock^

    @inline(.always)
    def socket(ref self) -> ref[self._sock] Socket:
        """The L1 socket, for options (`set_nodelay`, `set_linger`,
        `tcp_info`, ...). Do not clear O_NONBLOCK through it: L2 operations
        would then block in the kernel and ignore deadlines."""
        return self._sock

    @inline(.always)
    def raw_fd(self) -> Int32:
        """The descriptor, still owned by `self` (see `OwnedFd.raw_fd`)."""
        return self._sock.raw_fd()

    def try_clone(self) raises IoError -> TcpStream:
        """A second handle (F_DUPFD_CLOEXEC) to the same connection.

        Deadlines belong to the handle, not the connection: the clone starts
        with a copy of this handle's deadlines, and later changes to either
        do not affect the other. Everything kernel-side is shared: the byte
        stream (two readers split it arbitrarily), socket options and
        O_NONBLOCK."""
        var s = TcpStream(nonblocking_socket=self._sock.try_clone())
        s._rd = self._rd
        s._wr = self._wr
        return s^

    def close(deinit self) raises IoError:
        """Close and report errors (dropping the stream ignores them)."""
        self._sock^.close()

    # ---- deadlines -----------------------------------------------------------

    @inline(.always)
    def set_read_deadline(mut self, deadline: Deadline):
        """Bound every later read/peek; `Deadline.none()` removes it."""
        self._rd = deadline

    @inline(.always)
    def set_write_deadline(mut self, deadline: Deadline):
        """Bound every later write; `Deadline.none()` removes it."""
        self._wr = deadline

    @inline(.always)
    def set_deadline(mut self, deadline: Deadline):
        """Set the read and the write deadline."""
        self._rd = deadline
        self._wr = deadline

    @inline(.always)
    def read_deadline(self) -> Deadline:
        return self._rd

    @inline(.always)
    def write_deadline(self) -> Deadline:
        return self._wr

    # ---- I/O -----------------------------------------------------------------

    def read(self, buf: MutSpan[UInt8, _]) raises IoError -> Int:
        """Wait for data and return how much was read (at most `len(buf)`);
        0 means EOF (the peer shut down its write side) or an empty `buf`. A
        peer's abortive close raises `ConnectionReset`."""
        return recv_with_deadline(self._sock, buf, 0, self._rd, "read")

    def read_exact(self, buf: MutSpan[UInt8, _]) raises IoError:
        """Fill `buf`; EOF first raises `UnexpectedEof` (the bytes before it
        are in `buf`, but how many is not reported)."""
        recv_exact_with_deadline(self._sock, buf, self._rd, "read")

    def read_to_end(
        self, mut out: List[UInt8], max_bytes: Int = DEFAULT_READ_TO_END_MAX
    ) raises IoError -> Int:
        """Append everything up to EOF to `out`; returns the count.

        - At most `max_bytes` are appended (default 64 MiB, like
          `ByteBuffer`), because the peer decides how much comes: a stream
          with more raises `InvalidData` with exactly `max_bytes` appended
          and the rest unread. `Int.MAX` removes the cap; a negative one
          raises `InvalidInput`.
        - The read deadline bounds the whole call: it is also checked
          between chunks, so data that keeps arriving cannot keep the call
          running past it (`TimedOut`).
        - On error the bytes read so far stay appended."""
        return recv_to_end_with_deadline(
            self._sock, out, self._rd, "read", max_bytes
        )

    def read_vectored[
        o: MutOrigin
    ](self, bufs: Span[MutSpan[UInt8, o], _]) raises IoError -> Int:
        """Scatter-read into `bufs` in order (one recvmsg); 0 at EOF."""
        return recv_vectored_with_deadline(self._sock, bufs, self._rd, "read")

    def try_read(self, buf: MutSpan[UInt8, _]) raises IoError -> Optional[Int]:
        """For readiness loops (`linux.Epoll`): one read that never waits and
        ignores the read deadline. The bytes read, 0 at EOF (or for an empty
        `buf`), or None when nothing is available; with edge-triggered epoll,
        read until None before waiting again."""
        return try_recv(self._sock, buf, "read")

    def try_write(self, buf: Span[UInt8, _]) raises IoError -> Optional[Int]:
        """For readiness loops: one write that never waits and ignores the
        write deadline. The bytes queued (possibly fewer than `len(buf)`),
        or None when the send buffer is full: keep the rest and write it
        when the socket is writable again."""
        return try_send(self._sock, buf, "write")

    def peek(self, buf: MutSpan[UInt8, _]) raises IoError -> Int:
        """Like `read`, but the data stays queued (MSG_PEEK); waits for at
        least one byte under the read deadline. 0 means EOF."""
        return recv_with_deadline(self._sock, buf, MSG_PEEK, self._rd, "peek")

    def write(self, buf: Span[UInt8, _]) raises IoError -> Int:
        """Wait for buffer space and queue what fits: returns 1..len(buf)
        (0 only for an empty `buf`)."""
        return send_with_deadline(self._sock, buf, self._wr, "write")

    def write_all(self, buf: Span[UInt8, _]) raises IoError:
        """Queue all of `buf`, looping over partial writes."""
        send_all_with_deadline(self._sock, buf, self._wr, "write")

    def write_vectored[
        mut: Bool, //, o: Origin[mut=mut]
    ](self, bufs: Span[Span[UInt8, o], _]) raises IoError -> Int:
        """Gather-write `bufs` in order with one sendmsg; may be partial
        (only the first IOV_MAX buffers are used). Build `bufs` from spans
        sharing one origin, as for `Socket.send_vectored`."""
        return send_vectored_with_deadline(self._sock, bufs, self._wr, "write")

    def detect_dead_peers(
        self, keepalive: TcpKeepalive = DEAD_PEER_KEEPALIVE
    ) raises IoError:
        """Tune a connection that may sit idle for long (a database pool) to
        notice a vanished peer: keepalive probes (by default after 30 s of
        silence, every 10 s, giving up after 3) and TCP_USER_TIMEOUT of the
        same total for unacknowledged writes (see
        `net.blocking.detect_dead_peers`). A dead peer then fails the next
        read or write with `TimedOut` (ETIMEDOUT) within about a minute."""
        detect_dead_peers(self._sock, keepalive)

    def idle_state(self) -> IdleState:
        """Whether this idle stream can be reused, told without waiting or
        consuming anything (`net.blocking.IdleState`): EMPTY (reusable as
        far as can be told), DATA (bytes waiting) or CLOSED (FIN, reset or a
        pending error). A pool calls it before handing a connection out;
        with a `BufReader`, also check that nothing is buffered."""
        return idle_state(self._sock)

    def shutdown(self, how: Shutdown) raises IoError:
        """Shut down one direction or both (`NotConnected` if the stream is
        not connected).

        - `WRITE` sends FIN after the queued data (the peer reads EOF);
          reading continues.
        - `READ` discards nothing and tells the peer nothing (its writes
          keep succeeding). Linux still delivers the data already queued
          *and* data that arrives later; reads only stop waiting: whenever
          the receive queue is empty they return 0 at once. So a 0 after
          `READ` is not a real EOF: a later read may return data again, and
          `read_to_end` may stop early. To ignore the rest of the input,
          read and drop it, or close the stream.
        - `BOTH`: both of the above."""
        self._sock.shutdown(how)

    # ---- addresses -----------------------------------------------------------

    def local_addr(self) raises IoError -> SocketAddr:
        return self._sock.local_addr()

    def peer_addr(self) raises IoError -> SocketAddr:
        return self._sock.peer_addr()

    def write_to(self, mut writer: Some[Writer]):
        writer.write("TcpStream(fd=", self._sock.raw_fd(), ")")


@fieldwise_init
struct TcpAccepted(Movable):
    """What `TcpListener.accept` returns. Use the fields in place, or take
    the stream: `var peer = acc.addr; var s = acc^.into_stream()`."""

    var stream: TcpStream
    var addr: SocketAddr

    @inline(.always)
    def into_stream(deinit self) -> TcpStream:
        return self.stream^


# ---- TcpListener -------------------------------------------------------------


struct TcpListener(AsFd, Movable, Writable):
    """A listening TCP socket whose `accept` waits up to its deadline."""

    var _sock: Socket
    var _deadline: Deadline

    @inline(.always)
    def __init__(out self, *, var nonblocking_socket: Socket):
        """Wrap a listening socket that is already O_NONBLOCK."""
        self._sock = nonblocking_socket^
        self._deadline = Deadline.none()

    @staticmethod
    def bind(
        addr: SocketAddr, backlog: Int = DEFAULT_BACKLOG
    ) raises IoError -> TcpListener:
        """socket + SO_REUSEADDR + bind + listen. Port 0 picks a free port
        (read it back with `local_addr`). An IPv6 address keeps the system's
        IPV6_V6ONLY default; build the socket with L1 and use `from_socket`
        to choose."""
        var sock = Socket.new(
            Domain.for_address(addr), SockType.STREAM, nonblocking=True
        )
        sock.set_reuse_address(True)
        sock.bind(addr)
        sock.listen(backlog)
        return TcpListener(nonblocking_socket=sock^)

    @staticmethod
    def bind_reuseport(
        addr: SocketAddr, backlog: Int = DEFAULT_BACKLOG
    ) raises IoError -> TcpListener:
        """`bind` with SO_REUSEPORT too, for one listener per process (or per
        thread) on the same address: the kernel spreads new connections
        across them by a hash of the connection's addresses. Every socket
        bound to the port must set it, and all must belong to the same user
        (otherwise `AddrInUse`)."""
        var sock = Socket.new(
            Domain.for_address(addr), SockType.STREAM, nonblocking=True
        )
        sock.set_reuse_address(True)
        sock.set_reuse_port(True)
        sock.bind(addr)
        sock.listen(backlog)
        return TcpListener(nonblocking_socket=sock^)

    @staticmethod
    def from_socket(var sock: Socket) raises IoError -> TcpListener:
        """Adopt a bound, listening IP stream socket (for example one set up
        with SO_REUSEPORT, or inherited through socket activation).

        Anything but a listening AF_INET/AF_INET6 SOCK_STREAM socket raises
        `InvalidInput` (op "TcpListener.from_socket"; the socket is closed)
        here, instead of every later `accept` taking a connection and then
        failing on it. Sets FD_CLOEXEC (inherited descriptors arrive
        without it) and O_NONBLOCK."""
        return TcpListener(
            nonblocking_socket=adopt_stream_socket(
                sock^, unix=False, listener=True, op="TcpListener.from_socket"
            )
        )

    def accept(self) raises IoError -> TcpAccepted:
        """Wait (up to the accept deadline) for a connection. The stream is
        nonblocking, CLOEXEC, has TCP_NODELAY on and no deadlines.

        ECONNABORTED and EINTR retry silently; EMFILE/ENFILE raise
        `TooManyFiles` with the connection left queued; a listener that was
        shut down raises `InvalidInput` (EINVAL) (see
        `accept_with_deadline`)."""
        var peer = RawSockaddr()
        var sock = accept_with_deadline(self._sock, peer, self._deadline)
        sock.set_nodelay(True)
        return TcpAccepted(
            TcpStream(nonblocking_socket=sock^), SocketAddr.from_raw(peer)
        )

    def try_accept(self) raises IoError -> Optional[TcpAccepted]:
        """For readiness loops: accept without waiting (ignores the accept
        deadline). None when no connection is queued; with edge-triggered
        epoll, accept until None. The stream is set up as by `accept`.
        EMFILE/ENFILE raise `TooManyFiles` and leave the connection queued:
        stop accepting for a while instead of retrying at once (see
        docs/net.md)."""
        var peer = RawSockaddr()
        var sock = try_accept(self._sock, peer)
        if not sock:
            return None
        var s = sock.take()
        s.set_nodelay(True)
        return TcpAccepted(
            TcpStream(nonblocking_socket=s^), SocketAddr.from_raw(peer)
        )

    @inline(.always)
    def set_deadline(mut self, deadline: Deadline):
        """Bound every later `accept`; `Deadline.none()` removes it."""
        self._deadline = deadline

    @inline(.always)
    def deadline(self) -> Deadline:
        return self._deadline

    def local_addr(self) raises IoError -> SocketAddr:
        return self._sock.local_addr()

    @inline(.always)
    def socket(ref self) -> ref[self._sock] Socket:
        """The L1 socket, for options. Keep it O_NONBLOCK."""
        return self._sock

    @inline(.always)
    def into_socket(deinit self) -> Socket:
        return self._sock^

    @inline(.always)
    def raw_fd(self) -> Int32:
        return self._sock.raw_fd()

    def try_clone(self) raises IoError -> TcpListener:
        """A second handle to the same listener (for example one per
        thread); the clone starts with a copy of the accept deadline."""
        var l = TcpListener(nonblocking_socket=self._sock.try_clone())
        l._deadline = self._deadline
        return l^

    def close(deinit self) raises IoError:
        self._sock^.close()

    def write_to(self, mut writer: Some[Writer]):
        writer.write("TcpListener(fd=", self._sock.raw_fd(), ")")
