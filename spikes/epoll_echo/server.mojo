"""Single-threaded, edge-triggered epoll echo server: the M1 10k-connection
spike (docs/spikes.md, "10k-connection epoll spike").

It answers whether one Mojo thread on raw syscalls (no libc on the I/O path)
can hold 10k idle plus 1k busy TCP connections, and what that costs. It is
built the way M2's `rt` loop will be, so its costs carry over:

- Per-connection state lives in a slab (`List[Slot]`). A connection's epoll
  `data` is `generation << 32 | slot`, never a pointer (design contract 3).
  Freeing a slot bumps its generation, so an event still queued in the
  current `epoll_wait` batch for a closed connection is recognized as stale,
  even if an accept in the same batch reused the slot.
- Each socket is registered once with EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLET
  (as mio/tokio do). That means no epoll_ctl per message; EPOLLOUT edges
  matter only while output is queued.
- Reads go into one loop-owned 64 KiB buffer until EAGAIN. A short read
  also ends the loop: for a TCP stream it means the receive queue was empty,
  so any later data raises a new edge (tokio relies on the same fact).
  The exception is a FIN: its edge may already have been consumed (FIN
  coalesced with the last data, or delivered while reading was paused), so
  after EPOLLRDHUP/HUP/ERR the server reads until EOF or EAGAIN.
  `--strict-eagain` turns the shortcut off to measure what it saves.
- Echo sends directly. If the kernel takes only part, the rest is queued in
  the slot and the server retries until EAGAIN; EPOLLOUT finishes the job.
  Once more than `PENDING_CAP` bytes are queued, reading pauses, and TCP flow
  control pushes back on the peer. ET does not re-report data that is
  already buffered, so draining the queue resumes reading by hand.
- The accept loop runs accept4(NONBLOCK|CLOEXEC) until EAGAIN.
  EMFILE/ENFILE/ENOBUFS/ENOMEM pause accepting (logged on each transition)
  instead of spinning. Accepting resumes after a connection closes or on the
  next stats tick; pending clients wait in the kernel backlog.
- At start, RLIMIT_NOFILE is raised to the hard limit. `--nofile N` sets it to
  N instead, which is how the EMFILE path is exercised.
- `--prealloc-fds N` grows the kernel fd table to N slots at startup. Without
  it, each table doubling stalls one accept4 for an RCU grace period,
  because a Mojo process is always multi-threaded (see `prealloc_fd_table`).

Every syscall is counted, so syscalls per message come from the server
itself (this host has no strace or perf). A `STATS` line is printed per tick.

    pixi run mojo build -I src -I spikes/epoll_echo spikes/epoll_echo/server.mojo -o spikes/epoll_echo/out/server
    spikes/epoll_echo/out/server --port 7000 [--host 127.0.0.1] [--duration S]
        [--nofile N] [--max-events 1024] [--stats-ms 1000] [--backlog 4096]
        [--prealloc-fds N] [--strict-eagain] [--quiet]
"""

from std.sys import size_of

from linux import Errno, IoError, OwnedFd, RawFd, check, sys
from linux.abi import EpollEvent
from linux.consts import (
    EPOLLERR,
    EPOLLET,
    EPOLLHUP,
    EPOLLIN,
    EPOLLOUT,
    EPOLLRDHUP,
    F_GETFD,
    IPPROTO_TCP,
    MSG_NOSIGNAL,
    O_CLOEXEC,
    RLIMIT_NOFILE,
    SOCK_CLOEXEC,
    SOCK_NONBLOCK,
    TCP_NODELAY,
)
from linux.epoll import Epoll
from linux.fd import AsFd
from linux.nr import SYS_accept4
from linux.probe import Rlimit, nofile_limit, raise_nofile_limit, set_rlimit
from linux.syscall import err_of, is_err, syscall4
from linux.time import Instant, NANOS_PER_MILLI
from net.addr import Ipv4Addr, SocketAddr, SocketAddrV4
from net.socket import Domain, Socket, SockType

from echo_util import (
    LISTENER_TOKEN,
    MAX_SLOTS,
    Args,
    emit,
    getpid,
    token,
    token_gen,
    token_slot,
)

comptime READ_BUF = 64 * 1024
comptime PENDING_CAP = 256 * 1024
"""Queued, unsent bytes per connection above which reading pauses."""
comptime CONN_EVENTS = UInt32(EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET)
comptime READABLE = UInt32(EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)
comptime CLOSED_EVENTS = UInt32(EPOLLRDHUP | EPOLLHUP | EPOLLERR)
comptime CLOCK_EVERY = 64
"""Under load, read the clock once per this many waits (it is a syscall)."""


@inline(.always)
def _accept4_noaddr[F: AsFd](fd: F, flags: Int) -> Int:
    """accept4 without the peer address (NULL addr/addrlen are allowed); an
    echo server never looks at it, so skip copying 128 bytes per accept."""
    return syscall4(SYS_accept4, Int(fd.raw_fd()), 0, 0, flags)


@inline(.always)
def _is_transient_accept_error(e: Errno) -> Bool:
    """accept(2): Linux reports network errors already pending on the new
    connection through accept; treat them like EAGAIN-and-retry."""
    return (
        e == Errno.ECONNABORTED
        or e == Errno.EPROTO
        or e == Errno.ENETDOWN
        or e == Errno.ENOPROTOOPT
        or e == Errno.EHOSTDOWN
        or e == Errno.ENONET
        or e == Errno.EHOSTUNREACH
        or e == Errno.EOPNOTSUPP
        or e == Errno.ENETUNREACH
        or e == Errno.EPERM  # firewall rules
    )


@inline(.always)
def _is_fd_exhaustion(e: Errno) -> Bool:
    return (
        e == Errno.EMFILE
        or e == Errno.ENFILE
        or e == Errno.ENOBUFS
        or e == Errno.ENOMEM
    )


struct Slot(Movable):
    """One connection, 48 bytes (the flags sit in `gen`'s padding). An idle
    connection owns no heap memory: the read buffer is shared and `pending`
    is empty."""

    var gen: UInt32
    var read_paused: Bool
    var peer_eof: Bool
    """The peer half-closed while echo bytes were still queued: finish
    sending them, then close."""
    var read_closed: Bool
    """EPOLLRDHUP/HUP/ERR was reported. Sticky, as tokio's READ_CLOSED: once
    the FIN's edge has been consumed, no new edge will come, so a short read
    no longer proves that the next one would be EAGAIN (it may be EOF)."""
    var sock: Optional[OwnedFd]
    """The connection's fd; `None` while the slot is free."""
    var pending: List[UInt8]
    """Bytes read but not yet echoed (only after a partial send)."""
    var sent: Int
    """Prefix of `pending` already sent."""

    def __init__(out self):
        self.gen = 0
        self.read_paused = False
        self.peer_eof = False
        self.read_closed = False
        self.sock = None
        self.pending = List[UInt8]()
        self.sent = 0


struct Stats(Copyable, Movable):
    """Syscall and traffic counters (all cumulative)."""

    var waits: Int
    var events: Int
    var accept_calls: Int
    var accepted: Int
    var accept_exhausted: Int
    var recvs: Int
    var recv_eagain: Int
    var sends: Int
    var send_eagain: Int
    var send_partial: Int
    var ctls: Int
    var setsockopts: Int
    var closes: Int
    var clock_reads: Int
    var eintr: Int
    var stale: Int
    var resets: Int
    var bytes_in: Int
    var bytes_out: Int
    var pauses: Int

    def __init__(out self):
        self.waits = 0
        self.events = 0
        self.accept_calls = 0
        self.accepted = 0
        self.accept_exhausted = 0
        self.recvs = 0
        self.recv_eagain = 0
        self.sends = 0
        self.send_eagain = 0
        self.send_partial = 0
        self.ctls = 0
        self.setsockopts = 0
        self.closes = 0
        self.clock_reads = 0
        self.eintr = 0
        self.stale = 0
        self.resets = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.pauses = 0

    def syscalls(self) -> Int:
        return (
            self.waits
            + self.accept_calls
            + self.recvs
            + self.sends
            + self.ctls
            + self.setsockopts
            + self.closes
            + self.clock_reads
        )


struct Server(Movable):
    var ep: Epoll
    var listener: Socket
    var slots: List[Slot]
    var free: List[Int]
    var open: Int
    var buf: List[UInt8]
    var stats: Stats
    var strict_eagain: Bool
    var accept_paused: Bool
    var retry_accept: Bool

    def __init__(
        out self, var ep: Epoll, var listener: Socket, strict_eagain: Bool
    ):
        self.ep = ep^
        self.listener = listener^
        self.slots = List[Slot]()
        self.free = List[Int]()
        self.open = 0
        self.buf = List[UInt8](length=READ_BUF, fill=0)
        self.stats = Stats()
        self.strict_eagain = strict_eagain
        self.accept_paused = False
        self.retry_accept = False

    # ---- accept --------------------------------------------------------------

    def _alloc_slot(mut self) -> Int:
        if len(self.free) > 0:
            return self.free.pop()
        self.slots.append(Slot())
        return len(self.slots) - 1

    def accept_all(mut self) raises IoError:
        """Accept until EAGAIN (ET listener: anything left now would never be
        reported again until another connection arrives)."""
        while True:
            var r = _accept4_noaddr(
                self.listener, SOCK_NONBLOCK | SOCK_CLOEXEC
            )
            self.stats.accept_calls += 1
            if is_err(r):
                var e = Errno(err_of(r))
                if e == Errno.EAGAIN:
                    if self.accept_paused:
                        self.accept_paused = False
                        emit(String("accept: resumed, open=", self.open))
                    return
                if e == Errno.EINTR:
                    self.stats.eintr += 1
                    continue
                if _is_transient_accept_error(e):
                    continue
                if _is_fd_exhaustion(e):
                    self.stats.accept_exhausted += 1
                    if not self.accept_paused:
                        self.accept_paused = True
                        emit(
                            String(
                                "accept: ",
                                e,
                                ", pausing accepts (open=",
                                self.open,
                                ")",
                            )
                        )
                    return
                raise IoError.from_errno("accept4", e)
            if len(self.slots) >= MAX_SLOTS and len(self.free) == 0:
                _ = sys.close(Int32(r))
                self.stats.closes += 1
                continue
            var fd = OwnedFd(unsafe_from_raw=Int32(r))
            # Latency over Nagle for a request/response protocol; failure is
            # harmless (the connection still works).
            var one: Int32 = 1
            _ = sys.setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, one, 4)
            self.stats.setsockopts += 1
            var idx = self._alloc_slot()
            var t = token(idx, self.slots[idx].gen)
            self.stats.ctls += 1
            try:
                self.ep.add(fd, CONN_EVENTS, t)
            except e:
                # ENOMEM / ENOSPC (fs.epoll.max_user_watches): drop this one
                # connection (fd closes here) and keep serving the rest.
                emit(String("epoll_ctl(ADD): ", e))
                self.free.append(idx)
                self.stats.closes += 1
                continue
            self.slots[idx].sock = fd^
            self.open += 1
            self.stats.accepted += 1

    # ---- per-connection I/O --------------------------------------------------

    def close_slot(mut self, idx: Int):
        """EPOLL_CTL_DEL, then close (design contract 5); bump the generation
        so queued events for this connection become stale."""
        var fd = self.slots[idx].sock.take()
        try:
            self.ep.delete(fd)
        except:
            pass
        self.stats.ctls += 1
        try:
            fd^.close()
        except:
            pass
        self.stats.closes += 1
        self.slots[idx].gen += 1
        self.slots[idx].pending = List[UInt8]()
        self.slots[idx].sent = 0
        self.slots[idx].read_paused = False
        self.slots[idx].peer_eof = False
        self.slots[idx].read_closed = False
        self.free.append(idx)
        self.open -= 1
        if self.accept_paused:
            self.retry_accept = True

    def on_readable(mut self, idx: Int):
        """Read until EAGAIN (or a short read), echoing each chunk."""
        while True:
            if len(self.slots[idx].pending) - self.slots[idx].sent >= PENDING_CAP:
                if not self.slots[idx].read_paused:
                    self.slots[idx].read_paused = True
                    self.stats.pauses += 1
                return
            var r = sys.recv(self.slots[idx].sock.value(), Span(self.buf), 0)
            self.stats.recvs += 1
            if is_err(r):
                var e = Errno(err_of(r))
                if e == Errno.EAGAIN:
                    self.stats.recv_eagain += 1
                    return
                if e == Errno.EINTR:
                    self.stats.eintr += 1
                    continue
                self.stats.resets += 1
                self.close_slot(idx)
                return
            if r == 0:  # orderly EOF (the peer may still be reading)
                if len(self.slots[idx].pending) > self.slots[idx].sent:
                    self.slots[idx].peer_eof = True
                else:
                    self.close_slot(idx)
                return
            self.stats.bytes_in += r
            if not self.echo(idx, r):
                return
            if (
                r < READ_BUF
                and not self.strict_eagain
                and not self.slots[idx].read_closed
            ):
                return

    def echo(mut self, idx: Int, n: Int) -> Bool:
        """Send `buf[:n]` back. False if the connection was closed."""
        if len(self.slots[idx].pending) > self.slots[idx].sent:
            # Older bytes are still queued: keep order, queue behind them.
            # Drop the sent prefix once it is most of the queue, so a peer
            # that keeps reading slowly cannot grow it without bound (the
            # cap only counts unsent bytes). Amortized O(1) per byte.
            ref s = self.slots[idx]
            if s.sent >= 4096 and 2 * s.sent >= len(s.pending):
                var rest = List[UInt8](capacity=len(s.pending) - s.sent + n)
                rest.extend(Span(s.pending)[s.sent :])
                s.pending = rest^
                s.sent = 0
            s.pending.extend(Span(self.buf)[0:n])
            return True
        var off = 0
        while off < n:
            var r = sys.send(
                self.slots[idx].sock.value(),
                Span(self.buf)[off:n],
                MSG_NOSIGNAL,
            )
            self.stats.sends += 1
            if is_err(r):
                var e = Errno(err_of(r))
                if e == Errno.EINTR:
                    self.stats.eintr += 1
                    continue
                if e == Errno.EAGAIN:
                    self.stats.send_eagain += 1
                    break
                self.stats.resets += 1
                self.close_slot(idx)
                return False
            self.stats.bytes_out += r
            off += r
            if off < n:
                # Retry until EAGAIN: only EAGAIN guarantees an EPOLLOUT edge.
                self.stats.send_partial += 1
        if off < n:
            self.slots[idx].pending.clear()
            self.slots[idx].pending.extend(Span(self.buf)[off:n])
            self.slots[idx].sent = 0
        return True

    def flush(mut self, idx: Int) -> Bool:
        """Send queued bytes after EPOLLOUT. False if the connection closed."""
        while self.slots[idx].sent < len(self.slots[idx].pending):
            var r = sys.send(
                self.slots[idx].sock.value(),
                Span(self.slots[idx].pending)[self.slots[idx].sent :],
                MSG_NOSIGNAL,
            )
            self.stats.sends += 1
            if is_err(r):
                var e = Errno(err_of(r))
                if e == Errno.EINTR:
                    self.stats.eintr += 1
                    continue
                if e == Errno.EAGAIN:
                    self.stats.send_eagain += 1
                    return True
                self.stats.resets += 1
                self.close_slot(idx)
                return False
            self.stats.bytes_out += r
            self.slots[idx].sent += r
        # Drained: give the memory back (idle connections hold none).
        self.slots[idx].pending = List[UInt8]()
        self.slots[idx].sent = 0
        if self.slots[idx].peer_eof:
            self.close_slot(idx)
            return False
        if self.slots[idx].read_paused:
            # ET will not report data that was already buffered.
            self.slots[idx].read_paused = False
            self.on_readable(idx)
        return self.slots[idx].sock is not None

    def on_event(mut self, idx: Int, ev: UInt32):
        # Record a FIN/RST even if reading is paused: its edge is now
        # consumed, and the resumed reads must run to EOF/EAGAIN.
        if (ev & CLOSED_EVENTS) != 0:
            self.slots[idx].read_closed = True
        if (ev & UInt32(EPOLLOUT)) != 0 and len(self.slots[idx].pending) > 0:
            if not self.flush(idx):
                return
        if (
            (ev & READABLE) != 0
            and not self.slots[idx].read_paused
            and not self.slots[idx].peer_eof
        ):
            self.on_readable(idx)

    # ---- loop ----------------------------------------------------------------

    def print_stats(self, tag: StaticString, now: Instant):
        ref s = self.stats
        emit(
            String(
                tag,
                " mono_ns=",
                now.as_nanos(),
                " open=",
                self.open,
                " slots=",
                len(self.slots),
                " accepted=",
                s.accepted,
                " closes=",
                s.closes,
                " waits=",
                s.waits,
                " events=",
                s.events,
                " recvs=",
                s.recvs,
                " recv_eagain=",
                s.recv_eagain,
                " sends=",
                s.sends,
                " send_eagain=",
                s.send_eagain,
                " send_partial=",
                s.send_partial,
                " accept_calls=",
                s.accept_calls,
                " accept_exhausted=",
                s.accept_exhausted,
                " ctls=",
                s.ctls,
                " setsockopts=",
                s.setsockopts,
                " clock_reads=",
                s.clock_reads,
                " syscalls=",
                s.syscalls(),
                " eintr=",
                s.eintr,
                " stale=",
                s.stale,
                " resets=",
                s.resets,
                " pauses=",
                s.pauses,
                " bytes_in=",
                s.bytes_in,
                " bytes_out=",
                s.bytes_out,
            )
        )

    def run(
        mut self, max_events: Int, tick_ns: Int, duration_ns: Int, quiet: Bool
    ) raises IoError:
        var events = List[EpollEvent](capacity=max_events)
        var start = Instant.now()
        self.stats.clock_reads += 1
        var next_tick = start.as_nanos() + tick_ns
        var iter = 0
        while True:
            var n = self.ep.wait(events, tick_ns)
            self.stats.waits += 1
            self.stats.events += n
            for i in range(n):
                var data = events[i].data()
                if data == LISTENER_TOKEN:
                    self.accept_all()
                    continue
                var idx = token_slot(data)
                if (
                    idx >= len(self.slots)
                    or self.slots[idx].gen != token_gen(data)
                    or not self.slots[idx].sock
                ):
                    self.stats.stale += 1
                    continue
                self.on_event(idx, events[i].events())
            if self.retry_accept:
                self.retry_accept = False
                self.accept_all()
            iter += 1
            if n == 0 or iter % CLOCK_EVERY == 0:
                var now = Instant.now()
                self.stats.clock_reads += 1
                if now.as_nanos() >= next_tick:
                    next_tick = now.as_nanos() + tick_ns
                    if self.accept_paused:
                        self.accept_all()
                    if not quiet:
                        self.print_stats("STATS", now)
                if duration_ns > 0 and (now - start).as_nanos() >= duration_ns:
                    self.print_stats("FINAL", now)
                    return


def prealloc_fd_table(listener: Socket, size: Int):
    """Grow the kernel fd table to `size` entries now, not in accept4.

    The table doubles when an fd number reaches its size (64, 128, ...,
    8192). In a multi-threaded process, which every Mojo process is (the
    runtime starts its worker threads before `main`), each doubling waits
    for an RCU grace period (`synchronize_rcu` in fs/file.c
    `expand_fdtable`). That stalled accept4 for 17-47 ms per doubling here,
    long enough for a connect burst to overflow the accept queue. The table
    never shrinks, so one dup3 to the top slot pays that once, at startup.
    """
    var top = size - 1
    if top < 64:
        return
    if not is_err(sys.fcntl(RawFd(Int32(top)), F_GETFD)):
        emit(String("prealloc-fds: fd ", top, " is in use; skipped"))
        return
    var t0 = Instant.now()
    var r = sys.dup3(listener, Int32(top), O_CLOEXEC)
    if is_err(r):
        emit(String("prealloc-fds: dup3 failed: ", Errno(err_of(r))))
        return
    _ = sys.close(Int32(top))
    emit(
        String(
            "prealloc-fds: fd table grown to ",
            size,
            " in ",
            (Instant.now() - t0).as_micros(),
            " us",
        )
    )


def main() raises:
    var args = Args()
    args.validate(
        [
            "--host",
            "--port",
            "--duration",
            "--nofile",
            "--max-events",
            "--stats-ms",
            "--backlog",
            "--prealloc-fds",
        ],
        ["--strict-eagain", "--quiet"],
    )
    var host = args.string("--host", "127.0.0.1")
    var port = args.int("--port", 0)
    var duration_s = args.int("--duration", 0)
    var nofile = args.int("--nofile", 0)
    var max_events = args.int("--max-events", 1024)
    var stats_ms = args.int("--stats-ms", 1000)
    var backlog = args.int("--backlog", 4096)
    var prealloc = args.int("--prealloc-fds", 0)
    if port < 0 or port > 65535:
        raise Error("--port out of range")
    if max_events < 1 or stats_ms < 1 or duration_s < 0 or nofile < 0:
        raise Error("--max-events/--stats-ms must be >= 1, --duration/--nofile >= 0")

    # fd budget: raise to the hard limit, or pin it low to test EMFILE.
    var lim = nofile_limit()
    var soft: UInt64
    if nofile > 0:
        set_rlimit(RLIMIT_NOFILE, Rlimit(UInt64(nofile), lim.max))
        soft = UInt64(nofile)
    else:
        soft = raise_nofile_limit(lim.max)

    var listener = Socket.new(Domain.IPV4, SockType.STREAM, nonblocking=True)
    listener.set_reuse_address(True)
    var addr = SocketAddr(SocketAddrV4(Ipv4Addr.parse(host), UInt16(port)))
    listener.bind(addr)
    listener.listen(backlog)
    var bound = listener.local_addr()
    if prealloc > 0:
        prealloc_fd_table(listener, min(prealloc, Int(soft)))

    var ep = Epoll.new()
    ep.add(listener, UInt32(EPOLLIN | EPOLLET), LISTENER_TOKEN)

    emit(
        String(
            "LISTEN ",
            bound,
            " pid=",
            getpid(),
            " nofile_soft=",
            soft,
            " nofile_hard=",
            lim.max,
            " strict_eagain=",
            args.flag("--strict-eagain"),
            " slot_bytes=",
            size_of[Slot](),
        )
    )
    var server = Server(ep^, listener^, args.flag("--strict-eagain"))
    server.run(
        max_events,
        stats_ms * NANOS_PER_MILLI,
        duration_s * 1_000_000_000,
        args.flag("--quiet"),
    )
