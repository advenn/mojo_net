"""Single-threaded epoll load generator for the echo spike (docs/spikes.md,
"10k-connection epoll spike").

It opens `--idle` connections that never send and `--active` connections
that ping-pong one `--size`-byte message at a time for `--duration` seconds.
It reports connections established, messages/s, and round-trip latency
percentiles.

- Connects are nonblocking, with at most `--window` handshakes in flight, so
  the server's accept queue (somaxconn) never overflows and turns into 1 s
  SYN retransmits.
- RTT is measured per message on CLOCK_MONOTONIC (`linux.time.Instant`, a raw
  syscall). The clock is read once per completed echo, and that reading is
  also the send time of the next message, so the cost is one clock syscall
  per message.
- Every echo is checked: the 8-byte sequence number at the front, the
  pattern byte at the end, and no bytes beyond the message.
- `--start-at-ns T` (CLOCK_MONOTONIC) starts the load at T. Several client
  processes then measure the same window, and bench.py merges their HIST
  lines.
- At the end it closes with SO_LINGER {on, 0} (RST) by default. Repeated
  11k-connection runs then leave no TIME_WAIT sockets holding ephemeral
  ports; `--graceful` closes with FIN instead.

    spikes/epoll_echo/out/client --port 7000 --idle 10000 --active 1000
        --size 64 --duration 10 [--host 127.0.0.1] [--window 256]
        [--start-at-ns T] [--hold S] [--connect-timeout S] [--tag name]
        [--graceful]
"""

from std.sys import size_of

from linux import Errno, IoError, OwnedFd, check, sys
from linux.abi import EpollEvent, Linger
from linux.consts import (
    AF_INET,
    EPOLLERR,
    EPOLLET,
    EPOLLHUP,
    EPOLLIN,
    EPOLLOUT,
    EPOLLRDHUP,
    IPPROTO_TCP,
    MSG_NOSIGNAL,
    SO_ERROR,
    SO_LINGER,
    SOCK_CLOEXEC,
    SOCK_NONBLOCK,
    SOCK_STREAM,
    SOL_SOCKET,
    TCP_NODELAY,
)
from linux.epoll import Epoll
from linux.probe import nofile_limit, raise_nofile_limit
from linux.syscall import err_of, is_err
from linux.time import Instant, NANOS_PER_MILLI, NANOS_PER_SEC
from net.addr import Ipv4Addr, RawSockaddr, SocketAddr, SocketAddrV4

from echo_util import Args, Hist, emit

comptime CONNECTING: UInt8 = 0
comptime ESTABLISHED: UInt8 = 1
comptime CLOSED: UInt8 = 2

comptime EVENTS = UInt32(EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET)
comptime READABLE = UInt32(EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)
comptime WRITABLE = UInt32(EPOLLOUT | EPOLLHUP | EPOLLERR)
comptime READ_BUF = 64 * 1024


@inline(.always)
def _expected(seq: UInt64, k: Int, size: Int) -> UInt8:
    """Byte `k` of message `seq`: the sequence number (little endian) in the
    first 8 bytes, a seq-dependent pattern after."""
    if k < 8 and k < size:
        return UInt8((seq >> UInt64(8 * k)) & 0xFF)
    return UInt8((seq + UInt64(k)) & 0xFF)


struct Conn(Movable):
    var sock: Optional[OwnedFd]
    var state: UInt8
    var active: Bool
    var running: Bool
    """Has a message in flight (active connections during the load)."""
    var seq: UInt64
    var sent_at: Int
    var out_off: Int
    var got: Int

    def __init__(out self, var fd: OwnedFd, active: Bool):
        self.sock = fd^
        self.state = CONNECTING
        self.active = active
        self.running = False
        self.seq = 0
        self.sent_at = 0
        self.out_off = 0
        self.got = 0


struct Client(Movable):
    var ep: Epoll
    var conns: List[Conn]
    var raw: RawSockaddr
    var size: Int
    var msg: List[UInt8]
    var buf: List[UInt8]
    var hist: Hist
    # outcome counters
    var established: Int
    var connect_failed: Int
    var first_connect_error: Errno
    var inflight: Int
    var msgs: Int
    var mismatches: Int
    var resets: Int
    var idle_lost: Int
    var eintr: Int
    var waits: Int
    var recvs: Int
    var sends: Int
    var clock_reads: Int
    var end_ns: Int
    var running: Int

    def __init__(out self, var ep: Epoll, var raw: RawSockaddr, size: Int):
        self.ep = ep^
        self.conns = List[Conn]()
        self.raw = raw^
        self.size = size
        self.msg = List[UInt8](length=size, fill=0)
        self.buf = List[UInt8](length=READ_BUF, fill=0)
        self.hist = Hist()
        self.established = 0
        self.connect_failed = 0
        self.first_connect_error = Errno(0)
        self.inflight = 0
        self.msgs = 0
        self.mismatches = 0
        self.resets = 0
        self.idle_lost = 0
        self.eintr = 0
        self.waits = 0
        self.recvs = 0
        self.sends = 0
        self.clock_reads = 0
        self.end_ns = 0
        self.running = 0

    @inline(.always)
    def now(mut self) -> Int:
        self.clock_reads += 1
        return Instant.now().as_nanos()

    def _fail_connect(mut self, e: Errno):
        self.connect_failed += 1
        if self.first_connect_error.value == 0:
            self.first_connect_error = e

    # ---- connect phase ---------------------------------------------------------

    def start_connect(mut self, active: Bool) raises IoError:
        var r = sys.socket(
            AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0
        )
        if is_err(r):
            self._fail_connect(Errno(err_of(r)))
            return
        var fd = OwnedFd(unsafe_from_raw=Int32(r))
        var one: Int32 = 1
        _ = sys.setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, one, 4)
        var c = sys.connect(fd, self.raw.storage, self.raw.socklen())
        if is_err(c) and Errno(err_of(c)) == Errno.EINTR:
            # An interrupted connect continues in the kernel: wait for
            # EPOLLOUT exactly as for EINPROGRESS (never call it again).
            self.eintr += 1
            c = -Int(Errno.EINPROGRESS.value)
        if is_err(c) and Errno(err_of(c)) != Errno.EINPROGRESS:
            self._fail_connect(Errno(err_of(c)))
            return
        var idx = len(self.conns)
        self.ep.add(fd, EVENTS, UInt64(idx))
        self.conns.append(Conn(fd^, active))
        if c == 0:
            self.conns[idx].state = ESTABLISHED
            self.established += 1
        else:
            self.inflight += 1

    def finish_connect(mut self, idx: Int):
        """EPOLLOUT/ERR/HUP on a connecting socket: SO_ERROR says how the
        handshake ended."""
        var err: Int32 = 0
        var len: UInt32 = 4
        var r = sys.getsockopt(
            self.conns[idx].sock.value(), SOL_SOCKET, SO_ERROR, err, len
        )
        self.inflight -= 1
        if is_err(r):
            self._fail_connect(Errno(err_of(r)))
            self.close_conn(idx)
        elif err != 0:
            self._fail_connect(Errno(err))
            self.close_conn(idx)
        else:
            self.conns[idx].state = ESTABLISHED
            self.established += 1

    def close_conn(mut self, idx: Int):
        if self.conns[idx].state == CLOSED:
            return
        if self.conns[idx].running:
            self.running -= 1
            self.conns[idx].running = False
        self.conns[idx].state = CLOSED
        var fd = self.conns[idx].sock.take()
        try:
            self.ep.delete(fd)
        except:
            pass
        # Dropping `fd` closes it.

    def connect_all(
        mut self, idle: Int, active: Int, window: Int, timeout_ns: Int
    ) raises IoError -> Int:
        """Open idle+active connections; return the elapsed nanoseconds."""
        var total = idle + active
        var events = List[EpollEvent](capacity=1024)
        var t0 = self.now()
        var started = 0
        var assigned = 0
        # Active connections are spread over the whole range (every
        # `stride`-th), so a failure late in the connect phase does not hit
        # only one kind.
        var stride = max(1, total // max(1, active))
        while self.established + self.connect_failed < total:
            while self.inflight < window and started < total:
                var is_active = assigned < active and started % stride == 0
                if is_active:
                    assigned += 1
                self.start_connect(is_active)
                started += 1
            var n = self.ep.wait(events, 100 * NANOS_PER_MILLI)
            self.waits += 1
            for i in range(n):
                var idx = Int(events[i].data())
                var ev = events[i].events()
                if self.conns[idx].state == CONNECTING:
                    if (ev & WRITABLE) != 0:
                        self.finish_connect(idx)
                elif self.conns[idx].state == ESTABLISHED and (ev & READABLE) != 0:
                    self.on_unexpected(idx)
            if self.now() - t0 > timeout_ns:
                emit("connect phase timed out")
                break
        return self.now() - t0

    def on_unexpected(mut self, idx: Int):
        """Readable while no reply is due: the server closed or reset the
        connection (or echoed something nobody sent)."""
        var r = sys.recv(self.conns[idx].sock.value(), Span(self.buf), 0)
        self.recvs += 1
        if is_err(r) and Errno(err_of(r)) == Errno.EAGAIN:
            return
        if r > 0:
            self.mismatches += 1
            return
        if self.conns[idx].active:
            self.resets += 1
        else:
            self.idle_lost += 1
        self.close_conn(idx)

    # ---- load phase ------------------------------------------------------------

    def fill_msg(mut self, seq: UInt64):
        """Only the 8 sequence bytes and the last byte are checked, so only
        those are rewritten per message."""
        for k in range(min(8, self.size)):
            self.msg[k] = _expected(seq, k, self.size)
        self.msg[self.size - 1] = _expected(seq, self.size - 1, self.size)

    def send_msg(mut self, idx: Int):
        """Send (the rest of) the current request; EAGAIN waits for EPOLLOUT."""
        self.fill_msg(self.conns[idx].seq)
        while self.conns[idx].out_off < self.size:
            var r = sys.send(
                self.conns[idx].sock.value(),
                Span(self.msg)[self.conns[idx].out_off :],
                MSG_NOSIGNAL,
            )
            self.sends += 1
            if is_err(r):
                var e = Errno(err_of(r))
                if e == Errno.EINTR:
                    self.eintr += 1
                    continue
                if e == Errno.EAGAIN:
                    return
                self.resets += 1
                self.close_conn(idx)
                return
            self.conns[idx].out_off += r

    def start_msg(mut self, idx: Int, now: Int):
        self.conns[idx].sent_at = now
        self.conns[idx].out_off = 0
        self.conns[idx].got = 0
        self.send_msg(idx)

    def check_chunk(mut self, idx: Int, n: Int) -> Bool:
        """Check the bytes of `buf[:n]` that carry the sequence number or the
        end marker. False on a mismatch."""
        var base = self.conns[idx].got
        var seq = self.conns[idx].seq
        for k in range(base, min(base + n, 8)):
            if self.buf[k - base] != _expected(seq, k, self.size):
                return False
        var last = self.size - 1
        if last >= base and last < base + n:
            if self.buf[last - base] != _expected(seq, last, self.size):
                return False
        return True

    def on_reply(mut self, idx: Int):
        """Read until EAGAIN or a short read; complete the message when all
        `size` bytes are back, then send the next one."""
        while self.conns[idx].state == ESTABLISHED:
            var r = sys.recv(self.conns[idx].sock.value(), Span(self.buf), 0)
            self.recvs += 1
            if is_err(r):
                var e = Errno(err_of(r))
                if e == Errno.EAGAIN:
                    return
                if e == Errno.EINTR:
                    self.eintr += 1
                    continue
                self.resets += 1
                self.close_conn(idx)
                return
            if r == 0:
                self.resets += 1
                self.close_conn(idx)
                return
            if (
                not self.conns[idx].running
                or self.conns[idx].got + r > self.size
                or not self.check_chunk(idx, r)
            ):
                self.mismatches += 1
                self.close_conn(idx)
                return
            self.conns[idx].got += r
            if self.conns[idx].got == self.size:
                var now = self.now()
                if now <= self.end_ns:
                    self.hist.record(now - self.conns[idx].sent_at)
                    self.msgs += 1
                self.conns[idx].seq += 1
                if now < self.end_ns:
                    self.start_msg(idx, now)
                else:
                    self.conns[idx].running = False
                    self.running -= 1
                return  # a reply is never followed by more bytes
            if r < READ_BUF:
                return

    def run_load(mut self, start_ns: Int, duration_ns: Int) raises IoError:
        var events = List[EpollEvent](capacity=1024)
        # Wait for the common start time (several client processes).
        while True:
            var now = self.now()
            if now >= start_ns:
                break
            _ = self.ep.wait(events, min(start_ns - now, 50 * NANOS_PER_MILLI))
            self.waits += 1
            for i in range(len(events)):
                var idx = Int(events[i].data())
                if (events[i].events() & READABLE) != 0 and self.conns[idx].state == ESTABLISHED:
                    self.on_unexpected(idx)
        var t0 = self.now()
        self.end_ns = t0 + duration_ns
        for i in range(len(self.conns)):
            if self.conns[i].active and self.conns[i].state == ESTABLISHED:
                self.conns[i].running = True
                self.running += 1
                self.start_msg(i, t0)
        # Run until the end, then let in-flight replies land (not counted).
        var drain_until = self.end_ns + NANOS_PER_SEC
        while True:
            var now = self.now()
            if now >= drain_until or (now >= self.end_ns and self.running == 0):
                break
            var n = self.ep.wait(events, 100 * NANOS_PER_MILLI)
            self.waits += 1
            for i in range(n):
                var idx = Int(events[i].data())
                var ev = events[i].events()
                if self.conns[idx].state != ESTABLISHED:
                    continue
                if not self.conns[idx].running:
                    if (ev & READABLE) != 0:
                        self.on_unexpected(idx)
                    continue
                if (ev & UInt32(EPOLLOUT)) != 0 and self.conns[idx].out_off < self.size:
                    self.send_msg(idx)
                    if self.conns[idx].state != ESTABLISHED:
                        continue
                if (ev & READABLE) != 0:
                    self.on_reply(idx)

    def hold(mut self, hold_ns: Int) raises IoError:
        """Keep every connection open (for the server's RSS reading)."""
        var events = List[EpollEvent](capacity=1024)
        var until = self.now() + hold_ns
        while True:
            var now = self.now()
            if now >= until:
                return
            _ = self.ep.wait(events, until - now)
            self.waits += 1
            for i in range(len(events)):
                var idx = Int(events[i].data())
                if (events[i].events() & READABLE) != 0 and self.conns[idx].state == ESTABLISHED:
                    self.on_unexpected(idx)

    def close_all(mut self, graceful: Bool):
        var lg = Linger(1, 0)
        for i in range(len(self.conns)):
            if self.conns[i].state == CLOSED:
                continue
            if not graceful:
                _ = sys.setsockopt(
                    self.conns[i].sock.value(), SOL_SOCKET, SO_LINGER, lg, size_of[Linger]()
                )
            self.close_conn(i)
        sys.keep_alive(lg)


def main() raises:
    var args = Args()
    args.validate(
        [
            "--host",
            "--port",
            "--idle",
            "--active",
            "--size",
            "--duration",
            "--window",
            "--start-at-ns",
            "--hold",
            "--connect-timeout",
            "--tag",
        ],
        ["--graceful"],
    )
    var host = args.string("--host", "127.0.0.1")
    var port = args.int("--port", 0)
    var idle = args.int("--idle", 0)
    var active = args.int("--active", 1)
    var size = args.int("--size", 64)
    var duration_s = args.int("--duration", 10)
    var window = args.int("--window", 256)
    var start_at = args.int("--start-at-ns", 0)
    var hold_s = args.int("--hold", 0)
    var connect_timeout_s = args.int("--connect-timeout", 30)
    var tag = args.string("--tag", "client")
    if port <= 0 or port > 65535:
        raise Error("--port is required (1..65535)")
    if idle < 0 or active < 0 or idle + active == 0:
        raise Error("--idle/--active must be >= 0 and not both 0")
    if size < 1 or size > 1 << 20:
        raise Error("--size must be 1..1048576")
    if duration_s < 1 or window < 1 or hold_s < 0 or connect_timeout_s < 1:
        raise Error("--duration/--window/--connect-timeout >= 1, --hold >= 0")

    var lim = nofile_limit()
    var soft = raise_nofile_limit(lim.max)
    if Int(soft) < idle + active + 16:
        emit(
            String(
                "warning: RLIMIT_NOFILE soft=",
                soft,
                " < connections; expect EMFILE",
            )
        )

    var addr = SocketAddr(SocketAddrV4(Ipv4Addr.parse(host), UInt16(port)))
    var client = Client(Epoll.new(), addr.to_raw(), size)
    var connect_ns = client.connect_all(
        idle, active, window, connect_timeout_s * NANOS_PER_SEC
    )
    emit(
        String(
            "CONNECTED tag=",
            tag,
            " established=",
            client.established,
            " failed=",
            client.connect_failed,
            " first_error=",
            client.first_connect_error,
            " connect_ms=",
            connect_ns // NANOS_PER_MILLI,
        )
    )
    var duration_ns = duration_s * NANOS_PER_SEC
    client.run_load(start_at, duration_ns)
    var actual_ns = duration_ns
    if hold_s > 0:
        client.hold(hold_s * NANOS_PER_SEC)

    var still_open = 0
    for i in range(len(client.conns)):
        if client.conns[i].state == ESTABLISHED:
            still_open += 1
    ref h = client.hist
    var mps = client.msgs * NANOS_PER_SEC // actual_ns
    emit(
        String(
            "RESULT tag=",
            tag,
            " target=",
            idle + active,
            " established=",
            client.established,
            " connect_failed=",
            client.connect_failed,
            " connect_ms=",
            connect_ns // NANOS_PER_MILLI,
            " still_open=",
            still_open,
            " idle=",
            idle,
            " active=",
            active,
            " size=",
            size,
            " duration_ms=",
            actual_ns // NANOS_PER_MILLI,
            " msgs=",
            client.msgs,
            " msgs_per_s=",
            mps,
            " mib_per_s=",
            mps * size * 2 // (1 << 20),
            " p50_ns=",
            h.percentile(50.0),
            " p90_ns=",
            h.percentile(90.0),
            " p99_ns=",
            h.percentile(99.0),
            " p999_ns=",
            h.percentile(99.9),
            " max_ns=",
            h.max,
            " mean_ns=",
            h.sum // max(1, h.total),
            " mismatches=",
            client.mismatches,
            " resets=",
            client.resets,
            " idle_lost=",
            client.idle_lost,
            " eintr=",
            client.eintr,
            " waits=",
            client.waits,
            " recvs=",
            client.recvs,
            " sends=",
            client.sends,
            " clock_reads=",
            client.clock_reads,
        )
    )
    var hist_line = String("HIST tag=", tag, " ")
    h.write_buckets(hist_line)
    emit(hist_line^)
    client.close_all(args.flag("--graceful"))
