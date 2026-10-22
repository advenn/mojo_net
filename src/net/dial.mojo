"""Connecting by host name with Happy Eyeballs v2 (RFC 8305), on top of the
resolver's incremental `Lookup`.

    var conn = TcpStream.connect_host("db.internal", 5432, Duration.from_secs(5))

How `dial_tcp` connects:
- **Resolution and connecting overlap.** The A and AAAA queries run while
  connections start. An AAAA answer starts IPv6 attempts at once; an A
  answer that arrives first waits at most `RESOLUTION_DELAY` (50 ms) for
  AAAA (section 3). Answers that arrive later join the queue.
- **Order.** Each family is sorted by RFC 6724's policy table (answer
  order among equals), the first attempt goes to the family that ranks
  first (IPv6, unless its best address is ULA, 6to4, Teredo, ...), and
  then the families alternate (section 4).
- **Racing.** A new attempt starts every `ATTEMPT_DELAY` (250 ms) while no
  attempt has connected, and at once when one fails (section 5). Attempts
  run in parallel; the first to connect wins and the others are closed.
- **One deadline** bounds resolving and connecting together. Expiry raises
  `TimedOut` (op "connect", errno 0: `is_deadline()`).
- **Failure.** When every address has failed and nothing more can come,
  the error of the first attempt that reached the network (refused, reset,
  a kernel timeout) is raised; only if none did, the first error (no route,
  IPv6 disabled, ...). A failed lookup raises its own error (op "resolve").

IP literals connect directly, including bracketed (`[::1]`) and zoned
(`fe80::1%eth0`) IPv6 ones. `HostPort` splits `host:port` text the way
URLs and Go's `net.SplitHostPort` do.

This module does not import `rt` (blocking layer).
"""

from linux import ErrorKind, IoError, sys
from linux.abi import Pollfd
from linux.consts import POLLERR, POLLHUP, POLLOUT
from linux.errno import Errno
from linux.poll import poll_until
from linux.syscall import err_of, is_err
from linux.time import Deadline, Duration, Instant

from .addr import IpAddr, SocketAddr, SocketAddrV6
from .blocking import connect_with_deadline
from .dns import TYPE_AAAA
from .resolver import Lookup, Resolver, precedence
from .socket import Domain, SockType, Socket

comptime ATTEMPT_DELAY = Duration.from_millis(250)
"""RFC 8305's recommended Connection Attempt Delay."""
comptime RESOLUTION_DELAY = Duration.from_millis(50)
"""RFC 8305's recommended Resolution Delay."""


# ---- host:port ---------------------------------------------------------------


struct HostPort(Copyable, Movable, Writable):
    """A host (name or IP literal) and a port, as in `db.internal:5432`,
    `127.0.0.1:80` or `[::1]:443`."""

    var host: String
    """Without brackets: `::1`, not `[::1]`."""
    var port: UInt16

    def __init__(out self, var host: String, port: UInt16):
        self.host = host^
        self.port = port

    @staticmethod
    def parse(text: StringSlice) raises IoError -> HostPort:
        """Split `host:port`. An IPv6 literal must be bracketed (`[::1]:80`).
        `InvalidInput` (op "HostPort.parse") for a missing host or port, a
        port that is not a decimal 0..65535, a colon in an unbracketed
        host, a bracket inside the host, or anything after the closing
        bracket but `:port`."""
        var b = text.as_bytes()
        var n = len(b)
        var colon: Int
        var host_start: Int
        var host_end: Int
        if n > 0 and b[0] == 91:  # '['
            var close = -1
            for i in range(1, n):
                if b[i] == 93:
                    close = i
                    break
            if close < 0 or close + 1 >= n or b[close + 1] != 58:
                raise IoError.of_kind("HostPort.parse", ErrorKind.InvalidInput)
            host_start = 1
            host_end = close
            colon = close + 1
        else:
            colon = -1
            for i in range(n):
                if b[i] == 58:
                    if colon >= 0:  # a second colon: unbracketed IPv6
                        raise IoError.of_kind(
                            "HostPort.parse", ErrorKind.InvalidInput
                        )
                    colon = i
            if colon < 0:
                raise IoError.of_kind("HostPort.parse", ErrorKind.InvalidInput)
            host_start = 0
            host_end = colon
        if host_end <= host_start or colon + 1 >= n or n - colon - 1 > 5:
            raise IoError.of_kind("HostPort.parse", ErrorKind.InvalidInput)
        for i in range(host_start, host_end):
            if b[i] == 91 or b[i] == 93:  # a bracket inside the host
                raise IoError.of_kind("HostPort.parse", ErrorKind.InvalidInput)
        var port = 0
        for i in range(colon + 1, n):
            var c = b[i]
            if c < 48 or c > 57:
                raise IoError.of_kind("HostPort.parse", ErrorKind.InvalidInput)
            port = port * 10 + Int(c - 48)
        if port > 65535:
            raise IoError.of_kind("HostPort.parse", ErrorKind.InvalidInput)
        return HostPort(
            String(from_utf8_lossy=b[host_start:host_end]), UInt16(port)
        )

    def write_to(self, mut writer: Some[Writer]):
        var b = self.host.as_bytes()
        var v6 = False
        for c in b:
            if c == 58:
                v6 = True
        if v6:
            writer.write("[", self.host, "]:", self.port)
        else:
            writer.write(self.host, ":", self.port)


# ---- dialing -----------------------------------------------------------------


struct _Attempt(Movable):
    var sock: Socket
    var addr: SocketAddr

    def __init__(out self, var sock: Socket, addr: SocketAddr):
        self.sock = sock^
        self.addr = addr

    def into_sock(deinit self) -> Socket:
        return self.sock^


def _is_local_error(e: IoError) -> Bool:
    """Errors that say nothing about the destination host: no route, no
    such local address, the family disabled."""
    return (
        e.kind == ErrorKind.NetworkUnreachable
        or e.kind == ErrorKind.NetworkDown
        or e.kind == ErrorKind.AddrNotAvailable
        or e.kind == ErrorKind.InvalidInput
        or e.kind == ErrorKind.Unsupported
    )


struct _Errors(Movable):
    """The first error, and the first one from beyond this host."""

    var first: Optional[IoError]
    var remote: Optional[IoError]

    def __init__(out self):
        self.first = None
        self.remote = None

    def add(mut self, e: IoError):
        if not self.first:
            self.first = e
        if not self.remote and not _is_local_error(e):
            self.remote = e

    def best(self) -> Optional[IoError]:
        if self.remote:
            return self.remote
        return self.first


def _literal(host: StringSlice, port: UInt16) -> Optional[SocketAddr]:
    """`host` as an IP literal: plain, bracketed, or IPv6 with a zone."""
    var b = host.as_bytes()
    var n = len(b)
    var inner = String(host)
    if n >= 2 and b[0] == 91 and b[n - 1] == 93:
        inner = String(from_utf8_lossy=b[1 : n - 1])
    try:
        return SocketAddr(IpAddr.parse(inner), port)
    except:
        pass
    for c in inner.as_bytes():
        if c == 37:  # '%': a zone
            try:
                return SocketAddr(
                    SocketAddrV6.parse(
                        String("[", inner, "]:", port), resolve_zone=True
                    )
                )
            except:
                return None
    return None


def dial_tcp(
    host: StringSlice, port: UInt16, deadline: Deadline
) raises IoError -> Socket:
    """`dial_tcp` with the system configuration, read only when `host` is
    not an IP literal."""
    var literal = _literal(host, port)
    if literal:
        return _connect_literal(literal.value(), deadline)
    return dial_tcp(Resolver.system(), host, port, deadline)


def _connect_literal(addr: SocketAddr, deadline: Deadline) raises IoError -> Socket:
    var sock = Socket.new(
        Domain.for_address(addr), SockType.STREAM, nonblocking=True
    )
    connect_with_deadline(sock, addr.to_raw(), deadline)
    return sock^


def dial_tcp(
    resolver: Resolver, host: StringSlice, port: UInt16, deadline: Deadline
) raises IoError -> Socket:
    """A connected, nonblocking TCP socket to `host:port` (see the module
    docs). The socket has no options set (`TcpStream.connect_host` turns on
    TCP_NODELAY)."""
    var literal = _literal(host, port)
    if literal:
        return _connect_literal(literal.value(), deadline)

    var lk = resolver.start(host, deadline)
    var v6 = List[SocketAddr]()
    var v4 = List[SocketAddr]()
    var next_v6 = True
    var attempts = List[_Attempt]()
    var errors = _Errors()
    var last_start: Optional[Instant] = None
    var kick = False  # an attempt failed: start the next one now
    var v4_waiting_since: Optional[Instant] = None

    while True:
        var now = Instant.now()
        if deadline.is_expired(now):
            raise IoError.of_kind("connect", ErrorKind.TimedOut)

        # New answers join the queues, each kept in RFC 6724 precedence
        # order (stable: answer order among equals).
        var got = List[IpAddr]()
        lk.take(got)
        for ip in got:
            if ip.is_ipv6():
                _insert_by_precedence(v6, SocketAddr(ip, port))
            else:
                _insert_by_precedence(v4, SocketAddr(ip, port))

        # Resolution delay: IPv4 waits briefly for a pending AAAA answer
        # before the very first attempt.
        var hold = False
        if (
            not last_start
            and len(v6) == 0
            and len(v4) > 0
            and lk.is_pending(TYPE_AAAA)
        ):
            if not v4_waiting_since:
                v4_waiting_since = now
            if now - v4_waiting_since.value() < RESOLUTION_DELAY:
                hold = True

        # Start the next attempt when it is due.
        var queued = len(v6) + len(v4)
        var due = (
            len(attempts) == 0
            or kick
            or not last_start
            or now - last_start.value() >= ATTEMPT_DELAY
        )
        if queued > 0 and due and not hold:
            if not last_start and len(v6) > 0 and len(v4) > 0:
                # The first family is the one RFC 6724 ranks first (IPv6
                # unless its best address is ULA, 6to4, Teredo, ...).
                next_v6 = precedence(v6[0].ip()) >= precedence(v4[0].ip())
            var addr: SocketAddr
            if (next_v6 and len(v6) > 0) or len(v4) == 0:
                addr = v6.pop(0)
            else:
                addr = v4.pop(0)
            next_v6 = not addr.is_ipv6()
            last_start = now
            kick = False
            var connected = False
            var sock = _start(addr, errors, connected)
            if sock:
                if connected:
                    return sock.take()
                attempts.append(_Attempt(sock.take(), addr))
            else:
                kick = True  # failed at once: the next one starts now
            continue

        # Nothing left to try, now or later.
        if len(attempts) == 0 and queued == 0 and lk.is_done():
            var e = errors.best()
            if e:
                raise e.value()
            var le = lk.error()
            if le:
                raise le.value()
            raise IoError.of_kind("connect", ErrorKind.NotFound)

        # Wait for a connection, an answer, or the next timer.
        var fds = List[Pollfd]()
        lk.poll_fds(fds)
        var first_attempt = len(fds)
        for i in range(len(attempts)):
            fds.append(Pollfd(attempts[i].sock.raw_fd(), Int16(POLLOUT), 0))
        var wake = deadline.earliest(lk.next_deadline())
        if queued > 0 and last_start:
            wake = wake.earliest(
                Deadline.at(last_start.value() + ATTEMPT_DELAY)
            )
        if hold:
            wake = wake.earliest(
                Deadline.at(v4_waiting_since.value() + RESOLUTION_DELAY)
            )
        _ = poll_until(Span(fds), wake, "connect")

        var winner = _settle(attempts, Span(fds)[first_attempt:], errors)
        if winner:
            return attempts.pop(winner.value()).into_sock()
        if len(attempts) < len(fds) - first_attempt:
            kick = True  # some failed: the next attempt starts now
        lk.advance(deadline)


def _settle(
    mut attempts: List[_Attempt], revents: Span[Pollfd, _], mut errors: _Errors
) raises IoError -> Optional[Int]:
    """Look at the attempts that finished (`revents[i]` is attempt `i`'s
    poll entry). Return the index of the earliest-started one that
    connected (attempts are in start order, so a tie goes to the first),
    else record and drop the failed ones and return None."""
    var failed = List[Int]()
    for i in range(len(attempts)):
        var ev = revents[i].revents
        if (ev & Int16(POLLOUT | POLLERR | POLLHUP)) == 0:
            continue
        var err = attempts[i].sock.take_error()
        if not err and (ev & Int16(POLLOUT)) != 0:
            return i
        if err:
            errors.add(IoError.from_errno("connect", err.value().errno))
        else:
            errors.add(IoError.of_kind("connect", ErrorKind.ConnectionRefused))
        failed.append(i)
    for k in range(len(failed) - 1, -1, -1):  # from the end: indices stay valid
        _ = attempts.pop(failed[k])
    return None


def _insert_by_precedence(mut q: List[SocketAddr], addr: SocketAddr):
    """Insert `addr` after every queued address of at least its precedence
    (RFC 6724's policy table), so equal ones keep answer order."""
    var p = precedence(addr.ip())
    var at = len(q)
    for j in range(len(q)):
        if precedence(q[j].ip()) < p:
            at = j
            break
    q.insert(at, addr)


def _start(
    addr: SocketAddr, mut errors: _Errors, mut connected: Bool
) raises IoError -> Optional[Socket]:
    """socket + nonblocking connect: the socket (`connected` if it finished
    at once), or None with the error recorded. Local resource errors
    (EMFILE, ENOMEM) raise. EINTR counts as in progress: a TCP connect is
    never issued twice (docs/net.md)."""
    var sock: Socket
    try:
        sock = Socket.new(
            Domain.for_address(addr), SockType.STREAM, nonblocking=True
        )
    except e:
        if e.kind == ErrorKind.TooManyFiles or e.kind == ErrorKind.OutOfMemory:
            raise e
        errors.add(e)
        return None
    var raw = addr.to_raw()
    var r = sys.connect(sock, raw.storage, raw.socklen())
    if r == 0:
        connected = True
        return sock^
    var e = Errno(err_of(r))
    if e == Errno.EINPROGRESS or e == Errno.EINTR:
        return sock^
    errors.add(IoError.from_errno("connect", e))
    return None
