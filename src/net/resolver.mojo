"""A stub resolver in pure Mojo: host names to IP addresses through
/etc/hosts and the DNS servers of /etc/resolv.conf, with no libc
(`getaddrinfo` is libc's and blocks without a deadline).

    var r = Resolver.system()        # reads both files; keep and reuse it
    var ips = r.lookup_ip("db.internal", Deadline.after(Duration.from_secs(3)))

Sources, in order (nsswitch's `hosts: files dns`):
1. An IP literal is its own answer.
2. /etc/hosts: a listed name gets exactly its addresses there.
3. `localhost` and names under `.localhost` are the loopback addresses
   (RFC 6761) when the hosts file does not list them.
4. DNS: each name of the search list (`net.resolv.search_names`) in turn,
   asking A and AAAA in parallel, until one name has addresses.

DNS queries:
- **Sockets.** Each query type has its own UDP socket, connected to the
  server, so the kernel drops datagrams from anyone else. A and AAAA leave
  from different ports, which avoids the conntrack race behind the
  "5 second DNS delay" in containers (what glibc's `single-request-reopen`
  works around).
- **Forgery.** IDs are random (getrandom), ports are the kernel's random
  ephemeral ones, and a packet that is not an answer to the query (wrong ID
  or question) is ignored, not counted as a failure (`net.dns`).
- **TCP.** A truncated answer is asked again over TCP of the same server;
  `options use-vc` uses TCP for everything; `options edns0` advertises
  1232-byte UDP answers instead.
- **Servers.** In order (from a random one with `options rotate`), for
  `attempts` rounds; each try waits `timeout`. SERVFAIL, REFUSED, FORMERR,
  NOTIMP, a malformed answer, an ICMP port unreachable (ECONNREFUSED) and a
  failed send move to the next server at once. NXDOMAIN and NOERROR (with
  or without addresses) end the query for that name.

`lookup_ip` orders its result by a subset of RFC 6724's destination rules:
usable addresses first (the kernel has a route: probed with a UDP connect,
which sends nothing; only when both families are present), then by the
default policy table's precedence (::1, global IPv6, IPv4, 6to4, Teredo,
ULA, ...), keeping answer order otherwise. Callers that connect should use
`TcpStream.connect_host`, which races the addresses (Happy Eyeballs).

Errors carry op "resolve": `NotFound` when no candidate name has
addresses (NXDOMAIN or NODATA everywhere), `TimedOut` when the deadline
passes or a server never answered, `Other` when servers failed (SERVFAIL,
REFUSED, malformed answers), `InvalidInput` for a name that cannot be
asked (empty, a label over 63 bytes, a byte outside letters, digits, `-`
and `_`).

`Lookup` is the same work as an incremental state machine: a caller that
waits on other sockets too polls `poll_fds`, wakes by `next_deadline`, and
calls `advance`; addresses come out of `take` as each answer arrives.
"""

from linux import ErrorKind, IoError, sys
from linux.abi import Pollfd
from linux.consts import POLLIN
from linux.errno import Errno
from linux.poll import poll_until
from linux.random import fill_random
from linux.syscall import err_of, is_err
from linux.time import Deadline, Duration

from .addr import IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr
from .blocking import (
    connect_with_deadline,
    recv_exact_with_deadline,
    send_all_with_deadline,
)
from .dns import (
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    TYPE_A,
    TYPE_AAAA,
    DnsAnswer,
    build_query,
    parse_response,
    tcp_frame,
)
from .resolv import Hosts, ResolvConf, search_names
from .socket import Domain, SockType, Socket

comptime _WAITING = 1
comptime _DONE = 2

comptime _OUT_ADDRS = 1
"""NOERROR: addresses, or none (NODATA)."""
comptime _OUT_NXDOMAIN = 2
comptime _OUT_FAILED = 3
"""Every try ended with a server failure or a send error."""
comptime _OUT_TIMEOUT = 4
"""Every try ended, at least one of them by its timeout."""

comptime _RECV_BUF = 65535


# ---- one query ---------------------------------------------------------------


struct _Query(Movable):
    """One question (`qtype` for the current name) over the server list."""

    var qtype: UInt16
    var state: Int
    var sock: Optional[Socket]
    var msg: List[UInt8]
    var tries: Int
    var try_deadline: Deadline
    var outcome: Int
    var saw_timeout: Bool

    def __init__(out self, qtype: UInt16):
        self.qtype = qtype
        self.state = _DONE
        self.sock = None
        self.msg = List[UInt8]()
        self.tries = 0
        self.try_deadline = Deadline.none()
        self.outcome = 0
        self.saw_timeout = False


# ---- the lookup state machine ------------------------------------------------


struct Lookup(Movable):
    """One host lookup in progress (see the module docs). Not copyable: it
    owns its sockets. Drive it with `poll_fds` / `next_deadline` /
    `advance` until `is_done()`, collecting addresses with `take`."""

    var _servers: List[SocketAddr]
    var _timeout: Duration
    var _max_tries: Int
    var _edns: Bool
    var _tcp: Bool
    var _names: List[String]
    var _name_i: Int
    var _queries: List[_Query]
    var _ready: List[IpAddr]
    var _found: Bool
    var _done: Bool
    var _failed: Bool
    var _timed_out: Bool
    var _error: Optional[IoError]
    var _rbuf: List[UInt8]

    def __init__(out self, var addrs: List[IpAddr]):
        """A lookup answered without DNS (a literal or the hosts file)."""
        self._servers = List[SocketAddr]()
        self._timeout = Duration.ZERO
        self._max_tries = 0
        self._edns = False
        self._tcp = False
        self._names = List[String]()
        self._name_i = 0
        self._queries = List[_Query]()
        self._found = len(addrs) > 0
        self._ready = addrs^
        self._done = True
        self._failed = False
        self._timed_out = False
        self._error = None
        self._rbuf = List[UInt8]()
        if not self._found:
            self._error = IoError.of_kind("resolve", ErrorKind.NotFound)

    def __init__(
        out self,
        var names: List[String],
        conf: ResolvConf,
        *,
        want_v4: Bool,
        want_v6: Bool,
        deadline: Deadline,
    ) raises IoError:
        """Start asking DNS for `names` in turn (the first query is sent
        before this returns)."""
        self._servers = List[SocketAddr]()
        var n = len(conf.nameservers)
        var first = 0
        if conf.rotate and n > 1:
            var b = List[UInt8](length=1, fill=0)
            fill_random(Span(b))
            first = Int(b[0]) % n
        for i in range(n):
            self._servers.append(conf.nameservers[(first + i) % n])
        self._timeout = conf.timeout
        self._max_tries = n * max(conf.attempts, 1)
        self._edns = conf.edns0
        self._tcp = conf.use_tcp
        self._names = names^
        self._name_i = 0
        self._queries = List[_Query]()
        if want_v6:
            self._queries.append(_Query(TYPE_AAAA))
        if want_v4:
            self._queries.append(_Query(TYPE_A))
        self._ready = List[IpAddr]()
        self._found = False
        self._done = False
        self._failed = False
        self._timed_out = False
        self._error = None
        self._rbuf = List[UInt8](length=_RECV_BUF, fill=0)
        if len(self._names) == 0 or len(self._queries) == 0 or n == 0:
            self._done = True
            self._error = IoError.of_kind("resolve", ErrorKind.InvalidInput)
            return
        self._start_name(deadline)

    # ---- driving ---------------------------------------------------------

    def is_done(self) -> Bool:
        return self._done

    def error(self) -> Optional[IoError]:
        """Why the lookup found nothing, once `is_done()` (None if it found
        addresses)."""
        if self._found:
            return None
        return self._error

    def take(mut self, mut out: List[IpAddr]):
        """Move the addresses found since the last `take` to `out`, in the
        order their answers arrived."""
        for ip in self._ready:
            out.append(ip)
        self._ready.clear()

    def is_pending(self, qtype: UInt16) -> Bool:
        """Whether the query of `qtype` (`net.dns.TYPE_A` or `TYPE_AAAA`)
        for the current name is still waiting for an answer."""
        if self._done:
            return False
        for i in range(len(self._queries)):
            ref q = self._queries[i]
            if q.qtype == qtype and q.state == _WAITING:
                return True
        return False

    def poll_fds(self, mut fds: List[Pollfd]):
        """Append a POLLIN entry for each socket awaiting an answer. The
        entries hold raw descriptors: keep the lookup alive while polling."""
        for i in range(len(self._queries)):
            ref q = self._queries[i]
            if q.state == _WAITING and q.sock:
                fds.append(Pollfd(q.sock.value().raw_fd(), Int16(POLLIN), 0))

    def next_deadline(self) -> Deadline:
        """When `advance` must run again even without readiness."""
        var d = Deadline.none()
        for i in range(len(self._queries)):
            ref q = self._queries[i]
            if q.state == _WAITING:
                d = d.earliest(q.try_deadline)
        return d

    def advance(mut self, deadline: Deadline) raises IoError:
        """Read whatever answers have arrived (without waiting for UDP),
        move expired tries on, and start the next name when this one is
        finished. A TCP retry of a truncated answer is a blocking exchange
        bounded by its try timeout and `deadline`. Never raises for server
        behaviour, only for local failures (no descriptors, ...)."""
        if self._done:
            return
        for i in range(len(self._queries)):
            if self._queries[i].state == _WAITING:
                self._drain(i, deadline)
        for i in range(len(self._queries)):
            ref q = self._queries[i]
            if q.state == _WAITING and q.try_deadline.is_expired():
                q.saw_timeout = True
                q.sock = None
                self._next_try(i, deadline)
        self._settle(deadline)

    # ---- internals -------------------------------------------------------

    def _start_name(mut self, deadline: Deadline) raises IoError:
        for i in range(len(self._queries)):
            ref q = self._queries[i]
            q.state = _WAITING
            q.tries = 0
            q.outcome = 0
            q.saw_timeout = False
            q.sock = None
            self._next_try(i, deadline)
        self._settle(deadline)

    def _next_try(mut self, i: Int, deadline: Deadline) raises IoError:
        """Send query `i` to its next server, or finish it if none is
        left. Local resource errors (EMFILE, ENOMEM) raise."""
        while self._queries[i].tries < self._max_tries:
            var server = self._servers[
                self._queries[i].tries % len(self._servers)
            ]
            self._queries[i].tries += 1
            var id = List[UInt8](length=2, fill=0)
            fill_random(Span(id))
            self._queries[i].msg = build_query(
                (UInt16(id[0]) << 8) | UInt16(id[1]),
                self._names[self._name_i],
                self._queries[i].qtype,
                self._edns,
            )
            var try_deadline = deadline.earliest(Deadline.after(self._timeout))
            self._queries[i].try_deadline = try_deadline
            if self._tcp:
                if self._ask_tcp(i, server, try_deadline):
                    return
                continue
            var sock: Socket
            try:
                sock = Socket.new(
                    Domain.for_address(server), SockType.DGRAM, nonblocking=True
                )
            except e:
                if _is_local_resource_error(e):
                    raise e
                continue  # e.g. IPv6 disabled: next server
            try:
                sock.connect(server)
                _ = sock.send(Span(self._queries[i].msg))
            except e:
                if _is_local_resource_error(e):
                    raise e
                continue  # unreachable server: next one
            self._queries[i].sock = sock^
            self._queries[i].state = _WAITING
            return
        ref q = self._queries[i]
        q.state = _DONE
        q.sock = None
        q.outcome = _OUT_TIMEOUT if q.saw_timeout else _OUT_FAILED

    def _drain(mut self, i: Int, deadline: Deadline) raises IoError:
        """Receive every queued datagram of query `i` until EAGAIN or an
        accepted answer."""
        while self._queries[i].state == _WAITING and self._queries[i].sock:
            var r = sys.recv(
                self._queries[i].sock.value(), Span(self._rbuf), 0
            )
            if is_err(r):
                var e = Errno(err_of(r))
                if e == Errno.EAGAIN or e == Errno.EINTR:
                    if e == Errno.EAGAIN:
                        return
                    continue
                # ECONNREFUSED (ICMP port unreachable) and the like.
                self._queries[i].sock = None
                self._next_try(i, deadline)
                return
            var answer: Optional[DnsAnswer]
            try:
                answer = parse_response(
                    Span(self._rbuf)[0:r], Span(self._queries[i].msg)
                )
            except:
                # Our ID and question but malformed: a broken server.
                self._queries[i].sock = None
                self._next_try(i, deadline)
                return
            if not answer:
                continue  # not an answer to this query: ignore it
            var ans = answer.take()
            if ans.truncated:
                var server = self._server_of(i)
                self._queries[i].sock = None
                var tcp_deadline = deadline.earliest(
                    Deadline.after(self._timeout)
                )
                if not self._ask_tcp(i, server, tcp_deadline):
                    self._next_try(i, deadline)
                return
            if not self._accept(i, ans^):
                self._queries[i].sock = None
                self._next_try(i, deadline)
            return

    def _server_of(self, i: Int) -> SocketAddr:
        """The server of query `i`'s current try."""
        return self._servers[(self._queries[i].tries - 1) % len(self._servers)]

    def _ask_tcp(
        mut self, i: Int, server: SocketAddr, deadline: Deadline
    ) raises IoError -> Bool:
        """The current query over TCP to `server`. True if that decided the
        query; False to move on to the next server."""
        var resp: List[UInt8]
        try:
            resp = _exchange_tcp(server, Span(self._queries[i].msg), deadline)
        except e:
            if _is_local_resource_error(e):
                raise e
            if e.kind == ErrorKind.TimedOut:
                self._queries[i].saw_timeout = True
            return False
        var answer: Optional[DnsAnswer]
        try:
            answer = parse_response(Span(resp), Span(self._queries[i].msg))
        except:
            return False
        if not answer:
            return False
        var ans = answer.take()
        if ans.truncated:
            return False
        return self._accept(i, ans^)

    def _accept(mut self, i: Int, var ans: DnsAnswer) -> Bool:
        """Apply an answer to query `i`: True if it ends the query."""
        ref q = self._queries[i]
        if ans.rcode == RCODE_NOERROR:
            q.state = _DONE
            q.sock = None
            q.outcome = _OUT_ADDRS
            if len(ans.addrs) > 0:
                self._found = True
                for ip in ans.addrs:
                    self._ready.append(ip)
            return True
        if ans.rcode == RCODE_NXDOMAIN:
            q.state = _DONE
            q.sock = None
            q.outcome = _OUT_NXDOMAIN
            return True
        return False  # SERVFAIL, REFUSED, FORMERR, ...: next server

    def _settle(mut self, deadline: Deadline) raises IoError:
        """After progress: finish the lookup, or start the next name once
        every query for this one has ended without addresses."""
        while not self._done:
            for i in range(len(self._queries)):
                if self._queries[i].state != _DONE:
                    return
            if self._found:
                self._done = True
                return
            for i in range(len(self._queries)):
                var outcome = self._queries[i].outcome
                if outcome == _OUT_FAILED:
                    self._failed = True
                elif outcome == _OUT_TIMEOUT:
                    self._timed_out = True
            self._name_i += 1
            if self._name_i >= len(self._names):
                self._done = True
                if self._timed_out:
                    self._error = IoError.of_kind("resolve", ErrorKind.TimedOut)
                elif self._failed:
                    self._error = IoError.of_kind("resolve", ErrorKind.Other)
                else:
                    self._error = IoError.of_kind("resolve", ErrorKind.NotFound)
                return
            for i in range(len(self._queries)):
                ref q = self._queries[i]
                q.state = _WAITING
                q.tries = 0
                q.outcome = 0
                q.saw_timeout = False
                q.sock = None
                self._next_try(i, deadline)


def _is_local_resource_error(e: IoError) -> Bool:
    """Failures of this process, not of the network or a server: raised."""
    return e.kind == ErrorKind.TooManyFiles or e.kind == ErrorKind.OutOfMemory


def _exchange_tcp(
    server: SocketAddr, msg: Span[UInt8, _], deadline: Deadline
) raises IoError -> List[UInt8]:
    """One query and its answer over a fresh TCP connection (RFC 7766's
    framing: a 2-byte length before each message)."""
    var sock = Socket.new(
        Domain.for_address(server), SockType.STREAM, nonblocking=True
    )
    connect_with_deadline(sock, server.to_raw(), deadline)
    var frame = tcp_frame(msg)
    send_all_with_deadline(sock, Span(frame), deadline, "resolve")
    var head = List[UInt8](length=2, fill=0)
    recv_exact_with_deadline(sock, Span(head), deadline, "resolve")
    var n = (Int(head[0]) << 8) | Int(head[1])
    var resp = List[UInt8](length=n, fill=0)
    recv_exact_with_deadline(sock, Span(resp), deadline, "resolve")
    return resp^


# ---- the resolver ------------------------------------------------------------


def _is_localhost(name: StringSlice) -> Bool:
    """`localhost` or a name under `.localhost`, any case, one trailing dot
    allowed (RFC 6761 section 6.3)."""
    var b = name.as_bytes()
    var n = len(b)
    if n > 0 and b[n - 1] == 46:
        n -= 1
    comptime word = "localhost"
    if n < 9:
        return False
    for i in range(9):
        var c = b[n - 9 + i]
        if c >= 65 and c <= 90:
            c += 32
        if c != word.as_bytes()[i]:
            return False
    return n == 9 or b[n - 10] == 46


struct Resolver(Copyable, Movable):
    """Resolver configuration: the resolv.conf settings and the hosts table.
    `Resolver.system()` reads them once; create one per program (or per
    pool) rather than per lookup."""

    var conf: ResolvConf
    var hosts: Hosts

    def __init__(out self, var conf: ResolvConf, var hosts: Hosts):
        self.conf = conf^
        self.hosts = hosts^

    @staticmethod
    def system() raises IoError -> Resolver:
        """/etc/resolv.conf and /etc/hosts (missing files mean defaults)."""
        return Resolver(ResolvConf.load(), Hosts.load())

    def start(
        self,
        host: StringSlice,
        deadline: Deadline,
        *,
        want_v4: Bool = True,
        want_v6: Bool = True,
    ) raises IoError -> Lookup:
        """Begin looking up `host` (see the module docs for the sources)."""
        try:
            var ip = IpAddr.parse(host)
            var only = List[IpAddr]()
            if (ip.is_ipv4() and want_v4) or (ip.is_ipv6() and want_v6):
                only.append(ip)
            return Lookup(only^)
        except:
            pass
        var listed = self.hosts.lookup(host)
        if len(listed) > 0:
            return Lookup(_filter(listed, want_v4, want_v6))
        if _is_localhost(host):
            var lo = List[IpAddr]()
            if want_v6:
                lo.append(IpAddr(Ipv6Addr.from_bits(1)))
            if want_v4:
                lo.append(IpAddr(Ipv4Addr(127, 0, 0, 1)))
            return Lookup(lo^)
        var names = search_names(host, self.conf)
        return Lookup(
            names^,
            self.conf,
            want_v4=want_v4,
            want_v6=want_v6,
            deadline=deadline,
        )

    def lookup_ip(
        self,
        host: StringSlice,
        deadline: Deadline,
        *,
        want_v4: Bool = True,
        want_v6: Bool = True,
    ) raises IoError -> List[IpAddr]:
        """The addresses of `host`, sorted for connecting (see the module
        docs). Raises `TimedOut` once `deadline` passes."""
        var lk = self.start(host, deadline, want_v4=want_v4, want_v6=want_v6)
        var out = List[IpAddr]()
        while not lk.is_done():
            var fds = List[Pollfd]()
            lk.poll_fds(fds)
            if len(fds) == 0:
                # Every query waits on a socket while the lookup runs.
                raise IoError.of_kind("resolve", ErrorKind.Other)
            var wake = deadline.earliest(lk.next_deadline())
            _ = poll_until(Span(fds), wake, "resolve")
            if deadline.is_expired() and not lk.is_done():
                lk.advance(deadline)  # one last look at what has arrived
                if not lk.is_done():
                    raise IoError.of_kind("resolve", ErrorKind.TimedOut)
            lk.advance(deadline)
        lk.take(out)
        if len(out) == 0:
            var e = lk.error()
            if e:
                raise e.value()
            raise IoError.of_kind("resolve", ErrorKind.NotFound)
        sort_addresses(out)
        return out^


def _filter(
    addrs: List[IpAddr], want_v4: Bool, want_v6: Bool
) -> List[IpAddr]:
    var out = List[IpAddr]()
    for ip in addrs:
        if (ip.is_ipv4() and want_v4) or (ip.is_ipv6() and want_v6):
            out.append(ip)
    return out^


# ---- address order (RFC 6724, a subset) --------------------------------------


def precedence(ip: IpAddr) -> Int:
    """The default policy table's precedence (RFC 6724 section 2.1)."""
    if ip.is_ipv4():
        return 35
    var s = ip.v6().segments()
    if ip.v6() == Ipv6Addr.from_bits(1):
        return 50
    if s[0] == 0x2002:
        return 30
    if s[0] == 0x2001 and s[1] == 0:
        return 5
    if (s[0] & 0xFE00) == 0xFC00:
        return 3
    if (s[0] & 0xFFC0) == 0xFEC0 or s[0] == 0x3FFE:
        return 1
    var compat = True
    for i in range(6):
        if s[i] != 0:
            compat = False
    if compat and ip.v6() != Ipv6Addr.from_bits(0):
        return 1  # IPv4-compatible ::a.b.c.d
    return 40


def _usable(ip: IpAddr) -> Bool:
    """Whether the kernel has a route to `ip` (a UDP connect sends
    nothing)."""
    try:
        var dst = SocketAddr(ip, 9)
        var s = Socket.new(Domain.for_address(dst), SockType.DGRAM)
        s.connect(dst)
        return True
    except:
        return False


def sort_addresses(mut addrs: List[IpAddr]):
    """Order `addrs` for connecting: usable before unusable (only probed
    when both families are present), then higher precedence first, then
    the original order."""
    var has4 = False
    var has6 = False
    for ip in addrs:
        if ip.is_ipv4():
            has4 = True
        else:
            has6 = True
    var keys = List[Int]()
    for ip in addrs:
        var k = precedence(ip)
        if has4 and has6 and not _usable(ip):
            k -= 1000
        keys.append(k)
    # Insertion sort: stable, and lists are short.
    for i in range(1, len(addrs)):
        var ip = addrs[i]
        var k = keys[i]
        var j = i - 1
        while j >= 0 and keys[j] < k:
            addrs[j + 1] = addrs[j]
            keys[j + 1] = keys[j]
            j -= 1
        addrs[j + 1] = ip
        keys[j + 1] = k
