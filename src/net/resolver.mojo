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
  `options use-vc` uses TCP for everything. The TCP exchange is
  nonblocking like the UDP one: it never holds up the other query or a
  caller racing connections.
- **EDNS(0).** `options edns0` advertises 1232-byte UDP answers; a server
  that answers that with FORMERR or NOTIMP is asked again without it.
- **Servers.** In order (from a random one with `options rotate`), for
  `attempts` rounds; each try waits `timeout`, and once more over TCP
  after a truncated answer (Go's rule): at most twice `timeout`, however
  its legs chain (TCP, the EDNS fallback, truncated again). SERVFAIL,
  REFUSED, FORMERR, NOTIMP, a lame referral (no answer from a server that is neither
  authoritative nor recursive), a malformed answer, an ICMP port
  unreachable (ECONNREFUSED) and a failed send move to the next server at
  once. NXDOMAIN and NOERROR (with or without addresses) end the query for
  that name.
- **Deadline.** No try starts after the caller's deadline, and every try
  ends by it, so a lookup finishes by its deadline with whatever it has:
  an A answer is returned even if AAAA never came.

`lookup_ip` orders its result by a subset of RFC 6724's destination rules:
usable addresses first (the kernel has a route: probed with a UDP connect,
which sends nothing; only when both families are present), then by the
default policy table's precedence (::1, global IPv6, IPv4, 6to4, Teredo,
ULA, ...), keeping answer order otherwise. Callers that connect should use
`TcpStream.connect_host`, which races the addresses (Happy Eyeballs).

Errors carry op "resolve": `NotFound` when no candidate name has
addresses (NXDOMAIN or NODATA everywhere), `TimedOut` when the deadline
passed or a server never answered (and nothing was found), `Other` when servers failed (SERVFAIL,
REFUSED, malformed answers), `InvalidInput` for a name that cannot be
asked (empty, a label over 63 bytes, a byte outside letters, digits, `-`
and `_`).

`Lookup` is the same work as an incremental state machine: a caller that
waits on other sockets too polls `poll_fds`, wakes by `next_deadline`, and
calls `advance`; addresses come out of `take` as each answer arrives.
"""

from linux import ErrorKind, IoError, sys
from linux.abi import Pollfd
from linux.consts import MSG_NOSIGNAL, POLLIN, POLLOUT
from linux.errno import Errno
from linux.poll import poll_until
from linux.random import fill_random
from linux.syscall import err_of, is_err
from linux.time import Deadline, Duration

from .addr import IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr
from .dns import (
    RCODE_FORMERR,
    RCODE_NOERROR,
    RCODE_NOTIMP,
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

comptime _MAX_DRAIN = 64
"""Datagrams one `_drain` call reads at most (see there)."""

comptime _RECV_BUF = 65535


# ---- one query ---------------------------------------------------------------


struct _Query(Movable):
    """One question (`qtype` for the current name) over the server list. A
    try is a connected UDP socket (`udp`) or a TCP exchange in progress
    (`tcp`: after a truncated answer, or always with `use-vc`); both are
    nonblocking and driven by `Lookup.advance`."""

    var qtype: UInt16
    var state: Int
    var udp: Optional[Socket]
    var tcp: Optional[Socket]
    var tcp_out: List[UInt8]
    """The length-prefixed query; `tcp_sent` bytes of it are sent."""
    var tcp_sent: Int
    var tcp_in: List[UInt8]
    """The length prefix and answer received so far."""
    var msg: List[UInt8]
    var server: Int
    """Index of the current try's server."""
    var edns: Bool
    """Whether `msg` carries an OPT record."""
    var tries: Int
    var try_deadline: Deadline
    var tcp_leg: Bool
    """Whether the current try has had its TCP leg (after a truncated
    answer), with the one fresh timer a try gets."""
    var outcome: Int
    var saw_timeout: Bool

    def __init__(out self, qtype: UInt16):
        self.qtype = qtype
        self.state = _DONE
        self.udp = None
        self.tcp = None
        self.tcp_out = List[UInt8]()
        self.tcp_sent = 0
        self.tcp_in = List[UInt8]()
        self.msg = List[UInt8]()
        self.server = 0
        self.edns = False
        self.tries = 0
        self.try_deadline = Deadline.none()
        self.tcp_leg = False
        self.outcome = 0
        self.saw_timeout = False

    def close(mut self):
        self.udp = None
        self.tcp = None


# ---- the lookup state machine ------------------------------------------------


struct Lookup(Movable):
    """One host lookup in progress (see the module docs). Not copyable: it
    owns its sockets. Drive it with `poll_fds` / `next_deadline` /
    `advance` until `is_done()`, collecting addresses with `take`. Nothing
    in it waits: every socket is nonblocking."""

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
        """Start asking DNS for `names` in turn (the first queries are sent
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
        """Append an entry for each socket a query waits on (POLLIN for UDP
        and TCP answers, POLLOUT while a TCP query is connecting or
        sending). The entries hold raw descriptors: keep the lookup alive
        while polling."""
        for i in range(len(self._queries)):
            ref q = self._queries[i]
            if q.state != _WAITING:
                continue
            if q.tcp:
                var ev = POLLOUT if q.tcp_sent < len(q.tcp_out) else POLLIN
                fds.append(Pollfd(q.tcp.value().raw_fd(), Int16(ev), 0))
            elif q.udp:
                fds.append(Pollfd(q.udp.value().raw_fd(), Int16(POLLIN), 0))

    def next_deadline(self) -> Deadline:
        """When `advance` must run again even without readiness."""
        var d = Deadline.none()
        for i in range(len(self._queries)):
            ref q = self._queries[i]
            if q.state == _WAITING:
                d = d.earliest(q.try_deadline)
        return d

    def advance(mut self, deadline: Deadline) raises IoError:
        """Make progress without waiting: read the answers that arrived,
        push TCP exchanges along, move expired tries on, and start the next
        name when this one is finished. Once `deadline` has passed no new
        try starts, so the lookup finishes (with whatever it found). Raises
        only for local failures (no descriptors, ...), never for server
        behaviour."""
        if self._done:
            return
        for i in range(len(self._queries)):
            if self._queries[i].state != _WAITING:
                continue
            if self._queries[i].tcp:
                self._step_tcp(i, deadline)
            else:
                self._drain(i, deadline)
        for i in range(len(self._queries)):
            ref q = self._queries[i]
            if q.state == _WAITING and q.try_deadline.is_expired():
                q.saw_timeout = True
                q.close()
                self._next_try(i, deadline)
        self._settle(deadline)

    # ---- tries -----------------------------------------------------------

    def _start_name(mut self, deadline: Deadline) raises IoError:
        for i in range(len(self._queries)):
            ref q = self._queries[i]
            q.state = _WAITING
            q.tries = 0
            q.outcome = 0
            q.saw_timeout = False
            q.close()
            self._next_try(i, deadline)
        self._settle(deadline)

    def _next_try(mut self, i: Int, deadline: Deadline) raises IoError:
        """Send query `i` to its next server, or finish it when no try is
        left or `deadline` has passed."""
        while self._queries[i].tries < self._max_tries:
            if deadline.is_expired():
                self._queries[i].saw_timeout = True
                break
            self._queries[i].server = self._queries[i].tries % len(
                self._servers
            )
            self._queries[i].tries += 1
            if self._send(i, self._edns, deadline):
                return
        ref q = self._queries[i]
        q.state = _DONE
        q.close()
        q.outcome = _OUT_TIMEOUT if q.saw_timeout else _OUT_FAILED

    def _fail_try(mut self, i: Int, deadline: Deadline) raises IoError:
        self._queries[i].close()
        self._next_try(i, deadline)

    def _send(
        mut self, i: Int, edns: Bool, deadline: Deadline, new_try: Bool = True
    ) raises IoError -> Bool:
        """Send query `i` with a fresh ID to its current server, over UDP
        (or TCP with `use-vc`). False if that failed at once (no route,
        refused, IPv6 off, ...); local resource errors raise. `new_try`
        starts the try's timer; the EDNS fallback (`new_try=False`) runs
        within the try's time."""
        var server = self._servers[self._queries[i].server]
        var id = List[UInt8](length=2, fill=0)
        fill_random(Span(id))
        self._queries[i].msg = build_query(
            (UInt16(id[0]) << 8) | UInt16(id[1]),
            self._names[self._name_i],
            self._queries[i].qtype,
            edns,
        )
        self._queries[i].edns = edns
        if new_try:
            self._queries[i].try_deadline = deadline.earliest(
                Deadline.after(self._timeout)
            )
            self._queries[i].tcp_leg = False
        self._queries[i].close()
        self._queries[i].state = _WAITING
        if self._tcp:
            return self._start_tcp(i)
        var sock: Socket
        try:
            sock = Socket.new(
                Domain.for_address(server), SockType.DGRAM, nonblocking=True
            )
            sock.connect(server)
        except e:
            if _is_local_resource_error(e):
                raise e
            return False
        while True:
            var r = sys.send(sock, Span(self._queries[i].msg), MSG_NOSIGNAL)
            if r >= 0:
                break
            if Errno(err_of(r)) != Errno.EINTR:
                return False  # unreachable, refused, ...: the next server
        self._queries[i].udp = sock^
        return True

    def _start_tcp(mut self, i: Int) raises IoError -> Bool:
        """Begin query `i` over TCP to its current server: a nonblocking
        connect; `_step_tcp` sends and reads once the socket is ready."""
        var server = self._servers[self._queries[i].server]
        var sock: Socket
        try:
            sock = Socket.new(
                Domain.for_address(server), SockType.STREAM, nonblocking=True
            )
        except e:
            if _is_local_resource_error(e):
                raise e
            return False
        var raw = server.to_raw()
        var r = sys.connect(sock, raw.storage, raw.socklen())
        if r < 0:
            var e = Errno(err_of(r))
            # EINTR: the connect goes on in the background, never reissued.
            if e != Errno.EINPROGRESS and e != Errno.EINTR:
                return False
        self._queries[i].tcp_out = tcp_frame(Span(self._queries[i].msg))
        self._queries[i].tcp_sent = 0
        self._queries[i].tcp_in.clear()
        self._queries[i].tcp = sock^
        return True

    def _step_tcp(mut self, i: Int, deadline: Deadline) raises IoError:
        """Push query `i`'s TCP exchange as far as it goes without waiting.
        A send on a socket still connecting says EAGAIN, so one loop covers
        connecting and sending."""
        while self._queries[i].tcp_sent < len(self._queries[i].tcp_out):
            var r = sys.send(
                self._queries[i].tcp.value(),
                Span(self._queries[i].tcp_out)[self._queries[i].tcp_sent :],
                MSG_NOSIGNAL,
            )
            if r >= 0:
                self._queries[i].tcp_sent += r
                continue
            var e = Errno(err_of(r))
            if e == Errno.EINTR:
                continue
            if e == Errno.EAGAIN:
                return
            self._fail_try(i, deadline)  # refused, reset, unreachable
            return
        while True:
            var r = sys.recv(
                self._queries[i].tcp.value(), Span(self._rbuf), 0
            )
            if r == 0:
                self._fail_try(i, deadline)  # closed before the answer
                return
            if r < 0:
                var e = Errno(err_of(r))
                if e == Errno.EINTR:
                    continue
                if e == Errno.EAGAIN:
                    return
                self._fail_try(i, deadline)
                return
            self._queries[i].tcp_in.extend(Span(self._rbuf)[0:r])
            var have = len(self._queries[i].tcp_in)
            if have < 2:
                continue
            var need = 2 + (
                (Int(self._queries[i].tcp_in[0]) << 8)
                | Int(self._queries[i].tcp_in[1])
            )
            if have < need:
                continue
            var answer: Optional[DnsAnswer]
            try:
                answer = parse_response(
                    Span(self._queries[i].tcp_in)[2:need],
                    Span(self._queries[i].msg),
                )
            except:
                answer = None
            if not answer:  # TCP has no strays: an unrelated answer fails
                self._fail_try(i, deadline)
                return
            self._answer(i, answer.take(), deadline, from_tcp=True)
            return

    def _drain(mut self, i: Int, deadline: Deadline) raises IoError:
        """Receive the queued datagrams of query `i` until EAGAIN or an
        accepted answer, at most `_MAX_DRAIN` of them: under a stream of
        strays (from the server's address and port, or a spoofer that
        knows ours) it returns to `advance`, whose expiry check then ends
        the try on time instead of reading for as long as they come."""
        var left = _MAX_DRAIN
        while self._queries[i].state == _WAITING and self._queries[i].udp:
            if left == 0:
                return
            left -= 1
            var r = sys.recv(self._queries[i].udp.value(), Span(self._rbuf), 0)
            if is_err(r):
                var e = Errno(err_of(r))
                if e == Errno.EINTR:
                    continue
                if e == Errno.EAGAIN:
                    return
                # ECONNREFUSED (ICMP port unreachable) and the like.
                self._fail_try(i, deadline)
                return
            var answer: Optional[DnsAnswer]
            try:
                answer = parse_response(
                    Span(self._rbuf)[0:r], Span(self._queries[i].msg)
                )
            except:
                # Our ID and question but malformed: a broken server.
                self._fail_try(i, deadline)
                return
            if not answer:
                continue  # not an answer to this query: ignore it
            self._answer(i, answer.take(), deadline, from_tcp=False)
            return

    def _answer(
        mut self, i: Int, var ans: DnsAnswer, deadline: Deadline, from_tcp: Bool
    ) raises IoError:
        """Act on an answer to query `i`'s current try."""
        if ans.truncated:
            if from_tcp:
                self._fail_try(i, deadline)
                return
            # The same server again over TCP (no new exchange after the
            # caller's deadline). The first TCP leg of a try gets a fresh
            # timeout, as Go's resolver gives it; a later one (a server
            # that truncates again after the EDNS fallback) runs within
            # the time left, so a try lasts at most twice `timeout`.
            if deadline.is_expired():
                self._fail_try(i, deadline)
                return
            self._queries[i].close()
            if not self._queries[i].tcp_leg:
                self._queries[i].tcp_leg = True
                self._queries[i].try_deadline = deadline.earliest(
                    Deadline.after(self._timeout)
                )
            if not self._start_tcp(i):
                self._fail_try(i, deadline)
            return
        if (
            ans.rcode == RCODE_FORMERR or ans.rcode == RCODE_NOTIMP
        ) and self._queries[i].edns:
            # Perhaps no EDNS(0) support: the same server, without OPT (no
            # new exchange after the caller's deadline).
            if deadline.is_expired() or not self._send(
                i, False, deadline, new_try=False
            ):
                self._fail_try(i, deadline)
            return
        ref q = self._queries[i]
        if ans.rcode == RCODE_NOERROR and not ans.lame:
            q.state = _DONE
            q.close()
            q.outcome = _OUT_ADDRS
            if len(ans.addrs) > 0:
                self._found = True
                for ip in ans.addrs:
                    self._ready.append(ip)
            return
        if ans.rcode == RCODE_NXDOMAIN:
            q.state = _DONE
            q.close()
            q.outcome = _OUT_NXDOMAIN
            return
        self._fail_try(i, deadline)  # SERVFAIL, REFUSED, lame, ...

    def _settle(mut self, deadline: Deadline) raises IoError:
        """After progress: finish the lookup, or start the next name once
        every query for this one has ended without addresses (not after
        `deadline`)."""
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
            var expired = deadline.is_expired()
            if self._name_i >= len(self._names) or expired:
                self._done = True
                if self._timed_out or expired:
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
                q.close()
                self._next_try(i, deadline)


def _is_local_resource_error(e: IoError) -> Bool:
    """Failures of this process, not of the network or a server: raised."""
    return e.kind == ErrorKind.TooManyFiles or e.kind == ErrorKind.OutOfMemory


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
    def system() -> Resolver:
        """/etc/resolv.conf and /etc/hosts (files that are missing or
        unreadable mean the defaults), read once: a long-lived resolver
        does not see later changes (glibc rereads a changed resolv.conf).
        Make a new one when the network changes (DHCP, a VPN)."""
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
        var listed = _filter(self.hosts.lookup(host), want_v4, want_v6)
        if len(listed) > 0:
            # (Listed, but not in a family asked for: DNS is asked, as glibc's
            # files source answers NOTFOUND for that family.)
            return Lookup(listed^)
        if _is_localhost(host):
            var lo = List[IpAddr]()
            if want_v6:
                lo.append(IpAddr(Ipv6Addr.from_bits(1)))
            if want_v4:
                lo.append(IpAddr(Ipv4Addr(127, 0, 0, 1)))
            return Lookup(lo^)
        var names = search_names(host, self.conf)
        var dns_v6 = want_v6 and not self.conf.no_aaaa
        if not want_v4 and not dns_v6:
            return Lookup(List[IpAddr]())  # (`no-aaaa`, and only IPv6 asked for)
        return Lookup(
            names^,
            self.conf,
            want_v4=want_v4,
            want_v6=dns_v6,
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
        # Each try waits until `deadline` at the latest and no try starts
        # after it, so this loop ends by then; addresses found before it
        # (A answered, AAAA still pending) are returned, not dropped.
        while not lk.is_done():
            var fds = List[Pollfd]()
            lk.poll_fds(fds)
            if len(fds) == 0:
                # Every query waits on a socket while the lookup runs.
                raise IoError.of_kind("resolve", ErrorKind.Other)
            var wake = deadline.earliest(lk.next_deadline())
            _ = poll_until(Span(fds), wake, "resolve")
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
    if compat:
        return 1  # ::/96: IPv4-compatible ::a.b.c.d, and :: itself
    if s[0] == 0 and s[1] == 0 and s[2] == 0 and s[3] == 0 and s[4] == 0 and s[5] == 0xFFFF:
        return 35  # IPv4-mapped ::ffff:0:0/96, as IPv4 itself
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
