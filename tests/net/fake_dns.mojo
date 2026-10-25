"""A scripted DNS server for the resolver tests (not a test file itself).

`FakeDns()` starts a separate Python process (test-only Python) serving
two "servers" on 127.0.0.1, each on one UDP and one TCP port with the same
number. Answers depend on the query name (see `_SERVER`), so each test
picks its scenario by name. The process is killed when the `FakeDns` is
destroyed. The wire format here is written independently of `net.dns`."""

from std.python import Python, PythonObject

from linux.time import Deadline, Duration
from net.addr import IpAddr, SocketAddr
from net.resolv import Hosts, ResolvConf
from net.resolver import Resolver

comptime _SERVER = """
import socket, struct, sys, threading, time

A, AAAA, CNAME = 1, 28, 5

def wire(name):
    out = b''
    for label in name.split('.'):
        out += bytes([len(label)]) + label.encode()
    return out + b'\\0'

def rr(name, rtype, rdata, ttl=60):
    return wire(name) + struct.pack('!HHIH', rtype, 1, ttl, len(rdata)) + rdata

def a(ip):
    return rr_data(socket.AF_INET, ip)

def rr_data(family, ip):
    return socket.inet_pton(family, ip)

def reply(qid, question, rcode=0, answers=(), tc=False, qd=True, flags=0x8180, auth=()):
    flags = flags | rcode | (0x0200 if tc else 0)
    head = qid + struct.pack('!HHHHH', flags, 1 if qd else 0, len(answers), len(auth), 0)
    return head + (question if qd else b'') + b''.join(answers) + b''.join(auth)

SEEN = {}  # (server, name) -> queries seen, UDP and TCP

def parse(data):
    qid = data[0:2]
    ar = struct.unpack('!H', data[10:12])[0]
    pos, labels = 12, []
    while data[pos]:
        n = data[pos]
        labels.append(data[pos + 1:pos + 1 + n].decode().lower())
        pos += 1 + n
    pos += 1
    qtype = struct.unpack('!H', data[pos:pos + 2])[0]
    return qid, '.'.join(labels), qtype, data[12:pos + 4], ar > 0

def v4(name, ip):
    return rr(name, A, socket.inet_pton(socket.AF_INET, ip))

def v6(name, ip):
    return rr(name, AAAA, socket.inet_pton(socket.AF_INET6, ip))

BLACK_HOLE = [(3600, b'')]  # TCP: accept, then never answer

def answer(server, tcp, data):
    # A list of (delay seconds, bytes); [] sends nothing; None closes (TCP).
    qid, name, qtype, q, edns = parse(data)
    ok = lambda *rrs: [(0, reply(qid, q, 0, rrs))]
    if name.startswith('count.'):
        n = SEEN.get((server, name[6:]), 0)
        return ok(v4(name, '10.0.%d.%d' % (n >> 8, n & 255))) if qtype == A else ok()
    SEEN[(server, name)] = SEEN.get((server, name), 0) + 1
    if name == 'tcblack.test':
        if qtype == AAAA:  # arrives while A's TCP retry is under way
            return [(0.05, reply(qid, q, 0, (v6(name, '2001:db8::5'),)))]
        return BLACK_HOLE if tcp else [(0, reply(qid, q, 0, (), tc=True))]
    if name == 'tcstall.test':
        if qtype == A:
            return ok(v4(name, '127.0.0.1'))
        return BLACK_HOLE if tcp else [(0, reply(qid, q, 0, (), tc=True))]
    if name in ('lame.test', 'authnodata.test'):
        if server == 0:
            if name == 'lame.test':  # QR RD only: not authoritative, not recursive
                ns = rr('test', 2, wire('ns.elsewhere'))
                return [(0, reply(qid, q, 0, (), flags=0x8100, auth=(ns,)))]
            soa = rr('test', 6, wire('ns.test') + wire('host.test') + struct.pack('!IIIII', 1, 2, 3, 4, 5))
            return [(0, reply(qid, q, 0, (), flags=0x8500, auth=(soa,)))]  # QR AA RD
        return ok(v4(name, '192.0.2.30')) if qtype == A else ok()
    if name == 'noedns.test':
        if edns:
            return [(0, reply(qid, q, 1))]  # FORMERR
        return ok(v4(name, '192.0.2.78')) if qtype == A else ok()
    if name == 'ok.test':
        return ok(v4(name, '192.0.2.1')) if qtype == A else ok(v6(name, '2001:db8::1'))
    if name == 'v4only.test':
        return ok(v4(name, '192.0.2.4')) if qtype == A else ok()
    if name == 'nodata.test':
        return ok()
    if name in ('nx.test', 'db', 'nx.svc.test', 'nx'):
        return [(0, reply(qid, q, 3))]
    if name == 'db.svc.test':
        return ok(v4(name, '192.0.2.20')) if qtype == A else ok()
    if name == 'cname.test':
        chain = rr(name, CNAME, wire('mid.test')), rr('mid.test', CNAME, wire('target.test'))
        if qtype == A:
            return ok(*(chain + (v4('target.test', '192.0.2.7'),)))
        return ok(*chain)
    if name == 'big.test':
        if qtype != A:
            return ok()
        if not tcp:
            return [(0, reply(qid, q, 0, (), tc=True))]
        return ok(*[v4(name, '10.0.0.%d' % i) for i in range(1, 41)])
    if name == 'edns.test':
        if qtype != A:
            return ok()
        if tcp:
            return None
        if not edns:
            return [(0, reply(qid, q, 0, (), tc=True))]
        return ok(*[v4(name, '10.0.1.%d' % i) for i in range(1, 31)])
    if name in ('servfail.test', 'refused.test', 'garbage.test', 'formerr.test', 'drop0.test'):
        if server == 0:
            if name == 'servfail.test':
                return [(0, reply(qid, q, 2))]
            if name == 'refused.test':
                return [(0, reply(qid, q, 5))]
            if name == 'formerr.test':
                return [(0, reply(qid, q, 1, qd=False))]
            if name == 'garbage.test':
                bad = wire(name) + struct.pack('!HHIH', A, 1, 60, 200) + b'xx'
                return [(0, reply(qid, q, 0, (bad,)))]
            return []  # drop0: server 0 never answers
        return ok(v4(name, '192.0.2.9')) if qtype == A else ok()
    if name == 'drop.test':
        return []
    if name == 'junk.test':  # 200 strays with the wrong ID, and no answer
        if qtype != A:
            return ok()
        wrong_id = bytes([qid[0], qid[1] ^ 0xFF])
        return [(0, reply(wrong_id, q, 0, (v4(name, '6.6.6.6'),)))] * 200
    if name == 'loop.test':
        return ok(v4(name, '127.0.0.1')) if qtype == A else ok(v6(name, '::1'))
    if name == 'slowaaaa.test':
        if qtype == A:
            return ok(v4(name, '127.0.0.1'))
        return [(2.0, reply(qid, q, 0, (v6(name, '::1'),)))]
    if name == 'slowa.test':
        if qtype == A:
            return [(0.3, reply(qid, q, 0, (v4(name, '127.0.0.1'),)))]
        return ok(v6(name, '::1'))
    if name == 'slow.test':
        if qtype == A:
            return [(0.3, reply(qid, q, 0, (v4(name, '192.0.2.13'),)))]
        return [(0.4, reply(qid, q, 0, (v6(name, '2001:db8::13'),)))]
    if name == 'spoof.test':
        if qtype != A:
            return ok()
        wrong_id = bytes([qid[0], qid[1] ^ 0xFF])
        _, _, _, evil_q, _ = parse(b'\\0' * 12 + wire('evil.test') + struct.pack('!HH', A, 1))
        return [(0, reply(wrong_id, q, 0, (v4(name, '6.6.6.6'),))),
                (0, reply(qid, evil_q, 0, (v4('evil.test', '6.6.6.7'),))),
                (0.05, reply(qid, q, 0, (v4(name, '192.0.2.14'),)))]
    return [(0, reply(qid, q, 3))]

def send_later(delay, fn, data):
    if delay:
        threading.Timer(delay, fn, (data,)).start()
    else:
        fn(data)

def serve_udp(server, sock):
    while True:
        data, peer = sock.recvfrom(4096)
        try:
            out = answer(server, False, data) or []
        except Exception:
            continue
        for delay, msg in out:
            send_later(delay, lambda m, p=peer: sock.sendto(m, p), msg)

def serve_tcp_conn(server, conn):
    with conn:
        try:
            head = conn.recv(2, socket.MSG_WAITALL)
            n = struct.unpack('!H', head)[0]
            data = conn.recv(n, socket.MSG_WAITALL)
            out = answer(server, True, data)
            if out is None:
                return
            for delay, msg in out:
                time.sleep(delay)
                conn.sendall(struct.pack('!H', len(msg)) + msg)
        except Exception:
            pass

def serve_tcp(server, lsock):
    while True:
        conn, _ = lsock.accept()
        threading.Thread(target=serve_tcp_conn, args=(server, conn), daemon=True).start()

ports = []
for server in (0, 1):
    while True:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind(('127.0.0.1', 0))
        port = u.getsockname()[1]
        t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            t.bind(('127.0.0.1', port))
        except OSError:
            u.close(); t.close()
            continue
        t.listen(64)
        break
    ports.append(port)
    threading.Thread(target=serve_udp, args=(server, u), daemon=True).start()
    threading.Thread(target=serve_tcp, args=(server, t), daemon=True).start()
print('PORTS', ports[0], ports[1], flush=True)
while True:
    time.sleep(3600)
"""


struct FakeDns(Movable):
    var proc: PythonObject
    var ports: List[Int]

    def __init__(out self) raises:
        var subprocess = Python.import_module("subprocess")
        var pysys = Python.import_module("sys")
        self.proc = subprocess.Popen(
            Python.list(pysys.executable, "-c", _SERVER),
            stdout=subprocess.PIPE,
            text=True,
        )
        var line = String(py=self.proc.stdout.readline())
        var words = line.split()
        if len(words) != 3 or String(words[0]) != "PORTS":
            raise Error("fake DNS server did not start")
        self.ports = List[Int]()
        self.ports.append(atol(words[1]))
        self.ports.append(atol(words[2]))

    def __deinit__(deinit self):
        _kill(self.proc)

    def stop(deinit self):
        """Kill the server. End every test with `dns^.stop()`: Mojo
        destroys a value right after its last use, which would otherwise
        kill the server as soon as the test stops mentioning it."""
        _kill(self.proc)

    def server(self, i: Int) raises -> SocketAddr:
        return SocketAddr.parse(String("127.0.0.1:", self.ports[i]))

    def conf(self, timeout_secs: Int = 1, attempts: Int = 1) raises -> ResolvConf:
        """Both servers, in order, without search domains."""
        var c = ResolvConf()
        c.nameservers.append(self.server(0))
        c.nameservers.append(self.server(1))
        c.timeout = Duration.from_secs(timeout_secs)
        c.attempts = attempts
        return c^

    def resolver(self, timeout_secs: Int = 1, attempts: Int = 1) raises -> Resolver:
        return Resolver(self.conf(timeout_secs, attempts), Hosts())

    def count(self, server: Int, name: StringSlice) raises -> Int:
        """How many queries server `server` has seen for `name` (its
        `count.<name>` answer encodes the number in an IPv4 address)."""
        var c = ResolvConf()
        c.nameservers.append(self.server(server))
        var r = Resolver(c^, Hosts())
        var ips = r.lookup_ip(
            String("count.", name),
            Deadline.after(Duration.from_secs(5)),
            want_v6=False,
        )
        var o = ips[0].v4().octets()
        return Int(o[2]) * 256 + Int(o[3])


def _kill(proc: PythonObject):
    try:
        _ = proc.kill()
        _ = proc.wait()
    except:
        pass
