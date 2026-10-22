"""Regression tests for review findings in net.addr (fix group net-addr).

- F02: Linux accepts a 108-byte `sun_path` without a NUL. It NUL-terminates
  the path past `sun_path`, inside its `sockaddr_storage`, and reports
  addrlen 111 (> sizeof(sockaddr_un) = 110) from getsockname, getpeername,
  accept4 and recvfrom. `UnixAddr.from_raw` rejected that length, so one
  local peer bound to such a path made `UnixListener.accept` drop the
  connection and raise `InvalidInput`, and `recv_from_unix` lose the
  datagram.
- F07: `SocketAddr.v4()/v6()` and `IpAddr.v4()` checked the family only with
  a plain `debug_assert`, compiled out by default, so `v4()` of an IPv6
  address silently returned its low 32 bits (`[2001:db8::7f00:1]:80` became
  `127.0.0.1:80`). They now abort in every build; `as_v4()`/`as_v6()` are the
  checked accessors that return `None` instead.
- F23: `IpAddr.is_loopback/is_unspecified/is_multicast` answered for an
  IPv4-mapped address (`::ffff:127.0.0.1`, how dual-stack sockets report
  IPv4 peers) as plain IPv6, so loopback/unspecified deny-lists failed open.
  They now classify a mapped address by its IPv4 address (as CPython >= 3.13
  and Go's netip do); `Ipv6Addr`'s predicates stay strict IPv6.

The abort tests re-run this file as a child process (built once with
`mojo build`, or argv[0] itself when this is already a binary) with
MOJO_NET_ADDR_DEATH naming the case: an abort cannot be caught in-process.
"""

from std.os import getenv, listdir, remove, rmdir
from std.python import Python, PythonObject
from std.sys import argv, size_of
from std.tempfile import mkdtemp
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Errno, ErrorKind, IoError, OwnedFd, check
from linux import sys
from linux.abi import SockaddrUn
from linux.consts import (
    AF_INET,
    AF_INET6,
    AF_UNIX,
    IPPROTO_IPV6,
    IPV6_V6ONLY,
    SOCK_CLOEXEC,
    SOCK_STREAM,
)
from linux.nr import SYS_getpid
from linux.syscall import err_of, is_err, syscall0
from linux.time import Deadline, Duration
from net.addr import (
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    RawSockaddr,
    SocketAddr,
    SocketAddrV4,
    SocketAddrV6,
    UnixAddr,
)
from net.socket import Domain, SockType, Socket
from net.unix import UnixListener, UnixStream

comptime _DEATH_ENV = "MOJO_NET_ADDR_DEATH"


# ---- helpers ---------------------------------------------------------------


def _pid() -> Int:
    return syscall0(SYS_getpid)


def _unix_decode_rejects(raw: RawSockaddr) -> Bool:
    try:
        _ = UnixAddr.from_raw(raw)
    except e:
        return e.kind == ErrorKind.InvalidInput
    return False


def _put(mut raw: RawSockaddr, off: Int, v: UInt8):
    Pointer(to=raw.storage).unsafe_bitcast[UInt8]().unsafe_offset(off)[] = v


def _sockname(fd: Socket) raises IoError -> RawSockaddr:
    var raw = RawSockaddr()
    _ = check("getsockname", sys.getsockname(fd, raw.storage, raw.len))
    return raw^


def _path108(dir: String, tag: StaticString) -> String:
    """A pathname of exactly 108 bytes (all of `sun_path`, no room for a
    NUL) inside `dir`."""
    var p = String(dir, "/", tag, "_")
    return p + String("p") * (108 - p.byte_length())


def _raw_pathname_no_nul(path: String) -> RawSockaddr:
    """`sockaddr_un` for a 108-byte `path` with socklen 110 (no NUL), which
    `UnixAddr` itself cannot build but Linux, C and Go clients accept."""
    var raw = RawSockaddr()
    raw.storage.family = UInt16(AF_UNIX)
    var b = path.as_bytes()
    for i in range(len(b)):
        _put(raw, 2 + i, b[i])
    raw.len = UInt32(size_of[SockaddrUn]())
    return raw^


def _bind_108(sock: Socket, path: String) raises IoError:
    var raw = _raw_pathname_no_nul(path)
    _ = check("bind", sys.bind(sock, raw.storage, raw.socklen()))


def _is_path(a: UnixAddr, path: String) -> Bool:
    if not a.is_pathname():
        return False
    var want = path.as_bytes()
    var got = a.name()
    if len(got) != len(want):
        return False
    for i in range(len(want)):
        if got[i] != want[i]:
            return False
    return True


def _abstract(tag: StaticString) raises IoError -> UnixAddr:
    return UnixAddr.from_abstract_name(
        String("mojo_net.addr_regr.", tag, ".", _pid())
    )


def _try_remove(path: String):
    try:
        remove(path)
    except:
        pass


# ---- F02: 108-byte pathnames as the kernel reports them --------------------


def test_f02_unix_from_raw_accepts_kernel_len_111() raises:
    # The kernel form of a 108-byte path: 108 path bytes, a NUL at offset
    # 110 (past sun_path, inside sockaddr_storage), addrlen 111.
    var raw = RawSockaddr()
    raw.storage.family = UInt16(AF_UNIX)
    for i in range(108):
        _put(raw, 2 + i, 0x7A)
    _put(raw, 110, 0)
    raw.len = 111
    var a = UnixAddr.from_raw(raw)
    assert_true(a.is_pathname())
    assert_equal(len(a.name()), 108)
    assert_equal(String(a), String("z") * 108)
    # Re-encoded it is the 110-byte form, which decodes to the same address.
    var again = a.to_raw()
    assert_equal(again.socklen(), 110)
    assert_equal(UnixAddr.from_raw(again), a)
    # Bytes past sun_path never become part of the name, whatever the
    # length says (up to the storage capacity).
    _put(raw, 110, 0x41)
    _put(raw, 111, 0x42)
    raw.len = UInt32(RawSockaddr.capacity())
    assert_equal(UnixAddr.from_raw(raw), a)
    # A shorter path still ends at its first NUL with any length.
    _put(raw, 2 + 5, 0)
    var short = UnixAddr.from_raw(raw)
    assert_equal(String(short), "zzzzz")
    # Still rejected: past the storage, an abstract name longer than
    # sun_path allows, and a truncated family.
    raw.len = UInt32(RawSockaddr.capacity() + 1)
    assert_true(_unix_decode_rejects(raw))
    var abs = UnixAddr.from_abstract_name(String("x") * 107).to_raw()
    assert_equal(abs.socklen(), 110)
    assert_equal(len(UnixAddr.from_raw(abs).name()), 107)
    abs.len = 111
    assert_true(_unix_decode_rejects(abs))
    abs.len = 1
    assert_true(_unix_decode_rejects(abs))


def _rm_tmpdir(dir: String):
    """Remove `dir` and the socket files left in it."""
    try:
        for name in listdir(dir):
            _try_remove(String(dir, "/", name))
        rmdir(dir)
    except:
        pass


def _getsockname_of_108_byte_path(dir: String) raises:
    var path = _path108(dir, "own")
    assert_equal(path.byte_length(), 108)
    var s = Socket.new(Domain.UNIX, SockType.STREAM)
    _bind_108(s, path)
    var got = _sockname(s)
    # What the kernel reports for it: 111 > sizeof(sockaddr_un).
    assert_equal(got.socklen(), 111)
    assert_true(_is_path(UnixAddr.from_raw(got), path))
    assert_true(_is_path(s.local_unix_addr(), path))
    # A listener adopted from such a socket can report its address.
    s.listen(4)
    var l = UnixListener.from_socket(s^)
    assert_true(_is_path(l.local_addr(), path))


def test_f02_kernel_getsockname_of_108_byte_path() raises:
    # The body raises plain `Error`, so this `try` is not typed `IoError`.
    var dir = mkdtemp()
    try:
        _getsockname_of_108_byte_path(dir)
    finally:
        _rm_tmpdir(dir)


def _listener_accepts_108_byte_peer(dir: String) raises:
    var p1 = _path108(dir, "c1")
    var p2 = _path108(dir, "c2")
    var target = _abstract("listen")
    var l = UnixListener.bind(target)
    l.set_deadline(Deadline.after(Duration.from_secs(10)))
    # UnixListener.accept: the connection is kept and the peer decoded.
    var c = Socket.new(Domain.UNIX, SockType.STREAM)
    _bind_108(c, p1)
    c.connect_unix(target)
    var acc = l.accept()
    assert_true(_is_path(acc.addr, p1))
    var server = acc^.into_stream()
    server.set_deadline(Deadline.after(Duration.from_secs(10)))
    assert_true(_is_path(server.peer_addr(), p1))
    assert_true(_is_path(c.local_unix_addr(), p1))
    assert_equal(c.send(String("ping").as_bytes()), 4)
    var buf = List[UInt8](length=4, fill=0)
    server.read_exact(Span(buf))
    assert_equal(String(unsafe_from_utf8=Span(buf)), "ping")
    server.write_all(String("pong").as_bytes())
    assert_equal(c.recv(Span(buf)), 4)
    assert_equal(String(unsafe_from_utf8=Span(buf)), "pong")
    # Socket.accept_unix on the same listener, second such client.
    var c2 = Socket.new(Domain.UNIX, SockType.STREAM)
    _bind_108(c2, p2)
    c2.connect_unix(target)
    var acc2 = l.socket().accept_unix()
    assert_true(_is_path(acc2.addr, p2))
    assert_true(_is_path(acc2.socket.peer_unix_addr(), p2))


def test_f02_listener_accepts_peer_bound_to_108_byte_path() raises:
    # The body raises plain `Error`, so this `try` is not typed `IoError`.
    var dir = mkdtemp()
    try:
        _listener_accepts_108_byte_peer(dir)
    finally:
        _rm_tmpdir(dir)


def _recv_from_108_byte_sender(dir: String) raises:
    var p = _path108(dir, "dg")
    var target = _abstract("dgram")
    var server = Socket.new(Domain.UNIX, SockType.DGRAM)
    server.bind_unix(target)
    var client = Socket.new(Domain.UNIX, SockType.DGRAM)
    _bind_108(client, p)
    assert_equal(client.send_to_unix(String("hello").as_bytes(), target), 5)
    var buf = List[UInt8](length=16, fill=0)
    var got = server.recv_from_unix(Span(buf))
    assert_equal(got[0], 5)
    assert_true(_is_path(got[1], p))
    # The decoded sender works as a reply address (encoded as socklen 110).
    assert_equal(server.send_to_unix(String("ok").as_bytes(), got[1]), 2)
    assert_equal(client.recv(Span(buf)), 2)


def test_f02_recv_from_unix_sender_bound_to_108_byte_path() raises:
    # The body raises plain `Error`, so this `try` is not typed `IoError`.
    var dir = mkdtemp()
    try:
        _recv_from_108_byte_sender(dir)
    finally:
        _rm_tmpdir(dir)


# ---- F07: family accessors are checked ---------------------------------------


def test_f07_as_v4_as_v6_return_none_on_wrong_family() raises:
    var six = SocketAddr.parse("[2001:db8::7f00:1]:80")
    assert_false(Bool(six.as_v4()))
    assert_true(Bool(six.as_v6()))
    assert_equal(
        six.as_v6().value(), SocketAddrV6.parse("[2001:db8::7f00:1]:80")
    )
    var four = SocketAddr.parse("127.0.0.1:80")
    assert_false(Bool(four.as_v6()))
    assert_equal(four.as_v4().value(), SocketAddrV4.parse("127.0.0.1:80"))
    # The checked accessors keep flowinfo and scope id.
    var scoped = SocketAddr(SocketAddrV6(Ipv6Addr.LOCALHOST, 9, 7, 3))
    var back = scoped.as_v6().value()
    assert_equal(back.flowinfo(), 7)
    assert_equal(back.scope_id(), 3)
    # IpAddr.
    var ip6 = IpAddr.parse("::7f00:1")
    assert_false(Bool(ip6.as_v4()))
    assert_equal(ip6.as_v6().value(), Ipv6Addr.parse("::7f00:1"))
    var ip4 = IpAddr.parse("10.0.0.5")
    assert_equal(ip4.as_v4().value(), Ipv4Addr(10, 0, 0, 5))
    assert_false(Bool(ip4.as_v6()))
    # An IPv4-mapped IPv6 address is IPv6 (Rust semantics; fold it with
    # to_canonical first).
    var mapped = IpAddr.parse("::ffff:10.0.0.5")
    assert_false(Bool(mapped.as_v4()))
    assert_equal(mapped.to_canonical().as_v4().value(), Ipv4Addr(10, 0, 0, 5))
    # v4() and v6() still work on the right family.
    assert_equal(four.v4(), SocketAddrV4.parse("127.0.0.1:80"))
    assert_equal(six.v6().ip(), Ipv6Addr.parse("2001:db8::7f00:1"))
    assert_equal(ip4.v4(), Ipv4Addr(10, 0, 0, 5))
    # IpAddr.v6() is total: an IPv4 address gives its mapped form.
    assert_equal(ip4.v6(), Ipv6Addr.parse("::ffff:10.0.0.5"))


def _death_child(mode: String) raises:
    """Runs in the child: each case must abort before printing SURVIVED."""
    if mode == "socketaddr_v4":
        var a = SocketAddr.parse("[2001:db8::7f00:1]:80")
        print("SURVIVED", a.v4())
    elif mode == "socketaddr_v6":
        var a = SocketAddr.parse("127.0.0.1:80")
        print("SURVIVED", a.v6())
    elif mode == "ipaddr_v4":
        var a = IpAddr.parse("::7f00:1")
        print("SURVIVED", a.v4())
    elif mode == "control":
        print("SURVIVED control")
    else:
        print("unknown death mode", mode)


def _death_runner(tmp: String) raises -> PythonObject:
    """argv for running this program as a child: argv[0] itself when it is a
    built binary, else a binary built from this source file into `tmp`."""
    var os = Python.import_module("os")
    var shutil = Python.import_module("shutil")
    var subprocess = Python.import_module("subprocess")
    var me = String(argv()[0])
    if not me.endswith(".mojo"):
        return Python.list(me)
    var path = os.path.abspath(me)
    var root = os.path.dirname(os.path.dirname(os.path.dirname(path)))
    var src = os.path.join(root, "src")
    var mojo = shutil.which("mojo")
    assert_true(Bool(mojo), "mojo not on PATH (run under pixi)")
    var out = os.path.join(tmp, "addr_death_child")
    var r = subprocess.run(
        Python.list(mojo, "build", "-I", src, "-o", out, path),
        capture_output=True,
        text=True,
        timeout=600,
    )
    if Int(py=r.returncode) != 0:
        print(r.stdout, r.stderr)
    assert_equal(Int(py=r.returncode), 0, "building the death-test child")
    return Python.list(out)


def _run_child(runner: PythonObject, mode: StaticString) raises -> PythonObject:
    var os = Python.import_module("os")
    var subprocess = Python.import_module("subprocess")
    var env = os.environ.copy()
    env[_DEATH_ENV] = mode
    return subprocess.run(
        runner, env=env, capture_output=True, text=True, timeout=120
    )


def test_f07_wrong_family_accessors_abort_in_default_build() raises:
    var tmp = mkdtemp()
    try:
        _check_wrong_family_aborts(tmp)
    finally:
        _ = Python.import_module("shutil").rmtree(tmp, ignore_errors=True)


def _check_wrong_family_aborts(tmp: String) raises:
    var runner = _death_runner(tmp)
    # The harness itself works: the control case survives.
    var ok = _run_child(runner, "control")
    assert_equal(Int(py=ok.returncode), 0)
    assert_true("SURVIVED control" in String(py=ok.stdout))
    var cases: List[StaticString] = [
        "socketaddr_v4",
        "socketaddr_v6",
        "ipaddr_v4",
    ]
    var msgs: List[StaticString] = [
        "SocketAddr.v4() on an IPv6 address",
        "SocketAddr.v6() on an IPv4 address",
        "IpAddr.v4() on an IPv6 address",
    ]
    for i in range(len(cases)):
        var r = _run_child(runner, cases[i])
        var out = String(py=r.stdout) + String(py=r.stderr)
        assert_false("SURVIVED" in out, String(cases[i], " returned: ", out))
        assert_true(Int(py=r.returncode) != 0, String(cases[i], ": exit 0"))
        assert_true(msgs[i] in out, String(cases[i], ": ", out))


# ---- F23: IpAddr classifies IPv4-mapped addresses by their IPv4 address ------


def test_f23_ipaddr_predicates_unmap_ipv4_mapped() raises:
    assert_true(IpAddr.parse("::ffff:127.0.0.1").is_loopback())
    assert_true(IpAddr.parse("::ffff:127.200.0.9").is_loopback())
    assert_true(IpAddr.parse("::ffff:0.0.0.0").is_unspecified())
    assert_true(IpAddr.parse("::ffff:224.0.0.1").is_multicast())
    assert_true(IpAddr.parse("::ffff:239.255.255.255").is_multicast())
    assert_false(IpAddr.parse("::ffff:10.0.0.1").is_loopback())
    assert_false(IpAddr.parse("::ffff:10.0.0.1").is_unspecified())
    assert_false(IpAddr.parse("::ffff:10.0.0.1").is_multicast())
    # ::ffff:0:1 is mapped 0.0.0.1: neither IPv6 loopback nor unspecified.
    assert_false(IpAddr.parse("::ffff:0:1").is_loopback())
    assert_false(IpAddr.parse("::ffff:0:1").is_unspecified())
    # Through SocketAddr.ip(), as a server sees a dual-stack peer.
    assert_true(SocketAddr.parse("[::ffff:127.0.0.1]:80").ip().is_loopback())
    # Only ::ffff:0:0/96 is mapped: IPv4-compatible and NAT64 forms are not.
    assert_false(IpAddr.parse("::127.0.0.1").is_loopback())
    assert_false(IpAddr.parse("64:ff9b::127.0.0.1").is_loopback())
    # Plain answers are unchanged.
    assert_true(IpAddr.parse("::1").is_loopback())
    assert_true(IpAddr.parse("::").is_unspecified())
    assert_true(IpAddr.parse("ff02::1").is_multicast())
    assert_true(IpAddr.parse("127.0.0.1").is_loopback())
    assert_true(IpAddr.parse("0.0.0.0").is_unspecified())
    assert_true(IpAddr.parse("224.0.0.1").is_multicast())
    assert_false(IpAddr.parse("8.8.8.8").is_loopback())
    # Ipv6Addr stays strict IPv6 (documented), and equality is unchanged.
    assert_false(Ipv6Addr.parse("::ffff:127.0.0.1").is_loopback())
    assert_true(IpAddr.parse("::ffff:127.0.0.1") != IpAddr.parse("127.0.0.1"))


def _have_ipv6_sockets(test: StaticString) raises -> Bool:
    """Whether socket(AF_INET6) works, decided with a raw syscall. Without
    it this prints a skip line and the test returns early, unless
    MOJO_NET_REQUIRE_IPV6=1 makes that a failure."""
    var r = sys.socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0)
    if not is_err(r):
        _ = OwnedFd(unsafe_from_raw=Int32(r))
        return True
    if Errno(err_of(r)) != Errno.EAFNOSUPPORT:
        _ = check("socket(AF_INET6)", r)
    if getenv("MOJO_NET_REQUIRE_IPV6") == "1":
        raise Error(test, ": no IPv6 but MOJO_NET_REQUIRE_IPV6=1")
    print(String("    (skipped: ", test, ": no IPv6, EAFNOSUPPORT)"))
    return False


def test_f23_dual_stack_ipv4_loopback_peer_is_loopback() raises:
    # A v4 client of a dual-stack v6 listener shows up as ::ffff:127.0.0.1;
    # the peer is the loopback host and IpAddr must say so.
    if not _have_ipv6_sockets(
        "test_f23_dual_stack_ipv4_loopback_peer_is_loopback"
    ):
        return
    var l = Socket.new(Domain.IPV6, SockType.STREAM)
    var off: Int32 = 0
    _ = check(
        "setsockopt", sys.setsockopt(l, IPPROTO_IPV6, IPV6_V6ONLY, off, 4)
    )
    l.bind(SocketAddr.parse("[::]:0"))
    l.listen(4)
    var port = l.local_addr().port()
    var c = Socket.new(Domain.IPV4, SockType.STREAM)
    c.connect(SocketAddr(IpAddr(Ipv4Addr.LOCALHOST), port))
    var acc = l.accept()
    var peer = acc.addr
    assert_true(peer.is_ipv6())
    assert_true(peer.ip().is_loopback())
    assert_false(peer.ip().is_unspecified())
    assert_false(peer.ip().is_multicast())


def main() raises:
    var mode = getenv(_DEATH_ENV)
    if mode.byte_length() > 0:
        _death_child(mode)
        return
    TestSuite.discover_tests[__functions_in_module()]().run()
