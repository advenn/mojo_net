from std.sys import size_of
from std.testing import TestSuite, assert_equal, assert_true

from linux import Errno, OwnedFd, check
from linux import sys
from linux.abi import Ifreq, Iovec, Msghdr, SockaddrStorage
from linux.consts import (
    AF_UNIX,
    FIONREAD,
    SIOCGIFINDEX,
    SOCK_DGRAM,
    MSG_DONTWAIT,
    MSG_NOSIGNAL,
    MSG_PEEK,
    SHUT_WR,
    SO_TYPE,
    SOCK_CLOEXEC,
    SOCK_STREAM,
    SOL_SOCKET,
    AF_INET,
    SO_REUSEADDR,
    F_GETFD,
)
from linux.syscall import err_of, is_err


def _pair() raises -> Tuple[OwnedFd, OwnedFd]:
    var fds = Array[Int32, 2](fill=-1)
    _ = check("socketpair", sys.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds))
    return (OwnedFd(unsafe_from_raw=fds[0]), OwnedFd(unsafe_from_raw=fds[1]))


def test_send_recv_roundtrip() raises:
    var p = _pair()
    var msg = String("ping").as_bytes()
    assert_equal(check("send", sys.send(p[0], msg, MSG_NOSIGNAL)), 4)
    var buf = List[UInt8](length=16, fill=0)
    var n = check("recv", sys.recv(p[1], Span(buf), 0))
    assert_equal(n, 4)
    assert_equal(Int(buf[0]), ord("p"))
    assert_equal(Int(buf[3]), ord("g"))


def test_recv_dontwait_is_eagain() raises:
    var p = _pair()
    var buf = List[UInt8](length=4, fill=0)
    var r = sys.recv(p[1], Span(buf), MSG_DONTWAIT)
    assert_true(is_err(r) and Errno(err_of(r)) == Errno.EAGAIN)


def test_peek_then_read() raises:
    var p = _pair()
    _ = check("send", sys.send(p[0], String("abc").as_bytes(), MSG_NOSIGNAL))
    var buf = List[UInt8](length=8, fill=0)
    assert_equal(check("peek", sys.recv(p[1], Span(buf), MSG_PEEK)), 3)
    assert_equal(check("recv", sys.recv(p[1], Span(buf), 0)), 3)


def test_sendmsg_vectored() raises:
    var p = _pair()
    var a = String("head:").as_bytes()
    var b = String("body").as_bytes()
    var iov = List[Iovec](capacity=2)
    iov.append(Iovec(Int(a.unsafe_ptr()), UInt(len(a))))
    iov.append(Iovec(Int(b.unsafe_ptr()), UInt(len(b))))
    var m = Msghdr(0, 0, Int(iov.unsafe_ptr()), UInt(2), 0, UInt(0), 0)
    var n = check("sendmsg", sys.sendmsg(p[0], m, MSG_NOSIGNAL))
    sys.keep_alive(iov)
    sys.keep_alive(a)
    sys.keep_alive(b)
    assert_equal(n, 9)
    var buf = List[UInt8](length=16, fill=0)
    assert_equal(check("recv", sys.recv(p[1], Span(buf), 0)), 9)
    assert_equal(Int(buf[4]), ord(":"))
    assert_equal(Int(buf[5]), ord("b"))


def test_half_close_gives_eof() raises:
    var p = _pair()
    _ = check("shutdown", sys.shutdown(p[0], SHUT_WR))
    var buf = List[UInt8](length=4, fill=0)
    assert_equal(check("recv", sys.recv(p[1], Span(buf), 0)), 0)


def test_getsockopt_int() raises:
    var p = _pair()
    var v: Int32 = 0
    var vlen = UInt32(size_of[Int32]())
    _ = check("getsockopt", sys.getsockopt(p[0], SOL_SOCKET, SO_TYPE, v, vlen))
    assert_equal(Int(v), SOCK_STREAM)
    assert_equal(Int(vlen), 4)


def test_setsockopt_roundtrip() raises:
    var fd = OwnedFd(unsafe_from_raw=Int32(check("socket", sys.socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0))))
    var one: Int32 = 1
    _ = check("setsockopt", sys.setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, one, 4))
    var got: Int32 = 0
    var glen = UInt32(4)
    _ = check("getsockopt", sys.getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, got, glen))
    assert_equal(got, 1)


def test_getsockname_unix() raises:
    var p = _pair()
    var ss = SockaddrStorage.zeroed()
    var len = UInt32(size_of[SockaddrStorage]())
    _ = check("getsockname", sys.getsockname(p[0], ss, len))
    assert_equal(Int(ss.family), AF_UNIX)


def test_ioctl_ref_int_and_struct() raises:
    var p = _pair()
    _ = check("send", sys.send(p[0], String("abc").as_bytes(), MSG_NOSIGNAL))
    var queued: Int32 = -1
    _ = check("ioctl(FIONREAD)", sys.ioctl_ref(p[1], FIONREAD, queued))
    assert_equal(queued, 3)
    # A struct argument the kernel reads (name) and writes (ifindex).
    var fd = OwnedFd(unsafe_from_raw=Int32(check("socket", sys.socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0))))
    var req = Ifreq()
    req.name[0] = UInt8(ord("l"))
    req.name[1] = UInt8(ord("o"))
    _ = check("ioctl(SIOCGIFINDEX)", sys.ioctl_ref(fd, SIOCGIFINDEX, req))
    assert_true(req.ifindex > 0)
    var bad = Ifreq()
    bad.name[0] = UInt8(ord("?"))
    var r = sys.ioctl_ref(fd, SIOCGIFINDEX, bad)
    assert_true(is_err(r) and Errno(err_of(r)) == Errno.ENODEV)


def test_owner_outlives_syscall_when_last_use() raises:
    # Regression: Mojo destroys values right after their last use. With raw
    # numbers, `fcntl(owner.raw_fd(), ...)` as the owner's last use closed the
    # fd before the syscall ran (EBADF). Wrappers borrow the owner instead.
    var fd = OwnedFd(unsafe_from_raw=Int32(check("socket", sys.socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0))))
    assert_true(sys.fcntl(fd, F_GETFD) >= 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
