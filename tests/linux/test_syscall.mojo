from std.testing import TestSuite, assert_equal, assert_false, assert_raises, assert_true

from linux import Errno, ErrorKind, IoError, OwnedFd, check
from linux.consts import AF_INET, AF_INET6, SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_STREAM
from linux.nr import SYS_close, SYS_getpid, SYS_socket
from linux.syscall import err_of, is_err, syscall0, syscall1, syscall3


def _socket(flags: Int) raises IoError -> OwnedFd:
    var r = check("socket", syscall3(SYS_socket, AF_INET, SOCK_STREAM | flags, 0))
    return OwnedFd(unsafe_from_raw=Int32(r))


def test_getpid_positive() raises:
    assert_true(syscall0(SYS_getpid) > 0)


def test_error_decoding() raises:
    assert_true(is_err(-1))
    assert_true(is_err(-4095))
    assert_false(is_err(-4096))
    assert_false(is_err(0))
    assert_equal(err_of(-9), 9)


def test_close_bad_fd_is_ebadf() raises:
    var r = syscall1(SYS_close, 1_000_000)
    assert_true(is_err(r))
    assert_true(Errno(err_of(r)) == Errno.EBADF)
    assert_true(ErrorKind.of(Errno.EBADF) == ErrorKind.Closed)


def test_invalid_family_raises_typed_error() raises:
    var raised = False
    try:
        _ = check("socket", syscall3(SYS_socket, 9999, SOCK_STREAM, 0))
    except e:
        raised = True
        assert_true(e.errno == Errno.EAFNOSUPPORT)
        assert_true(e.kind == ErrorKind.InvalidInput)
        assert_equal(String(e.op), "socket")
    assert_true(raised)


def test_socket_flags_applied() raises:
    var fd = _socket(SOCK_NONBLOCK | SOCK_CLOEXEC)
    assert_true(fd.raw_fd() >= 0)
    assert_true(fd.is_cloexec())
    assert_true(fd.is_nonblocking())
    fd.set_nonblocking(False)
    assert_false(fd.is_nonblocking())
    fd^.close()


def test_clone_is_cloexec_and_distinct() raises:
    var a = _socket(0)
    var b = a.try_clone()
    assert_true(a.raw_fd() != b.raw_fd())
    assert_true(b.is_cloexec())
    a^.close()
    b^.close()


def test_drop_closes() raises:
    var fd = _socket(SOCK_CLOEXEC)
    var raw = fd.raw_fd()
    _ = fd^
    var r = syscall1(SYS_close, Int(raw))
    assert_true(is_err(r) and Errno(err_of(r)) == Errno.EBADF)


def test_into_raw_keeps_open() raises:
    var fd = _socket(SOCK_CLOEXEC)
    var raw = fd^.into_raw()
    assert_equal(syscall1(SYS_close, Int(raw)), 0)


def test_error_message() raises:
    var e = IoError.from_errno("connect", Errno.ECONNREFUSED)
    assert_equal(String(e), "connect: ConnectionRefused (ECONNREFUSED(111))")
    var t = IoError.of_kind("read", ErrorKind.TimedOut)
    assert_equal(String(t), "read: TimedOut")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
