# Fault-injection seam tests. Needs `-D MOJO_TCP_FAULTS=1`; tools/run_tests.sh
# passes it because the file name ends in `_faults.mojo`. Without it the
# `linux.fault` calls below fail to compile, so the faults can't be silently
# missing.
#
# The plan is process-global and TestSuite runs every test in one process:
# each test starts with `fault.clear()`.

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Errno, ErrorKind, IoError, OwnedFd, RawFd, check, fault, sys
from linux.consts import (
    AF_INET,
    AF_UNIX,
    F_GETFD,
    FD_CLOEXEC,
    MSG_DONTWAIT,
    MSG_NOSIGNAL,
    O_CLOEXEC,
    SO_REUSEADDR,
    SOCK_CLOEXEC,
    SOCK_STREAM,
    SOL_SOCKET,
)
from linux.nr import (
    SYS_bind,
    SYS_close,
    SYS_getpid,
    SYS_listen,
    SYS_read,
    SYS_recvfrom,
    SYS_recvmsg,
    SYS_sendmsg,
    SYS_sendto,
    SYS_setsockopt,
    SYS_socket,
    SYS_socketpair,
    SYS_write,
)
from linux.syscall import err_of, is_err, syscall0, syscall1


# ---- helpers ---------------------------------------------------------------


def _socket() raises IoError -> OwnedFd:
    var r = check("socket", sys.socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0))
    return OwnedFd(unsafe_from_raw=Int32(r))


def _pair() raises IoError -> Tuple[OwnedFd, OwnedFd]:
    var fds = Array[Int32, 2](fill=-1)
    _ = check(
        "socketpair",
        sys.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds),
    )
    return (OwnedFd(unsafe_from_raw=fds[0]), OwnedFd(unsafe_from_raw=fds[1]))


def _pipe() raises IoError -> Tuple[OwnedFd, OwnedFd]:
    var fds = Array[Int32, 2](fill=-1)
    _ = check("pipe2", sys.pipe2(fds, O_CLOEXEC))
    return (OwnedFd(unsafe_from_raw=fds[0]), OwnedFd(unsafe_from_raw=fds[1]))


def _err(op: StaticString, ret: Int) -> Optional[IoError]:
    """The IoError `check` raises for `ret`, or None if it does not raise."""
    try:
        _ = check(op, ret)
        return None
    except e:
        return e


def _errno(ret: Int) -> Int:
    """`ret` as a signed errno: 0 for success, else the errno."""
    return Int(err_of(ret)) if is_err(ret) else 0


def _text(buf: List[UInt8], n: Int) -> String:
    var s = String()
    for i in range(n):
        s += chr(Int(buf[i]))
    return s


def _recv_now(fd: OwnedFd, cap: Int = 64) raises -> String:
    """Everything queued on `fd` right now (one non-blocking recv)."""
    var buf = List[UInt8](length=cap, fill=0)
    var n = check("recv", sys.recv(fd, Span(buf), MSG_DONTWAIT))
    return _text(buf, n)


def _expect(op: StaticString, ret: Int) raises -> IoError:
    """The IoError `check` raises for `ret`; fails the test if none."""
    var e = _err(op, ret)
    assert_true(Bool(e), String(op) + " did not fail")
    return e.value()


def _assert_invalid(e: Optional[IoError], op: String) raises:
    assert_true(Bool(e), "expected InvalidInput from " + op)
    assert_true(e.value().kind == ErrorKind.InvalidInput)
    assert_true(e.value().errno == Errno(0))
    assert_equal(String(e.value().op), op)


# ---- the scenarios from the task -------------------------------------------


def test_enabled_in_this_build() raises:
    assert_true(fault.ENABLED)


def test_emfile_on_second_socket_only() raises:
    fault.clear()
    fault.inject(SYS_socket, Errno.EMFILE, skip=1, times=1)
    var first = _socket()
    var second = _expect(
        "socket", sys.socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)
    )
    var third = _socket()
    assert_true(second.kind == ErrorKind.TooManyFiles)
    assert_true(second.errno == Errno.EMFILE)
    assert_equal(String(second.op), "socket")
    # The real calls around the fault are untouched: real, distinct fds.
    assert_true(first.raw_fd() >= 0 and third.raw_fd() >= 0)
    assert_true(first.raw_fd() != third.raw_fd())
    assert_true(first.is_cloexec() and third.is_cloexec())
    assert_equal(fault.calls(SYS_socket), 3)
    assert_equal(fault.pending(), 0)
    # Later calls stay real.
    var fourth = _socket()
    assert_true(fourth.raw_fd() >= 0)
    assert_equal(fault.calls(SYS_socket), 4)
    first^.close()
    third^.close()
    fourth^.close()


def test_eintr_then_success_on_recv() raises:
    fault.clear()
    var p = _pair()
    _ = check("send", sys.send(p[0], String("data").as_bytes(), MSG_NOSIGNAL))
    fault.inject(SYS_recvfrom, Errno.EINTR, times=2)
    var buf = List[UInt8](length=16, fill=0)
    var interrupted = 0
    var n: Int
    # The explicit EINTR loop every blocking recv must have.
    while True:
        try:
            n = check("recv", sys.recv(p[1], Span(buf), 0))
            break
        except e:
            assert_true(e.kind == ErrorKind.Interrupted, String(e))
            assert_true(e.errno == Errno.EINTR)
            assert_equal(String(e.op), "recv")
            interrupted += 1
            assert_true(interrupted <= 2, "EINTR fired more often than planned")
    assert_equal(interrupted, 2)
    # The injected EINTRs never reached the kernel: no data was consumed.
    assert_equal(n, 4)
    assert_equal(_text(buf, n), "data")
    assert_equal(fault.calls(SYS_recvfrom), 3)
    assert_equal(fault.pending(), 0)


def test_short_sendto_delivers_partial_data() raises:
    fault.clear()
    var p = _pair()
    fault.inject_short(SYS_sendto, 3)
    var text = String("hello world")
    var msg = text.as_bytes()
    assert_equal(check("send", sys.send(p[0], msg, MSG_NOSIGNAL)), 3)
    # Exactly the first 3 bytes reached the peer, nothing more.
    assert_equal(_recv_now(p[1]), "hel")
    var buf = List[UInt8](length=8, fill=0)
    var r = sys.recv(p[1], Span(buf), MSG_DONTWAIT)
    assert_equal(_errno(r), Int(Errno.EAGAIN.value))
    # The rule is spent: the rest goes out whole.
    assert_equal(check("send", sys.send(p[0], msg[3:], MSG_NOSIGNAL)), 8)
    assert_equal(_recv_now(p[1]), "lo world")
    assert_equal(fault.calls(SYS_sendto), 2)


def test_short_sendto_forever_forces_a_send_all_loop() raises:
    fault.clear()
    var p = _pair()
    fault.inject_short(SYS_sendto, 4, times=-1)
    var text = String("hello world")
    var msg = text.as_bytes()
    var off = 0
    var sizes = List[Int]()
    while off < len(msg):
        var n = check("send", sys.send(p[0], msg[off:], MSG_NOSIGNAL))
        assert_true(n > 0)
        sizes.append(n)
        off += n
    assert_equal(len(sizes), 3)
    assert_equal(sizes[0], 4)
    assert_equal(sizes[1], 4)
    assert_equal(sizes[2], 3)
    assert_equal(_recv_now(p[1]), "hello world")
    assert_equal(fault.calls(SYS_sendto), 3)
    assert_equal(fault.pending(), 1)


def test_short_recv_leaves_the_rest_queued() raises:
    fault.clear()
    var p = _pair()
    _ = check("send", sys.send(p[0], String("abcdef").as_bytes(), MSG_NOSIGNAL))
    fault.inject_short(SYS_recvfrom, 2)
    var buf = List[UInt8](length=16, fill=0)
    var n = check("recv", sys.recv(p[1], Span(buf), 0))
    assert_equal(n, 2)
    assert_equal(_text(buf, n), "ab")
    assert_equal(_recv_now(p[1]), "cdef")


def test_short_limit_above_length_changes_nothing() raises:
    fault.clear()
    var p = _pair()
    fault.inject_short(SYS_sendto, 1000)
    assert_equal(
        check("send", sys.send(p[0], String("12345").as_bytes(), MSG_NOSIGNAL)),
        5,
    )
    assert_equal(_recv_now(p[1]), "12345")
    # It still fired (and is used up), it just had nothing to clamp.
    assert_equal(fault.pending(), 0)


def test_short_write_and_zero_length_read_on_a_pipe() raises:
    fault.clear()
    var p = _pipe()
    fault.inject_short(SYS_write, 1)
    assert_equal(check("write", sys.write(p[1], String("xyz").as_bytes())), 1)
    # max_bytes=0: the read returns 0 although data is queued (looks like EOF).
    fault.inject_short(SYS_read, 0)
    var buf = List[UInt8](length=8, fill=0)
    assert_equal(check("read", sys.read(p[0], Span(buf))), 0)
    var n = check("read", sys.read(p[0], Span(buf)))
    assert_equal(n, 1)
    assert_equal(_text(buf, n), "x")
    assert_equal(fault.calls(SYS_write), 1)
    assert_equal(fault.calls(SYS_read), 2)


def test_every_second_send_is_eagain() raises:
    fault.clear()
    var p = _pair()
    fault.inject(SYS_sendto, Errno.EAGAIN, every=2, times=-1)
    var text = String("abcdef")
    var letters = text.as_bytes()
    var failed = List[Int]()
    for i in range(6):
        var e = _err("send", sys.send(p[0], letters[i : i + 1], MSG_NOSIGNAL))
        if e:
            assert_true(e.value().kind == ErrorKind.WouldBlock)
            assert_true(e.value().errno == Errno.EAGAIN)
            failed.append(i + 1)
    assert_equal(len(failed), 3)
    assert_equal(failed[0], 2)
    assert_equal(failed[1], 4)
    assert_equal(failed[2], 6)
    # Failed calls were never issued: only the 1st, 3rd and 5th byte arrived.
    assert_equal(_recv_now(p[1]), "ace")
    assert_equal(fault.calls(SYS_sendto), 6)
    assert_equal(fault.pending(), 1)


def test_clear_restores_normal_behaviour() raises:
    fault.clear()
    fault.inject(SYS_socket, Errno.EMFILE, times=-1)
    fault.inject_short(SYS_sendto, 1, times=-1)
    for _ in range(3):
        var e = _expect(
            "socket", sys.socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)
        )
        assert_true(e.kind == ErrorKind.TooManyFiles)
    assert_equal(fault.calls(SYS_socket), 3)
    fault.clear()
    assert_equal(fault.pending(), 0)
    assert_equal(fault.calls(SYS_socket), 0)
    var s = _socket()
    assert_true(s.raw_fd() >= 0)
    var p = _pair()
    assert_equal(
        check("send", sys.send(p[0], String("whole").as_bytes(), MSG_NOSIGNAL)),
        5,
    )
    assert_equal(_recv_now(p[1]), "whole")
    assert_equal(fault.calls(SYS_socket), 1)
    s^.close()


def test_counts_are_per_syscall_and_exact() raises:
    fault.clear()
    for _ in range(3):
        assert_true(syscall0(SYS_getpid) > 0)
    var a = _socket()
    var b = _socket()
    var p = _pair()
    a^.close()
    b^.close()
    _ = syscall1(SYS_close, 1_000_000)  # failing real calls count too
    assert_equal(fault.calls(SYS_getpid), 3)
    assert_equal(fault.calls(SYS_socket), 2)
    assert_equal(fault.calls(SYS_socketpair), 1)
    assert_equal(fault.calls(SYS_close), 3)
    assert_equal(fault.calls(SYS_bind), 0)
    assert_equal(fault.calls(SYS_sendto), 0)
    # Numbers without a counter read as 0 instead of failing.
    assert_equal(fault.calls(-1), 0)
    assert_equal(fault.calls(1024), 0)
    assert_equal(fault.calls(1 << 40), 0)
    _ = p^


def test_every_syscall_arity_is_hooked() raises:
    fault.clear()
    # syscall0
    fault.inject(SYS_getpid, Errno.EPERM)
    assert_equal(syscall0(SYS_getpid), -1)
    # syscall1: the injected errno replaces the real EBADF.
    fault.inject(SYS_close, Errno.EIO)
    assert_equal(syscall1(SYS_close, 1_000_000), -Int(Errno.EIO.value))
    assert_equal(_errno(syscall1(SYS_close, 1_000_000)), Int(Errno.EBADF.value))
    var s = _socket()
    # syscall2
    fault.inject(SYS_listen, Errno.EADDRINUSE)
    assert_true(_expect("listen", sys.listen(s, 1)).kind == ErrorKind.AddrInUse)
    # syscall4: the kernel never ran, so it wrote no fds.
    fault.inject(SYS_socketpair, Errno.ENFILE)
    var fds = Array[Int32, 2](fill=-7)
    var r = sys.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds)
    assert_equal(_errno(r), Int(Errno.ENFILE.value))
    assert_equal(Int(fds[0]), -7)
    assert_equal(Int(fds[1]), -7)
    # syscall5
    fault.inject(SYS_setsockopt, Errno.ENOPROTOOPT)
    var one: Int32 = 1
    var se = _expect(
        "setsockopt", sys.setsockopt(s, SOL_SOCKET, SO_REUSEADDR, one, 4)
    )
    assert_true(se.kind == ErrorKind.Unsupported)
    assert_equal(
        check(
            "setsockopt", sys.setsockopt(s, SOL_SOCKET, SO_REUSEADDR, one, 4)
        ),
        0,
    )
    # syscall6
    var p = _pair()
    fault.inject(SYS_sendto, Errno.EPIPE)
    var pe = _expect(
        "send", sys.send(p[0], String("x").as_bytes(), MSG_NOSIGNAL)
    )
    assert_true(pe.kind == ErrorKind.BrokenPipe)
    assert_true(pe.errno == Errno.EPIPE)
    # syscall3 (socket) is covered by test_emfile_on_second_socket_only.
    assert_equal(fault.pending(), 0)
    s^.close()


def test_injected_errnos_decode_to_their_kinds() raises:
    fault.clear()
    var errnos: List[Errno] = [
        Errno.EAGAIN,
        Errno.EINTR,
        Errno.ETIMEDOUT,
        Errno.ECONNREFUSED,
        Errno.ECONNRESET,
        Errno.EPIPE,
        Errno.EMFILE,
        Errno.ENOMEM,
        Errno.EBADF,
        Errno.EINVAL,
        Errno(4095),
    ]
    var kinds: List[ErrorKind] = [
        ErrorKind.WouldBlock,
        ErrorKind.Interrupted,
        ErrorKind.TimedOut,
        ErrorKind.ConnectionRefused,
        ErrorKind.ConnectionReset,
        ErrorKind.BrokenPipe,
        ErrorKind.TooManyFiles,
        ErrorKind.OutOfMemory,
        ErrorKind.Closed,
        ErrorKind.InvalidInput,
        ErrorKind.Other,
    ]
    for i in range(len(errnos)):
        fault.inject(SYS_getpid, errnos[i])
        var e = _expect("getpid", syscall0(SYS_getpid))
        assert_true(e.errno == errnos[i])
        assert_true(e.kind == kinds[i], String(e))
        assert_equal(String(e.op), "getpid")
    # Back to the real result.
    assert_false(Bool(_err("getpid", syscall0(SYS_getpid))))


def test_skip_and_every_combined() raises:
    fault.clear()
    fault.inject(SYS_getpid, Errno.EPERM, skip=2, every=3, times=2)
    var failed = List[Int]()
    for i in range(1, 13):
        if is_err(syscall0(SYS_getpid)):
            failed.append(i)
    # Past the 2 skipped calls, every 3rd call fails, twice: calls 5 and 8.
    assert_equal(len(failed), 2)
    assert_equal(failed[0], 5)
    assert_equal(failed[1], 8)
    assert_equal(fault.pending(), 0)


def test_times_forever() raises:
    fault.clear()
    fault.inject(SYS_getpid, Errno.EPERM, times=-1)
    for _ in range(100):
        assert_equal(syscall0(SYS_getpid), -1)
    assert_equal(fault.calls(SYS_getpid), 100)
    assert_equal(fault.pending(), 1)


def test_first_rule_wins_and_a_shadowed_rule_keeps_its_budget() raises:
    fault.clear()
    fault.inject(SYS_getpid, Errno.EPERM)
    fault.inject(SYS_getpid, Errno.EIO)
    assert_equal(_errno(syscall0(SYS_getpid)), Int(Errno.EPERM.value))
    assert_equal(_errno(syscall0(SYS_getpid)), Int(Errno.EIO.value))
    assert_true(syscall0(SYS_getpid) > 0)
    assert_equal(fault.pending(), 0)


def test_schedules_count_calls_independently() raises:
    fault.clear()
    # The second rule counts the call the first one fails: its skip of 1 is
    # used up by call 1, so it fires on call 2.
    fault.inject(SYS_getpid, Errno.EPERM)
    fault.inject(SYS_getpid, Errno.EIO, skip=1)
    assert_equal(_errno(syscall0(SYS_getpid)), Int(Errno.EPERM.value))
    assert_equal(_errno(syscall0(SYS_getpid)), Int(Errno.EIO.value))
    assert_equal(_errno(syscall0(SYS_getpid)), 0)


def test_rules_for_other_syscalls_do_not_interfere() raises:
    fault.clear()
    fault.inject(SYS_recvfrom, Errno.ECONNRESET, times=-1)
    fault.inject(SYS_recvmsg, Errno.ECONNRESET, times=-1)
    var p = _pair()
    assert_equal(
        check("send", sys.send(p[0], String("ok").as_bytes(), MSG_NOSIGNAL)), 2
    )
    assert_true(syscall0(SYS_getpid) > 0)
    var buf = List[UInt8](length=8, fill=0)
    var e = _expect("recv", sys.recv(p[1], Span(buf), 0))
    assert_true(e.kind == ErrorKind.ConnectionReset)
    # read(2) is a different syscall and still reaches the queued bytes.
    assert_equal(check("read", sys.read(p[1], Span(buf))), 2)
    assert_equal(fault.calls(SYS_recvfrom), 1)
    assert_equal(fault.calls(SYS_sendto), 1)
    assert_equal(fault.calls(SYS_sendmsg), 0)


def test_injected_close_error_leaves_the_fd_open() raises:
    # Injection replaces the syscall; unlike a real close, the fd survives.
    fault.clear()
    var s = _socket()
    var raw = s.raw_fd()
    fault.inject(SYS_close, Errno.EIO)
    var raised = False
    try:
        s^.close()
    except e:
        raised = True
        assert_true(e.errno == Errno.EIO)
        assert_equal(String(e.op), "close")
    assert_true(raised)
    var flags = check("fcntl", sys.fcntl(RawFd(raw), F_GETFD))
    assert_true((flags & FD_CLOEXEC) != 0)
    # EINTR on close counts as closed in OwnedFd.close, so the injected one
    # is swallowed and the fd is still open (a leak only fault builds see).
    var t = OwnedFd(unsafe_from_raw=raw)
    fault.inject(SYS_close, Errno.EINTR)
    t^.close()
    assert_true(sys.fcntl(RawFd(raw), F_GETFD) >= 0)
    assert_equal(syscall1(SYS_close, Int(raw)), 0)
    assert_equal(_errno(sys.fcntl(RawFd(raw), F_GETFD)), Int(Errno.EBADF.value))


def _scenario() raises -> List[Int]:
    """One fixed sequence of calls; returns each call's errno (0 = ok)."""
    fault.clear()
    fault.inject(SYS_socket, Errno.EMFILE, every=3, times=-1)
    fault.inject(SYS_getpid, Errno.EPERM, skip=1, times=2)
    fault.inject_short(SYS_sendto, 2, skip=1, every=2, times=-1)
    var out = List[Int]()
    var p = _pair()
    for _ in range(10):
        var r = sys.socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)
        out.append(_errno(r))
        if not is_err(r):
            _ = OwnedFd(unsafe_from_raw=Int32(r))
        out.append(_errno(syscall0(SYS_getpid)))
        out.append(sys.send(p[0], String("abcd").as_bytes(), MSG_NOSIGNAL))
    _ = p^
    return out^


def test_same_plan_replays_identically() raises:
    var first = _scenario()
    var second = _scenario()
    assert_equal(len(first), 30)
    assert_equal(len(first), len(second))
    for i in range(len(first)):
        assert_equal(first[i], second[i], "diverged at call " + String(i))
    # Spot-check the schedule itself (round k uses indexes 3k, 3k+1, 3k+2):
    # socket fails in rounds 2, 5, 8; getpid in rounds 1 and 2; send is cut
    # to 2 bytes in rounds 2, 4, 6, 8 (skip 1, then every 2nd).
    var emfile = Int(Errno.EMFILE.value)
    var eperm = Int(Errno.EPERM.value)
    for k in range(10):
        assert_equal(first[3 * k], emfile if k % 3 == 2 else 0)
        assert_equal(first[3 * k + 1], eperm if k == 1 or k == 2 else 0)
        assert_equal(first[3 * k + 2], 2 if k % 2 == 0 and k > 0 else 4)


def test_invalid_rules_are_rejected() raises:
    fault.clear()
    var cases = List[Optional[IoError]]()
    for nr in [-1, 1024, 1 << 40]:
        try:
            fault.inject(nr, Errno.EIO)
            cases.append(None)
        except e:
            cases.append(e)
    for v in [0, -5, 4096, 100000]:
        try:
            fault.inject(SYS_getpid, Errno(Int32(v)))
            cases.append(None)
        except e:
            cases.append(e)
    try:
        fault.inject(SYS_getpid, Errno.EIO, skip=-1)
        cases.append(None)
    except e:
        cases.append(e)
    try:
        fault.inject(SYS_getpid, Errno.EIO, every=0)
        cases.append(None)
    except e:
        cases.append(e)
    try:
        fault.inject(SYS_getpid, Errno.EIO, every=-3)
        cases.append(None)
    except e:
        cases.append(e)
    try:
        fault.inject(SYS_getpid, Errno.EIO, times=0)
        cases.append(None)
    except e:
        cases.append(e)
    try:
        fault.inject(SYS_getpid, Errno.EIO, times=-2)
        cases.append(None)
    except e:
        cases.append(e)
    for c in cases:
        _assert_invalid(c, "fault.inject")
    assert_equal(len(cases), 12)

    var short = List[Optional[IoError]]()
    for nr in [SYS_socket, SYS_sendmsg, SYS_recvmsg, SYS_getpid, -1]:
        try:
            fault.inject_short(nr, 10)
            short.append(None)
        except e:
            short.append(e)
    try:
        fault.inject_short(SYS_sendto, -1)
        short.append(None)
    except e:
        short.append(e)
    try:
        fault.inject_short(SYS_sendto, 10, every=0)
        short.append(None)
    except e:
        short.append(e)
    for c in short:
        _assert_invalid(c, "fault.inject_short")
    # Nothing was added, and syscalls are untouched.
    assert_equal(fault.pending(), 0)
    assert_true(syscall0(SYS_getpid) > 0)


def test_valid_edge_values_are_accepted() raises:
    fault.clear()
    fault.inject(0, Errno(1))
    fault.inject(1023, Errno(4095), skip=1_000_000, every=1_000_000, times=-1)
    fault.inject_short(SYS_recvfrom, 0)
    assert_equal(fault.pending(), 3)
    fault.clear()
    assert_equal(fault.pending(), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
