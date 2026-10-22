from std.python import Python, PythonObject
from std.sys import CompilationTarget, align_of, size_of
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import AsFd, Errno, ErrorKind, OwnedFd, RawFd, check
from linux import sys
from linux.abi import EpollEvent, Timespec
from linux.consts import (
    AF_UNIX,
    CLOCK_MONOTONIC,
    EPOLLERR,
    EPOLLEXCLUSIVE,
    EPOLLET,
    EPOLLHUP,
    EPOLLIN,
    EPOLLONESHOT,
    EPOLLOUT,
    EPOLLRDHUP,
    F_GETFD,
    FD_CLOEXEC,
    MSG_DONTWAIT,
    MSG_NOSIGNAL,
    SHUT_WR,
    SIGALRM,
    SIGEV_THREAD_ID,
    SOCK_CLOEXEC,
    SOCK_NONBLOCK,
    SOCK_STREAM,
)
from linux.epoll import (
    MAX_TIMEOUT_MS,
    Epoll,
    epoll_pwait,
    epoll_pwait2,
    epoll_timeout_ms,
)
from linux.eventfd import EventFd
from linux.nr import (
    SYS_clock_gettime,
    SYS_getpid,
    SYS_gettid,
    SYS_timer_create,
    SYS_timer_delete,
    SYS_timer_settime,
)
from linux.probe import raise_nofile_limit
from linux.syscall import (
    err_of,
    is_err,
    syscall0,
    syscall1,
    syscall2,
    syscall3,
    syscall4,
)

# Mojo destroys a value right after its last use, and closing an fd silently
# removes it from every epoll set. Each test therefore ends with
# `sys.keep_alive(...)` on the owners it registered.

comptime IN = UInt32(EPOLLIN)
comptime OUT = UInt32(EPOLLOUT)
comptime ET = UInt32(EPOLLET)
comptime ONESHOT = UInt32(EPOLLONESHOT)
comptime RDHUP = UInt32(EPOLLRDHUP)
comptime HUP = UInt32(EPOLLHUP)
comptime ERR = UInt32(EPOLLERR)
comptime MS = 1_000_000


# ---- helpers -------------------------------------------------------------


struct _SignalBurst:
    """`count` SIGALRMs aimed at this thread, `gap_ms` apart, the first one
    `first_ms` from now (test-only; the library installs no handlers).

    - One-shot POSIX timers with SIGEV_THREAD_ID: a process-directed signal
      (setitimer, kill) may be taken by any runtime thread that does not
      block it, and would then interrupt nothing.
    - The handler is CPython's C-level one (installed without SA_RESTART
      through Python interop), so the interrupted syscall fails with EINTR.
    - Several signals: if this thread is delayed past the first one (CPU
      throttling, VM steal), it is handled before the blocking call starts
      and a later one still interrupts the call.
    - A bounded burst: a wait that wrongly restarted its full timeout after
      EINTR still ends (and fails its timing check) instead of hanging."""

    var timers: List[Int32]
    var signal: PythonObject
    var counter: PythonObject

    def __init__(
        out self, first_ms: Int, count: Int = 5, gap_ms: Int = 20
    ) raises:
        self.signal = Python.import_module("signal")
        self.counter = Python.evaluate("[0]")
        var make = Python.evaluate(
            "lambda c: (lambda s, f: c.__setitem__(0, c[0] + 1))"
        )
        _ = self.signal.signal(SIGALRM, make(self.counter))
        self.timers = List[Int32]()
        var tid = syscall0(SYS_gettid)
        for _ in range(count):
            # struct sigevent (64 bytes): sigev_value at 0, sigev_signo at
            # 8, sigev_notify at 12, _tid at 16.
            var sev = Array[Int32, 16](fill=0)
            sev[2] = Int32(SIGALRM)
            sev[3] = Int32(SIGEV_THREAD_ID)
            sev[4] = Int32(tid)
            var id: Int32 = -1
            _ = check(
                "timer_create",
                syscall3(
                    SYS_timer_create,
                    CLOCK_MONOTONIC,
                    Int(Pointer(to=sev)),
                    Int(Pointer(to=id)),
                ),
            )
            sys.keep_alive(sev)
            self.timers.append(id)
        for i in range(count):
            # struct itimerspec: it_interval (0: one-shot), it_value.
            var spec = Array[Int, 4](fill=0)
            var ns = (first_ms + i * gap_ms) * 1_000_000
            spec[2] = ns // 1_000_000_000
            spec[3] = ns % 1_000_000_000
            _ = check(
                "timer_settime",
                syscall4(
                    SYS_timer_settime,
                    Int(self.timers[i]),
                    0,
                    Int(Pointer(to=spec)),
                    0,
                ),
            )
            sys.keep_alive(spec)

    def stop(mut self) raises -> Int:
        """Delete the timers, run the pending Python handler, restore
        SIG_DFL. Returns how often the handler ran: CPython coalesces
        signals that arrive before it runs, so this is >= 1 when any
        arrived, not the number of signals."""
        for t in self.timers:
            _ = check("timer_delete", syscall1(SYS_timer_delete, Int(t)))
        self.timers.clear()
        _ = Python.evaluate("[i for i in range(3)]")  # runs pending handlers
        _ = self.signal.signal(SIGALRM, self.signal.SIG_DFL)
        return Int(py=self.counter[0])

    def __deinit__(deinit self):
        # A test that raised before stop(): disarm what is left.
        for t in self.timers:
            _ = syscall1(SYS_timer_delete, Int(t))



def _pair_fds() raises -> Array[Int32, 2]:
    var fds = Array[Int32, 2](fill=-1)
    _ = check(
        "socketpair",
        sys.socketpair(
            AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, fds
        ),
    )
    return fds^


def _pair() raises -> Tuple[OwnedFd, OwnedFd]:
    var fds = _pair_fds()
    return (OwnedFd(unsafe_from_raw=fds[0]), OwnedFd(unsafe_from_raw=fds[1]))


def _send(fd: OwnedFd, s: String) raises:
    _ = check("send", sys.send(fd, s.as_bytes(), MSG_NOSIGNAL | MSG_DONTWAIT))


def _drain_socket(fd: OwnedFd) raises -> Int:
    """Read until EAGAIN; return the byte count."""
    var buf = List[UInt8](length=65536, fill=0)
    var total = 0
    while True:
        var r = sys.recv(fd, Span(buf), MSG_DONTWAIT)
        if is_err(r):
            assert_true(Errno(err_of(r)) == Errno.EAGAIN)
            return total
        if r == 0:
            return total
        total += r


def _now_ns() -> Int:
    var ts = Timespec(0, 0)
    _ = syscall2(SYS_clock_gettime, CLOCK_MONOTONIC, Int(Pointer(to=ts)))
    return ts.sec * 1_000_000_000 + ts.nsec


def _events_buf(cap: Int) -> List[EpollEvent]:
    return List[EpollEvent](capacity=cap)


def _add_errno[F: AsFd](ep: Epoll, fd: F, ev: UInt32) -> Errno:
    try:
        ep.add(fd, ev, 0)
    except e:
        return e.errno
    return Errno(0)


def _mod_errno[F: AsFd](ep: Epoll, fd: F, ev: UInt32) -> Errno:
    try:
        ep.modify(fd, ev, 0)
    except e:
        return e.errno
    return Errno(0)


def _del_errno[F: AsFd](ep: Epoll, fd: F) -> Errno:
    try:
        ep.delete(fd)
    except e:
        return e.errno
    return Errno(0)


def _ensure_nofile(need: Int) raises:
    """Raise the soft RLIMIT_NOFILE (test-only) so 1000 socketpairs fit."""
    var soft = raise_nofile_limit(UInt64(need))
    assert_true(soft >= UInt64(need), "hard RLIMIT_NOFILE too low for test")


# ---- layout: the List buffer is the kernel's epoll_event array ----------


def test_event_list_is_contiguous_kernel_array() raises:
    comptime if CompilationTarget.is_x86():
        assert_equal(size_of[EpollEvent](), 12)
    else:
        assert_equal(size_of[EpollEvent](), 16)
    var evs = _events_buf(4)
    evs.append(EpollEvent(1, 0x1122334455667788))
    evs.append(EpollEvent(2, 0x99AABBCCDDEEFF00))
    var p = evs.unsafe_ptr()
    # Element stride equals sizeof(struct epoll_event): no padding between.
    assert_equal(Int(p.unsafe_offset(1)) - Int(p), size_of[EpollEvent]())
    var b = p.unsafe_bitcast[UInt8]()
    comptime data_off = 4 if CompilationTarget.is_x86() else 8
    var stride = size_of[EpollEvent]()
    assert_equal(Int(b.unsafe_offset(0)[]), 1)  # events (LE)
    assert_equal(Int(b.unsafe_offset(data_off)[]), 0x88)
    assert_equal(Int(b.unsafe_offset(data_off + 7)[]), 0x11)
    assert_equal(Int(b.unsafe_offset(stride)[]), 2)
    assert_equal(Int(b.unsafe_offset(stride + data_off)[]), 0x00)
    assert_equal(Int(b.unsafe_offset(stride + data_off + 7)[]), 0x99)
    assert_true(align_of[EpollEvent]() <= 8)


def test_kernel_writes_at_most_span_length() raises:
    # The raw wrapper passes len(span) as maxevents: entries past it must
    # stay untouched even when more fds are ready.
    var ep = Epoll.new()
    var efds = List[EventFd]()
    for i in range(5):
        var e = EventFd.new()
        e.signal()
        ep.add(e, IN, UInt64(100 + i))
        efds.append(e^)
    var evs = _events_buf(8)
    for _ in range(8):
        evs.append(EpollEvent(0xFFFF, 0xABCDABCDABCDABCD))
    var r = epoll_pwait(ep, Span(evs)[0:2], 0)
    assert_equal(r, 2)
    for i in range(2):
        assert_equal(evs[i].events(), IN)
        assert_true(evs[i].data() >= 100 and evs[i].data() < 105)
    for i in range(2, 8):
        assert_equal(evs[i].events(), UInt32(0xFFFF))
        assert_equal(evs[i].data(), UInt64(0xABCDABCDABCDABCD))
    sys.keep_alive(efds)  # registered fds must outlive the waits


# ---- lifecycle ------------------------------------------------------------


def test_epoll_fd_is_cloexec() raises:
    var ep = Epoll.new()
    assert_true(ep.raw_fd() >= 0)
    var fl = check("fcntl", sys.fcntl(ep, F_GETFD))
    assert_true((fl & FD_CLOEXEC) != 0)
    ep^.close()


def test_drop_closes_epoll_fd() raises:
    var ep = Epoll.new()
    var n = ep.raw_fd()
    var owned = ep^.into_fd()
    assert_equal(owned.raw_fd(), n)
    owned^.close()
    var r = sys.fcntl(RawFd(n), F_GETFD)
    assert_true(is_err(r) and Errno(err_of(r)) == Errno.EBADF)


# ---- readiness semantics --------------------------------------------------


def test_level_triggered_repeats_until_drained() raises:
    var ep = Epoll.new()
    var p = _pair()
    ep.add(p[1], IN, 7)
    var evs = _events_buf(4)
    assert_equal(ep.wait(evs, 0), 0)
    _send(p[0], "x")
    for _ in range(3):  # level-triggered: reported on every wait
        assert_equal(ep.wait(evs, 0), 1)
        assert_equal(len(evs), 1)
        assert_equal(evs[0].events(), IN)
        assert_equal(evs[0].data(), UInt64(7))
    assert_equal(_drain_socket(p[1]), 1)
    assert_equal(ep.wait(evs, 0), 0)
    assert_equal(len(evs), 0)
    sys.keep_alive(p)  # registered fds must outlive the waits


def test_edge_triggered_fires_once_until_drained() raises:
    var ep = Epoll.new()
    var p = _pair()
    ep.add(p[1], IN | ET, 9)
    var evs = _events_buf(4)
    _send(p[0], "abc")
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].events(), IN)
    # Data still unread, but no new edge: nothing more.
    assert_equal(ep.wait(evs, 0), 0)
    assert_equal(ep.wait(evs, 0), 0)
    # A partial read does not re-arm either.
    var one = List[UInt8](length=1, fill=0)
    assert_equal(check("recv", sys.recv(p[1], Span(one), MSG_DONTWAIT)), 1)
    assert_equal(ep.wait(evs, 0), 0)
    # Drain to EAGAIN, then new data is a new edge.
    assert_equal(_drain_socket(p[1]), 2)
    assert_equal(ep.wait(evs, 0), 0)
    _send(p[0], "d")
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].data(), UInt64(9))
    assert_equal(ep.wait(evs, 0), 0)
    sys.keep_alive(p)  # registered fds must outlive the waits


def test_oneshot_requires_rearm_via_modify() raises:
    var ep = Epoll.new()
    var p = _pair()
    ep.add(p[1], IN | ONESHOT, 1)
    var evs = _events_buf(4)
    _send(p[0], "x")
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].data(), UInt64(1))
    # Disarmed: still readable, but silent.
    assert_equal(ep.wait(evs, 0), 0)
    # Still registered: add is EEXIST, modify re-arms (with new data).
    assert_true(_add_errno(ep, p[1], IN) == Errno.EEXIST)
    ep.modify(p[1], IN | ONESHOT, 2)
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].data(), UInt64(2))
    assert_equal(ep.wait(evs, 0), 0)
    sys.keep_alive(p)  # registered fds must outlive the waits


def test_rdhup_on_peer_shutdown_wr() raises:
    var ep = Epoll.new()
    var p = _pair()
    ep.add(p[1], IN | RDHUP, 3)
    var evs = _events_buf(4)
    assert_equal(ep.wait(evs, 0), 0)
    _ = check("shutdown", sys.shutdown(p[0], SHUT_WR))
    assert_equal(ep.wait(evs, 0), 1)
    var e = evs[0].events()
    assert_true((e & RDHUP) != 0)
    assert_true((e & IN) != 0)  # EOF is readable
    assert_equal(e & HUP, UInt32(0))  # only half closed
    assert_equal(evs[0].data(), UInt64(3))
    sys.keep_alive(p)  # registered fds must outlive the waits


def test_rdhup_not_reported_unless_requested() raises:
    var ep = Epoll.new()
    var p = _pair()
    ep.add(p[1], IN, 3)
    _ = check("shutdown", sys.shutdown(p[0], SHUT_WR))
    var evs = _events_buf(4)
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].events(), IN)
    sys.keep_alive(p)  # registered fds must outlive the waits


def test_hup_after_peer_close_even_without_interest() raises:
    var ep = Epoll.new()
    var fds = _pair_fds()
    var a = OwnedFd(unsafe_from_raw=fds[0])
    var b = OwnedFd(unsafe_from_raw=fds[1])
    ep.add(b, UInt32(0), 0xDEAD)  # no interest: HUP/ERR are always reported
    var evs = _events_buf(4)
    assert_equal(ep.wait(evs, 0), 0)
    a^.close()
    assert_equal(ep.wait(evs, 0), 1)
    assert_true((evs[0].events() & HUP) != 0)
    assert_equal(evs[0].events() & IN, UInt32(0))  # IN was not requested
    assert_equal(evs[0].data(), UInt64(0xDEAD))
    # Level-triggered HUP persists.
    assert_equal(ep.wait(evs, 0), 1)
    ep.modify(b, IN, 0xBEEF)
    assert_equal(ep.wait(evs, 0), 1)
    assert_true((evs[0].events() & (HUP | IN)) == (HUP | IN))
    assert_equal(evs[0].data(), UInt64(0xBEEF))
    sys.keep_alive(b)  # registered fds must outlive the waits


def test_epollout_tracks_send_buffer_space() raises:
    var ep = Epoll.new()
    var p = _pair()
    ep.add(p[0], IN | OUT, 5)
    var evs = _events_buf(4)
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].events(), OUT)  # writable, nothing to read
    # Fill the send buffer until EAGAIN: no longer writable.
    var chunk = List[UInt8](length=65536, fill=0x5A)
    var sent = 0
    while True:
        var r = sys.send(p[0], Span(chunk), MSG_NOSIGNAL | MSG_DONTWAIT)
        if is_err(r):
            assert_true(Errno(err_of(r)) == Errno.EAGAIN)
            break
        sent += r
    assert_true(sent > 0)
    assert_equal(ep.wait(evs, 0), 0)
    # Peer drains: writable again.
    assert_equal(_drain_socket(p[1]), sent)
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].events(), OUT)
    sys.keep_alive(p)  # registered fds must outlive the waits


def test_data_u64_roundtrips_including_high_bits() raises:
    var values: List[UInt64] = [
        0xDEADBEEFCAFEBABE,
        0,
        1,
        0xFFFFFFFF,
        0x1_0000_0000,
        0x8000_0000_0000_0000,
        0xFFFF_FFFF_FFFF_FFFF,
    ]
    var ep = Epoll.new()
    var efds = List[EventFd]()
    for i in range(len(values)):
        var e = EventFd.new()
        e.signal()
        ep.add(e, IN, values[i])
        efds.append(e^)
    # All in one wait: the kernel writes consecutive entries; every one must
    # decode at the right stride.
    var evs = _events_buf(16)
    assert_equal(ep.wait(evs, 0), len(values))
    for i in range(len(values)):
        var hits = 0
        for j in range(len(evs)):
            if evs[j].data() == values[i]:
                hits += 1
                assert_equal(evs[j].events(), IN)
        assert_equal(hits, 1)
    # Modify carries a new 64-bit value too.
    ep.modify(efds[0], IN, 0x0123456789ABCDEF)
    for _ in range(len(values)):
        _ = efds[0].drain()
    for i in range(1, len(values)):
        _ = efds[i].drain()
    efds[0].signal()
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].data(), UInt64(0x0123456789ABCDEF))
    sys.keep_alive(efds)  # registered fds must outlive the waits


def test_modify_replaces_interest_and_data() raises:
    var ep = Epoll.new()
    var p = _pair()
    _send(p[0], "x")  # p[1] is readable and writable
    ep.add(p[1], IN, 1)
    var evs = _events_buf(4)
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].events(), IN)
    ep.modify(p[1], OUT, 2)
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].events(), OUT)
    assert_equal(evs[0].data(), UInt64(2))
    ep.modify(p[1], UInt32(0), 3)  # no interest: silent while connected
    assert_equal(ep.wait(evs, 0), 0)
    ep.modify(p[1], IN | OUT, 4)
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].events(), IN | OUT)
    assert_equal(evs[0].data(), UInt64(4))
    sys.keep_alive(p)  # registered fds must outlive the waits


def test_no_events_after_delete() raises:
    var ep = Epoll.new()
    var p = _pair()
    ep.add(p[1], IN, 1)
    _send(p[0], "x")
    var evs = _events_buf(4)
    assert_equal(ep.wait(evs, 0), 1)
    ep.delete(p[1])
    assert_equal(ep.wait(evs, 0), 0)
    _send(p[0], "y")  # more data after delete: still nothing
    assert_equal(ep.wait(evs, 0), 0)
    assert_true(_del_errno(ep, p[1]) == Errno.ENOENT)
    assert_true(_mod_errno(ep, p[1], IN) == Errno.ENOENT)
    # Re-adding after delete works.
    ep.add(p[1], IN, 2)
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].data(), UInt64(2))
    sys.keep_alive(p)  # registered fds must outlive the waits


def test_double_add_is_eexist() raises:
    var ep = Epoll.new()
    var p = _pair()
    ep.add(p[1], IN, 1)
    var raised = False
    try:
        ep.add(p[1], OUT, 2)
    except e:
        raised = True
        assert_true(e.errno == Errno.EEXIST)
        assert_equal(String(e.op), "epoll_ctl(ADD)")
    assert_true(raised)
    # The original registration is unchanged.
    _send(p[0], "x")
    var evs = _events_buf(4)
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(evs[0].events(), IN)
    assert_equal(evs[0].data(), UInt64(1))
    sys.keep_alive(p)  # registered fds must outlive the waits


def test_delete_unregistered_is_enoent() raises:
    var ep = Epoll.new()
    var p = _pair()
    var raised = False
    try:
        ep.delete(p[0])
    except e:
        raised = True
        assert_true(e.errno == Errno.ENOENT)
        assert_true(e.kind == ErrorKind.NotFound)
        assert_equal(String(e.op), "epoll_ctl(DEL)")
    assert_true(raised)
    assert_true(_mod_errno(ep, p[0], IN) == Errno.ENOENT)
    sys.keep_alive(p)  # registered fds must outlive the waits


def test_invalid_targets() raises:
    var ep = Epoll.new()
    # Closed / never-open descriptor.
    var e1 = _add_errno(ep, RawFd(1_000_000), IN)
    assert_true(e1 == Errno.EBADF)
    # An epoll instance cannot watch itself.
    assert_true(_add_errno(ep, ep, IN) == Errno.EINVAL)
    # Two epolls watching each other: the second link is a loop.
    var ep2 = Epoll.new()
    ep.add(ep2, IN, 0)
    assert_true(_add_errno(ep2, ep, IN) == Errno.ELOOP)
    # EPOLLEXCLUSIVE cannot be combined with modify.
    var p = _pair()
    ep.add(p[1], IN, 0)
    assert_true(
        _mod_errno(ep, p[1], IN | UInt32(EPOLLEXCLUSIVE)) == Errno.EINVAL
    )
    sys.keep_alive(ep2)  # registered fds must outlive the waits
    sys.keep_alive(p)  # registered fds must outlive the waits


# ---- wait: buffer, timeouts, fallback, EINTR ----------------------------


def test_wait_capacity_zero_is_einval() raises:
    var ep = Epoll.new()
    var evs = List[EpollEvent]()
    var raised = False
    try:
        _ = ep.wait(evs, 0)
    except e:
        raised = True
        assert_true(e.errno == Errno.EINVAL)
        assert_true(e.kind == ErrorKind.InvalidInput)
    assert_true(raised)
    assert_equal(len(evs), 0)


def test_wait_reuses_buffer_and_sets_length() raises:
    var ep = Epoll.new()
    var e = EventFd.new()
    ep.add(e, IN, 42)
    var evs = _events_buf(8)
    for _ in range(5):  # stale entries from a previous user
        evs.append(EpollEvent(0xFF, 0xFF))
    var ptr = Int(evs.unsafe_ptr())
    var cap = evs.capacity()
    assert_equal(ep.wait(evs, 0), 0)
    assert_equal(len(evs), 0)
    e.signal()
    assert_equal(ep.wait(evs, 0), 1)
    assert_equal(len(evs), 1)
    assert_equal(evs[0].data(), UInt64(42))
    assert_equal(Int(evs.unsafe_ptr()), ptr)  # never reallocated
    assert_equal(evs.capacity(), cap)
    sys.keep_alive(e)  # registered fds must outlive the waits


def test_more_ready_than_capacity_rotates() raises:
    # Level-triggered fds that stay ready are re-queued behind the others,
    # so consecutive small waits cover all of them (no starvation).
    var ep = Epoll.new()
    var efds = List[EventFd]()
    for i in range(5):
        var e = EventFd.new()
        e.signal()
        ep.add(e, IN, UInt64(i))
        efds.append(e^)
    var seen = List[Bool](length=5, fill=False)
    var evs = _events_buf(2)
    for _ in range(3):
        var n = ep.wait(evs, 0)
        assert_equal(n, 2)
        for j in range(n):
            seen[Int(evs[j].data())] = True
    for i in range(5):
        assert_true(seen[i])
    sys.keep_alive(efds)  # registered fds must outlive the waits


def test_timeout_conversion_rounds_up() raises:
    assert_equal(epoll_timeout_ms(-1), -1)
    assert_equal(epoll_timeout_ms(-1_000_000_000), -1)
    assert_equal(epoll_timeout_ms(0), 0)
    assert_equal(epoll_timeout_ms(1), 1)
    assert_equal(epoll_timeout_ms(999_999), 1)
    assert_equal(epoll_timeout_ms(1_000_000), 1)
    assert_equal(epoll_timeout_ms(1_000_001), 2)
    assert_equal(epoll_timeout_ms(1_500_000_000), 1500)
    assert_equal(epoll_timeout_ms(MAX_TIMEOUT_MS * 1_000_000), MAX_TIMEOUT_MS)
    assert_equal(
        epoll_timeout_ms((MAX_TIMEOUT_MS - 1) * 1_000_000 + 1), MAX_TIMEOUT_MS
    )
    assert_equal(epoll_timeout_ms(Int.MAX), MAX_TIMEOUT_MS)  # no overflow


def _check_timeout(mut ep: Epoll, timeout_ns: Int) raises:
    var evs = _events_buf(4)
    var t0 = _now_ns()
    assert_equal(ep.wait(evs, timeout_ns), 0)
    var dt = _now_ns() - t0
    assert_true(dt >= timeout_ns, "woke before the timeout")
    assert_true(dt < timeout_ns + 2000 * MS, "timeout far too late")


def test_wait_timeout_returns_zero_after_timeout() raises:
    var ep = Epoll.new()
    var e = EventFd.new()
    ep.add(e, IN, 0)  # registered but never ready
    _check_timeout(ep, 30 * MS)
    _check_timeout(ep, 1_500_000)  # sub-millisecond fraction
    ep.disable_pwait2()
    _check_timeout(ep, 30 * MS)
    _check_timeout(ep, 1_500_000)  # must round up to 2ms, not down to 1ms
    assert_false(ep.uses_pwait2())
    sys.keep_alive(e)  # registered fds must outlive the waits


def test_timeout_zero_returns_immediately() raises:
    var ep = Epoll.new()
    var e = EventFd.new()
    ep.add(e, IN, 0)
    var evs = _events_buf(4)
    for fallback in range(2):
        if fallback == 1:
            ep.disable_pwait2()
        var t0 = _now_ns()
        for _ in range(100):
            assert_equal(ep.wait(evs, 0), 0)
        assert_true(_now_ns() - t0 < 500 * MS)
    sys.keep_alive(e)  # registered fds must outlive the waits


def test_pwait2_choice_matches_kernel_probe() raises:
    var ep = Epoll.new()
    var evs = _events_buf(4)
    evs.resize(unsafe_uninit_length=4)
    var r = epoll_pwait2(ep, Span(evs), 0)
    var expect = not (
        is_err(r)
        and (
            Errno(err_of(r)) == Errno.ENOSYS or Errno(err_of(r)) == Errno.EPERM
        )
    )
    evs.clear()
    assert_true(ep.uses_pwait2())
    assert_equal(ep.wait(evs, 0), 0)
    assert_equal(ep.uses_pwait2(), expect)
    assert_equal(ep.wait(evs, 0), 0)  # works either way
    assert_equal(ep.uses_pwait2(), expect)


def test_eventfd_wakes_infinite_wait() raises:
    # Single-threaded: signal first, then an infinite wait must return at once.
    var ep = Epoll.new()
    var e = EventFd.new()
    ep.add(e, IN, 0xE0E0)
    var evs = _events_buf(4)
    for fallback in range(2):
        if fallback == 1:
            ep.disable_pwait2()
        e.signal()
        var t0 = _now_ns()
        assert_equal(ep.wait(evs, -1), 1)
        assert_true(_now_ns() - t0 < 1000 * MS)
        assert_equal(evs[0].events(), IN)
        assert_equal(evs[0].data(), UInt64(0xE0E0))
        assert_equal(e.drain(), UInt64(1))
        assert_equal(ep.wait(evs, 0), 0)
    sys.keep_alive(e)  # registered fds must outlive the waits


def test_eintr_returns_zero_events() raises:
    # A handled signal interrupts a blocked epoll wait with EINTR, which
    # `wait` reports as 0 events, for epoll_pwait2 and for the epoll_pwait
    # fallback. The signals target this thread only and nothing stops the
    # process. (This test used to SIGSTOP/SIGCONT the whole process from a
    # helper; a helper killed between the two, e.g. by Ctrl-C, left the
    # test stopped forever.)
    var ep = Epoll.new()
    var e = EventFd.new()
    ep.add(e, IN, 0)  # never ready
    var evs = _events_buf(4)
    var burst = _SignalBurst(first_ms=20)
    var t0 = _now_ns()
    var n1 = ep.wait(evs, 10_000 * MS)
    var dt1 = _now_ns() - t0
    var len1 = len(evs)
    var seen1 = burst.stop()
    ep.disable_pwait2()
    burst = _SignalBurst(first_ms=20)
    t0 = _now_ns()
    var n2 = ep.wait(evs, 10_000 * MS)
    var dt2 = _now_ns() - t0
    var len2 = len(evs)
    var seen2 = burst.stop()
    assert_true(seen1 >= 1 and seen2 >= 1, "no signal was handled")
    assert_equal(n1, 0)
    assert_equal(len1, 0)
    assert_true(dt1 < 5000 * MS, "epoll_pwait2 was not interrupted")
    assert_equal(n2, 0)
    assert_equal(len2, 0)
    assert_true(dt2 < 5000 * MS, "epoll_pwait was not interrupted")
    sys.keep_alive(e)  # registered fds must outlive the waits


# ---- scale: 1000 socketpairs ---------------------------------------------


def _make_pairs(
    mut ep: Epoll,
    n: Int,
    events: UInt32,
    mut a: List[OwnedFd],
    mut b: List[OwnedFd],
) raises:
    _ensure_nofile(2 * n + 64)
    for i in range(n):
        var fds = _pair_fds()
        a.append(OwnedFd(unsafe_from_raw=fds[0]))
        b.append(OwnedFd(unsafe_from_raw=fds[1]))
        ep.add(b[i], events, (UInt64(0xA5) << 56) | UInt64(i))


def test_1000_pairs_small_buffer_reports_exactly_the_ready_ones() raises:
    comptime N = 1000
    var ep = Epoll.new()
    var a = List[OwnedFd]()
    var b = List[OwnedFd]()
    _make_pairs(ep, N, IN, a, b)
    var expected = 0
    for i in range(N):
        if i % 3 == 0:
            _send(a[i], "!")
            expected += 1
    var seen = List[Bool](length=N, fill=False)
    var evs = _events_buf(16)
    var count = 0
    var calls = 0
    while True:
        var n = ep.wait(evs, 0)
        if n == 0:
            break
        calls += 1
        assert_true(calls <= N, "wait never ran dry")
        assert_true(n <= 16)
        for j in range(n):
            var d = evs[j].data()
            assert_equal(d >> 56, UInt64(0xA5))
            var idx = Int(d & 0xFFFFFFFF)
            assert_true(idx < N and idx % 3 == 0)
            assert_false(seen[idx], "reported again after being drained")
            assert_equal(evs[j].events(), IN)
            seen[idx] = True
            count += 1
            assert_equal(_drain_socket(b[idx]), 1)  # no longer ready
    assert_equal(count, expected)
    assert_equal(count, 334)
    assert_true(calls >= (expected + 15) // 16)
    for i in range(N):
        assert_equal(seen[i], i % 3 == 0)
    sys.keep_alive(a)  # registered fds must outlive the waits
    sys.keep_alive(b)  # registered fds must outlive the waits


def test_1000_pairs_edge_triggered_each_reported_once() raises:
    comptime N = 1000
    var ep = Epoll.new()
    var a = List[OwnedFd]()
    var b = List[OwnedFd]()
    _make_pairs(ep, N, IN | ET, a, b)
    for i in range(N):
        _send(a[i], "!")
    var seen = List[Bool](length=N, fill=False)
    var evs = _events_buf(64)
    var count = 0
    while True:
        var n = ep.wait(evs, 0)  # nothing is drained: ET must not repeat
        if n == 0:
            break
        for j in range(n):
            var idx = Int(evs[j].data() & 0xFFFFFFFF)
            assert_false(seen[idx])
            seen[idx] = True
            count += 1
        assert_true(count <= N)
    assert_equal(count, N)
    sys.keep_alive(a)  # registered fds must outlive the waits
    sys.keep_alive(b)  # registered fds must outlive the waits


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
