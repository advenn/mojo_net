from std.python import Python, PythonObject
from std.sys import CompilationTarget, size_of
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Errno, ErrorKind, IoError
from linux.abi import Rlimit
from linux.consts import (
    AT_EGID,
    AT_EUID,
    AT_GID,
    AT_NULL,
    AT_PAGESZ,
    AT_UID,
    RLIMIT_NOFILE,
)
from linux.probe import (
    MIN_KERNEL,
    RLIM_INFINITY,
    Capabilities,
    IoUringSupport,
    KernelVersion,
    ProbePolicy,
    auxv_lookup,
    _quota_of,
    cpu_count,
    cpu_quota,
    get_rlimit,
    has_epoll_pwait2,
    io_uring_setup_probe,
    kernel_version,
    nofile_limit,
    page_size,
    probe_io_uring,
    raise_nofile_limit,
    require_kernel,
    set_rlimit,
    uname,
    uts_string,
)
from linux.syscall import err_of, is_err


def _v(major: Int, minor: Int, patch: Int) -> KernelVersion:
    return KernelVersion(major, minor, patch)


def _check_parse(s: String, major: Int, minor: Int, patch: Int) raises:
    var v = KernelVersion.parse(s)
    assert_true(v == _v(major, minor, patch), String(s, " -> ", v))


def _check_rejects(s: String) raises:
    var raised = False
    try:
        _ = KernelVersion.parse(s)
    except e:
        raised = True
        assert_true(e.kind == ErrorKind.InvalidInput, String(s, ": ", e))
        assert_true(e.errno == Errno(0))
    assert_true(raised, String("accepted '", s, "'"))


def _py_rlim(v: PythonObject) raises -> UInt64:
    """Python reports RLIM_INFINITY as -1."""
    var i = Int(py=v)
    return RLIM_INFINITY if i < 0 else UInt64(i)


def _py_nofile() raises -> Rlimit:
    var resource = Python.import_module("resource")
    var lim = resource.getrlimit(resource.RLIMIT_NOFILE)
    return Rlimit(_py_rlim(lim[0]), _py_rlim(lim[1]))


def _open_fd_count() raises -> Int:
    var os = Python.import_module("os")
    return Int(py=Python.evaluate("len")(os.listdir("/proc/self/fd")))


# ---- KernelVersion parsing --------------------------------------------------


def test_cgroup_cpu_quota_rounds_up() raises:
    assert_equal(_quota_of("max 100000").or_else(-1), -1)  # no quota
    assert_equal(_quota_of("150000 100000\n").or_else(-1), 2)  # --cpus=1.5
    assert_equal(_quota_of("100000 100000").or_else(-1), 1)
    assert_equal(_quota_of("50000 100000").or_else(-1), 1)  # (at least one)
    assert_equal(_quota_of("400000 100000").or_else(-1), 4)
    assert_equal(_quota_of("garbage").or_else(-1), -1)
    assert_equal(_quota_of("0 100000").or_else(-1), -1)
    _ = cpu_quota()  # reads this host's cgroup without failing


def test_parse_release_table() raises:
    _check_parse("6.12.111+deb13-amd64", 6, 12, 111)
    _check_parse("5.15.0-122-generic", 5, 15, 0)
    _check_parse("6.1", 6, 1, 0)
    _check_parse("6.1.0", 6, 1, 0)
    _check_parse("6.12.0-rc1", 6, 12, 0)
    _check_parse("6.13-rc7", 6, 13, 0)
    _check_parse("5.15.153.1-microsoft-standard-WSL2", 5, 15, 153)
    _check_parse("4.19.0-0.bpo.13-amd64", 4, 19, 0)
    _check_parse("3.10.0-1160.el7.x86_64", 3, 10, 0)
    _check_parse("5.14.0-427.13.1.el9_4.x86_64", 5, 14, 0)
    _check_parse("6.6.30-gentoo", 6, 6, 30)
    _check_parse("6.8.0_custom", 6, 8, 0)
    _check_parse("6.1rc", 6, 1, 0)
    _check_parse("10.0.0", 10, 0, 0)
    _check_parse("2.6.32", 2, 6, 32)
    _check_parse("999999999.0.1", 999999999, 0, 1)
    _check_parse("6.1 #1 SMP", 6, 1, 0)


def test_parse_rejects_garbage() raises:
    _check_rejects("")
    _check_rejects("abc")
    _check_rejects("6")
    _check_rejects("6.")
    _check_rejects("6.x")
    _check_rejects(".6.1")
    _check_rejects("6..1")
    _check_rejects("6.1.")
    _check_rejects("6.1.x")
    _check_rejects("6.1.-rc1")
    _check_rejects(" 6.1")
    _check_rejects("-6.1")
    _check_rejects("+6.1")
    _check_rejects("v6.1")
    _check_rejects("6,1")
    _check_rejects("6-1")
    _check_rejects("1234567890.1")  # would overflow a sane component
    _check_rejects("6.1234567890")
    _check_rejects("6.1.99999999999999999999999")


def test_version_ordering_is_numeric() raises:
    assert_true(_v(5, 15, 0) < _v(6, 1, 0))
    assert_true(_v(6, 1, 0) < _v(6, 1, 1))
    assert_true(_v(6, 10, 0) > _v(6, 9, 99))  # not lexicographic
    assert_true(_v(6, 1, 0) == _v(6, 1, 0))
    assert_true(_v(6, 1, 0) != _v(6, 1, 1))
    assert_true(_v(6, 1, 5) >= _v(6, 1, 5))
    assert_true(_v(6, 1, 5).at_least(6, 1))
    assert_true(_v(6, 1, 5).at_least(6, 1, 5))
    assert_false(_v(6, 1, 5).at_least(6, 1, 6))
    assert_false(_v(5, 15, 200).at_least(6, 0))
    assert_true(MIN_KERNEL == _v(5, 15, 0))


def test_version_write() raises:
    assert_equal(String(_v(6, 12, 111)), "6.12.111")
    assert_equal(String(KernelVersion.parse("6.1")), "6.1.0")


# ---- live: uname / kernel -----------------------------------------------------


def test_uname_matches_python() raises:
    var u = uname()
    var py = Python.import_module("os").uname()
    assert_equal(uts_string(u.sysname), "Linux")
    assert_equal(uts_string(u.release), String(py.release))
    assert_equal(uts_string(u.machine), String(py.machine))
    assert_equal(uts_string(u.nodename), String(py.nodename))
    comptime if CompilationTarget.is_x86():
        assert_equal(uts_string(u.machine), "x86_64")
    else:
        assert_equal(uts_string(u.machine), "aarch64")


def test_kernel_version_live() raises:
    var v = kernel_version()
    var py = Python.import_module("platform").release()
    assert_true(v == KernelVersion.parse(String(py)))
    assert_true(v >= MIN_KERNEL, String("kernel ", v, " < 5.15"))


def test_require_kernel() raises:
    require_kernel(MIN_KERNEL)
    require_kernel(kernel_version())
    var raised = False
    try:
        require_kernel(_v(999, 0, 0))
    except e:
        raised = True
        assert_true(e.kind == ErrorKind.Unsupported)
        assert_equal(String(e.op), "require_kernel")
    assert_true(raised, "require_kernel(999.0.0) passed")


# ---- live: auxv / page size -----------------------------------------------------


def test_page_size_live() raises:
    var ps = page_size()
    var py = Int(py=Python.import_module("os").sysconf("SC_PAGE_SIZE"))
    assert_equal(ps, py)
    assert_true(ps >= 4096 and (ps & (ps - 1)) == 0)
    comptime if CompilationTarget.is_x86():
        assert_equal(ps, 4096)


def test_auxv_lookup_matches_process_ids() raises:
    var os = Python.import_module("os")
    var uid = auxv_lookup(UInt64(AT_UID)).value()
    var gid = auxv_lookup(UInt64(AT_GID)).value()
    var euid = auxv_lookup(UInt64(AT_EUID)).value()
    var egid = auxv_lookup(UInt64(AT_EGID)).value()
    assert_equal(Int(uid), Int(py=os.getuid()))
    assert_equal(Int(gid), Int(py=os.getgid()))
    assert_equal(Int(euid), Int(py=os.geteuid()))
    assert_equal(Int(egid), Int(py=os.getegid()))
    assert_equal(Int(auxv_lookup(UInt64(AT_PAGESZ)).value()), page_size())


def test_auxv_lookup_absent_keys() raises:
    assert_false(auxv_lookup(0xDEADBEEF))
    # AT_NULL terminates the vector, so it is never "found".
    assert_false(auxv_lookup(UInt64(AT_NULL)))


def test_probes_do_not_leak_fds() raises:
    _ = _open_fd_count()  # warm up Python's own fds
    var before = _open_fd_count()
    for _ in range(50):
        _ = page_size()
        _ = probe_io_uring()
        _ = has_epoll_pwait2()
    assert_equal(_open_fd_count(), before)


# ---- live: cpus / limits --------------------------------------------------------


def test_cpu_count_matches_affinity() raises:
    var n = cpu_count()
    var py = Python.evaluate("len")(
        Python.import_module("os").sched_getaffinity(0)
    )
    assert_true(n >= 1)
    assert_equal(n, Int(py=py))


def test_nofile_limit_matches_python() raises:
    var lim = nofile_limit()
    var py = _py_nofile()
    assert_equal(lim.cur, py.cur)
    assert_equal(lim.max, py.max)
    assert_true(lim.cur >= 3)
    assert_true(lim.cur <= lim.max)


def test_rlimit_layout() raises:
    # Mirror of `struct rlimit64 { __u64 rlim_cur; __u64 rlim_max; }`.
    assert_equal(size_of[Rlimit](), 16)
    var r = Rlimit(1, 2)
    var base = Int(Pointer(to=r))
    assert_equal(Int(Pointer(to=r.cur)) - base, 0)
    assert_equal(Int(Pointer(to=r.max)) - base, 8)


def _raise_nofile_body(orig: Rlimit) raises:
    var low: UInt64 = 1000 if orig.max >= 1000 else orig.max
    set_rlimit(RLIMIT_NOFILE, Rlimit(low, orig.max))
    assert_equal(nofile_limit().cur, low)
    # Never lowers.
    assert_equal(raise_nofile_limit(0), low)
    assert_equal(raise_nofile_limit(low - 1), low)
    assert_equal(nofile_limit().cur, low)
    # Raises to the target when it fits under the hard limit.
    if orig.max >= low + 24:
        assert_equal(raise_nofile_limit(low + 24), low + 24)
        assert_equal(_py_nofile().cur, low + 24)
    # Caps at the hard limit, which stays unchanged.
    assert_equal(raise_nofile_limit(RLIM_INFINITY), orig.max)
    var now = _py_nofile()
    assert_equal(now.cur, orig.max)
    assert_equal(now.max, orig.max)


def test_raise_nofile_limit() raises:
    var orig = nofile_limit()
    try:
        _raise_nofile_body(orig)
    finally:
        set_rlimit(RLIMIT_NOFILE, orig)
    assert_equal(nofile_limit().cur, orig.cur)


def _set_rlimit_errno(resource: Int, lim: Rlimit) -> Errno:
    """errno of a set_rlimit expected to fail (Errno(0) if it succeeded)."""
    try:
        set_rlimit(resource, lim)
    except e:
        return e.errno
    return Errno(0)


def test_set_rlimit_errors() raises:
    var orig = nofile_limit()
    # cur > max
    var e1 = _set_rlimit_errno(RLIMIT_NOFILE, Rlimit(orig.max, orig.max - 1))
    assert_true(e1 == Errno.EINVAL, String(e1))
    assert_true(ErrorKind.of(e1) == ErrorKind.InvalidInput)
    # RLIMIT_NOFILE hard limit above fs.nr_open is EPERM even for root.
    var nr_open = Int(
        py=Python.evaluate("int(open('/proc/sys/fs/nr_open').read())")
    )
    var e2 = _set_rlimit_errno(
        RLIMIT_NOFILE, Rlimit(orig.cur, UInt64(nr_open + 64))
    )
    if e2 == Errno(0):
        set_rlimit(RLIMIT_NOFILE, orig)
    assert_true(e2 == Errno.EPERM, String(e2))
    var raised = False
    try:
        _ = get_rlimit(9999)
    except e:
        raised = True
        assert_true(e.errno == Errno.EINVAL)
    assert_true(raised, "resource 9999 accepted")
    assert_true(nofile_limit().cur == orig.cur)


# ---- live: io_uring / epoll_pwait2 ----------------------------------------------


def test_io_uring_probe_matches_sysctl() raises:
    var os = Python.import_module("os")
    var path = "/proc/sys/kernel/io_uring_disabled"
    var disabled = 0
    if Python.evaluate("__import__('os').path.exists")(path):
        disabled = Int(
            py=Python.evaluate("lambda p: int(open(p).read())")(path)
        )
    var root = Int(py=os.geteuid()) == 0
    var got = probe_io_uring()
    var raw = io_uring_setup_probe()
    if disabled == 2:
        assert_true(got == IoUringSupport.Disabled)
        assert_true(is_err(raw) and Errno(err_of(raw)) == Errno.EPERM)
    elif disabled == 1 and not root:
        # Members of kernel.io_uring_group are still allowed.
        assert_true(
            got == IoUringSupport.Disabled or got == IoUringSupport.Available
        )
    elif got == IoUringSupport.Available:
        assert_true(is_err(raw) and Errno(err_of(raw)) == Errno.EINVAL)
    else:
        # Not disabled by sysctl: only a seccomp filter or CONFIG_IO_URING=n
        # may hide it. Report that loudly instead of passing silently.
        print("note: io_uring hidden by seccomp/config:", got, raw)
        assert_true(is_err(raw))
    assert_true(is_err(raw))  # 0 entries can never create a ring


def test_io_uring_support_names() raises:
    assert_equal(String(IoUringSupport.Available), "Available")
    assert_equal(String(IoUringSupport.NotCompiled), "NotCompiled")
    assert_equal(String(IoUringSupport.Disabled), "Disabled")
    assert_true(IoUringSupport.Available != IoUringSupport.Disabled)


def test_epoll_pwait2_probe() raises:
    # Implemented since 5.11, so present on every supported kernel unless a
    # seccomp filter hides it; the probe must return without waiting.
    var t = Python.import_module("time").monotonic()
    var have = has_epoll_pwait2()
    var dt = Float64(py=Python.import_module("time").monotonic() - t)
    assert_true(dt < 0.5)
    if kernel_version().at_least(5, 11):
        assert_true(have)


def test_capabilities_detect_is_consistent() raises:
    # Always: compare with the direct probes even under a seccomp filter
    # (the default policy skips two of them there; see
    # test_linux_time_poll_probe_regressions.mojo).
    var c = Capabilities.detect(ProbePolicy.Always)
    assert_true(c.kernel == kernel_version())
    assert_equal(c.cpus, cpu_count())
    assert_equal(c.page_size, page_size())
    assert_equal(c.nofile.cur, nofile_limit().cur)
    assert_true(c.io_uring == probe_io_uring())
    assert_equal(c.epoll_pwait2, has_epoll_pwait2())
    assert_equal(
        c.io_uring_usable(),
        c.io_uring == IoUringSupport.Available and c.kernel.at_least(6, 1),
    )
    var s = String(c)
    assert_true(s.startswith("Capabilities(kernel="))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
