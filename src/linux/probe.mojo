"""Kernel and process capability probing (no libc).

Answers "what can this process use?" once at startup: kernel version, CPUs
it may run on, page size, fd limits, and whether io_uring and epoll_pwait2
are reachable. The probes change no kernel state: the io_uring probe never
creates a ring and the epoll_pwait2 probe never waits.

Runtime decisions (io_uring backend vs epoll) must use these probes, not the
kernel version alone: io_uring is blocked by seccomp in Docker/containerd by
default and disabled by sysctl on some distributions, and backports make
version numbers unreliable in both directions.

Seccomp caveat: `probe_io_uring` and `has_epoll_pwait2` issue the syscall
they test, and they classify the errno a seccomp filter returns. A filter
can instead kill the process with SIGSYS (KILL/TRAP actions): systemd's
`SystemCallFilter=` without `SystemCallErrorNumber=` does that, and so do
some sandbox profiles. A process cannot read which action its filter uses
(`Seccomp: 2` in /proc/thread-self/status only says that a filter exists),
so `Capabilities.detect()` by default skips both probes while a filter is
installed (`ProbePolicy`) and reports them as unavailable. A caller that
knows its filter answers with an errno, as Docker, containerd and the
Kubernetes RuntimeDefault profile do, passes `ProbePolicy.Always`. The
other probes use only uname, sched_getaffinity, prlimit64 and openat/read
of /proc, which general allowlists include (systemd's `@system-service`
has all of them; its always-allowed `@default` set has the middle two).
"""

from std.bit import pop_count

from .abi import EpollEvent, Rlimit, UTS_LEN, Utsname
from .consts import (
    AT_NULL,
    AT_PAGESZ,
    F_DUPFD_CLOEXEC,
    RLIMIT_NOFILE,
)
from .errno import Errno
from .error import ErrorKind, IoError, check
from .fd import AsFd
from .fs import read_file
from .nr import (
    SYS_epoll_pwait2,
    SYS_io_uring_setup,
    SYS_prlimit64,
    SYS_sched_getaffinity,
    SYS_uname,
)
from .sys import close, fcntl, keep_alive
from .syscall import (
    err_of,
    is_err,
    syscall1,
    syscall2,
    syscall3,
    syscall4,
    syscall6,
)

comptime RLIM_INFINITY: UInt64 = ~UInt64(0)
"""`RLIM64_INFINITY`: no limit."""

comptime SECCOMP_MODE_DISABLED: Int = 0
"""`/proc/*/status` `Seccomp:` value: no seccomp."""
comptime SECCOMP_MODE_STRICT: Int = 1
"""`Seccomp:` value for strict mode (only read/write/exit/sigreturn)."""
comptime SECCOMP_MODE_FILTER: Int = 2
"""`Seccomp:` value when at least one BPF filter is installed."""

# sizeof(struct io_uring_params): 10 x u32 + io_sqring_offsets (40) +
# io_cqring_offsets (40) = 120 bytes, unchanged since 5.1. The probe only
# needs a zeroed buffer of at least this size, so no mirror struct here; the
# io_uring backend in `rt` owns the real one.
comptime _IO_URING_PARAMS_WORDS = 15


# ---- uname -------------------------------------------------------------------


@inline(.always)
def _uname(mut u: Utsname) -> Int:
    return syscall1(SYS_uname, Int(Pointer(to=u)))


def uname() raises IoError -> Utsname:
    var u = Utsname.zeroed()
    _ = check("uname", _uname(u))
    return u^


def _cstr_len(ref field: Array[UInt8, UTS_LEN]) -> Int:
    for i in range(UTS_LEN):
        if field[i] == 0:
            return i
    return UTS_LEN


def uts_string(ref field: Array[UInt8, UTS_LEN]) -> String:
    """A `Utsname` field as a `String` (up to its NUL; invalid UTF-8 is
    replaced, though the kernel only puts ASCII here)."""
    return String(from_utf8_lossy=Span(field)[0 : _cstr_len(field)])


# ---- kernel version ----------------------------------------------------------


@fieldwise_init
struct KernelVersion(Comparable, TrivialRegisterPassable, Writable):
    """`major.minor.patch` of a kernel release, ordered numerically."""

    var major: Int
    var minor: Int
    var patch: Int

    @staticmethod
    def parse(s: String) raises IoError -> KernelVersion:
        """Parse a release string: `6.12.111+deb13-amd64`,
        `5.15.0-122-generic`, `6.1`, `5.15.153.1-microsoft-standard-WSL2`.

        Grammar: `MAJOR.MINOR[.PATCH]SUFFIX`, components of 1 to 9 decimal
        digits, SUFFIX anything (`-rc1`, `+deb13`, `.1-microsoft`); a `.`
        right after MINOR must start a PATCH. A missing patch is 0. Anything
        else (empty, no minor, leading junk or space, `6..1`, `6.1.`,
        overlong numbers) raises `ErrorKind.InvalidInput`.
        """
        return Self.parse_bytes(s.as_bytes())

    @staticmethod
    def parse_bytes(b: Span[UInt8, _]) raises IoError -> KernelVersion:
        var i = 0
        var major = _number(b, i)
        if major < 0 or not _at(b, i, "."):
            raise _bad_version()
        i += 1
        var minor = _number(b, i)
        if minor < 0:
            raise _bad_version()
        var patch = 0
        if _at(b, i, "."):
            i += 1
            patch = _number(b, i)
            if patch < 0:
                raise _bad_version()
        return KernelVersion(major, minor, patch)

    @inline(.always)
    def at_least(self, major: Int, minor: Int, patch: Int = 0) -> Bool:
        return not self < KernelVersion(major, minor, patch)

    def __lt__(self, rhs: Self) -> Bool:
        if self.major != rhs.major:
            return self.major < rhs.major
        if self.minor != rhs.minor:
            return self.minor < rhs.minor
        return self.patch < rhs.patch

    def __eq__(self, rhs: Self) -> Bool:
        return (
            self.major == rhs.major
            and self.minor == rhs.minor
            and self.patch == rhs.patch
        )

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.major, ".", self.minor, ".", self.patch)


comptime MIN_KERNEL = KernelVersion(5, 15, 0)
"""The oldest kernel this library supports (5.15 LTS)."""

comptime _MAX_DIGITS = 9


@inline(.always)
def _bad_version() -> IoError:
    return IoError.of_kind("KernelVersion.parse", ErrorKind.InvalidInput)


@inline(.always)
def _at(b: Span[UInt8, _], i: Int, c: StaticString) -> Bool:
    return i < len(b) and b[i] == c.as_bytes()[0]


def _number(b: Span[UInt8, _], mut i: Int) -> Int:
    """Decimal digits at `b[i:]` (advancing `i`), or -1 if there are none or
    more than `_MAX_DIGITS` (so the value cannot overflow)."""
    var start = i
    var v = 0
    while i < len(b):
        var d = Int(b[i]) - ord("0")
        if d < 0 or d > 9:
            break
        if i - start == _MAX_DIGITS:
            return -1
        v = v * 10 + d
        i += 1
    return v if i > start else -1


def kernel_version() raises IoError -> KernelVersion:
    """The running kernel's version, from `uname().release`."""
    var u = uname()
    return KernelVersion.parse_bytes(Span(u.release)[0 : _cstr_len(u.release)])


def require_kernel(minimum: KernelVersion) raises IoError:
    """Raise `ErrorKind.Unsupported` if the running kernel is older."""
    if kernel_version() < minimum:
        raise IoError.of_kind("require_kernel", ErrorKind.Unsupported)


# ---- resource limits ---------------------------------------------------------
# `Rlimit` is the `linux.abi` mirror; it stays importable from here.


@inline(.always)
def _prlimit_get(resource: Int, mut old: Rlimit) -> Int:
    return syscall4(SYS_prlimit64, 0, resource, 0, Int(Pointer(to=old)))


@inline(.always)
def _prlimit_set(resource: Int, ref new: Rlimit) -> Int:
    return syscall4(SYS_prlimit64, 0, resource, Int(Pointer(to=new)), 0)


def get_rlimit(resource: Int) raises IoError -> Rlimit:
    """This process's limit for `resource` (`RLIMIT_*`), via prlimit64."""
    var lim = Rlimit(0, 0)
    _ = check("prlimit64", _prlimit_get(resource, lim))
    return lim


def set_rlimit(resource: Int, lim: Rlimit) raises IoError:
    """Set this process's limit. EINVAL if `cur > max`; EPERM when raising
    `max` without CAP_SYS_RESOURCE, or for RLIMIT_NOFILE when `max` exceeds
    `fs.nr_open`."""
    _ = check("prlimit64", _prlimit_set(resource, lim))


def nofile_limit() raises IoError -> Rlimit:
    """RLIMIT_NOFILE: how many fds this process may hold."""
    return get_rlimit(RLIMIT_NOFILE)


def raise_nofile_limit() raises IoError -> Int:
    """Raise the soft RLIMIT_NOFILE to the hard limit, as servers with many
    connections do at startup (no privilege is needed for that); returns
    the soft limit now in force. A soft limit already at the hard one is
    left alone."""
    var lim = nofile_limit()
    if lim.cur < lim.max:
        set_rlimit(RLIMIT_NOFILE, Rlimit(lim.max, lim.max))
        lim = nofile_limit()
    return Int(min(lim.cur, UInt64(Int.MAX)))


def raise_nofile_limit(target: UInt64) raises IoError -> UInt64:
    """Raise the soft RLIMIT_NOFILE toward `target`, capped at the hard
    limit (an unprivileged process can do that much); never lowers it.
    Returns the soft limit now in effect.

    Servers need this: the default soft limit is often 1024 while the hard
    limit is far higher. (Lowering is left to `set_rlimit`.)
    """
    var lim = nofile_limit()
    var want = target if target < lim.max else lim.max
    if want <= lim.cur:
        return lim.cur
    set_rlimit(RLIMIT_NOFILE, Rlimit(want, lim.max))
    return want


def pregrow_fd_table[F: AsFd](fd: F, max_fds: Int = 65536) -> Int:
    """Make the kernel allocate a large fd table once, now (best effort).

    The kernel doubles a process's fd table when an fd number reaches its
    size. In a multi-threaded process, and every Mojo process is one (the
    runtime starts its worker pool before main), each doubling waits for an
    RCU grace period. That stalls whatever syscall creates the fd for
    20-40 ms; under a connection burst it overflows the accept queue
    (docs/spikes.md). Long-running servers call this once at startup with any
    open fd (typically the listener).

    It duplicates `fd` to the lowest free number >= min(RLIMIT_NOFILE,
    `max_fds`) - 1, then closes the copy: the table stays large.
    F_DUPFD_CLOEXEC never touches an fd that is in use (dup3 would close it).
    Returns the number that was used, or -1 if nothing was done (limit too
    small to matter, or the dup failed)."""
    var limit = 1024
    try:
        limit = Int(min(nofile_limit().cur, UInt64(max(max_fds, 0))))
    except:
        pass
    var high = limit - 1
    if high < 256:
        return -1
    var r = fcntl(fd, F_DUPFD_CLOEXEC, high)
    if r < 0:
        return -1
    _ = close(Int32(r))
    return r


# ---- CPUs --------------------------------------------------------------------


@inline(.always)
def _sched_getaffinity(mask: MutSpan[UInt64, _]) -> Int:
    return syscall3(
        SYS_sched_getaffinity, 0, len(mask) * 8, Int(mask.unsafe_ptr())
    )


def cpu_count() raises IoError -> Int:
    """CPUs this thread may run on (its affinity mask, like `nproc`).

    This is the useful number for sizing loop threads: it honors `taskset`
    and cpuset cgroups, unlike counting online CPUs. CFS quotas
    (`cpu.max`) are not reflected. The mask buffer starts at 1024 CPUs and
    doubles while the kernel answers EINVAL (mask smaller than
    `nr_cpu_ids`).
    """
    var words = 16
    while True:
        var mask = List[UInt64](length=words, fill=0)
        var r = _sched_getaffinity(Span(mask))
        if r >= 0:
            # r = bytes written: min(len, cpumask_size()), a multiple of 8.
            var n = 0
            for w in range(r // 8):
                n += Int(pop_count(mask[w]))
            return n
        var e = Errno(err_of(r))
        if e == Errno.EINVAL and words < (1 << 16):
            words *= 2
            continue
        raise IoError.from_errno("sched_getaffinity", e)


def _quota_of(cpu_max: String) -> Optional[Int]:
    """CPUs from a cgroup v2 `cpu.max` ("<quota> <period>", or "max ..."),
    rounded up; None for no quota."""
    var parts = cpu_max.strip().split(" ")
    if len(parts) != 2 or parts[0] == "max":
        return None
    try:
        var quota = atol(parts[0])
        var period = atol(parts[1])
        if quota <= 0 or period <= 0:
            return None
        return max((quota + period - 1) // period, 1)
    except:
        return None


def cpu_quota() -> Optional[Int]:
    """The CPUs this process's cgroup (v2) lets it use on average: the
    tightest `cpu.max` quota on its way up the hierarchy, over its period,
    rounded up (`docker run --cpus=1.5` gives 2). None without a quota,
    under cgroup v1, or when the files cannot be read. Unlike `cpu_count`,
    this sees CFS quotas."""
    var path: String
    try:
        var text = String(from_utf8_lossy=Span(read_file("/proc/self/cgroup", "cpu_quota")))
        path = String()
        var found = False
        for line in text.split("\n"):
            if line.startswith("0::"):
                path = String(line[byte=3:].strip())
                found = True
        if not found:
            return None  # cgroup v1
    except:
        return None
    var best = Optional[Int](None)
    while True:
        try:
            var at = String("/sys/fs/cgroup", path, "/cpu.max") if path != "/" else String("/sys/fs/cgroup/cpu.max")
            var q = _quota_of(String(from_utf8_lossy=Span(read_file(at, "cpu_quota"))))
            if q and (not best or q.value() < best.value()):
                best = q
        except:
            pass  # (the root cgroup has no cpu.max)
        if path == "/" or path.byte_length() == 0:
            return best
        var cut = path.rfind("/")
        path = String(path[byte=0:cut]) if cut > 0 else String("/")


# ---- auxv / page size --------------------------------------------------------


def _read_file(
    path: StaticString, op: StaticString
) raises IoError -> List[UInt8]:
    """Read a whole (small, procfs) file; see `linux.fs.read_file`."""
    return read_file(path, op)


@inline(.always)
def _le64(b: Span[UInt8, _], at: Int) -> UInt64:
    var v: UInt64 = 0
    for k in range(8):
        v |= UInt64(b[at + k]) << UInt64(8 * k)
    return v


def auxv_lookup(key: UInt64) raises IoError -> Optional[UInt64]:
    """Value of an ELF auxiliary vector entry (`AT_*`) of this process, read
    from /proc/self/auxv (the kernel's copy; there is no syscall and
    `getauxval` is libc). None if absent. Raises if /proc is unavailable.
    Entries are pairs of native-endian u64 (both targets are little
    endian), terminated by AT_NULL."""
    var data = _read_file("/proc/self/auxv", "read(/proc/self/auxv)")
    var i = 0
    while i + 16 <= len(data):
        var k = _le64(Span(data), i)
        if k == UInt64(AT_NULL):
            break
        if k == key:
            return _le64(Span(data), i + 8)
        i += 16
    return None


def page_size() raises IoError -> Int:
    """The MMU page size (4096 on x86_64; 4K, 16K or 64K on aarch64), from
    AT_PAGESZ."""
    var v = auxv_lookup(UInt64(AT_PAGESZ))
    if not v:
        raise IoError.of_kind("page_size", ErrorKind.NotFound)
    return Int(v.value())


# ---- io_uring / epoll_pwait2 ---------------------------------------------------


@fieldwise_init
struct IoUringSupport(Equatable, TrivialRegisterPassable, Writable):
    """Whether `io_uring_setup` is reachable by this process."""

    var _v: UInt8

    comptime Available = IoUringSupport(0)
    """The syscall exists and this process may call it."""
    comptime NotCompiled = IoUringSupport(1)
    """ENOSYS: CONFIG_IO_URING=n, a pre-5.1 kernel, or a seccomp filter
    that answers ENOSYS (indistinguishable)."""
    comptime Disabled = IoUringSupport(2)
    """EPERM: sysctl `kernel.io_uring_disabled` (6.6+), or a seccomp filter
    (Docker's default profile answers EPERM). Any other unexpected answer is
    also reported here, to stay on epoll."""
    comptime NotProbed = IoUringSupport(3)
    """`Capabilities.detect()` did not issue the probe (`ProbePolicy.Never`,
    or `ProbePolicy.Auto` under a seccomp filter). Treat it as unavailable:
    stay on epoll."""

    @inline(.always)
    def __eq__(self, rhs: Self) -> Bool:
        return self._v == rhs._v

    def name(self) -> StaticString:
        if self._v == 0:
            return "Available"
        if self._v == 1:
            return "NotCompiled"
        if self._v == 3:
            return "NotProbed"
        return "Disabled"

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.name())


@inline(.always)
def _io_uring_setup(
    entries: Int, mut params: Array[UInt64, _IO_URING_PARAMS_WORDS]
) -> Int:
    return syscall2(SYS_io_uring_setup, entries, Int(Pointer(to=params)))


def io_uring_setup_probe() -> Int:
    """Raw result of `io_uring_setup(0, &zeroed_params)`; see
    `probe_io_uring`."""
    var params = Array[UInt64, _IO_URING_PARAMS_WORDS](fill=0)
    var r = _io_uring_setup(0, params)
    if r >= 0:
        _ = close(Int32(r))  # cannot happen with 0 entries; never leak an fd
    return r


def probe_io_uring() -> IoUringSupport:
    """Classify io_uring availability without creating a ring.

    `io_uring_setup(0, &params)` with zeroed params (verified against the
    kernel sources):
    - 5.15 (fs/io_uring.c) and 6.12 (io_uring/io_uring.c): `io_uring_setup()`
      copies the params (EFAULT on a bad pointer), rejects non-zero `resv`
      and unknown flags (EINVAL), then `io_uring_create()` starts with
      `if (!entries) return -EINVAL;`. So a reachable io_uring answers EINVAL
      before allocating anything.
    - 6.6+: `SYSCALL_DEFINE2(io_uring_setup)` first checks
      `io_uring_allowed()` (sysctl `kernel.io_uring_disabled`: 2 = off for
      everyone, 1 = only CAP_SYS_ADMIN or `kernel.io_uring_group`) and
      returns EPERM.
    - Not compiled in: `sys_ni_syscall` answers ENOSYS.
    - seccomp filters answer whatever errno the profile chose (EPERM for
      Docker's default).

    Available only means `io_uring_setup` is reachable: `io_uring_enter` or
    individual opcodes may still be filtered, so the backend must probe
    opcodes (IORING_REGISTER_PROBE) on a real ring.

    Under a seccomp filter whose action for `io_uring_setup` is KILL or
    TRAP, this call ends the process with SIGSYS; see the module doc and
    `ProbePolicy`.
    """
    var r = io_uring_setup_probe()
    if r >= 0:
        return IoUringSupport.Available
    var e = Errno(err_of(r))
    if e == Errno.EINVAL:
        return IoUringSupport.Available
    if e == Errno.ENOSYS:
        return IoUringSupport.NotCompiled
    return IoUringSupport.Disabled


def has_epoll_pwait2() -> Bool:
    """Whether epoll_pwait2 (5.11+, nanosecond timeouts) is reachable.

    `epoll_pwait2(-1, &ev, 1, NULL, NULL, 0)`: `do_epoll_wait` checks
    `maxevents` (EINVAL) and the events buffer (EFAULT) before `fdget(epfd)`,
    so with valid arguments an implemented syscall answers EBADF without
    waiting; ENOSYS (old kernel) or EPERM (seccomp) means unavailable.

    Under a seccomp filter whose action for `epoll_pwait2` is KILL or TRAP,
    this call ends the process with SIGSYS, and so does `Epoll.wait` until
    `Epoll.disable_pwait2()` is called. `Capabilities.detect()` skips this
    probe under a filter by default and reports False, so pass a False
    `epoll_pwait2` on to `disable_pwait2()`.
    """
    var ev = EpollEvent(0, 0)
    var r = syscall6(SYS_epoll_pwait2, -1, Int(Pointer(to=ev)), 1, 0, 0, 0)
    keep_alive(ev)  # only its address reached the kernel
    return is_err(r) and Errno(err_of(r)) == Errno.EBADF


# ---- seccomp -------------------------------------------------------------------


def seccomp_mode_of_status(status: Span[UInt8, _]) -> Int:
    """The `Seccomp:` value in the text of a `/proc/*/status` file:
    `SECCOMP_MODE_DISABLED`, `SECCOMP_MODE_STRICT` or `SECCOMP_MODE_FILTER`.

    A kernel without CONFIG_SECCOMP prints no `Seccomp:` line and cannot
    filter, so a missing line is `SECCOMP_MODE_DISABLED`. A line whose value
    is not a decimal number gives -1. Only a line that starts with exactly
    `Seccomp:` counts (not `Seccomp_filters:`).
    """
    var key = StaticString("Seccomp:").as_bytes()
    var n = len(status)
    var line = 0
    while line < n:
        var hit = line + len(key) <= n
        if hit:
            for k in range(len(key)):
                if status[line + k] != key[k]:
                    hit = False
                    break
        if hit:
            var i = line + len(key)
            while i < n and (status[i] == UInt8(9) or status[i] == UInt8(32)):
                i += 1
            return _number(status, i)
        while line < n and status[line] != UInt8(10):
            line += 1
        line += 1
    return SECCOMP_MODE_DISABLED


def seccomp_mode() raises IoError -> Int:
    """The calling thread's seccomp mode, from /proc/thread-self/status (see
    `seccomp_mode_of_status`). Filters are per thread, and a probe syscall
    runs on the calling thread, so this reads the thread's own status rather
    than the process's. Raises if /proc is unavailable."""
    var data = _read_file(
        "/proc/thread-self/status", "read(/proc/thread-self/status)"
    )
    return seccomp_mode_of_status(Span(data))


@fieldwise_init
struct ProbePolicy(Equatable, TrivialRegisterPassable, Writable):
    """Whether `Capabilities.detect()` issues the probes a seccomp filter
    may punish with SIGSYS: `io_uring_setup` (`probe_io_uring`) and
    `epoll_pwait2` (`has_epoll_pwait2`).

    A skipped probe is reported as unavailable: `IoUringSupport.NotProbed`
    and `epoll_pwait2 = False`, so the process stays on epoll and on
    `epoll_pwait`, with millisecond timeouts rounded up (see
    `Epoll.disable_pwait2`).
    """

    var _v: UInt8

    comptime Auto = ProbePolicy(0)
    """Probe only when the calling thread has no seccomp filter (`Seccomp:`
    is 0). With a filter, or if the mode cannot be read, skip both probes.
    The default."""
    comptime Always = ProbePolicy(1)
    """Probe even under a seccomp filter. Use it only when the filter is
    known to answer with an errno (Docker/containerd defaults, Kubernetes
    RuntimeDefault, systemd with `SystemCallErrorNumber=`) or to allow both
    syscalls. Under a KILL or TRAP filter that lists either syscall, this
    ends the process."""
    comptime Never = ProbePolicy(2)
    """Never issue the two probes."""

    @inline(.always)
    def __eq__(self, rhs: Self) -> Bool:
        return self._v == rhs._v

    def name(self) -> StaticString:
        if self._v == 0:
            return "Auto"
        if self._v == 1:
            return "Always"
        return "Never"

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.name())

    def allows_probes(self) -> Bool:
        """Whether this policy lets the two probes run for the calling
        thread right now (`Auto` reads `seccomp_mode()`)."""
        if self == ProbePolicy.Always:
            return True
        if self == ProbePolicy.Never:
            return False
        try:
            return seccomp_mode() == SECCOMP_MODE_DISABLED
        except:
            return False  # unknown: it may be a filter, so do not probe


# ---- everything --------------------------------------------------------------


@fieldwise_init
struct Capabilities(TrivialRegisterPassable, Writable):
    """What this process can use, probed once at startup."""

    var kernel: KernelVersion
    var cpus: Int
    var page_size: Int
    var nofile: Rlimit
    var io_uring: IoUringSupport
    """`IoUringSupport.NotProbed` when `detect()`'s policy skipped it."""
    var epoll_pwait2: Bool
    """True only when probed and reachable; False also when `detect()`'s
    policy skipped the probe. When False, call `Epoll.disable_pwait2()`."""

    @staticmethod
    def detect(
        policy: ProbePolicy = ProbePolicy.Auto,
    ) raises IoError -> Capabilities:
        """Run every probe. `policy` decides whether the io_uring and
        epoll_pwait2 probes run (by default not under a seccomp filter,
        because a KILL/TRAP filter would end the process; see the module
        doc). Skipped probes are reported as unavailable:
        `io_uring == IoUringSupport.NotProbed`, `epoll_pwait2 == False`."""
        var kernel = kernel_version()
        var cpus = cpu_count()
        var pages = page_size()
        var nofile = nofile_limit()
        var io_uring = IoUringSupport.NotProbed
        var pwait2 = False
        if policy.allows_probes():
            io_uring = probe_io_uring()
            pwait2 = has_epoll_pwait2()
        return Capabilities(kernel, cpus, pages, nofile, io_uring, pwait2)

    def io_uring_usable(self) -> Bool:
        """io_uring reachable on a kernel with the 6.1-level features the
        backend targets (see docs/design.md)."""
        return (
            self.io_uring == IoUringSupport.Available
            and self.kernel.at_least(6, 1)
        )

    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            "Capabilities(kernel=",
            self.kernel,
            ", cpus=",
            self.cpus,
            ", page_size=",
            self.page_size,
            ", nofile=",
            self.nofile.cur,
            "/",
            self.nofile.max,
            ", io_uring=",
            self.io_uring,
            ", epoll_pwait2=",
            self.epoll_pwait2,
            ")",
        )
