"""Processes with raw syscalls: replacing this one with a program
(`Exec.exec`, also this program again: `Exec.this_program`), starting
children (`spawn`) and waiting for them through pidfds (`Child`), CPU
affinity, and this process's threads (`threads`, `all_threads_block`).

`spawn` is clone3 with CLONE_PIDFD (a fork) followed at once by execve in
the child; where a seccomp profile refuses clone3 (Docker's default, with
ENOSYS), clone(2) with CLONE_PIDFD does the same. Between the clone and
execve the child runs only raw syscalls on memory laid out before the
clone (`Exec`). Every Mojo process has threads, and a child copied from
one may find a lock (the allocator's, say) held forever by a thread that
does not exist in it: it must not allocate or free before execve
replaces it.
"""

from std.bit import pop_count

from .abi import CloneArgs, Siginfo
from .consts import (
    AT_FDCWD,
    CLD_EXITED,
    CLONE_PIDFD,
    F_SETFD,
    O_CLOEXEC,
    O_RDONLY,
    P_ALL,
    P_PID,
    P_PIDFD,
    SIGCHLD,
    SIG_SETMASK,
    WEXITED,
    WNOHANG,
    WNOWAIT,
)
from .errno import Errno
from .error import ErrorKind, IoError, check
from .fd import AsFd, OwnedFd
from .fs import read_file
from .nr import (
    SYS_clone,
    SYS_clone3,
    SYS_execve,
    SYS_exit_group,
    SYS_fcntl,
    SYS_getdents64,
    SYS_openat,
    SYS_pidfd_send_signal,
    SYS_rt_sigprocmask,
    SYS_sched_getaffinity,
    SYS_sched_setaffinity,
    SYS_waitid,
)
from .signal import SignalSet
from .sys import keep_alive
from .syscall import _asm1, _asm3, _asm4, err_of, is_err, syscall1, syscall2, syscall3, syscall4, syscall5

comptime _CPU_WORDS = 16
"""Affinity masks start at 1024 CPUs: `allowed_cpus` doubles its mask
while the kernel answers EINVAL (one smaller than `nr_cpu_ids`), and the
masks given to the kernel grow to the highest CPU named."""


comptime _MAX_CPUS = 1 << 22
"""The kernel's limit on CPU numbers (CONFIG_NR_CPUS at most 2^22)."""


def _mask_words(cpu: Int) -> Int:
    """Words of a mask that holds `cpu` (at least `_CPU_WORDS`)."""
    return max(_CPU_WORDS, cpu // 64 + 1)


def _entries(data: List[UInt8]) -> List[List[UInt8]]:
    """The NUL-terminated entries of a /proc list (cmdline, environ)."""
    var out = List[List[UInt8]]()
    var start = 0
    for i in range(len(data)):
        if data[i] == 0:
            var e = List[UInt8]()
            e.extend(Span(data)[start:i])
            out.append(e^)
            start = i + 1
    if start < len(data):  # (no final NUL)
        var e = List[UInt8]()
        e.extend(Span(data)[start:])
        out.append(e^)
    return out^


def _bytes(s: StringSlice) -> List[UInt8]:
    var out = List[UInt8]()
    out.extend(s.as_bytes())
    return out^


def _starts_with(entry: List[UInt8], prefix: Span[UInt8, _]) -> Bool:
    if len(entry) < len(prefix):
        return False
    for i in range(len(prefix)):
        if entry[i] != prefix[i]:
            return False
    return True


struct Exec(Movable):
    """A program to execute: its path, arguments (argv[0] first) and
    environment ("NAME=value" entries), kept as bytes, and laid out for
    execve (NUL-terminated strings and pointer arrays) before each use."""

    var path: List[UInt8]
    var args: List[List[UInt8]]
    var env: List[List[UInt8]]
    var _arena: List[UInt8]
    var _ptrs: List[Int]
    """argv pointers and a 0, then envp pointers and a 0."""
    var _envp_at: Int

    def __init__(out self, path: StringSlice, args: List[String], env: List[String] = List[String]()):
        self.path = _bytes(path)
        self.args = List[List[UInt8]]()
        for i in range(len(args)):
            self.args.append(_bytes(args[i]))
        self.env = List[List[UInt8]]()
        for i in range(len(env)):
            self.env.append(_bytes(env[i]))
        self._arena = List[UInt8]()
        self._ptrs = List[Int]()
        self._envp_at = 0

    @staticmethod
    def this_program() raises IoError -> Exec:
        """This program again: /proc/self/exe with the arguments and the
        environment it was started with (/proc/self/cmdline and
        /proc/self/environ, so later changes to the environment are not
        seen). Under `mojo run` that is the compiler, which compiles the
        program again."""
        var e = Exec("/proc/self/exe", List[String]())
        e.args = _entries(read_file("/proc/self/cmdline", "Exec.this_program"))
        e.env = _entries(read_file("/proc/self/environ", "Exec.this_program"))
        return e^

    def get_env(self, name: StringSlice) -> Optional[String]:
        """The value of `name` in the environment, if set."""
        var prefix = _bytes(name)
        prefix.append(UInt8(ord("=")))
        for i in range(len(self.env)):
            if _starts_with(self.env[i], Span(prefix)):
                return String(from_utf8_lossy=Span(self.env[i])[len(prefix) :])
        return None

    def set_env(mut self, name: StringSlice, value: StringSlice):
        """Set `name` (replacing every entry for it)."""
        self.remove_env(name)
        var entry = _bytes(name)
        entry.append(UInt8(ord("=")))
        entry.extend(value.as_bytes())
        self.env.append(entry^)

    def remove_env(mut self, name: StringSlice):
        var prefix = _bytes(name)
        prefix.append(UInt8(ord("=")))
        var kept = List[List[UInt8]]()
        for i in range(len(self.env)):
            if not _starts_with(self.env[i], Span(prefix)):
                kept.append(self.env[i].copy())
        self.env = kept^

    def _put(mut self, entry: List[UInt8], mut starts: List[Int]) raises IoError:
        for b in entry:
            if b == 0:
                raise IoError.of_kind("Exec", ErrorKind.InvalidInput)
        starts.append(len(self._arena))
        self._arena.extend(Span(entry))
        self._arena.append(0)

    def _layout(mut self) raises IoError:
        """Lay out the strings and pointer arrays. A NUL inside a string is
        `InvalidInput` (execve would cut it there)."""
        self._arena.clear()
        var starts = List[Int]()
        self._put(self.path.copy(), starts)
        for i in range(len(self.args)):
            self._put(self.args[i].copy(), starts)
        for i in range(len(self.env)):
            self._put(self.env[i].copy(), starts)
        # Only now is the arena final: pointers into it stay valid.
        var base = Int(self._arena.unsafe_ptr())
        self._ptrs.clear()
        for i in range(len(self.args)):
            self._ptrs.append(base + starts[1 + i])
        self._ptrs.append(0)
        self._envp_at = len(self._ptrs)
        for i in range(len(self.env)):
            self._ptrs.append(base + starts[1 + len(self.args) + i])
        self._ptrs.append(0)

    def _path_ptr(self) -> Int:
        return Int(self._arena.unsafe_ptr())

    def _argv_ptr(self) -> Int:
        return Int(self._ptrs.unsafe_ptr())

    def _envp_ptr(self) -> Int:
        return Int(self._ptrs.unsafe_ptr()) + self._envp_at * 8

    def exec(mut self) raises IoError:
        """Replace this process with the program (execve). Returns only by
        raising. Descriptors without CLOEXEC, the signal mask and the CPU
        affinity carry over."""
        self._layout()
        var r = syscall3(SYS_execve, self._path_ptr(), self._argv_ptr(), self._envp_ptr())
        keep_alive(self)
        raise IoError.from_errno("execve", Errno(err_of(r)))


@fieldwise_init
struct ExitStatus(Equatable, TrivialRegisterPassable, Writable):
    """How a child ended: its exit code, or the signal that killed it."""

    var code: Int
    """The exit code, or -1 if a signal ended it."""
    var signal: Int
    """The signal that ended it, or 0."""

    def success(self) -> Bool:
        return self.code == 0 and self.signal == 0

    def __eq__(self, other: ExitStatus) -> Bool:
        return self.code == other.code and self.signal == other.signal

    def write_to(self, mut writer: Some[Writer]):
        if self.signal != 0:
            writer.write("killed by signal ", self.signal)
        else:
            writer.write("exit status ", self.code)


struct Child(AsFd, Movable, Writable):
    """A child process, held by its pidfd: readable (EPOLLIN) once the
    child has ended. Signals and waits go through the pidfd, so they never
    reach another process that reused the pid. A child that is never
    waited for stays a zombie until this process ends."""

    var pid: Int
    var _pidfd: OwnedFd

    def __init__(out self, pid: Int, var pidfd: OwnedFd):
        self.pid = pid
        self._pidfd = pidfd^

    @inline(.always)
    def raw_fd(self) -> Int32:
        return self._pidfd.raw_fd()

    def signal(self, sig: Int) raises IoError:
        """Send `sig` (ESRCH once it has been waited for)."""
        _ = check(
            "pidfd_send_signal",
            syscall4(SYS_pidfd_send_signal, Int(self._pidfd.raw_fd()), sig, 0, 0),
        )

    def _wait(self, options: Int) raises IoError -> Optional[ExitStatus]:
        var info = Siginfo()
        while True:
            var r = syscall5(
                SYS_waitid, P_PIDFD, Int(self._pidfd.raw_fd()), Int(Pointer(to=info)), options, 0
            )
            keep_alive(info)
            if not is_err(r):
                break
            var e = Errno(err_of(r))
            if e != Errno.EINTR:
                raise IoError.from_errno("waitid", e)
        if info.pid == 0:
            return None  # (WNOHANG) still running
        if Int(info.code) == CLD_EXITED:
            return ExitStatus(Int(info.status), 0)
        return ExitStatus(-1, Int(info.status))

    def try_wait(self) raises IoError -> Optional[ExitStatus]:
        """How the child ended, reaping it; None while it runs."""
        return self._wait(WEXITED | WNOHANG)

    def wait(self) raises IoError -> ExitStatus:
        """Block until the child ends, and reap it."""
        return self._wait(WEXITED).value()

    def write_to(self, mut writer: Some[Writer]):
        writer.write("Child(pid=", self.pid, ")")


def _child(path: Int, argv: Int, envp: Int, keep: Int, cpus: Int, cpu_bytes: Int, mask: Int):
    """The new child, until execve: raw syscalls on prepared memory only
    (see the module docs). Never returns. The bare `_asmN`, not `syscallN`:
    in a fault-seam build `syscallN` first looks up the fault plan through
    the Mojo runtime, whose lock a thread that does not exist in the child
    may hold, and would apply the parent's rules in the child."""
    if cpus != 0:
        _ = _asm3(SYS_sched_setaffinity, 0, cpu_bytes, cpus)
    if keep >= 0:
        _ = _asm3(SYS_fcntl, keep, F_SETFD, 0)  # survives execve
    if mask != 0:
        _ = _asm4(SYS_rt_sigprocmask, SIG_SETMASK, mask, 0, 8)
    _ = _asm3(SYS_execve, path, argv, envp)
    while True:
        _ = _asm1(SYS_exit_group, 127)


def spawn(
    mut program: Exec, *, keep: Int32 = -1, cpu: Int = -1, signal_mask: Optional[SignalSet] = None
) raises IoError -> Child:
    """Start `program` in a new child process.

    - `keep`: a descriptor (CLOEXEC, like every descriptor this library
      opens) that the child keeps across execve, at the same number.
    - `cpu` >= 0: the child's CPU affinity is that one CPU from before
      execve. The Mojo runtime sizes its thread pool by the affinity at
      start, so the program starts one runtime thread instead of one per
      CPU; it may widen its own affinity afterwards.
    - `signal_mask`: the child's signal mask from before execve. Without one it
      inherits the calling thread's, which is what a program that blocked
      SIGTERM for a signalfd may not want its children to have.
    - A child whose execve fails exits with status 127."""
    program._layout()
    if cpu >= _MAX_CPUS:
        raise IoError.of_kind("spawn", ErrorKind.InvalidInput)
    var mask = List[UInt64](length=_mask_words(max(cpu, 0)), fill=0)
    if cpu >= 0:
        mask[cpu // 64] = UInt64(1) << UInt64(cpu % 64)
    var pidfd: Int32 = -1
    var args = CloneArgs()
    args.flags = UInt64(CLONE_PIDFD)
    args.pidfd = UInt64(Int(Pointer(to=pidfd)))
    args.exit_signal = UInt64(SIGCHLD)
    var path = program._path_ptr()
    var argv = program._argv_ptr()
    var envp = program._envp_ptr()
    var cpus = Int(mask.unsafe_ptr()) if cpu >= 0 else 0
    var cpu_bytes = len(mask) * 8
    # (less glibc's signals 32 and 33, as `linux.signal.set_mask` does)
    var sigs: UInt64 = signal_mask.value().bits & ~((UInt64(1) << 31) | (UInt64(1) << 32)) if signal_mask else 0
    var sigs_at = Int(Pointer(to=sigs)) if signal_mask else 0
    var op: StaticString = "clone3"
    var r = syscall2(SYS_clone3, Int(Pointer(to=args)), 88)
    if r == 0:
        _child(path, argv, envp, Int(keep), cpus, cpu_bytes, sigs_at)
    if is_err(r) and (Errno(err_of(r)) == Errno.ENOSYS or Errno(err_of(r)) == Errno.EPERM):
        # clone3 refused (a seccomp filter): clone(2) with CLONE_PIDFD,
        # which stores the pidfd at parent_tid, its third argument on both
        # architectures (they differ in the fourth and fifth, unused here).
        op = "clone"
        r = syscall5(SYS_clone, CLONE_PIDFD | SIGCHLD, 0, Int(Pointer(to=pidfd)), 0, 0)
        if r == 0:
            _child(path, argv, envp, Int(keep), cpus, cpu_bytes, sigs_at)
    # Everything the child reads stays alive (and undestroyed) past the
    # clone on both sides: in the child, nothing after `_child` runs.
    keep_alive(args)
    keep_alive(mask)
    keep_alive(sigs)
    keep_alive(program)
    keep_alive(pidfd)
    if is_err(r):
        raise IoError.from_errno(op, Errno(err_of(r)))
    return Child(r, OwnedFd(unsafe_from_raw=pidfd))


def reap_others(known: List[Int]) raises IoError -> Int:
    """Reap children that ended and are not among the pids in `known`:
    orphans a process running as PID 1 (in a container) inherits, which
    would otherwise stay zombies. Stops at the first one that is in
    `known` (its own pidfd reaps it). Returns how many it reaped."""
    var reaped = 0
    while True:
        var info = Siginfo()
        var r = syscall5(SYS_waitid, P_ALL, 0, Int(Pointer(to=info)), WEXITED | WNOHANG | WNOWAIT, 0)
        keep_alive(info)
        if is_err(r) or info.pid == 0:
            return reaped  # (ECHILD: no children at all)
        var pid = Int(info.pid)
        for i in range(len(known)):
            if known[i] == pid:
                return reaped
        var done = Siginfo()
        _ = syscall5(SYS_waitid, P_PID, pid, Int(Pointer(to=done)), WEXITED | WNOHANG, 0)
        keep_alive(done)
        reaped += 1


def allowed_cpus() raises IoError -> List[Int]:
    """The CPUs the calling thread may run on (its affinity), in order."""
    var words = _CPU_WORDS
    var mask = List[UInt64](length=words, fill=0)
    var r: Int
    while True:
        r = syscall3(SYS_sched_getaffinity, 0, words * 8, Int(mask.unsafe_ptr()))
        keep_alive(mask)
        if not (is_err(r) and Errno(err_of(r)) == Errno.EINVAL and words * 64 < _MAX_CPUS):
            break
        words *= 2  # (the kernel's mask is larger: more than words * 64 CPUs)
        mask = List[UInt64](length=words, fill=0)
    _ = check("sched_getaffinity", r)
    var out = List[Int]()
    for w in range(r // 8):
        if pop_count(mask[w]) == 0:
            continue
        for b in range(64):
            if (mask[w] >> UInt64(b)) & 1 == 1:
                out.append(w * 64 + b)
    return out^


def set_allowed_cpus(cpus: List[Int]) raises IoError:
    """Restrict the calling thread to `cpus` (EINVAL if none is usable)."""
    var top = 0
    for i in range(len(cpus)):
        var c = cpus[i]
        if c < 0 or c >= _MAX_CPUS:
            raise IoError.of_kind("set_allowed_cpus", ErrorKind.InvalidInput)
        top = max(top, c)
    var mask = List[UInt64](length=_mask_words(top), fill=0)
    for i in range(len(cpus)):
        mask[cpus[i] // 64] |= UInt64(1) << UInt64(cpus[i] % 64)
    var r = syscall3(SYS_sched_setaffinity, 0, len(mask) * 8, Int(mask.unsafe_ptr()))
    keep_alive(mask)
    _ = check("sched_setaffinity", r)


# ---- threads -----------------------------------------------------------------


def threads() raises IoError -> List[Int]:
    """The ids of this process's threads (/proc/self/task)."""
    var path = _bytes("/proc/self/task")
    path.append(0)
    var r: Int
    while True:
        r = syscall4(SYS_openat, AT_FDCWD, Int(path.unsafe_ptr()), O_RDONLY | O_CLOEXEC, 0)
        if not (is_err(r) and Errno(err_of(r)) == Errno.EINTR):
            break
    keep_alive(path)
    var dir = OwnedFd(unsafe_from_raw=Int32(check("openat(/proc/self/task)", r)))
    var buf = List[UInt8](length=4096, fill=0)
    var out = List[Int]()
    while True:
        var n = syscall3(SYS_getdents64, Int(dir.raw_fd()), Int(buf.unsafe_ptr()), len(buf))
        keep_alive(buf)
        if is_err(n):
            if Errno(err_of(n)) == Errno.EINTR:
                continue
            raise IoError.from_errno("getdents64", Errno(err_of(n)))
        if n == 0:
            break
        var off = 0
        while off < n:
            # struct linux_dirent64 { u64 ino; s64 off; u16 reclen; u8 type; char name[]; }
            var reclen = Int(buf[off + 16]) | (Int(buf[off + 17]) << 8)
            var i = off + 19
            var tid = 0
            var digits = 0
            while Int(buf[i]) >= ord("0") and Int(buf[i]) <= ord("9"):
                tid = tid * 10 + Int(buf[i]) - ord("0")
                digits += 1
                i += 1
            if digits > 0 and buf[i] == 0:
                out.append(tid)  # (not "." or "..")
            off += reclen
    keep_alive(dir)
    return out^


def _sigblk(status: List[UInt8]) -> Optional[UInt64]:
    """The SigBlk mask of a /proc/<pid>/task/<tid>/status text."""
    var key = _bytes("SigBlk:")
    for i in range(len(status) - len(key) + 1):
        if i > 0 and status[i - 1] != UInt8(10):
            continue  # (only at the start of a line: not in a thread's Name)
        var at = True
        for j in range(len(key)):
            if status[i + j] != key[j]:
                at = False
                break
        if not at:
            continue
        var v: UInt64 = 0
        var k = i + len(key)
        while k < len(status) and (Int(status[k]) == ord(" ") or Int(status[k]) == ord("\t")):
            k += 1
        while k < len(status):
            var c = Int(status[k])
            var d: Int
            if c >= ord("0") and c <= ord("9"):
                d = c - ord("0")
            elif c >= ord("a") and c <= ord("f"):
                d = c - ord("a") + 10
            else:
                break
            v = (v << 4) | UInt64(d)
            k += 1
        return v
    return None


def all_threads_block(set: SignalSet) raises IoError -> Bool:
    """Whether every thread of this process blocks every signal of `set`
    (from each /proc/self/task/<tid>/status). Only then does a
    process-directed signal of `set` stay pending for a signalfd instead of
    reaching a thread's handler (`linux.signal`). A thread that ends while
    this looks is skipped."""
    var tids = threads()
    for i in range(len(tids)):
        var status: List[UInt8]
        try:
            status = read_file(String("/proc/self/task/", tids[i], "/status"), "all_threads_block")
        except e:
            # Gone: ENOENT at the open, or ESRCH when it ended between the
            # open and the read.
            if e.kind == ErrorKind.NotFound or e.errno == Errno.ESRCH:
                continue
            raise e
        var mask = _sigblk(status)
        if not mask or not SignalSet(mask.value()).includes(set):
            return False
    return True
