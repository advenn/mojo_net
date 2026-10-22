"""Shared helpers for the spikes: procfs inspection with raw syscalls only.

Everything here goes through `linux.syscall`, so measuring the process does
not itself start libc/stdlib machinery (no `open`, no `listdir`). The task
count uses a stack buffer and a static path, so it is safe to call as the very
first statement of `main` before anything allocates.

Syscalls not (yet) in `linux.nr` are module-local here, with both arches.
"""

from std.sys import CompilationTarget

from linux import Errno, IoError, OwnedFd, check, sys
from linux.consts import AT_FDCWD, O_CLOEXEC, O_RDONLY
from linux.nr import SYS_gettid, SYS_openat
from linux.syscall import err_of, is_err, syscall0, syscall3, syscall4

comptime _X86 = CompilationTarget.is_x86()
comptime SYS_getdents64: Int = 217 if _X86 else 61
comptime SYS_getcpu: Int = 309 if _X86 else 168
comptime O_DIRECTORY: Int = 0o200000 if _X86 else 0o40000
"""Differs per arch: x86_64 0200000, aarch64 040000 (asm/fcntl.h)."""

comptime _TASK_DIR: StaticString = "/proc/self/task\0"


@inline(.always)
def gettid() -> Int:
    return syscall0(SYS_gettid)


def getcpu() -> Int:
    """CPU the calling thread is running on right now (getcpu(2))."""
    var cpu: UInt32 = 0
    var r = syscall3(SYS_getcpu, Int(Pointer(to=cpu)), 0, 0)
    if is_err(r):
        return -Int(err_of(r))
    return Int(cpu)


@inline(.always)
def _openat(path: Span[UInt8, _], flags: Int) -> Int:
    """`path` must be NUL-terminated."""
    return syscall4(SYS_openat, AT_FDCWD, Int(path.unsafe_ptr()), flags, 0)


def _open_retry(path: Span[UInt8, _], flags: Int) raises IoError -> OwnedFd:
    var r: Int
    while True:
        r = _openat(path, flags)
        if not (is_err(r) and Errno(err_of(r)) == Errno.EINTR):
            break
    return OwnedFd(unsafe_from_raw=Int32(check("openat", r)))


@inline(.always)
def _getdents64(fd: OwnedFd, mut buf: Array[UInt8, 4096]) -> Int:
    # `fd` and `buf` are borrowed for the whole call, so both outlive it.
    return syscall3(
        SYS_getdents64, Int(fd.raw_fd()), Int(Pointer(to=buf)), 4096
    )


def _is_dot(ref buf: Array[UInt8, 4096], name: Int) -> Bool:
    comptime DOT = UInt8(ord("."))
    if buf[name] != DOT:
        return False
    if buf[name + 1] == 0:
        return True
    return buf[name + 1] == DOT and buf[name + 2] == 0


def _scan_tasks(mut out: List[Int], collect: Bool) raises IoError -> Int:
    var fd = _open_retry(
        _TASK_DIR.as_bytes(), O_RDONLY | O_DIRECTORY | O_CLOEXEC
    )
    var buf = Array[UInt8, 4096](fill=0)
    var count = 0
    while True:
        var n = _getdents64(fd, buf)
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
            var name = off + 19
            if not _is_dot(buf, name):
                count += 1
                if collect:
                    var v = 0
                    var i = name
                    while buf[i] != 0:
                        v = v * 10 + Int(buf[i]) - ord("0")
                        i += 1
                    out.append(v)
            off += reclen
    return count


def count_tasks() raises IoError -> Int:
    """Number of threads in this process. Allocates nothing."""
    var unused = List[Int]()
    return _scan_tasks(unused, False)


def list_tasks() raises IoError -> List[Int]:
    var out = List[Int]()
    _ = _scan_tasks(out, True)
    return out^


def read_proc(path: String) raises IoError -> String:
    """Whole contents of a small procfs file (openat/read, EINTR retried)."""
    var cpath = List[UInt8](capacity=path.byte_length() + 1)
    for b in path.as_bytes():
        cpath.append(b)
    cpath.append(0)
    var fd = _open_retry(Span(cpath), O_RDONLY | O_CLOEXEC)
    var out = List[UInt8]()
    var buf = List[UInt8](length=4096, fill=0)
    while True:
        var n = sys.read(fd, Span(buf))
        if is_err(n):
            if Errno(err_of(n)) == Errno.EINTR:
                continue
            raise IoError.from_errno("read", Errno(err_of(n)))
        if n == 0:
            break
        for i in range(n):
            out.append(buf[i])
    return String(unsafe_from_utf8=out)


def thread_comm(tid: Int) raises IoError -> String:
    var s = read_proc("/proc/self/task/" + String(tid) + "/comm")
    return String(s.strip())


def status_field(path: String, key: StaticString) raises IoError -> String:
    """Value of `key:` in a /proc/.../status file ("" if absent)."""
    var s = read_proc(path)
    # Not splitlines(): in Mojo 1.2.0rc2 it also splits on "\t".
    for line in s.split("\n"):
        if line.startswith(key):
            return String(line.removeprefix(key).strip())
    return String("")


def cpu_ticks() raises -> Int:
    """utime + stime of the whole process, in clock ticks (/proc/self/stat)."""
    var s = read_proc("/proc/self/stat")
    # comm (field 2) may contain spaces; fields after the last ')' are fixed.
    var rest = String(s[byte = s.rfind(")") + 2 :])
    var f = rest.split(" ")
    # rest starts at field 3 (state); utime = field 14, stime = field 15.
    return Int(f[11]) + Int(f[12])
