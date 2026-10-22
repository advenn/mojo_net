"""Regression tests for the linux-core review findings.

- F20: deadline expiry and kernel ETIMEDOUT share `ErrorKind.TimedOut`;
  `IoError.is_deadline()` tells them apart.
- F26: building for an unsupported target (aarch64_be, ...) is a compile
  error instead of a binary with byte-swapped ports and addresses.
- F29: the SIGPIPE policy of `linux.sys` (module doc): pipes raise it too,
  `MSG_NOSIGNAL` suppresses it on sockets, and no wrapper exists for the
  write paths that cannot suppress it.
- F37: docstrings in `src` cite files and methods that exist.
- F43: `sys.ioctl_int`, `sys.dup3` and `abi.Cmsghdr` (with the `cmsg_*`
  helpers) are exercised, including an SCM_RIGHTS round trip.

The source scans and the cross-target builds use Python (the pixi env's
CPython) and expect to run from the repository (any directory below it).
"""

from std.python import Python, PythonObject
from std.sys import CompilationTarget, size_of
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Errno, ErrorKind, IoError, OwnedFd, check, wait_ready
from linux import sys
from linux.abi import (
    CMSG_DATA_OFFSET,
    Cmsghdr,
    Iovec,
    Msghdr,
    Timespec,
    cmsg_align,
    cmsg_len,
    cmsg_space,
    hton16,
    hton32,
)
from linux.consts import (
    AF_UNIX,
    F_GETFD,
    FD_CLOEXEC,
    FIONREAD,
    MSG_CMSG_CLOEXEC,
    MSG_CTRUNC,
    MSG_NOSIGNAL,
    O_CLOEXEC,
    POLLIN,
    SCM_RIGHTS,
    SIG_BLOCK,
    SIG_SETMASK,
    SIGPIPE,
    SIOCOUTQ,
    SO_TYPE,
    SOCK_CLOEXEC,
    SOCK_DGRAM,
    SOCK_STREAM,
    SOL_SOCKET,
)
from linux.nr import SYS_rt_sigprocmask
from linux.syscall import SUPPORTED_TARGET, err_of, is_err, syscall4
from linux.time import Deadline, Duration

# Not in linux.nr (the library has no use for it); test-local, like the
# spikes' module-local numbers.
comptime _SYS_rt_sigtimedwait = 128 if CompilationTarget.is_x86() else 137
comptime _SIGSET_SIZE = 8


comptime _PY_HELPERS = """
import os, re, shutil, subprocess, tempfile

def repo_root():
    d = os.getcwd()
    while True:
        if os.path.isfile(os.path.join(d, "pixi.toml")) and os.path.isdir(
            os.path.join(d, "src", "linux")
        ):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            raise RuntimeError("run the tests from inside the repository")
        d = parent

def _sources(root):
    for dirpath, _, files in os.walk(os.path.join(root, "src")):
        for f in sorted(files):
            if f.endswith(".mojo"):
                p = os.path.join(dirpath, f)
                yield os.path.relpath(p, root), open(p).read()

def cited_paths_problems():
    # Every repo path a src docstring cites must exist; a build/ path must be
    # produced by a pixi task (it is generated and git-ignored).
    root = repo_root()
    pixi = open(os.path.join(root, "pixi.toml")).read()
    pat = re.compile(r"(?<![\\w/.])((?:tests|tools|docs|spikes|src|build)/[\\w./-]+\\.(?:mojo|md|py|sh|toml|c))")
    bad = []
    for rel, text in _sources(root):
        for m in pat.finditer(text):
            path = m.group(1)
            if path.startswith("build/"):
                if path not in pixi:
                    bad.append(rel + ": " + path + " (no pixi task produces it)")
            elif not os.path.exists(os.path.join(root, path)):
                bad.append(rel + ": " + path + " (does not exist)")
    return "\\n".join(bad)

def owner_method_problems():
    # `owner.NAME(` in src docs refers to an fd owner: NAME must be a method
    # defined in src/linux/fd.mojo.
    root = repo_root()
    fd = open(os.path.join(root, "src", "linux", "fd.mojo")).read()
    defined = set(re.findall(r"def (\\w+)\\(", fd))
    bad = []
    for rel, text in _sources(root):
        for name in re.findall(r"owner\\.(\\w+)\\(", text):
            if name not in defined:
                bad.append(rel + ": owner." + name + "()")
    return "\\n".join(bad)

def sigpipe_policy_problems():
    root = repo_root()
    sysmod = open(os.path.join(root, "src", "linux", "sys.mojo")).read()
    bad = []
    m = re.search(r"def write\\[[^\\n]*\\n\\s*\\"\\"\\"(.*?)\\"\\"\\"", sysmod, re.S)
    if m is None:
        bad.append("sys.write has no docstring")
    else:
        doc = m.group(1)
        for word in ("SIGPIPE", "pipe", "socket"):
            if word not in doc:
                bad.append("sys.write doc does not mention " + word)
    if "SIGPIPE policy" not in sysmod:
        bad.append("sys.mojo module doc has no SIGPIPE policy")
    # Write paths that cannot carry MSG_NOSIGNAL stay unused until the
    # policy records how SIGPIPE is handled for them.
    for rel, text in _sources(root):
        if rel.endswith(os.path.join("linux", "nr.mojo")):
            continue
        for nr in ("SYS_writev", "SYS_pwritev", "SYS_sendfile", "SYS_splice",
                   "SYS_vmsplice", "SYS_tee"):
            if re.search(r"\\b" + nr + r"\\b", text):
                bad.append(rel + " uses " + nr)
        for name in ("writev", "sendfile", "splice", "vmsplice"):
            if re.search(r"def " + name + r"\\b", text):
                bad.append(rel + " defines " + name)
    return "\\n".join(bad)

PROBE = '''
from linux.abi import hton16
from linux.nr import SYS_getpid
from linux.syscall import syscall0


def main():
    print(hton16(UInt16(syscall0(SYS_getpid) & 0xFFFF)))
'''

def cross_build(target):
    # Returns (exit code, compiler output) of building PROBE for `target`.
    mojo = shutil.which("mojo")
    if mojo is None:
        return (-1, "mojo is not on PATH; run the tests through pixi")
    root = repo_root()
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "probe.mojo")
        with open(src, "w") as f:
            f.write(PROBE)
        r = subprocess.run(
            [mojo, "build", "-I", os.path.join(root, "src"),
             "--target-triple", target, "--emit", "object",
             "-o", os.path.join(d, "probe.o"), src],
            capture_output=True, text=True, timeout=600,
        )
        return (r.returncode, r.stdout + r.stderr)

def cmsg_table(n):
    import socket
    return ",".join(
        str(socket.CMSG_LEN(i)) + ":" + str(socket.CMSG_SPACE(i)) for i in range(n)
    )
"""


def _py() raises -> PythonObject:
    return Python.evaluate(_PY_HELPERS, file=True, name="linux_core_helpers")


def _pipe() raises -> Tuple[OwnedFd, OwnedFd]:
    """(read end, write end), both CLOEXEC."""
    var fds = Array[Int32, 2](fill=-1)
    _ = check("pipe2", sys.pipe2(fds, O_CLOEXEC))
    return (OwnedFd(unsafe_from_raw=fds[0]), OwnedFd(unsafe_from_raw=fds[1]))


def _pair(type_: Int = SOCK_STREAM) raises -> Tuple[OwnedFd, OwnedFd]:
    var fds = Array[Int32, 2](fill=-1)
    _ = check(
        "socketpair", sys.socketpair(AF_UNIX, type_ | SOCK_CLOEXEC, 0, fds)
    )
    return (OwnedFd(unsafe_from_raw=fds[0]), OwnedFd(unsafe_from_raw=fds[1]))


# ---- F20: deadline expiry vs kernel ETIMEDOUT --------------------------------


def test_f20_deadline_expiry_is_deadline() raises:
    var p = _pipe()  # nothing is ever written: the read end never gets ready
    var raised = False
    try:
        _ = wait_ready(
            p[0],
            Int16(POLLIN),
            Deadline.after(Duration.from_millis(20)),
            "read",
        )
    except e:
        raised = True
        assert_true(e.kind == ErrorKind.TimedOut)
        assert_equal(e.errno.value, 0)
        assert_true(e.is_deadline())
    assert_true(raised)
    sys.keep_alive(p)


def test_f20_kernel_etimedout_is_not_deadline() raises:
    # The kernel aborted the connection (TCP_USER_TIMEOUT, keepalive, SYN
    # retries): same portable kind as before, but not a retryable deadline.
    var k = IoError.from_errno("read", Errno.ETIMEDOUT)
    assert_true(k.kind == ErrorKind.TimedOut)
    assert_false(k.is_deadline())
    var raised = False
    try:
        _ = check("recv", -Int(Errno.ETIMEDOUT.value))
    except e:
        raised = True
        assert_true(e.kind == ErrorKind.TimedOut)
        assert_false(e.is_deadline())
    assert_true(raised)
    # Other errors without an errno are not deadlines either.
    assert_false(IoError.of_kind("read", ErrorKind.UnexpectedEof).is_deadline())
    assert_true(IoError.of_kind("read", ErrorKind.TimedOut).is_deadline())


# ---- F26: unsupported targets fail to build ----------------------------------


def test_f26_host_target_is_supported_and_little_endian() raises:
    assert_true(SUPPORTED_TARGET)
    # hton16 must put the high byte first in memory (network order).
    var v = hton16(0x1F90)  # port 8080
    var b = Pointer(to=v).unsafe_bitcast[Array[UInt8, 2]]()[].copy()
    assert_equal(Int(b[0]), 0x1F)
    assert_equal(Int(b[1]), 0x90)
    var w = hton32(0x7F000001)  # 127.0.0.1
    var c = Pointer(to=w).unsafe_bitcast[Array[UInt8, 4]]()[].copy()
    assert_equal(Int(c[0]), 127)
    assert_equal(Int(c[3]), 1)


def test_f26_big_endian_target_is_a_build_error() raises:
    var py = _py()
    # The supported cross target still builds.
    var ok = py.cross_build("aarch64-unknown-linux-gnu")
    var ok_out = String(py=ok[1])
    assert_equal(Int(py=ok[0]), 0, ok_out)
    # aarch64_be used to build silently and swap every port and address.
    var be = py.cross_build("aarch64_be-unknown-linux-gnu")
    var be_out = String(py=be[1])
    assert_true(Int(py=be[0]) != 0, "aarch64_be built: " + be_out)
    assert_true(
        "supports only little-endian 64-bit Linux" in be_out,
        "aarch64_be failed for another reason: " + be_out,
    )


# ---- F29: SIGPIPE policy ------------------------------------------------------


def _sigmask(how: Int, set: UInt64) -> Tuple[Int, UInt64]:
    """rt_sigprocmask on the calling thread; returns (result, old mask)."""
    var new = set
    var old: UInt64 = 0
    var r = syscall4(
        SYS_rt_sigprocmask,
        how,
        Int(Pointer(to=new)),
        Int(Pointer(to=old)),
        _SIGSET_SIZE,
    )
    sys.keep_alive(new)
    sys.keep_alive(old)
    return (r, old)


def _take_pending(set: UInt64) -> Int:
    """rt_sigtimedwait(set, NULL, {0, 0}): the pending signal it consumed,
    or -EAGAIN if none of `set` is pending for this thread."""
    var s = set
    var zero = Timespec(0, 0)
    var r = syscall4(
        _SYS_rt_sigtimedwait,
        Int(Pointer(to=s)),
        0,
        Int(Pointer(to=zero)),
        _SIGSET_SIZE,
    )
    sys.keep_alive(s)
    sys.keep_alive(zero)
    return r


def _eagain() -> Int:
    return -Int(Errno.EAGAIN.value)


def _epipe() -> Int:
    return -Int(Errno.EPIPE.value)


def test_f29_sigpipe_from_pipe_socket_write_and_nosignal() raises:
    # SIGPIPE from a write is thread-directed: blocking it in this thread
    # keeps it pending (instead of killing the process) so the test can see
    # it, then consume it before restoring the mask. This is also the
    # mitigation the sys.mojo policy names for future sendfile/splice paths.
    comptime PIPE_BIT = UInt64(1) << UInt64(SIGPIPE - 1)

    var fds = Array[Int32, 2](fill=-1)
    _ = check("pipe2", sys.pipe2(fds, O_CLOEXEC))
    var pipe_r = OwnedFd(unsafe_from_raw=fds[0])
    var pipe_w = OwnedFd(unsafe_from_raw=fds[1])
    pipe_r^.close()
    var sv = Array[Int32, 2](fill=-1)
    _ = check(
        "socketpair", sys.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)
    )
    var sock = OwnedFd(unsafe_from_raw=sv[0])
    var peer = OwnedFd(unsafe_from_raw=sv[1])
    peer^.close()
    var x = String("x").as_bytes()

    var blocked = _sigmask(SIG_BLOCK, PIPE_BIT)
    if blocked[0] != 0:
        raise Error("rt_sigprocmask(SIG_BLOCK) failed: ", blocked[0])
    var pending_before = _take_pending(PIPE_BIT)
    # 1. write(2) on a pipe whose read end is closed: EPIPE and SIGPIPE.
    var pipe_ret = sys.write(pipe_w, x)
    var pipe_sig = _take_pending(PIPE_BIT)
    # 2. send(MSG_NOSIGNAL) on a socket whose peer is gone: EPIPE only.
    var nosig_ret = sys.send(sock, x, MSG_NOSIGNAL)
    var nosig_sig = _take_pending(PIPE_BIT)
    # 3. write(2) on the same socket: EPIPE and SIGPIPE.
    var plain_ret = sys.write(sock, x)
    var plain_sig = _take_pending(PIPE_BIT)
    var restored = _sigmask(SIG_SETMASK, blocked[1])

    assert_equal(restored[0], 0)
    assert_equal(pending_before, _eagain())
    assert_equal(pipe_ret, _epipe())
    assert_equal(pipe_sig, SIGPIPE)
    assert_equal(nosig_ret, _epipe())
    assert_equal(nosig_sig, _eagain())
    assert_equal(plain_ret, _epipe())
    assert_equal(plain_sig, SIGPIPE)


def test_f29_sigpipe_policy_documented_and_enforced() raises:
    var problems = String(py=_py().sigpipe_policy_problems())
    assert_equal(problems, "", problems)


# ---- F37: docstrings cite things that exist ----------------------------------


def test_f37_cited_repo_paths_exist() raises:
    var problems = String(py=_py().cited_paths_problems())
    assert_equal(problems, "", problems)


def test_f37_owner_methods_cited_in_docs_exist() raises:
    var problems = String(py=_py().owner_method_problems())
    assert_equal(problems, "", problems)


# ---- F43: ioctl_int, dup3, Cmsghdr --------------------------------------------


def test_f43_ioctl_int_fionread_and_siocoutq() raises:
    var p = _pair()
    _ = check("send", sys.send(p[0], String("hello").as_bytes(), MSG_NOSIGNAL))
    var queued: Int32 = -1
    assert_equal(
        check("ioctl(FIONREAD)", sys.ioctl_int(p[1], FIONREAD, queued)), 0
    )
    assert_equal(queued, 5)
    var unsent: Int32 = -1
    assert_equal(
        check("ioctl(SIOCOUTQ)", sys.ioctl_int(p[0], SIOCOUTQ, unsent)), 0
    )
    assert_true(unsent >= 0)
    # Pipes answer FIONREAD too.
    var fds = Array[Int32, 2](fill=-1)
    _ = check("pipe2", sys.pipe2(fds, O_CLOEXEC))
    var r = OwnedFd(unsafe_from_raw=fds[0])
    var w = OwnedFd(unsafe_from_raw=fds[1])
    _ = check("write", sys.write(w, String("abc").as_bytes()))
    var inpipe: Int32 = -1
    _ = check("ioctl(FIONREAD)", sys.ioctl_int(r, FIONREAD, inpipe))
    assert_equal(inpipe, 3)
    # An unknown request fails without touching `value`.
    var untouched: Int32 = 77
    var bad = sys.ioctl_int(r, 0x7FFF, untouched)
    assert_true(is_err(bad))
    assert_equal(untouched, 77)
    sys.keep_alive(w)


def test_f43_dup3_replaces_target_atomically_with_cloexec() raises:
    var dgram = _pair(SOCK_DGRAM)
    var stream = _pair(SOCK_STREAM)
    # Replace stream[0]'s number with a CLOEXEC duplicate of dgram[0]. The
    # target is a descriptor this test owns, so nothing else gets closed.
    var target = stream[0].raw_fd()
    assert_equal(
        check("dup3", sys.dup3(dgram[0], target, O_CLOEXEC)), Int(target)
    )
    var ty: Int32 = 0
    var tylen = UInt32(size_of[Int32]())
    _ = check(
        "getsockopt", sys.getsockopt(stream[0], SOL_SOCKET, SO_TYPE, ty, tylen)
    )
    assert_equal(
        Int(ty), SOCK_DGRAM
    )  # stream[0]'s number now names dgram[0]'s socket
    assert_true(
        (check("fcntl", sys.fcntl(stream[0], F_GETFD)) & FD_CLOEXEC) != 0
    )
    # dup3 to itself is EINVAL (unlike dup2), as are unknown flags.
    var same = sys.dup3(dgram[0], dgram[0].raw_fd(), O_CLOEXEC)
    assert_true(is_err(same) and Errno(err_of(same)) == Errno.EINVAL)
    var flags = sys.dup3(dgram[0], target, 1)
    assert_true(is_err(flags) and Errno(err_of(flags)) == Errno.EINVAL)


def test_f43_cmsg_helpers_match_cpython() raises:
    assert_equal(size_of[Cmsghdr](), 16)
    assert_equal(CMSG_DATA_OFFSET, 16)
    assert_equal(cmsg_align(0), 0)
    assert_equal(cmsg_align(1), 8)
    assert_equal(cmsg_align(8), 8)
    assert_equal(cmsg_align(17), 24)
    comptime N = 200
    var theirs = String(py=_py().cmsg_table(N)).split(",")
    assert_equal(len(theirs), N)
    for i in range(N):
        var ours = String(cmsg_len(i), ":", cmsg_space(i))
        assert_equal(ours, String(theirs[i]), String("n=", i))


def test_f43_scm_rights_roundtrip() raises:
    var sp = _pair()
    var fds = Array[Int32, 2](fill=-1)
    _ = check("pipe2", sys.pipe2(fds, O_CLOEXEC))
    var pr = OwnedFd(unsafe_from_raw=fds[0])
    var pw = OwnedFd(unsafe_from_raw=fds[1])

    # Send pw's descriptor with one data byte. The control buffer is
    # 8-aligned (UInt64 words) and exactly cmsg_space(4) bytes.
    comptime FD_BYTES = size_of[Int32]()
    comptime WORDS = cmsg_space(FD_BYTES) // 8
    var control = Array[UInt64, WORDS](fill=0)
    Pointer(to=control).unsafe_bitcast[Cmsghdr]()[] = Cmsghdr(
        UInt(cmsg_len(FD_BYTES)), Int32(SOL_SOCKET), Int32(SCM_RIGHTS)
    )
    Pointer(to=control).unsafe_bitcast[Array[Int32, WORDS * 2]]()[][
        CMSG_DATA_OFFSET // FD_BYTES
    ] = pw.raw_fd()
    var data = Array[UInt8, 1](fill=UInt8(ord("x")))
    var iov = Iovec(Int(Pointer(to=data)), UInt(1))
    var m = Msghdr(
        0,
        0,
        Int(Pointer(to=iov)),
        UInt(1),
        Int(Pointer(to=control)),
        UInt(cmsg_space(FD_BYTES)),
        0,
    )
    var n = check("sendmsg", sys.sendmsg(sp[0], m, MSG_NOSIGNAL))
    sys.keep_alive(control)
    sys.keep_alive(data)
    sys.keep_alive(iov)
    sys.keep_alive(pw)  # its number was inside the control buffer
    assert_equal(n, 1)

    var rcontrol = Array[UInt64, WORDS](fill=0)
    var rdata = Array[UInt8, 4](fill=0)
    var riov = Iovec(Int(Pointer(to=rdata)), UInt(4))
    var rm = Msghdr(
        0,
        0,
        Int(Pointer(to=riov)),
        UInt(1),
        Int(Pointer(to=rcontrol)),
        UInt(cmsg_space(FD_BYTES)),
        0,
    )
    var got = check("recvmsg", sys.recvmsg(sp[1], rm, MSG_CMSG_CLOEXEC))
    sys.keep_alive(rcontrol)
    sys.keep_alive(rdata)
    sys.keep_alive(riov)
    assert_equal(got, 1)
    assert_equal(Int(rdata[0]), ord("x"))
    assert_equal(Int(rm.flags) & MSG_CTRUNC, 0)
    assert_equal(Int(rm.controllen), cmsg_space(FD_BYTES))
    var hdr = Pointer(to=rcontrol).unsafe_bitcast[Cmsghdr]()[].copy()
    assert_equal(Int(hdr.len), cmsg_len(FD_BYTES))
    assert_equal(Int(hdr.level), SOL_SOCKET)
    assert_equal(Int(hdr.type), SCM_RIGHTS)
    var raw = Pointer(to=rcontrol).unsafe_bitcast[Array[Int32, WORDS * 2]]()[][
        CMSG_DATA_OFFSET // FD_BYTES
    ]
    assert_true(raw >= 0 and raw != pw.raw_fd())
    var passed = OwnedFd(unsafe_from_raw=raw)
    assert_true(passed.is_cloexec())  # MSG_CMSG_CLOEXEC
    # The received descriptor is the pipe's write end.
    _ = check("write", sys.write(passed, String("z").as_bytes()))
    var buf = List[UInt8](length=4, fill=0)
    assert_equal(check("read", sys.read(pr, Span(buf))), 1)
    assert_equal(Int(buf[0]), ord("z"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
