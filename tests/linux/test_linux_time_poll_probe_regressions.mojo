# Regression tests for review fix group "linux-time-poll-probe":
# - F28: `Capabilities.detect()` used to issue io_uring_setup and epoll_pwait2
#   unconditionally, so a KILL/TRAP seccomp filter that lists either syscall
#   ended the process with SIGSYS at startup.
# - F38: the linux.time module doc claimed a raw clock_gettime costs
#   ~50-100 ns; docs/spikes.md measured 116-118 ns.
from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux.probe import (
    SECCOMP_MODE_DISABLED,
    SECCOMP_MODE_FILTER,
    SECCOMP_MODE_STRICT,
    Capabilities,
    IoUringSupport,
    ProbePolicy,
    cpu_count,
    has_epoll_pwait2,
    kernel_version,
    nofile_limit,
    page_size,
    probe_io_uring,
    seccomp_mode,
    seccomp_mode_of_status,
)


comptime _PY_HELPERS = """
import os, re, shutil, subprocess, sys, tempfile

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

def thread_seccomp_field():
    # The Seccomp: value of the calling thread, or 0 when the line is absent.
    with open("/proc/thread-self/status") as f:
        for line in f.read().split("\\n"):
            if line.startswith("Seccomp:"):
                return int(line.split(":", 1)[1].strip())
    return 0

# ---- F38 ----

def _module_doc(text):
    m = re.match(r'\\s*\"\"\"(.*?)\"\"\"', text, re.S)
    return m.group(1) if m else ""

def time_doc_problems():
    root = repo_root()
    doc = _module_doc(open(os.path.join(root, "src", "linux", "time.mojo")).read())
    flat = " ".join(doc.split())
    spikes = open(os.path.join(root, "docs", "spikes.md")).read()
    rows = [l for l in spikes.split("\\n")
            if l.startswith("|") and "linux.time.Instant.now" in l]
    if len(rows) != 1:
        return "docs/spikes.md: want 1 cost row for linux.time.Instant.now, got %d" % len(rows)
    m = re.search(r"(\\d+)\\s*[-\\u2013]\\s*(\\d+)\\s*ns", rows[0])
    if m is None:
        return "docs/spikes.md: no 'A-B ns' figure in: " + rows[0]
    measured = m.group(1) + "-" + m.group(2) + " ns"
    bad = []
    if flat == "":
        bad.append("src/linux/time.mojo has no module docstring")
    if measured not in flat:
        bad.append("time.mojo module doc does not cite the measured " + measured)
    if "docs/spikes.md" not in flat:
        bad.append("time.mojo module doc does not cite docs/spikes.md")
    if re.search(r"50\\s*[-\\u2013]\\s*100\\s*ns", flat):
        bad.append("time.mojo module doc still claims 50-100 ns")
    if "once per loop iteration" not in flat:
        bad.append("time.mojo module doc does not say to read the clock once per loop iteration")
    return "\\n".join(bad)

# ---- F28 ----

# Installs a one-syscall seccomp filter, then execs argv. Exit 77 when this
# host does not allow an unprivileged filter.
LAUNCHER = r'''
import ctypes, os, platform, resource, struct, sys
action, nr, argv = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
RET = {"kill": 0x80000000, "trap": 0x00030000, "eperm": 0x00050000 | 1,
       "enosys": 0x00050000 | 38}[action]
ALLOW = 0x7FFF0000
ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}[platform.machine()]
def ins(code, jt, jf, k):
    return struct.pack("=HBBI", code, jt, jf, k)
LD, JEQ, RETK = 0x20, 0x15, 0x06
# arch != native -> allow; nr == target -> action; else allow
prog = (ins(LD, 0, 0, 4) + ins(JEQ, 0, 3, ARCH) + ins(LD, 0, 0, 0)
        + ins(JEQ, 0, 1, nr) + ins(RETK, 0, 0, RET) + ins(RETK, 0, 0, ALLOW))
buf = ctypes.create_string_buffer(prog, len(prog))
class Fprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
fp = Fprog(len(prog) // 8, ctypes.cast(buf, ctypes.c_void_p))
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
# No core file from the SIGSYS cases.
resource.setrlimit(resource.RLIMIT_CORE, (0, resource.getrlimit(resource.RLIMIT_CORE)[1]))
# PR_SET_NO_NEW_PRIVS = 38; PR_SET_SECCOMP = 22, SECCOMP_MODE_FILTER = 2
if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(22, 2, ctypes.addressof(fp), 0, 0) != 0:
    sys.stderr.write("seccomp filter setup failed: errno %d" % ctypes.get_errno())
    sys.exit(77)
os.execv(argv[0], argv)
'''

# Uses only the API that existed before the fix, so it also builds against
# the old library (that is how the regression was shown to fail before).
HELPER_DEFAULT = '''
from linux.probe import Capabilities


def main() raises:
    var c = Capabilities.detect()
    print("io_uring=", c.io_uring, " epoll_pwait2=", c.epoll_pwait2, sep="")
'''

HELPER_POLICY = '''
from std.sys import argv
from linux.probe import Capabilities, ProbePolicy


def main() raises:
    var args = argv()
    var policy = ProbePolicy.Auto
    var a = String(args[1])
    if a == "always":
        policy = ProbePolicy.Always
    elif a == "never":
        policy = ProbePolicy.Never
    var c = Capabilities.detect(policy)
    print("io_uring=", c.io_uring, " epoll_pwait2=", c.epoll_pwait2, sep="")
'''

SIGSYS = 31  # same number on x86_64 and aarch64
NR_IO_URING_SETUP = 425  # unified numbering, same on x86_64 and aarch64
NR_EPOLL_PWAIT2 = 441

def _build(mojo, root, d, name, source):
    src = os.path.join(d, name + ".mojo")
    with open(src, "w") as f:
        f.write(source)
    out = os.path.join(d, name)
    r = subprocess.run(
        [mojo, "build", "-I", os.path.join(root, "src"), "-o", out, src],
        capture_output=True, text=True, timeout=600,
    )
    if r.returncode != 0:
        raise RuntimeError("building " + name + " failed:\\n" + r.stdout + r.stderr)
    return out

def kill_filter_cases():
    # Returns ("skip", why) or ("done", problems), problems "" when all pass.
    mojo = shutil.which("mojo")
    if mojo is None:
        return ("skip", "mojo is not on PATH; run the tests through pixi")
    python = shutil.which("python3") or sys.executable
    if not python:
        return ("skip", "no python3 to launch the filtered child")
    root = repo_root()
    bad = []
    with tempfile.TemporaryDirectory() as d:
        launcher = os.path.join(d, "launcher.py")
        with open(launcher, "w") as f:
            f.write(LAUNCHER)
        default = _build(mojo, root, d, "helper_default", HELPER_DEFAULT)
        policy = _build(mojo, root, d, "helper_policy", HELPER_POLICY)

        def run(action, nr, argv):
            r = subprocess.run([python, launcher, action, str(nr)] + argv,
                               capture_output=True, text=True, timeout=120)
            return r.returncode, r.stdout.strip(), r.stderr.strip()

        # Can this host install a filter at all?
        code, out, err = run("eperm", NR_IO_URING_SETUP, [policy, "never"])
        if code == 77:
            return ("skip", "cannot install a seccomp filter here: " + err)

        def expect(label, action, nr, argv, code_want, out_has):
            code, out, err = run(action, nr, argv)
            if code != code_want:
                bad.append("%s: exit %d (want %d); out=%r err=%r"
                           % (label, code, code_want, out, err[-400:]))
                return
            for s in out_has:
                if s not in out:
                    bad.append("%s: %r not in %r" % (label, s, out))

        # The fix: the default detect() survives KILL/TRAP filters and
        # reports both probes as skipped.
        skipped = ["io_uring=NotProbed", "epoll_pwait2=False"]
        expect("default detect, KILL io_uring_setup", "kill",
               NR_IO_URING_SETUP, [default], 0, skipped)
        expect("default detect, TRAP io_uring_setup", "trap",
               NR_IO_URING_SETUP, [default], 0, skipped)
        expect("default detect, KILL epoll_pwait2", "kill",
               NR_EPOLL_PWAIT2, [default], 0, skipped)
        expect("Never, KILL io_uring_setup", "kill",
               NR_IO_URING_SETUP, [policy, "never"], 0, skipped)
        # The filter really is live: opting in under it is fatal. Without
        # this, the cases above could pass with an ineffective filter.
        expect("Always, KILL io_uring_setup", "kill",
               NR_IO_URING_SETUP, [policy, "always"], -SIGSYS, [])
        expect("Always, KILL epoll_pwait2", "kill",
               NR_EPOLL_PWAIT2, [policy, "always"], -SIGSYS, [])
        # Opting in under an errno filter still classifies the answer.
        expect("Always, EPERM io_uring_setup", "eperm",
               NR_IO_URING_SETUP, [policy, "always"], 0, ["io_uring=Disabled"])
        expect("Always, ENOSYS io_uring_setup", "enosys",
               NR_IO_URING_SETUP, [policy, "always"], 0, ["io_uring=NotCompiled"])
        expect("Always, EPERM epoll_pwait2", "eperm",
               NR_EPOLL_PWAIT2, [policy, "always"], 0, ["epoll_pwait2=False"])
    return ("done", "\\n".join(bad))
"""


def _py() raises -> PythonObject:
    return Python.evaluate(
        _PY_HELPERS, file=True, name="linux_time_poll_probe_helpers"
    )


def _seccomp_of(text: StaticString) -> Int:
    return seccomp_mode_of_status(text.as_bytes())


# ---- F28: seccomp mode -------------------------------------------------------


def test_f28_seccomp_status_parser() raises:
    assert_equal(
        _seccomp_of("Name:\tx\nSeccomp:\t2\nSeccomp_filters:\t1\n"),
        SECCOMP_MODE_FILTER,
    )
    assert_equal(_seccomp_of("Seccomp:\t0\n"), SECCOMP_MODE_DISABLED)
    assert_equal(_seccomp_of("Seccomp:  1"), SECCOMP_MODE_STRICT)
    # `Seccomp_filters:` is a different field, even when it comes first.
    assert_equal(
        _seccomp_of("Seccomp_filters:\t3\nSeccomp:\t2\n"), SECCOMP_MODE_FILTER
    )
    assert_equal(_seccomp_of("Seccomp_filters:\t3\n"), SECCOMP_MODE_DISABLED)
    # Only a line start counts.
    assert_equal(_seccomp_of("XSeccomp:\t2\n"), SECCOMP_MODE_DISABLED)
    assert_equal(_seccomp_of("Name:\tSeccomp:\t2\n"), SECCOMP_MODE_DISABLED)
    # No line (CONFIG_SECCOMP=n): no filter is possible.
    assert_equal(_seccomp_of(""), SECCOMP_MODE_DISABLED)
    assert_equal(_seccomp_of("Name:\tx\nUmask:\t0022\n"), SECCOMP_MODE_DISABLED)
    # Garbled value.
    assert_equal(_seccomp_of("Seccomp:\tx\n"), -1)
    assert_equal(_seccomp_of("Seccomp:"), -1)


def test_f28_seccomp_mode_live() raises:
    var py = _py()
    assert_equal(seccomp_mode(), Int(py=py.thread_seccomp_field()))
    var m = seccomp_mode()
    assert_true(m >= SECCOMP_MODE_DISABLED and m <= SECCOMP_MODE_FILTER)


# ---- F28: ProbePolicy in this process ---------------------------------------


def _same_basics(c: Capabilities) raises:
    assert_true(c.kernel == kernel_version())
    assert_equal(c.cpus, cpu_count())
    assert_equal(c.page_size, page_size())
    assert_equal(c.nofile.cur, nofile_limit().cur)
    assert_equal(c.nofile.max, nofile_limit().max)


def test_f28_policy_never_skips_both_probes() raises:
    var c = Capabilities.detect(ProbePolicy.Never)
    _same_basics(c)
    assert_true(c.io_uring == IoUringSupport.NotProbed, String(c))
    assert_false(c.epoll_pwait2)
    assert_false(c.io_uring_usable())
    assert_true("io_uring=NotProbed" in String(c), String(c))


def test_f28_policy_always_matches_direct_probes() raises:
    var c = Capabilities.detect(ProbePolicy.Always)
    _same_basics(c)
    assert_true(c.io_uring == probe_io_uring(), String(c))
    assert_equal(c.epoll_pwait2, has_epoll_pwait2())


def test_f28_default_policy_follows_seccomp_mode() raises:
    var c = Capabilities.detect()
    _same_basics(c)
    var unfiltered = seccomp_mode() == SECCOMP_MODE_DISABLED
    assert_equal(ProbePolicy.Auto.allows_probes(), unfiltered)
    if unfiltered:
        assert_true(c.io_uring == probe_io_uring(), String(c))
        assert_equal(c.epoll_pwait2, has_epoll_pwait2())
    else:
        print("note: this test process runs under a seccomp filter")
        assert_true(c.io_uring == IoUringSupport.NotProbed, String(c))
        assert_false(c.epoll_pwait2)
    assert_true(ProbePolicy.Always.allows_probes())
    assert_false(ProbePolicy.Never.allows_probes())


def test_f28_names() raises:
    assert_equal(String(IoUringSupport.NotProbed), "NotProbed")
    assert_equal(String(IoUringSupport.Disabled), "Disabled")
    assert_true(IoUringSupport.NotProbed != IoUringSupport.Disabled)
    assert_true(IoUringSupport.NotProbed != IoUringSupport.Available)
    assert_true(IoUringSupport.NotProbed != IoUringSupport.NotCompiled)
    assert_equal(String(ProbePolicy.Auto), "Auto")
    assert_equal(String(ProbePolicy.Always), "Always")
    assert_equal(String(ProbePolicy.Never), "Never")
    assert_true(ProbePolicy.Auto != ProbePolicy.Always)


# ---- F28: a real KILL/TRAP filter in a child process --------------------------


def test_f28_detect_survives_kill_filter() raises:
    var r = _py().kill_filter_cases()
    var status = String(py=r[0])
    var text = String(py=r[1])
    if status == "skip":
        print(
            String("    (skipped: test_f28_detect_survives_kill_filter: ", text)
            + ")"
        )
        return
    assert_equal(text, "")


# ---- F38: the clock cost in the linux.time docs ------------------------------


def test_f38_time_doc_matches_measured_cost() raises:
    var problems = String(py=_py().time_doc_problems())
    assert_equal(problems, "")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
