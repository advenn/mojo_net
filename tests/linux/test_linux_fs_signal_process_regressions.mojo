"""Regression tests for the second linux review (fs, signal, process).

- L2: `block`, `set_mask` and `SignalFd.new` leave glibc's signals 32 and 33
  out, so blocking "every signal" cannot hang a `setuid` in another thread
  (glibc's setuid waits until every thread has handled signal 33).
- L4: `all_threads_block` reads `SigBlk:` at the start of a line only, not
  inside a thread's name.
- L6: `set_allowed_cpus` takes CPU numbers past 1024 (the kernel ignores
  the ones that do not exist), instead of refusing them.
- L7: every `pkg.module.name` a docstring in `src` cites exists.

L1, L3, L5 and L6's EINVAL growth need the fault seam:
test_linux_fs_signal_process_regressions_faults.mojo.
"""

from std.ffi import external_call
from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import OwnedFd, check, sys
from linux.abi import Timespec
from linux.consts import AT_FDCWD, O_CLOEXEC, O_WRONLY, SIGTERM
from linux.fs import read_file
from linux.nr import SYS_openat
from linux.process import all_threads_block, allowed_cpus, set_allowed_cpus, threads
from linux.signal import SignalFd, SignalSet, blocked, block, set_mask
from linux.syscall import syscall4
from linux.time import unix_time_ns

comptime _ThreadEntry = def(OpaquePointer[MutAnyOrigin]) thin abi("C") -> OpaquePointer[MutAnyOrigin]


# ---- L2: glibc's signals ---------------------------------------------------------


def test_l2_blocking_every_signal_leaves_32_and_33() raises:
    var before = set_mask(SignalSet.empty())
    _ = block(SignalSet(~UInt64(0)))
    var after_block = blocked()
    _ = set_mask(SignalSet(~UInt64(0)))
    var after_set = blocked()
    _ = SignalFd.new(SignalSet(~UInt64(0)))  # (accepted, less 32 and 33)
    _ = set_mask(before)
    assert_true(after_block.contains(SIGTERM))
    assert_true(after_block.contains(31) and after_block.contains(34) and after_block.contains(64))
    assert_false(after_block.contains(32), "SIGCANCEL is glibc's")
    assert_false(after_block.contains(33), "SIGSETXID is glibc's")
    assert_true(after_set.contains(SIGTERM))
    assert_false(after_set.contains(32) or after_set.contains(33))


def _setuid_worker(arg: OpaquePointer[MutAnyOrigin]) abi("C") -> OpaquePointer[MutAnyOrigin]:
    var uid = external_call["getuid", UInt32]()
    _ = external_call["setuid", Int32](uid)  # (same uid: allowed, still a broadcast)
    return arg


def test_l2_setuid_in_another_thread_returns_while_this_one_blocks_everything() raises:
    var before = set_mask(SignalSet.empty())
    _ = block(SignalSet(~UInt64(0)))  # (blocks for a signalfd: the common pattern)
    var thread: UInt64 = 0
    var ctx = 0
    var made = external_call["pthread_create", Int32](
        Int(Pointer(to=thread)), 0, _setuid_worker, OpaquePointer[MutAnyOrigin](unsafe_from_address=Int(Pointer(to=ctx)))
    )
    assert_equal(made, 0)
    var at = unix_time_ns() + 5_000_000_000
    var deadline = Timespec(at // 1_000_000_000, at % 1_000_000_000)
    var joined = external_call["pthread_timedjoin_np", Int32](thread, 0, Int(Pointer(to=deadline)))
    sys.keep_alive(deadline)
    _ = set_mask(before)  # (with the bug: lets the stuck setuid finish)
    if joined != 0:
        _ = external_call["pthread_join", Int32](thread, 0)
    assert_equal(joined, 0, "setuid in another thread waited past 5 s for signal 33")
    sys.keep_alive(ctx)


# ---- L4: SigBlk at the start of a line -------------------------------------------


def _set_comm(tid: Int, name: StringSlice) raises:
    var path = List[UInt8](String("/proc/self/task/", tid, "/comm").as_bytes())
    path.append(0)
    var r = syscall4(SYS_openat, AT_FDCWD, Int(path.unsafe_ptr()), O_WRONLY | O_CLOEXEC, 0)
    sys.keep_alive(path)
    var fd = OwnedFd(unsafe_from_raw=Int32(check("open(comm)", r)))
    _ = check("write(comm)", sys.write(fd, name.as_bytes()))


def _comm(tid: Int) raises -> String:
    var text = String(from_utf8_lossy=Span(read_file(String("/proc/self/task/", tid, "/comm"), "comm")))
    return String(text.strip())


def test_l4_a_thread_named_sigblk_does_not_count_as_blocking() raises:
    var set = SignalSet.of(SIGTERM)
    assert_false(blocked().includes(set), "the test runs with SIGTERM unblocked")
    assert_false(all_threads_block(set))
    var tids = threads()
    var names = List[String]()
    for i in range(len(tids)):
        names.append(_comm(tids[i]))
    try:
        for i in range(len(tids)):
            _set_comm(tids[i], "SigBlk:ffffffff")
        assert_false(all_threads_block(set), "a thread name read as the SigBlk line")
    finally:
        for i in range(len(tids)):
            try:
                _set_comm(tids[i], names[i])
            except:
                pass  # (a thread that has ended)


# ---- L6: CPU numbers past 1024 ---------------------------------------------------


def test_l6_set_allowed_cpus_takes_cpu_numbers_past_1024() raises:
    var mine = allowed_cpus()
    var wider = mine.copy()
    wider.append(1500)  # (no such CPU here: the kernel keeps the ones that exist)
    set_allowed_cpus(wider)
    var now = allowed_cpus()
    assert_equal(len(now), len(mine))
    for i in range(len(mine)):
        assert_equal(now[i], mine[i])


# ---- L7: cited names exist -------------------------------------------------------

comptime _PY_HELPERS = """
import os, re

PKGS = ("linux", "bytes", "net", "http", "server", "pg", "redis", "crypto", "rt")
# A backticked name that starts with a package and one of its modules:
# `linux.process.Exec.this_program()`. A name followed by `*` is a prefix
# (`linux.consts.TCPI_OFF_*`).
PAT = re.compile(r"`((?:%s)\\.[a-z_]\\w*(?:\\.[A-Za-z_]\\w*)*)(?!\\w|\\*)" % "|".join(PKGS))
IGNORE = {"linux.fault.plan.v1"}  # (a runtime global's name, not a declaration)

def repo_root():
    d = os.getcwd()
    while not os.path.exists(os.path.join(d, "pixi.toml")):
        d = os.path.dirname(d)
    return d

_NAMES = {}

def _names(path):
    # The names a module declares or imports, and every def/var/comptime in
    # it (members).
    if path not in _NAMES:
        text = open(path).read()
        top = set(re.findall(r"^\\s*(?:def|struct|trait|comptime|var)\\s+(\\w+)", text, re.M))
        for group in re.findall(r"^\\s*from\\s+\\S+\\s+import\\s+(\\([^)]*\\)|[^\\n]*)", text, re.M):
            top.update(re.findall(r"\\w+", group))
        members = set(re.findall(r"\\b(?:def|var|comptime)\\s+(\\w+)", text))
        _NAMES[path] = (top, members)
    return _NAMES[path]

def _problem(root, dotted):
    parts = dotted.split(".")
    mod = os.path.join(root, "src", parts[0], parts[1] + ".mojo")
    if not os.path.exists(mod) or dotted in IGNORE:
        return None  # (not a module: a doc file, a sysctl, another language's name)
    top, members = _names(mod)
    if len(parts) > 2 and parts[2] not in top:
        return "no %s in src/%s/%s.mojo" % (parts[2], parts[0], parts[1])
    if len(parts) > 3 and parts[3] not in members:
        return "no %s.%s in src/%s/%s.mojo" % (parts[2], parts[3], parts[0], parts[1])
    return None

def cited_name_problems():
    root = repo_root()
    bad = set()
    checked = 0
    for dirpath, _, files in os.walk(os.path.join(root, "src")):
        for f in files:
            if not f.endswith(".mojo"):
                continue
            p = os.path.join(dirpath, f)
            for m in PAT.finditer(open(p).read()):
                checked += 1
                prob = _problem(root, m.group(1))
                if prob:
                    bad.add("%s: `%s`: %s" % (os.path.relpath(p, root), m.group(1), prob))
    if checked < 50:
        bad.add("only %d cited names found: the pattern matches nothing" % checked)
    return "\\n".join(sorted(bad))
"""


def test_l7_names_cited_in_docs_exist() raises:
    var py = Python.evaluate(_PY_HELPERS, file=True, name="linux_cites")
    var problems = String(py=py.cited_name_problems())
    assert_equal(problems, "", problems)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
