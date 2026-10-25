# Regression tests for the second linux review that need the fault seam
# (-D MOJO_NET_FAULTS=1; tools/run_tests.sh passes it for *_faults.mojo).
# Each test starts with `fault.clear()`: the plan is process-global.
#
# - L1: `open_beneath` retries EAGAIN (openat2 answers it with
#   RESOLVE_BENEATH when a ".." lookup races a rename anywhere on the host),
#   a bounded number of times: a write lease's EAGAIN still ends.
# - L3: `all_threads_block` skips a thread that ended between the open and
#   the read of its status (ESRCH), as it skips one already gone.
# - L5: `stat_fd` retries EINTR, as the other `linux.fs` calls do.
# - L6: `allowed_cpus` grows its mask while the kernel answers EINVAL (more
#   CPUs than the mask holds), as `probe.cpu_count` does.

from std.os import makedirs, remove, rmdir
from std.testing import TestSuite, assert_equal, assert_true

from linux import Errno, ErrorKind, IoError, fault
from linux.fs import open_beneath, open_dir, pread, stat_fd
from linux.nr import SYS_openat2, SYS_read, SYS_sched_getaffinity, SYS_statx
from linux.process import all_threads_block, allowed_cpus, threads
from linux.signal import SignalSet, blocked
from linux.syscall import syscall0
from linux.nr import SYS_getpid


def _scratch() raises -> String:
    """A scratch directory with one file in it, `hello.txt`."""
    var dir = String("build/test_l1_", syscall0(SYS_getpid))
    makedirs(dir, exist_ok=True)
    with open(dir + "/hello.txt", "w") as f:
        f.write("hello")
    return dir


def _cleanup(dir: String) raises:
    remove(dir + "/hello.txt")
    rmdir(dir)


def test_l1_open_beneath_retries_eagain() raises:
    fault.clear()
    var dir = _scratch()
    var root = open_dir(dir)
    fault.inject(SYS_openat2, Errno.EAGAIN, times=3)
    var f = open_beneath(root, "hello.txt")
    assert_equal(fault.calls(SYS_openat2), 4)
    var buf = List[UInt8](length=8, fill=0)
    assert_equal(pread(f, Span(buf), 0), 5)
    fault.clear()
    _cleanup(dir)


def test_l1_open_beneath_gives_up_on_lasting_eagain() raises:
    fault.clear()
    var dir = _scratch()
    var root = open_dir(dir)
    fault.inject(SYS_openat2, Errno.EAGAIN, times=-1)  # (a write lease)
    var before = fault.calls(SYS_openat2)
    var raised = False
    try:
        _ = open_beneath(root, "hello.txt")
    except e:
        raised = e.kind == ErrorKind.WouldBlock
    var tries = fault.calls(SYS_openat2) - before
    assert_equal(tries, 32)
    fault.clear()
    _cleanup(dir)
    assert_true(raised)


def test_l3_all_threads_block_skips_a_thread_that_just_ended() raises:
    fault.clear()
    var set = SignalSet.of(15)
    var expected = all_threads_block(set)
    # The first status read fails as for a thread that ended after its open.
    fault.inject(SYS_read, Errno.ESRCH, times=1)
    assert_equal(all_threads_block(set), expected)
    assert_true(fault.calls(SYS_read) >= 2)
    fault.clear()


def test_l5_stat_fd_retries_eintr() raises:
    fault.clear()
    var dir = _scratch()
    var root = open_dir(dir)
    var f = open_beneath(root, "hello.txt")
    var before = fault.calls(SYS_statx)  # (open_dir's)
    fault.inject(SYS_statx, Errno.EINTR, times=2)
    var st = stat_fd(f)
    assert_equal(Int(st.size), 5)
    assert_equal(fault.calls(SYS_statx) - before, 3)
    fault.clear()
    _cleanup(dir)


def test_l6_allowed_cpus_grows_its_mask_on_einval() raises:
    fault.clear()
    var mine = allowed_cpus()
    var before = fault.calls(SYS_sched_getaffinity)
    fault.inject(SYS_sched_getaffinity, Errno.EINVAL, times=2)
    var again = allowed_cpus()
    assert_equal(fault.calls(SYS_sched_getaffinity) - before, 3)
    assert_equal(len(again), len(mine))
    for i in range(len(mine)):
        assert_equal(again[i], mine[i])
    fault.clear()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
