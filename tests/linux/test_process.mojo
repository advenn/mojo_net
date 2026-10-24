"""`linux.process`: children started with clone3 + execve and held by
pidfds (exit codes, signals, a failed execve, readiness in epoll), the
descriptor a child keeps, the CPU and signal mask it starts with (read
from /proc/<pid>/status, so no shell in between can change them), `Exec`
(this program's arguments and environment, edits, NUL bytes), and this
process's threads and whether all of them block a signal."""

from std.python import Python
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import Epoll
from linux.abi import EpollEvent
from linux.consts import AF_UNIX, EPOLLIN, SIGKILL, SIGTERM, SIGUSR2, SOCK_CLOEXEC, SOCK_STREAM
from linux.error import ErrorKind
from linux.fd import OwnedFd
from linux.fs import read_file
from linux.nr import SYS_gettid
from linux.process import (
    Child,
    Exec,
    ExitStatus,
    all_threads_block,
    allowed_cpus,
    reap_others,
    set_allowed_cpus,
    spawn,
    threads,
)
from linux.syscall import syscall0
from linux.signal import SignalSet, block, blocked, set_mask
from linux import sys
from linux.time import Duration, Instant


def _sh(script: String) -> Exec:
    return Exec("/bin/sh", ["sh", "-c", script])


def test_exit_codes_and_signals() raises:
    var three = _sh("exit 3")
    var c = spawn(three)
    assert_true(c.pid > 0)
    assert_equal(c.wait(), ExitStatus(3, 0))
    var ok = _sh("exit 0")
    assert_true(spawn(ok).wait().success())
    var sleeper = Exec("/bin/sleep", ["sleep", "30"])
    var s = spawn(sleeper)
    assert_false(Bool(s.try_wait()))  # still running
    s.signal(SIGTERM)
    assert_equal(s.wait(), ExitStatus(-1, SIGTERM))
    assert_equal(String(ExitStatus(-1, SIGTERM)), "killed by signal 15")
    assert_equal(String(ExitStatus(3, 0)), "exit status 3")


def test_a_failed_execve_exits_127() raises:
    var missing = Exec("/nonexistent/program", ["program"])
    assert_equal(spawn(missing).wait(), ExitStatus(127, 0))


def test_a_childs_pidfd_is_readable_when_it_ends() raises:
    var short = _sh("exit 5")
    var c = spawn(short)
    var ep = Epoll.new()
    ep.add(c, UInt32(EPOLLIN), 9)
    var events = List[EpollEvent](capacity=4)
    assert_equal(ep.wait(events, Optional[Duration](Duration.from_secs(10))), 1)
    assert_equal(events[0].data(), 9)
    assert_equal(c.try_wait().value(), ExitStatus(5, 0))


def _pair() raises -> Tuple[Int32, Int32]:
    var fds = Array[Int32, 2](fill=-1)
    var r = sys.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds)
    assert_equal(r, 0)
    return (fds[0], fds[1])


def test_the_kept_descriptor_and_only_it_survives_execve() raises:
    var p = _pair()
    var mine = OwnedFd(unsafe_from_raw=p[0])
    var theirs = OwnedFd(unsafe_from_raw=p[1])
    var n = String(theirs.raw_fd())
    var write = _sh("echo hello >&" + n)
    assert_true(spawn(write, keep=theirs.raw_fd()).wait().success())
    var buf = List[UInt8](length=64, fill=0)
    var got = sys.read(mine, Span(buf))
    assert_equal(String(from_utf8_lossy=Span(buf)[0:got]), "hello\n")
    # not kept: closed at execve (CLOEXEC), so the shell cannot write to it
    var again = _sh("echo again >&" + n + " 2>/dev/null")
    assert_false(spawn(again).wait().success())
    sys.keep_alive(theirs)


def _status_field(pid: Int, name: StringSlice) raises -> String:
    """A field of /proc/<pid>/status, once the child runs `sleep`."""
    var t = Instant.now()
    while t.elapsed() < Duration.from_secs(10):
        var text = String(from_utf8_lossy=Span(read_file(String("/proc/", pid, "/status"), "status")))
        if text.find("Name:\tsleep") >= 0:
            for line in text.split("\n"):
                if line.startswith(String(name, ":")):
                    return String(line[byte = name.byte_length() + 1 :].strip())
    raise Error("no sleep at pid ", pid)


def test_a_child_starts_on_its_cpu_with_the_callers_signal_mask() raises:
    var cpus = allowed_cpus()
    assert_true(len(cpus) >= 1)
    var last = cpus[len(cpus) - 1]
    var before = blocked()
    _ = block(SignalSet.of(SIGUSR2, SIGTERM))
    var sleeper = Exec("/bin/sleep", ["sleep", "30"])
    var c = spawn(sleeper, cpu=last)
    _ = set_mask(before)
    assert_equal(_status_field(c.pid, "Cpus_allowed_list"), String(last))
    var sigblk = _status_field(c.pid, "SigBlk")
    var low = atol(sigblk[byte = sigblk.byte_length() - 8 :], base=16)
    assert_equal((low >> (SIGUSR2 - 1)) & 1, 1)
    # SIGTERM is blocked there: it waits instead of ending the child
    c.signal(SIGTERM)
    var t = Instant.now()
    while t.elapsed() < Duration.from_millis(200):
        assert_false(Bool(c.try_wait()))
    c.signal(SIGKILL)
    assert_equal(c.wait(), ExitStatus(-1, SIGKILL))


def test_affinity_of_the_calling_thread() raises:
    var cpus = allowed_cpus()
    set_allowed_cpus([cpus[0]])
    assert_equal(len(allowed_cpus()), 1)
    assert_equal(allowed_cpus()[0], cpus[0])
    set_allowed_cpus(cpus)
    assert_equal(len(allowed_cpus()), len(cpus))
    var refused = False
    try:
        set_allowed_cpus([-1])
    except e:
        refused = e.kind == ErrorKind.InvalidInput
    assert_true(refused, "a negative CPU")


def test_exec_of_this_program_and_environment_edits() raises:
    var me = Exec.this_program()
    var cmdline = read_file("/proc/self/cmdline", "test")
    assert_true(len(me.args) >= 1)
    var joined = List[UInt8]()
    for i in range(len(me.args)):
        joined.extend(Span(me.args[i]))
        joined.append(0)
    assert_equal(len(joined), len(cmdline))
    assert_true(Bool(me.get_env("PATH")))
    me.set_env("MOJO_NET_TEST_X", "1")
    me.set_env("MOJO_NET_TEST_X", "2")  # replaces
    assert_equal(me.get_env("MOJO_NET_TEST_X").value(), "2")
    me.remove_env("MOJO_NET_TEST_X")
    assert_false(Bool(me.get_env("MOJO_NET_TEST_X")))
    # the environment reaches the child
    var p = _pair()
    var mine = OwnedFd(unsafe_from_raw=p[0])
    var theirs = OwnedFd(unsafe_from_raw=p[1])
    var env = _sh("echo $MOJO_NET_TEST_Y >&" + String(theirs.raw_fd()))
    env.set_env("MOJO_NET_TEST_Y", "seen")
    assert_true(spawn(env, keep=theirs.raw_fd()).wait().success())
    var buf = List[UInt8](length=64, fill=0)
    var got = sys.read(mine, Span(buf))
    assert_equal(String(from_utf8_lossy=Span(buf)[0:got]), "seen\n")
    sys.keep_alive(theirs)


def test_threads_and_their_masks() raises:
    var tids = threads()
    assert_true(len(tids) >= 2)  # main and the runtime's
    var me = syscall0(SYS_gettid)
    var found = False
    for i in range(len(tids)):
        found = found or tids[i] == me
    assert_true(found)
    # Blocked in this thread only: the runtime's threads, started before
    # main, do not block it.
    var before = blocked()
    _ = block(SignalSet.of(SIGUSR2))
    assert_false(all_threads_block(SignalSet.of(SIGUSR2)))
    _ = set_mask(before)
    assert_true(all_threads_block(SignalSet.empty()))


def test_a_child_can_start_with_another_signal_mask() raises:
    var before = blocked()
    _ = block(SignalSet.of(SIGUSR2, SIGTERM))
    var sleeper = Exec("/bin/sleep", ["sleep", "30"])
    var c = spawn(sleeper, signal_mask=SignalSet.of(SIGTERM))  # USR2 not
    _ = set_mask(before)
    var sigblk = _status_field(c.pid, "SigBlk")
    var low = atol(sigblk[byte = sigblk.byte_length() - 8 :], base=16)
    assert_equal((low >> (SIGUSR2 - 1)) & 1, 0)
    assert_equal((low >> (SIGTERM - 1)) & 1, 1)
    c.signal(SIGKILL)
    assert_equal(c.wait(), ExitStatus(-1, SIGKILL))


def _until_ended(pid: Int) raises:
    """Wait until child `pid` has ended, without reaping it (at most 30 s:
    a loaded machine can take far longer than a fixed pause)."""
    var os = Python.import_module("os")
    var time = Python.import_module("time")
    var t = Instant.now()
    while String(os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)) == "None":
        if t.elapsed() > Duration.from_secs(30):
            raise Error("child ", pid, " did not end")
        _ = time.sleep(0.002)


def test_reap_others_leaves_the_known_children() raises:
    var six = _sh("exit 6")
    var mine = spawn(six)
    _until_ended(mine.pid)
    # A child this test does not know about: started by Python, ended, a
    # zombie until someone waits for it. `other` must stay alive until the
    # end: destroying a Popen runs its __del__, which reaps the child if it
    # has ended, and Mojo destroys a value right after its last use.
    var subprocess = Python.import_module("subprocess")
    var other = subprocess.Popen(Python.list("/bin/sh", "-c", "exit 0"))
    var other_pid = Int(py=other.pid)
    _until_ended(other_pid)
    var known = List[Int]()
    known.append(mine.pid)
    # It stops at the first known child it meets, which may be ours: then
    # reap ours (once) and the other comes up.
    var ours_reaped = False
    var reaped = reap_others(known)
    if reaped == 0:
        assert_equal(mine.wait(), ExitStatus(6, 0))
        ours_reaped = True
        reaped = reap_others(known)
    assert_equal(reaped, 1)
    var gone = False
    try:
        _ = Python.import_module("os").kill(other_pid, 0)
    except:
        gone = True  # (reaped: no such process)
    assert_true(gone)
    if not ours_reaped:
        assert_equal(mine.wait(), ExitStatus(6, 0))
    _ = other.pid  # (the last use of `other`: see above)


def test_a_nul_in_an_argument_is_refused() raises:
    var bad = _sh("exit 0")
    bad.args[1].append(0)
    var refused = False
    try:
        _ = spawn(bad)
    except e:
        refused = e.kind == ErrorKind.InvalidInput
    assert_true(refused, "spawned with a NUL in an argument")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
