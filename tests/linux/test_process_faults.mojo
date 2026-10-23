# Fault tests for `linux.process`. Needs `-D MOJO_NET_FAULTS=1`, which
# tools/run_tests.sh passes for this file name. Each test starts with
# `fault.clear()`.
#
# Docker's default seccomp profile refuses clone3 with ENOSYS (EPERM in
# some others): `spawn` must fall back to clone(2) with CLONE_PIDFD, and
# report anything else as it is (S5 review).

from std.testing import TestSuite, assert_equal, assert_true

from linux import Errno, fault
from linux.nr import SYS_clone, SYS_clone3
from linux.process import Exec, ExitStatus, spawn


def _sh(script: String) -> Exec:
    return Exec("/bin/sh", ["sh", "-c", script])


def test_spawn_falls_back_to_clone_where_clone3_is_refused() raises:
    for e in [Errno.ENOSYS, Errno.EPERM]:
        fault.clear()
        fault.inject(SYS_clone3, e, times=-1)
        var p = _sh("exit 4")
        var c = spawn(p)
        assert_equal(c.wait(), ExitStatus(4, 0))  # (and its pidfd works)
        assert_equal(fault.calls(SYS_clone3), 1)
        assert_equal(fault.calls(SYS_clone), 1)
    fault.clear()


def test_other_clone3_errors_are_raised_as_they_are() raises:
    fault.clear()
    fault.inject(SYS_clone3, Errno.EAGAIN)
    var kind_ok = False
    try:
        var p = _sh("exit 0")
        _ = spawn(p)
    except e:
        kind_ok = e.errno == Errno.EAGAIN
    assert_true(kind_ok, "EAGAIN (a process limit) is no reason to fall back")
    assert_equal(fault.calls(SYS_clone), 0)
    fault.clear()


def test_spawn_raises_when_clone_is_refused_too() raises:
    fault.clear()
    fault.inject(SYS_clone3, Errno.ENOSYS, times=-1)
    fault.inject(SYS_clone, Errno.EPERM, times=-1)
    var got = String()
    try:
        var p = _sh("exit 0")
        _ = spawn(p)
    except e:
        got = String(e.op, " ", e.errno)
    assert_equal(got, "clone EPERM(1)")
    fault.clear()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
