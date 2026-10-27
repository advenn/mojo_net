"""Regression test for the third review (2026-10-27; docs/net.md, "Third
review"), built with -D MOJO_NET_FAULTS=1. Each test starts with
`fault.clear()`.

SYS-3: between clone and execve the child issued its syscalls through
`syscallN`, which in a fault build first goes through the fault plan (the
Mojo runtime's global lookup, whose lock a thread missing from the child
may hold) and applies the parent's rules in the child: a rule meant for
the parent's own `execve` failed the child's instead, and the program
never ran."""

from std.testing import TestSuite, assert_equal

from linux import Errno, fault
from linux.nr import SYS_execve
from linux.process import Exec, ExitStatus, spawn


def test_sys3_the_child_skips_the_fault_seam() raises:
    fault.clear()
    fault.inject(SYS_execve, Errno.EACCES)
    var p = Exec("/bin/sh", ["sh", "-c", "exit 3"])
    var c = spawn(p)
    assert_equal(c.wait(), ExitStatus(3, 0))  # (127 when the rule fired in the child)
    assert_equal(fault.pending(), 1)  # (the parent never called execve)
    fault.clear()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
