# Regression test for the second net review that counts syscalls through the
# fault seam (-D MOJO_NET_FAULTS=1; tools/run_tests.sh passes it for
# *_faults.mojo). The plan is process-global: each test starts with
# `fault.clear()`.
#
# - D2: `Lookup.advance` read every queued datagram before checking its
#   tries' deadlines, so a steady stream of strays (wrong IDs, from the
#   server's own address) kept it reading past the deadline. One call now
#   reads at most 64 datagrams a query before the expiry check runs.

from std.testing import TestSuite, assert_true
from std.time import sleep

from linux import fault
from linux.nr import SYS_recvfrom
from linux.time import Deadline, Duration
from fake_dns import FakeDns


def test_d2_one_advance_reads_a_bounded_number_of_strays() raises:
    fault.clear()
    var dns = FakeDns()
    var r = dns.resolver()
    var deadline = Deadline.after(Duration.from_secs(5))
    var lk = r.start("junk.test", deadline, want_v6=False)
    sleep(0.5)  # (200 strays with the wrong ID are queued by now)
    var before = fault.calls(SYS_recvfrom)
    lk.advance(deadline)
    var reads = fault.calls(SYS_recvfrom) - before
    fault.clear()
    assert_true(reads >= 64 and reads <= 65, String(reads, " reads in one advance"))
    dns^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
