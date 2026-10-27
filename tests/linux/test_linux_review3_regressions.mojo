"""Regression tests for the third review of `net` and the layer under it
(2026-10-27; docs/net.md, "Third review"):

SYS-1: `open_beneath` and `read_file` opened without O_NOCTTY. A session
leader with no controlling terminal (a container's PID 1, anything run
under setsid) that opens a terminal device takes it as its controlling
terminal; a hangup on that line then sends it SIGHUP. `server.static`
opens files with `open_beneath` before it checks their type. The test
builds `tests/linux/noctty_app.mojo`, runs it under `setsid` on a fresh
pseudo-terminal, and reads its tty_nr."""

from std.python import Python
from std.testing import TestSuite, assert_equal, assert_true

comptime _DRIVER = """
import os, shutil, subprocess, sys, tempfile
d = tempfile.mkdtemp(prefix="mojo_net_noctty_")
try:
    exe = os.path.join(d, "noctty_app")
    src = os.environ.get("MOJO_NET_TEST_SRC", "src")
    r = subprocess.run([shutil.which("mojo"), "build", "-I", src, "tests/linux/noctty_app.mojo", "-o", exe],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("build failed: " + r.stdout + r.stderr); sys.exit(1)
    master, slave = os.openpty()
    name = os.ttyname(slave)
    os.close(slave)
    out = []
    for mode in ("beneath", "read"):
        os.write(master, b"abcd\\n")  # (a line to read: read_file then stops at its 1-byte limit)
        r = subprocess.run(["setsid", "-w", exe, os.path.dirname(name), os.path.basename(name), mode],
                           capture_output=True, text=True, timeout=60)
        out.append(mode + "=" + (r.stdout.strip().split("TTY ")[-1] if "TTY " in r.stdout else "?" + r.stdout + r.stderr))
    os.close(master)
    print(" ".join(out))
finally:
    shutil.rmtree(d, ignore_errors=True)
"""


def test_sys1_a_session_leader_opening_a_terminal_does_not_take_it() raises:
    var subprocess = Python.import_module("subprocess")
    var shutil = Python.import_module("shutil")
    if not shutil.which("setsid"):
        print("skip: no setsid")
        return
    var pysys = Python.import_module("sys")
    var r = subprocess.run(
        Python.list(pysys.executable, "-c", _DRIVER), capture_output=True, text=True, timeout=300
    )
    var out = String(String(py=r.stdout).strip()) + String(String(py=r.stderr).strip())
    assert_equal(out, "beneath=0 read=0", out)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
