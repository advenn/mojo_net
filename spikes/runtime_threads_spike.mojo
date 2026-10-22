"""Spike 2: how many OS threads does an idle Mojo 1.2 process have?

Counts `/proc/self/task` (raw openat/getdents64, see spike_util) at several
points of a program's life and names each thread (`comm`). The first count
is the very first statement of `main` and allocates nothing.

Run it as a built binary; `mojo run` JIT-executes inside the compiler
process, whose own threads would be counted too:

    pixi run mojo build -I src -I spikes spikes/runtime_threads_spike.mojo -o spikes/out/runtime_threads
    spikes/out/runtime_threads                  # all CPUs
    taskset -c 0 spikes/out/runtime_threads     # pool sized from affinity?
    SPIKE_PYTHON=1 spikes/out/runtime_threads   # also stage: Python interop
"""

from std.ffi import external_call
from std.python import Python
from std.os import getenv
from std.testing import TestSuite, assert_equal, assert_true

from linux import IoError
from linux.nr import SYS_rt_sigaction
from linux.syscall import syscall4
from linux.time import Duration, sleep

from spike_util import (
    count_tasks,
    cpu_ticks,
    list_tasks,
    status_field,
    thread_comm,
)


def _comm_or_gone(tid: Int) -> String:
    """A listed thread can exit before its comm is read (a just-joined
    pthread lingers in /proc/self/task briefly), so tolerate ENOENT."""
    try:
        return thread_comm(tid)
    except:
        return String("<gone>")


def _report(stage: StaticString) raises:
    var tids = list_tasks()
    var line = String(stage) + ": tasks=" + String(len(tids)) + " ["
    for i in range(len(tids)):
        if i > 0:
            line += ", "
        line += _comm_or_gone(tids[i])
    line += "] VmRSS=" + status_field("/proc/self/status", "VmRSS:")
    line += " VmSize=" + status_field("/proc/self/status", "VmSize:")
    print(line)


def _affinities() raises:
    """Per-thread CPU affinity: are runtime workers pinned?"""
    for t in list_tasks():
        var p = "/proc/self/task/" + String(t) + "/status"
        var cpus: String
        try:
            cpus = status_field(p, "Cpus_allowed_list:")
        except:
            cpus = String("<gone>")
        print("  tid", t, _comm_or_gone(t), "Cpus_allowed_list:", cpus)


def _signals(mask_hex: String) raises -> String:
    """Decode a /proc SigCgt-style hex mask into signal numbers."""
    var v: UInt64 = 0
    for b in mask_hex.as_bytes():
        var d = Int(b)
        var n = d - ord("0") if d <= ord("9") else (d | 0x20) - ord("a") + 10
        v = (v << 4) | UInt64(n)
    var out = String()
    for sig in range(1, 65):
        if (v >> UInt64(sig - 1)) & 1 == 1:
            out += String(sig) + " "
    return out


def _sigaction_flags(sig: Int) -> Tuple[Int, UInt64]:
    """(handler word, sa_flags) via raw rt_sigaction(sig, NULL, &old, 8).
    Kernel struct: handler, flags, restorer, mask - same on both arches."""
    var old = Array[UInt64, 4](fill=0)
    var r = syscall4(SYS_rt_sigaction, sig, 0, Int(Pointer(to=old)), 8)
    if r != 0:
        return (r, UInt64(0))
    return (Int(old[0]), old[1])


def _dispositions() raises:
    comptime SA_SIGINFO: UInt64 = 0x4
    comptime SA_ONSTACK: UInt64 = 0x08000000
    comptime SA_RESTART: UInt64 = 0x10000000
    comptime SA_NODEFER: UInt64 = 0x40000000
    comptime SA_RESETHAND: UInt64 = 0x80000000
    for sig in range(1, 65):
        if sig == 9 or sig == 19:
            continue  # SIGKILL/SIGSTOP cannot be queried meaningfully
        var hf = _sigaction_flags(sig)
        if hf[0] == 0 or hf[0] == 1:
            continue  # SIG_DFL / SIG_IGN
        var f = hf[1]
        var desc = String()
        if f & SA_SIGINFO:
            desc += "SA_SIGINFO "
        if f & SA_ONSTACK:
            desc += "SA_ONSTACK "
        if f & SA_RESTART:
            desc += "SA_RESTART "
        if f & SA_NODEFER:
            desc += "SA_NODEFER "
        if f & SA_RESETHAND:
            desc += "SA_RESETHAND "
        print("    sig", sig, "handler installed, flags:", desc)


def test_spike_dummy() raises:
    assert_equal(1 + 1, 2)
    assert_true(True)


def _null_entry(arg: Int) abi("C") -> Int:
    return arg


def main() raises:
    var at_start = count_tasks()  # before anything else touches the runtime
    print(
        "stage 0 (first statement of main, nothing allocated): tasks=", at_start
    )
    _report("stage 1 after print")
    _affinities()
    # The runtime's startup installs crash handlers (stack trace on fault).
    print(
        "  signals with handlers (SigCgt):",
        _signals(status_field("/proc/self/status", "SigCgt:")),
        "| blocked (SigBlk):",
        _signals(status_field("/proc/self/status", "SigBlk:")),
        "| ignored (SigIgn):",
        _signals(status_field("/proc/self/status", "SigIgn:")),
    )
    _dispositions()

    var l = List[Int]()
    for i in range(100_000):
        l.append(i)
    var d = Dict[String, Int]()
    for i in range(1000):
        d[String(i)] = i
    _report("stage 2 after List(100k)/Dict(1k)")

    try:
        raise Error("boom")
    except e:
        _ = String(e)
    _report("stage 3 after raise/catch Error + String")

    TestSuite.discover_tests[__functions_in_module()]().run()
    _report("stage 4 after std.testing + TestSuite.run")

    var t0 = cpu_ticks()
    sleep(Duration.from_millis(1000))
    var t1 = cpu_ticks()
    _report("stage 5 after 1 s idle sleep")
    print("  idle CPU ticks (utime+stime, whole process) over 1 s:", t1 - t0)

    # A pthread we create shows up and goes away again (sanity for the counter).
    var tid: UInt64 = 0
    var rc = external_call["pthread_create", Int32](
        Int(Pointer(to=tid)), 0, _null_entry, 0
    )
    var rj = external_call["pthread_join", Int32](tid, 0)
    print("  pthread create/join rc:", rc, rj)
    print("  tasks right after pthread_join returned:", count_tasks())
    # pthread_join returns when the kernel clears the tid futex, which is
    # before the task is reaped from /proc; poll until it is gone.
    var waited = 0
    while count_tasks() > at_start and waited < 1000:
        sleep(Duration.from_millis(1))
        waited += 1
    print(
        "  joined thread left /proc/self/task after ~", waited, "ms of polling"
    )
    _report("stage 6 after one pthread_create+join")

    # Not argv: TestSuite.run() parses argv and raises on anything but
    # --only/--skip ("invalid argument: python (expected '--only' or '--skip')").
    if getenv("SPIKE_PYTHON") == "1":
        var os = Python.import_module("os")
        _ = os.getpid()
        _report("stage 7 after Python.import_module(os)")
        sleep(Duration.from_millis(200))
        _report("stage 8 Python + 200 ms")

    print("sum", len(l), len(d))
