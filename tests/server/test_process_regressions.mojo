"""Regression tests for the S5 review of processes and signals, each
checked to fail on the code before its fix:
- a worker that saw its lifeline close took its own SIGTERM, which
  systemd sends next, as a second request and cut its requests;
- bytes on the lifeline stopped a worker (with fds 0-2 closed, the
  supervisor's log went into worker 0's lifeline);
- a broken stderr pipe killed the supervisor (SIGPIPE) and so every
  worker;
- `restart_delay=0` never backed off, and the first quick end waited
  twice `restart_delay`;
- workers kept MOJO_NET_WORKER in the environment their children get;
- the re-exec for the signal mask had no bound.
The supervisor ones run `tests/server/workers_app.mojo`, built."""

from std.python import Python
from std.testing import TestSuite, assert_equal, assert_true

from linux import sys
from linux.consts import AF_UNIX, SIGINT, SIGTERM, SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_STREAM
from linux.fd import OwnedFd
from linux.nr import SYS_getpid, SYS_gettid, SYS_tgkill
from linux.signal import SignalFd, SignalSet, block, blocked, set_mask
from linux.syscall import syscall0, syscall3
from server import Stop

comptime _DRIVER = """
import glob, os, shutil, signal, socket, subprocess, sys, time
mode = sys.argv[1]
out = []
seen_pids = set(); groups = set()

def cleanup():
    for g in groups:
        try:
            os.killpg(g, signal.SIGKILL)
        except ProcessLookupError:
            pass
    for pid in seen_pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
import atexit
atexit.register(cleanup)

def build():
    owner = os.getppid()
    for d in glob.glob("/tmp/mojo_net_procreg_*"):
        try:
            os.kill(int(d.rsplit("_", 1)[1]), 0)
        except (ProcessLookupError, ValueError):
            shutil.rmtree(d, ignore_errors=True)
        except PermissionError:
            pass
    d = f"/tmp/mojo_net_procreg_{owner}"
    exe = os.path.join(d, "workers_app")
    if not os.path.exists(exe):
        os.makedirs(d, exist_ok=True)
        tmp = exe + f".{os.getpid()}"
        r = subprocess.run([shutil.which("mojo"), "build", "-I", "src", "tests/server/workers_app.mojo", "-o", tmp],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("build failed: " + r.stdout + r.stderr, flush=True); sys.exit(1)
        os.replace(tmp, exe)
    return exe

s0 = socket.socket(); s0.bind(("127.0.0.1", 0)); port = s0.getsockname()[1]; s0.close()

def launch(preexec=None, stderr=subprocess.PIPE, **env):
    e = dict(os.environ, **env)
    p = subprocess.Popen([build(), f"127.0.0.1:{port}"], env=e, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=stderr, text=True, start_new_session=True, preexec_fn=preexec)
    seen_pids.add(p.pid); groups.add(p.pid)
    return p

def get(path):
    c = socket.create_connection(("127.0.0.1", port), timeout=5)
    c.sendall(b"GET " + path + b" HTTP/1.1\\r\\nHost: x\\r\\nConnection: close\\r\\n\\r\\n")
    d = b""
    while True:
        x = c.recv(4096)
        if not x:
            break
        d += x
    c.close()
    return d.split(b"\\r\\n\\r\\n", 1)[1].decode()

def up(within=30):
    t = time.time()
    while time.time() - t < within:
        try:
            get(b"/pid"); return True
        except OSError:
            time.sleep(0.05)
    return False

def workers(n, within=10):
    seen = {}
    t = time.time()
    while len(seen) < n and time.time() - t < within:
        try:
            w, pid = get(b"/pid").split()
            seen[int(w)] = int(pid); seen_pids.add(int(pid))
        except OSError:
            pass
    return seen

def wait(p, within):
    try:
        return p.wait(timeout=within)
    except subprocess.TimeoutExpired:
        return "timeout"

if mode == "sigpipe":
    r, w = os.pipe()
    p = launch(stderr=w, WORKERS="2")
    os.close(w)
    up(); pids = workers(2)
    os.close(r)  # the log reader is gone: the next log line hits a broken pipe
    os.kill(pids[0], signal.SIGKILL)
    t = time.time(); again = None
    while time.time() - t < 10 and again is None:
        try:
            ww, pid = get(b"/pid").split()
            seen_pids.add(int(pid))
            if int(ww) == 0 and int(pid) != pids[0]:
                again = int(pid)
        except OSError:
            pass
    out.append(f"restarted={again is not None} alive={p.poll() is None}")
    os.kill(p.pid, signal.SIGTERM)
    out.append(f"exit {wait(p, 30)}")
elif mode == "no-stdio":
    def close_stdio():
        for fd in (0, 1, 2):
            os.close(fd)
    p = launch(preexec=close_stdio, stderr=None, WORKERS="2")
    up()
    stdio = [os.readlink(f"/proc/{p.pid}/fd/{fd}") for fd in (0, 1, 2)]
    out.append(f"stdio={stdio == ['/dev/null'] * 3}")
    first = workers(2)
    time.sleep(2.0)
    later = workers(2)
    out.append(f"{len(first)} workers stable={first == later}")
    os.kill(p.pid, signal.SIGTERM)
    out.append(f"exit {wait(p, 30)}")
elif mode == "backoff":
    for delay in ["0", ""]:
        env = dict(WORKERS="1", CRASH="1")
        if delay:
            env["RESTART_DELAY_MS"] = delay
        p = launch(**env)
        time.sleep(2.0)
        os.kill(p.pid, signal.SIGTERM)
        code = wait(p, 30)
        err = p.stderr.read() if code != "timeout" else ""
        delays = [int(l.split("restarting in ")[1].split(" ")[0]) for l in err.splitlines() if "restarting in" in l]
        out.append(f"exit {code} starts<20={err.count(' started ') < 20} first={delays[0] if delays else None} growing={delays[1:] == sorted(delays[1:]) and len(set(delays)) > 2}")
elif mode == "worker-env":
    p = launch(WORKERS="1")
    up()
    out.append(get(b"/env"))
    os.kill(p.pid, signal.SIGTERM)
    out.append(f"exit {wait(p, 30)}")
elif mode == "reexec-once":
    p = launch(WORKERS="0", MOJO_NET_REEXEC="1")
    served = up()
    os.kill(p.pid, signal.SIGKILL); p.wait()
    err = p.stderr.read()
    out.append(f"served={served} warned={'even after running again' in err}")
print("|".join(out), flush=True)
"""


def _drive(mode: StaticString) raises -> String:
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    var r = subprocess.run(
        Python.list(pysys.executable, "-c", _DRIVER, mode), capture_output=True, text=True, timeout=300
    )
    return String(String(py=r.stdout).strip()) + String(String(py=r.stderr).strip())


def _tgkill(sig: Int):
    """`sig` to this thread only: blocked here, it waits for the signalfd."""
    _ = syscall3(SYS_tgkill, syscall0(SYS_getpid), syscall0(SYS_gettid), sig)


def test_a_signal_after_the_lifeline_is_still_graceful() raises:
    var before = blocked()
    _ = block(SignalSet.of(SIGTERM, SIGINT))
    var fds = Array[Int32, 2](fill=-1)
    assert_equal(sys.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, fds), 0)
    var supervisor = OwnedFd(unsafe_from_raw=fds[0])
    var stop = Stop(SignalFd.new(SignalSet.of(SIGTERM, SIGINT)), OwnedFd(unsafe_from_raw=fds[1]), 0)
    assert_equal(stop.requested(), Stop.NONE)
    _ = sys.write(supervisor, "log line\n".as_bytes())  # bytes on it mean nothing
    assert_equal(stop.requested(), Stop.NONE)
    _ = supervisor^  # the supervisor closes it: graceful
    assert_equal(stop.requested(), Stop.GRACEFUL)
    _tgkill(SIGTERM)  # then the worker's own SIGTERM (systemd's order): still graceful
    assert_equal(stop.requested(), Stop.GRACEFUL)
    _tgkill(SIGINT)  # a signal after a signal: now
    assert_equal(stop.requested(), Stop.NOW)
    _ = set_mask(before)


def test_the_supervisor_survives_a_broken_stderr() raises:
    assert_equal(_drive("sigpipe"), "restarted=True alive=True|exit 0")


def test_workers_started_without_stdio_are_stable() raises:
    assert_equal(_drive("no-stdio"), "stdio=True|2 workers stable=True|exit 0")


def test_restart_backoff() raises:
    # restart_delay=0: 0 ms, then from 50 ms doubling; the default: 100 ms first
    assert_equal(
        _drive("backoff"),
        "exit 0 starts<20=True first=0 growing=True|exit 0 starts<20=True first=100 growing=True",
    )


def test_workers_do_not_pass_their_worker_variable_on() raises:
    assert_equal(_drive("worker-env"), "[]|exit 0")


def test_the_reexec_happens_once() raises:
    assert_equal(_drive("reexec-once"), "served=True warned=True")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
