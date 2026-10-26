"""`server.run_workers` and `Stop`, on a built program
(`tests/server/workers_app.mojo`; a re-executed `mojo run` would compile
it again for every process). A Python script drives it: the supervisor
starts the workers (one runtime thread each, their affinity widened unless
pinned), restarts one that is killed, and on SIGTERM lets a request in
progress finish, then exits 0 once they have; a second signal stops at
once, and workers that do not stop are killed at `stop_timeout`; workers
whose supervisor dies stop on their own; workers that keep crashing are
restarted later and later; a supervisor that inherited SIGCHLD ignored
(its children reaped by the kernel) still restarts them; a worker started
without the supervisor's mask runs itself again and stops on SIGTERM. A single process with
`Stop.on_signals` stops gracefully on SIGINT, and at once on a second."""

from std.python import Python
from std.testing import TestSuite, assert_equal, assert_true

comptime _DRIVER = """
import glob, hashlib, os, shutil, signal, socket, ssl, subprocess, sys, tempfile, time
mode = sys.argv[1]
out = []
TLS = None  # (an ssl context: the routes are fetched over HTTPS)

def build():
    # One binary per test process (its pid in the path), built once.
    owner = os.getppid()
    for d in glob.glob("/tmp/mojo_net_workers_*"):
        try:
            os.kill(int(d.rsplit("_", 1)[1]), 0)
        except (ProcessLookupError, ValueError):
            shutil.rmtree(d, ignore_errors=True)  # its test process is gone
        except PermissionError:
            pass
    d = f"/tmp/mojo_net_workers_{owner}"
    exe = os.path.join(d, "workers_app")
    if not os.path.exists(exe):
        os.makedirs(d, exist_ok=True)
        tmp = exe + f".{os.getpid()}"
        src = os.environ.get("MOJO_NET_TEST_SRC", "src")  # (a planted copy, to check a test catches it)
        r = subprocess.run([shutil.which("mojo"), "build", "-I", src, "tests/server/workers_app.mojo", "-o", tmp],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("build failed: " + r.stdout + r.stderr, flush=True)
            sys.exit(1)
        os.replace(tmp, exe)
    return exe

seen_pids = set()
groups = set()

def cleanup():
    # Whatever a failure left running: never leave processes behind. Each
    # supervisor leads its own process group, which its workers share.
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

def stderr_of(p):
    cleanup()  # first: workers share the pipe, so reading waits for them all
    return p.stderr.read()

import atexit
atexit.register(cleanup)

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p

port = free_port()
def start(preexec=None, pass_fds=(), **env):
    e = dict(os.environ, **env)
    p = subprocess.Popen([build(), f"127.0.0.1:{port}"], env=e, stderr=subprocess.PIPE, text=True,
                         start_new_session=True, preexec_fn=preexec, pass_fds=pass_fds)
    seen_pids.add(p.pid); groups.add(p.pid)
    t = time.time()
    while time.time() - t < 30:
        try:
            get(b"/pid"); return p
        except OSError:
            time.sleep(0.05)
    p.kill(); print("never up: " + stderr_of(p), flush=True); sys.exit(1)

def get(path):
    c = socket.create_connection(("127.0.0.1", port), timeout=5)
    host = b"x"
    if TLS:
        c = TLS.wrap_socket(c, server_hostname="localhost")
        host = b"localhost"  # (another host than the SNI gets 421)
    c.sendall(b"GET " + path + b" HTTP/1.1\\r\\nHost: " + host + b"\\r\\nConnection: close\\r\\n\\r\\n")
    d = b""
    while True:
        x = c.recv(4096)
        if not x:
            break
        d += x
    c.close()
    return d.split(b"\\r\\n\\r\\n", 1)[1].decode()

def workers(n):
    seen = {}
    t = time.time()
    while len(seen) < n and time.time() - t < 10:
        try:
            w, pid = get(b"/pid").split()
            seen[int(w)] = int(pid)
            seen_pids.add(int(pid))
        except OSError:
            pass
    return seen

def threads_of(pid):
    return len(os.listdir(f"/proc/{pid}/task"))

def alive(pid):
    try:
        os.kill(pid, 0); return True
    except ProcessLookupError:
        return False

def gone(pids, within):
    t = time.time()
    while time.time() - t < within:
        if not any(alive(p) for p in pids):
            return True
        time.sleep(0.05)
    return False

def upload_started():
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(b"POST /upload HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 10\\r\\n\\r\\nabc")
    time.sleep(0.3)
    return s

def finish(s):
    try:
        s.sendall(b"defghij")
    except OSError:
        return "send failed"
    d = b""
    while True:
        try:
            x = s.recv(4096)
        except OSError:
            return "reset"
        if not x:
            break
        d += x
    if not d:
        return "closed"
    return f"{d.split(b'\\r\\n')[0].decode()} close={b'Connection: close' in d} {d.split(b'\\r\\n\\r\\n')[-1].decode()}"

def wait(p, within):
    try:
        return p.wait(timeout=within)
    except subprocess.TimeoutExpired:
        p.kill(); p.wait(); return "timeout"

def cpus():
    return os.sched_getaffinity(0)

def cpu_list(text):
    # /proc's list format: "0-3,5"
    got = set()
    for part in text.split(","):
        a, _, b = part.partition("-")
        got.update(range(int(a), int(b or a) + 1))
    return got

if mode == "tls":
    d = tempfile.mkdtemp(prefix="mojo_net_tls_workers_")  # (not mojo_net_workers_*: build() sweeps those)
    subprocess.run([sys.executable, "tests/tls/tls_pki.py", d], check=True, capture_output=True)
    TLS = ssl.create_default_context(cafile=d + "/root.pem")
    p = start(WORKERS="2", TLS_DIR=d, SSLKEYLOGFILE=d + "/keys.log")
    out.append(f"{len(workers(2))} workers over TLS")
    out.append(get(b"/keylog"))
    p.send_signal(signal.SIGTERM)
    out.append(f"supervisor exit {wait(p, 30)}")
    out.append(f"key log written={os.path.exists(d + '/keys.log')}")
    shutil.rmtree(d, ignore_errors=True)
elif mode == "supervise":
    p = start(WORKERS="3")
    pids = workers(3)
    out.append(f"{len(pids)} workers")
    # one runtime thread each (started on one CPU), then all CPUs again
    t = [get(b"/threads").split(" ", 1) for _ in range(6)]
    out.append(f"threads={sorted(set(x[0] for x in t))}")
    out.append(f"widened={all(cpu_list(x[1]) == cpus() for x in t) and len(cpus()) > 1}")
    victim = pids[1]
    os.kill(victim, signal.SIGKILL)
    t0 = time.time(); again = None
    while time.time() - t0 < 10 and again is None:
        try:
            w, pid = get(b"/pid").split()
            seen_pids.add(int(pid))
            if int(w) == 1 and int(pid) != victim:
                again = int(pid)
        except OSError:
            pass
    out.append(f"restarted={again is not None}")
    up = upload_started()
    os.kill(p.pid, signal.SIGTERM)
    time.sleep(0.3)
    out.append(f"while stopping: supervisor alive={p.poll() is None}")
    out.append(finish(up))
    out.append(f"supervisor exit {wait(p, 30)}")
    out.append(f"workers gone={gone(list(pids.values()) + [again], 5)}")
    err = stderr_of(p)
    out.append(f"logged={'restarting in' in err and 'all workers ended' in err}")
elif mode == "pinned":
    p = start(WORKERS="2", PIN="1")
    t = [get(b"/threads").split(" ", 1) for _ in range(6)]
    out.append(f"threads={sorted(set(x[0] for x in t))} one cpu each={all(x[1].isdigit() for x in t)}")
    os.kill(p.pid, signal.SIGTERM)
    out.append(f"supervisor exit {wait(p, 30)}")
elif mode == "twice":
    p = start(WORKERS="2")
    pids = workers(2)
    up = upload_started()
    os.kill(p.pid, signal.SIGTERM)
    time.sleep(0.3)
    os.kill(p.pid, signal.SIGTERM)  # again: at once
    t = time.time()
    out.append(f"supervisor exit {wait(p, 30)} quick={time.time() - t < 3}")
    out.append(finish(up))
    out.append(f"workers gone={gone(list(pids.values()), 5)}")
elif mode == "stubborn":
    p = start(WORKERS="2", STUBBORN="1", STOP_TIMEOUT_MS="500")
    pids = workers(2)
    os.kill(p.pid, signal.SIGTERM)
    t = time.time()
    out.append(f"supervisor exit {wait(p, 30)} within={time.time() - t < 5}")
    out.append(f"workers gone={gone(list(pids.values()), 5)}")
    err = stderr_of(p)
    out.append(f"killed={'stop timeout' in err and 'killed by signal 9' in err}")
elif mode == "sigchld-ignored":
    # inherited across exec: the kernel reaps the workers itself, and
    # waitid finds nothing (ECHILD)
    p = start(preexec=lambda: signal.signal(signal.SIGCHLD, signal.SIG_IGN), WORKERS="2")
    pids = workers(2)
    os.kill(pids[0], signal.SIGKILL)
    t0 = time.time(); again = None
    while time.time() - t0 < 10 and again is None:
        try:
            w, pid = get(b"/pid").split()
            seen_pids.add(int(pid))
            if int(w) == 0 and int(pid) != pids[0]:
                again = int(pid)
        except OSError:
            pass
    out.append(f"restarted={again is not None} supervisor alive={p.poll() is None}")
    os.kill(p.pid, signal.SIGTERM)
    out.append(f"supervisor exit {wait(p, 30)}")
elif mode == "foreign-worker":
    # a worker not started by a supervisor: no mask from it, so it runs
    # itself again before reading its signals
    results = []
    for _ in range(3):
        a, b = socket.socketpair()
        p = start(pass_fds=(b.fileno(),), MOJO_NET_WORKER=f"0:{b.fileno()}:")
        b.close()
        os.kill(p.pid, signal.SIGTERM)
        results.append(wait(p, 30))
        a.close()
    out.append(f"exits {results}")
elif mode == "orphans":
    p = start(WORKERS="2")
    pids = workers(2)
    p.kill(); p.wait()
    out.append(f"workers gone={gone(list(pids.values()), 10)}")
elif mode == "crashloop":
    e = dict(os.environ, WORKERS="1", CRASH="1")
    p = subprocess.Popen([build(), f"127.0.0.1:{port}"], env=e, stderr=subprocess.PIPE, text=True,
                         start_new_session=True)
    seen_pids.add(p.pid); groups.add(p.pid)
    time.sleep(2.0)
    os.kill(p.pid, signal.SIGTERM)
    out.append(f"supervisor exit {wait(p, 30)}")
    err = stderr_of(p)
    delays = [int(l.split("restarting in ")[1].split(" ")[0]) for l in err.splitlines() if "restarting in" in l]
    out.append(f"restarts={len(delays) >= 3} growing={delays == sorted(delays) and delays[0] < delays[-1]}")
    out.append(f"exit 3 seen={'exit status 3' in err}")
elif mode == "single":
    p = start(WORKERS="0")
    out.append(get(b"/pid").split()[0])
    up = upload_started()
    p.send_signal(signal.SIGINT)
    time.sleep(0.3)
    out.append(f"alive while a request is in progress={p.poll() is None}")
    out.append(finish(up))
    out.append(f"exit {wait(p, 30)}")
elif mode == "single-twice":
    p = start(WORKERS="0")
    up = upload_started()
    p.send_signal(signal.SIGINT)
    time.sleep(0.3)
    p.send_signal(signal.SIGINT)
    t = time.time()
    out.append(f"exit {wait(p, 30)} quick={time.time() - t < 3}")
    out.append(finish(up))
print("|".join(out), flush=True)
"""


def _drive(mode: StaticString) raises -> String:
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    var r = subprocess.run(
        Python.list(pysys.executable, "-c", _DRIVER, mode),
        capture_output=True,
        text=True,
        timeout=300,
    )
    return String(String(py=r.stdout).strip()) + String(String(py=r.stderr).strip())


def test_the_supervisor_restarts_and_stops_its_workers() raises:
    assert_equal(
        _drive("supervise"),
        "3 workers|threads=['2']|widened=True|restarted=True|while stopping: supervisor alive=True"
        + "|HTTP/1.1 200 OK close=True got 10|supervisor exit 0|workers gone=True|logged=True",
    )


def test_pinned_workers_stay_on_their_cpu() raises:
    assert_equal(_drive("pinned"), "threads=['2'] one cpu each=True|supervisor exit 0")


def test_a_second_signal_stops_at_once() raises:
    var got = _drive("twice")
    assert_true(got.startswith("supervisor exit 0 quick=True|"), got)
    assert_true(got.endswith("|workers gone=True"), got)
    assert_true(got.find("200 OK") < 0, got)  # the upload was cut


def test_workers_that_do_not_stop_are_killed_at_the_stop_timeout() raises:
    assert_equal(_drive("stubborn"), "supervisor exit 0 within=True|workers gone=True|killed=True")


def test_a_supervisor_that_inherited_sigchld_ignored_still_restarts() raises:
    assert_equal(_drive("sigchld-ignored"), "restarted=True supervisor alive=True|supervisor exit 0")


def test_a_worker_started_without_the_mask_gets_it() raises:
    assert_equal(_drive("foreign-worker"), "exits [0, 0, 0]")


def test_workers_stop_when_their_supervisor_dies() raises:
    assert_equal(_drive("orphans"), "workers gone=True")


def test_workers_that_keep_crashing_are_restarted_later_and_later() raises:
    assert_equal(_drive("crashloop"), "supervisor exit 0|restarts=True growing=True|exit 3 seen=True")


def test_a_single_process_stops_gracefully_on_sigint() raises:
    assert_equal(
        _drive("single"),
        "-1|alive while a request is in progress=True|HTTP/1.1 200 OK close=True got 10|exit 0",
    )


def test_workers_serve_tls() raises:
    """S7, TS13: each worker builds its own TLS context after starting (no
    TLS state crosses the fork), and none sees SSLKEYLOGFILE (TS11)."""
    assert_equal(_drive("tls"), "2 workers over TLS|[]|supervisor exit 0|key log written=False")


def test_a_second_sigint_stops_a_single_process_at_once() raises:
    var got = _drive("single-twice")
    assert_true(got.startswith("exit 0 quick=True|"), got)
    assert_true(got.find("200 OK") < 0, got)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
