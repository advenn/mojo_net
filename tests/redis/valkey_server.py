"""A throwaway Valkey server for the tests/redis files that need a real one
(started through `redis_server.mojo`).

    python tests/redis/valkey_server.py start [PID] [--requirepass PW] [--no-hello]   prints "port|dir"
    python tests/redis/valkey_server.py stop DIR                          stops it, removes DIR

It runs in a fresh temp directory (under /tmp when $TMPDIR is too long for
a socket path), on a free port on 127.0.0.1 and the Unix socket
`DIR/valkey.sock`, without persistence, and with DEBUG enabled (DEBUG
PROTOCOL, DEBUG SLEEP). Its users:

    default   no password, or --requirepass's   every command and key
    alice     "alice-pw"                         every command and key
    reader    "reader-pw"                        read commands only, keys pub:*

`--no-hello` takes HELLO away, so the server answers it as servers before
Redis 6 do ("unknown command").

With PID (the test process, as `redis_server.mojo` passes it), a detached
watcher also stops the server once that process has ended: a test that
crashes, or is killed at its timeout, cannot stop it itself.
"""

import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

_SOCKET_NAME = "/valkey.sock"
_SUN_PATH = 107  # bytes of sun_path before the terminating NUL


def _scratch():
    d = tempfile.mkdtemp(prefix="mojo_net_vk_")
    if len(d) + len(_SOCKET_NAME) <= _SUN_PATH:
        return d
    os.rmdir(d)
    return tempfile.mkdtemp(prefix="mojo_net_vk_", dir="/tmp")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _answers(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as c:
            c.sendall(b"*1\r\n$4\r\nPING\r\n")
            return c.recv(64) != b""  # (+PONG, or -NOAUTH with requirepass)
    except OSError:
        return False


def start(watch_pid=None, requirepass="", no_hello=False):
    root = _scratch()
    try:
        default = f"user default on >{requirepass} ~* &* +@all" if requirepass else "user default on nopass ~* &* +@all"
        for _ in range(5):  # (another process may take the free port first)
            port = _free_port()
            conf = os.path.join(root, "valkey.conf")
            with open(conf, "w") as f:
                f.write(
                    "\n".join(
                        [
                            f"port {port}",
                            "bind 127.0.0.1",
                            f"unixsocket {root}{_SOCKET_NAME}",
                            "unixsocketperm 700",
                            f"dir {root}",
                            'save ""',
                            "appendonly no",
                            "enable-debug-command yes",
                            default,
                            "user alice on >alice-pw ~* &* +@all",
                            "user reader on >reader-pw ~pub:* &* -@all +@read +@connection",
                        ]
                        + (['rename-command HELLO ""'] if no_hello else [])
                    )
                    + "\n"
                )
            with open(os.path.join(root, "log"), "w") as log:
                p = subprocess.Popen(
                    ["valkey-server", conf],
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            with open(os.path.join(root, "pid"), "w") as f:
                f.write(str(p.pid))
            for _ in range(200):
                if p.poll() is not None or _answers(port):
                    break
                time.sleep(0.02)
            if p.poll() is None and _answers(port):
                break
            p.kill()
            p.wait()
        else:
            raise RuntimeError("valkey-server did not start:\n" + open(os.path.join(root, "log")).read())
        if watch_pid is not None:
            with open(os.path.join(root, "watch.log"), "w") as errors:
                subprocess.Popen(  # (none of our pipes, or the caller would wait for it)
                    [sys.executable, os.path.abspath(__file__), "watch", root, str(watch_pid)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=errors,
                    start_new_session=True,
                )
    except BaseException:
        stop(root)
        raise
    print(f"{port}|{root}", flush=True)


def _ended(pid):
    """Whether process `pid` has ended: gone, or a zombie not reaped yet."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            state = f.read().rsplit(")", 1)[1].split()[0]
    except (OSError, IndexError):
        return True
    return state in ("Z", "X")


def watch(root, pid):
    """Stop the server at `root` once process `pid` has ended; return early
    when the server is stopped (`root` removed) first."""
    while os.path.isdir(root):
        if _ended(pid):
            stop(root)
            return
        time.sleep(0.5)


def stop(root):
    """Kill the server (no data to keep) and remove its directory."""
    try:
        with open(os.path.join(root, "pid")) as f:
            os.kill(int(f.read()), signal.SIGKILL)
    except (OSError, ValueError):
        pass
    shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    if sys.argv[1] == "start":
        args = sys.argv[2:]
        password = ""
        if "--requirepass" in args:
            i = args.index("--requirepass")
            password = args[i + 1]
            del args[i : i + 2]
        no_hello = "--no-hello" in args
        if no_hello:
            args.remove("--no-hello")
        start(int(args[0]) if args else None, password, no_hello)
    elif sys.argv[1] == "watch":
        watch(sys.argv[2], int(sys.argv[3]))
    else:
        stop(sys.argv[2])
