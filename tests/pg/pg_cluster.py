"""A throwaway PostgreSQL cluster for the tests/pg files that need a real
server (started through `pg_server.mojo`).

    python tests/pg/pg_cluster.py start   prints "port|dir" once it serves
    python tests/pg/pg_cluster.py stop DIR   stops it at once, removes DIR

The cluster lives in a fresh temp directory (under /tmp when $TMPDIR is too
long for a socket path): data, log, and the Unix socket
`DIR/.s.PGSQL.<port>`. It also listens on 127.0.0.1 at a free port. There is
one user per authentication method in pg_hba.conf, over both transports:

    trusty    trust
    plain     password        "plain-pw"
    md5user   md5             "md5-pw" (stored as MD5, so the exchange is MD5)
    scram     scram-sha-256   "pencil é" (non-ASCII, unchanged by SASLprep)

plus the superuser `postgres` (trust). Durability is off (fsync and so on):
the data is thrown away.
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile

_SOCKET_NAME = "/.s.PGSQL.65535"
_SUN_PATH = 107  # bytes of sun_path before the terminating NUL


def _scratch():
    d = tempfile.mkdtemp(prefix="mojo_net_pg_")
    if len(d) + len(_SOCKET_NAME) <= _SUN_PATH:
        return d
    os.rmdir(d)
    return tempfile.mkdtemp(prefix="mojo_net_pg_", dir="/tmp")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start():
    root = _scratch()
    data = os.path.join(root, "data")
    log = os.path.join(root, "log")
    try:
        subprocess.run(
            ["initdb", "-D", data, "-U", "postgres", "--auth=trust", "--no-sync", "-E", "UTF8", "--locale=C"],
            check=True,
            capture_output=True,
        )
        hba = ["local all postgres trust", "host all postgres 127.0.0.1/32 trust"]
        for user, method in [("trusty", "trust"), ("plain", "password"), ("md5user", "md5"), ("scram", "scram-sha-256")]:
            hba.append(f"local all {user} {method}")
            hba.append(f"host all {user} 127.0.0.1/32 {method}")
        with open(os.path.join(data, "pg_hba.conf"), "w") as f:
            f.write("\n".join(hba) + "\n")
        for _ in range(5):  # (another process may take the free port first)
            port = _free_port()
            opts = (
                f"-p {port} -k {root} -c listen_addresses=127.0.0.1 -c fsync=off"
                " -c synchronous_commit=off -c full_page_writes=off -c max_connections=50"
            )
            r = subprocess.run(
                ["pg_ctl", "-D", data, "-l", log, "-w", "-t", "60", "-o", opts, "start"], capture_output=True
            )
            if r.returncode == 0:
                break
        else:
            raise RuntimeError("pg_ctl start failed:\n" + open(log).read())
        sql = [
            "SET password_encryption = 'md5'",
            "CREATE ROLE md5user LOGIN PASSWORD 'md5-pw'",
            "SET password_encryption = 'scram-sha-256'",
            "CREATE ROLE plain LOGIN PASSWORD 'plain-pw'",
            "CREATE ROLE scram LOGIN PASSWORD 'pencil é'",
            "CREATE ROLE trusty LOGIN",
            "GRANT pg_signal_backend TO trusty",
            # (on disk now: with synchronous_commit off, a crash restart
            # would lose them, and tests crash a backend on purpose)
            "CHECKPOINT",
        ]
        subprocess.run(
            ["psql", "-h", root, "-p", str(port), "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-q"],
            input=";\n".join(sql) + ";\n",
            text=True,
            check=True,
            capture_output=True,
        )
    except BaseException:
        stop(root)
        raise
    print(f"{port}|{root}", flush=True)


def stop(root):
    """Stop the cluster at once and remove it, whatever fails on the way:
    if pg_ctl cannot stop it, the postmaster is killed by its PID file."""
    data = os.path.join(root, "data")
    try:
        r = subprocess.run(["pg_ctl", "-D", data, "-m", "immediate", "-w", "stop"], capture_output=True)
        stopped = r.returncode == 0
    except OSError:
        stopped = False
    if not stopped:
        try:
            with open(os.path.join(data, "postmaster.pid")) as f:
                os.kill(int(f.readline()), 9)  # (its children exit with it)
        except (OSError, ValueError):
            pass
    shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    if sys.argv[1] == "start":
        start()
    else:
        stop(sys.argv[2])
