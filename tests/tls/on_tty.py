"""Run a program on a pseudo-terminal of its own (test-only Python; not a
test file itself): `run(argv, timeout)` returns everything it wrote there,
or raises if it has not exited within `timeout` seconds (it would be
waiting for input, a passphrase for example). The terminal is its
controlling terminal, so /dev/tty is that pseudo-terminal."""

import os
import pty
import select
import signal
import time


def run(argv, timeout, env=None):
    """`env`: the program's environment (default: this process's)."""
    pid, fd = pty.fork()
    if pid == 0:
        try:
            if env is None:
                os.execv(argv[0], list(argv))
            else:
                os.execve(argv[0], list(argv), env)
        finally:
            os._exit(127)
    out = b""
    end = time.monotonic() + timeout
    while True:
        left = end - time.monotonic()
        if left <= 0:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            raise TimeoutError(f"still running after {timeout} s; it wrote: {out!r}")
        ready, _, _ = select.select([fd], [], [], min(left, 0.5))
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:  # (EIO: the program closed the terminal)
                chunk = b""
            if not chunk:
                break
            out += chunk
        done, _ = os.waitpid(pid, os.WNOHANG)
        if done and not ready:
            break
    os.waitpid(pid, 0) if not done else None
    os.close(fd)
    return out.decode(errors="replace")
