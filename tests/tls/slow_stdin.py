"""Run a command and write its stdin in timed pieces (test-only Python;
not a test file itself):

    python tests/tls/slow_stdin.py <gap seconds> <piece>... -- <command>...

Each piece (with "\\n" read as a newline) is written `gap` seconds after
the last, then stdin is closed; the command's output is its own, and so is
the exit status. `openssl s_client` takes a command letter (R, K, Q) only
when a read of its stdin starts with it, so each must arrive alone. A
separate process, not a thread of the test: Mojo code holds Python's lock
while it runs, so a thread would not run while the test serves."""

import subprocess
import sys
import time


def main():
    gap = float(sys.argv[1])
    cut = sys.argv.index("--")
    pieces = [p.replace("\\n", "\n") for p in sys.argv[2:cut]]
    proc = subprocess.Popen(sys.argv[cut + 1 :], stdin=subprocess.PIPE)
    try:
        for p in pieces:
            time.sleep(gap)
            proc.stdin.write(p.encode())
            proc.stdin.flush()
        time.sleep(gap)
        proc.stdin.close()
    except (BrokenPipeError, OSError):
        pass
    sys.exit(proc.wait())


if __name__ == "__main__":
    main()
