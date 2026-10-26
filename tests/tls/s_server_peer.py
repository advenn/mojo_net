"""`openssl s_server` driven through its stdin commands, for the transcript
cases Python's `ssl` cannot make (test-only Python; started by
tests/tls/test_transcripts.mojo, not a test file itself).

    python tests/tls/s_server_peer.py <pki dir> <scenario>

Prints "PORT <n>", then one line per step the scenario reaches, then
"CLIENTHELLOS <n>" and "KEYUPDATES_RECEIVED <n>" counted from s_server's
-trace output, then "END". Scenarios (each after a TLS 1.3 handshake
unless said):

  keyupdate  send "one", a KeyUpdate asking for one back (K), "two"; wait
             for the client's "back"; a KeyUpdate (k), "three"; wait for
             "done"; quit (close_notify)
  plaintext  send "one", then plaintext straight onto the TCP connection (P)
  renego     TLS 1.2: send "one", a HelloRequest (r), "two"; wait for
             "back" or the connection's end
"""

import os
import socket
import subprocess
import sys
import threading
import time

TIMEOUT = 20.0


class Server:
    def __init__(self, d, extra):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()  # (s_server binds it again: a small race, retried below)
        args = ["openssl", "s_server", "-accept", f"127.0.0.1:{self.port}", "-naccept", "1",
                "-cert", f"{d}/good.pem", "-key", f"{d}/good.key", "-trace", "-ign_eof", *extra]
        self.proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.lines = []
        self.cond = threading.Condition()
        threading.Thread(target=self._read, daemon=True).start()
        self.wait_for("ACCEPT")

    def _read(self):
        for line in self.proc.stdout:
            with self.cond:
                self.lines.append(line.rstrip("\n"))
                self.cond.notify_all()
        with self.cond:
            self.lines.append(None)
            self.cond.notify_all()

    def wait_for(self, text):
        """Wait until a line containing `text` (True), or the end (False)."""
        deadline = time.monotonic() + TIMEOUT
        seen = 0
        with self.cond:
            while True:
                while seen < len(self.lines):
                    line = self.lines[seen]
                    seen += 1
                    if line is None:
                        return False
                    if text in line:
                        return True
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                self.cond.wait(left)

    def send(self, line):
        try:
            self.proc.stdin.write(line + "\n")
            self.proc.stdin.flush()
        except BrokenPipeError:
            pass  # (s_server has ended: the scenario's next wait says so)
        time.sleep(0.1)  # (s_server reads stdin and the socket in turns)

    def finish(self):
        try:
            self.proc.stdin.close()
        except (OSError, BrokenPipeError):
            pass
        try:
            self.proc.wait(TIMEOUT)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        time.sleep(0.1)
        lines = [l for l in self.lines if l is not None]
        # -trace prints each record as "Received TLS Record" or "Sent TLS
        # Record", then its messages indented ("    KeyUpdate, Length=1").
        received, hellos, updates = False, 0, 0
        for l in lines:
            if l.startswith("Received TLS Record"):
                received = True
            elif l.startswith("Sent TLS Record"):
                received = False
            elif received and l.strip().startswith("ClientHello"):
                hellos += 1
            elif received and l.strip().startswith("KeyUpdate"):
                updates += 1
        print("CLIENTHELLOS", hellos, flush=True)
        print("KEYUPDATES_RECEIVED", updates, flush=True)
        if os.environ.get("S_SERVER_TRACE"):
            print("\n".join(lines), file=sys.stderr)


def main():
    d, scenario = sys.argv[1], sys.argv[2]
    extra = ["-tls1_2"] if scenario == "renego" else ["-tls1_3"]
    srv = Server(d, extra)
    print("PORT", srv.port, flush=True)
    if not srv.wait_for("CIPHER is"):
        print("NO_HANDSHAKE", flush=True)
    elif scenario == "keyupdate":
        srv.send("one")
        srv.send("K")
        srv.send("two")
        print("STEP back" if srv.wait_for("back") else "MISSING back", flush=True)
        srv.send("k")
        srv.send("three")
        print("STEP done" if srv.wait_for("done") else "MISSING done", flush=True)
        srv.send("Q")
    elif scenario == "plaintext":
        srv.send("one")
        srv.send("P")
        print("STEP sent", flush=True)
    elif scenario == "renego":
        srv.send("one")
        srv.send("r")
        srv.send("two")
        print("STEP back" if srv.wait_for("back") else "MISSING back", flush=True)
        srv.send("Q")
    srv.finish()
    print("END", flush=True)


if __name__ == "__main__":
    main()
