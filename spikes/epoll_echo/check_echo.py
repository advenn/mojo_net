#!/usr/bin/env python3
"""Adversarial correctness checks for both echo servers (server.mojo and
baseline.c), run before trusting their benchmark numbers.

Each check starts a fresh server pinned like the benchmark and talks to it
with plain Python sockets (the oracle):

1. 200 concurrent connections, random payload sizes from 1 B to 256 KiB,
   byte-exact echo.
2. A slow reader: 16 MiB sent while reading in small sips. The server must
   queue, pause reading at its cap, resume, and still echo byte-exact. The
   check asserts `pauses > 0` and `send_eagain > 0` in its counters.
3. Half-close: 8 MiB then shutdown(SHUT_WR). Everything must come back
   before EOF, so queued output survives the peer's FIN. Then 200 small
   messages whose FIN arrives together with the data: the server must still
   see EOF (regression test for a lost-EOF bug in the short-read shortcut).
4. An abortive close (RST) while the server holds queued output for the
   connection: the server must drop it and keep serving.
5. 1000 connect/close cycles with nothing sent, then `open == 0`: no slot
   or fd leaks.

    python3 spikes/epoll_echo/check_echo.py
"""

import os
import random
import selectors
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench  # noqa: E402


def payload(n, seed):
    return random.Random(seed).randbytes(n)


def stats(srv):
    time.sleep(0.6)  # one STATS tick (500 ms)
    lines = srv.find("STATS")
    return bench.kv(lines[-1]) if lines else None  # tokio prints none


def check_concurrent(port):
    sel = selectors.DefaultSelector()
    conns = {}
    rng = random.Random(1)
    for i in range(200):
        s = socket.create_connection(("127.0.0.1", port))
        s.setblocking(False)
        data = payload(rng.randint(1, 256 * 1024), i)
        conns[s] = {"out": memoryview(data), "want": data, "got": bytearray()}
        sel.register(s, selectors.EVENT_READ | selectors.EVENT_WRITE)
    deadline = time.monotonic() + 30
    pending = set(conns)
    while pending and time.monotonic() < deadline:
        for key, ev in sel.select(timeout=1):
            s, c = key.fileobj, conns[key.fileobj]
            if ev & selectors.EVENT_WRITE and c["out"]:
                n = s.send(c["out"])
                c["out"] = c["out"][n:]
                if not c["out"]:
                    sel.modify(s, selectors.EVENT_READ)
            if ev & selectors.EVENT_READ:
                chunk = s.recv(1 << 20)
                if not chunk:
                    raise AssertionError("server closed a connection early")
                c["got"] += chunk
                if len(c["got"]) >= len(c["want"]):
                    pending.discard(s)
    for s, c in conns.items():
        assert bytes(c["got"]) == c["want"], "echo mismatch"
        sel.unregister(s)
        s.close()
    assert not pending, f"{len(pending)} connections timed out"


def check_slow_reader(port):
    data = payload(16 << 20, 99)
    s = socket.create_connection(("127.0.0.1", port))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)
    got = bytearray()

    def writer():
        s.sendall(data)

    t = threading.Thread(target=writer)
    t.start()
    while len(got) < len(data):
        got += s.recv(4096)
        if len(got) < 4 << 20:
            time.sleep(0.0005)  # sip slowly at first: the server must queue
    t.join()
    s.close()
    assert bytes(got) == data, "slow-reader echo mismatch"


def check_half_close(port):
    data = payload(8 << 20, 7)
    s = socket.create_connection(("127.0.0.1", port))
    t = threading.Thread(target=lambda: (s.sendall(data), s.shutdown(socket.SHUT_WR)))
    t.start()
    time.sleep(0.2)  # let the server fill its queue before we read
    got = bytearray()
    while True:
        chunk = s.recv(1 << 20)
        if not chunk:
            break
        got += chunk
    t.join()
    s.close()
    assert len(got) == len(data), f"half-close: got {len(got)} of {len(data)} bytes"
    assert bytes(got) == data, "half-close echo mismatch"


def check_fin_with_data(port):
    """Data and FIN sent before the server even accepts, 200 times: the
    first readiness event then carries EPOLLIN|EPOLLRDHUP at once, the read
    is short, and a server that trusts "short read = drained" never sees the
    EOF (no further edge comes) and leaves the client waiting forever."""
    for i in range(200):
        data = payload(1 + i * 37 % 3000, i)
        s = socket.create_connection(("127.0.0.1", port))
        s.sendall(data)
        s.shutdown(socket.SHUT_WR)
        s.settimeout(3)
        got = bytearray()
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                got += chunk
        except socket.timeout:
            raise AssertionError(f"iteration {i}: no EOF after {len(got)} of {len(data)} bytes")
        finally:
            s.close()
        assert bytes(got) == data, f"iteration {i}: echo mismatch"


def check_rst_with_queue(port):
    s = socket.create_connection(("127.0.0.1", port))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.setblocking(False)
    sent = 0
    end = time.monotonic() + 2
    while time.monotonic() < end:
        try:
            sent += s.send(b"x" * 65536)
        except BlockingIOError:
            time.sleep(0.01)
            if sent > 4 << 20:
                break
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()  # RST while the server has output queued for us
    s2 = socket.create_connection(("127.0.0.1", port))
    s2.sendall(b"still alive")
    assert s2.recv(100) == b"still alive"
    s2.close()


def check_churn(port):
    for _ in range(1000):
        s = socket.create_connection(("127.0.0.1", port))
        s.close()


def main():
    ok = True
    kinds = ["mojo", "c"]
    if os.path.exists(bench.BIN["tokio"]):
        kinds.append("tokio")
    for kind in kinds:
        print(f"== {kind} server")
        for name, fn in (
            ("200 concurrent random-size echoes", check_concurrent),
            ("slow reader, 16 MiB (pause/resume)", check_slow_reader),
            ("half-close with queued output, 8 MiB", check_half_close),
            ("data + FIN before the first read, x200", check_fin_with_data),
            ("RST while output is queued", check_rst_with_queue),
            ("1000 connect/close cycles", check_churn),
        ):
            srv, port, pid, _ = bench.start_server(kind)
            try:
                t0 = time.monotonic()
                fn(port)
                st = stats(srv)
                alive = srv.p.poll() is None
                if st is None:  # no counters: only liveness is checked
                    good, extra = alive, " (no counters)"
                else:
                    good = alive and st["open"] == "0"
                    extra = f" open={st['open']} accepted={st['accepted']}"
                    if fn is check_slow_reader:
                        good &= int(st["pauses"]) > 0 and int(st["send_eagain"]) > 0
                        extra += f" pauses={st['pauses']} send_eagain={st['send_eagain']}"
                    if fn is check_half_close:
                        extra += f" send_eagain={st['send_eagain']}"
                print(
                    f"  {'ok  ' if good else 'FAIL'} {name} ({time.monotonic() - t0:.1f}s,{extra})"
                )
                ok &= good
            except Exception as e:  # noqa: BLE001
                print(f"  FAIL {name}: {e!r}")
                ok = False
            finally:
                srv.kill()
    print("ECHO CHECK:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
