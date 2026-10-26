"""A man in the middle for tests/tls/test_mutations.mojo (test-only Python;
not a test file itself): relays between the client under test and a TLS
server, and damages one direction once per connection, at a point chosen
by a seed (gate TG5).

    python tests/tls/tls_mitm.py <upstream port> <first seed> <count>

Prints "PORT <n>", then for each of `count` connections (seeds first,
first+1, ...) "SEED <seed> <what was done>" once the connection is over.
The damage, picked by the seed: flip a bit, drop bytes, duplicate bytes,
insert random bytes, replace bytes, or cut the connection, at an offset in
the handshake (half the seeds) or anywhere in the stream; mostly in the
server's direction, sometimes in the client's. Writes are split at seeded
points too, so records arrive in pieces. Once the damage is done, half a
second without traffic ends the connection: lost bytes stall a stream for
good, as a dead network would.
"""

import random
import socket
import sys
import threading


class Damage:
    def __init__(self, rng):
        self.direction = "s2c" if rng.random() < 0.8 else "c2s"
        self.offset = rng.randrange(0, 4000) if rng.random() < 0.5 else rng.randrange(0, 60000)
        self.kind = rng.choice(["flip", "drop", "dup", "insert", "replace", "cut"])
        self.size = rng.choice([1, 1, 2, 5, 16, 300])
        self.bit = rng.randrange(8)
        self.rng = rng
        self.done = False

    def describe(self):
        return f"{self.kind} {self.size} at {self.direction}+{self.offset}" + ("" if self.done else " (not reached)")

    def apply(self, data, pos):
        """`data` starts at stream offset `pos`; returns (bytes to send, cut?)."""
        if self.done or not (pos <= self.offset < pos + len(data)):
            return data, False
        self.done = True
        i = self.offset - pos
        if self.kind == "flip":
            b = bytearray(data)
            b[i] ^= 1 << self.bit
            return bytes(b), False
        if self.kind == "drop":
            return data[:i] + data[i + self.size :], False
        if self.kind == "dup":
            return data[: i + self.size] + data[i : i + self.size] + data[i + self.size :], False
        if self.kind == "insert":
            return data[:i] + bytes(self.rng.randrange(256) for _ in range(self.size)) + data[i:], False
        if self.kind == "replace":
            n = min(self.size, len(data) - i)
            return data[:i] + bytes(self.rng.randrange(256) for _ in range(n)) + data[i + n :], False
        return data[:i], True  # cut


def pump(src, dst, damage, direction, rng, closed):
    pos = 0
    src.settimeout(0.5)
    try:
        while not closed.is_set():
            try:
                data = src.recv(65536)
            except socket.timeout:
                if damage.done:  # (see the module docs)
                    break
                continue
            if not data:
                break
            out, cut = (damage.apply(data, pos) if damage.direction == direction else (data, False))
            pos += len(data)
            while out:  # (in seeded pieces)
                n = rng.randrange(1, len(out) + 1) if rng.random() < 0.3 else len(out)
                dst.sendall(out[:n])
                out = out[n:]
            if cut:
                break
    except OSError:
        pass
    closed.set()


def relay(client, upstream_port, seed):
    rng = random.Random(seed)
    damage = Damage(rng)
    server = socket.create_connection(("127.0.0.1", upstream_port))
    closed = threading.Event()
    threads = [
        threading.Thread(target=pump, args=(server, client, damage, "s2c", random.Random(seed * 2 + 1), closed)),
        threading.Thread(target=pump, args=(client, server, damage, "c2s", random.Random(seed * 2 + 2), closed)),
    ]
    for t in threads:
        t.start()
    closed.wait()  # (either direction ending, or a cut, ends the connection)
    for s in (client, server):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    for t in threads:
        t.join()
    client.close()
    server.close()
    return damage.describe()


def main():
    upstream, first, count = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(4)
    print("PORT", ls.getsockname()[1], flush=True)
    for seed in range(first, first + count):
        c, _ = ls.accept()
        print("SEED", seed, relay(c, upstream, seed), flush=True)


if __name__ == "__main__":
    main()
