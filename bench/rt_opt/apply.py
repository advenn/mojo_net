#!/usr/bin/env python3
"""Build the "rt-opt" variant used in bench/README.md: copy src/ to DEST,
then apply to DEST/rt the three changes proposed to the rt owner (src/rt is
never modified):

1. slab: chunks of raw, uninitialized `T` plus an occupancy flag per slot,
   instead of `List[List[Optional[T]]]` (no Optional construct/take, no
   bounds-checked double indexing on every `_ops[id]` / `_fds[fd]`);
2. `Op.addr`: out of line (`List[RawSockaddr]`, 24 B) instead of an inline
   `Optional[RawSockaddr]` (136 B) that only listen/connect use;
3. `FdEntry.peer/local`: one out-of-line `List[RawSockaddr]`.

    python3 bench/rt_opt/apply.py DEST     # then build with -I DEST

Each replacement asserts that it matched, so a change in rt shows up as an
error here instead of a silently different benchmark.
"""

import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(os.path.dirname(HERE)), "src")


def rep(s, old, new, path):
    if old not in s:
        sys.exit(f"apply.py: pattern not found in {path}:\n{old}")
    return s.replace(old, new)


def patch(path, edits):
    with open(path) as f:
        s = f.read()
    for old, new in edits:
        s = rep(s, old, new, path)
    with open(path, "w") as f:
        f.write(s)


def main():
    dest = sys.argv[1]
    if os.path.exists(dest):
        shutil.rmtree(dest)
    shutil.copytree(SRC, dest)
    rt = os.path.join(dest, "rt")
    patch(
        os.path.join(rt, "core.mojo"),
        [
            ("    var addr: Optional[RawSockaddr]\n", "    var addr: List[RawSockaddr]\n"),
            ("        self.addr = None\n", "        self.addr = []\n"),
            ("        op.addr = addr.copy()\n", "        op.addr.append(addr.copy())\n"),
            ("self._ops[id].addr.value().copy()", "self._ops[id].addr[0].copy()"),
            (
                "    var peer: Optional[RawSockaddr]\n    var local: Optional[RawSockaddr]\n",
                "    var addrs: List[RawSockaddr]\n",
            ),
            ("        self.peer = None\n        self.local = None\n", "        self.addrs = []\n"),
            (
                "        return self._fds[fd].peer.copy()",
                "        if len(self._fds[fd].addrs) == 0:\n            return None\n"
                "        return self._fds[fd].addrs[0].copy()",
            ),
            (
                "        return self._fds[fd].local.copy()",
                "        if len(self._fds[fd].addrs) == 0:\n            return None\n"
                "        return self._fds[fd].addrs[0].copy()",
            ),
            ("self._fds[fd.value()].local = Optional(local^)", "self._fds[fd.value()].addrs.append(local^)"),
            ("self._fds[fd].peer = Optional(addr.copy())", "self._fds[fd].addrs.append(addr.copy())"),
            ("self._fds[conn.value()].peer = Optional(peer^)", "self._fds[conn.value()].addrs.append(peer^)"),
        ],
    )
    slab = os.path.join(rt, "slab.mojo")
    with open(slab) as f:
        s = f.read()
    start = s.index("struct Slab[T: Movable & Deinitable](Movable, Sized):")
    with open(os.path.join(HERE, "slab_raw.mojo.txt")) as f:
        s = s[:start] + f.read()
    s = rep(s, "from std.hash import Hasher\n", "from std.hash import Hasher\nfrom std.memory import Layout, alloc\n", slab)
    with open(slab, "w") as f:
        f.write(s)
    print("rt-opt sources in", dest)


if __name__ == "__main__":
    main()
