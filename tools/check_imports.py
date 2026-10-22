#!/usr/bin/env python3
"""Enforce the package import rules (docs/design.md, "Packages").

Every Mojo file belongs to one package by its path:

    src/<pkg>/  tests/<pkg>/  examples/<pkg>/  bench/<pkg>/   -> <pkg>
    spikes/                                                   -> net (M1 evidence)

and may import only the packages listed for <pkg> in ALLOWED below (std is
always allowed; relative imports stay inside the package). In src/ that is
all it may import. Outside src/ other names are ignored, since tests and
benchmarks also import sibling helper modules (`test_loop_harness`,
`bench_common`). Docstrings and other triple-quoted strings are skipped, so
prose or embedded Python that starts with "from"/"import" is not an import.

    python3 tools/check_imports.py [--root DIR]

Prints each violation as `path:line: ...` and exits 1 if there are any. A
built-in self-test, run first, plants violations in a scratch tree and fails
if any goes unreported, so the check cannot pass by checking nothing.
"""

import argparse
import os
import re
import sys
import tempfile

# Dependencies point downward only: linux <- bytes <- net <- rt.
# `rt` is frozen and experimental: nothing outside it may import it.
ALLOWED = {
    "linux": {"linux"},
    "bytes": {"linux", "bytes"},
    "net": {"linux", "bytes", "net"},
    "rt": {"linux", "bytes", "net", "rt"},
}
AREAS = ("src", "tests", "examples", "bench")
FIXED = {"spikes": "net"}

_TRIPLE = re.compile(r'("""|\'\'\')(?:.|\n)*?\1')
_FROM = re.compile(r"^\s*from\s+(\.*)([A-Za-z_]\w*)?[\w.]*\s+import\b")
_IMPORT = re.compile(r"^\s*import\s+(.+)$")


def _blank(m):
    return "\n" * m.group(0).count("\n")


def imports(text):
    """Yield (line, top-level package) for every absolute import."""
    code = _TRIPLE.sub(_blank, text)
    for n, line in enumerate(code.split("\n"), 1):
        if line.lstrip().startswith("#"):
            continue
        m = _FROM.match(line)
        if m:
            if not m.group(1) and m.group(2):  # leading dots: relative
                yield n, m.group(2)
            continue
        m = _IMPORT.match(line)
        if m:
            for part in m.group(1).split("#")[0].split(","):
                name = part.strip().split(" ")[0]
                if name and not name.startswith("."):
                    yield n, name.split(".")[0]


def package_of(rel):
    """The package whose rules apply to `rel`, or (None, why)."""
    parts = rel.split(os.sep)
    if parts[0] in FIXED:
        return FIXED[parts[0]], None
    if parts[0] not in AREAS:
        return None, None  # not checked
    if len(parts) < 3:
        return None, f"put it under {parts[0]}/<package>/"
    if parts[1] not in ALLOWED:
        return None, f"unknown package {parts[1]!r} (add it to ALLOWED in tools/check_imports.py)"
    return parts[1], None


def check(root):
    """Return (files checked, violations)."""
    bad = []
    files = 0
    for top in AREAS + tuple(FIXED):
        base = os.path.join(root, top)
        for d, dirs, names in os.walk(base):
            dirs[:] = sorted(x for x in dirs if not x.startswith(".") and x != "out")
            for name in sorted(names):
                if not name.endswith(".mojo"):
                    continue
                path = os.path.join(d, name)
                rel = os.path.relpath(path, root)
                pkg, why = package_of(rel)
                if why:
                    bad.append(f"{rel}: {why}")
                    continue
                if pkg is None:
                    continue
                files += 1
                with open(path, encoding="utf-8") as f:
                    text = f.read()
                strict = rel.split(os.sep)[0] == "src"
                for line, name in imports(text):
                    if name == "std" or name in ALLOWED[pkg]:
                        continue
                    if name in ALLOWED:
                        bad.append(f"{rel}:{line}: {pkg} may not import {name}")
                    elif strict:
                        bad.append(f"{rel}:{line}: src/{pkg} may import only std and {sorted(ALLOWED[pkg])}, not {name}")
    return files, bad


def _self_test():
    plant = {
        # path: (source, expected violation substring or None)
        "src/linux/a.mojo": ("from bytes.buffer import ByteBuffer\n", "linux may not import bytes"),
        "src/bytes/b.mojo": ('"""Doc.\nfrom net import x\n"""\nfrom .buffer import y\n', None),
        "src/net/c.mojo": ("    from rt.core import Loop\n", "net may not import rt"),
        "src/net/d.mojo": ("import rt\n", "net may not import rt"),
        "src/net/e.mojo": ("from python import Python\n", "not python"),
        "src/rt/f.mojo": ("from net.addr import SocketAddr\nfrom std.sys import argv\n", None),
        "tests/net/g.mojo": ("from test_helpers import h\nfrom rt.event_loop import EventLoop\n", "net may not import rt"),
        "tests/rt/h.mojo": ("from test_loop_harness import H\nfrom rt.core import Loop\n", None),
        "examples/net/i.mojo": ("# from rt import nothing\nfrom net.tcp import TcpStream\n", None),
        "examples/j.mojo": ("from net.tcp import TcpStream\n", "put it under examples/<package>/"),
        "bench/http/k.mojo": ("from net.tcp import TcpStream\n", "unknown package 'http'"),
        "spikes/l.mojo": ("from rt.core import Loop\n", "net may not import rt"),
        "bench/rt/m.mojo": ("from bench_common import Ticker\nfrom rt.core import Loop\n", None),
    }
    with tempfile.TemporaryDirectory() as root:
        for rel, (src, _) in plant.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(src)
        files, bad = check(root)
        report = "\n".join(bad)
        errors = []
        for rel, (_, want) in plant.items():
            mine = [b for b in bad if b.startswith(rel)]
            if want is None and mine:
                errors.append(f"{rel}: unexpected {mine}")
            if want is not None and not any(want in b for b in mine):
                errors.append(f"{rel}: expected a violation containing {want!r}")
        expected = sum(1 for _, w in plant.values() if w is not None)
        if len(bad) != expected:
            errors.append(f"expected {expected} violations, got {len(bad)}:\n{report}")
        if files != 11:
            errors.append(f"expected 11 files checked, got {files}")
        if errors:
            sys.exit("check_imports self-test failed:\n" + "\n".join(errors))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    args = ap.parse_args()
    _self_test()
    files, bad = check(args.root)
    for b in bad:
        print(b)
    print(f"---- import rules: {files} files checked, {len(bad)} violations")
    if files == 0 or bad:
        sys.exit(1)


if __name__ == "__main__":
    main()
