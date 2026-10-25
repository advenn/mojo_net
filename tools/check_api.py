#!/usr/bin/env python3
"""Check the public API of the stable packages against its snapshot
(docs/design.md, "Stability").

`linux`, `bytes` and `net` are stable: their public names only grow, and a
replacement ships beside the name it replaces. This check makes every change
to that surface deliberate. It renders each package's public API from
`mojo doc` (the compiler's own view: every public module, struct, trait,
field, method overload, function and comptime value, with its signature)
and compares it with `api/<pkg>.txt`:

    python3 tools/check_api.py           # fail on any difference, with a diff
    python3 tools/check_api.py --write   # accept the current API as the snapshot

Names with a leading `_` are not public, and `mojo doc` leaves them out.
`linux.fault` (the test-only fault seam, compiled only under
-D MOJO_NET_FAULTS=1) is not part of the API either.

The rendering is host-independent: `mojo doc` reads declarations without
elaborating them, so `SYS_getpid` reads `Int(39) if CompilationTarget.is_x86()
else Int(172)` on either architecture. A self-check fails the run when a
package renders nearly empty or without the names it is known for, so the
check cannot pass by checking nothing.
"""

import argparse
import difflib
import json
import os
import subprocess
import sys
import tempfile

STABLE = ("linux", "bytes", "net")
EXCLUDED_MODULES = {"linux": {"fault"}}
# The self-check: names each package must render, and its least number of
# lines (about half of what it renders now).
ANCHORS = {
    "linux": ("struct IoError", "struct Epoll", "comptime SYS_getpid"),
    "bytes": ("struct ByteBuffer", "trait Codec"),
    "net": ("struct TcpStream", "struct UdpSocket", "struct Resolver"),
}
MIN_LINES = {"linux": 500, "bytes": 35, "net": 300}

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _with_raises(signature, raises):
    """Put `raises` where Mojo writes it: before the top-level `->`, or at
    the end."""
    if not raises:
        return signature
    depth = 0
    for i, c in enumerate(signature):
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif depth == 0 and signature.startswith(" -> ", i):
            return signature[:i] + " raises" + signature[i:]
    return signature + " raises"


def _function_lines(fn, indent):
    out = []
    for o in fn["overloads"]:
        static = o.get("isStatic") and fn["name"] != "__init__"  # (constructors always are)
        line = indent + ("static " if static else "") + _with_raises(o["signature"], o.get("raises"))
        if o.get("deprecated"):
            line += "  # deprecated: " + " ".join(o["deprecated"].split())
        out.append(line)
    return sorted(out)


def _traits(decl):
    names = sorted(t["name"] for t in decl.get("parentTraits", []) if t["name"] != "AnyType")
    return "(" + ", ".join(names) + ")" if names else ""


def _alias_line(a, indent):
    value = " ".join(a.get("value", "").split())
    return indent + a["signature"] + (" = " + value if value else "")  # (a trait's has none)


def _type_lines(decl, indent):
    """A struct or trait, then its members, indented."""
    head = decl.get("signature") or decl["kind"] + " " + decl["name"]  # (traits have no signature)
    out = [indent + head + _traits(decl)]
    inner = indent + "    "
    for a in sorted(decl.get("aliases", []), key=lambda a: a["name"]):
        out.append(_alias_line(a, inner))
    for f in sorted(decl.get("fields", []), key=lambda f: f["name"]):
        out.append(inner + "var " + f["name"] + ": " + f["type"])
    for fn in sorted(decl.get("functions", []), key=lambda f: f["name"]):
        out.extend(_function_lines(fn, inner))
    return out


def render(pkg, doc):
    """The package's API as text: one block per module, sorted, so the
    snapshot changes only when the API does."""
    lines = []
    for m in sorted(doc["decl"]["modules"], key=lambda m: m["name"]):
        if m["name"] in EXCLUDED_MODULES.get(pkg, ()):
            continue
        body = []
        for a in sorted(m["aliases"], key=lambda a: a["name"]):
            body.append(_alias_line(a, ""))
        for fn in sorted(m["functions"], key=lambda f: f["name"]):
            body.extend(_function_lines(fn, ""))
        for t in sorted(m["traits"], key=lambda t: t["name"]):
            body.extend(_type_lines(t, ""))
        for s in sorted(m["structs"], key=lambda s: s["name"]):
            body.extend(_type_lines(s, ""))
        if body:
            name = pkg if m["name"] == "__init__" else pkg + "." + m["name"]
            lines.append("")
            lines.append("# " + name)
            lines.extend(body)
    head = [
        "# The public API of `" + pkg + "`, rendered from `mojo doc` by tools/check_api.py.",
        "# Stable: change it only as docs/design.md (\"Stability\") allows, then run",
        "# `pixi run api-update` and say why in the commit.",
    ]
    return "\n".join(head + lines) + "\n"


def mojo_doc(pkg, scratch):
    out = os.path.join(scratch, pkg + ".json")
    r = subprocess.run(
        ["mojo", "doc", "-I", "src", "src/" + pkg, "-o", out],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        sys.exit("FAIL mojo doc src/" + pkg + " (exit %d)" % r.returncode)
    with open(out) as f:
        return json.load(f)


def self_check(pkg, text):
    missing = [a for a in ANCHORS[pkg] if not any(l.lstrip().startswith(a) for l in text.splitlines())]
    if missing or text.count("\n") < MIN_LINES[pkg]:
        sys.exit("FAIL api self-check: %s renders %d lines, missing %s" % (pkg, text.count("\n"), missing))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--write", action="store_true", help="accept the current API as the snapshot")
    args = ap.parse_args()
    failed = []
    with tempfile.TemporaryDirectory() as scratch:
        for pkg in STABLE:
            text = render(pkg, mojo_doc(pkg, scratch))
            self_check(pkg, text)
            path = os.path.join(ROOT, "api", pkg + ".txt")
            if args.write:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    f.write(text)
                print("wrote api/%s.txt (%d lines)" % (pkg, text.count("\n")))
                continue
            try:
                with open(path) as f:
                    want = f.read()
            except FileNotFoundError:
                want = ""
            if text != want:
                failed.append(pkg)
                diff = difflib.unified_diff(
                    want.splitlines(), text.splitlines(), "api/%s.txt" % pkg, "src/%s (now)" % pkg, lineterm="", n=1
                )
                print("\n".join(diff))
    if args.write:
        return
    if failed:
        print("---- public API changed: %s" % ", ".join(failed))
        print("     Removing or changing a stable name needs a replacement beside it first")
        print("     (docs/design.md, \"Stability\"). If the change is intended, run")
        print("     `pixi run api-update` and say why in the commit.")
        sys.exit(1)
    print("---- public API: %s match api/*.txt" % ", ".join(STABLE))


if __name__ == "__main__":
    main()
