#!/usr/bin/env python3
"""Build mojson's wheel from packaging/mojson/pyproject.toml (docs/mojson.md,
"Release"): only mojson's own files, never the rest of the repository.

    python3 tools/build_mojson_wheel.py [--out build/dist] [--target-cpu CPU]
    (pixi run -e release mojson-wheel, which then runs twine check)

The wheel holds mojson/__init__.py, mojson/_mojson.so and the licence:
- the extension is compiled for the portable CPU the metadata names for this
  machine (`mojo build` would otherwise target the build host's own);
- its RUNPATH is set to $ORIGIN/../modular/lib, where the mojo-compiler
  wheel it depends on installs the Mojo runtime; mojson/__init__.py loads
  the runtime from that distribution itself in other layouts;
- it is checked before it is packed: the libraries it links (the Mojo
  runtime and libc only), the glibc symbols it needs (none past its
  manylinux tag), its RUNPATH, and its PyInit symbol.

One build of the extension serves every Python the metadata lists: it
links no libpython (it resolves the C API from the interpreter that loads
it, and checks the object layouts it reads at import). It is packed once
per version, tagged cpXY-cpXY-<manylinux>_<machine>: a wheel tagged
`none` for its ABI would also install on the free-threaded build (cp314t, cp315t),
whose object headers differ and where the extension crashes at import.
Every check failing stops the build, with nothing written.
"""

import argparse
import base64
import hashlib
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGING = ROOT / "packaging" / "mojson"
SOURCE = ROOT / "python" / "mojson"
RUNPATH = "$ORIGIN/../modular/lib"
# What the extension may link: the Mojo runtime (from mojo-compiler) and
# glibc's own libraries, which every manylinux system has.
NEEDED = {"libKGENCompilerRTShared.so", "libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2"}


def fail(message):
    sys.exit("build_mojson_wheel: " + message)


def run(*cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        fail("%s failed:\n%s%s" % (" ".join(cmd), r.stdout, r.stderr))
    return r.stdout


def check_extension(so, glibc_max):
    """Fail unless the built extension is what the wheel's tag promises."""
    dynamic = run("readelf", "-d", "-W", str(so))
    needed = set(re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", dynamic))
    if not needed <= NEEDED:
        fail("the extension links %s, beyond %s" % (sorted(needed - NEEDED), sorted(NEEDED)))
    runpath = re.findall(r"\((RUNPATH|RPATH)\)\s+Library r(?:un)?path: \[([^\]]*)\]", dynamic)
    if runpath != [("RUNPATH", RUNPATH)]:
        fail("the extension's search path is %s, not RUNPATH %s" % (runpath, RUNPATH))
    versions = run("readelf", "-V", "-W", str(so))
    glibc = sorted({tuple(int(x) for x in v.split(".")) for v in re.findall(r"GLIBC_([0-9.]+)", versions)})
    if glibc and glibc[-1] > glibc_max:
        fail("the extension needs GLIBC_%s, past the tag's %s" % (".".join(map(str, glibc[-1])), ".".join(map(str, glibc_max))))
    if "PyInit__mojson" not in run("readelf", "--dyn-syms", "-W", str(so)):
        fail("the extension exports no PyInit__mojson")


def metadata(project, readme):
    lines = [
        "Metadata-Version: 2.4",
        "Name: " + project["name"],
        "Version: " + project["version"],
        "Summary: " + project["description"],
        "Keywords: " + ",".join(project.get("keywords", [])),
        "Author: " + ", ".join(a["name"] for a in project.get("authors", [])),
        "License-Expression: " + project["license"],
    ]
    lines += ["License-File: " + f for f in project.get("license-files", [])]
    lines += ["Classifier: " + c for c in project.get("classifiers", [])]
    lines += ["Project-URL: %s, %s" % kv for kv in project.get("urls", {}).items()]
    lines.append("Requires-Python: " + project["requires-python"])
    lines += ["Requires-Dist: " + d for d in project.get("dependencies", [])]
    lines.append("Description-Content-Type: " + project["readme"]["content-type"])
    return ("\n".join(lines) + "\n\n" + readme).encode()


def record_line(path, data):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return "%s,sha256=%s,%d" % (path, digest, len(data))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=str(ROOT / "build" / "dist"))
    ap.add_argument("--target-cpu", help="override the metadata's CPU for this machine")
    args = ap.parse_args()

    meta = tomllib.loads((PACKAGING / "pyproject.toml").read_text())
    project, cfg = meta["project"], meta["tool"]["mojson-wheel"]
    name, version = project["name"], project["version"]
    machine = platform.machine()
    if machine not in cfg["target-cpu"]:
        fail("no target CPU for %s in packaging/mojson/pyproject.toml" % machine)
    cpu = args.target_cpu or cfg["target-cpu"][machine]
    plat = "%s_%s" % (cfg["manylinux"], machine)
    glibc_max = tuple(int(x) for x in cfg["manylinux"].split("_")[1:3])

    # The versions that must agree: the package's, and the compiler's with
    # the runtime the wheel depends on.
    init = (SOURCE / "__init__.py").read_bytes()
    m = re.search(rb'^__version__ = "([^"]+)"', init, re.M)
    if not m or m.group(1).decode() != version:
        fail("python/mojson/__init__.py's __version__ is not %s" % version)
    mojo = re.search(r"Mojo (\S+)", run("mojo", "--version"))
    pins = [d for d in project["dependencies"] if d.startswith("mojo-compiler")]
    if not mojo or pins != ["mojo-compiler==" + mojo.group(1)]:
        fail("the dependency %s does not pin the compiler that builds the extension (%s)" % (pins, mojo and mojo.group(1)))

    with tempfile.TemporaryDirectory() as tmp:
        so = Path(tmp) / "_mojson.so"
        run("mojo", "build", "--emit", "shared-lib", "--target-cpu", cpu, "-I", str(ROOT / "src"), "-I", str(SOURCE), "-o", str(so), str(SOURCE / "_mojson.mojo"))
        run("patchelf", "--set-rpath", RUNPATH, str(so))
        check_extension(so, glibc_max)
        extension = so.read_bytes()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    readme = (PACKAGING / project["readme"]["file"]).read_text()
    print("target CPU %s; extension %d bytes" % (cpu, len(extension)))
    for py in cfg["python-tags"]:
        tag = "%s-%s-%s" % (py, py, plat)
        wheel = out / ("%s-%s-%s.whl" % (name, version, tag))
        write_wheel(wheel, name, version, tag, init, extension, metadata(project, readme), project.get("license-files", []))
        print("built %s (%d bytes)" % (wheel.relative_to(ROOT) if wheel.is_relative_to(ROOT) else wheel, wheel.stat().st_size))


def write_wheel(wheel, name, version, tag, init, extension, meta, license_files):
    """One wheel: mojson's two files, its metadata and its licence."""
    dist_info = "%s-%s.dist-info" % (name, version)
    wheel_meta = "Wheel-Version: 1.0\nGenerator: mojo_net tools/build_mojson_wheel.py\nRoot-Is-Purelib: false\nTag: %s\n" % tag
    files = [
        (name + "/__init__.py", init, 0o644),
        (name + "/_mojson.so", extension, 0o755),
        (dist_info + "/METADATA", meta, 0o644),
        (dist_info + "/WHEEL", wheel_meta.encode(), 0o644),
    ]
    files += [(dist_info + "/licenses/" + f, (ROOT / f).read_bytes(), 0o644) for f in license_files]
    record = "".join(record_line(p, d) + "\n" for p, d, _ in files) + dist_info + "/RECORD,,\n"
    files.append((dist_info + "/RECORD", record.encode(), 0o644))
    # Fixed timestamps: the same inputs give the same wheel.
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "315532800"))
    stamp = time.gmtime(max(epoch, 315532800))[:6]
    part = wheel.with_suffix(".part")
    with zipfile.ZipFile(part, "w", zipfile.ZIP_DEFLATED) as z:
        for path, data, mode in files:
            info = zipfile.ZipInfo(path, stamp)
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    part.replace(wheel)


if __name__ == "__main__":
    main()
