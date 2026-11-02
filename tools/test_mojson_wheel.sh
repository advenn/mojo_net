#!/usr/bin/env bash
# Test mojson's built wheels as a user gets them (docs/mojson.md, "Release").
# For each interpreter given, its own wheel from DIST (cpXY-cpXY):
#   1. a fresh virtualenv, the wheel installed by pip (mojo-compiler from
#      PyPI), and tests/mojson run against the installed package, not
#      build/python;
#   2. the Mojo runtime checked to come from that mojo-compiler (the
#      extension's RUNPATH, $ORIGIN/../modular/lib), not from this
#      repository's environment;
#   3. mojson alone in another directory (pip --target), where the RUNPATH
#      finds nothing and mojson/__init__.py loads the runtime itself.
# A free-threaded interpreter instead: pip must refuse every wheel, and
# mojson imported by path must raise ImportError, not crash.
#
#   bash tools/test_mojson_wheel.sh DIST PYTHON...
#   (locally: bash tools/test_mojson_wheel.sh build/dist "$(uv python find 3.12)" \
#      "$(uv python find 3.13)" "$(uv python find 3.14)" "$(uv python find 3.14t)")
set -euo pipefail
cd "$(dirname "$0")/.."
[ $# -ge 2 ] || { echo "usage: $0 DIST PYTHON..."; exit 2; }
dist=$(realpath "$1"); shift
here=$PWD
root=$here/build/wheeltest
mkdir -p "$root"
# Where the process loaded the Mojo runtime from, and the mojson it imported.
probe='
import sys, mojson
assert mojson.loads(b"[1, 2.5, \"\\u00e9\"]") == [1, 2.5, "\u00e9"]
maps = open("/proc/self/maps").read().split("\n")
rt = sorted({l.split()[-1] for l in maps if l.endswith("/libKGENCompilerRTShared.so")})
print(mojson.__file__, mojson.__version__, rt[0] if len(rt) == 1 else rt)
'
for py in "$@"; do
  read -r v tag ft < <("$py" -c 'import sys, sysconfig; print("%d.%d cp%d%d %d" % (*sys.version_info[:2], *sys.version_info[:2], bool(sysconfig.get_config_var("Py_GIL_DISABLED"))))')
  env=$root/py$v
  if [ "$ft" = 1 ]; then env=${env}t; fi
  rm -rf "$env" "$env-split"
  "$py" -m venv "$env"
  if [ "$ft" = 1 ]; then
    for w in "$dist"/mojson-*.whl; do
      if "$env/bin/python" -m pip install -q --disable-pip-version-check --no-deps "$w" 2>/dev/null; then
        echo "FAIL pip installed $(basename "$w") on free-threaded Python $v"; exit 1
      fi
    done
    w=$(ls "$dist"/mojson-*-"$tag"-"$tag"-*.whl)
    "$env/bin/python" -m zipfile -e "$w" "$env-split"
    out=$(cd / && PYTHONPATH="$env-split" "$env/bin/python" -c 'import mojson' 2>&1) && { echo "FAIL mojson imported on free-threaded Python $v"; exit 1; }
    [[ "$out" == *"ImportError: mojson does not support the free-threaded build"* ]] || { echo "$out"; echo "FAIL free-threaded Python $v: not the ImportError expected"; exit 1; }
    echo "== free-threaded Python $v: pip refuses every wheel; imported by path, ImportError"
    continue
  fi
  wheel=$(ls "$dist"/mojson-*-"$tag"-"$tag"-*.whl)
  "$env/bin/python" -m pip install -q --disable-pip-version-check "$wheel"
  site=$("$env/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["platlib"])')
  read -r file version runtime < <(cd / && "$env/bin/python" -c "$probe")
  echo "== Python $v ($(basename "$wheel")): $file $version, runtime $runtime"
  [[ "$file" == "$site/mojson/__init__.py" ]] || { echo "FAIL mojson was not imported from the virtualenv"; exit 1; }
  [[ "$runtime" == "$site/modular/lib/libKGENCompilerRTShared.so" ]] || { echo "FAIL the Mojo runtime did not come from the installed mojo-compiler"; exit 1; }
  out=$(cd tests/mojson && MOJSON_CORPUS="${MOJSON_CORPUS:-$here/build/bench_json}" "$env/bin/python" -m unittest test_mojson 2>&1) || { echo "$out"; echo "FAIL tests/mojson on Python $v"; exit 1; }
  echo "   tests/mojson: $(echo "$out" | grep -E '^Ran ')$(echo "$out" | grep -oE 'skipped=[0-9]+' | sed 's/^/, /')"
  "$env/bin/python" -m pip install -q --disable-pip-version-check --no-deps --target "$env-split" "$wheel"
  read -r file version runtime < <(cd / && PYTHONPATH="$env-split" "$env/bin/python" -c "$probe")
  echo "   split layout: $file, runtime $runtime"
  [[ "$file" == "$env-split/mojson/__init__.py" && "$runtime" == "$site/modular/lib/libKGENCompilerRTShared.so" ]] || { echo "FAIL the split layout"; exit 1; }
done
echo "ok   the wheels in $dist on $# interpreters"
