#!/usr/bin/env bash
# Build the mojson Python package (python/mojson) into build/python/mojson:
# its Python files, and the extension `_mojson.so` from python/mojson/_mojson.mojo
# (with src/ for `json`). `PYTHONPATH=build/python python3 -c "import mojson"`
# then imports it. MOJSON_TARGET_CPU sets --target-cpu (x86-64-v3 for valgrind).
set -euo pipefail
cd "$(dirname "$0")/.."
out=build/python/mojson
mkdir -p "$out"
cp python/mojson/*.py "$out/"
args=()
if [ -n "${MOJSON_TARGET_CPU:-}" ]; then
    args+=(--target-cpu "$MOJSON_TARGET_CPU" --debug-level line-tables)
fi
mojo build --emit shared-lib "${args[@]}" -I src -I python/mojson -o "$out/_mojson.so.part" python/mojson/_mojson.mojo
mv "$out/_mojson.so.part" "$out/_mojson.so"
echo "built $out"
