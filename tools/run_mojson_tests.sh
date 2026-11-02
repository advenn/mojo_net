#!/usr/bin/env bash
# Build mojson and run its tests (tests/mojson) with the environment's Python.
# The corpus part reads build/bench_json (written by `pixi run bench-json`)
# and is skipped without it; MOJSON_FUZZ_SCALE=n multiplies the fuzz counts.
set -euo pipefail
cd "$(dirname "$0")/.."
bash tools/build_mojson.sh
PYTHONPATH=build/python python3 -m unittest discover -s tests/mojson -v
