#!/usr/bin/env bash
# Build every example (examples/<package>/*.mojo) into build/examples/, so an
# example that stops compiling fails CI instead of rotting unnoticed.
set -u
cd "$(dirname "$0")/.."
out=build/examples
mkdir -p "$out"
fail=0
total=0
while IFS= read -r f; do
  total=$((total + 1))
  rel="${f#examples/}"
  bin="$out/${rel//\//_}"
  bin="${bin%.mojo}"
  if log=$(mojo build -I src "$f" -o "$bin" 2>&1 </dev/null); then
    echo "ok   $f"
  else
    echo "FAIL $f"
    echo "$log" | tail -30
    fail=$((fail + 1))
  fi
done < <(find examples -name '*.mojo' | sort)
echo "---- $((total - fail))/$total examples built"
[[ $fail -eq 0 && $total -gt 0 ]]
