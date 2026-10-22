#!/usr/bin/env bash
# Each spikes/expected_failures/*.mojo must FAIL to build, with the text on
# its "# EXPECT:" line in the compiler output. Run: bash spikes/check_expected_failures.sh
set -u
cd "$(dirname "$0")/.."
out_dir=$(mktemp -d)
trap 'rm -rf "$out_dir"' EXIT
fail=0
for f in spikes/expected_failures/*.mojo; do
  want=$(sed -n 's/^# EXPECT: //p' "$f")
  out=$(mojo build -I src "$f" -o "$out_dir/bin" 2>&1)
  code=$?
  if [[ $code -ne 0 && "$out" == *"$want"* ]]; then
    echo "ok   $f"
  else
    echo "FAIL $f (exit $code; wanted: $want)"
    echo "$out" | head -20
    fail=$((fail + 1))
  fi
done
[[ $fail -eq 0 ]]
