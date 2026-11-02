#!/usr/bin/env bash
# The json tests built with AddressSanitizer (docs/json.md, "Testing").
# The parser writes and reads through raw pointers, past what a List's
# length would allow if it were not kept in step: ASan's container checks
# see an access past a List's length even inside its capacity, which the
# tests' results alone never show (J2's first version wrote nodes past
# `_nodes`' length; tls-asan found it through tests/llm). Every
# tests/json/test_*.mojo, so a new file is covered; the fault-seam files
# with -D MOJO_NET_FAULTS=1. Leaks are not checked: json holds no C
# objects, and the tests' Python oracles leak by design.
set -u
cd "$(dirname "$0")/.."
out=build/json_asan
mkdir -p "$out"
fail=0
count=0
for f in tests/json/test_*.mojo; do
  name=$(basename "$f" .mojo)
  defines=()
  [[ "$name" == *_faults ]] && defines=(-D MOJO_NET_FAULTS=1)
  count=$((count + 1))
  if ! mojo build --sanitize address "${defines[@]}" -I src -I tests/json "$f" -o "$out/$name" >"$out/$name.build" 2>&1; then
    echo "FAIL $f (did not build with --sanitize address)"; tail -20 "$out/$name.build"; fail=1; continue
  fi
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 timeout --kill-after=10 900 "$out/$name" </dev/null >"$out/$name.log" 2>&1
  code=$?
  summary=$(grep -E "^Summary" "$out/$name.log" | tail -1)
  if [[ $code -ne 0 || "$summary" != *" 0 failed"* || "$summary" == *" 0 tests run"* ]] || grep -q "ERROR: AddressSanitizer" "$out/$name.log"; then
    echo "FAIL $f under ASan (exit $code)"
    grep -E -A12 "ERROR: AddressSanitizer|FAIL" "$out/$name.log" | head -60
    fail=1
  else
    echo "ok   $f under ASan  ${summary#Summary }"
  fi
done
if [[ $count -eq 0 ]]; then
  echo "FAIL no tests/json/test_*.mojo found"; fail=1
fi
echo "$count files under ASan"
exit $fail
