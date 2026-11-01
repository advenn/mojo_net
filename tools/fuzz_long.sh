#!/usr/bin/env bash
# The fuzzers, longer and from new seeds (2026-11 analysis: every fuzzer
# replayed the same cases in every run). Each of the files below reads
# MOJO_NET_FUZZ_SEED (shifts its seeds; a failure prints the value that
# replays it) and MOJO_NET_FUZZ_SCALE (multiplies its cases). By default the
# seed is the date and the scale 20. The parser fuzzers then run again built
# with AddressSanitizer, which sees a read past an input's end even when the
# output still matches the reference. Weekly in .github/workflows/fuzz.yml.
#
#   bash tools/fuzz_long.sh                       # seed from the date, scale 20
#   MOJO_NET_FUZZ_SEED=123 MOJO_NET_FUZZ_SCALE=1 bash tools/fuzz_long.sh
set -u
cd "$(dirname "$0")/.."
export MOJO_NET_FUZZ_SEED="${MOJO_NET_FUZZ_SEED:-$(date -u +%Y%m%d)}"
export MOJO_NET_FUZZ_SCALE="${MOJO_NET_FUZZ_SCALE:-20}"
echo "MOJO_NET_FUZZ_SEED=$MOJO_NET_FUZZ_SEED MOJO_NET_FUZZ_SCALE=$MOJO_NET_FUZZ_SCALE"
FUZZERS=(
  tests/http/test_parse_fuzz.mojo
  tests/http/test_body_fuzz.mojo
  tests/http/test_sse.mojo
  tests/http/test_form.mojo
  tests/json/test_json_fuzz.mojo
  tests/net/test_dns.mojo
  tests/server/test_router.mojo
)
ASAN=(tests/http/test_parse_fuzz.mojo tests/http/test_body_fuzz.mojo tests/json/test_json_fuzz.mojo tests/http/test_form.mojo)
out=build/fuzz_long
mkdir -p "$out"
fail=0
report() {  # report FILE LOG CODE TAG
  local summary
  summary=$(grep -E "^Summary" "$2" | tail -1)
  if [[ $3 -ne 0 || "$summary" != *" 0 failed"* || "$summary" == *" 0 tests run"* ]] || grep -q "ERROR: AddressSanitizer" "$2"; then
    echo "FAIL $1$4 (exit $3)"; grep -E -A8 "FAIL|ERROR: AddressSanitizer|replay" "$2" | head -40; fail=1
  else
    echo "ok   $1$4  ${summary#Summary }"
  fi
}
for f in "${FUZZERS[@]}"; do
  name=$(basename "$f" .mojo)
  timeout --kill-after=10 3000 mojo run -I src "$f" </dev/null >"$out/$name.log" 2>&1
  report "$f" "$out/$name.log" $? ""
done
for f in "${ASAN[@]}"; do
  name=$(basename "$f" .mojo)_asan
  if ! mojo build --sanitize address -I src -I "$(dirname "$f")" "$f" -o "$out/$name" >"$out/$name.build" 2>&1; then
    echo "FAIL $f (did not build with --sanitize address)"; tail -20 "$out/$name.build"; fail=1; continue
  fi
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 timeout --kill-after=10 3000 "$out/$name" </dev/null >"$out/$name.log" 2>&1
  report "$f" "$out/$name.log" $? " under ASan"
done
exit $fail
