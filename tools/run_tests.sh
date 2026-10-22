#!/usr/bin/env bash
# Run every tests/**/test_*.mojo (or those matching $1) with `mojo run -I src`.
# A file passes only if it ran >0 tests and reported 0 failures: TestSuite can
# discover zero tests and still exit 0.
# Files named test_*_faults.mojo (and only those) are built with
# -D MOJO_TCP_FAULTS=1, which compiles in the syscall fault-injection seam
# (src/linux/fault.mojo). Every other file runs on the exact production syscalls.
#
# Hangs: each file runs under `timeout` (MOJO_TCP_TEST_TIMEOUT seconds,
# default 600, then SIGKILL 10 s later), so a test that blocks forever fails
# with "timed out" instead of hanging the suite. The file name is printed
# before the file runs, so a CI log shows which file is running. `--foreground`
# keeps the test in the terminal's process group, so Ctrl-C still reaches it.
#
# Skips and notes: a test that cannot run on this host prints an indented
# "(skipped: <test>: <why>)" line and returns; a test that ran only partly
# prints "note: ...". Both are echoed under the file's result line, and skips
# are counted in the last line. MOJO_TCP_REQUIRE_IPV6=1 turns "no IPv6
# loopback" skips into failures (set it on hosts that have IPv6, e.g. CI).
#
# Without a filter the run also checks struct layouts and constants against
# this host's C headers (tools/gen_abi.py --check plus the generated
# build/test_abi_layout.mojo, i.e. `pixi run abi-check`). `pixi run ci` adds
# `nolibc-check`.
set -u
cd "$(dirname "$0")/.."
filter="${1:-}"
limit="${MOJO_TCP_TEST_TIMEOUT:-600}"
fail=0
total=0
skipped=0

# Overwrite the "run" line in a terminal; keep it as its own line in logs.
if [[ -t 1 ]]; then start_end=$'\r'; else start_end=$'\n'; fi

# run_one LABEL TAG CMD...: run CMD under the timeout and report LABEL.
run_one() {
  local label="$1" tag="$2"
  shift 2
  total=$((total + 1))
  printf 'run  %s%s' "$label" "$start_end"
  local out code summary notes n
  # stdin from /dev/null: the loop below feeds the file list on stdin, and a
  # test (or a child it spawns) must never consume it.
  out=$(timeout --foreground --kill-after=10 "$limit" "$@" </dev/null 2>&1)
  code=$?
  summary=$(grep -E "^Summary" <<<"$out" | tail -1)
  notes=$(grep -E '^[[:space:]]*(\(skipped:|note:)' <<<"$out")
  if [[ $code -eq 124 || $code -eq 137 ]]; then
    echo "FAIL $label  (timed out or killed after ${limit}s; exit $code)"
    echo "$out" | tail -40
    fail=$((fail + 1))
  elif [[ $code -ne 0 || -z "$summary" || "$summary" != *" 0 failed"* || "$summary" == *" 0 tests run"* ]]; then
    echo "FAIL $label"
    echo "$out" | tail -40
    fail=$((fail + 1))
  else
    echo "ok   $label  ${summary#Summary }${tag}"
  fi
  if [[ -n "$notes" ]]; then
    sed -E 's/^[[:space:]]*/       /' <<<"$notes"
    n=$(grep -cE '^[[:space:]]*\(skipped:' <<<"$notes")
    skipped=$((skipped + n))
  fi
}

while IFS= read -r f; do
  [[ -n "$filter" && "$f" != *"$filter"* ]] && continue
  base="$(basename "$f")"
  if [[ "$base" == test_*_faults.mojo ]]; then
    defines=(-D MOJO_TCP_FAULTS=1)
    run_one "$f" " [${defines[*]}]" mojo run "${defines[@]}" -I src "$f"
  else
    run_one "$f" "" mojo run -I src "$f"
  fi
done < <(find tests -name 'test_*.mojo' | sort)

if [[ -z "$filter" ]]; then
  run_one "build/test_abi_layout.mojo (gen_abi.py --check)" "" \
    bash -c 'python3 tools/gen_abi.py --check && mojo run -I src build/test_abi_layout.mojo'
fi

echo "---- $((total - fail))/$total test file runs passed, $skipped tests skipped on this host"
[[ $fail -eq 0 && $total -gt 0 ]]
