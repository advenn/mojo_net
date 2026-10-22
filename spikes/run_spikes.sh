#!/usr/bin/env bash
# Build and run all spikes (docs/spikes.md). Binaries go to spikes/out/.
# Usage: pixi run bash spikes/run_spikes.sh
set -u
cd "$(dirname "$0")/.."
out=spikes/out
mkdir -p "$out"
fail=0

build() {  # build <name>
  if ! mojo build -I src -I spikes "spikes/$1.mojo" -o "$out/$1" 2>&1 | grep -E "error" ; then
    return 0
  fi
  echo "FAIL build $1"; fail=$((fail + 1)); return 1
}

expect_pass() {  # expect_pass <label> <marker> <cmd...>
  local label=$1 marker=$2; shift 2
  local log; log=$("$@" 2>&1); local code=$?
  if [[ $code -eq 0 && "$log" == *"$marker"* ]]; then
    echo "ok   $label"
  else
    echo "FAIL $label (exit $code)"; echo "$log" | tail -20; fail=$((fail + 1))
  fi
}

echo "== $(mojo --version) / $(uname -srm)"
build pthread_spike
build runtime_threads_spike
build callback_spike

expect_pass "pthread spike" "PTHREAD SPIKE: PASS" timeout 60 "$out/pthread_spike"
expect_pass "pthread spike, taskset -c 0" "PTHREAD SPIKE: PASS" timeout 60 taskset -c 0 "$out/pthread_spike"
expect_pass "pthread spike, mojo run (JIT)" "PTHREAD SPIKE: PASS" timeout 120 mojo run -I src -I spikes spikes/pthread_spike.mojo
for m in detached-sleep detached-busy; do
  bad=0
  for _ in $(seq 1 50); do SPIKE_EXIT=$m timeout 10 "$out/pthread_spike" >/dev/null 2>&1 || bad=$((bad + 1)); done
  if [[ $bad -eq 0 ]]; then echo "ok   exit with live thread ($m) x50"; else echo "FAIL $m: $bad/50"; fail=$((fail + 1)); fi
done

echo "-- runtime threads (all CPUs)"
"$out/runtime_threads_spike" | grep -E "^stage|idle CPU|signals"
echo "-- runtime threads (taskset -c 0)"
taskset -c 0 "$out/runtime_threads_spike" | grep -E "^stage (0|5)"
echo "-- runtime threads (MODULAR_ENABLE_AFFINITY=1)"
MODULAR_ENABLE_AFFINITY=1 "$out/runtime_threads_spike" | grep -E "^stage 0|^  tid"

expect_pass "callback spike" "CALLBACK SPIKE: PASS" timeout 60 "$out/callback_spike"
taskset -c 3 "$out/callback_spike" | grep "ns/call"

bash spikes/check_expected_failures.sh || fail=$((fail + 1))
echo "---- spikes: $fail failure(s)"
[[ $fail -eq 0 ]]
