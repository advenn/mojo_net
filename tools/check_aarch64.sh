#!/usr/bin/env bash
# Cross-compile every test file and example for aarch64 (an ELF object;
# this host cannot run it), so code that only builds on x86_64 (syscall
# numbers, constants, struct layouts, inline asm) fails here. Pass paths to
# check only those: `pixi run aarch64-check tests/net/test_dns.mojo`.
# Files named test_*_faults.mojo get -D MOJO_NET_FAULTS=1, *_sim/_contract
# also the simulator define, as in tools/run_tests.sh.
set -u
cd "$(dirname "$0")/.."
out=build/aarch64
mkdir -p "$out"
fail=0
total=0
if [[ $# -gt 0 ]]; then
  files=("$@")
else
  mapfile -t files < <(find tests examples -name '*.mojo' \( -name 'test_*.mojo' -o -path 'examples/*' \) | sort)
fi
for f in "${files[@]}"; do
  total=$((total + 1))
  base="$(basename "$f")"
  defines=()
  [[ "$base" == test_*_faults.mojo ]] && defines+=(-D MOJO_NET_FAULTS=1)
  [[ "$base" == test_*_sim.mojo || "$base" == test_*_contract.mojo ]] && defines+=(-D MOJO_NET_SIM=1)
  obj="$out/$(echo "${f%.mojo}" | tr / _).o"
  if log=$(mojo build "${defines[@]}" -I src --target-triple aarch64-unknown-linux-gnu \
      --target-cpu generic --emit object -o "$obj" "$f" 2>&1 </dev/null); then
    echo "ok   $f"
  else
    echo "FAIL $f"
    echo "$log" | tail -20
    fail=$((fail + 1))
  fi
done
echo "---- $((total - fail))/$total files cross-compiled for aarch64"
[[ $fail -eq 0 && $total -gt 0 ]]
