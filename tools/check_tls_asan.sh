#!/usr/bin/env bash
# Gate TG7 (docs/tls.md, "Checks"): the tls tests built with AddressSanitizer
# and run with LeakSanitizer. A use-after-free, double free or overflow in
# Mojo code, and any leaked OpenSSL object (SSL, SSL_CTX, BIO, library
# context), fails it. Leaks of the embedded Python interpreter and of the
# test-only fault plan are suppressed (tools/lsan_tls.supp); nothing else is.
# ASan cannot see a misuse inside libssl itself (docs/spikes.md, T0),
# except through the memcpy it intercepts: TG8 (tools/check_tls_asan_openssl.sh)
# reruns this script against an OpenSSL built with ASan, by setting
# TLS_ASAN_LIBDIR to a directory holding it beside the Mojo runtime.
set -u
cd "$(dirname "$0")/.."
out=build/tls_asan${TLS_ASAN_LIBDIR:+_openssl}
against=${TLS_ASAN_LIBDIR:+ (ASan OpenSSL)}
mkdir -p "$out"
fail=0
run() {  # run NAME DEFINES... -- FILE
  local name="$1"; shift
  local defines=()
  while [[ "$1" != "--" ]]; do defines+=("$1"); shift; done
  shift
  local file="$1" exe="$out/$name"
  if ! mojo build --sanitize address "${defines[@]}" -I src -I "$(dirname "$file")" -I tests/tls "$file" -o "$exe" >"$out/$name.build" 2>&1; then
    echo "FAIL $file (did not build with --sanitize address)"; tail -20 "$out/$name.build"; fail=1; return
  fi
  LD_LIBRARY_PATH="${TLS_ASAN_LIBDIR:-${LD_LIBRARY_PATH:-}}" \
  ASAN_OPTIONS=detect_leaks=1:abort_on_error=0 LSAN_OPTIONS="suppressions=$PWD/tools/lsan_tls.supp:print_suppressions=0" \
    timeout --kill-after=10 900 "$exe" </dev/null >"$out/$name.log" 2>&1
  local code=$?
  local summary
  summary=$(grep -E "^Summary" "$out/$name.log" | tail -1)
  if [[ $code -ne 0 || "$summary" != *" 0 failed"* ]] || grep -qE "ERROR: (AddressSanitizer|LeakSanitizer)" "$out/$name.log"; then
    echo "FAIL $file under ASan$against (exit $code)"
    grep -E -A12 "ERROR: (AddressSanitizer|LeakSanitizer)|FAIL" "$out/$name.log" | head -60
    fail=1
  else
    echo "ok   $file under ASan and LSan$against  ${summary#Summary }"
  fi
}
# Which files: every tests/**/test_*.mojo that uses TLS, by rule, so that
# a new test or review regression file is covered without anyone adding it
# here (a hand-kept list missed TR2's regression files, the https client
# tests and llm over https). A file uses TLS when it imports `tls` or
# `tls_util`, or talks https to a local peer. SKIP holds the exceptions,
# each with its reason.
declare -A SKIP=(
  [tests/tls/test_hostile_config.mojo]="imports Python's ssl into the process on purpose (a hostile OpenSSL config), and Python never frees OpenSSL's objects: LeakSanitizer reports them, with stacks too short (no frame pointers in libcrypto) for tools/lsan_tls.supp's libpython rule"
)
uses_tls() {
  grep -qE '^(from|import) (tls|tls_util)\b|https://(127\.0\.0\.1|localhost|\[::1\])' "$1"
}
for f in "${!SKIP[@]}"; do
  if [[ ! -f "$f" ]] || ! uses_tls "$f"; then
    echo "FAIL SKIP names $f, which is not a test that uses TLS (stale entry)"; fail=1
  fi
done
count=0
while IFS= read -r f; do
  uses_tls "$f" || continue
  if [[ -n "${SKIP[$f]:-}" ]]; then
    echo "skip $f: ${SKIP[$f]}"; continue
  fi
  name=${f#tests/}; name=${name%.mojo}; name=${name//\//_}
  defines=()
  [[ "$f" == *_faults.mojo ]] && defines=(-D MOJO_NET_FAULTS=1)
  count=$((count + 1))
  if [[ "$f" == tests/tls/test_server_leak.mojo ]]; then
    # (fewer rounds; ASan's quarantine holds freed memory, so LeakSanitizer
    # rather than the resident size is the check here)
    MOJO_NET_TLS_LEAK_ROUNDS=1000 MOJO_NET_TLS_LEAK_RSS=0 run "$name" "${defines[@]}" -- "$f"
  else
    run "$name" "${defines[@]}" -- "$f"
  fi
done < <(find tests -name 'test_*.mojo' | sort)
echo "$count files under ASan and LSan$against"
exit $fail
