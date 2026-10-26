#!/usr/bin/env bash
# Gate TG7 (docs/tls.md, "Checks"): the tls tests built with AddressSanitizer
# and run with LeakSanitizer. A use-after-free, double free or overflow in
# Mojo code, and any leaked OpenSSL object (SSL, SSL_CTX, BIO, library
# context), fails it. Leaks of the embedded Python interpreter and of the
# test-only fault plan are suppressed (tools/lsan_tls.supp); nothing else is.
# ASan cannot see a misuse inside libssl itself (docs/spikes.md, T0).
set -u
cd "$(dirname "$0")/.."
out=build/tls_asan
mkdir -p "$out"
fail=0
run() {  # run NAME DEFINES... -- FILE
  local name="$1"; shift
  local defines=()
  while [[ "$1" != "--" ]]; do defines+=("$1"); shift; done
  shift
  local file="$1" exe="$out/$name"
  if ! mojo build --sanitize address "${defines[@]}" -I src -I tests/tls "$file" -o "$exe" >"$out/$name.build" 2>&1; then
    echo "FAIL $file (did not build with --sanitize address)"; tail -20 "$out/$name.build"; fail=1; return
  fi
  ASAN_OPTIONS=detect_leaks=1:abort_on_error=0 LSAN_OPTIONS="suppressions=$PWD/tools/lsan_tls.supp:print_suppressions=0" \
    timeout --kill-after=10 600 "$exe" </dev/null >"$out/$name.log" 2>&1
  local code=$?
  local summary
  summary=$(grep -E "^Summary" "$out/$name.log" | tail -1)
  if [[ $code -ne 0 || "$summary" != *" 0 failed"* ]] || grep -qE "ERROR: (AddressSanitizer|LeakSanitizer)" "$out/$name.log"; then
    echo "FAIL $file under ASan (exit $code)"
    grep -E -A12 "ERROR: (AddressSanitizer|LeakSanitizer)|FAIL" "$out/$name.log" | head -60
    fail=1
  else
    echo "ok   $file under ASan and LSan  ${summary#Summary }"
  fi
}
run client -- tests/tls/test_client.mojo
run codec -- tests/tls/test_codec.mojo
run faults -D MOJO_NET_FAULTS=1 -- tests/tls/test_tls_faults.mojo
run transcripts -- tests/tls/test_transcripts.mojo
run mutations -- tests/tls/test_mutations.mojo
exit $fail
