#!/usr/bin/env bash
# Gate TG2 (docs/tls.md, "Checks"): the x509-limbo corpus (BetterTLS's
# path-building and name-constraint cases included) through the tls
# client's own verification, in real handshakes: tools/limbo.py prepares
# the cases, tests/tls/limbo_client.mojo connects to tests/tls/limbo_peer.py
# once per case (twice when the case has the leaf's key), and every result
# that differs from limbo's expected one must be listed, with its reason, in
# tests/tls/limbo_deviations.txt.
#
#   pixi run tls-limbo              the gate
#   pixi run tls-limbo --update     rewrite the deviations file (new lines
#                                   say TODO and fail until given a reason)
#   pixi run tls-limbo --self-test  planted bugs it must catch
#
# The corpus is downloaded once (the commit pinned below, checked against
# its SHA-256) into build/limbo/. BetterTLS's certificates in it expire on
# 2027-01-21; after that its cases become time-dependent and the gate fails
# until the pin moves to a newer corpus.
set -euo pipefail
cd "$(dirname "$0")/.."

COMMIT=1080e565f26e544bbe9cf99953be8a57c08e7e20
SHA256=611e337b9fb477b927bae65434650692cb9d2070ff5b05f975d0403510acd4de
URL="https://raw.githubusercontent.com/C2SP/x509-limbo/$COMMIT/limbo.json"
DEVIATIONS=tests/tls/limbo_deviations.txt

top=build/limbo
corpus="$top/limbo-$COMMIT.json"
mkdir -p "$top"
if [[ ! -f "$corpus" ]]; then
  curl -sSfL -o "$corpus.part" "$URL"
  mv "$corpus.part" "$corpus"
fi
echo "$SHA256  $corpus" | sha256sum -c --quiet - || { echo "FAIL $corpus does not match its pinned SHA-256"; rm -f "$corpus"; exit 1; }

run() {  # run <src dir> <name>: build the client against <src dir>, run every case
  local src="$1" name="$2"
  mojo build -I "$src" -I tests/tls tests/tls/limbo_client.mojo -o "$top/$name/limbo_client" >"$top/$name/build.log" 2>&1 \
    || { echo "FAIL building the limbo client ($top/$name/build.log)"; tail -5 "$top/$name/build.log"; exit 1; }
  "$top/$name/limbo_client" "$top/run" "$top/$name/results.tsv" >"$top/$name/run.log" 2>&1 \
    || { echo "FAIL the limbo run ($top/$name/run.log)"; tail -5 "$top/$name/run.log"; exit 1; }
}

rm -rf "$top/run"
python3 tools/limbo.py prepare "$corpus" "$top/run"

if [[ "${1:-}" == "--self-test" ]]; then
  # Each planted bug weakens one verification setting (in tls/config.mojo;
  # " ;; " separates several replacements); the gate must fail.
  olds=(
    'comptime HOST_FLAGS: c_uint = X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT'
    'comptime VERIFY_FLAGS: UInt64 = X509_V_FLAG_X509_STRICT | X509_V_FLAG_TRUSTED_FIRST'
    'comptime VERIFY_FLAGS: UInt64 = X509_V_FLAG_X509_STRICT | X509_V_FLAG_TRUSTED_FIRST ;; flags == VERIFY_FLAGS and flags & X509_V_FLAG_PARTIAL_CHAIN == 0'
    'comptime SECURITY_LEVEL = 2'
  )
  news=(
    'comptime HOST_FLAGS: c_uint = X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS'
    'comptime VERIFY_FLAGS: UInt64 = X509_V_FLAG_TRUSTED_FIRST'
    'comptime VERIFY_FLAGS: UInt64 = X509_V_FLAG_X509_STRICT | X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN ;; flags == VERIFY_FLAGS'
    'comptime SECURITY_LEVEL = 0'
  )
  whats=(
    'the CN read when there is no SAN'
    'no X509_V_FLAG_X509_STRICT'
    'partial chains on'
    'security level 0'
  )
  failed=0
  for i in "${!olds[@]}"; do
    old="${olds[$i]}" new="${news[$i]}" what="${whats[$i]}"
    name="plant"
    rm -rf "$top/$name"
    mkdir -p "$top/$name"
    cp -r src "$top/$name/src"
    python3 - "$top/$name/src/tls/config.mojo" "$old" "$new" <<'PY'
import sys
path, olds, news = sys.argv[1:]
t = open(path).read()
for old, new in zip(olds.split(" ;; "), news.split(" ;; "), strict=True):
    assert t.count(old) == 1, f"the planted bug's anchor moved: update the self-test ({old!r})"
    t = t.replace(old, new)
open(path, "w").write(t)
PY
    run "$top/$name/src" "$name"
    if python3 tools/limbo.py compare "$top/run" "$top/$name/results.tsv" "$DEVIATIONS" >"$top/$name/compare.log"; then
      echo "FAIL self-test: $what was not caught"
      failed=1
    else
      echo "ok   self-test: $what is caught ($(grep -c '^FAIL' "$top/$name/compare.log") cases change)"
    fi
  done
  exit $failed
fi

mkdir -p "$top/main"
run src main
python3 tools/limbo.py compare "$top/run" "$top/main/results.tsv" "$DEVIATIONS" ${1:+"$1"}
