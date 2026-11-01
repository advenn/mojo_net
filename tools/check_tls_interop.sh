#!/usr/bin/env bash
# TG12 (docs/tls.md, "Checks"): the HTTPS server (examples/server/https.mojo)
# scanned by TLS tools written by other people (2026-11 analysis: the server
# side had never met one):
# - sslyze, against Mozilla's "intermediate" configuration (TLS versions,
#   cipher suites, curves, signature algorithms, the certificate's type);
# - testssl.sh, every check, failing on a finding rated HIGH or CRITICAL
#   (the test root is added as trusted, so the throwaway chain is not one;
#   IGNORED below lists what the throwaway certificate itself draws).
# Both come pinned: sslyze from PyPI ($SSLYZE), testssl.sh by tag and
# commit ($TESTSSL_TAG, $TESTSSL_COMMIT). Weekly in
# .github/workflows/tls-weekly.yml, on x86_64.
#
#   bash tools/check_tls_interop.sh              # needs network the first time
set -u
cd "$(dirname "$0")/.."
SSLYZE="${SSLYZE:-sslyze==6.3.1}"
TESTSSL_TAG="${TESTSSL_TAG:-v3.2.4}"
TESTSSL_COMMIT="${TESTSSL_COMMIT:-97763a411c525720a5f9bd9d2cded416b10f210a}"
out=build/tls_interop
mkdir -p "$out"
fail=0

# The tools, once.
if [[ ! -x "$out/venv/bin/sslyze" ]]; then
  # (Python 3.12: the newest that sslyze's nassl publishes wheels for)
  "${PIXI_EXE:-pixi}" exec --spec python=3.12 --spec pip -- python -m venv "$out/venv" \
    && "$out/venv/bin/python" -m pip install -q "$SSLYZE" || { echo "FAIL installing $SSLYZE"; exit 1; }
fi
if [[ ! -x "$out/testssl.sh/testssl.sh" ]]; then
  git clone -q --depth 1 --branch "$TESTSSL_TAG" https://github.com/testssl/testssl.sh "$out/testssl.sh" \
    || { echo "FAIL fetching testssl.sh $TESTSSL_TAG"; exit 1; }
fi
if [[ "$(git -C "$out/testssl.sh" rev-parse HEAD)" != "$TESTSSL_COMMIT" ]]; then
  echo "FAIL testssl.sh $TESTSSL_TAG is not commit $TESTSSL_COMMIT (a moved tag?)"; exit 1
fi

# The server, on a throwaway PKI.
pki="$out/pki"
rm -rf "$pki"
python3 tests/tls/tls_pki.py "$pki" >/dev/null || { echo "FAIL making the PKI"; exit 1; }
chmod 600 "$pki/good.key"
mojo build -I src examples/server/https.mojo -o "$out/https" >"$out/https.build" 2>&1 || { echo "FAIL building the server"; tail -20 "$out/https.build"; exit 1; }
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
"$out/https" "$pki/good.chain.pem" "$pki/good.key" localhost "127.0.0.1:$port" >"$out/server.log" 2>&1 &
server=$!
trap 'kill $server 2>/dev/null; wait $server 2>/dev/null' EXIT
for _ in $(seq 100); do
  python3 -c "import socket; socket.create_connection(('127.0.0.1', $port), 1).close()" 2>/dev/null && break
  sleep 0.1
done

# sslyze: Mozilla's intermediate configuration.
"$out/venv/bin/sslyze" --mozilla_config=intermediate --certinfo_ca_file "$pki/root.pem" "localhost:$port{127.0.0.1}" >"$out/sslyze.log" 2>&1
code=$?
if [[ $code -eq 0 ]]; then
  echo "ok   sslyze ($SSLYZE): compliant with Mozilla's intermediate configuration"
else
  echo "FAIL sslyze ($SSLYZE), exit $code:"; sed -n '/COMPLIANCE AGAINST/,$p' "$out/sslyze.log" | head -40; fail=1
fi

# testssl.sh: nothing rated HIGH or CRITICAL.
rm -f "$out/testssl.json"
"$out/testssl.sh/testssl.sh" --quiet --color 0 --warnings off --ip 127.0.0.1 --add-ca "$pki/root.pem" \
  --jsonfile "$out/testssl.json" "localhost:$port" >"$out/testssl.log" 2>&1
python3 - "$out/testssl.json" <<'EOF'
import json, sys
try:
    findings = json.load(open(sys.argv[1]))
except (OSError, ValueError) as e:
    print("FAIL testssl.sh: no results (%s)" % e)
    sys.exit(1)
# What the throwaway certificate draws, not the server: tests/tls/tls_pki.py
# makes certificates valid for two days, with no CRL or OCSP URL.
IGNORED = {
    "cert_expirationStatus": "the test certificate is valid for two days",
    "cert_notAfter": "the test certificate is valid for two days",
    "cert_revocation": "a test PKI has no CRL or OCSP URL",
}
bad = [f for f in findings if f.get("severity") in ("HIGH", "CRITICAL") and f.get("id") not in IGNORED]
for f in findings:
    if f.get("severity") in ("HIGH", "CRITICAL") and f.get("id") in IGNORED:
        print("     (ignored %s %s: %s)" % (f["severity"], f["id"], IGNORED[f["id"]]))
for f in bad:
    print("FAIL testssl.sh %s %s: %s" % (f["severity"], f["id"], f["finding"]))
if not bad:
    print("ok   testssl.sh: %d checks, none rated HIGH or CRITICAL" % len(findings))
sys.exit(1 if bad else 0)
EOF
[[ $? -eq 0 ]] || fail=1
exit $fail
