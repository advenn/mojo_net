"""Gate TG2 (docs/tls.md, "Checks"): the x509-limbo corpus through the tls
client's own verification, in real handshakes.

    python3 tools/limbo.py prepare <limbo.json> <dir>
    python3 tools/limbo.py compare <dir> <results.tsv> <deviations.txt> [--update]

`prepare` writes one directory per test case under <dir>/cases (the CA
file the client trusts, the chain and key the server presents) and
<dir>/cases.tsv, the cases the harness runs: index, id, the name kind (DNS
or IP), the expected name, and the expected result. Cases the client cannot
express are left out, each with its reason in <dir>/skipped.tsv: client
certificates, e-mail names, no expected name, key usages asked for, and
validation times that change the outcome (the client verifies at the
current time, and limbo's certificates mostly last from 1970 to 2969; the
17 that do not are its validity-window tests).

tests/tls/limbo_client.mojo then makes the handshakes, a `TlsClient`
built from `ClientConfig(trust=Trust.ca_file(...))` for the expected name,
against tests/tls/limbo_peer.py (Python's `ssl`, security level 0, so the
server presents whatever the case holds): SUB for every case (the chain
in a substituted TLS 1.2 Certificate message, since most cases have no
key), and KEY, a real handshake through the whole client, for those that
do. It writes <results.tsv>: index, mode, SUCCESS or FAILURE, the verify
result and the error. A case's result is KEY's when it has one, which may
be stricter than SUB's only through the client's gate.

`compare` lists every case whose result differs from limbo's expected one.
Each must appear in <deviations.txt> with a reason; the gate fails on an
unlisted deviation, and on a listed one that no longer deviates (so the
file stays exact). `--update` rewrites the file, keeping the reasons
already given and marking new lines "TODO" (which fail until a reason
replaces them). A deviation where the client accepts what limbo expects
refused is the dangerous kind: the file gives each its own reason, and
says whether OpenSSL 3.5.9's own harness accepts it too
(tools/limbo_openssl_anomalous.json, from x509-limbo.com).
"""

import base64
import datetime as dt
import json
import os
import re
import sys

MIN_CASES = 9000
"""Fewer cases to run means the pinned corpus has aged: BetterTLS's
certificates in it last one year (to 2027-01-21 in the pinned one), and
once they expire their cases become time-dependent. Then update the pin."""


def _der(pem):
    body = re.sub(r"-----[^-]+-----", "", pem)
    return base64.b64decode("".join(body.split()))


def _tlv(b, i):
    i += 1
    n = b[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[i : i + k], "big")
        i += k
    return i, i + n


def _time(tag, v):
    v = v.decode()
    if tag == 0x17:  # UTCTime: two-digit years, 1950-2049
        y = int(v[:2])
        v = str(y + (2000 if y < 50 else 1900)) + v[2:]
    return dt.datetime.strptime(v, "%Y%m%d%H%M%SZ").replace(tzinfo=dt.timezone.utc)


def validity(pem):
    """(notBefore, notAfter) of a certificate, or None if unreadable."""
    try:
        b = _der(pem)
        s, _ = _tlv(b, 0)  # Certificate
        s, _ = _tlv(b, s)  # TBSCertificate
        i = s
        if b[i] == 0xA0:  # [0] version
            i = _tlv(b, i)[1]
        for _ in range(3):  # serialNumber, signature, issuer
            i = _tlv(b, i)[1]
        a, _ = _tlv(b, i)  # Validity
        a1, z1 = _tlv(b, a)
        a2, z2 = _tlv(b, z1)
        return _time(b[a], b[a1:z1]), _time(b[z1], b[a2:z2])
    except Exception:
        return None


def _valid_at(certs, t):
    for c in certs:
        v = validity(c)
        if v is None:
            return None
        if not (v[0] <= t <= v[1]):
            return False
    return True


def skip_reason(tc, now):
    if tc["validation_kind"] != "SERVER":
        return "client certificate validation"
    name = tc["expected_peer_name"]
    if not name:
        return "no expected peer name"
    if name["kind"] not in ("DNS", "IP"):
        return "expected name of kind " + name["kind"]
    if tc["expected_peer_names"]:
        return "several expected names"
    if tc["key_usage"]:
        return "key usages asked for"
    if tc["signature_algorithms"]:
        return "signature algorithms asked for"
    eku = tc["extended_key_usage"]
    if eku and eku != ["serverAuth"]:
        return "extended key usage other than serverAuth"
    certs = tc["trusted_certs"] + tc["untrusted_intermediates"] + [tc["peer_certificate"]]
    if tc["validation_time"]:
        at = dt.datetime.fromisoformat(tc["validation_time"])
        then = _valid_at(certs, at)
        if then is not None and then != _valid_at(certs, now):
            return "validation time decides the outcome"
    elif _valid_at(certs, now) is False:
        return "no validation time, and not valid now"
    return None


def prepare(corpus, out):
    data = json.load(open(corpus))
    now = dt.datetime.now(dt.timezone.utc)
    cases_dir = os.path.join(out, "cases")
    os.makedirs(cases_dir, exist_ok=True)
    run, skipped = [], []
    for n, tc in enumerate(data["testcases"]):
        why = skip_reason(tc, now)
        if why:
            skipped.append(f"{tc['id']}\t{why}")
            continue
        d = os.path.join(cases_dir, str(n))
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "ca.pem"), "w") as f:
            f.write("".join(c if c.endswith("\n") else c + "\n" for c in tc["trusted_certs"]))
        with open(os.path.join(d, "chain.pem"), "w") as f:
            for c in [tc["peer_certificate"]] + tc["untrusted_intermediates"]:
                f.write(c if c.endswith("\n") else c + "\n")
        key = os.path.join(d, "key.pem")
        with open(key, "w") as f:
            f.write(tc["peer_certificate_key"] or "")
        os.chmod(key, 0o600)
        name = tc["expected_peer_name"]
        if "\t" in name["value"] or "\n" in name["value"]:
            skipped.append(f"{tc['id']}\tname with a tab or newline")
            continue
        has_key = "KEY" if tc["peer_certificate_key"] else "NOKEY"
        run.append(f"{n}\t{tc['id']}\t{name['kind']}\t{name['value']}\t{tc['expected_result']}\t{has_key}")
    with open(os.path.join(out, "cases.tsv"), "w") as f:
        f.write("\n".join(run) + "\n")
    with open(os.path.join(out, "skipped.tsv"), "w") as f:
        f.write("\n".join(skipped) + "\n")
    print(f"limbo: {len(run)} cases to run, {len(skipped)} left out ({out}/skipped.tsv)")
    if len(run) < MIN_CASES:
        raise SystemExit(f"FAIL only {len(run)} cases can run (< {MIN_CASES}): the pinned corpus has aged, update it")


def _read_deviations(path):
    """id -> (direction, reason) from the deviations file."""
    out = {}
    if not os.path.exists(path):
        return out
    for line in open(path):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            raise SystemExit(f"FAIL {path}: expected id<TAB>direction<TAB>reason: {line!r}")
        out[parts[0]] = (parts[1], parts[2])
    return out


HEADER = """\
# x509-limbo cases where the tls client's result differs from limbo's
# expected one (gate TG2, tools/limbo.py; docs/tls.md, "Checks").
# id<TAB>direction<TAB>reason. "accepted" means the client accepted a chain
# limbo expects refused (the dangerous direction), "refused" the reverse.
# "[openssl]" marks a case where OpenSSL 3.5.9's own limbo harness gives
# the same wrong result (x509-limbo.com, "anomalous results").
"""


def compare(out, results_path, dev_path, update):
    here = os.path.dirname(os.path.abspath(__file__))
    anomalous = json.load(open(os.path.join(here, "limbo_openssl_anomalous.json")))
    openssl_wrong = set(anomalous["verified"]) | set(anomalous["failed"])
    cases = {}
    for line in open(os.path.join(out, "cases.tsv")):
        if line.strip():
            n, tid, kind, name, expected, has_key = line.rstrip("\n").split("\t")
            cases[n] = (tid, expected, has_key == "KEY")
    runs = {}
    for line in open(results_path):
        if line.strip():
            parts = line.rstrip("\n").split("\t")
            runs.setdefault(parts[0], {})[parts[1]] = (parts[2], parts[4] if len(parts) > 4 else "", parts[3])
    failures = []
    deviations = {}
    for n, (tid, expected, has_key) in cases.items():
        r = runs.get(n, {})
        if "SUB" not in r or (has_key and "KEY" not in r):
            failures.append(f"no result: {tid}")
            continue
        for mode, (got, why, _) in r.items():
            if got not in ("SUCCESS", "FAILURE"):
                failures.append(f"{mode} gave {got}: {tid} ({why})")
        # A real handshake and the substituted one must agree (the
        # substitution is only a way to present a chain without its key),
        # but for the client's gate, which only a real handshake reaches:
        # it may refuse a chain OpenSSL verified (verify result 0).
        if has_key and r["KEY"][0] != r["SUB"][0]:
            gate = r["KEY"][0] == "FAILURE" and r["KEY"][2] == "0" and r["SUB"][0] == "SUCCESS"
            if not gate:
                failures.append(f"KEY and SUB disagree: {tid}: KEY {r['KEY'][0]} ({r['KEY'][1]}), SUB {r['SUB'][0]} ({r['SUB'][1]})")
        got, why, _ = r["KEY"] if has_key else r["SUB"]
        if got != expected:
            direction = "accepted" if got == "SUCCESS" else "refused"
            deviations[tid] = (direction, why)
    listed = _read_deviations(dev_path)
    for tid, (direction, why) in sorted(deviations.items()):
        if tid not in listed:
            failures.append(f"new deviation: {tid} {direction} ({why})")
        elif listed[tid][0] != direction:
            failures.append(f"changed direction: {tid} now {direction} ({why})")
        elif listed[tid][1].startswith("TODO"):
            failures.append(f"no reason given: {tid} {direction} ({why})")
    for tid in sorted(listed):
        if tid not in deviations:
            failures.append(f"no longer deviates (remove it): {tid}")
    accepted = sum(1 for d in deviations.values() if d[0] == "accepted")
    print(
        f"limbo: {len(cases)} cases run, {len(deviations)} deviate from limbo's expected result "
        f"({accepted} accepted that should be refused, {len(deviations) - accepted} refused that should pass)"
    )
    if update:
        lines = [HEADER]
        for tid, (direction, why) in sorted(deviations.items()):
            reason = listed[tid][1] if tid in listed and listed[tid][0] == direction else "TODO " + why
            mark = "[openssl] " if tid in openssl_wrong and not reason.startswith("[openssl]") else ""
            lines.append(f"{tid}\t{direction}\t{mark}{reason}")
        with open(dev_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        print(f"limbo: wrote {dev_path}")
        return 0
    for f in failures:
        print("FAIL " + f)
    if failures:
        return 1
    print("ok   every deviation is listed with its reason")
    return 0


def main():
    if len(sys.argv) >= 4 and sys.argv[1] == "prepare":
        prepare(sys.argv[2], sys.argv[3])
        return 0
    if len(sys.argv) >= 5 and sys.argv[1] == "compare":
        return compare(sys.argv[2], sys.argv[3], sys.argv[4], "--update" in sys.argv[5:])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
