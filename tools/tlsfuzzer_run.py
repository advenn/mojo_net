#!/usr/bin/env python3
"""TG12's tlsfuzzer part (docs/tls.md, "Checks"): tlsfuzzer's scripts that
fit this server, run one at a time against examples/server/https.mojo
serving an all-RSA chain (most scripts offer only RSA signature schemes,
for both the handshake and the certificates). tools/check_tls_interop.sh
starts the server and calls this with tlsfuzzer's checkout and the port:

    python tools/tlsfuzzer_run.py <tlsfuzzer dir> <port>

Each script runs with the tests that cannot apply here excluded (-e) and
the known deviations marked (-x NAME -X reason): a script fails on any
other failure, and on a marked test that passes (XPASS), so a fix shows.
Every exclusion and mark below was triaged on 2026-11-02 (tlsfuzzer
5eebc446, OpenSSL 3.5.9) against `openssl s_server` set to the same
policy. Kinds:
- policy: this server's policy (TLS 1.2 floor, groups X25519MLKEM768,
  X25519, P-256 and P-384, AEAD suites without CCM, no tickets, the 32 KiB
  ClientHello cap of TS8, the quiet budget);
- openssl: OpenSSL's own answer, the same from s_server (a different
  alert than tlsfuzzer expects, a limit it does not enforce);
- script: what the script assumes (TLS 1.2 suites hard-coded CBC, an echo
  server).
Scripts left out, for the same reasons: test-tls13-lengths (echo server),
test-tls13-non-support (servers without TLS 1.3), test-tls13-ecdsa-support
(an ECDSA certificate; sslyze covers ours), test-tls13-ffdhe-* (no FFDHE),
test-large-hello and test-client-hello-max-size (every probe over 32 KiB
meets the cap, every one under 16 KiB passed), and the TLS 1.2 scripts
whose positive probes are CBC only (extended-master-secret, heartbeat,
x25519, ecdhe-padded-shared-secret; EMS is checked by test-conversation's
-M)."""

import os
import re
import subprocess
import sys
import time

C12 = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"  # (a TLS 1.2 suite this server takes)
CLOSED = "Unexpected closure from peer"  # (our own limits close without an alert: docs/tls.md)


def x(name, reason):
    return ["-x", name, "-X", reason]


def e(*names):
    out = []
    for n in names:
        out += ["-e", n]
    return out


def finished_over_64():
    """test-tls13-finished: OpenSSL answers a Finished longer than 64 bytes
    (FINISHED_MAX_LENGTH) with illegal_parameter, tlsfuzzer expects
    decode_error (openssl)."""
    pads = {
        "TLS_AES_128_GCM_SHA256": (32, [(0, 1), (0, 2), (0, 4), (0, 8), (0, 16), (0, 32), (0, 48), (0, 2**14 - 4 - 32),
                                        (0, 0x20000), (0, 0x30000), (0, 256**3 - 1 - 32), (1, 0), (2, 0), (4, 0), (8, 0),
                                        (16, 0), (32, 0), (48, 0), (2**14 - 4 - 32, 0), (12, 0), (1, 1), (8, 8)]),
        "TLS_AES_256_GCM_SHA384": (48, [(0, 1), (0, 2), (0, 4), (0, 8), (0, 16), (0, 32), (0, 48), (0, 2**14 - 4 - 48),
                                        (0, 0x20000), (0, 0x30000), (0, 256**3 - 1 - 48), (0, 12), (1, 0), (2, 0), (4, 0),
                                        (8, 0), (16, 0), (32, 0), (48, 0), (2**14 - 4 - 48, 0), (1, 1), (8, 8)]),
    }
    out = []
    for cipher, (verify, sizes) in pads.items():
        for left, right in sizes:
            if verify + left + right > 64:
                out += x("padding - cipher %s, pad_byte 0, pad_left %d, pad_right %d" % (cipher, left, right), "illegal_parameter")
    return out


def no_ccm():
    """test-tls13-symetric-ciphers: the CCM suites (policy)."""
    out = []
    for cipher, n in (("TLS_AES_128_CCM_SHA256", 17), ("TLS_AES_128_CCM_8_SHA256", 9)):
        out += e("check connection with %s" % cipher)
        for what in ("application data", "finished message"):
            for v in (1, 2, 4, 8, 16, 32, 64, 128):
                for pos in range(-1, -n, -1):
                    out += e("check connection with %s - fuzz tag on %s with %d on pos %d" % (cipher, what, v, pos))
    return out


def random_extensions():
    """test-tls13-large-number-of-extensions: its random-payload probes
    are of random size, so which of them pass the 32 KiB cap changes from
    run to run (policy)."""
    ids = list(range(2, 5)) + list(range(6, 10)) + [11, 12, 17] + list(range(22, 28)) + list(range(29, 41)) + [46] + \
        list(range(52, 57)) + list(range(58, 65536))
    return [a for j in range(0, len(ids), 1024)
            for a in e("unassigned extensions with random payload, ids in range from %d to %d" % (ids[j], ids[min(j + 1023, len(ids) - 1)]))]


def record_limits():
    out = []
    for c in ("TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"):
        # (openssl: TLSInnerPlaintext over 2^14 + 1 is not refused; a Finished over 64 bytes)
        out += x("max size of Finished msg, with 16587 bytes of record layer padding %s" % c, "Timeout")
        out += x("max size payload (2**14) of Finished msg, with 16348 bytes of left padding, cipher %s" % c, 'received "illegal_parameter"')
        out += x("too big plaintext, size: 2**14 - 8, with an additional 9 bytes of padding, cipher %s" % c, "ApplicationData")
    # (policy: a first record over 2^14 is closed, without record_overflow)
    out += x("too big ClientHello msg, with 16168 bytes of padding", CLOSED)
    return out


def shuffled():
    # (openssl: a second ClientHello with its extensions reordered is taken)
    out = x("HRR reversed order of known extensions", "Handshake(server_hello)")
    out += x("HRR reversed order of unassigned extensions, ext_ids in range from 61493 to 65278", "Handshake(server_hello)")
    # (policy: the two ClientHellos together pass the 32 KiB cap)
    out += x("HRR reversed order of unassigned extensions, ext_ids in range from 52 to 4148", CLOSED)
    for s in range(4149, 57398, 4096):
        out += x("HRR reversed order of unassigned extensions, ext_ids in range from %d to %d" % (s, s + 4095), CLOSED)
    return out


def unrecognised_groups():
    out = []
    for r in ("EC", "FFDHE"):  # (policy: no FFDHE)
        for size in (64, 128, 256):
            out += e("known group ffdhe2048 and unknown groups from %s range, key_share of size %d" % (r, size),
                     "only unknown key_share from %s range, key_share of size %d + ffdhe2048 in supported_groups" % (r, size))
    for n in ("known group secp256r1 and unknown groups from EC range, key_share of size 256",  # (policy: over 32 KiB)
              "known group secp256r1 and unknown groups from FFDHE range, key_share of size 256",
              "known group secp256r1 and unknown groups from FFDHE range, key_share of size 128",
              "only unknown key_share from EC range, key_share of size 256 + secp256r1 in supported_groups",
              "only unknown key_share from FFDHE range, key_share of size 256 + secp256r1 in supported_groups",
              "only unknown key_share from FFDHE range, key_share of size 128 + secp256r1 in supported_groups",
              "only unknown supported_groups from EC range, key_share of size 256",
              "only unknown supported_groups from FFDHE range, key_share of size 256",
              "only unknown supported_groups from FFDHE range, key_share of size 128"):
        out += x(n, CLOSED)
    return out


def curves():
    out = e(*["secp521r1 - " + n for n in ("key share from other curve", "point at infinity", "point outside curve",
                                         "right 0-padded key_share", "right-truncated key_share", "x=0, y=0")])
    out += e(*["x448 - " + n for n in ("key share from other curve", "point at infinity", "right 0-padded key_share",
                                     "right-truncated key_share")])
    return out + e("sanity - secp521r1", "sanity - x448")  # (policy: no secp521r1, no x448)


RUNS = [
    # TLS 1.3
    ("test-tls13-conversation.py", []),
    ("test-tls13-version-negotiation.py", ["-n", "0", "-C", C12]  # (script: its TLS 1.2 default is CBC)
     + x("fallback from TLS 1.8 to 1.1", "protocol_version")  # (policy: no TLS 1.1)
     + x("SSL 2.0 ClientHello with TLS 1.3 version and TLS 1.3 only ciphersuites", CLOSED)),  # (policy: not a TLS record)
    ("test-tls13-legacy-version.py", x("version (3, 0)", 'received "handshake_failure"')),  # (openssl: SSL 3.0 has no protocol_version)
    ("test-tls13-ccs.py", []),
    ("test-tls13-connection-abort.py", e("After NewSessionTicket")),  # (policy: no tickets)
    ("test-tls13-empty-alert.py", []),
    ("test-tls13-finished.py", ["-n", "0"] + finished_over_64()),
    ("test-tls13-finished-plaintext.py", []),
    ("test-tls13-hrr.py", []),
    ("test-tls13-invalid-ciphers.py", []),
    ("test-tls13-keyshare-omitted.py", []),
    ("test-tls13-keyupdate.py", []),
    # (openssl: an early CCS with record version 0x0300 is a decode_error once the ServerHello is out)
    ("test-tls13-multiple-ccs-messages.py", x("sanity with one CCS message", CLOSED) + x("second CCS before client finished", CLOSED)
     + x("multiple CCS Messages in one TCP packet", 'received "decode_error"')
     + x("CH and multiple CCS Messages in one TCP packet", 'received "decode_error"')
     + x("multiple CCS Messages in one TLS record", 'received "decode_error"')),
    ("test-tls13-nociphers.py", []),
    ("test-tls13-record-layer-limits.py", record_limits()),
    ("test-tls13-record-padding.py", []),
    ("test-tls13-serverhello-random.py", e("TLS 1.3 with ffdhe2048", "TLS 1.3 with ffdhe3072", "TLS 1.3 with secp521r1",
                                           "TLS 1.3 with x448")),  # (policy: groups)
    ("test-tls13-shuffled-extentions.py", shuffled()),
    ("test-tls13-symetric-ciphers.py", ["-n", "0"] + no_ccm()),
    ("test-tls13-unencrypted-alert.py", []),
    ("test-tls13-unrecognised-groups.py", unrecognised_groups()),
    # (policy: a record without data counts against the quiet budget, padded or not)
    ("test-tls13-zero-length-data.py", x("zero-length app data with large padding", CLOSED)),
    ("test-tls13-ecdhe-curves.py", curves()),
    ("test-tls13-crfg-curves.py", e("all zero x448 key share", "too big x448 key share", "too small x448 key share",
                                    'x448 key share of "1"', "sanity x448 with compression ansiX962_compressed_char2",
                                    "sanity x448 with compression ansiX962_compressed_prime",
                                    "sanity x448 with compression uncompressed", "empty x448 key share")
     + x("empty x25519 key share", 'received "decode_error"')),  # (openssl: an empty key_exchange is a decode error)
    # (script: that probe's TLS 1.2 suites are CBC only)
    ("test-tls13-0rtt-garbage.py", x("handshake with invalid 0-RTT and unknown version (downgrade to TLS 1.2)", "handshake_failure")),
    ("test-tls13-count-tickets.py", ["-t", "0"]),
    ("test-tls13-mlkem.py", ["--kems", "x25519mlkem768"]),  # (policy: the one hybrid)
    ("test-tls13-signature-algorithms.py", ["-n", "0"] + e("32715 invalid schemes", "23752 invalid schemes",  # (policy: over 32 KiB)
                                                          "duplicated 23752 non-rsa schemes", "duplicated 32715 non-rsa schemes",
                                                          "tolerance 23752 methods", "tolerance 32715 methods",
                                                          "tolerance 32715 methods with sig_alg_cert")),
    # (script: OpenSSL ignores obsolete curves beside valid ones, as --relaxed allows)
    ("test-tls13-obsolete-curves.py", ["--relaxed", "-a", "handshake_failure"]
     + e("secp521r1 in supported_groups and key_share", "x448 in supported_groups and key_share")),
    ("test-tls13-pkcs-signature.py", []),
    ("test-tls13-no-unknown-groups.py", []),
    # (script: OpenSSL sends supported_groups in EncryptedExtensions)
    ("test-tls13-large-number-of-extensions.py", ["--supgroup", "-n", "0"] + random_extensions()),
    ("test-tls13-dhe-shared-secret-padding.py", ["-n", "0"] + e("TLS 1.3 with secp521r1", "TLS 1.3 with x448",
                                                               "TLS 1.3 with ffdhe2048", "TLS 1.3 with ffdhe3072")),
    ("test-tls13-rsa-signatures.py", []),
    ("test-tls13-zero-content-type.py", []),
    # TLS 1.2
    ("test-conversation.py", ["-C", C12, "-M"]),
    # (script: its TLS 1.2 suites are CBC only)
    ("test-fallback-scsv.py", ["--tls-1.3", "-d", "--min-support", "1.2"] + x("record SSL3.4 hello SSL3.4", "handshake_failure")
     + x("record TLSv1.2 hello TLSv1.2", "handshake_failure") + x("sanity - SSL3.4 version negotiation", "handshake_failure")
     + x("sanity", "handshake_failure")),
    ("test-renegotiation-disabled.py", ["-C", C12]),
    ("test-invalid-compression-methods.py", ["-C", C12]),
    ("test-record-layer-fragmentation.py", ["-C", C12] + e("big, needs fragmentation: max fragment - 32768B extension",
                                                         "maximum size: max fragment - 65385B extension")),  # (policy: over 32 KiB)
    ("test-truncating-of-client-hello.py", ["-C", C12]
     + x('huge pad: 131584 of "0" byte padding', 'received "illegal_parameter"')  # (openssl: over its 131,396-byte ClientHello)
     + x('max pad: 16777021 of "0" byte padding', 'received "illegal_parameter"')
     + x('big pad: 65536 of "0" byte padding', CLOSED)),  # (policy: over 32 KiB)
    ("test-invalid-client-hello.py", ["-n", "0"] + x("sanity", "handshake_failure") + x("sanity w/ext", "handshake_failure")),  # (script: CBC)
    ("test-zero-length-data.py", ["-C", C12]),
    ("test-no-mlkem-in-old-tls.py", ["-C", C12]),
    ("test-ecdhe-rsa-key-exchange-with-bad-messages.py", ["-C", C12]),
    ("test-chacha20.py", ["--extra-exts"]),
    ("test-aes-gcm-nonces.py", ["-d"] + x("sanity", "handshake_failure")),  # (script: its sanity is CBC; -C would send AES-256 empty)
    ("test-version-numbers.py", ["-C", C12]),
    ("test-invalid-content-type.py", ["-C", C12]),
    ("test-fuzzed-ciphertext.py", ["-C", C12]),
    ("test-ccs.py", ["-C", C12]),
]


def main():
    fuzzer, port = sys.argv[1], sys.argv[2]
    logs = os.path.join(os.path.dirname(os.path.abspath(fuzzer)), "tlsfuzzer_logs")
    os.makedirs(logs, exist_ok=True)
    failed = 0
    for script, args in RUNS:
        t0 = time.time()
        log = os.path.join(logs, script.replace(".py", ".log"))
        with open(log, "w") as f:
            try:
                code = subprocess.run([sys.executable, os.path.join("scripts", script), "-h", "localhost", "-p", port] + args,
                                      cwd=fuzzer, env=dict(os.environ, PYTHONPATH="."), stdout=f, stderr=subprocess.STDOUT,
                                      timeout=1800).returncode
            except subprocess.TimeoutExpired:
                code = "timeout"
        text = open(log, errors="replace").read()
        counts = " ".join("%s %s" % m for m in re.findall(r"^(PASS|XFAIL|FAIL|XPASS|SKIP): (\d+)", text, re.M))
        if code == 0:
            print("ok   tlsfuzzer %s: %s (%.0f s)" % (script, counts, time.time() - t0), flush=True)
        else:
            failed += 1
            print("FAIL tlsfuzzer %s, exit %s: %s (see %s)" % (script, code, counts, log), flush=True)
    print("%d of %d tlsfuzzer scripts passed" % (len(RUNS) - failed, len(RUNS)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
