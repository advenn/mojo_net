#!/bin/bash
# T0: the TLS-through-OpenSSL spike (docs/spikes.md, "TLS through OpenSSL").
# Runs every measurement and fails if a recorded fact no longer holds, so a
# run on another host or architecture checks the facts, not just prints them.
#   pixi run spike-tls
set -uo pipefail
cd "$(dirname "$0")/../.."
d=build/tls_spike
fail=0
expect() {  # expect <file> <fixed string> <what it shows>
    if grep -qF -- "$2" "$1"; then echo "  ok   $3"; else echo "  FAIL $3: no '$2' in $1"; fail=1; fi
}

bash spikes/tls/make_certs.sh "$d" >/dev/null

echo "== in-process pair over memory BIOs (mojo run)"
mojo run -I spikes/tls spikes/tls/pair.mojo "$d" > "$d/pair.txt" 2> "$d/pair.err" || { tail -5 "$d/pair.err"; fail=1; }
expect "$d/pair.txt" "version: OpenSSL 3.5." "the pinned 3.5 line is loaded"
expect "$d/pair.txt" "libssl from: $CONDA_PREFIX/lib/libssl.so.3" "libssl comes from the environment, by absolute path"
expect "$d/pair.txt" "handshake ok: True | verify result: 0 | TLSv1.3 TLS_AES_256_GCM_SHA384 X25519MLKEM768 peer_cert=True peername='localhost'" "good host: TLS 1.3 with the hybrid post-quantum group"
expect "$d/pair.txt" "truncation reported as SSL_ERROR_SSL: True" "a cut without close_notify is an error"
expect "$d/pair.txt" "unexpected eof while reading" "... reported as unexpected EOF"
expect "$d/pair.txt" "client read with only tickets queued: rc 0 error 2" "TLS 1.3 tickets alone make a read return WANT_READ"
expect "$d/pair.txt" "handshake ok: False | verify result: 62 |" "a wrong host fails (62)"
expect "$d/pair.txt" "handshake ok: False | verify result: 20 |" "an unrelated CA fails (20)"
expect "$d/pair.txt" "handshake ok: False | verify result: 64 |" "a wrong IP fails (64)"
expect "$d/pair.txt" "peer_cert=True peername=''" "an IP match leaves SSL_get0_peername empty"
grep -A2 "empty host (silent)" "$d/pair.txt" | grep -qF "handshake ok: True | verify result: 0" \
    && echo "  ok   hazard still present: an empty host name disables the check" \
    || { echo "  FAIL the empty-host hazard changed"; fail=1; }
grep -A2 "VERIFY_NONE, unrelated CA" "$d/pair.txt" | grep -qF "handshake ok: True | verify result: 20" \
    && echo "  ok   hazard still present: VERIFY_NONE completes despite verify result 20" \
    || { echo "  FAIL the VERIFY_NONE hazard changed"; fail=1; }

echo "== a hostile OPENSSL_CONF"
OPENSSL_CONF="$PWD/spikes/tls/hostile.cnf" mojo run -I spikes/tls spikes/tls/pair.mojo "$d" > "$d/conf_no.txt" 2>/dev/null || fail=1
OPENSSL_CONF="$PWD/spikes/tls/hostile.cnf" mojo run -I spikes/tls spikes/tls/pair.mojo "$d" load-config > "$d/conf_yes.txt" 2>/dev/null || fail=1
expect "$d/conf_no.txt" "legacy provider in the default context: 0" "NO_LOAD_CONFIG: the file loads no provider"
expect "$d/conf_no.txt" "min proto before setting it: 0 | security level before: 2" "NO_LOAD_CONFIG: the file changes no TLS setting"
expect "$d/conf_yes.txt" "legacy provider in the private context: 0" "loaded config: a private library context still has no legacy provider"
expect "$d/conf_yes.txt" "min proto before setting it: 769 | security level before: 0" "hazard: a config loaded first still reaches SSL_CTX_new_ex (TLS 1.0, level 0)"

echo "== the client over net.TcpStream against Python's ssl"
timeout 120 mojo run -I src -I spikes/tls spikes/tls/peer.mojo "$d" > "$d/peer.txt" 2> "$d/peer.err" || { tail -5 "$d/peer.err"; fail=1; }
expect "$d/peer.txt" "reply: 'echo:ping from TLSv1.3' | ended by close_notify: True" "TLS 1.3 to Python's ssl, ended by close_notify"
expect "$d/peer.txt" "peer exit code 0 | peer: clean TLS close" "the peer saw our close_notify"

echo "== version nodes of the bound symbols"
python spikes/tls/symver.py "$CONDA_PREFIX/lib" spikes/tls/pair.mojo spikes/tls/ffi.mojo spikes/tls/peer.mojo > "$d/symver.txt" || fail=1
expect "$d/symver.txt" " 0 outside OPENSSL_3.5.0 or older" "every bound symbol is in OPENSSL_3.5.0 or older"

echo "== built binary: syscalls and AddressSanitizer"
mojo build -I spikes/tls spikes/tls/pair.mojo -o "$d/pair" 2>/dev/null || fail=1
if command -v strace >/dev/null; then STRACE=strace; else STRACE="pixi exec --spec strace -- strace"; fi
if $STRACE -f -o "$d/strace.txt" "$d/pair" "$d" > "$d/pair_built.txt" 2>&1; then
    n=$(grep -cE "^[0-9]+ +(socket|connect|accept4?|bind|listen|sendto|recvfrom|sendmsg|recvmsg|sendmmsg|recvmmsg|getsockopt|setsockopt|shutdown|socketpair|epoll_[a-z_]+)\(" "$d/strace.txt")
    [ "$n" = 0 ] && echo "  ok   libssl makes no socket syscall (memory BIOs)" || { echo "  FAIL $n socket syscalls"; fail=1; }
    grep -qF "openssl.cnf" "$d/strace.txt" && { echo "  FAIL openssl.cnf was opened"; fail=1; } || echo "  ok   no config file is opened"
else
    echo "  skip strace unavailable"
fi
if mojo build --sanitize address -I spikes/tls spikes/tls/pair.mojo -o "$d/pair_asan" 2>/dev/null; then
    ASAN_OPTIONS=detect_leaks=1 "$d/pair_asan" "$d" > "$d/asan.txt" 2>&1 \
        && echo "  ok   AddressSanitizer and LeakSanitizer are clean" || { grep -E "SUMMARY|ERROR" "$d/asan.txt"; fail=1; }
    expect "$d/asan.txt" "libssl from: $CONDA_PREFIX/lib/libssl.so.3" "under ASan too, the environment's libssl"
else
    echo "  skip --sanitize address does not build here"
fi
[ $fail = 0 ] && echo "---- T0: every fact holds" || echo "---- T0: FAILED"
exit $fail
