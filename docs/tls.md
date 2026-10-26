# tls: TLS through OpenSSL

TLS for the other libraries (`http`'s `https://`, later `pg` and `redis`), with all of the cryptography and the protocol done by OpenSSL 3.5, the long-term-support line. This package writes no TLS and no cryptography of its own. It configures OpenSSL, drives it over memory buffers, and checks its results. The decision and the rules cited below (TL, TC, TB, TS, TA, TG) are in `docs/research/tls_with_openssl.md`; what was measured before any code was written is in `docs/spikes.md`, "TLS through OpenSSL (T0)". Package rules and the shared contracts are in `docs/design.md`.

**Status: T1 done**, the client: verification, the sans-I/O state machine, a blocking stream, and the checks below. Next is H8, `https://` in `http.Client`.

> **This code was written by an AI and has not been reviewed by a TLS expert.** The tests compare it with independent implementations and plant bugs to show that they catch them (see "Checks"), but they can only find what someone thought to test. The external review (gate TG15) is still to come. Until then, treat it as unreviewed.

## Scope
**In scope (T1):**
- a TLS 1.2 and 1.3 client that verifies the server's certificate chain against system roots or a CA file, and its name or IP address;
- ALPN, offered by the client and checked on return;
- `TlsClient`, a sans-I/O state machine (contract 1) for any driver; `TlsStream`, a blocking stream over `net.TcpStream` with deadlines;
- errors that name their reason (`Category`), with OpenSSL's verify code and text.

**Out of scope, by design:**
- **Any way to weaken verification.** There is no "insecure" flag, no verify callback, no accept-anyway, no partial chains, no subject-CN fallback. A self-signed server is trusted by listing its certificate as a CA file.
- **Revocation (OCSP, CRLs, AIA fetching)** (TC14). This departs from NIST SP 800-52r2 on purpose, as Go, Python and OpenSSL's defaults do: online revocation checks are slow and fail open in practice, Let's Encrypt turned its OCSP responders off in 2025, and certificate lifetimes are shrinking to 47 days by 2029. A revoked certificate is accepted until it expires (badssl.com's `revoked` host is, see "Checks"). A CRL-file mode for private PKIs may come later, failing hard.
- **Session resumption, 0-RTT, PSK, client certificates, kTLS, ECH, renegotiation.** Each is off, and the connection gate refuses a resumed session. Client certificates come with R8 (Redis).
- **A server.** That is T2, after the review (TR).

## Use
```mojo
from tls import ClientConfig, Trust
from tls.stream import TlsStream

var ctx = ClientConfig().build()      # system roots; once, then shared
var ctx2 = ClientConfig(trust=Trust.ca_file("ca.pem"), alpn=["http/1.1"]).build()
var s = TlsStream.connect("example.com", 443, ctx, Duration.from_secs(10))
s.write_all(request)
var n = s.read(buf)                   # 0: the server's close_notify
s^.close()                            # our close_notify, then the socket
```
`examples/tls/tls_get.mojo` fetches a page this way. `TlsStream.connect_deadline(host, port, ctx, deadline, server_name)` connects to `host` but expects a certificate for `server_name`; `TlsStream.handshake(tcp, ...)` runs over a connected `TcpStream`. A `ClientContext` is read-only once built and is shared by copying it. Use it from one thread at a time (TL8: not tested with ThreadSanitizer yet).

## Policy
Every setting is made explicitly on each context and then read back, and `build()` fails if any read-back differs. A configuration that something else in the process loaded first still reaches a new OpenSSL context (measured in T0), and the tests run under a hostile one:
- **Versions:** TLS 1.2 and 1.3.
- **Security level 2:** RSA and DH keys of 2048 bits or more, ECC of 224 or more, no SHA-1 signatures.
- **Ciphers:** TLS 1.3's three suites; for TLS 1.2, Mozilla's "intermediate" six: ECDHE with AES-GCM or ChaCha20-Poly1305. No RSA key exchange, CBC, 3DES, RC4 or NULL.
- **Groups:** `X25519MLKEM768` (the post-quantum hybrid, preferred), X25519, P-256, P-384.
- **Signature algorithms:** ECDSA, EdDSA, RSA-PSS and RSA PKCS#1 with SHA-2.
- **Options:** no compression, no renegotiation, middlebox compatibility; the session cache off. `SSL_OP_IGNORE_UNEXPECTED_EOF` is never set.
- **Verification:** `SSL_VERIFY_PEER`, no callback, strict X.509 (`X509_V_FLAG_X509_STRICT`), trusted-first chain building, partial chains off. Host checks never fall back to the subject's CN and refuse partial wildcards (`a*.example.com`); a wildcard covers one label.

**Trust** (TC1, TC2) is either the system's roots or a CA file you give, never both. System roots come from the first of these that is set, with no fallback after it: `SSL_CERT_FILE` (it must load); `SSL_CERT_DIR` (a hashed directory, which must exist and hold files); the loaded OpenSSL's default file (conda-forge's `ca-certificates` bundle, in `$PREFIX/ssl/cert.pem`); the distribution bundles Go looks for. A store with no CA in it is refused when the context is built.

## Names
`tls.target.Target` decides once what the certificate must match (TC4, TC5, TC7):
- **An IP address**, by `net.addr`'s strict parser: matched as 4 or 16 bytes against the certificate's IP entries. No SNI is sent (RFC 6066).
- **A DNS name:** letters, digits, `-` and `_`, in labels of 1 to 63 bytes that neither start nor end with `-`, 253 bytes at most. It is lower-cased and loses one trailing dot. It is sent as SNI and matched against DNS entries only. Internationalized names come as A-labels (`xn--...`).
- **Refused before any I/O:** an empty name, empty labels, `*`, spaces, NUL and other bytes outside the set, and names that look numeric but are not strict addresses (`127.1`, `0x7f.0.0.1`, `1.2.3.4.`): a resolver might read them as addresses while the certificate check reads them as names.

The name is given to OpenSSL with an explicit length: an empty name would turn its check off, which T0 showed.

## When a connection counts
After `SSL_do_handshake` returns 1, the client checks six things itself (TC9) before it reports `ESTABLISHED`, encrypts any data or delivers any (TC10). Each is a second layer over OpenSSL's own check, and each is tested on its own through a fault seam:
1. the server presented a certificate;
2. OpenSSL's verify result is `X509_V_OK`;
3. an independent `X509_check_host` (or `X509_check_ip`) on that certificate passes, and for a name, OpenSSL recorded the name it matched (`SSL_get0_peername`);
4. the version is TLS 1.2 or later;
5. no session was resumed;
6. the server's ALPN choice is one that was offered, or none.

Any failure frees the OpenSSL connection, and the error stays: every later call raises it again (TB8). The client's Finished message is dropped, so the server never sees a completed handshake. When OpenSSL itself refuses the certificate, `TlsStream` sends its alert (`unknown_ca`, `certificate_expired`, `bad_certificate`, ...) if the socket takes it at once, so the server's log says why; the tests check that the server saw it.

## Endings
- **The server's close_notify** is a CLOSED event (`read` returns 0) and is answered with ours. Input after it is ignored.
- **A TCP end without close_notify** raises `TRUNCATED` (`UnexpectedEof`), never a clean end, after the data before it is delivered (TB12). The data may have been cut short; only the protocol above can tell (an HTTP `Content-Length` that is complete). Many HTTPS servers end this way after `Connection: close`: H8 decides per RFC 9112 §9.8.
- **`close()`** sends close_notify once and does not wait for the server's (TB13). Nothing is sent during a handshake.

## Bounds
OpenSSL's memory buffers never refuse a write, so the state machine bounds them itself (TB17): at most 32 KiB of unread ciphertext and undelivered plaintext together (`feed_capacity()`, more than one record of any version; a driver that feeds without draining gets room 0), 256 KiB from the server before the handshake ends (a backstop above OpenSSL's 100 KiB limit on certificate chains), and 256 KiB of ciphertext waiting to be sent before `write` takes no more. Plaintext buffers are wiped with `OPENSSL_cleanse` when released (TB18).

## Errors
`TlsError` holds an `IoError` (for code that checks kinds, and `is_deadline()`), a `Category`, OpenSSL's verify code and a detail: OpenSSL's text, and the path or name concerned. `is_authentication()` is true for the certificate categories.

| Category | Means | `IoError` kind |
|---|---|---|
| `UNTRUSTED` | the chain does not lead to a trusted CA, or a CA in it is invalid | `PermissionDenied` |
| `EXPIRED` | a certificate has expired or is not yet valid | `PermissionDenied` |
| `HOST_MISMATCH`, `IP_MISMATCH` | the certificate is for another name or address | `PermissionDenied` |
| `NO_PEER_CERT`, `WEAK` | no certificate; a key or signature below security level 2 | `PermissionDenied` |
| `PROTOCOL` | the handshake or a record failed: version, ciphers, a bad message, an alert | `InvalidData` |
| `ALPN` | the server chose a protocol nobody offered | `InvalidData` |
| `TRUNCATED` | the connection ended without close_notify | `UnexpectedEof` |
| `NO_TRUST_STORE` | no CA certificate could be loaded | `NotFound`, `InvalidData` |
| `INPUT`, `RESOURCE`, `LIBRARY`, `CLOSED` | a bad name or configuration; a memory bound; OpenSSL missing or older than 3.5; use after close | various |
| `NONE` | the transport's own error (a reset, a deadline) | the socket's |

## How OpenSSL is reached
- **One module calls C** (TL7): `tls.ffi`. It opens `libssl.so.3` by absolute path from the directory the Mojo runtime was loaded from, which is the program's own environment, through `std.ffi.OwnedDLHandle`. Then it takes the address of each function it uses, once. It refuses an OpenSSL older than 3.5 or from another major version (TL3), and calls `OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG)` first, so no `openssl.cnf` is read (TL4). Contexts live in a private library context with only the default provider.
- **The functions bound are an allowlist** (TL5), in `tools/check_tls.py`. Each one's ELF version node is `OPENSSL_3.5.0` or older (TL2), so the package runs on any later 3.x. APIs with a CVE history, and the features listed above, are refused by name anywhere in `src/tls`.
- **The macros' command codes** (`SSL_ctrl` and friends) come from the headers (`tools/gen_tls_consts.py`, `pixi run gen-tls`) and are checked against them in CI (TB14).
- **No sockets in OpenSSL.** It sees only memory BIOs, and `net` does all of the I/O (T0 traced it). libssl and libcrypto make their own memory, randomness and file-read syscalls: the one exception to "no libc on the I/O path" (`docs/design.md`).
- **Errors** (TB6): the thread's error queue is cleared before each OpenSSL call that can fail, and `SSL_get_error` is called right after it. Every `SSL_ERROR_*` value is handled, and an unknown one fails the connection. OpenSSL 3.5.9 clears the queue itself on entering `SSL_do_handshake` and `SSL_read_ex` (measured), so the clears are there for the API's contract, and a test without them still passes on 3.5.
- **Packaging:** the conda package depends on `openssl >=3.5,<4` and `ca-certificates`; the repository's own environment is pinned to `openssl 3.5.*` (TA1).

## Checks
What runs, in `pixi run ci` on x86_64 and aarch64 unless said. Gates are the research's TG numbers. Planted bugs were each put in a scratch copy of `src/` and had to turn the named tests red; all did, except the one noted.

- **TG1, certificates and names** (`tests/tls/test_client.mojo`, 39 tests): a throwaway PKI made by the `openssl` command (`tests/tls/tls_pki.py`) and a server in Python's `ssl` (`tls_peer.py`) in a child process.
  - Accepted: DNS names, IPv4 and IPv6 addresses (without SNI, as the server sees), TLS 1.2 with ECDSA and RSA, an intermediate CA, a one-label wildcard, ALPN.
  - Refused, each with its category and OpenSSL's verify code: a wrong host (62), a CN-only certificate, wildcards across labels, partial wildcards, a wrong IP and an IP spelled as a DNS name (64), expired (10) and not yet valid (9), self-signed (18), an unrelated CA (20), a missing intermediate (20), an intermediate that is no CA, a trusted leaf that is no CA (no partial chains), a client-only certificate (26), RSA 1024 (66), SHA-1 (68), TLS 1.1, RSA key exchange with CBC, and a server that does not speak TLS.
  - Also: deadlines, truncation, close_notify both ways, 5 MiB each way, any receive size from 1 byte up giving the same data, and the feed room bounding a driver that never drains.
  - Planted bugs: no host checks, no IP checks, SNI sent for addresses, `SSL_VERIFY_NONE` with the verify result ignored, partial chains on, security level 0, a feed room that ignores undelivered data. All caught.
- **TG4, post-handshake messages** (`test_transcripts.mojo`, against `openssl s_server`): KeyUpdate with and without a request (the client answers the request, as s_server's trace shows); a TLS 1.2 HelloRequest, refused without a second ClientHello; plaintext injected into the stream.
- **TG5, damage** (`test_mutations.mojo`): a seeded proxy (`tls_mitm.py`) flips, drops, duplicates, inserts or replaces bytes, or cuts the connection, in the handshake or the data. The oracle: never a clean end with different data, never bytes the server did not send, never a hang. 80 seeds in CI; 3,000 seeds passed once, after a harness bug was fixed (a peer whose unread output filled its pipe). The truncation-as-clean-end bug is caught by seed 5.
- **TG6, faults** (`test_tls_faults.mojo`, built with `-D MOJO_NET_FAULTS=1`, seams in `tls.ffi`): OpenSSL too old, context and connection creation failing, a setting that does not read back, every `SSL_get_error` code from the handshake, reads and writes, and each of the six gate checks failing alone while OpenSSL passed.
  - Planted bug not detectable: removing the error-queue clears (OpenSSL 3.5 clears it itself, see above). `test_stale_openssl_errors_are_ignored` still shows that a stale error neither fails a connection nor leaks into an error's text.
- **TG7, sanitizers** (`pixi run tls-asan`): the client, codec, fault, transcript and damage tests built with AddressSanitizer and run with LeakSanitizer. Only the embedded Python interpreter and the test-only fault plan are suppressed. It found a real leak: an `SSL_CTX` was lost when configuration failed, because Mojo 1.2 skips `__deinit__` when `__init__` raises before a field's last assignment (`CLAUDE.md`). Fixed. A planted leak (a connection never freed) is caught. ASan cannot see misuse inside libssl itself (T0).
- **TG10, defaults** (`test_config.mojo`, `test_hostile_config.mojo`): the trust order and its environment variables, empty and missing stores, ALPN encoding, and the whole policy under a hostile `openssl.cnf` (TLS 1.0, security level 0, the legacy provider) loaded into the process first.
- **Static** (`pixi run tls-check`): FFI in one module, the binding allowlist, forbidden names, symbol versions, constants against the headers. Its self-test plants a violation of each. Also `import-check`: only `tls.stream` and `tls.target` import `net`.
- **TG14, freshness** (`pixi run tls-freshness`, daily in `.github/workflows/freshness.yml`): fails when conda-forge has had a newer `openssl` 3.5 or `ca-certificates` than `pixi.lock` for more than two days. Its first run found `ca-certificates` three days stale.
- **By hand, 2026-10-26: badssl.com and real APIs.**
  - Refused: expired, wrong host, self-signed, untrusted root, incomplete chain, SHA-1 intermediate, RSA 1024 behind an untrusted root, Superfish and the other bad roots, RC4, 3DES, NULL, DHE of 480 to 1024 bits, static RSA, CBC, TLS 1.0 and 1.1.
  - Accepted: badssl.com's good hosts; `revoked` (no revocation checks, by design); the APIs of OpenAI, Anthropic, Hugging Face, GitHub and Google, over TLS 1.3 with X25519MLKEM768.
  - Some badssl.com hosts reset connections intermittently, for `openssl s_client` too.

**Not verified yet:**
- the x509-limbo corpus (TG2) and BetterTLS (TG3), which test chain building and name constraints in depth;
- an ASan-built OpenSSL or Valgrind (TG8), and TLS-Anvil (TG11): both belong to TR;
- ThreadSanitizer, for a context shared across threads (TL8);
- the 256 KiB handshake bound, which OpenSSL's own limits reach first;
- ASan on aarch64, beyond what CI shows;
- the external review (TG15).

## Updates
OpenSSL 3.5 is supported until 2030-04-08. On a High or Critical OpenSSL advisory: `pixi update openssl`, the full `pixi run ci` on both architectures, and a release within 48 hours of the conda-forge build (TA4). Every advisory is triaged against what this package never calls (TA5), and logged here with whether it applies. The owner must be named before the project is published (TA3).

**Advisory log:** none since T1.

## Milestones
- **T0: the spike.** Done (`docs/spikes.md`).
- **T1: the client.** Done.
  - `tls.ffi`, `tls.consts` (generated), `tls.error`, `tls.target`, `tls.config`, `tls.client` (`TlsClient`), `tls.stream` (`TlsStream`).
  - Tests: 83 in 8 files, plus the ASan runs.
  - Tools: `tools/check_tls.py`, `tools/check_tls_asan.sh`, `tools/check_freshness.py`, `tools/gen_tls_consts.py`.
- **H8: `https://` in `http.Client`** (in `http`): the pool keyed by TLS settings, ALPN `http/1.1`, cross-host redirects verified again, truncation handled per RFC 9112.
- **P9, R8: TLS for `pg` and `redis`.** Parked, by the user's priorities.
- **TR: review.** Two independent internal reviews against the rules, each finding with a regression test (`tests/tls/test_tls_regressions*.mojo`); TG2, TG8 and TG11; the external review booked.
- **T2: the server**, then **S7: the TLS listener** in `server`.
