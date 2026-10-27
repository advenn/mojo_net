# tls: TLS through OpenSSL

TLS for the other libraries (`http`'s `https://`, later `pg` and `redis`), with all of the cryptography and the protocol done by OpenSSL 3.5, the long-term-support line. This package writes no TLS and no cryptography of its own. It configures OpenSSL, drives it over memory buffers, and checks its results. The decision and the rules cited below (TL, TC, TB, TS, TA, TG) are in `docs/research/tls_with_openssl.md`; what was measured before any code was written is in `docs/spikes.md`, "TLS through OpenSSL (T0)". Package rules and the shared contracts are in `docs/design.md`.

**Status: T1 and T2 done.** The client: verification, the sans-I/O state machine, a blocking stream, and the checks below; its first user, `https://` in `http.Client`, is done too (H8, `docs/http.md`). The internal review of the client (TR) is done, and its findings are fixed (see "Review"). The server (T2): a server context and the server side of a connection, as a sans-I/O state machine for an event loop; its first user is HTTPS in `server` (S7, `docs/server.md`, "TLS"). The internal review of the server (TR2) is done too, and its findings are fixed. The external review is still to come.

> **This code was written by an AI and has not been reviewed by a TLS expert.** Two internal reviews, also by AI, found no way past verification, and the tests compare it with independent implementations and plant bugs to show that they catch them (see "Checks"). But they can only find what someone thought to test. The external review (gate TG15) is still to come. Until then, treat it as unreviewed.

## Scope
**In scope:**
- (T1) a TLS 1.2 and 1.3 client that verifies the server's certificate chain against system roots or a CA file, and its name or IP address;
- ALPN, offered by the client and checked on return, and chosen by the server;
- `TlsClient`, a sans-I/O state machine (contract 1) for any driver; `TlsStream`, a blocking stream over `net.TcpStream` with deadlines;
- (T2) a TLS 1.2 and 1.3 server: one certificate chain and key per context, the names it serves, ALPN, and `TlsServer`, the server side as a sans-I/O state machine;
- errors that name their reason (`Category`), with OpenSSL's verify code and text.

**Out of scope, by design:**
- **Any way to weaken verification.** There is no "insecure" flag, no verify callback, no accept-anyway, no partial chains, no subject-CN fallback. A self-signed server is trusted by listing its certificate as a CA file.
- **Revocation (OCSP, CRLs, AIA fetching)** (TC14). This departs from NIST SP 800-52r2 on purpose, as Go, Python and OpenSSL's defaults do: online revocation checks are slow and fail open in practice, Let's Encrypt turned its OCSP responders off in 2025, and certificate lifetimes are shrinking to 47 days by 2029. A revoked certificate is accepted until it expires (badssl.com's `revoked` host is, see "Checks"). A CRL-file mode for private PKIs may come later, failing hard.
- **Session resumption, 0-RTT, PSK, client certificates, kTLS, ECH, renegotiation.** Each is off on both sides, and both gates refuse a resumed session. Client certificates come with R8 (Redis).
- **On the server:** session tickets, OCSP stapling, mutual TLS, in-process ACME, and switching contexts by SNI (TS14, TS6). A second chain of another key type (RSA beside ECDSA) is not offered yet: one chain per context. A blocking server stream is not offered either: the state machine is for an event loop, the HTTP server's (S7).

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

**Share contexts.** Each `build()` loads OpenSSL into a library context of its own, which holds 3 of the process's 1,024 thread-specific keys while it lives: a process can hold about 330 such contexts at once, and then every build fails, as does other code that needs a key (measured; see "Review", TR3). Copy one built context, or build the others with `build(sharing=ctx)`, which uses `ctx`'s OpenSSL and nothing else of it. `http.Client` and `llm.Client` take a built context (`tls_context`), and the HTTP server's reloads share the first context's.

## The server
```mojo
from tls import ServerConfig, TlsServer

var ctx = ServerConfig(
    certificate="fullchain.pem", key="privkey.pem",
    names=["example.com", "www.example.com"], alpn=["http/1.1"],
).build()                              # once per worker, then shared
var tls = TlsServer(ctx)               # per accepted connection
tls.feed(received); tls.poll_transmit(out); tls.next_event()  # as the client's
```
`TlsServer` is driven as `TlsClient` is, from the first byte the client sends, with the same events, latching, endings and bounds: both run on one engine (`tls.engine`), so a fix to one side is a fix to both.
- **Policy** (TS1, TS2, TS4, TS14): the client's, plus no session tickets (none issued and `SSL_OP_NO_TICKET`, together: the option alone makes TLS 1.3 tickets stateful, with a cache), no session cache, no early data, no client certificates, and exactly the chain configured (`SSL_MODE_NO_AUTO_CHAIN`). Each is read back. `tls13_only` raises the floor to TLS 1.3, Mozilla's modern profile.
- **Credentials** (TS3): the chain file holds the leaf first, then the intermediates; the key file an unencrypted PEM key. libssl reads both. `build()` refuses, naming why:
  - a key file other users can read: it must be the user's at mode 0600 or 0400, or root's at 0640 at most (PostgreSQL's rule);
  - an encrypted key, without prompting (libssl's default would ask on the terminal and wait);
  - a key that does not match the leaf, a leaf that has expired or is not valid yet, or one that does not cover every configured name;
  - a key below security level 2 (RSA 1024).

  Prefer an ECDSA P-256 leaf: it signs some 15 times faster than RSA 2048, which caps one core near 2,700 handshakes a second.
- **Names** (TS6): `names` lists the DNS names and IP addresses served (exact names; a wildcard certificate serves the names listed). A client that sends SNI must ask for one of the DNS names, or its connection fails when the handshake ends, before any data either way. A client connecting by address sends none and is served. The context is never switched mid-handshake (`SSL_set_SSL_CTX` is refused by `tls-check`).
- **ALPN** (TS5): the protocols spoken, in the server's order. A client that offers ALPN but none of them gets a fatal `no_application_protocol` alert (RFC 9325, against cross-protocol attacks); one that offers none is served. This is the package's one callback into Mojo, `tls.ffi.alpn_select`: it reads its arguments and nothing else.
- **Bounds:** a client may send at most 32 KiB before the handshake ends (TS8): a few times any real ClientHello, where OpenSSL alone would read 128 KiB. It is checked after each record, so OpenSSL reads at most one record more of an unending ClientHello; what a TLS 1.3 client sends behind its Finished (its first data) is not handshake and does not count. Once established, a client may send at most 4 KiB that carries no data (key updates, padding, its close_notify) over the whole connection, plus a byte per 4 KiB of data: each key update it asks the server to answer costs the server about 25 times what its bytes of data would (see "Review"). The other bounds are the engine's (see "Bounds").
- **Reloading** (TS12): build a new context from the files (`build(sharing=old)`, see "Use") and use it for new connections. Each connection keeps the context it began with, and a failed build leaves the old one serving. `expires_in()` and `renewal_due()` (less than a third of the leaf's lifetime left) are the expiry alarm.
- **The driver's part** (S7): admitting handshakes before making a `TlsServer` (TS7), one deadline per handshake (TS8), sending the alert after a failure and then closing (TS10), logging the category and never the detail at error level (TS11: a client's SNI is in it, cleaned to printable ASCII), and removing `SSLKEYLOGFILE` from workers' environments.

## Policy
Every setting is made explicitly on each context and then read back, and `build()` fails if any read-back differs. A configuration that something else in the process loaded first still reaches a new OpenSSL context (measured in T0), and the tests run under a hostile one:
- **Versions:** TLS 1.2 and 1.3.
- **Security level 2:** RSA and DH keys of 2048 bits or more, ECC of 224 or more, no SHA-1 signatures.
- **Ciphers:** TLS 1.3's three suites; for TLS 1.2, Mozilla's "intermediate" six: ECDHE with AES-GCM or ChaCha20-Poly1305. No RSA key exchange, CBC, 3DES, RC4 or NULL.
- **Groups:** `X25519MLKEM768` (the post-quantum hybrid, preferred), X25519, P-256, P-384.
- **Signature algorithms:** ECDSA, EdDSA, RSA-PSS and RSA PKCS#1 with SHA-2.
- **Options:** no compression, no certificate compression either way (RFC 8879; this OpenSSL has no compressor, but one built with one would turn it on unasked), no renegotiation, middlebox compatibility; the session cache off. `SSL_OP_IGNORE_UNEXPECTED_EOF` is never set.
- **Verification:** `SSL_VERIFY_PEER`, no callback, strict X.509 (`X509_V_FLAG_X509_STRICT`), trusted-first chain building, partial chains off. Host checks never fall back to the subject's CN and refuse partial wildcards (`a*.example.com`); a wildcard covers one label, and never a name that a CA in the chain excludes (the gate's check, below).

**Trust** (TC1, TC2) is either the system's roots (`Trust.system()`) or a CA file you give (`Trust.ca_file(path)`), never both. An empty path is refused when the context is built: it never means the system's roots, so a variable left unset cannot widen the trust to every public CA. System roots come from the first of these that is set, with no fallback after it: `SSL_CERT_FILE` (it must load); `SSL_CERT_DIR` (a hashed directory, which must exist and hold files); the loaded OpenSSL's default file (conda-forge's `ca-certificates` bundle, in `$PREFIX/ssl/cert.pem`); the distribution bundles Go looks for. A store with no CA certificate in it is refused when the context is built (a CRL in the file is no anchor).

**Trust marks.** A plain certificate in the store is an anchor only as the root of a chain (partial chains are off): an intermediate alone in a CA file trusts nothing. A `TRUSTED CERTIFICATE` block (OpenSSL's format with trust marks, as `openssl x509 -trustout` or `trust extract --format=openssl-bundle` write it) is different: OpenSSL honours its marks, so one marked for serverAuth is an anchor even if it is an intermediate, and one marked rejected is refused. That is the file's author's statement, and the client follows it (`test_tls_review3_regressions.mojo` pins both).

## Names
`tls.target.Target` decides once what the certificate must match (TC4, TC5, TC7):
- **An IP address**, by `net.addr`'s strict parser: matched as 4 or 16 bytes against the certificate's IP entries. No SNI is sent (RFC 6066). An IPv4-mapped address (`::ffff:a.b.c.d`) is the IPv4 address it reaches, 4 bytes, as Go's `net.IP.Equal` has it: a dual-stack socket sends to `a.b.c.d`.
- **A DNS name:** letters, digits, `-` and `_`, in labels of 1 to 63 bytes that neither start nor end with `-`, 253 bytes at most. It is lower-cased and loses one trailing dot. It is sent as SNI and matched against DNS entries only. Internationalized names come as A-labels (`xn--...`).
- **Refused before any I/O:** an empty name, empty labels, `*`, spaces, NUL and other bytes outside the set, and names that look numeric but are not strict addresses (`127.1`, `0x7f.0.0.1`, `1.2.3.4.`): a resolver might read them as addresses while the certificate check reads them as names.

The name is given to OpenSSL with an explicit length: an empty name would turn its check off, which T0 showed.

**Not checked: public suffixes.** OpenSSL refuses `*.com` (a wildcard needs two labels after it) but takes `*.co.uk` for `victim.co.uk`, as Go and Python do; browsers refuse it with the public suffix list, which this package does not carry. Such a certificate breaks the CA/B Forum's rules, so it takes a mis-issuing CA, or a private one.

## When a connection counts
After `SSL_do_handshake` returns 1, the client checks six things itself (TC9) before it reports `ESTABLISHED`, encrypts any data or delivers any (TC10). Each is a second layer over OpenSSL's own check, and each is tested on its own through a fault seam:
1. the server presented a certificate;
2. OpenSSL's verify result is `X509_V_OK`;
3. an independent `X509_check_host` (or `X509_check_ip`) on that certificate passes, and for a name, OpenSSL recorded the name it matched (`SSL_get0_peername`); when that name is a wildcard, no CA in the verified chain excludes the expected name by a DNS name constraint. OpenSSL checks constraints against the certificate's names as written, so `*.corp.example` passed a CA that excludes `login.corp.example` (Go's CVE-2025-61727); constraints that only permit names need no such check. Constraints that cannot be read refuse the connection;
4. the version is TLS 1.2 or later;
5. no session was resumed;
6. the server's ALPN choice is one that was offered, or none.

Any failure frees the OpenSSL connection, and the error stays: every later call raises it again (TB8). In TLS 1.3 the client's Finished is dropped, so the server never sees a completed handshake. In TLS 1.2 the client's Finished has already gone out by then, since it precedes the server's: the server may then count the handshake as done, but it gets no data, and its own data is discarded. OpenSSL's own verification, which refuses a bad certificate before the client's Finished, comes first in both versions; the gate is the second layer. When OpenSSL itself refuses the certificate, `TlsStream` sends its alert (`unknown_ca`, `certificate_expired`, `bad_certificate`, ...) if the socket takes it at once, so the server's log says why; the tests check that the server saw it.

## Endings
- **The server's close_notify** is a CLOSED event (`read` returns 0) and is answered with ours. Input after it is ignored.
- **A failure after the handshake** (a record that fails authentication, an unexpected message) is answered with OpenSSL's alert, best effort, before `read` raises it (RFC 8446 6.2).
- **A TCP end without close_notify** raises `TRUNCATED` (`UnexpectedEof`), never a clean end, after the data before it is delivered (TB12). The data may have been cut short; only the protocol above can tell (an HTTP `Content-Length` that is complete). Many HTTPS servers end this way after `Connection: close`: `http.Client` decides per RFC 9112 §9.8 (`docs/http.md`).
- **`close()`** sends close_notify once (TB13; nothing is sent during a handshake), after any plaintext written early, then ends the connection without losing what was sent. In the middle of the server's handshake message (a ticket or key update split across records) OpenSSL cannot send it yet: it goes once the rest has arrived (`TlsClient.close_pending()`; `TlsStream.close` reads for it within its linger).
  - It half-closes the socket, so the FIN follows the data, and reads to the server's end, discarding what arrives. It waits at most `linger` (2 s by default) and reads at most 256 KiB. The server's close_notify is not required.
  - Only then does it close the socket. Closing a socket that still holds unread input makes Linux send a reset, which drops the data not yet delivered. A TLS 1.3 server's session tickets sit unread in the socket of a client that only writes. Our GitHub CI caught this as a cut 5 MiB upload.
  - Dropping a `TlsStream` instead closes its socket at once, without close_notify: an abortive end.

## Bounds
OpenSSL's memory buffers never refuse a write, so the state machine bounds them itself (TB17):
- **Feed room:** at most 32 KiB of unread ciphertext and undelivered plaintext together (`feed_capacity()`, more than one record of any version). Each undelivered DATA event counts 64 bytes more, so a server sending one-byte records cannot fill memory with events. A driver that feeds without draining gets room 0.
- **A record at a time:** OpenSSL reads every record in its read BIO in one call, answering each key update on the way, so a bound checked once a feed was read could be passed by a feed's worth of records (a 32 KiB feed got 1,213 key updates answered where the budget allows about 150: TR3). Input goes to OpenSSL one record at a time instead, every bound checked after each; what comes behind the end of the handshake waits for the gate, then goes the same way.
- **Before the handshake ends:** at most 256 KiB from the server (a backstop above OpenSSL's 100 KiB limit on certificate chains).
- **Writes:** 256 KiB of ciphertext waiting to be sent before `write` takes no more. Plaintext written before the handshake is held, encrypted the moment the connection is established and before anything is read, and later writes wait behind it. In the middle of the peer's handshake message `write` takes nothing until more input comes (`wants_input()`): `TlsStream` reads for it, and its `try_write` returns None.
- **Work a server can cause:** once established, at most 256 KiB may arrive without any application data in it (session tickets, key updates), over the whole connection: data does not reset it, but each 4 KiB of data adds a byte; more fails the connection (`PROTOCOL`). Each data record is taken off with its overhead (22 bytes in TLS 1.3, 29 at most in 1.2), and a record still arriving is not counted yet. What reading makes OpenSSL queue to send (key update replies, alerts for TLS 1.2 HelloRequests) may not take the transmit queue past 256 KiB plus two records (`RESOURCE`). Without these, a server flooding tickets kept a reader working past its deadline, and one flooding HelloRequests grew memory.
- **Deadlines:** `read` checks its read deadline before every receive after the first, so records without data do not extend it, and sending what reading queued is bounded by it too.
- **A failed send latches:** it may have sent part of a record, so every later write, flush and close raises the same error. Reading goes on, so what the server sent before (an early 413) can still be read.
- **Wiping:** the package's plaintext buffers are wiped with `OPENSSL_cleanse` when released (TB18): the engine's, undelivered events included, and `TlsStream`'s, each record's as the next replaces it; OpenSSL wipes its own copies (`SSL_OP_CLEANSE_PLAINTEXT`). Plaintext a caller takes from a DATA event is the caller's: `TlsClient.wipe` and `TlsServer.wipe` zero a buffer. The HTTP server wipes the request bytes it took; HTTP's own buffers, which hold the same bytes parsed, are not wiped, as plain HTTP's are not.

## Errors
`TlsError` holds an `IoError` (for code that checks kinds, and `is_deadline()`), a `Category`, OpenSSL's verify code and a detail: OpenSSL's text, and the path or name concerned. `is_authentication()` is true for the certificate categories.

| Category | Means | `IoError` kind |
|---|---|---|
| `UNTRUSTED` | the chain does not lead to a trusted CA, or a CA in it is invalid | `PermissionDenied` |
| `EXPIRED` | a certificate has expired or is not yet valid | `PermissionDenied` |
| `HOST_MISMATCH`, `IP_MISMATCH` | the certificate is for another name or address | `PermissionDenied` |
| `NO_PEER_CERT`, `WEAK` | no certificate; a key or signature below security level 2 | `PermissionDenied` |
| `PROTOCOL` | the handshake or a record failed: version, ciphers, a bad message, an alert | `InvalidData` |
| `ALPN` | the server chose a protocol nobody offered; for a server, the client offered none it speaks | `InvalidData` |
| `CREDENTIALS` | a server's certificate or key is unusable: missing, mismatched, encrypted, weak, or readable by others | `NotFound`, `InvalidData`, `PermissionDenied` |
| `TRUNCATED` | the connection ended without close_notify | `UnexpectedEof` |
| `NO_TRUST_STORE` | no CA certificate could be loaded | `NotFound`, `InvalidData` |
| `INPUT`, `RESOURCE`, `LIBRARY`, `CLOSED` | a bad name or configuration; a memory bound; OpenSSL missing or older than 3.5; use after close | various |
| `NONE` | the transport's own error (a reset, a deadline) | the socket's |

## How OpenSSL is reached
- **One module calls C** (TL7): `tls.ffi`. It opens `libssl.so.3` by absolute path from the directory the Mojo runtime was loaded from, which is the program's own environment, through `std.ffi.OwnedDLHandle`. libssl finds its `libcrypto.so.3` by soname, so one that other code loaded first (another OpenSSL, through `LD_PRELOAD` or a library) would be used instead: loading refuses unless the mapped libcrypto sits beside the libssl. Then it takes the address of each function it uses, once. It refuses an OpenSSL older than 3.5.9 or from another major version (TL1, TL3), and calls `OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG)` first, so no `openssl.cnf` is read (TL4). That holds for the whole process: OpenSSL loads its configuration once, so other users of the same libcrypto (an embedded Python's `hashlib` and `ssl`, another native library) that start after the first context is built read no `openssl.cnf` either, while those that started before have read it (measured: a provider the file activates is there or not by import order). Loading the file instead would let its `[engines]` section install default ENGINEs, which take over key operations even in a private library context. Contexts live in a private library context with only the default provider.
- **The functions bound are an allowlist** (TL5), in `tools/check_tls.py`. Each binding names its function as a literal, so none escapes the list. Each one's ELF version node is `OPENSSL_3.5.0` or older (TL2), so the package runs on any later 3.x. APIs with a CVE history, the features listed above, socket BIOs, session setters and callbacks are refused by name anywhere in `src/tls`. The one function libssl may call is the server's ALPN choice (`alpn_select`), and the one binding that installs a callback is its setter; `tls-check` refuses any other. No public function outside `tls.ffi` hands out an OpenSSL handle, as `Obj` or as the `Int` it is, so a built context cannot be changed (TB3); C is reached only through the allowlisted bindings, in `tls.ffi` too. Mojo has no private fields, so this holds by convention for code that reaches into a struct (`ctx._inner`).
- **The macros' command codes** (`SSL_ctrl` and friends) come from the headers (`tools/gen_tls_consts.py`, `pixi run gen-tls`) and are checked against them in CI (TB14), with the offsets of the three public structs the gate reads (`NAME_CONSTRAINTS`, `GENERAL_SUBTREE`, `GENERAL_NAME`), on each architecture.
- **No sockets in OpenSSL.** It sees only memory BIOs, and `net` does all of the I/O (T0 traced it). libssl and libcrypto make their own memory, randomness and file-read syscalls: the one exception to "no libc on the I/O path" (`docs/design.md`).
- **Errors** (TB6): the thread's error queue is cleared before each OpenSSL call that can fail, and `SSL_get_error` is called right after it. Every `SSL_ERROR_*` value is handled, and an unknown one fails the connection. OpenSSL 3.5.9 clears the queue itself on entering `SSL_do_handshake` and `SSL_read_ex` (measured), so the clears are there for the API's contract, and a test without them still passes on 3.5.
- **Packaging:** the conda package depends on `openssl >=3.5.9,<4` and `ca-certificates`; the repository's own environment is pinned to `openssl 3.5.*` (TA1).

## Checks
What runs, in `pixi run ci` on x86_64 and aarch64 unless said. Gates are the research's TG numbers. Planted bugs were each put in a scratch copy of `src/` and had to turn the named tests red; all did, except the one noted.

- **TG1, certificates and names** (`tests/tls/test_client.mojo`, 41 tests): a throwaway PKI made by the `openssl` command (`tests/tls/tls_pki.py`) and a server in Python's `ssl` (`tls_peer.py`) in a child process.
  - Accepted: DNS names, IPv4 and IPv6 addresses (without SNI, as the server sees), TLS 1.2 with ECDSA and RSA, an intermediate CA, a one-label wildcard, ALPN.
  - Refused, each with its category and OpenSSL's verify code: a wrong host (62), a CN-only certificate, wildcards across labels, partial wildcards, a wrong IP and an IP spelled as a DNS name (64), expired (10) and not yet valid (9), self-signed (18), an unrelated CA (20), a missing intermediate (20), an intermediate that is no CA, a trusted leaf that is no CA (no partial chains), a client-only certificate (26), RSA 1024 (66), SHA-1 (68), TLS 1.1, RSA key exchange with CBC, and a server that does not speak TLS.
  - Also: deadlines, truncation, close_notify both ways, 5 MiB each way, an 8 MiB upload closed while most of it is still unsent (no reset), `close`'s linger bounds, any receive size from 1 byte up giving the same data, and the feed room bounding a driver that never drains.
  - Planted bugs: no host checks, no IP checks, SNI sent for addresses, `SSL_VERIFY_NONE` with the verify result ignored, partial chains on, security level 0, a feed room that ignores undelivered data. All caught.
- **TG4, post-handshake messages** (`test_transcripts.mojo`, against `openssl s_server`): KeyUpdate with and without a request (the client answers the request, as s_server's trace shows); a TLS 1.2 HelloRequest, refused without a second ClientHello; plaintext injected into the stream.
- **TG5, damage** (`test_mutations.mojo`): a seeded proxy (`tls_mitm.py`) flips, drops, duplicates, inserts or replaces bytes, or cuts the connection, in the handshake or the data. The oracle: never a clean end with different data, never bytes the server did not send, never a hang. 80 seeds in CI; 3,000 seeds passed once, after a harness bug was fixed (a peer whose unread output filled its pipe). The truncation-as-clean-end bug is caught by seed 5.
- **TG6, faults** (`test_tls_faults.mojo`, built with `-D MOJO_NET_FAULTS=1`, seams in `tls.ffi`): OpenSSL too old, context and connection creation failing, a setting that does not read back, every `SSL_get_error` code from the handshake, reads and writes, and each of the six gate checks failing alone while OpenSSL passed. Since TR also the write BIO, SNI, the expected host and address, ALPN, loading the trust store, and the library context and its provider, each failing cleanly with LeakSanitizer watching.
  - Planted bug not detectable: removing the error-queue clears (OpenSSL 3.5 clears it itself, see above). `test_stale_openssl_errors_are_ignored` still shows that a stale error neither fails a connection nor leaks into an error's text.
- **TG7, sanitizers** (`pixi run tls-asan`): the client, codec, fault, transcript, damage, review-regression and server tests built with AddressSanitizer and run with LeakSanitizer (the leak test with 1,000 connections, LeakSanitizer as its check). Only the embedded Python interpreter and the test-only fault plan are suppressed. It found a real leak: an `SSL_CTX` was lost when configuration failed, because Mojo 1.2 skips `__deinit__` when `__init__` raises before a field's last assignment (`CLAUDE.md`). Fixed. A planted leak (a connection never freed) is caught. ASan cannot see misuse inside libssl itself (T0), except through the `memcpy` calls it intercepts.
- **TG8, an instrumented OpenSSL** (`pixi run tls-asan-openssl`; weekly in `.github/workflows/tls-weekly.yml`): the same tests against OpenSSL 3.5.9 built from source with ASan (`enable-asan`), so every load and store libssl and libcrypto make is checked.
  - **How it is loaded,** with no switch in `src/`: `tls.ffi` opens `libssl.so.3` beside the Mojo runtime library. The script builds a directory with a copy of that library and the instrumented OpenSSL, and puts it first on `LD_LIBRARY_PATH`. The test binaries use RUNPATH, which `LD_LIBRARY_PATH` precedes.
  - **Measured:** a buffer freed before `SSL_write_ex` copies it is caught by both runs, since libssl copies it with `memcpy`. A `size_t` out-parameter freed before the call is caught only here: `ssl3_write_bytes` stores to it directly. That is the gate's planted bug (`--self-test`).
  - **Planting a use-after-free in Mojo takes raw memory** (`unsafe_alloc`, `unsafe_free`). A `List` whose storage was handed out as a `MutAnyOrigin` pointer stays alive while that pointer is in use, even after `_ = list^`. That is the language's rule for such pointers, and it is also why the wrapper's buffer passing is safe.
  - The full run passes: 86 tests in 7 files, with no report. It found one bug, in a new test: a context destroyed before OpenSSL read the `SSL_CTX` its raw handle pointed to (CLAUDE.md, FFI). Plain ASan missed it, since OpenSSL read the struct directly.
- **TG2, x509-limbo** (`pixi run tls-limbo`; weekly in `.github/workflows/tls-weekly.yml`, since it downloads the corpus): the 9,802 cases of [x509-limbo](https://github.com/C2SP/x509-limbo) at a pinned commit, BetterTLS's 9,572 path-building and name-constraint cases among them (so TG3 runs here too), through the client's own verification in real handshakes (`tools/limbo.py`, `tests/tls/limbo_client.mojo`, `tests/tls/limbo_peer.py`).
  - **How a chain is presented.** The client trusts the case's roots only (`Trust.ca_file`) and expects the case's name. A case that comes with the leaf's key gets a real handshake through the whole client, the gate included. Most cases (BetterTLS, the online chains) have no key, so the server holds a key of the leaf's type and the case's chain replaces its Certificate message on the way out, in TLS 1.2, which sends it in the clear. The client verifies the chain as the message arrives, before the ServerKeyExchange: a refused chain fails with its verify error, an accepted one at the ServerKeyExchange's signature, with verify result 0. On the 197 cases that have keys, both ways give the same verdict, and the gate checks that they still do.
  - **Left out (28):** client certificates, an e-mail name, no expected name, key usages asked for, and 14 whose outcome depends on limbo's validation time (the client verifies now).
  - **Result:** 9,692 of 9,774 as limbo expects. The 82 others are listed with their reasons in `tests/tls/limbo_deviations.txt`, and the gate fails on any change to that list. 35 are refusals limbo would accept: no partial chains (TC2), no ML-DSA, the TLS server purpose always checked, and 26 that OpenSSL's own harness refuses too. 47 are acceptances limbo would refuse, none of them the wrapper's doing: 10 need revocation checks (TC14), 2 set a chain-depth limit of their own, and 35 are OpenSSL's verifier, which its own harness accepts too. Those 35 are CA/B Forum and RFC 5280 issuance rules (serial numbers, EKU forms, a CN that differs from the SAN, which the client never reads), wildcards over public suffixes (see "Names"), and 9 malformed or misplaced name constraints (not critical, in a leaf, empty, a leading dot; a malformed SAN beside the valid one matched), none of which lets through a name a well-formed constraint excludes.
  - **It found VER-1** (see "Review", TR3): the two cases of CVE-2025-61727's shape, a wildcard reaching a name its CA excludes, were accepted; the gate now refuses them. Such checks act after the chain has verified, so only a real handshake sees them: a case may be refused by KEY and accepted by SUB, and the gate allows exactly that difference.
  - **Planted bugs,** each changing at least 7 cases: the CN read when there is no SAN, no `X509_V_FLAG_X509_STRICT`, partial chains on (with the read-back check removed too), security level 0. All caught (`--self-test`).
  - BetterTLS's certificates in the pinned corpus expire on 2027-01-21; after that the gate fails until the pin moves.
- **TG10, defaults** (`test_config.mojo`, `test_hostile_config.mojo`, `test_tls_regressions_hostile.mojo`): the trust order and its environment variables, empty and missing stores, ALPN encoding, and the whole policy under a hostile `openssl.cnf` loaded into the process first: TLS 1.0, security level 0 and the legacy provider; then an extra CA (`VerifyCAFile`) and weakening options (unsafe renegotiation, ignoring an end without close_notify, kTLS), shown to reach Python's contexts and not ours; and for a server, four session tickets, tickets back on and `ffdhe2048` first, none of which takes.
- **The server (T2):**
  - `test_server.mojo` (18 tests), against Python's `ssl` (`tls_client_peer.py`) and `openssl s_client`: TLS 1.3 and 1.2 with an intermediate-profile suite; TLS 1.1, and TLS 1.2 under `tls13_only`, refused; ALPN chosen, refused with `no_application_protocol`, absent; an unknown SNI refused before any data, SNI normalized, none from an address; no ticket and no resumption on a reconnect; truncation; a ClientHello that never ends cut at 32 KiB; `ffdhe2048`, DHE, static RSA, CBC and CCM suites refused; renegotiation refused (s_client's `R`); the server closing first.
  - `test_server_config.mojo` (13): every refusal above, the policy read back, an intermediate sent, lifetime and renewal, reloading with live connections, and no `SSLKEYLOGFILE` written. The encrypted key is tried on a pseudo-terminal of the program's own (`on_tty.py`): with the empty-password guard removed, the program prints "Enter PEM pass phrase:" and waits, and the test fails.
  - `test_server_pair.mojo`: client and server in one process with every byte under a seed. 40 seeds of random split points arrive intact; 200 seeds of damage (flipped, lost, repeated or inserted bytes, cuts) in either direction all fail cleanly, never delivering bytes the other side did not send. A KeyUpdate flood from the client (made with libssl's `SSL_key_update` in the test) fails the server's connection.
  - `test_server_faults.mojo` (6): each server-context call failing, and each part of the server's gate.
  - `test_server_leak.mojo`: 10,000 connections (whole, dropped mid-handshake, damaged): resident memory did not grow (178 MB before, 143 MB after, under `mojo run`). A planted leak (no `SSL_free`) fails it.
  - Planted bugs, each caught: tickets on, `ffdhe2048` in the groups, an ALPN callback that takes anything, no SNI check, the ClientHello bound at 256 KiB, a byte too many delivered, no bound on input without data, no empty password, no `SSL_free`.
  - **Not run: TG12 as specified.** sslyze, tlsfuzzer and testssl.sh are not on conda-forge, so the Mozilla-profile scan is the tests above, with `openssl s_client` and Python's `ssl` as the scanners. Run sslyze (`--mozilla_config=intermediate`) against the S7 listener before it is published.
- **Static** (`pixi run tls-check`): FFI in one module, and in it C reached only through the allowlisted bindings; forbidden names; one callback, wherever it is defined; no handle handed out, as `Obj` or as `Int`; symbol versions; constants against the headers. Its self-test plants a violation of each. Also `import-check`: only `tls.stream` and `tls.target` import `net`.
- **TG14, freshness** (`pixi run tls-freshness`, daily in `.github/workflows/freshness.yml`): fails when conda-forge has had a newer `openssl` 3.5 or `ca-certificates` than `pixi.lock` for more than two days. Its first run found `ca-certificates` three days stale.
- **By hand, 2026-10-26: badssl.com and real APIs.**
  - Refused: expired, wrong host, self-signed, untrusted root, incomplete chain, SHA-1 intermediate, RSA 1024 behind an untrusted root, Superfish and the other bad roots, RC4, 3DES, NULL, DHE of 480 to 1024 bits, static RSA, CBC, TLS 1.0 and 1.1.
  - Accepted: badssl.com's good hosts; `revoked` (no revocation checks, by design); the APIs of OpenAI, Anthropic, Hugging Face, GitHub and Google, over TLS 1.3 with X25519MLKEM768.
  - Some badssl.com hosts reset connections intermittently, for `openssl s_client` too.

## Review
**TR, 2026-10-26:** two independent internal reviews against the rules, both by AI, one of verification and the protocol, one of the FFI layer and memory. Neither found a way to establish a connection to a server whose certificate fails to chain to the configured trust or to match the name or address. Neither found a use-after-free, a double free, a leak or a wrong C signature. What they did find is fixed, each under a test that fails on the code before its fix (`tests/tls/test_tls_regressions.mojo`, `_faults.mojo`, `_hostile.mojo`, and `tests/http/test_https_regressions.mojo`):
- **A hostile server could make work without end.**
  - Session tickets or key updates without data kept `read`, `try_read` and `is_reusable` running past every deadline (a pool's check has none).
  - Key update replies and TLS 1.2 HelloRequest alerts grew the transmit queue without bound.
  - One-byte records multiplied the memory the feed room was meant to bound.
  - Now: the input and output bounds and the event cost above, and `read` checks its deadline between receives.
- **`Trust.ca_file("")` meant the system roots** (fail open, TC2). It is now refused.
- **Plaintext written before the handshake** could be overtaken by later writes, wait for the next input, or be dropped without a word when the server's close_notify came with its Finished.
- **Part of a record counted as "nothing arrived"** in `is_reusable`, so a held-back record could become the answer to the next request. The codec now follows the record framing itself, since OpenSSL takes partial records out of its read BIO.
- **A failed send did not latch:** the next write sent the cut record again, corrupting the stream.
- **Loading:** a libcrypto loaded first by other code was used in place of the one beside libssl, and the version floor was 3.5.0 where TL1 asks for 3.5.9.
- **A built context was not read-only:** `ClientContext.ssl_ctx()` and `library()` handed out the handles anyone could use to add trust anchors. They are private now, and `tls-check` refuses a public accessor of that kind.
- **Smaller:**
  - no alert after a failure past the handshake;
  - a CRL counted as a trust anchor;
  - OpenSSL's own copies of plaintext not wiped;
  - bad `https://` names reaching DNS and TCP before the TLS layer refused them;
  - names `tls-check` should have refused, and ways around its allowlist;
  - error paths without a fault seam.
- **Taken as is, and said so:**
  - In TLS 1.2 the client's Finished goes out before the gate runs (see "When a connection counts").
  - Buffers lent to C stay alive because their pointers have `MutAnyOrigin`, which Mojo documents as keeping every value in scope alive and as slated for removal. The two places that relied on it alone now keep their owner alive explicitly. A Mojo change there needs a review of every call.
  - `OPENSSL_init_ssl` runs without `OPENSSL_INIT_NO_ATEXIT`. An exit-time race between OpenSSL's cleanup and other threads is a known class of bug, not shown here.

**TR2, 2026-10-27: the server side** (T2, and HTTPS in `server`, S7). Two independent internal reviews, both by AI: one of the protocol and the policy against hostile clients, one of the HTTPS listener and of memory and FFI. Neither found a way past the gate: no resumption, early data, version below the floor, renegotiation, client certificate, foreign suite or group, unknown SNI or foreign ALPN got through. Neither found a use-after-free, double free, leak, wrong C signature or fd leak, under ASan and LeakSanitizer too, the HTTPS tests included (which `tls-asan` now runs). They found:
- **Key updates between bytes of data kept a server core busy** (high). Data reset the budget for input without data, so a client sending a byte of data every 9,000 key updates was never cut. Each key update it asks for costs the server 15.6 µs, about 25 times its bytes of data. The budget is now over the whole connection, data refills it only slowly, and a client gets 4 KiB of it (`CLIENT_QUIET_LIMIT`). Key updates sent behind the client's Finished, in the flight that ends the handshake, now count too.
- **Silent sockets locked the HTTPS listener out** (high, in `server`). Each accepted socket counted as a handshake, and accepting paused at the cap, so some 2,000 sockets sending nothing kept every client out. Now no TLS state exists before the first record has arrived whole (`docs/server.md`, "TLS").
- **The ClientHello bound counted the data behind the Finished** (medium; both reviews found it). A TLS 1.3 client's first 31 KB or more, read with its Finished, failed the handshake as too large, so uploads were reset. The bound is now checked after each feed, and only while the handshake is unfinished.
- **Smaller:**
  - the gate did not check `tls13_only` again;
  - certificate compression was left on, for a libssl that would have a compressor;
  - a key that did not match the certificate was reported as an encrypted key;
  - the TLS 1.2 path of a refused gate had no test;
  - in `server`: a failed reload was tried again only when the files changed in a way a `chmod` does not, and an absolute-form target's authority passed the SNI check while a different Host field stayed.
- **Taken as is, and said so:**
  - A refused gate sends no alert: the connection closes after a completed TLS 1.3 handshake, which the client sees as a cut. Sending `unrecognized_name` would need a second callback into Mojo.
  - Over HTTPS a TCP half-close loses the response: a request followed by the client's close_notify gets the server's close_notify in reply, and one followed by a FIN without close_notify is a truncation. Plain HTTP serves both.
  - A chain file cut between two PEM blocks still builds, without its intermediate: replace the files by renaming, as `docs/server.md` says.
  - A leaf no client would accept (a clientAuth-only extended key usage, a chain through a non-CA) still builds; an IP address sent as SNI is refused although RFC 6066 forbids only sending it; a key encrypted with an empty passphrase loads.
  - The key file's directory may be writable by others; PostgreSQL's rule checks the file only.
  - Each TLS connection holds about 60 KB (a 16 KiB decrypt buffer and OpenSSL's state), against 30 KB for plain HTTP.
  - `test_no_key_log_file_is_written` cannot fail with this libssl, which has no key log; the workers' environment check is the one that guards it.
- **Tests:** `tests/tls/test_tls_server_regressions.mojo` (8) and `test_tls_server_regressions_faults.mojo` (1); `tests/server/test_server_tls_regressions.mojo` (6), and `test_tls.mojo`'s admission tests rewritten for ClientHellos that wait.
- **Planted bugs:** 18, one per fix, each undone in turn: 17 caught at first. The one missed was a ClientHello waiting for admission, not closed at its handshake deadline but admitted late; a test now covers it.

**TR3, 2026-10-27: a third review, of the whole package** after T2 and S7: four independent internal reviews, all by AI, of the OpenSSL API and FFI layer, of verification and identity, of the engine as a state machine, and of the stack's use of TLS as an attacker would see it; and gate TG2, x509-limbo (see "Checks"), run for the first time. None found a way to deliver or encrypt plaintext before the gate, a wrong C signature, a misuse of `SSL_get_error`, or an ownership or lifetime bug. Each finding is fixed under a test that fails on the code before its fix, and each fix was then undone in a scratch copy of `src/` to see its test fail (`tests/tls/test_tls_review3_regressions.mojo` and `_faults.mojo`, `tests/http/test_https_review3_regressions.mojo` and `_faults.mojo`, `tests/server/test_server_tls_review3_regressions.mojo`):
- **VER-1, a wildcard reached a name its CA excludes** (medium). OpenSSL checks name constraints against the certificate's names as written: root, then an intermediate excluding `DNS:secret.wild.test`, then a leaf for `*.wild.test`, was accepted as `secret.wild.test`. This is Go's CVE-2025-61727, which BoringSSL and webpki refuse; x509-limbo has two cases of it. The gate now refuses a wildcard match for a name any CA in the verified chain excludes (see "When a connection counts").
- **ENG-1, the quiet budget was checked once a whole feed was read** (medium). OpenSSL answered 1,213 key updates from one 32 KiB feed, about 9 times the 4 KiB the budget allows a client, before the connection failed, and the 32 KB of replies went out after the failure. Records now go to OpenSSL one at a time (see "Bounds").
- **INT-1, a stalled handshake held its place** (medium, in `server`). A handshake counted against `tls_max_handshakes` until its end or its 10 s deadline. So clients that sent a ClientHello and went quiet kept all 1,024 places, and about 100 a second of them cut the server to about 100 handshakes a second. Now, while ClientHellos wait, one that has waited `tls_client_wait` (1 s) for its client since admission gives its place up (`docs/server.md`).
- **API-1, each built context loaded OpenSSL anew** (medium). About 330 live contexts used up the process's thread-specific keys (3 each, of 1,024), after which every build failed, and so did other code in the process that needed a key. Contexts can now share one (`build(sharing=...)`, `tls_context` in `http.Client` and `llm.Client`); reloads share the first context's (see "Use").
- **Smaller:**
  - **INT-2:** over https, an early 2xx that kept the connection could leave the body's last records unsent, while the caller saw success.
  - **INT-3:** over https, a read after a failed send raised the send's error instead of reading the early 413 that plain HTTP returns.
  - **ENG-2:** in the middle of a peer's handshake message split across records, `write` failed the connection with a misleading protocol error, `close` claimed close_notify went out when it had not, and a pooled connection looked reusable.
  - **ENG-3:** `close()` dropped plaintext written early that was still waiting, and `has_transmit()` then stayed true with nothing to send, so `TlsStream`'s flush looped.
  - **ENG-4:** `TlsStream` let go of each record's plaintext without wiping it.
  - **VER-3:** an IPv4-mapped address was checked as IPv6 while the connection went to the IPv4 address.
  - **API-3:** three ways past `tls-check`: `external_call` inside `tls.ffi`, a callback defined inside a struct, and a handle handed out as `Int`.
- **Said now, not changed:**
  - **VER-4:** a `TRUSTED CERTIFICATE` block's trust marks are honoured (see "Policy"; distrust marks are honoured too).
  - **VER-2:** no public suffix list (see "Names").
  - **API-2:** no `openssl.cnf` is read, process-wide (see "How OpenSSL is reached").
- **Planted bugs:** one per fix, each undone in turn; all caught. Two tests first missed their bug: ENG-3's, whose seam fired too early, and INT-2's, which needed a body large enough for the 200 to arrive while it was still being sent. Both were fixed and caught their plants after.

**Not verified yet:**
- TLS-Anvil (TG11): it needs a client that trusts TLS-Anvil's own certificates, which this package has no switch for;
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
- **H8: `https://` in `http.Client`** (in `http`). Done (`docs/http.md`): the pool keyed by scheme (one TLS context per `Client`), ALPN `http/1.1`, truncation handled per RFC 9112 §9.8. The client follows no redirects, so there is none to verify again. `TlsStream` gained the readiness-loop calls it needs: `try_read`, `try_write`, `flush_ready`, `buffered`, `is_reusable`.
- **P9, R8: TLS for `pg` and `redis`.** Parked, by the user's priorities.
- **TR: review.** Done, but for TG11 and the external review. Three rounds of independent internal reviews (TR, TR2, TR3), each finding fixed under a regression test (see "Review"); TG8, OpenSSL built with ASan; and TG2, x509-limbo, BetterTLS's cases with it. The external review (TG15) is a person's job: it is not booked yet.
- **T2: the server.** Done; reviewed internally (TR2, see "Review").
  - `tls.engine` (what both sides share, out of `tls.client`), `tls.server_config` (`ServerConfig`, `ServerContext`), `tls.server` (`TlsServer`); `linux.fs.stat_path` for the key's permissions; `linux.fault` seams up to 1099.
  - Tests: 42 in 6 files (one in `test_tls_regressions_hostile.mojo`), plus the ASan runs; `tls-check` knows the one callback. TR2 added 9 in two files.
- **S7: the TLS listener** in `server`. Done (`docs/server.md`, "TLS"): admission, the handshake deadline, close policy, reload when the files change (a check every 10 s rather than SIGHUP: certbot and Kubernetes replace files and need no signal) and the expiry alarm, workers, and the 421 for a `Host` other than the SNI.
