# Security

**This project is AI-generated, and not all of it has been reviewed.** Use it at your own risk. In particular:
- **TLS** (`tls`, and `https://` in `http.Client`) wraps OpenSSL 3.5 and writes no cryptography of its own. It has had two internal reviews, both by AI, and is tested against independent implementations, with fault injection, sanitizers and an OpenSSL built with AddressSanitizer. No human TLS expert has reviewed it yet. `docs/tls.md` says what is checked and what is not.
- **The HTTP server, the HTTP client, and the PostgreSQL and Redis drivers** have each had independent internal reviews (also by AI), with their findings fixed under regression tests. See each library's doc.
- Nothing in this repository has had an external security audit.

## Reporting a vulnerability
Please do not open a public issue for a vulnerability. Report it privately through GitHub: the repository's **Security** tab, then **Report a vulnerability**. If that option is not available, open an issue that asks for a private channel, without the details.

Say what is affected (package, function, version or commit), how to reproduce it, and what an attacker gains. A fix comes with a regression test that fails on the code before it, as every fix here does.

## Supported versions
Only the latest commit on `main`. There are no releases yet.

## OpenSSL
`tls` loads the environment's OpenSSL (`openssl >=3.5.9,<4`). On an OpenSSL advisory, update the environment (`pixi update openssl`); `docs/tls.md`, "Updates", says how the project handles advisories.
