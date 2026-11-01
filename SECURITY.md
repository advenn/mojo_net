# Security

**This project is AI-generated, and not all of it has been reviewed.** Use it at your own risk. Every review below was internal: done by AI agents that had not written the code, read-only, with each finding reproduced by a regression test that fails on the old code before it was fixed. No human expert has reviewed any of it, and nothing in this repository has had an external security audit.

| Package | Internal reviews | Where they are recorded |
|---|---|---|
| `tls` (and `https://` in `http.Client`) | three rounds: TR (2 reviewers), TR2 (2), TR3 (4); plus x509-limbo and an OpenSSL built with AddressSanitizer | `docs/tls.md`, "Review" and "Checks" |
| `linux`, `bytes`, `net` | three rounds | `docs/net.md` |
| `http` | three rounds (the third: HR3) | `docs/http.md` |
| `server` | two rounds (S5, SR2), plus TR2 and TR3 for HTTPS | `docs/server.md` |
| `pg` | one round of three reviewers (P7) | `docs/pg.md` |
| `crypto` | only as part of P7's review of PostgreSQL authentication | `docs/pg.md` |
| `json`, `llm` | one review each | `docs/json.md`, `docs/llm.md` |
| `redis` | none yet (R6) | `docs/redis.md` |
| `rt` | none (frozen, experimental) | `docs/rt.md` |

**TLS** wraps OpenSSL 3.5 and writes no cryptography of its own. It is tested against independent implementations, with fault injection, sanitizers and an OpenSSL built with AddressSanitizer, but no human TLS expert has reviewed it. `docs/tls.md` says what is checked and what is not.

## Reporting a vulnerability
Please do not open a public issue for a vulnerability. Report it privately through GitHub: the repository's **Security** tab, then **Report a vulnerability**. If that option is not available, open an issue that asks for a private channel, without the details.

Say what is affected (package, function, version or commit), how to reproduce it, and what an attacker gains. A fix comes with a regression test that fails on the code before it, as every fix here does.

## Supported versions
Only the latest commit on `main`. There are no releases yet.

## OpenSSL
`tls` loads the environment's OpenSSL (`openssl >=3.5.9,<4`). On an OpenSSL advisory, update the environment (`pixi update openssl`); `docs/tls.md`, "Updates", says how the project handles advisories.
