# pg: the PostgreSQL driver

A PostgreSQL client for Mojo on Linux, speaking the frontend/backend protocol (version 3.0) natively, without libpq. It is the first of the roadmap's database drivers. Package rules and the shared contracts are in `docs/design.md`. The transport is `net` (`docs/net.md`), and the authentication primitives are `crypto`.

**Status: P1 done** (the cryptographic primitives). Next is P2, the sans-I/O protocol codec.

## Scope
**In scope:**
- connecting over TCP (by name, with Happy Eyeballs) or a Unix-domain socket;
- authentication: trust, cleartext password, MD5 and SCRAM-SHA-256;
- the simple query protocol, then the extended one: prepared statements, parameters, binary results for common types;
- server errors and notices with all their fields, ParameterStatus, and cancellation through BackendKeyData;
- a deadline per operation, with a CancelRequest when a query's deadline passes;
- transactions, a connection pool, LISTEN/NOTIFY.

**Out of scope for now:**
- **TLS:** `sslmode=require` and stronger, `channel_binding`, SCRAM-SHA-256-PLUS. `net` has no TLS yet. Connections are cleartext, so use them over a Unix socket, a trusted network or a TLS-terminating sidecar.
- GSSAPI, SSPI and Kerberos authentication.
- The replication protocol. COPY is a P5 candidate.
- An async API (no async/await yet; see `docs/design.md`).

## Decisions
- **Sans-I/O.** The protocol logic is a `Codec` (design contract 1). It parses and builds messages, runs the startup and authentication exchange, and tracks the query flow, but never touches a socket or a clock. Only `pg.client` imports `net` (`SANS_IO` in `tools/check_imports.py`).
- **The caller supplies randomness.** The SCRAM client nonce is given to the codec; the blocking client reads it from getrandom. So codec tests replay exact exchanges (contract 7).
- **Protocol 3.0.** Every supported server speaks it. Protocol 3.2 (PostgreSQL 18, longer cancel keys) can come later. A NegotiateProtocolVersion answer is handled.
- **No silent downgrade.** `sslmode` values `disable`, `allow` and `prefer` connect in cleartext; none of them guarantees encryption. `require`, `verify-ca`, `verify-full` and `channel_binding=require` are refused with `Unsupported`, not ignored.
- **Authentication.**
  - **SCRAM-SHA-256** (RFC 5802, RFC 7677) has been PostgreSQL's default since version 14. The client checks the server's final signature, in constant time, so a server that does not know the password cannot pass as authenticated. It also checks that the server's nonce extends the client's.
  - **Restricting methods.** A `require_auth`-style option (as in libpq 16) limits the methods a server may ask for. By default every method above is accepted, as in libpq.
  - **MD5** is supported for old setups only. MD5 is broken as a hash, and the exchange protects no password against an eavesdropper.
- **SASLprep (RFC 4013).**
  - **What PostgreSQL does:** it normalizes a SCRAM password when the password is set, and uses the raw bytes when the password is not valid for SASLprep.
  - **ASCII passwords** come out unchanged either way, so they always work.
  - **Non-ASCII passwords** are sent as their UTF-8 bytes. One that SASLprep would change (non-ASCII spaces, NFKC compatibility forms) fails to authenticate. Full SASLprep needs Unicode tables and is a later item.
- **Server errors are data, not I/O failures.**
  - **In the codec:** ErrorResponse and NoticeResponse are events carrying every field: severity, SQLSTATE, message, detail, hint, position, and so on.
  - **In the blocking client:** it raises `PgError`, which holds either the transport's `IoError` or the server's error with its SQLSTATE. So a caller can tell a unique violation from a lost connection.
  - **Below `pg`:** contract 8 still holds. `IoError` is register-passable with a static op name and cannot carry a server's message.
- **Encoding.** The startup message asks for `client_encoding=UTF8`.

## Testing
- **P2:** captured exchanges replayed in every split, and a fake backend in Python whose SCRAM side is computed with hashlib, independently of `crypto`.
- **From P3:** a real PostgreSQL.
  - **Install:** `postgresql` from conda-forge becomes a pixi dependency.
  - **Clusters:** each test file creates its own with `initdb` in a scratch directory. It listens on a Unix socket in that directory, and on a free TCP port where needed.
  - **Users:** one for each authentication method in `pg_hba.conf`.

## Modules (planned)
- `message`: the wire format.
  - Frontend messages are built into a `ByteBuffer`. Backend messages are split and parsed: a type byte, then an Int32 length that counts itself. The startup packet has no type byte.
  - Everything a server sends is length-limited.
- `auth`: the MD5 and SCRAM-SHA-256 client exchanges.
- `connection`: `PgConnection`, the `Codec` for one connection. It covers startup, authentication, ParameterStatus and BackendKeyData, the query flows, and the transaction status from ReadyForQuery.
- `config`: connection parameters, from code or a `postgresql://` URL.
- `client`: the blocking `Client` over `net`, the only module that imports `net`.
- `types` (P4): values in binary and text form.

## Milestones
- **P1: cryptographic primitives.** Done.
  - **`crypto`:** SHA-256 (FIPS 180-4), MD5 (RFC 1321), HMAC-SHA-256 (RFC 2104), PBKDF2-HMAC-SHA-256 (RFC 8018) and `equal_constant_time`. Pure Mojo, importing only `std`.
  - **`bytes.base64`:** RFC 4648 with strict decoding.
  - **Tested against published vectors:** the FIPS 180-4 examples (a million "a"s included), the RFC 1321 suite, RFC 4231, RFC 7914 section 11 and RFC 4648 section 10.
  - **Tested differentially** against Python's hashlib, hmac and base64:
    - every message length over three blocks;
    - every key size from 0 to 139 bytes (a block is 64);
    - random inputs fed in random pieces;
    - every ASCII character in every position of a base64 quantum.
  - **Planted bugs:** 28 (padding edges, length encoding, key sizes, the PBKDF2 rounds, base64's alphabet ranges and padding, the comparison), all caught.
  - **Measured on an i5-1145G7, against OpenSSL 3.5 with SHA-NI (through Python's hashlib):**
    - **SHA-256:** about 260 MB/s with scalar code; OpenSSL does about 1.5 GB/s.
    - **PBKDF2** with 4096 rounds, PostgreSQL's default for SCRAM: about 1.9 ms; OpenSSL takes 0.75 ms. This is the client's cost per new connection; the server stores derived keys and never runs PBKDF2.
    - **What makes PBKDF2 fast:** the key's padded blocks are absorbed once, and after the first round each round is two compressions on words, with no allocation. That took it from 4.3 ms to 1.9 ms.
  - **Unrolling** the compressions with `comptime for` made them about nine times faster: with constant indexes the message schedule stays in registers (CLAUDE.md).
  - **Leads:**
    - the hardware SHA-256 instructions (x86 SHA-NI, the Armv8 SHA-2 extension);
    - a pool that keeps the derived SCRAM keys per salt and round count, so only its first connection pays for PBKDF2 (P5).
- **P2: the protocol codec.**
  - **Framing** both ways, with a configurable limit on a backend message's length.
  - **Startup:** the StartupMessage (user, database, application name, options), authentication (trust, cleartext, MD5, SCRAM-SHA-256 with the server signature checked), ParameterStatus, BackendKeyData, NegotiateProtocolVersion and ReadyForQuery.
  - **Simple query:** RowDescription, DataRow, CommandComplete (with the row count), EmptyQueryResponse, ErrorResponse, NoticeResponse and NotificationResponse. Several statements in one query, and an error in the middle of them.
  - **Tests:**
    - captured exchanges replayed in every split;
    - the Python fake backend, for authentication success and each failure: a wrong password, a bad server signature, a nonce that does not extend ours, unsupported methods;
    - malformed messages.
- **P3: the blocking client.**
  - **API:** `Client.connect(config)`, and `query(sql)` returning results whose rows hold text values.
  - **Transports:** TCP (`net.dial`) and Unix sockets.
  - **Deadlines:** one per operation. When it passes during a query, the client sends a CancelRequest on a new connection, then drains the connection to ReadyForQuery or closes it.
  - **Tests** against a real PostgreSQL:
    - every authentication method;
    - errors with their SQLSTATE, and notices;
    - large results;
    - cancellation;
    - a server that goes away.
- **P4: the extended protocol and types.**
  - **Messages:** Parse, Bind, Describe, Execute and Sync.
  - **Statements:** parameters (`$1`), and a statement cache per connection.
  - **Binary results** for bool, the integers, the floats, text, bytea, uuid, date and the timestamps; numeric as text.
  - **Pipelining:** several statements before one Sync.
- **P5: transactions, a pool, LISTEN/NOTIFY.**
  - **Transactions:** a scope that rolls back on error.
  - **Pool:** connections are health-checked and reset before reuse.
  - **Notifications:** delivered between queries, and waited for with a deadline.
  - **COPY**, if needed.
- **P6: review and polish.**
  - Independent reviews, with a regression test for each finding.
  - Performance measured against libpq.
  - Examples, and the guide.
