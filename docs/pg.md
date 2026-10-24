# pg: the PostgreSQL driver

A PostgreSQL client for Mojo on Linux, speaking the frontend/backend protocol (version 3.0) natively, without libpq. It is the first of the roadmap's database drivers. Package rules and the shared contracts are in `docs/design.md`. The transport is `net` (`docs/net.md`), and the authentication primitives are `crypto`.

**Status: P1–P4 done:**
- the cryptographic primitives;
- the sans-I/O codec for a session (`PgConnection`);
- a blocking client (`pg.client`), tested against PostgreSQL 18;
- the extended query protocol: parameters and prepared statements.

Next is P5: binary values for the common types, and a statement cache.

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
  - **Restricting methods.** `Startup.allow` (`AuthMethods`, like libpq 16's `require_auth`) limits the methods a server may ask for, and a refused method fails before any password leaves the client. By default every method above is accepted, as in libpq.
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
- **P2:** the Python oracle `tests/pg/pg_oracle.py`, written from the protocol documentation independently of `crypto` and `pg`.
  - It builds backend messages, parses what the client sent, and runs the server side of MD5 and SCRAM with hashlib and hmac.
  - Its transcripts are replayed in every split (`drive_chunked`), and mutated ones must end in events or an error, never a crash.
- **From P3:** a real PostgreSQL, `postgresql` from conda-forge (a pixi dependency, test-only like Python).
  - **Clusters:** `tests/pg/pg_cluster.py` makes a throwaway one per test, in under a second: `initdb` in a temp directory, durability off, a Unix socket in that directory and a free port on 127.0.0.1. `tests/pg/pg_server.mojo` starts and stops it; a test stops it whatever happens.
  - **Users:** one per authentication method in `pg_hba.conf`, over both transports: `trusty` (trust), `plain` (password), `md5user` (md5, its password stored as MD5) and `scram` (scram-sha-256, a non-ASCII password).
  - **Without a server** (no `initdb`, or running as root, which initdb refuses), these tests are skipped; `MOJO_NET_REQUIRE_PG=1` makes that an error.

## Using the client
```mojo
from linux.time import Duration
from pg.client import Client, PgError
from pg.config import Config


def main() raises:
    var db = Client.connect(Config.parse("postgresql://app:secret@localhost/shop"))
    var r = db.query("SELECT id, name, email FROM users WHERE id > $1 ORDER BY id", 10)
    for i in range(len(r)):
        var email = "-" if r.is_null(i, 2) else r.text(i, 2)
        print(r.int(i, 0), r.text(i, 1), email)
    try:
        _ = db.execute("INSERT INTO users (id, name) VALUES ($1, $2)", 1, "again")
    except e:
        if e.code() == "23505":  # unique_violation: the session goes on
            print("taken:", e.server().detail().or_else(""))
    try:
        _ = db.query("SELECT pg_sleep(10)", timeout=Duration.from_millis(200))
    except e:
        print("cancelled:", e.is_deadline())  # True; the session goes on
    db^.close()
```

- **Connecting:**
  - `Config(user, host=, port=, password=, database=, ...)`, or `Config.parse` with a libpq-style URI (`pg.config`).
  - A `host` that is an absolute directory means the Unix socket in it.
  - `connect_timeout` bounds the whole opening: name resolution, connecting, authentication.
- **Queries:**
  - `query(sql, args...)` runs one statement through the extended protocol, with `$1`, `$2`, ... bound to the arguments. The values are sent apart from the SQL, so nothing can be injected through them.
  - Each `Writable` argument goes in its text form, and the server reads it as the type the statement needs (`Int`, `Float64`, `Bool`, strings).
  - `query_params(sql, params)` takes a `Params` for NULLs, raw bytes (`add_binary`, bytea) or declared types (`add_text(value, oid)`).
  - `execute(sql, args...)` returns the rows affected.
  - `simple_query(sql)` runs a script of several statements, without parameters, and returns each one's result.
  - `Rows` has `columns`, `tag`, and per value `is_null`, `text`, `int`, `bool`, and `value` for the bytes. Values are in text form for now.
- **Errors raise `PgError`.**
  - A server error (`is_server()`, the SQLSTATE in `code()`, every field in `server()`) leaves the session usable.
  - Anything else closes it: a transport or protocol error, or the server ending the session.
- **A query's `timeout`:**
  - When it passes, the query is cancelled. The client sends a CancelRequest on a new connection and waits until the server has taken it, as libpq does.
  - The session stays usable, and the error says `is_deadline()`, with the server's 57014 attached.
  - If the server does not end the query within `CANCEL_GRACE`, the connection is closed.
- **On the side:** `take_notices()`, `take_notifications()` (after LISTEN), `parameter(name)`, `transaction_status()`, `cancel()`.

## Using the codec
`PgConnection` runs one session and does no I/O. The driver sends what it hands out and feeds it what the socket reads. This is a blocking driver's loop, what `pg.client` will run (P3):

```mojo
var nonce = List[UInt8](length=18, fill=0)
fill_random(Span(nonce))  # linux.random: fresh for every connection
var conn = PgConnection(Startup("alice", database="shop", password=secret), Span(nonce))
var ev = PgEvent()  # reused: its buffers are refilled
var out = ByteBuffer()
var asked = False
while True:
    while conn.poll(ev):  # raises IoError when the connection is unusable
        if ev.kind == EventKind.READY:
            if not asked:  # the first READY: the session is open
                conn.query("SELECT id, name FROM users")
                asked = True
            else:  # the query's cycle is over
                conn.terminate()
        elif ev.kind == EventKind.DATA_ROW:
            print(String(from_utf8_lossy=ev.value(1)))  # text values; ev.is_null(i)
        elif ev.kind == EventKind.ERROR:
            print(ev.server_message())  # SQLSTATE and message; READY follows
    while conn.poll_transmit(out) > 0:
        stream.write_all(out.readable_span())
        out.clear()
    var n = stream.read(Span(buf)[0 : min(len(buf), conn.feed_capacity())])
    if n == 0:
        conn.feed_eof()
        _ = conn.poll(ev)  # raises, unless the session ended (terminate(), a FATAL error)
        break
    conn.feed(Span(buf)[0:n])
```

- **Authentication runs inside the codec.**
  - It answers whatever the server asks, from the `Startup` (password, `allow`).
  - Its SCRAM rounds run in `poll`: about 2 ms for PostgreSQL's 4096.
- **Results come as events, in order.**
  - `query` may be called again before READY: the queries are pipelined, and each one's events end with its own READY.
  - `ev.columns()` describes the rows that follow. `ev.tag()` and `ev.rows_affected()` give the command's outcome.
- **Server errors are events.** `poll` raises only when the connection can no longer be used: the server broke the protocol, authentication was refused, or EOF came while the session was open. EOF after `terminate()` or after a FATAL error is the normal end.
- **The session's state:**
  - `is_idle()`;
  - `transaction_status()` (`IDLE`, `IN_TRANSACTION`, `FAILED_TRANSACTION`);
  - `parameter(name)`, the values from ParameterStatus;
  - `backend_key()`, for a CancelRequest on a new connection (`write_cancel_request`).

## Modules
- **`message`:** the wire format.
  - Frontend messages are built into a `ByteBuffer`. They refuse NUL bytes, and keep the startup packet under the server's 10000-byte limit.
  - Backend bodies are checked once, when they arrive. `ServerMessage` reads the fields of an error or notice, `Column` those of a RowDescription.
- **`auth`:** the MD5 answer, and `ScramClient`, the client side of SCRAM-SHA-256.
- **`connection`:**
  - `PgConnection` is the `Codec` for one session: startup and authentication, the simple query flow, and the session's state.
  - `Startup` holds the settings, and `AuthMethods` the methods a server may ask for.
  - `PgEvent` and `EventKind` are the events.
- **`config`:** `Config`, from code or a connection URI, with the settings a session needs.
- **`client`:** the blocking `Client`, `Rows` and `PgError`. It is the only module that imports `net`, and is not re-exported from `pg`.
- **Planned:** `types`, values in binary and text form (P4).

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
- **P2: the protocol codec.** Done.
  - **`pg.message`:** the wire format.
    - The builders refuse NULs and a startup packet over the server's limit.
    - Backend bodies are checked once, on arrival.
  - **`pg.auth`:** the MD5 answer, and `ScramClient`.
    - It checks that the server's nonce extends the client's, and checks the final signature in constant time.
    - It refuses unknown mandatory extensions, and more than `MAX_SCRAM_ITERATIONS` rounds.
  - **`pg.connection`:** `PgConnection`, `Startup`, `AuthMethods`, `PgEvent`.
    - **Startup:** the settings are checked (reserved or repeated parameters, NULs, a short nonce).
    - **Authentication:** whatever the server asks, within `Startup.allow`.
    - **The session's reports:** ParameterStatus, BackendKeyData, NegotiateProtocolVersion.
    - **Simple queries:** pipelined, with server errors and notices as events.
    - **COPY FROM STDIN:** refused with CopyFail, and the session goes on.
    - **The ends:** after a FATAL error or Terminate, EOF is the normal end.
    - **Protocol violations** poison the codec (rule 6).
  - **Refused, because a hostile or broken server could exploit them:**
    - AuthenticationOk before the SCRAM proof, which libpq also guards against;
    - a method the caller did not allow, refused before any password is sent;
    - a second authentication request;
    - rows without a RowDescription, or after their statement's end;
    - a ReadyForQuery that ends rows without their CommandComplete;
    - any message after the session's end;
    - messages over `max_message`, refused from the length field alone.
  - **Tests** (33 across three files) are written against the Python oracle, and the SCRAM client also against RFC 7677's example.
    - `drive_chunked` replays whole sessions in every split: a startup with notices, pipelined results with errors, a SCRAM exchange.
    - 3000 mutated transcripts each end in events or an `IoError`, never a crash.
    - **Planted bugs:** 59 across the three modules, all caught. The first run let 3 through: a forged NegotiateProtocolVersion, a repeated parameter whose case differs, and a NULL length loosened to -2. Each now has a test.
  - **Measured on a quiet core of an i5-1145G7:** a DataRow of three small values (35 bytes) takes about 70 ns end to end, about 14 M rows/s or 500 MB/s.
    - Checking a row's values takes 15–20 ns.
    - Copying the body into the reused event takes about 10 ns: `List.extend` is a memcpy.
- **P3: the blocking client.** Done.
  - **`pg.config`:** `Config`, and `Config.parse` for libpq-style URIs.
    - It reads the parts and parameters libpq does, percent-decoded.
    - It refuses what it cannot honour: TLS requirements and host lists (`Unsupported`), unknown parameters and malformed parts (`InvalidInput`), as libpq refuses them.
  - **`pg.client`:** `Client` over `net`, with TCP by name (Happy Eyeballs) or the Unix socket.
    - **Calls:** `connect`, `query`, `simple_query`, `execute`, `cancel`, `close`.
    - **Results:** `Rows` keeps every row's body in one buffer, plus offsets.
    - **Errors:** `PgError` carries the transport's `IoError`, the server's error, or both (a cancelled query).
  - **Deadlines:**
    - `connect_timeout` covers the opening.
    - A query's `timeout` ends with a cancel. The client waits for the server to close the cancel connection, so a cancel arriving late cannot hit the next query, then drains to ReadyForQuery.
  - **Tests:** 11 against PostgreSQL 18.6 (`tests/pg/test_client.mojo`), plus 4 on URIs.
    - Every authentication method over TCP and the Unix socket, each with `allow` limited to that method, so the exchange really is MD5 or SCRAM.
    - The refusals: a wrong password, a method not allowed, no password, no such database or user.
    - Values, NULLs, several statements, row counts, and server errors with their fields (position, constraint), all of which keep the session.
    - The transaction status through a failed transaction, notices, LISTEN and NOTIFY.
    - 100,000 rows; a deadline that cancels `pg_sleep(30)` within 300 ms.
    - COPY FROM STDIN refused; application_name and run-time parameters.
    - A session ended by `pg_terminate_backend`, a server that stops, and a connect deadline against a listener that never answers.
  - **Planted bugs:** 32, all caught. The first run let one through, a URI with no scheme, which now has a test.
    - In URI parsing: the scheme, a second `@`, ports, escapes, NULs, UTF-8, TLS settings, `require_auth`, host lists.
    - In the client: the cancel, value offsets, integers and booleans, the last statement's result, row counts, the Unix socket, server errors at startup and in queries, notices, a closed connection, empty queries.
  - **Measured** over the Unix socket, with client and server on one laptop:
    - `SELECT 1` round trips run at about 55,000 a second (18 µs each). pgbench, using libpq's simple protocol, does the same.
    - A million rows (an integer and a 32-character text) arrive in about 1 s, as with psql. That is the server's time.
  - **Example:** `examples/pg/query.mojo` runs SQL from the command line and prints every result.
- **P4: the extended query protocol.** Done.
  - **Messages:** `pg.message` builds Parse, Bind (with each value in text or binary form, and the format codes as short as the mix allows), Describe, Execute, Close, Sync and Flush. `Params` holds the values and their declared types.
  - **The codec's requests:**
    - `execute(sql, params)` uses the unnamed statement: Parse, Bind, Describe, Execute and Sync, in one round trip.
    - `prepare(name, ...)` makes a prepared statement and reports its parameter types and columns; `execute_prepared` and `close_statement` use and drop it.
    - Each request is queued whole or not at all, and requests pipeline: one cycle per Sync.
  - **The codec's events:** PARSE_COMPLETE, BIND_COMPLETE, CLOSE_COMPLETE, NO_DATA, PARAMETER_DESCRIPTION and PORTAL_SUSPENDED.
    - The RowDescription of a prepared statement is told apart from a portal's: no rows follow it.
    - An error skips to the cycle's Sync.
  - **COPY FROM STDIN in an extended cycle:** the server skips Sync while in copy-in mode, so after our CopyFail it waits for another. The codec sends it, as libpq does. Without it the session hung; the real-server test found this, the oracle did not.
  - **The client:**
    - `query` and `execute` take `Writable` arguments and send them in text form; `query_params` takes a `Params`.
    - They run one statement, with several refused by the server (42601).
    - `simple_query` stays for scripts.
  - **Tests:**
    - 8 on the codec against the oracle: what is sent, each cycle's events, errors and pipelining, violations, requests refused whole, and `drive_chunked` over a prepared exchange.
    - Against PostgreSQL: integers, floats, booleans and text through parameters; an injection attempt returned as a plain value; NULL and bytea through `Params`; and the server's refusals (08P01 for a missing value, 22P02, 42601), each leaving the session usable.
    - **Planted bugs:** 27, all caught. The first run let one through: Parse's parameter limit. Only `prepare` depends on it, since Bind checks the same limit, and it now has a test.
  - **Measured on a quiet machine** over the Unix socket:
    - `SELECT 1` takes 13.4 µs through `simple_query` (pgbench's simple mode: 13.2), and 16.5 µs through `query` (pgbench's extended mode: 15.0).
    - The extended path costs about 1 µs more client CPU than the simple one: 5.3–5.9 µs per query against 4.2–4.9, syscalls included.
    - **Lead:** each receive first tries a `recv` that returns EAGAIN, since the answer to a just-sent query cannot be there yet.
- **P5: types and a statement cache.**
  - **Binary results** for bool, the integers, the floats, text, bytea, uuid, date and the timestamps, with numeric as text, and typed accessors for them.
  - **A statement cache per connection:** prepare and describe once per SQL text. The parameters are then encoded for their types, and the results requested in binary where the type allows.
- **P6: transactions, a pool, LISTEN/NOTIFY.**
  - **Transactions:** a scope that rolls back on error.
  - **Pool:** connections are health-checked and reset before reuse.
  - **Notifications:** delivered between queries, and waited for with a deadline.
  - **COPY**, if needed.
- **P7: review and polish.**
  - Independent reviews, with a regression test for each finding.
  - Performance measured against libpq.
  - Examples, and the guide.
