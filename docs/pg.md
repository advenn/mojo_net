# pg: the PostgreSQL driver

A PostgreSQL client for Mojo on Linux, speaking the frontend/backend protocol (version 3.0) natively, without libpq. It is the first of the roadmap's database drivers. Package rules and the shared contracts are in `docs/design.md`. The transport is `net` (`docs/net.md`), and the authentication primitives are `crypto`.

**Status: P1–P7 done:**
- the cryptographic primitives;
- the sans-I/O codec for a session (`PgConnection`);
- a blocking client (`pg.client`), tested against PostgreSQL 18;
- the extended query protocol: parameters and prepared statements;
- types: binary values for the common types, typed accessors, and a statement cache;
- transactions, waiting for notifications, and a pool of sessions;
- three independent reviews, with every finding fixed and a regression test for each.

Leads: COPY (refused with CopyFail for now), TLS once `net` has it, protocol 3.2, full SASLprep.

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
- **Protocol 3.0.** Every supported server speaks it. Protocol 3.2 (PostgreSQL 18, longer cancel keys) can come later. The client asks for 3.0 and sends no protocol options (`_pq_.` parameters are refused), so a server has nothing to negotiate: a NegotiateProtocolVersion is refused (`InvalidData`), as libpq refuses one that asks for no change.
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
- **The session's settings.** The client's strings are UTF-8, and it reads the text forms of dates, floats and bytea, which depend on the session. So the startup message asks for `client_encoding=UTF8`, and `Config.startup` adds `DateStyle=ISO`, `extra_float_digits=3` (a float's text keeps every bit) and `bytea_output=hex` unless the caller set them. A role's or the server's defaults (`ALTER ROLE ... SET datestyle`) cannot change them then. A DateStyle whose output is not ISO is refused, and a session switched to another client_encoding (`SET client_encoding`) is ended (`Unsupported`), since every text value would be garbled both ways.
- **Bounds on what a server sends.** Messages are refused from their length field alone: past `max_message` (1 GiB) once authenticated, and before that past libpq's bounds (2000 bytes; 30000 for an error), since a server, or anything between before TLS, could otherwise make the client allocate without limit. More than 256 distinct ParameterStatus names are refused too, and past `MAX_NOTICES` (1024) the oldest notices kept are dropped.

## Testing
- **P2:** the Python oracle `tests/pg/pg_oracle.py`, written from the protocol documentation independently of `crypto` and `pg`.
  - It builds backend messages, parses what the client sent, and runs the server side of MD5 and SCRAM with hashlib and hmac.
  - Its transcripts are replayed in every split (`drive_chunked`), and mutated ones must end in events or an error, never a crash.
- **From P3:** a real PostgreSQL, `postgresql` from conda-forge (a pixi dependency, test-only like Python).
  - **Clusters:** `tests/pg/pg_cluster.py` makes a throwaway one per test, in under a second: `initdb` in a temp directory, durability off, a Unix socket in that directory and a free port on 127.0.0.1. `tests/pg/pg_server.mojo` starts and stops it; a test stops it whatever happens, and a watcher process stops it once the test process has ended without doing so (a crash, a timeout).
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
  - `Rows` has `columns`, `tag`, and per value `is_null`, `value` (the bytes as they came) and the typed accessors. A row or column out of range raises `InvalidInput`.
    - **The accessors:** `text`, `int`, `float`, `bool`, `bytes` (bytea), `date` (`pg.types.Date`), and `timestamp` (microseconds since 1970, UTC for timestamptz).
    - **Either form:** they read the binary or the text form alike, and `text` gives the server's own text for either.
    - **Each reads its own types:** `int` integers (and numerics or text holding one; not floats), `float` floats, integers and numerics (one past a float's range raises, as the server's cast does), `bool` booleans, `bytes` bytea.
- **The statement cache** (`Config.statement_cache`, 256 by default; `statement_cache_capacity` in a URI):
  - The first run of a SQL text prepares it, which costs one extra round trip and tells the column types. Every later run is one round trip without the server's parse, with binary results where `pg.types` reads them (`SELECT 1` takes 11.5 µs, against 13.5 µs through the simple protocol).
  - The key is the SQL text with the parameter types `Params` declares, which the prepare sends; types left at 0 go to the server.
  - The least recently used statement goes first when the cache is full, closed on the server too.
  - **A statement gone stale is prepared afresh and run once more, outside a transaction,** since nothing ran: when a cached plan's result type changed (after `ALTER TABLE`: 0A000 from `RevalidateCachedQuery`; another 0A000 is raised as is), or when the server dropped the statement (26000, after a `DEALLOCATE`). `DISCARD ALL` and `DEALLOCATE ALL` empty the cache.
  - Statement names are "mojo_", random hex and a counter, so they meet no statement the session had already (`PREPARE`, a pooler's).
  - 0 turns the cache off: each query then uses the unnamed statement, with text results, as PgBouncer's transaction pooling needs.
- **Errors raise `PgError`.**
  - A server error (`is_server()`, the SQLSTATE in `code()`, every field in `server()`) leaves the session usable.
  - Anything else closes it: a transport or protocol error, or the server ending the session.
- **A query's `timeout`** bounds it, rows still coming included:
  - When it passes, the query is cancelled. The client sends a CancelRequest on a new connection, to the address the session is connected to (not the host name resolved again), and waits until the server has taken it, as libpq does.
  - The session stays usable, and the error says `is_deadline()`, with the server's 57014 attached.
  - The cancel and the query's end share `CANCEL_GRACE`. If the query has not ended by then, or a cancel went out but was not seen through (it could land on the next statement), the connection is closed.
- **TCP keepalive** is on (`Config.keepalive`): probes after 30 s of silence and a user timeout, so a server that vanished is noticed within about a minute.
- **Transactions:**
  - `begin()`, `commit()` and `rollback()`. `commit()` raises when the server rolled a failed transaction back instead (`E_ROLLED_BACK`).
  - `savepoint(name)`, `rollback_to(name)` and `release(name)`, the name quoted as an identifier. `transaction_status()` follows each.
- **Notifications:** after `execute("LISTEN channel")`, `wait_notification(timeout)` returns the next one: one received during a query already, or the first to arrive. None when none came in time, and the session goes on.
- **A pool** (`pg.pool.Pool`): `acquire()` hands out a session, and `release(db^)` takes it back.
  - **Kept:** a session that is usable, idle outside a transaction, while there is room (`max_idle`). Anything else is closed.
  - **Checked** before it is handed out again (`Client.check()`, without a round trip): one the server ended meanwhile is replaced.
  - **Session state** (SET, temporary tables, LISTEN, prepared statements) stays with the session.
- **On the side:** `take_notices()`, `take_notifications()`, `parameter(name)`, `cancel()`.

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
- **Server errors are events.** `poll` raises only when the connection can no longer be used: the server broke the protocol, authentication was refused, or EOF came while the session was open. EOF after a FATAL error, or after `terminate()` once the queries queued before it were answered, is the normal end. Once `poll` raised, `is_open()` is false and requests raise the same error.
- **The session's state:**
  - `is_idle()`;
  - `transaction_status()` (`IDLE`, `IN_TRANSACTION`, `FAILED_TRANSACTION`);
  - `parameter(name)`, the values from ParameterStatus;
  - `backend_key()`, for a CancelRequest on a new connection (`write_cancel_request`).

## Modules
- **`message`:** the wire format.
  - Frontend messages are built into a `ByteBuffer`, whole or not at all. They refuse NUL bytes, and messages longer than the server reads (the startup packet's 10000 bytes; Query, Parse and Bind up to 1 GiB; Describe and Close up to 10000 bytes, which bounds statement names).
  - Backend bodies are checked once, when they arrive. `ServerMessage` reads the fields of an error or notice, `Column` those of a RowDescription.
- **`auth`:** the MD5 answer, and `ScramClient`, the client side of SCRAM-SHA-256.
- **`connection`:**
  - `PgConnection` is the `Codec` for one session: startup and authentication, the simple query flow, and the session's state.
  - `Startup` holds the settings, and `AuthMethods` the methods a server may ask for.
  - `PgEvent` and `EventKind` are the events.
- **`config`:** `Config`, from code or a connection URI, with the settings a session needs.
- **`client`:** the blocking `Client`, `Rows` and `PgError`. It is the only module that imports `net`, and is not re-exported from `pg`.
- **`pool`:** `Pool`, sessions kept for reuse: `acquire`, `release`, `close`.
- **`types`:** the OIDs of the built-in types, and which of them travel in binary form. It also holds their binary forms, the server's text for them, and parsers for the text forms of dates, timestamps and bytea. `Date` is a calendar date.

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
- **P5: types and a statement cache.** Done.
  - **`pg.types`:** binary forms for bool, the integers and oid, bytea, uuid, date, time, timestamp and the text types.
    - It writes the server's own text for each: ISO dates with BC years, the infinities, fractions without trailing zeros, the whole range up to 294276 AD.
    - It parses the text forms of dates, timestamps and timestamptz (offsets such as `+05:30`) and bytea.
    - The floats, timestamptz, numeric and the rest stay in text, where the text is exact or depends on the session.
  - **`Rows`:** typed accessors, which raise `PgError` like the rest of `pg.client`.
  - **The client's statement cache:** described above; `cached_statements()` says how many statements it holds.
  - **Tests:**
    - **`tests/pg/test_types.mojo`:** 3000 random dates and 3000 random timestamps against Python's datetime, for the binary form, the text written and the text parsed.
    - **Against PostgreSQL, binary against text:** the client's text of each binary value equals the server's own text for the same value. That covers each type's limits (int8's, 5874897 AD, 294276 AD, BC dates, the infinities, the text types), plus 2000 random dates and 2000 random timestamps.
    - **Typed accessors** in either form.
    - **The cache:** reuse, least-recently-used eviction checked in `pg_prepared_statements`, the 0A000 retry and its refusal inside a transaction, a refused statement evicting nothing, and the cache turned off.
    - **Bugs the tests found:** int8's limit overflowed when counted from 1970. A failed prepare evicted a cached statement first. And text columns, which arrive in binary form, were refused by the date and timestamp accessors.
    - **Planted bugs:** 31, of which the first run caught 29.
      - One was equivalent: Mojo's `Int(UInt64)` already keeps the bits, so the signed cast it removed changed nothing.
      - One showed dead code: `atof` reads NaN and the infinities itself, so those special cases are gone.
      - One, freed cache slots never reused (a leak in long sessions), needed a white-box test, now there.
  - **Measured on the Unix socket:**
    - `query("SELECT 1")` runs at about 86,000 a second (11.5 µs), against pgbench's prepared mode at 92,900 and our P4 unnamed path at 59,000.
    - With a parameter, it runs at about 81,000 a second.
- **P6: transactions, a pool, LISTEN/NOTIFY.** Done.
  - **Transactions:** `begin`, `commit` (which raises when a failed transaction was rolled back instead, as pgx does), `rollback`, and savepoints with quoted names.
  - **Notifications:** `wait_notification(timeout)` returns one queued during a query, or waits on the socket. When the time is up it returns None: nothing was in flight, so the session is intact.
  - **Health:** `Client.check()` reads what an idle session received without a round trip. A FATAL error (a terminated backend, an idle timeout) or a closed socket ends the session.
  - **`pg.pool.Pool`:** LIFO reuse of checked sessions, up to `max_idle`. Sessions in a transaction are not kept; queued notices and notifications are dropped on release.
  - **Tests** against PostgreSQL:
    - commit and rollback, and a nested `begin` refused;
    - a failed transaction's COMMIT, and a savepoint that rescues one;
    - notifications from a second session, a wait that times out, and one that came during a query;
    - the pool's reuse order, `max_idle`, transactions kept out, and a pooled session terminated by `pg_terminate_backend` and replaced on `acquire`.
  - **Planted bugs:** 12, of which the first run caught 10.
    - One was equivalent: after a FATAL error the session has ended, so `check()` refuses it even without its explicit test for errors.
    - One needed a stronger test. A backend killed outright sends nothing, and only its socket closes. The test kills one with SIGKILL (the cluster's `CHECKPOINT` after setup keeps its users through the crash recovery), and its retry loop no longer hides a dead session handed out.
  - **Not done:** COPY, which stays refused (CopyFail), a lead for later. So is a scope that rolls back by itself on an error, which needs `with` support or function values that capture the client.
- **P7: reviews and polish.** Done.
  - **Three independent reviews,** each by an agent that had not written the code: values and types; the client, its configuration and the pool; the wire protocol, the session codec and authentication. Each finding has a regression test that failed before its fix: `tests/pg/test_pg_regressions.mojo` (no server needed) and `tests/pg/test_pg_regressions_client.mojo` (against PostgreSQL).
  - **The serious ones:**
    - **Results one query behind.** A COPY FROM STDIN that fails before it reads (into a view, with FREEZE, from a statement trigger) leaves copy-in mode at once. Our first Sync then ends its cycle, and the Sync sent after the CopyFail draws a second ReadyForQuery. That one ended the next cycle, so every later query got the previous one's rows, while the session looked healthy and went back to a pool. The codec now keeps that Sync in its line of cycles. A ReadyForQuery that comes while it is at the head is its own and is dropped; any other message shows it drew none, since every cycle has a message before its ReadyForQuery.
    - **Settings from the role.** The text forms the client reads depend on DateStyle, extra_float_digits and bytea_output, which a role or the server may set. `ALTER ROLE app SET datestyle = 'SQL, DMY'` broke every date, and `extra_float_digits = 0` dropped float bits. The client now sets all three at startup (see the decisions above), and ends a session switched to another client_encoding.
    - **Cancels.** A cancel went to the host name resolved again, maybe to another server. One that was not seen through left the session open, where it could cancel the next statement. Cancels now go to the session's address, and one sent but unconfirmed closes the session.
    - **A deadline that rows outran.** A receive waits, and so checks the deadline, only when nothing is queued: a query whose rows kept coming was never stopped. The client checks the deadline before each receive.
    - **Memory before authentication.** A server, or anything between (there is no TLS), could send 1 GiB messages before AuthenticationOk, and SCRAM's parsing took 16 bytes per comma of one: tens of GiB. libpq's bounds now apply, and ScramClient reads only the attributes it needs.
    - **A half-written request.** A request that did not fit the transmit buffer (64 MiB) left its type byte and length queued, and the next request went out as the rest of its body: the session hung. Every builder now writes its message whole or not at all, refuses one longer than the server reads (`InvalidInput`, where the server would close the connection without a word), and the codec queues requests up to the server's 1 GiB.
  - **The rest:**
    - **Values:** timestamps past what microseconds since 1970 hold (PostgreSQL goes to 294276) wrapped, or landed on the infinity sentinels; impossible dates (February 30, year 0) and hours (24:30) were taken; offsets of three-digit hours (POSIX time zones) were refused; bytea in escape form was refused; `"char"` in binary form was not written as the server writes it, and now comes in text form; `int()` refused int8's extremes in text, and took floats; `bool()` took any byte; `float()` refused binary integers, read float4 text as a float8, and made numerics past a float's range into infinities; a result with no columns had no rows; an index past the end read another row.
    - **The cache:** declared parameter types were neither sent nor part of the key; `DISCARD ALL` and `DEALLOCATE` left it naming statements the server no longer had; any 0A000 ran the statement a second time, a function's own error after its side effects included.
    - **The session:** keepalive was off; notices piled up without bound; statement names could meet ones made with `PREPARE`; `begin()` on an ended session said a transaction was open; `Pool.opened()` counted connects that failed.
    - **URIs,** now read as libpq reads them: `[]` is no host, an empty `host=` the default, a repeated parameter its last value; `gssencmode`, `client_encoding` (UTF8 only) and `ssl=true` (`Unsupported`) are known.
    - **The codec:** a second RowDescription before CommandComplete was taken; ParameterStatus names had no bound; a failed `poll` left the event's new body under its old kind; `is_open()` stayed true after a failure; messages after a FATAL error were taken, and EOF after Terminate was clean with queries unanswered; a NUL in the password was found only when the server asked for it; statement names too long for the server's Describe and Close were sent; NegotiateProtocolVersion was taken, though nothing was asked; SCRAM user names were written as Latin-1.
  - **Not changed:** a server may choose a SCRAM iteration count of 1, which makes guessing the password from a captured exchange cheap. libpq and PostgreSQL accept any count too; a minimum is a lead, with TLS.
  - **A bug in the fixes:** re-reading them turned up one more. Before authentication, a `max_message` under libpq's 2000 bytes was not honoured, so such a message could never fit the receive buffer. It has a test too.
  - **Planted bugs:** 66, one per fix undone. The first run caught 61, but four of those counted for nothing: they were credited to a test file that failed without any mutation (`test_config.mojo`, whose expected startup message predated the new settings). Updated, with each test file now checked to pass before any mutant is judged by it, it catches all four.
    - Two were equivalent, and showed code to remove. Once each message reserves its whole room, building a Query apart before it joins the queue changed nothing. And a cancel not seen through spends the whole grace, so the collect after it already closes the session.
    - Three needed tests: a bytea escape with two octal digits; `DISCARD ALL`, whose tag the 26000 retry hid (now also checked through `DEALLOCATE ALL` in a transaction, where nothing is retried); and `check()` on an idle session with a notification waiting.
    - A second run of 8 caught all: those three, the reworked cancel, and the bug in the fixes.
    - The mutants that crashed a server test left its cluster running. `pg_cluster.py` now starts a watcher with each cluster, which stops it once the test process has ended.
  - **Measured** on the Unix socket, with client and server on one laptop. The code before and after the fixes was built side by side and run in turns against one server (medians of 8 runs):
    - `SELECT 1` takes 12.0 µs with the cache (pgbench's prepared mode: 10.5) and 13.5 µs through `simple_query` (pgbench's simple mode: 13.1).
    - The fixes cost up to 0.14 µs of client CPU per query: 5.30 µs became 5.44 for `SELECT 1` through the cache, 4.57 became 4.61 through `simple_query`.
    - A million rows of four columns take about 0.9 s, the server's time. The client's CPU is about 200 ns a row with binary results and 220 ns with text, the same as before the fixes.
