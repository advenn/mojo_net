# redis: the Redis client

A client for Redis and the servers that speak its protocol (Valkey, and others), in native Mojo on Linux, speaking RESP2 and RESP3 without hiredis. It is the second of the roadmap's database drivers, after `pg` (`docs/pg.md`). Package rules and the shared contracts are in `docs/design.md`; the transport is `net` (`docs/net.md`).

**Status: R1–R3 done:** the sans-I/O RESP codec, a blocking client tested against Valkey 9.1, pipelines, transactions and typed helpers. Next is R4: pub/sub.

## Scope
**In scope:**
- connecting over TCP (by name, with Happy Eyeballs) or a Unix-domain socket;
- RESP3, with RESP2 for servers and proxies that do not speak it;
- authentication (`AUTH`, ACL users), a database index, a client name;
- any command, with arguments sent as bulk strings (never spliced into a line);
- typed replies: strings, integers, doubles, booleans, nulls, big numbers, arrays, maps, sets, errors;
- pipelining, transactions (MULTI/EXEC, WATCH), and pub/sub on a dedicated connection;
- a deadline per call, a pool, and connection URIs (`redis://`, `unix://`).

**Out of scope for now:**
- **TLS** (`rediss://`): `net` has no TLS yet, so it is refused, not ignored.
- Cluster (MOVED/ASK redirects) and Sentinel: their errors reach the caller as server errors.
- Client-side caching (CLIENT TRACKING), MONITOR, and RESP3's streamed strings and aggregates, which no server sends.
- An async API (no async/await yet; see `docs/design.md`).

## Decisions
- **Sans-I/O.** The protocol logic is a `Codec` (design contract 1): it encodes commands, parses replies and matches them to commands, and never touches a socket or a clock. Only the modules that do I/O import `net` (`SANS_IO` in `tools/check_imports.py`).
- **A reply is one flat tree.** A RESP value can nest (an array of maps of arrays). It is kept as one list of nodes in pre-order, each with its kind, its bytes in one shared buffer, and for an aggregate its child count and subtree size, so that a sibling is one jump away. A reply of a million elements is a few large allocations, not a million small ones, and the codec hands it over without a copy.
- **The parser resumes.** A reply that arrives in pieces is parsed as it comes: what is complete is kept, with a stack of the aggregates still open, and a bulk string's bytes are copied out as they arrive. So the input buffer holds at most one unfinished line, and a reply in a thousand pieces is parsed once, not a thousand times.
- **Limits, checked from the header alone:** a bulk string's length (512 MiB by default, the server's own limit), an aggregate's element count, nesting depth, and a line's length. The server or anything between could otherwise make the client allocate without bound.
- **RESP3 first.** The client asks for RESP3 (`HELLO 3`), which types its replies (maps, doubles, booleans, nulls) and carries out-of-band data as push messages. A server without `HELLO` (before Redis 6) gets RESP2, and so can a caller, for proxies that only pass RESP2.
- **Pushes are kept aside.** RESP3 push messages can arrive between any two replies. They are never taken for a reply; the client keeps them for the caller.
- **Pub/sub has its own connection.** A subscribed RESP2 connection can only (un)subscribe and ping, and SUBSCRIBE's confirmations do not pair with commands the way replies do. So `Client` refuses the subscribe commands, and a `Subscriber` runs them on a connection of its own. Likewise refused: `CLIENT REPLY OFF|SKIP` (replies would stop pairing with commands) and `MONITOR`.
- **A deadline that passes closes the connection.** Redis cannot cancel a command, and its reply would still come and pair with the next command. So a call whose deadline passes closes the connection, as `http.client` does.
- **Server errors are data.** An error reply raises `RedisError` with the error's code (its first word: `ERR`, `WRONGTYPE`, `NOAUTH`, ...) and leaves the connection usable. Errors inside an aggregate (EXEC's results) are values.
- **Passwords travel in clear,** without TLS: use a Unix socket, a trusted network or a TLS-terminating sidecar.

## Testing
- **The oracle:** `tests/redis/resp_oracle.py`, a RESP2/RESP3 encoder and decoder in Python, written from the specification independently of `src/redis`. It makes server transcripts and reads what the client sent.
  - Random values are encoded by the oracle, fed to the codec in random pieces, and compared by their rendering (differential testing). Mutated inputs must end in events or an error, never a crash; `drive_chunked` replays transcripts in every split (contract 1, rule 4).
- **A real server:** `valkey-server` from conda-forge (test-only, BSD-licensed, and it speaks Redis's protocol). A throwaway server per test, on a free port and a Unix socket, with ACL users; a watcher stops it if the test process dies. `DEBUG PROTOCOL` makes it send each RESP3 type, attributes and pushes included.

## Milestones
- **R1: the RESP codec.** Done.
  - `redis.resp`: the value tree (`Value`) and its accessors; the resumable parser for every RESP2 and RESP3 type, with attributes parsed and dropped and the limits above; the command encoder (`Args`, `write_command`), whole or nothing, refusing what a server would not read.
  - `redis.connection`: `RespConnection`, the `Codec` for one connection. Commands pipeline; each reply pairs with the oldest command waiting for one, and push messages come apart. The commands that would break that pairing are refused. EOF is clean only with no reply due.
  - **The accessors read each value across protocols:** RESP2 sends doubles as bulk strings and booleans as integers, so `float()` reads a bulk "1.5" and `bool()` the integer 1. They refuse what is not theirs: `int()` a double or "007" (as INCR does), `float()` a number past a Float64's range.
  - **Tests** (16, in `tests/redis/test_resp.mojo` and `test_connection.mojo`):
    - every type, the accessors, attributes (before a reply, before an element, inside one another, before a push);
    - the limits, each refused from the header alone; 33 malformed values;
    - 400 random transcripts from the oracle, fed in pieces of 0 to 40 bytes; `drive_chunked` over every split of a transcript (rule 4); 600 mutated transcripts, never a crash;
    - a 1 MiB bulk string through the 128 KiB input buffer;
    - what Valkey 9.1.2 sends, recorded: every `DEBUG PROTOCOL` type, HELLO 3's reply, a push after a reply, an EXEC with an error inside, SUBSCRIBE's pushes;
    - the codec: pairing, pushes between replies, the refused commands, QUIT, the ends of a connection, failures that stick.
  - **Planted bugs:** 52, one per check undone, of which the first run caught 48.
    - Four needed tests: the short path's bulk limit (tested only with the header, which takes the long path), a bad CRLF after a bulk string that came in pieces, a map lookup past a key of the same length, and a length with a 9 in it (the encoder's digits).
    - A second run caught all. It also showed that four kills the first run reported as compile errors were crashes on bounds checks, which the runner now tells apart.
  - **Measured** on one core of an i5-1145G7, replies of 100,000 elements fed 64 KiB at a time: 35 ns an element for 10-byte bulk strings, 30 ns for integers. The first version took 60 and 48: it read each line through the input buffer's checked calls. Bulk strings whose bytes are all there and integers now take a short path over the bytes themselves. Encoding `SET key value` takes 150 ns, or 370 ns with its `Args` built each time.
- **R2: the blocking client.** Done.
  - `redis.config`: `Config`, and `Config.parse` for `redis://` and `unix://` URIs, read as redis-cli reads them (a password alone is the default user's). `rediss://` is refused (`Unsupported`), and so is an unknown parameter (`InvalidInput`).
  - `redis.client`: `Client` over `net`, TCP by name (Happy Eyeballs) with keepalive, or a Unix socket.
    - **Connecting:** `HELLO 3` with AUTH and SETNAME, one round trip; for RESP2, or a server without HELLO (it says "unknown command", or NOPROTO), AUTH and CLIENT SETNAME. Then SELECT. A refusal raises with the server's code (WRONGPASS, NOAUTH).
    - **Calls:** `command(args...)`, each argument in its text form, and `command_args(Args)` for bytes, each returning the reply's `Value`. An error reply raises `RedisError` with its code, and the connection goes on. A command the codec refuses raises `InvalidInput` with nothing sent.
    - **Deadlines:** a call whose deadline passes closes the connection, since its reply would pair with the next command. The deadline is checked before each receive, so a reply that keeps coming cannot outrun it.
    - **Pushes** that arrive during a call are kept (`take_pushes`, the newest `MAX_PUSHES`). `check()` reads an idle connection's input without a round trip, for a pool.
  - `examples/redis/cli.mojo`: one command from the command line, and its reply.
  - **Tests** (10 in `tests/redis/test_client.mojo`, against Valkey 9.1.2 from conda-forge):
    - both transports and both protocols, with the shapes each gives (HGETALL's map or array, ZSCORE's double or bulk string);
    - an ACL user through HELLO and through AUTH, WRONGPASS both ways, a read-only user's NOPERM that keeps the connection, the default user's password from a URI (`redis://:pw@`, `unix://pw@`), NOAUTH;
    - a server without HELLO (`rename-command`), as before Redis 6: RESP2, AUTH and CLIENT SETNAME;
    - a database and a client name over both protocols, and settings refused before connecting;
    - all 256 byte values and RESP's own bytes in a value, a 2 MB value, 5000 elements, every type DEBUG PROTOCOL sends, pushes kept up to the cap, EXEC with an error inside;
    - WRONGTYPE and an unknown command keeping the connection; a BLPOP past its deadline closing it; a connection killed by CLIENT KILL; input that never runs dry (`tests/redis/flood_peer.py`, pushes as fast as it can) stopped at its deadline;
    - CLIENT TRACKING invalidations, read by `check()`;
    - URIs: every part, the defaults, IPv6, both password forms, Unix paths with an `@`, and refusals.
  - **Planted bugs:** 35, of which the first run caught 33.
    - Two needed tests. One is the deadline before each receive: a peer that trickled a reply gave the client time to wait, so the call ended either way. `flood_peer.py` sends pushes faster than they are read. The other is an `@` in a Unix socket's path, with no user before it.
    - A second run caught both. The planted bugs that crashed or hung a test left no server behind: each has a watcher.
  - **Measured** on the Unix socket, with client and server on one laptop and the client pinned to one core:
    - PING, SET and GET take 8.2, 8.9 and 8.5 µs a round trip: 122,000, 112,000 and 117,000 a second.
    - Each costs about 4 µs of client CPU, system calls included.
    - `valkey-benchmark` (hiredis) with one connection and no pipelining does 107,000, 102,000 and 93,000 to 103,000 a second.
    - **Lead:** each call builds its `Args` anew (0.2 µs).
- **R3: pipelines, transactions and typed helpers.** Done.
  - **Pipelines:** `Client.run(Pipeline)` sends every command in one write and returns their replies in order. An error reply is a value in its place, since the commands after it ran too. The codec queues the batch whole or not at all (`RespConnection.commands`): one refused command refuses it, with nothing sent. A deadline closes the connection, as for one command.
  - **Transactions:** `Client.transaction(Pipeline)` sends MULTI, the commands and EXEC in one round trip.
    - It returns EXEC's results, as values of their own (`Value.part`), with an error met running a command in its place.
    - It returns None when a key WATCHed before changed, so nothing ran.
    - A command the server refuses while queuing aborts the transaction, and that command's error raises (as redis-py raises it), rather than EXEC's EXECABORT, which does not say which.
  - **Typed helpers** read each reply in either protocol: `get`, `set` (with an expiry, NX, XX), `delete`, `exists`, `incr`, `expire`, `ttl`, `hset`, `hget`, `hgetall` (a map in RESP3, a flat array in RESP2), `hdel`, `lpush`, `rpush`, `lpop`, `rpop`, `lrange`, `sadd`, `srem`, `smembers`, `sismember`, `zadd`, `zscore` (a double, or a bulk string), `zrange`, `publish`.
  - `examples/redis/transfer.mojo`: WATCH, read, MULTI/EXEC, and a retry when another client got there first.
  - **Tests:** 1 more on the codec (batches whole or not at all), and 2 more against Valkey, each over both protocols:
    - pipelines with errors in place, a push among the replies, a refusal that sends nothing, and a deadline;
    - transactions: their results, an aggregate among them, an error met running, an abort while queuing, WATCH both ways;
    - every helper.
  - **Planted bugs:** 24, all caught on the first run. Three of the tests were added when the bugs were written, before the run, for the gaps they would have shown: an aggregate among a transaction's results, a push inside a pipeline, and a deadline during one.
  - **Measured** on the Unix socket, the client pinned to one core, with the machine busy (load 3.6):
    - SET in pipelines of 10: 340,000 to 470,000 a second, against `valkey-benchmark -P 10`'s 433,000.
    - In pipelines of 100: 580,000 to 680,000 a second, with 550 to 660 ns of client CPU each, against `valkey-benchmark -P 100`'s 952,000. Here the client is the bottleneck.
    - **Lead (R5):** each reply is a `Value` of its own, which costs a few allocations; one tree for all of a pipeline's replies would remove them.
- **R4: pub/sub.** `Subscriber`: SUBSCRIBE, PSUBSCRIBE, SSUBSCRIBE and their opposites, messages with a timeout, over RESP3 or RESP2.
- **R5: a pool, examples, and measurements** against `valkey-benchmark`.
- **R6: reviews and polish.** Independent reviews, a regression test for each finding, planted bugs.
