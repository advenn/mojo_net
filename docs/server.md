# server: the HTTP/1.1 server

An HTTP/1.1 server for Mojo on Linux (roadmap step 3). It is built on the `http` library's sans-I/O `ServerConnection` and on `net`'s nonblocking sockets. Package rules and contracts are in `docs/design.md`; HTTP itself is in `docs/http.md`.

**Status: active.** S1 (the serving loop) and S2 (streaming) are done. Of S3, graceful shutdown and lingering close are done; worker processes and signals are next.

## Model
**One thread and one edge-triggered epoll loop per process**, with one `ServerConnection` per connection.
- This is the model `docs/design.md` describes for concurrency without a runtime: no threads, no async.
- For several cores, run N processes on one port with `SO_REUSEPORT`, and the kernel spreads the connections. S3 adds a helper that starts and supervises the processes.

**Handlers.** The application implements `Handler.handle(req, mut res)`. It is called once per request, with the whole request (the body buffered up to `max_body`). Defaulted hooks stream bodies instead, in either direction (see Streaming).
- **Handlers must not block:** the loop serves every connection of the process. Blocking work belongs in another process, or in a future runtime.
- **A trait rather than a function:** Mojo 1.2 function values cannot capture state, and a handler usually needs some (a pool, counters, configuration).

## Behaviour (S1)
- **Requests:**
  - Keep-alive and pipelining; pipelined requests are answered in order.
  - HEAD: a GET handler answers it, and its body is dropped.
  - `Expect: 100-continue` is answered when the body will be accepted.
  - Request bodies are limited to `max_body`. Beyond it the server answers 413, as soon as Content-Length says so.
  - Malformed requests get their status (400, 414, 431, 501 or 505) and the connection closes.
  - A handler that raises gets a 500.
- **Timeouts** (`ServerConfig`), against clients that are slow or stall:
  - `header_timeout`: a request head must arrive within it once it starts, else 408.
  - `idle_timeout`: how long a kept-alive connection may sit idle.
  - `read_timeout`: the most time without progress while a body arrives (408).
  - `write_timeout`: the most time a response may wait on a client that does not read.
- **Backpressure:** a connection reads nothing while its output is pending.
- **Responses** get `Date` and `Content-Length`, and `Server` if configured.
- **Resources:**
  - At start the fd limit is raised and the fd table pre-grown (docs/spikes.md).
  - Above `max_connections`, or on EMFILE, accepting pauses.

## Closing and shutdown (S3)
**Lingering close.** When the server ends a connection, it closes it at once unless the client may still be sending: a request answered before its body arrived (413, 408), requests pipelined after the last response, a malformed request (`ServerConnection.input_pending()`).
- Such a connection closes in stages, as RFC 9112 9.6 describes. The server shuts down its write side after the response, then reads and drops the client's input until the client's end of input, or for at most `linger_timeout` (2 s).
- Closing at once would answer the client's next bytes with a reset, and a reset can erase the response before the client has read it.

**Graceful shutdown.** `Server.shutdown()` begins it, and `step()` (or `run()`, which then returns) carries it out:
1. The connections the kernel has queued are accepted, without the `max_connections` cap, because their clients may have sent requests already. Then the listener closes, and new connections are refused.
2. Each connection first reads what has arrived, so a request already sent counts as in progress. Then `close_gracefully()` stops it taking requests:
   - an idle connection closes now;
   - a request in progress gets its response, the last on its connection, saying `Connection: close` if its head has not gone out yet;
   - requests pipelined after it are not answered, and the client retries them on another connection.
3. `Handler.shutting_down()` is called once. Streams last until `shutdown_timeout` unless they end, so a handler with long-lived ones (server-sent events) ends them there by waking them.
4. After `shutdown_timeout` (10 s), whatever is left closes. `stopped()` is True once no connection is left.

The trigger (SIGTERM, or a supervisor) is the rest of S3.

## Streaming (S2)
The `Handler` hooks beyond `handle` all have defaults, so a handler that buffers needs none of them.

**Request bodies.** `stream_request(req)` is asked at each request's head.
- If it returns True, the body goes to `on_body(req, data)` piece by piece as it arrives, without `max_body`. `handle` follows at the body's end, with `req.body` empty.
- `read_timeout` still applies between pieces, and `Expect: 100-continue` is answered as for a buffered body.

**Responses.** `handle` calls `res.stream()`, and the head goes out at once.
- **Framing:** chunked, unless the handler set Content-Length; then `produce` must give exactly that many bytes, or the connection closes.
- **The body comes from `produce(req, mut out)`.** The server asks for more while less than 64 KiB of the connection's output is queued, so a stream goes at its client's pace. A connection holds about 64 KiB, plus one piece; keep pieces small (64 KiB, say).
- **The end:** returning False ends the stream: the last chunk goes out, and the connection serves its next request.
- **Pausing:** appending nothing and returning True pauses the stream. Nothing more is asked until its connection is woken:
  - `Request.id` names the connection. It names that connection while it lives and never another one.
  - `Server.wake(id)` wakes it from outside the handler (between `step`s). `take_wakes()` returns the ids a handler collected during its own calls; the server asks after every call into the handler.
  - A wake is served in the next turn, which then does not wait for readiness. Wakes for closed connections, or for streams that are not paused, are ignored.
  - Server-sent events and long polling work this way: a subscriber's stream pauses until something for it arrives. In `tests/server/test_streaming.mojo`, events published by other connections' requests wake the subscribers.
  - A stream that wakes itself every time keeps the loop busy, but other connections are still served, since wakes wait for the next turn.
- **HEAD** gets the head only, with the fields its GET gets (`Transfer-Encoding: chunked`), and `produce` is never called. So do 204 and 304.

**Ends and errors.**
- A paused stream lasts as long as its handler wants: the header, idle and read timeouts do not apply to it, and the write timeout applies while its output waits.
- A client that closes or half-closes its side while its stream is paused ends the stream, as nginx does. This also holds when the client's pipelined requests fill the codec, so that no read can see the end of input: epoll's hangup flag tells instead.
- An error from `stream_request` or `on_body` answers 500, ignores the rest of the request, and closes the connection after the response (unless the rest is short enough to drain).
- An error from `produce` cuts the response: the connection closes, and the client sees an incomplete body.

## Milestones
- **S1: the serving loop.** Done.
  - `Server[H: Handler]` with `ServerConfig`, `Request` and `Response`, and the behaviour above. `run()` loops forever; `step(timeout)` runs one turn, for tests and for embedding the server in another loop.
  - **Tests:** end to end against Python's `http.client` and raw sockets (`tests/server/test_server.mojo`). Covered: keep-alive, HEAD, both request framings, pipelining, `100-continue`, body limits, handler errors, malformed requests, every timeout, a client that does not read, and the connection cap. The `Date` formatting is checked against Python's `formatdate`. A planted-bug run over the loop found one gap, now tested.
  - **Backpressure for pipelined requests:** that gap was real. A connection answered every buffered request before writing, so 20 pipelined requests for 8 MiB each queued 64 MiB. It now stops answering once 64 KiB is queued, and resumes when the client has taken it.
  - **Clock reads:** every one is a syscall without libc (161 ns, against 17 ns through the vDSO; docs/spikes.md). The loop reads the clock once per turn, and the `Date` field is reformatted once a second.
  - **Measured** with `examples/server/hello.mojo` and `bench/http/load.mojo`, one core each, while another heavy job shared the machine:

    | Load | Throughput | CPU per request, vs `examples/http/hello_server.mojo` on the bare codec |
    |---|---|---|
    | 50 keep-alive connections | ~116–123k req/s | ~8.0–8.4 µs vs ~6.2–6.7 µs |
    | 16 pipelined per connection | ~640k req/s | ~1.5 µs vs ~1.1 µs |
- **S2: streaming.** Done: the hooks above (`stream_request`/`on_body`, `res.stream()`/`produce`, pause and wake with `Request.id`, `Server.wake` and `take_wakes`).
  - **Tests** (`tests/server/test_streaming.mojo`), against Python clients:
    - a 32 MiB chunked upload with `max_body` at 1 KiB;
    - a 32 MiB download to a slow reader with a 64 KiB receive buffer, whose queued output stays under 1 MiB; a stream with the handler's Content-Length;
    - HEAD on a stream, on a keep-alive connection: the next response follows its head at once;
    - server-sent events woken by other connections, and by `wake` between steps (served without waiting);
    - a paused stream that outlives 200 ms timeouts;
    - a stream that keeps waking itself while another connection is served;
    - clients that leave a paused stream, including behind a full receive buffer;
    - failing hooks.
  - **Planted bugs:** 9 of the first 10 were caught. Two of them made a stream spin forever on a client's end of input, and the abandoned-stream test catches both. The survivor (paused streams timing out) is now tested.
  - **Found and fixed while reviewing:**
    - a handler that woke its own stream spun inside one `step`;
    - a wake between steps waited out the step's timeout;
    - a client that left behind a full receive buffer was not seen;
    - a streamed HEAD response lacked its GET's `Transfer-Encoding`.

    Each has a test, checked to fail on the old code.
- **S3: processes and shutdown.**
  - **Part 1, done:** graceful shutdown and lingering close (above), with `ServerConnection.close_gracefully()` and `input_pending()` in the codec.
    - **Tests** (`tests/server/test_shutdown.mojo`, plus codec cases): idle connections closed; an upload in progress answered with `Connection: close` and the request pipelined after it dropped; connections the kernel had queued accepted and answered; the listener gone; a stream ended by the hook, or cut at the timeout; a client still sending after its 413 gets an orderly end of input, not a reset; lingering ends at its timeout; a connection with nothing unread closes at once.
    - **Planted bugs:** 19 of 20 caught. The survivor only costs time: lingering after an end of input that was already read.
  - **Part 2, next:** start N worker processes on one port, restart those that die, and stop them all gracefully on SIGTERM.
    - The Mojo runtime starts its threads before `main`, with the signal mask the process was started with. A signalfd therefore receives SIGTERM reliably only if the signal was blocked at exec. The 30-run spike, recorded in `docs/spikes.md`, shows this.
    - The plan: block the signals and re-execute the program once, read them from a signalfd in the loop, and spawn workers with `clone3` and `execve`, using pidfds and a lifeline socketpair per worker.
- **S4: routing.** Method and path routes, path parameters, and static files.
- **S5: polish.** Interop, an independent review, benchmarks, and the guide.
