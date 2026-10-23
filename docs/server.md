# server: the HTTP/1.1 server

An HTTP/1.1 server for Mojo on Linux (roadmap step 3). It is built on the `http` library's sans-I/O `ServerConnection` and on `net`'s nonblocking sockets. Package rules and contracts are in `docs/design.md`; HTTP itself is in `docs/http.md`.

**Status: active.** S1 (the serving loop) and S2 (streaming) are done; S3 (processes) is next.

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
- **S3: processes.** Start N workers on one port and restart them if they die; graceful shutdown (stop accepting, finish in-flight requests, close idle connections).
- **S4: routing.** Method and path routes, path parameters, and static files.
- **S5: polish.** Interop, an independent review, benchmarks, and the guide.
