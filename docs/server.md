# server: the HTTP/1.1 server

An HTTP/1.1 server for Mojo on Linux (roadmap step 3). It is built on the `http` library's sans-I/O `ServerConnection` and on `net`'s nonblocking sockets. Package rules and contracts are in `docs/design.md`; HTTP itself is in `docs/http.md`.

**Status: active.** S1 (the serving loop) is done; S2 (streaming) is next.

## Model
**One thread and one edge-triggered epoll loop per process**, with one `ServerConnection` per connection.
- This is the model `docs/design.md` describes for concurrency without a runtime: no threads, no async.
- For several cores, run N processes on one port with `SO_REUSEPORT`, and the kernel spreads the connections. S3 adds a helper that starts and supervises the processes.

**Handlers.** The application implements `Handler.handle(req, mut res)`. It is called once per request, with the whole request (the body buffered up to `max_body`).
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
- **S2: streaming.** Request bodies and responses that are not buffered whole: large uploads, chunked and server-sent-event responses.
- **S3: processes.** Start N workers on one port and restart them if they die; graceful shutdown (stop accepting, finish in-flight requests, close idle connections).
- **S4: routing.** Method and path routes, path parameters, and static files.
- **S5: polish.** Interop, an independent review, benchmarks, and the guide.
