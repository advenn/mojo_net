# server: the HTTP/1.1 server

An HTTP/1.1 server for Mojo on Linux (roadmap step 3). It is built on the `http` library's sans-I/O `ServerConnection` and on `net`'s nonblocking sockets. Package rules and contracts are in `docs/design.md`; HTTP itself is in `docs/http.md`.

**Status: active.** S1 (the serving loop), S2 (streaming) and S3 (graceful shutdown, signals and worker processes) are done. Of S4, routing is done; static files are next.

## Model
**One thread and one edge-triggered epoll loop per process**, with one `ServerConnection` per connection.
- This is the model `docs/design.md` describes for concurrency without a runtime: no threads, no async.
- For several cores, run N processes on one port with `SO_REUSEPORT`, and the kernel spreads the connections. `run_workers` starts and supervises them (see Processes).

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

`Server.stop_on(stop)` connects the trigger: a `Stop` from `Stop.on_signals()` or `run_workers` (below).

## Processes (S3)
```mojo
def main() raises:
    var stop = run_workers(WorkerConfig(workers=4))  # or Stop.on_signals() for one process
    if not stop:
        return  # the supervisor: its workers have ended
    var server = Server(App(), ServerConfig(reuseport=True))
    server.bind(SocketAddr.parse("0.0.0.0:8080"))
    server.stop_on(stop.take())
    server.run()  # returns when the shutdown has finished
```
`examples/server/workers.mojo` is this program.

**Call it first in `main`.** Workers are new executions of the program (`/proc/self/exe` with the same arguments and environment, plus `MOJO_NET_WORKER`), so what comes before runs in every process. Run a built binary: under `mojo run`, each execution compiles the program again.

**The supervisor** is the process that calls `run_workers` first:
- **Starting:** it starts `workers` processes (default: one per CPU it may run on). Worker i's runtime starts on the i-th allowed CPU, so it starts one runtime thread instead of one per CPU (docs/spikes.md). Its affinity then widens to all of them, unless `pin`.
- **Restarting:** a worker that ends is restarted after `restart_delay` (100 ms). The delay doubles, up to `max_restart_delay` (10 s), while workers keep ending within a second of starting. Starts, ends and restarts are logged on stderr.
- **Stopping:** on SIGTERM or SIGINT, it closes each worker's lifeline (a socketpair), which asks the worker to shut down gracefully. It waits up to `stop_timeout` (15 s; keep it longer than the workers' `shutdown_timeout`), then kills what is left, and `run_workers` returns None. A second signal kills the workers at once.
- **A worker whose supervisor dies** sees its lifeline close, and shuts down gracefully as well.
- **Ctrl-C in a terminal** signals the whole process group: workers get SIGINT directly too, and treat it like the lifeline.

**`Stop`** is what a server stops on: SIGTERM or SIGINT, and in a worker its lifeline. The first request asks for a graceful shutdown; a signal after it asks to stop at once, closing every connection.

**Signals without handlers.** The library installs no signal handlers, so a stop signal is read from a signalfd. That works only if every thread blocks the signal. The Mojo runtime starts its threads before `main`, with the mask the process was started with; blocking in `main` therefore loses most SIGTERMs to the runtime's handler, which ends the process (25 of 30 runs in the spike, docs/spikes.md).
- So `Stop.on_signals` and `run_workers` block SIGTERM and SIGINT, check every thread's mask in `/proc/self/task`, and if one does not block them, execute the program again: the new image's threads start with the mask.
- Workers inherit the mask from the supervisor and need no second execution.

**In a container**, the supervisor can be PID 1. It handles SIGTERM, so `docker stop` and Kubernetes stop it gracefully. Their kill deadline (Docker: 10 s by default) must exceed `stop_timeout`, or the stop must be configured shorter.

## Routing (S4)
```mojo
struct App(Handler):  # what no route takes, and the streaming hooks
    def handle(mut self, req: Request, mut res: Response) raises:
        res.text(404, "not found\n")


def get_user(mut app: App, req: Request, params: Params, mut res: Response) raises:
    res.text(200, String("user ", params["id"], "\n"))


def main() raises:
    var router = Router(App())
    router.get("/users/:id", get_user)
    router.post("/users", create_user)
    var server = Server(router^)
```
**`Router[A: Handler]`** sends requests to route functions, `def(mut A, Request, Params, mut Response) raises`. Everything else goes to the application `A` itself: requests no route takes, and every streaming and shutdown hook. Parameters come as an argument, because `handle` gets the request immutably.

**Patterns:** "/" and segments.
- Text matches itself.
- `:name` matches one non-empty segment.
- `*name`, last only, matches the rest of the path (one or more segments, an empty one too), joined by "/".

**Matching:**
- The path (the target up to its query, also of an absolute-form target) is split at "/" and percent-decoded segment by segment, so an encoded "/" never splits one.
- The most specific pattern with a route for the method wins: at each segment, text beats a parameter, which beats the rest, with backtracking. So `/users/me` beats `/users/:id`, whatever order the routes were added in, but only for methods `/users/me` has.
- HEAD uses the GET route.
- When the path matches but the method has none: 405 with `Allow`, the union of the methods of every pattern that matches. OPTIONS gets 204 and the same `Allow`.

**Not routed** (the application gets these):
- a segment that decodes to something with "/" or NUL in it;
- an asterisk-form target;
- a path deeper than 128 segments.

A malformed percent-encoding gets 400. Matching is strict: no trailing-slash redirects, no case folding, and no dot-segment removal (`/a/../b` is three segments; whoever maps paths to files must refuse those).

**Measured:** 100 to 300 ns per match over 12 routes and paths of 1 to 4 segments (the minimum over batches, on a loaded machine).

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
  - **Part 2, done:** signals and worker processes (above).
    - Built on `linux.signal` (sets, thread masks, `SignalFd`) and `linux.process`:
      - `Exec`;
      - `spawn`: clone3 with a pidfd, then raw syscalls only until execve;
      - `Child`: signal and wait through the pidfd;
      - affinity, `threads`, `all_threads_block`.
    - **Tests:**
      - `tests/linux/test_signal.mojo` and `tests/linux/test_process.mojo` cover exit codes and signals, a failed execve, pidfd readiness, the descriptor a child keeps, and the CPU and mask a child starts with. They read `/proc/<pid>/status` directly, so no shell in between can change what is checked.
      - `tests/server/test_workers.mojo` builds `tests/server/workers_app.mojo` and drives it from Python. It covers workers with one runtime thread each and a widened (or pinned) affinity, a killed worker restarted, and a request in progress that finishes when the supervisor gets SIGTERM, with exit 0 after. Also:
        - a second signal stopping at once, and workers that ignore a stop killed at `stop_timeout`;
        - workers stopping when their supervisor dies;
        - a crash loop restarted later and later;
        - a supervisor that inherited SIGCHLD ignored, so the kernel reaps its children itself;
        - a worker started without a supervisor's mask;
        - a single process stopping on SIGINT, or at once on a second.

        The driver kills each supervisor's process group when it ends, so a failure leaves no process behind.
    - **Planted bugs:** 17 of 18 caught at first. The survivor (workers that ignore a stop were never killed) is now tested.
    - **Found and fixed while testing:**
      - a worker handed a blocking lifeline hung in its first stop request;
      - a supervisor that inherited SIGCHLD ignored crashed at the first worker exit (ECHILD);
      - a worker not started by a supervisor trusted a signal mask it did not have;
      - a failed spawn ended the supervisor; it now retries with backoff.

      Each fix has a test that fails on the old code, except the retry: making clone3 fail would take a process limit on the whole user.
- **S4: routing and static files.**
  - **Part 1, done:** `Router` (above).
    - **Tests** (`tests/server/test_router.mojo`): every rule above case by case, a server running a router over the wire, and a differential check of 12,000 matches against a naive matcher. The naive matcher ranks every matching route by its segment kinds, which is the specificity rule stated directly.
    - **Planted bugs:** 19 of 19 caught.
  - **Part 2, next:** static files.
- **S5: polish.** Interop, an independent review, benchmarks, and the guide.
