# server: the HTTP/1.1 server

An HTTP/1.1 server for Mojo on Linux (roadmap step 3). It is built on the `http` library's sans-I/O `ServerConnection` and on `net`'s nonblocking sockets. Package rules and contracts are in `docs/design.md`; HTTP itself is in `docs/http.md`.

**Status: done through S7:** the serving loop, streaming, graceful shutdown with signals and worker processes, routing and static files, an independent review with its fixes, server-sent events, and TLS (HTTPS) through OpenSSL. Leads for later are at the end.

## Guide
**A server** is a `Handler` run by a `Server`:
```mojo
from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig, Stop


struct Hello(Handler):
    var hits: Int

    def __init__(out self):
        self.hits = 0

    def handle(mut self, req: Request, mut res: Response) raises:
        self.hits += 1
        res.text(200, String("hello, request ", self.hits, "\n"))


def main() raises:
    var stop = Stop.on_signals()  # first in main: it may run the program again
    var server = Server(Hello(), ServerConfig(server_name="hello"))
    server.bind(SocketAddr.parse("0.0.0.0:8080"))
    server.stop_on(stop^)  # SIGTERM or Ctrl-C: a graceful shutdown
    server.run()  # returns when it has finished
```
- **`handle`** gets the whole request: `req.method`, `req.target` (`path()`, `query()`), `req.host()`, `req.headers`, `req.body` (`text()`), `req.peer`. It fills the response: `res.text(...)`, `res.bytes(...)`, `res.redirect(303, "/next")`, or `status`, `headers` and `body` directly. The server adds `Date`, `Content-Length` and the configured `Server`; HEAD drops the body; an error raised gets a 500 (which `failed` may change), and is logged on stderr.
- **`path()` is raw,** not percent-decoded. Make access decisions on decoded segments, as `Router` matches them: `/%61dmin` is `/admin`.
- **One loop serves every connection** of the process, so `handle` must not block: no blocking I/O, no sleeping. Handler state needs no locks.
- **`ServerConfig`** holds the limits and timeouts: `max_connections`, `max_body` and `max_body_memory`, the header, idle, read, write, request, linger and shutdown timeouts, `min_rate`, `limits` for request heads, `max_requests` and `max_connection_age` per connection, `drain_delay`, `reuseport`, `server_name`, `log_errors`, the event streams' `heartbeat`, and the `tls_*` settings (see TLS). `Server(...)` refuses one that cannot work (`InvalidInput`): a `server_name` that is no field value, `max_connections` past the id space, a negative `max_body`, `max_body_memory`, `max_requests` or `min_rate`, a `max_body_memory` under `max_body`, a zero header, idle, read or write timeout, inconsistent `limits` or `tls_*` settings. Every limit is per process: with N workers, the server takes N times as much.
- **More hooks,** all defaulted (see "Admission, errors and access logs"): `admit` answers at a request's head, before its body; `body_limit` sets a body limit per request; `failed` maps an error to another answer; `completed` sees every request once, for an access log. A `Handler` that wraps another must pass every hook on, as `Router` does: one it leaves out falls back to the default without a word.

**Routes** go to functions instead (see Routing), with parameters:
```mojo
def user(mut app: App, req: Request, params: Params, mut res: Response) raises:
    res.text(200, String("user ", params["id"], "\n"))

var router = Router(App())  # App is a Handler: what no route takes goes to it
router.get("/users/:id", user)
router.get("/static/*path", static_file)  # app.files.serve(req, params["path"], res)
var server = Server(router^)
```

**Static files** come from `StaticFiles.open(dir)`, behind a route (see Static files). The application passes `produce` and `stream_ended` on to it, because large files stream.

**Streaming** responses are a `res.stream()` in `handle`, then `produce` calls that append pieces as the client takes them (see Streaming). Server-sent events are streams that pause when there is nothing to send: something else (another request, `Server.wake`) wakes them when there is. `res.event_stream()` sets their fields and keeps them alive with heartbeats (see Server-sent events). Request bodies stream into `on_body` when `stream_request` says so.

**Several cores:** `run_workers` runs the program as one worker process per CPU on the same port, under a supervisor that restarts them and stops them gracefully (see Processes):
```mojo
def main() raises:
    var stop = run_workers(WorkerConfig())  # first in main
    if not stop:
        return  # the supervisor, after its workers have stopped
    var server = Server(App(), ServerConfig(reuseport=True))
    server.bind(SocketAddr.parse("0.0.0.0:8080"))
    server.stop_on(stop.take())
    server.run()
```

**Running it:**
- Build the program (`pixi run mojo build -I src app.mojo -o app`). Signals and workers both execute the program again, which under `mojo run` means compiling it again.
- Under systemd, `KillMode=mixed` or the default `control-group` both work: SIGTERM starts a graceful stop, which `stop_timeout` bounds (15 s by default). Keep `TimeoutStopSec` above that. (With `control-group`, each worker sees its lifeline close and then gets SIGTERM itself; that is still one graceful stop.)
- In a container, the supervisor can be PID 1: it reaps the orphans PID 1 inherits, and where the seccomp profile refuses clone3 (Docker's default) it starts workers with clone(2). `workers=0` sizes the pool by the container's CPU quota too (`--cpus`). Docker's default stop timeout is 10 s: raise it (`--stop-timeout`, `stop_grace_period`), or lower `stop_timeout` and `shutdown_timeout`.
- Raise the open-files limit for many connections. `bind` raises the soft limit to the hard one itself.

**Embedding:** `step(timeout)` runs one turn of the loop, for a program with other work to interleave, and for tests.

## Model
**One thread and one edge-triggered epoll loop per process**, with one `ServerConnection` per connection.
- This is the model `docs/design.md` describes for concurrency without a runtime: no threads, no async.
- For several cores, run N processes on one port with `SO_REUSEPORT`, and the kernel spreads the connections. `run_workers` starts and supervises them (see Processes).

**Handlers.** The application implements `Handler.handle(req, mut res)`. It is called once per request, with the whole request (the body buffered up to `max_body`). Defaulted hooks stream bodies instead, in either direction (see Streaming).
- **Handlers must not block:** the loop serves every connection of the process. Blocking work belongs in another process, or in a future runtime.
- **A trait rather than a function:** Mojo 1.2 function values cannot capture state, and a handler usually needs some (a pool, counters, configuration).

## Behaviour
- **Requests:**
  - Keep-alive and pipelining; pipelined requests are answered in order. Line ends before a request line are ignored (RFC 9112 2.2).
  - An absolute-form target (`http://host/path`, which a server must accept) becomes its path and query in `target`, and its authority, which replaces Host, is `host()` (RFC 9112 3.2.2).
  - HEAD: a GET handler answers it, and its body is dropped.
  - `Expect: 100-continue` is answered when the body will be accepted.
  - Request bodies are limited to `max_body`. Beyond it the server answers 413, as soon as Content-Length says so. That answer is the request's only one: a rest that then stalls or breaks closes the connection without another response.
  - Malformed requests get their status (400, 414, 431, 501 or 505), with a Date, and the connection closes. An HTTP/2 client with prior knowledge (`PRI * HTTP/2.0`) gets one 505 and an orderly end of input.
  - `Request.number` counts a connection's requests from 1 (with `Request.id`, it names a request: for logs). `Request.unix_time` is the second of the response's Date, so a handler need not read the clock (a syscall here) and can keep its own dates no later than Date.
  - A handler that raises gets a 500. So does an answer the server cannot send as asked:
    - a buffered body that does not match the handler's Content-Length, or is over 63 MiB (stream larger ones);
    - a 101, or a 2xx to CONNECT, since the server does no upgrades or tunnels.
- **Timeouts** (`ServerConfig`), against clients that are slow or stall:
  - `header_timeout`: a request head must arrive within it once it starts, else 408.
  - `idle_timeout`: how long a kept-alive connection may sit idle, from when its last response has gone out to the socket (not from when it was queued: a long download then left the client no time for its next request).
  - `read_timeout`: while a body arrives (408).
  - `write_timeout`: while a response waits on a client that does not read. At its end the connection is aborted (RST), so that the kernel does not go on sending what was queued, up to a send buffer, at the client's pace.
  - **Minimum rate:** the read and write timeouts restart only when a window's worth of progress has passed: `min_rate` (512 B/s) times the timeout, so 15 KB per 30 s window by default. A client dripping a byte at a time is cut at the timeout. `min_rate=0` restarts them on any progress.
  - Each of the four must be more than zero (`Server` refuses `Duration.ZERO`, which would close at the next sweep); `Duration.MAX` is practically never. For `heartbeat` and `tls_reload_check`, ZERO means never.
- **Configuration** is checked once, by `Server`, and kept: `Server.config()` returns a copy, so nothing can change it past its checks (a `server_name` set later could have split every response). `max_body` must not be negative. A server has one listener: a second `bind` raises `InvalidInput`.
- **Fairness:** a connection gets a slice of each turn: 64 KiB read and written, or 128 requests answered. Then it waits for the next turn, which does not wait for readiness. A client that pipelines without pause cannot keep the loop from the others, nor from accepting, the timeouts and stop requests.
- **Backpressure:** a connection reads nothing while its output is pending.
- **Responses** get `Date` and `Content-Length`, and `Server` if configured, the server's own answers (400, 408, 413, 421, 431, 500, 505) too.
- **Resources:**
  - At start the fd limit is raised and the fd table pre-grown (docs/spikes.md).
  - Above `max_connections` accepting pauses. On EMFILE, and on any other accept error but the network errors accept(2) passes on (those just skip that connection), it pauses for 100 ms.
  - An idle connection gives back every buffer grown past 16 KiB: the bodies, the header arenas, the codec's receive and output buffers. Whatever a client once sent or asked for, an idle connection holds about 100 KiB at most.
  - Connection ids are 40 bits of a per-server count above 24 bits of slot, so an id is not reused before 2^40 connections.

## Admission, errors and access logs (SR2)
**`admit(req, mut res) -> Bool`** is called at each request's head, first: before `stream_request`, before any of the body is read, and before `100 Continue`. False answers with `res` at once (401, 403, 413, 415, 417, 503; a buffered answer: a stream is refused), and the body is then ignored as after an early 413, read and dropped if short, else the connection closes after the answer. So a client is refused before it uploads, as Go and nginx allow.

**`body_limit(req) -> Int`** gives the request's body limit (413 beyond), asked after `stream_request` said False; -1 (the default) is `max_body`. An upload route can take more than the rest.

**`max_body_memory`** (256 MiB) bounds what buffered request bodies hold at once, over all of the process's connections: each holds its Content-Length from its head, or what has arrived of a chunked body. A request that would go past it gets 503 with `Retry-After: 1`, and is ignored as after a 413. Without it, 10,000 connections uploading 1 MiB slowly held 10 GiB; `min_rate` does not stop that, since 512 B/s a connection is cheap. Bodies streamed to `on_body` do not count.

**Errors.** A hook that raises (`handle`, `admit`, `stream_request`, `on_body`) gets a 500 with a fixed body, and nothing it had set. Then:
- `failed(req, error, mut res)` may change the answer (a malformed body: 400). A stream is not allowed there, and an error from it keeps the 500.
- With `log_errors` (the default), a line goes to stderr: the method, the path and the error, with every byte outside printable ASCII escaped (`\x1b`), so a client cannot write terminal escapes into a log. At most one a second, the next saying how many were left out. Accepting that pauses (at `max_connections`, or out of fds) is logged too, at most once in 10 s. The lines are written with `write_no_sigpipe`: a stderr whose reader has gone costs the line, not the process.
- An error from `produce` ends the connection (its response is under way), and is not logged.
- A Mojo abort (a bounds check, `abort()`) ends the process and every connection on it; run it under `run_workers` (even with one worker) to have it restarted.

**`completed(req, done: Exchange)`** is called once for each request whose head was read: when its response has been handed to the connection, or when it was cut. `Exchange` holds the status that went out (0 for none), the body bytes sent and received, when the head came and when it ended, whether the response went out whole (`finished`), and whether the server answered rather than the handler (`by_server`: 400, 408, 413, 421, 500, 501, 503). That is an access log; a malformed request whose head could not be read has no `Request`, and is not seen. "Handed to the connection" is not "delivered": the client may still be reading it.

**Keep-alive limits.** After `max_requests` requests on a connection, or once it is older than `max_connection_age`, the next response says `Connection: close` (both off by default, as in Go and Node). Long-lived connections from a load balancer then spread again over the workers after a restart. **`request_timeout`** (off by default) bounds the time from a request's head to the end of its buffered body, whatever its progress (408), as Node's `requestTimeout` does.

**CONNECT** gets 501 from the server, before the handler: the server cannot tunnel, and a handler's 2xx would have become a 500.

## Closing and shutdown (S3)
**Lingering close.** When the server ends a connection, it closes it at once unless the client may still be sending: a request answered before its body arrived (413, 408), requests pipelined after the last response, a malformed request (`ServerConnection.input_pending()`).
- Such a connection closes in stages, as RFC 9112 9.6 describes. The server shuts down its write side after the response, then reads and drops the client's input until the client's end of input, or for at most `linger_timeout` (2 s).
- Closing at once would answer the client's next bytes with a reset, and a reset can erase the response before the client has read it.

**Graceful shutdown.** `Server.shutdown()` begins it, and `step()` (or `run()`, which then returns) carries it out:
0. With a `drain_delay` (off by default), the server first goes on accepting and serving for that long, each response saying `Connection: close`, and `shutting_down()` is called at its start, so a readiness check can fail from then on. Kubernetes removes a pod's endpoint at the same time as it sends SIGTERM, and load balancers go on sending new connections for a few seconds: without a delay they are refused (the usual workaround is a `preStop` sleep). A stop at once (a second signal) cuts the delay short. Keep `WorkerConfig.stop_timeout` above `drain_delay` plus `shutdown_timeout`.
1. The connections the kernel has queued are accepted, without the `max_connections` cap, because their clients may have sent requests already. Then the listener closes, and new connections are refused.
2. Each connection first reads what has arrived, so a request already sent counts as in progress. Then `close_gracefully()` stops it taking requests:
   - an idle connection closes now;
   - a request in progress gets its response, the last on its connection, saying `Connection: close` if its head has not gone out yet;
   - requests pipelined after it are not answered, and the client retries them on another connection.
3. `Handler.shutting_down()` is called once (here, unless a drain called it). Streams last until `shutdown_timeout` unless they end, so a handler with long-lived ones (server-sent events) ends them there by waking them.
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
- **Starting:** it starts `workers` processes (default: one per CPU it may run on, and no more than its cgroup's CPU quota, `linux.probe.cpu_quota`). Worker i's runtime starts on the i-th allowed CPU, so it starts one runtime thread instead of one per CPU (docs/spikes.md). Its affinity then widens to all of them, unless `pin`.
- **clone3 refused:** where a seccomp profile refuses clone3 (Docker's default, with ENOSYS), workers start through clone(2) with CLONE_PIDFD. If processes cannot be made at all (ENOSYS or EPERM from both), `run_workers` raises instead of retrying forever.
- **Restarting:** a worker that ends is restarted after `restart_delay` (100 ms). Each further end within a second of starting, in a row, doubles the delay (from at least 50 ms, so a `restart_delay` of 0 grows too), up to `max_restart_delay` (10 s). Starts, ends and restarts are logged on stderr.
- **Stopping:** on SIGTERM or SIGINT, it closes each worker's lifeline (a socketpair), which asks the worker to shut down gracefully. It waits up to `stop_timeout` (15 s; keep it longer than the workers' `shutdown_timeout`), then kills what is left, and `run_workers` returns None. A second signal kills the workers at once.
- **A worker whose supervisor dies** sees its lifeline close, and shuts down gracefully as well.
- **Ctrl-C in a terminal** signals the whole process group: workers get SIGINT directly too, and treat it like the lifeline. A second Ctrl-C stops them at once.
- **Robust starts:** fds 0, 1 and 2 are opened on /dev/null where closed, so that no socket lands there and gets the log. The supervisor blocks SIGPIPE, so a broken stderr pipe cannot kill it (its log writes just fail); workers start without that. Workers remove `MOJO_NET_WORKER` from the environment their own children get.
- **As PID 1** (a container's init), the supervisor also reaps the orphans it inherits, which would otherwise stay zombies.

**`Stop`** is what a server stops on: SIGTERM or SIGINT, and in a worker its lifeline. The first request asks for a graceful shutdown. Only a signal after an earlier signal asks to stop at once, closing every connection; the lifeline only ever asks gracefully, and bytes on it mean nothing (only its end does).

**Signals without handlers.** The library installs no signal handlers, so a stop signal is read from a signalfd. That works only if every thread blocks the signal. The Mojo runtime starts its threads before `main`, with the mask the process was started with; blocking in `main` therefore loses most SIGTERMs to the runtime's handler, which ends the process (25 of 30 runs in the spike, docs/spikes.md).
- So `Stop.on_signals` and `run_workers` block SIGTERM and SIGINT, check every thread's mask in `/proc/self/task`, and if one does not block them, execute the program again: the new image's threads start with the mask.
- That happens at most once (`MOJO_NET_REEXEC` marks it). If some thread still does not block them after it, because something unblocks them, a warning goes to stderr, and a stop signal may end the process at once.
- Workers inherit the mask from the supervisor and need no second execution.
- **Children inherit the mask:** processes the server starts get SIGTERM and SIGINT blocked, as exec keeps the mask. Reset it where they should stop on those: `linux.process.spawn(signal_mask=...)`, or `signal.pthread_sigmask` in a Python `preexec_fn`.
- **An ignored SIGINT is still a stop request:** a SIGINT the parent set to be ignored (a background job of a script) is blocked, not discarded, and so it reaches the signalfd.

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
- Parameters are the decoded bytes, which must be UTF-8: decoded lossily, `a%FF` and `a%FE` would be one value.

**Paths no pattern can take fail closed**, so that a crafted path cannot skip a route's checks (`/admin/*rest` answering 403 is not bypassed by `/admin%2Fusers`, which a fallback that forwards would decode):
- 400: a malformed percent-encoding, a parameter that is not UTF-8, or a segment that decodes to something with "/" or NUL in it;
- 404: a path deeper than 128 segments.

With `router.fallback_unroutable = True`, the last two go to the application instead (a proxy that forwards paths as they came). An asterisk-form target (`OPTIONS *`) goes to the application. `find` tells these cases apart (`NO_ROUTE`, `NO_METHOD`, `MALFORMED`, `ENCODED_SLASH`, `TOO_DEEP`), and clears the parameters on a miss.

**Patterns refused** at `route()`: a method that is not a token, a name used twice in one pattern (`params["id"]` would return the first), and text with "%", "?" or "#" in it, which no decoded path holds.

Matching is strict: no trailing-slash redirects, no case folding, and no dot-segment removal (`/a/../b` is three segments; whoever maps paths to files must refuse those).

**Measured:** 100 to 300 ns per match over 12 routes and paths of 1 to 4 segments (the minimum over batches, on a loaded machine).

## Static files (S4)
`StaticFiles` answers requests with the files of one directory, from a route; `examples/server/files.mojo` is a whole file server.
```mojo
def assets(mut app: App, req: Request, params: Params, mut res: Response) raises:
    app.files.serve(req, params["path"], res)

router.get("/assets/*path", assets)
```
Large files are streamed, so the application passes `produce` and `stream_ended` on to `files`.

**No path leaves the directory:**
- First, the path itself is checked: no empty, "." or ".." segment, and no NUL (404). One trailing "/" names a directory.
- Dotfiles (`.env`, `.git/`) are 404 too, except `.well-known` (ACME challenges live there), unless `StaticFiles.open(..., dotfiles=True)`. Hiding them is a convenience, not a boundary: a link with another name, or a vfat short name (`GIT~1` for `.git`), still reaches them. Keep secrets out of the directory.
- Then the kernel keeps the lookup beneath the directory: openat2 with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`. A symlink out of it gets 404 too. `StaticFiles.open` checks that openat2 works (Linux 5.6 or later, and a seccomp profile that allows it), and raises if not; there is no fallback to an unconfined open.
- **Only regular files are served,** and nothing else is opened: a path is looked up first with O_PATH, which runs no device driver (a watchdog would arm, a tape rewind), opens no FIFO end, and needs only search permission on a directory (one at 0711 serves its index). A FIFO, socket or device gets 404. A regular file is then opened for reading.
- A path through a file (`a.txt/x`), a symlink loop or a name too long gets 404; a file the server may not read gets 403.
- **The directory is the one `open` found,** held open: renaming another tree over it, or flipping a symlink to it (a `current -> releases/N` deploy), is not seen until it is opened again. Symlinks inside it are followed on every request.

**Responses:**
- **Fields:** Content-Type (from the extension), Content-Length, Last-Modified (never later than the response's Date: a future modification time is replaced, RFC 9110 8.8.2.1), an ETag, `Accept-Ranges: bytes`, `X-Content-Type-Options: nosniff` (no browser runs an uploaded text file as a script), and `Cache-Control` when `cache_control` is set (`no-cache` for pages, `public, max-age=31536000, immutable` for assets with hashed names; without it, caches guess a freshness from the file's age).
- **The ETag** names the size, the modification time, and, unless `inode_etags=False`, the inode and the status-change time. User space cannot set the last, so a rewrite that keeps both the size and the modification time (`cp -p`, `rsync -t`, a reproducible build's fixed times) still changes the tag: with nginx's tag a client would revalidate to a stale 304. Turn it off for replicas behind one balancer that serve copies of one tree. A file changed within the last second or two gets a weak tag (another change in the same clock tick could keep every time), which If-Match and If-Range never match; If-Range by date does not match then either.
- **Directories:** a directory serves its `index.html`, after a 301 to the path with a trailing "/" when it lacks one. There are no listings.
- **Conditional requests,** in RFC 9110 13.2.2's order:
  - If-Match (strong comparison), and only without it If-Unmodified-Since, answer 412 when they fail. A resumed download of a file that changed gets 412, not new bytes after old ones.
  - Then If-None-Match (weak comparison) answers 304; only without it, If-Modified-Since does.
  - A list may come in several field lines (RFC 9110 5.3); a date in several is invalid, and ignored.
- **Ranges** (RFC 9110 14), for GET only (HEAD ignores Range):
  - one byte range gets 206 with Content-Range, an unsatisfiable one 416;
  - several ranges, a malformed one, or an If-Range that does not match get the whole file;
  - an empty file ignores Range.
- **Bodies:** up to 64 KiB are read whole. Larger ones stream in 16 KiB pieces as the client takes them (`produce`), and `stream_ended` closes the file however the response ends. A HEAD reads nothing. A slow client's download holds about 144 KiB: 64 KiB queued for its socket, 64 KiB in the codec, and the piece (it was 192 KiB with 64 KiB pieces). At `max_connections` (10,000) slow downloads that is 1.4 GB; sendfile would need none of it (a lead).
- **A body is the version its head describes.** A file that changes between its lookup and its read (size, times or inode) is looked up again, up to three times, then 500. One that changes while it streams (checked every 256 KiB, and after the last piece) or shrinks ends the connection short of its Content-Length: the client sees an incomplete body, never one made of two versions under the first one's validators (a rewrite in place, as `cp` and editors do; a rename over the file is served consistently, since the open file keeps the old inode).
- **Reads block:** they are plain preads, so a file not in the page cache stalls the loop while the disk reads it.

**HTTP dates** in conditional fields are read in all three forms, which recipients must accept (`parse_http_date`, RFC 9110 5.6.7).

## Streaming (S2)
The `Handler` hooks beyond `handle` all have defaults, so a handler that buffers needs none of them.

**Request bodies.** `stream_request(req)` is asked at each request's head.
- If it returns True, the body goes to `on_body(req, data)` piece by piece as it arrives, without `max_body`. `handle` follows at the body's end, with `req.body` empty.
- If the body never completes, `body_cut(req)` is called instead of `handle`: the client left, stalled or sent a malformed body, `on_body` raised, or a shutdown closed the connection. It is where what `stream_request` set up (an open file) is released.
- `read_timeout` and `min_rate` still apply, and `Expect: 100-continue` is answered as for a buffered body.

**Responses.** `handle` calls `res.stream()`, and the head goes out at once.
- **Framing:** chunked, unless the handler set Content-Length; then `produce` must give exactly that many bytes, or the connection closes.
- **The body comes from `produce(req, mut out)`.** The server asks for more only once the connection's output has gone to its socket, and while less than 64 KiB is queued, so a stream goes at its client's pace. A connection's buffers then hold up to 64 KiB queued for the socket and 64 KiB in the codec, plus the piece's: keep pieces small (16 KiB, as `StaticFiles` does). At `max_connections` (10,000) slow clients, that is about 1.4 GB: lower `max_connections` where memory is tighter.
- **The end:** returning False ends the stream: the last chunk goes out, and the connection serves its next request.
- **Pausing:** appending nothing and returning True pauses the stream. Nothing more is asked until its connection is woken:
  - `Request.id` names the connection. It names that connection while it lives and never another one.
  - `Server.wake(id)` wakes it from outside the handler (between `step`s). `take_wakes()` returns the ids a handler collected during its own calls; the server asks after every call into the handler.
  - A wake is served in the next turn, which then does not wait for readiness. Wakes for closed connections, or for streams that are not paused, are ignored.
  - Server-sent events and long polling work this way: a subscriber's stream pauses until something for it arrives. In `tests/server/test_streaming.mojo`, events published by other connections' requests wake the subscribers.
  - A stream that wakes itself every time keeps the loop busy, but other connections are still served, since wakes wait for the next turn.
- **HEAD** gets the head only, with the fields its GET gets (`Transfer-Encoding: chunked`), and `produce` is never called. So do 204 and 304.

**Ends and errors.**
- `Handler.stream_ended(req, finished)` is called once for every response made with `res.stream()`:
  - `finished` when its whole body was handed to the connection (it may still be on its way to the client), or when it had none to send (HEAD, 204, 304);
  - otherwise when it was cut: the client left, `produce` raised, the head was refused, or a shutdown timed out.

  It is where a stream's resources (an open file, a subscription) are released.
- A paused stream lasts as long as its handler wants: the header, idle and read timeouts do not apply to it, and the write timeout applies while its output waits. When it first pauses, its socket gets keepalive probes (`TcpStream.detect_dead_peers`: after 30 s of silence, then every 10 s, 3 of them), so a client that vanished without FIN or RST (power loss, a NAT that dropped the connection) is cut within about a minute rather than held forever.
- A client that closes or half-closes its side while its stream is paused ends the stream, as nginx does.
- A client that half-closes while output waits for it may still be reading, so the stream goes on. If the client is gone, the server's next probe of its zero window draws a reset (TCP's persist timer, about 200 ms), and the stream is cut then; a peer that never answers is cut at `write_timeout`. This also holds when the client's pipelined requests fill the codec, so that no read can see the end of input: epoll's hangup flag tells instead.
- An error from `stream_request` or `on_body` answers 500, ignores the rest of the request, and closes the connection after the response (unless the rest is short enough to drain).
- An error from `produce` cuts the response: the connection closes, and the client sees an incomplete body.

## Server-sent events (S6)
An event stream is a streamed response whose `produce` writes events with `http.sse.write_event`. This is how an OpenAI-compatible server sends tokens as the model makes them (`examples/server/sse_tokens.mojo`):
```mojo
def handle(mut self, req: Request, mut res: Response) raises:
    if self.busy():
        res.retry_later(429, Duration.from_secs(1))  # Retry-After: 1
        return
    self.start_generation(req.id)  # the model runs outside the handler
    res.event_stream()

def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
    for token in self.take_tokens(req.id):  # what the model made since
        write_event(out, token_json(token))
    if self.done(req.id):
        write_event(out, "[DONE]")
        return False  # the end of the stream
    return True  # nothing more yet: paused until the next wake

def stream_ended(mut self, req: Request, finished: Bool):
    self.stop_generation(req.id)  # finished, or the client left
```
And in the program's loop, `server.wake(id)` when the model has new tokens for `id`:
```mojo
while True:
    server.step(Duration.from_millis(10))
    for id in model.ids_with_new_tokens():
        server.wake(id)
```
- **`res.event_stream()`** sets `Content-Type: text/event-stream` and `Cache-Control: no-cache`. It also sets `X-Accel-Buffering: no`, so that nginx passes each event on at once rather than buffering them. Then it calls `stream()`. The handler may change these fields afterwards.
- **Heartbeats:** while an event stream is paused, a comment line (`:`) goes out each time it has sent nothing for `ServerConfig.heartbeat` (15 s; `Duration.ZERO` for none). Clients ignore comments, and proxies and load balancers that close idle connections (often at 60 s) see traffic.
  - A heartbeat goes between lines, never inside one. A stream whose last bytes did not end a line gets none until it does.
  - A stream with the handler's `Content-Length` gets none, since one would break its framing. Nor does HEAD, which has no body.
- **Cancelling:** a client that leaves, while the stream is paused or as a heartbeat goes out, ends it. `stream_ended(req, False)` is then where the generation for it stops.
- **Overload:** `res.retry_later(status, delay)` answers 429 or 503 with `Retry-After` in whole seconds, rounded up. `http.retry.retry_after` reads it on the client side.
- **The encoder** (`http.sse.write_event(out, data, event=, id=, retry_ms=)`) splits `data` into `data:` lines at every line end, and refuses an `event` or `id` that would break the stream (a line end, a NUL in the ID). `write_comment` writes comments.

## TLS (S7)
```mojo
from tls import ServerConfig as TlsConfig

var server = Server(App(), ServerConfig())
server.bind(SocketAddr.parse("0.0.0.0:8443"))
server.serve_tls(TlsConfig(certificate="fullchain.pem", key="privkey.pem", names=["example.com"]))
server.run()
```
`examples/server/https.mojo` is this program. The TLS itself is `tls.TlsServer` (`docs/tls.md`, "The server"): OpenSSL does the protocol, and the server drives it over memory buffers in its loop, between the socket and the HTTP codec. Every connection accepted after `serve_tls` is TLS; the listener serves nothing else.
- **What the server adds** (rules TS6 to TS13 of `docs/research/tls_with_openssl.md`):
  - **ALPN** is `http/1.1`, whatever the configuration asks: a client that offers only `h2` gets a fatal alert, one that offers none is served.
  - **No TLS state before the ClientHello.** A connection is accepted as any other, under `max_connections`. It gets its `TlsServer` (OpenSSL's state), and counts as a handshake, only once its first record has arrived whole, within `tls_hello_timeout` (5 s) of accept. Anything but a TLS handshake record of at most 16 KiB (plaintext HTTP, SSLv2's hello) is closed at once. So sockets that send nothing, or a byte, cost what an idle HTTP connection does and take no handshake's place. Accepting never waits for TLS: when it paused at the handshake cap, a few thousand silent sockets locked every client out (see "Review").
  - **Admission** (TS7): at most `tls_max_handshakes` handshakes under way (1,024) and `tls_handshake_rate` begun a second (1,000). Connections whose ClientHello came beyond either wait, unread, and are admitted in arrival order as handshakes end or the next second begins (`Server.tls_waiting()` counts them). While some wait, the oldest handshake that has waited `tls_client_wait` (1 s) for its client since its admission is closed to make room: the server's work is done once its flight is out, and clients that send a ClientHello and go quiet would otherwise hold every place until their deadline, cutting the server to about 100 handshakes a second (TR3, `docs/tls.md`). With nobody waiting, a slow client keeps its place to its deadline.
  - **One deadline per handshake** (TS8): `tls_handshake_timeout` (10 s) from accept, which progress does not extend, waiting for admission included, so a ClientHello dribbled a byte at a time is cut there. A client may send at most 32 KiB of handshake; the data a TLS 1.3 client sends behind its Finished does not count.
  - **The other timeouts** count plaintext: a client sending records without data makes no progress on a body. Records without data also count against the connection's slice of a turn, and more than 4 KiB of them over the connection (beyond a byte per 4 KiB of data) fails it: key updates sent between bytes of data would otherwise keep a core busy.
  - **Closing** (TS10): a graceful end (`Connection: close`, an idle connection at a shutdown) sends close_notify after the last response. A timeout or an error sends none; after a TLS failure, only the alert OpenSSL queued goes out, if the socket takes it at once. A shutdown lets handshakes under way finish within their deadline, then takes the request that came with the handshake's end as in progress.
  - **A Host that is not the SNI** gets 421 Misdirected Request, and the connection closes (TS6). A port, a trailing dot and case do not count; a request without a host makes no claim. A client that asked for no name in SNI (it connected by address) is not checked. An absolute-form target's authority is what is checked, and it replaces the Host field (RFC 9112 3.2.2), plain HTTP too, so that a handler, or a proxy it passes the fields to, sees the same host.
  - **Reloading** (TS12): every `tls_reload_check` (10 s) the certificate and key files are compared with what was loaded (inode, size, modification time). When either changed, a new context is built from them for new connections, on the first one's OpenSSL library context (a process can hold only about 330 of those: `docs/tls.md`, "Use"); connections keep the context they began with. A failed build leaves the old one serving and is said on stderr (once), and is tried again at every check until it works: what fixes it, a `chmod` of the key or fds freed, may change nothing the check compares. Replace the files by renaming new ones over them, as certbot does, so that a check never reads half a file.
  - **Renewal** (TS12): once a day, and after each reload, a line on stderr when less than a third of the certificate's lifetime is left.
  - **Secrets** (TS11): `serve_tls` removes `SSLKEYLOGFILE` from the environment, and workers start without it, so that no libssl writes session keys there. Failures are not logged; the client's SNI is attacker-controlled.
  - **Workers** (TS13): each worker calls `serve_tls` itself, after `run_workers`, so each builds its own context and no TLS state crosses a fork.
- **Not here:** HTTP/2, session resumption, client certificates, OCSP stapling and kTLS (`docs/tls.md`, "Scope").

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
  - **Part 2, done:** `StaticFiles` (above), `Handler.stream_ended`, and `linux.fs` gaining `open_dir`, `open_beneath` (openat2), `stat_fd` (statx: the same struct on both architectures, unlike `stat`) and `pread`.
    - **Tests** (`tests/server/test_static.mojo`, over a scratch directory): types, the index and its redirect, every way out refused (raw and encoded "..", empty segments, symlinks out, a FIFO, an unreadable file), conditional requests and their precedence, ranges (206, 416, suffixes, If-Range, several ranges), a 1 MiB file streamed and checked, HEAD, and an abandoned download whose file is closed (32 MiB: a 1 MiB file fit in the socket buffers, and its stream finished before the client left). Also the three date forms with RFC 850's century rule, and the type table. `tests/server/test_streaming.mojo` counts each mode's `stream_ended` calls.
    - **Planted bugs:** 21 of 21 caught, once the abandoned download was made too large for the socket buffers; that was the one that survived at first.
- **S5: polish.** Interop, an independent review, benchmarks, and the guide.
  - **The guide** (above). Its first example is built and run: it serves, then stops on SIGTERM with exit 0.
  - **Interop with curl** (8.14 here; skipped without it), in `tests/server/test_curl.mojo`:
    - keep-alive across URLs, POST, a chunked upload, and a 2 MiB body with `Expect: 100-continue` (curl waits for the 100);
    - HEAD, a range, a file compared byte for byte, a chunked streamed response, HTTP/1.0 with `Connection: close`, 405 with Allow, and 404.

    Also tried by hand against `examples/server/files.mojo`: the 301 to a directory, `--path-as-is` traversal refused, and a 304.
  - **Where the time goes**, measured by splitting the server process's CPU into user and system time, with the server and the load generator (`bench/http/load.mojo`) on separate CPUs, against `examples/http/hello_server.mojo` on the bare codec:

    | Load | Server: user + system per request | Bare codec |
    |---|---|---|
    | 50 keep-alive connections | 2.1–2.6 µs + 6.1–6.8 µs | 1.2–1.5 µs + 5.3–5.9 µs |
    | 16 pipelined per connection | 0.9–1.2 µs + 0.3–0.5 µs | 0.5–0.7 µs + 0.3 µs |

    - The kernel's share dominates without pipelining: epoll, recv and send through loopback TCP for every request.
    - What the server adds is about 0.4–0.5 µs of user time per request (`Request` and `Response`, the header scans, the hooks), plus one clock read per loop turn.
    - That read is a syscall without libc (161 ns, against 17 ns through the vDSO; docs/spikes.md). Calling the vDSO's `clock_gettime` would remove most of it (a lead for later).
  - **At 2,000 connections** (`examples/server/hello.mojo`, one core):
    - keep-alive: 103k req/s, and the median round trip is about 19 ms, which is 2,000 requests in flight queued on one core;
    - 4 pipelined per connection: 293k req/s;
    - after each run the process is back to 5 open descriptors, at 27–29 MB RSS.
  - **Against Go, Rust and nginx** (`bench/server/README.md`, 2026-10-27). The setup: wrk, TechEmpower's plaintext test, every process pinned, and each server in its fastest usual form (Go with PGO, fasthttp prefork, hyper with fat LTO and `target-cpu=native`). Runs of 60 s, one server at a time, twice; a shared laptop:
    - one CPU, 64 keep-alive connections: hyper 181k req/s, nginx 175k, fasthttp 164k, mojo 156k, Go's net/http 86k. The first four take 5.5–6.4 µs of CPU a request, mostly the kernel's loopback TCP;
    - one CPU, 16 pipelined: hyper 1.17M, fasthttp 1.07M, mojo 762k (1.31 µs a request against hyper's 0.85), nginx 191k, net/http 102k;
    - one CPU, 1024 connections: hyper 144k, nginx 141k, mojo 132k, fasthttp 124k, net/http 70k;
    - four CPUs (two cores), 16 pipelined: hyper 2.12M, fasthttp 1.97M, mojo 1.33M, nginx 410k, net/http 182k. Without pipelining, wrk was the limit (83–92% of its CPU) at 300–350k;
    - **Why mojo was slower** (`bench/server/README.md`): the kernel's time per request is the same as hyper's; mojo's user time was about twice hyper's (9,644 instructions a request pipelined, against 4,565). Most of it was `http`'s handling of header fields: each head was walked several times and checked a byte at a time, plus the standard library's bounds checks (5%). The server loop was 7%, and nothing is allocated per request. HR3 and SR2 closed the gap (SR2, below).
  - **The independent review:** three reviewers, one each for protocol and security, resources and the loop, and processes and signals. They reported 35 distinct findings and found no request smuggling, desync, client-driven header injection or path escape. Every finding that could be reproduced was, first by a regression test failing on the old code:
    - `tests/server/test_server_regressions.mojo`;
    - `tests/server/test_static_regressions.mojo`;
    - `tests/server/test_process_regressions.mojo`;
    - `tests/linux/test_process_faults.mojo` (the clone3 refusal, through the fault seam);
    - new cases in `tests/linux/test_process.mojo` and `tests/linux/test_probe.mojo`.

    The most severe:
    - **One client could hold the loop.** Pipelining without pause, it got every turn: one `step()` measured 5.5 s, during which no other connection, accept, timeout or stop request was served. Fixed with per-connection slices.
    - **Workers never started in a default Docker container,** whose seccomp profile refuses clone3 (now clone(2)).
    - **A graceful stop under systemd's default `KillMode=control-group` cut in-flight requests.** A worker took its own SIGTERM, after its lifeline closed, as a second request.
    - **A slow-drip client held a connection forever** (now `min_rate` per timeout window, and RST at the write timeout).
    - **A resumed download of a changed file was silently corrupted** (If-Match and If-Unmodified-Since were ignored).
    - **A broken stderr pipe killed the supervisor and every worker** (SIGPIPE).

    The others are in the sections above: a cut streamed body (`body_cut`), a second response after an early 413, dropped answers for 101 or a wrong Content-Length, stray CRLFs, a large `max_head`, `step()` spinning after a shutdown, buffers kept at their peak, accept errors, id reuse, the redirect echoing an absolute-form authority, a future Last-Modified, `server_name` injection, HEAD with Range, Date on errors, dotfiles, and the supervisor items (stdio, PID 1 orphans, backoff, environment, the re-exec bound, the cgroup quota, a failed registration).
    - A suspicion the reviewer could not reproduce is handled too: before closing at once, the server reads once more, and lingers if a late pipelined request arrived. Closing with it unread would reset the connection.
    - **Planted bugs:** 33 of the first 36 caught. Of the three survivors:
      - the stdio fix was hidden by the lifeline fix (log lines on a lifeline no longer stop a worker); the test now checks the supervisor's fds 0–2 directly;
      - `body_cut` at close was reached by no case until a client resetting mid-body was added;
      - `body_cut` on a malformed body is defense in depth: without it the hook still comes, when the connection closes after its 400.
  - **Leads for later:** a vDSO clock; sendfile for large files (it needs the SIGPIPE decision in `linux/sys.mojo`); precompressed files. (TLS came in S7.)
- **S6: server-sent events.** Done. `res.event_stream()`, heartbeats (`ServerConfig.heartbeat`), `res.retry_later`, and `List[UInt8]` forms of `http.sse.write_event` / `write_comment` for `produce`.
  - **Tests** (`tests/server/test_sse.mojo`): Python clients parse what arrives with `tests/http/sse_oracle.py`, written from the WHATWG standard's text independently of the parser. Covered:
    - the fields, and events with IDs, read back as written;
    - heartbeats while a stream is paused, and none while it sends (woken every 30 ms, with a 250 ms heartbeat);
    - none inside a line, none with a Content-Length (the body stays exactly its length), none on HEAD;
    - a client that leaves after a heartbeat ends the stream;
    - `retry_later`: rounding up, the phrase as the default body, the statuses it refuses.
  - **By hand:** `examples/server/sse_tokens.mojo` against `curl -N` and `examples/http/sse_events.mojo` (every token, then `[DONE]`); 64 streams at once, then a 429 with `Retry-After: 1`.
  - **Planted bugs:** 10 of 12 caught. Neither survivor can corrupt a stream:
    - a heartbeat for a stream that is not paused: such a stream has just sent, or was just woken;
    - no reset of the quiet time when a stream starts: a reused connection's next event stream could get its first heartbeat early.
- **S7: TLS.** Done. `Server.serve_tls(tls.ServerConfig)`, the `tls_*` settings of `ServerConfig`, and the behaviour in "TLS" above; `TlsServer.pending_transmit()` (and `TlsClient`'s) for the backpressure over TLS.
  - **Tests** (`tests/server/test_tls.mojo`, 12; and `test_workers.mojo`'s TLS case), against clients in Python's `ssl`: three keep-alive requests and a 100 KB body over TLS 1.3 with ALPN `http/1.1`, then close_notify after `Connection: close`; `h2` alone refused with `no_application_protocol`; an unknown SNI answered nothing; the 421 (and a port, a trailing dot, case); a ClientHello dribbled for longer than a 1 s deadline cut at it; a ClientHello that never ends closed; two handshakes at once, then the next two only after the first two ended; three a second, the fourth in the next second; a reload while a connection lives, then broken files with the last good certificate serving on; close_notify to an idle connection at a shutdown, and a handshake under way at a shutdown let finish, its request answered as the last; two workers over TLS, which never see `SSLKEYLOGFILE`.
  - **Planted bugs:** 9 of 9 caught: no close_notify, no 421, no handshake deadline, no cap on handshakes at once or a second, no reload, the configured ALPN kept, `SSLKEYLOGFILE` passed on, handshakes cut at a shutdown. (`test_workers.mojo` builds its app from `MOJO_NET_TEST_SRC` when set, so that a planted copy reaches it.)
  - **Review (TR2, 2026-10-27; `docs/tls.md`, "Review"):** silent sockets held every handshake's place while accepting paused (fixed: no TLS state before the ClientHello, which waits for admission unread); an upload behind the Finished refused as a too large handshake; a failed reload never tried again after a `chmod`; an absolute-form authority checked while another Host field stayed. Tests: `tests/server/test_server_tls_regressions.mojo` (6), with the admission tests of `test_tls.mojo` rewritten. `tls-asan` now runs `test_tls.mojo` too.
  - **Not run here:** sslyze against the listener (not on conda-forge); the protocol profile is tested on `tls.TlsServer` itself (`docs/tls.md`, "Checks"), and the listener uses that context unchanged.
- **SR2: the second review (2026-10-28).** Three internal reviewers, read-only: the loop as an attacker sees it, best practices against Go, nginx, hyper and Kestrel, and static files with the router. Every finding is fixed, each with a regression test checked to fail on the old code:
  - `tests/server/test_server_review2_regressions.mojo` (15: the router failing closed, UTF-8 parameters, patterns refused, parameters cleared on a miss; keepalive on a paused stream, the configuration read-only, a saturating `min_rate` window, a log line to a broken stderr, the idle timer after a long response, a second `bind`, settings refused, the server's own errors with `Server`, request numbers, `unix_time`, the HTTP/2 preface);
  - `tests/server/test_static_review2_regressions.mojo` (10) and `test_static_review2_faults.mojo` (3, through the fault seam: openat2 refused, a short read);
  - `tests/linux/test_signal.mojo` (`write_no_sigpipe`).

  The most severe:
  - **A file rewritten in place while it downloaded was sent whole, as a mix of both versions,** under the first one's strong ETag (`cp`, a shell `>`, `rsync --inplace`). Now the connection ends short, and a file that changes between its lookup and its read is looked up again.
  - **ETags collided** for a same-size change that kept the modification time (`cp -p`, reproducible builds), so clients revalidated to stale 304s; times before 1970 lost their seconds.
  - **A long poll to a client that vanished without FIN or RST was never reclaimed**: nothing was sent, so nothing timed out. A paused stream now turns on keepalive probes.
  - **The router passed paths it cannot route to the application** (an encoded "/", NUL, over 128 segments), past every route's checks.
  - **A log line to a stderr pipe whose reader had gone killed the process** (SIGPIPE): a TLS reload note did it, and a certificate in its last third crash-looped every worker.
  - Also: `server_name` could be changed past its check (`Server.config()` is a copy now); a long `min_rate` window wrapped; the idle timer started when a long response was queued; a second `bind` closed the first listener; a negative `max_body` refused every request; FIFOs and devices were opened before their type was known; a 0711 directory answered 403; openat2 refused made every request fail after `open` succeeded; list fields in several lines; a Last-Modified a second past Date; non-UTF-8 parameters decoded lossily; patterns that could not work.
  - **Best practices** (`tests/server/test_server_practices.mojo`, 11): `admit` and `body_limit`, `max_body_memory`, `failed` and the error log, `completed` with `Exchange`, `max_requests` and `max_connection_age`, `request_timeout`, `drain_delay`, CONNECT answered 501, `Response.redirect`, nosniff and `cache_control` on files (see the sections above).
  - **Cost per request** (`pixi run -e bench bench-profile`, pipelined, one CPU): from 6,417 user-space instructions to 4,227, against hyper's 4,565 in the same run. Under wrk the same day (`bench/server/README.md`, `out/20261028-105727.json`): 0.84 µs of CPU a request pipelined on one CPU against hyper's 0.83 (1.31 against 0.85 before HR3 and SR2), 1,185k req/s against 1,193k; on 4 CPUs, 2,153k against 2,073k. The Content-Type default is set without checks, `path()` scans bytes, `Expect` is read from the codec's summary, and the server hands the codec its Date and Server lines encoded once a second and the body's length as a number (`ServerConnection._respond`, checked byte for byte against `send_response` by `tests/http/test_respond.mojo`). Building an `Error` ahead to hold one had cost a stack trace per request (60 instructions); errors are now handled where they are caught.
  - **Planted bugs:** 62 of 62 caught: 31 for the findings, 25 for the best practices, 6 for the savings. Three survived the first tests and got better ones: STA-3's measured queued output, which the loop already bounds (it now measures the buffers); the unchecked Content-Type and the last chunk's end were not looked at by `test_server.mojo` (a Content-Type test, and `test_server_connection.mojo`'s exact bytes, catch them).
  - **Not done** (the owner's decisions, or later): sendfile for large files; precompressed files; a cross-thread waker; socket activation, readiness and sd_notify; SIGHUP; 503 at the connection cap; WebSocket; renames (`server_name` → `server_header`); PROXY protocol; a default `idle_timeout` of 75 s (load balancers keep 60); workers forced to `reuseport`.
