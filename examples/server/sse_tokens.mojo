"""Stream tokens as server-sent events, the way an OpenAI-compatible
inference server does, with a fake model that makes a token every 50 ms.

    pixi run mojo run -I src examples/server/sse_tokens.mojo [PORT]
    curl -N -X POST localhost:8080/v1/completions
    pixi run mojo run -I src examples/http/sse_events.mojo http://127.0.0.1:8080/v1/completions '{}'

The model runs outside the handler: the program's own loop calls
`server.step` and, when a stream has a token due, hands it over and wakes
the stream (`Server.wake`). An inference engine on other threads would do
the same with what it has generated. Each event is a JSON chunk; the
stream ends with `data: [DONE]`. A client that leaves stops its
generation (`stream_ended`). Past `MAX_STREAMS` at once, a request gets
429 with `Retry-After`. Paused streams get a heartbeat comment every 15 s.
"""

from std.sys import argv

from http.sse import write_event
from linux.time import Duration, Instant
from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig

comptime MAX_STREAMS = 64
comptime TOKENS: List[StaticString] = ["Mojo", " is", " a", " language", " for", " AI", "."]


@fieldwise_init
struct Generation(Copyable, Movable):
    var id: UInt64
    """The connection (`Request.id`) the tokens go to."""
    var next: Int
    """The next token's index."""
    var ready: Int
    """Tokens the model has made so far."""
    var due: Instant
    """When the model makes its next one."""


struct Tokens(Handler):
    var running: List[Generation]

    def __init__(out self):
        self.running = List[Generation]()

    def _find(self, id: UInt64) -> Int:
        for i in range(len(self.running)):
            if self.running[i].id == id:
                return i
        return -1

    def handle(mut self, req: Request, mut res: Response) raises:
        var path = req.path()
        if not (path == "/v1/completions" and req.method == "POST"):
            res.text(404, "POST /v1/completions\n")
            return
        if len(self.running) >= MAX_STREAMS:
            res.retry_later(429, Duration.from_secs(1))
            return
        self.running.append(Generation(req.id, 0, 0, Instant.now() + Duration.from_millis(50)))
        res.event_stream()

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        var i = self._find(req.id)
        if i < 0:
            return False
        ref g = self.running[i]
        var tokens = materialize[TOKENS]()
        while g.next < g.ready:
            var text = String(tokens[g.next])
            write_event(out, String('{"choices":[{"index":0,"text":"', text, '"}]}'))
            g.next += 1
        if g.next == len(tokens):
            write_event(out, "[DONE]")
            return False
        return True  # (nothing more yet: paused until the next token)

    def stream_ended(mut self, req: Request, finished: Bool):
        # Finished, or the client left: either way, stop generating for it.
        var i = self._find(req.id)
        if i >= 0:
            _ = self.running.pop(i)


def main() raises:
    var args = argv()
    var port = String(args[1]) if len(args) > 1 else String("8080")
    var server = Server(Tokens(), ServerConfig(server_name="sse-tokens"))
    server.bind(SocketAddr.parse(String("0.0.0.0:", port)))
    print("listening on port", port)
    var count = len(materialize[TOKENS]())
    while True:
        server.step(Duration.from_millis(10))
        # The "model": a token every 50 ms for each stream.
        var now = Instant.now()
        for i in range(len(server.handler.running)):
            ref g = server.handler.running[i]
            if g.ready < count and now >= g.due:
                g.ready += 1
                g.due = now + Duration.from_millis(50)
                server.wake(g.id)
