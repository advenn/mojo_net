"""Print the server-sent events of a URL as they arrive, the way a client
reads tokens streamed by an LLM API.

    pixi run mojo run -I src examples/http/sse_events.mojo URL [JSON-BODY]

With a body, the request is a POST of `application/json` (add an
`Authorization` header for a real API); without one, a GET. A 429 or 503
prints how long the server asks to wait. The stream ends at its end or at
OpenAI's `[DONE]`; Ctrl-C cancels it.
"""

from std.sys import argv, exit, stderr

from http.client import Client, EventStream
from http.headers import Headers
from http.retry import retry_after
from http.sse import SseEvent
from linux.time import Duration, unix_time_ns


def main() raises:
    var args = argv()
    if len(args) < 2 or len(args) > 3:
        print("usage: sse_events URL [JSON-BODY]", file=stderr)
        exit(2)
        return
    var client = Client()
    var h = Headers()
    h.add("Accept", "text/event-stream")
    var body = String(args[2]) if len(args) == 3 else String()
    if len(args) == 3:
        h.add("Content-Type", "application/json")
    var method = "POST" if len(args) == 3 else "GET"
    var r = client.stream(method, String(args[1]), h, body.as_bytes(), idle_timeout=Duration.from_secs(30))
    if r.status == 429 or r.status == 503:
        var wait = retry_after(r.headers, unix_time_ns() // 1_000_000_000)
        print(r.status, r.reason, "; retry after", wait.value() if wait else Duration.ZERO, file=stderr)
        exit(1)
        return
    if r.status != 200:
        print(r.status, r.reason, file=stderr)
        print(String(from_utf8_lossy=Span(r.read_all(1024 * 1024))), file=stderr)
        exit(1)
        return
    var events = EventStream(r^)
    var ev = SseEvent()
    while events.next(ev):
        if ev.data == "[DONE]":
            break
        print(ev.event, ": ", ev.data, sep="")
