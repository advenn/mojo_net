"""A fake model API for tests/llm (test-only Python; not a test file): Python's
http.server speaking OpenAI's chat completions and embeddings and Anthropic's
Messages, normal and streamed, the way the providers' API references show
them. It prints "PORT <n>" and serves until killed, or until its stdin ends (the
test process holding it has gone).

The path picks the behaviour: `/<scenario>/v1/...`, where <scenario> is
  ok              answers (the text is "echo: " + the last user message)
  tools           answers with a tool call (get_weather, {"location": "Tashkent"})
  rate-<id>-<n>   429 with retry-after-ms: 5, n times for <id>, then ok
  fail-<id>-<n>   500 n times for <id>, then ok
  bad             400 with the API's error JSON and a request id
  noretry         503 with x-should-retry: false
  cut             a stream that stops before its end marker
  broken          a stream with an error event in the middle
  slow            a stream that pauses 3 s between pieces
  html            200 with a body that is not JSON
  hang            never answers (holds the connection 30 s)
  trickle500      a 500 whose body comes one byte every 0.2 s
  endless         a stream of text that never ends
  pings           an Anthropic stream of pings every 0.1 s, never ending
  badindex        a stream: "A", a chunk with a tool call index 7, "B", [DONE]
  drop            a stream cut by the connection's end (no last chunk)
  retrybroken-<id>-<n>  429 n times, then a stream with an error event
Streams carry x-request-id: req_stream (request-id for Anthropic).
GET /_log returns every request so far (path, headers, body) as JSON, and
POST /_reset forgets them.
"""

import base64
import json
import os
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = []
COUNTS = {}
LOCK = threading.Lock()


def _echo(messages):
    text = ""
    for m in messages:
        if m.get("role") == "user":
            c = m.get("content")
            text = c if isinstance(c, str) else json.dumps(c)
    return "echo: " + text


def _pieces(text, n=3):
    return [text[i : i + n] for i in range(0, len(text), n)] or [""]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send_json(self, status, obj, headers=()):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _start_stream(self, anthropic=False):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("request-id" if anthropic else "x-request-id", "req_stream")
        self.end_headers()

    def _chunk(self, data):
        b = data.encode()
        self.wfile.write(b"%x\r\n" % len(b) + b + b"\r\n")
        self.wfile.flush()

    def _end_stream(self):
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def do_GET(self):
        if self.path == "/_log":
            with LOCK:
                self._send_json(200, LOG)
            return
        self._send_json(404, {"error": {"message": "no such route", "type": "invalid_request_error"}})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n)
        if self.path == "/_reset":
            with LOCK:
                LOG.clear()
                COUNTS.clear()
            self._send_json(200, {})
            return
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        with LOCK:
            LOG.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
        parts = self.path.split("/")
        scenario = parts[1] if len(parts) > 2 else ""
        endpoint = "/" + "/".join(parts[3:])
        if scenario.startswith("rate-") or scenario.startswith("fail-") or scenario.startswith("retrybroken-"):
            _, ident, times = scenario.split("-")
            with LOCK:
                seen = COUNTS.get(scenario, 0)
                COUNTS[scenario] = seen + 1
            if seen < int(times):
                if not scenario.startswith("fail-"):
                    self._send_json(429, {"error": {"message": "Rate limit reached", "type": "requests", "code": "rate_limit_exceeded"}},
                                    [("retry-after-ms", "5"), ("x-request-id", "req_rate")])
                else:
                    self._send_json(500, {"error": {"message": "The server had an error", "type": "server_error"}})
                return
            scenario = "broken" if scenario.startswith("retrybroken-") else "ok"
        if scenario == "hang":
            time.sleep(30)
            return
        if scenario == "nohead":
            self.close_connection = True  # (closed before any response: retryable)
            return
        if scenario.startswith("ratehang-"):
            with LOCK:
                seen = COUNTS.get(scenario, 0)
                COUNTS[scenario] = seen + 1
            if seen == 0:
                self._send_json(429, {"error": {"message": "Rate limit reached", "type": "requests"}}, [("retry-after-ms", "1500")])
                return
            time.sleep(30)
            return
        if scenario == "trickle500":
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "100000")
            self.end_headers()
            for _ in range(100000):
                self.wfile.write(b" ")
                self.wfile.flush()
                time.sleep(0.2)
            return
        if scenario == "bad":
            self._send_json(400, {"error": {"message": "Invalid 'messages': empty", "type": "invalid_request_error",
                                            "param": "messages", "code": "invalid_value"}},
                            [("x-request-id", "req_123")])
            return
        if scenario == "noretry":
            self._send_json(503, {"error": {"message": "unavailable", "type": "server_error"}}, [("x-should-retry", "false")])
            return
        if scenario == "html":
            b = b"<html>not json</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        if endpoint == "/chat/completions":
            self._openai_chat(scenario, body)
        elif endpoint == "/messages":
            self._anthropic(scenario, body)
        elif endpoint == "/embeddings":
            self._embeddings(body)
        else:
            self._send_json(404, {"error": {"message": "no such endpoint " + endpoint, "type": "invalid_request_error"}})

    # ---- OpenAI ----

    def _openai_chat(self, scenario, body):
        text = _echo(body.get("messages", []))
        tools = scenario == "tools"
        if not body.get("stream"):
            message = {"role": "assistant", "content": None if tools else text, "refusal": None}
            if tools:
                message["tool_calls"] = [{"id": "call_1", "type": "function",
                                          "function": {"name": "get_weather", "arguments": "{\"location\": \"Tashkent\"}"}}]
            self._send_json(200, {"id": "chatcmpl-1", "object": "chat.completion", "created": 1730000000, "model": body["model"],
                                  "choices": [{"index": 0, "message": message, "logprobs": None,
                                               "finish_reason": "tool_calls" if tools else "stop"}],
                                  "usage": {"prompt_tokens": 9, "completion_tokens": 12, "total_tokens": 21}},
                            [("x-request-id", "req_ok")])
            return
        self._start_stream()
        base = {"id": "chatcmpl-2", "object": "chat.completion.chunk", "created": 1730000000, "model": body["model"]}

        def chunk(delta, finish=None):
            c = dict(base)
            c["choices"] = [{"index": 0, "delta": delta, "logprobs": None, "finish_reason": finish}]
            self._chunk("data: " + json.dumps(c) + "\n\n")

        chunk({"role": "assistant", "content": ""})
        if scenario == "endless":
            while True:
                chunk({"content": "x" * 100})
        if scenario == "badindex":
            chunk({"content": "A"})
            chunk({"tool_calls": [{"index": 0, "id": "a", "type": "function", "function": {"name": "f", "arguments": "{}"}},
                                  {"index": 7, "function": {"arguments": "x"}}]})
            chunk({"content": "B"})
            chunk({}, "stop")
            self._chunk("data: [DONE]\n\n")
            self._end_stream()
            return
        if scenario == "drop":
            chunk({"content": "partial"})
            self.wfile.flush()
            self.close_connection = True
            return
        if tools:
            chunk({"tool_calls": [{"index": 0, "id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": ""}}]})
            for p in ["{\"loc", "ation\": \"Ta", "shkent\"}"]:
                chunk({"tool_calls": [{"index": 0, "function": {"arguments": p}}]})
            chunk({"tool_calls": [{"index": 1, "id": "call_2", "type": "function", "function": {"name": "get_time", "arguments": "{}"}}]})
        else:
            for i, p in enumerate(_pieces(text)):
                if scenario == "broken" and i == 2:
                    self._chunk("data: " + json.dumps({"error": {"message": "The model is overloaded", "type": "server_error"}}) + "\n\n")
                    self._end_stream()
                    return
                if scenario == "slow" and i == 1:
                    time.sleep(3)
                chunk({"content": p})
        if scenario == "cut":
            self._end_stream()
            return
        chunk({}, "tool_calls" if tools else "stop")
        if body.get("stream_options", {}).get("include_usage"):
            c = dict(base)
            c["choices"] = []
            c["usage"] = {"prompt_tokens": 9, "completion_tokens": 12, "total_tokens": 21}
            self._chunk("data: " + json.dumps(c) + "\n\n")
        self._chunk("data: [DONE]\n\n")
        self._end_stream()

    def _embeddings(self, body):
        data = []
        for i, s in enumerate(body["input"]):
            vec = [float(len(s)), float(i), 0.5, -1.25]
            if body.get("encoding_format") == "base64":
                emb = base64.b64encode(struct.pack("<%df" % len(vec), *vec)).decode()
            else:
                emb = vec
            data.append({"object": "embedding", "index": i, "embedding": emb})
        data.reverse()  # (clients must place vectors by index)
        self._send_json(200, {"object": "list", "data": data, "model": body["model"],
                              "usage": {"prompt_tokens": 7, "total_tokens": 7}})

    # ---- Anthropic ----

    def _anthropic(self, scenario, body):
        text = _echo(body.get("messages", []))
        tools = scenario == "tools"
        if not body.get("stream"):
            content = [{"type": "text", "text": text}]
            if tools:
                content = [{"type": "text", "text": "Let me check."},
                           {"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {"location": "Tashkent"}}]
            self._send_json(200, {"id": "msg_1", "type": "message", "role": "assistant", "model": body["model"],
                                  "content": content, "stop_reason": "tool_use" if tools else "end_turn", "stop_sequence": None,
                                  "usage": {"input_tokens": 25, "output_tokens": 13}},
                            [("request-id", "req_ant")])
            return
        self._start_stream(anthropic=True)

        def event(name, obj):
            self._chunk("event: " + name + "\ndata: " + json.dumps(obj) + "\n\n")

        event("message_start", {"type": "message_start", "message": {"id": "msg_2", "type": "message", "role": "assistant",
                                "content": [], "model": body["model"], "stop_reason": None, "stop_sequence": None,
                                "usage": {"input_tokens": 25, "output_tokens": 1}}})
        if scenario == "pings":
            while True:
                event("ping", {"type": "ping"})
                time.sleep(0.1)
        event("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})
        event("ping", {"type": "ping"})
        for i, p in enumerate(_pieces("Let me check." if tools else text)):
            if scenario == "broken" and i == 2:
                event("error", {"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}})
                self._end_stream()
                return
            event("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": p}})
        event("content_block_stop", {"type": "content_block_stop", "index": 0})
        if tools:
            event("content_block_start", {"type": "content_block_start", "index": 1,
                                          "content_block": {"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {}}})
            for p in ["{\"location\": \"Ta", "shkent\"}"]:
                event("content_block_delta", {"type": "content_block_delta", "index": 1,
                                              "delta": {"type": "input_json_delta", "partial_json": p}})
            event("content_block_stop", {"type": "content_block_stop", "index": 1})
            event("content_block_start", {"type": "content_block_start", "index": 2,
                                          "content_block": {"type": "tool_use", "id": "toolu_2", "name": "get_time", "input": {}}})
            event("content_block_stop", {"type": "content_block_stop", "index": 2})
        event("some_future_event", {"type": "some_future_event", "detail": 1})
        if scenario == "cut":
            self._end_stream()
            return
        event("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use" if tools else "end_turn",
                                "stop_sequence": None}, "usage": {"output_tokens": 15}})
        event("message_stop", {"type": "message_stop"})
        self._end_stream()


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # A client that hangs up mid-stream (cancelling, or timing out) is
        # what several tests do on purpose.
        if isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


def _exit_with_parent():
    """The test process holds our stdin: when it ends, even by a crash,
    stdin reaches EOF and the server goes too (no orphans)."""
    sys.stdin.read()
    os._exit(0)


def main():
    threading.Thread(target=_exit_with_parent, daemon=True).start()
    server = Server(("127.0.0.1", 0), Handler)
    print("PORT", server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
