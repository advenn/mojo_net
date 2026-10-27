"""`llm.client.Client` against tests/llm/llm_peer.py, a fake model API in
Python that speaks OpenAI's chat completions and embeddings and Anthropic's
Messages as their API references show them: whole and streamed replies,
tool calls, the auth headers, retries (429 with retry-after-ms, 500s, a
503 that says not to), API errors with their request ids, streams that
are cut short or carry an error event, a stream's idle timeout, and a port
nobody listens on."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind
from linux.time import Duration, Instant
from llm import ChatRequest, Delta, DeltaKind, LlmError, Message, RetryPolicy, Tool
from llm.client import Client, Provider, ReplyStream

from llm_peer import LlmPeer


def _fast() -> RetryPolicy:
    """The default policy's retries, with short waits."""
    var p = RetryPolicy()
    p.initial = Duration.from_millis(5)
    p.max_delay = Duration.from_millis(20)
    return p


def _req(text: StringSlice = "hello") -> ChatRequest:
    var r = ChatRequest("test-model", [Message.system("Be brief."), Message.user(text)])
    r.max_tokens = 64
    return r^


def _drain(mut s: ReplyStream) raises LlmError -> List[Delta]:
    var out = List[Delta]()
    var d = Delta()
    while s.next(d):
        out.append(d.copy())
    return out^


def _error(mut c: Client, req: ChatRequest) -> LlmError:
    try:
        _ = c.chat(req)
    except e:
        return e^
    return LlmError(0, "no error")


def _stream_error(mut c: Client, req: ChatRequest) -> LlmError:
    try:
        var s = c.stream(req)
        _ = _drain(s)
    except e:
        return e^
    return LlmError(0, "no error")


def test_openai_chat() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("ok"), "sk-test")
    var reply = c.chat(_req("hi there"))
    assert_equal(reply.text, "echo: hi there")
    assert_equal(reply.finish_reason, "stop")
    assert_equal(reply.usage.input_tokens, 9)
    assert_equal(reply.usage.output_tokens, 12)
    assert_equal(reply.id, "chatcmpl-1")
    var log = peer.log()
    assert_equal(Int(py=log.__len__()), 1)
    var r = log[0]
    assert_equal(String(r["path"]), "/ok/v1/chat/completions")
    assert_equal(String(r["headers"]["authorization"]), "Bearer sk-test")
    assert_equal(String(r["headers"]["content-type"]), "application/json")
    assert_equal(String(r["body"]["model"]), "test-model")
    assert_equal(String(r["body"]["messages"][1]["content"]), "hi there")
    assert_equal(Int(py=r["body"]["max_tokens"]), 64)
    assert_false(Bool(py=r["body"].__contains__("stream")))
    peer^.stop()


def test_openai_tool_calls_round_trip() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("tools"))
    var req = _req("weather?")
    req.tools.append(Tool("get_weather", "The weather at a place", '{"type":"object","properties":{"location":{"type":"string"}}}'))
    var reply = c.chat(req)
    assert_equal(len(reply.tool_calls), 1)
    assert_equal(reply.tool_calls[0].name, "get_weather")
    assert_equal(reply.tool_calls[0].arguments, '{"location": "Tashkent"}')
    assert_equal(reply.finish_reason, "tool_calls")
    assert_equal(reply.text, "")
    # Send the call and its result back.
    req.messages.append(Message.assistant("", reply.tool_calls.copy()))
    req.messages.append(Message.tool(reply.tool_calls[0].id, "sunny, 21 C"))
    _ = c.chat(req)
    var body = peer.log()[1]["body"]
    assert_equal(String(body["tools"][0]["function"]["parameters"]["properties"]["location"]["type"]), "string")
    var m = body["messages"]
    assert_true(m[2]["content"] is Python.none())
    assert_equal(String(m[2]["tool_calls"][0]["function"]["arguments"]), '{"location": "Tashkent"}')
    assert_equal(String(m[3]["role"]), "tool")
    assert_equal(String(m[3]["tool_call_id"]), "call_1")
    assert_false(Bool(py=peer.log()[0]["headers"].__contains__("authorization")))  # (no key: no header)
    peer^.stop()


def test_openai_stream() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("ok"), "sk-test")
    var s = c.stream(_req("streaming"))
    var ds = _drain(s)
    var text = String()
    for d in ds:
        if d.kind == DeltaKind.TEXT:
            text += d.text
    assert_equal(text, "echo: streaming")
    var last = ds[len(ds) - 1].copy()
    assert_true(last.kind == DeltaKind.DONE)
    assert_equal(last.text, "stop")
    assert_equal(last.usage.output_tokens, 12)
    var whole = s.reply()
    assert_equal(whole.text, "echo: streaming")
    assert_equal(whole.id, "chatcmpl-2")
    var body = peer.log()[0]["body"]
    assert_true(Bool(py=body["stream"]))
    assert_true(Bool(py=body["stream_options"]["include_usage"]))
    assert_equal(String(peer.log()[0]["headers"]["accept"]), "text/event-stream")
    peer^.stop()


def test_openai_stream_tool_calls() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("tools"))
    var s = c.stream(_req())
    var ds = _drain(s)
    var starts = 0
    var args = List[String]()
    args.append(String())
    args.append(String())
    for d in ds:
        if d.kind == DeltaKind.TOOL_CALL:
            assert_equal(d.index, starts)
            starts += 1
        elif d.kind == DeltaKind.TOOL_ARGS:
            args[d.index] += d.text
    assert_equal(starts, 2)
    assert_equal(args[0], '{"location": "Tashkent"}')
    var whole = s.reply()
    assert_equal(len(whole.tool_calls), 2)
    assert_equal(whole.tool_calls[0].id, "call_1")
    assert_equal(whole.tool_calls[0].arguments, '{"location": "Tashkent"}')
    assert_equal(whole.tool_calls[1].name, "get_time")
    assert_equal(whole.tool_calls[1].arguments, "{}")
    assert_equal(whole.finish_reason, "tool_calls")
    peer^.stop()


def test_anthropic_messages() raises:
    var peer = LlmPeer()
    var c = Client(Provider.ANTHROPIC, peer.base("ok"), "sk-ant")
    var reply = c.chat(_req("bonjour"))
    assert_equal(reply.text, "echo: bonjour")
    assert_equal(reply.finish_reason, "end_turn")
    assert_equal(reply.usage.input_tokens, 25)
    var r = peer.log()[0]
    assert_equal(String(r["path"]), "/ok/v1/messages")
    assert_equal(String(r["headers"]["x-api-key"]), "sk-ant")
    assert_equal(String(r["headers"]["anthropic-version"]), "2023-06-01")
    assert_false(Bool(py=r["headers"].__contains__("authorization")))
    assert_equal(String(r["body"]["system"]), "Be brief.")
    assert_equal(Int(py=r["body"]["messages"].__len__()), 1)
    peer^.stop()


def test_anthropic_tools_and_stream() raises:
    var peer = LlmPeer()
    var c = Client(Provider.ANTHROPIC, peer.base("tools"), "sk-ant")
    var reply = c.chat(_req())
    assert_equal(reply.text, "Let me check.")
    assert_equal(len(reply.tool_calls), 1)
    assert_equal(reply.tool_calls[0].arguments, '{"location":"Tashkent"}')
    var s = c.stream(_req())
    var ds = _drain(s)
    var whole = s.reply()
    assert_equal(whole.text, "Let me check.")
    assert_equal(len(whole.tool_calls), 2)
    assert_equal(whole.tool_calls[0].arguments, '{"location": "Tashkent"}')
    assert_equal(whole.tool_calls[1].arguments, "{}")  # (no input deltas)
    assert_equal(whole.finish_reason, "tool_use")
    assert_equal(whole.usage.input_tokens, 25)
    assert_equal(whole.usage.output_tokens, 15)
    assert_true(ds[len(ds) - 1].kind == DeltaKind.DONE)
    # Tool results go back as one user turn of tool_result blocks.
    var req = _req()
    req.messages.append(Message.assistant("Let me check.", reply.tool_calls.copy()))
    req.messages.append(Message.tool("toolu_1", "sunny"))
    req.messages.append(Message.tool("toolu_2", "noon"))
    _ = c.chat(req)
    var m = peer.log()[2]["body"]["messages"]
    assert_equal(Int(py=m.__len__()), 3)
    assert_equal(String(m[1]["content"][1]["type"]), "tool_use")
    assert_equal(String(m[1]["content"][1]["input"]["location"]), "Tashkent")
    assert_equal(String(m[2]["role"]), "user")
    assert_equal(Int(py=m[2]["content"].__len__()), 2)
    assert_equal(String(m[2]["content"][1]["tool_use_id"]), "toolu_2")
    peer^.stop()


def test_embeddings() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("ok"))
    var inputs: List[String] = ["a", "bcd", "efghij"]
    var e = c.embed("emb-model", inputs)
    assert_equal(len(e.vectors), 3)
    for i in range(3):
        assert_equal(len(e.vectors[i]), 4)
        assert_equal(e.vectors[i][0], Float32(inputs[i].byte_length()))
        assert_equal(e.vectors[i][1], Float32(i))
        assert_equal(e.vectors[i][3], Float32(-1.25))
    assert_equal(e.usage.input_tokens, 7)
    assert_equal(String(peer.log()[0]["body"]["encoding_format"]), "base64")
    var kind = 0
    try:
        var a = Client(Provider.ANTHROPIC, peer.base("ok"))
        _ = a.embed("m", inputs)
    except err:
        kind = err.kind
    assert_equal(kind, LlmError.USAGE)
    peer^.stop()


def test_retries_rate_limit_then_succeeds() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("rate-a-2"), retry=_fast())
    var reply = c.chat(_req("again"))
    assert_equal(reply.text, "echo: again")
    assert_equal(Int(py=peer.log().__len__()), 3)
    # A stream is retried too, until its head.
    var s = c.stream(_req("s"))
    _ = _drain(s)
    peer^.stop()


def test_retries_give_up() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("fail-b-5"), retry=_fast())
    var e = _error(c, _req())
    assert_equal(e.kind, LlmError.HTTP)
    assert_equal(e.status, 500)
    assert_equal(e.retries, 2)
    assert_equal(e.type, "server_error")
    assert_equal(Int(py=peer.log().__len__()), 3)
    var none = Client(Provider.OPENAI, peer.base("fail-c-5"), retry=RetryPolicy.none())
    assert_equal(_error(none, _req()).retries, 0)
    peer^.stop()


def test_api_errors_are_not_retried() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("bad"), retry=_fast())
    var e = _error(c, _req())
    assert_equal(e.kind, LlmError.HTTP)
    assert_equal(e.status, 400)
    assert_equal(e.type, "invalid_request_error")
    assert_equal(e.code, "invalid_value")
    assert_equal(e.message, "Invalid 'messages': empty")
    assert_equal(e.request_id, "req_123")
    assert_equal(e.retries, 0)
    var nc = Client(Provider.OPENAI, peer.base("noretry"), retry=_fast())
    var n = _error(nc, _req())
    assert_equal(n.status, 503)
    assert_equal(n.retries, 0)  # (x-should-retry: false)
    var s = _stream_error(c, _req())
    assert_equal(s.status, 400)
    assert_equal(s.request_id, "req_123")
    assert_equal(Int(py=peer.log().__len__()), 3)
    var hc = Client(Provider.OPENAI, peer.base("html"))
    var html = _error(hc, _req())
    assert_equal(html.kind, LlmError.PROTOCOL)
    peer^.stop()


def test_broken_streams() raises:
    var peer = LlmPeer()
    for p in [Provider.OPENAI, Provider.ANTHROPIC]:
        var cut = Client(p, peer.base("cut"))
        assert_equal(_stream_error(cut, _req()).kind, LlmError.PROTOCOL)
        var broken = Client(p, peer.base("broken"))
        var e = _stream_error(broken, _req("a longer message"))
        assert_equal(e.kind, LlmError.API)
        assert_true(e.message == "The model is overloaded" or e.message == "Overloaded", e.message)
    var ac = Client(Provider.ANTHROPIC, peer.base("broken"))
    var a = _stream_error(ac, _req("a longer message"))
    assert_equal(a.type, "overloaded_error")
    peer^.stop()


def test_stream_idle_timeout() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("slow"), stream_idle=Duration.from_millis(500))
    var t = Instant.now()
    var e = _stream_error(c, _req("slowly"))
    assert_equal(e.kind, LlmError.TRANSPORT)
    assert_true(e.io.kind == ErrorKind.TimedOut)
    assert_true(Instant.now().duration_since(t) < Duration.from_secs(3))
    peer^.stop()


def test_connection_refused_is_retried_then_transport() raises:
    # A port with no listener: bind one, note it, close it.
    var socket = Python.import_module("socket")
    var s = socket.socket()
    _ = s.bind(Python.tuple("127.0.0.1", 0))
    var port = Int(py=s.getsockname()[1])
    _ = s.close()
    var c = Client(Provider.OPENAI, String("http://127.0.0.1:", port, "/v1"), retry=_fast())
    var e = _error(c, _req())
    assert_equal(e.kind, LlmError.TRANSPORT)
    assert_true(e.io.kind == ErrorKind.ConnectionRefused)
    assert_equal(e.retries, 2)


def test_keys_cannot_inject_headers() raises:
    """A key with CR or LF is refused before anything is sent."""
    for key in ["sk\r\nX-Evil: 1", "sk\nX: y", "sk\r"]:
        var c = Client(Provider.OPENAI, "http://127.0.0.1:9/v1", key)
        assert_equal(_error(c, _req()).kind, LlmError.USAGE)
        var a = Client(Provider.ANTHROPIC, "http://127.0.0.1:9/v1", key)
        assert_equal(_error(a, _req()).kind, LlmError.USAGE)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
