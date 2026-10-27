"""`llm.openai`, `llm.anthropic` and `llm.retry`, sans-I/O: request bodies
read back by Python's json and checked field by field; replies, stream
chunks and events shaped as the providers' API references show them,
and malformed ones; embeddings as numbers and as base64 float32 (encoded
by Python's struct and base64); the retry waits."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from http.headers import Headers
from linux.time import Duration
from llm import ChatRequest, Delta, DeltaKind, LlmError, Message, RetryPolicy, Tool, ToolCall
from llm.anthropic import EventDecoder, read_messages, write_messages
from llm.openai import ChunkDecoder, read_chat, read_embeddings, read_error, write_chat, write_embeddings
from llm.retry import Jitter, backoff, retryable_status, wait_before_retry


def _py(body: List[UInt8]) raises -> PythonObject:
    var json = Python.import_module("json")
    return json.loads(String(unsafe_from_utf8=Span(body)))


def _b(s: StringSlice) -> List[UInt8]:
    return List[UInt8](s.as_bytes())


def _req() -> ChatRequest:
    var r = ChatRequest("m1", [Message.system("rule one"), Message.system("rule two"), Message.user("hi")])
    r.max_tokens = 50
    return r^


def _usage_kind_chat(req: ChatRequest, anthropic: Bool) -> Int:
    try:
        if anthropic:
            _ = write_messages(req)
        else:
            _ = write_chat(req)
    except e:
        return e.kind
    return 0


def test_write_chat() raises:
    var req = _req()
    req.messages.append(Message.assistant("", [ToolCall("call_9", "f", '{"x": 1}')]))
    req.messages.append(Message.tool("call_9", "result"))
    req.tools.append(Tool("f", "does f", '{"type":"object","properties":{"x":{"type":"integer"}}}'))
    req.temperature = 0.7
    req.top_p = 0.9
    req.stop = ["END", "STOP"]
    req.seed = 42
    req.extra = '{"response_format": {"type": "json_object"}, "user": "u1"}'
    var b = _py(write_chat(req, stream=True))
    assert_equal(String(b["model"]), "m1")
    assert_equal(Int(py=b["messages"].__len__()), 5)
    assert_equal(String(b["messages"][0]["role"]), "system")
    assert_true(b["messages"][3]["content"] is Python.none())
    assert_equal(String(b["messages"][3]["tool_calls"][0]["function"]["arguments"]), '{"x": 1}')
    assert_equal(String(b["messages"][4]["tool_call_id"]), "call_9")
    assert_equal(String(b["tools"][0]["type"]), "function")
    assert_equal(String(b["tools"][0]["function"]["parameters"]["properties"]["x"]["type"]), "integer")
    assert_equal(Float64(py=b["temperature"]), 0.7)
    assert_equal(Float64(py=b["top_p"]), 0.9)
    assert_equal(String(b["stop"][1]), "STOP")
    assert_equal(Int(py=b["seed"]), 42)
    assert_equal(Int(py=b["max_tokens"]), 50)
    assert_true(Bool(py=b["stream"]))
    assert_true(Bool(py=b["stream_options"]["include_usage"]))
    assert_equal(String(b["response_format"]["type"]), "json_object")
    assert_equal(String(b["user"]), "u1")
    var plain = _py(write_chat(_req()))
    assert_false(Bool(py=plain.__contains__("stream")))
    assert_false(Bool(py=plain.__contains__("temperature")))
    assert_false(Bool(py=plain.__contains__("tools")))


def test_write_chat_refusals() raises:
    var r = _req()
    r.extra = '{"model": "other"}'
    assert_equal(_usage_kind_chat(r, False), LlmError.USAGE)
    r = _req()
    r.extra = "[1]"
    assert_equal(_usage_kind_chat(r, False), LlmError.USAGE)
    r = _req()
    r.tools.append(Tool("f", "", "not json"))
    assert_equal(_usage_kind_chat(r, False), LlmError.USAGE)
    r = _req()
    r.tools.append(Tool("f", "", "[]"))
    assert_equal(_usage_kind_chat(r, False), LlmError.USAGE)
    r = _req()
    r.messages.append(Message("narrator", "x"))
    assert_equal(_usage_kind_chat(r, False), LlmError.USAGE)
    r = _req()
    r.messages.append(Message.tool("", "x"))
    assert_equal(_usage_kind_chat(r, False), LlmError.USAGE)
    r = _req()
    r.temperature = Float64.MAX * 2 - Float64.MAX * 2  # (NaN)
    assert_equal(_usage_kind_chat(r, False), LlmError.USAGE)
    assert_equal(_usage_kind_chat(ChatRequest("m"), False), LlmError.USAGE)
    assert_equal(_usage_kind_chat(ChatRequest("", [Message.user("x")]), False), LlmError.USAGE)
    var bad: List[UInt8] = [0xFF]
    assert_equal(_usage_kind_chat(ChatRequest("m", [Message.user(StringSlice(unsafe_from_utf8=Span(bad)))]), False), LlmError.USAGE)


def test_write_messages() raises:
    var req = _req()
    req.messages.append(Message.assistant("checking", [ToolCall("toolu_1", "f", '{"x": 1}'), ToolCall("toolu_2", "g", "")]))
    req.messages.append(Message.tool("toolu_1", "one"))
    req.messages.append(Message.tool("toolu_2", "two"))
    req.messages.append(Message.user("thanks"))
    req.tools.append(Tool("f", "does f", '{"type":"object"}'))
    req.stop = ["END"]
    var b = _py(write_messages(req, stream=True))
    assert_equal(String(b["system"]), "rule one\n\nrule two")
    var m = b["messages"]
    assert_equal(Int(py=m.__len__()), 4)
    assert_equal(String(m[0]["role"]), "user")
    assert_equal(String(m[1]["content"][0]["text"]), "checking")
    assert_equal(Int(py=m[1]["content"][1]["input"]["x"]), 1)
    assert_equal(Int(py=m[1]["content"][2]["input"].__len__()), 0)  # (no arguments: {})
    assert_equal(String(m[2]["role"]), "user")
    assert_equal(Int(py=m[2]["content"].__len__()), 2)
    assert_equal(String(m[2]["content"][0]["type"]), "tool_result")
    assert_equal(String(m[2]["content"][1]["content"]), "two")
    assert_equal(String(m[3]["content"]), "thanks")
    assert_equal(String(b["tools"][0]["input_schema"]["type"]), "object")
    assert_equal(String(b["stop_sequences"][0]), "END")
    assert_equal(Int(py=b["max_tokens"]), 50)
    assert_true(Bool(py=b["stream"]))
    var r = _req()
    r.max_tokens = 0
    assert_equal(_usage_kind_chat(r, True), LlmError.USAGE)
    r = _req()
    r.seed = 1
    assert_equal(_usage_kind_chat(r, True), LlmError.USAGE)
    r = _req()
    r.messages.append(Message.assistant("", [ToolCall("t", "f", "[1]")]))
    assert_equal(_usage_kind_chat(r, True), LlmError.USAGE)
    var only_system = ChatRequest("m", [Message.system("s")])
    only_system.max_tokens = 5
    assert_equal(_usage_kind_chat(only_system, True), LlmError.USAGE)


def _read_kind_chat(text: StringSlice) -> Int:
    try:
        _ = read_chat(text.as_bytes())
    except e:
        return e.kind
    return 0


def test_read_chat() raises:
    # (shaped as OpenAI's API reference shows them)
    var r = read_chat(
        _b('{"id":"chatcmpl-B9MBs8CjcvOU2jLn4n570S5qMJKcT","object":"chat.completion","created":1741569952,'
        + '"model":"gpt-4.1-2025-04-14","choices":[{"index":0,"message":{"role":"assistant","content":"Hello! How can I help?",'
        + '"refusal":null,"annotations":[]},"logprobs":null,"finish_reason":"stop"}],"usage":{"prompt_tokens":19,'
        + '"completion_tokens":10,"total_tokens":29,"prompt_tokens_details":{"cached_tokens":0}},"service_tier":"default"}')
    )
    assert_equal(r.text, "Hello! How can I help?")
    assert_equal(r.model, "gpt-4.1-2025-04-14")
    assert_equal(r.usage.input_tokens, 19)
    var t = read_chat(
        _b('{"id":"c","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_abc",'
        + '"type":"function","function":{"name":"get_weather","arguments":"{\\"location\\":\\"Boston\\"}"}}]},'
        + '"finish_reason":"tool_calls"}]}')
    )
    assert_equal(t.text, "")
    assert_equal(t.tool_calls[0].arguments, '{"location":"Boston"}')
    assert_equal(t.usage.input_tokens, -1)
    assert_equal(_read_kind_chat('{"choices":[]}'), LlmError.PROTOCOL)
    assert_equal(_read_kind_chat('{"choices":"x"}'), LlmError.PROTOCOL)
    assert_equal(_read_kind_chat('{"choices":[{"message":{"content":5}}]}'), LlmError.PROTOCOL)
    assert_equal(_read_kind_chat("<html>"), LlmError.PROTOCOL)
    assert_equal(_read_kind_chat('{"error":{"message":"boom","type":"server_error"}}'), LlmError.API)


def test_read_error() raises:
    var e = read_error(_b('{"error":{"message":"Incorrect API key provided","type":"invalid_request_error","param":null,"code":"invalid_api_key"}}'), 401)
    assert_equal(e.kind, LlmError.HTTP)
    assert_equal(e.status, 401)
    assert_equal(e.message, "Incorrect API key provided")
    assert_equal(e.code, "invalid_api_key")
    var a = read_error(_b('{"type":"error","error":{"type":"rate_limit_error","message":"Number of request tokens has exceeded your rate limit"}}'), 429)
    assert_equal(a.type, "rate_limit_error")
    assert_true(a.is_rate_limit())
    var n = read_error(_b('{"error":{"message":"m","code":429}}'), 429)
    assert_equal(n.code, "429")
    var h = read_error(_b("<html>Bad Gateway</html>"), 502)
    assert_equal(h.message, "<html>Bad Gateway</html>")
    assert_equal(h.status, 502)


def _feed_all(mut d: ChunkDecoder, events: List[String]) raises LlmError -> List[Delta]:
    var out = List[Delta]()
    for e in events:
        d.feed(e, out)
    return out^


def test_openai_chunks() raises:
    var events: List[String] = [
        '{"id":"x1","object":"chat.completion.chunk","model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":"","refusal":null},"finish_reason":null}]}',
        '{"id":"x1","choices":[{"index":0,"delta":{"content":"Hel"},"finish_reason":null}]}',
        '{"id":"x1","choices":[{"index":0,"delta":{"content":"lo"},"finish_reason":null}]}',
        '{"id":"x1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"f","arguments":"{\\"a"}}]}}]}',
        '{"id":"x1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\\":1}"}},{"index":1,"id":"call_2","function":{"name":"g","arguments":""}}]}}]}',
        '{"id":"x1","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}',
        '{"id":"x1","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}',
        "[DONE]",
    ]
    var d = ChunkDecoder()
    var ds = _feed_all(d, events)
    var kinds = List[DeltaKind]()
    for x in ds:
        kinds.append(x.kind)
    assert_equal(len(ds), 7)
    assert_true(kinds[0] == DeltaKind.TEXT and kinds[1] == DeltaKind.TEXT)
    assert_true(kinds[2] == DeltaKind.TOOL_CALL and kinds[3] == DeltaKind.TOOL_ARGS)
    assert_true(kinds[4] == DeltaKind.TOOL_ARGS and kinds[5] == DeltaKind.TOOL_CALL and kinds[6] == DeltaKind.DONE)
    assert_equal(ds[5].name, "g")
    assert_equal(ds[6].text, "tool_calls")
    assert_equal(ds[6].usage.output_tokens, 4)
    assert_equal(d.reply.text, "Hello")
    assert_equal(d.reply.tool_calls[0].arguments, '{"a":1}')
    assert_equal(d.reply.tool_calls[1].id, "call_2")
    d.finish()
    # After [DONE], nothing more; before it, the end is a cut.
    var kind = 0
    try:
        var out = List[Delta]()
        d.feed('{"choices":[]}', out)
    except e:
        kind = e.kind
    assert_equal(kind, LlmError.PROTOCOL)
    var cut = ChunkDecoder()
    _ = _feed_all(cut, [events[0], events[1]])
    kind = 0
    try:
        cut.finish()
    except e:
        kind = e.kind
    assert_equal(kind, LlmError.PROTOCOL)


def _chunk_error(events: List[String]) -> LlmError:
    var d = ChunkDecoder()
    try:
        _ = _feed_all(d, events)
    except e:
        return e^
    return LlmError(0, "none")


def test_openai_bad_chunks() raises:
    var e = _chunk_error(['{"error":{"message":"overloaded","type":"server_error","code":"busy"}}'])
    assert_equal(e.kind, LlmError.API)
    assert_equal(e.code, "busy")
    assert_equal(_chunk_error(["not json"]).kind, LlmError.PROTOCOL)
    assert_equal(_chunk_error(['{"choices":[{"index":0,"delta":{"tool_calls":[{"index":2,"function":{}}]}}]}']).kind, LlmError.PROTOCOL)
    assert_equal(_chunk_error(['{"choices":[{"index":0,"delta":{"content":[1]}}]}']).kind, LlmError.PROTOCOL)
    # Other choices than the first are skipped.
    var d = ChunkDecoder()
    var ds = _feed_all(d, ['{"choices":[{"index":1,"delta":{"content":"other"}},{"index":0,"delta":{"content":"mine"}}]}'])
    assert_equal(len(ds), 1)
    assert_equal(ds[0].text, "mine")


def _anthropic_feed(events: List[String], mut d: EventDecoder) raises LlmError -> List[Delta]:
    var out = List[Delta]()
    for e in events:
        d.feed(e, out)
    return out^


def test_anthropic_events() raises:
    # (shaped as Anthropic's streaming reference shows them)
    var events: List[String] = [
        '{"type":"message_start","message":{"id":"msg_1nZdL29xx5MUA1yADyHTEsnR8uuvGzszyY","type":"message","role":"assistant","content":[],"model":"claude-opus-4","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":472,"output_tokens":2}}}',
        '{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
        '{"type":"ping"}',
        '{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Okay"}}',
        '{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":", let me check"}}',
        '{"type":"content_block_stop","index":0}',
        '{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01T1x1fJ34qAmk2tNTrN7Up6","name":"get_weather","input":{}}}',
        '{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":""}}',
        '{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\\"location\\":"}}',
        '{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":" \\"San Francisco, CA\\"}"}}',
        '{"type":"content_block_stop","index":1}',
        '{"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":89}}',
        '{"type":"message_stop"}',
    ]
    var d = EventDecoder()
    var ds = _anthropic_feed(events, d)
    assert_equal(d.reply.text, "Okay, let me check")
    assert_equal(d.reply.tool_calls[0].name, "get_weather")
    assert_equal(d.reply.tool_calls[0].arguments, '{"location": "San Francisco, CA"}')
    assert_equal(d.reply.usage.input_tokens, 472)
    assert_equal(d.reply.usage.output_tokens, 89)
    assert_equal(d.reply.finish_reason, "tool_use")
    assert_true(ds[len(ds) - 1].kind == DeltaKind.DONE)
    assert_equal(ds[2].kind, DeltaKind.TOOL_CALL)
    assert_equal(ds[2].id, "toolu_01T1x1fJ34qAmk2tNTrN7Up6")
    d.finish()
    var cut = EventDecoder()
    _ = _anthropic_feed([events[0], events[1], events[3]], cut)
    var kind = 0
    try:
        cut.finish()
    except e:
        kind = e.kind
    assert_equal(kind, LlmError.PROTOCOL)


def _anthropic_error(events: List[String]) -> LlmError:
    var d = EventDecoder()
    try:
        _ = _anthropic_feed(events, d)
    except e:
        return e^
    return LlmError(0, "none")


def test_anthropic_bad_events() raises:
    var e = _anthropic_error(['{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}'])
    assert_equal(e.kind, LlmError.API)
    assert_equal(e.type, "overloaded_error")
    assert_equal(e.message, "Overloaded")
    assert_equal(_anthropic_error(['{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"x"}}']).kind, LlmError.PROTOCOL)
    assert_equal(_anthropic_error(['{"type":"content_block_start","index":3,"content_block":{"type":"text"}}']).kind, LlmError.PROTOCOL)
    assert_equal(
        _anthropic_error([
            '{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
            '{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{"}}',
        ]).kind,
        LlmError.PROTOCOL,
    )
    # Unknown events and deltas (thinking) are skipped.
    var d = EventDecoder()
    var ds = _anthropic_feed([
        '{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}',
        '{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hmm"}}',
        '{"type":"a_new_event"}',
    ], d)
    assert_equal(len(ds), 0)


def test_read_messages() raises:
    var r = read_messages(
        _b('{"id":"msg_013Zva2CMHLNnXjNJJKqJ2EF","type":"message","role":"assistant","model":"claude-opus-4",'
        + '"content":[{"type":"thinking","thinking":"...","signature":"x"},{"type":"text","text":"Hi! "},{"type":"text","text":"Ok."},'
        + '{"type":"tool_use","id":"toolu_1","name":"f","input":{"q":[1,2]}}],"stop_reason":"tool_use","stop_sequence":null,'
        + '"usage":{"input_tokens":2095,"output_tokens":503,"cache_read_input_tokens":0}}')
    )
    assert_equal(r.text, "Hi! Ok.")
    assert_equal(r.tool_calls[0].arguments, '{"q":[1,2]}')
    assert_equal(r.usage.output_tokens, 503)
    var kind = 0
    try:
        _ = read_messages(_b('{"type":"error","error":{"type":"api_error","message":"x"}}'))
    except e:
        kind = e.kind
    assert_equal(kind, LlmError.API)


def test_embeddings() raises:
    var inputs: List[String] = ["a", "b", "c"]
    var w = _py(write_embeddings("e1", inputs, dimensions=256))
    assert_equal(String(w["encoding_format"]), "base64")
    assert_equal(Int(py=w["dimensions"]), 256)
    assert_equal(Int(py=w["input"].__len__()), 3)
    # Base64 float32, from Python's struct, out of order.
    var py = Python.import_module("builtins")
    var pystruct = Python.import_module("struct")
    var b64 = Python.import_module("base64")
    var vals = Python.list(1.5, -2.25, 3.0e-8, 65504.0)
    var raw = pystruct.pack("<4f", vals[0], vals[1], vals[2], vals[3])
    var enc = String(b64.b64encode(raw).decode())
    var body = String('{"object":"list","data":[{"index":2,"embedding":"', enc, '"},{"index":0,"embedding":[0.5,1]},',
        '{"index":1,"embedding":"', enc, '"}],"model":"e1","usage":{"prompt_tokens":3,"total_tokens":3}}')
    var e = read_embeddings(body.as_bytes(), 3)
    assert_equal(len(e.vectors[0]), 2)
    assert_equal(e.vectors[0][0], Float32(0.5))
    for i in range(4):
        assert_equal(e.vectors[2][i], Float32(Float64(py=pystruct.unpack("<f", pystruct.pack("<f", vals[i]))[0])))
    assert_equal(e.usage.input_tokens, 3)
    _ = py
    var bad: List[String] = [
        '{"data":[{"index":0,"embedding":[1]}]}',  # (3 expected)
        '{"data":[{"index":0,"embedding":[1]},{"index":0,"embedding":[1]},{"index":2,"embedding":[1]}]}',
        '{"data":[{"index":0,"embedding":"AAA"},{"index":1,"embedding":[1]},{"index":2,"embedding":[1]}]}',
        '{"data":[{"index":0,"embedding":"AAAA"},{"index":1,"embedding":[1]},{"index":2,"embedding":[1]}]}',
        '{"data":[{"index":0,"embedding":["x"]},{"index":1,"embedding":[1]},{"index":2,"embedding":[1]}]}',
        '{"data":[{"index":0},{"index":1,"embedding":[1]},{"index":2,"embedding":[1]}]}',
        '{"data":[{"index":5,"embedding":[1]},{"index":1,"embedding":[1]},{"index":2,"embedding":[1]}]}',
    ]
    for b in bad:
        var kind = 0
        try:
            _ = read_embeddings(b.as_bytes(), 3)
        except err:
            kind = err.kind
        assert_equal(kind, LlmError.PROTOCOL, b)


def test_retry_waits() raises:
    var p = RetryPolicy()
    assert_equal(backoff(p, 0, 0.0), Duration.from_millis(500))
    assert_equal(backoff(p, 1, 0.0), Duration.from_secs(1))
    assert_equal(backoff(p, 3, 0.0), Duration.from_secs(4))
    assert_equal(backoff(p, 4, 0.0), Duration.from_secs(8))
    assert_equal(backoff(p, 40, 0.0), Duration.from_secs(8))
    assert_equal(backoff(p, 0, 0.5), Duration.from_millis(437) + Duration.from_micros(500))
    var h = Headers()
    h.add("retry-after-ms", "1500")
    assert_equal(wait_before_retry(p, 0, h, 0, 0.0), Duration.from_millis(1500))
    var long = Headers()
    long.add("retry-after", "120")
    assert_equal(wait_before_retry(p, 1, long, 0, 0.0), Duration.from_secs(1))  # (over 60 s: the backoff)
    var none = Headers()
    for s in [408, 409, 429, 500, 502, 503, 504, 599]:
        assert_true(retryable_status(s, none), String(s))
    for s in [400, 401, 403, 404, 413, 422]:
        assert_false(retryable_status(s, none), String(s))
    var yes = Headers()
    yes.add("x-should-retry", "true")
    assert_true(retryable_status(400, yes))
    var no = Headers()
    no.add("x-should-retry", "false")
    assert_false(retryable_status(503, no))
    var j = Jitter(7)
    for _ in range(1000):
        var x = j.next()
        assert_true(x >= 0.0 and x < 1.0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
