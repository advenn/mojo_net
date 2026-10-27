"""Regression tests for the review of `llm` (L1), one per finding.


1. `timeout` covers a whole call, retries and their waits included (it
   restarted per attempt: 3 x 600 s by default).
2. A stream's error body is read under the call's deadline (a trickled
   500 body outlived it).
3. A stream is bounded: `max_reply` bytes, `max_tool_calls`, and
   `stream_total` (pings kept `next` from ever returning).
4. A stream's first error is final (the refused event's deltas, and DONE,
   still came out of later calls).
5. A connection dropped mid-stream is TRANSPORT (UnexpectedEof); the docs
   now say so.
6. Stream errors carry the head's request id and the retries.
7. Anthropic blocks other than text and tool_use (server and MCP tool
   uses) skip their input deltas instead of failing the stream.
8. TGI's `{"error": "<text>", "error_type": ...}` is API, with its text.
9. `max_tokens_field` sends `max_completion_tokens` (OpenAI's reasoning
   models refuse `max_tokens`).
10. `Retry-After: 0` (and a past date) waits the backoff, as the SDKs do.
11. (From planting bugs) each attempt gets only what is left of the call's
    deadline, not the whole `timeout` again; and a connection lost before
    the head is retried `max_retries` times, no more.
And the lower-confidence ones that were fixed: tool-call fragments without
an index; arguments sent as an object (TGI 2.3); refusals; empty content
refused for Anthropic; `extra` fields the request leaves unset; error
messages clipped; a caller's framing header (USAGE, not TRANSPORT).
"""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from http.headers import Headers
from linux import ErrorKind
from linux.time import Duration, Instant
from llm import ChatRequest, Delta, DeltaKind, LlmError, Message, RetryPolicy
from llm.anthropic import EventDecoder, write_messages
from llm.client import Client, Provider, ReplyStream
from llm.openai import ChunkDecoder, read_chat, read_error, write_chat
from llm.retry import backoff, wait_before_retry

from llm_peer import LlmPeer


def _fast() -> RetryPolicy:
    var p = RetryPolicy()
    p.initial = Duration.from_millis(5)
    p.max_delay = Duration.from_millis(20)
    return p


def _req(text: StringSlice = "hello") -> ChatRequest:
    var r = ChatRequest("m", [Message.user(text)])
    r.max_tokens = 64
    return r^


def _chat_error(mut c: Client) -> LlmError:
    try:
        _ = c.chat(_req())
    except e:
        return e^
    return LlmError(0, "none")


def _stream_error(mut c: Client) -> LlmError:
    try:
        var s = c.stream(_req())
        var d = Delta()
        while s.next(d):
            pass
    except e:
        return e^
    return LlmError(0, "none")


def _secs(t: Instant) -> Float64:
    return Float64(Instant.now().duration_since(t).as_nanos()) / 1e9


def test_1_timeout_covers_the_whole_call() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("hang"), timeout=Duration.from_secs(1), retry=_fast())
    var t = Instant.now()
    var e = _chat_error(c)
    assert_equal(e.kind, LlmError.TRANSPORT)
    assert_true(e.io.kind == ErrorKind.TimedOut)
    assert_true(_secs(t) < 2.0, String(_secs(t)))
    var s = Client(Provider.OPENAI, peer.base("hang"), timeout=Duration.from_secs(1), retry=_fast())
    t = Instant.now()
    assert_equal(_stream_error(s).kind, LlmError.TRANSPORT)
    assert_true(_secs(t) < 2.0, String(_secs(t)))
    peer^.stop()


def test_2_error_body_read_under_the_deadline() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("trickle500"), timeout=Duration.from_secs(1), stream_idle=Duration.from_secs(2), retry=RetryPolicy.none())
    var t = Instant.now()
    var e = _stream_error(c)
    assert_equal(e.status, 500)
    assert_true(_secs(t) < 2.0, String(_secs(t)))
    peer^.stop()


def test_3_streams_are_bounded() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("endless"), max_reply=10000)
    var e = _stream_error(c)
    assert_equal(e.kind, LlmError.PROTOCOL)
    assert_true(e.message.find("max_reply") >= 0, e.message)
    # The "tools" stream starts two calls in either dialect: refused at a
    # bound of 1, taken at 2.
    for p in [Provider.OPENAI, Provider.ANTHROPIC]:
        var calls = 2
        var under = Client(p, peer.base("tools"), max_tool_calls=calls - 1)
        var ue = _stream_error(under)
        assert_equal(ue.kind, LlmError.PROTOCOL)
        assert_true(ue.message.find("max_tool_calls") >= 0, ue.message)
        var at = Client(p, peer.base("tools"), max_tool_calls=calls)
        assert_equal(_stream_error(at).kind, 0)  # (no error)
    var p = Client(Provider.ANTHROPIC, peer.base("pings"), stream_total=Duration.from_secs(1), stream_idle=Duration.from_millis(500))
    var t = Instant.now()
    var pe = _stream_error(p)
    assert_equal(pe.kind, LlmError.TRANSPORT)
    assert_true(pe.io.kind == ErrorKind.TimedOut)
    assert_true(_secs(t) < 2.5, String(_secs(t)))
    peer^.stop()


def test_4_a_stream_error_is_final() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("badindex"))
    var s = c.stream(_req())
    var d = Delta()
    var texts = String()
    var failures = 0
    var done = False
    var kinds = List[Int]()
    for _ in range(6):
        try:
            if s.next(d):
                texts += d.text if d.kind == DeltaKind.TEXT else String()
                done = done or d.kind == DeltaKind.DONE
        except e:
            kinds.append(e.kind)
            failures += 1
    assert_false(done)
    for k in kinds:
        assert_equal(k, LlmError.PROTOCOL)
    assert_equal(texts, "A")
    assert_equal(failures, 5)  # (the first error, then the same one each time)
    assert_false(s.complete())
    peer^.stop()


def test_5_a_dropped_connection_is_transport() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("drop"))
    var e = _stream_error(c)
    assert_equal(e.kind, LlmError.TRANSPORT)
    assert_true(e.io.kind == ErrorKind.UnexpectedEof)
    var cut = Client(Provider.OPENAI, peer.base("cut"))
    assert_equal(_stream_error(cut).kind, LlmError.PROTOCOL)  # (a clean end before [DONE])
    peer^.stop()


def test_6_stream_errors_carry_request_id_and_retries() raises:
    var peer = LlmPeer()
    for p in [Provider.OPENAI, Provider.ANTHROPIC]:
        var c = Client(p, peer.base("retrybroken-" + String(p) + "-2"), retry=_fast())
        var s = c.stream(_req("a longer message"))
        assert_equal(s.request_id(), "req_stream")
        var e = LlmError(0, "none")
        try:
            var d = Delta()
            while s.next(d):
                pass
        except err:
            e = err^
        assert_equal(e.kind, LlmError.API)
        assert_equal(e.request_id, "req_stream")
        assert_equal(e.retries, 2)
    peer^.stop()


def _anthropic(events: List[String]) raises LlmError -> EventDecoder:
    var d = EventDecoder()
    var out = List[Delta]()
    for e in events:
        d.feed(e, out)
    return d^


def test_7_anthropic_server_tool_blocks_are_skipped() raises:
    for kind in ["server_tool_use", "mcp_tool_use", "a_future_block"]:
        var d = _anthropic([
            '{"type":"message_start","message":{"id":"m","model":"c","usage":{"input_tokens":1}}}',
            '{"type":"content_block_start","index":0,"content_block":{"type":"' + String(kind) + '","id":"srvtoolu_1","name":"web_search","input":{}}}',
            '{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"query\\": \\"x\\"}"}}',
            '{"type":"content_block_stop","index":0}',
            '{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}',
            '{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"found it"}}',
            '{"type":"message_stop"}',
        ])
        assert_equal(d.reply.text, "found it")
        assert_equal(len(d.reply.tool_calls), 0)
        assert_true(d.done)


def test_8_tgi_error_shape() raises:
    var d = ChunkDecoder()
    var out = List[Delta]()
    var e = LlmError(0, "none")
    try:
        d.feed('{"error":"Input validation error: max_new_tokens must be <= 512","error_type":"validation"}', out)
    except err:
        e = err^
    assert_equal(e.kind, LlmError.API)
    assert_equal(e.message, "Input validation error: max_new_tokens must be <= 512")
    assert_equal(e.type, "validation")
    var h = read_error('{"error":"Model is overloaded","error_type":"overloaded"}'.as_bytes(), 503)
    assert_equal(h.message, "Model is overloaded")
    assert_equal(h.type, "overloaded")


def test_9_max_completion_tokens() raises:
    var r = _req()
    r.max_tokens_field = "max_completion_tokens"
    var json = Python.import_module("json")
    var b = json.loads(String(unsafe_from_utf8=Span(write_chat(r))))
    assert_equal(Int(py=b["max_completion_tokens"]), 64)
    assert_false(Bool(py=b.__contains__("max_tokens")))
    r.max_tokens_field = "tokens"
    var kind = 0
    try:
        _ = write_chat(r)
    except e:
        kind = e.kind
    assert_equal(kind, LlmError.USAGE)


def test_10_zero_retry_after_waits_the_backoff() raises:
    var p = RetryPolicy()
    for v in ["0", "Thu, 01 Jan 1970 00:00:00 GMT"]:
        var h = Headers()
        h.add("retry-after", v)
        assert_equal(wait_before_retry(p, 1, h, 1_800_000_000, 0.0), backoff(p, 1, 0.0))
    var ms = Headers()
    ms.add("retry-after-ms", "0")
    assert_equal(wait_before_retry(p, 0, ms, 0, 0.0), backoff(p, 0, 0.0))


def test_11_attempts_share_the_deadline() raises:
    # The first attempt gets a 429 asking for 1.5 s; the second hangs. With
    # a 2 s timeout the call ends near 2 s; an attempt given the whole
    # timeout again would end near 3.5 s.
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("ratehang-chat"), timeout=Duration.from_secs(2), retry=_fast())
    var t = Instant.now()
    var e = _chat_error(c)
    assert_equal(e.kind, LlmError.TRANSPORT)
    assert_true(e.io.kind == ErrorKind.TimedOut)
    assert_equal(e.retries, 1)
    assert_true(_secs(t) < 3.0, String(_secs(t)))
    var s = Client(Provider.OPENAI, peer.base("ratehang-stream"), timeout=Duration.from_secs(2), retry=_fast())
    t = Instant.now()
    assert_equal(_stream_error(s).kind, LlmError.TRANSPORT)
    assert_true(_secs(t) < 3.0, String(_secs(t)))
    peer^.stop()


def test_11_lost_connections_retry_max_retries_times() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("nohead"), retry=_fast())
    var e = _chat_error(c)
    assert_equal(e.kind, LlmError.TRANSPORT)
    assert_equal(e.retries, 2)
    var s = Client(Provider.OPENAI, peer.base("nohead"), retry=_fast())
    var se = _stream_error(s)
    assert_equal(se.kind, LlmError.TRANSPORT)
    assert_equal(se.retries, 2)
    var log = peer.log()
    var n = 0
    for i in range(Int(py=log.__len__())):
        if String(py=log[i]["path"]).startswith("/nohead/"):
            n += 1
    assert_equal(n, 6)  # (three attempts each)
    peer^.stop()


def test_tool_fragments_without_index() raises:
    var d = ChunkDecoder()
    var out = List[Delta]()
    d.feed('{"choices":[{"index":0,"delta":{"tool_calls":[{"id":"a","function":{"name":"f","arguments":"{\\"x\\":"}}]}}]}', out)
    d.feed('{"choices":[{"index":0,"delta":{"tool_calls":[{"function":{"arguments":"1}"}}]}}]}', out)
    d.feed('{"choices":[{"index":0,"delta":{"tool_calls":[{"id":"b","function":{"name":"g","arguments":"{}"}}]}}]}', out)
    d.feed("[DONE]", out)
    assert_equal(len(d.reply.tool_calls), 2)
    assert_equal(d.reply.tool_calls[0].arguments, '{"x":1}')
    assert_equal(d.reply.tool_calls[1].name, "g")


def test_arguments_as_an_object_and_refusals() raises:
    var r = read_chat(
        '{"choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"c","type":"function","function":{"name":"f","arguments":{"x":[1,2]}}}]},"finish_reason":"tool_calls"}]}'.as_bytes()
    )
    assert_equal(r.tool_calls[0].arguments, '{"x":[1,2]}')
    var refused = read_chat('{"choices":[{"index":0,"message":{"role":"assistant","content":null,"refusal":"I cannot help with that."},"finish_reason":"stop"}]}'.as_bytes())
    assert_equal(refused.refusal, "I cannot help with that.")
    var d = ChunkDecoder()
    var out = List[Delta]()
    d.feed('{"choices":[{"index":0,"delta":{"refusal":"I cannot"}}]}', out)
    assert_true(out[0].kind == DeltaKind.REFUSAL)
    assert_equal(d.reply.refusal, "I cannot")


def test_anthropic_empty_content_and_unset_extra() raises:
    var r = ChatRequest("m", [Message.user("")])
    r.max_tokens = 5
    var kind = 0
    try:
        _ = write_messages(r)
    except e:
        kind = e.kind
    assert_equal(kind, LlmError.USAGE)
    # A system prompt as blocks with cache_control, through extra (no
    # system message is set), and tools likewise.
    var ok = ChatRequest("m", [Message.user("hi")])
    ok.max_tokens = 5
    ok.extra = '{"system": [{"type": "text", "text": "Be brief.", "cache_control": {"type": "ephemeral"}}], "tools": [{"type": "web_search_20250305", "name": "web_search"}]}'
    var json = Python.import_module("json")
    var b = json.loads(String(unsafe_from_utf8=Span(write_messages(ok))))
    assert_equal(String(b["system"][0]["cache_control"]["type"]), "ephemeral")
    assert_equal(String(b["tools"][0]["name"]), "web_search")
    ok.messages.insert(0, Message.system("set here too"))
    kind = 0
    try:
        _ = write_messages(ok)
    except e:
        kind = e.kind
    assert_equal(kind, LlmError.USAGE)  # (now the request sets system itself)


def test_error_messages_are_clipped() raises:
    var long = String()
    for _ in range(10000):
        long += "x"
    var e = read_error(String('{"error":{"message":"', long, '"}}').as_bytes(), 400)
    assert_true(e.message.byte_length() <= 4096 + 3)


def test_framing_headers_are_usage() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("ok"))
    c.headers.add("Content-Length", "5")
    assert_equal(_chat_error(c).kind, LlmError.USAGE)
    peer^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
