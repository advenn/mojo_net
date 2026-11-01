"""Regression tests for the 2026-11 analysis of the stack, for `llm`
(finding llm-thinking-content-cache, as its skeptic corrected it):

- Claude's thinking blocks were dropped, in replies and streams, so a tool
  loop failed on its second request: the API refuses an assistant turn
  with tool calls that does not start with its thinking blocks, and
  current Claude models think by default. Now `Reply.thinking` keeps them,
  signatures and all, and `Message.from_reply` sends them back.
- `Usage` had only input and output: cache reads and writes, and reasoning
  tokens, were lost, and Anthropic's `input_tokens` (which leaves the
  cached input out) was taken as the prompt's size.
- No cache breakpoint could be put on a message, a system message or a
  tool (Anthropic's `cache_control`).
- The reasoning of OpenAI-compatible servers (`reasoning_content`) was
  dropped.

Against tests/llm/llm_peer.py's `thinking` scenario, which refuses what
the real API refuses; the rest sans-I/O."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_true

from linux.time import Duration
from llm import ChatRequest, Delta, DeltaKind, LlmError, Message, Reply, Tool
from llm.anthropic import EventDecoder, write_messages
from llm.client import Client, Provider, ReplyStream
from llm.openai import ChunkDecoder, read_chat

from llm_peer import LlmPeer


def _req() -> ChatRequest:
    var r = ChatRequest("test-model", [Message.user("Weather in Tashkent?")])
    r.max_tokens = 1024
    r.tools.append(Tool("get_weather", "The weather at a place", '{"type":"object"}'))
    return r^


def _check_thinking(reply: Reply) raises:
    assert_equal(len(reply.thinking), 2)
    assert_equal(reply.thinking[0].text, "Let me think.")
    assert_equal(reply.thinking[0].signature, "sig_1")
    assert_equal(reply.thinking[1].redacted, "enc_1")
    assert_equal(reply.text, "Let me check.")
    assert_equal(len(reply.tool_calls), 1)
    # Usage: the whole prompt (5 + 20 read from the cache + 3 written).
    assert_equal(reply.usage.input_tokens, 28)
    assert_equal(reply.usage.cache_read_tokens, 20)
    assert_equal(reply.usage.cache_write_tokens, 3)
    assert_equal(reply.usage.output_tokens, 13)


def _answer(mut c: Client, reply: Reply) raises -> String:
    """The next request of the tool loop: the reply sent back, and the
    tool's result."""
    var req = _req()
    req.messages.append(Message.from_reply(reply))
    req.messages.append(Message.tool(reply.tool_calls[0].id, "sunny"))
    return c.chat(req).text


def test_a_claude_tool_loop_with_thinking() raises:
    var peer = LlmPeer()
    var c = Client(Provider.ANTHROPIC, peer.base("thinking"), "sk-ant", timeout=Duration.from_secs(20))
    var reply = c.chat(_req())
    _check_thinking(reply)
    assert_equal(_answer(c, reply), "It is sunny.")
    # The same from a stream: the reasoning as THINKING deltas, the
    # signature assembled from its deltas.
    var s = c.stream(_req())
    var thought = String()
    var d = Delta()
    while s.next(d):
        if d.kind == DeltaKind.THINKING:
            thought += d.text
    var whole = s.reply()
    assert_equal(thought, "Let me think.")
    _check_thinking(whole)
    assert_equal(_answer(c, whole), "It is sunny.")
    peer^.stop()


def test_kept_thinking_counts_against_max_reply() raises:
    """Signatures and redacted thinking come without a delta of their own,
    so `ReplyStream` counts them through `EventDecoder.kept`: a server
    could otherwise grow a reply past `max_reply` with signature deltas."""
    var d = EventDecoder()
    var out = List[Delta]()
    d.feed('{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}', out)
    var piece = String("s") * 1000
    for _ in range(3):
        d.feed(String('{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"', piece, '"}}'), out)
    d.feed('{"type":"content_block_start","index":1,"content_block":{"type":"redacted_thinking","data":"abcd"}}', out)
    assert_equal(d.kept, 3004)
    assert_equal(len(out), 0)


def _json(body: List[UInt8]) raises -> PythonObject:
    return Python.import_module("json").loads(String(from_utf8_lossy=Span(body)))


def test_cache_breakpoints() raises:
    var req = ChatRequest("m")
    req.max_tokens = 10
    var system = Message.system("A long system prompt.")
    system.cache = True
    req.messages.append(system^)
    var user = Message.user("A long document.")
    user.cache = True
    req.messages.append(user^)
    req.tools.append(Tool("f", "", '{"type":"object"}', cache=True))
    var j = _json(write_messages(req))
    assert_equal(String(j["system"][0]["text"]), "A long system prompt.")
    assert_equal(String(j["system"][0]["cache_control"]["type"]), "ephemeral")
    assert_equal(String(j["messages"][0]["content"][0]["cache_control"]["type"]), "ephemeral")
    assert_equal(String(j["tools"][0]["cache_control"]["type"]), "ephemeral")
    # Without breakpoints, the plain forms as before.
    var plain = _json(write_messages(_req()))
    assert_equal(String(plain["messages"][0]["content"]), "Weather in Tashkent?")


def test_openai_reasoning_and_usage_details() raises:
    var body = String(
        '{"id":"c","model":"m","choices":[{"index":0,"finish_reason":"stop","message":',
        '{"role":"assistant","content":"42","reasoning_content":"Six times seven."}}],',
        '"usage":{"prompt_tokens":100,"completion_tokens":50,',
        '"prompt_tokens_details":{"cached_tokens":64},"completion_tokens_details":{"reasoning_tokens":40}}}',
    )
    var reply = read_chat(body.as_bytes())
    assert_equal(reply.text, "42")
    assert_equal(reply.thinking[0].text, "Six times seven.")
    assert_equal(reply.usage.input_tokens, 100)
    assert_equal(reply.usage.cache_read_tokens, 64)
    assert_equal(reply.usage.reasoning_tokens, 40)
    var dec = ChunkDecoder()
    var out = List[Delta]()
    dec.feed('{"id":"c","choices":[{"index":0,"delta":{"reasoning_content":"Six "}}]}', out)
    dec.feed('{"id":"c","choices":[{"index":0,"delta":{"reasoning":"times seven."}}]}', out)
    dec.feed('{"id":"c","choices":[{"index":0,"delta":{"content":"42"},"finish_reason":"stop"}]}', out)
    dec.feed("[DONE]", out)
    assert_true(out[0].kind == DeltaKind.THINKING and out[1].kind == DeltaKind.THINKING)
    assert_equal(dec.reply.thinking[0].text, "Six times seven.")
    assert_equal(dec.reply.text, "42")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
