"""Regression tests for the third http review's findings in `llm` (HR3,
2026-10-27; docs/http.md, "Review"), against tests/llm/llm_peer.py.

- CLI-8: a `base_url` with a query (Azure OpenAI's
  `?api-version=...`) had the API's path appended after the query.
- A stream's connection could not go back to the pool, so every streamed
  call paid a new TCP connection (and TLS handshake): `Client.release`.
- A TLS failure's TRANSPORT error did not say why (a refused certificate
  was a bare PermissionDenied).
- Each attempt's timeout is passed per request, no longer by changing the
  http client's own.
"""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux.time import Duration
from llm import ChatRequest, Delta, LlmError, Message
from llm.client import Client, Provider

from llm_peer import LlmPeer


def _req(text: StringSlice = "hello") -> ChatRequest:
    var r = ChatRequest("m", [Message.user(text)])
    r.max_tokens = 64
    return r^


def test_cli8_a_query_in_base_url_stays_after_the_path() raises:
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("ok") + "?api-version=2024-10-21")
    assert_equal(c.chat(_req()).text, String("echo: hello"))
    var log = peer.log()
    assert_equal(String(py=log[len(log) - 1]["path"]), String("/ok/v1/chat/completions?api-version=2024-10-21"))
    var a = Client(Provider.ANTHROPIC, peer.base("ok") + "/?x=1")
    _ = a.chat(_req())
    log = peer.log()
    assert_equal(String(py=log[len(log) - 1]["path"]), String("/ok/v1/messages?x=1"))
    peer^.stop()


def test_a_complete_streams_connection_is_pooled() raises:
    var peer = LlmPeer()
    for p in [Provider.OPENAI, Provider.ANTHROPIC]:
        var c = Client(p, peer.base("ok"), timeout=Duration.from_secs(30))
        var s = c.stream(_req())
        var d = Delta()
        while s.next(d):
            pass
        assert_true(s.complete())
        c.release(s^)
        assert_equal(c._http.idle_connections(), 1)
        var again = c.stream(_req())  # (on the pooled connection)
        assert_equal(c._http.idle_connections(), 0)
        while again.next(d):
            pass
        c.release(again^)
        assert_equal(c._http.idle_connections(), 1)
        assert_equal(c._http.timeout, Duration.from_secs(30))  # (attempts pass theirs per request)
    peer^.stop()


def test_an_incomplete_stream_is_not_pooled() raises:
    """Dropped mid-reply, or cut before its end marker (the body itself
    ended cleanly): closed, not pooled."""
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, peer.base("endless"))
    var s = c.stream(_req())
    var d = Delta()
    _ = s.next(d)
    assert_false(s.complete())
    c.release(s^)
    assert_equal(c._http.idle_connections(), 0)
    var cut = Client(Provider.OPENAI, peer.base("cut"))
    var t = cut.stream(_req())
    try:
        while t.next(d):
            pass
    except e:
        assert_equal(e.kind, LlmError.PROTOCOL)
    assert_false(t.complete())
    cut.release(t^)
    assert_equal(cut._http.idle_connections(), 0)
    peer^.stop()


def test_a_tls_failure_says_why() raises:
    """https to a plain HTTP server: the handshake fails, and the error's
    text carries the TLS reason."""
    var peer = LlmPeer()
    var c = Client(Provider.OPENAI, String("https://127.0.0.1:", peer.port, "/ok/v1"), timeout=Duration.from_secs(10))
    var got = LlmError(0, "none")
    try:
        _ = c.chat(_req())
    except e:
        got = e^
    assert_equal(got.kind, LlmError.TRANSPORT)
    assert_true(got.message.find("[tls: ") >= 0, got.message)
    peer^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
