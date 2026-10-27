# llm: clients for model APIs

Clients for the APIs that serve language models, in native Mojo, on `http` (with `https://` through `tls`) and `json`. Two dialects:
- **OpenAI-compatible:** OpenAI's chat completions and embeddings, as OpenAI and the servers compatible with it speak them (vLLM, SGLang, TGI, Ollama, llama.cpp, Modular's `max serve`).
- **Anthropic:** the Messages API.

Package rules are in `docs/design.md`.

**Status: L1 done:** chat and streamed chat for both dialects, tool calls, OpenAI-style embeddings, and the SDKs' retries. It is tested against a fake API in Python, not against the real services: their keys and costs are not in CI.

## Scope
**In scope:**
- one provider-neutral chat model:
  - `ChatRequest`: messages with the roles system, user, assistant and tool; an assistant's tool calls; tools described by JSON Schema; the common options, and extra fields as given;
  - `Reply`: text, tool calls, finish reason and usage;
  - `Delta`: the pieces of a streamed reply;
- each dialect's request bodies, replies and stream events, sans-I/O (`llm.openai`, `llm.anthropic`);
- `Client`: blocking calls over `http.client`, with one deadline per call, an idle timeout per stream, and retries;
- embeddings fetched as base64 float32 and decoded.

**Out of scope for now (later milestones):**
- OpenAI's legacy completions and its Responses API;
- images, audio and other content parts (text only);
- WebSocket and realtime modes, batch APIs, tokenizers and agent frameworks;
- an async API (no async/await yet; see `docs/design.md`).

## Decisions
- **One model, two mappings.** Code that calls a model should not change with the provider. Each dialect module maps the same `ChatRequest` to its API:
  - OpenAI-style: tools under `{"type": "function"}`, an assistant's `tool_calls`, a tool turn's `tool_call_id`.
  - Anthropic: `system` at the top level; `tool_use` blocks whose `input` is the arguments' object; consecutive tool results joined into one user turn of `tool_result` blocks; `max_tokens` required. `seed` is refused, since the API has none, rather than dropped.
- **The token limit's name differs.** OpenAI's reasoning models (o-series, gpt-5) refuse `max_tokens` and want `max_completion_tokens`, which other servers may not read. So `ChatRequest.max_tokens_field` picks the name sent to OpenAI-style APIs; it is `max_tokens` by default, and Anthropic always takes `max_tokens`.
- **Tool arguments stay text.** A model writes a call's arguments as JSON text, and it can write something that is not valid JSON. `ToolCall.arguments` keeps exactly what came: OpenAI sends a string, and Anthropic's `input` object is rendered back to text. The caller parses it with `json.parse` and checks it before acting on it.
- **Streams end explicitly.** A streamed reply is complete only at OpenAI's `[DONE]` or Anthropic's `message_stop`. A stream whose body ends cleanly before that is cut short (PROTOCOL); a connection dropped mid-body is TRANSPORT (`UnexpectedEof`). Either way it can never look like a short answer.
  - **Error events:** an error event in the middle of a stream raises API. That is `{"error": {...}}`, TGI's `{"error": "<text>", "error_type": ...}`, or Anthropic's `error` event.
  - **Skipped:** event types this client does not know, and `ping`, as Anthropic asks of clients. So are content blocks other than text and `tool_use`: thinking, a server tool's or an MCP tool's use, and their deltas.
- **A stream's first error is final.** An event that fails gives out none of its deltas, and every later `next` raises the same error, so a caller that keeps reading cannot reach a DONE. `complete()` says whether the reply ended as the API ends one. `reply()` after a failure may hold part of the event that failed.
- **Streams are bounded.** A reply's text and tool arguments together may grow to `max_reply` bytes (16 MiB), and a reply may start `max_tool_calls` calls (128); past either, the stream fails. `stream_total` bounds a stream's whole time. Pings and unknown events keep a stream alive between deltas, so set `stream_total` when the caller needs a wall-clock bound.
- **Retries as the SDKs do them.**
  - **When:** 408, 409, 429 and 5xx answers, timeouts, and refused or lost connections, at most twice, and only while the call's deadline leaves time for the wait. `x-should-retry` overrides the status.
  - **How long:** the server's `retry-after-ms` or `Retry-After` when it is above zero and at most 60 s; otherwise 0.5 s doubling up to 8 s, less a random quarter.
  - **Streams:** retried only until their head has come; once tokens have flowed, a retry would repeat them. The final error says how many retries it took.
- **Deadlines:** `timeout` (600 s, the SDKs' default) covers a whole call: every attempt, the waits between them, and an error's body. For a stream it covers the time to its head. After that, a stream waits at most `stream_idle` (600 s) between pieces and lasts at most `stream_total` (no limit by default). Dropping the stream closes the connection, which cancels the reply.
- **Errors** are `LlmError`:
  - **HTTP:** the API's message (cut to 4 KiB), type, code and request id (`x-request-id`, or Anthropic's `request-id`).
  - **API:** an error event inside a stream, with the stream's request id.
  - **PROTOCOL:** a body that is not the API's JSON, or a field of the wrong type.
  - **TRANSPORT:** the network's `IoError` is kept in `io`; after a TLS failure the message also says why (the category, OpenSSL's verify code and text), where `io` alone would be a bare `PermissionDenied`.
  - **USAGE:** a request that cannot be sent as given: no model, an unknown role, a schema that is not a JSON object, an extra field the request writes itself, NaN, a header `http` frames itself (`Content-Length`), or empty content for Anthropic, which refuses it.
- **Refusals** (OpenAI-style) are kept apart: `Reply.refusal`, and REFUSAL deltas.
- **Embeddings come as base64** (`encoding_format: "base64"`), a quarter of the bytes of decimal text, and are decoded as little-endian float32. Each vector is placed by its `index`, which must cover every input exactly once.
- **Keys** go in `Authorization: Bearer` or `x-api-key`, built through `http.headers`, which refuses CR and LF (no header injection). Use `https://` for any remote API: over `http://` a key travels in clear.
- **Connections are reused.** `chat` and `embed` give theirs back to `http`'s pool; a stream's goes back through `c.release(s^)` once it is `complete()` (what its body has after the last event, the last chunk, is read first: at most 64 KiB within 1 s). In an agent's loop of streamed calls that saves a TCP connection and a TLS handshake per call. A stream dropped, or released before it is complete, closes its connection.
- **`base_url`** is the API's root up to its version. The paths are appended to its path, before a query: Azure OpenAI's `.../deployments/d?api-version=2024-10-21` works.
- **Many clients** (one per tenant, say) should share one TLS context, built with ALPN `http/1.1` (`Client(..., tls_context=ctx)`): each context built on its own loads OpenSSL anew, and a process can hold only about 330 of those (`docs/tls.md`, "Use").

## Use
```mojo
from llm import ChatRequest, Delta, DeltaKind, Message, Tool
from llm.client import Client, Provider

var c = Client(Provider.OPENAI, "http://localhost:8000/v1")      # max serve, vLLM, ...
var req = ChatRequest("model", [Message.system("Be brief."), Message.user("Why is the sky blue?")])
print(c.chat(req).text)

var s = c.stream(req)                                              # tokens as they come
var d = Delta()
while s.next(d):
    if d.kind == DeltaKind.TEXT:
        print(d.text, end="")
c.release(s^)                                                      # the connection, for the next call
```
`examples/llm/chat.mojo` streams an answer from any of the servers above, or from Anthropic's API.

## Testing
- **A fake API:** `tests/llm/llm_peer.py` is Python's http.server speaking both dialects as the providers' API references show them. Its replies are chunked event streams with tool calls split across chunks, usage in the last chunk, `ping`, and an event type from the future. Paths choose failures: 429 with `retry-after-ms`, 500s, a 503 that says not to retry, a 400 with a request id, a body that is not JSON, a cut stream, an error event in the middle, a stream that pauses. It logs every request, so the tests check the headers and bodies the client sent.
- **The codecs:** request bodies are read back by Python's json and checked field by field. Replies, chunks and events shaped as the API references show them, and malformed ones (wrong types, skipped indexes, deltas for blocks that never started, events after the end) must raise the right kind. Embeddings come as numbers and as base64 from Python's `struct`. The retry waits are checked against the SDKs' formula.
- **Planted bugs:** 31 one-line bugs were planted in the four modules, one at a time, after the review's fixes. The tests caught 28 at first. The three they missed:
  - a stream retried a connection lost before its head once more than `max_retries`;
  - `chat` gave a retry the whole `timeout` again instead of what was left;
  - `max_tool_calls` could be removed unnoticed.
  
  Each now has a test (`test_11_*` and the tool-call bound in `test_3_*`), and each test was checked red with its bug planted again.

## Review
An independent review of L1 (an agent, not a person) probed the client against its own fake servers. It found ten defects, fixed with a regression test each in `tests/llm/test_llm_regressions.mojo`:
- **Deadlines:** `timeout` restarted on every attempt, so the defaults allowed 3 × 600 s. A stream's error body was read without the call's deadline.
- **Streams:**
  - they had no bound on size or total time;
  - a stream's error did not stick: later reads returned the refused event and a DONE;
  - a dropped connection was not PROTOCOL as the docs said (the docs now describe TRANSPORT, which is what it is);
  - stream errors lost the request id and the retry count;
  - Anthropic's server-tool and MCP-tool blocks failed the stream.
- **Wire format:** TGI's string-shaped stream errors became PROTOCOL, and OpenAI's reasoning models refuse `max_tokens`.
- **Retries:** `Retry-After: 0` retried at once, where the SDKs back off.

Its lower-confidence findings were fixed too:
- tool-call fragments without an index;
- arguments sent as an object (TGI 2.3);
- refusals;
- empty Anthropic content;
- `extra` refusing fields the request had left unset;
- unclipped error messages;
- a framing header reported as TRANSPORT.

Still open from it: extended thinking with tools (the thinking blocks are dropped, and Anthropic refuses the next turn without them), and keys over `http://` to a host other than the local machine, which are documented, not refused.

## Milestones
- **L1: chat, streams, tools, embeddings, retries.** Done.
  - **Tests:** 43: `tests/llm/test_llm_codec.mojo` (sans-I/O), `test_llm_client.mojo` (against the fake API, including keys with CR or LF, refused before anything is sent) and `test_llm_regressions.mojo` (the review's findings, and the planted bugs the other files missed).
- **L2:** OpenAI's Responses API and legacy completions; image and document content parts; a pool of streams for many concurrent calls.
