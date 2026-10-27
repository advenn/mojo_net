"""OpenAI's API as OpenAI-compatible servers speak it (OpenAI; vLLM,
SGLang, TGI, Ollama, llama.cpp; Modular's `max serve`): the bodies of
`POST /chat/completions` and `POST /embeddings`, the replies, and the
chunks of a streamed chat. Sans-I/O: bytes in, values out.

- **Requests:** `write_chat` maps a `ChatRequest`: messages with their
  roles, an assistant's `tool_calls` and a tool's `tool_call_id`; tools as
  `{"type": "function", "function": {...}}` with their JSON Schema; the
  options that are set; `stream` with `stream_options.include_usage`; and
  `extra` fields as given (one the request sets is refused).
- **Replies:** `read_chat` reads the first choice: its text (null when
  only tools are called), its tool calls (arguments kept as the text the
  model wrote), the finish reason, the usage.
- **Streams:** `ChunkDecoder` turns each event's data into `Delta`s: text
  pieces, a tool call's start and its argument pieces (by the call's
  index), and DONE at `[DONE]`, with the finish reason and the usage that
  came before it. An `{"error": ...}` chunk raises API. A stream that ends
  without `[DONE]` is cut short (`finish()` raises PROTOCOL).
- **Errors:** `read_error` reads `{"error": {"message", "type", "code"}}`.
"""

from std.memory import bitcast

from bytes.base64 import base64_decode
from json import JsonError, Kind, Writer

from .common import Reader, clip, usage_error, write_extra, write_object_text
from .error import LlmError
from .types import ChatRequest, Delta, DeltaKind, Embeddings, Reply, ToolCall, Usage

comptime _ROLES: List[StaticString] = ["system", "user", "assistant", "tool"]


def _known_role(role: String) -> Bool:
    for r in materialize[_ROLES]():
        if role == r:
            return True
    return False


def _set_fields(req: ChatRequest, stream: Bool) -> List[String]:
    """The top-level fields `write_chat` writes for `req`: `extra` may
    hold any other."""
    var out: List[String] = ["model", "messages"]
    if len(req.tools) > 0:
        out.append("tools")
    if req.max_tokens > 0:
        out.append(req.max_tokens_field)
    if req.temperature:
        out.append("temperature")
    if req.top_p:
        out.append("top_p")
    if len(req.stop) > 0:
        out.append("stop")
    if req.seed:
        out.append("seed")
    if stream:
        out.append("stream")
        if req.stream_usage:
            out.append("stream_options")
    return out^


# ---- chat ---------------------------------------------------------------------


def write_chat(req: ChatRequest, stream: Bool = False) raises LlmError -> List[UInt8]:
    """The JSON body of `POST /chat/completions` for `req`."""
    try:
        return _write_chat(req, stream)
    except e:
        raise usage_error(e)


def _write_chat(req: ChatRequest, stream: Bool) raises JsonError -> List[UInt8]:
    if req.model.byte_length() == 0:
        raise JsonError(JsonError.USAGE, "llm: the request names no model")
    if len(req.messages) == 0:
        raise JsonError(JsonError.USAGE, "llm: the request has no messages")
    var w = Writer()
    w.begin_object()
    w.key("model")
    w.string(req.model)
    w.key("messages")
    w.begin_array()
    for m in req.messages:
        if not _known_role(m.role):
            raise JsonError(JsonError.USAGE, "llm: a message's role is not system, user, assistant or tool")
        w.begin_object()
        w.key("role")
        w.string(m.role)
        w.key("content")
        if m.role == "assistant" and m.content.byte_length() == 0 and len(m.tool_calls) > 0:
            w.null()
        else:
            w.string(m.content)
        if len(m.tool_calls) > 0:
            if m.role != "assistant":
                raise JsonError(JsonError.USAGE, "llm: only an assistant message carries tool calls")
            w.key("tool_calls")
            w.begin_array()
            for c in m.tool_calls:
                w.begin_object()
                w.key("id")
                w.string(c.id)
                w.key("type")
                w.string("function")
                w.key("function")
                w.begin_object()
                w.key("name")
                w.string(c.name)
                w.key("arguments")
                w.string(c.arguments)
                w.end_object()
                w.end_object()
            w.end_array()
        if m.role == "tool":
            if m.tool_call_id.byte_length() == 0:
                raise JsonError(JsonError.USAGE, "llm: a tool message names no tool call")
            w.key("tool_call_id")
            w.string(m.tool_call_id)
        w.end_object()
    w.end_array()
    if len(req.tools) > 0:
        w.key("tools")
        w.begin_array()
        for t in req.tools:
            w.begin_object()
            w.key("type")
            w.string("function")
            w.key("function")
            w.begin_object()
            w.key("name")
            w.string(t.name)
            if t.description.byte_length() > 0:
                w.key("description")
                w.string(t.description)
            w.key("parameters")
            write_object_text(w, t.parameters)
            w.end_object()
            w.end_object()
        w.end_array()
    if req.max_tokens > 0:
        if req.max_tokens_field != "max_tokens" and req.max_tokens_field != "max_completion_tokens":
            raise JsonError(JsonError.USAGE, "llm: max_tokens_field is max_tokens or max_completion_tokens")
        w.key(req.max_tokens_field)
        w.int(req.max_tokens)
    if req.temperature:
        w.key("temperature")
        w.float(req.temperature.value())
    if req.top_p:
        w.key("top_p")
        w.float(req.top_p.value())
    if len(req.stop) > 0:
        w.key("stop")
        w.begin_array()
        for s in req.stop:
            w.string(s)
        w.end_array()
    if req.seed:
        w.key("seed")
        w.int(req.seed.value())
    if stream:
        w.key("stream")
        w.bool(True)
        if req.stream_usage:
            w.key("stream_options")
            w.begin_object()
            w.key("include_usage")
            w.bool(True)
            w.end_object()
    write_extra(w, req.extra, _set_fields(req, stream))
    w.end_object()
    return w.take()


def _usage(mut r: Reader, n: Int) -> Usage:
    var u = r.object(n, "usage")
    if u < 0:
        return Usage.unknown()
    return Usage(r.int(u, "prompt_tokens"), r.int(u, "completion_tokens"))


def read_chat(body: Span[UInt8, _]) raises LlmError -> Reply:
    """The reply in a `/chat/completions` response body (status 200)."""
    var r = Reader(body)
    _raise_error_member(r)
    var reply = Reply()
    reply.id = r.str(0, "id")
    reply.model = r.str(0, "model")
    reply.usage = _usage(r, 0)
    var choices = r.array(0, "choices")
    r.check()
    if r.count(choices) == 0:
        raise LlmError(LlmError.PROTOCOL, "llm: the response has no choices")
    var choice = r.first(choices)
    reply.finish_reason = r.str(choice, "finish_reason")
    var message = r.object(choice, "message")
    reply.text = r.str(message, "content")
    reply.refusal = r.str(message, "refusal")
    var calls = r.array(message, "tool_calls")
    var c = r.first(calls)
    for _ in range(r.count(calls)):
        var f = r.object(c, "function")
        reply.tool_calls.append(ToolCall(r.str(c, "id"), r.str(f, "name"), r.arguments(f, "arguments")))
        c = r.next(c)
    r.check()
    return reply^


def read_error(body: Span[UInt8, _], status: Int) -> LlmError:
    """The error in a response with `status` >= 400: its message, type and
    code, or the body itself when it is not the API's JSON."""
    var e = LlmError(LlmError.HTTP, String("llm: the API answered ", status), status=status)
    try:
        var r = Reader(body)
        if _fill_error(r, e):
            return e^
    except:
        pass
    e.message = String(from_utf8_lossy=body[: min(len(body), 512)])
    return e^


def _fill_error(mut r: Reader, mut e: LlmError) -> Bool:
    """The `error` member into `e`: an object with message, type and code,
    or (TGI) a string with `error_type` beside it. False if there is none."""
    var err = r.get(0, "error")
    if err < 0:
        return False
    var k = r.kind(err)
    if k == Kind.STRING:
        e.message = clip(r.str(0, "error"))
        e.type = r.str(0, "error_type")
        return True
    if k != Kind.OBJECT:
        return False
    e.message = clip(r.str(err, "message"))
    e.type = r.str(err, "type")
    var code = r.get(err, "code")
    if code >= 0:
        e.code = clip(r.json(code) if r.kind(code) != Kind.STRING else r.str(err, "code"))
    return True


def _raise_error_member(mut r: Reader) raises LlmError:
    """A body that holds `{"error": ...}` instead of an answer."""
    var e = LlmError(LlmError.API, "")
    if _fill_error(r, e):
        raise e^
    if r.get(0, "error") >= 0:
        raise LlmError(LlmError.PROTOCOL, "llm: an error that is neither an object nor a string")


struct ChunkDecoder(Movable):
    """The `Delta`s of a streamed chat, one event's data at a time; it also
    builds the whole `Reply` (`reply`)."""

    var reply: Reply
    var done: Bool
    var _calls: Int
    """Tool calls started (their indexes are 0 to `_calls` - 1)."""

    def __init__(out self):
        self.reply = Reply()
        self.done = False
        self._calls = 0

    def feed(mut self, data: StringSlice, mut out: List[Delta]) raises LlmError:
        """Append the deltas in one event's `data` to `out`."""
        if self.done:
            raise LlmError(LlmError.PROTOCOL, "llm: an event after [DONE]")
        if data == "[DONE]":
            self.done = True
            var d = Delta()
            d.kind = DeltaKind.DONE
            d.text = self.reply.finish_reason
            d.usage = self.reply.usage
            out.append(d^)
            return
        var r = Reader(data.as_bytes())
        _raise_error_member(r)
        if self.reply.id.byte_length() == 0:
            self.reply.id = r.str(0, "id")
            self.reply.model = r.str(0, "model")
        var u = _usage(r, 0)
        if u.input_tokens >= 0 or u.output_tokens >= 0:
            self.reply.usage = u
        var choices = r.array(0, "choices")
        var c = r.first(choices)
        for _ in range(r.count(choices)):
            if r.int(c, "index", 0) == 0:
                self._choice(r, c, out)
            c = r.next(c)
        r.check()

    def _choice(mut self, mut r: Reader, c: Int, mut out: List[Delta]):
        var reason = r.str(c, "finish_reason")
        if reason.byte_length() > 0:
            self.reply.finish_reason = reason
        var delta = r.object(c, "delta")
        if delta < 0:
            return
        var text = r.str(delta, "content")
        if text.byte_length() > 0:
            self.reply.text += text
            var d = Delta()
            d.text = text^
            out.append(d^)
        var refusal = r.str(delta, "refusal")
        if refusal.byte_length() > 0:
            self.reply.refusal += refusal
            var d = Delta()
            d.kind = DeltaKind.REFUSAL
            d.text = refusal^
            out.append(d^)
        var calls = r.array(delta, "tool_calls")
        var t = r.first(calls)
        for _ in range(r.count(calls)):
            var index = r.int(t, "index", -1)
            if index < 0 and r.get(t, "index") < 0:
                # No index (some servers leave it out): a new id starts a
                # new call; anything else continues the last one.
                var id = r.str(t, "id")
                var last = self._calls - 1
                if self._calls == 0 or (id.byte_length() > 0 and id != self.reply.tool_calls[last].id):
                    index = self._calls
                else:
                    index = last
            var f = r.object(t, "function")
            if index == self._calls:
                # A new call: its id and name come in its first fragment.
                self._calls += 1
                self.reply.tool_calls.append(ToolCall(r.str(t, "id"), r.str(f, "name"), String()))
                var d = Delta()
                d.kind = DeltaKind.TOOL_CALL
                d.index = index
                d.id = self.reply.tool_calls[index].id
                d.name = self.reply.tool_calls[index].name
                out.append(d^)
            elif index < 0 or index > self._calls:
                r.bad = True
                r.problem = String("llm: a tool call fragment skips an index")
                return
            var args = r.arguments(f, "arguments")
            if args.byte_length() > 0:
                self.reply.tool_calls[index].arguments += args
                var d = Delta()
                d.kind = DeltaKind.TOOL_ARGS
                d.index = index
                d.text = args^
                out.append(d^)
            t = r.next(t)

    def finish(self) raises LlmError:
        """The stream has ended: PROTOCOL unless `[DONE]` came."""
        if not self.done:
            raise LlmError(LlmError.PROTOCOL, "llm: the stream ended before [DONE]")


# ---- embeddings ---------------------------------------------------------------


def write_embeddings(model: StringSlice, inputs: List[String], *, base64: Bool = True, dimensions: Int = 0) raises LlmError -> List[UInt8]:
    """The JSON body of `POST /embeddings`. With `base64`, the vectors come
    as base64 float32 (a quarter of the bytes of decimal text)."""
    try:
        if model.byte_length() == 0 or len(inputs) == 0:
            raise JsonError(JsonError.USAGE, "llm: embeddings need a model and at least one input")
        var w = Writer()
        w.begin_object()
        w.key("model")
        w.string(model)
        w.key("input")
        w.begin_array()
        for s in inputs:
            w.string(s)
        w.end_array()
        w.key("encoding_format")
        w.string("base64" if base64 else "float")
        if dimensions > 0:
            w.key("dimensions")
            w.int(dimensions)
        w.end_object()
        return w.take()
    except e:
        raise usage_error(e)


def read_embeddings(body: Span[UInt8, _], expected: Int) raises LlmError -> Embeddings:
    """The vectors in an `/embeddings` response, in input order: each
    `data` item's `index` places it, and each of the `expected` inputs must
    have exactly one. Vectors come as arrays of numbers or as base64
    little-endian float32."""
    var r = Reader(body)
    _raise_error_member(r)
    var out = Embeddings()
    out.model = r.str(0, "model")
    var u = r.object(0, "usage")
    if u >= 0:
        out.usage = Usage(r.int(u, "prompt_tokens"), -1)
    var data = r.array(0, "data")
    r.check()
    if r.count(data) != expected:
        raise LlmError(LlmError.PROTOCOL, "llm: the response's embeddings do not match the inputs")
    for _ in range(expected):
        out.vectors.append(List[Float32]())
    var seen = List[Bool](length=expected, fill=False)
    var item = r.first(data)
    for _ in range(expected):
        var index = r.int(item, "index")
        if index < 0 or index >= expected or seen[index]:
            raise LlmError(LlmError.PROTOCOL, "llm: an embedding's index is missing, repeated or out of range")
        seen[index] = True
        var v = r.get(item, "embedding")
        if v < 0:
            raise LlmError(LlmError.PROTOCOL, "llm: an embedding is missing")
        if r.kind(v) == Kind.STRING:
            out.vectors[index] = _float32s(r.str(item, "embedding"))
        elif r.kind(v) == Kind.ARRAY:
            var vec = List[Float32](capacity=r.count(v))
            var x = r.first(v)
            for _ in range(r.count(v)):
                try:
                    vec.append(Float32(r.doc.float(x)))
                except:
                    raise LlmError(LlmError.PROTOCOL, "llm: an embedding holds something other than numbers")
                x += 1
            out.vectors[index] = vec^
        else:
            raise LlmError(LlmError.PROTOCOL, "llm: an embedding is neither an array nor base64")
        item = r.next(item)
    r.check()
    return out^


def _float32s(text: String) raises LlmError -> List[Float32]:
    """Base64 (strict) of little-endian float32 values."""
    var raw: List[UInt8]
    try:
        raw = base64_decode(text)
    except:
        raise LlmError(LlmError.PROTOCOL, "llm: an embedding is not valid base64")
    if len(raw) % 4 != 0:
        raise LlmError(LlmError.PROTOCOL, "llm: a base64 embedding is not whole float32 values")
    var out = List[Float32](capacity=len(raw) // 4)
    for i in range(0, len(raw), 4):
        var bits = UInt32(raw[i]) | (UInt32(raw[i + 1]) << 8) | (UInt32(raw[i + 2]) << 16) | (UInt32(raw[i + 3]) << 24)
        out.append(bitcast[DType.float32](bits))
    return out^
