"""Anthropic's Messages API: the body of `POST /messages`, the reply, and
the events of a streamed reply. Sans-I/O.

- **Requests:** `write_messages` maps a `ChatRequest`. System messages
  become the top-level `system` (joined by blank lines). An assistant's
  tool calls become `tool_use` blocks, whose `input` is the arguments'
  object. Tool results become `tool_result` blocks in a user turn, with
  consecutive results in one turn. Tools carry their `input_schema`.
  `max_tokens` is required, `seed` is refused (the API has none), and so
  is a turn with empty content (the API refuses it).
- **Replies:** `read_messages` joins the text blocks and keeps each
  `tool_use` block as a call (its `input` as JSON text). Other blocks
  (thinking, a server tool's or MCP tool's use) are skipped, in replies
  and streams alike, so extended thinking with tools, which needs the
  thinking blocks sent back, is not supported yet.
- **Streams:** `EventDecoder` follows the event types: `message_start`,
  `content_block_start` / `_delta` / `_stop`, `message_delta`,
  `message_stop` (DONE), `ping`; `error` raises API. Types it does not
  know are skipped, as Anthropic asks of clients. A stream that ends
  before `message_stop` is cut short (`finish()` raises PROTOCOL).
- **Errors** are `{"type": "error", "error": {"type", "message"}}`, which
  `openai.read_error` reads as well.
"""

from json import JsonError, Writer

from .common import Reader, clip, usage_error, write_extra, write_object_text
from .error import LlmError
from .types import ChatRequest, Delta, DeltaKind, Reply, ToolCall, Usage

comptime VERSION = "2023-06-01"
"""The `anthropic-version` header this module speaks."""



def write_messages(req: ChatRequest, stream: Bool = False) raises LlmError -> List[UInt8]:
    """The JSON body of `POST /messages` for `req`."""
    try:
        return _write_messages(req, stream)
    except e:
        raise usage_error(e)


def _write_messages(req: ChatRequest, stream: Bool) raises JsonError -> List[UInt8]:
    if req.model.byte_length() == 0:
        raise JsonError(JsonError.USAGE, "llm: the request names no model")
    if req.max_tokens <= 0:
        raise JsonError(JsonError.USAGE, "llm: Anthropic's API requires max_tokens")
    if req.seed:
        raise JsonError(JsonError.USAGE, "llm: Anthropic's API takes no seed")
    var system = String()
    for m in req.messages:
        if m.role == "system":
            if system.byte_length() > 0:
                system += "\n\n"
            system += m.content
    var w = Writer()
    w.begin_object()
    w.key("model")
    w.string(req.model)
    w.key("max_tokens")
    w.int(req.max_tokens)
    if system.byte_length() > 0:
        w.key("system")
        w.string(system)
    w.key("messages")
    w.begin_array()
    var in_results = False  # (a user turn of tool results is open)
    var turns = 0
    for m in req.messages:
        if m.role == "system":
            continue
        if m.role == "tool":
            if m.tool_call_id.byte_length() == 0:
                raise JsonError(JsonError.USAGE, "llm: a tool message names no tool call")
            if not in_results:
                w.begin_object()
                w.key("role")
                w.string("user")
                w.key("content")
                w.begin_array()
                in_results = True
                turns += 1
            w.begin_object()
            w.key("type")
            w.string("tool_result")
            w.key("tool_use_id")
            w.string(m.tool_call_id)
            w.key("content")
            w.string(m.content)
            w.end_object()
            continue
        if in_results:
            w.end_array()
            w.end_object()
            in_results = False
        if m.role != "user" and m.role != "assistant":
            raise JsonError(JsonError.USAGE, "llm: a message's role is not system, user, assistant or tool")
        if len(m.tool_calls) > 0 and m.role != "assistant":
            raise JsonError(JsonError.USAGE, "llm: only an assistant message carries tool calls")
        if m.content.byte_length() == 0 and len(m.tool_calls) == 0:
            raise JsonError(JsonError.USAGE, "llm: Anthropic's API refuses a message with empty content")
        turns += 1
        w.begin_object()
        w.key("role")
        w.string(m.role)
        w.key("content")
        if len(m.tool_calls) == 0:
            w.string(m.content)
        else:
            w.begin_array()
            if m.content.byte_length() > 0:
                w.begin_object()
                w.key("type")
                w.string("text")
                w.key("text")
                w.string(m.content)
                w.end_object()
            for c in m.tool_calls:
                w.begin_object()
                w.key("type")
                w.string("tool_use")
                w.key("id")
                w.string(c.id)
                w.key("name")
                w.string(c.name)
                w.key("input")
                write_object_text(w, c.arguments if c.arguments.byte_length() > 0 else String("{}"))
                w.end_object()
            w.end_array()
        w.end_object()
    if in_results:
        w.end_array()
        w.end_object()
    w.end_array()
    if turns == 0:
        raise JsonError(JsonError.USAGE, "llm: the request has no messages")
    if len(req.tools) > 0:
        w.key("tools")
        w.begin_array()
        for t in req.tools:
            w.begin_object()
            w.key("name")
            w.string(t.name)
            if t.description.byte_length() > 0:
                w.key("description")
                w.string(t.description)
            w.key("input_schema")
            write_object_text(w, t.parameters)
            w.end_object()
        w.end_array()
    if req.temperature:
        w.key("temperature")
        w.float(req.temperature.value())
    if req.top_p:
        w.key("top_p")
        w.float(req.top_p.value())
    if len(req.stop) > 0:
        w.key("stop_sequences")
        w.begin_array()
        for s in req.stop:
            w.string(s)
        w.end_array()
    if stream:
        w.key("stream")
        w.bool(True)
    var taken: List[String] = ["model", "max_tokens", "messages"]  # (what was written: extra may hold the rest)
    if system.byte_length() > 0:
        taken.append("system")
    if len(req.tools) > 0:
        taken.append("tools")
    if req.temperature:
        taken.append("temperature")
    if req.top_p:
        taken.append("top_p")
    if len(req.stop) > 0:
        taken.append("stop_sequences")
    if stream:
        taken.append("stream")
    write_extra(w, req.extra, taken)
    w.end_object()
    return w.take()


def _raise_if_error(mut r: Reader) raises LlmError:
    if r.str(0, "type") != "error":
        return
    var err = r.object(0, "error")
    var e = LlmError(LlmError.API, clip(r.str(err, "message")))
    e.type = r.str(err, "type")
    raise e^


def read_messages(body: Span[UInt8, _]) raises LlmError -> Reply:
    """The reply in a `/messages` response body (status 200)."""
    var r = Reader(body)
    _raise_if_error(r)
    var reply = Reply()
    reply.id = r.str(0, "id")
    reply.model = r.str(0, "model")
    reply.finish_reason = r.str(0, "stop_reason")
    var u = r.object(0, "usage")
    if u >= 0:
        reply.usage = Usage(r.int(u, "input_tokens"), r.int(u, "output_tokens"))
    var content = r.array(0, "content")
    r.check()
    if content < 0:
        raise LlmError(LlmError.PROTOCOL, "llm: the response has no content")
    var b = r.first(content)
    for _ in range(r.count(content)):
        var t = r.str(b, "type")
        if t == "text":
            reply.text += r.str(b, "text")
        elif t == "tool_use":
            var input = r.object(b, "input")
            reply.tool_calls.append(ToolCall(r.str(b, "id"), r.str(b, "name"), r.json(input) if input >= 0 else String("{}")))
        b = r.next(b)
    r.check()
    return reply^


struct EventDecoder(Movable):
    """The `Delta`s of a streamed reply, one event at a time; it also
    builds the whole `Reply` (`reply`)."""

    var reply: Reply
    var done: Bool
    var _tool_of_block: List[Int]
    """Per content block: its tool call's index; -1 for a text block, -2
    for any other (thinking, a server or MCP tool's use, a type to come)."""

    def __init__(out self):
        self.reply = Reply()
        self.done = False
        self._tool_of_block = List[Int]()

    def feed(mut self, data: StringSlice, mut out: List[Delta]) raises LlmError:
        """Append the deltas in one event's `data` to `out` (the event's
        type is read from the data's own `type`)."""
        if self.done:
            raise LlmError(LlmError.PROTOCOL, "llm: an event after message_stop")
        var r = Reader(data.as_bytes())
        _raise_if_error(r)
        var t = r.str(0, "type")
        if t == "message_start":
            var m = r.object(0, "message")
            self.reply.id = r.str(m, "id")
            self.reply.model = r.str(m, "model")
            var u = r.object(m, "usage")
            if u >= 0:
                self.reply.usage.input_tokens = r.int(u, "input_tokens")
        elif t == "content_block_start":
            var index = r.int(0, "index")
            var block = r.object(0, "content_block")
            if index < 0 or index != len(self._tool_of_block):
                raise LlmError(LlmError.PROTOCOL, "llm: content blocks out of order")
            var kind = r.str(block, "type")
            if kind == "tool_use":
                var call = len(self.reply.tool_calls)
                self._tool_of_block.append(call)
                self.reply.tool_calls.append(ToolCall(r.str(block, "id"), r.str(block, "name"), String()))
                var d = Delta()
                d.kind = DeltaKind.TOOL_CALL
                d.index = call
                d.id = self.reply.tool_calls[call].id
                d.name = self.reply.tool_calls[call].name
                out.append(d^)
            elif kind == "text":
                self._tool_of_block.append(-1)
                self._text(r.str(block, "text"), out)
            else:
                self._tool_of_block.append(-2)
        elif t == "content_block_delta":
            var index = r.int(0, "index")
            if index < 0 or index >= len(self._tool_of_block):
                raise LlmError(LlmError.PROTOCOL, "llm: a delta for a block that did not start")
            var delta = r.object(0, "delta")
            var kind = r.str(delta, "type")
            if kind == "text_delta":
                self._text(r.str(delta, "text"), out)
            elif kind == "input_json_delta":
                var call = self._tool_of_block[index]
                if call == -1:
                    raise LlmError(LlmError.PROTOCOL, "llm: tool input for a text block")
                if call < 0:  # (a server tool's or MCP tool's input: not a call for the caller)
                    r.check()
                    return
                var piece = r.str(delta, "partial_json")
                if piece.byte_length() > 0:
                    self.reply.tool_calls[call].arguments += piece
                    var d = Delta()
                    d.kind = DeltaKind.TOOL_ARGS
                    d.index = call
                    d.text = piece^
                    out.append(d^)
        elif t == "content_block_stop":
            var index = r.int(0, "index")
            if index >= 0 and index < len(self._tool_of_block):
                var call = self._tool_of_block[index]
                if call >= 0 and self.reply.tool_calls[call].arguments.byte_length() == 0:
                    self.reply.tool_calls[call].arguments = "{}"
        elif t == "message_delta":
            var delta = r.object(0, "delta")
            var reason = r.str(delta, "stop_reason")
            if reason.byte_length() > 0:
                self.reply.finish_reason = reason
            var u = r.object(0, "usage")
            if u >= 0:
                self.reply.usage.output_tokens = r.int(u, "output_tokens")
        elif t == "message_stop":
            self.done = True
            var d = Delta()
            d.kind = DeltaKind.DONE
            d.text = self.reply.finish_reason
            d.usage = self.reply.usage
            out.append(d^)
        # ("ping", and types this module does not know, are skipped.)
        r.check()

    def _text(mut self, text: String, mut out: List[Delta]):
        if text.byte_length() == 0:
            return
        self.reply.text += text
        var d = Delta()
        d.text = text
        out.append(d^)

    def finish(self) raises LlmError:
        """The stream has ended: PROTOCOL unless `message_stop` came."""
        if not self.done:
            raise LlmError(LlmError.PROTOCOL, "llm: the stream ended before message_stop")
