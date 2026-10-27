"""The provider-neutral model of a chat: `Message`s with tool calls and
results, `Tool`s described by a JSON Schema, a `ChatRequest`, the `Reply`
and the `Delta`s a streamed reply arrives as. `llm.openai` and
`llm.anthropic` map them to and from each API's JSON."""


@fieldwise_init
struct ToolCall(Copyable, Movable, Writable):
    """A function the model asked to call."""

    var id: String
    var name: String
    var arguments: String
    """The arguments as the model wrote them: JSON text, meant to be an
    object (the model may still write something else; parse and check)."""

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.name, "(", self.arguments, ") #", self.id)


struct Message(Copyable, Movable):
    """One turn of the conversation."""

    var role: String
    """"system", "user", "assistant" or "tool"."""
    var content: String
    var tool_calls: List[ToolCall]
    """An assistant turn's calls, when the conversation is sent back."""
    var tool_call_id: String
    """A "tool" turn: the call it answers."""

    def __init__(out self, role: StringSlice, content: StringSlice):
        self.role = String(role)
        self.content = String(content)
        self.tool_calls = List[ToolCall]()
        self.tool_call_id = String()

    @staticmethod
    def system(content: StringSlice) -> Message:
        return Message("system", content)

    @staticmethod
    def user(content: StringSlice) -> Message:
        return Message("user", content)

    @staticmethod
    def assistant(content: StringSlice, var tool_calls: List[ToolCall] = List[ToolCall]()) -> Message:
        var m = Message("assistant", content)
        m.tool_calls = tool_calls^
        return m^

    @staticmethod
    def tool(call_id: StringSlice, content: StringSlice) -> Message:
        """The result of the call `call_id`."""
        var m = Message("tool", content)
        m.tool_call_id = String(call_id)
        return m^


@fieldwise_init
struct Tool(Copyable, Movable):
    """A function the model may call."""

    var name: String
    var description: String
    var parameters: String
    """A JSON Schema of the arguments, as JSON text (an object)."""


struct ChatRequest(Copyable, Movable):
    """A chat to send. Unset options (None, 0, empty) are left out, so the
    server's defaults apply."""

    var model: String
    var messages: List[Message]
    var tools: List[Tool]
    var max_tokens: Int
    """0 to leave it to the server (OpenAI-style APIs); Anthropic's API
    requires it."""
    var max_tokens_field: String
    """OpenAI-style APIs: the field `max_tokens` is sent as, "max_tokens"
    (what most servers read) or "max_completion_tokens" (what OpenAI's
    reasoning models, o-series and gpt-5, require)."""
    var temperature: Optional[Float64]
    var top_p: Optional[Float64]
    var stop: List[String]
    var seed: Optional[Int]
    """OpenAI-style APIs only."""
    var stream_usage: Bool
    """Ask an OpenAI-style stream for usage in its last chunk
    (`stream_options.include_usage`)."""
    var extra: String
    """More top-level fields, as a JSON object's text (`{"response_format":
    {...}}`), written as given; a field this request writes itself is
    refused (one it leaves unset, such as `system` with no system message,
    may come from here)."""

    def __init__(out self, model: StringSlice, var messages: List[Message] = List[Message]()):
        self.model = String(model)
        self.messages = messages^
        self.tools = List[Tool]()
        self.max_tokens = 0
        self.max_tokens_field = String("max_tokens")
        self.temperature = None
        self.top_p = None
        self.stop = List[String]()
        self.seed = None
        self.stream_usage = True
        self.extra = String()


@fieldwise_init
struct Usage(Copyable, Equatable, TrivialRegisterPassable, Writable):
    """Tokens counted by the provider (-1 when it did not say)."""

    var input_tokens: Int
    var output_tokens: Int

    @staticmethod
    def unknown() -> Usage:
        return Usage(-1, -1)

    def __eq__(self, other: Self) -> Bool:
        return self.input_tokens == other.input_tokens and self.output_tokens == other.output_tokens

    def write_to(self, mut writer: Some[Writer]):
        writer.write("in=", self.input_tokens, " out=", self.output_tokens)


struct Reply(Copyable, Movable, Writable):
    """The model's answer (the first choice, for APIs that can give more)."""

    var id: String
    var model: String
    var text: String
    var tool_calls: List[ToolCall]
    var finish_reason: String
    """As the provider says it: "stop", "length", "tool_calls" (OpenAI);
    "end_turn", "max_tokens", "tool_use", "stop_sequence" (Anthropic)."""
    var refusal: String
    """OpenAI-style APIs: the model's refusal, when it refused instead of
    answering ("" otherwise)."""
    var usage: Usage

    def __init__(out self):
        self.id = String()
        self.model = String()
        self.text = String()
        self.tool_calls = List[ToolCall]()
        self.finish_reason = String()
        self.refusal = String()
        self.usage = Usage.unknown()

    def write_to(self, mut writer: Some[Writer]):
        writer.write(repr(self.text), " [", self.finish_reason, "; ", self.usage, "]")
        for c in self.tool_calls:
            writer.write(" ", c)


struct DeltaKind(Equatable, TrivialRegisterPassable, Writable):
    var _v: Int

    comptime TEXT = DeltaKind(1)
    """`text` is the next piece of the answer."""
    comptime TOOL_CALL = DeltaKind(2)
    """Tool call `index` starts: `id` and `name`."""
    comptime TOOL_ARGS = DeltaKind(3)
    """`text` is the next piece of tool call `index`'s arguments."""
    comptime DONE = DeltaKind(4)
    """The answer is complete: `text` is the finish reason, and `usage`."""
    comptime REFUSAL = DeltaKind(5)
    """`text` is the next piece of a refusal (OpenAI-style APIs)."""

    def __init__(out self, v: Int):
        self._v = v

    def __eq__(self, other: Self) -> Bool:
        return self._v == other._v

    def write_to(self, mut writer: Some[Writer]):
        var names: List[StaticString] = ["?", "text", "tool_call", "tool_args", "done", "refusal"]
        writer.write(names[self._v] if self._v > 0 and self._v < len(names) else "?")


struct Delta(Copyable, Movable, Writable):
    """One piece of a streamed reply (see `DeltaKind`)."""

    var kind: DeltaKind
    var text: String
    var index: Int
    var id: String
    var name: String
    var usage: Usage

    def __init__(out self):
        self.kind = DeltaKind.TEXT
        self.text = String()
        self.index = 0
        self.id = String()
        self.name = String()
        self.usage = Usage.unknown()

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.kind, " ", repr(self.text))
        if self.kind == DeltaKind.TOOL_CALL:
            writer.write(" #", self.index, " ", self.id, " ", self.name)
        elif self.kind == DeltaKind.TOOL_ARGS:
            writer.write(" #", self.index)
        elif self.kind == DeltaKind.DONE:
            writer.write(" ", self.usage)


struct Embeddings(Copyable, Movable):
    """Vectors in the order of the inputs."""

    var vectors: List[List[Float32]]
    var model: String
    var usage: Usage

    def __init__(out self):
        self.vectors = List[List[Float32]]()
        self.model = String()
        self.usage = Usage.unknown()
