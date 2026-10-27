"""`LlmError`: what went wrong in a call to a model API, of which kind."""

from linux import ErrorKind, IoError


struct LlmError(Copyable, Movable, Writable):
    """Raised by everything in `llm`. `kind` is one of the constants below.
    For HTTP and API errors, `status`, `type`, `code`, `message` and
    `request_id` come from the provider's response (empty when it gave
    none); for TRANSPORT errors, `io` is the network's error."""

    comptime HTTP = 1
    """The API answered with a status of 400 or more."""
    comptime API = 2
    """An error event in the middle of a stream (the status was 200)."""
    comptime PROTOCOL = 3
    """The response is not what the API's protocol says: not JSON, a field
    of the wrong type, a stream cut short before its end marker."""
    comptime TRANSPORT = 4
    """Connecting, TLS, sending or receiving failed, or a deadline passed."""
    comptime USAGE = 5
    """The request cannot be sent as given (a tool's schema that is not a
    JSON object, an unknown role, a missing field the API requires)."""

    var kind: Int
    var status: Int
    var type: String
    var code: String
    var message: String
    var request_id: String
    var io: IoError
    var retries: Int
    """How many times the call was sent again before this error."""

    def __init__(out self, kind: Int, message: StringSlice, *, status: Int = 0):
        self.kind = kind
        self.status = status
        self.type = String()
        self.code = String()
        self.message = String(message)
        self.request_id = String()
        self.io = IoError.of_kind("llm", ErrorKind.Other)
        self.retries = 0

    @staticmethod
    def transport(io: IoError) -> LlmError:
        var e = LlmError(LlmError.TRANSPORT, String(io))
        e.io = io
        return e^

    def is_rate_limit(self) -> Bool:
        return self.kind == LlmError.HTTP and self.status == 429

    def write_to(self, mut writer: Some[Writer]):
        var names: List[StaticString] = ["", "http", "api", "protocol", "transport", "usage"]
        writer.write("llm ", names[self.kind] if self.kind > 0 and self.kind < len(names) else "error")
        if self.status > 0:
            writer.write(" ", self.status)
        if self.type.byte_length() > 0:
            writer.write(" ", self.type)
        if self.code.byte_length() > 0:
            writer.write(" (", self.code, ")")
        writer.write(": ", self.message)
        if self.request_id.byte_length() > 0:
            writer.write(" [request ", self.request_id, "]")
        if self.retries > 0:
            writer.write(" after ", self.retries, " retries")
