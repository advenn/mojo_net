"""`Client`: calls a model API over `http.client.Client`, blocking, with the
SDKs' retries (`llm.retry`). One client speaks one dialect (`Provider`):

    var c = Client(Provider.OPENAI, "http://localhost:8000/v1")   # max serve, vLLM, ...
    var req = ChatRequest("model", [Message.user("Hi")])
    print(c.chat(req).text)
    var s = c.stream(req)
    var d = Delta()
    while s.next(d):
        if d.kind == DeltaKind.TEXT:
            print(d.text, end="")

- **Paths** are appended to `base_url`: `/chat/completions` and
  `/embeddings` (OpenAI-style), `/messages` (Anthropic).
- **Headers:** `Authorization: Bearer` (OpenAI-style, when there is a
  key) or `x-api-key` with `anthropic-version` (Anthropic), plus the
  caller's `headers`.
- **Deadlines:** `timeout` (600 s, the SDKs' default) covers a whole call,
  its retries and their waits included; for a stream it covers the call up
  to the stream's head. A stream then waits at most `stream_idle` between
  pieces, and lasts at most `stream_total` (no limit by default).
- **Bounds:** a reply's text and tool arguments together may grow to
  `max_reply` bytes (16 MiB), and a stream may start `max_tool_calls`
  calls (128); past either, the stream fails (PROTOCOL). A whole reply is
  bounded by `max_body` (64 MiB).
- **Retries:** a call that fails in a way worth retrying is sent again
  (`llm.retry`), while its deadline leaves time for the wait; a stream only
  until its head has come, never once it has started. The error raised in
  the end says how many retries it took.
- **Errors** are `LlmError`: HTTP with the API's message, type, code and
  request id (`x-request-id`, or Anthropic's `request-id`); API for an
  error event in a stream (with the stream's request id); PROTOCOL;
  TRANSPORT (a connection dropped mid-stream is TRANSPORT, UnexpectedEof);
  USAGE. A stream's first error is final: `next` raises it again.
"""

from http.client import Client as HttpClient, EventStream, Response, StreamedResponse
from http.headers import Headers
from http.sse import SseEvent
from linux import ErrorKind, IoError
from linux.time import Deadline, Duration, sleep, unix_time_ns
from tls import ClientConfig, ClientContext

from .anthropic import VERSION as ANTHROPIC_VERSION, EventDecoder, read_messages, write_messages
from .error import LlmError
from .openai import ChunkDecoder, read_chat, read_embeddings, read_error, write_chat, write_embeddings
from .retry import Jitter, RetryPolicy, backoff, retryable_io, retryable_status, wait_before_retry
from .types import ChatRequest, Delta, DeltaKind, Embeddings, Reply

comptime DEFAULT_MAX_REPLY = 16 * 1024 * 1024
comptime DEFAULT_MAX_TOOL_CALLS = 128
comptime _MAX_ERROR_BODY = 64 * 1024


struct Provider(Equatable, TrivialRegisterPassable, Writable):
    var _v: Int

    comptime OPENAI = Provider(1)
    """OpenAI's API, and the servers compatible with it."""
    comptime ANTHROPIC = Provider(2)

    def __init__(out self, v: Int):
        self._v = v

    def __eq__(self, other: Self) -> Bool:
        return self._v == other._v

    def write_to(self, mut writer: Some[Writer]):
        writer.write("openai" if self._v == 1 else "anthropic")


def _request_id(headers: Headers) -> String:
    var id = headers.get("x-request-id")
    if not id:
        id = headers.get("request-id")
    return String(id.value()) if id else String()


def _timed_out(retries: Int) -> LlmError:
    var e = LlmError.transport(IoError.of_kind("llm: the call's deadline passed", ErrorKind.TimedOut))
    e.retries = retries
    return e^


struct Client(Movable):
    """See the module docs. Not for use from several threads at once."""

    var provider: Provider
    var base_url: String
    var api_key: String
    var headers: Headers
    """Sent with every request, after the client's own."""
    var retry: RetryPolicy
    var timeout: Duration
    var stream_idle: Duration
    var stream_total: Duration
    var max_reply: Int
    var max_tool_calls: Int
    var _http: HttpClient
    var _jitter: Jitter

    def __init__(
        out self,
        provider: Provider,
        base_url: StringSlice,
        api_key: StringSlice = "",
        *,
        timeout: Duration = Duration.from_secs(600),
        retry: RetryPolicy = RetryPolicy(),
        stream_idle: Duration = Duration.from_secs(600),
        stream_total: Duration = Duration.MAX,
        max_reply: Int = DEFAULT_MAX_REPLY,
        max_tool_calls: Int = DEFAULT_MAX_TOOL_CALLS,
        max_body: Int = 64 * 1024 * 1024,
        var tls: ClientConfig = ClientConfig(),
        tls_context: Optional[ClientContext] = None,
    ) raises LlmError:
        """`base_url` up to the API's version (`https://api.openai.com/v1`,
        `https://api.anthropic.com/v1`, `http://localhost:8000/v1`).
        `tls_context`: a context built already, with ALPN `http/1.1`, to
        share between clients (`http.client.Client`)."""
        var end = base_url.byte_length()
        while end > 0 and base_url.as_bytes()[end - 1] == 47:  # (a trailing '/')
            end -= 1
        self.provider = provider
        self.base_url = String(base_url[byte=:end])
        self.api_key = String(api_key)
        self.headers = Headers()
        self.retry = retry
        self.timeout = timeout
        self.stream_idle = stream_idle
        self.stream_total = stream_total
        self.max_reply = max_reply
        self.max_tool_calls = max_tool_calls
        try:
            self._http = HttpClient(timeout=timeout, max_body=max_body, user_agent="mojo-net-llm", tls=tls^, tls_context=tls_context)
        except e:
            raise LlmError(LlmError.USAGE, String(e))
        self._jitter = Jitter(UInt64(unix_time_ns()))

    # ---- calls ------------------------------------------------------------

    def chat(mut self, req: ChatRequest) raises LlmError -> Reply:
        """Send `req` and return the whole reply."""
        if self.provider == Provider.ANTHROPIC:
            var body = write_messages(req)
            var r = self._call("/messages", body)
            return read_messages(Span(r.body))
        var body = write_chat(req)
        var r = self._call("/chat/completions", body)
        return read_chat(Span(r.body))

    def stream(mut self, req: ChatRequest) raises LlmError -> ReplyStream:
        """Send `req` with `stream` on, and return once the reply starts:
        read its `Delta`s with `ReplyStream.next`. Dropping the stream
        closes the connection, which cancels the reply."""
        var anthropic = self.provider == Provider.ANTHROPIC
        var body = write_messages(req, stream=True) if anthropic else write_chat(req, stream=True)
        var retries = 0
        var r = self._open("/messages" if anthropic else "/chat/completions", body, retries)
        var id = _request_id(r.headers)
        var events: EventStream
        try:
            events = EventStream(r^)
        except e:
            var err = LlmError(LlmError.PROTOCOL, "llm: the stream's response is not text/event-stream")
            err.request_id = id
            err.retries = retries
            raise err^
        return ReplyStream(events^, self.provider, id, retries, self.max_reply, self.max_tool_calls)

    def embed(mut self, model: StringSlice, inputs: List[String], *, dimensions: Int = 0) raises LlmError -> Embeddings:
        """The embeddings of `inputs` (OpenAI-style APIs; fetched as base64
        float32)."""
        if self.provider != Provider.OPENAI:
            raise LlmError(LlmError.USAGE, "llm: Anthropic's API has no embeddings")
        var body = write_embeddings(model, inputs, base64=True, dimensions=dimensions)
        var r = self._call("/embeddings", body)
        return read_embeddings(Span(r.body), len(inputs))

    # ---- transport --------------------------------------------------------

    def _request_headers(self, stream: Bool) raises LlmError -> Headers:
        var h = Headers()
        try:
            h.add("Content-Type", "application/json")
            h.add("Accept", "text/event-stream" if stream else "application/json")
            if self.provider == Provider.ANTHROPIC:
                h.add("anthropic-version", ANTHROPIC_VERSION)
                if self.api_key.byte_length() > 0:
                    h.add("x-api-key", self.api_key)
            elif self.api_key.byte_length() > 0:
                h.add("Authorization", String("Bearer ", self.api_key))
            for i in range(len(self.headers)):
                h.add(self.headers.name(i), self.headers.value(i))
        except e:
            raise LlmError(LlmError.USAGE, String("llm: a header cannot be sent: ", e))
        return h^

    def _error(self, status: Int, headers: Headers, body: Span[UInt8, _], retries: Int) -> LlmError:
        var e = read_error(body, status)
        e.request_id = _request_id(headers)
        e.retries = retries
        return e^

    def _io_error(self, e: IoError, retries: Int) -> LlmError:
        """`InvalidInput` from `http` is the caller's (a header http frames
        itself, a bad URL): USAGE. Everything else is TRANSPORT."""
        var err = LlmError(LlmError.USAGE, String("llm: the request cannot be sent: ", e)) if e.kind == ErrorKind.InvalidInput else LlmError.transport(e)
        err.retries = retries
        return err^

    def _wait(mut self, d: Duration, deadline: Deadline) raises LlmError -> Bool:
        """Sleep `d` if the deadline leaves room for it and an attempt after
        it; False (without sleeping) if not."""
        var left = deadline.remaining()
        if left and not (d < left.value()):
            return False
        try:
            sleep(d)
        except e:
            raise LlmError.transport(e)
        return True

    def _attempt_timeout(self, deadline: Deadline, retries: Int) raises LlmError -> Duration:
        """What is left of the call's deadline, for the next attempt."""
        var left = deadline.remaining()
        if not left:
            return self.timeout
        if left.value().is_zero():
            raise _timed_out(retries)
        return left.value()

    def _call(mut self, path: StringSlice, body: List[UInt8]) raises LlmError -> Response:
        """POST `body` to `path` and read the whole response, retrying as
        the policy says within one deadline; a status of 400 or more raises
        HTTP."""
        var url = self.base_url + path
        var h = self._request_headers(False)
        var deadline = Deadline.after(self.timeout)
        var retries = 0
        while True:
            self._http.timeout = self._attempt_timeout(deadline, retries)
            var r: Response
            try:
                r = self._http.request("POST", url, h, Span(body))
            except e:
                if e.kind == ErrorKind.TimedOut and deadline.is_expired():
                    raise _timed_out(retries)
                if retryable_io(e) and retries < self.retry.max_retries:
                    if self._wait(backoff(self.retry, retries, self._jitter.next()), deadline):
                        retries += 1
                        continue
                raise self._io_error(e, retries)
            if r.status < 400:
                return r^
            if retryable_status(r.status, r.headers) and retries < self.retry.max_retries:
                var d = wait_before_retry(self.retry, retries, r.headers, unix_time_ns() // 1_000_000_000, self._jitter.next())
                if self._wait(d, deadline):
                    retries += 1
                    continue
            raise self._error(r.status, r.headers, Span(r.body), retries)

    def _open(mut self, path: StringSlice, body: List[UInt8], mut retries: Int) raises LlmError -> StreamedResponse:
        """POST for a stream and return at its head, retrying (as `_call`)
        only until a head of 2xx comes, within one deadline. An error's
        body is read under that deadline too."""
        var url = self.base_url + path
        var h = self._request_headers(True)
        var deadline = Deadline.after(self.timeout)
        while True:
            self._http.timeout = self._attempt_timeout(deadline, retries)
            var r: StreamedResponse
            try:
                r = self._http.stream("POST", url, h, Span(body), idle_timeout=self.stream_idle, total=self.stream_total)
            except e:
                if e.kind == ErrorKind.TimedOut and deadline.is_expired():
                    raise _timed_out(retries)
                if retryable_io(e) and retries < self.retry.max_retries:
                    if self._wait(backoff(self.retry, retries, self._jitter.next()), deadline):
                        retries += 1
                        continue
                raise self._io_error(e, retries)
            if r.status < 400:
                return r^
            r.limit_total(deadline)
            var errbody: List[UInt8]
            try:
                errbody = r.read_all(_MAX_ERROR_BODY)
            except:
                errbody = List[UInt8]()
            if retryable_status(r.status, r.headers) and retries < self.retry.max_retries:
                var d = wait_before_retry(self.retry, retries, r.headers, unix_time_ns() // 1_000_000_000, self._jitter.next())
                if self._wait(d, deadline):
                    retries += 1
                    continue
            raise self._error(r.status, r.headers, Span(errbody), retries)


struct ReplyStream(Movable):
    """A streamed reply (`Client.stream`): `next` gives its `Delta`s in
    order, the last one DONE; `reply()` is what has come so far, put
    together (after a failure, possibly part of the event that failed:
    trust it only when `complete()`)."""

    var _events: EventStream
    var _provider: Provider
    var _openai: ChunkDecoder
    var _anthropic: EventDecoder
    var _queue: List[Delta]
    var _at: Int
    var _ended: Bool
    var _ev: SseEvent
    var _request_id: String
    var _retries: Int
    var _max_reply: Int
    var _max_tool_calls: Int
    var _size: Int
    var _calls: Int
    var _failure: List[LlmError]
    """The first error (one element), raised again by every later `next`."""
    var _complete: Bool

    def __init__(
        out self, var events: EventStream, provider: Provider, request_id: String, retries: Int, max_reply: Int, max_tool_calls: Int
    ):
        self._events = events^
        self._provider = provider
        self._openai = ChunkDecoder()
        self._anthropic = EventDecoder()
        self._queue = List[Delta]()
        self._at = 0
        self._ended = False
        self._ev = SseEvent()
        self._request_id = request_id
        self._retries = retries
        self._max_reply = max_reply
        self._max_tool_calls = max_tool_calls
        self._size = 0
        self._calls = 0
        self._failure = List[LlmError]()
        self._complete = False

    def request_id(self) -> String:
        """The request id the stream's head carried ("" if none)."""
        return self._request_id

    def complete(self) -> Bool:
        """Whether the reply ended as the API ends one (DONE) and nothing
        failed."""
        return self._complete and len(self._failure) == 0

    def next(mut self, mut d: Delta) raises LlmError -> Bool:
        """The next delta into `d`; False after DONE. The stream's clean end
        before DONE raises PROTOCOL; a transport failure TRANSPORT; an error
        event API. The first error is raised again by every later call."""
        if len(self._failure) > 0:
            raise self._failure[0].copy()
        try:
            return self._next(d)
        except e:
            var err = e^
            if err.request_id.byte_length() == 0:
                err.request_id = self._request_id
            err.retries = self._retries
            self._failure.append(err.copy())
            self._queue.clear()
            self._at = 0
            self._ended = True
            raise err^

    def _next(mut self, mut d: Delta) raises LlmError -> Bool:
        while True:
            if self._at < len(self._queue):
                d = self._queue[self._at].copy()
                self._at += 1
                return True
            self._queue.clear()
            self._at = 0
            if self._ended:
                return False
            var got: Bool
            try:
                got = self._events.next(self._ev)
            except e:
                raise LlmError.transport(e)
            if not got:
                self._ended = True
                if self._provider == Provider.ANTHROPIC:
                    self._anthropic.finish()
                else:
                    self._openai.finish()
                return False
            var fresh = List[Delta]()
            if self._provider == Provider.ANTHROPIC:
                self._anthropic.feed(self._ev.data, fresh)
            else:
                self._openai.feed(self._ev.data, fresh)
            # (Counted before any of the event is given out: an event over a
            # bound fails whole.)
            for x in fresh:
                if x.kind == DeltaKind.TOOL_CALL:
                    self._calls += 1
                elif x.kind != DeltaKind.DONE:
                    self._size += x.text.byte_length()
                elif len(self._failure) == 0:
                    self._complete = True
            if self._size > self._max_reply:
                raise LlmError(LlmError.PROTOCOL, "llm: the reply is over max_reply bytes")
            if self._calls > self._max_tool_calls:
                raise LlmError(LlmError.PROTOCOL, "llm: the reply starts more than max_tool_calls calls")
            self._queue = fresh^
            self._ended = self._anthropic.done if self._provider == Provider.ANTHROPIC else self._openai.done

    def reply(self) -> Reply:
        """The reply put together from what has come so far."""
        if self._provider == Provider.ANTHROPIC:
            return self._anthropic.reply.copy()
        return self._openai.reply.copy()
