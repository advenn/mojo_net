"""What both APIs' modules share: `Reader`, which reads a response's JSON
without raising for each field (a missing or null field reads as empty, one
of the wrong type marks the reply bad), and the writers for JSON given as
text (tool schemas, extra fields)."""

from json import Document, JsonError, Kind, Writer, parse

from .error import LlmError


struct Reader(Movable):
    """A parsed response. Accessors return "", 0 or -1 for a field that is
    absent or null; a field of another kind sets `bad` (and `problem`),
    which the caller turns into one PROTOCOL error."""

    var doc: Document
    var bad: Bool
    var problem: String

    def __init__(out self, body: Span[UInt8, _]) raises LlmError:
        try:
            self.doc = parse(body)
        except e:
            raise LlmError(LlmError.PROTOCOL, String("llm: the response is not JSON: ", e))
        self.bad = False
        self.problem = String()

    def _fail(mut self, key: StringSlice):
        if not self.bad:
            self.bad = True
            self.problem = String("llm: unexpected type for the field ", repr(String(key)))

    def check(self) raises LlmError:
        if self.bad:
            raise LlmError(LlmError.PROTOCOL, self.problem)

    def kind(self, n: Int) -> Kind:
        try:
            return self.doc.kind(n)
        except:
            return Kind.NULL

    def get(mut self, n: Int, key: StringSlice) -> Int:
        """The value of `key` in object `n`, or -1 (absent, or null)."""
        if n < 0:
            return -1
        try:
            if self.doc.kind(n) != Kind.OBJECT:
                self._fail(key)
                return -1
            var v = self.doc.get(n, key)
            if not v or self.doc.is_null(v.value()):
                return -1
            return v.value()
        except:
            self._fail(key)
            return -1

    def str(mut self, n: Int, key: StringSlice) -> String:
        var v = self.get(n, key)
        if v < 0:
            return String()
        try:
            if self.doc.kind(v) == Kind.STRING:
                return self.doc.text(v)
        except:
            pass
        self._fail(key)
        return String()

    def int(mut self, n: Int, key: StringSlice, default: Int = -1) -> Int:
        var v = self.get(n, key)
        if v < 0:
            return default
        try:
            return self.doc.int(v)
        except:
            self._fail(key)
            return default

    def array(mut self, n: Int, key: StringSlice) -> Int:
        """The array at `key` (-1 when absent or null; bad if not an array)."""
        var v = self.get(n, key)
        if v < 0:
            return -1
        if self.kind(v) != Kind.ARRAY:
            self._fail(key)
            return -1
        return v

    def object(mut self, n: Int, key: StringSlice) -> Int:
        var v = self.get(n, key)
        if v < 0:
            return -1
        if self.kind(v) != Kind.OBJECT:
            self._fail(key)
            return -1
        return v

    def count(self, n: Int) -> Int:
        if n < 0:
            return 0
        try:
            return self.doc.count(n)
        except:
            return 0

    def first(self, n: Int) -> Int:
        """The first element of array `n` (call only when `count(n) > 0`)."""
        return n + 1

    def next(self, n: Int) -> Int:
        try:
            return self.doc.next(n)
        except:
            return -1

    def json(self, n: Int) -> String:
        try:
            return self.doc.json(n)
        except:
            return String()

    def arguments(mut self, n: Int, key: StringSlice) -> String:
        """A tool call's arguments: a string as it is, or an object (as
        TGI 2.3 and earlier send them) as its JSON text."""
        var v = self.get(n, key)
        if v < 0:
            return String()
        var k = self.kind(v)
        if k == Kind.STRING:
            return self.str(n, key)
        if k == Kind.OBJECT:
            return self.json(v)
        self._fail(key)
        return String()


comptime MAX_MESSAGE = 4096
"""The most of a server's error message kept in an `LlmError`."""


def clip(s: String) -> String:
    """`s`, cut to `MAX_MESSAGE` bytes at a character boundary."""
    var b = s.as_bytes()
    if len(b) <= MAX_MESSAGE:
        return s
    var end = MAX_MESSAGE
    while end > 0 and (b[end] & 0xC0) == 0x80:
        end -= 1
    return String(unsafe_from_utf8=b[:end]) + "..."


def write_object_text(mut w: Writer, text: StringSlice) raises JsonError:
    """`text`, which must be one JSON object, as the next value."""
    var doc: Document
    try:
        doc = parse(text)
    except:
        raise JsonError(JsonError.USAGE, "llm: a tool's schema or arguments are not a JSON object")
    if doc.kind() != Kind.OBJECT:
        raise JsonError(JsonError.USAGE, "llm: a tool's schema or arguments are not a JSON object")
    w.document(doc)


def write_extra(mut w: Writer, extra: StringSlice, taken: List[String]) raises JsonError:
    """The members of `extra` (a JSON object's text, or empty), each a
    top-level field; one of the `taken` fields is refused."""
    if extra.byte_length() == 0:
        return
    var doc: Document
    try:
        doc = parse(extra)
    except:
        raise JsonError(JsonError.USAGE, "llm: the extra fields are not a JSON object")
    if doc.kind() != Kind.OBJECT:
        raise JsonError(JsonError.USAGE, "llm: the extra fields are not a JSON object")
    var k = 1
    for _ in range(doc.count()):
        var name = doc.text(k)
        for t in taken:
            if t == name:
                raise JsonError(JsonError.USAGE, "llm: an extra field is one the request sets itself")
        w.key(name)
        w.document(doc, k + 1)
        k = doc.next(k + 1)


def usage_error(e: JsonError) -> LlmError:
    return LlmError(LlmError.USAGE, String(e))
