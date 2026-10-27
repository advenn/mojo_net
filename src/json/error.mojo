"""`JsonError`: what went wrong, of which kind, and where in the input."""


struct JsonError(Copyable, Movable, Writable):
    """Raised by everything in `json`. `kind` is one of the constants
    below; `offset` is the input's byte where parsing stopped, or -1 when
    the error is not about input."""

    comptime SYNTAX = 1
    """The input is not JSON text (RFC 8259), or not UTF-8."""
    comptime LIMIT = 2
    """The input is over one of the parser's `Limits`."""
    comptime TYPE = 3
    """A node is of another kind than the one asked for."""
    comptime MISSING = 4
    """No such node, element or key."""
    comptime RANGE = 5
    """A number does not fit the type asked for."""
    comptime USAGE = 6
    """A `Writer` call out of place, or a value JSON cannot hold (NaN, an
    infinity, bytes that are not UTF-8)."""

    var kind: Int
    var message: StaticString
    var offset: Int

    def __init__(out self, kind: Int, message: StaticString, offset: Int = -1):
        self.kind = kind
        self.message = message
        self.offset = offset

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.message)
        if self.offset >= 0:
            writer.write(" (at byte ", self.offset, ")")
