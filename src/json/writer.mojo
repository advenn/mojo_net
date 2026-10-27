"""`Writer`: JSON text built call by call, compact, its structure checked as
it goes: a key where a value is due, a value where a key is due, a second
root value, a close that does not match, or `take()` before the text is
complete, each raise USAGE, and so do the values JSON cannot hold (NaN,
the infinities, strings that are not UTF-8). What `take()` returns is
therefore always one complete JSON value.

    var w = Writer()
    w.begin_object()
    w.key("model"); w.string("m")
    w.key("messages"); w.begin_array()
    w.begin_object(); w.key("role"); w.string("user"); w.end_object()
    w.end_array()
    w.key("temperature"); w.float(0.2)
    w.end_object()
    var body = w.take()   # {"model":"m","messages":[{"role":"user"}],"temperature":0.2}

Strings are written as themselves, except '"', '\\' and the control
characters (the short escapes where JSON has them, \\u00XX for the rest);
floats as `write_float` writes them (shortest round-trip).
"""

from .document import Document
from .error import JsonError
from .ryu import write_float
from .text import write_quoted

comptime _ARRAY: UInt8 = 0
comptime _OBJECT: UInt8 = 1


struct Writer(Movable):
    """JSON text, built call by call (see the module docs)."""

    var _out: List[UInt8]
    var _open: List[UInt8]
    """The arrays and objects open, innermost last."""
    var _first: Bool
    """Nothing is written yet in the innermost open array or object."""
    var _after_key: Bool
    """In an object: a key is written, its value is due."""
    var _done: Bool
    """The root value is complete."""

    def __init__(out self, capacity: Int = 0):
        self._out = List[UInt8](capacity=capacity)
        self._open = List[UInt8]()
        self._first = True
        self._after_key = False
        self._done = False

    def clear(mut self):
        """Start again, keeping the buffer's capacity."""
        self._out.clear()
        self._open.clear()
        self._first = True
        self._after_key = False
        self._done = False

    def is_complete(self) -> Bool:
        """Whether the text is one complete value."""
        return self._done

    def as_bytes(self) -> Span[UInt8, origin_of(self._out)]:
        """The text so far."""
        return Span(self._out)

    def take(mut self) raises JsonError -> List[UInt8]:
        """The text, once complete; the writer starts again, empty."""
        if not self._done:
            raise JsonError(JsonError.USAGE, "json: the text is not complete")
        var out = List[UInt8]()
        swap(out, self._out)
        self.clear()
        return out^

    # ---- structure ---------------------------------------------------------

    @inline(.always)
    def _value(mut self) raises JsonError:
        """Before a value: check one is due here, and write its comma."""
        var depth = len(self._open)
        if depth == 0:
            if self._done:
                raise JsonError(JsonError.USAGE, "json: the text already holds its one value")
            self._done = True  # (so it is complete once this value is)
            return
        if self._open[depth - 1] == _OBJECT:
            if not self._after_key:
                raise JsonError(JsonError.USAGE, "json: a key is due, not a value")
            self._after_key = False
            return
        if not self._first:
            self._out.append(44)  # ','
        self._first = False

    def key(mut self, name: StringSlice) raises JsonError:
        """An object's key; its value comes next."""
        var depth = len(self._open)
        if depth == 0 or self._open[depth - 1] != _OBJECT or self._after_key:
            raise JsonError(JsonError.USAGE, "json: a key is not due here")
        var mark = len(self._out)
        if not self._first:
            self._out.append(44)
        if not write_quoted(self._out, name.as_bytes(), validate=True):
            self._out.resize(mark, 0)
            raise JsonError(JsonError.USAGE, "json: a key is not UTF-8")
        self._out.append(58)  # ':'
        self._first = False
        self._after_key = True

    def begin_object(mut self) raises JsonError:
        self._begin(_OBJECT, 123)

    def begin_array(mut self) raises JsonError:
        self._begin(_ARRAY, 91)

    def _begin(mut self, kind: UInt8, byte: UInt8) raises JsonError:
        self._value()
        self._out.append(byte)
        self._open.append(kind)
        self._first = True
        self._done = False

    def end_object(mut self) raises JsonError:
        self._end(_OBJECT, 125)

    def end_array(mut self) raises JsonError:
        self._end(_ARRAY, 93)

    def _end(mut self, kind: UInt8, byte: UInt8) raises JsonError:
        var depth = len(self._open)
        if depth == 0 or self._open[depth - 1] != kind:
            raise JsonError(JsonError.USAGE, "json: no such array or object is open")
        if self._after_key:
            raise JsonError(JsonError.USAGE, "json: a key's value is due")
        _ = self._open.pop()
        self._out.append(byte)
        self._first = False
        self._done = len(self._open) == 0

    # ---- values ------------------------------------------------------------

    def string(mut self, s: StringSlice) raises JsonError:
        """A string; USAGE if `s` is not UTF-8 (a String built unchecked)."""
        var mark = len(self._out)
        var first = self._first
        var after_key = self._after_key
        var done = self._done
        self._value()
        if not write_quoted(self._out, s.as_bytes(), validate=True):
            self._out.resize(mark, 0)
            self._first = first
            self._after_key = after_key
            self._done = done
            raise JsonError(JsonError.USAGE, "json: a string is not UTF-8")

    def int(mut self, v: Int) raises JsonError:
        self._value()
        if v < 0:
            self._out.append(45)
        var u = UInt64(v) if v >= 0 else UInt64(0) - UInt64(v)
        var digits = Array[UInt8, 20](fill=0)
        var k = 20
        while True:
            k -= 1
            var q = u // 10
            digits[k] = UInt8(48) + UInt8(u - 10 * q)
            u = q
            if u == 0:
                break
        self._out.extend(Span(digits)[k:])

    def float(mut self, x: Float64) raises JsonError:
        """The shortest text that reads back as `x`; USAGE for NaN and the
        infinities, which JSON cannot hold."""
        if x != x or x - x != 0:
            raise JsonError(JsonError.USAGE, "json: NaN and the infinities have no JSON form")
        self._value()
        write_float(self._out, x)

    def bool(mut self, v: Bool) raises JsonError:
        self._value()
        self._out.extend(("true" if v else "false").as_bytes())

    def null(mut self) raises JsonError:
        self._value()
        self._out.extend("null".as_bytes())

    def document(mut self, doc: Document, n: Int = 0) raises JsonError:
        """Node `n` of `doc` and everything in it, as one value."""
        _ = doc.kind(n)  # (MISSING before anything is written)
        self._value()
        doc.write_json(n, self._out)
