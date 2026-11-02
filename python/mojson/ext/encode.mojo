"""Python objects written as JSON text, byte for byte as the standard
library's json.dumps writes them (its C encoder, `_json.c`), rule by rule:

- None, True, False; str (subclasses too); int (subclasses as
  `int.__repr__` writes them, not their own `__repr__`); float
  (subclasses too) as `float.__repr__`, NaN and the infinities as `NaN`,
  `Infinity`, `-Infinity`, or ValueError without `allow_nan`; list and
  tuple (and subclasses, by their items); dict (and subclasses, through
  their `items()`); anything else through `default`, or TypeError.
- Keys: str; float, True, False, None and int converted as json converts
  them; others skipped with `skipkeys`, else TypeError. `sort_keys` sorts
  the items as `list.sort` does.
- Strings: `"`, `\\` and the control characters escaped (the short forms
  where JSON has them, `\\u00XX` for the rest); with `ensure_ascii` also
  DEL and every non-ASCII character, as `\\uXXXX` (a surrogate pair past
  U+FFFF), lowercase.
- `indent` and the separators as given; circular references found
  (`check_circular`) as ValueError; nesting bounded by the interpreter's
  recursion limit (`Py_EnterRecursiveCall`), as json's is.

Floats are written from Ryū's shortest digits (`json.ryu.shortest`) in
the layout of `float.__repr__`: plain digits from 1e-4 up to 1e16, an
exponent of at least two digits outside (`1e-05`, `1e+16`), `.0` after
an integer. Text is built as UTF-8 in one buffer (lone surrogates as
WTF-8, which the str is decoded from with "surrogatepass")."""

from std.bit import count_leading_zeros, count_trailing_zeros
from std.memory import pack_bits, unsafe_memcpy

from json.ryu import shortest

from .capi import (
    Api,
    Obj,
    TPFLAGS_DICT,
    TPFLAGS_LIST,
    TPFLAGS_LONG,
    TPFLAGS_TUPLE,
    TPFLAGS_UNICODE,
    buf,
    cstr,
    out,
    load_int,
    str_data,
    str_is_ascii,
    str_kind,
    str_length,
)

comptime ApiPtr = Pointer[Api, MutUntrackedOrigin]
comptime _HEX = "0123456789abcdef"


struct Options(Copyable, Movable):
    """json.dumps's arguments, as the encoder reads them."""

    var skipkeys: Bool
    var ensure_ascii: Bool
    var check_circular: Bool
    var allow_nan: Bool
    var indent: List[UInt8]
    var has_indent: Bool
    var item_sep: List[UInt8]
    var key_sep: List[UInt8]
    var default: Obj
    """A callable, or 0."""
    var sort_keys: Bool

    def __init__(out self):
        """json.dumps's defaults."""
        self.skipkeys = False
        self.ensure_ascii = True
        self.check_circular = True
        self.allow_nan = True
        self.indent = List[UInt8]()
        self.has_indent = False
        self.item_sep = List[UInt8](", ".as_bytes())
        self.key_sep = List[UInt8](": ".as_bytes())
        self.default = 0
        self.sort_keys = False


@inline(.always)
def _plain_ascii_run(p: Pointer[UInt8, MutAnyOrigin], start: Int, n: Int, ensure_ascii: Bool) -> Int:
    """Where the first byte at or after `start` that a string must escape
    is (control, '"', '\\', and with `ensure_ascii` DEL and >= 0x80), or
    `n`."""
    var i = start
    while i + 32 <= n:
        var v = p.unsafe_load[width=32](i)
        var special = (
            v.lt(SIMD[DType.uint8, 32](0x20)) | v.eq(SIMD[DType.uint8, 32](34)) | v.eq(SIMD[DType.uint8, 32](92))
        )
        if ensure_ascii:
            special = special | v.ge(SIMD[DType.uint8, 32](0x7F))
        var bits = pack_bits[DType.uint32](special)
        if bits != 0:
            return i + Int(count_trailing_zeros(bits))
        i += 32
    while i < n:
        var b = p[unsafe_offset=i]
        if b < 0x20 or b == 34 or b == 92 or (ensure_ascii and b >= 0x7F):
            return i
        i += 1
    return n


@inline(.always)
def _copy_small(dst: Pointer[UInt8, MutUntrackedOrigin], src: Pointer[UInt8, _], n: Int):
    """`n` bytes, reading no byte of `src` past them: two overlapping
    words below 16 bytes, `unsafe_memcpy` above."""
    if n >= 16:
        unsafe_memcpy(dest=dst, src=src, count=n)
    elif n >= 8:
        dst.unsafe_store(0, src.unsafe_load[width=8](0))
        dst.unsafe_store(n - 8, src.unsafe_load[width=8](n - 8))
    elif n >= 4:
        dst.unsafe_store(0, src.unsafe_load[width=4](0))
        dst.unsafe_store(n - 4, src.unsafe_load[width=4](n - 4))
    else:
        for k in range(n):
            dst[unsafe_offset=k] = src[unsafe_offset=k]


@inline(.always)
def _first_special(q: Pointer[UInt8, MutUntrackedOrigin], n: Int, high: Bool) -> Int:
    """`_plain_ascii_run` over our own buffer, which has 32 bytes to read
    past `n`: vectors only, the bytes past `n` masked off."""
    var i = 0
    while i < n:
        var v = q.unsafe_load[width=32](i)
        var special = (
            v.lt(SIMD[DType.uint8, 32](0x20)) | v.eq(SIMD[DType.uint8, 32](34)) | v.eq(SIMD[DType.uint8, 32](92))
        )
        if high:
            special = special | v.ge(SIMD[DType.uint8, 32](0x7F))
        var bits = pack_bits[DType.uint32](special)
        if n - i < 32:
            bits &= (UInt32(1) << UInt32(n - i)) - 1
        if bits != 0:
            return i + Int(count_trailing_zeros(bits))
        i += 32
    return n


struct Out(Movable):
    """The text being written: a list's buffer, written through a pointer.
    `reserve` makes room once (per string, per number); `put` and `copy`
    then write without checks, and `byte` and `bytes` check for
    themselves. While it is written, the list's length is its capacity,
    so that AddressSanitizer's container checks see no write past it;
    `finish` sets the length to the text's."""

    var list: List[UInt8]
    var p: Pointer[UInt8, MutUntrackedOrigin]
    var n: Int
    var cap: Int

    def __init__(out self, var list: List[UInt8]):
        self.list = list^
        self.list.clear()
        if self.list.capacity() < 256:
            self.list.reserve(256)
        self.list.resize(unsafe_uninit_length=self.list.capacity())
        self.p = self.list.unsafe_ptr().unsafe_origin_cast[MutUntrackedOrigin]()
        self.n = 0
        self.cap = self.list.capacity()

    @inline(.always)
    def reserve(mut self, k: Int):
        if self.n + k > self.cap:
            self._grow(k)

    @no_inline
    def _grow(mut self, k: Int):
        self.list.resize(unsafe_uninit_length=self.n)
        self.list.reserve(max(2 * self.cap, self.n + k))
        self.list.resize(unsafe_uninit_length=self.list.capacity())
        self.p = self.list.unsafe_ptr().unsafe_origin_cast[MutUntrackedOrigin]()
        self.cap = self.list.capacity()

    @inline(.always)
    def put(mut self, b: UInt8):
        """One byte, room reserved."""
        self.p[unsafe_offset=self.n] = b
        self.n += 1

    @inline(.always)
    def copy(mut self, src: Pointer[UInt8, _], count: Int):
        """`count` bytes, room reserved."""
        _copy_small(self.p.unsafe_offset(self.n), src, count)
        self.n += count

    @inline(.always)
    def byte(mut self, b: UInt8):
        self.reserve(1)
        self.put(b)

    @inline(.always)
    def bytes(mut self, s: Span[UInt8, _]):
        self.reserve(len(s))
        self.copy(s.unsafe_ptr(), len(s))

    def finish(mut self):
        self.list.resize(unsafe_uninit_length=self.n)


struct EncState(Movable):
    """What an `Encoder` writes into and keeps track of."""

    var api: ApiPtr
    var o: Out
    var path: List[Obj]
    """The lists, dicts and `default` arguments being written, outermost
    first (`check_circular`)."""
    var level: Int
    var wtf8: Bool
    """A lone surrogate was written (the text is WTF-8, not UTF-8)."""
    var int_repr: Obj
    """`int.__repr__`, for int subclasses."""
    var raw_type: Obj
    """A str subclass whose text is written as it is (0: none)."""
    var opts: Options

    def __init__(out self, api: ApiPtr, int_repr: Obj, raw_type: Obj, var buffer: List[UInt8], var opts: Options):
        self.api = api
        self.opts = opts^
        self.o = Out(buffer^)
        self.path = List[Obj]()
        self.level = 0
        self.wtf8 = False
        self.int_repr = int_repr
        self.raw_type = raw_type


@fieldwise_init
struct Encoder(TrivialRegisterPassable):
    """The writer: one pointer to its `EncState`. (A method that takes a
    larger struct as `mut self` and is not inlined gets the struct copied
    in and out on every call, in Mojo 1.2; through this pointer, a call
    passes one word.)"""

    var s: Pointer[EncState, MutUntrackedOrigin]

    @inline(.always)
    def _raised(self) raises:
        raise Error("mojson: Python raised")

    @inline(.always)
    def _put(self, s: StaticString):
        self.s[].o.bytes(s.as_bytes())

    # ---- scalars -------------------------------------------------------------

    def write_int(self, o: Obj) raises:
        """An exact int."""
        ref api = self.s[].api[]
        var overflow: Int32 = 0
        var v = api.PyLong_AsLongLongAndOverflow(o, out(overflow))
        if overflow == 0:
            if v == -1 and api.PyErr_Occurred():
                self._raised()
            self._digits(v)
            return
        var r = api.PyObject_Repr(o)
        if not r:
            self._raised()
        self._utf8_of(r)
        api.Py_DecRef(r)

    def write_int_subclass(self, o: Obj) raises:
        ref api = self.s[].api[]
        var r = api.PyObject_CallOneArg(self.s[].int_repr, o)
        if not r:
            self._raised()
        self._utf8_of(r)
        api.Py_DecRef(r)

    def _utf8_of(self, s: Obj) raises:
        """An ASCII str's text (a repr)."""
        ref api = self.s[].api[]
        var n = 0
        var p = api.PyUnicode_AsUTF8AndSize(s, out(n))
        if not p:
            self._raised()
        self.s[].o.bytes(Span[UInt8, MutAnyOrigin](unsafe_ptr=buf(p), length=n))

    @inline(.always)
    def _digits(self, v: Int):
        self.s[].o.reserve(21)
        if v < 0:
            self.s[].o.put(45)
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
        self.s[].o.copy(Span(digits).unsafe_ptr().unsafe_offset(k), 20 - k)

    def write_float(self, o: Obj, x: Float64, allow_nan: Bool) raises:
        """`x` (the value of float `o`) as `float.__repr__` writes it."""
        if x != x or x - x != 0:
            if not allow_nan:
                ref api = self.s[].api[]
                var r = api.PyObject_Repr(o)
                var msg = String("Out of range float values are not JSON compliant: ")
                if r:
                    var n = 0
                    var p = api.PyUnicode_AsUTF8AndSize(r, out(n))
                    if p:
                        msg += String(unsafe_from_utf8=Span[UInt8, MutAnyOrigin](unsafe_ptr=buf(p), length=n))
                    api.Py_DecRef(r)
                api.fail(api.ValueError, msg)
                self._raised()
            if x != x:
                self._put("NaN")
            elif x > 0:
                self._put("Infinity")
            else:
                self._put("-Infinity")
            return
        self.s[].o.reserve(32)
        write_py_float(self.s[].o, x)

    # ---- strings -------------------------------------------------------------

    @inline(.always)
    def _escape(self, c: UInt32):
        """A character json escapes: '"', '\\', a control character, or
        (ensure_ascii) DEL and any non-ASCII one, below U+10000."""
        self.s[].o.put(92)
        if c == 34 or c == 92:
            self.s[].o.put(UInt8(c))
        elif c == 10:
            self.s[].o.put(110)
        elif c == 13:
            self.s[].o.put(114)
        elif c == 9:
            self.s[].o.put(116)
        elif c == 8:
            self.s[].o.put(98)
        elif c == 12:
            self.s[].o.put(102)
        else:
            self.s[].o.put(117)
            var h = _HEX.as_bytes()
            self.s[].o.put(h[Int((c >> 12) & 15)])
            self.s[].o.put(h[Int((c >> 8) & 15)])
            self.s[].o.put(h[Int((c >> 4) & 15)])
            self.s[].o.put(h[Int(c & 15)])

    @inline(.always)
    def _char(self, c: UInt32, ensure_ascii: Bool):
        """One character of a str (room reserved: 12 bytes)."""
        if c < 0x80:
            if c < 0x20 or c == 34 or c == 92 or (ensure_ascii and c == 0x7F):
                self._escape(c)
            else:
                self.s[].o.put(UInt8(c))
        elif ensure_ascii:
            if c >= 0x10000:
                var v = c - 0x10000
                self._escape(0xD800 | (v >> 10))
                self._escape(0xDC00 | (v & 0x3FF))
            else:
                self._escape(c)
        elif c < 0x800:
            self.s[].o.put(UInt8(0xC0 | (c >> 6)))
            self.s[].o.put(UInt8(0x80 | (c & 0x3F)))
        elif c < 0x10000:
            if c >= 0xD800 and c <= 0xDFFF:
                self.s[].wtf8 = True
            self.s[].o.put(UInt8(0xE0 | (c >> 12)))
            self.s[].o.put(UInt8(0x80 | ((c >> 6) & 0x3F)))
            self.s[].o.put(UInt8(0x80 | (c & 0x3F)))
        else:
            self.s[].o.put(UInt8(0xF0 | (c >> 18)))
            self.s[].o.put(UInt8(0x80 | ((c >> 12) & 0x3F)))
            self.s[].o.put(UInt8(0x80 | ((c >> 6) & 0x3F)))
            self.s[].o.put(UInt8(0x80 | (c & 0x3F)))

    def write_str(self, s: Obj, ensure_ascii: Bool) raises:
        """A str (or subclass), quoted: room reserved for the worst case
        (each character 6 bytes, or 12 past U+FFFF), then written
        unchecked."""
        ref api = self.s[].api[]
        if api.fast_str:
            var n = str_length(s)
            var kind = str_kind(s)
            var d = str_data(s)
            self.s[].o.reserve((12 if kind == 4 else 6) * n + 34)
            self.s[].o.put(34)
            if kind == 1:
                # Copied whole, then scanned where it landed (32 bytes of
                # room past it); written again from the first character
                # that needs more than itself.
                var p = buf(d)
                var high = ensure_ascii or not str_is_ascii(s)
                var start = self.s[].o.n
                _copy_small(self.s[].o.p.unsafe_offset(start), p, n)
                var i = _first_special(self.s[].o.p.unsafe_offset(start), n, high)
                self.s[].o.n = start + i
                while i < n:
                    self._char(UInt32(p[unsafe_offset=i]), ensure_ascii)
                    i += 1
                    var j = _plain_ascii_run(p, i, n, high)
                    if j > i:
                        self.s[].o.copy(p.unsafe_offset(i), j - i)
                    i = j
            elif kind == 2:
                var p = Pointer[UInt16, MutAnyOrigin](unsafe_from_address=d)
                for i in range(n):
                    self._char(UInt32(p[unsafe_offset=i]), ensure_ascii)
            else:
                var p = Pointer[UInt32, MutAnyOrigin](unsafe_from_address=d)
                for i in range(n):
                    self._char(p[unsafe_offset=i], ensure_ascii)
            self.s[].o.put(34)
            return
        # Through the C API: the text as UTF-8 (WTF-8 for lone surrogates).
        var size = 0
        var p = api.PyUnicode_AsUTF8AndSize(s, out(size))
        var held: Obj = 0
        if not p:
            api.PyErr_Clear()
            held = api.PyUnicode_AsEncodedString(s, cstr("utf-8"), cstr("surrogatepass"))
            if not held:
                self._raised()
            p = api.PyBytes_AsString(held)
            size = api.PyBytes_Size(held)
        self.s[].o.reserve(6 * size + 2)
        self.s[].o.put(34)
        var b = buf(p)
        var i = 0
        while i < size:
            var c = UInt32(b[unsafe_offset=i])
            var k = 1
            if c >= 0xF0:
                c = ((c & 0x07) << 18) | ((UInt32(b[unsafe_offset=i + 1]) & 0x3F) << 12)
                c |= ((UInt32(b[unsafe_offset=i + 2]) & 0x3F) << 6) | (UInt32(b[unsafe_offset=i + 3]) & 0x3F)
                k = 4
            elif c >= 0xE0:
                c = ((c & 0x0F) << 12) | ((UInt32(b[unsafe_offset=i + 1]) & 0x3F) << 6)
                c |= UInt32(b[unsafe_offset=i + 2]) & 0x3F
                k = 3
            elif c >= 0xC0:
                c = ((c & 0x1F) << 6) | (UInt32(b[unsafe_offset=i + 1]) & 0x3F)
                k = 2
            self._char(c, ensure_ascii)
            i += k
        if held:
            api.Py_DecRef(held)
        self.s[].o.put(34)

    # ---- structure -------------------------------------------------------------

    @inline(.always)
    def _newline(self):
        ref opts = self.s[].opts
        self.s[].o.byte(10)
        for _ in range(self.s[].level):
            self.s[].o.bytes(Span(opts.indent))

    def _enter(self, o: Obj) raises:
        """Before a list, a dict or a `default` result: the recursion
        limit, and `o` not already being written."""
        ref opts = self.s[].opts
        ref api = self.s[].api[]
        if opts.check_circular:
            for p in self.s[].path:
                if p == o:
                    api.fail(api.ValueError, "Circular reference detected")
                    self._raised()
        if api.Py_EnterRecursiveCall(cstr(" while encoding a JSON object")) != 0:
            self._raised()
        if opts.check_circular:
            self.s[].path.append(o)

    def _leave(self):
        ref opts = self.s[].opts
        if opts.check_circular:
            _ = self.s[].path.pop()
        self.s[].api[].Py_LeaveRecursiveCall()

    def write(self, o: Obj) raises:
        """Any value."""
        ref opts = self.s[].opts
        ref api = self.s[].api[]
        if o == api.none:
            self._put("null")
            return
        if o == api.true:
            self._put("true")
            return
        if o == api.false:
            self._put("false")
            return
        var t = api.type_of(o)
        if t == api.str_type:
            self.write_str(o, opts.ensure_ascii)
            return
        if t == api.int_type:
            self.write_int(o)
            return
        if t == api.float_type:
            self.write_float(o, api.PyFloat_AsDouble(o), opts.allow_nan)
            return
        if t == api.list_type:
            self.write_list(o)
            return
        if t == api.dict_type:
            self.write_dict(o)
            return
        if t == api.tuple_type:
            self.write_list(o)
            return
        if t == self.s[].raw_type and t != 0:
            self._utf8_of(o)
            return
        var f = api.PyType_GetFlags(t)
        if f & TPFLAGS_UNICODE:
            self.write_str(o, opts.ensure_ascii)
        elif f & TPFLAGS_LONG:
            self.write_int_subclass(o)
        elif api.is_float(o):
            var x = api.PyFloat_AsDouble(o)
            if x == -1.0 and api.PyErr_Occurred():
                self._raised()
            self.write_float(o, x, opts.allow_nan)
        elif f & (TPFLAGS_LIST | TPFLAGS_TUPLE):
            self.write_list(o)
        elif f & TPFLAGS_DICT:
            self.write_dict(o)
        else:
            self.write_default(o)

    def write_default(self, o: Obj) raises:
        ref opts = self.s[].opts
        ref api = self.s[].api[]
        if not opts.default:
            api.fail(api.TypeError, String("Object of type ", api.type_name(o), " is not JSON serializable"))
            self._raised()
        self._enter(o)
        var r = api.PyObject_CallOneArg(opts.default, o)
        if not r:
            self._leave()
            self._raised()
        try:
            self.write(r)
        except e:
            api.Py_DecRef(r)
            self._leave()
            raise e^
        api.Py_DecRef(r)
        self._leave()

    def write_list(self, o: Obj) raises:
        """A list or tuple (or subclass), by its items."""
        ref opts = self.s[].opts
        ref api = self.s[].api[]
        var seq = api.PySequence_Fast(o, cstr(""))
        if not seq:
            self._raised()
        var is_list = api.type_of(seq) == api.list_type or (api.flags(seq) & TPFLAGS_LIST) != 0
        var n = load_int(seq + 16)  # (ob_size)
        if n == 0:
            api.Py_DecRef(seq)
            self._put("[]")
            return
        try:
            self._enter(o)
        except e:
            api.Py_DecRef(seq)
            raise e^
        self.s[].o.byte(91)
        if opts.has_indent:
            self.s[].level += 1
            self._newline()
        var i = 0
        while i < load_int(seq + 16):
            if i > 0:
                self.s[].o.bytes(Span(opts.item_sep))
                if opts.has_indent:
                    self._newline()
            var item = api.PyList_GetItem(seq, i) if is_list else api.PyTuple_GetItem(seq, i)
            api.Py_IncRef(item)
            try:
                self.write(item)
            except e:
                api.Py_DecRef(item)
                api.Py_DecRef(seq)
                self._leave()
                raise e^
            api.Py_DecRef(item)
            i += 1
        if opts.has_indent:
            self.s[].level -= 1
            self._newline()
        self.s[].o.byte(93)
        api.Py_DecRef(seq)
        self._leave()

    def _key(self, k: Obj) raises -> Bool:
        """A key, as json converts it; False to skip it (`skipkeys`)."""
        ref opts = self.s[].opts
        ref api = self.s[].api[]
        var t = api.type_of(k)
        if t == api.str_type or (api.PyType_GetFlags(t) & TPFLAGS_UNICODE) != 0:
            self.write_str(k, opts.ensure_ascii)
            return True
        var mark = self.s[].o.n
        self.s[].o.byte(34)
        if api.is_float(k):
            self.write_float(k, api.PyFloat_AsDouble(k), opts.allow_nan)
        elif k == api.true:
            self._put("true")
        elif k == api.false:
            self._put("false")
        elif k == api.none:
            self._put("null")
        elif t == api.int_type:
            self.write_int(k)
        elif (api.PyType_GetFlags(t) & TPFLAGS_LONG) != 0:
            self.write_int_subclass(k)
        elif opts.skipkeys:
            self.s[].o.n = mark
            return False
        else:
            self.s[].o.n = mark
            api.fail(api.TypeError, String("keys must be str, int, float, bool or None, not ", api.tp_name(k)))
            self._raised()
        self.s[].o.byte(34)
        return True

    def _pair(self, k: Obj, v: Obj, mut first: Bool) raises:
        """One pair: the separator (with the indent's line) unless first,
        then the key (or nothing at all, the key skipped) and the value."""
        ref opts = self.s[].opts
        var mark = self.s[].o.n
        if not first:
            self.s[].o.bytes(Span(opts.item_sep))
            if opts.has_indent:
                self._newline()
        if not self._key(k):
            self.s[].o.n = mark
            return
        first = False
        self.s[].o.bytes(Span(opts.key_sep))
        self.write(v)

    def write_dict(self, o: Obj) raises:
        """A dict (or subclass): an exact one by `PyDict_Next`, unless
        sorted; others by their `items()`, as json does."""
        ref opts = self.s[].opts
        ref api = self.s[].api[]
        var exact = api.type_of(o) == api.dict_type
        if api.PyDict_Size(o) == 0:
            self._put("{}")
            return
        self._enter(o)
        self.s[].o.byte(123)
        if opts.has_indent:
            self.s[].level += 1
            self._newline()
        var first = True
        try:
            if exact and not opts.sort_keys:
                var pos = 0
                var k: Obj = 0
                var v: Obj = 0
                while api.PyDict_Next(o, out(pos), out(k), out(v)) != 0:
                    api.Py_IncRef(k)
                    api.Py_IncRef(v)
                    try:
                        self._pair(k, v, first)
                    except e:
                        api.Py_DecRef(k)
                        api.Py_DecRef(v)
                        raise e^
                    api.Py_DecRef(k)
                    api.Py_DecRef(v)
            else:
                var items = api.PyMapping_Items(o)
                if not items:
                    self._raised()
                if opts.sort_keys and api.PyList_Sort(items) < 0:
                    api.Py_DecRef(items)
                    self._raised()
                var i = 0
                while i < load_int(items + 16):
                    var item = api.PyList_GetItem(items, i)
                    var k = api.PyTuple_GetItem(item, 0)
                    var v = api.PyTuple_GetItem(item, 1)
                    if not k or not v:
                        api.Py_DecRef(items)
                        self._raised()
                    try:
                        self._pair(k, v, first)
                    except e:
                        api.Py_DecRef(items)
                        raise e^
                    i += 1
                api.Py_DecRef(items)
        except e:
            self._leave()
            raise e^
        if opts.has_indent:
            self.s[].level -= 1
            self._newline()
        self.s[].o.byte(125)
        self._leave()


comptime _DIGIT_PAIRS = "00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899"
"""The two-digit decimal strings 00 to 99, for writing digits in pairs."""

comptime _POW10: Array[UInt64, 20] = [
    1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 10000000000, 100000000000,
    1000000000000, 10000000000000, 100000000000000, 1000000000000000, 10000000000000000,
    100000000000000000, 1000000000000000000, 10000000000000000000,
]


@inline(.always)
def _digits_into(dst: Pointer[UInt8, MutUntrackedOrigin], v0: UInt64, n: Int):
    """The `n` decimal digits of `v0` at `dst`, two at a time from the
    right."""
    var pairs = _DIGIT_PAIRS.as_bytes().unsafe_ptr()
    var v = v0
    var k = n
    while k >= 2:
        var q = v // 100
        var r = Int(v - 100 * q)
        dst[unsafe_offset=k - 2] = pairs[unsafe_offset=2 * r]
        dst[unsafe_offset=k - 1] = pairs[unsafe_offset=2 * r + 1]
        v = q
        k -= 2
    if k == 1:
        dst[unsafe_offset=0] = UInt8(48) + UInt8(v)


def write_py_float(mut out: Out, x: Float64):
    """Finite `x` as `float.__repr__` writes it: the shortest digits
    that read back as `x`, plain from 1e-4 up to 1e16 (with `.0` after an
    integer), else with an exponent of at least two digits. (32 bytes of
    room reserved: at most 17 digits, a sign, a point and an exponent.)"""
    var s = shortest(x)
    if s.negative:
        out.put(45)
    if s.digits == 0:
        out.put(48)
        out.put(46)
        out.put(48)
        return
    # Digits: from the bit length (log10(2) ~ 1233 / 4096), then one
    # comparison with the power of ten it may have missed.
    var bits = 64 - Int(count_leading_zeros(s.digits))
    var n = (bits * 1233) >> 12  # (at most 19)
    if s.digits >= materialize[_POW10]().unsafe_get(n):
        n += 1
    var tmp = Array[UInt8, 24](uninitialized=True)
    var t = tmp.unsafe_ptr().unsafe_origin_cast[MutUntrackedOrigin]()
    _digits_into(t, s.digits, n)
    var decpt = n + s.exponent
    if decpt <= -4 or decpt > 16:
        out.put(t[unsafe_offset=0])
        if n > 1:
            out.put(46)
            out.copy(t.unsafe_offset(1), n - 1)
        out.put(101)
        var e = decpt - 1
        out.put(UInt8(45) if e < 0 else UInt8(43))
        var a = -e if e < 0 else e
        var en = 2 if a < 100 else 3
        _digits_into(out.p.unsafe_offset(out.n), UInt64(a), en)
        out.n += en
        return
    if decpt <= 0:
        out.put(48)
        out.put(46)
        for _ in range(-decpt):
            out.put(48)
        out.copy(t, n)
    elif decpt >= n:
        out.copy(t, n)
        for _ in range(decpt - n):
            out.put(48)
        out.put(46)
        out.put(48)
    else:
        out.copy(t, decpt)
        out.put(46)
        out.copy(t.unsafe_offset(decpt), n - decpt)
