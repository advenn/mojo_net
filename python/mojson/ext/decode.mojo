"""A parsed `json.Document` made into Python objects, as Python's
json.loads makes them: dicts (or `object_hook`'s, `object_pairs_hook`'s
results), lists, str, int (any size), float, True, False and None.

- **Strings:** an ASCII string is made with `PyUnicode_New` and its bytes
  copied in (`Api.fast_str`); any other through `PyUnicode_DecodeUTF8`,
  with "surrogatepass" for the lone surrogates `Dialect.python` keeps.
- **Keys:** ASCII keys of up to 64 bytes are kept in a cache of 1,024
  str objects shared by every call (`KeyCache`), each with its hash
  computed once, so that an array of objects shares its keys, as json's
  per-call memo makes them share.
- **Numbers:** an integer of up to 18 digits is read here; a longer one
  through `PyLong_FromString` (with its digit limit); a float by
  `json.read_float` (Eisel-Lemire), or, for what that leaves (more than
  19 digits, subnormals), `PyOS_string_to_double`, as `float()` reads it
  (an overflow is an infinity, as in json). `parse_int`, `parse_float` and `parse_constant`
  get the number's text as a str.

The walk keeps its own stack (`Document.visit`), so no depth overflows
the C stack. On a failure the objects built so far are released and the
Python exception set stays set; `decode` returns 0."""

from std.bit import count_trailing_zeros
from std.memory import bitcast, pack_bits, unsafe_memcpy

from json import SPAN_SLACK, Document, Visitor, read_float

from .capi import Api, Obj, Addr, Buf, SURROGATEPASS, buf, cstr, str_data, str_length

comptime _CACHE = 1024
comptime _CACHE_MAX_KEY = 64

comptime _LIST: UInt8 = 0
comptime _DICT: UInt8 = 1
comptime _PAIRS: UInt8 = 2

comptime ApiPtr = Pointer[Api, MutUntrackedOrigin]


@inline(.always)
def _is_ascii(p: Pointer[UInt8, ImmutAnyOrigin], n: Int) -> Bool:
    """Whether a document span is ASCII: whole vectors, the bytes past it
    (`SPAN_SLACK`) masked off."""
    var i = 0
    while i < n:
        var bits = pack_bits[DType.uint32](p.unsafe_load[width=32](i).ge(SIMD[DType.uint8, 32](0x80)))
        if n - i < 32:
            bits &= (UInt32(1) << UInt32(n - i)) - 1
        if bits != 0:
            return False
        i += 32
    return True


@inline(.always)
def _word(p: Pointer[UInt8, ImmutAnyOrigin], i: Int, n: Int) -> UInt64:
    """The 8 bytes at `i` of a document span of `n` bytes, those past it
    zero (`SPAN_SLACK` makes the load safe)."""
    var w = bitcast[DType.uint64, 1](p.unsafe_load[width=8](i))
    if n - i < 8:
        w &= (UInt64(1) << UInt64(8 * (n - i))) - 1
    return w


@inline(.always)
def _key_hash(p: Pointer[UInt8, ImmutAnyOrigin], n: Int) -> UInt64:
    """A multiply-xorshift over the words of a key: only a cache slot's
    choice (and a quick check before the bytes are compared)."""
    var h: UInt64 = 0x9E3779B97F4A7C15 ^ UInt64(n)
    var i = 0
    while i < n:
        h = (h ^ _word(p, i, n)) * 0xBF58476D1CE4E5B9
        h ^= h >> 31
        i += 8
    return h


struct KeyCache(Movable):
    """ASCII keys of up to `_CACHE_MAX_KEY` bytes made into str objects,
    by a hash of their bytes: one object per slot, the cache holding a
    reference to each, and the key's bytes in a slot of their own (zero
    past the key), so that a lookup compares whole vectors."""

    var hashes: List[UInt64]
    var objs: List[Int]
    var bytes: List[UInt8]

    def __init__(out self):
        self.hashes = List[UInt64](length=_CACHE, fill=0)
        self.objs = List[Int](length=_CACHE, fill=0)
        self.bytes = List[UInt8](length=_CACHE * _CACHE_MAX_KEY, fill=0)


@fieldwise_init
struct Frame(Copyable, TrivialRegisterPassable):
    """An array or object being built."""

    var obj: Obj
    var key: Obj
    """An object's key waiting for its value (0: none)."""
    var index: Int
    """An array's (or pair list's) next slot."""
    var kind: UInt8


@inline(.always)
def _copy_in(dst: Buf, src: Pointer[UInt8, ImmutAnyOrigin], n: Int):
    """`n` bytes into a new str's characters: two overlapping words below
    16 bytes (no byte past `n` written), `unsafe_memcpy` above."""
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


struct DecState(Movable):
    """What a `Decoder` builds with: the stacks of the arrays and objects
    open, and the hooks."""

    var api: ApiPtr
    var cache: Pointer[KeyCache, MutUntrackedOrigin]
    var frames: List[Frame]
    """The arrays and objects open, innermost last."""
    var result: Obj
    var surrogates: Bool
    var object_hook: Obj
    var object_pairs_hook: Obj
    var parse_float: Obj
    var parse_int: Obj
    var parse_constant: Obj
    var num: List[UInt8]
    """A number's text with a NUL after it, for the C readers."""

    def __init__(out self, api: ApiPtr, cache: Pointer[KeyCache, MutUntrackedOrigin], surrogates: Bool):
        """`Codec` keeps one, and `reset`s it for each call, so that its
        stacks keep their room."""
        self.api = api
        self.cache = cache
        self.frames = List[Frame]()
        self.result = 0
        self.surrogates = surrogates
        self.object_hook = 0
        self.object_pairs_hook = 0
        self.parse_float = 0
        self.parse_int = 0
        self.parse_constant = 0
        self.num = List[UInt8]()

    def reset(mut self, api: ApiPtr, cache: Pointer[KeyCache, MutUntrackedOrigin]):
        """Ready for a new call, with no hooks."""
        self.api = api
        self.cache = cache
        self.frames.clear()
        self.result = 0
        self.object_hook = 0
        self.object_pairs_hook = 0
        self.parse_float = 0
        self.parse_int = 0
        self.parse_constant = 0


@fieldwise_init
struct Decoder(TrivialRegisterPassable, Visitor):
    """`Document.visit`'s visitor that builds the Python objects: one
    pointer to its `DecState` (see `encode.Encoder` for why)."""

    var s: Pointer[DecState, MutUntrackedOrigin]

    def release(self):
        """After a failure: drop everything built."""
        ref api = self.s[].api[]
        for f in self.s[].frames:
            api.Py_DecRef(f.obj)
            if f.key:
                api.Py_DecRef(f.key)
        if self.s[].result:
            api.Py_DecRef(self.s[].result)
        self.s[].frames.clear()
        self.s[].result = 0

    # ---- making values -----------------------------------------------------

    @inline(.always)
    def _check(self, o: Obj) raises -> Obj:
        if o == 0:
            raise Error("mojson: Python raised")
        return o

    @inline(.always)
    def make_str(self, text: Span[UInt8, ImmutAnyOrigin]) raises -> Obj:
        ref api = self.s[].api[]
        var n = len(text)
        var p = text.unsafe_ptr()
        if api.fast_str and _is_ascii(p, n):
            var o = self._check(api.PyUnicode_New(n, 127))
            _copy_in(buf(str_data(o)), p, n)
            return o
        return self._check(api.PyUnicode_DecodeUTF8(Int(p), n, cstr(SURROGATEPASS) if self.s[].surrogates else 0))

    @inline(.always)
    def make_key(self, text: Span[UInt8, ImmutAnyOrigin]) raises -> Obj:
        ref api = self.s[].api[]
        var n = len(text)
        var p = text.unsafe_ptr()
        if n > _CACHE_MAX_KEY or not api.fast_str or not _is_ascii(p, n):
            return self.make_str(text)
        var h = _key_hash(p, n)
        var slot = Int(h) & (_CACHE - 1)
        ref cache = self.s[].cache[]
        var objs = cache.objs.unsafe_ptr()
        var hashes = cache.hashes.unsafe_ptr()
        var kb = cache.bytes.unsafe_ptr().unsafe_offset(slot * _CACHE_MAX_KEY)
        var o = objs[unsafe_offset=slot]
        if o != 0 and hashes[unsafe_offset=slot] == h and str_length(o) == n:
            var same = True
            var i = 0
            while i < n:
                var v = p.unsafe_load[width=32](i)
                var w = kb.unsafe_load[width=32](i)
                var bits = pack_bits[DType.uint32](v.ne(w))
                if n - i < 32:
                    bits &= (UInt32(1) << UInt32(n - i)) - 1
                if bits != 0:
                    same = False
                    break
                i += 32
            if same:
                api.Py_IncRef(o)
                return o
        var made = self.make_str(text)
        if api.PyObject_Hash(made) == -1:
            api.Py_DecRef(made)
            raise Error("mojson: Python raised")
        if o != 0:
            api.Py_DecRef(o)
        objs[unsafe_offset=slot] = made
        hashes[unsafe_offset=slot] = h
        for k in range(_CACHE_MAX_KEY):
            kb[unsafe_offset=k] = p[unsafe_offset=k] if k < n else 0
        api.Py_IncRef(made)
        return made

    def _hook(self, hook: Obj, text: Span[UInt8, ImmutAnyOrigin]) raises -> Obj:
        """`hook(text)`, the text as a str."""
        ref api = self.s[].api[]
        var s = self.make_str(text)
        var r = api.PyObject_CallOneArg(hook, s)
        api.Py_DecRef(s)
        return self._check(r)

    def _cnum(self, text: Span[UInt8, ImmutAnyOrigin]) -> Addr:
        """The text, NUL-terminated, for C."""
        self.s[].num.clear()
        self.s[].num.extend(text)
        self.s[].num.append(0)
        return Int(self.s[].num.unsafe_ptr())

    # ---- putting values in place -------------------------------------------

    @inline(.always)
    def put(self, o: Obj) raises:
        """`o` (a new reference, given away) into the innermost open array
        or object, or as the result."""
        var depth = len(self.s[].frames)
        if depth == 0:
            self.s[].result = o
            return
        ref api = self.s[].api[]
        ref f = self.s[].frames.unsafe_ptr()[unsafe_offset=depth - 1]
        var kind = f.kind
        var top = f.obj
        if kind == _LIST:
            api.list_set(top, f.index, o)
            f.index += 1
        elif kind == _DICT:
            var k = f.key
            f.key = 0
            var r = api.PyDict_SetItem(top, k, o)
            api.Py_DecRef(k)
            api.Py_DecRef(o)
            if r < 0:
                raise Error("mojson: Python raised")
        else:
            var k = f.key
            f.key = 0
            var pair = api.PyTuple_New(2)
            if pair == 0:
                api.Py_DecRef(k)
                api.Py_DecRef(o)
                raise Error("mojson: Python raised")
            _ = api.PyTuple_SetItem(pair, 0, k)
            _ = api.PyTuple_SetItem(pair, 1, o)
            api.list_set(top, f.index, pair)
            f.index += 1

    @inline(.always)
    def _open(self, o: Obj, kind: UInt8):
        self.s[].frames.append(Frame(o, 0, 0, kind))

    @inline(.always)
    def _close(self) -> Tuple[Obj, UInt8]:
        var f = self.s[].frames.pop()
        return (f.obj, f.kind)

    # ---- the visitor ---------------------------------------------------------

    def null(mut self) raises:
        self.put(self.s[].api[].new_ref(self.s[].api[].none))

    def boolean(mut self, value: Bool) raises:
        ref api = self.s[].api[]
        self.put(api.new_ref(api.true if value else api.false))

    def number(mut self, text: Span[UInt8, ImmutAnyOrigin], integer: Bool) raises:
        ref api = self.s[].api[]
        var n = len(text)
        var p = text.unsafe_ptr()
        if integer:
            if self.s[].parse_int:
                self.put(self._hook(self.s[].parse_int, text))
                return
            if n <= 18:
                var neg = p[unsafe_offset=0] == 45
                var v = 0
                for i in range(1 if neg else 0, n):
                    v = v * 10 + Int(p[unsafe_offset=i] - 48)
                self.put(self._check(api.PyLong_FromLongLong(-v if neg else v)))
                return
            self.put(self._check(api.PyLong_FromString(self._cnum(text), 0, 10)))
            return
        if p[unsafe_offset=n - 1] > 57:  # NaN, Infinity, -Infinity
            if self.s[].parse_constant:
                self.put(self._hook(self.s[].parse_constant, text))
                return
            var x: Float64 = FloatLiteral.nan
            if p[unsafe_offset=0] == 73:
                x = FloatLiteral.infinity
            elif p[unsafe_offset=0] == 45:
                x = FloatLiteral.negative_infinity
            self.put(self._check(api.PyFloat_FromDouble(x)))
            return
        if self.s[].parse_float:
            self.put(self._hook(self.s[].parse_float, text))
            return
        var x: Float64 = 0
        if not read_float[padded=True](text, x):  # (more than 19 digits, subnormals; SPAN_SLACK)
            x = api.PyOS_string_to_double(self._cnum(text), 0, 0)
            if x == -1.0 and api.PyErr_Occurred():
                raise Error("mojson: Python raised")
        self.put(self._check(api.PyFloat_FromDouble(x)))

    def string(mut self, text: Span[UInt8, ImmutAnyOrigin]) raises:
        self.put(self.make_str(text))

    def key(mut self, text: Span[UInt8, ImmutAnyOrigin]) raises:
        var k = self.make_key(text)
        self.s[].frames.unsafe_ptr()[unsafe_offset=len(self.s[].frames) - 1].key = k

    def begin_array(mut self, count: Int) raises:
        self._open(self._check(self.s[].api[].PyList_New(count)), _LIST)

    def end_array(mut self) raises:
        var o = self._close()[0]
        self.put(o)

    def begin_object(mut self, count: Int) raises:
        if self.s[].object_pairs_hook:
            self._open(self._check(self.s[].api[].PyList_New(count)), _PAIRS)
        else:
            self._open(self._check(self.s[].api[].new_dict(count)), _DICT)

    def end_object(mut self) raises:
        ref api = self.s[].api[]
        var c = self._close()
        var o = c[0]
        var hook = self.s[].object_pairs_hook if c[1] == _PAIRS else self.s[].object_hook
        if hook:
            var r = api.PyObject_CallOneArg(hook, o)
            api.Py_DecRef(o)
            o = self._check(r)
        self.put(o)


def decode(var dec: Decoder, doc: Document) -> Obj:
    """The document's root as a new reference, or 0 with a Python
    exception set."""
    try:
        doc.visit(dec)
    except:
        dec.release()
        return 0
    var r = dec.s[].result
    dec.s[].result = 0
    return r
