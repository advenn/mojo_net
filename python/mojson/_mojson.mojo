"""The `mojson` extension module: one type, `Codec`, whose methods are the
fast paths of `mojson.loads` and `mojson.dumps` (python/mojson/__init__.py
binds one instance's methods as the module's functions). A `Codec` holds
the C API (`capi.Api`), a `json.Document` reused by every parse, and the
key cache, so that a call allocates only the objects it returns.

Whatever the fast paths do not take (keyword arguments they do not read,
input that is not UTF-8 text, and every input `json.Document` refuses)
goes to the Python fallbacks `set_fallbacks` installs, which end in the
standard library's json: results and errors are then json's own."""

from std.os import abort
from std.python import Python, PythonObject
from std.python._cpython import PyObjectPtr
from std.python.bindings import PyMojoObject, PythonModuleBuilder

from json import MAX_SIZE, Dialect, Document, JsonError, Limits

from std.memory import unsafe_memcpy

from ext.capi import Api, Obj, Addr, SURROGATEPASS, buf, cstr, load_int, out, str_data
from ext.decode import DecState, Decoder, KeyCache, decode
from ext.encode import EncState, Encoder, Options

comptime _MAX_DEPTH = 512
"""Nesting the fast path parses; deeper text goes to json, which allows
what the interpreter's recursion limit allows."""


struct Codec(Movable, Writable):
    var api: Api
    var doc: Document
    var cache: KeyCache
    var dec: DecState
    """Reused by every loads (`decoder`)."""
    var fallback: Obj
    """The standard library's json.loads, for what the fast path leaves."""
    var kw_fallback: Obj
    """The loads of python/mojson that reads keyword arguments."""
    var dumps_fallback: Obj
    """The dumps of python/mojson that reads keyword arguments."""
    var parse_error: Obj
    """The exception of python/mojson for a refused text (`rfc8259`): its
    arguments are the reason and the byte offset."""
    var int_repr: Obj
    var raw_type: Obj
    """The `_Raw` of python/mojson: text written as it is (a Decimal's
    digits)."""
    var out: List[UInt8]
    """The text `dumps` builds, reused."""

    def __init__(out self) raises:
        self.api = Api()
        self.doc = Document()
        self.cache = KeyCache()
        self.dec = DecState(
            Pointer(to=self.api).unsafe_origin_cast[MutUntrackedOrigin](),
            Pointer(to=self.cache).unsafe_origin_cast[MutUntrackedOrigin](),
            True,
        )
        self.fallback = 0
        self.kw_fallback = 0
        self.dumps_fallback = 0
        self.parse_error = 0
        self.raw_type = 0
        self.int_repr = self.api.PyObject_GetAttrString(self.api.int_type, cstr("__repr__"))
        if not self.int_repr:
            raise Error("mojson: int.__repr__ is missing")
        self.out = List[UInt8]()

    @staticmethod
    def py_init(out self: Codec, args: PythonObject, kwargs: PythonObject) raises:
        self = Codec()

    def write_to(self, mut writer: Some[Writer]):
        writer.write("<mojson.Codec>")

    def write_repr_to(self, mut writer: Some[Writer]):
        self.write_to(writer)

    def decoder(mut self) -> Decoder:
        """The decoder, reset for a call (its pointers set again: the Codec
        moved into its Python object after it was made)."""
        self.dec.reset(
            Pointer(to=self.api).unsafe_origin_cast[MutUntrackedOrigin](),
            Pointer(to=self.cache).unsafe_origin_cast[MutUntrackedOrigin](),
        )
        return Decoder(Pointer(to=self.dec).unsafe_origin_cast[MutUntrackedOrigin]())


@inline(.always)
def _codec(py_self: PyObjectPtr) -> Pointer[Codec, MutAnyOrigin]:
    ref value = py_self.bitcast[PyMojoObject[Codec]]().unsafe_value()[].mojo_value
    return Pointer(to=value).unsafe_origin_cast[MutAnyOrigin]()


@inline(.always)
def _ptr(o: Obj) -> PyObjectPtr:
    var x = o
    return Pointer(to=x).unsafe_bitcast[PyObjectPtr]()[]


@inline(.always)
def _obj(p: PyObjectPtr) -> Obj:
    return Int(p)


def _text(ref api: Api, s: Obj, mut ptr: Addr, mut size: Int) -> Bool:
    """`s`'s bytes when the fast path can read them as UTF-8 text: a str
    (its UTF-8 form), or bytes or a bytearray that json would decode as
    UTF-8 (no byte order mark, no NUL among the first four bytes)."""
    var t = api.type_of(s)
    if t == api.str_type or (api.flags(s) & UInt64(1 << 28)) != 0:
        var n = 0
        var p = api.PyUnicode_AsUTF8AndSize(s, out(n))
        if p == 0:  # (lone surrogates: json's way)
            api.PyErr_Clear()
            return False
        ptr = p
        size = n
        return True
    if t == api.bytes_type:
        ptr = api.PyBytes_AsString(s)
        size = api.PyBytes_Size(s)
    elif t == api.bytearray_type:
        ptr = api.PyByteArray_AsString(s)
        size = api.PyByteArray_Size(s)
    else:
        return False
    var b = buf(ptr)
    if size > 0 and (b[unsafe_offset=0] >= 0xEF or b[unsafe_offset=0] == 0):
        return False
    for i in range(1, min(size, 4)):
        if b[unsafe_offset=i] == 0:
            return False
    return True


struct _Refused(Movable):
    """Why the fast path's parse refused a text."""

    var kind: Int
    var message: StaticString
    var offset: Int

    def __init__(out self):
        self.kind = 0
        self.message = ""
        self.offset = -1


def _parse_and_decode(mut codec: Codec, s: Obj, strict: Bool, rfc8259: Bool, max_depth: Int, mut why: _Refused) -> Obj:
    """The fast path: `s` parsed (strictly, by RFC 8259, with `rfc8259`;
    else as json reads) and made into objects by `codec.dec`, which the
    caller has reset (`Codec.decoder`) and given its hooks; -1 when the
    parse refused it (`why`: 0 when it is not text the fast path reads at
    all) or it is the fallback's to read, 0 when Python raised."""
    ref api = codec.api
    var ptr: Addr = 0
    var size = 0
    if not _text(api, s, ptr, size) or size > MAX_SIZE:
        return -1
    try:
        codec.doc.parse(
            Span[UInt8, MutAnyOrigin](unsafe_ptr=buf(ptr), length=size),
            Limits(max_depth=max_depth, max_size=MAX_SIZE),
            Dialect() if rfc8259 else Dialect.python(control_characters=not strict),
        )
    except e:
        why.kind = e.kind
        why.message = e.message
        why.offset = e.offset
        return -1
    var r = decode(Decoder(Pointer(to=codec.dec).unsafe_origin_cast[MutUntrackedOrigin]()), codec.doc)
    if size > (1 << 20):
        codec.doc = Document()  # (no large buffers kept between calls)
    else:
        codec.doc.clear()
    return r


def _refuse(ref codec: Codec, ref why: _Refused) -> Obj:
    """Raise mojson's parse error (reason, byte offset); returns 0."""
    ref api = codec.api
    var full = String(why.message)
    var body = String(full[byte=6:]) if full.startswith("json: ") else full.copy()
    var m = String(body[byte=0:1]).upper() + String(body[byte=1:])
    var args = api.PyTuple_New(2)
    if not args:
        return 0
    var mb = m.as_bytes()
    _ = api.PyTuple_SetItem(args, 0, api.PyUnicode_FromStringAndSize(Int(mb.unsafe_ptr()), len(mb)))
    _ = api.PyTuple_SetItem(args, 1, api.PyLong_FromLongLong(why.offset))
    api.PyErr_SetObject(codec.parse_error, args)
    api.Py_DecRef(args)
    _ = m^
    return 0


def _loads(py_self: PyObjectPtr, args: PyObjectPtr, kwargs: PyObjectPtr) abi("C") -> PyObjectPtr:
    """`loads(s, **kw)`: the fast path with no keyword arguments."""
    ref codec = _codec(py_self)[]
    ref api = codec.api
    var a = _obj(args)
    var kw = _obj(kwargs)
    if (kw != 0 and api.PyDict_Size(kw) > 0) or api.PyTuple_Size(a) != 1:
        return _ptr(api.PyObject_Call(codec.kw_fallback, a, kw))
    _ = codec.decoder()
    var why = _Refused()
    var r = _parse_and_decode(codec, api.PyTuple_GetItem(a, 0), True, False, _MAX_DEPTH, why)
    if r == -1:
        return _ptr(api.PyObject_Call(codec.fallback, a, 0))
    return _ptr(r)


@inline(.always)
def _hook(ref api: Api, args: Obj, i: Int) -> Obj:
    """Argument `i`, 0 for None."""
    var o = api.PyTuple_GetItem(args, i)
    return 0 if o == api.none else o


def _loads_with(py_self: PyObjectPtr, args: PyObjectPtr, kwargs: PyObjectPtr) abi("C") -> PyObjectPtr:
    """`loads_with(s, object_hook, object_pairs_hook, parse_float,
    parse_int, parse_constant, strict, rfc8259, max_depth)`, each hook None
    or a callable, `max_depth` None or an int: the fast path with json's
    hooks, and mojson's own options. NotImplemented when the text is
    json's to read (mojson then calls json.loads with the same
    arguments); with `rfc8259`, or past a `max_depth`, a refused text
    raises mojson's parse error instead."""
    ref codec = _codec(py_self)[]
    ref api = codec.api
    var a = _obj(args)
    if api.PyTuple_Size(a) != 9:
        api.fail(api.TypeError, "loads_with takes 9 arguments")
        return _ptr(0)
    ref hooks = codec.decoder().s[]
    hooks.object_hook = _hook(api, a, 1)
    hooks.object_pairs_hook = _hook(api, a, 2)
    hooks.parse_float = _hook(api, a, 3)
    hooks.parse_int = _hook(api, a, 4)
    hooks.parse_constant = _hook(api, a, 5)
    var strict = api.PyTuple_GetItem(a, 6) != api.false
    var rfc8259 = api.PyTuple_GetItem(a, 7) == api.true
    var depth_arg = api.PyTuple_GetItem(a, 8)
    var max_depth = _MAX_DEPTH
    var own_depth = depth_arg != api.none
    if own_depth:
        var overflow: Int32 = 0
        max_depth = api.PyLong_AsLongLongAndOverflow(depth_arg, out(overflow))
        if max_depth == -1 and api.PyErr_Occurred():
            return _ptr(0)
        if overflow != 0 or max_depth < 0:
            api.fail(api.ValueError, "max_depth must be a non-negative int")
            return _ptr(0)
    var why = _Refused()
    var r = _parse_and_decode(codec, api.PyTuple_GetItem(a, 0), strict, rfc8259, max_depth, why)
    if r == -1:
        if why.kind != 0 and (rfc8259 or (own_depth and why.kind == JsonError.LIMIT)):
            return _ptr(_refuse(codec, why))
        return _ptr(api.new_ref(api.not_implemented))
    return _ptr(r)


def _set_fallbacks(py_self: PyObjectPtr, args: PyObjectPtr, kwargs: PyObjectPtr) abi("C") -> PyObjectPtr:
    """`set_fallbacks(json_loads, kw_loads, kw_dumps, parse_error,
    raw_type)`."""
    ref codec = _codec(py_self)[]
    ref api = codec.api
    var a = _obj(args)
    if api.PyTuple_Size(a) != 5:
        api.fail(api.TypeError, "set_fallbacks takes 5 arguments")
        return _ptr(0)
    var got = List[Obj]()
    for i in range(5):
        got.append(api.new_ref(api.PyTuple_GetItem(a, i)))
    for o in [codec.fallback, codec.kw_fallback, codec.dumps_fallback, codec.parse_error, codec.raw_type]:
        if o:
            api.Py_DecRef(o)
    codec.fallback = got[0]
    codec.kw_fallback = got[1]
    codec.dumps_fallback = got[2]
    codec.parse_error = got[3]
    codec.raw_type = got[4]
    return _ptr(api.new_ref(api.none))


def _dump(mut codec: Codec, o: Obj, var opts: Options, as_bytes: Bool) -> Obj:
    """`o` as JSON text: a str, or (`as_bytes`) its UTF-8 bytes."""
    ref api = codec.api
    var buffer = List[UInt8]()
    swap(buffer, codec.out)
    var ensure_ascii = opts.ensure_ascii
    var state = EncState(
        Pointer(to=codec.api).unsafe_origin_cast[MutUntrackedOrigin](), codec.int_repr, codec.raw_type, buffer^, opts^
    )
    var enc = Encoder(Pointer(to=state).unsafe_origin_cast[MutUntrackedOrigin]())
    var ok = True
    try:
        enc.write(o)
    except:
        ok = False
    ref st = state
    st.o.finish()
    var r: Obj = 0
    if ok:
        var n = st.o.n
        var p = st.o.list.unsafe_ptr()
        if as_bytes and not st.wtf8:
            r = api.PyBytes_FromStringAndSize(Int(p), n)
        elif ensure_ascii and not st.wtf8 and api.fast_str:
            r = api.PyUnicode_New(n, 127)
            if r and n > 0:
                unsafe_memcpy(dest=buf(str_data(r)), src=p, count=n)
        else:
            r = api.PyUnicode_DecodeUTF8(Int(p), n, cstr(SURROGATEPASS))
            if r and as_bytes:  # (lone surrogates: str.encode's error)
                var b = api.PyUnicode_AsEncodedString(r, cstr("utf-8"), cstr("strict"))
                api.Py_DecRef(r)
                r = b
    swap(st.o.list, codec.out)
    _ = state^
    if codec.out.capacity() > (1 << 22):
        codec.out = List[UInt8]()
    return r


def _dumps(py_self: PyObjectPtr, args: PyObjectPtr, kwargs: PyObjectPtr) abi("C") -> PyObjectPtr:
    """`dumps(obj, **kw)`: the fast path with no keyword arguments."""
    ref codec = _codec(py_self)[]
    ref api = codec.api
    var a = _obj(args)
    var kw = _obj(kwargs)
    if (kw != 0 and api.PyDict_Size(kw) > 0) or api.PyTuple_Size(a) != 1:
        return _ptr(api.PyObject_Call(codec.dumps_fallback, a, kw))
    return _ptr(_dump(codec, api.PyTuple_GetItem(a, 0), Options(), False))


def _str_bytes(ref api: Api, s: Obj, mut dst: List[UInt8]) -> Bool:
    """A str argument's UTF-8 bytes into `dst`."""
    var n = 0
    var p = api.PyUnicode_AsUTF8AndSize(s, out(n))
    if not p:
        return False
    dst.clear()
    dst.extend(Span[UInt8, MutAnyOrigin](unsafe_ptr=buf(p), length=n))
    return True


def _dumps_with(py_self: PyObjectPtr, args: PyObjectPtr, kwargs: PyObjectPtr) abi("C") -> PyObjectPtr:
    """`dumps_with(obj, skipkeys, ensure_ascii, check_circular, allow_nan,
    indent, item_separator, key_separator, default, sort_keys, as_bytes)`:
    `indent` None or a str, the separators str, `default` None or a
    callable; python/mojson checks them as json does."""
    ref codec = _codec(py_self)[]
    ref api = codec.api
    var a = _obj(args)
    if api.PyTuple_Size(a) != 11:
        api.fail(api.TypeError, "dumps_with takes 11 arguments")
        return _ptr(0)
    var opts = Options()
    opts.skipkeys = api.PyTuple_GetItem(a, 1) == api.true
    opts.ensure_ascii = api.PyTuple_GetItem(a, 2) == api.true
    opts.check_circular = api.PyTuple_GetItem(a, 3) == api.true
    opts.allow_nan = api.PyTuple_GetItem(a, 4) == api.true
    var indent = api.PyTuple_GetItem(a, 5)
    if indent != api.none:
        opts.has_indent = True
        if not _str_bytes(api, indent, opts.indent):
            return _ptr(0)
    if not _str_bytes(api, api.PyTuple_GetItem(a, 6), opts.item_sep):
        return _ptr(0)
    if not _str_bytes(api, api.PyTuple_GetItem(a, 7), opts.key_sep):
        return _ptr(0)
    opts.default = _hook(api, a, 8)
    opts.sort_keys = api.PyTuple_GetItem(a, 9) == api.true
    var as_bytes = api.PyTuple_GetItem(a, 10) == api.true
    return _ptr(_dump(codec, api.PyTuple_GetItem(a, 0), opts^, as_bytes))


@export
def PyInit__mojson() abi("C") -> PythonObject:
    try:
        var m = PythonModuleBuilder("_mojson")
        _ = (
            m.add_type[Codec]("Codec")
            .def_py_init[Codec.py_init]()
            .def_py_c_method(_loads, "loads")
            .def_py_c_method(_loads_with, "loads_with")
            .def_py_c_method(_set_fallbacks, "set_fallbacks")
            .def_py_c_method(_dumps, "dumps")
            .def_py_c_method(_dumps_with, "dumps_with")
        )
        return m.finalize()
    except e:
        abort(String("mojson: failed to create the module: ", e))
