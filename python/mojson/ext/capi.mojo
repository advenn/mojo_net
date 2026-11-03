"""The CPython C API as `mojson` calls it: the only module of the extension
that reaches C. Every function is resolved once, when the module is
imported, from the interpreter that imports it (`dlopen(NULL)`), into a
typed function pointer; objects travel as `Obj`, their addresses (0 for
NULL), since Mojo's pointers cannot be null.

A few object layouts are read directly where a call would cost more than
the work (a type, a str's characters, a list's items, a compact int's
digit, a float's value, a dict's entries). `Api.__init__` checks each
against the C API on objects it builds, and the reads are used only where
the check passed (`fast_str`, `fast_list`, `fast_int`, `fast_float`,
`fast_dict`); otherwise the extension goes through the C API alone. An object's type is read always,
so an interpreter whose objects do not start with (refcount, type), as
free-threaded CPython's do not, is refused at import. The offsets are
those of CPython 3.12 to 3.15 with the GIL on 64-bit platforms (3.15's
headers lay them out as 3.14's)."""

from std.ffi import OwnedDLHandle, c_int
from std.memory import bitcast

comptime Obj = Int
"""A `PyObject*`, as its address; 0 is NULL."""
comptime Buf = Pointer[UInt8, MutAnyOrigin]
comptime Addr = Int
"""Any other pointer handed to C that C only reads (a `char*`)."""
comptime IntOut = Pointer[Int, MutAnyOrigin]
comptime I32Out = Pointer[Int32, MutAnyOrigin]
"""Out-parameters go as typed mutable pointers, never as `Int` addresses:
passed as an address, the compiler may read the variable back unchanged
(CLAUDE.md, "FFI")."""

comptime _F_v_o = def(Obj) thin abi("C") -> None
comptime _F_o = def() thin abi("C") -> Obj
comptime _F_v = def() thin abi("C") -> None
comptime _F_v_oa = def(Obj, Addr) thin abi("C") -> None
comptime _F_v_oo = def(Obj, Obj) thin abi("C") -> None
comptime _F_i_o = def(Obj) thin abi("C") -> c_int
comptime _F_o_o = def(Obj) thin abi("C") -> Obj
comptime _F_o_oo = def(Obj, Obj) thin abi("C") -> Obj
comptime _F_o_ooo = def(Obj, Obj, Obj) thin abi("C") -> Obj
comptime _F_o_oa = def(Obj, Addr) thin abi("C") -> Obj
comptime _F_l_o = def(Obj) thin abi("C") -> Int
comptime _F_u64_o = def(Obj) thin abi("C") -> UInt64
comptime _F_o_l = def(Int) thin abi("C") -> Obj
comptime _F_o_aai = def(Addr, Addr, c_int) thin abi("C") -> Obj
comptime _F_l_oi32 = def(Obj, I32Out) thin abi("C") -> Int
comptime _F_o_d = def(Float64) thin abi("C") -> Obj
comptime _F_d_o = def(Obj) thin abi("C") -> Float64
comptime _F_o_lu = def(Int, UInt32) thin abi("C") -> Obj
comptime _F_o_ala = def(Addr, Int, Addr) thin abi("C") -> Obj
comptime _F_a_on = def(Obj, IntOut) thin abi("C") -> Addr
comptime _F_o_oaa = def(Obj, Addr, Addr) thin abi("C") -> Obj
comptime _F_o_al = def(Addr, Int) thin abi("C") -> Obj
comptime _F_a_o = def(Obj) thin abi("C") -> Addr
comptime _F_i_olo = def(Obj, Int, Obj) thin abi("C") -> c_int
comptime _F_i_oo = def(Obj, Obj) thin abi("C") -> c_int
comptime _F_i_ooo = def(Obj, Obj, Obj) thin abi("C") -> c_int
comptime _F_i_onnn = def(Obj, IntOut, IntOut, IntOut) thin abi("C") -> c_int
comptime _F_d_aao = def(Addr, Addr, Obj) thin abi("C") -> Float64
comptime _F_i_a = def(Addr) thin abi("C") -> c_int
comptime _F_i = def() thin abi("C") -> c_int
comptime _F_a_l = def(Int) thin abi("C") -> Addr
comptime _F_a_al = def(Addr, Int) thin abi("C") -> Addr
comptime _F_v_a = def(Addr) thin abi("C") -> None
comptime _F_i_nl = def(IntOut, Int) thin abi("C") -> c_int
comptime _F_i_ooi = def(Obj, Obj, c_int) thin abi("C") -> c_int
comptime _F_o_ol = def(Obj, Int) thin abi("C") -> Obj

comptime SURROGATEPASS = "surrogatepass"
comptime UTF8 = "utf-8"

comptime TPFLAGS_LONG = UInt64(1) << 24
comptime TPFLAGS_LIST = UInt64(1) << 25
comptime TPFLAGS_TUPLE = UInt64(1) << 26
comptime TPFLAGS_BYTES = UInt64(1) << 27
comptime TPFLAGS_UNICODE = UInt64(1) << 28
comptime TPFLAGS_DICT = UInt64(1) << 29


def _sym[F: TrivialRegisterPassable](h: OwnedDLHandle, name: StaticString) raises -> F:
    """`name`'s address in `h` as a C function of type `F`."""
    var p = h.get_symbol[NoneType](name)
    if not p:
        raise Error("mojson: the Python C API lacks ", name)
    var addr = Int(p.value())
    return Pointer(to=addr).unsafe_bitcast[F]()[]


def _data(h: OwnedDLHandle, name: StaticString) raises -> Int:
    """The address of the data symbol `name` (an object, or a variable)."""
    var p = h.get_symbol[NoneType](name)
    if not p:
        raise Error("mojson: the Python C API lacks ", name)
    return Int(p.value())


@inline(.always)
def load_int(addr: Int) -> Int:
    return Pointer[Int, MutAnyOrigin](unsafe_from_address=addr)[]


@inline(.always)
def store_int(addr: Int, v: Int):
    Pointer[Int, MutAnyOrigin](unsafe_from_address=addr)[] = v


@inline(.always)
def buf(addr: Int) -> Buf:
    return Buf(unsafe_from_address=addr)


@inline(.always)
def out[T: AnyType](mut x: T) -> Pointer[T, MutAnyOrigin]:
    """`x` as an out-parameter for C."""
    return Pointer(to=x).unsafe_origin_cast[MutAnyOrigin]()


@inline(.always)
def cstr(s: StaticString) -> Addr:
    """A literal's bytes, which end in a NUL, as a `const char*`."""
    return Int(s.unsafe_ptr())


struct Api(Movable):
    """The interpreter's C API (see the module docs)."""

    var _handle: OwnedDLHandle

    var Py_IncRef: _F_v_o
    var Py_DecRef: _F_v_o
    var PyErr_Occurred: _F_o
    var PyErr_SetString: _F_v_oa
    var PyErr_SetObject: _F_v_oo
    var PyErr_Clear: _F_v
    var PyErr_ExceptionMatches: _F_i_o
    var PyErr_NoMemory: _F_o
    var PyObject_Repr: _F_o_o
    var PyObject_Str: _F_o_o
    var PyObject_CallOneArg: _F_o_oo
    var PyObject_Call: _F_o_ooo
    var PyObject_Hash: _F_l_o
    var PyObject_GetAttrString: _F_o_oa
    var PyObject_IsInstance: _F_i_oo
    var PyType_GetFlags: _F_u64_o
    var PyType_IsSubtype: _F_i_oo
    var PyLong_FromLongLong: _F_o_l
    var PyLong_FromString: _F_o_aai
    var PyLong_AsLongLongAndOverflow: _F_l_oi32
    var PyFloat_FromDouble: _F_o_d
    var PyFloat_AsDouble: _F_d_o
    var PyOS_string_to_double: _F_d_aao
    var PyUnicode_New: _F_o_lu
    var PyUnicode_Resize: _F_i_nl
    var _PyBytes_Resize: _F_i_nl
    var PyMem_RawMalloc: _F_a_l
    var PyMem_RawRealloc: _F_a_al
    var PyMem_RawFree: _F_v_a
    var PyUnicode_DecodeUTF8: _F_o_ala
    var PyUnicode_AsUTF8AndSize: _F_a_on
    var PyUnicode_AsEncodedString: _F_o_oaa
    var PyUnicode_FromStringAndSize: _F_o_al
    var PyUnicode_InternInPlace: _F_v_o
    var PyBytes_FromStringAndSize: _F_o_al
    var PyBytes_AsString: _F_a_o
    var PyBytes_Size: _F_l_o
    var PyByteArray_AsString: _F_a_o
    var PyByteArray_Size: _F_l_o
    var PyList_New: _F_o_l
    var PyList_SetItem: _F_i_olo
    var PyList_GetItem: _F_o_ol
    var PyList_Append: _F_i_oo
    var PyList_Sort: _F_i_o
    var PyTuple_New: _F_o_l
    var PyTuple_SetItem: _F_i_olo
    var PyTuple_GetItem: _F_o_ol
    var PyTuple_Size: _F_l_o
    var PyDict_New: _F_o
    var _PyDict_NewPresized: _F_o_l
    var has_presized: Bool
    var PyDict_SetItem: _F_i_ooo
    var PyDict_DelItem: _F_i_oo
    var PyDict_Next: _F_i_onnn
    var PyDict_Size: _F_l_o
    var PyMapping_Items: _F_o_o
    var PySequence_Fast: _F_o_oa
    var Py_EnterRecursiveCall: _F_i_a
    var Py_LeaveRecursiveCall: _F_v
    var PyObject_RichCompareBool: _F_i_ooi

    var none: Obj
    var not_implemented: Obj
    var true: Obj
    var false: Obj
    var str_type: Obj
    var int_type: Obj
    var float_type: Obj
    var bool_type: Obj
    var list_type: Obj
    var tuple_type: Obj
    var dict_type: Obj
    var bytes_type: Obj
    var bytearray_type: Obj
    var TypeError: Obj
    var ValueError: Obj
    var OverflowError: Obj
    var RecursionError: Obj
    var UnicodeError: Obj

    var fast_str: Bool
    """A str's header and characters are read directly (checked at load)."""
    var fast_list: Bool
    """A list's item array is written directly (checked at load)."""
    var fast_float: Bool
    """A float's value is read directly (checked at load)."""
    var fast_int: Bool
    """A compact int's value (one 30-bit digit at most) is read directly
    (checked at load)."""
    var counted_recursion: Bool
    """Py_EnterRecursiveCall counts calls (Python 3.12 and 3.13), where
    3.14 and later compare the C stack's depth with a limit instead: a
    loop that takes no stack per level need not call it per level."""
    var fast_dict: Bool
    """A combined dict's entries are read directly (`dict_next`, checked
    at load against PyDict_Next), and an exact dict's size (`ma_used`, the
    third word)."""

    def __init__(out self) raises:
        var h = OwnedDLHandle()
        self.Py_IncRef = _sym[_F_v_o](h, "Py_IncRef")
        self.Py_DecRef = _sym[_F_v_o](h, "Py_DecRef")
        self.PyErr_Occurred = _sym[_F_o](h, "PyErr_Occurred")
        self.PyErr_SetString = _sym[_F_v_oa](h, "PyErr_SetString")
        self.PyErr_SetObject = _sym[_F_v_oo](h, "PyErr_SetObject")
        self.PyErr_Clear = _sym[_F_v](h, "PyErr_Clear")
        self.PyErr_ExceptionMatches = _sym[_F_i_o](h, "PyErr_ExceptionMatches")
        self.PyErr_NoMemory = _sym[_F_o](h, "PyErr_NoMemory")
        self.PyObject_Repr = _sym[_F_o_o](h, "PyObject_Repr")
        self.PyObject_Str = _sym[_F_o_o](h, "PyObject_Str")
        self.PyObject_CallOneArg = _sym[_F_o_oo](h, "PyObject_CallOneArg")
        self.PyObject_Call = _sym[_F_o_ooo](h, "PyObject_Call")
        self.PyObject_Hash = _sym[_F_l_o](h, "PyObject_Hash")
        self.PyObject_GetAttrString = _sym[_F_o_oa](h, "PyObject_GetAttrString")
        self.PyObject_IsInstance = _sym[_F_i_oo](h, "PyObject_IsInstance")
        self.PyType_GetFlags = _sym[_F_u64_o](h, "PyType_GetFlags")
        self.PyType_IsSubtype = _sym[_F_i_oo](h, "PyType_IsSubtype")
        self.PyLong_FromLongLong = _sym[_F_o_l](h, "PyLong_FromLongLong")
        self.PyLong_FromString = _sym[_F_o_aai](h, "PyLong_FromString")
        self.PyLong_AsLongLongAndOverflow = _sym[_F_l_oi32](h, "PyLong_AsLongLongAndOverflow")
        self.PyFloat_FromDouble = _sym[_F_o_d](h, "PyFloat_FromDouble")
        self.PyFloat_AsDouble = _sym[_F_d_o](h, "PyFloat_AsDouble")
        self.PyOS_string_to_double = _sym[_F_d_aao](h, "PyOS_string_to_double")
        self.PyUnicode_New = _sym[_F_o_lu](h, "PyUnicode_New")
        self.PyUnicode_Resize = _sym[_F_i_nl](h, "PyUnicode_Resize")
        self._PyBytes_Resize = _sym[_F_i_nl](h, "_PyBytes_Resize")
        self.PyMem_RawMalloc = _sym[_F_a_l](h, "PyMem_RawMalloc")
        self.PyMem_RawRealloc = _sym[_F_a_al](h, "PyMem_RawRealloc")
        self.PyMem_RawFree = _sym[_F_v_a](h, "PyMem_RawFree")
        self.PyUnicode_DecodeUTF8 = _sym[_F_o_ala](h, "PyUnicode_DecodeUTF8")
        self.PyUnicode_AsUTF8AndSize = _sym[_F_a_on](h, "PyUnicode_AsUTF8AndSize")
        self.PyUnicode_AsEncodedString = _sym[_F_o_oaa](h, "PyUnicode_AsEncodedString")
        self.PyUnicode_FromStringAndSize = _sym[_F_o_al](h, "PyUnicode_FromStringAndSize")
        self.PyUnicode_InternInPlace = _sym[_F_v_o](h, "PyUnicode_InternInPlace")
        self.PyBytes_FromStringAndSize = _sym[_F_o_al](h, "PyBytes_FromStringAndSize")
        self.PyBytes_AsString = _sym[_F_a_o](h, "PyBytes_AsString")
        self.PyBytes_Size = _sym[_F_l_o](h, "PyBytes_Size")
        self.PyByteArray_AsString = _sym[_F_a_o](h, "PyByteArray_AsString")
        self.PyByteArray_Size = _sym[_F_l_o](h, "PyByteArray_Size")
        self.PyList_New = _sym[_F_o_l](h, "PyList_New")
        self.PyList_SetItem = _sym[_F_i_olo](h, "PyList_SetItem")
        self.PyList_GetItem = _sym[_F_o_ol](h, "PyList_GetItem")
        self.PyList_Append = _sym[_F_i_oo](h, "PyList_Append")
        self.PyList_Sort = _sym[_F_i_o](h, "PyList_Sort")
        self.PyTuple_New = _sym[_F_o_l](h, "PyTuple_New")
        self.PyTuple_SetItem = _sym[_F_i_olo](h, "PyTuple_SetItem")
        self.PyTuple_GetItem = _sym[_F_o_ol](h, "PyTuple_GetItem")
        self.PyTuple_Size = _sym[_F_l_o](h, "PyTuple_Size")
        self.PyDict_New = _sym[_F_o](h, "PyDict_New")
        # (private, but exported by every CPython 3; PyDict_New without it)
        self.has_presized = Bool(h.get_symbol[NoneType]("_PyDict_NewPresized"))
        if self.has_presized:
            self._PyDict_NewPresized = _sym[_F_o_l](h, "_PyDict_NewPresized")
        else:
            self._PyDict_NewPresized = _sym[_F_o_l](h, "PyList_New")  # (never called)
        self.PyDict_SetItem = _sym[_F_i_ooo](h, "PyDict_SetItem")
        self.PyDict_DelItem = _sym[_F_i_oo](h, "PyDict_DelItem")
        self.PyDict_Next = _sym[_F_i_onnn](h, "PyDict_Next")
        self.PyDict_Size = _sym[_F_l_o](h, "PyDict_Size")
        self.PyMapping_Items = _sym[_F_o_o](h, "PyMapping_Items")
        self.PySequence_Fast = _sym[_F_o_oa](h, "PySequence_Fast")
        self.Py_EnterRecursiveCall = _sym[_F_i_a](h, "Py_EnterRecursiveCall")
        self.Py_LeaveRecursiveCall = _sym[_F_v](h, "Py_LeaveRecursiveCall")
        self.PyObject_RichCompareBool = _sym[_F_i_ooi](h, "PyObject_RichCompareBool")

        self.none = _data(h, "_Py_NoneStruct")
        self.not_implemented = _data(h, "_Py_NotImplementedStruct")
        self.true = _data(h, "_Py_TrueStruct")
        self.false = _data(h, "_Py_FalseStruct")
        self.str_type = _data(h, "PyUnicode_Type")
        self.int_type = _data(h, "PyLong_Type")
        self.float_type = _data(h, "PyFloat_Type")
        self.bool_type = _data(h, "PyBool_Type")
        self.list_type = _data(h, "PyList_Type")
        self.tuple_type = _data(h, "PyTuple_Type")
        self.dict_type = _data(h, "PyDict_Type")
        self.bytes_type = _data(h, "PyBytes_Type")
        self.bytearray_type = _data(h, "PyByteArray_Type")
        self.TypeError = load_int(_data(h, "PyExc_TypeError"))
        self.ValueError = load_int(_data(h, "PyExc_ValueError"))
        self.OverflowError = load_int(_data(h, "PyExc_OverflowError"))
        self.RecursionError = load_int(_data(h, "PyExc_RecursionError"))
        self.UnicodeError = load_int(_data(h, "PyExc_UnicodeError"))
        self.fast_str = False
        self.fast_list = False
        self.fast_float = False
        self.fast_int = False
        self.fast_dict = False
        self.counted_recursion = (load_int(_data(h, "Py_Version")) & 0xFFFFFFFF) < 0x030E0000
        self._handle = h^
        # Every path reads an object's type directly: refuse an interpreter
        # whose objects do not start with (refcount, type), as free-threaded
        # CPython's do not.
        if self.type_of(self.true) != self.bool_type or self.type_of(self.none) == self.bool_type:
            raise Error("mojson: this interpreter's object layout is not one mojson reads (free-threaded?)")
        self._check_layouts()

    # ---- direct reads ------------------------------------------------------

    @inline(.always)
    def type_of(self, o: Obj) -> Obj:
        """`Py_TYPE(o)`: the second word of every object (checked)."""
        return load_int(o + 8)

    def _check_layouts(mut self):
        """Compare each direct read with the C API on objects built here;
        enable only those that agree."""
        var ascii = self.PyUnicode_FromStringAndSize(cstr("json"), 4)
        var w: List[UInt8] = [0xC3, 0xA9, 0x74, 0xC3, 0xA9, 0x20, 0xE4, 0xB8, 0xAD]  # "été 中" in UTF-8
        var a: List[UInt8] = [0xF0, 0x9F, 0x98, 0x80]  # U+1F600
        var wide = self.PyUnicode_DecodeUTF8(Int(w.unsafe_ptr()), len(w), 0)
        var astral = self.PyUnicode_DecodeUTF8(Int(a.unsafe_ptr()), len(a), 0)
        _ = w^
        _ = a^
        if ascii and wide and astral and self.type_of(ascii) == self.str_type:
            var ok = (
                str_length(ascii) == 4
                and str_kind(ascii) == 1
                and str_is_ascii(ascii)
                and buf(str_data(ascii))[unsafe_offset=0] == 106
                and buf(str_data(ascii))[unsafe_offset=3] == 110
                and str_length(wide) == 5
                and str_kind(wide) == 2
                and not str_is_ascii(wide)
                and Pointer[UInt16, MutAnyOrigin](unsafe_from_address=str_data(wide))[unsafe_offset=0] == 0xE9
                and Pointer[UInt16, MutAnyOrigin](unsafe_from_address=str_data(wide))[unsafe_offset=4] == 0x4E2D
                and str_length(astral) == 1
                and str_kind(astral) == 4
                and Pointer[UInt32, MutAnyOrigin](unsafe_from_address=str_data(astral))[unsafe_offset=0] == 0x1F600
            )
            # A str made by PyUnicode_New is filled in place.
            var made = self.PyUnicode_New(3, 127)
            if ok and made:
                var d = buf(str_data(made))
                d[unsafe_offset=0] = 97
                d[unsafe_offset=1] = 98
                d[unsafe_offset=2] = 99
                var size = 0
                var u = self.PyUnicode_AsUTF8AndSize(made, out(size))
                ok = u != 0 and size == 3 and buf(u)[unsafe_offset=0] == 97 and buf(u)[unsafe_offset=2] == 99
            if made:
                self.Py_DecRef(made)
            self.fast_str = ok
        for o in [ascii, wide, astral]:
            if o:
                self.Py_DecRef(o)
        var list = self.PyList_New(2)
        if list and self.type_of(list) == self.list_type:
            self.Py_IncRef(self.none)
            self.Py_IncRef(self.true)
            store_int(load_int(list + 24), self.none)
            store_int(load_int(list + 24) + 8, self.true)
            var rendered = self.PyObject_Repr(list)
            if rendered:
                var size = 0
                var u = self.PyUnicode_AsUTF8AndSize(rendered, out(size))
                # "[None, True]"
                self.fast_list = (
                    u != 0 and size == 12 and buf(u)[unsafe_offset=1] == 78 and buf(u)[unsafe_offset=7] == 84
                )
                self.Py_DecRef(rendered)
            self.Py_DecRef(list)
        # A float's value is its third word; an int of at most one digit
        # is compact, its sign and size in the tag (third word), its digit
        # in the fourth (3.12 to 3.15's layout).
        var ok = True
        for x in [Float64(1.5), Float64(-0.0), Float64(1e300), Float64(-3.25e-310)]:
            var f = self.PyFloat_FromDouble(x)
            if not f:
                ok = False
                break
            var bits = UInt64(load_int(f + 16))
            ok = ok and self.type_of(f) == self.float_type and bits == bitcast[DType.uint64, 1](SIMD[DType.float64, 1](x))
            self.Py_DecRef(f)
        self.fast_float = ok
        ok = True
        for v in [0, 1, -1, 7, -12345, (1 << 30) - 1, -((1 << 30) - 1)]:
            var o = self.PyLong_FromLongLong(v)
            if not o:
                ok = False
                break
            ok = ok and self.type_of(o) == self.int_type and compact_int(o) and compact_value(o) == v
            self.Py_DecRef(o)
        for v in [1 << 30, -(1 << 30), 1 << 62]:
            var o = self.PyLong_FromLongLong(v)
            if not o:
                ok = False
                break
            ok = ok and not compact_int(o)
            self.Py_DecRef(o)
        self.fast_int = ok
        self.fast_dict = self._check_dicts()
        self.PyErr_Clear()

    def _check_dicts(self) -> Bool:
        """`dict_next` against PyDict_Next on dicts built here: str keys,
        a deleted entry, other keys (the general table), and a dict past
        256 slots (2-byte indices)."""
        var d = self.PyDict_New()
        var g = self.PyDict_New()
        var big = self.PyDict_New()
        if not d or not g or not big:
            return False
        var ok = True
        var made = List[Obj]()
        for i in range(400):
            var k = self.PyLong_FromLongLong(i * 7919)
            var ks = self.PyObject_Repr(k)
            if not k or not ks:
                ok = False
                break
            made.append(k)
            made.append(ks)
            if i < 5:
                ok = ok and self.PyDict_SetItem(d, ks, k) == 0
            if i < 3:
                ok = ok and self.PyDict_SetItem(g, k, ks) == 0 and self.PyDict_SetItem(g, ks, k) == 0
            ok = ok and self.PyDict_SetItem(big, ks, k) == 0
        if ok:
            ok = self.PyDict_DelItem(d, made[3]) == 0  # (the second key)
        for o in [d, g, big]:
            ok = ok and load_int(o + 40) == 0 and self._same_iteration(o)
        for o in made:
            self.Py_DecRef(o)
        for o in [d, g, big]:
            self.Py_DecRef(o)
        self.PyErr_Clear()
        return ok

    def _same_iteration(self, o: Obj) -> Bool:
        var pos = 0
        var mine = 0
        var k: Obj = 0
        var v: Obj = 0
        var k2: Obj = 0
        var v2: Obj = 0
        var count = 0
        while True:
            var a = self.PyDict_Next(o, out(pos), out(k), out(v)) != 0
            var b = dict_next(o, mine, k2, v2)
            if a != b:
                return False
            if not a:
                return count == self.PyDict_Size(o) and load_int(o + 16) == count  # (ma_used)
            if k != k2 or v != v2 or pos != mine:
                return False
            count += 1

    # ---- helpers -----------------------------------------------------------

    @inline(.always)
    def flags(self, o: Obj) -> UInt64:
        return self.PyType_GetFlags(self.type_of(o))

    @inline(.always)
    def new_dict(self, n: Int) -> Obj:
        """A dict with room for `n` items."""
        if self.has_presized:
            return self._PyDict_NewPresized(n)
        return self.PyDict_New()

    @inline(.always)
    def new_ref(self, o: Obj) -> Obj:
        self.Py_IncRef(o)
        return o

    @inline(.always)
    def list_set(self, list: Obj, i: Int, item: Obj):
        """`PyList_SET_ITEM`: steals `item`, into a new list's slot `i`."""
        if self.fast_list:
            store_int(load_int(list + 24) + 8 * i, item)
        else:
            _ = self.PyList_SetItem(list, i, item)

    @inline(.always)
    def list_items(self, list: Obj) -> Int:
        """A list's item array (`fast_list` only)."""
        return load_int(list + 24)

    def fail(self, exc: Obj, message: String):
        """Raise `exc(message)` in Python; the caller returns NULL."""
        var c = List[UInt8](message.as_bytes())
        c.append(0)
        self.PyErr_SetString(exc, Int(c.unsafe_ptr()))
        _ = c^

    def is_float(self, o: Obj) -> Bool:
        """`PyFloat_Check(o)`: a float or a subclass (no __instancecheck__)."""
        var t = self.type_of(o)
        return t == self.float_type or self.PyType_IsSubtype(t, self.float_type) != 0

    def tp_name(self, o: Obj) -> String:
        """`Py_TYPE(o)->tp_name`, the third word of a type object."""
        var name = load_int(self.type_of(o) + 24)
        var n = 0
        while buf(name)[unsafe_offset=n] != 0 and n < 200:
            n += 1
        return String(unsafe_from_utf8=Span[UInt8, MutAnyOrigin](unsafe_ptr=buf(name), length=n))

    def type_name(self, o: Obj) -> String:
        """`type(o).__name__`."""
        var name = self.PyObject_GetAttrString(self.type_of(o), cstr("__name__"))
        if not name:
            self.PyErr_Clear()
            return String("object")
        var size = 0
        var u = self.PyUnicode_AsUTF8AndSize(name, out(size))
        var out = String("?")
        if u:
            out = String(unsafe_from_utf8=Span[UInt8, MutAnyOrigin](unsafe_ptr=buf(u), length=size))
        else:
            self.PyErr_Clear()
        self.Py_DecRef(name)
        return out^


# ---- int and float internals (CPython 3.12-3.15, GIL builds) ----------------
# PyLongObject: refcnt, type, lv_tag (16), then 30-bit digits (24). The tag
# holds the number of digits above its 3 low bits, and the sign in its 2
# lowest (0 positive, 1 zero, 2 negative); an int of 0 or 1 digits is
# compact. PyFloatObject: refcnt, type, ob_fval (16).


@inline(.always)
def compact_int(o: Obj) -> Bool:
    """Whether an exact int has at most one digit (`Api.fast_int`)."""
    return load_int(o + 16) < (2 << 3)


@inline(.always)
def compact_value(o: Obj) -> Int:
    """A compact int's value (`compact_int`)."""
    var tag = load_int(o + 16)
    var digit = Int(Pointer[UInt32, MutAnyOrigin](unsafe_from_address=o + 24)[])
    return (1 - (tag & 3)) * digit


@inline(.always)
def dict_next(o: Obj, mut pos: Int, mut k: Obj, mut v: Obj) -> Bool:
    """PyDict_Next for a dict with a combined table (`ma_values` NULL; its
    keys object read again on each call, as PyDict_Next reads it): the
    next live entry at or after `pos`. PyDictObject: refcnt, type, ma_used
    (16), a tag (24), ma_keys (32), ma_values (40). The keys object:
    dk_refcnt, dk_log2_size (8), dk_log2_index_bytes (9), dk_kind (10),
    dk_version, dk_usable, dk_nentries (24), the indices (32), then the
    entries: (key, value) for str keys (kind 1), (hash, key, value) for
    others (`Api.fast_dict`)."""
    var keys = load_int(o + 32)
    var b = buf(keys)
    var unicode = b[unsafe_offset=10] == 1
    var step = 16 if unicode else 24
    var e = keys + 32 + (1 << Int(b[unsafe_offset=9])) + (0 if unicode else 8)
    var n = load_int(keys + 24)
    var i = pos
    while i < n:
        var at = e + i * step
        var value = load_int(at + 8)
        i += 1
        if value != 0:
            k = load_int(at)
            v = value
            pos = i
            return True
    pos = i
    return False


@inline(.always)
def dict_table(o: Obj) -> Tuple[Int, Int, Int]:
    """A combined dict's entries as `dict_next` reads them: the address of
    the first one's key, the size of an entry, and the entries used
    (`dk_nentries`, deleted ones included: a NULL value)."""
    var keys = load_int(o + 32)
    var b = buf(keys)
    var unicode = b[unsafe_offset=10] == 1
    return (
        keys + 32 + (1 << Int(b[unsafe_offset=9])) + (0 if unicode else 8),
        16 if unicode else 24,
        load_int(keys + 24),
    )


@inline(.always)
def float_value(o: Obj) -> Float64:
    """An exact float's value (`Api.fast_float`)."""
    return Pointer[Float64, MutAnyOrigin](unsafe_from_address=o + 16)[]


# ---- str internals (CPython 3.12-3.15, GIL builds; `Api.fast_str`) ----------
# PyASCIIObject: refcnt, type, length (16), hash (24), state (32), then the
# characters of a compact ASCII str (40); PyCompactUnicodeObject adds
# utf8_length and utf8 (characters at 56); a legacy str holds a pointer
# to them at 56.


@inline(.always)
def str_length(o: Obj) -> Int:
    return load_int(o + 16)


@inline(.always)
def _state(o: Obj) -> UInt32:
    return Pointer[UInt32, MutAnyOrigin](unsafe_from_address=o + 32)[]


@inline(.always)
def str_kind(o: Obj) -> Int:
    """1, 2 or 4 bytes per character."""
    return Int((_state(o) >> 2) & 7)


@inline(.always)
def str_is_ascii(o: Obj) -> Bool:
    return ((_state(o) >> 6) & 1) == 1


@inline(.always)
def str_data(o: Obj) -> Addr:
    var st = _state(o)
    if (st >> 5) & 1 == 1:  # compact
        return o + (40 if (st >> 6) & 1 == 1 else 56)
    return load_int(o + 56)
