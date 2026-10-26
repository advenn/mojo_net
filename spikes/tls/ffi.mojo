"""T0 spike: loading OpenSSL at run time (docs/spikes.md, "TLS through
OpenSSL"). Not library code: spikes may use `external_call` (CLAUDE.md).

The library is opened by absolute path with the standard library's
`OwnedDLHandle`, and each function's address (`get_symbol`) becomes a typed
C function pointer, so no linker flags are needed under `mojo run` or
`mojo build`. Pointers to OpenSSL objects travel as `Int` here; the real
package gives them types.
"""

from std.ffi import OwnedDLHandle, c_int, c_uint, external_call

comptime RUNTIME_LIB = "libKGENCompilerRTShared.so"
"""A library every Mojo program loads, from its own environment's lib
directory: OpenSSL is opened beside it, by absolute path. A bare
`dlopen("libssl.so.3")` searches from whoever calls it: under
AddressSanitizer (which intercepts dlopen) it found the host's OpenSSL
3.5.7 in /lib instead of the environment's 3.5.9 (T0 finding)."""

comptime _VoidPtr = OpaquePointer[MutAnyOrigin]


def cstr(s: StringSlice) -> List[UInt8]:
    """`s` NUL-terminated (the caller keeps the result alive across the
    call that reads it)."""
    var b = List[UInt8](s.as_bytes())
    b.append(0)
    return b^


def from_cstr(addr: Int) -> String:
    """A copy of the C string at `addr` ("" for NULL)."""
    if addr == 0:
        return String()
    var p = UnsafePointer[UInt8, MutAnyOrigin](unsafe_from_address=addr)
    var out = List[UInt8]()
    var i = 0
    while p[i] != 0:
        out.append(p[i])
        i += 1
    return String(unsafe_from_utf8=Span(out))


def runtime_dir() raises -> String:
    """The directory the Mojo runtime library was mapped from
    (/proc/self/maps; a plain file read, no dl* call)."""
    var text = String()
    with open("/proc/self/maps", "r") as f:
        text = f.read()
    for line in text.split("\n"):
        if line.endswith("/" + RUNTIME_LIB):
            var b = line.as_bytes()
            var start = line.find("/")
            var stop = line.rfind("/")
            return String(unsafe_from_utf8=b[start:stop])
    raise Error("the Mojo runtime library is not mapped")


struct Lib(Movable):
    """An `OwnedDLHandle` (the public dlopen) and lookups through it. The
    standard library declares dlopen and dlsym itself (std.sys._libc); one C
    symbol has one signature per program, so declaring them again breaks any
    program that also uses Python (T0 finding)."""

    var handle: OwnedDLHandle

    def __init__(out self, path: StringSlice) raises:
        self.handle = OwnedDLHandle(String(path))

    @staticmethod
    def beside_runtime(name: StringSlice) raises -> Lib:
        """`name` from the Mojo runtime's directory, by absolute path."""
        return Lib(runtime_dir() + "/" + name)

    def address(self, name: StringSlice) raises -> Int:
        var p = self.handle.get_symbol[NoneType](name)
        if not p:
            raise Error(String("missing symbol ", name))
        return Int(p.value())

    def sym[F: TrivialRegisterPassable](self, name: StringSlice) raises -> F:
        """`name` as a C function of type `F`; raises if it is missing."""
        var addr = self.address(name)
        return UnsafePointer(to=addr).bitcast[F]()[]

    def path_of(self, name: StringSlice) raises -> String:
        """The file the symbol `name` was loaded from (dladdr)."""
        var info = List[Int](length=4, fill=0)  # Dl_info: fname, fbase, sname, saddr
        _ = external_call["dladdr", c_int](_VoidPtr(unsafe_from_address=self.address(name)), info.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]())
        return from_cstr(info[0])


# C signatures (LP64: long and size_t are Int; int is c_int).
comptime F_p = def() thin abi("C") -> Int
comptime F_p_p = def(Int) thin abi("C") -> Int
comptime F_p_pp = def(Int, Int) thin abi("C") -> Int
comptime F_p_ppp = def(Int, Int, Int) thin abi("C") -> Int
comptime F_i_p = def(Int) thin abi("C") -> c_int
comptime F_i_pp = def(Int, Int) thin abi("C") -> c_int
comptime F_i_ppp = def(Int, Int, Int) thin abi("C") -> c_int
comptime F_i_ppi = def(Int, Int, c_int) thin abi("C") -> c_int
comptime F_i_pi = def(Int, c_int) thin abi("C") -> c_int
comptime F_i_ppnp = def(Int, Int, Int, Int) thin abi("C") -> c_int
comptime F_i_u64p = def(UInt64, Int) thin abi("C") -> c_int
comptime F_l_pilp = def(Int, c_int, Int, Int) thin abi("C") -> Int
comptime F_l_p = def(Int) thin abi("C") -> Int
comptime F_u64_pu64 = def(Int, UInt64) thin abi("C") -> UInt64
comptime F_u64 = def() thin abi("C") -> UInt64
comptime F_v = def() thin abi("C") -> None
comptime F_v_p = def(Int) thin abi("C") -> None
comptime F_v_pp = def(Int, Int) thin abi("C") -> None
comptime F_v_pip = def(Int, c_int, Int) thin abi("C") -> None
comptime F_v_pu = def(Int, c_uint) thin abi("C") -> None
comptime F_v_u64pn = def(UInt64, Int, Int) thin abi("C") -> None
comptime F_i_ppn = def(Int, Int, Int) thin abi("C") -> c_int
comptime F_i_pi_ = def(Int, c_int) thin abi("C") -> c_int
