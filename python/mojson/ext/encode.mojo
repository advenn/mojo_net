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
from std.memory import bitcast, pack_bits, unsafe_memcpy, unsafe_memmove
from std.os import abort

from json.ryu import shortest

from .capi import (
    Api,
    Obj,
    SURROGATEPASS,
    TPFLAGS_DICT,
    TPFLAGS_LIST,
    TPFLAGS_LONG,
    TPFLAGS_TUPLE,
    TPFLAGS_UNICODE,
    buf,
    compact_int,
    compact_value,
    cstr,
    dict_next,
    float_value,
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
def _copy_scan(dst: Pointer[UInt8, MutUntrackedOrigin], src: Pointer[UInt8, _], n: Int, high: Bool) -> Int:
    """Copy `src`'s `n` bytes to `dst` a 32-byte vector at a time, up to
    the first byte that must be escaped (`_plain_ascii_run`'s set); its
    index, or `n`. One pass, where a copy and then a scan made two. `dst`
    has room to 32 bytes past `n`. A vector that would read past the end
    of `src` is loaded whole only when it stays inside one 4 KiB page
    (which a read past a str's characters cannot fault on); else its bytes
    are gathered one by one."""
    var i = 0
    while i < n:
        var v: SIMD[DType.uint8, 32]
        if n - i >= 32 or ((Int(src) + i) & 4095) <= 4096 - 32:
            v = src.unsafe_load[width=32](i)
        else:
            v = SIMD[DType.uint8, 32](0)
            for k in range(n - i):
                v[k] = src[unsafe_offset=i + k]
        dst.unsafe_store(i, v)
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


comptime _HEX_PAIRS = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
"""Each byte's two lowercase hex digits, for `_u_escape`."""


@inline(.always)
def _u_escape(c: UInt32) -> UInt64:
    """`\\uXXXX` for `c` (below U+10000), as the 6 low bytes of a word:
    each byte's two digits one load from `_HEX_PAIRS`."""
    var t = _HEX_PAIRS.as_bytes().unsafe_ptr()
    var hi = bitcast[DType.uint16, 1](t.unsafe_load[width=2](Int(c >> 8) * 2))
    var lo = bitcast[DType.uint16, 1](t.unsafe_load[width=2](Int(c & 0xFF) * 2))
    return 0x755C | (UInt64(hi) << 16) | (UInt64(lo) << 32)


@inline(.always)
def _put_char(q: Pointer[UInt8, MutUntrackedOrigin], m: Int, c: UInt32, ensure_ascii: Bool, mut wtf8: Bool) -> Int:
    """One character of a str at `q[m]`, as json writes it; where the next
    goes. Each escape or UTF-8 sequence is built in a word and stored once
    (8 bytes, room reserved: 12 a character, and 32 past the end). A lone
    surrogate written as it is (not ensure_ascii) sets `wtf8`."""
    if c < 0x80:
        if c >= 0x20 and c != 34 and c != 92 and not (ensure_ascii and c == 0x7F):
            q[unsafe_offset=m] = UInt8(c)
            return m + 1
        var two: UInt64 = 0
        if c == 34 or c == 92:
            two = UInt64(c)
        elif c == 10:
            two = 110
        elif c == 13:
            two = 114
        elif c == 9:
            two = 116
        elif c == 8:
            two = 98
        elif c == 12:
            two = 102
        if two != 0:
            q.unsafe_store(m, bitcast[DType.uint8, 8](0x5C | (two << 8)))
            return m + 2
        q.unsafe_store(m, bitcast[DType.uint8, 8](_u_escape(c)))
        return m + 6
    if ensure_ascii:
        if c >= 0x10000:
            var v = c - 0x10000
            q.unsafe_store(m, bitcast[DType.uint8, 8](_u_escape(0xD800 | (v >> 10))))
            q.unsafe_store(m + 6, bitcast[DType.uint8, 8](_u_escape(0xDC00 | (v & 0x3FF))))
            return m + 12
        q.unsafe_store(m, bitcast[DType.uint8, 8](_u_escape(c)))
        return m + 6
    var w: UInt64
    var k: Int
    if c < 0x800:
        w = UInt64(0xC0 | (c >> 6)) | (UInt64(0x80 | (c & 0x3F)) << 8)
        k = 2
    elif c < 0x10000:
        if c >= 0xD800 and c <= 0xDFFF:
            wtf8 = True
        w = UInt64(0xE0 | (c >> 12)) | (UInt64(0x80 | ((c >> 6) & 0x3F)) << 8) | (UInt64(0x80 | (c & 0x3F)) << 16)
        k = 3
    else:
        w = (
            UInt64(0xF0 | (c >> 18))
            | (UInt64(0x80 | ((c >> 12) & 0x3F)) << 8)
            | (UInt64(0x80 | ((c >> 6) & 0x3F)) << 16)
            | (UInt64(0x80 | (c & 0x3F)) << 24)
        )
        k = 4
    q.unsafe_store(m, bitcast[DType.uint8, 8](w))
    return m + k


@inline(.always)
def _plain_str(q: Pointer[UInt8, MutUntrackedOrigin], n: Int, s: Obj, high: Bool) -> Int:
    """An exact compact ASCII str of at most 64 characters, with nothing to
    escape, quoted at `q[n]` (room: 130 bytes); the length after it, or -1
    (`q` past `n` garbage, nothing counted) for any other str (`fast_str`)."""
    if not str_is_ascii(s):
        return -1
    var size = str_length(s)
    if size > 64:
        return -1
    q[unsafe_offset=n] = 34
    if _copy_scan(q.unsafe_offset(n + 1), buf(str_data(s)), size, high) != size:
        return -1
    q[unsafe_offset=n + 1 + size] = 34
    return n + size + 2


comptime _STR_START = 256
"""Characters a str written into starts with (`Out.into_str`)."""


struct Out(Movable):
    """The text being written, through a pointer, into one of two stores:

    - raw memory (`PyMem_RawMalloc`, kept by the `Codec` between calls),
      grown by `PyMem_RawRealloc`: realloc moves a large block's pages
      rather than copying them, where a new block and a copy (as a `List`
      grows) wrote and faulted in every page again;
    - the characters of a new ASCII str (`into_str`, for ensure_ascii
      output) or bytes object (`into_bytes`, for dumpb), grown by
      `PyUnicode_Resize` or `_PyBytes_Resize`, which realloc too: the
      object is the result, with no copy at the end.

    On a 1 GB document, the List and the final copy cost 1.2 million page
    faults and 1.2 s in the kernel per dumps.

    `reserve` makes room once (per string, per number); `put` and `copy`
    then write without checks, and `byte` and `bytes` check for
    themselves. Writes may reach 32 bytes past what they count, within
    what was reserved."""

    var api: ApiPtr
    var p: Pointer[UInt8, MutUntrackedOrigin]
    var n: Int
    var cap: Int
    var raw: Int
    """The raw block (0 for none yet), and its size."""
    var raw_cap: Int
    var obj: Obj
    """The str or bytes object written into (0: the raw block)."""
    var bytes_obj: Bool
    var flush_at: Int
    """Text past this many bytes goes to the sink (`Encoder._flush`), at
    the next item boundary: `Int.MAX` but for `dump`."""

    def __init__(out self, api: ApiPtr, raw: Int, raw_cap: Int):
        """Raw memory: `raw` (`raw_cap` bytes, from PyMem_RawMalloc), or
        a new block when 0."""
        self.api = api
        self.raw = raw
        self.raw_cap = raw_cap
        if self.raw == 0:
            self.raw_cap = 4096
            self.raw = api[].PyMem_RawMalloc(self.raw_cap)
            if self.raw == 0:
                abort("mojson: out of memory")
        self.p = Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=self.raw)
        self.n = 0
        self.cap = self.raw_cap
        self.obj = 0
        self.bytes_obj = False
        self.flush_at = Int.MAX

    def into_bytes(mut self):
        """Write into a new bytes object from here on (before anything is
        written); the raw block stays where it was if it cannot be made."""
        ref api = self.api[]
        var b = api.PyBytes_FromStringAndSize(0, _STR_START)
        if not b:
            api.PyErr_Clear()
            return
        self.obj = b
        self.bytes_obj = True
        self.p = buf(api.PyBytes_AsString(b)).unsafe_origin_cast[MutUntrackedOrigin]()
        self.cap = _STR_START

    def into_str(mut self):
        """Write into a new ASCII str from here on (before anything is
        written); the raw block stays where it was if it cannot be made."""
        ref api = self.api[]
        var s = api.PyUnicode_New(_STR_START, 127)
        if not s:
            api.PyErr_Clear()
            return
        self.obj = s
        self.p = buf(str_data(s)).unsafe_origin_cast[MutUntrackedOrigin]()
        self.cap = _STR_START

    def take(mut self) -> Obj:
        """The str or bytes written into, cut to the text: its owner's now
        (0 on a failure, Python's error set)."""
        var s = self.obj
        self.obj = 0
        if self.bytes_obj:
            # (_PyBytes_Resize releases the object when it fails.)
            return s if self.api[]._PyBytes_Resize(out(s), self.n) == 0 else 0
        if self.api[].PyUnicode_Resize(out(s), self.n) != 0:
            self.api[].Py_DecRef(s)
            return 0
        return s

    def drop(mut self):
        """Release the str or bytes written into, if any (after a
        failure, or when the text must be decoded instead)."""
        if self.obj != 0:
            self.api[].Py_DecRef(self.obj)
            self.obj = 0

    @inline(.always)
    def reserve(mut self, k: Int):
        if self.n + k > self.cap:
            self._grow(k)

    @no_inline
    def _grow(mut self, k: Int):
        ref api = self.api[]
        var want = max(2 * self.cap, self.n + k)
        if self.obj != 0:
            var s = self.obj
            if self.bytes_obj:
                if api._PyBytes_Resize(out(s), want) != 0:
                    abort("mojson: out of memory")
                self.p = buf(api.PyBytes_AsString(s)).unsafe_origin_cast[MutUntrackedOrigin]()
            else:
                if api.PyUnicode_Resize(out(s), want) != 0:
                    abort("mojson: out of memory")
                self.p = buf(str_data(s)).unsafe_origin_cast[MutUntrackedOrigin]()
            self.obj = s
        else:
            var b = api.PyMem_RawRealloc(self.raw, want)
            if b == 0:
                abort("mojson: out of memory")
            self.raw = b
            self.raw_cap = want
            self.p = Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=b)
        self.cap = want

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
    def word(mut self, w: UInt64, k: Int):
        """The `k` (at most 8) low bytes of `w`, in memory order (little
        endian, as x86_64 and aarch64 Linux are): one 8-byte store, room
        for all 8 reserved."""
        self.reserve(8)
        self.p.unsafe_store(self.n, bitcast[DType.uint8, 8](w))
        self.n += k

    @inline(.always)
    def byte(mut self, b: UInt8):
        self.reserve(1)
        self.put(b)

    @inline(.always)
    def bytes(mut self, s: Span[UInt8, _]):
        self.reserve(len(s))
        self.copy(s.unsafe_ptr(), len(s))



def _packed(s: List[UInt8]) -> Tuple[UInt64, Int]:
    """`s` as one little-endian word and its length, or (0, -1) past 8
    bytes."""
    if len(s) > 8:
        return (UInt64(0), -1)
    var w: UInt64 = 0
    for i in range(len(s)):
        w |= UInt64(s[i]) << UInt64(8 * i)
    return (w, len(s))


comptime _KEYS = 4096
"""Slots in `KeyBytes` (a power of two). Direct-mapped: the keys of a dict
of 159 (a BestBuy product) collided in a quarter of 512 slots, and
colliding keys pushed each other out on every product."""
comptime _KEY_TEXT = 6 * 64 + 2
"""The longest quoted key kept: 64 characters at their longest escape."""
comptime _KEY_ARENA = 1 << 18
"""Bytes of quoted keys kept before `KeyBytes` starts over."""


struct KeyBytes(Movable):
    """Dict keys already written, by object, as the decoder's `KeyCache`
    keeps keys read: exact str objects with their quoted text, in the
    `ensure_ascii` mode they were written in. Each object is held by a
    reference while it is here, so that no other object can take its
    address. Shared by every dumps call; a key is looked up by its
    address, and its text copied, in place of writing it again."""

    var objs: List[Obj]
    var off: List[Int32]
    var size: List[Int32]
    var text: List[UInt8]
    var used: List[Int32]
    """The slots filled since the last `clear` (each once)."""
    var ascii: Int
    """The mode the texts are in: 1 for ensure_ascii, 0 not, -1 none yet."""

    def __init__(out self):
        self.objs = List[Obj](length=_KEYS, fill=0)
        self.off = List[Int32](length=_KEYS, fill=0)
        self.size = List[Int32](length=_KEYS, fill=0)
        self.text = List[UInt8](capacity=_KEY_ARENA + 32)
        self.used = List[Int32]()
        self.ascii = -1

    def clear(mut self, ref api: Api):
        """Forget every key, releasing its object."""
        for i in self.used:
            var slot = Int(i)
            if self.objs[slot] != 0:
                api.Py_DecRef(self.objs[slot])
                self.objs[slot] = 0
        self.used.clear()
        self.text.clear()

    def mode(mut self, ref api: Api, ensure_ascii: Bool):
        """Start over unless the texts are in this call's mode."""
        if self.ascii != Int(ensure_ascii):
            self.clear(api)
            self.ascii = Int(ensure_ascii)


@inline(.always)
def _copy_blocks(dst: Pointer[UInt8, MutUntrackedOrigin], src: Pointer[UInt8, _], n: Int):
    """`n` bytes a 32-byte block at a time: both `dst` and `src` must have
    room to 32 bytes past `n` (the arena of `KeyBytes`, a reserved `Out`)."""
    var i = 0
    while i < n:
        dst.unsafe_store(i, src.unsafe_load[width=32](i))
        i += 32


@inline(.always)
def _key_slot(k: Obj) -> Int:
    return Int((UInt64(k) * 0x9E3779B97F4A7C15) >> UInt64(52))


comptime FLUSH_AT = 1 << 16
"""`dump` hands its text to `fp.write` in pieces of about this many bytes."""


@inline(.always)
def _utf8_cut(p: Pointer[UInt8, MutUntrackedOrigin], n: Int) -> Int:
    """Where `n` bytes of (W)UTF-8 can be cut so that no sequence is split:
    `n`, or the start of a last sequence not yet whole."""
    var j = n - 1
    while j > 0 and n - j < 4 and (p[unsafe_offset=j] & 0xC0) == 0x80:
        j -= 1
    var b = p[unsafe_offset=j]
    if b < 0x80:
        return n
    var need = 2 if b < 0xE0 else (3 if b < 0xF0 else 4)
    return n if n - j >= need else j


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
    var nonascii: Bool
    """Bytes past ASCII were written as they are (a `raw_type` text), even
    under ensure_ascii."""
    var sink: Obj
    """`fp.write` for `dump` (0 for none)."""
    var use_keys: Bool
    """Keys through `KeyBytes` (not inside another call: its keys may be
    in another `ensure_ascii` mode)."""
    var int_repr: Obj
    """`int.__repr__`, for int subclasses."""
    var raw_type: Obj
    """A str subclass whose text is written as it is (0: none)."""
    var opts: Options
    var keys: Pointer[KeyBytes, MutUntrackedOrigin]
    var item_word: UInt64
    var item_len: Int
    """`opts.item_sep` as one word, or -1 when longer than 8 bytes."""
    var key_word: UInt64
    var key_len: Int

    def __init__(
        out self,
        api: ApiPtr,
        int_repr: Obj,
        raw_type: Obj,
        raw: Int,
        raw_cap: Int,
        var opts: Options,
        keys: Pointer[KeyBytes, MutUntrackedOrigin],
    ):
        self.api = api
        self.item_word, self.item_len = _packed(opts.item_sep)
        self.key_word, self.key_len = _packed(opts.key_sep)
        self.opts = opts^
        self.keys = keys
        self.o = Out(api, raw, raw_cap)
        self.path = List[Obj]()
        self.level = 0
        self.wtf8 = False
        self.nonascii = False
        self.sink = 0
        self.use_keys = True
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

    def _flush(self, final: Bool) raises:
        """The text written so far to the sink, as a str (`dump`): all of
        it when `final`, else up to the last whole UTF-8 sequence. Called
        at item boundaries only, never while a key or value that no
        reference holds is being written: `fp.write` is Python code, and
        may change the object being dumped."""
        ref st = self.s[]
        ref api = st.api[]
        var n = st.o.n
        var cut = n if final else _utf8_cut(st.o.p, n)
        if cut == 0:
            return
        var chunk: Obj
        if st.opts.ensure_ascii and not st.nonascii and api.fast_str:
            chunk = api.PyUnicode_New(cut, 127)
            if chunk:
                unsafe_memcpy(dest=buf(str_data(chunk)), src=st.o.p, count=cut)
        else:
            chunk = api.PyUnicode_DecodeUTF8(Int(st.o.p), cut, cstr(SURROGATEPASS))
        if not chunk:
            self._raised()
        var r = api.PyObject_CallOneArg(st.sink, chunk)
        api.Py_DecRef(chunk)
        if not r:
            self._raised()
        api.Py_DecRef(r)
        var rest = n - cut
        if rest > 0:
            unsafe_memmove(dest=st.o.p, src=st.o.p.unsafe_offset(cut), count=rest)
        st.o.n = rest

    @inline(.always)
    def _null(self):
        self.s[].o.word(0x6C6C756E, 4)  # null

    @inline(.always)
    def _true(self):
        self.s[].o.word(0x65757274, 4)  # true

    @inline(.always)
    def _false(self):
        self.s[].o.word(0x65736C6166, 5)  # false

    @inline(.always)
    def _item_sep(self):
        ref st = self.s[]
        if st.item_len >= 0:
            st.o.word(st.item_word, st.item_len)
        else:
            st.o.bytes(Span(st.opts.item_sep))

    @inline(.always)
    def _key_sep(self):
        ref st = self.s[]
        if st.key_len >= 0:
            st.o.word(st.key_word, st.key_len)
        else:
            st.o.bytes(Span(st.opts.key_sep))

    # ---- scalars -------------------------------------------------------------

    def write_int(self, o: Obj) raises:
        """An exact int."""
        ref api = self.s[].api[]
        if api.fast_int and compact_int(o):
            self._digits(compact_value(o))
            return
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
        """`v` in decimal: its digits counted, then written in pairs where
        they go (the buffer's pointer and length read once)."""
        ref o = self.s[].o
        o.reserve(21)
        var q = o.p
        var m = o.n
        var u = UInt64(v)
        if v < 0:
            q[unsafe_offset=m] = 45
            m += 1
            u = UInt64(0) - UInt64(v)
        var nd = _ndigits(u)
        _digits_fast(q.unsafe_offset(m), u, nd)
        o.n = m + nd

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
        ref out = self.s[].o
        out.reserve(64)
        out.n = _py_float_into(out.p, out.n, x)

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
            ref o = self.s[].o
            o.reserve((12 if kind == 4 else 6) * n + 34)
            if kind == 1:
                # Copied whole, then scanned where it landed (32 bytes of
                # room past it); written again from the first character
                # that needs more than itself. The buffer's pointer and
                # length are read once (stores through the pointer would
                # otherwise make the compiler read them again).
                var p = buf(d)
                var high = ensure_ascii or not str_is_ascii(s)
                var q = o.p
                var start = o.n + 1
                q[unsafe_offset=start - 1] = 34
                var i = _copy_scan(q.unsafe_offset(start), p, n, high)
                if i == n:  # (nothing to escape: the common case)
                    q[unsafe_offset=start + n] = 34
                    o.n = start + n + 1
                    return
                # Then each character to write otherwise, and the run of
                # plain ones after it copied and scanned in one pass again
                # (which writes at most 32 bytes past the run: within the
                # room, since each character before took at least one).
                var m = start + i
                var wtf8 = False
                while i < n:
                    m = _put_char(q, m, UInt32(p[unsafe_offset=i]), ensure_ascii, wtf8)
                    i += 1
                    if i < n:
                        var k = _copy_scan(q.unsafe_offset(m), p.unsafe_offset(i), n - i, high)
                        m += k
                        i += k
                q[unsafe_offset=m] = 34
                o.n = m + 1
                return
            var q = o.p
            var m = o.n
            q[unsafe_offset=m] = 34
            m += 1
            var wtf8 = False
            # Characters 16 (or 8) at a time while they are plain ASCII,
            # narrowed to bytes and stored at once; the others one by one.
            var i = 0
            if kind == 2:
                var p = Pointer[UInt16, MutAnyOrigin](unsafe_from_address=d)
                while i < n:
                    if i + 16 <= n:
                        var v = p.unsafe_load[width=16](i)
                        var special = (
                            v.ge(SIMD[DType.uint16, 16](0x7F if ensure_ascii else 0x80))
                            | v.lt(SIMD[DType.uint16, 16](0x20))
                            | v.eq(SIMD[DType.uint16, 16](34))
                            | v.eq(SIMD[DType.uint16, 16](92))
                        )
                        var bits = pack_bits[DType.uint16](special)
                        q.unsafe_store(m, v.cast[DType.uint8]())
                        if bits == 0:
                            m += 16
                            i += 16
                            continue
                        var k = Int(count_trailing_zeros(bits))
                        m += k
                        i += k
                    m = _put_char(q, m, UInt32(p[unsafe_offset=i]), ensure_ascii, wtf8)
                    i += 1
            else:
                var p = Pointer[UInt32, MutAnyOrigin](unsafe_from_address=d)
                while i < n:
                    if i + 8 <= n:
                        var v = p.unsafe_load[width=8](i)
                        var special = (
                            v.ge(SIMD[DType.uint32, 8](0x7F if ensure_ascii else 0x80))
                            | v.lt(SIMD[DType.uint32, 8](0x20))
                            | v.eq(SIMD[DType.uint32, 8](34))
                            | v.eq(SIMD[DType.uint32, 8](92))
                        )
                        var bits = pack_bits[DType.uint8](special)
                        q.unsafe_store(m, v.cast[DType.uint8]())
                        if bits == 0:
                            m += 8
                            i += 8
                            continue
                        var k = Int(count_trailing_zeros(bits))
                        m += k
                        i += k
                    m = _put_char(q, m, p[unsafe_offset=i], ensure_ascii, wtf8)
                    i += 1
            q[unsafe_offset=m] = 34
            o.n = m + 1
            if wtf8:
                self.s[].wtf8 = True
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

    @inline(.always)
    def _write_scalar(self, v: Obj) raises -> Bool:
        """`v` written if it is None, a bool, or an exact str, int or float,
        whose writing runs no Python code (so that a borrowed `v` needs no
        reference held); False, nothing written, for anything else."""
        ref st = self.s[]
        ref api = st.api[]
        if v == api.none:
            self._null()
            return True
        if v == api.true:
            self._true()
            return True
        if v == api.false:
            self._false()
            return True
        var t = api.type_of(v)
        if t == api.str_type:
            self.write_str(v, st.opts.ensure_ascii)
            return True
        if t == api.int_type:
            if api.fast_int and compact_int(v):
                self._digits(compact_value(v))
            else:
                self.write_int(v)
            return True
        if t == api.float_type:
            self.write_float(v, float_value(v) if api.fast_float else api.PyFloat_AsDouble(v), st.opts.allow_nan)
            return True
        if t == api.list_type and api.fast_list and load_int(v + 16) == 0:
            self._put("[]")
            return True
        return False

    def write(self, o: Obj) raises:
        """Any value."""
        ref opts = self.s[].opts
        ref api = self.s[].api[]
        if self._write_scalar(o):
            return
        var t = api.type_of(o)
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
            var start = self.s[].o.n
            self._utf8_of(o)
            for i in range(start, self.s[].o.n):
                if self.s[].o.p[unsafe_offset=i] >= 0x80:
                    self.s[].nonascii = True
                    break
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

    def _write_exact_list(self, o: Obj) raises:
        """An exact list, its items read from its array (`fast_list`): a
        scalar borrowed (`_write_scalar`), anything else held by a
        reference while it is written. The length and the array are read
        again for each item, since Python code (a `default`, `fp.write`)
        may change the list between them."""
        ref opts = self.s[].opts
        ref api = self.s[].api[]
        if load_int(o + 16) == 0:  # (ob_size)
            self._put("[]")
            return
        self._enter(o)
        self.s[].o.byte(91)
        if opts.has_indent:
            self.s[].level += 1
            self._newline()
        var i = 0
        # Without an indent, the separator and the items that are None, a
        # bool or a compact int are written with the buffer's pointer,
        # length and capacity in locals, kept from item to item: through
        # `Out`, each write loaded the length its last one stored, a chain
        # through memory that bounded the loop. They go back to `Out`
        # before anything else is written, and are read again after.
        var fast = not opts.has_indent and self.s[].item_len >= 0 and api.fast_int
        var item_word = self.s[].item_word
        var item_len = self.s[].item_len
        ref ob = self.s[].o
        var q = ob.p
        var n = ob.n
        var cap = ob.cap
        while i < load_int(o + 16):
            try:
                if fast:
                    if n >= ob.flush_at:
                        ob.n = n
                        self._flush(False)
                        q = ob.p
                        n = ob.n
                        cap = ob.cap
                        if i >= load_int(o + 16):
                            break
                    if n + 72 > cap:
                        ob.n = n
                        ob._grow(72)
                        q = ob.p
                        cap = ob.cap
                    if i > 0:
                        q.unsafe_store(n, bitcast[DType.uint8, 8](item_word))
                        n += item_len
                    var item = load_int(api.list_items(o) + 8 * i)
                    i += 1
                    if item == api.none:
                        q.unsafe_store(n, bitcast[DType.uint8, 8](UInt64(0x6C6C756E)))
                        n += 4
                        continue
                    if item == api.true:
                        q.unsafe_store(n, bitcast[DType.uint8, 8](UInt64(0x65757274)))
                        n += 4
                        continue
                    if item == api.false:
                        q.unsafe_store(n, bitcast[DType.uint8, 8](UInt64(0x65736C6166)))
                        n += 5
                        continue
                    var t = api.type_of(item)
                    if t == api.float_type and api.fast_float:
                        var x = float_value(item)
                        if x - x == 0:  # (finite)
                            n = _py_float_into(q, n, x)
                            continue
                    elif t == api.int_type and compact_int(item):
                        var v = compact_value(item)
                        var u = UInt64(v)
                        if v < 0:
                            q[unsafe_offset=n] = 45
                            n += 1
                            u = UInt64(0) - UInt64(v)
                        var nd = _ndigits(u)
                        _digits_fast(q.unsafe_offset(n), u, nd)
                        n += nd
                        continue
                    ob.n = n
                    if not self._write_scalar(item):
                        api.Py_IncRef(item)
                        try:
                            self.write(item)
                        except e:
                            api.Py_DecRef(item)
                            raise e^
                        api.Py_DecRef(item)
                    q = ob.p
                    n = ob.n
                    cap = ob.cap
                    continue
                if self.s[].o.n >= self.s[].o.flush_at:
                    self._flush(False)
                    if i >= load_int(o + 16):
                        break
                if i > 0:
                    self._item_sep()
                    if opts.has_indent:
                        self._newline()
                var item = load_int(api.list_items(o) + 8 * i)
                if not self._write_scalar(item):
                    api.Py_IncRef(item)
                    try:
                        self.write(item)
                    except e:
                        api.Py_DecRef(item)
                        raise e^
                    api.Py_DecRef(item)
            except e:
                self._leave()
                raise e^
            i += 1
        if fast:
            ob.n = n
        if opts.has_indent:
            self.s[].level -= 1
            self._newline()
        self.s[].o.byte(93)
        self._leave()

    def write_list(self, o: Obj) raises:
        """A list or tuple (or subclass), by its items."""
        ref opts = self.s[].opts
        ref api = self.s[].api[]
        if api.fast_list and api.type_of(o) == api.list_type:
            self._write_exact_list(o)
            return
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
            if self.s[].o.n >= self.s[].o.flush_at:
                # (Before an item is taken: `fp.write` may change the
                # list, so its length is read again after.)
                try:
                    self._flush(False)
                except e:
                    api.Py_DecRef(seq)
                    self._leave()
                    raise e^
                if i >= load_int(seq + 16):
                    break
            if i > 0:
                self._item_sep()
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
        if t == api.str_type and self.s[].use_keys:
            self._str_key(k)
            return True
        if t == api.str_type:
            self.write_str(k, opts.ensure_ascii)
            return True
        if (api.PyType_GetFlags(t) & TPFLAGS_UNICODE) != 0:
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

    @inline(.always)
    def _str_key(self, k: Obj) raises:
        """An exact str key: its text from `KeyBytes` when it is there,
        else written, then kept (unless long, or holding a lone surrogate,
        whose WTF-8 the caller must know of)."""
        ref st = self.s[]
        ref keys = st.keys[]
        var slot = _key_slot(k)
        if keys.objs.unsafe_ptr()[unsafe_offset=slot] == k:
            var size = Int(keys.size.unsafe_ptr()[unsafe_offset=slot])
            st.o.reserve(size + 32)
            _copy_blocks(
                st.o.p.unsafe_offset(st.o.n),
                keys.text.unsafe_ptr().unsafe_offset(Int(keys.off.unsafe_ptr()[unsafe_offset=slot])),
                size,
            )
            st.o.n += size
            return
        var start = st.o.n
        var wtf8 = st.wtf8
        st.wtf8 = False
        self.write_str(k, st.opts.ensure_ascii)
        var surrogate = st.wtf8
        st.wtf8 = wtf8 or surrogate
        var size = st.o.n - start
        if surrogate or size > _KEY_TEXT:
            return
        if load_int(k) <= 1:
            # (Its dict holds the only reference, `ob_refcnt`: no other
            # dict can share it, and keeping it would push out a key that
            # comes again.)
            return
        ref api = st.api[]
        if len(keys.text) + size > _KEY_ARENA:
            keys.clear(api)
        var old = keys.objs[slot]
        if old != 0:
            api.Py_DecRef(old)
        else:
            keys.used.append(Int32(slot))
        api.Py_IncRef(k)
        keys.objs[slot] = k
        keys.off[slot] = Int32(len(keys.text))
        keys.size[slot] = Int32(size)
        keys.text.extend(Span[UInt8, MutUntrackedOrigin](unsafe_ptr=st.o.p.unsafe_offset(start), length=size))

    @inline(.always)
    def _scalar(self, v: Obj) -> Bool:
        """Whether writing `v` can run no Python code (None, a bool, or an
        exact str, int or float), so that it needs no reference held."""
        ref api = self.s[].api[]
        if v == api.none or v == api.true or v == api.false:
            return True
        var t = api.type_of(v)
        return t == api.str_type or t == api.int_type or t == api.float_type

    def _pair(self, k: Obj, v: Obj, mut first: Bool) raises:
        """One pair: the separator (with the indent's line) unless first,
        then the key (or nothing at all, the key skipped) and the value."""
        ref opts = self.s[].opts
        var mark = self.s[].o.n
        if not first:
            self._item_sep()
            if opts.has_indent:
                self._newline()
        if not self._key(k):
            self.s[].o.n = mark
            return
        first = False
        self._key_sep()
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
                ref st = self.s[]
                ref keys = st.keys[]
                var fast = not opts.has_indent and st.item_len >= 0 and st.key_len >= 0 and st.use_keys
                var fast_values = fast and api.fast_str and api.fast_int
                # A combined table's entries are read as PyDict_Next reads
                # them, without the call (`capi.dict_next`); a split one
                # (an instance's `__dict__`) stays split, and goes through
                # PyDict_Next.
                var direct = api.fast_dict and load_int(o + 40) == 0
                var item_word = st.item_word
                var item_len = st.item_len
                var key_word = st.key_word
                var key_len = st.key_len
                var high = opts.ensure_ascii
                # The buffer's pointer, length and capacity in locals, kept
                # from pair to pair (see `_write_exact_list`): they go back
                # to `Out` before anything else writes, and are read again
                # after.
                ref ob = st.o
                var q = ob.p
                var n = ob.n
                var cap = ob.cap
                while True:
                    # The sink is written to before the next pair is
                    # taken (borrowed): `fp.write` may change the dict.
                    if n >= ob.flush_at:
                        ob.n = n
                        self._flush(False)
                        q = ob.p
                        n = ob.n
                        cap = ob.cap
                    if direct:
                        if not dict_next(o, pos, k, v):
                            break
                    elif api.PyDict_Next(o, out(pos), out(k), out(v)) == 0:
                        break
                    # A str key already in `KeyBytes`: the separator, its
                    # text and the key separator stored at once, room
                    # reserved once, and a value that is None, a bool, a
                    # compact int or a short ASCII str with nothing to
                    # escape with them.
                    if fast and api.type_of(k) == api.str_type:
                        var slot = _key_slot(k)
                        if keys.objs.unsafe_ptr()[unsafe_offset=slot] == k:
                            var size = Int(keys.size.unsafe_ptr()[unsafe_offset=slot])
                            if n + size + 160 > cap:
                                ob.n = n
                                ob._grow(size + 160)
                                q = ob.p
                                cap = ob.cap
                            if not first:
                                q.unsafe_store(n, bitcast[DType.uint8, 8](item_word))
                                n += item_len
                            first = False
                            _copy_blocks(
                                q.unsafe_offset(n),
                                keys.text.unsafe_ptr().unsafe_offset(Int(keys.off.unsafe_ptr()[unsafe_offset=slot])),
                                size,
                            )
                            n += size
                            q.unsafe_store(n, bitcast[DType.uint8, 8](key_word))
                            n += key_len
                            if v == api.none:
                                q.unsafe_store(n, bitcast[DType.uint8, 8](UInt64(0x6C6C756E)))
                                n += 4
                                continue
                            if v == api.true:
                                q.unsafe_store(n, bitcast[DType.uint8, 8](UInt64(0x65757274)))
                                n += 4
                                continue
                            if v == api.false:
                                q.unsafe_store(n, bitcast[DType.uint8, 8](UInt64(0x65736C6166)))
                                n += 5
                                continue
                            if fast_values:
                                var t = api.type_of(v)
                                if t == api.str_type:
                                    var m = _plain_str(q, n, v, high)
                                    if m >= 0:
                                        n = m
                                        continue
                                elif t == api.float_type and api.fast_float:
                                    var x = float_value(v)
                                    if x - x == 0:  # (finite)
                                        n = _py_float_into(q, n, x)
                                        continue
                                elif t == api.int_type and compact_int(v):
                                    var iv = compact_value(v)
                                    var u = UInt64(iv)
                                    if iv < 0:
                                        q[unsafe_offset=n] = 45
                                        n += 1
                                        u = UInt64(0) - UInt64(iv)
                                    var nd = _ndigits(u)
                                    _digits_fast(q.unsafe_offset(n), u, nd)
                                    n += nd
                                    continue
                            ob.n = n
                            if not self._write_scalar(v):
                                api.Py_IncRef(v)
                                try:
                                    self.write(v)
                                except e:
                                    api.Py_DecRef(v)
                                    raise e^
                                api.Py_DecRef(v)
                            q = ob.p
                            n = ob.n
                            cap = ob.cap
                            continue
                    # The key is written before any Python code can run
                    # (only a value's `default`, or a container's, can),
                    # so it needs no reference held; nor does a value
                    # whose writing runs none.
                    ob.n = n
                    if self._scalar(v):
                        self._pair(k, v, first)
                    else:
                        api.Py_IncRef(v)
                        try:
                            self._pair(k, v, first)
                        except e:
                            api.Py_DecRef(v)
                            raise e^
                        api.Py_DecRef(v)
                    q = ob.p
                    n = ob.n
                    cap = ob.cap
                ob.n = n
            else:
                var items = api.PyMapping_Items(o)
                if not items:
                    self._raised()
                if opts.sort_keys and api.PyList_Sort(items) < 0:
                    api.Py_DecRef(items)
                    self._raised()
                var i = 0
                while i < load_int(items + 16):
                    if self.s[].o.n >= self.s[].o.flush_at:
                        try:
                            self._flush(False)
                        except e:
                            api.Py_DecRef(items)
                            raise e^
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
def _ndigits(u: UInt64) -> Int:
    """How many decimal digits `u` has (1 for 0): from its bit length
    (log10(2) ~ 1233 / 4096), then one comparison with the power of ten
    that may have been missed."""
    if u < 10:
        return 1
    var n = ((64 - Int(count_leading_zeros(u))) * 1233) >> 12
    if u >= materialize[_POW10]().unsafe_get(n):
        n += 1
    return n


@inline(.always)
def _pair_at(t: Pointer[UInt8, ImmutAnyOrigin], i: UInt64) -> UInt64:
    """The two digits of `i` (< 100) from `_DIGIT_PAIRS`, as 2 bytes."""
    return UInt64(bitcast[DType.uint16, 1](t.unsafe_load[width=2](Int(i) * 2)))


@inline(.always)
def _eight_digits(v: UInt64) -> UInt64:
    """The 8 digits of `v` (< 10^8, leading zeros kept) as 8 ASCII bytes
    in memory order, by arithmetic within one word: the two halves of four
    digits in 32-bit lanes, each split into its hundreds and the rest
    (x * 10486 >> 20 is x // 100 below 43,699), giving four 16-bit lanes
    below 100, each split into tens and ones (x * 103 >> 10 is x // 10
    below 179). A lane's product never reaches the next lane, and the
    masks drop what each shift brings down from the lane above."""
    var merged = (v // 10000) | ((v % 10000) << 32)
    var hundreds = ((merged * 10486) >> 20) & 0x0000007F0000007F
    var lanes = hundreds | ((merged - hundreds * 100) << 16)
    var tens = ((lanes * 103) >> 10) & 0x000F000F000F000F
    var ones = lanes - tens * 10
    return (tens | (ones << 8)) + 0x3030303030303030


@inline(.always)
def _digits_fast(dst: Pointer[UInt8, MutUntrackedOrigin], v: UInt64, n: Int):
    """The `n` (`_ndigits(v)`) digits of `v` at `dst`, 8 at a time: the
    leading 1 to 8 first, as one 8-byte store, then each full group of 8
    after them. Writes up to 8 bytes from `dst`, past `n` when `n` < 8."""
    var groups = (n - 1) >> 3
    var lead = n - 8 * groups
    var top = v
    var g1: UInt64 = 0
    var g0: UInt64 = 0
    if groups >= 1:
        top = v // 100000000
        g0 = v - top * 100000000
        if groups == 2:
            var t2 = top // 100000000
            g1 = top - t2 * 100000000
            top = t2
    dst.unsafe_store(0, bitcast[DType.uint8, 8](_eight_digits(top) >> UInt64(8 * (8 - lead))))
    if groups == 2:
        dst.unsafe_store(lead, bitcast[DType.uint8, 8](_eight_digits(g1)))
        dst.unsafe_store(lead + 8, bitcast[DType.uint8, 8](_eight_digits(g0)))
    elif groups == 1:
        dst.unsafe_store(lead, bitcast[DType.uint8, 8](_eight_digits(g0)))


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


@inline(.always)
def _py_float_into(q: Pointer[UInt8, MutUntrackedOrigin], m0: Int, x: Float64) -> Int:
    """Finite `x` as `float.__repr__` writes it, at `q[m0]` (64 bytes of
    room); the length after it. The shortest digits that read back as `x`
    (Ryū), plain from 1e-4 up to 1e16 (`.0` after an integer), else with an
    exponent of at least two digits. The digits go to a small buffer first,
    then into place a vector at a time, the point between them stored
    after."""
    var s = shortest(x)
    var m = m0
    if s.negative:
        q[unsafe_offset=m] = 45
        m += 1
    if s.digits == 0:
        q.unsafe_store(m, bitcast[DType.uint8, 4](UInt32(0x302E30)))  # 0.0
        return m + 3
    var n = _ndigits(s.digits)
    var tmp = Array[UInt8, 48](uninitialized=True)
    var t = tmp.unsafe_ptr().unsafe_origin_cast[MutUntrackedOrigin]()
    _digits_fast(t, s.digits, n)
    var decpt = n + s.exponent
    if decpt <= -4 or decpt > 16:
        q[unsafe_offset=m] = t[unsafe_offset=0]
        if n > 1:
            q[unsafe_offset=m + 1] = 46
            q.unsafe_store(m + 2, t.unsafe_load[width=16](1))
            m += n + 1
        else:
            m += 1
        var e = decpt - 1
        q[unsafe_offset=m] = 101
        q[unsafe_offset=m + 1] = UInt8(45) if e < 0 else UInt8(43)
        var a = UInt64(-e if e < 0 else e)
        var pairs = _DIGIT_PAIRS.as_bytes().unsafe_ptr().unsafe_origin_cast[ImmutAnyOrigin]()
        if a < 100:
            q.unsafe_store(m + 2, bitcast[DType.uint8, 2](UInt16(_pair_at(pairs, a))))
            return m + 4
        q[unsafe_offset=m + 2] = UInt8(48) + UInt8(a // 100)
        q.unsafe_store(m + 3, bitcast[DType.uint8, 2](UInt16(_pair_at(pairs, a % 100))))
        return m + 5
    if decpt <= 0:
        q.unsafe_store(m, bitcast[DType.uint8, 8](UInt64(0x3030303030302E30)))  # 0.000000
        m += 2 - decpt
        q.unsafe_store(m, t.unsafe_load[width=32](0))
        return m + n
    if decpt >= n:
        q.unsafe_store(m, t.unsafe_load[width=16](0))
        q.unsafe_store(m + n, SIMD[DType.uint8, 16](48))
        m += decpt
        q.unsafe_store(m, bitcast[DType.uint8, 2](UInt16(0x302E)))  # .0
        return m + 2
    q.unsafe_store(m, t.unsafe_load[width=16](0))
    q[unsafe_offset=m + decpt] = 46
    q.unsafe_store(m + decpt + 1, t.unsafe_load[width=16](decpt))
    return m + n + 1
