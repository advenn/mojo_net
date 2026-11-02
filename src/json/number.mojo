"""A JSON number's text read as the nearest Float64, fast: `read_float`.

Up to 19 significant digits (any number of leading and, after the point,
trailing zeros aside) are read into one integer w, so the number is
w * 10^q exactly. Then:

- **Clinger's fast path:** w at most 2^53 and q in [-22, 22]: w and 10^|q|
  are both exact Float64s, and one IEEE multiplication or division of
  exact values is correctly rounded.
- **The Eisel-Lemire algorithm** (Daniel Lemire, "Number Parsing at a
  Gigabyte per Second", Software: Practice and Experience, 2021), as
  fast_float computes it: w normalized, times a 128-bit approximation of
  5^q (`lemire_tables`, from tools/gen_ryu_tables.py), the round to even
  done on the bits that product leaves exact. Noble Mushtak and Daniel
  Lemire ("Fast number parsing without fallback", 2023) proved that for
  such w the 128-bit product always decides, so no case is undecided.

`read_float` returns False, and the caller reads the text some slower way
(Mojo's `atof`, Python's `PyOS_string_to_double`), for more than 19
significant digits and for results below the normal range (subnormals),
which fast_float rounds by a path of its own. A text past the range reads
as an infinity, as Python's float() reads it; `Document.float` refuses
that one."""

from std.bit import count_leading_zeros, count_trailing_zeros
from std.memory import bitcast

from .lemire_tables import POW5_128, POW5_128_MAX_Q, POW5_128_MIN_Q

comptime _POW10: Array[Float64, 23] = [
    1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11,
    1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22,
]
"""The powers of ten that are exact Float64s."""


@inline(.always)
def _digit(c: UInt8) -> Bool:
    return c >= 48 and c <= 57


@inline(.always)
def _eight(p: Pointer[UInt8, _], i: Int, mut value: UInt64) -> Bool:
    """Whether the 8 bytes at `i` are all digits, and if so their value:
    the SWAR test and sum of simdjson and fast_float (a byte b is a digit
    when its top nibble is 3 and b + 6 keeps it 3)."""
    var v = bitcast[DType.uint64, 1](p.unsafe_load[width=8](i))
    if ((v & 0xF0F0F0F0F0F0F0F0) | (((v + 0x0606060606060606) & 0xF0F0F0F0F0F0F0F0) >> 4)) != 0x3333333333333333:
        return False
    v -= 0x3030303030303030
    v = (v * 10) + (v >> 8)
    value = (((v & 0x000000FF000000FF) * (100 + (1000000 << 32))) + (((v >> 16) & 0x000000FF000000FF) * (1 + (10000 << 32)))) >> 32
    return True


@inline(.always)
def _up_to_eight(p: Pointer[UInt8, _], i: Int, limit: Int, mut value: UInt64) -> Int:
    """How many digits (0 to 8, at most `limit`) start at `i`, and their
    value: one 8-byte load, the digits found by their bytes' top bits
    (b ^ '0' + 0x76 sets it for a byte that is no digit) and moved to the
    top of the word, where the 8-digit sum reads the zeros below them as
    leading zeros."""
    var t = bitcast[DType.uint64, 1](p.unsafe_load[width=8](i)) ^ 0x3030303030303030
    var m = ((t + 0x7676767676767676) | t) & 0x8080808080808080
    var k = 8 if m == 0 else Int(count_trailing_zeros(m)) >> 3
    k = min(k, limit)
    if k == 0:
        value = 0
        return 0
    if k < 8:
        t = (t & ((UInt64(1) << UInt64(8 * k)) - 1)) << UInt64(8 * (8 - k))
    t = (t * 10) + (t >> 8)
    value = (((t & 0x000000FF000000FF) * (100 + (1000000 << 32))) + (((t >> 16) & 0x000000FF000000FF) * (1 + (10000 << 32)))) >> 32
    return k


comptime _POW10_INT: Array[UInt64, 9] = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000]


def read_float[padded: Bool = False](text: Span[UInt8, _], mut out: Float64) -> Bool:
    """`text`, a number in JSON's grammar, as the nearest Float64 in
    `out`; False when it is the caller's to read (see the module docs).
    Digits go eight at a time; with `padded` (the caller's word that 8
    bytes past the text can be read, as a `Document`'s spans can:
    `SPAN_SLACK`), the last few too."""
    var p = text.unsafe_ptr()
    var n = len(text)
    var i = 0
    var neg = n > 0 and p[unsafe_offset=0] == 45
    if neg:
        i = 1
    var w: UInt64 = 0
    var digits = 0
    var q = 0
    var eight: UInt64 = 0
    var pow10 = materialize[_POW10_INT]()
    if i >= n or not _digit(p[unsafe_offset=i]):
        return False
    if p[unsafe_offset=i] == 48:
        i += 1  # (JSON's integer part is 0, or has no leading zero)
    else:
        comptime if padded:
            while digits <= 11:
                var k = _up_to_eight(p, i, n - i, eight)
                w = w * pow10.unsafe_get(k) + eight
                digits += k
                i += k
                if k < 8:
                    break
        else:
            while i + 8 <= n and digits <= 11 and _eight(p, i, eight):
                w = w * 100000000 + eight
                digits += 8
                i += 8
        while i < n and _digit(p[unsafe_offset=i]):
            if digits == 19:
                return False
            w = w * 10 + UInt64(p[unsafe_offset=i] - 48)
            digits += 1
            i += 1
    if i < n and p[unsafe_offset=i] == 46:  # '.'
        i += 1
        var start = i
        if w == 0:
            while i < n and p[unsafe_offset=i] == 48:
                q -= 1
                i += 1
        comptime if padded:
            while digits <= 11:
                var k = _up_to_eight(p, i, n - i, eight)
                w = w * pow10.unsafe_get(k) + eight
                digits += k
                q -= k
                i += k
                if k < 8:
                    break
        else:
            while i + 8 <= n and digits <= 11 and _eight(p, i, eight):
                w = w * 100000000 + eight
                digits += 8
                q -= 8
                i += 8
        while i < n and _digit(p[unsafe_offset=i]):
            if digits == 19:
                return False
            w = w * 10 + UInt64(p[unsafe_offset=i] - 48)
            digits += 1
            q -= 1
            i += 1
        if i == start:
            return False
    if i < n and (p[unsafe_offset=i] | 0x20) == 101:  # e E
        i += 1
        var eneg = False
        if i < n and (p[unsafe_offset=i] == 43 or p[unsafe_offset=i] == 45):
            eneg = p[unsafe_offset=i] == 45
            i += 1
        var e = 0
        var first = i
        while i < n and _digit(p[unsafe_offset=i]):
            if e < 100000:
                e = e * 10 + Int(p[unsafe_offset=i] - 48)
            i += 1
        if i == first:
            return False
        q += -e if eneg else e
    if i != n:
        return False
    if w == 0:
        out = -0.0 if neg else 0.0
        return True
    if w <= (UInt64(1) << 53) and q >= -22 and q <= 22:
        var x = Float64(w)
        x = x / materialize[_POW10]().unsafe_get(-q) if q < 0 else x * materialize[_POW10]().unsafe_get(q)
        out = -x if neg else x
        return True
    if q < POW5_128_MIN_Q:
        out = -0.0 if neg else 0.0
        return True
    if q > POW5_128_MAX_Q:
        out = FloatLiteral.negative_infinity if neg else FloatLiteral.infinity
        return True
    var lz = Int(count_leading_zeros(w))
    w <<= UInt64(lz)
    var index = 2 * (q - POW5_128_MIN_Q)
    var product = UInt128(w) * UInt128(materialize[POW5_128]().unsafe_get(index))
    var hi = UInt64(product >> 64)
    var lo = UInt64(product & 0xFFFFFFFFFFFFFFFF)
    if (hi & 0x1FF) == 0x1FF:  # (55 bits of precision may not be enough)
        var second = UInt64((UInt128(w) * UInt128(materialize[POW5_128]().unsafe_get(index + 1))) >> 64)
        lo += second
        if second > lo:
            hi += 1
    var upperbit = Int(hi >> 63)
    var shift = upperbit + 9
    var mantissa = hi >> UInt64(shift)
    var power2 = (((152170 + 65536) * q) >> 16) + 63 + upperbit - lz + 1023
    if power2 <= 0:
        return False  # (a subnormal: the caller's)
    # Exactly between two doubles (only possible for q in [-4, 23], where
    # 5^q's product is exact): round to even, not up.
    if lo <= 1 and q >= -4 and q <= 23 and (mantissa & 3) == 1:
        if (mantissa << UInt64(shift)) == hi:
            mantissa &= ~UInt64(1)
    mantissa += mantissa & 1
    mantissa >>= 1
    if mantissa >= (UInt64(2) << 52):
        mantissa = UInt64(1) << 52
        power2 += 1
    mantissa &= ~(UInt64(1) << 52)
    if power2 >= 0x7FF:
        out = FloatLiteral.negative_infinity if neg else FloatLiteral.infinity
        return True
    var bits = mantissa | (UInt64(power2) << 52) | (UInt64(1) << 63 if neg else UInt64(0))
    out = bitcast[DType.float64, 1](bits)
    return True
