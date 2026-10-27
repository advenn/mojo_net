"""Shortest round-trip formatting of a Float64: the fewest decimal digits
that read back as the same double, the nearest such when there are
several (ties to even).

The digits come from Ryū (Ulf Adams, "Ryū: fast float-to-string
conversion", PLDI 2018), ported from the reference d2s.c
(github.com/ulfjack/ryu, Apache-2.0); its tables are generated, not
copied (tools/gen_ryu_tables.py). Mojo's `String(Float64)` is not used:
it does not always round-trip.

The layout is ECMAScript's Number::toString, as JSON.stringify writes
numbers: plain digits from 1e-6 up to 1e21 ("0.001", "1.5",
"100000000000000000000"), exponents outside it ("1e+21", "1.5e-7"); an
integral value has no ".0". One difference: negative zero is "-0" (it
reads back as -0.0), where ECMAScript writes "0".
"""

from std.memory import bitcast

from .error import JsonError
from .ryu_tables import POW5_BITCOUNT, POW5_INV_BITCOUNT, POW5_INV_SPLIT, POW5_SPLIT

comptime _MANTISSA_BITS = 52
comptime _EXPONENT_BITS = 11
comptime _BIAS = 1023
comptime MAX_FLOAT_LENGTH = 25
"""The longest text `write_float` writes: "-0.0000012345678901234567"."""


@fieldwise_init
struct Shortest(Equatable, TrivialRegisterPassable, Writable):
    """A finite double as `digits` * 10^`exponent`, `digits` as short as
    round-tripping allows (no trailing zeros); zero is (0, 0)."""

    var negative: Bool
    var digits: UInt64
    var exponent: Int

    def __eq__(self, other: Self) -> Bool:
        return self.negative == other.negative and self.digits == other.digits and self.exponent == other.exponent

    def write_to(self, mut writer: Some[Writer]):
        writer.write("-" if self.negative else "", self.digits, "e", self.exponent)


@inline(.always)
def _pow5bits(e: Int) -> Int:
    """ceil(log2(5^e)) for e in [1, 3528]; 1 for 0."""
    return ((e * 1217359) >> 19) + 1


@inline(.always)
def _log10_pow2(e: Int) -> Int:
    """floor(log10(2^e)) for e in [0, 1650]."""
    return (e * 78913) >> 18


@inline(.always)
def _log10_pow5(e: Int) -> Int:
    """floor(log10(5^e)) for e in [0, 2620]."""
    return (e * 732923) >> 20


def _pow5_factor(v: UInt64) -> Int:
    var value = v
    var count = 0
    while True:
        var q = value // 5
        if value - 5 * q != 0:
            return count
        value = q
        count += 1


@inline(.always)
def _multiple_of_pow5(value: UInt64, p: Int) -> Bool:
    return _pow5_factor(value) >= p


@inline(.always)
def _multiple_of_pow2(value: UInt64, p: Int) -> Bool:
    """`p` < 64."""
    return (value & ((UInt64(1) << UInt64(p)) - 1)) == 0


@inline(.always)
def _mul_shift(m: UInt64, lo: UInt64, hi: UInt64, j: Int) -> UInt64:
    """(m * (hi * 2^64 + lo)) >> j, for j in [64, 128)."""
    var b0 = UInt128(m) * UInt128(lo)
    var b2 = UInt128(m) * UInt128(hi)
    return UInt64(((b0 >> 64) + b2) >> UInt128(j - 64))


def _d2d(ieee_mantissa: UInt64, ieee_exponent: Int) -> Shortest:
    """d2d of the reference: the shortest digits of a positive double."""
    var e2: Int
    var m2: UInt64
    if ieee_exponent == 0:
        e2 = 1 - _BIAS - _MANTISSA_BITS - 2
        m2 = ieee_mantissa
    else:
        e2 = ieee_exponent - _BIAS - _MANTISSA_BITS - 2
        m2 = (UInt64(1) << _MANTISSA_BITS) | ieee_mantissa
    var accept_bounds = (m2 & 1) == 0
    # The interval of values that read back as this double, in units of
    # 2^e2: [mv - 1 - mm_shift, mv + 2] around mv (mm_shift is 0 at a power
    # of two, where the gap below is half the gap above).
    var mv = 4 * m2
    var mm_shift = UInt64(1) if (ieee_mantissa != 0 or ieee_exponent <= 1) else UInt64(0)

    var vr: UInt64
    var vp: UInt64
    var vm: UInt64
    var e10: Int
    var vm_trailing_zeros = False
    var vr_trailing_zeros = False
    if e2 >= 0:
        var q = _log10_pow2(e2) - (1 if e2 > 3 else 0)
        e10 = q
        var k = POW5_INV_BITCOUNT + _pow5bits(q) - 1
        var i = -e2 + q + k
        var lo = materialize[POW5_INV_SPLIT]().unsafe_get(2 * q)
        var hi = materialize[POW5_INV_SPLIT]().unsafe_get(2 * q + 1)
        vr = _mul_shift(mv, lo, hi, i)
        vp = _mul_shift(mv + 2, lo, hi, i)
        vm = _mul_shift(mv - 1 - mm_shift, lo, hi, i)
        if q <= 21:
            # Only one of mv, mv + 2 and mv - 1 - mm_shift can be a
            # multiple of 5, if any.
            if mv - 5 * (mv // 5) == 0:
                vr_trailing_zeros = _multiple_of_pow5(mv, q)
            elif accept_bounds:
                vm_trailing_zeros = _multiple_of_pow5(mv - 1 - mm_shift, q)
            elif _multiple_of_pow5(mv + 2, q):
                vp -= 1
    else:
        var q = _log10_pow5(-e2) - (1 if -e2 > 1 else 0)
        e10 = q + e2
        var i = -e2 - q
        var k = _pow5bits(i) - POW5_BITCOUNT
        var j = q - k
        var lo = materialize[POW5_SPLIT]().unsafe_get(2 * i)
        var hi = materialize[POW5_SPLIT]().unsafe_get(2 * i + 1)
        vr = _mul_shift(mv, lo, hi, j)
        vp = _mul_shift(mv + 2, lo, hi, j)
        vm = _mul_shift(mv - 1 - mm_shift, lo, hi, j)
        if q <= 1:
            # mv has at least two trailing zero bits, so vr is exact.
            vr_trailing_zeros = True
            if accept_bounds:
                vm_trailing_zeros = mm_shift == 1
            else:
                vp -= 1
        elif q < 63:
            # vr = mv * 5^i / 2^q is exact when 2^q divides mv.
            vr_trailing_zeros = _multiple_of_pow2(mv, q)

    # Remove digits while the interval still holds a shorter number.
    var removed = 0
    var last_removed: UInt64 = 0
    var output: UInt64
    if vm_trailing_zeros or vr_trailing_zeros:
        # The general case (rare): exact bounds and ties need the digits.
        while True:
            var vp10 = vp // 10
            var vm10 = vm // 10
            if vp10 <= vm10:
                break
            var vm_mod = vm - 10 * vm10
            var vr10 = vr // 10
            var vr_mod = vr - 10 * vr10
            vm_trailing_zeros = vm_trailing_zeros and vm_mod == 0
            vr_trailing_zeros = vr_trailing_zeros and last_removed == 0
            last_removed = vr_mod
            vr = vr10
            vp = vp10
            vm = vm10
            removed += 1
        if vm_trailing_zeros:
            while True:
                var vm10 = vm // 10
                if vm - 10 * vm10 != 0:
                    break
                var vp10 = vp // 10
                var vr10 = vr // 10
                var vr_mod = vr - 10 * vr10
                vr_trailing_zeros = vr_trailing_zeros and last_removed == 0
                last_removed = vr_mod
                vr = vr10
                vp = vp10
                vm = vm10
                removed += 1
        if vr_trailing_zeros and last_removed == 5 and vr % 2 == 0:
            last_removed = 4  # (exactly ...50...0: round to even)
        var up = (vr == vm and (not accept_bounds or not vm_trailing_zeros)) or last_removed >= 5
        output = vr + (UInt64(1) if up else UInt64(0))
    else:
        # The common case: no exact bounds, round half up.
        var round_up = False
        var vp100 = vp // 100
        var vm100 = vm // 100
        if vp100 > vm100:
            var vr100 = vr // 100
            round_up = vr - 100 * vr100 >= 50
            vr = vr100
            vp = vp100
            vm = vm100
            removed += 2
        while True:
            var vp10 = vp // 10
            var vm10 = vm // 10
            if vp10 <= vm10:
                break
            var vr10 = vr // 10
            round_up = vr - 10 * vr10 >= 5
            vr = vr10
            vp = vp10
            vm = vm10
            removed += 1
        output = vr + (UInt64(1) if (vr == vm or round_up) else UInt64(0))
    return Shortest(False, output, e10 + removed)


def shortest(x: Float64) -> Shortest:
    """`x` as its shortest round-trip digits; `x` must be finite."""
    var bits = bitcast[DType.uint64](x)
    var negative = (bits >> 63) != 0
    var ieee_mantissa = bits & ((UInt64(1) << _MANTISSA_BITS) - 1)
    var ieee_exponent = Int((bits >> _MANTISSA_BITS) & ((UInt64(1) << _EXPONENT_BITS) - 1))
    if ieee_exponent == 0 and ieee_mantissa == 0:
        return Shortest(negative, 0, 0)
    # An integer in [1, 2^53) is its own shortest form, once its trailing
    # decimal zeros are moved into the exponent.
    var e2 = ieee_exponent - _BIAS - _MANTISSA_BITS
    if e2 <= 0 and e2 >= -52:
        var m2 = (UInt64(1) << _MANTISSA_BITS) | ieee_mantissa
        if m2 & ((UInt64(1) << UInt64(-e2)) - 1) == 0:
            var v = m2 >> UInt64(-e2)
            var e = 0
            while True:
                var q = v // 10
                if v - 10 * q != 0:
                    break
                v = q
                e += 1
            return Shortest(negative, v, e)
    var s = _d2d(ieee_mantissa, ieee_exponent)
    s.negative = negative
    return s


@inline(.always)
def _digit_count(v: UInt64) -> Int:
    """Decimal digits in `v` (1 for 0); `v` < 10^17."""
    var n = 1
    var p: UInt64 = 10
    while n < 17 and v >= p:
        p *= 10
        n += 1
    return n


def _write_layout(mut out: List[UInt8], s: Shortest):
    """`s` laid out as ECMAScript's Number::toString (see the module),
    each byte written once into a buffer, then appended."""
    var buf = Array[UInt8, 32](uninitialized=True)
    var p = buf.unsafe_ptr()
    var w = 0
    if s.negative:
        p[unsafe_offset=0] = 45  # '-'
        w = 1
    var k = _digit_count(s.digits)
    var n = k + s.exponent  # (the value is 0.d1d2...dk * 10^n)
    var base: Int  # where digit 0 goes
    var dot: Int  # digits from this one on go one place further, past a '.'
    if k <= n and n <= 21:
        base = w
        dot = k
        for i in range(k, n):
            p[unsafe_offset=w + i] = 48
        w += n
    elif 0 < n and n <= 21:
        base = w
        dot = n
        p[unsafe_offset=w + n] = 46  # '.'
        w += k + 1
    elif -6 < n and n <= 0:
        p[unsafe_offset=w] = 48
        p[unsafe_offset=w + 1] = 46
        for i in range(-n):
            p[unsafe_offset=w + 2 + i] = 48
        base = w + 2 - n
        dot = k
        w = base + k
    else:
        base = w
        dot = 1 if k > 1 else k
        if k > 1:
            p[unsafe_offset=w + 1] = 46
            w += k + 1
        else:
            w += 1
        var e = n - 1
        p[unsafe_offset=w] = 101  # 'e'
        p[unsafe_offset=w + 1] = 43 if e >= 0 else 45
        w += 2
        if e < 0:
            e = -e
        if e >= 100:
            p[unsafe_offset=w] = UInt8(48 + e // 100)
            w += 1
        if e >= 10:
            p[unsafe_offset=w] = UInt8(48 + (e // 10) % 10)
            w += 1
        p[unsafe_offset=w] = UInt8(48 + e % 10)
        w += 1
    var v = s.digits
    for i in range(k - 1, -1, -1):
        var q = v // 10
        p[unsafe_offset=base + i + (1 if i >= dot else 0)] = UInt8(48) + UInt8(v - 10 * q)
        v = q
    out.extend(Span(buf)[:w])


def write_float(mut out: List[UInt8], x: Float64) raises JsonError:
    """Append `x` as JSON: the shortest digits that read back as `x` (see
    the module for the layout). NaN and the infinities have no JSON form
    and raise USAGE."""
    if x != x or x - x != 0:  # (NaN, or an infinity: inf - inf is NaN)
        raise JsonError(JsonError.USAGE, "json: NaN and the infinities have no JSON form")
    if x == 0:  # (either sign: no digits to find)
        if bitcast[DType.uint64](x) >> 63 != 0:
            out.append(45)
        out.append(48)
        return
    _write_layout(out, shortest(x))


def format_float(x: Float64) raises JsonError -> String:
    """`x` as `write_float` writes it."""
    var out = List[UInt8](capacity=MAX_FLOAT_LENGTH)
    write_float(out, x)
    return String(unsafe_from_utf8=Span(out))
