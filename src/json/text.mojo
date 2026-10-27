"""Bytes inside JSON strings: strict UTF-8 (RFC 3629) and the escapes a
string needs to be written (RFC 8259, section 7)."""

from std.bit import count_trailing_zeros
from std.memory import pack_bits

comptime _W = 16
"""Bytes looked at once when searching a string for the next byte that is
not plain printable ASCII."""

comptime _QUOTE: UInt8 = 34
comptime _BACKSLASH: UInt8 = 92


@inline(.always)
def _cont(b: UInt8) -> Bool:
    return (b & 0xC0) == 0x80


@inline(.always)
def utf8_length(s: Span[UInt8, _], i: Int) -> Int:
    """The length of the valid UTF-8 sequence that starts at `s[i]`, a
    byte >= 0x80; 0 when there is none: a stray continuation byte, an
    overlong form, a surrogate (U+D800-U+DFFF), past U+10FFFF, or cut off
    by the end of `s`."""
    var p = s.unsafe_ptr()
    var n = len(s)
    var c = p[unsafe_offset=i]
    if c < 0xC2:
        return 0
    if c < 0xE0:
        return 2 if i + 1 < n and _cont(p[unsafe_offset=i + 1]) else 0
    if c < 0xF0:
        if i + 2 >= n:
            return 0
        var c1 = p[unsafe_offset=i + 1]
        var lo: UInt8 = 0xA0 if c == 0xE0 else 0x80
        var hi: UInt8 = 0x9F if c == 0xED else 0xBF
        if c1 < lo or c1 > hi or not _cont(p[unsafe_offset=i + 2]):
            return 0
        return 3
    if c < 0xF5:
        if i + 3 >= n:
            return 0
        var c1 = p[unsafe_offset=i + 1]
        var lo: UInt8 = 0x90 if c == 0xF0 else 0x80
        var hi: UInt8 = 0x8F if c == 0xF4 else 0xBF
        if c1 < lo or c1 > hi or not _cont(p[unsafe_offset=i + 2]) or not _cont(p[unsafe_offset=i + 3]):
            return 0
        return 4
    return 0


@inline(.always)
def is_plain(b: UInt8) -> Bool:
    """Printable ASCII other than '"' and '\\': the bytes a string holds as
    themselves, in input and in output alike."""
    return b >= 0x20 and b < 0x80 and b != _QUOTE and b != _BACKSLASH


@inline(.always)
def plain_run(s: Span[UInt8, _], start: Int) -> Int:
    """Where the first byte at or after `start` that is not `is_plain` is
    (`len(s)` if none): `_W` bytes compared at once, then one at a time
    for the tail."""
    var p = s.unsafe_ptr()
    var n = len(s)
    var i = start
    while i + _W <= n:
        var v = p.unsafe_load[width=_W](i)
        var special = (v - 0x20).ge(SIMD[DType.uint8, _W](0x60)) | v.eq(SIMD[DType.uint8, _W](_QUOTE)) | v.eq(
            SIMD[DType.uint8, _W](_BACKSLASH)
        )
        var bits = pack_bits[DType.uint16](special)
        if bits != 0:
            return i + Int(count_trailing_zeros(bits))
        i += _W
    while i < n and is_plain(p[unsafe_offset=i]):
        i += 1
    return i


@inline(.always)
def escape_run(s: Span[UInt8, _], start: Int) -> Int:
    """Where the first byte at or after `start` that a JSON string must
    escape is (a control character, '"' or '\\'), or `len(s)`."""
    var p = s.unsafe_ptr()
    var n = len(s)
    var i = start
    while i + _W <= n:
        var v = p.unsafe_load[width=_W](i)
        var special = v.lt(SIMD[DType.uint8, _W](0x20)) | v.eq(SIMD[DType.uint8, _W](_QUOTE)) | v.eq(
            SIMD[DType.uint8, _W](_BACKSLASH)
        )
        var bits = pack_bits[DType.uint16](special)
        if bits != 0:
            return i + Int(count_trailing_zeros(bits))
        i += _W
    while i < n:
        var b = p[unsafe_offset=i]
        if b < 0x20 or b == _QUOTE or b == _BACKSLASH:
            return i
        i += 1
    return n


comptime _HEX = "0123456789abcdef"


def write_quoted(mut out: List[UInt8], s: Span[UInt8, _], validate: Bool) -> Bool:
    """Append `s` as a JSON string: quoted, with '"', '\\' and the control
    characters escaped (the short forms where JSON has them, \\u00XX for
    the rest) and everything else as itself. With `validate`, returns
    False, having appended nothing, if `s` is not UTF-8."""
    var n = len(s)
    if validate:
        var i = 0
        while i < n:
            i = plain_run(s, i)
            if i < n:
                var b = s[i]
                if b >= 0x80:
                    var k = utf8_length(s, i)
                    if k == 0:
                        return False
                    i += k
                else:
                    i += 1
    out.append(_QUOTE)
    var i = 0
    while i < n:
        var j = escape_run(s, i)
        if j > i:
            out.extend(s[i:j])
        if j == n:
            break
        var b = s[j]
        if b == _QUOTE or b == _BACKSLASH:
            out.append(_BACKSLASH)
            out.append(b)
        elif b == 0x0A:
            out.append(_BACKSLASH)
            out.append(110)  # n
        elif b == 0x0D:
            out.append(_BACKSLASH)
            out.append(114)  # r
        elif b == 0x09:
            out.append(_BACKSLASH)
            out.append(116)  # t
        elif b == 0x08:
            out.append(_BACKSLASH)
            out.append(98)  # b
        elif b == 0x0C:
            out.append(_BACKSLASH)
            out.append(102)  # f
        else:
            out.append(_BACKSLASH)
            out.append(117)  # u
            out.append(48)
            out.append(48)
            out.append(_HEX.as_bytes()[Int(b >> 4)])
            out.append(_HEX.as_bytes()[Int(b & 15)])
        i = j + 1
    out.append(_QUOTE)
    return True
