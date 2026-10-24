"""Base64 (RFC 4648, section 4: the standard alphabet with `=` padding),
as SCRAM and HTTP Basic authentication use it."""

comptime _ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def base64_encode(data: Span[UInt8, _]) -> String:
    var a = _ALPHABET.as_bytes()
    var out = List[UInt8](capacity=(len(data) + 2) // 3 * 4)
    var i = 0
    var n = len(data)
    while i + 3 <= n:
        var v = (UInt32(data[i]) << 16) | (UInt32(data[i + 1]) << 8) | UInt32(data[i + 2])
        out.append(a[Int((v >> 18) & 63)])
        out.append(a[Int((v >> 12) & 63)])
        out.append(a[Int((v >> 6) & 63)])
        out.append(a[Int(v & 63)])
        i += 3
    if n - i == 1:
        var v = UInt32(data[i]) << 16
        out.append(a[Int((v >> 18) & 63)])
        out.append(a[Int((v >> 12) & 63)])
        out.append(61)
        out.append(61)
    elif n - i == 2:
        var v = (UInt32(data[i]) << 16) | (UInt32(data[i + 1]) << 8)
        out.append(a[Int((v >> 18) & 63)])
        out.append(a[Int((v >> 12) & 63)])
        out.append(a[Int((v >> 6) & 63)])
        out.append(61)
    return String(unsafe_from_utf8=Span(out))


@inline(.always)
def _value(c: UInt8) -> Int:
    if c >= 65 and c <= 90:
        return Int(c) - 65
    if c >= 97 and c <= 122:
        return Int(c) - 71
    if c >= 48 and c <= 57:
        return Int(c) + 4
    if c == 43:
        return 62
    if c == 47:
        return 63
    return -1


def base64_decode(text: StringSlice) raises -> List[UInt8]:
    """The bytes `text` encodes. Strict: a length that is a multiple of 4,
    only the alphabet, and padding only at the end; raises otherwise. (Like
    Python's `b64decode(validate=True)`, unused low bits need not be 0.)"""
    return base64_decode(text.as_bytes())


def base64_decode(t: Span[UInt8, _]) raises -> List[UInt8]:
    """The same, for text given as bytes (which need not be UTF-8: anything
    outside the alphabet is refused)."""
    var n = len(t)
    if n % 4 != 0:
        raise Error("base64: length not a multiple of 4")
    var out = List[UInt8](capacity=n // 4 * 3)
    var i = 0
    while i < n:
        var pad = 0
        if i + 4 == n:
            if t[n - 1] == 61:
                pad = 1
                if t[n - 2] == 61:
                    pad = 2
        var v: UInt32 = 0
        for k in range(4):
            var c = t[i + k]
            var x: Int
            if k >= 4 - pad:
                x = 0  # (padding)
            else:
                x = _value(c)
                if x < 0:
                    raise Error("base64: not in the alphabet")
            v = (v << 6) | UInt32(x)
        out.append(UInt8((v >> 16) & 0xFF))
        if pad < 2:
            out.append(UInt8((v >> 8) & 0xFF))
        if pad < 1:
            out.append(UInt8(v & 0xFF))
        i += 4
    return out^
