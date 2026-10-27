"""SipHash (Aumasson and Bernstein, 2012), for the parser's repeated-key
check: a key's hash decides which keys are compared byte for byte.

`siphash13` is SipHash-1-3, as Python (since 3.11) and Rust hash with.
The parser uses a fixed key: a group of k keys with one 64-bit hash costs
whoever builds it about 2^(64(k-1)/k) evaluations, and a collision only
costs the parser one comparison of the keys' bytes, so no secret is
needed for the bound."""


@inline(.always)
def _rotl(x: UInt64, b: UInt64) -> UInt64:
    return (x << b) | (x >> (64 - b))


@inline(.always)
def _round(mut v0: UInt64, mut v1: UInt64, mut v2: UInt64, mut v3: UInt64):
    v0 += v1
    v1 = _rotl(v1, 13)
    v1 ^= v0
    v0 = _rotl(v0, 32)
    v2 += v3
    v3 = _rotl(v3, 16)
    v3 ^= v2
    v0 += v3
    v3 = _rotl(v3, 21)
    v3 ^= v0
    v2 += v1
    v1 = _rotl(v1, 17)
    v1 ^= v2
    v2 = _rotl(v2, 32)


def siphash[c: Int, d: Int](k0: UInt64, k1: UInt64, data: Span[UInt8, _]) -> UInt64:
    """SipHash-c-d of `data` under the key (`k0`, `k1`), each the key's
    eight bytes read little-endian."""
    var v0 = k0 ^ 0x736F6D6570736575
    var v1 = k1 ^ 0x646F72616E646F6D
    var v2 = k0 ^ 0x6C7967656E657261
    var v3 = k1 ^ 0x7465646279746573
    var p = data.unsafe_ptr()
    var n = len(data)
    var end = n - n % 8
    var i = 0
    while i < end:
        var m: UInt64 = 0
        for j in range(8):
            m |= UInt64(p[unsafe_offset=i + j]) << UInt64(8 * j)
        v3 ^= m
        comptime for _ in range(c):
            _round(v0, v1, v2, v3)
        v0 ^= m
        i += 8
    var b = UInt64(n & 0xFF) << 56
    for j in range(n - end):
        b |= UInt64(p[unsafe_offset=end + j]) << UInt64(8 * j)
    v3 ^= b
    comptime for _ in range(c):
        _round(v0, v1, v2, v3)
    v0 ^= b
    v2 ^= 0xFF
    comptime for _ in range(d):
        _round(v0, v1, v2, v3)
    return v0 ^ v1 ^ v2 ^ v3


def siphash13(k0: UInt64, k1: UInt64, data: Span[UInt8, _]) -> UInt64:
    return siphash[1, 3](k0, k1, data)
