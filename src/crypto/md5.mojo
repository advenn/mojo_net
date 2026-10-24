"""MD5 (RFC 1321), only for PostgreSQL's legacy `md5` authentication: MD5
is broken as a hash and is no protection against an attacker who sees the
exchange. Same shape as `crypto.sha256`."""

comptime DIGEST_SIZE = 16
comptime BLOCK_SIZE = 64

comptime _K = SIMD[DType.uint32, 64](
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
)
comptime _S = SIMD[DType.uint32, 64](
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
)


@inline(.always)
def _rotl(x: UInt32, n: UInt32) -> UInt32:
    return (x << n) | (x >> (32 - n))


def _compress(mut state: SIMD[DType.uint32, 4], block: Span[UInt8, _]):
    """One 64-byte block into `state`, fully unrolled (see `crypto.sha256`)."""
    var p = block.unsafe_ptr()
    var m = Array[UInt32, 16](fill=0)
    comptime for t in range(16):
        m[t] = (
            UInt32(p[unsafe_offset=4 * t])
            | (UInt32(p[unsafe_offset=4 * t + 1]) << 8)
            | (UInt32(p[unsafe_offset=4 * t + 2]) << 16)
            | (UInt32(p[unsafe_offset=4 * t + 3]) << 24)
        )
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    comptime for i in range(64):
        var f: UInt32
        comptime g = i if i < 16 else ((5 * i + 1) % 16 if i < 32 else ((3 * i + 5) % 16 if i < 48 else (7 * i) % 16))
        comptime if i < 16:
            f = (b & c) | (~b & d)
        elif i < 32:
            f = (d & b) | (~d & c)
        elif i < 48:
            f = b ^ c ^ d
        else:
            f = c ^ (b | ~d)
        var next = b + _rotl(a + f + UInt32(_K[i]) + m[g], UInt32(_S[i]))
        a = d
        d = c
        c = b
        b = next
    state += SIMD[DType.uint32, 4](a, b, c, d)


struct Md5(Copyable, Movable):
    """Incremental MD5: `update` any number of times, then `digest`."""

    var _state: SIMD[DType.uint32, 4]
    var _block: Array[UInt8, BLOCK_SIZE]
    var _used: Int
    var _length: UInt64

    def __init__(out self):
        self._state = SIMD[DType.uint32, 4](0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
        self._block = Array[UInt8, BLOCK_SIZE](fill=0)
        self._used = 0
        self._length = 0

    def update(mut self, data: Span[UInt8, _]):
        var i = 0
        var n = len(data)
        self._length += UInt64(n)
        if self._used > 0:
            while i < n and self._used < BLOCK_SIZE:
                self._block[self._used] = data[i]
                self._used += 1
                i += 1
            if self._used < BLOCK_SIZE:
                return
            _compress(self._state, Span(self._block))
            self._used = 0
        while n - i >= BLOCK_SIZE:
            _compress(self._state, data[i : i + BLOCK_SIZE])
            i += BLOCK_SIZE
        while i < n:
            self._block[self._used] = data[i]
            self._used += 1
            i += 1

    def digest(var self) -> List[UInt8]:
        var bits = self._length * 8
        self._block[self._used] = 0x80
        self._used += 1
        if self._used > BLOCK_SIZE - 8:
            while self._used < BLOCK_SIZE:
                self._block[self._used] = 0
                self._used += 1
            _compress(self._state, Span(self._block))
            self._used = 0
        while self._used < BLOCK_SIZE - 8:
            self._block[self._used] = 0
            self._used += 1
        for k in range(8):
            self._block[BLOCK_SIZE - 8 + k] = UInt8((bits >> UInt64(8 * k)) & 0xFF)
        _compress(self._state, Span(self._block))
        var out = List[UInt8](capacity=DIGEST_SIZE)
        for k in range(4):
            var v = self._state[k]
            out.append(UInt8(v & 0xFF))
            out.append(UInt8((v >> 8) & 0xFF))
            out.append(UInt8((v >> 16) & 0xFF))
            out.append(UInt8(v >> 24))
        return out^


def md5(data: Span[UInt8, _]) -> List[UInt8]:
    """The MD5 digest of `data` (16 bytes)."""
    var h = Md5()
    h.update(data)
    return h^.digest()
