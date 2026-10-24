"""SHA-256 (FIPS 180-4), incremental (`Sha256`) or at once (`sha256`).

Written for authentication (SCRAM, HMAC, PBKDF2), not for bulk hashing:
scalar code, a few hundred MB/s. `Sha256` is a value: copying one after
absorbing a common prefix (an HMAC key's padded block) and finishing the
copies is how `crypto.hmac` reuses work.
"""

comptime DIGEST_SIZE = 32
comptime BLOCK_SIZE = 64

comptime _K = SIMD[DType.uint32, 64](
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)
comptime _H0 = SIMD[DType.uint32, 8](
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
)


@inline(.always)
def _rotr(x: UInt32, n: UInt32) -> UInt32:
    return (x >> n) | (x << (32 - n))


def _compress(mut state: SIMD[DType.uint32, 8], block: Span[UInt8, _]):
    """One 64-byte block into `state`. Fully unrolled (`comptime for`):
    with every index a constant, the schedule stays in registers and the
    round constants fold, which made it about ten times faster than the
    loop with runtime indexes into SIMD values."""
    var p = block.unsafe_ptr()
    var w = Array[UInt32, 16](fill=0)
    comptime for t in range(16):
        w[t] = (
            (UInt32(p[unsafe_offset=4 * t]) << 24)
            | (UInt32(p[unsafe_offset=4 * t + 1]) << 16)
            | (UInt32(p[unsafe_offset=4 * t + 2]) << 8)
            | UInt32(p[unsafe_offset=4 * t + 3])
        )
    _compress_words(state, w)


def _compress_words(mut state: SIMD[DType.uint32, 8], block: Array[UInt32, 16]):
    """One block, given as its 16 big-endian words, into `state`."""
    var w = Array[UInt32, 64](fill=0)
    comptime for t in range(16):
        w[t] = block[t]
    comptime for t in range(16, 64):
        var x = w[t - 15]
        var y = w[t - 2]
        var s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)
        var s1 = _rotr(y, 17) ^ _rotr(y, 19) ^ (y >> 10)
        w[t] = w[t - 16] + s0 + w[t - 7] + s1
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]
    comptime for t in range(64):
        var big1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        var ch = (e & f) ^ (~e & g)
        var t1 = h + big1 + ch + UInt32(_K[t]) + w[t]
        var big0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        var maj = (a & b) ^ (a & c) ^ (b & c)
        var t2 = big0 + maj
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
    state += SIMD[DType.uint32, 8](a, b, c, d, e, f, g, h)


struct Sha256(Copyable, Movable):
    """Incremental SHA-256: `update` any number of times, then `digest`."""

    var _state: SIMD[DType.uint32, 8]
    var _block: Array[UInt8, BLOCK_SIZE]
    var _used: Int
    """Bytes waiting in `_block`."""
    var _length: UInt64
    """Bytes absorbed in all."""

    def __init__(out self):
        self._state = _H0
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
        """The 32-byte digest of everything absorbed (consumes the value:
        copy it first to go on)."""
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
            self._block[BLOCK_SIZE - 1 - k] = UInt8((bits >> UInt64(8 * k)) & 0xFF)
        _compress(self._state, Span(self._block))
        var out = List[UInt8](capacity=DIGEST_SIZE)
        for k in range(8):
            var v = self._state[k]
            out.append(UInt8(v >> 24))
            out.append(UInt8((v >> 16) & 0xFF))
            out.append(UInt8((v >> 8) & 0xFF))
            out.append(UInt8(v & 0xFF))
        return out^


def sha256(data: Span[UInt8, _]) -> List[UInt8]:
    """The SHA-256 digest of `data` (32 bytes)."""
    var h = Sha256()
    h.update(data)
    return h^.digest()
