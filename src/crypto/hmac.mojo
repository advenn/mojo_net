"""HMAC-SHA-256 (RFC 2104) and PBKDF2-HMAC-SHA-256 (RFC 8018), what
SCRAM-SHA-256 (RFC 5802, RFC 7677) needs."""

from .sha256 import BLOCK_SIZE, DIGEST_SIZE, Sha256, _compress_words, sha256


struct HmacSha256(Copyable, Movable):
    """HMAC-SHA-256 under one key: the key's padded blocks are absorbed
    once, so each `mac` costs the message plus two compressions."""

    var _inner: Sha256
    var _outer: Sha256

    def __init__(out self, key: Span[UInt8, _]):
        var k = Array[UInt8, BLOCK_SIZE](fill=0)
        if len(key) > BLOCK_SIZE:
            var d = sha256(key)
            for i in range(DIGEST_SIZE):
                k[i] = d[i]
        else:
            for i in range(len(key)):
                k[i] = key[i]
        var pad = Array[UInt8, BLOCK_SIZE](fill=0)
        for i in range(BLOCK_SIZE):
            pad[i] = k[i] ^ 0x36
        self._inner = Sha256()
        self._inner.update(Span(pad))
        for i in range(BLOCK_SIZE):
            pad[i] = k[i] ^ 0x5C
        self._outer = Sha256()
        self._outer.update(Span(pad))

    def mac(self, data: Span[UInt8, _]) -> List[UInt8]:
        var inner = self._inner.copy()
        inner.update(data)
        var d = inner^.digest()
        var outer = self._outer.copy()
        outer.update(Span(d))
        return outer^.digest()


def hmac_sha256(key: Span[UInt8, _], data: Span[UInt8, _]) -> List[UInt8]:
    """HMAC-SHA-256 of `data` under `key` (32 bytes)."""
    return HmacSha256(key).mac(data)


def pbkdf2_hmac_sha256(
    password: Span[UInt8, _], salt: Span[UInt8, _], iterations: Int, length: Int
) raises -> List[UInt8]:
    """PBKDF2 with HMAC-SHA-256 (RFC 8018 5.2): `length` bytes derived from
    `password` and `salt` over `iterations` rounds. Raises for
    `iterations` < 1 or `length` < 1."""
    if iterations < 1 or length < 1:
        raise Error("pbkdf2: iterations and length must be at least 1")
    var prf = HmacSha256(password)
    # Every iteration after the first MACs a 32-byte value: one block for
    # the inner hash (the key's padded block is already in its state) and
    # one for the outer, both with fixed padding for 96 bytes in all. So the
    # loop runs on words, two compressions per iteration, no allocation.
    var inner = prf._inner._state
    var outer = prf._outer._state
    var out = List[UInt8](capacity=length)
    var block: UInt32 = 1
    while len(out) < length:
        var first = List[UInt8](capacity=len(salt) + 4)
        first.extend(salt)
        first.append(UInt8(block >> 24))
        first.append(UInt8((block >> 16) & 0xFF))
        first.append(UInt8((block >> 8) & 0xFF))
        first.append(UInt8(block & 0xFF))
        var u = _words(prf.mac(Span(first)))
        var t = u
        var w = Array[UInt32, 16](fill=0)
        w[8] = 0x80000000
        w[15] = (BLOCK_SIZE + DIGEST_SIZE) * 8  # bits hashed in all
        for _ in range(1, iterations):
            comptime for k in range(8):
                w[k] = u[k]
            var s = inner
            _compress_words(s, w)
            comptime for k in range(8):
                w[k] = s[k]
            var o = outer
            _compress_words(o, w)
            u = o
            t ^= u
        for i in range(min(DIGEST_SIZE, length - len(out))):
            out.append(UInt8((t[i // 4] >> UInt32(24 - 8 * (i % 4))) & 0xFF))
        block += 1
    return out^


def _words(d: List[UInt8]) -> SIMD[DType.uint32, 8]:
    """A 32-byte digest as its 8 big-endian words."""
    var w = SIMD[DType.uint32, 8](0)
    for k in range(8):
        w[k] = (
            (UInt32(d[4 * k]) << 24)
            | (UInt32(d[4 * k + 1]) << 16)
            | (UInt32(d[4 * k + 2]) << 8)
            | UInt32(d[4 * k + 3])
        )
    return w
