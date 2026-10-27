"""What `json.ryu` must write for a double, for tests/json/test_float.mojo
(test-only Python; not a test file itself).

The digits come from Python's repr(), which is shortest round-trip (David
Gay's dtoa in CPython), a different algorithm from Ryū. The layout is
ECMAScript's Number::toString (ECMA-262, "Number::toString", steps 5-12),
written here from the spec, with "-0" for negative zero.

    batch(seed, n, mode) -> "bits expected\n..." for n doubles of a kind
    expect(x) -> the text for one double
"""

import decimal
import math
import random
import struct


def bits(x):
    return struct.unpack("<Q", struct.pack("<d", x))[0]


def from_bits(b):
    return struct.unpack("<d", struct.pack("<Q", b))[0]


def digits(x):
    """(negative, digits, exponent): x = digits * 10^exponent, the digits
    repr's, with no trailing zeros."""
    neg = math.copysign(1.0, x) < 0
    if x == 0:
        return neg, 0, 0
    t = decimal.Decimal(repr(abs(x))).as_tuple()
    d = int("".join(map(str, t.digits)))
    e = t.exponent
    while d % 10 == 0:
        d //= 10
        e += 1
    return neg, d, e


def expect(x):
    neg, d, e = digits(x)
    sign = "-" if neg else ""
    if d == 0:
        return sign + "0"
    s = str(d)
    k = len(s)
    n = k + e  # x = 0.s * 10^n
    if k <= n <= 21:
        out = s + "0" * (n - k)
    elif 0 < n <= 21:
        out = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * -n + s
    else:
        ex = n - 1
        out = s[0] + ("." + s[1:] if k > 1 else "") + "e" + ("+" if ex >= 0 else "-") + str(abs(ex))
    text = sign + out
    assert float(text) == x and math.copysign(1.0, float(text)) == math.copysign(1.0, x)
    return text


# Known hard cases: Ryū's own tests (d2s_test.cc: boundaries, regressions,
# trailing zeros, values that look like powers of five), round numbers at
# the layout's edges, and classics.
HARD = [
    0.0, -0.0, 1.0, -1.0, 0.1, 0.2, 0.1 + 0.2, 1.5, 100.0, 123456.0,
    2.2250738585072014e-308, 2.2250738585072009e-308, 4.9e-324, 1e-323,
    1.7976931348623157e308, -1.7976931348623157e308, 2.98023223876953125e-8,
    -2.109808898695963e16, 4.940656e-318, 1.18575755e-316, 2.989102097996e-312,
    9.0608011534336e15, 4.708356024711512e18, 9.409340012568248e18, 1.2345678,
    5.764607523034235e39, 1.152921504606847e40, 2.305843009213694e40,
    1.0e21, 9.999999999999999e20, 1.0e20, 123456789012345680000.0, 1.0e-6,
    1.0e-7, 9.999999999999999e-7, 1.23e-18, 0.000001, 0.0000012345678901234567,
    2.0**53, 2.0**53 - 1, 2.0**53 + 2, 2.0**63, 2.0**64, 2.0**-1074, 2.0**-1022,
    2.0**1023, 1.0e15, 1.0e16, 1.0e17, 1.0e22, 1.0e23, 5.0e-324, 1.0e308,
    1.2345678901234567, 12.345678901234567, 0.30000000000000004, 1.0 / 3.0,
    2.0 / 3.0, math.pi, math.e, 9007199254740993.0, 4.35, 0.3, 1e-5, 5e-7,
]


def hard():
    out = []
    for x in HARD:
        for y in (x, -x, math.nextafter(x, math.inf), math.nextafter(x, -math.inf)):
            if math.isfinite(y):
                out.append("%016x %s" % (bits(y), expect(y)))
    for e in range(-325, 310):
        for m in (1, 2, 5, 9, 25, 125):
            y = float("%de%d" % (m, e))
            if math.isfinite(y):
                out.append("%016x %s" % (bits(y), expect(y)))
    for e in range(-1074, 1024):
        y = math.ldexp(1.0, e)
        for z in (y, math.nextafter(y, math.inf), math.nextafter(y, 0.0)):
            if math.isfinite(z):
                out.append("%016x %s" % (bits(z), expect(z)))
    return "\n".join(out)


def _one(rng, mode):
    if mode == "bits":
        while True:
            x = from_bits(rng.getrandbits(64))
            if math.isfinite(x):
                return x
    if mode == "decimal":  # short decimals, as people write them
        d = rng.randrange(1, 10 ** rng.randint(1, 17))
        return float("%de%d" % (d, rng.randint(-340, 320))) if rng.random() < 0.5 else float("%de%d" % (d, rng.randint(-25, 25)))
    if mode == "int":
        return float(rng.getrandbits(rng.randint(1, 70)))
    if mode == "subnormal":
        return from_bits(rng.getrandbits(52) | (rng.getrandbits(1) << 63))
    raise ValueError(mode)


def batch(seed, n, mode):
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        x = _one(rng, mode)
        if not math.isfinite(x):
            continue
        out.append("%016x %s" % (bits(x), expect(x)))
    return "\n".join(out)
