"""Number texts and the Float64 Python's float() reads them as (test-only
Python, for tests/json/test_number.mojo): Python's float() is David Gay's
correctly rounded strtod, a different algorithm from json.number's.

    cases(seed, n) -> "<text> <bits as 16 hex digits>\\n" for n texts
"""

import random
import struct

import json_oracle


def _bits(x):
    return struct.pack(">d", x).hex()


def _random_double(rng):
    while True:
        x = struct.unpack("<d", struct.pack("<Q", rng.getrandbits(64)))[0]
        if x == x and x - x == 0:
            return x


def _texts(rng):
    r = rng.random()
    if r < 0.2:
        return json_oracle.number_text(rng)
    x = _random_double(rng)
    if r < 0.4:
        return repr(x).replace("inf", "1e999")
    if r < 0.55:
        return "%.17g" % x
    if r < 0.65:
        return "%.*e" % (rng.randint(0, 25), x)
    if r < 0.8:
        # Integers around and past 2^53, plain and with exponents: the
        # halfway cases Clinger's path and the round to even meet.
        v = rng.randint(2**53 - 100, 10**19 - 1) if rng.random() < 0.5 else rng.randint(1, 2**64)
        s = str(v)
        if rng.random() < 0.5:
            s += "e%d" % rng.randint(-30, 30)
        return s
    if r < 0.9:
        # Short decimals over the whole exponent range.
        s = str(rng.randint(1, 10 ** rng.randint(1, 19)))
        return s + "e%d" % rng.randint(-360, 320)
    return rng.choice(EDGES)


EDGES = [
    "0", "-0", "0.0", "-0.0", "0e5", "0.000e-400", "1", "-1", "9007199254740992", "9007199254740993",
    "9007199254740994", "9007199254740995", "18014398509481985", "1e22", "1e23", "1e-22", "1e-23",
    "4.9e-324", "5e-324", "2.4703282292062327e-324", "2.4703282292062328e-324", "2.2250738585072011e-308",
    "2.2250738585072014e-308", "1.7976931348623157e308", "1.7976931348623158e308", "1.7976931348623159e308",
    "1e308", "1e309", "1e-342", "1e-343", "1e-400", "9999999999999999999e-361", "9999999999999999999e-343",
    "1e-307", "123456789012345678e-300", "0.1", "0.2", "0.3", "1.5", "2.5", "1234567890123456789",
    "12345678901234567890", "0.0000000000000000000000000001", "7.2057594037927933e16", "8.98846567431158e307",
    "3.0517578125e-05", "2.98023223876953125E-8", "-1e-1", "1E+2", "1e+0",
]


def cases(seed, n):
    rng = random.Random(seed)
    out = []
    for i in range(n):
        t = EDGES[i] if i < len(EDGES) else _texts(rng)
        out.append(t + " " + _bits(float(t)))
    return "\n".join(out)
