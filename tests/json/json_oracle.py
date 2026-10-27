"""The Python side of the `json` package's tests (test-only Python; not a
test file itself): Python's own json module, made as strict as `json.parse`
is, as the oracle for differential tests, and generators of documents,
mutated documents, numbers and strings.

    expect(data) -> "ok <hex of the compact text>" or "err"
    fuzz(seed, n) -> "<hex doc> <expect(doc)>\\n" for n generated documents
    numbers(seed, n) -> "<hex text> <float> <int>\\n": float is the bits as
        16 hex digits or "range"; int is the value, "range" or "type"
    strings(seed, n) -> "<hex of UTF-8>\\n" for n random strings
    CASES: (bytes, accepted) written by hand from RFC 8259

Python's json accepts NaN and Infinity, lone surrogates and repeated keys,
and gives numbers as values; here the hooks refuse the first three and
keep each number's text, and the compact rendering writes numbers as that
text and strings as json.dumps(ensure_ascii=False) escapes them, which is
how `Document.write_json` must write them too.
"""

import json
import math
import random
import struct


class _Num(str):
    """A number, as its text."""


class _Obj(list):
    """An object, as its (key, value) pairs in order."""


def _pairs(ps):
    keys = [k for k, _ in ps]
    if len(set(keys)) != len(keys):
        raise ValueError("a repeated key")
    return _Obj(ps)


def _constant(name):
    raise ValueError("not JSON: " + name)


def _has_surrogate(s):
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def _check(v):
    if isinstance(v, _Obj):
        for k, x in v:
            if _has_surrogate(k):
                raise ValueError("a lone surrogate")
            _check(x)
    elif isinstance(v, list):
        for x in v:
            _check(x)
    elif isinstance(v, str) and not isinstance(v, _Num) and _has_surrogate(v):
        raise ValueError("a lone surrogate")


def load(data):
    text = data.decode("utf-8")  # (strict: no overlongs, no encoded surrogates)
    v = json.loads(text, object_pairs_hook=_pairs, parse_int=_Num, parse_float=_Num, parse_constant=_constant)
    _check(v)
    return v


def render(v):
    if isinstance(v, _Obj):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + render(x) for k, x in v) + "}"
    if isinstance(v, list):
        return "[" + ",".join(render(x) for x in v) + "]"
    if isinstance(v, _Num):
        return str.__str__(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if v is True:
        return "true"
    if v is False:
        return "false"
    assert v is None
    return "null"


def _depth(v):
    if isinstance(v, list):
        return 1 + max((_depth(x[1] if isinstance(v, _Obj) else x) for x in v), default=0)
    return 0


def expect(data):
    try:
        v = load(bytes(data))
    except (ValueError, RecursionError):
        return "err"
    if _depth(v) > 128:
        return "err"
    return "ok " + render(v).encode("utf-8").hex()


# ---- generated documents ---------------------------------------------------

_WS = [" ", "\t", "\n", "\r"]
_ESCAPES = ['\\"', "\\\\", "\\/", "\\b", "\\f", "\\n", "\\r", "\\t"]


def _ws(rng):
    if rng.random() < 0.7:
        return ""
    return "".join(rng.choice(_WS) for _ in range(rng.randint(1, 3)))


def _char(rng):
    r = rng.random()
    if r < 0.5:
        return chr(rng.randint(0x20, 0x7E)).replace("\\", "\\\\").replace('"', '\\"')
    if r < 0.65:
        return rng.choice(_ESCAPES)
    if r < 0.75:
        u = rng.choice([rng.randint(0, 0xD7FF), rng.randint(0xE000, 0xFFFF)])
        return "\\u%04x" % u if rng.random() < 0.5 else "\\u%04X" % u
    if r < 0.8:  # an astral character as a surrogate pair
        u = rng.randint(0x10000, 0x10FFFF) - 0x10000
        return "\\u%04x\\u%04x" % (0xD800 + (u >> 10), 0xDC00 + (u & 0x3FF))
    if r < 0.9:
        return chr(rng.choice([rng.randint(0x80, 0x7FF), rng.randint(0x800, 0xD7FF), rng.randint(0xE000, 0xFFFF)]))
    return chr(rng.randint(0x10000, 0x10FFFF))


def _string(rng):
    n = rng.choice([0, 1, 2, 5, 10, 40, 100])
    return '"' + "".join(_char(rng) for _ in range(rng.randint(0, n))) + '"'


def _digits(rng, n):
    return "".join(rng.choice("0123456789") for _ in range(n))


def number_text(rng):
    s = "-" if rng.random() < 0.3 else ""
    if rng.random() < 0.15:
        s += "0"
    else:
        s += rng.choice("123456789") + _digits(rng, rng.choice([0, 0, 1, 3, 8, 18, 19, 25, 300]))
    if rng.random() < 0.4:
        s += "." + _digits(rng, rng.choice([1, 2, 5, 17, 40]))
    if rng.random() < 0.3:
        s += rng.choice("eE") + rng.choice(["", "+", "-"]) + _digits(rng, rng.choice([1, 2, 3, 4]))
    return s


def _value(rng, depth, budget):
    """A value of about `budget[0]` nodes at most (shared down the tree,
    so the size stays bounded whatever the depth)."""
    budget[0] -= 1
    r = rng.random()
    if depth >= 8 or budget[0] <= 0 or r < 0.45:
        r = rng.random()
        if r < 0.35:
            return _string(rng)
        if r < 0.7:
            return number_text(rng)
        return rng.choice(["true", "false", "null"])
    if r < 0.7:
        items = [_ws(rng) + _value(rng, depth + 1, budget) + _ws(rng) for _ in range(rng.choice([0, 1, 2, 3, 5, 20]))]
        return "[" + (",".join(items) if items else _ws(rng)) + "]"
    keys = []
    for _ in range(rng.choice([0, 1, 2, 3, 6, 17, 40])):
        k = _string(rng)
        if k not in keys:
            keys.append(k)
    if keys and rng.random() < 0.05:
        keys.append(rng.choice(keys))  # (a repeated key, though possibly not byte for byte)
    items = [_ws(rng) + k + _ws(rng) + ":" + _ws(rng) + _value(rng, depth + 1, budget) + _ws(rng) for k in keys]
    return "{" + (",".join(items) if items else _ws(rng)) + "}"


_TOKENS = [
    b"\xef\xbb\xbf", b"\xc0\x80", b"\xc1\xbf", b"\xe0\x80\xaf", b"\xed\xa0\x80", b"\xed\xbf\xbf",
    b"\xf4\x90\x80\x80", b"\xf8\x88\x80\x80\x80", b"\x80", b"\xbf", b"\xc3", b"\xe2\x82", b"\xff",
    b"\\ud800", b"\\udc00", b"\\ud800\\u0041", b"\\uDBFF\\uDFFF", b"\\u", b"\\u12", b"\\x41", b"\\'",
    b",", b"]", b"}", b"[", b"{", b":", b'"', b"\\", b"01", b"-", b"-0", b"1.", b".5", b"+1", b"1e",
    b"1E+", b"0x1", b"NaN", b"Infinity", b"-Infinity", b"tru", b"nul", b"True", b"'", b"/*", b"//",
    b"\x00", b"\x1f", b"\x7f", b"\x0b", b"\x0c", b" ", b"\t", b"\xc2\xa0", b"\xe2\x80\xa8",
]


def _mutate(rng, data):
    b = bytearray(data)
    for _ in range(rng.randint(1, 3)):
        r = rng.random()
        i = rng.randint(0, len(b))
        if r < 0.3 and b:
            b[min(i, len(b) - 1)] = rng.randint(0, 255)
        elif r < 0.45 and b:
            del b[min(i, len(b) - 1)]
        elif r < 0.75:
            b[i:i] = rng.choice(_TOKENS)
        elif r < 0.85 and b:
            j = rng.randint(i, len(b))
            b[i:i] = b[i:j]
        elif b:
            del b[i:]
    return bytes(b)


def fuzz(seed, n):
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        doc = (_ws(rng) + _value(rng, 0, [rng.choice([1, 5, 30, 200])]) + _ws(rng)).encode("utf-8")
        if rng.random() < 0.6:
            doc = _mutate(rng, doc)
        out.append(doc.hex() + " " + expect(doc))
    return "\n".join(out)


# ---- numbers and strings ---------------------------------------------------


def numbers(seed, n):
    rng = random.Random(seed)
    out = []
    for i in range(n):
        t = number_text(rng)
        x = float(t)
        fbits = "range" if math.isinf(x) else "%016x" % struct.unpack("<Q", struct.pack("<d", x))[0]
        if "." in t or "e" in t or "E" in t:
            iv = "type"
        else:
            v = int(t)
            iv = str(v) if -(2**63) <= v < 2**63 else "range"
        out.append(t.encode().hex() + " " + fbits + " " + iv)
    return "\n".join(out)


def strings(seed, n):
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        k = rng.choice([0, 1, 3, 16, 17, 40, 200])
        cs = []
        for _ in range(rng.randint(0, k)):
            r = rng.random()
            if r < 0.4:
                cs.append(chr(rng.randint(0x20, 0x7E)))
            elif r < 0.6:
                cs.append(chr(rng.randint(0, 0x20)))
            elif r < 0.7:
                cs.append(rng.choice(['"', "\\", "/", "\x7f"]))
            elif r < 0.9:
                cs.append(chr(rng.choice([rng.randint(0x80, 0xD7FF), rng.randint(0xE000, 0xFFFF)])))
            else:
                cs.append(chr(rng.randint(0x10000, 0x10FFFF)))
        out.append("".join(cs).encode("utf-8").hex())
    return "\n".join(out)


def loads_hex(h):
    """The string a writer's output (hex) holds, as UTF-8 hex; for checking
    `Writer.string` (it must be JSON a strict reader takes)."""
    v = load(bytes.fromhex(h))
    return v.encode("utf-8").hex()


# ---- hand-written cases ----------------------------------------------------

CASES = [
    # accepted
    (b"[]", True), (b"{}", True), (b"0", True), (b"-0", True), (b'""', True), (b"null", True),
    (b"true", True), (b"false", True), (b" [ ] ", True), (b"\t\n\r [\t\n\r]\t\n\r", True),
    (b"[1,2,3]", True), (b'{"a":1,"b":[true,false,null]}', True), (b"1.5e300", True),
    (b"-1.5E-300", True), (b"1e+2", True), (b"1E2", True), (b"0.0", True), (b"0e0", True),
    (b"123456789012345678901234567890", True), (b"1e400", True), (b"1e-400", True),
    (b'"\\"\\\\\\/\\b\\f\\n\\r\\t"', True), (b'"\\u0000"', True), (b'"\\uD83D\\uDE00"', True),
    (b'"\\ud83d\\ude00"', True), (b'"\\uFFFF"', True), (b'"\xc3\xa9"', True), (b'"\xf0\x9f\x98\x80"', True),
    (b'"\xef\xbf\xbf"', True), (b'"\xf4\x8f\xbf\xbf"', True), (b'"\x7f"', True), (b'"\xe2\x80\xa8"', True),
    (b'{"a":{"a":1}}', True), (b'[{"a":1},{"a":2}]', True), (b'{"":0}', True), (b'{"a":1,"A":2}', True),
    (b"[[[[[[[[[[1]]]]]]]]]]", True), (b'{"\\u0061b":1,"ab\\u0000":2}', True),
    # keys of one length, 16 bytes or more, that differ inside a 16-byte block
    (b'{"0123456789abcdef":1,"x123456789abcdef":2}', True), (b'{"0123456789abcdefgh":1,"0123456789abcdeXgh":2}', True),
    (b'{"0123456789abcdef0123456789abcdef":1,"0123456789abcdef0123456789abcdeX":2}', True),
    # refused: structure
    (b"", False), (b" ", False), (b"[", False), (b"]", False), (b"[1,]", False), (b"[,1]", False),
    (b"[1 2]", False), (b'{"a":1,}', False), (b'{"a" 1}', False), (b'{"a":}', False), (b'{a:1}', False),
    (b"{'a':1}", False), (b'{"a":1 "b":2}', False), (b'{1:2}', False), (b"[1]]", False), (b"[1][2]", False),
    (b"1 2", False), (b"[1}", False), (b'{"a":1]', False), (b"[]x", False), (b"\xef\xbb\xbf[]", False),
    (b"[] /* c */", False), (b"// c\n[]", False), (b"\x0b[]", False), (b"\x0c[]", False),
    (b"\xc2\xa0[]", False), (b"[\x00]", False),
    # refused: literals
    (b"tru", False), (b"True", False), (b"nul", False), (b"NaN", False), (b"Infinity", False),
    (b"-Infinity", False), (b"[nulll]", False), (b"undefined", False), (b"nill", False), (b"trUe", False),
    (b"fakse", False), (b"[tru]", False), (b"[n]", False),
    # refused: numbers
    (b"01", False), (b"-01", False), (b"+1", False), (b".5", False), (b"5.", False), (b"1.e5", False),
    (b"1e", False), (b"1e+", False), (b"1E-", False), (b"-", False), (b"--1", False), (b"0x10", False),
    (b"1_000", False), (b"- 1", False), (b"1.5.5", False), (b"1e5e5", False), (b"\xd9\xa1", False),
    # refused: strings
    (b'"', False), (b'"abc', False), (b"'a'", False), (b'"\x00"', False), (b'"\x1f"', False),
    (b'"\n"', False), (b'"\t"', False), (b'"\\x41"', False), (b'"\\\'"', False), (b'"\\a"', False),
    (b'"\\u12"', False), (b'"\\u12G4"', False), (b'"\\U0041"', False), (b'"\\"', False),
    (b'"\\ud800"', False), (b'"\\udc00"', False), (b'"\\udfff"', False), (b'"\\udbff"', False), (b'"a\\udfffb"', False), (b'"\\ud800\\u0041"', False), (b'"\\ud800\\ud800"', False),
    (b'"\\udfff\\ud800"', False), (b'"\\ud800x"', False), (b'"\xff"', False), (b'"\x80"', False),
    (b'"\xc0\x80"', False), (b'"\xc1\xbf"', False), (b'"\xe0\x80\xaf"', False), (b'"\xed\xa0\x80"', False),
    (b'"\xf0\x80\x80\xaf"', False), (b'"\xf4\x90\x80\x80"', False), (b'"\xf5\x80\x80\x80"', False),
    (b'"\xc3"', False), (b'"\xe2\x82"', False), (b'"\xc3\x28"', False), (b'"\xe2\x28\xa1"', False),
    # refused: repeated keys
    (b'{"a":1,"a":2}', False), (b'{"a":1,"b":2,"a":3}', False), (b'{"a":1,"\\u0061":2}', False),
    (b'{"\xc3\xa9":1,"\\u00e9":2}', False), (b'{"x":{"a":1,"a":1}}', False),
    (b'{"0123456789abcdef0123":1,"0123456789abcdef0123":2}', False),
]


def dumps_hex(h):
    """json.dumps of the string whose UTF-8 is `h` (hex), as UTF-8 hex: how
    `Writer.string` must write it, byte for byte."""
    return json.dumps(bytes.fromhex(h).decode("utf-8"), ensure_ascii=False).encode("utf-8").hex()


def objects(seed, n):
    """`fuzz`'s format, for objects of 17 to 20,000 pairs (past the pair by
    pair check) whose keys share prefixes and lengths, a third of them
    with one key twice (the same bytes, or the same text escaped)."""
    rng = random.Random(seed)
    out = []
    for i in range(n):
        count = 20000 if i % 100 == 99 else rng.choice([17, 18, 40, 300, 2000])
        prefix = rng.choice(["", "k", "same_prefix_" * 3])
        # Unique by construction (a counter), sharing prefixes and lengths.
        keys = [json.dumps(prefix + "".join(rng.choice("xy") for _ in range(rng.randint(0, 3))) + "%x" % j) for j in range(count)]
        if rng.random() < 0.3:
            # One length, 16 to 40 bytes, differing anywhere (the first
            # bytes too): equal hashes then compare whole 16-byte blocks.
            width = rng.randint(16, 40)
            keys = [json.dumps(("%x" % j).rjust(width, rng.choice("xy"))[::-1]) for j in range(count)]
        if rng.random() < 0.35:
            k = rng.choice(keys)
            if rng.random() < 0.5 and len(k) > 2:
                k = '"' + "\\u%04x" % ord(k[1]) + k[2:]  # (the same key, escaped)
            keys.insert(rng.randint(0, len(keys)), k)
        doc = ("{" + ",".join(k + ":0" for k in keys) + "}").encode()
        out.append(doc.hex() + " " + expect(doc))
    return "\n".join(out)


def siphash_cases(seed, n):
    """Random byte strings (hex), each with Python's hash of it under
    PYTHONHASHSEED=0: SipHash-1-3 with a zero key (CPython's bytes hash;
    run in a child process with that variable set)."""
    rng = random.Random(seed)
    out = []
    for i in range(n):
        b = bytes(rng.getrandbits(8) for _ in range(rng.choice([1, 2, 7, 8, 9, 15, 16, 17, 31, 64, 100])))
        out.append(b.hex() + " %016x" % (hash(b) & (2**64 - 1)))
    return "\n".join(out)
