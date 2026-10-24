"""The server side of RESP2 and RESP3, for tests/redis.

It builds replies, renders values the way `redis.resp.Value` renders them,
makes random values for differential tests, and reads the commands a
client sent. Written from the RESP3 specification
(redis/redis-specifications), independently of src/redis. Bytes cross to
Mojo as hex strings: every builder returns hex, so a transcript is the
concatenation of their results.

A value here is a tuple: ("simple", bytes), ("error", bytes), ("int", n),
("bulk", bytes), ("null",), ("bool", b), ("double", text), ("big", text),
("blob_error", bytes), ("verbatim", fmt, bytes), ("array", [values]),
("map", [(key, value)]), ("set", [values]), ("push", [values]), and
("attr", [(key, value)], value): metadata, then the value it is for.
"""

import random


def _b(x):
    return x.encode() if isinstance(x, str) else bytes(x)


# ---- builders (hex) ------------------------------------------------------------


def simple(s):
    return (b"+" + _b(s) + b"\r\n").hex()


def error(s):
    return (b"-" + _b(s) + b"\r\n").hex()


def integer(n):
    return (b":%d\r\n" % n).hex()


def bulk(x):
    x = _b(x)
    return (b"$%d\r\n" % len(x) + x + b"\r\n").hex()


def null():
    return b"_\r\n".hex()


def null_bulk():
    return b"$-1\r\n".hex()


def null_array():
    return b"*-1\r\n".hex()


def boolean(v):
    return (b"#t\r\n" if v else b"#f\r\n").hex()


def double(text):
    return (b"," + _b(text) + b"\r\n").hex()


def big(text):
    return (b"(" + _b(text) + b"\r\n").hex()


def blob_error(x):
    x = _b(x)
    return (b"!%d\r\n" % len(x) + x + b"\r\n").hex()


def verbatim(fmt, x):
    x = _b(fmt) + b":" + _b(x)
    return (b"=%d\r\n" % len(x) + x + b"\r\n").hex()


def _aggregate(t, count, items):
    return (_b(t) + b"%d\r\n" % count).hex() + "".join(str(i) for i in items)


def array(*items):
    return _aggregate("*", len(items), items)


def map_(*keys_and_values):
    """Keys and values alternating."""
    return _aggregate("%", len(keys_and_values) // 2, keys_and_values)


def set_(*items):
    return _aggregate("~", len(items), items)


def push(*items):
    return _aggregate(">", len(items), items)


def attribute(*keys_and_values):
    """Only the attribute: the value it is for follows."""
    return _aggregate("|", len(keys_and_values) // 2, keys_and_values)


# ---- values: encoding and rendering ------------------------------------------


def encode(v, rng=None):
    """RESP bytes for value `v`. With `rng`, a null may take RESP2's forms."""
    t = v[0]
    if t == "simple":
        return b"+" + v[1] + b"\r\n"
    if t == "error":
        return b"-" + v[1] + b"\r\n"
    if t == "int":
        return b":%d\r\n" % v[1]
    if t == "bulk":
        return b"$%d\r\n" % len(v[1]) + v[1] + b"\r\n"
    if t == "null":
        return rng.choice([b"_\r\n", b"$-1\r\n", b"*-1\r\n"]) if rng else b"_\r\n"
    if t == "bool":
        return b"#t\r\n" if v[1] else b"#f\r\n"
    if t == "double":
        return b"," + _b(v[1]) + b"\r\n"
    if t == "big":
        return b"(" + _b(v[1]) + b"\r\n"
    if t == "blob_error":
        return b"!%d\r\n" % len(v[1]) + v[1] + b"\r\n"
    if t == "verbatim":
        x = _b(v[1]) + b":" + v[2]
        return b"=%d\r\n" % len(x) + x + b"\r\n"
    if t in ("array", "set", "push"):
        mark = {"array": b"*", "set": b"~", "push": b">"}[t]
        return mark + b"%d\r\n" % len(v[1]) + b"".join(encode(e, rng) for e in v[1])
    if t == "map":
        return b"%%%d\r\n" % len(v[1]) + b"".join(encode(k, rng) + encode(x, rng) for k, x in v[1])
    if t == "attr":
        return b"|%d\r\n" % len(v[1]) + b"".join(encode(k, rng) + encode(x, rng) for k, x in v[1]) + encode(v[2], rng)
    raise ValueError(t)


def _escape(x, quoted):
    out = []
    for c in x:
        if quoted and c in (34, 92):
            out.append("\\" + chr(c))
        elif 32 <= c <= 126:
            out.append(chr(c))
        else:
            out.append("\\x%02x" % c)
    s = "".join(out)
    return '"' + s + '"' if quoted else s


def render(v):
    """The rendering `redis.resp.Value` writes (an attribute disappears)."""
    t = v[0]
    if t == "simple":
        return "+" + _escape(v[1], False)
    if t == "error":
        return "-" + _escape(v[1], False)
    if t == "int":
        return ":%d" % v[1]
    if t == "bulk":
        return _escape(v[1], True)
    if t == "null":
        return "_"
    if t == "bool":
        return "#t" if v[1] else "#f"
    if t == "double":
        return "," + _escape(_b(v[1]), False)
    if t == "big":
        return "(" + _escape(_b(v[1]), False)
    if t == "blob_error":
        return "!" + _escape(v[1], True)
    if t == "verbatim":
        return "=" + _escape(_b(v[1]), False) + ":" + _escape(v[2], True)
    if t in ("array", "set", "push"):
        mark = {"array": "*[", "set": "~[", "push": ">["}[t]
        return mark + " ".join(render(e) for e in v[1]) + "]"
    if t == "map":
        return "%{" + " ".join(render(k) + " " + render(x) for k, x in v[1]) + "}"
    if t == "attr":
        return render(v[2])
    raise ValueError(t)


# ---- random values ---------------------------------------------------------------


def _bytes(rng, simple_line=False):
    n = rng.choice([0, 1, 2, 5, 17, 200])
    alphabet = list(range(256)) if not simple_line else [c for c in range(256) if c not in (10, 13)]
    if rng.random() < 0.5:
        alphabet = list(b"abcxyz019 _-") if simple_line else list(b"abc\r\n\x00\xff\"\\")
    return bytes(rng.choice(alphabet) for _ in range(n))


_DOUBLES = ["0", "1.5", "-2.25", "3e10", "1.5E-7", "inf", "-inf", "nan", "10", "-0.001", "+1"]


def random_value(rng, depth=0, top=False):
    kinds = ["simple", "error", "int", "bulk", "null", "bool", "double", "big", "blob_error", "verbatim"]
    if depth < 4:
        kinds += ["array", "map", "set", "attr"] * 2
    if top:
        kinds += ["push"]
    t = rng.choice(kinds)
    if t in ("simple", "error"):
        return (t, _bytes(rng, simple_line=True))
    if t == "int":
        return (t, rng.choice([0, 1, -1, 42, 2**63 - 1, -(2**63), rng.randrange(-(10**12), 10**12)]))
    if t in ("bulk", "blob_error"):
        return (t, _bytes(rng))
    if t == "null":
        return (t,)
    if t == "bool":
        return (t, rng.random() < 0.5)
    if t == "double":
        return (t, rng.choice(_DOUBLES))
    if t == "big":
        return (t, rng.choice(["0", "-1", "123456789012345678901234567890", "-99999999999999999999999"]))
    if t == "verbatim":
        return (t, rng.choice(["txt", "mkd"]), _bytes(rng))
    n = rng.choice([0, 1, 2, 3, 7])
    if t in ("array", "set", "push"):
        return (t, [random_value(rng, depth + 1) for _ in range(n)])
    if t == "map":
        return (t, [(random_value(rng, depth + 1), random_value(rng, depth + 1)) for _ in range(n)])
    # an attribute, then the value it is for
    pairs = [(random_value(rng, depth + 1), random_value(rng, depth + 1)) for _ in range(rng.choice([0, 1, 2]))]
    return ("attr", pairs, random_value(rng, depth, top))


def transcript(seed, count):
    """`count` random top-level values: (the hex of them all, their
    events rendered and joined by "|", how many are replies)."""
    rng = random.Random(seed)
    data = b""
    events = []
    replies = 0
    for _ in range(count):
        v = random_value(rng, top=True)
        data += encode(v, rng)
        inner = v
        while inner[0] == "attr":
            inner = inner[2]
        kind = "PUSH" if inner[0] == "push" else "REPLY"
        replies += kind == "REPLY"
        events.append(kind + " " + render(v))
    return data.hex(), "|".join(events), replies


# ---- what the client sent ------------------------------------------------------


def commands(data_hex):
    """The commands in `data_hex` (arrays of bulk strings), each as its
    arguments joined by spaces (escaped like bulk strings, unquoted), the
    commands joined by "|". Raises on anything else."""
    data = bytes.fromhex(data_hex)
    out = []
    i = 0
    while i < len(data):
        assert data[i : i + 1] == b"*", data[i:]
        end = data.index(b"\r\n", i)
        n = int(data[i + 1 : end])
        i = end + 2
        args = []
        for _ in range(n):
            assert data[i : i + 1] == b"$"
            end = data.index(b"\r\n", i)
            size = int(data[i + 1 : end])
            arg = data[end + 2 : end + 2 + size]
            assert data[end + 2 + size : end + 4 + size] == b"\r\n"
            i = end + 4 + size
            args.append(_escape(arg, False))
        out.append(" ".join(args))
    return "|".join(out)
