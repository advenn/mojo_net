"""mojson against the standard library's json, which is its specification:
the same result for every input and arguments, and the same exception
(type, message, position) for every refusal; then what mojson adds.

    pixi run mojson-test     (builds the extension into build/python first)

Differential parts use tests/json/json_oracle.py's generator of documents
and its mutations (bytes changed, cut or repeated, tokens planted), and
MOJSON_FUZZ_SCALE multiplies their counts.
"""

import collections
import dataclasses
import datetime
import decimal
import enum
import io
import json
import math
import os
import random
import struct
import sys
import unittest
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "json"))

import json_oracle  # noqa: E402
import mojson  # noqa: E402

SCALE = int(os.environ.get("MOJSON_FUZZ_SCALE", "1"))
CORPUS = os.environ.get("MOJSON_CORPUS", os.path.join(HERE, "..", "..", "build", "bench_json"))
# The files of that corpus (bench/json/corpus.py and payloads.py), by name:
# never whatever else lies in the directory (a 1 GB file once did).
CORPUS_NAMES = ["chunk", "chat_completion", "tools_request", "embeddings", "github", "twitter", "citm_catalog", "canada", "recipe_book"]


def corpus_files():
    return [n + ".json" for n in CORPUS_NAMES if os.path.isfile(os.path.join(CORPUS, n + ".json"))]


def outcome(fn, *args, **kw):
    """What a call gives: ("ok", value) or ("raise", type, str, attributes)."""
    try:
        return ("ok", fn(*args, **kw))
    except Exception as e:  # noqa: BLE001
        attrs = tuple(getattr(e, a, None) for a in ("msg", "pos", "lineno", "colno"))
        return ("raise", type(e), str(e), attrs)


def same(a, b):
    """Equal results, of the same types, NaN equal to NaN and -0.0 apart
    from 0.0 (with its own stack: results nest deeply)."""
    todo = [(a, b)]
    while todo:
        a, b = todo.pop()
        if type(a) is not type(b):
            return False
        if isinstance(a, float):
            if not ((math.isnan(a) and math.isnan(b)) or (a == b and math.copysign(1, a) == math.copysign(1, b))):
                return False
        elif isinstance(a, (list, tuple)):
            if len(a) != len(b):
                return False
            todo.extend(zip(a, b))
        elif isinstance(a, dict):
            if list(a.keys()) != list(b.keys()):
                return False
            todo.extend((a[k], b[k]) for k in a)
        elif a != b:
            return False
    return True


class Loads(unittest.TestCase):
    def check(self, s, **kw):
        want = outcome(json.loads, s, **kw)
        got = outcome(mojson.loads, s, **kw)
        if want[0] == "ok":
            self.assertEqual(got[0], "ok", (s, kw, got))
            self.assertTrue(same(got[1], want[1]), (s, kw, got[1], want[1]))
        else:
            self.assertEqual(got[:3], want[:3], (s, kw))
            self.assertEqual(got[3], want[3], (s, kw))

    def test_corpus(self):
        names = corpus_files()
        if not names:
            self.skipTest("no corpus in %s (pixi run bench-json writes it)" % CORPUS)
        for name in names:
            with open(os.path.join(CORPUS, name), "rb") as f:
                data = f.read()
            self.check(data)
            self.check(data.decode("utf-8"))
            self.check(bytearray(data))

    def test_scalars_and_numbers(self):
        for s in ["0", "-0", "1", "-1", "123456789012345678", "1234567890123456789", "-9223372036854775808",
                  "9223372036854775808", "1" * 400, "0.5", "-0.0", "1e5", "1E+5", "1e-5", "1.5e300", "1e400",
                  "-1e400", "1e-400", "4.9e-324", "2.2250738585072014e-308", "0.1", "17.0000000000000000001",
                  "NaN", "Infinity", "-Infinity", "true", "false", "null", '""', '"x"', "[]", "{}", " [ ] ",
                  "\t\n\r 1 \t\n\r"]:
            self.check(s)
        self.check("1" * 5000)  # (past int's digit limit: json's ValueError)

    def test_strings(self):
        for s in ['"\\u00e9"', '"\\ud83d\\ude00"', '"\\ud800"', '"\\udc00x"', '"\\ud800\\u0041"', '"\\uDBFF\\uDFFF"',
                  '"\\ud800\\ud800"', '"a\\/b"', '"\\b\\f\\n\\r\\t\\"\\\\"', '"été 中 \U0001F600"',
                  '"\x7f"', '"tab\there"', '"nul\x00"']:
            self.check(s)
            self.check(s, strict=False)
            self.check(s.encode("utf-8", "surrogatepass"))
        self.check(b'"\xed\xa0\x80"')  # (a surrogate in UTF-8's form: surrogatepass)
        self.check('"\ud800"')  # (a str holding a lone surrogate)
        self.check(b'"\xff"')
        self.check(b'"\xc0\x80"')

    def test_encodings_and_bom(self):
        doc = '{"a": "é", "b": [1, 2]}'
        for enc in ["utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"]:
            self.check(doc.encode(enc))
        self.check("﻿[1]")
        self.check(b"\xef\xbb\xbf[1]")

    def test_repeated_keys_last_wins(self):
        self.check('{"a": 1, "a": 2, "b": 3, "a": 4}')
        self.check('{"a": 1, "\\u0061": 2}')
        self.check('{"a": 1, "a": 2}', object_pairs_hook=list)

    def test_hooks(self):
        doc = '{"a": [1, 2.5, "x", NaN, {"b": null}], "c": 12345678901234567890}'
        self.check(doc, object_hook=lambda d: ("hook", sorted(d)))
        self.check(doc, object_pairs_hook=lambda p: ("pairs", p))
        self.check(doc, object_pairs_hook=collections.OrderedDict)
        self.check(doc, object_hook=dict, object_pairs_hook=list)
        self.check(doc, parse_float=decimal.Decimal)
        self.check(doc, parse_int=float)
        self.check(doc, parse_int=str, parse_float=str)
        self.check(doc, parse_float=float, parse_int=int)
        self.check(doc, parse_constant=lambda c: "C:" + c)
        self.check(doc, parse_constant=None, object_hook=None)

        def boom(_):
            raise KeyError("boom")

        self.check(doc, object_hook=boom)
        self.check(doc, parse_float=boom)

    def test_cls_and_unknown_arguments(self):
        class Upper(json.JSONDecoder):
            def decode(self, s):
                return super().decode(s.upper())

        self.check('{"a": "b"}', cls=Upper)
        self.check('{"a": "b"}', cls=json.JSONDecoder)
        self.check('{"a": "b"}', nonsense=1)
        self.check('"\x01"', strict=False)
        self.check('"\x01"', strict=True)

    def test_not_text(self):
        for s in [None, 1, 1.5, [], memoryview(b"[1]"), object()]:
            self.check(s)

    def test_errors_are_jsons(self):
        for s in ["", " ", "[", "[1,", "[1,]", "{", '{"a"', '{"a":', '{"a":1,}', '{1: 2}', "[1 2]", "01", "-",
                  "1.", ".5", "+1", "1e", "1e+", "0x1", "tru", "nul", "True", "'a'", '"abc', '"\\x"', '"\\u12"',
                  '"\\u12zz"', "[1] x", "[1]]", "nan", "inf", "-Inf", "[,]", "{,}", '"\\', "\x00", "/*c*/1"]:
            self.check(s)
            self.check(s.encode())

    def test_deep_nesting(self):
        for d in [10, 100, 511, 512, 513, 1000, 5000]:
            self.check("[" * d + "]" * d)
            self.check('{"a":' * d + "1" + "}" * d)

    def test_differential_fuzz(self):
        rng = random.Random(20261102)
        bad = 0
        for _ in range(3000 * SCALE):
            doc = (json_oracle._ws(rng) + json_oracle._value(rng, 0, [rng.choice([1, 5, 30, 200])])
                   + json_oracle._ws(rng)).encode("utf-8")
            if rng.random() < 0.6:
                doc = json_oracle._mutate(rng, doc)
            for s in (doc, doc.decode("utf-8", "replace")):
                want = outcome(json.loads, s)
                got = outcome(mojson.loads, s)
                ok = (got[0] == want[0] == "ok" and same(got[1], want[1])) or (got[0] == want[0] == "raise"
                                                                              and got[1:] == want[1:])
                if not ok:
                    bad += 1
                    if bad < 5:
                        print("differs:", s[:200], want[:3], got[:3])
        self.assertEqual(bad, 0)

    def test_load_reads_a_file(self):
        self.assertEqual(mojson.load(io.StringIO('{"a": [1]}')), {"a": [1]})
        self.assertEqual(mojson.load(io.BytesIO(b'{"a": [1]}')), {"a": [1]})

    def test_names(self):
        for name in json.__all__ + ["detect_encoding", "decoder", "encoder", "scanner"]:
            self.assertTrue(hasattr(mojson, name), name)
        self.assertIs(mojson.JSONDecodeError, json.JSONDecodeError)


class Color(enum.IntEnum):
    RED = 1


class Shade(str, enum.Enum):
    DARK = "dark"


class MyInt(int):
    def __repr__(self):
        return "MyInt!"


class MyFloat(float):
    def __repr__(self):
        return "MyFloat!"


class MyStr(str):
    pass


class MyList(list):
    def __iter__(self):
        return iter(["not", "these"])


class MyDict(dict):
    def items(self):
        return [("x", 1)]


class MyTuple(tuple):
    pass


def random_float(rng):
    r = rng.random()
    if r < 0.4:
        return struct.unpack("<d", struct.pack("<Q", rng.getrandbits(64)))[0]
    if r < 0.7:
        return round(rng.uniform(-1e6, 1e6), rng.randint(0, 17))
    if r < 0.8:
        return float(rng.randint(-10 ** 17, 10 ** 17))
    return rng.choice([0.0, -0.0, 1e16, 1e15, 1e-4, 1e-5, 9.999999999999999e15, 0.0001, 0.00009999, 5e-324,
                       1.7976931348623157e308, 2.0 ** 53, 2.0 ** 63, 0.1, 1 / 3, 123.0, 1e21, 1e22])


def random_text(rng):
    cps = [rng.randint(0x20, 0x7E), rng.randint(0, 0x1F), 0x7F, 0x22, 0x5C, rng.randint(0x80, 0xFF),
           rng.randint(0x100, 0xD7FF), rng.randint(0xD800, 0xDFFF), rng.randint(0xE000, 0xFFFF),
           rng.randint(0x10000, 0x10FFFF), 0x2028]
    n = rng.choice([0, 1, 3, 8, 15, 16, 17, 31, 32, 33, 100])
    kind = rng.random()
    out = []
    for _ in range(n):
        if kind < 0.5:
            out.append(chr(rng.randint(0x20, 0x7E)) if rng.random() < 0.9 else chr(rng.choice(cps[1:5])))
        else:
            out.append(chr(rng.choice(cps)))
    return "".join(out)


def random_object(rng, depth=0):
    r = rng.random()
    if depth > 5 or r < 0.5:
        r = rng.random()
        if r < 0.3:
            return random_text(rng)
        if r < 0.5:
            return rng.choice([0, 1, -1, rng.randint(-10 ** 18, 10 ** 18), rng.randint(-10 ** 40, 10 ** 40)])
        if r < 0.75:
            return random_float(rng)
        return rng.choice([None, True, False])
    if r < 0.75:
        items = [random_object(rng, depth + 1) for _ in range(rng.choice([0, 1, 3, 10]))]
        return tuple(items) if rng.random() < 0.2 else items
    d = {}
    for _ in range(rng.choice([0, 1, 3, 10])):
        k = rng.choice([random_text(rng), random_text(rng), rng.randint(-5, 5), random_float(rng), True, None])
        d[k] = random_object(rng, depth + 1)
    return d


class Dumps(unittest.TestCase):
    OPTIONS = [
        {},
        {"ensure_ascii": False},
        {"indent": 2},
        {"indent": "\t", "sort_keys": True},
        {"indent": 0},
        {"separators": (",", ":")},
        {"separators": (" , ", " : "), "indent": 1},
        {"allow_nan": False},
        {"skipkeys": True},
        {"check_circular": False},
        {"sort_keys": True, "ensure_ascii": False},
    ]

    def check(self, o, **kw):
        want = outcome(json.dumps, o, **kw)
        got = outcome(mojson.dumps, o, **kw)
        self.assertEqual(got[:3], want[:3], (o, kw))
        if want[0] == "ok" and not any(0xD800 <= ord(c) <= 0xDFFF for c in want[1]):
            self.assertEqual(outcome(mojson.dumpb, o, **kw), ("ok", want[1].encode("utf-8")), (o, kw))

    def test_corpus(self):
        names = corpus_files()
        if not names:
            self.skipTest("no corpus in %s" % CORPUS)
        for name in names:
            with open(os.path.join(CORPUS, name), "rb") as f:
                o = json.loads(f.read())
            for kw in self.OPTIONS:
                self.check(o, **kw)

    def test_floats(self):
        rng = random.Random(7)
        xs = [random_float(rng) for _ in range(20000 * SCALE)]
        self.assertEqual(mojson.dumps(xs), json.dumps(xs))
        for x in [float("nan"), float("inf"), -float("inf")]:
            for kw in [{}, {"allow_nan": False}]:
                self.check(x, **kw)
                self.check({x: 1}, **kw)

    def test_strings(self):
        rng = random.Random(8)
        for _ in range(3000 * SCALE):
            s = random_text(rng)
            self.check(s)
            self.check(s, ensure_ascii=False)
            self.check({s: s}, sort_keys=True)

    def test_random_objects(self):
        rng = random.Random(9)
        for _ in range(400 * SCALE):
            o = random_object(rng)
            for kw in self.OPTIONS:
                self.check(o, **kw)

    def test_subclasses_and_enums(self):
        o = {"i": MyInt(5), "f": MyFloat(1.5), "s": MyStr("x"), "l": MyList([1, 2]), "d": MyDict(a=1),
             "t": MyTuple((1, 2)), "e": Color.RED, "se": Shade.DARK, MyStr("k"): 1, MyInt(3): 2, Color.RED: 3,
             MyFloat(2.5): 4}
        for kw in self.OPTIONS:
            self.check(o, **kw)

    def test_keys(self):
        for k in [1, -1, 10 ** 30, 1.5, float("nan"), True, False, None, "s", (1, 2), b"x", 1j]:
            self.check({k: 1})
            self.check({k: 1}, skipkeys=True)
            self.check({k: 1, "z": 2}, skipkeys=True, indent=2)
        self.check({1: 1, "a": 2}, sort_keys=True)  # (json's TypeError: mixed keys)

    def test_default_and_errors(self):
        self.check(object())
        self.check({"a": [datetime.date(2026, 1, 2)]})
        self.check(datetime.date(2026, 1, 2), default=str)
        self.check({"a": {1, 2}}, default=sorted)
        self.check(decimal.Decimal("1.5"), default=lambda d: [float(d)])

        def boom(o):
            raise KeyError(o)

        self.check(object(), default=boom)
        self.check(object(), default=lambda o: o)  # (default returns its argument: a cycle)
        a = []
        a.append(a)
        self.check(a)
        d = {}
        d["d"] = d
        self.check(d)
        self.check(1, indent=1.5)
        self.check([1], separators=(1, 2))
        self.check([1], separators=(",",))
        self.check([1], nonsense=True)

    def test_custom_encoder(self):
        class Dates(json.JSONEncoder):
            def default(self, o):
                if isinstance(o, datetime.date):
                    return o.isoformat()
                return super().default(o)

        class Loud(json.JSONEncoder):
            def encode(self, o):
                return super().encode(o).upper()

        for kw in [{}, {"indent": 2}, {"sort_keys": True, "separators": (",", ":")}]:
            self.check({"d": datetime.date(2026, 1, 2), "x": "y"}, cls=Dates, **kw)
            self.check({"x": "y"}, cls=Loud, **kw)
            self.check(object(), cls=Dates, **kw)

    def test_deep(self):
        for d in [10, 100, 500]:
            o = []
            for i in range(d):
                o = [o, 1] if i % 2 else {"k": o, "n": None}
            self.check(o)

    def test_dump_writes_a_file(self):
        f = io.StringIO()
        mojson.dump({"a": [1, "é"]}, f, ensure_ascii=False)
        self.assertEqual(f.getvalue(), json.dumps({"a": [1, "é"]}, ensure_ascii=False))


class Extensions(unittest.TestCase):
    def test_rfc8259(self):
        for s, ok in [("[1]", True), ('{"a": 1, "a": 2}', False), ('{"a": 1, "\\u0061": 2}', False), ("NaN", False),
                      ("[-Infinity]", False), ('"\\ud800"', False), ('"\\ud83d\\ude00"', True), (b'"\xed\xa0\x80"', False),
                      ('"\x01"', False), ("[1,]", False), ('{"a": {"b": 1, "b": 2}}', False)]:
            got = outcome(mojson.loads, s, rfc8259=True)
            if ok:
                self.assertEqual(got, ("ok", json.loads(s)), s)
            else:
                self.assertEqual(got[0:2], ("raise", json.JSONDecodeError), (s, got))
        s = '{"\u00e9": 1, "\u00e9": 2}'
        e = outcome(mojson.loads, s, rfc8259=True)
        self.assertEqual(e[3][1], s.index("}"))  # (a position in characters, at the '}')
        self.assertEqual(outcome(mojson.loads, s.encode(), rfc8259=True)[3][1], s.index("}"))
        self.assertEqual(mojson.loads(b'{"a": [1, 2]}', rfc8259=True, object_hook=dict), {"a": [1, 2]})
        self.assertEqual(outcome(mojson.loads, 1, rfc8259=True)[1], TypeError)
        self.assertEqual(outcome(mojson.loads, "[1]".encode("utf-16"), rfc8259=True)[1], json.JSONDecodeError)
        self.assertEqual(outcome(mojson.loads, '"\ud800"', rfc8259=True)[1], json.JSONDecodeError)  # (a str with one)

    def test_max_depth(self):
        self.assertEqual(mojson.loads("[[1]]", max_depth=2), [[1]])
        self.assertEqual(outcome(mojson.loads, "[[1]]", max_depth=1)[1], json.JSONDecodeError)
        self.assertEqual(outcome(mojson.loads, "[1]", max_depth=-1)[1], ValueError)
        self.assertEqual(outcome(mojson.loads, "[1]", max_depth=1, cls=json.JSONDecoder)[0], "ok")

    def test_dumpb(self):
        o = {"a": ["é", 1.5, None]}
        self.assertEqual(mojson.dumpb(o), json.dumps(o).encode())
        self.assertEqual(mojson.dumpb(o, ensure_ascii=False), json.dumps(o, ensure_ascii=False).encode())
        self.assertEqual(outcome(mojson.dumpb, "\ud800", ensure_ascii=False)[1], UnicodeEncodeError)

    def test_extended(self):
        @dataclasses.dataclass
        class P:
            x: int
            when: datetime.datetime

        class E(enum.Enum):
            A = "a"

        u = uuid.UUID(int=1)
        t = datetime.datetime(2026, 11, 2, 1, 2, 3, tzinfo=datetime.timezone.utc)
        o = {"p": P(1, t), "u": u, "d": decimal.Decimal("1.10"), "big": decimal.Decimal("1E+400"),
             "nan": decimal.Decimal("NaN"), "e": E.A, "s": frozenset([3]), "date": t.date(), "time": t.time()}
        got = json.loads(mojson.dumps(o, extended=True))
        self.assertEqual(got, {"p": {"x": 1, "when": t.isoformat()}, "u": str(u), "d": 1.1, "big": float("inf"),
                               "nan": got["nan"], "e": "a", "s": [3], "date": "2026-11-02", "time": "01:02:03"})
        self.assertIn('"d": 1.10', mojson.dumps(o, extended=True))
        self.assertIn('"big": 1e+400', mojson.dumps(o, extended=True))
        self.assertEqual(outcome(mojson.dumps, object(), extended=True)[1], TypeError)
        self.assertEqual(mojson.dumps(object(), extended=True, default=lambda o: "x"), '"x"')
        self.assertEqual(outcome(mojson.dumps, o)[1], TypeError)  # (not without extended)


if __name__ == "__main__":
    unittest.main()
