# mojson

Python's `json` module with its parsing and writing done in [Mojo](https://www.modular.com/mojo). `import mojson as json` is meant to change nothing but the speed: the same results, byte for byte, and the same exceptions.

> **Warning: this is an AI-generated project, and not all of it has been reviewed. Use it at your own risk; it is not meant for production.**
>
> The code, tests and documentation of mojson, and of the [mojo_net](https://github.com/advenn/mojo_net) repository it comes from, were written by an AI (Claude) at the direction of the maintainer. The tests hold it to the standard library's `json`, but it comes with no guarantee of any kind.

## Install

From TestPyPI, in two steps. Its dependency comes from PyPI first; then mojson alone from TestPyPI. Anyone can upload to TestPyPI under any free name, so a one-line install that also searches it for dependencies could pick up someone else's `mojo-compiler`:

```bash
pip install mojo-compiler==1.2.0
pip install -i https://test.pypi.org/simple/ --no-deps mojson
```

Requirements:
- **Linux** on x86_64 with AVX2 (Haswell, 2013, or newer), or on aarch64 (Neoverse N1 / Graviton2 or newer); glibc 2.34 or newer.
- **CPython** 3.12, 3.13, 3.14 or 3.15, as normally built: pip installs no wheel on the free-threaded build, and an import there raises ImportError.
- **`mojo-compiler`** from PyPI (about 80 MB), the first step above: it holds the Mojo runtime the extension links, under [Modular's licence](https://www.modular.com/legal/max). mojson ships none of it.

## Use

```python
import mojson as json

data = json.loads(body)            # str, bytes or bytearray: json's results and errors
text = json.dumps(obj, indent=2)   # json's output, byte for byte
```

`load`, `dump`, `JSONDecodeError`, `JSONDecoder` and `JSONEncoder` are there too: the last three are json's own. `dump` writes as it goes, in pieces of about 64 KiB, so a large document never takes its whole text in memory.

Beyond json:

```python
json.loads(s, rfc8259=True)        # strict RFC 8259: repeated keys, NaN, Infinity, lone surrogates refused
json.loads(s, max_depth=64)        # nesting past 64 arrays and objects refused
json.dumpb(obj)                    # dumps as UTF-8 bytes, with no str in between
json.dumps(obj, extended=True)     # also datetime, date, time, UUID, Decimal (exact), Enum, dataclasses, sets
```

## How it stays json

The extension takes the common cases. Everything else goes to the standard library's `json` unchanged: a custom `cls` that overrides `encode`, keyword arguments json would refuse, UTF-16 and UTF-32 input, and every text the parser refuses, which json then reads again to raise its own error, with its message and position. The writer follows `_json.c` rule by rule: subclasses of int, float, list and dict are written as json writes them, floats in `float.__repr__`'s layout.

The test suite holds mojson to json on the 8 encodings json detects, every escape, numbers at every edge, every hook, malformed texts, deep nesting, 20,000 floats, 3,000 random strings, and thousands of generated and mutated documents.

## Speed

Measured on one core of an Intel i5-1145G7, CPython 3.14, against json and orjson on real documents (twitter, citm_catalog, canada, github, and payloads of an LLM API). Every library got bytes, and its result matched json's:

| | mojson against json | mojson against orjson |
|---|---|---|
| `loads` | 1.7 to 4.1 times as fast | 0.61 to 0.91 of its speed |
| `dumps` | 3.3 to 7.0 times as fast | 0.35 to 0.69 of its speed |

On a 1 GB document, `loads` takes 4.7 s (json 8.3 s, orjson 3.7 s), and `dumps` 1.4 s (json 4.2 s, orjson 0.76 s).

The tables, and how they were taken, are in [docs/mojson.md](https://github.com/advenn/mojo_net/blob/main/docs/mojson.md#measured).

## Licence

mojson is under the Apache License 2.0. Its dependency `mojo-compiler` is Modular's, under [Modular's licence](https://www.modular.com/legal/max).
