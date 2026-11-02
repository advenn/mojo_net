# mojson: Python's json module, in Mojo

`mojson` is a Python package with the standard library json's API whose parsing and writing are done by the Mojo `json` package (`docs/json.md`). It lives in `python/mojson`: a Mojo extension module, `_mojson`, and a small Python layer over it.

**Status: done through Y4**, tested against the standard library's json on CPython 3.12 to 3.15. Its wheels are prepared for TestPyPI (the user's decision, 2026-11-02), and nothing else of the repository is published; like the rest of it, mojson is not meant for production use.

## Use
```bash
pixi run mojson-build                  # build/python/mojson: __init__.py and _mojson.so
PYTHONPATH=build/python python3 -c 'import mojson as json; print(json.dumps(json.loads("[1, 2.5]")))'
pixi run mojson-test                   # build, then tests/mojson against the standard library's json
pixi run -e pyjson bench-json-compare  # mojson beside json, orjson, ujson, msgspec, simdjson, ...
```

`import mojson as json` changes nothing but the speed:

- `loads`, `load`, `dumps` and `dump` take json's arguments (`cls`, the hooks, `strict`, `indent`, `separators`, `default`, `sort_keys`, ...) and give json's results, byte for byte.
- `dump` writes as json.dump does, in str pieces to `fp.write`: of about 64 KiB, as the text goes, so the whole text is never held. Writing a 1 GB document took no memory past the objects, where `fp.write(dumps(obj))` took 2.1 GB more (the str, and its encoding into the file).
- They raise json's exceptions: `JSONDecodeError` is json's own class, with json's messages and positions.
- `JSONDecoder`, `JSONEncoder`, `detect_encoding` and the `decoder`, `encoder` and `scanner` modules are json's, re-exported.

## How it stays json
The extension takes the common cases. Whatever it does not take goes, unchanged, to the standard library's json:

- **Arguments it does not read.** A custom `cls` that overrides `encode` or `iterencode`, and keyword arguments json would refuse (so json raises its own TypeError). A `JSONEncoder` subclass that only changes `default` or the options keeps the fast path: its settings are read from an instance.
- **Text that is not UTF-8 text.** Bytes with a byte order mark or NULs (UTF-16 and UTF-32, which json detects), a str holding lone surrogates, objects that are not str, bytes or bytearray.
- **Every text the parser refuses.** json then reads it again and raises its own error (or, past the fast path's limits, returns its own result). Errors are therefore json's exactly; they cost a second parse, and only invalid text pays it.

The parser reads in `json.Dialect.python()`, which accepts what Python's json accepts beyond RFC 8259:

- a key twice in one object (the last wins in the dict, as in json);
- `NaN`, `Infinity` and `-Infinity`;
- lone surrogates, as `\ud800` escapes and in UTF-8's form (Python decodes bytes with "surrogatepass");
- control characters in strings, with `strict=False`.

Numbers are read as json reads them. Integers are exact at any size, under Python's limit on digits. A float is the nearest double (`json.read_float`, Eisel-Lemire), else `PyOS_string_to_double`, which is what `float()` uses; `1e400` is an infinity. The writer follows `_json.c`'s encoder rule by rule (`python/mojson/ext/encode.mojo`):

- subclasses of int and float are written by `int.__repr__` and `float.__repr__`, not their own;
- lists, tuples and their subclasses are written by their items, dicts and their subclasses by `items()`;
- keys are converted, skipped or refused as json does;
- floats are written in `float.__repr__`'s layout, from Ryū's shortest digits;
- circular references and the recursion limit raise as json raises.

## Beyond json
- **`loads(s, rfc8259=True)`** reads strictly by RFC 8259 with the Mojo parser's own rules: a key twice in one object, `NaN` and the infinities, lone surrogates, and control characters are errors (a `JSONDecodeError` whose position is in characters), where json accepts them. It is for input from elsewhere, where two parsers that disagree on a repeated key disagree on what a request says (see "Decisions" in `docs/json.md`).
- **`loads(s, max_depth=n)`**: nesting past `n` arrays and objects is a `JSONDecodeError`. json's only bound is the interpreter's recursion limit.
- **`dumpb(obj, **kw)`**: `dumps`, as UTF-8 bytes, with no str in between (for a socket or an HTTP body).
- **`dumps(obj, extended=True)`** writes more types before `default` is asked:
  - datetime, date and time, in ISO 8601;
  - UUID, as its string;
  - Decimal: a finite one as its own digits (a JSON number, no float in between); NaN and the infinities as json writes the floats;
  - Enum members, by their value;
  - dataclass instances, as objects of their fields;
  - set and frozenset, as arrays.

## How it is built
- **`ext/capi.mojo`** is the extension's only C. It resolves the CPython C API from the interpreter that imports it (`dlopen(NULL)`) into typed function pointers, once.
  - Objects travel as their addresses, and out-parameters as typed mutable pointers. As `Int` addresses, the compiler read them back unchanged (CLAUDE.md, "FFI").
  - A few layouts are read directly where a call would cost more than the work: an object's type, a str's header and characters, a list's item array. Each is checked at import against the C API, on objects built for the check, and used only where it agreed. These are CPython 3.12 to 3.15's layouts (3.15's headers lay them out as 3.14's), with the GIL, on 64-bit platforms.
- **`ext/decode.mojo`** builds the objects:
  - without hooks, as the text is read (`Builder`, a `Document.scan` handler): each value goes on a stack, and an array or object takes its items off the top when it ends, where `scan` gives their number. No document is built;
  - with hooks, from a parsed `json.Document` (`Decoder`, through `Document.visit`). No hook runs before the whole text is known to parse. A text the parser refuses goes to json, which reads it again, and a hook that ran on its first part would run twice;
  - an ASCII str with `PyUnicode_New` and a copy, any other through `PyUnicode_DecodeUTF8`;
  - lists filled in place, dicts presized;
  - ASCII keys of up to 64 bytes from a cache of 1,024 str objects shared by every call, each with its hash computed once, as json's per-call memo shares them.
- **`ext/encode.mojo`** writes into the result str or bytes itself, or into raw memory (`Out`), reserving room once per string and once per dict pair. It reads str characters in their own width (1, 2 or 4 bytes), and keeps dict keys encoded in `KeyBytes` across calls ("Measured").
- **`_mojson.mojo`** holds one `Codec` per process: the C API, a reused `Document` (a scan's scratch) and decoder state, the key cache, and the text buffer. A call allocates only the objects it returns, and buffers past 1 MiB (a document) or 4 MiB (text) are not kept between calls.
- **State behind one pointer.** The decoder and the encoder keep their state in a struct and pass a pointer to it. In Mojo 1.2 a struct passed as `mut`, or as `ref` to a mutable value, to a function not inlined was copied in and out of every call; for the encoder's state and options that was half its time (CLAUDE.md, "Mojo 1.2 pitfalls").

## Testing
`tests/mojson/test_mojson.py` (standard library unittest; `pixi run mojson-test`, in `ci`) holds mojson to the standard library's json. Each case must give json's result: equal values of equal types, NaN as NaN, -0.0 apart from 0.0. A raise must match in type, message, `pos`, `lineno` and `colno`.

- **loads:**
  - the corpus as bytes, str and bytearray;
  - numbers at every edge: the int digit limit, 19 and 20 digits, overflow and underflow, subnormals;
  - strings: every escape, surrogate pairs and lone ones, raw control characters with and without `strict`, invalid UTF-8;
  - all eight encodings json detects, and the byte order marks;
  - repeated keys;
  - every hook alone and together, and hooks that raise;
  - custom decoders, and arguments json refuses;
  - objects that are not text;
  - 37 malformed texts;
  - nesting to 5,000 levels.
- **Differential fuzzing:** 3,000 generated documents, 60% of them mutated by `tests/json/json_oracle.py`, each as bytes and as text. Every outcome must be json's. `MOJSON_FUZZ_SCALE=n` multiplies the count; it has passed at 5.
- **dumps:**
  - the corpus under 11 option sets;
  - 20,000 floats: random bits, short decimals, integers, the repr layout's edges;
  - 3,000 random strings of every character class, ensure_ascii on and off, as keys too;
  - 400 random structures under every option set;
  - subclasses of int, float, str, list, dict and tuple whose own methods json ignores, and enums;
  - every key type, with and without `skipkeys`, and sorting mixed keys;
  - `default` that converts, raises, or returns its argument;
  - circular lists and dicts;
  - invalid `indent` and `separators`;
  - custom encoders that override `default` or `encode`;
  - deep nesting.
- **Beyond json:** `rfc8259` refusals and their positions in characters, `max_depth`, `dumpb` (including a lone surrogate's UnicodeEncodeError), and every `extended` type.

## Measured
`pixi run -e pyjson bench-json-compare`: each library's best of 7 samples of at least 0.1 s of thread CPU time, pinned to one core of an i5-1145G7 (Tiger Lake), CPython 3.14, mojson 0.1.3 built as its wheels are (x86-64-v3).

Every library got the same bytes, and its result was checked against json's.
- The run took three minutes, under a load average of 1.1 to 1.7.
- yyjson's `loads` (its Python binding, 4.x) differs from json's on the five files with text beyond ASCII. Given bytes, it decodes their strings as Latin-1: "Été" comes back as "Ã\x89tÃ©". Its times stand, but its results are wrong. The other libraries match json.
- simdjson's `loads` builds every object at once, as json does. Its lazy `Parser` is in `docs/json.md`, beside the Mojo parser.

**loads** (bytes in, Python objects out):

|file|size|json|ujson|simdjson|yyjson|msgspec|orjson|mojson|json / mojson|orjson / mojson|
|---|---|---|---|---|---|---|---|---|---|---|
|chunk|220 B|2.14 µs|0.82 µs|1.14 µs|0.73 µs|0.47 µs|0.59 µs|0.70 µs|3.1x|0.84|
|chat_completion|557 B|3.46 µs|1.60 µs|1.74 µs|1.25 µs|0.93 µs|1.07 µs|1.17 µs|3.0x|0.91|
|tools_request|3.4 KB|17.0 µs|11.9 µs|11.9 µs|9.73 µs|7.67 µs|8.20 µs|8.75 µs|1.9x|0.94|
|embeddings|511.5 KB|4.80 ms|1.97 ms|851 µs|756 µs|958 µs|708 µs|1.07 ms|4.5x|0.66|
|github|55.8 KB|153 µs|128 µs|102 µs|83.0 µs|69.0 µs|70.5 µs|72.9 µs|2.1x|0.97|
|twitter|631.5 KB|2.84 ms|1.67 ms|1.69 ms|1.15 ms|1.21 ms|1.00 ms|1.25 ms|2.3x|0.80|
|citm_catalog|1.7 MB|7.32 ms|3.90 ms|3.90 ms|3.02 ms|3.44 ms|2.83 ms|2.94 ms|2.5x|0.96|
|canada|2.3 MB|29.1 ms|11.9 ms|8.03 ms|5.70 ms|8.27 ms|6.81 ms|9.79 ms|3.0x|0.69|
|recipe_book|30.0 KB|98.3 µs|60.5 µs|53.4 µs|43.0 µs|45.3 µs|35.9 µs|43.8 µs|2.2x|0.82|

**dumps** (Python objects in, a str out; msgspec and orjson return bytes):

|file|size|json|ujson|yyjson|msgspec|orjson|mojson|json / mojson|orjson / mojson|
|---|---|---|---|---|---|---|---|---|---|
|chunk|220 B|2.13 µs|0.71 µs|0.70 µs|0.27 µs|0.19 µs|0.54 µs|3.9x|0.35|
|chat_completion|557 B|3.18 µs|1.37 µs|1.11 µs|0.46 µs|0.28 µs|0.83 µs|3.8x|0.34|
|tools_request|3.4 KB|20.2 µs|10.0 µs|5.64 µs|3.59 µs|2.12 µs|4.71 µs|4.3x|0.45|
|embeddings|511.5 KB|7.87 ms|2.17 ms|729 µs|904 µs|559 µs|1.14 ms|6.9x|0.49|
|github|55.8 KB|158 µs|97.8 µs|45.7 µs|30.8 µs|18.8 µs|26.8 µs|5.9x|0.70|
|twitter|631.5 KB|1.47 ms|1.03 ms|726 µs|332 µs|195 µs|463 µs|3.2x|0.42|
|citm_catalog|1.7 MB|3.23 ms|1.99 ms|1.14 ms|570 µs|480 µs|929 µs|3.5x|0.52|
|canada|2.3 MB|38.7 ms|12.0 ms|4.22 ms|4.29 ms|2.84 ms|7.40 ms|5.2x|0.38|
|recipe_book|30.0 KB|86.1 µs|48.1 µs|22.5 µs|22.6 µs|12.1 µs|20.7 µs|4.2x|0.58|

What the numbers say:
- **loads** is 1.9 to 4.5 times as fast as json, and 0.66 to 0.97 of orjson's speed.
  - 0.1.3 builds the objects as the text is read ("How it is built"). That made loads 8 to 14% faster than 0.1.2: in alternating processes, 0.71 against 0.80 µs for chunk, 73 against 84 µs for github, 1.21 against 1.35 ms for twitter, 9.1 against 9.9 ms for canada. Callgrind counts 10 to 12% fewer instructions per load (canada: 122 million, from 135).
  - CPython's own objects (allocation, freeing, the garbage collector's passes) take about half of a load. json and orjson pay for those too.
  - Floats cost the most of what is left: canada and the embeddings are at 0.66 to 0.69 of orjson. `read_float` takes about 250 instructions a float, reading digits the scan has just checked.
- **dumps** is 3.2 to 6.9 times as fast as json, and 0.34 to 0.70 of orjson's speed. 0.1.3's streaming check (one comparison per item) costs about 1.5% of its instructions (github: 6,000 of 390,000).
  - It keeps json's exact output, and so its rules: every str is checked for what needs escaping, every key for its type, and the options are honoured. orjson has fewer options.
  - The floats in canada and the embeddings go through Ryū, and then `float.__repr__`'s layout: about 500 instructions a float.

**A 1 GB document** (BestBuy products, Zenodo record 7582191; `loads` from bytes, `dumps` with json's defaults; best of 2 on one core, each library in a process of its own):

| | loads | dumps | peak memory |
|---|---|---|---|
| json | 8.3 s | 4.2 s | 5.2 GB |
| orjson | 3.7 s | 0.76 s (compact bytes) | 5.8 GB |
| mojson 0.1.0 | 4.7 s | 3.0 s | 5.9 to 6.6 GB |
| mojson 0.1.2 | 4.7 s | 1.4 s | 5.6 GB |
| mojson 0.1.3 | 3.6 s | 1.5 s | 3.9 GB |

- 0.1.3's loads builds the objects with no document in between. The document held a 12-byte node per value and the text unescaped, 1.7 GB here, which also cost 600,000 page faults and 0.7 s in the kernel.
- The peak is now the input (1 GB) and the objects (2.8 GB). orjson's is 5.8 GB.
- `dump` to a file writes pieces of 64 KiB, so it adds no output to the peak; `fp.write(dumps(obj))` adds 2.1 GB (the str, and its encoding into the file).

All five parse it to the same objects, and mojson's text is json's, byte for byte.

**What made dumps faster in 0.1.2** (the BestBuy file: 700,000 dicts of about 160 keys, mostly null):
- **Memory, at 1 GB.** The output grew as a `List`, which a larger block and a copy replace each time, and the text was then copied once more into the str. That came to 1.2 million page faults and 1.2 s in the kernel per dumps.
  - The text now goes straight into the str (ensure_ascii) or bytes (dumpb) that is the result. It grows by `PyUnicode_Resize` or `_PyBytes_Resize`, which realloc: a large block's pages move, they are not copied.
  - The other output goes into raw memory (`PyMem_RawRealloc`).
  - Down to 250,000 page faults and 0.3 s.
- **Instructions**, on a 45 MB sample of it under callgrind: 871 million per dumps, down to 434 million.
  - **Keys.** A dict's keys repeat from dict to dict. `KeyBytes` keeps each exact str key's quoted text, by object, and the dict loop copies it in 32-byte blocks, with the separators and a null or bool value, into room reserved once.
  - **Separators** are one 8-byte store, not a byte loop.
  - **References.** None is held on a key, nor on a scalar value: writing those runs no Python code.
  - **Strings** are copied and scanned in one pass.

## Release
mojson's wheels go to **TestPyPI** only. They hold mojson's own files and nothing else of the repository: `mojson/__init__.py`, `mojson/_mojson.so` (about 400 KB), the metadata and the licence. `packaging/mojson` holds what PyPI needs: `pyproject.toml` (the metadata, the CPU targets) and `README.md` (the PyPI page, with the repository's warning).

- **Built** by `tools/build_mojson_wheel.py` (`pixi run -e release mojson-wheel`, then `twine check --strict`):
  - **One build per machine.** The extension links no libpython: it resolves the C API from the interpreter that loads it, so one build serves Python 3.12 to 3.15. It is packed into one wheel per version, tagged `cp312-cp312` to `cp315-cp315`, `manylinux_2_34`. A `none` ABI tag would also match the free-threaded build (`cp314t`), where loading the extension crashes: Mojo's module setup reads the GIL build's object layout before any check of mojson's can run. So pip refuses the wheels there, and `mojson/__init__.py` raises ImportError if it is imported by path.
  - **A portable CPU.** `mojo build` targets the build host's own CPU by default, which put AVX-512 into the extension on the machine this was written on. The wheels target x86-64-v3 and neoverse-n1. Modular's runtime libraries already need those: on x86_64 they use AVX2, BMI2 and FMA with no fallback, and on aarch64 LSE, RCpc and dot-product instructions. Against x86-64-v2, v3 was 0 to 12% faster per file (about 4% on average); the build host's own target was 5 to 15% faster still, which a wheel cannot use.
  - **The Mojo runtime is not in the wheel.** The extension links `libKGENCompilerRTShared.so`, which needs two more of Modular's libraries; all three are under Modular's licence. The wheel depends on `mojo-compiler==1.2.0` from PyPI (about 80 MB), whose wheel installs them in `site-packages/modular/lib`.
    - The extension's RUNPATH is `$ORIGIN/../modular/lib`, so it finds them when both packages share a site-packages.
    - Otherwise, `mojson/__init__.py` loads them from the `mojo-compiler` distribution, wherever it is installed.
    - The pin is the compiler that builds the extension, and the build checks it against `mojo --version`.
  - **Checked before packing:** the extension links only the Mojo runtime and glibc's libraries, needs no glibc symbol past 2.34, has that RUNPATH and no other, and exports `PyInit__mojson`. The package version must match `__version__`. Timestamps are fixed, so the same inputs give the same wheel.
- **Tested** by `tools/test_mojson_wheel.sh DIST PYTHON...`, per interpreter:
  - each wheel is installed by pip into a fresh virtualenv outside pixi, and `tests/mojson` runs against the installed package;
  - `/proc/self/maps` must show the runtime loaded from that virtualenv's `mojo-compiler`;
  - mojson alone in another directory (`pip --target`) must load it too;
  - on a free-threaded interpreter, pip must refuse every wheel, and an import by path must raise ImportError.

  Locally: x86_64, CPython 3.12, 3.13, 3.14, 3.15, and 3.15t (from uv).
- **Published** by `.github/workflows/mojson-wheels.yml`:
  - It builds on both machines, then tests each wheel on Python 3.12 to 3.15 and the free-threaded 3.14t and 3.15t on GitHub's runners. It does this on every change to mojson, `json` or the packaging.
  - On a manual run with `publish` ticked, it also uploads the tested wheels to TestPyPI by trusted publishing, so no token is stored.
  - Once, before the first upload, register a "pending publisher" on test.pypi.org (Account settings → Publishing). Its fields: project `mojson`, owner `advenn`, repository `mojo_net`, workflow `mojson-wheels.yml`, environment `testpypi`.
  - TestPyPI never takes a version twice, so raise `version` in `packaging/mojson/pyproject.toml` and `__version__` in `python/mojson/__init__.py` together before each upload.
- **Installed** in two steps: `pip install mojo-compiler==1.2.0` from PyPI, then `pip install -i https://test.pypi.org/simple/ --no-deps mojson`. Anyone can upload to TestPyPI under any free name. A one-line install with PyPI as a second index (`--extra-index-url`) would search TestPyPI for `mojo-compiler` too, and could pick up someone else's package of that name.
- **No sdist.** Building needs the Mojo toolchain this repository pins, and a user without a matching wheel (macOS, another Python) has no other way to build it.

## Milestones
- **Y1: the json module's API, with its fallbacks; rfc8259, max_depth, dumpb, extended.** Done.
- **Y2: wheels for TestPyPI**, holding only mojson's files ("Release"). Done: 0.1.0 published 2026-11-02; 0.1.1 adds Python 3.15.
- **Y5: loads without a document (0.1.3).** Done. Calls without hooks build the objects from `Document.scan`'s events (`json`'s J3), as the text is read: 8 to 14% faster, and 1.7 GB less at the peak for a 1 GB file ("Measured").
- **Y4: a streaming dump, and calls inside calls (0.1.3).** Done.
  - `dump` hands str pieces of about 64 KiB to `fp.write`, between items only: never while a key or value is being written, since `fp.write` may change the object being dumped, and the dict loop holds no reference on its keys and scalars. A piece never splits a UTF-8 sequence.
  - loads and dumps run Python code (hooks, `default`, `fp.write`), which may call them again. 0.1.0 to 0.1.2 crashed on a `loads` inside an `object_hook`: the inner call parsed into the document the outer one was walking. A call inside another now gets a `Document`, `DecState` and raw memory of its own, and no `KeyBytes`, whose texts may be in the other `ensure_ascii` mode (`Codec.busy`).
- **Y3: dumps 1.3 to 2.2 times faster (0.1.2)**: the output written into the result object, keys kept encoded, separators as words ("Measured"). Done. It also fixes 0.1.0's output for a `_Raw` text past ASCII, which went into an ASCII str as UTF-8 bytes.
- Ideas, not plans:
  - a lazy document for Python (fields read without building the whole tree, as simdjson's `Parser` does);
  - JSON Lines;
  - free-threaded CPython (refused: pip installs no wheel there, and an import by path raises ImportError, since its objects' headers differ);
  - macOS (mojo-compiler has macOS arm64 wheels; mojson is untested there).
