# mojson: Python's json module, in Mojo

`mojson` is a Python package with the standard library json's API whose parsing and writing are done by the Mojo `json` package (`docs/json.md`). It lives in `python/mojson`: a Mojo extension module, `_mojson`, and a small Python layer over it.

**Status: done (Y1)**, tested against the standard library's json on CPython 3.14. Like the rest of the repository, it is not published and not meant for production use.

## Use
```bash
pixi run mojson-build                  # build/python/mojson: __init__.py and _mojson.so
PYTHONPATH=build/python python3 -c 'import mojson as json; print(json.dumps(json.loads("[1, 2.5]")))'
pixi run mojson-test                   # build, then tests/mojson against the standard library's json
pixi run -e pyjson bench-json-compare  # mojson beside json, orjson, ujson, msgspec, simdjson, ...
```

`import mojson as json` changes nothing but the speed:

- `loads`, `load`, `dumps` and `dump` take json's arguments (`cls`, the hooks, `strict`, `indent`, `separators`, `default`, `sort_keys`, ...) and give json's results, byte for byte.
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
  - A few layouts are read directly where a call would cost more than the work: an object's type, a str's header and characters, a list's item array. Each is checked at import against the C API, on objects built for the check, and used only where it agreed. These are CPython 3.12 to 3.14's layouts, with the GIL, on 64-bit platforms.
- **`ext/decode.mojo`** walks a parsed `json.Document` (`Document.visit`) and builds the objects:
  - an ASCII str with `PyUnicode_New` and a copy, any other through `PyUnicode_DecodeUTF8`;
  - lists filled in place, dicts presized;
  - ASCII keys of up to 64 bytes from a cache of 1,024 str objects shared by every call, each with its hash computed once, as json's per-call memo shares them.
- **`ext/encode.mojo`** writes into one reused buffer, reserving room once per string, and reads str characters in their own width (1, 2 or 4 bytes).
- **`_mojson.mojo`** holds one `Codec` per process: the C API, a reused `Document` and decoder, the key cache, and the text buffer. A call allocates only the objects it returns, and buffers past 1 MiB (a document) or 4 MiB (text) are not kept between calls.
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
`pixi run -e pyjson bench-json-compare`: each library's best of 7 samples of at least 0.1 s of thread CPU time, pinned to one core of an i5-1145G7 (Tiger Lake), CPython 3.14.

Every library got the same bytes, and its result was checked against json's.
- The run took four minutes, pinned to one core, under a load average of 7.6 to 9.0: the machine is shared, and other people's Go test suites were running.
- yyjson's `loads` (its Python binding, 4.x) differs from json's on the five files with text beyond ASCII. Given bytes, it decodes their strings as Latin-1: "Été" comes back as "Ã\x89tÃ©". Its times stand, but its results are wrong. The other libraries match json.
- simdjson's `loads` builds every object at once, as json does. Its lazy `Parser` is in `docs/json.md`, beside the Mojo parser.

**loads** (bytes in, Python objects out):

|file|size|json|ujson|simdjson|yyjson|msgspec|orjson|mojson|json / mojson|orjson / mojson|
|---|---|---|---|---|---|---|---|---|---|---|
|chunk|220 B|3.64 µs|1.34 µs|1.63 µs|1.07 µs|0.68 µs|0.78 µs|1.09 µs|3.3x|0.72|
|chat_completion|557 B|5.50 µs|2.45 µs|2.55 µs|1.88 µs|1.45 µs|1.75 µs|2.39 µs|2.3x|0.73|
|tools_request|3.4 KB|24.4 µs|17.1 µs|16.2 µs|14.4 µs|10.9 µs|12.5 µs|19.8 µs|1.2x|0.63|
|embeddings|511 KB|12.4 ms|5.23 ms|2.22 ms|1.61 ms|2.37 ms|1.96 ms|2.39 ms|5.2x|0.82|
|github|55.8 KB|212 µs|186 µs|268 µs|211 µs|191 µs|182 µs|206 µs|1.0x|0.89|
|twitter|632 KB|4.29 ms|2.38 ms|2.50 ms|1.99 ms|1.82 ms|1.49 ms|2.28 ms|1.9x|0.66|
|citm_catalog|1.7 MB|10.6 ms|5.95 ms|5.69 ms|5.00 ms|4.86 ms|3.96 ms|4.96 ms|2.1x|0.80|
|canada|2.3 MB|64.7 ms|19.5 ms|13.2 ms|10.0 ms|12.6 ms|11.3 ms|18.3 ms|3.5x|0.62|
|recipe_book|30.0 KB|169 µs|99.4 µs|72.8 µs|59.6 µs|70.3 µs|48.5 µs|70.7 µs|2.4x|0.69|

**dumps** (Python objects in, a str out; msgspec and orjson return bytes):

|file|size|json|ujson|yyjson|msgspec|orjson|mojson|json / mojson|orjson / mojson|
|---|---|---|---|---|---|---|---|---|---|
|chunk|220 B|3.15 µs|1.07 µs|1.05 µs|0.42 µs|0.28 µs|0.81 µs|3.9x|0.35|
|chat_completion|557 B|5.44 µs|2.22 µs|1.70 µs|0.70 µs|0.46 µs|1.48 µs|3.7x|0.31|
|tools_request|3.4 KB|68.2 µs|19.7 µs|11.2 µs|6.95 µs|4.30 µs|11.5 µs|5.9x|0.37|
|embeddings|511 KB|12.2 ms|3.11 ms|957 µs|1.27 ms|790 µs|1.62 ms|7.5x|0.49|
|github|55.8 KB|436 µs|140 µs|86.5 µs|48.9 µs|26.4 µs|60.2 µs|7.2x|0.44|
|twitter|632 KB|1.98 ms|1.49 ms|1.03 ms|407 µs|251 µs|984 µs|2.0x|0.26|
|citm_catalog|1.7 MB|7.41 ms|4.36 ms|1.99 ms|840 µs|742 µs|2.37 ms|3.1x|0.31|
|canada|2.3 MB|54.4 ms|17.0 ms|5.57 ms|6.49 ms|4.33 ms|9.53 ms|5.7x|0.45|
|recipe_book|30.0 KB|121 µs|67.4 µs|30.6 µs|32.9 µs|16.0 µs|39.8 µs|3.0x|0.40|

What the numbers say:
- **loads** is 1.0 to 5.2 times as fast as json, and 0.62 to 0.89 of orjson's speed.
  - The Mojo parse is under a third of a load: about 37,000 of a tools_request load's 158,000 instructions (callgrind).
  - CPython's own dicts and strs take most of the rest. json pays for those too. github is mostly strs and dicts, and there every library is within 1.3x of json, either way.
  - canada is 111,080 floats in nested lists. There mojson is 3.5x json, but orjson and yyjson are faster still.
- **dumps** is 2.0 to 7.5 times as fast as json, and 0.26 to 0.49 of orjson's speed.
  - It keeps json's exact output, and so its rules: every str is checked for what needs escaping, every key for its type, and the options are honoured. orjson has fewer options.
  - It writes UTF-8 into one buffer, then copies it into the result. For a str with `ensure_ascii=False`, that copy decodes the UTF-8.

## Milestones
- **Y1: the json module's API, with its fallbacks; rfc8259, max_depth, dumpb, extended.** Done.
- Ideas, not plans:
  - a lazy document for Python (fields read without building the whole tree, as simdjson's `Parser` does);
  - JSON Lines;
  - free-threaded CPython (the import refuses it: its objects' headers differ).
