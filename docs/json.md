# json: JSON in pure Mojo

A strict JSON (RFC 8259) parser and writer, in native Mojo, for the AI-facing parts of the stack: the bodies of LLM API requests and responses, streamed chunks, embeddings and tool schemas. It imports only `std`. Package rules are in `docs/design.md`.

**Status: J2 done.**

- J1: the parser (`json.parse`, `Document`), the writer (`Writer`) and shortest round-trip floats (`write_float`, Ryū).
- J2: a parser 2 to 3.7 times faster, `Dialect` (what Python's json reads besides), `Visitor`, and fast float reading (`read_float`, Eisel-Lemire).

Its first user outside Mojo is `mojson`, the Python json module's API on this package (`docs/mojson.md`).

## Scope
**In scope:**
- parsing one JSON text into a document that can be walked and read with typed accessors;
- writing JSON text call by call, with its structure checked;
- floats written as the shortest text that reads back as the same Float64, and read correctly rounded;
- limits on what the parser accepts (input size, nesting depth).

**Out of scope for now:**
- streaming (SAX-style) parsing of one document in pieces: an SSE event or an HTTP body is parsed once it is complete;
- binding documents to structs (no reflection in Mojo yet): callers read fields by name;
- JSON Schema validation, JSON Pointer and JSON Patch, JSON5 or comments, and lenient modes beyond `Dialect`, which is what Python's json reads.

## Decisions
- **Strict by default.** Every place RFC 8259 leaves to the implementation is decided toward refusal (`Dialect()`):
  - A byte order mark is refused, and so are comments, trailing commas, single quotes, NaN and Infinity.
  - Numbers must follow RFC 8259's grammar: no leading zeros, `+`, `.5` or `5.`.
  - Strings must be UTF-8 under RFC 3629's rules, with no overlong forms, no encoded surrogates and nothing past U+10FFFF. They may hold no control characters, and the only escapes allowed are JSON's.
  - Lone surrogate escapes (`"\ud800"`) are refused. UTF-8 cannot hold them, and passing them through is how readers end up with different texts.
- **Python's dialect, and nothing looser.** `Dialect.python()` accepts what Python's json module accepts beyond the strict grammar, for `mojson`, which must read exactly what json reads, and for text Python wrote:
  - repeated keys, all pairs kept in order;
  - `NaN`, `Infinity` and `-Infinity`, as numbers whose text is the word (`float()` reads them);
  - lone surrogates: escapes, and UTF-8's three-byte form, kept in the string as those bytes (WTF-8, not UTF-8);
  - with `control_characters` (Python's `strict=False`), raw control characters in strings.

  The switches are read only where a strict parse would fail, except the key check, which the parser is compiled with and without. So the strict parse pays nothing for them. Each is its own field; nothing else is loosened.
- **No key twice in one object** (the strict dialect). RFC 8259 says names SHOULD be unique and leaves duplicates' meaning open. When two parsers on a request's path disagree (the first value or the last), they disagree on what the request says, and that disagreement has been exploited ("An Exploration of JSON Interoperability Vulnerabilities", Bishop Fox, 2021). So a repeated key is an error, compared after unescaping (`"a"` and `"\u0061"` are the same key).
  - Each key gets a cheap 64-bit hash of its length and its first and last 8 bytes, which equal keys share.
  - Objects of up to 16 pairs compare every two hashes, and the keys' bytes (16 at a time) where the hashes are equal.
  - Larger objects put the keys into an open-addressing table of at least twice their number, probed linearly, compared only where the hashes are equal. Past 4,096 pairs the keys are first split into 256 buckets by the hash's top byte, so that each bucket's table stays in cache.
  - The cheap hash is public, so keys can be chosen to collide in it, and a flooded table would be quadratic. So a key that probes more than 16 slots ends the table. The object is then checked by sorting the (hash, key) values; a run of more than 8 keys with one cheap hash goes through SipHash-1-3, sorted (buckets by the top 16 bits from 16,384 pairs up), with bytes compared only between keys that share a SipHash.
  - The time is bounded by the keys' bytes, each compared with at most 16 others, plus, for colliding keys only, sorts of 16-byte values. SipHash's key is fixed and public too. That is safe because the sort does not depend on a secret: a group of k keys with one 64-bit SipHash costs whoever builds it about 2^(64(k-1)/k) evaluations, and each collision costs the parser only one comparison.
- **One flat tree.** A document is a list of 12-byte nodes in pre-order. Each node holds its kind and either a string's bytes in one shared buffer or an array's or object's member count and subtree size, so that the next sibling is one jump away, as in `redis.resp.Value`. A document of a million values is a few large allocations, and `Document.parse` reuses them.
  - **The buffer has room.** It holds the input's length plus 64 bytes, since strings unescaped and numbers' text never take more bytes than the input. So the parser stores whole 32-byte vectors without checking. And every span `Document.visit` hands out can be read `SPAN_SLACK` (32) bytes past its end, which lets a visitor load whole vectors and mask what lies past it. A copy of a document keeps the room.
  - **The pass** writes nodes and text through raw pointers into that room, growing the node list once per value at most. It keeps the innermost open array or object in locals (an open object's node holds where its keys start), raises nothing (one raise outside, so no error is built on paths that succeed), and scans strings and whitespace 32 bytes at a time and digits 8 at a time.
- **Walking a document:** `Document.visit[V: Visitor]` calls a visitor for each node in order (`begin_array(count)`, the elements, `end_array()`; `begin_object(count)`, then `key` and the value of each pair, `end_object()`), with its own stack, so any depth walks. mojson builds Python objects with one.
  - **Memory:** a document takes up to about 7 times its input, since a node can be 2 input bytes (`0,`). The size limit therefore bounds memory too, and its default is 64 MiB, so a parse takes at most about 450 MB. Raise it for large payloads, such as embeddings of big batches.
  - **Navigation:** `child(n, k)`, `key(n, i)` and `val(n, i)` walk to their member, so they cost O(k). To visit every member, step with `next()`, as the module docs show. A loop over `child(n, k)` would be quadratic.
- **Numbers keep their text.** A number is checked against the grammar while parsing and kept as written. `int()` reads it exactly or raises (RANGE outside Int's range; TYPE if it has a fraction or an exponent). Rendering a document writes numbers exactly as they came.
- **`float()` reads a number correctly rounded** with `read_float` (`json.number`), else with Mojo's `atof`, which a test of 30,050 hard cases found correct. A number past Float64's range raises rather than becoming an infinity, which JSON cannot hold; one too small reads as 0 or a subnormal, the correctly rounded value.
  - `read_float` reads up to 19 significant digits into one integer w, 8 digits at a time. Then it takes Clinger's fast path (w up to 2^53, a power of ten up to 22: one exact multiplication or division), or the Eisel-Lemire algorithm (Lemire, 2021, as fast_float computes it). Mushtak and Lemire proved (2023) that its 128-bit product always decides for such w, so it needs no fallback.
  - Its table of 128-bit powers of five for exponents -342 to 308 comes from Python's integers, generated and checked by `tools/gen_ryu_tables.py` beside Ryū's (`pixi run json-check`).
  - It leaves more digits and subnormals to `atof` (about 1 text in 6 of the test's mix, which leans on them; real payloads rarely have any).
- **Floats are written shortest.** Mojo's `String(Float64)` does not always round-trip (4 doubles in 20,000 in one measurement), so floats go through Ryū (Ulf Adams, PLDI 2018), ported from the reference implementation. It writes the fewest digits that read back as the same double, and the nearest of them, ties to even. Its tables of 128-bit powers of five are generated from Python's integers by `tools/gen_ryu_tables.py`, which checks each entry against its definition. CI checks that the committed tables are current (`pixi run json-check`).
- **The layout of a float is JSON.stringify's** (ECMAScript's Number::toString). Plain digits are used from 1e-6 up to 1e21 (`0.001`, `1.5`, `100`); outside that range the number is written with an exponent (`1e+21`, `1.5e-7`). There is one difference: negative zero is `-0`, so it reads back as -0.0, where JavaScript writes `0`.
- **The writer checks structure.** A key where a value is due, a value where a key is due, a second root value, a close that does not match an open, and a string that is not UTF-8 all raise USAGE and leave the text as it was. So does `take()` before the value is complete. NaN and the infinities are refused too. What `take()` returns is always one complete JSON value. `take()` hands over the buffer itself; to reuse one buffer, read `as_bytes()` and then `clear()`.
- **Errors** are `JsonError`, with a kind (SYNTAX, LIMIT, TYPE, MISSING, RANGE, USAGE) and, for parsing, the byte offset where the parser stopped. The parser reports the first error and leaves the document empty.

## Use
```mojo
from json import Writer, parse

var doc = parse(body)                                   # Span[UInt8] or a string
var choice = doc.child(doc.member(0, "choices"), 0)
var text = doc.text(doc.member(doc.member(choice, "message"), "content"))
var tokens = doc.int(doc.member(doc.member(0, "usage"), "total_tokens"))

var w = Writer()
w.begin_object()
w.key("model"); w.string("gpt-4o-mini")
w.key("temperature"); w.float(0.2)
w.end_object()
var request = w.take()                                  # List[UInt8]
```

## Testing
- **Oracles.** The tests use Python as the reference:
  - **Parsing:** `tests/json/json_oracle.py` uses Python's `json` module made as strict as ours. Hooks refuse repeated keys, NaN and Infinity, and the input is decoded as strict UTF-8 first. Strings with lone surrogates are refused, and numbers are kept as their text.
  - **Floats:** `tests/json/float_oracle.py` takes the digits from Python's `repr`, which uses David Gay's dtoa, a different algorithm from Ryū. It lays them out with an implementation of ECMAScript's Number::toString written from the spec, and checks that each text reads back.
- **Hand-written cases:** 128 inputs from RFC 8259's grammar, each labelled accepted or refused by hand, in the categories of Nicolas Seriot's JSONTestSuite: structure, literals, numbers, strings, UTF-8 and repeated keys. Python's strict json agrees with every label.
- **Differential fuzzing:** generated documents, 60% of them mutated: bytes changed, cut or repeated, and tokens planted (bad UTF-8, surrogate escapes, stray brackets, leading zeros, BOMs, NaN). Each must be accepted or refused as the oracle does, and an accepted one must render to the oracle's compact text byte for byte. Numbers must read as Python reads them: `float` to the same bits, `int` to the same value.
- **Floats:** 700,000 doubles, of random bits, short decimals, integers and subnormals, plus about 7,000 hard cases: Ryū's own regressions, powers of two and ten with their neighbours, and the layout's edges. Each is written, compared with the oracle and read back through `atof`.
- **Writer:** strings with every kind of character are escaped exactly as `json.dumps(ensure_ascii=False)` escapes them and read back by the strict oracle. Every misuse is tested, and random structures must read back, by our parser and by Python's, as exactly what was written.
- **Number reading:** `tests/json/test_number.mojo` reads 200,000 number texts from `number_oracle.py` and compares the bits with Python's float():
  - random digits;
  - random doubles written every way;
  - integers around 2^53 (the round to even);
  - short decimals over the whole exponent range;
  - the subnormal and overflow edges.

  The texts go through `read_float`, padded and not (with digits planted after the text), and through `Document.float` (the fallback too).
- **AddressSanitizer:** `pixi run json-asan` (in `ci`) builds every `tests/json` file with ASan.
  - The parser writes through raw pointers. Each List's length covers all it may write, and `_data` keeps `_SLACK` bytes in its length after its text, so ASan's container checks see any access past a length, even inside the capacity.
  - J2's first version wrote nodes past `_nodes`' length. Its results were right and no json test ran under ASan; `tls-asan` found it through `tests/llm`.
- **The key check's paths** in normal builds (`tests/json/test_json_keys.mojo`): every size from 2 to 20,000 pairs finds a repeat at its start, middle and end. Keys chosen to share the cheap hash (one length, the same first and last 8 bytes) overflow the table's probes and go through the sort and SipHash, at about 10 times an array's parse, where a pair-by-pair check of 200,000 keys would take minutes.
- **Colliding hashes:** fault-seam builds (`-D MOJO_NET_FAULTS=1`) keep 8 bits of each key's hash, so that `tests/json/test_json_keys_faults.mojo` drives the comparisons within one hash, and the buckets, against the oracle on objects of 17 to 20,000 pairs. `json.siphash` is checked against Python's own bytes hash, which is SipHash-1-3 under a zero key when PYTHONHASHSEED=0, and against the paper's SipHash-2-4 vectors.
- **Planted bugs:** 58, each undoing one check. Of these, 11 are in Ryū, 8 in the hash-based repeated-key check, and 39 elsewhere: the UTF-8 rules, the grammar, the first (merge sort) key check, the limits, the accessors, the renderer and the writer. The tests caught 49; the other 9 cannot change any output:
  - **Ryū (5):** most are bounds or ties that cannot occur where they are checked. For example, the `e2 ≥ 0` branch can never hit an exact tie, which would need fewer factors of two in the value than its exponent gives it. Another plant changes the bound only at 2^-1022, where the gap below equals the gap above.
  - **The merge sort, reversed:** it still put equal keys side by side.
  - **A bucket of two left unsorted:** its two hashes are adjacent either way.
  - **Grouping by 63 hash bits instead of 64:** it adds comparisons, never removes one.
  - **`Int.MIN`:** the explicit branch gives the same bits as the wrapping subtraction.
  - **Gaps found and closed:** three plants needed new tests. Two were first caught only through fuzzing, with no hand-written case: a lone low surrogate up to `\udfff`, and a literal compared on its first byte only. The third was missed outright: a 16-byte block comparison that never fails, which needed keys of one length, 16 bytes or more, differing inside a block. Hand cases now cover all three, and the colliding-hash objects cover the third.

## Review
An independent review of J1 (an agent, not a person) checked:
- every 2- and 3-byte UTF-8 sequence, and every 4-byte lead with 13 trailing-byte values, around the 16-byte scan boundary;
- all 65,536 `\uXXXX` escapes and every surrogate pairing;
- every input of up to 5 to 7 bytes over the grammar's symbols, against the oracle (2.9 million inputs);
- the bounds of every unchecked read;
- 20 million doubles through Ryū, after reading the port against `d2s.c` line by line.

It found no defect in those. It did find two problems:
- **A cost problem:** the repeated-key check was a merge sort of the keys by their bytes. One 259 MB object of 7 million keys under a shared 24-byte prefix took 17.5 s, about 29 times its parse, through cache misses. Hashing replaced it (above). `tests/json/test_json_regressions.mojo` bounds the time against the same strings in an array: 300,000 such keys now parse in about 31 ms, against 79 ms before.
- **Memory:** a document takes up to about 7 times its input, so the default size limit came down from 256 MiB to 64 MiB.

## Milestones
- **J2: speed, `Dialect`, `Visitor`, `read_float`.** Done.
  - **Measured** (`pixi run bench-json`; thread CPU time, best of 7 samples of at least 0.1 s, one core of an i5-1145G7 under the machine's usual load):

    | payload | size | J1 `parse` | J2 `parse` | J2 / J1 | J2 MB/s |
    |---|---|---|---|---|---|
    | a streamed chat chunk | 220 B | 0.94 µs | 0.36 µs | 2.6x | 610 |
    | a chat completion | 557 B | 1.78 µs | 0.61 µs | 2.9x | 910 |
    | a request with 8 tool schemas | 3.3 KB | 15.8 µs | 4.96 µs | 3.2x | 680 |
    | 16 embeddings of 1,536 floats | 511 KB | 1.15 ms | 0.42 ms | 2.7x | 1,210 |
    | github.json (orjson's corpus) | 56 KB | 139 µs | 42.5 µs | 3.3x | 1,310 |
    | twitter.json | 632 KB | 1.94 ms | 0.66 ms | 2.9x | 950 |
    | citm_catalog.json | 1.7 MB | 4.66 ms | 1.37 ms | 3.4x | 1,260 |
    | canada.json (floats) | 2.3 MB | 4.91 ms | 2.46 ms | 2.0x | 920 |
    | recipe_book.json | 30 KB | 105 µs | 28.5 µs | 3.7x | 1,050 |

    - J1 and J2 were built from the same benchmark and run alternately, twice each, the best of each kept, under a load average of 7 to 8 (the machine is shared). `write_json` did not change (within 7% either way).
    - After these runs, the key check for objects of up to 16 pairs lost its bounds checks and its array fill. That saves 2 to 11% of the instructions per parse, counted by callgrind: chunk 4,093 down to 3,754, tools_request 57,619 down to 54,736, github 477,873 down to 427,140, and twitter 2% fewer. The times above predate it.
    - **Against parsers in C++, in the same hour, under the same load** (`bench-json-compare`, through their Python bindings: a document built, no Python objects):
      - J2 is faster than simdjson's, cysimdjson's and yyjson's document parses on the float-heavy files, which they convert while parsing and `json` keeps as text: 1.7 to 1.9x on the embeddings, 1.6 to 1.7x on canada.
      - It is level on chunk (220 bytes), where their times include a Python call.
      - It is slower on the rest:

        | file | J2 takes, against them |
        |---|---|
        | citm | 1.04 to 1.4x |
        | chat_completion | 1.1 to 1.5x |
        | github | 1.4 to 2.1x |
        | recipe_book | 1.8 to 2.2x |
        | twitter | 2.1 to 2.8x |
        | tools_request | 2.3 to 2.6x |

      - Small, dense objects cost the most: tools_request (an OpenAI tool schema, 59 objects in 3.3 KB) takes 16 instructions a byte, github 8.
      - The gap left is simdjson's two stages (structural indexes found 64 bytes at a time first). The scan here is one pass, and about a quarter of its instructions are register spills.
    - Reading each of the embeddings' 24,576 floats with `float()` (the accessor's checks included) takes about 40 ns each with `read_float`, against 170 to 210 ns with `atof`, in the same runs.
- **J1: parser, writer, floats.** Done.
  - **Measured** (`pixi run bench-json`), on one core of an i5-1145G7, against Python 3.14's json and its C accelerator, on AI-shaped payloads:

    | payload | size | `parse` | Python `loads` | `write_json` | Python `dumps` |
    |---|---|---|---|---|---|
    | a streamed chat chunk | 220 B | 0.59 µs | 1.82 µs | 0.46 µs | 2.71 µs |
    | a chat completion | 557 B | 1.08 µs | 3.22 µs | 0.66 µs | 4.16 µs |
    | a request with 8 tool schemas | 3.3 KB | 9.4 µs | 16.7 µs | 4.6 µs | 22.7 µs |
    | 16 embeddings of 1,536 floats | 511 KB | 0.79 ms | 4.8 ms | 0.41 ms | 8.2 ms |

    - Parsing runs at 360 to 650 MB/s, 1.8 to 6 times Python's speed.
    - Reading an embedding value with `float()` takes 72 ns; writing one with `Writer.float` (shortest round-trip) takes 60 ns, against about 1.2 µs for Python's `repr`.
    - Specialised parsers such as simdjson are several times faster still. Parse speed is not where J1 put its effort.
