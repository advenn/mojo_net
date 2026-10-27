# json: JSON in pure Mojo

A strict JSON (RFC 8259) parser and writer, in native Mojo, for the AI-facing parts of the stack: the bodies of LLM API requests and responses, streamed chunks, embeddings and tool schemas. It imports only `std`. Package rules are in `docs/design.md`.

**Status: J1 done:** the parser (`json.parse`, `Document`), the writer (`Writer`) and shortest round-trip floats (`write_float`, Ryū).

## Scope
**In scope:**
- parsing one JSON text into a document that can be walked and read with typed accessors;
- writing JSON text call by call, with its structure checked;
- floats written as the shortest text that reads back as the same Float64, and read correctly rounded;
- limits on what the parser accepts (input size, nesting depth).

**Out of scope for now:**
- streaming (SAX-style) parsing of one document in pieces: an SSE event or an HTTP body is parsed once it is complete;
- binding documents to structs (no reflection in Mojo yet): callers read fields by name;
- JSON Schema validation, JSON Pointer and JSON Patch, JSON5 or comments, and lenient modes of any kind.

## Decisions
- **Strict, with no lenient switch.** Every place RFC 8259 leaves to the implementation is decided toward refusal:
  - A byte order mark is refused, and so are comments, trailing commas, single quotes, NaN and Infinity.
  - Numbers must follow RFC 8259's grammar: no leading zeros, `+`, `.5` or `5.`.
  - Strings must be UTF-8 under RFC 3629's rules, with no overlong forms, no encoded surrogates and nothing past U+10FFFF. They may hold no control characters, and the only escapes allowed are JSON's.
  - Lone surrogate escapes (`"\ud800"`) are refused. UTF-8 cannot hold them, and passing them through is how readers end up with different texts.
- **No key twice in one object.** RFC 8259 says names SHOULD be unique and leaves duplicates' meaning open. When two parsers on a request's path disagree (the first value or the last), they disagree on what the request says, and that disagreement has been exploited ("An Exploration of JSON Interoperability Vulnerabilities", Bishop Fox, 2021). So a repeated key is an error, compared after unescaping (`"a"` and `"\u0061"` are the same key).
  - Objects of up to 16 pairs compare every two keys: lengths first, then 16 bytes at a time.
  - Larger objects hash each key once with SipHash-1-3, sort the (hash, key) values, and compare bytes only between keys that share a hash. The sort buckets by the top 16 bits first, from 16,384 pairs up. The time is bounded by the keys' bytes plus a sort of 16-byte values, whatever the keys are.
  - The hash key is fixed and public. That is safe here because the sort does not depend on a secret: a group of k keys with one 64-bit hash costs whoever builds it about 2^(64(k-1)/k) evaluations, and each collision costs the parser only one comparison. A hash table would need a secret key, since keys that share low bits flood it.
- **One flat tree.** A document is a list of 12-byte nodes in pre-order. Each node holds its kind and either a string's bytes in one shared buffer or an array's or object's member count and subtree size, so that the next sibling is one jump away, as in `redis.resp.Value`. A document of a million values is a few large allocations, and `Document.parse` reuses them.
  - **Memory:** a document takes up to about 7 times its input, since a node can be 2 input bytes (`0,`). The size limit therefore bounds memory too, and its default is 64 MiB, so a parse takes at most about 450 MB. Raise it for large payloads, such as embeddings of big batches.
  - **Navigation:** `child(n, k)`, `key(n, i)` and `val(n, i)` walk to their member, so they cost O(k). To visit every member, step with `next()`, as the module docs show. A loop over `child(n, k)` would be quadratic.
- **Numbers keep their text.** A number is checked against the grammar while parsing and kept as written. `int()` reads it exactly or raises (RANGE outside Int's range; TYPE if it has a fraction or an exponent). `float()` reads it correctly rounded, through Mojo's `atof`, which a test of 30,050 hard cases found correct. A number past Float64's range raises rather than becoming an infinity, which JSON cannot hold; one too small reads as 0 or a subnormal, the correctly rounded value. Rendering a document writes numbers exactly as they came.
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
