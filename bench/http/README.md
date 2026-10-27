# HTTP benchmarks

`load.mojo` is a small HTTP/1.1 load generator for servers that answer every request with the same response. It does not use the `http` package: it learns the response's size from one request and then counts bytes, so it measures the server rather than our own parser.

```bash
pixi run mojo run -I src examples/http/hello_server.mojo 127.0.0.1:8080 &
pixi run mojo run -I src bench/http/load.mojo 127.0.0.1:8080 50 5      # 50 connections, 5 s
pixi run mojo run -I src bench/http/load.mojo 127.0.0.1:8080 50 5 16   # 16 pipelined per connection
```

It prints requests per second and the median and 99th-percentile round trip. Server CPU per request (from `/proc/<pid>/stat` over the run) is the better number when the load generator, which is single-threaded too, is the bottleneck. docs/http.md (H6) has the measurements.

## The codecs alone

`codec.mojo` measures the codecs alone, in one process: per request, what `ServerConnection` does to parse a request and frame a 13-byte response, and what `ClientConnection` does for a request and its response, for a few request shapes (wrk's two-line GET, a browser's GET with 14 fields, a small POST, 16 pipelined). It prints the best of several rounds in ns per request. Each request also builds its response head (or the client its request head) the way an application would, a fresh one with its header arena: about 1,400 of the instructions below are that, not the codec.

```bash
pixi run mojo build -I src bench/http/codec.mojo -o build/bench_codec && build/bench_codec 7
# instructions per request, which a loaded machine does not change:
pixi run mojo build -I src --target-cpu x86-64-v3 --debug-level line-tables bench/http/codec.mojo -o build/bench_codec_prof
pixi run -e bench valgrind --tool=callgrind --callgrind-out-file=build/cg.wrk build/bench_codec_prof 1 wrk
pixi run -e bench python3 bench/server/profile.py --analyze build/cg.wrk --requests 200000
```

### The third review's cost work (HR3, 2026-10-27)

Instructions per request under callgrind (x86-64-v3), before and after:

| Shape | Before | After | |
|---|---|---|---|
| server, wrk's GET | 8,277 | 4,821 | −42% |
| server, a browser's GET (14 fields) | 13,897 | 9,435 | −32% |
| client, a GET and a 7-field response | 12,910 | 7,575 | −41% |

What it took, by size:
1. **`IoError` passed in memory** (`linux.error`): about 1,000 per server request, 1,550 per client one. As `TrivialRegisterPassable` its `op` pointer sat in the typed-raise result in registers, and Mojo 1.2 split it into bytes: a raising function built its error even on success, without a branch (a mask of the sign of the test, then 16 byte stores), and its caller put the bytes back together (16 `vpinsrb`), about 85 instructions per call that did not raise. Passed in memory, a success is one flag test. A function with an untyped `raises` never had the cost. Every library that raises `IoError` gains.
2. **Head encoders in one pass:** one capacity test, raw stores, one commit, for `RequestHead`, `ResponseHead` and the server's response head (they wrote byte by byte, each write tested and raising): about 500 per client request.
3. **Bounds checks the loop bounds already prove:** header records, the parser's line ends, the host check.
4. **Comparisons:** `eq_ignore_case` folds only where the bytes differ by the case bit; `_summarize` compares names and values with lowercase literals by OR-ing 0x20, exact for field bytes; the host check is a bitmap, in a tight loop.
5. **No new Strings for a reused head's method and target** when the bytes are the same: about 300 per server request.
6. **`ByteBuffer`**: unsigned compares, so each check is one branch; `write_bytes` inlined.

Tried and dropped, as no faster once `IoError` moved to memory: raising from out-of-line helpers, and status codes in place of raises in `ByteBuffer`. Each rewritten predicate is checked against its old definition in `tests/http/test_http_review3_regressions.mojo`.

Nanoseconds before the work (this machine, x86_64): server wrk 680, browser 1,105, post 901, pipelined 651; client 1,039.
