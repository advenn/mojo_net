# HTTP benchmarks

`load.mojo` is a small HTTP/1.1 load generator for servers that answer every request with the same response. It does not use the `http` package: it learns the response's size from one request and then counts bytes, so it measures the server rather than our own parser.

```bash
pixi run mojo run -I src examples/http/hello_server.mojo 127.0.0.1:8080 &
pixi run mojo run -I src bench/http/load.mojo 127.0.0.1:8080 50 5      # 50 connections, 5 s
pixi run mojo run -I src bench/http/load.mojo 127.0.0.1:8080 50 5 16   # 16 pipelined per connection
```

It prints requests per second and the median and 99th-percentile round trip. Server CPU per request (from `/proc/<pid>/stat` over the run) is the better number when the load generator, which is single-threaded too, is the bottleneck. docs/http.md (H6) has the measurements.
