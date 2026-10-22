#!/usr/bin/env bash
# Build the M2 benchmark binaries into bench/out/ and run a step.
#   pixi run bash bench/run.sh build            # everything below
#   pixi run bash bench/run.sh gate [--reps 3]  # echo gate: rt vs tokio vs spike
#   pixi run bash bench/run.sh one --server rt --size 64
#   pixi run bash bench/run.sh http [--reps 3]  # HTTP hello: Mojo vs Rust (wrk)
set -euo pipefail
cd "$(dirname "$0")/.."
o=bench/out
mkdir -p "$o"
inc=(-I src -I bench -I spikes/epoll_echo)

build() {
  mojo build "${inc[@]}" bench/rt_echo_server.mojo -o "$o/rt_echo_server"
  mojo build "${inc[@]}" -D BENCH_STOCK_LOOP=1 bench/rt_echo_server.mojo -o "$o/rt_echo_server_stock"
  mojo build "${inc[@]}" bench/rt_raw_echo_server.mojo -o "$o/rt_raw_echo_server"
  mojo build "${inc[@]}" bench/http_hello.mojo -o "$o/http_hello"
  mojo build "${inc[@]}" bench/rt_microbench.mojo -o "$o/rt_microbench"
  # (The "rt-opt" variants are gone: the slab and out-of-line address
  # changes they measured are now in src/rt itself.)
  # The M1 spike's server and load generator, rebuilt with today's tree.
  mojo build -I src -I spikes/epoll_echo spikes/epoll_echo/server.mojo -o "$o/spike_server"
  mojo build -I src -I spikes/epoll_echo spikes/epoll_echo/client.mojo -o "$o/client"
  if command -v cargo >/dev/null; then
    CARGO_TARGET_DIR="$o/tokio-target" cargo build -q --release --offline \
      --manifest-path spikes/epoll_echo/tokio_echo/Cargo.toml
    CARGO_TARGET_DIR="$o/tokio-target" cargo build -q --release --offline \
      --manifest-path bench/rust_http/Cargo.toml
  fi
  echo "built: $(mojo --version) / $(rustc --version 2>/dev/null || echo no rustc) / $(uname -srm)"
}

cmd="${1:-build}"
[[ $# -gt 0 ]] && shift
case "$cmd" in
  build) build ;;
  gate) python3 bench/bench.py gate "$@" ;;
  one) python3 bench/bench.py one "$@" ;;
  http) python3 bench/http_bench.py "$@" ;;
  *) echo "unknown step: $cmd" >&2; exit 2 ;;
esac
