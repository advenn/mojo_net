#!/usr/bin/env bash
# Build the epoll echo spike into spikes/epoll_echo/out/ (Mojo server and
# client, C baseline, syscall microbenchmark, and the tokio baseline when
# cargo can build it offline), then run the requested step.
#   pixi run bash spikes/epoll_echo/run.sh             # build, checks, matrix, costs
#   pixi run bash spikes/epoll_echo/run.sh build       # build only
#   pixi run bash spikes/epoll_echo/run.sh check       # correctness + EMFILE checks
#   pixi run bash spikes/epoll_echo/run.sh matrix --reps 3 --servers mojo,c,tokio
#   pixi run bash spikes/epoll_echo/run.sh one --server c --size 1024 --clients 3
#   pixi run bash spikes/epoll_echo/run.sh cost        # syscall + fd-table costs
#   pixi run bash spikes/epoll_echo/run.sh burst       # accept-burst stalls
set -euo pipefail
cd "$(dirname "$0")/../.."
d=spikes/epoll_echo
mkdir -p "$d/out"
for p in server client syscall_cost; do
  mojo build -I src -I "$d" "$d/$p.mojo" -o "$d/out/$p"
done
gcc -O2 -Wall -Wextra -o "$d/out/baseline" "$d/baseline.c"
gcc -O2 -Wall -Wextra -pthread -o "$d/out/fdtable_grow" "$d/fdtable_grow.c"
if command -v cargo >/dev/null; then
  CARGO_TARGET_DIR="$d/out/tokio-target" cargo build -q --release --offline \
    --manifest-path "$d/tokio_echo/Cargo.toml" || echo "tokio baseline not built (needs cached crates)"
fi
echo "built: $(mojo --version) / $(gcc --version | head -1) / $(uname -srm)"
cmd="${1:-all}"
[[ $# -gt 0 ]] && shift
check() { python3 "$d/check_echo.py" && python3 "$d/bench.py" emfile; }
cost() {
  taskset -c 2 "$d/out/syscall_cost"
  "$d/out/fdtable_grow"
  "$d/out/fdtable_grow" threads
}
case "$cmd" in
  build) ;;
  check) check ;;
  cost) cost ;;
  all) check && python3 "$d/bench.py" matrix "$@" && python3 "$d/bench.py" burst && cost ;;
  *) python3 "$d/bench.py" "$cmd" "$@" ;;
esac
