#!/bin/sh
# Reproduce the SecureCore benchmarks against the running docker/ stack.
#   bench/run.sh breakdown [engines]   1 + 4a  one tab per engine: per-request cost, call costs, tab RSS (3 × 30 requests)
#   bench/run.sh load [engines]        2, 3, 4b  latency, throughput, stack peak memory (3 repeats)
#   bench/run.sh all [engines]
# engines: comma-separated, p8 (default), php-wasm, native (native is NOT a sandbox: a lower bound).
# Needs: bun install, bun run wasm, bun run build, docker/setup.sh.
# Results: .tmp/bench/. Exits non-zero if any step fails.
set -eu
cd "$(dirname "$0")/.."
what=${1:-all}
engines=${2:-p8}
out=.tmp/bench
mkdir -p "$out"
compose() { docker compose -f docker/compose.yml "$@"; }

breakdown() {
  for engine in $(echo "$engines" | tr ',' ' '); do
    for i in 1 2 3; do
      compose exec -T php php /usr/src/securecore/bench/breakdown.php 30 1000 "$engine" > "$out/breakdown-$engine-$i.json" 2>"$out/breakdown-$engine-$i.err"
      echo "breakdown $engine repeat $i ok"
    done
  done
}

load() {
  bun bench/load.ts 3 "$engines" > "$out/load.md" 2>"$out/load.err"
  echo "load ok"
}

case $what in
  breakdown) breakdown ;;
  load) load ;;
  all) breakdown; load ;;
  *) echo "usage: bench/run.sh breakdown|load|all [engines]" >&2; exit 2 ;;
esac
echo "results in $out/"
