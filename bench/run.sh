#!/bin/sh
# Reproduce the SecureCore benchmarks against the running docker/ stack.
#   bench/run.sh breakdown   1 + 4a  per-step startup, call costs, RSS per sandbox (3 × 30 runs)
#   bench/run.sh load        2, 3, 4b  latency, throughput, stack peak memory (3 repeats)
#   bench/run.sh tabs        5  instantiate + boot in one process, memory restore (3 × 30 runs)
#   bench/run.sh all
# Needs: bun install, bun run wasm, bun run build, bun run build:bench, docker/setup.sh.
# Results: .tmp/bench/*.json. Exits non-zero if any step fails.
set -eu
cd "$(dirname "$0")/.."
what=${1:-all}
out=.tmp/bench
mkdir -p "$out"
compose() { docker compose -f docker/compose.yml "$@"; }

functions() {
  # Every function core has: the list SecureCore sends a sandbox at boot. Taken with the
  # sandboxed plugins inactive (wp-cli loads plugins normally), as core would have it.
  compose run --rm -T cli wp plugin deactivate hello securecore-probe securecore-bench >/dev/null 2>&1
  compose run --rm -T cli wp eval 'echo json_encode(get_defined_functions()["user"]);' > "$out/functions.json" 2>"$out/functions.err"
  compose cp "$out/functions.json" php:/var/www/html/wp-content/securecore-bench-functions.json >/dev/null 2>&1
  compose run --rm -T cli wp plugin activate hello securecore-probe securecore-bench >/dev/null 2>&1
}

breakdown() {
  for i in 1 2 3; do
    compose exec -T php php /usr/src/securecore/bench/breakdown.php 30 1000 > "$out/breakdown-$i.json" 2>"$out/breakdown-$i.err"
    echo "breakdown repeat $i ok"
  done
}

tabs() {
  for i in 1 2 3; do
    compose exec -T php securecore-tabs /var/www/html/wp-content/plugins/securecore-bench securecore-bench.php \
      /var/www/html/wp-content/securecore-bench-functions.json 30 > "$out/tabs-$i.json" 2>"$out/tabs-$i.err"
    echo "tabs repeat $i ok"
  done
}

load() {
  bun bench/load.ts 3 > "$out/load.md" 2>"$out/load.err"
  echo "load ok"
}

functions
case $what in
  breakdown) breakdown ;;
  tabs) tabs ;;
  load) load ;;
  all) breakdown; tabs; load ;;
  *) echo "usage: bench/run.sh breakdown|load|tabs|all" >&2; exit 2 ;;
esac
echo "results in $out/"
