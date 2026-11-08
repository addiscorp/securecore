#!/bin/sh
# Front-page p50 for layer 1, the securecore-fpm launcher (addiscorp/securecore#53, E6), on the
# test/ext-layer1.sh stack (run that first), with Classic Editor, Yoast SEO and Contact Form 7
# active. The extension is unloaded on both sides, so the only difference is the sandbox:
#   stock   layer1 disabled: securecore-fpm execs php-fpm as it is (the same process stock
#           php-fpm is, no sandbox)
#   layer1  examples/wordpress.json's layer1 (Landlock + seccomp on master and workers),
#           layers 2 and 3 disabled
# Alternating, php-fpm restarted for each run; each run is 20 warm-up + 100 measured sequential
# requests by oha on the stack's network. Prints each run and the median p50 of each side;
# writes .tmp/bench/layer1.json.
#   DOCKER_CONTEXT=colima bench/layer1.sh [rounds]     (default 7)
set -eu
cd "$(dirname "$0")/.."
rounds=${1:-7}
project=${SECURECORE_EXT_PROJECT:-securecore-layer1}
port=${SECURECORE_EXT_PORT:-8090}
OHA=ghcr.io/hatoo/oha@sha256:3ec3dbf549ea197793482d47a6324797411406bbf438c2fe8b91f244ec641a2f # oha 1.16.0
ini=/usr/local/etc/php/conf.d/securecore.ini
conf=/var/www/html/securecore.json
out=.tmp/bench
mkdir -p "$out"
compose() {
  SECURECORE_PORT=$port docker compose -f docker/compose.yml -f docker/compose.ext.yml \
    -f docker/compose.ext-layer1.yml -p "$project" "$@"
}
oha() { docker run --rm --network "${project}_default" "$OHA" --no-tui --output-format json -H "Host: 127.0.0.1:$port" "$@" http://web/; }
# layer1 enabled (true|false), layers 2 and 3 off.
cfg() {
  awk -v l1="$1" '/"layer1": \{/ { s = 1 } /"layer2": \{/ { s = 2 } /"layer3": \{/ { s = 3 }
    s && /"enabled": true/ { if (s == 1) sub(/true/, l1); else sub(/true/, "false"); s = 0 } { print }' \
    ext/examples/wordpress.json > "$out/layer1-$2.json"
}
cfg false stock
cfg true layer1
compose exec -T php sh -c "[ -f $ini.off ] || mv $ini $ini.off"

# side <stock|layer1> -> p50 ms
side() {
  compose cp "$out/layer1-$1.json" "php:$conf" >/dev/null 2>&1
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  compose restart php >/dev/null 2>&1
  i=0; until [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/")" = 200 ]; do
    i=$((i + 1)); [ "$i" -lt 60 ] || { echo "php did not come back" >&2; exit 1; }; sleep 1
  done
  want="layer 1 is off"; [ "$1" = layer1 ] && want="layer 1 on from"
  compose logs --no-log-prefix --since "$since" php 2>&1 | grep -q "securecore-fpm: $want" || { echo "launcher state is not $1" >&2; exit 1; }
  [ "$(compose exec -T php sh -c 'php -m | grep -cx securecore || true')" = 0 ] || { echo "the extension is loaded" >&2; exit 1; }
  oha -n 20 -c 1 >/dev/null
  oha -n 100 -c 1 > "$out/layer1-$1.run.json"
  ok=$(jq -r '.statusCodeDistribution["200"] // 0' "$out/layer1-$1.run.json")
  [ "$ok" = 100 ] || { echo "not all 100 responses were 200 ($1)" >&2; exit 1; }
  jq -r '.metrics.latency_ms.p50' "$out/layer1-$1.run.json"
}

median() { sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }
stock="" layer1=""
r=1
while [ "$r" -le "$rounds" ]; do
  a=$(side stock); b=$(side layer1)
  printf 'round %s: stock %.2f ms   layer1 %.2f ms\n' "$r" "$a" "$b"
  stock="$stock $a" layer1="$layer1 $b"
  r=$((r + 1))
done
# Leave the stack as test/ext-layer1.sh does: the extension loaded, wordpress.json.
compose exec -T php sh -c "[ -f $ini ] || mv $ini.off $ini"
compose cp ext/examples/wordpress.json "php:$conf" >/dev/null 2>&1
compose restart php >/dev/null 2>&1
ms=$(echo "$stock" | tr ' ' '\n' | grep . | median)
ml=$(echo "$layer1" | tr ' ' '\n' | grep . | median)
printf 'median p50: stock %.2f ms, layer1 %.2f ms, delta %+.2f ms\n' "$ms" "$ml" "$(echo "$ml - $ms" | bc -l)"
list() { echo "$1" | sed 's/^ //; s/ /,/g'; }
printf '{"rounds":%s,"stock":[%s],"layer1":[%s],"median_stock":%s,"median_layer1":%s}\n' \
  "$rounds" "$(list "$stock")" "$(list "$layer1")" "$ms" "$ml" > "$out/layer1.json"
