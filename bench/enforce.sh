#!/bin/sh
# Front-page p50 for E2b enforcement (addiscorp/securecore#53), on the test/ext-config.sh stack
# (project securecore-ext; run that first), with Classic Editor, Yoast SEO and Contact Form 7
# active. Two sides, alternating, php-fpm restarted for each:
#   none     the extension not loaded (the #55 baseline conditions: ~45.2 ms)
#   enforce  loaded, examples/wordpress.json in enforce mode (file + process policy live)
# Each run is 20 warm-up + 100 measured sequential requests by oha on the stack's network.
# Prints each run and the median p50 of each side; writes .tmp/bench/enforce.json. The target is
# under 2 ms added by enforcement.
#   DOCKER_CONTEXT=colima bench/enforce.sh [rounds]     (default 3)
set -eu
cd "$(dirname "$0")/.."
rounds=${1:-3}
OHA=ghcr.io/hatoo/oha@sha256:3ec3dbf549ea197793482d47a6324797411406bbf438c2fe8b91f244ec641a2f # oha 1.16.0
ini=/usr/local/etc/php/conf.d/securecore.ini
conf=/var/www/html/securecore.json
out=.tmp/bench
mkdir -p "$out"
compose() { SECURECORE_PORT=8089 docker compose -f docker/compose.yml -f docker/compose.ext.yml -p securecore-ext "$@"; }
wp() { compose run --rm -T cli wp "$@" 2>/dev/null | tr -d '\r'; }
oha() { docker run --rm --network securecore-ext_default "$OHA" --no-tui --output-format json -H 'Host: 127.0.0.1:8089' "$@" http://web/; }
loaded() { compose exec -T php sh -c 'php -m | grep -cx securecore || true'; }

wp plugin install classic-editor wordpress-seo contact-form-7 --activate >/dev/null || { echo "plugin install failed" >&2; exit 1; }
compose cp ext/examples/wordpress.json "php:$conf" >/dev/null 2>&1

# side <none|enforce> -> p50 ms
side() {
  if [ "$1" = enforce ]; then
    compose exec -T php sh -c "[ -f $ini ] || mv $ini.off $ini"
  else
    compose exec -T php sh -c "[ -f $ini.off ] || mv $ini $ini.off"
  fi
  compose restart php >/dev/null 2>&1
  i=0; until [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8089/)" = 200 ]; do
    i=$((i + 1)); [ "$i" -lt 60 ] || { echo "php did not come back" >&2; exit 1; }; sleep 1
  done
  [ "$(loaded)" = "$([ "$1" = enforce ] && echo 1 || echo 0)" ] || { echo "extension state is not $1" >&2; exit 1; }
  oha -n 20 -c 1 >/dev/null
  oha -n 100 -c 1 > "$out/enforce-$1.json"
  ok=$(jq -r '.statusCodeDistribution["200"] // 0' "$out/enforce-$1.json")
  [ "$ok" = 100 ] || { echo "not all 100 responses were 200 ($1)" >&2; exit 1; }
  jq -r '.metrics.latency_ms.p50' "$out/enforce-$1.json"
}

median() { sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }
none="" enforce=""
r=1
while [ "$r" -le "$rounds" ]; do
  a=$(side none); b=$(side enforce)
  printf 'round %s: not loaded %.2f ms   enforce %.2f ms\n' "$r" "$a" "$b"
  none="$none $a" enforce="$enforce $b"
  r=$((r + 1))
done
side enforce >/dev/null # leave it loaded, enforcing
mn=$(echo "$none" | tr ' ' '\n' | grep . | median)
me=$(echo "$enforce" | tr ' ' '\n' | grep . | median)
printf 'median p50: not loaded %.2f ms, enforce %.2f ms, delta %+.2f ms\n' "$mn" "$me" "$(echo "$me - $mn" | bc -l)"
list() { echo "$1" | sed 's/^ //; s/ /,/g'; }
printf '{"rounds":%s,"not_loaded":[%s],"enforce":[%s],"median_not_loaded":%s,"median_enforce":%s}\n' \
  "$rounds" "$(list "$none")" "$(list "$enforce")" "$mn" "$me" > "$out/enforce.json"
