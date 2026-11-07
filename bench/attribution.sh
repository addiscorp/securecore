#!/bin/sh
# Front-page p50 for E2a attribution (addiscorp/securecore#53), on the test/ext-config.sh stack
# (compose project securecore-ext; run that first), with layer 2 in log mode. Three sides,
# alternating, `rounds` times, php-fpm restarted for each:
#   none  the extension not loaded
#   off   loaded, securecore.debug_attribution_log=off (the default: no observer, no hook)
#   on    loaded, securecore.debug_attribution_log=both (a log line per open per rule)
# Each run is 20 warm-up + 100 measured sequential requests by oha on the stack's network,
# straight to nginx. Prints each run and the median p50 of each side; writes
# .tmp/bench/attribution.json. Measures whatever plugins are active (stock WordPress unless
# research/attribution/measure.sh installed its three).
#   DOCKER_CONTEXT=colima bench/attribution.sh [rounds]     (default 3)
set -eu
cd "$(dirname "$0")/.."
rounds=${1:-3}
OHA=ghcr.io/hatoo/oha@sha256:3ec3dbf549ea197793482d47a6324797411406bbf438c2fe8b91f244ec641a2f # oha 1.16.0
ini=/usr/local/etc/php/conf.d/securecore.ini
debug=/usr/local/etc/php/conf.d/securecore-debug.ini
conf=/var/www/html/securecore.json
out=.tmp/bench
mkdir -p "$out"
compose() { SECURECORE_PORT=8089 docker compose -f docker/compose.yml -f docker/compose.ext.yml -p securecore-ext "$@"; }
oha() { docker run --rm --network securecore-ext_default "$OHA" --no-tui --output-format json -H 'Host: 127.0.0.1:8089' "$@" http://web/; }
loaded() { compose exec -T php sh -c 'php -m | grep -cx securecore || true'; }
logging() { compose exec -T php sh -c "php -r 'echo ini_get(\"securecore.debug_attribution_log\");' 2>/dev/null || true"; }

sed 's/"mode": "enforce"/"mode": "log"/' ext/examples/wordpress.json > "$out/log.json"
compose cp "$out/log.json" "php:$conf" >/dev/null 2>&1

# side <none|off|on> → p50 ms
side() {
  case $1 in
    none) compose exec -T php sh -c "rm -f $debug; [ -f $ini.off ] || mv $ini $ini.off" ;;
    off) compose exec -T php sh -c "rm -f $debug; [ -f $ini ] || mv $ini.off $ini" ;;
    on) compose exec -T php sh -c "[ -f $ini ] || mv $ini.off $ini; echo securecore.debug_attribution_log=both > $debug" ;;
  esac
  compose restart php >/dev/null 2>&1
  i=0; until [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8089/)" = 200 ]; do
    i=$((i + 1)); [ "$i" -lt 60 ] || { echo "php did not come back" >&2; exit 1; }; sleep 1
  done
  want_loaded=1 want_log=off
  [ "$1" = none ] && want_loaded=0 want_log=
  [ "$1" = on ] && want_log=both
  [ "$(loaded)" = "$want_loaded" ] || { echo "extension state is not $1" >&2; exit 1; }
  [ "$(logging)" = "$want_log" ] || { echo "attribution logging is not '$want_log' ($1)" >&2; exit 1; }
  oha -n 20 -c 1 >/dev/null
  oha -n 100 -c 1 > "$out/attribution-$1.json"
  ok=$(jq -r '.statusCodeDistribution["200"] // 0' "$out/attribution-$1.json")
  [ "$ok" = 100 ] || { echo "not all 100 responses were 200 ($1)" >&2; exit 1; }
  jq -r '.metrics.latency_ms.p50' "$out/attribution-$1.json"
}

median() { sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }
none="" off="" on=""
r=1
while [ "$r" -le "$rounds" ]; do
  a=$(side none); b=$(side off); c=$(side on)
  printf 'round %s: not loaded %.2f ms   logging off %.2f ms   logging on %.2f ms\n' "$r" "$a" "$b" "$c"
  none="$none $a" off="$off $b" on="$on $c"
  r=$((r + 1))
done
side off >/dev/null # leave it loaded, logging off
compose cp ext/examples/wordpress.json "php:$conf" >/dev/null 2>&1
compose restart php >/dev/null 2>&1
m() { echo "$1" | tr ' ' '\n' | grep . | median; }
mn=$(m "$none") mf=$(m "$off") mo=$(m "$on")
printf 'median p50: not loaded %.2f ms, logging off %.2f ms (%+.2f), logging on %.2f ms (%+.2f)\n' \
  "$mn" "$mf" "$(echo "$mf - $mn" | bc -l)" "$mo" "$(echo "$mo - $mn" | bc -l)"
list() { echo "$1" | sed 's/^ //; s/ /,/g'; }
printf '{"rounds":%s,"not_loaded":[%s],"logging_off":[%s],"logging_on":[%s],"median_not_loaded":%s,"median_logging_off":%s,"median_logging_on":%s}\n' \
  "$rounds" "$(list "$none")" "$(list "$off")" "$(list "$on")" "$mn" "$mf" "$mo" > "$out/attribution.json"
