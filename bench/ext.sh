#!/bin/sh
# Front-page p50 with the SecureCore extension loaded vs not (addiscorp/securecore#53, E1), on
# the test/ext-config.sh stack (compose project securecore-ext; run that first). php-fpm is
# restarted with and without docker/securecore.ini, alternating, `rounds` times; each run is
# 20 warm-up + 100 measured sequential requests by oha on the stack's network, straight to
# nginx. Prints each run and the median p50 of each side; writes .tmp/bench/ext.json.
#   DOCKER_CONTEXT=colima bench/ext.sh [rounds]     (default 3)
set -eu
cd "$(dirname "$0")/.."
rounds=${1:-3}
OHA=ghcr.io/hatoo/oha@sha256:3ec3dbf549ea197793482d47a6324797411406bbf438c2fe8b91f244ec641a2f # oha 1.16.0
ini=/usr/local/etc/php/conf.d/securecore.ini
out=.tmp/bench
mkdir -p "$out"
compose() { SECURECORE_PORT=8089 docker compose -f docker/compose.yml -f docker/compose.ext.yml -p securecore-ext "$@"; }
oha() { docker run --rm --network securecore-ext_default "$OHA" --no-tui --output-format json -H 'Host: 127.0.0.1:8089' "$@" http://web/; }
loaded() { compose exec -T php sh -c 'php -m | grep -cx securecore || true'; }

# side <on|off>: php-fpm with or without the extension, then one measured run → p50 ms
side() {
  if [ "$1" = on ]; then
    compose exec -T php sh -c "[ -f $ini ] || mv $ini.off $ini"
  else
    compose exec -T php sh -c "[ -f $ini.off ] || mv $ini $ini.off"
  fi
  compose restart php >/dev/null 2>&1
  i=0; until [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8089/)" = 200 ]; do
    i=$((i + 1)); [ "$i" -lt 60 ] || { echo "php did not come back" >&2; exit 1; }; sleep 1
  done
  [ "$(loaded)" = "$([ "$1" = on ] && echo 1 || echo 0)" ] || { echo "extension state is not $1" >&2; exit 1; }
  oha -n 20 -c 1 >/dev/null
  oha -n 100 -c 1 > "$out/ext-$1.json"
  ok=$(jq -r '.statusCodeDistribution["200"] // 0' "$out/ext-$1.json")
  [ "$ok" = 100 ] || { echo "not all 100 responses were 200 ($1)" >&2; exit 1; }
  jq -r '.metrics.latency_ms.p50' "$out/ext-$1.json"
}

median() { sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }
on="" off=""
r=1
while [ "$r" -le "$rounds" ]; do
  a=$(side on); b=$(side off)
  printf 'round %s: loaded %.2f ms   not loaded %.2f ms\n' "$r" "$a" "$b"
  on="$on $a" off="$off $b"
  r=$((r + 1))
done
side on >/dev/null   # leave the extension loaded
mon=$(echo "$on" | tr ' ' '\n' | grep . | median)
moff=$(echo "$off" | tr ' ' '\n' | grep . | median)
printf 'median p50: loaded %.2f ms, not loaded %.2f ms, delta %+.2f ms\n' "$mon" "$moff" "$(echo "$mon - $moff" | bc -l)"
printf '{"rounds":%s,"loaded_p50_ms":[%s],"not_loaded_p50_ms":[%s],"median_loaded":%s,"median_not_loaded":%s}\n' \
  "$rounds" "$(echo "$on" | sed 's/^ //; s/ /,/g')" "$(echo "$off" | sed 's/^ //; s/ /,/g')" "$mon" "$moff" > "$out/ext.json"
