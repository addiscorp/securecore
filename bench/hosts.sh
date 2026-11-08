#!/bin/sh
# Front-page p50 and per-connection cost for the E5 hostname allowlist (addiscorp/securecore#53),
# on an extension stack with Classic Editor, Yoast SEO and Contact Form 7 active. Two sides,
# alternating, php-fpm restarted for each:
#   none     the extension not loaded (the baseline)
#   enforce  loaded, layer 2 in enforce with the hosts allowlist live
# A front-page request makes close to no outbound calls, so the front-page delta is near zero; the
# per-connection cost is measured separately on a wp_remote_get loop to an allowed, reachable host
# (the stack's own web container), loaded vs not.
#
# Each front-page run is 20 warm-up + 100 measured sequential requests by oha. Prints each round
# and the medians; writes .tmp/bench/hosts.json.
#   DOCKER_CONTEXT=colima bench/hosts.sh [rounds]     (default 7)
#   SECURECORE_EXT_PROJECT / SECURECORE_EXT_PORT pick the stack (default securecore-ext / 8089).
set -eu
cd "$(dirname "$0")/.."
rounds=${1:-7}
project=${SECURECORE_EXT_PROJECT:-securecore-ext}
port=${SECURECORE_EXT_PORT:-8089}
OHA=ghcr.io/hatoo/oha@sha256:3ec3dbf549ea197793482d47a6324797411406bbf438c2fe8b91f244ec641a2f # oha 1.16.0
ini=/usr/local/etc/php/conf.d/securecore.ini
conf=/var/www/html/securecore.json
out=.tmp/bench
mkdir -p "$out"
compose() { SECURECORE_PORT=$port docker compose -f docker/compose.yml -f docker/compose.ext.yml -p "$project" "$@"; }
wp() { compose run --rm -T cli wp "$@" 2>/dev/null | tr -d '\r'; }
net=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$(compose ps -q php)" | awk '{print $1}')
oha() { docker run --rm --network "$net" "$OHA" --no-tui --output-format json -H "Host: 127.0.0.1:$port" "$@" http://web/; }
loaded() { compose exec -T php sh -c 'php -m | grep -cx securecore || true'; }

wp plugin install classic-editor wordpress-seo contact-form-7 --activate >/dev/null || { echo "plugin install failed" >&2; exit 1; }
# A bench config with the hosts layer live. core.hosts allows the stack's own web container so the
# per-connection loop actually connects (and so the front page's own-site calls, if any, pass).
cat > "$out/hosts.json" <<JSON
{
  "layer1": { "enabled": false },
  "layer2": {
    "enabled": true, "app": "wordpress", "mode": "enforce",
    "core": { "hosts": ["web", "api.wordpress.org", "downloads.wordpress.org"] },
    "default": { "hosts": [] },
    "components": {}
  },
  "layer3": { "enabled": false }
}
JSON
compose cp "$out/hosts.json" "php:$conf" >/dev/null 2>&1

restart_wait() {
  compose restart php >/dev/null 2>&1
  i=0; until [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/")" = 200 ]; do
    i=$((i + 1)); [ "$i" -lt 60 ] || { echo "php did not come back" >&2; exit 1; }; sleep 1
  done
}
set_side() {
  if [ "$1" = enforce ]; then compose exec -T php sh -c "[ -f $ini ] || mv $ini.off $ini"
  else compose exec -T php sh -c "[ -f $ini.off ] || mv $ini $ini.off"; fi
  restart_wait
  [ "$(loaded)" = "$([ "$1" = enforce ] && echo 1 || echo 0)" ] || { echo "extension state is not $1" >&2; exit 1; }
}

# front-page p50 for the current side
front() {
  oha -n 20 -c 1 >/dev/null
  oha -n 100 -c 1 > "$out/hosts-$1.json"
  ok=$(jq -r '.statusCodeDistribution["200"] // 0' "$out/hosts-$1.json")
  [ "$ok" = 100 ] || { echo "not all 100 responses were 200 ($1)" >&2; exit 1; }
  jq -r '.metrics.latency_ms.p50' "$out/hosts-$1.json"
}

# per-connection cost: N wp_remote_get to the allowed web host, total ms / N, for the current side.
N_CONN=200
perconn() {
  wp eval "\$n=$N_CONN; \$t=microtime(true); for(\$i=0;\$i<\$n;\$i++){ wp_remote_get('http://web/', ['timeout'=>5]); } printf('%.4f', (microtime(true)-\$t)*1000/\$n);"
}

median() { sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }
none="" enforce="" pc_none="" pc_enf=""
r=1
while [ "$r" -le "$rounds" ]; do
  set_side none;    a=$(front none);    pa=$(perconn)
  set_side enforce; b=$(front enforce); pb=$(perconn)
  printf 'round %s: front not loaded %.2f ms   enforce %.2f ms   | per-conn not loaded %.3f ms   enforce %.3f ms\n' "$r" "$a" "$b" "$pa" "$pb"
  none="$none $a" enforce="$enforce $b" pc_none="$pc_none $pa" pc_enf="$pc_enf $pb"
  r=$((r + 1))
done
set_side enforce
mn=$(echo "$none" | tr ' ' '\n' | grep . | median)
me=$(echo "$enforce" | tr ' ' '\n' | grep . | median)
pn=$(echo "$pc_none" | tr ' ' '\n' | grep . | median)
pe=$(echo "$pc_enf" | tr ' ' '\n' | grep . | median)
printf 'median front p50: not loaded %.2f ms, enforce %.2f ms, delta %+.2f ms\n' "$mn" "$me" "$(echo "$me - $mn" | bc -l)"
printf 'median per-connection: not loaded %.3f ms, enforce %.3f ms, delta %+.3f ms (over %s calls/round)\n' "$pn" "$pe" "$(echo "$pe - $pn" | bc -l)" "$N_CONN"
list() { echo "$1" | sed 's/^ //; s/ /,/g'; }
printf '{"rounds":%s,"front_not_loaded":[%s],"front_enforce":[%s],"perconn_not_loaded":[%s],"perconn_enforce":[%s],"median_front_not_loaded":%s,"median_front_enforce":%s,"median_perconn_not_loaded":%s,"median_perconn_enforce":%s}\n' \
  "$rounds" "$(list "$none")" "$(list "$enforce")" "$(list "$pc_none")" "$(list "$pc_enf")" "$mn" "$me" "$pn" "$pe" > "$out/hosts.json"
