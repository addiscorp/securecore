#!/bin/sh
# What layer 3 costs (addiscorp/securecore#53, E7): time to first byte of a post whose content
# goes through the probe plugin's the_content filter and one of its shortcodes
# (test/ext/layer3-plugin), with the probe isolated vs the same probe loaded in the worker. On the
# test/ext-config.sh stack (run that first). Layer 2 enforce and layer 3 enabled on both sides;
# only `layer3.isolate` differs, switched live (layers 2 and 3 reload without a restart), so the
# helper and php-fpm stay up and the sides alternate round by round:
#   plain     isolate []              the probe runs in the php-fpm worker
#   isolated  isolate ["sc-l3probe"]  the probe runs in a child of the helper (fork per request)
# Each side per round: 40 warm-up (every php-fpm worker reloads the config and warms up) + N measured sequential requests (curl's time_starttransfer).
# Prints each round's median per side, then the median of the round medians and their range.
#   DOCKER_CONTEXT=colima bench/layer3.sh [rounds] [requests]     (default 7 rounds, 50 requests)
set -eu
cd "$(dirname "$0")/.."
rounds=${1:-7}
n=${2:-50}
project=${SECURECORE_EXT_PROJECT:-securecore-ext}
port=${SECURECORE_EXT_PORT:-8089}
base=http://127.0.0.1:$port
conf=/var/www/html/securecore.json
probe=/var/www/html/wp-content/plugins/sc-l3probe
out=.tmp/bench
mkdir -p "$out"
compose() { SECURECORE_PORT=$port docker compose -f docker/compose.yml -f docker/compose.ext.yml -p "$project" "$@"; }
wp() { compose run --rm -T cli wp "$@" 2>/dev/null | tr -d '\r'; }
put_live() { compose exec -T php sh -c "cat > $conf.new && mv $conf.new $conf" < "$1"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$base$1"; }

compose exec -T php sh -c "rm -rf $probe && mkdir -p $probe"
compose cp test/ext/layer3-plugin/sc-l3probe.php "php:$probe/sc-l3probe.php" >/dev/null 2>&1
compose exec -T php sh -c "chown -R www-data:www-data $probe"
wp plugin activate sc-l3probe >/dev/null
post=$(wp post create --post_status=publish --post_title="L3 bench" --post_content='SC-L3-BODY [sc_l3 say="bench"]' --porcelain)
cleanup() {
  wp post delete "$post" --force >/dev/null 2>&1 || true
  wp plugin deactivate sc-l3probe >/dev/null 2>&1 || true
  compose exec -T php sh -c "rm -rf $probe" || true
  compose cp ext/examples/wordpress.json "php:$conf" >/dev/null 2>&1 || true
  compose restart php >/dev/null 2>&1 || true
  i=0; until [ "$(code /)" = 200 ] || [ "$i" -ge 60 ]; do i=$((i + 1)); sleep 1; done
}
trap cleanup EXIT

cfg() { # $1 name, $2 isolate list
  cat > "$out/layer3-$1.json" <<JSON
{
  "layer1": { "isolation": "off" },
  "layer2": {
    "enabled": true, "app": "wordpress", "mode": "enforce",
    "vault": { "from": { "wpConfig": "wp-config.php" }, "secrets": [{ "name": "DB_PASSWORD", "env": "WORDPRESS_DB_PASSWORD" }] },
    "default": {}, "components": {}
  },
  "layer3": { "enabled": true, "isolate": [$2], "limits": { "timeoutMs": 5000, "memoryMb": 256 } }
}
JSON
}
cfg plain ''
cfg isolated '"sc-l3probe"'
# The helper starts with php-fpm when layer 3 is enabled: restart once, on a layer-3 config.
compose cp "$out/layer3-isolated.json" "php:$conf" >/dev/null 2>&1
compose restart php >/dev/null 2>&1
i=0; until [ "$(code /)" = 200 ]; do i=$((i + 1)); [ "$i" -lt 60 ] || { echo "php did not come back" >&2; exit 1; }; sleep 1; done

median() { sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }
# side <plain|isolated> -> median TTFB (ms) of n requests
side() {
  put_live "$out/layer3-$1.json"
  sleep 1.3 # > RELOAD_INTERVAL: every worker has the new config
  url="$base/?p=$post"
  curl -s "$url" | grep -q 'class="sc-l3-short">said bench' || { echo "the probe did not render ($1)" >&2; exit 1; }
  j=0; while [ "$j" -lt 40 ]; do curl -s -o /dev/null "$url"; j=$((j + 1)); done
  : > "$out/layer3-$1.times"
  j=0; while [ "$j" -lt "$n" ]; do
    curl -s -o /dev/null -w '%{http_code} %{time_starttransfer}\n' "$url" >> "$out/layer3-$1.times"
    j=$((j + 1))
  done
  [ "$(grep -c '^200 ' "$out/layer3-$1.times")" = "$n" ] || { echo "not all $n responses were 200 ($1)" >&2; exit 1; }
  awk '{ printf "%.3f\n", $2 * 1000 }' "$out/layer3-$1.times" | median
}

plain="" isolated=""
r=1
while [ "$r" -le "$rounds" ]; do
  # Alternate which side goes first, so neither always follows the other's config switch.
  if [ $((r % 2)) = 1 ]; then a=$(side plain); b=$(side isolated); else b=$(side isolated); a=$(side plain); fi
  printf 'round %s: plain %.2f ms   isolated %.2f ms   delta %+.2f ms\n' "$r" "$a" "$b" "$(awk "BEGIN { print $b - $a }")"
  plain="$plain $a" isolated="$isolated $b"
  r=$((r + 1))
done
range() { echo "$1" | tr ' ' '\n' | grep . | sort -n | awk 'NR == 1 { lo = $1 } { hi = $1 } END { printf "%.2f-%.2f", lo, hi }'; }
mp=$(echo "$plain" | tr ' ' '\n' | grep . | median)
mi=$(echo "$isolated" | tr ' ' '\n' | grep . | median)
printf 'median TTFB over %s rounds: plain %.2f ms [%s], isolated %.2f ms [%s], delta %+.2f ms\n' \
  "$rounds" "$mp" "$(range "$plain")" "$mi" "$(range "$isolated")" "$(awk "BEGIN { print $mi - $mp }")"
