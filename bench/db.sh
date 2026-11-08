#!/bin/sh
# E4 database-policy benchmark (addiscorp/securecore#53): front-page and dashboard p50 with
# Classic Editor, Yoast SEO and Contact Form 7 active, layer 2 in enforce mode, main's extension
# against this branch's. Both sides run the same securecore.json (default: research/db/compat.sh's
# .tmp/db-compat-caller/enforce.json, the example with the generated entries), so the difference is the
# database policy. Sides alternate, php-fpm recreated for each; each measurement is 20 warm-up +
# 100 sequential requests by oha on the stack's network. Writes .tmp/bench/db.json.
#   DOCKER_CONTEXT=colima bench/db.sh [rounds] [config]     (default 7, .tmp/db-compat-caller/enforce.json)
#   SECURECORE_DB_ATTRIBUTION=component sets the research setting securecore.debug_db_attribution
#   on both sides (main ignores the key); the rule is `caller`.
#   SECURECORE_EXT_PROJECT / SECURECORE_EXT_PORT pick another project / port.
set -eu
cd "$(dirname "$0")/.."
rounds=${1:-7}
config=${2:-.tmp/db-compat-caller/enforce.json}
project=${SECURECORE_EXT_PROJECT:-securecore-ext}
port=${SECURECORE_EXT_PORT:-8089}
OHA=ghcr.io/hatoo/oha@sha256:3ec3dbf549ea197793482d47a6324797411406bbf438c2fe8b91f244ec641a2f # oha 1.16.0
conf=/var/www/html/securecore.json
ini=/usr/local/etc/php/conf.d/securecore.ini
image=$project-php
out=.tmp/bench
mkdir -p "$out"
[ -f "$config" ] || { echo "no $config: run research/db/compat.sh first, or pass a config" >&2; exit 1; }
compose() { SECURECORE_PORT=$port docker compose -f docker/compose.yml -f docker/compose.ext.yml -p "$project" "$@"; }
oha() { docker run --rm --network "${project}_default" "$OHA" --no-tui --output-format json -H "Host: 127.0.0.1:$port" "$@"; }

# The two images: this branch's (what compose built) and main's, built from origin/main's tree.
docker tag "$image:latest" "$image:branch"
git archive origin/main | docker build -q -f docker/ext.Dockerfile --target php -t "$image:main" - >/dev/null

up() { # $1 = main | branch
  docker tag "$image:$1" "$image:latest"
  compose up -d --no-build --force-recreate php >/dev/null 2>&1
  i=0; until [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/")" = 200 ]; do
    i=$((i + 1)); [ "$i" -lt 90 ] || { echo "php did not come back ($1)" >&2; exit 1; }; sleep 1
  done
  compose cp "$config" "php:$conf" >/dev/null 2>&1
  if [ -n "${SECURECORE_DB_ATTRIBUTION:-}" ]; then
    compose exec -T php sh -c "grep -v '^securecore.debug_db_attribution' $ini > $ini.new && echo 'securecore.debug_db_attribution=$SECURECORE_DB_ATTRIBUTION' >> $ini.new && mv $ini.new $ini"
  fi
  compose restart php >/dev/null 2>&1
  i=0; until [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/")" = 200 ]; do
    i=$((i + 1)); [ "$i" -lt 90 ] || { echo "php did not come back on the config ($1)" >&2; exit 1; }; sleep 1
  done
}

cookie() { # the admin's auth cookies, as one Cookie header value
  j=$out/db-cookies
  : > "$j"
  curl -s -c "$j" -b "$j" -o /dev/null "http://127.0.0.1:$port/wp-login.php"
  curl -s -c "$j" -b "$j" -o /dev/null -d 'log=admin&pwd=securecore-demo&wp-submit=Log+In&testcookie=1' "http://127.0.0.1:$port/wp-login.php"
  # curl writes HttpOnly cookies as "#HttpOnly_<domain> …": those are cookies, not comments.
  awk '{ sub(/^#HttpOnly_/, "") } !/^#/ && NF >= 7 { printf "%s%s=%s", (n++ ? "; " : ""), $6, $7 }' "$j"
}

p50() { # $1 = name, rest = oha args + URL
  name=$1; shift
  oha -n 20 -c 1 "$@" >/dev/null
  oha -n 100 -c 1 "$@" > "$out/db-$name.json"
  ok=$(jq -r '.statusCodeDistribution["200"] // 0' "$out/db-$name.json")
  [ "$ok" = 100 ] || { echo "not all 100 responses were 200 ($name)" >&2; exit 1; }
  jq -r '.metrics.latency_ms.p50' "$out/db-$name.json"
}

side() { # $1 = main | branch -> "front admin"
  up "$1"
  c=$(cookie)
  f=$(p50 "$1-front" http://web/)
  a=$(p50 "$1-admin" -H "Cookie: $c" http://web/wp-admin/)
  echo "$f $a"
}

median() { sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }
mf="" ma="" bf="" ba=""
r=1
while [ "$r" -le "$rounds" ]; do
  s=$(side main); m1=${s% *} m2=${s#* }
  s=$(side branch); b1=${s% *} b2=${s#* }
  printf 'round %s: front main %.2f branch %.2f   dashboard main %.2f branch %.2f ms\n' "$r" "$m1" "$b1" "$m2" "$b2"
  mf="$mf $m1" ma="$ma $m2" bf="$bf $b1" ba="$ba $b2"
  r=$((r + 1))
done
docker tag "$image:branch" "$image:latest"
compose up -d --no-build --force-recreate php >/dev/null 2>&1
med() { echo "$1" | tr ' ' '\n' | grep . | median; }
printf 'median p50 front:     main %.2f ms, branch %.2f ms, delta %+.2f ms\n' "$(med "$mf")" "$(med "$bf")" "$(echo "$(med "$bf") - $(med "$mf")" | bc -l)"
printf 'median p50 dashboard: main %.2f ms, branch %.2f ms, delta %+.2f ms\n' "$(med "$ma")" "$(med "$ba")" "$(echo "$(med "$ba") - $(med "$ma")" | bc -l)"
list() { echo "$1" | sed 's/^ //; s/ /,/g'; }
printf '{"rounds":%s,"front":{"main":[%s],"branch":[%s]},"dashboard":{"main":[%s],"branch":[%s]}}\n' \
  "$rounds" "$(list "$mf")" "$(list "$bf")" "$(list "$ma")" "$(list "$ba")" > "$out/db.json"
