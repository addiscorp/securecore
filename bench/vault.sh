#!/bin/sh
# Front-page and login-round p50 for the vault (addiscorp/securecore#53, E3), on the
# test/ext-config.sh stack (project securecore-ext; run that first). The extension is loaded on
# both sides; only the vault differs, so this isolates the vault's per-request cost (the getenv /
# define overrides and the point-of-use password swap; the MINIT masking is one-off):
#   novault  examples/wordpress.json with the vault removed (layer 2 enforce, no vault)
#   vault    examples/wordpress.json as-is (the vault on: DB password and salts hidden)
# Each side, each round: 20 warm-up + 100 measured sequential requests by oha, for the front page
# (/) and a login round (/wp-login.php). php-fpm is restarted for each side (the vault is read at
# MINIT). Prints each round and the median p50 per side and page; writes .tmp/bench/vault.json.
#   DOCKER_CONTEXT=colima bench/vault.sh [rounds]     (default 7)
set -eu
cd "$(dirname "$0")/.."
rounds=${1:-7}
OHA=ghcr.io/hatoo/oha@sha256:3ec3dbf549ea197793482d47a6324797411406bbf438c2fe8b91f244ec641a2f # oha 1.16.0
project=${SECURECORE_EXT_PROJECT:-securecore-ext}
port=${SECURECORE_EXT_PORT:-8089}
conf=/var/www/html/securecore.json
muplugin=/var/www/html/wp-content/mu-plugins/securecore-vault.php
out=.tmp/bench
mkdir -p "$out"
compose() { SECURECORE_PORT=$port docker compose -f docker/compose.yml -f docker/compose.ext.yml -p "$project" "$@"; }
oha() { docker run --rm --network "${project}_default" "$OHA" --no-tui --output-format json -H "Host: 127.0.0.1:$port" "$@"; }

# The vault mu-plugin on both sides (it no-ops when the vault is inactive).
compose cp ext/mu-plugin/securecore-vault.php "php:$muplugin" >/dev/null 2>&1
compose exec -T php chown www-data:www-data "$muplugin"
# The no-vault config: wordpress.json with the "vault" object dropped (built on the host with jq).
jq 'del(.layer2.vault)' ext/examples/wordpress.json > "$out/novault.json"
compose cp "$out/novault.json" php:/tmp/novault.json >/dev/null 2>&1

wait_200() { i=0; until [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8089$1")" = 200 ]; do i=$((i+1)); [ "$i" -lt 60 ] || { echo "php did not come back ($1)" >&2; exit 1; }; sleep 1; done; }

# p50 <path> -> median p50 ms over the current side.
p50() {
  oha -n 20 -c 1 "http://web$1" >/dev/null
  oha -n 100 -c 1 "http://web$1" > "$out/vault-run.json"
  ok=$(jq -r '.statusCodeDistribution["200"] // 0' "$out/vault-run.json")
  [ "$ok" = 100 ] || { echo "not all 100 responses were 200 ($1)" >&2; exit 1; }
  jq -r '.metrics.latency_ms.p50' "$out/vault-run.json"
}

# side <novault|vault>: apply its config, restart, and print "<front> <login>".
side() {
  if [ "$1" = vault ]; then
    compose cp ext/examples/wordpress.json "php:$conf" >/dev/null 2>&1
  else
    compose exec -T php sh -c "cp /tmp/novault.json $conf"
  fi
  compose restart php >/dev/null 2>&1
  wait_200 /
  echo "$(p50 /) $(p50 /wp-login.php)"
}

median() { sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }
nf="" nl="" vf="" vl=""
r=1
while [ "$r" -le "$rounds" ]; do
  n=$(side novault); n_front=${n% *}; n_login=${n#* }
  v=$(side vault);   v_front=${v% *}; v_login=${v#* }
  printf 'round %s: front  novault %.2f  vault %.2f    login  novault %.2f  vault %.2f  (ms)\n' \
    "$r" "$n_front" "$v_front" "$n_login" "$v_login"
  nf="$nf $n_front" nl="$nl $n_login" vf="$vf $v_front" vl="$vl $v_login"
  r=$((r + 1))
done
mnf=$(echo "$nf" | tr ' ' '\n' | grep . | median)
mnl=$(echo "$nl" | tr ' ' '\n' | grep . | median)
mvf=$(echo "$vf" | tr ' ' '\n' | grep . | median)
mvl=$(echo "$vl" | tr ' ' '\n' | grep . | median)
printf 'median p50 front: novault %.2f ms, vault %.2f ms, delta %+.2f ms\n' "$mnf" "$mvf" "$(echo "$mvf - $mnf" | bc -l)"
printf 'median p50 login: novault %.2f ms, vault %.2f ms, delta %+.2f ms\n' "$mnl" "$mvl" "$(echo "$mvl - $mnl" | bc -l)"
list() { echo "$1" | sed 's/^ //; s/ /,/g'; }
printf '{"rounds":%s,"front_novault":[%s],"front_vault":[%s],"login_novault":[%s],"login_vault":[%s],"median":{"front_novault":%s,"front_vault":%s,"login_novault":%s,"login_vault":%s}}\n' \
  "$rounds" "$(list "$nf")" "$(list "$vf")" "$(list "$nl")" "$(list "$vl")" "$mnf" "$mvf" "$mnl" "$mvl" > "$out/vault.json"
