#!/bin/sh
# Property tests for the gelada-sandboxed worker (addiscorp/securecore#42, part 3) on the running
# docker/ stack. A sandboxed probe (test/gelada-plugin) tries to read wp-config.php, connect out
# and write around the filesystem, and reports each to the worker log. This runs it:
#   - with gelada, pre-boot      → everything blocked, the request still renders;
#   - WITHOUT gelada, pre-boot   → the same probe reads wp-config, reaches MySQL/php-fpm and writes
#                                  the plugins folder — proving the block is gelada's doing;
#   - with gelada, per-request   → blocked there too.
# Exits non-zero on any failure. Writes .tmp/gelada/.
#   DOCKER_CONTEXT=colima test/gelada.sh
set -u
cd "$(dirname "$0")/.." || exit 1
base=http://127.0.0.1:8088
dir=.tmp/gelada
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete 2>/dev/null
PROBE=securecore-gelada/securecore-gelada.php
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }
compose() { docker compose -f docker/compose.yml "$@"; }
wp() { compose run --rm -T cli wp "$@" 2>>"$dir/wp.err"; }
in_root() { compose exec -T php sh -c "$1"; }
plugindir=/var/www/html/wp-content/plugins

# shellcheck disable=SC2329  # invoked indirectly via trap EXIT
cleanup() {
  in_root "grep -rl '\"plugin\": \"$PROBE\"' /var/www/html/wp-content/securecore/manifests/ 2>/dev/null | xargs -r rm -f" >/dev/null 2>&1
  compose run --rm -T cli wp --skip-plugins plugin deactivate securecore-gelada >/dev/null 2>&1
  in_root "rm -rf $plugindir/securecore-gelada" >/dev/null 2>&1
  # Leave the worker back on gelada + pre-boot.
  SECURECORE_REALWP=1 SECURECORE_PREBOOT=1 compose up -d --force-recreate worker >/dev/null 2>&1
}
trap cleanup EXIT

wp config set SECURECORE_REALWP true --raw >/dev/null 2>&1 || true
wp config set SECURECORE_SOCKET /run/securecore/worker.sock >/dev/null 2>&1 || true

# worker_up <preboot 0|1> <nogelada 0|1>
worker_up() {
  SECURECORE_REALWP=1 SECURECORE_PREBOOT=$([ "$1" = 1 ] && echo 1 || echo '') \
    SECURECORE_NOGELADA=$([ "$2" = 1 ] && echo 1 || echo '') \
    compose up -d --force-recreate worker >/dev/null 2>&1
  i=0; until compose logs --tail=5 worker 2>&1 | grep -q 'listening on'; do i=$((i + 1)); [ "$i" -lt 30 ] || break; sleep 1; done
}
wait_php() { i=0; until [ "$(curl -s -o /dev/null -w '%{http_code}' "$base/")" = 200 ]; do i=$((i + 1)); [ "$i" -lt 30 ] || break; sleep 1; done; }

# --- install + sandbox the probe ------------------------------------------------------------------
in_root "mkdir -p $plugindir/securecore-gelada"
compose cp test/gelada-plugin/securecore-gelada.php php:$plugindir/securecore-gelada/securecore-gelada.php >/dev/null
in_root "chown -R www-data:www-data $plugindir/securecore-gelada"
wp plugin activate securecore-gelada hello >/dev/null 2>&1
worker_up 1 0

login() {
  : > "$dir/cookies"
  curl -s -c "$dir/cookies" -b "$dir/cookies" -o /dev/null "$base/wp-login.php"
  curl -s -c "$dir/cookies" -b "$dir/cookies" -o /dev/null -d 'log=admin&pwd=securecore-demo&wp-submit=Log+In&testcookie=1' "$base/wp-login.php"
}
login
nonce=$(for _ in 1 2 3; do curl -s -b "$dir/cookies" -o "$dir/s.html" "$base/wp-admin/options-general.php?page=securecore"; n=$(sed -n 's/.*name="_wpnonce" value="\([^"]*\)".*/\1/p' "$dir/s.html" | head -n 1); [ -n "$n" ] && { echo "$n"; break; }; done)
set -- --data-urlencode "_wpnonce=$nonce" -d securecore_action=save
for p in hello.php "$PROBE"; do set -- "$@" --data-urlencode "sandbox[]=$p"; done
curl -s -b "$dir/cookies" -o "$dir/saved.html" "$@" "$base/wp-admin/options-general.php?page=securecore"
if grep -q "Sandboxed: .*securecore-gelada" "$dir/saved.html"; then pass "probe sandboxed"; else fail "could not sandbox the probe"; exit 1; fi

run_probe() {
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  code=$(curl -s -o /dev/null -w '%{http_code}' "$base/")
  sleep 1
  compose logs --since "$since" worker 2>&1 | grep 'GELADA_PROBE:' > "$dir/$1.log" || true
  echo "$code" > "$dir/$1.code"
}
obs() { sed -n "s/.*GELADA_PROBE:$2=\(.*\)/\1/p" "$dir/$1.log" | tail -n 1; }
# want_prefix <tag> <key> <prefix> <desc>
is() { case "$(obs "$1" "$2")" in "$3"*) pass "$4 ($2=$(obs "$1" "$2"))" ;; *) fail "$4" "$2=$(obs "$1" "$2")" ;; esac; }
isnot() { case "$(obs "$1" "$2")" in "$3"*) fail "$4" "$2=$(obs "$1" "$2")" ;; *) pass "$4 ($2=$(obs "$1" "$2"))" ;; esac; }

# --- phase A: gelada ON, pre-boot -----------------------------------------------------------------
echo "== gelada ON, pre-boot =="
run_probe on
is on read_wp_config failed "wp-config.php is unreadable"
is on db_password_const undefined "DB_PASSWORD is not defined in the sandbox"
is on connect_mysql blocked "MySQL connect blocked"
is on connect_php_fpm blocked "php-fpm connect blocked"
is on connect_arbitrary blocked "arbitrary host connect blocked"
is on write_uploads ok "writes to uploads allowed"
is on write_plugins failed "writes to the plugins folder blocked"
is on write_wp_includes failed "writes to wp-includes blocked"
is on write_mu_plugins failed "writes to mu-plugins blocked"
[ "$(cat "$dir/on.code")" = 200 ] && pass "the request still renders (200)" || fail "request renders" "HTTP $(cat "$dir/on.code")"

# --- phase B: gelada OFF, pre-boot (the same probe must now leak) ---------------------------------
echo "== gelada OFF, pre-boot (same probe should now leak) =="
worker_up 1 1; wait_php
run_probe off
isnot off read_wp_config failed "without gelada, wp-config.php is readable"
isnot off connect_mysql blocked "without gelada, MySQL is reachable"
isnot off connect_php_fpm blocked "without gelada, php-fpm is reachable"
is off write_plugins ok "without gelada, the plugins folder is writable"

# --- phase C: gelada ON, per-request --------------------------------------------------------------
echo "== gelada ON, per-request =="
worker_up 0 0; wait_php
run_probe req
is req read_wp_config failed "per-request: wp-config.php unreadable"
is req connect_mysql blocked "per-request: MySQL connect blocked"
is req write_plugins failed "per-request: writes to the plugins folder blocked"
[ "$(cat "$dir/req.code")" = 200 ] && pass "per-request: the request still renders (200)" || fail "per-request renders" "HTTP $(cat "$dir/req.code")"

echo
[ "$fails" -eq 0 ] && echo "gelada: PASS" || echo "gelada: FAIL ($fails)"
exit "$fails"
