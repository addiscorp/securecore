#!/bin/sh
# Canary for addiscorp/securecore#47: a secret autoloaded option set OUTSIDE the sandbox must
# not be reachable from a sandboxed plugin's memory under pre-boot, and must not be written to
# the options snapshot. On the running docker/ stack:
#   1. install and sandbox a probe plugin (test/canary-plugin);
#   2. set `securecore_canary_secret` to a sentinel from wp-cli (a non-sandboxed context);
#   3. force a fresh snapshot and (re)start the worker pre-booted from it;
#   4. the snapshot file must not contain the sentinel;
#   5. load a page so the sandbox loads the probe, which scans $GLOBALS and the $wpdb object and
#      writes SECURECORE_CANARY_RESULT:FOUND/CLEAN to the worker log — it must be CLEAN.
# Exits non-zero if the secret leaks. Writes .tmp/canary/.
#   DOCKER_CONTEXT=colima test/canary.sh
set -u
cd "$(dirname "$0")/.." || exit 1
base=http://127.0.0.1:8088
dir=.tmp/canary
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete 2>/dev/null
SENTINEL=SECURECORE_CANARY_SENTINEL_7f3ad2c1
PROBE=securecore-canary/securecore-canary.php
BASE_SANDBOX="hello.php securecore-probe/securecore-probe.php"
J=$dir/cookies
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }

compose() { docker compose -f docker/compose.yml "$@"; }
wp() { compose run --rm -T cli wp "$@" 2>>"$dir/wp.err"; }
in_php() { compose exec -T php sh -c "$1"; }
snapshot=/var/www/html/wp-content/securecore/options-snapshot.php

# shellcheck disable=SC2329  # invoked indirectly via trap EXIT
cleanup() {
  in_php "rm -f /var/www/html/wp-content/securecore/manifests/securecore-canary.json" >/dev/null 2>&1
  compose run --rm -T cli wp --skip-plugins plugin deactivate securecore-canary >/dev/null 2>&1
  compose run --rm -T cli wp --skip-plugins option delete securecore_canary_secret >/dev/null 2>&1
  in_php "rm -rf /var/www/html/wp-content/plugins/securecore-canary" >/dev/null 2>&1
}
trap cleanup EXIT

# Pre-boot must be on (the issue is about the pre-boot snapshot).
wp config set SECURECORE_REALWP true --raw >/dev/null
wp config set SECURECORE_SOCKET /run/securecore/worker.sock >/dev/null 2>&1 || true

# Bring the worker up pre-booted now, before any admin page loads: a realwp wp-config talking to
# a stub worker hangs the request (504).
worker_up() {
  SECURECORE_REALWP=1 SECURECORE_PREBOOT=1 compose up -d --force-recreate worker >/dev/null 2>&1
  i=0
  until compose logs --tail=5 worker 2>&1 | grep -q 'listening on'; do
    i=$((i + 1)); [ "$i" -lt 30 ] || break; sleep 1
  done
}
worker_up

# 1. Install the probe plugin and activate it.
in_php 'mkdir -p /var/www/html/wp-content/plugins/securecore-canary'
compose cp test/canary-plugin/securecore-canary.php php:/var/www/html/wp-content/plugins/securecore-canary/securecore-canary.php >/dev/null
in_php 'chown -R www-data:www-data /var/www/html/wp-content/plugins/securecore-canary'
wp plugin activate securecore-canary hello securecore-probe >/dev/null 2>&1

# 2. Set the secret autoloaded option from wp-cli (SecureCore is inert under WP_CLI).
wp option update securecore_canary_secret "$SENTINEL" --autoload=yes >/dev/null

# 3. Sandbox the probe: Settings -> SecureCore -> Save, which generates its manifest.
login() {
  : > "$J"
  curl -s -c "$J" -b "$J" -o /dev/null "$base/wp-login.php"
  curl -s -c "$J" -b "$J" -o /dev/null -d 'log=admin&pwd=securecore-demo&wp-submit=Log+In&testcookie=1' "$base/wp-login.php"
}
nonce_of() { sed -n 's/.*name="_wpnonce" value="\([^"]*\)".*/\1/p' "$1" | head -n 1; }
login
for _ in 1 2 3; do
  curl -s -b "$J" -c "$J" -o "$dir/settings.html" "$base/wp-admin/options-general.php?page=securecore"
  [ -n "$(nonce_of "$dir/settings.html")" ] && break
done
set -- --data-urlencode "_wpnonce=$(nonce_of "$dir/settings.html")" -d securecore_action=save
for p in $BASE_SANDBOX $PROBE; do set -- "$@" --data-urlencode "sandbox[]=$p"; done
curl -s -b "$J" -o "$dir/saved.html" "$@" "$base/wp-admin/options-general.php?page=securecore"
grep -q 'Saved. Sandboxed:' "$dir/saved.html" || { echo "FAIL could not sandbox the probe"; exit 1; }
# SecureCore names a generated manifest after the whole plugin path and keys it by the plugin
# field inside, so match on content, not a guessed filename.
if in_php "grep -rl 'securecore-canary/securecore-canary.php' /var/www/html/wp-content/securecore/manifests/ >/dev/null 2>&1"; then
  pass "probe sandboxed (manifest generated)"
else
  fail "probe manifest missing"
fi

# 4. Force a fresh snapshot that reflects the secret just set, then pre-boot the worker from it.
in_php "rm -f $snapshot ${snapshot%.php}.hash"
curl -s -o /dev/null "$base/"   # a request writes the snapshot (core side)
sleep 1
worker_up                       # re-boot the worker from the fresh snapshot

# 5. The snapshot file must not contain the sentinel.
if in_php "test -f $snapshot && grep -q '$SENTINEL' $snapshot"; then
  fail "snapshot file contains the secret"
else
  pass "snapshot file does not contain the secret"
fi

# 6. Load a page so the sandbox loads the probe; read its verdict from the worker log.
curl -s -o /dev/null "$base/"
sleep 1
result=$(compose logs worker 2>&1 | grep -oE 'SECURECORE_CANARY_RESULT:(FOUND|CLEAN)' | tail -1)
case "$result" in
  *CLEAN) pass "probe did not find the secret in sandbox memory" ;;
  *FOUND) fail "probe found the secret in sandbox memory" "the leak #47 describes" ;;
  *)
    fail "probe did not report" "SECURECORE_CANARY_RESULT not in the worker log"
    echo "--- worker log tail (debug) ---"; compose logs --tail=20 worker 2>&1 | sed 's/^/  /'
    ;;
esac

echo
[ "$fails" -eq 0 ] && echo "canary: PASS" || echo "canary: FAIL ($fails)"
exit "$fails"
