#!/bin/sh
# Checks a running docker/ stack from the outside, the way a user would see it.
#   test/site.sh            SecureCore on: Hello Dolly works sandboxed, the probe's attacks fail
#   test/site.sh baseline   SecureCore off: Hello Dolly works as a normal plugin
# Exits non-zero on the first failed check.
set -u
cd "$(dirname "$0")/.."
mode=${1:-sandbox}
url=http://127.0.0.1:8088
dir=.tmp/site-test
mkdir -p "$dir"
jar=$dir/cookies
page=$dir/admin.html
fails=0

compose() { docker compose -f docker/compose.yml "$@"; }
wp() { compose run --rm -T cli wp "$@" 2>/dev/null; }
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1"; fails=$((fails + 1)); }
has() { if grep -qF -- "$2" "$3"; then pass "$1"; else fail "$1"; fi; }
lacks() { if grep -qF -- "$2" "$3"; then fail "$1"; else pass "$1"; fi; }

wp user delete probe_admin --yes >/dev/null
compose exec -T -u www-data php sh -c ': > wp-content/securecore-audit.log'
if [ "$mode" = baseline ]; then
  wp config set SECURECORE_DISABLED true --raw >/dev/null
else
  wp config delete SECURECORE_DISABLED >/dev/null
fi

: > "$jar"
curl -s -c "$jar" -b "$jar" -o /dev/null "$url/wp-login.php"
curl -s -c "$jar" -b "$jar" -o /dev/null -d 'log=admin&pwd=securecore-demo&wp-submit=Log+In&testcookie=1' "$url/wp-login.php"
code=$(curl -s -b "$jar" -o "$page" -w '%{http_code} %{time_total}' "$url/wp-admin/")
echo "GET /wp-admin/ -> $code s"
case $code in 200*) pass "wp-admin loads" ;; *) fail "wp-admin loads" ;; esac
has "Hello Dolly notice shows" 'id="dolly"' "$page"

if [ "$mode" = baseline ]; then
  has "probe runs in core when SecureCore is off" 'data-where="core"' "$page"
  lacks "no sandbox report" '<!-- securecore: sandboxed' "$page"
  wp config delete SECURECORE_DISABLED >/dev/null
  wp user delete probe_admin --yes >/dev/null
else
  has "probe runs in the sandbox" 'data-where="sandbox" data-file="/plugin/securecore-probe.php"' "$page"
  has "core included no sandboxed plugin" 'included by core: none -->' "$page"
  for attempt in read-wp-config read-db-password create-admin send-out; do
    has "$attempt failed" "$attempt=failed" "$page"
  done
  if wp user get probe_admin >/dev/null; then fail "no probe_admin user exists"; else pass "no probe_admin user exists"; fi
  log=$dir/audit.log
  compose exec -T php cat wp-content/securecore-audit.log > "$log"
  has "audit: wp-config.php read denied" '"event":"fs.deny","op":"open","path":"/wordpress/wp-config.php"' "$log"
  has "audit: DB_PASSWORD use failed" 'Undefined constant \"DB_PASSWORD\"' "$log"
  has "audit: wp_insert_user denied" '"event":"wp.deny","name":"wp_insert_user"' "$log"
  has "audit: wp_remote_post denied" '"event":"wp.deny","name":"wp_remote_post"' "$log"
fi

[ "$fails" -eq 0 ] && echo "all checks passed ($mode)" || echo "$fails check(s) failed ($mode)"
[ "$fails" -eq 0 ]
