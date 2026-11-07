#!/bin/sh
# E2a measurement (addiscorp/securecore#53): which component each attribution rule charges for
# every file open during real page loads, with Classic Editor, Yoast SEO and Contact Form 7
# active, on the extension stack test/ext-config.sh leaves up (project securecore-ext, 8089).
#
# Layer 2 in log mode and securecore.debug_attribution_log=both; then, twice each (the first
# pass includes first-visit work such as caches being written): the front page, the wp-admin
# dashboard, each plugin's settings screen (Settings → Writing for Classic Editor, Yoast's
# dashboard, CF7's form list) and a page with a CF7 form. The php-fpm log of those requests
# goes through securecore-attribution-report, which prints one table per rule.
# Data only: no rule is defined or enforced here.
#
# Writes .tmp/attribution/: php.log (the raw lines), report.md (the tables), detail.tsv (every
# path), plugins.txt (versions), pages/. Restores examples/wordpress.json and removes the debug
# ini at the end; leaves the three plugins installed and active.
#   DOCKER_CONTEXT=colima research/attribution/measure.sh
set -u
cd "$(dirname "$0")/../.." || exit 1
port=8089
base=http://127.0.0.1:$port
out=.tmp/attribution
mkdir -p "$out/pages"
find "$out" -mindepth 1 -type f -delete 2>/dev/null
conf=/var/www/html/securecore.json
ini=/usr/local/etc/php/conf.d/securecore-debug.ini
compose() { SECURECORE_PORT=$port docker compose -f docker/compose.yml -f docker/compose.ext.yml -p securecore-ext "$@"; }
wp() { compose run --rm -T cli wp "$@" 2>>"$out/wp.err" | tr -d '\r'; }
code() { curl -s -o /dev/null -w '%{http_code}' "$base$1"; }
wait_200() { i=0; until [ "$(code /)" = 200 ]; do i=$((i + 1)); [ "$i" -lt 60 ] || return 1; sleep 1; done; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
J=$out/cookies
fails=0

[ "$(code /)" = 200 ] || { echo "the extension stack is not up on $base: run test/ext-config.sh first" >&2; exit 1; }

# --- the plugins and a CF7 form page --------------------------------------------------------
wp plugin install classic-editor wordpress-seo contact-form-7 --activate >/dev/null || { echo "plugin install failed" >&2; exit 1; }
wp plugin list --status=active --fields=name,version --format=csv > "$out/plugins.txt"
cat "$out/plugins.txt"
CF7_ID=$(wp post list --post_type=wpcf7_contact_form --field=ID | head -n 1)
[ -n "$CF7_ID" ] || { echo "Contact Form 7 made no default form" >&2; exit 1; }
CF7_PAGE=$(wp post list --post_type=page --name=attribution-cf7 --field=ID)
[ -n "$CF7_PAGE" ] || CF7_PAGE=$(wp post create --post_type=page --post_status=publish --post_name=attribution-cf7 \
  --post_title='Attribution CF7' --post_content="[contact-form-7 id=\"$CF7_ID\"]" --porcelain)

# --- log mode, both rules logged --------------------------------------------------------------
sed 's/"mode": "enforce"/"mode": "log"/' ext/examples/wordpress.json > "$out/log.json"
compose cp "$out/log.json" "php:$conf" >/dev/null 2>&1
printf 'securecore.debug_attribution_log=both\n' | compose exec -T php sh -c "cat > $ini"
compose restart php >/dev/null 2>&1
wait_200 || { echo "php-fpm did not come back" >&2; exit 1; }
restore() {
  compose exec -T php rm -f "$ini"
  compose cp ext/examples/wordpress.json "php:$conf" >/dev/null 2>&1
  compose restart php >/dev/null 2>&1
  wait_200 || echo "php-fpm did not come back after restoring" >&2
}
trap restore EXIT

# Signed in before the measured window, so wp-login.php is not part of it.
: > "$J"
curl -s -c "$J" -b "$J" -o /dev/null "$base/wp-login.php"
curl -s -c "$J" -b "$J" -o /dev/null -d 'log=admin&pwd=securecore-demo&wp-submit=Log+In&testcookie=1' "$base/wp-login.php"
# A plugin's first admin view after activation may be a welcome redirect: take it now.
curl -sL -b "$J" -c "$J" -o /dev/null "$base/wp-admin/"

# name|path|signed-in|must contain
pages="front|/|no|</html>
dashboard|/wp-admin/|yes|id=\"dashboard-widgets
classic-editor-settings|/wp-admin/options-writing.php|yes|classic-editor-replace
yoast-dashboard|/wp-admin/admin.php?page=wpseo_dashboard|yes|wpseo
cf7-forms|/wp-admin/admin.php?page=wpcf7|yes|wpcf7
cf7-form-page|/?page_id=$CF7_PAGE|no|class=\"wpcf7-form"
# --since has one-second resolution: keep the warm-up request out of the window.
sleep 1; t=$(now); sleep 1
for pass in 1 2; do
  echo "$pages" | while IFS='|' read -r name path auth want; do
    set -- -s -o "$out/pages/$name-$pass.html" -w '%{http_code}'
    [ "$auth" = yes ] && set -- "$@" -b "$J" -c "$J"
    c=$(curl "$@" "$base$path")
    if [ "$c" = 200 ] && grep -q "$want" "$out/pages/$name-$pass.html"; then
      echo "ok   pass $pass: $name ($path) 200"
    else
      echo "FAIL pass $pass: $name ($path) $c, or no '$want'"
      echo x >> "$out/failed"
    fi
  done
done
sleep 1
compose logs --no-log-prefix --since "$t" php > "$out/php.log" 2>&1
[ -f "$out/failed" ] && fails=$(grep -c . "$out/failed")
echo "$(grep -c 'securecore: attribution ' "$out/php.log") attribution lines"

# --- the tables -----------------------------------------------------------------------------
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$PWD/.target} cargo run -q --locked --manifest-path ext/Cargo.toml \
  -p securecore-attribution --bin securecore-attribution-report -- \
  --root /var/www/html --detail "$out/detail.tsv" "$out/php.log" > "$out/report.md"
rc=$?
[ "$rc" -eq 0 ] || { echo "report failed ($rc)" >&2; exit 1; }
cat "$out/report.md"
[ "$fails" -eq 0 ]
