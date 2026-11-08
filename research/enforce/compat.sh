#!/bin/sh
# E2b compatibility check (addiscorp/securecore#53): Classic Editor, Yoast SEO and Contact
# Form 7 active, layer 2 in ENFORCE mode with examples/wordpress.json, on the extension stack
# test/ext-config.sh leaves up (project securecore-ext, 8089). Loads the same pages as the E2a
# measurement, twice, and lists every refusal the enforcement produced (grouped
# component/op/rule/path with a count) and each page's HTTP status, so each refusal can be
# judged policy-correct or rule-wrong. Data only.
#   DOCKER_CONTEXT=colima research/enforce/compat.sh
set -u
cd "$(dirname "$0")/../.." || exit 1
port=8089
base=http://127.0.0.1:$port
out=.tmp/enforce-compat
mkdir -p "$out/pages"
find "$out" -mindepth 1 -type f -delete 2>/dev/null
conf=/var/www/html/securecore.json
compose() { SECURECORE_PORT=$port docker compose -f docker/compose.yml -f docker/compose.ext.yml -p securecore-ext "$@"; }
wp() { compose run --rm -T cli wp "$@" 2>>"$out/wp.err" | tr -d '\r'; }
code() { curl -s -o /dev/null -w '%{http_code}' "$base$1"; }
wait_200() { i=0; until [ "$(code /)" = 200 ]; do i=$((i + 1)); [ "$i" -lt 60 ] || return 1; sleep 1; done; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
J=$out/cookies

[ "$(code /)" = 200 ] || { echo "the extension stack is not up on $base: run test/ext-config.sh first" >&2; exit 1; }

wp plugin install classic-editor wordpress-seo contact-form-7 --activate >/dev/null || { echo "plugin install failed" >&2; exit 1; }
wp plugin list --status=active --fields=name,version --format=csv > "$out/plugins.txt"
cat "$out/plugins.txt"
CF7_ID=$(wp post list --post_type=wpcf7_contact_form --field=ID | head -n 1)
CF7_PAGE=$(wp post list --post_type=page --name=enforce-cf7 --field=ID)
[ -n "$CF7_PAGE" ] || CF7_PAGE=$(wp post create --post_type=page --post_status=publish --post_name=enforce-cf7 \
  --post_title='Enforce CF7' --post_content="[contact-form-7 id=\"$CF7_ID\"]" --porcelain)

# examples/wordpress.json is already enforce mode. Put it live.
compose cp ext/examples/wordpress.json "php:$conf" >/dev/null 2>&1
compose restart php >/dev/null 2>&1
wait_200 || { echo "php-fpm did not come back" >&2; exit 1; }

# Sign in before the measured window.
: > "$J"
curl -s -c "$J" -b "$J" -o /dev/null "$base/wp-login.php"
curl -s -c "$J" -b "$J" -o /dev/null -d 'log=admin&pwd=securecore-demo&wp-submit=Log+In&testcookie=1' "$base/wp-login.php"
curl -sL -b "$J" -c "$J" -o /dev/null "$base/wp-admin/"

pages="front|/|no
dashboard|/wp-admin/|yes
classic-editor-settings|/wp-admin/options-writing.php|yes
yoast-dashboard|/wp-admin/admin.php?page=wpseo_dashboard|yes
cf7-forms|/wp-admin/admin.php?page=wpcf7|yes
cf7-form-page|/?page_id=$CF7_PAGE|no"
sleep 1; t=$(now); sleep 1
echo "# page status (enforce mode)"
for pass in 1 2; do
  echo "$pages" | while IFS='|' read -r name path auth; do
    set -- -s -o "$out/pages/$name-$pass.html" -w '%{http_code}'
    [ "$auth" = yes ] && set -- "$@" -b "$J" -c "$J"
    c=$(curl "$@" "$base$path")
    echo "  pass $pass  $name  $path  -> $c"
  done
done
sleep 1
compose logs --no-log-prefix --since "$t" php 2>&1 | sed -n 's/.*securecore: //p' | grep '^layer2 enforce ' > "$out/refusals.raw" || true

echo
n=$(grep -c . "$out/refusals.raw" 2>/dev/null || echo 0)
echo "# $n refusal log lines in the window"
echo "# grouped: count  component  op  rule  path"
# Drop the mode column, group identical (component op rule path), newest paths kept verbatim.
awk '{ $1=""; sub(/^ /,""); c[$0]++ } END { for (k in c) printf "%6d  %s\n", c[k], k }' "$out/refusals.raw" | sort -k2 > "$out/refusals.grouped"
cat "$out/refusals.grouped"
echo
echo "wrote $out/refusals.grouped and $out/refusals.raw"
