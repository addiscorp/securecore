#!/bin/sh
# E5 hostname-allowlist compatibility check (addiscorp/securecore#53): Classic Editor, Yoast SEO
# and Contact Form 7 active, layer 2 in ENFORCE mode with the README's recommended `hosts`
# (core: api.wordpress.org + downloads.wordpress.org; each plugin: none). Loads the front page,
# the dashboard, each plugin's settings screen and a CF7 form page, twice, and lists every
# *network* refusal (grouped component/op/host with a count) plus each page's HTTP status, so each
# refusal can be judged policy-correct or rule-wrong. Data only — nothing is asserted.
#   DOCKER_CONTEXT=colima research/hosts/compat.sh
#   SECURECORE_EXT_PROJECT / SECURECORE_EXT_PORT pick the stack (default securecore-ext / 8089).
set -u
cd "$(dirname "$0")/../.." || exit 1
project=${SECURECORE_EXT_PROJECT:-securecore-ext}
port=${SECURECORE_EXT_PORT:-8089}
base=http://127.0.0.1:$port
out=.tmp/hosts-compat
mkdir -p "$out/pages"
find "$out" -mindepth 1 -type f -delete 2>/dev/null
conf=/var/www/html/securecore.json
compose() { SECURECORE_PORT=$port docker compose -f docker/compose.yml -f docker/compose.ext.yml -p "$project" "$@"; }
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
CF7_PAGE=$(wp post list --post_type=page --name=hosts-cf7 --field=ID)
[ -n "$CF7_PAGE" ] || CF7_PAGE=$(wp post create --post_type=page --post_status=publish --post_name=hosts-cf7 \
  --post_title='Hosts CF7' --post_content="[contact-form-7 id=\"$CF7_ID\"]" --porcelain)

# The recommended hosts: core may reach wordpress.org, each plugin nothing (default deny).
cat > "$out/hosts.json" <<JSON
{
  "layer1": { "enabled": false },
  "layer2": {
    "enabled": true, "app": "wordpress", "mode": "enforce",
    "core": { "hosts": ["api.wordpress.org", "downloads.wordpress.org"] },
    "default": { "hosts": [] },
    "components": {
      "classic-editor": { "hosts": [] },
      "wordpress-seo": { "hosts": [] },
      "contact-form-7": { "hosts": [] }
    }
  },
  "layer3": { "enabled": false }
}
JSON
compose cp "$out/hosts.json" "php:$conf" >/dev/null 2>&1
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
echo "# page status (enforce mode, recommended hosts)"
for pass in 1 2; do
  echo "$pages" | while IFS='|' read -r name path auth; do
    set -- -s -o "$out/pages/$name-$pass.html" -w '%{http_code}'
    [ "$auth" = yes ] && set -- "$@" -b "$J" -c "$J"
    c=$(curl "$@" "$base$path")
    echo "  pass $pass  $name  $path  -> $c"
  done
done
sleep 1
compose logs --no-log-prefix --since "$t" php 2>&1 | sed -n 's/.*securecore: //p' | grep '^layer2 enforce .* net ' > "$out/refusals.raw" || true

echo
n=$(grep -c . "$out/refusals.raw" 2>/dev/null || echo 0)
echo "# $n network refusal log lines in the window"
echo "# grouped: count  component  op  host"
# layer2 enforce <component> net <op> <rule> <host> <detail> -> count by component/op/host.
awk '{ printf "%6s %s %s %s\n", "", $3, $5, $7 }' "$out/refusals.raw" | sort | uniq -c | sort -rn > "$out/refusals.grouped"
cat "$out/refusals.grouped"
echo
echo "wrote $out/refusals.grouped and $out/refusals.raw"
