#!/bin/sh
# E4 compatibility check (addiscorp/securecore#53): Classic Editor, Yoast SEO and Contact Form 7
# under the database policy, on the extension stack test/ext-config.sh leaves up.
#   1. log mode, examples/wordpress.json with no database entries for the three: load the pages
#      twice and submit the CF7 form; securecore-db-suggest turns the log lines into entries;
#   2. enforce mode with those generated entries merged into the example: the same pages and
#      submission, and every refusal listed (grouped, with a count) with each page's status, to be
#      judged policy-right or rule-wrong.
# Data only. Writes .tmp/db-compat-<attribution>/ (suggested.json, refusals.grouped, …).
# The vault's mu-plugin is installed, as the README recommends (its native wp_salt keeps core's
# salt fallback from reading the salt options under a component's frame).
#   DOCKER_CONTEXT=colima research/db/compat.sh
#   SECURECORE_DB_ATTRIBUTION=component ...   research only: charge queries to the innermost
#                                            component on the stack, the rule #60 measured and
#                                            rejected (securecore.debug_db_attribution); default caller
#   SECURECORE_EXT_PROJECT / SECURECORE_EXT_PORT pick another project / port.
set -u
cd "$(dirname "$0")/../.." || exit 1
project=${SECURECORE_EXT_PROJECT:-securecore-ext}
port=${SECURECORE_EXT_PORT:-8089}
attr=${SECURECORE_DB_ATTRIBUTION:-caller}
base=http://127.0.0.1:$port
out=.tmp/db-compat-$attr
mkdir -p "$out/pages"
find "$out" -mindepth 1 -type f -delete 2>/dev/null
conf=/var/www/html/securecore.json
ini=/usr/local/etc/php/conf.d/securecore.ini
mu=/var/www/html/wp-content/mu-plugins
compose() { SECURECORE_PORT=$port docker compose -f docker/compose.yml -f docker/compose.ext.yml -p "$project" "$@"; }
wp() { compose run --rm -T cli wp "$@" 2>>"$out/wp.err" | tr -d '\r'; }
code() { curl -s -o /dev/null -w '%{http_code}' "$base$1"; }
wait_200() { i=0; until [ "$(code /)" = 200 ]; do i=$((i + 1)); [ "$i" -lt 60 ] || return 1; sleep 1; done; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
J=$out/cookies

[ "$(code /)" = 200 ] || { echo "the extension stack is not up on $base: run test/ext-config.sh first" >&2; exit 1; }

# The attribution setting for this run, and the vault's mu-plugin; both undone at the end.
compose cp "php:$ini" "$out/securecore.ini" >/dev/null 2>&1
{ grep -v '^securecore.debug_db_attribution' "$out/securecore.ini"; echo "securecore.debug_db_attribution=$attr"; } > "$out/run.ini"
compose cp "$out/run.ini" "php:$ini" >/dev/null 2>&1
compose exec -T php sh -c "mkdir -p $mu && chown www-data:www-data $mu"
compose cp ext/mu-plugin/securecore-vault.php "php:$mu/securecore-vault.php" >/dev/null 2>&1
restore() {
  compose cp "$out/securecore.ini" "php:$ini" >/dev/null 2>&1
  compose exec -T php rm -f "$mu/securecore-vault.php"
  compose cp ext/examples/wordpress.json "php:$conf" >/dev/null 2>&1
  compose restart php >/dev/null 2>&1
  wait_200 || echo "php-fpm did not come back on examples/wordpress.json" >&2
}
trap restore EXIT
echo "# securecore.debug_db_attribution=$attr"

wp plugin install classic-editor wordpress-seo contact-form-7 --activate >/dev/null || { echo "plugin install failed" >&2; exit 1; }
wp plugin list --status=active --fields=name,version --format=csv > "$out/plugins.txt"
cat "$out/plugins.txt"
CF7_ID=$(wp post list --post_type=wpcf7_contact_form --field=ID | head -n 1)
CF7_PAGE=$(wp post list --post_type=page --name=db-cf7 --field=ID)
[ -n "$CF7_PAGE" ] || CF7_PAGE=$(wp post create --post_type=page --post_status=publish --post_name=db-cf7 \
  --post_title='DB CF7' --post_content="[contact-form-7 id=\"$CF7_ID\"]" --porcelain)

pages="front|/|no
dashboard|/wp-admin/|yes
writing-settings|/wp-admin/options-writing.php|yes
yoast-dashboard|/wp-admin/admin.php?page=wpseo_dashboard|yes
yoast-settings|/wp-admin/admin.php?page=wpseo_page_settings|yes
cf7-forms|/wp-admin/admin.php?page=wpcf7|yes
cf7-form-page|/?page_id=$CF7_PAGE|no"

# phase <name> <config>: put the config live (restart: a vault change needs one), sign in, load
# every page twice, submit the form; the window's layer2 database lines go to $out/<name>.raw.
phase() {
  compose cp "$2" "php:$conf" >/dev/null 2>&1
  compose restart php >/dev/null 2>&1
  wait_200 || { echo "php-fpm did not come back" >&2; exit 1; }
  : > "$J"
  curl -s -c "$J" -b "$J" -o /dev/null "$base/wp-login.php"
  curl -s -c "$J" -b "$J" -o /dev/null -d 'log=admin&pwd=securecore-demo&wp-submit=Log+In&testcookie=1' "$base/wp-login.php"
  curl -sL -b "$J" -c "$J" -o /dev/null "$base/wp-admin/"
  sleep 1; t=$(now); sleep 1
  echo "# $1: page status"
  for pass in 1 2; do
    echo "$pages" | while IFS='|' read -r name path auth; do
      set -- -s -o "$out/pages/$1-$name-$pass.html" -w '%{http_code}'
      [ "$auth" = yes ] && set -- "$@" -b "$J" -c "$J"
      echo "  pass $pass  $name  $path  -> $(curl "$@" "$base$path")"
    done
  done
  # A CF7 submission through its REST route (the form's own fields; the mail itself may fail on
  # this stack, which has no mailer: the status line says which).
  # ?rest_route=: the stack has no pretty permalinks, so /wp-json/ isn't routed.
  sub=$(curl -s -X POST "$base/?rest_route=/contact-form-7/v1/contact-forms/$CF7_ID/feedback" \
    -F "_wpcf7=$CF7_ID" -F "_wpcf7_unit_tag=wpcf7-f$CF7_ID-o1" -F "_wpcf7_container_post=$CF7_PAGE" \
    -F 'your-name=Probe' -F 'your-email=probe@example.com' -F 'your-subject=Hi' -F 'your-message=Hello')
  echo "$sub" > "$out/pages/$1-cf7-submit.json"
  echo "  cf7 submit -> $(jq -r '.status // "no status"' "$out/pages/$1-cf7-submit.json" 2>/dev/null || echo 'not JSON')"
  sleep 1
  compose logs --no-log-prefix --since "$t" php 2>&1 | sed -n 's/.*securecore: //p' \
    | grep -E '^layer2 (log|enforce) [^ ]+ (mysqli|pdo::)' > "$out/$1.raw" || true
  grep -iE 'PHP (Fatal|Warning)' "$out/pages/"*"$1"* >/dev/null 2>&1 && echo "  (a page printed a PHP fatal/warning)"
}

# 1. log mode, no database entries for the three.
jq '.layer2.mode = "log"' ext/examples/wordpress.json > "$out/log.json"
phase log "$out/log.json"
cargo run -q --manifest-path ext/Cargo.toml -p securecore-db --bin securecore-db-suggest -- --prefix wp_ "$out/log.raw" > "$out/suggested.json" \
  || { echo "securecore-db-suggest failed" >&2; exit 1; }
echo "# suggested entries (from $(grep -c . "$out/log.raw") log lines)"
cat "$out/suggested.json"

# 2. enforce mode with the generated entries merged into the example's components.
jq --slurpfile s "$out/suggested.json" '.layer2.mode = "enforce" | .layer2.components *= $s[0].components' \
  ext/examples/wordpress.json > "$out/enforce.json"
phase enforce "$out/enforce.json"

echo
echo "# enforce: $(grep -c . "$out/enforce.raw") refusal lines; grouped: count  component  route  rule  statement  tables"
awk '{ $1=""; $2=""; sub(/^  /,""); c[$0]++ } END { for (k in c) printf "%6d  %s\n", c[k], k }' "$out/enforce.raw" | sort -k2 > "$out/refusals.grouped"
cat "$out/refusals.grouped"
echo
echo "# core lines (unparseable / allowlist) in either phase"
grep -h ' core ' "$out/log.raw" "$out/enforce.raw" | awk '{ $1=""; c[$0]++ } END { for (k in c) printf "%6d %s\n", c[k], k }' || true

echo
echo "wrote $out/suggested.json, $out/refusals.grouped, $out/log.raw and $out/enforce.raw"
