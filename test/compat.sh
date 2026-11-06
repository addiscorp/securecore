#!/bin/sh
# Does one wordpress.org plugin really work sandboxed? On the running docker/ stack:
#   1. install (or update to) the current wordpress.org version and activate it;
#   2. run its functional check with the plugin TRUSTED (in core): the baseline, which proves
#      the check sees the feature at all (a check that passes with the feature dead is useless);
#   3. switch it into the sandbox the way a user does (Settings → SecureCore → Save, which
#      generates its manifest from its code);
#   4. load the front page, the dashboard, the Plugins screen and its own admin screens:
#      each 200, no "critical error", and the page footer says the plugin ran sandboxed with
#      core including none of them;
#   5. run the same functional check sandboxed;
#   6. the logs: no audit denials / sandbox failures / PHP messages from the sandbox for this
#      plugin, and nothing new in wp-content/debug.log (core-side PHP warnings);
#   7. test/site.sh still passes with it active and sandboxed;
#   8. switch it out of the sandbox and deactivate it again.
# Exits non-zero if it does not work sandboxed. Writes .tmp/compat/<slug>/ (pages, logs) and
# one line to .tmp/compat/results.tsv: slug, version, result, failed checks.
#   DOCKER_CONTEXT=colima test/compat.sh <slug>
# Setup the checks need (WooCommerce, a product, the mail catcher) is done by
# test/compat-all.sh; run that once first.
set -u
cd "$(dirname "$0")/.." || exit 1
slug=${1:?usage: test/compat.sh <wordpress.org plugin slug>}
base=http://127.0.0.1:8088
dir=.tmp/compat/$slug
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete
compose() { docker compose -f docker/compose.yml "$@"; }
# wp-cli, keeping its exit status (a pipe into tr would hide it).
wp() {
  compose run --rm -T cli wp "$@" > "$dir/wp.out" 2>>"$dir/wp-cli.err"; wp_rc=$?
  tr -d '\r' < "$dir/wp.out"; return "$wp_rc"
}
in_php() { compose exec -T -u www-data php sh -c "$1"; }
fails=0
failed=
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); failed="${failed:+$failed; }$1"; }
note() { echo "note $1"; }
J=$dir/cookies
BASE_SANDBOX="hello.php securecore-probe/securecore-probe.php"

# --- the plugin ------------------------------------------------------------------------------
wp plugin install "$slug" --force >/dev/null || { echo "FAIL install $slug from wordpress.org"; exit 1; }
wp plugin activate "$slug" >/dev/null
main=$(wp plugin list --name="$slug" --field=file)
version=$(wp plugin list --name="$slug" --field=version)
status=$(wp plugin list --name="$slug" --field=status)
[ "$status" = active ] || { echo "FAIL $slug did not activate (status $status)"; exit 1; }
echo "== $slug $version ($main)"
# However this ends, the plugin leaves the sandbox and is deactivated (--skip-plugins, so a
# plugin that breaks wp-cli can still be switched off), so the next run starts clean.
cleanup() {
  in_php "grep -l '\"plugin\": \"$main\"' wp-content/securecore/manifests/*.json 2>/dev/null | xargs -r rm -f"
  compose run --rm -T cli wp --skip-plugins plugin deactivate "$slug" >/dev/null 2>&1
}
trap cleanup EXIT
wp plugin get "$slug" --field=title >/dev/null
# The page's icon: wordpress.org's plugins API, "icons" (prefer the SVG, then 2x, then 1x).
curl -fsS "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D=$slug&request%5Bfields%5D%5Bicons%5D=1" -o "$dir/info.json" || true
icon=$(sed -n 's/.*"icons":{\([^}]*\)}.*/\1/p' "$dir/info.json" | tr ',' '\n' | sed -nE 's/"(svg|2x|1x)":"([^"]*)"/\1 \2/p' | sed 's#\\/#/#g' | sort -k1,1r | awk '{print $2}' | head -n 1)

login() {
  : > "$J"
  curl -s -c "$J" -b "$J" -o /dev/null "$base/wp-login.php"
  curl -s -c "$J" -b "$J" -o /dev/null -d 'log=admin&pwd=securecore-demo&wp-submit=Log+In&testcookie=1' "$base/wp-login.php"
}
nonce_of() { sed -n 's/.*name="_wpnonce" value="\([^"]*\)".*/\1/p' "$1" | head -n 1; }
# sandbox_set <plugin files>: Settings → SecureCore → tick exactly these (plus the probe,
# which the screen doesn't list) → Save.
sandbox_set() {
  # A plugin's first admin page view after activation may be its welcome-screen redirect.
  for _ in 1 2 3; do
    curl -s -b "$J" -c "$J" -o "$dir/settings.html" "$base/wp-admin/options-general.php?page=securecore"
    [ -n "$(nonce_of "$dir/settings.html")" ] && break
  done
  set -- --data-urlencode "_wpnonce=$(nonce_of "$dir/settings.html")" -d securecore_action=save
  for p in $BASE_SANDBOX $want; do set -- "$@" --data-urlencode "sandbox[]=$p"; done
  curl -s -b "$J" -o "$dir/saved.html" "$@" "$base/wp-admin/options-general.php?page=securecore"
  grep -q 'Saved. Sandboxed:' "$dir/saved.html"
}
# get <name> <path>: fetch as the logged-in admin; sets $code; page in $dir/<name>.html.
get() { code=$(curl -sL -b "$J" -c "$J" -o "$dir/$1.html" -w '%{http_code}' "$base/$2"); }
# The footer comment SecureCore prints: which plugins ran sandboxed, and that core included none.
sandboxed_here() { grep -q "securecore: sandboxed [^;]*$main" "$dir/$1.html" && grep -q 'included by core: none -->' "$dir/$1.html"; }
page_ok() { [ "$code" = 200 ] && ! grep -qi 'critical error' "$dir/$1.html"; }

# --- per plugin: its admin screens and one real check of its main feature ---------------------
# check_<slug> <phase> runs with the plugin trusted (phase=core) and sandboxed (phase=sandbox),
# returns 0 when the feature works, and leaves evidence in $dir. NEEDS: what the main feature
# needs that this stack doesn't have (an account, a service); then only the generic checks run.
ADMIN=
NEEDS=
CHECK="the plugin's main feature"
mail_count() { in_php 'cat wp-content/securecore-mail.log 2>/dev/null' | grep -c '^To:'; }
rest_nonce() { curl -s -b "$J" "$base/wp-admin/admin-ajax.php?action=rest-nonce"; }
case $slug in
  wordpress-seo)
    ADMIN="admin.php?page=wpseo_dashboard"
    CHECK="writes its SEO meta into a post's page (canonical, og:title, schema graph)"
    check() { get "post-$1" "?p=$POST_ID"; page_ok "post-$1" && grep -q 'This site is optimized with the Yoast SEO plugin' "$dir/post-$1.html" && grep -q '<link rel="canonical"' "$dir/post-$1.html" && grep -q 'property="og:title"' "$dir/post-$1.html" && grep -q 'yoast-schema-graph' "$dir/post-$1.html"; } ;;
  all-in-one-seo-pack)
    ADMIN="admin.php?page=aioseo"
    CHECK="writes its SEO meta into a post's page (canonical, og:title, schema graph)"
    check() { get "post-$1" "?p=$POST_ID"; page_ok "post-$1" && grep -q 'All in One SEO' "$dir/post-$1.html" && grep -q '<link rel="canonical"' "$dir/post-$1.html" && grep -q 'property="og:title"' "$dir/post-$1.html" && grep -q 'aioseo-schema' "$dir/post-$1.html"; } ;;
  contact-form-7)
    ADMIN="admin.php?page=wpcf7"
    CHECK="a visitor submits its contact form and the email is sent with the message"
    check() {
      before=$(mail_count)
      get "form-$1" "?page_id=$CF7_PAGE"
      page_ok "form-$1" && grep -q 'class="wpcf7-form' "$dir/form-$1.html" || return 1
      unit=$(sed -n 's/.*name="_wpcf7_unit_tag" value="\([^"]*\)".*/\1/p' "$dir/form-$1.html" | head -n 1)
      curl -s -o "$dir/submit-$1.json" -F "_wpcf7=$CF7_ID" -F "_wpcf7_unit_tag=$unit" -F "_wpcf7_locale=en_US" -F "_wpcf7_version=$version" \
        -F "your-name=Compat $1" -F "your-email=visitor@example.com" -F "your-subject=Hello" -F "your-message=compat-$1-message" \
        "$base/wp-json/contact-form-7/v1/contact-forms/$CF7_ID/feedback"
      grep -q '"status":"mail_sent"' "$dir/submit-$1.json" && [ "$(mail_count)" -gt "$before" ] && in_php 'cat wp-content/securecore-mail.log' | grep -q "compat-$1-message"
    } ;;
  classic-editor)
    CHECK="Posts → Add New opens the classic editor, not the block editor"
    check() { get "new-$1" "wp-admin/post-new.php"; page_ok "new-$1" && grep -q 'id="postdivrich"' "$dir/new-$1.html" && grep -q 'id="wp-content-editor-container"' "$dir/new-$1.html"; } ;;
  akismet)
    ADMIN="options-general.php?page=akismet-key-config"
    NEEDS="an Akismet API key (an akismet.com account) to check comments for spam"
    CHECK="its settings screen asks for the API key" ;;
  wpforms-lite)
    ADMIN="admin.php?page=wpforms-overview"
    CHECK="its form renders on a page from the [wpforms] shortcode"
    check() { get "form-$1" "?page_id=$WPF_PAGE"; page_ok "form-$1" && grep -q "id=\"wpforms-form-$WPF_ID\"" "$dir/form-$1.html"; } ;;
  jetpack)
    ADMIN="admin.php?page=jetpack"
    NEEDS="a WordPress.com account (Jetpack's features run through its connection)"
    CHECK="its dashboard screen loads and offers to connect" ;;
  google-site-kit)
    ADMIN="admin.php?page=googlesitekit-splash"
    NEEDS="a Google account (Site Kit shows data from Google services)"
    CHECK="its setup screen loads" ;;
  updraftplus)
    ADMIN="options-general.php?page=updraftplus"
    NEEDS="a long-running backup job driven by WP-Cron and its own job runner (checked: settings screen only)"
    CHECK="its backup screen loads" ;;
  litespeed-cache)
    ADMIN="admin.php?page=litespeed"
    NEEDS="a LiteSpeed web server (its page cache is served by the server; this stack is nginx)"
    CHECK="its dashboard loads" ;;
  wp-mail-smtp)
    ADMIN="admin.php?page=wp-mail-smtp"
    CHECK="its Email Test tool sends a test email"
    check() {
      before=$(mail_count)
      get "tools-$1" "wp-admin/admin.php?page=wp-mail-smtp-tools&tab=test"
      page_ok "tools-$1" || return 1
      n=$(sed -n 's/.*name="wp-mail-smtp-tools-tests-nonce" value="\([^"]*\)".*/\1/p' "$dir/tools-$1.html" | head -n 1)
      [ -n "$n" ] || n=$(nonce_of "$dir/tools-$1.html")
      curl -s -b "$J" -o "$dir/sent-$1.html" --data-urlencode "wp-mail-smtp-tools-tests-nonce=$n" --data-urlencode "_wpnonce=$n" \
        -d 'wp-mail-smtp[test][email]=compat@example.com&wp-mail-smtp[test][html]=no&wp-mail-smtp-post=1' \
        "$base/wp-admin/admin.php?page=wp-mail-smtp-tools&tab=test"
      [ "$(mail_count)" -gt "$before" ] && in_php 'cat wp-content/securecore-mail.log' | tail -n 20 | grep -q 'To: compat@example.com'
    } ;;
  really-simple-ssl)
    ADMIN="options-general.php?page=really-simple-security"
    NEEDS="HTTPS (it moves a site to https; this stack is plain http)"
    CHECK="its settings screen loads" ;;
  wordfence)
    ADMIN="admin.php?page=Wordfence"
    CHECK="its firewall blocks an IP you block (Wordfence → Blocking), with its block page"
    check() {
      code=$(curl -s -o "$dir/blocked-$1.html" -w '%{http_code}' -H 'X-Forwarded-For: 203.0.113.9' "$base/?compat=$1")
      [ "$code" = 503 ] && grep -qi 'wordfence' "$dir/blocked-$1.html"
    } ;;
  redirection)
    ADMIN="tools.php?page=redirection.php"
    CHECK="a redirect added in it sends the visitor to the target (301)"
    check() {
      src="/compat-old-$1"
      n=$(rest_nonce)
      curl -s -b "$J" -o "$dir/add-$1.json" -H "X-WP-Nonce: $n" -H 'Content-Type: application/json' \
        -d "{\"url\":\"$src\",\"action_data\":{\"url\":\"/compat-new-$1\"},\"action_type\":\"url\",\"match_type\":\"url\",\"group_id\":1,\"action_code\":301}" \
        "$base/wp-json/redirection/v1/redirect"
      loc=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "$base$src")
      echo "$loc" > "$dir/redirect-$1.txt"
      [ "${loc%% *}" = 301 ] && case $loc in *"/compat-new-$1") true ;; *) false ;; esac
    } ;;
  elementor)
    ADMIN="admin.php?page=elementor"
    CHECK="a page built with Elementor (a heading widget) renders with Elementor's markup"
    check() { get "page-$1" "?page_id=$EL_PAGE"; page_ok "page-$1" && grep -q 'elementor-widget-heading' "$dir/page-$1.html" && grep -q 'compat-elementor-heading' "$dir/page-$1.html"; } ;;
  woo-store-vacation)
    ADMIN="admin.php?page=woo-store-vacation"
    CHECK="vacation mode on: the shop shows its notice"
    check() { code=$(curl -s -o "$dir/shop-$1.html" -w '%{http_code}' "$base/shop/"); [ "$code" = 200 ] && grep -q 'compat-vacation-notice' "$dir/shop-$1.html"; } ;;
  *)
    NEEDS="no functional check written for this plugin" ;;
esac
command -v check >/dev/null 2>&1 || NEEDS=${NEEDS:-"no functional check"}

# Fixtures a check needs, made with the plugin trusted (wp-cli always runs plugins in core).
POST_ID=$(wp post list --post_type=post --name=compat-post --field=ID)
[ -n "$POST_ID" ] || POST_ID=$(wp post create --post_type=post --post_status=publish --post_name=compat-post --post_title='Compat post' --post_content='A post for the compatibility checks.' --porcelain)
case $slug in
  contact-form-7)
    CF7_ID=$(wp post list --post_type=wpcf7_contact_form --field=ID | head -n 1)
    CF7_PAGE=$(wp post create --post_type=page --post_status=publish --post_title='Compat CF7' --post_content="[contact-form-7 id=\"$CF7_ID\"]" --porcelain) ;;
  wpforms-lite)
    WPF_ID=$(wp post create --post_type=wpforms --post_status=publish --post_title='Compat form' --porcelain)
    wp post update "$WPF_ID" --post_content="{\"id\":\"$WPF_ID\",\"field_id\":2,\"fields\":{\"1\":{\"id\":\"1\",\"type\":\"text\",\"label\":\"Name\"}},\"settings\":{\"form_title\":\"Compat form\"}}" >/dev/null
    WPF_PAGE=$(wp post create --post_type=page --post_status=publish --post_title='Compat WPForms' --post_content="[wpforms id=\"$WPF_ID\"]" --porcelain) ;;
  elementor)
    EL_PAGE=$(wp post create --post_type=page --post_status=publish --post_title='Compat Elementor' --porcelain)
    wp post meta update "$EL_PAGE" _elementor_edit_mode builder >/dev/null
    wp post meta update "$EL_PAGE" _elementor_data '[{"id":"a1","elType":"section","settings":[],"elements":[{"id":"b1","elType":"column","settings":{"_column_size":100},"elements":[{"id":"c1","elType":"widget","widgetType":"heading","settings":{"title":"compat-elementor-heading"},"elements":[]}]}]}]' >/dev/null ;;
  wordfence)
    # Block one IP the way Wordfence → Blocking does, and trust X-Forwarded-For (behind nginx).
    wp eval 'wfConfig::set("howGetIPs", "HTTP_X_FORWARDED_FOR"); wfBlock::createIP("compat", "203.0.113.9", wfBlock::DURATION_FOREVER);' >/dev/null ;;
  woo-store-vacation)
    wp option update woo_store_vacation_options '{"vacation_mode":"1","disable_purchase":"1","start_date":"2020-01-01","end_date":"2099-12-31","notice":"compat-vacation-notice"}' --format=json >/dev/null ;;
esac

login
want=
sandbox_set || { echo "FAIL could not reset Settings → SecureCore"; exit 1; }

# --- 2. baseline: trusted ----------------------------------------------------------------------
if [ -z "$NEEDS" ]; then
  if check core; then pass "baseline, trusted: $CHECK"; else
    # The check doesn't see the feature even in core, so it can't judge the sandbox: skip it,
    # still run the generic checks, and never report this plugin as working.
    fail "baseline, trusted: $CHECK (the check itself does not see the feature)"
    NEEDS="a working check (its baseline failed with the plugin trusted)"
  fi
fi

# --- 3. sandbox it -------------------------------------------------------------------------------
in_php ': > wp-content/securecore-audit.log; : > wp-content/debug.log'
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
want=$main
if sandbox_set && grep -q "Sandboxed: .*$main" "$dir/saved.html"; then pass "switched into the sandbox (manifest generated)"; else fail "switch into the sandbox"; fi
in_php "cat wp-content/securecore/manifests/*.json" > "$dir/manifests.json" 2>/dev/null
[ "$(compose exec -T worker sh -c 'test -S /run/securecore/worker.sock && echo up')" = up ] || fail "worker is running"

# --- 4. its pages ---------------------------------------------------------------------------------
for spec in "front:" "dashboard:wp-admin/" "plugins:wp-admin/plugins.php" ${ADMIN:+"admin:wp-admin/$ADMIN"}; do
  name=${spec%%:*}; path=${spec#*:}
  get "$name" "$path"
  if page_ok "$name"; then pass "$name loads (200)"; else fail "$name loads" "HTTP $code"; fi
  if sandboxed_here "$name"; then pass "$name: ran sandboxed, core included none"; else fail "$name: ran sandboxed" "footer: $(grep -o 'securecore: sandboxed[^>]*' "$dir/$name.html" | head -n 1)"; fi
done
if grep -q "id=\"deactivate-$slug\"" "$dir/plugins.html"; then pass "Plugins screen lists it active"; else fail "Plugins screen lists it active"; fi

# --- 5. the feature, sandboxed ------------------------------------------------------------------
if [ -z "$NEEDS" ]; then
  if check sandbox; then pass "sandboxed: $CHECK"; else fail "sandboxed: $CHECK"; fi
else
  note "main feature not checked: needs $NEEDS"
fi

# --- 6. logs ----------------------------------------------------------------------------------------
in_php 'cat wp-content/securecore-audit.log' > "$dir/audit.log"
in_php 'cat wp-content/debug.log' > "$dir/debug.log"
compose logs --no-log-prefix --since "$since" worker > "$dir/worker.log" 2>&1
grep -F "\"plugin\":\"$main\"" "$dir/audit.log" | grep -E '"event":"(wp\.deny|hook\.deny|sandbox\.(fail|throw|exit|timeout|log))"' > "$dir/problems.log"
n=$(wc -l < "$dir/problems.log" | tr -d ' ')
if [ "$n" = 0 ]; then pass "audit log: no denials, failures or PHP messages from it"; else
  fail "audit log clean" "$n problem lines; first: $(head -n 1 "$dir/problems.log" | cut -c1-300)"
fi
if [ -s "$dir/debug.log" ]; then fail "no PHP messages in debug.log" "$(head -n 1 "$dir/debug.log" | cut -c1-300)"; else pass "debug.log: no PHP messages"; fi
if grep -qiE 'fatal|warning|php:' "$dir/worker.log"; then fail "worker log clean" "$(grep -iE 'fatal|warning|php:' "$dir/worker.log" | head -n 1 | cut -c1-300)"; else pass "worker log: nothing new"; fi

# --- 7. the stack's own checks ------------------------------------------------------------------------
if test/site.sh > "$dir/site.log" 2>&1; then pass "test/site.sh passes with it sandboxed"; else fail "test/site.sh" "$(grep FAIL "$dir/site.log" | head -n 1)"; fi

# --- 8. back out --------------------------------------------------------------------------------------
want=
sandbox_set >/dev/null || note "could not switch it out of the sandbox"
wp plugin deactivate "$slug" >/dev/null

if [ "$fails" = 0 ] && [ -z "$NEEDS" ]; then result=yes
elif [ "$fails" = 0 ]; then result=partly
else result=no; fi
printf '%s\t%s\t%s\t%s\t%s\n' "$slug" "$version" "$result" "${failed:-${NEEDS:+main feature not checked: needs $NEEDS}}" "$icon" >> .tmp/compat/results.tsv
echo "== $slug $version: $result${failed:+ — $failed}"
[ "$fails" = 0 ]
