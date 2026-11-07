#!/bin/sh
# Live canary for the database gateway's SQL policy (addiscorp/securecore#42, part 2), on the
# running docker/ stack with SECURECORE_REALWP + SECURECORE_PREBOOT. A sandboxed probe plugin
# (test/policy-plugin) tries reads and writes the policy must block and ones it must allow, and
# reports each to the worker log; this script checks them, and checks from outside the sandbox
# that blocked writes did not land. It runs the probe twice — with the policy on, then with it
# off (the vendored parser moved aside, so the gateway falls back to allowing everything) — so the
# block is shown to be the policy's doing, not an accident. Then it grants one door and shows it
# open, and runs the decide()-level unit assertions (test/policy-unit.php) for the destructive and
# structural refusals that cannot be run live without wrecking the stack.
#   DOCKER_CONTEXT=colima test/policy.sh
# Exits non-zero on any failure. Writes .tmp/policy/.
set -u
cd "$(dirname "$0")/.." || exit 1
base=http://127.0.0.1:8088
dir=.tmp/policy
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete 2>/dev/null
PROBE=securecore-policy/securecore-policy.php
FOREIGN=securecore_policy_foreign_secret
FSECRET=FOREIGN_SECRET_VALUE_9c4e
EVIL=securecore-policy-evil@example.com
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }

compose() { docker compose -f docker/compose.yml "$@"; }
wp() { compose run --rm -T cli wp "$@" 2>>"$dir/wp.err"; }
in_root() { compose exec -T php sh -c "$1"; }
plugindir=/var/www/html/wp-content/plugins/securecore

# shellcheck disable=SC2329  # invoked indirectly via trap EXIT
cleanup() {
  in_root "test -d $plugindir/vendor.off && mv $plugindir/vendor.off $plugindir/vendor" >/dev/null 2>&1
  compose restart php >/dev/null 2>&1
  wp option update admin_email admin@example.com >/dev/null 2>&1
  wp option delete "$FOREIGN" >/dev/null 2>&1
  in_root "grep -rl '\"plugin\": \"$PROBE\"' /var/www/html/wp-content/securecore/manifests/ 2>/dev/null | xargs -r rm -f" >/dev/null 2>&1
  compose run --rm -T cli wp --skip-plugins plugin deactivate securecore-policy >/dev/null 2>&1
  in_root "rm -rf $plugindir/../securecore-policy /var/www/html/wp-content/securecore/policy-unit.php" >/dev/null 2>&1
}
trap cleanup EXIT

# --- worker in real-WordPress pre-boot mode -------------------------------------------------------
wp config set SECURECORE_REALWP true --raw >/dev/null 2>&1 || true
wp config set SECURECORE_SOCKET /run/securecore/worker.sock >/dev/null 2>&1 || true
worker_up() {
  SECURECORE_REALWP=1 SECURECORE_PREBOOT=1 compose up -d --force-recreate worker >/dev/null 2>&1
  i=0; until compose logs --tail=5 worker 2>&1 | grep -q 'listening on'; do i=$((i + 1)); [ "$i" -lt 30 ] || break; sleep 1; done
}
wait_php() { i=0; until [ "$(curl -s -o /dev/null -w '%{http_code}' "$base/")" = 200 ]; do i=$((i + 1)); [ "$i" -lt 30 ] || break; sleep 1; done; }

# --- scenario: a foreign secret, and user 1's session + caps exist --------------------------------
wp option update "$FOREIGN" "$FSECRET" --autoload=yes >/dev/null
wp option update admin_email admin@example.com >/dev/null
wp eval 'update_user_meta(1, "session_tokens", array("probe" => array("expiration" => time() + 3600)));' >/dev/null 2>&1

# --- install + sandbox the probe ------------------------------------------------------------------
in_root "mkdir -p $plugindir/../securecore-policy"
compose cp test/policy-plugin/securecore-policy.php php:$plugindir/../securecore-policy/securecore-policy.php >/dev/null
in_root "chown -R www-data:www-data $plugindir/../securecore-policy"
wp plugin activate securecore-policy hello securecore-probe >/dev/null 2>&1
worker_up

login() {
  : > "$dir/cookies"
  curl -s -c "$dir/cookies" -b "$dir/cookies" -o /dev/null "$base/wp-login.php"
  curl -s -c "$dir/cookies" -b "$dir/cookies" -o /dev/null -d 'log=admin&pwd=securecore-demo&wp-submit=Log+In&testcookie=1' "$base/wp-login.php"
}
login
nonce=$(for _ in 1 2 3; do curl -s -b "$dir/cookies" -o "$dir/settings.html" "$base/wp-admin/options-general.php?page=securecore"; n=$(sed -n 's/.*name="_wpnonce" value="\([^"]*\)".*/\1/p' "$dir/settings.html" | head -n 1); [ -n "$n" ] && { echo "$n"; break; }; done)
set -- --data-urlencode "_wpnonce=$nonce" -d securecore_action=save
for p in hello.php securecore-probe/securecore-probe.php "$PROBE"; do set -- "$@" --data-urlencode "sandbox[]=$p"; done
curl -s -b "$dir/cookies" -o "$dir/saved.html" "$@" "$base/wp-admin/options-general.php?page=securecore"
if grep -q "Sandboxed: .*securecore-policy" "$dir/saved.html"; then pass "probe sandboxed (manifest generated)"; else fail "could not sandbox the probe"; cat "$dir/saved.html" | grep -o 'Saved[^<]*'; exit 1; fi
in_root "cat /var/www/html/wp-content/securecore/manifests/*.json" > "$dir/manifests.json" 2>/dev/null

# run_probe <tag>: load a page so the sandbox runs the probe, capture its log lines into $dir/<tag>.log
run_probe() {
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  curl -s -o /dev/null "$base/"
  sleep 1
  compose logs --since "$since" worker 2>&1 | grep 'POLICY_PROBE:' > "$dir/$1.log" || true
}
# obs <tag> <key>: the last reported value for a probe key
obs() { sed -n "s/.*POLICY_PROBE:$2=\(.*\)/\1/p" "$dir/$1.log" | tail -n 1; }

# --- phase 1: policy ON ---------------------------------------------------------------------------
echo "== policy ON =="
run_probe on
check_on() { v=$(obs on "$1"); if [ "$v" = "$2" ]; then pass "$3 ($1=$v)"; else fail "$3" "$1=$v want $2"; fi; }
check_on bulk_admin_email absent "core secret admin_email kept out of a bulk options read"
check_on bulk_foreign_secret absent "another plugin's secret kept out of a bulk options read"
check_on read_user_pass empty "wp_users.user_pass not readable"
check_on read_session_tokens empty "usermeta session_tokens not readable"
check_on read_caps empty "usermeta capabilities not readable without a grant"
check_on read_own_option own-ok "the plugin's own option is readable"
check_on read_siteurl nonempty "siteurl is readable (needed to render)"
if [ "$(obs on read_posts_count)" != denied ] && [ -n "$(obs on read_posts_count)" ]; then pass "core content (posts) is readable (count=$(obs on read_posts_count))"; else fail "core content readable" "read_posts_count=$(obs on read_posts_count)"; fi
if [ "$(wp option get admin_email)" = admin@example.com ]; then pass "a write to the protected option admin_email was blocked"; else fail "admin_email write blocked" "now $(wp option get admin_email)"; fi

# --- phase 2: policy OFF (parser moved aside) -----------------------------------------------------
echo "== policy OFF (parser disabled: the same probe should now leak) =="
in_root "mv $plugindir/vendor $plugindir/vendor.off" >/dev/null 2>&1
compose restart php >/dev/null 2>&1; wait_php
run_probe off
leak() { v=$(obs off "$1"); if [ "$v" = "$2" ]; then pass "without the policy, $3 ($1=$v)"; else fail "OFF: expected leak for $3" "$1=$v want $2"; fi; }
leak bulk_admin_email present "admin_email leaks into the bulk read"
leak bulk_foreign_secret present "the other plugin's secret leaks into the bulk read"
leak read_user_pass nonempty "user_pass is readable"
leak read_session_tokens nonempty "session_tokens is readable"
leak read_caps nonempty "capabilities are readable"
if [ "$(wp option get admin_email)" = "$EVIL" ]; then pass "without the policy, the admin_email write landed"; else fail "OFF: admin_email write should land" "now $(wp option get admin_email)"; fi
# restore
wp option update admin_email admin@example.com >/dev/null
in_root "mv $plugindir/vendor.off $plugindir/vendor" >/dev/null 2>&1
compose restart php >/dev/null 2>&1; wait_php

# --- phase 3: a grant opens exactly its door ------------------------------------------------------
echo "== grant usermeta:capabilities =="
mf=$(in_root "grep -rl '\"plugin\": \"$PROBE\"' /var/www/html/wp-content/securecore/manifests/ 2>/dev/null | head -n 1" | tr -d '\r')
if [ -n "$mf" ]; then
  in_root "php -r '\$f=\"$mf\"; \$m=json_decode(file_get_contents(\$f),true); \$m[\"db\"][\"grants\"]=[\"usermeta:capabilities\"]; file_put_contents(\$f, json_encode(\$m, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));'" >/dev/null 2>&1
  run_probe grant
  if [ "$(obs grant read_caps)" = nonempty ]; then pass "with the grant, capabilities are readable"; else fail "grant should allow capabilities" "read_caps=$(obs grant read_caps)"; fi
else
  fail "could not find the probe manifest to grant"
fi

# --- phase 4: decide()-level refusals that are unsafe to run live ---------------------------------
echo "== unit: destructive / structural refusals =="
compose cp test/policy-unit.php php:/var/www/html/wp-content/securecore/policy-unit.php >/dev/null
if compose run --rm -T cli wp eval-file wp-content/securecore/policy-unit.php > "$dir/unit.log" 2>&1; then
  pass "policy-unit.php: all decide() verdicts correct"
else
  fail "policy-unit.php" "$(grep -E '^FAIL|policy-unit:' "$dir/unit.log" | head -n 3 | tr '\n' ' ')"
fi

echo
[ "$fails" -eq 0 ] && echo "policy: PASS" || echo "policy: FAIL ($fails)"
exit "$fails"
