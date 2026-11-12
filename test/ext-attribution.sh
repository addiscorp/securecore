#!/bin/sh
# E2a integration tests for attribution (addiscorp/securecore#53): on the extension stack that
# test/ext-config.sh leaves up (compose project securecore-ext, port 8089), with fixture plugins
# that open files in known ways (test/ext/attr-*):
#   1. logging is off by default: no attribution lines, and who-is-running still answers
#      (securecore_status()['caller']);
#   2. securecore.debug_attribution_log=both: one line per open per rule, with the component
#      each rule charges. The cases that tell the rules apart: a plugin asking a core API that
#      opens the file (rule frame: core; rule component: the plugin), and securecore_status()
#      reached through core's apply_filters();
#   3. the map: a plugin's own include, a mu-plugin's callback, a plugin symlinked in from
#      outside the plugins folder, core including plugin and mu-plugin files;
#   4. securecore.debug_attribution_rule picks the rule who-is-running uses;
#   5. layer2 mode off records nothing; an invalid debug value refuses to start.
# Exits non-zero on any failure. Writes .tmp/ext-attribution/. Leaves the stack as it found it
# (examples/wordpress.json, no debug ini, fixtures removed).
# On the microVM target (SC_TARGET=microvm, test/lib/target.sh) everything runs in the guest: the
# debug settings are the launcher's --guest-ini file, delivered to the running guest (#90).
#   DOCKER_CONTEXT=colima test/ext-config.sh && DOCKER_CONTEXT=colima test/ext-attribution.sh
set -u
cd "$(dirname "$0")/.." || exit 1
project=${SECURECORE_EXT_PROJECT:-securecore-ext}
port=${SECURECORE_EXT_PORT:-8089}
dir=.tmp/ext-attribution
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete 2>/dev/null
. test/lib/target.sh
content=$html/wp-content
data=$content/uploads/sc-attr
plugin=$content/plugins/securecore-attr
shared=$content/sc-attr-shared/securecore-attr-linked
ini=/usr/local/etc/php/conf.d/securecore-debug.ini
fails=0
# (n/a while NA_WHY is set: the checks that need a debug ini on the microVM.)
pass() { na_now "$1" && return; echo "ok   $1"; }
fail() { na_now "$1" && return; echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }
is() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3" "got '$1', want '$2'"; fi; }
wp() { compose run --rm -T cli wp "$@" 2>>"$dir/wp.err"; }
in_php() { compose exec -T php sh -c "$1"; }
case_() { curl -s "$base/?sc_attr=$1"; }
status() { curl -s "$base/securecore-status.php" > "$dir/status"; }
field() { sed -n "s/^$1=//p" "$dir/status"; }
# The attribution lines php-fpm logged since <mark>, without the prefix: "<rule> <component> <op> <path>".
attr() { phplog "$1" | sed -n 's/.*securecore: attribution //p'; }
# has <since> <line> <label>
has() { if attr "$1" | grep -qxF "$2"; then pass "$3"; else fail "$3" "no line '$2'"; fi; }
# debug <ini lines>: write the debug ini (empty: remove it) and restart php-fpm. On the microVM
# the site's php.ini settings are the launcher's --guest-ini file: it delivers them to the running
# guest and starts its php-fpm again gracefully (#90); this waits for that, or for the launcher
# to stop (a value the extension refuses stops the guest's php-fpm, as on a host).
debug() {
  if on_microvm; then
    _m=$(now)
    # Nothing changes: nothing to deliver (and nothing to wait for).
    if [ -z "$1" ]; then
      [ -e "$tdir/guest.ini" ] || return 0
      rm -f "$tdir/guest.ini"
    else
      [ "$(cat "$tdir/guest.ini" 2>/dev/null)" != "$1" ] || return 0
      printf '%s\n' "$1" > "$tdir/guest.ini"
    fi
    _i=0
    until phplog "$_m" | grep -q "delivered the site's php.ini settings\|the guest refused them\|Firecracker exited"; do
      launcher_alive || return 0
      _i=$((_i + 1)); [ "$_i" -lt 600 ] || { echo "  the launcher did not deliver the php.ini settings in 60 s"; return 0; }
      sleep 0.1
    done
    return 0
  fi
  if [ -z "$1" ]; then in_php "rm -f $ini"; else printf '%s\n' "$1" | compose exec -T php sh -c "cat > $ini"; fi
  compose restart php >/dev/null 2>&1
}

stack_is_up

# --- fixtures --------------------------------------------------------------------------------
sed 's/"mode": "enforce"/"mode": "log"/' ext/examples/wordpress.json > "$dir/log.json"
sed 's/"mode": "enforce"/"mode": "off"/' ext/examples/wordpress.json > "$dir/off-mode.json"
put_live "$dir/log.json"
in_php "rm -rf $plugin $shared $content/plugins/securecore-attr-linked && mkdir -p $content/mu-plugins $data $(dirname "$shared")"
compose cp test/ext/attr-plugin "php:$plugin" >>"$dir/cp.log" 2>&1
compose cp test/ext/attr-linked "php:$shared" >>"$dir/cp.log" 2>&1
compose cp test/ext/attr-mu.php "php:$content/mu-plugins/securecore-attr-mu.php" >>"$dir/cp.log" 2>&1
# A plugin symlinked in from outside the plugins folder: PHP reports its files by real path.
in_php "ln -s $shared $content/plugins/securecore-attr-linked"
in_php "printf 'direct\n' > $data/direct.txt; printf '<?php\n/* Name: core-api */\n' > $data/core-api.txt; printf 'mu\n' > $data/mu.txt; printf 'linked\n' > $data/linked.txt; chown -R www-data:www-data $content"
wp plugin activate securecore-attr securecore-attr-linked >/dev/null
theme=$(wp option get stylesheet | tr -d '\r')
cleanup() {
  wp plugin deactivate securecore-attr securecore-attr-linked >/dev/null
  in_php "rm -rf $plugin $content/plugins/securecore-attr-linked $(dirname "$shared") $content/mu-plugins/securecore-attr-mu.php $data $ini"
  put ext/examples/wordpress.json
  ! on_microvm || rm -f "$tdir/guest.ini"
  php_restart >/dev/null 2>&1
  wait_200 || echo "FAIL php-fpm did not come back after cleanup"
}
trap cleanup EXIT
# The fixtures reach the guest at its next start (microvm; nothing on docker).
site_sync
debug ""
wait_200 || { echo "FAIL php-fpm did not start"; exit 1; }

# --- 1. off by default -----------------------------------------------------------------------
status
is "$(field attribution_log)/$(field attribution_rule)" off/component "defaults: logging off, rule component"
is "$(field caller)" core "who is running, from a core file (securecore-status.php): core"
t=$(now); sleep 1
is "$(case_ direct)" direct "the fixture plugin reads its file"
is "$(case_ status)" plugin:securecore-attr "who is running, from the plugin: plugin:securecore-attr (no logging needed)"
is "$(case_ status-via-core)" plugin:securecore-attr "who is running, plugin → core apply_filters → securecore_status: the plugin (rule component)"
sleep 1
is "$(attr "$t" | grep -c .)" 0 "logging off: no attribution lines at all"

# --- 2. both rules logged --------------------------------------------------------------------
debug "securecore.debug_attribution_log=both"
wait_200 || fail "php-fpm starts with logging on"
status
is "$(field attribution_log)" both "status: attribution_log both"
t=$(now); sleep 1
for c in direct core-api include write filter linked; do case_ "$c" > "$dir/case-$c.txt"; done
sleep 1
attr "$t" > "$dir/lines.txt"
for rule in frame component; do
  has "$t" "$rule plugin:securecore-attr file_get_contents $data/direct.txt" "$rule: the plugin opening a file itself is the plugin"
  has "$t" "$rule plugin:securecore-attr require_once $plugin/inc/own.php" "$rule: the plugin including its own file is the plugin"
  has "$t" "$rule plugin:securecore-attr file_put_contents $data/written.txt" "$rule: file_put_contents is recorded as the plugin's write"
  has "$t" "$rule plugin:securecore-attr fopen:wb $data/fopen-w.txt" "$rule: fopen records its mode (wb)"
  has "$t" "$rule mu-plugin:securecore-attr-mu file_get_contents $data/mu.txt" "$rule: a mu-plugin's callback is the mu-plugin"
  has "$t" "$rule plugin:securecore-attr-linked file_get_contents $data/linked.txt" "$rule: a symlinked plugin is still itself (real path $shared)"
  has "$t" "$rule core include_once $plugin/securecore-attr.php" "$rule: core including a plugin's main file is core"
  has "$t" "$rule core include_once $shared/securecore-attr-linked.php" "$rule: core including the symlinked plugin, by its real path"
  has "$t" "$rule core include_once $content/mu-plugins/securecore-attr-mu.php" "$rule: core including a mu-plugin is core"
  has "$t" "$rule core include $content/themes/$theme/functions.php" "$rule: core including the theme's functions.php is core"
done
# The central question: a plugin asks core to open the file.
has "$t" "frame core file_get_contents $data/core-api.txt" "rule frame: plugin → core get_file_data() → the open is charged to core"
has "$t" "component plugin:securecore-attr file_get_contents $data/core-api.txt" "rule component: plugin → core get_file_data() → the open is charged to the plugin"
is "$(grep -c '^frame ' "$dir/lines.txt")" "$(grep -c '^component ' "$dir/lines.txt")" "one line per open for each rule"
is "$(grep -c ' php://\| https\?://' "$dir/lines.txt")" 0 "only plain files are recorded"

# --- 3. the rule setting ---------------------------------------------------------------------
debug "securecore.debug_attribution_rule=frame"
wait_200 || fail "php-fpm starts with rule frame"
status
is "$(field attribution_rule)/$(field attribution_log)" frame/off "status: rule frame, logging off"
is "$(case_ status-via-core)" core "rule frame: plugin → core apply_filters → securecore_status: core"
is "$(case_ status)" plugin:securecore-attr "rule frame: called from the plugin's own code: the plugin"

# --- 4. mode off records nothing; invalid values refuse to start ------------------------------
debug "securecore.debug_attribution_log=component"
wait_200 || fail "php-fpm starts with logging component"
put_live "$dir/off-mode.json"
sleep 1.2
t=$(now); sleep 1
case_ direct >/dev/null; case_ direct >/dev/null
sleep 1
is "$(attr "$t" | grep -c .)" 0 "layer2 mode off: nothing recorded"
put_live "$dir/log.json"
sleep 1.2
t=$(now); sleep 1
case_ core-api >/dev/null
sleep 1
has "$t" "component plugin:securecore-attr file_get_contents $data/core-api.txt" "back to log mode: recorded again (one rule: component)"
is "$(attr "$t" | grep -c '^frame ')" 0 "logging component: no frame lines"

since=$(now)
# (Not "yes": PHP's ini parser turns yes/on/true into "1" before the extension sees it.)
debug "securecore.debug_attribution_log=everything"
if [ -z "$NA_WHY" ] && wait_exited; then pass "invalid debug_attribution_log: php-fpm refuses to start"; else fail "invalid debug_attribution_log: php-fpm refuses to start" "$(php_state)"; fi
if phplog "$since" | grep -qF 'securecore: securecore.debug_attribution_log = "everything": expected off, frame, component or both; refusing to start'; then
  pass "invalid debug_attribution_log: the log says why"
else
  fail "invalid debug_attribution_log: the log says why"
fi
in_php_stopped() { compose cp "$1" "php:$2" >>"$dir/cp.log" 2>&1; }
printf '' > "$dir/empty.ini"
if on_microvm; then cp "$dir/empty.ini" "$tdir/guest.ini"; else in_php_stopped "$dir/empty.ini" "$ini"; fi
php_start
if wait_200; then pass "fixed: php-fpm starts again"; else fail "fixed: php-fpm starts again"; fi
NA_WHY=

echo
na_summary
if [ "$fails" -eq 0 ]; then echo "all ext-attribution checks passed"; else echo "$fails check(s) failed"; fi
[ "$fails" -eq 0 ]
