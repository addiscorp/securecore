#!/bin/sh
# E1 integration tests for the SecureCore extension (addiscorp/securecore#53): WordPress on
# php-fpm with securecore.so loaded (docker/compose.ext.yml), as its own compose project on
# port 8089 so it runs beside the worker stack on 8088.
#   1. a valid config → the front page is 200 and securecore_status() in php-fpm reports the
#      file's sha256, layers and mode;
#   2. the config edited in place → every php-fpm worker reports the new file within the
#      reload interval, with no restart (same master pid and container start time); a layer1
#      edit is flagged restart_needed;
#   3. an invalid edit while running → the last valid config stays live, reload_error names
#      the file and the problem;
#   4. php-fpm (re)started with an invalid, a missing or no config → it refuses to start, and
#      its log names the file and the problem; a fixed file starts it again.
# Exits non-zero on any failure. Writes .tmp/ext-config/. Leaves the stack up on a valid config.
#   DOCKER_CONTEXT=colima test/ext-config.sh
set -u
cd "$(dirname "$0")/.." || exit 1
port=8089
base=http://127.0.0.1:$port
dir=.tmp/ext-config
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete 2>/dev/null
# At the site root, as in a real install: the root is the folder containing it.
conf=/var/www/html/securecore.json
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }
# is <actual> <expected> <label>
is() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3" "got '$1', want '$2'"; fi; }
compose() { SECURECORE_PORT=$port docker compose -f docker/compose.yml -f docker/compose.ext.yml -p securecore-ext "$@"; }
wp() { compose run --rm -T cli wp "$@" 2>>"$dir/wp.err"; }
cp_in() { compose cp "$1" "php:$2" >>"$dir/cp.log" 2>&1; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
code() { curl -s -o /dev/null -w '%{http_code}' "$base$1"; }
# status → key=value lines from the php-fpm worker that serves the request.
status() { curl -s "$base/securecore-status.php" > "$dir/status"; }
field() { sed -n "s/^$1=//p" "$dir/status"; }
layers() { echo "$(field layer1)$(field layer2)$(field layer3)"; }
php_state() { docker inspect -f '{{.State.Status}} {{.State.StartedAt}}' "$(compose ps -aq php)"; }
# phplog <since>: php-fpm's log from <since> on (earlier runs' lines are in the log too).
phplog() { compose logs --no-log-prefix --since "$1" php 2>&1; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
master_pid() { compose exec -T php sh -c 'cut -d" " -f1,22 /proc/1/stat'; }
# Replace the config in the running container atomically (write + rename, like an editor).
put_live() { compose exec -T php sh -c "cat > $conf.new && mv $conf.new $conf" < "$1"; }
# Replace it whether or not php-fpm is running (docker cp works on a stopped container).
put() { cp_in "$1" "$conf"; }
wait_200() { i=0; until [ "$(code /)" = 200 ]; do i=$((i + 1)); [ "$i" -lt 60 ] || return 1; sleep 1; done; }
wait_exited() { i=0; until php_state | grep -q '^exited'; do i=$((i + 1)); [ "$i" -lt 30 ] || return 1; sleep 1; done; }
# > RELOAD_INTERVAL (1000 ms): every worker re-checks the file on its next request.
wait_reload() { sleep 1.2; }

# --- stack -----------------------------------------------------------------------------------
echo "building and starting the extension stack (project securecore-ext, $base)"
compose build php > "$dir/build.log" 2>&1 || { echo "FAIL docker build (see $dir/build.log)"; exit 1; }
compose up -d db php web > "$dir/up.log" 2>&1 || { echo "FAIL compose up (see $dir/up.log)"; exit 1; }
# On a new site volume the image's entrypoint first copies WordPress (and off.json as
# securecore.json) into it, then starts php-fpm: wait for php-fpm, so that copy can't overwrite
# the config put below.
i=0
until [ "$(php_state | cut -d' ' -f1)" = running ] && compose exec -T php sh -c 'grep -q "^php-fpm" /proc/1/comm' >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 120 ] || { echo "FAIL php-fpm did not start"; exit 1; }
  sleep 1
done
put ext/examples/wordpress.json
compose restart php >/dev/null 2>&1
i=0
until compose exec -T db mariadb -uwordpress -pwordpress-db-password -e 'select 1' wordpress >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "FAIL database did not start"; exit 1; }
  sleep 1
done
if ! wp core is-installed >/dev/null 2>&1; then
  wp core install --url="$base" --title=SecureCore --admin_user=admin \
    --admin_password=securecore-demo --admin_email=admin@example.com --skip-email >/dev/null
fi
cp_in test/ext/securecore-status.php /var/www/html/securecore-status.php
wait_200 || { echo "FAIL front page never served 200"; exit 1; }

# --- 1. loaded with a valid config -----------------------------------------------------------
is "$(compose exec -T php php -m | grep -cx securecore)" 1 "php -m lists securecore"
is "$(code /)" 200 "front page 200 with the extension and examples/wordpress.json"
status
want=$(sha ext/examples/wordpress.json)
is "$(field loaded)" 1 "securecore_status() exists in php-fpm"
is "$(field sha256)" "$want" "status sha256 is the file's ($want)"
is "$(field config)" "$conf" "status names the config path"
is "$(layers)" 111 "status: all three layers enabled"
is "$(field layer2_mode)/$(field layer2_app)" enforce/wordpress "status: layer2 enforce, app wordpress"
is "$(field off)/$(field reload_error)" 0/ "status: not off, no reload error"
is "$(field root)" /var/www/html "status: the root is the folder containing securecore.json"

# The file sits in the web root, so nginx must refuse it (and any copy an editor leaves).
if compose exec -T php test -s "$conf"; then pass "securecore.json is in the web root"; else fail "securecore.json is in the web root"; fi
compose exec -T php sh -c "cp $conf $conf.bak"
for u in /securecore.json /SecureCore.JSON /securecore%2Ejson /./securecore.json //securecore.json /securecore.json.bak '/securecore.json?x=1'; do
  c=$(code "$u")
  case $c in 403|404) pass "nginx refuses $u ($c)" ;; *) fail "nginx refuses $u" "$c" ;; esac
done
compose exec -T php rm -f "$conf.bak"
# The refusal is the rule, not a missing file: the same request for a sibling file works.
compose exec -T php sh -c "cp /var/www/html/readme.html /var/www/html/securecore-probe.json"
is "$(code /securecore-probe.json)" 200 "a sibling .json file in the web root is served (so the 404s above are the rule)"
compose exec -T php rm -f /var/www/html/securecore-probe.json

# --- 2. reload without a restart -------------------------------------------------------------
before="$(php_state) $(master_pid)"
sed 's/"mode": "enforce"/"mode": "log"/' ext/examples/wordpress.json > "$dir/log-mode.json"
t=$(now)
put_live "$dir/log-mode.json"
want=$(sha "$dir/log-mode.json")
wait_reload
good=0 pids=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  status
  pids="$pids $(field pid)"
  [ "$(field sha256)/$(field layer2_mode)" = "$want/log" ] && good=$((good + 1))
done
workers=$(echo "$pids" | tr ' ' '\n' | sort -u | grep -c .)
is "$good" 10 "edited to mode=log: 10/10 requests ($workers php-fpm workers) report the new sha256 and mode"
is "$(php_state) $(master_pid)" "$before" "no restart: same php-fpm master and container start"
is "$(field restart_needed)" 0 "a layer2 edit does not need a restart"
is "$(phplog "$t" | grep -cF "securecore: reloaded $conf (sha256 $want)" | grep -c '^[1-9]')" 1 "the php-fpm log records the reload and the new sha256"

cp ext/examples/off.json "$dir/off.json"
put_live "$dir/off.json"
wait_reload
status
is "$(field sha256)/$(field off)/$(layers)" "$(sha "$dir/off.json")/1/000" "edited to off.json: status reports off, all layers disabled"
is "$(field restart_needed)" 1 "layer1 changed (enabled → disabled): restart_needed"
is "$(code /)" 200 "front page 200 with all layers off"

# --- 3. an invalid edit while running keeps the last valid config ----------------------------
printf '{"layer1":{"enabled":false},"layer2":{"enabled":true,"app":"wordpress","mode":"block"},"layer3":{"enabled":false}}\n' > "$dir/bad-mode.json"
t=$(now)
put_live "$dir/bad-mode.json"
wait_reload
status
is "$(field sha256)" "$(sha "$dir/off.json")" "invalid edit: the last valid config stays live"
case $(field reload_error) in
  "$conf: invalid: unknown variant \`block\`"*) pass "invalid edit: reload_error names the file and the problem" ;;
  *) fail "invalid edit: reload_error names the file and the problem" "$(field reload_error)" ;;
esac
is "$(code /)" 200 "invalid edit: still serving on the last valid config"
is "$(phplog "$t" | grep -F "securecore: $conf: invalid: unknown variant \`block\`" | grep -cF 'keeping the last valid config' | grep -c '^[1-9]')" 1 \
  "invalid edit: the php-fpm log says why and that the last valid config is kept"

# --- 4. fail closed at startup ---------------------------------------------------------------
# refuses <label> <expected log text>: php is restarted on the current file and must exit.
refuses() {
  since=$(now)
  compose restart php >/dev/null 2>&1
  if wait_exited; then pass "$1: php-fpm refuses to start"; else fail "$1: php-fpm refuses to start" "$(php_state)"; fi
  phplog "$since" > "$dir/refuse.log"
  if grep -qF "$2" "$dir/refuse.log" && grep -q 'Unable to start securecore module' "$dir/refuse.log"; then
    pass "$1: the log says why: $(grep -F 'PHP Startup' "$dir/refuse.log" | head -1 | sed 's/.*PHP Startup: //')"
  else
    fail "$1: the log names the file and the problem" "$(tr '\n' ' ' < "$dir/refuse.log")"
  fi
  c=$(code /)
  if [ "$c" != 200 ]; then pass "$1: no page is served ($c)"; else fail "$1: no page is served" "$c"; fi
}
refuses "invalid mode" "securecore: $conf: invalid: unknown variant \`block\`"

printf '{"layer1":{"enabled":false},"layer2":{"enabled":false},"layer3":{"enabled":false},"layer4":{}}\n' > "$dir/unknown-key.json"
put "$dir/unknown-key.json"
refuses "unknown key" "securecore: $conf: invalid: unknown field \`layer4\`"

ini=/usr/local/etc/php/conf.d/securecore.ini
compose cp "php:$ini" "$dir/securecore.ini" >>"$dir/cp.log" 2>&1
sed "s|^securecore.config=.*|securecore.config=/etc/securecore/missing.json|" "$dir/securecore.ini" > "$dir/missing.ini"
cp_in "$dir/missing.ini" "$ini"
refuses "missing file" "securecore: /etc/securecore/missing.json: cannot read it: No such file or directory"

sed "/^securecore.config=/d" "$dir/securecore.ini" > "$dir/unset.ini"
cp_in "$dir/unset.ini" "$ini"
refuses "securecore.config unset" "securecore: securecore.config is not set"

# Fixed: the original ini and a valid file start it again.
cp_in "$dir/securecore.ini" "$ini"
put ext/examples/wordpress.json
compose start php >/dev/null 2>&1
if wait_200; then pass "fixed config: php-fpm starts and serves 200"; else fail "fixed config: php-fpm starts and serves 200" "$(php_state)"; fi
status
is "$(field sha256)/$(field restart_needed)" "$(sha ext/examples/wordpress.json)/0" "after the restart: wordpress.json live, restart_needed cleared"

echo
if [ "$fails" -eq 0 ]; then echo "all ext-config checks passed"; else echo "$fails check(s) failed"; fi
[ "$fails" -eq 0 ]
