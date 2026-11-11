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
# On the microVM target (SC_TARGET=microvm, test/lib/target.sh) php-fpm runs in the guest: 2 and
# 3 become "a changed config reaches the guest at its next start" (the guest's site disk is a copy
# made at each start, so an in-place edit can't reach a running guest), and 4's refusals are the
# launcher's (exit 125, its log), the ini cases n/a (php.ini is on the guest's read-only root).
# Exits non-zero on any failure. Writes .tmp/ext-config/. Leaves the stack up on a valid config.
#   DOCKER_CONTEXT=colima test/ext-config.sh
#   sudo SC_TARGET=microvm test/ext-config.sh      (a KVM host, as root)
#   SECURECORE_EXT_PROJECT / SECURECORE_EXT_PORT pick another project / port (all ext-* tests).
set -u
cd "$(dirname "$0")/.." || exit 1
project=${SECURECORE_EXT_PROJECT:-securecore-ext}
port=${SECURECORE_EXT_PORT:-8089}
dir=.tmp/ext-config
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete 2>/dev/null
. test/lib/target.sh
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }
# is <actual> <expected> <label>
is() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3" "got '$1', want '$2'"; fi; }
wp() { compose run --rm -T cli wp "$@" 2>>"$dir/wp.err"; }
cp_in() { compose cp "$1" "php:$2" >>"$dir/cp.log" 2>&1; }
# status → key=value lines from the php-fpm worker that serves the request.
status() { curl -s "$base/securecore-status.php" > "$dir/status"; }
field() { sed -n "s/^$1=//p" "$dir/status"; }
layers() { echo "$(field layer1)$(field layer2)$(field layer3)"; }
started_at() { docker inspect -f '{{.State.Status}} {{.State.StartedAt}}' "$(compose ps -aq php)"; }
master_pid() { compose exec -T php sh -c 'cut -d" " -f1,22 /proc/1/stat'; }
# > RELOAD_INTERVAL (1000 ms): every worker re-checks the file on its next request.
wait_reload() { sleep 1.2; }

# --- stack -----------------------------------------------------------------------------------
stack_up
cp_in test/ext/securecore-status.php /var/www/html/securecore-status.php
site_sync
wait_200 || { echo "FAIL front page never served 200"; exit 1; }

# --- 1. loaded with a valid config -----------------------------------------------------------
if on_microvm; then
  na "php -m lists securecore" "php -m runs in the php container; securecore_status() below is the guest's php-fpm"
else
  is "$(compose exec -T php php -m | grep -cx securecore)" 1 "php -m lists securecore"
fi
is "$(code /)" 200 "front page 200 with the extension and examples/wordpress.json"
status
want=$(conf_sha ext/examples/wordpress.json)
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
sed 's/"mode": "enforce"/"mode": "log"/' ext/examples/wordpress.json > "$dir/log-mode.json"
cp ext/examples/off.json "$dir/off.json"
if on_microvm; then
  # The guest's site disk is a copy made at each start: the edit reaches it at the next one.
  reason="the guest's site disk is a copy made at each start, so a config edit reaches the guest only when the launcher starts it again"
  na "edited to mode=log: every worker reports the new file without a restart" "$reason"
  na "no restart: same php-fpm master and container start" "$reason"
  na "the php-fpm log records the reload and the new sha256" "$reason"
  t=$(now)
  put_live "$dir/log-mode.json"
  want=$(conf_sha "$dir/log-mode.json")
  good=0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    status
    [ "$(field sha256)/$(field layer2_mode)" = "$want/log" ] && good=$((good + 1))
  done
  is "$good" 10 "edited to mode=log, the launcher started again: 10/10 requests report the new sha256 and mode"
  is "$(field restart_needed)" 0 "a layer2 edit does not need a restart"
  is "$(phplog "$t" | grep -c 'microVM restored from snapshot\|made the snapshot' | grep -c '^[1-9]')" 1 "the launcher started the guest on the new site (its log)"
  put_live "$dir/off.json"
  status
  # layer1 stays on: the target's config is always isolation microvm (an off config runs php-fpm on
  # the host); layers 2 and 3 are the file's.
  is "$(field sha256)/$(layers)" "$(conf_sha "$dir/off.json")/100" "edited to off.json: layers 2 and 3 disabled, layer 1 the microVM"
  na "edited to off.json: status reports off" "the target keeps layer 1 on (isolation microvm), so the config is never all off"
  na "layer1 changed (enabled → disabled): restart_needed" "the target keeps layer 1 on; restart_needed is about an edit a running php-fpm can't apply, and the guest is always started again"
  is "$(code /)" 200 "front page 200 with layers 2 and 3 off"
else
  before="$(started_at) $(master_pid)"
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
  is "$(started_at) $(master_pid)" "$before" "no restart: same php-fpm master and container start"
  is "$(field restart_needed)" 0 "a layer2 edit does not need a restart"
  is "$(phplog "$t" | grep -cF "securecore: reloaded $conf (sha256 $want)" | grep -c '^[1-9]')" 1 "the php-fpm log records the reload and the new sha256"

  put_live "$dir/off.json"
  wait_reload
  status
  is "$(field sha256)/$(field off)/$(layers)" "$(sha "$dir/off.json")/1/000" "edited to off.json: status reports off, all layers disabled"
  is "$(field restart_needed)" 1 "layer1 changed (enabled → disabled): restart_needed"
  is "$(code /)" 200 "front page 200 with all layers off"
fi

# --- 3. an invalid edit while running keeps the last valid config ----------------------------
printf '{"layer1":{"isolation":"off"},"layer2":{"enabled":true,"app":"wordpress","mode":"block"},"layer3":{"enabled":false}}\n' > "$dir/bad-mode.json"
if on_microvm; then
  reason="a running guest never sees an edit (its site disk is a copy made at start); an invalid file at a start is section 4"
  for l in "invalid edit: the last valid config stays live" "invalid edit: reload_error names the file and the problem" \
    "invalid edit: still serving on the last valid config" "invalid edit: the php-fpm log says why and that the last valid config is kept"; do
    na "$l" "$reason"
  done
  put "$dir/bad-mode.json"
else
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
fi

# --- 4. fail closed at startup ---------------------------------------------------------------
# refuses <label> <the problem>: php is restarted on the current file and must exit. In the
# container the extension refuses (php-fpm's log, "securecore: <problem>"); on the microVM the
# launcher refuses before any guest boots (exit 125, its log, naming its view of the file).
# <the problem> starting "<file>: " names the config: $conf in the container, the launcher's path
# on the microVM.
refuses() {
  since=$(now)
  php_restart > /dev/null 2>&1
  if wait_exited; then pass "$1: php-fpm refuses to start"; else fail "$1: php-fpm refuses to start" "$(php_state)"; fi
  phplog "$since" > "$dir/refuse.log"
  problem=$2
  if on_microvm; then
    is "$(php_state)" "exited 125" "$1: the launcher exits 125"
    # The launcher's words, when they differ (<the launcher's problem>, a third argument): it
    # never quotes the file, so a JSON or schema error says where and what kind (#90 review).
    if grep -qF "securecore-fpm: $(site_dir)/securecore.json: ${3:-${problem#\$conf: }}" "$dir/refuse.log"; then
      pass "$1: the log says why: $(grep -F 'securecore-fpm' "$dir/refuse.log" | head -1 | cut -c1-200)"
    else
      fail "$1: the log names the file and the problem" "$(tr '\n' ' ' < "$dir/refuse.log" | cut -c1-400)"
    fi
    is "$(grep -c 'guest: ' "$dir/refuse.log")" 0 "$1: no guest started"
  elif grep -qF "securecore: $(echo "$problem" | sed "s|^\\\$conf|$conf|")" "$dir/refuse.log" && grep -q 'Unable to start securecore module' "$dir/refuse.log"; then
    pass "$1: the log says why: $(grep -F 'PHP Startup' "$dir/refuse.log" | head -1 | sed 's/.*PHP Startup: //')"
  else
    fail "$1: the log names the file and the problem" "$(tr '\n' ' ' < "$dir/refuse.log")"
  fi
  c=$(code /)
  if [ "$c" != 200 ]; then pass "$1: no page is served ($c)"; else fail "$1: no page is served" "$c"; fi
}
# (Single quotes: '$conf' is the literal placeholder refuses() fills in.)
put "$dir/bad-mode.json"
refuses "invalid mode" '$conf: invalid: unknown variant `block`' "invalid at line "
! on_microvm || is "$(grep -c 'block' "$dir/refuse.log")" 0 "invalid mode: the launcher's log doesn't quote the file's value"

printf '{"layer1":{"isolation":"off"},"layer2":{"enabled":false},"layer3":{"enabled":false},"layer4":{}}\n' > "$dir/unknown-key.json"
put "$dir/unknown-key.json"
refuses "unknown key" '$conf: invalid: unknown field `layer4`' "invalid at line "

# layer1.enabled is retired: the extension refuses a file that still sets it, saying why.
printf '{"layer1":{"enabled":false},"layer2":{"enabled":false},"layer3":{"enabled":false}}\n' > "$dir/retired.json"
put "$dir/retired.json"
refuses "the retired layer1.enabled" "\$conf: invalid: layer1.enabled is retired: layer1.isolation is layer 1's only switch"

ini=/usr/local/etc/php/conf.d/securecore.ini
if on_microvm; then
  reason="php.ini is on the guest's read-only root image, the same for every site; the launcher passes the config path itself"
  for l in "missing file: php-fpm refuses to start" "securecore.config unset: php-fpm refuses to start"; do na "$l" "$reason"; done
else
  compose cp "php:$ini" "$dir/securecore.ini" >>"$dir/cp.log" 2>&1
  sed "s|^securecore.config=.*|securecore.config=/etc/securecore/missing.json|" "$dir/securecore.ini" > "$dir/missing.ini"
  cp_in "$dir/missing.ini" "$ini"
  refuses "missing file" "/etc/securecore/missing.json: cannot read it: No such file or directory"
  sed "/^securecore.config=/d" "$dir/securecore.ini" > "$dir/unset.ini"
  cp_in "$dir/unset.ini" "$ini"
  refuses "securecore.config unset" "securecore.config is not set"
  cp_in "$dir/securecore.ini" "$ini"
fi

# Fixed: the original ini and a valid file start it again.
put ext/examples/wordpress.json
php_start
if wait_200; then pass "fixed config: php-fpm starts and serves 200"; else fail "fixed config: php-fpm starts and serves 200" "$(php_state)"; fi
status
is "$(field sha256)/$(field restart_needed)" "$(conf_sha ext/examples/wordpress.json)/0" "after the restart: wordpress.json live, restart_needed cleared"

echo
na_summary
if [ "$fails" -eq 0 ]; then echo "all ext-config checks passed"; else echo "$fails check(s) failed"; fi
[ "$fails" -eq 0 ]
