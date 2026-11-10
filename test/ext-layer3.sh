#!/bin/sh
# E7 integration tests for layer 3 (addiscorp/securecore#53): an isolated plugin runs in a clean
# child of the helper, never in the php-fpm worker. On the extension stack test/ext-config.sh
# leaves up. Fixtures (test/ext/layer3-plugin): the probe plugin sc-l3probe (isolated: a
# the_content filter, shortcodes, and benign probes for the limits) and a neighbour plugin that
# is never isolated (it runs in the worker after the probe's filter, prints the worker's pid and
# whether the probe's code exists there). Hello Dolly is isolated too.
#   1. layer 3 on (layer 2 enforce): pages render with the probe's filter and shortcode output,
#      produced in a child (another pid than the worker's, a new one per request); the probe's
#      code is not in the worker, and a stray include of its files there is refused; Hello Dolly
#      renders on the dashboard from its child; the helper runs as the pool user with an empty
#      environment; a core option change re-boots the helper (the child sees the new value).
#   2. the limits: a write outside its folder, a read of wp-config.php / securecore.json and a
#      network connect are stopped (and the write logged); a too-long loop is killed at timeoutMs
#      and too much memory ends the child, each logged, while the page still renders.
#   3. layer 2 off, layer 3 on: the kernel alone (gelada) still stops the write and the reads.
#   4. the revert proof, layer 3 off (layer 2 log): the probe runs in the worker, every probe
#      case goes through, the loop holds the page for its 8 s and the memory probe kills the page.
# Exits non-zero on any failure. Writes .tmp/ext-layer3/. Restores examples/wordpress.json and
# removes the fixtures at the end.
#   DOCKER_CONTEXT=colima test/ext-config.sh && DOCKER_CONTEXT=colima test/ext-layer3.sh
set -u
cd "$(dirname "$0")/.." || exit 1
project=${SECURECORE_EXT_PROJECT:-securecore-ext}
port=${SECURECORE_EXT_PORT:-8089}
base=http://127.0.0.1:$port
dir=.tmp/ext-layer3
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete 2>/dev/null
html=/var/www/html
conf=$html/securecore.json
content=$html/wp-content
probe=$content/plugins/sc-l3probe
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }
is() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3" "got '$1', want '$2'"; fi; }
compose() { SECURECORE_PORT=$port docker compose -f docker/compose.yml -f docker/compose.ext.yml -p "$project" "$@"; }
wp() { compose run --rm -T cli wp "$@" 2>>"$dir/wp.err" | tr -d '\r'; }
in_php() { compose exec -T php sh -c "$1"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$base$1"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
# The login page: the front page lists the probe posts, and in the revert run the memory probe
# kills any page that renders it.
wait_200() { i=0; until [ "$(code /wp-login.php)" = 200 ]; do i=$((i + 1)); [ "$i" -lt 60 ] || return 1; sleep 1; done; }
put_live() { compose exec -T php sh -c "cat > $conf.new && mv $conf.new $conf" < "$1"; }
phplog() { compose logs --no-log-prefix --since "$1" php 2>&1; }
# has <since> <substring> <label>: php-fpm's log (the helper's included) has a securecore line with it.
has() { if phplog "$1" | grep -F 'securecore: ' | grep -qF -- "$2"; then pass "$3"; else fail "$3" "no securecore line matching '$2'"; fi; }
# haslog <since> <substring> <label>: any line of php-fpm's log (PHP's own errors from the child).
haslog() { if phplog "$1" | grep -qF -- "$2"; then pass "$3"; else fail "$3" "no log line matching '$2'"; fi; }
hasnt() { if phplog "$1" | grep -F 'securecore: ' | grep -qF -- "$2"; then fail "$3" "unexpected line '$2'"; else pass "$3"; fi; }
# get <name> <path>: fetch into $dir/<name>, recording the status and the time taken.
get() { curl -s -m 30 -b "$dir/jar" -o "$dir/$1" -w '%{http_code} %{time_total}' "$base$2" > "$dir/$1.meta"; }
status_of() { cut -d' ' -f1 "$dir/$1.meta"; }
secs_of() { cut -d' ' -f2 "$dir/$1.meta" | cut -d. -f1; }
contains() { if grep -qF -- "$2" "$dir/$1"; then pass "$3"; else fail "$3" "'$2' not in $1"; fi; }
lacks() { if grep -qF -- "$2" "$dir/$1"; then fail "$3" "'$2' in $1"; else pass "$3"; fi; }
# The pid a fixture printed: field <file> <prefix> (e.g. "l3 filter pid=").
pid_after() { sed -n "s/.*$2\([0-9][0-9]*\).*/\1/p" "$dir/$1" | head -1; }
verdict() { sed -n "s/^$2=//p" "$dir/$1" | head -1; }
want() { v=$(verdict "$1" "$2"); if [ "$v" = "$3" ]; then pass "$4: $2 is $3"; else fail "$4: $2 is $3" "got '$v'"; fi; }

[ "$(code /)" = 200 ] || { echo "FAIL the extension stack is not up on $base: run test/ext-config.sh first"; exit 1; }

# --- fixtures --------------------------------------------------------------------------------
in_php "rm -rf $probe $content/plugins/sc-l3-neighbour.php && mkdir -p $probe $content/uploads/sc-l3probe"
compose cp test/ext/layer3-plugin/sc-l3probe.php "php:$probe/sc-l3probe.php" >>"$dir/cp.log" 2>&1
compose cp test/ext/layer3-plugin/inc.php "php:$probe/inc.php" >>"$dir/cp.log" 2>&1
compose cp test/ext/layer3-plugin/sc-l3-neighbour.php "php:$content/plugins/sc-l3-neighbour.php" >>"$dir/cp.log" 2>&1
in_php "rm -f $content/uploads/sc-l3-up.txt $content/uploads/sc-l3probe/w.txt $probe/w.txt; chown -R www-data:www-data $probe $content/uploads"
wp plugin activate sc-l3probe sc-l3-neighbour hello >/dev/null
post() { wp post create --post_status=publish --post_title="$1" --post_content="$2" --porcelain; }
p_main=$(post "L3 main" 'SC-L3-BODY [sc_l3 say="hello"]')
p_loop=$(post "L3 loop" '[sc_l3_loop] SC-L3-AFTER-LOOP')
p_mem=$(post "L3 memory" '[sc_l3_memory] SC-L3-AFTER-MEMORY')
p_probe=$(post "L3 probe" '[sc_l3_probe] SC-L3-AFTER-PROBE')
[ -n "$p_main" ] && [ -n "$p_probe" ] || { echo "FAIL could not create the test posts (see $dir/wp.err)"; exit 1; }

cleanup() {
  wp plugin deactivate sc-l3probe sc-l3-neighbour hello >/dev/null 2>&1
  for p in $p_main $p_loop $p_mem $p_probe; do wp post delete "$p" --force >/dev/null 2>&1; done
  wp option update blogname SecureCore >/dev/null 2>&1
  in_php "rm -rf $probe $content/plugins/sc-l3-neighbour.php $content/uploads/sc-l3probe $content/uploads/sc-l3-up.txt"
  compose cp ext/examples/wordpress.json "php:$conf" >/dev/null 2>&1
  compose restart php >/dev/null 2>&1
  wait_200 || echo "FAIL php-fpm did not come back after cleanup"
}
trap cleanup EXIT

# --- configs ---------------------------------------------------------------------------------
cfg() { # $1 name, $2 layer2 mode, $3 layer3 enabled
  cat > "$dir/$1.json" <<JSON
{
  "layer1": { "enabled": false },
  "layer2": {
    "enabled": true, "app": "wordpress", "mode": "$2",
    "vault": { "from": { "wpConfig": "wp-config.php" }, "secrets": [{ "name": "DB_PASSWORD", "env": "WORDPRESS_DB_PASSWORD" }] },
    "default": {},
    "components": {}
  },
  "layer3": {
    "enabled": $3,
    "isolate": ["sc-l3probe", "hello"],
    "limits": { "timeoutMs": 1500, "memoryMb": 64 },
    "write": { "sc-l3probe": ["wp-content/uploads/sc-l3probe"] }
  }
}
JSON
}
cfg on enforce true
cfg l2off off true
cfg revert log false

# use <config>: install it and restart php-fpm (the helper starts with php-fpm), wait for 200.
use() {
  compose cp "$dir/$1.json" "php:$conf" >>"$dir/cp.log" 2>&1
  compose restart php >/dev/null 2>&1
  wait_200 || fail "$1: php-fpm serves 200 after the restart"
}
login() {
  rm -f "$dir/jar"
  curl -s -c "$dir/jar" -o /dev/null "$base/wp-login.php"
  curl -s -b "$dir/jar" -c "$dir/jar" -o /dev/null -d 'log=admin&pwd=securecore-demo&testcookie=1&rememberme=forever' "$base/wp-login.php"
}

# --- 1. layer 3 on ---------------------------------------------------------------------------
echo "# layer 3 on (layer 2 enforce)"
use on
T=$(now); sleep 1
get main1 "/?p=$p_main"
get main2 "/?p=$p_main"
is "$(status_of main1)" 200 "on: the post renders"
contains main1 "SC-L3-BODY" "on: the post's own content is there"
contains main1 'class="sc-l3-short">said hello' "on: the isolated shortcode rendered"
contains main1 'class="sc-l3-filter">l3 filter' "on: the isolated the_content filter ran"
contains main1 'probe-not-in-worker' "on: the probe's code does not exist in the php-fpm worker"
worker=$(pid_after main1 'neighbour pid=')
child=$(pid_after main1 'l3 filter pid=')
short=$(pid_after main1 'said hello pid=')
child2=$(pid_after main2 'l3 filter pid=')
if [ -n "$worker" ] && [ -n "$child" ] && [ "$child" != "$worker" ]; then pass "on: the filter ran in another process ($child) than the worker ($worker)"; else fail "on: the filter ran in another process than the worker" "child '$child' worker '$worker'"; fi
is "$short" "$child" "on: the shortcode and the filter ran in the same child"
if [ -n "$child2" ] && [ "$child2" != "$child" ]; then pass "on: the next request got a fresh child ($child2)"; else fail "on: the next request got a fresh child" "'$child2'"; fi
is "$(code /)" 200 "on: front page 200"
is "$(code /wp-login.php)" 200 "on: login page 200"
get inc "/?p=$p_main&sc_l3_inc=1"
contains inc 'inc=refused' "on: an include of the probe's file from the worker is refused"
has "$T" "layer3 plugin:sc-l3probe include refused $probe/inc.php" "on: the refused include is logged"
login
get dash "/wp-admin/"
is "$(status_of dash)" 200 "on: the dashboard renders"
contains dash 'id="dolly"' "on: Hello Dolly (isolated) prints its lyric on the dashboard"
# The helper: never root once serving, and an empty environment (no DB password, no salts).
in_php 'for p in /proc/[0-9]*; do if [ "$(cat $p/comm 2>/dev/null)" = php ] && tr "\0" " " < $p/cmdline 2>/dev/null | grep -q "securecore.layer3_role=helper"; then echo "$(basename $p) $(sed -n "s/^Uid:[[:space:]]*\([0-9]*\).*/\1/p" $p/status) $(tr "\0" "\n" < $p/environ | grep -c .)"; fi; done' > "$dir/helpers"
if [ -s "$dir/helpers" ]; then pass "on: helper processes exist ($(wc -l < "$dir/helpers"))"; else fail "on: helper processes exist"; fi
is "$(awk '$2 != 33' "$dir/helpers" | grep -c .)" 0 "on: every helper process runs as www-data (uid 33)"
is "$(awk '$3 != 0' "$dir/helpers" | grep -c .)" 0 "on: every helper process has an empty environment"
# A core option change: the helper re-boots from the new snapshot, so the child sees it.
wp option update blogname "SC-L3-Renamed" >/dev/null
get renamed "/?p=$p_main"
contains renamed 'blogname=SC-L3-Renamed' "on: after a core option change the child sees the new value (re-booted)"
wp option update blogname SecureCore >/dev/null

# --- 2. the limits ---------------------------------------------------------------------------
echo "# limits (timeoutMs 1500, memoryMb 64, write: uploads/sc-l3probe)"
T=$(now); sleep 1
get probe "/?p=$p_probe"
is "$(status_of probe)" 200 "limits: the probe page renders"
contains probe "SC-L3-AFTER-PROBE" "limits: the rest of the probe page is there"
want probe write-own OK "limits"
for c in write-uploads write-plugin-dir read-config read-securecore-json net-db; do want probe "$c" BLOCKED "limits"; done
has "$T" "layer3 plugin:sc-l3probe open write-outside $content/uploads/sc-l3-up.txt" "limits: the write outside its folder is logged"
get loop "/?p=$p_loop"
is "$(status_of loop)" 200 "limits: the too-long loop's page renders"
contains loop "SC-L3-AFTER-LOOP" "limits: the rest of the loop page is there"
lacks loop "loop-finished" "limits: the loop did not finish"
if [ "$(secs_of loop)" -lt 6 ]; then pass "limits: the loop page took $(cut -d' ' -f2 "$dir/loop.meta") s, not the loop's 8"; else fail "limits: the loop page was cut short" "$(cut -d' ' -f2 "$dir/loop.meta") s"; fi
has "$T" "timed out after 1500 ms; child" "limits: the timeout is logged"
sleep 2 # the zygote reports a child's end when it reaps it (at most a second later)
has "$T" "killed by signal 9" "limits: the child was killed"
get mem "/?p=$p_mem"
is "$(status_of mem)" 200 "limits: the too-much-memory page renders"
contains mem "SC-L3-AFTER-MEMORY" "limits: the rest of the memory page is there"
lacks mem "memory-ok" "limits: the allocation did not succeed"
haslog "$T" "Allowed memory size of 67108864 bytes exhausted" "limits: the child hit its 64 MB memory_limit"
has "$T" "ended during call" "limits: the worker logged the child ending mid-call"
is "$(code /)" 200 "limits: front page still 200 afterwards"

# --- 3. layer 2 off: the kernel alone ----------------------------------------------------------
echo "# layer 2 off, layer 3 on (the kernel alone)"
use l2off
in_php "rm -f $content/uploads/sc-l3-up.txt $content/uploads/sc-l3probe/w.txt $probe/w.txt"
T=$(now); sleep 1
get probe2 "/?p=$p_probe"
is "$(status_of probe2)" 200 "l2off: the probe page renders"
contains probe2 'probe-not-in-worker' "l2off: the probe is still not in the worker"
want probe2 write-own OK "l2off"
for c in write-uploads write-plugin-dir read-config read-securecore-json net-db; do want probe2 "$c" BLOCKED "l2off"; done
hasnt "$T" "write-outside" "l2off: no layer 2 file line (the kernel stopped it)"

# --- 4. revert: layer 3 off --------------------------------------------------------------------
echo "# revert: layer 3 off (layer 2 log)"
use revert
in_php "rm -f $content/uploads/sc-l3-up.txt $content/uploads/sc-l3probe/w.txt $probe/w.txt"
get rmain "/?p=$p_main"
contains rmain 'probe-in-worker' "revert: the probe's code is in the worker"
is "$(pid_after rmain 'l3 filter pid=')" "$(pid_after rmain 'neighbour pid=')" "revert: the filter ran in the worker"
get rprobe "/?p=$p_probe"
for c in write-own write-uploads write-plugin-dir read-config read-securecore-json net-db; do want rprobe "$c" OK "revert"; done
get rloop "/?p=$p_loop"
contains rloop "loop-finished" "revert: the loop ran to the end"
if [ "$(secs_of rloop)" -ge 7 ]; then pass "revert: the loop held the page for $(cut -d' ' -f2 "$dir/rloop.meta") s"; else fail "revert: the loop held the page for 8 s" "$(cut -d' ' -f2 "$dir/rloop.meta") s"; fi
get rmem "/?p=$p_mem"
if [ "$(status_of rmem)" != 200 ] || ! grep -qF SC-L3-AFTER-MEMORY "$dir/rmem"; then pass "revert: too much memory kills the page ($(status_of rmem))"; else fail "revert: too much memory kills the page" "200 with content"; fi

echo
if [ "$fails" -eq 0 ]; then echo "all ext-layer3 checks passed"; else echo "$fails check(s) failed"; fi
[ "$fails" -eq 0 ]
