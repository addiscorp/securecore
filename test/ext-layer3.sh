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
#   1b. the database gateway (#94), with the database probe sc-l3db (isolated): its own table by
#      dbDelta through every $wpdb method, its own option persisting across requests into the
#      site's database, the site's and core's options; layer 2's refusals (a core table, a
#      statement, another plugin's table) with layer 2's lines; the gateway's own refusals (not
#      UTF-8, the time cap); the caps (queries, result bytes, a statement cut at timeoutMs); no DB
#      password in the child's environment or memory; the cost of a query.
#   2. the limits: a write outside its folder, a read of wp-config.php / securecore.json and a
#      network connect are stopped (and the write logged); a too-long loop is killed at timeoutMs
#      and too much memory ends the child, each logged, while the page still renders.
#   3. layer 2 off, layer 3 on: the kernel alone (gelada) still stops the write and the reads.
#      With layer 2 off, the database probe's refused queries run through the gateway.
#   3b. the database probe unisolated (layer 3 off, layer 2 enforce): layer 2's lines are exactly
#      the isolated plugin's; SQL that isn't UTF-8 is refused by layer 2 itself; no cap applies.
#   4. the revert proof, layer 3 off (layer 2 log): the probe runs in the worker, every probe
#      case goes through, the loop holds the page for its 8 s and the memory probe kills the page.
# Exits non-zero on any failure. Writes .tmp/ext-layer3/. Restores examples/wordpress.json and
# removes the fixtures at the end.
# On the microVM target (SC_TARGET=microvm, test/lib/target.sh) the helper and its children run
# in the guest (Landlock in the guest's kernel). The helper's /proc check is n/a there (the
# guest's processes aren't the php container's). In the revert run, layer 1 still holds in the
# guest: the plugin folder is on its read-only site disk, and the guest has no name `db` (its
# database is 127.0.0.1:3306), so those two cases are checked as BLOCKED / n/a.
#   DOCKER_CONTEXT=colima test/ext-config.sh && DOCKER_CONTEXT=colima test/ext-layer3.sh
set -u
cd "$(dirname "$0")/.." || exit 1
project=${SECURECORE_EXT_PROJECT:-securecore-ext}
port=${SECURECORE_EXT_PORT:-8089}
dir=.tmp/ext-layer3
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete 2>/dev/null
. test/lib/target.sh
content=$html/wp-content
probe=$content/plugins/sc-l3probe
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }
is() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3" "got '$1', want '$2'"; fi; }
wp() { compose run --rm -T cli wp "$@" 2>>"$dir/wp.err" | tr -d '\r'; }
in_php() { compose exec -T php sh -c "$1"; }
# The login page: the front page lists the probe posts, and in the revert run the memory probe
# kills any page that renders it.
wait_login() { wait_200 /wp-login.php; }
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

stack_is_up

# --- fixtures --------------------------------------------------------------------------------
in_php "rm -rf $probe $content/plugins/sc-l3-neighbour.php && mkdir -p $probe $content/uploads/sc-l3probe"
compose cp test/ext/layer3-plugin/sc-l3probe.php "php:$probe/sc-l3probe.php" >>"$dir/cp.log" 2>&1
compose cp test/ext/layer3-plugin/inc.php "php:$probe/inc.php" >>"$dir/cp.log" 2>&1
compose cp test/ext/layer3-plugin/sc-l3-neighbour.php "php:$content/plugins/sc-l3-neighbour.php" >>"$dir/cp.log" 2>&1
in_php "rm -f $content/uploads/sc-l3-up.txt $content/uploads/sc-l3probe/w.txt $probe/w.txt; chown -R www-data:www-data $probe $content/uploads"
# The database probe (#94), isolated: its own table, its own options, the caps and the secrets.
in_php "rm -rf $content/plugins/sc-l3db.php $content/uploads/sc-l3db && mkdir -p $content/uploads/sc-l3db && chown www-data:www-data $content/uploads/sc-l3db"
compose cp test/ext/layer3-plugin/sc-l3db.php "php:$content/plugins/sc-l3db.php" >>"$dir/cp.log" 2>&1
# db_exec <sql>: as the site's database user, on the db container.
db_exec() { compose exec -T db mariadb -uwordpress -pwordpress-db-password -N wordpress -e "$1" 2>>"$dir/db.err"; }
db_exec "DROP TABLE IF EXISTS wp_sc_l3db_items; DROP TABLE IF EXISTS wp_sc_l3_neighbour_data; CREATE TABLE wp_sc_l3_neighbour_data (id int); INSERT INTO wp_sc_l3_neighbour_data VALUES (1), (2), (3), (4), (5), (6); DELETE FROM wp_options WHERE option_name LIKE 'sc\\_l3db\\_%' OR option_name LIKE '\\_transient\\_%sc\\_l3db%'"
wp option add sc_l3db_greeting hello-from-wp --autoload=no >/dev/null
wp plugin activate sc-l3probe sc-l3-neighbour hello sc-l3db >/dev/null
post() { wp post create --post_status=publish --post_title="$1" --post_content="$2" --porcelain; }
# Pages, not posts: the front page lists posts, and these must run only when asked.
page() { wp post create --post_type=page --post_status=publish --post_title="$1" --post_content="$2" --porcelain; }
p_main=$(post "L3 main" 'SC-L3-BODY [sc_l3 say="hello"]')
p_loop=$(post "L3 loop" '[sc_l3_loop] SC-L3-AFTER-LOOP')
p_mem=$(post "L3 memory" '[sc_l3_memory] SC-L3-AFTER-MEMORY')
p_probe=$(post "L3 probe" '[sc_l3_probe] SC-L3-AFTER-PROBE')
d_rw=$(page "L3 db rw" '[sc_l3db_rw]')
d_l2=$(page "L3 db layer 2" '[sc_l3db_l2]')
d_l3=$(page "L3 db gateway" '[sc_l3db_l3]')
d_many=$(page "L3 db many" '[sc_l3db_many n=80] SC-L3DB-AFTER')
d_big=$(page "L3 db big" '[sc_l3db_big]')
d_sleep=$(page "L3 db sleep" '[sc_l3db_sleep] SC-L3DB-AFTER-SLEEP')
d_secrets=$(page "L3 db secrets" '[sc_l3db_secrets]')
d_time=$(page "L3 db time" '[sc_l3db_time n=50]')
d_txn=$(page "L3 db txn" '[sc_l3db_txn_dies] SC-L3DB-AFTER-TXN')
d_txo=$(page "L3 db txn open" '[sc_l3db_txn_open] SC-L3DB-AFTER-TXO')
d_aco=$(page "L3 db autocommit off" '[sc_l3db_autocommit_off] SC-L3DB-AFTER-ACO')
d_huge=$(page "L3 db huge" '[sc_l3db_huge] SC-L3DB-AFTER-HUGE')
d_err=$(page "L3 db error" '[sc_l3db_err]')
d_sleeps=$(page "L3 db sleeps" '[sc_l3db_sleeps] SC-L3DB-AFTER-SLEEPS')
d_chain=$(page "L3 db chain" '[sc_l3db_chain] SC-L3DB-AFTER-CHAIN')
d_session=$(page "L3 db session" '[sc_l3db_session]')
d_tiny=$(page "L3 db tiny" '[sc_l3db_tiny] SC-L3DB-AFTER-TINY')
d_throw=$(page "L3 db throw" '[sc_l3db_throw] SC-L3DB-AFTER-THROW')
# scan_secrets <name>: fetch the secrets page into $dir/<name> and, while the process serving its
# call waits, read that process's environment and memory from outside (as root with
# CAP_SYS_PTRACE in the php container: a layer 3 child isn't dumpable) into $dir/<name>.scan,
# counting the DB password, a salt and (the control) "WordPress".
scan_secrets() {
  f=$content/uploads/sc-l3db
  in_php "rm -f $f/pid $f/scanned"
  compose exec --privileged -T php sh -c "i=0; until [ -s $f/pid ] || [ \$i -ge 250 ]; do sleep 0.02; i=\$((i + 1)); done
    [ -s $f/pid ] && php -- \"\$(cat $f/pid)\" wordpress-db-password sc-test-auth-key WordPress; touch $f/scanned" \
    < test/ext/layer3-memscan.php > "$dir/$1.scan" 2>&1 &
  scanner=$!
  get "$1" "/?page_id=$d_secrets"
  wait "$scanner"
}
scan_val() { sed -n "s/^$2=//p" "$dir/$1.scan" | head -1; }
scan_is() { v=$(scan_val "$1" "$2"); if [ "$v" = "$3" ]; then pass "$4"; else fail "$4" "$2 is '$v', want '$3'"; fi; }
# cost <name>: the median of 7 timings of the time page (µs per query, in the plugin).
cost() {
  for i in 1 2 3 4 5 6 7; do get "$1-$i" "/?page_id=$d_time"; verdict "$1-$i" us_per_query; done | sort -n | sed -n 4p
}
[ -n "$p_main" ] && [ -n "$p_probe" ] && [ -n "$d_secrets" ] || { echo "FAIL could not create the test posts (see $dir/wp.err)"; exit 1; }

cleanup() {
  wp plugin deactivate sc-l3probe sc-l3-neighbour hello sc-l3db >/dev/null 2>&1
  for p in $p_main $p_loop $p_mem $p_probe $d_rw $d_l2 $d_l3 $d_many $d_big $d_sleep $d_secrets $d_time $d_txn $d_txo $d_aco $d_huge $d_err $d_sleeps $d_chain $d_session $d_tiny $d_throw; do wp post delete "$p" --force >/dev/null 2>&1; done
  wp option update blogname SecureCore >/dev/null 2>&1
  db_exec "DROP TABLE IF EXISTS wp_sc_l3db_items, wp_sc_l3_neighbour_data; DELETE FROM wp_options WHERE option_name LIKE 'sc\\_l3db\\_%' OR option_name LIKE '\\_transient\\_%sc\\_l3db%' OR option_name = 'sc_l3_neighbour_mark'"
  in_php "rm -rf $probe $content/plugins/sc-l3-neighbour.php $content/plugins/sc-l3db.php $content/uploads/sc-l3db $content/uploads/sc-l3probe $content/uploads/sc-l3-up.txt"
  put ext/examples/wordpress.json
  php_restart >/dev/null 2>&1
  wait_login || echo "FAIL php-fpm did not come back after cleanup"
}
trap cleanup EXIT

# --- configs ---------------------------------------------------------------------------------
cfg() { # $1 name, $2 layer2 mode, $3 layer3 enabled
  cat > "$dir/$1.json" <<JSON
{
  "layer1": { "isolation": "off" },
  "layer2": {
    "enabled": true, "app": "wordpress", "mode": "$2",
    "vault": { "from": { "wpConfig": "wp-config.php" }, "secrets": [{ "name": "DB_PASSWORD", "env": "WORDPRESS_DB_PASSWORD" }] },
    "default": {},
    "components": {}
  },
  "layer3": {
    "enabled": $3,
    "isolate": ["sc-l3probe", "hello", "sc-l3db"],
    "limits": { "timeoutMs": 1500, "memoryMb": 64, "dbQueries": 60, "dbResultBytes": 4194304 },
    "write": { "sc-l3probe": ["wp-content/uploads/sc-l3probe"], "sc-l3db": ["wp-content/uploads/sc-l3db"] }
  }
}
JSON
}
cfg on enforce true
cfg l2off off true
cfg unisolated enforce false
cfg revert log false

# use <config>: install it and restart php-fpm (the helper starts with php-fpm), wait for 200.
use() {
  put "$dir/$1.json"
  php_restart >/dev/null 2>&1
  wait_login || fail "$1: php-fpm serves 200 after the restart"
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
if on_microvm; then
  why="the helper runs in the guest; /proc here is the php container's (the guest has no exec channel)"
  for l in "on: helper processes exist" "on: every helper process runs as www-data (uid 33)" "on: every helper process has an empty environment"; do na "$l" "$why"; done
else
  in_php 'for p in /proc/[0-9]*; do if [ "$(cat $p/comm 2>/dev/null)" = php ] && tr "\0" " " < $p/cmdline 2>/dev/null | grep -q "securecore.layer3_role=helper"; then echo "$(basename $p) $(sed -n "s/^Uid:[[:space:]]*\([0-9]*\).*/\1/p" $p/status) $(tr "\0" "\n" < $p/environ | grep -c .)"; fi; done' > "$dir/helpers"
  if [ -s "$dir/helpers" ]; then pass "on: helper processes exist ($(wc -l < "$dir/helpers"))"; else fail "on: helper processes exist"; fi
  is "$(awk '$2 != 33' "$dir/helpers" | grep -c .)" 0 "on: every helper process runs as www-data (uid 33)"
  is "$(awk '$3 != 0' "$dir/helpers" | grep -c .)" 0 "on: every helper process has an empty environment"
fi
# A core option change: the helper re-boots from the new snapshot, so the child sees it.
wp option update blogname "SC-L3-Renamed" >/dev/null
get renamed "/?p=$p_main"
contains renamed 'blogname=SC-L3-Renamed' "on: after a core option change the child sees the new value (re-booted)"
wp option update blogname SecureCore >/dev/null

# --- 1b. the database gateway (#94) ------------------------------------------------------------
echo "# the database gateway (layer 3 on, layer 2 enforce)"
T=$(now); sleep 1
get dbrw "/?page_id=$d_rw"
get dbrw2 "/?page_id=$d_rw"
is "$(status_of dbrw)" 200 "db: the page renders"
want dbrw isolated 1 "db: the plugin ran in its child"
for c in dbdelta insert get_row get_row_array update replace insert_id_next get_var get_col get_results get_col_info get_results_k \
  transaction delete bad_query_error last_error_clears counter_written transient; do
  want dbrw "$c" OK "db"
done
want dbrw prefix wp_ "db"
want dbrw options_table wp_options "db"
want dbrw charset utf8mb4 "db: the worker's charset"
want dbrw greeting hello-from-wp "db: an option the site set, read in a call"
want dbrw loaded_greeting hello-from-wp "db: and while the plugin loads"
want dbrw blogname SecureCore "db: a core option"
c1=$(verdict dbrw counter); c2=$(verdict dbrw2 counter)
is "$c2" "$((c1 + 1))" "db: its own option persisted from one request (child) to the next"
is "$(db_exec "SELECT option_value FROM wp_options WHERE option_name = 'sc_l3db_counter'")" "$((c2 + 1))" "db: the option is in the site's database"
is "$(db_exec 'SELECT name FROM wp_sc_l3db_items')" replaced "db: the plugin's table, made by dbDelta, holds its row in the site's database"
hasnt "$T" "layer2 enforce plugin:sc-l3db" "db: layer 2 refused nothing of its own table and options"
hasnt "$T" "layer3 plugin:sc-l3db database refused" "db: the gateway refused nothing"
cost_isolated=$(cost tiso)
case "$cost_isolated" in [0-9]*) pass "db: a one-row query isolated costs $cost_isolated µs (median of 7 × 50)" ;; *) fail "db: the cost page" "'$cost_isolated'" ;; esac
# Layer 2's refusals, with the lines a non-isolated plugin gets (compared in section 3b).
T=$(now); sleep 1
get dbl2 "/?page_id=$d_l2"
for c in core-table statement cross-plugin; do want dbl2 "$c" BLOCKED "db refusals"; done
want dbl2 core-table-error securecore "db refusals: last_error is layer 2's"
has "$T" "layer2 enforce plugin:sc-l3db mysqli_query core-table select wp_users" "db refusals: a core table without a grant, charged to the plugin"
has "$T" "layer2 enforce plugin:sc-l3db mysqli_query server-file select -" "db refusals: a refused statement"
has "$T" "layer2 enforce plugin:sc-l3db mysqli_query table select wp_sc_l3_neighbour_data" "db refusals: another plugin's table"
sleep 1
phplog "$T" | grep -o 'securecore: layer2 [a-z]* plugin:sc-l3db .*' | sort -u > "$dir/l2-isolated.lines"
get dbl3 "/?page_id=$d_l3"
want dbl3 not-utf8 BLOCKED "db gateway"
want dbl3 not-utf8-direct none "db gateway: the child has no connection of its own"
want dbl3 time-cap BLOCKED "db gateway"
has "$T" "layer3 plugin:sc-l3db database refused: the query is not UTF-8" "db gateway: SQL that isn't UTF-8 is refused, logged"
has "$T" "layer3 plugin:sc-l3db database refused: it changes the statement time cap" "db gateway: a change to the time cap is refused, logged"
# The caps (dbQueries 60, dbResultBytes 4 MiB, timeoutMs 1500).
T=$(now); sleep 1
get many "/?page_id=$d_many"
ran=$(verdict many ran)
if [ -n "$ran" ] && [ "$ran" -lt 60 ] && [ "$ran" -ge 50 ]; then pass "caps: $ran of 80 queries ran under dbQueries 60"; else fail "caps: the query cap stopped the loop" "ran '$ran'"; fi
want many error dbQueries "caps"
contains many SC-L3DB-AFTER "caps: the page goes on"
sleep 1
is "$(phplog "$T" | grep -c 'layer3 plugin:sc-l3db database refused: over the dbQueries cap of 60 per request')" 1 "caps: the query cap is logged once per request"
get big "/?page_id=$d_big"
want big big BLOCKED "caps"
want big error dbResultBytes "caps"
has "$T" "over the dbResultBytes cap of 4194304" "caps: the result cap is logged"
get sleep "/?page_id=$d_sleep"
is "$(status_of sleep)" 200 "caps: the 5 s statement's page renders"
contains sleep SC-L3DB-AFTER-SLEEP "caps: the rest of the page is there"
lacks sleep "slept=" "caps: the call did not finish"
if [ "$(secs_of sleep)" -lt 4 ]; then pass "caps: the 5 s statement was cut at timeoutMs ($(cut -d' ' -f2 "$dir/sleep.meta") s)"; else fail "caps: the 5 s statement was cut at timeoutMs" "$(cut -d' ' -f2 "$dir/sleep.meta") s"; fi
has "$T" "layer3 plugin:sc-l3db call" "caps: the timed-out call is logged"
is "$(db_exec "SELECT COUNT(*) FROM information_schema.processlist WHERE info LIKE 'SELECT SLEEP(5)%'")" 0 "caps: the statement is not running on the server any more"
# A child killed with a transaction open: the worker rolls it back (its write never lands).
T=$(now); sleep 1
mark=m$$x$(date +%s)
get txn "/?page_id=$d_txn&sc_l3_mark=$mark"
contains txn SC-L3DB-AFTER-TXN "transactions: the page goes on after the child is killed"
lacks txn "survived=" "transactions: the call did not finish"
has "$T" "layer3 plugin:sc-l3db left a transaction open on the worker's connection: rolled back" "transactions: the worker rolled back what the dead child left open"
is "$(db_exec "SELECT COUNT(*) FROM wp_sc_l3db_items WHERE name = 'orphan'")" 0 "transactions: the dead child's write is not in the database"
is "$(db_exec "SELECT option_value FROM wp_options WHERE option_name = 'sc_l3_neighbour_mark'")" "$mark" \
  "transactions: a later write in the same request (another plugin's) committed, not swallowed by the open transaction"
# Left open on a normal return: a START TRANSACTION behind a comment, and autocommit turned off.
# Read from the server's state, not the SQL: rolled back, autocommit restored, core's write commits.
# (txo: behind a comment; chain: after trying completion_type = CHAIN; the plugin's own `query`
# filter answers the stand-in's state read with "nothing open" if it is ever mirrored; throw: a
# `query` filter in the worker throws while the plugin's query runs, caught around the shortcodes.)
for c in txo:open1 chain:chain1 throw:thrown1; do
  n=${c%%:*} row=${c#*:}
  eval "pg=\$d_$n"
  T=$(now); sleep 1
  mark=m$$${n}$(date +%s)
  get "$n" "/?page_id=$pg&sc_l3_mark=$mark&sc_l3_throw=1&sc_l3_session=1"
  [ "$n" = throw ] || want "$n" returned yes "transactions ($n): the call returned normally"
  has "$T" "layer3 plugin:sc-l3db left a transaction open on the worker's connection: rolled back" "transactions ($n): the worker rolled back what the plugin left open"
  is "$(db_exec "SELECT COUNT(*) FROM wp_sc_l3db_items WHERE name = '$row'")" 0 "transactions ($n): the plugin's uncommitted row is not in the database"
  is "$(db_exec "SELECT option_value FROM wp_options WHERE option_name = 'sc_l3_neighbour_mark'")" "$mark" \
    "transactions ($n): core's later write in the same request committed"
  is "$(verdict "$n" core_rows)" 5 "transactions ($n): core's next query on the connection is unaffected"
done
has "$T" "layer3 plugin:sc-l3db hook query not mirrored: it shapes SQL the worker runs" "hooks: the plugin's own query filter is never mirrored into the worker"
want chain completion_type BLOCKED "transactions (chain): completion_type is refused"
contains throw "caught=RuntimeException" "transactions (throw): the worker's exception reached the page's own catch"
has "$T" "layer3 plugin:sc-l3db exchange aborted: the worker failed while running its query" "transactions (throw): the aborted exchange ends the channel, with a line"
# autocommit off is refused now (session state), so the plugin's write is an ordinary committed one.
T=$(now); sleep 1
mark=m$$aco$(date +%s)
get aco "/?page_id=$d_aco&sc_l3_mark=$mark"
want aco returned yes "transactions (aco): the call returned normally"
has "$T" "layer3 plugin:sc-l3db database refused: it changes the worker connection's session state" "transactions (aco): SET autocommit is refused"
is "$(db_exec "SELECT option_value FROM wp_options WHERE option_name = 'sc_l3_neighbour_mark'")" "$mark" "transactions (aco): core's later write committed"
# Session state: the allowlist, and core's next queries see the session as it was.
get sbase "/?page_id=$d_err&sc_l3_session=1"
get session "/?page_id=$d_session&sc_l3_session=1"
for c in names group_concat big_selects; do want session "$c" OK "session: allowed"; done
for c in completion_type select_limit read_only sql_mode autocommit time_zone isolation hidden names_other chain; do want session "$c" BLOCKED "session: refused"; done
sess=$(verdict sbase session)
is "$(verdict session session)" "$sess" "session: core's next query sees the session unchanged ($sess)"
is "$(verdict session core_rows)" 5 "session: core's LIMIT 5 query returns 5 rows (no sql_select_limit)"
# dbResultBytes against a result far over it (40 MiB, cap 64 KiB): refused while the rows are
# copied, and the worker stays within memory_limit.
get huge "/?page_id=$d_huge&sc_l3_peak=1"
is "$(status_of huge)" 200 "result cap: the 40 MiB result's page renders (no memory_limit fatal)"
contains huge SC-L3DB-AFTER-HUGE "result cap: the rest of the page is there"
want huge huge BLOCKED "result cap"
want huge error dbResultBytes "result cap"
peak=$(verdict huge peak)
if [ -n "$peak" ] && [ "$peak" -lt 20000000 ]; then pass "result cap: the worker's peak memory stayed at $peak bytes, under the 40 MiB result"; else fail "result cap: the worker's peak memory stayed under 20 MB" "'$peak'"; fi
# A million one-byte rows under the 4 MiB cap: refused early (each row counts ~200 bytes), the
# worker's memory bounded.
get tiny "/?page_id=$d_tiny&sc_l3_peak=1"
is "$(status_of tiny)" 200 "result cap: the million-row page renders"
contains tiny SC-L3DB-AFTER-TINY "result cap: the rest of the page is there"
want tiny tiny BLOCKED "result cap: a million tiny rows"
want tiny error dbResultBytes "result cap: a million tiny rows"
peak=$(verdict tiny peak)
if [ -n "$peak" ] && [ "$peak" -lt 20000000 ]; then pass "result cap: the worker's peak memory for a million rows stayed at $peak bytes"; else fail "result cap: the worker's peak memory for a million rows stayed under 20 MB" "'$peak'"; fi
# The error the child sees names neither the database nor its user.
get err "/?page_id=$d_err"
e=$(verdict err err)
case "$e" in *sc_l3db_nope*) pass "errors: the child sees the error ($e)" ;; *) fail "errors: the child sees the error" "'$e'" ;; esac
case "$e" in "[1146] "*) pass "errors: with its code" ;; *) fail "errors: with its code" "'$e'" ;; esac
case "$e" in *wordpress*) fail "errors: the database name is taken out" "'$e'" ;; *) pass "errors: the database name is taken out" ;; esac
# The statement cap is the time left: two 1 s statements in a 1.5 s call end at ~1.5 s, not 2.
get sleeps "/?page_id=$d_sleeps"
contains sleeps SC-L3DB-AFTER-SLEEPS "time cap: the page goes on"
lacks sleeps "slept=" "time cap: the call did not finish"
s=$(cut -d' ' -f2 "$dir/sleeps.meta")
if awk "BEGIN { exit !($s < 1.85) }"; then pass "time cap: the second statement was cut at the time left ($s s)"; else fail "time cap: the second statement was cut at the time left" "$s s"; fi
# The secrets: the child has no database password, in its environment or its memory.
if on_microvm; then
  na "secrets: the child's environment and memory scanned for the DB password" "the child runs in the guest; the scan reads /proc in the php container"
else
scan_secrets secrets
want secrets isolated 1 "secrets"
want secrets scanned yes "secrets: the process was scanned while it ran the call"
want secrets getenv 0 "secrets: getenv() is empty"
want secrets env_superglobal 0 "secrets: \$_ENV is empty"
want secrets db_password_const undefined "secrets: no DB_PASSWORD constant"
scan_is secrets environ 0 "secrets: the child's environment (/proc/<pid>/environ) is empty"
bytes=$(scan_val secrets bytes)
if [ -n "$bytes" ] && [ "$bytes" -gt 4000000 ]; then pass "secrets: read $bytes bytes of the child's memory"; else fail "secrets: read the child's memory" "'$bytes' bytes"; fi
scan_is secrets found_0 0 "secrets: the DB password is nowhere in the child's memory"
scan_is secrets found_1 0 "secrets: nor a salt"
if [ "$(scan_val secrets found_2)" -gt 0 ] 2>/dev/null; then pass "secrets: control: the scan finds WordPress's strings in it"; else fail "secrets: control: the scan finds WordPress's strings" "$(scan_val secrets found_2)"; fi
fi

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
# The gateway runs what layer 2 allows: with layer 2 off, the refused queries run.
get dbl2off "/?page_id=$d_l2"
want dbl2off isolated 1 "l2off: db"
for c in core-table statement cross-plugin; do want dbl2off "$c" OK "l2off: db (the refusals were layer 2's)"; done
get dbrw3 "/?page_id=$d_rw"
want dbrw3 get_results OK "l2off: db"

# --- 3b. the same plugin unisolated: the same verdicts and lines ------------------------------
echo "# the database probe unisolated (layer 3 off, layer 2 enforce)"
use unisolated
T=$(now); sleep 1
get udbl2 "/?page_id=$d_l2"
want udbl2 isolated 0 "unisolated: the probe runs in the worker"
for c in core-table statement cross-plugin; do want udbl2 "$c" BLOCKED "unisolated"; done
sleep 1
phplog "$T" | grep -o 'securecore: layer2 [a-z]* plugin:sc-l3db .*' | sort -u > "$dir/l2-unisolated.lines"
if [ -s "$dir/l2-isolated.lines" ] && cmp -s "$dir/l2-isolated.lines" "$dir/l2-unisolated.lines"; then
  pass "layer 2's lines for the isolated plugin are the unisolated plugin's ($(wc -l < "$dir/l2-isolated.lines") distinct)"
else
  fail "layer 2's lines for the isolated plugin are the unisolated plugin's" "$(diff "$dir/l2-isolated.lines" "$dir/l2-unisolated.lines" | tr '\n' ' ')"
fi
get udbrw "/?page_id=$d_rw"
for c in dbdelta insert get_row update replace get_var get_col get_results transaction delete counter_written; do want udbrw "$c" OK "unisolated: db"; done
cost_worker=$(cost tuni)
case "$cost_worker" in
  [0-9]*) pass "db: the same query unisolated costs $cost_worker µs; the gateway adds $(echo "$cost_isolated - $cost_worker" | awk '{ printf "%.1f", $1 - $3 }') µs per query" ;;
  *) fail "db: the cost page unisolated" "'$cost_worker'" ;;
esac
# Layer 2 reads SQL that is not UTF-8 too (it was skipped before #94): refused unisolated as well.
T=$(now); sleep 1
get udbl3 "/?page_id=$d_l3"
want udbl3 not-utf8-direct BLOCKED "unisolated: SQL that isn't UTF-8, straight to mysqli"
has "$T" "layer2 enforce plugin:sc-l3db mysqli_query protected-column select wp_users" "unisolated: layer 2 refuses it on what it says"
# The caps' revert: in the worker nothing caps the plugin's queries.
get umany "/?page_id=$d_many"
want umany ran 80 "unisolated: no query cap"
get ubig "/?page_id=$d_big"
want ubig big OK "unisolated: no result cap"
get usleep "/?page_id=$d_sleep"
if [ "$(secs_of usleep)" -ge 5 ]; then pass "unisolated: the 5 s statement held the page ($(cut -d' ' -f2 "$dir/usleep.meta") s)"; else fail "unisolated: the 5 s statement held the page" "$(cut -d' ' -f2 "$dir/usleep.meta") s"; fi

# --- 4. revert: layer 3 off --------------------------------------------------------------------
echo "# revert: layer 3 off (layer 2 log)"
use revert
in_php "rm -f $content/uploads/sc-l3-up.txt $content/uploads/sc-l3probe/w.txt $probe/w.txt"
get rmain "/?p=$p_main"
contains rmain 'probe-in-worker' "revert: the probe's code is in the worker"
is "$(pid_after rmain 'l3 filter pid=')" "$(pid_after rmain 'neighbour pid=')" "revert: the filter ran in the worker"
get rprobe "/?p=$p_probe"
if on_microvm; then
  for c in write-own write-uploads read-config read-securecore-json; do want rprobe "$c" OK "revert"; done
  want rprobe write-plugin-dir BLOCKED "revert (layer 1: the guest's site disk is read-only)"
  na "revert: net-db is OK" "the probe connects to the name db, which the guest doesn't have (its database is 127.0.0.1:3306 through the host)"
else
  for c in write-own write-uploads write-plugin-dir read-config read-securecore-json net-db; do want rprobe "$c" OK "revert"; done
fi
get rloop "/?p=$p_loop"
contains rloop "loop-finished" "revert: the loop ran to the end"
if [ "$(secs_of rloop)" -ge 7 ]; then pass "revert: the loop held the page for $(cut -d' ' -f2 "$dir/rloop.meta") s"; else fail "revert: the loop held the page for 8 s" "$(cut -d' ' -f2 "$dir/rloop.meta") s"; fi
get rmem "/?p=$p_mem"
if [ "$(status_of rmem)" != 200 ] || ! grep -qF SC-L3-AFTER-MEMORY "$dir/rmem"; then pass "revert: too much memory kills the page ($(status_of rmem))"; else fail "revert: too much memory kills the page" "200 with content"; fi
# The secrets' control: the same scan of the worker serving the call does find the DB password.
if on_microvm; then
  na "revert: the worker's memory scan finds the DB password" "the worker runs in the guest"
else
  scan_secrets rsecrets
  want rsecrets isolated 0 "revert: the secrets probe runs in the worker"
  n=$(scan_val rsecrets found_0)
  if [ -n "$n" ] && [ "$n" -gt 0 ]; then pass "revert: the worker's memory holds the DB password ($n times), so the scan finds it"; else fail "revert: the worker's memory holds the DB password" "'$n'"; fi
fi
get rdbl2 "/?page_id=$d_l2"
for c in core-table statement cross-plugin; do want rdbl2 "$c" OK "revert (layer 2 log): db"; done

echo
na_summary
if [ "$fails" -eq 0 ]; then echo "all ext-layer3 checks passed"; else echo "$fails check(s) failed"; fi
[ "$fails" -eq 0 ]
