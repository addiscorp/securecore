#!/bin/sh
# E4 integration tests for the layer-2 database policy (addiscorp/securecore#53), on the extension
# stack test/ext-config.sh leaves up (default project securecore-ext, port 8089; this branch was
# run as SECURECORE_EXT_PROJECT=securecore-db SECURECORE_EXT_PORT=8093). A probe plugin
# (test/ext/db-plugin, slug securecore-db-probe) sends every case through every query route —
# mysqli_query, mysqli_real_query, mysqli::query / real_query, multi_query (both), the prepare
# routes (mysqli_prepare, mysqli::prepare, mysqli_stmt_prepare, mysqli_stmt::prepare,
# new mysqli_stmt, mysqli_execute_query, mysqli::execute_query), PDO::query / exec / prepare (and
# silent mode), and $wpdb->query — and prints <route>|<case>=BLOCKED (SecureCore's error) or
# RAN:<errno> (it reached the server, whatever the server said). Configs:
#   1. enforce, no grants: its own table and option RAN, everything else BLOCKED on every route,
#      with an audit line per rule; strict-mode mysqli throws 1142; select_db and an unsafe charset
#      are refused; $wpdb returns false with last_error set (no fatal: the page prints DONE).
#   2. log: every case RAN (the revert proof: the refusals in 1 become successes), audit lines say
#      "layer2 log".
#   3. off: every case RAN and no layer2 line.
#   4. enforce with posts:read, users:read, options:write: core-posts now RAN; user_pass, the users
#      wildcard, the protected option, another plugin's table and the shape refusals stay BLOCKED.
#   5. core: may read user_pass and write siteurl, runs and logs an unparseable query, but is held
#      to the statement allowlist (PREPARE, SET @ BLOCKED).
#   6. the extension unloaded: every case RAN (the check removed altogether).
# Exits non-zero on any failure. Writes .tmp/ext-db/. Restores examples/wordpress.json at the end.
#   DOCKER_CONTEXT=colima test/ext-config.sh && DOCKER_CONTEXT=colima test/ext-db.sh
set -u
cd "$(dirname "$0")/.." || exit 1
project=${SECURECORE_EXT_PROJECT:-securecore-ext}
port=${SECURECORE_EXT_PORT:-8089}
base=http://127.0.0.1:$port
dir=.tmp/ext-db
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete 2>/dev/null
html=/var/www/html
conf=$html/securecore.json
ini=/usr/local/etc/php/conf.d/securecore.ini
plugin=$html/wp-content/plugins/securecore-db-probe
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }
compose() { SECURECORE_PORT=$port docker compose -f docker/compose.yml -f docker/compose.ext.yml -p "$project" "$@"; }
wp() { compose run --rm -T cli wp "$@" 2>>"$dir/wp.err" | tr -d '\r'; }
in_php() { compose exec -T php sh -c "$1"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$base$1"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
wait_200() { i=0; until [ "$(code /)" = 200 ]; do i=$((i + 1)); [ "$i" -lt 60 ] || return 1; sleep 1; done; }
put_live() { compose exec -T php sh -c "cat > $conf.new && mv $conf.new $conf" < "$1"; }
audit() { compose logs --no-log-prefix --since "$1" php 2>&1 | sed -n 's/.*securecore: //p' | grep '^layer2 '; }
has() { if audit "$1" | grep -qF "$2"; then pass "$3"; else fail "$3" "no layer2 line matching '$2'"; fi; }

[ "$(code /)" = 200 ] || { echo "FAIL the extension stack is not up on $base: run test/ext-config.sh first"; exit 1; }

# --- fixtures: the probe, its own table, another plugin's table, the core probe ----------------
in_php "rm -rf $plugin && mkdir -p $plugin"
compose cp test/ext/db-plugin/securecore-db-probe.php "php:$plugin/securecore-db-probe.php" >>"$dir/cp.log" 2>&1
compose cp test/ext/db-core.php "php:$html/sc-db-core.php" >>"$dir/cp.log" 2>&1
in_php "chown -R www-data:www-data $plugin"
dbq() { compose exec -T db mariadb -uwordpress -pwordpress-db-password wordpress -e "$1"; }
dbq "CREATE TABLE IF NOT EXISTS wp_securecore_db_probe (id INT AUTO_INCREMENT PRIMARY KEY, note VARCHAR(64)); CREATE TABLE IF NOT EXISTS wp_otherplugin_data (id INT);"
wp plugin activate securecore-db-probe >/dev/null

cleanup() {
  wp plugin deactivate securecore-db-probe >/dev/null 2>&1
  in_php "rm -rf $plugin $html/sc-db-core.php"
  dbq "DROP TABLE IF EXISTS wp_securecore_db_probe, wp_otherplugin_data" >/dev/null 2>&1
  [ -f "$dir/securecore.ini" ] && compose cp "$dir/securecore.ini" "php:$ini" >/dev/null 2>&1
  compose cp ext/examples/wordpress.json "php:$conf" >/dev/null 2>&1
  compose restart php >/dev/null 2>&1
  wait_200 || echo "FAIL php-fpm did not come back after cleanup"
}
trap cleanup EXIT

# --- configs: layer 2 only, no vault (the probe opens its own connections with DB_PASSWORD) -----
cfg() { # $1 = name, $2 = mode, $3 = the probe's grants
  cat > "$dir/$1.json" <<JSON
{
  "layer1": { "enabled": false },
  "layer2": {
    "enabled": true, "app": "wordpress", "mode": "$2",
    "default": { "tables": "own", "options": "own" },
    "components": { "securecore-db-probe": { "grants": [$3] } }
  },
  "layer3": { "enabled": false }
}
JSON
}
cfg enforce enforce ''
cfg log log ''
cfg off off ''
cfg granted enforce '"posts:read", "users:read", "options:write"'

# The vault is read at startup only: restart php-fpm once on a vault-less config, so DB_PASSWORD is
# the real value and the probe can open its own mysqli and PDO connections (the policy is per
# call, on every connection, not only $wpdb's).
compose cp "$dir/enforce.json" "php:$conf" >>"$dir/cp.log" 2>&1
compose restart php >/dev/null 2>&1
wait_200 || { echo "FAIL php-fpm did not come back on the vault-less config"; exit 1; }

run() { # $1 = config: apply it, run the probe and the core probe; T = the log window start
  put_live "$dir/$1.json"
  sleep 1.3 # > RELOAD_INTERVAL, so every worker has the new config
  T=$(now); sleep 1
  curl -s "$base/?sc_db=run" > "$dir/out.$1"
  curl -s "$base/sc-db-core.php" > "$dir/core.$1"
  sleep 1
}
# The 18 routes the probe reports, one per line (one has a space in its name).
routes='mysqli_query
mysqli_real_query
mysqli::query
mysqli::real_query
mysqli_multi_query
mysqli::multi_query
mysqli_prepare
mysqli::prepare
mysqli_stmt_prepare
mysqli_stmt::prepare
new mysqli_stmt
mysqli_execute_query
mysqli::execute_query
PDO::query
PDO::exec
PDO::prepare
PDO::query(silent)
wpdb::query'
nl='
'
own_cases="own-select own-insert own-option"
refused_cases="other-table core-posts user-pass users-star protected-opt prepare set-var load-file outfile multi comment-trick ansi-quotes"
# expect <config> <case> <BLOCKED|RAN>: every route agrees (RAN matches RAN:<any errno>).
expect() {
  bad=""
  old_ifs=$IFS; IFS=$nl
  for r in $routes; do
    v=$(grep -F "$r|$2=" "$dir/out.$1" | head -1 | sed 's/.*=//')
    case "$3:$v" in BLOCKED:BLOCKED|RAN:RAN:*) ;; *) bad="$bad [$r]=$v" ;; esac
  done
  IFS=$old_ifs
  if [ -z "$bad" ]; then pass "$1: $2 is $3 on all 18 routes"; else fail "$1: $2 is $3 on all 18 routes" "$bad"; fi
}
line() { grep -F "$2" "$dir/out.$1" | head -1 | sed 's/.*=//'; }
# coreline <config> <case>: the core probe's verdict.
coreline() { grep -F "core|$2=" "$dir/core.$1" | head -1 | sed 's/.*=//'; }
completed() { if grep -qx DONE "$dir/out.$1"; then pass "$1: the probe ran to the end (no fatal)"; else fail "$1: the probe ran to the end (no fatal)" "$(tail -3 "$dir/out.$1" | tr '\n' ' ')"; fi; }

# --- 1. enforce, no grants ----------------------------------------------------------------------
echo "# enforce (no grants)"
run enforce
completed enforce
for c in $own_cases; do expect enforce "$c" RAN; done
for c in $refused_cases; do expect enforce "$c" BLOCKED; done
is_() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3" "got '$1', want '$2'"; fi; }
is_ "$(line enforce 'strict|user-pass=')" BLOCKED "enforce: strict-mode mysqli throws mysqli_sql_exception 1142"
is_ "$(line enforce 'select_db|use=')" BLOCKED "enforce: a component's select_db is refused"
is_ "$(line enforce 'set_charset|gbk=')" BLOCKED "enforce: set_charset('gbk') is refused"
p=plugin:securecore-db-probe
has "$T" "layer2 enforce $p mysqli_query protected-column select wp_users" "enforce: user_pass audit line (route, rule, statement, table)"
has "$T" "layer2 enforce $p mysqli_query core-table select wp_posts" "enforce: core table without a grant"
has "$T" "layer2 enforce $p mysqli_query table select wp_otherplugin_data" "enforce: another plugin's table"
has "$T" "layer2 enforce $p mysqli_query protected-option update wp_options" "enforce: a protected option write"
has "$T" "layer2 enforce $p mysqli_query prepare prepare -" "enforce: PREPARE"
has "$T" "layer2 enforce $p mysqli_query user-variable set -" "enforce: SET @"
has "$T" "layer2 enforce $p mysqli_query server-file select -" "enforce: LOAD_FILE / INTO OUTFILE"
has "$T" "layer2 enforce $p mysqli_query multi-statement select -" "enforce: multi-statement"
has "$T" "layer2 enforce $p mysqli_query executable-comment" "enforce: /*! */ comment trick"
has "$T" "layer2 enforce $p mysqli_query sql-mode set -" "enforce: ANSI_QUOTES"
has "$T" "layer2 enforce $p mysqli_prepare protected-column select wp_users" "enforce: the prepare route is checked at prepare"
has "$T" "layer2 enforce $p pdo::exec protected-column select wp_users" "enforce: PDO::exec"
has "$T" "layer2 enforce $p mysqli_stmt::__construct protected-column select wp_users" "enforce: new mysqli_stmt"
for c in user-pass siteurl unparseable; do is_ "$(coreline enforce "$c" | cut -c1-3)" RAN "core: $c RAN (core is unrestricted)"; done
for c in prepare set-var; do is_ "$(coreline enforce "$c")" BLOCKED "core: $c BLOCKED (the allowlist applies to core)"; done
has "$T" "layer2 enforce core mysqli_query unparseable" "core: the unparseable query is logged"

# --- 2. log: the revert proof -------------------------------------------------------------------
echo "# log (nothing blocked)"
run log
completed log
for c in $own_cases $refused_cases; do expect log "$c" RAN; done
is_ "$(line log 'strict|user-pass=' | cut -c1-3)" RAN "log: strict-mode mysqli reads user_pass"
is_ "$(line log 'select_db|use=' | cut -c1-3)" RAN "log: select_db runs"
has "$T" "layer2 log $p mysqli_query protected-column select wp_users" "log: the would-be refusal is recorded"
for c in prepare set-var; do is_ "$(coreline log "$c" | cut -c1-3)" RAN "log: core $c RAN"; done

# --- 3. off ------------------------------------------------------------------------------------
echo "# off"
run off
completed off
for c in $own_cases $refused_cases; do expect off "$c" RAN; done
if [ "$(audit "$T" | grep -cE ' (mysqli|pdo::)')" = 0 ]; then pass "off: no layer2 database lines"; else fail "off: no layer2 database lines" "$(audit "$T" | head -1)"; fi

# --- 4. enforce with grants ----------------------------------------------------------------------
echo "# enforce (posts:read, users:read, options:write)"
run granted
completed granted
for c in $own_cases core-posts; do expect granted "$c" RAN; done
for c in other-table user-pass users-star protected-opt prepare set-var load-file outfile multi comment-trick ansi-quotes; do
  expect granted "$c" BLOCKED
done

# --- 6. the extension unloaded: the check removed altogether --------------------------------------
echo "# extension unloaded"
compose cp "php:$ini" "$dir/securecore.ini" >>"$dir/cp.log" 2>&1
grep -v '^extension=' "$dir/securecore.ini" > "$dir/no-ext.ini"
compose cp "$dir/no-ext.ini" "php:$ini" >>"$dir/cp.log" 2>&1
compose restart php >/dev/null 2>&1
wait_200 || fail "unloaded: front page 200"
curl -s "$base/?sc_db=run" > "$dir/out.unloaded"
completed unloaded
for c in $own_cases $refused_cases; do expect unloaded "$c" RAN; done
compose cp "$dir/securecore.ini" "php:$ini" >>"$dir/cp.log" 2>&1

echo
if [ "$fails" -eq 0 ]; then echo "all ext-db checks passed"; else echo "$fails check(s) failed"; fi
[ "$fails" -eq 0 ]
