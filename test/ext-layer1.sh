#!/bin/sh
# E6 integration tests for layer 1, the securecore-fpm launcher (addiscorp/securecore#53):
# WordPress with php-fpm started by securecore-fpm inside gelada (docker/compose.ext-layer1.yml,
# the php-layer1 image target), as its own compose project (default securecore-layer1, port
# 8090) beside the other stacks. Classic Editor, Yoast SEO and Contact Form 7 are active. A
# core-level probe (test/ext/layer1/probe.php, at the web root, so layer 2 never restricts it)
# tries each thing layer 1 decides, against listeners outside the sandbox that log what
# actually arrives (test/ext/layer1/listen.php). Run twice: with layer 2 off (layer 1 alone) and
# with layer 2 in enforce mode (1+2), both on examples/wordpress.json's layer1:
#   1. nginx → php-fpm on 9000 serves the front page (200) with the three plugins active; the
#      master and every worker carry gelada's seccomp filters and no_new_privs, workers as
#      www-data;
#   2. the DB on 3306 works (names resolve over TCP 53); 443 works, locally and to
#      api.wordpress.org;
#   3. a connect to 25 or to nginx's 80, a bind of 8081, UDP and a unix socket are refused, and
#      nothing reaches the listeners;
#   4. writes outside the listed folders are refused even from core, and from a program
#      php-fpm starts; the uploads and /tmp writes work; reading the denied path is refused;
#   5. a config with unixSockets and TCP ports is refused at launch (exit 125, naming #57), and
#      an invalid config exits 125 with the launcher's reason, in both cases without php-fpm
#      ever starting.
# The revert proof is in the PR: the same script against a launcher built without its sandbox
# step, without the #57 check, and failing open on an invalid file.
# Exits non-zero on any failure. Writes .tmp/ext-layer1/. Leaves the stack up on wordpress.json.
#   DOCKER_CONTEXT=colima test/ext-layer1.sh
#   SECURECORE_EXT_PROJECT / SECURECORE_EXT_PORT pick another project / port.
set -u
cd "$(dirname "$0")/.." || exit 1
project=${SECURECORE_EXT_PROJECT:-securecore-layer1}
port=${SECURECORE_EXT_PORT:-8090}
base=http://127.0.0.1:$port
dir=.tmp/ext-layer1
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete 2>/dev/null
html=/var/www/html
conf=$html/securecore.json
listen_log=/run/sc-l1.log
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }
is() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3" "got '$1', want '$2'"; fi; }
compose() {
  SECURECORE_PORT=$port docker compose -f docker/compose.yml -f docker/compose.ext.yml \
    -f docker/compose.ext-layer1.yml -p "$project" "$@"
}
wp() { compose run --rm -T cli wp "$@" 2>>"$dir/wp.err" | tr -d '\r'; }
in_php() { compose exec -T php sh -c "$1"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$base$1"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
php_state() { docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$(compose ps -aq php)"; }
phplog() { compose logs --no-log-prefix --since "$1" php 2>&1; }
put() { compose cp "$1" "php:$conf" >>"$dir/cp.log" 2>&1; }
wait_200() { i=0; until [ "$(code /)" = 200 ]; do i=$((i + 1)); [ "$i" -lt 60 ] || return 1; sleep 1; done; }
wait_exited() { i=0; until php_state | grep -q '^exited'; do i=$((i + 1)); [ "$i" -lt 30 ] || return 1; sleep 1; done; }
# start <config>: restart php-fpm through the launcher on <config>; echoes the log window start.
start() {
  put "$1"
  T=$(now)
  compose restart php >/dev/null 2>&1
}

# --- stack -----------------------------------------------------------------------------------
echo "building and starting the layer-1 stack (project $project, $base)"
compose build php > "$dir/build.log" 2>&1 || { echo "FAIL docker build (see $dir/build.log)"; exit 1; }
compose up -d db php web > "$dir/up.log" 2>&1 || { echo "FAIL compose up (see $dir/up.log)"; exit 1; }
# A new site volume: the entrypoint copies WordPress (and off.json) in first, then the launcher
# execs php-fpm. Wait for that, so the copy can't overwrite the config put below.
i=0
until [ "$(php_state | cut -d' ' -f1)" = running ] && in_php 'grep -q "^php-fpm" /proc/1/comm' >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 120 ] || { echo "FAIL php-fpm did not start"; exit 1; }
  sleep 1
done
i=0
until compose exec -T db mariadb -uwordpress -pwordpress-db-password -e 'select 1' wordpress >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "FAIL database did not start"; exit 1; }
  sleep 1
done
if ! wp core is-installed >/dev/null 2>&1; then
  wp core install --url="$base" --title=SecureCore --admin_user=admin \
    --admin_password=securecore-demo --admin_email=admin@example.com --skip-email >/dev/null
fi
wp plugin install classic-editor wordpress-seo contact-form-7 --activate >/dev/null || { echo "FAIL plugin install"; exit 1; }

# Fixtures: the probe at the web root (core), the listeners outside php-fpm, a denied backup
# that www-data could read by its permissions, and the writable folders owned by www-data, so
# every refusal below can only be layer 1's.
compose cp test/ext/layer1/probe.php "php:$html/sc-l1-probe.php" >>"$dir/cp.log" 2>&1
compose cp test/ext/layer1/listen.php php:/usr/local/lib/sc-l1-listen.php >>"$dir/cp.log" 2>&1
fixtures() {
  in_php "mkdir -p /srv/backups $html/wp-content/uploads $html/wp-content/cache && echo secret > /srv/backups/dump.sql && chmod 644 /srv/backups/dump.sql && chown www-data:www-data $html $html/wp-content/plugins $html/wp-content/uploads $html/wp-content/cache && rm -f $html/sc-l1-core-write.txt $html/sc-l1-child.txt $html/wp-content/plugins/sc-l1-write.txt $html/wp-content/uploads/sc-l1.txt /tmp/sc-l1.txt $listen_log"
  # `php -n`: the listener runs without the extension and outside the launcher.
  compose exec -d php php -n /usr/local/lib/sc-l1-listen.php "$listen_log"
  i=0; until in_php "grep -q ready $listen_log" 2>/dev/null; do i=$((i + 1)); [ "$i" -lt 20 ] || { fail "the listeners started"; return; }; sleep 0.5; done
}
verdict() { sed -n "s/^$2=\([A-Z]*\).*/\1/p" "$dir/probe.$1"; }
want() {
  v=$(verdict "$1" "$2")
  if [ "$v" = "$3" ]; then pass "$1: $2 is $3"; else fail "$1: $2 is $3" "$(grep "^$2=" "$dir/probe.$1" || echo 'no line')"; fi
}
arrived() { in_php "cat $listen_log" | grep -c "^$1 "; }

# layer2 enabled or not, on examples/wordpress.json's layer1.
awk '/"layer2": \{/ { l2 = 1 } l2 && /"enabled": true/ { sub(/"enabled": true/, "\"enabled\": false"); l2 = 0 } { print }' \
  ext/examples/wordpress.json > "$dir/l2-off.json"
cp ext/examples/wordpress.json "$dir/l2-enforce.json"
grep -q '"mode": "enforce"' "$dir/l2-enforce.json" || fail "examples/wordpress.json has layer 2 in enforce mode"

# --- 1-4. layer 1 alone, then layers 1+2 -----------------------------------------------------
for variant in l2-off l2-enforce; do
  echo "# layer 1 on, layer 2 ${variant#l2-}"
  start "$dir/$variant.json"
  wait_200 || { fail "$variant: php-fpm serves the front page" "$(php_state)"; continue; }
  phplog "$T" > "$dir/log.$variant"
  if grep -q "^securecore-fpm: layer 1 on from $conf (sha256 [0-9a-f]*): write $html/wp-content/uploads $html/wp-content/cache /tmp; deny /srv/backups; tcp bind 9000; tcp connect 53 3306 443; starting php-fpm$" "$dir/log.$variant"; then
    pass "$variant: the launcher logs layer 1 and its plan"
  else
    fail "$variant: the launcher logs layer 1 and its plan" "$(grep securecore-fpm "$dir/log.$variant")"
  fi
  fixtures
  is "$(code /)" 200 "$variant: nginx → php-fpm on 9000: front page 200"
  is "$(wp plugin list --status=active --field=name | grep -cxE 'classic-editor|wordpress-seo|contact-form-7')" 3 \
    "$variant: Classic Editor, Yoast SEO and Contact Form 7 are active"
  is "$(curl -s "$base/" | grep -c 'yoast-schema-graph')" 1 "$variant: the front page carries Yoast's output"
  if [ "$variant" = l2-enforce ]; then
    printf '<?php $s = securecore_status(); echo $s["layer2_mode"], "/", $s["layers"]["layer1"] ? 1 : 0;\n' > "$dir/l2.php"
    compose cp "$dir/l2.php" "php:$html/sc-l1-l2.php" >>"$dir/cp.log" 2>&1
    is "$(curl -s "$base/sc-l1-l2.php")" enforce/1 "$variant: the extension in php-fpm is enforcing layer 2"
    in_php "rm -f $html/sc-l1-l2.php"
  fi
  # Every php-fpm process: gelada's two seccomp filters on top of Docker's one, no_new_privs.
  in_php 'for d in /proc/[0-9]*; do case "$(cat $d/comm 2>/dev/null)" in php-fpm*) echo "$(grep -E "^(Uid|NoNewPrivs|Seccomp_filters):" $d/status | awk "{print \$2}" | tr "\n" " ")";; esac; done' > "$dir/procs.$variant"
  is "$(grep -c . "$dir/procs.$variant" | grep -c '^[3-9]')" 1 "$variant: a master and workers ($(grep -c . "$dir/procs.$variant") php-fpm processes)"
  is "$(grep -vc '^[0-9]* 1 3 $' "$dir/procs.$variant")" 0 "$variant: every php-fpm process has no_new_privs and 3 seccomp filters (Docker's + gelada's 2)"
  is "$(awk '$1 == 0' "$dir/procs.$variant" | grep -c .)/$(awk '$1 == 33' "$dir/procs.$variant" | grep -c . | grep -c '^[1-9]')" 1/1 \
    "$variant: the master runs as root and the workers dropped to www-data"

  curl -s "$base/sc-l1-probe.php" > "$dir/probe.$variant"
  sleep 0.5
  for c in db-3306 dns-tcp tcp-443-local tcp-443-internet write-uploads write-tmp read-wp-config; do want "$variant" "$c" OK; done
  for c in tcp-25 tcp-80-web bind-8081 udp-5353 unix-socket write-root write-plugins read-denied child-write-root; do want "$variant" "$c" BLOCKED; done
  is "$(arrived tcp-443)" 1 "$variant: the 443 connect reached its listener"
  is "$(arrived tcp-25)/$(arrived udp-5353)/$(arrived unix)" 0/0/0 "$variant: nothing reached the 25, UDP or unix-socket listeners"
  is "$(in_php "ls $html/sc-l1-core-write.txt $html/sc-l1-child.txt $html/wp-content/plugins/sc-l1-write.txt 2>/dev/null" | grep -c .)" 0 \
    "$variant: none of the refused writes left a file"
  is "$(in_php "cat $html/wp-content/uploads/sc-l1.txt /tmp/sc-l1.txt" | grep -c '^layer1 write-')" 2 "$variant: the allowed writes did"
  is "$(grep -cE '^tcp-25=BLOCKED errno=13 |^tcp-80-web=BLOCKED errno=13 ' "$dir/probe.$variant")" 2 \
    "$variant: the refused connects fail with EACCES (Landlock), not a refused connection"
done

# --- 5. refused at launch ----------------------------------------------------------------------
# refused <label> <config> <expected log text>: the launcher must exit 125 without php-fpm starting.
refused() {
  start "$2"
  if wait_exited; then pass "$1: the container exits"; else fail "$1: the container exits" "$(php_state)"; fi
  is "$(php_state | cut -d' ' -f2)" 125 "$1: the launcher exits 125"
  phplog "$T" > "$dir/refused.log"
  if grep -qF "$3" "$dir/refused.log"; then pass "$1: the log says why: $(grep -F 'securecore-fpm' "$dir/refused.log" | head -1 | cut -c1-160)…"; else fail "$1: the log says why" "$(tr '\n' ' ' < "$dir/refused.log" | cut -c1-400)"; fi
  is "$(grep -cE 'fpm is running|ready to handle connections|PHP Startup' "$dir/refused.log")" 0 "$1: php-fpm never started (no fpm or PHP startup lines)"
  c=$(code /)
  if [ "$c" != 200 ]; then pass "$1: no page is served ($c)"; else fail "$1: no page is served" "$c"; fi
}
echo "# refused at launch"
sed 's|"connect": \[{ "port": 53 }, { "port": 3306 }, { "port": 443 }\]|"connect": [{ "port": 53 }, { "port": 3306 }, { "port": 443 }], "unixSockets": ["/run/mysqld/mysqld.sock"]|' \
  ext/examples/wordpress.json > "$dir/unix-and-ports.json"
grep -q unixSockets "$dir/unix-and-ports.json" || fail "the unixSockets fixture was made"
refused "unixSockets + TCP ports" "$dir/unix-and-ports.json" \
  "securecore-fpm: $conf: layer1.network.unixSockets (/run/mysqld/mysqld.sock) can't be combined with TCP ports (layer1.network.bind/connect) yet: gelada 0.3.0 refuses a unix-socket allowlist together with port rules on Linux (addiscorp/securecore#57)"
sed 's|{ "port": 9000 }|{ "port": 0 }|' ext/examples/wordpress.json > "$dir/invalid.json"
refused "invalid config (port 0)" "$dir/invalid.json" \
  "securecore-fpm: $conf: invalid: invalid value: integer \`0\`, expected a nonzero u16"

# Back to the example.
put ext/examples/wordpress.json
compose start php >/dev/null 2>&1
if wait_200; then pass "fixed config: php-fpm starts again under layer 1"; else fail "fixed config: php-fpm starts again" "$(php_state)"; fi

echo
if [ "$fails" -eq 0 ]; then echo "all ext-layer1 checks passed"; else echo "$fails check(s) failed"; fi
[ "$fails" -eq 0 ]
