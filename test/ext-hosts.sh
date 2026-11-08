#!/bin/sh
# E5 integration tests for the layer-2 outbound hostname allowlist (addiscorp/securecore#53), on
# its own extension stack (compose project securecore-hosts, port 8092, beside the stacks on
# 8088/8089/8091). A probe plugin (test/ext/hosts-plugin) and a core mu-plugin
# (test/ext/hosts-mu/securecore-loader.php) attempt one outbound connection per network route, to
# an allowed and to a disallowed host, on ?sc_hosts=run and print "<case>=OK|BLOCKED|SKIP".
#
# No internet is needed: a single nginx helper joins the stack's network under several aliases and
# answers every name (and its own IP) with "REACHED"; redirector.test 302s to disallowed.test.
# Every "disallowed" target is thus really reachable, just not in the allowlist — so in log/off
# mode every case reaches it and prints OK (the revert proof), while in enforce the refused ones
# print BLOCKED.
#
# It checks, for each route: an allowed host is reached and a disallowed one refused in enforce,
# logged+allowed in log, allowed with the hosts layer off; a redirect allowed→disallowed refused
# at the hop; a disallowed IP literal, an allowed.example@evil URL, and CURLOPT_RESOLVE /
# CONNECT_TO overrides pointing an allowed name at a disallowed address all refused; and that core
# is restricted to core.hosts. Then it quotes the enforce-mode refusals (the revert proof is the
# log run flipping every one to OK).
#
#   DOCKER_CONTEXT=colima test/ext-hosts.sh
#   SECURECORE_EXT_PROJECT / SECURECORE_EXT_PORT override the project / port.
set -u
cd "$(dirname "$0")/.." || exit 1
project=${SECURECORE_EXT_PROJECT:-securecore-hosts}
port=${SECURECORE_EXT_PORT:-8092}
base=http://127.0.0.1:$port
dir=.tmp/ext-hosts
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete 2>/dev/null
html=/var/www/html
conf=$html/securecore.json
content=$html/wp-content
plugindir=$content/plugins/securecore-hosts-probe
mudir=$content/mu-plugins
helper=${project}-hoststest
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }
compose() { SECURECORE_PORT=$port docker compose -f docker/compose.yml -f docker/compose.ext.yml -p "$project" "$@"; }
wp() { compose run --rm -T cli wp "$@" 2>>"$dir/wp.err" | tr -d '\r'; }
in_php() { compose exec -T php sh -c "$1"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$base$1"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
php_state() { docker inspect -f '{{.State.Status}}' "$(compose ps -aq php)" 2>/dev/null; }
wait_200() { i=0; until [ "$(code /)" = 200 ]; do i=$((i + 1)); [ "$i" -lt 60 ] || return 1; sleep 1; done; }
put_live() { compose exec -T php sh -c "cat > $conf.new && mv $conf.new $conf" < "$1"; }
put() { compose cp "$1" "php:$conf" >>"$dir/cp.log" 2>&1; }
# The layer2 net audit lines php-fpm logged since <time>.
audit() { compose logs --no-log-prefix --since "$1" php 2>&1 | sed -n 's/.*securecore: //p' | grep '^layer2 .* net '; }
has() { if audit "$1" | grep -qF "$2"; then pass "$3"; else fail "$3" "no net audit line matching '$2'"; fi; }
hasnt() { if audit "$1" | grep -qF "$2"; then fail "$3" "unexpected line '$2'"; else pass "$3"; fi; }

# --- stack ------------------------------------------------------------------------------------
echo "building and starting the hosts stack (project $project, $base)"
compose build php > "$dir/build.log" 2>&1 || { echo "FAIL docker build (see $dir/build.log)"; exit 1; }
compose up -d db php web > "$dir/up.log" 2>&1 || { echo "FAIL compose up (see $dir/up.log)"; exit 1; }
i=0
until [ "$(php_state)" = running ] && compose exec -T php sh -c 'grep -q "^php-fpm" /proc/1/comm' >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 120 ] || { echo "FAIL php-fpm did not start"; exit 1; }
  sleep 1
done
i=0
until compose exec -T db mariadb -uwordpress -pwordpress-db-password -e 'select 1' wordpress >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "FAIL database did not start"; exit 1; }
  sleep 1
done
# Install, and retry until the front page actually serves 200 (is-installed can report a
# half-initialised fresh volume as installed, so gate on the real page, not on its exit code).
i=0
until [ "$(code /)" = 200 ]; do
  wp core install --url="$base" --title=SecureCore --admin_user=admin \
    --admin_password=securecore-demo --admin_email=admin@example.com --skip-email >>"$dir/wp.err" 2>&1 || true
  i=$((i + 1)); [ "$i" -lt 12 ] || { echo "FAIL WordPress did not install (see $dir/wp.err)"; exit 1; }
  sleep 2
done

# --- the no-internet helper (nginx under several aliases) -------------------------------------
net=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$(compose ps -q php)" | awk '{print $1}')
[ -n "$net" ] || { echo "FAIL could not find the stack network"; exit 1; }
cat > "$dir/helper.conf" <<'NGINX'
server {
  listen 80 default_server;
  server_name _;
  location / { add_header Content-Type text/plain; return 200 "REACHED\n"; }
}
server {
  listen 80;
  server_name redirector.test;
  location / { return 302 http://disallowed.test/; }
}
NGINX
docker rm -f "$helper" >/dev/null 2>&1
docker create --name "$helper" --network "$net" \
  --network-alias allowed.test --network-alias disallowed.test --network-alias redirector.test \
  --network-alias a.wild.test --network-alias allowed-resolve.test --network-alias allowed-connect.test \
  --network-alias core-allowed.test \
  nginx:1.27-alpine >>"$dir/helper.log" 2>&1 || { echo "FAIL could not create the helper"; exit 1; }
docker cp "$dir/helper.conf" "$helper:/etc/nginx/conf.d/default.conf" >>"$dir/helper.log" 2>&1
docker start "$helper" >>"$dir/helper.log" 2>&1 || { echo "FAIL could not start the helper"; exit 1; }
ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "$helper")
[ -n "$ip" ] || { echo "FAIL helper has no IP on $net"; exit 1; }
echo "helper $helper on $net at $ip (aliases allowed.test disallowed.test redirector.test a.wild.test allowed-resolve.test allowed-connect.test core-allowed.test)"

# --- fixtures ---------------------------------------------------------------------------------
in_php "rm -rf $plugindir && mkdir -p $plugindir $mudir"
compose cp test/ext/hosts-plugin/securecore-hosts-probe.php "php:$plugindir/securecore-hosts-probe.php" >>"$dir/cp.log" 2>&1
compose cp test/ext/hosts-mu/securecore-loader.php "php:$mudir/securecore-loader.php" >>"$dir/cp.log" 2>&1
in_php "chown -R www-data:www-data $plugindir $mudir"
wp plugin activate securecore-hosts-probe >/dev/null

cleanup() {
  wp plugin deactivate securecore-hosts-probe >/dev/null 2>&1
  in_php "rm -rf $plugindir $mudir/securecore-loader.php"
  docker rm -f "$helper" >/dev/null 2>&1
  compose cp ext/examples/wordpress.json "php:$conf" >/dev/null 2>&1
  compose restart php >/dev/null 2>&1
}
trap cleanup EXIT

# --- configs (layer 2 only; the probe plugin and core are what differ) ------------------------
cfg() { # $1 = mode, $2 = file
  cat > "$dir/$2.json" <<JSON
{
  "layer1": { "enabled": false },
  "layer2": {
    "enabled": true, "app": "wordpress", "mode": "$1",
    "vault": { "from": "wp-config.php", "secrets": ["DB_PASSWORD"] },
    "core": { "hosts": ["core-allowed.test"] },
    "default": { "hosts": [] },
    "components": {
      "securecore-hosts-probe": { "hosts": ["allowed.test", "redirector.test", "*.wild.test", "allowed-resolve.test", "allowed-connect.test"] }
    }
  },
  "layer3": { "enabled": false }
}
JSON
}
cfg enforce enforce
cfg log     log
cfg off     off

put "$dir/enforce.json"
compose restart php >/dev/null 2>&1
wait_200 || { echo "FAIL front page never served 200"; exit 1; }

# run <config> : apply, fetch the report, return the log window start in $T.
run() {
  put_live "$dir/$1.json"
  sleep 1.3 # > RELOAD_INTERVAL
  T=$(now); sleep 1
  curl -s "$base/?sc_hosts=run&ip=$ip" > "$dir/out.$1"
  sleep 1
}
verdict() { sed -n "s/^$2=//p" "$dir/out.$1"; }
want() { # $1 config $2 case $3 expected
  v=$(verdict "$1" "$2")
  if [ "$v" = SKIP ]; then echo "skip $1: $2 (extension not built)"; return; fi
  if [ "$v" = "$3" ]; then pass "$1: $2 is $3"; else fail "$1: $2 is $3" "got '$v'"; fi
}

# Group A: a disallowed target — BLOCKED in enforce, OK in log and off (reachable both times).
GROUP_A="stream-disallowed fopen-disallowed get_headers-disallowed userinfo-evil ip-literal \
stream-redirect fsockopen-disallowed pfsockopen-disallowed ssc-disallowed socket-connect-disallowed \
curl-disallowed curl-array-disallowed curlmulti-disallowed curl-resolve-evil curl-connectto-evil \
curl-redirect curl-copy-disallowed"
# Group B: an allowed host — OK in every mode.
GROUP_B="stream-allowed wildcard-allowed fsockopen-allowed ssc-allowed curl-allowed curl-copy-allowed"
# Enforce-only: refused in enforce; in log/off the call behaves in an extension-specific way we
# don't pin (a file:// read succeeds in log; gopher/no-url fail in libcurl regardless).
ENFORCE_ONLY="curl-file curl-gopher curl-nostate soap-disallowed"

echo "# enforce"
run enforce
for c in $GROUP_A; do want enforce "$c" BLOCKED; done
for c in $GROUP_B; do want enforce "$c" OK; done
for c in $ENFORCE_ONLY; do want enforce "$c" BLOCKED; done
want enforce core-allowed OK
want enforce core-disallowed BLOCKED
# audit lines
has "$T" "layer2 enforce plugin:securecore-hosts-probe net open host disallowed.test" "enforce: stream to disallowed is a net refusal"
has "$T" "layer2 enforce plugin:securecore-hosts-probe net open host disallowed.test http://allowed.test@disallowed.test/" "enforce: the userinfo URL is attributed to its real host"
has "$T" "layer2 enforce plugin:securecore-hosts-probe net curl_exec host disallowed.test" "enforce: curl to disallowed is a net refusal"
has "$T" "layer2 enforce plugin:securecore-hosts-probe net curl_exec host $ip" "enforce: the CURLOPT_RESOLVE override to a disallowed IP is refused"
has "$T" "layer2 enforce plugin:securecore-hosts-probe net curl_redirect host disallowed.test" "enforce: a curl FOLLOWLOCATION redirect is refused at the hop"
has "$T" "layer2 enforce plugin:securecore-hosts-probe net curl_exec scheme file" "enforce: a curl file:// URL is refused by the scheme restriction"
has "$T" "layer2 enforce plugin:securecore-hosts-probe net curl_exec no-url" "enforce: a handle with no recorded URL fails closed"
has "$T" "layer2 enforce core net open host allowed.test" "enforce: core is restricted to core.hosts"

echo "# log (the revert proof: every refusal above now reaches and is OK, and is logged)"
run log
for c in $GROUP_A; do want log "$c" OK; done
for c in $GROUP_B; do want log "$c" OK; done
want log core-allowed OK
want log core-disallowed OK
has "$T" "layer2 log plugin:securecore-hosts-probe net open host disallowed.test" "log: the refusal is recorded"
has "$T" "layer2 log plugin:securecore-hosts-probe net curl_redirect host disallowed.test" "log: the curl redirect hop is recorded and then followed"
has "$T" "layer2 log core net open host allowed.test" "log: core's refusal is recorded"

echo "# off (nothing checked, nothing logged)"
run off
for c in $GROUP_A $GROUP_B; do want off "$c" OK; done
want off core-allowed OK
want off core-disallowed OK
hasnt "$T" "layer2 " "off: no layer2 line at all"

# --- the enforce-mode refusals, quoted (the revert proof is the log run flipping them to OK) ---
echo "# enforce-mode refusals (each flipped to OK in log mode above):"
sed -n 's/\(.*\)=BLOCKED/  \1/p' "$dir/out.enforce"

echo
if [ "$fails" -eq 0 ]; then echo "ext-hosts: all checks passed"; else echo "ext-hosts: $fails checks FAILED"; fi
exit "$([ "$fails" -eq 0 ] && echo 0 || echo 1)"
