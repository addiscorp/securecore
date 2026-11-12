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
# is restricted to core.hosts. A database connect is attributed as the vault attributes it: the
# plugin's own mysqli to the DB host is refused, while a $wpdb reconnect the plugin triggers is
# core's and always works. Then it quotes the enforce-mode refusals (the revert proof is the
# log run flipping every one to OK).
#
#   DOCKER_CONTEXT=colima test/ext-hosts.sh
#   SECURECORE_EXT_PROJECT / SECURECORE_EXT_PORT override the project / port.
# On the microVM target (SC_TARGET=microvm, test/lib/target.sh) the probe runs in the guest,
# which has no network device: it reaches only its listed ports through the host, and egress only
# public addresses by name (#72). The helper is on the stack's private network, so every case
# that expects to reach it is n/a there; the refusals, the audit lines and the database cases
# (through MariaDB's socket) are checked as on the docker target.
set -u
cd "$(dirname "$0")/.." || exit 1
project=${SECURECORE_EXT_PROJECT:-securecore-hosts}
port=${SECURECORE_EXT_PORT:-8092}
dir=.tmp/ext-hosts
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete 2>/dev/null
. test/lib/target.sh
content=$html/wp-content
plugindir=$content/plugins/securecore-hosts-probe
mudir=$content/mu-plugins
helper=${project}-hoststest
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }
wp() { compose run --rm -T cli wp "$@" 2>>"$dir/wp.err" | tr -d '\r'; }
in_php() { compose exec -T php sh -c "$1"; }
# The layer2 net audit lines php-fpm logged since <mark>.
audit() { phplog "$1" | sed -n 's/.*securecore: //p' | grep '^layer2 .* net '; }
has() { if audit "$1" | grep -qF "$2"; then pass "$3"; else fail "$3" "no net audit line matching '$2'"; fi; }
hasnt() { if audit "$1" | grep -qF "$2"; then fail "$3" "unexpected line '$2'"; else pass "$3"; fi; }
# has_hop: a redirect hop's line, which needs the first request answered by the helper.
has_hop() { if on_microvm; then na "$3" "the redirect comes from the helper, which the guest never reaches, so there is no hop"; else has "$@"; fi; }

# --- stack ------------------------------------------------------------------------------------
stack_up

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
  put ext/examples/wordpress.json
  php_restart >/dev/null 2>&1
}
trap cleanup EXIT

# --- configs (layer 2 only; the probe plugin and core are what differ) ------------------------
cfg() { # $1 = mode, $2 = file
  cat > "$dir/$2.json" <<JSON
{
  "layer1": { "isolation": "off" },
  "layer2": {
    "enabled": true, "app": "wordpress", "mode": "$1",
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
php_restart >/dev/null 2>&1
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
  if on_microvm && [ "$3" = OK ]; then
    case $2 in
      own-mysqli-dbhost | wpdb-reconnect) ;; # the database: through MariaDB's socket in the guest too
      *) na "$1: $2 is OK" "the target is the helper on the stack's private network; the guest has no network device and its egress reaches only public addresses (#72)"; return ;;
    esac
  fi
  v=$(verdict "$1" "$2")
  if [ "$v" = SKIP ]; then echo "skip $1: $2 (extension not built)"; return; fi
  if [ "$v" = "$3" ]; then pass "$1: $2 is $3"; else fail "$1: $2 is $3" "got '$v'"; fi
}

# Group A: a disallowed target — BLOCKED in enforce, OK in log and off (reachable both times).
GROUP_A="stream-disallowed fopen-disallowed get_headers-disallowed userinfo-evil ip-literal \
stream-redirect fsockopen-disallowed pfsockopen-disallowed ssc-disallowed socket-connect-disallowed \
curl-disallowed curl-array-disallowed curlmulti-disallowed curl-resolve-evil curl-connectto-evil \
curl-redirect curl-copy-disallowed own-mysqli-dbhost"
# Group B: an allowed host — OK in every mode. wpdb-reconnect: the plugin makes
# $wpdb->check_connection() reconnect to the DB host, which is core's connection (the vault's
# attribution), never refused as the plugin's (#53 review, finding 5).
GROUP_B="stream-allowed wildcard-allowed fsockopen-allowed ssc-allowed curl-allowed curl-copy-allowed wpdb-reconnect"
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
has_hop "$T" "layer2 enforce plugin:securecore-hosts-probe net curl_redirect host disallowed.test" "enforce: a curl FOLLOWLOCATION redirect is refused at the hop"
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
has_hop "$T" "layer2 log plugin:securecore-hosts-probe net curl_redirect host disallowed.test" "log: the curl redirect hop is recorded and then followed"
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
na_summary
if [ "$fails" -eq 0 ]; then echo "ext-hosts: all checks passed"; else echo "ext-hosts: $fails checks FAILED"; fi
exit "$([ "$fails" -eq 0 ] && echo 0 || echo 1)"
