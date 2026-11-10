#!/bin/sh
# E3 integration tests for the vault (addiscorp/securecore#53), on the extension stack
# test/ext-config.sh leaves up (compose project securecore-ext, port 8089). Two probes — a plugin
# (test/ext/vault/plugin.php) and a core web-root script (test/ext/vault/core.php) — run the same
# routes (test/ext/vault/routine.php) and must never see the real DB password or any real salt, in
# enforce mode and in log mode. The DB password comes from an environment variable; the salts come
# from a vault file outside the docroot. Checks:
#   1. enforce: neither probe sees the real DB password or any salt by any route (getenv, $_ENV,
#      $_SERVER, phpinfo, the constants + get_defined_constants, $wpdb->dbpassword + a var_dump /
#      print_r / serialize / reflection of $wpdb, wp_salt/wp_hash, reading/including the vault file
#      and wp-config, debug_backtrace, $GLOBALS, and the error log);
#   2. log mode: the same — the vault is where the value lives, not a policy, so it hides the
#      secret in log mode too;
#   3. the vault keeps WordPress working: the DB connects, and nonces, auth cookies and password
#      reset round-trip; wp_hash is byte-identical to a known-salt HMAC — with no vault mu-plugin
#      installed, as the extension defines wp_salt/wp_hash itself;
#   3b–3d. the connect boundary: a plugin, a foreign host, a salt placeholder and the DB host on
#      another port all get the placeholder, never the value; an earlier mu-plugin defining
#      wp_salt/wp_hash can't take them over;
#   4. the backstop masks every env var whose value equals a secret, logging only the names;
#   5. revert proof: with the vault removed from the config, and with the extension unloaded, the
#      probe DOES see the real secret;
#   6. compat: Classic Editor, Yoast SEO and Contact Form 7 — front page and login still 200.
# Exits non-zero on any failure. Writes .tmp/ext-vault/. Restores examples/wordpress.json at the end.
#   DOCKER_CONTEXT=colima test/ext-config.sh && DOCKER_CONTEXT=colima test/ext-vault.sh
#   SECURECORE_EXT_PROJECT / SECURECORE_EXT_PORT pick another project / port (all ext-* tests).
set -u
cd "$(dirname "$0")/.." || exit 1
project=${SECURECORE_EXT_PROJECT:-securecore-ext}
port=${SECURECORE_EXT_PORT:-8089}
base=http://127.0.0.1:$port
dir=.tmp/ext-vault
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete 2>/dev/null
html=/var/www/html
conf=$html/securecore.json
ini=/usr/local/etc/php/conf.d/securecore.ini
plugin=$html/wp-content/plugins/securecore-vault-probe
muplugin=$html/wp-content/mu-plugins/securecore-vault.php
vaultfile=/etc/securecore/vault.json

# The test site's secret material (never a real secret): the DB password (compose.yml) and the
# eight salts (compose.yml env + the vault file below carry the same values, so the backstop sees
# the env vars as secrets). The DB password is referred to below only as "the test password".
db_password=wordpress-db-password
auth_secret=sc-test-auth-keysc-test-auth-salt   # wp_salt('auth') = AUTH_KEY . AUTH_SALT
# Every value that must never appear in a probe's output.
secrets="$db_password sc-test-auth-key sc-test-secure-auth-key sc-test-logged-in-key sc-test-nonce-key sc-test-auth-salt sc-test-secure-auth-salt sc-test-logged-in-salt sc-test-nonce-salt"

fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }
# is <actual> <expected> <label>
is() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3" "got '$1', want '$2'"; fi; }
compose() { SECURECORE_PORT=$port docker compose -f docker/compose.yml -f docker/compose.ext.yml -p "$project" "$@"; }
wp() { compose run --rm -T cli wp "$@" 2>>"$dir/wp.err" | tr -d '\r'; }
in_php() { compose exec -T php sh -c "$1"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$base$1"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
wait_200() { i=0; until [ "$(code /)" = 200 ]; do i=$((i + 1)); [ "$i" -lt 60 ] || return 1; sleep 1; done; }
put_live() { compose exec -T php sh -c "cat > $conf.new && mv $conf.new $conf" < "$1"; }
phplog() { compose logs --no-log-prefix --since "$1" php 2>&1; }
# hmac_md5 <key>: HMAC-MD5 of "sc-vault-probe" (what the probe hashes), lowercase hex — stock PHP's
# hash_hmac with no extension and no ini (php -n), so it needs nothing on the Docker host (openssl
# is not on every one).
hmac_md5() { compose exec -T php php -n -r 'echo hash_hmac("md5", "sc-vault-probe", $argv[1]);' "$1"; }

[ "$(code /)" = 200 ] || { echo "FAIL the extension stack is not up on $base: run test/ext-config.sh first"; exit 1; }

# --- fixtures --------------------------------------------------------------------------------
# The vault file: a JSON object of NAME:value, outside the docroot, root-owned and readable only
# by root. php-fpm's master (root) reads it at MINIT, before it drops to www-data; the workers
# cannot open it at all.
cat > "$dir/vault.json" <<JSON
{
  "AUTH_KEY": "sc-test-auth-key",
  "SECURE_AUTH_KEY": "sc-test-secure-auth-key",
  "LOGGED_IN_KEY": "sc-test-logged-in-key",
  "NONCE_KEY": "sc-test-nonce-key",
  "AUTH_SALT": "sc-test-auth-salt",
  "SECURE_AUTH_SALT": "sc-test-secure-auth-salt",
  "LOGGED_IN_SALT": "sc-test-logged-in-salt",
  "NONCE_SALT": "sc-test-nonce-salt"
}
JSON
in_php "mkdir -p $(dirname "$vaultfile")"
compose cp "$dir/vault.json" "php:$vaultfile" >>"$dir/cp.log" 2>&1
in_php "chown root:root $vaultfile && chmod 400 $vaultfile"

# The two read probes, the connect probes and the fake MySQL server. No vault mu-plugin: the
# extension defines wp_salt/wp_hash itself (#53 review, finding 4), so the site works without it.
connect_plugin=$html/wp-content/plugins/securecore-vault-connect
fakescript=/tmp/sc-fakemysql.php
fakecap=/tmp/sc-fake.bin
fakepid=/tmp/sc-fake.pid
earlymu=$html/wp-content/mu-plugins/0-sc-early-salt.php
in_php "mkdir -p $plugin $connect_plugin $html/wp-content/mu-plugins && rm -f $muplugin"
compose cp test/ext/vault/plugin.php "php:$plugin/securecore-vault-probe.php" >>"$dir/cp.log" 2>&1
compose cp test/ext/vault/routine.php "php:$html/sc-vault-routine.php" >>"$dir/cp.log" 2>&1
compose cp test/ext/vault/core.php "php:$html/sc-vault-core.php" >>"$dir/cp.log" 2>&1
compose cp test/ext/vault/connect-plugin.php "php:$connect_plugin/securecore-vault-connect.php" >>"$dir/cp.log" 2>&1
compose cp test/ext/vault/connect-core.php "php:$html/sc-vault-connect-core.php" >>"$dir/cp.log" 2>&1
compose cp test/ext/vault/fakemysql.php "php:$fakescript" >>"$dir/cp.log" 2>&1
in_php "chown -R www-data:www-data $plugin $connect_plugin $html/sc-vault-routine.php $html/sc-vault-core.php $html/sc-vault-connect-core.php"
wp plugin activate securecore-vault-probe securecore-vault-connect >/dev/null

# fake_start / fake_stop: a fake MySQL server (cleartext-forcing) on $fakeport, by PID.
fakeport=33070
fake_start() { in_php "rm -f $fakecap; php $fakescript $fakeport $fakecap >/tmp/sc-fake.log 2>&1 & echo \$! > $fakepid"; sleep 1; }
fake_stop() { in_php "[ -f $fakepid ] && kill \$(cat $fakepid) 2>/dev/null; rm -f $fakepid"; }
# fakedb_start / fakedb_stop: the same fake server ON THE DB HOST, on another port: a container of
# the php image (php -n: no extension, no config) sharing the db container's network namespace, so
# "db:<port>" reaches it. Its capture is read with fakedb_capture.
fakedb=${project}-fakedb
fakedbport=33071
fakedb_start() {
  docker rm -f "$fakedb" >/dev/null 2>&1
  docker create --name "$fakedb" --network "container:$(compose ps -q db)" --entrypoint php \
    "$(docker inspect -f '{{.Image}}' "$(compose ps -q php)")" -n /fake.php "$fakedbport" /cap.bin >>"$dir/fakedb.log" 2>&1 &&
    docker cp test/ext/vault/fakemysql.php "$fakedb:/fake.php" >>"$dir/fakedb.log" 2>&1 &&
    docker start "$fakedb" >>"$dir/fakedb.log" 2>&1
  sleep 1
}
fakedb_capture() { docker exec "$fakedb" cat /cap.bin 2>/dev/null; }
fakedb_stop() { docker rm -f "$fakedb" >/dev/null 2>&1; }

cleanup() {
  fake_stop
  wp plugin deactivate securecore-vault-probe securecore-vault-connect classic-editor wordpress-seo contact-form-7 >/dev/null 2>&1
  fakedb_stop
  in_php "rm -rf $plugin $connect_plugin $muplugin $earlymu $html/sc-vault-routine.php $html/sc-vault-core.php $html/sc-vault-connect-core.php $html/sc-lit-config.php $fakescript $fakecap $fakepid"
  compose cp ext/examples/wordpress.json "php:$conf" >/dev/null 2>&1
  # Restore the extension ini in case a revert step changed it, then restart.
  compose cp docker/securecore.ini "php:$ini" >/dev/null 2>&1
  compose restart php >/dev/null 2>&1
  wait_200 || echo "FAIL php-fpm did not come back after cleanup"
}
trap cleanup EXIT

# The vault config for this test: DB password from the environment, salts from the vault file.
vault_cfg() { # $1 = mode
  cat > "$dir/$1.json" <<JSON
{
  "layer1": { "enabled": false },
  "layer2": {
    "enabled": true, "app": "wordpress", "mode": "$1",
    "vault": {
      "from": { "vaultFile": "$vaultfile" },
      "secrets": [
        { "name": "DB_PASSWORD", "env": "WORDPRESS_DB_PASSWORD" },
        "AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
        "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"
      ]
    },
    "core": { "hosts": ["127.0.0.1"] },
    "default": { "hosts": ["127.0.0.1", "db"] }, "components": {}
  },
  "layer3": { "enabled": false }
}
JSON
}
# The hosts (E5) let the probes reach the fake server (127.0.0.1) and, for the plugins, the DB host,
# so a connection that fails there fails because of the vault, not the host policy.

# apply <mode>: put the config and restart php-fpm (the vault is read at MINIT).
apply() {
  vault_cfg "$1"
  compose cp "$dir/$1.json" "php:$conf" >/dev/null 2>&1
  compose restart php >/dev/null 2>&1
  wait_200 || fail "$1: php-fpm serves the front page"
}

# field <file> <key>: a scalar probe field (the part before ==BLOBS==).
field() { awk -F= -v k="$2" 'f{next} $0=="==BLOBS=="{f=1;next} $1==k{sub(/^[^=]*=/,"");print}' "$1"; }

# no_secret <file> <label>: the whole probe output contains none of the real secret values.
no_secret() {
  found=''
  for sec in $secrets; do
    if grep -qF "$sec" "$1"; then found="$found $sec"; fi
  done
  if [ -z "$found" ]; then pass "$2: no real secret in any route"; else fail "$2: no real secret in any route" "leaked:$found"; fi
}

# --- 1 & 2. enforce and log: neither probe sees a secret -------------------------------------
for mode in enforce log; do
  echo "# $mode"
  apply "$mode"
  curl -s "$base/?sc_vault=run" > "$dir/plugin.$mode"
  curl -s "$base/sc-vault-core.php" > "$dir/core.$mode"
  is "$(sed -n '1s/^probe=//p' "$dir/plugin.$mode")" plugin "$mode: plugin probe ran"
  is "$(sed -n '1s/^probe=//p' "$dir/core.$mode")" core "$mode: core probe ran"
  no_secret "$dir/plugin.$mode" "$mode plugin"
  no_secret "$dir/core.$mode" "$mode core"

  # The placeholders are what the probe sees instead.
  for who in plugin core; do
    f="$dir/$who.$mode"
    is "$(field "$f" getenv_db)" "'securecore-vault:DB_PASSWORD'" "$mode $who: getenv(DB) is the placeholder"
    is "$(field "$f" const_db)" "'securecore-vault:DB_PASSWORD'" "$mode $who: DB_PASSWORD constant is the placeholder"
    is "$(field "$f" const_auth_key)" "'securecore-vault:AUTH_KEY'" "$mode $who: AUTH_KEY constant is the placeholder"
    is "$(field "$f" wpdb_dbpassword)" "'securecore-vault:DB_PASSWORD'" "$mode $who: \$wpdb->dbpassword is the placeholder"
    is "$(field "$f" wp_salt_auth)" "'securecore-vault-salt:auth'" "$mode $who: wp_salt('auth') is a token, not the key"
    is "$(field "$f" wp_salt_defined_by)/$(field "$f" wp_hash_defined_by)" extension/extension "$mode $who: wp_salt/wp_hash are the extension's, with no vault mu-plugin installed"
  done

  # 3. the vault keeps WordPress working.
  is "$(field "$dir/core.$mode" db_ok)" true "$mode: the DB connects with the real value"
  is "$(field "$dir/core.$mode" nonce_roundtrip)" 1 "$mode: nonce verifies"
  is "$(field "$dir/core.$mode" auth_cookie_roundtrip)" 1 "$mode: auth cookie validates"
  is "$(field "$dir/core.$mode" password_reset_roundtrip)" true "$mode: password reset key round-trips"
  # wp_hash byte-identical to a known-salt HMAC.
  is "$(field "$dir/core.$mode" wp_hash_auth)" "$(hmac_md5 "$auth_secret")" "$mode: wp_hash('auth') is byte-identical to stock HMAC"
done

# --- 3b. the connect boundary: the real value never leaves to a foreign host or for a plugin ---
# A fake MySQL server that forces clear-text auth captures whatever password a connecting client
# sends. A probe connects to it (another host/port) with a vault placeholder; the captured bytes
# must be the placeholder, never the real value. The swap is allowed only for core, to the real
# DB host, with the DB password placeholder — so a plugin, a foreign host, or a salt placeholder
# is refused in enforce AND in log mode (leaking is never "log and allow").
for mode in enforce log; do
  echo "# connect boundary ($mode)"
  apply "$mode"
  fake_start
  t=$(now)
  curl -s "$base/?sc_conn=run&fp=$fakeport" > "$dir/connect.plugin.$mode"
  curl -s "$base/sc-vault-connect-core.php?fp=$fakeport" > "$dir/connect.core.$mode"
  sleep 1
  in_php "cat $fakecap 2>/dev/null" > "$dir/capture.$mode"
  fake_stop

  # No real secret in the bytes the foreign server received (plugin DB + salt, core DB).
  cap_leak=''
  for sec in $secrets; do if grep -qF "$sec" "$dir/capture.$mode"; then cap_leak="$cap_leak $sec"; fi; done
  is "$cap_leak" "" "$mode: no real DB password or salt reached the fake server"
  # The placeholders DID arrive — so the probe connected and the clean capture is the gate, not a
  # failed connection.
  if grep -qF 'securecore-vault:DB_PASSWORD' "$dir/capture.$mode"; then pass "$mode: the DB placeholder (not the value) reached the foreign server"; else fail "$mode: the DB placeholder reached the foreign server" "$(tr -d '\0' < "$dir/capture.$mode" | tr '\n' ' ')"; fi
  if grep -qF 'securecore-vault:AUTH_KEY' "$dir/capture.$mode"; then pass "$mode: a salt placeholder (not the value) reached the foreign server"; else fail "$mode: a salt placeholder reached the foreign server"; fi
  # A plugin is refused the swap even to the real DB host: the connection fails.
  is "$(sed -n 's/^plugin_connects_real_db=//p' "$dir/connect.plugin.$mode")" failed "$mode: a plugin is refused the swap to the real DB (connection fails)"
  # Core still connects to the real DB with the placeholder (the swap is allowed).
  is "$(sed -n 's/^core_connects_real_db=//p' "$dir/connect.core.$mode")" CONNECTED "$mode: core still connects to the real DB"
  # The refusals are recorded (both modes).
  if phplog "$t" | grep -q 'vault: refused DB-password swap'; then pass "$mode: refused swaps are recorded in the log"; else fail "$mode: refused swaps are recorded"; fi
  # And the log carries no real value.
  leak=''
  for sec in $secrets; do if phplog "$t" | grep -qF "$sec"; then leak="$leak $sec"; fi; done
  is "$leak" "" "$mode: the refusal log carries no real value"
done

# --- 3c. the right DB host on another port (#53 review, finding 3) ---------------------------
# A plugin builds its own wpdb to DB_HOST:<other port>, where a fake server listens on the DB host
# itself. wpdb connecting is core (the connector rule), so only the host gate stands between the
# password and that server: host AND port must match, so it gets the placeholder.
echo "# connect boundary: the DB host on another port"
apply enforce
fakedb_start
t=$(now)
curl -s "$base/?sc_conn=port&fp=$fakedbport" > "$dir/connect.port"
sleep 1
fakedb_capture > "$dir/capture.port"
fakedb_stop
is "$(sed -n '1s/^probe=//p' "$dir/connect.port")" connect-port "port: the probe ran"
if grep -qF 'securecore-vault:DB_PASSWORD' "$dir/capture.port"; then pass "port: the server on db:$fakedbport received the placeholder"; else fail "port: the server on db:$fakedbport received the placeholder" "capture: $(tr -d '\0' < "$dir/capture.port" | tr '\n' ' ') $(cat "$dir/fakedb.log" | tr '\n' ' ')"; fi
if grep -qF "$db_password" "$dir/capture.port"; then fail "port: the real DB password did not reach db:$fakedbport" "it did"; else pass "port: the real DB password did not reach db:$fakedbport"; fi
if phplog "$t" | grep -q "vault: refused DB-password swap (wrong-host) for core connecting to \"db:$fakedbport\""; then pass "port: the refusal names the host and port"; else fail "port: the refusal names the host and port" "$(phplog "$t" | grep 'vault:' | tail -1)"; fi
# Core's own connection (DB_HOST, no port, i.e. 3306) still gets the real password.
curl -s "$base/sc-vault-core.php" > "$dir/core.port"
is "$(field "$dir/core.port" db_ok)" true "port: core still connects to the DB with the real value"

# --- 3d. a mu-plugin can't take over wp_salt/wp_hash (#53 review, finding 4) ---------------------
# An earlier mu-plugin defines wp_salt/wp_hash the way pluggable.php does (if !function_exists),
# keyed with a value it knows. The extension's definitions exist before any PHP runs, so its
# functions are never defined and every HMAC still uses the real salts.
echo "# an earlier mu-plugin defining wp_salt/wp_hash"
cat > "$dir/early-salt.php" <<'PHP'
<?php
// test/ext-vault.sh: an mu-plugin that loads first and tries to own the salted pluggables.
if (!function_exists('wp_salt')) {
    function wp_salt($scheme = 'auth') { return 'sc-early-mu-plugin-salt'; }
}
if (!function_exists('wp_hash')) {
    function wp_hash($data, $scheme = 'auth', $algo = 'md5') { return hash_hmac($algo, $data, 'sc-early-mu-plugin-salt'); }
}
PHP
compose cp "$dir/early-salt.php" "php:$earlymu" >>"$dir/cp.log" 2>&1
in_php "chown www-data:www-data $earlymu"
curl -s "$base/sc-vault-core.php" > "$dir/core.early"
in_php "rm -f $earlymu"
is "$(field "$dir/core.early" wp_salt_defined_by)" extension "early mu-plugin: wp_salt is still the extension's"
is "$(field "$dir/core.early" wp_salt_auth)" "'securecore-vault-salt:auth'" "early mu-plugin: wp_salt('auth') is the vault's token, not the mu-plugin's"
is "$(field "$dir/core.early" wp_hash_auth)" "$(hmac_md5 "$auth_secret")" "early mu-plugin: wp_hash('auth') is still keyed with the real salts"
is "$(field "$dir/core.early" nonce_roundtrip)" 1 "early mu-plugin: nonces still verify"

# 4. the backstop masked the salt env vars (names only), and no value is in the log.
t=$(now)
apply enforce
masked_line=$(phplog "$t" | sed -n 's/.*securecore: //p' | grep '^vault: masked' | tail -1)
if echo "$masked_line" | grep -q WORDPRESS_AUTH_KEY && echo "$masked_line" | grep -q WORDPRESS_NONCE_SALT; then
  pass "backstop: the salt env vars were masked by value (names logged)"
else
  fail "backstop: the salt env vars were masked" "$masked_line"
fi
leak=''
for sec in $secrets; do if echo "$masked_line" | grep -qF "$sec"; then leak="$leak $sec"; fi; done
is "$leak" "" "backstop: the log names only variables, never a value"

# The error log the probe wrote (placeholders) carries no real secret.
t=$(now)
curl -s "$base/?sc_vault=run" > /dev/null
leak=''
for sec in $secrets; do if phplog "$t" | grep -qF "$sec"; then leak="$leak $sec"; fi; done
is "$leak" "" "error log: no real secret in any php-fpm log line"

# --- 5. revert proof -------------------------------------------------------------------------
echo "# revert proof"
# (a) the vault removed from the config: the extension no longer hides anything.
cat > "$dir/no-vault.json" <<JSON
{ "layer1": { "enabled": false },
  "layer2": { "enabled": true, "app": "wordpress", "mode": "enforce", "default": {}, "components": {} },
  "layer3": { "enabled": false } }
JSON
compose cp "$dir/no-vault.json" "php:$conf" >/dev/null 2>&1
compose restart php >/dev/null 2>&1
wait_200 || fail "no-vault: php-fpm serves the front page"
curl -s "$base/sc-vault-core.php" > "$dir/core.no-vault"
if grep -qF "$db_password" "$dir/core.no-vault"; then
  pass "revert (no vault): the probe DOES see the test password — $(field "$dir/core.no-vault" getenv_db)"
else
  fail "revert (no vault): the probe sees the secret" "getenv_db=$(field "$dir/core.no-vault" getenv_db)"
fi

# (b) the extension unloaded: no masking at all.
compose cp "php:$ini" "$dir/securecore.ini" >>"$dir/cp.log" 2>&1
grep -v '^extension=' "$dir/securecore.ini" > "$dir/no-ext.ini"
compose cp "$dir/no-ext.ini" "php:$ini" >/dev/null 2>&1
compose restart php >/dev/null 2>&1
wait_200 || fail "no-ext: php-fpm serves the front page"
if [ "$(compose exec -T php php -m | grep -cx securecore)" = 0 ]; then pass "revert (no extension): securecore is not loaded"; else fail "revert (no extension): securecore is not loaded"; fi
curl -s "$base/sc-vault-core.php" > "$dir/core.no-ext"
if grep -qF "$db_password" "$dir/core.no-ext" && grep -qF "sc-test-auth-key" "$dir/core.no-ext"; then
  pass "revert (no extension): the probe DOES see the test password and the salts"
else
  fail "revert (no extension): the probe sees the secrets" "getenv_db=$(field "$dir/core.no-ext" getenv_db)"
fi
# Restore the extension and the vault config.
compose cp "$dir/securecore.ini" "php:$ini" >/dev/null 2>&1
apply enforce

# --- 5b. opcache: a wpConfig literal secret is refused at startup (fail closed) ---------------
# A secret read as a bare string literal from wp-config.php can't be hidden (opcache inlines the
# define to DECLARE_CONST). With the optimizer on (PHP's default), MINIT must refuse, naming the
# secret — not run a vault that silently isn't one.
echo "# opcache literal fail-closed"
# opcache really is loaded in this php-fpm (checked while it is still up), so the refusal below is
# the real fail-closed path, not a vacuous one.
is "$(in_php 'php -v 2>/dev/null | grep -c "Zend OPcache"')" 1 "opcache: Zend OPcache is loaded, so the refusal is the fail-closed path"
in_php "printf '<?php define(\"SC_LIT_SECRET\", \"literal-xyz-123\");\n' > $html/sc-lit-config.php"
cat > "$dir/wpc-lit.json" <<JSON
{ "layer1": { "enabled": false },
  "layer2": { "enabled": true, "app": "wordpress", "mode": "enforce",
    "vault": { "from": { "wpConfig": "sc-lit-config.php" }, "secrets": ["SC_LIT_SECRET"] },
    "default": {}, "components": {} },
  "layer3": { "enabled": false } }
JSON
compose cp "$dir/wpc-lit.json" "php:$conf" >/dev/null 2>&1
since=$(now)
compose restart php >/dev/null 2>&1
# It must refuse to start (php-fpm exits), not serve.
i=0; until compose ps -a --format '{{.State}}' php 2>/dev/null | grep -q exited; do i=$((i+1)); [ "$i" -lt 30 ] || break; sleep 1; done
if compose ps -a --format '{{.State}}' php 2>/dev/null | grep -q exited; then pass "opcache: php-fpm refuses to start on a literal wpConfig secret"; else fail "opcache: php-fpm refuses to start" "$(compose ps -a --format '{{.State}}' php)"; fi
refuse_log=$(phplog "$since" 2>&1)
if echo "$refuse_log" | grep -q "SC_LIT_SECRET is a string literal" && echo "$refuse_log" | grep -q "DECLARE_CONST"; then
  pass "opcache: the log names the secret and says to move it to a vault file or the env"
else
  fail "opcache: the log explains the refusal" "$(echo "$refuse_log" | grep -i securecore | tail -1)"
fi
# Restore and restart.
in_php "rm -f $html/sc-lit-config.php"
apply enforce

# --- 6. compat -------------------------------------------------------------------------------
echo "# compat (Classic Editor, Yoast SEO, Contact Form 7)"
if wp plugin install classic-editor wordpress-seo contact-form-7 --activate >>"$dir/compat.log" 2>&1; then
  # A fresh request builds the pages with the three plugins and the vault on.
  is "$(code /)" 200 "compat: front page 200 with the three plugins and the vault on"
  is "$(code /wp-login.php)" 200 "compat: login page 200 with the three plugins and the vault on"
  # The DB still connects with the plugins loaded, and no secret leaks.
  curl -s "$base/sc-vault-core.php" > "$dir/core.compat"
  is "$(field "$dir/core.compat" db_ok)" true "compat: DB connects with the plugins active"
  no_secret "$dir/core.compat" "compat"
else
  fail "compat: could not install the plugins (network?)" "see $dir/compat.log"
fi

echo
if [ "$fails" -eq 0 ]; then echo "all ext-vault checks passed"; else echo "$fails check(s) failed"; fi
[ "$fails" -eq 0 ]
