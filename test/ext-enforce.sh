#!/bin/sh
# E2b integration tests for layer-2 file/process enforcement (addiscorp/securecore#53), on the
# extension stack test/ext-config.sh leaves up (compose project securecore-ext, port 8089). A
# probe plugin (test/ext/enforce-plugin) attempts one operation per case on ?sc_enf=run and
# prints "<case>=OK" (it did what it asks) or "<case>=BLOCKED" (refused). The test runs it under
# four configs and checks the verdicts and the audit log:
#   1. enforce, the plugin ungranted: every forbidden op is BLOCKED, the allowed ones OK, and
#      each refusal is in the log as "layer2 enforce …";
#   2. log mode (same policy, nothing blocked): every op is now OK — the revert proof that the
#      block in (1) is what stopped each one — and each refusal is logged as "layer2 log …";
#   3. layer 2 off: every op OK and nothing logged;
#   4. enforce, the plugin granted exec and file paths: the granted ops are now OK, while the
#      protected file, ungranted paths and securecore_status() stay BLOCKED.
# Exits non-zero on any failure. Writes .tmp/ext-enforce/. Restores examples/wordpress.json and
# removes the fixture at the end.
#   DOCKER_CONTEXT=colima test/ext-config.sh && DOCKER_CONTEXT=colima test/ext-enforce.sh
set -u
cd "$(dirname "$0")/.." || exit 1
project=${SECURECORE_EXT_PROJECT:-securecore-ext}
port=${SECURECORE_EXT_PORT:-8089}
base=http://127.0.0.1:$port
dir=.tmp/ext-enforce
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete 2>/dev/null
html=/var/www/html
conf=$html/securecore.json
content=$html/wp-content
plugin=$content/plugins/securecore-enforce
victim=$content/sc-enf-victim.txt
renamef=$content/sc-enf-rename.txt
hardlink=$content/sc-enf-hardlink.txt
escape=$content/sc-enf-escape.php
escapedir=$content/sc-enf-escape-dir
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
# The audit lines php-fpm logged since <time>, prefix stripped: "layer2 <mode> <component> <op> <rule> <path>".
audit() { compose logs --no-log-prefix --since "$1" php 2>&1 | sed -n 's/.*securecore: //p' | grep '^layer2 '; }
# has <since> <substring> <label>: a layer2 line since <since> contains <substring>.
has() { if audit "$1" | grep -qF "$2"; then pass "$3"; else fail "$3" "no layer2 line matching '$2'"; fi; }
hasnt() { if audit "$1" | grep -qF "$2"; then fail "$3" "unexpected line '$2'"; else pass "$3"; fi; }

[ "$(code /)" = 200 ] || { echo "FAIL the extension stack is not up on $base: run test/ext-config.sh first"; exit 1; }

# --- fixtures --------------------------------------------------------------------------------
in_php "rm -rf $plugin && mkdir -p $plugin/inc"
compose cp test/ext/enforce-plugin/securecore-enforce.php "php:$plugin/securecore-enforce.php" >>"$dir/cp.log" 2>&1
compose cp test/ext/enforce-plugin/inc.php "php:$plugin/inc.php" >>"$dir/cp.log" 2>&1
# A PHP file outside the app root, for the include-outside case.
in_php "printf '<?php return \"outok\";\n' > /opt/sc-enf-out.php && chmod 644 /opt/sc-enf-out.php"
in_php "mkdir -p $content/uploads && chown -R www-data:www-data $content/plugins/securecore-enforce $content/uploads"
wp plugin activate securecore-enforce >/dev/null

cleanup() {
  wp plugin deactivate securecore-enforce >/dev/null 2>&1
  in_php "rm -rf $plugin $victim $renamef $renamef.moved $hardlink $content/sc-enf-newdir /opt/sc-enf-out.php /tmp/sc-enf.txt $content/uploads/sc-enf $escape $escapedir"
  compose cp ext/examples/wordpress.json "php:$conf" >/dev/null 2>&1
  compose restart php >/dev/null 2>&1
  wait_200 || echo "FAIL php-fpm did not come back after cleanup"
}
trap cleanup EXIT

# --- config variants (layer 2 only; layers 1 and 3 are inert on this stack) -------------------
base_cfg() { # $1 = mode, $2 = components object body
  cat > "$dir/$3.json" <<JSON
{
  "layer1": { "enabled": false },
  "layer2": {
    "enabled": true, "app": "wordpress", "mode": "$1",
    "vault": { "from": { "wpConfig": "wp-config.php" }, "secrets": [{ "name": "DB_PASSWORD", "env": "WORDPRESS_DB_PASSWORD" }] },
    "default": {},
    "components": { $2 }
  },
  "layer3": { "enabled": false }
}
JSON
}
grant='"securecore-enforce": { "exec": true, "files": { "read": ["/etc", "/opt"], "write": ["wp-content/plugins/securecore-enforce"] } }'
base_cfg enforce ''        enforce
base_cfg log     ''        log
base_cfg off     ''        off
base_cfg enforce "$grant"  granted

# run <config> : apply it, recreate the victim, fetch the report into $dir/out, return the log window start.
run() {
  put_live "$dir/$1.json"
  sleep 1.3 # > RELOAD_INTERVAL, so every worker has the new config
  in_php "printf victim > $victim && printf rn > $renamef && ln -f $html/wp-config.php $hardlink && chown www-data:www-data $victim $renamef"
  # Escape fixtures under uploads, each pointing where the lexical path does not: a dangling symlink,
  # a dir symlink outside uploads, and a 9-deep symlink chain (one past SYMLINK_FOLLOW_MAX = 8). The
  # write/mkdir probes must resolve the first two; the chain must be refused as unresolvable, not
  # guessed from its lexical path.
  in_php "d=$content/uploads/sc-enf; rm -rf \$d/dangle \$d/esc-dir-link \$d/chain* \$d/chaindst $escape $escapedir; mkdir -p \$d $escapedir; chown -R www-data:www-data \$d $escapedir; ln -s $escape \$d/dangle; ln -s $escapedir \$d/esc-dir-link; for i in 1 2 3 4 5 6 7 8; do ln -s chain\$((i+1)) \$d/chain\$i; done; ln -s chaindst \$d/chain9"
  T=$(now); sleep 1
  curl -s "$base/?sc_enf=run" > "$dir/out.$1"
  sleep 1
}
# verdict <config> <case> : the plugin's OK/BLOCKED for a case.
verdict() { sed -n "s/^$2=//p" "$dir/out.$1"; }
# want <config> <case> <OK|BLOCKED> : assert the verdict.
want() {
  v=$(verdict "$1" "$2")
  if [ "$v" = "$3" ]; then pass "$1: $2 is $3"; else fail "$1: $2 is $3" "got '$v'"; fi
}

# --- 1. enforce, ungranted -------------------------------------------------------------------
echo "# enforce (ungranted)"
run enforce
for c in read-own write-uploads include-own; do want enforce "$c" OK; done
for c in read-config read-etc fopen-read-etc scandir-etc write-own write-tmp fopen-write-own \
         unlink-core mkdir-core rename-core shell_exec exec include-outside status \
         symlink-read symlink-write link-protected hardlink-read \
         symlink-escape-create symlink-dangling-write mkdir-escape symlink-chain-write; do
  want enforce "$c" BLOCKED
done
has "$T" "layer2 enforce plugin:securecore-enforce open read-protected $html/wp-config.php" "enforce: reading wp-config resolves to read-protected"
has "$T" "layer2 enforce plugin:securecore-enforce open read-outside-root /etc/hostname" "enforce: reading /etc is read-outside-root"
has "$T" "layer2 enforce plugin:securecore-enforce open write $plugin/w.txt" "enforce: writing the own folder is a refused write"
has "$T" "layer2 enforce plugin:securecore-enforce exec exec echo scok" "enforce: exec is refused"
has "$T" "layer2 enforce plugin:securecore-enforce include read-outside-root /opt/sc-enf-out.php" "enforce: include outside the root is refused"
has "$T" "layer2 enforce plugin:securecore-enforce securecore_status core-only" "enforce: securecore_status from a plugin is core-only"
has "$T" "layer2 enforce plugin:securecore-enforce link-target read-protected $html/wp-config.php" "enforce: hard-linking a protected file is refused (1c)"
has "$T" "layer2 enforce plugin:securecore-enforce open read-protected $hardlink" "enforce: a hard link to a protected file is caught by inode (1b)"
has "$T" "layer2 enforce plugin:securecore-enforce symlink-target write $escape" "enforce: a symlink target outside the writable area is refused (item 1, create)"
has "$T" "layer2 enforce plugin:securecore-enforce open write $escape" "enforce: a write through a dangling symlink resolves to its target (item 1, write)"
has "$T" "layer2 enforce plugin:securecore-enforce mkdir write $escapedir/a/b" "enforce: a recursive mkdir through a symlink resolves to the real folder (item 2)"
has "$T" "layer2 enforce plugin:securecore-enforce open unresolvable $content/uploads/sc-enf/chain1" "enforce: a write past the symlink hop limit is refused as unresolvable (hop limit)"

# --- 2. log mode: the revert proof — the same ops now all succeed ----------------------------
echo "# log (nothing blocked)"
run log
for c in read-own read-config read-etc fopen-read-etc scandir-etc write-uploads write-own \
         write-tmp fopen-write-own unlink-core mkdir-core rename-core shell_exec exec \
         include-own include-outside status symlink-read symlink-write link-protected hardlink-read \
         symlink-escape-create symlink-dangling-write mkdir-escape symlink-chain-write; do
  want log "$c" OK
done
has "$T" "layer2 log plugin:securecore-enforce open read-protected $html/wp-config.php" "log: the would-be refusal is recorded, mode log"
has "$T" "layer2 log plugin:securecore-enforce open read-protected $hardlink" "log: the hard-link read is recorded (1b), mode log"
has "$T" "layer2 log plugin:securecore-enforce open write $escape" "log: the dangling-symlink write is recorded (item 1), mode log"
has "$T" "layer2 log plugin:securecore-enforce mkdir write $escapedir/a/b" "log: the mkdir-through-symlink is recorded (item 2), mode log"
has "$T" "layer2 log plugin:securecore-enforce open unresolvable $content/uploads/sc-enf/chain1" "log: the over-limit symlink chain is recorded as unresolvable, mode log"
has "$T" "layer2 log plugin:securecore-enforce exec exec echo scok" "log: exec would-be refusal recorded"

# --- 3. layer 2 off: everything works, nothing recorded --------------------------------------
echo "# off"
run off
for c in read-config read-etc write-own exec include-outside status symlink-read hardlink-read \
         symlink-escape-create symlink-dangling-write mkdir-escape symlink-chain-write; do want off "$c" OK; done
if [ "$(audit "$T" | grep -c .)" = 0 ]; then pass "off: no layer2 lines"; else fail "off: no layer2 lines" "$(audit "$T" | head -1)"; fi

# --- 4. enforce, granted ---------------------------------------------------------------------
echo "# enforce (granted exec + /etc + /opt + own folder)"
run granted
for c in read-own read-etc fopen-read-etc scandir-etc write-uploads write-own fopen-write-own \
         shell_exec exec include-own include-outside symlink-write; do
  want granted "$c" OK
done
for c in read-config write-tmp unlink-core mkdir-core rename-core status symlink-read link-protected hardlink-read \
         symlink-escape-create symlink-dangling-write mkdir-escape symlink-chain-write; do
  want granted "$c" BLOCKED
done
has "$T" "layer2 enforce plugin:securecore-enforce open read-protected $html/wp-config.php" "granted: the protected file is still refused"
has "$T" "layer2 enforce plugin:securecore-enforce open read-protected $hardlink" "granted: the hard link to it is still refused (inode)"
has "$T" "layer2 enforce plugin:securecore-enforce securecore_status core-only" "granted: securecore_status is still core-only"
hasnt "$T" "read-outside-root /etc/hostname" "granted: /etc is no longer refused"

echo
if [ "$fails" -eq 0 ]; then echo "all ext-enforce checks passed"; else echo "$fails check(s) failed"; fi
[ "$fails" -eq 0 ]
