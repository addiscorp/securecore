#!/bin/sh
# The release check for one cell of the extension's matrix (addiscorp/securecore#53, E8): boot
# WordPress on that cell's PHP with that cell's built extension, installed by the release's own
# installer, and run a smoke subset of the ext-* suites. A release can't ship a cell that fails.
#
#   test/release-check.sh <php> <ts> <dir>      e.g. test/release-check.sh 8.3 nts .tmp/ext-dist
#
# <dir> holds the cell's built files (scripts/ext-build.sh): securecore-php<php>-<ts>-linux-<arch>.so
# and securecore-fpm-linux-<arch>, for this Docker host's architecture. They are laid out as a
# release with scripts/release-layout.sh (the script the bucket's release uses), and:
#   1. install: install-ext.sh, from that release, detects this PHP and installs the .so, the
#      ini, the launcher, the schema and the mu-plugin; the installed .so is the release's bytes;
#      a second run changes nothing; a tampered .so is refused and changes nothing;
#   2. config load: PHP refuses to start on a missing config (fail closed); with
#      examples/wordpress.json the front page is 200 and securecore_status() (core) reports the
#      file's sha256, all three layers, enforce, wordpress and caller=core;
#   3. attribution: a mu-plugin's call to securecore_status() is charged to mu-plugin:sc-smoke
#      and refused;
#   4. one enforce refusal: the mu-plugin can't write core's folders (but can write uploads),
#      logged; in log mode the same write goes through (the revert proof);
#   5. vault: the mu-plugin sees only placeholders for DB_PASSWORD, its env var and AUTH_KEY
#      while WordPress still connects; with the vault removed from the config it sees the real
#      password (the revert proof);
#   6. layer 1: started by securecore-fpm, the SAPI runs sandboxed (NoNewPrivs, seccomp), serves
#      200, and a core write outside layer1.write is refused — the same write that worked with
#      the plain SAPI.
# Exits non-zero on any failure. Writes .tmp/release-check/<cell>/. Takes the stack down (with
# its volumes) at the end unless SECURECORE_RELEASE_KEEP=1.
#   SECURECORE_RELEASE_PROJECT / SECURECORE_RELEASE_PORT: another compose project / port
#   (default securecore-release-<cell>, 8095).
set -u
cd "$(dirname "$0")/.." || exit 1
[ $# -eq 3 ] || { echo "usage: $0 <php> <ts> <dir-with-the-cell's-files>" >&2; exit 2; }
php=$1 ts=$2 src=$3
arch=$(scripts/ext-cells.sh arch) || exit 1
image=$(scripts/ext-cells.sh image "$php" "$ts") || exit 1
cell=php$php-$ts-linux-$arch
so=securecore-$cell.so
launcher=securecore-fpm-linux-$arch
project=${SECURECORE_RELEASE_PROJECT:-securecore-release-$(echo "$cell" | tr . -)}
port=${SECURECORE_RELEASE_PORT:-8095}
base=http://127.0.0.1:$port
dir=.tmp/release-check/$cell
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }
is() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3" "got '$1', want '$2'"; fi; }
has() { if grep -qF -- "$2" "$1"; then pass "$3"; else fail "$3" "no '$2' in $1"; fi; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

for f in "$so" "$launcher"; do [ -f "$src/$f" ] || { echo "FAIL $src/$f is missing (scripts/ext-build.sh $php $ts $src)"; exit 1; }; done
mkdir -p "$dir/ext"
cp "$src/$so" "$src/$launcher" "$dir/ext/"
# Layer 1's microVM files (#71), resolved as the release resolves them: mirab's newest stable
# release, or, while that has no vm/ images (mirab#89), mirab's newest canary, so the
# installer's microVM step is checked either way. x86_64 only (mirab pins Firecracker for it).
vm=
if [ "$arch" = x86_64 ]; then
  TMPDIR=${TMPDIR:-$PWD/.tmp} scripts/mirab-vm.sh "$dir/ext" > "$dir/mirab.log" 2>&1; rc=$?
  if [ "$rc" = 3 ]; then
    canary=$(curl -fsSL https://mirab-releases.addis.gg/canary.json | sed -n 's/.*"version": *"\([^"]*\)".*/\1/p')
    TMPDIR=${TMPDIR:-$PWD/.tmp} scripts/mirab-vm.sh "$dir/ext" "https://mirab-releases.addis.gg/$canary/vm/manifest.json" >> "$dir/mirab.log" 2>&1; rc=$?
  fi
  [ "$rc" = 0 ] || { echo "FAIL mirab's microVM files (see $dir/mirab.log)"; cat "$dir/mirab.log"; exit 1; }
  vm=$dir/ext/mirab-vm.json
fi
version="$(scripts/version.sh)-canary-check"
TMPDIR=${TMPDIR:-$PWD/.tmp} scripts/release-layout.sh "$version" "v$version" "$(git rev-parse HEAD)" canary "$dir/release" "$dir/ext" > "$dir/layout.log" \
  || { echo "FAIL release layout (see $dir/layout.log)"; exit 1; }

if [ "$ts" = zts ]; then user=www-data; else user=root; fi
export SC_PHP_IMAGE="$image" SC_TS="$ts" SC_RELEASE_DIR="$PWD/$dir/release" SC_USER="$user" SC_PORT="$port" SC_COMMAND=sapi
compose() { docker compose -f docker/compose.release-check.yml -p "$project" "$@"; }
in_php() { compose exec -T php sh -c "$1"; }
in_root() { compose exec -T -u root php sh -c "$1"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$base$1"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
# The SAPI's log: php's own output, and for php-cgi (ZTS) what it sends down FastCGI's stderr
# during a request, which nginx logs. (error_log = /proc/self/fd/2 can't stand in for that on ZTS:
# its virtual-cwd open resolves the link to "pipe:[…]" and fails.)
phplog() { compose logs --no-log-prefix --since "$1" php web 2>&1; }
wait_200() { i=0; until [ "$(code "${1:-/}")" = 200 ]; do i=$((i + 1)); [ "$i" -lt 60 ] || return 1; sleep 1; done; }
conf=/var/www/html/securecore.json
put_conf() { compose cp "$1" "php:$conf" >> "$dir/cp.log" 2>&1; }
# > the extension's reload interval (1 s): every worker picks the edit up on its next request.
put_live() { in_root "cat > $conf.new && chmod 644 $conf.new && mv $conf.new $conf" < "$1"; sleep 1.2; }
smoke() { curl -s "$base/?sc_smoke=1" > "$dir/$1"; }
core() { curl -s "$base/sc-smoke-core.php" > "$dir/$1"; }
field() { sed -n "s/^$2=//p" "$dir/$1"; }
# The stack, its volumes and the images it built (one per cell: they add up).
down() { [ "${SECURECORE_RELEASE_KEEP:-}" = 1 ] || compose down -v --remove-orphans --rmi local > "$dir/down.log" 2>&1; }
trap down EXIT

echo "release check $cell ($image), project $project, $base"
compose down -v --remove-orphans > /dev/null 2>&1
compose build php web > "$dir/build.log" 2>&1 || { echo "FAIL build: install-ext.sh or the image (see $dir/build.log)"; tail -20 "$dir/build.log"; exit 1; }
compose up -d db php web > "$dir/up.log" 2>&1 || { echo "FAIL compose up (see $dir/up.log)"; exit 1; }

# --- 1. install -------------------------------------------------------------------------------
in_php 'cat /release-check/install.log' > "$dir/install.log"
cat "$dir/install.log"
case $ts in nts) TS_LABEL=NTS ;; *) TS_LABEL=ZTS ;; esac
if grep -qE "^ok PHP +PHP $php\.[0-9]+ $TS_LABEL $arch " "$dir/install.log"; then pass "install-ext.sh detected PHP $php $TS_LABEL $arch"; else fail "install-ext.sh detected PHP $php $TS_LABEL $arch"; fi
has "$dir/install.log" "matching its sha256 in release.json" "install-ext.sh verified the downloads against release.json"
has "$dir/install.log" "ok Loaded" "install-ext.sh: PHP loads the extension after the install"
extdir=$(in_php 'php -r "echo ini_get(\"extension_dir\");"')
is "$(in_php "sha256sum $extdir/securecore.so" | cut -d' ' -f1)" "$(sha "$src/$so")" "the installed securecore.so is the built $so, byte for byte"
is "$(in_php 'sha256sum /usr/local/bin/securecore-fpm' | cut -d' ' -f1)" "$(sha "$src/$launcher")" "the installed securecore-fpm is the built $launcher"
is "$(in_php 'test -f /var/www/html/wp-content/mu-plugins/securecore-vault.php && test -f /usr/local/share/securecore/securecore.schema.json && echo yes')" yes "mu-plugin and schema installed"
is "$(in_php 'php -r "echo PHP_MAJOR_VERSION, \".\", PHP_MINOR_VERSION, PHP_ZTS ? \"-zts\" : \"-nts\";"')" "$php-$ts" "the site's PHP is $php $ts"
is "$(in_php 'php -m' | grep -cx securecore)" 1 "php -m lists securecore"

# Again with the defaults the site shows (no --canary, no --wordpress), from outside the site:
# with no latest.json it takes the newest canary, and it finds WordPress in /var/www/html.
if [ -n "$vm" ]; then
  # jsonv <key>: a value from mirab-vm.json (the last one of that name: the firecracker block's
  # come after the kernel's, so ask for the ones that are unique).
  jsonv() { tr -d ' \n' < "$vm" | grep -o "\"$1\":\"[^\"]*\"" | tail -n 1 | cut -d'"' -f4; }
  has "$dir/install.log" "ok microVM" "install-ext.sh installed layer 1's microVM files"
  has "$dir/install.log" "each matching mirab's sha256" "and checked them against mirab's sha256s"
  is "$(in_php 'sha256sum /usr/local/share/securecore/vm/vmlinux' | cut -d' ' -f1)" "$(jsonv unpacked_sha256)" "the installed guest kernel is mirab's, by its unpacked sha256"
  is "$(in_php 'sha256sum /usr/local/share/securecore/vm/firecracker' | cut -d' ' -f1)" "$(jsonv member_sha256)" "the installed Firecracker is the one mirab pins"
  is "$(in_php 'test -x /usr/local/share/securecore/vm/firecracker && echo yes')" yes "and it is executable"
  is "$(in_php 'cat /usr/local/share/securecore/vm/installed.json' | tr -d ' \n' | grep -o '"mirab":"[^"]*"' | cut -d'"' -f4)" "$(jsonv mirab)" \
    "vm/installed.json records the mirab release ($(jsonv mirab))"
fi
in_root 'cd / && sh /release/install-ext.sh --from file:///release' > "$dir/install-2.log" 2>&1; rc=$?
if [ "$rc" = 0 ] && ! grep -qE '^ok +(Extension|Launcher|JSON Schema|mu-plugin|Config|ini|Firecracker|Guest kernel|microVM record) ' "$dir/install-2.log"; then
  pass "install-ext.sh again, with the defaults: exit 0, nothing changed"
else
  fail "install-ext.sh again, with the defaults: exit 0, nothing changed" "rc=$rc: $(tr '\n' '|' < "$dir/install-2.log")"
fi
has "$dir/install-2.log" "no stable release yet, so the newest canary" "install-ext.sh with no stable release takes the newest canary"
in_root "rm -rf /tmp/tampered && cp -a /release /tmp/tampered && printf x >> /tmp/tampered/$version/ext/$so"
in_root 'sh /release/install-ext.sh --from file:///tmp/tampered --canary --wordpress /var/www/html' > "$dir/install-tampered.log" 2>&1; rc=$?
if [ "$rc" != 0 ] && grep -q "ext/$so failed its sha256 check against release.json, so nothing was installed" "$dir/install-tampered.log"; then
  pass "a tampered $so is refused"
else
  fail "a tampered $so is refused" "rc=$rc: $(tr '\n' '|' < "$dir/install-tampered.log")"
fi
is "$(in_php "sha256sum $extdir/securecore.so" | cut -d' ' -f1)" "$(sha "$src/$so")" "after the tampered run the installed .so is unchanged"
in_root 'rm -rf /tmp/tampered'
if [ -n "$vm" ]; then
  # A release whose mirab-vm.json names another kernel sha256 (release.json agrees with it, so
  # only mirab's sha256 check can catch the kernel): refused, and nothing changes.
  mkdir -p "$dir/badvm-ext"
  cp "$dir/ext/"* "$dir/badvm-ext/"
  sed "s/$(jsonv unpacked_sha256)/$(printf '0%.0s' $(seq 64))/" "$vm" > "$dir/badvm-ext/mirab-vm.json"
  TMPDIR=${TMPDIR:-$PWD/.tmp} scripts/release-layout.sh "$version" "v$version" "$(git rev-parse HEAD)" canary "$dir/badvm" "$dir/badvm-ext" > "$dir/layout-badvm.log" \
    || fail "the bad-kernel release layout"
  compose cp "$dir/badvm" php:/tmp/badvm >> "$dir/cp.log" 2>&1
  in_root 'sh /tmp/badvm/install-ext.sh --from file:///tmp/badvm --canary --wordpress /var/www/html' > "$dir/install-badvm.log" 2>&1; rc=$?
  if [ "$rc" != 0 ] && grep -q "unpacked guest kernel failed its sha256 check against mirab's" "$dir/install-badvm.log"; then
    pass "a kernel that doesn't match mirab's sha256 is refused"
  else
    fail "a kernel that doesn't match mirab's sha256 is refused" "rc=$rc: $(tr '\n' '|' < "$dir/install-badvm.log")"
  fi
  is "$(in_php 'sha256sum /usr/local/share/securecore/vm/vmlinux' | cut -d' ' -f1)" "$(jsonv unpacked_sha256)" "after the refused run the installed kernel is unchanged"
  in_root 'find /tmp/badvm -mindepth 1 -delete && rmdir /tmp/badvm'
fi

# --- 2. config load ---------------------------------------------------------------------------
out=$(in_php 'php -d securecore.config=/etc/securecore/missing.json -r "echo \"ran\";"' 2>&1); rc=$?
case $out in
  *"securecore: /etc/securecore/missing.json: cannot read it"*) if [ "$rc" != 0 ] && [ "${out%ran}" = "$out" ]; then pass "a missing config: PHP refuses to start (fail closed)"; else fail "a missing config: PHP refuses to start" "rc=$rc"; fi ;;
  *) fail "a missing config: PHP refuses to start, naming the file" "rc=$rc: $out" ;;
esac
put_conf ext/examples/wordpress.json
compose cp test/ext/securecore-status.php php:/var/www/html/securecore-status.php >> "$dir/cp.log" 2>&1
compose cp test/release/sc-smoke-core.php php:/var/www/html/sc-smoke-core.php >> "$dir/cp.log" 2>&1
compose cp test/release/sc-smoke.php php:/var/www/html/wp-content/mu-plugins/sc-smoke.php >> "$dir/cp.log" 2>&1
in_root 'chmod 644 /var/www/html/securecore.json /var/www/html/securecore-status.php /var/www/html/sc-smoke-core.php /var/www/html/wp-content/mu-plugins/sc-smoke.php'
compose restart php > /dev/null 2>&1
i=0
until compose exec -T db mariadb -uwordpress -pwordpress-db-password -e 'select 1' wordpress > /dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 180 ] || { echo "FAIL the database did not start"; compose logs db 2>&1 | tail -10; exit 1; }
  sleep 1
done
wait_200 /securecore-status.php || { echo "FAIL php never served the status probe"; compose logs php | tail -20; exit 1; }
# WordPress's own installer, through the extension (core is never restricted).
curl -s -o "$dir/wp-install.html" -w '%{http_code}' "$base/wp-admin/install.php?step=2" \
  --data-urlencode weblog_title=SecureCore --data-urlencode user_name=admin \
  --data-urlencode admin_password=securecore-demo --data-urlencode admin_password2=securecore-demo \
  --data-urlencode pw_weak=1 --data-urlencode admin_email=admin@example.com --data-urlencode blog_public=0 > "$dir/wp-install.code"
is "$(code /)" 200 "WordPress front page 200 with the extension and examples/wordpress.json"
curl -s "$base/securecore-status.php" > "$dir/status"
is "$(field status loaded)" 1 "securecore_status() exists in the SAPI"
is "$(field status sha256)" "$(sha ext/examples/wordpress.json)" "status: the live config is examples/wordpress.json"
is "$(field status layer1)$(field status layer2)$(field status layer3)" 111 "status: all three layers enabled"
is "$(field status layer2_mode)/$(field status layer2_app)" enforce/wordpress "status: layer 2 enforce, app wordpress"
is "$(field status caller)" core "attribution: a web-root script is core"
core plain
is "$(field plain write-wp-includes)" OK "plain SAPI: core can write wp-includes (layer 1 is not running)"

# --- 3-5. attribution, an enforce refusal, the vault --------------------------------------------
t=$(now)
smoke enforce
is "$(field enforce status)" BLOCKED "attribution: the mu-plugin's securecore_status() is refused"
is "$(field enforce write-core)" BLOCKED "enforce: the mu-plugin can't write wp-content/sc-smoke-escape.php"
is "$(field enforce write-uploads)" OK "enforce: the mu-plugin can write uploads"
phplog "$t" > "$dir/enforce.log"
has "$dir/enforce.log" "layer2 enforce mu-plugin:sc-smoke securecore_status" "the refusal of securecore_status() names mu-plugin:sc-smoke"
if grep -F "layer2 enforce mu-plugin:sc-smoke" "$dir/enforce.log" | grep -qF "/var/www/html/wp-content/sc-smoke-escape.php"; then
  pass "the refused write is logged against mu-plugin:sc-smoke"
else
  fail "the refused write is logged against mu-plugin:sc-smoke" "$(grep -F 'securecore:' "$dir/enforce.log" | tail -3 | tr '\n' '|')"
fi
is "$(field enforce db_password)" "securecore-vault:DB_PASSWORD" "vault: DB_PASSWORD is the placeholder"
is "$(field enforce getenv)" "securecore-vault:DB_PASSWORD" "vault: getenv(WORDPRESS_DB_PASSWORD) is the placeholder"
is "$(field enforce auth_key)" "securecore-vault:AUTH_KEY" "vault: AUTH_KEY is the placeholder"
if grep -q wordpress-db-password "$dir/enforce"; then fail "vault: the real DB password appears nowhere in the probe"; else pass "vault: the real DB password appears nowhere in the probe"; fi

sed 's/"mode": "enforce"/"mode": "log"/' ext/examples/wordpress.json > "$dir/log-mode.json"
put_live "$dir/log-mode.json"
smoke logmode
is "$(field logmode write-core)/$(field logmode status)" OK/OK "revert proof: in log mode the same write and call go through"
in_root 'rm -f /var/www/html/wp-content/sc-smoke-escape.php'

# The vault lives in MINIT, so removing it takes a restart.
# shellcheck disable=SC2016 # the $c is PHP's, expanded by neither shell
in_php 'php -n -r "\$c = json_decode(file_get_contents(\"php://stdin\"), true); unset(\$c[\"layer2\"][\"vault\"]); echo json_encode(\$c, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);"' < ext/examples/wordpress.json > "$dir/no-vault.json"
put_conf "$dir/no-vault.json"
in_root "chmod 644 $conf"
compose restart php > /dev/null 2>&1
wait_200 || fail "front page 200 without the vault"
smoke novault
is "$(field novault db_password)" wordpress-db-password "revert proof: without the vault the mu-plugin reads the real DB password"

# --- 6. layer 1 -------------------------------------------------------------------------------
put_conf ext/examples/wordpress.json
in_root "chmod 644 $conf"
t=$(now)
SC_COMMAND=sapi-layer1 compose up -d php > "$dir/up-layer1.log" 2>&1
# A new php container may get a new address; nginx resolved the old one at its start.
compose restart web > /dev/null 2>&1
if wait_200; then pass "layer 1: started by securecore-fpm, front page 200"; else fail "layer 1: started by securecore-fpm, front page 200" "$(compose logs php 2>&1 | tail -5 | tr '\n' '|')"; fi
phplog "$t" > "$dir/layer1.log"
has "$dir/layer1.log" "securecore-fpm: layer 1 on from $conf" "layer 1: the launcher says layer 1 is on"
core layer1
is "$(field layer1 nonewprivs)/$(field layer1 seccomp)" 1/2 "layer 1: the SAPI runs with no_new_privs and seccomp filters"
is "$(field layer1 write-wp-includes)" BLOCKED "layer 1: core can't write wp-includes (outside layer1.write)"
is "$(field layer1 write-uploads)" OK "layer 1: core can write uploads"
smoke layer1-smoke
is "$(field layer1-smoke db_password)" "securecore-vault:DB_PASSWORD" "layer 1 + 2: the vault still holds"

echo
if [ "$fails" -eq 0 ]; then echo "all release checks passed for $cell"; else echo "$fails release check(s) failed for $cell"; fi
[ "$fails" -eq 0 ]
