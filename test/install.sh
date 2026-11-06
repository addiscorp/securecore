#!/bin/sh
# Test install.sh like a user, on the running docker/ stack (the existing test site): serve a
# release built by scripts/release-layout.sh from inside the php container, run the
# one-liner with --from as the site's file owner, and check install, upgrade in place,
# a tampered download, an unwritable site, --path from elsewhere, --uninstall, and a
# reinstall; then test/site.sh. Exits non-zero on the first failure.
#   DOCKER_CONTEXT=colima test/install.sh
set -u
cd "$(dirname "$0")/.." || exit 1
compose() { docker compose -f docker/compose.yml "$@"; }
in_php() { compose exec -T -u www-data php sh -c "$1"; }
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1"; fails=$((fails + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
out=.tmp/install-test
mkdir -p "$out"

version=0.1.0-canary-test
rel=$out/release
find "$rel" -mindepth 1 -delete 2>/dev/null || true
TMPDIR=$PWD/.tmp scripts/release-layout.sh "$version" "v$version" "$(git rev-parse HEAD)" canary "$rel" >/dev/null || { echo "FAIL release layout"; exit 1; }

# Serve it from inside the php container, the way the bucket would.
compose exec -T php sh -c 'rm -rf /tmp/release && mkdir -p /tmp/release'
tar -C "$rel" -cf - . | compose exec -T php tar -xf - -C /tmp/release
compose exec -T php sh -c 'chown -R www-data /tmp/release; (php -S 127.0.0.1:8099 -t /tmp/release >/tmp/release-server.log 2>&1 & echo $! > /tmp/release-server.pid)'
sleep 1
FROM=http://127.0.0.1:8099
ONE_LINER="cd /var/www/html && curl -fsSL $FROM/install.sh | sh -s -- --from $FROM"

echo "\$ $ONE_LINER"
in_php "$ONE_LINER" > "$out/install-1.log" 2>&1; rc=$?
cat "$out/install-1.log"
check "install exits 0" "[ $rc = 0 ]"
check "plugin in wp-content/plugins/securecore" "in_php 'test -f /var/www/html/wp-content/plugins/securecore/securecore.php'"
check "loader in mu-plugins" "in_php 'test -f /var/www/html/wp-content/mu-plugins/securecore-loader.php'"
check "installed version is $version" "in_php 'grep -qx $version /var/www/html/wp-content/plugins/securecore/VERSION'"
check "says the PHP CLI here has no pcntl (worker runs in its own container)" "grep -q 'has no pcntl' $out/install-1.log"
check "ends with the next step" "grep -q 'Next: start the sandbox worker' $out/install-1.log"
check "plugin is active" "compose run --rm -T cli wp plugin is-active securecore >/dev/null 2>&1"

# A manifest from the admin screen must survive an upgrade.
in_php 'echo "{\"plugin\":\"keep-me.php\",\"functions\":[],\"hooks\":[]}" > /var/www/html/wp-content/securecore/manifests/keep-me.json'
echo "\$ $ONE_LINER   # again: upgrade in place"
in_php "$ONE_LINER" > "$out/install-2.log" 2>&1; rc=$?
check "re-run exits 0 and says it is upgrading" "[ $rc = 0 ] && grep -q 'Upgrading SecureCore $version -> $version' $out/install-2.log"
check "manifests kept across the upgrade" "in_php 'test -f /var/www/html/wp-content/securecore/manifests/keep-me.json'"
in_php 'rm -f /var/www/html/wp-content/securecore/manifests/keep-me.json'

# A download that does not match release.json must change nothing.
compose exec -T php sh -c "cp /tmp/release/$version/securecore.zip /tmp/good.zip && printf x >> /tmp/release/$version/securecore.zip"
in_php "$ONE_LINER" > "$out/install-tampered.log" 2>&1; rc=$?
compose exec -T php sh -c "cp /tmp/good.zip /tmp/release/$version/securecore.zip"
check "tampered zip: fails" "[ $rc != 0 ] && grep -q 'failed its checksum' $out/install-tampered.log"
check "tampered zip: installed plugin untouched" "in_php 'grep -qx $version /var/www/html/wp-content/plugins/securecore/VERSION'"

# Not the site owner: a clear message, no sudo.
compose exec -T -u nobody php sh -c "$ONE_LINER" > "$out/install-unwritable.log" 2>&1; rc=$?
check "unwritable site: fails with a clear message" "[ $rc != 0 ] && grep -q 'is not writable by' $out/install-unwritable.log"
check "never calls sudo" "! grep -vE '^[[:space:]]*#' install.sh | grep -qE '(^|[;&|]|\\\$\\()[[:space:]]*sudo[[:space:]]'"

# Not a WordPress root, and --path from elsewhere.
in_php "cd /tmp && curl -fsSL $FROM/install.sh | sh -s -- --from $FROM" > "$out/install-notwp.log" 2>&1; rc=$?
check "outside WordPress: fails, says to use --path" "[ $rc != 0 ] && grep -q -- '--path' $out/install-notwp.log"
in_php "cd / && curl -fsSL $FROM/install.sh | sh -s -- --path /var/www/html --from $FROM" > "$out/install-path.log" 2>&1; rc=$?
check "--path from another directory works" "[ $rc = 0 ]"

# --uninstall, then put it back.
in_php "cd /var/www/html && curl -fsSL $FROM/install.sh | sh -s -- --uninstall" > "$out/uninstall.log" 2>&1; rc=$?
cat "$out/uninstall.log"
check "--uninstall exits 0" "[ $rc = 0 ]"
check "--uninstall removed the plugin and loader" "in_php '! test -e /var/www/html/wp-content/plugins/securecore && ! test -e /var/www/html/wp-content/mu-plugins/securecore-loader.php'"
check "--uninstall kept the manifests" "in_php 'test -f /var/www/html/wp-content/securecore/manifests/hello.json'"
in_php "$ONE_LINER" > "$out/install-3.log" 2>&1; rc=$?
check "reinstall exits 0" "[ $rc = 0 ]"
compose run --rm -T cli wp plugin activate securecore >/dev/null 2>&1

# shellcheck disable=SC2016 # expands inside the container's shell, on purpose
compose exec -T php sh -c 'kill "$(cat /tmp/release-server.pid)" 2>/dev/null; rm -f /tmp/release-server.pid /tmp/good.zip'
compose restart worker >/dev/null 2>&1
sleep 3

echo "\$ test/site.sh"
if test/site.sh > "$out/site.log" 2>&1; then pass "test/site.sh after install"; else fail "test/site.sh after install"; cat "$out/site.log"; fi

[ "$fails" -eq 0 ] && echo "install.sh: all checks passed" || echo "install.sh: $fails check(s) failed"
[ "$fails" -eq 0 ]
