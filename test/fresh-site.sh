#!/bin/sh
# Fresh stock WordPress, no repo scripts: runs INSIDE a plain debian:12 container standing in
# for a server (test/install-fresh.sh starts it). Installs nginx + php-fpm + php-cli from apt
# and the current WordPress on SQLite, then does exactly what a site owner does: the
# install.sh one-liner (with --from pointing at a locally served release), the worker
# command it prints, and Settings → SecureCore to sandbox Hello Dolly. Exits non-zero on
# failure.
set -u
FROM=http://127.0.0.1:8099
WP_ROOT=/var/www/html
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1"; fails=$((fails + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
as_owner() { sudo -u www-data sh -c "$1"; }

# --- a stock WordPress site (the starting point, before SecureCore) -------------------------
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx php-fpm php-cli php-opcache php-sqlite3 php-curl php-xml php-mbstring php-zip curl unzip ca-certificates sudo >/dev/null
PHPVER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
mkdir -p "$WP_ROOT"
curl -sS https://wordpress.org/latest.tar.gz | tar -xz -C /tmp
cp -r /tmp/wordpress/. "$WP_ROOT/"
curl -sSL https://downloads.wordpress.org/plugin/sqlite-database-integration.zip -o /tmp/sqlite.zip
unzip -q /tmp/sqlite.zip -d "$WP_ROOT/wp-content/plugins/"
sed -e "s#{SQLITE_IMPLEMENTATION_FOLDER_PATH}#$WP_ROOT/wp-content/plugins/sqlite-database-integration#" \
    -e "s#{SQLITE_PLUGIN}#sqlite-database-integration/load.php#" \
    "$WP_ROOT/wp-content/plugins/sqlite-database-integration/db.copy" > "$WP_ROOT/wp-content/db.php"
cat > "$WP_ROOT/wp-config.php" <<'PHP'
<?php
define('DB_NAME', 'wordpress'); define('DB_USER', ''); define('DB_PASSWORD', 'top-secret-db-pw-21');
define('DB_HOST', 'localhost'); define('DB_CHARSET', 'utf8'); define('DB_COLLATE', '');
define('AUTH_KEY','a');define('SECURE_AUTH_KEY','b');define('LOGGED_IN_KEY','c');define('NONCE_KEY','d');
define('AUTH_SALT','e');define('SECURE_AUTH_SALT','f');define('LOGGED_IN_SALT','g');define('NONCE_SALT','h');
// A test site: no background updates mid-test (they put up the maintenance page).
define('AUTOMATIC_UPDATER_DISABLED', true);
$table_prefix = 'wp_';
if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
PHP
chown -R www-data:www-data "$WP_ROOT"
FPMSOCK=$(ls /run/php/php*-fpm.sock 2>/dev/null || echo "/run/php/php${PHPVER}-fpm.sock")
cat > /etc/nginx/sites-available/default <<NGINX
server {
    listen 80 default_server; root $WP_ROOT; index index.php;
    location / { try_files \$uri \$uri/ /index.php?\$args; }
    location ~ \.php\$ { include snippets/fastcgi-php.conf; fastcgi_pass unix:${FPMSOCK}; }
}
NGINX
service "php${PHPVER}-fpm" start >/dev/null
service nginx start >/dev/null
curl -sS https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp
chmod +x /usr/local/bin/wp
as_owner "wp --path=$WP_ROOT core install --url=http://localhost --title=Fresh --admin_user=admin --admin_password=securecore-demo --admin_email=a@b.test --skip-email" >/dev/null
as_owner "wp --path=$WP_ROOT plugin activate hello" >/dev/null
echo "stock WordPress $(as_owner "wp --path=$WP_ROOT core version") on PHP $PHPVER, nginx + php-fpm from apt"
set +e

# --- the release, served locally (stands in for securecore.addis.gg) ------------------------
(php -S 127.0.0.1:8099 -t /release >/tmp/release-server.log 2>&1 &)
sleep 1

# --- what the site owner runs -----------------------------------------------------------------
ONE_LINER="cd $WP_ROOT && curl -fsSL $FROM/install.sh | sh -s -- --from $FROM"
echo
echo "\$ $ONE_LINER"
as_owner "$ONE_LINER" > /tmp/install.log 2>&1
rc=$?
cat /tmp/install.log
check "one-liner exits 0" "[ $rc = 0 ]"
check "activated with WP-CLI" "grep -q 'Activated the SecureCore plugin with WP-CLI' /tmp/install.log"
check "no missing-extension warning (pcntl + opcache are here)" "! grep -q 'has no' /tmp/install.log"
as_owner "wp --path=$WP_ROOT plugin list --fields=name,status --format=csv" > /tmp/plugins.csv
grep -i securecore /tmp/plugins.csv
check "the loader is listed only as must-use, not as a second plugin" \
  "[ \"\$(grep -c securecore-loader /tmp/plugins.csv)\" = 1 ] && grep -qx 'securecore-loader,must-use' /tmp/plugins.csv"

# The worker command install.sh printed, run as the site owner, in the background.
WORKER=$(sed -n "s#^ *\\($WP_ROOT/wp-content/plugins/securecore/bin/securecore-worker .*\\)\$#\\1#p" /tmp/install.log | head -n 1)
check "install.sh printed the worker command" "[ -n \"\$WORKER\" ]"
mkdir -p /run/securecore && chown www-data:www-data /run/securecore
echo "\$ $WORKER   # (in the background)"
# Started through a shell that records its PID, so it is stopped by PID later.
start_worker() {
  # shellcheck disable=SC2016 # $$, $0 and $@ belong to the inner shell
  as_owner "setsid -f sh -c 'echo \$\$ > /tmp/worker.pid; exec \"\$0\" \"\$@\"' $WORKER >> /tmp/worker.log 2>&1 < /dev/null"
  sleep 2
}
start_worker
cat /tmp/worker.log

# Settings → SecureCore: the worker shows as running; switch Hello Dolly on.
J=/tmp/jar
curl -s -c "$J" -b "$J" -o /dev/null http://localhost/wp-login.php
curl -s -c "$J" -b "$J" -o /dev/null -d 'log=admin&pwd=securecore-demo&wp-submit=Log+In&testcookie=1' http://localhost/wp-login.php
curl -s -b "$J" 'http://localhost/wp-admin/options-general.php?page=securecore' -o /tmp/screen.html
check "Settings → SecureCore shows the worker running" "grep -q 'color:green\">running' /tmp/screen.html"
NONCE=$(sed -n 's/.*name="_wpnonce" value="\([^"]*\)".*/\1/p' /tmp/screen.html | head -n 1)
curl -s -b "$J" -o /tmp/saved.html --data-urlencode "_wpnonce=$NONCE" \
  -d 'securecore_action=save&sandbox[]=hello.php' 'http://localhost/wp-admin/options-general.php?page=securecore'
check "switched Hello Dolly on" "grep -q 'Saved. Sandboxed: hello.php' /tmp/saved.html"
M=$WP_ROOT/wp-content/securecore/manifests/hello.php.json
check "manifest generated from Hello Dolly's code" "[ -f $M ]"
[ -f "$M" ] && cat "$M"

# The worker reads manifests when it starts: restart it (by PID), then Hello Dolly is sandboxed.
kill "$(cat /tmp/worker.pid)" 2>/dev/null
sleep 1
start_worker
curl -s -b "$J" http://localhost/wp-admin/ -o /tmp/admin.html
check "Hello Dolly's lyric shows in wp-admin" "grep -q 'id=\"dolly\"' /tmp/admin.html"
check "Hello Dolly ran in the sandbox, not in core" "grep -q 'securecore: sandboxed hello.php; included by core: none' /tmp/admin.html"

# --uninstall puts the site back.
UNINSTALL="cd $WP_ROOT && curl -fsSL $FROM/install.sh | sh -s -- --uninstall"
echo "\$ $UNINSTALL"
as_owner "$UNINSTALL" > /tmp/uninstall.log 2>&1
rc=$?
cat /tmp/uninstall.log
check "--uninstall exits 0" "[ $rc = 0 ]"
check "--uninstall removed plugin + loader" "[ ! -e $WP_ROOT/wp-content/plugins/securecore ] && [ ! -e $WP_ROOT/wp-content/mu-plugins/securecore-loader.php ]"
curl -s -b "$J" http://localhost/wp-admin/ -o /tmp/after.html
check "after uninstall Hello Dolly loads normally in core" "grep -q 'id=\"dolly\"' /tmp/after.html && ! grep -q 'securecore: sandboxed' /tmp/after.html"
kill "$(cat /tmp/worker.pid)" 2>/dev/null

[ "$fails" -eq 0 ] && echo "fresh site: all checks passed" || echo "fresh site: $fails check(s) failed"
[ "$fails" -eq 0 ]
