#!/bin/sh
# One install.sh scenario, run INSIDE a throwaway container by test/full-setup.sh. The
# release (with php.json and the mirrored PHP builds) is served at $FROM; the probe plugin
# and its benign manifest are in /probe. Exits non-zero on failure.
#   setup-scenario.sh empty        no system PHP: install.sh --yes in an empty folder
#   setup-scenario.sh interactive  no system PHP: the same, answering every question on a terminal
#   setup-scenario.sh nopcntl      a system PHP without pcntl (the official WordPress image's)
set -u
SCENARIO=$1
FROM=${FROM:-http://release:8099}
SITE=/home/site/mysite
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1"; fails=$((fails + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
as_site() { su site -s /bin/sh -c "$1"; }

id site >/dev/null 2>&1 || useradd -m -s /bin/sh site
command -v php >/dev/null 2>&1 && echo "system php: $(command -v php)" || echo "system php: none"
as_site "mkdir -p $SITE"

ONE_LINER="cd $SITE && curl -fsSL $FROM/install.sh | sh -s -- --from $FROM"
case $SCENARIO in
  empty|nopcntl)
    echo "site\$ $ONE_LINER --yes"
    as_site "$ONE_LINER --yes" > /tmp/install.log 2>&1; rc=$?
    cat /tmp/install.log
    check "install exits 0 and installed SecureCore" "[ $rc = 0 ] && grep -q 'Installed .*/securecore-loader.php' /tmp/install.log" ;;
  interactive)
    # Answers, in order: download PHP (Enter = yes), database (Enter = sqlite), WordPress
    # version (Enter = newest), title, admin user, email, password (Enter = generate),
    # commands or compose (Enter = commands), start the worker now (y).
    echo "site\$ $ONE_LINER        # in a terminal, answering the questions"
    printf '\n\n\nMy SecureCore site\n\n\n\n\ny\n' | as_site "script -qec '$ONE_LINER' /dev/null" > /tmp/install.log 2>&1; rc=$?
    tr -d '\r' < /tmp/install.log
    check "install exits 0 and installed SecureCore" "[ $rc = 0 ] && grep -q 'Installed .*/securecore-loader.php' /tmp/install.log"
    check "asked to download PHP" "grep -q 'Download PHP into' /tmp/install.log"
    check "asked for the database" "grep -q 'Database: sqlite' /tmp/install.log"
    check "asked for the WordPress version, newest first" "grep -q 'WordPress version (newest first' /tmp/install.log"
    check "asked for the title, user, email and password" "grep -q 'Site title' /tmp/install.log && grep -q 'Admin password' /tmp/install.log"
    check "asked how to run it" "grep -q 'commands printed below, or with Docker Compose' /tmp/install.log"
    check "started the worker when asked" "grep -q 'Started the worker on' /tmp/install.log" ;;
esac

L=/tmp/install.log
case $SCENARIO in
  empty|interactive)
    check "no system PHP: downloaded bulk (worker) and common (site, SQLite)" "grep -q 'PHP 8.4.23 (bulk): sha256' $L && grep -q 'PHP 8.4.23 (common): sha256' $L"
    check "PHP lives in the project, not the system" "[ -x $SITE/.securecore/php/bulk/8.4.23/linux-x64/php ] && [ -x $SITE/.securecore/php/common/8.4.23/linux-x64/php ] && ! command -v php >/dev/null" ;;
  nopcntl)
    check "described the system PHP: pcntl NO" "grep -q 'pcntl NO' $L"
    check "downloaded bulk for the worker only; the site uses the system PHP" "grep -q 'PHP 8.4.23 (bulk): sha256' $L && ! grep -q '(common): sha256' $L && grep -q 'for the site: /usr/local/bin/php' $L" ;;
esac
check "WordPress downloaded and checked against wordpress.org's sha1" "grep -q 'matches wordpress.org' $L"
check "SQLite through the plugin and its db.php drop-in" "grep -q 'SQLite (wp-content/database' $L && grep -q 'sqlite-database-integration' $SITE/wp-content/db.php"
check "SecureCore installed and active" "[ -f $SITE/wp-content/plugins/securecore/securecore.php ] && grep -q 'Activated the SecureCore plugin' $L"
check "printed the web server command with real paths" "grep -q \"cd $SITE && $SITE/.securecore/bin/php-web -S localhost:8080\" $L"
PASS=$(sed -n 's/^Admin password (generated; keep it): //p' $L | tr -d '\r')
check "printed the generated admin password" "[ -n \"$PASS\" ]"

# Run it the way the output says.
echo "site\$ cd $SITE && .securecore/bin/php-web -S localhost:8080 &"
as_site "cd $SITE && (.securecore/bin/php-web -S localhost:8080 > /tmp/web.log 2>&1 &)"
if [ "$SCENARIO" != interactive ]; then
  echo "site\$ $SITE/wp-content/plugins/securecore/bin/securecore-worker &"
  as_site "($SITE/wp-content/plugins/securecore/bin/securecore-worker >> /tmp/worker.log 2>&1 &)"
fi
sleep 2

J=/tmp/jar
curl -s -c $J -b $J -o /dev/null http://localhost:8080/wp-login.php
curl -s -c $J -b $J -o /dev/null --data-urlencode "pwd=$PASS" -d 'log=admin&wp-submit=Log+In&testcookie=1' http://localhost:8080/wp-login.php
curl -s -b $J 'http://localhost:8080/wp-admin/options-general.php?page=securecore' -o /tmp/screen.html
check "logged in with the generated password; Settings → SecureCore shows the worker running" "grep -q 'color:green\">running' /tmp/screen.html"
# Activate Hello Dolly in wp-admin → Plugins, then sandbox it.
curl -s -b $J http://localhost:8080/wp-admin/plugins.php -o /tmp/plugins.html
ACT=$(sed -n 's/.*href="\(plugins.php?action=activate&amp;plugin=hello.php[^"]*\)".*/\1/p' /tmp/plugins.html | head -n 1 | sed 's/&amp;/\&/g')
curl -s -b $J -o /dev/null "http://localhost:8080/wp-admin/$ACT"
NONCE=$(sed -n 's/.*name="_wpnonce" value="\([^"]*\)".*/\1/p' /tmp/screen.html | head -n 1)
curl -s -b $J -o /tmp/saved.html --data-urlencode "_wpnonce=$NONCE" -d 'securecore_action=save&sandbox[]=hello.php' 'http://localhost:8080/wp-admin/options-general.php?page=securecore'
curl -s -b $J http://localhost:8080/wp-admin/ -o /tmp/admin.html
check "Hello Dolly runs sandboxed on the next request" "grep -q 'id=\"dolly\"' /tmp/admin.html && grep -q 'securecore: sandboxed hello.php; included by core: none' /tmp/admin.html"
# The probe: benign manifest, backdoored code.
cp -r /probe/securecore-probe "$SITE/wp-content/plugins/" && cp /probe/securecore-probe.json "$SITE/wp-content/securecore/manifests/"
chown -R site "$SITE/wp-content"
curl -s -b $J http://localhost:8080/wp-admin/plugins.php -o /tmp/plugins.html
ACT=$(sed -n 's/.*href="\(plugins.php?action=activate&amp;plugin=securecore-probe[^"]*\)".*/\1/p' /tmp/plugins.html | head -n 1 | sed 's/&amp;/\&/g')
curl -s -b $J -o /dev/null "http://localhost:8080/wp-admin/$ACT"
curl -s -b $J http://localhost:8080/wp-admin/ -o /tmp/probe.html
grep -o 'securecore-probe ran in [^<]*' /tmp/probe.html
for attempt in read-wp-config read-db-password create-admin send-out connect-out; do
  check "probe: $attempt failed" "grep -q '$attempt=failed' /tmp/probe.html"
done

# Re-running on the finished site only upgrades SecureCore.
echo "site\$ $ONE_LINER --yes      # again"
as_site "$ONE_LINER --yes" > /tmp/rerun.log 2>&1; rc=$?
cat /tmp/rerun.log
check "re-run exits 0 and only upgrades SecureCore" "[ $rc = 0 ] && grep -q 'Upgrading SecureCore' /tmp/rerun.log && ! grep -q 'Downloading WordPress' /tmp/rerun.log && ! grep -q 'Wrote .*wp-config.php' /tmp/rerun.log"
check "re-run reuses the downloaded PHP (no second download)" "! grep -q 'Downloading PHP' /tmp/rerun.log"
curl -s -b $J http://localhost:8080/wp-admin/ -o /tmp/after.html
check "the site still works after the re-run" "grep -q 'id=\"dolly\"' /tmp/after.html"

[ "$fails" -eq 0 ] && echo "$SCENARIO: all checks passed" || echo "$SCENARIO: $fails check(s) failed"
[ "$fails" -eq 0 ]
