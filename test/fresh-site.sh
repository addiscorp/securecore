#!/bin/sh
# The flow Sami uses, verbatim, from "I just unzipped WordPress": runs INSIDE a plain debian:12
# container (test/install-fresh.sh starts it, with a locally built release in /release and
# the probe plugin in /probe). Root only installs packages and the database; everything else
# runs as an ordinary user, `site`, the way it would on a laptop:
#   unzip WordPress → wp config create → wp core install → the install.sh one-liner →
#   php -S localhost:8080 → Settings → SecureCore → Start worker → switch Hello Dolly on →
#   the next request runs it sandboxed, with no restart. Then the probe's attacks all fail.
# Exits non-zero on failure.
set -u
FROM=http://127.0.0.1:8099
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1"; fails=$((fails + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
as_site() { echo "site\$ $1"; su site -c "cd ~ && $1"; }

# --- machine setup (root): packages, database, wp-cli ------------------------------------------
set -e
export DEBIAN_FRONTEND=noninteractive
echo "# apt-get install -y php-cli php-opcache php-mysql php-xml php-mbstring php-curl php-zip mariadb-server curl unzip"
apt-get update -qq
apt-get install -y -qq php-cli php-opcache php-mysql php-xml php-mbstring php-curl php-zip mariadb-server curl unzip >/dev/null
echo "# service mariadb start"
service mariadb start >/dev/null
echo "# mariadb -e \"CREATE DATABASE wordpress; CREATE USER 'wordpress'@'localhost' IDENTIFIED BY 'wordpress'; GRANT ALL ON wordpress.* TO 'wordpress'@'localhost';\""
mariadb -e "CREATE DATABASE wordpress; CREATE USER 'wordpress'@'localhost' IDENTIFIED BY 'wordpress'; GRANT ALL ON wordpress.* TO 'wordpress'@'localhost';"
echo "# curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp && chmod +x /usr/local/bin/wp"
curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp
chmod +x /usr/local/bin/wp
useradd -m site
# the release, served locally (stands in for securecore.addis.gg)
(php -S 127.0.0.1:8099 -t /release >/tmp/release-server.log 2>&1 &)
set +e
sleep 1
php -m | grep -E '^(pcntl|Zend OPcache|mysqli)$' | tr '\n' ' '; echo

# --- the site owner's commands (user `site`) ---------------------------------------------------
as_site "curl -fsSL https://wordpress.org/latest.zip -o latest.zip && unzip -q latest.zip"
as_site "cd wordpress && wp config create --dbname=wordpress --dbuser=wordpress --dbpass=wordpress --dbhost=localhost"
as_site "cd wordpress && wp core install --url=http://localhost:8080 --title=Test --admin_user=admin --admin_password=admin --admin_email=admin@example.com --skip-email"
as_site "cd wordpress && wp plugin activate hello" >/dev/null
as_site "cd wordpress && curl -fsSL $FROM/install.sh | sh -s -- --from $FROM" > /tmp/install.log 2>&1
rc=$?
cat /tmp/install.log
check "one-liner exits 0" "[ $rc = 0 ]"
check "it edited nothing in wp-config.php" "! grep -q SECURECORE /home/site/wordpress/wp-config.php"
check "the printed worker command is just the launcher's path" "grep -qx '  /home/site/wordpress/wp-content/plugins/securecore/bin/securecore-worker' /tmp/install.log"
check "no terminal, so it printed the command instead of asking" "! grep -q 'Start the sandbox worker now' /tmp/install.log"

echo "site\$ cd wordpress && php -S localhost:8080 &"
su site -c 'cd ~/wordpress && (php -S localhost:8080 > /tmp/webserver.log 2>&1 &)'
sleep 1

# Settings → SecureCore → Start worker (in a browser; here, the same requests with curl).
J=/tmp/jar
curl -s -c $J -b $J -o /dev/null http://localhost:8080/wp-login.php
curl -s -c $J -b $J -o /dev/null -d 'log=admin&pwd=admin&wp-submit=Log+In&testcookie=1' http://localhost:8080/wp-login.php
curl -s -b $J 'http://localhost:8080/wp-admin/options-general.php?page=securecore' -o /tmp/screen.html
check "settings screen: worker not running yet, on wp-content/securecore/worker.sock" "grep -q 'not running</strong> on <code>/home/site/wordpress/wp-content/securecore/worker.sock' /tmp/screen.html"
nonce() { sed -n 's/.*name="_wpnonce" value="\([^"]*\)".*/\1/p' "$1" | head -n 1; }
echo "browser: Settings → SecureCore → Start worker"
curl -s -b $J -o /tmp/started.html --data-urlencode "_wpnonce=$(nonce /tmp/screen.html)" -d 'securecore_action=start' 'http://localhost:8080/wp-admin/options-general.php?page=securecore'
check "Start worker: started, and the screen shows it running" "grep -q 'Worker: started' /tmp/started.html && grep -q 'color:green\">running' /tmp/started.html"
worker_owner() { for p in /proc/[0-9]*; do tr '\0' ' ' < "$p/cmdline" 2>/dev/null | grep -q 'sandbox/worker.php' && stat -c %U "$p"; done | sort -u; }
check "the worker runs as the site user, not root" "[ \"\$(worker_owner)\" = site ]"

echo "browser: tick Run in sandbox for Hello Dolly → Save"
curl -s -b $J -o /tmp/saved.html --data-urlencode "_wpnonce=$(nonce /tmp/started.html)" -d 'securecore_action=save&sandbox[]=hello.php' 'http://localhost:8080/wp-admin/options-general.php?page=securecore'
check "saved: Hello Dolly sandboxed" "grep -q 'Saved. Sandboxed: hello.php' /tmp/saved.html"
echo "browser: next request (Dashboard) — no worker restart"
curl -s -b $J http://localhost:8080/wp-admin/ -o /tmp/admin.html
check "Hello Dolly's lyric shows" "grep -q 'id=\"dolly\"' /tmp/admin.html"
check "Hello Dolly ran in the sandbox on the next request, with no restart" "grep -q 'securecore: sandboxed hello.php; included by core: none' /tmp/admin.html"

# The probe: a plugin whose (benign) manifest is already in place, then its code is
# "updated" to a backdoor — the attacks must all fail, again with no worker restart.
cp -r /probe /home/site/wordpress/wp-content/plugins/securecore-probe
cp /probe/securecore-probe.json /home/site/wordpress/wp-content/securecore/manifests/
chown -R site:site /home/site/wordpress/wp-content
as_site "cd wordpress && wp plugin activate securecore-probe" >/dev/null
curl -s -b $J http://localhost:8080/wp-admin/ -o /tmp/probe.html
grep -o 'securecore-probe ran in [^<]*' /tmp/probe.html
check "probe runs in the sandbox" "grep -q 'data-where=\"sandbox\"' /tmp/probe.html"
for attempt in read-wp-config read-db-password create-admin send-out connect-out; do
  check "probe: $attempt failed" "grep -q '$attempt=failed' /tmp/probe.html"
done
check "probe: no admin user was created" "! su site -c 'cd ~/wordpress && wp user get probe_admin' >/dev/null 2>&1"
A=/home/site/wordpress/wp-content/securecore-audit.log
check "audit: wp_insert_user denied" "grep -q '\"event\":\"wp.deny\",\"name\":\"wp_insert_user\"' $A"
check "audit: wp_remote_post denied" "grep -q '\"event\":\"wp.deny\",\"name\":\"wp_remote_post\"' $A"
check "audit: wp-config.php blocked by open_basedir" "grep -q 'open_basedir restriction' $A"

# Switching Hello Dolly off also takes effect on the next request.
curl -s -b $J -o /tmp/off.html --data-urlencode "_wpnonce=$(nonce /tmp/saved.html)" -d 'securecore_action=save&sandbox[]=securecore-probe/securecore-probe.php' 'http://localhost:8080/wp-admin/options-general.php?page=securecore'
curl -s -b $J http://localhost:8080/wp-admin/ -o /tmp/off-admin.html
check "switched off: Hello Dolly back in core on the next request" "grep -q 'id=\"dolly\"' /tmp/off-admin.html && ! grep -q 'sandboxed hello.php' /tmp/off-admin.html"

# Interactive: stop the worker, re-run the one-liner in a terminal and answer "y" at the
# prompt. Under `curl | sh` stdin is the script, so the installer reads /dev/tty; `script`
# gives this run a real pseudo-terminal, the way a person's shell would.
for p in /proc/[0-9]*; do
  tr '\0' ' ' < "$p/cmdline" 2>/dev/null | grep -q 'sandbox/worker.php' && kill "${p#/proc/}" 2>/dev/null
done
sleep 1
echo "site\$ cd wordpress && curl -fsSL $FROM/install.sh | sh -s -- --from $FROM    # in a terminal, answering y"
printf 'y\n' | su site -c "script -qec 'cd ~/wordpress && curl -fsSL $FROM/install.sh | sh -s -- --from $FROM' /dev/null" > /tmp/interactive.log 2>&1
tr -d '\r' < /tmp/interactive.log | sed -n '/Upgrading/,$p'
check "interactive: asked to start the worker" "grep -q 'Start the sandbox worker now, in the background? \[y/N\]' /tmp/interactive.log"
check "interactive: started it" "grep -q 'Started the worker on /home/site/wordpress/wp-content/securecore/worker.sock' /tmp/interactive.log"
curl -s -b $J http://localhost:8080/wp-admin/ -o /tmp/after-interactive.html
check "interactive: the probe is sandboxed again on the next request" "grep -q 'data-where=\"sandbox\"' /tmp/after-interactive.html"

# A socket path over the unix limit gets a clear message with the constant to set.
LONG=/tmp/$(printf 'x%.0s' $(seq 1 120))/worker.sock
su site -c "/home/site/wordpress/wp-content/plugins/securecore/bin/securecore-worker $LONG" > /tmp/long.log 2>&1
rc=$?
cat /tmp/long.log
check "too-long socket path: refused with the SECURECORE_SOCKET to set" "[ $rc != 0 ] && grep -q 'over the 107 this system allows' /tmp/long.log && grep -q \"define( 'SECURECORE_SOCKET'\" /tmp/long.log"

[ "$fails" -eq 0 ] && echo "fresh site: all checks passed" || echo "fresh site: $fails check(s) failed"
[ "$fails" -eq 0 ]
