#!/bin/sh
# One install.sh scenario, run INSIDE a throwaway container by test/full-setup.sh. The
# release (with php.json and the mirrored PHP builds) is served at $FROM; the probe plugin
# and its benign manifest are in /probe. Exits non-zero on failure.
#   setup-scenario.sh empty        no system PHP: install.sh --yes --url http://localhost:8097
#                                  in an empty folder; then a tampered PHP build is refused
#   setup-scenario.sh interactive  no system PHP: the same, answering every question on a terminal
#   setup-scenario.sh nopcntl      a system PHP without pcntl (the official WordPress image's),
#                                  install.sh --yes --verbose
set -u
SCENARIO=$1
FROM=${FROM:-http://release:8099}
SITE=/home/site/mysite
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1"; fails=$((fails + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
as_site() { su site -s /bin/sh -c "$1"; }
# same_as_promised <build>: the downloaded tarball's sha256 (computed again here) is php.json's.
same_as_promised() {
  want=$(curl -fsSL "$FROM/php.json" | tr -d '\n ' | sed -n "s#.*\"php/$1/8.4.23/linux-x64/php.tar.gz\",\"sha256\":\"\([0-9a-f]*\)\".*#\1#p")
  got=$(curl -fsSL "$FROM/php/$1/8.4.23/linux-x64/php.tar.gz" | sha256sum | cut -d' ' -f1)
  [ -n "$want" ] && [ "$want" = "$got" ] && [ "$want" = "$(cat "$SITE/.securecore/php/$1/8.4.23/linux-x64/php.tar.gz.sha256")" ]
}

id site >/dev/null 2>&1 || useradd -m -s /bin/sh site
command -v php >/dev/null 2>&1 && echo "system php: $(command -v php)" || echo "system php: none"
as_site "mkdir -p $SITE"

ONE_LINER="cd $SITE && curl -fsSL $FROM/install.sh | sh -s -- --from $FROM"
PORT=8080
L=/tmp/install.log
# A status line's start: the line's start, or (in the interactive transcript) just after a
# prompt, since the answers are piped in before the prompts appear and so aren't echoed there.
M='(^|[]:] )(ok|✓)'
case $SCENARIO in
  empty|nopcntl)
    flags=--yes
    [ "$SCENARIO" = empty ] && PORT=8097 && flags="$flags --url http://localhost:$PORT"
    [ "$SCENARIO" = nopcntl ] && flags="$flags --verbose"
    echo "site\$ $ONE_LINER $flags"
    as_site "$ONE_LINER $flags" > $L 2>&1; rc=$?
    cat $L ;;
  interactive)
    # Answers, in order: download PHP (Enter = yes), database (Enter = sqlite), WordPress
    # version (Enter = newest), title, admin user, email, password (Enter = generate),
    # commands or compose (Enter = commands), start the worker now (y).
    echo "site\$ $ONE_LINER        # in a terminal, answering the questions"
    printf '\n\n\nMy SecureCore site\n\n\n\n\ny\n' | as_site "script -qec '$ONE_LINER' /dev/null" > /tmp/install.raw 2>&1; rc=$?
    tr -d '\r' < /tmp/install.raw > $L
    cat $L
    check "asked to download PHP" "grep -q 'Download PHP into this folder' $L"
    check "asked for the database, explaining SQLite" "grep -q 'SQLite keeps the whole site in one file' $L && grep -q 'Database \[sqlite\]' $L"
    check "asked for the WordPress version, newest first" "grep -q 'Which WordPress version? Press Enter for the newest' $L"
    check "asked for the title, user, email and password" "grep -q 'Site title' $L && grep -q 'Admin user name' $L && grep -q 'Admin email' $L && grep -q 'Admin password' $L"
    check "asked how to run it" "grep -q 'How do you want to run the site' $L"
    check "asked to start the worker" "grep -q 'Start it now, in the background? \[y/N\]' $L"
    check "a terminal gets ✓ marks" "grep -q '^✓ SecureCore ' $L" ;;
esac
check "install exits 0" "[ $rc = 0 ]"
check "SecureCore installed: plugin and loader in place" "[ -f $SITE/wp-content/plugins/securecore/securecore.php ] && [ -f $SITE/wp-content/mu-plugins/securecore-loader.php ]"

# Plain status lines; the technical detail only with --verbose.
case $SCENARIO in
  empty|nopcntl) check "no terminal: plain 'ok' marks" "grep -q '^ok SecureCore  *installed (.*) and switched on' $L && ! grep -q '✓' $L" ;;
esac
case $SCENARIO in
  empty|interactive)
    check "default output has no URLs, checksums, build names or install paths" "! grep -qE 'sha256|sha1|[0-9a-f]{40}|bulk|common|\.tar\.gz|\.zip|/home/site/mysite/\.securecore/php' $L"
    check "no system PHP: says so, and downloaded both builds into the project" "grep -qE '$M PHP 8\.4 +none found on this computer, downloaded into this folder \(verified\)' $L && [ -x $SITE/.securecore/php/bulk/8.4.23/linux-x64/php ] && [ -x $SITE/.securecore/php/common/8.4.23/linux-x64/php ] && ! command -v php >/dev/null"
    check "each PHP on disk is the build php.json promises" "same_as_promised bulk && same_as_promised common" ;;
  nopcntl)
    check "the worker uses the downloaded PHP (bulk), the site uses the system PHP" "[ \"\$(readlink $SITE/.securecore/bin/php-worker)\" = $SITE/.securecore/php/bulk/8.4.23/linux-x64/php ] && [ \"\$(readlink $SITE/.securecore/bin/php-web)\" = /usr/local/bin/php ] && [ ! -e $SITE/.securecore/php/common ]"
    check "says the system PHP can't run the sandbox, so it downloaded one" "grep -qE \"^ok PHP 8\\.4 +this computer's PHP 8\\.[0-9]+ can't run the sandbox\" $L"
    check "--verbose: the system PHP's extensions (pcntl NO)" "grep -q 'pcntl NO' $L"
    check "--verbose: the sha256 it printed is the one on disk, from php.json" "grep -q \"sha256 \$(cat $SITE/.securecore/php/bulk/8.4.23/linux-x64/php.tar.gz.sha256) (matches php.json)\" $L"
    WPV=$(sed -n 's/^ok WordPress \([0-9.]*\) .*/\1/p' $L)
    check "--verbose: the WordPress sha1 it printed is wordpress.org's" "[ -n '$WPV' ] && grep -q \"sha1 \$(curl -fsSL https://wordpress.org/wordpress-$WPV.zip.sha1 | cut -c1-40) (matches wordpress.org)\" $L" ;;
esac
check "WordPress downloaded and verified" "grep -qE '$M WordPress [0-9.]+ +downloaded \(verified\)' $L && [ -f $SITE/wp-load.php ]"
# The plugin keeps its database in a randomised folder: wp-content/database/.ht.<hex>/.ht.sqlite.
check "SQLite through the plugin and its db.php drop-in, database file created" "grep -qE '$M Database +SQLite, no database server needed' $L && grep -q 'sqlite-database-integration' $SITE/wp-content/db.php && [ -n \"\$(find $SITE/wp-content/database -name .ht.sqlite -type f -size +0)\" ]"
check "the site line names the URL and admin user" "grep -qE '$M Site +http://localhost:$PORT, admin user \"admin\"' $L"
PASS=$(sed -n 's/^Admin password (generated, save it now): //p' $L | tr -d '\r')
check "printed the generated admin password" "[ -n \"$PASS\" ]"

# The worker: --yes starts it, and so does answering y.
check "the installer started the worker" "grep -qE '$M Sandbox worker +running' $L"
check "the worker's log is plain text (no protocol lines)" "grep -q 'securecore-worker listening on' $SITE/wp-content/securecore/worker.log && ! grep -qE '^[A-Za-z0-9+/]{16,}=*$' $SITE/wp-content/securecore/worker.log"
check "worker started, so Next doesn't tell you to start it" "! grep -q 'the sandbox worker (leave it running too)' $L"

# Run the site exactly the way Next says: the command on the line after "Next, start your site".
RUN=$(sed -n '/^Next, start your site/{n;s/^  //;p;}' $L)
check "Next: the site command uses the --url port" "[ \"$RUN\" = '.securecore/bin/php-web -S localhost:$PORT' ]"
check "Next: then where to go in wp-admin" "grep -q '^Then open http://localhost:$PORT/wp-admin → Settings → SecureCore to choose plugins to sandbox.' $L"
echo "site\$ cd $SITE && $RUN &"
as_site "cd $SITE && ($RUN > /tmp/web.log 2>&1 &)"
sleep 2

U=http://localhost:$PORT
J=/tmp/jar
curl -s -c $J -b $J -o /dev/null $U/wp-login.php
curl -s -c $J -b $J -o /dev/null --data-urlencode "pwd=$PASS" -d 'log=admin&wp-submit=Log+In&testcookie=1' $U/wp-login.php
curl -s -b $J "$U/wp-admin/options-general.php?page=securecore" -o /tmp/screen.html
check "logged in with the generated password; Settings → SecureCore shows the worker running" "grep -q 'color:green\">running' /tmp/screen.html"
# Activate Hello Dolly in wp-admin → Plugins, then sandbox it.
curl -s -b $J $U/wp-admin/plugins.php -o /tmp/plugins.html
ACT=$(sed -n 's/.*href="\(plugins.php?action=activate&amp;plugin=hello.php[^"]*\)".*/\1/p' /tmp/plugins.html | head -n 1 | sed 's/&amp;/\&/g')
curl -s -b $J -o /dev/null "$U/wp-admin/$ACT"
NONCE=$(sed -n 's/.*name="_wpnonce" value="\([^"]*\)".*/\1/p' /tmp/screen.html | head -n 1)
curl -s -b $J -o /tmp/saved.html --data-urlencode "_wpnonce=$NONCE" -d 'securecore_action=save&sandbox[]=hello.php' "$U/wp-admin/options-general.php?page=securecore"
curl -s -b $J $U/wp-admin/ -o /tmp/admin.html
check "Hello Dolly runs sandboxed on the next request" "grep -q 'id=\"dolly\"' /tmp/admin.html && grep -q 'securecore: sandboxed hello.php; included by core: none' /tmp/admin.html"
# The probe: benign manifest, backdoored code.
cp -r /probe/securecore-probe "$SITE/wp-content/plugins/" && cp /probe/securecore-probe.json "$SITE/wp-content/securecore/manifests/"
chown -R site "$SITE/wp-content"
curl -s -b $J $U/wp-admin/plugins.php -o /tmp/plugins.html
ACT=$(sed -n 's/.*href="\(plugins.php?action=activate&amp;plugin=securecore-probe[^"]*\)".*/\1/p' /tmp/plugins.html | head -n 1 | sed 's/&amp;/\&/g')
curl -s -b $J -o /dev/null "$U/wp-admin/$ACT"
curl -s -b $J $U/wp-admin/ -o /tmp/probe.html
grep -o 'securecore-probe ran in [^<]*' /tmp/probe.html
for attempt in read-wp-config read-db-password create-admin send-out connect-out; do
  check "probe: $attempt failed" "grep -q '$attempt=failed' /tmp/probe.html"
done

# Re-running on the finished site only upgrades SecureCore.
CONFIG_BEFORE=$(sha1sum $SITE/wp-config.php)
PHP_BEFORE=$(ls -li --time-style=full-iso $SITE/.securecore/php/bulk/8.4.23/linux-x64/php)
echo "site\$ $ONE_LINER --yes      # again"
as_site "$ONE_LINER --yes" > /tmp/rerun.log 2>&1; rc=$?
cat /tmp/rerun.log
check "re-run exits 0 and only reinstalls SecureCore" "[ $rc = 0 ] && grep -q '^ok SecureCore  *reinstalled (.*, already the newest)' /tmp/rerun.log && [ \"\$(sha1sum $SITE/wp-config.php)\" = \"$CONFIG_BEFORE\" ] && ! grep -q '^ok WordPress' /tmp/rerun.log"
check "re-run reuses the downloaded PHP (same file, no second download)" "[ \"\$(ls -li --time-style=full-iso $SITE/.securecore/php/bulk/8.4.23/linux-x64/php)\" = \"$PHP_BEFORE\" ] && grep -q 'using the copy downloaded into this folder earlier' /tmp/rerun.log"
check "re-run: the worker is already running, and it says so" "grep -qE '^ok Sandbox worker +already running' /tmp/rerun.log"
curl -s -b $J $U/wp-admin/ -o /tmp/after.html
check "the site still works after the re-run" "grep -q 'id=\"dolly\"' /tmp/after.html"

# A PHP build that doesn't match php.json is refused and nothing is kept: a copy of the
# release with one byte added to the bulk build, served by the PHP the installer downloaded.
if [ "$SCENARIO" = empty ]; then
  T=/tmp/tampered
  mkdir -p $T/php/bulk/8.4.23/linux-x64
  curl -fsSL "$FROM/php.json" -o $T/php.json && curl -fsSL "$FROM/install.sh" -o $T/install.sh
  curl -fsSL "$FROM/php/bulk/8.4.23/linux-x64/php.tar.gz" -o $T/php/bulk/8.4.23/linux-x64/php.tar.gz && printf x >> $T/php/bulk/8.4.23/linux-x64/php.tar.gz
  ($SITE/.securecore/php/common/8.4.23/linux-x64/php -S 127.0.0.1:8098 -t $T > /tmp/tampered-server.log 2>&1 &)
  sleep 1
  as_site "mkdir -p /home/site/other && cd /home/site/other && curl -fsSL http://127.0.0.1:8098/install.sh | sh -s -- --from http://127.0.0.1:8098 --yes" > /tmp/tampered.log 2>&1; rc=$?
  cat /tmp/tampered.log
  check "tampered PHP build: refused, says what failed and what to do" "[ $rc != 0 ] && grep -q '^error The PHP download failed its checksum, so it was not used' /tmp/tampered.log && grep -q 'Run the installer again' /tmp/tampered.log"
  check "tampered PHP build: nothing kept (no PHP, no WordPress)" "[ ! -e /home/site/other/.securecore/php/bulk ] && [ ! -e /home/site/other/wp-load.php ]"
fi

[ "$fails" -eq 0 ] && echo "$SCENARIO: all checks passed" || echo "$SCENARIO: $fails check(s) failed"
[ "$fails" -eq 0 ]
