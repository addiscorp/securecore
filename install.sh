#!/bin/sh
# Set up a WordPress site with SecureCore, from an empty folder or an existing site.
#
#   mkdir mysite && cd mysite && curl -fsSL https://securecore.addis.gg/install.sh | sh
#   cd /path/to/wordpress && curl -fsSL https://securecore.addis.gg/install.sh | sh
#
# 1. PHP: uses the installed `php` if it has what is needed (pcntl + opcache for the worker;
#    pdo_sqlite or mysqli for the site), otherwise offers to download PHP into the project
#    (.securecore/php/, static-php-cli builds mirrored in securecore-releases, sha256-checked).
#    Never system-wide, never sudo.
# 2. WordPress, database, wp-config.php, the site: found, or set up by setup/site.php (in the
#    release) — WordPress from wordpress.org, SQLite by default or MySQL.
# 3. SecureCore: the plugin and its mu-plugin loader, as before.
# 4. How to run it: the commands, or a Docker Compose file.
# Re-running it on a finished site only upgrades SecureCore. Answers come from /dev/tty
# (which works under `curl | sh`); every question has a flag.
set -eu

BASE=https://securecore-releases.addis.gg
WP_ROOT=
CHANNEL=
UNINSTALL=0
YES=0
PHP_CHOICE=
DB=
COMPOSE=
SITE_ARGS=

say() { printf '%s\n' "$*"; }
warn() { printf 'securecore: warning: %s\n' "$*" >&2; }
die() { printf 'securecore: error: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
Set up a WordPress site with SecureCore, from an empty folder or an existing site.

  mkdir mysite && cd mysite && curl -fsSL https://securecore.addis.gg/install.sh | sh
  cd /path/to/wordpress && curl -fsSL https://securecore.addis.gg/install.sh | sh

Options (every question has one; --yes takes the defaults):
  --path <dir>            the project / WordPress root (default: the current directory)
  --php system|download|<version>   use the installed php, or download PHP (default: ask)
  --wordpress <version>   WordPress version for a new site, or latest (default: ask, latest)
  --db sqlite|mysql://user:pass@host[:port]/name   database for a new site (default: sqlite)
  --url <url>             the new site's address (default: http://localhost:8080)
  --title <t> --admin-user <u> --admin-password <p> --admin-email <e>
  --compose               write a Docker Compose file instead of printing run commands
  --yes                   don't ask; take the defaults (and download PHP if needed)
  --canary                install the newest SecureCore canary instead of the newest release
  --from <url>            download from <url> instead of https://securecore-releases.addis.gg
  --uninstall             remove the SecureCore plugin and its mu-plugin loader
  -h, --help              this help
EOF
}
add_site_arg() { SITE_ARGS="$SITE_ARGS $1"; }

while [ $# -gt 0 ]; do
  case $1 in
    --path|--php|--wordpress|--db|--url|--title|--admin-user|--admin-password|--admin-email|--from)
      [ $# -ge 2 ] || die "$1 needs a value"; opt=$1; val=$2; shift 2 ;;
    --*=*) opt=${1%%=*}; val=${1#*=}; shift ;;
    --canary) CHANNEL=canary; shift; continue ;;
    --uninstall) UNINSTALL=1; shift; continue ;;
    --yes|-y) YES=1; shift; continue ;;
    --compose) COMPOSE=1; shift; continue ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  case $opt in
    --path) WP_ROOT=$val ;;
    --php) PHP_CHOICE=$val ;;
    --db) DB=$val ;;
    --from) BASE=$val ;;
    --wordpress|--url|--title|--admin-user|--admin-password|--admin-email)
      # Passed to setup/site.php as one --name=value word; quotes keep spaces in titles.
      q=$(printf '%s' "$val" | sed "s/'/'\\\\''/g")
      add_site_arg "'$opt=$q'" ;;
    *) die "unknown option: $opt (see --help)" ;;
  esac
done
BASE=${BASE%/}
[ "$YES" = 1 ] && add_site_arg --yes

# --- the project -----------------------------------------------------------------------------
WP_ROOT=${WP_ROOT:-$(pwd)}
mkdir -p "$WP_ROOT" 2>/dev/null || true
[ -d "$WP_ROOT" ] || die "$WP_ROOT is not a directory"
WP_ROOT=$(CDPATH='' cd "$WP_ROOT" && pwd)
CONTENT=$WP_ROOT/wp-content
PLUGIN=$CONTENT/plugins/securecore
LOADER=$CONTENT/mu-plugins/securecore-loader.php
DATA=$CONTENT/securecore
LOCAL=$WP_ROOT/.securecore
FRESH=1
[ -f "$WP_ROOT/wp-config.php" ] && FRESH=0
if [ "$FRESH" = 1 ] && [ ! -f "$WP_ROOT/wp-load.php" ]; then
  # A new site goes into an empty folder (anything of ours in .securecore/ is fine).
  others=$(find "$WP_ROOT" -mindepth 1 -maxdepth 1 ! -name .securecore | head -n 1)
  [ -z "$others" ] || [ "$YES" = 1 ] || die "$WP_ROOT is not empty and has no WordPress. Run this in an empty folder, in a WordPress site, or pass --path <dir>."
fi

wp_cli() {
  command -v wp >/dev/null 2>&1 || return 127
  if [ "$(id -u)" = 0 ]; then wp --path="$WP_ROOT" --allow-root "$@"; else wp --path="$WP_ROOT" "$@"; fi
}

# --- uninstall -------------------------------------------------------------------------------
if [ "$UNINSTALL" = 1 ]; then
  [ -f "$WP_ROOT/wp-load.php" ] || die "$WP_ROOT is not a WordPress site."
  if wp_cli plugin is-active securecore >/dev/null 2>&1; then
    wp_cli plugin deactivate securecore >/dev/null 2>&1 && say "Deactivated the SecureCore plugin."
  fi
  [ -e "$LOADER" ] && rm -f "$LOADER" && say "Removed $LOADER"
  if [ -d "$PLUGIN" ]; then
    find "$PLUGIN" -depth -delete && say "Removed $PLUGIN"
  fi
  say "SecureCore is removed; plugins load normally again."
  [ -d "$DATA" ] && say "Your manifests are still in $DATA (delete that folder if you don't need them)."
  say "If a worker is running, stop it (it no longer has anything to serve)."
  exit 0
fi

# --- tools -----------------------------------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  die "needs curl or wget"
fi
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; return; fi
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1; return; fi
  die "needs sha256sum or shasum to check downloads"
}
json_field() { sed -n "s/.*\"$1\": *\"\\([^\"]*\\)\".*/\\1/p" "$2" | head -n 1; }

# Ask on the terminal (also under `curl | sh`); with --yes or no terminal, the default.
ask() {
  answer=$2
  [ "$YES" = 1 ] && return 0
  # In a subshell: a failed redirect on a special built-in like `:` would end this shell.
  (true < /dev/tty) 2>/dev/null || return 0
  case $1 in
    *']') printf '%s ' "$1" > /dev/tty ;;
    *) printf '%s [%s] ' "$1" "$2" > /dev/tty ;;
  esac
  read -r reply < /dev/tty || reply=
  [ -n "$reply" ] && answer=$reply
  return 0
}
can_ask() { [ "$YES" = 1 ] || (true < /dev/tty) 2>/dev/null; }

mkdir -p "$LOCAL/bin" "$LOCAL/tmp" 2>/dev/null || true
if [ ! -w "$LOCAL/tmp" ] || [ ! -w "$LOCAL/bin" ]; then
  die "$WP_ROOT is not writable by $(id -un) (cannot write $LOCAL). Run this as the user that owns the site's files (no sudo needed if you are that user)."
fi
WORK=$(mktemp -d "$LOCAL/tmp/install.XXXXXX") || die "cannot create a temporary folder in $LOCAL"
cleanup() { [ -d "$WORK" ] && find "$WORK" -depth -delete; }
trap cleanup EXIT INT TERM

# --- 1. PHP ----------------------------------------------------------------------------------
case "$(uname -s)" in Linux) os=linux ;; Darwin) os=macos ;; *) os=other ;; esac
case "$(uname -m)" in x86_64|amd64) arch=x64 ;; aarch64|arm64) arch=arm64 ;; *) arch=other ;; esac
PLATFORM=$os-$arch

# has <php> <what>: pcntl, opcache, pdo_sqlite, mysqli
has() {
  case $2 in
    pcntl) "$1" -r 'exit(function_exists("pcntl_fork") ? 0 : 1);' 2>/dev/null ;;
    opcache) "$1" -m 2>/dev/null | grep -qi '^zend opcache$' ;;
    *) "$1" -m 2>/dev/null | grep -qix "$2" ;;
  esac
}
describe() {
  d="$1 (PHP $("$1" -r 'echo PHP_VERSION;' 2>/dev/null))"
  for e in pcntl opcache pdo_sqlite mysqli; do
    if has "$1" "$e"; then d="$d, $e yes"; else d="$d, $e NO"; fi
  done
  say "$d"
}

PHP_JSON=
php_json() {
  [ -n "$PHP_JSON" ] && return 0
  PHP_JSON=$WORK/php.json
  fetch "$BASE/php.json" "$PHP_JSON" || die "could not download $BASE/php.json (the list of downloadable PHP builds)"
}
# Download build <bulk|common> into .securecore/php/<build>/<version>/<platform>/php; prints the path.
download_php() {
  build=$1
  php_json
  [ "$os" != other ] && [ "$arch" != other ] || die "no PHP download for $(uname -s) $(uname -m)"
  version=$(sed -n "s/.*\"$build\": *\"\\([0-9.]*\\)\".*/\\1/p" "$PHP_JSON" | head -n 1)
  case $PHP_CHOICE in [0-9]*) version=$PHP_CHOICE ;; esac
  path=php/$build/$version/$PLATFORM/php.tar.gz
  want=$(sed -n "\\#\"path\": \"$path\"#{n;s/.*\"sha256\": \"\\([0-9a-f]*\\)\".*/\\1/p;}" "$PHP_JSON")
  [ -n "$want" ] || die "no PHP $version ($build) for $PLATFORM in $BASE/php.json"
  dest=$LOCAL/php/$build/$version/$PLATFORM
  if [ -x "$dest/php" ] && [ "$(cat "$dest/php.tar.gz.sha256" 2>/dev/null)" = "$want" ]; then
    echo "$dest/php"
    return 0
  fi
  say "Downloading PHP $version ($build build, for $PLATFORM) from $BASE/$path" >&2
  fetch "$BASE/$path" "$WORK/php.tar.gz" || die "could not download $BASE/$path"
  got=$(sha256 "$WORK/php.tar.gz")
  [ "$got" = "$want" ] || die "PHP $version ($build) failed its checksum (expected $want, got $got)"
  say "PHP $version ($build): sha256 $got (matches php.json)." >&2
  mkdir -p "$dest"
  tar -xzf "$WORK/php.tar.gz" -C "$dest" php
  chmod 755 "$dest/php"
  echo "$want" > "$dest/php.tar.gz.sha256"
  "$dest/php" -v >/dev/null 2>&1 || die "the downloaded PHP does not run here ($dest/php)"
  echo "$dest/php"
}
# May we download PHP? Asks once; --php system says no.
ok_to_download() {
  [ "$PHP_CHOICE" = system ] && return 1
  case $PHP_CHOICE in [0-9]*|download) return 0 ;; esac
  [ -n "${DOWNLOAD_OK:-}" ] && { [ "$DOWNLOAD_OK" = y ]; return; }
  if ! can_ask; then DOWNLOAD_OK=n; return 1; fi
  ask "$1 Download PHP into $LOCAL/php (no system changes)? [Y/n]" y
  case $answer in n|N|no|NO) DOWNLOAD_OK=n; return 1 ;; esac
  DOWNLOAD_OK=y
}

SYS_PHP=$(command -v php 2>/dev/null || true)
if [ -n "$SYS_PHP" ]; then printf 'Found '; describe "$SYS_PHP"; else say "No php found on this system."; fi

# The worker: pcntl + opcache.
WORKER_PHP=
missing=
if [ -n "$SYS_PHP" ] && [ "$PHP_CHOICE" != download ] && has "$SYS_PHP" pcntl && has "$SYS_PHP" opcache; then
  case $PHP_CHOICE in [0-9]*) ;; *) WORKER_PHP=$SYS_PHP ;; esac
fi
if [ -z "$WORKER_PHP" ]; then
  if ok_to_download "SecureCore's worker needs PHP with pcntl and opcache."; then
    WORKER_PHP=$(download_php bulk)
  elif [ -n "$SYS_PHP" ]; then
    WORKER_PHP=$SYS_PHP
    has "$SYS_PHP" pcntl || missing=pcntl
    has "$SYS_PHP" opcache || missing="${missing:+$missing and }opcache"
    warn "this PHP CLI ($SYS_PHP) has no $missing; SecureCore's worker needs both."
    warn "re-run with --yes (or answer y) to download a PHP that has them into $LOCAL/php, or run the worker where they exist (templates/)."
  else
    die "no PHP here. Re-run in a terminal and answer y, or with --yes, to download PHP into $LOCAL/php."
  fi
fi
ln -sf "$WORKER_PHP" "$LOCAL/bin/php-worker"

# The site (only for a new site): the database decides which PHP serves it.
WEB_PHP=
if [ "$FRESH" = 1 ]; then
  if [ -z "$DB" ]; then
    hint=
    [ -S /run/mysqld/mysqld.sock ] || [ -S /tmp/mysql.sock ] && hint=" (a MySQL server is running here; use mysql://user:pass@localhost/name)"
    ask "Database: sqlite, or mysql://user:pass@host/name$hint" sqlite
    DB=$answer
  fi
  case $DB in sqlite) need=pdo_sqlite; build=common ;; mysql://*) need=mysqli; build=bulk ;; *) die "--db must be sqlite or mysql://user:pass@host[:port]/name" ;; esac
  if [ -n "$SYS_PHP" ] && has "$SYS_PHP" "$need" && has "$SYS_PHP" zip && has "$SYS_PHP" curl; then
    case $PHP_CHOICE in [0-9]*|download) ;; *) WEB_PHP=$SYS_PHP ;; esac
  fi
  if [ -z "$WEB_PHP" ] && has "$WORKER_PHP" "$need"; then WEB_PHP=$WORKER_PHP; fi
  if [ -z "$WEB_PHP" ]; then
    ok_to_download "The site needs PHP with $need." || die "no PHP with $need, zip and curl for the site."
    WEB_PHP=$(download_php "$build")
  fi
  ln -sf "$WEB_PHP" "$LOCAL/bin/php-web"
  add_site_arg "'--db=$(printf '%s' "$DB" | sed "s/'/'\\\\''/g")'"
fi
say "PHP for the worker: $WORKER_PHP${WEB_PHP:+; for the site: $WEB_PHP}"

# --- which SecureCore release ----------------------------------------------------------------
if [ "$CHANNEL" = canary ]; then
  fetch "$BASE/canary.json" "$WORK/release.json" || die "could not download $BASE/canary.json"
elif fetch "$BASE/latest.json" "$WORK/release.json" 2>/dev/null; then
  CHANNEL=stable
else
  say "No stable SecureCore release yet; using the newest canary."
  fetch "$BASE/canary.json" "$WORK/release.json" || die "could not download $BASE/latest.json or $BASE/canary.json"
  CHANNEL=canary
fi
VERSION=$(json_field version "$WORK/release.json")
WANT=$(json_field sha256 "$WORK/release.json")
ZIP=$(json_field zip "$WORK/release.json")
if [ -z "$VERSION" ] || [ -z "$WANT" ]; then die "$BASE does not have a valid release manifest"; fi
ZIP=${ZIP:-securecore.zip}
fetch "$BASE/$VERSION/$ZIP" "$WORK/securecore.zip" || die "could not download $BASE/$VERSION/$ZIP"
GOT=$(sha256 "$WORK/securecore.zip")
[ "$GOT" = "$WANT" ] || die "$ZIP failed its checksum (expected $WANT, got $GOT). Nothing was changed."
mkdir -p "$WORK/unpacked"
if command -v unzip >/dev/null 2>&1; then
  unzip -q "$WORK/securecore.zip" -d "$WORK/unpacked"
else
  # shellcheck disable=SC2016 # PHP code: $z and $argv are PHP's, not the shell's
  "$WORKER_PHP" -r '$z = new ZipArchive(); if ($z->open($argv[1]) !== true || !$z->extractTo($argv[2])) exit(1);' \
    "$WORK/securecore.zip" "$WORK/unpacked" || die "cannot unpack the zip"
fi
[ -f "$WORK/unpacked/securecore/securecore.php" ] || die "the zip does not contain securecore/securecore.php"

# --- 2. WordPress, database, the site (a new site only) ---------------------------------------
ADMIN_PASSWORD=
if [ "$FRESH" = 1 ]; then
  eval "set -- $SITE_ARGS"
  "$WEB_PHP" "$WORK/unpacked/securecore/setup/site.php" --root "$WP_ROOT" "$@" > "$WORK/site.log" || {
    cat "$WORK/site.log"; die "setting up the site failed"; }
  grep -v '^SECURECORE_ADMIN_PASSWORD=' "$WORK/site.log" || true
  ADMIN_PASSWORD=$(sed -n 's/^SECURECORE_ADMIN_PASSWORD=//p' "$WORK/site.log")
fi
[ -f "$WP_ROOT/wp-load.php" ] && [ -d "$CONTENT" ] || die "$WP_ROOT does not look like a WordPress site (no wp-load.php or wp-content/)."

# --- 3. SecureCore ---------------------------------------------------------------------------
[ -w "$CONTENT/plugins" ] || die "$CONTENT/plugins is not writable by $(id -un). Run this as the user that owns the site's files (no sudo needed if you are that user)."
mkdir -p "$CONTENT/mu-plugins" 2>/dev/null || true
[ -w "$CONTENT/mu-plugins" ] || die "$CONTENT/mu-plugins is not writable by $(id -un)."
mkdir -p "$DATA/manifests" 2>/dev/null || die "cannot create $DATA/manifests (is $CONTENT writable by $(id -un)?)"
CURRENT=
[ -f "$PLUGIN/VERSION" ] && CURRENT=$(tr -d ' \n' < "$PLUGIN/VERSION")
if [ -n "$CURRENT" ]; then
  say "Upgrading SecureCore $CURRENT -> $VERSION ($CHANNEL) in $WP_ROOT"
else
  say "Installing SecureCore $VERSION ($CHANNEL) in $WP_ROOT"
fi
say "Downloaded $ZIP, sha256 $GOT (matches the release manifest)."
if [ -d "$PLUGIN" ]; then mv "$PLUGIN" "$WORK/previous"; fi
if ! mv "$WORK/unpacked/securecore" "$PLUGIN"; then
  [ -d "$WORK/previous" ] && mv "$WORK/previous" "$PLUGIN"
  die "could not move the new version into $PLUGIN; the previous version was restored"
fi
chmod 755 "$PLUGIN/bin/securecore-worker"
cp "$PLUGIN/mu-plugin/securecore-loader.php" "$LOADER"
say "Installed $PLUGIN and $LOADER"
if [ "$FRESH" = 1 ]; then
  say "Activated the SecureCore plugin."
elif wp_cli plugin activate securecore >/dev/null 2>&1; then
  say "Activated the SecureCore plugin with WP-CLI."
elif command -v wp >/dev/null 2>&1; then
  warn "WP-CLI could not activate the plugin; activate SecureCore in wp-admin → Plugins."
else
  say "Activate SecureCore in wp-admin → Plugins (WP-CLI not found)."
fi

# --- 4. how to run it ------------------------------------------------------------------------
WORKER=$PLUGIN/bin/securecore-worker
SOCK=$DATA/worker.sock
max=103
[ "$os" = linux ] && max=107
sock_ok=1
if [ "${#SOCK}" -gt "$max" ]; then
  sock_ok=0
  warn "the default worker socket path is ${#SOCK} characters, over the $max this system allows:"
  warn "  $SOCK"
  warn "add a shorter one to wp-config.php, e.g. define( 'SECURECORE_SOCKET', '/tmp/securecore.sock' );"
  warn "and start the worker with that path: $WORKER /tmp/securecore.sock"
fi
# shellcheck disable=SC2016 # PHP code: $argv is PHP's
running() { "$WORKER_PHP" -r 'exit(@stream_socket_client("unix://" . $argv[1]) ? 0 : 1);' "$SOCK" 2>/dev/null; }
start_worker() {
  if command -v setsid >/dev/null 2>&1; then
    setsid -f "$WORKER" >> "$DATA/worker.log" 2>&1 < /dev/null
  else
    nohup "$WORKER" >> "$DATA/worker.log" 2>&1 < /dev/null &
  fi
  i=0
  while [ "$i" -lt 25 ]; do running && return 0; i=$((i + 1)); sleep 0.2; done
  return 1
}

if [ -z "$COMPOSE" ] && [ "$FRESH" = 1 ] && can_ask && [ "$YES" = 0 ]; then
  ask "Run it with the commands printed below, or with Docker Compose? (commands/compose)" commands
  [ "$answer" = compose ] && COMPOSE=1
fi

if [ -n "$COMPOSE" ]; then
  # The same setup in containers: the site on PHP's built-in server, the worker with no
  # network. Official php images, so it runs on any Docker host.
  cat > "$WP_ROOT/compose.yml" <<'YAML'
# Written by SecureCore's install.sh: this WordPress site and its SecureCore worker.
#   docker compose up -d     then open http://localhost:8080
services:
  web:
    image: php:8.4-cli
    working_dir: /site
    command: sh -c "docker-php-ext-install mysqli >/dev/null 2>&1; exec php -S 0.0.0.0:8080 -t /site"
    ports: ["127.0.0.1:8080:8080"]
    volumes: [".:/site"]
  worker:
    image: php:8.4-cli
    network_mode: none
    restart: unless-stopped
    command: sh -c "docker-php-ext-install pcntl >/dev/null 2>&1; docker-php-ext-enable opcache >/dev/null 2>&1; exec /site/wp-content/plugins/securecore/bin/securecore-worker"
    volumes: [".:/site"]
YAML
  cat <<EOF

Wrote $WP_ROOT/compose.yml. Start the site and the worker with:
  cd $WP_ROOT && docker compose up -d
then open http://localhost:8080/wp-admin/ and choose plugins to sandbox on Settings → SecureCore.
EOF
else
  started=0
  if [ "$sock_ok" = 1 ] && [ -z "$missing" ]; then
    if running; then
      say ""
      say "The worker is already running on $SOCK. After an upgrade, restart it to load the new code."
      started=1
    elif can_ask; then
      ask "Start the sandbox worker now, in the background? [y/N]" n
      case $answer in
        y|Y|yes|YES)
          if start_worker; then
            say "Started the worker on $SOCK (log: $DATA/worker.log)."
            started=1
          else
            warn "the worker did not come up; see $DATA/worker.log"
          fi ;;
      esac
    fi
  fi
  say ""
  if [ "$FRESH" = 1 ]; then
    say "Start the site (PHP's built-in web server), and leave it running:"
    say "  cd $WP_ROOT && $LOCAL/bin/php-web -S localhost:8080"
  fi
  if [ "$started" = 0 ]; then
    say "Start the sandbox worker, as this user ($(id -un)), and leave it running:"
    say "  $WORKER"
    say "(or press Start worker on Settings → SecureCore, where the site's PHP may run proc_open)"
  fi
  say ""
  say "Then choose plugins to sandbox on Settings → SecureCore. Switching one on takes effect on the"
  say "next request."
fi
if [ "$FRESH" = 1 ] && [ -n "$ADMIN_PASSWORD" ]; then
  say ""
  say "Admin password (generated; keep it): $ADMIN_PASSWORD"
fi
cat <<EOF

Stronger options, same worker:
  - systemd (own user, no network, read-only site): $PLUGIN/templates/securecore.service
  - Docker (no network, read-only mount):           $PLUGIN/templates/compose.yml
Details: $PLUGIN/INSTALL.md
EOF
