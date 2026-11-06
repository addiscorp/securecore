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
# 4. The sandbox worker (started with --yes or when asked), then what to run next, or a
#    Docker Compose file.
# Re-running it on a finished site only upgrades SecureCore. Answers come from /dev/tty
# (which works under `curl | sh`); every question has a flag.
#
# Output is for the person running it: one line per step (✓ done, ! needs attention,
# ✗ failed, · skipped; ok/!/error/- when stdout is not a terminal). URLs, checksums, build
# names and paths are printed only with --verbose.
set -eu

BASE=https://securecore-releases.addis.gg
WP_ROOT=
CHANNEL=
UNINSTALL=0
YES=0
VERBOSE=0
PHP_CHOICE=
DB=
COMPOSE=
SITE_ARGS=
SITE_URL=http://localhost:8080
START_DIR=$(pwd)

if [ -t 1 ]; then OK='✓' BAD='✗' NOTE='!' SKIP='·'; else OK=ok BAD=error NOTE='!' SKIP=-; fi
TAB=$(printf '\t')

say() { printf '%s\n' "$*"; }
# step <mark> <name> <what happened>: one status line.
step() { printf '%s %-16s %s\n' "$1" "$2" "$3"; }
# detail <text>: only with --verbose.
detail() { [ "$VERBOSE" = 1 ] && printf '    %s\n' "$*"; return 0; }
warn() { printf '%s %s\n' "$NOTE" "$*" >&2; }
die() { printf '%s %s\n' "$BAD" "$*" >&2; exit 1; }
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
  --yes                   don't ask; take the defaults, download PHP if needed, start the worker
  --verbose               also print download URLs, checksums, PHP builds and file paths
  --canary                install the newest SecureCore canary instead of the newest release
  --from <url>            download from <url> instead of https://securecore-releases.addis.gg
  --uninstall             remove the SecureCore plugin and its mu-plugin loader
  -h, --help              this help
EOF
}
add_site_arg() { SITE_ARGS="$SITE_ARGS $1"; }
quote() { printf '%s' "$1" | sed "s/'/'\\\\''/g"; }

while [ $# -gt 0 ]; do
  case $1 in
    --path|--php|--wordpress|--db|--url|--title|--admin-user|--admin-password|--admin-email|--from)
      [ $# -ge 2 ] || die "$1 needs a value (see --help)."; opt=$1; val=$2; shift 2 ;;
    --*=*) opt=${1%%=*}; val=${1#*=}; shift ;;
    --canary) CHANNEL=canary; shift; continue ;;
    --uninstall) UNINSTALL=1; shift; continue ;;
    --yes|-y) YES=1; shift; continue ;;
    --verbose|-v) VERBOSE=1; shift; continue ;;
    --compose) COMPOSE=1; shift; continue ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option $1 (see --help)." ;;
  esac
  case $opt in
    --path) WP_ROOT=$val ;;
    --php) PHP_CHOICE=$val ;;
    --db) DB=$val ;;
    --from) BASE=$val ;;
    --wordpress|--url|--title|--admin-user|--admin-password|--admin-email)
      [ "$opt" = --url ] && SITE_URL=$val
      # Passed to setup/site.php as one --name=value word; quotes keep spaces in titles.
      add_site_arg "'$opt=$(quote "$val")'" ;;
    *) die "Unknown option $opt (see --help)." ;;
  esac
done
BASE=${BASE%/}
SITE_URL=${SITE_URL%/}
[ "$YES" = 1 ] && add_site_arg --yes
[ "$VERBOSE" = 1 ] && add_site_arg --verbose

# The address PHP's built-in server listens on, from the site's URL: host:port.
HOSTPORT=${SITE_URL#*://}
HOSTPORT=${HOSTPORT%%/*}
case $HOSTPORT in
  *:*) ;;
  *) case $SITE_URL in https://*) HOSTPORT=$HOSTPORT:443 ;; *) HOSTPORT=$HOSTPORT:80 ;; esac ;;
esac
PORT=${HOSTPORT##*:}

# --- the project -----------------------------------------------------------------------------
WP_ROOT=${WP_ROOT:-$START_DIR}
mkdir -p "$WP_ROOT" 2>/dev/null || true
[ -d "$WP_ROOT" ] || die "$WP_ROOT is not a folder. Pass --path with a folder you can write to."
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
  [ -z "$others" ] || [ "$YES" = 1 ] || die "$WP_ROOT has files in it but no WordPress site, so there is nowhere to put SecureCore. Run the installer in an empty folder (for a new site) or in a WordPress folder, or pass --path <folder>."
fi
# The command prefix that gets someone from where they ran this to the site's folder.
GO=
[ "$WP_ROOT" = "$START_DIR" ] || GO="cd $WP_ROOT && "

wp_cli() {
  command -v wp >/dev/null 2>&1 || return 127
  if [ "$(id -u)" = 0 ]; then wp --path="$WP_ROOT" --allow-root "$@"; else wp --path="$WP_ROOT" "$@"; fi
}

# --- uninstall -------------------------------------------------------------------------------
if [ "$UNINSTALL" = 1 ]; then
  [ -f "$WP_ROOT/wp-load.php" ] || die "$WP_ROOT is not a WordPress site. Run --uninstall in the site's folder, or pass --path <folder>."
  say "SecureCore uninstaller"
  say ""
  if wp_cli plugin is-active securecore >/dev/null 2>&1; then
    wp_cli plugin deactivate securecore >/dev/null 2>&1 && step "$OK" SecureCore "switched off"
  fi
  if [ -e "$LOADER" ]; then rm -f "$LOADER"; detail "removed $LOADER"; fi
  if [ -d "$PLUGIN" ]; then find "$PLUGIN" -depth -delete; detail "removed $PLUGIN"; fi
  step "$OK" SecureCore "removed; plugins load normally again"
  [ -d "$DATA" ] && step "$SKIP" "Your settings" "kept in wp-content/securecore (delete it if you don't need it)"
  say ""
  say "If the sandbox worker is running, stop it: it has nothing left to do."
  exit 0
fi

# --- tools -----------------------------------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  die "This computer has neither curl nor wget, and the installer needs one to download files. Install curl, then run the installer again."
fi
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; return; fi
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1; return; fi
  die "This computer has neither sha256sum nor shasum, which the installer needs to check its downloads. Install one (coreutils or perl), then run the installer again."
}
json_field() { sed -n "s/.*\"$1\": *\"\\([^\"]*\\)\".*/\\1/p" "$2" | head -n 1; }

# Ask on the terminal (also under `curl | sh`); with --yes or no terminal, the default.
# The question may span lines; the last one is the prompt.
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

say "SecureCore installer"
say ""
detail "folder: $WP_ROOT"
detail "downloads from: $BASE"

mkdir -p "$LOCAL/bin" "$LOCAL/tmp" 2>/dev/null || true
if [ ! -w "$LOCAL/tmp" ] || [ ! -w "$LOCAL/bin" ]; then
  die "$WP_ROOT is not writable by $(id -un), so the installer can't save anything there. Run it as the user that owns the site's files (no sudo needed if you are that user)."
fi
WORK=$(mktemp -d "$LOCAL/tmp/install.XXXXXX") || die "Couldn't create a temporary folder in $LOCAL. Check there is free disk space, then run the installer again."
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
php_version() { "$1" -r 'echo PHP_MAJOR_VERSION, ".", PHP_MINOR_VERSION;' 2>/dev/null; }
describe() {
  d="$1 (PHP $("$1" -r 'echo PHP_VERSION;' 2>/dev/null))"
  for e in pcntl opcache pdo_sqlite mysqli; do
    if has "$1" "$e"; then d="$d, $e yes"; else d="$d, $e NO"; fi
  done
  printf '%s' "$d"
}

PHP_JSON=
php_json() {
  [ -n "$PHP_JSON" ] && return 0
  PHP_JSON=$WORK/php.json
  fetch "$BASE/php.json" "$PHP_JSON" || die "Couldn't download the list of PHP builds from $BASE. Check this computer's internet connection, then run the installer again."
}
# Download build <bulk|common> into .securecore/php/<build>/<version>/<platform>/php, or reuse
# the copy already there. Sets PHP_PATH; FETCHED=1 when it downloaded, REUSED=1 when not.
FETCHED=
REUSED=
download_php() {
  build=$1
  php_json
  if [ "$os" = other ] || [ "$arch" = other ]; then
    die "There is no PHP download for this kind of computer ($(uname -s) $(uname -m)). Install PHP 8.1 or newer with pcntl and opcache, then run the installer again."
  fi
  version=$(sed -n "s/.*\"$build\": *\"\\([0-9.]*\\)\".*/\\1/p" "$PHP_JSON" | head -n 1)
  case $PHP_CHOICE in [0-9]*) version=$PHP_CHOICE ;; esac
  path=php/$build/$version/$PLATFORM/php.tar.gz
  want=$(sed -n "\\#\"path\": \"$path\"#{n;s/.*\"sha256\": \"\\([0-9a-f]*\\)\".*/\\1/p;}" "$PHP_JSON")
  [ -n "$want" ] || die "PHP $version isn't available to download for this computer ($PLATFORM). Run the installer again without --php $version to get the default version."
  dest=$LOCAL/php/$build/$version/$PLATFORM
  PHP_PATH=$dest/php
  if [ -x "$dest/php" ] && [ "$(cat "$dest/php.tar.gz.sha256" 2>/dev/null)" = "$want" ]; then
    detail "PHP $version ($build build, $PLATFORM): already downloaded, $dest/php"
    REUSED=1
    return 0
  fi
  detail "PHP $version ($build build, $PLATFORM): downloading $BASE/$path"
  fetch "$BASE/$path" "$WORK/php.tar.gz" || die "Couldn't download PHP from $BASE. Check this computer's internet connection, then run the installer again."
  got=$(sha256 "$WORK/php.tar.gz")
  if [ "$got" != "$want" ]; then
    detail "expected sha256 $want, got $got"
    die "The PHP download failed its checksum, so it was not used and nothing was changed. Run the installer again; if this keeps happening, the download is being tampered with or corrupted on the way."
  fi
  detail "sha256 $got (matches php.json)"
  mkdir -p "$dest"
  tar -xzf "$WORK/php.tar.gz" -C "$dest" php
  chmod 755 "$dest/php"
  echo "$want" > "$dest/php.tar.gz.sha256"
  "$dest/php" -v >/dev/null 2>&1 || die "The downloaded PHP doesn't run on this computer. Install PHP 8.1 or newer with pcntl and opcache, then run the installer again with --php system."
  detail "saved to $dest/php"
  FETCHED=1
}
# May we download PHP? Asks once; --php system says no.
ok_to_download() {
  [ "$PHP_CHOICE" = system ] && return 1
  case $PHP_CHOICE in [0-9]*|download) return 0 ;; esac
  [ -n "${DOWNLOAD_OK:-}" ] && { [ "$DOWNLOAD_OK" = y ]; return; }
  if ! can_ask; then DOWNLOAD_OK=n; return 1; fi
  ask "$1
Download PHP into this folder (.securecore/php)? Nothing outside this folder changes. [Y/n]" y
  case $answer in n|N|no|NO) DOWNLOAD_OK=n; return 1 ;; esac
  DOWNLOAD_OK=y
}

SYS_PHP=$(command -v php 2>/dev/null || true)
SYS_VER=
if [ -n "$SYS_PHP" ]; then
  SYS_VER=$(php_version "$SYS_PHP")
  detail "found $(describe "$SYS_PHP")"
else
  detail "no php command on this computer"
fi

# The worker: pcntl + opcache.
WORKER_PHP=
missing=
WORKER_FETCHED=
if [ -n "$SYS_PHP" ] && [ "$PHP_CHOICE" != download ] && has "$SYS_PHP" pcntl && has "$SYS_PHP" opcache; then
  case $PHP_CHOICE in [0-9]*) ;; *) WORKER_PHP=$SYS_PHP ;; esac
fi
if [ -z "$WORKER_PHP" ]; then
  if [ -n "$SYS_PHP" ]; then
    why="The PHP on this computer ($SYS_VER) can't run SecureCore's sandbox: it needs the pcntl and opcache extensions."
  else
    why="There is no PHP on this computer. SecureCore and WordPress need it."
  fi
  if ok_to_download "$why"; then
    download_php bulk
    WORKER_PHP=$PHP_PATH
    WORKER_FETCHED=$FETCHED
  elif [ -n "$SYS_PHP" ]; then
    WORKER_PHP=$SYS_PHP
    has "$SYS_PHP" pcntl || missing=pcntl
    has "$SYS_PHP" opcache || missing="${missing:+$missing and }opcache"
  else
    die "There is no PHP on this computer, and none was downloaded. Run the installer again in a terminal and answer y, or add --yes."
  fi
fi
ln -sf "$WORKER_PHP" "$LOCAL/bin/php-worker"

# The site (only for a new site): the database decides which PHP serves it.
WEB_PHP=
if [ "$FRESH" = 1 ]; then
  if [ -z "$DB" ]; then
    hint=
    [ -S /run/mysqld/mysqld.sock ] || [ -S /tmp/mysql.sock ] && hint="
(A MySQL server is running on this computer; to use it, type mysql://user:password@localhost/name.)"
    ask "Database: SQLite keeps the whole site in one file in this folder and needs no database server.
To use a MySQL server instead, type its address as mysql://user:password@host/name.$hint
Database" sqlite
    DB=$answer
  fi
  case $DB in sqlite) need=pdo_sqlite; build=common ;; mysql://*) need=mysqli; build=bulk ;; *) die "The database must be sqlite or mysql://user:password@host[:port]/name, not \"$DB\". Run the installer again with one of those." ;; esac
  if [ -n "$SYS_PHP" ] && has "$SYS_PHP" "$need" && has "$SYS_PHP" zip && has "$SYS_PHP" curl; then
    case $PHP_CHOICE in [0-9]*|download) ;; *) WEB_PHP=$SYS_PHP ;; esac
  fi
  if [ -z "$WEB_PHP" ] && has "$WORKER_PHP" "$need"; then WEB_PHP=$WORKER_PHP; fi
  if [ -z "$WEB_PHP" ]; then
    ok_to_download "The site needs a PHP that can use its database, and none here can." || die "No PHP here can use the site's database ($need, zip and curl), and none was downloaded. Run the installer again and answer y, or add --php download."
    download_php "$build"
    WEB_PHP=$PHP_PATH
  fi
  ln -sf "$WEB_PHP" "$LOCAL/bin/php-web"
  add_site_arg "'--db=$(quote "$DB")'"
fi
detail "PHP for the worker: $WORKER_PHP${WEB_PHP:+; for the site: $WEB_PHP}"
PHP_LABEL="PHP $(php_version "$WORKER_PHP")"
if [ -n "$FETCHED" ] && [ -z "$SYS_PHP" ]; then
  step "$OK" "$PHP_LABEL" "none found on this computer, downloaded into this folder (verified)"
elif [ -n "$WORKER_FETCHED" ]; then
  step "$OK" "$PHP_LABEL" "this computer's PHP $SYS_VER can't run the sandbox, so downloaded one into this folder (verified)"
elif [ -n "$FETCHED" ]; then
  step "$OK" "$PHP_LABEL" "this computer's PHP can't use the database, so downloaded one into this folder (verified)"
elif [ -n "$REUSED" ]; then
  step "$OK" "$PHP_LABEL" "using the copy downloaded into this folder earlier"
else
  step "$OK" "$PHP_LABEL" "using the PHP already on this computer"
fi

# --- which SecureCore release ----------------------------------------------------------------
NO_RELEASE="Couldn't download SecureCore from $BASE. Check this computer's internet connection, then run the installer again."
if [ "$CHANNEL" = canary ]; then
  fetch "$BASE/canary.json" "$WORK/release.json" || die "$NO_RELEASE"
elif fetch "$BASE/latest.json" "$WORK/release.json" 2>/dev/null; then
  CHANNEL=stable
else
  detail "no stable SecureCore release yet; using the newest canary"
  fetch "$BASE/canary.json" "$WORK/release.json" || die "$NO_RELEASE"
  CHANNEL=canary
fi
VERSION=$(json_field version "$WORK/release.json")
WANT=$(json_field sha256 "$WORK/release.json")
ZIP=$(json_field zip "$WORK/release.json")
if [ -z "$VERSION" ] || [ -z "$WANT" ]; then die "$BASE did not describe a SecureCore release the installer can use. Run the installer again later."; fi
ZIP=${ZIP:-securecore.zip}
detail "SecureCore $VERSION ($CHANNEL): downloading $BASE/$VERSION/$ZIP"
fetch "$BASE/$VERSION/$ZIP" "$WORK/securecore.zip" || die "$NO_RELEASE"
GOT=$(sha256 "$WORK/securecore.zip")
if [ "$GOT" != "$WANT" ]; then
  detail "expected sha256 $WANT, got $GOT"
  die "The SecureCore download failed its checksum, so nothing was changed. Run the installer again; if this keeps happening, the download is being tampered with or corrupted on the way."
fi
detail "sha256 $GOT (matches the release manifest)"
mkdir -p "$WORK/unpacked"
if command -v unzip >/dev/null 2>&1; then
  unzip -q "$WORK/securecore.zip" -d "$WORK/unpacked"
else
  # Its stderr is kept aside: a downloaded PHP reads the system's php.ini too and warns about
  # every extension there it can't load, which is noise unless unpacking fails.
  # shellcheck disable=SC2016 # PHP code: $z and $argv are PHP's, not the shell's
  if ! "$WORKER_PHP" -r '$z = new ZipArchive(); if ($z->open($argv[1]) !== true || !$z->extractTo($argv[2])) exit(1);' \
    "$WORK/securecore.zip" "$WORK/unpacked" 2> "$WORK/unzip.err"; then
    cat "$WORK/unzip.err" >&2
    die "Couldn't unpack the SecureCore download. Run the installer again."
  fi
fi
[ -f "$WORK/unpacked/securecore/securecore.php" ] || die "The SecureCore download is incomplete (no securecore.php in it). Run the installer again."

# --- 2. WordPress, database, the site (a new site only) ---------------------------------------
# setup/site.php reports tab-separated records on stdout, read here as it goes:
#   step <name> <text>   detail <text>   warn <text>   fail <text>   password <text>
# Anything else (a PHP error) is printed as it is.
ADMIN_PASSWORD=
if [ "$FRESH" = 1 ]; then
  eval "set -- $SITE_ARGS"
  mkfifo "$WORK/site.out"
  "$WEB_PHP" "$WORK/unpacked/securecore/setup/site.php" --root "$WP_ROOT" "$@" > "$WORK/site.out" &
  site_pid=$!
  site_failed=
  while IFS= read -r line; do
    kind=${line%%"$TAB"*}
    rest=${line#*"$TAB"}
    case $kind in
      step) step "$OK" "${rest%%"$TAB"*}" "${rest#*"$TAB"}" ;;
      detail) detail "$rest" ;;
      warn) warn "$rest" ;;
      fail) printf '%s %s\n' "$BAD" "$rest" >&2; site_failed=1 ;;
      password) ADMIN_PASSWORD=$rest ;;
      *) say "$line" ;;
    esac
  done < "$WORK/site.out"
  if ! wait "$site_pid"; then
    [ -n "$site_failed" ] && exit 1
    die "Setting up WordPress stopped unexpectedly (see above). Empty this folder, then run the installer again."
  fi
fi
if [ ! -f "$WP_ROOT/wp-load.php" ] || [ ! -d "$CONTENT" ]; then
  die "$WP_ROOT does not look like a WordPress site (no wp-load.php or wp-content). Run the installer in the site's folder, or pass --path <folder>."
fi

# --- 3. SecureCore ---------------------------------------------------------------------------
[ -w "$CONTENT/plugins" ] || die "$CONTENT/plugins is not writable by $(id -un). Run the installer as the user that owns the site's files (no sudo needed if you are that user)."
mkdir -p "$CONTENT/mu-plugins" 2>/dev/null || true
[ -w "$CONTENT/mu-plugins" ] || die "$CONTENT/mu-plugins is not writable by $(id -un). Run the installer as the user that owns the site's files."
mkdir -p "$DATA/manifests" 2>/dev/null || die "Couldn't create $DATA/manifests. Run the installer as the user that owns the site's files."
CURRENT=
[ -f "$PLUGIN/VERSION" ] && CURRENT=$(tr -d ' \n' < "$PLUGIN/VERSION")
if [ -d "$PLUGIN" ]; then mv "$PLUGIN" "$WORK/previous"; fi
if ! mv "$WORK/unpacked/securecore" "$PLUGIN"; then
  [ -d "$WORK/previous" ] && mv "$WORK/previous" "$PLUGIN"
  die "Couldn't put the new SecureCore in place, so the previous one was restored. Check there is free disk space, then run the installer again."
fi
chmod 755 "$PLUGIN/bin/securecore-worker"
cp "$PLUGIN/mu-plugin/securecore-loader.php" "$LOADER"
detail "installed $PLUGIN and $LOADER"
if [ -z "$CURRENT" ]; then
  done_what="installed ($VERSION)"
elif [ "$CURRENT" = "$VERSION" ]; then
  done_what="reinstalled ($VERSION, already the newest)"
else
  done_what="updated from $CURRENT to $VERSION"
fi
if [ "$FRESH" = 1 ] || wp_cli plugin activate securecore >/dev/null 2>&1; then
  step "$OK" SecureCore "$done_what and switched on"
elif command -v wp >/dev/null 2>&1; then
  step "$NOTE" SecureCore "$done_what, but WP-CLI couldn't switch it on: switch it on in wp-admin → Plugins"
else
  # No WP-CLI, so whether it is on can't be checked from here.
  step "$OK" SecureCore "$done_what; switch it on in wp-admin → Plugins if it isn't on already"
fi
# An existing site's address, for the Next block, when WP-CLI can tell us.
if [ "$FRESH" = 0 ]; then
  SITE_URL=$(wp_cli option get home 2>/dev/null || true)
fi

# --- 4. the worker, and how to run it --------------------------------------------------------
WORKER=$PLUGIN/bin/securecore-worker
SOCK=$DATA/worker.sock
max=103
[ "$os" = linux ] && max=107
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
  ask "How do you want to run the site? \"commands\": start it yourself with the commands printed at the end.
\"compose\": write a Docker Compose file that runs the site and the worker in containers.
Run with" commands
  [ "$answer" = compose ] && COMPOSE=1
fi

if [ -n "$COMPOSE" ]; then
  # The same setup in containers: the site on PHP's built-in server, the worker with no
  # network. Official php images, so it runs on any Docker host.
  cat > "$WP_ROOT/compose.yml" <<YAML
# Written by SecureCore's install.sh: this WordPress site and its SecureCore worker.
#   docker compose up -d     then open $SITE_URL
services:
  web:
    image: php:8.4-cli
    working_dir: /site
    command: sh -c "docker-php-ext-install mysqli >/dev/null 2>&1; exec php -S 0.0.0.0:$PORT -t /site"
    ports: ["127.0.0.1:$PORT:$PORT"]
    volumes: [".:/site"]
  worker:
    image: php:8.4-cli
    network_mode: none
    restart: unless-stopped
    command: sh -c "docker-php-ext-install pcntl >/dev/null 2>&1; docker-php-ext-enable opcache >/dev/null 2>&1; exec /site/wp-content/plugins/securecore/bin/securecore-worker"
    volumes: [".:/site"]
YAML
  detail "wrote $WP_ROOT/compose.yml"
  step "$OK" "Docker Compose" "wrote compose.yml, which runs the site and the sandbox worker"
  say ""
  say "Next, start them:"
  say "  ${GO}docker compose up -d"
else
  started=0
  if [ "${#SOCK}" -gt "$max" ]; then
    detail "worker socket: $SOCK (${#SOCK} characters; this system allows $max)"
    step "$NOTE" "Sandbox worker" "not started: this folder's path is too long for the worker's socket. Add define( 'SECURECORE_SOCKET', '/tmp/securecore.sock' ); to wp-config.php and start it with: $WORKER /tmp/securecore.sock"
  elif [ -n "$missing" ]; then
    step "$NOTE" "Sandbox worker" "not started: this computer's PHP has no $missing, which the worker needs. Run the installer again with --php download to get a PHP that has it, or run the worker in its own container ($PLUGIN/templates/compose.yml)."
  elif running; then
    detail "worker socket: $SOCK"
    step "$OK" "Sandbox worker" "already running (restart it to load the new version)"
    started=1
  else
    if [ "$YES" = 1 ]; then
      answer=y
    elif can_ask; then
      ask "The sandbox worker runs the plugins you choose to sandbox, separately from the site.
Start it now, in the background? [y/N]" n
    else
      answer=n
    fi
    case $answer in
      y|Y|yes|YES)
        if start_worker; then
          detail "worker socket: $SOCK; log: $DATA/worker.log"
          step "$OK" "Sandbox worker" "running"
          started=1
        else
          step "$BAD" "Sandbox worker" "didn't start; what went wrong is in wp-content/securecore/worker.log"
        fi ;;
      *) step "$SKIP" "Sandbox worker" "not started yet (see Next)" ;;
    esac
  fi
  say ""
  if [ "$FRESH" = 1 ]; then
    say "Next, start your site (leave it running):"
    say "  ${GO}.securecore/bin/php-web -S $HOSTPORT"
    if [ "$started" = 0 ]; then
      say "and, in another terminal, the sandbox worker (leave it running too):"
      say "  $WORKER"
    fi
  elif [ "$started" = 0 ]; then
    say "Next, start the sandbox worker as $(id -un), and leave it running:"
    say "  $WORKER"
    say "(or press Start worker on Settings → SecureCore)"
  fi
fi
if [ -n "$SITE_URL" ]; then where="open $SITE_URL/wp-admin"; else where="open your site's wp-admin"; fi
case "$FRESH:${started:-1}:$COMPOSE" in
  0:1:) say "Next, $where → Settings → SecureCore to choose plugins to sandbox." ;;
  *) say "Then $where → Settings → SecureCore to choose plugins to sandbox." ;;
esac
if [ -n "$ADMIN_PASSWORD" ]; then
  say ""
  say "Admin password (generated, save it now): $ADMIN_PASSWORD"
fi
detail "Stronger options, same worker:"
detail "  systemd (own user, no network, read-only site): $PLUGIN/templates/securecore.service"
detail "  Docker (no network, read-only mount):           $PLUGIN/templates/compose.yml"
detail "Details: $PLUGIN/INSTALL.md"
