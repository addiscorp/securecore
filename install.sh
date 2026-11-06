#!/bin/sh
# Install or upgrade SecureCore in a WordPress site.
#
#   cd /path/to/wordpress && curl -fsSL https://securecore.addis.gg/install.sh | sh
#   curl -fsSL https://securecore.addis.gg/install.sh | sh -s -- --path /var/www/html
#
# Options:
#   --path <dir>   the WordPress root (default: the current directory)
#   --canary       install the newest canary instead of the newest stable release
#   --from <url>   download releases from <url> instead of https://securecore-releases.addis.gg
#   --uninstall    remove the SecureCore plugin and its mu-plugin loader
#   -h, --help     this help
#
# It puts the plugin in wp-content/plugins/securecore/ and the loader in
# wp-content/mu-plugins/, activates the plugin with WP-CLI when `wp` is available, and
# never uses sudo. Re-running it upgrades in place; your manifests in
# wp-content/securecore/ are kept.
set -eu

BASE=https://securecore-releases.addis.gg
WP_ROOT=
CHANNEL=
UNINSTALL=0

say() { printf '%s\n' "$*"; }
warn() { printf 'securecore: warning: %s\n' "$*" >&2; }
die() { printf 'securecore: error: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
Install or upgrade SecureCore in a WordPress site.

  cd /path/to/wordpress && curl -fsSL https://securecore.addis.gg/install.sh | sh
  curl -fsSL https://securecore.addis.gg/install.sh | sh -s -- --path /var/www/html

Options:
  --path <dir>   the WordPress root (default: the current directory)
  --canary       install the newest canary instead of the newest stable release
  --from <url>   download releases from <url> instead of https://securecore-releases.addis.gg
  --uninstall    remove the SecureCore plugin and its mu-plugin loader
  -h, --help     this help
EOF
}

while [ $# -gt 0 ]; do
  case $1 in
    --path) [ $# -ge 2 ] || die "--path needs a directory"; WP_ROOT=$2; shift 2 ;;
    --path=*) WP_ROOT=${1#--path=}; shift ;;
    --canary) CHANNEL=canary; shift ;;
    --from) [ $# -ge 2 ] || die "--from needs a URL"; BASE=$2; shift 2 ;;
    --from=*) BASE=${1#--from=}; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done
BASE=${BASE%/}

# --- the WordPress root --------------------------------------------------------------------
WP_ROOT=${WP_ROOT:-$(pwd)}
[ -d "$WP_ROOT" ] || die "$WP_ROOT is not a directory"
WP_ROOT=$(CDPATH='' cd "$WP_ROOT" && pwd)
if [ ! -f "$WP_ROOT/wp-load.php" ] || [ ! -d "$WP_ROOT/wp-content" ]; then
  die "$WP_ROOT does not look like a WordPress site (no wp-load.php or wp-content/). Run this from the WordPress root or pass --path <dir>."
fi
CONTENT=$WP_ROOT/wp-content
PLUGIN=$CONTENT/plugins/securecore
LOADER=$CONTENT/mu-plugins/securecore-loader.php
DATA=$CONTENT/securecore

wp_cli() {
  command -v wp >/dev/null 2>&1 || return 127
  if [ "$(id -u)" = 0 ]; then
    wp --path="$WP_ROOT" --allow-root "$@"
  else
    wp --path="$WP_ROOT" "$@"
  fi
}

# --- uninstall -----------------------------------------------------------------------------
if [ "$UNINSTALL" = 1 ]; then
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

# --- tools ---------------------------------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  die "needs curl or wget to download SecureCore"
fi

command -v php >/dev/null 2>&1 || die "no 'php' command found. SecureCore's worker needs the PHP CLI (with the pcntl and opcache extensions)."

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; return; fi
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1; return; fi
  # shellcheck disable=SC2016 # PHP code: $argv is PHP's, not the shell's
  php -r 'echo hash_file("sha256", $argv[1]);' "$1"
}

# The worker needs pcntl and opcache in the PHP CLI that runs it. Installing the files does
# not, so a missing extension here is a warning: run the worker where they exist (or use the
# systemd/Docker options).
missing=
php -r 'exit(function_exists("pcntl_fork") ? 0 : 1);' 2>/dev/null || missing="pcntl"
php -m 2>/dev/null | grep -qi '^zend opcache$' || missing="${missing:+$missing and }opcache"
if [ -n "$missing" ]; then
  warn "this PHP CLI ($(command -v php), PHP $(php -r 'echo PHP_VERSION;')) has no $missing."
  warn "SecureCore's worker needs both. Install them (Debian/Ubuntu: apt-get install php-cli php-opcache; pcntl is built into php-cli there),"
  warn "or run the worker on a host or container that has them (see templates/ after installing)."
fi

# --- writable? -----------------------------------------------------------------------------
[ -w "$CONTENT/plugins" ] || die "$CONTENT/plugins is not writable by $(id -un). Run this as the user that owns the site's files (no sudo needed if you are that user)."
mkdir -p "$CONTENT/mu-plugins" 2>/dev/null || true
[ -w "$CONTENT/mu-plugins" ] || die "$CONTENT/mu-plugins is not writable by $(id -un)."
mkdir -p "$DATA/manifests" 2>/dev/null || die "cannot create $DATA/manifests (is $CONTENT writable by $(id -un)?)"

# --- which release -------------------------------------------------------------------------
WORK=$(mktemp -d "$CONTENT/.securecore-install.XXXXXX") || die "cannot create a temporary folder in $CONTENT"
cleanup() { [ -d "$WORK" ] && find "$WORK" -depth -delete; }
trap cleanup EXIT INT TERM

json_field() { sed -n "s/.*\"$1\": *\"\\([^\"]*\\)\".*/\\1/p" "$2" | head -n 1; }

if [ "$CHANNEL" = canary ]; then
  fetch "$BASE/canary.json" "$WORK/release.json" || die "could not download $BASE/canary.json"
elif fetch "$BASE/latest.json" "$WORK/release.json" 2>/dev/null; then
  CHANNEL=stable
else
  say "No stable release yet; installing the newest canary."
  fetch "$BASE/canary.json" "$WORK/release.json" || die "could not download $BASE/latest.json or $BASE/canary.json"
  CHANNEL=canary
fi
VERSION=$(json_field version "$WORK/release.json")
WANT=$(json_field sha256 "$WORK/release.json")
ZIP=$(json_field zip "$WORK/release.json")
if [ -z "$VERSION" ] || [ -z "$WANT" ]; then
  die "$BASE does not have a valid release manifest"
fi
ZIP=${ZIP:-securecore.zip}

CURRENT=
[ -f "$PLUGIN/VERSION" ] && CURRENT=$(tr -d ' \n' < "$PLUGIN/VERSION")
if [ -n "$CURRENT" ]; then
  say "Upgrading SecureCore $CURRENT -> $VERSION ($CHANNEL) in $WP_ROOT"
else
  say "Installing SecureCore $VERSION ($CHANNEL) in $WP_ROOT"
fi

# --- download and check --------------------------------------------------------------------
fetch "$BASE/$VERSION/$ZIP" "$WORK/securecore.zip" || die "could not download $BASE/$VERSION/$ZIP"
GOT=$(sha256 "$WORK/securecore.zip")
[ "$GOT" = "$WANT" ] || die "$ZIP failed its checksum (expected $WANT, got $GOT). Nothing was changed."
say "Downloaded $ZIP, sha256 $GOT (matches the release manifest)."

mkdir -p "$WORK/unpacked"
if command -v unzip >/dev/null 2>&1; then
  unzip -q "$WORK/securecore.zip" -d "$WORK/unpacked"
else
  # shellcheck disable=SC2016 # PHP code: $z and $argv are PHP's, not the shell's
  php -r '$z = new ZipArchive(); if ($z->open($argv[1]) !== true || !$z->extractTo($argv[2])) exit(1);' \
    "$WORK/securecore.zip" "$WORK/unpacked" || die "cannot unpack the zip (no unzip, and PHP's zip extension failed)"
fi
[ -f "$WORK/unpacked/securecore/securecore.php" ] || die "the zip does not contain securecore/securecore.php"

# --- put it in place (old version aside until the new one is there) -------------------------
if [ -d "$PLUGIN" ]; then
  mv "$PLUGIN" "$WORK/previous"
fi
if ! mv "$WORK/unpacked/securecore" "$PLUGIN"; then
  [ -d "$WORK/previous" ] && mv "$WORK/previous" "$PLUGIN"
  die "could not move the new version into $PLUGIN; the previous version was restored"
fi
chmod 755 "$PLUGIN/bin/securecore-worker"
cp "$PLUGIN/mu-plugin/securecore-loader.php" "$LOADER"
say "Installed $PLUGIN and $LOADER"

# --- activate ------------------------------------------------------------------------------
if wp_cli plugin activate securecore >/dev/null 2>&1; then
  say "Activated the SecureCore plugin with WP-CLI."
elif command -v wp >/dev/null 2>&1; then
  warn "WP-CLI could not activate the plugin; activate SecureCore in wp-admin → Plugins."
else
  say "Activate SecureCore in wp-admin → Plugins (WP-CLI not found)."
fi

cat <<EOF

Next: start the sandbox worker.
  - In wp-admin: Settings → SecureCore → Start worker (works where your web server's PHP may run proc_open), or
  - yourself, as the user that should run it (the socket's folder must be writable by it and readable by the web server):
      $PLUGIN/bin/securecore-worker /run/securecore/worker.sock $CONTENT/plugins $DATA/manifests
Then choose plugins to sandbox on Settings → SecureCore.

Stronger options, same worker:
  - systemd (own user, no network, read-only site): $PLUGIN/templates/securecore.service
  - Docker (no network, read-only mount):           $PLUGIN/templates/compose.yml
Details: $PLUGIN/INSTALL.md
EOF
