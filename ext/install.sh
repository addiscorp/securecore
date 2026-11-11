#!/bin/sh
# Install the SecureCore PHP extension (addiscorp/securecore#53) on a Linux server, for the PHP
# that runs the site:
#
#   curl -fsSL https://securecore.addis.gg/install.sh | sudo sh
#
# (securecore.addis.gg/install.sh redirects to securecore-releases.addis.gg/install-ext.sh.) With
# no options it installs the newest stable release, or the newest canary while there is none, for
# the WordPress in the current folder, or else in /var/www/html.
#
# 1. Finds the PHP (`php` on PATH, or --php): its version, thread safety (NTS/ZTS), extension
#    folder and ini folder; and this machine's architecture (x86_64 or arm64).
# 2. Downloads release.json (the newest stable, or --canary, or --version) and the files this
#    PHP needs, and checks every file's sha256 against release.json before using it. Nothing
#    downloaded is run or installed unless it matches.
# 3. Checks the extension loads in this PHP (with every layer off), then installs:
#      securecore.so         into PHP's extension folder
#      securecore-fpm        the layer-1 launcher, into /usr/local/bin (--bin-dir)
#      securecore.schema.json  into /usr/local/share/securecore (--share-dir)
#      vm/firecracker, vm/vmlinux  layer 1's microVM (#71) on x86_64, when the release carries
#                            ext/mirab-vm.json: mirab's guest kernel and the Firecracker mirab
#                            pins, each checked against mirab's sha256s, and vm/installed.json,
#                            which records the mirab release they came from
#                            (into <share-dir>/vm, where securecore-fpm looks)
#      vm/rootfs.ext4        the microVM's guest image (#80), when the release ships
#                            vm/linux-x86_64/rootfs.ext4.gz: its gzip and its unpacked bytes
#                            each checked against release.json, its sha256 recorded in
#                            vm/installed.json (securecore-fpm boots nothing it doesn't name)
#      securecore-vault.php  the mu-plugin, into <wordpress>/wp-content/mu-plugins
#      securecore.json       only if there is none: every layer off (an existing one is kept)
#      securecore.ini        last: `extension=securecore.so` and `securecore.config=<file>`
# 4. Says what it did, one line per step, and what to run next (restart php-fpm).
#
# Idempotent: a file already installed with the same bytes is left alone ("unchanged"), so
# running it again changes nothing. It never restarts a service, never runs sudo itself, and
# never edits a securecore.json that exists, except to upgrade one an earlier release wrote
# (securecore-fpm --migrate-config: the retired layer1.enabled), keeping the original beside it.
set -eu

BASE=https://securecore-releases.addis.gg
CHANNEL=auto
VERSION=
PHP=php
WP=
CONFIG=
INI_DIR=
EXT_DIR=
BIN_DIR=/usr/local/bin
SHARE_DIR=/usr/local/share/securecore

if [ -t 1 ]; then OK='✓' SAME='=' BAD='✗' NOTE='!' SKIP='·'; else OK=ok SAME=same BAD=error NOTE='!' SKIP=-; fi
say() { printf '%s\n' "$*"; }
step() { printf '%s %-14s %s\n' "$1" "$2" "$3"; }
die() { printf '%s %s\n' "$BAD" "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
Install the SecureCore PHP extension for the PHP that runs your site (Linux, x86_64 or arm64,
PHP 8.1-8.4, NTS or ZTS).

  curl -fsSL https://securecore.addis.gg/install.sh | sudo sh

Every option is optional; the defaults suit a usual server.

Options:
  --wordpress <dir>   the WordPress root: the mu-plugin goes into its wp-content/mu-plugins and
                      the config defaults to <dir>/securecore.json (default: the current
                      directory if it is a WordPress root, else /var/www/html if that is one)
  --config <file>     securecore.json (default: <wordpress>/securecore.json). Created with
                      every layer off if it doesn't exist; if it does, kept, and only
                      upgraded from an earlier release's form (backup beside it)
  --php <program>     the PHP CLI of the same build as your php-fpm (default: php)
  --ini-dir <dir>     where securecore.ini goes (default: PHP's scan folder; on Debian/Ubuntu
                      packages, mods-available + phpenmod)
  --extension-dir <dir>  where securecore.so goes (default: PHP's extension_dir)
  --bin-dir <dir>     where securecore-fpm goes (default: /usr/local/bin)
  --share-dir <dir>   where the JSON Schema goes (default: /usr/local/share/securecore)
  --canary            install the newest canary (default: the newest stable release, or the
                      newest canary while there is no stable one)
  --version <v>       install this release (e.g. 0.1.0 or 0.1.0-canary-a1b2c3d)
  --from <url>        download from <url> instead of https://securecore-releases.addis.gg
  -h, --help          this help
EOF
}

while [ $# -gt 0 ]; do
  case $1 in
    --wordpress|--config|--php|--ini-dir|--extension-dir|--bin-dir|--share-dir|--version|--from)
      [ $# -ge 2 ] || die "$1 needs a value (see --help)."; opt=$1 val=$2; shift 2 ;;
    --*=*) opt=${1%%=*} val=${1#*=}; shift ;;
    --canary) CHANNEL=canary; shift; continue ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option $1 (see --help)." ;;
  esac
  case $opt in
    --wordpress) WP=$val ;;
    --config) CONFIG=$val ;;
    --php) PHP=$val ;;
    --ini-dir) INI_DIR=$val ;;
    --extension-dir) EXT_DIR=$val ;;
    --bin-dir) BIN_DIR=$val ;;
    --share-dir) SHARE_DIR=$val ;;
    --version) VERSION=$val ;;
    --from) BASE=$val ;;
    *) die "Unknown option $opt (see --help)." ;;
  esac
done
BASE=${BASE%/}

command -v curl >/dev/null 2>&1 || die "This installer needs curl. Install it, then run the installer again."
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else die "This installer needs sha256sum (coreutils) to check its downloads."; fi
}
fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }

# --- this machine and its PHP ----------------------------------------------------------------
[ "$(uname -s)" = Linux ] || die "SecureCore's extension is for Linux (this is $(uname -s))."
case $(uname -m) in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "There is no SecureCore build for $(uname -m); there are builds for x86_64 and arm64." ;;
esac
command -v "$PHP" >/dev/null 2>&1 || die "No PHP found ($PHP). Pass --php with the PHP CLI that matches your php-fpm."
WORK=$(mktemp -d)
trap 'find "$WORK" -mindepth 1 -delete; rmdir "$WORK"' EXIT
# Every layer off: what PHP reads while the installer asks it about itself (below) and checks
# the download. An installed SecureCore refuses to start on an invalid config, and the config
# may be one an earlier release wrote, which is upgraded only further down.
printf '{"layer1":{"isolation":"off"},"layer2":{"enabled":false},"layer3":{"enabled":false}}\n' > "$WORK/off.json"
php_eval() { "$PHP" -n -r "$1"; }
# The PHP with its own ini (an installed SecureCore loads), but reading the every-layer-off config.
php_ini() { "$PHP" -d "securecore.config=$WORK/off.json" -r "$1"; }
PHP_VER=$(php_eval 'echo PHP_MAJOR_VERSION, ".", PHP_MINOR_VERSION;')
if [ "$(php_eval 'echo PHP_ZTS;')" = 1 ]; then TS=zts; TS_LABEL=ZTS; else TS=nts; TS_LABEL=NTS; fi
PHP_LABEL="PHP $(php_eval 'echo PHP_VERSION;') $TS_LABEL $ARCH"
# Not -n here: extension_dir and the scan folder are the build's, and php.ini may move the
# extension folder.
[ -n "$EXT_DIR" ] || EXT_DIR=$(php_ini 'echo ini_get("extension_dir");')
case $EXT_DIR in /*) ;; *) die "PHP's extension_dir is '$EXT_DIR', not an absolute folder. Pass --extension-dir." ;; esac
SO=securecore-php$PHP_VER-$TS-linux-$ARCH.so
LAUNCHER=securecore-fpm-linux-$ARCH
step "$OK" "PHP" "$PHP_LABEL ($(php_ini 'echo PHP_BINARY;'))"

# The ini goes where this PHP's SAPIs read it. Debian/Ubuntu packages keep one conf.d per SAPI
# (cli, fpm, apache2) fed from mods-available by phpenmod; the official images and source
# builds have one scan folder shared by the CLI and php-fpm.
SCAN=$(php_ini 'echo PHP_CONFIG_FILE_SCAN_DIR;')
ENMOD=
if [ -z "$INI_DIR" ]; then
  mods=/etc/php/$PHP_VER/mods-available
  case $SCAN in
    /etc/php/"$PHP_VER"/*/conf.d) if [ -d "$mods" ] && command -v phpenmod >/dev/null 2>&1; then INI_DIR=$mods ENMOD=1; fi ;;
  esac
  [ -n "$INI_DIR" ] || INI_DIR=$SCAN
fi
[ -n "$INI_DIR" ] || die "This PHP has no folder for extra ini files. Pass --ini-dir."

# --- WordPress and the config ------------------------------------------------------------------
if [ -z "$WP" ] && [ -z "$CONFIG" ]; then
  if [ -f ./wp-load.php ]; then WP=$(pwd)
  elif [ -f /var/www/html/wp-load.php ]; then WP=/var/www/html
  else die "There's no WordPress here or in /var/www/html. Run the installer from your WordPress folder, or pass --wordpress <folder>."
  fi
fi
if [ -n "$WP" ]; then
  [ -f "$WP/wp-load.php" ] || die "$WP is not a WordPress root (no wp-load.php). Pass --wordpress with the folder that has wp-config.php."
  WP=$(CDPATH='' cd "$WP" && pwd)
fi
if [ -z "$CONFIG" ] && [ -n "$WP" ]; then CONFIG=$WP/securecore.json; fi
[ -n "$CONFIG" ] || die "Say where securecore.json lives: --wordpress <root> (it goes at the root) or --config <file>."
case $CONFIG in /*) ;; *) CONFIG=$(pwd)/$CONFIG ;; esac

# Writable? Never sudo from here: say what to run.
for d in "$EXT_DIR" "$INI_DIR" "$BIN_DIR"; do
  if [ -d "$d" ] && [ ! -w "$d" ]; then die "Can't write to $d. Run the installer as root: curl -fsSL $BASE/install-ext.sh | sudo sh -s -- …"; fi
done

# --- the release -------------------------------------------------------------------------------
if [ -n "$VERSION" ]; then
  fetch "$BASE/$VERSION/release.json" "$WORK/release.json" || die "There is no SecureCore release $VERSION at $BASE."
elif [ "$CHANNEL" = canary ]; then
  fetch "$BASE/canary.json" "$WORK/release.json" || die "Couldn't download $BASE/canary.json. Check the connection, then run the installer again."
elif ! fetch "$BASE/latest.json" "$WORK/release.json" 2>/dev/null; then
  fetch "$BASE/canary.json" "$WORK/release.json" || die "Couldn't download $BASE/latest.json or $BASE/canary.json. Check the connection, then run the installer again."
  step "$NOTE" Release "no stable release yet, so the newest canary"
fi
tr -d ' \t\r\n' < "$WORK/release.json" > "$WORK/release.flat"
field() { sed -n "s/.*\"$1\":\"\\([^\"]*\\)\".*/\\1/p" "$WORK/release.flat" | head -n 1; }
REL=$(field version)
[ -n "$REL" ] || die "$BASE did not describe a SecureCore release. Run the installer again later."
# wantf <path> <field>: a sha256 field (sha256, unpacked_sha256) release.json gives for <path>,
# or nothing. want <path>: its sha256.
wantf() {
  key=$(printf '%s' "$1" | sed 's/[.]/[.]/g')
  grep -o "\"$key\":{[^}]*}" "$WORK/release.flat" | sed -n "s/.*\"$2\":\"\\([0-9a-f]\\{64\\}\\)\".*/\\1/p" | head -n 1
}
want() { wantf "$1" sha256; }
[ -n "$(want "ext/$SO")" ] || die "SecureCore $REL has no build for PHP $PHP_VER $TS_LABEL on $ARCH (ext/$SO). Builds: $(grep -o '"ext/securecore-php[^"]*"' "$WORK/release.flat" | tr -d '"' | sed 's|ext/securecore-||' | tr '\n' ' ')"
# get <path> <file>: download <path> of the release and check it against release.json.
get() {
  sha=$(want "$1")
  [ -n "$sha" ] || die "release.json of SecureCore $REL lists no $1."
  fetch "$BASE/$REL/$1" "$WORK/$2" || die "Couldn't download $BASE/$REL/$1. Run the installer again."
  [ "$(sha256 "$WORK/$2")" = "$sha" ] || die "$1 failed its sha256 check against release.json, so nothing was installed. Run the installer again; if it keeps failing, the download is being corrupted or tampered with."
}
get "ext/$SO" securecore.so
get "ext/$LAUNCHER" securecore-fpm
get ext/securecore-vault.php securecore-vault.php
get ext/securecore.schema.json securecore.schema.json
step "$OK" "Download" "SecureCore $REL: 4 files, each matching its sha256 in release.json"

# Layer 1's microVM (#71): mirab's guest kernel and the Firecracker mirab pins, as the release
# resolved them from mirab's newest stable release (ext/mirab-vm.json, itself checked against
# release.json). Each download is checked against the sha256s recorded there: the gzipped and
# the unpacked kernel, the Firecracker tarball and the binary in it.
VM=
if [ -z "$(want ext/mirab-vm.json)" ]; then
  step "$SKIP" "microVM" "this release carries none (mirab has no stable vm/ images yet), so layer 1's auto is gelada"
elif [ "$ARCH" != x86_64 ]; then
  step "$SKIP" "microVM" "mirab's Firecracker is for x86_64 only; layer 1's auto is gelada on $ARCH"
else
  get ext/mirab-vm.json mirab-vm.json
  tr -d ' \t\r\n' < "$WORK/mirab-vm.json" > "$WORK/vm.flat"
  # vm <block> <key>: a string from mirab-vm.json's linux-x86_64 <block> (kernel, firecracker),
  # or from its top level when <block> is "-".
  vm() {
    if [ "$1" = - ]; then src=$(cat "$WORK/vm.flat"); else src=$(grep -o "\"$1\":{[^}]*}" "$WORK/vm.flat" | head -n 1); fi
    printf '%s' "$src" | sed -n "s/.*\"$2\":\"\\([^\"]*\\)\".*/\\1/p" | head -n 1
  }
  check() { [ "$(sha256 "$1")" = "$2" ] || die "$3 failed its sha256 check against mirab's (release.json → ext/mirab-vm.json), so nothing was installed. Run the installer again."; }
  MIRAB=$(vm - mirab)
  fetch "$(vm kernel url)" "$WORK/vmlinux.gz" || die "Couldn't download mirab's guest kernel ($(vm kernel url)). Run the installer again."
  check "$WORK/vmlinux.gz" "$(vm kernel sha256)" "mirab $MIRAB's guest kernel"
  gzip -dc "$WORK/vmlinux.gz" > "$WORK/vmlinux" || die "mirab $MIRAB's guest kernel didn't unpack."
  check "$WORK/vmlinux" "$(vm kernel unpacked_sha256)" "mirab $MIRAB's unpacked guest kernel"
  FC=$(vm firecracker version)
  fetch "$(vm firecracker url)" "$WORK/fc.tgz" || die "Couldn't download Firecracker $FC ($(vm firecracker url)). Run the installer again."
  check "$WORK/fc.tgz" "$(vm firecracker sha256)" "Firecracker $FC's tarball"
  member=$(vm firecracker member)
  mkdir -p "$WORK/fc"
  jmember=$(vm jailer member)
  tar -xzf "$WORK/fc.tgz" -C "$WORK/fc" "$member" "$jmember" || die "Firecracker $FC's tarball has no $member or $jmember."
  mv "$WORK/fc/$member" "$WORK/firecracker"
  mv "$WORK/fc/$jmember" "$WORK/jailer"
  check "$WORK/firecracker" "$(vm firecracker member_sha256)" "Firecracker $FC"
  # The jailer (Firecracker runs under it, never as root): mirab's pin lists none, so it comes
  # from the tarball checked above and must match the sha256 the release recorded for it.
  check "$WORK/jailer" "$(vm jailer jailer_sha256)" "Firecracker $FC's jailer"
  rm -f "$WORK/vmlinux.gz" "$WORK/fc.tgz"
  # The guest's root image (#80): SecureCore's own, built with this release, gzipped. Its gzip
  # and its unpacked bytes are each checked against release.json. A release without one (before
  # #80) installs the rest, and installed.json then records no rootfs_sha256, so nothing boots.
  GUEST=
  ROOTFS=vm/linux-x86_64/rootfs.ext4.gz
  rootfs_rec=
  if [ -n "$(want "$ROOTFS")" ]; then
    unpacked=$(wantf "$ROOTFS" unpacked_sha256)
    [ -n "$unpacked" ] || die "release.json of SecureCore $REL lists $ROOTFS with no unpacked_sha256, so nothing was installed."
    get "$ROOTFS" rootfs.ext4.gz
    gzip -dc "$WORK/rootfs.ext4.gz" > "$WORK/rootfs.ext4" || die "$ROOTFS didn't unpack, so nothing was installed. Run the installer again."
    rm -f "$WORK/rootfs.ext4.gz"
    [ "$(sha256 "$WORK/rootfs.ext4")" = "$unpacked" ] \
      || die "$ROOTFS unpacked failed its sha256 check against release.json, so nothing was installed. Run the installer again; if it keeps failing, the download is being corrupted or tampered with."
    rootfs_rec=$(printf ',\n  "rootfs_sha256": "%s"' "$unpacked")
    GUEST=1
  fi
  printf '{\n  "securecore": "%s",\n  "mirab": "%s",\n  "commit": "%s",\n  "manifest": "%s",\n  "kernel_sha256": "%s",\n  "firecracker": "%s",\n  "firecracker_sha256": "%s",\n  "jailer_sha256": "%s"%s\n}\n' \
    "$REL" "$MIRAB" "$(vm - commit)" "$(vm - manifest)" "$(vm kernel unpacked_sha256)" "$FC" "$(vm firecracker member_sha256)" "$(vm jailer jailer_sha256)" "$rootfs_rec" > "$WORK/installed.json"
  if [ -n "$GUEST" ]; then
    step "$OK" "microVM" "mirab $MIRAB's guest kernel, Firecracker $FC, its jailer and SecureCore $REL's guest image, each matching its recorded sha256"
  else
    step "$OK" "microVM" "mirab $MIRAB's guest kernel, Firecracker $FC and its jailer, each matching its recorded sha256"
  fi
  VM=1
fi

# The verified extension must load in this PHP before anything is installed.
if ! out=$("$PHP" -n -d "extension=$WORK/securecore.so" -d "securecore.config=$WORK/off.json" \
    -r 'exit(extension_loaded("securecore") ? 0 : 1);' 2>&1); then
  die "The SecureCore build for $PHP_LABEL does not load in this PHP, so nothing was installed: $out"
fi
step "$OK" "Check" "the extension loads in this PHP"

# --- install -----------------------------------------------------------------------------------
# put <file> <dest> <mode> <label>: install unless the same bytes are there; atomic (rename).
put() {
  if [ -f "$2" ] && [ "$(sha256 "$2")" = "$(sha256 "$WORK/$1")" ]; then
    step "$SAME" "$4" "unchanged ($2)"
    return
  fi
  mkdir -p "$(dirname "$2")"
  cp "$WORK/$1" "$2.securecore-new"
  chmod "$3" "$2.securecore-new"
  mv -f "$2.securecore-new" "$2"
  step "$OK" "$4" "installed $2"
}
put securecore.so "$EXT_DIR/securecore.so" 644 "Extension"
put securecore-fpm "$BIN_DIR/securecore-fpm" 755 "Launcher"
put securecore.schema.json "$SHARE_DIR/securecore.schema.json" 644 "JSON Schema"
if [ -n "$VM" ]; then
  put firecracker "$SHARE_DIR/vm/firecracker" 755 "Firecracker"
  put jailer "$SHARE_DIR/vm/jailer" 755 "Jailer"
  put vmlinux "$SHARE_DIR/vm/vmlinux" 644 "Guest kernel"
  if [ -n "$GUEST" ]; then put rootfs.ext4 "$SHARE_DIR/vm/rootfs.ext4" 644 "Guest image"; fi
  # The unprivileged user Firecracker runs as (securecore-fpm --vm-user, default securecore-vm).
  if id securecore-vm >/dev/null 2>&1; then
    step "$SAME" "microVM user" "securecore-vm exists"
  elif command -v useradd >/dev/null 2>&1 && useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --user-group securecore-vm 2>/dev/null; then
    step "$OK" "microVM user" "created securecore-vm (system user, no login)"
  else
    step "$NOTE" "microVM user" "couldn't create securecore-vm: create it, or pass securecore-fpm --vm-user <uid>:<gid>"
  fi
  # What is installed, and from which mirab release: nobody edits a version by hand.
  put installed.json "$SHARE_DIR/vm/installed.json" 644 "microVM record"
  if [ -z "$GUEST" ]; then
    step "$NOTE" "microVM" "SecureCore $REL ships no guest image, so nothing verified boots: layer 1's auto is gelada and microvm refuses"
  fi
fi
if [ -n "$WP" ]; then
  mu=$WP/wp-content/mu-plugins
  put securecore-vault.php "$mu/securecore-vault.php" 644 "mu-plugin"
  # The site's files belong to the site's user, not root.
  owner=$(stat -c '%u:%g' "$WP/wp-content")
  chown "$owner" "$mu" "$mu/securecore-vault.php" 2>/dev/null || true
else
  put securecore-vault.php "$SHARE_DIR/securecore-vault.php" 644 "mu-plugin"
  step "$SKIP" "WordPress" "none given (--wordpress): for the vault, copy $SHARE_DIR/securecore-vault.php into wp-content/mu-plugins"
fi

# The config: never overwrite one. A new one has every layer off, so loading the extension
# changes nothing until a person turns layers on. Readable by the php-fpm workers, which reload it.
if [ -f "$CONFIG" ]; then
  # A file an earlier release wrote (layer1.enabled, now retired) is refused at startup, so the
  # launcher just installed upgrades it, keeping the original beside it.
  if out=$("$BIN_DIR/securecore-fpm" --migrate-config "$CONFIG" 2>&1); then
    case $out in
      unchanged*) step "$SAME" "Config" "kept $CONFIG" ;;
      *) step "$OK" "Config" "$out" ;;
    esac
  else
    step "$NOTE" "Config" "kept $CONFIG; $out"
  fi
  NEW_CONFIG=
else
  mkdir -p "$(dirname "$CONFIG")"
  cat > "$CONFIG.securecore-new" <<EOF
{
  "\$schema": "file://$SHARE_DIR/securecore.schema.json",
  "layer1": { "isolation": "off" },
  "layer2": { "enabled": false },
  "layer3": { "enabled": false }
}
EOF
  chmod 644 "$CONFIG.securecore-new"
  if [ -n "$WP" ]; then chown "$(stat -c '%u:%g' "$WP")" "$CONFIG.securecore-new" 2>/dev/null || true; fi
  mv -f "$CONFIG.securecore-new" "$CONFIG"
  step "$OK" "Config" "created $CONFIG (every layer off)"
  NEW_CONFIG=1
fi

# The ini last: from here on every new PHP process loads the extension, and refuses to start
# without a valid config, which now exists.
printf '; SecureCore %s (install-ext.sh). The config is read once at startup; layers 2 and 3 reload.\n; priority=20\nextension=securecore.so\nsecurecore.config=%s\n' "$REL" "$CONFIG" > "$WORK/securecore.ini"
# The version line changes on every upgrade; compare what PHP reads.
if [ -f "$INI_DIR/securecore.ini" ] && [ "$(grep -v '^;' "$INI_DIR/securecore.ini")" = "$(grep -v '^;' "$WORK/securecore.ini")" ]; then
  step "$SAME" "ini" "unchanged ($INI_DIR/securecore.ini)"
  INI_CHANGED=
else
  put securecore.ini "$INI_DIR/securecore.ini" 644 "ini"
  INI_CHANGED=1
fi
if [ -n "$ENMOD" ]; then
  # phpenmod is idempotent; run it every time so a SAPI added since is enabled too.
  phpenmod -v "$PHP_VER" securecore
  if [ -n "$INI_CHANGED" ]; then step "$OK" "phpenmod" "enabled for every PHP $PHP_VER SAPI"; else step "$SAME" "phpenmod" "enabled for every PHP $PHP_VER SAPI"; fi
fi

# What PHP sees now, with the site's ini.
# Its answer on stdout; stderr carries the extension's startup notes (the vault's count) and,
# on a refusal, the reason.
if out=$("$PHP" -r 'echo extension_loaded("securecore") ? "loaded" : "not loaded";' 2>"$WORK/loaded.err") && [ "$out" = loaded ]; then
  step "$OK" "Loaded" "php -m lists securecore, config $CONFIG"
elif [ -n "$NEW_CONFIG" ]; then
  die "PHP doesn't load SecureCore after the install: $out $(cat "$WORK/loaded.err")"
else
  step "$NOTE" "Loaded" "this PHP refuses $CONFIG here: $out $(cat "$WORK/loaded.err")"
  say "  php-fpm refuses it the same way unless its environment differs (vault env variables). Fix the file before restarting php-fpm."
fi

say ""
say "SecureCore $REL is installed for $PHP_LABEL. Next:"
say "  restart php-fpm (e.g. systemctl restart php$PHP_VER-fpm) to load it;"
say "  turn layers on in $CONFIG (schema: $SHARE_DIR/securecore.schema.json);"
say "  for layer 1, start php-fpm through the launcher: $BIN_DIR/securecore-fpm --config $CONFIG -- <php-fpm args>"
