#!/bin/sh
# Build the release zip: only what a site needs, laid out as the plugin folder.
#   scripts/package.sh [version] [out-dir]     (defaults: VERSION, dist/)
# Writes <out-dir>/securecore.zip and securecore.zip.sha256. Unzipped into
# wp-content/plugins/ it is wp-content/plugins/securecore/.
set -eu
root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
version=${1:-$("$root/scripts/version.sh")}
out=${2:-$root/dist}
mkdir -p "$out"
out=$(CDPATH='' cd "$out" && pwd)

stage=$(mktemp -d "${TMPDIR:-$root/.tmp}/securecore-package.XXXXXX")
trap 'find "$stage" -mindepth 1 -delete; rmdir "$stage"' EXIT
pkg="$stage/securecore"
mkdir -p "$pkg/sandbox" "$pkg/bin" "$pkg/templates" "$pkg/setup"
# install.sh's site setup (WordPress, database, wp-config.php), run before the plugin is in place.
cp "$root/setup/site.php" "$pkg/setup/"

cp "$root/plugin/securecore.php" "$root/plugin/SecureCore.php" "$pkg/"
# The loader lives one level down so WordPress does not list it as a second plugin.
mkdir -p "$pkg/mu-plugin"
cp "$root/plugin/securecore-loader.php" "$pkg/mu-plugin/"
cp "$root/sandbox/worker.php" "$root/sandbox/setup.php" "$root/sandbox/scan.php" "$root/sandbox/gen-manifest.php" \
  "$root/sandbox/bootstrap.php" "$root/sandbox/realwp.php" "$root/sandbox/marshal.php" "$pkg/sandbox/"
cp "$root/bin/securecore-worker" "$pkg/bin/"
cp "$root/templates/securecore.service" "$root/templates/compose.yml" "$pkg/templates/"
cp "$root/INSTALL.md" "$pkg/"
printf '%s\n' "$version" > "$pkg/VERSION"
chmod 755 "$pkg/bin/securecore-worker"
# The plugin header carries the version WordPress shows.
sed "s/^ \* Version: .*/ * Version: $version/" "$root/plugin/securecore.php" > "$pkg/securecore.php"

rm -f "$out/securecore.zip"
(cd "$stage" && find securecore -exec touch -t 202601010000 {} + && zip -qrX "$out/securecore.zip" securecore)
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$out" && sha256sum securecore.zip | cut -d' ' -f1 > securecore.zip.sha256)
else
  (cd "$out" && shasum -a 256 securecore.zip | cut -d' ' -f1 > securecore.zip.sha256)
fi
echo "securecore $version: $out/securecore.zip ($(cat "$out/securecore.zip.sha256"))"
