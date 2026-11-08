#!/bin/sh
# Lay out a release the way the securecore-releases bucket holds it (APS 12):
#   <out>/<version>/securecore.zip          the plugin (scripts/package.sh)
#   <out>/<version>/securecore.zip.sha256
#   <out>/<version>/ext/…                   the extension (E8, addiscorp/securecore#53), when
#                                            <ext-dir> is given: every file in it (the cells'
#                                            securecore-php<v>-<ts>-linux-<arch>.so and the
#                                            securecore-fpm-linux-<arch> launchers, from
#                                            scripts/ext-build.sh), plus the mu-plugin
#                                            (securecore-vault.php) and the JSON Schema
#                                            (securecore.schema.json) from ext/
#   <out>/<version>/release.json            version, tag, commit, channel, zip + sha256, and
#                                            "files": the sha256 and size of every other file
#                                            in <version>/ — the manifest installers verify
#   <out>/canary.json                        a copy of that release.json (newest canary)
#   <out>/install.sh                         the plugin installer
#   <out>/install-ext.sh                     the extension installer (ext/install.sh)
# Used by .github/workflows/release.yml (the release, and each cell's release check), by
# test/install.sh and by test/release-check.sh, so the tests serve exactly what the bucket would.
#   scripts/release-layout.sh <version> <tag> <commit> <channel> <out-dir> [<ext-dir>]
set -eu
root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
[ $# -eq 5 ] || [ $# -eq 6 ] || { echo "usage: $0 <version> <tag> <commit> <channel> <out-dir> [<ext-dir>]" >&2; exit 2; }
version=$1
tag=$2
commit=$3
channel=$4
out=$5
ext=${6:-}
sum() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
mkdir -p "$out/$version"
"$root/scripts/package.sh" "$version" "$out/$version" >/dev/null
sha=$(cat "$out/$version/securecore.zip.sha256")
if [ -n "$ext" ]; then
  mkdir -p "$out/$version/ext"
  for f in "$ext"/*; do
    case ${f##*/} in
      securecore-php[0-9]*.[0-9]*-[nz]ts-linux-*.so|securecore-fpm-linux-*) cp "$f" "$out/$version/ext/" ;;
      *) echo "$0: $f is not a release file (securecore-php<v>-<ts>-linux-<arch>.so or securecore-fpm-linux-<arch>)" >&2; exit 1 ;;
    esac
  done
  cp "$root/ext/mu-plugin/securecore-vault.php" "$root/ext/securecore.schema.json" "$out/$version/ext/"
fi
# One line per file, sorted, so the manifest is stable and an installer can read it with sed.
files=$(cd "$out/$version" && find . -type f ! -name release.json | sed 's|^\./||' | LC_ALL=C sort)
manifest=$(
  n=0
  for f in $files; do
    n=$((n + 1))
    [ "$n" -gt 1 ] && printf ',\n'
    printf '    "%s": { "sha256": "%s", "bytes": %s }' "$f" "$(sum "$out/$version/$f")" "$(wc -c < "$out/$version/$f" | tr -d ' ')"
  done
)
cat > "$out/$version/release.json" <<EOF
{
  "name": "securecore",
  "version": "$version",
  "tag": "$tag",
  "commit": "$commit",
  "channel": "$channel",
  "published_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "zip": "securecore.zip",
  "sha256": "$sha",
  "files": {
$manifest
  }
}
EOF
cp "$out/$version/release.json" "$out/canary.json"
cp "$root/install.sh" "$out/install.sh"
cp "$root/ext/install.sh" "$out/install-ext.sh"
echo "$out: securecore $version ($channel) sha256 $sha, $(echo "$files" | grep -c .) files in release.json"
