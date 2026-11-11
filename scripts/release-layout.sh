#!/bin/sh
# Lay out a release the way the securecore-releases bucket holds it (APS 12):
#   <out>/<version>/securecore.zip          the plugin (scripts/package.sh)
#   <out>/<version>/securecore.zip.sha256
#   <out>/<version>/ext/…                   the extension (E8, addiscorp/securecore#53), when
#                                            <ext-dir> is given: every file in it (the cells'
#                                            securecore-php<v>-<ts>-linux-<arch>.so and the
#                                            securecore-fpm-linux-<arch> launchers, from
#                                            scripts/ext-build.sh; mirab-vm.json, what layer 1's
#                                            microVM takes from mirab, from scripts/mirab-vm.sh,
#                                            when the release resolved one), plus the mu-plugin
#                                            (securecore-vault.php) and the JSON Schema
#                                            (securecore.schema.json) from ext/
#   <out>/<version>/vm/linux-x86_64/rootfs.ext4.gz  layer 1's microVM guest image (#80), when
#                                            <ext-dir> holds rootfs-linux-x86_64.ext4.gz
#                                            (scripts/guest-build.sh), with
#   <out>/<version>/vm/manifest.json         its sha256 and size gzipped and unpacked (the
#                                            shape of mirab's vm/manifest.json); release.json's
#                                            entry for it carries the same four values
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
      securecore-php[0-9]*.[0-9]*-[nz]ts-linux-*.so|securecore-fpm-linux-*|mirab-vm.json) cp "$f" "$out/$version/ext/" ;;
      rootfs-linux-x86_64.ext4.gz)
        mkdir -p "$out/$version/vm/linux-x86_64"
        cp "$f" "$out/$version/vm/linux-x86_64/rootfs.ext4.gz" ;;
      *) echo "$0: $f is not a release file (securecore-php<v>-<ts>-linux-<arch>.so, securecore-fpm-linux-<arch>, mirab-vm.json or rootfs-linux-x86_64.ext4.gz)" >&2; exit 1 ;;
    esac
  done
  cp "$root/ext/mu-plugin/securecore-vault.php" "$root/ext/securecore.schema.json" "$out/$version/ext/"
fi
# The guest image's two sha256s and sizes, gzipped and unpacked, read from the bytes here (never
# from a file beside them): release.json and vm/manifest.json both print these variables.
rootfs=vm/linux-x86_64/rootfs.ext4.gz
if [ -f "$out/$version/$rootfs" ]; then
  gzip -t "$out/$version/$rootfs" || { echo "$0: $rootfs is not a whole gzip file" >&2; exit 1; }
  r_sha=$(sum "$out/$version/$rootfs")
  r_bytes=$(wc -c < "$out/$version/$rootfs" | tr -d ' ')
  if command -v sha256sum >/dev/null 2>&1; then r_unpacked=$(gzip -dc "$out/$version/$rootfs" | sha256sum | cut -d' ' -f1)
  else r_unpacked=$(gzip -dc "$out/$version/$rootfs" | shasum -a 256 | cut -d' ' -f1); fi
  r_unpacked_bytes=$(gzip -dc "$out/$version/$rootfs" | wc -c | tr -d ' ')
  # The version's own manifest for vm/ (APS 12; the shape of mirab's vm/manifest.json). Promote
  # copies it byte for byte, so it names the canary it was built as, not a version.
  cat > "$out/$version/vm/manifest.json" <<EOF
{
  "name": "securecore",
  "built_as": "$version",
  "commit": "$commit",
  "platforms": {
    "linux-x86_64": {
      "rootfs": {
        "file": "linux-x86_64/rootfs.ext4.gz",
        "sha256": "$r_sha",
        "size": $r_bytes,
        "unpacked": { "sha256": "$r_unpacked", "size": $r_unpacked_bytes }
      }
    }
  }
}
EOF
fi
# One line per file, sorted, so the manifest is stable and an installer can read it with sed.
files=$(cd "$out/$version" && find . -type f ! -name release.json | sed 's|^\./||' | LC_ALL=C sort)
manifest=$(
  n=0
  for f in $files; do
    n=$((n + 1))
    [ "$n" -gt 1 ] && printf ',\n'
    if [ "$f" = "$rootfs" ]; then
      # Flat, so the installer's sed reads it: the gzip's sha256 and size, then the image's.
      printf '    "%s": { "sha256": "%s", "bytes": %s, "unpacked_sha256": "%s", "unpacked_bytes": %s }' \
        "$f" "$r_sha" "$r_bytes" "$r_unpacked" "$r_unpacked_bytes"
    else
      printf '    "%s": { "sha256": "%s", "bytes": %s }' "$f" "$(sum "$out/$version/$f")" "$(wc -c < "$out/$version/$f" | tr -d ' ')"
    fi
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
