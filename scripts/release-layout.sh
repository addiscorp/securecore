#!/bin/sh
# Lay out a release the way the securecore-releases bucket holds it (APS 12):
#   <out>/<version>/securecore.zip          the plugin (scripts/package.sh)
#   <out>/<version>/securecore.zip.sha256
#   <out>/<version>/release.json            version, tag, commit, channel, zip + sha256
#   <out>/canary.json                        a copy of that release.json (newest canary)
#   <out>/install.sh                         the installer
# Used by .github/workflows/release.yml and by test/install.sh, so the local test serves
# exactly what the bucket would.
#   scripts/release-layout.sh <version> <tag> <commit> <channel> <out-dir>
set -eu
root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
version=$1
tag=$2
commit=$3
channel=$4
out=$5
mkdir -p "$out/$version"
"$root/scripts/package.sh" "$version" "$out/$version" >/dev/null
sha=$(cat "$out/$version/securecore.zip.sha256")
cat > "$out/$version/release.json" <<EOF
{
  "name": "securecore",
  "version": "$version",
  "tag": "$tag",
  "commit": "$commit",
  "channel": "$channel",
  "published_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "zip": "securecore.zip",
  "sha256": "$sha"
}
EOF
cp "$out/$version/release.json" "$out/canary.json"
cp "$root/install.sh" "$out/install.sh"
echo "$out: securecore $version ($channel) sha256 $sha"
