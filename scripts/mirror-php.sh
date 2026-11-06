#!/bin/sh
# Mirror the PHP builds in scripts/php-builds.txt from static-php-cli into a directory laid out
# like the bucket, and write php.json describing every mirrored file:
#   <out>/php/<build>/<version>/<platform>/php.tar.gz
#   <out>/php.json
# Each php.json entry records our sha256, the upstream URL and the upstream file's sha256 at
# mirror time (dl.static-php.dev publishes no checksums, so this is the provenance).
#
#   scripts/mirror-php.sh <out-dir> [existing-php.json-url] [platform ...]
#
# With an existing php.json (the bucket's), entries already mirrored are kept as they are and
# not downloaded again; only new builds/versions/platforms land in <out-dir>/php/. With
# platforms given, only those are mirrored (the tests use linux-x64 alone).
# Used by .github/workflows/release.yml (which uploads <out-dir>) and by test/full-setup.sh.
set -eu
root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
out=$1
existing=${2:-}
shift $(($# >= 2 ? 2 : $#))
platforms=${*:-linux-x64 linux-arm64 macos-x64 macos-arm64}
UPSTREAM=https://dl.static-php.dev/static-php-cli
mkdir -p "$out"

sum() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
upstream_platform() { case $1 in linux-x64) echo linux-x86_64 ;; linux-arm64) echo linux-aarch64 ;; macos-x64) echo macos-x86_64 ;; macos-arm64) echo macos-aarch64 ;; *) return 1 ;; esac; }

old='{}'
if [ -n "$existing" ]; then
  old=$(curl -fsSL "$existing" 2>/dev/null || echo '{}')
  echo "$old" | jq -e . >/dev/null 2>&1 || old='{}'
fi

json=$(echo "$old" | jq '{builds: (.builds // {}), defaults: {}}')
while read -r build version; do
  case $build in ''|'#'*) continue ;; esac
  json=$(echo "$json" | jq --arg b "$build" --arg v "$version" '.defaults[$b] //= $v')
  for platform in $platforms; do
    have=$(echo "$json" | jq -r --arg b "$build" --arg v "$version" --arg p "$platform" '.builds[$b][$v][$p].sha256 // empty')
    if [ -n "$have" ]; then
      echo "kept     $build $version $platform ($have)"
      continue
    fi
    url="$UPSTREAM/$build/php-$version-cli-$(upstream_platform "$platform").tar.gz"
    path="php/$build/$version/$platform/php.tar.gz"
    mkdir -p "$out/$(dirname "$path")"
    curl -fsSL -A securecore-mirror "$url" -o "$out/$path"
    upstream_sha=$(sum "$out/$path")
    # The file we publish is the upstream file, byte for byte: both hashes are recorded so a
    # reader sees where it came from and what it was when we took it.
    tar -tzf "$out/$path" | grep -qx php || { echo "$url: no php binary inside" >&2; exit 1; }
    json=$(echo "$json" | jq --arg b "$build" --arg v "$version" --arg p "$platform" --arg path "$path" \
      --arg sha "$(sum "$out/$path")" --arg size "$(wc -c < "$out/$path" | tr -d ' ')" \
      --arg url "$url" --arg usha "$upstream_sha" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      '.builds[$b][$v][$p] = {path: $path, sha256: $sha, size: ($size | tonumber), upstream_url: $url, upstream_sha256: $usha, mirrored_at: $at}')
    echo "mirrored $build $version $platform ($upstream_sha) from $url"
  done
done < "$root/scripts/php-builds.txt"

echo "$json" | jq --arg src "$UPSTREAM" '{source: $src, defaults, builds}' > "$out/php.json"
echo "wrote $out/php.json"
