#!/bin/sh
# What layer 1's microVM takes from mirab (addiscorp/securecore#71), resolved at release time and
# never pinned here: mirab's newest stable release (latest.json), its vm/manifest.json (the guest
# kernel and its sha256s), and the Firecracker release mirab pins at that release's commit
# (mirab's scripts/firecracker.json; mirab's release publishes no Firecracker of its own). The
# result is <out>/mirab-vm.json, which the release lists in release.json and ext/install.sh
# installs from: every download checked against these sha256s.
#
#   scripts/mirab-vm.sh <out-dir>                       mirab's newest stable release
#   scripts/mirab-vm.sh <out-dir> <manifest-url>        an explicit vm/manifest.json instead, for
#       development: https://mirab-releases.addis.gg/<version>/vm/manifest.json (a canary)
#   scripts/mirab-vm.sh --files <dir> <out-dir> [...]   also keep the checked files in <dir>
#       (firecracker, vmlinux), as the installer would install them: for the tests
#
# Every file named is downloaded and checked here too, so a release never records a sha256 the
# bytes don't match. Exit 0: written. Exit 3: the release has no vm/ images (mirab stable before
# mirab#89), nothing written: the release ships without the microVM, and layer 1 is gelada.
# Anything else is an error. Linux x86_64 only: mirab pins Firecracker for x86_64.
# Needs curl, jq, sha256sum, tar, gzip.
set -eu
files=
if [ "${1:-}" = --files ]; then files=${2:?--files needs a folder}; shift 2; fi
[ $# -eq 1 ] || [ $# -eq 2 ] || { echo "usage: $0 [--files <dir>] <out-dir> [<vm/manifest.json url>]" >&2; exit 2; }
out=$1 manifest_url=${2:-}
MIRAB=https://mirab-releases.addis.gg
work=$(mktemp -d "${TMPDIR:?set TMPDIR to a folder of your own}/mirab-vm.XXXXXX")
trap 'find "$work" -mindepth 1 -delete; rmdir "$work"' EXIT
get() { curl -fsSL --retry 3 -o "$2" "$1"; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
want() { [ "$(sha "$1")" = "$2" ] || { echo "$0: $3: sha256 $(sha "$1"), but $4 says $2" >&2; exit 1; }; }

if [ -z "$manifest_url" ]; then
  get "$MIRAB/latest.json" "$work/latest.json"
  version=$(jq -er .version "$work/latest.json")
  channel=$(jq -er .channel "$work/latest.json")
  manifest_url=$MIRAB/$version/vm/manifest.json
  code=$(curl -s -o "$work/manifest.json" -w '%{http_code}' "$manifest_url")
  if [ "$code" = 404 ]; then
    echo "$0: mirab $version ($channel) has no vm/manifest.json, so this release carries no microVM (mirab#89 adds it)" >&2
    exit 3
  fi
  [ "$code" = 200 ] || { echo "$0: $manifest_url: HTTP $code" >&2; exit 1; }
else
  case $manifest_url in
    "$MIRAB"/*/vm/manifest.json) ;;
    *) echo "$0: $manifest_url is not a mirab release's vm/manifest.json ($MIRAB/<version>/vm/manifest.json)" >&2; exit 2 ;;
  esac
  get "$manifest_url" "$work/manifest.json"
  case $(jq -er .version "$work/manifest.json") in
    *-canary-*) channel="canary (override)" ;;
    *) channel="stable (override)" ;;
  esac
fi
version=$(jq -er .version "$work/manifest.json")
commit=$(jq -er .commit "$work/manifest.json")
[ "$manifest_url" = "$MIRAB/$version/vm/manifest.json" ] || { echo "$0: $manifest_url names version $version" >&2; exit 1; }
kfile=$(jq -er '.platforms["linux-x64"].kernel.file' "$work/manifest.json")
ksha=$(jq -er '.platforms["linux-x64"].kernel.sha256' "$work/manifest.json")
kunpacked=$(jq -er '.platforms["linux-x64"].kernel.unpacked.sha256' "$work/manifest.json")
kurl=$MIRAB/$version/vm/$kfile
get "$kurl" "$work/vmlinux.gz"
want "$work/vmlinux.gz" "$ksha" "$kurl" "$manifest_url"
gzip -dc "$work/vmlinux.gz" > "$work/vmlinux"
want "$work/vmlinux" "$kunpacked" "$kurl unpacked" "$manifest_url"

# Firecracker: mirab's pin at the commit this release was built from.
pin_url=https://raw.githubusercontent.com/addiscorp/mirab/$commit/scripts/firecracker.json
get "$pin_url" "$work/firecracker.json"
fv=$(jq -er .version "$work/firecracker.json")
furl=$(jq -er .tarball "$work/firecracker.json")
fsha=$(jq -er .sha256 "$work/firecracker.json")
member=release-v$fv-x86_64/firecracker-v$fv-x86_64
msha=$(jq -er ".files[\"firecracker-v$fv-x86_64\"]" "$work/firecracker.json")
get "$furl" "$work/fc.tgz"
want "$work/fc.tgz" "$fsha" "$furl" "$pin_url"
tar -xzf "$work/fc.tgz" -C "$work" "$member"
want "$work/$member" "$msha" "$member" "$pin_url"
# The jailer, from the same tarball. mirab's pin lists no jailer, so it is trusted through the
# tarball's sha256 (which the pin does list) and checked against the tarball's own SHA256SUMS.
jmember=release-v$fv-x86_64/jailer-v$fv-x86_64
sums=release-v$fv-x86_64/SHA256SUMS
tar -xzf "$work/fc.tgz" -C "$work" "$jmember" "$sums"
jsha=$(sha "$work/$jmember")
jlisted=$(awk -v f="jailer-v$fv-x86_64" '$2 == f || $2 == "./" f || $2 == "*" f { print $1 }' "$work/$sums")
[ "$jlisted" = "$jsha" ] || { echo "$0: $jmember: sha256 $jsha, but the tarball's SHA256SUMS says '${jlisted:-nothing}'" >&2; exit 1; }
if [ "$(jq -r ".files[\"jailer-v$fv-x86_64\"] // empty" "$work/firecracker.json")" = "" ]; then
  echo "$0: note: mirab's $pin_url lists no jailer; it is checked through the pinned tarball and its SHA256SUMS" >&2
fi

mkdir -p "$out"
jq -n --arg version "$version" --arg commit "$commit" --arg channel "$channel" --arg manifest "$manifest_url" \
  --arg manifest_sha256 "$(sha "$work/manifest.json")" \
  --arg kurl "$kurl" --arg ksha "$ksha" --arg kunpacked "$kunpacked" \
  --arg pin "$pin_url" --arg fv "$fv" --arg furl "$furl" --arg fsha "$fsha" --arg member "$member" --arg msha "$msha" \
  --arg jmember "$jmember" --arg jsha "$jsha" '{
    mirab: $version, commit: $commit, channel: $channel,
    manifest: $manifest, manifest_sha256: $manifest_sha256,
    platforms: { "linux-x86_64": {
      kernel: { url: $kurl, sha256: $ksha, unpacked_sha256: $kunpacked },
      firecracker: { version: $fv, pin: $pin, url: $furl, sha256: $fsha, member: $member, member_sha256: $msha },
      jailer: { member: $jmember, jailer_sha256: $jsha }
    } }
  }' > "$out/mirab-vm.json"
if [ -n "$files" ]; then
  mkdir -p "$files"
  cp "$work/vmlinux" "$files/vmlinux"
  cp "$work/$member" "$files/firecracker"
  cp "$work/$jmember" "$files/jailer"
  chmod 644 "$files/vmlinux"
  chmod 755 "$files/firecracker" "$files/jailer"
fi
echo "$out/mirab-vm.json: mirab $version ($channel, $commit): kernel $kunpacked, Firecracker $fv $msha"
