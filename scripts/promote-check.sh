#!/bin/sh
# Refuses a canary release that must never become stable: one whose layer-1 microVM files were
# resolved from anything but mirab's stable channel (addiscorp/securecore#71; a development
# override such as a canary manifest, scripts/mirab-vm.sh's second argument), or whose guest
# image (#80) isn't the one its release.json and vm/manifest.json name, gzipped and unpacked.
# promote.yml runs it on the canary's bytes before it publishes them as stable, and again on the
# stable files read back from the bucket.
#   scripts/promote-check.sh <release-version-dir>       (the folder holding release.json)
# Exit 0: promotable. Exit 1: refused, with the reason. Needs jq, gzip, sha256sum.
set -eu
[ $# -eq 1 ] || { echo "usage: $0 <release-version-dir>" >&2; exit 2; }
dir=$1
[ -f "$dir/release.json" ] || { echo "$0: $dir has no release.json" >&2; exit 1; }
refuse() { echo "$0: refusing to promote: $*" >&2; exit 1; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

# The guest image: present exactly when release.json lists it, and the same bytes, gzipped and
# unpacked, that release.json and vm/manifest.json both name.
rootfs=vm/linux-x86_64/rootfs.ext4.gz
guest=
if jq -e --arg f "$rootfs" '.files[$f]' "$dir/release.json" > /dev/null 2>&1; then
  [ -f "$dir/$rootfs" ] || refuse "release.json lists $rootfs, but $dir has no such file"
  [ -f "$dir/vm/manifest.json" ] || refuse "$dir ships a guest image with no vm/manifest.json"
  want=$(jq -r --arg f "$rootfs" '.files[$f].sha256' "$dir/release.json")
  want_unpacked=$(jq -r --arg f "$rootfs" '.files[$f].unpacked_sha256 // empty' "$dir/release.json")
  [ -n "$want_unpacked" ] || refuse "release.json lists $rootfs with no unpacked_sha256"
  [ "$(jq -r '.platforms["linux-x86_64"].rootfs.sha256' "$dir/vm/manifest.json")" = "$want" ] \
    && [ "$(jq -r '.platforms["linux-x86_64"].rootfs.unpacked.sha256' "$dir/vm/manifest.json")" = "$want_unpacked" ] \
    || refuse "vm/manifest.json and release.json name different guest images"
  got=$(sha "$dir/$rootfs")
  [ "$got" = "$want" ] || refuse "$rootfs has sha256 $got, but release.json says $want"
  got=$(gzip -dc "$dir/$rootfs" | sha256sum | cut -d' ' -f1)
  [ "$got" = "$want_unpacked" ] || refuse "$rootfs unpacks to sha256 $got, but release.json says $want_unpacked"
  guest="; guest image $want_unpacked (unpacked), matching release.json and vm/manifest.json"
elif [ -e "$dir/$rootfs" ]; then
  refuse "$dir holds $rootfs, which release.json doesn't list"
fi

vm=$dir/ext/mirab-vm.json
if [ ! -f "$vm" ]; then
  echo "promotable: no microVM files from mirab in this release$guest"
  exit 0
fi
channel=$(jq -er .channel "$vm") || { echo "$0: $vm has no channel" >&2; exit 1; }
if [ "$channel" != stable ]; then
  refuse "$vm says its microVM files came from mirab's '$channel' channel ($(jq -r .manifest "$vm")); a stable release takes them from mirab's stable release only. Build a new canary without the mirab_manifest override."
fi
echo "promotable: microVM files from mirab $(jq -r .mirab "$vm") (stable)$guest"
