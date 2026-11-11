#!/bin/sh
# Refuses a canary release that must never become stable (addiscorp/securecore#71): one whose
# layer-1 microVM files were resolved from anything but mirab's stable channel (a development
# override such as a canary manifest, scripts/mirab-vm.sh's second argument). promote.yml runs
# it on the canary's bytes before it publishes them as stable.
#   scripts/promote-check.sh <release-version-dir>       (the folder holding release.json)
# Exit 0: promotable. Exit 1: refused, with the reason.
set -eu
[ $# -eq 1 ] || { echo "usage: $0 <release-version-dir>" >&2; exit 2; }
dir=$1
[ -f "$dir/release.json" ] || { echo "$0: $dir has no release.json" >&2; exit 1; }
vm=$dir/ext/mirab-vm.json
if [ ! -f "$vm" ]; then
  echo "promotable: no microVM files in this release"
  exit 0
fi
channel=$(jq -er .channel "$vm") || { echo "$0: $vm has no channel" >&2; exit 1; }
if [ "$channel" != stable ]; then
  echo "$0: refusing to promote: $vm says its microVM files came from mirab's '$channel' channel ($(jq -r .manifest "$vm")); a stable release takes them from mirab's stable release only. Build a new canary without the mirab_manifest override." >&2
  exit 1
fi
echo "promotable: microVM files from mirab $(jq -r .mirab "$vm") (stable)"
