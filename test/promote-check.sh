#!/bin/sh
# scripts/promote-check.sh (addiscorp/securecore#71): a canary whose microVM files came from a
# development mirab manifest is refused; one from mirab's stable channel, or one with no microVM
# files, is promotable. Needs jq. Exits non-zero on any failure. Writes .tmp/promote-check/.
set -u
cd "$(dirname "$0")/.." || exit 1
dir=.tmp/promote-check
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete
fails=0
check() {
  name=$1 channel=$2 want=$3
  mkdir -p "$dir/$name/ext"
  echo '{"version":"0.1.0-canary-abcdef0"}' > "$dir/$name/release.json"
  [ -z "$channel" ] || printf '{"mirab":"0.2.1-canary-b0b093c","channel":"%s","manifest":"https://mirab-releases.addis.gg/x/vm/manifest.json"}\n' "$channel" > "$dir/$name/ext/mirab-vm.json"
  scripts/promote-check.sh "$dir/$name" > "$dir/$name.log" 2>&1
  got=$?
  if [ "$got" = "$want" ]; then echo "ok   $name: exit $got"; else echo "FAIL $name: exit $got, want $want ($(cat "$dir/$name.log"))"; fails=$((fails + 1)); fi
}
check stable stable 0
check no-microvm "" 0
check canary-override "canary (override)" 1
check stable-override "stable (override)" 1
if grep -q "refusing to promote" "$dir/canary-override.log"; then echo "ok   the refusal says why"; else echo "FAIL the refusal says why"; fails=$((fails + 1)); fi
[ "$fails" -eq 0 ]
