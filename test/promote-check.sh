#!/bin/sh
# scripts/promote-check.sh (addiscorp/securecore#71, #80): a canary whose microVM files came from a
# development mirab manifest is refused; one from mirab's stable channel, or one with no microVM
# files, is promotable. A release with a guest image is promotable only when the image is the one
# release.json and vm/manifest.json name, gzipped and unpacked (the releases here are laid out by
# scripts/release-layout.sh, as release.yml lays them out). Needs jq, gzip, sha256sum.
# Exits non-zero on any failure. Writes .tmp/promote-check/.
set -u
cd "$(dirname "$0")/.." || exit 1
dir=.tmp/promote-check
mkdir -p "$dir"
find "$dir" -mindepth 1 -delete
export TMPDIR="${TMPDIR:-$PWD/.tmp}"
fails=0
# expect <name> <want-exit> <release-dir>
expect() {
  scripts/promote-check.sh "$3" > "$dir/$1.log" 2>&1
  got=$?
  if [ "$got" = "$2" ]; then echo "ok   $1: exit $got"; else echo "FAIL $1: exit $got, want $2 ($(cat "$dir/$1.log"))"; fails=$((fails + 1)); fi
}
check() {
  name=$1 channel=$2 want=$3
  mkdir -p "$dir/$name/ext"
  echo '{"version":"0.1.0-canary-abcdef0"}' > "$dir/$name/release.json"
  [ -z "$channel" ] || printf '{"mirab":"0.2.1-canary-b0b093c","channel":"%s","manifest":"https://mirab-releases.addis.gg/x/vm/manifest.json"}\n' "$channel" > "$dir/$name/ext/mirab-vm.json"
  expect "$name" "$want" "$dir/$name"
}
check stable stable 0
check no-microvm "" 0
check canary-override "canary (override)" 1
check stable-override "stable (override)" 1
if grep -q "refusing to promote" "$dir/canary-override.log"; then echo "ok   the refusal says why"; else echo "FAIL the refusal says why"; fails=$((fails + 1)); fi

# The guest image (#80). A small stand-in for rootfs.ext4 (the check reads bytes, not ext4), laid
# out with a stable mirab-vm.json and a cell's files the way release.yml does.
v=0.1.0-canary-abcdef0
src=$dir/guest-src
mkdir -p "$src"
head -c 300000 /dev/zero | tr '\0' 'g' > "$src/rootfs.ext4"
gzip -n -c "$src/rootfs.ext4" > "$src/rootfs-linux-x86_64.ext4.gz"
rm "$src/rootfs.ext4"
printf '{"mirab":"0.2.1","channel":"stable","manifest":"https://mirab-releases.addis.gg/0.2.1/vm/manifest.json"}\n' > "$src/mirab-vm.json"
: > "$src/securecore-php8.3-nts-linux-x86_64.so"
: > "$src/securecore-fpm-linux-x86_64"
# guest <name>: a fresh layout of that release in $dir/<name>/; sets r to its <version> folder.
guest() {
  r=$dir/$1/$v
  if scripts/release-layout.sh "$v" "v$v" 0000000000000000000000000000000000000000 canary "$dir/$1" "$src" > "$dir/$1.layout.log" 2>&1 \
    && [ -f "$r/$gz" ] && [ -f "$r/vm/manifest.json" ]; then
    :
  else
    echo "FAIL $1: release layout with the guest image ($(cat "$dir/$1.layout.log"))"; fails=$((fails + 1))
  fi
}
gz=vm/linux-x86_64/rootfs.ext4.gz
guest guest-ok
expect guest-ok 0 "$r"
if grep -q "guest image .* matching release.json and vm/manifest.json" "$dir/guest-ok.log"; then echo "ok   it names the guest image it checked"; else echo "FAIL it names the guest image it checked ($(cat "$dir/guest-ok.log"))"; fails=$((fails + 1)); fi
if [ "$(jq -r --arg f "$gz" '.files[$f].unpacked_sha256' "$r/release.json")" = "$(gzip -dc "$src/rootfs-linux-x86_64.ext4.gz" | sha256sum | cut -d' ' -f1)" ] \
  && [ "$(jq -r '.platforms["linux-x86_64"].rootfs.unpacked.size' "$r/vm/manifest.json")" = 300000 ]; then
  echo "ok   the layout records the image's unpacked sha256 (release.json) and size (vm/manifest.json)"
else
  echo "FAIL the layout records the image's unpacked sha256 and size"; fails=$((fails + 1))
fi
guest guest-changed-gz
printf x >> "$r/$gz"
expect guest-changed-gz 1 "$r"
guest guest-other-unpacked
jq --arg f "$gz" '.files[$f].unpacked_sha256 = ("0" * 64)' "$r/release.json" > "$r/release.new" && mv "$r/release.new" "$r/release.json"
jq '.platforms["linux-x86_64"].rootfs.unpacked.sha256 = ("0" * 64)' "$r/vm/manifest.json" > "$r/vm/manifest.new" && mv "$r/vm/manifest.new" "$r/vm/manifest.json"
expect guest-other-unpacked 1 "$r"
if grep -q "unpacks to sha256" "$dir/guest-other-unpacked.log"; then
  echo "ok   a release.json naming another unpacked image: says so"
else
  echo "FAIL a release.json naming another unpacked image: says so ($(cat "$dir/guest-other-unpacked.log"))"; fails=$((fails + 1))
fi
guest guest-manifest-disagrees
jq '.platforms["linux-x86_64"].rootfs.sha256 = ("0" * 64)' "$r/vm/manifest.json" > "$r/vm/manifest.new" && mv "$r/vm/manifest.new" "$r/vm/manifest.json"
expect guest-manifest-disagrees 1 "$r"
guest guest-unlisted
jq --arg f "$gz" 'del(.files[$f])' "$r/release.json" > "$r/release.new" && mv "$r/release.new" "$r/release.json"
expect guest-unlisted 1 "$r"
guest guest-missing
rm "$r/$gz"
expect guest-missing 1 "$r"
[ "$fails" -eq 0 ]
