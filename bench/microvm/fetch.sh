#!/bin/sh
# Fetches what layer 1's microVM reuses from mirab (addiscorp/securecore#68), into .tmp/mvm/:
#   firecracker   the release mirab pins (firecracker.json is mirab's scripts/firecracker.json,
#                 verbatim): the tarball and the binary are both checked against the pin, as
#                 mirab's src/isolation/firecracker-install.ts does
#   vmlinux       mirab's published guest kernel (mirab-kernel.json: the canary whose
#                 vm/manifest.json lists it), checked gzipped and unpacked
# Needs curl, jq, tar, gzip, sha256sum.   bench/microvm/fetch.sh
set -eu
cd "$(dirname "$0")/../.."
here=bench/microvm
out=.tmp/mvm
mkdir -p "$out"
sha() { sha256sum "$1" | cut -d' ' -f1; }
check() { [ "$(sha "$1")" = "$2" ] || { echo "refusing $1: sha256 $(sha "$1") is not the pinned $2" >&2; exit 1; }; }

v=$(jq -r .version $here/firecracker.json)
name=firecracker-v$v-x86_64
if [ ! -x "$out/firecracker" ] || [ "$(sha "$out/firecracker")" != "$(jq -r ".files[\"$name\"]" $here/firecracker.json)" ]; then
  curl -fsSL -o "$out/fc.tgz" "$(jq -r .tarball $here/firecracker.json)"
  check "$out/fc.tgz" "$(jq -r .sha256 $here/firecracker.json)"
  tar -xzf "$out/fc.tgz" -C "$out" "release-v$v-x86_64/$name"
  check "$out/release-v$v-x86_64/$name" "$(jq -r ".files[\"$name\"]" $here/firecracker.json)"
  mv "$out/release-v$v-x86_64/$name" "$out/firecracker"
  chmod 755 "$out/firecracker"
  rmdir "$out/release-v$v-x86_64"
  rm -f "$out/fc.tgz"
fi
echo "firecracker $("$out/firecracker" --version | head -1) (sha256 $(sha "$out/firecracker"))"

if [ ! -s "$out/vmlinux" ] || [ "$(sha "$out/vmlinux")" != "$(jq -r .unpacked_sha256 $here/mirab-kernel.json)" ]; then
  # The pin must still be what mirab's release says it is.
  curl -fsSL "$(jq -r .manifest $here/mirab-kernel.json)" | jq -r '.platforms["linux-x64"].kernel.sha256' > "$out/manifest.sha"
  [ "$(cat "$out/manifest.sha")" = "$(jq -r .sha256 $here/mirab-kernel.json)" ] || { echo "mirab's manifest no longer lists the pinned kernel" >&2; exit 1; }
  curl -fsSL -o "$out/vmlinux.gz" "$(jq -r .url $here/mirab-kernel.json)"
  check "$out/vmlinux.gz" "$(jq -r .sha256 $here/mirab-kernel.json)"
  gzip -dc "$out/vmlinux.gz" > "$out/vmlinux"
  check "$out/vmlinux" "$(jq -r .unpacked_sha256 $here/mirab-kernel.json)"
  rm -f "$out/vmlinux.gz" "$out/manifest.sha"
fi
echo "vmlinux mirab $(jq -r .mirab $here/mirab-kernel.json) (sha256 $(sha "$out/vmlinux"))"
