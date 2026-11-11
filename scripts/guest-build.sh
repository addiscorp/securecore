#!/bin/sh
# Layer 1's microVM guest image for a release (addiscorp/securecore#80): docker/ext.Dockerfile's
# `guest` target (its base pinned by digest), exported by scripts/guest-image.sh to a
# reproducible ext4 and gzipped (-n: no name or time in the header) to
#   <out-dir>/rootfs-linux-x86_64.ext4.gz
# which scripts/release-layout.sh publishes as <version>/vm/linux-x86_64/rootfs.ext4.gz.
# SOURCE_DATE_EPOCH is this commit's time unless set. As root (guest-image.sh keeps the image's
# owners), on an x86_64 Docker host (Firecracker is x86_64 only).
#
#   scripts/guest-build.sh <out-dir>           build it
#   scripts/guest-build.sh --check <out-dir>   build it, then again from scratch (docker build
#       --no-cache, a new export and mke2fs), and fail unless both images have the same sha256
set -eu
root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
check=
if [ "${1:-}" = --check ]; then check=1; shift; fi
[ $# -eq 1 ] || { echo "usage: $0 [--check] <out-dir>" >&2; exit 2; }
out=$1
cd "$root"
arch=$(scripts/ext-cells.sh arch)
[ "$arch" = x86_64 ] || { echo "$0: this Docker host is $arch; the microVM guest is x86_64 only" >&2; exit 1; }
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
export SOURCE_DATE_EPOCH
tag=securecore-guest-build:$$
mkdir -p "$out"
sha() { sha256sum "$1" | cut -d' ' -f1; }
# build <out.ext4> [docker build flags]
build() {
  f=$1; shift
  docker build -q "$@" --build-arg SOURCE_DATE_EPOCH -f docker/ext.Dockerfile --target guest -t "$tag" . > /dev/null
  scripts/guest-image.sh "$tag" "$f" >&2
  docker image rm "$tag" > /dev/null
}
build "$out/rootfs-linux-x86_64.ext4"
first=$(sha "$out/rootfs-linux-x86_64.ext4")
if [ -n "$check" ]; then
  build "$out/rootfs-again.ext4" --no-cache
  again=$(sha "$out/rootfs-again.ext4")
  rm -f "$out/rootfs-again.ext4"
  if [ "$first" != "$again" ]; then
    echo "$0: not reproducible: the first build's image is $first, the second's (--no-cache) $again" >&2
    exit 1
  fi
  echo "reproducible: two builds (the second with --no-cache) both made $first"
fi
gzip -n -9 -f "$out/rootfs-linux-x86_64.ext4"
echo "$out/rootfs-linux-x86_64.ext4.gz: $(wc -c < "$out/rootfs-linux-x86_64.ext4.gz") bytes gzipped, sha256 $(sha "$out/rootfs-linux-x86_64.ext4.gz"); unpacked $(gzip -dc "$out/rootfs-linux-x86_64.ext4.gz" | wc -c) bytes, sha256 $first (SOURCE_DATE_EPOCH $SOURCE_DATE_EPOCH)"
