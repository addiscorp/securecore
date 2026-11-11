#!/bin/sh
# Layer 1's microVM guest image for a release (addiscorp/securecore#80): docker/ext.Dockerfile's
# `guest` target (its base pinned by digest, its apt packages from snapshot.debian.org), made
# into a reproducible ext4 by scripts/guest-image.sh and gzipped (-n: no name or time) inside the
# pinned `guest-tools` image, to
#   <out-dir>/rootfs-linux-x86_64.ext4.gz
# which scripts/release-layout.sh publishes as <version>/vm/linux-x86_64/rootfs.ext4.gz.
# SOURCE_DATE_EPOCH is this commit's time unless set. On an x86_64 Docker host (Firecracker is
# x86_64 only).
#
#   scripts/guest-build.sh <out-dir>           build it (the release)
#   scripts/guest-build.sh --check <out-dir>   build it, then again from nothing in a builder of
#       its own (a new BuildKit with no layer and no RUN --mount cache, removed afterwards), and
#       fail, naming the files that differ, unless both disks have the same sha256. A separate,
#       non-gating CI job (release.yml's guest-reproducible); never part of the release path.
set -eu
root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
check=
if [ "${1:-}" = --check ]; then check=1; shift; fi
[ $# -eq 1 ] || { echo "usage: $0 [--check] <out-dir>" >&2; exit 2; }
mkdir -p "$1"
out=$(CDPATH='' cd "$1" && pwd)
cd "$root"
arch=$(scripts/ext-cells.sh arch)
[ "$arch" = x86_64 ] || { echo "$0: this Docker host is $arch; the microVM guest is x86_64 only" >&2; exit 1; }
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
export SOURCE_DATE_EPOCH
tag=securecore-guest-build:$$
sha() { sha256sum "$1" | cut -d' ' -f1; }
docker build -q --build-arg SOURCE_DATE_EPOCH -f docker/ext.Dockerfile --target guest -t "$tag" . > /dev/null
scripts/guest-image.sh "$tag" "$out/rootfs-linux-x86_64.ext4" >&2
first=$(sha "$out/rootfs-linux-x86_64.ext4")
if [ -n "$check" ]; then
  # The second build: its own BuildKit (pinned), so nothing of the first build is reused, the
  # cargo registry and target caches included.
  builder=securecore-guest-check-$$
  docker buildx create --name "$builder" --driver docker-container \
    --driver-opt image=moby/buildkit:v0.34.0@sha256:b059f8d7226d0b326bc871af489a5dddf65e36af4d20d14251b072974d9ee87c > /dev/null
  trap 'docker buildx rm "$builder" > /dev/null 2>&1; docker image rm "$tag" "$tag-again" > /dev/null 2>&1' EXIT
  docker buildx build --builder "$builder" --no-cache --load -q --build-arg SOURCE_DATE_EPOCH \
    -f docker/ext.Dockerfile --target guest -t "$tag-again" . > /dev/null
  scripts/guest-image.sh "$tag-again" "$out/rootfs-again.ext4" >&2
  again=$(sha "$out/rootfs-again.ext4")
  rm -f "$out/rootfs-again.ext4"
  if [ "$first" != "$again" ]; then
    echo "$0: not reproducible: the first build's disk is $first, the second's (a fresh builder) $again" >&2
    # Which files differ, from the two images' trees (the same tools image lists them).
    for t in "$tag" "$tag-again"; do
      c=$(docker create "$t")
      docker export "$c" | docker run -i --rm securecore-guest-tools:local sh -c \
        'mkdir /t && tar -x --numeric-owner -C /t && cd /t && find . -xdev \( -type f -exec sha256sum {} + \) -o \( ! -type f -printf "%y %m %U:%G - %p %l\n" \) | sort -k2' > "$out/tree-$t.txt"
      docker rm "$c" > /dev/null
    done
    diff "$out/tree-$tag.txt" "$out/tree-$tag-again.txt" | head -50 >&2 || true
    echo "$0: (no lines above: the trees match and the disks differ, so mke2fs or the export is at fault)" >&2
    exit 1
  fi
  echo "reproducible: two builds (the second from nothing in a builder of its own) both made $first"
else
  docker image rm "$tag" > /dev/null
fi
docker run --rm -v "$out:/out" securecore-guest-tools:local gzip -n -9 -f /out/rootfs-linux-x86_64.ext4
gz=$out/rootfs-linux-x86_64.ext4.gz
echo "$gz: $(wc -c < "$gz") bytes gzipped, sha256 $(sha "$gz"); unpacked $(gzip -dc "$gz" | wc -c) bytes, sha256 $first (SOURCE_DATE_EPOCH $SOURCE_DATE_EPOCH)"
