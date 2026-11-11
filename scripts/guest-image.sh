#!/bin/sh
# The microVM guest's root filesystem (addiscorp/securecore#71): a Docker image built from
# docker/ext.Dockerfile's `guest` target, exported to a read-only ext4 image, rootfs.ext4, which
# securecore-fpm boots (--rootfs, or <vm-dir>/rootfs.ext4). Needs Docker.
#   scripts/guest-image.sh <image> <out.ext4>
# The image carries no site's settings or secrets: the launcher delivers php-fpm's environment
# in each start message (#72).
#
# Reproducible (#80): the same image gives the same ext4, byte for byte, on any host. The export
# is unpacked and the disk made inside the `guest-tools` target (pinned base, e2fsprogs from
# snapshot.debian.org; scripts/guest-disk.sh), never with the host's tar or mke2fs: mke2fs 1.47.0
# (GitHub's ubuntu-24.04) copies each file's ctime from the unpacked tree, so two exports of one
# image made different disks there. SOURCE_DATE_EPOCH (default 0) is every file's time.
# scripts/guest-build.sh builds the image and this disk for a release.
set -eu
[ $# -eq 2 ] || { echo "usage: $0 <image> <out.ext4>" >&2; exit 2; }
image=$1 out=$2
root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
mkdir -p "$(dirname "$out")"
outdir=$(CDPATH='' cd "$(dirname "$out")" && pwd)
name=$(basename "$out")
tools=securecore-guest-tools:local
docker build -q -f "$root/docker/ext.Dockerfile" --target guest-tools -t "$tools" "$root" > /dev/null
c=$(docker create "$image")
# shellcheck disable=SC2064 # the container id is known now
trap "docker rm '$c' > /dev/null" EXIT
docker export "$c" | docker run -i --rm -e SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}" -v "$outdir:/out" "$tools" guest-disk "/out/$name"
echo "$out from $image ($(sha256sum "$out" | cut -d' ' -f1))"
