#!/bin/sh
# The microVM guest's root filesystem (addiscorp/securecore#71): a Docker image built from
# docker/ext.Dockerfile's `guest` target, exported to a read-only ext4 image, rootfs.ext4, which
# securecore-fpm boots (--rootfs, or <vm-dir>/rootfs.ext4). Needs Docker and mke2fs, as root
# (the export keeps the image's owners).
#   scripts/guest-image.sh <image> <out.ext4> [<env-file>]
# <env-file>: KEY=VALUE lines the guest's php-fpm gets as its environment (/etc/securecore/
# guest.env). Only for test images: a product image must not carry a site's secrets (#72).
set -eu
[ $# -eq 2 ] || [ $# -eq 3 ] || { echo "usage: $0 <image> <out.ext4> [<env-file>]" >&2; exit 2; }
image=$1 out=$2 env=${3:-}
stage=$(mktemp -d "${TMPDIR:?set TMPDIR to a folder of your own}/guest-image.XXXXXX")
trap 'find "$stage" -mindepth 1 -delete; rmdir "$stage"' EXIT
c=$(docker create "$image")
docker export "$c" | tar -x -C "$stage"
docker rm "$c" >/dev/null
[ -x "$stage/usr/local/bin/securecore-fpm" ] && [ -L "$stage/sbin/securecore-init" ] \
  || { echo "$0: $image is not a guest image (no securecore-fpm or /sbin/securecore-init)" >&2; exit 1; }
if [ -n "$env" ]; then
  cp "$env" "$stage/etc/securecore/guest.env"
  chmod 600 "$stage/etc/securecore/guest.env"
fi
# Sized to the contents plus 30 % and 64 MiB; read-only in the VM, so no journal.
mb=$(( $(du -sm "$stage" | cut -f1) * 13 / 10 + 64 ))
rm -f "$out.new"
mke2fs -q -F -t ext4 -b 4096 -m 0 -O ^has_journal -E root_owner=0:0 -d "$stage" "$out.new" "${mb}M"
mv -f "$out.new" "$out"
echo "$out: $mb MiB from $image ($(sha256sum "$out" | cut -d' ' -f1))"
