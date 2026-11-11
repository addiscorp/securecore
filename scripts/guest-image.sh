#!/bin/sh
# The microVM guest's root filesystem (addiscorp/securecore#71): a Docker image built from
# docker/ext.Dockerfile's `guest` target, exported to a read-only ext4 image, rootfs.ext4, which
# securecore-fpm boots (--rootfs, or <vm-dir>/rootfs.ext4). Needs Docker and mke2fs, as root
# (the export keeps the image's owners).
#   scripts/guest-image.sh <image> <out.ext4>
# The image carries no site's settings or secrets: the launcher delivers php-fpm's environment
# in each start message (--guest-env and the vault's env names, #72).
#
# Reproducible (#80): the same image gives the same ext4, byte for byte. Every file's times are
# SOURCE_DATE_EPOCH (default 0), owners are the image's numeric ids (never names looked up on
# this host), the filesystem's UUID and directory hash seed are fixed, mke2fs's own clock is
# SOURCE_DATE_EPOCH (E2FSPROGS_FAKE_TIME), and the size comes from the contents alone.
# scripts/guest-build.sh builds the image and this disk for a release.
set -eu
[ $# -eq 2 ] || { echo "usage: $0 <image> <out.ext4>" >&2; exit 2; }
image=$1 out=$2
epoch=${SOURCE_DATE_EPOCH:-0}
# Fixed, and only ever this guest's: the image's identity is its sha256, not a random UUID.
UUID=5ec0c0de-0080-4000-8000-000000000080
stage=$(mktemp -d "${TMPDIR:?set TMPDIR to a folder of your own}/guest-image.XXXXXX")
trap 'find "$stage" -mindepth 1 -delete; rmdir "$stage"' EXIT
c=$(docker create "$image")
docker export "$c" | tar -x --numeric-owner -C "$stage"
docker rm "$c" >/dev/null
[ -x "$stage/usr/local/bin/securecore-fpm" ] && [ -L "$stage/sbin/securecore-init" ] \
  || { echo "$0: $image is not a guest image (no securecore-fpm or /sbin/securecore-init)" >&2; exit 1; }
find "$stage" -exec touch -h -d "@$epoch" {} +
# Sized from the contents' own sizes (each file in whole 4 KiB blocks, a block for every other
# entry), never from this host's filesystem: plus 10 % and 32 MiB for the inode tables, block
# groups and extent blocks. Read-only in the VM, so no journal and no reserved blocks.
mb=$(find "$stage" -printf '%y %s\n' | awk '{ b += ($1 == "f") ? int(($2 + 4095) / 4096) : 1 } END { printf "%d", b * 4096 / 1048576 * 1.1 + 32 }')
rm -f "$out.new"
E2FSPROGS_FAKE_TIME=$epoch mke2fs -q -F -t ext4 -b 4096 -m 0 -O ^has_journal -U "$UUID" \
  -E "root_owner=0:0,hash_seed=$UUID,lazy_itable_init=0,nodiscard" -d "$stage" "$out.new" "${mb}M"
mv -f "$out.new" "$out"
echo "$out: $mb MiB from $image ($(sha256sum "$out" | cut -d' ' -f1))"
