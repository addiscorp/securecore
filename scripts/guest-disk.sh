#!/bin/sh
# The guest disk's maker (addiscorp/securecore#80), run by scripts/guest-image.sh inside
# docker/ext.Dockerfile's `guest-tools` image (pinned tar, mke2fs and gzip; never the host's):
#   docker export <guest> | docker run -i … guest-tools guest-disk <out.ext4>
# reads the guest's filesystem as a tar on stdin and writes <out.ext4> (a bind-mounted folder).
#
# Reproducible: the same tar gives the same disk, byte for byte. Owners are the tar's numeric ids,
# every file's times are SOURCE_DATE_EPOCH (default 0), the filesystem's UUID and directory hash
# seed are fixed, mke2fs's own clock is SOURCE_DATE_EPOCH, and the size comes from the contents'
# own sizes.
set -eu
[ $# -eq 1 ] || { echo "usage: … | $0 <out.ext4>" >&2; exit 2; }
out=$1
epoch=${SOURCE_DATE_EPOCH:-0}
export SOURCE_DATE_EPOCH="$epoch"
# Fixed, and only ever this guest's: the image's identity is its sha256, not a random UUID.
UUID=5ec0c0de-0080-4000-8000-000000000080
stage=/guest-root
mkdir "$stage"
tar -x --numeric-owner -C "$stage"
[ -x "$stage/sc/securecore-init" ] && [ -d "$stage/sc/php" ] && [ -d "$stage/sc/conf" ] \
  || { echo "$0: this is not a guest base (no /sc/securecore-init, /sc/php or /sc/conf)" >&2; exit 1; }
find "$stage" -exec touch -h -d "@$epoch" {} +
# Each file in whole 4 KiB blocks and a block for every other entry, plus 10 % and 32 MiB for the
# inode tables, block groups and extent blocks. Read-only in the VM: no journal, no reserved blocks.
mb=$(find "$stage" -printf '%y %s\n' | awk '{ b += ($1 == "f") ? int(($2 + 4095) / 4096) : 1 } END { printf "%d", b * 4096 / 1048576 * 1.1 + 32 }')
rm -f "$out.new"
E2FSPROGS_FAKE_TIME=$epoch mke2fs -q -F -t ext4 -b 4096 -m 0 -O ^has_journal -U "$UUID" \
  -E "root_owner=0:0,hash_seed=$UUID,lazy_itable_init=0,nodiscard" -d "$stage" "$out.new" "${mb}M"
mv -f "$out.new" "$out"
echo "$out: $mb MiB, $(mke2fs -V 2>&1 | head -n 1)"
