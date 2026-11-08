#!/bin/sh
# Build one cell of the extension's release matrix (addiscorp/securecore#53, E8) on this Docker
# host's architecture, in that cell's official php image (scripts/ext-cells.txt), and write it
# under its release names:
#   <out>/securecore-php<php>-<ts>-linux-<arch>.so
#   <out>/securecore-fpm-linux-<arch>
# The release workflow and a local run use this same script.
#   scripts/ext-build.sh <php> <ts> <out-dir>        e.g. scripts/ext-build.sh 8.3 nts .tmp/ext-dist
set -eu
[ $# -eq 3 ] || { echo "usage: $0 <php> <ts> <out-dir>" >&2; exit 2; }
php=$1 ts=$2 out=$3
root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
image=$("$root/scripts/ext-cells.sh" image "$php" "$ts")
arch=$("$root/scripts/ext-cells.sh" arch)
mkdir -p "$out"
work=$(mktemp -d "${TMPDIR:-/tmp}/ext-build.XXXXXX")
trap 'find "$work" -mindepth 1 -delete; rmdir "$work"' EXIT
docker build -f "$root/docker/ext.Dockerfile" --build-arg "PHP_IMAGE=$image" --target dist -o "$work" "$root"
cp "$work/securecore.so" "$out/securecore-php$php-$ts-linux-$arch.so"
cp "$work/securecore-fpm" "$out/securecore-fpm-linux-$arch"
chmod 644 "$out/securecore-php$php-$ts-linux-$arch.so"
chmod 755 "$out/securecore-fpm-linux-$arch"
echo "$out: securecore-php$php-$ts-linux-$arch.so securecore-fpm-linux-$arch (built in $image)"
