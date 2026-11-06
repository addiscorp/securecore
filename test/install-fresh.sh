#!/bin/sh
# Run test/fresh-site.sh in a plain debian:12 container (a stand-in machine, nothing from this
# repo's docker/ stack), with a locally built release served from /release. The container
# is removed afterwards. Exits non-zero on failure.
#   DOCKER_CONTEXT=colima test/install-fresh.sh
set -u
cd "$(dirname "$0")/.." || exit 1
out=.tmp/install-fresh
rel=$out/release
mkdir -p "$out"
find "$rel" -mindepth 1 -delete 2>/dev/null || true
version=0.1.0-canary-fresh
TMPDIR=$PWD/.tmp scripts/release-layout.sh "$version" "v$version" "$(git rev-parse HEAD)" canary "$rel" >/dev/null || { echo "FAIL release layout"; exit 1; }

name=securecore-fresh-$$
docker run -d --name "$name" debian:12 sleep infinity >/dev/null || exit 1
trap 'docker rm -f "$name" >/dev/null 2>&1' EXIT
docker exec "$name" mkdir -p /release
COPYFILE_DISABLE=1 tar --no-xattrs -C "$rel" -cf - . | docker exec -i "$name" tar -xf - -C /release
COPYFILE_DISABLE=1 tar --no-xattrs -C test -cf - fresh-site.sh | docker exec -i "$name" tar -xf - -C /root
docker exec "$name" mkdir -p /probe
COPYFILE_DISABLE=1 tar --no-xattrs -C probe -cf - . | docker exec -i "$name" tar -xf - -C /probe
COPYFILE_DISABLE=1 tar --no-xattrs -C manifests -cf - securecore-probe.json | docker exec -i "$name" tar -xf - -C /probe
docker exec "$name" sh /root/fresh-site.sh > "$out/fresh-site.log" 2>&1; rc=$?
cat "$out/fresh-site.log"
exit "$rc"
