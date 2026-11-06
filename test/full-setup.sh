#!/bin/sh
# install.sh's full setup, tested like a user, each scenario in its own throwaway container:
#   empty        debian:12 with no PHP at all, an empty folder, install.sh --yes
#   interactive  the same, answering every question on a terminal (the transcript to read)
#   nopcntl      the official WordPress image: a system PHP without pcntl
# A release built from this tree (scripts/release-layout.sh) plus the mirrored PHP builds
# (scripts/mirror-php.sh, linux-x64) is served from a small php -S container on a private
# Docker network, standing in for securecore-releases. Exits non-zero on any failure.
#   DOCKER_CONTEXT=colima test/full-setup.sh [scenario ...]
set -u
cd "$(dirname "$0")/.." || exit 1
scenarios=${*:-empty interactive nopcntl}
out=.tmp/full-setup
rel=$out/release
mkdir -p "$out"
find "$rel" -mindepth 1 -delete 2>/dev/null || true
version=0.1.0-canary-full
TMPDIR=$PWD/.tmp scripts/release-layout.sh "$version" "v$version" "$(git rev-parse HEAD)" canary "$rel" >/dev/null || { echo "FAIL release layout"; exit 1; }
# PHP builds: mirrored once into .tmp/mirror-cache, then reused (they are ~42 MB).
cache=.tmp/mirror-cache
[ -f "$cache/php.json" ] || scripts/mirror-php.sh "$cache" "" linux-x64 || { echo "FAIL mirror"; exit 1; }
cp -R "$cache/php" "$cache/php.json" "$rel/"

net=securecore-full-$$
docker network create "$net" >/dev/null || exit 1
cleanup() {
  for c in $(docker ps -aq --filter "label=securecore-full=$$"); do docker rm -f "$c" >/dev/null 2>&1; done
  docker network rm "$net" >/dev/null 2>&1
}
trap cleanup EXIT
put() { COPYFILE_DISABLE=1 tar --no-xattrs -C "$2" -cf - "$3" | docker exec -i "$1" tar -xf - -C "$4"; }

docker run -d --label "securecore-full=$$" --network "$net" --network-alias release --name "release-$$" \
  php:8.3-cli sh -c 'mkdir -p /release && exec php -S 0.0.0.0:8099 -t /release' >/dev/null
sleep 1
put "release-$$" "$rel" . /release || { echo "FAIL could not copy the release into the server container"; exit 1; }
docker exec "release-$$" sh -c 'test -f /release/php.json && test -f /release/install.sh' || { echo "FAIL release server is not serving the release"; exit 1; }

fails=0
for s in $scenarios; do
  case $s in nopcntl) image=wordpress:php8.3-fpm ;; *) image=debian:12 ;; esac
  c=scenario-$s-$$
  docker run -d --label "securecore-full=$$" --network "$net" --name "$c" --entrypoint sleep "$image" infinity >/dev/null
  # The machine's own tools (a stand-in user's laptop or server), not SecureCore's.
  docker exec "$c" sh -c 'command -v curl >/dev/null && command -v script >/dev/null || { apt-get update -qq && apt-get install -y -qq curl ca-certificates bsdutils >/dev/null 2>&1; }'
  docker exec "$c" mkdir -p /probe
  put "$c" test setup-scenario.sh /root
  put "$c" . probe /tmp && docker exec "$c" sh -c 'mkdir -p /probe/securecore-probe && cp /tmp/probe/* /probe/securecore-probe/'
  put "$c" manifests securecore-probe.json /probe
  echo "=== $s ($image)"
  docker exec -e FROM=http://release:8099 "$c" sh /root/setup-scenario.sh "$s" > "$out/$s.log" 2>&1; rc=$?
  cat "$out/$s.log"
  [ "$rc" = 0 ] || fails=$((fails + 1))
done
[ "$fails" = 0 ] && echo "full setup: all scenarios passed" || echo "full setup: $fails scenario(s) failed"
[ "$fails" = 0 ]
