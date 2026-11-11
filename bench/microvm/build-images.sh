#!/bin/sh
# Builds the microVM's disks (addiscorp/securecore#68) from the test/ext-layer1.sh stack (run that
# first; project sc-mvm here), into .tmp/mvm/:
#   rootfs.ext4   guest.Dockerfile on top of the stack's php-layer1 image, read-only in the VM,
#                 shared by every site; /etc/securecore-guest.env is the php container's
#                 WORDPRESS_* environment with the DB host pointed at the guest's loopback
#   site.ext4     the stack's site volume (WordPress core, plugins, themes, wp-config.php,
#                 securecore.json) without wp-content/uploads, read-only in the VM
#   uploads.ext4  wp-content/uploads, the one writable disk
# The site gets test/ext/securecore-status.php as sc-status.php and test/ext-vault.sh's core
# probe first (both the volume, which nginx serves static files from, and the image), so the
# bench can ask the guest's extension what it enforces. Needs Docker (root) and mke2fs.
#   bench/microvm/build-images.sh
set -eu
cd "$(dirname "$0")/../.."
project=${SECURECORE_EXT_PROJECT:-sc-mvm}
out=$PWD/.tmp/mvm
mkdir -p "$out"
php=$(docker compose -p "$project" ps -q php)
[ -n "$php" ] || { echo "no php container in project $project: run test/ext-layer1.sh first" >&2; exit 1; }
docker cp test/ext/securecore-status.php "$php:/var/www/html/sc-status.php"
docker cp test/ext/vault/routine.php "$php:/var/www/html/sc-vault-routine.php"
docker cp test/ext/vault/core.php "$php:/var/www/html/sc-vault-core.php"
docker cp bench/microvm/sc-perf.php "$php:/var/www/html/sc-perf.php"
docker cp bench/microvm/sc-front.php "$php:/var/www/html/sc-front.php"

# ext4 image of a directory: sized to its contents + 30% + 64 MiB, built as root so owners stay.
pack() {
  mb=$(( $(du -sm "$1" | cut -f1) * 13 / 10 + 64 ))
  rm -f "$2"
  truncate -s "${mb}M" "$2"
  mke2fs -q -t ext4 -E root_owner=0:0 -d "$1" -F "$2"
  echo "$(basename "$2"): ${mb} MiB from $(du -sm "$1" | cut -f1) MiB"
}
fresh() { mkdir -p "$1"; find "$1" -mindepth 1 -delete; }

docker build -q -f bench/microvm/guest.Dockerfile --build-arg BASE="$project-php" -t "$project-guest" . >/dev/null
fresh "$out/root"
c=$(docker create "$project-guest")
docker export "$c" | tar -x -C "$out/root"
docker rm "$c" >/dev/null
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$php" | grep '^WORDPRESS_' \
  | sed 's|^WORDPRESS_DB_HOST=.*|WORDPRESS_DB_HOST=127.0.0.1:3306|' > "$out/root/etc/securecore-guest.env"
chmod 600 "$out/root/etc/securecore-guest.env"
grep -q '^WORDPRESS_DB_HOST=127.0.0.1:3306$' "$out/root/etc/securecore-guest.env"
pack "$out/root" "$out/rootfs.ext4"

fresh "$out/site"
fresh "$out/uploads"
docker run --rm -v "${project}_wp:/s:ro" --entrypoint tar "$project-guest" -C /s -cf - . | tar -x -C "$out/site"
if [ -d "$out/site/wp-content/uploads" ]; then
  (cd "$out/site/wp-content/uploads" && tar -cf - .) | tar -x -C "$out/uploads"
  find "$out/site/wp-content/uploads" -mindepth 1 -delete
fi
chown 33:33 "$out/uploads"
pack "$out/site" "$out/site.ext4"
pack "$out/uploads" "$out/uploads.ext4"
find "$out/root" "$out/site" "$out/uploads" -mindepth 1 -delete
rmdir "$out/root" "$out/site" "$out/uploads"
