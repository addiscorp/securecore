#!/bin/sh
# The microVM's capture of the host's PHP against real hosts (addiscorp/securecore#101): a Debian
# (dpkg), an Alpine (apk) and a Fedora (rpm) container, each with its distribution's own php-fpm
# installed by its package manager, run `securecore-fpm --check-capture` (the capture and its
# validation alone, as a microVM start makes them). Each must:
#   - capture php-fpm, its extensions and their libraries, checked against that package manager's
#     own records (dpkg's md5sums, apk's installed database, rpm's file digests);
#   - refuse once one packaged extension (opcache.so) has a byte appended, naming the file and the
#     package whose record it no longer matches;
#   - refuse an extension that isn't root's alone, and a config that loads a .so from outside
#     PHP's own folders, each naming the file.
# Needs Docker (pulls debian:trixie-slim, alpine:3.22 and fedora:42, installs php-fpm from each
# distribution's mirrors) and a Linux securecore-fpm (SECURECORE_FPM=, default
# .target/release/securecore-fpm; it runs inside the containers, so a static one: docker/
# ext.Dockerfile's build-init). Exits non-zero on any failure.
set -u
cd "$(dirname "$0")/.." || exit 1
fpm=${SECURECORE_FPM:-$PWD/.target/release/securecore-fpm}
[ -x "$fpm" ] || { echo "FAIL no securecore-fpm at $fpm"; exit 1; }
dir=$PWD/.tmp/ext-capture
mkdir -p "$dir"
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }
has() { if grep -qF -- "$2" "$1"; then pass "$3"; else fail "$3" "no '$2' in $1: $(tr '\n' ' ' < "$1" | cut -c1-400)"; fi; }

# distro <name> <image> <install> <kind> <scan folder>: installs php-fpm, then captures, tampers
# and captures again.
distro() {
  name=$1 image=$2 install=$3 kind=$4 ini=$5
  # shellcheck disable=SC2016 # expanded in the container
  docker run --rm -e "ini=$ini" -v "$fpm:/sc/securecore-fpm:ro" "$image" sh -c "$install > /tmp/install.log 2>&1 || { tail -5 /tmp/install.log; exit 3; }"'
    f=$(ls /usr/sbin/php-fpm* | head -1)
    so=$(find / -xdev -name opcache.so -path "*php*" 2>/dev/null | head -1)
    echo "fpm=$f so=$so"
    /sc/securecore-fpm --check-capture --php-fpm "$f"; echo "clean rc=$?"
    cp -p "$so" /tmp/opcache.keep; printf x >> "$so"
    /sc/securecore-fpm --check-capture --php-fpm "$f" 2>&1; echo "tampered rc=$?"
    cat /tmp/opcache.keep > "$so"; touch -r /tmp/opcache.keep "$so"
    chown 65534 "$so"
    /sc/securecore-fpm --check-capture --php-fpm "$f" 2>&1; echo "owner rc=$?"
    chown 0:0 "$so"
    mkdir -p /opt/evil && cp "$so" /opt/evil/x.so
    echo "extension=/opt/evil/x.so" > "$ini/zz-evil.ini"
    echo "ini=$ini"
    /sc/securecore-fpm --check-capture --php-fpm "$f" 2>&1; echo "outside rc=$?"' > "$dir/$name.log" 2>&1
  echo "  $name: $(head -2 "$dir/$name.log" | tail -1 | cut -c1-300)"
  has "$dir/$name.log" "clean rc=0" "$name: the distribution's php-fpm is captured"
  has "$dir/$name.log" "checked against $kind (" "$name: checked against $kind's records"
  so=$(sed -n 's/.* so=//p' "$dir/$name.log" | head -1)
  has "$dir/$name.log" "tampered rc=1" "$name: an extension changed after its package installed it is refused"
  has "$dir/$name.log" "can't be captured: $so: its bytes don't match what $kind recorded" "$name: naming $so and $kind's record"
  has "$dir/$name.log" "owner rc=1" "$name: an extension that isn't root's alone is refused"
  has "$dir/$name.log" "can't be captured: $so: the file is owned by 65534" "$name: naming it"
  has "$dir/$name.log" "outside rc=1" "$name: a config that loads a .so from outside PHP's folders is refused"
  has "$dir/$name.log" "zz-evil.ini:1: extension = /opt/evil/x.so loads native code from outside the captured set" "$name: naming the config and its line"
}

distro debian debian:trixie-slim "apt-get update && apt-get install -y --no-install-recommends php8.4-fpm php8.4-opcache" dpkg /etc/php/8.4/fpm/conf.d
distro alpine alpine:3.22 "apk add --no-cache php84-fpm php84-opcache" apk /etc/php84/conf.d
distro fedora fedora:42 "dnf install -y -q php-fpm php-opcache" rpm /etc/php.d

if [ "$fails" -eq 0 ]; then echo "all ext-capture checks passed"; else echo "$fails check(s) failed"; fi
[ "$fails" -eq 0 ]
