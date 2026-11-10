#!/bin/sh
# Builds mirab's guest kernel recipe (mirab scripts/build-vm-guest.sh: Linux 6.12.112 from
# kernel.org, sha256-pinned, allnoconfig + mirab's guest-agent/kernel-x86_64.config) with
# kernel-securecore.config on top, so gelada works inside the guest. Writes .tmp/mvm/vmlinux-sc.
# Needs Docker and jq.   bench/microvm/kernel.sh <mirab's kernel-x86_64.config>
set -eu
cd "$(dirname "$0")/../.."
mirab_config=$1
out=.tmp/mvm
mkdir -p "$out"
cat "$mirab_config" bench/microvm/kernel-securecore.config > "$out/kernel-sc.config"
v=$(jq -r .linux bench/microvm/mirab-kernel.json)
s=$(jq -r .linux_sha256 bench/microvm/mirab-kernel.json)
name=securecore-mvm-kernel
docker rm -f "$name" >/dev/null 2>&1 || true
docker run --name "$name" -v "$PWD/$out/kernel-sc.config:/kernel.config:ro" debian:trixie-slim sh -euc "
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    build-essential flex bison bc curl xz-utils ca-certificates libelf-dev >/dev/null
  cd /root && curl -fsSL -o linux.tar.xz https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$v.tar.xz
  echo '$s  linux.tar.xz' | sha256sum -c - >/dev/null
  tar -xJf linux.tar.xz && cd linux-$v
  KCONFIG_ALLCONFIG=/kernel.config make -s ARCH=x86_64 allnoconfig
  missing=''
  for o in \$(grep -o '^CONFIG_[A-Z0-9_]*=y' /kernel.config | cut -d= -f1); do
    grep -q \"^\$o=y\" .config || missing=\"\$missing \$o\"
  done
  [ -z \"\$missing\" ] || { echo \"kernel config: did not stick:\$missing\" >&2; exit 1; }
  grep -q '^CONFIG_LSM=\"landlock\"' .config
  make -s ARCH=x86_64 -j\$(nproc) vmlinux
  cp vmlinux /vmlinux"
docker cp "$name:/vmlinux" "$out/vmlinux-sc"
docker rm "$name" >/dev/null
echo "vmlinux-sc $(sha256sum "$out/vmlinux-sc" | cut -d' ' -f1)"
