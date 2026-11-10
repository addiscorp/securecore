#!/bin/sh
# PID 1 in the microVM guest (addiscorp/securecore#68). The guest has no network device: lo
# only, and two vsock ends.
#   vda  root (this image), read-only           vdb  the site, read-only, at /var/www/html
#   vdc  the site's uploads, read-write, at /var/www/html/wp-content/uploads
#   in   vsock 9000 → php-fpm on 127.0.0.1:9000
#   out  127.0.0.1:3306 → vsock to the host (CID 2) port 3306, which the host driver forwards
#        to MySQL. Nothing else leaves the guest.
# Kernel arguments: sc.time=<epoch> (Firecracker has no RTC), sc.ext=0 (php-fpm without the
# extension, for the latency comparison), sc.layer1=1 (start php-fpm through securecore-fpm,
# i.e. gelada inside the guest too).
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs none /dev
mount -t tmpfs -o mode=1777 tmpfs /tmp
mount -t tmpfs tmpfs /run
ext=1 layer1=0
# shellcheck disable=SC2013 # the command line is one line of space-separated words
for kv in $(cat /proc/cmdline); do
  case $kv in
    sc.time=*) date -s "@${kv#sc.time=}" >/dev/null ;;
    sc.ext=*) ext=${kv#sc.ext=} ;;
    sc.layer1=*) layer1=${kv#sc.layer1=} ;;
  esac
done
mount -o ro,noload /dev/vdb /var/www/html
mount /dev/vdc /var/www/html/wp-content/uploads
[ -d /var/www/html/wp-content/cache ] && mount -t tmpfs -o uid=33,gid=33 tmpfs /var/www/html/wp-content/cache
ip link set lo up
# The site's environment (DB name/user, the vault's env sources), written by build-images.sh.
set -a
# shellcheck disable=SC1091 # written into the image by build-images.sh
. /etc/securecore-guest.env
set +a
[ "$ext" = 0 ] && export PHP_INI_SCAN_DIR=/usr/local/etc/php/conf.d-noext
# -t 0: when php-fpm closes its end, close the vsock end at once. socat's default waits 0.5 s
# for the other direction first, and nginx (no FastCGI keepalive) waits for that close: +500 ms
# on every request (measured). nodelay on the TCP ends, so no round trip waits out a delayed ACK.
socat -t 0 VSOCK-LISTEN:9000,fork,reuseaddr TCP:127.0.0.1:9000,nodelay &
socat -t 0 TCP-LISTEN:3306,bind=127.0.0.1,fork,reuseaddr,nodelay VSOCK-CONNECT:2:3306 &
echo "securecore-init: ext=$ext layer1=$layer1 up $(cut -d' ' -f1 /proc/uptime)s"
# php-fpm's log (and the extension's audit lines) go to the host over vsock port 1514, which the
# driver appends to <dir>/guest.log: the serial console is an emulated 8250, and writing a few
# lines per request to it costs hundreds of milliseconds a page.
if [ "$layer1" = 1 ]; then
  securecore-fpm --config /var/www/html/securecore.json 2>&1 | socat -u - VSOCK-CONNECT:2:1514
else
  php-fpm -F 2>&1 | socat -u - VSOCK-CONNECT:2:1514
fi
# PID 1 exiting panics the kernel, and panic=1 reboot=k stops the VM: no php-fpm, no VM.
echo "securecore-init: php-fpm exited"
exit 1
