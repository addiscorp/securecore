#!/bin/sh
# PID 1 in the microVM guest (addiscorp/securecore#68). The guest has no network device: lo
# only, and two vsock ends.
#   vda  root (this image), read-only           vdb  the site, read-only, at /var/www/html
#   vdc  the site's uploads, read-write, at /var/www/html/wp-content/uploads
#   in   vsock 9000 → guest-forward → php-fpm on 127.0.0.1:9000
#   out  mysqlnd's connect to 127.0.0.1:3306 is a vsock connect to the host (CID 2) port 3306
#        (libsc-vsock-connect.so, #70), which the host points at MySQL. Nothing else leaves
#        the guest.
# Kernel arguments: sc.time=<epoch> (Firecracker has no RTC), sc.ext=0 (php-fpm without the
# extension, for the latency comparison), sc.layer1=1 (start php-fpm through securecore-fpm,
# i.e. gelada inside the guest too).
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs none /dev
mount -t tmpfs -o mode=1777 tmpfs /tmp
mount -t tmpfs tmpfs /run
# The database path (#70), sc.db=:
#   vsock  (default) php-fpm runs with libsc-vsock-connect.so, so mysqlnd's connect to
#          127.0.0.1:3306 is a vsock connect to the host: no process in the guest between PHP and
#          vsock. gelada's seccomp refuses AF_VSOCK sockets, so with sc.layer1=1 it is fwd.
#   fwd    securecore-microvm guest-forward: loopback 3306 → vsock, one process, no fork.
#   socat  the #68 spike's path (a socat fork per connection), for comparison.
#   tap    for comparison only: no vsock for the DB; eth0 gets sc.net=<addr/prefix> and
#          WordPress connects to sc.dbhost=<ip:port> over the (bridged) network.
# The FastCGI path, sc.fpm=: fwd (default; guest-forward, vsock 9000 → 127.0.0.1:9000) or socat.
ext=1 layer1=0 db=vsock fpm=fwd net="" dbhost=""
# shellcheck disable=SC2013 # the command line is one line of space-separated words
for kv in $(cat /proc/cmdline); do
  case $kv in
    sc.time=*) date -s "@${kv#sc.time=}" >/dev/null ;;
    sc.ext=*) ext=${kv#sc.ext=} ;;
    sc.layer1=*) layer1=${kv#sc.layer1=} ;;
    sc.db=*) db=${kv#sc.db=} ;;
    sc.fpm=*) fpm=${kv#sc.fpm=} ;;
    sc.net=*) net=${kv#sc.net=} ;;
    sc.dbhost=*) dbhost=${kv#sc.dbhost=} ;;
  esac
done
[ "$db" = vsock ] && [ "$layer1" = 1 ] && db=fwd
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
# socat's -t 0: when php-fpm closes its end, close the vsock end at once. socat's default waits
# 0.5 s for the other direction first, and nginx (no FastCGI keepalive) waits for that close:
# +500 ms on every request (measured). nodelay on the TCP ends, so no round trip waits out a
# delayed ACK. guest-forward closes each direction as soon as its source ends, and sets nodelay.
case $fpm in
  socat) socat -t 0 VSOCK-LISTEN:9000,fork,reuseaddr TCP:127.0.0.1:9000,nodelay & ;;
  *) securecore-microvm guest-forward --vsock-to-tcp 9000=127.0.0.1:9000 & ;;
esac
preload=""
case $db in
  vsock) preload=/usr/local/lib/libsc-vsock-connect.so ;;
  fwd) securecore-microvm guest-forward --tcp-to-vsock 127.0.0.1:3306=3306 & ;;
  socat) socat -t 0 TCP-LISTEN:3306,bind=127.0.0.1,fork,reuseaddr,nodelay VSOCK-CONNECT:2:3306 & ;;
  tap)
    ip link set eth0 up
    ip addr add "$net" dev eth0
    export WORDPRESS_DB_HOST="$dbhost"
    ;;
esac
echo "securecore-init: ext=$ext layer1=$layer1 db=$db fpm=$fpm clocksource=$(cat /sys/devices/system/clocksource/clocksource0/current_clocksource) up $(cut -d' ' -f1 /proc/uptime)s"
# php-fpm's log (and the extension's audit lines) go to the host over vsock port 1514, which the
# driver appends to <dir>/guest.log: the serial console is an emulated 8250, and writing a few
# lines per request to it costs hundreds of milliseconds a page.
fpm_cmd="php-fpm -F"
[ "$layer1" = 1 ] && fpm_cmd="securecore-fpm --config /var/www/html/securecore.json"
if [ -n "$preload" ]; then
  # shellcheck disable=SC2086 # fpm_cmd is a command and its arguments
  LD_PRELOAD=$preload SC_VSOCK_PORTS=3306 $fpm_cmd 2>&1 | socat -u - VSOCK-CONNECT:2:1514
else
  # shellcheck disable=SC2086 # as above
  $fpm_cmd 2>&1 | socat -u - VSOCK-CONNECT:2:1514
fi
# PID 1 exiting panics the kernel, and panic=1 reboot=k stops the VM: no php-fpm, no VM.
echo "securecore-init: php-fpm exited"
exit 1
