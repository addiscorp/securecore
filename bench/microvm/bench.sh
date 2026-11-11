#!/bin/sh
# Measurements for layer 1 as a Firecracker microVM (addiscorp/securecore#68, docs/layer1-microvm.md),
# on the test/ext-layer1.sh stack (project sc-mvm, port 8095) after fetch.sh and build-images.sh.
# Runs as root (Firecracker, docker). The microVM's PHP is reached through a second nginx
# (sc-mvm-mvmweb, port 8096, bench/microvm/nginx.conf) on the stack's network, serving static
# files from the same site volume; MySQL is the stack's db container, forwarded over vsock.
#   bench/microvm/bench.sh boot [n]        cold boots: driver timings + first front page via nginx
#   bench/microvm/bench.sh snapshot [n]    warm a VM, snapshot it, then n restores, timed the same way
#   bench/microvm/bench.sh memory          host memory per VM (firecracker RSS/PSS, MemAvailable)
#   bench/microvm/bench.sh latency [n]     front-page p50: host php-fpm vs the microVM, extension
#                                          off on both (bench/layer1.sh's method), n rounds
#   bench/microvm/bench.sh ext             the extension in the guest: status, the vault probe,
#                                          layer 3's isolated plugin, vs the host stack
#   bench/microvm/bench.sh fallback        detect / launch with and without /dev/kvm
#   bench/microvm/bench.sh dbpath [n]      #70: sc-perf.php (connect, query, CPU) for every
#                                          database path candidate, n samples each
#   bench/microvm/bench.sh breakdown       #70: empty / 70 KB / front-page p50 and time inside
#                                          PHP, host php-fpm vs the microVM
# KERNEL=<vmlinux> picks the guest kernel (default .tmp/mvm/vmlinux, mirab's). Results:
# .tmp/bench/mvm/. Exits non-zero on any failure.
# The database path (#70) for every command, by environment:
#   MVM_DB=vsock|fwd|socat|tap   the guest side (init.sh's sc.db; default vsock)
#   MVM_FPM=fwd|socat            the guest's FastCGI forwarder (default fwd)
#   MVM_HOST=unix|tcp|splice     the host side: unix (default) points Firecracker's v.sock_3306
#                                straight at MariaDB's unix socket; tcp is the driver's TCP hop
#                                (the spike's); splice is that hop with splice(2)
#   MVM_DB=tap needs no MVM_HOST: a tap device on the stack's bridge, removed on exit.
# The spike's path is MVM_DB=socat MVM_FPM=socat MVM_HOST=tcp.
set -eu
cd "$(dirname "$0")/../.."
what=${1:-}
n=${2:-5}
project=sc-mvm port=8095 vport=8096
mvm=$PWD/.tmp/mvm
run=$mvm/run
res=.tmp/bench/mvm
bin=${SECURECORE_MICROVM:-$PWD/.target/release/securecore-microvm}
kernel=${KERNEL:-$mvm/vmlinux}
OHA=ghcr.io/hatoo/oha@sha256:3ec3dbf549ea197793482d47a6324797411406bbf438c2fe8b91f244ec641a2f # oha 1.16.0
ini=/usr/local/etc/php/conf.d/securecore.ini
conf=/var/www/html/securecore.json
mkdir -p "$run" "$res"
compose() {
  SECURECORE_PORT=$port docker compose -f docker/compose.yml -f docker/compose.ext.yml \
    -f docker/compose.ext-layer1.yml -p "$project" "$@"
}
die() { echo "FAIL $*" >&2; exit 1; }
now_ns() { date +%s%N; }
dbip() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(compose ps -q db)"; }
code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: 127.0.0.1:$port" "http://127.0.0.1:$1$2"; }
oha() { docker run --rm --network "${project}_default" "$OHA" --no-tui --output-format json -H "Host: 127.0.0.1:$port" "$@"; }
median() { sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }

web_up() {
  docker rm -f "$project-mvmweb" >/dev/null 2>&1 || true
  docker run -d --name "$project-mvmweb" --network "${project}_default" --network-alias mvmweb \
    -p "127.0.0.1:$vport:80" -v "${project}_wp:/var/www/html:ro" -v "$run:/run/mvm" \
    -v "$PWD/bench/microvm/nginx.conf:/etc/nginx/conf.d/default.conf:ro" "$project-web" >/dev/null
}

tap=sc70tap0
tap_down() { ip link show "$tap" >/dev/null 2>&1 && ip link del "$tap"; return 0; }
# The driver's options for the database path (MVM_DB, MVM_FPM, MVM_HOST above).
db_opts() {
  d=${MVM_DB:-vsock} h=${MVM_HOST:-unix}
  set -- --arg "sc.db=$d" --arg "sc.fpm=${MVM_FPM:-fwd}"
  if [ "$d" = tap ]; then
    # The guest on the stack's own bridge, at the subnet's .250, reaching the db container's IP.
    netid=$(docker network inspect -f '{{.Id}}' "${project}_default")
    subnet=$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "${project}_default")
    tap_down
    ip tuntap add dev "$tap" mode tap
    ip link set "$tap" master "br-$(echo "$netid" | cut -c1-12)"
    ip link set "$tap" up
    set -- "$@" --tap "$tap" --arg "sc.net=${subnet%.*/*}.250/${subnet#*/}" --arg "sc.dbhost=$(dbip):3306"
  else
    case $h in
      # MariaDB's socket, reached through its container's root; a product mounts the socket's
      # folder instead.
      unix) set -- "$@" --forward "3306=unix:/proc/$(docker inspect -f '{{.State.Pid}}' "$(compose ps -q db)")/root/run/mysqld/mysqld.sock" ;;
      tcp) set -- "$@" --forward "3306=$(dbip):3306" ;;
      splice) set -- "$@" --forward "3306=$(dbip):3306" --splice 1 ;;
      *) die "MVM_HOST=$h" ;;
    esac
  fi
  printf '%s\n' "$@"
}
# vm_start <name> [boot options]: starts the driver, waits for its ready line and for the first
# front page (200) through nginx. Sets DRV (driver pid), FCPID, and PAGE_MS (driver start → 200).
vm_start() {
  name=$1; shift
  opts=$(db_opts) || die "db_opts"
  t0=$(now_ns)
  # shellcheck disable=SC2086 # one option per word; no path in them has a space
  "$bin" boot --dir "$run" --firecracker "$mvm/firecracker" --kernel "$kernel" \
    --rootfs "$mvm/rootfs.ext4" --site "$mvm/site.ext4" --uploads "$mvm/uploads.ext4" \
    $opts "$@" > "$res/$name.out" 2> "$res/$name.err" &
  DRV=$!
  until grep -q '"ready"' "$res/$name.out" 2>/dev/null; do
    kill -0 "$DRV" 2>/dev/null || die "$name: driver exited: $(cat "$res/$name.err")"
    sleep 0.002
  done
  w=0
  until [ "$(code "$vport" /)" = 200 ]; do
    w=$((w + 1)); [ "$w" -lt 5000 ] || die "$name: no 200 through nginx"
    sleep 0.002
  done
  PAGE_MS=$(( ($(now_ns) - t0) / 1000000 ))
  FCPID=$(grep -o '"firecracker_pid":[0-9]*' "$res/$name.out" | cut -d: -f2)
}
vm_stop() {
  "$bin" ctl --dir "$run" quit >/dev/null; wait "$DRV" || die "driver exited non-zero"
  DRV=""
  [ "${MVM_DB:-}" != tap ] || tap_down
}
# On any exit, a VM still running (a failed step) is stopped, with its driver: a leftover VM
# skews every later measurement (#70: one left over with idle=poll took two of the four cores).
DRV=""
cleanup() {
  if [ -n "$DRV" ]; then
    "$bin" ctl --dir "$run" quit >/dev/null 2>&1 || true
    fc=$(grep -o '"firecracker_pid":[0-9]*' "$res/$name.out" 2>/dev/null | cut -d: -f2)
    [ -z "$fc" ] || kill "$fc" 2>/dev/null || true
    kill "$DRV" 2>/dev/null || true
  fi
  tap_down
}
trap cleanup EXIT
field() { grep -o "\"$1\":[0-9.]*" "$2" | cut -d: -f2; }

boot() {
  web_up
  fpm="" page=""
  i=1
  while [ "$i" -le "$n" ]; do
    vm_start "boot-$i" "$@"
    p=$(field fpm_ping_ms "$res/boot-$i.out")
    second=$(curl -s -o /dev/null -w '%{time_total}' -H "Host: 127.0.0.1:$port" "http://127.0.0.1:$vport/")
    printf 'cold boot %s: firecracker API %s ms, InstanceStart %s ms, php-fpm ping %s ms, first front page %s ms (the next one %.0f ms)\n' \
      "$i" "$(field api_ms "$res/boot-$i.out")" "$(field started_ms "$res/boot-$i.out")" "$p" "$PAGE_MS" "$(echo "$second * 1000" | bc -l)"
    fpm="$fpm $p" page="$page $PAGE_MS"
    vm_stop
    i=$((i + 1))
  done
  printf 'median: php-fpm ping %s ms, first front page %s ms (n=%s, kernel %s)\n' \
    "$(echo "$fpm" | tr ' ' '\n' | grep . | median)" "$(echo "$page" | tr ' ' '\n' | grep . | median)" "$n" "$(basename "$kernel")"
  grep -h 'securecore-init' "$run/console.log" | tail -1
}

snapshot() {
  web_up
  snap=$mvm/snap
  mkdir -p "$snap"
  vm_start snap-src
  oha -n 50 -c 1 http://mvmweb/ > "$res/snap-warm.json"
  "$bin" ctl --dir "$run" snapshot "$snap" | tee "$res/snapshot.json"
  wait "$DRV" || die "driver exited non-zero"
  du -h --apparent-size "$snap/vm.mem" "$snap/vm.snap"
  ready="" page=""
  i=1
  while [ "$i" -le "$n" ]; do
    sync; echo 3 > /proc/sys/vm/drop_caches
    vm_start "restore-$i" --restore "$snap"
    p=$(field fpm_ping_ms "$res/restore-$i.out")
    printf 'restore %s (cold page cache): snapshot loaded %s ms, php-fpm ping %s ms, first front page %s ms\n' \
      "$i" "$(field started_ms "$res/restore-$i.out")" "$p" "$PAGE_MS"
    ready="$ready $p" page="$page $PAGE_MS"
    vm_stop
    i=$((i + 1))
  done
  i=1
  while [ "$i" -le "$n" ]; do
    vm_start "restore-warm-$i" --restore "$snap"
    printf 'restore %s (warm page cache): snapshot loaded %s ms, php-fpm ping %s ms, first front page %s ms\n' \
      "$i" "$(field started_ms "$res/restore-warm-$i.out")" "$(field fpm_ping_ms "$res/restore-warm-$i.out")" "$PAGE_MS"
    vm_stop
    i=$((i + 1))
  done
  printf 'median restore (cold cache): php-fpm ping %s ms, first front page %s ms\n' \
    "$(echo "$ready" | tr ' ' '\n' | grep . | median)" "$(echo "$page" | tr ' ' '\n' | grep . | median)"
}

mem_of() {
  printf '%s: firecracker RSS %s, PSS %s; driver RSS %s\n' "$1" \
    "$(awk '/^VmRSS/ { print $2 " kB" }' "/proc/$FCPID/status")" \
    "$(awk '/^Pss:/ { print $2 " kB" }' "/proc/$FCPID/smaps_rollup")" \
    "$(awk '/^VmRSS/ { print $2 " kB" }' "/proc/$DRV/status")"
}
avail() { awk '/^MemAvailable/ { print $2 }' /proc/meminfo; }
memory() {
  web_up
  sync; echo 3 > /proc/sys/vm/drop_caches; sleep 1
  a0=$(avail)
  vm_start mem-cold
  mem_of "cold boot, idle after the first page"
  oha -n 200 -c 4 http://mvmweb/ > "$res/mem-warm.json"
  mem_of "cold boot, after 200 front pages (4 concurrent)"
  a1=$(avail)
  echo "MemAvailable drop with one VM: $(( (a0 - a1) / 1024 )) MiB (page cache dropped first)"
  vm_stop
  if [ -f "$mvm/snap/vm.mem" ]; then
    vm_start mem-restore --restore "$mvm/snap"
    mem_of "restored from snapshot, idle after the first page"
    vm_stop
  fi
}

# host php-fpm as bench/layer1.sh's "stock" side: the extension unloaded, layer 1 off.
host_stock() {
  awk '{ sub(/"isolation": "auto"/, "\"isolation\": \"off\"") } /"layer2": \{/ { s = 2 } /"layer3": \{/ { s = 3 }
    s && /"enabled": true/ { sub(/true/, "false"); s = 0 } { print }' ext/examples/wordpress.json > "$res/stock.json"
  compose exec -T php sh -c "[ -f $ini.off ] || mv $ini $ini.off"
  compose cp "$res/stock.json" "php:$conf" >/dev/null 2>&1
}
host_restore() {
  compose exec -T php sh -c "[ -f $ini ] || mv $ini.off $ini"
  compose cp ext/examples/wordpress.json "php:$conf" >/dev/null 2>&1
  compose restart php >/dev/null 2>&1
}
p50() {
  oha -n 20 -c 1 "$1" > /dev/null
  oha -n 100 -c 1 "$1" > "$res/$2.json"
  [ "$(jq -r '.statusCodeDistribution["200"] // 0' "$res/$2.json")" = 100 ] || die "$2: not all 100 responses were 200"
  jq -r '.metrics.latency_ms.p50' "$res/$2.json"
}
latency() {
  web_up
  host_stock
  host="" vm=""
  r=1
  while [ "$r" -le "$n" ]; do
    compose restart php >/dev/null 2>&1
    i=0; until [ "$(code "$port" /)" = 200 ]; do i=$((i + 1)); [ "$i" -lt 300 ] || die "host php-fpm did not come back"; sleep 0.2; done
    [ "$(compose exec -T php sh -c 'php -m | grep -cx securecore || true')" = 0 ] || die "the extension is loaded on the host side"
    a=$(p50 http://web/ "lat-host-$r")
    vm_start "lat-vm-$r" --arg sc.ext=0
    b=$(p50 http://mvmweb/ "lat-vm-$r")
    vm_stop
    printf 'round %s: host php-fpm %.2f ms   microVM %.2f ms\n' "$r" "$a" "$b"
    host="$host $a" vm="$vm $b"
    r=$((r + 1))
  done
  host_restore
  mh=$(echo "$host" | tr ' ' '\n' | grep . | median)
  mv=$(echo "$vm" | tr ' ' '\n' | grep . | median)
  printf 'median p50: host php-fpm %.2f ms, microVM %.2f ms, delta %+.2f ms\n' "$mh" "$mv" "$(echo "$mv - $mh" | bc -l)"
}

# What the extension in one php-fpm reports and enforces: status lines, the vault probe's
# verdicts (never its values), and whether isolated Contact Form 7 still renders its assets.
ext_report() {
  base=http://127.0.0.1:$1
  curl -s -H "Host: 127.0.0.1:$port" "$base/sc-status.php" | grep -E '^(loaded|layer2_mode|layer1|layer2|layer3|reload_error)=' | tr '\n' ' '
  echo
  curl -s -H "Host: 127.0.0.1:$port" "$base/sc-vault-core.php" > "$res/vault.$2"
  # shellcheck disable=SC2016 # expanded by the container's shell; compared, never printed
  pw=$(compose exec -T php sh -c 'printf %s "$WORDPRESS_DB_PASSWORD"')
  printf '  vault: db_ok=%s; DB password visible to PHP anywhere in the probe output: %s\n' \
    "$(grep -a '^db_ok=' "$res/vault.$2" | cut -d= -f2)" "$(grep -aqF "$pw" "$res/vault.$2" && echo YES || echo no)"
  printf '  vault probe scalars: %s\n' "$(grep -aE '^(getenv_db|const_db|wpdb_dbpassword)=' "$res/vault.$2" | grep -avF "$pw" | tr '\n' ' ')"
  curl -s -H "Host: 127.0.0.1:$port" "$base/" > "$res/front.$2"
  printf '  front page %s bytes; Contact Form 7 (isolated by layer 3) assets in it: %s\n' \
    "$(wc -c < "$res/front.$2")" "$(grep -c 'contact-form-7' "$res/front.$2")"
}
ext() {
  web_up
  host_restore
  sleep 2
  echo "host php-fpm (sc-mvm stack, gelada layer 1 + layers 2 and 3, examples/wordpress.json):"
  ext_report "$port" host
  compose logs --no-log-prefix --since 20s php 2>&1 | grep -aE 'layer3' | cut -c1-200 | sed 's/^\[[^]]*\] //' | sort | uniq -c | sort -rn | head -3 || true
  echo "microVM, kernel $(basename "$kernel"), boot arguments: ${*:-(none)}:"
  : > "$run/guest.log"
  vm_start ext-vm "$@"
  ext_report "$vport" vm
  vm_stop
  grep -aE 'securecore-fpm' "$run/guest.log" | head -2 || true
  grep -aE 'layer3' "$run/guest.log" | cut -c1-200 | sort | uniq -c | sort -rn | head -4 || true
}

perf() {
  host_stock
  compose restart php >/dev/null 2>&1
  w=0; until [ "$(code "$port" /)" = 200 ]; do w=$((w + 1)); [ "$w" -lt 300 ] || die "host php-fpm did not come back"; sleep 0.2; done
  web_up
  for _ in 1 2 3 4 5; do printf 'host php-fpm: %s\n' "$(curl -s -H "Host: 127.0.0.1:$port" "http://127.0.0.1:$port/sc-perf.php")"; done
  vm_start perf --arg sc.ext=0
  for _ in 1 2 3 4 5; do printf 'microVM:      %s\n' "$(curl -s -H "Host: 127.0.0.1:$port" "http://127.0.0.1:$vport/sc-perf.php")"; done
  vm_stop
  host_restore
}

# #70: sc-perf.php's connect, per-query and CPU times for each database path, n samples each,
# extension off on both sides (as perf).
perf_line() {
  for _ in $(seq "$n"); do curl -s -H "Host: 127.0.0.1:$port" "http://127.0.0.1:$1/sc-perf.php"; done > "$res/dbpath-$2.txt"
  grep -c '^connect_ms=' "$res/dbpath-$2.txt" | grep -qx "$n" || die "$2: sc-perf.php: $(head -c 300 "$res/dbpath-$2.txt")"
  m() { sed -n "s/.*$1=\([0-9.]*\).*/\1/p" "$res/dbpath-$2.txt" | median; }
  printf '%-34s connect_ms=%s query_ms=%s cpu_ms=%s clock_ms=%s stat_ms=%s mem_ms=%s (median of %s)\n' "$2" \
    "$(m connect_ms "$2")" "$(m query_ms "$2")" "$(m cpu_ms "$2")" "$(m clock_ms "$2")" "$(m stat_ms "$2")" "$(m mem_ms "$2")" "$n"
}
dbpath() {
  host_stock
  compose restart php >/dev/null 2>&1
  w=0; until [ "$(code "$port" /)" = 200 ]; do w=$((w + 1)); [ "$w" -lt 300 ] || die "host php-fpm did not come back"; sleep 0.2; done
  web_up
  perf_line "$port" "host php-fpm (TCP to the db container)"
  # How many statements one front page sends (MariaDB's Questions counter, minus the reading).
  # shellcheck disable=SC2016 # expanded by the db container's shell
  qs() { compose exec -T db sh -c 'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" -N -e "SHOW GLOBAL STATUS LIKE '\''Questions'\''"' | awk '{ print $2 }'; }
  q0=$(qs); code "$port" / >/dev/null; q1=$(qs)
  echo "one front page (host php-fpm, extension off): $((q1 - q0 - 1)) statements to MySQL"
  # db/fpm/host[/extra boot options, comma-separated]. The last two rows are diagnostics, not
  # candidates: idle=poll (the guest's vCPUs never halt: what waking a halted vCPU costs, at
  # one host core per vCPU) and one vCPU.
  for c in socat/socat/tcp fwd/fwd/tcp fwd/fwd/splice fwd/fwd/unix vsock/fwd/tcp vsock/fwd/splice \
    vsock/fwd/unix tap/fwd/- vsock/fwd/unix/--arg,idle=poll vsock/fwd/unix/--vcpus,1; do
    MVM_DB=$(echo "$c" | cut -d/ -f1) MVM_FPM=$(echo "$c" | cut -d/ -f2) MVM_HOST=$(echo "$c" | cut -d/ -f3)
    extra=$(echo "$c" | cut -s -d/ -f4 | tr , ' ')
    export MVM_DB MVM_FPM MVM_HOST
    # shellcheck disable=SC2086 # extra is a list of options
    vm_start "dbpath-$MVM_DB-$MVM_HOST" --arg sc.ext=0 $extra
    perf_line "$vport" "microVM db=$MVM_DB host=$MVM_HOST${extra:+ $extra}"
    vm_stop
  done
  unset MVM_DB MVM_FPM MVM_HOST
  host_restore
}

# #70: where a front page's time goes, host php-fpm against the microVM (extension off on both,
# the default database path): oha p50 of an empty PHP response, of 70,725 bytes (the front
# page's size) with no WordPress, and of the front page; and the median time inside PHP for
# the front page (sc-front.php's X-SC-PHP-MS, n=21).
php_ms() {
  for _ in $(seq 21); do
    curl -s -o /dev/null -D - -H "Host: 127.0.0.1:$port" "http://127.0.0.1:$1/sc-front.php" | tr -d '\r' | sed -n 's/^X-SC-PHP-MS: //p'
  done | median
}
breakdown_side() {
  printf '%-14s empty %.2f ms   70 KB %.2f ms   front page %.2f ms   inside PHP %s ms\n' "$1" \
    "$(p50 "http://$2/sc-front.php?big=0" "bd-$1-empty")" "$(p50 "http://$2/sc-front.php?big=70725" "bd-$1-big")" \
    "$(p50 "http://$2/" "bd-$1-front")" "$(php_ms "$3")"
}
breakdown() {
  web_up
  host_stock
  compose restart php >/dev/null 2>&1
  w=0; until [ "$(code "$port" /)" = 200 ]; do w=$((w + 1)); [ "$w" -lt 300 ] || die "host php-fpm did not come back"; sleep 0.2; done
  breakdown_side "host php-fpm" web "$port"
  vm_start breakdown --arg sc.ext=0
  breakdown_side microVM mvmweb "$vport"
  vm_stop
  host_restore
}

fallback() {
  # The driver as the php image's Debian would build it (the NixOS build's loader is Nix's).
  RUST=rust:1.99-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c
  docker run --rm -v "$PWD/bench/microvm:/src:ro" -v "$PWD/.target-deb:/t" -e CARGO_TARGET_DIR=/t -w /src "$RUST" \
    cargo build -q --release > "$res/fallback-build.log" 2>&1 || die "debian build of the driver (see $res/fallback-build.log)"
  hostbin=$bin
  bin=$PWD/.target-deb/release/securecore-microvm
  echo "this host:"
  "$hostbin" detect --firecracker "$mvm/firecracker" --kernel "$kernel" --rootfs "$mvm/rootfs.ext4" || echo "  exit $?"
  echo "the php-layer1 container (no /dev/kvm device):"
  php=$(compose ps -q php)
  docker cp "$bin" "$php:/usr/local/bin/securecore-microvm"
  docker exec "$php" securecore-microvm detect || echo "  exit $?"
  echo "the same container with --device /dev/kvm (a new one, same image):"
  docker run --rm --device /dev/kvm -v "$bin:/usr/local/bin/securecore-microvm:ro" --entrypoint securecore-microvm "$project-php" detect || echo "  exit $?"
  echo "launch in a container without /dev/kvm execs securecore-fpm (gelada) with the config:"
  docker run --rm -v "$bin:/usr/local/bin/securecore-microvm:ro" -v "$PWD/ext/examples/wordpress.json:/var/www/html/securecore.json:ro" \
    --entrypoint sh "$project-php" -c 'timeout 5 securecore-microvm launch --fpm /usr/local/bin/securecore-fpm --config /var/www/html/securecore.json 2>&1; echo "exit $?"' \
    > "$res/fallback.log" 2>&1 || true
  grep -E 'securecore-microvm|securecore-fpm|fpm is running|ready to handle|exit' "$res/fallback.log" | head -8
}

# One VM, a few timed front pages: a smoke check of the whole path.
smoke() {
  web_up
  vm_start smoke "$@"
  echo "first front page ${PAGE_MS} ms after the driver started"
  for _ in 1 2 3 4 5 6; do
    curl -s -o /dev/null -w "front page %{http_code} %{time_total}s\n" -H "Host: 127.0.0.1:$port" "http://127.0.0.1:$vport/"
  done
  curl -s -o /dev/null -w "sc-status.php (no WordPress) %{http_code} %{time_total}s\n" -H "Host: 127.0.0.1:$port" "http://127.0.0.1:$vport/sc-status.php"
  curl -s -o /dev/null -w "readme.html (static, host nginx) %{http_code} %{time_total}s\n" -H "Host: 127.0.0.1:$port" "http://127.0.0.1:$vport/readme.html"
  vm_stop
}

case $what in
  smoke) shift 2 2>/dev/null || shift; smoke "$@" ;;
  boot) shift 2 2>/dev/null || shift; boot "$@" ;;
  snapshot) snapshot ;;
  memory) memory ;;
  latency) latency ;;
  ext) shift 2 2>/dev/null || shift; ext "$@" ;;
  fallback) fallback ;;
  perf) perf ;;
  dbpath) dbpath ;;
  breakdown) breakdown "$@" ;;
  *) echo "usage: bench/microvm/bench.sh boot|snapshot|memory|latency|ext|fallback|perf|dbpath|breakdown [n]" >&2; exit 2 ;;
esac
