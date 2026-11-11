#!/bin/sh
# Integration tests for layer 1's isolation values and the microVM (addiscorp/securecore#71), on a
# Linux host with KVM, as root (Firecracker, Docker). The site is test/ext-layer1.sh's stack
# (WordPress, Classic Editor, Yoast SEO, Contact Form 7, MariaDB) as its own project (default
# sc-mvm, port 8095); docker/compose.ext-microvm.yml puts MariaDB's socket folder on the host and
# adds an nginx (port 8096) whose PHP goes to the host-side securecore-fpm, which runs php-fpm in
# a Firecracker guest. Checks:
#   1. the four values: off runs php-fpm as it is; gelada sandboxes it in place; on this KVM host
#      auto and microvm both boot the microVM; in the php container (no /dev/kvm) auto falls
#      back to gelada and says why, and microvm exits 125 without php-fpm ever running;
#   2. a real WordPress front page is served from the guest (the guest's kernel, loopback only,
#      securecore-init as PID 1), with layer 2 enforcing, layer 3's helper running, the
#      database reached through MariaDB's socket, uploads writable and the site read-only;
#   3. the first start makes a snapshot and the next one restores it, with the guest's clock
#      resynced and the uploads disk kept; a site change makes a new snapshot; a broken snapshot
#      falls back to a cold boot; --no-snapshot cold-boots;
#   4. SIGTERM stops the VM and the launcher exits 0.
# Exits non-zero on any failure. Writes .tmp/ext-microvm/. Leaves the stack up.
#   test/ext-microvm.sh            the checks
#   test/ext-microvm.sh bench [n]  front-page p50, host php-fpm vs the microVM, extension off on
#                                  both (bench/layer1.sh's method, #70's numbers), n rounds
# Needs: the guest kernel (KERNEL=, default .tmp/mvm/vmlinux-sc from bench/microvm/kernel.sh:
# mirab's kernel plus Landlock and seccomp, until mirab#89 ships them) and mirab's Firecracker
# (bench/microvm/fetch.sh, run here); a host securecore-fpm (SECURECORE_FPM=, default
# .target/release/securecore-fpm); docker, mke2fs, curl, jq.
set -u
cd "$(dirname "$0")/.." || exit 1
what=${1:-check}
rounds=${2:-5}
project=${SECURECORE_EXT_PROJECT:-sc-mvm}
port=${SECURECORE_EXT_PORT:-8095}
vport=$((port + 1))
dir=$PWD/.tmp/ext-microvm
vm=$dir/vm
state=$dir/state
run=$dir/run
mysqld=$dir/mysqld
fpm=${SECURECORE_FPM:-$PWD/.target/release/securecore-fpm}
kernel=${KERNEL:-$PWD/.tmp/mvm/vmlinux-sc}
OHA=ghcr.io/hatoo/oha@sha256:3ec3dbf549ea197793482d47a6324797411406bbf438c2fe8b91f244ec641a2f # oha 1.16.0
html=/var/www/html
mkdir -p "$dir" "$vm" "$state" "$run" "$mysqld"
find "$dir" -maxdepth 1 -type f -delete
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }
is() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3" "got '$1', want '$2'"; fi; }
has() { if grep -qF -- "$2" "$1"; then pass "$3"; else fail "$3" "no '$2' in $1: $(tail -5 "$1" | tr '\n' ' ' | cut -c1-400)"; fi; }
lacks() { if grep -qF -- "$2" "$1"; then fail "$3" "$(grep -F -- "$2" "$1" | head -2 | tr '\n' ' ')"; else pass "$3"; fi; }
die() { echo "FAIL $*"; exit 1; }
compose() {
  SECURECORE_PORT=$port SC_MVM_PORT=$vport SC_MVM_MYSQLD=$mysqld SC_MVM_RUN=$run docker compose \
    -f docker/compose.yml -f docker/compose.ext.yml -f docker/compose.ext-layer1.yml -f docker/compose.ext-microvm.yml \
    -p "$project" "$@"
}
wp() { compose run --rm -T cli wp "$@" 2>>"$dir/wp.err" | tr -d '\r'; }
in_php() { compose exec -T php sh -c "$1"; }
# Through the microVM's nginx, with the site's own Host so WordPress doesn't redirect.
vget() { curl -s -H "Host: 127.0.0.1:$port" "http://127.0.0.1:$vport$1"; }
vcode() { curl -s -o /dev/null -w '%{http_code}' -H "Host: 127.0.0.1:$port" "http://127.0.0.1:$vport$1"; }
code() { curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port$1"; }
probe() { vget "/sc-mvm-probe.php$1" > "$dir/probe.$2"; }
val() { sed -n "s/^$2=//p" "$dir/probe.$1"; }

# --- the stack ---------------------------------------------------------------------------------
[ -x "$fpm" ] || die "no host securecore-fpm at $fpm (cd ext && cargo build --release -p securecore-fpm)"
[ "$kernel" = "$vm/vmlinux" ] || [ -s "$kernel" ] || die "no guest kernel at $kernel (bench/microvm/kernel.sh; KERNEL=$vm/vmlinux for mirab's)"
[ -r /dev/kvm ] || die "this host has no /dev/kvm"
chown 999:999 "$mysqld"
echo "starting the stack (project $project, ports $port and $vport)"
compose build php mvmweb > "$dir/build.log" 2>&1 || die "docker build (see $dir/build.log)"
compose up -d db php web mvmweb > "$dir/up.log" 2>&1 || die "compose up (see $dir/up.log)"
i=0
until compose exec -T db mariadb -uwordpress -pwordpress-db-password -e 'select 1' wordpress >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 90 ] || die "the database did not start"; sleep 1
done
[ -S "$mysqld/mysqld.sock" ] || die "MariaDB's socket is not at $mysqld/mysqld.sock"
i=0
until [ "$(code /)" = 200 ]; do
  wp core install --url="http://127.0.0.1:$port" --title=SecureCore --admin_user=admin \
    --admin_password=securecore-demo --admin_email=admin@example.com --skip-email >/dev/null 2>&1 || true
  i=$((i + 1)); [ "$i" -lt 30 ] || die "WordPress did not install"; sleep 2
done
wp plugin install classic-editor wordpress-seo contact-form-7 --activate >/dev/null || die "plugin install"
site=$(docker volume inspect -f '{{.Mountpoint}}' "${project}_wp")
[ -f "$site/wp-load.php" ] || die "the site volume is not at $site"

# --- the guest's files -------------------------------------------------------------------------
# Firecracker and mirab's kernel the way a release resolves them (scripts/mirab-vm.sh): mirab's
# newest stable release, or, while that has no vm/ images (mirab#89), its newest canary.
scripts/mirab-vm.sh --files "$vm" "$dir" > "$dir/mirab.log" 2>&1; rc=$?
if [ "$rc" = 3 ]; then
  canary=$(curl -fsSL https://mirab-releases.addis.gg/canary.json | jq -r .version)
  scripts/mirab-vm.sh --files "$vm" "$dir" "https://mirab-releases.addis.gg/$canary/vm/manifest.json" >> "$dir/mirab.log" 2>&1; rc=$?
fi
[ "$rc" = 0 ] || die "mirab's VM files (see $dir/mirab.log)"
tail -1 "$dir/mirab.log"
# The guest kernel: mirab's, unless KERNEL names one with Landlock and seccomp (layer 3).
[ "$kernel" = "$vm/vmlinux" ] || cp "$kernel" "$vm/vmlinux"
docker build -q -f docker/ext.Dockerfile --target guest -t "$project-guest" . > "$dir/guest-build.log" 2>&1 \
  || die "the guest image (see $dir/guest-build.log)"
# The test site's environment for the guest's php-fpm (database settings and the vault's env
# sources, the stack's fixed test values), with the database on the guest's loopback.
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$(compose ps -q php)" | grep '^WORDPRESS_' \
  | sed 's|^WORDPRESS_DB_HOST=.*|WORDPRESS_DB_HOST=127.0.0.1:3306|' > "$dir/guest.env"
grep -q '^WORDPRESS_DB_HOST=127.0.0.1:3306$' "$dir/guest.env" || die "the guest's env file"
rootfs_built=$dir/rootfs.stamp
img=$(docker image inspect -f '{{.Id}}' "$project-guest")
if [ ! -s "$vm/rootfs.ext4" ] || [ "$(cat "$rootfs_built" 2>/dev/null)" != "$img" ]; then
  scripts/guest-image.sh "$project-guest" "$vm/rootfs.ext4" "$dir/guest.env" > "$dir/rootfs.log" 2>&1 || die "rootfs.ext4 (see $dir/rootfs.log)"
  echo "$img" > "$rootfs_built"
fi

# The site's files the VM sees: the probe, the status page, writable folders owned by www-data.
cp test/ext/microvm/probe.php "$site/sc-mvm-probe.php"
cp test/ext/securecore-status.php "$site/sc-status.php"
mkdir -p "$site/wp-content/uploads" "$site/wp-content/cache"
chown 33:33 "$site/wp-content/uploads" "$site/wp-content/cache" "$site/wp-content/plugins" "$site"
# layer1 for the microVM: the example's, with MySQL's port pointed at MariaDB's socket.
conf() {
  # The first "enabled" is layer1's.
  sed -e "s|{ \"port\": 3306 }|{ \"port\": 3306, \"socket\": \"$mysqld/mysqld.sock\" }|" \
      -e "0,/\"enabled\": true,/s//\"enabled\": true, \"isolation\": \"$1\",/" ext/examples/wordpress.json
}
conf microvm > "$dir/microvm.json"
if ! grep -q '"isolation": "microvm"' "$dir/microvm.json" || ! grep -q "\"socket\": \"$mysqld/mysqld.sock\"" "$dir/microvm.json"; then
  die "the microvm config fixture"
fi
[ "$(grep -c '"isolation"' "$dir/microvm.json")" = 1 ] || die "isolation only in layer1"

# start <name> <config> [flags]: the host launcher in the background on <config> as the site's
# securecore.json. Sets PID. Waits for "serving" (or for the launcher to exit).
start() {
  name=$1 config=$2; shift 2
  cp "$config" "$site/securecore.json"
  "$fpm" --config "$site/securecore.json" --vm-dir "$vm" --state-dir "$state" --listen "unix:$run/fpm.sock" \
    --guest-root "$html" "$@" > "$dir/$name.log" 2>&1 &
  PID=$!
  i=0
  until grep -q 'securecore-fpm: serving FastCGI' "$dir/$name.log"; do
    kill -0 "$PID" 2>/dev/null || { wait "$PID"; echo "  launcher exited $?: $(tail -3 "$dir/$name.log" | tr '\n' ' ')"; PID=""; return 1; }
    i=$((i + 1)); [ "$i" -lt 1200 ] || { echo "  no 'serving' in 120 s"; return 1; }
    sleep 0.1
  done
}
stop() {
  [ -n "$PID" ] || return 0
  kill -TERM "$PID"; wait "$PID"; STOPPED=$?; PID=""
}
PID=""
trap '[ -z "$PID" ] || kill -TERM "$PID" 2>/dev/null' EXIT
first_page() {
  t0=$(date +%s%N)
  c=$(vcode /)
  echo "$c $(( ($(date +%s%N) - t0) / 1000000 ))"
}

if [ "$what" = restore ]; then
  # Where the first page after a restore spends its time (#71's snapshot question): n restores of
  # one snapshot, each followed by five requests timed whole (curl) and inside PHP (sc-front.php's
  # X-SC-PHP-MS), first with the front page first, then with an empty PHP request first; and the
  # same after dropping the host's page cache (vm.mem read from disk).
  cp bench/microvm/sc-front.php "$site/sc-front.php"
  timed() { curl -s -o /dev/null -D - -w 'total=%{time_total}\n' -H "Host: 127.0.0.1:$port" "http://127.0.0.1:$vport$1" | tr -d '\r' | sed -n 's/^X-SC-PHP-MS: /php=/p;s/^total=/total=/p' | tr '\n' ' '; }
  start restore-warm "$dir/microvm.json" > /dev/null || die "the snapshot"
  stop
  for variant in front empty-first cold-cache; do
    r=1
    while [ "$r" -le "$rounds" ]; do
      [ "$variant" = cold-cache ] && { sync; echo 3 > /proc/sys/vm/drop_caches; }
      start "restore-$variant-$r" "$dir/microvm.json" || die "restore"
      line="$variant $r: $(sed -n 's/.*(load and php-fpm ping \([0-9.]*\) ms).*/restore+ping \1 ms/p' "$dir/restore-$variant-$r.log") |"
      [ "$variant" = empty-first ] && line="$line empty: $(timed '/sc-front.php?big=1') |"
      for i in 1 2 3 4 5; do line="$line $i: $(timed /sc-front.php)|"; done
      echo "$line"
      stop
      r=$((r + 1))
    done
  done
  rm -f "$site/sc-front.php"
  exit 0
fi

if [ "$what" = bench ]; then
  # bench/layer1.sh's method (#70): 20 warm-up and 100 sequential requests by oha on the stack's
  # network, extension off on both sides; host php-fpm is the php container with layer 1 off.
  oha() { docker run --rm --network "${project}_default" "$OHA" --no-tui --output-format json -H "Host: 127.0.0.1:$port" "$@"; }
  p50() {
    oha -n 20 -c 1 "$1" > /dev/null
    oha -n 100 -c 1 "$1" > "$dir/$2.json"
    [ "$(jq -r '.statusCodeDistribution["200"] // 0' "$dir/$2.json")" = 100 ] || die "$2: not all 100 responses were 200"
    jq -r '.metrics.latency_ms.p50' "$dir/$2.json"
  }
  ini=/usr/local/etc/php/conf.d/securecore.ini
  awk '/"layer1": \{/ { s = 1 } /"layer2": \{/ { s = 2 } /"layer3": \{/ { s = 3 }
    s && /"enabled": true/ { sub(/true/, "false"); s = 0 } { print }' ext/examples/wordpress.json > "$dir/stock.json"
  in_php "[ -f $ini.off ] || mv $ini $ini.off"
  host="" mvm=""
  r=1
  while [ "$r" -le "$rounds" ]; do
    cp "$dir/stock.json" "$site/securecore.json"
    compose restart php >/dev/null 2>&1
    i=0; until [ "$(code /)" = 200 ]; do i=$((i + 1)); [ "$i" -lt 300 ] || die "host php-fpm did not come back"; sleep 0.2; done
    a=$(p50 http://web/ "lat-host-$r")
    start "bench-$r" "$dir/microvm.json" --guest-arg sc.ext=0 || die "bench VM"
    b=$(p50 http://mvmweb/ "lat-vm-$r")
    stop
    printf 'round %s: host php-fpm %.2f ms   microVM %.2f ms\n' "$r" "$a" "$b"
    host="$host $a" mvm="$mvm $b"
    r=$((r + 1))
  done
  in_php "[ -f $ini ] || mv $ini.off $ini"
  cp ext/examples/wordpress.json "$site/securecore.json"
  compose restart php >/dev/null 2>&1
  median() { tr ' ' '\n' | grep . | sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }
  mh=$(echo "$host" | median) mv=$(echo "$mvm" | median)
  printf 'median p50: host php-fpm %.2f ms, microVM %.2f ms, delta %+.2f ms\n' "$mh" "$mv" "$(echo "$mv - $mh" | bc -l)"
  exit 0
fi

# --- 1. the four values ------------------------------------------------------------------------
echo "# the four values"
# A stand-in php-fpm: records that it ran, and its seccomp and no_new_privs state.
standin="grep -E '^(NoNewPrivs|Seccomp_filters):' /proc/self/status | tr -s '\t ' ' ' | tr '\n' ' '; echo standin-ran"
sed 's|"enabled": true, "isolation": "microvm"|"enabled": false, "isolation": "off"|' "$dir/microvm.json" > "$dir/off.json"
conf gelada > "$dir/gelada.json"
for v in off gelada; do
  cp "$dir/$v.json" "$site/securecore.json"
  "$fpm" --config "$site/securecore.json" --vm-dir "$vm" --php-fpm /bin/sh -- -c "$standin" > "$dir/value-$v.log" 2>&1
  is "$?" 0 "$v (KVM host): the launcher execs php-fpm"
  has "$dir/value-$v.log" standin-ran "$v: php-fpm ran"
done
has "$dir/value-off.log" "layer 1 is off in $site/securecore.json" "off: the launcher says layer 1 is off"
has "$dir/value-off.log" "Seccomp_filters: 0" "off: php-fpm has no seccomp filter"
has "$dir/value-gelada.log" "layer 1 isolation gelada: gelada" "gelada: chosen as asked, even with KVM here"
has "$dir/value-gelada.log" "NoNewPrivs: 1 Seccomp_filters: 2" "gelada: php-fpm runs under gelada's two seccomp filters"
lacks "$dir/value-gelada.log" "microVM" "gelada: no microVM"
# The php container has no /dev/kvm: auto falls back, microvm refuses. The image's own launcher.
conf auto > "$dir/auto.json"
for v in auto microvm; do
  compose cp "$dir/$v.json" "php:/tmp/sc-$v.json" >/dev/null 2>&1
  in_php "rm -f /tmp/sc-ran; securecore-fpm --config /tmp/sc-$v.json --php-fpm /bin/sh -- -c \"$standin; touch /tmp/sc-ran\"; echo exit=\$?; ls /tmp/sc-ran 2>/dev/null" > "$dir/container-$v.log" 2>&1
done
has "$dir/container-auto.log" "layer 1 isolation auto: gelada, because this host can't run the microVM (/dev/kvm: No such file or directory (os error 2))" \
  "auto without KVM: falls back to gelada and says why"
has "$dir/container-auto.log" "exit=0" "auto without KVM: php-fpm starts"
has "$dir/container-auto.log" "/tmp/sc-ran" "auto without KVM: php-fpm ran"
has "$dir/container-auto.log" "Seccomp_filters: 3" "auto without KVM: php-fpm runs under gelada (Docker's filter + gelada's 2)"
has "$dir/container-microvm.log" "exit=125" "microvm without KVM: the launcher exits 125"
has "$dir/container-microvm.log" "layer1.isolation is \"microvm\" but this host can't run the microVM (/dev/kvm: No such file or directory (os error 2))" \
  "microvm without KVM: refused, with the reason"
lacks "$dir/container-microvm.log" "standin-ran" "microvm without KVM: php-fpm never ran"
lacks "$dir/container-microvm.log" "/tmp/sc-ran" "microvm without KVM: nothing php-fpm would do happened"

# --- 2. WordPress from the guest, and 3. the snapshot ------------------------------------------
echo "# microvm: the first start makes the snapshot"
find "$state" -mindepth 1 -delete
if start first "$dir/microvm.json"; then
  has "$dir/first.log" "layer 1 isolation microvm: microvm" "microvm on the KVM host: the microVM"
  has "$dir/first.log" "built the site disk" "the site disk is built from the app root"
  has "$dir/first.log" "made the snapshot" "the first start makes a snapshot"
  has "$dir/first.log" "microVM restored from snapshot" "and serves from a restore of it"
  is "$(readlink "$state/v.sock_3306")" "$mysqld/mysqld.sock" "guest port 3306 is Firecracker's direct hop to MariaDB's socket"
  r=$(first_page)
  is "${r% *}" 200 "the front page through the microVM: 200 (first page after the restore: ${r#* } ms)"
  is "$(vget / | grep -c yoast-schema-graph)" 1 "it carries Yoast's output"
  probe "?write=first-$$" first
  is "$(val first kernel | cut -d. -f1-2)/$( [ "$(val first kernel)" != "$(uname -r)" ] && echo other)" 6.12/other \
    "PHP runs on the guest's kernel, mirab's Linux 6.12 ($(val first kernel); this host is $(uname -r))"
  is "$(val first guest_init)" 1 "PID 1 is securecore-init"
  is "$(val first netdev)" lo "the guest has loopback only, no network device"
  is "$(val first write_uploads)" OK "uploads are writable (their own disk)"
  is "$(val first write_root)/$(val first write_plugins)" BLOCKED/BLOCKED "the site itself is read-only"
  is "$(val first write_tmp)" OK "/tmp is writable (tmpfs)"
  skew=$(( $(date +%s) - $(val first time) ))
  is "$( [ "${skew#-}" -le 2 ] && echo ok )" ok "the guest's clock matches the host's (skew ${skew} s)"
  vget /sc-status.php > "$dir/status.first"
  is "$(sed -n 's/^loaded=//p;s/^layer2_mode=//p' "$dir/status.first" | tr '\n' /)" "1/enforce/" "the extension is loaded in the guest, layer 2 enforcing"
  is "$(sed -n 's/^layer1=//p;s/^layer2=//p;s/^layer3=//p' "$dir/status.first" | tr '\n' /)" "1/1/1/" "all three layers on in the guest's config"
  # Contact Form 7's isolated child runs (its database calls are refused, as on the host); on a
  # kernel without Landlock the child fails closed instead ("child refused to start").
  has "$dir/first.log" "securecore: layer3 plugin:contact-form-7 database refused (not yet available to an isolated plugin)" \
    "layer 3's isolated child runs in the guest (Landlock in the guest kernel)"
  lacks "$dir/first.log" "child refused to start" "no isolated child failed closed"
  has "$dir/first.log" "securecore: layer2 enforce plugin:wordpress-seo" "layer 2 refuses in the guest as on the host (Yoast's tables)"
  stop
  is "$STOPPED" 0 "SIGTERM: the launcher exits 0"
  has "$dir/first.log" "stopped by signal 15" "and says so"
  is "$(pgrep -fc "api-sock $state/fc.sock")" 0 "no Firecracker left running"
else
  fail "microvm: the first start serves"
fi

echo "# microvm: the next start restores"
sleep 3 # the snapshot is now older than the host's clock by at least this
if start second "$dir/microvm.json"; then
  lacks "$dir/second.log" "made the snapshot" "the same key: no new snapshot"
  has "$dir/second.log" "microVM restored from snapshot" "restored from the snapshot"
  r=$(first_page)
  is "${r% *}" 200 "the front page after a restore: 200 (${r#* } ms; $(sed -n 's/.*restored from snapshot [0-9a-f]* (load and php-fpm ping \([0-9.]*\) ms).*/load and ping \1 ms/p' "$dir/second.log"))"
  probe "" second
  skew=$(( $(date +%s) - $(val second time) ))
  is "$( [ "${skew#-}" -le 2 ] && echo ok )" ok "the restored guest's clock was resynced (skew ${skew} s)"
  is "$(val second read_uploads)" "first-$$" "the upload from the first start is still there (its disk persists)"
  stop
else
  fail "microvm: the second start serves"
fi

echo "# auto on the KVM host, after a site change"
date > "$site/sc-mvm-changed.txt"
if start third "$dir/auto.json"; then
  has "$dir/third.log" "layer 1 isolation auto: microvm" "auto with KVM: the microVM"
  has "$dir/third.log" "built the site disk" "the changed site gets a new disk"
  has "$dir/third.log" "made the snapshot" "and a new snapshot"
  is "$(find "$state" -maxdepth 1 -name 'snap-*' | grep -c .)" 1 "the old snapshot is removed"
  is "$(vcode /)" 200 "the front page: 200"
  stop
else
  fail "auto: the start serves"
fi

echo "# a broken snapshot falls back to a cold boot"
snap=$(find "$state" -maxdepth 1 -name 'snap-*' | head -1)
: > "$snap/vm.snap"
if start fourth "$dir/auto.json"; then
  has "$dir/fourth.log" "failed" "the restore fails"
  has "$dir/fourth.log" "cold-booting instead" "and the launcher cold-boots instead"
  has "$dir/fourth.log" "microVM cold-booted" "the cold-booted VM serves"
  is "$(vcode /)" 200 "the front page: 200"
  stop
else
  fail "a broken snapshot: the start serves"
fi

echo "# --no-snapshot"
if start fifth "$dir/auto.json" --no-snapshot; then
  has "$dir/fifth.log" "microVM cold-booted" "--no-snapshot: a cold boot"
  lacks "$dir/fifth.log" "snapshot" "and no snapshot is made or used"
  is "$(vcode /)" 200 "the front page: 200"
  stop
else
  fail "--no-snapshot: the start serves"
fi

for f in sc-mvm-probe.php sc-status.php sc-mvm-changed.txt; do rm -f "$site/$f"; done
cp ext/examples/wordpress.json "$site/securecore.json"
echo
if [ "$fails" -eq 0 ]; then echo "all ext-microvm checks passed"; else echo "$fails check(s) failed"; fi
[ "$fails" -eq 0 ]
