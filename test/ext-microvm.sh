#!/bin/sh
# Integration tests for layer 1's isolation values and the microVM (addiscorp/securecore#71), on a
# Linux host with KVM, as root (Firecracker's jailer, Docker). The site is test/ext-layer1.sh's
# stack (WordPress, Classic Editor, Yoast SEO, Contact Form 7, MariaDB) as its own project
# (default sc-mvm, port 8095); docker/compose.ext-microvm.yml puts MariaDB's socket folder on the
# host and adds an nginx (port 8096) whose PHP goes to the host-side securecore-fpm, which runs
# php-fpm in a jailed Firecracker guest. Checks:
#   1. the values: off runs php-fpm as it is; gelada sandboxes it in place; auto is gelada even
#      on this KVM host (until #72) and says why; auto with a config the VM can't express falls
#      back with that reason and microvm refuses it; microvm refuses a root image nothing
#      verified, and mirab's kernel (no Landlock) when layer 3 is on; in the php container (no
#      /dev/kvm) auto falls back and microvm exits 125 without php-fpm ever running;
#   2. a real WordPress front page from the guest (its kernel, loopback only, securecore-init as
#      PID 1), with layer 2 enforcing and layer 3's child running there, the database through
#      MariaDB's socket; Firecracker jailed as an unprivileged uid, so MariaDB's root (unix_socket
#      auth) is refused to the guest while uid 0 on the same socket gets it; fpm.sock 0660
#      root:101; the warm-up sent MariaDB nothing; USR1 and USR2 don't stop the launcher (USR2
#      reloads the guest's php-fpm); systemd's NOTIFY_SOCKET gets READY=1; a second start
#      message is refused by the guest; a second launcher on the same state is refused;
#   3. the first start makes a snapshot and the next restores it, with the clock resynced, fresh
#      randomness (kernel and php-fpm's workers) and the uploads disk kept; a stale socket link
#      left in the jail is gone; a site change makes a new snapshot; a larger --write-disk-mib
#      grows the uploads disk and keeps its files; a broken snapshot falls back to a cold boot;
#      --no-snapshot cold-boots; an orphaned uploads disk of a moved site is refused;
#   3b. the folder sync (#72): uploads of 100 KB, 10 MiB and 100 MiB reach the host's folder
#      (timed) and nginx serves them; renames, chmods and folder removals follow; the writer runs
#      as the pool user with no network; a link in the host's folder is replaced, never written
#      through; an upload made while the writer is stopped survives a SIGKILL of the launcher;
#      the writer killed mid-file leaves the old file whole and the next one resends it; a stop
#      drains the sync;
#   4. SIGTERM stops the VM and the launcher exits 0.
# Exits non-zero on any failure (and at once without /dev/kvm: never a skip). Writes
# .tmp/ext-microvm/. Leaves the stack up.
#   test/ext-microvm.sh            the checks
#   test/ext-microvm.sh bench [n]  front-page p50, host php-fpm vs the microVM, extension off on
#                                  both (bench/layer1.sh's method, #70's numbers), n rounds
#   test/ext-microvm.sh restore [n]  the requests after a restore, timed
# Needs: the guest kernel (KERNEL=, default .tmp/mvm/vmlinux-sc from bench/microvm/kernel.sh:
# mirab's kernel plus Landlock and seccomp, until mirab#89 ships them); a host securecore-fpm
# (SECURECORE_FPM=, default .target/release/securecore-fpm); docker, mke2fs, e2fsck, resize2fs,
# curl, jq, socat. mirab's files come from scripts/mirab-vm.sh: stable, or MIRAB_MANIFEST=<url>,
# or mirab's newest canary while stable has no vm/.
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
# Host sockets the guest reaches live where the VM's user can reach them: every folder above a
# connect[].socket counts (a 0700 home in between would refuse it, as it should).
sockdir=/run/$project
mysqld=$sockdir/mysqld
fpm=${SECURECORE_FPM:-$PWD/.target/release/securecore-fpm}
kernel=${KERNEL:-$PWD/.tmp/mvm/vmlinux-sc}
OHA=ghcr.io/hatoo/oha@sha256:3ec3dbf549ea197793482d47a6324797411406bbf438c2fe8b91f244ec641a2f # oha 1.16.0
html=/var/www/html
mkdir -p "$dir" "$vm" "$state" "$run" "$mysqld"
chmod 755 "$sockdir"
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
db_root() { compose exec -T db mariadb -uroot -proot-db-password -N -e "$1" 2>/dev/null; }
# Through the microVM's nginx, with the site's own Host so WordPress doesn't redirect.
vget() { curl -s -H "Host: 127.0.0.1:$port" "http://127.0.0.1:$vport$1"; }
vcode() { curl -s -o /dev/null -w '%{http_code}' -H "Host: 127.0.0.1:$port" "http://127.0.0.1:$vport$1"; }
code() { curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port$1"; }
probe() { vget "/sc-mvm-probe.php$1" > "$dir/probe.$2"; }
val() { sed -n "s/^$2=//p" "$dir/probe.$1"; }

# --- the stack ---------------------------------------------------------------------------------
[ -c /dev/kvm ] || die "this host has no /dev/kvm: the microVM tests need KVM (they never skip)"
[ -x "$fpm" ] || die "no host securecore-fpm at $fpm (cd ext && cargo build --release -p securecore-fpm)"
[ "$kernel" = "$vm/vmlinux" ] || [ -s "$kernel" ] || die "no guest kernel at $kernel (bench/microvm/kernel.sh; KERNEL=$vm/vmlinux for mirab's)"
for t in socat mke2fs e2fsck resize2fs jq; do command -v "$t" >/dev/null 2>&1 || die "$t isn't on PATH"; done
chown 999:999 "$mysqld"
echo "starting the stack (project $project, ports $port and $vport)"
compose build php mvmweb > "$dir/build.log" 2>&1 || die "docker build (see $dir/build.log)"
compose up -d db php web mvmweb > "$dir/up.log" 2>&1 || die "compose up (see $dir/up.log)"
# A site volume from an earlier run may hold an older securecore.json (one with the retired
# layer1.enabled is refused, so php-fpm wouldn't start): the current example, then php again.
site=$(docker volume inspect -f '{{.Mountpoint}}' "${project}_wp")
if [ -f "$site/securecore.json" ]; then
  cp ext/examples/wordpress.json "$site/securecore.json"
  compose restart php > /dev/null 2>&1
fi
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
# MariaDB's root by unix_socket (as Debian's packages set it up): whoever connects to the socket
# as uid 0 is the database's root, with no password.
db_root "ALTER USER 'root'@'localhost' IDENTIFIED VIA unix_socket OR mysql_native_password USING PASSWORD('root-db-password')" > /dev/null \
  || die "root@localhost by unix_socket"

# --- the guest's files -------------------------------------------------------------------------
# Firecracker, its jailer and mirab's kernel the way a release resolves them (scripts/mirab-vm.sh):
# mirab's newest stable release, or MIRAB_MANIFEST, or, while stable has no vm/ (mirab#89), its
# newest canary.
if [ -n "${MIRAB_MANIFEST:-}" ]; then
  scripts/mirab-vm.sh --files "$vm" "$dir" "$MIRAB_MANIFEST" > "$dir/mirab.log" 2>&1; rc=$?
else
  scripts/mirab-vm.sh --files "$vm" "$dir" > "$dir/mirab.log" 2>&1; rc=$?
  if [ "$rc" = 3 ]; then
    canary=$(curl -fsSL https://mirab-releases.addis.gg/canary.json | jq -r .version)
    scripts/mirab-vm.sh --files "$vm" "$dir" "https://mirab-releases.addis.gg/$canary/vm/manifest.json" >> "$dir/mirab.log" 2>&1; rc=$?
  fi
fi
[ "$rc" = 0 ] || die "mirab's VM files (see $dir/mirab.log)"
tail -1 "$dir/mirab.log"
[ -x "$vm/jailer" ] || die "no jailer from Firecracker's tarball"
cp "$vm/vmlinux" "$dir/vmlinux-mirab"
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
# installed.json, as the installer writes it, with the rootfs too (this test built it; no
# release ships one yet). record <vm-dir> [no-rootfs].
sum() { sha256sum "$1" | cut -d' ' -f1; }
record() {
  r=""
  [ "${2:-}" = no-rootfs ] || r=", \"rootfs_sha256\": \"$(sum "$1/rootfs.ext4")\""
  printf '{ "firecracker_sha256": "%s", "jailer_sha256": "%s", "kernel_sha256": "%s"%s }\n' \
    "$(sum "$1/firecracker")" "$(sum "$1/jailer")" "$(sum "$1/vmlinux")" "$r" > "$1/installed.json"
}
record "$vm"
# Variants for the refusals: nothing verified for the rootfs; mirab's kernel (no Landlock).
for v in vm-norootfs vm-mirabkernel; do
  mkdir -p "$dir/$v"
  find "$dir/$v" -mindepth 1 -delete
  for f in firecracker jailer vmlinux rootfs.ext4; do ln "$vm/$f" "$dir/$v/$f"; done
done
record "$dir/vm-norootfs" no-rootfs
rm -f "$dir/vm-mirabkernel/vmlinux"
cp "$dir/vmlinux-mirab" "$dir/vm-mirabkernel/vmlinux"
record "$dir/vm-mirabkernel"
# The jailed user, and nginx's group (the alpine image's nginx is 101:101) for fpm.sock.
vmuser=${SC_VM_USER:-64000:64000}

# The site's files the VM sees: the probe, the status page, writable folders owned by www-data.
cp test/ext/microvm/probe.php "$site/sc-mvm-probe.php"
cp test/ext/securecore-status.php "$site/sc-status.php"
mkdir -p "$site/wp-content/uploads" "$site/wp-content/cache"
chown 33:33 "$site/wp-content/plugins" "$site"
# The site's pool user, as php-fpm runs it on this host: not the image's www-data (33), so the
# guest must map it. It owns the writable folders.
pool=1234:1234
chown -R "$pool" "$site/wp-content/uploads" "$site/wp-content/cache"
# layer1 for the microVM: the example's, with MySQL's port pointed at MariaDB's socket.
# Port 4444 goes to the peer-credential listener; layer 2 lets core (the probe) reach 127.0.0.1.
conf() {
  # The first "enabled" is layer1's.
  sed -e "s|{ \"port\": 3306 }|{ \"port\": 3306, \"socket\": \"$mysqld/mysqld.sock\" }, { \"port\": 4444, \"socket\": \"$peer/peer.sock\" }|" \
      -e "s/\"isolation\": \"auto\"/\"isolation\": \"$1\"/" \
      -e 's#"hosts": \["api.wordpress.org", "downloads.wordpress.org"\]#"hosts": ["api.wordpress.org", "downloads.wordpress.org", "127.0.0.1"]#' \
      ext/examples/wordpress.json
}
peer=$sockdir/peer
mkdir -p "$peer"
chmod 755 "$peer"
rm -f "$peer/peer.sock"
python3 -I test/ext/microvm/peercred.py "$peer/peer.sock" > "$dir/peercred.log" 2>&1 &
peer_pid=$!
i=0; until [ -S "$peer/peer.sock" ]; do i=$((i + 1)); [ "$i" -lt 50 ] || die "the peer-credential listener"; sleep 0.1; done
conf microvm > "$dir/microvm.json"
if ! grep -q '"port": 4444' "$dir/microvm.json" || ! grep -q '"127.0.0.1"\]' "$dir/microvm.json"; then
  die "the microvm config fixture (4444, core hosts)"
fi
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
    --listen-owner 0 --listen-group 101 --listen-mode 0660 --vm-user "$vmuser" --pool-user "$pool" \
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
trap '[ -z "$PID" ] || kill -TERM "$PID" 2>/dev/null; kill "$peer_pid" 2>/dev/null' EXIT
first_page() {
  t0=$(date +%s%N)
  c=$(vcode /)
  echo "$c $(( ($(date +%s%N) - t0) / 1000000 ))"
}
jail_root() { find "$state/jail/firecracker" -mindepth 2 -maxdepth 2 -name root 2>/dev/null | head -1; }
# Empties the state folder, unmounting a leftover jail's bind mounts first: never delete through
# one (it is MariaDB's socket folder).
clean_state() {
  awk -v s="$state/" 'index($5, s) == 1 { print $5 }' /proc/self/mountinfo | sort -r | while read -r m; do umount -l "$m"; done
  if awk -v s="$state/" 'index($5, s) == 1' /proc/self/mountinfo | grep -q .; then die "a mount under $state is still there"; fi
  find "$state" -mindepth 1 -xdev -delete
}
questions() { db_root "SHOW GLOBAL STATUS LIKE 'Questions'" | awk '{ print $2 }'; }
# once <name> <config> [flags]: the launcher in the foreground with a stand-in php-fpm.
standin="grep -E '^(NoNewPrivs|Seccomp_filters):' /proc/self/status | tr -s '\t ' ' ' | tr '\n' ' '; echo standin-ran"
once() {
  name=$1 config=$2; shift 2
  cp "$config" "$site/securecore.json"
  "$fpm" --config "$site/securecore.json" --state-dir "$state" --vm-user "$vmuser" --pool-user "$pool" "$@" --php-fpm /bin/sh -- -c "$standin" > "$dir/value-$name.log" 2>&1
  echo "exit=$?" >> "$dir/value-$name.log"
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
  # p50 <url> <name>: sets P50; dies (in this shell, never a subshell) unless all 100 were 200s.
  p50() {
    oha -n 20 -c 1 "$1" > /dev/null
    oha -n 100 -c 1 "$1" > "$dir/$2.json"
    ok=$(jq -r '.statusCodeDistribution["200"] // 0' "$dir/$2.json")
    [ "$ok" = 100 ] || die "$2: $ok of 100 responses were 200"
    P50=$(jq -r '.metrics.latency_ms.p50' "$dir/$2.json")
  }
  ini=/usr/local/etc/php/conf.d/securecore.ini
  awk '{ sub(/"isolation": "auto"/, "\"isolation\": \"off\"") } /"layer2": \{/ { s = 2 } /"layer3": \{/ { s = 3 }
    s && /"enabled": true/ { sub(/true/, "false"); s = 0 } { print }' ext/examples/wordpress.json > "$dir/stock.json"
  grep -q '"isolation": "off"' "$dir/stock.json" || die "the stock config has layer 1 off"
  in_php "[ -f $ini.off ] || mv $ini $ini.off"
  host="" mvm=""
  r=1
  while [ "$r" -le "$rounds" ]; do
    cp "$dir/stock.json" "$site/securecore.json"
    compose restart php >/dev/null 2>&1
    i=0; until [ "$(code /)" = 200 ]; do i=$((i + 1)); [ "$i" -lt 300 ] || die "host php-fpm did not come back"; sleep 0.2; done
    p50 http://web/ "lat-host-$r"; a=$P50
    start "bench-$r" "$dir/microvm.json" --guest-arg sc.ext=0 || die "bench VM"
    p50 http://mvmweb/ "lat-vm-$r"; b=$P50
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

# --- 1. the values -----------------------------------------------------------------------------
echo "# the values"
clean_state
sed 's|"isolation": "microvm"|"isolation": "off"|' "$dir/microvm.json" > "$dir/off.json"
# A config that still sets the retired layer1.enabled: refused, with what to write instead.
sed 's|"isolation": "microvm"|"enabled": true, "isolation": "microvm"|' "$dir/microvm.json" > "$dir/retired.json"
conf gelada > "$dir/gelada.json"
conf auto > "$dir/auto.json"
# A config the microVM can't express: a denied path inside the app root.
sed 's|"deny": \["/srv/backups"\]|"deny": ["/srv/backups", "wp-content/private"]|' "$dir/microvm.json" > "$dir/microvm-deny.json"
sed 's|"isolation": "microvm"|"isolation": "auto"|' "$dir/microvm-deny.json" > "$dir/auto-deny.json"
grep -q 'wp-content/private' "$dir/auto-deny.json" || die "the inexpressible fixture"
# Writable folders that aren't real folders in the root: one through a link to a root-only
# folder, one with "..". Neither may be read by the launcher.
ln -sfn /root "$site/wp-content/sc-evil"
sed 's|"write": \["wp-content/uploads"|"write": ["wp-content/sc-evil", "wp-content/uploads"|' "$dir/microvm.json" > "$dir/microvm-link.json"
sed 's|"write": \["wp-content/uploads"|"write": ["wp-content/uploads/../../../root", "wp-content/uploads"|' "$dir/microvm.json" > "$dir/microvm-dotdot.json"
if ! grep -q sc-evil "$dir/microvm-link.json" || ! grep -q '\.\./\.\./\.\./root' "$dir/microvm-dotdot.json"; then die "the link fixtures"; fi
# A socket the VM's user can't reach: a 0777 socket in a 0755 folder inside a root-only one (the
# socket's own folder is open; a folder above it isn't).
mkdir -p "$sockdir/locked/inner"
chmod 700 "$sockdir/locked"
chmod 755 "$sockdir/locked/inner"
rm -f "$sockdir/locked/inner/db.sock"
socat UNIX-LISTEN:"$sockdir/locked/inner/db.sock",fork,mode=777 /dev/null > /dev/null 2>&1 &
locked_pid=$!
i=0; until [ -S "$sockdir/locked/inner/db.sock" ]; do i=$((i + 1)); [ "$i" -lt 50 ] || die "the locked socket"; sleep 0.1; done
sed "s|{ \"port\": 4444|{ \"port\": 5555, \"socket\": \"$sockdir/locked/inner/db.sock\" }, { \"port\": 4444|" "$dir/microvm.json" > "$dir/microvm-locked.json"
grep -q '"port": 5555' "$dir/microvm-locked.json" || die "the locked-socket fixture"
once off "$dir/off.json" --vm-dir "$vm"
once gelada "$dir/gelada.json" --vm-dir "$vm"
once auto "$dir/auto.json" --vm-dir "$vm" --state-dir "$dir/gated-state"
once microvm-deny "$dir/microvm-deny.json" --vm-dir "$vm"
once microvm-norootfs "$dir/microvm.json" --vm-dir "$dir/vm-norootfs"
once microvm-mirabkernel "$dir/microvm.json" --vm-dir "$dir/vm-mirabkernel"
once microvm-link "$dir/microvm-link.json" --vm-dir "$vm"
once microvm-dotdot "$dir/microvm-dotdot.json" --vm-dir "$vm"
once microvm-locked "$dir/microvm-locked.json" --vm-dir "$vm"
once retired "$dir/retired.json" --vm-dir "$vm"
kill "$locked_pid" 2>/dev/null
rm -f "$site/wp-content/sc-evil"
for v in off gelada auto; do
  has "$dir/value-$v.log" "exit=0" "$v (KVM host): the launcher execs php-fpm"
  has "$dir/value-$v.log" standin-ran "$v: php-fpm ran"
done
has "$dir/value-off.log" "layer 1 is off in $site/securecore.json" "off: the launcher says layer 1 is off"
has "$dir/value-off.log" "Seccomp_filters: 0" "off: php-fpm has no seccomp filter"
has "$dir/value-gelada.log" "layer 1 isolation gelada: gelada" "gelada: chosen as asked, even with KVM here"
has "$dir/value-gelada.log" "NoNewPrivs: 1 Seccomp_filters: 2" "gelada: php-fpm runs under gelada's two seccomp filters"
has "$dir/value-auto.log" "layer 1 isolation auto: gelada, because auto doesn't pick the microVM until its writable folders sync back to the host (addiscorp/securecore#72)" \
  "auto on a KVM host that could run the microVM: gelada, with the #72 gate as the reason"
has "$dir/value-auto.log" "NoNewPrivs: 1 Seccomp_filters: 2" "auto: php-fpm runs under gelada"
is "$( [ -e "$dir/gated-state" ] && echo made || echo none)" none "gated auto probes nothing: no state folder, no hashing, no cgroup write"
for v in deny norootfs mirabkernel link dotdot locked; do
  has "$dir/value-microvm-$v.log" "exit=125" "microvm, $v: exit 125"
  lacks "$dir/value-microvm-$v.log" standin-ran "microvm, $v: php-fpm never ran"
done
has "$dir/value-microvm-deny.log" "is inside the app root" "microvm with a denied path in the root: says why"
has "$dir/value-microvm-norootfs.log" "the guest root image isn't verified" "microvm without a verified root image: says why"
has "$dir/value-microvm-mirabkernel.log" "has no Landlock and seccomp filters" "microvm with layer 3 on mirab's kernel: says why"
has "$dir/value-microvm-link.log" "wp-content/sc-evil is a symlink" "a writable folder that is a link (to a root-only folder) is refused, never read"
has "$dir/value-microvm-dotdot.log" "holds \"..\"" "a writable folder with \"..\" is refused, never read"
has "$dir/value-microvm-locked.log" "may not connect to $sockdir/locked/inner/db.sock (Permission denied" \
  "a socket below a folder the VM's user can't search is refused (every parent's permissions count)"
has "$dir/value-retired.log" "exit=125" "a config that still sets layer1.enabled: exit 125"
has "$dir/value-retired.log" "layer1.enabled is retired: layer1.isolation is layer 1's only switch" "and it says to use isolation instead"
lacks "$dir/value-retired.log" standin-ran "and php-fpm never ran"
# A file in the site only root may read: the site disk is copied as the pool user, so it fails.
echo secret > "$site/sc-root-only.txt"
chmod 600 "$site/sc-root-only.txt"
once microvm-rootonly "$dir/microvm.json" --vm-dir "$vm"
rm -f "$site/sc-root-only.txt"
has "$dir/value-microvm-rootonly.log" "exit=125" "a root-only file in the site: the start fails"
has "$dir/value-microvm-rootonly.log" "as uid 1234" "because the site disk is copied as the pool user, never as root"
clean_state
# The php container has no /dev/kvm: auto falls back, microvm refuses. The image's own launcher.
for v in auto microvm; do
  compose cp "$dir/$v.json" "php:/tmp/sc-$v.json" >/dev/null 2>&1
  in_php "rm -f /tmp/sc-ran; securecore-fpm --config /tmp/sc-$v.json --php-fpm /bin/sh -- -c \"$standin; touch /tmp/sc-ran\"; echo exit=\$?; ls /tmp/sc-ran 2>/dev/null" > "$dir/container-$v.log" 2>&1
done
has "$dir/container-auto.log" "layer 1 isolation auto: gelada, because auto doesn't pick the microVM" "auto without KVM: gelada (the gate answers before any probe)"
has "$dir/container-auto.log" "exit=0" "auto without KVM: php-fpm starts"
has "$dir/container-auto.log" "Seccomp_filters: 3" "auto without KVM: php-fpm runs under gelada (Docker's filter + gelada's 2)"
has "$dir/container-microvm.log" "exit=125" "microvm without KVM: the launcher exits 125"
has "$dir/container-microvm.log" "layer1.isolation is \"microvm\" but the microVM can't run here" "microvm without KVM: refused, with the reason"
lacks "$dir/container-microvm.log" "standin-ran" "microvm without KVM: php-fpm never ran"

# --- 2. WordPress from the jailed guest, and 3. the snapshot -----------------------------------
echo "# microvm: the first start makes the snapshot"
clean_state
# The folder sync's files from an earlier run (the uploads disk is made from this folder now).
up=$site/wp-content/uploads
for d in lat moved mid crash drain sc-evil sc-evil2; do if [ -e "$up/$d" ] || [ -L "$up/$d" ]; then find "$up/$d" -delete; fi; done
# Real uploads, larger than the site's code: the site disk must not carry them.
head -c 300M /dev/urandom > "$site/wp-content/uploads/sc-big.bin"
chown "$pool" "$site/wp-content/uploads/sc-big.bin"
# What asking costs: two asks in a row, nothing between.
qa=$(questions); qb=$(questions); qbase=$((qb - qa))
q0=$(questions)
rm -f "$dir/notify.sock" "$dir/notify.msg"
socat -u "UNIX-RECV:$dir/notify.sock" "OPEN:$dir/notify.msg,creat" &
notify_pid=$!
sleep 0.3
export NOTIFY_SOCKET="$dir/notify.sock"
started=0
start first "$dir/microvm.json" && started=1
unset NOTIFY_SOCKET
q1=$(questions)
if [ "$started" = 1 ]; then
  is "$((q1 - q0))" "$qbase" "the warm-up and snapshot sent MariaDB nothing (Questions +$((q1 - q0)), the same as asking twice)"
  has "$dir/first.log" "warmed the guest's page cache for the snapshot (read=" "the warm-up read the site into the guest's page cache"
  lacks "$dir/first.log" "PHP Fatal error" "no PHP fatal error in the guest (the warm-up compiles nothing out of context)"
  has "$dir/first.log" "layer 1 isolation microvm: microvm" "microvm on the KVM host: the microVM"
  has "$dir/first.log" "made the snapshot" "the first start makes a snapshot"
  has "$dir/first.log" "microVM restored from snapshot" "and serves from a restore of it"
  sitedisk=$(find "$state" -maxdepth 1 -name 'site-*.ext4' | head -1)
  is "$(debugfs -R 'ls /wp-content/uploads' "$sitedisk" 2>/dev/null | grep -c sc-big.bin)" 0 \
    "the site disk holds no upload (the writable folders are only mount points in it)"
  is "$( [ "$(du -m "$sitedisk" | cut -f1)" -lt 300 ] && echo smaller)" smaller "and uses less than the 300 MiB of uploads ($(du -m "$sitedisk" | cut -f1) MiB)"
  fcpid=$(sed -n 's/.*Firecracker runs jailed as uid [0-9]* gid [0-9]* (pid \([0-9]*\)).*/\1/p' "$dir/first.log")
  is "$(awk '/^Uid:/ { print $2 "/" $3 }' "/proc/$fcpid/status" 2>/dev/null)/$(awk '/^Gid:/ { print $2 }' "/proc/$fcpid/status" 2>/dev/null)" 64000/64000/64000 \
    "Firecracker (pid $fcpid) runs as the unprivileged uid and gid, not root"
  is "$(awk '/^Groups:/ { print NF - 1 }' "/proc/$fcpid/status")" 0 "with no supplementary groups"
  is "$(stat -Lc %d:%i "/proc/$fcpid/root")" "$(stat -c %d:%i "$(jail_root)")" "chrooted into its jail (its / is the jail's root)"
  is "$( [ "$(readlink "/proc/$fcpid/ns/net")" != "$(readlink /proc/self/ns/net)" ] && echo own)" own "in its own network namespace"
  cg=$(cut -d: -f3 "/proc/$fcpid/cgroup")
  is "$(cat "/sys/fs/cgroup$cg/memory.max")/$(cat "/sys/fs/cgroup$cg/cpu.max")" "$(((512 + 256) << 20))/200000 100000" "in a cgroup with memory.max and cpu.max set ($cg)"
  is "$(stat -c '%a %u %g' "$run/fpm.sock")" "660 0 101" "fpm.sock is 0660 root:101 (--listen-mode/owner/group), not 0666"
  is "$(cat "$dir/notify.msg" 2>/dev/null | head -1)" "READY=1" "NOTIFY_SOCKET got READY=1 (systemd Type=notify)"
  r=$(first_page)
  is "${r% *}" 200 "the front page through the jailed microVM: 200 (first page after the restore: ${r#* } ms)"
  is "$(vget / | grep -c yoast-schema-graph)" 1 "it carries Yoast's output"
  probe "?write=first-$$&peer=1" first
  is "$(val first kernel | cut -d. -f1-2)/$( [ "$(val first kernel)" != "$(uname -r)" ] && echo other)" 6.12/other \
    "PHP runs on the guest's kernel, mirab's Linux 6.12 ($(val first kernel); this host is $(uname -r))"
  is "$(val first guest_init)" 1 "PID 1 is securecore-init"
  is "$(val first euid)" 1234 "the guest's php-fpm workers run as the host's pool user (1234), not the image's www-data"
  is "$(val first netdev)" lo "the guest has loopback only, no network device"
  is "$(val first write_uploads)" OK "uploads are writable (their own disk)"
  is "$(val first write_root)/$(val first write_plugins)" BLOCKED/BLOCKED "the site itself is read-only"
  is "$(val first write_tmp)" OK "/tmp is writable (tmpfs)"
  # Who a host socket sees on the guest's connections (SO_PEERCRED): the jailed uid. With
  # unix_socket auth, uid 0 on MariaDB's socket is the database's root (the control shows it).
  is "$(val first peer)" "uid=64000 gid=64000" "a host socket sees the guest's connections as uid 64000 (SO_PEERCRED), not root"
  is "$(docker run --rm -v "$mysqld:/run/mysqld" --entrypoint mariadb mariadb:11.4 -uroot -N -e 'select 1' 2>/dev/null)" 1 \
    "control: uid 0 on MariaDB's socket is the database's root (unix_socket), which the guest never gets"
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
  is "$(grep -c '^NOTICE\|^\[' "$dir/first.log")" 0 "every line from the guest is marked 'guest: ' in the launcher's log"
  # A second start message, straight to the guest's control port: refused.
  # (From inside the jail: its full path is longer than a unix socket address holds. The lines go
  # after Firecracker's OK: it drops what follows the CONNECT line in the same write, #70.)
  { printf 'CONNECT 1515\n'; sleep 1; printf 'time 1 0\nentropy %s\ndone\n' "$(printf '00%.0s' $(seq 64))"; sleep 3; } \
    | (cd "$(jail_root)" && socat -t 5 - UNIX-CONNECT:v.sock) > "$dir/second-start.out" 2>&1
  has "$dir/second-start.out" "error this boot's start message was already taken" "the guest refuses a second start message"
  # A second launcher on the same state folder.
  "$fpm" --config "$site/securecore.json" --vm-dir "$vm" --state-dir "$state" --vm-user "$vmuser" --listen "unix:$run/other.sock" > "$dir/second-launcher.log" 2>&1
  is "$?" 125 "a second launcher on the same state exits 125"
  has "$dir/second-launcher.log" "is locked" "because the state folder is locked"
  # USR1 and USR2 don't stop it.
  kill -USR1 "$PID"; sleep 0.5
  kill -USR2 "$PID"; sleep 2
  is "$(kill -0 "$PID" 2>/dev/null && echo running)" running "SIGUSR1 and SIGUSR2 leave the launcher running"
  has "$dir/first.log" "SIGUSR1: nothing to reopen" "SIGUSR1 is acknowledged"
  has "$dir/first.log" "reloaded the guest's php-fpm gracefully" "SIGUSR2 reloads the guest's php-fpm"
  is "$(vcode /)" 200 "the front page after the reload: 200"
  # Two reloads close together: the second USR2 arrives while the first reload waits for a 5 s
  # request in flight. One reload at a time, on both sides: the second runs after the first
  # (never on the 0 the guest records while a master is replaced), and php-fpm keeps serving.
  reloads() { grep -c "reloaded the guest's php-fpm gracefully" "$dir/first.log"; }
  before=$(reloads)
  vget "/sc-mvm-probe.php?sleep=5" > "$dir/during-reloads.out" &
  slow=$!
  sleep 1
  kill -USR2 "$PID"
  sleep 0.5
  kill -USR2 "$PID"
  i=0
  while [ "$(reloads)" -lt $((before + 2)) ] && [ "$i" -lt 120 ]; do i=$((i + 1)); sleep 0.5; done
  wait "$slow"
  is "$(reloads)" $((before + 2)) "two USR2s close together: two reloads, one after the other"
  lacks "$dir/first.log" "reload failed" "neither reload failed"
  is "$(kill -0 "$PID" 2>/dev/null && echo running)" running "the launcher (and its VM) still runs after both"
  is "$(vcode /)" 200 "the front page after two reloads close together: 200"
  is "$(stat -c '%a %u %g' "$(find "$state" -maxdepth 2 -path '*/snap-*/vm.mem' | head -1)")" "640 0 64000" \
    "the snapshot is root's, read-only to the VM's group"
  # A slow reload (a 15 s request in flight, which php-fpm's graceful stop waits for), and a stop
  # during it: the stop's sync must still reach the guest at once (the upload above must survive
  # into the next start), not wait behind the reload.
  vget "/sc-mvm-probe.php?sleep=15" > /dev/null &
  slow=$!
  sleep 1
  kill -USR2 "$PID"
  sleep 1
  stop
  kill "$slow" 2>/dev/null
  is "$STOPPED" 0 "SIGTERM during a slow reload: the launcher exits 0"
  lacks "$dir/first.log" "did not sync" "and the guest synced its disks first"
  has "$dir/first.log" "stopped by signal 15" "and says so"
  is "$(pgrep -fc "api-sock /fc.sock")" 0 "no Firecracker left running"
  is "$(grep -c " $state/jail" /proc/self/mountinfo)" 0 "and nothing mounted in its jail"
else
  fail "microvm: the first start serves"
fi
kill "$notify_pid" 2>/dev/null

echo "# microvm: the next start restores"
sleep 3 # the snapshot is now older than the host's clock by at least this
# A stale link left in a jail (an older config's port): a fresh jail never has it.
jr=$state/jail/firecracker/sc-$(printf %s "$(readlink -f "$site")" | sha256sum | cut -c1-16)/root
mkdir -p "$jr"
ln -s /run/stale.sock "$jr/v.sock_7777"
if start second "$dir/microvm.json"; then
  lacks "$dir/second.log" "made the snapshot" "the same key: no new snapshot"
  has "$dir/second.log" "microVM restored from snapshot" "restored from the snapshot"
  is "$(find "$state/jail" -name 'v.sock_7777' | grep -c .)" 0 "the stale v.sock_7777 link is gone: every start begins with an empty jail"
  is "$(find "$(jail_root)" -maxdepth 1 -name 'v.sock_*' -printf '%f\n' | sort | tr '\n' ' ')" "v.sock_1514 v.sock_3306 v.sock_4444 " "the jail holds only the planned ports"
  r=$(first_page)
  is "${r% *}" 200 "the front page after a restore: 200 (${r#* } ms; $(sed -n 's/.*restored from snapshot [0-9a-f]* (load and php-fpm ping \([0-9.]*\) ms).*/load and ping \1 ms/p' "$dir/second.log"))"
  probe "" second
  skew=$(( $(date +%s) - $(val second time) ))
  is "$( [ "${skew#-}" -le 2 ] && echo ok )" ok "the restored guest's clock was resynced (skew ${skew} s)"
  is "$(val second read_uploads)" "first-$$" "the upload from the first start is still there (its disk persists)"
  is "$(cat "$site/wp-content/uploads/sc-mvm.txt" 2>/dev/null)" "first-$$" "and the host's uploads folder has it too (the folder sync, #72)"
  # Two restores of one snapshot: their randomness differs.
  differ() { if [ "$1" != "$2" ]; then echo yes; else echo "no ($1)"; fi; }
  is "$(differ "$(val second random)" "$(val first random)")" yes "random_bytes differs between two restores of one snapshot (fresh entropy)"
  is "$(differ "$(val second mt_rand)" "$(val first mt_rand)")" yes "mt_rand differs too (php-fpm's workers seed after the restore)"
  stop
else
  fail "microvm: the second start serves"
fi

echo "# the folder sync (#72): what the guest writes to uploads reaches the host's folder"
outside=$sockdir/sync-outside
mkdir -p "$outside"
find "$outside" -mindepth 1 -delete
# The pool user could write here: only the writer's own rules keep it out.
chown "$pool" "$outside"
# A link the site owner put in the host's folder while the VM was stopped: not in the guest's
# tree, so the listing removes it (never follows it).
ln -sfn "$outside" "$up/sc-evil2"
# eventually <tenths> <shell test>: until the test holds, or the time is up.
eventually() { n=0; until eval "$2"; do n=$((n + 1)); [ "$n" -lt "$1" ] || return 1; sleep 0.1; done; }
# synced <rel> <size> <sha256>: waits (60 s at most) for the host's copy, then prints the ms.
synced() {
  t0=$(date +%s%N)
  eventually 600 "[ \"\$(stat -c %s \"$up/$1\" 2>/dev/null)\" = $2 ] && [ \"\$(sha256sum \"$up/$1\" | cut -d' ' -f1)\" = $3 ]" || { echo never; return 1; }
  echo "$(( ($(date +%s%N) - t0) / 1000000 ))"
}
writer_pid() { ps -o pid=,args= --ppid "$PID" | awk '/--sync-writer/ { print $1 }' | head -1; }
if start sync "$dir/microvm.json"; then
  eventually 300 "grep -q 'sync: folder 0 reconciled' \"$dir/sync.log\"" || true
  has "$dir/sync.log" "syncing the writable folders back to the host as uid 1234" "the launcher syncs the writable folders as the pool user"
  has "$dir/sync.log" "sync: folder 0 reconciled" "the guest's listing reconciled the host's folder"
  is "$( [ -L "$up/sc-evil2" ] || [ -e "$up/sc-evil2" ] && echo there || echo gone)" gone "a link planted in the host's folder is removed by the listing"
  wpid=$(writer_pid)
  is "$(awk '/^Uid:/ { print $2 "/" $3 }' "/proc/$wpid/status" 2>/dev/null)" 1234/1234 "the writer (pid $wpid) runs as the pool user, never root"
  is "$(awk '/^Groups:/ { print NF - 1 }' "/proc/$wpid/status")" 0 "with no supplementary groups"
  is "$( [ "$(readlink "/proc/$wpid/ns/net")" != "$(readlink /proc/self/ns/net)" ] && echo own)" own "and no network (a network namespace of its own)"
  for size in 102400 10485760 104857600; do
    probe "?put=lat/$size.bin&size=$size&seed=$size" "put-$size"
    ms=$(synced "lat/$size.bin" "$size" "$(val "put-$size" put_sha)")
    is "$( [ "$ms" != never ] && echo synced)" synced "a $size-byte upload reaches the host whole (${ms} ms after its request returned; PHP wrote it in $(val "put-$size" put_ms) ms)"
  done
  is "$(curl -s -H "Host: 127.0.0.1:$port" "http://127.0.0.1:$vport/wp-content/uploads/lat/102400.bin" | sha256sum | cut -d' ' -f1)" "$(val put-102400 put_sha)" \
    "nginx serves the upload from the host's folder"
  is "$(stat -c '%u:%g' "$up/lat/102400.bin")" 1234:1234 "the host's copy is the pool user's"
  probe "?mv=lat/102400.bin&to=moved/deep/r.bin" mv
  eventually 100 "[ -f \"$up/moved/deep/r.bin\" ] && [ ! -e \"$up/lat/102400.bin\" ]"
  is "$(sha256sum "$up/moved/deep/r.bin" 2>/dev/null | cut -d' ' -f1)" "$(val put-102400 put_sha)" "a rename in the guest is a rename on the host"
  probe "?chmod=lat/10485760.bin&mode=600" chmod
  eventually 100 "[ \"\$(stat -c %a \"$up/lat/10485760.bin\")\" = 600 ]"
  is "$(stat -c %a "$up/lat/10485760.bin")" 600 "a chmod in the guest reaches the host"
  probe "?rm=moved" rm
  eventually 100 "[ ! -e \"$up/moved\" ]"
  is "$( [ -e "$up/moved" ] && echo there || echo gone)" gone "a folder removed in the guest is removed on the host, with what was in it"
  # A link planted in the host's folder while the VM runs, where the guest then makes a folder:
  # the writer replaces the link, and writes nothing through it.
  ln -sfn "$outside" "$up/sc-evil"
  probe "?put=sc-evil/x.php&size=10&seed=evil" evil
  eventually 100 "[ -f \"$up/sc-evil/x.php\" ]"
  is "$( [ -d "$up/sc-evil" ] && [ ! -L "$up/sc-evil" ] && echo dir)" dir "a link in the host's folder is replaced by the guest's folder"
  is "$(find "$outside" -mindepth 1 | grep -c .)" 0 "and nothing is written where it pointed (a folder the pool user could write)"
  # A crash before an upload synced: the writer is stopped, the upload committed in the guest,
  # then the launcher is killed. The next start's listing sends it.
  kill -STOP "$wpid"
  probe "?put=crash/c.bin&size=1048576&seed=crash" crash
  # The guest writes its disks back within about a second (its writeback interval and ext4's
  # commit=1), whether or not the host's writer keeps up; this one is stopped.
  sleep 3
  is "$( [ -e "$up/crash/c.bin" ] && echo there || echo absent)" absent "an upload made while the writer is stopped hasn't reached the host"
  fc=$(sed -n 's/.*Firecracker runs jailed as uid [0-9]* gid [0-9]* (pid \([0-9]*\)).*/\1/p' "$dir/sync.log")
  kill -KILL "$PID"; wait "$PID" 2>/dev/null; PID=""
  eventually 50 "! kill -0 $fc 2>/dev/null && ! kill -0 $wpid 2>/dev/null"
  is "$(kill -0 "$wpid" 2>/dev/null && echo alive || echo gone)" gone "the writer dies with the launcher (SIGKILL)"
  sleep 0.5
  if start sync2 "$dir/microvm.json"; then
    ms=$(synced crash/c.bin 1048576 "$(val crash put_sha)")
    is "$( [ "$ms" != never ] && echo synced)" synced "after the crash, the next start's listing sends the upload (${ms} ms after serving)"
    # The writer killed in the middle of a file: the host keeps the old one whole, and nothing
    # partial; the launcher starts a new writer, and the listing sends the new file.
    probe "?put=mid/m.bin&size=10485760&seed=v1" v1
    synced mid/m.bin 10485760 "$(val v1 put_sha)" > /dev/null
    wpid=$(writer_pid)
    kill -STOP "$wpid"
    probe "?put=mid/m.bin&size=209715200&seed=v2" v2
    kill -CONT "$wpid"
    # The moment it holds the nameless file it writes into.
    eventually 100 "ls -l /proc/$wpid/fd 2>/dev/null | grep -q '(deleted)'"
    kill -KILL "$wpid"
    is "$(sha256sum "$up/mid/m.bin" | cut -d' ' -f1)" "$(val v1 put_sha)" "the writer killed mid-file: the host keeps the old file whole"
    is "$(find "$up" -name '.sc-sync-*' | grep -c .)" 0 "and no partial or temporary file"
    ms=$(synced mid/m.bin 209715200 "$(val v2 put_sha)")
    is "$( [ "$ms" != never ] && echo synced)" synced "a new writer, and the listing sends the new file (${ms} ms)"
    has "$dir/sync2.log" "the folder sync's writer ended" "the launcher says the writer ended and connects again"
    # The test's files go, through the guest (its disk is the authority).
    for d in lat mid crash sc-evil; do probe "?rm=$d" "rm-$d"; done
    eventually 100 "[ ! -e \"$up/lat\" ] && [ ! -e \"$up/mid\" ] && [ ! -e \"$up/crash\" ] && [ ! -e \"$up/sc-evil\" ]" || fail "the test's files removed through the guest"
    # A stop syncs first: an upload made just before it is on the host when the launcher exits.
    probe "?put=drain/d.bin&size=104857600&seed=drain" drain
    stop
    is "$(sha256sum "$up/drain/d.bin" 2>/dev/null | cut -d' ' -f1)" "$(val drain put_sha)" "an upload made just before a stop is on the host when the launcher exits"
    lacks "$dir/sync2.log" "did not sync" "the stop's sync drained the folder sync"
  else
    fail "the folder sync: the start after the crash serves"
  fi
else
  fail "the folder sync: the start serves"
fi

echo "# the launcher killed (SIGKILL): the VM goes with it"
if start killed "$dir/microvm.json"; then
  kpid=$(sed -n 's/.*Firecracker runs jailed as uid [0-9]* gid [0-9]* (pid \([0-9]*\)).*/\1/p' "$dir/killed.log")
  cgk=$(cut -d: -f3 "/proc/$kpid/cgroup")
  kill -KILL "$PID"; wait "$PID" 2>/dev/null; PID=""
  i=0; while kill -0 "$kpid" 2>/dev/null && [ "$i" -lt 50 ]; do i=$((i + 1)); sleep 0.1; done
  is "$(kill -0 "$kpid" 2>/dev/null && echo alive || echo gone)" gone "Firecracker (pid $kpid) is gone once its launcher is killed"
  sleep 0.5
  is "$(grep -c " $state/jail" /proc/self/mountinfo)" 0 "nothing stays mounted in the jail"
  is "$( [ -d "/sys/fs/cgroup$cgk" ] && echo left || echo removed)" removed "and its cgroup ($cgk) is removed"
else
  fail "the launcher killed: the start serves"
fi

echo "# Firecracker exits on its own: the launcher stops and clears the jail"
if start fcdied "$dir/microvm.json"; then
  dpid=$(sed -n 's/.*Firecracker runs jailed as uid [0-9]* gid [0-9]* (pid \([0-9]*\)).*/\1/p' "$dir/fcdied.log")
  kill -KILL "$dpid"
  wait "$PID"; rc=$?; PID=""
  is "$( [ "$rc" != 0 ] && echo failed)" failed "the launcher exits non-zero (exit $rc)"
  has "$dir/fcdied.log" "Firecracker exited on its own; the jail is cleared" "and says the jail is cleared"
  is "$(grep -c " $state/jail" /proc/self/mountinfo)" 0 "nothing stays mounted in the jail"
else
  fail "Firecracker exits: the start serves"
fi

echo "# a snapshot that restores but can't start falls back to a cold boot"
if start badsnap "$dir/microvm.json"; then
  # Snapshot this VM after its start message (as a stale or broken snapshot would be): restoring
  # it works, but its guest refuses the next start message.
  (cd "$(jail_root)" && curl -s --unix-socket fc.sock -X PATCH http://localhost/vm -H 'Content-Type: application/json' -d '{"state":"Paused"}' \
    && curl -s --unix-socket fc.sock -X PUT http://localhost/snapshot/create -H 'Content-Type: application/json' \
         -d '{"snapshot_type":"Full","snapshot_path":"/snap/bad.snap","mem_file_path":"/snap/bad.mem"}') > "$dir/badsnap.api" 2>&1
  cp "$(jail_root)/snap/bad.snap" "$dir/bad.snap"
  cp "$(jail_root)/snap/bad.mem" "$dir/bad.mem"
  stop
  snapd=$(find "$state" -maxdepth 1 -name 'snap-*' | head -1)
  install -m 640 -o 0 -g 64000 "$dir/bad.snap" "$snapd/vm.snap"
  install -m 640 -o 0 -g 64000 "$dir/bad.mem" "$snapd/vm.mem"
  rm -f "$dir/bad.snap" "$dir/bad.mem"
  if start badsnap2 "$dir/microvm.json"; then
    has "$dir/badsnap2.log" "the restored guest failed its start message" "the restore works but its start message fails"
    has "$dir/badsnap2.log" "removing the snapshot and cold-booting instead" "so the snapshot goes and the launcher cold-boots"
    is "$(vcode /)" 200 "the front page: 200"
    stop
  else
    fail "a snapshot that can't start: the launcher falls back" "$(tail -3 "$dir/badsnap2.log" | tr '\n' ' ')"
  fi
else
  fail "a bad snapshot: the first start serves"
fi

echo "# a site change, and a larger --write-disk-mib"
date > "$site/sc-mvm-changed.txt"
if start third "$dir/microvm.json" --write-disk-mib 1500; then
  has "$dir/third.log" "built the site disk" "the changed site gets a new disk"
  has "$dir/third.log" "made the snapshot" "and a new snapshot"
  has "$dir/third.log" "grew the writable disk" "the uploads disk grows to the new size"
  is "$(find "$state" -maxdepth 1 -name 'snap-*' | grep -c .)" 1 "the old snapshot is removed"
  probe "" third
  is "$(val third read_uploads)" "first-$$" "and keeps its files"
  is "$(vcode /)" 200 "the front page: 200"
  stop
else
  fail "a site change: the start serves"
fi

echo "# a broken snapshot falls back to a cold boot"
snap=$(find "$state" -maxdepth 1 -name 'snap-*' | head -1)
: > "$snap/vm.snap"
if start fourth "$dir/microvm.json" --write-disk-mib 1500; then
  has "$dir/fourth.log" "failed" "the restore fails"
  has "$dir/fourth.log" "cold-booting instead" "and the launcher cold-boots instead"
  has "$dir/fourth.log" "microVM cold-booted" "the cold-booted VM serves"
  is "$(vcode /)" 200 "the front page: 200"
  stop
else
  fail "a broken snapshot: the start serves"
fi

echo "# --no-snapshot"
if start fifth "$dir/microvm.json" --write-disk-mib 1500 --no-snapshot; then
  has "$dir/fifth.log" "microVM cold-booted" "--no-snapshot: a cold boot"
  lacks "$dir/fifth.log" "snapshot " "and no snapshot is made or used"
  is "$(vcode /)" 200 "the front page: 200"
  stop
else
  fail "--no-snapshot: the start serves"
fi

echo "# a moved site's uploads"
# The uploads disk of a site that was elsewhere, beside a state folder that has none yet.
moved=$dir/states
mkdir -p "$moved/old" "$moved/new"
find "$moved" -mindepth 2 -delete
printf '{"root":"/srv/a-site-that-moved"}\n' > "$moved/old/site.json"
cp "$state"/w*.ext4 "$moved/old/"
cp "$dir/microvm.json" "$site/securecore.json"
"$fpm" --config "$site/securecore.json" --vm-dir "$vm" --state-dir "$moved/new" --vm-user "$vmuser" --listen "unix:$run/moved.sock" --guest-root "$html" > "$dir/moved.log" 2>&1
is "$?" 125 "a new state beside an orphaned uploads disk: the launcher exits 125"
has "$dir/moved.log" "holds the writable disks (uploads) of the site that was at /srv/a-site-that-moved" "naming the orphan"
has "$dir/moved.log" "--state-dir $moved/old" "and how to keep it"
find "$moved" -mindepth 1 -delete

for f in sc-mvm-probe.php sc-status.php sc-mvm-changed.txt wp-content/uploads/sc-big.bin; do rm -f "$site/$f"; done
cp ext/examples/wordpress.json "$site/securecore.json"
echo
if [ "$fails" -eq 0 ]; then echo "all ext-microvm checks passed"; else echo "$fails check(s) failed"; fi
[ "$fails" -eq 0 ]
