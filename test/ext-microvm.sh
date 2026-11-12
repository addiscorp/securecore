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
#      verified, and a kernel without Landlock when layer 3 is on; in the php container (no
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
#      (timed) and nginx serves them; renames, chmods and folder removals follow, removals into
#      the root-only trash; the writer runs as the pool user with no network, no new privileges,
#      seccomp, a memory limit and an empty environment; a link in the host's folder is kept,
#      never written through or removed; a file the owner edits on the host wins over the
#      guest's write, and reaches the guest at the next start with the files the owner added
#      while it was stopped (timed); an upload made while the writer is stopped survives a
#      SIGKILL of the launcher; the writer killed mid-file leaves the old file whole and the
#      next one resends it; a stop drains the sync;
#   3c. egress (#72): curl and PHP's https stream in the guest reach api.wordpress.org on 443 by
#      name through the host (TLS end to end); an IP the guest picks is unreachable; a host layer 2
#      doesn't list is refused in the guest, and by the host too when the guest has no extension;
#   3d. the guest's log (#86): 6000 numbered php-fpm log lines from 240 requests on a restored
#      guest, with sync refusals and a reload among them, all reach the launcher's log, each once;
#   4. SIGTERM stops the VM and the launcher exits 0.
# Exits non-zero on any failure (and at once without /dev/kvm: never a skip). Writes
# .tmp/ext-microvm/. Leaves the stack up.
#   test/ext-microvm.sh            the checks
#   test/ext-microvm.sh bench [n]  front-page p50, host php-fpm vs the microVM, extension off on
#                                  both (bench/layer1.sh's method, #70's numbers), n rounds
#   test/ext-microvm.sh restore [n]  the requests after a restore, timed
#   test/ext-microvm.sh density    N sites' VMs at once: PSS, KSM, restores under load, p50
#                                  (DENSITY_NS, DENSITY_MEM; docs/layer1-microvm.md "Density")
#   test/ext-microvm.sh log        only the guest's log under load (3d, #86)
# Needs: the guest kernel (KERNEL=, default .tmp/mvm/vmlinux-sc from bench/microvm/kernel.sh:
# mirab's kernel plus Landlock and seccomp, until mirab#89 ships them); a host securecore-fpm
# (SECURECORE_FPM=, default .target/release/securecore-fpm); docker, mke2fs, e2fsck, resize2fs,
# curl, jq, python3 (test/sock.py stands in for socat). mirab's files come from scripts/mirab-vm.sh: stable, or MIRAB_MANIFEST=<url>,
# or mirab's newest canary while stable has no vm/.
set -u
cd "$(dirname "$0")/.." || exit 1
# The guest's files (mvm_files, record) are the ext-* suites' microVM target's too. Sourced first:
# this file's own helpers below replace the library's same-named ones.
project=${SECURECORE_EXT_PROJECT:-sc-mvm}
port=${SECURECORE_EXT_PORT:-8095}
SC_TARGET=docker # (the switch is for the ext-* suites; this one drives the launcher itself)
. test/lib/target.sh
what=${1:-check}
rounds=${2:-5}
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
sockpy="$PWD/test/sock.py"
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
# (umask 022: a file the tests put in the php container's config is root's 0644, as a host's is;
# the capture refuses one anyone else may write.)
in_php() { compose exec -T php sh -c "umask 022; $1"; }
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
for t in python3 mke2fs e2fsck resize2fs jq; do command -v "$t" >/dev/null 2>&1 || die "$t isn't on PATH"; done
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
# Layer 3's database gateway (#94) in the guest: test/ext-layer3.sh's database probe, isolated
# beside Contact Form 7, on a page of its own.
cp test/ext/layer3-plugin/sc-l3db.php "$site/wp-content/plugins/sc-l3db.php"
compose exec -T db mariadb -uwordpress -pwordpress-db-password wordpress \
  -e "DROP TABLE IF EXISTS wp_sc_l3db_items; DELETE FROM wp_options WHERE option_name LIKE 'sc\\_l3db\\_%' OR option_name LIKE '\\_transient\\_%sc\\_l3db%'" 2>/dev/null
wp option add sc_l3db_greeting hello-from-wp --autoload=no >/dev/null
wp plugin activate sc-l3db >/dev/null || die "activating the database probe"
for p in $(wp post list --post_type=page --title="L3 db rw" --field=ID); do wp post delete "$p" --force >/dev/null; done
d_rw=$(wp post create --post_type=page --post_status=publish --post_title="L3 db rw" --post_content='[sc_l3db_rw]' --porcelain)
[ -n "$d_rw" ] || die "the database probe's page"
# MariaDB's root by unix_socket (as Debian's packages set it up): whoever connects to the socket
# as uid 0 is the database's root, with no password.
db_root "ALTER USER 'root'@'localhost' IDENTIFIED VIA unix_socket OR mysql_native_password USING PASSWORD('root-db-password')" > /dev/null \
  || die "root@localhost by unix_socket"

# --- the guest's files -------------------------------------------------------------------------
# Firecracker, its jailer and mirab's kernel the way a release resolves them, the guest kernel,
# the root image and installed.json (test/lib/target.sh's mvm_files; mirab's kernel kept as
# $dir/vmlinux-mirab).
w=$(mvm_files "$vm" "$dir" "$project-guest") || die "$w"
echo "$w"
# The test site's environment for the guest's php-fpm (database settings and the vault's env
# sources, the stack's fixed test values), with the database on the guest's loopback. The
# launcher gets it as its own environment and delivers it in each start message (#72); no image
# carries it.
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$(compose ps -q php)" | grep '^WORDPRESS_' \
  | sed 's|^WORDPRESS_DB_HOST=.*|WORDPRESS_DB_HOST=127.0.0.1:3306|' > "$dir/guest.env"
grep -q '^WORDPRESS_DB_HOST=127.0.0.1:3306$' "$dir/guest.env" || die "the guest's env file"
# Variants for the refusals: nothing verified for the rootfs; a kernel without Landlock and
# seccomp filters. (mirab's own kernel had neither until mirab 0.2.1; the kernel here is the
# kernel's bytes with both symbols renamed, recorded like any other, so it is refused by the
# check and never booted.)
for v in vm-norootfs vm-mirabkernel; do
  mkdir -p "$dir/$v"
  find "$dir/$v" -mindepth 1 -delete
  for f in firecracker jailer vmlinux rootfs.ext4; do ln "$vm/$f" "$dir/$v/$f"; done
done
record "$dir/vm-norootfs" no-rootfs
rm -f "$dir/vm-mirabkernel/vmlinux"
LC_ALL=C sed -e 's/landlock_merge_ruleset/landlock_merge_rulesex/g' -e 's/__seccomp_filter/__seccomp_filtex/g' "$vm/vmlinux" > "$dir/vm-mirabkernel/vmlinux"
record "$dir/vm-mirabkernel"
# The jailed user, and nginx's group (the alpine image's nginx is 101:101) for fpm.sock.
vmuser=${SC_VM_USER:-64000:64000}

# The site's files the VM sees: the probe, the status page, writable folders owned by www-data.
cp test/ext/microvm/probe.php "$site/sc-mvm-probe.php"
# An executable script on the site disk: the guest mounts it noexec, so it never runs (#86 review).
printf '#!/bin/sh\necho ran\n' > "$site/sc-mvm-exec.sh"
chmod 755 "$site/sc-mvm-exec.sh"
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
      -e 's#"isolate": \["contact-form-7"\]#"isolate": ["contact-form-7", "sc-l3db"]#' \
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
# fpm_env [flags] &: the launcher with the test site's environment as its own (php-fpm on a host
# gets it the same way), each of those names passed on to the guest (--guest-env). Only ever
# run in the background: it execs, so $! is the launcher.
fpm_env() {
  while IFS= read -r l; do export "$l"; done < "$dir/guest.env"
  # shellcheck disable=SC2046 # the names are plain words
  # This run's own record of the unpackaged files (#101: trust on first use), and MariaDB's uid in
  # the stack (999) as the database's user, whose socket a bare 3306 may reach.
  exec "$fpm" $(sed 's/=.*//; s/^/--guest-env /' "$dir/guest.env") --unpackaged-record "$dir/unpackaged.json" --db-user 999 "$@"
}
dbpass=$(sed -n 's/^WORDPRESS_DB_PASSWORD=//p' "$dir/guest.env")
[ -n "$dbpass" ] || die "the test site's DB password"
# The host's PHP the guest is built from (#101): the stack's php container's (Debian: its
# libraries are dpkg's, php-fpm and the extensions are compiled and root's), read through its root.
php_root() { echo "/proc/$(docker inspect -f '{{.State.Pid}}' "$(compose ps -q php)")/root"; }
[ -x "$(php_root)/usr/local/sbin/php-fpm" ] || die "no php-fpm in the php container at $(php_root)"
start() {
  name=$1 config=$2; shift 2
  cp "$config" "$site/securecore.json"
  fpm_env --config "$site/securecore.json" --vm-dir "$vm" --state-dir "$state" --listen "unix:$run/fpm.sock" \
    --listen-owner 0 --listen-group 101 --listen-mode 0660 --vm-user "$vmuser" --pool-user "$pool" \
    --guest-root "$html" --php-root "$(php_root)" "$@" > "$dir/$name.log" 2>&1 &
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
  # A "microvm" start never execs a php-fpm (it boots the host's, captured, or refuses): the
  # stand-in is only for the values that exec one on the host (#101: --php-fpm is also what the
  # microVM captures, so it is the container's real one there).
  case $name in
    microvm*) fpm_env --config "$site/securecore.json" --state-dir "$state" --vm-user "$vmuser" --pool-user "$pool" --php-root "$(php_root)" "$@" > "$dir/value-$name.log" 2>&1 & ;;
    *) fpm_env --config "$site/securecore.json" --state-dir "$state" --vm-user "$vmuser" --pool-user "$pool" --php-root "$(php_root)" "$@" --php-fpm /bin/sh -- -c "$standin" > "$dir/value-$name.log" 2>&1 & ;;
  esac
  wait $!
  echo "exit=$?" >> "$dir/value-$name.log"
}
# eventually <tenths> <shell test>: until the test holds, or the time is up.
eventually() { n=0; until eval "$2"; do n=$((n + 1)); [ "$n" -lt "$1" ] || return 1; sleep 0.1; done; }

# The guest's log under load (#86): a restored guest; 240 requests, 8 at a time, each writing 25
# numbered lines to php-fpm's log (6000 lines, as layer 2's audit lines go); 20 of them write an
# upload over a link the owner put in the host's folder, which the host's sync refuses (each
# refusal is a line the guest's init logs); a graceful reload between the two halves. Every line
# must be in the launcher's log, once. (`test/ext-microvm.sh log` runs only this.)
log_stress() {
  echo "# the guest's log under load: every line php-fpm writes reaches the launcher's log (#86)"
  # A folder of this run's own: the uploads disk keeps what an earlier run's guest wrote, and the
  # next start syncs that back to the host.
  ln86=sc86-$(date +%s)
  lg=$site/wp-content/uploads/$ln86
  mkdir -p "$lg"
  find "$lg" -mindepth 1 -delete
  chown "$pool" "$lg"
  if start log86 "$dir/microvm.json"; then
    has "$dir/log86.log" "microVM restored from snapshot" "the stress runs on a restored guest (a restore resets the guest's vsock connections)"
    # The links appear on the host after the start: the guest never sees them, the sync refuses them.
    for i in $(seq 0 19); do ln -s /nonexistent "$lg/r-$i"; done
    burst() {
      seq "$1" "$2" | xargs -P 8 -I{} sh -c '
        i={}; q="?log=25&id=r$i"; [ "$i" -lt 20 ] && q="$q&put=$3/r-$i&size=10"
        curl -s -o /dev/null -w "%{http_code}\n" -H "Host: 127.0.0.1:$1" "http://127.0.0.1:$2/sc-mvm-probe.php$q"' sh "$port" "$vport" "$ln86"
    }
    burst 0 119 > "$dir/log86.codes"
    # The second half from the php-fpm a graceful reload started (its own log pipe).
    kill -USR2 "$PID"
    eventually 400 "grep -q \"reloaded the guest's php-fpm gracefully\" \"$dir/log86.log\"" || true
    burst 120 239 >> "$dir/log86.codes"
    is "$(grep -c '^200$' "$dir/log86.codes")" 240 "240 requests answered 200"
    # The lines reach the log after the answers: wait for the last ones, then stop (its sync
    # drains what the guest still holds).
    got() { grep -oE 'sc86 r[0-9]+ [0-9]{3}' "$dir/log86.log" | sort -u | wc -l; }
    eventually 300 '[ "$(got)" -ge 6000 ]' || true
    eventually 300 '[ "$(grep -c "the host refused \"$ln86/r-" "$dir/log86.log")" -ge 20 ]' || true
    stop
    is "$(got)" 6000 "all 6000 numbered lines are in the launcher's log"
    is "$(grep -oE 'sc86 r[0-9]+ [0-9]{3}' "$dir/log86.log" | sort | uniq -d | wc -l)" 0 "and each once"
    is "$(grep -oE "the host refused \"$ln86/r-[0-9]+\"" "$dir/log86.log" | sort -u | wc -l)" 20 "all 20 sync refusals are in the launcher's log"
    has "$dir/log86.log" "reloaded the guest's php-fpm gracefully" "a reload ran during the stress"
    lacks "$dir/log86.log" "guest log line" "no line was lost or counted as lost"
    is "$(find "$lg" -maxdepth 1 -name 'r-*' -type l | wc -l)" 20 "the owner's 20 links are still links"
  else
    fail "the guest's log under load: the start serves"
  fi
  find "$lg" -mindepth 1 -delete
  rmdir "$lg"
}
if [ "$what" = log ]; then
  log_stress
  if [ "$fails" -eq 0 ]; then echo "all log checks passed"; else echo "$fails check(s) failed"; fi
  [ "$fails" -eq 0 ]
  exit
fi

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

if [ "$what" = density ]; then
  # Density (#72, docs/layer1-microvm.md "Density"): N sites' microVMs on this host, for N in
  # DENSITY_NS (default "1 4 8 16", stopping early when MemAvailable would drop under 700 MiB),
  # guest memory DENSITY_MEM MiB (default 512). Each site is a copy of this one in its own Docker
  # volume (sc-density-<k>), with its own state folder: one VM per site, as the product runs them.
  # Two layouts: "own" (each site restores its own snapshot, as today) and "shared" (every site's
  # vm.mem a hard link to site 1's: N VMs restored from one snapshot, so its clean pages are one
  # copy in the page cache). Per N: Firecracker's total and per-VM PSS and RSS (smaps_rollup), with
  # KSM off and then on (30 s of ksmd, pages_sharing), each start's restore time while the earlier
  # VMs run and VM 1 serves a load, and VM 1's front-page p50 (oha, bench's method) with all N up.
  mem=${DENSITY_MEM:-512}
  ns=${DENSITY_NS:-"1 4 8 16"}
  max=$(echo "$ns" | tr ' ' '\n' | sort -n | tail -1)
  dd=$dir/density
  mkdir -p "$dd"
  oha() { docker run --rm --network "${project}_default" "$OHA" --no-tui --output-format json -H "Host: 127.0.0.1:$port" "$@"; }
  avail() { awk '/^MemAvailable:/ { print int($2 / 1024) }' /proc/meminfo; }
  # The sites: copies of this one without its uploads (the writable disk is sized from them).
  find "$site/wp-content/uploads" -mindepth 1 -maxdepth 1 -name 'sc-big.bin' -delete
  k=1
  while [ "$k" -le "$max" ]; do
    docker volume create "sc-density-$k" > /dev/null
    s=$(docker volume inspect -f '{{.Mountpoint}}' "sc-density-$k")
    [ -f "$s/wp-load.php" ] || cp -a "$site/." "$s/"
    cp "$dir/microvm.json" "$s/securecore.json"
    mkdir -p "$dd/state-$k" "$dd/run-$k"
    k=$((k + 1))
  done
  # dstart <k> <log>: site k's launcher in the background (VM 1 listens where mvmweb sends PHP).
  dstart() {
    s=$(docker volume inspect -f '{{.Mountpoint}}' "sc-density-$1")
    l=$dd/run-$1/fpm.sock
    [ "$1" = 1 ] && l=$run/fpm.sock
    fpm_env --config "$s/securecore.json" --vm-dir "$vm" --state-dir "$dd/state-$1" --listen "unix:$l" \
      --listen-owner 0 --listen-group 101 --listen-mode 0660 --vm-user "$vmuser" --pool-user "$pool" \
      --guest-root "$html" --php-root "$(php_root)" --mem "$mem" > "$2" 2>&1 &
    echo $! > "$dd/pid-$1"
    i=0
    until grep -q 'securecore-fpm: serving FastCGI' "$2"; do
      kill -0 "$(cat "$dd/pid-$1")" 2>/dev/null || { echo "  site $1's launcher exited: $(tail -2 "$2" | tr '\n' ' ')"; return 1; }
      i=$((i + 1)); [ "$i" -lt 1800 ] || return 1
      sleep 0.1
    done
  }
  dstop() { for f in "$dd"/pid-*; do [ -f "$f" ] || continue; kill -TERM "$(cat "$f")" 2>/dev/null; wait "$(cat "$f")" 2>/dev/null; rm -f "$f"; done; }
  trap 'dstop; [ -z "$PID" ] || kill -TERM "$PID" 2>/dev/null; kill "$peer_pid" 2>/dev/null; echo 0 > /sys/kernel/mm/ksm/run 2>/dev/null' EXIT
  fcpid() { sed -n 's/.*Firecracker runs jailed as uid [0-9]* gid [0-9]* (pid \([0-9]*\)).*/\1/p' "$1" | tail -1; }
  # pss <n>: "<total PSS MiB> <total RSS MiB>" of the n Firecracker processes.
  pss() {
    t=0 r=0 k=1
    while [ "$k" -le "$1" ]; do
      f=$(fcpid "$dd/run-$k.log")
      t=$((t + $(awk '/^Pss:/ { print $2 }' "/proc/$f/smaps_rollup"))) r=$((r + $(awk '/^Rss:/ { print $2 }' "/proc/$f/smaps_rollup")))
      k=$((k + 1))
    done
    echo "$((t / 1024)) $((r / 1024))"
  }
  # Every site's own snapshot first, one at a time.
  k=1
  while [ "$k" -le "$max" ]; do
    dstart "$k" "$dd/prep-$k.log" || die "site $k's first start"
    dstop
    k=$((k + 1))
  done
  echo "density: guest memory $mem MiB, $(nproc) CPUs, $(awk '/^MemTotal:/ { print int($2 / 1024) }' /proc/meminfo) MiB, KSM $(cat /sys/kernel/mm/ksm/run 2>/dev/null || echo absent)"
  for layout in own shared; do
    if [ "$layout" = shared ]; then
      one=$(find "$dd/state-1" -maxdepth 2 -path '*/snap-*/vm.mem' | head -1)
      k=2
      while [ "$k" -le "$max" ]; do
        ln -f "$one" "$(find "$dd/state-$k" -maxdepth 2 -path '*/snap-*/vm.mem' | head -1)"
        k=$((k + 1))
      done
    fi
    for n in $ns; do
      dstart 1 "$dd/run-1.log" || die "VM 1"
      # VM 1 under load while the others restore (a named container, stopped by its name).
      docker run --rm --name "$project-density-load" --network "${project}_default" "$OHA" --no-tui \
        -H "Host: 127.0.0.1:$port" -z 600s -c 2 http://mvmweb/ > /dev/null 2>&1 &
      load=$!
      restores="" k=2 got=1
      while [ "$k" -le "$n" ]; do
        if [ "$(avail)" -lt $((700 + mem / 2)) ]; then echo "  stopping at $got VMs: $(avail) MiB available"; break; fi
        dstart "$k" "$dd/run-$k.log" || break
        restores="$restores $(sed -n 's/.*restored from snapshot [0-9a-f]* (load and php-fpm ping \([0-9.]*\) ms); ready \([0-9]*\) ms.*/\1\/\2/p' "$dd/run-$k.log")"
        got=$k k=$((k + 1))
      done
      docker stop "$project-density-load" > /dev/null 2>&1; wait "$load" 2>/dev/null
      sleep 5
      # shellcheck disable=SC2046 # two numbers
      set -- $(pss "$got")
      off_t=$1 off_r=$2
      oha -n 20 -c 1 http://mvmweb/ > /dev/null
      oha -n 100 -c 1 http://mvmweb/ > "$dd/p50-$layout-$n.json"
      p50=$(jq -r '.metrics.latency_ms.p50' "$dd/p50-$layout-$n.json")
      ok=$(jq -r '.statusCodeDistribution["200"] // 0' "$dd/p50-$layout-$n.json")
      on_t=- share=-
      if [ -w /sys/kernel/mm/ksm/run ]; then
        echo 1 > /sys/kernel/mm/ksm/run; sleep 30
        # shellcheck disable=SC2046 # two numbers
        set -- $(pss "$got"); on_t=$1
        share=$(( $(cat /sys/kernel/mm/ksm/pages_sharing) * 4 / 1024 ))
        echo 2 > /sys/kernel/mm/ksm/run; sleep 2; echo 0 > /sys/kernel/mm/ksm/run
      fi
      printf '%s N=%s: PSS %s MiB (%s/VM), RSS %s MiB | KSM on: PSS %s MiB, sharing %s MiB | restores (ping/ready ms):%s | VM 1 p50 %.2f ms (%s/100 200s) | %s MiB available\n' \
        "$layout" "$got" "$off_t" "$((off_t / got))" "$off_r" "$on_t" "$share" "${restores:- -}" "$p50" "$ok" "$(avail)"
      dstop
    done
  done
  k=1
  while [ "$k" -le "$max" ]; do
    s=$dd/state-$k
    awk -v s="$s/" 'index($5, s) == 1 { print $5 }' /proc/self/mountinfo | sort -r | while read -r m; do umount -l "$m"; done
    find "$s" -mindepth 1 -xdev -delete
    docker volume rm "sc-density-$k" > /dev/null
    k=$((k + 1))
  done
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
python3 "$sockpy" listen "$sockdir/locked/inner/db.sock" > /dev/null 2>&1 &
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
has "$dir/value-microvm-mirabkernel.log" "has no Landlock and seccomp filters" "microvm with layer 3 on a kernel without Landlock: says why"
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
for d in lat moved mid crash drain sc-evil sc-evil2 host-made wins; do if [ -e "$up/$d" ] || [ -L "$up/$d" ]; then find "$up/$d" -delete; fi; done
# Real uploads, larger than the site's code: the site disk must not carry them.
head -c 300M /dev/urandom > "$site/wp-content/uploads/sc-big.bin"
chown "$pool" "$site/wp-content/uploads/sc-big.bin"
# What asking costs: two asks in a row, nothing between.
qa=$(questions); qb=$(questions); qbase=$((qb - qa))
q0=$(questions)
rm -f "$dir/notify.sock" "$dir/notify.msg"
python3 "$sockpy" recv "$dir/notify.sock" "$dir/notify.msg" &
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
  # The secrets (#72): delivered at each start, never in an image, a snapshot or a console.
  has "$dir/first.log" "the guest's php-fpm gets WORDPRESS_" "the launcher delivers php-fpm's environment by name"
  lacks "$dir/first.log" "$dbpass" "the DB password is in no launcher log line"
  snapd=$(find "$state" -maxdepth 1 -name 'snap-*' | head -1)
  for f in "$vm/rootfs.ext4" "$snapd/vm.mem" "$snapd/vm.snap" "$state/console.log"; do
    is "$(grep -c -a -F -- "$dbpass" "$f")" 0 "the DB password is not in $(basename "$f")"
  done
  is "$(grep -c -a -F -- "$(printf %s "$dbpass" | od -An -tx1 | tr -d ' \n')" "$snapd/vm.mem")" 0 "nor hex-encoded in the snapshot's memory"
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
  is "$(grep -c '^READY=1$' "$dir/notify.msg" 2>/dev/null)" 1 "NOTIFY_SOCKET got READY=1 (systemd Type=notify)"
  # A first start (capture, disks, snapshot) asks systemd for more time before it is ready (#100 review).
  is "$(awk '/^EXTEND_TIMEOUT_USEC=30000000$/ && !r { e = 1 } /^READY=1$/ { r = 1 } END { print (e && r) ? "before" : "no" }' "$dir/notify.msg")" before \
    "and EXTEND_TIMEOUT_USEC=30000000 before it"
  # The guest is the host's own PHP (#101): captured from the php container, checked, layered.
  has "$dir/first.log" "captured the host's PHP 8.3" "the start captures the host's PHP"
  has "$dir/first.log" "checked against dpkg (" "checked against dpkg's records"
  has "$dir/first.log" "built the PHP layer" "and builds the PHP layer"
  has "$dir/first.log" "built the config layer" "and the config layer"
  man=$state/capture-manifest.json
  is "$(stat -c '%a %u' "$man")" "600 0" "the capture's manifest is root's alone"
  is "$(jq -r '[.[] | select(.path | endswith("/securecore.so"))][0].source' "$man")" "unpackaged (root-owned)" "the manifest: securecore.so is unpackaged and root-owned"
  is "$(jq -r '[.[] | select(.source // "" | startswith("dpkg:libxml2"))] | length > 0' "$man")" true "the manifest: libxml2 is checked against dpkg"
  is "$(jq -r '[.[] | select(.sha256 and (.sha256 | length) == 64)] | length > 100' "$man")" true "every file with its sha256 ($(jq length "$man") entries)"
  printf '%s\n' "$(jq -r '[.[] | select(.sha256)] | length' "$man") files, $(jq -r '[.[] | select(.link)] | length' "$man") links, $(jq -r '[.[] | select(.source == "config")] | length' "$man") configs; PHP layer $(du -m "$(find "$state" -maxdepth 1 -name 'php-*.ext4' | head -1)" | cut -f1) MiB on disk ($(stat -c %s "$(find "$state" -maxdepth 1 -name 'php-*.ext4' | head -1)") bytes)" > "$dir/capture-sizes.txt"
  echo "  capture: $(cat "$dir/capture-sizes.txt")"
  r=$(first_page)
  is "${r% *}" 200 "the front page through the jailed microVM: 200 (first page after the restore: ${r#* } ms)"
  is "$(vget / | grep -c yoast-schema-graph)" 1 "it carries Yoast's output"
  probe "?write=first-$$&peer=1" first
  is "$(val first kernel | cut -d. -f1-2)/$( [ "$(val first kernel)" != "$(uname -r)" ] && echo other)" 6.12/other \
    "PHP runs on the guest's kernel, mirab's Linux 6.12 ($(val first kernel); this host is $(uname -r))"
  is "$(val first guest_init)" 1 "PID 1 is securecore-init"
  is "$(val first guest_fpm)" /usr/local/sbin/php-fpm "the guest runs the host's own php-fpm, at its own path"
  is "$(val first php_ini_scan)" /sc/conf/conf.d "with the host's scan folder, from the config layer"
  is "$(val first ini_files | grep -c 'securecore.ini')" 1 "whose files are the host's (securecore.ini among them)"
  probe "?missing=1" missing
  is "$(val missing missing_rc)" 127 "a program the guest lacks isn't there (exit 127)"
  eventually 50 "grep -q 'guest-init: \"sc-no-such-program-101\" isn.t in the guest' \"$dir/first.log\"" || true
  has "$dir/first.log" "guest-init: \"sc-no-such-program-101\" isn't in the guest: the host had no such program to capture" "and the guest's init says which program PHP tried to run"
  is "$(val first euid)" 1234 "the guest's php-fpm workers run as the host's pool user (1234), not the image's www-data"
  is "$(val first netdev)" lo "the guest has loopback only, no network device"
  # #86 review: a program PHP starts gets neither the vsock preload nor its ports, and /tmp runs
  # nothing (the same script runs through /bin/sh, so it is /tmp's noexec that stops it).
  is "$(val first child_env)/$(val first child_sees)" "/." "neither PHP nor a program it starts sees LD_PRELOAD or SC_VSOCK_PORTS"
  is "$(val first tmp_exec)/$(val first sh_exec)" "BLOCKED/ran" "/tmp is noexec in the guest"
  is "$(val first uploads_exec)" BLOCKED "an uploads disk is noexec in the guest"
  is "$(val first site_exec)/$(val first site_sh_exec)" "BLOCKED/ran" "the site disk is noexec in the guest (its script runs only through /bin/sh)"
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
  # Layer 3 in the guest: the database probe's isolated child creates its table and writes and
  # reads it through the gateway (the guest's php-fpm runs each query on its own connection, to
  # MariaDB through the host's socket); on a kernel without Landlock the child fails closed
  # instead ("child refused to start").
  vget "/?page_id=$d_rw" > "$dir/db.first"
  dbv() { sed -n "s/^$1=//p" "$dir/db.first" | head -1; }
  is "$(dbv isolated)" 1 "layer 3's isolated child runs in the guest (Landlock in the guest kernel)"
  for c in dbdelta insert get_row update replace get_var get_col get_results transaction delete counter_written; do
    is "$(dbv "$c")" OK "the guest's isolated plugin: $c through the database gateway"
  done
  is "$(dbv greeting)" hello-from-wp "the guest's isolated plugin reads the site's option"
  is "$(compose exec -T db mariadb -uwordpress -pwordpress-db-password -N wordpress -e 'SELECT name FROM wp_sc_l3db_items' 2>/dev/null)" replaced \
    "its table, made by dbDelta in the guest, holds its row in the host's MariaDB"
  lacks "$dir/first.log" "child refused to start" "no isolated child failed closed"
  lacks "$dir/first.log" "layer3 plugin:sc-l3db database refused" "the gateway refused none of its queries"
  has "$dir/first.log" "securecore: layer2 enforce plugin:wordpress-seo" "layer 2 refuses in the guest as on the host (Yoast's tables)"
  is "$(grep -c '^NOTICE\|^\[' "$dir/first.log")" 0 "every line from the guest is marked 'guest: ' in the launcher's log"
  # A second start message, straight to the guest's control port: refused.
  # (From inside the jail: its full path is longer than a unix socket address holds. The lines go
  # after Firecracker's OK: it drops what follows the CONNECT line in the same write, #70.)
  { printf 'CONNECT 1515\n'; sleep 1; printf 'time 1 0\nentropy %s\ndone\n' "$(printf '00%.0s' $(seq 64))"; sleep 3; } \
    | (cd "$(jail_root)" && python3 "$sockpy" connect v.sock) > "$dir/second-start.out" 2>&1
  has "$dir/second-start.out" "error this boot's start message was already taken" "the guest refuses a second start message"
  # A second launcher on the same state folder.
  "$fpm" --config "$site/securecore.json" --vm-dir "$vm" --state-dir "$state" --vm-user "$vmuser" --php-root "$(php_root)" --unpackaged-record "$dir/unpackaged.json" --listen "unix:$run/other.sock" > "$dir/second-launcher.log" 2>&1
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
  # This site's VM only (its jail id is sc- and 16 hex digits of the app root's sha256): another
  # launcher on this host (a suite's, another agent's) may run a VM of its own.
  is "$(pgrep -fc -- "--id sc-$(printf %s "$site" | sha256sum | cut -c1-16) ")" 0 "no Firecracker left running"
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
  is "$(find "$(jail_root)" -maxdepth 1 -name 'v.sock_*' -printf '%f\n' | sort | tr '\n' ' ')" "v.sock_1514 v.sock_1517 v.sock_3306 v.sock_4444 " "the jail holds only the planned ports (log, egress, MySQL, the peer listener)"
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
# A link the site owner put in the host's folder while the VM was stopped: the host's, so the
# listing keeps it (never follows, removes or pushes it).
ln -sfn "$outside" "$up/sc-evil2"
# synced <rel> <size> <sha256>: waits (60 s at most) for the host's copy, then prints the ms.
synced() {
  t0=$(date +%s%N)
  eventually 600 "[ \"\$(stat -c %s \"$up/$1\" 2>/dev/null)\" = $2 ] && [ \"\$(sha256sum \"$up/$1\" | cut -d' ' -f1)\" = $3 ]" || { echo never; return 1; }
  echo "$(( ($(date +%s%N) - t0) / 1000000 ))"
}
writer_pid() { ps -o pid=,args= --ppid "$PID" | awk '/--sync-writer/ { print $1 }' | head -1; }
if start sync "$dir/microvm.json"; then
  eventually 300 "grep -q 'sync: folder 0 reconciled' \"$dir/sync.log\"" || true
  has "$dir/sync.log" "syncing the writable folders with the host's as uid 1234" "the launcher syncs the writable folders as the pool user"
  has "$dir/sync.log" "sync: folder 0 reconciled" "the guest's listing reconciled the host's folder"
  is "$( [ -L "$up/sc-evil2" ] && echo link)" link "a link planted in the host's folder is the host's: kept"
  has "$dir/sync.log" "not synced, never removed: a symlink on the host" "and logged once as never synced"
  wpid=$(writer_pid)
  is "$(awk '/^Uid:/ { print $2 "/" $3 }' "/proc/$wpid/status" 2>/dev/null)" 1234/1234 "the writer (pid $wpid) runs as the pool user, never root"
  is "$(awk '/^Groups:/ { print NF - 1 }' "/proc/$wpid/status")" 0 "with no supplementary groups"
  is "$( [ "$(readlink "/proc/$wpid/ns/net")" != "$(readlink /proc/self/ns/net)" ] && echo own)" own "and no network (a network namespace of its own)"
  is "$(awk '/^NoNewPrivs:/ { print $2 } /^Seccomp:/ { print $2 }' "/proc/$wpid/status" | tr '\n' /)" 1/2/ "no new privileges, and a seccomp filter"
  is "$(awk '/^Max address space/ { print $4 }' "/proc/$wpid/limits")" 1073741824 "a memory limit (RLIMIT_AS 1 GiB)"
  is "$(tr '\0' '\n' < "/proc/$wpid/environ" | grep -c .)" 0 "and an empty environment"
  is "$(ls -l "/proc/$wpid/fd" | grep -c '\.record')" 0 "the record, read at its start, isn't held open (it is root's to write)"
  is "$(ls -l "/proc/$wpid/fd" | grep -c "$state/trash/")" 2 "it holds each writable folder's trash (two folders)"
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
  trashed=$(find "$state/trash" -path '*/moved/deep/r.bin' | head -1)
  is "$(sha256sum "$trashed" 2>/dev/null | cut -d' ' -f1)" "$(val put-102400 put_sha)" "into the trash (${trashed#"$state"/}), never unlinked"
  is "$(stat -c '%U %a' "$state/trash" "$(dirname "$(dirname "$(dirname "$(dirname "$trashed")")")")" | tr '\n' ' ')" "root 700 root 700 " \
    "the trash and its day are root's, 0700, outside the web root"
  # A link planted in the host's folder while the VM runs, where the guest then makes a folder:
  # the host's link wins; nothing is written through it, and it stays.
  ln -sfn "$outside" "$up/sc-evil"
  probe "?put=sc-evil/x.php&size=10&seed=evil" evil
  eventually 100 "grep -q 'sc-evil.*is not a folder on the host' \"$dir/sync.log\"" || true
  is "$( [ -L "$up/sc-evil" ] && echo link)" link "a link in the host's folder is never replaced"
  has "$dir/sync.log" '"sc-evil" is not a folder on the host' "the writer says so"
  is "$(find "$outside" -mindepth 1 | grep -c .)" 0 "and nothing is written where it pointed (a folder the pool user could write)"
  # A file the site owner edits on the host wins over the guest's next write to it.
  probe "?put=wins/w.txt&size=1000&seed=w1" w1
  synced wins/w.txt 1000 "$(val w1 put_sha)" > /dev/null
  printf 'the owner edited this on the host\n' > "$up/wins/w.txt"
  owner_sha=$(sha256sum "$up/wins/w.txt" | cut -d' ' -f1)
  probe "?put=wins/w.txt&size=2000&seed=w2" w2
  eventually 100 "grep -q 'wins/w.txt.*changed on the host' \"$dir/sync.log\"" || true
  is "$(sha256sum "$up/wins/w.txt" | cut -d' ' -f1)" "$owner_sha" "a file the owner changed on the host is never overwritten by the guest"
  has "$dir/sync.log" "the host's copy wins" "the writer says the host's copy wins"
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
  # Files the site owner adds on the host while the VM is stopped (an SFTP upload, a restore):
  # pushed into the guest's disk at the next start. 50 files of 1 MiB and one of 100 MiB.
  mkdir -p "$up/host-made"
  for n in $(seq 1 50); do head -c 1M /dev/urandom > "$up/host-made/f$n.bin"; done
  head -c 100M /dev/urandom > "$up/host-made/big.bin"
  chown -R "$pool" "$up/host-made"
  host_sha=$(sha256sum "$up/host-made/big.bin" | cut -d' ' -f1)
  ino0=$(stat -c %i "$up/host-made/f1.bin" "$up/host-made/big.bin" | tr '\n' ' ')
  if start sync2 "$dir/microvm.json"; then
    ms=$(synced crash/c.bin 1048576 "$(val crash put_sha)")
    is "$( [ "$ms" != never ] && echo synced)" synced "after the crash, the next start's listing sends the upload (${ms} ms after serving)"
    if [ "$ms" = never ]; then
      probe "?sha=crash/c.bin" crash-guest
      echo "  the guest's copy: $(val crash-guest sha); the host's: $(stat -c %s "$up/crash/c.bin" 2>&1); want $(val crash put_sha)"
      grep -E 'crash|refused|sync:' "$dir/sync2.log" | tail -8 | sed 's/^/  | /'
    fi
    eventually 300 "grep -q 'folder 0 reconciled' \"$dir/sync2.log\"" || true
    pushed=$(grep -m1 'folder 0 reconciled' "$dir/sync2.log")
    echo "  import at the start: ${pushed#*sync: }"
    is "$(echo "$pushed" | sed -n 's/.* \([0-9]*\) pushed to the guest.*/\1/p')" 53 "the host's new files (51) and folder, and the owner's edit, are pushed into the guest at the start"
    probe "?sha=host-made/big.bin" pushed
    is "$(val pushed sha)" "$host_sha" "the guest has the host's file, whole"
    probe "?sha=wins/w.txt" wins
    is "$(val wins sha)" "$owner_sha" "and the owner's edit, which won"
    # A push that came back as a change would replace the host's file (a new inode).
    sleep 2
    is "$(stat -c %i "$up/host-made/f1.bin" "$up/host-made/big.bin" | tr '\n' ' ')" "$ino0" "nothing pushed comes back to the host as a change"
    # The writer killed in the middle of a file: the host keeps the old one whole, and nothing
    # partial; the launcher starts a new writer, and the listing sends the new file.
    probe "?put=mid/m.bin&size=10485760&seed=v1" v1
    synced mid/m.bin 10485760 "$(val v1 put_sha)" > /dev/null
    wpid=$(writer_pid)
    kill -STOP "$wpid"
    probe "?put=mid/m.bin&size=209715200&seed=v2" v2
    kill -CONT "$wpid"
    # The moment it holds the nameless file it writes into: the kill lands mid-file, or the test
    # proves nothing.
    if eventually 100 "ls -l /proc/$wpid/fd 2>/dev/null | grep -q '(deleted)'"; then
      pass "the writer holds its nameless temporary file mid-transfer"
    else
      fail "the writer holds its nameless temporary file mid-transfer" "never seen in /proc/$wpid/fd"
    fi
    kill -KILL "$wpid"
    is "$(sha256sum "$up/mid/m.bin" | cut -d' ' -f1)" "$(val v1 put_sha)" "the writer killed mid-file: the host keeps the old file whole"
    is "$(find "$up" -name '.sc-sync-*' | grep -c .)" 0 "and no partial or temporary file"
    ms=$(synced mid/m.bin 209715200 "$(val v2 put_sha)")
    is "$( [ "$ms" != never ] && echo synced)" synced "a new writer, and the listing sends the new file (${ms} ms)"
    has "$dir/sync2.log" "the folder sync's writer ended" "the launcher says the writer ended and connects again"
    # The test's files go, through the guest (the sync wrote or took them all, so they are the
    # guest's to remove); the links are the host's, removed here.
    for d in lat mid crash host-made wins; do probe "?rm=$d" "rm-$d"; done
    probe "?rm=sc-evil" rm-sc-evil
    eventually 100 "[ ! -e \"$up/lat\" ] && [ ! -e \"$up/mid\" ] && [ ! -e \"$up/crash\" ] && [ ! -e \"$up/host-made\" ] && [ ! -e \"$up/wins\" ]" \
      || fail "the test's files removed through the guest" "$(ls "$up" | tr '\n' ' ')"
    rm -f "$up/sc-evil" "$up/sc-evil2"
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

echo "# egress (#72): named hosts on the egress ports, through the host"
wporg=https://api.wordpress.org/core/version-check/1.7/
if start egress "$dir/microvm.json"; then
  has "$dir/egress.log" "the guest reaches named hosts on ports [53, 443] through the host: only layer 2's hosts (127.0.0.1, api.stripe.com, api.wordpress.org, downloads.wordpress.org)" \
    "the launcher says which names the guest may reach"
  probe "?curl=$wporg" curl
  is "$(val curl curl_code)" 200 "curl in the guest reaches api.wordpress.org over 443 ($(val curl curl_error))"
  is "$(val curl curl_body | grep -c '"offers"')" 1 "and gets WordPress's answer, through TLS end to end"
  probe "?stream=$wporg" stream
  is "$(val stream stream_ok)" 1 "PHP's https stream reaches it too ($(val stream stream_error))"
  has "$dir/egress.log" "egress: api.wordpress.org:443 via" "the host connected it, by name"
  # The host's end of an egress connection is the pool user's (uid-based firewalls apply).
  probe "?tcp=api.wordpress.org:443&hold=4" hold > /dev/null 2>&1 &
  hold_pid=$!
  eventually 40 "ss -Htne state established '( dport = :443 )' | grep -q 'uid:1234 '" || true
  owners=$(ss -Htne state established '( dport = :443 )' | grep -o 'uid:[0-9]*' | sort -u | tr '\n' ' ')
  wait "$hold_pid"
  is "$(val hold tcp)" CONNECTED "a plain socket in the guest reaches api.wordpress.org:443 by name"
  is "$(echo "$owners" | grep -c 'uid:1234 ')" 1 "the host connects it as the pool user (1234; owners of :443 connections: ${owners:-none})"
  has "$dir/egress.log" "egress connects only to public addresses that aren't this host's, as the pool user" "the launcher says so"
  # With the extension on, layer 2 refuses an unlisted IP first (no errno): the route itself is
  # checked below, with the extension off.
  probe "?tcp=1.1.1.1:443" ip
  is "$(val ip tcp | cut -c1-6)" FAILED "an IP the guest picks itself, unlisted, is refused in the guest (got '$(val ip tcp)')"
  probe "?curl=https://example.com/" other
  is "$(val other curl_code)" 0 "a host layer 2 doesn't list is refused in the guest ($(val other curl_error | cut -c1-120))"
  stop
else
  fail "egress: the start serves"
fi
# Without the extension (nothing in the guest checks names), the host still does.
if start egress-noext "$dir/microvm.json" --guest-arg sc.ext=0 --no-snapshot; then
  # Nothing in the guest refuses it now: only the missing route does (ENETUNREACH, 101).
  probe "?tcp=1.1.1.1:443" noext-ip
  is "$(val noext-ip tcp | cut -d' ' -f1-2)" "FAILED 101" "an IP the guest picks itself is unreachable: no network device, no route (got '$(val noext-ip tcp)')"
  probe "?curl=https://example.com/" noext
  is "$(val noext curl_code)" 0 "with no extension in the guest, a host no config lists is still refused"
  has "$dir/egress-noext.log" "egress refused: example.com:443: example.com is in none of layer 2's host lists" "by the host, which says why"
  probe "?curl=$wporg" noext-ok
  is "$(val noext-ok curl_code)" 200 "and a listed one still works"
  stop
else
  fail "egress without the extension: the start serves"
fi
# Layer 2 in log mode: the host lets an unlisted name through, and logs it as layer 2 would.
sed 's/"mode": "enforce"/"mode": "log"/' "$dir/microvm.json" > "$dir/microvm-log.json"
if start egress-log "$dir/microvm-log.json" --guest-arg sc.ext=0 --no-snapshot; then
  has "$dir/egress-log.log" "any name, layer 2 logging those not in its hosts" "with layer 2 in log mode the launcher says any name goes, logged"
  probe "?tcp=example.com:443" logmode
  is "$(val logmode tcp)" CONNECTED "an unlisted host is reached in log mode (layer 2's own decision)"
  eventually 30 "grep -q 'egress: example.com:443 via .*(layer2 log: refused in enforce by the host rule)' \"$dir/egress-log.log\"" || true
  has "$dir/egress-log.log" "(layer2 log: refused in enforce by the host rule)" "and the host logs it as layer 2 would have refused it"
  stop
else
  fail "egress in log mode: the start serves"
fi

log_stress

echo "# a guest booted for another protocol gets no start message, so no secret (#72)"
# What an older root image's init is to this launcher: the handshake fails before any env line.
if start oldproto "$dir/microvm.json" --guest-arg sc.proto=3 --no-snapshot; then
  fail "a guest booted for protocol 3 is refused before its start message" "the launcher served"
  stop
else
  has "$dir/oldproto.log" "doesn't speak this launcher's protocol" "the handshake fails first: the launcher stops before its start message"
  has "$dir/oldproto.log" "speaks protocol" "the guest's init says which protocol it speaks"
  lacks "$dir/oldproto.log" "$dbpass" "the DB password is nowhere in the launcher's log"
  lacks "$dir/oldproto.log" "$(printf %s "$dbpass" | od -An -tx1 | tr -d ' \n')" "nor hex-encoded"
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

echo "# the host's own PHP (#101): cached by what it holds, validated, refused with the file named"
# ms_to_ready <log>: the launcher's own "ready … ms" or "started … ms after launch" figure.
ready_ms() { sed -n 's/.*ready \([0-9]*\) ms, started \([0-9]*\) ms after launch.*/\2/p' "$1" | tail -1; }
# A normal restore: nothing changed, so nothing is captured, hashed or built.
if start same "$dir/microvm.json"; then
  has "$dir/same.log" "is as captured before" "a start with nothing changed reuses the capture (no hashing, no loader)"
  lacks "$dir/same.log" "built the PHP layer" "and builds no layer"
  has "$dir/same.log" "microVM restored from snapshot" "and restores"
  echo "  time to ready, a normal restore: $(ready_ms "$dir/same.log") ms" | tee -a "$dir/measure.txt"
  stop
else
  fail "a start with nothing changed serves"
fi
# A php.ini-only change: only the (small) config layer is rebuilt, then a new snapshot.
in_php "printf 'memory_limit = 201M\n' > /usr/local/etc/php/conf.d/zz-sc101.ini"
if start ini "$dir/microvm.json"; then
  has "$dir/ini.log" "built the config layer" "a php.ini change rebuilds the config layer"
  lacks "$dir/ini.log" "built the PHP layer" "and not the PHP layer"
  has "$dir/ini.log" "capture: " "and the change is logged"
  probe "" ini
  is "$(val ini memory_limit)" 201M "the guest's PHP has the host's new setting"
  echo "  time to ready, a php.ini-only change: $(ready_ms "$dir/ini.log") ms" | tee -a "$dir/measure.txt"
  stop
else
  fail "a php.ini change: the start serves"
fi
in_php "rm -f /usr/local/etc/php/conf.d/zz-sc101.ini"
# refuses <name> <expected file> <why>: microvm refuses (exit 125) with the capture's line naming the
# file, and php-fpm never runs.
# refuses <name> <file|""> <why> [config] [nolisten]: as above; with "" the refusal is the launcher's
# own (not the capture's) and only <why> is checked; nolisten: no --listen (several pools).
refuses() {
  cp "${4:-$dir/microvm.json}" "$site/securecore.json"
  if [ "${5:-}" = nolisten ]; then rl=""; else rl="unix:$run/fpm.sock"; fi
  fpm_env --config "$site/securecore.json" --vm-dir "$vm" --state-dir "$state" ${rl:+--listen "$rl"} \
    --vm-user "$vmuser" --pool-user "$pool" --guest-root "$html" --php-root "$(php_root)" > "$dir/$1.log" 2>&1 &
  rp=$!
  # Never a hang: a launcher that starts serving instead is stopped.
  eventually 900 "! kill -0 $rp 2>/dev/null || grep -q 'serving FastCGI' \"$dir/$1.log\"" || true
  kill -0 "$rp" 2>/dev/null && kill -TERM "$rp"
  wait "$rp"
  is "$?" 125 "$1: microvm refuses to start (exit 125)"
  [ -z "$2" ] || has "$dir/$1.log" "the host's PHP can't be captured: $2" "$1: naming $2"
  has "$dir/$1.log" "$3" "$1: $3"
  lacks "$dir/$1.log" "serving FastCGI" "$1: nothing served"
}
# A library a package installed, changed after: its bytes don't match dpkg's record.
lib=$(jq -r '[.[] | select(.sha256 and (.source // "" | startswith("dpkg:libxml2")))][0].from' "$man")
in_php "cp -p $lib /tmp/sc101-lib && printf x >> $lib"
refuses tampered-lib "$lib" "don't match what dpkg recorded for libxml2"
in_php "cat /tmp/sc101-lib > $lib && touch -r /tmp/sc101-lib $lib && rm -f /tmp/sc101-lib"
# An extension the pool user may write (any file not root's alone).
ext=$(jq -r '[.[] | select(.sha256 and (.path | endswith("/sockets.so")))][0].path' "$man")
in_php "chown ${pool%%:*} $ext"
refuses writable-ext "$ext" "everything captured must be root's and writable by no one else"
in_php "chown 0:0 $ext"
# An extension changed in place, still root's 0644: this image compiles its own, so no package
# records it; the install's record (trust on first use, written at this run's first start) does.
# (A dpkg-packaged one is in test/ext-capture.sh.)
in_php "cp -p $ext /tmp/sc101-ext && printf x >> $ext"
refuses tampered-ext "$ext" "recorded at install"
in_php "cat /tmp/sc101-ext > $ext && touch -r /tmp/sc101-ext $ext && rm -f /tmp/sc101-ext"
# A config that loads native code from outside PHP's folders.
in_php "mkdir -p /opt/sc101 && cp $ext /opt/sc101/evil.so && printf 'extension=/opt/sc101/evil.so\n' > /usr/local/etc/php/conf.d/zz-sc101-evil.ini"
refuses outside-so "/usr/local/etc/php/conf.d/zz-sc101-evil.ini:1" "extension = /opt/sc101/evil.so loads native code from outside the captured set"
in_php "rm -rf /opt/sc101 /usr/local/etc/php/conf.d/zz-sc101-evil.ini"
# After each refusal the host is as it was: the next start serves (and recaptures).
if start after-tamper "$dir/microvm.json"; then
  is "$(vcode /)" 200 "with the host restored, the microVM serves again"
  stop
else
  fail "after the refusals: the start serves"
fi
# A bare 3306 and PHP's localhost (#100 review): the database through the host's MySQL socket,
# which PHP's own setting names (mysqli.default_socket), with WordPress's DB_HOST=localhost.
sed "s|{ \"port\": 3306, \"socket\": \"$mysqld/mysqld.sock\" }|{ \"port\": 3306 }|" "$dir/microvm.json" > "$dir/bare.json"
grep -q '{ "port": 3306 }' "$dir/bare.json" || die "the bare-3306 fixture"
in_php "printf 'mysqli.default_socket = $mysqld/mysqld.sock\n' > /usr/local/etc/php/conf.d/zz-sc101-db.ini"
cp "$dir/guest.env" "$dir/guest.env.keep"
sed 's|^WORDPRESS_DB_HOST=.*|WORDPRESS_DB_HOST=localhost|' "$dir/guest.env.keep" > "$dir/guest.env"
if start bare "$dir/bare.json"; then
  has "$dir/bare.log" "port 3306 has no socket or address: DB_HOST is localhost, so it goes to the host's MySQL socket $mysqld/mysqld.sock" \
    "a bare 3306 goes where the site's DB_HOST says: the host's MySQL socket (the database's own, uid 999)"
  is "$(vcode /)" 200 "and WordPress reaches its database at localhost (the front page: 200)"
  is "$(vget / | grep -c yoast-schema-graph)" 1 "with its content"
  stop
else
  fail "a bare 3306: the start serves"
fi
# A socket any local user could have put there is never the database (#102 review): the same
# start with the socket another user's refuses, naming it.
chown 1234:1234 "$mysqld/mysqld.sock"
refuses untrusted-db "" "the MySQL socket $mysqld/mysqld.sock is owned by uid 1234" "$dir/bare.json"
chown 999:999 "$mysqld/mysqld.sock"
cp "$dir/guest.env.keep" "$dir/guest.env"
in_php "rm -f /usr/local/etc/php/conf.d/zz-sc101-db.ini"
# One microVM per pool (#100 review): each listens where its pool says (with its allowed_clients
# and ACLs, #102 review), the launcher tells systemd once both serve, and a stop stops both. Each
# pool names this site (chdir).
in_php "printf '[www]\nchdir = /var/www/html\nlisten = $sockdir/www.sock\nlisten.acl_users = www-data\n[second]\nchdir = /var/www/html\nuser = www-data\ngroup = www-data\nlisten = 127.0.0.1:9339\nlisten.allowed_clients = 192.0.2.1\npm = static\npm.max_children = 2\nenv[SC_POOL] = second\n' > /usr/local/etc/php-fpm.d/zz-sc101-pools.conf"
cp "$dir/microvm.json" "$site/securecore.json"
rm -f "$dir/notify-pools.sock" "$dir/notify-pools.msg"
python3 "$sockpy" recv "$dir/notify-pools.sock" "$dir/notify-pools.msg" &
npid=$!
sleep 0.3
NOTIFY_SOCKET=$dir/notify-pools.sock fpm_env --config "$site/securecore.json" --vm-dir "$vm" --state-dir "$state" --vm-user "$vmuser" \
  --guest-root "$html" --php-root "$(php_root)" > "$dir/pools.log" 2>&1 &
PID=$!
eventually 1800 "grep -q 'every pool.s microVM serves' \"$dir/pools.log\" || ! kill -0 $PID 2>/dev/null" || true
has "$dir/pools.log" "one microVM per pool: www, second" "two pools: a microVM each"
has "$dir/pools.log" "every pool's microVM serves (www, second)" "both serve"
is "$(python3 test/ext/microvm/fcgi-ping.py "unix:$sockdir/www.sock")" pong "the www pool's php-fpm answers where its pool listens (root: always)"
# As other users: the ping and the socket where they can reach them (the test's own folders are
# root's alone), so a refusal is the launcher's, not a path's.
cp test/ext/microvm/fcgi-ping.py "$sockdir/fcgi-ping.py" && chmod 644 "$sockdir/fcgi-ping.py"
as_ping() { setpriv --reuid "$1" --regid "$1" --clear-groups python3 "$sockdir/fcgi-ping.py" "unix:$sockdir/www.sock" 2>/dev/null; }
is "$(as_ping 33)" pong "www-data, in its listen.acl_users: answered"
is "$(as_ping 65534)" "" "nobody, not in its ACLs: refused (the socket is 0666, the launcher checks the peer)"
has "$dir/pools.log" "refused a FastCGI connection: uid 65534 gid 65534 isn't in the pool's listen.acl_users" "and the launcher says so"
is "$(python3 test/ext/microvm/fcgi-ping.py "127.0.0.1:9339" 2>/dev/null)" "" "the second pool (TCP) refuses 127.0.0.1, which its listen.allowed_clients doesn't list"
has "$dir/pools.log" "refused a FastCGI connection: 127.0.0.1 isn't in the pool's listen.allowed_clients" "and the launcher says so"
is "$(find "$state/pool-www" "$state/pool-second" -maxdepth 1 -name 'conf-*.ext4' | wc -l)" 2 "each pool has its own config layer and state folder"
is "$(grep -c '^READY=1$' "$dir/notify-pools.msg")" 1 "systemd is told once, when both serve"
stop
is "$STOPPED" 0 "SIGTERM stops both pools' microVMs, exit 0"
is "$(pgrep -f -- "--id sc-[0-9a-f]*-[0-9a-f]\{6\}" | wc -l)" 0 "no pool's Firecracker is left running"
kill "$npid" 2>/dev/null
# A pool of another site (#102 review, Sami's decision): microvm refuses the whole config, naming
# it (auto falls back to gelada once, with the same reason).
in_php "printf '[www]\nchdir = /var/www/html\nlisten = $run/www.sock\n[other]\nchdir = /srv/other-site\nuser = www-data\nlisten = $run/other.sock\n' > /usr/local/etc/php-fpm.d/zz-sc101-pools.conf"
refuses other-site "" "pool [other] serves another site (/srv/other-site)" "$dir/microvm.json" nolisten
in_php "rm -f /usr/local/etc/php-fpm.d/zz-sc101-pools.conf"
rm -f "$run/www.sock" "$run/second.sock" "$run/other.sock" "$sockdir/www.sock" "$sockdir/fcgi-ping.py"

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
"$fpm" --config "$site/securecore.json" --vm-dir "$vm" --state-dir "$moved/new" --vm-user "$vmuser" --php-root "$(php_root)" --unpackaged-record "$dir/unpackaged.json" --listen "unix:$run/moved.sock" --guest-root "$html" > "$dir/moved.log" 2>&1
is "$?" 125 "a new state beside an orphaned uploads disk: the launcher exits 125"
has "$dir/moved.log" "holds the writable disks (uploads) of the site that was at /srv/a-site-that-moved" "naming the orphan"
has "$dir/moved.log" "--state-dir $moved/old" "and how to keep it"
find "$moved" -mindepth 1 -delete

for f in sc-mvm-probe.php sc-mvm-exec.sh sc-status.php sc-mvm-changed.txt wp-content/uploads/sc-big.bin; do rm -f "$site/$f"; done
cp ext/examples/wordpress.json "$site/securecore.json"
echo
if [ "$fails" -eq 0 ]; then echo "all ext-microvm checks passed"; else echo "$fails check(s) failed"; fi
[ "$fails" -eq 0 ]
