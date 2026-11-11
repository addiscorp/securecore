# shellcheck shell=sh
# Where the test/ext-*.sh suites run php-fpm (addiscorp/securecore#72). One switch, SC_TARGET:
#   docker   (the default) php-fpm in the stack's php container, as the suites always did;
#   microvm  php-fpm in a Firecracker guest started by the host's securecore-fpm (as root, on a
#            KVM host), with the site's environment as the launcher's own (delivered to the guest
#            at each start). The stack's nginx `mvmweb` (docker/compose.ext-microvm.yml) sends
#            PHP to the launcher's socket and serves the static files from the same site volume.
# A suite sets `project`, `port` and `dir` (and `compose_files` when it needs more than
# compose.yml + compose.ext.yml), then sources this file. It gets the same helpers on both
# targets, so a suite is one file with no target branches, except where a check has no meaning
# in the guest: those are `na <label> <reason>` on the microVM target, said per check, never a
# silent skip.
#
#   compose …            docker compose for this suite's project (with the microVM's overlay)
#   base / code <path>   the site's URL (on microvm: mvmweb's port, the guest's PHP)
#   stack_up             build, start, install WordPress, put examples/wordpress.json, serve 200
#   put <json>           the site's securecore.json (on microvm: as the guest needs it, below)
#   put_live <json>      replace it while serving (docker: in place, reloaded by the extension;
#                        microvm: the guest's site disk is a copy made at each start, so a
#                        restart of the launcher)
#   conf_sha <json>      the sha256 of what `put` writes for <json>
#   php_restart [args]   restart php-fpm (microvm: the launcher; args go to it, e.g.
#                        --guest-arg sc.ext=0); php_start; php_state ("<state> <exit code>");
#                        wait_exited
#   site_sync            after changing the site's files: the guest sees them at its next start
#   now / phplog <mark>  php-fpm's log from <mark> on (microvm: the launcher's, guest lines
#                        marked "guest: ")
#   on_microvm           true on the microVM target
#   na <label> <reason>  a check that can't apply on this target, with why
#
# On microvm a config is translated for the guest (mvm_conf): layer1.isolation becomes
# "microvm" (an `off` or `gelada` config would run php-fpm on the host, outside the target), the
# example's layer1 fills in a config that has none, and MySQL's port goes to MariaDB's socket
# (docker/compose.ext-microvm.yml puts it on the host). Layer 2 and 3 are as the suite wrote them.
# Fresh projects: the microVM target's default project is the suite's with -mvm and its port is
# +200, so it never shares a site volume, an image or a port with a docker run. stack_up recreates
# a container whose image is gone instead of failing on it.
#
# Needs on microvm (as test/ext-microvm.sh): /dev/kvm, root, the guest kernel (KERNEL=, default
# .tmp/mvm/vmlinux-sc from bench/microvm/kernel.sh), a host securecore-fpm (SECURECORE_FPM=,
# default .target/release/securecore-fpm), mke2fs, e2fsck, resize2fs, curl, jq, python3.

SC_TARGET=${SC_TARGET:-docker}
case $SC_TARGET in
  docker | microvm) ;;
  *) echo "FAIL SC_TARGET=$SC_TARGET: want docker or microvm"; exit 1 ;;
esac
on_microvm() { [ "$SC_TARGET" = microvm ]; }
if on_microvm; then
  [ -n "${SECURECORE_EXT_PROJECT:-}" ] || project=$project-mvm
  [ -n "${SECURECORE_EXT_PORT:-}" ] || port=$((port + 200))
fi
base=http://127.0.0.1:$port
html=/var/www/html
conf=$html/securecore.json
compose_files=${compose_files:-"-f docker/compose.yml -f docker/compose.ext.yml"}
nas=0
na() { echo "n/a  $1 (on the microVM target: $2)"; nas=$((nas + 1)); }
# A stretch of checks that can't apply: set NA_WHY=<reason> (only on microvm), and a suite's
# check helpers start with `na_now <label> && return`, so each check in it is still named, n/a.
NA_WHY=
na_now() { [ -n "$NA_WHY" ] || return 1; na "$1" "$NA_WHY"; }
# The suite's last line: how many checks didn't apply here. On the microVM target the count is
# gated (#86 review): it must be the suite's number in test/lib/na-expected.txt, so a change that
# turns real checks into n/a fails the suite (and one that turns n/a into real checks updates the
# file in the same change). Counts as a failed check (the suite's `fails`).
na_summary() {
  [ "$nas" -eq 0 ] || echo "$nas check(s) not applicable on the $SC_TARGET target (n/a above, each with why)"
  on_microvm || return 0
  _suite=$(basename "$0" .sh)
  _want=$(awk -v s="$_suite" '$1 == s { print $2 }' test/lib/na-expected.txt 2>/dev/null)
  if [ -z "$_want" ]; then
    echo "FAIL n/a count: $_suite has no line in test/lib/na-expected.txt (it has $nas)"; fails=$((fails + 1))
  elif [ "$nas" != "$_want" ]; then
    echo "FAIL n/a count: $nas check(s) n/a on the microVM target, test/lib/na-expected.txt says $_want"; fails=$((fails + 1))
  else
    echo "ok   n/a count: $nas, as test/lib/na-expected.txt says"
  fi
}
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
code() { curl -s -o /dev/null -w '%{http_code}' "$base$1"; }
# wait_200 [path]
wait_200() { i=0; until [ "$(code "${1:-/}")" = 200 ]; do i=$((i + 1)); [ "$i" -lt 60 ] || return 1; sleep 1; done; }

# --- the microVM's paths -------------------------------------------------------------------------
# Per project: the launcher's state, its socket folder (mounted into mvmweb), its log, pid and
# exit status. Shared: the guest's files (Firecracker, jailer, kernel, root image), built once.
# MariaDB's socket folder is under /run, where the VM's user can reach it.
tdir=$PWD/.tmp/sc-target/$project
mvm_vm=$PWD/.tmp/sc-target/vm
mvm_state=$tdir/state
mvm_run=$tdir/run
mvm_log=$tdir/launcher.log
mvm_sockdir=/run/$project
mvm_mysqld=$mvm_sockdir/mysqld
mvm_fpm=${SECURECORE_FPM:-$PWD/.target/release/securecore-fpm}
mvm_kernel=${KERNEL:-$PWD/.tmp/mvm/vmlinux-sc}
# The VM's jailed user, and the site's pool user: www-data, who owns the site in the stack.
mvm_vmuser=${SC_VM_USER:-64000:64000}
mvm_pool=33:33

compose() {
  if on_microvm; then
    # shellcheck disable=SC2086 # the file list is words
    SECURECORE_PORT=$((port + 1000)) SC_MVM_PORT=$port SC_MVM_MYSQLD=$mvm_mysqld SC_MVM_RUN=$mvm_run \
      docker compose $compose_files -f docker/compose.ext-microvm.yml -p "$project" "$@"
  else
    # shellcheck disable=SC2086
    SECURECORE_PORT=$port docker compose $compose_files -p "$project" "$@"
  fi
}
site_dir() { docker volume inspect -f '{{.Mountpoint}}' "${project}_wp"; }

# --- the site's config -----------------------------------------------------------------------------
# mvm_conf <json>: the config as the guest needs it (above). A file jq can't read goes as it is.
mvm_conf() {
  jq --arg sock "$mvm_mysqld/mysqld.sock" --slurpfile ex ext/examples/wordpress.json '
    (if (.layer1 | type) == "object" and (.layer1 | has("network")) then .layer1 else $ex[0].layer1 + (.layer1 // {}) end) as $l1
    | .layer1 = ($l1 | .isolation = "microvm"
        | .network.connect = [(.network.connect // [])[] | if .port == 3306 then { port: 3306, socket: $sock } else . end])' "$1" 2>/dev/null \
    || cat "$1"
}
# conf_for <json> <out>: what `put` writes.
conf_for() { if on_microvm; then mvm_conf "$1" > "$2"; else cp "$1" "$2"; fi; }
conf_sha() { conf_for "$1" "$tdir/conf-sha.json"; sha "$tdir/conf-sha.json"; }
put() {
  if on_microvm; then
    mvm_conf "$1" > "$tdir/conf.json" && cp "$tdir/conf.json" "$(site_dir)/securecore.json"
  else
    compose cp "$1" "php:$conf" >> "$tdir/cp.log" 2>&1
  fi
}
put_live() {
  if on_microvm; then put "$1" && php_restart; else compose exec -T php sh -c "cat > $conf.new && mv $conf.new $conf" < "$1"; fi
}

# --- php-fpm: the container's, or the launcher's ----------------------------------------------------
# now: a mark in php-fpm's log; phplog <mark>: the log from it on.
now() { if on_microvm; then echo "@$(wc -c < "$mvm_log" 2>/dev/null || echo 0)"; else date -u +%Y-%m-%dT%H:%M:%SZ; fi; }
phplog() {
  case $1 in
    @*) tail -c +$((${1#@} + 1)) "$mvm_log" ;;
    *) compose logs --no-log-prefix --since "$1" php 2>&1 ;;
  esac
}
launcher_pid() { cat "$tdir/launcher.pid" 2>/dev/null; }
# (This file's own variables start with _, so a suite's never change under it.)
launcher_alive() { _p=$(launcher_pid); [ -n "$_p" ] && kill -0 "$_p" 2>/dev/null; }
php_state() {
  if on_microvm; then
    if launcher_alive; then echo "running 0"; else echo "exited $(cat "$tdir/launcher.exit" 2>/dev/null || echo none)"; fi
  else
    docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$(compose ps -aq php)"
  fi
}
wait_exited() { i=0; until php_state | grep -q '^exited'; do i=$((i + 1)); [ "$i" -lt 30 ] || return 1; sleep 1; done; }
# launcher_start [args]: securecore-fpm on the site's securecore.json, detached from this shell
# (the next suite on the same stack drives it through its pid file), with the test site's
# environment as its own. Waits for "serving" or for it to exit; returns 1 if it exited.
launcher_start() {
  launcher_alive && return 0
  rm -f "$tdir/launcher.exit" "$tdir/launcher.pid"
  _mark=$(now)
  _site=$(site_dir)
  # shellcheck disable=SC2016,SC2046 # the wrapper's own $ expansions; the env names are plain words
  setsid sh -c '
    pidf=$1 exitf=$2 envf=$3; shift 3
    while IFS= read -r l; do export "$l"; done < "$envf"
    "$@" &
    echo $! > "$pidf"
    wait $!
    echo $? > "$exitf"' sh "$tdir/launcher.pid" "$tdir/launcher.exit" "$tdir/guest.env" \
    "$mvm_fpm" $(sed 's/=.*//; s/^/--guest-env /' "$tdir/guest.env") \
    --config "$_site/securecore.json" --vm-dir "$mvm_vm" --state-dir "$mvm_state" --listen "unix:$mvm_run/fpm.sock" \
    --listen-owner 0 --listen-group 101 --listen-mode 0660 --vm-user "$mvm_vmuser" --pool-user "$mvm_pool" \
    --guest-root "$html" "$@" >> "$mvm_log" 2>&1 < /dev/null &
  _i=0
  until phplog "$_mark" | grep -q 'securecore-fpm: serving FastCGI'; do
    [ -s "$tdir/launcher.exit" ] && return 1
    _i=$((_i + 1)); [ "$_i" -lt 1800 ] || { echo "  the launcher said nothing about serving in 180 s"; return 1; }
    sleep 0.1
  done
}
launcher_stop() {
  _p=$(launcher_pid)
  [ -n "$_p" ] || return 0
  if kill -0 "$_p" 2>/dev/null; then
    kill -TERM "$_p"
    _i=0; while kill -0 "$_p" 2>/dev/null; do _i=$((_i + 1)); [ "$_i" -lt 300 ] || { kill -KILL "$_p"; break; }; sleep 0.1; done
  fi
  # The wrapper writes the exit status as the launcher ends.
  _i=0; until [ -s "$tdir/launcher.exit" ] || [ "$_i" -ge 50 ]; do _i=$((_i + 1)); sleep 0.1; done
}
# php_restart [launcher args]: on docker the args are ignored (the container's php-fpm).
php_restart() {
  if on_microvm; then launcher_stop; launcher_start "$@"; else compose restart php > /dev/null 2>&1; fi
}
php_start() { if on_microvm; then launcher_start "$@"; else compose start php > /dev/null 2>&1; fi; }
site_sync() { if on_microvm; then php_restart "$@"; fi; }

# --- the guest's files (shared with test/ext-microvm.sh) ---------------------------------------------
# record <vm-dir> [no-rootfs]: installed.json, as the installer writes it (with the root image:
# this test built it; no release ships one yet).
sum() { sha256sum "$1" | cut -d' ' -f1; }
record() {
  r=""
  [ "${2:-}" = no-rootfs ] || r=", \"rootfs_sha256\": \"$(sum "$1/rootfs.ext4")\""
  printf '{ "firecracker_sha256": "%s", "jailer_sha256": "%s", "kernel_sha256": "%s"%s }\n' \
    "$(sum "$1/firecracker")" "$(sum "$1/jailer")" "$(sum "$1/vmlinux")" "$r" > "$1/installed.json"
}
# mvm_files <vm-dir> <work-dir> <image tag>: Firecracker, its jailer and mirab's kernel the way a
# release resolves them (scripts/mirab-vm.sh: mirab's newest stable, or MIRAB_MANIFEST, or while
# stable has no vm/ (mirab#89) its newest canary); the guest kernel (KERNEL, with Landlock and
# seccomp); the guest image and its rootfs.ext4 (rebuilt when the image changes); installed.json.
# Keeps mirab's own kernel as <work-dir>/vmlinux-mirab. Returns 1 with the reason on stdout.
mvm_files() {
  v=$1 w=$2 tag=$3
  mkdir -p "$v" "$w"
  if [ -n "${MIRAB_MANIFEST:-}" ]; then
    scripts/mirab-vm.sh --files "$v" "$w" "$MIRAB_MANIFEST" > "$w/mirab.log" 2>&1; rc=$?
  else
    scripts/mirab-vm.sh --files "$v" "$w" > "$w/mirab.log" 2>&1; rc=$?
    if [ "$rc" = 3 ]; then
      canary=$(curl -fsSL https://mirab-releases.addis.gg/canary.json | jq -r .version)
      scripts/mirab-vm.sh --files "$v" "$w" "https://mirab-releases.addis.gg/$canary/vm/manifest.json" >> "$w/mirab.log" 2>&1; rc=$?
    fi
  fi
  [ "$rc" = 0 ] || { echo "mirab's VM files (see $w/mirab.log)"; return 1; }
  tail -1 "$w/mirab.log"
  [ -x "$v/jailer" ] || { echo "no jailer from Firecracker's tarball"; return 1; }
  cp "$v/vmlinux" "$w/vmlinux-mirab"
  # The guest kernel: mirab's, unless KERNEL names one with Landlock and seccomp (layer 3).
  [ "$mvm_kernel" = "$v/vmlinux" ] || cp "$mvm_kernel" "$v/vmlinux"
  docker build -q -f docker/ext.Dockerfile --target guest -t "$tag" . > "$w/guest-build.log" 2>&1 \
    || { echo "the guest image (see $w/guest-build.log)"; return 1; }
  img=$(docker image inspect -f '{{.Id}}' "$tag")
  if [ ! -s "$v/rootfs.ext4" ] || [ "$(cat "$v/rootfs.stamp" 2>/dev/null)" != "$img" ]; then
    scripts/guest-image.sh "$tag" "$v/rootfs.ext4" > "$w/rootfs.log" 2>&1 || { echo "rootfs.ext4 (see $w/rootfs.log)"; return 1; }
    echo "$img" > "$v/rootfs.stamp"
  fi
  record "$v"
}
# mvm_clean_state <state>: empties a launcher's state folder, unmounting a leftover jail's bind
# mounts first: never delete through one (one is MariaDB's socket folder).
mvm_clean_state() {
  awk -v s="$1/" 'index($5, s) == 1 { print $5 }' /proc/self/mountinfo | sort -r | while read -r m; do umount -l "$m"; done
  if awk -v s="$1/" 'index($5, s) == 1' /proc/self/mountinfo | grep -q .; then echo "a mount under $1 is still there"; return 1; fi
  find "$1" -mindepth 1 -xdev -delete
}

# --- the stack -----------------------------------------------------------------------------------
# up <services>: compose up, recreating containers whose image no longer exists (a stale
# project's), never touching the volumes.
up() {
  compose up -d "$@" > "$tdir/up.log" 2>&1 && return 0
  compose rm -fs "$@" >> "$tdir/up.log" 2>&1
  compose up -d --force-recreate "$@" >> "$tdir/up.log" 2>&1
}
# stack_up: the extension stack with WordPress installed, serving examples/wordpress.json with
# 200. Exits the suite on failure.
stack_up() {
  echo "building and starting the stack (project $project, $base, target $SC_TARGET)"
  if on_microvm; then
    [ -c /dev/kvm ] || { echo "FAIL this host has no /dev/kvm: the microVM target needs KVM (it never skips)"; exit 1; }
    [ -x "$mvm_fpm" ] || { echo "FAIL no host securecore-fpm at $mvm_fpm (cd ext && cargo build --release -p securecore-fpm)"; exit 1; }
    [ -s "$mvm_kernel" ] || { echo "FAIL no guest kernel at $mvm_kernel (bench/microvm/kernel.sh)"; exit 1; }
    for t in mke2fs e2fsck resize2fs jq python3; do command -v "$t" > /dev/null 2>&1 || { echo "FAIL $t isn't on PATH"; exit 1; }; done
    launcher_stop
    mkdir -p "$mvm_state" "$mvm_run" "$mvm_mysqld"
    chmod 755 "$mvm_sockdir"
    chown 999:999 "$mvm_mysqld"
    mvm_clean_state "$mvm_state" > "$tdir/state.log" 2>&1 || { echo "FAIL $(cat "$tdir/state.log")"; exit 1; }
    : > "$mvm_log"
    builds="php mvmweb" services="db php web mvmweb"
  else
    builds=php services="db php web"
  fi
  # shellcheck disable=SC2086
  compose build $builds > "$tdir/build.log" 2>&1 || { echo "FAIL docker build (see $tdir/build.log)"; exit 1; }
  # shellcheck disable=SC2086
  up $services || { echo "FAIL compose up (see $tdir/up.log)"; exit 1; }
  # On a new site volume the image's entrypoint copies WordPress (and off.json as securecore.json)
  # in first, then starts php-fpm: wait for that, so the copy can't overwrite the config put below.
  i=0
  until [ "$(docker inspect -f '{{.State.Status}}' "$(compose ps -aq php)")" = running ] \
    && compose exec -T php sh -c 'grep -q "^php-fpm" /proc/1/comm' > /dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -lt 120 ] || { echo "FAIL the php container's php-fpm did not start"; exit 1; }
    # A site volume from an earlier run may hold a config php-fpm refuses: the example, then again.
    if docker inspect -f '{{.State.Status}}' "$(compose ps -aq php)" | grep -q '^exited'; then
      compose cp ext/examples/wordpress.json "php:$conf" >> "$tdir/cp.log" 2>&1
      compose start php > /dev/null 2>&1
    fi
    sleep 1
  done
  i=0
  until compose exec -T db mariadb -uwordpress -pwordpress-db-password -e 'select 1' wordpress > /dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -lt 90 ] || { echo "FAIL the database did not start"; exit 1; }
    sleep 1
  done
  _site=$(site_dir)
  if on_microvm; then
    [ -S "$mvm_mysqld/mysqld.sock" ] || { echo "FAIL MariaDB's socket is not at $mvm_mysqld/mysqld.sock"; exit 1; }
    _w=$(mvm_files "$mvm_vm" "$PWD/.tmp/sc-target/work" sc-target-guest) || { echo "FAIL $_w"; exit 1; }
    echo "$_w"
    # The test site's environment (database settings, the vault's env sources: the stack's fixed
    # test values) with the database on the guest's loopback. The launcher gets it as its own
    # and delivers it in each start message; no image carries it.
    docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$(compose ps -q php)" | grep '^WORDPRESS_' \
      | sed 's|^WORDPRESS_DB_HOST=.*|WORDPRESS_DB_HOST=127.0.0.1|' > "$tdir/guest.env"
    grep -q '^WORDPRESS_DB_HOST=127.0.0.1$' "$tdir/guest.env" || { echo "FAIL the guest's env file"; exit 1; }
    chmod 600 "$tdir/guest.env"
    # The microVM mounts a disk at each writable folder inside the root, so they must exist.
    mkdir -p "$_site/wp-content/uploads" "$_site/wp-content/cache"
    chown 33:33 "$_site/wp-content/uploads" "$_site/wp-content/cache"
  fi
  put ext/examples/wordpress.json
  if on_microvm; then
    launcher_start || { echo "FAIL the launcher did not serve: $(tail -5 "$mvm_log" | tr '\n' ' ')"; exit 1; }
  else
    compose restart php > /dev/null 2>&1
  fi
  # Install, retrying until the front page serves 200: `wp core is-installed` can report a
  # half-initialised fresh volume as installed, so gate on the real page.
  i=0
  until [ "$(code /)" = 200 ]; do
    compose run --rm -T cli wp core install --url="$base" --title=SecureCore --admin_user=admin \
      --admin_password=securecore-demo --admin_email=admin@example.com --skip-email >> "$tdir/wp.err" 2>&1 || true
    i=$((i + 1)); [ "$i" -lt 30 ] || { echo "FAIL WordPress did not install (see $tdir/wp.err)"; exit 1; }
    sleep 2
  done
}
# stack_is_up: the stack an earlier suite left (on microvm: its launcher too, started again if
# it stopped). Exits the suite if there is none.
stack_is_up() {
  if on_microvm && [ -s "$tdir/guest.env" ] && ! launcher_alive; then launcher_start > /dev/null; fi
  [ "$(code /)" = 200 ] || { echo "FAIL the extension stack is not up on $base: run SC_TARGET=$SC_TARGET test/ext-config.sh first"; exit 1; }
}
mkdir -p "$tdir"
