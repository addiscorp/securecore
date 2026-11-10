# Spike: layer 1 as a Firecracker microVM (#68, part of #53)

Today layer 1 is `securecore-fpm`, which starts php-fpm inside gelada (Landlock and seccomp on
the host kernel). This spike runs php-fpm inside a Firecracker microVM instead. It follows the
"middle path":

- securecore drives Firecracker over its API socket itself, with no mirab CLI in between.
- It reuses mirab's pinned Firecracker and mirab's guest kernel.
- Hosts without `/dev/kvm` fall back to today's gelada layer 1.

All numbers were measured on **[xps]**: Linux 6.18.57 (NixOS), 4 cores, 7.5 GiB, `/dev/kvm`
present. The setup:

- Firecracker v1.17.0. The guest kernel is mirab's Linux 6.12.112.
- The site is the `test/ext-layer1.sh` stack: WordPress with Classic Editor, Yoast SEO and
  Contact Form 7, PHP 8.3 NTS php-fpm, MariaDB 11.4, run as project `sc-mvm` on port 8095. All
  68 of its checks pass on [xps].

This is a spike. The driver proves the numbers; it is not the product launcher. Where something
wasn't built, this doc says so.

## What was built

```
nginx (container, bench/microvm/nginx.conf)  ── static files from the site volume
  │ fastcgi_pass unix:<dir>/fpm.sock
  ▼
securecore-microvm (host, Rust, std only)    ── Firecracker API, vsock bridge, readiness ping
  │ CONNECT 9000 on Firecracker's vsock socket
  ▼
microVM: no network device, lo only
  socat vsock:9000 → 127.0.0.1:9000 → php-fpm + securecore.so (layers 2 and 3)
  socat 127.0.0.1:3306 → vsock host:3306 ──► driver ──► MySQL (the only way out)
  php-fpm's log → vsock host:1514 ──► driver ──► <dir>/guest.log
  vda root (ro, shared) · vdb site (ro) · vdc uploads (rw) · tmpfs /tmp, /run, wp-content/cache
```

| file | what |
|---|---|
| `bench/microvm/src/main.rs` | `securecore-microvm`. Its commands: `detect` (can this host run the VM?); `launch` (the VM, or exec `securecore-fpm` as the fallback); `boot` (cold or `--restore`); `ctl quit` and `ctl snapshot` |
| `bench/microvm/firecracker.json` | mirab's `scripts/firecracker.json`, verbatim |
| `bench/microvm/mirab-kernel.json` | the pin for mirab's published kernel: version, URL, both sha256 values |
| `bench/microvm/fetch.sh` | fetches Firecracker (tarball and binary checked against the pin, as mirab's `firecracker-install.ts` does) and mirab's `vmlinux` (gzip and unpacked sha256, re-checked against mirab's live manifest) |
| `bench/microvm/kernel.sh`, `kernel-securecore.config` | mirab's kernel recipe plus five lines (Landlock and seccomp), giving `vmlinux-sc` |
| `bench/microvm/guest.Dockerfile`, `init.sh`, `zz-microvm.conf` | the guest's root: the `php-layer1` image plus socat, a PID 1 and the pool overrides |
| `bench/microvm/build-images.sh` | `rootfs.ext4`, `site.ext4` and `uploads.ext4`, built from the stack |
| `bench/microvm/bench.sh` | every measurement below (`boot`, `snapshot`, `memory`, `latency`, `perf`, `ext`, `fallback`, `smoke`) |

**Why `bench/microvm/` and not `ext/`.** `ext/layer1/` doesn't exist: layer 1 is `ext/fpm`
(`securecore-fpm`). The driver lives outside the `ext/` workspace on purpose:

- It is spike code with no crates.io dependencies.
- It shouldn't become a release-matrix member or a CI gate before its design is agreed.

The product version belongs in `ext/fpm` (follow-up 3).

To reproduce on a KVM host (every script runs as root under the build lock):

```sh
SECURECORE_EXT_PROJECT=sc-mvm SECURECORE_EXT_PORT=8095 test/ext-layer1.sh
bench/microvm/fetch.sh
bench/microvm/kernel.sh <mirab>/guest-agent/kernel-x86_64.config   # vmlinux-sc
(cd bench/microvm && CARGO_TARGET_DIR=$PWD/../../.target cargo build --release)
bench/microvm/build-images.sh
bench/microvm/bench.sh boot 5        # and snapshot, memory, latency, perf, ext, fallback
```

## Does mirab publish a built kernel?

**Yes, but only on canaries.** mirab's release workflow publishes
`<version>/vm/manifest.json` and `vm/linux-x64/vmlinux.gz` to mirab-releases.addis.gg:

- The canary `0.2.1-canary-b0b093c` lists `linux-x64/vmlinux.gz` (sha256 `2122b850…`; unpacked
  19,722,472 bytes, sha256 `3bfc869b…`). `fetch.sh` downloads it and verifies both hashes.
- The current stable, `0.2.0` (`latest.json`), has **no** `vm/manifest.json` (HTTP 404). Its
  release predates the vm images.
- mirab's `docs/VM.md` still says "mirab doesn't publish images yet". That line is stale.

So today securecore can only pin a mirab **canary** kernel. That needs a decision (below).

**mirab's kernel lacks what gelada needs.** `guest-agent/kernel-x86_64.config` has no
`CONFIG_SECURITY_LANDLOCK` and no `CONFIG_SECCOMP_FILTER`. Inside that guest, layer 3's
isolated children fail closed (see Q6), and `securecore-fpm`'s gelada step couldn't run either.
`kernel-securecore.config` adds five lines:

- `SECURITY`, `SECURITY_LANDLOCK`, `LSM="landlock"`, `SECCOMP`, `SECCOMP_FILTER`.
- They are built with mirab's own recipe: same kernel.org tarball and sha256, allnoconfig.

The result is `vmlinux-sc`: 19,886,840 bytes, sha256 `fffc8270…`, 164 KB larger than mirab's.

## 1. Boot

Cold boot is measured from the moment the driver starts. Each column is a point in the boot:

- **API up:** Firecracker's API socket answers.
- **Started:** `InstanceStart` has returned.
- **php-fpm ping:** the first FastCGI `/fpm-ping` answered over vsock.
- **First front page:** a 200 through nginx.

The extension is on (`examples/wordpress.json`: layer 2 enforce, layer 3 isolating Contact Form
7), with 2 vCPUs and 512 MiB of memory.

```
$ bench/microvm/bench.sh boot 5                                  # mirab's vmlinux
cold boot 1: firecracker API 1.6 ms, InstanceStart 12.7 ms, php-fpm ping 397.2 ms, first front page 1832 ms (the next one 119 ms)
cold boot 2: firecracker API 1.8 ms, InstanceStart 13.6 ms, php-fpm ping 382.5 ms, first front page 1883 ms (the next one 116 ms)
cold boot 3: firecracker API 1.6 ms, InstanceStart 13.7 ms, php-fpm ping 398.4 ms, first front page 1881 ms (the next one 125 ms)
cold boot 4: firecracker API 1.7 ms, InstanceStart 14.2 ms, php-fpm ping 393.6 ms, first front page 1803 ms (the next one 119 ms)
cold boot 5: firecracker API 1.6 ms, InstanceStart 15.3 ms, php-fpm ping 391.9 ms, first front page 1826 ms (the next one 175 ms)
median: php-fpm ping 393.6 ms, first front page 1832 ms (n=5, kernel vmlinux)
securecore-init: ext=1 layer1=0 up 0.08s
$ KERNEL=.tmp/mvm/vmlinux-sc bench/microvm/bench.sh boot 5        # + Landlock, seccomp
median: php-fpm ping 409.9 ms, first front page 1948 ms (n=5, kernel vmlinux-sc)
```

- **The kernel reaches PID 1 in about 80–90 ms** (`up 0.08s`).
- **php-fpm answers at about 0.4 s.** Most of that is php-fpm and the extension starting.
- **The first front page takes about 1.8–1.9 s.** That is cold PHP: an empty opcache, and
  Yoast building its indexables against layer 2's refusals. The next page already takes
  120–175 ms.
- The kernel with Landlock costs about +16 ms to the ping. The +116 ms on the first page
  includes layer 3's helper and child actually starting, which mirab's kernel refuses.

**Snapshot and restore.** One VM is warmed with 50 front pages, then snapshotted. Each restore
is a new Firecracker process loading the snapshot, timed the same way:

```
$ bench/microvm/bench.sh snapshot 3
{"event":"snapshot","pause_ms":0.7,"create_ms":613.3}
vm.mem 536870912 bytes (the whole 512 MiB guest), vm.snap 25216 bytes
restore 1 (cold page cache): snapshot loaded 14.8 ms, php-fpm ping 103.8 ms, first front page 748 ms
restore 2 (cold page cache): snapshot loaded 16.2 ms, php-fpm ping 102.4 ms, first front page 786 ms
restore 3 (cold page cache): snapshot loaded 16.1 ms, php-fpm ping 103.2 ms, first front page 759 ms
restore 1 (warm page cache): snapshot loaded 5.9 ms, php-fpm ping 13.7 ms, first front page 327 ms
restore 2 (warm page cache): snapshot loaded 5.4 ms, php-fpm ping 15.1 ms, first front page 307 ms
restore 3 (warm page cache): snapshot loaded 5.7 ms, php-fpm ping 13.7 ms, first front page 329 ms
$ bench/microvm/bench.sh smoke 1 --restore .tmp/mvm/snap
first front page 324 ms after the driver started
front page 200 0.128201s / 0.089593s / 0.123748s / 0.126125s / 0.089426s / 0.088216s
```

- **Restore is the fast path.** A restore answers php-fpm's ping in about 14 ms when the
  snapshot file is in the page cache, and about 103 ms when it isn't (`drop_caches` before each
  run).
- **The first page after a restore still takes about 0.3 s, against 1.8 s cold.** The pages
  after it settle within a few requests.
- Not investigated: why the first restored page isn't at the steady 80 ms. The candidates are
  guest pages faulting in from `vm.mem`, and the guest clock still being the snapshot's time
  (WordPress cron and transients). See follow-up 9.

## 2. Memory

Measured on one VM with a 512 MiB guest and php-fpm's default pool (`pm = dynamic`, up to 5
workers):

```
$ bench/microvm/bench.sh memory
cold boot, idle after the first page: firecracker RSS 235308 kB, PSS 235296 kB; driver RSS 2772 kB
cold boot, after 200 front pages (4 concurrent): firecracker RSS 273972 kB, PSS 273960 kB; driver RSS 3024 kB
restored from snapshot, idle after the first page: firecracker RSS 96044 kB, PSS 96032 kB; driver RSS 2780 kB
```

- **A cold-booted VM costs about 270 MB on the host under load.** That is the guest kernel,
  page cache, php-fpm and opcache. The driver adds 3 MB.
- **A restored VM is about 96 MB when idle.** Its memory is the snapshot file mapped
  copy-on-write, and only the pages the guest touches become resident.
- On [xps]'s 7.5 GiB, cold-booted VMs therefore fit at roughly 20 sites.
- Restored VMs should share their untouched snapshot pages through the page cache. That would
  make more of them fit, but it wasn't measured with several VMs (follow-up 11).
- The script also prints a `MemAvailable` delta. It is left out here: other agents' stacks run
  on [xps], and the two runs gave 94 and 35 MiB.

## 3. Request path: vsock, and latency against host php-fpm

**What the prototype uses: vsock, with no network device in the guest.** nginx's
`fastcgi_pass` points at a unix socket the driver owns. The driver opens `CONNECT 9000` on
Firecracker's vsock socket for each connection, and socat in the guest connects that to
php-fpm on loopback. The guest never gets an IP address, so there is nothing to route, filter
or masquerade.

**Tap networking was not built.** A tap device would need:

- a bridge, tap devices and nftables rules on the host;
- mirab's `vm network setup` model, which NixOS would have to declare;
- egress filtering to stand in for layer 1's port rules.

vsock avoids all of that and makes the allowlist the driver's forward list (Q5). A tap path is
worth measuring only if the database overhead below can't be closed over vsock (follow-up 8).

**Front-page p50, with the method of `bench/layer1.sh`:**

- 20 warm-up requests, then 100 sequential ones, by oha on the stack's network, over 5 rounds.
- The extension is off on both sides, so the only difference is where php-fpm runs.
- "host php-fpm" is the stack's php container with layer 1 off (`bench/layer1.sh`'s "stock").

```
$ bench/microvm/bench.sh latency 5
round 1: host php-fpm 65.94 ms   microVM 81.14 ms
round 2: host php-fpm 65.87 ms   microVM 80.75 ms
round 3: host php-fpm 66.10 ms   microVM 80.92 ms
round 4: host php-fpm 65.79 ms   microVM 81.09 ms
round 5: host php-fpm 66.03 ms   microVM 80.74 ms
median p50: host php-fpm 65.94 ms, microVM 80.92 ms, delta +14.98 ms
$ bench/layer1.sh 5          # for reference, today's gelada layer 1 on the same box
median p50: stock 65.82 ms, layer1 66.04 ms, delta +0.22 ms
```

**The microVM adds about 15 ms (+23 %) to the front page; gelada adds 0.2 ms.** That is over
the 2 ms budget #53 sets for layer 2. `sc-perf.php` times the cost inside PHP, so nginx,
FastCGI and the bridge are not in its numbers:

```
$ bench/microvm/bench.sh perf
host php-fpm: connect_ms=0.611 query_ms=0.0500 cpu_ms=39.15    (5 runs; median shown)
microVM:      connect_ms=1.237 query_ms=0.2069 cpu_ms=41.29
```

- **CPU costs the same** (a 2M-step PHP loop: 39–46 ms on both sides).
- **Each MySQL round trip costs 0.05 ms on the host and 0.20 ms in the VM.** The VM's path has
  four userspace copies: guest socat, vsock, the driver's thread, then TCP to the db container.
- At +0.15 ms a query, about 100 queries per page (WordPress plus Yoast) account for the whole
  gap. The database path is what to optimise (follow-up 8), not the VM.

**Two fixes the measurements forced**, both in `init.sh`:

- **socat's default `-t 0.5`.** After php-fpm closes, socat waits 0.5 s before closing the vsock
  side, and nginx (no FastCGI keepalive) waits for that close. A PHP page with no WordPress took
  504 ms, and 2 ms with `-t 0`.
- **The serial console.** Writing the extension's audit lines there costs too much per request,
  so php-fpm's log goes to the host over vsock 1514 instead.

## 4. Files: how the guest sees WordPress without virtio-fs

Firecracker 1.17.0 has no virtio-fs. Its binary names `vhost-user-blk` and no `vhost-user-fs`
(checked with `grep -ao 'vhost[-_a-z]*'`, as mirab's FINDINGS did for 1.15.1). It has no 9p
either. The prototype therefore uses block devices:

| disk | what | mode | size here |
|---|---|---|---|
| `rootfs.ext4` (vda) | the guest OS: Debian, PHP 8.3, the extension, securecore-fpm, socat | read-only, one per PHP build, shared by every site | 1110 MiB (805 MiB used) |
| `site.ext4` (vdb) | WordPress core, plugins, themes, `wp-config.php`, `securecore.json`, without uploads | read-only | 247 MiB (141 MiB used) |
| `uploads.ext4` (vdc) | `wp-content/uploads` | read-write, the only writable disk | 65 MiB |
| tmpfs | `/tmp`, `/run`, `wp-content/cache` | lost on stop | in guest RAM |

- **A read-only site disk matches what layer 1 already enforces.** `examples/wordpress.json`
  lets php-fpm write only uploads, cache and `/tmp`. Core and plugins are already unwritable
  under gelada; in the VM they are unwritable at the block level as well.
- **The cost of a read-only site disk:** updating core or a plugin from wp-admin can't work.
  An update means rebuilding `site.ext4` from the tree (`mke2fs -d`, no root needed) and
  restarting or restoring the VM. Today, under layer 1, those updates fail anyway.
- **The cost of the uploads disk:** the host can't safely read an ext4 image while the guest
  has it mounted read-write. In the prototype, nginx serves uploads from the host's copy, which
  doesn't see the guest's new files. Product options (follow-up 5):
  - serve `/wp-content/uploads` through the guest, as a small static location in the guest's
    php-fpm or a second vsock port;
  - push each finished upload back to the host, the way mirab syncs a workspace;
  - keep uploads on object storage (an offload plugin).
- **Other options considered:**
  - An NFS or 9p server on the host, exported over vsock, keeps one tree but puts a network
    file system under every `include`. Not measured.
  - virtiofsd isn't usable because Firecracker has no front end for it.
  - Copying the tree into a fresh disk at every boot (mirab's per-job workspace) is fine for CI
    but wasteful for a long-lived site.

## 5. Database, with layer 2's rules still applying

- **The way out is the driver's forward list.** The guest reaches MySQL at `127.0.0.1:3306`;
  socat carries that to vsock host port 3306, and the driver connects it to the configured
  address (`--forward 3306=<db>:3306`). Nothing else is reachable. Without a network device
  there is no DNS, UDP or other port to deny: `layer1.network.connect` becomes the forward list
  in the product (follow-up 3), deny-by-default by construction.
- **Layer 2 runs inside the guest, in the extension, unchanged.** It is SQL-level, so the
  transport doesn't matter. The guest's log shows the same enforce decisions as the host stack.
  For example, Yoast's queries are refused because the test config gives `wordpress-seo` no
  generated table entries:

  ```
  securecore: layer2 enforce plugin:wordpress-seo mysqli_query table select wp_yoast_indexable
  WordPress database error securecore: plugin:wordpress-seo may not run this select (table) for query SELECT * FROM `wp_yoast_indexable` …
  ```

- **The vault holds in the guest** (`bench.sh ext`, `test/ext-vault.sh`'s core probe). WordPress
  connects to the database (`db_ok=true`), yet the real password appears nowhere in the probe's
  output. The host stack and the guest give the same result:

  ```
  getenv_db='securecore-vault:DB_PASSWORD' const_db='securecore-vault:DB_PASSWORD' wpdb_dbpassword='securecore-vault:DB_PASSWORD'
  ```

- **Not built:**
  - **Outbound HTTPS.** core's `api.wordpress.org` and the 443 in layer 1's connect list would
    need a host-side forward, or a CONNECT proxy, over vsock. Layer 2's hostname rules would
    keep applying in the guest (follow-up 7).
  - **The guest's secrets.** The vault's env sources come from `/etc/securecore-guest.env` in
    the root image. These are the stack's fixed test values, but a product image must never
    carry them: they belong on a per-site config disk or a vsock handshake at boot
    (follow-up 6).

## 6. The extension inside the guest

The same `securecore.so` and the same `securecore.json` were used, unchanged
(`bench.sh ext`). The front page is 70,725 bytes on the host stack and in every guest
variant.

| | host stack (gelada L1 + L2 + L3) | guest, mirab's kernel | guest, `vmlinux-sc` | guest, `vmlinux-sc`, `sc.layer1=1` |
|---|---|---|---|---|
| extension loaded, `layer2_mode` | 1, enforce | 1, enforce | 1, enforce | 1, enforce |
| vault: DB works, password hidden | yes | probe returned no lines (not investigated) | yes | yes |
| layer 3 (Contact Form 7 isolated) | `layer3 helper started`, child runs | **fails closed**: `child refused to start: layer3: gelada: the sandbox isn't available here: Landlock isn't enabled in this kernel` | helper and child run; the child's DB calls are refused as on the host (`not yet available to an isolated plugin`) | as before |
| `securecore-fpm` (gelada) inside the guest | n/a | not tried (no Landlock) | n/a | `securecore-fpm: layer 1 on from /var/www/html/securecore.json … tcp bind 9000; tcp connect 53 3306 443; starting php-fpm`, and the site serves |

- **With mirab's kernel, layers 2 and 3 load, and layer 3 refuses to run unsandboxed.** That is
  the designed fail-closed behaviour, but Contact Form 7 doesn't load.
- **With the five extra kernel lines, everything works unchanged.** Even gelada's layer 1 can
  run inside the VM as an inner wall.
- **Not done:** running the full `test/ext-*.sh` suites against the guest. They drive the stack
  through `docker compose exec php`, and need a harness that targets the VM (follow-up 10).

## 7. Detection and the gelada fallback

`securecore-microvm detect` decides:

1. **microVM**, when all of these hold:
   - `/dev/kvm` opens read-write;
   - `ioctl(KVM_GET_API_VERSION)` returns 12;
   - the Firecracker binary, kernel and root image exist, and Firecracker is executable.
2. **gelada** otherwise, with the reason.

`launch` boots the VM in the first case. In the second, it execs `securecore-fpm --config
<file>`, which is today's layer 1, unchanged. In neither case does php-fpm run without layer 1.

```
$ bench/microvm/bench.sh fallback
this host:
microvm
the php-layer1 container (no /dev/kvm device):
gelada: /dev/kvm: No such file or directory (os error 2)
  exit 3
the same container with --device /dev/kvm (a new one, same image):
microvm
launch in a container without /dev/kvm execs securecore-fpm (gelada) with the config:
securecore-microvm: layer 1 falls back to gelada (/dev/kvm: No such file or directory (os error 2)): exec /usr/local/bin/securecore-fpm --config /var/www/html/securecore.json
securecore-fpm: layer 1 on from /var/www/html/securecore.json (sha256 5ae649c5…): write … tcp bind 9000; tcp connect 53 3306 443; starting php-fpm
```

What isn't settled is whether a site that asks for a microVM should fall back at all. mirab's
policy is that "a requested level that is unavailable is refused, never downgraded"; #53 says an
invalid config never runs unprotected. gelada is protected, but weaker. See "Needs a decision".

## Recommended design

1. **Configuration.** Add `layer1.isolation` to `securecore.json`, with three values:
   - `"gelada"`: today's behaviour.
   - `"microvm"`: refuse to start without KVM, mirab's rule.
   - `"auto"`: a microVM when `detect` passes, gelada otherwise. The launcher logs the choice
     and `securecore_status()` reports it.

   The `write`, `deny` and `network` keys keep their meaning:
   - **gelada:** they are Landlock rules.
   - **microVM:** `write` picks which paths get the writable disk or tmpfs, and
     `network.connect` becomes the vsock forward list.
2. **The driver goes in `securecore-fpm`** (Rust, `ext/fpm`). It keeps the shape of this
   prototype:
   - Firecracker's API driven directly, with mirab's pinned release and sha256-checked install;
   - vsock only, no tap devices and no root-owned network setup;
   - the guest's log over vsock.

   The guest's socat and shell PID 1 should become a small static Rust init that does the
   forwarding itself. That saves a userspace hop per query (follow-up 8).
3. **Kernel.** Upstream the five Landlock/seccomp lines into mirab's `kernel-x86_64.config`,
   then pin mirab's published `vmlinux` by sha256 as `mirab-kernel.json` does. That gives one
   kernel for both projects, with no fork. Until mirab promotes a release with `vm/` images,
   the pin is a canary.
4. **Start from a snapshot.** Build a golden snapshot per root image, site image and config:
   boot, warm up, snapshot. Restore it on start (6–16 ms to load, about 14–100 ms to php-fpm,
   about 0.3 s to the first page). Keep cold boot (0.4 s to php-fpm) as the path when no
   snapshot exists.
5. **Ship the microVM as opt-in (`auto`) only after the database path is within budget.**
   Today the microVM costs +15 ms p50 against gelada's +0.2 ms, and the gap is MySQL round
   trips, not virtualisation. Until it is closed, gelada stays the default and the microVM is
   the high-isolation choice for operators who accept the cost.

## Follow-up issues (not filed)

1. **mirab: Landlock and seccomp in the x86_64 guest kernel.** Add `SECURITY`,
   `SECURITY_LANDLOCK`, `LSM="landlock"`, `SECCOMP` and `SECCOMP_FILTER` to
   `guest-agent/kernel-x86_64.config`. Measured: +164 KB, about +16 ms boot. Also fix
   `docs/VM.md`'s stale "doesn't publish images yet".
2. **mirab: a stable release that carries `vm/` images.** That lets securecore pin a promoted
   kernel (APS 9) instead of a canary.
3. **securecore E9: the microVM layer 1 in `securecore-fpm`.** This covers:
   - `layer1.isolation` in the config types and the JSON Schema;
   - detection and the fallback;
   - the Firecracker driver, the vsock bridge and the forward list taken from `network.connect`;
   - property tests that fail with the VM removed;
   - #53's three-plugin pass criteria.
4. **The guest image in the release pipeline.** One read-only root per PHP cell, with a static
   Rust init instead of socat and sh, published to `securecore-releases` with the canary and
   promote steps (APS 9, APS 12).
5. **The site and uploads disks.** Build `site.ext4` on deploy and on update, decide how uploads
   are served (through the guest, synced back, or offloaded), and say what wp-admin updates do.
6. **Secrets into the guest.** Deliver the vault's env sources over vsock or a per-site config
   disk, never baked into an image, and prove they never reach the console or `/proc/cmdline`.
7. **Egress for core hosts (443).** A host-side forward or CONNECT proxy over vsock, with
   layer 2's hostname rules applying in the guest. DNS too, if it's needed at all.
8. **The database path over vsock.** Go from 0.20 ms to under 0.1 ms per query: an in-guest
   forwarder with no socat fork, splice on the host, or a direct vsock-to-unix-socket hop to
   MySQL. Measure tap networking for comparison. The target is under +5 ms on the front page.
9. **Snapshot lifecycle.** Decide when a snapshot is rebuilt (image, site or config sha256),
   resync the guest clock after a restore, and find out why the first page after a restore
   takes 0.3 s rather than 80 ms.
10. **Run the `test/ext-*.sh` suites against a microVM target.** Their harness needs to
    reach php-fpm in the guest, not only through `docker compose exec php`.
11. **Density.** Run N restored VMs from one snapshot and measure PSS sharing. Pick the guest
    memory and pool size: 512 MiB and 5 workers here, and 256 MiB is probably enough.
12. **arm64 hosts.** mirab pins Firecracker for x86_64 only. arm64 needs its own pin and kernel
    (mirab has `kernel-arm64-vz.config` for vz only).

## Needs a decision

- **Fallback semantics.** When a site asks for the microVM and KVM is missing, should the
  launcher refuse or fall back to gelada? The recommendation is the three values above, with
  `"auto"` as the only one that falls back.
- **Which kernel to pin.** The options:
  - mirab adds the five lines and securecore pins mirab's published kernel (recommended);
  - securecore builds and publishes its own kernel from mirab's recipe.

  Separately: pin a mirab canary now, or wait for a promoted release that carries `vm/`
  images.
- **Whether +15 ms p50 is acceptable for an opt-in high-isolation mode** before follow-up 8
  closes the gap.
