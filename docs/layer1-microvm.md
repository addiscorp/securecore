# Spike: layer 1 as a Firecracker microVM (#68, part of #53)

Today layer 1 is `securecore-fpm`, which starts php-fpm inside gelada (Landlock and seccomp on
the host kernel). This spike runs php-fpm inside a Firecracker microVM instead. It follows the
"middle path":

- securecore drives Firecracker over its API socket itself, with no mirab CLI in between.
- It reuses mirab's pinned Firecracker and mirab's guest kernel.
- Hosts without `/dev/kvm` fall back to today's gelada layer 1. (Since 10 Nov the microVM is
  layer 1's default where KVM exists: "`auto` is the microVM where KVM exists", below.)

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
  guest-forward vsock:9000 → 127.0.0.1:9000 → php-fpm + securecore.so (layers 2 and 3)
  mysqlnd's connect to 127.0.0.1:3306 = a vsock connect to host:3306 (libsc-vsock-connect.so)
     ──► Firecracker ──► <dir>/v.sock_3306 = MySQL's own unix socket (the only way out)
  php-fpm's log → vsock host:1514 ──► driver ──► <dir>/guest.log
  vda root (ro, shared) · vdb site (ro) · vdc uploads (rw) · tmpfs /tmp, /run, wp-content/cache
```

That is the database path after #70 (section 3). The spike's was socat in the guest, then the
driver's thread, then TCP to MySQL; `bench.sh` still runs it with `MVM_DB=socat MVM_FPM=socat
MVM_HOST=tcp`.

| file | what |
|---|---|
| `bench/microvm/src/main.rs` | `securecore-microvm`. Its commands: `detect` (can this host run the VM?); `launch` (the VM, or exec `securecore-fpm` as the fallback); `boot` (cold or `--restore`); `ctl quit` and `ctl snapshot`; `guest-forward` (inside the guest, socat's replacement) |
| `bench/microvm/vsock-connect.c` | `libsc-vsock-connect.so`, preloaded into the guest's php-fpm: a connect to 127.0.0.1:3306 becomes a vsock connect to the host (#70) |
| `bench/microvm/sc-perf.php`, `sc-front.php` | time a page's parts inside PHP: MySQL connect and round trip, CPU, clock, stat, memory; the front page's own time |
| `bench/microvm/firecracker.json` | mirab's `scripts/firecracker.json`, verbatim |
| `bench/microvm/mirab-kernel.json` | the pin for mirab's published kernel: version, URL, both sha256 values |
| `bench/microvm/fetch.sh` | fetches Firecracker (tarball and binary checked against the pin, as mirab's `firecracker-install.ts` does) and mirab's `vmlinux` (gzip and unpacked sha256, re-checked against mirab's live manifest) |
| `bench/microvm/kernel.sh`, `kernel-securecore.config` | mirab's kernel recipe plus five lines (Landlock and seccomp), giving `vmlinux-sc` |
| `bench/microvm/guest.Dockerfile`, `init.sh`, `zz-microvm.conf` | the guest's root: the `php-layer1` image plus the forwarder, the preload, a PID 1 and the pool overrides (socat stays for the comparison runs and the log pipe) |
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
Firecracker's vsock socket for each connection, and `guest-forward` in the guest connects that
to php-fpm on loopback. The guest never gets an IP address, so there is nothing to route,
filter or masquerade.

**Front-page p50, with the method of `bench/layer1.sh`:**

- 20 warm-up requests, then 100 sequential ones, by oha on the stack's network, over 5 rounds.
- The extension is off on both sides, so the only difference is where php-fpm runs.
- "host php-fpm" is the stack's php container with layer 1 off (`bench/layer1.sh`'s "stock").

### The spike's path: +15 ms

The spike (#68) measured this; #70 re-ran it on the same box on 10 Nov, with the same method
and result:

```
$ bench/microvm/bench.sh latency 5                                 # #68
median p50: host php-fpm 65.94 ms, microVM 80.92 ms, delta +14.98 ms
$ MVM_DB=socat MVM_FPM=socat MVM_HOST=tcp bench/microvm/bench.sh latency 5   # #70, the same path
round 1: host php-fpm 66.00 ms   microVM 80.88 ms
round 2: host php-fpm 66.31 ms   microVM 81.47 ms
round 3: host php-fpm 65.93 ms   microVM 81.13 ms
round 4: host php-fpm 66.06 ms   microVM 81.25 ms
round 5: host php-fpm 66.00 ms   microVM 80.93 ms
median p50: host php-fpm 66.00 ms, microVM 81.13 ms, delta +15.12 ms
$ bench/layer1.sh 5          # for reference, gelada layer 1 on the same box (#68)
median p50: stock 65.82 ms, layer1 66.04 ms, delta +0.22 ms
```

That path was socat (one fork per connection) in the guest, then vsock, then the driver's
thread, then TCP to the db container.

**The spike's diagnosis was half right.** It assumed about 100 queries a page. A front page
actually sends **34 statements** (MariaDB's `Questions` counter, `bench.sh dbpath`), so the
0.15 ms extra a `SELECT 1` costs explains about 5 ms, not 15. Even so, the database path turned
out to be most of the gap (8.5 ms, below), because WordPress's real queries carry larger
results through every hop and each page pays a socat fork.

### The candidates (#70)

`sc-perf.php` times the cost inside PHP, so nginx, FastCGI and the bridge are not in its
numbers: connect is one `mysqli` connect, and query is a `SELECT 1` round trip averaged over 200.
Every row is the median of 7 page loads on one VM, with the extension off. Rows run in sequence
on the same box, with nothing else of ours running:

```
$ bench/microvm/bench.sh dbpath 7
host php-fpm (TCP to the db container) connect_ms=0.712 query_ms=0.0524 cpu_ms=41.54 clock_ms=3.77 stat_ms=53.22 mem_ms=33.29
one front page (host php-fpm, extension off): 34 statements to MySQL
microVM db=socat host=tcp          connect_ms=1.282 query_ms=0.2298 cpu_ms=41.86 clock_ms=3.74 stat_ms=23.48 mem_ms=24.79
microVM db=fwd host=tcp            connect_ms=0.876 query_ms=0.2239 cpu_ms=41.26 clock_ms=3.74 stat_ms=23.56 mem_ms=26.17
microVM db=fwd host=splice         connect_ms=1.008 query_ms=0.2123 cpu_ms=41.13 clock_ms=3.76 stat_ms=23.86 mem_ms=23.99
microVM db=fwd host=unix           connect_ms=0.606 query_ms=0.1649 cpu_ms=40.21 clock_ms=3.74 stat_ms=23.61 mem_ms=24.18
microVM db=vsock host=tcp          connect_ms=0.757 query_ms=0.1811 cpu_ms=41.25 clock_ms=3.75 stat_ms=23.52 mem_ms=23.96
microVM db=vsock host=splice       connect_ms=0.742 query_ms=0.1656 cpu_ms=41.19 clock_ms=3.74 stat_ms=23.26 mem_ms=24.93
microVM db=vsock host=unix         connect_ms=0.451 query_ms=0.1136 cpu_ms=40.03 clock_ms=3.75 stat_ms=23.40 mem_ms=23.86
microVM db=tap host=-              connect_ms=0.651 query_ms=0.1261 cpu_ms=41.66 clock_ms=3.75 stat_ms=23.67 mem_ms=25.98
microVM db=vsock host=unix --arg idle=poll connect_ms=0.425 query_ms=0.1172 cpu_ms=40.88 …
microVM db=vsock host=unix --vcpus 1 connect_ms=0.521 query_ms=0.1342 cpu_ms=41.22 …
```

| candidate | guest side (`sc.db`) | host side (`MVM_HOST`) | query | connect |
|---|---|---|---|---|
| the spike | socat, a fork per connection | the driver's thread, TCP | 0.230 ms | 1.28 ms |
| in-guest forwarder, no fork | `guest-forward` | the driver, TCP | 0.224 | 0.88 |
| splice on the host | `guest-forward` | the driver, `splice(2)` | 0.212 | 1.01 |
| direct hop to MySQL's unix socket | `guest-forward` | `v.sock_3306` → `mysqld.sock` | 0.165 | 0.61 |
| no forwarder in the guest | mysqlnd on vsock (preload) | the driver, TCP | 0.181 | 0.76 |
| the same, with splice | mysqlnd on vsock | `splice(2)` | 0.166 | 0.74 |
| **both hops gone** | **mysqlnd on vsock** | **`mysqld.sock` directly** | **0.114** | **0.45** |
| tap, for comparison | a virtio-net device, TCP to the db's IP | the host bridge | 0.126 | 0.65 |
| host php-fpm | | TCP to the db container | 0.052 | 0.71 |

What each candidate is:

- **An in-guest forwarder without forks** (`securecore-microvm guest-forward`). It is one
  long-lived Rust process, with a thread pair per connection. Per query it is no faster than
  socat: the hop is the cost, not the fork. It only saves socat's fork at connect (0.4 ms).
- **Splice on the host** (`--splice 1`). It saves at most 0.015 ms a query. MySQL's packets
  are small, so copying them was never the cost; waking the driver's threads is.
- **A direct hop to MySQL's unix socket** (`--forward 3306=unix:<mysqld.sock>`). For a
  guest-initiated connection to port P, Firecracker connects to the unix socket
  `<uds_path>_P`. The driver makes that path a symlink to MariaDB's own socket, so Firecracker
  connects the guest straight to MySQL: no driver thread and no TCP. This saves 0.06 ms a query
  with either guest side. The bench reaches the db container's socket through
  `/proc/<mariadbd>/root/run/mysqld/mysqld.sock`; a product mounts the socket's folder instead.
- **No forwarder in the guest** (`libsc-vsock-connect.so`, `vsock-connect.c`). It is preloaded
  into php-fpm, and turns mysqlnd's `connect()` to `127.0.0.1:3306` into an `AF_VSOCK` connect
  to the host on the same port. It does this in place, on the same fd, keeping its
  `O_NONBLOCK`, so mysqlnd's non-blocking connect, poll and `SO_ERROR` work unchanged. Only the
  listed ports (`SC_VSOCK_PORTS=3306`) and only loopback are affected; every other `connect()`
  is untouched. Combined with the direct hop, PHP's socket goes guest kernel → Firecracker →
  `mysqld.sock`, and nothing else is on the path.
- **tap**, for comparison only (`MVM_DB=tap`): a virtio-net device on the stack's docker bridge,
  with WordPress connecting to the db container's IP. At 0.126 ms it is slower than the best
  vsock path, and it costs the guest a network device. For layer 2 that means:
  - the guest can reach every address the bridge can unless the host filters it, so
    `layer1.network.connect` stops being deny-by-default by construction and becomes nftables
    rules the launcher must install and keep right;
  - DNS, UDP and every other port become reachable unless they are filtered too;
  - layer 2's SQL rules and the vault still hold (they are in the extension), but nothing
    below them stops a bypass of the extension (an isolated child, or a PHP RCE) from opening
    any socket the bridge routes.

  vsock keeps the forward list as the only way out. Tap is not worth that.
- **Diagnostics, not candidates:** `idle=poll` (the guest's vCPUs never halt) and one vCPU
  change nothing (0.117 and 0.134 ms). Waking a halted vCPU is not the remaining cost; KVM's
  200 µs `halt_poll_ns` already covers it. What is left, 0.06 ms a query over the host, is
  Firecracker's vsock device (two event-loop wakeups per round trip) and the guest's virtio
  queues.
- **The guest isn't slower at anything else a page does.** It matches or beats the host
  container at a 100k-call `microtime()` loop (3.7 ms both; the guest clocksource is `tsc`, so
  calls stay in the vDSO), 20k uncached `stat()`s (23 ms against 53 ms through overlayfs) and
  1M-element arrays (24 against 33 ms).

### The chosen path: +5 ms

The pick is **mysqlnd on vsock plus the direct hop to `mysqld.sock`**, with `guest-forward`
replacing socat for FastCGI (port 9000). It is now the default of `init.sh` and `bench.sh`:

```
$ bench/microvm/bench.sh latency 5                                 # 10 Nov, quiet box
round 1: host php-fpm 65.83 ms   microVM 71.32 ms
round 2: host php-fpm 66.26 ms   microVM 72.47 ms
round 3: host php-fpm 65.85 ms   microVM 70.95 ms
round 4: host php-fpm 66.19 ms   microVM 71.16 ms
round 5: host php-fpm 66.02 ms   microVM 72.33 ms
median p50: host php-fpm 66.02 ms, microVM 71.32 ms, delta +5.30 ms
$ bench/microvm/bench.sh latency 5                                 # again, 9 minutes later
round 1: host php-fpm 116.68 ms   microVM 117.58 ms               # (another agent's load)
round 2: host php-fpm 79.96 ms   microVM 71.65 ms
round 3: host php-fpm 65.92 ms   microVM 70.94 ms
round 4: host php-fpm 66.04 ms   microVM 70.86 ms
round 5: host php-fpm 66.10 ms   microVM 70.61 ms
median p50: host php-fpm 66.10 ms, microVM 70.94 ms, delta +4.84 ms
```

**The front page goes from +15.1 ms to about +5 ms (+5.30 and +4.84 in two runs; +8 %
instead of +23 %).** Every VM-side round in both runs is between 70.6 and 72.5 ms. The target
was under +5 ms: one run meets it, the other misses by 0.3 ms.

Where the 10 ms went, with each half measured alone:

```
$ MVM_FPM=socat bench/microvm/bench.sh latency 5                   # new DB path, socat for FastCGI
median p50: host php-fpm 65.90 ms, microVM 72.57 ms, delta +6.67 ms
$ MVM_DB=socat MVM_HOST=tcp bench/microvm/bench.sh latency 5       # spike DB path, guest-forward for FastCGI
median p50: host php-fpm 66.16 ms, microVM 80.08 ms, delta +13.92 ms
```

- **The database path: 8.5 ms** (+15.1 → +6.7).
- **guest-forward instead of socat for FastCGI: 1.2 ms** (+15.1 → +13.9). That is socat's
  fork and exec on every request, since nginx opens a connection per request.

What remains of the +5 ms (`bench.sh breakdown`):

```
$ bench/microvm/bench.sh breakdown
host php-fpm   empty 1.03 ms   70 KB 2.07 ms   front page 67.88 ms   inside PHP 64.29 ms
microVM        empty 1.07 ms   70 KB 1.42 ms   front page 71.12 ms   inside PHP 70.01 ms
```

- **The FastCGI bridge costs nothing measurable now.** An empty PHP response and a 70,725-byte
  one (the front page's size, no WordPress) take the same time through the VM as on the host.
- **The rest is inside PHP:** about 2 ms is the 34 statements at 0.06 ms over the host each,
  and the remainder (about 3 ms, within this box's run-to-run noise of ±1 ms) shows up in none
  of the microbenchmarks above.
- **Going further means making fewer round trips**, or a faster virtio-vsock (vhost-vsock in
  the kernel, which Firecracker doesn't offer). A persistent connection would save the
  0.45 ms connect, for example. Further shaving of the transport has run out: the best
  transport is 0.06 ms over the host, and tap, `idle=poll` and one vCPU don't beat it.

### Layer 2 and the vault on the new path

`bench.sh ext` with `vmlinux-sc`, on the default path (mysqlnd on vsock) and with gelada inside
the guest (`sc.layer1=1`, where the path is `guest-forward`, below):

```
$ KERNEL=.tmp/mvm/vmlinux-sc bench/microvm/bench.sh ext
microVM, kernel vmlinux-sc, boot arguments: (none):
loaded=1 layer2_mode=enforce reload_error= layer1=1 layer2=1 layer3=1
  vault: db_ok=true; DB password visible to PHP anywhere in the probe output: no
  vault probe scalars: getenv_db='securecore-vault:DB_PASSWORD' const_db='securecore-vault:DB_PASSWORD' wpdb_dbpassword='securecore-vault:DB_PASSWORD'
  front page 70725 bytes; Contact Form 7 (isolated by layer 3) assets in it: 0
      3 securecore: layer3 plugin:contact-form-7 database refused (not yet available to an isolated plugin): SELECT option_value FROM wp_options WHERE option_name = 'wpcf7' LIMIT 1
NOTICE: PHP message: securecore: layer2 enforce plugin:wordpress-seo mysqli_query table select wp_yoast_indexable
$ KERNEL=.tmp/mvm/vmlinux-sc bench/microvm/bench.sh ext 1 --arg sc.layer1=1
loaded=1 layer2_mode=enforce reload_error= layer1=1 layer2=1 layer3=1
  vault: db_ok=true; DB password visible to PHP anywhere in the probe output: no
  vault probe scalars: getenv_db='securecore-vault:DB_PASSWORD' const_db='securecore-vault:DB_PASSWORD' wpdb_dbpassword='securecore-vault:DB_PASSWORD'
  front page 70725 bytes; Contact Form 7 (isolated by layer 3) assets in it: 0
securecore-fpm: layer 1 on from /var/www/html/securecore.json (sha256 5ae649c5…): write /var/www/html/wp-content/uploads /var/www/html/wp-content/cache /tmp; deny /srv/backups
securecore-init: ext=1 layer1=1 db=fwd fpm=fwd clocksource=tsc up 0.30s
NOTICE: PHP message: securecore: layer2 enforce plugin:wordpress-seo mysqli_query table select wp_yoast_indexable
```

The results are the same as on the host stack and in the spike:

- layer 2 enforces (Yoast's refused `select`);
- the vault holds (the DB works, and the password appears nowhere);
- layer 3 isolates Contact Form 7, and its child's DB calls are refused.

The preload changes only which socket family carries the bytes. The vault's substitution and
layer 2's SQL checks run in the extension, above mysqlnd, so they see the same calls.

**gelada inside the guest refuses vsock, as it should.** gelada's seccomp filter (0.3.0,
`linux.rs`) denies `socket()` for every family but `AF_UNIX`, `AF_NETLINK`, `AF_INET` and
`AF_INET6` when the network is on, `AF_VSOCK` included. So under `sc.layer1=1`, init uses
`guest-forward` for the database instead (`db=fwd`: 0.165 ms a query with the direct hop). That
keeps the inner wall intact rather than punching a vsock hole in it.

**Three bugs the work found**, fixed in this prototype:

- **Firecracker drops a guest's half-close.** A vsock `SHUTDOWN` carrying only SEND never
  reaches the host's socket. A forwarder that only half-closed (as `join` does on the host) left
  every FastCGI request hanging after its headers: nginx waits for php-fpm's close. It would
  also have left each MySQL connection open on the host. `guest-forward` shuts both sockets down
  completely when either direction ends, as `socat -t 0` does.
- **The driver's `CONNECT` line went out in pieces.** `writeln!` formats the line in several
  `write()`s, and Firecracker reads the handshake without blocking. A split line was dropped
  ("error adding local-init connection: WouldBlock" in the console) and nginx returned a 502:
  often enough that a 120-request latency round failed. It is now one write.
- **A failed bench step left its VM running.** One such VM, booted with `idle=poll`, used two of
  the four cores and skewed every later number until it was found. `bench.sh` now stops any VM
  on exit.

**Two fixes the spike's measurements forced**, both in `init.sh`:

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

- **The way out is the driver's forward list.** The guest reaches MySQL at `127.0.0.1:3306`.
  mysqlnd's connect becomes a vsock connect to host port 3306 (section 3, #70), and that reaches
  whatever the driver put at `<dir>/v.sock_3306`:
  - MySQL's own unix socket (`--forward 3306=unix:<path>`, the default);
  - or a driver thread to a TCP address (`--forward 3306=<db>:3306`), for a database that has no
    socket on this host.

  A port with no entry has no socket, so Firecracker refuses the connection. Nothing else is
  reachable. Without a network device
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
    keep applying in the guest (follow-up 7). Built in #72: "Egress" below.
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

   **The database path is #70's** (section 3), and #71 builds the product version of it:
   - **Host:** `network.connect` entries for MySQL point Firecracker's `v.sock_<port>` at the
     database's unix socket when it is on this host. The launcher mounts or symlinks the socket's
     folder, never through `/proc/<pid>/root` as the bench does. A remote database falls back
     to the driver's TCP thread (splice isn't worth it: 0.015 ms).
   - **Guest, php-fpm:** mysqlnd's socket goes onto vsock directly. The preload is the
     prototype. The product can keep it as a tiny audited library in the root image, or move
     the same in-place swap into the extension, which already sits in every php-fpm. Either way
     it is restricted to loopback and the listed ports.
   - **Guest, everything else:** `guest-forward` (or the static Rust init that replaces
     `init.sh`) carries FastCGI on 9000. It also carries the database when gelada runs inside
     the guest, since gelada's seccomp refuses `AF_VSOCK`. It closes both sockets fully on either
     side's end, because Firecracker drops half-closes.
   - **Driver:** the vsock `CONNECT` line goes out in one write.
3. **Kernel.** Upstream the five Landlock/seccomp lines into mirab's `kernel-x86_64.config`,
   then pin mirab's published `vmlinux` by sha256 as `mirab-kernel.json` does. That gives one
   kernel for both projects, with no fork. Until mirab promotes a release with `vm/` images,
   the pin is a canary.
4. **Start from a snapshot.** Build a golden snapshot per root image, site image and config:
   boot, warm up, snapshot. Restore it on start (6–16 ms to load, about 14–100 ms to php-fpm,
   about 0.3 s to the first page). Keep cold boot (0.4 s to php-fpm) as the path when no
   snapshot exists.
5. **The cost after #70: about +5 ms p50** (+5.30 and +4.84 against +15.1, section 3). Sami
   made the microVM layer 1's default on 10 Nov. The +5 ms is now
   - about 2 ms of MySQL round trips (34 a page at 0.06 ms over the host);
   - about 3 ms inside PHP that no microbenchmark here attributes.

   Going lower means fewer round trips (a persistent connection saves the 0.45 ms connect, for
   example), not a faster transport.

## What #71 built from this

The product version of items 1, 2 and 4 is in `ext/fpm` (`securecore-fpm`; `ext/README.md`,
"`layer1.isolation`"), tested by `test/ext-microvm.sh`:

- `layer1.isolation` is `off`, `gelada`, `microvm` or `auto` (the default). Only `auto` falls
  back; `microvm` refuses. `layer1.network.connect[].socket` / `address` say where a guest port
  goes on the host.
- The driver (`vm.rs`), the vsock bridges (`vsock.rs`) and the guest's PID 1 (`guest.rs`, the
  same binary as `/sbin/securecore-init`) replace `bench/microvm/src/main.rs` and `init.sh`: no
  socat, no shell in the guest's start. The preload moved to `ext/fpm/guest/`, the guest root to
  `docker/ext.Dockerfile`'s `guest` target and `scripts/guest-image.sh`.
- Snapshots are keyed by the sha256s of Firecracker, the kernel, the root image, the site tree and
  the config, plus the machine; the writable disks are mounted only after a restore, after the
  clock is set; a stop syncs them first.
- After the security review (PR #75): Firecracker runs under its jailer as an unprivileged
  user, chrooted, in its own namespaces and cgroup, so the guest's socket connections carry that
  user's credentials, not root's; only files the installer recorded by sha256 boot; `auto` was
  gated off until #72 synced uploads back (it no longer is: next section); the snapshot is warmed
  without the database; every start message brings fresh entropy and replaces php-fpm's workers.

## `auto` is the microVM where KVM exists

Sami made the microVM layer 1's default on 10 Nov, and with uploads syncing back (#72, #81), the
guest image in every release (#80, #82–#84) and the suites passing on a microVM target (#88),
`auto` (the default, also when `isolation` is absent) now picks it: `AUTO_SELECTS_MICROVM` in
`ext/fpm/src/lib.rs` is on, and a test pins it there. The launcher logs
`layer 1 isolation auto: microvm`.

**Where the microVM can't run, `auto` is gelada**, as layer 1 was before, and logs exactly one
line saying why: `layer 1 isolation auto: gelada, because the microVM can't run here (<reason>)`.
The reasons, most basic first (the launcher checks them in this order, and `test/ext-microvm.sh`
checks each line on [xps]):

- no KVM (`no KVM: /dev/kvm: No such file or directory (os error 2)`, or an API version other
  than 12);
- the launcher isn't root (the jailer needs it);
- nothing verified installed (no `installed.json`: arm64, or a release without the guest), or no
  jailed user, or no e2fsprogs;
- a config the microVM can't express (a denied path inside the app root, `unixSockets`, a
  writable folder that is a link or holds `..`, no port to take FastCGI on, a root-owned app
  root without `--pool-user`);
- a root image, kernel, Firecracker or jailer that doesn't match `installed.json` (or that it
  doesn't name: `the guest root image isn't verified: …`);
- uploads that don't fit: a writable folder of more than 1 Mi entries, or one whose new disk's
  copy doesn't fit the state folder's filesystem;
- a guest kernel without Landlock and seccomp while layer 3 is on;
- a `connect[].socket` the jailed user can't open;
- no cgroup v2.

`microvm` refuses for the same reasons (exit 125); `gelada` and `off` are unchanged. A microVM
that `auto` picked and that then fails to boot is a failed start (exit 125), not a silent gelada.

**Opting out:** `"layer1": { "isolation": "gelada", … }` keeps gelada on a KVM host.

**Host requirements:** x86_64 Linux with KVM, cgroup v2, the launcher as root, the installer's
files; **no swap, or encrypted swap** (the guest's memory holds the vault's secrets, below); and
**about 300 MiB of memory per busy site** (section 2: about 270 MB cold-booted under load, 96 MB
restored and idle; each VM's cgroup allows the guest's 512 MiB plus 256 MiB).

**Upgrades.** `ext/install.sh` on a KVM host over a site whose `isolation` is `auto` says that
the next php-fpm start through `securecore-fpm` moves into the microVM, what happens to the
uploads and how to opt out, and lists the `connect` ports with neither `socket` nor `address`
(in the microVM those reach only public hosts by name, so a database on the host needs one). It
starts nothing. That next start makes each writable disk from the host's folder (`mke2fs -d`,
so the first listing finds both sides in step and sends nothing); the host's files stay, a file
the owner changes on the host wins, and nothing is removed. `test/release-check.sh` (7b) checks
exactly this on a site with 203 uploads.
- Nothing is pinned: `scripts/mirab-vm.sh` resolves mirab's newest stable release, its
  `vm/manifest.json` and the Firecracker mirab pins at that commit, and `install-ext.sh` checks
  each file against those sha256s. `bench/microvm/firecracker.json` and `mirab-kernel.json`
  stay as the spike's record only.

## Uploads sync back to the host (#72)

A writable folder inside the app root (`wp-content/uploads`) is an ext4 disk in the guest. The
host can't safely read that image while the guest has it mounted read-write. Until #72, nginx
and backups therefore never saw an upload, and `auto` was gated off. Now the guest tells the
host what changes, and the host applies it to the real folder (`ext/fpm/src/sync.rs`):

```
guest  securecore-init: inotify on every folder of each writable disk
         │ vsock 516: the guest listens (below 1024, so only its root can); the host connects
host   securecore-fpm ── hands the connection to ──► securecore-fpm --sync-writer
         the site's pool user (never root: it refuses), no supplementary groups, an empty
         environment, its own empty network namespace, no new privileges, RLIMIT_AS 1 GiB,
         killed with the launcher; then it confines itself: Landlock to its folders and their
         trash (nothing else, not even reads), a seccomp allowlist of the calls it makes
         (anything else is EPERM); one O_PATH handle per folder (opened beneath the app root);
         every path opened beneath it with openat2 RESOLVE_BENEATH | NO_SYMLINKS |
         NO_MAGICLINKS | NO_XDEV (never across a mount inside the folder)
```

- **Who wins: the record.** The host keeps, per folder, a record of what the writer last wrote
  there or found in step with the guest: path → (size, mtime, inode). It lives in the state
  folder (`<state>/sync-<disk>.record`, root's, 0600), where neither the guest nor the writer
  can write. The writer gets a read-only copy at its start and reports each change on its stdout;
  the launcher appends it, and compacts the file at the next start.
  - The writer replaces, renames over or removes a host entry **only while it still matches the
    record**. Anything else (a file the site owner added, or one that changed since the sync
    wrote it) is the owner's and wins. The guest's op on it is refused and logged, and the
    connection goes on.
  - A losing guest change isn't lost on the host side alone: at the next connection (every
    start, and every reconnect) the host pushes its winning files and folders into the guest's
    disk, so the two agree again.
  - A lost record line (a crash before it was appended) costs nothing: an entry both sides have
    with the same size and mtime is recorded again at the next listing, and anything else is the
    host's, which only means a push.
- **The listing.** Each connection starts with the guest's whole tree. Against it the host:
  - records what agrees (size and mtime; `mke2fs -d` keeps both, so a new disk sends nothing);
  - asks for each file the guest changed or made;
  - moves to the trash what the guest removed (recorded entries only; a folder goes once
    empty, so one holding an owner's file stays);
  - pushes what the host changed or made (the data as extents, holes skipped). The guest writes
    each into a temporary file, renames it into place, and answers; only a push the guest
    took is recorded. Its own inotify events for those files aren't sent back.

  After that the guest streams its changes: a file when it is closed after writing; new
  folders (with what is already in them); deletes, renames (a folder's watches follow it) and
  modes; a hard link when it is made. A queue overflow resends the listing.
- **The trash.** A removal never unlinks: the file moves to
  `<state>/trash/<YYYY-MM-DD>/<disk>/<its path>` (a rename, or a copy when the state folder is on
  another filesystem). The trash and each day's folder are root's, 0700, outside the web root;
  the day's folder for a disk is the pool user's, reachable only through the writer's handle.
  Days older than 7 are removed at a start.
- **What the guest can do to the host** is what it can do to its own disk, inside the folders,
  within caps, and only to entries the record says are the sync's:
  - paths are plain and relative (`..`, `.`, empty names, more than 64 levels or 4096 bytes are
    refused, and the connection closes); a name is its bytes, so one that isn't UTF-8 syncs too;
  - a symlink, a device, another mount or a name that isn't UTF-8 found on the host (and not in
    the record) is never followed, written through, removed or pushed: it is skipped, and
    logged once;
  - a file is refused before its body when it would take its folder past its cap (its disk's
    size, below), counting blocks, not length (a sparse file costs its data); the connection
    goes on, so a lowered `--write-disk-mib` or a full folder refuses those files once per
    listing and never loops. A guest that sends more data than it declared has that file
    refused at the cap;
  - a hard link reaches the host as a link to the copy already there (its blocks count once);
  - at most 1 Mi files and folders per folder, and a listing of at most 1 Mi entries and 64 MiB
    of paths;
  - a mode change goes only to a recorded entry, and never to a file with more than one name
    (a hard link the site owner made to a file outside the folder would carry it there);
  - 256 MiB/s and 2000 operations a second, each with one second of burst;
  - setuid, setgid and sticky bits are dropped.
- **A disk sized from its folder.** A writable disk is twice what its host folder takes (each
  inode once), at least 1 GiB, rounded up to a power of two (so the snapshot's key changes only
  when it doubles), and never less than `--write-disk-mib`. It only grows. `available` refuses a
  folder of more than 1 Mi entries, or one whose new disk's copy doesn't fit the state folder's
  filesystem, so `auto` falls back to gelada with the reason and `microvm` exits 125.
- **Crash safety.**
  - The host writes each file into a nameless file (O_TMPFILE), fsyncs it, links it to a
    temporary name and renames it into place, then fsyncs the folder. A writer killed in the
    middle leaves the old file whole and nothing partial.
  - The guest fsyncs a file before it sends it.
  - The guest's own writeback no longer waits for the host. Dirty pages older than 1 s are
    written every 0.5 s (the defaults are 30 s and 5 s), and the writable disks mount with
    `commit=1`. So an upload is out of guest RAM within about a second of its request, even
    when the host's writer is stuck. The first run without this lost an upload made while the
    writer was stopped and Firecracker was then killed (below).
  - A broken connection (either side crashing) is followed by a new writer and a new listing,
    which sends whatever didn't arrive.
- **A stop drains the sync.** The `sync` control line waits up to 8 s for every change made
  before it to be written on the host.

Measured on [xps] by `test/ext-microvm.sh` (the time from the PHP request returning, with the
file closed in the guest, until the host's copy has the right sha256):

| upload | PHP's write in the guest (two runs) | on the host after (two runs) |
|---|---|---|
| 100 KB | 0.7 / 2.4 ms | 9 / 26 ms |
| 10 MiB | 67 / 123 ms | 165 / 194 ms |
| 100 MiB | 684 / 1270 ms | 647 / 1370 ms |
| 1 MiB made while the writer was stopped, then the launcher killed | | 23 ms after the next start serves |
| 200 MiB, resent after the writer was killed mid-file | | 3.2 / 3.3 s (1 s reconnect delay, listing, transfer) |

The second run's guest was slower at writing the file too (another agent's load on the box).
Roughly, the host has a file 10–25 ms plus about 10 ms per MiB after PHP closes it.

The listing at a start compares 6 to 13 entries (300 MiB of uploads) in under 1 ms and sends
nothing. `mke2fs -d` keeps nanosecond mtimes, so the first start doesn't resend the folder.
The sync costs a page nothing: its threads wait in `poll` until a writable folder changes.

**Alternatives considered:**
- **Serving `/wp-content/uploads` through the guest** (nginx → FastCGI → a static handler in the
  guest). Backups and anything else on the host would still never see the files, and every
  image request would pay the vsock hop.
- **An NFS or 9p server over vsock** would make the host's folder the guest's. That puts a
  network file system under every upload and directory scan, and a file server parsing guest
  requests, as root, on the host. Firecracker has no virtio-fs.
- **Reading the guest's ext4 image on the host** means root parsing an image the guest wrote,
  which #75 rules out.
- **Offload plugins** (object storage) work unchanged in the guest, but they aren't a default.

## Egress: named hosts through the host (#72)

The guest still has no network device and no DNS. A `layer1.network.connect` port with
neither a `socket` nor an `address` (443 in the example) is an **egress port**. On it, the
guest reaches named hosts through the host, never an address of its own choosing
(`ext/fpm/src/egress.rs`, and the preload `ext/fpm/guest/vsock-connect.c`):

```
guest  php-fpm (curl, PHP streams, anything that calls getaddrinfo + connect)
         getaddrinfo("api.wordpress.org")  → 127.77.0.1: the preload answers, and keeps the name
         connect(127.77.0.1:443)           → vsock host:1517, "api.wordpress.org 443\n", the
                                              host's "OK\n" (or "ERR <why>\n" = ECONNREFUSED)
host   securecore-fpm: is 443 an egress port, and what does layer 2 decide for the name? Resolve
       it here; keep only public addresses that aren't the host's own; then
       securecore-fpm --egress-connect, as the pool user, connects and pipes (TLS end to end)
```

- **Only the hosts the config allows are reachable**, by layer 2's own decision
  (`securecore_attribution::hosts::net_verdict`, the function the extension uses too). While
  layer 2's host allowlist is active (on, an app set, mode not `off`), the name is checked
  against all of layer 2's host patterns: core's, `default`'s and every component's (exact
  names, `*.` wildcards, IP literals; IDNA, case and trailing dot normalised).
  - `enforce`: a name no pattern allows is refused.
  - `log`: it goes through, and the launcher logs it as layer 2 would have refused it
    (`egress: example.com:443 via … (layer2 log: refused in enforce by the host rule)`).
  - `off`, or layer 2 disabled: any name on an egress port, as gelada's port rules allow any
    host.

  Layer 2 then checks the caller inside the guest, per component, as on the host.
- **Never an internal address, whatever layer 2 says.** For a name and an IP literal alike, the
  host connects only to globally routable addresses. It refuses loopback, RFC 1918, link-local
  (cloud metadata), CGNAT, benchmarking, unique-local, documentation and v4-mapped forms of
  these, and every address on the host's own interfaces (read at each connection), public ones
  included. An internal target is reachable only through an explicit `connect` entry with a
  `socket` or an `address`, never through egress.
- **As the pool user.** The connect is made by `securecore-fpm --egress-connect`, one per
  connection, running as the site's pool user (no supplementary groups, an empty environment,
  no new privileges). The host's uid-based firewall rules (`iptables -m owner`, nftables
  `skuid`) apply to the guest's traffic as they would to the site's own php-fpm. The launcher
  (root) only parses the request, decides and resolves.
- **No DNS in the guest.** The names never leave the guest as DNS queries; the host resolves them.
  Port 53 in a connect list is just another egress port.
- **No tap device**, no host network configuration, and nothing in the guest listens. An IP the
  guest picks itself (`1.1.1.1:443`) is unreachable, because there is no route.
- The handshake is blocking inside `connect()`, which then returns 0 to a non-blocking caller
  (curl handles that). `getpeername`/`getsockname` on such a socket answer AF_INET addresses.
- The snapshot's warm-up VM has no egress listener, like its missing database.

## Secrets: delivered at each start (#72)

The guest's php-fpm needs the vault's env sources (`WORDPRESS_DB_PASSWORD`, the salts) and the
site's settings (`WORDPRESS_DB_HOST`, …). Until #72 the test image baked them into
`/etc/securecore/guest.env` on the root image. Now:

- **The launcher delivers them in every start message**, after a cold boot and after every
  restore. They travel as `env <NAME> <hex>` control lines on vsock 1515, which only the host
  can open. The set is each `layer2.vault.secrets[].env` (always) plus each `--guest-env <NAME>`,
  with the values from the launcher's own environment, as php-fpm on the host gets them (a
  systemd `EnvironmentFile`, compose's `environment`). A name the launcher lacks stops the start
  with the name, never a value.
- **Never baked in.** `scripts/guest-image.sh` takes no env file any more, and the guest reads
  none. The values are not boot arguments, so they are not in `/proc/cmdline`. Neither side
  logs them, and a malformed `env` line is refused without being echoed.
- **Never in a snapshot.** The snapshot is taken before any start message, so its memory has no
  value. php-fpm still has to start at boot for the warm-up and the snapshot, and the
  extension's vault refuses to load without its variables. So the host passes the *names*
  (`sc.env=WORDPRESS_DB_PASSWORD,…`, never a value) as a boot argument, and at boot each gets
  the placeholder `securecore-not-delivered-yet`. On a start message with `env` lines, init keeps them in its own memory and starts a
  fresh php-fpm master with them (graceful stop, start, then waits until it listens). A restore
  gets them again from its own start message. A `reload` (SIGUSR2/SIGHUP) starts php-fpm with
  them too.
- **A handshake comes first, and nothing echoes.** The host's first control connection carries
  `proto <N>` alone (no secret). The guest's init answers `ok` only when it speaks protocol N
  and was booted with `sc.proto=N`; it takes no start message otherwise. An older init (one
  that doesn't know `proto`, and would echo an unknown line back) fails the handshake, so it
  never sees an `env` line. Whatever a guest answers to a message that carried `env` lines is
  never put into the launcher's error or log; the guest logs its own reason, which never holds
  a value.
- **Nothing the launcher runs gets its environment**, where the secrets come from: the jailer
  (so Firecracker), the sync writer, the egress helper, and `mke2fs`, `e2fsck` and `resize2fs`
  (PATH only). Only the host's own php-fpm (layer 1 `gelada` or `off`) gets it, as before.
- **Guest memory can be swapped.** The secrets live in the guest's RAM (init's memory and
  php-fpm's), which is Firecracker's memory on the host: under memory pressure the host may
  write those pages to its swap, like any process's. Run microVM hosts with **no swap, or
  encrypted swap** (dm-crypt with a random key per boot, `zram`), as for the host's own
  php-fpm, which holds the same values. The snapshot files never hold them (above).
- `test/ext-microvm.sh` checks that the DB password appears in none of these: `rootfs.ext4`,
  the snapshot's `vm.mem` (as text or hex) and `vm.snap`, `console.log`, the launcher's log. It
  also checks that a restored guest still reaches the database.

## Density: N sites on one host (#72)

`test/ext-microvm.sh density` runs N sites' microVMs at once on [xps] (4 cores, 7.5 GiB; other
agents' stacks running beside them), for N = 1, 4, 8 and 16. Each site is a copy of the test site
(WordPress, Classic Editor, Yoast SEO, Contact Form 7, `examples/wordpress.json`: all three
layers, Contact Form 7 isolated) in its own volume and state folder, one VM per site, as the
product runs them.
- **VM 1 serves a load** (oha, 2 concurrent) while the others restore one after another.
- **The others are idle once started.**
- **PSS and RSS** are Firecracker's (`/proc/<pid>/smaps_rollup`), summed over the N VMs.
- **"KSM on"** is the same VMs after 30 s of ksmd (`/sys/kernel/mm/ksm/run` = 1, then unmerged and
  set back to 0).
- **Restore** is each start's "load and php-fpm ping" and "ready" from the launcher's log.
- **p50** is VM 1's front page (bench's method: 20 warm-up, then 100 sequential requests, all
  200s) with all N up.

Guest memory 512 MiB (the default):

| N | total PSS | per VM | RSS | PSS with KSM on | restores while the others run (ping / ready, ms) | VM 1 p50 | MemAvailable after |
|---|---|---|---|---|---|---|---|
| 1 | 289 MiB | 289 MiB | 289 MiB | 289 MiB (0 shared) | – | 136.5 ms | 5433 MiB |
| 4 | 567 MiB | 141 MiB | 567 MiB | 569 MiB (0 shared) | 122–173 / 273–331 | 136.5 ms | 5142 MiB |
| 8 | 971 MiB | 121 MiB | 971 MiB | 975 MiB (0 shared) | 28–141 / 82–240 | 136.9 ms | 4957 MiB |
| 16 | 1383 MiB | 86 MiB | 1383 MiB | 1367 MiB (0 shared) | 58–155 / 116–251 | 137.8 ms | 4792 MiB |

Guest memory 256 MiB (`DENSITY_MEM=256`), the same way:

| N | total PSS | per VM | RSS | PSS with KSM on | restores (ping / ready, ms) | VM 1 p50 | MemAvailable after |
|---|---|---|---|---|---|---|---|
| 1 | 245 MiB | 245 MiB | 245 MiB | 245 MiB (0 shared) | – | 135.7 ms | 5414 MiB |
| 8 | 920 MiB | 115 MiB | 920 MiB | 920 MiB (0 shared) | 109–132 / 186–231 | 136.0 ms | 5110 MiB |
| 16 | 1397 MiB | 87 MiB | 1397 MiB | 1375 MiB (0 shared) | 36–171 / 105–287 | 137.1 ms | 4794 MiB |

What this shows:
- **PSS equals RSS: restored VMs share nothing.**
  - Each site restores its own snapshot (the key holds the site's tree), so each VM maps its own
    `vm.mem`, and the page cache holds N copies of nearly the same pages.
  - The cost is what each guest touches. The loaded VM 1 is about 290 MiB, and an idle restored
    VM 60 to 75 MiB (16 VMs: 1383 MiB, with VM 1 the 290 of it).
- **KSM does nothing here.** ksmd merged 0 pages: it merges only memory marked `MADV_MERGEABLE`,
  and Firecracker doesn't mark guest memory. A host-wide `prctl(PR_SET_MEMORY_MERGE)` on each
  Firecracker would be the switch to try. That is a product change, so it isn't measured here.
- **"N VMs from one snapshot" is not something the launcher does.** The run also tried a "shared"
  layout: every site's `vm.mem` a hard link to site 1's.
  - Each launcher made a new snapshot instead: its start took 2.1–4.0 s to "ready", the time to
    make a snapshot. The PSS was the same as with each site's own snapshot (16 VMs: 1916 MiB,
    with the extra snapshot work in it).
  - Sharing pages across sites needs a snapshot that doesn't hold the site: one per root image and
    config, with the site disk attached after the restore, as the writable disks already are.
    That is a design change (follow-up below), not a default to flip.
- **Restores stay fast under load**: 82–331 ms to "ready" while VM 1 serves its load and up to
  15 others run. The php-fpm ping is 28–173 ms. Four CPUs are shared by all of it.
- **Density doesn't slow a served site.** VM 1's p50 is 136.5 ms with 1 VM and 137.8 ms with 16.
  (That p50 is with all three layers and Contact Form 7's isolated child on every request; #70's
  +5 ms figure is the extension off.)
- **The memory a host needs is the busy sites', not the count.** At about 290 MiB a busy site
  and 70 MiB an idle one, [xps]'s 7.5 GiB holds about 20 busy sites or 60 mostly idle ones, beside
  its other work.

### Recommendation

- **Keep 512 MiB of guest memory and php-fpm's pool of 5 workers (`pm = dynamic`, the defaults).**
  - A guest is charged only for the pages it touches, so its size costs an idle site nothing:
    16 VMs took 1383 MiB at 512 and 1397 MiB at 256.
  - What 256 saves is on a busy site: 245 against 289 MiB for VM 1 under this load. But that is
    96 % of a 256 MiB guest with 5 workers, against 56 % of 512. A heavier site (WooCommerce, image
    work) would hit the guest's limit there first, and its php-fpm workers would be killed instead
    of the page slowing down.
  - 256 MiB would want a smaller pool (3 workers, say), which wasn't measured. No default
    changes.
- **Size a host by its busy sites:**
  - about 300 MiB each for a busy site and 75 MiB each for an idle one, plus the launchers and the
    page cache;
  - restores stay under about 0.3 s to "ready" while the others run.
- **Next, if density matters more:**
  - a site-independent snapshot, so restored VMs share their clean pages through one `vm.mem`;
  - or marking guest memory mergeable for KSM.

  Either is a launcher change (follow-up 13 below).

## The guest's log: what it guarantees, and against whom (#86)

php-fpm's lines (layer 2's audit lines among them) and the init's own come to the launcher on
vsock 1514, numbered and acknowledged. A line that can't be delivered is counted in the
launcher's own log ("N guest log lines lost"), never dropped in silence.

- **Only the init writes the log.** The launcher makes a fresh 32-byte log key for every boot
  and every restore, and gives it to the init over the control port, which only the host can
  reach. A connection to 1514 that doesn't present that key first, within a second, is refused,
  and the refusals are counted in the launcher's log. A restored init's old key (the
  snapshot's) is refused too. It is never let in, and is only counted apart.
- **Labels.** php-fpm's output (master and workers) is logged as `guest: …`. The init's own lines
  go in a frame of their own and are logged as `guest-init: …`, which nothing php-fpm writes can
  produce.
- **Reserved room for the init.** The init's lines have the last 256 KiB of the guest's 4 MiB
  buffer to themselves, so php-fpm's lines can't crowd them out.
- **Escaping.** Control characters and the Unicode line separators in a guest line are escaped,
  so one guest line is one launcher line.

**This holds against code that isn't root in the guest: PHP, plugins, and anything they run as
the pool user. It does not hold against root in the guest.** The lines are produced inside the
guest, by php-fpm's master and the init, and the key is in the init's memory. Code that becomes
root in the guest (a kernel exploit, say) can forge lines, drop them before they are numbered,
or send nothing at all. What the launcher still guarantees then is that such lines are marked
as the guest's (`guest:`/`guest-init:`) and never read as its own (`securecore-fpm:`), and
that a key learned in one restored guest is worthless in the next. An audit trail that must
survive a compromised guest has to be kept outside it: the host's egress, sync and database
logs are the launcher's own.

## The guest is the host's own PHP (#101)

Sami decided on 12 Nov that the microVM adapts to the host: the guest runs the host's own
php-fpm, extensions and settings, not a fixed PHP image. `ext/fpm/src/capture.rs` captures them
at every start (and reuses the last capture when nothing it read changed), `pkgdb.rs` reads the
host's package database, and `phpconf.rs` parses php.ini and php-fpm's config.

```
vda  rootfs.ext4  the SecureCore base (the release's, sha256 in installed.json): /sc/securecore-init
                  (static), /sc/libsc-vsock-connect.so, /sc/warm.php, empty mount points; nothing else
vdb  php-<key>.ext4   the host's php-fpm, every extension in its extension folder, the libraries
                  they load, /bin/sh, sendmail, ImageMagick and ghostscript when present, their data
                  (CA certificates, ImageMagick's modules…); mounted at /sc/php, and each top-level
                  folder bound onto the base's (/sc/php/usr → /usr; /lib64 → usr/lib64 follows the
                  host's own link)
vdc  conf-<key>.ext4  php.ini, the scan folder's files, and php-fpm.conf for this pool; at /sc/conf
vdd  site, vde… the writable folders (as before)
```

**What is captured.** php-fpm (`--php-fpm`, a path or a name on the usual PATH), every `.so` in its
extension folder (`php-fpm -n -i`, run as nobody once php-fpm and its libraries are checked; a
config's `extension_dir` wins), every `.so` a config names by path inside PHP's own folders, and
for each of these the libraries the host's own loader lists (`ld.so --list`, glibc or musl). The
helpers PHP runs, when the host has them: `/bin/sh` (exec, popen, proc_open), sendmail
(`sendmail_path`), `convert`/`magick` and `gs`; with ImageMagick, its module and config folders
(its coders are loaded by name, not by the linker); with ghostscript, its resources. Data:
`ld.so.cache`, `passwd`/`group` (never `shadow`), the CA certificates, `openssl.cnf`,
`localtime`. Never anything under `/etc/ssl/private`.

**What is checked** (Sami: in case the host is compromised):
- **Package checksums.** A file a package installed must match its package manager's record:
  dpkg's md5sums, apk's SHA-1 (`Z:Q1…`), rpm's file digests (SHA-256 on current distributions; the
  host's `rpm -qa` reads the database, chrooted, as nobody). A merged `/usr` is looked up both ways.
- **Ownership.** Every file root's and writable by no one else (its group only when that is
  root's), in folders that are the same all the way from `/`.
- **Links.** On the way to a binary or library: a top-level link (`/lib64` → `usr/lib64`) or a
  merged `/usr`'s own (`/usr/sbin` → `bin`), a link a package installed, or the package manager's
  alternatives. A link no package installed (ldconfig's soname links, busybox's applets) is
  allowed only when it leads to a file a package installed whose checksum matches: an unpackaged
  file is never reached through one.
- **Configs under `/etc`** that the data includes (`passwd`, `group`) are held to the ownership
  rules only, as configs are: rpm records `/etc/passwd`'s checksum as installed. In data folders and configs a link is followed and what it
  points at is checked as a file of its own (and copied, so the guest has no link there).
- **Configs.** php.ini, the scan folder (`PHP_INI_SCAN_DIR` as php-fpm reads it), php-fpm's
  config and its includes: the same ownership rules, parsed, and refused when `extension` or
  `zend_extension` names native code outside the captured set, or `auto_prepend_file`,
  `auto_append_file` or `opcache.preload` (in php.ini or a pool's `php_*_value`) runs a PHP file
  outside the app root.
- **The bytes that boot.** Each file is hashed as it is read, and the copy that goes into the
  disk is hashed again (a file changed in between is refused).

Any failure is one line naming the file, and the launcher refuses (`microvm`, exit 125) or falls
back (`auto`):

```
securecore-fpm: /var/www/html/securecore.json: layer1.isolation is "microvm" but the microVM can't run here (the host's PHP can't be captured: /usr/lib/x86_64-linux-gnu/libxml2.so.2.9.14: its bytes don't match what dpkg recorded for libxml2 (Md5 …, the file's is …): it changed after its package installed it). …
… (the host's PHP can't be captured: /usr/local/lib/php/extensions/no-debug-non-zts-20230831/sockets.so: the file is owned by 1234:0 with mode 644; everything captured must be root's and writable by no one else)
… (the host's PHP can't be captured: /usr/local/etc/php/conf.d/zz-sc101-evil.ini:1: extension = /opt/sc101/evil.so loads native code from outside the captured set (…))
```

**The manifest.** `<state>/capture-manifest.json`, root's, 0600: every entry's path, where its
bytes came from, owner, mode, sha256 and source (`dpkg:libxml2`, `unpackaged (root-owned)`,
`config`…). A capture that differs from the last logs what changed
(`capture: 1 entries changed since the last capture: /usr/local/etc/php/conf.d/zz-sc101.ini`).

**Caching.** The PHP layer is keyed by the sha256 of every captured entry (path, mode, owner,
sha256, link target) and the guest's mount points; the config layer by its files' sha256s; the
snapshot's key holds both. A start where nothing the last capture read has changed (each path
stat'ed: device, inode, size, mtime, ctime, mode, owner) reuses it without hashing anything. A
php.ini edit rebuilds only the config layer (a few KiB) and the snapshot.

**One VM per pool** (#100 review). Each pool in php-fpm's config gets a microVM, each a launcher
of its own (`--pool <name>`, state in `<state>/pool-<name>/`, the PHP layer shared):
- it listens where the pool says (`listen`, with `listen.owner`, `listen.group` and `listen.mode`;
  `$pool` replaced), so nginx needs no change; `--listen` still wins for a single pool;
- its php-fpm runs as the pool's `user`/`group` (`--pool-user` wins);
- the guest's pool carries `pm`, `pm.*`, `env[]`, `php_value`/`php_flag`/`php_admin_value`/
  `php_admin_flag`, `clear_env`, `request_terminate_timeout`, `rlimit_*`,
  `security.limit_extensions` and `catch_workers_output` over, and leaves out what names the host's
  paths (logs, slowlog, chroot, chdir; the launcher logs which). `env[X] = $NAME` delivers `NAME`
  from the launcher's environment, as php-fpm's master on the host would read it;
- the first launcher tells systemd it is ready once every pool's VM serves, passes stop and reload
  signals on, and stops them all when one stops. Its wait has a deadline (`--pools-ready-within`,
  300 s); a stop signal during it is taken at once. Stopping the pools' launchers is SIGTERM, up
  to 10 s, then SIGKILL, and each is reaped. A pool's own launcher never falls back by itself: the
  first one decides for the whole config. Every Firecracker API call has a 60 s timeout.
- `--listen` keeps the pool's `allowed_clients` or ACLs, and refuses when they can't apply to its
  kind of socket.

Several pools of one site share its writable folders; each VM syncs its own disk with them.

**Every check before `auto` commits** (#100 review). Everything a start does before the boot now
happens before the choice: the host checks, the capture and its validation, the pool's user and
sockets, the vault's env sources and the pool's `env[]`, `claim_state`, the space every new disk
and the snapshot need (with a margin: a twentieth of the filesystem and at least 1 GiB stays
free, for the database), the PHP and config layers, the site disk (copied as the pool user) and
the writable disks. So `auto` falls back on any of them with the reason. And a VM `auto` chose
that then fails before it serves anything (its boot, its listening socket) falls back to gelada
too (`layer 1 isolation auto: gelada, because the microVM failed before it served (…)`);
`microvm` still exits 125.

**A bare 3306 and `localhost`** (#100 and #102 reviews, and Sami's decision on the second's
verification). A `{ "port": 3306 }` with no socket or address: the site's own `DB_HOST` is only a
hint for which target the operator approved to use, never a target of its own, because the
launcher is root and a site must not point it at Redis, D-Bus or another pool's php-fpm. The
launcher reads `DB_HOST` from `wp-config.php` (a literal, or the official image's
`getenv_docker('WORDPRESS_DB_HOST', …)` from its own environment; comments are skipped, and two
defines that disagree are no answer):
- `localhost` (or `localhost:/path`): that socket, PHP's default socket
  (`mysqli.default_socket`, `pdo_mysql.default_socket`), or MySQL's standard places, never `/tmp`.
  The socket must be the database user's (`--db-user`, `mysql`, else `mariadb`), in folders only
  root or that user may write, or exactly the one `--db-socket` names (then root's is accepted);
- TCP: MySQL's own ports on the loopback (3306, 33060 for the X protocol), or exactly the
  host:port `--db-address` names. The connection is made as the pool user (`--egress-connect`), so
  the host's uid-based firewall rules apply, never as root;
- anything else, or a `DB_HOST` the launcher can't read: the guest gets no database on 3306 (it
  stays an egress port, public names only), and the launcher says why. The start still serves.

A socket in its own folder is bind-mounted into the jail with that folder; a socket directly in a
folder services share (`/`, `/run`, `/var/run`, `/tmp`, `/var/tmp`, `/dev`, `/dev/shm`) is
bind-mounted alone, never the folder. This holds for `connect[].socket` entries too.

Whatever 3306 reaches, the guest has a unix socket at each of PHP's default sockets, the host
socket's own path and `/run/mysqld/mysqld.sock`, so `DB_HOST=localhost` works as on the host.

**Who may connect** (#102 review). A pool's `listen = 9000` binds `127.0.0.1:9000`, never every
address (only a pool that names one, `0.0.0.0:9000`, gets that). `listen.allowed_clients` is
enforced on every TCP connection; `listen.acl_users` and `listen.acl_groups` on a unix socket
(the socket is then 0666 and each connection's peer credentials are checked, root always
admitted). Refusals are logged (the first five, then every thousandth).

**Only this site's pools** (#102 review, Sami's decision). A microVM holds one site's files, so
only pools whose `chdir`, `doc_root` or `prefix` is this app root (or inside it, on the host or as
the guest sees it) run here; php-fpm's only pool may name none. Any other pool refuses the whole
config (`pool [X] serves another site (…)`), and `auto` falls back to gelada once. All pools of
one site share its writable folders (each VM syncs its own disk with them), so they must be of one
trust level.

**Unpackaged files** (#102 review, Sami's decision: trust on first use). The installer records the
sha256 of every captured file no package's checksum covers (a compiled php-fpm, PECL extensions,
`securecore.so`) in `/var/lib/securecore/unpackaged.json` (root's, 0600;
`securecore-fpm --check-capture --write-record`), and every capture checks them against it: one
that differs or isn't recorded is refused, naming it (`run the installer again` after an
upgrade). What lives in `/etc` (`hostname`, `hosts`, generated certificate bundles) differs from
host to host and changes in normal use, so it is held to the ownership rules only, as configs are.
The installer is the only writer: a start without a record refuses (`run the installer to record
unpackaged files`), so `auto` runs gelada and `microvm` exits 125. `--unpackaged-record` names
another file.

**Parsing as PHP does** (#102 review). A value with two quoted strings (PHP joins them), or text
after a quoted string other than a comment, is refused with its file and line rather than
guessed; `\"` and `\\` in double quotes are read as PHP reads them. Pool settings go into the
guest's config byte for byte as the host's file has them. `ffi.preload` is refused unless every
file it names is captured. Data files are captured only when everyone may read them (a 0600 key
beside the certificates stays out). dpkg's diversions are followed; rpm's SHA-224 and SHA-384
digests are checked, and an algorithm the capture can't compute refuses the file. rpm itself must
pass the ownership rules before it runs, and its package's checksum after.

**A long first start** (#100 review). Under systemd (`NOTIFY_SOCKET`), the launcher sends
`EXTEND_TIMEOUT_USEC=30000000` every 10 s from the moment it starts preparing until the VM serves,
and `STATUS=` lines for each step, so a first capture, disk build and snapshot never run into
`TimeoutStartSec`.

**A program PHP runs that the guest lacks** is logged: the preload hooks `execve`, `execv` and
`execvp`, and one that fails with ENOENT for a name on no PATH folder writes
`securecore-guest: <name> isn't in the guest: the host had no such program to capture (PHP tried
to run <path>)` to the worker's stderr, which reaches the launcher's log.

**Proved on other package managers** (`test/ext-capture.sh`): Debian trixie (php8.4-fpm, dpkg),
Alpine 3.22 (php84-fpm, apk, musl's loader) and Fedora 42 (php-fpm, rpm) capture their own
distribution's PHP, and refuse it, naming the file, once a packaged `opcache.so` has a byte
appended, once it isn't root's, and once a config loads a `.so` from `/opt`.

**Measured on [xps]** (the `test/ext-microvm.sh` stack: WordPress's php8.3-fpm image, PHP 8.3.36,
its libraries dpkg's; launcher log figures, "started … after launch"):

| start | what it did | to ready |
|---|---|---|
| first build (empty state) | capture 2.7 s, PHP layer 2.0 s, config layer 23 ms, site disk 0.6 s, two writable disks, cold boot + warm-up + snapshot 1.1 s, restore | 8.3 s |
| after a PHP package upgrade (`zlib1g` 1.3.1-1+b1 → +deb13u1 from trixie-security) | capture 2.7 s, PHP layer 1.8 s, a new site disk 0.6 s (the config differed too), snapshot 1.4 s | 7.3 s |
| a php.ini-only change | capture 2.7 s, config layer 23 ms, snapshot 1.2 s, restore | 4.6 s |
| a normal restore | the capture reused (every path stat'ed), restore 25 ms | 0.26–0.28 s |

What is captured there: 1135 files (201 MiB) and 119 links, 1116 of the files checked against
dpkg's records and 19 unpackaged and root-owned (php-fpm, `php`, the extensions,
`securecore.so`), 19 configs, one pool. The PHP layer is a 283 MiB image (188 MiB on disk), the
config layer a few KiB, and the base `rootfs.ext4` 37 MiB (8 MiB used) instead of 1110 MiB.
Most of the PHP layer is ghostscript's resources and ImageMagick's libraries; gd, imagick and
intl bring their own (libavif, libgomp, ICU).

**Limits.** glibc's gconv modules aren't captured (PHP's iconv then has glibc's built-in
charsets). Fonts ghostscript finds through fontconfig aren't either. A dpkg diversion isn't
followed. The preload is built against glibc 2.36, so a musl host (Alpine) captures and validates
but doesn't boot until a musl preload ships.

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
8. **The database path over vsock.** Done in #70 (section 3): 0.230 → 0.114 ms a query, +15.1 →
   about +5 ms a front page. The product version is #71.
9. **Snapshot lifecycle.** Decide when a snapshot is rebuilt (image, site or config sha256),
   resync the guest clock after a restore, and find out why the first page after a restore
   takes 0.3 s rather than 80 ms.
10. **Run the `test/ext-*.sh` suites against a microVM target.** Their harness needs to
    reach php-fpm in the guest, not only through `docker compose exec php`.
11. **Density.** Measured (#72, "Density" above): restored VMs share nothing, KSM merges
    nothing, keep 512 MiB and 5 workers.
12. **arm64 hosts.** mirab pins Firecracker for x86_64 only. arm64 needs its own pin and kernel
    (mirab has `kernel-arm64-vz.config` for vz only).
13. **A snapshot that sites share.** Snapshot the guest before its site disk is attached (one per
    root image and config), attach the site's disk after the restore as the writable disks are,
    and key the snapshot without the site tree. Restored VMs would then share their clean pages
    through one `vm.mem`. Or have the launcher mark guest memory mergeable
    (`prctl(PR_SET_MEMORY_MERGE)` on Firecracker) and measure KSM again.

## Needs a decision

- **Fallback semantics.** When a site asks for the microVM and KVM is missing, should the
  launcher refuse or fall back to gelada? The recommendation is the three values above, with
  `"auto"` as the only one that falls back.
- **Which kernel to pin.** The options:
  - mirab adds the five lines and securecore pins mirab's published kernel (recommended);
  - securecore builds and publishes its own kernel from mirab's recipe.

  Separately: pin a mirab canary now, or wait for a promoted release that carries `vm/`
  images.
- **Whether about +5 ms p50 (one run +4.84, one +5.30) meets "under +5 ms" for the default.**
  If it doesn't, the next lever is fewer database round trips, not the transport. That is
  section 3's finding: the best vsock path is 0.06 ms a query over the host, and tap,
  `idle=poll` and one vCPU don't do better. (#68 asked whether +15 ms was acceptable for an
  opt-in mode; the default decision of 10 Nov replaced that question.)
