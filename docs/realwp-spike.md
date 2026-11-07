# Spike: real WordPress in the sandbox (part 1 of #42)

What this builds, what runs, and the numbers. Part 1 of the redesign Sami approved on 6 Nov:
make the sandbox child run *inside a real WordPress* instead of against forwarding stand-ins
(the forward-stub worker, #11, is why the compatibility sweep found 0/17 plugins loading,
docs/compatibility.md). Measured on the `docker/` stack (WordPress 7.1.4, php-fpm 8.3,
MariaDB 11.4, worker on PHP 8.3 CLI), Docker on colima.

This is a spike for measurements. It does **not** include the gelada wrapping, the SQL
policy, or the security tests — those are later parts of #42. Where request state could not
be made to match core, it is reported here rather than built out.

## How it works

Off by default (the #11 forward-stub worker stays, for the benchmark). Turn it on with
`SECURECORE_REALWP` — define it in `wp-config.php` (core side) and set it on the worker
(`docker/compose.yml` reads `SECURECORE_REALWP` from the environment):

```
SECURECORE_REALWP=1 docker/setup.sh     # or set it on the worker service + wp config set SECURECORE_REALWP true
```

- **Worker boot.** The child boots the site's own WordPress by including `wp-settings.php`
  directly (never `wp-config.php`): `sandbox/bootstrap.php` defines `ABSPATH`, the table
  prefix and a couple of debug constants, pre-seats a connectionless `$wpdb` subclass, and
  includes `wp-settings.php`. The sandbox holds no database password and has no network; every
  query the `$wpdb` subclass would run goes back to core over the request socket — the
  **database gateway** in `securecore-core.php` runs it against core's real `$wpdb`. (No SQL policy
  yet: core runs whatever query the sandbox sends — see "Not closed yet".)
- **Fork per request.** `sandbox/worker.php` forks a child per connection, as before; the
  child (`sandbox/realwp.php`) boots WordPress, reseeds `mt_rand`, loads its one plugin, and
  fetches that plugin's options through the gateway like any other query.
- **Mirroring.** The plugin registers into the sandbox's WordPress; the child diffs the
  registration globals and sends core the new entries, which core mirrors as stubs that call
  back into the sandbox: hooks, shortcodes, REST routes, scripts, styles, admin menus (and the
  page registries `admin.php` checks). The ~15 salted pluggable functions (`wp_create_nonce`,
  `wp_verify_nonce`, `wp_hash`, `wp_salt`, the auth cookies) plus `wp_mail` are forwarded to
  core so they agree with core's secrets.
- **Request state.** After core resolves the request it replays the main query and current
  user into the sandbox (`sandbox/realwp.php` `setup_request_state`), so a callback sees the
  same post/query/user. WordPress objects that cross the socket as hook arguments or return
  values (`WP_Query`, `WP_Post`, `WP_User`, `WP_Term`, `WP`, `WP_Screen`, REST
  request/response, `WP_Error`) are marshalled to markers each side rebuilds from its own
  WordPress (`sandbox/marshal.php`); an object neither side knows crosses as `null`.

Files: `sandbox/bootstrap.php`, `sandbox/realwp.php`, `sandbox/marshal.php` (new); the
`RealWpSandbox` class in `plugin/securecore-core.php`; `sandbox/worker.php` (realwp branch);
`bin/securecore-worker` (widens open_basedir to the WordPress root under realwp);
`docker/worker.Dockerfile` (adds the `mysqli` extension — present, never connected).

## Plugins

`test/compat.sh` functional checks, each plugin sandboxed on the running `docker/` stack.

| plugin | loads sandboxed | its pages (200, ran sandboxed) | its feature (same check as trusted) | notes |
|---|---|---|---|---|
| Classic Editor 1.7.0 | yes | front, dashboard, Plugins — all yes | **yes** — Posts → Add New opens the classic editor | audit clean; full functional pass |
| Yoast SEO 28.8 | yes | front, dashboard, Plugins — yes; **admin screen 500** | **yes** — canonical, og:title and the schema graph are written into the post page | front end clean; admin screen and the admin-bar node are the gaps |
| Contact Form 7 6.2.4.1 | yes | front, dashboard, Plugins — yes; **admin screen 403** | **no** — the `[contact-form-7]` shortcode renders empty and the REST submit does not complete | loads and its pages are sandboxed; the form feature needs more |

Against the baseline: the compatibility sweep (#39) had **0/17** plugins even loading
sandboxed. All three here load, two reach their feature, and Classic Editor passes its check
cleanly end to end.

## Measurements

`bun bench/load.ts` on the `docker/` stack, median of 1 run, with the worker in each model.
Hello Dolly is the one sandboxed plugin for the "1 plugin" rows; Hello Dolly + the bench
plugin for "2 plugins".

| config | front `/` p50 (ms) | `/wp-admin/` p50 (ms) | throughput c=8 (req/s) | worker PSS (MiB) |
|---|---|---|---|---|
| SecureCore off | 104.8 | 124.9 | 32.1 | — |
| #11 fork worker, 1 plugin | 106.2 | 127.9 | 28.9 | 25 |
| #11 fork worker, 2 plugins | 109.3 | 131.1 | 27.5 | 30 |
| real WordPress, 1 plugin | 166.5 | 193.0 | 18.8 | 73 |
| real WordPress, 2 plugins | 227.6 | 246.1 | 13.7 | 95 |

- **Per sandboxed plugin:** the #11 forward-stub worker adds **~2 ms**; the real-WordPress
  model adds **~62 ms** and ~45–65 MiB of worker PSS. The ~62 ms is one WordPress boot in the
  child, paid on every request.
- **Pre-booted core vs booting per request.** The model as built in part 1 boots WordPress in
  the child **per request** — that is the ~62 ms/plugin above. Pre-booting (the parent boots
  WordPress once, children fork and inherit it copy-on-write) amortizes that ~62 ms to the fork
  cost, at the price of a resident booted-WordPress parent. **This is now built — see "Part 1b:
  pre-boot" below** for how the parent boots with no database (from a core-written options
  snapshot) and the measurements across all three models.

## Request state — what a callback sees

The question the spike had to answer. For the **front end** it works: with the main query and
current user replayed, Yoast's `wp_head` callbacks read the queried post and write the correct
canonical, og:title and schema graph. Hook arguments and return values that are WordPress
objects marshal correctly (that is what carries `WP_Query`/`WP_Post` into a callback).

Where it does not (yet): **admin** requests. The admin page and the admin bar pass objects and
rely on screen/menu state that only partly reconstructs across the socket — Yoast's admin
screen 500s and its `admin_bar_menu` callback gets a throwaway admin bar whose nodes never
reach core. An object neither side recognises crosses as `null`, which is where these fail.

## Not closed yet (and why)

- **wp-config.php is readable from the sandbox.** The real-WordPress model needs the WordPress
  root in `open_basedir` to boot core, which also exposes `wp-config.php`. Denying it is
  gelada's job (hole #1 in the issue), a later part; `test/site.sh`'s `read-wp-config` check
  therefore fails under realwp. The default #11 model still passes `test/site.sh` in full (no
  regression).
- **No SQL policy.** The gateway runs whatever query the sandbox sends, so a DB-write attack
  (create an admin through raw SQL / `wp_insert_user`) still reaches the database. That policy
  is a later part of #42; `test/site.sh`'s write-attack checks fail under realwp by design.
- **Admin screens** (Yoast 500, CF7 403) and **CF7's shortcode + REST submit** need more work
  (above). The mechanism is in place; these are the specific callbacks/objects that don't
  round-trip yet.

## Part 1b: pre-boot

Part 1 booted WordPress in the child, per request — the ~62 ms above. Part 1b boots it once in
the worker parent and forks each child from that booted state, so a request pays the fork, not
a boot. Turn it on with `SECURECORE_PREBOOT` alongside `SECURECORE_REALWP` (both on the worker;
`SECURECORE_REALWP` also in wp-config, as in part 1). Without it the real-WordPress worker
still boots per request, which is the "real WordPress, per request" row in the table below.

### How the parent boots with no database

The parent has no network and no request socket, so it can reach neither the database nor the
gateway. Core writes a snapshot of its own autoloaded options to
`wp-content/securecore/options-snapshot.php` — a plain `<?php return [...]` of the raw option
values — and the parent boots against it: a connectionless `$wpdb` subclass (`make_snapshot_wpdb`
in `sandbox/bootstrap.php`) serves the one query a no-plugin boot makes, `wp_load_alloptions()`'s
autoloaded-options SELECT, from that file, and treats anything else as empty (logged). With the
options in hand WordPress runs `wp-settings.php` to the end with no plugins (the
`SECURECORE_SANDBOX` guard empties the active-plugin lists), warms the REST server, and stops.
That booted image is what every child inherits copy-on-write.

Two things a no-plugin boot still reaches for are caught rather than served: it validates an
auth cookie (no user — returns null) and, on the default theme, writes a block-pattern cache
transient (swallowed; the parent recomputes it once and the children inherit it). Both are
logged as pre-boot notes; neither is fatal.

### Fresh options in the child

After the fork the child points `$wpdb` at the request socket (the gateway), runs
`wp_set_wpdb_vars()` on it so its table names and field types are set, and drops the parent's
`alloptions`/`notoptions` cache. So the first `get_option()` re-reads the whole autoloaded set
fresh through the gateway: no option value a plugin sees is served from the parent's copy. The
snapshot exists only to carry the parent through its bootstrap.

### Keeping the snapshot current

Core rewrites the snapshot when a **boot-structural** option changes — siteurl/home, the theme
(`template`/`stylesheet`), the permalink structure and rewrite rules, charset/locale/timezone,
the widget map, and a handful more — and writes its sha1 to `options-snapshot.hash`. It
deliberately does not rewrite on the churn that cannot affect a no-plugin boot: a plugin's own
options (a sandboxed plugin writes through the gateway as raw SQL and never trips core's option
hooks anyway; a trusted plugin like WooCommerce writes dozens of `woocommerce_*` options on
activation), transients, the cron array, and the active-plugin lists are all excluded. Without
this the worker re-boots on ordinary option writes — a WooCommerce activation alone flapped it
through a whole compatibility run.

The worker checks the hash once per accepted connection (driven by a request, never a timer);
when it differs it finishes the request it just forked and exits 75 for its supervisor to
restart it — Docker's `restart: unless-stopped` here, a systemd `Restart=` otherwise — which
re-boots from the new snapshot. A booted WordPress cannot be re-initialised in place, so a
re-boot is a restart. The one request that forked against the old snapshot is the bounded
staleness; because the child reads option values fresh through the gateway, only the parent's
own structural state (e.g. rewrite rules) can briefly lag, never a value a plugin reads.

### Request shape

The parent boots the front-end shape (no `WP_ADMIN`). A child serving an admin request defines
`WP_ADMIN` and loads `wp-admin/includes/admin.php` after the fork, as part 1 did, so admin
screens are no better and no worse than part 1. Front end and REST take the full win.

### Review note 1

`db_answer()` now allowlists the four `$wpdb` calls the sandbox makes — `query`, `db_version`,
`db_server_info` and `get_col_info` — and audits anything else as `db.refused`, ahead of the
SQL policy.

### Plugins under pre-boot

`test/compat.sh` for the three target plugins, run under both models on the same build (the
per-request column is the part-1 behaviour, confirmed on this build as the baseline):

| plugin | per request (part 1) | pre-boot |
|---|---|---|
| Classic Editor 1.7.0 | front/dashboard 200, **feature passes**, audit clean | front/dashboard 200, **feature passes**, but 21 non-fatal `Undefined property` notices (user/term) |
| Yoast SEO 28.8 | front/dashboard 200, **feature passes** (SEO meta), admin screen 500 | **front/dashboard/admin 500** |
| Contact Form 7 6.2.4.1 | front/dashboard 200, shortcode empty, admin 403 | **front/dashboard 500**, admin 403 |

So pre-boot does **not** keep parity: Classic Editor still passes functionally (with new
notices), but Contact Form 7 and Yoast — which load and reach (Yoast) their feature under the
per-request model — serve 500s under pre-boot. The regression and its cause are in "Still open
after 1b" below. (`test/site.sh` fails under both real-WordPress models by design — wp-config
readable, no SQL policy — the deferred parts of #42.)

### Measurements

`bun bench/preboot.ts` on the `docker/` stack: the three worker models side by side, three runs
each in one session, with `DISABLE_WP_CRON` on so the autoloaded options stay still. Front-page
and wp-admin p50, requests/s at concurrency 8, and the worker's summed PSS (master + forks),
median with [min, max]. Hello Dolly is the one sandboxed plugin for the 1-plugin rows; Hello
Dolly + the bench plugin for the 2-plugin rows.

| config | front `/` p50 (ms) | `/wp-admin/` p50 (ms) | req/s c=8 | worker PSS (MiB) |
|---|---|---|---|---|
| SecureCore off | 103.9 [103.7, 104.1] | 124.6 [124.2, 124.8] | 26.2 [26, 26.6] | — |
| #11 stub, 1 plugin | 108.3 [107.9, 110.2] | 132.1 [129.5, 132.1] | 22.2 [22.2, 22.6] | 28 [27, 28] |
| #11 stub, 2 plugins | 113.0 [111.1, 114.1] | 134.8 [133.2, 135.3] | 21.7 [19.9, 21.7] | 32 [31, 32] |
| real WP, per request, 1 plugin | 167.7 [167.4, 168.6] | 188.2 [187.5, 189.1] | 15.2 [14.8, 15.4] | 73 [73, 74] |
| real WP, per request, 2 plugins | 230.5 [230.4, 232.5] | 249.8 [249.6, 250.0] | 11.2 [11, 11.2] | 103 [101, 106] |
| **real WP, pre-boot, 1 plugin** | **110.3 [109.5, 110.5]** | **132.9 [132.5, 133.6]** | **20.8 [20.7, 21.2]** | **71 [71, 71]** |
| **real WP, pre-boot, 2 plugins** | **113.8 [113.4, 115.1]** | **137.7 [137.4, 137.7]** | **19.1 [16.1, 19.3]** | **84 [83, 87]** |

- **Per sandboxed plugin (front p50, the 2-plugin row minus the 1-plugin row):** #11 stub **+4.7 ms**,
  real WP per request **+62.8 ms**, real WP pre-boot **+3.5 ms**. Pre-boot removes the ~62 ms
  per-request WordPress boot and pays only the fork — the same ~3–5 ms the stub pays.
- **Against "off" (front p50):** the first sandboxed plugin adds +4.4 ms (stub), +63.8 ms (per
  request), **+6.4 ms (pre-boot)**. Pre-boot runs a *real* WordPress per request for roughly what
  the forward-stub worker costs, and roughly a third of the per-request-boot latency at two
  plugins (113.8 ms vs 230.5 ms).
- **Throughput at c=8** tracks the same story: pre-boot 20.8 / 19.1 req/s (1 / 2 plugins) vs per
  request 15.2 / 11.2, approaching the stub's 22.2 / 21.7.
- **Worker PSS:** pre-boot holds one resident booted WordPress in the parent (~71 MiB), shared
  copy-on-write across the forks, so it grows slowly with plugins (71 → 84). Per request each
  child boots its own (73 → 103). The stub carries no WordPress (28 → 32).

### Still open after 1b

- **Pre-boot regresses request state for plugins that read the user/terms.** This is the
  finding of the spike. Under pre-boot the sandbox child builds *malformed* user and term
  objects from the gateway — `Undefined property: stdClass::$ID` / `$user_login` (user.php) and
  `$term_id` (class-wp-list-util.php) — which the per-request boot (part 1) does not. A simple
  plugin only logs the notices and still works (Classic Editor's feature passes end to end). A
  plugin that runs capability or meta logic over those objects fatals: Contact Form 7 and Yoast
  both register `map_meta_cap`, which core fires on *every* capability check and mirrors back to
  the sandbox; a query built there from the bad object reaches core's `$wpdb->query()` as a
  non-string and the request 500s (front and admin). So CF7 and Yoast, which *load* and reach
  their feature under part 1's per-request model, serve 500s under pre-boot. The cause is in how
  the child reconstructs these objects after forking from the pre-booted parent (it is not stale
  object cache — flushing the whole cache after the fork changed nothing); it is a request-state
  boundary, exactly what this spike was asked to surface rather than build around. `db_answer()`
  now refuses a non-string query defensively, but the malformed objects upstream are the real
  gap. **Pre-boot is not ready to be the default real-WordPress mode until this is fixed** — it
  stays opt-in behind `SECURECORE_PREBOOT`, and the per-request model (part 1) is unaffected.
  **→ Fixed in Part 1c below.**
- **The admin gaps from part 1 remain** (Yoast's admin screen, CF7's shortcode and REST submit),
  underneath the regression above.
- **The parent still holds every autoloaded option in memory**, plugin options included, for
  its lifetime. They are inert — the child never reads the parent's copy — but "no plugin
  options in the parent" is only met in the sense that none is *served* from it. Holding only
  the options a no-plugin boot reads would need core to know which options are core's, which
  WordPress does not expose; it is a hardening step, not a correctness one.
- **A re-boot is a process restart** (exit 75 + supervisor), so it needs a supervisor that
  restarts on a non-zero exit — Docker `restart: unless-stopped`, systemd `Restart=`. A bare
  `bin/securecore-worker` in a plain shell exits instead; `pcntl_exec` is not an option (it is
  in the launcher's `disable_functions`).
- **`site.sh` still fails under the real-WordPress model** by design (wp-config readable,
  no SQL policy) — gelada and the SQL policy are later parts of #42.

## Part 1c: correct pre-boot state

### The cause

The child was **swapping `$GLOBALS['wpdb']`** after the fork: it threw away the `$wpdb` the
parent had booted against and installed a fresh gateway `$wpdb` (then re-ran
`wp_set_wpdb_vars()` on it). WordPress had already booted in the parent against the *original*
`$wpdb`, and parts of that booted state reach for the object they were set up with rather than
re-reading `$GLOBALS['wpdb']`. After the swap those reads hit the now-inert snapshot `$wpdb`
(no gateway, no request socket) and came back empty — so user and term rows rebuilt into
objects with no `ID` / `user_login` / `term_id`. A simple plugin only logged the notices; a
plugin that then ran capability or meta logic over the bad object built a broken query and the
request 500'd. This is why flushing the object cache in 1b did nothing (the stale thing was a
`$wpdb` reference, not a cached value), and why the per-request model never saw it (it boots
once, against one `$wpdb`, and never swaps).

The diagnostic that found it: dumping `$GLOBALS` right after boot in a per-request child and a
pre-booted child for the same front request showed them **nearly identical** (the only diffs
were the worker's own file-scope vars leaking into `$GLOBALS` and a one-key `$_SERVER`
difference), which ruled out the post-boot snapshot and pointed at something dynamic. The
worker's parent-boot-miss log confirmed the snapshot `$wpdb` answered a few non-autoloaded
options empty during the parent's boot (`WPLANG`, the image-crop sizes, `theme_switched`) —
harmless, but the same "answered empty off the snapshot" shape that, through a retained
reference, produced the malformed objects.

### The fix

The pre-boot `$wpdb` is now **one object for the life of the process** (`make_snapshot_wpdb` in
`sandbox/bootstrap.php`): while `Registry::$parentBoot` is true it serves the options query from
the snapshot and logs anything else; once a child clears that flag after the fork, the **same
object** forwards every query to core over the request socket. The child no longer swaps `$wpdb`
or re-runs `wp_set_wpdb_vars()` (the parent already ran it on this object and the child inherits
the table names) — so any reference taken during the parent's boot keeps working.

### Plugins under pre-boot (after 1c)

`test/compat.sh`, pre-boot, against the per-request baseline (same build):

| plugin | per request (part 1) | pre-boot (after 1c) |
|---|---|---|
| Classic Editor 1.7.0 | front/dash 200, feature passes, audit clean | **front/dash 200, feature passes, audit + debug.log clean** (no new notices) |
| Yoast SEO 28.8 | front/dash 200, feature passes, admin 500 | **front/dash 200, feature passes**, admin 500 |
| Contact Form 7 6.2.4.1 | front/dash 200, shortcode empty, admin 403 | **front/dash 200**, shortcode empty, admin 403 |

Pre-boot now matches the per-request model for all three: Classic Editor is a clean pass with
no new notices, and Yoast and CF7 reach exactly their per-request results. What remains (Yoast's
admin screen 500, CF7's shortcode/REST and admin 403, `site.sh`'s wp-config/SQL checks) is
identical under both models — the part-1 request-state gaps and the by-design `site.sh`
failures, not a pre-boot regression.

### Measurements (after 1c)

`bun bench/preboot.ts 3` — the +3.5 ms-per-plugin result still holds after the fix (the child
now does slightly *less* work per request — no `$wpdb` swap, no `wp_set_wpdb_vars()`):

| config | front `/` p50 (ms) | `/wp-admin/` p50 (ms) | req/s c=8 | worker PSS (MiB) |
|---|---|---|---|---|
| SecureCore off | 104.9 [104.8, 105.3] | 125.7 [125.2, 126.3] | 25.0 [24.8, 25.1] | — |
| #11 stub, 1 plugin | 109.2 [108.9, 109.8] | 130.8 [130.3, 131.1] | 22.0 [21.8, 22.3] | 29 [28, 30] |
| #11 stub, 2 plugins | 111.0 [110.7, 111.7] | 133.2 [133.2, 133.2] | 21.2 [21.1, 21.3] | 31 [30, 32] |
| real WP, per request, 1 plugin | 168.5 [168.2, 169.6] | 188.3 [188.2, 190.0] | 14.9 [12.6, 15.1] | 73 [73, 73] |
| real WP, per request, 2 plugins | 232.0 [230.6, 232.8] | 251.6 [250.0, 253.9] | 10.8 [10.8, 11.1] | 104 [102, 104] |
| **real WP, pre-boot, 1 plugin** | **110.3 [110.2, 110.9]** | **133.2 [132.4, 133.2]** | **21.4 [20.5, 21.5]** | **69 [69, 70]** |
| **real WP, pre-boot, 2 plugins** | **115.4 [113.3, 116.5]** | **137.5 [136.9, 138.9]** | **19.8 [19.6, 19.8]** | **83 [83, 84]** |

Per sandboxed plugin (front p50, 2-plugin row minus 1-plugin row): #11 stub **+1.8 ms**, real WP
per request **+63.5 ms**, real WP pre-boot **+5.1 ms**. The per-plugin cost is still the fork, not
a WordPress boot — a few ms like the stub (1b measured +3.5 ms; the ~5 ms here is run-to-run
variance, same order), against +63.5 ms for the per-request boot. The 1c fix did not cost
anything: the child does slightly less now (no `$wpdb` swap, no `wp_set_wpdb_vars()`). Throughput
and PSS are unchanged from 1b — pre-boot keeps one resident booted WordPress (~69→83 MiB) where
per request each child boots its own (73→104).

### Dev-stack fix (#45)

`scripts/package.sh` freezes installed-file mtimes for reproducible release zips, so php-fpm's
`validate_timestamps` opcache did not notice when `install-securecore` overwrote core PHP —
core-side changes silently kept running the old bytes until opcache was reset. Fixed:
`docker/install-securecore.sh` now gives the files it writes a current mtime, and
`docker/setup.sh` restarts php after installing so the change is live immediately.

## Part 1d: core-only snapshot (#47)

Through 1b/1c the snapshot held **every** autoloaded option except transients and the
active-plugin lists — which includes every other plugin's own autoloaded settings (license
keys, SMTP/API credentials). The pre-booted parent loaded all of it into the snapshot `$wpdb`'s
`$snapshot` property, inherited by every forked child, so a sandboxed plugin could read another
plugin's options straight out of memory. That contradicts #42's "parent boots with no plugins,
no plugin options and no secrets", and the gateway's future row policy would not see those reads.

**Fix (#47).**
1. `write_options_snapshot()` now snapshots only an **allowlist of WordPress's own options** —
   the names `populate_options()` seeds (parsed from the site's own `wp-admin/includes/schema.php`,
   so it tracks the version) plus the active theme's `theme_mods_<stylesheet>` — intersected with
   the autoloaded options. A core option boot needs that is not on the list (e.g. `rewrite_rules`,
   added after install, not by `populate_options()`) shows up as a parent-boot miss in the worker
   log; the child reads it fresh through the gateway when it matters, so the miss is harmless.
2. After the fork the child calls `$wpdb->drop_snapshot()` (sets the `$snapshot` property to
   `[]`), so it keeps none of core's options in memory either — belt and braces with the gateway
   forwarding, which never consults the snapshot in a child.

**gelada (later).** When the gelada policy lands, it should **deny the sandbox read access to
`wp-content/securecore/options-snapshot.php`**. The worker reads the snapshot in the parent,
before any sandbox profile is applied to a child, so denying the child has no cost; it closes the
file as a second path to the same data. (The snapshot now holds only core options, but the deny
is still correct defence in depth.)

**Canary test (`test/canary.sh`, `test/canary-plugin/`).** A secret autoloaded option
(`securecore_canary_secret`) is set from wp-cli — a non-sandboxed context — then a sandboxed probe
scans `$GLOBALS` and the `$wpdb` object (private properties included, via reflection) for the
value. It must not find it, and the value must be absent from the snapshot file.

With the fix:

```
ok   probe sandboxed (manifest generated)
ok   snapshot file does not contain the secret
ok   probe did not find the secret in sandbox memory
canary: PASS
```

With the fix reverted (snapshot back to all autoloaded options, and `drop_snapshot()` disabled),
the same test fails — which is what proves it catches the leak:

```
ok   probe sandboxed (manifest generated)
FAIL snapshot file contains the secret
FAIL probe found the secret in sandbox memory (the leak #47 describes)
canary: FAIL (2)
```

Nothing else regressed: under pre-boot `test/compat.sh` still gives the #46 results (Classic Editor
clean, Yoast and CF7 at their per-request baselines, zero worker re-boots), and `bench/preboot.ts`
still shows the per-plugin cost as the fork — front p50 pre-boot 110.3 → 113.2 ms for 1 → 2
plugins (+2.9 ms/plugin) against 165.3 → 228.8 ms (+63.5 ms) for the per-request boot.

## Part 2: the database gateway policy (#42)

Through part 1 the gateway ran **whatever** query the sandbox forwarded against core's real
`$wpdb`. A sandboxed plugin could therefore read any row core could — every user's password hash,
every other plugin's secret option, the mail credentials — and write anything, including making
itself an administrator. Part 2 puts a policy in front of the gateway.

### How a query is checked

`db_answer`'s `query` path (now `RealWpSandbox::gateway_query()` in `plugin/securecore-core.php`) runs
every forwarded statement through `SqlPolicy` (`plugin/sql-policy.php`) first:

1. **Parse** with [phpmyadmin/sql-parser], pinned to **6.0.1** in `plugin/composer.json` and
   vendored into the release zip (`plugin/vendor/`, copied by `scripts/package.sh`). Dependencies
   come from a registry by exact version, no git pins — APS 10. An **unparseable** or
   **multi-statement** query is refused.
2. **Check the shape** (deny-by-default on statement *type*, before any table is considered). The
   statement is classified by the parser's statement **class** — its text, which an alias or
   comment could disguise, is not trusted — and only an allowlisted type ever runs; everything else
   is refused whatever it names (see *Statement-shape allowlist* below). The tables it touches are
   found by scanning the SQL for core's own table names, read live from `$wpdb` (`$wpdb->users`,
   `tables('all')`, …), word-bounded so `wp_users` ≠ `wp_usermeta`. (`getTables()` alone misses
   JOINed and `CREATE` targets, so the policy does not rely on it for that.)
3. **Decide on the data**, per the table and operation below. A statement touching no core table —
   the plugin's own tables, another plugin's, or a session/metadata statement like `SET NAMES` —
   is free on data (its shape was already checked in step 2).

[phpmyadmin/sql-parser]: https://packagist.org/packages/phpmyadmin/sql-parser

### Statement-shape allowlist

An earlier cut of this policy decided only on the tables a statement named, and let anything that
named no core table through. That is bypassable: `SET @s = 0x<hex of "SELECT user_pass FROM
wp_users">`, then `PREPARE x FROM @s`, then `EXECUTE x` — none of the three names `wp_users` as a
table the scan can see, so the column checks never run and the `EXECUTE` reads the hashes. Reading
a file off the DB server (`SELECT LOAD_FILE('/etc/passwd')`, `… INTO OUTFILE`), `CALL`-ing a stored
procedure, `LOAD DATA INFILE` into a plugin table, and `CREATE FUNCTION` / `VIEW` were open the
same way. The policy now allowlists statement **types** by the parser's statement class:

- **run:** SELECT, INSERT, UPDATE, DELETE, REPLACE; SHOW, DESCRIBE / DESC, EXPLAIN; the session
  `SET`s (SET NAMES, SET SESSION sql_mode, SET autocommit — never `SET @x` or `SET @@…`);
  transaction control (START TRANSACTION, BEGIN, COMMIT, ROLLBACK [TO [SAVEPOINT]], SAVEPOINT,
  RELEASE SAVEPOINT); CREATE / ALTER / DROP / TRUNCATE on a **non-core** table;
- **refused, whatever it names:** PREPARE, EXECUTE, DEALLOCATE, HANDLER, DO, USE, CALL, LOAD DATA,
  LOCK / UNLOCK, CREATE PROCEDURE / FUNCTION / TRIGGER / EVENT / VIEW, GRANT, CTEs (`WITH …`), the
  table-maintenance statements, and anything the parser does not build a statement for (PREPARE,
  EXECUTE, DEALLOCATE, HANDLER, DO and USE all parse to **zero** statements in 6.0.1, so the "no
  statement" case is a refusal, not a pass).

Inside an allowed statement, `LOAD_FILE(`, `INTO OUTFILE` and `INTO DUMPFILE` are refused too —
string literals are stripped first, so a query that merely mentions them as data (searching
`post_content` for `"into outfile"`) is not caught. Transaction-control statements are matched on
the normalised text *before* the parser, because 6.0.1 reports several of them (COMMIT, ROLLBACK,
SAVEPOINT, …) as parse errors; the match is anchored with no `.*`, so a second statement cannot be
smuggled in after one. `test/policy-unit.php` asserts every refused shape and every allowed one;
`test/policy.sh` runs the full SET → PREPARE → EXECUTE chain live — blocked with the policy on,
and (proving the policy is what blocks it) reading `user_pass` with it off.

### The policy

| data | read | write |
|---|---|---|
| `wp_users.user_pass`, `.user_activation_key` | never (a query naming them is refused; `SELECT *` returns the row with them stripped) | via `users` grant |
| `wp_usermeta` `session_tokens` | never | via `usermeta:capabilities` grant |
| `wp_usermeta` `{prefix}capabilities`, `{prefix}user_level` | via `usermeta:capabilities` grant | via that grant |
| `wp_users` rows (other columns) | allowed, secrets stripped | via `users` grant |
| options `active_plugins`, `admin_email`, `users_can_register`, `default_role`, `cron`, `mailserver_login`, `mailserver_pass` | via `option:<name>` grant | via that grant |
| options `siteurl`, `home`, `{prefix}user_roles` | **allowed** (see below) | via `option:<name>` grant |
| the plugin's own tables / options / meta | free | free |
| core content: `posts`, `postmeta`, `terms`, `comments`, … | free | free (see open questions) |

A refused statement never reaches the database; the gateway returns what a failed `$wpdb` query
returns (`false` / empty, `last_error` = `securecore: denied <reason>`), so the plugin degrades
instead of crashing, and the refusal is audited as `db.deny` with the plugin and a SQL excerpt.
Reads that are allowed-but-filtered run and then have their result rows trimmed: `user_pass` /
`user_activation_key` columns dropped; `session_tokens` and (ungranted) capability rows dropped; a
**bulk** options read (`wp_load_alloptions`' autoload `SELECT`) cut to the core allowlist plus the
plugin's own options, so it cannot hand the sandbox every plugin's settings. A read that *names* a
protected option or meta_key is refused rather than filtered, because such reads usually project
only `option_value` / `meta_value` and leave no key column to strip.

"The plugin's own options" are the ones its code writes (`update_option`/`register_setting`/…,
scanned into the manifest's new `db.options` by `sandbox/scan.php`). A plugin cannot launder a
protected option into "its own" by writing it — the deny beats the own-claim, in both the manifest
generator and the policy.

### siteurl / home / {prefix}user_roles — a deliberate divergence

#42 lists `siteurl`, `home` and `{prefix}user_roles` among the options a sandbox may not read
without a grant. The policy **allows reading them** (writes still need a grant) and keeps them in
the pre-boot snapshot, because:

- the sandbox's *own* WordPress needs them — `siteurl`/`home` for every URL it builds,
  `user_roles` for `WP_Roles` (without it `current_user_can()` is empty) — so read-denying them
  regresses the front page and dashboard below part 1d's results, which #42 requires we hold;
- they are **public, non-secret** config (anyone can see a site's URL; roles are definitions, not
  data).

So the real protection on these three is "a plugin cannot *change* them". Flagging it for review:
if you want them read-denied too, the child needs another way to source them (e.g. keeping the
core-only snapshot in its cache rather than re-reading over the gateway), which is a bootstrap
change, not a gateway one.

### Snapshot and the shared allowlist (step 4)

`write_options_snapshot()` and the gateway's bulk filter now share one source of truth —
`snapshot_option_allowlist()` — so the options the parent boots from and the options a child may
re-read can never disagree. It is `core_option_names()` **plus** `{prefix}user_roles`, **minus**
the read-denied options (`admin_email`, `users_can_register`, `default_role`, `cron`,
`mailserver_login`, `mailserver_pass`, and the active-plugin lists). The live snapshot dropped from
549 options to **91** core options; `admin_email`, `mailserver_pass` and `active_plugins` are gone,
`siteurl`/`home`/`{prefix}user_roles` remain.

### The manifest's `db` section and grants

`generate_manifest()` now writes `"db": { "options": [...], "tables": [...], "grants": [] }`.
`options`/`tables` are scanned from the plugin's code (its own options and `$wpdb->prefix . '…'`
tables). `grants` is **empty by default** — a sandboxed plugin reaches none of core's sensitive
data until a human adds `users`, `usermeta:capabilities` or `option:<name>`. (No admin UI for
grants yet; they are a manifest edit.)

### Caching (AGENTS.md §7c)

The policy is per-query, but its inputs are memoized: the schema parse (`core_option_names()`), the
shared allowlist and the per-request `SqlPolicy` (built once at sandbox boot) are all computed once
and reused. The remaining cost is the per-query parse, measured below.

### Open questions / out of scope

- **Core-content writes.** The policy frees reads *and* writes of `posts`/`terms`/`comments`
  (many plugins create posts); #42 names only "reads of core content" as free and is silent on
  writes. Left free to avoid regressing compat; flagging whether post/comment writes should be
  gated in a later part.
- **Cross-plugin isolation.** The policy protects *core's* sensitive data, not one plugin's tables
  or specifically-named options from another; a bulk options read is filtered, but an explicit
  `get_option('other_plugins_secret')` is still allowed. That is a separate concern from #42's
  scope.
- **One install per database.** Core tables are recognised from *this* install's `$wpdb` (its
  prefix and table names). A second WordPress sharing the same MySQL database under a different
  prefix (`otherprefix_users`, `otherprefix_options`) is invisible to the policy — the table scan
  does not match it — so a sandboxed plugin may read and write those tables as if they were its
  own; `otherprefix_users.user_pass` counts as free. SecureCore assumes one install per database;
  a shared database is out of scope for this part.

### Tests

`test/policy.sh` is a live canary on the pre-boot stack: a sandboxed probe
(`test/policy-plugin/`) tries the blocked and allowed operations and reports each to the worker
log; the script checks them, and checks from outside the sandbox that blocked writes did not land.
It runs the probe **with the policy on, then with it off** (the vendored parser moved aside, so the
gateway falls back to allowing everything), proving the block is the policy's doing:

```
== policy ON ==
ok   core secret admin_email kept out of a bulk options read (bulk_admin_email=absent)
ok   another plugin's secret kept out of a bulk options read (bulk_foreign_secret=absent)
ok   wp_users.user_pass not readable (read_user_pass=empty)
ok   usermeta session_tokens not readable (read_session_tokens=empty)
ok   usermeta capabilities not readable without a grant (read_caps=empty)
ok   prepared-statement bypass (SET/PREPARE/EXECUTE) blocked (bypass_user_pass=empty)
ok   the plugin's own option is readable (read_own_option=own-ok)
ok   siteurl is readable (needed to render) (read_siteurl=nonempty)
ok   core content (posts) is readable (count=97)
ok   a write to the protected option admin_email was blocked
== policy OFF (parser disabled: the same probe should now leak) ==
ok   without the policy, admin_email leaks into the bulk read (bulk_admin_email=present)
ok   without the policy, the other plugin's secret leaks into the bulk read
ok   without the policy, user_pass is readable
ok   without the policy, session_tokens is readable
ok   without the policy, capabilities are readable
ok   without the policy, the prepared-statement bypass reads user_pass (bypass_user_pass=nonempty)
ok   without the policy, the admin_email write landed
== grant usermeta:capabilities ==
ok   with the grant, capabilities are readable
```

The destructive and structural refusals (DROP/ALTER/TRUNCATE on a core table, multi-statement,
INSERT into users, capability escalation, the whole statement-shape allowlist, …) cannot all be
run live without wrecking the stack, so `test/policy-unit.php` asserts them at the `decide()` level
with a real `$wpdb` — 61 verdicts, including that a grant opens exactly its own door and nothing
else:

```
ok    DROP core table                    deny: DROP on a core table
ok    escalate capabilities              deny: writes the protected usermeta key 'wp_capabilities'
ok    write active_plugins               deny: writes the protected option 'active_plugins'
ok    SET user variable                  deny: SET of a user or system variable
ok    PREPARE                            deny: unsupported statement
ok    SELECT LOAD_FILE                   deny: uses a server file function (load_file / outfile / dumpfile)
ok    CALL                               deny: unsupported statement type
ok    WITH (CTE)                         deny: unsupported statement type
ok    select * users (secrets stripped)  allow
ok    COMMIT                             allow
ok    search posts (outfile literal)     allow
ok    insert users (granted)             allow
ok    still DROP-denied (granted)        deny: DROP on a core table
policy-unit: PASS
```

**No regression.** `test/canary.sh` (#47) still passes. Under `SECURECORE_PREBOOT`,
`test/compat.sh` gives the part-1d / #48 results for each plugin's own checks:

| plugin | front / dashboard / plugins | its admin screen | its feature | `db.deny` it hits |
|---|---|---|---|---|
| classic-editor 1.7.0 | 200, sandboxed | — | passes | **none** |
| wordpress-seo 28.8 | 200, sandboxed | 500 (the part-1c `admin_bar_menu` `WP_Admin_Bar`-null throw, as #48) | passes (SEO meta on a post) | active_plugins (read), cron (read+write) |
| contact-form-7 6.2.4.1 | 200, sandboxed | 403 (as #48) | incomplete (shortcode/REST, as #48) | **none** |

`test/site.sh` fails under pre-boot for all three, as it does from part 1b on and as it did at #48:
it is a part-1/#11 test (it asserts the probe cannot read `wp-config.php`), but under
`SECURECORE_REALWP` the worker's `open_basedir` includes the WordPress root so core can boot, and
closing `wp-config.php` to a child is gelada's job in a later part of #42. So `test/compat.sh`'s
overall verdict stays `no` for the same reason as #48; every check that is the plugin's own is
unchanged.

The only plugin the new policy denies anything is Yoast: it reads `active_plugins` (to spot
conflicting plugins) and reads/writes `cron` (to schedule its background indexing) — both on #42's
denied list, both refused as `db.deny`, and both degrade gracefully (its front page, dashboard and
SEO-meta feature are unaffected, exactly as #48; only the background work it cannot schedule is
lost). **Neither the policy nor the plugin is wrong**: a sandboxed plugin should not be able to
rewrite the site's WP-Cron array (whose entries name hooks core later fires) or read the active-
plugin list; a deployment that wants Yoast's indexing grants it `option:cron`. Classic Editor and
CF7 hit zero denials.

`bench/preboot.ts 3` (front-page p50, median [min, max] of 3 runs):

| config | front p50 (ms) | /wp-admin/ p50 (ms) | req/s c=8 | worker PSS (MiB) |
|---|---|---|---|---|
| off | 113.8 | 132 | 22.5 | — |
| stub 1p / 2p | 111.3 / 115.3 | 134.1 / 140.2 | 21.5 / 20.1 | ~28 |
| realwp 1p / 2p | 266 / 215.9 | 279.8 / 232.2 | 7.4 / 12.2 | ~70 |
| preboot 1p / 2p | 125.4 / 112.7 | 149.1 / 135.1 | 18.5 / 19.4 | ~73 |

Pre-boot stays an order of magnitude ahead of the per-request real-WordPress boot (≈113–125 ms
vs ≈216–266 ms) — the policy did not change that. The policy's own cost is the per-query parse:
`SqlPolicy::decide()` measured standalone (stub `$wpdb`, opcache on, mix of seven real query
shapes) is **≈0.22 ms/query**. A page makes a few dozen gateway queries, so the aggregate is a few
milliseconds (visible as the preboot 1p figure sitting ~12 ms over part 1d's 110.3 ms; the 2p
figure, 112.7 ms, is within run-to-run noise of it). If that ever matters, `decide()` is a pure
function of the query string and could be memoised per distinct statement — most of a request's
queries repeat. (AGENTS.md §7c: its inputs — the schema parse, the allowlist, the per-request
policy object — are already computed once and reused.)

## Part 3: the worker inside gelada (#42)

Parts 1–2 isolated the sandbox with the launcher's `open_basedir`/`disable_functions` and, in the
Docker spike, a `network_mode: none` container with the site mounted read-only. Under
`SECURECORE_REALWP` the launcher has to widen `open_basedir` to the WordPress root so core can
boot — which leaves `wp-config.php` readable (part 1d flagged this as "gelada's job later"). Part
3 runs the worker inside [gelada](https://github.com/addiscorp/gelada), an OS sandbox applied at
`exec` (Landlock + seccomp on Linux), so the worker and every child it forks get real filesystem
and network confinement from the kernel.

### How it is wired

gelada comes from crates.io by exact version — `cargo install gelada --version 0.2.0 --locked` in
a builder stage of `docker/worker.Dockerfile`, copied into the worker image (APS 10: a registry by
version, no git pin; the worker image carries no Rust toolchain). The worker is launched as:

```
gelada --deny /var/www/html/wp-config.php [--deny wp-config-*.php …] \
       --allow-write /run/securecore \
       --allow-write /var/www/html/wp-content/uploads \
       --allow-write /var/www/html/wp-content/cache \
       -- securecore-worker <socket> <plugins> <manifests>
```

- **`--deny` wp-config.php** (and any `wp-config-*.php` backups the wrapper finds): unreadable even
  though the WordPress root is readable, so the DB password never reaches the sandbox.
- **network off, no `--allow-unix-socket`:** every outbound connect fails — MySQL, php-fpm's
  FastCGI socket, any TCP host. The worker still binds and accepts on its *own* socket, because
  gelada's seccomp blocks `connect`, not `socket`/`bind`/`listen`/`accept`, and the socket's folder
  (`/run/securecore`) is `--allow-write`, so a writable path that is a socket is usable. Core,
  which is not sandboxed, connects to it from outside.
- **`--allow-write` only** the socket dir, uploads and cache; everything else — `wp-admin`,
  `wp-includes`, `plugins`, `themes`, `mu-plugins` — is read-only. gelada's own `TMPDIR` is
  writable and cleaned up.
- The parent reads `options-snapshot.php` at boot; under the CLI it is sandboxed from the start, so
  it is **not** denied in this layer. #47's deny of the snapshot *to a child* moves to the
  per-child layer (part 4, below).

The container is no longer `network_mode: none` and the site is mounted read-write: gelada is now
the boundary, so the test can prove it is gelada doing the work (a real install may keep the
no-network container and a read-only mount as extra layers). The worker container keeps Docker's
**default** seccomp profile — no `security_opt` override. That profile already allows the
`seccomp()` syscall, Landlock and seccomp user-notification, and gelada sets `no_new_privs` itself,
so it installs its *own* seccomp + Landlock filter on **top** of the default profile rather than
replacing it; `seccomp:unconfined` would have dropped the whole default profile, which is less
confinement, not more. (gelada 0.2.0's own test suite passes under the default profile on this
colima, as root and as an unprivileged user.) Colima's kernel is 6.8 (Landlock needs 5.13+).

### Property tests (`test/gelada.sh`, `test/gelada-plugin/`)

A sandboxed probe tries each attack with functions the launcher's `disable_functions` does **not**
block (`file_get_contents`, `mysqli_connect`, `file_put_contents`), so what stops them is gelada.
It runs with gelada on, then with gelada off (the `SECURECORE_NOGELADA` dev switch runs the
launcher directly), then on again per-request:

```
== gelada ON, pre-boot ==
ok   wp-config.php is unreadable (read_wp_config=failed)
ok   DB_PASSWORD is not defined in the sandbox (db_password_const=undefined)
ok   MySQL connect blocked (connect_mysql=blocked(2002))
ok   php-fpm connect blocked (connect_php_fpm=blocked(2002))
ok   arbitrary host connect blocked (connect_arbitrary=blocked(2002))
ok   writes to uploads allowed (write_uploads=ok)
ok   writes to the plugins folder blocked (write_plugins=failed)
ok   writes to wp-includes blocked (write_wp_includes=failed)
ok   writes to mu-plugins blocked (write_mu_plugins=failed)
ok   the request still renders (200)
== gelada OFF, pre-boot (same probe should now leak) ==
ok   without gelada, wp-config.php is readable (read_wp_config=read 6113 bytes)
ok   without gelada, MySQL is reachable (connect_mysql=reached(1045))
ok   without gelada, php-fpm is reachable (connect_php_fpm=reached(2006))
ok   without gelada, the plugins folder is writable (write_plugins=ok)
== gelada ON, per-request ==
ok   per-request: wp-config.php unreadable / MySQL blocked / plugins writes blocked / renders 200
```

`reached(1045)` for MySQL without gelada is the TCP connection succeeding and MySQL then refusing
the bad credentials — it got there; with gelada the socket never opens (`2002`).

### No regression

`test/canary.sh` (#47) still passes under gelada. `test/compat.sh` in **both** modes (pre-boot and
per-request) gives the #48 per-plugin results unchanged: classic-editor all green; wordpress-seo
front/dash/feature green, admin 500 (the part-1c `admin_bar_menu` throw); contact-form-7 front/dash
green, admin 403 + feature incomplete. No plugin hits a gelada filesystem or network denial while
rendering — `--allow-write` on uploads/cache plus read-everything-else is enough. `test/site.sh`
still fails (its overall verdict stays `no`), as it has since part 1b: it is a part-1/#11 test, and
two of its checks no longer apply under realwp+gelada — `wp_remote_post` returns a `WP_Error`
instead of throwing (so its probe reports "sent"), and this part drops the container's
`network_mode: none` on purpose so the network block is gelada's to prove, which trips site.sh's
"worker has no network" check. A deployment that keeps `network_mode: none` as an extra layer makes
that check pass again.

`bench/preboot.ts 3` (front-page p50, median of 3 runs), worker wrapped in gelada:

| config | front p50 (ms) | /wp-admin/ p50 (ms) | req/s c=8 | worker PSS (MiB) |
|---|---|---|---|---|
| off | 103.8 | 123.4 | 25.7 | — |
| stub 1p / 2p | 106.4 / 107 | 126.8 / 128 | 22.4 / 22.1 | ~29 |
| realwp 1p / 2p | 166.6 / 166.5 | 186.4 / 186.3 | 15.1 / 15.1 | ~75 |
| preboot 1p / 2p | 110.2 / 109.4 | 131.8 / 131.4 | 21.3 / 21.2 | ~73 |

gelada costs **about nothing per request**: pre-boot front p50 is 110.2 / 109.4 ms with the worker
inside gelada, against 110.3 / 113.2 ms for the same pre-boot worker without it in part 1d — within
run-to-run noise. That is expected: gelada applies the Landlock ruleset and seccomp filter once,
when the worker starts, and every forked child inherits them with no per-request syscall. Worker
PSS is unchanged (~73 MiB). So the sandbox is real isolation at no measurable runtime cost.

### A real-server install

gelada is a single binary. Building it on the server would need a Rust toolchain there, which the
rest of SecureCore avoids. **Recommendation:** ship prebuilt per-platform gelada binaries in the
SecureCore release (the same canary→promote model as the worker PHP), each verified by sha256
against the release manifest before use, and have `install.sh` / the launcher pick the one for the
host's OS and arch. gelada supports Linux (Landlock + seccomp) and macOS (Seatbelt); on a host
with neither (an old kernel, Windows) gelada refuses to run rather than falling back unsandboxed,
so SecureCore must treat "no gelada" as "do not start the worker", not "start it unsandboxed".

### The per-child layer (open design question for part 4)

Today one gelada sandbox wraps the whole worker, so every child shares one profile. #42 wants each
child narrowed to *its* plugin — deny the options snapshot (#47), allow only that plugin's own
upload subfolder, and so on. gelada has `restrict_self()` for exactly this ("a worker that forks a
child per request can narrow each child"), applied from the forked child before it loads the
plugin, and it only ever restricts further. The snag is that `restrict_self()` is a Rust function
and the child is PHP. The options:

1. **A tiny PHP extension** exposing `restrict_self()` (and the builder for its profile). The child
   calls it right after the fork, before `require`-ing the plugin. `restrict_self()` is designed
   for this fork-per-request shape and refuses a process that has other threads (PHP-CLI has none),
   and it can narrow — turn unix sockets fully off, deny more paths — but not add a unix-socket
   allowlist (its supervisor would be a thread). It ships as one more per-platform binary.
2. **Re-exec gelada per request** (`gelada <per-plugin opts> -- php child.php`). Simple and needs
   no extension, but it throws away the pre-boot fork (parts 1b–1d): each request pays the full
   WordPress boot again. A non-starter for the numbers below.
3. **PHP FFI** into gelada's C ABI. No extension to build, but FFI would have to stay enabled in
   the sandbox, which is itself an attack surface a hostile plugin could use.

**Recommended: option 1, the extension.** It keeps the pre-boot fork (the whole point of parts
1b–1d), uses `restrict_self()` as its author intended, and does not leave FFI enabled in the
sandbox. Option 2 only if an extension cannot be shipped for a platform, and never with pre-boot.
