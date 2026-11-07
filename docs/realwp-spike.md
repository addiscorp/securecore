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
  **database gateway** in `SecureCore.php` runs it against core's real `$wpdb`. (No SQL policy
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
`RealWpSandbox` class in `plugin/SecureCore.php`; `sandbox/worker.php` (realwp branch);
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
