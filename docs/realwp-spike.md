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
- **Pre-booted core vs booting per request.** The model as built boots WordPress in the child
  **per request** — that is the ~62 ms/plugin above. Pre-booting (the parent boots WordPress
  once, children fork and inherit it copy-on-write) would amortize that ~62 ms to the fork
  cost, which the #11 numbers put at ~2 ms, at the price of a resident booted-WordPress parent
  (roughly the 73 MiB PSS, shared across forks). **Pre-boot is not wired here:** the parent has
  no network and no database, so it cannot boot against the live database. The issue's design
  — the parent boots "with no plugins and no plugin options, holding no secrets" — points the
  way: boot from core's autoloaded-options snapshot (options are not secrets), children then
  fetch their plugin's options through the gateway. That is the next step if the per-request
  boot cost is too high.

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
