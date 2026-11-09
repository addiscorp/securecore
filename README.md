# SecureCore

Runs WordPress plugins in a separate sandbox process instead of in the web server. WordPress
core stays on the server's own PHP; each sandboxed plugin runs in the SecureCore worker, and
every call between a plugin and WordPress crosses SecureCore and is checked against the
plugin's manifest.

```
browser → nginx → php-fpm (WordPress core)
                    │  securecore-core.php (mu-plugin): one unix-socket connection per request
                    ▼
       SecureCore worker  —  its own container, NO NETWORK, only wp-content/plugins (ro)
         php worker.php, opcache on, booted once, listening on the socket
         per connection: pcntl_fork() → child includes that one plugin, serves, exits
```

The worker is one process for all sandboxed plugins, like php-fpm's master. It boots
`setup.php` once (no plugin) with opcache on, so compiled plugin code sits in shared memory
the children inherit. Per request it forks; the child includes that one plugin's main file
fresh — exactly like PHP re-running a plugin each request, made cheap by opcache — and serves
the conversation. So state is clean per request (a fresh process), and a child only ever
loads one plugin, so the per-plugin manifest checks still mean something.

Isolation is **where the worker runs, not PHP flags**: its own container with no network,
only the plugin folder mounted read-only and the socket dir, a clean environment, and
`disable_functions` for exec/shell/proc. On a bare server, the same as a systemd unit with
`PrivateNetwork=yes` and read-only paths.

## How a request works

1. `securecore-core.php` (in the SecureCore plugin) is loaded early by the mu-plugin loader while
   the plugin is active. Plugins with a manifest in `wp-content/securecore/manifests/` are
   hidden from core's plugin loader.
2. For each, it connects to the worker's unix socket. One connection = one `pcntl_fork()` in
   the worker = one child for this request. If the worker is not running, those plugins do
   not load, and wp-admin says so.
3. The child includes the plugin. `setup.php` has already, in the worker's parent, scanned
   the plugin with `token_get_all` for the WordPress functions it calls; the child defines a
   stand-in for each. A stand-in sends the call to core, which runs it only if the manifest
   grants it and refuses and logs it otherwise.
4. `add_action` / `add_filter` keep the callback in the child under a number; core registers
   a stub that calls back in when the hook fires. Output the plugin prints is sent with each
   message and printed by core in the right place.
5. Calls nest both ways (plugin → core → plugin), like a normal call stack.
6. The request ends, the child exits. A call that takes over 5 s is cut off. A wasm/PHP trap
   kills only that child; the worker parent keeps serving.

A manifest:

```json
{ "plugin": "hello.php",
  "hooks": ["admin_notices", "admin_head"],
  "functions": ["wptexturize", "get_user_locale", "__", "is_rtl"] }
```

Settings in `wp-config.php`: `SECURECORE_DISABLED` (load plugins normally),
`SECURECORE_ENFORCE` (`false` = allow and log what the manifest does not grant),
`SECURECORE_SOCKET` (default `/run/securecore/worker.sock`). Every allow/deny lands in
`wp-content/securecore-audit.log`.

## Files

| file | what |
|---|---|
| `sandbox/worker.php` | the worker: boots setup.php, listens on the socket, forks per request |
| `sandbox/setup.php` | the protocol and the per-request work: stand-ins, callbacks, the call loop |
| `plugin/securecore.php` | the plugin's main file (header, version) |
| `plugin/securecore-core.php` | core side: hides sandboxed plugins, connects per request, manifest checks, audit log, Settings → SecureCore |
| `plugin/securecore-loader.php` | the mu-plugin loader (installed to `wp-content/mu-plugins/`) |
| `bin/securecore-worker` | the launcher: starts the worker with its PHP isolation forced on |
| `sandbox/scan.php`, `sandbox/gen-manifest.php` | the `token_get_all` scan behind generated manifests |
| `install.sh` | the one-line installer (POSIX sh) |
| `templates/` | the systemd unit and Docker Compose service shipped in the zip |
| `scripts/` | `version.sh`, `package.sh` (the zip), `release-layout.sh` (the bucket layout and `release.json`, the manifest), `ext-cells.txt`/`ext-cells.sh` (the extension's matrix), `ext-build.sh` (one cell), `r2.sh` (one object over R2's S3 API) |
| `ext/install.sh` | the extension installer, published as `install-ext.sh` (ext/README.md, Install) |
| `test/release-check.sh` | the release check for one extension cell: WordPress on that PHP, installed by `install-ext.sh` |
| `.github/workflows/` | tag-canary (nightly), release (16 extension cells built and release-checked, then canary → R2), promote (same bytes → stable) |
| `probe/securecore-probe.php` | test plugin that behaves like a backdoored update |
| `test/plugin/securecore-state.php` | test plugin for request isolation (a static that would leak without the fork) |
| `manifests/` | one manifest per sandboxed plugin |
| `docker/` | nginx + php-fpm + MariaDB + the worker container |
| `test/site.sh` | checks the running stack over HTTP |
| `test/isolation.sh` | proves two requests don't see each other's state, and that it leaks without the fork |

(`sandbox/securecore.ts` is the earlier wasm one-shot binary; the worker path does not use
it.)

## Install it on a site

```
mkdir mysite && cd mysite && curl -fsSL https://securecore.addis.gg/install.sh | sh     # a new site, from nothing
cd /path/to/wordpress && curl -fsSL https://securecore.addis.gg/install.sh | sh        # an existing site
```

See INSTALL.md. install.sh finds or downloads PHP; `setup/site.php` (in the release) sets up
WordPress, the database and the site. Releases: `scripts/package.sh` builds the zip (only
what a site needs); `scripts/mirror-php.sh` mirrors the static-php-cli builds listed in
`scripts/php-builds.txt` and writes `php.json`;
`scripts/release-layout.sh` lays out a release as the `securecore-releases` bucket holds it;
`.github/workflows/` tags a canary nightly when main changed, builds and release-checks the
extension matrix, publishes it, and promotes a canary to stable with the same bytes (APS 9,
APS 12; ext/README.md, Release).

## Run it (dev stack)

Needs Docker.

```sh
docker/setup.sh        # build the zip and images, start the stack + worker, install WordPress
test/site.sh           # SecureCore on: plugins sandboxed, the probe's attacks all fail
test/site.sh baseline  # SecureCore off: same notices from normal plugins
test/isolation.sh      # request isolation, with and without the fork
test/install.sh        # install.sh on this site via --from: install, upgrade, tamper, uninstall, then test/site.sh
test/install-fresh.sh  # install.sh on an unzipped WordPress (debian, apt php-cli + MariaDB, php -S)
test/full-setup.sh     # install.sh from an empty folder: no PHP, interactive, system PHP without pcntl
test/woo.sh            # a WooCommerce store walk (needs WooCommerce set up; see docs/woocommerce-survey.md)
test/compat-all.sh     # the plugin compatibility sweep (test/compat.sh <slug> for one); docs/compatibility.md
```

Benchmarks (on the running stack):

```sh
bench/run.sh breakdown   # per-request split: fork, include (opcache hit), first call
bench/run.sh load        # latency, throughput, memory PSS/RSS (oha inside the Docker network)
bun bench/summary.ts     # the split table; load prints its own (.tmp/bench/load.md)
```

Open http://127.0.0.1:8088/wp-admin/ (admin / securecore-demo). Stop with
`docker compose -f docker/compose.yml down -v`.

## License

SecureCore's own code is [MIT](LICENSE). The plugin's release zip also ships
the libraries in `plugin/vendor/`, which keep their own licences:
phpMyAdmin's sql-parser is GPL-2.0-or-later and symfony/polyfill-mbstring is
MIT. So the zip as a whole is distributed under the GPL-2.0-or-later, like
the WordPress plugins it sits beside.
