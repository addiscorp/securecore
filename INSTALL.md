# Installing SecureCore

SecureCore runs your WordPress plugins in a separate sandbox process (the **worker**).
WordPress core keeps running on your web server's PHP; each sandboxed plugin runs in the
worker, and every call between a plugin and WordPress is checked against the plugin's
manifest. This guide sets up a new site with SecureCore from an empty folder, or adds it to
an existing WordPress site.

## Quick start: a new site from an empty folder

```
mkdir mysite && cd mysite && curl -fsSL https://securecore.addis.gg/install.sh | sh
```

No PHP, WordPress or database needed beforehand. The installer:

1. **PHP:** uses your `php` if it has what's needed. That's pcntl + opcache for the worker, and pdo_sqlite or mysqli for the site. Otherwise it offers to download PHP into `.securecore/php/` inside the project: never system-wide, never sudo.
   - The builds are static-php-cli's prebuilt binaries, mirrored in SecureCore's release bucket and checked by sha256. `php.json` there records each file's upstream URL and its sha256 when mirrored.
   - The `bulk` build runs the worker. The site runs on `common` for SQLite or `bulk` for MySQL.
2. **WordPress:** a version from wordpress.org's list, newest first, checked against wordpress.org's published sha1 (wordpress.org publishes sha1 and md5, not sha256).
3. **Database:** SQLite by default (the SQLite Database Integration plugin and its `db.php` drop-in, no server), or MySQL/MariaDB. It writes `wp-config.php` and installs the site: title and admin user asked, password asked or generated and printed.
4. **SecureCore**, as below.
5. **The worker and how to run it:** offers to start the sandbox worker in the background, then prints the command that starts the site (PHP's built-in web server, on the port of `--url`) and where to go in wp-admin; or writes a Docker Compose file for the same setup.

The output is one plain line per step, ending with what to run next:

```
SecureCore installer

✓ PHP 8.4          none found on this computer, downloaded into this folder (verified)
✓ WordPress 7.1.4  downloaded (verified)
✓ Database         SQLite, no database server needed
✓ Site             http://localhost:8080, admin user "admin"
✓ SecureCore       installed (0.1.0) and switched on
✓ Sandbox worker   running

Next, start your site (leave it running):
  .securecore/bin/php-web -S localhost:8080
Then open http://localhost:8080/wp-admin → Settings → SecureCore to choose plugins to sandbox.
```

`--verbose` adds the detail: download URLs, sha256/sha1 values, the PHP builds and file paths. When the output isn't a terminal (a log, CI), `✓` is written as `ok`.

It asks on the terminal, which also works under `curl | sh`. Every question has a flag:

```
curl -fsSL https://securecore.addis.gg/install.sh | sh -s -- --yes \
  --php download --wordpress latest --db sqlite --title "My site" --admin-user admin --admin-email me@example.com
```

`--db mysql://user:pass@host[:port]/name` uses MySQL. `--php system` never downloads PHP. `--compose` writes `compose.yml` instead of printing commands. `--yes` takes every default, including downloading PHP if needed, and starts the worker. `--url http://localhost:8097` sets the site's address, and the printed command uses its port. Re-running it on a finished site only upgrades SecureCore.

There are three ways to run the worker. They use the same code; each adds a layer of
isolation:

1. **Plain** — `php worker.php`, anywhere PHP CLI runs. Isolation comes from the worker's own
   PHP settings, forced on the command line. Start here.
2. **systemd** — the plain worker as a service under its own user, with the network and the
   filesystem locked down by the unit. For a bare Linux server.
3. **Docker** — the plain worker in a container with no network. For a container host.

## Requirements

- WordPress on PHP 8.1+ (your web server, unchanged).
- A **PHP CLI** with the `pcntl` and `opcache` extensions, for the worker. Check:
  ```
  php -v
  php -m | grep -E 'pcntl|Zend OPcache'
  ```
  On Debian/Ubuntu: `apt-get install php-cli php-opcache` (pcntl is built into php-cli).

## 1. Install the files

For an existing site: from your WordPress root, as the user that owns the site's files (no sudo):

```
cd /path/to/wordpress && curl -fsSL https://securecore.addis.gg/install.sh | sh
```

It checks for `php` with `pcntl` and opcache and says exactly what's missing. If they're missing, it offers to download a PHP that has them into `.securecore/php/` for the worker; your site keeps its own PHP. It then downloads the newest release, checks its sha256, puts the plugin in `wp-content/plugins/securecore/`
and the loader in `wp-content/mu-plugins/securecore-loader.php`, activates the plugin with
WP-CLI if `wp` is available (otherwise activate **SecureCore** in wp-admin → Plugins), and
prints the next step. Options: `--path <dir>` (WordPress root), `--canary` (newest canary),
`--uninstall`. Re-running it upgrades in place; your manifests are kept.

Without the script: unzip `securecore.zip` from a release into `wp-content/plugins/`, copy
`wp-content/plugins/securecore/mu-plugin/securecore-loader.php` to `wp-content/mu-plugins/`,
and activate SecureCore. Either way you get:

```
wp-content/
  mu-plugins/securecore-loader.php   # loads SecureCore early while the plugin is active
  plugins/securecore/                # the plugin: replaced as a whole on upgrade
    securecore.php  securecore-core.php  sql-policy.php
    sandbox/   worker.php setup.php scan.php gen-manifest.php
    bin/       securecore-worker     # the launcher
    templates/ securecore.service compose.yml
  securecore/manifests/              # your manifests: kept across upgrades
```

Deactivating the SecureCore plugin turns it off; plugins then load normally.

## 2. Start the worker (plain)

install.sh offers to start it for you (with `--yes` it just does). Otherwise, from the
WordPress root, as the user that owns the site's files:

```
wp-content/plugins/securecore/bin/securecore-worker
```

With no arguments it works out everything from where it is installed: the socket
`wp-content/securecore/worker.sock` (SecureCore's default, so nothing needs configuring),
the plugins folder and the manifests. Pass `<socket> <plugins-dir> <manifests-dir>` to
choose them yourself.

Unix socket paths are short (103 usable characters on macOS, 107 on Linux). If your site's
path makes the default too long, the launcher, install.sh and the settings screen say so;
use a shorter path, e.g. `securecore-worker /tmp/securecore.sock` and in `wp-config.php`
`define( 'SECURECORE_SOCKET', '/tmp/securecore.sock' );`.

The launcher forces the worker's isolation through PHP settings, so the site's `php.ini`
cannot loosen them:

- `open_basedir` = the worker code, the plugins folder, the manifests and the socket dir
  only — so a plugin cannot read `wp-config.php` or anything else on disk;
- `disable_functions` = process execution (`exec`, `shell_exec`, `system`, `proc_*`, …) and
  every outbound-network call (`fsockopen`, `stream_socket_client`, `socket_*`, `curl_*`);
- `allow_url_fopen` / `allow_url_include` off;
- a clean environment (`env -i`).

Leave it running (it is a long-lived process). To run it in the background:
`nohup wp-content/plugins/securecore/bin/securecore-worker >> wp-content/securecore/worker.log 2>&1 &`.

If the web server's PHP may call `proc_open` (including `php -S`), you can instead press
**Start worker** on the SecureCore settings screen, which runs this same launcher for you.

## 3. Choose which plugins to sandbox

In wp-admin, go to **Settings → SecureCore**. It shows whether the worker is running and
lists your installed plugins with a **Run in sandbox** switch. Turn a plugin on and Save:
SecureCore reads that plugin's code and writes its manifest (the WordPress functions and
hooks it uses) under `wp-content/securecore/manifests`. That stored manifest is what the
worker enforces. Turning a plugin off deletes its manifest. Either takes effect on the next
request: the worker reads a plugin's manifest each time it serves it, so it never needs a
restart for this. (After upgrading SecureCore itself, restart the worker to load the new
code.)

If the worker is not running, the screen says so, and any plugin you have sandboxed does not
load until you start it.

## systemd (stronger, for a bare server)

Run the same launcher as a service under its own user, with the unit adding a private
network and read-only paths. The unit is in the plugin:
`wp-content/plugins/securecore/templates/securecore.service`. Copy it to
`/etc/systemd/system/`, set `WP=` to your WordPress root and the users, then
`systemctl daemon-reload && systemctl enable --now securecore`.

`PrivateNetwork=yes` gives the worker no network at all; `ReadOnlyPaths` and `ProtectSystem`
keep it off the rest of the disk. The web server's user must be able to reach
`/run/securecore` to connect (the unit's `Group=www-data` and `RuntimeDirectoryMode=0750`
do that for a `www-data` web server). Since the site is read-only to the worker, its socket
is `/run/securecore/worker.sock`; add `define( 'SECURECORE_SOCKET',
'/run/securecore/worker.sock' );` to `wp-config.php`.

## Docker (for a container host)

Run the same launcher in a container with `network_mode: none`, the site mounted read-only
and a shared socket volume. The service is in the plugin:
`wp-content/plugins/securecore/templates/compose.yml`. Add it to your stack, point its
volume at your WordPress files, and mount the same socket volume into your PHP-FPM
container at `/run/securecore`. As with systemd, add `define( 'SECURECORE_SOCKET',
'/run/securecore/worker.sock' );` to `wp-config.php`.

## Removing SecureCore

```
cd /path/to/wordpress && curl -fsSL https://securecore.addis.gg/install.sh | sh -s -- --uninstall
```

That deactivates and removes the plugin and the loader (plugins load normally again) and
keeps your manifests in `wp-content/securecore` (delete that folder if you don't need them).
Stop the worker if it is running.
