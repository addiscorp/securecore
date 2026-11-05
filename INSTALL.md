# Installing SecureCore

SecureCore runs your WordPress plugins in a separate sandbox process (the **worker**).
WordPress core keeps running on your web server's PHP; each sandboxed plugin runs in the
worker, and every call between a plugin and WordPress is checked against the plugin's
manifest. This guide adds SecureCore to an existing WordPress site.

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

## 1. Copy the files

SecureCore is one folder plus one mu-plugin. From a release (or this repo), copy them into
your site's `wp-content`:

```
wp-content/
  mu-plugins/SecureCore.php          # loads automatically; no activation needed
  securecore/
    sandbox/   worker.php setup.php scan.php gen-manifest.php
    bin/       securecore-worker       # the launcher (chmod +x)
    manifests/                         # created as you switch plugins on
```

So:

```
mkdir -p wp-content/mu-plugins wp-content/securecore
cp -r securecore/sandbox securecore/bin wp-content/securecore/
cp securecore/mu-plugins/SecureCore.php wp-content/mu-plugins/
mkdir -p wp-content/securecore/manifests
chmod +x wp-content/securecore/bin/securecore-worker
```

(Match the files' owner to your web server user, e.g. `chown -R www-data:www-data
wp-content/securecore wp-content/mu-plugins/SecureCore.php`.)

## 2. Start the worker (plain)

```
wp-content/securecore/bin/securecore-worker \
  /run/securecore/worker.sock \
  "$PWD/wp-content/plugins" \
  "$PWD/wp-content/securecore/manifests"
```

The first argument is the socket SecureCore will connect to; the socket's directory must be
writable by the worker's user and readable by the web server's user. Pick a path both can
reach (e.g. make `/run/securecore` and `chown` it, or use a path under `wp-content`).

The launcher forces the worker's isolation through PHP settings, so the site's `php.ini`
cannot loosen them:

- `open_basedir` = the worker code, the plugins folder, the manifests and the socket dir
  only — so a plugin cannot read `wp-config.php` or anything else on disk;
- `disable_functions` = process execution (`exec`, `shell_exec`, `system`, `proc_*`, …) and
  every outbound-network call (`fsockopen`, `stream_socket_client`, `socket_*`, `curl_*`);
- `allow_url_fopen` / `allow_url_include` off;
- a clean environment (`env -i`).

Leave it running (it is a long-lived process). To run it in the background:
`setsid -f wp-content/securecore/bin/securecore-worker … >> wp-content/securecore-worker.log 2>&1`.

If the web server's PHP may call `proc_open`, you can instead press **Start worker** on the
SecureCore settings screen (step 4), which runs this same launcher for you.

## 3. Tell SecureCore the socket (if not the default)

The default socket path is `/run/securecore/worker.sock`. To use another, add to
`wp-config.php`:

```php
define( 'SECURECORE_SOCKET', '/path/you/chose/worker.sock' );
```

## 4. Choose which plugins to sandbox

In wp-admin, go to **Settings → SecureCore**. It shows whether the worker is running and
lists your installed plugins with a **Run in sandbox** switch. Turn a plugin on and Save:
SecureCore reads that plugin's code and writes its manifest (the WordPress functions and
hooks it uses) under `wp-content/securecore/manifests`. That stored manifest is what the
worker enforces. Turning a plugin off deletes its manifest.

If the worker is not running, the screen says so, and any plugin you have sandboxed does not
load until you start it.

## systemd (stronger, for a bare server)

Run the same launcher as a service under its own user, with the unit adding a private
network and read-only paths. Example `/etc/systemd/system/securecore.service`:

```ini
[Unit]
Description=SecureCore worker
After=network.target

[Service]
User=securecore
RuntimeDirectory=securecore
ExecStart=/var/www/html/wp-content/securecore/bin/securecore-worker \
  /run/securecore/worker.sock \
  /var/www/html/wp-content/plugins \
  /var/www/html/wp-content/securecore/manifests
PrivateNetwork=yes
ProtectSystem=strict
ReadOnlyPaths=/var/www/html
ReadWritePaths=/run/securecore
NoNewPrivileges=yes
Restart=always

[Install]
WantedBy=multi-user.target
```

`PrivateNetwork=yes` gives the worker no network at all; `ReadOnlyPaths` and `ProtectSystem`
keep it off the rest of the disk. The web server's user must be able to read
`/run/securecore` to reach the socket (add it to the `securecore` group, or widen
`RuntimeDirectoryMode`). `systemctl enable --now securecore`.

## Docker (for a container host)

Run the same launcher in a container with `network_mode: none`, the plugins mounted
read-only and a shared socket volume. `docker/compose.yml` in this repo is a working
example (its `worker` service); copy that service into your stack, pointing its volumes at
your WordPress files, and mount the same socket volume into your PHP-FPM container at
`/run/securecore`.

## Removing SecureCore

Delete `wp-content/mu-plugins/SecureCore.php` (plugins load normally again), stop the
worker, and delete `wp-content/securecore`.
