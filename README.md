# SecureCore

Runs WordPress plugins in a separate sandbox process instead of in the web server. WordPress
core stays on the server's own PHP; each sandboxed plugin runs in the SecureCore worker, and
every call between a plugin and WordPress crosses SecureCore and is checked against the
plugin's manifest.

```
browser → nginx → php-fpm (WordPress core)
                    │  SecureCore.php (mu-plugin): one unix-socket connection per request
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

1. `SecureCore.php` loads as a mu-plugin. Plugins with a manifest in
   `wp-content/securecore/manifests/` are hidden from core's plugin loader.
2. For each, it connects to the worker's unix socket. One connection = one `pcntl_fork()` in
   the worker = one child for this request. If the worker is not running, those plugins do
   not load (core does not start it; the worker container does).
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
| `plugin/SecureCore.php` | the mu-plugin: hides sandboxed plugins, connects per request, manifest checks, audit log |
| `probe/securecore-probe.php` | test plugin that behaves like a backdoored update |
| `test/plugin/securecore-state.php` | test plugin for request isolation (a static that would leak without the fork) |
| `manifests/` | one manifest per sandboxed plugin |
| `docker/` | nginx + php-fpm + MariaDB + the worker container |
| `test/site.sh` | checks the running stack over HTTP |
| `test/isolation.sh` | proves two requests don't see each other's state, and that it leaks without the fork |

(`sandbox/securecore.ts` is the earlier wasm one-shot binary; the worker path does not use
it.)

## Run it

Needs Docker.

```sh
docker/setup.sh        # build images, start the stack + worker, install WordPress
test/site.sh           # SecureCore on: plugins sandboxed, the probe's attacks all fail
test/site.sh baseline  # SecureCore off: same notices from normal plugins
test/isolation.sh      # request isolation, with and without the fork
```

Benchmarks (on the running stack):

```sh
bench/run.sh breakdown   # per-request split: fork, include (opcache hit), first call
bench/run.sh load        # latency, throughput, memory PSS/RSS (oha inside the Docker network)
bun bench/summary.ts     # the split table; load prints its own (.tmp/bench/load.md)
```

Open http://127.0.0.1:8088/wp-admin/ (admin / securecore-demo). Stop with
`docker compose -f docker/compose.yml down -v`.
