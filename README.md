# SecureCore

Runs each WordPress plugin in its own p8 wasm sandbox. WordPress core stays on the server's
own PHP. Every call between a sandboxed plugin and WordPress crosses SecureCore and is
checked against the plugin's manifest.

```
browser → nginx → php-fpm (stock PHP) → WordPress core
                                          │  SecureCore.php (mu-plugin)
                                          │    unix socket, one line per message
                                          ▼
                              tab: securecore serve, one per plugin (php2.wasm = p8)
                                sees only: the plugin's folder, /tmp
                                no wp-config.php, no environment, no network
```

## How a request works

1. `SecureCore.php` loads as a mu-plugin. Plugins with a manifest in
   `wp-content/securecore/manifests/` are hidden from core's plugin loader.
2. For each of them it connects to that plugin's **tab**: a `securecore serve` process
   that stays up, one per plugin, on a unix socket in the php container's temp dir.
   SecureCore.php starts it (`setsid -f`) if it is not running. A tab compiles the wasm
   once and keeps a few worker slots, each holding a fresh instance that is already
   prepared; a request takes one, and the slot prepares a new one. No instance ever serves
   two requests.
3. Preparing (before any request): `sandbox/setup.php` scans the plugin's files with
   `token_get_all` and defines a stand-in for each function the plugin calls but neither
   defines nor gets from PHP. A stand-in sends the call to core and waits; core runs it
   only if the manifest grants it, and refuses and logs it otherwise. Per request it only
   sets the request's `$_GET`/`$_POST`/`$_SERVER` and includes the plugin.
4. `add_action` / `add_filter` keep the callback in the sandbox under a number; core
   registers a stub that calls back in when the hook fires. Output the plugin prints is
   sent with each message and printed by core in the right place.
5. Calls nest both ways (plugin → core → plugin), like a normal call stack.
6. At `shutdown` the connections close and those instances exit. A call that takes more
   than 5 s is cut off; an instance still running 2 s after its request ended, or a
   crashed slot, is replaced. Only that plugin's tab is affected.

A manifest (hand-written for now; generating it with `token_get_all` comes next):

```json
{ "plugin": "hello.php",
  "functions": ["wptexturize", "get_user_locale", "__", "is_rtl"],
  "hooks": ["admin_notices", "admin_head"] }
```

Engines (`SECURECORE_ENGINE` in `wp-config.php`): `p8` (default, php2.wasm), `php-wasm`
(stock PHP 8.3 compiled to wasm by WordPress Playground, `@php-wasm/node-8-3`, GPL-2.0-or-later),
and `native` (the php CLI as a child process: a benchmark lower bound, **not a sandbox**).
Both wasm engines get the same isolation: only the plugin's folder, no env, no network
(php-wasm's sockets are refused and logged as `net.deny`).

Settings in `wp-config.php`: `SECURECORE_DISABLED` (load plugins normally),
`SECURECORE_ENFORCE` (`false` = allow and log what the manifest does not grant),
`SECURECORE_BINARY` (default `/usr/local/bin/securecore`). Every allow/deny lands in
`wp-content/securecore-audit.log`.

## Files

| file | what |
|---|---|
| `plugin/SecureCore.php` | the mu-plugin: plugin loading, sandboxes, the call loop, manifest checks, audit log |
| `sandbox/setup.php` | runs inside the sandbox before the plugin: stand-ins, callback table, the call loop |
| `sandbox/securecore.ts` | the binary: `serve` (the tab: socket, slots) or one instance on stdin/stdout |
| `sandbox/tab.ts` | one tab slot (a worker thread): fresh instance per request, fed through a shared ring |
| `sandbox/engine.ts` | what every engine shares (visible file tree, path audit, prepare message); the p8 and php-wasm engines |
| `probe/securecore-probe.php` | test plugin that behaves like a backdoored update |
| `manifests/` | manifests for Hello Dolly and the probe |
| `docker/` | nginx + php-fpm + MariaDB, the real-server test stack |
| `test/site.sh` | checks the running stack over HTTP |

## Run it

Needs bun and Docker.

```sh
bun install
bun run wasm          # fetch php2.wasm (24 MB, sha256-pinned) into sandbox/
bun run build         # dist/securecore-linux-x64 (bun single-file executable)
docker/setup.sh       # build images, start the stack, install WordPress, activate plugins
test/site.sh          # SecureCore on: Hello Dolly sandboxed, the probe's attacks fail
test/site.sh baseline # SecureCore off: same notice from a normal plugin
```

Benchmarks (on the running stack):

```sh
bench/run.sh breakdown p8,php-wasm,native   # one tab per engine: per-request cost, call costs, tab RSS
bench/run.sh load p8,php-wasm,native        # latency, throughput, peak memory (oha inside the Docker network)
bun bench/summary.ts p8,php-wasm,native     # breakdown table; load prints its own (.tmp/bench/load.md)
```

Open http://127.0.0.1:8088/wp-admin/ (admin / securecore-demo). Stop with
`docker compose -f docker/compose.yml down -v`.
