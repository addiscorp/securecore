# SecureCore

Runs each WordPress plugin in its own p8 wasm sandbox. WordPress core stays on the server's
own PHP. Every call between a sandboxed plugin and WordPress crosses SecureCore and is
checked against the plugin's manifest.

```
browser → nginx → php-fpm (stock PHP) → WordPress core
                                          │  SecureCore.php (mu-plugin)
                                          │    stdin/stdout, one line per message
                                          ▼
                              securecore binary (php2.wasm = p8)
                                sees only: the plugin's folder, /tmp
                                no wp-config.php, no environment, no network
```

## How a request works

1. `SecureCore.php` loads as a mu-plugin. Plugins with a manifest in
   `wp-content/securecore/manifests/` are hidden from core's plugin loader.
2. For each of them it starts the `securecore` binary (`proc_open`, one per plugin per
   request in this first version).
3. In the sandbox, `sandbox/setup.php` defines every WordPress function as a stand-in that
   sends the call to core and waits. Core runs it only if the manifest grants it.
4. `add_action` / `add_filter` keep the callback in the sandbox under a number; core
   registers a stub that calls back in when the hook fires. Output the plugin prints is
   sent with each message and printed by core in the right place.
5. Calls nest both ways (plugin → core → plugin), like a normal call stack.
6. At `shutdown` the sandboxes exit.

A manifest (hand-written for now; generating it with `token_get_all` comes next):

```json
{ "plugin": "hello.php",
  "functions": ["wptexturize", "get_user_locale", "__", "is_rtl"],
  "hooks": ["admin_notices", "admin_head"] }
```

Settings in `wp-config.php`: `SECURECORE_DISABLED` (load plugins normally),
`SECURECORE_ENFORCE` (`false` = allow and log what the manifest does not grant),
`SECURECORE_BINARY` (default `/usr/local/bin/securecore`). Every allow/deny lands in
`wp-content/securecore-audit.log`.

## Files

| file | what |
|---|---|
| `plugin/SecureCore.php` | the mu-plugin: plugin loading, sandboxes, the call loop, manifest checks, audit log |
| `sandbox/setup.php` | runs inside the sandbox before the plugin: stand-ins, callback table, the call loop |
| `sandbox/securecore.ts` | the binary: embeds `php2.wasm` and `setup.php`, maps stdin/stdout, mounts only the plugin |
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
bun run build:bench   # dist/securecore-tabs-linux-x64 (bench/tabs.ts; the image includes it)
docker/setup.sh       # build images, start the stack, install WordPress, activate plugins
test/site.sh          # SecureCore on: Hello Dolly sandboxed, the probe's attacks fail
test/site.sh baseline # SecureCore off: same notice from a normal plugin
```

Benchmarks (on the running stack; `bun run build:bench` first, then `docker/setup.sh` again):

```sh
bench/run.sh breakdown   # per-step startup, call costs, RSS per sandbox
bench/run.sh load        # latency, throughput, peak memory (oha inside the Docker network)
bench/run.sh tabs        # one process: instantiate + boot repeatedly, memory restore
bun bench/summary.ts     # tables for breakdown + tabs; load prints its own (.tmp/bench/load.md)
```

Open http://127.0.0.1:8088/wp-admin/ (admin / securecore-demo). Stop with
`docker compose -f docker/compose.yml down -v`.
