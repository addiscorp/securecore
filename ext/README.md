# SecureCore PHP extension

SecureCore as one PHP extension written in Rust ([ext-php-rs](https://crates.io/crates/ext-php-rs)),
configured from one file, `securecore.json` (addiscorp/securecore#53). Phases so far: **E1** loads,
validates and reloads the config and reports it; **E2a** works out which component is running;
**E2b** enforces layer 2's file and process rules. Still to come: the vault (E3), the database
and hostname policy (E4–E5), the layer 1 launcher (E6) and layer 3 (E7).

| crate | what |
|---|---|
| `config/` (`securecore-config`) | the config types (serde), the loader, the reloader and the JSON Schema. Plain Rust, no PHP: the `securecore-fpm` launcher (E6) reads the file with the same code. |
| `attribution/` (`securecore-attribution`) | E2a: path → component (plugin, mu-plugin, theme, core), the two "who is running" rules, the watched file functions, `securecore-attribution-report`; and E2b: the file/process [`policy`](attribution/src/policy.rs). Plain Rust, no PHP. |
| `php/` (`securecore-php`) | the extension, built as `securecore.so` |

## Build

The extension builds against PHP's headers, in Docker (PHP 8.3 NTS, Debian bookworm). From the
repo root:

```sh
docker build -f docker/ext.Dockerfile --target so -o .tmp/ext .   # → .tmp/ext/securecore.so
docker build -f docker/ext.Dockerfile --target check .            # clippy -D warnings + cargo test, whole workspace
```

The config crate alone needs no PHP: `cargo test` in `ext/` runs its tests (the workspace's
default member).

## Install

Copy `securecore.so` into PHP's extension folder and add one ini file to `conf.d`
(`docker/securecore.ini`):

```ini
extension=securecore.so
securecore.config=/var/www/html/securecore.json
```

**The app root is the folder containing `securecore.json`** (as with `composer.json`): every
relative path in the file is relative to it, and absolute paths are used as they are. So the
file usually sits at the web root, and **the web server must never serve it**: the docker nginx
config answers 404 for any URI containing `securecore.json` (copies such as `.bak` included);
an installer that writes the file must do the same for its server.

`securecore.config` is `PHP_INI_SYSTEM`: set it in php.ini or `conf.d`, not in a php-fpm pool
(`php_admin_value`), because the file is loaded once when PHP starts, before pools exist.

**Fail closed.** With the extension loaded, a config that is not set, missing, unreadable or
invalid stops PHP from starting: module startup fails, PHP logs

```
PHP Warning:  PHP Startup: securecore: /var/www/html/securecore.json: invalid: unknown variant `block`, expected one of `enforce`, `log`, `off` at line 1 column 85; refusing to start in Unknown on line 0
PHP Fatal error:  Unable to start securecore module in Unknown on line 0
```

to php-fpm's error log (stderr under Docker or systemd) and exits; `php-fpm -t` and the PHP CLI
refuse the same way. There is no fallback to running unprotected. A config with all three
layers disabled (`examples/off.json`) is valid and means SecureCore is off.

## Config

`securecore.json` has three objects, `layer1`, `layer2` and `layer3`, and an optional
`"$schema"`. Every object rejects unknown keys. The reference is
[`securecore.schema.json`](securecore.schema.json), generated from the Rust types (the doc
comments on them are its descriptions), so the schema and the parser can't disagree; the
`schema_in_sync` test fails if the committed file is stale. Regenerate it in `ext/` with:

```sh
cargo run -p securecore-config --bin securecore-schema > securecore.schema.json
```

Examples: [`examples/wordpress.json`](examples/wordpress.json) (every field, the #53 example) and
[`examples/off.json`](examples/off.json) (the minimum: three `{"enabled": false}`).

Beyond the schema's structure, one rule is checked in code and expressed in the schema as an
`if`/`then`: `layer2.app` is required when layer 2 is enabled. `layer2.mode` defaults to
`enforce`. The parser accepts exactly what the schema accepts: serde would also read any object
from a JSON array (its fields by position), and that form is rejected
(`layer1 is an array; it must be an object`).

Each entry in `layer2.default` and `layer2.components.<slug>` sets a component's rules; a field
left out of an entry inherits from `default`. For E2b those fields are `files` — an object with
`read` (extra readable paths outside the root) and `write` (extra writable paths, on top of
uploads and cache) — and `exec` (a bool: may the component run programs). See
[Enforcement (E2b)](#enforcement-e2b) for what each means. (`hosts`, `tables`, `options` and
`grants` are for later phases.)

## Reload

Layers 2 and 3 follow the file without a php-fpm restart. At request start (RINIT) each php-fpm
worker `stat`s the file at most once per second (`RELOAD_INTERVAL`), and reads, hashes and
parses it only when the stat (inode, size, mtime, ctime) changed. A new valid file goes live in
that worker and is logged (`securecore: reloaded <path> (sha256 …)`). So an edit is live
everywhere about a second after it is saved; the cost on a request with no change is one clock
read, and one `stat` a second per worker.

- An edit that does not load (invalid, unreadable, deleted) keeps the **last valid config** live,
  never off, and is logged once per distinct problem:
  `securecore: <path>: invalid: …; keeping the last valid config`. A restart then refuses to
  start until the file is fixed.
- `layer1` is read by the launcher at start. If it changes, the extension logs
  `layer1 changed; it applies only after a php-fpm restart` and reports `restart_needed`.

## `securecore_status(): array`

What this worker is enforcing:

```php
[
  'version' => '0.1.0',
  'config' => '/var/www/html/securecore.json',
  'sha256' => '6e5d42ec…',          // of the file's bytes
  'off' => false,                   // all three layers disabled
  'layers' => ['layer1' => true, 'layer2' => true, 'layer3' => true],
  'layer2_mode' => 'enforce',       // enforce | log | off
  'layer2_app' => 'wordpress',      // or null
  'reloads' => 0,                   // reloads in this worker since it forked
  'restart_needed' => false,        // layer1 differs from the one php-fpm started with
  'reload_error' => null,           // the problem with the file on disk, while it can't load
  'root' => '/var/www/html',        // the folder containing securecore.json
  'caller' => 'core',               // who called, by the attribution rule (below)
  'attribution_rule' => 'component',
  'attribution_log' => 'off',
]
```

`phpinfo()` shows the config path and sha256 too.

Since E2b, `securecore_status()` is **callable from core only**. A component that calls it is
refused in `enforce` mode (a thrown exception) and recorded but allowed in `log` mode, like any
other layer-2 operation.

## Attribution (E2a)

Layer 2 restricts each **component**. For `layer2.app = "wordpress"` (`attribution/`):

- each folder in the plugins directory, or `.php` file directly in it, is `plugin:<slug>`;
- each entry in mu-plugins is `mu-plugin:<name>`, except SecureCore's own loader
  (`securecore-loader.php`), which is core;
- each folder in the themes directory is `theme:<slug>`;
- everything else under the root (and in `WP_CONTENT_DIR`) is `core`; anything else is
  `outside`. `index.php` in those directories is core.

`WP_CONTENT_DIR`, `WP_PLUGIN_DIR` and `WPMU_PLUGIN_DIR` move the directories when defined
(read when asked, so they count once wp-config.php has set them). Symlinks are resolved: a plugin
symlinked in from elsewhere is still itself when PHP reports its files by their real path. The
map re-reads the component directories when their mtime changes (checked at most once a
second).

**Who is running** is computed only when asked, from the PHP stack (`execute_data`), by one of
two rules:

| rule | the component responsible is | a plugin calling a core API that opens a file |
|---|---|---|
| `frame` (a) | the innermost user-code frame's file | core |
| `component` (b) | the innermost frame on the stack that belongs to a component; core only when none is | the plugin |

Two debug settings, both PHP_INI_SYSTEM, choose and expose it:

```ini
securecore.debug_attribution_rule = component   ; frame | component (the default)
securecore.debug_attribution_log  = off         ; off (default) | frame | component | both
```

With logging on and layer 2 in `log` or `enforce` mode, every file open writes one line per
logged rule to PHP's error log:

```
securecore: attribution component plugin:contact-form-7 file_get_contents /var/www/html/wp-content/uploads/x.txt
securecore: attribution frame core require_once /var/www/html/wp-includes/version.php
```

"Opens" are every include/require that loads a file (through a `zend_compile_file` wrapper, so
opcache hits count), and the PHP functions that open a path through the plain-files wrapper
(`attribution/src/watch.rs`: fopen with its mode, file_get_contents, file_put_contents, file,
readfile, opendir/scandir/glob, unlink/rename/copy/mkdir/… and SplFileObject), through a Zend
observer. Not seen: opens made inside other extensions' C code (GD, Zip, …) and metadata calls
(`file_exists`, `stat`). With logging off neither hook exists, so the normal request path pays
nothing. This is observation only: nothing is blocked.

`research/attribution/measure.sh` runs the measurement on the docker stack and
`securecore-attribution-report` turns the log into per-component tables.

## Enforcement (E2b)

Layer 2 enforces a file and process policy on each **component** (plugin, mu-plugin or theme),
by the `component` attribution rule — the one #55's measurement recommended, which charges the
caller. **Core is never restricted.** The rules (in [`attribution/src/policy.rs`](attribution/src/policy.rs),
plain Rust, unit-tested):

- **read:** anywhere under the app root, except the two protected files — the vault's `from`
  file (e.g. `wp-config.php`) and `securecore.json`. Outside the root, only what the component's
  `files.read` lists. (Reads under the root are open because shared libraries and core APIs
  routinely read another component's files on its behalf; the secrets are what stay closed.)
- **write** (create, modify, delete, rename, mkdir): the uploads and cache folders, plus what
  `files.write` lists. Never a protected file — not even its own folder.
- **exec** (exec, shell_exec, system, passthru, popen, proc_open, pcntl_exec, and mail when it
  shells out): refused unless the component's `exec` is `true`.

`mode` decides what a refusal does: `enforce` blocks it and the call fails as PHP fails on a
permission error (a warning, and `false`; a denied include stops as a missing file would —
a warning for `include`, a fatal for `require`); `log` writes one line and lets it through;
`off` does neither. A refusal line is

```
securecore: layer2 enforce plugin:acme file_put_contents write /var/www/html/wp-includes/x.php
securecore: layer2 log     plugin:acme exec               exec  /usr/bin/convert input.png
```

**Where the checks sit.** Every file open PHP code makes is a call to a file function or an
include. A stream wrapper would see only `file://` and user schemes: a bare path — nearly all
real paths — is served by the built-in plain-files wrapper, a `const` the engine returns
directly without consulting any registry, so it cannot be wrapped without rewriting read-only
memory. The one place every bare-path open passes through is the function it was called from, so
on the first request of a worker (once layer 2 is active) the extension replaces the handlers of
the watched file functions and the process functions with one checking handler, and the
`zend_compile_file` wrapper (shared with E2a) covers include and require. opcache does not touch
function handlers, and php-fpm forks after this, so one install per worker holds for every
request.

**Covered** (each fails as PHP would on a permission error): `fopen` (read and write modes),
`file_get_contents`, `file`, `readfile`, `parse_ini_file`, `md5_file`, `sha1_file`, `hash_file`,
`opendir`, `scandir`, `dir`, `glob`, `file_put_contents`, `unlink`, `mkdir`, `rmdir`, `touch`,
`chmod`, `tempnam`, `rename`, `copy`, `move_uploaded_file`; `include`/`require`(`_once`); and the
process functions above. **Not covered** (documented gaps, not silently missed): opens made
inside another extension's C code (GD, Zip), metadata-only calls (`file_exists`, `stat`,
`is_dir` — not opens), and the OO file classes (`SplFileObject`, `DirectoryIterator`), whose
construct-time open neither returns `false` nor passes through a function handler; these are
follow-ups, and layer 1 (the kernel) backstops a component that reaches a file another way.

`research/enforce/compat.sh` runs Classic Editor, Yoast SEO and Contact Form 7 in enforce mode
and lists every refusal; `bench/enforce.sh` is the front-page benchmark.

## Tests

- `cargo test` (in Docker: the `check` target): the examples parse, unknown keys and bad
  values are rejected at every level, the schema is in sync, and the reloader follows the file,
  keeps the last valid config on a bad edit and flags layer 1 changes.
- `DOCKER_CONTEXT=colima test/ext-config.sh`: WordPress on the docker stack with the extension
  (`docker/compose.ext.yml`, project `securecore-ext`, port 8089): front page 200, the status
  reports the file's sha256 and layers, an edit is live in every worker without a restart, and
  an invalid, missing or unset config makes php-fpm refuse to start with the reason in its log.
- `DOCKER_CONTEXT=colima test/ext-attribution.sh` (after ext-config.sh): fixture plugins open
  files in known ways; checks the component each rule charges, the map (own includes, a
  mu-plugin callback, a symlinked plugin, core including plugins and the theme), the rule
  setting, that logging is off by default and that mode `off` records nothing.
- `DOCKER_CONTEXT=colima test/ext-enforce.sh` (after ext-config.sh): a probe plugin attempts
  each file and process operation; checks that enforce mode blocks the forbidden ones (and the
  refusals are logged), that log mode lets the same ones through (the revert proof), that layer 2
  off records nothing, and that a granted component gets its grants while the protected file and
  `securecore_status()` stay refused.
- `DOCKER_CONTEXT=colima bench/ext.sh`: front-page p50 with the extension loaded vs not.
- `DOCKER_CONTEXT=colima bench/attribution.sh`: front-page p50 not loaded, loaded with
  attribution logging off, and on.
- `DOCKER_CONTEXT=colima bench/enforce.sh`: front-page p50 with the three plugins, not loaded vs
  loaded in enforce mode.
