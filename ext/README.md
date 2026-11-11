# SecureCore PHP extension

SecureCore as one PHP extension written in Rust ([ext-php-rs](https://crates.io/crates/ext-php-rs)),
configured from one file, `securecore.json` (addiscorp/securecore#53). Phases so far: **E1** loads,
validates and reloads the config and reports it; **E2a** works out which component is running;
**E2b** enforces layer 2's file and process rules; **E3** is the [vault](#vault-e3), which keeps
the DB password and the WordPress keys and salts out of PHP's reach; **E4** is the
[database policy](#database-policy-e4), which checks every query PHP sends; **E6** is layer 1, the
`securecore-fpm` launcher ([Layer 1](#layer-1-securecore-fpm-e6)); **E5** is the
[hostname policy](#hostnames-e5); **E7** is [layer 3](#layer-3-isolated-plugins-e7), which runs the
plugins listed in `layer3.isolate` in a clean child process instead of the php-fpm worker (first
part: filters, actions and shortcodes; see [Not yet](#not-yet)).

| crate | what |
|---|---|
| `config/` (`securecore-config`) | the config types (serde), the loader, the reloader and the JSON Schema; and the vault's pure logic (E3): reading a secret's source ([`source`](config/src/source.rs)) and the salt reconstruction + keyed hashing ([`salt`](config/src/salt.rs)). Plain Rust, no PHP: the `securecore-fpm` launcher (E6) reads the file with the same code, and the extension and the host tests share the vault's bytes. |
| `attribution/` (`securecore-attribution`) | E2a: path → component (plugin, mu-plugin, theme, core), the two "who is running" rules, the watched file functions, `securecore-attribution-report`; and E2b: the file/process [`policy`](attribution/src/policy.rs). Plain Rust, no PHP. |
| `db/` (`securecore-db`) | E4: the [database policy](#database-policy-e4) — the SQL analysis ([`analyze`](db/src/analyze.rs), on sqlparser-rs's MySQL dialect), the per-component decision ([`policy`](db/src/policy.rs)), the per-worker query cache, and `securecore-db-suggest`. Plain Rust, no PHP. |
| `layer3/` (`securecore-layer3`) | E7: layer 3's wire protocol ([`wire`](layer3/src/wire.rs)), the snapshot's option allowlist ([`options`](layer3/src/options.rs)) and the isolated child's sandbox and rlimits ([`child`](layer3/src/child.rs)). Plain Rust, no PHP. |
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

`--build-arg PHP_IMAGE=<image>` builds against another PHP. The release builds every cell of
[`scripts/ext-cells.txt`](../scripts/ext-cells.txt) that way (below).

## Release (E8)

Every release ships, in `securecore-releases/<version>/ext/` (APS 12):

| file | what |
|---|---|
| `securecore-php<v>-<ts>-linux-<arch>.so` | the extension, for PHP 8.1, 8.2, 8.3, 8.4 × `nts`/`zts` × `x86_64`/`arm64`: 16 cells |
| `securecore-fpm-linux-<arch>` | the layer-1 launcher, one per architecture (plain Rust: every cell builds the same bytes, and the release refuses to ship if they differ) |
| `securecore-vault.php` | the mu-plugin, now empty: the extension defines `wp_salt`/`wp_hash` itself |
| `securecore.schema.json` | the JSON Schema for `securecore.json` |

and `release.json` lists every file in the release with its sha256 and size.

**The matrix.** [`scripts/ext-cells.txt`](../scripts/ext-cells.txt) pins one official php image
per version and thread-safety build (`php:<v>-fpm-bookworm` for NTS, `php:<v>-zts-bookworm` for
ZTS) by its multi-arch digest; each image's `php-config` and headers are that PHP exactly, so
bindgen sees the ABI the extension is loaded into. `scripts/ext-build.sh <php> <ts> <out>` builds
one cell on the Docker host's architecture. Built on bookworm (glibc 2.36), the binaries also run
on trixie and Ubuntu 24.04. On ZTS the engine's globals are per thread, so the extension reads
`EG`/`CG` through ext-php-rs's accessors (`executor_globals()`/`compiler_globals()` in
`php/src/lib.rs`), never the NTS-only statics.

**The release check.** `test/release-check.sh <php> <ts> <dir>` lays the cell's files out as a
release (`scripts/release-layout.sh`, the script the bucket's release uses), builds that PHP's
image with WordPress (`docker/release-check.Dockerfile`), installs SecureCore **with
`install-ext.sh` from that release**, and runs the smoke subset of the ext-* suites: the install
(right cell detected, the installed bytes are the built ones, a re-run changes nothing, a tampered
file is refused), config load (fail closed on a missing file; status reports the file, the layers,
enforce, `caller=core`), attribution (a mu-plugin's `securecore_status()` is charged to
`mu-plugin:sc-smoke` and refused), one enforce refusal (and the same write passing in log mode),
the vault (placeholders only, the real password with the vault removed), and layer 1 (started by
`securecore-fpm`: sandboxed, serving, a core write outside `layer1.write` refused that worked
without it). NTS runs WordPress on php-fpm; the ZTS images have no php-fpm, so ZTS runs it on
`php-cgi -b` (FastCGI, forked children) behind the same nginx. That exercises the ZTS build's ABI
and every hook, but in processes, not threads: a threaded ZTS server (FrankenPHP, Apache's worker
MPM with mod_php) is not in the check. Under php-cgi a request's log lines go down FastCGI's
stderr into the web server's error log.

**Canary and stable (APS 9).** `tag-canary.yml` tags main nightly (09:00 UTC, only if it changed)
and dispatches `release.yml`: 16 jobs build and release-check one cell each and stage the checked
files with their `SHA256SUMS` in `staging/<tag>/<run>/`; publish verifies every cell against its
sums, checks the launchers agree, lays out the release, uploads it, reads every file in
`release.json` back from `https://securecore-releases.addis.gg` and only then points
`canary.json` at it. `promote.yml` copies those bytes to `<X.Y.Z>/`, verifying every manifest
file, never rebuilding.

## Install

```sh
curl -fsSL https://securecore.addis.gg/install.sh | sudo sh
```

(`securecore.addis.gg/install.sh` redirects to `securecore-releases.addis.gg/install-ext.sh`.)
With no options it uses the WordPress in the current folder, or else `/var/www/html`
(`--wordpress` for another), and the newest stable release, or the newest canary while there is
none (`--canary` or `--version` to choose).

[`install.sh`](install.sh) (published as `install-ext.sh`) finds the PHP (`--php` for another
one), its version, NTS/ZTS, extension and ini folders, and the machine's architecture; downloads
`release.json` and that cell's files; checks each against its
sha256 and that the extension loads in this PHP; then installs the `.so`, the launcher
(`/usr/local/bin`), the schema, the mu-plugin (`<wordpress>/wp-content/mu-plugins`), a
`securecore.json` with every layer off **only if none exists**, and last the ini (on Debian/Ubuntu
packages through `mods-available` + `phpenmod`, elsewhere in PHP's scan folder). It is
idempotent, prints one line per step, never restarts a service and never runs sudo itself.

By hand: copy `securecore.so` into PHP's extension folder and add one ini file to `conf.d`
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
[`examples/off.json`](examples/off.json) (the minimum: `layer1` `{"isolation": "off"}`, and
`layer2` and `layer3` `{"enabled": false}`; layer 1's switch is `isolation`, the others' is
`enabled`).

Beyond the schema's structure, one rule is checked in code and expressed in the schema as an
`if`/`then`: `layer2.app` is required when layer 2 is enabled. `layer2.mode` defaults to
`enforce`. The parser accepts exactly what the schema accepts: serde would also read any object
from a JSON array (its fields by position), and that form is rejected
(`layer1 is an array; it must be an object`).

Each entry in `layer2.default` and `layer2.components.<slug>` sets a component's rules; a field
left out of an entry inherits from `default`. For E2b those fields are `files` — an object with
`read` (extra readable paths outside the root) and `write` (extra writable paths, on top of
uploads and cache) — and `exec` (a bool: may the component run programs). See
[Enforcement (E2b)](#enforcement-e2b) for what each means. `tables`, `options` and `grants` are
the [database policy](#database-policy-e4)'s (E4). (`hosts` is for E5.)

## Reload

Layers 2 and 3 follow the file without a php-fpm restart. At request start (RINIT) each php-fpm
worker `stat`s the file at most once per second (`RELOAD_INTERVAL`), and reads, hashes and
parses it only when the stat (inode, size, mtime, ctime) changed, or while the stat is too recent
to tell two writes apart: file times tick coarsely, so two same-size writes inside one tick leave
the same stat, and for 2 s after the file changed the sha256 is compared too ("racily clean", as
git calls it; #63). A new valid file goes live in
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
  - **the connector is core** — by `attribution::db_connector`, the one rule the vault and the
    host policy share: the code that called connect is the database layer (a method of `wpdb` or
    of a subclass of it, such as a `db.php` drop-in) or core code, so WordPress's `wpdb` counts
    and a plugin's own `new mysqli` does not.
  - **the connection goes exactly where the configured DB host says** — `layer2.vault.dbHost`, or
    the `DB_HOST` constant, read the way WordPress reads it — the same host **and** the same port
    or socket ([`config/src/dbhost.rs`](config/src/dbhost.rs)). What a side leaves unset is filled
    the way the driver fills it: mysqli from `mysqli.default_host` / `_port` / `_socket` (the
    connect from their values now, the configured host from php.ini's), PDO from `localhost` /
    3306, MySQL's default port 3306 underneath. The right host on another port is another server
    (`new wpdb(DB_USER, DB_PASSWORD, DB_NAME, 'db:3307')` gets the placeholder), and a component
    pointing a connect at its own server never matches, so the password is not sent there even
    over a cleartext or RSA-under-attacker-key auth exchange. A PDO DSN that is not a plain
    `mysql:` one (`uri:`, an ini alias) or names a key twice never matches.
- **Salts:** when `layer2.app` is `wordpress` and the vault holds WordPress's eight keys and salts,
  the extension defines `wp_salt()` and `wp_hash()` itself, natively, at module startup — before
  any PHP runs, so `pluggable.php` skips its own and no mu-plugin can define them first (a vault
  that holds some of the eight but not all refuses to start; one that holds none, only the DB
  password, leaves WordPress's own). `wp_hash()` computes `hash_hmac($algo, $data,
  wp_salt($scheme))` over the **real** keys inside the extension — byte-identical to stock
  WordPress for the standard key/salt constants — so the HMAC key never becomes a PHP value, while
  login cookies, nonces and password-reset keys keep working. `wp_salt()` returns a scheme token,
  never the key, so a probe that calls it cannot recover the key. The reconstruction and hashing
  are one plain-Rust function ([`config/src/salt.rs`](config/src/salt.rs)), shared by the extension
  and the host tests; the same functions stay available as `securecore_vault_salt` /
  `securecore_vault_hash`. The mu-plugin `securecore-vault.php` that used to define them is now
  empty (kept so an install that copies it is harmless): defined in PHP, they failed open when
  the file was missing or an earlier mu-plugin defined `wp_salt` first.

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

## Database policy (E4)

Every query PHP sends is charged to the code that called the database layer
([below](#who-a-query-is-charged-to)) and checked before it reaches the server. A port of the worker spike's PHP policy
(#49, `plugin/sql-policy.php`) to Rust ([`db/`](db/)), with per-component tables, options and
grants. `log` writes an audit line and runs the query; `enforce` writes the line and the query
fails as a MySQL permission error does; `off` does neither.

```
securecore: layer2 enforce plugin:acme mysqli_query protected-column select wp_users
securecore: layer2 log     plugin:acme mysqli_query option select wp_options options=blogname
securecore: layer2 enforce core mysqli_query unparseable select -
```

(`layer2 <mode> <component> <route> <rule> <statement> <tables>`; an options refusal adds the
option names it pinned.)

### The rules

**Everyone, core included**, gets only the allowlisted statement types: SELECT, INSERT, REPLACE,
UPDATE, DELETE; SHOW, DESCRIBE, EXPLAIN; the session SETs (`SET NAMES`, `SET SESSION sql_mode`,
`SET autocommit`, …); transaction control; and table DDL (CREATE / ALTER / DROP / TRUNCATE /
RENAME TABLE, CREATE / DROP INDEX). Refused for everyone, whatever they name: PREPARE / EXECUTE /
DEALLOCATE, `SET @var` and `SET @@…`, `LOAD_FILE(`, `INTO OUTFILE` / `DUMPFILE`, LOAD DATA, CALL,
HANDLER, DO, USE, LOCK / UNLOCK, GRANT, CTEs (`WITH …`), `SELECT … INTO`, the table-maintenance
statements, stored-object DDL (views, functions, procedures, triggers, events), a `/*! … */`
executable comment, a `sql_mode` with `ANSI_QUOTES`, `ANSI` or `NO_BACKSLASH_ESCAPES`, and a
charset other than utf8mb4 / utf8 / utf8mb3 / latin1 / ascii / binary (`SET NAMES`,
`SET CHARACTER SET`, `mysqli_set_charset`). Those last three change how the server tokenizes the
text, so after one of them the parser and MySQL would read the same query differently. The worker
spike (#49) checked only the sandboxed plugins' queries; E4 holds core to the allowlist too.

**Core** is otherwise unrestricted. An unparseable query from core runs and is logged
(`unparseable`), except an unparseable `SET`, which is refused.

**A component** (plugin, mu-plugin, theme):

| | may | never |
|---|---|---|
| **tables** | its own: named after its slug (`<prefix><slug>` and `<prefix><slug>_*`, with `-` read as `_`), plus what its `tables` globs match (against the name without the prefix, e.g. `["wc_*"]`) | DDL on a core table, whatever it is granted; another component's tables; another schema (except reading `information_schema`) |
| **core tables** | only through `grants`: `users`, `capabilities`, `posts`, `comments`, `terms`, `links`, `options`, `network`, each `:read` or `:write` (`write` includes `read`) | |
| **options** | its own (names equal to its slug or starting with `<slug>_` / `<slug>-`, transients included), plus what its `options` globs match; any other one with `options:read` / `options:write` | write a protected option: `siteurl`, `home`, `active_plugins`, `<prefix>user_roles`, `admin_email`, `users_can_register`, `default_role`, `cron`, `mailserver_login`, `mailserver_pass` and the salt options. The read-protected ones (#49's list) are readable only when named in `options`; the salt options never |
| **users** | with `users:read`, any column but the two below; with `users:write`, write rows (and set a password, as `wp_set_password` does) | read `user_pass` or `user_activation_key`: naming either anywhere (select list, WHERE, ORDER BY, JOIN … USING), a `*` / `users.*` over `users`, or a NATURAL JOIN with it |
| **usermeta** | through `users`; capability rows (`<prefix>capabilities`, `<prefix>user_level`) need `capabilities:write` too, and so does a write not pinned to named keys | read `session_tokens` by name |
| **statements** | one per query | an unparseable or multi-statement query (refused in enforce: fail closed) |

**How "own" is decided: by name, from the slug.** Not "tables it created": that needs a
persistent ledger shared by every worker, and it rewards squatting (a component creating another
plugin's table first). Not a hand-written list alone: most plugins' tables and options already
follow their slug. Where they don't (Yoast's slug is `wordpress-seo`, its options `wpseo*`), the
entry lists globs, and `securecore-db-suggest` writes those entries.

**Which options a statement touches** comes from the parsed WHERE: `option_name = '…'`,
`IN (…)`, or `LIKE 'prefix%'`, only through top-level ANDs (an OR could widen it), and from the
VALUES or SET of an INSERT / UPDATE (so a row can't be renamed into `siteurl`). A read not pinned
to named options needs `options:read`; an unpinned write is refused (it could reach a protected
option).

### Where queries are seen

As internal-function handlers, on the vault's hook mechanism (`vault::hook_with`): `mysqli_query`,
`mysqli_real_query`, `mysqli_multi_query`, `mysqli_prepare`, `mysqli_stmt_prepare`,
`mysqli_execute_query`, and the `mysqli::query`, `real_query`, `multi_query`, `prepare` and
`execute_query`, `mysqli_stmt::prepare` and `new mysqli_stmt($link, $sql)` methods; `PDO::exec`,
`PDO::query` and `PDO::prepare`. `$wpdb` uses `mysqli_query`. A prepared statement is checked at
prepare: the execute calls carry no SQL. PHP 8.3 has no `mysqli_send_query`; an async query is sent
by `mysqli_query`. `select_db` and `change_user` are refused for a component (`USE` and a
re-login), except `select_db` of the site's own `DB_NAME` (exactly): `wpdb::db_connect()` runs it on
every reconnect, so refusing it killed a `$wpdb->check_connection()` a plugin's call triggered;
`set_charset` to an unsafe charset is refused for everyone. Every connection is checked,
not just `$wpdb`'s.

### What a refusal does

`enforce` hands the server a statement that fails in the query's place, so the failure is the
native one in every error mode:

- **a query** (`query`, `real_query`, `multi_query`, `exec`, the PDO routes) runs
  `SIGNAL SQLSTATE '42000' SET MYSQL_ERRNO = 1142` (MySQL's "command denied") with the reason as its
  message. mysqli returns `false` and sets `errno`/`error`, or throws `mysqli_sql_exception` 1142
  in strict report mode; PDO follows its error mode; `$wpdb->query()` returns `false` with
  `$wpdb->last_error` set. Plugins degrade, nothing is fatal;
- **a mysqli prepare** gets a statement the server rejects *at prepare* (a syntax error naming the
  rule, `securecore_denied_<rule>`): MariaDB prepares a SIGNAL successfully and would fail only at
  execute, after `bind_param` had already thrown `ArgumentCountError` on the placeholder count. So
  `prepare` returns `false` (or `new mysqli_stmt` leaves the statement unprepared, as PHP does for
  any failed prepare);
- **select_db / change_user / set_charset** return `false` without reaching the server (a failed
  `change_user` would drop the connection, core's included).

### Parser: sqlparser-rs

[sqlparser](https://crates.io/crates/sqlparser) `=0.63.0` (Apache DataFusion's), with its MySQL
dialect. It is the maintained Rust SQL parser with a MySQL grammar (the alternatives are
unmaintained, Postgres- or SQLite-only), and it reads every shape WordPress and the three plugins
send: `SQL_CALC_FOUND_ROWS`, `ON DUPLICATE KEY UPDATE`, `SHOW FULL COLUMNS`, `@@SESSION`,
multi-table DELETE (unit-tested in `wordpress_query_shapes_parse`, and on the stack: no core
`unparseable` line on the compat pages). Its gaps are handled before it runs. A few refused
statements aren't in its grammar (`PREPARE … FROM`, `HANDLER`, `DO`, `INTO OUTFILE`), so they're
refused by leading keyword or token rather than left to "unparseable", which core is allowed. Its
tokenizer expands some `/*! … */` comments and not others, while MySQL runs them, so any executable
comment is refused, found by scanning the raw text.

### Cost

Analyses are cached by query text, per worker (bounded LRU, 2048 texts; texts over 8 KiB aren't
kept). On the host, a miss (parse + analysis) costs ~37 µs, a hit 0.06 µs, the decision 0.1 µs
(`cargo test --release -p securecore-db -- --ignored --nocapture parse_cost`). `bench/db.sh`
measures the page cost against main.

### Who a query is charged to

**A database query is charged to whoever called the database layer, because core APIs run their
own SQL on a plugin's behalf.** That is the innermost frame outside the database layer
([`db/src/caller.rs`](db/src/caller.rs), unit-tested). The database layer is known by its class,
not its file: a method (not a closure) of `wpdb` or of a subclass of it, by the class entry's
parent chain — so a `wp-content/db.php` drop-in (HyperDB, LudicrousDB, Query Monitor) is the
database layer too, and a plugin's query through it is still the plugin's:

- a component's own SQL is the component's: `$wpdb->query(...)` in its file, or its own mysqli
  or PDO connection;
- the SQL a core API composes is core's, whoever called the API: `get_user_by()` loading the
  current user, `WP_Query`, `wp_schedule_event()`'s cron write.

Charging core's SQL to the plugin on the stack instead (E2a's `component` rule, the one files use)
was measured and rejected (#60). Yoast triggers the current-user load, so core's login check,
`SELECT * FROM wp_users`, was charged to Yoast and refused as a protected column, and every signed-in
admin page was 403. Under the caller rule the three plugins have 0 refusals. Files stay on
`component` (E2b measured 0 refusals with it).

**Passthrough helpers.** A core function that runs SQL, or a table, column or option name, its
caller hands it would otherwise launder that SQL into core's. So while the chain of core frames from
the query outward runs through one, the query is charged to the helper's caller (the innermost
helper decides):

- `wp-admin/includes/upgrade.php`: `dbDelta`, `maybe_create_table`, `maybe_add_column`,
  `maybe_convert_table_to_utf8mb4`, `drop_index`, `add_clean_index`, `__get_option`;
- `install-helper.php`: `maybe_drop_column`, `check_column`;
- `schema.php`: `populate_options`, `populate_network`, `populate_network_meta`,
  `populate_site_meta`;
- the option write API: `add_option`, `update_option`, `delete_option` and their `_site_` /
  `_network_` forms.

So `dbDelta("UPDATE wp_options … 'active_plugins'")` and `update_option('mailserver_pass', …)`
from a plugin are the plugin's (refused). `wp_schedule_event()` is core's (its `update_option('cron')`
is called by core's cron code), while a plugin's own `UPDATE` of `cron` is refused. A function is a
helper only when core defines it.

`securecore.debug_db_attribution` (`caller`, the default, | `component`) exists only to reproduce
that measurement; it is not configuration.

### Threat model

E4 stops a component's **own SQL** from reaching what it doesn't own: other components' tables,
core's tables without a grant, the protected options and columns, and the statements that bypass
the checks. That includes SQL routed through core's passthrough helpers. It does **not** stop:

- **Filters (known gap).** A component's `query`, `posts_where`, `posts_clauses` (and similar)
  callback has returned by the time core runs the SQL it shaped, so that SQL runs as core. Closing
  this needs the filter results checked.
- **What core APIs hand back.** `get_userdata()` returns a `WP_User` with `user_pass`, and core
  keeps the current user's hash in memory for every plugin; `update_user_meta()` and
  `WP_User::set_role()` write capability rows as core. These are API surface, beyond any SQL policy.
- **WordPress's caches.** An autoloaded option is served from memory, without SQL.

### Known limits

The filter gap and what core APIs return: see the [threat model](#threat-model).

- **No result filtering.** #49 let a plugin run `SELECT * FROM wp_users` and stripped `user_pass`
  from the rows, and cut a bulk options read down to an allowlist. E4 decides on the query alone,
  so a `*` over `users` is refused, and an unpinned options read needs `options:read` (and then
  returns every row, the read-protected ones included). Bulk `usermeta` reads with `users:read`
  return `session_tokens` rows; those hold hashed token verifiers, not the cookies.
- **Tables in a write statement are all writes.** `INSERT INTO mine SELECT … FROM wp_posts` needs
  `posts:write`, not `posts:read` (fails closed).

### Suggesting entries

Run the site in `log` mode, use it, then

```sh
cargo run -p securecore-db --bin securecore-db-suggest -- --prefix wp_ php-fpm.log > suggested.json
```

prints the `components` entries (tables, options, grants) each component needed, for a person to
approve, plus `refusedAlways`: what no entry can open (a protected option written, a protected
column). `research/db/compat.sh` does this for Classic Editor, Yoast and CF7.

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

## Hostnames (E5)

Layer 2 also restricts **where PHP may open a network connection**, per component and for core, so a
compromised site cannot phone home. Every outbound connection is attributed to the innermost
responsible component (the `component` rule) and checked against that component's `hosts` — its own
entry's list, or `default.hosts` when it has none. A connection **core** makes is checked against
`core.hosts`: core *is* restricted here (unlike the file policy). Code outside the app root is not a
component and is not checked. The matching rules are in
[`attribution/src/hosts.rs`](attribution/src/hosts.rs) (plain Rust, unit-tested).

**Patterns.** An entry is an exact name (`api.stripe.com`), a leading `*.` wildcard matching one or
more labels (`*.example.com` matches `a.example.com` and `a.b.example.com`, never `example.com`), or
an IP literal (v4 or v6), which matches only that address. Matching is case-insensitive, after
IDNA/punycode normalisation and with a trailing dot stripped; a name never matches an IP pattern and
an IP never matches a name pattern. An empty list denies every host.

**The host a connection actually goes to, not what a URL claims.** The checks sit where the real
connect host is known:

- **The socket transport** (`tcp`/`ssl`/`tls`). SecureCore overrides the transport factories, the one
  point every PHP socket connection passes through *at connect time*, with the resolved host — so
  `fsockopen`, `pfsockopen`, `stream_socket_client`, the http/https/ftp stream wrappers
  (`file_get_contents`, `fopen`, `SoapClient`, `get_headers`), WordPress's Requests library, and
  **each redirect hop** (the http wrapper follows a `Location` by opening a fresh transport to the new
  host) are all checked on the host they connect to. A `user:pass@` prefix and the SNI/`Host` header
  never reach this point, so they don't count.
- **The http/https/ftp wrappers** are additionally wrapped so the **target** host is checked even when
  a **proxy** is set in the stream context (the transport then connects to the proxy — which is
  checked too — while the request names the target).
- **curl** does its own DNS and connect, below PHP's socket layer, so it is checked from the options
  recorded on the handle at `curl_exec` / `curl_multi_add_handle`: the URL host, `CURLOPT_PROXY`, and
  the `CURLOPT_RESOLVE` / `CURLOPT_CONNECT_TO` overrides (so an override pointing an allowed name at a
  disallowed IP or host is refused). A component may only speak **http/https/ftp/ftps** through curl —
  `CURLOPT_PROTOCOLS`/`REDIR_PROTOCOLS` are clamped and the scheme is checked, so `file://`
  (which would bypass E2b's file policy) and gopher/dict/telnet/smb are refused. `curl_copy_handle`
  carries the recorded options to the copy; a handle whose URL SecureCore never saw being set fails
  closed for a component at exec.
  - **Redirects:** libcurl follows a redirect *internally*, below any PHP hook. So when a restricted
    component has `CURLOPT_FOLLOWLOCATION` on, SecureCore turns it off and **follows in the
    extension** — on each 3xx it reads the resolved next URL, checks its host with the same rules (an
    audit line per hop), and re-runs, honouring `CURLOPT_MAXREDIRS` and POSTREDIR. A redirect to a
    disallowed host is refused at the hop. `curl_multi` (which follows internally with no hook) and a
    `FOLLOWLOCATION` request whose body is printed rather than captured are **degraded**: following
    is turned off and the 3xx is returned, not followed.

**DNS rebinding.** Layer 2 allowlists *names* and checks the exact name string the connect uses (the
transport resolves the very name this code read), so there is no check-versus-connect *name*
discrepancy. An allowed name whose DNS later resolves to an internal IP is an IP-level rebind a name
allowlist cannot see; layer 1's port rules (no internal ports open) are its backstop.

**The database host** is allowed implicitly for **core's** connection only: WordPress's `DB_HOST` need
not appear in `core.hosts`, and a vaulted password still connects. The DB goes through the transport
factory (mysqlnd), where a connection attributed to core and aimed at `DB_HOST` is passed through
before the allowlist is consulted; a *component* reaching the DB host directly is still checked
against its own `hosts`. A database connect (`mysqli_connect`, `mysqli_real_connect`, `new mysqli`,
`mysqli::real_connect`, `new PDO`) is attributed by the vault's rule, `attribution::db_connector`,
not by the configured rule: the database layer (`wpdb` or a subclass) connecting is core even with
a plugin further out on the stack, so a `wpdb::check_connection()` reconnect a plugin's call
triggers is never refused as the plugin's.

`mode` decides the effect, as everywhere: `enforce` refuses the connection the way PHP fails a refused
connection — the stream opener and the socket functions return `false` (and Requests turns that into a
`WP_Error`), `curl_exec` returns `false`, never a fatal — `log` records one line and lets it through,
`off` does neither. A refusal line is

```
securecore: layer2 enforce plugin:acme net connect host evil.example tcp://evil.example:443
securecore: layer2 log     core        net curl_exec host api.example http://api.example/v1
```

**Covered:** the http/https/ftp wrappers, `fsockopen`/`pfsockopen`/`stream_socket_client`, `curl`
(`curl_exec`, `curl_multi_*`, `CURLOPT_FOLLOWLOCATION` followed in-extension per hop,
`RESOLVE`/`CONNECT_TO`/proxy, the scheme and protocol clamp, `curl_copy_handle`), `get_headers`
and `SoapClient` (both use the http wrapper), `socket_connect` from ext/sockets (a function handler;
the transport factory does not see ext/sockets, which uses a raw socket), and SMTP that a mail plugin
opens with `fsockopen`/`stream_socket_client`. **Left to layer 1:** metadata-free local transports
(`unix`/`udg`) are not hostnames; and a component that reaches the network by native code the engine's
streams and curl never see is the kernel's job.

**Recommended `hosts` for the bundled-WordPress compat set** (what SecureCore's generated manifests
suggest; a person approves them as a git diff):

| component | `hosts` | why |
|---|---|---|
| core | `api.wordpress.org`, `downloads.wordpress.org` | core updates, plugin/theme installs |
| Classic Editor | *(none)* | makes no outbound calls |
| Yoast SEO | *(none)* for normal operation | its indexing/SEO work is local; add `*.yoast.com` only if you use myYoast/premium |
| Contact Form 7 | *(none)* | local; add `www.google.com` only if you enable reCAPTCHA |

`test/ext-hosts.sh` is the property test (a no-internet nginx helper under several aliases), and
`bench/hosts.sh` is the front-page and per-connection benchmark.

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

With `layer1.isolation: "off"` it execs php-fpm as it is and says so (`layer 1 is off in …`).
`isolation` is layer 1's only switch: `layer1.enabled` is retired, and a file that still sets it
is refused (`layer1.enabled is retired: layer1.isolation is layer 1's only switch …`).
The installer upgrades such a file when it keeps it (`securecore-fpm --migrate-config <file>`):
`"enabled": false` becomes `"isolation": "off"`, `"enabled": true` is removed (leaving
`isolation` as it is, `auto` when absent), and the original is kept beside it as
`<file>.before-isolation` (`.1`, `.2`, … if that exists), with the same owner and mode.
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

### `layer1.isolation`: gelada or a microVM (#71)

`layer1.isolation` picks what php-fpm runs inside. The launcher logs the choice first
(`securecore-fpm: layer 1 isolation auto: …`).

| value | what runs |
|---|---|
| `auto` (the default) | gelada, with the reason. **`auto` does not pick the microVM until the guest's writable folders sync back to the host (#72)**: `AUTO_SELECTS_MICROVM` in `fpm/src/lib.rs` is that gate, and a test pins it off. Once it opens, `auto` is the microVM where it can run and gelada otherwise (`layer 1 isolation auto: gelada, because the microVM can't run here (…)`), whether the host or the config is why. The only value that falls back |
| `microvm` | the microVM, or nothing: without one the launcher exits 125 (`layer1.isolation is "microvm" but this host can't run the microVM (…). "microvm" never falls back`) |
| `gelada` | gelada on the host kernel, as above, even where KVM exists |
| `off` | layer 1 off: php-fpm runs as it is. The only way to turn layer 1 off (`layer1.enabled` is retired) |

**The microVM can run** when all of these hold (otherwise `auto` logs why and `microvm` exits
125 with it):
- the launcher is root (the jailer needs it) and the jailed user (`--vm-user`, a name or
  `<uid>:<gid>`, default `securecore-vm`, which the installer creates) exists and isn't root;
- `/dev/kvm` opens read-write and answers `KVM_GET_API_VERSION` with 12;
- `<vm-dir>/firecracker`, `jailer`, `vmlinux` and `rootfs.ext4` (`--vm-dir`, default
  `/usr/local/share/securecore/vm`) each match the sha256 in `<vm-dir>/installed.json`, the
  installer's record. Nothing unrecorded boots. The installer records the kernel, Firecracker,
  the jailer and the guest image. Each release ships its guest image (#80) at
  `<version>/vm/linux-x86_64/rootfs.ext4.gz`, with its sha256 gzipped and unpacked in
  `release.json` and `vm/manifest.json`: `docker/ext.Dockerfile`'s `guest` target (its base pinned
  by digest, apt from snapshot.debian.org; compilers, sources, docs and every setuid/setgid bit
  removed) made into an ext4 inside the pinned `guest-tools` image by `scripts/guest-image.sh`
  (`scripts/guest-build.sh`; `--check` builds it twice and compares, a CI report that never
  gates). The installer checks both sha256s before it places anything, unpacking in
  `<vm-dir>/.securecore-staging` after checking there is room. In the guest, the root is mounted
  nosuid and php-fpm runs under no_new_privs;
- the config is one the microVM can enforce (below), and every `connect[].socket` is a socket the
  jailed user may open itself (checked by running a probe as that user);
- with layer 3 on, the kernel has Landlock and seccomp filters (its symbols are checked; mirab's
  kernel has neither until mirab#89, and its isolated children would fail closed);
- cgroup v2, and `mke2fs`, `e2fsck` and `resize2fs` on `PATH`.

**Firecracker never runs as root.** Its jailer (from the same Firecracker tarball) starts it as
the jailed user with no supplementary groups, chrooted into `<state>/jail/firecracker/<id>/root`,
which holds only this VM's kernel, disks, snapshot and sockets, in new mount, network, IPC and UTS
namespaces, and in the cgroup `securecore/<id>` with `cpu.max` (the vCPUs) and `memory.max` (the
guest's memory plus 256 MiB). A `connect[].socket`'s folder is bind-mounted read-only into the
jail, so a guest's database connection reaches MariaDB with the jailed user's credentials
(`SO_PEERCRED`): `unix_socket` authentication never makes it root. Every start empties the jail
first, so no link from an earlier config survives. One launcher per state folder (a lock). A
watchdog process takes the VM down when the launcher goes, however it goes (a crash, SIGKILL):
it waits on a pipe only the launcher holds, then kills the VM's cgroup (`cgroup.kill`),
unmounts the jail and removes the cgroup. When Firecracker exits on its own, the launcher
clears the jail and exits non-zero. Firecracker's console goes to `<state>/console.log`, capped
at 8 MiB (then `console.log.1`); guest log lines are cut at 8 KiB, at most 4 log connections and
64 connections per `address` forward are served at once.

**The site's files are copied as the site's pool user, never as root** (`--pool-user`, a name
or `<uid>:<gid>`, default the app root's owner; a root-owned root needs the flag). `mke2fs -d`
runs as that user in a private mount namespace where every writable folder is covered by an
empty tmpfs, so the site disk holds the code and not the uploads (the writable folders are only
mount points in it), and a file only root may read fails the build instead of reaching the
guest. A writable folder must be a real folder in the root: `..` and a symlink anywhere along
its path are refused. `e2fsck`/`resize2fs` on a guest-written disk run as the jailed user. The
guest's php-fpm pool runs as the pool user's uid and gid (`sc.user`, so uploads keep the host's
ownership), and a unix `--listen` socket's group defaults to the pool user's group.

**In the microVM** the launcher stays in the foreground (like `php-fpm -F`) and is the guest's
only way in or out. SIGTERM, SIGINT and SIGQUIT sync the guest's disks, stop the VM and exit 0;
SIGUSR2 and SIGHUP reload the guest's php-fpm gracefully; SIGUSR1 is acknowledged (everything
logs to stderr, so there is nothing to reopen). With `NOTIFY_SOCKET` set (systemd
`Type=notify`) it sends `READY=1` once it serves. A unix `--listen` socket gets
`--listen-owner`, `--listen-group` and `--listen-mode` (0660 by default, as php-fpm's
`listen.mode`), set as it is made and never through a link. Every line from the guest is logged
as `guest: …`, so the guest can't write the launcher's lines. The guest has no network device,
only vsock, and `layer1` maps onto it as follows:

| `layer1` | in the microVM |
|---|---|
| `network.bind` | the first port is where the launcher takes FastCGI, on `127.0.0.1` (`--listen unix:<path>` or `<host>:<port>` for another), and passes it to php-fpm over vsock |
| `network.connect` with `socket` | the guest's `127.0.0.1:<port>` reaches that unix socket on the host, with nothing in between (Firecracker connects it, as the jailed user; mysqlnd's connect goes onto vsock in place, #70). Only a socket the jailed user can reach and open itself counts (its real path; every folder above it too). With the socket under `/run`, the same path works in the guest too (WordPress's `DB_HOST=localhost`) |
| `network.connect` with `address` | the launcher connects the guest's `127.0.0.1:<port>` to that TCP `host:port` |
| `network.connect` port 1514 | refused: it is the guest's log channel |
| `network.connect`, neither | an egress port (#72): the guest reaches *named* hosts on it through the host (`getaddrinfo` in the guest answers a placeholder address, and the connect goes over vsock with the name). Layer 2's own decision applies: in `enforce` only names in its host lists (core's, `default`'s or a component's), in `log` any name with the unlisted ones logged, with layer 2 off (or `off`) any name; layer 2 still checks each caller in the guest. The host resolves the name and connects only to public addresses that aren't its own (an IP literal too), as the site's pool user, so uid-based firewall rules apply. An internal target needs a `socket` or `address` entry. No DNS and no IP routes in the guest |
| `network.connect` port 1517 with a socket or address | refused: it is the guest's egress channel |
| `network.unixSockets` | refused: give the port the socket instead |
| `write`, inside the app root | its own read-write disk, made once from the folder's contents and kept across starts: twice what the folder takes, at least 1 GiB, in powers of two, never less than `--write-disk-mib` (1024); it only grows (in place), and the guest logs past 90 % and 98 % full, before writes fail with ENOSPC. **It syncs with the host's folder** (#72): every change the guest makes (a file once it is closed, folders, deletes, renames, modes, hard links) is applied to the real folder, the one nginx serves, by `securecore-fpm --sync-writer`: the pool user, no network, no new privileges, Landlock to the folder and its trash, a seccomp allowlist, every path opened beneath the folder (no symlink, no `..`, no other mount). A record in the state folder says what the sync wrote; the writer changes or removes a host file only while it still matches. A file the site owner adds or edits on the host wins, and reaches the guest at the next start; removals go to `<state>/trash/<date>/` for 7 days. Symlinks, other mounts and unknown names that aren't UTF-8 on the host are left alone. Each connection starts with the guest's whole listing, so a crash on either side loses nothing. A new site's disks are refused while a state folder beside it holds the disks of a root that no longer exists (a moved site: `--state-dir <that folder>` adopts them) |
| `write`, outside it | a tmpfs in the guest (`/tmp` always is one) |
| `deny`, outside the app root | nothing to do: the guest never has it |
| `deny`, inside it | refused: the site disk is the whole root |

**php-fpm's environment in the guest** (#72). The vault's env sources
(`layer2.vault.secrets[].env`) always go to the guest, and so does each `--guest-env <NAME>`
(repeatable; e.g. `WORDPRESS_DB_HOST`). Their values come from the launcher's own environment,
where php-fpm on the host would have them, for example a systemd `EnvironmentFile`. The launcher
sends them in every start message: after a cold boot, after every restore, and again to a
reloaded php-fpm. They are never in the guest's image, its boot arguments, a snapshot or a
log. A name the launcher's environment lacks stops the start. Firecracker, the sync writer and
the egress helper run with an empty environment, and mke2fs, e2fsck and resize2fs with PATH
only. A protocol handshake (`sc.proto`) comes first: an init of another protocol (an older
root image) gets no start message, and a guest's reply to one that carried values is never
shown. Guest memory can be swapped on the host: run microVM hosts with no swap or encrypted swap.

The site is a read-only disk built from the app root with `mke2fs -d`, mounted at the same path
(or `--guest-root`, the root nginx sends in `SCRIPT_FILENAME`). The guest's root is read-only
too, so core, plugins and themes can't be written. Its PID 1 is `securecore-fpm` again, as
`/sbin/securecore-init`: it mounts the disks, forwards vsock and starts php-fpm, whose log comes
back to the launcher's stderr, every line numbered and acknowledged, so a line that can't be
delivered is counted in the launcher's log, never silently dropped (#86). When php-fpm exits,
the guest sends its last lines and its exit status first, and the launcher's stop line quotes
them (#87). Layers 2 and 3 run in the guest's php-fpm unchanged; layer 3's
isolated children need Landlock and seccomp in the guest kernel (mirab#89 adds them to mirab's).

**Editing `securecore.json` while the guest runs** (#90). The launcher follows the file, as the
extension does on a host (a look a second, the same parser), reading it as the pool user, never
through a link and at most 128 KiB (a link, a device or a larger file is refused and logged): an
invalid file is refused and
logged, and the guest keeps the last valid config; a valid one is also checked against what a
start would check (a config the microVM can't run is refused the same way), then put in place
of the guest's copy, where the extension reloads it within a second. As on a host, layers 2 and
3 change in place, and a change to `layer1` or the vault applies at the next start
(`restart_needed`); the host's egress takes layer 2's new hosts at once.

**The site's php.ini settings** (#90). php.ini in the guest is the root image's, the same for
every site. `--guest-ini <file>` names a file of the extension's per-site debug settings
(`securecore.debug_* = …` lines with plain-word values, `[a-z0-9_.,:-]`, so no `${VAR}`; any
other setting is refused with the reason, which never quotes the file), delivered in
each start message and again whenever the file changes, with php-fpm started again gracefully,
as a php.ini change needs on a host. A value the extension refuses stops php-fpm, as it would
on a host, and the launcher's log says why.

**Snapshots.** A start restores a snapshot of a warmed-up VM when there is one for this key: the
sha256s of Firecracker, the kernel, the root image, the site tree (every path, mode, owner, size
and mtime, writable folders excepted) and `securecore.json`, plus the memory, vCPUs, boot
arguments and disks. Without one, the launcher cold-boots a VM that has no way to the database,
warms it by reading the site's PHP files into the guest's page cache (the guest image's
`warm.php`; nothing is compiled or run, so the production database sees nothing, and opcache
holds nothing compiled out of context: `opcache_compile_file` over a WordPress tree declares
functions as it goes and caches classes whose traits aren't bound, which broke Contact Form 7),
snapshots it, and restores that, so the next
start is fast; old snapshots and site disks are removed. A restore that fails is removed and the
launcher cold-boots instead. After every boot or restore the launcher sends the guest one start
message, which the guest takes from the host's CID only and only once per boot: the clock (a
restored guest has the snapshot's), 64 fresh random bytes (credited to the guest kernel's pool,
and its CRNG reseeded, so restores of one snapshot don't share a random stream), after a restore
a graceful replacement of php-fpm's workers (forked before the snapshot; the master forks fresh
ones and opcache stays warm), and only then the writable disks, so no snapshot ever holds a
stale view of them. The guest kernel has no `CONFIG_VMGENID` (mirab's config), so the entropy in
the start message is the only reseed; the residual risk is a generator inside a long-lived
process that isn't a worker (the master, layer 3's helper), which seeds from the kernel before
the snapshot. `--no-snapshot`
cold-boots every time. Each site's disks, snapshot and sockets live in `--state-dir` (default
`/var/lib/securecore/vm/<sha256 of the app root>`). `--mem` (512) and `--vcpus` (2) size the
guest.

**Where the VM's files come from.** Nothing is pinned here. The release resolves mirab's newest
stable release at build time (`scripts/mirab-vm.sh`): its `vm/manifest.json` (the kernel, with
both sha256s) and the Firecracker mirab pins at that release's commit (mirab's
`scripts/firecracker.json`; mirab's releases carry no Firecracker). It records them as
`ext/mirab-vm.json` in the release, and `install-ext.sh` downloads both, checks each against
those sha256s (the kernel gzipped and unpacked, the Firecracker tarball and its binary) and
writes `<share-dir>/vm/installed.json`, naming the mirab release. While mirab's stable has no
`vm/` (before mirab#89) a release carries no `mirab-vm.json` and `auto` is gelada. For
development, `scripts/mirab-vm.sh <out> <manifest-url>` (the release workflow's `mirab_manifest`
input) takes a canary's manifest instead.

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

## Layer 3: isolated plugins (E7)

A plugin listed in `layer3.isolate` never runs in the php-fpm worker. It runs in a clean child
process, one per request, forked from a helper that booted WordPress without it, and restricted
by the kernel before the plugin's first line:

```json
"layer3": {
  "enabled": true,
  "isolate": ["contact-form-7"],
  "limits": { "timeoutMs": 5000, "memoryMb": 256 },
  "write": { "contact-form-7": ["wp-content/uploads/wpcf7_uploads"] }
}
```

It is the process model the #42 spike measured (`docs/realwp-spike.md`), moved into the
extension. The wiring is [`php/src/layer3.rs`](php/src/layer3.rs); the parts that need no PHP
(the wire, the snapshot's allowlist, the child's limits) are [`layer3/`](layer3/), unit-tested.

### How it works

1. **The helper.** At MINIT under php-fpm, with layer 3 enabled, the master fork+execs
   `<PHP_BINDIR>/php -d securecore.layer3_role=helper -r <helper.php>`
   ([`php/src/layer3/helper.php`](php/src/layer3/helper.php), compiled into the `.so`) with an
   **empty environment**, stdin and stdout on `/dev/null`, stderr shared with php-fpm (so its lines
   land in php-fpm's log), and one end of a `SOCK_SEQPACKET` control socket on fd 3. The master
   keeps the other end, so every worker inherits it; a request socket is a `socketpair`, so layer
   1's "no unix sockets" holds. The helper never reads the vault (`securecore.layer3_role=helper`
   skips it) and never sees wp-config.php. It runs as the pool user: the control socket has
   `SO_PASSCRED`, so the kernel stamps each worker's uid and gid on its message, and the helper
   drops from root to them on the first one and ignores any other uid after.
2. **The zygote.** The helper's supervisor forks a *zygote* per core-options snapshot. The zygote
   boots WordPress once (`wp-settings.php`, not wp-config.php) from the snapshot the worker sent
   — **WordPress's own options only** (#47): the names `populate_options()` in the site's
   `wp-admin/includes/schema.php` installs, plus `<prefix>user_roles` and the active theme's mods,
   minus the database policy's read-protected and never-readable options and the active-plugin
   lists ([`options.rs`](layer3/src/options.rs), one list shared with E4). It boots against a
   `$wpdb` with no connection that is **one object for the process's life** (#46): it serves
   `wp_load_alloptions()` from the snapshot during the boot and answers nothing else. No plugin, no
   mu-plugin and no theme code runs in it. When a worker's snapshot hash differs (a core option
   changed), the supervisor boots a new zygote and the old one finishes its children and exits.
3. **One child per request.** When `wp-settings.php` includes an isolated plugin, the
   `zend_compile_file` wrapper (the place layer 2 sees includes) compiles a stand-in instead
   ([`php/src/layer3/stub.php`](php/src/layer3/stub.php)). The stand-in sends the helper one end of
   a fresh `socketpair` with a hello (slug, file, ABSPATH, table prefix, the snapshot's and the
   config's sha256). The zygote forks a child; the child restricts itself, loads only that plugin,
   and answers with what it registered: every new hook callback (`add_filter`/`add_action`, with
   its priority and accepted args) and shortcode. The stand-in registers a forwarding callback for
   each in the worker; when WordPress fires one, the call (its arguments PHP-serialized) goes to
   the child, which runs the plugin's callback with its output captured and answers with the
   return value, the output and anything the callback registered in turn. At request end the
   worker closes the socket and the child exits: no state carries from one request to the next.
4. **No isolated code in the worker.** Any other include of an isolated plugin's files in a worker
   (another plugin including it, a CLI or CGI process with no helper) is refused, as a missing
   file is, with a line. If the helper can't give a child, the plugin is simply not there for that
   request; it is never loaded in the worker instead.
5. **Attribution.** The child acts as the plugin: `attribution::responsible` (and the database
   caller rule) return `plugin:<slug>` for everything in the child, whatever the stack shows, so
   layer 2's checks there all charge the isolated plugin.

### Limits

| | where | what happens |
|---|---|---|
| **files** | gelada `restrict_self` in the child (Landlock + seccomp) | reads everything but securecore.json, the vault's `from` file and wp-config.php (at ABSPATH and the folder above); writes **only** `layer3.write.<slug>` (not uploads, not cache, not `/tmp`: gelada's own temporary folder is removed before the rules are built); no network (no TCP, no UDP, no new unix socket; the request socket it holds keeps working). With layer 2 active the child's file wrapper also refuses a write outside those folders first, with a line, in every layer 2 mode: `securecore: layer3 plugin:<slug> open write-outside <path>` |
| **timeoutMs** | the worker, per call | each call's wall-clock deadline. Past it the worker logs `layer3 plugin:<slug> call <id> timed out after <ms> ms; child <pid> killed`, asks the helper to `SIGKILL` the child (only the zygote that forked it can, and only before it reaps it, so a pid is never reused), and the plugin's callbacks pass through for the rest of the request. The child's CPU time is also capped at `timeoutMs` (rounded up to whole seconds) for its whole life, a backstop for a loop while the plugin loads |
| **memoryMb** | the child | PHP's `memory_limit`, and the address space above what the child inherited (`RLIMIT_AS`), so native allocations are capped too. A child over it dies; the worker logs `child <pid> ended during call <id>` and the zygote `child <pid> exited with status 255` |

A failed call never fails the page: a filter returns its first argument unchanged, a shortcode
renders empty, an action does nothing.

### Not yet

The first part covers what it proves end to end (`test/ext-layer3.sh`): a plugin that adds content
through filters, actions and shortcodes, on the front end and the dashboard (Hello Dolly). Not yet:

- **The database.** An isolated plugin's queries are refused (`layer3 plugin:<slug> database
  refused …`, once per query text). It sees core's options from the snapshot; its own options read
  as unset. Next: the #42 gateway, the child's queries run by the worker under E4's policy.
- **Request state.** The child does not see the request: no current user, main query, `$post` or
  `$_GET`/`$_POST`/cookies. Next: replay them, as the spike's `setup_request_state` did.
- **Objects across the socket.** Arguments and return values cross PHP-serialized with objects
  replaced by `null` (`WP_Post`, `WP_Query`, …). Filters on strings and arrays work; a filter whose
  value is an object gets `null`. Next: the spike's marshalling (`sandbox/marshal.php`).
- **Salted pluggables and mail.** Nonces, `wp_hash` and auth cookies made in the child use no real
  salt (the helper holds none), and `wp_mail` does not send. Next: forward them to the worker.
- **Admin pages, AJAX and REST of the plugin's own.** Admin menus and pages, `admin-ajax.php`
  handlers and REST routes are registered through hooks whose callbacks need the request state and
  objects above. Activating the plugin from the admin screen includes its file from
  `wp-admin/includes/plugin.php`, which is refused; so does WP-CLI in a PHP with the extension
  loaded (the test stack's WP-CLI container has no extension). Uninstall hooks likewise.
- **Removing hooks.** A plugin that removes a core callback (`remove_action`) does so in its child
  only.
- **Outbound HTTP** from an isolated plugin (no network in the child). Next: forward through the
  worker under E5's hostnames.
- **A loop while the plugin loads** is stopped by the CPU limit, not at `timeoutMs` (the child's
  pid is not known to the worker until it is ready).
- **Drop-ins** (`db.php`, `object-cache.php`) load in the zygote like core.
- **Themes and mu-plugins** can't be isolated yet: `isolate` names plugins.
- **One pool user.** The helper serves the uid of the first worker that asks; a second pool under
  another user gets no children (logged).
- php-fpm only: under the CLI or CGI there is no helper, so an isolated plugin does not load at all.

### Cost

`bench/layer3.sh`: time to first byte of a post that goes through the probe plugin's
`the_content` filter and one shortcode, the probe isolated vs the same probe in the worker,
alternating round by round. On a 4-thread Linux box shared with CI runners (7 rounds × 50
requests): median 74.6 ms in the worker [72.5–76.1] vs 84.4 ms isolated [82.8–87.5], **+9.8 ms**
for one isolated plugin with two calls. That is the snapshot hash, the hand-off, the fork, the
child's sandbox (gelada builds its Landlock rules per child), loading the plugin and two round
trips; the spike's +3–5 ms was the fork alone. Building the sandbox rules once in the zygote and
caching the snapshot hash per worker are the obvious next cuts. A snapshot change costs one
WordPress boot in a new zygote, on the request that brings it.

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
  ports and an invalid file exit 125 at launch with php-fpm never starting. In the container
  there is no `/dev/kvm`, so this is also `auto` falling back to gelada.
- `test/ext-microvm.sh` (a Linux host with KVM, as root; #71; also CI's `microvm` job, which
  fails without KVM): the `layer1.isolation` values (off and gelada; auto gelada behind the #72
  gate; auto falling back and microvm refusing on a config the VM can't express, on an
  unverified root image and on a kernel without Landlock; in the php container without
  `/dev/kvm`, auto falls back and microvm exits 125 without php-fpm running), then the same
  WordPress served from a jailed Firecracker guest: Firecracker as 64000:64000 with no
  supplementary groups, chrooted, in its own network namespace and cgroup; a host socket seeing
  the guest's connections as that uid (`SO_PEERCRED`); the guest's kernel, loopback only, a
  read-only site with writable uploads, layer 2 enforcing and layer 3's child running in the
  guest, the database through MariaDB's socket; the warm-up sending MariaDB nothing; fpm.sock
  0660; `READY=1` to `NOTIFY_SOCKET`; USR1/USR2 not stopping it; a second start message and a
  second launcher refused; the first start making a snapshot and the next restoring it with the
  clock resynced, fresh randomness and the uploads kept; a stale jail link gone; a site change
  making a new snapshot, a larger `--write-disk-mib` growing the uploads disk, a broken snapshot
  falling back to a cold boot, `--no-snapshot`, an orphaned uploads disk refused. `bench [n]` is
  #70's latency comparison and `restore [n]` times the requests after a restore.
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
- `DOCKER_CONTEXT=colima test/ext-db.sh` (after ext-config.sh): a probe plugin sends 15 cases
  through all 18 query routes (mysqli procedural and method, the prepare routes, PDO in exception
  and silent mode, `$wpdb`), on core's connection and its own. In enforce mode its own table and
  option run, and another plugin's table, a core table without a grant, `user_pass`, a `*` over
  users, a protected option, PREPARE, `SET @`, LOAD_FILE, INTO OUTFILE, multi-statement, the
  `/*! */` comment trick and ANSI_QUOTES are refused on every route, with audit lines. In strict
  mode mysqli throws 1142; `select_db` and an unsafe charset are refused; nothing is fatal. With
  grants, the granted table runs and the rest stay refused. A core probe may read `user_pass` but
  not PREPARE. Through core's passthrough helpers the probe's `dbDelta` write of `active_plugins`
  and `user_pass` copy, `maybe_create_table` with a protected write, and `update_option` of a
  protected option are refused; its `wp_schedule_single_event` works, while its own `UPDATE` of
  `cron` is refused. The revert proof: in log mode, with layer 2 off, and with the extension unloaded,
  every refused case runs.
- `DOCKER_CONTEXT=colima test/ext-layer3.sh` (after ext-config.sh): layer 3 with a probe plugin
  (`test/ext/layer3-plugin`, isolated), a neighbour plugin that is not, and Hello Dolly (isolated).
  With layer 3 on, a post renders with the probe's filter and shortcode output, made in a child
  (another pid than the worker's, a fresh one per request); the probe's code does not exist in the
  worker and a stray include of its files is refused; Hello Dolly prints its lyric on the dashboard
  from its child; the helper processes run as www-data with an empty environment; a core option
  change re-boots the helper. The limits: a write outside its folder (logged), reads of
  wp-config.php and securecore.json and a connect to the database are stopped; a loop past
  `timeoutMs` is killed (logged) and too much memory ends the child (logged), while each page still
  renders. With layer 2 off the kernel alone still stops the write and the reads. The revert proof:
  with layer 3 off the probe runs in the worker, every probe case goes through, the loop holds the
  page and the memory probe kills it.
- `DOCKER_CONTEXT=colima bench/layer3.sh` (after ext-config.sh): time to first byte of a post
  through the probe's filter and shortcode, isolated vs in the worker, alternating, 7 rounds.
- `DOCKER_CONTEXT=colima research/db/compat.sh` (after ext-config.sh): Classic Editor, Yoast and
  CF7 in log mode, entries suggested from the log, then enforce mode with them, every refusal
  listed.
- `DOCKER_CONTEXT=colima bench/db.sh` (after research/db/compat.sh): front-page and dashboard p50,
  main's extension against this branch's, same config, 7 rounds.
- `DOCKER_CONTEXT=colima bench/vault.sh` (after ext-config.sh): front-page p50 and a login round,
  7 rounds, with the vault on vs a no-vault config.
- `DOCKER_CONTEXT=colima bench/ext.sh`: front-page p50 with the extension loaded vs not.
- `DOCKER_CONTEXT=colima bench/attribution.sh`: front-page p50 not loaded, loaded with
  attribution logging off, and on.
- `DOCKER_CONTEXT=colima bench/enforce.sh`: front-page p50 with the three plugins, not loaded vs
  loaded in enforce mode.
- `DOCKER_CONTEXT=colima bench/layer1.sh` (after ext-layer1.sh): front-page p50 with the three
  plugins and the extension unloaded, layer 1 off (stock php-fpm) vs on.
