//! `securecore.json`: the one file that configures SecureCore's three layers
//! (addiscorp/securecore#53).
//!
//! The types here are the single source of truth. serde reads the file with them, and
//! `ext/securecore.schema.json` is generated from them ([`schema_json`]); a test fails if the
//! committed schema drifts. Doc comments on the types become the schema's descriptions.
//!
//! Plain Rust with no PHP dependency: the extension (layers 2 and 3) and the `securecore-fpm`
//! launcher (layer 1, E6) both read the file through [`load`].

pub mod dbhost;
pub mod grant;
pub mod salt;
pub mod source;

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::fs;
use std::num::{NonZeroU16, NonZeroU32};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// SecureCore configuration. Three layers, each enabled independently; all three disabled
/// means SecureCore is off. An invalid file means nothing starts. Relative paths are relative to
/// the folder containing this file (the app root, as with composer.json); absolute paths are
/// used as they are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(title = "securecore.json")]
pub struct Config {
    /// Optional pointer to this schema, for editors. Not read by SecureCore.
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub layer1: Layer1,
    pub layer2: Layer2,
    pub layer3: Layer3,
}

/// Layer 1, the outer layer: the `securecore-fpm` launcher starts php-fpm inside gelada
/// (Landlock + seccomp). Knows only paths and ports, so it works for any PHP app. Read once by
/// the launcher: a change needs a php-fpm restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Layer1 {
    pub enabled: bool,
    /// Folders php-fpm may write (relative to the folder containing securecore.json, or
    /// absolute). Everything else is read-only.
    #[serde(default)]
    pub write: Vec<String>,
    /// Paths php-fpm may not read at all, on top of the common secrets gelada always denies
    /// under the launcher's HOME (~/.ssh, ~/.aws, …) (relative to the folder containing
    /// securecore.json, or absolute).
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub network: Network,
}

/// The sockets php-fpm may use. Anything not listed is refused by the kernel.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Network {
    /// TCP ports php-fpm may listen on.
    #[serde(default)]
    pub bind: Vec<Port>,
    /// TCP ports php-fpm may connect to (by port: the kernel can't see hostnames).
    #[serde(default)]
    pub connect: Vec<Port>,
    /// Unix sockets php-fpm may connect to. Not enforceable by securecore-fpm yet: on Linux
    /// gelada can't combine them with TCP ports, nor allow them in place
    /// (addiscorp/securecore#57), so a layer 1 that lists any is refused at launch.
    #[serde(default)]
    pub unix_sockets: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Port {
    pub port: NonZeroU16,
}

/// Layer 2, the extension: engine-level policy inside php-fpm, per component (plugin or
/// theme). Reloaded when the file changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend(
    "if" = { "properties": { "enabled": { "const": true } }, "required": ["enabled"] },
    "then" = { "required": ["app"] }
))]
pub struct Layer2 {
    pub enabled: bool,
    /// The app adapter: where the secrets live, what a component is and what it owns.
    /// Required when layer 2 is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<App>,
    #[serde(default)]
    pub mode: Mode,
    /// Secrets that never exist as PHP-visible values (E3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<Vault>,
    /// Rules for the app's own code (WordPress core).
    #[serde(default)]
    pub core: Core,
    /// Rules for every component without an entry of its own, and the base each entry in
    /// `components` overrides field by field.
    #[serde(default)]
    pub default: Rules,
    /// Per-component rules, keyed by the component's slug (plugin or theme folder name).
    #[serde(default)]
    pub components: BTreeMap<String, Rules>,
}

/// An app adapter for layer 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum App {
    Wordpress,
}

impl App {
    pub fn as_str(self) -> &'static str {
        match self {
            App::Wordpress => "wordpress",
        }
    }
}

/// `enforce` blocks; `log` reports what would be blocked and blocks nothing; `off` does
/// neither.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Enforce,
    Log,
    Off,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Enforce => "enforce",
            Mode::Log => "log",
            Mode::Off => "off",
        }
    }
}

/// The vault (E3): secrets PHP never sees. The extension reads every real value once, at module
/// startup in the php-fpm master before it forks, and keeps it in its own memory; PHP sees a
/// placeholder (`securecore-vault:<NAME>`) in the constant, the environment, `$_ENV`,
/// `$_SERVER` and `getenv()`. The extension puts the real value back only inside the database
/// connect calls and the salted functions (`wp_salt`, `wp_hash`). Read at startup only: a change
/// needs a php-fpm restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    /// Where a secret listed by name alone gets its real value. Required when any entry in
    /// `secrets` is a bare name; a secret with `env` never reads it. When set, the file is also
    /// protected: no PHP code may read or write it (wp-config.php may still be included).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Source>,
    /// The constants SecureCore supplies natively instead of PHP. A bare name (`"AUTH_KEY"`)
    /// takes its value from `from`; `{"name": …, "env": …}` takes it from that environment
    /// variable of the php-fpm master.
    pub secrets: Vec<Secret>,
    /// The database host the DB password may be sent to. The real password is restored only on a
    /// connection whose host matches this (so a component can't point a connect at its own server
    /// and collect the password). Normally left unset: the extension reads it from WordPress's
    /// `DB_HOST` constant, the way WordPress does. Set it only when there is no such constant to
    /// read; no host is ever guessed, so an unknown host means the swap is refused.
    #[serde(rename = "dbHost", default, skip_serializing_if = "Option::is_none")]
    pub db_host: Option<String>,
}

/// Where bare-named secrets come from. Exactly one key, so the source is always stated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum Source {
    /// Read the secret from this wp-config.php (relative to the folder containing securecore.json,
    /// or absolute). Safe only for the usual `define('NAME', getenv('NAME'))` form, where the
    /// value is an expression: opcache leaves the `define()` call intact, so the extension masks
    /// it. A secret written as a bare string **literal** (`define('NAME', 'secret')`) is NOT
    /// hidden — opcache's optimizer inlines it to a compile-time `DECLARE_CONST`, which the
    /// extension cannot intercept, and the plaintext stays in opcache's shared memory. For a
    /// hardcoded secret, use `vaultFile` instead.
    WpConfig(String),
    /// A vault file: a JSON object of `"NAME": "value"` strings, outside the app root, owned by
    /// the user that starts php-fpm (root) and readable by it alone (mode 0400 or 0600). The
    /// recommended source: php-fpm's workers can't open it at all.
    VaultFile(String),
}

impl Source {
    /// The file's path as written in the config.
    pub fn path(&self) -> &str {
        match self {
            Source::WpConfig(p) | Source::VaultFile(p) => p,
        }
    }
}

/// One secret: a constant name, or a constant name and the environment variable holding it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Secret {
    /// A constant whose value comes from `vault.from`.
    Name(String),
    /// A constant whose value comes from an environment variable.
    Env(EnvSecret),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvSecret {
    /// The constant (e.g. `DB_PASSWORD`).
    pub name: String,
    /// The environment variable holding the real value (e.g. `WORDPRESS_DB_PASSWORD`). It is
    /// replaced by the placeholder before PHP runs.
    pub env: String,
}

impl Secret {
    pub fn name(&self) -> &str {
        match self {
            Secret::Name(n) => n,
            Secret::Env(e) => &e.name,
        }
    }

    pub fn env(&self) -> Option<&str> {
        match self {
            Secret::Name(_) => None,
            Secret::Env(e) => Some(&e.env),
        }
    }
}

impl Vault {
    /// The rules serde can't express: names are PHP constant names and unique, env names are
    /// non-empty and free of `=`, and a bare name has a `from` to come from.
    fn validate(&self) -> Result<(), String> {
        let mut seen = std::collections::BTreeSet::new();
        for s in &self.secrets {
            let name = s.name();
            let ok = name.bytes().next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
            if !ok {
                return Err(format!("layer2.vault.secrets: {name:?} is not a constant name"));
            }
            if !seen.insert(name) {
                return Err(format!("layer2.vault.secrets: {name} is listed twice"));
            }
            if let Some(env) = s.env()
                && (env.is_empty() || env.contains('=') || env.contains('\0'))
            {
                return Err(format!("layer2.vault.secrets: {name}: env {env:?} is not an environment variable name"));
            }
            if s.env().is_none() && self.from.is_none() {
                return Err(format!("layer2.vault.secrets: {name} has no env and layer2.vault.from is not set; say where it comes from"));
            }
        }
        if self.from.as_ref().is_some_and(|f| f.path().is_empty()) {
            return Err("layer2.vault.from: the path is empty".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Core {
    /// Hostnames core may reach over HTTP.
    #[serde(default)]
    pub hosts: Vec<String>,
}

/// What a component may touch. A field left out inherits from `default`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    /// Hostnames the component may reach over HTTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<String>>,
    /// Extra file access, on top of what a component always has (read anywhere under the app
    /// root except the protected files; write to uploads and cache). Unset inherits `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<Files>,
    /// Whether the component may run external programs (exec, shell_exec, system, passthru,
    /// popen, proc_open, pcntl_exec, and mail when it shells out). Default: no. Unset inherits
    /// `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<bool>,
    /// The database tables the component may use (E4). Always its own: the tables named after
    /// its slug (`<prefix><slug>` and `<prefix><slug>_*`, `-` read as `_`), never one of core's.
    /// A list adds glob patterns (`*`, `?`) matched against the table name without the site's
    /// table prefix, e.g. `["wc_*", "woocommerce_*"]`. Core's tables are reached only through
    /// `grants`. Unset inherits `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tables: Option<Scope>,
    /// The options (rows of core's `options` table) the component may read and write (E4).
    /// Always its own: names equal to its slug or starting with `<slug>_` / `<slug>-` (transients
    /// included). A list adds glob patterns. The protected options (siteurl, home,
    /// active_plugins, the role capabilities and the rest of the README's list) are never
    /// writable; listing a read-protected one makes it readable only. Unset inherits `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Scope>,
    /// Extra access to what core owns, as `<area>:read` or `<area>:write` (`write` includes
    /// `read`). Areas: `users`, `capabilities`, `posts`, `comments`, `terms`, `links`, `options`,
    /// `network`. E.g. `users:read`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<Vec<String>>,
}

/// Extra file access for a component (E2b). A component may always read anywhere under the app
/// root except the protected files (the vault's `from` file and `securecore.json`), and write
/// to the uploads and cache folders; these lists add to that. Each entry is a path (a file or a
/// folder) relative to the folder containing securecore.json, or absolute; a folder entry
/// covers everything under it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Files {
    /// Paths outside the app root the component may also read (reads under the root need no
    /// entry).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read: Vec<String>,
    /// Paths the component may also write, on top of uploads and cache.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write: Vec<String>,
}

/// `"own"` (what the app adapter says the component owns) or an explicit list of patterns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Scope {
    Keyword(ScopeKeyword),
    Patterns(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ScopeKeyword {
    Own,
}

/// Layer 3, the clean child: calls into an isolated component run in a forked child under
/// gelada. Lives inside the extension. Reloaded when the file changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Layer3 {
    pub enabled: bool,
    /// Components (slugs) whose calls run in an isolated child.
    #[serde(default)]
    pub isolate: Vec<String>,
    #[serde(default)]
    pub limits: Limits,
    /// Extra folders an isolated component's child may write (relative to the folder
    /// containing securecore.json, or absolute).
    #[serde(default)]
    pub write: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Limits {
    /// Wall-clock limit for one isolated call.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: NonZeroU32,
    /// Memory limit for one isolated child.
    #[serde(default = "default_memory_mb")]
    pub memory_mb: NonZeroU32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { timeout_ms: default_timeout_ms(), memory_mb: default_memory_mb() }
    }
}

impl Layer2 {
    /// The vault in force (E3): `vault`, when layer 2 is enabled. The vault isn't a policy, so
    /// `mode` does not gate it; the real values are read once at startup regardless.
    pub fn started_vault_ref(&self) -> Option<&Vault> {
        self.enabled.then_some(self.vault.as_ref()).flatten()
    }
}

fn default_timeout_ms() -> NonZeroU32 {
    NonZeroU32::new(5000).unwrap_or(NonZeroU32::MIN)
}

fn default_memory_mb() -> NonZeroU32 {
    NonZeroU32::new(256).unwrap_or(NonZeroU32::MIN)
}

impl Config {
    /// Parses and validates a file's bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Config, Problem> {
        let config: Config = serde_json::from_slice(bytes).map_err(Problem::Parse)?;
        // serde's derived structs also accept a JSON array (fields by position); the schema
        // says object. Compare the input with the typed value's own serialization, where every
        // struct is an object: the parser then accepts exactly what the schema accepts.
        let input: serde_json::Value = serde_json::from_slice(bytes).map_err(Problem::Parse)?;
        let typed = serde_json::to_value(&config).map_err(Problem::Parse)?;
        objects_are_objects(&typed, &input, &mut String::new())?;
        config.validate()?;
        Ok(config)
    }

    /// The rules serde can't express. Each one is also in the schema (see [`Layer2`]'s
    /// `if`/`then`), so an editor flags the same files.
    fn validate(&self) -> Result<(), Problem> {
        if self.layer2.enabled && self.layer2.app.is_none() {
            return Err(Problem::Invalid("layer2.enabled is true but layer2.app is missing".into()));
        }
        if let Some(vault) = &self.layer2.vault {
            vault.validate().map_err(Problem::Invalid)?;
        }
        grant::validate(&self.layer2).map_err(Problem::Invalid)?;
        Ok(())
    }

    /// All three layers disabled: SecureCore is off. A valid configuration.
    pub fn is_off(&self) -> bool {
        !self.layer1.enabled && !self.layer2.enabled && !self.layer3.enabled
    }
}

/// Fails where `typed` (the parsed config, serialized) has an object and `input` (the file) has
/// an array: a struct written in serde's positional array form. `at` is the JSON path so far.
fn objects_are_objects(typed: &serde_json::Value, input: &serde_json::Value, at: &mut String) -> Result<(), Problem> {
    use serde_json::Value;
    match (typed, input) {
        (Value::Object(_), Value::Array(_)) => {
            let place = if at.is_empty() { "the top level" } else { at.as_str() };
            Err(Problem::Invalid(format!("{place} is an array; it must be an object")))
        }
        (Value::Object(t), Value::Object(i)) => {
            for (key, tv) in t {
                if let Some(iv) = i.get(key) {
                    let len = at.len();
                    if !at.is_empty() {
                        at.push('.');
                    }
                    at.push_str(key);
                    objects_are_objects(tv, iv, at)?;
                    at.truncate(len);
                }
            }
            Ok(())
        }
        (Value::Array(t), Value::Array(i)) => {
            for (n, (tv, iv)) in t.iter().zip(i).enumerate() {
                let len = at.len();
                let _ = write!(at, "[{n}]");
                objects_are_objects(tv, iv, at)?;
                at.truncate(len);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// What is wrong with a config file, without the path ([`LoadError`] adds it).
#[derive(Debug)]
pub enum Problem {
    Read(std::io::Error),
    Parse(serde_json::Error),
    Invalid(String),
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Problem::Read(e) => write!(f, "cannot read it: {e}"),
            Problem::Parse(e) => write!(f, "invalid: {e}"),
            Problem::Invalid(e) => write!(f, "invalid: {e}"),
        }
    }
}

/// A config file that could not be loaded. Its message names the file and the problem.
#[derive(Debug)]
pub struct LoadError {
    pub path: PathBuf,
    pub problem: Problem,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.problem)
    }
}

impl std::error::Error for LoadError {}

/// A loaded, valid config and the bytes it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded {
    pub path: PathBuf,
    pub config: Config,
    /// Lowercase hex sha256 of the file's bytes.
    pub sha256: String,
    /// The app root: the folder containing the file, with symlinks resolved. The file itself
    /// may be a symlink; the root is where it sits, not where it points.
    pub root: PathBuf,
}

impl Loaded {
    /// A path from the config: relative paths are relative to [`Loaded::root`], absolute ones
    /// are used as they are.
    pub fn resolve(&self, path: &str) -> PathBuf {
        resolve_against(&self.root, path)
    }
}

/// `path` relative to `root` (or as is, if absolute).
pub fn resolve_against(root: &Path, path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() { p.to_owned() } else { root.join(p) }
}

/// The folder containing `path`, absolute and with symlinks resolved where it exists.
fn root_of(path: &Path) -> PathBuf {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_owned(),
        _ => PathBuf::from("."),
    };
    fs::canonicalize(&parent)
        .or_else(|_| std::env::current_dir().map(|cwd| cwd.join(&parent)))
        .unwrap_or(parent)
}

/// Reads, parses and validates the file at `path`.
pub fn load(path: &Path) -> Result<Loaded, LoadError> {
    let err = |problem| LoadError { path: path.to_owned(), problem };
    let bytes = fs::read(path).map_err(|e| err(Problem::Read(e)))?;
    let config = Config::from_slice(&bytes).map_err(err)?;
    Ok(Loaded { path: path.to_owned(), config, sha256: sha256_hex(&bytes), root: root_of(path) })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for b in Sha256::digest(bytes) {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The JSON Schema for [`Config`], as committed in `ext/securecore.schema.json`.
pub fn schema_json() -> String {
    let schema = schemars::schema_for!(Config);
    let mut out = serde_json::to_string_pretty(&schema).unwrap_or_default();
    out.push('\n');
    out
}

/// Identifies a version of the file on disk without reading it: a change to any of these
/// means the file may have changed, and only then is it read and hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

/// How close to the moment it was taken a stamp's ctime may be before the stamp stops telling two
/// writes apart. File timestamps come from the kernel's coarse clock (a few ms), and some
/// filesystems keep whole seconds or two, so two writes of the same size inside one tick leave
/// the same (inode, size, mtime, ctime). Git calls such an entry "racily clean".
const RACY: Duration = Duration::from_secs(2);

/// A stamp taken at `at` can't vouch for the file's bytes when the file changed (ctime) within
/// [`RACY`] of `at`: a later write in the same tick would leave the stamp unchanged.
fn racy(stamp: &Stamp, at: SystemTime) -> bool {
    let (secs, nsec) = stamp.ctime;
    let (Ok(secs), Ok(nsec)) = (u64::try_from(secs), u32::try_from(nsec)) else { return true };
    let ctime = UNIX_EPOCH + Duration::new(secs, nsec);
    ctime + RACY > at
}

fn stamp(path: &Path) -> std::io::Result<Stamp> {
    let m = fs::metadata(path)?;
    Ok(Stamp {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        mtime: (m.mtime(), m.mtime_nsec()),
        ctime: (m.ctime(), m.ctime_nsec()),
    })
}

/// The vault a config puts in force at startup: `layer2.vault`, when layer 2 is enabled.
pub fn started_vault(config: &Config) -> Option<Vault> {
    config.layer2.enabled.then(|| config.layer2.vault.clone()).flatten()
}

/// What [`Reloader::poll`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Poll {
    /// Too soon since the last check, or the file is unchanged.
    Unchanged,
    /// A new valid config is live. `layer1_changed` / `vault_changed`: its `layer1` /
    /// `layer2.vault` differs from the one the process started with, which only a php-fpm
    /// restart applies.
    Reloaded { layer1_changed: bool, vault_changed: bool },
    /// The file changed but can't be loaded. The last valid config stays live (never off);
    /// reported once per distinct problem.
    Rejected(String),
}

/// Keeps the live config in step with the file, cheaply: at most one `stat` per `interval`,
/// and a read + hash + parse only when the stat changes.
#[derive(Debug)]
pub struct Reloader {
    live: Arc<Loaded>,
    /// The `layer1` the process started with.
    started_layer1: Layer1,
    /// The vault the process started with (E3): `layer2.vault` when layer 2 was enabled. The
    /// real values are read once at startup, so this, not the live file, is the vault in force.
    started_vault: Option<Vault>,
    stamp: Option<Stamp>,
    /// When `stamp` was taken (wall clock, which file times use): see [`racy`].
    stamped_at: SystemTime,
    interval: Duration,
    next_check: Instant,
    reloads: u64,
    error: Option<String>,
}

impl Reloader {
    /// Loads the file; fails if it can't be loaded (the caller fails closed).
    pub fn start(path: &Path, interval: Duration, now: Instant) -> Result<Reloader, LoadError> {
        // Stamp before reading: a write between the two is then seen by the next poll.
        let stamped_at = SystemTime::now();
        let stamp = stamp(path).ok();
        let live = load(path)?;
        Ok(Reloader {
            started_layer1: live.config.layer1.clone(),
            started_vault: started_vault(&live.config),
            live: Arc::new(live),
            stamp,
            stamped_at,
            interval,
            next_check: now + interval,
            reloads: 0,
            error: None,
        })
    }

    pub fn live(&self) -> &Arc<Loaded> {
        &self.live
    }

    pub fn reloads(&self) -> u64 {
        self.reloads
    }

    /// The problem with the file on disk, while it can't be loaded.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// The file's `layer1` differs from the one the process started with.
    pub fn layer1_changed(&self) -> bool {
        self.live.config.layer1 != self.started_layer1
    }

    /// The file's vault differs from the one the process started with.
    pub fn vault_changed(&self) -> bool {
        started_vault(&self.live.config) != self.started_vault
    }

    /// Something in the file applies only after a php-fpm restart: `layer1` or the vault.
    pub fn restart_needed(&self) -> bool {
        self.layer1_changed() || self.vault_changed()
    }

    /// The vault in force: the one the process started with (see [`Vault`]).
    pub fn started_vault(&self) -> Option<&Vault> {
        self.started_vault.as_ref()
    }

    pub fn poll(&mut self, now: Instant) -> Poll {
        if now < self.next_check {
            return Poll::Unchanged;
        }
        self.next_check = now + self.interval;
        let path = self.live.path.clone();
        let at = SystemTime::now();
        let current = stamp(&path).ok();
        // An unchanged stamp means an unchanged file, unless it is racy (the file changed within
        // a timestamp tick or two of when the stamp was taken): then compare the bytes' sha256.
        // That costs a read only in the seconds right after an edit.
        if let Some(s) = current
            && current == self.stamp
            && !racy(&s, self.stamped_at)
        {
            return Poll::Unchanged;
        }
        match load(&path) {
            Ok(loaded) if loaded.sha256 == self.live.sha256 => {
                self.stamp = current;
                self.stamped_at = at;
                self.error = None;
                Poll::Unchanged
            }
            Ok(loaded) => {
                self.stamp = current;
                self.stamped_at = at;
                self.error = None;
                self.reloads += 1;
                self.live = Arc::new(loaded);
                Poll::Reloaded { layer1_changed: self.layer1_changed(), vault_changed: self.vault_changed() }
            }
            Err(e) => {
                // Keep the stamp unchanged so the file is retried until it is fixed, but
                // report each distinct problem once.
                let message = e.to_string();
                if self.error.as_deref() == Some(&message) {
                    return Poll::Unchanged;
                }
                self.error = Some(message.clone());
                Poll::Rejected(message)
            }
        }
    }
}

#[cfg(test)]
mod tests;
