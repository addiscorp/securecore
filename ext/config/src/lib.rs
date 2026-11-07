//! `securecore.json`: the one file that configures SecureCore's three layers
//! (addiscorp/securecore#53).
//!
//! The types here are the single source of truth. serde reads the file with them, and
//! `ext/securecore.schema.json` is generated from them ([`schema_json`]); a test fails if the
//! committed schema drifts. Doc comments on the types become the schema's descriptions.
//!
//! Plain Rust with no PHP dependency: the extension (layers 2 and 3) and the `securecore-fpm`
//! launcher (layer 1, E6) both read the file through [`load`].

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::fs;
use std::num::{NonZeroU16, NonZeroU32};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// SecureCore configuration. Three layers, each enabled independently; all three disabled
/// means SecureCore is off. An invalid file means nothing starts.
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
    /// Folders php-fpm may write, relative to the app root. Everything else is read-only.
    #[serde(default)]
    pub write: Vec<String>,
    /// Paths php-fpm may not read at all, on top of the common secrets SecureCore always denies.
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
    /// Unix sockets php-fpm may connect to.
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    /// The file the secrets are defined in, relative to the app root.
    pub from: String,
    /// The constants SecureCore supplies natively instead of PHP.
    pub secrets: Vec<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<Scope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tables: Option<Scope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Scope>,
    /// Extra access to what core owns, as `<area>:<access>` (e.g. `users:read`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<Vec<String>>,
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
    /// Extra folders an isolated component's child may write, relative to the app root.
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
        config.validate()?;
        Ok(config)
    }

    /// The rules serde can't express. Each one is also in the schema (see [`Layer2`]'s
    /// `if`/`then`), so an editor flags the same files.
    fn validate(&self) -> Result<(), Problem> {
        if self.layer2.enabled && self.layer2.app.is_none() {
            return Err(Problem::Invalid("layer2.enabled is true but layer2.app is missing".into()));
        }
        Ok(())
    }

    /// All three layers disabled: SecureCore is off. A valid configuration.
    pub fn is_off(&self) -> bool {
        !self.layer1.enabled && !self.layer2.enabled && !self.layer3.enabled
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
}

/// Reads, parses and validates the file at `path`.
pub fn load(path: &Path) -> Result<Loaded, LoadError> {
    let err = |problem| LoadError { path: path.to_owned(), problem };
    let bytes = fs::read(path).map_err(|e| err(Problem::Read(e)))?;
    let config = Config::from_slice(&bytes).map_err(err)?;
    Ok(Loaded { path: path.to_owned(), config, sha256: sha256_hex(&bytes) })
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

/// What [`Reloader::poll`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Poll {
    /// Too soon since the last check, or the file is unchanged.
    Unchanged,
    /// A new valid config is live. `layer1_changed`: its `layer1` differs from the one the
    /// process started with, which only a php-fpm restart applies.
    Reloaded { layer1_changed: bool },
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
    stamp: Option<Stamp>,
    interval: Duration,
    next_check: Instant,
    reloads: u64,
    error: Option<String>,
}

impl Reloader {
    /// Loads the file; fails if it can't be loaded (the caller fails closed).
    pub fn start(path: &Path, interval: Duration, now: Instant) -> Result<Reloader, LoadError> {
        // Stamp before reading: a write between the two is then seen by the next poll.
        let stamp = stamp(path).ok();
        let live = load(path)?;
        Ok(Reloader {
            started_layer1: live.config.layer1.clone(),
            live: Arc::new(live),
            stamp,
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
    pub fn restart_needed(&self) -> bool {
        self.live.config.layer1 != self.started_layer1
    }

    pub fn poll(&mut self, now: Instant) -> Poll {
        if now < self.next_check {
            return Poll::Unchanged;
        }
        self.next_check = now + self.interval;
        let path = self.live.path.clone();
        let current = stamp(&path).ok();
        if current.is_some() && current == self.stamp {
            return Poll::Unchanged;
        }
        match load(&path) {
            Ok(loaded) if loaded.sha256 == self.live.sha256 => {
                self.stamp = current;
                self.error = None;
                Poll::Unchanged
            }
            Ok(loaded) => {
                self.stamp = current;
                self.error = None;
                self.reloads += 1;
                self.live = Arc::new(loaded);
                Poll::Reloaded { layer1_changed: self.restart_needed() }
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
