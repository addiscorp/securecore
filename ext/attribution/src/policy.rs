//! The layer-2 file and process policy (addiscorp/securecore#53, phase E2b): what a component
//! may read, write and execute. Plain Rust with no PHP, so every rule is unit-tested here; the
//! extension (`securecore-php`) supplies the inputs and carries out the decision (block in
//! `enforce`, log in `log`).
//!
//! The rules, from #55's measurement (`component` attribution, which charges the caller):
//!
//! - **Core is unrestricted.** Only a *component* (plugin, mu-plugin or theme) is checked.
//! - **read:** anything under the app root, except the protected files (the vault's `from`
//!   file and `securecore.json`). Outside the root, only what the component's `files.read`
//!   lists. (Reads under the root are open because a shared library or a core API routinely
//!   reads another component's files on a component's behalf; the secrets live in the vault and
//!   the two protected files, which stay closed.)
//! - **write:** the uploads and cache folders, plus what the component's `files.write` lists.
//!   Never a protected file.
//! - **exec:** refused unless the component's `exec` is true.

use std::path::{Path, PathBuf};

use securecore_config::{Layer2, Mode, resolve_against};

use crate::{Component, real_path};

/// The kind of access a file or process operation needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Read,
    Write,
    Exec,
}

/// A policy decision. `Refuse` carries the rule that refused, the token in the audit line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Refuse(&'static str),
}

impl Decision {
    pub fn is_allowed(self) -> bool {
        self == Decision::Allow
    }

    /// The rule token, or `""` when allowed.
    pub fn rule(self) -> &'static str {
        match self {
            Decision::Allow => "",
            Decision::Refuse(r) => r,
        }
    }
}

/// What one component may do beyond the baseline every component has: extra read and write
/// roots (absolute, resolved as far as they exist) and whether it may run programs. Built from
/// the layer-2 rules by [`access_for`]; `None` from there means "not a restricted component"
/// (core, or code outside the root), which the caller lets through.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Access {
    pub read: Vec<PathBuf>,
    pub write: Vec<PathBuf>,
    pub exec: bool,
}

/// The component's effective access, or `None` when layer 2 does not restrict this caller: when
/// the component is core or outside the root, or layer 2 is disabled or in `off` mode. The
/// effective rules are `default` with the component's own entry laid over it, field by field
/// (the same inheritance as the other per-component rules).
pub fn access_for(l2: &Layer2, root: &Path, component: &Component) -> Option<Access> {
    if !l2.enabled || l2.mode == Mode::Off {
        return None;
    }
    let slug = match component {
        Component::Plugin(s) | Component::MuPlugin(s) | Component::Theme(s) => s,
        Component::Core | Component::Outside => return None,
    };
    let own = l2.components.get(slug);
    let files = own.and_then(|r| r.files.as_ref()).or(l2.default.files.as_ref());
    let exec = own.and_then(|r| r.exec).or(l2.default.exec).unwrap_or(false);
    let resolve = |list: &[String]| list.iter().map(|p| real_path(&resolve_against(root, p))).collect();
    Some(Access {
        read: files.map(|f| resolve(&f.read)).unwrap_or_default(),
        write: files.map(|f| resolve(&f.write)).unwrap_or_default(),
        exec,
    })
}

/// The baseline every component shares: the site's root, its uploads and cache folders, and
/// the protected files. One per site; cheap to make per request from the live config. All paths
/// are absolute and resolved ([`real_path`]), the same way an operation's path is resolved
/// before [`Policy::decide`], so the prefix tests mean what they say across symlinks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    root: PathBuf,
    uploads: PathBuf,
    cache: PathBuf,
    /// Paths a component may never read or write: the vault's `from` file and `securecore.json`.
    protected: Vec<PathBuf>,
}

impl Policy {
    pub fn new(root: PathBuf, uploads: PathBuf, cache: PathBuf, protected: Vec<PathBuf>) -> Policy {
        Policy { root, uploads, cache, protected }
    }

    fn is_protected(&self, path: &Path) -> bool {
        self.protected.iter().any(|p| p == path)
    }

    /// Whether `access` lets the component perform `op` on `path`. `path` must be absolute and
    /// resolved the way the operation will open it (see [`real_path`]); for `Op::Exec` it is the
    /// program or command, used only for the audit line.
    pub fn decide(&self, access: &Access, op: Op, path: &Path) -> Decision {
        match op {
            Op::Exec => {
                if access.exec {
                    Decision::Allow
                } else {
                    Decision::Refuse("exec")
                }
            }
            Op::Read => {
                if self.is_protected(path) {
                    Decision::Refuse("read-protected")
                } else if under_or_eq(path, &self.root) || access.read.iter().any(|r| under_or_eq(path, r)) {
                    Decision::Allow
                } else {
                    Decision::Refuse("read-outside-root")
                }
            }
            Op::Write => {
                let writable = under_or_eq(path, &self.uploads)
                    || under_or_eq(path, &self.cache)
                    || access.write.iter().any(|w| under_or_eq(path, w));
                if self.is_protected(path) {
                    Decision::Refuse("write-protected")
                } else if writable {
                    Decision::Allow
                } else {
                    Decision::Refuse("write")
                }
            }
        }
    }
}

/// `path` is `base` or sits under it. Component-wise, so `/a/bc` is not under `/a/b`.
fn under_or_eq(path: &Path, base: &Path) -> bool {
    path == base || path.starts_with(base)
}

#[cfg(test)]
mod tests;
