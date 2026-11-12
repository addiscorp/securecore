//! The microVM's guest is the host's own PHP (addiscorp/securecore#101, Sami 12 Nov): the
//! launcher captures the host's `php-fpm`, every extension in its extension folder, the
//! libraries they all load (the dynamic loader's own `--list`), the programs PHP runs
//! (`/bin/sh`, sendmail, ImageMagick, ghostscript) when the host has them, and the data they
//! read (CA certificates, ImageMagick's modules…); and, apart from those, php.ini, its scan
//! folder and php-fpm's config with its pools. A small fixed SecureCore base (the guest's init,
//! the preload, the warm-up script: `rootfs.ext4`, checked against the installer's record) goes
//! under it.
//!
//! **Everything captured is validated, in case the host is compromised:**
//! - a binary, library or data file a package installed must match the checksum its package
//!   manager recorded ([`crate::pkgdb`]: dpkg, rpm or apk);
//! - any file must be root's and writable by no one else (its group may write only when it is
//!   root's group), in folders that are the same, all the way from `/`;
//! - a link on the way to a binary or library is allowed at the top (`/lib64` → `usr/lib64`, a
//!   merged `/usr`) or when a package installed it; any other link is refused (an unpackaged file
//!   is never reached through one). In data folders and configs a link is followed, and what it
//!   points at is checked as a file of its own;
//! - configs (php.ini, the scan folder, php-fpm's config and its includes) follow the same
//!   ownership rules, are parsed, and are refused when they load native code from outside the
//!   captured set or run a PHP file outside the app root ([`crate::phpconf::code_refusal`]);
//! - each file's bytes are hashed as they are read, and the copy that goes into the guest's disk
//!   is hashed again: what boots is what was checked.
//!
//! Any failure is a [`Refused`] naming the file, so `auto` falls back to gelada with it and
//! `microvm` exits 125 with it. A root-only manifest (`capture-manifest.json`) records each
//! file's path, owner, mode, sha256 and source; changes since the last start are logged.
//!
//! The PHP layer and the config layer are separate disks, each cached by the sha256 of what it
//! holds: a php.ini edit rebuilds only the (small) config disk. A start where nothing changed
//! reuses the last capture whole: every path it read is stat'ed again (device, inode, size,
//! mtime, ctime, mode, owner), and any difference means a full capture.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::phpconf::{self, FpmConfig, Setting};
use crate::pkgdb::{self, PkgDb, Verdict};

/// The PATH the capture searches (php-fpm, the helpers) and the guest's php-fpm gets.
pub const PHP_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// The programs PHP itself runs, captured when the host has them: the shell (exec, popen,
/// proc_open), sendmail (mail()), ImageMagick and ghostscript (WordPress's image editors and PDF
/// previews).
pub const HELPERS: [&str; 5] = ["/bin/sh", "sendmail", "convert", "magick", "gs"];
/// Data the libraries read by path, captured when present (never anything under
/// `/etc/ssl/private`, never `/etc/shadow`).
pub const DATA_FILES: [&str; 10] = [
    "/etc/hostname",
    "/etc/hosts",
    "/etc/ld.so.cache",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/localtime",
    "/etc/ssl/openssl.cnf",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
];
/// Data folders captured whole when present (links in them followed and checked).
/// (glibc's gconv modules aren't: PHP's iconv then has glibc's built-in charsets only.)
pub const DATA_TREES: [&str; 2] = ["/etc/ssl/certs", "/usr/share/ca-certificates"];
/// The base's top-level folders a captured tree can be mounted on (`/sc/php/<top>` → `/<top>`).
pub const TOPS: [&str; 14] = ["bin", "etc", "home", "lib", "lib32", "lib64", "libx32", "nix", "opt", "root", "sbin", "srv", "usr", "var"];
/// Never captured, whatever links point there.
const NEVER: [&str; 4] = ["/etc/ssl/private", "/etc/shadow", "/etc/gshadow", "/root/.ssh"];
/// The largest file captured.
const MAX_FILE: u64 = 1 << 30;
/// The largest config file read.
const MAX_CONFIG: u64 = 1 << 20;

/// What the capture refused, and the file it is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub file: String,
    pub why: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the host's PHP can't be captured: {}: {}", self.file, self.why)
    }
}

fn refused(file: impl Into<String>, why: impl Into<String>) -> Refused {
    Refused { file: file.into(), why: why.into() }
}

/// One entry of the PHP layer, at its path on the host (which is its path in the guest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Item {
    File {
        path: String,
        /// Where the bytes are read from on the host: `path` itself, or what a link in a data
        /// folder points at.
        from: String,
        mode: u32,
        uid: u32,
        gid: u32,
        size: u64,
        sha256: String,
        source: String,
    },
    Link {
        path: String,
        target: String,
        source: String,
    },
    Dir {
        path: String,
        mode: u32,
    },
}

impl Item {
    pub fn path(&self) -> &str {
        match self {
            Item::File { path, .. } | Item::Link { path, .. } | Item::Dir { path, .. } => path,
        }
    }
}

/// One config file as the guest's config disk gets it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfFile {
    /// Its path on the host.
    pub path: String,
    pub text: String,
    pub sha256: String,
    /// It loads the SecureCore extension (left out for `sc.ext=0`).
    pub securecore: bool,
}

/// The host's PHP, captured and validated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capture {
    /// php-fpm's path (the guest runs it there).
    pub fpm: String,
    pub php_version: String,
    pub ext_dir: String,
    pub ini: Option<ConfFile>,
    /// The scan folder's files, in PHP's order.
    pub conf_d: Vec<ConfFile>,
    /// The scan folders, as the host has them: the guest binds the config layer's there too,
    /// for a PHP that reads its compiled-in ones (the CLI layer 3's helper runs).
    pub scan_dirs: Vec<String>,
    /// php-fpm's config files (the main one and its includes), for the manifest.
    pub fpm_files: Vec<ConfFile>,
    pub pools: Vec<phpconf::Pool>,
    pub items: Vec<Item>,
    pub helpers: Vec<String>,
    pub missing_helpers: Vec<String>,
    /// Where PHP's settings say `localhost` reaches MySQL.
    pub mysql_sockets: Vec<String>,
    /// The package manager whose records the binaries were checked against.
    pub pkg: String,
    /// The PHP layer's key: the sha256 of every item.
    pub php_key: String,
    /// Every path the capture read, with its stat stamp (`-` for one it found absent).
    pub watch: Vec<(String, String)>,
    /// What the capture was asked (php-fpm, its args, the scan folder from the environment).
    pub asked: String,
}

/// What to capture.
#[derive(Debug, Clone)]
pub struct Request {
    /// The root the host's PHP is under: `/` on a host; the stack's php container's root in the
    /// tests (`--php-root /proc/<pid>/root`).
    pub root: PathBuf,
    /// `--php-fpm`: a path, or a name looked up on [`PHP_PATH`].
    pub php_fpm: String,
    /// php-fpm's own arguments (`-y`/`--fpm-config`, `-c`/`--php-ini`, `-p`/`--prefix`).
    pub fpm_args: Vec<String>,
    /// The launcher's `PHP_INI_SCAN_DIR`, which php-fpm on the host would read.
    pub scan_dir_env: Option<String>,
    /// The app root as the guest sees it: a PHP file that runs at every request must be there.
    pub app_root: String,
    /// The installer's record of the unpackaged files' sha256s (Sami: trust on first use, root's
    /// alone): an unpackaged file must match it. Absent: this capture writes it.
    pub record: Option<PathBuf>,
}

/// Where the installer records the unpackaged files' sha256s.
pub const DEFAULT_RECORD: &str = "/var/lib/securecore/unpackaged.json";

/// The record's entries: path → sha256, for every captured file no package's checksum covers,
/// but what lives in `/etc` (a host's own settings and data, `/etc/hostname`, `/etc/hosts`,
/// generated certificate bundles: held to the ownership rules, as configs are, since they differ
/// from host to host and change in normal use).
pub fn unpackaged(items: &[Item]) -> BTreeMap<String, String> {
    items
        .iter()
        .filter_map(|i| match i {
            Item::File { path, sha256, source, .. } if (source.starts_with("unpackaged") || source.contains("no checksum")) && !path.starts_with("/etc/") => {
                Some((path.clone(), sha256.clone()))
            }
            _ => None,
        })
        .collect()
}

/// Writes the record (root's, 0600), with the folder above it root's 0700 when it makes it.
pub fn write_record(path: &Path, items: &[Item]) -> Result<usize, Refused> {
    let at = |e: io::Error| refused(path.display().to_string(), e.to_string());
    if let Some(d) = path.parent()
        && !d.exists()
    {
        fs::create_dir_all(d).map_err(at)?;
        fs::set_permissions(d, fs::Permissions::from_mode(0o700)).map_err(at)?;
    }
    let map = unpackaged(items);
    write_private(path, serde_json::to_vec_pretty(&map).unwrap_or_default().as_slice()).map_err(at)?;
    Ok(map.len())
}

/// Every unpackaged file against the record: one it doesn't hold, or whose bytes differ, is
/// refused, naming the file. `Ok(false)`: there was no record (the caller writes one).
pub fn check_record(path: &Path, items: &[Item]) -> Result<bool, Refused> {
    let text = match fs::read(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(refused(path.display().to_string(), e.to_string())),
    };
    let m = fs::metadata(path).map_err(|e| refused(path.display().to_string(), e.to_string()))?;
    if m.uid() != 0 || m.mode() & 0o077 != 0 {
        return Err(refused(path.display().to_string(), owner_why(&m, "the install's record of unpackaged files (it must be root's alone, 0600)")));
    }
    let rec: BTreeMap<String, String> = serde_json::from_slice(&text).map_err(|e| refused(path.display().to_string(), e.to_string()))?;
    for (p, sha) in unpackaged(items) {
        match rec.get(&p) {
            Some(want) if *want == sha => {}
            Some(want) => {
                return Err(refused(&p, format!("its sha256 is {sha}, not the {want} recorded at install in {}: it changed since (run the installer again if that was an upgrade)", path.display())));
            }
            None => {
                return Err(refused(&p, format!("no package installed it and it isn't in the install's record ({}): run the installer again to record it", path.display())));
            }
        }
    }
    Ok(true)
}

impl Request {
    fn asked(&self) -> String {
        format!("root {} php-fpm {} args {:?} scan {:?} app {} record {:?}", self.root.display(), self.php_fpm, self.fpm_args, self.scan_dir_env, self.app_root, self.record)
    }

    fn arg(&self, short: &str, long: &str) -> Option<String> {
        let mut it = self.fpm_args.iter();
        while let Some(a) = it.next() {
            if a == short || a == long {
                return it.next().cloned();
            }
            if let Some(v) = a.strip_prefix(&format!("{long}=")) {
                return Some(v.to_owned());
            }
        }
        None
    }
}

/// A stat stamp: what changes when a file's bytes, owner, mode or identity do.
fn stamp(m: &fs::Metadata) -> String {
    format!("{} {} {} {}.{} {}.{} {:o} {}:{}", m.dev(), m.ino(), m.size(), m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec(), m.mode(), m.uid(), m.gid())
}

/// A folder only root may change: root's, writable by no one else (its group only if root's).
pub fn dir_ok(m: &fs::Metadata) -> bool {
    m.uid() == 0 && m.mode() & 0o002 == 0 && (m.mode() & 0o020 == 0 || m.gid() == 0)
}

/// A file only root may change: the same rule.
pub fn file_ok(m: &fs::Metadata) -> bool {
    dir_ok(m)
}

fn owner_why(m: &fs::Metadata, what: &str) -> String {
    format!(
        "{what} is owned by {}:{} with mode {:o}; everything captured must be root's and writable by no one else",
        m.uid(),
        m.gid(),
        m.mode() & 0o7777
    )
}

/// How links on a path are treated.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Links {
    /// Binaries and libraries: a link only at the top, or one a package installed.
    Strict,
    /// Data and configs: any link only root can change, followed.
    Follow,
}

struct Walker<'a> {
    root: &'a Path,
    db: &'a PkgDb,
    items: BTreeMap<String, Item>,
    watch: BTreeMap<String, String>,
    /// Objects whose libraries were listed already.
    listed: BTreeSet<String>,
    /// php-fpm's own loader: a shared library (an extension) names none of its own.
    loader: Option<String>,
    /// The first link no package installed on the path being resolved (and its target).
    unpackaged_link: Option<(String, String)>,
    /// Data files left out because not everyone may read them.
    skipped: Vec<String>,
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" { format!("/{name}") } else { format!("{dir}/{name}") }
}

fn parent(p: &str) -> String {
    match p.rsplit_once('/') {
        Some(("", _)) | None => "/".to_owned(),
        Some((d, _)) => d.to_owned(),
    }
}

impl Walker<'_> {
    fn host(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }

    fn lstat(&mut self, p: &str) -> io::Result<fs::Metadata> {
        let m = fs::symlink_metadata(self.host(p))?;
        self.watch.insert(p.to_owned(), stamp(&m));
        Ok(m)
    }

    /// `path` resolved inside the root, component by component: every folder checked, every link
    /// judged by `links` and (for [`Links::Strict`]) recorded so the guest has it too. The
    /// resolved path and its metadata.
    fn resolve(&mut self, path: &str, links: Links) -> Result<(String, fs::Metadata), Refused> {
        if !path.starts_with('/') {
            return Err(refused(path, "not an absolute path"));
        }
        let mut todo: Vec<String> = path.split('/').filter(|c| !c.is_empty()).rev().map(str::to_owned).collect();
        let mut cur = "/".to_owned();
        let m = self.lstat("/").map_err(|e| refused("/", e.to_string()))?;
        if !dir_ok(&m) {
            return Err(refused(self.root.display().to_string(), owner_why(&m, "the PHP root")));
        }
        let mut hops = 0;
        let mut last = m;
        while let Some(c) = todo.pop() {
            match c.as_str() {
                "." => continue,
                ".." => {
                    cur = parent(&cur);
                    continue;
                }
                _ => {}
            }
            let next = join(&cur, &c);
            if NEVER.iter().any(|n| next == *n || next.starts_with(&format!("{n}/"))) {
                return Err(refused(&next, "is never captured (secrets)"));
            }
            let m = self.lstat(&next).map_err(|e| refused(&next, e.to_string()))?;
            if m.file_type().is_symlink() {
                hops += 1;
                if hops > 40 {
                    return Err(refused(path, "too many links"));
                }
                if m.uid() != 0 {
                    return Err(refused(&next, owner_why(&m, "a link")));
                }
                let target = fs::read_link(self.host(&next)).map_err(|e| refused(&next, e.to_string()))?;
                let target = target.to_str().ok_or_else(|| refused(&next, "a link whose target isn't UTF-8"))?.to_owned();
                if links == Links::Strict {
                    // The top, and a merged /usr's own links (Fedora 42: /usr/sbin → bin).
                    const MERGED: [&str; 4] = ["/usr/sbin", "/usr/lib64", "/usr/lib32", "/usr/libx32"];
                    let top = cur == "/" || (MERGED.contains(&next.as_str()) && !target.contains('/'));
                    // The package manager's alternatives (/usr/bin/convert → /etc/alternatives/
                    // convert → …) are its own links, though no package lists them.
                    let alternative = next.starts_with("/etc/alternatives/") || target.starts_with("/etc/alternatives/");
                    let pkg = self.db.owns(&next).map(str::to_owned).or_else(|| alternative.then(|| "alternatives".to_owned()));
                    // A link no package installed (ldconfig's soname links, busybox's applets):
                    // allowed only on the way to a file a package installed, whose checksum
                    // matches ([`Walker::object`] checks; an unpackaged file is refused).
                    if !top && pkg.is_none() && self.unpackaged_link.is_none() {
                        self.unpackaged_link = Some((next.clone(), target.clone()));
                    }
                    let source = pkg.map_or_else(
                        || if top { "top-level link".to_owned() } else { "link no package installed (to a package's file)".to_owned() },
                        |p| format!("{}:{p}", self.db.kind.map_or("pkg", |k| k.as_str())),
                    );
                    self.items.insert(next.clone(), Item::Link { path: next.clone(), target: target.clone(), source });
                }
                todo.extend(target.split('/').filter(|c| !c.is_empty()).rev().map(str::to_owned));
                if target.starts_with('/') {
                    cur = "/".to_owned();
                }
                continue;
            }
            if m.is_dir() {
                if !dir_ok(&m) {
                    return Err(refused(&next, owner_why(&m, "a folder")));
                }
                if links == Links::Strict {
                    self.items.entry(next.clone()).or_insert(Item::Dir { path: next.clone(), mode: m.mode() & 0o7777 });
                }
                cur = next;
                last = m;
                continue;
            }
            if !todo.is_empty() {
                return Err(refused(&next, "is not a folder"));
            }
            cur = next;
            last = m;
        }
        Ok((cur, last))
    }

    /// Reads a file at its resolved path, never through a link swapped in since it was
    /// resolved (O_NOFOLLOW, and the same device and inode).
    fn read(&self, path: &str, m: &fs::Metadata, cap: u64) -> Result<Vec<u8>, Refused> {
        let f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.host(path))
            .map_err(|e| refused(path, e.to_string()))?;
        let fm = f.metadata().map_err(|e| refused(path, e.to_string()))?;
        if fm.dev() != m.dev() || fm.ino() != m.ino() {
            return Err(refused(path, "changed while it was being captured"));
        }
        if fm.len() > cap {
            return Err(refused(path, format!("is {} bytes, more than the capture takes ({cap})", fm.len())));
        }
        let mut b = Vec::with_capacity(fm.len() as usize);
        f.take(cap + 1).read_to_end(&mut b).map_err(|e| refused(path, e.to_string()))?;
        Ok(b)
    }

    fn source(&self, path: &str, bytes: &[u8]) -> Result<String, Refused> {
        let kind = self.db.kind.map_or("pkg", |k| k.as_str());
        match self.db.check_bytes(path, bytes) {
            Verdict::Matches { pkg } => Ok(format!("{kind}:{pkg}")),
            Verdict::NoChecksum { pkg } => Ok(format!("{kind}:{pkg} (no checksum recorded; root-owned)")),
            Verdict::Unpackaged => Ok("unpackaged (root-owned)".to_owned()),
            Verdict::Unverifiable { pkg, algo } => Err(refused(path, format!("{kind} records {pkg}'s checksum in an algorithm the capture can't compute ({algo:?}), so it isn't let through unchecked"))),
            Verdict::Differs { pkg, recorded, algo } => Err(refused(
                path,
                format!(
                    "its bytes don't match what {kind} recorded for {pkg} ({algo:?} {recorded}, the file's is {}): it changed after its package installed it",
                    pkgdb::digest_of(algo, bytes)
                ),
            )),
        }
    }

    /// A binary or library: validated, recorded, and with `closure` the libraries it loads too.
    fn object(&mut self, path: &str, closure: bool) -> Result<String, Refused> {
        self.unpackaged_link = None;
        let (real, m) = self.resolve(path, Links::Strict)?;
        let via = self.unpackaged_link.take();
        if !m.is_file() {
            return Err(refused(&real, "is not a regular file"));
        }
        if !file_ok(&m) {
            return Err(refused(&real, owner_why(&m, "the file")));
        }
        let packaged = |s: &str| !s.starts_with("unpackaged") && !s.contains("no checksum");
        if let Some(Item::File { source, .. }) = self.items.get(&real)
            && let Some((link, target)) = &via
            && !packaged(source)
        {
            return Err(refused(link, format!("a link to {target} that no package installed, below {}, to a file no package installed; an unpackaged file is never reached through a link", top_of(link))));
        }
        if !self.items.get(&real).is_some_and(|i| matches!(i, Item::File { .. })) {
            let bytes = self.read(&real, &m, MAX_FILE)?;
            let source = self.source(&real, &bytes)?;
            if let Some((link, target)) = &via
                && !packaged(&source)
            {
                return Err(refused(link, format!("a link to {target} that no package installed, below {}, to a file no package installed; an unpackaged file is never reached through a link", top_of(link))));
            }
            let sha256 = pkgdb::hex(&Sha256::digest(&bytes));
            self.items.insert(
                real.clone(),
                Item::File { path: real.clone(), from: real.clone(), mode: m.mode() & 0o7777, uid: 0, gid: 0, size: m.len(), sha256, source },
            );
            if closure
                && phpconf::is_elf(&bytes)
                && self.listed.insert(real.clone())
                && let Some(interp) = phpconf::elf_interp(&bytes).or_else(|| self.loader.clone())
            {
                if self.loader.is_none() {
                    self.loader = Some(interp.clone());
                }
                self.object(&interp, false)?;
                // musl's loader exits 127 on an extension's PHP symbols (php-fpm defines them, not
                // a library), after it has listed what it found: its list stands, and a library it
                // couldn't find is still a refusal below.
                let out = match run_in_root_out(self.root, &[&interp, "--list", &real], Duration::from_secs(30)) {
                    Ok((true, out, _)) => out,
                    Ok((false, out, err)) if !out.is_empty() && err.lines().all(|l| l.contains("symbol not found")) => out,
                    Ok((false, _, err)) => return Err(refused(&real, format!("listing its libraries: {}", err.lines().next().unwrap_or("failed")))),
                    Err(e) => return Err(refused(&real, format!("listing its libraries: {e}"))),
                };
                let libs = phpconf::parse_ld_list(&out).map_err(|name| refused(&real, format!("needs {name}, which the host's loader can't find")))?;
                for lib in libs {
                    self.object(&lib, false)?;
                }
            }
        }
        Ok(real)
    }

    /// A config file: root's, read (links followed and checked).
    fn config(&mut self, path: &str) -> Result<ConfFile, Refused> {
        let (real, m) = self.resolve(path, Links::Follow)?;
        if !m.is_file() || !file_ok(&m) {
            return Err(refused(path, owner_why(&m, "the config")));
        }
        let b = self.read(&real, &m, MAX_CONFIG)?;
        let text = String::from_utf8_lossy(&b).into_owned();
        let sha256 = pkgdb::hex(&Sha256::digest(&b));
        let securecore = phpconf::parse_ini(&text).iter().any(|s| s.key == "extension" && s.value.contains("securecore"));
        Ok(ConfFile { path: path.to_owned(), text, sha256, securecore })
    }

    /// A data file at `path` (a link followed: its target's bytes are stored at `path`).
    fn data(&mut self, path: &str) -> Result<(), Refused> {
        let (real, m) = self.resolve(path, Links::Follow)?;
        if !m.is_file() {
            return Ok(());
        }
        if !file_ok(&m) {
            return Err(refused(&real, owner_why(&m, "the file")));
        }
        // Data is what anyone on the host may read: a file only some may read (a private key
        // beside the certificates, 0600) never goes into the guest.
        if m.mode() & 0o004 == 0 {
            self.skipped.push(path.to_owned());
            return Ok(());
        }
        let bytes = self.read(&real, &m, MAX_FILE)?;
        // A file under /etc is a config (rpm records /etc/passwd's checksum as installed; adding a
        // user changes it): held to the ownership rules, as configs are, not to a package's
        // checksum. Binaries and libraries never are.
        let source = match self.source(&real, &bytes) {
            Err(e) if real.starts_with("/etc/") && e.why.contains("don't match what") => "config, changed since its package (root-owned)".to_owned(),
            r => r?,
        };
        let sha256 = pkgdb::hex(&Sha256::digest(&bytes));
        // The folders on the way exist in the guest as they do here.
        self.dirs_of(path)?;
        self.items.insert(
            path.to_owned(),
            Item::File { path: path.to_owned(), from: real, mode: m.mode() & 0o7777, uid: 0, gid: 0, size: m.len(), sha256, source },
        );
        Ok(())
    }

    /// The folders above `path`, as folders (a link on the way taken the strict way).
    fn dirs_of(&mut self, path: &str) -> Result<(), Refused> {
        let p = parent(path);
        if p != "/" {
            self.resolve(&p, Links::Strict)?;
        }
        Ok(())
    }

    /// A data folder, whole: files as [`Walker::data`], `.so` files as objects with their
    /// libraries.
    fn tree(&mut self, dir: &str, depth: usize) -> Result<(), Refused> {
        let (real, m) = self.resolve(dir, Links::Strict)?;
        if !m.is_dir() || depth > 12 {
            return Ok(());
        }
        let mut names: Vec<String> = fs::read_dir(self.host(&real)).map_err(|e| refused(&real, e.to_string()))?.flatten().filter_map(|e| e.file_name().into_string().ok()).collect();
        names.sort();
        for n in names {
            let p = join(&real, &n);
            let em = self.lstat(&p).map_err(|e| refused(&p, e.to_string()))?;
            if em.is_dir() {
                self.tree(&p, depth + 1)?;
            } else if n.ends_with(".so") || n.contains(".so.") {
                self.object(&p, true)?;
            } else {
                // A link to a folder isn't followed (no loops); to a file, it is; one that points
                // at nothing (a font package that isn't installed) is left out. Resolved inside
                // the PHP root, as everything is.
                if em.file_type().is_symlink() {
                    match self.resolve(&p, Links::Follow) {
                        Ok((_, t)) if t.is_dir() => continue,
                        Err(e) if e.why.contains("No such file") => continue,
                        Err(e) => return Err(e),
                        Ok(_) => {}
                    }
                }
                self.data(&p)?;
            }
        }
        Ok(())
    }

    /// `name` on [`PHP_PATH`] (or a path), when present.
    fn which(&mut self, name: &str) -> Option<String> {
        if name.contains('/') {
            return self.lstat(name).is_ok().then(|| name.to_owned());
        }
        for d in PHP_PATH.split(':') {
            let p = join(d, name);
            // A link that points at nothing is no program.
            if self.lstat(&p).is_ok() && self.resolve(&p, Links::Follow).is_ok() {
                return Some(p);
            }
            self.watch.insert(p, "-".to_owned());
        }
        None
    }
}

fn top_of(p: &str) -> String {
    format!("/{}", p.trim_start_matches('/').split('/').next().unwrap_or(""))
}

/// The files in an ini scan folder, in PHP's order (alphabetical), `.ini` only.
fn ini_files(w: &mut Walker<'_>, dir: &str) -> Result<Vec<String>, Refused> {
    let (real, m) = match w.resolve(dir, Links::Follow) {
        Ok(r) => r,
        Err(e) if e.why.contains("No such file") => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    if !m.is_dir() {
        return Ok(Vec::new());
    }
    let mut names: Vec<String> = fs::read_dir(w.host(&real))
        .map_err(|e| refused(&real, e.to_string()))?
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".ini"))
        .collect();
    names.sort();
    Ok(names.into_iter().map(|n| join(dir.trim_end_matches('/'), &n)).collect())
}

/// `pattern`'s files: a path, or a folder and a last component with `*` (php-fpm's include
/// globs, `etc/php-fpm.d/*.conf`).
fn glob(w: &mut Walker<'_>, pattern: &str) -> Result<Vec<String>, Refused> {
    let (dir, last) = (parent(pattern), pattern.rsplit('/').next().unwrap_or(""));
    let Some((pre, post)) = last.split_once('*') else { return Ok(vec![pattern.to_owned()]) };
    let (real, m) = match w.resolve(&dir, Links::Follow) {
        Ok(r) => r,
        Err(e) if e.why.contains("No such file") => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    if !m.is_dir() {
        return Ok(Vec::new());
    }
    let mut names: Vec<String> = fs::read_dir(w.host(&real))
        .map_err(|e| refused(&real, e.to_string()))?
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with(pre) && n.ends_with(post) && n.len() >= pre.len() + post.len())
        .collect();
    names.sort();
    Ok(names.into_iter().map(|n| join(&dir, &n)).collect())
}

/// The first candidate whose path, NUL-terminated, is a string in php-fpm's binary (where its
/// compiled-in defaults live), else the first that exists.
fn compiled<'c>(w: &mut Walker<'_>, fpm_bytes: &[u8], candidates: &'c [String]) -> Option<&'c String> {
    let has = |s: &str| {
        let needle = [s.as_bytes(), b"\0"].concat();
        fpm_bytes.windows(needle.len()).any(|x| x == needle.as_slice())
    };
    candidates.iter().find(|c| has(c)).or_else(|| candidates.iter().find(|c| w.lstat(c).is_ok()))
}

/// Captures and validates the host's PHP for `req` ([module docs](self)).
pub fn capture(req: &Request) -> Result<Capture, Refused> {
    // rpm's database is read by running the host's rpm: before it runs, it and the folders to it
    // must pass the ownership rules (its libraries too, as listed by the loader, nothing run
    // yet); after, it must match its own package's record like any captured binary.
    let rpm = if PkgDb::is_rpm(&req.root) {
        let none = PkgDb::default();
        let mut pre = Walker { root: &req.root, db: &none, items: BTreeMap::new(), watch: BTreeMap::new(), listed: BTreeSet::new(), loader: None, unpackaged_link: None, skipped: Vec::new() };
        let p = pre.which("rpm").ok_or_else(|| refused("rpm", format!("an rpm database, but no rpm on {PHP_PATH}")))?;
        let (real, m) = pre.resolve(&p, Links::Follow)?;
        if !m.is_file() || !file_ok(&m) {
            return Err(refused(&real, owner_why(&m, "rpm")));
        }
        Some(real)
    } else {
        None
    };
    let db = PkgDb::open_with(&req.root, rpm.as_deref().unwrap_or("rpm")).map_err(|e| refused(req.root.join("var/lib").display().to_string(), e))?;
    let mut w = Walker { root: &req.root, db: &db, items: BTreeMap::new(), watch: BTreeMap::new(), listed: BTreeSet::new(), loader: None, unpackaged_link: None, skipped: Vec::new() };
    // The top-level links of a merged /usr (/bin → usr/bin, /lib64 → usr/lib64…): the guest has
    // them as the host does, so a program named by either path is there (PHP runs /bin/sh).
    for top in TOPS {
        let p = format!("/{top}");
        if w.lstat(&p).is_ok_and(|m| m.file_type().is_symlink()) {
            w.resolve(&p, Links::Strict)?;
        }
    }
    if let Some(rpm) = &rpm {
        w.object(rpm, true).map_err(|e| refused(e.file, format!("{} (rpm, which read the package database)", e.why)))?;
    }
    let fpm = w.which(&req.php_fpm).ok_or_else(|| refused(&req.php_fpm, format!("no such program on {PHP_PATH}")))?;
    let fpm = w.object(&fpm, true)?;
    let fpm_bytes = {
        let (_, m) = w.resolve(&fpm, Links::Strict)?;
        w.read(&fpm, &m, MAX_FILE)?
    };
    // Its compiled-in folders: run only now that it and its libraries are checked, as nobody,
    // with no ini file.
    let info = run_in_root(&req.root, &[&fpm, "-n", "-i"], Duration::from_secs(20)).map_err(|e| refused(&fpm, format!("php-fpm -n -i: {e}")))?;
    let info = phpconf::parse_phpinfo(&info);
    let php_version = info.get("PHP Version").cloned().ok_or_else(|| refused(&fpm, "isn't php-fpm: `php-fpm -n -i` printed no PHP Version"))?;
    let ini_dir = info.get("Configuration File (php.ini) Path").cloned().unwrap_or_default();
    // php.ini: -c (a file or a folder), else php-fpm.ini or php.ini in the compiled folder.
    let ini_arg = req.arg("-c", "--php-ini");
    let ini_candidates: Vec<String> = match &ini_arg {
        Some(c) if c.ends_with(".ini") => vec![c.clone()],
        Some(d) => vec![join(d, "php-fpm.ini"), join(d, "php.ini")],
        None => vec![join(&ini_dir, "php-fpm.ini"), join(&ini_dir, "php.ini")],
    };
    let mut ini = None;
    for c in &ini_candidates {
        if w.lstat(c).is_ok() {
            ini = Some(w.config(c)?);
            break;
        }
        w.watch.insert(c.clone(), "-".to_owned());
    }
    // The scan folder(s): PHP_INI_SCAN_DIR as php-fpm reads it (an empty entry is the compiled
    // one), else the compiled one.
    let compiled_scan = {
        let c = vec![join(&ini_dir, "conf.d"), "/etc/php.d".to_owned(), format!("{ini_dir}.d")];
        compiled(&mut w, &fpm_bytes, &c).cloned()
    };
    let scan: Vec<String> = match &req.scan_dir_env {
        Some(env) => env.split(':').filter_map(|d| if d.is_empty() { compiled_scan.clone() } else { Some(d.to_owned()) }).collect(),
        None => compiled_scan.into_iter().collect(),
    };
    let mut conf_d = Vec::new();
    for d in &scan {
        for f in ini_files(&mut w, d)? {
            conf_d.push(w.config(&f)?);
        }
    }
    let mut settings: Vec<(String, Setting)> = Vec::new();
    for c in ini.iter().chain(conf_d.iter()) {
        settings.extend(phpconf::parse_ini(&c.text).into_iter().map(|s| (c.path.clone(), s)));
    }
    let ext_dir = settings
        .iter()
        .rev()
        .find(|(_, s)| s.key == "extension_dir")
        .map(|(_, s)| s.value.clone())
        .or_else(|| info.get("extension_dir").cloned())
        .ok_or_else(|| refused(&fpm, "has no extension_dir"))?;
    // Every extension in the folder, with its libraries.
    match w.resolve(&ext_dir, Links::Strict) {
        Ok((real, m)) if m.is_dir() => {
            let mut names: Vec<String> = fs::read_dir(w.host(&real)).map_err(|e| refused(&real, e.to_string()))?.flatten().filter_map(|e| e.file_name().into_string().ok()).filter(|n| n.ends_with(".so")).collect();
            names.sort();
            for n in names {
                w.object(&join(&real, &n), true)?;
            }
        }
        Ok(_) => return Err(refused(&ext_dir, "the extension folder isn't a folder")),
        Err(e) if e.why.contains("No such file") => {}
        Err(e) => return Err(e),
    }
    // PHP's own folders: the extension folder, the one above it, and <prefix>/lib/php. A config
    // that names native code by path there gets it captured (and checked like any binary); a
    // path anywhere else is outside the captured set and refused below.
    let prefix = req.arg("-p", "--prefix").unwrap_or_else(|| parent(&parent(&fpm)));
    let php_roots = [ext_dir.trim_end_matches('/').to_owned(), parent(&ext_dir), join(&prefix, "lib/php")];
    let named: Vec<(String, String, usize)> = settings
        .iter()
        .filter(|(_, s)| phpconf::NATIVE_KEYS.contains(&s.key.to_ascii_lowercase().as_str()) && s.value.starts_with('/') && !s.value.contains(".."))
        .map(|(f, s)| (f.clone(), s.value.clone(), s.line))
        .collect();
    for (file, path, line) in named {
        if php_roots.iter().any(|r| path.starts_with(&format!("{r}/"))) && w.lstat(&path).is_ok() {
            w.object(&path, true).map_err(|e| refused(e.file, format!("{} (named by {file}:{line})", e.why)))?;
        }
    }
    // A config may load only what was captured, and run only PHP files on the site disk.
    check_settings(&settings, &ext_dir, &req.app_root, &|p| captured_ro(&w, p))?;
    // php-fpm's config: -y, else php-fpm.conf beside php.ini's folder or above it (the compiled
    // one is a string in the binary). Relative includes are under its prefix (-p, else the
    // folder above php-fpm's own).
    let fpm_conf = match req.arg("-y", "--fpm-config") {
        Some(c) => c,
        None => {
            let c = vec![join(&ini_dir, "php-fpm.conf"), join(&parent(&ini_dir), "php-fpm.conf")];
            compiled(&mut w, &fpm_bytes, &c).cloned().ok_or_else(|| refused(join(&ini_dir, "php-fpm.conf"), "no php-fpm config found (pass -y to php-fpm)"))?
        }
    };
    let mut fc = FpmConfig::default();
    let mut fpm_files = Vec::new();
    let mut queue = vec![(fpm_conf, 0)];
    while let Some((file, depth)) = queue.pop() {
        if depth > 8 {
            return Err(refused(&file, "includes nest more than 8 deep"));
        }
        let c = w.config(&file)?;
        let includes = fc.add(&file, &c.text);
        fpm_files.push(c);
        let mut next = Vec::new();
        for inc in includes {
            let inc = if inc.starts_with('/') { inc } else { join(&prefix, &inc) };
            next.extend(glob(&mut w, &inc)?);
        }
        // In order: the first include is read first.
        queue.extend(next.into_iter().rev().map(|f| (f, depth + 1)));
    }
    if fc.pools.is_empty() {
        return Err(refused(&fpm_files[0].path, "php-fpm's config defines no pool"));
    }
    check_pools(&fc, &ext_dir, &req.app_root, &|x| captured_ro(&w, x))?;
    // The programs PHP runs, when the host has them.
    let sendmail = settings
        .iter()
        .rev()
        .find(|(_, s)| s.key == "sendmail_path")
        .and_then(|(_, s)| s.value.split_whitespace().next().map(str::to_owned))
        .unwrap_or_else(|| "sendmail".to_owned());
    let (mut helpers, mut missing) = (Vec::new(), Vec::new());
    let mut names: Vec<String> = HELPERS.iter().map(|h| (*h).to_owned()).collect();
    names[1] = sendmail;
    // PHP's CLI beside php-fpm: layer 3's helper is `<PHP_BINDIR>/php`.
    names.push(join(&prefix, "bin/php"));
    for h in names {
        match w.which(&h) {
            Some(p) => {
                w.object(&p, true)?;
                helpers.push(p);
            }
            None => missing.push(h),
        }
    }
    // ImageMagick's modules and settings (its coders are loaded by name, not by the linker),
    // ghostscript's resources: when PHP can reach either.
    let has_imagick = w.items.keys().any(|k| k.ends_with("/imagick.so")) || helpers.iter().any(|h| h.ends_with("/convert") || h.ends_with("/magick"));
    let mut trees: Vec<String> = DATA_TREES.iter().map(|t| (*t).to_owned()).collect();
    if has_imagick {
        for base in ["/etc", "/usr/lib", "/usr/lib64", "/usr/lib/x86_64-linux-gnu", "/usr/share", "/usr/local/lib", "/usr/local/etc"] {
            if let Ok(list) = fs::read_dir(w.host(base)) {
                let mut found: Vec<String> = list.flatten().filter_map(|e| e.file_name().into_string().ok()).filter(|n| n.starts_with("ImageMagick")).map(|n| join(base, &n)).collect();
                found.sort();
                trees.extend(found);
            }
        }
    }
    if helpers.iter().any(|h| h.ends_with("/gs")) {
        trees.push("/usr/share/ghostscript".to_owned());
    }
    for t in &trees {
        if w.lstat(t).is_ok() {
            w.tree(t, 0)?;
        } else {
            w.watch.insert(t.clone(), "-".to_owned());
        }
    }
    for f in DATA_FILES {
        if w.lstat(f).is_ok() {
            w.data(f)?;
        } else {
            w.watch.insert(f.to_owned(), "-".to_owned());
        }
    }
    // OpenSSL's own folder, whose links lead to the certificates captured above (PHP's https
    // streams use its default paths); only the links a package installed.
    for l in ["/usr/lib/ssl/certs", "/usr/lib/ssl/openssl.cnf", "/usr/lib/ssl/cert.pem"] {
        if w.lstat(l).is_ok_and(|m| m.file_type().is_symlink()) && w.db.owns(l).is_some() {
            w.dirs_of(l)?;
            let target = fs::read_link(w.host(l)).map_err(|e| refused(l, e.to_string()))?.to_string_lossy().into_owned();
            w.items.insert(l.to_owned(), Item::Link { path: l.to_owned(), target, source: format!("{}:{}", w.db.kind.map_or("pkg", |k| k.as_str()), w.db.owns(l).unwrap_or("")) });
        }
    }
    // Every captured entry must have a base folder to be mounted on.
    for p in w.items.keys() {
        let top = p.trim_start_matches('/').split('/').next().unwrap_or("");
        if !TOPS.contains(&top) {
            return Err(refused(p, format!("is under /{top}, which the guest's base has no folder for (it has {})", TOPS.join(" "))));
        }
    }
    let mysql_sockets = phpconf::mysql_default_sockets(&settings.iter().map(|(_, s)| s.clone()).collect::<Vec<_>>());
    let items: Vec<Item> = w.items.values().cloned().collect();
    // Trust on first use: the install's record of what no package's checksum covers.
    if let Some(rec) = &req.record
        && !check_record(rec, &items)?
    {
        write_record(rec, &items)?;
    }
    let php_key = items_key(&items);
    Ok(Capture {
        fpm,
        php_version,
        ext_dir,
        ini,
        conf_d,
        scan_dirs: scan,
        fpm_files,
        pools: fc.pools,
        items,
        helpers,
        missing_helpers: missing,
        mysql_sockets,
        pkg: db.kind.map_or_else(|| "none".to_owned(), |k| format!("{} ({} paths)", k.as_str(), db.len())),
        php_key,
        watch: w.watch.into_iter().collect(),
        asked: req.asked(),
    })
}

/// Whether `p` (or what it resolves to) is a captured file, without recording anything.
fn captured_ro(w: &Walker<'_>, p: &str) -> bool {
    let file = |k: &str| w.items.get(k).is_some_and(|i| matches!(i, Item::File { .. }));
    if file(p) {
        return true;
    }
    // A path through a captured link: what it resolves to must be a captured file, never a folder.
    fs::canonicalize(w.host(p)).ok().and_then(|c| c.strip_prefix(w.root).ok().map(|r| format!("/{}", r.display()))).is_some_and(|r| file(&r))
}

/// The settings that load code, against the captured set: the first refusal, naming the file
/// and line. Settings this parser can't read as PHP does are refused too.
pub fn check_settings(settings: &[(String, Setting)], ext_dir: &str, app_root: &str, captured: &dyn Fn(&str) -> bool) -> Result<(), Refused> {
    for (file, s) in settings {
        if s.ambiguous {
            return Err(refused(format!("{file}:{}", s.line), format!("{} = {}: a value PHP reads differently from a single string (two quoted strings, or text after one); write it as one", s.key, s.raw)));
        }
        if let Some(why) = phpconf::code_refusal(&s.key, &s.value, ext_dir, app_root, captured) {
            return Err(refused(format!("{file}:{}", s.line), why));
        }
    }
    Ok(())
}

/// The pools' `php_value`/`php_admin_value`/`php_flag`/`php_admin_flag` settings against the
/// captured set, as [`check_settings`]; and any pool setting this parser can't read as PHP does.
pub fn check_pools(fc: &FpmConfig, ext_dir: &str, app_root: &str, captured: &dyn Fn(&str) -> bool) -> Result<(), Refused> {
    if let Some(at) = fc.ambiguous.first() {
        return Err(refused(at, "a value PHP reads differently from a single string (two quoted strings, or text after one); write it as one"));
    }
    for p in &fc.pools {
        for (k, v) in &p.settings {
            if let Some(key) = phpconf::php_value_key(k)
                && let Some(why) = phpconf::code_refusal(key, v, ext_dir, app_root, captured)
            {
                return Err(refused(p.at(k), format!("pool [{}]: {k}: {why}", p.name)));
            }
        }
    }
    Ok(())
}

/// The PHP layer's key: every item, in path order.
pub fn items_key(items: &[Item]) -> String {
    let mut h = Sha256::new();
    for i in items {
        match i {
            Item::File { path, mode, uid, gid, sha256, .. } => h.update(format!("F {path} {mode:o} {uid}:{gid} {sha256}\n")),
            Item::Link { path, target, .. } => h.update(format!("L {path} {target}\n")),
            Item::Dir { path, mode } => h.update(format!("D {path} {mode:o}\n")),
        }
    }
    pkgdb::hex(&h.finalize())
}

/// Whether every path the last capture read is as it was (the fast path: no hashing, no
/// loader, no package database).
pub fn unchanged(root: &Path, last: &Capture) -> bool {
    last.watch.iter().all(|(p, s)| {
        let host = root.join(p.trim_start_matches('/'));
        match fs::symlink_metadata(&host) {
            Ok(m) => stamp(&m) == *s,
            Err(_) => s == "-",
        }
    })
}

/// The capture for `req`: the last one when nothing it read changed (`<cache>/capture.json`),
/// else a new one. Writes the root-only manifest and logs what changed since the last.
pub fn capture_cached(req: &Request, cache: &Path, log: &dyn Fn(&str)) -> Result<(Capture, bool), Refused> {
    let saved = cache.join("capture.json");
    let last: Option<Capture> = fs::read(&saved).ok().and_then(|b| serde_json::from_slice(&b).ok());
    if let Some(last) = &last
        && last.asked == req.asked()
        && unchanged(&req.root, last)
    {
        return Ok((last.clone(), true));
    }
    let t = Instant::now();
    let c = capture(req)?;
    let manifest = manifest(&c);
    let path = cache.join("capture-manifest.json");
    let old: Vec<serde_json::Value> = fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    if !old.is_empty() {
        let key = |v: &serde_json::Value| (v["path"].as_str().unwrap_or("").to_owned(), v.to_string());
        let before: BTreeMap<String, String> = old.iter().map(key).collect();
        let after: BTreeMap<String, String> = manifest.iter().map(key).collect();
        let changed: Vec<&String> = after.iter().filter(|(p, v)| before.get(*p) != Some(*v)).map(|(p, _)| p).chain(before.keys().filter(|p| !after.contains_key(*p))).collect();
        if !changed.is_empty() {
            let shown: Vec<&str> = changed.iter().take(6).map(|s| s.as_str()).collect();
            log(&format!("capture: {} entries changed since the last capture: {}{}", changed.len(), shown.join(" "), if changed.len() > 6 { " …" } else { "" }));
        }
    }
    write_private(&path, serde_json::to_vec_pretty(&manifest).unwrap_or_default().as_slice()).map_err(|e| refused(path.display().to_string(), e.to_string()))?;
    write_private(&saved, serde_json::to_vec(&c).unwrap_or_default().as_slice()).map_err(|e| refused(saved.display().to_string(), e.to_string()))?;
    let files = c.items.iter().filter(|i| matches!(i, Item::File { .. })).count();
    let bytes: u64 = c.items.iter().map(|i| if let Item::File { size, .. } = i { *size } else { 0 }).sum();
    log(&format!(
        "captured the host's PHP {} ({}): {files} files ({} MiB), {} configs, {} pool(s), checked against {}, in {:.0} ms",
        c.php_version,
        c.fpm,
        bytes >> 20,
        c.conf_d.len() + usize::from(c.ini.is_some()) + c.fpm_files.len(),
        c.pools.len(),
        c.pkg,
        t.elapsed().as_secs_f64() * 1000.0
    ));
    Ok((c, false))
}

/// The manifest: every captured entry's path, owner, mode, sha256 and source, and every config.
pub fn manifest(c: &Capture) -> Vec<serde_json::Value> {
    let mut out: Vec<serde_json::Value> = c
        .items
        .iter()
        .map(|i| match i {
            Item::File { path, from, mode, uid, gid, sha256, source, .. } => serde_json::json!({
                "path": path, "from": from, "owner": format!("{uid}:{gid}"), "mode": format!("{mode:o}"), "sha256": sha256, "source": source }),
            Item::Link { path, target, source } => serde_json::json!({ "path": path, "link": target, "source": source }),
            Item::Dir { path, mode } => serde_json::json!({ "path": path, "dir": format!("{mode:o}") }),
        })
        .collect();
    for f in c.ini.iter().chain(c.conf_d.iter()).chain(c.fpm_files.iter()) {
        out.push(serde_json::json!({ "path": f.path, "owner": "0:0", "sha256": f.sha256, "source": "config" }));
    }
    out
}

/// A file only root may read.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("new");
    let _ = fs::remove_file(&tmp);
    {
        use std::io::Write as _;
        let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Runs `argv` inside `root` (chroot), as nobody (65534) with no supplementary groups, no
/// environment but [`PHP_PATH`], stdin closed, for at most `timeout`. Its stdout (at most
/// 16 MiB); an exit that isn't 0 is an error with its stderr's first line.
pub fn run_in_root(root: &Path, argv: &[&str], timeout: Duration) -> Result<String, String> {
    match run_in_root_out(root, argv, timeout)? {
        (true, out, _) => Ok(out),
        (false, _, err) => {
            let first = err.lines().next().unwrap_or("").to_owned();
            Err(format!("{} failed{}", argv[0], if first.is_empty() { String::new() } else { format!(": {first}") }))
        }
    }
}

/// [`run_in_root`]'s run: whether it exited 0, its stdout and its stderr.
pub fn run_in_root_out(root: &Path, argv: &[&str], timeout: Duration) -> Result<(bool, String, String), String> {
    let root_c = std::ffi::CString::new(root.as_os_str().as_encoded_bytes()).map_err(|_| "a NUL in the root".to_owned())?;
    let mut cmd = Command::new(argv[0]);
    cmd.args(&argv[1..]).env_clear().env("PATH", PHP_PATH).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // SAFETY: only async-signal-safe calls between fork and exec, on a string made before.
    unsafe {
        cmd.pre_exec(move || {
            if libc::chroot(root_c.as_ptr()) < 0 || libc::chdir(c"/".as_ptr()) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setgroups(0, std::ptr::null()) < 0 || libc::setgid(65534) < 0 || libc::setuid(65534) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().map_err(|e| format!("{}: {e}", argv[0]))?;
    let mut out = child.stdout.take().ok_or("no stdout")?;
    let mut err = child.stderr.take().ok_or("no stderr")?;
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = (&mut out).take(16 << 20).read_to_end(&mut b);
        b
    });
    let ereader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = (&mut err).take(64 << 10).read_to_end(&mut b);
        b
    });
    let t = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if t.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{} took more than {} s", argv[0], timeout.as_secs()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => return Err(e.to_string()),
        }
    };
    let out = reader.join().unwrap_or_default();
    let err = ereader.join().unwrap_or_default();
    Ok((status.success(), String::from_utf8_lossy(&out).into_owned(), String::from_utf8_lossy(&err).into_owned()))
}

/// Lays `items` out under `stage` (root's, empty): folders, links, and each file copied from
/// the host and hashed again, so the disk holds the bytes that were checked. Also the extra
/// folders the guest mounts on (`mounts`, guest paths) and `/var/run` → `/run`.
pub fn stage_php(root: &Path, items: &[Item], mounts: &[String], files: &[String], stage: &Path) -> Result<(), Refused> {
    let at = |p: &str| stage.join(p.trim_start_matches('/'));
    for i in items {
        match i {
            Item::Dir { path, mode } => {
                fs::create_dir_all(at(path)).map_err(|e| refused(path, e.to_string()))?;
                fs::set_permissions(at(path), fs::Permissions::from_mode(*mode & 0o755)).map_err(|e| refused(path, e.to_string()))?;
            }
            Item::Link { path, target, .. } => {
                if let Some(d) = at(path).parent() {
                    fs::create_dir_all(d).map_err(|e| refused(path, e.to_string()))?;
                }
                std::os::unix::fs::symlink(target, at(path)).map_err(|e| refused(path, e.to_string()))?;
            }
            Item::File { path, from, mode, sha256, .. } => {
                if let Some(d) = at(path).parent() {
                    fs::create_dir_all(d).map_err(|e| refused(path, e.to_string()))?;
                }
                let src = root.join(from.trim_start_matches('/'));
                let mut f = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&src).map_err(|e| refused(from, e.to_string()))?;
                let mut b = Vec::new();
                f.read_to_end(&mut b).map_err(|e| refused(from, e.to_string()))?;
                let got = pkgdb::hex(&Sha256::digest(&b));
                if got != *sha256 {
                    return Err(refused(from, format!("changed between its check (sha256 {sha256}) and its copy (sha256 {got})")));
                }
                let mut o = fs::OpenOptions::new().write(true).create_new(true).mode(*mode & 0o755).open(at(path)).map_err(|e| refused(path, e.to_string()))?;
                io::Write::write_all(&mut o, &b).map_err(|e| refused(path, e.to_string()))?;
                // No setuid or setgid bit in the guest (#80); the mode is set past the umask.
                fs::set_permissions(at(path), fs::Permissions::from_mode(*mode & 0o755)).map_err(|e| refused(path, e.to_string()))?;
            }
        }
    }
    for m in mounts {
        fs::create_dir_all(at(m)).map_err(|e| refused(m, e.to_string()))?;
    }
    // Empty files a file of the config layer is bound onto (php.ini at its host path).
    for f in files {
        if let Some(d) = at(f).parent() {
            fs::create_dir_all(d).map_err(|e| refused(f, e.to_string()))?;
        }
        if fs::symlink_metadata(at(f)).is_err() {
            fs::write(at(f), b"").map_err(|e| refused(f, e.to_string()))?;
        }
    }
    if stage.join("var").is_dir() && fs::symlink_metadata(stage.join("var/run")).is_err() {
        std::os::unix::fs::symlink("/run", stage.join("var/run")).map_err(|e| refused("/var/run", e.to_string()))?;
    }
    Ok(())
}

/// The config disk's files for one pool: `php.ini`, `conf.d/`, `conf.d-noext/` (without the
/// files that load the SecureCore extension, for `sc.ext=0`) and `php-fpm.conf` (the guest's,
/// [`phpconf::guest_fpm_conf`]). Paths relative to the disk's root.
pub fn conf_files(c: &Capture, fpm_conf: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(ini) = &c.ini {
        out.push(("php.ini".to_owned(), ini.text.clone()));
    }
    for (n, f) in c.conf_d.iter().enumerate() {
        // The file's own name, with its place in PHP's order kept (two scan folders may both
        // have one of the same name).
        let name = format!("{n:03}-{}", f.path.rsplit('/').next().unwrap_or("x.ini"));
        out.push((format!("conf.d/{name}"), f.text.clone()));
        if !f.securecore {
            out.push((format!("conf.d-noext/{name}"), f.text.clone()));
        }
    }
    out.push(("php-fpm.conf".to_owned(), fpm_conf.to_owned()));
    out
}

/// The config disk's key.
pub fn conf_key(files: &[(String, String)]) -> String {
    let mut h = Sha256::new();
    for (p, t) in files {
        h.update(format!("{p}\0{}\n", pkgdb::hex(&Sha256::digest(t.as_bytes()))));
    }
    pkgdb::hex(&h.finalize())
}

/// Writes the config disk's files under `stage` (root's, readable by all: the guest's php-fpm
/// master reads them as root, its workers never need them).
pub fn stage_conf(files: &[(String, String)], stage: &Path) -> io::Result<()> {
    for d in ["conf.d", "conf.d-noext"] {
        fs::create_dir_all(stage.join(d))?;
    }
    for (p, t) in files {
        let path = stage.join(p);
        fs::write(&path, t)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

/// An ext4 image of `stage` at `out` (through a temporary name), read-only in the guest: no
/// journal, no reserved blocks, every file root's. Made as root from a folder root made.
pub fn image(stage: &Path, out: &Path) -> Result<u64, String> {
    let (mut bytes, mut entries) = (0u64, 0u64);
    let mut stack = vec![stage.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).map_err(|e| e.to_string())?.flatten() {
            let m = e.metadata().map_err(|e| e.to_string())?;
            entries += 1;
            bytes += m.len().div_ceil(4096) * 4096 + 4096;
            if m.is_dir() {
                stack.push(e.path());
            }
        }
    }
    let mb = (bytes + bytes / 5) / (1 << 20) + 32;
    let tmp = out.with_extension("ext4.new");
    let _ = fs::remove_file(&tmp);
    let mut cmd = Command::new("mke2fs");
    cmd.env_clear().env("PATH", std::env::var_os("PATH").unwrap_or_default()).stdin(Stdio::null());
    cmd.args(["-q", "-F", "-t", "ext4", "-b", "4096", "-m", "0", "-O", "^has_journal"]).arg("-N").arg((entries * 2 + 1024).to_string());
    cmd.args(["-E", "root_owner=0:0", "-d"]).arg(stage).arg(&tmp).arg(format!("{mb}M"));
    let o = cmd.output().map_err(|e| format!("mke2fs: {e}"))?;
    if !o.status.success() {
        let _ = fs::remove_file(&tmp);
        return Err(format!("mke2fs {}: {} {}", out.display(), o.status, String::from_utf8_lossy(&o.stderr).trim()));
    }
    fs::rename(&tmp, out).map_err(|e| format!("{}: {e}", out.display()))?;
    Ok(mb)
}

/// Empties and removes a staging folder this process made (never across a mount).
pub fn remove_stage(stage: &Path) {
    let _ = fs::remove_dir_all(stage);
}

/// The validation rules against a fake host root (#102 review). They set owners, so they run as
/// root (the `check` target does); elsewhere each returns at once.
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn root_user() -> bool {
        // SAFETY: geteuid(2) takes nothing.
        unsafe { libc::geteuid() == 0 }
    }

    /// A fresh fake root, root's 0755, with `/usr/lib` and `/etc`.
    fn fake(name: &str) -> PathBuf {
        let r = std::env::temp_dir().join(format!("sc-capture-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&r);
        for d in ["usr/lib", "etc/ssl/private", "etc/ssl/certs"] {
            fs::create_dir_all(r.join(d)).expect("dirs");
        }
        let mut stack = vec![r.clone()];
        while let Some(d) = stack.pop() {
            std::os::unix::fs::chown(&d, Some(0), Some(0)).expect("chown");
            fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).expect("chmod");
            for e in fs::read_dir(&d).expect("ls").flatten() {
                if e.file_type().expect("type").is_dir() {
                    stack.push(e.path());
                }
            }
        }
        r
    }

    fn file(r: &Path, p: &str, body: &[u8], mode: u32) {
        let at = r.join(p.trim_start_matches('/'));
        fs::write(&at, body).expect("write");
        std::os::unix::fs::chown(&at, Some(0), Some(0)).expect("chown");
        fs::set_permissions(&at, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    fn walker<'a>(r: &'a Path, db: &'a PkgDb) -> Walker<'a> {
        Walker { root: r, db, items: BTreeMap::new(), watch: BTreeMap::new(), listed: BTreeSet::new(), loader: None, unpackaged_link: None, skipped: Vec::new() }
    }

    #[test]
    fn a_folder_anyone_else_may_write_is_refused() {
        if !root_user() {
            return;
        }
        let r = fake("folders");
        file(&r, "/usr/lib/x.so", b"not elf", 0o644);
        let db = PkgDb::default();
        assert!(walker(&r, &db).object("/usr/lib/x.so", false).is_ok(), "root's 0755 folders");
        fs::set_permissions(r.join("usr/lib"), fs::Permissions::from_mode(0o777)).expect("chmod");
        let e = walker(&r, &db).object("/usr/lib/x.so", false).expect_err("a 0777 folder");
        assert_eq!(e.file, "/usr/lib");
        assert!(e.why.contains("a folder is owned by 0:0 with mode 777"), "{e}");
        fs::set_permissions(r.join("usr/lib"), fs::Permissions::from_mode(0o755)).expect("chmod");
        std::os::unix::fs::chown(r.join("usr"), Some(1234), Some(0)).expect("chown");
        assert!(walker(&r, &db).object("/usr/lib/x.so", false).is_err(), "a folder another user owns, anywhere on the way");
        std::os::unix::fs::chown(r.join("usr"), Some(0), Some(0)).expect("chown");
        file(&r, "/usr/lib/x.so", b"not elf", 0o666);
        assert!(walker(&r, &db).object("/usr/lib/x.so", false).expect_err("a 0666 file").why.contains("the file is owned by 0:0 with mode 666"));
        let _ = fs::remove_dir_all(&r);
    }

    #[test]
    fn links_are_followed_only_where_the_rules_allow() {
        if !root_user() {
            return;
        }
        let r = fake("links");
        file(&r, "/usr/lib/libx.so.1.0", b"libx", 0o644);
        symlink("libx.so.1.0", r.join("usr/lib/libx.so.1")).expect("link");
        symlink("usr/lib", r.join("lib")).expect("top link");
        let none = PkgDb::default();
        // A top-level link (a merged /usr) is fine on the way.
        let mut w = walker(&r, &none);
        assert_eq!(w.object("/lib/libx.so.1.0", false).expect("top-level link"), "/usr/lib/libx.so.1.0");
        assert!(matches!(w.items.get("/lib"), Some(Item::Link { .. })), "the guest gets the link too");
        // A link no package installed, to a file no package installed: refused.
        let e = walker(&r, &none).object("/usr/lib/libx.so.1", false).expect_err("unpackaged link to an unpackaged file");
        assert_eq!(e.file, "/usr/lib/libx.so.1");
        assert!(e.why.contains("an unpackaged file is never reached through a link"), "{e}");
        // The same link to a file a package installed, whose checksum matches: allowed.
        let mut db = PkgDb::default();
        db.kind = Some(crate::pkgdb::Kind::Dpkg);
        db.add_dpkg_md5sums("libx1", &format!("{}  usr/lib/libx.so.1.0\n", crate::pkgdb::digest_of(crate::pkgdb::Algo::Md5, b"libx")));
        assert_eq!(walker(&r, &db).object("/usr/lib/libx.so.1", false).expect("to a packaged file"), "/usr/lib/libx.so.1.0");
        // A link not root's: refused even at the top.
        symlink("usr/lib", r.join("lib64")).expect("link");
        // SAFETY: lchown(2) on a path made here.
        let c = std::ffi::CString::new(r.join("lib64").as_os_str().as_encoded_bytes()).expect("path");
        unsafe { libc::lchown(c.as_ptr(), 1234, 1234) };
        assert!(walker(&r, &none).object("/lib64/libx.so.1.0", false).expect_err("another user's link").why.contains("a link is owned by 1234"));
        let _ = fs::remove_dir_all(&r);
    }

    #[test]
    fn secrets_are_never_captured_and_data_is_what_anyone_may_read() {
        if !root_user() {
            return;
        }
        let r = fake("never");
        file(&r, "/etc/ssl/private/key.pem", b"KEY", 0o600);
        file(&r, "/etc/ssl/certs/ca.pem", b"CA", 0o644);
        file(&r, "/etc/ssl/certs/local-key.pem", b"KEY2", 0o600);
        symlink("/etc/ssl/private/key.pem", r.join("etc/ssl/certs/linked-key.pem")).expect("link");
        let db = PkgDb::default();
        let mut w = walker(&r, &db);
        assert!(w.resolve("/etc/ssl/private/key.pem", Links::Follow).expect_err("never").why.contains("never captured"));
        // A link into a never-captured folder is refused too, wherever it sits.
        assert!(w.tree("/etc/ssl/certs", 0).expect_err("a link to a key").why.contains("never captured"));
        std::fs::remove_file(r.join("etc/ssl/certs/linked-key.pem")).expect("rm");
        let mut w = walker(&r, &db);
        w.tree("/etc/ssl/certs", 0).expect("certs");
        assert!(w.items.contains_key("/etc/ssl/certs/ca.pem"), "a certificate anyone may read");
        assert!(!w.items.contains_key("/etc/ssl/certs/local-key.pem"), "a 0600 file beside it is left out");
        assert_eq!(w.skipped, vec!["/etc/ssl/certs/local-key.pem"]);
        let _ = fs::remove_dir_all(&r);
    }

    #[test]
    fn the_copy_is_hashed_again_and_loses_setuid() {
        if !root_user() {
            return;
        }
        let r = fake("copy");
        file(&r, "/usr/lib/a.so", b"checked bytes", 0o4755);
        let sha = pkgdb::hex(&Sha256::digest(b"checked bytes"));
        let item = |sha256: &str| Item::File {
            path: "/usr/lib/a.so".into(),
            from: "/usr/lib/a.so".into(),
            mode: 0o4755,
            uid: 0,
            gid: 0,
            size: 13,
            sha256: sha256.into(),
            source: "unpackaged (root-owned)".into(),
        };
        let stage = r.join("stage");
        stage_php(&r, &[item(&sha)], &[], &[], &stage).expect("staged");
        let m = fs::metadata(stage.join("usr/lib/a.so")).expect("staged file");
        assert_eq!(m.mode() & 0o7777, 0o755, "no setuid bit in the guest");
        // Bytes that changed after the check: refused at the copy.
        let stage2 = r.join("stage2");
        let e = stage_php(&r, &[item(&"0".repeat(64))], &[], &[], &stage2).expect_err("changed");
        assert!(e.why.contains("changed between its check"), "{e}");
        let _ = fs::remove_dir_all(&r);
    }

    #[test]
    fn code_loading_settings_are_refused_with_the_file_and_line() {
        let none = |_: &str| false;
        let mut c = FpmConfig::default();
        c.add("/etc/php-fpm.d/www.conf", "[www]\npm = static\nphp_admin_value[auto_prepend_file] = /etc/evil.php\n");
        let e = check_pools(&c, "/ext", "/var/www/html", &none).expect_err("prepend outside the root");
        assert_eq!(e.file, "/etc/php-fpm.d/www.conf:3");
        assert!(e.why.contains("php_admin_value[auto_prepend_file]"), "{e}");
        let mut c = FpmConfig::default();
        c.add("/etc/php-fpm.d/www.conf", "[www]\nphp_admin_value[extension] = /opt/x.so\n");
        assert!(check_pools(&c, "/ext", "/var/www/html", &none).is_err(), "an extension from a pool");
        let mut c = FpmConfig::default();
        c.add("/etc/php-fpm.d/www.conf", "[www]\nphp_admin_value[auto_prepend_file] = /var/www/html/waf.php\n");
        assert!(check_pools(&c, "/ext", "/var/www/html", &none).is_ok(), "inside the root");
        let s = |k: &str, v: &str| ("/etc/php/conf.d/x.ini".to_owned(), phpconf::parse_ini(&format!("{k} = {v}\n")).remove(0));
        assert!(check_settings(&[s("auto_prepend_file", "/tmp/p.php")], "/ext", "/var/www/html", &none).expect_err("outside").file.ends_with("x.ini:1"));
        assert!(check_settings(&[s("ffi.preload", "/opt/x.h")], "/ext", "/var/www/html", &none).is_err());
        assert!(check_settings(&[s("extension", "\"a\" \"b\"")], "/ext", "/var/www/html", &none).expect_err("ambiguous").why.contains("two quoted strings"));
        assert!(check_settings(&[s("memory_limit", "256M")], "/ext", "/var/www/html", &none).is_ok());
    }

    #[test]
    fn unpackaged_files_must_match_the_install_record() {
        if !root_user() {
            return;
        }
        let r = fake("record");
        let rec = r.join("rec/unpackaged.json");
        let items = vec![Item::File {
            path: "/usr/local/sbin/php-fpm".into(),
            from: "/usr/local/sbin/php-fpm".into(),
            mode: 0o755,
            uid: 0,
            gid: 0,
            size: 1,
            sha256: "a".repeat(64),
            source: "unpackaged (root-owned)".into(),
        }];
        assert_eq!(check_record(&rec, &items), Ok(false), "no record yet");
        let mut with_etc = items.clone();
        with_etc.push(Item::File {
            path: "/etc/hostname".into(),
            from: "/etc/hostname".into(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: 4,
            sha256: "c".repeat(64),
            source: "unpackaged (root-owned)".into(),
        });
        assert_eq!(unpackaged(&with_etc).len(), 1, "/etc is the host's own (it differs per host), never recorded");
        assert_eq!(write_record(&rec, &items), Ok(1));
        assert_eq!(fs::metadata(&rec).expect("record").mode() & 0o777, 0o600);
        assert_eq!(check_record(&rec, &items), Ok(true));
        let mut changed = items.clone();
        if let Item::File { sha256, .. } = &mut changed[0] {
            *sha256 = "b".repeat(64);
        }
        assert!(check_record(&rec, &changed).expect_err("changed").why.contains("recorded at install"));
        let mut extra = items.clone();
        if let Item::File { path, .. } = &mut extra[0] {
            *path = "/usr/local/lib/php/extensions/new.so".into();
        }
        assert!(check_record(&rec, &extra).expect_err("not recorded").why.contains("isn't in the install's record"));
        let _ = fs::remove_dir_all(&r);
    }
}
