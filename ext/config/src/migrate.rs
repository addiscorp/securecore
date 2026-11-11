//! Upgrading a `securecore.json` written for an earlier release (`securecore-fpm
//! --migrate-config <file>`, run by the installer on a config it keeps).
//!
//! The one change so far: `layer1.enabled` is retired, and `layer1.isolation` is layer 1's only
//! switch. A file that still sets `enabled` is refused at startup, so an upgrade would leave
//! every PHP process refusing to start. The migration:
//! - `"enabled": false` → `"isolation": "off"` (layer 1 was off; any `isolation` beside it
//!   never applied);
//! - `"enabled": true` → the key removed, `isolation` left as it is (`auto` when absent).
//!
//! The original file is copied next to it first ([`backup_path`]), with its owner and mode, and
//! the new one replaces it atomically (a rename), with the same owner and mode.

use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};use std::path::{Path, PathBuf};

use crate::Config;

/// What a migration did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Migrated {
    /// Nothing to change.
    Unchanged,
    /// Rewritten; the original is at `backup`. `changes` says what changed, one entry each.
    Rewritten { backup: PathBuf, changes: Vec<String> },
}

/// A file's new bytes, and what changed in them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewrite {
    pub bytes: Vec<u8>,
    pub changes: Vec<String>,
}

/// The bytes of `input` with every retired key replaced, or `None` when there is none. The
/// result is not validated here: the caller says if the file is still invalid for another
/// reason. Fails on input that isn't a JSON object, or a `layer1.enabled` that isn't a boolean
/// (nothing says what that meant).
pub fn migrate_bytes(input: &[u8]) -> Result<Option<Rewrite>, String> {
    let mut v: serde_json::Value = serde_json::from_slice(input).map_err(|e| format!("not JSON: {e}"))?;
    let Some(layer1) = v.get_mut("layer1").and_then(serde_json::Value::as_object_mut) else { return Ok(None) };
    let Some(enabled) = layer1.remove("enabled") else { return Ok(None) };
    let changes = match enabled {
        serde_json::Value::Bool(false) => {
            layer1.insert("isolation".into(), "off".into());
            vec!["layer1.enabled false → layer1.isolation \"off\"".to_owned()]
        }
        serde_json::Value::Bool(true) => {
            let isolation = layer1.get("isolation").and_then(serde_json::Value::as_str).unwrap_or("auto").to_owned();
            vec![format!("layer1.enabled true removed (layer1.isolation stays \"{isolation}\")")]
        }
        other => return Err(format!("layer1.enabled is {other}, not true or false: fix it by hand (layer1.isolation is layer 1's switch)")),
    };
    let mut out = serde_json::to_vec_pretty(&v).map_err(|e| e.to_string())?;
    out.push(b'\n');
    Ok(Some(Rewrite { bytes: out, changes }))
}

/// Where the original goes: `<file>.before-isolation`, or with `.1`, `.2`, … when that exists
/// (an earlier backup is never overwritten).
pub fn backup_path(path: &Path) -> PathBuf {
    let base = format!("{}.before-isolation", path.display());
    let mut candidate = PathBuf::from(&base);
    let mut n = 1;
    while fs::symlink_metadata(&candidate).is_ok() {
        candidate = PathBuf::from(format!("{base}.{n}"));
        n += 1;
    }
    candidate
}

/// A new file at `path` (which must not exist) with `bytes`, `mode`, and owner `uid`:`gid`.
fn write_new(path: &Path, bytes: &[u8], mode: u32, uid: u32, gid: u32) -> io::Result<()> {
    // create_new is O_CREAT|O_EXCL: it never opens or follows anything already at `path`.
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    // The same owner as the original (only root may give a file away; as the owner it is a
    // no-op), then its mode.
    let m = f.metadata()?;
    if m.uid() != uid || m.gid() != gid {
        std::os::unix::fs::fchown(&f, Some(uid), Some(gid))?;
    }
    f.set_permissions(fs::Permissions::from_mode(mode & 0o7777))
}

/// Migrates the file at `path` in place: the original backed up beside it first, then the new
/// bytes written to a temporary file and renamed over it. `Err` names the file; on an error
/// nothing at `path` has changed.
pub fn migrate_file(path: &Path) -> Result<Migrated, String> {
    let at = |e: io::Error| format!("{}: {e}", path.display());
    let m = fs::symlink_metadata(path).map_err(at)?;
    if !m.is_file() {
        return Err(format!("{}: not a regular file (a link is never rewritten)", path.display()));
    }
    let bytes = fs::read(path).map_err(at)?;
    let Some(Rewrite { bytes: new, changes }) = migrate_bytes(&bytes).map_err(|e| format!("{}: {e}", path.display()))? else {
        return Ok(Migrated::Unchanged);
    };
    let backup = backup_path(path);
    write_new(&backup, &bytes, m.mode(), m.uid(), m.gid()).map_err(|e| format!("backing up to {}: {e}", backup.display()))?;
    let tmp = PathBuf::from(format!("{}.securecore-migrate", path.display()));
    let _ = fs::remove_file(&tmp);
    write_new(&tmp, &new, m.mode(), m.uid(), m.gid()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        at(e)
    })?;
    Ok(Migrated::Rewritten { backup, changes })
}

/// Whether the (migrated) bytes are a valid config, for the caller's report.
pub fn still_invalid(path: &Path) -> Option<String> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => return Some(e.to_string()),
    };
    Config::from_slice(&bytes).err().map(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("securecore-migrate-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        dir
    }

    fn layer1(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice::<serde_json::Value>(bytes).expect("json")["layer1"].clone()
    }

    #[test]
    fn enabled_false_becomes_isolation_off_and_true_is_dropped() {
        let off = br#"{"layer1":{"enabled":false,"isolation":"microvm","write":["/tmp"]},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#;
        let r = migrate_bytes(off).expect("migrates").expect("a change");
        assert_eq!(layer1(&r.bytes), serde_json::json!({"isolation": "off", "write": ["/tmp"]}), "off wins: layer 1 was off");
        assert_eq!(r.changes.len(), 1, "{:?}", r.changes);
        Config::from_slice(&r.bytes).expect("the result is a valid config");
        let on = br#"{"layer1":{"enabled":true,"isolation":"gelada"},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#;
        let r = migrate_bytes(on).expect("migrates").expect("a change");
        assert_eq!(layer1(&r.bytes), serde_json::json!({"isolation": "gelada"}), "true: the key goes, isolation stays");
        let on_default = br#"{"layer1":{"enabled":true},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#;
        let r = migrate_bytes(on_default).expect("migrates").expect("a change");
        assert_eq!(layer1(&r.bytes), serde_json::json!({}), "isolation stays at its default (auto)");
        assert!(r.changes[0].contains("\"auto\""), "{:?}", r.changes);
        assert!(Config::from_slice(&r.bytes).expect("valid").layer1.enabled());
        let current = br#"{"layer1":{"isolation":"off"},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#;
        assert_eq!(migrate_bytes(current).expect("parses"), None, "a current file is left alone");
        assert!(migrate_bytes(br#"{"layer1":{"enabled":"yes"}}"#).expect_err("not a bool").contains("not true or false"));
        assert!(migrate_bytes(b"[1").is_err());
    }

    #[test]
    fn an_old_file_is_backed_up_then_rewritten_with_its_mode() {
        let dir = scratch("file");
        let path = dir.join("securecore.json");
        let old = br#"{"layer1":{"enabled":false},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#;
        fs::write(&path, old).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("chmod");
        assert!(crate::load(&path).is_err(), "the old file is refused before the migration");
        let Migrated::Rewritten { backup, .. } = migrate_file(&path).expect("migrates") else { panic!("unchanged") };
        assert_eq!(backup, dir.join("securecore.json.before-isolation"));
        assert_eq!(fs::read(&backup).expect("backup"), old, "the backup is the original, byte for byte");
        assert_eq!(fs::metadata(&backup).expect("meta").permissions().mode() & 0o777, 0o640);
        assert_eq!(fs::metadata(&path).expect("meta").permissions().mode() & 0o777, 0o640, "the new file keeps the mode");
        let loaded = crate::load(&path).expect("the migrated file loads");
        assert!(!loaded.config.layer1.enabled());
        assert_eq!(still_invalid(&path), None);
        assert_eq!(migrate_file(&path).expect("again"), Migrated::Unchanged, "a second run changes nothing");
        // A later old-style file: a second backup, the first kept.
        fs::write(&path, old).expect("write");
        let Migrated::Rewritten { backup, .. } = migrate_file(&path).expect("migrates") else { panic!("unchanged") };
        assert_eq!(backup, dir.join("securecore.json.before-isolation.1"));
        assert!(!dir.join("securecore.json.securecore-migrate").exists(), "no temporary file left");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_link_is_never_rewritten() {
        let dir = scratch("link");
        let target = dir.join("real.json");
        fs::write(&target, br#"{"layer1":{"enabled":false}}"#).expect("write");
        let link = dir.join("securecore.json");
        std::os::unix::fs::symlink(&target, &link).expect("link");
        assert!(migrate_file(&link).expect_err("a link").contains("not a regular file"));
        let _ = fs::remove_dir_all(&dir);
    }
}
