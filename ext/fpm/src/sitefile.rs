//! Reading `securecore.json` the careful way (addiscorp/securecore#90 review, S1): at launch and
//! in the microVM's config watcher, with one function. The file is the site's, and the site's
//! owner controls it, so the launcher (root) never lets it point anywhere else:
//!
//! - the root (the folder holding `securecore.json`, which the operator names with `--config`)
//!   is the operator's: resolved once with `canonicalize`, so a deployment's link
//!   (`/var/www/current -> releases/7`) works;
//! - below it everything is the site owner's: the file is opened from an fd on that root with
//!   `openat2` `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, so no link (the file itself, a folder on
//!   the way) and no `..` out of the root is followed;
//! - the file is opened as the owner of the root (this thread's filesystem ids,
//!   `setfsuid`/`setfsgid`), so a file that owner can't read (another site's, root's own) isn't;
//! - it must be a regular file, opened `O_NONBLOCK` (a FIFO or a device is refused at once,
//!   never read), and at most [`MAX_CONFIG`] bytes are read;
//! - no error quotes the file's bytes ([`securecore_config::LoadError::without_contents`]).

use std::io::{self, Read as _};
use std::path::Path;

use securecore_config::{LoadError, Loaded};

/// The largest `securecore.json` read (and the largest a microVM guest takes).
pub const MAX_CONFIG: usize = 128 * 1024;

/// Reads `path` as described in the module header, its folder being the root: `Ok(None)` when
/// it doesn't exist.
pub fn read(path: &Path, cap: usize) -> Result<Option<Vec<u8>>, String> {
    let (root, name) = match (path.parent(), path.file_name()) {
        (Some(d), Some(n)) if !d.as_os_str().is_empty() => (d, Path::new(n)),
        (_, Some(n)) => (Path::new("."), Path::new(n)),
        _ => return Err(format!("{}: not a file path", path.display())),
    };
    read_beneath(root, name, cap)
}

/// Reads `rel` beneath `root` as described in the module header: `root` resolved once (the
/// operator's), nothing below it a link. `Ok(None)` when it doesn't exist.
pub fn read_beneath(root: &Path, rel: &Path, cap: usize) -> Result<Option<Vec<u8>>, String> {
    let path = root.join(rel);
    let shown = path.display();
    let f = match open(root, rel) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::EXDEV)) => {
            return Err(format!("{shown}: a link is in its path below {}: refused (the file is read only as itself)", root.display()));
        }
        Err(e) => return Err(format!("{shown}: {e}")),
    };
    let m = f.metadata().map_err(|e| format!("{shown}: {e}"))?;
    if !m.file_type().is_file() {
        return Err(format!("{shown} is not a regular file: refused"));
    }
    if m.len() > cap as u64 {
        return Err(format!("{shown} is larger than {cap} bytes: refused"));
    }
    let mut b = Vec::new();
    f.take(cap as u64 + 1).read_to_end(&mut b).map_err(|e| format!("{shown}: {e}"))?;
    if b.len() > cap {
        return Err(format!("{shown} is larger than {cap} bytes: refused"));
    }
    Ok(Some(b))
}

/// [`read`], then the config crate's own parser: the launcher's start and the microVM's
/// watcher see the same file the same way. Errors never quote the file.
pub fn load(path: &Path) -> Result<Loaded, String> {
    match read(path, MAX_CONFIG)? {
        None => Err(format!("{}: cannot read it: No such file or directory", path.display())),
        Some(b) => securecore_config::load_bytes(path, &b).map_err(|e: LoadError| e.without_contents()),
    }
}

#[cfg(target_os = "linux")]
fn open(root: &Path, rel: &Path) -> io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    let c = |p: &Path| std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| io::Error::other("a path with a NUL"));
    // The root is the operator's (`/var/www/current -> releases/7` is a deployment, not an
    // attack): resolved once, as the launcher.
    let root = std::fs::canonicalize(root)?;
    let (d, n) = (c(&root)?, c(rel)?);
    // SAFETY: open(2) with a NUL-terminated path; the fd is owned below.
    let dfd = unsafe { libc::open(d.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if dfd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: dfd was just returned by openat2(2).
    let dfd = unsafe { OwnedFd::from_raw_fd(dfd) };
    let owner = std::fs::File::from(dfd.try_clone()?).metadata()?;
    // As the folder's owner, when that isn't who runs this (root reading a site's file).
    // SAFETY: getuid only reads this process's id.
    let swap = (unsafe { libc::geteuid() } == 0 && owner.uid() != 0).then_some((owner.uid(), owner.gid()));
    // SAFETY: setfsuid(2)/setfsgid(2) change only this thread's filesystem ids; put back below.
    let old = swap.map(|(u, g)| unsafe { (libc::setfsgid(g), libc::setfsuid(u)) });
    // Below the root everything is the site owner's: no link, no `..` out of it.
    let fd = crate::jail::openat2_raw(dfd.as_raw_fd(), &n, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC, crate::jail::BENEATH);
    let err = io::Error::last_os_error();
    if let Some((g, u)) = old {
        // SAFETY: as above.
        unsafe {
            libc::setfsuid(u as libc::uid_t);
            libc::setfsgid(g as libc::gid_t);
        }
    }
    if fd < 0 {
        return Err(err);
    }
    // SAFETY: fd was just returned by openat2(2).
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Elsewhere (the launcher runs on Linux; this keeps the crate's tests building): no link as the
/// last component.
#[cfg(not(target_os = "linux"))]
fn open(root: &Path, rel: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(root.join(rel))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{Duration, Instant};

    fn scratch(name: &str) -> std::path::PathBuf {
        // A folder whose path holds no link (macOS's /var is one; /private/var isn't).
        let base = fs::canonicalize(std::env::temp_dir()).expect("tmp");
        let dir = base.join(format!("sc-sitefile-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        dir
    }

    /// S1: at launch as in the watcher, a link to another site's config, root's own file, a
    /// device and a FIFO are refused at once, and no error quotes the file.
    #[test]
    fn the_config_is_read_as_itself_by_its_folders_owner() {
        let dir = scratch("read");
        let good = dir.join("securecore.json");
        fs::write(&good, r#"{"layer1":{"isolation":"off"},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#).expect("write");
        assert!(load(&good).is_ok(), "a plain file loads");
        let other = dir.join("other-site.json");
        fs::write(&other, r#"{"layer1":{"isolation":"off"},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#).expect("write");
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&other, &link).expect("link");
        assert!(load(&link).expect_err("a link").contains("link"), "a link to another site's config");
        let zero = dir.join("zero.json");
        std::os::unix::fs::symlink("/dev/zero", &zero).expect("link");
        let t = Instant::now();
        assert!(load(&zero).is_err(), "/dev/zero through a link");
        assert!(read(Path::new("/dev/zero"), MAX_CONFIG).expect_err("a device").contains("not a regular file"));
        let fifo = dir.join("fifo.json");
        let cf = std::ffi::CString::new(fifo.to_str().expect("utf8")).expect("cstr");
        // SAFETY: mkfifo(3) with a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(cf.as_ptr(), 0o644) }, 0);
        assert!(read(&fifo, MAX_CONFIG).expect_err("a FIFO").contains("not a regular file"));
        assert!(t.elapsed() < Duration::from_secs(1), "refused at once, never read");
        let big = dir.join("big.json");
        fs::write(&big, vec![b' '; MAX_CONFIG + 1]).expect("write");
        assert!(read(&big, MAX_CONFIG).expect_err("too big").contains("larger than"));
        // serde's messages quote what they met; these never do.
        fs::write(&good, r#"{"layer1":{"isolation":"sk_live_SECRET"},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#).expect("write");
        let e = load(&good).expect_err("an unknown value");
        assert!(e.contains("invalid at line 1 column") && !e.contains("SECRET"), "{e}");
        fs::write(&good, "{\"layer1\": \"sk_live_SECRET").expect("write");
        assert!(!load(&good).expect_err("not JSON").contains("SECRET"));
        // As root: the file is opened as the folder's owner, so root's own file isn't read.
        // SAFETY: geteuid only reads this process's id.
        #[cfg(target_os = "linux")]
        if unsafe { libc::geteuid() } == 0 {
            use std::os::unix::fs::PermissionsExt as _;
            let site = dir.join("site");
            fs::create_dir_all(&site).expect("site");
            std::os::unix::fs::chown(&site, Some(65534), Some(65534)).expect("chown");
            let root_only = site.join("securecore.json");
            fs::write(&root_only, "{}").expect("write");
            fs::set_permissions(&root_only, fs::Permissions::from_mode(0o600)).expect("chmod");
            assert!(read(&root_only, MAX_CONFIG).expect_err("root's alone").contains("Permission denied"));
            fs::set_permissions(&root_only, fs::Permissions::from_mode(0o644)).expect("chmod");
            assert!(read(&root_only, MAX_CONFIG).expect("readable").is_some());
            // A link anywhere in the path, not only the last component.
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// The site root may be reached through the operator's link (a deployment's
    /// `/var/www/current -> releases/1`); below it, a link (the file, a folder on the way) or a
    /// `..` out of it is refused.
    #[test]
    fn the_root_may_be_a_deployments_link_but_nothing_below_it() {
        let dir = scratch("deploy");
        let release = dir.join("releases/1");
        fs::create_dir_all(release.join("conf")).expect("release");
        let json = r#"{"layer1":{"isolation":"off"},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#;
        fs::write(release.join("securecore.json"), json).expect("write");
        fs::write(release.join("conf/site.ini"), "x").expect("write");
        let current = dir.join("current");
        std::os::unix::fs::symlink("releases/1", &current).expect("link");
        let loaded = load(&current.join("securecore.json")).expect("through the deployment's link");
        assert_eq!(loaded.config, securecore_config::Config::from_slice(json.as_bytes()).expect("valid"));
        // Below the root: the file a link, a folder a link, and `..` out of the root.
        fs::write(dir.join("elsewhere.json"), json).expect("write");
        let inside = release.join("linked.json");
        std::os::unix::fs::symlink(dir.join("elsewhere.json"), &inside).expect("link");
        assert!(read(&current.join("linked.json"), MAX_CONFIG).expect_err("a linked file").contains("a link is in its path"));
        std::os::unix::fs::symlink(release.join("conf"), release.join("conflink")).expect("link");
        // (openat2 is Linux's; the fallback elsewhere checks the last component only.)
        #[cfg(target_os = "linux")]
        assert!(read_beneath(&current, Path::new("conflink/site.ini"), 1024).expect_err("a linked folder").contains("a link is in its path"));
        assert_eq!(read_beneath(&current, Path::new("conf/site.ini"), 1024), Ok(Some(b"x".to_vec())), "a real folder is fine");
        #[cfg(target_os = "linux")]
        assert!(read_beneath(&current, Path::new("../../elsewhere.json"), 1024).is_err(), "never out of the root");
        let _ = fs::remove_dir_all(&dir);
    }
}
