//! Reading `securecore.json` the careful way (addiscorp/securecore#90 review, S1): at launch and
//! in the microVM's config watcher, with one function. The file is the site's, and the site's
//! owner controls it, so the launcher (root) never lets it point anywhere else:
//!
//! - every component of the path is resolved without following a link (`openat2`
//!   `RESOLVE_NO_SYMLINKS`), the last one included;
//! - the file is opened as the owner of the folder that holds it (this thread's filesystem ids,
//!   `setfsuid`/`setfsgid`), so a file that owner can't read (another site's, root's own) isn't;
//! - it must be a regular file, opened `O_NONBLOCK` (a FIFO or a device is refused at once,
//!   never read), and at most [`MAX_CONFIG`] bytes are read;
//! - no error quotes the file's bytes ([`securecore_config::LoadError::without_contents`]).

use std::io::{self, Read as _};
use std::path::Path;

use securecore_config::{LoadError, Loaded};

/// The largest `securecore.json` read (and the largest a microVM guest takes).
pub const MAX_CONFIG: usize = 128 * 1024;

/// Reads `path` as described in the module header: `Ok(None)` when it doesn't exist.
pub fn read(path: &Path, cap: usize) -> Result<Option<Vec<u8>>, String> {
    let shown = path.display();
    let f = match open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(format!("{shown}: a link is in its path: refused (the file is read only as itself, at its own path)"));
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
fn open(path: &Path) -> io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    let c = |p: &Path| std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| io::Error::other("a path with a NUL"));
    let (dir, name) = match (path.parent(), path.file_name()) {
        (Some(d), Some(n)) if !d.as_os_str().is_empty() => (d, Path::new(n)),
        (_, Some(n)) => (Path::new("."), Path::new(n)),
        _ => return Err(io::Error::other("not a file path")),
    };
    let (d, n) = (c(dir)?, c(name)?);
    let dfd = crate::jail::openat2_raw(libc::AT_FDCWD, &d, libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC, crate::jail::NO_LINKS);
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
    let fd = crate::jail::openat2_raw(dfd.as_raw_fd(), &n, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC, crate::jail::NO_LINKS);
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
fn open(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)
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
            let via = dir.join("via");
            std::os::unix::fs::symlink(&site, &via).expect("link");
            assert!(read(&via.join("securecore.json"), MAX_CONFIG).expect_err("a link in the path").contains("link"));
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
