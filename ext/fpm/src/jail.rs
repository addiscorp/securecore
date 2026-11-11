//! Firecracker under its jailer (addiscorp/securecore#71, review finding 1). Linux only.
//!
//! Firecracker never runs as root. The jailer (from the same Firecracker release tarball as
//! Firecracker, checked by the installer) starts it:
//! - as an unprivileged uid and gid (`--vm-user`), with no supplementary groups;
//! - chrooted into `<state>/jail/firecracker/<id>/root`, which holds only what this VM uses:
//!   the kernel, the disks, the snapshot, Firecracker's own sockets, and for each
//!   `connect[].socket` the socket's folder, bind-mounted read-only;
//! - in new mount (the jailer's), network, IPC and UTS namespaces;
//! - in a cgroup v2 child of `securecore/` with `cpu.max` and `memory.max` set.
//!
//! So a guest's connection to a host socket arrives with the jailed uid's credentials
//! (`SO_PEERCRED`), never root's, and Firecracker reaches only the sockets that uid may open
//! itself: the kernel checks the socket file's permissions against it on every connect. The
//! launcher checks the same before it boots ([`can_connect_as`]), to refuse with the reason.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// The cgroup v2 folder every VM's cgroup goes under.
pub const PARENT_CGROUP: &str = "securecore";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The jailed uid and gid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
}

/// `<uid>:<gid>`, or a user name (its uid and primary gid). Root is refused.
pub fn user(spec: &str) -> Result<User, String> {
    let u = if let Some((uid, gid)) = spec.split_once(':') {
        let n = |s: &str| s.parse::<u32>().map_err(|_| format!("--vm-user {spec}: want <uid>:<gid> or a user name"));
        User { uid: n(uid)?, gid: n(gid)? }
    } else {
        let name = CString::new(spec).map_err(|_| format!("--vm-user {spec:?}: not a name"))?;
        // SAFETY: getpwnam(3) with a NUL-terminated name; the result is read before any other
        // passwd call in this single place.
        let pw = unsafe { libc::getpwnam(name.as_ptr()) };
        if pw.is_null() {
            return Err(format!(
                "the microVM's user {spec} doesn't exist (the installer creates it; or pass --vm-user <uid>:<gid>)"
            ));
        }
        // SAFETY: pw is non-null and points at getpwnam's static result.
        unsafe { User { uid: (*pw).pw_uid, gid: (*pw).pw_gid } }
    };
    if u.uid == 0 || u.gid == 0 {
        return Err(format!("--vm-user {spec}: Firecracker must not run as root (uid or gid 0)"));
    }
    Ok(u)
}

/// Whether `user` can connect to the unix socket at `path` the way Firecracker will in the
/// jail, where the socket's folder is bind-mounted: through that folder (opened here as root),
/// as `user` with no supplementary groups. So the folder's and the socket's own permissions
/// decide, as they will for Firecracker; the folders above it don't (the jail never has them).
/// Forks, so it runs before the launcher starts any thread.
pub fn can_connect_as(user: User, path: &Path) -> Result<(), String> {
    let m = fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !std::os::unix::fs::FileTypeExt::is_socket(&m.file_type()) {
        return Err(format!("{} is not a unix socket", path.display()));
    }
    let (dir, name) = match (path.parent(), path.file_name()) {
        (Some(d), Some(n)) => (d, n),
        _ => return Err(format!("{}: no folder", path.display())),
    };
    let dir_fd = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let via = format!("/proc/self/fd/{}/{}", std::os::fd::AsRawFd::as_raw_fd(&dir_fd), name.to_string_lossy());
    // SAFETY: an all-zero sockaddr_un is valid; the path is copied in below, NUL-terminated.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if via.len() >= addr.sun_path.len() {
        return Err(format!("{}: the path is too long for a unix socket", path.display()));
    }
    for (d, s) in addr.sun_path.iter_mut().zip(via.as_bytes()) {
        *d = *s as libc::c_char;
    }
    // SAFETY: fork(2) in a process with one thread (checked by the caller's timing: the probe
    // runs before any thread starts). The child makes plain syscalls only and _exits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", io::Error::last_os_error()));
    }
    if pid == 0 {
        // SAFETY: the child: drop to the user, try the connect, exit with the errno (0: it worked).
        unsafe {
            if libc::setgroups(0, std::ptr::null()) < 0 || libc::setgid(user.gid) < 0 || libc::setuid(user.uid) < 0 {
                libc::_exit(100);
            }
            let s = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
            let r = libc::connect(s, (&raw const addr).cast(), len);
            libc::_exit(if r == 0 { 0 } else { *libc::__errno_location() & 0x7f });
        }
    }
    let mut status = 0;
    // SAFETY: waitpid(2) for the child just forked.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    drop(dir_fd);
    let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -1 };
    match code {
        0 => Ok(()),
        100 => Err(format!("probing {}: could not switch to uid {}", path.display(), user.uid)),
        errno => Err(format!(
            "the microVM's user (uid {}) may not connect to {} ({}); only sockets it can open itself are \
             reachable from the guest",
            user.uid,
            path.display(),
            io::Error::from_raw_os_error(errno)
        )),
    }
}

/// One site's jail.
#[derive(Debug, Clone)]
pub struct Jail {
    pub id: String,
    pub base: PathBuf,
    pub root: PathBuf,
    pub user: User,
}

fn mount_points_under(root: &Path) -> Vec<PathBuf> {
    let text = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let mut points: Vec<PathBuf> = text
        .lines()
        .filter_map(|l| l.split(' ').nth(4))
        .map(|p| PathBuf::from(p.replace("\\040", " ")))
        .filter(|p| p.starts_with(root))
        .collect();
    // Deepest first.
    points.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    points
}

/// Removes `dir`'s tree without ever leaving its filesystem (a mount under it is an error, so
/// an operator's bind-mounted folder can't be emptied by accident).
fn remove_tree(dir: &Path, dev: u64) -> io::Result<()> {
    let m = match fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if m.dev() != dev {
        return Err(io::Error::other(format!("{} is another filesystem; not removing it", dir.display())));
    }
    if m.is_dir() {
        for e in fs::read_dir(dir)? {
            remove_tree(&e?.path(), dev)?;
        }
        fs::remove_dir(dir)
    } else {
        fs::remove_file(dir)
    }
}

fn cstr(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_encoded_bytes()).map_err(|_| io::Error::other("a path holds a NUL"))
}

impl Jail {
    pub fn new(state: &Path, id: &str, user: User) -> Jail {
        let base = state.join("jail");
        let root = base.join("firecracker").join(id).join("root");
        Jail { id: id.to_owned(), base, root, user }
    }

    /// The host path of a path inside the jail.
    pub fn host(&self, inside: &str) -> PathBuf {
        self.root.join(inside.trim_start_matches('/'))
    }

    /// Stops a Firecracker a crashed launcher left in this jail, unmounts what is mounted
    /// under it and removes it: every start begins with an empty jail, so nothing from an
    /// earlier config (a socket, a forward) survives into this one.
    pub fn clear(&self) -> Result<(), String> {
        // A process's root reads "/" from inside its mount namespace, so compare the inode.
        let same_root = |pid: i32| match (fs::metadata(format!("/proc/{pid}/root")), fs::metadata(&self.root)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        };
        if let Ok(pid) = fs::read_to_string(self.base.join("firecracker.pid"))
            && let Ok(pid) = pid.trim().parse::<i32>()
            && same_root(pid)
        {
            // SAFETY: kill(2) on the Firecracker this jail recorded, whose root is this jail.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            std::thread::sleep(Duration::from_millis(100));
        }
        for point in mount_points_under(&self.root) {
            let c = cstr(&point).map_err(|e| e.to_string())?;
            // SAFETY: umount2(2) with a NUL-terminated path.
            if unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) } < 0 {
                return Err(format!("unmounting {}: {}", point.display(), io::Error::last_os_error()));
            }
        }
        fs::create_dir_all(&self.base).map_err(|e| format!("{}: {e}", self.base.display()))?;
        let dev = fs::metadata(&self.base).map_err(|e| e.to_string())?.dev();
        let jail_dir = self.base.join("firecracker");
        remove_tree(&jail_dir, dev).map_err(|e| format!("clearing {}: {e}", jail_dir.display()))
    }

    /// An empty jail root, owned by the jailed user (Firecracker makes its sockets there).
    pub fn prepare(&self) -> Result<(), String> {
        self.clear()?;
        fs::create_dir_all(&self.root).map_err(|e| format!("{}: {e}", self.root.display()))?;
        std::os::unix::fs::chown(&self.root, Some(self.user.uid), Some(self.user.gid)).map_err(|e| e.to_string())?;
        fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
    }

    /// Puts `src` into the jail as `name`: a hard link (a copy when `src` is on another
    /// filesystem).
    pub fn place(&self, src: &Path, name: &str) -> Result<(), String> {
        let dst = self.host(name);
        if let Some(dir) = dst.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        if fs::hard_link(src, &dst).is_err() {
            fs::copy(src, &dst).map_err(|e| format!("{} → {}: {e}", src.display(), dst.display()))?;
        }
        Ok(())
    }

    /// A folder inside the jail the jailed user owns (e.g. for a snapshot Firecracker writes).
    pub fn user_dir(&self, name: &str) -> Result<PathBuf, String> {
        let d = self.host(name);
        fs::create_dir_all(&d).map_err(|e| format!("{}: {e}", d.display()))?;
        std::os::unix::fs::chown(&d, Some(self.user.uid), Some(self.user.gid)).map_err(|e| e.to_string())?;
        Ok(d)
    }

    /// Bind-mounts the host folder `src` read-only (nosuid, nodev, noexec) at `name` in the jail.
    pub fn bind_dir(&self, src: &Path, name: &str) -> Result<(), String> {
        let dst = self.host(name);
        fs::create_dir_all(&dst).map_err(|e| format!("{}: {e}", dst.display()))?;
        let (s, d) = (cstr(src).map_err(|e| e.to_string())?, cstr(&dst).map_err(|e| e.to_string())?);
        let none = std::ptr::null();
        // SAFETY: mount(2) with NUL-terminated paths; a bind, then its read-only remount.
        unsafe {
            if libc::mount(s.as_ptr(), d.as_ptr(), none, libc::MS_BIND, none.cast()) < 0 {
                return Err(format!("bind-mounting {} into the jail: {}", src.display(), io::Error::last_os_error()));
            }
            let flags = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
            if libc::mount(none, d.as_ptr(), none, flags, none.cast()) < 0 {
                return Err(format!("remounting {} read-only: {}", dst.display(), io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    /// The cgroup v2 parent with the cpu and memory controllers on for its children.
    pub fn cgroup_parent() -> Result<(), String> {
        let parent = Path::new(CGROUP_ROOT).join(PARENT_CGROUP);
        if !Path::new(CGROUP_ROOT).join("cgroup.controllers").is_file() {
            return Err(format!("{CGROUP_ROOT} is not cgroup v2"));
        }
        fs::create_dir_all(&parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        fs::write(parent.join("cgroup.subtree_control"), "+cpu +memory")
            .map_err(|e| format!("{}/cgroup.subtree_control: {e}", parent.display()))
    }

    /// The jailer's command line for Firecracker with `args`, limited to `vcpus` CPUs and
    /// `mem_mib` of guest memory plus Firecracker's own overhead.
    pub fn command(&self, jailer: &Path, firecracker: &Path, vcpus: u32, mem_mib: u32, args: &[&str]) -> Command {
        let mut cmd = Command::new(jailer);
        cmd.arg("--id")
            .arg(&self.id)
            .arg("--exec-file")
            .arg(firecracker)
            .arg("--uid")
            .arg(self.user.uid.to_string())
            .arg("--gid")
            .arg(self.user.gid.to_string())
            .arg("--chroot-base-dir")
            .arg(&self.base)
            .args(["--cgroup-version", "2", "--parent-cgroup", PARENT_CGROUP])
            .arg("--cgroup")
            .arg(format!("cpu.max={} 100000", u64::from(vcpus) * 100_000))
            .arg("--cgroup")
            .arg(format!("memory.max={}", (u64::from(mem_mib) + 256) << 20))
            .arg("--")
            .args(args);
        // SAFETY: setgroups(2) and unshare(2) only, between fork and exec: the jailer (root)
        // keeps no supplementary groups to hand down, and Firecracker gets its own network,
        // IPC and UTS namespaces (the jailer adds the mount namespace and the chroot).
        unsafe {
            cmd.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) < 0
                    || libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vm_user_is_never_root() {
        assert_eq!(user("64000:64001"), Ok(User { uid: 64000, gid: 64001 }));
        assert!(user("0:64000").expect_err("root uid").contains("must not run as root"));
        assert!(user("64000:0").expect_err("root gid").contains("must not run as root"));
        assert!(user("root").expect_err("root by name").contains("must not run as root"));
        assert!(user("no-such-user-sc71").expect_err("missing").contains("doesn't exist"));
        assert!(user("1:x").is_err());
    }

    #[test]
    fn the_jailer_drops_to_the_user_with_limits() {
        let j = Jail::new(Path::new("/var/lib/securecore/vm/abc"), "sc-abc", User { uid: 64000, gid: 64000 });
        assert_eq!(j.root, Path::new("/var/lib/securecore/vm/abc/jail/firecracker/sc-abc/root"));
        assert_eq!(j.host("/v.sock"), j.root.join("v.sock"));
        let cmd = j.command(Path::new("/vm/jailer"), Path::new("/vm/firecracker"), 2, 512, &["--api-sock", "/fc.sock"]);
        let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        let joined = args.join(" ");
        assert!(joined.contains("--uid 64000 --gid 64000"), "{joined}");
        assert!(joined.contains("--chroot-base-dir /var/lib/securecore/vm/abc/jail"), "{joined}");
        assert!(joined.contains("--cgroup-version 2 --parent-cgroup securecore"), "{joined}");
        assert!(args.contains(&"cpu.max=200000 100000".to_owned()), "{joined}");
        assert!(args.contains(&format!("memory.max={}", 768u64 << 20)), "{joined}");
        assert!(joined.ends_with("-- --api-sock /fc.sock"), "{joined}");
    }

    /// Root only (the Docker `check` gate runs as root): switching uid needs it.
    #[test]
    fn a_socket_counts_only_if_the_jailed_user_may_open_it() {
        // SAFETY: geteuid(2) can't fail.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("not root: the uid switch can't be tested here");
            return;
        }
        let dir = std::env::temp_dir().join(format!("securecore-jail-probe-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("dir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod");
        let path = dir.join("db.sock");
        let _ = fs::remove_file(&path);
        let _l = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let nobody = User { uid: 65534, gid: 65534 };
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod");
        let e = can_connect_as(nobody, &path).expect_err("a root-only socket");
        assert!(e.contains("may not connect") && e.contains("Permission denied"), "{e}");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).expect("chmod");
        can_connect_as(nobody, &path).expect("a socket anyone may open");
        assert!(can_connect_as(nobody, &dir).expect_err("a folder").contains("not a unix socket"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn removing_the_jail_never_crosses_into_another_filesystem() {
        let dir = std::env::temp_dir().join(format!("securecore-jail-rm-{}", std::process::id()));
        fs::create_dir_all(dir.join("a/b")).expect("dirs");
        fs::write(dir.join("a/b/f"), "x").expect("file");
        let dev = fs::metadata(&dir).expect("meta").dev();
        assert!(remove_tree(&dir.join("a"), dev + 1).is_err(), "another device: refused, nothing removed");
        assert!(dir.join("a/b/f").exists());
        remove_tree(&dir.join("a"), dev).expect("same device");
        assert!(!dir.join("a").exists());
        let _ = fs::remove_dir(&dir);
    }
}
