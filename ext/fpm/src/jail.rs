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
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
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

/// openat2(2): `path` under `dir` with `flags` and the `resolve` rules (`RESOLVE_*`). Raw, with no
/// allocation, so it may run between fork and exec. The fd, or -1 with errno set.
pub fn openat2_raw(dir: libc::c_int, path: &std::ffi::CStr, flags: libc::c_int, resolve: u64) -> libc::c_int {
    // SAFETY: open_how is plain data (all zeroes is valid); openat2(2) reads `how` (its size
    // passed) and the NUL-terminated path.
    unsafe {
        let mut how: libc::open_how = std::mem::zeroed();
        how.flags = (flags | libc::O_CLOEXEC) as u64;
        how.resolve = resolve;
        libc::syscall(libc::SYS_openat2, dir, path.as_ptr(), &raw const how, std::mem::size_of::<libc::open_how>()) as libc::c_int
    }
}

/// `/proc/self/fd/<fd>` as a NUL-terminated path in `buf`, written without allocating (so it
/// may run between fork and exec).
pub fn proc_fd_path(fd: libc::c_int, buf: &mut [u8; 32]) -> *const libc::c_char {
    let prefix = b"/proc/self/fd/";
    buf[..prefix.len()].copy_from_slice(prefix);
    let mut at = prefix.len();
    let mut digits = [0u8; 10];
    let (mut n, mut len) = (fd.max(0) as u32, 0);
    loop {
        digits[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    for d in digits[..len].iter().rev() {
        buf[at] = *d;
        at += 1;
    }
    buf[at] = 0;
    buf.as_ptr().cast()
}

/// No symlink anywhere on the way (the last component included), and no magic link.
pub const NO_LINKS: u64 = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
/// [`NO_LINKS`], and never out of the starting folder (no `..` above it, no absolute path).
pub const BENEATH: u64 = NO_LINKS | libc::RESOLVE_BENEATH;

/// An `O_PATH` handle on the folder `rel` inside `root`: `root` opened with no symlink on its
/// own path (it is a resolved path), then `rel` walked beneath it with no symlink and no `..`
/// out. What is opened is the folder that is there now, so a link put in its place or above it
/// after a check by path is refused (ELOOP), never followed.
pub fn open_dir_beneath(root: &Path, rel: &Path) -> Result<std::os::fd::OwnedFd, String> {
    use std::os::fd::FromRawFd as _;
    let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    // The open's error, saying so when a link is why: ELOOP for one on the way, ENOTDIR for the
    // last component being one (O_NOFOLLOW opens the link itself, which is no folder).
    let refused = |path: &Path| {
        let e = io::Error::last_os_error();
        let link = e.raw_os_error() == Some(libc::ELOOP)
            || (e.raw_os_error() == Some(libc::ENOTDIR) && fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()));
        let why = if link { " (a symlink is on the way: only real folders are followed)" } else { "" };
        format!("{}: {e}{why}", path.display())
    };
    let r = cstr(root).map_err(|e| e.to_string())?;
    let fd = openat2_raw(libc::AT_FDCWD, &r, flags, NO_LINKS);
    if fd < 0 {
        return Err(refused(root));
    }
    // SAFETY: fd was just returned by openat2(2) and is owned here.
    let root_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    let rel_c = if rel.as_os_str().is_empty() { CString::from(c".") } else { cstr(rel).map_err(|e| e.to_string())? };
    let fd = openat2_raw(std::os::fd::AsRawFd::as_raw_fd(&root_fd), &rel_c, flags, BENEATH);
    if fd < 0 {
        return Err(refused(&root.join(rel)));
    }
    // SAFETY: as above.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// A `connect[].socket`'s folder, held open from the moment it is checked: the check
/// ([`can_connect_as`]) and the bind mount ([`Jail::bind_dir`]) both go through this handle, so
/// they see the same folder whatever happens to the path in between.
#[derive(Debug)]
pub struct SocketDir {
    /// The socket's path (resolved: no symlink in it), for messages.
    pub path: PathBuf,
    /// The socket's name in its folder.
    pub name: std::ffi::OsString,
    /// `O_PATH|O_NOFOLLOW` on the folder, opened with no symlink anywhere on its path.
    pub dir: std::os::fd::OwnedFd,
}

impl SocketDir {
    /// Opens the folder of the socket at `path`, which must be a resolved, absolute path.
    pub fn open(path: &Path) -> Result<SocketDir, String> {
        let dir = path.parent().filter(|d| d.is_absolute()).ok_or_else(|| format!("{}: not an absolute socket path", path.display()))?;
        let name = path.file_name().ok_or_else(|| format!("{}: no file name", path.display()))?.to_owned();
        let dir = open_dir_beneath(dir, Path::new("")).map_err(|e| format!("the socket's folder {e}"))?;
        Ok(SocketDir { path: path.to_owned(), name, dir })
    }

    /// `/proc/self/fd/<n>`: the held folder, as a path the kernel resolves to it.
    pub fn proc_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&self.dir)))
    }
}

/// Whether `user` can connect to the socket in `sock`'s held folder itself: a real connect, as
/// `user` with no supplementary groups. The child, as `user`, opens the socket's folder by its
/// path with no symlink on the way, so every folder above it counts; that must be the very
/// folder `sock` holds (device and inode); and it connects through that handle. Forks, so it
/// runs before the launcher starts any thread.
pub fn can_connect_as(user: User, sock: &SocketDir) -> Result<(), String> {
    let path = &sock.path;
    let held = sock.proc_path().join(&sock.name);
    let m = fs::symlink_metadata(&held).map_err(|e| format!("{}: {e}", path.display()))?;
    if !std::os::unix::fs::FileTypeExt::is_socket(&m.file_type()) {
        return Err(format!("{} is not a unix socket", path.display()));
    }
    let dir_meta = fs::metadata(sock.proc_path()).map_err(|e| e.to_string())?;
    let (dev, ino) = (dir_meta.dev(), dir_meta.ino());
    let dir_path = cstr(path.parent().unwrap_or(Path::new("/"))).map_err(|e| e.to_string())?;
    let name = CString::new(sock.name.as_encoded_bytes()).map_err(|_| format!("{}: holds a NUL", path.display()))?;
    // SAFETY: an all-zero sockaddr_un is valid; the child fills its path.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // "/proc/self/fd/<n>/<name>": the longest fd is 10 digits.
    if 14 + 10 + 1 + name.as_bytes().len() >= addr.sun_path.len() {
        return Err(format!("{}: the socket's name is too long", path.display()));
    }
    // SAFETY: fork(2) in a process with one thread (checked by the caller's timing: the probe
    // runs before any thread starts). The child makes plain syscalls only and _exits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", io::Error::last_os_error()));
    }
    if pid == 0 {
        // SAFETY: the child: drop to the user, open the folder as it, compare, connect through
        // it, and exit with the errno (0: it worked; 101: another folder than the one held).
        unsafe {
            if libc::setgroups(0, std::ptr::null()) < 0 || libc::setgid(user.gid) < 0 || libc::setuid(user.uid) < 0 {
                libc::_exit(100);
            }
            let fd = openat2_raw(libc::AT_FDCWD, &dir_path, libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW, NO_LINKS);
            if fd < 0 {
                libc::_exit(*libc::__errno_location() & 0x7f);
            }
            let mut st: libc::stat = std::mem::zeroed();
            if libc::fstat(fd, &mut st) < 0 || st.st_dev != dev || st.st_ino != ino {
                libc::_exit(101);
            }
            // sun_path = "/proc/self/fd/<fd>/<name>", written without allocating.
            let mut buf = [0u8; 32];
            proc_fd_path(fd, &mut buf);
            let mut at = 0;
            for &b in buf.iter().take_while(|b| **b != 0) {
                addr.sun_path[at] = b as libc::c_char;
                at += 1;
            }
            addr.sun_path[at] = b'/' as libc::c_char;
            at += 1;
            for &b in name.as_bytes() {
                addr.sun_path[at] = b as libc::c_char;
                at += 1;
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
    let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -1 };
    match code {
        0 => Ok(()),
        100 => Err(format!("probing {}: could not switch to uid {}", path.display(), user.uid)),
        101 => Err(format!(
            "{}: its folder changed while it was checked (the path now leads to another folder); refusing it",
            path.display()
        )),
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
        remove_tree(&jail_dir, dev).map_err(|e| format!("clearing {}: {e}", jail_dir.display()))?;
        // The VM's cgroup, once nothing is left in it (the jailer makes one per start).
        let cg = self.cgroup();
        if cg.exists() {
            let _ = fs::write(cg.join("cgroup.kill"), "1");
            for _ in 0..50 {
                if fs::remove_dir(&cg).is_ok() || !cg.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        Ok(())
    }

    /// This jail's cgroup v2 folder (the jailer's `--parent-cgroup`/`--id`).
    pub fn cgroup(&self) -> PathBuf {
        Path::new(CGROUP_ROOT).join(PARENT_CGROUP).join(&self.id)
    }

    /// A process that takes the VM down when the launcher goes, however it goes (a crash, a
    /// SIGKILL): it blocks on a pipe whose only writer is the launcher, and when that closes it
    /// kills everything in the VM's cgroup (`cgroup.kill`), unmounts the jail's bind mounts
    /// (`mounts`, deepest first) and removes the cgroup. The launcher keeps the returned write
    /// end open for its whole life and never writes to it. Forks, so it runs before the
    /// launcher starts any thread; the child makes syscalls only.
    pub fn watchdog(&self, mounts: &[PathBuf]) -> Result<std::os::fd::OwnedFd, String> {
        use std::os::fd::FromRawFd as _;
        let cg = self.cgroup();
        let kill = cstr(&cg.join("cgroup.kill")).map_err(|e| e.to_string())?;
        let cg = cstr(&cg).map_err(|e| e.to_string())?;
        let mounts: Vec<CString> = mounts.iter().map(|m| cstr(m)).collect::<Result<_, _>>().map_err(|e| e.to_string())?;
        let mut fds = [0; 2];
        // SAFETY: pipe2(2) fills the two-element array.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(format!("pipe: {}", io::Error::last_os_error()));
        }
        // SAFETY: fork(2) with one thread (see above).
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(format!("fork: {}", io::Error::last_os_error()));
        }
        if pid == 0 {
            // SAFETY: the child: syscalls only, on strings made before the fork, then _exit.
            unsafe {
                libc::close(fds[1]);
                // Not the launcher's terminal signals: it outlives the launcher on purpose.
                libc::signal(libc::SIGINT, libc::SIG_IGN);
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
                libc::signal(libc::SIGHUP, libc::SIG_IGN);
                libc::signal(libc::SIGQUIT, libc::SIG_IGN);
                let mut b = [0u8; 1];
                while libc::read(fds[0], b.as_mut_ptr().cast(), 1) != 0 {
                    if *libc::__errno_location() != libc::EINTR {
                        break;
                    }
                }
                let fd = libc::open(kill.as_ptr(), libc::O_WRONLY);
                if fd >= 0 {
                    libc::write(fd, c"1".as_ptr().cast(), 1);
                    libc::close(fd);
                }
                for m in &mounts {
                    libc::umount2(m.as_ptr(), libc::MNT_DETACH);
                }
                for _ in 0..100 {
                    if libc::rmdir(cg.as_ptr()) == 0 || *libc::__errno_location() == libc::ENOENT {
                        break;
                    }
                    libc::usleep(20_000);
                }
                libc::_exit(0);
            }
        }
        // SAFETY: the parent: the read end is the watchdog's; the write end is ours.
        unsafe {
            libc::close(fds[0]);
            Ok(std::os::fd::OwnedFd::from_raw_fd(fds[1]))
        }
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
        if fs::hard_link(src, &dst).is_ok() {
            return Ok(());
        }
        // Another filesystem: a copy, into a file that must not exist yet (the jail is fresh and
        // Firecracker isn't running), so nothing at `dst` is followed or written through.
        let mut from = fs::File::open(src).map_err(|e| format!("{}: {e}", src.display()))?;
        let mut to = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .map_err(|e| format!("{}: {e}", dst.display()))?;
        io::copy(&mut from, &mut to).map_err(|e| format!("{} → {}: {e}", src.display(), dst.display()))?;
        to.set_permissions(from.metadata().map_err(|e| e.to_string())?.permissions()).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// A folder inside the jail the jailed user owns (e.g. for a snapshot Firecracker writes).
    pub fn user_dir(&self, name: &str) -> Result<PathBuf, String> {
        let d = self.host(name);
        fs::create_dir_all(&d).map_err(|e| format!("{}: {e}", d.display()))?;
        std::os::unix::fs::chown(&d, Some(self.user.uid), Some(self.user.gid)).map_err(|e| e.to_string())?;
        Ok(d)
    }

    /// Bind-mounts the socket's held folder (`src`, through its handle: the folder that was
    /// checked, whatever its path leads to now) read-only (nosuid, nodev, noexec) at `name` in
    /// the jail.
    pub fn bind_dir(&self, src: &SocketDir, name: &str) -> Result<(), String> {
        let dst = self.host(name);
        fs::create_dir_all(&dst).map_err(|e| format!("{}: {e}", dst.display()))?;
        let (s, d) = (cstr(&src.proc_path()).map_err(|e| e.to_string())?, cstr(&dst).map_err(|e| e.to_string())?);
        let none = std::ptr::null();
        let shown = src.path.parent().unwrap_or(Path::new("/")).display();
        // SAFETY: mount(2) with NUL-terminated paths; a bind, then its read-only remount.
        unsafe {
            if libc::mount(s.as_ptr(), d.as_ptr(), none, libc::MS_BIND, none.cast()) < 0 {
                return Err(format!("bind-mounting {shown} into the jail: {}", io::Error::last_os_error()));
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
        // Nothing of the launcher's environment (which holds the guest's secrets, #72).
        cmd.env_clear();
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
        let probe = |p: &Path| can_connect_as(nobody, &SocketDir::open(p)?);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod");
        let e = probe(&path).expect_err("a root-only socket");
        assert!(e.contains("may not connect") && e.contains("Permission denied"), "{e}");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).expect("chmod");
        // Every folder above counts, not only the socket's own: a 0777 socket in a 0755 folder
        // inside a root-only one is refused.
        let inner = dir.join("inner");
        fs::create_dir_all(&inner).expect("inner");
        fs::set_permissions(&inner, fs::Permissions::from_mode(0o755)).expect("chmod");
        let deep = inner.join("db.sock");
        let _ = fs::remove_file(&deep);
        let _l2 = std::os::unix::net::UnixListener::bind(&deep).expect("bind");
        fs::set_permissions(&deep, fs::Permissions::from_mode(0o777)).expect("chmod");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod");
        let e = probe(&deep).expect_err("a socket below a root-only folder");
        assert!(e.contains("Permission denied"), "{e}");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod");
        let searchable = dir.ancestors().skip(1).all(|a| fs::metadata(a).is_ok_and(|m| m.permissions().mode() & 0o001 != 0));
        if searchable {
            probe(&path).expect("a socket anyone may reach and open");
            // The folder checked is the folder held: its path swapped for another folder (with
            // a socket anyone may open) after it was opened is refused, never checked instead.
            let held = SocketDir::open(&deep).expect("open");
            fs::rename(&inner, dir.join("inner-old")).expect("move the folder away");
            fs::create_dir_all(&inner).expect("another folder in its place");
            fs::set_permissions(&inner, fs::Permissions::from_mode(0o755)).expect("chmod");
            let _l3 = std::os::unix::net::UnixListener::bind(&deep).expect("bind");
            fs::set_permissions(&deep, fs::Permissions::from_mode(0o777)).expect("chmod");
            let e = can_connect_as(nobody, &held).expect_err("the path leads elsewhere now");
            assert!(e.contains("its folder changed"), "{e}");
        } else {
            eprintln!("{} has a folder above it others can't search: the allowed case is checked in the Docker gate", dir.display());
        }
        assert!(probe(&dir).expect_err("a folder").contains("not a unix socket"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_socket_folder_is_opened_with_no_link_on_the_way() {
        let dir = std::env::temp_dir().join(format!("securecore-jail-link-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("real")).expect("dirs");
        let dir = fs::canonicalize(&dir).expect("canonical");
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).expect("link");
        SocketDir::open(&dir.join("real/db.sock")).expect("a real folder");
        let e = SocketDir::open(&dir.join("link/db.sock")).expect_err("a link to the folder");
        assert!(e.contains("symlink is on the way"), "{e}");
        let e = open_dir_beneath(&dir, Path::new("link")).expect_err("a link beneath");
        assert!(e.contains("symlink is on the way"), "{e}");
        assert!(open_dir_beneath(&dir, Path::new("../")).is_err(), "never out of the root");
        open_dir_beneath(&dir, Path::new("real")).expect("a real folder beneath");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Root with CAP_SYS_ADMIN (a mount): the bind mount is of the folder held, not of what its
    /// path leads to by then.
    #[test]
    fn the_bind_mount_is_of_the_folder_that_was_checked() {
        let caps = fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| s.lines().find_map(|l| l.strip_prefix("CapEff:").map(|v| v.trim().to_owned())))
            .and_then(|v| u64::from_str_radix(&v, 16).ok())
            .unwrap_or(0);
        // SAFETY: geteuid(2) can't fail.
        if unsafe { libc::geteuid() } != 0 || caps & (1 << 21) == 0 {
            eprintln!("not root with CAP_SYS_ADMIN: checked on the KVM host and in test/ext-microvm.sh");
            return;
        }
        let dir = std::env::temp_dir().join(format!("securecore-jail-bind-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("run")).expect("dirs");
        let dir = fs::canonicalize(&dir).expect("canonical");
        fs::write(dir.join("run/checked"), "").expect("marker");
        let held = SocketDir::open(&dir.join("run/db.sock")).expect("open");
        fs::rename(dir.join("run"), dir.join("run-old")).expect("move away");
        fs::create_dir_all(dir.join("run")).expect("another");
        fs::write(dir.join("run/swapped"), "").expect("marker");
        let j = Jail::new(&dir.join("state"), "sc-bindtest", User { uid: 65534, gid: 65534 });
        fs::create_dir_all(&j.root).expect("jail root");
        j.bind_dir(&held, "/sock-1").expect("bind");
        let seen = j.host("/sock-1");
        let (checked, swapped) = (seen.join("checked").exists(), seen.join("swapped").exists());
        let c = cstr(&seen).expect("cstr");
        // SAFETY: umount2(2) of the bind just made.
        unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
        assert!(checked && !swapped, "the jail sees the checked folder: checked={checked} swapped={swapped}");
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
