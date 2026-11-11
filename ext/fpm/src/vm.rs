//! Layer 1 as a Firecracker microVM, the host side (addiscorp/securecore#71; the spike is #68,
//! the database path #70, `docs/layer1-microvm.md`). `securecore-fpm` drives Firecracker over
//! its API socket itself and is the guest's only way in or out: the guest has no network
//! device, only vsock. Firecracker runs under its jailer as an unprivileged user ([`crate::jail`]).
//!
//! ```text
//!   in    --listen (TCP, or a unix socket with php-fpm's listen.owner/group/mode) → vsock 9000
//!   out   guest port P → <jail>/v.sock_P: for a connect[].socket, a link to the socket in its
//!         folder bind-mounted into the jail (Firecracker connects as the jailed user), or a
//!         thread that connects to its TCP `address`. A port with neither is unreachable.
//!   log   guest port 1514 → this process's stderr, each line marked `guest: ` (read only)
//!   ctl   guest port 1515 ← one start message after each boot or restore (clock, fresh
//!         randomness, the workers' refresh after a restore, then the disks); later `sync`
//!         before a stop and `reload` on SIGUSR2/SIGHUP
//! ```
//!
//! Disks: vda the guest root (`rootfs.ext4`, read-only, shared); vdb the site, built from the
//! app root with `mke2fs -d` (read-only, rebuilt when the tree changes); vdc on one per
//! `layer1.write` folder inside the app root (read-write, `--write-disk-mib`, kept across
//! starts and grown when the size goes up). `write` folders outside the root are tmpfs.
//!
//! Only verified files boot: `<vm-dir>/installed.json` (written by the installer) must give the
//! sha256 of Firecracker, the jailer, the kernel and the root image, and they must match.
//!
//! Start: from a snapshot when there is one for this key ([`Key`]), else a cold boot that is
//! warmed up (the site's PHP files read into the guest's page cache; nothing is compiled or run,
//! and the VM has no way to the database while it warms) and snapshotted first, so the next
//! start restores. A restore
//! that fails falls back to a cold boot; a snapshot that can't be made leaves the cold-booted VM
//! serving.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use securecore_config::Loaded;
use sha2::{Digest as _, Sha256};

use crate::fcgi;
use crate::guest::{CTL_PORT, Ctl, FPM_PORT, LOG_PORT};
use crate::jail::{self, Jail, User};
use crate::vsock;

/// Where the installer puts the VM's files (`ext/install.sh`).
pub const DEFAULT_VM_DIR: &str = "/usr/local/share/securecore/vm";
/// Where each site's disks, snapshot and jail live, under a folder per app root.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/securecore/vm";
/// The user Firecracker runs as unless `--vm-user` says otherwise (the installer creates it).
pub const DEFAULT_VM_USER: &str = "securecore-vm";
/// Bumped whenever what goes into a guest changes shape (boot arguments, disks, the start
/// message), so old snapshots are never restored into a new driver.
const PROTOCOL: u32 = 2;
/// KVM_GET_API_VERSION, and the only value every KVM since Linux 2.6.22 returns.
const KVM_GET_API_VERSION: libc::c_ulong = 0xAE00;
const KVM_API_VERSION: i32 = 12;
/// The guest root image's warm-up script: reads the site's PHP files into the page cache.
pub const WARM_SCRIPT: &str = "/usr/local/lib/securecore/warm.php";
/// Symbols only a kernel with Landlock and with seccomp filters has (searched in `vmlinux`).
const LANDLOCK_SYMBOL: &[u8] = b"landlock_merge_ruleset\0";
const SECCOMP_SYMBOL: &[u8] = b"__seccomp_filter\0";

/// The files the microVM needs, all from `--vm-dir`: mirab's Firecracker, its jailer and kernel
/// (resolved by the release build, checked by the installer), the guest root image, and the
/// installer's record of their sha256s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assets {
    pub firecracker: PathBuf,
    pub jailer: PathBuf,
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub record: PathBuf,
}

impl Assets {
    pub fn in_dir(dir: &Path) -> Assets {
        Assets {
            firecracker: dir.join("firecracker"),
            jailer: dir.join("jailer"),
            kernel: dir.join("vmlinux"),
            rootfs: dir.join("rootfs.ext4"),
            record: dir.join("installed.json"),
        }
    }
}

fn on_path(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(program).is_file()))
}

/// Where FastCGI arrives on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listen {
    Unix(PathBuf),
    Tcp(String),
}

impl Listen {
    /// `unix:<path>` or `<host>:<port>`.
    pub fn parse(s: &str) -> Result<Listen, String> {
        if let Some(path) = s.strip_prefix("unix:") {
            return Ok(Listen::Unix(PathBuf::from(path)));
        }
        let (_, port) = s.rsplit_once(':').ok_or_else(|| format!("--listen {s}: want unix:<path> or <host>:<port>"))?;
        port.parse::<u16>().map_err(|_| format!("--listen {s}: {port} is not a port"))?;
        Ok(Listen::Tcp(s.to_owned()))
    }
}

impl std::fmt::Display for Listen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Listen::Unix(p) => write!(f, "unix:{}", p.display()),
            Listen::Tcp(a) => write!(f, "{a}"),
        }
    }
}

/// A unix `--listen` socket's owner, group and mode, as php-fpm's `listen.owner`,
/// `listen.group` and `listen.mode` (0660 by default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketMode {
    pub owner: Option<u32>,
    pub group: Option<u32>,
    pub mode: u32,
}

/// The launcher's VM options (flags in `main.rs`).
#[derive(Debug, Clone)]
pub struct Options {
    pub assets: Assets,
    pub kvm: PathBuf,
    /// This site's folder for disks, snapshot and jail (default: under [`DEFAULT_STATE_DIR`]).
    pub state: Option<PathBuf>,
    /// Default: `127.0.0.1:<the first layer1.network.bind port>`.
    pub listen: Option<Listen>,
    pub listen_mode: SocketMode,
    /// Where the guest mounts the site, i.e. the root nginx sends (default: the app root).
    pub guest_root: Option<String>,
    pub mem_mib: u32,
    pub vcpus: u32,
    /// The size of each writable folder's disk; a larger value grows existing disks.
    pub write_disk_mib: u64,
    /// `<uid>:<gid>` or a user name: who Firecracker runs as.
    pub vm_user: String,
    /// The site's pool user (default: the app root's owner).
    pub pool_user: Option<String>,
    /// Start from a snapshot (and make one when there is none). Off: cold boot every time.
    pub snapshot: bool,
    /// Extra guest boot arguments (e.g. `sc.ext=0`).
    pub guest_args: Vec<String>,
}

/// A writable folder inside the app root: its own disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteDisk {
    pub host: PathBuf,
    pub guest: String,
    /// The drive id and file name: `w` + 12 hex digits of the folder's path's sha256.
    pub id: String,
}

/// What the VM is, for one config: everything here is decided before anything boots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub root: PathBuf,
    pub guest_root: String,
    pub disks: Vec<WriteDisk>,
    /// Writable folders outside the app root, as guest paths (tmpfs). `/tmp` is always one.
    pub tmpfs: Vec<String>,
    /// Guest port → host unix socket (direct, through Firecracker).
    pub sockets: Vec<(u16, PathBuf)>,
    /// Guest port → host TCP address (through this process).
    pub addresses: Vec<(u16, String)>,
    /// `connect` ports the guest can't reach: no socket or address (egress is #72).
    pub unreachable: Vec<u16>,
    pub listen: Listen,
    pub state: PathBuf,
    /// The jail's id: `sc-` and 16 hex digits of the app root's sha256.
    pub id: String,
    /// The site's pool user: disks are copied as it, and the guest's pool runs as its uid/gid.
    pub pool: User,
}

fn no_space(what: &str, s: &str) -> Result<(), String> {
    if s.chars().any(char::is_whitespace) {
        return Err(format!("{what} {s:?} holds a space, which the guest's boot arguments can't carry"));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn sha_of(text: &str) -> String {
    hex(&Sha256::digest(text.as_bytes()))
}

/// Refuses a symlink anywhere from `root` (canonical) down to `path`: the launcher reads these
/// folders to build disks, and a link the site owner controls must never take it elsewhere.
fn no_link_beneath(root: &Path, path: &Path) -> Result<(), String> {
    let rel = path.strip_prefix(root).map_err(|_| format!("{} is not under {}", path.display(), root.display()))?;
    let mut at = root.to_path_buf();
    for c in rel.components() {
        match c {
            std::path::Component::Normal(name) => at.push(name),
            _ => return Err(format!("{} is not a plain path under the app root", path.display())),
        }
        match fs::symlink_metadata(&at) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(format!("{} is a symlink; a microVM's writable folder must be a real folder in the app root", at.display()));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("{}: {e}", at.display())),
        }
    }
    Ok(())
}

/// The microVM plan for `loaded`'s layer 1, or why it can't be one.
pub fn plan(loaded: &Loaded, opts: &Options) -> Result<Plan, String> {
    let layer1 = &loaded.config.layer1;
    let root = loaded.root.clone();
    let root_str = root.to_str().ok_or("the app root's path isn't UTF-8")?.to_owned();
    let guest_root = opts.guest_root.clone().unwrap_or_else(|| root_str.clone());
    no_space("the guest root", &guest_root)?;
    if !guest_root.starts_with('/') {
        return Err(format!("the guest root {guest_root:?} isn't absolute"));
    }
    if let Some(socket) = layer1.network.unix_sockets.first() {
        return Err(crate::Refusal::UnixSocketsInMicrovm { socket: loaded.resolve(socket).display().to_string() }.to_string());
    }
    for deny in &layer1.deny {
        let path = loaded.resolve(deny);
        if path.starts_with(&root) {
            return Err(format!(
                "layer1.deny {} is inside the app root, and the microVM's site disk is the whole root: \
                 move it out of the root (paths outside it are never in the guest)",
                path.display()
            ));
        }
    }
    let (mut disks, mut tmpfs) = (Vec::new(), Vec::new());
    for w in &layer1.write {
        if Path::new(w).components().any(|c| c == std::path::Component::ParentDir) {
            return Err(format!("layer1.write {w:?} holds \"..\": a microVM's writable folders are named without it"));
        }
        let host = loaded.resolve(w);
        if host.starts_with(&root) {
            no_link_beneath(&root, &host).map_err(|e| format!("layer1.write {w:?}: {e}"))?;
        }
        match host.strip_prefix(&root) {
            Ok(rel) if rel.as_os_str().is_empty() => return Err("layer1.write lists the app root itself; list its writable folders".into()),
            Ok(rel) => {
                if !host.is_dir() {
                    return Err(format!("layer1.write {}: no such folder; the guest mounts its disk there, so create it first", host.display()));
                }
                let guest = format!("{}/{}", guest_root.trim_end_matches('/'), rel.display());
                no_space("layer1.write", &guest)?;
                let id = format!("w{}", &sha_of(&guest)[..12]);
                disks.push(WriteDisk { host, guest, id });
            }
            Err(_) => {
                let guest = host.to_str().ok_or("a layer1.write path isn't UTF-8")?.to_owned();
                no_space("layer1.write", &guest)?;
                if guest != "/tmp" {
                    tmpfs.push(guest);
                }
            }
        }
    }
    let (mut sockets, mut addresses, mut unreachable) = (Vec::new(), Vec::new(), Vec::new());
    for c in &layer1.network.connect {
        let port = c.port.get();
        if u32::from(port) == LOG_PORT {
            return Err(format!(
                "layer1.network.connect port {LOG_PORT} is the guest's log channel to the host; a microVM can't forward it"
            ));
        }
        match (&c.socket, &c.address) {
            // Its real path: the launcher checks this path as the VM's user and bind-mounts this
            // path's folder, so a link can't make the two differ.
            (Some(s), _) => {
                let p = loaded.resolve(s);
                sockets.push((port, fs::canonicalize(&p).unwrap_or(p)));
            }
            (None, Some(a)) => addresses.push((port, a.clone())),
            (None, None) => unreachable.push(port),
        }
    }
    let listen = match &opts.listen {
        Some(l) => l.clone(),
        None => {
            let port = layer1.network.bind.first().ok_or(
                "layer1.network.bind is empty, so there is no port to take FastCGI on: list one, or pass --listen",
            )?;
            Listen::Tcp(format!("127.0.0.1:{}", port.port))
        }
    };
    let key = sha_of(&root_str);
    let state = opts.state.clone().unwrap_or_else(|| Path::new(DEFAULT_STATE_DIR).join(&key[..16]));
    let id = format!("sc-{}", &key[..16]);
    let pool = pool_user(opts, &root)?;
    Ok(Plan { root, guest_root, disks, tmpfs, sockets, addresses, unreachable, listen, state, id, pool })
}

/// The site's pool user: `--pool-user` (a name or `<uid>:<gid>`), or the app root's owner. Never
/// root: the disks are copied as this user, and the guest's php-fpm pool runs as it.
fn pool_user(opts: &Options, root: &Path) -> Result<User, String> {
    match &opts.pool_user {
        Some(spec) => jail::user(spec).map_err(|e| {
            e.replace("--vm-user", "--pool-user")
                .replace("Firecracker must not run as root", "the site's files are copied and served as this user, never root")
        }),
        None => {
            let m = fs::metadata(root).map_err(|e| format!("{}: {e}", root.display()))?;
            if m.uid() == 0 || m.gid() == 0 {
                return Err(format!(
                    "the app root {} is owned by root, so the site's pool user isn't known: pass --pool-user <name>|<uid>:<gid> (php-fpm's pool user)",
                    root.display()
                ));
            }
            Ok(User { uid: m.uid(), gid: m.gid() })
        }
    }
}

/// The site tree's sha256 (every entry's path, type, mode, owner, size, mtime and link target,
/// in order, skipping the writable folders and the state folder), the bytes it really uses on
/// disk (allocated blocks, as `du`), and its entry count.
pub fn site_sha256(root: &Path, skip: &BTreeSet<PathBuf>) -> io::Result<(String, u64, u64)> {
    let mut h = Sha256::new();
    let (mut bytes, mut entries) = (0u64, 0u64);
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut list: Vec<_> = fs::read_dir(&dir)?.collect::<Result<_, _>>()?;
        list.sort_by_key(|e| e.file_name());
        for e in list {
            let path = e.path();
            if skip.contains(&path) {
                continue;
            }
            let m = fs::symlink_metadata(&path)?;
            let rel = path.strip_prefix(root).unwrap_or(&path);
            let link = if m.file_type().is_symlink() { fs::read_link(&path)?.display().to_string() } else { String::new() };
            // ctime too: a touch can put mtime back, but any change to a file moves its ctime.
            h.update(format!(
                "{}\0{:o}\0{}\0{}\0{}\0{}.{}\0{}.{}\0{link}\n",
                rel.display(),
                m.mode(),
                m.uid(),
                m.gid(),
                m.size(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec()
            ));
            entries += 1;
            bytes += m.blocks() * 512;
            if m.is_dir() {
                stack.push(path);
            }
        }
    }
    Ok((hex(&h.finalize()), bytes, entries))
}

/// A big file's sha256, cached in `<state>/sha256.cache` by path, device, inode, size and
/// mtime, so the 1 GiB root image isn't read on every start.
fn file_sha256(state: &Path, path: &Path) -> io::Result<String> {
    let m = fs::metadata(path)?;
    let stamp = format!("{} {} {} {}.{} {}", m.dev(), m.ino(), m.size(), m.mtime(), m.mtime_nsec(), path.display());
    let cache = state.join("sha256.cache");
    let old = fs::read_to_string(&cache).unwrap_or_default();
    if let Some(sha) = old.lines().find_map(|l| l.split_once(' ').filter(|(_, rest)| *rest == stamp).map(|(s, _)| s.to_owned())) {
        return Ok(sha);
    }
    let mut h = Sha256::new();
    let mut f = fs::File::open(path)?;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let sha = hex(&h.finalize());
    let mut kept: Vec<&str> = old.lines().filter(|l| !l.ends_with(&format!(" {}", path.display()))).collect();
    let line = format!("{sha} {stamp}");
    kept.push(&line);
    fs::write(&cache, kept.join("\n") + "\n")?;
    Ok(sha)
}

/// The sha256s the installer recorded (`installed.json`), by file.
fn recorded(record: &Path) -> Result<serde_json::Value, String> {
    let text = fs::read_to_string(record).map_err(|e| {
        format!("{}: {e}; nothing verified is installed (the installer checks and records the microVM's files)", record.display())
    })?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", record.display()))
}

/// Every file the VM boots matches the sha256 the installer recorded for it: Firecracker, the
/// jailer, the kernel and the root image. A file the record doesn't name is not verified.
pub fn verify(assets: &Assets, state: &Path) -> Result<Key0, String> {
    let rec = recorded(&assets.record)?;
    let mut shas = Vec::new();
    for (key, path, what) in [
        ("firecracker_sha256", &assets.firecracker, "Firecracker"),
        ("jailer_sha256", &assets.jailer, "the jailer"),
        ("kernel_sha256", &assets.kernel, "the guest kernel"),
        ("rootfs_sha256", &assets.rootfs, "the guest root image"),
    ] {
        let want = rec[key].as_str().ok_or_else(|| {
            format!("{what} isn't verified: {} records no {key}", assets.record.display())
        })?;
        let got = file_sha256(state, path).map_err(|e| format!("{what} {}: {e}", path.display()))?;
        if got != want {
            return Err(format!(
                "{what} {} has sha256 {got}, but {} records {want}: refusing to boot it",
                path.display(),
                assets.record.display()
            ));
        }
        shas.push(got);
    }
    Ok(Key0 { firecracker: shas[0].clone(), jailer: shas[1].clone(), kernel: shas[2].clone(), rootfs: shas[3].clone() })
}

/// The verified files' sha256s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key0 {
    pub firecracker: String,
    pub jailer: String,
    pub kernel: String,
    pub rootfs: String,
}

/// Whether the guest kernel has Landlock and seccomp filters, which layer 3's isolated
/// children need (gelada). Read from the kernel's symbols; a kernel without them (or stripped)
/// is refused for a config with layer 3 on.
pub fn kernel_supports_layer3(kernel: &Path) -> Result<(), String> {
    let bytes = fs::read(kernel).map_err(|e| format!("{}: {e}", kernel.display()))?;
    let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    let mut missing = Vec::new();
    if !has(LANDLOCK_SYMBOL) {
        missing.push("Landlock");
    }
    if !has(SECCOMP_SYMBOL) {
        missing.push("seccomp filters");
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "layer 3 is on, but the guest kernel {} has no {} (its isolated children would fail closed; mirab#89 adds them)",
            kernel.display(),
            missing.join(" and ")
        ))
    }
}

/// Whether this host can run `loaded`'s layer 1 as a microVM. `Err` says why not, for `auto`'s
/// log line and `microvm`'s refusal:
/// - the launcher is root (the jailer needs it), and the jailed user exists and isn't root;
/// - `kvm` opens read-write and answers KVM_GET_API_VERSION with 12;
/// - Firecracker, the jailer, the kernel and the root image match the installer's record;
/// - the config is one a microVM can enforce ([`plan`]), and each `connect[].socket` is a
///   socket the jailed user may open itself;
/// - with layer 3 on, the kernel has Landlock and seccomp;
/// - cgroup v2, and `mke2fs`, `e2fsck` and `resize2fs` on PATH.
pub fn available(loaded: &Loaded, opts: &Options) -> Result<(), String> {
    // SAFETY: geteuid(2) takes nothing and can't fail.
    if unsafe { libc::geteuid() } != 0 {
        return Err("the microVM's jailer needs the launcher to run as root".into());
    }
    let user = jail::user(&opts.vm_user)?;
    let dev = OpenOptions::new().read(true).write(true).open(&opts.kvm).map_err(|e| format!("{}: {e}", opts.kvm.display()))?;
    // SAFETY: KVM_GET_API_VERSION takes no argument and returns an int; the fd is open.
    let v = unsafe { libc::ioctl(dev.as_raw_fd(), KVM_GET_API_VERSION, 0) };
    if v != KVM_API_VERSION {
        return Err(format!("{}: KVM_GET_API_VERSION returned {v}, not {KVM_API_VERSION}", opts.kvm.display()));
    }
    for tool in ["mke2fs", "e2fsck", "resize2fs"] {
        if !on_path(tool) {
            return Err(format!("{tool} (e2fsprogs) isn't on PATH; it builds and grows the site's disks"));
        }
    }
    let plan = plan(loaded, opts)?;
    fs::create_dir_all(&plan.state).map_err(|e| format!("{}: {e}", plan.state.display()))?;
    fs::set_permissions(&plan.state, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    verify(&opts.assets, &plan.state)?;
    if loaded.config.layer3.enabled {
        kernel_supports_layer3(&opts.assets.kernel)?;
    }
    for (_, socket) in &plan.sockets {
        jail::can_connect_as(user, socket)?;
    }
    Jail::cgroup_parent()
}

/// What a snapshot is valid for. Two starts with the same key boot the same bytes the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub files: Key0,
    pub site: String,
    pub config: String,
    /// Everything else that shapes the guest: memory, vCPUs, boot arguments (without the
    /// clock), the drives in order and their sizes.
    pub machine: String,
}

impl Key {
    pub fn sha256(&self) -> String {
        sha_of(&format!(
            "securecore-fpm microvm {PROTOCOL}\nfirecracker {}\njailer {}\nkernel {}\nrootfs {}\nsite {}\nconfig {}\nmachine {}\n",
            self.files.firecracker, self.files.jailer, self.files.kernel, self.files.rootfs, self.site, self.config, self.machine
        ))
    }
}

fn log(message: &str) {
    eprintln!("securecore-fpm: {message}");
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

/// A JSON string literal, for the API bodies.
fn json_str(s: &str) -> String {
    serde_json::Value::String(s.to_owned()).to_string()
}

fn run_tool(cmd: &mut Command, what: &str) -> Result<(), String> {
    let out = cmd.stdin(Stdio::null()).output().map_err(|e| format!("{what}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{what}: {} {}", out.status, String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

fn cpath(p: &Path) -> Result<std::ffi::CString, String> {
    std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).map_err(|_| format!("{}: holds a NUL", p.display()))
}

/// The fds the copy's source folder and its output image get in `mke2fs`'s process
/// (`-d /proc/self/fd/200`, the device `/proc/self/fd/201`): both opened as root, so the pool
/// user needs no right on the root-only folders around them.
const SOURCE_FD: libc::c_int = 200;
const OUTPUT_FD: libc::c_int = 201;

/// Runs `cmd` as `who`, with no supplementary groups. With `source`, first (still root, in a
/// private mount namespace of its own) every folder in `masks` is covered by an empty read-only
/// tmpfs, and `source` is opened (after the masks, so they apply) as fd [`SOURCE_FD`]: the
/// command reads the tree through it, as `who`, so it sees only what `who` may read, never the
/// masked folders, and needs no search right on the folders above `source`.
fn as_user(cmd: &mut Command, who: User, source: Option<&Path>, masks: &[PathBuf], output: Option<&fs::File>) -> Result<(), String> {
    let source = source.map(cpath).transpose()?;
    let output = output.map(|f| f.as_raw_fd());
    let masks: Vec<std::ffi::CString> = masks.iter().map(|m| cpath(m)).collect::<Result<_, _>>()?;
    let (tmpfs, none) = (c"tmpfs", c"none");
    let data = c"mode=0755,size=4k";
    // SAFETY: only syscalls between fork and exec, on strings made before the fork.
    unsafe {
        cmd.pre_exec(move || {
            let err = || Err(io::Error::last_os_error());
            if let Some(src) = &source {
                if !masks.is_empty() {
                    if libc::unshare(libc::CLONE_NEWNS) < 0 {
                        return err();
                    }
                    if libc::mount(none.as_ptr(), c"/".as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) < 0 {
                        return err();
                    }
                    for m in &masks {
                        let flags = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
                        if libc::mount(tmpfs.as_ptr(), m.as_ptr(), tmpfs.as_ptr(), flags, data.as_ptr().cast()) < 0 {
                            return err();
                        }
                    }
                }
                let fd = libc::open(src.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW);
                if fd < 0 || libc::dup2(fd, SOURCE_FD) < 0 {
                    return err();
                }
            }
            if let Some(out) = output
                && libc::dup2(out, OUTPUT_FD) < 0
            {
                return err();
            }
            if libc::setgroups(0, std::ptr::null()) < 0 || libc::setgid(who.gid) < 0 || libc::setuid(who.uid) < 0 {
                return err();
            }
            Ok(())
        });
    }
    Ok(())
}

/// `mke2fs -d <from>` into `<to>` (through a temporary name), `mb` MiB, the copy made as
/// `who` (the site's pool user, [`as_user`]) with `masks` left out, and the image's root owned
/// like `<from>`.
fn mke2fs(who: User, from: &Path, masks: &[PathBuf], to: &Path, mb: u64, inodes: u64, journal: bool) -> Result<(), String> {
    let tmp = to.with_extension("ext4.new");
    let _ = fs::remove_file(&tmp);
    // Made and opened here, owned by `who`, and handed to mke2fs (as `who`) as an fd.
    let out = {
        use std::os::unix::fs::OpenOptionsExt as _;
        let f = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::os::unix::fs::fchown(&f, Some(who.uid), Some(who.gid)).map_err(|e| e.to_string())?;
        f
    };
    let m = fs::symlink_metadata(from).map_err(|e| format!("{}: {e}", from.display()))?;
    if !m.is_dir() {
        return Err(format!("{} is not a folder", from.display()));
    }
    let mut cmd = Command::new("mke2fs");
    cmd.args(["-q", "-F", "-t", "ext4", "-b", "4096", "-m", "0"]).arg("-N").arg(inodes.to_string());
    if !journal {
        cmd.args(["-O", "^has_journal"]);
    }
    cmd.arg("-E").arg(format!("root_owner={}:{}", m.uid(), m.gid())).arg("-d").arg(format!("/proc/self/fd/{SOURCE_FD}"));
    cmd.arg(format!("/proc/self/fd/{OUTPUT_FD}")).arg(format!("{mb}M"));
    as_user(&mut cmd, who, Some(from), masks, Some(&out))?;
    if let Err(e) = run_tool(&mut cmd, &format!("mke2fs {} (copying {} as uid {})", to.display(), from.display(), who.uid)) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fs::rename(&tmp, to).map_err(|e| format!("{}: {e}", to.display()))
}

/// The site's read-only disk for this tree, built when it isn't there yet (older ones removed):
/// the app root without its writable folders (only their mount points), copied as the pool user.
/// Readable by the jailed group only: it holds the site's files, wp-config.php included.
fn site_disk(plan: &Plan, sha: &str, bytes: u64, entries: u64, user: User) -> Result<PathBuf, String> {
    let path = plan.state.join(format!("site-{}.ext4", &sha[..16]));
    if !path.is_file() {
        let t = Instant::now();
        // What the tree uses on disk, plus a third for ext4's own blocks and directories, plus 64 MiB.
        let mb = bytes * 4 / 3 / (1 << 20) + 64;
        let masks: Vec<PathBuf> = plan.disks.iter().map(|d| d.host.clone()).collect();
        mke2fs(plan.pool, &plan.root, &masks, &path, mb, entries * 2 + 1024, false)?;
        log(&format!("built the site disk {} ({mb} MiB, {entries} entries) in {:.0} ms", path.display(), ms(t)));
        for e in fs::read_dir(&plan.state).map_err(|e| e.to_string())?.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with("site-") && e.path() != path {
                let _ = fs::remove_file(e.path());
            }
        }
    }
    std::os::unix::fs::chown(&path, Some(0), Some(user.gid)).map_err(|e| e.to_string())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).map_err(|e| e.to_string())?;
    Ok(path)
}

/// A writable folder's disk, `mib` MiB: made once from the folder's contents, then kept (the
/// guest's writes live there; syncing them back is addiscorp/securecore#72), and grown in place
/// (`e2fsck` + `resize2fs`, offline: it isn't mounted before the guest's start message) when
/// `mib` is more than it has. Owned by the jailed user, private.
fn write_disk(plan: &Plan, disk: &WriteDisk, mib: u64, user: User) -> Result<PathBuf, String> {
    let path = plan.state.join(format!("{}.ext4", disk.id));
    let want = mib << 20;
    if !path.is_file() {
        let (_, bytes, entries) = site_sha256(&disk.host, &BTreeSet::new()).map_err(|e| format!("{}: {e}", disk.host.display()))?;
        if bytes + (64 << 20) > want {
            return Err(format!(
                "{} holds {} MiB, which doesn't fit a {mib} MiB writable disk: raise --write-disk-mib",
                disk.host.display(),
                bytes >> 20
            ));
        }
        mke2fs(plan.pool, &disk.host, &[], &path, mib, (entries * 2 + 4096).max(16384), true)?;
        log(&format!("made the writable disk {} for {} ({mib} MiB)", path.display(), disk.guest));
    } else {
        let have = fs::metadata(&path).map_err(|e| e.to_string())?.len();
        if have < want {
            // The guest wrote this image: root never parses it. e2fsck and resize2fs run as the
            // VM's user, on the image root opened for them (no link followed).
            use std::os::unix::fs::OpenOptionsExt as _;
            let img = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            let via = format!("/proc/self/fd/{OUTPUT_FD}");
            let mut fsck = Command::new("e2fsck");
            fsck.args(["-f", "-y", &via]);
            as_user(&mut fsck, user, None, &[], Some(&img))?;
            run_tool(&mut fsck, "e2fsck").or_else(|e| if e.contains("exit status: 1") { Ok(()) } else { Err(e) })?;
            img.set_len(want).map_err(|e| e.to_string())?;
            let mut resize = Command::new("resize2fs");
            resize.arg(&via);
            as_user(&mut resize, user, None, &[], Some(&img))?;
            run_tool(&mut resize, "resize2fs")?;
            log(&format!("grew the writable disk {} for {} from {} to {mib} MiB", path.display(), disk.guest, have >> 20));
        } else if have > want {
            log(&format!(
                "the writable disk {} is {} MiB, more than --write-disk-mib {mib}: disks only grow; keeping it",
                path.display(),
                have >> 20
            ));
        }
    }
    std::os::unix::fs::chown(&path, Some(user.uid), Some(user.gid)).map_err(|e| e.to_string())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    Ok(path)
}

/// `<state>/site.json` names the app root a state folder belongs to. A folder of another root
/// is refused while that root exists (two sites, one disk), and adopted when it is gone (the
/// site moved and the operator pointed `--state-dir` at its old state). A new site whose
/// writable disks don't exist yet is refused while a state folder beside it holds the writable
/// disks of a root that no longer exists: that is most likely this site, moved, and starting
/// empty would hide its uploads.
fn claim_state(plan: &Plan) -> Result<(), String> {
    let mine = plan.state.join("site.json");
    let root = plan.root.display().to_string();
    let read_root = |p: &Path| -> Option<String> {
        let v: serde_json::Value = serde_json::from_str(&fs::read_to_string(p).ok()?).ok()?;
        v["root"].as_str().map(str::to_owned)
    };
    if let Some(theirs) = read_root(&mine)
        && theirs != root
    {
        if Path::new(&theirs).exists() {
            return Err(format!(
                "the state folder {} belongs to the site at {theirs}, which still exists: give this site its own --state-dir",
                plan.state.display()
            ));
        }
        log(&format!("adopting the state of the site that was at {theirs} (it no longer exists)"));
    }
    let new_disks = plan.disks.iter().any(|d| !plan.state.join(format!("{}.ext4", d.id)).is_file());
    if new_disks && let Some(parent) = plan.state.parent() {
        {
            for e in fs::read_dir(parent).into_iter().flatten().flatten() {
                let dir = e.path();
                if dir == plan.state {
                    continue;
                }
                let Some(other) = read_root(&dir.join("site.json")) else { continue };
                let has_disks = fs::read_dir(&dir)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .any(|f| f.file_name().to_string_lossy().starts_with('w') && f.file_name().to_string_lossy().ends_with(".ext4"));
                if has_disks && !Path::new(&other).exists() {
                    return Err(format!(
                        "{} holds the writable disks (uploads) of the site that was at {other}, which no longer exists. \
                         If this site moved from there, start it with --state-dir {} to keep them; if not, remove that \
                         folder. Starting empty would hide them",
                        dir.display(),
                        dir.display()
                    ));
                }
            }
        }
    }
    fs::write(&mine, serde_json::json!({ "root": root }).to_string()).map_err(|e| format!("{}: {e}", mine.display()))
}

/// One request on Firecracker's API socket. Errors carry Firecracker's own fault message.
fn api(sock: &Path, method: &str, path: &str, body: &str) -> Result<(), String> {
    let mut s = UnixStream::connect(sock).map_err(|e| format!("{}: {e}", sock.display()))?;
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).map_err(|e| format!("{method} {path}: {e}"))?;
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).map_err(|e| format!("{method} {path}: {e}"))? == 0 {
            return Err(format!("{method} {path}: connection closed"));
        }
        head.push(b[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let len = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut resp = vec![0u8; len];
    s.read_exact(&mut resp).map_err(|e| format!("{method} {path}: {e}"))?;
    let status = head.split_whitespace().nth(1).unwrap_or("");
    if status.starts_with('2') {
        Ok(())
    } else {
        Err(format!("{method} {path}: HTTP {status} {}", String::from_utf8_lossy(&resp)))
    }
}

/// The guest's boot arguments, without the clock (that part goes into no key).
fn boot_args(plan: &Plan, opts: &Options) -> String {
    // mirab's (src/isolation/firecracker.ts): the i8042 flags skip a 500 ms keyboard probe.
    // Firecracker adds root=/dev/vda ro for a read-only root drive.
    let mut a = format!(
        "console=ttyS0 reboot=k panic=1 pci=off init=/sbin/securecore-init i8042.noaux i8042.nokbd i8042.nopnp \
         i8042.dumbkbd quiet loglevel=1 sc.root={} sc.user={}:{}",
        plan.guest_root, plan.pool.uid, plan.pool.gid
    );
    let ports: Vec<String> = plan.sockets.iter().map(|(p, _)| p).chain(plan.addresses.iter().map(|(p, _)| p)).map(u16::to_string).collect();
    if !ports.is_empty() {
        let _ = write!(a, " sc.ports={}", ports.join(","));
    }
    for (port, socket) in &plan.sockets {
        let s = socket.display().to_string();
        if s.starts_with("/run/") && !s.chars().any(char::is_whitespace) {
            let _ = write!(a, " sc.sock={port}:{s}");
        }
    }
    for x in &opts.guest_args {
        a.push(' ');
        a.push_str(x);
    }
    a
}

/// Paths inside the jail.
const IN_API: &str = "/fc.sock";
const IN_VSOCK: &str = "/v.sock";
const IN_KERNEL: &str = "/vmlinux";
const IN_ROOTFS: &str = "/rootfs.ext4";
const IN_SITE: &str = "/site.ext4";
const IN_SNAP: &str = "/snap";
const IN_SNAP_NEW: &str = "/snap-new";

/// A running, jailed Firecracker. Killed when dropped.
struct Vm {
    child: Option<Child>,
    pid: i32,
    api: PathBuf,
    vsock: PathBuf,
    /// The jail root, held open: the sockets in it are reached as `/proc/self/fd/<n>/<name>`,
    /// so their paths stay under the 108 bytes a unix socket address holds, however deep the
    /// state folder is.
    _root: fs::File,
    /// Emptied (bind mounts unmounted first) when the VM is dropped, on every path out.
    jail: Jail,
}

/// An `O_PATH` handle on `dir` and the short path prefix that reaches into it.
fn short_dir(dir: &Path) -> Result<(fs::File, PathBuf), String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let prefix = PathBuf::from(format!("/proc/self/fd/{}", f.as_raw_fd()));
    Ok((f, prefix))
}

impl Drop for Vm {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        } else if !FIRECRACKER_EXITED.load(Ordering::SeqCst) {
            // SAFETY: kill(2) on the Firecracker this VM started (its Child was handed to the
            // waiter thread, which hasn't reaped it: it would have said so).
            unsafe { libc::kill(self.pid, libc::SIGKILL) };
            thread::sleep(Duration::from_millis(50));
        }
        if let Err(e) = self.jail.clear() {
            log(&format!("clearing the jail: {e}"));
        }
    }
}

/// Everything the driver has decided before booting: the files, the drives and the key.
struct Machine {
    site: PathBuf,
    disks: Vec<(String, PathBuf)>,
    args: String,
    key: String,
    user: User,
}

/// What a jail holds for one spawn: the host ends of the guest's ports come with it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wiring {
    /// The guest's ports to the host's sockets and addresses, and its log.
    Full,
    /// Its log only: the VM warmed up for a snapshot reaches nothing else (no database).
    LogOnly,
}

impl Vm {
    /// A fresh jail with this machine's files (and `snap`'s, to restore it), then the jailer.
    /// A spawn that fails leaves no jail behind (nothing stays mounted).
    fn spawn(plan: &Plan, opts: &Options, m: &Machine, wiring: Wiring, snap: Option<&Path>) -> Result<Vm, String> {
        let j = Jail::new(&plan.state, &plan.id, m.user);
        Vm::spawn_in(&j, plan, opts, m, wiring, snap).inspect_err(|_| {
            let _ = j.clear();
        })
    }

    fn spawn_in(j: &Jail, plan: &Plan, opts: &Options, m: &Machine, wiring: Wiring, snap: Option<&Path>) -> Result<Vm, String> {
        j.prepare()?;
        j.place(&opts.assets.kernel, IN_KERNEL)?;
        j.place(&opts.assets.rootfs, IN_ROOTFS)?;
        j.place(&m.site, IN_SITE)?;
        for (id, path) in &m.disks {
            j.place(path, &format!("/{id}.ext4"))?;
        }
        // Every folder Firecracker uses is made here, as root, before it runs: nothing below is
        // created by root inside the jail while the jailed user is in it.
        if let Some(snap) = snap {
            j.user_dir(IN_SNAP)?;
            j.place(&snap.join("vm.snap"), &format!("{IN_SNAP}/vm.snap"))?;
            j.place(&snap.join("vm.mem"), &format!("{IN_SNAP}/vm.mem"))?;
        }
        if wiring == Wiring::LogOnly {
            j.user_dir(IN_SNAP_NEW)?;
        }
        let (root, short) = short_dir(&j.root)?;
        wire(plan, j, &short, m.user, wiring)?;
        let mut cmd = j.command(&opts.assets.jailer, &opts.assets.firecracker, opts.vcpus, opts.mem_mib, &["--api-sock", IN_API]);
        // stdout and stderr together, through a pipe, into a capped console.log.
        let (rd, wr) = std::io::pipe().map_err(|e| format!("pipe: {e}"))?;
        let wr2 = wr.try_clone().map_err(|e| e.to_string())?;
        cmd.stdin(Stdio::null()).stdout(wr).stderr(wr2);
        let child = cmd.spawn().map_err(|e| format!("{}: {e}", opts.assets.jailer.display()))?;
        drop(cmd);
        let console = plan.state.join("console.log");
        thread::spawn(move || console_writer(rd, console, CONSOLE_CAP));
        let pid = child.id() as i32;
        let _ = fs::write(j.base.join("firecracker.pid"), pid.to_string());
        let inside = |p: &str| short.join(p.trim_start_matches('/'));
        let mut vm = Vm { child: Some(child), pid, api: inside(IN_API), vsock: inside(IN_VSOCK), _root: root, jail: j.clone() };
        let t = Instant::now();
        while UnixStream::connect(&vm.api).is_err() {
            if let Some(st) = vm.exited() {
                return Err(format!("the jailer exited ({st}) before Firecracker's API came up; see {}", plan.state.join("console.log").display()));
            }
            if t.elapsed() > Duration::from_secs(5) {
                return Err("Firecracker's API socket did not appear in 5 s".into());
            }
            thread::sleep(Duration::from_micros(500));
        }
        Ok(vm)
    }

    fn api(&self, method: &str, path: &str, body: &str) -> Result<(), String> {
        api(&self.api, method, path, body)
    }

    fn exited(&mut self) -> Option<String> {
        match self.child.as_mut().map(Child::try_wait) {
            Some(Ok(Some(st))) => Some(st.to_string()),
            _ => None,
        }
    }

    /// Waits until php-fpm in the guest answers its ping over vsock.
    fn wait_ready(&mut self, state: &Path, timeout: Duration) -> Result<(), String> {
        let t = Instant::now();
        loop {
            let r = vsock::connect_through(&self.vsock, FPM_PORT, Duration::from_secs(2)).and_then(|mut s| {
                s.set_read_timeout(Some(Duration::from_secs(2)))?;
                fcgi::ping(&mut s)
            });
            match r {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if let Some(st) = self.exited() {
                        return Err(format!("Firecracker exited ({st}) before php-fpm answered; see {}", state.join("console.log").display()));
                    }
                    if t.elapsed() > timeout {
                        return Err(format!("php-fpm did not answer over vsock in {} s: {e}", timeout.as_secs()));
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }
}

fn now() -> (i64, u32) {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (d.as_secs() as i64, d.subsec_nanos())
}

fn cold_boot(plan: &Plan, opts: &Options, m: &Machine, wiring: Wiring) -> Result<Vm, String> {
    let vm = Vm::spawn(plan, opts, m, wiring, None)?;
    vm.api("PUT", "/machine-config", &format!(r#"{{"vcpu_count":{},"mem_size_mib":{},"smt":false}}"#, opts.vcpus, opts.mem_mib))?;
    let args = format!("{} sc.time={}", m.args, now().0);
    vm.api("PUT", "/boot-source", &format!(r#"{{"kernel_image_path":{},"boot_args":{}}}"#, json_str(IN_KERNEL), json_str(&args)))?;
    let mut drives = vec![("rootfs".to_owned(), IN_ROOTFS.to_owned(), true, true), ("site".to_owned(), IN_SITE.to_owned(), false, true)];
    drives.extend(m.disks.iter().map(|(id, _)| (id.clone(), format!("/{id}.ext4"), false, false)));
    for (id, path, root, ro) in drives {
        // A writable disk passes the guest's flushes on to the host's disk (fsync); Firecracker's
        // default ("Unsafe") drops them.
        let cache = if ro { "Unsafe" } else { "Writeback" };
        vm.api(
            "PUT",
            &format!("/drives/{id}"),
            &format!(
                r#"{{"drive_id":"{id}","path_on_host":{},"is_root_device":{root},"is_read_only":{ro},"cache_type":"{cache}"}}"#,
                json_str(&path)
            ),
        )?;
    }
    vm.api("PUT", "/vsock", &format!(r#"{{"guest_cid":3,"uds_path":{}}}"#, json_str(IN_VSOCK)))?;
    vm.api("PUT", "/actions", r#"{"action_type":"InstanceStart"}"#)?;
    Ok(vm)
}

fn restore(plan: &Plan, opts: &Options, m: &Machine, snap: &Path) -> Result<Vm, String> {
    let vm = Vm::spawn(plan, opts, m, Wiring::Full, Some(snap))?;
    vm.api(
        "PUT",
        "/snapshot/load",
        &format!(
            r#"{{"snapshot_path":{},"mem_backend":{{"backend_type":"File","backend_path":{}}},"resume_vm":true}}"#,
            json_str(&format!("{IN_SNAP}/vm.snap")),
            json_str(&format!("{IN_SNAP}/vm.mem"))
        ),
    )?;
    Ok(vm)
}

/// Pauses the VM and writes its snapshot (inside the jail, as the jailed user), then links it
/// out to `<snap>` (through a temporary folder).
fn snapshot(vm: &Vm, plan: &Plan, user: User, snap: &Path) -> Result<(), String> {
    let j = Jail::new(&plan.state, &plan.id, user);
    // Made before the VM started (spawn_in); the jailed user may have changed what is in it.
    let inside = j.host(IN_SNAP_NEW);
    vm.api("PATCH", "/vm", r#"{"state":"Paused"}"#)?;
    vm.api(
        "PUT",
        "/snapshot/create",
        &format!(
            r#"{{"snapshot_type":"Full","snapshot_path":{},"mem_file_path":{}}}"#,
            json_str(&format!("{IN_SNAP_NEW}/vm.snap")),
            json_str(&format!("{IN_SNAP_NEW}/vm.mem"))
        ),
    )?;
    let tmp = snap.with_extension("new");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    }
    fs::create_dir_all(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    for f in ["vm.snap", "vm.mem"] {
        take_out(&inside.join(f), &tmp.join(f), user).map_err(|e| format!("{f}: {e}"))?;
    }
    fs::rename(&tmp, snap).map_err(|e| format!("{}: {e}", snap.display()))
}

/// Links the file the jailed user wrote at `inside` to `out`, never through a link: opened with
/// O_NOFOLLOW, it must be a regular file the jailed user owns; it becomes root's, readable by the
/// jailed group only (a restore reads it, nothing in the jail may change it), and that very inode
/// is linked out (linkat AT_EMPTY_PATH). No copy: the jail and the state folder are one
/// filesystem.
fn take_out(inside: &Path, out: &Path, user: User) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(inside)
        .map_err(|e| format!("{}: {e}", inside.display()))?;
    let m = f.metadata().map_err(|e| e.to_string())?;
    if !m.is_file() || m.uid() != user.uid || m.nlink() != 1 {
        return Err(format!("{} is not a file the VM wrote (type, owner or links differ)", inside.display()));
    }
    std::os::unix::fs::fchown(&f, Some(0), Some(user.gid)).map_err(|e| e.to_string())?;
    f.set_permissions(fs::Permissions::from_mode(0o640)).map_err(|e| e.to_string())?;
    let dst = cpath(out)?;
    // SAFETY: linkat(2) of the open fd's inode (AT_EMPTY_PATH) to a NUL-terminated path.
    let r = unsafe { libc::linkat(f.as_raw_fd(), c"".as_ptr(), libc::AT_FDCWD, dst.as_ptr(), libc::AT_EMPTY_PATH) };
    if r < 0 {
        return Err(format!("linking out {}: {}", inside.display(), io::Error::last_os_error()));
    }
    Ok(())
}

/// The start message: the clock, fresh randomness, the workers' refresh after a restore, then
/// the writable disks and tmpfs folders.
fn start_message(plan: &Plan, restored: bool, entropy: [u8; 64]) -> Vec<Ctl> {
    let (secs, nanos) = now();
    let mut lines = vec![Ctl::Time { secs, nanos }, Ctl::Entropy { hex: hex(&entropy) }];
    if restored {
        lines.push(Ctl::Refresh);
    }
    // vda root, vdb site, then the writable disks in drive order.
    for (n, disk) in plan.disks.iter().enumerate() {
        let device = format!("/dev/vd{}", char::from(b'c' + n as u8));
        lines.push(Ctl::Mount { device, path: disk.guest.clone() });
    }
    lines.extend(plan.tmpfs.iter().map(|p| Ctl::Tmpfs { path: p.clone() }));
    lines.push(Ctl::Done);
    lines
}

/// 64 bytes from the host's CSPRNG (getrandom).
fn random64() -> Result<[u8; 64], String> {
    let mut b = [0u8; 64];
    // SAFETY: getrandom(2) fills at most b.len() bytes of b.
    let n = unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
    if n != b.len() as isize {
        return Err(format!("getrandom: {}", io::Error::last_os_error()));
    }
    Ok(b)
}

/// Sends `lines` (ending in [`Ctl::Done`]) to the guest's control port and waits up to
/// `timeout` for its `ok`.
fn tell_guest(uds: &Path, lines: &[Ctl], timeout: Duration) -> Result<(), String> {
    let t = Instant::now();
    let mut s = loop {
        match vsock::connect_through(uds, CTL_PORT, Duration::from_secs(2)) {
            Ok(s) => break s,
            Err(e) if t.elapsed() > timeout => return Err(format!("the guest's control port: {e}")),
            Err(_) => thread::sleep(Duration::from_millis(2)),
        }
    };
    let message: String = lines.iter().map(Ctl::line).collect();
    s.write_all(message.as_bytes()).map_err(|e| format!("the guest's control port: {e}"))?;
    s.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    let mut reply = String::new();
    BufReader::new(s).read_line(&mut reply).map_err(|e| format!("the guest's control port: {e}"))?;
    match reply.trim_end() {
        "ok" => Ok(()),
        other => Err(format!("the guest refused {:?}: {other}", lines.iter().map(|c| c.line().trim_end().split(' ').next().unwrap_or("").to_owned()).collect::<Vec<_>>())),
    }
}

/// How the VM came up, for the log.
enum Started {
    Restored { load_ms: f64 },
    Cold,
}

/// Reads the site's PHP files into the guest's page cache through php-fpm (the guest image's
/// warm-up script): nothing is compiled or run, so nothing reaches the database (the VM has no
/// way to it then) and opcache holds nothing compiled out of context.
fn warm_up(vm: &Vm, root: &str) -> Result<String, String> {
    let mut s = vsock::connect_through(&vm.vsock, FPM_PORT, Duration::from_secs(2)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(120))).map_err(|e| e.to_string())?;
    let out = fcgi::request(
        &mut s,
        &[
            ("REQUEST_METHOD", "GET"),
            ("SCRIPT_FILENAME", WARM_SCRIPT),
            ("SCRIPT_NAME", "/securecore-warm.php"),
            ("REQUEST_URI", "/securecore-warm.php"),
            ("SERVER_PROTOCOL", "HTTP/1.1"),
            ("SC_WARM_ROOT", root),
        ],
    )
    .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out);
    text.lines().find(|l| l.starts_with("read=")).map(str::to_owned).ok_or_else(|| format!("the warm-up answered {:?}", text.trim()))
}

/// Boots or restores the VM for `m`, by the rules in the module header.
fn snap_dir(plan: &Plan, m: &Machine) -> PathBuf {
    plan.state.join(format!("snap-{}", &m.key[..16]))
}

fn start(plan: &Plan, opts: &Options, m: &Machine) -> Result<(Vm, Started), String> {
    let snap = snap_dir(plan, m);
    let ready = Duration::from_secs(60);
    if opts.snapshot {
        if !snap.join("vm.mem").is_file() {
            let t = Instant::now();
            let mut vm = cold_boot(plan, opts, m, Wiring::LogOnly)?;
            vm.wait_ready(&plan.state, ready)?;
            match warm_up(&vm, &plan.guest_root) {
                Ok(n) => log(&format!("warmed the guest's page cache for the snapshot ({n})")),
                Err(e) => log(&format!("the warm-up failed ({e}); the snapshot has a cold page cache")),
            }
            match snapshot(&vm, plan, m.user, &snap) {
                Ok(()) => {
                    log(&format!("made the snapshot {} (key {}) in {:.0} ms", snap.display(), &m.key[..16], ms(t)));
                    for e in fs::read_dir(&plan.state).map_err(|e| e.to_string())?.flatten() {
                        let name = e.file_name().to_string_lossy().into_owned();
                        if name.starts_with("snap-") && e.path() != snap {
                            let _ = fs::remove_dir_all(e.path());
                        }
                    }
                }
                Err(e) => log(&format!("could not make a snapshot ({e}); cold-booting instead")),
            }
            drop(vm);
        }
        if snap.join("vm.mem").is_file() {
            let t = Instant::now();
            match restore(plan, opts, m, &snap).and_then(|mut vm| vm.wait_ready(&plan.state, Duration::from_secs(10)).map(|()| vm)) {
                Ok(vm) => return Ok((vm, Started::Restored { load_ms: ms(t) })),
                Err(e) => {
                    log(&format!("restoring {} failed ({e}); removing it and cold-booting instead", snap.display()));
                    let _ = fs::remove_dir_all(&snap);
                }
            }
        }
    }
    let mut vm = cold_boot(plan, opts, m, Wiring::Full)?;
    vm.wait_ready(&plan.state, ready)?;
    Ok((vm, Started::Cold))
}

/// Binds a unix socket at `path` with `mode` from the start (umask), never following a link at
/// `path` (bind fails on one, after the unlink of a stale socket), then sets its owner and
/// group without following one either (lchown).
fn bind_unix(path: &Path, mode: SocketMode) -> Result<UnixListener, String> {
    let _ = fs::remove_file(path);
    // SAFETY: umask(2) only swaps the process's mask; it is put back right after bind.
    let old = unsafe { libc::umask(!(mode.mode as libc::mode_t) & 0o777) };
    let l = UnixListener::bind(path);
    // SAFETY: as above.
    unsafe { libc::umask(old) };
    let l = l.map_err(|e| format!("{}: {e}", path.display()))?;
    if mode.owner.is_some() || mode.group.is_some() {
        std::os::unix::fs::lchown(path, mode.owner, mode.group).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(l)
}

/// The host ends of the guest's ports, in the jail: each `connect[].socket` as a link into its
/// folder bind-mounted read-only, each `address` as a listener here, and the log listener. The
/// jail was emptied first, so nothing from an earlier config is left.
fn wire(plan: &Plan, j: &Jail, short: &Path, user: User, wiring: Wiring) -> Result<(), String> {
    let owned = SocketMode { owner: Some(user.uid), group: Some(user.gid), mode: 0o600 };
    if wiring == Wiring::Full {
        for (port, socket) in &plan.sockets {
            let dir = socket.parent().ok_or_else(|| format!("{}: no folder", socket.display()))?;
            let name = socket.file_name().ok_or_else(|| format!("{}: no file name", socket.display()))?;
            let mount = format!("/sock-{port}");
            j.bind_dir(dir, &mount)?;
            let link = j.host(&format!("/v.sock_{port}"));
            std::os::unix::fs::symlink(Path::new(&mount[1..]).join(name), &link).map_err(|e| format!("{}: {e}", link.display()))?;
        }
        for (port, address) in &plan.addresses {
            let l = bind_unix(&short.join(format!("v.sock_{port}")), owned)?;
            let address = address.clone();
            let port = *port;
            let slots: &'static Slots = Box::leak(Box::new(Slots::new(FORWARD_SLOTS)));
            thread::spawn(move || {
                for c in l.incoming().flatten() {
                    let Some(slot) = slots.take() else {
                        log(&format!("guest port {port}: {FORWARD_SLOTS} connections already open; refusing another"));
                        continue;
                    };
                    let address = address.clone();
                    thread::spawn(move || {
                        let _slot = slot;
                        match TcpStream::connect(&address) {
                            Ok(t) => {
                                let _ = t.set_nodelay(true);
                                pipe_both(c, t);
                            }
                            Err(e) => log(&format!("guest port {port} → {address}: {e}")),
                        }
                    });
                }
            });
        }
    }
    // php-fpm's log, to this process's stderr: read only, and every line marked as the guest's,
    // so nothing the guest writes can pass for the launcher's own lines.
    let l = bind_unix(&short.join(format!("v.sock_{LOG_PORT}")), owned)?;
    thread::spawn(move || {
        for c in l.incoming().flatten() {
            let Some(slot) = LOG_SLOTS.take() else { continue };
            thread::spawn(move || {
                let _slot = slot;
                let _ = c.shutdown(std::net::Shutdown::Write);
                mark_guest_lines(c, &mut io::stderr());
            });
        }
    });
    Ok(())
}

/// Copies the guest's log to `to`, every line marked `guest: `, so no line the guest writes
/// reads as the launcher's own (`securecore-fpm: …`).
/// A line longer than [`MAX_LINE`] bytes is cut there (and marked), so the guest can't make the
/// launcher buffer without bound.
pub fn mark_guest_lines(from: impl Read, to: &mut impl Write) {
    let mut r = BufReader::new(from);
    let mut line: Vec<u8> = Vec::with_capacity(256);
    loop {
        line.clear();
        let mut cut = false;
        let mut eof = false;
        loop {
            let buf = match r.fill_buf() {
                Ok([]) => {
                    eof = true;
                    break;
                }
                Ok(b) => b,
                Err(_) => {
                    eof = true;
                    break;
                }
            };
            let (take, done) = match buf.iter().position(|&b| b == b'\n') {
                Some(i) => (i, true),
                None => (buf.len(), false),
            };
            let room = MAX_LINE.saturating_sub(line.len());
            line.extend_from_slice(&buf[..take.min(room)]);
            cut |= take > room;
            r.consume(if done { take + 1 } else { take });
            if done {
                break;
            }
        }
        if eof && line.is_empty() {
            return;
        }
        let text = String::from_utf8_lossy(&line);
        let _ = writeln!(to, "guest: {}{}", text.trim_end_matches('\r'), if cut { " …[cut]" } else { "" });
        if eof {
            return;
        }
    }
}

/// The longest guest log line kept whole.
pub const MAX_LINE: usize = 8 * 1024;

/// A fixed number of slots: a connection takes one or is turned away.
pub struct Slots(std::sync::atomic::AtomicUsize, usize);

impl Slots {
    pub const fn new(n: usize) -> Slots {
        Slots(std::sync::atomic::AtomicUsize::new(0), n)
    }
    pub fn take(&'static self) -> Option<SlotGuard> {
        if self.0.fetch_add(1, Ordering::SeqCst) >= self.1 {
            self.0.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(SlotGuard(self))
    }
}

pub struct SlotGuard(&'static Slots);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The guest's log connections at once (its php-fpm stream, and the init's short reports).
static LOG_SLOTS: Slots = Slots::new(4);
/// Connections through one `address` forward at once.
const FORWARD_SLOTS: usize = 64;

/// Copies both ways (each direction half-closing its destination at its end) and returns when
/// both are done: one thread for a → b, this one for b → a.
fn pipe_both<A: vsock::Half, B: vsock::Half>(a: A, b: B) {
    let (Ok(mut a2), Ok(mut b2)) = (a.dup(), b.dup()) else { return };
    let t = thread::spawn(move || {
        let mut a = a;
        let _ = io::copy(&mut a, &mut b2);
        b2.shut(std::net::Shutdown::Write);
    });
    let mut b = b;
    let _ = io::copy(&mut b, &mut a2);
    a2.shut(std::net::Shutdown::Write);
    let _ = t.join();
}

/// Firecracker's stdout and stderr to `<state>/console.log`, at most `cap` bytes in it: past that
/// the file moves to `console.log.1` (replacing an older one) and a new one starts.
fn console_writer(from: impl Read, path: PathBuf, cap: u64) {
    let open = |p: &Path| OpenOptions::new().create(true).write(true).truncate(true).open(p);
    let Ok(mut out) = open(&path) else { return };
    let mut written = 0u64;
    let mut from = from;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let mut rest = &buf[..n];
        while !rest.is_empty() {
            if written >= cap {
                let _ = fs::rename(&path, path.with_extension("log.1"));
                match open(&path) {
                    Ok(f) => out = f,
                    Err(_) => return,
                }
                written = 0;
            }
            let take = rest.len().min((cap - written) as usize);
            let _ = out.write_all(&rest[..take]);
            written += take as u64;
            rest = &rest[take..];
        }
    }
}

/// `console.log`'s cap.
const CONSOLE_CAP: u64 = 8 << 20;

fn serve<S: vsock::Half>(incoming: impl Iterator<Item = io::Result<S>>, uds: PathBuf) {
    for c in incoming.flatten() {
        match vsock::connect_through(&uds, FPM_PORT, Duration::from_secs(2)) {
            Ok(v) => {
                let _ = vsock::join(c, v);
            }
            Err(e) => log(&format!("FastCGI → vsock {FPM_PORT}: {e}")),
        }
    }
}

/// systemd's readiness notification (`Type=notify`): `READY=1` to `$NOTIFY_SOCKET`, a path or
/// (with a leading `@`) an abstract socket. Nothing when it isn't set.
pub fn notify_ready(socket: Option<&str>, pid: u32) -> io::Result<bool> {
    let Some(socket) = socket.filter(|s| !s.is_empty()) else { return Ok(false) };
    let d = UnixDatagram::unbound()?;
    let msg = format!("READY=1\nMAINPID={pid}\nSTATUS=serving FastCGI from the microVM\n");
    if let Some(name) = socket.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt as _;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
        d.send_to_addr(msg.as_bytes(), &addr)?;
    } else {
        d.send_to(msg.as_bytes(), socket)?;
    }
    Ok(true)
}

static QUITTING: AtomicBool = AtomicBool::new(false);
static FIRECRACKER_EXITED: AtomicBool = AtomicBool::new(false);
/// The host's wait for the guest to take its start message.
const START_TIMEOUT: Duration = Duration::from_secs(30);

/// The signals the launcher takes itself: TERM, INT and QUIT stop the VM (after a sync); USR2
/// and HUP reload the guest's php-fpm gracefully; USR1 (php-fpm's log reopen) is acknowledged:
/// the launcher writes only to stderr, so there is no file to reopen. Blocked before any
/// thread starts, so every thread inherits the mask and only `sigwait` sees them.
const SIGNALS: [libc::c_int; 6] = [libc::SIGTERM, libc::SIGINT, libc::SIGQUIT, libc::SIGHUP, libc::SIGUSR1, libc::SIGUSR2];

fn block_signals() -> libc::sigset_t {
    // SAFETY: sigemptyset/sigaddset/pthread_sigmask on a sigset_t we own.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in SIGNALS {
            libc::sigaddset(&mut set, s);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        set
    }
}

fn wait_for_signal(set: &libc::sigset_t) -> i32 {
    let mut sig = 0;
    // SAFETY: sigwait(3) on the set blocked above.
    unsafe { libc::sigwait(set, &mut sig) };
    sig
}

/// One launcher per state folder: an exclusive lock on `<state>/lock`, held until exit.
fn lock_state(state: &Path) -> Result<fs::File, String> {
    let f = OpenOptions::new().create(true).truncate(false).write(true).open(state.join("lock")).map_err(|e| e.to_string())?;
    // SAFETY: flock(2) on a file we hold open.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        return Err(format!(
            "another securecore-fpm runs this site's microVM ({} is locked)",
            state.join("lock").display()
        ));
    }
    Ok(f)
}

/// Runs php-fpm in the microVM until a stop signal. Returns only on failure (the launcher
/// exits 125) or after a clean stop (`Ok`).
pub fn run(loaded: &Loaded, opts: &Options) -> Result<(), String> {
    let set = block_signals();
    let t0 = Instant::now();
    let plan = plan(loaded, opts)?;
    let user = jail::user(&opts.vm_user)?;
    fs::create_dir_all(&plan.state).map_err(|e| format!("{}: {e}", plan.state.display()))?;
    fs::set_permissions(&plan.state, fs::Permissions::from_mode(0o700)).map_err(|e| format!("{}: {e}", plan.state.display()))?;
    let _lock = lock_state(&plan.state)?;
    // Before any thread: whatever ends this process, the VM ends with it.
    let jail = Jail::new(&plan.state, &plan.id, user);
    let mounts: Vec<PathBuf> = plan.sockets.iter().map(|(p, _)| jail.root.join(format!("sock-{p}"))).collect();
    let _watchdog = jail.watchdog(&mounts)?;
    claim_state(&plan)?;
    if !plan.unreachable.is_empty() {
        log(&format!(
            "layer1.network.connect ports {:?} have no socket or address, so the microVM can't reach them \
             (outbound connections from the guest are addiscorp/securecore#72)",
            plan.unreachable
        ));
    }
    let files = verify(&opts.assets, &plan.state)?;
    // The site's key: the tree without the writable folders, the state folder and the config
    // file, whose bytes are keyed by their own sha256 instead (copying the same file in again
    // changes its mtime, not the site).
    let mut skip: BTreeSet<PathBuf> = plan.disks.iter().map(|d| d.host.clone()).collect();
    skip.insert(plan.state.clone());
    skip.extend(loaded.path.file_name().map(|name| plan.root.join(name)));
    let (tree, bytes, entries) = site_sha256(&plan.root, &skip).map_err(|e| format!("{}: {e}", plan.root.display()))?;
    let site = sha_of(&format!("tree {tree}\nconfig {}\n", loaded.sha256));
    let site_path = site_disk(&plan, &site, bytes, entries, user)?;
    let mut disks = Vec::new();
    for d in &plan.disks {
        disks.push((d.id.clone(), write_disk(&plan, d, opts.write_disk_mib, user)?));
    }
    let args = boot_args(&plan, opts);
    let key = Key {
        files,
        site,
        config: loaded.sha256.clone(),
        machine: format!(
            "mem {} vcpus {} args {args} drives {} size {}",
            opts.mem_mib,
            opts.vcpus,
            disks.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>().join(","),
            opts.write_disk_mib
        ),
    };
    let m = Machine { site: site_path, disks, args, key: key.sha256(), user };
    let (mut vm, mut how) = start(&plan, opts, &m)?;
    let t_ready = ms(t0);
    let restored = matches!(how, Started::Restored { .. });
    if let Err(e) = tell_guest(&vm.vsock, &start_message(&plan, restored, random64()?), START_TIMEOUT) {
        if !restored {
            return Err(e);
        }
        // A snapshot that restores but can't start is as bad as one that doesn't restore.
        log(&format!("the restored guest failed its start message ({e}); removing the snapshot and cold-booting instead"));
        drop(vm);
        let _ = fs::remove_dir_all(snap_dir(&plan, &m));
        let mut cold = cold_boot(&plan, opts, &m, Wiring::Full)?;
        cold.wait_ready(&plan.state, Duration::from_secs(60))?;
        tell_guest(&cold.vsock, &start_message(&plan, false, random64()?), START_TIMEOUT)?;
        vm = cold;
        how = Started::Cold;
    }
    let t_started = ms(t0);
    match how {
        Started::Restored { load_ms } => log(&format!(
            "microVM restored from snapshot {} (load and php-fpm ping {load_ms:.1} ms); ready {t_ready:.0} ms, started {t_started:.0} ms after launch",
            &m.key[..16]
        )),
        Started::Cold => log(&format!("microVM cold-booted; ready {t_ready:.0} ms, started {t_started:.0} ms after launch")),
    }
    log(&format!("Firecracker runs jailed as uid {} gid {} (pid {})", user.uid, user.gid, vm.pid));
    let uds = vm.vsock.clone();
    match &plan.listen {
        Listen::Unix(path) => {
            // nginx must reach it: by default the pool user's group, as php-fpm's listen.group.
            let mode = SocketMode { group: opts.listen_mode.group.or(Some(plan.pool.gid)), ..opts.listen_mode };
            let l = bind_unix(path, mode)?;
            thread::spawn(move || serve(l.incoming(), uds.clone()));
        }
        Listen::Tcp(addr) => {
            let l = TcpListener::bind(addr).map_err(|e| format!("--listen {addr}: {e}"))?;
            thread::spawn(move || serve(l.incoming(), uds.clone()));
        }
    }
    log(&format!("serving FastCGI on {} (state {})", plan.listen, plan.state.display()));
    match notify_ready(std::env::var("NOTIFY_SOCKET").ok().as_deref(), std::process::id()) {
        Ok(true) => log("told systemd we are ready (NOTIFY_SOCKET)"),
        Ok(false) => {}
        Err(e) => log(&format!("could not notify systemd (NOTIFY_SOCKET): {e}")),
    }
    let mut child = vm.child.take().ok_or("no Firecracker")?;
    let state = plan.state.clone();
    thread::spawn(move || {
        let st = child.wait();
        if !QUITTING.load(Ordering::SeqCst) {
            log(&format!("Firecracker exited ({st:?}); see {}; stopping", state.join("console.log").display()));
            // The main thread stops as for a signal, so the jail is cleared on the way out.
            FIRECRACKER_EXITED.store(true, Ordering::SeqCst);
            // SAFETY: kill(2) to this process, whose main thread waits for SIGTERM.
            unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
        }
    });
    let sig = loop {
        let sig = wait_for_signal(&set);
        match sig {
            libc::SIGUSR1 => log("SIGUSR1: nothing to reopen (the launcher and the guest log to stderr)"),
            // In its own thread: a stop signal during a reload is handled at once, and its sync
            // reaches the guest on its own connection, never behind the reload.
            libc::SIGUSR2 | libc::SIGHUP => {
                let uds = vm.vsock.clone();
                thread::spawn(move || match tell_guest(&uds, &[Ctl::Reload, Ctl::Done], crate::guest::RELOAD_TIMEOUT) {
                    Ok(()) => log(&format!("signal {sig}: reloaded the guest's php-fpm gracefully")),
                    Err(e) => log(&format!("signal {sig}: the guest's php-fpm reload failed: {e}")),
                });
            }
            _ => break sig,
        }
    };
    QUITTING.store(true, Ordering::SeqCst);
    if FIRECRACKER_EXITED.load(Ordering::SeqCst) {
        drop(vm);
        return Err("Firecracker exited on its own; the jail is cleared".into());
    }
    // The guest's writes to the writable disks reach the host's images before the VM stops.
    if let Err(e) = tell_guest(&vm.vsock, &[Ctl::Sync, Ctl::Done], crate::guest::SYNC_TIMEOUT) {
        log(&format!("the guest did not sync its disks before the stop: {e}"));
    }
    // Stops Firecracker (still unreaped, so its pid is still its own) and empties the jail.
    drop(vm);
    if let Listen::Unix(p) = &plan.listen {
        let _ = fs::remove_file(p);
    }
    log(&format!("stopped by signal {sig}"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use securecore_config::Config;

    fn loaded(dir: &Path, layer1: &str) -> Loaded {
        let path = dir.join("securecore.json");
        let json = format!(r#"{{"layer1":{layer1},"layer2":{{"enabled":false}},"layer3":{{"enabled":false}}}}"#);
        fs::write(&path, &json).expect("write");
        let loaded = securecore_config::load(&path).expect("valid");
        assert_eq!(loaded.config, Config::from_slice(json.as_bytes()).expect("valid"));
        loaded
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("securecore-fpm-vm-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("wp-content/uploads")).expect("dirs");
        fs::canonicalize(&dir).expect("canonical")
    }

    fn opts() -> Options {
        Options {
            assets: Assets::in_dir(Path::new("/nonexistent")),
            kvm: PathBuf::from("/dev/kvm"),
            state: None,
            listen: None,
            listen_mode: SocketMode { owner: None, group: None, mode: 0o660 },
            guest_root: Some("/var/www/html".into()),
            mem_mib: 512,
            vcpus: 2,
            write_disk_mib: 1024,
            vm_user: "64000:64000".into(),
            pool_user: Some("33:33".into()),
            snapshot: true,
            guest_args: vec![],
        }
    }

    #[test]
    fn the_plan_maps_layer1_onto_disks_tmpfs_and_forwards() {
        let dir = scratch("plan");
        let l = loaded(
            &dir,
            r#"{"isolation":"microvm","write":["wp-content/uploads","/tmp","/var/cache/sc"],"deny":["/srv/backups"],
                "network":{"bind":[{"port":9000}],"connect":[{"port":3306,"socket":"/run/mysqld/mysqld.sock"},{"port":6379,"address":"10.0.0.5:6379"},{"port":443}]}}"#,
        );
        let p = plan(&l, &opts()).expect("plan");
        assert_eq!(p.disks.len(), 1);
        assert_eq!(p.disks[0].guest, "/var/www/html/wp-content/uploads", "a folder in the root, at the guest root");
        assert_eq!(p.disks[0].host, dir.join("wp-content/uploads"));
        assert_eq!(p.tmpfs, ["/var/cache/sc"], "outside the root: tmpfs; /tmp is always one");
        assert_eq!(p.sockets, [(3306, PathBuf::from("/run/mysqld/mysqld.sock"))]);
        assert_eq!(p.addresses, [(6379, "10.0.0.5:6379".to_owned())]);
        assert_eq!(p.unreachable, [443], "no socket or address: the guest can't reach it");
        assert_eq!(p.listen, Listen::Tcp("127.0.0.1:9000".into()), "the first bind port, on loopback");
        assert!(p.state.starts_with(DEFAULT_STATE_DIR));
        assert!(p.id.starts_with("sc-") && p.id.len() == 19, "{}", p.id);
        let args = boot_args(&p, &opts());
        assert!(args.contains(" sc.root=/var/www/html") && args.contains(" sc.ports=3306,6379"), "{args}");
        assert!(args.contains(" sc.user=33:33"), "the guest's pool runs as the host's pool user: {args}");
        assert!(args.contains(" sc.sock=3306:/run/mysqld/mysqld.sock"), "{args}");
        assert!(!args.contains("sc.time"), "the clock is in no key: {args}");
        let msg = start_message(&p, true, [7; 64]);
        assert!(matches!(msg[0], Ctl::Time { .. }), "the clock first");
        assert_eq!(msg[1], Ctl::Entropy { hex: "07".repeat(64) }, "then fresh randomness");
        assert_eq!(msg[2], Ctl::Refresh, "a restore replaces the workers forked before the snapshot");
        assert_eq!(msg[3], Ctl::Mount { device: "/dev/vdc".into(), path: "/var/www/html/wp-content/uploads".into() });
        assert_eq!(msg[4], Ctl::Tmpfs { path: "/var/cache/sc".into() });
        assert_eq!(msg.last(), Some(&Ctl::Done));
        assert!(!start_message(&p, false, [7; 64]).contains(&Ctl::Refresh), "a cold boot's workers are fresh");
        assert_ne!(random64().expect("random"), random64().expect("random"), "every start message gets its own");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_plan_refuses_what_a_microvm_cant_enforce() {
        let dir = scratch("refuse");
        let refused = |layer1: &str| plan(&loaded(&dir, layer1), &opts()).expect_err(layer1);
        let e = refused(r#"{"isolation":"microvm","network":{"bind":[{"port":9000}],"unixSockets":["/run/x.sock"]}}"#);
        assert!(e.contains("connect [{ \"port\": 3306, \"socket\": \"/run/x.sock\" }]"), "{e}");
        let e = refused(r#"{"isolation":"microvm","deny":["private"],"network":{"bind":[{"port":9000}]}}"#);
        assert!(e.contains("inside the app root"), "{e}");
        let e = refused(r#"{"isolation":"microvm","write":["wp-content/missing"],"network":{"bind":[{"port":9000}]}}"#);
        assert!(e.contains("no such folder"), "{e}");
        let e = refused(r#"{"isolation":"microvm"}"#);
        assert!(e.contains("layer1.network.bind is empty"), "{e}");
        let e = refused(r#"{"isolation":"microvm","network":{"bind":[{"port":9000}],"connect":[{"port":1514,"address":"127.0.0.1:1514"}]}}"#);
        assert!(e.contains("port 1514 is the guest's log channel"), "{e}");
        let mut o = opts();
        o.guest_root = Some("/var/www/my site".into());
        let e = plan(&loaded(&dir, r#"{"isolation":"microvm","network":{"bind":[{"port":9000}]}}"#), &o).expect_err("space");
        assert!(e.contains("holds a space"), "{e}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_site_key_changes_with_the_tree_but_not_with_uploads() {
        let dir = scratch("key");
        fs::write(dir.join("index.php"), "<?php echo 1;").expect("write");
        let skip: BTreeSet<PathBuf> = [dir.join("wp-content/uploads")].into();
        let (a, used, _) = site_sha256(&dir, &skip).expect("sha");
        assert!(used >= 4096, "what the tree really uses on disk: {used}");
        fs::write(dir.join("wp-content/uploads/photo.jpg"), "jpeg").expect("write");
        assert_eq!(site_sha256(&dir, &skip).expect("sha").0, a, "an upload is not a site change");
        fs::write(dir.join("index.php"), "<?php echo 2;").expect("write");
        assert_ne!(site_sha256(&dir, &skip).expect("sha").0, a, "an edit is");
        let files = Key0 { firecracker: "f".into(), jailer: "j".into(), kernel: "k".into(), rootfs: "r".into() };
        let k = Key { files: files.clone(), site: "s".into(), config: "c".into(), machine: "m".into() };
        for changed in [
            Key { files: Key0 { kernel: "k2".into(), ..files.clone() }, ..k.clone() },
            Key { files: Key0 { rootfs: "r2".into(), ..files.clone() }, ..k.clone() },
            Key { files: Key0 { jailer: "j2".into(), ..files.clone() }, ..k.clone() },
            Key { files: Key0 { firecracker: "f2".into(), ..files.clone() }, ..k.clone() },
            Key { site: "s2".into(), ..k.clone() },
            Key { config: "c2".into(), ..k.clone() },
            Key { machine: "m2".into(), ..k.clone() },
        ] {
            assert_ne!(changed.sha256(), k.sha256(), "{changed:?}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_files_the_installer_recorded_boot() {
        let dir = scratch("verify");
        let vm = dir.join("vm");
        fs::create_dir_all(&vm).expect("vm dir");
        let a = Assets::in_dir(&vm);
        for (f, body) in [(&a.firecracker, "fc"), (&a.jailer, "jailer"), (&a.kernel, "kernel"), (&a.rootfs, "rootfs")] {
            fs::write(f, body).expect("write");
        }
        let e = verify(&a, &dir).expect_err("no record");
        assert!(e.contains("nothing verified is installed"), "{e}");
        let sha = |s: &str| sha_of(s);
        let rec = |rootfs: Option<&str>| {
            let mut v = serde_json::json!({
                "firecracker_sha256": sha("fc"), "jailer_sha256": sha("jailer"), "kernel_sha256": sha("kernel")
            });
            if let Some(r) = rootfs {
                v["rootfs_sha256"] = r.into();
            }
            fs::write(&a.record, v.to_string()).expect("record");
        };
        rec(None);
        let e = verify(&a, &dir).expect_err("no rootfs in the record");
        assert!(e.contains("the guest root image isn't verified"), "{e}");
        rec(Some(&sha("rootfs")));
        let k = verify(&a, &dir).expect("all four match");
        assert_eq!(k.rootfs, sha("rootfs"));
        fs::write(&a.rootfs, "tampered").expect("write");
        let e = verify(&a, &dir).expect_err("tampered");
        assert!(e.contains("refusing to boot it"), "{e}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn layer3_needs_landlock_and_seccomp_in_the_kernel() {
        let dir = scratch("kernel");
        let k = dir.join("vmlinux");
        fs::write(&k, b"...__x64_sys_landlock_create_ruleset\0...").expect("write");
        let e = kernel_supports_layer3(&k).expect_err("syscall stubs alone aren't Landlock");
        assert!(e.contains("no Landlock and seccomp filters"), "{e}");
        fs::write(&k, b"..landlock_merge_ruleset\0..__seccomp_filter\0..").expect("write");
        kernel_supports_layer3(&k).expect("both");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_moved_sites_uploads_are_never_silently_left_behind() {
        let dir = scratch("orphan");
        let states = dir.join("states");
        let old = states.join("old");
        fs::create_dir_all(&old).expect("old state");
        fs::write(old.join("site.json"), serde_json::json!({ "root": "/srv/gone-site" }).to_string()).expect("site.json");
        fs::write(old.join("w0123456789ab.ext4"), "disk").expect("disk");
        let mut o = opts();
        o.state = Some(states.join("new"));
        let l = loaded(&dir, r#"{"isolation":"microvm","write":["wp-content/uploads"],"network":{"bind":[{"port":9000}]}}"#);
        let p = plan(&l, &o).expect("plan");
        fs::create_dir_all(&p.state).expect("state");
        let e = claim_state(&p).expect_err("an orphan beside it");
        assert!(e.contains("/srv/gone-site") && e.contains(&format!("--state-dir {}", old.display())), "{e}");
        // Adopting the old state: allowed, since its site is gone.
        let mut adopt = opts();
        adopt.state = Some(old.clone());
        let p = plan(&l, &adopt).expect("plan");
        claim_state(&p).expect("adopted");
        // Another live site's state: refused.
        fs::write(old.join("site.json"), serde_json::json!({ "root": dir.display().to_string() + "/wp-content" }).to_string()).expect("site.json");
        let e = claim_state(&p).expect_err("a live site's state");
        assert!(e.contains("still exists"), "{e}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_fastcgi_socket_gets_its_mode_from_the_start_and_never_follows_a_link() {
        let dir = scratch("listen");
        let path = dir.join("fpm.sock");
        let _l = bind_unix(&path, SocketMode { owner: None, group: None, mode: 0o660 }).expect("bind");
        assert_eq!(fs::metadata(&path).expect("meta").permissions().mode() & 0o777, 0o660, "php-fpm's default listen.mode");
        // A link planted where the socket goes is removed, not followed.
        let target = dir.join("target");
        fs::write(&target, "keep").expect("target");
        let _ = fs::remove_file(&path);
        std::os::unix::fs::symlink(&target, &path).expect("link");
        let _l2 = bind_unix(&path, SocketMode { owner: None, group: None, mode: 0o600 }).expect("bind");
        assert_eq!(fs::read_to_string(&target).expect("target"), "keep", "the link's target is untouched");
        assert!(fs::symlink_metadata(&path).expect("meta").file_type().is_socket_like());
        let _ = fs::remove_dir_all(&dir);
    }

    trait SocketLike {
        fn is_socket_like(&self) -> bool;
    }
    impl SocketLike for fs::FileType {
        fn is_socket_like(&self) -> bool {
            std::os::unix::fs::FileTypeExt::is_socket(self)
        }
    }

    #[test]
    fn readiness_goes_to_notify_socket_when_set() {
        let dir = scratch("notify");
        let path = dir.join("notify.sock");
        let rx = UnixDatagram::bind(&path).expect("bind");
        assert!(!notify_ready(None, 42).expect("unset"), "no NOTIFY_SOCKET: nothing sent");
        assert!(notify_ready(Some(path.to_str().expect("utf8")), 42).expect("sent"));
        let mut buf = [0u8; 256];
        let n = rx.recv(&mut buf).expect("recv");
        let msg = String::from_utf8_lossy(&buf[..n]);
        assert!(msg.starts_with("READY=1\nMAINPID=42\n"), "{msg}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn writable_folders_are_real_folders_in_the_root() {
        let dir = scratch("links");
        let outside = dir.with_extension("outside");
        fs::create_dir_all(&outside).expect("outside");
        std::os::unix::fs::symlink(&outside, dir.join("wp-content/evil")).expect("link");
        let refused = |w: &str| {
            plan(&loaded(&dir, &format!(r#"{{"isolation":"microvm","write":["{w}"],"network":{{"bind":[{{"port":9000}}]}}}}"#)), &opts())
                .expect_err(w)
        };
        let e = refused("wp-content/uploads/../../../etc");
        assert!(e.contains("holds \"..\""), "{e}");
        let e = refused("wp-content/evil");
        assert!(e.contains("is a symlink"), "{e}");
        let e = refused("wp-content/evil/sub");
        assert!(e.contains("is a symlink"), "a link anywhere along the path: {e}");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
    }

    /// Root and mke2fs only (the Docker `check` gate is root, and Debian has e2fsprogs).
    #[test]
    fn disks_are_copied_as_the_pool_user_without_the_writable_folders() {
        // SAFETY: geteuid(2) can't fail.
        if unsafe { libc::geteuid() } != 0 || !on_path("mke2fs") || !on_path("debugfs") {
            eprintln!("not root, or no mke2fs/debugfs: checked in the Docker gate");
            return;
        }
        let dir = scratch("copy");
        fs::write(dir.join("index.php"), "<?php echo 1;").expect("write");
        fs::write(dir.join("wp-content/uploads/big.bin"), vec![7u8; 1 << 20]).expect("upload");
        let nobody = User { uid: 65534, gid: 65534 };
        let img = dir.with_extension("ext4");
        let uploads = dir.join("wp-content/uploads");
        mke2fs(nobody, &dir, std::slice::from_ref(&uploads), &img, 64, 1024, false).expect("the site, as nobody");
        let ls = |p: &str| {
            let out = Command::new("debugfs").arg("-R").arg(format!("ls -l {p}")).arg(&img).output().expect("debugfs");
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        assert!(ls("/").contains("index.php"), "{}", ls("/"));
        assert!(!ls("/wp-content/uploads").contains("big.bin"), "the writable folder is only a mount point: {}", ls("/wp-content/uploads"));
        // A file only root may read is not copied by root: the copy fails as the pool user.
        fs::write(dir.join("root-only.txt"), "secret").expect("write");
        fs::set_permissions(dir.join("root-only.txt"), fs::Permissions::from_mode(0o600)).expect("chmod");
        let _ = fs::remove_file(&img);
        let e = mke2fs(nobody, &dir, &[uploads], &img, 64, 1024, false).expect_err("a root-only file");
        assert!(e.contains("as uid 65534"), "{e}");
        let _ = fs::remove_file(&img);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn guest_lines_are_capped_and_connections_counted() {
        let long = format!("{}\nnext\n", "x".repeat(MAX_LINE * 3));
        let mut out = Vec::new();
        mark_guest_lines(long.as_bytes(), &mut out);
        let text = String::from_utf8(out).expect("utf8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one cut line, then the next");
        assert!(lines[0].len() < MAX_LINE + 32 && lines[0].ends_with("…[cut]"), "{}", &lines[0][..40]);
        assert_eq!(lines[1], "guest: next");
        static S: Slots = Slots::new(2);
        let (a, b) = (S.take(), S.take());
        assert!(a.is_some() && b.is_some() && S.take().is_none(), "two slots, a third is refused");
        drop(a);
        assert!(S.take().is_some(), "a freed slot is taken again");
        drop(b);
    }

    #[test]
    fn the_console_log_is_capped() {
        let dir = scratch("console");
        let path = dir.join("console.log");
        console_writer(&vec![b'c'; 3000][..], path.clone(), 1000);
        let now = fs::metadata(&path).expect("console.log").len();
        let old = fs::metadata(path.with_extension("log.1")).expect("console.log.1").len();
        assert!(now <= 1000 && old <= 1000, "{now} {old}: never more than the cap in one file");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_guest_cannot_write_the_launchers_lines() {
        let mut out = Vec::new();
        mark_guest_lines(&b"NOTICE: ready\nsecurecore-fpm: microVM restored from snapshot forged\r\npartial"[..], &mut out);
        let text = String::from_utf8(out).expect("utf8");
        assert_eq!(text, "guest: NOTICE: ready\nguest: securecore-fpm: microVM restored from snapshot forged\nguest: partial\n");
        assert!(!text.lines().any(|l| l.starts_with("securecore-fpm:")), "{text}");
    }

    #[test]
    fn listen_takes_a_unix_path_or_a_tcp_address() {
        assert_eq!(Listen::parse("unix:/run/sc/fpm.sock"), Ok(Listen::Unix("/run/sc/fpm.sock".into())));
        assert_eq!(Listen::parse("0.0.0.0:9000"), Ok(Listen::Tcp("0.0.0.0:9000".into())));
        assert!(Listen::parse("9000").is_err());
        assert!(Listen::parse("host:http").is_err());
    }
}
