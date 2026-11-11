//! Layer 1 as a Firecracker microVM, the host side (addiscorp/securecore#71; the spike is #68,
//! the database path #70, `docs/layer1-microvm.md`). `securecore-fpm` drives Firecracker over
//! its API socket itself and is the guest's only way in or out: the guest has no network
//! device, only vsock.
//!
//! ```text
//!   in    --listen (TCP or a unix socket nginx's fastcgi_pass points at) → vsock 9000 → php-fpm
//!   out   guest port P → <state>/v.sock_P: a symlink to the unix socket layer1.network.connect
//!         names for P (Firecracker connects the guest straight to it, e.g. MySQL's), or a
//!         thread that connects to its TCP `address`. A port with neither is unreachable.
//!   log   guest port 1514 → this process's stderr (php-fpm's log, the extension's audit lines)
//!   ctl   guest port 1515 ← the start message after each boot or restore: clock, then disks
//! ```
//!
//! Disks: vda the guest root (`rootfs.ext4`, read-only, shared); vdb the site, built from the
//! app root with `mke2fs -d` (read-only, rebuilt when the tree changes); vdc on one per
//! `layer1.write` folder inside the app root (read-write, kept across starts). `write` folders
//! outside the root are tmpfs in the guest.
//!
//! Start: from a snapshot when there is one for this key ([`Key`]: the Firecracker, kernel and
//! root image sha256s, the site tree's, the config's, and the machine), else a cold boot that
//! is warmed up and snapshotted first, so the next start restores. A restore that fails falls
//! back to a cold boot; a snapshot that can't be made leaves the cold-booted VM serving.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use securecore_config::Loaded;
use sha2::{Digest as _, Sha256};

use crate::fcgi;
use crate::guest::{CTL_PORT, Ctl, FPM_PORT, LOG_PORT};
use crate::vsock;

/// Where the installer puts the VM's files (`ext/install.sh`).
pub const DEFAULT_VM_DIR: &str = "/usr/local/share/securecore/vm";
/// Where each site's disks, snapshot and sockets live, under a folder per app root.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/securecore/vm";
/// Bumped whenever what goes into a guest changes shape (boot arguments, disks, the start
/// message), so old snapshots are never restored into a new driver.
const PROTOCOL: u32 = 1;
/// KVM_GET_API_VERSION, and the only value every KVM since Linux 2.6.22 returns.
const KVM_GET_API_VERSION: libc::c_ulong = 0xAE00;
const KVM_API_VERSION: i32 = 12;
/// Front pages run through php-fpm before a snapshot is taken (opcache, page cache, workers).
const WARM_UP: usize = 20;

/// The files the microVM needs: mirab's Firecracker and kernel (resolved by the release build,
/// checked by the installer), and the guest root image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assets {
    pub firecracker: PathBuf,
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
}

impl Assets {
    /// `<dir>/firecracker`, `<dir>/vmlinux` and `<dir>/rootfs.ext4`.
    pub fn in_dir(dir: &Path) -> Assets {
        Assets { firecracker: dir.join("firecracker"), kernel: dir.join("vmlinux"), rootfs: dir.join("rootfs.ext4") }
    }
}

fn on_path(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(program).is_file()))
}

/// Whether this host can run layer 1's microVM: `kvm` (normally `/dev/kvm`) opens read-write
/// and answers KVM_GET_API_VERSION with 12, the three files exist (Firecracker executable), and
/// `mke2fs` is there to build the site's disks. `Err` says what is missing.
pub fn available(kvm: &Path, assets: &Assets) -> Result<(), String> {
    let dev = OpenOptions::new().read(true).write(true).open(kvm).map_err(|e| format!("{}: {e}", kvm.display()))?;
    // SAFETY: KVM_GET_API_VERSION takes no argument and returns an int; the fd is open.
    let v = unsafe { libc::ioctl(std::os::fd::AsRawFd::as_raw_fd(&dev), KVM_GET_API_VERSION, 0) };
    if v != KVM_API_VERSION {
        return Err(format!("{}: KVM_GET_API_VERSION returned {v}, not {KVM_API_VERSION}", kvm.display()));
    }
    for (what, path) in [("Firecracker", &assets.firecracker), ("the guest kernel", &assets.kernel), ("the guest root image", &assets.rootfs)] {
        let m = fs::metadata(path).map_err(|e| format!("{what} {}: {e}", path.display()))?;
        if what == "Firecracker" && m.permissions().mode() & 0o111 == 0 {
            return Err(format!("Firecracker {}: not executable", path.display()));
        }
    }
    if !on_path("mke2fs") {
        return Err("mke2fs (e2fsprogs) isn't on PATH; it builds the site's disks".into());
    }
    Ok(())
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

/// The launcher's VM options (flags in `main.rs`).
#[derive(Debug, Clone)]
pub struct Options {
    pub assets: Assets,
    pub kvm: PathBuf,
    /// This site's folder for disks, snapshot and sockets (default: under [`DEFAULT_STATE_DIR`]).
    pub state: Option<PathBuf>,
    /// Default: `127.0.0.1:<the first layer1.network.bind port>`.
    pub listen: Option<Listen>,
    /// Where the guest mounts the site, i.e. the root nginx sends (default: the app root).
    pub guest_root: Option<String>,
    pub mem_mib: u32,
    pub vcpus: u32,
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
        let host = loaded.resolve(w);
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
        match (&c.socket, &c.address) {
            (Some(s), _) => sockets.push((port, loaded.resolve(s))),
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
    let state = opts.state.clone().unwrap_or_else(|| Path::new(DEFAULT_STATE_DIR).join(&sha_of(&root_str)[..16]));
    Ok(Plan { root, guest_root, disks, tmpfs, sockets, addresses, unreachable, listen, state })
}

/// The site tree's sha256: every entry's path, type, mode, owner, size, mtime and link target,
/// in order, skipping the writable folders (their own disks) and the state folder. Any edit
/// changes it; uploads don't.
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
            h.update(format!(
                "{}\0{:o}\0{}\0{}\0{}\0{}.{}\0{link}\n",
                rel.display(),
                m.mode(),
                m.uid(),
                m.gid(),
                m.size(),
                m.mtime(),
                m.mtime_nsec()
            ));
            entries += 1;
            bytes += m.size().div_ceil(4096) * 4096;
            if m.is_dir() {
                stack.push(path);
            }
        }
    }
    Ok((hex(&h.finalize()), bytes, entries))
}

/// A big file's sha256, cached in `<state>/sha256.cache` by path, size and mtime, so the
/// 1 GiB root image isn't read on every start.
fn file_sha256(state: &Path, path: &Path) -> io::Result<String> {
    let m = fs::metadata(path)?;
    let stamp = format!("{} {}.{} {}", m.size(), m.mtime(), m.mtime_nsec(), path.display());
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

/// What a snapshot is valid for. Two starts with the same key boot the same bytes the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub firecracker: String,
    pub kernel: String,
    pub rootfs: String,
    pub site: String,
    pub config: String,
    /// Everything else that shapes the guest: memory, vCPUs, boot arguments (without the
    /// clock), the drives in order.
    pub machine: String,
}

impl Key {
    pub fn sha256(&self) -> String {
        sha_of(&format!(
            "securecore-fpm microvm {PROTOCOL}\nfirecracker {}\nkernel {}\nrootfs {}\nsite {}\nconfig {}\nmachine {}\n",
            self.firecracker, self.kernel, self.rootfs, self.site, self.config, self.machine
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
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// `mke2fs -d <from>` into `<to>` (through a temporary name), `mb` MiB, owned like `<from>`.
fn mke2fs(from: Option<&Path>, to: &Path, mb: u64, inodes: u64, journal: bool) -> Result<(), String> {
    let tmp = to.with_extension("ext4.new");
    let _ = fs::remove_file(&tmp);
    let mut cmd = Command::new("mke2fs");
    cmd.args(["-q", "-F", "-t", "ext4", "-b", "4096", "-m", "0"]).arg("-N").arg(inodes.to_string());
    if !journal {
        cmd.args(["-O", "^has_journal"]);
    }
    if let Some(from) = from {
        let m = fs::metadata(from).map_err(|e| format!("{}: {e}", from.display()))?;
        cmd.arg("-E").arg(format!("root_owner={}:{}", m.uid(), m.gid())).arg("-d").arg(from);
    }
    cmd.arg(&tmp).arg(format!("{mb}M")).stdin(Stdio::null());
    let out = cmd.output().map_err(|e| format!("mke2fs: {e}"))?;
    if !out.status.success() {
        let _ = fs::remove_file(&tmp);
        return Err(format!("mke2fs {}: {} {}", to.display(), out.status, String::from_utf8_lossy(&out.stderr).trim()));
    }
    fs::rename(&tmp, to).map_err(|e| format!("{}: {e}", to.display()))
}

/// The site's read-only disk for this tree, built when it isn't there yet (older ones removed).
fn site_disk(plan: &Plan, sha: &str, bytes: u64, entries: u64) -> Result<PathBuf, String> {
    let path = plan.state.join(format!("site-{}.ext4", &sha[..16]));
    if path.is_file() {
        return Ok(path);
    }
    let t = Instant::now();
    // The tree, plus a third for ext4's own blocks and directories, plus 64 MiB.
    let mb = bytes * 4 / 3 / (1 << 20) + 64;
    mke2fs(Some(&plan.root), &path, mb, entries * 2 + 1024, false)?;
    log(&format!("built the site disk {} ({mb} MiB, {entries} entries) in {:.0} ms", path.display(), ms(t)));
    for e in fs::read_dir(&plan.state).map_err(|e| e.to_string())?.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with("site-") && e.path() != path {
            let _ = fs::remove_file(e.path());
        }
    }
    Ok(path)
}

/// A writable folder's disk: made once from the folder's contents, then kept (the guest's
/// writes live there; serving and syncing them back is addiscorp/securecore#72).
fn write_disk(plan: &Plan, disk: &WriteDisk) -> Result<PathBuf, String> {
    let path = plan.state.join(format!("{}.ext4", disk.id));
    if path.is_file() {
        return Ok(path);
    }
    let (_, bytes, entries) = site_sha256(&disk.host, &BTreeSet::new()).map_err(|e| format!("{}: {e}", disk.host.display()))?;
    let mb = (bytes * 2 / (1 << 20) + 64).max(256);
    mke2fs(Some(&disk.host), &path, mb, (entries * 2 + 4096).max(16384), true)?;
    log(&format!("made the writable disk {} for {} ({mb} MiB)", path.display(), disk.guest));
    Ok(path)
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
         i8042.dumbkbd quiet loglevel=1 sc.root={}",
        plan.guest_root
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

/// A running Firecracker. Killed when dropped.
struct Vm {
    child: Option<Child>,
    pid: i32,
    api: PathBuf,
    vsock: PathBuf,
}

impl Drop for Vm {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Vm {
    fn spawn(firecracker: &Path, state: &Path) -> Result<Vm, String> {
        let (api_sock, vsock) = (state.join("fc.sock"), state.join("v.sock"));
        for f in [&api_sock, &vsock] {
            let _ = fs::remove_file(f);
        }
        let console = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(state.join("console.log"))
            .map_err(|e| format!("console.log: {e}"))?;
        let console2 = console.try_clone().map_err(|e| e.to_string())?;
        let mut cmd = Command::new(firecracker);
        cmd.arg("--api-sock").arg(&api_sock).arg("--id").arg("securecore").stdin(Stdio::null()).stdout(console).stderr(console2);
        // SAFETY: prctl(2) only, between fork and exec: Firecracker dies with this process.
        unsafe {
            cmd.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().map_err(|e| format!("{}: {e}", firecracker.display()))?;
        let pid = child.id() as i32;
        let vm = Vm { child: Some(child), pid, api: api_sock, vsock };
        let t = Instant::now();
        while UnixStream::connect(&vm.api).is_err() {
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

/// Everything the driver has decided before booting: the files, the drives and the key.
struct Machine {
    rootfs: PathBuf,
    site: PathBuf,
    disks: Vec<(String, PathBuf)>,
    args: String,
    key: String,
}

fn cold_boot(plan: &Plan, opts: &Options, m: &Machine) -> Result<Vm, String> {
    let vm = Vm::spawn(&opts.assets.firecracker, &plan.state)?;
    vm.api("PUT", "/machine-config", &format!(r#"{{"vcpu_count":{},"mem_size_mib":{},"smt":false}}"#, opts.vcpus, opts.mem_mib))?;
    let args = format!("{} sc.time={}", m.args, now().0);
    let kernel = opts.assets.kernel.to_str().ok_or("the kernel's path isn't UTF-8")?;
    vm.api("PUT", "/boot-source", &format!(r#"{{"kernel_image_path":{},"boot_args":{}}}"#, json_str(kernel), json_str(&args)))?;
    let mut drives = vec![("rootfs".to_owned(), m.rootfs.clone(), true, true), ("site".to_owned(), m.site.clone(), false, true)];
    drives.extend(m.disks.iter().map(|(id, p)| (id.clone(), p.clone(), false, false)));
    for (id, path, root, ro) in drives {
        let path = path.to_str().ok_or("a disk's path isn't UTF-8")?.to_owned();
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
    let uds = vm.vsock.to_str().ok_or("the state folder's path isn't UTF-8")?.to_owned();
    vm.api("PUT", "/vsock", &format!(r#"{{"guest_cid":3,"uds_path":{}}}"#, json_str(&uds)))?;
    vm.api("PUT", "/actions", r#"{"action_type":"InstanceStart"}"#)?;
    Ok(vm)
}

fn restore(plan: &Plan, opts: &Options, snap: &Path) -> Result<Vm, String> {
    let vm = Vm::spawn(&opts.assets.firecracker, &plan.state)?;
    let (s, mem) = (snap.join("vm.snap"), snap.join("vm.mem"));
    vm.api(
        "PUT",
        "/snapshot/load",
        &format!(
            r#"{{"snapshot_path":{},"mem_backend":{{"backend_type":"File","backend_path":{}}},"resume_vm":true}}"#,
            json_str(&s.to_string_lossy()),
            json_str(&mem.to_string_lossy())
        ),
    )?;
    Ok(vm)
}

/// Pauses the VM and writes its snapshot to `<snap>` (through a temporary folder).
fn snapshot(vm: &Vm, snap: &Path) -> Result<(), String> {
    let tmp = snap.with_extension("new");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    }
    fs::create_dir_all(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    vm.api("PATCH", "/vm", r#"{"state":"Paused"}"#)?;
    vm.api(
        "PUT",
        "/snapshot/create",
        &format!(
            r#"{{"snapshot_type":"Full","snapshot_path":{},"mem_file_path":{}}}"#,
            json_str(&tmp.join("vm.snap").to_string_lossy()),
            json_str(&tmp.join("vm.mem").to_string_lossy())
        ),
    )?;
    fs::rename(&tmp, snap).map_err(|e| format!("{}: {e}", snap.display()))
}

/// The start message: the clock, then the writable disks and tmpfs folders.
fn start_message(plan: &Plan) -> Vec<Ctl> {
    let (secs, nanos) = now();
    let mut lines = vec![Ctl::Time { secs, nanos }];
    // vda root, vdb site, then the writable disks in drive order.
    for (n, disk) in plan.disks.iter().enumerate() {
        let device = format!("/dev/vd{}", char::from(b'c' + n as u8));
        lines.push(Ctl::Mount { device, path: disk.guest.clone() });
    }
    lines.extend(plan.tmpfs.iter().map(|p| Ctl::Tmpfs { path: p.clone() }));
    lines.push(Ctl::Done);
    lines
}

/// Sends `lines` (ending in [`Ctl::Done`]) to the guest's control port and waits for its `ok`.
fn tell_guest(uds: &Path, lines: &[Ctl]) -> Result<(), String> {
    let t = Instant::now();
    let mut s = loop {
        match vsock::connect_through(uds, CTL_PORT, Duration::from_secs(2)) {
            Ok(s) => break s,
            Err(e) if t.elapsed() > Duration::from_secs(10) => return Err(format!("the guest's control port: {e}")),
            Err(_) => thread::sleep(Duration::from_millis(2)),
        }
    };
    let message: String = lines.iter().map(Ctl::line).collect();
    s.write_all(message.as_bytes()).map_err(|e| format!("the guest's control port: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(30))).map_err(|e| e.to_string())?;
    let mut reply = String::new();
    BufReader::new(s).read_line(&mut reply).map_err(|e| format!("the guest's control port: {e}"))?;
    match reply.trim_end() {
        "ok" => Ok(()),
        other => Err(format!("the guest refused {:?}: {other}", message.trim_end())),
    }
}

/// How the VM came up, for the log.
enum Started {
    Restored { load_ms: f64 },
    Cold,
}

fn warm_up(vm: &Vm, root: &str) {
    for _ in 0..WARM_UP {
        if let Ok(mut s) = vsock::connect_through(&vm.vsock, FPM_PORT, Duration::from_secs(2)) {
            let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
            let _ = fcgi::get_front_page(&mut s, root);
        }
    }
}

/// Boots or restores the VM for `m`, by the rules in the module header.
fn start(plan: &Plan, opts: &Options, m: &Machine) -> Result<(Vm, Started), String> {
    let snap = plan.state.join(format!("snap-{}", &m.key[..16]));
    let ready = Duration::from_secs(60);
    if opts.snapshot {
        if !snap.join("vm.mem").is_file() {
            let t = Instant::now();
            let mut vm = cold_boot(plan, opts, m)?;
            vm.wait_ready(&plan.state, ready)?;
            warm_up(&vm, &plan.guest_root);
            match snapshot(&vm, &snap) {
                Ok(()) => {
                    log(&format!("made the snapshot {} (key {}) in {:.0} ms", snap.display(), &m.key[..16], ms(t)));
                    for e in fs::read_dir(&plan.state).map_err(|e| e.to_string())?.flatten() {
                        let name = e.file_name().to_string_lossy().into_owned();
                        if name.starts_with("snap-") && e.path() != snap {
                            let _ = fs::remove_dir_all(e.path());
                        }
                    }
                }
                Err(e) => {
                    log(&format!("could not make a snapshot ({e}); this VM keeps serving, cold-booted"));
                    vm.api("PATCH", "/vm", r#"{"state":"Resumed"}"#)?;
                    return Ok((vm, Started::Cold));
                }
            }
            drop(vm);
        }
        let t = Instant::now();
        match restore(plan, opts, &snap).and_then(|mut vm| vm.wait_ready(&plan.state, Duration::from_secs(10)).map(|()| vm)) {
            Ok(vm) => return Ok((vm, Started::Restored { load_ms: ms(t) })),
            Err(e) => {
                log(&format!("restoring {} failed ({e}); removing it and cold-booting instead", snap.display()));
                let _ = fs::remove_dir_all(&snap);
            }
        }
    }
    let mut vm = cold_boot(plan, opts, m)?;
    vm.wait_ready(&plan.state, ready)?;
    Ok((vm, Started::Cold))
}

fn bind_unix(path: &Path) -> Result<UnixListener, String> {
    let _ = fs::remove_file(path);
    let l = UnixListener::bind(path).map_err(|e| format!("{}: {e}", path.display()))?;
    // nginx's workers (another user) connect.
    fs::set_permissions(path, fs::Permissions::from_mode(0o666)).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(l)
}

/// Guest port P's host end, before the guest can dial it.
fn forwards(plan: &Plan) -> Result<(), String> {
    for (port, socket) in &plan.sockets {
        let at = plan.state.join(format!("v.sock_{port}"));
        let _ = fs::remove_file(&at);
        std::os::unix::fs::symlink(socket, &at).map_err(|e| format!("{}: {e}", at.display()))?;
    }
    for (port, address) in &plan.addresses {
        let l = bind_unix(&plan.state.join(format!("v.sock_{port}")))?;
        let address = address.clone();
        let port = *port;
        thread::spawn(move || {
            for c in l.incoming().flatten() {
                match TcpStream::connect(&address) {
                    Ok(t) => {
                        let _ = t.set_nodelay(true);
                        let _ = vsock::join(c, t);
                    }
                    Err(e) => log(&format!("guest port {port} → {address}: {e}")),
                }
            }
        });
    }
    // php-fpm's log, to this process's stderr.
    let l = bind_unix(&plan.state.join(format!("v.sock_{LOG_PORT}")))?;
    thread::spawn(move || {
        for c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut c = c;
                let _ = io::copy(&mut c, &mut io::stderr());
            });
        }
    });
    Ok(())
}

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

static QUITTING: AtomicBool = AtomicBool::new(false);
static FIRECRACKER: AtomicI32 = AtomicI32::new(0);

/// Blocks the signals that stop the launcher, so [`wait_for_signal`] can take them. Called
/// before any thread starts, so every thread inherits the mask.
fn block_signals() -> libc::sigset_t {
    // SAFETY: sigemptyset/sigaddset/pthread_sigmask on a sigset_t we own.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT] {
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

/// Runs php-fpm in the microVM until a signal stops it. Returns only on failure (the
/// launcher exits 125) or after a clean stop (`Ok`).
pub fn run(loaded: &Loaded, opts: &Options) -> Result<(), String> {
    let set = block_signals();
    let t0 = Instant::now();
    let plan = plan(loaded, opts)?;
    fs::create_dir_all(&plan.state).map_err(|e| format!("{}: {e}", plan.state.display()))?;
    fs::set_permissions(&plan.state, fs::Permissions::from_mode(0o700)).map_err(|e| format!("{}: {e}", plan.state.display()))?;
    if !plan.unreachable.is_empty() {
        log(&format!(
            "layer1.network.connect ports {:?} have no socket or address, so the microVM can't reach them \
             (outbound connections from the guest are addiscorp/securecore#72)",
            plan.unreachable
        ));
    }
    // The site's key: the tree without the writable folders, the state folder and the config
    // file, whose bytes are keyed by their own sha256 instead (copying the same file in again
    // changes its mtime, not the site).
    let mut skip: BTreeSet<PathBuf> = plan.disks.iter().map(|d| d.host.clone()).collect();
    skip.insert(plan.state.clone());
    skip.extend(loaded.path.file_name().map(|name| plan.root.join(name)));
    let (tree, bytes, entries) = site_sha256(&plan.root, &skip).map_err(|e| format!("{}: {e}", plan.root.display()))?;
    let site = sha_of(&format!("tree {tree}\nconfig {}\n", loaded.sha256));
    let site_path = site_disk(&plan, &site, bytes, entries)?;
    let mut disks = Vec::new();
    for d in &plan.disks {
        disks.push((d.id.clone(), write_disk(&plan, d)?));
    }
    let args = boot_args(&plan, opts);
    let sha = |p: &Path| file_sha256(&plan.state, p).map_err(|e| format!("{}: {e}", p.display()));
    let key = Key {
        firecracker: sha(&opts.assets.firecracker)?,
        kernel: sha(&opts.assets.kernel)?,
        rootfs: sha(&opts.assets.rootfs)?,
        site,
        config: loaded.sha256.clone(),
        machine: format!(
            "mem {} vcpus {} args {args} drives {}",
            opts.mem_mib,
            opts.vcpus,
            disks.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>().join(",")
        ),
    };
    let m = Machine { rootfs: opts.assets.rootfs.clone(), site: site_path, disks, args, key: key.sha256() };
    forwards(&plan)?;
    let (mut vm, how) = start(&plan, opts, &m)?;
    let t_ready = ms(t0);
    tell_guest(&vm.vsock, &start_message(&plan))?;
    let t_started = ms(t0);
    match how {
        Started::Restored { load_ms } => log(&format!(
            "microVM restored from snapshot {} (load and php-fpm ping {load_ms:.1} ms); ready {t_ready:.0} ms, started {t_started:.0} ms after launch",
            &m.key[..16]
        )),
        Started::Cold => log(&format!("microVM cold-booted; ready {t_ready:.0} ms, started {t_started:.0} ms after launch")),
    }
    let uds = vm.vsock.clone();
    match &plan.listen {
        Listen::Unix(path) => {
            let l = bind_unix(path)?;
            thread::spawn(move || serve(l.incoming(), uds));
        }
        Listen::Tcp(addr) => {
            let l = TcpListener::bind(addr).map_err(|e| format!("--listen {addr}: {e}"))?;
            thread::spawn(move || serve(l.incoming(), uds));
        }
    }
    log(&format!("serving FastCGI on {} (state {})", plan.listen, plan.state.display()));
    FIRECRACKER.store(vm.pid, Ordering::SeqCst);
    let mut child = vm.child.take().ok_or("no Firecracker")?;
    let state = plan.state.clone();
    thread::spawn(move || {
        let st = child.wait();
        if !QUITTING.load(Ordering::SeqCst) {
            log(&format!("Firecracker exited ({st:?}); see {}; stopping", state.join("console.log").display()));
            std::process::exit(1);
        }
    });
    let sig = wait_for_signal(&set);
    // The guest's writes to the writable disks reach the host's images before the VM stops.
    if let Err(e) = tell_guest(&plan.state.join("v.sock"), &[Ctl::Sync, Ctl::Done]) {
        log(&format!("the guest did not sync its disks before the stop: {e}"));
    }
    QUITTING.store(true, Ordering::SeqCst);
    // SAFETY: kill(2) on the Firecracker this process started.
    unsafe { libc::kill(FIRECRACKER.load(Ordering::SeqCst), libc::SIGKILL) };
    if let Listen::Unix(p) = &plan.listen {
        let _ = fs::remove_file(p);
    }
    for f in ["fc.sock", "v.sock"] {
        let _ = fs::remove_file(plan.state.join(f));
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
            guest_root: Some("/var/www/html".into()),
            mem_mib: 512,
            vcpus: 2,
            snapshot: true,
            guest_args: vec![],
        }
    }

    #[test]
    fn the_plan_maps_layer1_onto_disks_tmpfs_and_forwards() {
        let dir = scratch("plan");
        let l = loaded(
            &dir,
            r#"{"enabled":true,"write":["wp-content/uploads","/tmp","/var/cache/sc"],"deny":["/srv/backups"],
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
        let args = boot_args(&p, &opts());
        assert!(args.contains(" sc.root=/var/www/html") && args.contains(" sc.ports=3306,6379"), "{args}");
        assert!(args.contains(" sc.sock=3306:/run/mysqld/mysqld.sock"), "{args}");
        assert!(!args.contains("sc.time"), "the clock is in no key: {args}");
        let msg = start_message(&p);
        assert!(matches!(msg[0], Ctl::Time { .. }), "the clock first");
        assert_eq!(msg[1], Ctl::Mount { device: "/dev/vdc".into(), path: "/var/www/html/wp-content/uploads".into() });
        assert_eq!(msg[2], Ctl::Tmpfs { path: "/var/cache/sc".into() });
        assert_eq!(msg.last(), Some(&Ctl::Done));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_plan_refuses_what_a_microvm_cant_enforce() {
        let dir = scratch("refuse");
        let refused = |layer1: &str| plan(&loaded(&dir, layer1), &opts()).expect_err(layer1);
        let e = refused(r#"{"enabled":true,"network":{"bind":[{"port":9000}],"unixSockets":["/run/x.sock"]}}"#);
        assert!(e.contains("connect [{ \"port\": 3306, \"socket\": \"/run/x.sock\" }]"), "{e}");
        let e = refused(r#"{"enabled":true,"deny":["private"],"network":{"bind":[{"port":9000}]}}"#);
        assert!(e.contains("inside the app root"), "{e}");
        let e = refused(r#"{"enabled":true,"write":["wp-content/missing"],"network":{"bind":[{"port":9000}]}}"#);
        assert!(e.contains("no such folder"), "{e}");
        let e = refused(r#"{"enabled":true}"#);
        assert!(e.contains("layer1.network.bind is empty"), "{e}");
        let mut o = opts();
        o.guest_root = Some("/var/www/my site".into());
        let e = plan(&loaded(&dir, r#"{"enabled":true,"network":{"bind":[{"port":9000}]}}"#), &o).expect_err("space");
        assert!(e.contains("holds a space"), "{e}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_site_key_changes_with_the_tree_but_not_with_uploads() {
        let dir = scratch("key");
        fs::write(dir.join("index.php"), "<?php echo 1;").expect("write");
        let skip: BTreeSet<PathBuf> = [dir.join("wp-content/uploads")].into();
        let (a, _, _) = site_sha256(&dir, &skip).expect("sha");
        fs::write(dir.join("wp-content/uploads/photo.jpg"), "jpeg").expect("write");
        assert_eq!(site_sha256(&dir, &skip).expect("sha").0, a, "an upload is not a site change");
        fs::write(dir.join("index.php"), "<?php echo 2;").expect("write");
        assert_ne!(site_sha256(&dir, &skip).expect("sha").0, a, "an edit is");
        let k = Key {
            firecracker: "f".into(),
            kernel: "k".into(),
            rootfs: "r".into(),
            site: "s".into(),
            config: "c".into(),
            machine: "m".into(),
        };
        for changed in [
            Key { kernel: "k2".into(), ..k.clone() },
            Key { rootfs: "r2".into(), ..k.clone() },
            Key { site: "s2".into(), ..k.clone() },
            Key { config: "c2".into(), ..k.clone() },
            Key { firecracker: "f2".into(), ..k.clone() },
            Key { machine: "m2".into(), ..k.clone() },
        ] {
            assert_ne!(changed.sha256(), k.sha256(), "{changed:?}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn listen_takes_a_unix_path_or_a_tcp_address() {
        assert_eq!(Listen::parse("unix:/run/sc/fpm.sock"), Ok(Listen::Unix("/run/sc/fpm.sock".into())));
        assert_eq!(Listen::parse("0.0.0.0:9000"), Ok(Listen::Tcp("0.0.0.0:9000".into())));
        assert!(Listen::parse("9000").is_err());
        assert!(Listen::parse("host:http").is_err());
    }

    #[test]
    fn no_kvm_device_is_a_reason_not_a_crash() {
        let why = available(Path::new("/nonexistent/kvm"), &Assets::in_dir(Path::new("/nonexistent"))).expect_err("no kvm");
        assert!(why.starts_with("/nonexistent/kvm: "), "{why}");
    }
}
