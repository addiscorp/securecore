//! Layer 1 as a Firecracker microVM, the host side (addiscorp/securecore#71; the spike is #68,
//! the database path #70, `docs/layer1-microvm.md`). `securecore-fpm` drives Firecracker over
//! its API socket itself and is the guest's only way in or out: the guest has no network
//! device, only vsock. Firecracker runs under its jailer as an unprivileged user ([`crate::jail`]).
//!
//! ```text
//!   in    --listen (TCP, or a unix socket with php-fpm's listen.owner/group/mode) → vsock 9000
//!   out   guest port P → <jail>/v.sock_P: for a connect[].socket, a link to the socket in its
//!         folder bind-mounted into the jail (Firecracker connects as the jailed user), or a
//!         thread that connects to its TCP `address`. A port with neither is an egress port:
//!         the guest reaches named hosts on it through `<jail>/v.sock_1517` ([`crate::egress`]).
//!   log   guest port 1514 → this process's stderr, each line marked `guest: `: numbered frames,
//!         each logged once and acknowledged; a lost line is counted ([`crate::guestlog`], #86)
//!   ctl   guest port 1515 ← one start message after each boot or restore (clock, fresh
//!         randomness, the workers' refresh after a restore, then the disks); later `sync`
//!         before a stop and `reload` on SIGUSR2/SIGHUP
//!   sync  guest port 516 ← the writable folders' changes, applied to the host's folders by
//!         `securecore-fpm --sync-writer` as the pool user ([`crate::sync`], #72)
//! ```
//!
//! Disks: vda the guest root (`rootfs.ext4`, read-only, shared); vdb the site, built from the
//! app root with `mke2fs -d` (read-only, rebuilt when the tree changes); vdc on one per
//! `layer1.write` folder inside the app root (read-write, `--write-disk-mib`, kept across
//! starts and grown when the size goes up), mirrored back into that folder on the host as the
//! guest changes it. `write` folders outside the root are tmpfs.
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
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use securecore_config::Loaded;
use sha2::{Digest as _, Sha256};

use crate::capture;
use crate::fcgi;
use crate::guestlog;
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
/// message, the sync), so old snapshots are never restored into a new driver. The guest's init
/// is the same binary: it boots with `sc.proto=<this>`, answers the handshake only when it is
/// its own, and takes no start message otherwise ([`handshake`]).
/// 5: the log port's numbered, acknowledged frames ([`guestlog`], #86).
/// 6: the guest is the host's own PHP (#101): the base, then the PHP and config layers.
pub const PROTOCOL: u32 = 6;
/// KVM_GET_API_VERSION, and the only value every KVM since Linux 2.6.22 returns.
const KVM_GET_API_VERSION: libc::c_ulong = 0xAE00;
const KVM_API_VERSION: i32 = 12;
/// The base's warm-up script: reads the site's PHP files into the page cache.
pub const WARM_SCRIPT: &str = "/sc/warm.php";
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
    /// `--mem` and `--vcpus`; `None`: sized from the pool and the host ([`size_guest`]).
    pub mem_mib: Option<u32>,
    pub vcpus: Option<u32>,
    /// How long a start may take before it gives up (`--start-within`): systemd is asked for
    /// more time until then, and `auto` then runs gelada ([`start_deadline`]).
    pub start_within: Duration,
    /// The shared record of the space each running start keeps for its disks (`--space-ledger`,
    /// [`crate::space::DEFAULT_SPACE_LEDGER`]).
    pub space_ledger: PathBuf,
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
    /// Variables of the launcher's environment the guest's php-fpm gets, besides the vault's
    /// own (`layer2.vault.secrets[].env`), which it always gets ([`guest_env`]).
    pub guest_env: Vec<String>,
    /// The site's php.ini settings for the guest's php-fpm (#90): a file of `securecore.debug_*`
    /// lines ([`crate::guest::site_ini`]), delivered at each start and again whenever it changes.
    /// A missing file is no settings.
    pub guest_ini: Option<PathBuf>,
    /// Where the host's PHP is (#101): `/` on a host (`--php-root`).
    pub php_root: PathBuf,
    /// The host's php-fpm (`--php-fpm`: a path, or a name on [`capture::PHP_PATH`]).
    pub php_fpm: String,
    /// php-fpm's own arguments (after the launcher's), for its `-y`, `-c` and `-p`.
    pub fpm_args: Vec<String>,
    /// The one pool this launcher runs (`--pool`, set by the launcher itself for a php-fpm with
    /// several: one VM per pool, each a launcher of its own).
    pub pool: Option<String>,
    /// The install's record of the unpackaged files' sha256s (`--unpackaged-record`,
    /// [`capture::DEFAULT_RECORD`]).
    pub record: PathBuf,
    /// The database server's user (`--db-user`, `mysql`): a MySQL socket the guest reaches is
    /// this user's or root's, in folders only they may write.
    pub db_user: String,
    /// The database targets the operator approves for a bare 3306 (`--db-address`,
    /// `--db-socket`), beside MySQL's own loopback ports and the database user's sockets.
    pub db_address: Option<String>,
    pub db_socket: Option<PathBuf>,
}

/// The site's php.ini settings as the guest gets them: `None` without `--guest-ini` or while the
/// file is missing; refused with the reason when it sets anything else. The file is the
/// operator's (a launcher flag names it, as with `--config`), read the way `securecore.json` is
/// ([`crate::sitefile::read`]: no link anywhere in its path, as its folder's owner, regular
/// only), within [`MAX_SITE_INI`].
pub fn read_site_ini(path: Option<&Path>) -> Result<Option<String>, String> {
    let Some(path) = path else { return Ok(None) };
    match crate::sitefile::read(path, MAX_SITE_INI) {
        Ok(None) => Ok(None),
        Ok(Some(b)) => {
            let text = String::from_utf8(b).map_err(|_| format!("{}: not UTF-8", path.display()))?;
            crate::guest::site_ini(&text).map(Some).map_err(|e| format!("{}: {e}", path.display()))
        }
        Err(e) => Err(e),
    }
}

/// The largest `--guest-ini` file read.
pub const MAX_SITE_INI: usize = 16 * 1024;

/// php-fpm's environment in the guest: each name in `--guest-env` and each vault secret's `env`,
/// with its value from the launcher's own environment (as php-fpm on the host would have it).
/// Delivered in every start message, never in an image, a boot argument or a snapshot. A name
/// the launcher's environment lacks is refused: the guest's vault would fail closed anyway.
pub fn guest_env(loaded: &Loaded, names: &[String], get: impl Fn(&str) -> Option<String>) -> Result<Vec<(String, String)>, String> {
    let mut all: Vec<String> = names.to_vec();
    let l2 = &loaded.config.layer2;
    if l2.enabled
        && let Some(v) = &l2.vault
    {
        for s in &v.secrets {
            if let securecore_config::Secret::Env(e) = s {
                all.push(e.env.clone());
            }
        }
    }
    let mut out: Vec<(String, String)> = Vec::new();
    for name in all {
        if out.iter().any(|(n, _)| *n == name) {
            continue;
        }
        if !crate::guest::env_name_ok(&name) {
            return Err(format!("--guest-env {name:?} is not a variable name"));
        }
        let value = get(&name).ok_or_else(|| {
            format!("the launcher's environment has no {name}, which the guest's php-fpm needs (--guest-env, or layer2.vault.secrets[].env)")
        })?;
        if value.len() > crate::guest::MAX_ENV_VALUE {
            return Err(format!("{name} is longer than {} bytes", crate::guest::MAX_ENV_VALUE));
        }
        out.push((name, value));
    }
    Ok(out)
}

/// A writable folder inside the app root: its own disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteDisk {
    pub host: PathBuf,
    pub guest: String,
    /// The drive id and file name: `w` + 12 hex digits of the folder's path's sha256.
    pub id: String,
}

impl WriteDisk {
    /// The folder relative to the app root, which it is always inside ([`plan`]).
    fn rel(&self, root: &Path) -> Result<PathBuf, String> {
        self.host.strip_prefix(root).map(Path::to_path_buf).map_err(|_| format!("{} is not in the app root", self.host.display()))
    }
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
    /// `connect` ports with no socket or address: the guest reaches named hosts on them through
    /// the host ([`crate::egress`]), never an IP of its own choosing.
    pub egress: Vec<u16>,
    pub listen: Listen,
    pub state: PathBuf,
    /// Where the host's PHP capture and its layer disks are kept: the site's state folder (with
    /// several pools, the one above each pool's).
    pub cache: PathBuf,
    /// The jail's id: `sc-` and 16 hex digits of the app root's sha256 (and the pool's).
    pub id: String,
    /// The site's pool user: disks are copied as it, and the guest's pool runs as its uid/gid.
    pub pool: User,
    /// Unix sockets in the guest that reach a forwarded port (`localhost` for MySQL: PHP's
    /// default sockets), as guest paths under `/run` or `/tmp`.
    pub guest_socks: Vec<(u16, String)>,
    /// The site's own `DB_HOST` endpoint (`host:port`, a name or an IPv4 address) when a bare 3306
    /// goes to an address ([`resolve_db`]): in the guest, a connection to it reaches 3306's
    /// forward, so the site's unchanged `DB_HOST` works there (`sc.dbalias`).
    pub db_alias: Option<String>,
}

/// What the host's pool says, for [`plan_with`]: who it runs as and where it listens.
#[derive(Debug, Clone, Default)]
pub struct PoolHints {
    pub user: Option<User>,
    pub listen: Option<Listen>,
    pub listen_mode: Option<SocketMode>,
    pub admit: Admit,
}

/// Who may connect to the launcher's listening socket, as the pool says (#102 review): php-fpm's
/// `listen.allowed_clients` for TCP, its `listen.acl_users`/`listen.acl_groups` for a unix socket.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Admit {
    #[default]
    Any,
    /// TCP: only these peer addresses.
    Addresses(Vec<std::net::IpAddr>),
    /// A unix socket: only peers (SO_PEERCRED) with one of these uids, or whose gid, or a group
    /// they belong to, is one of these gids; root always.
    Users { uids: Vec<u32>, gids: Vec<u32>, members: Vec<u32> },
}

impl Admit {
    /// Whether a TCP peer may connect.
    pub fn tcp(&self, peer: std::net::IpAddr) -> bool {
        match self {
            Admit::Addresses(a) => a.iter().any(|x| *x == peer || x.to_canonical() == peer.to_canonical()),
            _ => true,
        }
    }

    /// Whether a unix-socket peer (uid, gid) may connect.
    pub fn unix(&self, uid: u32, gid: u32) -> bool {
        match self {
            Admit::Users { uids, gids, members } => uid == 0 || uids.contains(&uid) || gids.contains(&gid) || members.contains(&uid),
            _ => true,
        }
    }
}

/// The pool's rule of who may connect (`admit`), for where the launcher listens: kept as it is
/// when it fits that socket, refused when it can't (a pool's `allowed_clients` with a unix
/// `--listen`, its ACLs with a TCP one), never dropped.
pub fn listen_admit(listen: &Listen, admit: &Admit) -> Result<Admit, String> {
    match (listen, admit) {
        (_, Admit::Any) | (Listen::Tcp(_), Admit::Addresses(_)) | (Listen::Unix(_), Admit::Users { .. }) => Ok(admit.clone()),
        (Listen::Unix(p), Admit::Addresses(_)) => Err(format!(
            "its listen.allowed_clients can't apply to the unix socket --listen unix:{} names: listen on TCP, or remove allowed_clients",
            p.display()
        )),
        (Listen::Tcp(a), Admit::Users { .. }) => {
            Err(format!("its listen.acl_users/acl_groups can't apply to the TCP address --listen {a} names: listen on a unix socket, or remove the ACLs"))
        }
    }
}

/// The site a pool serves, by its own settings: `chdir`, `php_admin_value[doc_root]` /
/// `php_value[doc_root]`, then `prefix` (`$pool` replaced). `None`: the pool names none.
pub fn pool_site(pool: &crate::phpconf::Pool) -> Option<String> {
    ["chdir", "php_admin_value[doc_root]", "php_value[doc_root]", "prefix"]
        .iter()
        .find_map(|k| pool.get(k).filter(|v| !v.is_empty()))
        .map(|v| v.replace("$pool", &pool.name).trim_end_matches('/').to_owned())
}

/// Whether a pool is this site's (#102 review, Sami's decision): its site (above) is the app root
/// or inside it, on the host or as the guest sees it. A pool that names no site is this site's
/// only when it is php-fpm's only pool.
pub fn pool_is_this_site(pool: &crate::phpconf::Pool, root: &Path, guest_root: &str, only: bool) -> Result<(), String> {
    match pool_site(pool) {
        None if only => Ok(()),
        None => Err(format!(
            "pool [{}] names no site (chdir, doc_root or prefix), and php-fpm has several pools: each pool a microVM runs must name its site, so one site's VM never serves another's",
            pool.name
        )),
        Some(s) => {
            let inside = |r: &str| s == r || s.starts_with(&format!("{r}/"));
            if inside(root.to_string_lossy().trim_end_matches('/')) || inside(guest_root.trim_end_matches('/')) {
                Ok(())
            } else {
                Err(format!("pool [{}] serves another site ({s}), not this one ({}): a microVM here holds only this site's files", pool.name, root.display()))
            }
        }
    }
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

/// The microVM plan for `loaded`'s layer 1, or why it can't be one. The pool user and the
/// listening address are the flags' or, without them, the app root's owner and the first
/// `layer1.network.bind` port; [`prepare`] plans again with the host pool's ([`plan_with`]).
pub fn plan(loaded: &Loaded, opts: &Options) -> Result<Plan, String> {
    plan_with(loaded, opts, &PoolHints::default(), false)
}

/// The site's state folder: `--state-dir`, or one under [`DEFAULT_STATE_DIR`] by the app root.
pub fn state_base(loaded: &Loaded, opts: &Options) -> PathBuf {
    let key = sha_of(&loaded.root.display().to_string());
    opts.state.clone().unwrap_or_else(|| Path::new(DEFAULT_STATE_DIR).join(&key[..16]))
}

/// A pool's name as a folder name and a jail id: php-fpm's names are section names, so anything
/// else is refused.
pub fn pool_dir_name(name: &str) -> Result<String, String> {
    if name.is_empty() || name.len() > 32 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.') || name.starts_with('.') {
        return Err(format!("php-fpm pool [{name}]: a microVM pool's name is 1 to 32 of A-Z a-z 0-9 _ - . (it names its state folder)"));
    }
    Ok(format!("pool-{name}"))
}

/// [`plan`] with the host pool's user and listening address as the defaults the flags override.
/// `defer`: plan without them yet (the cheap checks run before the capture): a missing pool user
/// or listening address isn't an error then.
pub fn plan_with(loaded: &Loaded, opts: &Options, hints: &PoolHints, defer: bool) -> Result<Plan, String> {
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
    let (mut sockets, mut addresses, mut egress) = (Vec::new(), Vec::new(), Vec::new());
    for c in &layer1.network.connect {
        let port = c.port.get();
        if u32::from(port) == LOG_PORT {
            return Err(format!(
                "layer1.network.connect port {LOG_PORT} is the guest's log channel to the host; a microVM can't forward it"
            ));
        }
        if u32::from(port) == crate::egress::EGRESS_PORT && (c.socket.is_some() || c.address.is_some()) {
            return Err(format!(
                "layer1.network.connect port {} is the guest's channel for named hosts; a microVM can't forward it to a socket or address",
                crate::egress::EGRESS_PORT
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
            (None, None) => egress.push(port),
        }
    }
    let listen = match (&opts.listen, &hints.listen) {
        (Some(l), _) | (None, Some(l)) => l.clone(),
        (None, None) => match layer1.network.bind.first() {
            Some(port) => Listen::Tcp(format!("127.0.0.1:{}", port.port)),
            None if defer => Listen::Tcp(String::new()),
            None => {
                return Err("layer1.network.bind is empty and the pool has no listen, so there is no port to take FastCGI on: list one, or pass --listen".into());
            }
        },
    };
    let key = sha_of(&root_str);
    let cache = state_base(loaded, opts);
    let (state, id) = match &opts.pool {
        Some(name) => {
            let dir = pool_dir_name(name)?;
            (cache.join(&dir), format!("sc-{}-{}", &key[..12], &sha_of(name)[..6]))
        }
        None => (cache.clone(), format!("sc-{}", &key[..16])),
    };
    let pool = match pool_user(opts, &root, hints.user) {
        Ok(u) => u,
        Err(_) if defer => User { uid: u32::MAX, gid: u32::MAX },
        Err(e) => return Err(e),
    };
    Ok(Plan { root, guest_root, disks, tmpfs, sockets, addresses, egress, listen, state, cache, id, pool, guest_socks: Vec::new(), db_alias: None })
}

/// The site's pool user: `--pool-user` (a name or `<uid>:<gid>`), else the host pool's `user`
/// (`hint`), else the app root's owner. Never root: the disks are copied as this user, and the
/// guest's php-fpm pool runs as it.
fn pool_user(opts: &Options, root: &Path, hint: Option<User>) -> Result<User, String> {
    match (&opts.pool_user, hint) {
        (Some(spec), _) => jail::user(spec).map_err(|e| {
            e.replace("--vm-user", "--pool-user")
                .replace("Firecracker must not run as root", "the site's files are copied and served as this user, never root")
        }),
        (None, Some(u)) => Ok(u),
        (None, None) => {
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
/// log line and `microvm`'s refusal. In this order, host first, so the reason is the most basic
/// one (a host without KVM says so, not that some file is missing), and nothing is written
/// until the host and the installed files pass:
/// - `kvm` opens read-write and answers KVM_GET_API_VERSION with 12;
/// - the launcher is root (the jailer needs it);
/// - the installer's record (`installed.json`) exists, and the jailed user exists and isn't root;
/// - `mke2fs`, `e2fsck` and `resize2fs` on PATH;
/// - the config is one a microVM can enforce ([`plan`]);
/// - Firecracker, the jailer, the kernel and the root image match the installer's record;
/// - every writable folder fits its disk and the sync ([`fits`]);
/// - with layer 3 on, the kernel has Landlock and seccomp;
/// - each `connect[].socket` is a socket the jailed user may open itself;
/// - cgroup v2.
pub fn available(loaded: &Loaded, opts: &Options) -> Result<(), String> {
    match prepare_all(loaded, opts)? {
        Ready::One(_) | Ready::Pools(_) => Ok(()),
    }
}

/// The host checks every start makes first, before anything is captured or built, host first so
/// the reason is the most basic one (a host without KVM says so and writes nothing): KVM, root,
/// the installer's record, the jailed user, e2fsprogs, the plan (without the host pool's user and
/// listen yet), the verified files, the writable folders' fit, layer 3's kernel, the sockets, the
/// cgroup.
fn host_checks(loaded: &Loaded, opts: &Options) -> Result<(Plan, User), String> {
    let dev = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&opts.kvm)
        .map_err(|e| format!("no KVM: {}: {e}", opts.kvm.display()))?;
    // SAFETY: KVM_GET_API_VERSION takes no argument and returns an int; the fd is open.
    let v = unsafe { libc::ioctl(dev.as_raw_fd(), KVM_GET_API_VERSION, 0) };
    if v != KVM_API_VERSION {
        return Err(format!("no KVM: {}: KVM_GET_API_VERSION returned {v}, not {KVM_API_VERSION}", opts.kvm.display()));
    }
    drop(dev);
    // SAFETY: geteuid(2) takes nothing and can't fail.
    if unsafe { libc::geteuid() } != 0 {
        return Err("the microVM's jailer needs the launcher to run as root".into());
    }
    recorded(&opts.assets.record)?;
    let user = jail::user(&opts.vm_user)?;
    for tool in ["mke2fs", "e2fsck", "resize2fs"] {
        if !on_path(tool) {
            return Err(format!("{tool} (e2fsprogs) isn't on PATH; it builds and grows the site's disks"));
        }
    }
    let plan = plan_with(loaded, opts, &PoolHints::default(), true)?;
    for dir in [&plan.cache, &plan.state] {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    verify(&opts.assets, &plan.state)?;
    // Every writable folder must fit its disk (sized from it, [`disk_mib`]) and the sync.
    for d in &plan.disks {
        let (used, entries) = folder_usage(&plan, d)?;
        let new = !plan.state.join(format!("{}.ext4", d.id)).is_file();
        fits(&d.host, used, entries, if new { Some(free_bytes(&plan.state)?) } else { None })?;
    }
    if loaded.config.layer3.enabled {
        kernel_supports_layer3(&opts.assets.kernel)?;
    }
    open_sockets(&plan, user)?;
    Jail::cgroup_parent()?;
    Ok((plan, user))
}

/// What [`prepare_all`] found: one VM to run here, or a php-fpm with several pools, one VM (and
/// one launcher) each, all prepared once already.
pub enum Ready {
    One(Box<Prepared>),
    Pools(Vec<String>),
}

/// Everything a start does before anything boots (#100 review: `auto` commits only after all of
/// it): the host checks, the capture of the host's PHP and its validation, the pool's user,
/// listen and sockets, the vault's env sources, the state folder's claim, the space every new
/// disk and the snapshot need (with a margin), the PHP and config layers, the site disk (copied
/// as the pool user) and the writable disks. A php-fpm with several pools prepares each (in its
/// own state folder below the site's): [`Ready::Pools`].
pub fn prepare_all(loaded: &Loaded, opts: &Options) -> Result<Ready, String> {
    let (plan0, _) = host_checks(loaded, opts)?;
    let capture = host_capture(&plan0, opts)?;
    // Every pool php-fpm runs is this site's, or the microVM isn't for this config (#102 review:
    // a VM holds one site's files; under `auto` the whole config falls back once, with this).
    let only = capture.pools.len() == 1;
    for p in capture.pools.iter().filter(|p| opts.pool.as_ref().is_none_or(|n| *n == p.name)) {
        pool_is_this_site(p, &loaded.root, &plan0.guest_root, only)?;
    }
    if opts.pool.is_some() || capture.pools.len() == 1 {
        return prepare(loaded, opts, capture).map(|p| Ready::One(Box::new(p)));
    }
    if opts.listen.is_some() {
        return Err(format!(
            "php-fpm's config has {} pools ({}): each gets a microVM of its own listening where its pool says, so --listen can't be given",
            capture.pools.len(),
            capture.pools.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    let mut names = Vec::new();
    for p in &capture.pools {
        let mut o = opts.clone();
        o.pool = Some(p.name.clone());
        host_checks(loaded, &o)?;
        // Each pool's checks and disks now, so a child launcher fails on nothing it can find
        // here; its state lock is let go for it.
        drop(prepare(loaded, &o, capture.clone()).map_err(|e| format!("pool [{}]: {e}", p.name))?);
        names.push(p.name.clone());
    }
    Ok(Ready::Pools(names))
}

/// The host's PHP, captured and validated ([`capture::capture_cached`]), the app root as the
/// guest mounts it.
fn host_capture(plan: &Plan, opts: &Options) -> Result<capture::Capture, String> {
    status("capturing the host's PHP");
    let req = capture::Request {
        root: opts.php_root.clone(),
        php_fpm: opts.php_fpm.clone(),
        fpm_args: opts.fpm_args.clone(),
        scan_dir_env: std::env::var("PHP_INI_SCAN_DIR").ok(),
        app_root: plan.guest_root.clone(),
        record: Some(opts.record.clone()),
    };
    let (c, reused) = capture::capture_cached(&req, &plan.cache, &log).map_err(|e| e.to_string())?;
    if reused {
        log(&format!("the host's PHP {} is as captured before ({} entries, checked against {})", c.php_version, c.items.len(), c.pkg));
    }
    if !c.missing_helpers.is_empty() {
        log(&format!("the host has no {}: PHP in the guest can't run them either (each attempt is logged)", c.missing_helpers.join(", ")));
    }
    Ok(c)
}

/// A user or group of the PHP root: a number, or a name in its `/etc/passwd` / `/etc/group`.
fn root_id(root: &Path, spec: &str, group: bool) -> Result<u32, String> {
    if let Ok(n) = spec.parse::<u32>() {
        return Ok(n);
    }
    let file = root.join(if group { "etc/group" } else { "etc/passwd" });
    let text = fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    text.lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() > 3 && f[0] == spec).then(|| f[2].parse::<u32>().ok()).flatten()
        })
        .ok_or_else(|| format!("{}: no {} {spec}", file.display(), if group { "group" } else { "user" }))
}

/// The host pool's user, listen and its socket's owner, group and mode.
fn pool_hints(root: &Path, pool: &crate::phpconf::Pool) -> Result<PoolHints, String> {
    let at = |e: String| format!("{} pool [{}]: {e}", pool.file, pool.name);
    let user = match pool.get("user") {
        Some(u) => {
            let uid = root_id(root, u, false).map_err(at)?;
            let gid = match pool.get("group") {
                Some(g) => root_id(root, g, true).map_err(at)?,
                None => {
                    // php-fpm: the user's own group.
                    let file = root.join("etc/passwd");
                    let text = fs::read_to_string(&file).unwrap_or_default();
                    text.lines()
                        .find_map(|l| {
                            let f: Vec<&str> = l.split(':').collect();
                            (f.len() > 3 && f[2] == uid.to_string()).then(|| f[3].parse::<u32>().ok()).flatten()
                        })
                        .unwrap_or(uid)
                }
            };
            if uid == 0 || gid == 0 {
                return Err(at("the pool runs as root, which a microVM's pool never does: give it a user of its own".into()));
            }
            Some(User { uid, gid })
        }
        None => None,
    };
    let listen = match pool.listen() {
        Some(l) => Some(match crate::phpconf::pool_listen(&l).map_err(at)? {
            crate::phpconf::PoolListen::Unix(p) => Listen::Unix(PathBuf::from(p)),
            crate::phpconf::PoolListen::Tcp(a) => Listen::Tcp(a),
        }),
        None => None,
    };
    let mut listen_mode = SocketMode {
        owner: pool.get("listen.owner").map(|o| root_id(root, o, false)).transpose().map_err(at)?,
        group: pool.get("listen.group").map(|g| root_id(root, g, true)).transpose().map_err(at)?,
        mode: crate::phpconf::listen_mode(pool.get("listen.mode")).map_err(at)?,
    };
    let admit = match &listen {
        Some(Listen::Tcp(_)) => match crate::phpconf::allowed_clients(pool.get("listen.allowed_clients")).map_err(at)? {
            Some(a) => Admit::Addresses(a),
            None => Admit::Any,
        },
        Some(Listen::Unix(_)) => {
            let users = crate::phpconf::acl_list(pool.get("listen.acl_users"));
            let groups = crate::phpconf::acl_list(pool.get("listen.acl_groups"));
            if users.is_empty() && groups.is_empty() {
                Admit::Any
            } else {
                // php-fpm: with ACLs, listen.owner and listen.group are ignored and the socket is
                // for the listed users and groups. Here the socket is open to all (0666) and every
                // connection's peer is checked against the lists instead.
                listen_mode = SocketMode { owner: None, group: None, mode: 0o666 };
                let uids = users.iter().map(|u| root_id(root, u, false)).collect::<Result<Vec<_>, _>>().map_err(at)?;
                let gids = groups.iter().map(|g| root_id(root, g, true)).collect::<Result<Vec<_>, _>>().map_err(at)?;
                let members = group_members(root, &gids);
                Admit::Users { uids, gids, members }
            }
        }
        None => Admit::Any,
    };
    Ok(PoolHints { user, listen, listen_mode: Some(listen_mode), admit })
}

/// The uids of the users `/etc/group` (under `root`) lists in the groups `gids`, as named in
/// `/etc/passwd`.
fn group_members(root: &Path, gids: &[u32]) -> Vec<u32> {
    let group = fs::read_to_string(root.join("etc/group")).unwrap_or_default();
    let mut out = Vec::new();
    for l in group.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() > 3 && f[2].parse::<u32>().is_ok_and(|g| gids.contains(&g)) {
            for name in f[3].split(',').filter(|n| !n.is_empty()) {
                if let Ok(uid) = root_id(root, name, false) {
                    out.push(uid);
                }
            }
        }
    }
    out
}

/// The standard places MySQL and MariaDB put their socket (never `/tmp`, which anyone may take).
pub const MYSQL_SOCKETS: [&str; 3] = ["/run/mysqld/mysqld.sock", "/var/run/mysqld/mysqld.sock", "/var/lib/mysql/mysql.sock"];

/// Whether `path` is a socket the database server put there: a socket owned by root or the
/// database's user (`db`: uid and gid), every folder above it owned by one of them and writable
/// by no one else (its group only when that is root's or the database's). Any local user could
/// otherwise put a socket where the guest's database connections (and their passwords) go.
/// `approved`: the operator named this very socket (`--db-socket`), so root's is accepted too;
/// otherwise only the database user's (#102 verification: a root-owned socket such as D-Bus's is
/// never a database because a site's `DB_HOST` names it).
pub fn trusted_db_socket(path: &Path, db: Option<(u32, u32)>, approved: bool) -> Result<(), String> {
    let ok_uid = |u: u32| u == 0 || db.is_some_and(|(d, _)| d == u);
    let ok_gid = |g: u32| g == 0 || db.is_some_and(|(_, d)| d == g);
    let m = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !std::os::unix::fs::FileTypeExt::is_socket(&m.file_type()) {
        return Err(format!("{} is not a socket", path.display()));
    }
    let owner_ok = if approved { ok_uid(m.uid()) } else { db.is_some_and(|(d, _)| d == m.uid()) };
    if !owner_ok {
        return Err(format!(
            "the socket {} is owned by uid {}, not the database's user (--db-user{}){}",
            path.display(),
            m.uid(),
            db.map_or_else(|| ", which this host doesn't have".to_owned(), |(d, _)| format!(", uid {d}")),
            if approved { "" } else { "; name it with --db-socket if it really is the database's" }
        ));
    }
    let mut dir = path.parent();
    while let Some(d) = dir {
        let dm = fs::symlink_metadata(d).map_err(|e| format!("{}: {e}", d.display()))?;
        if dm.file_type().is_symlink() {
            return Err(format!("{} is a link on the way to the MySQL socket {}", d.display(), path.display()));
        }
        let mode = dm.mode();
        if !ok_uid(dm.uid()) || mode & 0o002 != 0 || (mode & 0o020 != 0 && !ok_gid(dm.gid())) {
            return Err(format!(
                "{} (owner {}:{}, mode {:o}) on the way to the MySQL socket {} may be written by someone other than root and the database's user",
                d.display(),
                dm.uid(),
                dm.gid(),
                mode & 0o7777,
                path.display()
            ));
        }
        dir = d.parent();
    }
    Ok(())
}

/// The database's user and group (`--db-user`: a name in the host's `/etc/passwd`, or a uid);
/// `None` when the host has no such user (then only root's sockets are trusted).
pub fn db_ids(spec: &str) -> Option<(u32, u32)> {
    let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
    let by = |f: &dyn Fn(&[&str]) -> bool| {
        passwd.lines().map(|l| l.split(':').collect::<Vec<_>>()).find(|f2| f2.len() > 3 && f(f2)).and_then(|f| Some((f[2].parse().ok()?, f[3].parse().ok()?)))
    };
    match spec.parse::<u32>() {
        Ok(uid) => by(&|f| f[2] == spec).or(Some((uid, uid))),
        // The default names MySQL's user; MariaDB's packages may name theirs mariadb.
        Err(_) if spec == "mysql" => by(&|f| f[0] == "mysql").or_else(|| by(&|f| f[0] == "mariadb")),
        Err(_) => by(&|f| f[0] == spec),
    }
}

/// WordPress's `DB_HOST` for this site, as the launcher can read it: `wp-config.php` in the app
/// root (or the folder above, where WordPress also looks), read as the site's files are (no
/// link, capped), its `define` read by [`crate::phpconf::wp_db_host`] with the launcher's
/// environment.
pub fn site_db_host(root: &Path) -> Option<String> {
    for rel in ["wp-config.php", "../wp-config.php"] {
        let (base, file) = match rel.strip_prefix("../") {
            Some(f) => (root.parent()?, f),
            None => (root, rel),
        };
        if let Ok(Some(b)) = crate::sitefile::read_beneath(base, Path::new(file), 1 << 20) {
            return crate::phpconf::wp_db_host(&String::from_utf8_lossy(&b), &|n| std::env::var(n).ok());
        }
    }
    None
}

/// Where a guest unix socket can be: on the guest's tmpfs folders.
fn guest_sock_ok(p: &str) -> bool {
    (p.starts_with("/run/") || p.starts_with("/var/run/") || p.starts_with("/tmp/")) && !p.contains("/../") && !p.chars().any(char::is_whitespace)
}

/// The database targets the operator approved, in root's own configuration (the launcher's
/// flags), never the site's: `--db-address <host:port>` and `--db-socket <path>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DbApproved {
    pub address: Option<String>,
    pub socket: Option<PathBuf>,
}

/// MySQL's own TCP ports: the classic protocol and the X protocol.
pub const MYSQL_PORTS: [u16; 2] = [3306, 33060];

/// The database port (#100 review, #102 review and its verification): a bare
/// `{ "port": 3306 }`. The site's `DB_HOST` (`db_host`, from `wp-config.php`) is only a hint for
/// which of the targets the operator approved to use, never a target of its own (Sami's
/// decision): a site must not point the launcher, which is root, at Redis, D-Bus or another
/// pool's php-fpm.
/// - **TCP** (`127.0.0.1`/`::1`, or any host): only MySQL's ports on the loopback
///   ([`MYSQL_PORTS`]), or exactly the host:port `approved.address` names. The connection is made
///   as the pool user, so the host's uid-based firewall rules apply.
/// - **A unix socket** (`localhost`, with a socket or PHP's default, `hint_sockets`, or MySQL's
///   standard places): only one the database user owns, in folders only root or that user may
///   write (`trusted(path, approved)`, [`trusted_db_socket`]), or exactly `approved.socket`.
/// - Anything else, or no `DB_HOST` the launcher can read: no database for the guest on 3306
///   (it stays an egress port: public names only), and the launcher says why.
///
/// An explicit `connect` entry (`socket` or `address`) wins over all of this. Whatever 3306
/// reaches, PHP's `localhost` reaches too: a socket in the guest at each of PHP's default
/// sockets, the host socket's own path and `/run/mysqld/mysqld.sock`. Returns what was decided,
/// for the log.
pub fn resolve_db(
    plan: &mut Plan,
    db_host: Option<&str>,
    hint_sockets: &[String],
    approved: &DbApproved,
    trusted: &dyn Fn(&Path, bool) -> Result<(), String>,
) -> Result<Option<String>, String> {
    const DB: u16 = crate::guest::DB_FORWARD;
    let mut said = None;
    let no_db = |why: String| Some(format!("port {DB} has no socket or address, and {why}: the guest gets no database on it (only public names)"));
    if plan.egress.contains(&DB) {
        let target = db_host.and_then(securecore_config::dbhost::parse_db_host);
        let defaults = securecore_config::dbhost::Defaults { host: "localhost", port: DB, socket: hint_sockets.first().map(String::as_str) };
        match (db_host, target.map(|t| t.resolve(&defaults))) {
            (None, _) | (_, None) => {
                said = no_db(
                    "the site's DB_HOST isn't one the launcher can read (wp-config.php's define, a literal or the environment); \
                     give the connect entry a socket or address, or approve one with --db-socket / --db-address"
                        .into(),
                );
            }
            (Some(h), Some(ep)) if ep.host == "localhost" => {
                let sock = match &ep.socket {
                    Some(s) => Some(PathBuf::from(s)),
                    None => approved.socket.clone().or_else(|| MYSQL_SOCKETS.iter().map(PathBuf::from).find(|p| p.exists())),
                };
                match sock {
                    None => said = no_db(format!("DB_HOST is {h}, but this host has no MySQL socket at {} (and PHP names none)", MYSQL_SOCKETS.join(", "))),
                    Some(sock) => {
                        let real = fs::canonicalize(&sock).unwrap_or_else(|_| sock.clone());
                        let is_approved = approved.socket.as_ref().is_some_and(|a| fs::canonicalize(a).unwrap_or_else(|_| a.clone()) == real);
                        match trusted(&real, is_approved) {
                            Err(e) => said = no_db(format!("DB_HOST is {h}, but {e}")),
                            Ok(()) => {
                                plan.egress.retain(|p| *p != DB);
                                said = Some(format!("port {DB} has no socket or address: DB_HOST is {h}, so it goes to the database's socket {}", real.display()));
                                plan.sockets.push((DB, real));
                            }
                        }
                    }
                }
            }
            (Some(h), Some(ep)) => {
                let addr = if ep.host.contains(':') { format!("[{}]:{}", ep.host, ep.port) } else { format!("{}:{}", ep.host, ep.port) };
                let loopback = ep.host == "127.0.0.1" || ep.host == "::1";
                let named = approved.address.as_deref().is_some_and(|a| a.eq_ignore_ascii_case(&addr));
                if named || (loopback && MYSQL_PORTS.contains(&ep.port)) {
                    plan.egress.retain(|p| *p != DB);
                    said = Some(format!("port {DB} has no socket or address: DB_HOST is {h}, so it goes to {addr}, connected as the pool user"));
                    plan.addresses.push((DB, addr));
                    // The guest's PHP connects where the site's DB_HOST says (a name, another
                    // port): that endpoint reaches the forward too (#100 review).
                    plan.db_alias = db_alias(&ep.host, ep.port, DB);
                } else if loopback {
                    said = no_db(format!(
                        "DB_HOST is {h}: port {} on this host isn't MySQL's ({}) nor the one --db-address approves",
                        ep.port,
                        MYSQL_PORTS.map(|p| p.to_string()).join(", ")
                    ));
                } else {
                    said = Some(format!("port {DB} has no socket or address: DB_HOST is {h}, a database the guest reaches by name (public addresses only)"));
                }
            }
        }
    }
    let forwarded = plan.sockets.iter().any(|(p, _)| *p == DB) || plan.addresses.iter().any(|(p, _)| *p == DB);
    if forwarded {
        let host_sock: Vec<String> = plan.sockets.iter().filter(|(p, _)| *p == DB).map(|(_, s)| s.display().to_string()).collect();
        let mut paths: Vec<String> = Vec::new();
        for p in hint_sockets.iter().map(String::as_str).chain(host_sock.iter().map(String::as_str)).chain(["/run/mysqld/mysqld.sock"]) {
            // /var/run is /run in the guest.
            let p = p.strip_prefix("/var").filter(|r| r.starts_with("/run/")).unwrap_or(p);
            if guest_sock_ok(p) && !paths.iter().any(|x| x == p) {
                paths.push(p.to_owned());
            }
        }
        plan.guest_socks.extend(paths.into_iter().map(|p| (DB, p)));
    }
    Ok(said)
}

/// The guest's alias for a forwarded database (`sc.dbalias=<host>:<port>`, [`Plan::db_alias`]):
/// `host:port` when the site's `DB_HOST` names anything but the guest's own `127.0.0.1:<fwd>`.
/// `None` for an IPv6 address (the guest's connect hook knows IPv4 and names) or a name the
/// command line can't carry.
pub fn db_alias(host: &str, port: u16, fwd: u16) -> Option<String> {
    if host == "127.0.0.1" && port == fwd {
        return None;
    }
    crate::guest::db_alias_host_ok(host).then(|| format!("{host}:{port}"))
}

/// What `auto` doesn't move into the microVM although it could run there (#100 review): a bare
/// `{ "port": 3306 }` that leaves the guest without the database the site's `DB_HOST` names.
/// gelada reaches it on 3306 as before, so `auto` stays there, saying how to approve it.
/// `no_db`: [`resolve_db`] kept 3306 an egress port (no socket, no address); `said`: what it
/// logged; `reachable(host, port)`: whether the guest reaches that name through egress (layer 2's
/// hosts, a public address).
pub fn auto_db_gap(no_db: bool, said: Option<&str>, db_host: Option<&str>, reachable: &dyn Fn(&str, u16) -> Result<(), String>) -> Option<String> {
    if !no_db {
        return None;
    }
    let ep = db_host.and_then(securecore_config::dbhost::parse_db_host).map(|t| {
        t.resolve(&securecore_config::dbhost::Defaults { host: "localhost", port: 3306, socket: None })
    });
    let why = match &ep {
        // Named, not an IP the guest would pick, and reachable: the guest has it through egress.
        Some(ep) if ep.host != "localhost" && ep.host.parse::<std::net::IpAddr>().is_err() => match reachable(&ep.host, ep.port) {
            Ok(()) => return None,
            Err(e) => format!("DB_HOST is {}, which the guest can't reach by name ({e})", db_host.unwrap_or_default()),
        },
        Some(ep) if ep.host != "localhost" && !ep.host.starts_with("127.") && ep.host != "::1" => format!(
            "DB_HOST is {}, an IP address, and the guest reaches other hosts only by name (port 3306 has no socket or address)",
            db_host.unwrap_or_default()
        ),
        _ => said.unwrap_or("port 3306 gives the guest no database").to_owned(),
    };
    Some(format!(
        "{why}; the site would lose its database, which gelada reaches on port 3306: approve it with --db-socket or --db-address, \
         or give the connect entry a socket or address"
    ))
}

/// The other thing `auto` doesn't move (#100 review): a pool whose `listen` is a bare port, which
/// php-fpm binds on every address, with no `--listen`: the microVM listens on `127.0.0.1` only
/// ([`crate::phpconf::pool_listen`]), so a web server elsewhere would get 502s. Unless its
/// `listen.allowed_clients` admits only the loopback anyway.
pub fn auto_listen_gap(pool: &str, listen: Option<&str>, listen_flag: bool, admit: &Admit) -> Option<String> {
    let l = listen.filter(|l| crate::phpconf::listens_everywhere(l))?;
    if listen_flag || matches!(admit, Admit::Addresses(a) if a.iter().all(|ip| ip.to_canonical().is_loopback())) {
        return None;
    }
    Some(format!(
        "pool [{pool}] has listen = {l}, which php-fpm binds on every address, and the microVM listens on 127.0.0.1:{l} only: \
         a web server on another host or container would get 502s. Set listen = 127.0.0.1:{l} or 0.0.0.0:{l} (or --listen) to say which"
    ))
}

/// What a writable disk may still take on the state folder's filesystem: a new one grows to its
/// whole size (`want`), an existing one (`Some((size, allocated))`) to the larger of its size and
/// `want`, less what it holds already (#100 review: the disks are sparse; they fill as the guest
/// writes, next to the database).
pub fn disk_room(want: u64, existing: Option<(u64, u64)>) -> u64 {
    match existing {
        None => want,
        Some((size, allocated)) => want.max(size).saturating_sub(allocated),
    }
}

/// The ports a bare `connect` entry may have under `auto`: those that only ever go to public
/// hosts by name (DNS, HTTP, HTTPS), which is what a bare port reaches in the microVM.
pub const PUBLIC_EGRESS_PORTS: [u16; 3] = [53, 80, 443];

/// SMTP, submission over TLS and submission: a public relay's, unless one listens on this host.
pub const MAIL_PORTS: [u16; 3] = [25, 465, 587];

/// Whether something listens on this host's loopback on `port` (a local mail relay).
pub fn listens_locally(port: u16) -> bool {
    TcpStream::connect_timeout(&std::net::SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(300)).is_ok()
}

/// The third thing `auto` doesn't move (#100 re-review): a bare `connect` port (no `socket`, no
/// `address`) other than 3306 ([`auto_db_gap`]) and [`PUBLIC_EGRESS_PORTS`]. gelada lets it
/// reach any host on it, the guest only public names, and nothing says where it goes: a Redis
/// or memcached on this host, a Postgres in a container, an SMTP relay on `localhost:25` would
/// be lost without a word. `egress`: the plan's bare ports after [`resolve_db`].
///
/// Mail submission ([`MAIL_PORTS`]) goes to a public relay by name (WP Mail SMTP, layer 2's hosts
/// police it) unless a relay listens on this host's loopback (`local(port)`): only then does it
/// keep `auto` on gelada (#100 second re-review).
pub fn auto_port_gap(egress: &[u16], local: &dyn Fn(u16) -> bool) -> Option<String> {
    let ports: Vec<u16> = egress
        .iter()
        .copied()
        .filter(|p| *p != crate::guest::DB_FORWARD && !PUBLIC_EGRESS_PORTS.contains(p) && (!MAIL_PORTS.contains(p) || local(*p)))
        .collect();
    let first = *ports.first()?;
    Some(format!(
        "layer1.network.connect port(s) {} have no \"socket\" or \"address\": gelada reaches any host on them, the microVM only public \
         names, and nothing says where they go (a Redis, memcached, Postgres or mail server on this host or its network would be lost): \
         give each its target, e.g. {{ \"port\": {first}, \"address\": \"127.0.0.1:{first}\" }} or a \"socket\", or set \"isolation\": \"microvm\" \
         if they only go to public names",
        ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")
    ))
}

/// What the guest must hold for one pool: `pm.max_children` workers of `memory_limit` each
/// (`None`: `-1`, no limit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSize {
    pub name: String,
    pub max_children: u32,
    pub memory_limit: Option<u64>,
}

/// The host's memory (MiB, `MemTotal`) and the CPUs this process may use.
pub fn host_resources() -> (u64, u32) {
    let mem = fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|m| m.lines().find_map(|l| l.strip_prefix("MemTotal:").and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())))
        .map_or(0, |kib| kib >> 10);
    let cpus = thread::available_parallelism().map_or(1, |n| u32::try_from(n.get()).unwrap_or(u32::MAX));
    (mem, cpus)
}

/// A pool's [`PoolSize`]: its `pm.max_children` (php-fpm requires it; 5 when it can't be read),
/// and `memory_limit` as the pool sets it (`php_admin_value`, then `php_value`), else as PHP's
/// ini files do, else PHP's default, 128M.
pub fn pool_size(pool: &crate::phpconf::Pool, capture: &capture::Capture) -> Result<PoolSize, String> {
    let max_children = pool.get("pm.max_children").and_then(|v| v.trim().parse::<u32>().ok()).filter(|n| *n > 0).unwrap_or(5);
    let limit = pool
        .get("php_admin_value[memory_limit]")
        .or_else(|| pool.get("php_value[memory_limit]"))
        .map(str::to_owned)
        .or_else(|| capture.memory_limit.clone())
        .unwrap_or_else(|| "128M".to_owned());
    let memory_limit = crate::phpconf::ini_size(&limit).map_err(|e| format!("pool [{}]: {e}", pool.name))?;
    Ok(PoolSize { name: pool.name.clone(), max_children, memory_limit })
}

/// What a guest needs besides its workers: its kernel, init, php-fpm's master, opcache's shared
/// memory and some page cache.
pub const GUEST_OVERHEAD_MIB: u64 = 256;

/// The guest's size for a pool, and the line that says why ([`size_guest`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sized {
    pub mem_mib: u32,
    pub vcpus: u32,
    pub said: String,
}

/// The guest's memory and vCPUs for `pool` on a host with `host` (MiB, CPUs) (#100 re-review:
/// a pool that worked under gelada must not be OOM-killed in a fixed 512 MiB guest). It needs
/// `pm.max_children × memory_limit` plus [`GUEST_OVERHEAD_MIB`]; a guest gets at least 512 MiB
/// (memory a guest doesn't touch is never the host's), at most three quarters of the host's.
/// vCPUs: one per four workers, at least 2, at most the host's. `--mem` / `--vcpus` win.
/// Under `auto` (`auto`), a pool that can't fit (more than the cap, more than `--mem`, or no
/// memory limit to size from) is an `Err`: gelada runs it as before. Under `microvm` the guest
/// gets the cap and the line says it's short.
pub fn size_guest(pool: &PoolSize, host: (u64, u32), flag_mem: Option<u32>, flag_vcpus: Option<u32>, auto: bool) -> Result<Sized, String> {
    let (host_mem, host_cpus) = host;
    let cap = host_mem * 3 / 4;
    let vcpus = flag_vcpus.unwrap_or_else(|| pool.max_children.div_ceil(4).max(2).min(host_cpus.max(1)));
    let what = |limit: u64| format!("pool [{}] has pm.max_children {} × memory_limit {} MiB + {GUEST_OVERHEAD_MIB} MiB", pool.name, pool.max_children, limit >> 20);
    let Some(limit) = pool.memory_limit else {
        return match flag_mem {
            Some(m) => Ok(Sized { mem_mib: m, vcpus, said: format!("the guest gets {m} MiB (--mem) and {vcpus} vCPUs: pool [{}] has no memory_limit", pool.name) }),
            None if auto => Err(format!(
                "pool [{}] has memory_limit = -1 (no limit), so the microVM can't be sized for its {} workers: set memory_limit or --mem",
                pool.name, pool.max_children
            )),
            None => Ok(Sized { mem_mib: 512, vcpus, said: format!("the guest gets 512 MiB and {vcpus} vCPUs: pool [{}] has no memory_limit to size from", pool.name) }),
        };
    };
    let need = u64::from(pool.max_children) * (limit >> 20) + GUEST_OVERHEAD_MIB;
    let to_u32 = |m: u64| u32::try_from(m).unwrap_or(u32::MAX);
    match flag_mem {
        Some(m) if auto && need > u64::from(m) => {
            Err(format!("{} = {need} MiB, more than the guest's --mem {m} MiB: under load its workers would be killed", what(limit)))
        }
        Some(m) => Ok(Sized { mem_mib: m, vcpus, said: format!("the guest gets {m} MiB (--mem) and {vcpus} vCPUs: {} = {need} MiB", what(limit)) }),
        None if need > cap && auto => Err(format!(
            "{} = {need} MiB, more than this host gives one microVM ({cap} MiB, three quarters of its {host_mem} MiB): under load its workers would be killed",
            what(limit)
        )),
        None if need > cap => Ok(Sized {
            mem_mib: to_u32(cap),
            vcpus,
            said: format!("the guest gets {cap} MiB, three quarters of this host's, and {vcpus} vCPUs: {} = {need} MiB, so it is short", what(limit)),
        }),
        None => {
            let mem = need.max(512);
            Ok(Sized { mem_mib: to_u32(mem), vcpus, said: format!("the guest gets {mem} MiB and {vcpus} vCPUs: {} = {need} MiB", what(limit)) })
        }
    }
}

/// What a start's writable disks may still take, all of them: each [`disk_room`] (`want`, and the
/// disk's size and allocation when it exists), existing disks included, since they grow too.
pub fn writable_room(disks: &[(u64, Option<(u64, u64)>)]) -> u64 {
    disks.iter().map(|(want, existing)| disk_room(*want, *existing)).sum()
}

/// One message to systemd's notify socket, when the launcher runs under it.
pub fn notify(msg: &str) {
    if let Ok(s) = std::env::var("NOTIFY_SOCKET") {
        let _ = notify_to(&s, msg);
    }
}

fn notify_to(socket: &str, msg: &str) -> io::Result<()> {
    let d = UnixDatagram::unbound()?;
    if let Some(name) = socket.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt as _;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
        d.send_to_addr(msg.as_bytes(), &addr)?;
    } else {
        d.send_to(msg.as_bytes(), socket)?;
    }
    Ok(())
}

fn status(what: &str) {
    notify(&format!("STATUS={what}\n"));
}

/// Set once the VM serves, or the start has failed or fallen back, or a stop began: the start's
/// timeout extensions stop (they must never stretch systemd's stop timeout either).
static SERVING: AtomicBool = AtomicBool::new(false);

/// No more `EXTEND_TIMEOUT_USEC` ([`extend_start_timeout`]).
pub fn stop_extending() {
    SERVING.store(true, Ordering::SeqCst);
}
/// How much longer each extension asks systemd for, and how often one is sent.
pub const EXTEND_BY: Duration = Duration::from_secs(30);
const EXTEND_EVERY: Duration = Duration::from_secs(10);

/// `--start-within`'s default: how long a start may take, in all.
pub const START_WITHIN: Duration = Duration::from_secs(600);

/// This start's deadline and the time it was given ([`extend_start_timeout`]).
static START: std::sync::OnceLock<(Instant, Duration)> = std::sync::OnceLock::new();

/// A first start captures the host's PHP, builds its disks and makes a snapshot, which may take
/// longer than systemd's `TimeoutStartSec` (#100 review): while it does, systemd is told every
/// 10 s that it needs 30 s more (`EXTEND_TIMEOUT_USEC`), until the VM serves or the start ends.
/// The start itself never runs past `within` (#100 re-reviews): the launcher's watchdog runs
/// gelada at that deadline, whatever step it is in (`main.rs`), every disk tool still running is
/// stopped shortly after ([`tool_status_until`]), and the boot never begins past it
/// ([`start_deadline`]). The deadline holds without `NOTIFY_SOCKET` too.
pub fn extend_start_timeout(within: Duration) {
    static STARTED: std::sync::Once = std::sync::Once::new();
    let _ = START.set((Instant::now() + within, within));
    if std::env::var_os("NOTIFY_SOCKET").is_none() {
        return;
    }
    STARTED.call_once(|| {
        thread::spawn(move || {
            while !SERVING.load(Ordering::SeqCst) {
                notify(&format!("EXTEND_TIMEOUT_USEC={}\n", EXTEND_BY.as_micros()));
                // In small steps, so a stop that begins meanwhile sends no further extension.
                let t = Instant::now();
                while t.elapsed() < EXTEND_EVERY && !SERVING.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(100));
                }
            }
        });
    });
}

/// The start's deadline and the time it was given, once [`extend_start_timeout`] set them.
pub fn deadline() -> Option<(Instant, Duration)> {
    START.get().copied()
}

/// The record that a start of this site ran past its deadline (#100 second re-review): until
/// the config or the app root changes, the next starts go straight to gelada.
fn deadline_record(state: &Path) -> PathBuf {
    state.join("deadline-fallback.json")
}

/// What the record is kept for: the config's sha256 and the app root's mtime and ctime (a plugin
/// or theme installed, a file added at the top).
fn site_stamp(loaded: &Loaded) -> String {
    let m = fs::metadata(&loaded.root).ok();
    format!(
        "config {} root {}.{} {}.{}",
        loaded.sha256,
        m.as_ref().map_or(0, |m| m.mtime()),
        m.as_ref().map_or(0, |m| m.mtime_nsec()),
        m.as_ref().map_or(0, |m| m.ctime()),
        m.as_ref().map_or(0, |m| m.ctime_nsec())
    )
}

/// Records that this start ran past its deadline (`why`), in its state folder.
pub fn record_deadline_fallback(loaded: &Loaded, opts: &Options, why: &str) {
    let state = state_base(loaded, opts);
    let _ = fs::create_dir_all(&state);
    let v = serde_json::json!({ "stamp": site_stamp(loaded), "why": why, "at": now().0 });
    let _ = fs::write(deadline_record(&state), v.to_string());
}

/// Why `auto` goes straight to gelada: an earlier start of this same site and config ran past its
/// deadline. A record for another stamp is removed (the site or config changed: try again).
pub fn deadline_fallback(loaded: &Loaded, opts: &Options) -> Option<String> {
    let file = deadline_record(&state_base(loaded, opts));
    let v: serde_json::Value = serde_json::from_str(&fs::read_to_string(&file).ok()?).ok()?;
    if v["stamp"].as_str() != Some(site_stamp(loaded).as_str()) {
        let _ = fs::remove_file(&file);
        return None;
    }
    Some(format!(
        "a start of this site ran past its deadline before ({}), so it stays on gelada until securecore.json or the site changes, or {} is removed",
        v["why"].as_str().unwrap_or("?"),
        file.display()
    ))
}

/// `Err` once this start has run past its deadline ([`extend_start_timeout`]); checked before
/// the boot.
pub fn start_deadline() -> Result<(), String> {
    match START.get() {
        Some((d, within)) if Instant::now() >= *d => {
            Err(format!("the start took longer than {} s (--start-within), so the microVM gives up on it", within.as_secs()))
        }
        _ => Ok(()),
    }
}

/// Bytes the filesystem holding `path` has in all.
fn fs_size(path: &Path) -> Result<u64, String> {
    let c = cpath(path)?;
    // SAFETY: statvfs(2) fills the zeroed struct passed.
    unsafe {
        let mut s: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut s) < 0 {
            return Err(format!("{}: {}", path.display(), io::Error::last_os_error()));
        }
        Ok(s.f_blocks as u64 * s.f_frsize as u64)
    }
}

/// What a start may leave free at the least on the state folder's filesystem, which is often the
/// database's too (#100 review): a twentieth of it, and at least 1 GiB.
pub fn space_margin(fs_bytes: u64) -> u64 {
    (fs_bytes / 20).max(1 << 30)
}

/// Whether the new files a start makes (`needs`: what, bytes) fit the state folder's filesystem
/// (`free` of `fs_bytes`, less `others`: what other starts on it keep for their disks,
/// [`crate::space`]) with [`space_margin`] left.
pub fn space_ok(needs: &[(String, u64)], free: u64, others: u64, fs_bytes: u64) -> Result<(), String> {
    let total: u64 = needs.iter().map(|(_, b)| b).sum();
    let margin = space_margin(fs_bytes);
    if total + margin + others <= free {
        return Ok(());
    }
    Err(format!(
        "this start needs {} MiB on the state folder's filesystem ({}) and keeps {} MiB free beside it (for the database and the host), but it has {} MiB free{}",
        total >> 20,
        needs.iter().map(|(w, b)| format!("{w} {} MiB", b >> 20)).collect::<Vec<_>>().join(", "),
        margin >> 20,
        free >> 20,
        if others > 0 { format!(", {} MiB of which other sites' starts keep for their disks", others >> 20) } else { String::new() }
    ))
}

/// What the host keeps for itself and its database, out of every guest's reach: a quarter of its
/// memory, and at least 2 GiB (MiB).
pub fn host_memory_reserve(host_mem: u64) -> u64 {
    (host_mem / 4).max(2048)
}

/// Whether a guest of `mine` MiB fits beside the `others` MiB the other running guests on this
/// host hold (#100 second re-review): a guest's memory, once touched, stays the host's until it
/// stops (no balloon), so together they stay within the host's memory less
/// [`host_memory_reserve`]. Checked under `auto` only.
pub fn memory_ok(mine: u64, others: u64, host_mem: u64) -> Result<(), String> {
    let reserve = host_memory_reserve(host_mem);
    let budget = host_mem.saturating_sub(reserve);
    if mine + others <= budget {
        return Ok(());
    }
    Err(format!(
        "this guest's {mine} MiB and the {others} MiB the other microVMs on this host hold come to more than its guests' budget, \
         {budget} MiB ({host_mem} MiB less {reserve} MiB kept for the database and the host)"
    ))
}

/// One VM, prepared ([`prepare_all`]): nothing is left that can fail but the boot.
pub struct Prepared {
    plan: Plan,
    user: User,
    sockets: Vec<(u16, jail::SocketDir)>,
    env: Vec<(String, String)>,
    ini: Option<String>,
    machine_parts: (PathBuf, PathBuf, PathBuf, Vec<(String, PathBuf)>, String, String),
    sync: Vec<SyncFolder>,
    /// The listening socket's owner, group and mode: the pool's, or the flags'.
    listen_mode: SocketMode,
    /// Who may connect: the pool's `listen.allowed_clients`, or its ACLs.
    admit: Admit,
    _lock: fs::File,
    pub pool_name: String,
    /// The guest's size ([`size_guest`]).
    mem_mib: u32,
    vcpus: u32,
    /// The space this start keeps in the shared record while it runs ([`crate::space`]), and
    /// what its writable disks may still take (all it keeps once the snapshot is written).
    space: crate::space::Reservation,
    writable_room: u64,
}

/// [`prepare_all`] for one pool (`opts.pool`, or the only one).
fn prepare(loaded: &Loaded, opts: &Options, capture: capture::Capture) -> Result<Prepared, String> {
    let pool = match &opts.pool {
        Some(n) => capture.pools.iter().find(|p| p.name == *n).ok_or_else(|| format!("php-fpm's config has no pool [{n}]"))?,
        None => &capture.pools[0],
    };
    let hints = pool_hints(&opts.php_root, pool)?;
    let mut plan = plan_with(loaded, opts, &hints, false)?;
    // Where the pool listens, with its listen.owner/group/mode; --listen and its flags win.
    let listen_mode = match (&opts.listen, &hints.listen, hints.listen_mode) {
        (None, Some(_), Some(m)) => m,
        _ => opts.listen_mode,
    };
    // The pool's own rule of who may connect stands whatever --listen says (#102 verification);
    // one that can't apply to --listen's kind of socket is refused, never dropped.
    let admit = listen_admit(&plan.listen, &hints.admit).map_err(|e| format!("pool [{}]: {e}", pool.name))?;
    let user = jail::user(&opts.vm_user)?;
    let lock = lock_state(&plan.state)?;
    let db = db_ids(&opts.db_user);
    let db_host = site_db_host(&plan.root);
    let approved = DbApproved { address: opts.db_address.clone(), socket: opts.db_socket.clone() };
    let said = resolve_db(&mut plan, db_host.as_deref(), &capture.mysql_sockets, &approved, &|p, a| trusted_db_socket(p, db, a))?;
    // Under `auto`, a start that would cost the site its database or its web server's FastCGI
    // stays on gelada (#100 review): before anything is built.
    if loaded.config.layer1.isolation() == securecore_config::Isolation::Auto {
        let egress = crate::egress::Egress::new(loaded, plan.egress.clone());
        let own = crate::egress::host_addresses();
        let reachable = |h: &str, p: u16| -> Result<(), String> {
            egress.allows(h, p)?;
            crate::egress::addresses(h, p, &own).map(|_| ())
        };
        let no_db = plan.egress.contains(&crate::guest::DB_FORWARD);
        if let Some(why) = auto_db_gap(no_db, said.as_deref(), db_host.as_deref(), &reachable) {
            return Err(why);
        }
        if let Some(why) = auto_listen_gap(&pool.name, pool.listen().as_deref(), opts.listen.is_some(), &hints.admit) {
            return Err(why);
        }
        if let Some(why) = auto_port_gap(&plan.egress, &listens_locally) {
            return Err(why);
        }
    }
    let auto = loaded.config.layer1.isolation() == securecore_config::Isolation::Auto;
    let sized = size_guest(&pool_size(pool, &capture)?, host_resources(), opts.mem_mib, opts.vcpus, auto)?;
    if let Some(said) = said {
        log(&said);
    }
    log(&sized.said);
    let (mem_mib, vcpus) = (sized.mem_mib, sized.vcpus);
    // Checked again here, not only in host_checks: what is checked is what is bind-mounted.
    let sockets = open_sockets(&plan, user)?;
    claim_state(&plan)?;
    // The vault's env sources and the pool's env[] (#100 review): a name the launcher lacks
    // refuses now, not after the choice.
    let mut names = opts.guest_env.clone();
    let mut env = guest_env(loaded, &names, |n| std::env::var(n).ok())?;
    for r in pool.env_refs() {
        if !env.iter().any(|(n, _)| *n == r)
            && let Ok(v) = std::env::var(&r)
            && crate::guest::env_name_ok(&r)
            && v.len() <= crate::guest::MAX_ENV_VALUE
        {
            names.push(r.clone());
            env.push((r, v));
        }
    }
    if !env.is_empty() {
        // The names only, never a value.
        log(&format!("the guest's php-fpm gets {} from the launcher's environment, in each start message", env.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(" ")));
    }
    let ini = read_site_ini(opts.guest_ini.as_deref())?;
    let files = verify(&opts.assets, &plan.state)?;
    // The guest's php-fpm config for this pool, and the layers' keys.
    let (fpm_conf, dropped) = crate::phpconf::guest_fpm_conf(pool, plan.pool.uid, plan.pool.gid, FPM_PORT);
    if !dropped.is_empty() {
        log(&format!("pool [{}]: the guest's pool leaves out the host's {} (host paths and sockets)", pool.name, dropped.join(" ")));
    }
    let conf_files = capture::conf_files(&capture, &fpm_conf);
    let conf_key = capture::conf_key(&conf_files);
    // The PHP layer also holds the folders the guest mounts on: the site root and any tmpfs.
    let mut mounts = vec![plan.guest_root.clone()];
    mounts.extend(plan.tmpfs.iter().cloned());
    // The host's own config paths, where the config layer is bound too (a PHP that reads its
    // compiled-in ones: the CLI layer 3's helper runs).
    let scan_dir = capture.scan_dirs.first().filter(|d| no_space("a scan folder", d).is_ok()).cloned();
    let ini_file = capture.ini.as_ref().map(|i| i.path.clone()).filter(|p| no_space("php.ini", p).is_ok());
    mounts.extend(scan_dir.iter().cloned());
    let mount_files: Vec<String> = ini_file.iter().cloned().collect();
    let php_key = sha_of(&format!("{}\nmounts {mounts:?}\nfiles {mount_files:?}\n", capture.php_key));
    let php_path = plan.cache.join(format!("php-{}.ext4", &php_key[..16]));
    let conf_path = plan.state.join(format!("conf-{}.ext4", &conf_key[..16]));
    // The site's key: the tree without the writable folders, the state folder and the config
    // file, whose bytes are keyed by their own sha256 instead (copying the same file in again
    // changes its mtime, not the site).
    let mut skip: BTreeSet<PathBuf> = plan.disks.iter().map(|d| d.host.clone()).collect();
    skip.insert(plan.cache.clone());
    skip.insert(plan.state.clone());
    skip.extend(loaded.path.file_name().map(|name| plan.root.join(name)));
    let (tree, bytes, entries) = site_sha256(&plan.root, &skip).map_err(|e| format!("{}: {e}", plan.root.display()))?;
    let site = sha_of(&format!("tree {tree}\nconfig {}\n", loaded.sha256));
    // Space for what this start makes new, with a margin, before any of it is made.
    let mut needs: Vec<(String, u64)> = Vec::new();
    let site_path = plan.state.join(format!("site-{}.ext4", &site[..16]));
    if !site_path.is_file() {
        needs.push(("site disk".into(), bytes * 4 / 3 + (64 << 20)));
    }
    if !php_path.is_file() {
        let b: u64 = capture.items.iter().map(|i| if let capture::Item::File { size, .. } = i { size.div_ceil(4096) * 4096 } else { 4096 }).sum();
        needs.push(("PHP layer".into(), b + b / 5 + (32 << 20)));
    }
    if !conf_path.is_file() {
        needs.push(("config layer".into(), 33 << 20));
    }
    // Each writable disk is sparse: what it may still take as the guest fills it (#100 review).
    let mut disks_now = Vec::new();
    for d in &plan.disks {
        let want = disk_mib(opts.write_disk_mib, folder_usage(&plan, d)?.0) << 20;
        let existing = fs::metadata(plan.state.join(format!("{}.ext4", d.id))).ok().filter(|m| m.is_file()).map(|m| (m.len(), m.blocks() * 512));
        disks_now.push((want, existing));
    }
    let writable = writable_room(&disks_now);
    if writable > 0 {
        needs.push(("writable disks, as they fill".into(), writable));
    }
    if opts.snapshot {
        needs.push(("snapshot".into(), u64::from(mem_mib) << 20));
    }
    // Checked and kept in the shared record under its lock (#100 re-review): what other starts
    // on this filesystem keep for their disks counts as taken.
    let total: u64 = needs.iter().map(|(_, b)| b).sum();
    let dev = fs::metadata(&plan.state).map_err(|e| format!("{}: {e}", plan.state.display()))?.dev();
    let host_mem = host_resources().0;
    let space = crate::space::reserve(&opts.space_ledger, &plan.state, dev, total, u64::from(mem_mib), |others| {
        // Free space measured under the lock (#100 second re-review), and under `auto` every
        // guest on this host within its memory budget.
        space_ok(&needs, free_bytes(&plan.state)?, others.bytes, fs_size(&plan.state)?)?;
        if auto {
            memory_ok(u64::from(mem_mib), others.mem_mib, host_mem)?;
        }
        Ok(())
    })?;
    // The layers, cached by what they hold.
    status("building the guest's disks");
    if !php_path.is_file() {
        let t = Instant::now();
        let stage = plan.cache.join("php-stage");
        capture::remove_stage(&stage);
        fs::create_dir_all(&stage).map_err(|e| format!("{}: {e}", stage.display()))?;
        let made = capture::stage_php(&opts.php_root, &capture.items, &mounts, &mount_files, &stage).map_err(|e| e.to_string()).and_then(|()| capture::image(&stage, &php_path));
        capture::remove_stage(&stage);
        let mb = made?;
        log(&format!("built the PHP layer {} ({mb} MiB, {} entries) in {:.0} ms", php_path.display(), capture.items.len(), ms(t)));
        remove_others(&plan.cache, "php-", &php_path);
    }
    if !conf_path.is_file() {
        let t = Instant::now();
        let stage = plan.state.join("conf-stage");
        capture::remove_stage(&stage);
        let made = capture::stage_conf(&conf_files, &stage).map_err(|e| format!("{}: {e}", stage.display())).and_then(|()| capture::image(&stage, &conf_path));
        capture::remove_stage(&stage);
        made?;
        log(&format!("built the config layer {} ({} files) in {:.0} ms", conf_path.display(), conf_files.len(), ms(t)));
        remove_others(&plan.state, "conf-", &conf_path);
    }
    for p in [&php_path, &conf_path] {
        std::os::unix::fs::chown(p, Some(0), Some(user.gid)).map_err(|e| e.to_string())?;
        fs::set_permissions(p, fs::Permissions::from_mode(0o640)).map_err(|e| e.to_string())?;
    }
    // The site disk is copied as the pool user (#100 review: a file it can't read refuses now).
    let site_path = site_disk(&plan, &site, bytes, entries, user)?;
    let mut disks = Vec::new();
    let mut sync = Vec::new();
    let mut sizes = Vec::new();
    for d in &plan.disks {
        let (used, _) = folder_usage(&plan, d)?;
        let (path, bytes) = write_disk(&plan, d, disk_mib(opts.write_disk_mib, used), user)?;
        disks.push((d.id.clone(), path));
        sync.push(SyncFolder { rel: d.rel(&plan.root)?, id: d.id.clone(), cap: bytes });
        sizes.push((bytes >> 20).to_string());
    }
    let mut args = boot_args(&plan, opts, &env.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), &capture.fpm);
    if let Some(d) = &scan_dir {
        let _ = write!(args, " sc.inidir={d}");
    }
    if let Some(f) = &ini_file {
        let _ = write!(args, " sc.inifile={f}");
    }
    let key = Key {
        files,
        php: php_key,
        conf: conf_key,
        site,
        config: loaded.sha256.clone(),
        machine: format!(
            "mem {} vcpus {} args {args} drives {} size {}",
            mem_mib,
            vcpus,
            disks.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>().join(","),
            sizes.join(",")
        ),
    };
    let pool_name = pool.name.clone();
    // Built: from now on the writable disks' growth is still to come, and the snapshot until it
    // is written (#100 second re-review: [`run`] lets it go after the boot).
    let snapshot_bytes = if opts.snapshot { u64::from(mem_mib) << 20 } else { 0 };
    space.keep(writable + snapshot_bytes)?;
    Ok(Prepared {
        plan,
        user,
        sockets,
        env,
        ini,
        machine_parts: (php_path, conf_path, site_path, disks, args, key.sha256()),
        sync,
        listen_mode,
        admit,
        _lock: lock,
        pool_name,
        mem_mib,
        vcpus,
        space,
        writable_room: writable,
    })
}

/// Removes `<dir>/<prefix>*` but `keep` (older layer disks).
fn remove_others(dir: &Path, prefix: &str, keep: &Path) {
    for e in fs::read_dir(dir).into_iter().flatten().flatten() {
        if e.file_name().to_string_lossy().starts_with(prefix) && e.path() != keep && e.path().extension().is_some_and(|x| x == "ext4") {
            let _ = fs::remove_file(e.path());
        }
    }
}

/// Each `connect[].socket`'s folder, opened with no symlink on its (resolved) path and held:
/// the jailed user's connect is checked through the handle ([`jail::can_connect_as`]), and
/// [`wire`] bind-mounts the same handle, so the two can't see different folders. Forks for each
/// check, so it runs before any thread starts.
fn open_sockets(plan: &Plan, user: User) -> Result<Vec<(u16, jail::SocketDir)>, String> {
    let mut out = Vec::new();
    for (port, socket) in &plan.sockets {
        let held = jail::SocketDir::open(socket)?;
        jail::can_connect_as(user, &held)?;
        out.push((*port, held));
    }
    Ok(out)
}

/// What a snapshot is valid for. Two starts with the same key boot the same bytes the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub files: Key0,
    /// The host's PHP layer and config layer (#101): their contents' sha256s.
    pub php: String,
    pub conf: String,
    pub site: String,
    pub config: String,
    /// Everything else that shapes the guest: memory, vCPUs, boot arguments (without the
    /// clock), the drives in order and their sizes.
    pub machine: String,
}

impl Key {
    pub fn sha256(&self) -> String {
        sha_of(&format!(
            "securecore-fpm microvm {PROTOCOL}\nfirecracker {}\njailer {}\nkernel {}\nrootfs {}\nphp {}\nconf {}\nsite {}\nconfig {}\nmachine {}\n",
            self.files.firecracker, self.files.jailer, self.files.kernel, self.files.rootfs, self.php, self.conf, self.site, self.config, self.machine
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
    let (status, stderr) = tool_status_until(cmd, what, tool_deadline())?;
    if !status.success() {
        return Err(format!("{what}: {status} {}", String::from_utf8_lossy(&stderr).trim()));
    }
    Ok(())
}

/// When a tool this start runs must have ended: the start's deadline ([`start_deadline`]), or
/// [`START_WITHIN`] from now when none was set.
pub fn tool_deadline() -> Instant {
    // A little past the start's: the watchdog (`main.rs`) acts at the deadline itself; this is
    // the stop for a tool that would outlive it.
    START.get().map_or_else(|| Instant::now() + START_WITHIN, |(d, _)| *d + Duration::from_secs(10))
}

/// Runs a tool (mke2fs, e2fsck, resize2fs) to its end or until `deadline`, whichever comes
/// first (#100 re-review: a copy from a stalled mount must never hold the start forever): past
/// it the tool is killed and reaped, and the start fails with why. Its status and the first
/// 64 KiB of its stderr.
pub fn tool_status_until(cmd: &mut Command, what: &str, deadline: Instant) -> Result<(std::process::ExitStatus, Vec<u8>), String> {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().map_err(|e| format!("{what}: {e}"))?;
    let stderr = child.stderr.take();
    let reader = thread::spawn(move || {
        let mut out = Vec::new();
        if let Some(e) = stderr {
            let _ = e.take(64 << 10).read_to_end(&mut out);
        }
        out
    });
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok((status, reader.join().unwrap_or_default())),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{what}: still running at the start's deadline (--start-within), so it was stopped"));
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(format!("{what}: {e}")),
        }
    }
}

/// e2fsck's verdict, by its exit code (e2fsck(8)): 0 clean and 1 errors corrected are fine
/// to grow; anything else (2 reboot needed, 4 errors left, 8 an operational error, a signal…)
/// is refused.
fn fsck_result(status: std::process::ExitStatus, stderr: &[u8]) -> Result<(), String> {
    match status.code() {
        Some(0 | 1) => Ok(()),
        _ => Err(format!("e2fsck: {status} {}", String::from_utf8_lossy(stderr).trim())),
    }
}

fn cpath(p: &Path) -> Result<std::ffi::CString, String> {
    std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).map_err(|_| format!("{}: holds a NUL", p.display()))
}

/// The fds the copy's source folder and its output image get in `mke2fs`'s process
/// (`-d /proc/self/fd/200`, the device `/proc/self/fd/201`): both opened as root, so the pool
/// user needs no right on the root-only folders around them.
const SOURCE_FD: libc::c_int = 200;
const OUTPUT_FD: libc::c_int = 201;

/// A folder to copy: `rel` inside the app root `root` (a resolved path). Every folder is
/// opened by walking from a handle on `root` ([`jail::open_dir_beneath`]'s rules: no symlink,
/// no `..` out), never reopened by path.
#[derive(Clone, Copy)]
struct Source<'a> {
    root: &'a Path,
    rel: &'a Path,
}

/// The folder `rel` names (empty: the root itself), for openat2 from the root's handle.
fn rel_cstr(rel: &Path) -> Result<std::ffi::CString, String> {
    if rel.as_os_str().is_empty() { Ok(c".".to_owned()) } else { cpath(rel) }
}

/// Runs `cmd` as `who`, with no supplementary groups. With `source`, first (still root, in a
/// private mount namespace of its own) the app root is opened with no symlink on its path, every
/// folder in `masks` (relative to it) is opened beneath it and covered by an empty read-only
/// tmpfs mounted onto that handle (`/proc/self/fd/<n>`), and the source folder is opened beneath
/// it (after the masks, so they apply) as fd [`SOURCE_FD`]: the command reads the tree through
/// it, as `who`, so it sees only what `who` may read, never the masked folders, and needs no
/// search right on the folders above the source. A symlink put anywhere on the way after the
/// plan's checks fails the open (ELOOP), so the command never runs.
fn as_user(cmd: &mut Command, who: User, source: Option<Source<'_>>, masks: &[PathBuf], output: Option<&fs::File>) -> Result<(), String> {
    // Nothing of the launcher's environment (it holds the guest's secrets, #72) but PATH, which
    // finds the tool.
    cmd.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    let source = source.map(|s| Ok::<_, String>((cpath(s.root)?, rel_cstr(s.rel)?))).transpose()?;
    let output = output.map(|f| f.as_raw_fd());
    let masks: Vec<std::ffi::CString> = masks.iter().map(|m| rel_cstr(m)).collect::<Result<_, _>>()?;
    let (tmpfs, none) = (c"tmpfs", c"none");
    let data = c"mode=0755,size=4k";
    let dir_flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    // SAFETY: only syscalls between fork and exec, on strings made before the fork (the fd
    // paths are written into a stack buffer).
    unsafe {
        cmd.pre_exec(move || {
            let err = || Err(io::Error::last_os_error());
            if let Some((root, rel)) = &source {
                if !masks.is_empty() {
                    if libc::unshare(libc::CLONE_NEWNS) < 0 {
                        return err();
                    }
                    if libc::mount(none.as_ptr(), c"/".as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) < 0 {
                        return err();
                    }
                }
                // Opened in this mount namespace, so the masks mounted through it apply to it.
                let root_fd = jail::openat2_raw(libc::AT_FDCWD, root, dir_flags, jail::NO_LINKS);
                if root_fd < 0 {
                    return err();
                }
                for m in &masks {
                    let fd = jail::openat2_raw(root_fd, m, dir_flags, jail::BENEATH);
                    if fd < 0 {
                        return err();
                    }
                    let mut at = [0u8; 32];
                    let target = jail::proc_fd_path(fd, &mut at);
                    let flags = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
                    if libc::mount(tmpfs.as_ptr(), target, tmpfs.as_ptr(), flags, data.as_ptr().cast()) < 0 {
                        return err();
                    }
                    libc::close(fd);
                }
                let fd = jail::openat2_raw(root_fd, rel, dir_flags, jail::BENEATH);
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
/// `who` (the site's pool user, [`as_user`]) with `masks` (relative to the app root) left out,
/// and the image's root owned like `<from>`. `from` and every mask are opened beneath the app
/// root first, here, to refuse a link on the way with the reason; the copy opens them again the
/// same way in its own process, so a link put there in between fails it too.
fn mke2fs(who: User, from: Source<'_>, masks: &[PathBuf], to: &Path, mb: u64, inodes: u64, journal: bool) -> Result<(), String> {
    let shown = from.root.join(from.rel);
    let src = jail::open_dir_beneath(from.root, from.rel)?;
    for m in masks {
        jail::open_dir_beneath(from.root, m).map_err(|e| format!("a writable folder left out of the copy: {e}"))?;
    }
    let m = fs::File::from(src).metadata().map_err(|e| format!("{}: {e}", shown.display()))?;
    let tmp = to.with_extension("ext4.new");
    let _ = fs::remove_file(&tmp);
    // Made and opened here, owned by `who`, and handed to mke2fs (as `who`) as an fd.
    let out = {
        use std::os::unix::fs::OpenOptionsExt as _;
        let f = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::os::unix::fs::fchown(&f, Some(who.uid), Some(who.gid)).map_err(|e| e.to_string())?;
        f
    };
    let mut cmd = Command::new("mke2fs");
    cmd.args(["-q", "-F", "-t", "ext4", "-b", "4096", "-m", "0"]).arg("-N").arg(inodes.to_string());
    if !journal {
        cmd.args(["-O", "^has_journal"]);
    }
    cmd.arg("-E").arg(format!("root_owner={}:{}", m.uid(), m.gid())).arg("-d").arg(format!("/proc/self/fd/{SOURCE_FD}"));
    cmd.arg(format!("/proc/self/fd/{OUTPUT_FD}")).arg(format!("{mb}M"));
    as_user(&mut cmd, who, Some(from), masks, Some(&out))?;
    if let Err(e) = run_tool(&mut cmd, &format!("mke2fs {} (copying {} as uid {})", to.display(), shown.display(), who.uid)) {
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
        let masks: Vec<PathBuf> = plan.disks.iter().map(|d| d.rel(&plan.root)).collect::<Result<_, _>>()?;
        mke2fs(plan.pool, Source { root: &plan.root, rel: Path::new("") }, &masks, &path, mb, entries * 2 + 1024, false)?;
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

/// What a writable folder on the host holds now: the bytes its files take on disk (each inode
/// once) and its files and folders. Metadata only, walked through the folder opened beneath the
/// app root: no link is followed, and another mount inside it isn't walked.
pub fn folder_usage(plan: &Plan, disk: &WriteDisk) -> Result<(u64, u64), String> {
    let held = jail::open_dir_beneath(&plan.root, &disk.rel(&plan.root)?)?;
    let via = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()));
    let dev = fs::metadata(&via).map_err(|e| format!("{}: {e}", disk.host.display()))?.dev();
    let (mut bytes, mut entries) = (0u64, 0u64);
    let mut seen = BTreeSet::new();
    let mut stack = vec![via];
    while let Some(dir) = stack.pop() {
        let Ok(list) = fs::read_dir(&dir) else { continue };
        for e in list.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.dev() != dev {
                continue;
            }
            if m.is_dir() {
                entries += 1;
                stack.push(e.path());
            } else if m.is_file() {
                entries += 1;
                if m.nlink() <= 1 || seen.insert(m.ino()) {
                    bytes += m.blocks() * 512;
                }
            }
            if entries > crate::sync::MAX_ENTRIES as u64 {
                return Ok((bytes, entries));
            }
        }
    }
    Ok((bytes, entries))
}

/// A writable disk's size in MiB for a folder taking `used` bytes: twice that and at least
/// 1 GiB, rounded up to a power of two (so the snapshot's key changes only when it doubles), and
/// never less than `--write-disk-mib`.
pub fn disk_mib(flag: u64, used: u64) -> u64 {
    (2 * used).div_ceil(1 << 20).max(1024).next_power_of_two().max(flag)
}

/// Whether a writable folder (`used` bytes, `entries` files and folders) can go onto its disk:
/// the sync handles at most [`crate::sync::MAX_ENTRIES`] entries, and a new disk's copy needs
/// `used` plus 64 MiB free where the state folder is (`free`; `None`: the disk exists already).
pub fn fits(host: &Path, used: u64, entries: u64, free: Option<u64>) -> Result<(), String> {
    let max = crate::sync::MAX_ENTRIES as u64;
    if entries > max {
        return Err(format!("{} holds more than {max} files and folders, more than the folder sync keeps in step", host.display()));
    }
    if let Some(free) = free
        && used + (64 << 20) > free
    {
        return Err(format!(
            "{} takes {} MiB, and the state folder's filesystem has {} MiB free for its writable disk",
            host.display(),
            used >> 20,
            free >> 20
        ));
    }
    Ok(())
}

/// Bytes free for root's use on the filesystem holding `path`.
fn free_bytes(path: &Path) -> Result<u64, String> {
    let c = cpath(path)?;
    // SAFETY: statvfs(2) fills the zeroed struct passed.
    unsafe {
        let mut s: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut s) < 0 {
            return Err(format!("{}: {}", path.display(), io::Error::last_os_error()));
        }
        Ok(s.f_bfree as u64 * s.f_frsize as u64)
    }
}

/// A writable folder's disk, `mib` MiB ([`disk_mib`]): made once from the folder's contents,
/// then kept (the guest's writes live there, and sync with the host's folder, [`crate::sync`]),
/// and grown in place (`e2fsck` + `resize2fs`, offline: it isn't mounted before the guest's
/// start message) when `mib` is more than it has. Owned by the jailed user, private. Its path and
/// its size in bytes.
fn write_disk(plan: &Plan, disk: &WriteDisk, mib: u64, user: User) -> Result<(PathBuf, u64), String> {
    let path = plan.state.join(format!("{}.ext4", disk.id));
    let want = mib << 20;
    if !path.is_file() {
        let rel = disk.rel(&plan.root)?;
        // Measured through the folder opened beneath the root, as the copy reads it.
        let held = jail::open_dir_beneath(&plan.root, &rel)?;
        let via = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()));
        let (_, bytes, entries) = site_sha256(&via, &BTreeSet::new()).map_err(|e| format!("{}: {e}", disk.host.display()))?;
        drop(held);
        if bytes + (64 << 20) > want {
            return Err(format!(
                "{} holds {} MiB, which doesn't fit a {mib} MiB writable disk: raise --write-disk-mib",
                disk.host.display(),
                bytes >> 20
            ));
        }
        mke2fs(plan.pool, Source { root: &plan.root, rel: &rel }, &[], &path, mib, (entries * 2 + 4096).max(16384), true)?;
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
            let (status, stderr) = tool_status_until(&mut fsck, "e2fsck", tool_deadline())?;
            fsck_result(status, &stderr)?;
            img.set_len(want).map_err(|e| e.to_string())?;
            let mut resize = Command::new("resize2fs");
            resize.arg(&via);
            as_user(&mut resize, user, None, &[], Some(&img))?;
            run_tool(&mut resize, "resize2fs")?;
            log(&format!("grew the writable disk {} for {} from {} to {mib} MiB", path.display(), disk.guest, have >> 20));
        } else if have > want {
            log(&format!(
                "the writable disk {} is {} MiB, more than the {mib} MiB it needs now: disks only grow; keeping it",
                path.display(),
                have >> 20
            ));
        }
    }
    std::os::unix::fs::chown(&path, Some(user.uid), Some(user.gid)).map_err(|e| e.to_string())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    // The cap the sync holds the host folder to: the disk as it is (it may be bigger than asked).
    let size = fs::metadata(&path).map_err(|e| e.to_string())?.len().max(want);
    Ok((path, size))
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

/// How long one Firecracker API call may take.
pub const API_TIMEOUT: Duration = Duration::from_secs(60);

/// One request on Firecracker's API socket. Errors carry Firecracker's own fault message.
fn api(sock: &Path, method: &str, path: &str, body: &str) -> Result<(), String> {
    let mut s = UnixStream::connect(sock).map_err(|e| format!("{}: {e}", sock.display()))?;
    // A Firecracker that stops answering never holds a start forever (#102 verification): the
    // slowest call, a snapshot of the whole guest memory, takes about a second.
    s.set_read_timeout(Some(API_TIMEOUT)).map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(API_TIMEOUT)).map_err(|e| e.to_string())?;
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

/// The guest's boot arguments, without the clock (that part goes into no key). `env_names`: the
/// names (never the values) of php-fpm's delivered environment, so php-fpm can start at boot
/// with a placeholder for each ([`crate::guest::NOT_DELIVERED`]).
fn boot_args(plan: &Plan, opts: &Options, env_names: &[&str], fpm: &str) -> String {
    // mirab's (src/isolation/firecracker.ts): the i8042 flags skip a 500 ms keyboard probe.
    // Firecracker adds root=/dev/vda ro for a read-only root drive.
    let mut a = format!(
        "console=ttyS0 reboot=k panic=1 pci=off init={} i8042.noaux i8042.nokbd i8042.nopnp \
         i8042.dumbkbd quiet loglevel=1 sc.proto={PROTOCOL} sc.root={} sc.user={}:{} sc.fpm={fpm}",
        crate::guest::INIT,
        plan.guest_root,
        plan.pool.uid,
        plan.pool.gid
    );
    let ports: Vec<String> = plan.sockets.iter().map(|(p, _)| p).chain(plan.addresses.iter().map(|(p, _)| p)).map(u16::to_string).collect();
    if !ports.is_empty() {
        let _ = write!(a, " sc.ports={}", ports.join(","));
    }
    if !env_names.is_empty() {
        let _ = write!(a, " sc.env={}", env_names.join(","));
    }
    if !plan.egress.is_empty() {
        let _ = write!(a, " sc.egress={}", plan.egress.iter().map(u16::to_string).collect::<Vec<_>>().join(","));
    }
    for (port, path) in &plan.guest_socks {
        let _ = write!(a, " sc.sock={port}:{path}");
    }
    if let Some(alias) = &plan.db_alias {
        let _ = write!(a, " sc.dbalias={alias}");
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
const IN_PHP: &str = "/php.ext4";
const IN_CONF: &str = "/conf.ext4";
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
    /// Its log, as the launcher received it: quoted when the VM stops on its own (#87).
    log: &'static Mutex<guestlog::Inbox>,
    /// The key only its init's log connections present ([`guestlog`]).
    log_key: guestlog::Key,
    /// Its log port's server: what it hasn't said yet is said when the VM goes ([`Drop`]).
    log_server: &'static guestlog::LogServer,
}

/// A VM's log key, and the old one a restored snapshot's init still holds for a moment.
#[derive(Clone, Copy)]
struct LogKeys {
    key: guestlog::Key,
    stale: Option<guestlog::Key>,
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
        // The last second's refusals on its log port (#86 verification review).
        self.log_server.flush();
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
    /// The host's PHP and its settings (#101).
    php: PathBuf,
    conf: PathBuf,
    site: PathBuf,
    disks: Vec<(String, PathBuf)>,
    args: String,
    key: String,
    user: User,
    /// The `connect[].socket` folders, checked and held ([`open_sockets`]).
    sockets: Vec<(u16, jail::SocketDir)>,
    /// What the guest may reach by name.
    egress: &'static std::sync::RwLock<crate::egress::Egress>,
    /// The guest's size ([`size_guest`]).
    mem_mib: u32,
    vcpus: u32,
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
    /// `keys`: this VM's log key, and a restored snapshot's old one, which is refused quietly.
    fn spawn(plan: &Plan, opts: &Options, m: &Machine, wiring: Wiring, snap: Option<&Path>, keys: LogKeys) -> Result<Vm, String> {
        let j = Jail::new(&plan.state, &plan.id, m.user);
        Vm::spawn_in(&j, plan, opts, m, wiring, snap, keys).inspect_err(|_| {
            let _ = j.clear();
        })
    }

    fn spawn_in(j: &Jail, plan: &Plan, opts: &Options, m: &Machine, wiring: Wiring, snap: Option<&Path>, keys: LogKeys) -> Result<Vm, String> {
        let key = keys.key;
        j.prepare()?;
        j.place(&opts.assets.kernel, IN_KERNEL)?;
        j.place(&opts.assets.rootfs, IN_ROOTFS)?;
        j.place(&m.php, IN_PHP)?;
        j.place(&m.conf, IN_CONF)?;
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
        let log_server = wire(plan, m, j, &short, wiring, keys)?;
        let log = log_server.inbox();
        let mut cmd = j.command(&opts.assets.jailer, &opts.assets.firecracker, m.vcpus, m.mem_mib, &["--api-sock", IN_API]);
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
        let mut vm = Vm { child: Some(child), pid, api: inside(IN_API), vsock: inside(IN_VSOCK), _root: root, jail: j.clone(), log, log_key: key, log_server };
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
                        return Err(exited_before_ready(&st, &self.log.lock().unwrap_or_else(|p| p.into_inner()).recent(), state));
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

/// Why the launcher stops when Firecracker exits before php-fpm answered: the guest's own last
/// lines (php-fpm's reason and init's exit status, which the guest delivers before it stops,
/// #87), or, when it said nothing, where to look.
/// The guest's last lines inside a launcher line: last in it, after a label that says they are
/// the guest's words, each quoted and escaped ([`guestlog::Inbox::recent`]).
pub fn quoted_guest(recent: &str) -> String {
    if recent.is_empty() { "the guest logged nothing".to_owned() } else { format!("the guest's last log lines, as the guest wrote them (quoted): {recent}") }
}

pub fn exited_before_ready(st: &str, recent: &str, state: &Path) -> String {
    let console = state.join("console.log");
    if recent.is_empty() {
        format!("Firecracker exited ({st}) before php-fpm answered, and the guest logged nothing; see {}", console.display())
    } else {
        format!("Firecracker exited ({st}) before php-fpm answered; see {}; {}", console.display(), quoted_guest(recent))
    }
}

fn now() -> (i64, u32) {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (d.as_secs() as i64, d.subsec_nanos())
}

/// The file beside a snapshot that holds its VM's log key (the init in the snapshot has it).
const SNAP_LOG_KEY: &str = "log.key";

fn random_key() -> Result<guestlog::Key, String> {
    let r = random64()?;
    let mut k = [0u8; guestlog::KEY_LEN];
    k.copy_from_slice(&r[..guestlog::KEY_LEN]);
    Ok(k)
}

/// Gives a booting guest's init its log key, on a thread of its own (the boot goes on meanwhile):
/// the init sends its log, its boot's own lines included, only once it has it.
fn give_log_key(vm: &Vm) {
    let (uds, hex) = (vm.vsock.clone(), hex(&vm.log_key));
    thread::spawn(move || {
        if let Err(e) = tell_guest(&uds, &[Ctl::LogKey { hex }, Ctl::Done], START_TIMEOUT) {
            log(&format!("could not give the guest's init its log key ({e}): the guest's log is refused"));
        }
    });
}

fn cold_boot(plan: &Plan, opts: &Options, m: &Machine, wiring: Wiring) -> Result<Vm, String> {
    let vm = Vm::spawn(plan, opts, m, wiring, None, LogKeys { key: random_key()?, stale: None })?;
    vm.api("PUT", "/machine-config", &format!(r#"{{"vcpu_count":{},"mem_size_mib":{},"smt":false}}"#, m.vcpus, m.mem_mib))?;
    let args = format!("{} sc.time={}", m.args, now().0);
    vm.api("PUT", "/boot-source", &format!(r#"{{"kernel_image_path":{},"boot_args":{}}}"#, json_str(IN_KERNEL), json_str(&args)))?;
    // In the order the guest names them (crate::guest: vda base, vdb PHP, vdc config, vdd site).
    let mut drives = vec![
        ("rootfs".to_owned(), IN_ROOTFS.to_owned(), true, true),
        ("php".to_owned(), IN_PHP.to_owned(), false, true),
        ("conf".to_owned(), IN_CONF.to_owned(), false, true),
        ("site".to_owned(), IN_SITE.to_owned(), false, true),
    ];
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
    give_log_key(&vm);
    Ok(vm)
}

/// A snapshot's log key: its init already holds it, so a restore's log is taken with it.
fn snap_key(snap: &Path) -> Result<guestlog::Key, String> {
    let path = snap.join(SNAP_LOG_KEY);
    let b = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    b.try_into().map_err(|_| format!("{}: not a log key", path.display()))
}

/// A restore's log keys: a fresh one of its own, and the snapshot's as the stale one.
fn restore_keys(snap: &Path) -> Result<LogKeys, String> {
    Ok(LogKeys { key: random_key()?, stale: Some(snap_key(snap)?) })
}

/// A restore: a fresh log key of its own, given to the restored init at once (#86 verification
/// review, K2). The snapshot's key, which every restore of it starts with, is only ever refused
/// (quietly): whoever learned it in one restored guest has nothing in the next.
fn restore(plan: &Plan, opts: &Options, m: &Machine, snap: &Path) -> Result<Vm, String> {
    let vm = Vm::spawn(plan, opts, m, Wiring::Full, Some(snap), restore_keys(snap)?)?;
    vm.api(
        "PUT",
        "/snapshot/load",
        &format!(
            r#"{{"snapshot_path":{},"mem_backend":{{"backend_type":"File","backend_path":{}}},"resume_vm":true}}"#,
            json_str(&format!("{IN_SNAP}/vm.snap")),
            json_str(&format!("{IN_SNAP}/vm.mem"))
        ),
    )?;
    give_log_key(&vm);
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
    // The init in the snapshot has this VM's log key: every restore's log is taken with it.
    // Root's alone (the state folder is root's, 0700).
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let p = tmp.join(SNAP_LOG_KEY);
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        f.write_all(&vm.log_key).map_err(|e| format!("{}: {e}", p.display()))?;
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
fn start_message(plan: &Plan, restored: bool, entropy: [u8; 64], env: &[(String, String)], ini: Option<&str>) -> Vec<Ctl> {
    let (secs, nanos) = now();
    let mut lines = vec![Ctl::Time { secs, nanos }, Ctl::Entropy { hex: hex(&entropy) }];
    lines.extend(env.iter().map(|(name, value)| Ctl::Env { name: name.clone(), hex: hex(value.as_bytes()) }));
    // The site's php.ini settings (#90): php-fpm starts again with them, as with `env`.
    lines.extend(ini.map(|text| Ctl::Ini { hex: hex(text.as_bytes()) }));
    if restored {
        lines.push(Ctl::Refresh);
    }
    // vda base, vdb PHP, vdc config, vdd site, then the writable disks in drive order.
    for (n, disk) in plan.disks.iter().enumerate() {
        let device = format!("/dev/vd{}", char::from(crate::guest::FIRST_WRITABLE + n as u8));
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
    let reply = read_reply(s)?;
    refused(lines, reply.trim_end())
}

/// What the launcher says when the guest's sync before a stop fails: the guest syncs its disks
/// first and reports log lines it couldn't get acknowledged after, so a reply naming those is a
/// count of lost log lines, not a failed disk sync.
pub fn stop_sync_failed(e: &str) -> String {
    match e.split_once("error ") {
        Some((_, why)) if why.contains(guestlog::UNACKED_AT_STOP) => format!("the guest synced its disks before the stop, but {why}"),
        _ => format!("the guest did not sync its disks before the stop: {e}"),
    }
}

/// The guest's reply to `lines` as a result. Its text is shown only when `lines` carried no
/// `env` line: an older init echoes a line it doesn't know, and that line could be a secret
/// (a current init never echoes one, and logs its reason on the log port).
fn refused(lines: &[Ctl], reply: &str) -> Result<(), String> {
    if reply == "ok" {
        return Ok(());
    }
    let kinds: Vec<String> = lines.iter().map(|c| c.line().trim_end().split(' ').next().unwrap_or("").to_owned()).collect();
    if lines.iter().any(|c| matches!(c, Ctl::Env { .. } | Ctl::LogKey { .. })) {
        return Err(format!("the guest refused {kinds:?} (its reply isn't shown: the message carried secrets; the guest's own log line says why)"));
    }
    Err(format!("the guest refused {kinds:?}: {reply}"))
}

/// How often the launcher looks at the config and the site's php.ini settings: the extension's
/// own reload interval, so an edit reaches the guest's workers about as soon as a host's.
pub const WATCH_INTERVAL: Duration = Duration::from_millis(1000);

/// How [`live_change`]'s refusal starts.
const VM_CANT_RUN: &str = "the microVM can't run it";

/// Whether a running guest can take `new` (#90), the config it started with being `started`:
/// `Err(why)` when the microVM can't express it (the same check a start makes, [`plan`]), so the
/// guest keeps what it has; else what the launcher says about it. As on a host, a change to
/// `layer1` or to the vault takes effect only at the next start (the extension in the guest
/// reports `restart_needed`); layers 2 and 3 reload in place.
pub fn live_change(started: &Loaded, new: &Loaded, opts: &Options) -> Result<Vec<String>, String> {
    plan(new, opts).map_err(|e| format!("{VM_CANT_RUN} ({e})"))?;
    let mut notes = Vec::new();
    if new.config.layer1 != started.config.layer1 {
        notes.push("layer1 differs from the one this VM started with: it applies at the next start (restart_needed)".to_owned());
    }
    if securecore_config::started_vault(&new.config) != securecore_config::started_vault(&started.config) {
        notes.push("layer2.vault differs from the one this VM started with: it applies at the next start (restart_needed)".to_owned());
    }
    Ok(notes)
}

/// Follows the config file and the site's php.ini settings for the running guest (#90), every
/// [`WATCH_INTERVAL`], with the extension's own [`securecore_config::Reloader`]: an invalid file
/// or one the microVM can't run is refused with the reason, and the guest keeps what it has; a
/// valid one is put in place in the guest, where the extension reloads it as on a host (and the
/// host's egress takes its layer 2 hosts). A changed php.ini is delivered and php-fpm started
/// again gracefully with it.
fn watch_live(started: &Loaded, opts: &Options, uds: &Path, egress: &std::sync::RwLock<crate::egress::Egress>, ports: &[u16], mut ini: Option<String>) {
    let mut in_guest = started.sha256.clone();
    // The file's bytes last looked at (by sha256), and what was said about them: each version is
    // judged once, as the extension's Reloader does.
    let mut seen = started.sha256.clone();
    let mut refused: Option<String> = None;
    let mut read_error: Option<String> = None;
    let mut ini_refused: Option<String> = None;
    let mut unsure: Option<(Loaded, u8)> = None;
    loop {
        thread::sleep(WATCH_INTERVAL);
        // The launcher's start reads it the same way (#90 review): no link anywhere in its path,
        // as its folder's owner, regular only, at most MAX_CONFIG bytes.
        let bytes = match crate::sitefile::read(&started.path, crate::guest::MAX_CONFIG) {
            Ok(Some(b)) => {
                read_error = None;
                Some(b)
            }
            other => {
                let e = other.err().unwrap_or_else(|| format!("{}: missing", started.path.display()));
                if read_error.as_deref() != Some(&e) {
                    log(&format!("{e}; keeping the last valid config in the guest (sha256 {})", short_sha(&in_guest)));
                    read_error = Some(e);
                }
                None
            }
        };
        let live = match bytes {
            Some(b) if securecore_config::sha256_hex(&b) != seen => {
                let sha = securecore_config::sha256_hex(&b);
                seen = sha.clone();
                match securecore_config::Config::from_slice(&b) {
                    Ok(config) => Some((Loaded { path: started.path.clone(), config, sha256: sha, root: started.root.clone() }, b)),
                    Err(problem) => {
                        // Never quoting the file (#90 review), as at the start.
                        let e = securecore_config::LoadError { path: started.path.clone(), problem }.without_contents();
                        log(&format!("{e}; keeping the last valid config in the guest (sha256 {})", short_sha(&in_guest)));
                        None
                    }
                }
            }
            _ => None,
        };
        if let Some((live, b)) = live
            && live.sha256 != in_guest
            && refused.as_deref() != Some(&live.sha256)
        {
            let t = Instant::now();
            let result = live_change(started, &live, opts).and_then(|notes| deliver_config(uds, &b, &live.sha256).map(|how| (notes, how)));
            match result {
                Ok((mut notes, how)) => {
                    notes.extend(how);
                    log(&format!(
                        "delivered {} (sha256 {}) to the running guest in {:.0} ms; its extension reloads it",
                        live.path.display(),
                        short_sha(&live.sha256),
                        ms(t)
                    ));
                    for n in notes {
                        log(&n);
                    }
                    *egress.write().unwrap_or_else(|p| p.into_inner()) = crate::egress::Egress::new(&live, ports.to_vec());
                    in_guest = live.sha256.clone();
                    refused = None;
                }
                Err(e) => {
                    log(&format!(
                        "{}: refused for the running guest: {e}; keeping the last valid config in the guest (sha256 {})",
                        live.path.display(),
                        short_sha(&in_guest)
                    ));
                    // No answer from the guest (not its own refusal, not ours): it may still put
                    // it in place late, so its answer is asked for again on the next looks.
                    if !guest_answered(&e) && !e.starts_with(VM_CANT_RUN) {
                        unsure = Some((live.clone(), 0));
                    }
                    refused = Some(live.sha256.clone());
                }
            }
        } else if let Some((live, tries)) = unsure.take() {
            // N4 (#90 verification review): the guest's own answer decides a delivery whose
            // reply was lost, on the next looks too.
            match ask_config_sha(uds) {
                Ok(now) if now == live.sha256 => {
                    log(&format!(
                        "the running guest reads {} (sha256 {}) after all (it answered late): delivered",
                        live.path.display(),
                        short_sha(&live.sha256)
                    ));
                    *egress.write().unwrap_or_else(|p| p.into_inner()) = crate::egress::Egress::new(&live, ports.to_vec());
                    in_guest = live.sha256.clone();
                    refused = None;
                }
                Ok(_) => {}
                Err(_) if tries < 10 => unsure = Some((live, tries + 1)),
                Err(e) => log(&format!("the guest never said which config it reads ({e}); it is taken to keep sha256 {}", short_sha(&in_guest))),
            }
        }
        if let Some(path) = &opts.guest_ini {
            // As the pool user, never through a link, capped; a refusal never quotes the file.
            match read_site_ini(Some(path)) {
                Ok(text) if text != ini => {
                    ini_refused = None;
                    let t = Instant::now();
                    let body = text.clone().unwrap_or_default();
                    match tell_guest(uds, &[Ctl::Ini { hex: hex(body.as_bytes()) }, Ctl::Done], crate::guest::RELOAD_TIMEOUT) {
                        Ok(()) => log(&format!(
                            "delivered the site's php.ini settings from {} ({} lines) to the running guest and started its php-fpm again gracefully in {:.0} ms",
                            path.display(),
                            body.lines().count(),
                            ms(t)
                        )),
                        // No answer at all (N4, #90 verification review): the next look delivers
                        // them again; the guest's own refusal stands.
                        Err(e) if !guest_answered(&e) => {
                            log(&format!("the site's php.ini settings from {}: no answer from the guest ({e}); sending them again", path.display()));
                            continue;
                        }
                        Err(e) => log(&format!("the site's php.ini settings from {}: the guest refused them: {e}", path.display())),
                    }
                    ini = text;
                }
                Ok(_) => {}
                Err(e) => {
                    if ini_refused.as_deref() != Some(e.as_str()) {
                        log(&format!("{e}; the guest keeps its php.ini settings"));
                    }
                    ini_refused = Some(e);
                }
            }
        }
    }
}

/// How long a live config delivery waits for the guest's `ok`.
const SYNC_TIMEOUT_LIVE: Duration = Duration::from_secs(10);

/// Puts `bytes` (whose sha256 is `sha`) in the running guest. The guest's answer decides (#90
/// review): an `error` reply is a refusal; when no answer came (a timeout, a broken connection)
/// the guest is asked which config it reads now, and if that is `sha` the delivery stands. `Ok`
/// carries a note when it was decided that way.
fn deliver_config(uds: &Path, bytes: &[u8], sha: &str) -> Result<Option<String>, String> {
    let sent = tell_guest(uds, &[Ctl::Config { hex: hex(bytes) }, Ctl::Done], SYNC_TIMEOUT_LIVE);
    let asked = match &sent {
        Err(e) if !guest_answered(e) => Some(ask_config_sha(uds)),
        _ => None,
    };
    delivery_outcome(sent, asked, sha)
}

/// Whether a [`tell_guest`] error is the guest's own `error` reply (as opposed to no reply).
fn guest_answered(e: &str) -> bool {
    e.starts_with("the guest refused ")
}

/// [`deliver_config`]'s decision, given the delivery's result and, when it had no answer, the
/// guest's answer to "which config do you read now".
pub fn delivery_outcome(sent: Result<(), String>, asked: Option<Result<String, String>>, sha: &str) -> Result<Option<String>, String> {
    match (sent, asked) {
        (Ok(()), _) => Ok(None),
        (Err(e), Some(Ok(now))) if now == sha => Ok(Some(format!("its reply was lost ({e}), but it reads that config now: delivered"))),
        (Err(e), Some(Ok(now))) => Err(format!("{e}; the guest reads sha256 {} now", short_sha(&now))),
        (Err(e), Some(Err(q))) => Err(format!("{e}; asking the guest which config it reads failed too ({q})")),
        (Err(e), None) => Err(e),
    }
}

/// The sha256 of the config the guest's extension reads now ([`Ctl::ConfigSha`]).
fn ask_config_sha(uds: &Path) -> Result<String, String> {
    let mut s = vsock::connect_through(uds, CTL_PORT, Duration::from_secs(2)).map_err(|e| format!("the guest's control port: {e}"))?;
    let message: String = [Ctl::ConfigSha, Ctl::Done].iter().map(Ctl::line).collect();
    s.write_all(message.as_bytes()).map_err(|e| format!("the guest's control port: {e}"))?;
    s.set_read_timeout(Some(SYNC_TIMEOUT_LIVE)).map_err(|e| e.to_string())?;
    let reply = read_reply(s)?;
    match reply.trim_end().split_once(' ') {
        Some(("sha", sha)) if sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()) => Ok(sha.to_owned()),
        _ => Err(format!("the guest answered {:?}", reply.trim_end())),
    }
}

fn short_sha(sha: &str) -> &str {
    &sha[..sha.len().min(16)]
}

/// The protocol handshake, alone on its connection before any start message: `proto <N>`. The
/// guest's init answers `ok` only when it speaks this launcher's protocol and was booted for it;
/// an older init doesn't know the line. Either way nothing secret has been sent yet.
fn handshake(uds: &Path) -> Result<(), String> {
    tell_guest(uds, &[Ctl::Proto { version: PROTOCOL }, Ctl::Done], START_TIMEOUT)
        .map_err(|e| format!("the guest's init doesn't speak this launcher's protocol {PROTOCOL} (an older or newer root image?), so it gets no start message: {e}"))
}

/// The longest reply the guest's control port may give (`ok`, or `error <why>`), newline
/// included.
pub const MAX_REPLY: u64 = 4096;

/// The guest's one-line reply, read through a [`MAX_REPLY`] cap: a guest that sends more
/// without a newline (or closes before one) is refused, never buffered without bound.
pub fn read_reply(from: impl Read) -> Result<String, String> {
    let mut reply = String::new();
    BufReader::new(from.take(MAX_REPLY)).read_line(&mut reply).map_err(|e| format!("the guest's control port: {e}"))?;
    if !reply.ends_with('\n') {
        return Err(if reply.len() as u64 >= MAX_REPLY {
            format!("the guest's control port: a reply longer than {MAX_REPLY} bytes; refused")
        } else {
            "the guest's control port: closed before a whole reply".to_owned()
        });
    }
    Ok(reply)
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

/// What bringing a VM up does, as steps, so their order is tested without a VM ([`bring_up`];
/// [`Real`] boots Firecracker). The rule they keep: **a snapshot is only ever made from a VM that
/// never took a start message**, so it holds no secret (`env` lines come only in a start message).
trait Lifecycle {
    type Vm;
    fn has_snapshot(&self) -> bool;
    /// A cold boot, ready. `for_snapshot`: the warm-up VM (log port only, no forwards).
    fn cold(&mut self, for_snapshot: bool) -> Result<Self::Vm, String>;
    /// The warm-up and the snapshot of `vm`, which no start message has reached.
    fn snapshot(&mut self, vm: &Self::Vm) -> Result<(), String>;
    fn restore(&mut self) -> Result<Self::Vm, String>;
    fn remove_snapshot(&mut self);
    /// The protocol handshake, then the start message (the clock, entropy, `env`, the disks).
    fn tell(&mut self, vm: &Self::Vm, restored: bool) -> Result<(), String>;
}

/// The VM, started: restored from the snapshot (made first, from a VM of its own, when there is
/// none) or cold-booted, then told its start message. A restore that fails, or whose start
/// message fails, falls back to a cold boot. Also the moment it was ready, before its start
/// message.
fn bring_up<L: Lifecycle>(l: &mut L, snapshots: bool) -> Result<(L::Vm, Started, Instant), String> {
    let mut restored = None;
    if snapshots {
        if !l.has_snapshot() {
            let vm = l.cold(true)?;
            if let Err(e) = l.snapshot(&vm) {
                log(&format!("could not make a snapshot ({e}); cold-booting instead"));
            }
            // Never told anything: dropped as it is.
            drop(vm);
        }
        if l.has_snapshot() {
            let t = Instant::now();
            match l.restore() {
                Ok(vm) => restored = Some((vm, ms(t))),
                Err(e) => {
                    log(&format!("restoring the snapshot failed ({e}); removing it and cold-booting instead"));
                    l.remove_snapshot();
                }
            }
        }
    }
    if let Some((vm, load_ms)) = restored {
        let ready = Instant::now();
        match l.tell(&vm, true) {
            Ok(()) => return Ok((vm, Started::Restored { load_ms }, ready)),
            Err(e) => {
                // A snapshot that restores but can't start is as bad as one that doesn't restore.
                log(&format!("the restored guest failed its start message ({e}); removing the snapshot and cold-booting instead"));
                drop(vm);
                l.remove_snapshot();
            }
        }
    }
    let vm = l.cold(false)?;
    let ready = Instant::now();
    l.tell(&vm, false)?;
    Ok((vm, Started::Cold, ready))
}

/// [`Lifecycle`] with Firecracker.
struct Real<'a> {
    plan: &'a Plan,
    opts: &'a Options,
    m: &'a Machine,
    env: &'a [(String, String)],
    ini: Option<&'a str>,
}

impl Lifecycle for Real<'_> {
    type Vm = Vm;

    fn has_snapshot(&self) -> bool {
        snap_dir(self.plan, self.m).join("vm.mem").is_file()
    }

    fn cold(&mut self, for_snapshot: bool) -> Result<Vm, String> {
        let mut vm = cold_boot(self.plan, self.opts, self.m, if for_snapshot { Wiring::LogOnly } else { Wiring::Full })?;
        vm.wait_ready(&self.plan.state, Duration::from_secs(60))?;
        Ok(vm)
    }

    fn snapshot(&mut self, vm: &Vm) -> Result<(), String> {
        let (plan, m) = (self.plan, self.m);
        let snap = snap_dir(plan, m);
        let t = Instant::now();
        match warm_up(vm, &plan.guest_root) {
            Ok(n) => log(&format!("warmed the guest's page cache for the snapshot ({n})")),
            Err(e) => log(&format!("the warm-up failed ({e}); the snapshot has a cold page cache")),
        }
        snapshot(vm, plan, m.user, &snap)?;
        log(&format!("made the snapshot {} (key {}) in {:.0} ms", snap.display(), &m.key[..16], ms(t)));
        for e in fs::read_dir(&plan.state).map_err(|e| e.to_string())?.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with("snap-") && e.path() != snap {
                let _ = fs::remove_dir_all(e.path());
            }
        }
        Ok(())
    }

    fn restore(&mut self) -> Result<Vm, String> {
        let mut vm = restore(self.plan, self.opts, self.m, &snap_dir(self.plan, self.m))?;
        vm.wait_ready(&self.plan.state, Duration::from_secs(10))?;
        Ok(vm)
    }

    fn remove_snapshot(&mut self) {
        let _ = fs::remove_dir_all(snap_dir(self.plan, self.m));
    }

    fn tell(&mut self, vm: &Vm, restored: bool) -> Result<(), String> {
        handshake(&vm.vsock)?;
        tell_guest(&vm.vsock, &start_message(self.plan, restored, random64()?, self.env, self.ini), START_TIMEOUT)
    }
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
fn wire(plan: &Plan, m: &Machine, j: &Jail, short: &Path, wiring: Wiring, keys: LogKeys) -> Result<&'static guestlog::LogServer, String> {
    let user = m.user;
    let owned = SocketMode { owner: Some(user.uid), group: Some(user.gid), mode: 0o600 };
    if wiring == Wiring::Full {
        for (port, held) in &m.sockets {
            let mount = format!("/sock-{port}");
            j.bind_dir(held, &mount)?;
            let link = j.host(&format!("/v.sock_{port}"));
            std::os::unix::fs::symlink(Path::new(&mount[1..]).join(&held.name), &link).map_err(|e| format!("{}: {e}", link.display()))?;
        }
        for (port, address) in &plan.addresses {
            let l = bind_unix(&short.join(format!("v.sock_{port}")), owned)?;
            let address = address.clone();
            let port = *port;
            let pool = plan.pool;
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
                        // Never as root (#102 verification): the pool user connects, as the host's
                        // own php-fpm would, so uid-based firewall rules apply to the guest's.
                        let addrs: Vec<std::net::SocketAddr> = match std::net::ToSocketAddrs::to_socket_addrs(address.as_str()) {
                            Ok(a) => a.collect(),
                            Err(e) => return log(&format!("guest port {port} → {address}: {e}")),
                        };
                        if let Err(e) = connect_as_pool(c, &addrs, pool, false) {
                            log(&format!("guest port {port} → {address}: {e}"));
                        }
                    });
                }
            });
        }
        // Named hosts on the egress ports (#72): each connection's request line is checked here.
        // The rules are read per connection: a delivered config changes layer 2's hosts (#90).
        let egress = m.egress;
        if !egress.read().unwrap_or_else(|p| p.into_inner()).ports.is_empty() {
            let l = bind_unix(&short.join(format!("v.sock_{}", crate::egress::EGRESS_PORT)), owned)?;
            let slots: &'static Slots = Box::leak(Box::new(Slots::new(FORWARD_SLOTS)));
            let pool = plan.pool;
            thread::spawn(move || {
                for c in l.incoming().flatten() {
                    let Some(slot) = slots.take() else {
                        log(&format!("egress: {FORWARD_SLOTS} connections already open; refusing another"));
                        continue;
                    };
                    thread::spawn(move || {
                        let _slot = slot;
                        // The host's addresses now (an interface may have come up since the start).
                        let own = crate::egress::host_addresses();
                        let connect = |conn: UnixStream, addrs: &[std::net::SocketAddr]| egress_as_pool(conn, addrs, pool);
                        let rules = egress.read().unwrap_or_else(|p| p.into_inner()).clone();
                        match crate::egress::serve(c, &rules, &own, &connect) {
                            Ok(what) => log(&format!("egress: {what} closed")),
                            Err(why) => log(&format!("egress refused: {why}")),
                        }
                    });
                }
            });
        }
    }
    // php-fpm's log, to this process's stderr (#86): only connections that present this VM's log
    // key, numbered frames, each logged once and acknowledged once written, every line marked as
    // the guest's, so nothing the guest writes can pass for the launcher's own lines
    // ([`crate::guestlog`]). Never shut for writing: Firecracker turns a host's half-close into a
    // full close and drops whatever the guest sends after it.
    let l = bind_unix(&short.join(format!("v.sock_{LOG_PORT}")), owned)?;
    // Each write whole: a guest line never interleaves with another thread's.
    let emit = Box::new(|s: &str| io::stderr().lock().write_all(s.as_bytes()));
    let server: &'static guestlog::LogServer = Box::leak(Box::new(guestlog::LogServer::new(keys.key, keys.stale, emit)));
    thread::spawn(move || {
        for c in l.incoming().flatten() {
            thread::spawn(move || server.take(c));
        }
    });
    Ok(server)
}

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

/// Requests for one thing that runs one at a time (the guest's reload): a request while none
/// is queued queues one; requests while one is queued join it. The worker takes them with
/// [`Coalesce::next`], so requests made while a run is under way make exactly one more run.
pub struct Coalesce {
    pending: std::sync::Mutex<bool>,
    cv: std::sync::Condvar,
}

impl Coalesce {
    pub const fn new() -> Coalesce {
        Coalesce { pending: std::sync::Mutex::new(false), cv: std::sync::Condvar::new() }
    }

    /// Queues a run. `false`: one was already queued, and this request joins it.
    pub fn request(&self) -> bool {
        let mut p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let new = !*p;
        *p = true;
        self.cv.notify_one();
        new
    }

    /// Waits for a queued run and takes it.
    pub fn next(&self) {
        let mut p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        while !*p {
            p = self.cv.wait(p).unwrap_or_else(|e| e.into_inner());
        }
        *p = false;
    }
}

impl Default for Coalesce {
    fn default() -> Coalesce {
        Coalesce::new()
    }
}

/// Connections through one `address` forward at once.
const FORWARD_SLOTS: usize = 64;

/// `<exe> --egress-connect <addr>…` ([`crate::egress::helper_main`]) for one guest connection:
/// the connection on its stdin, its verdict on its stdout; as `user` (the site's pool user, so
/// uid-based firewall rules on the host apply) with no supplementary groups, an empty
/// environment and no new privileges, killed if the launcher dies.
pub fn spawn_egress_helper(exe: &Path, conn: UnixStream, addrs: &[std::net::SocketAddr], user: User) -> Result<Child, String> {
    spawn_connect_helper(exe, conn, addrs, user, true)
}

/// [`spawn_egress_helper`], with egress's OK/ERR answer to the guest or (`handshake` false, a
/// forwarded `connect[].address` port) without it.
pub fn spawn_connect_helper(exe: &Path, conn: UnixStream, addrs: &[std::net::SocketAddr], user: User, handshake: bool) -> Result<Child, String> {
    let mut cmd = Command::new(exe);
    cmd.env_clear().arg0("securecore-fpm").arg("--egress-connect");
    if !handshake {
        cmd.arg("--raw");
    }
    cmd.args(addrs.iter().map(|a| a.to_string()));
    cmd.stdin(Stdio::from(std::os::fd::OwnedFd::from(conn))).stdout(Stdio::piped());
    // SAFETY: only syscalls between fork and exec, on values made before the fork.
    unsafe {
        cmd.pre_exec(move || {
            let err = || Err(io::Error::last_os_error());
            if libc::setgroups(0, std::ptr::null()) < 0 || libc::setgid(user.gid) < 0 || libc::setuid(user.uid) < 0 {
                return err();
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                return err();
            }
            Ok(())
        });
    }
    cmd.spawn().map_err(|e| format!("the egress helper: {e}"))
}

/// The egress connector in production: the helper as the pool user, waited on; the address it
/// used, or why none.
fn egress_as_pool(conn: UnixStream, addrs: &[std::net::SocketAddr], pool: User) -> Result<String, String> {
    connect_as_pool(conn, addrs, pool, true)
}

fn connect_as_pool(conn: UnixStream, addrs: &[std::net::SocketAddr], pool: User, handshake: bool) -> Result<String, String> {
    let child = spawn_connect_helper(Path::new("/proc/self/exe"), conn, addrs, pool, handshake)?;
    let out = child.wait_with_output().map_err(|e| format!("the egress helper: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().next().unwrap_or("").to_owned();
    match line.split_once(' ') {
        Some(("via", a)) => Ok(a.to_owned()),
        Some(("error", why)) => Err(why.to_owned()),
        _ => Err(format!("the egress helper ended ({}) without a verdict", out.status)),
    }
}

/// Copies both ways (each direction half-closing its destination at its end) and returns when
/// both are done: one thread for a → b, this one for b → a.
pub(crate) fn pipe_both<A: vsock::Half, B: vsock::Half>(a: A, b: B) {
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

/// The writable folders' sync (#72, [`crate::sync`]): connects to the guest's sync port and
/// hands the connection to a writer ([`spawn_writer`]). When the writer ends (either side
/// crashed, or the connection broke), it connects again, and the guest starts over with its
/// whole listing, so nothing that didn't arrive is lost. Ends with the VM.
fn sync_folders(uds: PathBuf, root: PathBuf, state: PathBuf, folders: Vec<SyncFolder>, pool: User) {
    let mut quiet = false;
    while !QUITTING.load(Ordering::SeqCst) && !FIRECRACKER_EXITED.load(Ordering::SeqCst) {
        match spawn_writer(&uds, &root, &state, &folders, pool) {
            Ok(mut child) => {
                quiet = false;
                // The writer's reports, appended to each folder's record until it ends.
                if let Some(out) = child.stdout.take() {
                    keep_records(out, &state, &folders);
                }
                let st = child.wait();
                if QUITTING.load(Ordering::SeqCst) || FIRECRACKER_EXITED.load(Ordering::SeqCst) {
                    return;
                }
                log(&format!("the folder sync's writer ended ({}); connecting again", st.map_or_else(|e| e.to_string(), |s| s.to_string())));
            }
            Err(e) if !quiet => {
                log(&format!("the folder sync can't start ({e}); retrying every second"));
                quiet = true;
            }
            Err(_) => {}
        }
        thread::sleep(Duration::from_secs(1));
    }
}

/// One writable folder the sync keeps in step: its path in the app root, its disk's id (its
/// record and trash are named by it) and its cap (the disk's size).
#[derive(Debug, Clone)]
pub struct SyncFolder {
    pub rel: PathBuf,
    pub id: String,
    pub cap: u64,
}

/// `<state>/sync-<id>.record`: the folder's record ([`crate::sync::Record`]), root's only.
fn record_path(state: &Path, id: &str) -> PathBuf {
    state.join(format!("sync-{id}.record"))
}

/// The folder's record, compacted (written through a temporary name), and opened read-only for
/// the writer. A record that isn't a plain file of root's is refused.
fn open_record(state: &Path, id: &str) -> Result<fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let path = record_path(state, id);
    let text = match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&path) {
        Ok(f) => {
            let m = f.metadata().map_err(|e| e.to_string())?;
            if !m.is_file() || m.uid() != 0 {
                return Err(format!("{}: not a file of root's; refusing it", path.display()));
            }
            let mut s = String::new();
            (&f).take(256 << 20).read_to_string(&mut s).map_err(|e| format!("{}: {e}", path.display()))?;
            s
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let tmp = path.with_extension("record.new");
    let _ = fs::remove_file(&tmp);
    {
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(crate::sync::Record::parse(&text).text().as_bytes()).and_then(|()| f.sync_all()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    }
    fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Appends the writer's reports (`<disk> <record line>`) to each folder's record, until the
/// writer closes its end. A line that isn't one is dropped and logged once.
fn keep_records(out: impl Read, state: &Path, folders: &[SyncFolder]) {
    let mut files: Vec<Option<fs::File>> = folders.iter().map(|f| OpenOptions::new().append(true).open(record_path(state, &f.id)).ok()).collect();
    let mut warned = false;
    for line in BufReader::new(out.take(u64::MAX)).split(b'\n') {
        let Ok(line) = line else { break };
        let parsed = std::str::from_utf8(&line).ok().and_then(|l| l.split_once(' ')).and_then(|(d, rest)| Some((d.parse::<usize>().ok()?, rest)));
        let ok = parsed.filter(|(d, rest)| *d < files.len() && rest.len() < 3 * crate::sync::MAX_PATH && crate::sync::Record::default().apply(rest));
        match ok {
            Some((d, rest)) => {
                if let Some(f) = files[d].as_mut() {
                    let _ = f.write_all(format!("{rest}\n").as_bytes());
                }
            }
            None if !warned => {
                log("the folder sync's writer reported a line that isn't a record change; dropped");
                warned = true;
            }
            None => {}
        }
    }
    for f in files.iter().flatten() {
        let _ = f.sync_all();
    }
}

/// A day as `YYYY-MM-DD` (UTC), from days since 1970-01-01 (the civil calendar).
pub fn date_of(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// The days since 1970-01-01 of a `YYYY-MM-DD` [`date_of`] made, or `None`.
pub fn days_of(date: &str) -> Option<i64> {
    let mut it = date.split('-');
    let (y, m, d): (i64, i64, i64) = (it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?.parse().ok()?);
    if it.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    (date_of(days) == date).then_some(days)
}

/// Today's trash folder for one writable folder, `<state>/trash/<date>/<id>` (the first two
/// root's, 0700; the last the pool user's, which only the writer reaches, through its handle),
/// and the date folders older than [`crate::sync::TRASH_DAYS`] removed.
fn trash_dir(state: &Path, id: &str, pool: User) -> Result<std::os::fd::OwnedFd, String> {
    let trash = state.join("trash");
    let today = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64) / 86_400;
    let made = |p: &Path| -> Result<(), String> {
        match fs::create_dir(p) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("{}: {e}", p.display())),
        }
        let m = fs::symlink_metadata(p).map_err(|e| e.to_string())?;
        if !m.is_dir() || m.uid() != 0 {
            return Err(format!("{}: not a folder of root's", p.display()));
        }
        fs::set_permissions(p, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
    };
    made(&trash)?;
    for e in fs::read_dir(&trash).map_err(|e| e.to_string())?.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if days_of(&name).is_some_and(|d| today - d > crate::sync::TRASH_DAYS) {
            // std's remove_dir_all never follows a link it finds inside.
            if let Err(err) = fs::remove_dir_all(e.path()) {
                log(&format!("the trash folder {}: {err}", e.path().display()));
            }
        }
    }
    let day = trash.join(date_of(today));
    made(&day)?;
    let mine = day.join(id);
    match fs::create_dir(&mine) {
        Ok(()) => {
            std::os::unix::fs::chown(&mine, Some(pool.uid), Some(pool.gid)).map_err(|e| e.to_string())?;
            fs::set_permissions(&mine, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("{}: {e}", mine.display())),
    }
    jail::open_dir_beneath(&day, Path::new(id))
}

/// `securecore-fpm --sync-writer` for one connection to the guest's sync port: the connection
/// on its stdin, its reports on its stdout, and per writable folder, from fd 3 on, a handle on
/// the folder (opened beneath the app root, no link on the way), its trash folder and its record
/// (read-only). As the site's pool user with no supplementary groups, an empty environment, no
/// new privileges, a network namespace of its own (no network) and [`WRITER_MEMORY`] of address
/// space; killed if the launcher dies. It confines itself further (Landlock, seccomp) before it
/// reads from the guest ([`crate::sync::confine`]).
fn spawn_writer(uds: &Path, root: &Path, state: &Path, folders: &[SyncFolder], pool: User) -> Result<Child, String> {
    use crate::sync::{WRITER_FDS_PER_FOLDER, WRITER_FIRST_FD, WRITER_MEMORY};
    use std::os::fd::OwnedFd;
    let mut held: Vec<OwnedFd> = Vec::new();
    for f in folders {
        held.push(jail::open_dir_beneath(root, &f.rel)?);
        held.push(trash_dir(state, &f.id, pool)?);
        held.push(OwnedFd::from(open_record(state, &f.id)?));
    }
    let conn = vsock::connect_through(uds, crate::sync::SYNC_PORT, Duration::from_secs(2)).map_err(|e| format!("guest port {}: {e}", crate::sync::SYNC_PORT))?;
    let raw: Vec<libc::c_int> = held.iter().map(|f| f.as_raw_fd()).collect();
    let mut high = vec![0 as libc::c_int; raw.len()];
    let caps = folders.iter().map(|f| f.cap.to_string()).collect::<Vec<_>>().join(",");
    let mut cmd = Command::new("/proc/self/exe");
    // Nothing of the launcher's environment (which may hold the site's secrets).
    cmd.env_clear().arg0("securecore-fpm").arg("--sync-writer").arg(caps).stdin(Stdio::from(OwnedFd::from(conn))).stdout(Stdio::piped());
    debug_assert_eq!(WRITER_FDS_PER_FOLDER, 3);
    // SAFETY: only syscalls between fork and exec, on values made before the fork.
    unsafe {
        cmd.pre_exec(move || {
            let err = || Err(io::Error::last_os_error());
            // Each fd to a fresh high one first (closed at exec), then into place from fd 3: no
            // source is overwritten before it is moved.
            for (h, &fd) in high.iter_mut().zip(&raw) {
                *h = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 64);
                if *h < 0 {
                    return err();
                }
            }
            for (n, &h) in high.iter().enumerate() {
                if libc::dup2(h, WRITER_FIRST_FD + n as libc::c_int) < 0 {
                    return err();
                }
            }
            if libc::unshare(libc::CLONE_NEWNET) < 0 {
                return err();
            }
            let mem = libc::rlimit { rlim_cur: WRITER_MEMORY, rlim_max: WRITER_MEMORY };
            if libc::setrlimit(libc::RLIMIT_AS, &mem) < 0 {
                return err();
            }
            if libc::setgroups(0, std::ptr::null()) < 0 || libc::setgid(pool.gid) < 0 || libc::setuid(pool.uid) < 0 {
                return err();
            }
            // After the uid change, which clears it.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                return err();
            }
            Ok(())
        });
    }
    let child = cmd.spawn().map_err(|e| format!("the sync writer: {e}"))?;
    drop(held);
    Ok(child)
}

/// The peer of an accepted connection, judged by the pool's rule (#102 review): the address of a
/// TCP peer, the credentials of a unix-socket one.
pub trait Peer {
    fn admitted(&self, admit: &Admit) -> Result<(), String>;
}

impl Peer for TcpStream {
    fn admitted(&self, admit: &Admit) -> Result<(), String> {
        let ip = self.peer_addr().map_err(|e| e.to_string())?.ip();
        if admit.tcp(ip) { Ok(()) } else { Err(format!("{ip} isn't in the pool's listen.allowed_clients")) }
    }
}

impl Peer for UnixStream {
    fn admitted(&self, admit: &Admit) -> Result<(), String> {
        if *admit == Admit::Any {
            return Ok(());
        }
        let mut cred = libc::ucred { pid: 0, uid: u32::MAX, gid: u32::MAX };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: getsockopt(2) SO_PEERCRED fills the ucred passed, of the length given.
        let r = unsafe { libc::getsockopt(self.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &mut len) };
        if r < 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        if admit.unix(cred.uid, cred.gid) { Ok(()) } else { Err(format!("uid {} gid {} isn't in the pool's listen.acl_users or listen.acl_groups", cred.uid, cred.gid)) }
    }
}

fn serve<S: vsock::Half + Peer>(incoming: impl Iterator<Item = io::Result<S>>, uds: PathBuf, admit: Admit) {
    let refusals = std::sync::atomic::AtomicU64::new(0);
    for c in incoming.flatten() {
        if let Err(why) = c.admitted(&admit) {
            // Said for the first few, then every thousandth: a flood can't fill the log.
            let n = refusals.fetch_add(1, Ordering::Relaxed);
            if n < 5 || n.is_multiple_of(1000) {
                log(&format!("refused a FastCGI connection: {why} ({} refused so far)", n + 1));
            }
            drop(c);
            continue;
        }
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
pub const SIGNALS: [libc::c_int; 6] = [libc::SIGTERM, libc::SIGINT, libc::SIGQUIT, libc::SIGHUP, libc::SIGUSR1, libc::SIGUSR2];

/// Blocks [`SIGNALS`] in this thread (and every thread started after). The launcher does it
/// before a microVM start prepares anything, so no helper thread can take a stop signal's
/// default action; [`unblock_signals`] puts them back before gelada's exec.
pub fn block_signals() -> libc::sigset_t {
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

/// How a microVM start ended: before it served (so `auto` may still run gelada, nothing having
/// been served), or after.
#[derive(Debug)]
pub enum RunError {
    BeforeServing(String),
    AfterServing(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::BeforeServing(e) | RunError::AfterServing(e) => f.write_str(e),
        }
    }
}

/// The signal mask [`block_signals`] set, put back (before gelada's exec).
pub fn unblock_signals() {
    // SAFETY: as block_signals, unblocking the same set.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in SIGNALS {
            libc::sigaddset(&mut set, s);
        }
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
    }
}

/// Runs php-fpm in the microVM `p` ([`prepare_all`]) until a stop signal. Returns only on failure
/// (before or after it served) or after a clean stop (`Ok`).
pub fn run(loaded: &Loaded, opts: &Options, p: Prepared, t0: Instant) -> Result<(), RunError> {
    let set = block_signals();
    let before = RunError::BeforeServing;
    let Prepared { plan, user, sockets, env, ini, machine_parts: (php, conf, site_path, disks, args, key), sync, listen_mode, admit, _lock, pool_name: _, mem_mib, vcpus, space, writable_room } = p;
    // Before any thread: whatever ends this process, the VM ends with it.
    let jail = Jail::new(&plan.state, &plan.id, user);
    // What [`Jail::bind_dir`] mounts: the socket's folder, or the socket alone in a shared folder.
    let mounts: Vec<PathBuf> = plan
        .sockets
        .iter()
        .map(|(p, s)| {
            let at = jail.root.join(format!("sock-{p}"));
            match (s.parent(), s.file_name()) {
                (Some(d), Some(n)) if jail::bind_socket_only(d) => at.join(n),
                _ => at,
            }
        })
        .collect();
    let _watchdog = jail.watchdog(&mounts).map_err(before)?;
    let egress = crate::egress::Egress::new(loaded, plan.egress.clone());
    if !plan.egress.is_empty() {
        log(&format!(
            "the guest reaches named hosts on ports {:?} through the host: {}",
            egress.ports,
            match &egress.layer2 {
                Some((securecore_config::Mode::Log, h)) => format!("any name, layer 2 logging those not in its hosts ({})", h.join(", ")),
                Some((_, h)) if h.is_empty() => "none (layer 2 lists no hosts)".to_owned(),
                Some((_, h)) => format!("only layer 2's hosts ({})", h.join(", ")),
                None => "any name (layer 2's host allowlist is off)".to_owned(),
            }
        ));
        log("egress connects only to public addresses that aren't this host's, as the pool user");
    }
    let egress: &'static std::sync::RwLock<crate::egress::Egress> = Box::leak(Box::new(std::sync::RwLock::new(egress)));
    if let (Some(path), Some(text)) = (&opts.guest_ini, &ini) {
        log(&format!("the guest's php-fpm gets the site's php.ini settings from {} ({} lines), in each start message", path.display(), text.lines().count()));
    }
    let m = Machine { php, conf, site: site_path, disks, args, key, user, sockets, egress, mem_mib, vcpus };
    start_deadline().map_err(before)?;
    status("starting the microVM");
    let (mut vm, how, ready) = bring_up(&mut Real { plan: &plan, opts, m: &m, env: &env, ini: ini.as_deref() }, opts.snapshot).map_err(before)?;
    // The snapshot is on disk now (or was there, or wasn't made): only the disks' growth is kept.
    space.keep(writable_room).map_err(before)?;
    log(&format!("the shared space record keeps {} MiB for this site's disks as they fill", writable_room >> 20));
    let t_ready = ready.duration_since(t0).as_secs_f64() * 1000.0;
    let t_started = ms(t0);
    match how {
        Started::Restored { load_ms } => log(&format!(
            "microVM restored from snapshot {} (load and php-fpm ping {load_ms:.1} ms); ready {t_ready:.0} ms, started {t_started:.0} ms after launch",
            &m.key[..16]
        )),
        Started::Cold => log(&format!("microVM cold-booted; ready {t_ready:.0} ms, started {t_started:.0} ms after launch")),
    }
    log(&format!("Firecracker runs jailed as uid {} gid {} (pid {})", user.uid, user.gid, vm.pid));
    if !sync.is_empty() {
        let (uds, root, state, pool) = (vm.vsock.clone(), plan.root.clone(), plan.state.clone(), plan.pool);
        log(&format!(
            "syncing the writable folders with the host's as uid {} ({})",
            pool.uid,
            sync.iter().map(|f| format!("{} ({} MiB)", f.rel.display(), f.cap >> 20)).collect::<Vec<_>>().join(", ")
        ));
        thread::spawn(move || sync_folders(uds, root, state, sync, pool));
    }
    let uds = vm.vsock.clone();
    match &plan.listen {
        Listen::Unix(path) => {
            // nginx must reach it: by default the pool user's group, as php-fpm's listen.group.
            let mode = SocketMode { group: listen_mode.group.or(Some(plan.pool.gid)), ..listen_mode };
            if let Some(dir) = path.parent() {
                // As php-fpm does for its own socket's folder (/run/php on Debian).
                let _ = fs::create_dir_all(dir);
            }
            let l = bind_unix(path, mode).map_err(before)?;
            let admit = admit.clone();
            thread::spawn(move || serve(l.incoming(), uds.clone(), admit));
        }
        Listen::Tcp(addr) => {
            let l = TcpListener::bind(addr).map_err(|e| before(format!("listen {addr}: {e}")))?;
            let admit = admit.clone();
            thread::spawn(move || serve(l.incoming(), uds.clone(), admit));
        }
    }
    if admit != Admit::Any {
        log(&format!("FastCGI connections are taken only from {admit:?} (the pool's allowed_clients / ACLs)"));
    }
    log(&format!("serving FastCGI on {} (state {})", plan.listen, plan.state.display()));
    SERVING.store(true, Ordering::SeqCst);
    match notify_ready(std::env::var("NOTIFY_SOCKET").ok().as_deref(), std::process::id()) {
        Ok(true) => log("told systemd we are ready (NOTIFY_SOCKET)"),
        Ok(false) => {}
        Err(e) => log(&format!("could not notify systemd (NOTIFY_SOCKET): {e}")),
    }
    let after = RunError::AfterServing;
    let mut child = vm.child.take().ok_or_else(|| after("no Firecracker".into()))?;
    let state = plan.state.clone();
    let guest_log = vm.log;
    thread::spawn(move || {
        let st = child.wait();
        if !QUITTING.load(Ordering::SeqCst) {
            let recent = guest_log.lock().unwrap_or_else(|p| p.into_inner()).recent();
            log(&format!("Firecracker exited ({st:?}); stopping; see {}; {}", state.join("console.log").display(), quoted_guest(&recent)));
            // The main thread stops as for a signal, so the jail is cleared on the way out.
            FIRECRACKER_EXITED.store(true, Ordering::SeqCst);
            // SAFETY: kill(2) to this process, whose main thread waits for SIGTERM.
            unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
        }
    });
    // Reloads in a thread of their own: a stop signal during a reload is handled at once, and its
    // sync reaches the guest on its own connection, never behind the reload. One reload at a
    // time: the signals that arrive while one runs make exactly one more after it.
    static RELOADS: Coalesce = Coalesce::new();
    let uds = vm.vsock.clone();
    thread::spawn(move || {
        loop {
            RELOADS.next();
            match tell_guest(&uds, &[Ctl::Reload, Ctl::Done], crate::guest::RELOAD_TIMEOUT) {
                Ok(()) => log("reloaded the guest's php-fpm gracefully"),
                Err(e) => log(&format!("the guest's php-fpm reload failed: {e}")),
            }
        }
    });
    // An edited securecore.json and php.ini settings reach the running guest (#90).
    {
        let (loaded, opts, uds) = (loaded.clone(), opts.clone(), vm.vsock.clone());
        let ports = plan.egress.clone();
        thread::spawn(move || watch_live(&loaded, &opts, &uds, egress, &ports, ini));
    }
    let sig = loop {
        let sig = wait_for_signal(&set);
        match sig {
            libc::SIGUSR1 => log("SIGUSR1: nothing to reopen (the launcher and the guest log to stderr)"),
            libc::SIGUSR2 | libc::SIGHUP => {
                if !RELOADS.request() {
                    log(&format!("signal {sig}: a reload is already queued; this one joins it"));
                }
            }
            _ => break sig,
        }
    };
    QUITTING.store(true, Ordering::SeqCst);
    stop_extending();
    if FIRECRACKER_EXITED.load(Ordering::SeqCst) {
        drop(vm);
        return Err(after("Firecracker exited on its own; the jail is cleared".into()));
    }
    // The guest's writes to the writable disks reach the host's images before the VM stops.
    if let Err(e) = tell_guest(&vm.vsock, &[Ctl::Sync, Ctl::Done], crate::guest::SYNC_TIMEOUT) {
        log(&stop_sync_failed(&e));
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
            mem_mib: None,
            vcpus: None,
            start_within: Duration::from_secs(600),
            space_ledger: PathBuf::from("/nonexistent/space.json"),
            write_disk_mib: 1024,
            vm_user: "64000:64000".into(),
            pool_user: Some("33:33".into()),
            snapshot: true,
            guest_args: vec![],
            guest_env: vec![],
            guest_ini: None,
            php_root: PathBuf::from("/"),
            php_fpm: "php-fpm".into(),
            fpm_args: vec![],
            pool: None,
            record: PathBuf::from("/nonexistent/record.json"),
            db_user: "mysql".into(),
            db_address: None,
            db_socket: None,
        }
    }

    /// The host comes first: without KVM that is the reason, whoever runs the launcher and
    /// whatever is installed, and nothing is written (no state folder).
    #[test]
    fn no_kvm_is_the_first_reason_and_writes_nothing() {
        let dir = scratch("nokvm");
        let l = loaded(&dir, r#"{"isolation":"auto","write":["wp-content/uploads"],"network":{"bind":[{"port":9000}]}}"#);
        let state = dir.join("state");
        let o = Options { kvm: dir.join("no-kvm"), state: Some(state.clone()), vm_user: "no-such-user-sc".into(), ..opts() };
        let e = available(&l, &o).expect_err("no KVM");
        assert_eq!(e, format!("no KVM: {}: No such file or directory (os error 2)", dir.join("no-kvm").display()));
        assert!(!state.exists(), "nothing probed past KVM");
        // A device that isn't KVM: says so too.
        let o = Options { kvm: PathBuf::from("/dev/null"), ..o };
        assert!(available(&l, &o).expect_err("not KVM").starts_with("no KVM: /dev/null: KVM_GET_API_VERSION returned"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_guests_environment_is_the_vaults_and_the_named_variables() {
        let dir = scratch("env");
        let path = dir.join("securecore.json");
        let json = r#"{"layer1":{"isolation":"microvm"},"layer2":{"enabled":true,"app":"wordpress","mode":"enforce",
            "vault":{"secrets":[{"name":"DB_PASSWORD","env":"WORDPRESS_DB_PASSWORD"},{"name":"AUTH_KEY","env":"WORDPRESS_AUTH_KEY"}]}},
            "layer3":{"enabled":false}}"#;
        fs::write(&path, json).expect("write");
        let l = securecore_config::load(&path).expect("valid");
        let get = |n: &str| match n {
            "WORDPRESS_DB_PASSWORD" => Some("pw".to_owned()),
            "WORDPRESS_AUTH_KEY" => Some("key".to_owned()),
            "WORDPRESS_DB_HOST" => Some("127.0.0.1:3306".to_owned()),
            _ => None,
        };
        let env = guest_env(&l, &["WORDPRESS_DB_HOST".into(), "WORDPRESS_DB_PASSWORD".into()], get).expect("all there");
        let names: Vec<&str> = env.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["WORDPRESS_DB_HOST", "WORDPRESS_DB_PASSWORD", "WORDPRESS_AUTH_KEY"], "the vault's always, each once");
        let e = guest_env(&l, &["MISSING".into()], get).expect_err("missing");
        assert!(e.contains("has no MISSING") && !e.contains("pw"), "{e}");
        assert!(guest_env(&l, &["BAD-NAME".into()], get).is_err());
        let e = guest_env(&l, &[], |_| None).expect_err("the vault's own, missing");
        assert!(e.contains("WORDPRESS_DB_PASSWORD"), "{e}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bare_3306_reaches_the_hosts_database() {
        let dir = scratch("bare3306");
        let l = loaded(&dir, r#"{"isolation":"microvm","network":{"bind":[{"port":9000}],"connect":[{"port":3306},{"port":443}]}}"#);
        let p0 = plan(&l, &opts()).expect("plan");
        assert_eq!(p0.egress, [3306, 443], "planned as egress until the host is asked");
        let none = DbApproved::default();
        let ok: &dyn Fn(&Path, bool) -> Result<(), String> = &|_, _| Ok(());
        let no_db = |p: &Plan| p.sockets.is_empty() && p.addresses.is_empty() && p.guest_socks.is_empty() && p.egress.contains(&3306);
        // DB_HOST localhost:<socket>: that socket, when the database's user owns it.
        let mut p = p0.clone();
        let said = resolve_db(&mut p, Some("localhost:/run/sc-test/mysqld.sock"), &[], &none, ok).expect("ok").expect("said");
        assert!(said.contains("database's socket /run/sc-test/mysqld.sock"), "{said}");
        assert_eq!(p.egress, [443]);
        assert_eq!(p.sockets, [(3306, PathBuf::from("/run/sc-test/mysqld.sock"))]);
        assert!(p.guest_socks.contains(&(3306, "/run/sc-test/mysqld.sock".to_owned())), "localhost in the guest: {:?}", p.guest_socks);
        assert!(!p.guest_socks.iter().any(|(_, s)| s.starts_with("/tmp")), "never /tmp: {:?}", p.guest_socks);
        // DB_HOST localhost: PHP's own default socket.
        let mut p = p0.clone();
        resolve_db(&mut p, Some("localhost"), &["/run/php-says/mysqld.sock".to_owned()], &none, ok).expect("ok");
        assert_eq!(p.sockets, [(3306, PathBuf::from("/run/php-says/mysqld.sock"))]);
        // A hostile DB_HOST (#102 verification): D-Bus's socket (root's, not the database user's)
        // gives the guest no database, and says why; it is never an error that hides the site.
        let mut p = p0.clone();
        let said = resolve_db(&mut p, Some("localhost:/run/dbus/system_bus_socket"), &[], &none, &|_, approved| {
            if approved { Ok(()) } else { Err("the socket /run/dbus/system_bus_socket is owned by uid 0, not the database's user".into()) }
        })
        .expect("not an error")
        .expect("said");
        assert!(said.contains("not the database's user") && said.contains("the guest gets no database"), "{said}");
        assert!(no_db(&p), "{p:?}");
        // The operator may approve a root-owned socket by naming it (--db-socket).
        let mut p = p0.clone();
        let named = DbApproved { socket: Some("/run/dbus/system_bus_socket".into()), ..DbApproved::default() };
        resolve_db(&mut p, Some("localhost:/run/dbus/system_bus_socket"), &[], &named, &|_, approved| if approved { Ok(()) } else { Err("x".into()) }).expect("ok");
        assert_eq!(p.sockets.len(), 1, "approved by root's configuration");
        // A hostile DB_HOST at Redis (127.0.0.1:6379), or any other loopback port: no database.
        for h in ["127.0.0.1:6379", "127.0.0.1:2375", "[::1]:9000", "127.0.0.1:3307"] {
            let mut p = p0.clone();
            let said = resolve_db(&mut p, Some(h), &[], &none, ok).expect("ok").expect("said");
            assert!(said.contains("isn't MySQL's") && said.contains("the guest gets no database"), "{h}: {said}");
            assert!(no_db(&p), "{h}: {p:?}");
        }
        // MySQL's own ports on the loopback, and exactly what --db-address names.
        for (h, want) in [("127.0.0.1", "127.0.0.1:3306"), ("127.0.0.1:33060", "127.0.0.1:33060"), ("[::1]:3306", "[::1]:3306")] {
            let mut p = p0.clone();
            let said = resolve_db(&mut p, Some(h), &[], &none, ok).expect("ok").expect("said");
            assert!(said.contains("as the pool user"), "{said}");
            assert_eq!(p.addresses, [(3306, want.to_owned())], "{h}");
        }
        let mut p = p0.clone();
        let addr = DbApproved { address: Some("10.0.0.5:3307".into()), ..DbApproved::default() };
        resolve_db(&mut p, Some("10.0.0.5:3307"), &[], &addr, ok).expect("ok");
        assert_eq!(p.addresses, [(3306, "10.0.0.5:3307".to_owned())], "the address root's configuration names");
        // Another host, or no DB_HOST: an egress port still, never a guess at the loopback.
        for h in [Some("db.example.com"), None] {
            let mut p = p0.clone();
            let said = resolve_db(&mut p, h, &[], &none, ok).expect("ok").expect("said");
            assert!(said.contains("by name") || said.contains("only public names"), "{said}");
            assert!(no_db(&p));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_stays_on_gelada_rather_than_lose_the_database() {
        let public = |_: &str, _: u16| -> Result<(), String> { Ok(()) };
        let private = |h: &str, _: u16| -> Result<(), String> { Err(format!("{h} resolves to no public address")) };
        let said = Some("port 3306 has no socket or address, and …: the guest gets no database on it (only public names)");
        // A forward was found (a socket, an approved address): nothing to keep.
        assert_eq!(auto_db_gap(false, said, Some("db"), &private), None);
        // The site's database on this host, another container, a private address, or unknown.
        for h in [Some("localhost"), Some("127.0.0.1:6379"), Some("db"), Some("10.0.0.5"), Some("192.168.1.9:3307"), None] {
            let why = auto_db_gap(true, said, h, &private).unwrap_or_else(|| panic!("{h:?}: auto must keep gelada"));
            assert!(why.contains("the site would lose its database") && why.contains("--db-address"), "{h:?}: {why}");
        }
        assert!(auto_db_gap(true, said, Some("db:3306"), &private).expect("db").contains("DB_HOST is db:3306, which the guest can't reach by name"));
        assert!(auto_db_gap(true, said, Some("10.0.0.5"), &public).expect("an IP").contains("an IP address"), "an IP is never egress, public or not");
        // A public database by name: the guest reaches it through egress.
        assert_eq!(auto_db_gap(true, said, Some("db.example.com:3306"), &public), None);
    }

    #[test]
    fn auto_stays_on_gelada_for_a_pool_listening_everywhere() {
        let any = Admit::Any;
        let why = auto_listen_gap("www", Some("9000"), false, &any).expect("a bare port");
        assert!(why.contains("pool [www] has listen = 9000") && why.contains("502"), "{why}");
        assert_eq!(auto_listen_gap("www", Some("9000"), true, &any), None, "--listen says where");
        let lo = Admit::Addresses(vec!["127.0.0.1".parse().expect("ip")]);
        assert_eq!(auto_listen_gap("www", Some("9000"), false, &lo), None, "only the loopback is admitted anyway");
        let lan = Admit::Addresses(vec!["127.0.0.1".parse().expect("ip"), "10.0.0.2".parse().expect("ip")]);
        assert!(auto_listen_gap("www", Some("9000"), false, &lan).is_some(), "a client elsewhere");
        for l in ["127.0.0.1:9000", "0.0.0.0:9000", "/run/php/php8.3-fpm.sock"] {
            assert_eq!(auto_listen_gap("www", Some(l), false, &any), None, "{l}: binds where it says");
        }
        assert_eq!(auto_listen_gap("www", None, false, &any), None);
    }

    #[test]
    fn the_guest_is_sized_from_the_pool_and_the_host() {
        let mib = 1u64 << 20;
        let pool = |n: u32, limit: Option<u64>| PoolSize { name: "www".into(), max_children: n, memory_limit: limit };
        let host = (16 * 1024, 8);
        // The image's default pool: 5 × 128M + 256 = 896 MiB, 2 vCPUs.
        let s = size_guest(&pool(5, Some(128 * mib)), host, None, None, true).expect("fits");
        assert_eq!((s.mem_mib, s.vcpus), (896, 2), "{}", s.said);
        assert!(s.said.contains("pm.max_children 5 × memory_limit 128 MiB"), "{}", s.said);
        // A small pool still gets 512.
        assert_eq!(size_guest(&pool(1, Some(64 * mib)), host, None, None, true).expect("fits").mem_mib, 512);
        // WooCommerce's (#100 re-review): 30 × 256M = 7936 MiB of a 16 GiB host's 12288: it fits, with 8 vCPUs.
        let s = size_guest(&pool(30, Some(256 * mib)), host, None, None, true).expect("fits");
        assert_eq!((s.mem_mib, s.vcpus), (7936, 8));
        // On an 8 GiB host it doesn't: auto stays on gelada; microvm gets the cap and says so.
        let small = (8 * 1024, 4);
        let e = size_guest(&pool(30, Some(256 * mib)), small, None, None, true).expect_err("too big for auto");
        assert!(e.contains("7936 MiB, more than this host gives one microVM (6144 MiB"), "{e}");
        let s = size_guest(&pool(30, Some(256 * mib)), small, None, None, false).expect("microvm");
        assert_eq!(s.mem_mib, 6144);
        assert!(s.said.contains("so it is short"), "{}", s.said);
        // --mem: wins, but auto refuses one too small for the pool.
        assert!(size_guest(&pool(30, Some(256 * mib)), host, Some(1024), None, true).expect_err("--mem too small").contains("more than the guest's --mem 1024 MiB"));
        assert_eq!(size_guest(&pool(5, Some(128 * mib)), host, Some(2048), Some(3), true).expect("--mem").mem_mib, 2048);
        assert_eq!(size_guest(&pool(5, Some(128 * mib)), host, None, Some(3), true).expect("--vcpus").vcpus, 3);
        // No memory limit: nothing to size from.
        assert!(size_guest(&pool(5, None), host, None, None, true).expect_err("-1").contains("memory_limit = -1"));
        assert_eq!(size_guest(&pool(5, None), host, Some(1024), None, true).expect("--mem").mem_mib, 1024);
        // vCPUs never more than the host's.
        assert_eq!(size_guest(&pool(64, Some(16 * mib)), (16 * 1024, 4), None, None, true).expect("fits").vcpus, 4);
        assert_eq!(crate::phpconf::ini_size("256M"), Ok(Some(256 * mib)));
        assert_eq!(crate::phpconf::ini_size("1g"), Ok(Some(1 << 30)));
        assert_eq!(crate::phpconf::ini_size("-1"), Ok(None));
        assert!(crate::phpconf::ini_size("lots").is_err());
    }

    #[test]
    fn guests_stay_within_the_hosts_memory_budget() {
        // 16 GiB: 4 GiB kept for the host, 12 GiB for guests.
        assert_eq!(host_memory_reserve(16 << 10), 4 << 10);
        assert_eq!(host_memory_reserve(4 << 10), 2048, "at least 2 GiB");
        // The re-review's three shops at 7936 MiB on a 16 GiB host: one fits, a second doesn't.
        memory_ok(7936, 0, 16 << 10).expect("one");
        let e = memory_ok(7936, 7936, 16 << 10).expect_err("two");
        assert!(e.contains("7936 MiB the other microVMs on this host hold") && e.contains("12288 MiB (16384 MiB less 4096 MiB"), "{e}");
    }

    #[test]
    fn auto_stays_on_gelada_for_a_bare_port_with_nowhere_said() {
        let none = |_: u16| false;
        let relay = |p: u16| p == 25;
        assert_eq!(auto_port_gap(&[53, 443], &none), None, "the example's: public names only");
        assert_eq!(auto_port_gap(&[3306, 80], &none), None, "3306 is the database's rule");
        let why = auto_port_gap(&[443, 6379, 25], &relay).expect("Redis and a local SMTP relay");
        assert!(why.contains("port(s) 6379, 25 have no \"socket\" or \"address\"") && why.contains("\"address\": \"127.0.0.1:6379\""), "{why}");
        for p in [11211, 5432] {
            assert!(auto_port_gap(&[p], &none).is_some(), "{p}");
        }
        // A public relay (#100 second re-review): mail ports with nothing local on them move.
        assert_eq!(auto_port_gap(&[587, 465, 25], &none), None, "public relays by name");
        assert!(auto_port_gap(&[587], &|p| p == 587).is_some(), "a relay on this host's loopback");
    }

    #[test]
    fn a_disk_tool_never_outlives_the_starts_deadline() {
        let t = Instant::now();
        let e = tool_status_until(Command::new("sleep").arg("30"), "sleep", Instant::now() + Duration::from_millis(300)).expect_err("past the deadline");
        assert!(e.contains("still running at the start's deadline"), "{e}");
        assert!(t.elapsed() < Duration::from_secs(5), "stopped at the deadline, not after 30 s: {:?}", t.elapsed());
        let (st, err) = tool_status_until(Command::new("sh").args(["-c", "echo oops >&2; exit 3"]), "sh", Instant::now() + Duration::from_secs(10)).expect("ran");
        assert_eq!((st.code(), String::from_utf8_lossy(&err).trim()), (Some(3), "oops"));
    }

    #[test]
    fn a_writable_disk_counts_what_it_may_still_take() {
        let (mib, gib) = (1u64 << 20, 1u64 << 30);
        assert_eq!(disk_room(gib, None), gib, "a new disk may fill to its size, not only its first copy");
        assert_eq!(disk_room(gib, Some((gib, 300 * mib))), gib - 300 * mib, "an existing one, less what it holds");
        assert_eq!(disk_room(2 * gib, Some((gib, 300 * mib))), 2 * gib - 300 * mib, "grown at this start");
        assert_eq!(disk_room(gib, Some((2 * gib, 2 * gib))), 0, "full");
        // A start's disks together: a new uploads disk (1 GiB) and an existing cache disk that
        // holds 100 MiB of its 1 GiB. #102 counted only the new one's first copy (its folder's
        // bytes + 64 MiB); the existing one's 924 MiB of growth is counted too.
        assert_eq!(writable_room(&[(gib, None), (gib, Some((gib, 100 * mib)))]), 2 * gib - 100 * mib);
        assert_eq!(writable_room(&[]), 0);
    }

    #[test]
    fn the_sites_db_host_reaches_the_forward_in_the_guest() {
        let dir = scratch("dbalias");
        let l = loaded(&dir, r#"{"isolation":"microvm","network":{"bind":[{"port":9000}],"connect":[{"port":3306},{"port":443}]}}"#);
        let p0 = plan(&l, &opts()).expect("plan");
        let ok: &dyn Fn(&Path, bool) -> Result<(), String> = &|_, _| Ok(());
        for (h, approved, want) in [
            ("db", Some("db:3306"), Some("db:3306")),
            ("10.0.0.5:3307", Some("10.0.0.5:3307"), Some("10.0.0.5:3307")),
            ("127.0.0.1:33060", None, Some("127.0.0.1:33060")),
            ("127.0.0.1", None, None),
        ] {
            let mut p = p0.clone();
            let a = DbApproved { address: approved.map(str::to_owned), ..DbApproved::default() };
            resolve_db(&mut p, Some(h), &[], &a, ok).expect("ok");
            assert_eq!(p.db_alias.as_deref(), want, "{h}");
            let args = boot_args(&p, &opts(), &[], "/usr/sbin/php-fpm");
            assert_eq!(args.contains(" sc.dbalias="), want.is_some(), "{h}: {args}");
            let boot = crate::guest::parse_cmdline(&args).expect("the guest parses it");
            assert_eq!(boot.db_alias.as_deref(), want, "{h}: the guest takes it");
        }
        assert_eq!(db_alias("::1", 3306, 3306), None, "IPv6: not for the connect hook");
        assert!(crate::guest::parse_cmdline("sc.root=/srv sc.dbalias=db").is_err(), "no port");
        assert!(crate::guest::parse_cmdline("sc.root=/srv sc.dbalias=a/b:3306").is_err(), "not a name");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_mysql_socket_is_trusted_only_from_root_or_the_database() {
        // Run as root (the check target is): owners are set here.
        // SAFETY: geteuid(2) takes nothing.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        // Below / itself: the system temp folder is 1777, and the rule refuses anything under it.
        let dir = Path::new("/").join(format!("sc-dbsock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let d = dir.join("mysqld");
        fs::create_dir_all(&d).expect("dir");
        let chown = |p: &Path, u: u32, g: u32| std::os::unix::fs::chown(p, Some(u), Some(g)).expect("chown");
        let chmod = |p: &Path, m: u32| fs::set_permissions(p, fs::Permissions::from_mode(m)).expect("chmod");
        chown(&dir, 0, 0);
        chmod(&dir, 0o755);
        let sock = d.join("mysqld.sock");
        let _l = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
        // Control: the same socket under the system temp folder (1777 above it) is refused.
        let tmp = std::env::temp_dir();
        if fs::metadata(&tmp).is_ok_and(|m| m.mode() & 0o002 != 0) {
            let t = tmp.join(format!("sc-dbsock-{}.sock", std::process::id()));
            let _ = fs::remove_file(&t);
            let _lt = std::os::unix::net::UnixListener::bind(&t).expect("bind");
            assert!(trusted_db_socket(&t, None, true).is_err(), "a socket in a folder anyone may write, even approved");
            let _ = fs::remove_file(&t);
        }
        chown(&d, 999, 999);
        chmod(&d, 0o755);
        chown(&sock, 999, 999);
        assert_eq!(trusted_db_socket(&sock, Some((999, 999)), false), Ok(()), "the database's socket in its own folder");
        assert!(trusted_db_socket(&sock, None, false).is_err(), "no database user known");
        chown(&sock, 1234, 1234);
        assert!(trusted_db_socket(&sock, Some((999, 999)), false).expect_err("another user's").contains("owned by uid 1234"));
        // Root's socket (D-Bus's, say): never because a site names it; only when the operator does.
        chown(&sock, 0, 0);
        assert!(trusted_db_socket(&sock, Some((999, 999)), false).expect_err("root's, not approved").contains("--db-socket"));
        assert_eq!(trusted_db_socket(&sock, Some((999, 999)), true), Ok(()), "root's, approved by --db-socket");
        chown(&sock, 999, 999);
        chmod(&d, 0o777);
        assert!(trusted_db_socket(&sock, Some((999, 999)), false).expect_err("a folder anyone may write").contains("may be written"));
        chmod(&d, 0o775);
        chown(&d, 999, 1234);
        assert!(trusted_db_socket(&sock, Some((999, 999)), false).is_err(), "group-writable by another group");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pool_takes_connections_only_from_whom_it_lists() {
        let a = Admit::Addresses(vec!["127.0.0.1".parse().unwrap(), "10.0.0.5".parse().unwrap()]);
        assert!(a.tcp("127.0.0.1".parse().unwrap()) && a.tcp("10.0.0.5".parse().unwrap()));
        assert!(!a.tcp("10.0.0.6".parse().unwrap()), "an address the pool doesn't list");
        assert!(a.tcp("::ffff:127.0.0.1".parse().unwrap()), "a v4-mapped peer is its v4 address");
        let u = Admit::Users { uids: vec![33], gids: vec![101], members: vec![1500] };
        assert!(u.unix(33, 5) && u.unix(7, 101) && u.unix(1500, 7) && u.unix(0, 0));
        assert!(!u.unix(1234, 1234), "a user the ACLs don't list");
        assert!(Admit::Any.tcp("192.0.2.1".parse().unwrap()) && Admit::Any.unix(1, 1));
        // --listen keeps the pool's rule, or refuses: never drops it.
        let (tcp, unix) = (Listen::Tcp("127.0.0.1:9000".into()), Listen::Unix("/run/x.sock".into()));
        assert_eq!(listen_admit(&tcp, &a), Ok(a.clone()));
        assert_eq!(listen_admit(&unix, &u), Ok(u.clone()));
        assert!(listen_admit(&unix, &a).expect_err("allowed_clients on a unix socket").contains("allowed_clients"));
        assert!(listen_admit(&tcp, &u).expect_err("ACLs on TCP").contains("acl_users"));
        assert_eq!(listen_admit(&tcp, &Admit::Any), Ok(Admit::Any));
        assert!(jail::bind_socket_only(Path::new("/run")) && jail::bind_socket_only(Path::new("/tmp/")) && jail::bind_socket_only(Path::new("/")));
        assert!(!jail::bind_socket_only(Path::new("/run/mysqld")), "a socket's own folder is bound as a folder");
    }

    #[test]
    fn only_this_sites_pools_run_here() {
        let pool = |name: &str, k: &str, v: &str| {
            let mut c = crate::phpconf::FpmConfig::default();
            c.add("/p.conf", &format!("[{name}]\n{k} = {v}\n"));
            c.pools.remove(0)
        };
        let root = Path::new("/var/lib/docker/volumes/site/_data");
        assert!(pool_is_this_site(&pool("a", "chdir", "/var/www/html"), root, "/var/www/html", false).is_ok(), "the guest's root");
        assert!(pool_is_this_site(&pool("a", "php_admin_value[doc_root]", "/var/lib/docker/volumes/site/_data/public"), root, "/var/www/html", false).is_ok());
        assert!(pool_is_this_site(&pool("a", "prefix", "/var/www/$pool"), root, "/var/www/a", false).is_ok(), "$pool replaced");
        let e = pool_is_this_site(&pool("b", "chdir", "/srv/other-site"), root, "/var/www/html", false).expect_err("another site");
        assert!(e.contains("pool [b] serves another site (/srv/other-site)"), "{e}");
        assert!(pool_is_this_site(&pool("c", "pm", "static"), root, "/var/www/html", true).is_ok(), "php-fpm's only pool, naming no site");
        assert!(pool_is_this_site(&pool("c", "pm", "static"), root, "/var/www/html", false).is_err(), "one of several naming no site");
        assert!(pool_is_this_site(&pool("d", "chdir", "/var/www/html2"), root, "/var/www/html", false).is_err(), "a sibling with a common prefix");
    }

    #[test]
    fn a_start_keeps_a_margin_free() {
        let gib = 1u64 << 30;
        assert_eq!(space_margin(10 * gib), gib, "at least 1 GiB");
        assert_eq!(space_margin(100 * gib), 5 * gib, "a twentieth");
        let needs = vec![("site disk".to_owned(), gib / 4), ("PHP layer".to_owned(), gib / 4), ("snapshot".to_owned(), gib / 2)];
        assert!(space_ok(&needs, 3 * gib, 0, 10 * gib).is_ok());
        let e = space_ok(&needs, gib + gib / 2, 0, 10 * gib).expect_err("1 GiB of disks and 1 GiB of margin in 1.5 GiB");
        assert!(e.contains("needs 1024 MiB") && e.contains("site disk 256 MiB, PHP layer 256 MiB, snapshot 512 MiB") && e.contains("keeps 1024 MiB free"), "{e}");
        // What other sites' starts keep counts as taken (#100 re-review).
        let e = space_ok(&needs, 3 * gib, 2 * gib, 10 * gib).expect_err("3 GiB free, 2 GiB of it kept by others");
        assert!(e.contains("2048 MiB of which other sites' starts keep"), "{e}");
    }

    #[test]
    fn a_pool_has_a_state_folder_and_jail_of_its_own() {
        let dir = scratch("pools");
        let l = loaded(&dir, r#"{"isolation":"microvm","network":{"connect":[]}}"#);
        let e = plan(&l, &opts()).expect_err("no bind port and no pool listen");
        assert!(e.contains("the pool has no listen"), "{e}");
        let hints = PoolHints { user: Some(User { uid: 1234, gid: 1235 }), listen: Some(Listen::Unix("/run/php/www.sock".into())), listen_mode: None, admit: Admit::Any };
        let mut o = opts();
        o.pool_user = None;
        let p = plan_with(&l, &o, &hints, false).expect("plan");
        assert_eq!(p.pool, User { uid: 1234, gid: 1235 }, "the pool's user");
        assert_eq!(p.listen, Listen::Unix("/run/php/www.sock".into()), "where the pool listens");
        assert_eq!(p.state, p.cache);
        o.pool = Some("admin".into());
        o.listen = Some(Listen::Tcp("127.0.0.1:9100".into()));
        let q = plan_with(&l, &o, &hints, false).expect("plan");
        assert_eq!(q.state, p.cache.join("pool-admin"), "below the site's");
        assert_ne!(q.id, p.id);
        assert_eq!(q.listen, Listen::Tcp("127.0.0.1:9100".into()), "--listen wins");
        assert_eq!(plan_with(&l, &opts(), &hints, false).expect("plan").pool, User { uid: 33, gid: 33 }, "--pool-user wins");
        for bad in ["", "../x", ".hidden", "a b", &"x".repeat(33)] {
            assert!(pool_dir_name(bad).is_err(), "{bad:?}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_plan_maps_layer1_onto_disks_tmpfs_and_forwards() {
        let dir = scratch("plan");
        let l = loaded(
            &dir,
            r#"{"isolation":"microvm","write":["wp-content/uploads","/tmp","/var/cache/sc"],"deny":["/srv/backups"],
                "network":{"bind":[{"port":9000}],"connect":[{"port":3306,"socket":"/run/mysqld/mysqld.sock"},{"port":6379,"address":"10.0.0.5:6379"},{"port":443}]}}"#,
        );
        let mut p = plan(&l, &opts()).expect("plan");
        // A forwarded 3306 is PHP's `localhost` too: sockets in the guest.
        assert_eq!(resolve_db(&mut p, None, &[], &DbApproved::default(), &|_, _| Err("never asked".into())), Ok(None), "3306 has its socket: nothing to decide");
        assert_eq!(p.guest_socks, [(3306, "/run/mysqld/mysqld.sock".to_owned())]);
        assert_eq!(p.disks.len(), 1);
        assert_eq!(p.disks[0].guest, "/var/www/html/wp-content/uploads", "a folder in the root, at the guest root");
        assert_eq!(p.disks[0].host, dir.join("wp-content/uploads"));
        assert_eq!(p.tmpfs, ["/var/cache/sc"], "outside the root: tmpfs; /tmp is always one");
        assert_eq!(p.sockets, [(3306, PathBuf::from("/run/mysqld/mysqld.sock"))]);
        assert_eq!(p.addresses, [(6379, "10.0.0.5:6379".to_owned())]);
        assert_eq!(p.egress, [443], "no socket or address: named hosts through the host");
        assert!(boot_args(&p, &opts(), &[], "/usr/local/sbin/php-fpm").contains(" sc.egress=443"), "the guest learns its egress ports");
        let e = plan(
            &loaded(&dir, r#"{"isolation":"microvm","network":{"bind":[{"port":9000}],"connect":[{"port":1517,"address":"10.0.0.1:1"}]}}"#),
            &opts(),
        )
        .expect_err("1517 forwarded");
        assert!(e.contains("channel for named hosts"), "{e}");
        assert_eq!(p.listen, Listen::Tcp("127.0.0.1:9000".into()), "the first bind port, on loopback");
        assert!(p.state.starts_with(DEFAULT_STATE_DIR));
        assert!(p.id.starts_with("sc-") && p.id.len() == 19, "{}", p.id);
        let args = boot_args(&p, &opts(), &["WORDPRESS_DB_PASSWORD"], "/usr/sbin/php-fpm8.3");
        assert!(args.contains(" sc.fpm=/usr/sbin/php-fpm8.3") && args.contains(" init=/sc/securecore-init "), "the host's php-fpm, under the base's init: {args}");
        assert!(args.contains(" sc.env=WORDPRESS_DB_PASSWORD"), "the names, for php-fpm's placeholders at boot: {args}");
        assert!(args.contains(" sc.root=/var/www/html") && args.contains(" sc.ports=3306,6379"), "{args}");
        assert!(args.contains(&format!(" sc.proto={PROTOCOL} ")), "the guest learns the protocol it was booted for: {args}");
        assert!(args.contains(" sc.user=33:33"), "the guest's pool runs as the host's pool user: {args}");
        assert!(args.contains(" sc.sock=3306:/run/mysqld/mysqld.sock"), "{args}");
        assert!(!args.contains("sc.time"), "the clock is in no key: {args}");
        let env = [("WORDPRESS_DB_PASSWORD".to_owned(), "s3cret".to_owned())];
        let msg = start_message(&p, true, [7; 64], &env, None);
        assert!(matches!(msg[0], Ctl::Time { .. }), "the clock first");
        assert_eq!(msg[1], Ctl::Entropy { hex: "07".repeat(64) }, "then fresh randomness");
        assert_eq!(msg[2], Ctl::Env { name: "WORDPRESS_DB_PASSWORD".into(), hex: hex(b"s3cret") }, "then php-fpm's environment");
        assert_eq!(msg[3], Ctl::Refresh, "a restore replaces the workers forked before the snapshot");
        assert_eq!(msg[4], Ctl::Mount { device: "/dev/vde".into(), path: "/var/www/html/wp-content/uploads".into() }, "after the base, PHP, config and site");
        assert_eq!(msg[5], Ctl::Tmpfs { path: "/var/cache/sc".into() });
        assert_eq!(msg.last(), Some(&Ctl::Done));
        assert!(!start_message(&p, false, [7; 64], &env, None).contains(&Ctl::Refresh), "a cold boot's workers are fresh");
        // The site's php.ini settings (#90), after the environment.
        let ini = "securecore.debug_attribution_log = both\n";
        let msg = start_message(&p, false, [7; 64], &env, Some(ini));
        assert_eq!(msg[3], Ctl::Ini { hex: hex(ini.as_bytes()) });
        assert!(!args.contains("s3cret") && !args.contains(&hex(b"s3cret")), "never a boot argument");
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

    /// A live edit (#90): refused when the microVM can't run it; else delivered, with layer1 and
    /// vault changes flagged for the next start (restart_needed), as on a host.
    #[test]
    fn a_live_edit_is_refused_when_the_vm_cant_run_it_and_flags_what_needs_a_start() {
        let dir = scratch("live");
        let base = r#"{"isolation":"microvm","network":{"bind":[{"port":9000}]}}"#;
        let started = loaded(&dir, base);
        let same_l1 = started.clone();
        assert_eq!(live_change(&started, &same_l1, &opts()), Ok(vec![]), "layers 2 and 3 only: delivered, nothing for the next start");
        let more = loaded(&dir, r#"{"isolation":"microvm","write":["wp-content/uploads"],"network":{"bind":[{"port":9000}]}}"#);
        let notes = live_change(&started, &more, &opts()).expect("the VM can run it");
        assert!(notes.len() == 1 && notes[0].contains("restart_needed"), "{notes:?}");
        let socks = loaded(&dir, r#"{"isolation":"microvm","network":{"bind":[{"port":9000}],"unixSockets":["/run/x.sock"]}}"#);
        let e = live_change(&started, &socks, &opts()).expect_err("unixSockets");
        assert!(e.starts_with("the microVM can't run it"), "{e}");
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
        let k = Key { files: files.clone(), php: "p".into(), conf: "i".into(), site: "s".into(), config: "c".into(), machine: "m".into() };
        for changed in [
            Key { php: "p2".into(), ..k.clone() },
            Key { conf: "i2".into(), ..k.clone() },
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

    /// Root with CAP_SYS_ADMIN (the masks are a private mount namespace) and mke2fs only: runs on
    /// a KVM host's unit run (and in ext-microvm, end to end); a Docker build has no
    /// CAP_SYS_ADMIN, so it says so and stops there.
    #[test]
    fn disks_are_copied_as_the_pool_user_without_the_writable_folders() {
        let cap_sys_admin = fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| s.lines().find_map(|l| l.strip_prefix("CapEff:").map(|v| v.trim().to_owned())))
            .and_then(|v| u64::from_str_radix(&v, 16).ok())
            .is_some_and(|caps| caps & (1 << 21) != 0);
        // SAFETY: geteuid(2) can't fail.
        if unsafe { libc::geteuid() } != 0 || !cap_sys_admin || !on_path("mke2fs") || !on_path("debugfs") {
            eprintln!("not root with CAP_SYS_ADMIN, or no mke2fs/debugfs: checked on the KVM host and in test/ext-microvm.sh");
            return;
        }
        let dir = scratch("copy");
        fs::write(dir.join("index.php"), "<?php echo 1;").expect("write");
        fs::write(dir.join("wp-content/uploads/big.bin"), vec![7u8; 1 << 20]).expect("upload");
        let nobody = User { uid: 65534, gid: 65534 };
        let img = dir.with_extension("ext4");
        let uploads = PathBuf::from("wp-content/uploads");
        let site = Source { root: &dir, rel: Path::new("") };
        mke2fs(nobody, site, std::slice::from_ref(&uploads), &img, 64, 1024, false).expect("the site, as nobody");
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
        let e = mke2fs(nobody, site, std::slice::from_ref(&uploads), &img, 64, 1024, false).expect_err("a root-only file");
        assert!(e.contains("as uid 65534"), "{e}");
        // mke2fs, e2fsck and resize2fs get none of the launcher's environment (its secrets) but
        // PATH: what `env` prints run the same way.
        let mut cmd = Command::new("env");
        as_user(&mut cmd, nobody, None, &[], None).expect("prepared");
        let out = cmd.output().expect("env");
        let names: Vec<String> = String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| l.split_once('=')).map(|(n, _)| n.to_owned()).collect();
        assert_eq!(names, ["PATH"], "the tools' environment");
        assert!(std::env::vars().count() > 1, "the test's own environment has more than PATH (so the check means something)");
        let _ = fs::remove_file(&img);
        fs::remove_file(dir.join("root-only.txt")).expect("rm");
        // A link put above the mask after every check by path: the mask is opened beneath the
        // root in the copy's own process, so the copy fails there (ELOOP), nothing copied.
        let outside = dir.with_extension("mask-outside");
        fs::create_dir_all(outside.join("uploads")).expect("outside");
        fs::rename(dir.join("wp-content"), dir.join("wp-content-old")).expect("move");
        std::os::unix::fs::symlink(&outside, dir.join("wp-content")).expect("link");
        let mut cmd = Command::new("true");
        as_user(&mut cmd, nobody, Some(site), std::slice::from_ref(&uploads), None).expect("prepared");
        let e = cmd.status().expect_err("the mask's open fails in the child");
        assert_eq!(e.raw_os_error(), Some(libc::ELOOP), "{e}");
        let _ = fs::remove_file(&img);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
    }

    /// The write folders are checked by path when the plan is made; a symlinked parent put in
    /// after that (here: wp-content swapped for a link to a tree outside the root) is refused
    /// when the disks are built, never followed.
    #[test]
    fn a_link_put_in_after_the_plan_is_refused_when_the_disks_are_built() {
        let dir = scratch("race");
        let l = loaded(&dir, r#"{"isolation":"microvm","write":["wp-content/uploads"],"network":{"bind":[{"port":9000}]}}"#);
        let mut o = opts();
        o.state = Some(dir.with_extension("race-state"));
        let p = plan(&l, &o).expect("plan: a real folder");
        let outside = dir.with_extension("race-outside");
        fs::create_dir_all(outside.join("uploads")).expect("outside");
        fs::write(outside.join("uploads/secret.txt"), "not the site's").expect("write");
        fs::rename(dir.join("wp-content"), dir.join("wp-content-old")).expect("move");
        std::os::unix::fs::symlink(&outside, dir.join("wp-content")).expect("link");
        let nobody = User { uid: 65534, gid: 65534 };
        let e = write_disk(&p, &p.disks[0], 1024, nobody).expect_err("the writable disk's folder");
        assert!(e.contains("symlink is on the way"), "{e}");
        let e = site_disk(&p, &"0".repeat(64), 0, 0, nobody).expect_err("the site disk's mask");
        assert!(e.contains("symlink is on the way"), "{e}");
        // Root only (a uid switch): the copy's own process opens the folder beneath the root
        // again, so a link put in after the launcher's own check fails it there too.
        // SAFETY: geteuid(2) can't fail.
        if unsafe { libc::geteuid() } == 0 {
            let mut cmd = Command::new("true");
            as_user(&mut cmd, nobody, Some(Source { root: &p.root, rel: Path::new("wp-content/uploads") }), &[], None).expect("prepared");
            let e = cmd.status().expect_err("the source's open fails in the child");
            assert_eq!(e.raw_os_error(), Some(libc::ELOOP), "{e}");
        }
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn guest_lines_are_capped_and_connections_counted() {
        let long = format!("L 1 {}\nL 2 next\n", "x".repeat(guestlog::MAX_LINE * 3));
        let out = Mutex::new(String::new());
        let mut acks = Vec::new();
        let emit = |s: &str| -> io::Result<()> {
            out.lock().expect("out").push_str(s);
            Ok(())
        };
        guestlog::serve(long.as_bytes(), &mut acks, &Mutex::new(guestlog::Inbox::default()), &emit).expect("serves");
        let text = out.lock().expect("out").clone();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one cut line, then the next");
        assert!(lines[0].len() < guestlog::MAX_LINE + 96 && lines[0].ends_with("…[cut]"), "{}", &lines[0][..40]);
        assert_eq!(lines[1], "guest: next");
        assert_eq!(String::from_utf8(acks).expect("utf8"), "A 2\n", "acknowledged once all that arrived is logged");
        static S: Slots = Slots::new(2);
        let (a, b) = (S.take(), S.take());
        assert!(a.is_some() && b.is_some() && S.take().is_none(), "two slots, a third is refused");
        drop(a);
        assert!(S.take().is_some(), "a freed slot is taken again");
        drop(b);
    }

    /// A [`Lifecycle`] with numbered VMs instead of Firecracker: it records each step, and its
    /// snapshot refuses a VM that a start message (the only carrier of `env`) has reached.
    #[derive(Default)]
    struct Fake {
        next: u32,
        snapshot: bool,
        restore_fails: bool,
        restored_tell_fails: bool,
        told: Vec<(u32, bool)>,
        snapshotted: Vec<u32>,
        steps: Vec<String>,
    }

    impl Lifecycle for Fake {
        type Vm = u32;
        fn has_snapshot(&self) -> bool {
            self.snapshot
        }
        fn cold(&mut self, for_snapshot: bool) -> Result<u32, String> {
            self.next += 1;
            self.steps.push(format!("cold {} {}", self.next, if for_snapshot { "for-snapshot" } else { "full" }));
            Ok(self.next)
        }
        fn snapshot(&mut self, vm: &u32) -> Result<(), String> {
            assert!(!self.told.iter().any(|(v, _)| v == vm), "VM {vm} took a start message (env) before its snapshot");
            self.steps.push(format!("snapshot {vm}"));
            self.snapshotted.push(*vm);
            self.snapshot = true;
            Ok(())
        }
        fn restore(&mut self) -> Result<u32, String> {
            self.next += 1;
            self.steps.push(format!("restore {}", self.next));
            if self.restore_fails { Err("broken".into()) } else { Ok(self.next) }
        }
        fn remove_snapshot(&mut self) {
            self.steps.push("remove-snapshot".into());
            self.snapshot = false;
        }
        fn tell(&mut self, vm: &u32, restored: bool) -> Result<(), String> {
            self.steps.push(format!("tell {vm}"));
            self.told.push((*vm, restored));
            if restored && self.restored_tell_fails { Err("refused".into()) } else { Ok(()) }
        }
    }

    /// The snapshot is made from a VM that never took a start message, on every path: the first
    /// start, a restore, a broken snapshot, a restore whose start message fails, no snapshots.
    /// It would fail if the start message (with `env`) were ever sent before a snapshot.
    #[test]
    fn a_snapshot_is_only_made_from_a_vm_that_never_got_env() {
        let check = |f: &Fake| {
            for s in &f.snapshotted {
                assert!(!f.told.iter().any(|(v, _)| v == s), "snapshotted VM {s} was told: {:?}", f.steps);
            }
        };
        let mut f = Fake::default();
        let (vm, how, _) = bring_up(&mut f, true).expect("first start");
        assert_eq!(f.steps, ["cold 1 for-snapshot", "snapshot 1", "restore 2", "tell 2"]);
        assert!(matches!(how, Started::Restored { .. }) && vm == 2 && f.told == [(2, true)]);
        check(&f);
        let mut f = Fake { snapshot: true, ..Fake::default() };
        bring_up(&mut f, true).expect("a restore");
        assert_eq!(f.steps, ["restore 1", "tell 1"], "a snapshot there: no new one");
        let mut f = Fake { restore_fails: true, ..Fake::default() };
        let (vm, how, _) = bring_up(&mut f, true).expect("a broken snapshot");
        assert_eq!(f.steps, ["cold 1 for-snapshot", "snapshot 1", "restore 2", "remove-snapshot", "cold 3 full", "tell 3"]);
        assert!(matches!(how, Started::Cold) && vm == 3);
        check(&f);
        let mut f = Fake { snapshot: true, restored_tell_fails: true, ..Fake::default() };
        let (vm, _, _) = bring_up(&mut f, true).expect("a restore that can't start");
        assert_eq!(f.steps, ["restore 1", "tell 1", "remove-snapshot", "cold 2 full", "tell 2"]);
        assert_eq!((vm, f.told.as_slice()), (2, &[(1, true), (2, false)][..]));
        let mut f = Fake::default();
        bring_up(&mut f, false).expect("--no-snapshot");
        assert_eq!(f.steps, ["cold 1 full", "tell 1"]);
        assert!(f.snapshotted.is_empty());
    }

    /// An older init answers a line it doesn't know by echoing it, and a start message's `env`
    /// lines carry secrets: such a reply is never shown. The handshake comes first, alone.
    #[test]
    fn a_refused_start_message_is_never_echoed_and_the_protocol_is_checked_first() {
        let secret = hex(b"hunter2");
        let msg = [Ctl::Time { secs: 1, nanos: 0 }, Ctl::Env { name: "WORDPRESS_DB_PASSWORD".into(), hex: secret.clone() }, Ctl::Done];
        let e = refused(&msg, &format!("error unknown control line \"env WORDPRESS_DB_PASSWORD {secret}\"")).expect_err("refused");
        assert!(!e.contains(&secret) && !e.contains("hunter2") && !e.contains("unknown control line"), "{e}");
        let e = refused(&[Ctl::Sync, Ctl::Done], "error the writable folders did not sync").expect_err("refused");
        assert!(e.contains("did not sync"), "a reply to a message with no secret is shown: {e}");
        refused(&msg, "ok").expect("ok");
        // The guest's side: its own protocol only, and no start message unless booted for it.
        let mine = PROTOCOL;
        crate::guest::protocol_ok(&[Ctl::Proto { version: mine }, Ctl::Done], Some(mine)).expect("the same protocol");
        assert!(crate::guest::protocol_ok(&[Ctl::Proto { version: mine + 1 }, Ctl::Done], Some(mine)).is_err(), "a newer host");
        assert!(crate::guest::protocol_ok(&[Ctl::Proto { version: mine }, Ctl::Done], Some(mine - 1)).is_err(), "booted for another");
        assert!(crate::guest::protocol_ok(&msg, None).expect_err("no sc.proto").contains("takes no start message"));
        assert!(crate::guest::protocol_ok(&msg, Some(mine - 1)).is_err());
        crate::guest::protocol_ok(&msg, Some(mine)).expect("a start message for its own protocol");
        assert!(crate::guest::allowed(&[Ctl::Proto { version: mine }, Ctl::Time { secs: 1, nanos: 0 }, Ctl::Done], false).is_err(), "the handshake comes alone");
        assert_eq!(Ctl::parse(&Ctl::Proto { version: 7 }.line()), Ok(Ctl::Proto { version: 7 }));
        assert_eq!(crate::guest::parse_cmdline(&format!("sc.root=/srv sc.proto={mine}")).expect("parses").proto, Some(mine));
    }

    /// A writable disk is sized from its folder: twice what it holds, at least 1 GiB, in powers of
    /// two, never below the flag. A folder too big for the sync, or for the state folder's
    /// filesystem, is refused by `available` (so `auto` falls back with the reason).
    #[test]
    fn a_writable_disk_is_sized_from_its_folder_and_must_fit() {
        assert_eq!(disk_mib(1024, 0), 1024);
        assert_eq!(disk_mib(1024, 300 << 20), 1024, "300 MiB of uploads: 1 GiB");
        assert_eq!(disk_mib(1024, 600 << 20), 2048, "600 MiB: 2 GiB, not a refusal");
        assert_eq!(disk_mib(1024, 5 << 30), 16384, "5 GiB: 16 GiB");
        assert_eq!(disk_mib(4096, 10 << 20), 4096, "the flag is a floor");
        assert_eq!(disk_mib(64, 0), 1024, "and never below 1 GiB");
        let p = Path::new("/srv/site/wp-content/uploads");
        fits(p, 300 << 20, 1000, None).expect("an existing disk");
        fits(p, 300 << 20, 1000, Some(1 << 30)).expect("room for the copy");
        let e = fits(p, 300 << 20, 1000, Some(200 << 20)).expect_err("no room for the copy");
        assert!(e.contains("MiB free"), "{e}");
        let e = fits(p, 0, crate::sync::MAX_ENTRIES as u64 + 1, None).expect_err("too many entries");
        assert!(e.contains("files and folders"), "{e}");
    }

    #[test]
    fn trash_folders_are_named_by_their_day() {
        assert_eq!(date_of(0), "1970-01-01");
        assert_eq!(date_of(20_403), "2025-11-11");
        assert_eq!(date_of(11_016), "2000-02-29");
        for d in [0, 11_016, 20_403, 20_404, 47_482] {
            assert_eq!(days_of(&date_of(d)), Some(d));
        }
        for bad in ["2026-13-01", "2026-02-30", "x", "2026-1-1-1", "../2026-01-01"] {
            assert_eq!(days_of(bad), None, "{bad}");
        }
    }

    #[test]
    fn e2fsck_passes_only_on_exit_0_or_1() {
        use std::os::unix::process::ExitStatusExt as _;
        let exit = |code: i32| std::process::ExitStatus::from_raw(code << 8);
        fsck_result(exit(0), b"").expect("clean");
        fsck_result(exit(1), b"").expect("errors corrected");
        // 12 (4 errors left + 8 operational) reads "exit status: 12", which holds "exit status: 1".
        for code in [2, 4, 8, 12, 16, 128] {
            assert!(fsck_result(exit(code), b"").is_err(), "exit {code}");
        }
        let killed = std::process::ExitStatus::from_raw(libc::SIGKILL);
        assert!(fsck_result(killed, b"").is_err(), "killed by a signal");
    }

    #[test]
    fn the_guests_reply_is_capped() {
        assert_eq!(read_reply(&b"ok\n"[..]), Ok("ok\n".to_owned()));
        let long = format!("error {}\n", "y".repeat(MAX_REPLY as usize));
        assert!(read_reply(long.as_bytes()).expect_err("too long").contains("longer than"));
        assert!(read_reply(&b"ok"[..]).expect_err("cut").contains("closed before"), "no newline: not a reply");
        // A guest streaming without a newline: refused at the cap, not read to the end.
        let e = read_reply(io::repeat(b'x')).expect_err("endless");
        assert!(e.contains("longer than 4096 bytes"), "{e}");
    }

    /// Five reload signals while a reload runs: one more reload after it, never two at once.
    #[test]
    fn reload_signals_during_a_reload_make_exactly_one_more() {
        use std::sync::atomic::AtomicUsize;
        static Q: Coalesce = Coalesce::new();
        static STARTED: AtomicUsize = AtomicUsize::new(0);
        static FINISHED: AtomicUsize = AtomicUsize::new(0);
        static RUNNING: AtomicBool = AtomicBool::new(false);
        thread::spawn(|| {
            loop {
                Q.next();
                assert!(!RUNNING.swap(true, Ordering::SeqCst), "two runs at once");
                STARTED.fetch_add(1, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(200));
                RUNNING.store(false, Ordering::SeqCst);
                FINISHED.fetch_add(1, Ordering::SeqCst);
            }
        });
        let until = |what: &dyn Fn() -> bool| {
            let t = Instant::now();
            while !what() {
                assert!(t.elapsed() < Duration::from_secs(5), "timed out");
                thread::sleep(Duration::from_millis(5));
            }
        };
        assert!(Q.request(), "the first request queues a run");
        until(&|| STARTED.load(Ordering::SeqCst) == 1);
        let queued: Vec<bool> = (0..5).map(|_| Q.request()).collect();
        assert_eq!(queued, [true, false, false, false, false], "one more run queued; the rest join it");
        until(&|| FINISHED.load(Ordering::SeqCst) == 2);
        thread::sleep(Duration::from_millis(300));
        assert_eq!(STARTED.load(Ordering::SeqCst), 2, "six requests, two runs");
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

    /// A guest that stops before php-fpm answers: the launcher's error quotes what the guest said
    /// (#87), and says so when it said nothing.
    #[test]
    fn a_guest_that_stops_at_boot_is_quoted() {
        let inbox = Mutex::new(guestlog::Inbox::default());
        let from = b"L 1 PHP Fatal error: SC_LIT_SECRET is a string literal\nI 2 php-fpm exited at boot, before it served (exit code 78)\n";
        guestlog::serve(&from[..], io::sink(), &inbox, &|_| Ok(())).expect("serves");
        let e = exited_before_ready("exit status: 0", &inbox.lock().expect("inbox").recent(), Path::new("/s"));
        assert!(
            e.ends_with(
                r#"the guest's last log lines, as the guest wrote them (quoted): "PHP Fatal error: SC_LIT_SECRET is a string literal" | "guest-init: php-fpm exited at boot, before it served (exit code 78)""#
            ),
            "{e}"
        );
        let e = exited_before_ready("exit status: 0", "", Path::new("/s"));
        assert!(e.contains("the guest logged nothing; see /s/console.log"), "{e}");
    }

    #[test]
    fn the_guest_cannot_write_the_launchers_lines() {
        let out = Mutex::new(String::new());
        let emit = |s: &str| -> io::Result<()> {
            out.lock().expect("out").push_str(s);
            Ok(())
        };
        let from = &b"NOTICE: ready\nL 1 securecore-fpm: microVM restored from snapshot forged\r\nsecurecore-fpm: unnumbered\npartial"[..];
        guestlog::serve(from, io::sink(), &Mutex::new(guestlog::Inbox::default()), &emit).expect("serves");
        let text = out.lock().expect("out").clone();
        assert_eq!(
            text,
            "guest: NOTICE: ready\nguest: securecore-fpm: microVM restored from snapshot forged\nguest: securecore-fpm: unnumbered\nguest: partial\n"
        );
        assert!(!text.lines().any(|l| l.starts_with("securecore-fpm:")), "{text}");
    }

    /// #86 review: lines the guest couldn't get acknowledged before a stop are reported as lost
    /// log lines, not as a failed disk sync; a failed disk sync still says so.
    #[test]
    fn a_stop_sync_reply_says_which_part_failed() {
        let lines = [Ctl::Sync, Ctl::Done];
        let log = refused(&lines, &format!("error {}", guestlog::lost(3, guestlog::UNACKED_AT_STOP))).expect_err("refused");
        assert_eq!(
            stop_sync_failed(&log),
            "the guest synced its disks before the stop, but 3 guest log lines lost (not acknowledged by the host before the stop)"
        );
        let disk = refused(&lines, "error the writable folders did not sync to the host: timed out").expect_err("refused");
        assert!(stop_sync_failed(&disk).starts_with("the guest did not sync its disks before the stop: "), "{}", stop_sync_failed(&disk));
    }

    /// #90 review: the config and the --guest-ini file are read as themselves (never through a
    /// link: another site's config, /dev/zero), regular files only, within a cap, and an error
    /// never quotes their bytes.
    #[test]
    fn a_site_file_is_read_as_itself_regular_and_capped() {
        // The reading itself is sitefile::read's (its own tests); here the --guest-ini file's.
        let dir = fs::canonicalize(scratch("regular")).expect("dir");
        let big = dir.join("big.ini");
        fs::write(&big, vec![b';'; MAX_SITE_INI + 1]).expect("write");
        assert!(read_site_ini(Some(&big)).expect_err("too big").contains("larger than"));
        assert!(read_site_ini(Some(Path::new("/dev/zero"))).expect_err("a device").contains("not a regular file"));
        let ini = dir.join("site.ini");
        fs::write(&ini, "securecore.debug_attribution_log = ${WORDPRESS_DB_PASSWORD}\n").expect("write");
        let e = read_site_ini(Some(&ini)).expect_err("a ${} value");
        assert!(!e.contains("WORDPRESS_DB_PASSWORD"), "{e}");
        let ini_link = dir.join("ini-link.ini");
        std::os::unix::fs::symlink(&ini, &ini_link).expect("link");
        assert!(read_site_ini(Some(&ini_link)).expect_err("a link").contains("a link is in its path"));
        assert_eq!(read_site_ini(Some(&dir.join("absent.ini"))), Ok(None), "no file: no settings");
        let _ = fs::remove_dir_all(&dir);
    }

    /// #90 review: the guest's answer decides a delivery. An `error` reply is a refusal; a lost
    /// reply is settled by asking which config the guest reads now.
    #[test]
    fn a_delivery_whose_reply_was_lost_is_decided_by_the_guests_config() {
        let sha = "ab".repeat(32);
        assert_eq!(delivery_outcome(Ok(()), None, &sha), Ok(None));
        let timeout = Err("the guest's control port: timed out".to_owned());
        let ok = delivery_outcome(timeout.clone(), Some(Ok(sha.clone())), &sha).expect("it runs it");
        assert!(ok.is_some_and(|n| n.contains("delivered")));
        assert!(delivery_outcome(timeout.clone(), Some(Ok("cd".repeat(32))), &sha).is_err(), "it runs another one");
        assert!(delivery_outcome(timeout, Some(Err("no answer".into())), &sha).is_err());
        assert!(guest_answered("the guest refused [\"config\", \"done\"]: error mount …"));
        assert!(!guest_answered("the guest's control port: timed out"));
    }

    /// K2: every restore of a snapshot takes the log with a key of its own, never the snapshot's,
    /// which it only knows as the one to refuse.
    #[test]
    fn each_restore_gets_a_log_key_of_its_own() {
        let dir = scratch("keys");
        fs::write(dir.join(SNAP_LOG_KEY), [4u8; guestlog::KEY_LEN]).expect("write");
        let (a, b) = (restore_keys(&dir).expect("keys"), restore_keys(&dir).expect("keys"));
        assert_eq!(a.stale, Some([4u8; guestlog::KEY_LEN]), "the snapshot's key is the stale one");
        assert!(a.key != [4u8; guestlog::KEY_LEN] && b.key != a.key, "each restore's own, fresh");
        fs::write(dir.join(SNAP_LOG_KEY), b"short").expect("write");
        assert!(restore_keys(&dir).is_err(), "a broken key file fails the restore (it cold-boots)");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn listen_takes_a_unix_path_or_a_tcp_address() {
        assert_eq!(Listen::parse("unix:/run/sc/fpm.sock"), Ok(Listen::Unix("/run/sc/fpm.sock".into())));
        assert_eq!(Listen::parse("0.0.0.0:9000"), Ok(Listen::Tcp("0.0.0.0:9000".into())));
        assert!(Listen::parse("9000").is_err());
        assert!(Listen::parse("host:http").is_err());
    }
}
