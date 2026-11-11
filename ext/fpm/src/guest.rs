//! PID 1 in the microVM guest (addiscorp/securecore#71): `securecore-fpm` run as
//! `/sbin/securecore-init`. It replaces the spike's `init.sh` and its socat processes. The guest
//! has no network device, only loopback and vsock:
//!
//! ```text
//!   in    vsock 9000 → 127.0.0.1:9000 → php-fpm (FastCGI from the host driver)
//!   out   php-fpm's connect to 127.0.0.1:<port> is a vsock connect to the host on that port
//!         (libsc-vsock-connect.so, #70), for each port the host forwards (sc.ports); a unix
//!         socket under /run (sc.sock) reaches the same port through a forwarder here
//!   log   php-fpm's stdout and stderr, and this init's own lines → vsock host:1514 (the serial
//!         console is too slow), numbered and held until the host acknowledges them (#86,
//!         [`crate::guestlog`])
//!   ctl   vsock 1515: the host's start message, sent after every cold boot and every restore:
//!         the clock, then the writable disks to mount; and `sync` before it stops the VM
//!         (see [`Ctl`])
//! ```
//!
//! Disks: vda is this root (read-only), vdb the site (read-only, at `sc.root`), and vdc on are
//! the writable folders, which the host names in its start message. They are mounted only then,
//! never before a snapshot, so a restored guest never holds a stale view of a disk the host
//! may have changed since: the snapshot has the devices but no filesystem on them, and each
//! device's buffer cache is dropped before it is mounted.

use std::ffi::CString;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::thread;
use std::time::Duration;

use crate::vsock::{self, HOST_CID, Vsock};

/// The guest port php-fpm is reached on, and the loopback port its pool listens on.
pub const FPM_PORT: u32 = 9000;
/// The host port the guest sends php-fpm's output to.
pub const LOG_PORT: u32 = 1514;
/// The guest port the host's start message arrives on.
pub const CTL_PORT: u32 = 1515;
/// mysqlnd's connect onto vsock, preloaded into php-fpm (#70).
pub const PRELOAD: &str = "/usr/local/lib/libsc-vsock-connect.so";
/// php-fpm's environment as the host's start message delivered it (`env` lines: the vault's
/// secrets and the site's settings, #72). Only in this process's memory: never in an image, a
/// boot argument or the console, and empty in a snapshot (it is taken before any start
/// message), so every restore gets it again.
static GUEST_ENV: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
/// The longest value an `env` line may carry.
pub const MAX_ENV_VALUE: usize = 16 * 1024;
/// php-fpm's value for a delivered variable before the start message has delivered it.
pub const NOT_DELIVERED: &str = "securecore-not-delivered-yet";
/// The same ini folder without securecore.ini (`sc.ext=0`, the latency comparison).
pub const NOEXT_INI: &str = "/usr/local/etc/php/conf.d-noext";

/// BLKFLSBUF, `_IO(0x12, 97)`: drop a block device's buffer cache.
const BLKFLSBUF: libc::c_ulong = 0x1261;

/// What the kernel command line tells the guest (`sc.*` words; the rest are the kernel's).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Boot {
    /// `sc.time=<epoch seconds>`: Firecracker has no RTC.
    pub time: Option<i64>,
    /// `sc.root=<path>`: where the site disk is mounted, the path nginx sends in SCRIPT_FILENAME.
    pub root: String,
    /// `sc.ports=3306,6379`: the host forwards these; php-fpm's loopback connects to them go
    /// over vsock.
    pub ports: Vec<u16>,
    /// `sc.sock=3306:/run/mysqld/mysqld.sock` (repeatable): a unix socket in the guest that
    /// reaches host port 3306's forward.
    pub socks: Vec<(u16, String)>,
    /// `sc.egress=443`: php-fpm's connections to a named host on these ports go through the
    /// host, which checks the name ([`crate::egress`]).
    pub egress: Vec<u16>,
    /// `sc.proto=<N>`: the protocol the host booted this guest for. Unless it is this init's
    /// own ([`crate::vm::PROTOCOL`]), the init takes no start message (so no secret).
    pub proto: Option<u32>,
    /// `sc.env=WORDPRESS_DB_PASSWORD,…`: the names (never the values) of the environment the
    /// start message delivers. Until it does, php-fpm has [`NOT_DELIVERED`] for each, so it can
    /// start at boot (the extension's vault refuses a missing variable) and the snapshot holds
    /// no secret.
    pub env_names: Vec<String>,
    /// `sc.ext=0`: php-fpm without the extension.
    pub ext: bool,
    /// `sc.user=<uid>:<gid>`: the host's pool user, whom php-fpm's pool runs as here, so the
    /// writable disks (owned as on the host) are writable whatever the image's www-data is.
    pub user: Option<(u32, u32)>,
}

/// Parses the guest's kernel command line. Paths may not hold spaces (the command line is
/// space-separated); the host refuses such paths before it boots.
pub fn parse_cmdline(line: &str) -> Result<Boot, String> {
    let mut boot = Boot { ext: true, ..Boot::default() };
    for word in line.split_whitespace() {
        let Some((key, value)) = word.split_once('=') else { continue };
        match key {
            "sc.time" => boot.time = Some(value.parse().map_err(|_| format!("sc.time={value}: not a number"))?),
            "sc.root" => boot.root = value.to_owned(),
            "sc.ports" => {
                for p in value.split(',').filter(|p| !p.is_empty()) {
                    boot.ports.push(p.parse().map_err(|_| format!("sc.ports: {p} is not a port"))?);
                }
            }
            "sc.env" => {
                for n in value.split(',').filter(|n| !n.is_empty()) {
                    if !env_name_ok(n) {
                        return Err(format!("sc.env: {n:?} is not a variable name"));
                    }
                    boot.env_names.push(n.to_owned());
                }
            }
            "sc.egress" => {
                for p in value.split(',').filter(|p| !p.is_empty()) {
                    boot.egress.push(p.parse().map_err(|_| format!("sc.egress: {p} is not a port"))?);
                }
            }
            "sc.sock" => {
                let (port, path) = value.split_once(':').ok_or_else(|| format!("sc.sock={value}: want PORT:PATH"))?;
                let port = port.parse().map_err(|_| format!("sc.sock: {port} is not a port"))?;
                boot.socks.push((port, path.to_owned()));
            }
            "sc.ext" => boot.ext = value != "0",
            "sc.proto" => boot.proto = Some(value.parse().map_err(|_| format!("sc.proto={value}: not a number"))?),
            "sc.user" => {
                let bad = || format!("sc.user={value}: want <uid>:<gid>, not root");
                let (u, g) = value.split_once(':').ok_or_else(bad)?;
                let (u, g) = (u.parse::<u32>().map_err(|_| bad())?, g.parse::<u32>().map_err(|_| bad())?);
                if u == 0 || g == 0 {
                    return Err(bad());
                }
                boot.user = Some((u, g));
            }
            _ => {}
        }
    }
    if !boot.root.starts_with('/') {
        return Err(format!("sc.root={:?}: want an absolute path", boot.root));
    }
    Ok(boot)
}

/// One line of the host's start message on vsock 1515. The host writes [`Ctl::line`]s and then
/// [`Ctl::Done`]; the guest applies each in order, answers `ok` or `error <why>` to `done`, and
/// closes. The same type encodes and decodes, so the two sides can't disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ctl {
    /// Set the clock (after a restore it is the snapshot's).
    Time { secs: i64, nanos: u32 },
    /// Fresh randomness from the host (64 bytes, hex): credited to the kernel's pool and the
    /// CRNG reseeded, so a restored guest doesn't replay the snapshot's random stream.
    Entropy { hex: String },
    /// One variable of php-fpm's environment (its value hex-encoded): the vault's secrets and
    /// the site's settings. A start message with any starts a fresh php-fpm that has them.
    Env { name: String, hex: String },
    /// This boot is a restore: php-fpm's workers were forked before the snapshot (and hold its
    /// userland generator state), so they are replaced by fresh ones.
    Refresh,
    /// Mount an ext4 disk read-write at a path.
    Mount { device: String, path: String },
    /// Mount a tmpfs at a path (a writable folder outside the app root).
    Tmpfs { path: String },
    /// Write every dirty page to the disks: the host sends it before it stops the VM, so what
    /// php-fpm wrote to a writable folder is on the host's disk image.
    Sync,
    /// A graceful php-fpm reload (SIGUSR2 to its master): the launcher's SIGUSR2 or SIGHUP.
    Reload,
    /// The handshake, alone on its connection before the start message: the host's protocol.
    /// `ok` only when it is this init's own and the one it booted with (`sc.proto`).
    Proto { version: u32 },
    /// A new `securecore.json` (hex), after the start (#90): put in place of the site disk's
    /// copy at `<root>/securecore.json`, where the extension's own reload picks it up, as it does
    /// on a host. The host validated it first.
    Config { hex: String },
    /// The site's php.ini settings (hex, the whole file; empty: none), in the start message or
    /// after it (#90): php-fpm is started again with them (a graceful stop first), as a php.ini
    /// change needs on a host. The host allows only `securecore.debug_*` keys ([`site_ini`]).
    Ini { hex: String },
    /// This VM's log key (hex, [`crate::guestlog::KEY_LEN`] bytes): the host takes the log only
    /// from connections that present it (#86). Alone on its connection, at any time; only the
    /// host can reach this port, and no other process in the guest learns the key.
    LogKey { hex: String },
    /// A question, alone on its connection: the sha256 of the config the guest's extension reads
    /// now, answered `sha <hex>` (#90 review: a delivery whose reply was lost is decided by it).
    ConfigSha,
    Done,
}

/// The largest `securecore.json` the host delivers (bytes).
pub const MAX_CONFIG: usize = crate::sitefile::MAX_CONFIG;
/// Where the guest keeps delivered configs and the site's ini.
const LIVE_DIR: &str = "/run/securecore";
/// php-fpm's extra ini folder, after the image's own: the site's settings ([`Ctl::Ini`]).
pub const SITE_INI_DIR: &str = "/run/securecore/conf.d";
/// The image's ini folder (PHP's compiled-in scan dir in the official images).
pub const IMAGE_INI: &str = "/usr/local/etc/php/conf.d";
/// At most this many configs are delivered into one running guest: each is a file mounted over
/// the one before it (the swap is atomic for the extension's readers), so they stack, each file
/// kept in the guest's memory: at most 200 × [`MAX_CONFIG`] (25 MiB), a few hundred KiB for
/// configs of the usual size. A restart starts the count again.
pub const MAX_CONFIG_SWAPS: usize = 200;

/// A value a site's php.ini setting may have in the guest: `[a-z0-9_.,:-]{0,64}`.
pub fn site_ini_value_ok(value: &str) -> bool {
    value.len() <= 64 && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.,:-".contains(&b))
}

/// The settings a site's php.ini may give the guest's php-fpm (#90): the extension's per-site
/// debug settings only, with plain-word values ([`site_ini_value_ok`]). Everything else in
/// php.ini is the image's (the same for every site); a line setting anything else, or that
/// isn't `key = value`, is refused with the reason, which never quotes the file. Returns the
/// file as the guest writes it.
pub fn site_ini(text: &str) -> Result<String, String> {
    let mut out = String::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        // Nothing from the file is ever quoted back (#90 review): a refused line could hold
        // anything, a secret among it, and the reason goes to the launcher's log.
        let n = n + 1;
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {n}: not `key = value`"));
        };
        let (key, value) = (key.trim(), value.trim());
        let ok = key.strip_prefix("securecore.debug_").is_some_and(|k| !k.is_empty() && k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
        if !ok {
            return Err(format!(
                "line {n}: a site's php.ini may set only the extension's securecore.debug_* settings in the guest (the rest of php.ini is the guest image's)"
            ));
        }
        // Plain words only: PHP's ini parser expands ${VAR} from php-fpm's environment, where the
        // vault's secrets are, and quotes would let a value say more than a word (#90 review).
        if !site_ini_value_ok(value) {
            return Err(format!("line {n}: {key}: a value may hold only a-z, 0-9 and _ . , : - (at most 64)"));
        }
        out.push_str(&format!("{key} = {value}\n"));
    }
    Ok(out)
}

impl Ctl {
    pub fn line(&self) -> String {
        match self {
            Ctl::Time { secs, nanos } => format!("time {secs} {nanos}\n"),
            Ctl::Entropy { hex } => format!("entropy {hex}\n"),
            Ctl::Env { name, hex } => format!("env {name} {hex}\n"),
            Ctl::Refresh => "refresh\n".into(),
            Ctl::Mount { device, path } => format!("mount {device} {path}\n"),
            Ctl::Tmpfs { path } => format!("tmpfs {path}\n"),
            Ctl::Sync => "sync\n".into(),
            Ctl::Reload => "reload\n".into(),
            Ctl::Proto { version } => format!("proto {version}\n"),
            Ctl::Config { hex } => format!("config {hex}\n"),
            Ctl::Ini { hex } if hex.is_empty() => "ini\n".into(),
            Ctl::Ini { hex } => format!("ini {hex}\n"),
            Ctl::LogKey { hex } => format!("logkey {hex}\n"),
            Ctl::ConfigSha => "configsha\n".into(),
            Ctl::Done => "done\n".into(),
        }
    }

    pub fn parse(line: &str) -> Result<Ctl, String> {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["time", secs, nanos] => Ok(Ctl::Time {
                secs: secs.parse().map_err(|_| format!("time: {secs}"))?,
                nanos: nanos.parse().ok().filter(|n| *n < 1_000_000_000).ok_or_else(|| format!("time: {nanos}"))?,
            }),
            ["entropy", hex] if hex.len() == 128 && hex.bytes().all(|b| b.is_ascii_hexdigit()) => Ok(Ctl::Entropy { hex: (*hex).into() }),
            ["env", name, hex] if env_name_ok(name) && hex.len() % 2 == 0 && hex.len() <= 2 * MAX_ENV_VALUE && hex.bytes().all(|b| b.is_ascii_hexdigit()) => {
                Ok(Ctl::Env { name: (*name).into(), hex: (*hex).into() })
            }
            ["env", name] if env_name_ok(name) => Ok(Ctl::Env { name: (*name).into(), hex: String::new() }),
            ["refresh"] => Ok(Ctl::Refresh),
            ["mount", device, path] => Ok(Ctl::Mount { device: (*device).into(), path: (*path).into() }),
            ["tmpfs", path] => Ok(Ctl::Tmpfs { path: (*path).into() }),
            ["sync"] => Ok(Ctl::Sync),
            ["reload"] => Ok(Ctl::Reload),
            ["proto", v] => Ok(Ctl::Proto { version: v.parse().map_err(|_| format!("proto: {v}"))? }),
            ["config", hex] if hex.len() % 2 == 0 && hex.len() <= 2 * MAX_CONFIG && hex.bytes().all(|b| b.is_ascii_hexdigit()) => {
                Ok(Ctl::Config { hex: (*hex).into() })
            }
            ["ini", hex] if hex.len() % 2 == 0 && hex.len() <= 2 * MAX_CONFIG && hex.bytes().all(|b| b.is_ascii_hexdigit()) => Ok(Ctl::Ini { hex: (*hex).into() }),
            ["ini"] => Ok(Ctl::Ini { hex: String::new() }),
            ["config" | "ini", ..] => Err(format!("a malformed {} line", words[0])),
            ["logkey", hex] if hex.len() == 2 * crate::guestlog::KEY_LEN && hex.bytes().all(|b| b.is_ascii_hexdigit()) => Ok(Ctl::LogKey { hex: (*hex).into() }),
            // Never echo it: it is a secret.
            ["logkey", ..] => Err("a malformed logkey line".into()),
            ["configsha"] => Ok(Ctl::ConfigSha),
            ["done"] => Ok(Ctl::Done),
            // Never echo an env line: it carries a secret.
            ["env", ..] => Err("a malformed env line".into()),
            _ => Err(format!("unknown control line {line:?}")),
        }
    }

    /// Part of the one start message a boot accepts (the rest may come any time after it).
    pub fn starts(&self) -> bool {
        matches!(self, Ctl::Time { .. } | Ctl::Entropy { .. } | Ctl::Env { .. } | Ctl::Refresh | Ctl::Mount { .. } | Ctl::Tmpfs { .. })
    }
}

/// An environment variable's name: a letter or `_`, then letters, digits and `_`, 1 to 128.
pub fn env_name_ok(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty() && b.len() <= 128 && (b[0].is_ascii_alphabetic() || b[0] == b'_') && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

/// What a control connection may do, given whether this boot's start message was taken.
/// Exactly one start message per boot (a snapshot is taken before it, so each restore takes its
/// own); after it only `sync` and `reload`, and nothing at all before it but a start.
pub fn allowed(lines: &[Ctl], started: bool) -> Result<(), String> {
    if lines.iter().any(|c| matches!(c, Ctl::Proto { .. } | Ctl::LogKey { .. })) && lines.len() > 1 {
        return Err("the handshake comes alone".into());
    }
    let starts = lines.iter().any(Ctl::starts);
    // (`ini` goes with either: at the start, or alone after it.)
    let others = lines.iter().any(|c| matches!(c, Ctl::Sync | Ctl::Reload | Ctl::Config { .. }));
    match (started, starts, others) {
        (true, true, _) => Err("this boot's start message was already taken".into()),
        (false, false, true) => Err("nothing but the start message before the start message".into()),
        (false, false, false) if lines.iter().any(|c| matches!(c, Ctl::Ini { .. })) => Err("nothing but the start message before the start message".into()),
        (false, true, true) => Err("a start message carries no sync, reload or config".into()),
        _ => Ok(()),
    }
}

/// Whether this init may take `lines`, given the protocol it was booted for (`sc.proto`): the
/// handshake is answered `ok` only for its own protocol, and a start message (which may carry
/// secrets) is taken only when it was booted for it. The host sends nothing secret until the
/// handshake's `ok` ([`crate::vm::PROTOCOL`]).
pub fn protocol_ok(lines: &[Ctl], booted: Option<u32>) -> Result<(), String> {
    let mine = crate::vm::PROTOCOL;
    let booted_s = booted.map_or_else(|| "no sc.proto".to_owned(), |b| format!("sc.proto={b}"));
    for c in lines {
        if let Ctl::Proto { version } = c
            && (*version != mine || booted != Some(mine))
        {
            return Err(format!("this guest's init speaks protocol {mine} ({booted_s}), the host {version}"));
        }
    }
    if lines.iter().any(Ctl::starts) && booted != Some(mine) {
        return Err(format!("this guest's init speaks protocol {mine} and was booted with {booted_s}: it takes no start message"));
    }
    Ok(())
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::other(format!("{s:?} holds a NUL")))
}

fn mount(source: &str, target: &str, fstype: &str, flags: libc::c_ulong, data: &str) -> io::Result<()> {
    let (s, t, f, d) = (cstr(source)?, cstr(target)?, cstr(fstype)?, cstr(data)?);
    // SAFETY: mount(2) with NUL-terminated strings that live across the call.
    let r = unsafe { libc::mount(s.as_ptr(), t.as_ptr(), f.as_ptr(), flags, d.as_ptr().cast()) };
    if r < 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("mount {source} on {target} ({fstype}): {e}")));
    }
    Ok(())
}

fn set_clock(secs: i64, nanos: u32) -> io::Result<()> {
    let ts = libc::timespec { tv_sec: secs as libc::time_t, tv_nsec: nanos as libc::c_long };
    // SAFETY: clock_settime(2) reads the timespec passed.
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `ip link set lo up`, without iproute2.
fn loopback_up() -> io::Result<()> {
    // SAFETY: a plain datagram socket for the interface ioctls; owned below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was just returned by socket(2).
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: ifreq is plain data; all zeroes is a valid value.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in req.ifr_name.iter_mut().zip(b"lo") {
        *dst = *src as libc::c_char;
    }
    // SAFETY: SIOCGIFFLAGS / SIOCSIFFLAGS read and write the ifreq passed, on our socket.
    unsafe {
        if libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFFLAGS, &mut req) < 0 {
            return Err(io::Error::last_os_error());
        }
        req.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        if libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFFLAGS, &req) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// RNDADDENTROPY (`_IOW('R', 0x03, int[2])`) and RNDRESEEDCRNG (`_IO('R', 0x07)`).
const RNDADDENTROPY: libc::c_ulong = 0x4008_5203;
const RNDRESEEDCRNG: libc::c_ulong = 0x5207;

/// Credits `bytes` to the kernel's pool and reseeds the CRNG from it.
fn add_entropy(bytes: &[u8]) -> io::Result<()> {
    // struct rand_pool_info { int entropy_count; int buf_size; __u32 buf[]; }
    let mut info: Vec<u8> = Vec::with_capacity(8 + bytes.len());
    info.extend_from_slice(&((bytes.len() * 8) as i32).to_ne_bytes());
    info.extend_from_slice(&(bytes.len() as i32).to_ne_bytes());
    info.extend_from_slice(bytes);
    let dev = fs::OpenOptions::new().write(true).open("/dev/random")?;
    // SAFETY: both ioctls on /dev/random; RNDADDENTROPY reads the rand_pool_info laid out above.
    unsafe {
        if libc::ioctl(dev.as_raw_fd(), RNDADDENTROPY, info.as_ptr()) < 0 {
            return Err(io::Error::other(format!("RNDADDENTROPY: {}", io::Error::last_os_error())));
        }
        if libc::ioctl(dev.as_raw_fd(), RNDRESEEDCRNG, 0) < 0 {
            return Err(io::Error::other(format!("RNDRESEEDCRNG: {}", io::Error::last_os_error())));
        }
    }
    Ok(())
}

/// Bytes as lowercase hex (the `entropy` and `env` lines' encoding).
pub fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2).filter_map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()).collect()
}

/// php-fpm's master, once started (0 while a reload restarts it).
static FPM_MASTER: AtomicI32 = AtomicI32::new(0);
/// The kernel command line's settings, for a reload's fresh php-fpm.
static BOOT: std::sync::OnceLock<Boot> = std::sync::OnceLock::new();
/// Whether this boot took its start message.
static STARTED: AtomicBool = AtomicBool::new(false);
/// Control connections being served now.
static CTL_BUSY: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// How long a reload waits for php-fpm's graceful stop before it kills it. The host waits
/// [`RELOAD_TIMEOUT`] for the whole reload, which includes php-fpm starting again.
pub const RELOAD_GRACE: Duration = Duration::from_secs(20);
pub const RELOAD_TIMEOUT: Duration = Duration::from_secs(40);
/// The host's wait for a `sync` (and the guest's for a control connection's lines).
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(10);
/// The writable disks' mount points, in the start message's order: watched for space, and
/// synced to the host (their index is the sync's disk number).
static WRITABLE: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// The folder sync's progress, which a `sync` line waits on.
static DRAIN: std::sync::OnceLock<crate::sync::Drain> = std::sync::OnceLock::new();
/// How long a `sync` line waits for the writable folders to reach the host (the host waits
/// [`SYNC_TIMEOUT`] for the whole line).
const SYNC_DRAIN: Duration = Duration::from_secs(8);
/// A writable disk's ext4 options: its journal commits every second (see `boot_guest`).
pub const WRITABLE_MOUNT_DATA: &str = "commit=1";

/// php-fpm's pool workers (`php-fpm: pool …`), children of the master: not the master, and not
/// the extension's layer 3 helper.
fn pool_workers(master: i32) -> Vec<i32> {
    let mut out = Vec::new();
    for e in fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        // pid (comm) state ppid …: comm may hold spaces, so split after its closing paren.
        let ppid = stat.rsplit_once(')').and_then(|(_, rest)| rest.split_whitespace().nth(1)).and_then(|p| p.parse::<i32>().ok());
        let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        if ppid == Some(master) && cmdline.starts_with(b"php-fpm: pool ") {
            out.push(pid);
        }
    }
    out
}

/// kill(2), never on a pid ≤ 0: 0 is init's own process group and -1 every process in the
/// guest, which a master pid read mid-reload (0) must never turn into.
pub fn signal(pid: i32, sig: libc::c_int) -> io::Result<()> {
    if pid <= 0 {
        return Err(io::Error::other(format!("refusing to send signal {sig} to pid {pid}")));
    }
    // SAFETY: kill(2) on one positive pid.
    if unsafe { libc::kill(pid, sig) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// php-fpm's master `pid` stopped gracefully (SIGQUIT: in-flight requests finish), or killed
/// after [`RELOAD_GRACE`]. Init's wait loop reaps it.
fn stop_gracefully(pid: i32) {
    if signal(pid, libc::SIGQUIT).is_err() {
        return;
    }
    let t = std::time::Instant::now();
    while Path::new(&format!("/proc/{pid}")).exists() {
        if t.elapsed() > RELOAD_GRACE {
            let _ = signal(pid, libc::SIGKILL);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// One reload at a time: two control connections can each carry a `reload` (two signals close
/// together on the host), and the second must stop the master the first started, never read
/// the 0 that stands for "being replaced".
static RELOADING: Mutex<()> = Mutex::new(());

/// Replaces the master recorded in `master`: `stop` the old one (when there is one: a reload
/// whose start failed leaves none), `start` a fresh one and record it. Serialised by
/// [`RELOADING`].
pub fn reload(master: &AtomicI32, stop: impl FnOnce(i32), start: impl FnOnce() -> io::Result<i32>) -> io::Result<()> {
    let _one = RELOADING.lock().unwrap_or_else(|p| p.into_inner());
    let old = master.swap(0, Ordering::SeqCst);
    if old > 0 {
        stop(old);
    }
    let pid = start()?;
    master.store(pid, Ordering::SeqCst);
    Ok(())
}

/// Configs delivered into this guest so far ([`MAX_CONFIG_SWAPS`]).
static CONFIG_SWAPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Puts `bytes` in place of `<root>/securecore.json` (#90): written to a new file on tmpfs, then
/// bind-mounted (read-only) over the path, on top of the one before. A reader opens either the
/// old file or the new one, never a half-written one, and the extension's stat sees a new inode.
fn put_config(bytes: &[u8]) -> io::Result<()> {
    let boot = BOOT.get().ok_or_else(|| io::Error::other("no boot settings"))?;
    if bytes.len() > MAX_CONFIG {
        return Err(io::Error::other(format!("a config over {MAX_CONFIG} bytes")));
    }
    let n = CONFIG_SWAPS.fetch_add(1, Ordering::SeqCst) + 1;
    if n > MAX_CONFIG_SWAPS {
        CONFIG_SWAPS.fetch_sub(1, Ordering::SeqCst);
        return Err(io::Error::other(format!("{MAX_CONFIG_SWAPS} configs were already delivered to this guest; restart the launcher to apply more")));
    }
    fs::create_dir_all(LIVE_DIR)?;
    let file = format!("{LIVE_DIR}/securecore-{n}.json");
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o644).open(&file)?;
        f.write_all(bytes)?;
    }
    let target = format!("{}/securecore.json", boot.root);
    // Mounted on the file itself, never through a link (#90 review): the site disk is the site's,
    // and `<root>/securecore.json` there could be a link to anywhere in the guest. Opened without
    // following one, it must be a regular file, and the mount goes on that very file.
    let at = regular_target(&target)?;
    mount(&file, &fd_path(&at), "", libc::MS_BIND, "")?;
    // A bind mount takes its flags only on a remount: on the new mount, again by its file.
    let top = regular_target(&target)?;
    mount("", &fd_path(&top), "", libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, "")?;
    // The file stays: the next config is mounted on this one, and Linux refuses a mount on a
    // file that has been unlinked. (Under /run, which php-fpm's pool user can't write.)
    Ok(())
}

/// `path` opened `O_PATH | O_NOFOLLOW`: refused unless it is a regular file itself (a link is
/// not followed, and is refused).
pub fn regular_target(path: &str) -> io::Result<OwnedFd> {
    let c = cstr(path)?;
    // SAFETY: open(2) with a NUL-terminated path; the fd is owned below.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("{path}: {e}")));
    }
    // SAFETY: fd was just returned by open(2).
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let f = fs::File::from(fd);
    let m = f.metadata().map_err(|e| io::Error::new(e.kind(), format!("{path}: {e}")))?;
    if !m.file_type().is_file() {
        return Err(io::Error::other(format!("{path} is not a regular file (a link, a folder or a device): not replaced")));
    }
    Ok(OwnedFd::from(f))
}

/// `/proc/self/fd/<n>`: the open file itself, for a call that takes a path.
fn fd_path(fd: &OwnedFd) -> String {
    format!("/proc/self/fd/{}", fd.as_raw_fd())
}

/// The sha256 of the config the guest's extension reads now (`<root>/securecore.json`), for the
/// host to ask after a delivery whose answer it didn't get (#90 review).
fn config_sha() -> io::Result<String> {
    use sha2::{Digest as _, Sha256};
    let boot = BOOT.get().ok_or_else(|| io::Error::other("no boot settings"))?;
    // Never through a link, capped (#90 verification review, N5): the launcher's own reading.
    let path = format!("{}/securecore.json", boot.root);
    let bytes = crate::sitefile::read(Path::new(&path), MAX_CONFIG).map_err(io::Error::other)?.ok_or_else(|| io::Error::other(format!("{path}: missing")))?;
    Ok(hex_of(&Sha256::digest(&bytes)))
}

/// Applies one control line.
fn apply(ctl: &Ctl) -> io::Result<()> {
    match ctl {
        Ctl::Time { secs, nanos } => set_clock(*secs, *nanos),
        Ctl::Entropy { hex } => add_entropy(&unhex(hex)),
        Ctl::Env { name, hex } => {
            let value = String::from_utf8(unhex(hex)).map_err(|_| io::Error::other(format!("env {name}: not UTF-8")))?;
            let mut env = GUEST_ENV.lock().unwrap_or_else(|p| p.into_inner());
            env.retain(|(n, _)| n != name);
            env.push((name.clone(), value));
            Ok(())
        }
        Ctl::Refresh => {
            // A graceful stop of each worker; the master forks fresh ones from itself (it ran no
            // request before the snapshot), and opcache's shared memory stays warm.
            let master = FPM_MASTER.load(Ordering::SeqCst);
            if master > 0 {
                for pid in pool_workers(master) {
                    let _ = signal(pid, libc::SIGQUIT);
                }
            }
            Ok(())
        }
        Ctl::Reload => {
            // Not php-fpm's own SIGUSR2: that re-execs the master with its current environment,
            // where the vault has already put placeholders in place of the secrets. A graceful
            // stop (SIGQUIT: in-flight requests finish), then a fresh php-fpm with init's own
            // environment, as at boot.
            let boot = BOOT.get().ok_or_else(|| io::Error::other("no boot settings"))?;
            reload(&FPM_MASTER, stop_gracefully, || start_php_fpm(boot).map(|pid| pid as i32))
        }
        Ctl::Mount { device, path } => {
            // The snapshot may hold the device's first blocks from the kernel's partition scan
            // at boot, and the host may have written the disk since: drop them first.
            let dev = fs::File::open(device).map_err(|e| io::Error::new(e.kind(), format!("{device}: {e}")))?;
            // SAFETY: BLKFLSBUF takes no argument; the fd is open.
            if unsafe { libc::ioctl(dev.as_raw_fd(), BLKFLSBUF, 0) } < 0 {
                let e = io::Error::last_os_error();
                return Err(io::Error::new(e.kind(), format!("{device}: BLKFLSBUF: {e}")));
            }
            drop(dev);
            // noexec (#86 verification review): nothing written to a writable folder runs.
            mount(device, path, "ext4", libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, WRITABLE_MOUNT_DATA)?;
            WRITABLE.lock().unwrap_or_else(|p| p.into_inner()).push(path.clone());
            // Every file closed after writing is made durable at once, whatever the host's sync
            // is doing (it may be stuck behind a host that doesn't answer).
            let mount_path = path.clone();
            thread::spawn(move || {
                if let Err(e) = crate::sync::keep_durable(&mount_path) {
                    report(&format!("sync: making {mount_path} durable on close stopped: {e}"));
                }
            });
            Ok(())
        }
        Ctl::Tmpfs { path } => mount("tmpfs", path, "tmpfs", libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, "mode=1777"),
        Ctl::Sync => {
            // SAFETY: sync(2) takes nothing and can't fail.
            unsafe { libc::sync() };
            // And every change to a writable folder is on the host's copy of it (#72).
            if !WRITABLE.lock().unwrap_or_else(|p| p.into_inner()).is_empty() {
                let drain = DRAIN.get().ok_or_else(|| io::Error::other("the folder sync never started"))?;
                drain.wait(SYNC_DRAIN).map_err(|e| io::Error::other(format!("the writable folders did not sync to the host: {e}")))?;
            }
            // The host stops the VM after a sync: every log line must be in its log by then, or
            // counted there as lost (the reply is the launcher's to log).
            LOG.drain(LOG_DRAIN).map_err(|n| io::Error::other(crate::guestlog::lost(n as u64, crate::guestlog::UNACKED_AT_STOP)))
        }
        Ctl::Config { hex } => put_config(&unhex(hex)),
        Ctl::Ini { hex } => {
            let text = String::from_utf8(unhex(hex)).map_err(|_| io::Error::other("ini: not UTF-8"))?;
            // Checked again here: the guest takes no php.ini line but the extension's debug ones.
            let text = site_ini(&text).map_err(io::Error::other)?;
            fs::create_dir_all(SITE_INI_DIR)?;
            let path = format!("{SITE_INI_DIR}/zz-site.ini");
            fs::write(format!("{path}.new"), &text)?;
            fs::rename(format!("{path}.new"), &path)?;
            Ok(())
        }
        Ctl::LogKey { hex } => {
            let key: crate::guestlog::Key = unhex(hex).try_into().map_err(|_| io::Error::other("logkey: not a key"))?;
            LOG.set_key(key);
            Ok(())
        }
        // Answered by serve_ctl itself.
        Ctl::ConfigSha => Ok(()),
        // Checked before anything is applied ([`protocol_ok`]).
        Ctl::Proto { .. } | Ctl::Done => Ok(()),
    }
}

/// One control connection, from the host only: its lines up to `done` are read (within 10 s),
/// checked against [`allowed`], applied in order, and answered `ok` or `error <why>`.
fn serve_ctl(conn: Vsock, peer_cid: u32) {
    let mut out = match vsock::Half::dup(&conn) {
        Ok(out) => out,
        Err(e) => return say(&format!("ctl: {e}")),
    };
    if peer_cid != HOST_CID {
        say(&format!("ctl: refused a connection from CID {peer_cid}: only the host (CID {HOST_CID}) controls this guest"));
        return;
    }
    let _ = conn.set_read_timeout(SYNC_TIMEOUT);
    let mut lines = Vec::new();
    let mut failed: Option<String> = None;
    let mut done = false;
    for line in BufReader::new(conn).lines() {
        let Ok(line) = line else { break };
        match Ctl::parse(&line) {
            Ok(Ctl::Done) => {
                done = true;
                break;
            }
            Ok(ctl) => lines.push(ctl),
            Err(e) => failed = failed.or(Some(e)),
        }
    }
    if !done {
        return say("ctl: a control connection closed or timed out before `done`; nothing applied");
    }
    // The one question: which config the extension reads now.
    if failed.is_none() && lines == [Ctl::ConfigSha] {
        let reply = config_sha().map_or_else(|e| format!("error {e}\n"), |sha| format!("sha {sha}\n"));
        let _ = out.write_all(reply.as_bytes());
        return;
    }
    let started = STARTED.load(Ordering::SeqCst);
    if failed.is_none() {
        failed = allowed(&lines, started).err();
    }
    // Before anything is applied: a start message only for the protocol this init booted for.
    if failed.is_none() {
        failed = protocol_ok(&lines, BOOT.get().and_then(|b| b.proto)).err();
    }
    // The start message claims the boot's one start atomically (connections run concurrently).
    if failed.is_none() && lines.iter().any(Ctl::starts) && STARTED.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        failed = Some("this boot's start message was already taken".into());
    }
    if failed.is_none() {
        for ctl in &lines {
            if let Err(e) = apply(ctl) {
                failed = Some(e.to_string());
                break;
            }
        }
    }
    // The delivered environment reaches php-fpm only through a fresh master: the one running
    // now started at boot (before any start message, so a snapshot holds none of it). The same
    // for the site's php.ini settings, which PHP reads only at startup.
    if failed.is_none() && lines.iter().any(|c| matches!(c, Ctl::Env { .. } | Ctl::Ini { .. })) {
        if let Err(e) = apply(&Ctl::Reload) {
            failed = Some(format!("starting php-fpm with the delivered environment: {e}"));
        } else if !fpm_listening(Duration::from_secs(10)) {
            failed = Some(format!("php-fpm with the delivered environment isn't listening on 127.0.0.1:{FPM_PORT}"));
        }
    } else if failed.is_none() && lines.contains(&Ctl::Reload) && !fpm_listening(Duration::from_secs(10)) {
        // A reload is done once the fresh php-fpm takes requests, not once it is started: the
        // host says "reloaded" on this answer, and sends requests on (found by #86's stress on
        // GitHub's runners, where requests right after a reload met no listener).
        failed = Some(format!("the reloaded php-fpm isn't listening on 127.0.0.1:{FPM_PORT}"));
    }
    // The host never shows a reply to a message that carried secrets, so the reason is logged
    // here too (no message here ever holds a value: refused env lines are never echoed).
    if let Some(e) = &failed
        && lines.iter().any(|c| matches!(c, Ctl::Env { .. }))
    {
        report(&format!("ctl: the start message was refused: {e}"));
    }
    // A refusal may end the launcher: the lines that explain it reach its log first.
    if failed.is_some() {
        let _ = LOG.drain(LOG_DRAIN);
    }
    let reply = failed.map_or_else(|| "ok\n".to_owned(), |e| format!("error {e}\n"));
    let _ = out.write_all(reply.as_bytes());
}

/// Every line for the host's log (php-fpm's output and this init's own), held until the host
/// acknowledges it (#86): one numbered stream on one connection ([`crate::guestlog`]).
static LOG: crate::guestlog::Outbox = crate::guestlog::Outbox::new(crate::guestlog::OUTBOX_BYTES);
/// How long a `sync` waits for the host to have every log line (inside [`SYNC_TIMEOUT`]).
const LOG_DRAIN: Duration = Duration::from_secs(1);

/// The log's sender, once per boot (a restore resumes it with the snapshot).
fn start_log() {
    thread::spawn(|| crate::guestlog::send(&LOG, || Vsock::connect(HOST_CID, LOG_PORT)));
}

/// One line to the host's log, from this init (the host marks every guest line as the guest's).
fn report(message: &str) {
    // Its own kind of frame: the launcher logs it as `guest-init: `, which php-fpm's lines can't
    // be (#86 verification review).
    LOG.init_line(message.as_bytes());
}

/// Warns once a writable disk passes 90 % (and again past 98 %): beyond it, php-fpm's writes
/// fail with ENOSPC. The disk's size is the launcher's `--write-disk-mib`.
fn watch_space() {
    let mut warned: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    loop {
        thread::sleep(Duration::from_secs(30));
        let paths = WRITABLE.lock().unwrap_or_else(|p| p.into_inner()).clone();
        for path in paths {
            let Ok(c) = cstr(&path) else { continue };
            // SAFETY: statvfs(3) fills the struct passed.
            let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::statvfs(c.as_ptr(), &mut s) } < 0 || s.f_blocks == 0 {
                continue;
            }
            let used = 100 - (s.f_bavail as u64 * 100 / s.f_blocks as u64);
            let level = if used >= 98 { 98 } else if used >= 90 { 90 } else { 0 };
            if level > *warned.get(&path).unwrap_or(&0) {
                let free_mib = (s.f_bavail as u64 * s.f_frsize as u64) >> 20;
                report(&format!(
                    "the writable disk at {path} is {used}% full ({free_mib} MiB left): writes there will fail with \
                     ENOSPC when it fills; restart with a larger --write-disk-mib to grow it"
                ));
            }
            warned.insert(path, level);
        }
    }
}

/// php-fpm's output to the host's log, a line at a time ([`LOG`] delivers it). Never blocks on
/// the host: php-fpm's master writes every worker's lines to this pipe.
fn pump_log(from: fs::File) {
    let mut r = BufReader::with_capacity(64 << 10, from);
    let mut line = Vec::with_capacity(256);
    while let Some(cut) = crate::guestlog::read_capped(&mut r, &mut line, crate::guestlog::MAX_LINE) {
        if cut {
            line.extend_from_slice(" …[cut]".as_bytes());
        }
        LOG.line(&line);
        let mut last = LAST_WORDS.lock().unwrap_or_else(|p| p.into_inner());
        if last.len() == LAST_WORDS_N {
            last.pop_front();
        }
        last.push_back(String::from_utf8_lossy(&line).into_owned());
    }
}

/// php-fpm's last lines, for the console when it exits (#87): the log port may be what failed.
static LAST_WORDS: Mutex<std::collections::VecDeque<String>> = Mutex::new(std::collections::VecDeque::new());
const LAST_WORDS_N: usize = 20;
/// Each php-fpm master's log pump, by the master's pid: its exit is explained only once its
/// output is read to the end.
static PUMPS: Mutex<Vec<(i32, thread::JoinHandle<()>)>> = Mutex::new(Vec::new());
/// How long init waits, after php-fpm's master exits, for its last lines and for the host to
/// acknowledge them before it stops the VM.
const LAST_WORDS_WAIT: Duration = Duration::from_secs(3);

/// What a wait status says: `exit code N` or `killed by signal N`.
pub fn wait_status(status: libc::c_int) -> String {
    if libc::WIFEXITED(status) {
        format!("exit code {}", libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        format!("killed by signal {}", libc::WTERMSIG(status))
    } else {
        format!("wait status {status}")
    }
}

/// php-fpm's master `pid` exited with `status`, so the VM stops: its remaining output is read
/// to the end, the reason goes to the host's log (and the console), and the host acknowledges it
/// before init returns (#87). The launcher quotes it.
fn explain_exit(pid: i32, status: libc::c_int, started: bool) -> String {
    let t = std::time::Instant::now();
    let pump = {
        let mut p = PUMPS.lock().unwrap_or_else(|p| p.into_inner());
        p.iter().position(|(m, _)| *m == pid).map(|i| p.remove(i).1)
    };
    if let Some(pump) = pump {
        // The workers may hold the pipe a moment longer than the master.
        while !pump.is_finished() && t.elapsed() < LAST_WORDS_WAIT {
            thread::sleep(Duration::from_millis(10));
        }
    }
    let when = if started { "while serving" } else { "at boot, before it served" };
    let why = format!("php-fpm exited {when} ({}): its own lines above say why; stopping the VM", wait_status(status));
    for l in LAST_WORDS.lock().unwrap_or_else(|p| p.into_inner()).iter() {
        say(&format!("php-fpm: {l}"));
    }
    say(&why);
    report(&why);
    let _ = LOG.drain(LAST_WORDS_WAIT.saturating_sub(t.elapsed()).max(Duration::from_secs(1)));
    why
}

fn say(message: &str) {
    // The console: the serial port, read on the host as console.log.
    println!("securecore-init: {message}");
}

/// Whether php-fpm's pool accepts on loopback within `timeout` (the host serves once the start
/// message is answered, so a fresh master must be listening by then).
fn fpm_listening(timeout: Duration) -> bool {
    let t = std::time::Instant::now();
    while t.elapsed() < timeout {
        if TcpStream::connect(("127.0.0.1", FPM_PORT as u16)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    false
}

fn delivered_env() -> Vec<(String, String)> {
    GUEST_ENV.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

fn listen_forwards(boot: &Boot) -> io::Result<()> {
    // FastCGI from the host: vsock 9000 → php-fpm on loopback.
    let fpm = Vsock::listen(FPM_PORT)?;
    thread::spawn(move || {
        loop {
            let Ok((v, _)) = fpm.accept() else { continue };
            match TcpStream::connect(("127.0.0.1", FPM_PORT as u16)) {
                Ok(t) => {
                    let _ = t.set_nodelay(true);
                    let _ = vsock::join_closing(v, t);
                }
                Err(e) => say(&format!("fpm: 127.0.0.1:{FPM_PORT}: {e}")),
            }
        }
    });
    // A unix socket in the guest for a forwarded port (e.g. WordPress's DB_HOST=localhost).
    for (port, path) in &boot.socks {
        let port = u32::from(*port);
        if let Some(dir) = Path::new(path).parent() {
            fs::create_dir_all(dir)?;
        }
        let _ = fs::remove_file(path);
        let l = UnixListener::bind(path).map_err(|e| io::Error::new(e.kind(), format!("{path}: {e}")))?;
        let _ = fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o666));
        thread::spawn(move || {
            for c in l.incoming().flatten() {
                match Vsock::connect(HOST_CID, port) {
                    Ok(v) => {
                        let _ = vsock::join_closing(c, v);
                    }
                    Err(e) => say(&format!("vsock host:{port}: {e}")),
                }
            }
        });
    }
    // The writable folders' sync (#72): the host connects once the start message mounted them.
    // Bound here, before php-fpm starts, and below 1024: no other process can take the port.
    let sync = Vsock::listen(crate::sync::SYNC_PORT)?;
    if DRAIN.get().is_none() {
        let _ = DRAIN.set(crate::sync::Drain::new()?);
    }
    let drain: &'static crate::sync::Drain = DRAIN.get().ok_or_else(|| io::Error::other("the folder sync's state"))?;
    thread::spawn(move || {
        loop {
            let Ok((conn, cid)) = sync.accept() else { continue };
            if cid != HOST_CID {
                say(&format!("sync: refused a connection from CID {cid}"));
                continue;
            }
            let mounts = WRITABLE.lock().unwrap_or_else(|p| p.into_inner()).clone();
            if mounts.is_empty() {
                continue;
            }
            let (Ok(r), Ok(w)) = (vsock::Half::dup(&conn), vsock::Half::dup(&conn)) else { continue };
            let hangup = conn.as_raw_fd();
            let r = BufReader::with_capacity(64 << 10, r);
            if let Err(e) = crate::sync::serve_guest(&mounts, r, w, hangup, drain, &|m| report(&format!("sync: {m}"))) {
                report(&format!("sync: the connection to the host ended: {e}"));
            }
            drop(conn);
        }
    });
    let ctl = Vsock::listen(CTL_PORT)?;
    thread::spawn(move || {
        loop {
            // A thread per connection: a sync must never wait behind a reload. At most a few at
            // once (only the host can connect, and it sends one at a time per purpose).
            if let Ok((c, cid)) = ctl.accept() {
                if CTL_BUSY.fetch_add(1, Ordering::SeqCst) >= 4 {
                    CTL_BUSY.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }
                thread::spawn(move || {
                    serve_ctl(c, cid);
                    CTL_BUSY.fetch_sub(1, Ordering::SeqCst);
                });
            }
        }
    });
    Ok(())
}

/// php-fpm's config with the `www` pool's user and group set to numbers (php-fpm takes ids).
pub fn pool_conf(uid: u32, gid: u32) -> String {
    format!("[global]\ninclude=/usr/local/etc/php-fpm.conf\n[www]\nuser = {uid}\ngroup = {gid}\n")
}

fn start_php_fpm(boot: &Boot) -> io::Result<u32> {
    let mut fds = [0; 2];
    // SAFETY: pipe2(2) fills the two-element array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both fds were just returned by pipe2(2) and are owned from here.
    let (read, write) = unsafe { (fs::File::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let mut cmd = Command::new("php-fpm");
    cmd.arg("-F");
    if let Some((uid, gid)) = boot.user {
        // The image's php-fpm.conf, then the pool's user and group as the host's pool user's.
        let conf = "/run/securecore-php-fpm.conf";
        fs::write(conf, pool_conf(uid, gid))?;
        cmd.arg("-y").arg(conf);
    }
    // Exactly this environment: nothing of init's own.
    cmd.env_clear()
        .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        .envs(boot.env_names.iter().map(|n| (n.clone(), NOT_DELIVERED.to_owned())))
        .envs(delivered_env())
        .stdin(Stdio::null())
        .stdout(Stdio::from(write.try_clone()?))
        .stderr(Stdio::from(write));
    if !boot.ports.is_empty() || !boot.egress.is_empty() {
        let list = |p: &[u16]| p.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
        cmd.env("LD_PRELOAD", PRELOAD).env("SC_VSOCK_PORTS", list(&boot.ports));
        if !boot.egress.is_empty() {
            cmd.env("SC_EGRESS_PORTS", list(&boot.egress)).env("SC_EGRESS_HOST_PORT", crate::egress::EGRESS_PORT.to_string());
        }
    }
    // The image's ini folder, then the site's settings when it has any (#90).
    let base = if boot.ext { IMAGE_INI } else { NOEXT_INI };
    if Path::new(&format!("{SITE_INI_DIR}/zz-site.ini")).exists() {
        cmd.env("PHP_INI_SCAN_DIR", format!("{base}:{SITE_INI_DIR}"));
    } else if !boot.ext {
        cmd.env("PHP_INI_SCAN_DIR", NOEXT_INI);
    }
    // php-fpm and every worker under no_new_privs (#80): no exec ever gains privileges (a setuid
    // file, file capabilities), whatever the image or a writable disk holds. The master keeps
    // what it has (root, to switch to the pool user); a worker can't get root back.
    // SAFETY: prctl(2) only, between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().map_err(|e| io::Error::new(e.kind(), format!("php-fpm: {e}")))?;
    drop(cmd);
    let pump = thread::spawn(move || pump_log(read));
    let mut pumps = PUMPS.lock().unwrap_or_else(|p| p.into_inner());
    // An earlier master's pump ends with its output (a reload).
    pumps.retain(|(_, p)| !p.is_finished());
    pumps.push((child.id() as i32, pump));
    Ok(child.id())
}

/// The standard `/dev` links ([`boot_guest`]).
pub const STD_LINKS: [(&str, &str); 4] =
    [("/dev/fd", "/proc/self/fd"), ("/dev/stdin", "/proc/self/fd/0"), ("/dev/stdout", "/proc/self/fd/1"), ("/dev/stderr", "/proc/self/fd/2")];

fn boot_guest() -> io::Result<u32> {
    let flags = libc::MS_NOSUID | libc::MS_NODEV;
    // The root image read-only, nosuid and nodev (#80): the kernel mounts it ro from the command
    // line, which can't say nosuid; a bind remount sets the mount's flags and nothing else.
    mount("", "/", "", libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | flags, "")?;
    mount("proc", "/proc", "proc", flags | libc::MS_NOEXEC, "")?;
    mount("sysfs", "/sys", "sysfs", flags | libc::MS_NOEXEC, "")?;
    mount("devtmpfs", "/dev", "devtmpfs", libc::MS_NOSUID, "")?;
    // The links udev makes on a normal system and devtmpfs doesn't (#87): the image's php.ini has
    // `error_log = /dev/stderr`, and without the link every PHP error that isn't a request's
    // (the extension refusing to start at MINIT among them) went nowhere.
    for (link, to) in STD_LINKS {
        if let Err(e) = std::os::unix::fs::symlink(to, link)
            && e.kind() != io::ErrorKind::AlreadyExists
        {
            return Err(io::Error::new(e.kind(), format!("{link}: {e}")));
        }
    }
    // noexec: nothing a site writes there runs (#86 review).
    mount("tmpfs", "/tmp", "tmpfs", flags | libc::MS_NOEXEC, "mode=1777")?;
    mount("tmpfs", "/run", "tmpfs", flags, "mode=755")?;
    // The host's log first: whatever fails from here on can be said there (#87).
    start_log();
    let boot = parse_cmdline(&fs::read_to_string("/proc/cmdline")?).map_err(io::Error::other)?;
    if let Some(t) = boot.time {
        set_clock(t, 0)?;
    }
    // noexec too: php-fpm reads the site's PHP, nothing on the site disk ever runs as a program.
    mount("/dev/vdb", &boot.root, "ext4", libc::MS_RDONLY | flags | libc::MS_NOEXEC, "noload")?;
    loopback_up()?;
    // The folder sync watches every folder of the writable disks (8192 by default here).
    let _ = fs::write("/proc/sys/fs/inotify/max_user_watches", "65536");
    // A write to a writable disk is on the host's image (out of guest RAM, so a killed
    // Firecracker can't lose it) within about a second, whether or not the host's sync keeps up:
    // dirty pages older than 1 s are written every 0.5 s, and ext4 commits every second
    // (`commit=1` on the mount). The defaults are 30 s and 5 s.
    fs::write("/proc/sys/vm/dirty_expire_centisecs", "100")?;
    fs::write("/proc/sys/vm/dirty_writeback_centisecs", "50")?;
    listen_forwards(&boot)?;
    let pid = start_php_fpm(&boot)?;
    FPM_MASTER.store(pid as i32, Ordering::SeqCst);
    thread::spawn(watch_space);
    let uptime = fs::read_to_string("/proc/uptime").unwrap_or_default();
    say(&format!(
        "php-fpm started (pid {pid}), root {}, forwarded ports {:?}, ext {}, up {}s",
        boot.root,
        boot.ports,
        u8::from(boot.ext),
        uptime.split_whitespace().next().unwrap_or("?")
    ));
    let _ = BOOT.set(boot);
    Ok(pid)
}

/// PID 1: boots the guest, then reaps every process until php-fpm exits. Returning ends PID 1,
/// which panics the kernel, and `panic=1 reboot=k` stops the VM: no php-fpm, no VM.
pub fn init() -> io::Error {
    if let Err(e) = boot_guest() {
        // The host's log may be up (it is started first): the reason goes there too.
        report(&format!("the guest's boot failed: {e}; stopping the VM"));
        let _ = LOG.drain(LAST_WORDS_WAIT);
        return e;
    }
    loop {
        let mut status = 0;
        // SAFETY: waitpid(2) for any child, writing the status passed.
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        // The current master only: a reload's old master exits on purpose.
        if pid > 0 && pid == FPM_MASTER.load(Ordering::SeqCst) {
            return io::Error::other(explain_exit(pid, status, STARTED.load(Ordering::SeqCst)));
        }
        if pid < 0 {
            thread::sleep(Duration::from_millis(100));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_line_carries_the_root_ports_and_sockets() {
        let b = parse_cmdline(
            "console=ttyS0 reboot=k panic=1 init=/sbin/securecore-init sc.time=1762800000 sc.root=/var/www/html \
             sc.ports=3306,6379 sc.sock=3306:/run/mysqld/mysqld.sock",
        )
        .expect("parses");
        assert_eq!(b.time, Some(1_762_800_000));
        assert_eq!(b.root, "/var/www/html");
        assert_eq!(b.ports, [3306, 6379]);
        assert_eq!(b.socks, [(3306, "/run/mysqld/mysqld.sock".to_owned())]);
        assert!(b.ext, "the extension is on unless sc.ext=0");
        assert!(!parse_cmdline("sc.root=/srv sc.ext=0").expect("parses").ext);
        assert!(parse_cmdline("sc.ports=3306").is_err(), "no root: refused");
        assert_eq!(parse_cmdline("sc.root=/srv sc.user=1234:1235").expect("parses").user, Some((1234, 1235)));
        assert!(parse_cmdline("sc.root=/srv sc.user=0:0").is_err(), "the pool never runs as root");
        let conf = pool_conf(1234, 1235);
        assert!(conf.starts_with("[global]\ninclude=/usr/local/etc/php-fpm.conf\n") && conf.ends_with("[www]\nuser = 1234\ngroup = 1235\n"), "{conf}");
        assert!(parse_cmdline("sc.root=/srv sc.ports=99999").is_err());
        assert_eq!(parse_cmdline("sc.root=/srv sc.egress=443,8443").expect("parses").egress, [443, 8443]);
        assert!(parse_cmdline("sc.root=/srv sc.egress=x").is_err());
        assert_eq!(parse_cmdline("sc.root=/srv sc.env=A_1,B").expect("parses").env_names, ["A_1", "B"]);
        assert!(parse_cmdline("sc.root=/srv sc.env=A=b").is_err(), "names only, never a value");
    }

    #[test]
    fn start_message_lines_round_trip() {
        for ctl in [
            Ctl::Time { secs: 1_762_800_000, nanos: 123_456_789 },
            Ctl::Mount { device: "/dev/vdc".into(), path: "/var/www/html/wp-content/uploads".into() },
            Ctl::Tmpfs { path: "/var/cache/x".into() },
            Ctl::Entropy { hex: "ab".repeat(64) },
            Ctl::Env { name: "WORDPRESS_DB_PASSWORD".into(), hex: hex_of(b"p a$$ w\nd") },
            Ctl::Env { name: "EMPTY".into(), hex: String::new() },
            Ctl::Refresh,
            Ctl::Sync,
            Ctl::Reload,
            Ctl::Config { hex: hex_of(br#"{"layer1":{}}"#) },
            Ctl::Ini { hex: hex_of(b"securecore.debug_attribution_log = both\n") },
            Ctl::Ini { hex: String::new() },
            Ctl::Done,
        ] {
            assert_eq!(Ctl::parse(ctl.line().trim_end()), Ok(ctl.clone()), "{ctl:?}");
        }
        assert!(Ctl::parse("time 1 1000000000").is_err(), "nanoseconds below one second");
        assert!(Ctl::parse("reboot").is_err());
        assert!(Ctl::parse(&format!("entropy {}", "ab".repeat(8))).is_err(), "64 bytes, no fewer");
        assert!(Ctl::parse(&format!("entropy {}", "zz".repeat(64))).is_err(), "hex only");
        assert_eq!(unhex("00ff10"), [0, 255, 16]);
        assert!(Ctl::Env { name: "X".into(), hex: String::new() }.starts(), "part of the start message");
        for bad in ["env 1X 5ec7e7", "env X-Y 5ec7e7", "env X 5ec7e", "env X 5ec7e7zz", "env"] {
            let e = Ctl::parse(bad).expect_err(bad);
            assert!(!e.contains("5ec7e"), "a refused env line's value is never echoed (it may be a secret): {e}");
        }
        let long = format!("env X {}", "00".repeat(MAX_ENV_VALUE + 1));
        assert!(Ctl::parse(&long).is_err(), "a value over the cap");
    }

    /// Two reloads at once (two USR2s close together on the host): the second waits for the
    /// first, then stops the master the first started; neither ever sees the 0 in between.
    #[test]
    fn reloads_run_one_at_a_time_and_never_signal_pid_0() {
        static MASTER: AtomicI32 = AtomicI32::new(100);
        static NEXT: AtomicI32 = AtomicI32::new(101);
        static BUSY: AtomicBool = AtomicBool::new(false);
        let stopped = Mutex::new(Vec::new());
        thread::scope(|s| {
            for _ in 0..2 {
                s.spawn(|| {
                    reload(
                        &MASTER,
                        |old| {
                            assert!(!BUSY.swap(true, Ordering::SeqCst), "two reloads overlapped");
                            stopped.lock().expect("lock").push(old);
                            thread::sleep(Duration::from_millis(50));
                        },
                        || {
                            thread::sleep(Duration::from_millis(50));
                            BUSY.store(false, Ordering::SeqCst);
                            Ok(NEXT.fetch_add(1, Ordering::SeqCst))
                        },
                    )
                    .expect("reload");
                });
            }
        });
        assert_eq!(*stopped.lock().expect("lock"), [100, 101], "each reload stopped the master before it");
        assert_eq!(MASTER.load(Ordering::SeqCst), 102);
        // kill(0, …) is init's process group and kill(-1, …) every process: never.
        assert!(signal(0, 0).is_err() && signal(-1, 0).is_err());
        signal(std::process::id() as i32, 0).expect("a real pid");
    }

    /// php-fpm's exit, as init reports it before the VM stops (#87).
    #[test]
    fn a_wait_status_says_the_exit_code_or_the_signal() {
        assert_eq!(wait_status(78 << 8), "exit code 78");
        assert_eq!(wait_status(9), "killed by signal 9");
        assert_eq!(wait_status(0), "exit code 0");
    }

    #[test]
    fn a_boot_takes_one_start_message_then_only_sync_and_reload() {
        let start = [Ctl::Time { secs: 1, nanos: 0 }, Ctl::Entropy { hex: "00".repeat(64) }, Ctl::Mount { device: "/dev/vdc".into(), path: "/u".into() }];
        assert_eq!(allowed(&start, false), Ok(()), "the first start message");
        assert!(allowed(&start, true).expect_err("a second").contains("already taken"));
        assert!(allowed(&[Ctl::Mount { device: "/dev/vdd".into(), path: "/x".into() }], true).is_err(), "no mounts after the start");
        assert_eq!(allowed(&[Ctl::Sync], true), Ok(()));
        assert_eq!(allowed(&[Ctl::Reload], true), Ok(()));
        assert!(allowed(&[Ctl::Sync], false).is_err(), "nothing before the start");
        // The log key (#86 review): at any time, alone, and never echoed when malformed.
        let key = Ctl::LogKey { hex: "ab".repeat(crate::guestlog::KEY_LEN) };
        assert_eq!(Ctl::parse(key.line().trim_end()), Ok(key.clone()));
        assert_eq!(allowed(std::slice::from_ref(&key), false), Ok(()));
        assert_eq!(allowed(std::slice::from_ref(&key), true), Ok(()));
        assert!(allowed(&[key, Ctl::Sync], true).is_err(), "alone on its connection");
        let e = Ctl::parse(&format!("logkey {}", "5ec7".repeat(8))).expect_err("short");
        assert!(!e.contains("5ec7"), "{e}");
        assert!(allowed(&[Ctl::Time { secs: 1, nanos: 0 }, Ctl::Reload], false).is_err());
        // #90: a config only after the start; the site's ini in the start message or after it.
        let config = Ctl::Config { hex: hex_of(b"{}") };
        let ini = Ctl::Ini { hex: String::new() };
        assert_eq!(allowed(std::slice::from_ref(&config), true), Ok(()));
        assert!(allowed(std::slice::from_ref(&config), false).is_err(), "no config before the start");
        assert!(allowed(&[Ctl::Time { secs: 1, nanos: 0 }, config], false).is_err(), "nor in the start message");
        assert_eq!(allowed(&[Ctl::Time { secs: 1, nanos: 0 }, ini.clone()], false), Ok(()));
        assert_eq!(allowed(std::slice::from_ref(&ini), true), Ok(()));
        assert!(allowed(&[ini], false).is_err(), "nothing but the start message before it");
    }

    /// A site's php.ini in the guest (#90): the extension's debug settings only.
    #[test]
    fn a_sites_ini_carries_only_the_debug_settings() {
        assert_eq!(
            site_ini("; comment\n\nsecurecore.debug_attribution_log=both\n  securecore.debug_attribution_rule = frame \n").as_deref(),
            Ok("securecore.debug_attribution_log = both\nsecurecore.debug_attribution_rule = frame\n")
        );
        assert_eq!(site_ini("").as_deref(), Ok(""));
        for bad in ["securecore.config = /etc/x.json", "extension = evil.so", "memory_limit = 1G", "securecore.debug_ = x", "securecore.debug_attribution_log"] {
            assert!(site_ini(bad).is_err(), "{bad}");
        }
        assert!(site_ini("securecore.debug_attribution_log = a\u{7}b").is_err());
        // #90 review: values are plain words (PHP expands ${VAR} from php-fpm's environment,
        // where the vault's secrets are), and a refusal never quotes the file.
        for bad in [
            "securecore.debug_attribution_log = ${WORDPRESS_DB_PASSWORD}",
            "securecore.debug_attribution_log = \"both\"",
            "securecore.debug_attribution_log = {x}",
            "securecore.debug_attribution_log = Both",
            "securecore.debug_attribution_log = $SECRET",
        ] {
            let e = site_ini(bad).expect_err(bad);
            assert!(!e.contains("WORDPRESS") && !e.contains("SECRET") && !e.contains("both") && !e.contains("Both"), "{e}");
        }
        for bad in ["sk_live_SECRET = 1", "SECRET-NO-EQUALS"] {
            let e = site_ini(bad).expect_err(bad);
            assert!(!e.contains("SECRET") && !e.contains("sk_live"), "a refused line is never quoted: {e}");
        }
        assert_eq!(site_ini("securecore.debug_db_attribution = component").as_deref(), Ok("securecore.debug_db_attribution = component\n"));
    }

    /// #90 review: the config is mounted on `<root>/securecore.json` only when that is a regular
    /// file itself, never through a link the site disk holds.
    #[test]
    fn a_mount_target_must_be_a_regular_file_not_a_link() {
        let dir = std::env::temp_dir().join(format!("sc-guest-target-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("securecore.json");
        fs::write(&file, "{}").expect("write");
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&file, &link).expect("link");
        assert!(regular_target(file.to_str().expect("utf8")).is_ok());
        let e = regular_target(link.to_str().expect("utf8")).expect_err("a link");
        assert!(e.to_string().contains("not a regular file"), "{e}");
        assert!(regular_target(dir.to_str().expect("utf8")).is_err(), "a folder");
        let _ = fs::remove_dir_all(&dir);
    }
}
