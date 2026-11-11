//! PID 1 in the microVM guest (addiscorp/securecore#71): `securecore-fpm` run as
//! `/sbin/securecore-init`. It replaces the spike's `init.sh` and its socat processes. The guest
//! has no network device, only loopback and vsock:
//!
//! ```text
//!   in    vsock 9000 → 127.0.0.1:9000 → php-fpm (FastCGI from the host driver)
//!   out   php-fpm's connect to 127.0.0.1:<port> is a vsock connect to the host on that port
//!         (libsc-vsock-connect.so, #70), for each port the host forwards (sc.ports); a unix
//!         socket under /run (sc.sock) reaches the same port through a forwarder here
//!   log   php-fpm's stdout and stderr → vsock host:1514 (the serial console is too slow)
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
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixListener;
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
/// `KEY=VALUE` lines php-fpm gets as its environment, when the root image has the file. The
/// test images carry the stack's database settings here; a product image must not carry
/// secrets (delivering them per site is addiscorp/securecore#72).
pub const ENV_FILE: &str = "/etc/securecore/guest.env";
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
            "sc.sock" => {
                let (port, path) = value.split_once(':').ok_or_else(|| format!("sc.sock={value}: want PORT:PATH"))?;
                let port = port.parse().map_err(|_| format!("sc.sock: {port} is not a port"))?;
                boot.socks.push((port, path.to_owned()));
            }
            "sc.ext" => boot.ext = value != "0",
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
    Done,
}

impl Ctl {
    pub fn line(&self) -> String {
        match self {
            Ctl::Time { secs, nanos } => format!("time {secs} {nanos}\n"),
            Ctl::Entropy { hex } => format!("entropy {hex}\n"),
            Ctl::Refresh => "refresh\n".into(),
            Ctl::Mount { device, path } => format!("mount {device} {path}\n"),
            Ctl::Tmpfs { path } => format!("tmpfs {path}\n"),
            Ctl::Sync => "sync\n".into(),
            Ctl::Reload => "reload\n".into(),
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
            ["refresh"] => Ok(Ctl::Refresh),
            ["mount", device, path] => Ok(Ctl::Mount { device: (*device).into(), path: (*path).into() }),
            ["tmpfs", path] => Ok(Ctl::Tmpfs { path: (*path).into() }),
            ["sync"] => Ok(Ctl::Sync),
            ["reload"] => Ok(Ctl::Reload),
            ["done"] => Ok(Ctl::Done),
            _ => Err(format!("unknown control line {line:?}")),
        }
    }

    /// Part of the one start message a boot accepts (the rest may come any time after it).
    pub fn starts(&self) -> bool {
        matches!(self, Ctl::Time { .. } | Ctl::Entropy { .. } | Ctl::Refresh | Ctl::Mount { .. } | Ctl::Tmpfs { .. })
    }
}

/// What a control connection may do, given whether this boot's start message was taken.
/// Exactly one start message per boot (a snapshot is taken before it, so each restore takes its
/// own); after it only `sync` and `reload`, and nothing at all before it but a start.
pub fn allowed(lines: &[Ctl], started: bool) -> Result<(), String> {
    let starts = lines.iter().any(Ctl::starts);
    let others = lines.iter().any(|c| matches!(c, Ctl::Sync | Ctl::Reload));
    match (started, starts, others) {
        (true, true, _) => Err("this boot's start message was already taken".into()),
        (false, false, true) => Err("nothing but the start message before the start message".into()),
        (false, true, true) => Err("a start message carries no sync or reload".into()),
        _ => Ok(()),
    }
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
/// The writable disks' mount points, watched for space.
static WRITABLE: Mutex<Vec<String>> = Mutex::new(Vec::new());

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

/// Applies one control line.
fn apply(ctl: &Ctl) -> io::Result<()> {
    match ctl {
        Ctl::Time { secs, nanos } => set_clock(*secs, *nanos),
        Ctl::Entropy { hex } => add_entropy(&unhex(hex)),
        Ctl::Refresh => {
            // A graceful stop of each worker; the master forks fresh ones from itself (it ran no
            // request before the snapshot), and opcache's shared memory stays warm.
            for pid in pool_workers(FPM_MASTER.load(Ordering::SeqCst)) {
                // SAFETY: kill(2) on a php-fpm worker of this guest.
                unsafe { libc::kill(pid, libc::SIGQUIT) };
            }
            Ok(())
        }
        Ctl::Reload => {
            // Not php-fpm's own SIGUSR2: that re-execs the master with its current environment,
            // where the vault has already put placeholders in place of the secrets. A graceful
            // stop (SIGQUIT: in-flight requests finish), then a fresh php-fpm with init's own
            // environment, as at boot.
            let boot = BOOT.get().ok_or_else(|| io::Error::other("no boot settings"))?;
            let old = FPM_MASTER.swap(0, Ordering::SeqCst);
            // SAFETY: kill(2) on php-fpm's master, which this init started.
            unsafe { libc::kill(old, libc::SIGQUIT) };
            let t = std::time::Instant::now();
            while Path::new(&format!("/proc/{old}")).exists() {
                if t.elapsed() > RELOAD_GRACE {
                    // SAFETY: as above; it didn't stop gracefully in time.
                    unsafe { libc::kill(old, libc::SIGKILL) };
                }
                thread::sleep(Duration::from_millis(10));
            }
            let pid = start_php_fpm(boot)?;
            FPM_MASTER.store(pid as i32, Ordering::SeqCst);
            Ok(())
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
            mount(device, path, "ext4", libc::MS_NOSUID | libc::MS_NODEV, "")?;
            WRITABLE.lock().unwrap_or_else(|p| p.into_inner()).push(path.clone());
            Ok(())
        }
        Ctl::Tmpfs { path } => mount("tmpfs", path, "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, "mode=1777"),
        Ctl::Sync => {
            // SAFETY: sync(2) takes nothing and can't fail.
            unsafe { libc::sync() };
            Ok(())
        }
        Ctl::Done => Ok(()),
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
    let started = STARTED.load(Ordering::SeqCst);
    if failed.is_none() {
        failed = allowed(&lines, started).err();
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
    let reply = failed.map_or_else(|| "ok\n".to_owned(), |e| format!("error {e}\n"));
    let _ = out.write_all(reply.as_bytes());
}

/// One line to the host's log, from this init (the host marks every guest line as the guest's).
fn report(message: &str) {
    if let Ok(mut c) = Vsock::connect(HOST_CID, LOG_PORT) {
        let _ = c.write_all(format!("securecore-init: {message}\n").as_bytes());
    }
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

/// php-fpm's output to the host, reconnecting when the connection breaks (every restore
/// resets the guest's vsock connections).
fn pump_log(mut from: fs::File) {
    let mut conn: Option<Vsock> = None;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        for _ in 0..50 {
            if conn.is_none() {
                conn = Vsock::connect(HOST_CID, LOG_PORT).ok();
            }
            match conn.as_mut().map(|c| c.write_all(&buf[..n])) {
                Some(Ok(())) => break,
                _ => {
                    conn = None;
                    thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }
}

fn say(message: &str) {
    // The console: the serial port, read on the host as console.log.
    println!("securecore-init: {message}");
}

fn env_file() -> Vec<(String, String)> {
    let Ok(text) = fs::read_to_string(ENV_FILE) else { return Vec::new() };
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
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
    cmd.env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        .envs(env_file())
        .stdin(Stdio::null())
        .stdout(Stdio::from(write.try_clone()?))
        .stderr(Stdio::from(write));
    if !boot.ports.is_empty() {
        let ports: Vec<String> = boot.ports.iter().map(u16::to_string).collect();
        cmd.env("LD_PRELOAD", PRELOAD).env("SC_VSOCK_PORTS", ports.join(","));
    }
    if !boot.ext {
        cmd.env("PHP_INI_SCAN_DIR", NOEXT_INI);
    }
    let child = cmd.spawn().map_err(|e| io::Error::new(e.kind(), format!("php-fpm: {e}")))?;
    drop(cmd);
    thread::spawn(move || pump_log(read));
    Ok(child.id())
}

fn boot_guest() -> io::Result<u32> {
    let flags = libc::MS_NOSUID | libc::MS_NODEV;
    mount("proc", "/proc", "proc", flags | libc::MS_NOEXEC, "")?;
    mount("sysfs", "/sys", "sysfs", flags | libc::MS_NOEXEC, "")?;
    mount("devtmpfs", "/dev", "devtmpfs", libc::MS_NOSUID, "")?;
    mount("tmpfs", "/tmp", "tmpfs", flags, "mode=1777")?;
    mount("tmpfs", "/run", "tmpfs", flags, "mode=755")?;
    let boot = parse_cmdline(&fs::read_to_string("/proc/cmdline")?).map_err(io::Error::other)?;
    if let Some(t) = boot.time {
        set_clock(t, 0)?;
    }
    mount("/dev/vdb", &boot.root, "ext4", libc::MS_RDONLY | flags, "noload")?;
    loopback_up()?;
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
        return e;
    }
    loop {
        let mut status = 0;
        // SAFETY: waitpid(2) for any child, writing the status passed.
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        // The current master only: a reload's old master exits on purpose.
        if pid > 0 && pid == FPM_MASTER.load(Ordering::SeqCst) {
            return io::Error::other(format!("php-fpm exited (wait status {status})"));
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
    }

    #[test]
    fn start_message_lines_round_trip() {
        for ctl in [
            Ctl::Time { secs: 1_762_800_000, nanos: 123_456_789 },
            Ctl::Mount { device: "/dev/vdc".into(), path: "/var/www/html/wp-content/uploads".into() },
            Ctl::Tmpfs { path: "/var/cache/x".into() },
            Ctl::Entropy { hex: "ab".repeat(64) },
            Ctl::Refresh,
            Ctl::Sync,
            Ctl::Reload,
            Ctl::Done,
        ] {
            assert_eq!(Ctl::parse(ctl.line().trim_end()), Ok(ctl.clone()), "{ctl:?}");
        }
        assert!(Ctl::parse("time 1 1000000000").is_err(), "nanoseconds below one second");
        assert!(Ctl::parse("reboot").is_err());
        assert!(Ctl::parse(&format!("entropy {}", "ab".repeat(8))).is_err(), "64 bytes, no fewer");
        assert!(Ctl::parse(&format!("entropy {}", "zz".repeat(64))).is_err(), "hex only");
        assert_eq!(unhex("00ff10"), [0, 255, 16]);
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
        assert!(allowed(&[Ctl::Time { secs: 1, nanos: 0 }, Ctl::Reload], false).is_err());
    }
}
