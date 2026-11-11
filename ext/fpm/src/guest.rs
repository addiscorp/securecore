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
    /// Mount an ext4 disk read-write at a path.
    Mount { device: String, path: String },
    /// Mount a tmpfs at a path (a writable folder outside the app root).
    Tmpfs { path: String },
    /// Write every dirty page to the disks: the host sends it before it stops the VM, so what
    /// php-fpm wrote to a writable folder is on the host's disk image.
    Sync,
    Done,
}

impl Ctl {
    pub fn line(&self) -> String {
        match self {
            Ctl::Time { secs, nanos } => format!("time {secs} {nanos}\n"),
            Ctl::Mount { device, path } => format!("mount {device} {path}\n"),
            Ctl::Tmpfs { path } => format!("tmpfs {path}\n"),
            Ctl::Sync => "sync\n".into(),
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
            ["mount", device, path] => Ok(Ctl::Mount { device: (*device).into(), path: (*path).into() }),
            ["tmpfs", path] => Ok(Ctl::Tmpfs { path: (*path).into() }),
            ["sync"] => Ok(Ctl::Sync),
            ["done"] => Ok(Ctl::Done),
            _ => Err(format!("unknown start message line {line:?}")),
        }
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

/// Applies one start message line.
fn apply(ctl: &Ctl) -> io::Result<()> {
    match ctl {
        Ctl::Time { secs, nanos } => set_clock(*secs, *nanos),
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
            mount(device, path, "ext4", libc::MS_NOSUID | libc::MS_NODEV, "")
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

/// One start message: every line applied in order, then `ok` (or the first error) to `done`.
fn serve_ctl(conn: Vsock) {
    let mut out = match vsock::Half::dup(&conn) {
        Ok(out) => out,
        Err(e) => return say(&format!("ctl: {e}")),
    };
    let mut failed: Option<String> = None;
    for line in BufReader::new(conn).lines() {
        let Ok(line) = line else { break };
        let ctl = Ctl::parse(&line);
        match ctl {
            Ok(Ctl::Done) => {
                let reply = failed.take().map_or_else(|| "ok\n".to_owned(), |e| format!("error {e}\n"));
                let _ = out.write_all(reply.as_bytes());
                return;
            }
            Ok(ctl) if failed.is_none() => {
                if let Err(e) = apply(&ctl) {
                    failed = Some(e.to_string());
                }
            }
            Ok(_) => {}
            Err(e) => failed = failed.or(Some(e)),
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
            let Ok(v) = fpm.accept() else { continue };
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
            if let Ok(c) = ctl.accept() {
                serve_ctl(c);
            }
        }
    });
    Ok(())
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
    cmd.arg("-F")
        .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
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
    let uptime = fs::read_to_string("/proc/uptime").unwrap_or_default();
    say(&format!(
        "php-fpm started (pid {pid}), root {}, forwarded ports {:?}, ext {}, up {}s",
        boot.root,
        boot.ports,
        u8::from(boot.ext),
        uptime.split_whitespace().next().unwrap_or("?")
    ));
    Ok(pid)
}

/// PID 1: boots the guest, then reaps every process until php-fpm exits. Returning ends PID 1,
/// which panics the kernel, and `panic=1 reboot=k` stops the VM: no php-fpm, no VM.
pub fn init() -> io::Error {
    let fpm = match boot_guest() {
        Ok(pid) => pid as libc::pid_t,
        Err(e) => return e,
    };
    loop {
        let mut status = 0;
        // SAFETY: waitpid(2) for any child, writing the status passed.
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid == fpm {
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
        assert!(parse_cmdline("sc.root=/srv sc.ports=99999").is_err());
    }

    #[test]
    fn start_message_lines_round_trip() {
        for ctl in [
            Ctl::Time { secs: 1_762_800_000, nanos: 123_456_789 },
            Ctl::Mount { device: "/dev/vdc".into(), path: "/var/www/html/wp-content/uploads".into() },
            Ctl::Tmpfs { path: "/var/cache/x".into() },
            Ctl::Sync,
            Ctl::Done,
        ] {
            assert_eq!(Ctl::parse(ctl.line().trim_end()), Ok(ctl.clone()), "{ctl:?}");
        }
        assert!(Ctl::parse("time 1 1000000000").is_err(), "nanoseconds below one second");
        assert!(Ctl::parse("reboot").is_err());
    }
}
