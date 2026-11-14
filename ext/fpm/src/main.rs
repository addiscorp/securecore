//! `securecore-fpm --config <securecore.json> [options] [--] [php-fpm args…]`
//!
//! Reads `layer1` from the file and starts php-fpm inside what `layer1.isolation` picks
//! (addiscorp/securecore#71):
//! - **gelada**: applies `layer1` to itself as a gelada sandbox and execs php-fpm (`php-fpm` on
//!   `PATH` unless `--php-fpm` names another) with the remaining arguments, so the whole of
//!   php-fpm, master and workers, runs inside it.
//! - **microvm**: boots the guest's php-fpm in a jailed Firecracker microVM and stays in the
//!   foreground as its only way in and out, until SIGTERM/SIGINT/SIGQUIT (see `vm.rs`).
//! - **auto** (the default): the microVM where this host can run it for this config, and gelada
//!   otherwise, with one log line saying why ([`securecore_fpm::AUTO_SELECTS_MICROVM`]).
//! - layer 1 off: execs php-fpm as it is and says so.
//!
//! Fails closed: an invalid file, a layer 1 it can't enforce, `microvm` where the microVM
//! can't run, or a sandbox the kernel won't apply exits 125 with the reason on stderr, and
//! php-fpm never runs.
//!
//! Run as `/sbin/securecore-init` (a link in the guest image), it is PID 1 in the guest.

use std::ffi::OsString;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use securecore_fpm::{Choice, FAILED, choose, plan};

const USAGE: &str = "usage: securecore-fpm --config <securecore.json> [--php-fpm <program>] \
[--vm-dir <dir>] [--vm-user <name>|<uid>:<gid>] [--pool-user <name>|<uid>:<gid>] [--kvm <device>] [--state-dir <dir>] \
[--listen unix:<path>|<host>:<port>] [--listen-owner <user>] [--listen-group <group>] [--listen-mode <octal>] \
[--guest-root <path>] [--mem <MiB>] [--vcpus <n>] [--write-disk-mib <MiB>] [--no-snapshot] \
[--guest-arg <word>]... [--guest-env <NAME>]... [--guest-ini <file>] [--php-root <dir>] [--pool <name>] \
[--unpackaged-record <file>] [--db-user <name>|<uid>] [--db-address <host:port>] [--db-socket <path>] [--pools-ready-within <s>] [--start-within <s>] [--space-ledger <file>] [--] [php-fpm args...] \
| securecore-fpm --migrate-config <securecore.json>";

struct Args {
    config: PathBuf,
    php_fpm: OsString,
    vm_dir: PathBuf,
    vm_user: String,
    pool_user: Option<String>,
    kvm: PathBuf,
    state_dir: Option<PathBuf>,
    listen: Option<String>,
    listen_owner: Option<String>,
    listen_group: Option<String>,
    listen_mode: u32,
    guest_root: Option<String>,
    /// `None`: sized from the pool and the host (#100 re-review).
    mem: Option<u32>,
    vcpus: Option<u32>,
    /// How long a microVM start may take, in seconds.
    start_within: u32,
    space_ledger: PathBuf,
    write_disk_mib: u64,
    snapshot: bool,
    guest_args: Vec<String>,
    guest_env: Vec<String>,
    guest_ini: Option<PathBuf>,
    /// Where the host's PHP is, for the microVM's capture (#101): `/`.
    php_root: PathBuf,
    /// The one pool this launcher runs as a microVM (the launcher passes it to its own children
    /// for a php-fpm with several pools).
    pool: Option<String>,
    /// The install's record of the unpackaged files' sha256s (#101).
    record: PathBuf,
    /// The database server's user, who may own the MySQL socket a bare 3306 reaches.
    db_user: String,
    /// Database targets the operator approves for a bare 3306 (root's configuration).
    db_address: Option<String>,
    db_socket: Option<PathBuf>,
    /// How long several pools' launchers get to all serve, in seconds.
    pools_within: u32,
    /// The launcher's own (`--gelada-fallback <line>`): `auto` fell back after a microVM start
    /// began (threads were started), and the launcher ran itself again to apply gelada in a
    /// process with one thread ([`relaunch`]). `<line>` is what it logs.
    gelada_fallback: Option<String>,
    rest: Vec<OsString>,
}

/// The launcher's flags come first; `--`, or the first argument that isn't one of them, starts
/// php-fpm's own (so `securecore-fpm --config f -F` passes `-F` on). `Ok(None)`: `--help`.
fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Option<Args>, String> {
    let mut args = args.into_iter().peekable();
    let mut a = Args {
        config: PathBuf::new(),
        php_fpm: OsString::from("php-fpm"),
        vm_dir: PathBuf::from("/usr/local/share/securecore/vm"),
        vm_user: "securecore-vm".into(),
        pool_user: None,
        kvm: PathBuf::from("/dev/kvm"),
        state_dir: None,
        listen: None,
        listen_owner: None,
        listen_group: None,
        listen_mode: 0o660,
        guest_root: None,
        mem: None,
        vcpus: None,
        start_within: 600,
        space_ledger: PathBuf::from("/var/lib/securecore/space.json"),
        write_disk_mib: 1024,
        snapshot: true,
        guest_args: Vec::new(),
        guest_env: Vec::new(),
        guest_ini: None,
        php_root: PathBuf::from("/"),
        pool: None,
        record: PathBuf::from("/var/lib/securecore/unpackaged.json"),
        db_user: "mysql".into(),
        db_address: None,
        db_socket: None,
        pools_within: 300,
        gelada_fallback: None,
        rest: Vec::new(),
    };
    let mut config = None;
    while let Some(arg) = args.peek() {
        let flag = arg.to_str().unwrap_or_default().to_owned();
        match flag.as_str() {
            "--" => {
                args.next();
                break;
            }
            "--help" => return Ok(None),
            "--no-snapshot" => {
                args.next();
                a.snapshot = false;
            }
            "--config" | "--php-fpm" | "--vm-dir" | "--vm-user" | "--pool-user" | "--kvm" | "--state-dir" | "--listen" | "--listen-owner"
            | "--listen-group" | "--listen-mode" | "--guest-root" | "--mem" | "--vcpus" | "--write-disk-mib" | "--guest-arg" | "--guest-env" | "--guest-ini"
            | "--php-root" | "--pool" | "--unpackaged-record" | "--db-user" | "--db-address" | "--db-socket" | "--pools-ready-within" | "--gelada-fallback" | "--start-within" | "--space-ledger" => {
                args.next();
                let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
                let text = || value.to_str().map(str::to_owned).ok_or_else(|| format!("{flag}: not UTF-8"));
                let number = || text()?.parse::<u32>().ok().filter(|n| *n > 0).ok_or_else(|| format!("{flag}: want a number"));
                match flag.as_str() {
                    "--config" => config = Some(PathBuf::from(&value)),
                    "--php-fpm" => a.php_fpm = value,
                    "--vm-dir" => a.vm_dir = PathBuf::from(&value),
                    "--vm-user" => a.vm_user = text()?,
                    "--pool-user" => a.pool_user = Some(text()?),
                    "--kvm" => a.kvm = PathBuf::from(&value),
                    "--state-dir" => a.state_dir = Some(PathBuf::from(&value)),
                    "--listen" => a.listen = Some(text()?),
                    "--listen-owner" => a.listen_owner = Some(text()?),
                    "--listen-group" => a.listen_group = Some(text()?),
                    "--listen-mode" => {
                        a.listen_mode = u32::from_str_radix(&text()?, 8)
                            .ok()
                            .filter(|m| *m <= 0o777)
                            .ok_or_else(|| format!("{flag}: want an octal mode such as 0660"))?;
                    }
                    "--guest-root" => a.guest_root = Some(text()?),
                    "--mem" => a.mem = Some(number()?),
                    "--vcpus" => a.vcpus = Some(number()?),
                    "--start-within" => a.start_within = number()?,
                    "--space-ledger" => a.space_ledger = PathBuf::from(&value),
                    "--write-disk-mib" => a.write_disk_mib = u64::from(number()?),
                    "--guest-env" => a.guest_env.push(text()?),
                    "--guest-ini" => a.guest_ini = Some(PathBuf::from(&value)),
                    "--php-root" => a.php_root = PathBuf::from(&value),
                    "--pool" => a.pool = Some(text()?),
                    "--unpackaged-record" => a.record = PathBuf::from(&value),
                    "--db-user" => a.db_user = text()?,
                    "--db-address" => a.db_address = Some(text()?),
                    "--db-socket" => a.db_socket = Some(PathBuf::from(&value)),
                    "--pools-ready-within" => a.pools_within = number()?,
                    "--gelada-fallback" => a.gelada_fallback = Some(text()?),
                    _ => a.guest_args.push(text()?),
                }
            }
            _ => break,
        }
    }
    a.config = config.ok_or("--config is required")?;
    a.rest = args.collect();
    Ok(Some(a))
}

/// The threads this process has (`/proc/self/task`; 1 where that can't be read).
fn threads() -> usize {
    std::fs::read_dir("/proc/self/task").map(|d| d.count()).unwrap_or(1).max(1)
}

/// gelada applies to the calling process only while it has one thread
/// ([`gelada::Sandbox::restrict_self`] refuses otherwise). A microVM start that was prepared or
/// begun has started threads (systemd's start-timeout extensions, the VM's sync and log), so when
/// `auto` then falls back, the launcher execs itself afresh, same pid, signals unblocked, with
/// the decision (`--gelada-fallback <line>`), and that process applies gelada (#100 review).
/// Returns only when the exec fails.
fn relaunch(argv: &[OsString], line: &str) -> ExitCode {
    #[cfg(target_os = "linux")]
    securecore_fpm::vm::unblock_signals();
    // This very binary, even when its path was replaced or removed meanwhile (an upgrade during
    // the start: current_exe() would name "… (deleted)").
    let mut cmd = Command::new("/proc/self/exe");
    if let Some(name) = argv.first() {
        cmd.arg0(name);
    }
    let err = cmd.arg("--gelada-fallback").arg(line).args(argv.iter().skip(1)).exec();
    failed(&format!("running the launcher again for gelada ({line}): {err}"))
}

/// A reason folded onto one line, as the choice's own reasons are.
fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn log(message: &str) {
    eprintln!("securecore-fpm: {message}");
}

fn failed(message: &str) -> ExitCode {
    log(&format!("{message}; refusing to start php-fpm"));
    ExitCode::from(FAILED)
}

#[cfg(target_os = "linux")]
mod microvm {
    use super::Args;
    use securecore_config::Loaded;
    use securecore_fpm::vm::{self, Assets, Listen, Options, SocketMode};
    use std::time::Instant;

    /// A user or group: a number, or a name looked up in the passwd / group database.
    fn id(spec: &str, group: bool) -> Result<u32, String> {
        if let Ok(n) = spec.parse::<u32>() {
            return Ok(n);
        }
        let name = std::ffi::CString::new(spec).map_err(|_| format!("{spec:?}: not a name"))?;
        // SAFETY: getgrnam(3)/getpwnam(3) with a NUL-terminated name; the static result is read
        // at once.
        unsafe {
            if group {
                let g = libc::getgrnam(name.as_ptr());
                if g.is_null() { Err(format!("no group {spec}")) } else { Ok((*g).gr_gid) }
            } else {
                let p = libc::getpwnam(name.as_ptr());
                if p.is_null() { Err(format!("no user {spec}")) } else { Ok((*p).pw_uid) }
            }
        }
    }

    pub fn options(a: &Args) -> Result<Options, String> {
        Ok(Options {
            assets: Assets::in_dir(&a.vm_dir),
            kvm: a.kvm.clone(),
            state: a.state_dir.clone(),
            listen: a.listen.as_deref().map(Listen::parse).transpose()?,
            listen_mode: SocketMode {
                owner: a.listen_owner.as_deref().map(|o| id(o, false)).transpose()?,
                group: a.listen_group.as_deref().map(|g| id(g, true)).transpose()?,
                mode: a.listen_mode,
            },
            guest_root: a.guest_root.clone(),
            mem_mib: a.mem,
            vcpus: a.vcpus,
            start_within: std::time::Duration::from_secs(u64::from(a.start_within)),
            space_ledger: a.space_ledger.clone(),
            write_disk_mib: a.write_disk_mib,
            vm_user: a.vm_user.clone(),
            pool_user: a.pool_user.clone(),
            snapshot: a.snapshot,
            guest_args: a.guest_args.clone(),
            guest_env: a.guest_env.clone(),
            guest_ini: a.guest_ini.clone(),
            php_root: a.php_root.clone(),
            php_fpm: a.php_fpm.to_string_lossy().into_owned(),
            fpm_args: a.rest.iter().map(|s| s.to_string_lossy().into_owned()).collect(),
            pool: a.pool.clone(),
            record: a.record.clone(),
            db_user: a.db_user.clone(),
            db_address: a.db_address.clone(),
            db_socket: a.db_socket.clone(),
        })
    }

    pub struct Ready(vm::Ready);

    /// How long a pool's launcher gets to stop after SIGTERM before it is killed.
    const STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

    pub fn stop_extending() {
        vm::stop_extending();
    }

    /// Everything before the boot (#100 review: before `auto` commits). Signals are blocked
    /// first, so no thread it starts can take a stop signal's default action.
    pub fn prepare(loaded: &Loaded, a: &Args) -> Result<Ready, String> {
        vm::block_signals();
        vm::extend_start_timeout(std::time::Duration::from_secs(u64::from(a.start_within)));
        vm::prepare_all(loaded, &options(a)?).map(Ready)
    }

    /// How a microVM start ended.
    pub enum Outcome {
        Done(Result<(), String>),
        /// It failed before it served anything: `auto` may still run gelada.
        Fallback(String),
    }

    pub fn run(loaded: &Loaded, a: &Args, ready: Ready, argv: &[std::ffi::OsString], t0: Instant) -> Outcome {
        let opts = match options(a) {
            Ok(o) => o,
            Err(e) => return Outcome::Done(Err(e)),
        };
        match ready.0 {
            vm::Ready::One(p) => match vm::run(loaded, &opts, *p, t0) {
                Ok(()) => Outcome::Done(Ok(())),
                Err(vm::RunError::BeforeServing(e)) => Outcome::Fallback(e),
                Err(vm::RunError::AfterServing(e)) => Outcome::Done(Err(e)),
            },
            vm::Ready::Pools(names) => pools(loaded, &opts, &names, argv, std::time::Duration::from_secs(u64::from(a.pools_within))),
        }
    }

    /// One VM per pool (#100 review): a launcher of its own for each, `--pool <name>` and the rest
    /// of this one's arguments, all prepared already ([`vm::prepare_all`]). Each tells this one
    /// it serves over a notify socket of this one's (the systemd protocol); this one tells
    /// systemd once all do. Stop and reload signals go to every pool's launcher. A pool that
    /// fails before all serve stops the others (`auto` then runs gelada); one that stops later
    /// stops them all.
    fn pools(loaded: &Loaded, opts: &vm::Options, names: &[String], argv: &[std::ffi::OsString], within: std::time::Duration) -> Outcome {
        use std::os::unix::net::UnixDatagram;
        let set = vm::block_signals();
        let base = vm::state_base(loaded, opts);
        let sock = base.join("pools.notify");
        let _ = std::fs::remove_file(&sock);
        let d = match UnixDatagram::bind(&sock) {
            Ok(d) => d,
            Err(e) => return Outcome::Fallback(format!("{}: {e}", sock.display())),
        };
        let _ = d.set_read_timeout(Some(std::time::Duration::from_millis(200)));
        // This very binary, as [`super::relaunch`] (an upgrade during the start removes its path).
        let exe = std::path::PathBuf::from("/proc/self/exe");
        let mut kids: Vec<(String, std::process::Child, bool)> = Vec::new();
        // SIGTERM to every pool's launcher, up to STOP_GRACE for them to stop their VMs, then
        // SIGKILL for any still running (its jail's watchdog ends its VM), and every one reaped:
        // a stop always ends (#102 verification).
        let stop_all = |kids: &mut Vec<(String, std::process::Child, bool)>| {
            for (_, c, _) in kids.iter_mut() {
                // SAFETY: kill(2) to a child this process started and hasn't reaped.
                unsafe { libc::kill(c.id() as i32, libc::SIGTERM) };
            }
            let t = std::time::Instant::now();
            while t.elapsed() < STOP_GRACE && kids.iter_mut().any(|(_, c, _)| matches!(c.try_wait(), Ok(None))) {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            for (n, c, _) in kids.iter_mut() {
                if matches!(c.try_wait(), Ok(None)) {
                    super::log(&format!("pool [{n}]'s launcher didn't stop within {} s of SIGTERM; killing it", STOP_GRACE.as_secs()));
                    let _ = c.kill();
                }
                let _ = c.wait();
            }
        };
        for n in names {
            let mut cmd = std::process::Command::new(&exe);
            cmd.arg("--pool").arg(n).args(argv.iter().skip(1)).env("NOTIFY_SOCKET", &sock);
            match cmd.spawn() {
                Ok(c) => kids.push((n.clone(), c, false)),
                Err(e) => {
                    stop_all(&mut kids);
                    return Outcome::Fallback(format!("pool [{n}]'s launcher: {e}"));
                }
            }
        }
        super::log(&format!("one microVM per pool: {}", names.join(", ")));
        let mut buf = [0u8; 4096];
        // Every pool was prepared before the choice: what is left is the boot (and, with no
        // snapshot yet, the warm-up VM and the snapshot), so this is a generous ceiling. Past it
        // the pools that serve are stopped too, and `auto` runs gelada (#102 review: never a
        // wait without end).
        let deadline = std::time::Instant::now() + within;
        loop {
            if std::time::Instant::now() > deadline {
                let waiting: Vec<&str> = kids.iter().filter(|(_, _, r)| !r).map(|(n, _, _)| n.as_str()).collect();
                let waiting = waiting.join(", ");
                vm::stop_extending();
                stop_all(&mut kids);
                vm::unblock_signals();
                return Outcome::Fallback(format!("pool(s) {waiting} didn't serve within {} s", within.as_secs()));
            }
            // A stop during the wait is taken at once (never only after the deadline), and from
            // then on systemd is asked for no more time.
            let now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            // SAFETY: sigtimedwait(2) on the set this thread blocked, not waiting.
            let sig = unsafe { libc::sigtimedwait(&set, std::ptr::null_mut(), &now) };
            if [libc::SIGTERM, libc::SIGINT, libc::SIGQUIT].contains(&sig) {
                vm::stop_extending();
                stop_all(&mut kids);
                let _ = std::fs::remove_file(&sock);
                super::log(&format!("stopped by signal {sig} before every pool served; every pool's launcher is stopped"));
                return Outcome::Done(Ok(()));
            }
            if let Ok(n) = d.recv(&mut buf) {
                let msg = String::from_utf8_lossy(&buf[..n]).into_owned();
                if let Some(pid) = msg.lines().find_map(|l| l.strip_prefix("MAINPID=")).and_then(|p| p.parse::<u32>().ok())
                    && msg.lines().any(|l| l == "READY=1")
                    && let Some(k) = kids.iter_mut().find(|(_, c, _)| c.id() == pid)
                {
                    k.2 = true;
                }
                if let Some(ext) = msg.lines().find(|l| l.starts_with("EXTEND_TIMEOUT_USEC=")) {
                    vm::notify(&format!("{ext}\n"));
                }
            }
            if let Some(i) = kids.iter_mut().position(|(_, c, _)| matches!(c.try_wait(), Ok(Some(_)))) {
                let name = kids[i].0.clone();
                stop_all(&mut kids);
                vm::stop_extending();
                vm::unblock_signals();
                return Outcome::Fallback(format!("pool [{name}]'s microVM stopped before every pool served (its lines above say why)"));
            }
            if kids.iter().all(|(_, _, r)| *r) {
                break;
            }
        }
        vm::stop_extending();
        super::log(&format!("every pool's microVM serves ({})", names.join(", ")));
        let _ = vm::notify_ready(std::env::var("NOTIFY_SOCKET").ok().as_deref(), std::process::id());
        loop {
            let ts = libc::timespec { tv_sec: 0, tv_nsec: 500_000_000 };
            // SAFETY: sigtimedwait(2) on the set this thread blocked.
            let sig = unsafe { libc::sigtimedwait(&set, std::ptr::null_mut(), &ts) };
            if sig > 0 {
                for (_, c, _) in &kids {
                    // SAFETY: kill(2) to a child this process started and hasn't reaped.
                    unsafe { libc::kill(c.id() as i32, sig) };
                }
                if [libc::SIGTERM, libc::SIGINT, libc::SIGQUIT].contains(&sig) {
                    stop_all(&mut kids);
                    let _ = std::fs::remove_file(&sock);
                    super::log(&format!("stopped every pool's microVM by signal {sig}"));
                    return Outcome::Done(Ok(()));
                }
            }
            if let Some(i) = kids.iter_mut().position(|(_, c, _)| matches!(c.try_wait(), Ok(Some(_)))) {
                let name = kids[i].0.clone();
                stop_all(&mut kids);
                return Outcome::Done(Err(format!("pool [{name}]'s microVM stopped; every pool's is stopped with it")));
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod microvm {
    use super::Args;
    use securecore_config::Loaded;
    use std::time::Instant;

    pub struct Ready;

    pub fn prepare(_: &Loaded, _: &Args) -> Result<Ready, String> {
        Err("the microVM needs Linux with KVM".into())
    }

    pub enum Outcome {
        Done(Result<(), String>),
        #[allow(dead_code)] // the Linux one's shape: never made here
        Fallback(String),
    }

    pub fn run(_: &Loaded, _: &Args, _: Ready, _: &[std::ffi::OsString], _: Instant) -> Outcome {
        Outcome::Done(Err("the microVM needs Linux with KVM".into()))
    }

    pub fn stop_extending() {}
}

#[cfg(target_os = "linux")]
fn guest_init() -> ExitCode {
    let e = securecore_fpm::guest::init();
    eprintln!("securecore-init: {e}; stopping the VM");
    ExitCode::FAILURE
}

#[cfg(not(target_os = "linux"))]
fn guest_init() -> ExitCode {
    eprintln!("securecore-init: the guest is Linux");
    ExitCode::FAILURE
}

/// `securecore-fpm --migrate-config <file>`: upgrades a securecore.json an earlier release wrote
/// (the installer runs it on a config it keeps; [`securecore_config::migrate`]). One line on
/// stdout, `unchanged <file>` or `migrated <file>: …`; exit 1 with the reason on stderr when it
/// can't, or when the file is still invalid for another reason afterwards.
fn migrate_config(file: &std::path::Path) -> ExitCode {
    use securecore_config::migrate::{Migrated, migrate_file, still_invalid};
    match migrate_file(file) {
        Ok(Migrated::Unchanged) => {
            println!("unchanged {}", file.display());
            ExitCode::SUCCESS
        }
        Ok(Migrated::Rewritten { backup, changes }) => {
            let what = format!("migrated {}: {}; the original is kept at {}", file.display(), changes.join(", "), backup.display());
            match still_invalid(file) {
                None => {
                    println!("{what}");
                    ExitCode::SUCCESS
                }
                Some(problem) => {
                    eprintln!("{what}, but it is still invalid: {problem}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("could not migrate: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `securecore-fpm --check-capture [--php-root <dir>] [--php-fpm <program>] [--app-root <dir>]
/// [--] [php-fpm args…]`: captures and validates the host's PHP as a microVM start would
/// (#101), without anything else: one line on stdout with what was captured and the package
/// manager it was checked against, or the refusal naming the file on stderr and exit 1. Run as
/// root (the loader and php-fpm run chrooted, as nobody).
#[cfg(target_os = "linux")]
fn check_capture(args: &[OsString]) -> ExitCode {
    let mut req = securecore_fpm::capture::Request {
        root: PathBuf::from("/"),
        php_fpm: "php-fpm".into(),
        fpm_args: Vec::new(),
        scan_dir_env: std::env::var("PHP_INI_SCAN_DIR").ok(),
        app_root: "/var/www/html".into(),
        record: None,
    };
    let mut write = None;
    let mut it = args.iter().map(|a| a.to_string_lossy().into_owned());
    while let Some(a) = it.next() {
        match a.as_str() {
            // Checked against the install's record (an unpackaged file it lacks or that differs
            // is refused); written there first when it doesn't exist.
            "--record" => req.record = Some(PathBuf::from(it.next().unwrap_or_default())),
            // The installer: (re)records the unpackaged files' sha256s, after the capture's own
            // checks pass (trust on first use, again on every install).
            "--write-record" => write = Some(PathBuf::from(it.next().unwrap_or_default())),
            "--php-root" => req.root = PathBuf::from(it.next().unwrap_or_default()),
            "--php-fpm" => req.php_fpm = it.next().unwrap_or_default(),
            "--app-root" => req.app_root = it.next().unwrap_or_default(),
            "--" => {
                req.fpm_args = it.collect();
                break;
            }
            other => {
                eprintln!("--check-capture: unknown argument {other}");
                return ExitCode::from(2);
            }
        }
    }
    match securecore_fpm::capture::capture(&req) {
        Ok(c) => {
            if let Some(w) = &write {
                match securecore_fpm::capture::write_record(w, &c.items) {
                    Ok(n) => println!("recorded {n} unpackaged files' sha256s in {}", w.display()),
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            let files: Vec<&securecore_fpm::capture::Item> = c.items.iter().filter(|i| matches!(i, securecore_fpm::capture::Item::File { .. })).collect();
            let packaged = files.iter().filter(|i| matches!(i, securecore_fpm::capture::Item::File { source, .. } if !source.starts_with("unpackaged"))).count();
            let bytes: u64 = files.iter().map(|i| if let securecore_fpm::capture::Item::File { size, .. } = i { *size } else { 0 }).sum();
            println!(
                "captured PHP {} ({}): {} files ({} MiB; {packaged} checked against {}, {} unpackaged and root-owned), {} configs, pools {}, helpers {}, missing {}",
                c.php_version,
                c.fpm,
                files.len(),
                bytes >> 20,
                c.pkg,
                files.len() - packaged,
                c.conf_d.len() + usize::from(c.ini.is_some()) + c.fpm_files.len(),
                c.pools.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(","),
                c.helpers.join(","),
                c.missing_helpers.join(",")
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().collect();
    if argv.first().map(PathBuf::from).is_some_and(|p| p.file_name().is_some_and(|n| n == "securecore-init")) {
        return guest_init();
    }
    #[cfg(target_os = "linux")]
    if argv.get(1).is_some_and(|a| a == "--sync-writer") {
        // The microVM's folder sync (#72): started by the launcher itself, never by hand.
        return ExitCode::from(securecore_fpm::sync::writer_main(argv.get(2).and_then(|c| c.to_str()).unwrap_or("")));
    }
    #[cfg(target_os = "linux")]
    if argv.get(1).is_some_and(|a| a == "--egress-connect") {
        // The microVM's egress (#72): one checked guest connection, as the pool user.
        let addrs: Vec<String> = argv[2..].iter().map(|a| a.to_string_lossy().into_owned()).collect();
        return ExitCode::from(securecore_fpm::egress::helper_main(&addrs));
    }
    #[cfg(target_os = "linux")]
    if argv.get(1).is_some_and(|a| a == "--check-capture") {
        return check_capture(&argv[2..]);
    }
    if argv.get(1).is_some_and(|a| a == "--migrate-config") {
        return match argv.get(2..) {
            Some([file]) => migrate_config(std::path::Path::new(file)),
            _ => {
                eprintln!("usage: securecore-fpm --migrate-config <securecore.json>");
                ExitCode::from(2)
            }
        };
    }
    let args = match parse(argv.clone().into_iter().skip(1)) {
        Ok(Some(args)) => args,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(problem) => return failed(&format!("{problem} ({USAGE})")),
    };
    // Never through a link, as the folder's owner, capped, and no error quotes the file
    // (#90 review): the same reading the microVM's config watcher does.
    let loaded = match securecore_fpm::sitefile::load(&args.config) {
        Ok(loaded) => loaded,
        Err(err) => return failed(&err),
    };
    let path = loaded.path.display();
    let layer1 = &loaded.config.layer1;
    let t0 = std::time::Instant::now();
    // Everything a microVM start checks and builds happens here, before the choice (#100
    // review): `auto` falls back on any of it, with the reason.
    let mut ready = None;
    let choice = match &args.gelada_fallback {
        // This launcher, run again by itself once `auto` fell back ([`relaunch`]): decided already.
        // The config may have changed in between (#100 re-review): gelada and off are what it
        // asks for now, and only microvm, which never falls back, refuses.
        Some(line) => match layer1.isolation() {
            securecore_config::Isolation::Auto => Choice::Gelada { fallback: Some(line.clone()) },
            securecore_config::Isolation::Gelada => Choice::Gelada { fallback: None },
            securecore_config::Isolation::Off => Choice::Off,
            securecore_config::Isolation::Microvm => {
                return failed(&format!("{path}: layer1.isolation is now \"microvm\", which never falls back, and the microVM failed ({line})"));
            }
        },
        None => match choose(layer1, || microvm::prepare(&loaded, &args).map(|r| ready = Some(r))) {
            Ok(choice) => choice,
            Err(refusal) => {
                microvm::stop_extending();
                return failed(&format!("{path}: {refusal}"));
            }
        },
    };
    // A pool's own launcher (`--pool`, started by the one that runs every pool) never falls back
    // by itself: it exits, and the first launcher decides for the whole config (#102 review).
    let child = args.pool.is_some();
    if child && choice != Choice::Microvm {
        microvm::stop_extending();
        return failed(&format!("{path}: pool [{}]: {choice}", args.pool.as_deref().unwrap_or("")));
    }
    if choice != Choice::Microvm {
        microvm::stop_extending();
    }
    if layer1.enabled() {
        match (&args.gelada_fallback, &choice) {
            (Some(line), Choice::Gelada { fallback: Some(_) }) => log(&format!("layer 1 isolation auto: {line}")),
            // The microVM's preparation started threads (systemd's timeout extensions): gelada
            // needs a process with one.
            (None, Choice::Gelada { fallback: Some(_) }) if threads() > 1 => return relaunch(&argv, &choice.to_string()),
            _ => log(&format!("layer 1 isolation {}: {choice}", layer1.isolation().as_str())),
        }
    }
    if choice == Choice::Microvm
        && let Some(ready) = ready.take()
    {
        log(&format!("layer 1 on from {path} (sha256 {}): php-fpm in a microVM", loaded.sha256));
        match microvm::run(&loaded, &args, ready, &argv, t0) {
            microvm::Outcome::Done(Ok(())) => return ExitCode::SUCCESS,
            microvm::Outcome::Done(Err(err)) => return failed(&format!("{path}: the microVM: {err}")),
            // Nothing was served yet: `auto` still has gelada (#100 review); `microvm` refuses, and
            // so does a pool's own launcher (its parent decides).
            microvm::Outcome::Fallback(err) if layer1.isolation() == securecore_config::Isolation::Auto && !child => {
                microvm::stop_extending();
                // The VM's threads are still here: gelada in a fresh process.
                return relaunch(&argv, &format!("gelada, because the microVM failed before it served ({})", one_line(&err)));
            }
            microvm::Outcome::Fallback(err) => return failed(&format!("{path}: the microVM: {err}")),
        }
    }
    let program = PathBuf::from(&args.php_fpm);
    let mut command = Command::new(&args.php_fpm);
    command.args(&args.rest);
    // Kept until exec: dropping it would remove gelada's temporary folder, which php-fpm may
    // write. exec replaces the process without running destructors, so it stays.
    let _sandbox = match plan(&loaded) {
        Err(refusal) => return failed(&format!("{path}: {refusal}")),
        Ok(None) => {
            log(&format!("layer 1 is off in {path} (sha256 {}); starting {} without it", loaded.sha256, program.display()));
            None
        }
        Ok(Some(plan)) => {
            let sandbox = match plan.sandbox() {
                Ok(sandbox) => sandbox,
                Err(err) => return failed(&format!("{path}: the layer 1 sandbox can't be built: {err}")),
            };
            // If this fails part-way the process may be partly restricted; it exits either way.
            if let Err(err) = sandbox.restrict_self() {
                return failed(&format!("{path}: the layer 1 sandbox can't be applied: {err}"));
            }
            log(&format!("layer 1 on from {path} (sha256 {}): {plan}; starting {}", loaded.sha256, program.display()));
            Some(sandbox)
        }
    };
    // A microVM start that was prepared (or failed) blocked the stop signals: php-fpm gets them
    // as a host's php-fpm does.
    #[cfg(target_os = "linux")]
    securecore_fpm::vm::unblock_signals();
    let err = command.exec();
    failed(&format!("{}: {err}", program.display()))
}
