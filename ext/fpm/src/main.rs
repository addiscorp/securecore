//! `securecore-fpm --config <securecore.json> [options] [--] [php-fpm args…]`
//!
//! Reads `layer1` from the file and starts php-fpm inside what `layer1.isolation` picks
//! (addiscorp/securecore#71):
//! - **gelada**: applies `layer1` to itself as a gelada sandbox and execs php-fpm (`php-fpm` on
//!   `PATH` unless `--php-fpm` names another) with the remaining arguments, so the whole of
//!   php-fpm, master and workers, runs inside it.
//! - **microvm**: boots the guest's php-fpm in a jailed Firecracker microVM and stays in the
//!   foreground as its only way in and out, until SIGTERM/SIGINT/SIGQUIT (see `vm.rs`).
//! - **auto** (the default): gelada, and the reason; the microVM once `auto` may pick it
//!   ([`securecore_fpm::AUTO_SELECTS_MICROVM`]).
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
[--guest-arg <word>]... [--] [php-fpm args...] | securecore-fpm --migrate-config <securecore.json>";

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
    mem: u32,
    vcpus: u32,
    write_disk_mib: u64,
    snapshot: bool,
    guest_args: Vec<String>,
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
        mem: 512,
        vcpus: 2,
        write_disk_mib: 1024,
        snapshot: true,
        guest_args: Vec::new(),
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
            | "--listen-group" | "--listen-mode" | "--guest-root" | "--mem" | "--vcpus" | "--write-disk-mib" | "--guest-arg" => {
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
                    "--mem" => a.mem = number()?,
                    "--vcpus" => a.vcpus = number()?,
                    "--write-disk-mib" => a.write_disk_mib = u64::from(number()?),
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
            write_disk_mib: a.write_disk_mib,
            vm_user: a.vm_user.clone(),
            pool_user: a.pool_user.clone(),
            snapshot: a.snapshot,
            guest_args: a.guest_args.clone(),
        })
    }

    pub fn available(loaded: &Loaded, a: &Args) -> Result<(), String> {
        vm::available(loaded, &options(a)?)
    }

    pub fn run(loaded: &Loaded, a: &Args) -> Result<(), String> {
        vm::run(loaded, &options(a)?)
    }
}

#[cfg(not(target_os = "linux"))]
mod microvm {
    use super::Args;
    use securecore_config::Loaded;

    pub fn available(_: &Loaded, _: &Args) -> Result<(), String> {
        Err("the microVM needs Linux with KVM".into())
    }

    pub fn run(_: &Loaded, _: &Args) -> Result<(), String> {
        Err("the microVM needs Linux with KVM".into())
    }
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
    if argv.get(1).is_some_and(|a| a == "--migrate-config") {
        return match argv.get(2..) {
            Some([file]) => migrate_config(std::path::Path::new(file)),
            _ => {
                eprintln!("usage: securecore-fpm --migrate-config <securecore.json>");
                ExitCode::from(2)
            }
        };
    }
    let args = match parse(argv.into_iter().skip(1)) {
        Ok(Some(args)) => args,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(problem) => return failed(&format!("{problem} ({USAGE})")),
    };
    let loaded = match securecore_config::load(&args.config) {
        Ok(loaded) => loaded,
        Err(err) => return failed(&err.to_string()),
    };
    let path = loaded.path.display();
    let layer1 = &loaded.config.layer1;
    let choice = match choose(layer1, || microvm::available(&loaded, &args)) {
        Ok(choice) => choice,
        Err(refusal) => return failed(&format!("{path}: {refusal}")),
    };
    if layer1.enabled() {
        log(&format!("layer 1 isolation {}: {choice}", layer1.isolation().as_str()));
    }
    if choice == Choice::Microvm {
        log(&format!("layer 1 on from {path} (sha256 {}): php-fpm in a microVM", loaded.sha256));
        return match microvm::run(&loaded, &args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => failed(&format!("{path}: the microVM: {err}")),
        };
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
    let err = command.exec();
    failed(&format!("{}: {err}", program.display()))
}
