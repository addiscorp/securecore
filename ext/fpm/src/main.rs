//! `securecore-fpm --config <securecore.json> [options] [--] [php-fpm args…]`
//!
//! Reads `layer1` from the file and starts php-fpm inside what `layer1.isolation` picks
//! (addiscorp/securecore#71):
//! - **gelada**: applies `layer1` to itself as a gelada sandbox and execs php-fpm (`php-fpm` on
//!   `PATH` unless `--php-fpm` names another) with the remaining arguments, so the whole of
//!   php-fpm, master and workers, runs inside it.
//! - **microvm**: boots the guest's php-fpm in a Firecracker microVM and stays in the
//!   foreground as its only way in and out, until SIGTERM/SIGINT (see `vm.rs`).
//! - **auto** (the default): microvm where this host can run it, gelada otherwise.
//! - layer 1 off: execs php-fpm as it is and says so.
//!
//! Fails closed: an invalid file, a layer 1 it can't enforce, `microvm` on a host without the
//! microVM, or a sandbox the kernel won't apply exits 125 with the reason on stderr, and
//! php-fpm never runs.
//!
//! Run as `/sbin/securecore-init` (a link in the guest image), it is PID 1 in the guest.

use std::ffi::OsString;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use securecore_fpm::{Choice, FAILED, choose, plan};

const USAGE: &str = "usage: securecore-fpm --config <securecore.json> [--php-fpm <program>] \
[--vm-dir <dir>] [--firecracker <file>] [--kernel <file>] [--rootfs <file>] [--kvm <device>] \
[--state-dir <dir>] [--listen unix:<path>|<host>:<port>] [--guest-root <path>] [--mem <MiB>] \
[--vcpus <n>] [--no-snapshot] [--guest-arg <word>]... [--] [php-fpm args...]";

struct Args {
    config: PathBuf,
    php_fpm: OsString,
    vm_dir: PathBuf,
    firecracker: Option<PathBuf>,
    kernel: Option<PathBuf>,
    rootfs: Option<PathBuf>,
    kvm: PathBuf,
    state_dir: Option<PathBuf>,
    listen: Option<String>,
    guest_root: Option<String>,
    mem: u32,
    vcpus: u32,
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
        firecracker: None,
        kernel: None,
        rootfs: None,
        kvm: PathBuf::from("/dev/kvm"),
        state_dir: None,
        listen: None,
        guest_root: None,
        mem: 512,
        vcpus: 2,
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
            "--config" | "--php-fpm" | "--vm-dir" | "--firecracker" | "--kernel" | "--rootfs" | "--kvm" | "--state-dir"
            | "--listen" | "--guest-root" | "--mem" | "--vcpus" | "--guest-arg" => {
                args.next();
                let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
                let text = || value.to_str().map(str::to_owned).ok_or_else(|| format!("{flag}: not UTF-8"));
                let number = || text()?.parse::<u32>().ok().filter(|n| *n > 0).ok_or_else(|| format!("{flag}: want a number"));
                match flag.as_str() {
                    "--config" => config = Some(PathBuf::from(&value)),
                    "--php-fpm" => a.php_fpm = value,
                    "--vm-dir" => a.vm_dir = PathBuf::from(&value),
                    "--firecracker" => a.firecracker = Some(PathBuf::from(&value)),
                    "--kernel" => a.kernel = Some(PathBuf::from(&value)),
                    "--rootfs" => a.rootfs = Some(PathBuf::from(&value)),
                    "--kvm" => a.kvm = PathBuf::from(&value),
                    "--state-dir" => a.state_dir = Some(PathBuf::from(&value)),
                    "--listen" => a.listen = Some(text()?),
                    "--guest-root" => a.guest_root = Some(text()?),
                    "--mem" => a.mem = number()?,
                    "--vcpus" => a.vcpus = number()?,
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
    use securecore_fpm::vm::{self, Assets, Listen, Options};

    pub fn options(a: &Args) -> Result<Options, String> {
        let dir = Assets::in_dir(&a.vm_dir);
        Ok(Options {
            assets: Assets {
                firecracker: a.firecracker.clone().unwrap_or(dir.firecracker),
                kernel: a.kernel.clone().unwrap_or(dir.kernel),
                rootfs: a.rootfs.clone().unwrap_or(dir.rootfs),
            },
            kvm: a.kvm.clone(),
            state: a.state_dir.clone(),
            listen: a.listen.as_deref().map(Listen::parse).transpose()?,
            guest_root: a.guest_root.clone(),
            mem_mib: a.mem,
            vcpus: a.vcpus,
            snapshot: a.snapshot,
            guest_args: a.guest_args.clone(),
        })
    }

    pub fn available(a: &Args) -> Result<(), String> {
        let o = options(a)?;
        vm::available(&o.kvm, &o.assets)
    }

    pub fn run(loaded: &securecore_config::Loaded, a: &Args) -> Result<(), String> {
        vm::run(loaded, &options(a)?)
    }
}

#[cfg(not(target_os = "linux"))]
mod microvm {
    use super::Args;

    pub fn available(_: &Args) -> Result<(), String> {
        Err("the microVM needs Linux with KVM".into())
    }

    pub fn run(_: &securecore_config::Loaded, _: &Args) -> Result<(), String> {
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

fn main() -> ExitCode {
    let argv0 = std::env::args_os().next().map(PathBuf::from).unwrap_or_default();
    if argv0.file_name().is_some_and(|n| n == "securecore-init") {
        return guest_init();
    }
    let args = match parse(std::env::args_os().skip(1)) {
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
    let choice = match choose(layer1, || microvm::available(&args)) {
        Ok(choice) => choice,
        Err(refusal) => return failed(&format!("{path}: {refusal}")),
    };
    if layer1.enabled {
        log(&format!("layer 1 isolation {}: {choice}", layer1.isolation.as_str()));
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
