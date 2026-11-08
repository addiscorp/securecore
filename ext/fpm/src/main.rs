//! `securecore-fpm --config <securecore.json> [--php-fpm <program>] [--] [php-fpm args…]`
//!
//! Reads `layer1` from the file, applies it to itself as a gelada sandbox and execs php-fpm
//! (`php-fpm` on `PATH` unless `--php-fpm` names another) with the remaining arguments, so the
//! whole of php-fpm, master and workers, runs inside it. With layer 1 disabled it execs php-fpm
//! as it is and says so. Fails closed: an invalid file, a layer 1 it can't enforce, or a
//! sandbox the kernel won't apply exits 125 with the reason on stderr, and php-fpm never runs.

use std::ffi::OsString;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use securecore_fpm::{FAILED, plan};

const USAGE: &str = "usage: securecore-fpm --config <securecore.json> [--php-fpm <program>] [--] [php-fpm args...]";

struct Args {
    config: PathBuf,
    php_fpm: OsString,
    rest: Vec<OsString>,
}

/// The launcher's flags come first; `--`, or the first argument that isn't one of them, starts
/// php-fpm's own (so `securecore-fpm --config f -F` passes `-F` on). `Ok(None)`: `--help`.
fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Option<Args>, String> {
    let mut args = args.into_iter().peekable();
    let (mut config, mut php_fpm) = (None, OsString::from("php-fpm"));
    while let Some(arg) = args.peek() {
        let flag = arg.to_str().unwrap_or_default().to_owned();
        match flag.as_str() {
            "--" => {
                args.next();
                break;
            }
            "--help" => return Ok(None),
            "--config" | "--php-fpm" => {
                args.next();
                let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
                if flag == "--config" {
                    config = Some(PathBuf::from(value));
                } else {
                    php_fpm = value;
                }
            }
            _ => break,
        }
    }
    let config = config.ok_or("--config is required")?;
    Ok(Some(Args { config, php_fpm, rest: args.collect() }))
}

fn log(message: &str) {
    eprintln!("securecore-fpm: {message}");
}

fn failed(message: &str) -> ExitCode {
    log(&format!("{message}; refusing to start php-fpm"));
    ExitCode::from(FAILED)
}

fn main() -> ExitCode {
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
