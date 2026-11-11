//! `securecore-fpm`: SecureCore's layer 1 (addiscorp/securecore#53, E6). It reads `layer1`
//! from `securecore.json` with the same types and loader as the extension, applies a gelada
//! sandbox to itself ([`gelada::Sandbox::restrict_self`]: Landlock + seccomp) and then execs
//! php-fpm, so php-fpm's master and every worker it forks run inside it. Nothing here is a
//! default: what php-fpm may write, read and reach is what `layer1` lists, plus what gelada
//! always allows (see [`Plan`]).
//!
//! This module turns a loaded config into a [`Plan`] (or a [`Refusal`]) and a plan into a
//! [`gelada::Sandbox`]; `main.rs` parses the arguments, applies it and execs.
//!
//! `layer1.isolation` (addiscorp/securecore#71) picks what php-fpm runs inside: [`choose`]
//! decides between off, gelada and a Firecracker microVM ([`vm`], the host driver; [`guest`],
//! the guest's PID 1). `auto`, the default, is the only value that falls back.

use std::fmt;
use std::path::PathBuf;

use securecore_config::{Isolation, Layer1, Loaded};

#[cfg(target_os = "linux")]
pub mod egress;
pub mod fcgi;
#[cfg(target_os = "linux")]
pub mod guest;
#[cfg(target_os = "linux")]
pub mod jail;
#[cfg(target_os = "linux")]
pub mod sync;
#[cfg(target_os = "linux")]
pub mod vm;
#[cfg(target_os = "linux")]
pub mod vsock;

/// What layer 1 runs php-fpm inside, once `layer1.isolation` has met this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    /// Layer 1 is off (`isolation: "off"`).
    Off,
    /// gelada. `fallback` is why `auto` didn't pick a microVM (`None`: `gelada` was asked for).
    Gelada { fallback: Option<String> },
    /// A Firecracker microVM.
    Microvm,
}

/// Whether `auto` may pick the microVM. Not until the guest's writes to its writable folders
/// (uploads) sync back to the host (addiscorp/securecore#72): until then a microVM keeps them in
/// its own disk image, which nginx and backups don't see, so only an explicit `microvm` gets one.
pub const AUTO_SELECTS_MICROVM: bool = false;

/// Why `auto` is gelada on a host that could run the microVM.
pub const AUTO_GATE: &str = "auto doesn't pick the microVM until its writable folders sync back to the host \
(addiscorp/securecore#72); set \"microvm\" to ask for it";

/// `layer1.isolation` against this host. `microvm` is `Ok` when this host can run the microVM
/// for this config and `Err(why)` when it can't ([`vm::available`] on Linux); it is only asked
/// when the answer matters. Only `auto` falls back; `microvm` without one is a [`Refusal`].
pub fn choose(layer1: &Layer1, microvm: impl FnOnce() -> Result<(), String>) -> Result<Choice, Refusal> {
    choose_with(layer1, AUTO_SELECTS_MICROVM, microvm)
}

/// [`choose`] with the `auto` gate given, so both settings are tested.
pub fn choose_with(layer1: &Layer1, auto_microvm: bool, microvm: impl FnOnce() -> Result<(), String>) -> Result<Choice, Refusal> {
    match layer1.isolation() {
        Isolation::Off => Ok(Choice::Off),
        Isolation::Gelada => Ok(Choice::Gelada { fallback: None }),
        Isolation::Microvm => match microvm() {
            Ok(()) => Ok(Choice::Microvm),
            Err(why) => Err(Refusal::NoMicrovm { why }),
        },
        // Gated: gelada without asking anything (no state folder, no hashing, no cgroup write).
        Isolation::Auto if !auto_microvm => Ok(Choice::Gelada { fallback: Some(AUTO_GATE.into()) }),
        Isolation::Auto => Ok(match microvm() {
            Err(why) => Choice::Gelada { fallback: Some(why) },
            Ok(()) => Choice::Microvm,
        }),
    }
}

impl fmt::Display for Choice {
    /// The launcher's log line for the choice, after `layer 1 isolation <value>: `.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Choice::Off => write!(f, "off"),
            Choice::Gelada { fallback: None } => write!(f, "gelada"),
            Choice::Gelada { fallback: Some(why) } if why == AUTO_GATE => write!(f, "gelada, because {why}"),
            Choice::Gelada { fallback: Some(why) } => write!(f, "gelada, because the microVM can't run here ({why})"),
            Choice::Microvm => write!(f, "microvm"),
        }
    }
}

/// The exit code when the launcher itself fails (an invalid config, a sandbox that can't be
/// applied, a php-fpm that can't be run), as gelada, `env` and `docker run` use it. php-fpm is
/// never started in that case.
pub const FAILED: u8 = 125;

/// What php-fpm runs inside: `layer1`'s paths resolved against the app root, and its ports.
///
/// gelada adds three things of its own on top, which are not in the config because they are
/// not SecureCore's to choose: its own empty temporary folder (writable; under the launcher's
/// `TMPDIR`), the devices programs write by path (`/dev/null`, `/dev/zero`, `/dev/full`,
/// `/dev/tty`, `/dev/ptmx`, `/dev/pts`, `/dev/shm`), and the denial of its common secrets
/// under the launcher's `HOME` (`~/.ssh`, `~/.aws`, …: [`gelada::COMMON_SECRETS`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Writable folders (everything else is read-only).
    pub write: Vec<PathBuf>,
    /// Neither readable nor writable, even inside a writable folder.
    pub deny: Vec<PathBuf>,
    /// TCP ports php-fpm may bind and listen on.
    pub bind: Vec<u16>,
    /// TCP ports php-fpm may connect to, on any host.
    pub connect: Vec<u16>,
}

/// A valid `layer1` that the launcher can't enforce as written. It refuses to start rather
/// than drop part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `unixSockets` together with TCP ports: gelada 0.3.0 refuses that combination on Linux
    /// (addiscorp/securecore#57).
    UnixSocketsWithPorts { socket: String },
    /// `unixSockets` without ports: the allowlist needs gelada's supervisor in a separate
    /// process, and the launcher runs php-fpm in its own place (`restrict_self`), so gelada
    /// refuses it there.
    UnixSocketsInPlace { socket: String },
    /// `isolation: "microvm"` on a host that can't run the microVM: never downgraded.
    NoMicrovm { why: String },
    /// `unixSockets` in a microVM: the guest reaches no host socket by path, only through
    /// `connect[].socket`.
    UnixSocketsInMicrovm { socket: String },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::UnixSocketsWithPorts { socket } => write!(
                f,
                "layer1.network.unixSockets ({socket}) can't be combined with TCP ports \
                 (layer1.network.bind/connect) yet: gelada 0.3.0 refuses a unix-socket allowlist \
                 together with port rules on Linux (addiscorp/securecore#57). Reach the service \
                 over its TCP port instead (MySQL: 3306) and remove unixSockets"
            ),
            Refusal::UnixSocketsInPlace { socket } => write!(
                f,
                "layer1.network.unixSockets ({socket}) can't be enforced by securecore-fpm yet: \
                 gelada checks unix-socket connects in a supervisor that must run in another \
                 process, and securecore-fpm becomes php-fpm (restrict_self), so gelada refuses \
                 it (see addiscorp/securecore#57). Reach the service over its TCP port instead \
                 and remove unixSockets"
            ),
            Refusal::NoMicrovm { why } => write!(
                f,
                "layer1.isolation is \"microvm\" but the microVM can't run here ({why}). \
                 \"microvm\" never falls back; use \"auto\" to accept gelada where there is no microVM"
            ),
            Refusal::UnixSocketsInMicrovm { socket } => write!(
                f,
                "layer1.network.unixSockets ({socket}) can't reach into a microVM: give the port the \
                 socket instead, as layer1.network.connect [{{ \"port\": 3306, \"socket\": \"{socket}\" }}], \
                 and remove unixSockets"
            ),
        }
    }
}

/// The plan for `loaded`'s `layer1`: `None` when layer 1 is disabled (php-fpm runs without
/// it), or a [`Refusal`] when it can't be enforced as written.
pub fn plan(loaded: &Loaded) -> Result<Option<Plan>, Refusal> {
    let layer1 = &loaded.config.layer1;
    if !layer1.enabled() {
        return Ok(None);
    }
    let net = &layer1.network;
    let bind = net.bind.iter().map(|p| p.port.get()).collect::<Vec<_>>();
    let connect = net.connect.iter().map(|c| c.port.get()).collect::<Vec<_>>();
    if let Some(socket) = net.unix_sockets.first() {
        let socket = loaded.resolve(socket).display().to_string();
        return Err(if bind.is_empty() && connect.is_empty() {
            Refusal::UnixSocketsInPlace { socket }
        } else {
            Refusal::UnixSocketsWithPorts { socket }
        });
    }
    Ok(Some(Plan {
        write: layer1.write.iter().map(|p| loaded.resolve(p)).collect(),
        deny: layer1.deny.iter().map(|p| loaded.resolve(p)).collect(),
        bind,
        connect,
    }))
}

impl Plan {
    /// The gelada sandbox for this plan: gelada's defaults (read everything but the common
    /// secrets, write nothing, no network) narrowed and opened exactly as the plan says.
    pub fn sandbox(&self) -> Result<gelada::Sandbox, gelada::Error> {
        let mut sandbox = gelada::Sandbox::new()?;
        for path in &self.deny {
            sandbox = sandbox.deny(path);
        }
        for path in &self.write {
            sandbox = sandbox.allow_write(path);
        }
        for &port in &self.bind {
            sandbox = sandbox.allow_tcp_bind(port);
        }
        for &port in &self.connect {
            sandbox = sandbox.allow_tcp_connect(port);
        }
        Ok(sandbox)
    }
}

impl fmt::Display for Plan {
    /// One line for the log: `write …; deny …; tcp bind …; tcp connect …`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn list<T: fmt::Display>(items: impl Iterator<Item = T>) -> String {
            let items: Vec<String> = items.map(|i| i.to_string()).collect();
            if items.is_empty() { "none".into() } else { items.join(" ") }
        }
        write!(
            f,
            "write {}; deny {}; tcp bind {}; tcp connect {}",
            list(self.write.iter().map(|p| p.display())),
            list(self.deny.iter().map(|p| p.display())),
            list(self.bind.iter()),
            list(self.connect.iter()),
        )
    }
}

#[cfg(test)]
mod tests;
