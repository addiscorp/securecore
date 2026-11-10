//! The isolated child's limits (Linux): what it may write, what it may never read, how much
//! memory and CPU it gets. Applied by the child to itself right after the fork, before the
//! plugin's first line runs, so a plugin can't loosen them.

use std::io;
use std::path::{Path, PathBuf};

/// What the child runs inside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The only folders the child may write (`layer3.write.<slug>`, resolved). Nothing else,
    /// not even uploads, cache or a temporary folder.
    pub write: Vec<PathBuf>,
    /// Never readable: securecore.json, the vault's source and vault files, wp-config.php.
    pub deny: Vec<PathBuf>,
}

impl Plan {
    /// The gelada sandbox: read everything but `deny`, write only `write`, no network (no TCP,
    /// no UDP, no new unix sockets; the request socket it already holds keeps working).
    ///
    /// gelada makes a temporary folder of its own and makes it writable. The child must keep no
    /// state between requests and exits without running destructors, so the folder is removed
    /// before the sandbox is built: gelada writes rules only for paths that exist.
    pub fn sandbox(&self) -> Result<gelada::Sandbox, gelada::Error> {
        let mut sandbox = gelada::Sandbox::empty()?;
        let _ = std::fs::remove_dir(sandbox.temp_dir());
        for path in &self.deny {
            sandbox = sandbox.deny(path);
        }
        for path in &self.write {
            sandbox = sandbox.allow_write(path);
        }
        Ok(sandbox)
    }

    /// Applies the sandbox to this process. Fails if it can't (the caller exits).
    pub fn restrict_self(&self) -> Result<(), String> {
        self.sandbox().and_then(|s| s.restrict_self()).map_err(|e| format!("layer3: gelada: {e}"))
    }
}

/// The paths a child is denied for a site: the config, the vault's sources, and wp-config.php
/// where WordPress looks for it (`ABSPATH` and the folder above).
pub fn denied(config: &Path, vault_sources: &[PathBuf], abspath: &Path) -> Vec<PathBuf> {
    let mut out = vec![config.to_owned()];
    out.extend(vault_sources.iter().cloned());
    out.push(abspath.join("wp-config.php"));
    if let Some(up) = abspath.parent() {
        out.push(up.join("wp-config.php"));
    }
    out.sort();
    out.dedup();
    out
}

/// This process's virtual size now, in bytes (`/proc/self/statm`, field 1, in pages).
pub fn virtual_size() -> io::Result<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm")?;
    let pages: u64 = statm.split_whitespace().next().and_then(|p| p.parse().ok()).ok_or_else(|| io::Error::other("bad statm"))?;
    // SAFETY: a plain getter.
    let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096);
    Ok(pages * page)
}

fn set(resource: libc::__rlimit_resource_t, value: u64) -> io::Result<()> {
    let lim = libc::rlimit { rlim_cur: value, rlim_max: value };
    // SAFETY: a plain struct.
    if unsafe { libc::setrlimit(resource, &raw const lim) } != 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// The kernel's limits for the child, a backstop under PHP's own `memory_limit` (which the
/// child also sets) and the worker's wall-clock deadline:
/// - address space: what the child has mapped at the fork plus `memory_mb` (so an allocation
///   PHP's allocator never sees, in native code, is capped too);
/// - CPU time: `cpu_seconds` for the child's whole life (SIGXCPU, then SIGKILL);
/// - no core files.
pub fn apply_rlimits(memory_mb: u32, cpu_seconds: u64) -> io::Result<()> {
    let base = virtual_size()?;
    set(libc::RLIMIT_AS, base + u64::from(memory_mb) * 1024 * 1024)?;
    set(libc::RLIMIT_CPU, cpu_seconds.max(1))?;
    set(libc::RLIMIT_CORE, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_the_config_vault_and_wp_config() {
        let d = denied(Path::new("/srv/site/securecore.json"), &[PathBuf::from("/etc/securecore/vault.json")], Path::new("/srv/site/wp/"));
        assert_eq!(
            d,
            [
                PathBuf::from("/etc/securecore/vault.json"),
                PathBuf::from("/srv/site/securecore.json"),
                PathBuf::from("/srv/site/wp/wp-config.php"),
                PathBuf::from("/srv/site/wp-config.php"),
            ]
        );
    }

    #[test]
    fn statm_is_readable() {
        assert!(virtual_size().unwrap() > 0);
    }

    /// The sandbox, applied in a forked child: a write outside `write` and a read of a denied
    /// file fail, the allowed folder works. (Forked so the test process stays unrestricted.)
    #[test]
    fn a_child_writes_only_its_folders() {
        let base = std::env::temp_dir().join(format!("sc-l3-child-{}", std::process::id()));
        let ok = base.join("ok");
        let other = base.join("other");
        std::fs::create_dir_all(&ok).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let secret = base.join("secret.json");
        std::fs::write(&secret, "{}").unwrap();
        let plan = Plan { write: vec![ok.clone()], deny: vec![secret.clone()] };
        // SAFETY: fork in a test; the child only makes syscalls and exits.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let code = match plan.restrict_self() {
                Err(_) => 10,
                Ok(()) => {
                    let wrote_ok = std::fs::write(ok.join("a"), "x").is_ok();
                    let wrote_other = std::fs::write(other.join("a"), "x").is_ok();
                    let read_secret = std::fs::read(&secret).is_ok();
                    let wrote_tmp = std::fs::write(std::env::temp_dir().join(format!("sc-l3-tmp-{}", std::process::id())), "x").is_ok();
                    u8::from(!wrote_ok) | (u8::from(wrote_other) << 1) | (u8::from(read_secret) << 2) | (u8::from(wrote_tmp) << 3)
                }
            };
            // SAFETY: leave the forked test child without running the harness.
            unsafe { libc::_exit(i32::from(code)) };
        }
        let mut status = 0;
        // SAFETY: our child.
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        let _ = std::fs::remove_dir_all(&base);
        let code = libc::WEXITSTATUS(status);
        if code == 10 {
            eprintln!("skipped: Landlock is not available here");
            return;
        }
        assert_eq!(code, 0, "bits: 1 = allowed write failed, 2 = other write worked, 4 = secret read, 8 = /tmp write worked");
    }
}
