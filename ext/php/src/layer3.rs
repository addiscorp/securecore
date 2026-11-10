//! Layer 3 (addiscorp/securecore#53, E7): a plugin listed in `layer3.isolate` runs in a clean
//! child process, never in the php-fpm worker. The #42 spike's process model, inside the
//! extension:
//!
//! 1. **The helper.** At MINIT under php-fpm, the master fork+execs `php -r <helper.php>` with an
//!    empty environment and one end of a `SOCK_SEQPACKET` control socket on fd 3; the master
//!    keeps the other end, so every worker inherits it. The helper is a supervisor that forks a
//!    *zygote* per core-options snapshot; the zygote boots WordPress once from the snapshot
//!    (core options only, #47; one `$wpdb` for its life, #46) with no plugins, no mu-plugins and
//!    no theme code, and holds no secret.
//! 2. **One child per request.** When WordPress loads an isolated plugin, the worker sends the
//!    helper one end of a fresh socketpair. The zygote forks a child, which restricts itself
//!    (gelada: writes only `layer3.write.<slug>`, never reads securecore.json, the vault's sources
//!    or wp-config.php, no network; rlimits on memory and CPU), loads only that plugin and reports
//!    its hooks and shortcodes. It answers the worker's calls until the request ends, then exits.
//! 3. **No isolated code in the worker.** The `zend_compile_file` wrapper gives WordPress's
//!    include of the plugin a stand-in ([`stub.php`](layer3/stub.php)) that mirrors the
//!    registrations as forwarding callbacks; every other include of its files is refused.
//! 4. **Attribution.** The child acts as the plugin ([`crate::attribution::act_as`]): layer 2
//!    charges everything it does to it.
//! 5. **Limits.** `timeoutMs` is each call's wall-clock deadline in the worker (then the child is
//!    killed), `memoryMb` the child's PHP `memory_limit` and, above what it inherited, its address
//!    space; its CPU time is capped at `timeoutMs` too.

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use ext_php_rs::boxed::ZBox;
use ext_php_rs::error::php_error;
use ext_php_rs::ffi::{zend_execute_data, zend_op_array};
use ext_php_rs::flags::ErrorType;
use ext_php_rs::prelude::*;
use ext_php_rs::types::{ZendHashTable, ZendStr, Zval};
use securecore_attribution::Component;
use securecore_config::Loaded;
use securecore_layer3::child::{self, Plan};
use securecore_layer3::options;
use securecore_layer3::wire::{self, Hello};

use crate::{LOG_NOTICE, LOG_WARNING, attribution, log};

/// Internal: the helper's role, set only on its command line by [`spawn_helper`].
pub const INI_ROLE: &str = "securecore.layer3_role";

const HELPER_PHP: &str = include_str!("layer3/helper.php");
const STUB_PHP: &str = include_str!("layer3/stub.php");

/// The control socket's descriptor in the helper.
const FD_CONTROL: RawFd = 3;
/// How long the helper waits for a worker's hello and snapshot, and a worker for the helper to
/// answer before the plugin's own time starts.
const HANDSHAKE: Duration = Duration::from_secs(5);
/// Extra time a request that needs a new zygote may take: it boots WordPress first.
const BOOT_ALLOWANCE: Duration = Duration::from_secs(10);
/// How often the helper's loops wake to reap exited processes.
const REAP_EVERY: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// A php-fpm master or worker: isolated plugins load through the helper.
    Fpm,
    /// The helper (supervisor, zygote or child).
    Helper,
    /// Any other SAPI (CLI, CGI): no helper, so isolated plugins don't load at all.
    Other,
}

static ROLE: OnceLock<Role> = OnceLock::new();
/// php-fpm: the master's end of the control socket, inherited by every worker.
static CONTROL: OnceLock<RawFd> = OnceLock::new();

fn role() -> Role {
    ROLE.get().copied().unwrap_or(Role::Other)
}

fn lock<T>(m: &'static Mutex<T>) -> MutexGuard<'static, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn is_helper(role: &str) -> bool {
    role.trim() == "helper"
}

/// At MINIT: notes this process's role and, in a php-fpm master with layer 3 enabled, starts
/// the helper. A helper that can't start is logged, not fatal: isolated plugins then never load
/// (they never run unisolated either).
pub(crate) fn startup(role: &str, live: &Loaded) -> Result<(), String> {
    if is_helper(role) {
        let _ = ROLE.set(Role::Helper);
        return Ok(());
    }
    if !role.trim().is_empty() {
        return Err(format!("{INI_ROLE} = {role:?}: internal to layer 3, set only by the extension"));
    }
    let fpm = sapi_name().as_deref() == Some("fpm-fcgi");
    let _ = ROLE.set(if fpm { Role::Fpm } else { Role::Other });
    if fpm && live.config.layer3.enabled {
        match spawn_helper() {
            Ok((fd, pid)) => {
                let _ = CONTROL.set(fd);
                log(LOG_NOTICE, &format!("layer3 helper started (pid {pid})"));
            }
            Err(e) => log(LOG_WARNING, &format!("layer3 helper could not start ({e}); isolated plugins will not load")),
        }
    }
    Ok(())
}

fn sapi_name() -> Option<String> {
    // SAFETY: the SAPI module struct, set before any extension starts; name is a C string.
    unsafe {
        let sapi = ext_php_rs::ffi::ext_php_rs_sapi_module().as_ref()?;
        (!sapi.name.is_null()).then(|| CStr::from_ptr(sapi.name).to_string_lossy().into_owned())
    }
}

/// Fork + exec the helper: `<PHP_BINDIR>/php -d securecore.layer3_role=helper -r <helper.php>`,
/// an empty environment, stdin and stdout on /dev/null, stderr shared with php-fpm (its log), the
/// control socket on fd 3 and no other descriptor.
fn spawn_helper() -> io::Result<(RawFd, i32)> {
    let (ours, theirs) = wire::socketpair(libc::SOCK_SEQPACKET)?;
    let bindir = attribution::constant(c"PHP_BINDIR").unwrap_or_else(|| "/usr/local/bin".to_owned());
    let cstr = |s: &str| CString::new(s).map_err(io::Error::other);
    let php = cstr(&format!("{bindir}/php"))?;
    let code = HELPER_PHP.trim_start().strip_prefix("<?php").unwrap_or(HELPER_PHP);
    let args = [
        "php",
        "-d",
        "securecore.layer3_role=helper",
        "-d",
        "display_errors=0",
        "-d",
        "log_errors=1",
        "-d",
        "error_log=",
        "-d",
        "opcache.enable_cli=0",
        "-r",
        code,
    ]
    .map(cstr)
    .into_iter()
    .collect::<io::Result<Vec<_>>>()?;
    let mut argv: Vec<*const c_char> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let envp: [*const c_char; 1] = [std::ptr::null()];
    let devnull = cstr("/dev/null")?;
    // SAFETY: fork in the single-threaded php-fpm master at MINIT; the child only makes
    // async-signal-safe calls with values prepared above, then execs or _exits.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error()),
        0 => unsafe {
            let fd = theirs.as_raw_fd();
            if fd == FD_CONTROL {
                libc::fcntl(fd, libc::F_SETFD, 0);
            } else {
                libc::dup2(fd, FD_CONTROL);
            }
            let null = libc::open(devnull.as_ptr(), libc::O_RDWR);
            if null >= 0 {
                libc::dup2(null, 0);
                libc::dup2(null, 1);
            }
            close_from(FD_CONTROL + 1);
            libc::execve(php.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(127)
        },
        _ => {
            drop(theirs);
            Ok((ours.into_raw_fd(), pid))
        }
    }
}

/// Closes every descriptor from `first` up (close_range, or a loop on an old kernel).
fn close_from(first: RawFd) {
    let Ok(first) = u32::try_from(first) else { return };
    // SAFETY: closing descriptors in a process about to exec.
    unsafe {
        if libc::syscall(libc::SYS_close_range, first, u32::MAX, 0u32) != 0 {
            for fd in first..4096 {
                libc::close(fd as RawFd);
            }
        }
    }
}

// --- the php-fpm worker -------------------------------------------------------------------------

/// This request's children, by slug. `None`: the plugin couldn't be had (or its child died), so
/// its callbacks pass through for the rest of the request.
struct Channel {
    sock: OwnedFd,
    pid: i32,
}

static CHANNELS: Mutex<Option<HashMap<String, Option<Channel>>>> = Mutex::new(None);

/// At request end: close every child's socket; each child exits.
pub(crate) fn request_shutdown() {
    lock(&CHANNELS).take();
}

/// Whether the `zend_compile_file` wrapper is needed for layer 3: a worker with plugins to
/// isolate (live config).
pub(crate) fn isolating() -> bool {
    role() != Role::Helper && crate::with_live(|l| l.config.layer3.enabled && !l.config.layer3.isolate.is_empty()).unwrap_or(false)
}

/// What to do with an include.
pub(crate) enum Include {
    /// Not an isolated plugin's file (or this is its child): compile it as usual.
    Normal,
    /// An isolated plugin's file outside WordPress's own load: refuse it (as a missing file).
    Refuse,
    /// WordPress loading an isolated plugin: run this stand-in instead.
    Stub(*mut zend_op_array),
}

/// The decision for an include of `path` by the frame `current`.
pub(crate) fn include(path: &str, current: *const zend_execute_data) -> Include {
    if role() == Role::Helper {
        return Include::Normal;
    }
    let Some(live) = crate::live_arc() else { return Include::Normal };
    let l3 = &live.config.layer3;
    if !l3.enabled || l3.isolate.is_empty() {
        return Include::Normal;
    }
    let Component::Plugin(slug) = attribution::component_of(&live.root, path) else { return Include::Normal };
    if !l3.isolate.contains(&slug) {
        return Include::Normal;
    }
    let reason = if !includer_is_wp_settings(&live, current) {
        "isolated: its code runs only in its child"
    } else if role() != Role::Fpm || CONTROL.get().is_none() {
        "isolated, and there is no layer 3 helper in this process (php-fpm only)"
    } else {
        let op_array = stub(&slug, path);
        if !op_array.is_null() {
            return Include::Stub(op_array);
        }
        "isolated, and its stand-in did not compile"
    };
    log(LOG_WARNING, &format!("layer3 plugin:{slug} include refused {path} ({reason})"));
    Include::Refuse
}

/// The include comes from wp-settings.php, which loads the active plugins.
fn includer_is_wp_settings(live: &Loaded, current: *const zend_execute_data) -> bool {
    // SAFETY: the frame running the include, on the request's own thread.
    let file = unsafe { current.as_ref().and_then(|f| f.func.as_ref()).and_then(|func| attribution::zstr(func.op_array.filename)) };
    file.is_some_and(|f| f.ends_with("/wp-settings.php") && attribution::component_of(&live.root, f) == Component::Core)
}

/// A PHP single-quoted string literal.
fn php_quote(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// Compiles the stand-in for `slug`'s main file.
fn stub(slug: &str, file: &str) -> *mut zend_op_array {
    let body = STUB_PHP.trim_start().strip_prefix("<?php").unwrap_or(STUB_PHP);
    let source = body.replace("__SC_SLUG__", &php_quote(slug)).replace("__SC_FILE__", &php_quote(file));
    let Ok(name) = CString::new(format!("securecore-layer3:{slug}")) else { return std::ptr::null_mut() };
    let source = ZendStr::new(source, false);
    // SAFETY: a live zend_string and filename for the call; the engine copies what it keeps.
    unsafe { ext_php_rs::ffi::ext_php_rs_zend_compile_string(source.as_ptr().cast_mut(), name.as_ptr()) }
}

/// The snapshot's option names for this site (WordPress's own, minus the protected ones),
/// cached per worker by schema.php's mtime.
#[php_function]
pub fn securecore_layer3_snapshot_names(abspath: String, prefix: String, stylesheet: String) -> Vec<String> {
    /// schema.php's path and mtime, and the names read from it.
    type CoreNames = (PathBuf, Option<SystemTime>, std::collections::BTreeSet<String>);
    static CORE: Mutex<Option<CoreNames>> = Mutex::new(None);
    let schema = Path::new(&abspath).join("wp-admin/includes/schema.php");
    let mtime = std::fs::metadata(&schema).and_then(|m| m.modified()).ok();
    let mut cache = lock(&CORE);
    if cache.as_ref().is_none_or(|(p, t, _)| p != &schema || *t != mtime) {
        let names = std::fs::read_to_string(&schema).map(|s| options::core_option_names(&s)).unwrap_or_default();
        *cache = Some((schema, mtime, names));
    }
    let core = cache.as_ref().map(|(_, _, n)| n.clone()).unwrap_or_default();
    options::snapshot_allowlist(&core, &prefix, &stylesheet).into_iter().collect()
}

/// The worker's side of loading an isolated plugin: get a child for it from the helper, and
/// return what the plugin registered there (PHP-serialized), or null when it can't be had.
#[php_function]
pub fn securecore_layer3_open(slug: String, file: String, abspath: String, prefix: String, snapshot: &Zval) -> Zval {
    let mut out = Zval::new();
    let Some(live) = crate::live_arc() else { return out };
    if role() != Role::Fpm || !live.config.layer3.enabled || !live.config.layer3.isolate.contains(&slug) {
        return out;
    }
    let mut channels = lock(&CHANNELS);
    let channels = channels.get_or_insert_with(HashMap::new);
    if channels.contains_key(&slug) {
        return out;
    }
    let Some(&control) = CONTROL.get() else { return out };
    let snapshot = snapshot.zend_str().map(|s| s.as_bytes().to_vec()).unwrap_or_default();
    let hello = Hello {
        slug: slug.clone(),
        file,
        abspath,
        prefix,
        snapshot_sha: securecore_config::sha256_hex(&snapshot),
        config_sha: live.sha256.clone(),
    };
    let timeout = Duration::from_millis(u64::from(live.config.layer3.limits.timeout_ms.get()));
    match open(control, &hello, &snapshot, timeout) {
        Ok((channel, payload)) => {
            channels.insert(slug, Some(channel));
            out.set_binary(payload);
        }
        Err(e) => {
            log(LOG_WARNING, &format!("layer3 plugin:{slug} not loaded: {e}"));
            channels.insert(slug, None);
        }
    }
    out
}

fn open(control: RawFd, hello: &Hello, snapshot: &[u8], timeout: Duration) -> Result<(Channel, Vec<u8>), String> {
    let (ours, theirs) = wire::socketpair(libc::SOCK_STREAM).map_err(|e| format!("socketpair: {e}"))?;
    // SAFETY: the control socket, open for the process's life.
    let control = unsafe { BorrowedFd::borrow_raw(control) };
    wire::send_packet(control, b"R", Some(theirs.as_fd())).map_err(|e| format!("the helper is not reachable: {e}"))?;
    drop(theirs);
    let start = Instant::now();
    let fail = |what: &str, e: io::Error| {
        if e.kind() == io::ErrorKind::TimedOut { format!("timed out waiting for {what}") } else { format!("{what}: {e}") }
    };
    wire::write_frame(ours.as_fd(), &hello.encode()?, Some(start + HANDSHAKE)).map_err(|e| fail("the helper", e))?;
    let mut frame = wire::read_frame(ours.as_fd(), Some(start + HANDSHAKE + timeout)).map_err(|e| fail("the child", e))?;
    if frame.as_deref() == Some(wire::NEED_SNAPSHOT) {
        wire::write_frame(ours.as_fd(), snapshot, Some(Instant::now() + HANDSHAKE)).map_err(|e| fail("the helper", e))?;
        frame = wire::read_frame(ours.as_fd(), Some(Instant::now() + BOOT_ALLOWANCE + timeout)).map_err(|e| fail("the helper to boot", e))?;
    }
    let frame = frame.ok_or("the helper closed the request")?;
    if let Some(error) = frame.strip_prefix(wire::ERROR) {
        return Err(String::from_utf8_lossy(error).into_owned());
    }
    let (pid, payload) = wire::decode_ready(&frame).ok_or("the child's answer is not a ready frame")?;
    Ok((Channel { sock: ours, pid }, payload.to_vec()))
}

/// The worker's side of one call into an isolated plugin's callback `id`: the child's answer
/// (PHP-serialized), or null when the call failed (and the child is gone).
#[php_function]
pub fn securecore_layer3_call(slug: String, id: i64, args: &Zval) -> Zval {
    let mut out = Zval::new();
    let timeout_ms = crate::with_live(|l| l.config.layer3.limits.timeout_ms.get()).unwrap_or(5000);
    let mut channels = lock(&CHANNELS);
    let Some(slot) = channels.as_mut().and_then(|c| c.get_mut(&slug)) else { return out };
    let Some(channel) = slot.as_ref() else { return out };
    let mut body = format!("{id}\n").into_bytes();
    body.extend_from_slice(args.zend_str().map_or(&b""[..], |s| s.as_bytes()));
    let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
    let answer = wire::write_frame(channel.sock.as_fd(), &body, Some(deadline)).and_then(|()| wire::read_frame(channel.sock.as_fd(), Some(deadline)));
    match answer {
        Ok(Some(frame)) => out.set_binary(frame),
        Ok(None) => {
            log(LOG_WARNING, &format!("layer3 plugin:{slug} child {} ended during call {id}", channel.pid));
            *slot = None;
        }
        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
            log(LOG_WARNING, &format!("layer3 plugin:{slug} call {id} timed out after {timeout_ms} ms; child {} killed", channel.pid));
            if let Some(&control) = CONTROL.get() {
                // SAFETY: the control socket, open for the process's life.
                let _ = wire::send_packet(unsafe { BorrowedFd::borrow_raw(control) }, &wire::encode_kill(channel.pid), None);
            }
            *slot = None;
        }
        Err(e) => {
            log(LOG_WARNING, &format!("layer3 plugin:{slug} child {} failed during call {id}: {e}", channel.pid));
            *slot = None;
        }
    }
    out
}

// --- the helper: supervisor ---------------------------------------------------------------------

struct Zygote {
    pid: i32,
    chan: OwnedFd,
    snapshot_sha: String,
    draining: bool,
}

/// The helper's supervisor loop. Returns only in a newly forked zygote, with what it boots from:
/// `abspath`, `prefix` and `snapshot` (the PHP-serialized core options).
#[php_function]
pub fn securecore_layer3_helper() -> PhpResult<ZBox<ZendHashTable>> {
    if role() != Role::Helper {
        return Err("securecore_layer3_helper() runs only in the layer 3 helper".into());
    }
    // SAFETY: fd 3 is the control socket the extension put there before exec.
    let control = unsafe { OwnedFd::from_raw_fd(FD_CONTROL) };
    wire::pass_credentials(control.as_fd()).map_err(|e| format!("layer3 helper: fd {FD_CONTROL} is not the control socket: {e}"))?;
    let mut owner: Option<(u32, u32)> = None;
    let mut zygotes: Vec<Zygote> = Vec::new();
    loop {
        reap_zygotes(&mut zygotes);
        let packet = match wire::recv_packet(control.as_fd(), Some(Instant::now() + REAP_EVERY)) {
            Ok(Some(p)) => p,
            // php-fpm's master is gone (its end closed): so is the helper.
            Ok(None) => exit(0),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(e) => {
                log(LOG_WARNING, &format!("layer3 helper: control socket: {e}"));
                exit(1);
            }
        };
        let Some(creds) = packet.creds else { continue };
        match owner {
            None => {
                drop_privileges(creds);
                owner = Some(creds);
            }
            Some(o) if o != creds => {
                log(LOG_WARNING, &format!("layer3 helper: ignored a request from uid {} (serving uid {})", creds.0, o.0));
                continue;
            }
            Some(_) => {}
        }
        if wire::decode_kill(&packet.body).is_some() {
            for z in &zygotes {
                let _ = wire::send_packet(z.chan.as_fd(), &packet.body, None);
            }
            continue;
        }
        let (b"R", Some(fd)) = (packet.body.as_slice(), packet.fd) else { continue };
        match route(fd, &mut zygotes) {
            Ok(Some(boot)) => return Ok(boot),
            Ok(None) => {}
            Err(e) => log(LOG_WARNING, &format!("layer3 helper: {e}")),
        }
    }
}

fn exit(code: i32) -> ! {
    // SAFETY: leaves the helper without running PHP's shutdown (there is no request to finish).
    unsafe { libc::_exit(code) }
}

/// Runs the helper as the user php-fpm's workers run as (the first request's sender), never as
/// the master's root.
fn drop_privileges((uid, gid): (u32, u32)) {
    // SAFETY: plain credential syscalls in the single-threaded helper.
    unsafe {
        if libc::getuid() != 0 || uid == 0 {
            return;
        }
        if libc::setgroups(0, std::ptr::null()) != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
            log(LOG_WARNING, &format!("layer3 helper: could not drop to uid {uid}: {}", io::Error::last_os_error()));
            exit(1);
        }
    }
}

fn reap_zygotes(zygotes: &mut Vec<Zygote>) {
    loop {
        let mut status = 0;
        // SAFETY: reaping our own children.
        let pid = unsafe { libc::waitpid(-1, &raw mut status, libc::WNOHANG) };
        if pid <= 0 {
            return;
        }
        if let Some(i) = zygotes.iter().position(|z| z.pid == pid) {
            let z = zygotes.remove(i);
            if !z.draining {
                log(LOG_WARNING, &format!("layer3 helper: zygote {pid} {}", describe(status)));
            }
        }
    }
}

fn describe(status: i32) -> String {
    if libc::WIFSIGNALED(status) {
        format!("killed by signal {}", libc::WTERMSIG(status))
    } else {
        format!("exited with status {}", libc::WEXITSTATUS(status))
    }
}

/// Hands one request to the zygote booted from its snapshot, booting one first if there is none
/// (`Ok(Some(_))` is that new zygote, returning to PHP to boot).
fn route(fd: OwnedFd, zygotes: &mut Vec<Zygote>) -> Result<Option<ZBox<ZendHashTable>>, String> {
    let deadline = Some(Instant::now() + HANDSHAKE);
    let hello_bytes = wire::read_frame(fd.as_fd(), deadline).map_err(|e| format!("reading a hello: {e}"))?.ok_or("a worker closed before its hello")?;
    let hello = Hello::decode(&hello_bytes)?;
    let mut message = b"H".to_vec();
    message.extend_from_slice(&hello_bytes);
    if let Some(z) = zygotes.iter().find(|z| !z.draining && z.snapshot_sha == hello.snapshot_sha) {
        return wire::send_packet(z.chan.as_fd(), &message, Some(fd.as_fd())).map(|()| None).map_err(|e| format!("zygote {}: {e}", z.pid));
    }
    wire::write_frame(fd.as_fd(), wire::NEED_SNAPSHOT, deadline).map_err(|e| format!("asking for a snapshot: {e}"))?;
    let snapshot = wire::read_frame(fd.as_fd(), deadline).map_err(|e| format!("reading a snapshot: {e}"))?.ok_or("a worker closed before its snapshot")?;
    if securecore_config::sha256_hex(&snapshot) != hello.snapshot_sha {
        let _ = wire::write_frame(fd.as_fd(), b"error the snapshot does not match its hash", deadline);
        return Err("a snapshot did not match its hash".into());
    }
    // Every older zygote finishes the children it has, then exits.
    for z in zygotes.iter_mut().filter(|z| !z.draining) {
        let _ = wire::send_packet(z.chan.as_fd(), b"D", None);
        z.draining = true;
    }
    let (sup, zyg) = wire::socketpair(libc::SOCK_SEQPACKET).map_err(|e| format!("socketpair: {e}"))?;
    // SAFETY: fork in the single-threaded helper.
    match unsafe { libc::fork() } {
        -1 => Err(format!("fork: {}", io::Error::last_os_error())),
        0 => {
            // The zygote: keeps only its own channel (the control socket closes when the
            // supervisor's frame returns; the other zygotes' channels close here).
            drop(sup);
            zygotes.clear();
            *lock(&ZYGOTE) = Some(ZygoteState { chan: zyg, children: HashMap::new(), draining: false });
            let mut boot = ZendHashTable::new();
            boot.insert("abspath", hello.abspath.as_str()).map_err(|e| e.to_string())?;
            boot.insert("prefix", hello.prefix.as_str()).map_err(|e| e.to_string())?;
            let mut s = Zval::new();
            s.set_binary(snapshot);
            boot.insert("snapshot", s).map_err(|e| e.to_string())?;
            Ok(Some(boot))
        }
        pid => {
            drop(zyg);
            // Queued until the zygote has booted and starts reading.
            let sent = wire::send_packet(sup.as_fd(), &message, Some(fd.as_fd()));
            zygotes.push(Zygote { pid, chan: sup, snapshot_sha: hello.snapshot_sha, draining: false });
            sent.map(|()| None).map_err(|e| format!("zygote {pid}: {e}"))
        }
    }
}

// --- the helper: zygote -------------------------------------------------------------------------

struct ZygoteState {
    chan: OwnedFd,
    /// Live children: pid → slug.
    children: HashMap<i32, String>,
    draining: bool,
}

static ZYGOTE: Mutex<Option<ZygoteState>> = Mutex::new(None);

/// The zygote's loop, after WordPress booted. Returns only in a forked child, restricted and
/// acting as its plugin, with `slug`, `file` and `memory_mb`.
#[php_function]
pub fn securecore_layer3_zygote() -> PhpResult<ZBox<ZendHashTable>> {
    let mut state = lock(&ZYGOTE).take().ok_or("securecore_layer3_zygote() runs only in a layer 3 zygote")?;
    loop {
        reap_children(&mut state.children);
        if state.draining && state.children.is_empty() {
            exit(0);
        }
        let packet = match wire::recv_packet(state.chan.as_fd(), Some(Instant::now() + REAP_EVERY)) {
            Ok(Some(p)) => p,
            Ok(None) => {
                // The supervisor is gone: finish the children there are, then go.
                state.draining = true;
                while !state.children.is_empty() {
                    let mut status = 0;
                    // SAFETY: waiting for our own children.
                    let pid = unsafe { libc::waitpid(-1, &raw mut status, 0) };
                    if pid <= 0 {
                        break;
                    }
                    state.children.remove(&pid);
                }
                exit(0);
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(e) => {
                log(LOG_WARNING, &format!("layer3 zygote: {e}"));
                exit(1);
            }
        };
        match packet.body.first() {
            Some(b'D') => state.draining = true,
            Some(b'K') => {
                if let Some(pid) = wire::decode_kill(&packet.body)
                    && state.children.contains_key(&pid)
                {
                    // Our child, not yet reaped: the pid can't have been reused.
                    // SAFETY: a signal to our own child.
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                }
            }
            Some(b'H') => {
                let Some(fd) = packet.fd else { continue };
                let hello = match Hello::decode(&packet.body[1..]) {
                    Ok(h) => h,
                    Err(e) => {
                        log(LOG_WARNING, &format!("layer3 zygote: {e}"));
                        continue;
                    }
                };
                // SAFETY: fork in the single-threaded zygote.
                match unsafe { libc::fork() } {
                    -1 => {
                        let _ = wire::write_frame(fd.as_fd(), format!("error fork: {}", io::Error::last_os_error()).as_bytes(), None);
                    }
                    0 => {
                        drop(state);
                        return match become_child(&hello, fd.as_raw_fd()) {
                            Ok(info) => {
                                *lock(&CHILD_SOCK) = Some(fd);
                                Ok(info)
                            }
                            Err(e) => {
                                log(LOG_WARNING, &format!("layer3 plugin:{} child refused to start: {e}", hello.slug));
                                let _ = wire::write_frame(fd.as_fd(), format!("error {e}").as_bytes(), Some(Instant::now() + HANDSHAKE));
                                exit(1);
                            }
                        };
                    }
                    pid => {
                        state.children.insert(pid, hello.slug);
                    }
                }
            }
            _ => {}
        }
    }
}

fn reap_children(children: &mut HashMap<i32, String>) {
    loop {
        let mut status = 0;
        // SAFETY: reaping our own children.
        let pid = unsafe { libc::waitpid(-1, &raw mut status, libc::WNOHANG) };
        if pid <= 0 {
            return;
        }
        let slug = children.remove(&pid).unwrap_or_default();
        let clean = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        if !clean {
            log(LOG_WARNING, &format!("layer3 plugin:{slug} child {pid} {}", describe(status)));
        }
    }
}

// --- the helper: child --------------------------------------------------------------------------

/// The child's request socket.
static CHILD_SOCK: Mutex<Option<OwnedFd>> = Mutex::new(None);
/// The child's writable folders (resolved), for the layer 2 file check ([`child_write_refused`]).
static CHILD_WRITE: OnceLock<(String, Vec<PathBuf>)> = OnceLock::new();

/// Turns the freshly forked process into the plugin's child: config as the worker has it,
/// charged to the plugin, rlimits, and the gelada sandbox. Fails closed: the caller exits.
fn become_child(hello: &Hello, _sock: RawFd) -> Result<ZBox<ZendHashTable>, String> {
    if crate::live_arc().is_none_or(|l| l.sha256 != hello.config_sha) {
        crate::reload_now();
    }
    let live = crate::live_arc().ok_or("no config")?;
    let l3 = &live.config.layer3;
    if !l3.enabled || !l3.isolate.contains(&hello.slug) {
        return Err("not isolated in this config".into());
    }
    let resolve = |p: &str| {
        let p = live.resolve(p);
        std::fs::canonicalize(&p).unwrap_or(p)
    };
    let write: Vec<PathBuf> = l3.write.get(&hello.slug).map(|v| v.iter().map(|p| resolve(p)).collect()).unwrap_or_default();
    let vault_sources: Vec<PathBuf> =
        live.config.layer2.vault.as_ref().and_then(|v| v.from.as_ref()).map(|f| resolve(f.path())).into_iter().collect();
    let plan = Plan { write: write.clone(), deny: child::denied(&live.path, &vault_sources, Path::new(&hello.abspath)) };
    let memory_mb = l3.limits.memory_mb.get();
    let cpu_seconds = u64::from(l3.limits.timeout_ms.get()).div_ceil(1000);
    child::apply_rlimits(memory_mb, cpu_seconds).map_err(|e| format!("rlimits: {e}"))?;
    attribution::act_as(Component::Plugin(hello.slug.clone()));
    let _ = CHILD_WRITE.set((hello.slug.clone(), write));
    plan.restrict_self()?;
    let mut info = ZendHashTable::new();
    info.insert("slug", hello.slug.as_str()).map_err(|e| e.to_string())?;
    info.insert("file", hello.file.as_str()).map_err(|e| e.to_string())?;
    info.insert("memory_mb", i64::from(memory_mb)).map_err(|e| e.to_string())?;
    Ok(info)
}

/// In a child: a write to `path` outside its `layer3.write` folders is refused, with a line.
pub(crate) fn child_write_refused(op: &str, path: &Path) -> bool {
    let Some((slug, write)) = CHILD_WRITE.get() else { return false };
    if write.iter().any(|w| path.starts_with(w)) {
        return false;
    }
    log(LOG_NOTICE, &format!("layer3 plugin:{slug} {op} write-outside {}", path.display()));
    php_error(&ErrorType::Warning, &format!("securecore: plugin:{slug} may not {op} {} (layer3 write-outside)", path.display()));
    true
}

fn child_sock<R>(f: impl FnOnce(BorrowedFd<'_>) -> R) -> Option<R> {
    lock(&CHILD_SOCK).as_ref().map(|s| f(s.as_fd()))
}

/// The child's first frame to the worker: ready, its pid, and what the plugin registered.
#[php_function]
pub fn securecore_layer3_ready(payload: &Zval) -> bool {
    let bytes = payload.zend_str().map_or(&b""[..], |s| s.as_bytes());
    let frame = wire::encode_ready(std::process::id(), bytes);
    child_sock(|s| wire::write_frame(s, &frame, None).is_ok()).unwrap_or(false)
}

/// The child's answer to one call.
#[php_function]
pub fn securecore_layer3_send(payload: &Zval) -> bool {
    let bytes = payload.zend_str().map_or(&b""[..], |s| s.as_bytes());
    child_sock(|s| wire::write_frame(s, bytes, None).is_ok()).unwrap_or(false)
}

/// The child's next call from the worker, or null when the worker's request is over.
#[php_function]
pub fn securecore_layer3_recv() -> Zval {
    let mut out = Zval::new();
    if let Some(Ok(Some(frame))) = child_sock(|s| wire::read_frame(s, None)) {
        out.set_binary(frame);
    }
    out
}

/// Adds layer 3's functions to the module.
pub(crate) fn register(module: ModuleBuilder) -> ModuleBuilder {
    module
        .function(wrap_function!(securecore_layer3_snapshot_names))
        .function(wrap_function!(securecore_layer3_open))
        .function(wrap_function!(securecore_layer3_call))
        .function(wrap_function!(securecore_layer3_helper))
        .function(wrap_function!(securecore_layer3_zygote))
        .function(wrap_function!(securecore_layer3_ready))
        .function(wrap_function!(securecore_layer3_send))
        .function(wrap_function!(securecore_layer3_recv))
}
