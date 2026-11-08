//! Layer-2 enforcement (addiscorp/securecore#53, phase E2b): the file and process policy, put
//! into effect on PHP's streams and functions. The rules live in
//! [`securecore_attribution::policy`] (plain Rust, unit-tested); this module is the wiring.
//!
//! **File access goes through one C stream wrapper.** Every open of a plain path — `fopen`,
//! `file_get_contents`, `include`, `SplFileObject`, GD by filename, `error_log` type 3,
//! `libxml`, … — resolves a stream wrapper for its scheme, and a bare path resolves `"file"`.
//! `php_stream_locate_url_wrapper` (PHP 8.3) looks `"file"` up in the per-request wrapper table
//! `FG(stream_wrappers)` when it is set, which is how userland `stream_wrapper_unregister('file')`
//! replaces it. So at each request (once layer 2 is active) we register a volatile C `file`
//! wrapper whose ops check the policy and delegate to `php_plain_files_wrapper`'s ops. That is
//! the single checkpoint for everything that opens through PHP streams, metadata ops
//! (touch/chmod/chown via `stream_metadata`) included. Opcache-cached includes skip the open, so
//! the `zend_compile_file` wrapper in [`crate::attribution`] still covers them.
//!
//! **Function handlers cover only what does not go through a stream wrapper:** the process
//! functions, `symlink`/`link` (handled in `ext/standard/link.c`, not via wops), and
//! `stream_wrapper_register`/`unregister`/`restore` of `"file"` (which a component could use to
//! undo the override). Opens inside another extension's C code that call `open(2)` directly
//! (libzip's archive I/O) bypass streams and are not seen here; layer 1 (gelada) backstops them.
//!
//! A refused call fails the way PHP fails on a permission error — the opener returns NULL / the
//! op returns 0 (so the PHP function returns `false`), with a warning. `log` mode records and
//! lets it through; `off` does neither. Core is never restricted.
//!
//! Paths are resolved (symlinks followed) through PHP's realpath cache before the decision, so a
//! symlink under the root cannot smuggle a read or write past the prefix tests; protected files
//! are matched by (device, inode) so a hard link to one is caught too. A file about to be created
//! has no realpath, so [`resolve_new`] resolves its deepest existing ancestor and follows a
//! dangling symlink at the first new component — the path a write or a recursive `mkdir` actually
//! lands on, not the lexical path. `symlink()` itself is refused when its target is not writable.

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use ext_php_rs::error::php_error;
use ext_php_rs::ffi::{
    _zend_known_string_id_ZEND_STR_FILE as ZEND_STR_FILE, php_register_url_stream_wrapper_volatile, php_stream,
    php_stream_context, php_stream_statbuf, php_stream_wrapper, php_stream_wrapper_ops,
    php_unregister_url_stream_wrapper_volatile, zend_execute_data, zend_function, zend_hash_str_find_ptr_lc,
    zend_known_strings, zend_string, zval,
};
use ext_php_rs::flags::ErrorType;
use ext_php_rs::types::Zval;
use securecore_attribution::policy::{self, Access, Op, Policy};
use securecore_attribution::{Component, Rule, normalize, watch};
use securecore_config::Mode;

use crate::attribution;

unsafe extern "C" {
    /// The engine's built-in plain-files wrapper (main/php_streams.h). We read its ops and
    /// delegate to them; we never write it.
    static php_plain_files_wrapper: php_stream_wrapper;
    /// Resolve a path through the realpath cache (Zend/zend_virtual_cwd.h): the plain wrapper
    /// uses the same cache, so this stays cheap. `real_path` is a buffer of at least MAXPATHLEN.
    fn tsrm_realpath(path: *const c_char, real_path: *mut c_char) -> *mut c_char;
}

/// Process-execution functions, refused for a component unless its `exec` is true. `mail` is
/// here because it shells out through `sendmail_path` unless an SMTP transport is set up.
const PROCESS: &[&str] = &["exec", "shell_exec", "system", "passthru", "popen", "proc_open", "pcntl_exec", "mail"];
/// Link functions — not stream ops, handled directly in ext/standard/link.c.
const LINKS: &[&str] = &["symlink", "link"];
/// A component may not re-register, unregister or restore the `file` wrapper (it would undo us).
const WRAPPER_GUARDS: &[&str] = &["stream_wrapper_register", "stream_wrapper_unregister", "stream_wrapper_restore"];

/// A Zend internal-function handler.
type Zif = unsafe extern "C" fn(*mut zend_execute_data, *mut zval);

/// How deep a chain of not-yet-existing symlinks `resolve_new` follows before giving up and
/// deciding on the lexical path. A write or mkdir rarely passes through even one.
const SYMLINK_FOLLOW_MAX: u32 = 8;

/// The handlers we replaced, by lowercase function name. Set once per process; read lock-free.
static ORIGINALS: OnceLock<HashMap<String, Zif>> = OnceLock::new();
static INSTALLED: AtomicBool = AtomicBool::new(false);

fn lock<T>(m: &'static Mutex<T>) -> MutexGuard<'static, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Layer 2 is enforcing or logging right now: enabled, an app set, mode not `off`.
pub(crate) fn layer2_active() -> bool {
    crate::with_live(|l| {
        let l2 = &l.config.layer2;
        l2.enabled && l2.app.is_some() && l2.mode != Mode::Off
    })
    .unwrap_or(false)
}

// --- the file stream wrapper --------------------------------------------------------------------

/// A `php_stream_wrapper_ops` is not `Sync` (raw pointers); it is read-only after startup and
/// PHP is NTS, so wrap it to put it in a `static`.
struct SyncWops(php_stream_wrapper_ops);
// SAFETY: the ops table is initialised once at compile time and never mutated; PHP is NTS.
unsafe impl Sync for SyncWops {}

/// Our `file` wrapper's ops: every one checks the policy, then delegates to the plain wrapper.
static SC_WOPS: SyncWops = SyncWops(php_stream_wrapper_ops {
    stream_opener: Some(sc_stream_opener),
    stream_closer: Some(sc_stream_closer),
    stream_stat: Some(sc_stream_stat),
    url_stat: Some(sc_url_stat),
    dir_opener: Some(sc_dir_opener),
    label: std::ptr::null(),
    unlink: Some(sc_unlink),
    rename: Some(sc_rename),
    stream_mkdir: Some(sc_mkdir),
    stream_rmdir: Some(sc_rmdir),
    stream_metadata: Some(sc_metadata),
});

/// Our `file` wrapper. `wops` is set to `SC_WOPS` at install; `is_url` is 0, like the plain
/// wrapper (so allow_url_fopen gating is unchanged).
static mut SC_WRAPPER: php_stream_wrapper = php_stream_wrapper { wops: std::ptr::null(), abstract_: std::ptr::null_mut(), is_url: 0 };

/// The plain wrapper's ops, to delegate to.
///
/// # Safety
/// Read of the engine's immutable wrapper global.
unsafe fn plain() -> &'static php_stream_wrapper_ops {
    // SAFETY: php_plain_files_wrapper.wops is a valid static ops table for the process's life.
    unsafe { &*php_plain_files_wrapper.wops }
}

/// The interned `"file"` string (ZEND_STR_FILE), the protocol key.
///
/// # Safety
/// Read of the engine's known-strings table, populated at startup.
unsafe fn file_protocol() -> *mut zend_string {
    // SAFETY: zend_known_strings is a live array indexed by the known-string id.
    unsafe { *(*std::ptr::addr_of!(zend_known_strings)).add(ZEND_STR_FILE as usize) }
}

/// Register our volatile `file` wrapper for this request (after removing the plain one from the
/// per-request table, which creates that table as a copy of the global on first use).
unsafe fn register_file_wrapper() {
    // SAFETY: the volatile wrapper API on the request's own thread.
    unsafe {
        let protocol = file_protocol();
        php_unregister_url_stream_wrapper_volatile(protocol);
        php_register_url_stream_wrapper_volatile(protocol, std::ptr::addr_of_mut!(SC_WRAPPER));
    }
}

/// Remove our `file` wrapper for this request, so the plain one is active again (used around
/// `symlink`/`link`, which require the path to resolve to the plain wrapper).
unsafe fn unregister_file_wrapper() {
    // SAFETY: as above.
    unsafe { php_unregister_url_stream_wrapper_volatile(file_protocol()) };
}

// --- installing the function handlers -----------------------------------------------------------

/// At request start, when layer 2 is active: install the function handlers once per process, and
/// register the volatile `file` wrapper each request (volatile wrappers are per-request).
pub(crate) fn request_startup() {
    if !layer2_active() {
        return;
    }
    if !INSTALLED.load(Ordering::Relaxed) {
        INSTALLED.store(true, Ordering::Relaxed);
        // SAFETY: CG(function_table) on the request's own thread before userland runs.
        unsafe { install() };
    }
    // SAFETY: registering our per-request wrapper before userland opens anything.
    unsafe { register_file_wrapper() };
}

/// # Safety
/// Called once, from RINIT, before userland code runs this request.
unsafe fn install() {
    // Point our wrapper at our ops.
    // SAFETY: SC_WRAPPER is set once here before it is registered or read.
    unsafe { (*std::ptr::addr_of_mut!(SC_WRAPPER)).wops = std::ptr::addr_of!(SC_WOPS.0) };

    let ft = unsafe { (*std::ptr::addr_of_mut!(ext_php_rs::ffi::compiler_globals)).function_table };
    if ft.is_null() {
        return;
    }
    let mut originals = HashMap::new();
    for &name in PROCESS.iter().chain(LINKS).chain(WRAPPER_GUARDS) {
        let lc = name.to_ascii_lowercase();
        // SAFETY: a live function table and a byte string; the lookup is read-only.
        let ptr = unsafe { zend_hash_str_find_ptr_lc(ft.cast_const(), lc.as_ptr().cast(), lc.len()) };
        let Some(func) = (unsafe { ptr.cast::<zend_function>().as_mut() }) else { continue };
        // SAFETY: the entries we look up by name are internal functions (reading the union).
        let Some(previous) = (unsafe { func.internal_function.handler }) else { continue };
        func.internal_function.handler = Some(dispatch);
        originals.insert(name.to_string(), previous);
    }
    let _ = ORIGINALS.set(originals);
}

/// The replacement handler for the overridden (non-stream) functions.
unsafe extern "C" fn dispatch(execute_data: *mut zend_execute_data, return_value: *mut zval) {
    // SAFETY: a call frame for one of the functions we overrode; the name is the engine's own
    // lowercase key, borrowed.
    let name = unsafe { fn_name(execute_data) };
    if name.is_some_and(|n| unsafe { blocked(execute_data, n) }) {
        if let Some(rv) = unsafe { return_value.cast::<Zval>().as_mut() } {
            rv.set_bool(false);
        }
        return;
    }
    let Some(name) = name else { return };
    let Some(original) = ORIGINALS.get().and_then(|m| m.get(name).copied()) else { return };
    // symlink/link check the path against the plain wrapper, so our `file` wrapper must be out of
    // the way while the original runs; restore it after.
    if name == "symlink" || name == "link" {
        unsafe {
            unregister_file_wrapper();
            original(execute_data, return_value);
            register_file_wrapper();
        }
    } else {
        // SAFETY: the engine handler we replaced for this function.
        unsafe { original(execute_data, return_value) };
    }
}

/// Whether an overridden function call must be blocked (enforce + refuse).
///
/// # Safety
/// `ex` is the live call frame of `name`.
unsafe fn blocked(ex: *mut zend_execute_data, name: &str) -> bool {
    let from = unsafe { ex.as_ref() }.map_or(std::ptr::null(), |f| f.prev_execute_data);
    if PROCESS.contains(&name) {
        let Some(ctx) = slow(from) else { return false };
        let cmd = unsafe { arg_string(ex, 1) }.unwrap_or_else(|| name.to_owned());
        return refuse_decision(&ctx, Op::Exec, name, &cmd, ctx.policy.decide(&ctx.access, Op::Exec, Path::new(&cmd)));
    }
    if name == "symlink" {
        // The link path (arg 2) is a write of where the link sits, and a write *through* the link
        // lands on its target (arg 1, taken relative to the link's own directory) — so the target
        // must pass the write rule too: a link may point only where the component could write.
        let link = unsafe { guard_arg(ex, from, 2, Op::Write, "symlink") };
        let target = unsafe { guard_symlink_target(ex, from) };
        return link || target;
    }
    if name == "link" {
        // write the new path (arg 2), and never hard-link a protected file (arg 1, a read).
        let w = unsafe { guard_arg(ex, from, 2, Op::Write, "link") };
        let t = unsafe { guard_arg(ex, from, 1, Op::Read, "link-target") };
        return w || t;
    }
    if WRAPPER_GUARDS.contains(&name) {
        if unsafe { arg_string(ex, 1) }.as_deref() != Some("file") {
            return false;
        }
        let Some(ctx) = slow(from) else { return false }; // core may manage wrappers
        return refuse_decision(&ctx, Op::Write, name, "file", policy::Decision::Refuse("wrapper"));
    }
    false
}

/// Guard argument `n` (a path) of a call frame for `op`.
///
/// # Safety
/// `ex` is a live call frame.
unsafe fn guard_arg(ex: *mut zend_execute_data, from: *const zend_execute_data, n: u32, op: Op, token: &str) -> bool {
    let Some(path) = (unsafe { arg_string(ex, n) }) else { return false };
    guard(from, op, token, resolve_str(&path), Inode::Stat)
}

/// Guard the effective target of `symlink(target, link)` as a write. A relative target is
/// interpreted relative to the link's own directory (not the cwd), so a write through the link
/// lands there — that is the path the write rule must clear.
///
/// # Safety
/// `ex` is the live `symlink` call frame.
unsafe fn guard_symlink_target(ex: *mut zend_execute_data, from: *const zend_execute_data) -> bool {
    let (Some(target), Some(link)) = (unsafe { arg_string(ex, 1) }, unsafe { arg_string(ex, 2) }) else {
        return false;
    };
    let target = Path::new(&target);
    let effective = if target.is_absolute() {
        target.to_owned()
    } else {
        let Some(dir) = abs_parent(&link) else { return false };
        dir.join(target)
    };
    guard(from, Op::Write, "symlink-target", resolve_str(&effective.to_string_lossy()), Inode::Stat)
}

/// The absolute parent directory of a path given as a string (a relative path against the cwd).
fn abs_parent(path: &str) -> Option<PathBuf> {
    let p = Path::new(path);
    let abs = if p.is_absolute() { p.to_owned() } else { std::env::current_dir().ok()?.join(p) };
    abs.parent().map(Path::to_owned)
}

// --- the stream wrapper ops ---------------------------------------------------------------------

// The opener/dir_opener signatures have no STREAMS_DC tail in a non-debug (production) PHP build.
unsafe extern "C" fn sc_stream_opener(
    wrapper: *mut php_stream_wrapper,
    filename: *const c_char,
    mode: *const c_char,
    options: c_int,
    opened_path: *mut *mut zend_string,
    context: *mut php_stream_context,
) -> *mut php_stream {
    let op = if unsafe { mode_writes(mode) } { Op::Write } else { Op::Read };
    if unsafe { guard_c(filename, op, "open") } {
        return std::ptr::null_mut();
    }
    let Some(opener) = (unsafe { plain() }).stream_opener else { return std::ptr::null_mut() };
    // SAFETY: delegating to the plain opener with the arguments unchanged.
    unsafe { opener(wrapper, filename, mode, options, opened_path, context) }
}

unsafe extern "C" fn sc_dir_opener(
    wrapper: *mut php_stream_wrapper,
    filename: *const c_char,
    mode: *const c_char,
    options: c_int,
    opened_path: *mut *mut zend_string,
    context: *mut php_stream_context,
) -> *mut php_stream {
    if unsafe { guard_c(filename, Op::Read, "opendir") } {
        return std::ptr::null_mut();
    }
    let Some(opener) = (unsafe { plain() }).dir_opener else { return std::ptr::null_mut() };
    // SAFETY: delegating unchanged.
    unsafe { opener(wrapper, filename, mode, options, opened_path, context) }
}

unsafe extern "C" fn sc_unlink(wrapper: *mut php_stream_wrapper, url: *const c_char, options: c_int, context: *mut php_stream_context) -> c_int {
    if unsafe { guard_c(url, Op::Write, "unlink") } {
        return 0;
    }
    let Some(f) = (unsafe { plain() }).unlink else { return 0 };
    unsafe { f(wrapper, url, options, context) }
}

unsafe extern "C" fn sc_rename(wrapper: *mut php_stream_wrapper, from: *const c_char, to: *const c_char, options: c_int, context: *mut php_stream_context) -> c_int {
    if unsafe { guard_c(from, Op::Write, "rename") } || unsafe { guard_c(to, Op::Write, "rename") } {
        return 0;
    }
    let Some(f) = (unsafe { plain() }).rename else { return 0 };
    unsafe { f(wrapper, from, to, options, context) }
}

unsafe extern "C" fn sc_mkdir(wrapper: *mut php_stream_wrapper, url: *const c_char, mode: c_int, options: c_int, context: *mut php_stream_context) -> c_int {
    if unsafe { guard_c(url, Op::Write, "mkdir") } {
        return 0;
    }
    let Some(f) = (unsafe { plain() }).stream_mkdir else { return 0 };
    unsafe { f(wrapper, url, mode, options, context) }
}

unsafe extern "C" fn sc_rmdir(wrapper: *mut php_stream_wrapper, url: *const c_char, options: c_int, context: *mut php_stream_context) -> c_int {
    if unsafe { guard_c(url, Op::Write, "rmdir") } {
        return 0;
    }
    let Some(f) = (unsafe { plain() }).stream_rmdir else { return 0 };
    unsafe { f(wrapper, url, options, context) }
}

unsafe extern "C" fn sc_metadata(wrapper: *mut php_stream_wrapper, url: *const c_char, options: c_int, value: *mut std::ffi::c_void, context: *mut php_stream_context) -> c_int {
    if unsafe { guard_c(url, Op::Write, "metadata") } {
        return 0;
    }
    let Some(f) = (unsafe { plain() }).stream_metadata else { return 0 };
    unsafe { f(wrapper, url, options, value, context) }
}

// url_stat (file_exists/stat), stream_stat and stream_closer are read-metadata or operate on an
// already-opened stream: delegate unchanged.
unsafe extern "C" fn sc_url_stat(wrapper: *mut php_stream_wrapper, url: *const c_char, flags: c_int, ssb: *mut php_stream_statbuf, context: *mut php_stream_context) -> c_int {
    let Some(f) = (unsafe { plain() }).url_stat else { return -1 };
    unsafe { f(wrapper, url, flags, ssb, context) }
}

unsafe extern "C" fn sc_stream_stat(wrapper: *mut php_stream_wrapper, stream: *mut php_stream, ssb: *mut php_stream_statbuf) -> c_int {
    let Some(f) = (unsafe { plain() }).stream_stat else { return -1 };
    unsafe { f(wrapper, stream, ssb) }
}

unsafe extern "C" fn sc_stream_closer(wrapper: *mut php_stream_wrapper, stream: *mut php_stream) -> c_int {
    let Some(f) = (unsafe { plain() }).stream_closer else { return 0 };
    unsafe { f(wrapper, stream) }
}

// --- the decision -------------------------------------------------------------------------------

/// Whether `op` on `cpath` (from the wrapper, caller = EG(current_execute_data)) must be blocked.
///
/// # Safety
/// `cpath` is a valid NUL-terminated path from the engine.
unsafe fn guard_c(cpath: *const c_char, op: Op, token: &str) -> bool {
    let from = current_execute_data();
    guard(from, op, token, unsafe { resolve_c(cpath) }, Inode::Stat)
}

/// Whether a protected file is also matched by inode (catching a hard link), and when.
#[derive(Clone, Copy)]
enum Inode {
    /// Always stat — wrapper ops and `symlink`/`link`; not the hot path.
    Stat,
    /// Stat only for a path *outside* the code directories — includes. Keeps the include hot
    /// path (a file under plugins/mu-plugins/themes) off the stat, while still catching a hard
    /// link to a protected file included from elsewhere. A component can no longer make such a
    /// link (`link()` is refused), so a residual link under a code directory is the only gap.
    StatUnlessCode,
}

/// The decision for a resolved path. The fast path (an allowed read/include under the root, or a
/// write to uploads/cache) never walks the stack; only a protected file or an op the baseline
/// can't clear does. The baseline is the authority on "protected" (path *and* inode); the policy
/// (plain Rust) only does path-based protection, so protection is settled here, not there.
fn guard(from: *const zend_execute_data, op: Op, token: &str, resolved: Option<PathBuf>, inode: Inode) -> bool {
    let Some(resolved) = resolved else { return false }; // unresolvable: let the plain op report it
    match classify(op, &resolved, inode) {
        None => false,            // layer 2 not active
        Some(Verdict::Allow) => false,
        Some(Verdict::Protected) => {
            // Refused for a component; core (slow() → None) may read/write it.
            let Some(ctx) = slow(from) else { return false };
            let rule = if op == Op::Write { "write-protected" } else { "read-protected" };
            apply(ctx.mode, &ctx.component.to_string(), token, &resolved.display().to_string(), rule)
        }
        Some(Verdict::Check) => {
            let Some(ctx) = slow(from) else { return false };
            refuse_decision(&ctx, op, token, &resolved.display().to_string(), ctx.policy.decide(&ctx.access, op, &resolved))
        }
    }
}

/// Record a refusal (both modes) and say whether to block it (enforce only).
fn refuse_decision(ctx: &Slow, _op: Op, token: &str, path: &str, decision: policy::Decision) -> bool {
    let policy::Decision::Refuse(rule) = decision else { return false };
    apply(ctx.mode, &ctx.component.to_string(), token, path, rule)
}

fn apply(mode: Mode, component: &str, op: &str, path: &str, rule: &str) -> bool {
    audit(mode, component, op, path, rule);
    if mode == Mode::Enforce {
        warn(component, op, path, rule);
        true
    } else {
        false
    }
}

// --- the baseline and the fast path -------------------------------------------------------------

/// The site facts a decision rests on, cached per config (keyed by its sha256): the root, the
/// uploads and cache folders (resolved), and the protected files by path and by (dev, inode).
struct Baseline {
    sha: String,
    root: PathBuf,
    uploads: PathBuf,
    cache: PathBuf,
    /// The plugins, mu-plugins and themes directories — where almost every include lives. Used to
    /// keep the include hot path off the inode stat (see [`include_blocked`]).
    code_dirs: Vec<PathBuf>,
    protected: Vec<PathBuf>,
    protected_ids: Vec<(u64, u64)>,
}

impl Baseline {
    fn is_protected(&self, resolved: &Path, inode_check: bool) -> bool {
        if self.protected.iter().any(|p| p == resolved) {
            return true;
        }
        // A hard link has its own path but the protected file's inode. The stat is skipped for an
        // include under a code directory (the hot path; see `Inode::StatUnlessCode`): a component
        // can no longer create such a link, and including a protected file re-runs it rather than
        // disclosing its bytes.
        inode_check && std::fs::metadata(resolved).is_ok_and(|m| self.protected_ids.contains(&(m.dev(), m.ino())))
    }
}

static BASELINE: Mutex<Option<Baseline>> = Mutex::new(None);

/// Run `f` against the baseline for the live config, rebuilt only on a reload. `None` when layer
/// 2 is not active. The lock is held across `f`, so `f` is the fast-path check.
fn with_baseline<R>(f: impl FnOnce(&Baseline) -> R) -> Option<R> {
    let loaded = crate::live_arc()?;
    let l2 = &loaded.config.layer2;
    if !l2.enabled || l2.app.is_none() || l2.mode == Mode::Off {
        return None;
    }
    let mut guard = lock(&BASELINE);
    if guard.as_ref().map(|b| b.sha.as_str()) != Some(loaded.sha256.as_str()) {
        let layout = attribution::layout(&loaded.root);
        let resolve_cfg = |p: &Path| resolve_str(&p.to_string_lossy()).unwrap_or_else(|| normalize(p));
        let mut protected = vec![resolve_cfg(&loaded.path)];
        if let Some(vault) = &l2.vault {
            protected.push(resolve_cfg(&loaded.resolve(&vault.from)));
        }
        let protected_ids = protected.iter().filter_map(|p| std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()))).collect();
        *guard = Some(Baseline {
            sha: loaded.sha256.clone(),
            root: resolve_cfg(&loaded.root),
            uploads: resolve_cfg(&layout.content.join("uploads")),
            cache: resolve_cfg(&layout.content.join("cache")),
            code_dirs: [&layout.plugins, &layout.mu_plugins, &layout.themes].map(|d| resolve_cfg(d)).into(),
            protected,
            protected_ids,
        });
    }
    Some(f(guard.as_ref().unwrap_or_else(|| unreachable!("set above"))))
}

/// What the baseline alone can say about an op on a resolved path.
enum Verdict {
    /// Allowed for any component: a read/include under the root, or a write to uploads/cache.
    Allow,
    /// A protected file (by path or inode): refused for a component, allowed for core.
    Protected,
    /// The baseline can't clear it (outside the root, a write elsewhere, exec): ask the policy.
    Check,
}

/// `None` when layer 2 is not active. Protected is checked first, so a hard link or symlink to a
/// protected file is caught before the under-root allow.
fn classify(op: Op, resolved: &Path, inode: Inode) -> Option<Verdict> {
    with_baseline(|b| {
        let stat = match inode {
            Inode::Stat => true,
            Inode::StatUnlessCode => !b.code_dirs.iter().any(|d| under_or_eq(resolved, d)),
        };
        if b.is_protected(resolved, stat) {
            return Verdict::Protected;
        }
        match op {
            Op::Read if under_or_eq(resolved, &b.root) => Verdict::Allow,
            Op::Write if under_or_eq(resolved, &b.uploads) || under_or_eq(resolved, &b.cache) => Verdict::Allow,
            _ => Verdict::Check,
        }
    })
}

// --- the slow path ------------------------------------------------------------------------------

struct Slow {
    component: Component,
    access: Access,
    mode: Mode,
    policy: Policy,
}

fn slow(from: *const zend_execute_data) -> Option<Slow> {
    let loaded = crate::live_arc()?;
    let l2 = &loaded.config.layer2;
    if !l2.enabled || l2.app.is_none() || l2.mode == Mode::Off {
        return None;
    }
    let rule = attribution::settings().map_or(Rule::Component, |s| s.rule);
    let component = attribution::responsible(rule, &loaded.root, from);
    // None here means core or code outside the root: not a restricted component.
    let access = policy::access_for(l2, &loaded.root, &component)?;
    let policy = with_baseline(|b| Policy::new(b.root.clone(), b.uploads.clone(), b.cache.clone(), b.protected.clone()))?;
    Some(Slow { component, access, mode: l2.mode, policy })
}

/// The read-policy decision for an include/require of `path` by the code at `from`. Used by the
/// `zend_compile_file` wrapper in [`crate::attribution`].
///
/// Includes are the hot path, so the inode stat (which catches a hard link to a protected file) is
/// skipped for the common case — a file under plugins, mu-plugins or themes — and run only for an
/// include whose resolved path lands elsewhere, which is rare. The protected *path* is always
/// matched; a component can no longer create a hard link (`link()` is refused), so a residual hard
/// link under a code directory is the only gap, noted in the README.
pub(crate) fn include_blocked(op: &str, path: &str, from: *const zend_execute_data) -> bool {
    guard(from, Op::Read, op, resolve_str(path), Inode::StatUnlessCode)
}

/// `securecore_status()` is for core. In `enforce` mode a component's call is refused; in `log`
/// mode it is recorded and allowed. `caller` is the component token who-is-running computed.
pub(crate) fn status_only_core(caller: &str) -> Option<String> {
    let loaded = crate::live_arc()?;
    let l2 = &loaded.config.layer2;
    if !l2.enabled || l2.app.is_none() || l2.mode == Mode::Off {
        return None;
    }
    if apply(l2.mode, caller, "securecore_status", "", "core-only") {
        Some("securecore_status() is callable only from core".to_owned())
    } else {
        None
    }
}

// --- path resolution ----------------------------------------------------------------------------

/// Resolve a path from the wrapper (NUL-terminated) through the realpath cache, following
/// symlinks. `None` only if it cannot be made into a path at all.
///
/// # Safety
/// `cpath` is a valid NUL-terminated string.
unsafe fn resolve_c(cpath: *const c_char) -> Option<PathBuf> {
    // The whole path, via the realpath cache, with no allocation (already NUL-terminated).
    if let Some(r) = resolve_existing(cpath) {
        return Some(r);
    }
    // A path that does not exist yet (a new file being written): resolve via its parent.
    let s = unsafe { CStr::from_ptr(cpath) }.to_str().ok()?;
    resolve_new(Path::new(s))
}

/// Resolve a path given as a Rust string (includes, symlink/link args).
fn resolve_str(path: &str) -> Option<PathBuf> {
    let plain = watch::plain_path(path)?; // skip php://, https:// …
    let c = CString::new(plain).ok()?;
    if let Some(r) = resolve_existing(c.as_ptr()) {
        return Some(r);
    }
    resolve_new(Path::new(plain))
}

/// `tsrm_realpath` on an existing path, or `None`.
fn resolve_existing(cpath: *const c_char) -> Option<PathBuf> {
    let mut buf = [0u8; 4096];
    // SAFETY: cpath is NUL-terminated; buf is MAXPATHLEN.
    let r = unsafe { tsrm_realpath(cpath, buf.as_mut_ptr().cast()) };
    if r.is_null() {
        return None;
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..len])))
}

/// A path that does not exist as a whole (a file or folder about to be created): resolve its
/// deepest existing ancestor through the realpath cache (so every symlink in it is followed), then
/// append the rest. Two cases the plain parent-resolve missed:
///   * the final component is itself a *dangling* symlink — it exists to `lstat` but not to
///     realpath, and a write or `mkdir` follows it, so we read the link and decide on its target
///     (`symlink('../other/x', uploads/link); fwrite(uploads/link)` writes `other/x`);
///   * a recursive `mkdir` through a symlinked ancestor whose own parent doesn't exist
///     (`mkdir(uploads/link/a/b)` with `uploads/link -> ../other` creates folders in `other`).
///
/// Bounded by [`SYMLINK_FOLLOW_MAX`]; falls back to the lexical path.
fn resolve_new(abs: &Path) -> Option<PathBuf> {
    let abs = if abs.is_absolute() { abs.to_owned() } else { std::env::current_dir().ok()?.join(abs) };
    Some(resolve_tail(abs, 0))
}

/// Resolve `abs` by finding its deepest existing ancestor and appending the non-existing tail,
/// following a dangling symlink at the first tail component (which is where a write lands).
fn resolve_tail(abs: PathBuf, depth: u32) -> PathBuf {
    if depth > SYMLINK_FOLLOW_MAX {
        return normalize(&abs);
    }
    // Walk up until a prefix resolves; `tail` collects the non-existing names, outermost last.
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = abs.as_path();
    loop {
        if let Ok(c) = CString::new(cur.as_os_str().as_bytes())
            && let Some(rp) = resolve_existing(c.as_ptr())
        {
            let Some(first) = tail.pop() else { return rp }; // the whole path resolved
            let here = rp.join(&first);
            // A dangling symlink at the first not-yet-existing component: a write follows it.
            if let Ok(meta) = std::fs::symlink_metadata(&here)
                && meta.file_type().is_symlink()
                && let Ok(target) = std::fs::read_link(&here)
            {
                let base = if target.is_absolute() { target } else { rp.join(target) };
                let next = tail.iter().rev().fold(base, |p, c| p.join(c));
                return resolve_tail(next, depth + 1);
            }
            // Genuinely new: lexical from the resolved ancestor.
            return tail.iter().rev().fold(here, |p, c| p.join(c));
        }
        match cur.parent() {
            Some(p) if p != cur => {
                if let Some(name) = cur.file_name() {
                    tail.push(name.to_owned());
                }
                cur = p;
            }
            _ => return normalize(&abs),
        }
    }
}

// --- helpers ------------------------------------------------------------------------------------

fn under_or_eq(path: &Path, base: &Path) -> bool {
    path == base || path.starts_with(base)
}

/// Whether an fopen-style mode creates or changes the file.
///
/// # Safety
/// `mode` is NUL-terminated or null.
unsafe fn mode_writes(mode: *const c_char) -> bool {
    if mode.is_null() {
        return false;
    }
    unsafe { CStr::from_ptr(mode) }.to_bytes().iter().any(|b| matches!(b, b'w' | b'a' | b'x' | b'c' | b'+'))
}

fn current_execute_data() -> *const zend_execute_data {
    // SAFETY: EG(current_execute_data) on the request's own thread.
    unsafe { (*std::ptr::addr_of!(ext_php_rs::ffi::executor_globals)).current_execute_data }
}

fn audit(mode: Mode, component: &str, op: &str, path: &str, rule: &str) {
    crate::log(crate::LOG_NOTICE, &format!("layer2 {} {component} {op} {rule} {path}", mode.as_str()));
}

fn warn(component: &str, op: &str, path: &str, rule: &str) {
    php_error(&ErrorType::Warning, &format!("securecore: {component} may not {op} {path} ({rule})"));
}

/// Function name of a call frame (already lowercase in the table), borrowed.
///
/// # Safety
/// `ex` is a live call frame.
unsafe fn fn_name(ex: *mut zend_execute_data) -> Option<&'static str> {
    let func = unsafe { ex.as_ref()?.func.as_ref()? };
    attribution::zstr(unsafe { func.common.function_name })
}

/// Argument `n` (1-based) of a call frame as a string, when present.
///
/// # Safety
/// `ex` is a live call frame.
unsafe fn arg_string(ex: *mut zend_execute_data, n: u32) -> Option<String> {
    let argc = unsafe { ex.as_ref() }.map_or(0, |f| unsafe { f.This.u2.num_args });
    if n > argc {
        return None;
    }
    unsafe { attribution::arg(ex, n) }.and_then(Zval::str).map(str::to_owned)
}
