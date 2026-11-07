//! Layer-2 enforcement (addiscorp/securecore#53, phase E2b): the file and process policy, put
//! into effect on PHP's own functions. The rules live in [`securecore_attribution::policy`]
//! (plain Rust, unit-tested); this module is the wiring to the engine.
//!
//! Where the checks sit, and why here and not a stream wrapper. Every file open PHP code makes
//! is a call to a file function (fopen, file_get_contents, unlink, …) or an include; a stream
//! wrapper would see only `file://` and user schemes, because a bare path — almost all real
//! paths — is served by the built-in plain-files wrapper, a `const` the engine returns directly
//! and never consults a registry for. So the one place every bare-path open passes through is
//! the function it was called from. At the first request of a worker (once layer 2 is active)
//! we replace the handlers of the watched file functions and the process functions with
//! [`dispatch`], and the `zend_compile_file` wrapper in [`crate::attribution`] covers include
//! and require. Opens made inside another extension's C code (GD, Zip) and the OO file classes
//! (`SplFileObject`, `DirectoryIterator`) do not pass through a function handler and are not
//! enforced here; see the PR for the full coverage list.
//!
//! In `enforce` mode a refused call is blocked and fails the way PHP fails on a permission
//! error — a warning, and `false` (the include stops as a missing file would). In `log` mode
//! the would-be refusal is written to the error log and the call proceeds. Core is never
//! checked.
//!
//! Cost. Almost every op is a read or include under the app root, or a write to uploads — all
//! allowed for any component. Those take the [`fast`] path: a lexical path check against a
//! baseline cached per config (no `stat`/`canonicalize`, no stack walk). Only an op that the
//! fast path can't clear — a read outside the root, a write elsewhere, a process call — takes
//! the slow path, which resolves the path and walks the stack to find the component.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use ext_php_rs::error::php_error;
use ext_php_rs::ffi::{zend_execute_data, zend_function, zend_hash_str_find_ptr_lc, zval};
use ext_php_rs::flags::ErrorType;
use ext_php_rs::types::Zval;
use securecore_attribution::policy::{self, Access, Op, Policy};
use securecore_attribution::{Component, Rule, normalize, real_path, watch};
use securecore_config::Mode;

use crate::attribution;

/// The process-execution functions, refused for a component unless its `exec` is true. `mail`
/// is here because it shells out through `sendmail_path` unless an SMTP transport is set up.
const PROCESS: &[&str] = &["exec", "shell_exec", "system", "passthru", "popen", "proc_open", "pcntl_exec", "mail"];

/// A Zend internal-function handler.
type Zif = unsafe extern "C" fn(*mut zend_execute_data, *mut zval);

/// The handlers we replaced, by lowercase function name, so [`dispatch`] can call through when a
/// call is allowed. Set once per process at [`request_startup`]; read lock-free after.
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

// --- installing the handlers --------------------------------------------------------------------

/// At request start: once per process, when layer 2 is active, replace the handlers of the file
/// and process functions with [`dispatch`]. Internal functions live in one table for the whole
/// process; php-fpm forks workers after this, and opcache does not touch handlers, so the one
/// install holds for every request a worker serves. Installing on the first *active* request
/// (not strictly the first) means enabling layer 2 by a reload takes effect without a restart.
pub(crate) fn request_startup() {
    if INSTALLED.load(Ordering::Relaxed) || !layer2_active() {
        return;
    }
    INSTALLED.store(true, Ordering::Relaxed);
    // SAFETY: CG(function_table), the process's function table, reached on the request's own
    // thread before any userland code of this request has run.
    unsafe { install() };
}

/// # Safety
/// Called once, from RINIT, before userland code runs this request.
unsafe fn install() {
    let ft = unsafe { (*std::ptr::addr_of_mut!(ext_php_rs::ffi::compiler_globals)).function_table };
    if ft.is_null() {
        return;
    }
    let file_funcs = watch::WATCHED.iter().filter(|w| w.class.is_none()).map(|w| w.function);
    let mut originals = HashMap::new();
    for name in file_funcs.chain(PROCESS.iter().copied()) {
        let lc = name.to_ascii_lowercase();
        // SAFETY: a live function table and a byte string; the lookup is read-only.
        let ptr = unsafe { zend_hash_str_find_ptr_lc(ft.cast_const(), lc.as_ptr().cast(), lc.len()) };
        // A function not registered (e.g. pcntl_exec without ext/pcntl) is simply skipped.
        let Some(func) = (unsafe { ptr.cast::<zend_function>().as_mut() }) else { continue };
        // SAFETY: the entries we look up by name are internal functions (reading the union).
        let Some(previous) = (unsafe { func.internal_function.handler }) else { continue };
        // Writing a union field is safe; it is the read above that needs `unsafe`.
        func.internal_function.handler = Some(dispatch);
        originals.insert(name.to_string(), previous);
    }
    let _ = ORIGINALS.set(originals);
}

/// The replacement handler for every overridden function: check the policy, then either block
/// (enforce) or call through.
unsafe extern "C" fn dispatch(execute_data: *mut zend_execute_data, return_value: *mut zval) {
    // SAFETY: a call frame for one of the functions we overrode. The name is the engine's own
    // lowercase key, borrowed (no allocation on the hot path).
    let name = unsafe { fn_name(execute_data) };
    if name.is_some_and(|n| unsafe { blocked(execute_data, n) }) {
        // Fail as PHP does on a permission error: blocked() has emitted the warning; return false.
        if let Some(rv) = unsafe { return_value.cast::<Zval>().as_mut() } {
            rv.set_bool(false);
        }
        return;
    }
    let original = name.and_then(|n| ORIGINALS.get().and_then(|m| m.get(n).copied()));
    if let Some(original) = original {
        // SAFETY: the engine handler we replaced for this function, called with its own frame.
        unsafe { original(execute_data, return_value) };
    }
}

// --- the baseline and the fast path -------------------------------------------------------------

/// The site facts a decision rests on that do not change within a config: the root, the uploads
/// and cache folders, and the protected files. Cached per config (keyed by its sha256) and
/// rebuilt only when the file reloads, so the fast path does no filesystem work per op.
struct Baseline {
    sha: String,
    root: PathBuf,
    uploads: PathBuf,
    cache: PathBuf,
    protected: Vec<PathBuf>,
}

static BASELINE: Mutex<Option<Baseline>> = Mutex::new(None);

/// Run `f` against the baseline for the live config, rebuilding it only on a reload. `None` when
/// layer 2 is not active. The lock is held across `f`, so `f` is just the fast-path check.
fn with_baseline<R>(f: impl FnOnce(&Baseline) -> R) -> Option<R> {
    let loaded = crate::live_arc()?;
    let l2 = &loaded.config.layer2;
    if !l2.enabled || l2.app.is_none() || l2.mode == Mode::Off {
        return None;
    }
    let mut guard = lock(&BASELINE);
    if guard.as_ref().map(|b| b.sha.as_str()) != Some(loaded.sha256.as_str()) {
        let layout = attribution::layout(&loaded.root);
        let mut protected = vec![real_path(&loaded.path)];
        if let Some(vault) = &l2.vault {
            protected.push(real_path(&loaded.resolve(&vault.from)));
        }
        *guard = Some(Baseline {
            sha: loaded.sha256.clone(),
            root: real_path(&loaded.root),
            uploads: real_path(&layout.content.join("uploads")),
            cache: real_path(&layout.content.join("cache")),
            protected,
        });
    }
    Some(f(guard.as_ref().unwrap_or_else(|| unreachable!("set above"))))
}

/// The fast decision for a lexically-normalized path: `Some(true)` = allow outright,
/// `Some(false)` = can't tell cheaply, use the slow path, `None` = layer 2 off. It only ever
/// short-circuits to *allow* (reads under the root, writes to uploads/cache); anything it can't
/// clear falls to [`slow`], which is the precise decision, so resolving symlinks lexically here
/// can at worst cost a slow-path trip, never a wrong allow.
fn fast(op: Op, lex: &Path) -> Option<bool> {
    with_baseline(|b| match op {
        Op::Read => !b.protected.iter().any(|p| p == lex) && under_or_eq(lex, &b.root),
        Op::Write => under_or_eq(lex, &b.uploads) || under_or_eq(lex, &b.cache),
        Op::Exec => false,
    })
}

// --- the slow path ------------------------------------------------------------------------------

/// What the slow path needs: the responsible component, its access, the mode and the policy
/// (built from the cached baseline). Computed only when the fast path can't clear an op.
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

impl Slow {
    /// Decide `op` on `path` precisely, record a refusal, and say whether to block it.
    fn evaluate(&self, op: Op, op_token: &str, path: &Path) -> bool {
        let decision = self.policy.decide(&self.access, op, path);
        let policy::Decision::Refuse(rule) = decision else { return false };
        apply(self.mode, &self.component.to_string(), op_token, &path.display().to_string(), rule)
    }
}

/// Record a refusal (both modes) and say whether to block it (enforce only).
fn apply(mode: Mode, component: &str, op: &str, path: &str, rule: &str) -> bool {
    audit(mode, component, op, path, rule);
    if mode == Mode::Enforce {
        warn(component, op, path, rule);
        true
    } else {
        false
    }
}

// --- the two entry points -----------------------------------------------------------------------

/// Whether this call must be blocked: true only in `enforce` mode on a refusal.
///
/// # Safety
/// `ex` is the live call frame of `name`.
unsafe fn blocked(ex: *mut zend_execute_data, name: &str) -> bool {
    let from = unsafe { ex.as_ref() }.map_or(std::ptr::null(), |f| f.prev_execute_data);
    if PROCESS.contains(&name) {
        let Some(ctx) = slow(from) else { return false };
        let cmd = unsafe { arg_string(ex, 1) }.unwrap_or_else(|| name.to_owned());
        return ctx.evaluate(Op::Exec, name, Path::new(&cmd));
    }
    let Some(w) = watch::watched(None, name) else { return false };
    let argc = unsafe { ex.as_ref() }.map_or(0, |f| unsafe { f.This.u2.num_args });
    let mode = w.mode.filter(|m| *m <= argc).and_then(|m| unsafe { attribution::arg(ex, m) }).and_then(Zval::str);
    let mut ctx: Option<Slow> = None;
    let mut block = false;
    for pa in w.paths.iter().filter(|p| p.arg <= argc) {
        let Some(lex) = (unsafe { attribution::arg(ex, pa.arg) }).and_then(Zval::str).and_then(lexical) else {
            continue;
        };
        let op_token = match w.mode {
            Some(_) => watch::with_mode(pa.op, mode.unwrap_or("r")),
            None => pa.op.to_owned(),
        };
        let op = if watch::writes(&op_token) { Op::Write } else { Op::Read };
        match fast(op, &lex) {
            None => return false,       // layer 2 not active
            Some(true) => continue,     // allowed outright
            Some(false) => {}           // need the slow path
        }
        if ctx.is_none() {
            ctx = slow(from);
        }
        let Some(ctx) = ctx.as_ref() else { return false };
        block |= ctx.evaluate(op, &op_token, &real_path(&lex));
    }
    block
}

/// The read-policy decision for an include/require of `path` (lexically normalized) by the code
/// at `from`. Used by the `zend_compile_file` wrapper in [`crate::attribution`].
pub(crate) fn include_blocked(op: &str, lex: &Path, from: *const zend_execute_data) -> bool {
    match fast(Op::Read, lex) {
        None | Some(true) => false,
        Some(false) => {
            let Some(ctx) = slow(from) else { return false };
            ctx.evaluate(Op::Read, op, &real_path(lex))
        }
    }
}

/// `securecore_status()` is for core. In `enforce` mode a component's call is refused (returns
/// the message to throw); in `log` mode it is recorded and allowed (returns `None`). `caller` is
/// the component token who-is-running already computed.
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

// --- helpers ------------------------------------------------------------------------------------

/// `path` is `base` or sits under it (component-wise).
fn under_or_eq(path: &Path, base: &Path) -> bool {
    path == base || path.starts_with(base)
}

/// A path argument, made absolute and lexically normalized (no filesystem): relative paths are
/// joined to the CWD, `.`/`..` are resolved, symlinks are not. `None` for a non-plain-files
/// scheme (php://, https://…), which this policy does not govern.
fn lexical(arg: &str) -> Option<PathBuf> {
    let plain = watch::plain_path(arg)?;
    let p = Path::new(plain);
    let abs = if p.is_absolute() { p.to_owned() } else { std::env::current_dir().ok()?.join(p) };
    Some(normalize(&abs))
}

/// One line to PHP's error log per refusal: `layer2 <mode> <component> <op> <rule> <path>`.
fn audit(mode: Mode, component: &str, op: &str, path: &str, rule: &str) {
    crate::log(crate::LOG_NOTICE, &format!("layer2 {} {component} {op} {rule} {path}", mode.as_str()));
}

/// The warning a blocked call emits, so the plugin sees a permission failure.
fn warn(component: &str, op: &str, path: &str, rule: &str) {
    php_error(&ErrorType::Warning, &format!("securecore: {component} may not {op} {path} ({rule})"));
}

/// Function name of a call frame. Internal functions are keyed lowercase in the function table,
/// so the engine's stored name is already lowercase and is returned borrowed (no allocation).
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
