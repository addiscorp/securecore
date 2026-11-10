//! Who is running (addiscorp/securecore#53, E2a): the component responsible for what the code
//! on the PHP stack is doing, computed only when asked, and (behind a debug setting) a log line
//! for every file open saying which component each rule would charge.
//!
//! Observation only: nothing is blocked here.
//!
//! The normal request path stays free: [`who_is_running`] walks the stack only when called, and
//! the open recorder (a Zend observer on the watched file functions, and a `zend_compile_file`
//! wrapper for includes) is installed only when `securecore.debug_attribution_log` is not
//! `off`. With it off, neither exists and the engine runs exactly as without attribution.

use std::ffi::{CStr, c_char, c_int};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use ext_php_rs::ffi::{
    ZEND_INTERNAL_FUNCTION, zend_execute_data, zend_observer_fcall_handlers, zend_observer_fcall_register, zend_op_array,
    zend_string, zval,
};
use ext_php_rs::types::Zval;
use securecore_attribution::{Component, Layout, MapCache, Rule, real_path, watch};

/// Debug settings (PHP_INI_SYSTEM, php.ini or conf.d, read at startup).
pub const INI_RULE: &str = "securecore.debug_attribution_rule";
pub const INI_LOG: &str = "securecore.debug_attribution_log";

/// `ZEND_INCLUDE_OR_EVAL` (Zend/zend_vm_opcodes.h).
const ZEND_INCLUDE_OR_EVAL: u8 = 73;

/// How often the component map re-checks the plugins, mu-plugins and themes folders.
const MAP_INTERVAL: Duration = Duration::from_millis(1000);

/// The rule [`who_is_running`] uses, and the rules the open recorder logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub rule: Rule,
    pub log: Vec<Rule>,
}

impl Settings {
    /// From the two ini values. An unknown value is an error: the caller refuses to start.
    pub fn parse(rule: &str, log: &str) -> Result<Settings, String> {
        let rule = Rule::parse(rule.trim()).ok_or_else(|| format!("{INI_RULE} = {rule:?}: expected frame or component"))?;
        let log = match log.trim() {
            "" | "off" | "0" => vec![],
            "both" => Rule::ALL.to_vec(),
            other => vec![Rule::parse(other).ok_or_else(|| format!("{INI_LOG} = {other:?}: expected off, frame, component or both"))?],
        };
        Ok(Settings { rule, log })
    }

    pub fn log_str(&self) -> &'static str {
        match self.log.as_slice() {
            [] => "off",
            [r] => r.as_str(),
            _ => "both",
        }
    }
}

static SETTINGS: Mutex<Option<Settings>> = Mutex::new(None);
static MAP: Mutex<MapCache> = Mutex::new(MapCache::new(MAP_INTERVAL));

fn lock<T>(m: &'static Mutex<T>) -> MutexGuard<'static, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn settings() -> Option<Settings> {
    lock(&SETTINGS).clone()
}

/// At module startup: keeps the settings, and registers the open recorder when logging is on.
pub fn startup(settings: Settings) {
    let observe = !settings.log.is_empty();
    *lock(&SETTINGS) = Some(settings);
    if observe {
        // SAFETY: called from MINIT, the only time observers may be registered.
        unsafe { zend_observer_fcall_register(Some(observer_init)) };
    }
}

unsafe extern "C" {
    /// Zend/zend_constants.h: the constant's value, or NULL when it is not defined.
    fn zend_get_constant_str(name: *const c_char, name_len: usize) -> *mut zval;
}

pub(crate) fn constant(name: &CStr) -> Option<String> {
    // SAFETY: a NUL-terminated name; the returned zval (if any) lives in the constants table.
    let zv = unsafe { zend_get_constant_str(name.as_ptr(), name.to_bytes().len()).cast::<Zval>().as_ref() }?;
    zv.str().map(str::to_owned)
}

/// WordPress's directories now: its defaults under the root, moved by `WP_CONTENT_DIR`,
/// `WP_PLUGIN_DIR` and `WPMU_PLUGIN_DIR` once wp-config.php / wp-settings.php define them.
pub(crate) fn layout(root: &Path) -> Layout {
    Layout::wordpress(
        root,
        constant(c"WP_CONTENT_DIR").as_deref(),
        constant(c"WP_PLUGIN_DIR").as_deref(),
        constant(c"WPMU_PLUGIN_DIR").as_deref(),
    )
}

pub(crate) fn zstr(s: *const zend_string) -> Option<&'static str> {
    // SAFETY: a live zend_string from the engine (an op_array filename or function name),
    // which outlives the call that reads it.
    let s = unsafe { s.as_ref() }?;
    std::str::from_utf8(s.as_bytes()).ok()
}

/// The filenames of the user-code frames from `ex` outwards, innermost first.
fn user_frames(mut ex: *const zend_execute_data) -> impl Iterator<Item = &'static str> {
    std::iter::from_fn(move || {
        // SAFETY: the engine's frame chain, valid while the code that asked is running.
        unsafe {
            while let Some(frame) = ex.as_ref() {
                ex = frame.prev_execute_data;
                let Some(func) = frame.func.as_ref() else { continue };
                if u32::from(func.type_) == ZEND_INTERNAL_FUNCTION {
                    continue;
                }
                if let Some(file) = zstr(func.op_array.filename) {
                    return Some(file);
                }
            }
            None
        }
    })
}

/// Layer 3 (E7): the component an isolated child acts as. Set once, in the child, right after the
/// fork and before the plugin loads; never in a php-fpm worker. While set, everything the process
/// does is charged to that component, whatever the stack shows: the child exists to run it, so
/// core code it calls (a filter, a file read) acts on its behalf.
static ACT_AS: OnceLock<Component> = OnceLock::new();

/// Charges everything in this process to `component` from now on (layer 3's child).
pub fn act_as(component: Component) {
    let _ = ACT_AS.set(component);
}

/// The component a file belongs to (by path, through the cached map).
pub fn component_of(root: &Path, file: &str) -> Component {
    let layout = layout(root);
    lock(&MAP).frame(&layout, Instant::now(), file)
}

/// The component responsible, by `rule`, for the code running from frame `from` outwards. In a
/// layer 3 child, the isolated component (see [`act_as`]).
pub fn responsible(rule: Rule, root: &Path, from: *const zend_execute_data) -> Component {
    if let Some(c) = ACT_AS.get() {
        return c.clone();
    }
    let layout = layout(root);
    let now = Instant::now();
    let mut map = lock(&MAP);
    securecore_attribution::responsible(rule, user_frames(from).map(|file| map.frame(&layout, now, file)))
}

/// Who a database query is charged to (E4): the code that called the database layer, with core's
/// passthrough helpers (`dbDelta`, `update_option`, …) handing the charge to their caller. The
/// rule is [`securecore_db::caller::charged`] (plain Rust, unit-tested); this collects its frames.
pub fn db_caller(root: &Path, from: *const zend_execute_data) -> Component {
    if let Some(c) = ACT_AS.get() {
        return c.clone();
    }
    let layout = layout(root);
    let now = Instant::now();
    let mut map = lock(&MAP);
    // Lowercased function names, owned for the frames below (stacks are shallow).
    let named: Vec<(&'static str, Option<String>)> = named_user_frames(from).collect();
    let frames: Vec<securecore_db::caller::Frame<'_>> = named
        .iter()
        .map(|(file, function)| securecore_db::caller::Frame {
            component: map.frame(&layout, now, file),
            file,
            function: function.as_deref(),
        })
        .collect();
    securecore_db::caller::charged(&frames)
}

/// The user-code frames from `ex` outwards, innermost first: each one's file, and its function
/// name lowercased when it is a plain function (`None` for top-level code, closures and methods).
fn named_user_frames(mut ex: *const zend_execute_data) -> impl Iterator<Item = (&'static str, Option<String>)> {
    std::iter::from_fn(move || {
        // SAFETY: the engine's frame chain, valid while the code that asked is running.
        unsafe {
            while let Some(frame) = ex.as_ref() {
                ex = frame.prev_execute_data;
                let Some(func) = frame.func.as_ref() else { continue };
                if u32::from(func.type_) == ZEND_INTERNAL_FUNCTION {
                    continue;
                }
                let Some(file) = zstr(func.op_array.filename) else { continue };
                let name = if func.common.scope.is_null() {
                    zstr(func.common.function_name).map(str::to_ascii_lowercase)
                } else {
                    None
                };
                return Some((file, name));
            }
            None
        }
    })
}

/// Who is running now, by the configured rule: the stack of the code calling into the
/// extension. `root` is the app root (the folder containing securecore.json).
pub fn who_is_running(root: &Path) -> Component {
    let rule = settings().map_or(Rule::Component, |s| s.rule);
    // SAFETY: EG(current_execute_data), read on the request's own thread.
    let current = unsafe { (*crate::executor_globals()).current_execute_data };
    responsible(rule, root, current)
}

// --- the open recorder (debug) ------------------------------------------------------------------

/// The app root, when the live config has layer 2 recording: enabled for WordPress, mode
/// `log` or `enforce`.
fn recording_root() -> Option<PathBuf> {
    crate::with_live(|live| {
        let l2 = &live.config.layer2;
        (l2.enabled && l2.app.is_some() && l2.mode != securecore_config::Mode::Off).then(|| live.root.clone())
    })
    .flatten()
}

fn record(op: &str, path: &Path, from: *const zend_execute_data) {
    let Some(root) = recording_root() else { return };
    let Some(settings) = settings() else { return };
    for rule in settings.log {
        let c = responsible(rule, &root, from);
        crate::log(crate::LOG_NOTICE, &format!("attribution {} {c} {op} {}", rule.as_str(), path.display()));
    }
}

/// Which functions to observe: the watched file functions. Everything else gets no handler,
/// so it costs nothing after this.
unsafe extern "C" fn observer_init(ex: *mut zend_execute_data) -> zend_observer_fcall_handlers {
    let none = zend_observer_fcall_handlers { begin: None, end: None };
    // SAFETY: the frame about to run, from the engine.
    let Some(func) = (unsafe { ex.as_ref().and_then(|f| f.func.as_ref()) }) else { return none };
    // SAFETY: `common` is valid for every function type.
    let common = unsafe { &func.common };
    if u32::from(common.type_) == ZEND_INTERNAL_FUNCTION && watched_of(common).is_some() {
        return zend_observer_fcall_handlers { begin: Some(on_call), end: None };
    }
    none
}

fn watched_of(common: &ext_php_rs::ffi::_zend_function__bindgen_ty_1) -> Option<&'static watch::Watched> {
    let name = zstr(common.function_name)?;
    // SAFETY: a function's scope is a live class entry or NULL.
    let class = unsafe { common.scope.as_ref() }.and_then(|ce| zstr(ce.name));
    watch::watched(class, name)
}

/// The zval of argument `n` (1-based) of a call frame: `ZEND_CALL_ARG(call, n)`.
///
/// # Safety
/// `ex` is a live call frame with at least `n` arguments.
pub(crate) unsafe fn arg<'a>(ex: *const zend_execute_data, n: u32) -> Option<&'a Zval> {
    let slot = std::mem::size_of::<zend_execute_data>().div_ceil(std::mem::size_of::<zval>());
    // SAFETY: the caller guarantees the frame and the argument count.
    unsafe { ex.cast::<zval>().add(slot + n as usize - 1).cast::<Zval>().as_ref() }
}

/// A path argument as the plain-files wrapper will open it: absolute (relative to PHP's
/// working directory), normalized, symlinks resolved as far as it exists.
pub(crate) fn opened_path(arg: &str) -> Option<PathBuf> {
    let plain = watch::plain_path(arg)?;
    let p = Path::new(plain);
    let abs = if p.is_absolute() { p.to_owned() } else { std::env::current_dir().ok()?.join(p) };
    Some(real_path(&abs))
}

unsafe extern "C" fn on_call(ex: *mut zend_execute_data) {
    // SAFETY: the call frame of a watched internal function, about to run.
    let Some(frame) = (unsafe { ex.as_ref() }) else { return };
    let Some(func) = (unsafe { frame.func.as_ref() }) else { return };
    let Some(w) = watched_of(unsafe { &func.common }) else { return };
    // SAFETY: ZEND_CALL_NUM_ARGS(call) is This.u2.num_args.
    let argc = unsafe { frame.This.u2.num_args };
    let mode = w.mode.filter(|m| *m <= argc).and_then(|m| unsafe { arg(ex, m) }).and_then(Zval::str);
    for p in w.paths.iter().filter(|p| p.arg <= argc) {
        // SAFETY: p.arg <= argc.
        let Some(path) = (unsafe { arg(ex, p.arg) }).and_then(Zval::str).and_then(opened_path) else { continue };
        let op = match w.mode {
            Some(_) => watch::with_mode(p.op, mode.unwrap_or("r")),
            None => p.op.to_owned(),
        };
        record(&op, &path, frame.prev_execute_data);
    }
}

// --- includes ------------------------------------------------------------------------------------
//
// Not an observer: the engine does not execute (so never observes) an included file whose
// top-level code is a lone `return 1`, which is what a file holding only declarations
// compiles to, and most class files are that. Every include and require that loads a file
// calls `zend_compile_file`, cached in opcache or not, so the recorder wraps that. It has to be
// the outermost wrapper: opcache replaces `zend_compile_file` after every MINIT and serves
// cache hits without calling what it wrapped. So the wrapper is installed at the first request
// (RINIT), once per process, and only when logging is on.

type CompileFile = unsafe extern "C" fn(file_handle: *mut ext_php_rs::ffi::zend_file_handle, kind: c_int) -> *mut zend_op_array;

unsafe extern "C" {
    /// Zend/zend_compile.h: `ZEND_API extern zend_op_array *(*zend_compile_file)(...)`.
    static mut zend_compile_file: Option<CompileFile>;
}

/// The `zend_compile_file` the wrapper calls (opcache's, when it is loaded).
static PREVIOUS_COMPILE_FILE: Mutex<Option<CompileFile>> = Mutex::new(None);
static INCLUDES_HOOKED: AtomicBool = AtomicBool::new(false);

/// At request start: installs the `zend_compile_file` wrapper once per process, if attribution
/// logging is on (to record includes, E2a) or layer 2 is active (to enforce them, E2b). It is
/// the one wrapper that does both; with neither wanted it is never installed, so a request that
/// needs nothing from it pays nothing.
pub fn request_startup() {
    if INCLUDES_HOOKED.load(Ordering::Relaxed) {
        return;
    }
    let logging = !settings().is_none_or(|s| s.log.is_empty());
    if !logging && !crate::enforce::layer2_active() && !crate::layer3::isolating() {
        return;
    }
    INCLUDES_HOOKED.store(true, Ordering::Relaxed);
    // SAFETY: the engine's global hook, replaced on the request's own thread between requests'
    // compilations; the previous value is kept and always called.
    unsafe {
        let hook = &mut *std::ptr::addr_of_mut!(zend_compile_file);
        *lock(&PREVIOUS_COMPILE_FILE) = *hook;
        *hook = Some(compile_file);
    }
}

unsafe extern "C" fn compile_file(file_handle: *mut ext_php_rs::ffi::zend_file_handle, kind: c_int) -> *mut zend_op_array {
    let Some(previous) = *lock(&PREVIOUS_COMPILE_FILE) else { return std::ptr::null_mut() };
    // The frame running the include and the include op (include/require, not eval). eval and the
    // main script (no caller) are neither recorded nor enforced.
    // SAFETY: EG(current_execute_data) and its opline, on the request's own thread.
    let (op, current) = unsafe {
        let current = (*crate::executor_globals()).current_execute_data;
        let op = current
            .as_ref()
            .and_then(|c| c.opline.as_ref())
            .filter(|o| o.opcode == ZEND_INCLUDE_OR_EVAL)
            .and_then(|o| watch::include_op(o.extended_value));
        (op, current)
    };
    // E7: an isolated plugin's files never load in a php-fpm worker. WordPress loading its main
    // file gets the layer 3 stand-in instead; any other include of its files is refused (fails
    // as a missing file does). SAFETY: the file handle from the engine.
    if op.is_some()
        && let Some(path) = unsafe { file_handle.as_ref() }.and_then(|f| zstr(f.filename)).and_then(watch::plain_path)
    {
        match crate::layer3::include(path, current) {
            crate::layer3::Include::Normal => {}
            crate::layer3::Include::Refuse => return std::ptr::null_mut(),
            crate::layer3::Include::Stub(op_array) => return op_array,
        }
    }
    // E2b: enforce the read policy on the file before compiling it. Blocking here (return null,
    // never compiling) makes a denied include fail exactly as a missing file does: a warning and
    // `false` for include, a fatal for require. SAFETY: the file handle from the engine.
    if let Some(op) = op
        && let Some(path) = unsafe { file_handle.as_ref() }.and_then(|f| zstr(f.filename)).and_then(watch::plain_path)
        && crate::enforce::include_blocked(op, path, current)
    {
        return std::ptr::null_mut();
    }
    // SAFETY: the engine's own call, passed through unchanged.
    let op_array = unsafe { previous(file_handle, kind) };
    // E2a logging (observation only): one line per logged rule, from the compiled op_array's
    // resolved filename. Guarded by logging being on, so enforcement-only workers (the common
    // case) never pay for the real_path here. SAFETY: the op_array just compiled or from opcache.
    if settings().is_some_and(|s| !s.log.is_empty())
        && let Some(op) = op
        && let Some(file) = unsafe { op_array.as_ref() }.and_then(|a| zstr(a.filename))
        && let Some(path) = watch::plain_path(file)
    {
        record(op, &real_path(Path::new(path)), current);
    }
    op_array
}
