//! The SecureCore PHP extension (addiscorp/securecore#53), phase E1: the `securecore.config`
//! ini setting, loading and validating `securecore.json` at module startup, reloading it at
//! request start, and `securecore_status()`.
//!
//! Fail closed: if the file is missing, unreadable or invalid, MINIT fails. PHP then logs
//! "PHP Startup: securecore: <path>: <problem>" and "Unable to start securecore module" and
//! the process exits, so php-fpm never serves a request unprotected.
//!
//! Reload: layers 2 and 3 follow the file without a php-fpm restart. Each worker process
//! `stat`s it at most once per [`RELOAD_INTERVAL`], at request start, and reads + hashes +
//! parses it only when the stat changed. An edit that doesn't load keeps the last valid
//! config live (never "off") and is logged; a `layer1` change is logged as needing a restart.
//!
//! E2a adds attribution ([`attribution`]): which component (plugin, mu-plugin, theme or core)
//! is responsible for the running code, and a debug log of the component each rule would
//! charge for every file open. Observation only.

mod attribution;
mod db;
mod enforce;
mod vault;

use std::ffi::{CString, c_char, c_int};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use ext_php_rs::error::php_error;
use ext_php_rs::ffi::{ZEND_RESULT_CODE_FAILURE, ZEND_RESULT_CODE_SUCCESS};
use ext_php_rs::flags::IniEntryPermission;
use ext_php_rs::prelude::*;
use ext_php_rs::types::ZendHashTable;
use ext_php_rs::boxed::ZBox;
use ext_php_rs::zend::{ExecutorGlobals, IniEntryDef, IniEntryDefs, ModuleEntry};
use ext_php_rs::{info_table_end, info_table_row, info_table_start};
use securecore_config::{App, Loaded, Poll, Reloader};

/// The ini setting naming the config file. PHP_INI_SYSTEM: php.ini or conf.d only, read once
/// at startup.
const INI_CONFIG: &str = "securecore.config";

/// How often a worker process checks the file for changes.
pub const RELOAD_INTERVAL: Duration = Duration::from_millis(1000);

/// `securecore.config`, and two debug settings for attribution (E2a), all PHP_INI_SYSTEM:
/// `securecore.debug_attribution_rule` (`frame` | `component`, the rule
/// `securecore_status()['caller']` and later phases use) and `securecore.debug_attribution_log`
/// (`off` | `frame` | `component` | `both`: a log line per file open, per rule).
static INI: IniEntryDefs<5> = IniEntryDefs::new([
    IniEntryDef::new(c"securecore.config", c"", IniEntryPermission::System),
    IniEntryDef::new(c"securecore.debug_attribution_rule", c"component", IniEntryPermission::System),
    IniEntryDef::new(c"securecore.debug_attribution_log", c"off", IniEntryPermission::System),
    // E4, research only: who a database query is charged to. `caller` is the rule; `component`
    // reproduces the measurement that rejected it. See db::DbAttribution.
    IniEntryDef::new(c"securecore.debug_db_attribution", c"caller", IniEntryPermission::System),
    IniEntryDef::end(),
]);

/// The executor globals (`EG`) of the calling thread, without ext-php-rs's lock (the hot paths
/// read one field). On an NTS build this is `&executor_globals`; on a ZTS build the static does
/// not exist and the pointer is the thread's TSRM slot, so every read of `EG` goes through here.
pub(crate) fn executor_globals() -> *mut ext_php_rs::ffi::zend_executor_globals {
    // SAFETY: ext-php-rs's C helper; it only computes the address (TSRMG on ZTS).
    unsafe { ext_php_rs::ffi::ext_php_rs_executor_globals() }
}

/// The compiler globals (`CG`) of the calling thread, as [`executor_globals`] does for `EG`.
pub(crate) fn compiler_globals() -> *mut ext_php_rs::ffi::zend_compiler_globals {
    // SAFETY: as above.
    unsafe { ext_php_rs::ffi::ext_php_rs_compiler_globals() }
}

/// The live config. php-fpm loads it in the master at MINIT; each worker inherits it at fork
/// and then reloads on its own.
static STATE: Mutex<Option<Reloader>> = Mutex::new(None);

fn state() -> MutexGuard<'static, Option<Reloader>> {
    // A panic while holding the lock can't leave a Reloader half-updated in a way that
    // matters: every field is replaced whole. Keep serving the last state.
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `f` on the live config, holding the lock only for the call.
fn with_live<R>(f: impl FnOnce(&Loaded) -> R) -> Option<R> {
    state().as_ref().map(|r| f(r.live()))
}

/// A cheap clone of the live config (an `Arc` bump), for the enforcement path (E2b): it reads
/// several fields across one decision without holding the state lock for the whole call.
pub(crate) fn live_arc() -> Option<Arc<Loaded>> {
    state().as_ref().map(|r| Arc::clone(r.live()))
}

unsafe extern "C" {
    /// PHP's error log (`error_log`, or the SAPI's log): main/main.c, PHPAPI since 7.x.
    fn php_log_err_with_severity(message: *const c_char, syslog_type: c_int);
}

const LOG_WARNING: c_int = 4;
const LOG_NOTICE: c_int = 5;

/// Writes one line to PHP's error log, never to the response.
fn log(severity: c_int, message: &str) {
    if let Ok(line) = CString::new(format!("securecore: {message}")) {
        // SAFETY: a NUL-terminated string that outlives the call; PHP copies it.
        unsafe { php_log_err_with_severity(line.as_ptr(), severity) };
    }
}

/// Fails module startup with a message naming the file and the problem.
fn refuse(message: &str) -> i32 {
    php_error(&ErrorType::CoreWarning, &format!("securecore: {message}; refusing to start"));
    ZEND_RESULT_CODE_FAILURE
}

extern "C" fn module_startup(_ty: i32, module_number: i32) -> i32 {
    IniEntryDef::register(INI.as_slice(), module_number);
    let mut ini = ExecutorGlobals::get().ini_values();
    let mut value = |key: &str| ini.remove(key).flatten().unwrap_or_default();
    let (path, rule, log) = (value(INI_CONFIG), value(attribution::INI_RULE), value(attribution::INI_LOG));
    if let Err(e) = db::startup(&value(db::INI_ATTRIBUTION)) {
        return refuse(&e);
    }
    if path.trim().is_empty() {
        return refuse(&format!("{INI_CONFIG} is not set; point it at securecore.json"));
    }
    let settings = match attribution::Settings::parse(&rule, &log) {
        Ok(s) => s,
        Err(e) => return refuse(&e),
    };
    match Reloader::start(Path::new(&path), RELOAD_INTERVAL, Instant::now()) {
        Ok(reloader) => {
            // The vault (E3): read the real secret values and mask the environment here, in the
            // fpm master before it forks, so the workers inherit only placeholders. A missing or
            // empty secret refuses MINIT, like a bad config.
            let live = reloader.live();
            if let Err(e) = vault::startup(&live.config, &live.root) {
                return refuse(&e);
            }
            *state() = Some(reloader);
            attribution::startup(settings);
            ZEND_RESULT_CODE_SUCCESS
        }
        Err(e) => refuse(&e.to_string()),
    }
}

extern "C" fn request_startup(_ty: i32, _module_number: i32) -> i32 {
    attribution::request_startup();
    enforce::request_startup();
    vault::request_startup();
    db::request_startup();
    let mut guard = state();
    if let Some(reloader) = guard.as_mut() {
        match reloader.poll(Instant::now()) {
            Poll::Unchanged => {}
            Poll::Reloaded { layer1_changed, vault_changed } => {
                let live = reloader.live();
                log(LOG_NOTICE, &format!("reloaded {} (sha256 {})", live.path.display(), live.sha256));
                if layer1_changed {
                    log(LOG_WARNING, "layer1 changed; it applies only after a php-fpm restart");
                }
                if vault_changed {
                    log(LOG_WARNING, "layer2.vault changed; it applies only after a php-fpm restart");
                }
            }
            Poll::Rejected(problem) => {
                log(LOG_WARNING, &format!("{problem}; keeping the last valid config"));
            }
        }
    }
    ZEND_RESULT_CODE_SUCCESS
}

/// What the extension is enforcing: which layers are enabled, layer 2's mode, the config
/// file and its sha256, and the reload state.
#[php_function]
pub fn securecore_status() -> PhpResult<ZBox<ZendHashTable>> {
    // Who called, before taking the state lock (attribution reads the live config itself).
    let root = with_live(|l| l.root.clone()).ok_or("securecore: no config loaded")?;
    let caller = attribution::who_is_running(&root).to_string();
    // securecore_status() is for core (E2b): a component's call is refused in enforce mode and
    // recorded (but allowed) in log mode. "outside" code (not under the root) is let through.
    if caller != "core" && caller != "outside"
        && let Some(message) = enforce::status_only_core(&caller)
    {
        return Err(message.into());
    }
    let settings = attribution::settings();
    let guard = state();
    let reloader = guard.as_ref().ok_or("securecore: no config loaded")?;
    let live = reloader.live();
    let c = &live.config;
    let mut layers = ZendHashTable::new();
    layers.insert("layer1", c.layer1.enabled)?;
    layers.insert("layer2", c.layer2.enabled)?;
    layers.insert("layer3", c.layer3.enabled)?;
    let mut out = ZendHashTable::new();
    out.insert("version", env!("CARGO_PKG_VERSION"))?;
    out.insert("config", live.path.display().to_string())?;
    out.insert("sha256", live.sha256.as_str())?;
    out.insert("off", c.is_off())?;
    out.insert("layers", layers)?;
    out.insert("layer2_mode", c.layer2.mode.as_str())?;
    out.insert("layer2_app", c.layer2.app.map(App::as_str))?;
    // The vault (E3): active in this process (loaded at MINIT), and how many secrets it holds.
    // Never the values, and never the placeholders — only the count.
    out.insert("vault", vault::active())?;
    out.insert("vault_secrets", i64::try_from(vault::secret_count()).unwrap_or(i64::MAX))?;
    out.insert("reloads", i64::try_from(reloader.reloads()).unwrap_or(i64::MAX))?;
    out.insert("restart_needed", reloader.restart_needed())?;
    out.insert("reload_error", reloader.error().map(str::to_owned))?;
    out.insert("root", root.display().to_string())?;
    // The component responsible for this call, by the configured rule (E2a).
    out.insert("caller", caller)?;
    out.insert("attribution_rule", settings.as_ref().map(|s| s.rule.as_str()))?;
    out.insert("attribution_log", settings.as_ref().map(attribution::Settings::log_str))?;
    Ok(out)
}

extern "C" fn module_info(_module: *mut ModuleEntry) {
    let guard = state();
    info_table_start!();
    info_table_row!("securecore", "enabled");
    if let Some(live) = guard.as_ref().map(Reloader::live) {
        info_table_row!("config", live.path.display().to_string());
        info_table_row!("sha256", live.sha256.as_str());
    }
    info_table_end!();
}

#[php_module]
pub fn get_module(module: ModuleBuilder) -> ModuleBuilder {
    let module = module
        .name("securecore")
        .startup_function(module_startup)
        .request_startup_function(request_startup)
        .info_function(module_info)
        .function(wrap_function!(securecore_status));
    // The vault's native salted pluggables (E3); the mu-plugin defines wp_salt/wp_hash as thin
    // wrappers over these so the HMAC key never reaches PHP. Registered from their own module so
    // the macro finds the glue it generates there.
    vault::register(module)
}
