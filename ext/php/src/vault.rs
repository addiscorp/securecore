//! The vault (addiscorp/securecore#53, phase E3): the database password and the WordPress keys
//! and salts never exist as a value PHP can read. The real values live only in this module's
//! process memory; everywhere PHP could look — the constant, the environment, `$_ENV`,
//! `$_SERVER`, `getenv()`, `phpinfo()` — carries a placeholder. The extension puts the real
//! value back only at the two points where it is used: inside the database `connect` call, and
//! inside the native `wp_salt`/`wp_hash` the mu-plugin installs.
//!
//! **Where the values are read (MINIT, in the fpm master before it forks).** For each secret:
//! its value comes from the mapped environment variable (`env`), or from `vault.from` — the
//! `define()` literals of wp-config.php read natively, or a vault file (a JSON object of
//! `NAME: value`, kept outside the docroot). Read once, kept here, then masked:
//!   * every mapped environment variable is overwritten in the C `environ` with the secret's
//!     placeholder (`securecore-vault:<NAME>`), so the master's workers inherit the masked
//!     environment;
//!   * a backstop sweep then masks **every** `environ` entry whose value equals any secret's
//!     value, whatever its name (only the names are logged, never the values);
//!   * a missing or empty secret, or a mapped variable that isn't set, refuses MINIT — the
//!     extension fails closed, exactly as a bad config does.
//!
//! **Where PHP is kept from the value (per request / per call).** `getenv()` is overridden to
//! return the placeholder for any value that matches a secret; `define()` of a secret name is
//! forced to the placeholder whatever fed it; and `$_ENV`/`$_SERVER` carry only placeholders
//! because php-fpm builds them from the masked `environ`.
//!
//! **Where the value is used.** `mysqli_connect`, `mysqli_real_connect`, `new mysqli` and
//! `new PDO` get the placeholder swapped for the real password inside the handler, before the
//! engine's own function runs, so the real value reaches libmysql/PDO and never a PHP zval the
//! caller keeps. `wp_salt`/`wp_hash` (native, [`securecore_config::salt`]) compute over the real
//! keys, so the HMAC key never becomes a PHP value either.
//!
//! The vault is not a policy: it works in `log` mode as in `enforce`, and with no `vault` in the
//! config it does nothing. A change to the vault needs a php-fpm restart (the values are read at
//! MINIT), which [`securecore_config::Reloader`] reports as `restart_needed`.

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char};
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use ext_php_rs::ffi::{
    zend_execute_data, zend_function, zend_hash_str_find_ptr_lc, zval,
};
use ext_php_rs::prelude::*;
use ext_php_rs::types::Zval;
use securecore_attribution::{Component, Rule};
use securecore_config::salt::{self, Secrets};
use securecore_config::{Config, Mode, Secret, Source};

/// The placeholder a secret's real value is replaced by, everywhere PHP can see. Unique per
/// secret (it carries the constant name), so the point of use knows which value to restore.
fn placeholder(name: &str) -> String {
    format!("securecore-vault:{name}")
}

/// The WordPress constant that holds the database password: the one secret the vault ever
/// restores at a connect boundary (never a salt).
const DB_PASSWORD: &str = "DB_PASSWORD";

/// What the vault holds after MINIT: the real values, kept out of PHP's reach, and the lookups
/// the request path needs.
struct Vault {
    /// Constant name → its real value (for the native salted functions).
    by_name: HashMap<String, String>,
    /// Placeholder → the real value (for the point-of-use password swap).
    by_placeholder: HashMap<String, String>,
    /// (real value, placeholder) pairs, longest value first, for masking `getenv()` and the
    /// `environ` backstop by value.
    by_value: Vec<(String, String)>,
    /// The database host the DB password may be sent to, from `layer2.vault.dbHost`. When unset,
    /// the extension reads WordPress's `DB_HOST` constant instead; a host is never guessed.
    db_host: Option<String>,
}

impl Secrets for Vault {
    fn get(&self, name: &str) -> Option<&str> {
        self.by_name.get(name).map(String::as_str)
    }
}

impl Vault {
    /// The DB password's placeholder and real value, when the vault holds `DB_PASSWORD`. This is
    /// the only secret ever restored at a connect boundary.
    fn db_password(&self) -> Option<(String, &str)> {
        self.by_name.get(DB_PASSWORD).map(|v| (placeholder(DB_PASSWORD), v.as_str()))
    }

    /// Whether `ph` is any secret's placeholder (used to spot a salt placeholder smuggled into a
    /// password argument).
    fn is_placeholder(&self, ph: &str) -> bool {
        self.by_placeholder.contains_key(ph)
    }
}

static VAULT: OnceLock<Vault> = OnceLock::new();

fn vault() -> Option<&'static Vault> {
    VAULT.get()
}

/// Whether the vault is in force in this process: it was loaded at MINIT.
pub(crate) fn active() -> bool {
    VAULT.get().is_some()
}

/// How many secrets the vault holds (0 when it is not active). Never the values.
pub(crate) fn secret_count() -> usize {
    vault().map_or(0, |v| v.by_name.len())
}

// --- MINIT: read the real values and mask the environment ---------------------------------------

unsafe extern "C" {
    /// The process environment, as a NULL-terminated array of `KEY=VALUE` C strings.
    static mut environ: *mut *mut c_char;
}

fn c_getenv(name: &str) -> Option<String> {
    let c = CString::new(name).ok()?;
    // SAFETY: a NUL-terminated name; libc::getenv returns a pointer into `environ` or NULL.
    let p = unsafe { libc::getenv(c.as_ptr()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: a NUL-terminated value owned by the environment.
    unsafe { CStr::from_ptr(p) }.to_str().ok().map(str::to_owned)
}

/// `setenv(name, value, 1)`.
fn c_setenv(name: &str, value: &str) {
    if let (Ok(n), Ok(v)) = (CString::new(name), CString::new(value)) {
        // SAFETY: NUL-terminated strings; setenv copies them.
        unsafe { libc::setenv(n.as_ptr(), v.as_ptr(), 1) };
    }
}

/// Read every secret's real value from its source, or an error naming the first one that is
/// missing or empty (the caller refuses MINIT — fail closed).
fn read_values(config: &Config, root: &Path) -> Result<HashMap<String, String>, String> {
    let Some(vault) = config.layer2.started_vault_ref() else {
        return Ok(HashMap::new());
    };
    // The source file (wp-config.php's literals or a vault file) is read and parsed once.
    let from_file = match vault.from.as_ref() {
        Some(source) => Some(securecore_config::source::read(source, root)?),
        None => None,
    };
    let mut values = HashMap::new();
    for secret in &vault.secrets {
        let name = secret.name();
        let value = match secret {
            Secret::Env(e) => c_getenv(&e.env)
                .ok_or_else(|| format!("layer2.vault: {name}: environment variable {} is not set", e.env))?,
            Secret::Name(_) => from_file
                .as_ref()
                .expect("a bare-named secret requires vault.from, enforced by config validation")
                .get(name)
                .cloned()
                .ok_or_else(|| format!("layer2.vault: {name}: not found in {}", vault.from.as_ref().map_or("", Source::path)))?,
        };
        if value.is_empty() {
            return Err(format!("layer2.vault: {name} is empty"));
        }
        values.insert(name.to_owned(), value);
    }
    Ok(values)
}

/// At MINIT, in the fpm master before it forks: read the real values, keep them here, and mask
/// the environment so the workers inherit only placeholders. Returns an error (fail closed) when
/// a secret is missing or empty. A no-op when there is no vault.
pub(crate) fn startup(config: &Config, root: &Path) -> Result<(), String> {
    if config.layer2.started_vault_ref().is_none() {
        return Ok(());
    }
    let values = read_values(config, root)?;

    // Fail closed on the opcache leak: a secret read as a bare string literal from wp-config.php
    // cannot be hidden, because opcache's optimizer inlines `define('NAME', 'literal')` into a
    // compile-time DECLARE_CONST that the extension can't intercept (and keeps the plaintext in
    // shared memory). Refuse at MINIT, naming the secret, rather than run a vault that silently
    // isn't one. Expression defines (`getenv`) are not literals, so env-mapped secrets and the
    // vault file are unaffected.
    if let Some(vault) = config.layer2.started_vault_ref()
        && matches!(vault.from, Some(Source::WpConfig(_)))
        && opcache_inlines_defines()
        && let Some(secret) = vault.secrets.iter().find(|s| matches!(s, Secret::Name(_)))
    {
        let file = vault.from.as_ref().map_or("wp-config.php", Source::path);
        return Err(format!(
            "layer2.vault: {} is a string literal in {file} and opcache inlines it (DECLARE_CONST), so the vault cannot hide it; \
             move it to a vault file (from.vaultFile) or an environment variable (secrets[].env)",
            secret.name()
        ));
    }

    // Mask every mapped environment variable with its secret's placeholder.
    if let Some(vault) = config.layer2.started_vault_ref() {
        for secret in &vault.secrets {
            if let Some(env) = secret.env() {
                c_setenv(env, &placeholder(secret.name()));
            }
        }
    }

    // Backstop: mask every environ entry whose value equals any secret's value, whatever its
    // name. Build value → placeholder first (a value may belong to more than one constant; the
    // first wins, deterministically, by sorting the names).
    let mut value_to_ph: HashMap<&str, String> = HashMap::new();
    let mut names: Vec<&String> = values.keys().collect();
    names.sort();
    for name in names {
        value_to_ph.entry(values[name].as_str()).or_insert_with(|| placeholder(name));
    }
    let mut masked: Vec<String> = Vec::new();
    for (key, value) in read_environ() {
        if let Some(ph) = value_to_ph.get(value.as_str())
            && value != *ph
        {
            c_setenv(&key, ph);
            masked.push(key);
        }
    }
    if !masked.is_empty() {
        masked.sort();
        masked.dedup();
        crate::log(crate::LOG_NOTICE, &format!("vault: masked {} environment variable(s): {}", masked.len(), masked.join(" ")));
    }

    // Keep the values and the lookups; drop the plaintext map after moving it in.
    let by_placeholder: HashMap<String, String> = values.iter().map(|(n, v)| (placeholder(n), v.clone())).collect();
    let mut by_value: Vec<(String, String)> = values.iter().map(|(n, v)| (v.clone(), placeholder(n))).collect();
    // Longest value first: a secret that is a prefix of another is still matched exactly (we
    // only compare whole values, but ordering keeps the sweep deterministic).
    by_value.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
    by_value.dedup();
    let db_host = config.layer2.started_vault_ref().and_then(|v| v.db_host.clone());
    let _ = VAULT.set(Vault { by_name: values, by_placeholder, by_value, db_host });
    crate::log(
        crate::LOG_NOTICE,
        &format!("vault: {} secret(s) held in the extension; PHP sees placeholders", vault().map_or(0, |v| v.by_name.len())),
    );
    Ok(())
}

/// Every `KEY=VALUE` currently in `environ`, split once on `=`.
fn read_environ() -> Vec<(String, String)> {
    let mut out = Vec::new();
    // SAFETY: `environ` is the process's NULL-terminated environment array.
    unsafe {
        let mut p = environ;
        if p.is_null() {
            return out;
        }
        while !(*p).is_null() {
            if let Ok(s) = CStr::from_ptr(*p).to_str()
                && let Some((k, v)) = s.split_once('=')
            {
                out.push((k.to_owned(), v.to_owned()));
            }
            p = p.add(1);
        }
    }
    out
}

/// Whether opcache would inline a literal `define()` into a `DECLARE_CONST` in this process:
/// opcache is enabled (for this SAPI) and its optimizer is on. Conservative (fail closed): any
/// non-zero `opcache.optimization_level` with opcache enabled counts, since the standard
/// optimizer includes the define-inlining pass. With opcache absent or its optimizer off, a
/// literal define stays a real function call the extension can intercept.
fn opcache_inlines_defines() -> bool {
    // opcache is a zend_extension, reliably detectable at this module's MINIT. Its own ini values
    // (`opcache.enable`, `opcache.optimization_level`) are not yet applied here — they read as 0 —
    // so we cannot tell at MINIT whether the optimizer is off. A standard build turns the
    // optimizer on, and it inlines `define('NAME', <literal>)` into a compile-time DECLARE_CONST
    // the extension can't intercept (with the plaintext left in shared memory). So fail closed: if
    // opcache is loaded, a literal secret is treated as un-hideable. With no opcache at all, a
    // literal define stays a real `define()` call the extension masks. Env-mapped secrets and the
    // vault file are literals in no PHP file, so they are unaffected either way.
    zend_extension_loaded("Zend OPcache")
}

/// Whether a Zend extension (e.g. opcache) is loaded.
fn zend_extension_loaded(name: &str) -> bool {
    let Ok(c) = CString::new(name) else { return false };
    // SAFETY: a NUL-terminated name; `zend_get_extension` returns a pointer or NULL.
    !unsafe { zend_get_extension(c.as_ptr()) }.is_null()
}

unsafe extern "C" {
    /// Zend/zend_extensions.h: the loaded zend_extension by name, or NULL.
    fn zend_get_extension(extension_name: *const c_char) -> *const std::ffi::c_void;
}

// --- the function handlers ----------------------------------------------------------------------

/// A Zend internal-function handler.
pub(crate) type Zif = unsafe extern "C" fn(*mut zend_execute_data, *mut zval);

/// Where a connect function carries the host to compare against the configured DB host: a plain
/// argument (mysqli), or inside the PDO DSN (`host=…`).
#[derive(Clone, Copy)]
enum HostArg {
    /// The host is argument `n` (1-based).
    Arg(u32),
    /// The host is `host=` inside the DSN at argument `n`.
    Dsn(u32),
}

/// A connect boundary where the DB password placeholder may be restored: which argument is the
/// password, and where its host is.
#[derive(Clone, Copy)]
struct Swap {
    password_arg: u32,
    host: HostArg,
}

/// Global functions we override. `getenv`/`define` have no connect swap; the mysqli/PDO
/// constructors are handled as methods.
const FUNCS: &[(&str, Option<Swap>)] = &[
    ("getenv", None),
    ("define", None),
    ("mysqli_connect", Some(Swap { password_arg: 3, host: HostArg::Arg(1) })),
    ("mysqli_real_connect", Some(Swap { password_arg: 4, host: HostArg::Arg(2) })),
];
/// Methods we override: `(class, method, swap)`. `mysqli::real_connect` has no link argument, so
/// its host/password are one position earlier than the procedural `mysqli_real_connect`.
const METHODS: &[(&str, &str, Swap)] = &[
    ("mysqli", "__construct", Swap { password_arg: 3, host: HostArg::Arg(1) }),
    ("mysqli", "real_connect", Swap { password_arg: 3, host: HostArg::Arg(1) }),
    ("pdo", "__construct", Swap { password_arg: 3, host: HostArg::Dsn(1) }),
];

/// The handlers we replaced, by a key (`"func"` or `"class::method"`), with the connect swap.
struct Override {
    original: Zif,
    swap: Option<Swap>,
}
static ORIGINALS: OnceLock<HashMap<String, Override>> = OnceLock::new();
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// At request start, when the vault is active: install the function/method handlers once per
/// process. (The environment was masked at MINIT; these keep PHP from the value at the use
/// points and through `getenv`/`define`.)
pub(crate) fn request_startup() {
    if !active() || INSTALLED.load(Ordering::Relaxed) {
        return;
    }
    INSTALLED.store(true, Ordering::Relaxed);
    // SAFETY: the function/class tables on the request's own thread, before userland runs.
    unsafe { install() };
}

/// # Safety
/// Called once, from RINIT, before userland code runs this request.
unsafe fn install() {
    let mut originals = HashMap::new();
    let ft = unsafe { (*std::ptr::addr_of_mut!(ext_php_rs::ffi::compiler_globals)).function_table };
    if !ft.is_null() {
        for &(name, swap) in FUNCS {
            if let Some(original) = unsafe { hook_in(ft, name) } {
                originals.insert(name.to_string(), Override { original, swap });
            }
        }
    }
    for &(class, method, swap) in METHODS {
        // SAFETY: the class's own method table, on the request's own thread.
        if let Some(mft) = unsafe { method_table(class) }
            && let Some(original) = unsafe { hook_in(mft, method) }
        {
            originals.insert(format!("{class}::{method}"), Override { original, swap: Some(swap) });
        }
    }
    let _ = ORIGINALS.set(originals);
}

/// The method table of the internal class `class` (lowercase name), when it is loaded. Shared with
/// the database policy's hooks ([`crate::db`]).
///
/// # Safety
/// Called on the request's own thread, before userland runs.
pub(crate) unsafe fn method_table(class: &str) -> Option<*mut ext_php_rs::ffi::HashTable> {
    let ct = unsafe { (*std::ptr::addr_of_mut!(ext_php_rs::ffi::compiler_globals)).class_table };
    if ct.is_null() {
        return None;
    }
    // SAFETY: the class table; the class entry (if present) owns its function table.
    let ce = unsafe { zend_hash_str_find_ptr_lc(ct.cast_const(), class.as_ptr().cast(), class.len()) }.cast::<ext_php_rs::ffi::zend_class_entry>();
    let ce = unsafe { ce.as_ref() }?;
    let mft: *const ext_php_rs::ffi::HashTable = std::ptr::addr_of!(ce.function_table);
    Some(mft.cast_mut())
}

/// Replace the handler of the internal function `name` in table `ft` with [`dispatch`], returning
/// the handler it replaced.
///
/// # Safety
/// `ft` is a live function table on the request's own thread.
unsafe fn hook_in(ft: *mut ext_php_rs::ffi::HashTable, name: &str) -> Option<Zif> {
    unsafe { hook_with(ft, name, dispatch) }
}

/// Replace the handler of the internal function `name` in table `ft` with `handler`, returning the
/// handler it replaced (the vault's hooks and the database policy's, [`crate::db`], share this).
///
/// # Safety
/// `ft` is a live function table on the request's own thread.
pub(crate) unsafe fn hook_with(ft: *mut ext_php_rs::ffi::HashTable, name: &str, handler: Zif) -> Option<Zif> {
    let lc = name.to_ascii_lowercase();
    // SAFETY: a live function table and a byte string; the lookup is read-only.
    let ptr = unsafe { zend_hash_str_find_ptr_lc(ft.cast_const(), lc.as_ptr().cast(), lc.len()) };
    let func = unsafe { ptr.cast::<zend_function>().as_mut() }?;
    // SAFETY: an internal function; reading the union.
    let previous = unsafe { func.internal_function.handler }?;
    func.internal_function.handler = Some(handler);
    Some(previous)
}

/// The replacement handler for every overridden function/method.
unsafe extern "C" fn dispatch(execute_data: *mut zend_execute_data, return_value: *mut zval) {
    let key = unsafe { dispatch_key(execute_data) };
    let Some(ov) = key.as_deref().and_then(|k| ORIGINALS.get().and_then(|m| m.get(k))) else {
        return;
    };
    let name = key.as_deref().unwrap_or("");

    // Point of use: restore the real DB password in the frame, before the engine's own function
    // runs — but only when it is safe to (see [`connect_swap`]). The caller's own `$password`
    // zval is untouched (a by-value argument is a separate zval), so the real value reaches
    // libmysql/PDO and no PHP variable.
    if let Some(swap) = ov.swap {
        unsafe { connect_swap(execute_data, swap) };
    }
    if name == "define" {
        unsafe { force_define_placeholder(execute_data) };
    }

    // SAFETY: the engine handler we replaced for this function.
    unsafe { (ov.original)(execute_data, return_value) };

    // getenv: mask any secret value in the result (belt and braces over the masked environ).
    if name == "getenv" {
        unsafe { mask_getenv_result(return_value) };
    }
}

/// The `ORIGINALS` key for a call frame: `class::method` for a method, else the function name.
///
/// # Safety
/// `ex` is a live call frame.
pub(crate) unsafe fn dispatch_key(ex: *mut zend_execute_data) -> Option<String> {
    let func = unsafe { ex.as_ref()?.func.as_ref()? };
    let common = unsafe { &func.common };
    let name = crate::attribution::zstr(common.function_name)?;
    // SAFETY: a function's scope is a live class entry or NULL.
    let class = unsafe { common.scope.as_ref() }.and_then(|ce| crate::attribution::zstr(ce.name));
    Some(match class {
        Some(c) => format!("{}::{}", c.to_ascii_lowercase(), name.to_ascii_lowercase()),
        None => name.to_ascii_lowercase(),
    })
}

/// Restore the real DB password at a connect boundary — but only when all three hold, because the
/// real value is about to leave the process. One: the password argument is the **DB password's**
/// placeholder, never a salt's (a salt placeholder handed to a connect as the password is refused,
/// not swapped). Two: the **caller is core**, by E2a's `frame` attribution — the innermost
/// user-code frame that calls connect, so WordPress's `wpdb` counts and a plugin's own `new
/// mysqli` does not. Three: the **host is the configured DB host** (`layer2.vault.dbHost`, or
/// WordPress's `DB_HOST` constant), compared after normalising the `p:` prefix, a `:port` and a
/// socket path. Otherwise the placeholder is left in place (so the connection fails) and the
/// refusal is recorded. This holds in `log` mode too: the vault is not a policy, and leaking a
/// secret is never "log and allow".
///
/// # Safety
/// `ex` is a live connect call frame.
unsafe fn connect_swap(ex: *mut zend_execute_data, swap: Swap) {
    // Read the password argument (immutable) and decide before taking the mutable borrow.
    let Some(current) = (unsafe { arg(ex, swap.password_arg) }).and_then(Zval::str).map(str::to_owned) else { return };
    let Some(v) = vault() else { return };
    let Some((db_ph, db_val)) = v.db_password() else { return };

    // 1. Only the DB password placeholder is ever restored.
    if current != db_ph {
        // A salt placeholder (or any other) handed to a connect as the password is an attempt to
        // exfiltrate it: refuse, never swap. A real (non-placeholder) password is left alone.
        if v.is_placeholder(&current) {
            refuse("not-db-secret", unsafe { caller(ex) }, None);
        }
        return;
    }

    // 2. The caller must be core.
    let who = unsafe { caller(ex) };
    if who.as_ref() != Some(&Component::Core) {
        refuse("noncore-connect", who, None);
        return;
    }

    // 3. The host must be the configured DB host.
    let host = unsafe { connect_host(ex, swap.host) };
    let expected = expected_db_host(v);
    match (host.as_deref(), expected.as_deref()) {
        (Some(h), Some(e)) if securecore_config::dbhost::normalize_host(h) == securecore_config::dbhost::normalize_host(e) => {
            let val = db_val.to_owned();
            if let Some(zv) = unsafe { arg_mut(ex, swap.password_arg) } {
                let _ = zv.set_string(&val, false);
            }
        }
        (h, _) => refuse("wrong-host", who, h),
    }
}

/// The component responsible for a connect call, by E2a's `frame` rule (the innermost user-code
/// frame that made the call): WordPress's `wpdb` is core; a plugin's own connect is the plugin.
///
/// # Safety
/// `ex` is a live call frame.
unsafe fn caller(ex: *mut zend_execute_data) -> Option<Component> {
    let from = unsafe { ex.as_ref() }?.prev_execute_data;
    let loaded = crate::live_arc()?;
    Some(crate::attribution::responsible(Rule::Frame, &loaded.root, from))
}

/// The host a connect call targets: a plain argument (mysqli), or `host=` from the PDO DSN.
///
/// # Safety
/// `ex` is a live connect call frame.
unsafe fn connect_host(ex: *mut zend_execute_data, host: HostArg) -> Option<String> {
    match host {
        HostArg::Arg(n) => unsafe { arg(ex, n) }.and_then(Zval::str).map(str::to_owned),
        HostArg::Dsn(n) => {
            let dsn = unsafe { arg(ex, n) }.and_then(Zval::str)?;
            securecore_config::dbhost::dsn_host(dsn)
        }
    }
}

/// The DB host the password may be sent to: `layer2.vault.dbHost`, or WordPress's `DB_HOST`
/// constant (the way WordPress reads it). `None` when neither is known — the swap is then refused,
/// never guessed.
fn expected_db_host(v: &Vault) -> Option<String> {
    v.db_host.clone().or_else(|| constant("DB_HOST"))
}

/// A PHP constant's string value, or `None` when it is not defined.
fn constant(name: &str) -> Option<String> {
    let c = CString::new(name).ok()?;
    // SAFETY: a NUL-terminated name; the returned zval (if any) lives in the constants table.
    let zv = unsafe { zend_get_constant_str(c.as_ptr(), name.len()).cast::<Zval>().as_ref() }?;
    zv.str().map(str::to_owned)
}

unsafe extern "C" {
    /// Zend/zend_constants.h: the constant's value, or NULL when it is not defined.
    fn zend_get_constant_str(name: *const c_char, name_len: usize) -> *mut zval;
}

/// Record a refused password swap (both modes): the reason, the component (if known) and the host
/// it tried to reach. Never the password or any placeholder's value.
fn refuse(reason: &str, who: Option<Component>, host: Option<&str>) {
    let mode = crate::live_arc().map_or(Mode::Enforce, |l| l.config.layer2.mode);
    let who = who.map_or_else(|| "unknown".to_string(), |c| c.to_string());
    let host = host.unwrap_or("");
    crate::log(crate::LOG_WARNING, &format!("vault: refused DB-password swap ({reason}) for {who} connecting to {host:?} [{}]", mode.as_str()));
}

/// For `define(name, value)`: if `name` is a vault secret, force `value` (argument 2) to the
/// secret's placeholder, whatever source produced it (so a wp-config string literal is masked
/// just like an env value).
///
/// # Safety
/// `ex` is a live `define` call frame.
unsafe fn force_define_placeholder(ex: *mut zend_execute_data) {
    let Some(name) = (unsafe { arg(ex, 1) }).and_then(Zval::str) else { return };
    if vault().is_none_or(|v| !v.by_name.contains_key(name)) {
        return;
    }
    let ph = placeholder(name);
    if let Some(value) = unsafe { arg_mut(ex, 2) } {
        let _ = value.set_string(&ph, false);
    }
}

/// Replace a secret value in `getenv()`'s return — a bare string, or any matching entry of the
/// all-variables array — with the placeholder.
///
/// # Safety
/// `return_value` is the engine's return slot for this `getenv` call.
unsafe fn mask_getenv_result(return_value: *mut zval) {
    let Some(rv) = (unsafe { return_value.cast::<Zval>().as_mut() }) else { return };
    let Some(vault) = vault() else { return };
    // A single value: replace it when it is a secret (compute the placeholder before taking the
    // mutable borrow for set_string).
    let one = rv.str().and_then(|s| vault.by_value.iter().find(|(v, _)| v == s).map(|(_, ph)| ph.clone()));
    if let Some(ph) = one {
        let _ = rv.set_string(&ph, false);
        return;
    }
    if rv.is_string() {
        return; // a non-secret string: nothing to mask
    }
    if let Some(arr) = rv.array_mut() {
        // Collect the string keys whose value is a secret, then overwrite them.
        let mut hits: Vec<(String, String)> = Vec::new();
        for (key, val) in arr.iter() {
            if let Some(s) = val.str()
                && let Some((_, ph)) = vault.by_value.iter().find(|(v, _)| v == s)
            {
                hits.push((key.to_string(), ph.clone()));
            }
        }
        for (key, ph) in hits {
            let _ = arr.insert(key.as_str(), ph);
        }
    }
}

// --- the native salted pluggables ---------------------------------------------------------------

/// `wp_salt($scheme)` as the extension serves it: never the real secret. Returns a stable,
/// scheme-specific token so the key stays in the extension; core computes its real HMACs through
/// [`securecore_vault_hash`], not this. A probe that calls `wp_salt()` gets this token, not the
/// key.
#[php_function]
pub fn securecore_vault_salt(scheme: Option<String>) -> String {
    let scheme = scheme.unwrap_or_else(|| "auth".to_string());
    format!("securecore-vault-salt:{scheme}")
}

/// `wp_hash($data, $scheme, $algo)`, native: `hash_hmac($algo, $data, wp_salt($scheme))` over the
/// **real** keys from the vault, so the HMAC key never becomes a PHP value. Byte-identical to
/// stock WordPress for the standard key/salt constants. Falls back to an empty string only when
/// the vault can't serve the scheme (no vault, or a missing constant) or the algorithm is
/// unsupported — the same shape core would hit with undefined salts.
#[php_function]
pub fn securecore_vault_hash(data: String, scheme: Option<String>, algo: Option<String>) -> String {
    let scheme = scheme.unwrap_or_else(|| "auth".to_string());
    let algo = algo.unwrap_or_else(|| "md5".to_string());
    match vault() {
        Some(v) => salt::wp_hash(data.as_bytes(), &scheme, &algo, v).unwrap_or_default(),
        None => String::new(),
    }
}

/// Add the native salted pluggables to the module (called from [`crate::get_module`], so the
/// `wrap_function!` glue the macro generates is in this module's scope).
pub(crate) fn register(module: ModuleBuilder) -> ModuleBuilder {
    module
        .function(wrap_function!(securecore_vault_salt))
        .function(wrap_function!(securecore_vault_hash))
}

// --- argument access (mirrors attribution::arg, with a mutable form) -----------------------------

/// The zval of argument `n` (1-based) of a call frame: `ZEND_CALL_ARG(call, n)`.
///
/// # Safety
/// `ex` is a live call frame with at least `n` arguments.
pub(crate) unsafe fn arg<'a>(ex: *mut zend_execute_data, n: u32) -> Option<&'a Zval> {
    if n == 0 || n > unsafe { num_args(ex) } {
        return None;
    }
    unsafe { crate::attribution::arg(ex, n) }
}

/// A mutable reference to argument `n` (1-based) of a call frame.
///
/// # Safety
/// `ex` is a live call frame with at least `n` arguments.
pub(crate) unsafe fn arg_mut<'a>(ex: *mut zend_execute_data, n: u32) -> Option<&'a mut Zval> {
    if n == 0 || n > unsafe { num_args(ex) } {
        return None;
    }
    let slot = std::mem::size_of::<zend_execute_data>().div_ceil(std::mem::size_of::<zval>());
    // SAFETY: n is within the frame's argument count (checked above).
    unsafe { ex.cast::<zval>().add(slot + n as usize - 1).cast::<Zval>().as_mut() }
}

/// `ZEND_CALL_NUM_ARGS(call)`.
///
/// # Safety
/// `ex` is a live call frame.
unsafe fn num_args(ex: *mut zend_execute_data) -> u32 {
    unsafe { ex.as_ref() }.map_or(0, |f| unsafe { f.This.u2.num_args })
}
