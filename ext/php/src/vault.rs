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
use securecore_config::salt::{self, Secrets};
use securecore_config::{Config, Secret, Source};

/// The placeholder a secret's real value is replaced by, everywhere PHP can see. Unique per
/// secret (it carries the constant name), so the point of use knows which value to restore.
fn placeholder(name: &str) -> String {
    format!("securecore-vault:{name}")
}

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
}

impl Secrets for Vault {
    fn get(&self, name: &str) -> Option<&str> {
        self.by_name.get(name).map(String::as_str)
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
    let _ = VAULT.set(Vault { by_name: values, by_placeholder, by_value });
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

// --- the function handlers ----------------------------------------------------------------------

/// A Zend internal-function handler.
type Zif = unsafe extern "C" fn(*mut zend_execute_data, *mut zval);

/// Global functions we override, and the 1-based argument that carries the DB password (if any).
/// `getenv`/`define` have no password arg; the mysqli/PDO constructors are handled as methods.
const FUNCS: &[(&str, Option<u32>)] = &[
    ("getenv", None),
    ("define", None),
    ("mysqli_connect", Some(3)),
    ("mysqli_real_connect", Some(4)),
];
/// Methods we override: `(class, method, password arg)`.
const METHODS: &[(&str, &str, u32)] = &[("mysqli", "__construct", 3), ("pdo", "__construct", 3)];

/// The handlers we replaced, by a key (`"func"` or `"class::method"`), with the password arg.
struct Override {
    original: Zif,
    password_arg: Option<u32>,
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
        for &(name, pw) in FUNCS {
            if let Some(original) = unsafe { hook_in(ft, name) } {
                originals.insert(name.to_string(), Override { original, password_arg: pw });
            }
        }
    }
    let ct = unsafe { (*std::ptr::addr_of_mut!(ext_php_rs::ffi::compiler_globals)).class_table };
    if !ct.is_null() {
        for &(class, method, pw) in METHODS {
            // SAFETY: the class table; the class entry (if present) owns its function table.
            let ce = unsafe { zend_hash_str_find_ptr_lc(ct.cast_const(), class.as_ptr().cast(), class.len()) }.cast::<ext_php_rs::ffi::zend_class_entry>();
            let Some(ce) = (unsafe { ce.as_ref() }) else { continue };
            let mft: *const ext_php_rs::ffi::HashTable = std::ptr::addr_of!(ce.function_table);
            if let Some(original) = unsafe { hook_in(mft.cast_mut(), method) } {
                originals.insert(format!("{class}::{method}"), Override { original, password_arg: Some(pw) });
            }
        }
    }
    let _ = ORIGINALS.set(originals);
}

/// Replace the handler of the internal function `name` in table `ft` with [`dispatch`], returning
/// the handler it replaced.
///
/// # Safety
/// `ft` is a live function table on the request's own thread.
unsafe fn hook_in(ft: *mut ext_php_rs::ffi::HashTable, name: &str) -> Option<Zif> {
    let lc = name.to_ascii_lowercase();
    // SAFETY: a live function table and a byte string; the lookup is read-only.
    let ptr = unsafe { zend_hash_str_find_ptr_lc(ft.cast_const(), lc.as_ptr().cast(), lc.len()) };
    let func = unsafe { ptr.cast::<zend_function>().as_mut() }?;
    // SAFETY: an internal function; reading the union.
    let previous = unsafe { func.internal_function.handler }?;
    func.internal_function.handler = Some(dispatch);
    Some(previous)
}

/// The replacement handler for every overridden function/method.
unsafe extern "C" fn dispatch(execute_data: *mut zend_execute_data, return_value: *mut zval) {
    let key = unsafe { dispatch_key(execute_data) };
    let Some(ov) = key.as_deref().and_then(|k| ORIGINALS.get().and_then(|m| m.get(k))) else {
        return;
    };
    let name = key.as_deref().unwrap_or("");

    // Point of use: swap a placeholder password argument for the real value, in the frame, before
    // the engine's own function runs. The caller's own `$password` zval is untouched (a by-value
    // argument is a separate zval), so the real value reaches libmysql/PDO and no PHP variable.
    if let Some(n) = ov.password_arg {
        unsafe { swap_password(execute_data, n) };
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
unsafe fn dispatch_key(ex: *mut zend_execute_data) -> Option<String> {
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

/// If argument `n` (1-based) of the frame is a known placeholder, replace it in place with the
/// real value.
///
/// # Safety
/// `ex` is a live call frame.
unsafe fn swap_password(ex: *mut zend_execute_data, n: u32) {
    let Some(zv) = (unsafe { arg_mut(ex, n) }) else { return };
    // Resolve the real value before taking the mutable borrow for set_string.
    let real = zv.str().and_then(|current| vault().and_then(|v| v.by_placeholder.get(current)).cloned());
    if let Some(real) = real {
        let _ = zv.set_string(&real, false);
    }
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
unsafe fn arg<'a>(ex: *mut zend_execute_data, n: u32) -> Option<&'a Zval> {
    if n == 0 || n > unsafe { num_args(ex) } {
        return None;
    }
    unsafe { crate::attribution::arg(ex, n) }
}

/// A mutable reference to argument `n` (1-based) of a call frame.
///
/// # Safety
/// `ex` is a live call frame with at least `n` arguments.
unsafe fn arg_mut<'a>(ex: *mut zend_execute_data, n: u32) -> Option<&'a mut Zval> {
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
