//! The layer-2 database policy (addiscorp/securecore#53, phase E4), wired into PHP. The rules
//! live in [`securecore_db`] (plain Rust, unit-tested); this module finds the queries and carries
//! out the decision.
//!
//! **Where queries are seen.** Every route that hands SQL text to the server, as an internal
//! function handler (through the vault's [`crate::vault::hook_with`], so the two share one hook
//! mechanism and never hook the same function): `mysqli_query`, `mysqli_real_query`,
//! `mysqli_multi_query`, `mysqli_prepare`, `mysqli_stmt_prepare`, `mysqli_execute_query` and their
//! `mysqli` / `mysqli_stmt` methods (`new mysqli_stmt($link, $sql)` included), and `PDO::exec`,
//! `PDO::query`, `PDO::prepare`. `$wpdb` uses `mysqli_query`, so WordPress is covered there. The
//! execute calls (`mysqli_stmt_execute`, `PDOStatement::execute`) carry no SQL: the statement was
//! checked when it was prepared. PHP 8.3 has no `mysqli_send_query`; an async query
//! (`MYSQLI_ASYNC`) is sent by `mysqli_query`. `select_db` and `change_user` are refused for a
//! component (they are `USE` and a re-login), and `set_charset` to a charset the parser can't read
//! the way MySQL does is refused for everyone.
//!
//! **Who.** The code that called the database layer, through core's passthrough helpers
//! ([`securecore_db::caller`]). Files stay on E2a's `component` rule.
//!
//! **What a refusal does.** `log`: an audit line, and the query runs. `enforce`: the audit line,
//! and the server is given a statement that fails in its place, so the failure is the native one
//! in every error mode: a query route gets `SIGNAL SQLSTATE '42000' SET MYSQL_ERRNO = 1142`
//! (MySQL's "command denied" error) with the reason as its message, so mysqli returns false and
//! sets `errno`/`error` (or throws `mysqli_sql_exception` in strict report mode), PDO follows its
//! error mode, and `$wpdb->last_error` shows it. A mysqli *prepare* gets a statement the server
//! rejects at prepare time (a syntax error naming the rule) instead: MariaDB prepares a SIGNAL
//! successfully and would fail only at execute, after `bind_param` had already thrown on the
//! placeholder count. `off`: nothing.
//!
//! **Cost.** Analyses are cached by query text in a bounded per-worker LRU ([`CACHE_SIZE`]), so a
//! repeated query costs a hash lookup; the decision is a few set lookups.

use std::collections::HashMap;
use std::ffi::{CString, c_char};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use ext_php_rs::ffi::{IS_INDIRECT, IS_REFERENCE, zend_execute_data, zend_hash_str_find, zval};
use ext_php_rs::types::Zval;
use securecore_attribution::{Component, Rule};
use securecore_config::Mode;
use securecore_db::{Cache, Decision, Rules4, Site, Who, analyze::safe_charset, decide};

use crate::vault::{self, Zif};

/// Distinct query texts kept per worker.
pub const CACHE_SIZE: usize = 2048;

/// The ini setting choosing who a query is charged to (PHP_INI_SYSTEM).
pub const INI_ATTRIBUTION: &str = "securecore.debug_db_attribution";

/// Who a query is charged to. The rule is `Caller`, fixed (#60); the ini setting exists only to
/// reproduce the measurement that chose it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DbAttribution {
    /// The code that called the database layer ([`securecore_db::caller`]): a component's own SQL
    /// is the component's, SQL a core API composes is core's, and core's passthrough helpers
    /// (`dbDelta`, `update_option`, …) hand the charge to their caller.
    Caller,
    /// Research only: E2a's configured rule (the innermost component on the stack), which charges
    /// a plugin for the SQL a core API runs on its behalf (with Yoast active it logs the admin out).
    Component,
}

static ATTRIBUTION: OnceLock<DbAttribution> = OnceLock::new();

/// At MINIT: the research setting. An unknown value refuses to start (fail closed).
pub(crate) fn startup(value: &str) -> Result<(), String> {
    let a = match value.trim() {
        "" | "caller" => DbAttribution::Caller,
        "component" => DbAttribution::Component,
        other => return Err(format!("{INI_ATTRIBUTION} = {other:?}: expected component or caller")),
    };
    let _ = ATTRIBUTION.set(a);
    Ok(())
}

/// What a hooked route does with its SQL argument.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Sends the text as a query: a refusal becomes the SIGNAL.
    Query,
    /// mysqli prepare: a refusal becomes a statement that fails at prepare.
    Prepare,
    /// `USE` / re-login: refused for a component.
    NotForComponents,
    /// Changes the connection charset: an unsafe one is refused for everyone.
    Charset,
}

/// `(route, argument holding the SQL, kind)`.
const FUNCS: &[(&str, u32, Kind)] = &[
    ("mysqli_query", 2, Kind::Query),
    ("mysqli_real_query", 2, Kind::Query),
    ("mysqli_multi_query", 2, Kind::Query),
    ("mysqli_prepare", 2, Kind::Prepare),
    ("mysqli_stmt_prepare", 2, Kind::Prepare),
    ("mysqli_execute_query", 2, Kind::Prepare),
    ("mysqli_select_db", 2, Kind::NotForComponents),
    ("mysqli_change_user", 2, Kind::NotForComponents),
    ("mysqli_set_charset", 2, Kind::Charset),
];
const METHODS: &[(&str, &str, u32, Kind)] = &[
    ("mysqli", "query", 1, Kind::Query),
    ("mysqli", "real_query", 1, Kind::Query),
    ("mysqli", "multi_query", 1, Kind::Query),
    ("mysqli", "prepare", 1, Kind::Prepare),
    ("mysqli", "execute_query", 1, Kind::Prepare),
    ("mysqli", "select_db", 1, Kind::NotForComponents),
    ("mysqli", "change_user", 1, Kind::NotForComponents),
    ("mysqli", "set_charset", 1, Kind::Charset),
    ("mysqli_stmt", "__construct", 2, Kind::Prepare),
    ("mysqli_stmt", "prepare", 1, Kind::Prepare),
    // PDO prepares are emulated by default and never throw on a placeholder count, so a SIGNAL is
    // the right failure for all three.
    ("pdo", "exec", 1, Kind::Query),
    ("pdo", "query", 1, Kind::Query),
    ("pdo", "prepare", 1, Kind::Query),
];

struct Hook {
    original: Zif,
    route: &'static str,
    sql_arg: u32,
    kind: Kind,
}

static HOOKS: OnceLock<HashMap<String, Hook>> = OnceLock::new();
static INSTALLED: AtomicBool = AtomicBool::new(false);
static CACHE: Mutex<Option<Cache>> = Mutex::new(None);
/// The config's sha256, and each component's effective rules under it.
type RulesBySlug = (String, Option<HashMap<String, Arc<Rules4>>>);
static RULES: Mutex<RulesBySlug> = Mutex::new((String::new(), None));
/// The site facts, read once per request (the prefix is set by wp-config.php).
static SITE: Mutex<Option<Site>> = Mutex::new(None);

fn lock<T>(m: &'static Mutex<T>) -> MutexGuard<'static, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// At request start, when layer 2 is active: install the handlers once per process, and forget the
/// last request's site facts.
pub(crate) fn request_startup() {
    *lock(&SITE) = None;
    if !crate::enforce::layer2_active() || INSTALLED.swap(true, Ordering::Relaxed) {
        return;
    }
    // SAFETY: the function and class tables on the request's own thread, before userland runs.
    unsafe { install() };
}

/// # Safety
/// Called once, from RINIT, before userland code runs this request.
unsafe fn install() {
    let mut hooks = HashMap::new();
    let ft = unsafe { (*std::ptr::addr_of_mut!(ext_php_rs::ffi::compiler_globals)).function_table };
    if !ft.is_null() {
        for &(name, sql_arg, kind) in FUNCS {
            if let Some(original) = unsafe { vault::hook_with(ft, name, dispatch) } {
                hooks.insert(name.to_owned(), Hook { original, route: name, sql_arg, kind });
            }
        }
    }
    for &(class, method, sql_arg, kind) in METHODS {
        if let Some(mft) = unsafe { vault::method_table(class) }
            && let Some(original) = unsafe { vault::hook_with(mft, method, dispatch) }
        {
            let route: &'static str = Box::leak(format!("{class}::{method}").into_boxed_str());
            hooks.insert(route.to_owned(), Hook { original, route, sql_arg, kind });
        }
    }
    let _ = HOOKS.set(hooks);
}

/// What the handler does after the check.
enum Then {
    /// Call the original with the arguments as they are.
    Run,
    /// Replace the SQL argument with this, then call the original (enforce).
    RunInstead(String),
    /// Return false without calling the original (enforce, a non-query route).
    False,
}

unsafe extern "C" fn dispatch(execute_data: *mut zend_execute_data, return_value: *mut zval) {
    let Some(key) = (unsafe { vault::dispatch_key(execute_data) }) else { return };
    let Some(hook) = HOOKS.get().and_then(|h| h.get(&key)) else { return };
    match unsafe { check(execute_data, hook) } {
        Then::Run => {}
        Then::RunInstead(sql) => {
            if let Some(zv) = unsafe { vault::arg_mut(execute_data, hook.sql_arg) } {
                let _ = zv.set_string(&sql, false);
            }
        }
        Then::False => {
            if let Some(rv) = unsafe { return_value.cast::<Zval>().as_mut() } {
                rv.set_bool(false);
            }
            return;
        }
    }
    // SAFETY: the engine handler we replaced for this function.
    unsafe { (hook.original)(execute_data, return_value) };
}

/// # Safety
/// `ex` is the live call frame of `hook`'s route.
unsafe fn check(ex: *mut zend_execute_data, hook: &Hook) -> Then {
    let Some(loaded) = crate::live_arc() else { return Then::Run };
    let l2 = &loaded.config.layer2;
    if !l2.enabled || l2.app.is_none() || l2.mode == Mode::Off {
        return Then::Run;
    }
    let Some(text) = (unsafe { vault::arg(ex, hook.sql_arg) }).and_then(Zval::str).map(str::to_owned) else {
        // No SQL argument (mysqli_stmt without a query, a non-string): nothing to decide.
        return Then::Run;
    };
    let from = unsafe { ex.as_ref() }.map_or(std::ptr::null(), |f| f.prev_execute_data);
    let who = match ATTRIBUTION.get().copied().unwrap_or(DbAttribution::Caller) {
        DbAttribution::Component => {
            let rule = crate::attribution::settings().map_or(Rule::Component, |s| s.rule);
            crate::attribution::responsible(rule, &loaded.root, from)
        }
        DbAttribution::Caller => crate::attribution::db_caller(&loaded.root, from),
    };
    let component = who.is_component();

    match hook.kind {
        Kind::NotForComponents if component => return refuse(l2.mode, &who, hook.route, "statement", "", "-", Then::False),
        Kind::NotForComponents => return Then::Run,
        Kind::Charset if !safe_charset(&text) => return refuse(l2.mode, &who, hook.route, "charset", "", &text, Then::False),
        Kind::Charset => return Then::Run,
        Kind::Query | Kind::Prepare => {}
    }

    let analysis = lock(&CACHE).get_or_insert_with(|| Cache::new(CACHE_SIZE)).get(&text);
    let decision = if component {
        let slug = match &who {
            Component::Plugin(s) | Component::MuPlugin(s) | Component::Theme(s) => s.as_str(),
            Component::Core | Component::Outside => "",
        };
        let rules = rules_for(&loaded.sha256, l2, slug);
        match site() {
            Some(site) => decide(&analysis, &Who::Component(&rules), &site),
            // The table prefix is unknown (no $table_prefix yet), so core's tables can't be told
            // apart: a component's query that names any table is refused.
            None if analysis.tables().next().is_some() => Decision::Refuse("site-unknown"),
            None => decide(&analysis, &Who::Component(&rules), &Site { prefix: "\u{0}".into(), db_name: None }),
        }
    } else {
        decide(&analysis, &Who::Core, &site().unwrap_or(Site { prefix: "\u{0}".into(), db_name: None }))
    };
    let tables = {
        let t: Vec<String> = analysis.tables().map(ToString::to_string).collect();
        if t.is_empty() { "-".to_owned() } else { t.join(",") }
    };
    match decision {
        Decision::Allow => Then::Run,
        Decision::AllowLogged(r) => {
            audit(l2.mode, &who, hook.route, r, &analysis.keyword, &tables);
            Then::Run
        }
        Decision::Refuse(r) => {
            // An options refusal names the options it pinned, so securecore-db-suggest can propose
            // the entry that would open it.
            let tables = match r {
                "option" | "protected-option" | "options-unpinned" if !analysis.option_names.names.is_empty() => {
                    let names: Vec<String> = analysis
                        .option_names
                        .names
                        .iter()
                        .map(|p| match p {
                            securecore_db::analyze::Pin::Exact(n) => n.clone(),
                            securecore_db::analyze::Pin::Prefix(n) => format!("{n}*"),
                        })
                        .collect();
                    format!("{tables} options={}", names.join(","))
                }
                _ => tables,
            };
            let instead = match hook.kind {
                Kind::Prepare => Then::RunInstead(format!("securecore_denied_{}", r.replace('-', "_"))),
                _ => Then::RunInstead(signal(&who, &analysis.keyword, r)),
            };
            refuse(l2.mode, &who, hook.route, r, &analysis.keyword, &tables, instead)
        }
    }
}

fn refuse(mode: Mode, who: &Component, route: &str, rule: &str, keyword: &str, tables: &str, then: Then) -> Then {
    audit(mode, who, route, rule, keyword, tables);
    if mode == Mode::Enforce { then } else { Then::Run }
}

/// `layer2 <mode> <component> <route> <rule> <statement> <tables>`, like the file policy's lines.
fn audit(mode: Mode, who: &Component, route: &str, rule: &str, keyword: &str, tables: &str) {
    let keyword = if keyword.is_empty() { "-" } else { keyword };
    crate::log(crate::LOG_NOTICE, &format!("layer2 {} {who} {route} {rule} {keyword} {tables}", mode.as_str()));
}

/// The statement run in place of a refused query: MySQL's "command denied" error, the reason as
/// its message (at most 128 characters, quotes and backslashes kept out).
fn signal(who: &Component, keyword: &str, rule: &str) -> String {
    let clean = |s: &str| s.chars().map(|c| if c.is_ascii_alphanumeric() || "._:-".contains(c) { c } else { '_' }).collect::<String>();
    let mut msg = format!("securecore: {} may not run this {} ({})", clean(&who.to_string()), clean(keyword), clean(rule));
    msg.truncate(128);
    format!("SIGNAL SQLSTATE '42000' SET MYSQL_ERRNO = 1142, MESSAGE_TEXT = '{msg}'")
}

fn rules_for(sha: &str, l2: &securecore_config::Layer2, slug: &str) -> Arc<Rules4> {
    let mut guard = lock(&RULES);
    if guard.0 != sha {
        *guard = (sha.to_owned(), Some(HashMap::new()));
    }
    let map = guard.1.get_or_insert_with(HashMap::new);
    Arc::clone(map.entry(slug.to_owned()).or_insert_with(|| Arc::new(Rules4::for_component(l2, slug))))
}

/// The table prefix (`$table_prefix`) and `DB_NAME`, once wp-config.php has set them; read once per
/// request.
fn site() -> Option<Site> {
    let mut guard = lock(&SITE);
    if guard.is_none() {
        let prefix = global_string("table_prefix")?.to_ascii_lowercase();
        *guard = Some(Site { prefix, db_name: constant("DB_NAME").map(|s| s.to_ascii_lowercase()) });
    }
    guard.clone()
}

/// A global variable's string value (`$GLOBALS[name]`), following the symbol table's indirect and
/// reference slots.
fn global_string(name: &str) -> Option<String> {
    let c = CString::new(name).ok()?;
    // SAFETY: EG(symbol_table) on the request's own thread; a read-only lookup.
    let mut zv = unsafe {
        let table = std::ptr::addr_of!((*std::ptr::addr_of!(ext_php_rs::ffi::executor_globals)).symbol_table);
        zend_hash_str_find(table, c.as_ptr(), name.len())
    };
    // SAFETY: zv is a live zval from the table (or NULL); IS_INDIRECT points at the CV slot,
    // IS_REFERENCE at a zend_reference whose first member after the refcount header is its zval.
    unsafe {
        for _ in 0..2 {
            let z = zv.as_ref()?;
            match u32::from(z.u1.v.type_) {
                t if t == IS_INDIRECT => zv = z.value.zv,
                t if t == IS_REFERENCE => zv = std::ptr::addr_of_mut!((*z.value.ref_).val),
                _ => break,
            }
        }
        zv.cast::<Zval>().as_ref()?.str().map(str::to_owned)
    }
}

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
