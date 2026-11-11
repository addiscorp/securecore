//! Layer-2 outbound hostname allowlist (addiscorp/securecore#53, phase E5): every network
//! connection PHP makes is attributed to a component and checked against that component's `hosts`
//! (or `core.hosts` for core). The matching rules live in [`securecore_attribution::hosts`] (plain
//! Rust, unit-tested); this module is the wiring onto PHP's network routes.
//!
//! **Decide on the host the connection actually goes to, not what a URL claims.** The checks sit
//! where the real connect host is known:
//!
//! - **The http/https/ftp/ftps stream wrappers** (file_get_contents, fopen, get_headers,
//!   SoapClient) go through a volatile URL wrapper whose opener and url ops check the target host
//!   and delegate to the built-in wrapper. The built-in http wrapper re-enters this opener for
//!   every redirect hop (it re-opens the `Location` URL through the wrapper registry), so **each
//!   hop is checked**. A `user:pass@` prefix is stripped before the host is read, and a proxy set
//!   in the stream context is checked too (its host *and* the target host must both be allowed).
//! - **fsockopen, pfsockopen, stream_socket_client** and **socket_connect** (ext/sockets) go
//!   through function handlers that read the host (or `transport://host:port`) argument — the host
//!   the function itself resolves and connects to.
//! - **curl** (`curl_exec`, `curl_multi_add_handle`) is checked from the options recorded on the
//!   handle (`curl_init`/`curl_setopt`/`curl_setopt_array`): the URL host, `CURLOPT_PROXY`, and the
//!   `CURLOPT_RESOLVE` / `CURLOPT_CONNECT_TO` overrides, so an override that points an allowed name
//!   at a disallowed IP or host is refused.
//!
//! **DNS rebinding.** Layer 2 allowlists *names*, and it checks the exact name string the connect
//! uses (the wrapper and the socket functions resolve the very name this module read), so there is
//! no check-versus-connect *name* discrepancy to exploit. An allowed name whose DNS later resolves
//! to an internal IP is an IP-level rebind a name allowlist cannot see; layer 1's port rules (no
//! internal ports open) are its backstop, documented in `ext/README.md`.
//!
//! A refused connection fails the way PHP fails on a refused connection: the stream opener returns
//! NULL (so file_get_contents/fopen warn and return `false`, and WordPress's Requests library turns
//! that into a `WP_Error`), the socket functions return `false`, and curl_exec returns `false` —
//! never a fatal. `log` mode records the line and lets it through; `off` does neither.
//!
//! This module is independent of [`crate::enforce`] (a disjoint set of functions, its own handler
//! table), so E3's vault (which also edits `enforce.rs`'s install list and the DB handlers) merges
//! without touching it. Database connections (mysqli/PDO through mysqlnd) do not pass through any
//! route here, so **core's DB host is reached without a hosts check** — see the module note below.

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard, OnceLock, PoisonError};

use ext_php_rs::error::php_error;
use ext_php_rs::ffi::{
    php_register_url_stream_wrapper_volatile, php_stream, php_stream_context, php_stream_statbuf, php_stream_wrapper,
    php_stream_wrapper_ops, php_unregister_url_stream_wrapper_volatile, zend_execute_data, zend_function,
    zend_hash_str_find_ptr_lc, zend_string, zval,
};
use ext_php_rs::flags::ErrorType;
use ext_php_rs::types::{ArrayKey, ZendCallable, ZendStr, Zval};
use securecore_attribution::hosts;
use securecore_attribution::{Component, Rule};
use securecore_config::Mode;

use crate::attribution;

unsafe extern "C" {
    /// The engine's built-in http(s) and ftp(s) URL wrappers (main/php_streams.h, ext/standard).
    /// We read their ops and delegate to them; we never write them.
    static php_stream_http_wrapper: php_stream_wrapper;
    static php_stream_ftp_wrapper: php_stream_wrapper;
    /// The socket-transport factory registry (main/streams/transports.c). Overriding the tcp/ssl/
    /// tls factories is the one point every PHP socket connection passes through *at connect time*,
    /// with the real host — including each redirect hop the http wrapper follows internally.
    fn php_stream_xport_get_hash() -> *mut ext_php_rs::ffi::HashTable;
    fn php_stream_xport_register(protocol: *const c_char, factory: TransportFactory) -> c_int;
    /// Zend/zend_constants.h: a constant's value, or NULL (used to read WordPress's `DB_HOST`).
    fn zend_get_constant_str(name: *const c_char, name_len: usize) -> *mut zval;
}

/// A socket-transport factory (`php_stream_transport_factory_func`), the non-debug signature
/// (no `STREAMS_DC` tail), matching the engine's production build. `timeout` and `context` are
/// passed through untouched, so `timeout` is an opaque pointer here.
type TransportFactory = unsafe extern "C" fn(
    proto: *const c_char,
    protolen: usize,
    resourcename: *const c_char,
    resourcenamelen: usize,
    persistent_id: *const c_char,
    options: c_int,
    flags: c_int,
    timeout: *mut std::ffi::c_void,
    context: *mut php_stream_context,
) -> *mut php_stream;

/// `STREAM_XPORT_CONNECT` (main/streams/php_stream_transport.h): set when the transport is being
/// opened to connect out (a client), as opposed to bind/listen (a server). We check only connects.
const STREAM_XPORT_CONNECT: c_int = 2;

/// The transports we override, and the originals we delegate to (addresses kept as `usize` so the
/// map is `Send`/`Sync`; transmuted back to call).
static ORIG_FACTORIES: OnceLock<SyncFactories> = OnceLock::new();
struct SyncFactories(HashMap<String, usize>);
unsafe impl Sync for SyncFactories {}
unsafe impl Send for SyncFactories {}
static XPORT_INSTALLED: AtomicBool = AtomicBool::new(false);
const XPORT_PROTOCOLS: &[&str] = &["tcp", "ssl", "tls"];

/// A Zend internal-function handler.
type Zif = unsafe extern "C" fn(*mut zend_execute_data, *mut zval);

/// Functions whose network connection is checked (refused by failing as PHP fails). The curl
/// recording functions are installed too, but never refuse.
const CHECK: &[&str] = &["fsockopen", "pfsockopen", "stream_socket_client", "socket_connect", "curl_exec", "curl_multi_add_handle"];
/// Functions that only record a curl handle's options, so the check at `curl_exec` has them.
const RECORD: &[&str] = &["curl_init", "curl_setopt", "curl_setopt_array", "curl_reset", "curl_close", "curl_copy_handle"];

/// The handlers we replaced. Set once per process; read lock-free.
static ORIGINALS: OnceLock<HashMap<String, Zif>> = OnceLock::new();
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Interned protocol strings for the volatile wrapper registration, made once and kept forever.
static PROTOCOLS: OnceLock<SyncPtrs> = OnceLock::new();
// SAFETY: the pointers are to persistent interned zend_strings (never freed); PHP is NTS.
struct SyncPtrs(Vec<*mut zend_string>);
unsafe impl Sync for SyncPtrs {}
unsafe impl Send for SyncPtrs {}

/// Layer 2's hostname allowlist is active right now: enabled, an app set, mode not `off`.
pub(crate) fn hosts_active() -> bool {
    crate::with_live(|l| hosts::checks_hosts(&l.config.layer2)).unwrap_or(false)
}

// --- the volatile net wrapper -------------------------------------------------------------------

struct SyncWops(php_stream_wrapper_ops);
// SAFETY: initialised once at compile time, never mutated; PHP is NTS.
unsafe impl Sync for SyncWops {}

/// Our http/https/ftp/ftps wrapper's ops: every one checks the target (and proxy) host, then
/// delegates to the matching built-in wrapper's op.
static SC_WOPS: SyncWops = SyncWops(php_stream_wrapper_ops {
    stream_opener: Some(sc_opener),
    stream_closer: None,
    stream_stat: None,
    url_stat: Some(sc_url_stat),
    dir_opener: Some(sc_dir_opener),
    label: std::ptr::null(),
    unlink: Some(sc_unlink),
    rename: Some(sc_rename),
    stream_mkdir: Some(sc_mkdir),
    stream_rmdir: Some(sc_rmdir),
    stream_metadata: Some(sc_metadata),
});

static mut SC_WRAPPER: php_stream_wrapper = php_stream_wrapper { wops: std::ptr::null(), abstract_: std::ptr::null_mut(), is_url: 1 };

/// The built-in wrapper for a URL's scheme, to delegate to, and its ops.
///
/// # Safety
/// Reads the engine's immutable wrapper globals.
unsafe fn delegate(url: &str) -> Option<(*mut php_stream_wrapper, &'static php_stream_wrapper_ops)> {
    let scheme = url.split_once("://").map(|(s, _)| s).unwrap_or("");
    // SAFETY: both are valid static wrappers for the process's life.
    let wrapper: *const php_stream_wrapper = match scheme.to_ascii_lowercase().as_str() {
        "http" | "https" => std::ptr::addr_of!(php_stream_http_wrapper),
        "ftp" | "ftps" => std::ptr::addr_of!(php_stream_ftp_wrapper),
        _ => return None,
    };
    let ops = unsafe { (*wrapper).wops.as_ref() }?;
    Some((wrapper.cast_mut(), ops))
}

/// Register our volatile wrappers for http/https/ftp/ftps this request (volatile wrappers are
/// per-request). The built-in ones stay in the global table and are what we delegate to.
unsafe fn register_wrappers() {
    let protocols = PROTOCOLS.get_or_init(|| {
        SyncPtrs(["http", "https", "ftp", "ftps"].iter().map(|p| ZendStr::new_interned(*p, true).into_raw().cast::<zend_string>()).collect())
    });
    // SAFETY: SC_WRAPPER is set once before it is registered or read.
    unsafe { (*std::ptr::addr_of_mut!(SC_WRAPPER)).wops = std::ptr::addr_of!(SC_WOPS.0) };
    for &protocol in &protocols.0 {
        // SAFETY: the volatile wrapper API on the request's own thread, with a persistent key.
        unsafe {
            php_unregister_url_stream_wrapper_volatile(protocol);
            php_register_url_stream_wrapper_volatile(protocol, std::ptr::addr_of_mut!(SC_WRAPPER));
        }
    }
}

// --- the net wrapper ops ------------------------------------------------------------------------

/// Check a URL op's target host (and any context proxy); `true` if the op must be refused.
///
/// # Safety
/// `url` and `context` come from the engine.
unsafe fn blocked_url(url: *const c_char, context: *mut php_stream_context, token: &str) -> bool {
    let Ok(url) = (unsafe { CStr::from_ptr(url) }).to_str() else { return false };
    let from = current_execute_data();
    // The proxy (if any) is connected to in place of the target, and the target is sent on; both
    // must be allowed (brief: "the proxy's host is checked, and the target too").
    if let Some(proxy) = unsafe { context_proxy(context) }
        && check_host(from, &proxy, token, "proxy")
    {
        return true;
    }
    let Some(host) = host_from_url(url) else { return false };
    check_host(from, &host, token, url)
}

unsafe extern "C" fn sc_opener(
    _wrapper: *mut php_stream_wrapper,
    filename: *const c_char,
    mode: *const c_char,
    options: c_int,
    opened_path: *mut *mut zend_string,
    context: *mut php_stream_context,
) -> *mut php_stream {
    if unsafe { blocked_url(filename, context, "open") } {
        return std::ptr::null_mut();
    }
    let Some((wrapper, ops)) = (unsafe { delegate(cstr(filename)) }) else { return std::ptr::null_mut() };
    let Some(opener) = ops.stream_opener else { return std::ptr::null_mut() };
    // SAFETY: delegating to the built-in opener with the arguments unchanged, under the real wrapper.
    unsafe { opener(wrapper, filename, mode, options, opened_path, context) }
}

unsafe extern "C" fn sc_dir_opener(
    _wrapper: *mut php_stream_wrapper,
    filename: *const c_char,
    mode: *const c_char,
    options: c_int,
    opened_path: *mut *mut zend_string,
    context: *mut php_stream_context,
) -> *mut php_stream {
    if unsafe { blocked_url(filename, context, "opendir") } {
        return std::ptr::null_mut();
    }
    let Some((wrapper, ops)) = (unsafe { delegate(cstr(filename)) }) else { return std::ptr::null_mut() };
    let Some(opener) = ops.dir_opener else { return std::ptr::null_mut() };
    unsafe { opener(wrapper, filename, mode, options, opened_path, context) }
}

unsafe extern "C" fn sc_url_stat(wrapper: *mut php_stream_wrapper, url: *const c_char, flags: c_int, ssb: *mut php_stream_statbuf, context: *mut php_stream_context) -> c_int {
    if unsafe { blocked_url(url, context, "url_stat") } {
        return -1;
    }
    let Some((real, ops)) = (unsafe { delegate(cstr(url)) }) else { return -1 };
    let _ = wrapper;
    let Some(f) = ops.url_stat else { return -1 };
    unsafe { f(real, url, flags, ssb, context) }
}

unsafe extern "C" fn sc_unlink(_wrapper: *mut php_stream_wrapper, url: *const c_char, options: c_int, context: *mut php_stream_context) -> c_int {
    if unsafe { blocked_url(url, context, "unlink") } {
        return 0;
    }
    let Some((real, ops)) = (unsafe { delegate(cstr(url)) }) else { return 0 };
    let Some(f) = ops.unlink else { return 0 };
    unsafe { f(real, url, options, context) }
}

unsafe extern "C" fn sc_rename(_wrapper: *mut php_stream_wrapper, from: *const c_char, to: *const c_char, options: c_int, context: *mut php_stream_context) -> c_int {
    if unsafe { blocked_url(from, context, "rename") } || unsafe { blocked_url(to, context, "rename") } {
        return 0;
    }
    let Some((real, ops)) = (unsafe { delegate(cstr(from)) }) else { return 0 };
    let Some(f) = ops.rename else { return 0 };
    unsafe { f(real, from, to, options, context) }
}

unsafe extern "C" fn sc_mkdir(_wrapper: *mut php_stream_wrapper, url: *const c_char, mode: c_int, options: c_int, context: *mut php_stream_context) -> c_int {
    if unsafe { blocked_url(url, context, "mkdir") } {
        return 0;
    }
    let Some((real, ops)) = (unsafe { delegate(cstr(url)) }) else { return 0 };
    let Some(f) = ops.stream_mkdir else { return 0 };
    unsafe { f(real, url, mode, options, context) }
}

unsafe extern "C" fn sc_rmdir(_wrapper: *mut php_stream_wrapper, url: *const c_char, options: c_int, context: *mut php_stream_context) -> c_int {
    if unsafe { blocked_url(url, context, "rmdir") } {
        return 0;
    }
    let Some((real, ops)) = (unsafe { delegate(cstr(url)) }) else { return 0 };
    let Some(f) = ops.stream_rmdir else { return 0 };
    unsafe { f(real, url, options, context) }
}

unsafe extern "C" fn sc_metadata(_wrapper: *mut php_stream_wrapper, url: *const c_char, options: c_int, value: *mut std::ffi::c_void, context: *mut php_stream_context) -> c_int {
    if unsafe { blocked_url(url, context, "metadata") } {
        return 0;
    }
    let Some((real, ops)) = (unsafe { delegate(cstr(url)) }) else { return 0 };
    let Some(f) = ops.stream_metadata else { return 0 };
    unsafe { f(real, url, options, value, context) }
}

/// The `http.proxy` option of a stream context, as a host string, if set.
///
/// # Safety
/// `context` is a valid stream context or null.
unsafe fn context_proxy(context: *mut php_stream_context) -> Option<String> {
    let ctx = unsafe { context.as_ref() }?;
    // SAFETY: `options` is a zval (an array, or undef) held by the context.
    let options = unsafe { std::ptr::addr_of!(ctx.options).cast::<Zval>().as_ref() }?;
    let http = options.array()?.get("http")?.array()?;
    let proxy = http.get("proxy")?.str()?;
    host_from_url(proxy)
}

// --- the function handlers ----------------------------------------------------------------------

/// At request start, when the hosts layer is active: install the function handlers once per
/// process, register the volatile wrappers each request, and clear the per-request curl state.
pub(crate) fn request_startup() {
    if !hosts_active() {
        return;
    }
    if !INSTALLED.load(Ordering::Relaxed) {
        INSTALLED.store(true, Ordering::Relaxed);
        // SAFETY: CG(function_table) on the request's own thread before userland runs.
        unsafe { install() };
    }
    curl().clear();
    if !XPORT_INSTALLED.load(Ordering::Relaxed) {
        XPORT_INSTALLED.store(true, Ordering::Relaxed);
        // SAFETY: the transport registry on the request's own thread, after every MINIT (so
        // ssl/tls from ext/openssl are present), before userland opens a socket.
        unsafe { install_transports() };
    }
    // SAFETY: registering our per-request wrappers before userland opens anything.
    unsafe { register_wrappers() };
}

// --- the transport factory (every socket connect, each redirect hop, at connect time) -----------

/// Override the tcp/ssl/tls/udp transport factories once per process, keeping the originals to
/// delegate to. This is global (there is no volatile transport registry), so the factory itself
/// re-checks `hosts_active()` each time and simply delegates when the layer is off.
///
/// # Safety
/// Called once, from RINIT, on the request's own thread.
unsafe fn install_transports() {
    let hash = unsafe { php_stream_xport_get_hash() };
    if hash.is_null() {
        return;
    }
    let mut originals = HashMap::new();
    for &proto in XPORT_PROTOCOLS {
        // SAFETY: the registry hash and a byte key; the lookup is read-only. A protocol that is
        // not registered (no ext/openssl → no ssl/tls) is skipped.
        let ptr = unsafe { zend_hash_str_find_ptr_lc(hash.cast_const(), proto.as_ptr().cast(), proto.len()) };
        if ptr.is_null() {
            continue;
        }
        originals.insert(proto.to_string(), ptr as usize);
    }
    let _ = ORIG_FACTORIES.set(SyncFactories(originals));
    // Register ours only for the protocols we captured an original for.
    for proto in ORIG_FACTORIES.get().map(|m| m.0.keys().cloned().collect::<Vec<_>>()).unwrap_or_default() {
        if let Ok(c) = CString::new(proto) {
            // SAFETY: registering our factory under an interned copy of the protocol name.
            unsafe { php_stream_xport_register(c.as_ptr(), sc_transport_factory) };
        }
    }
}

/// Our transport factory: on a client connect, check the host the socket actually goes to, then
/// delegate to the original factory. A refused connect returns NULL, exactly as a failed connect
/// does, so the stream/socket function reports failure.
unsafe extern "C" fn sc_transport_factory(
    proto: *const c_char,
    protolen: usize,
    resourcename: *const c_char,
    resourcenamelen: usize,
    persistent_id: *const c_char,
    options: c_int,
    flags: c_int,
    timeout: *mut std::ffi::c_void,
    context: *mut php_stream_context,
) -> *mut php_stream {
    // `proto` points into the resource buffer and is NOT NUL-terminated at the scheme: only the
    // first `protolen` bytes are the protocol (e.g. "tcp" of "tcp://db:3306"). Read exactly those.
    let scheme = unsafe { cstr_n(proto, protolen) };
    let delegate = ORIG_FACTORIES
        .get()
        .and_then(|m| m.0.get(scheme))
        // SAFETY: the stored address is the original factory function for this protocol.
        .map(|&addr| unsafe { std::mem::transmute::<usize, TransportFactory>(addr) });
    let Some(original) = delegate else { return std::ptr::null_mut() };
    // Only client connects carry a host to check; bind/listen do not.
    if flags & STREAM_XPORT_CONNECT != 0
        && let Some(host) = host_from_authority(cstr(resourcename))
        && check_host(current_execute_data(), &host, "connect", cstr(resourcename))
    {
        return std::ptr::null_mut();
    }
    // SAFETY: the engine's own factory, with every argument passed through unchanged.
    unsafe { original(proto, protolen, resourcename, resourcenamelen, persistent_id, options, flags, timeout, context) }
}

/// WordPress's `DB_HOST`, as a bare host (so core's DB connection is allowed implicitly without
/// listing it — see the module note). `None` when the constant is unset.
fn db_host() -> Option<String> {
    let name = CString::new("DB_HOST").ok()?;
    // SAFETY: a NUL-terminated name; the returned zval (if any) lives in the constants table.
    let zv = unsafe { zend_get_constant_str(name.as_ptr(), 7).cast::<Zval>().as_ref() }?;
    host_from_authority(zv.str()?)
}

/// # Safety
/// Called once, from RINIT, before userland code runs this request.
unsafe fn install() {
    let ft = unsafe { (*crate::compiler_globals()).function_table };
    if ft.is_null() {
        return;
    }
    let mut originals = HashMap::new();
    for &name in CHECK.iter().chain(RECORD) {
        // SAFETY: a live function table and a byte string; the lookup is read-only. curl_* are
        // absent when ext/curl is not loaded — then the lookup is null and we skip it.
        let ptr = unsafe { zend_hash_str_find_ptr_lc(ft.cast_const(), name.as_ptr().cast(), name.len()) };
        let Some(func) = (unsafe { ptr.cast::<zend_function>().as_mut() }) else { continue };
        let Some(previous) = (unsafe { func.internal_function.handler }) else { continue };
        func.internal_function.handler = Some(dispatch);
        originals.insert(name.to_string(), previous);
    }
    let _ = ORIGINALS.set(originals);
}

/// The replacement handler for every overridden network function.
unsafe extern "C" fn dispatch(execute_data: *mut zend_execute_data, return_value: *mut zval) {
    let Some(name) = (unsafe { fn_name(execute_data) }) else { return };
    // Recording functions run first, then record from the args (curl_init needs its return value).
    if RECORD.contains(&name) {
        if let Some(original) = ORIGINALS.get().and_then(|m| m.get(name).copied()) {
            unsafe { original(execute_data, return_value) };
        }
        unsafe { record_curl(name, execute_data, return_value) };
        return;
    }
    // curl gets full handling: scheme restriction, the pre-connect host checks, and manual
    // redirect following (libcurl follows internally, below PHP, so FOLLOWLOCATION would otherwise
    // let an open redirect on an allowed host reach anywhere).
    if name == "curl_exec" {
        unsafe { exec_curl(execute_data, return_value) };
        return;
    }
    if name == "curl_multi_add_handle" {
        unsafe { multi_add_curl(execute_data, return_value) };
        return;
    }
    // The socket functions: a refused connection fails without calling the original.
    if unsafe { blocked_call(execute_data, name) } {
        if let Some(rv) = unsafe { return_value.cast::<Zval>().as_mut() } {
            rv.set_bool(false); // fsockopen/pfsockopen/stream_socket_client/socket_connect fail
        }
        return;
    }
    if let Some(original) = ORIGINALS.get().and_then(|m| m.get(name).copied()) {
        // SAFETY: the engine handler we replaced for this function.
        unsafe { original(execute_data, return_value) };
    }
}

/// Whether a checking call must be refused (enforce + a disallowed host).
///
/// # Safety
/// `ex` is the live call frame of `name`.
unsafe fn blocked_call(ex: *mut zend_execute_data, name: &str) -> bool {
    let from = unsafe { ex.as_ref() }.map_or(std::ptr::null(), |f| f.prev_execute_data);
    match name {
        // fsockopen($host, …) / pfsockopen($host, …): arg 1 is `host` or `transport://host`.
        "fsockopen" | "pfsockopen" => unsafe { guard_authority(ex, from, 1, name) },
        // stream_socket_client("tcp://host:port", …): arg 1 is the remote socket.
        "stream_socket_client" => unsafe { guard_authority(ex, from, 1, name) },
        // socket_connect($socket, $address, …): arg 2 is the address (usually an IP literal).
        "socket_connect" => unsafe { guard_authority(ex, from, 2, name) },
        _ => false,
    }
}

/// `curl_exec`/`curl_multi_add_handle` is called `original` with `original(ex, rv)`. This runs the
/// real libcurl `curl_exec` without re-entering our dispatch (we call the saved handler directly).
///
/// # Safety
/// `ex`/`rv` are the live frame and return value.
unsafe fn call_original(name: &str, ex: *mut zend_execute_data, rv: *mut zval) {
    if let Some(original) = ORIGINALS.get().and_then(|m| m.get(name).copied()) {
        // SAFETY: the engine handler we replaced for this function.
        unsafe { original(ex, rv) };
    }
}

/// Guard the host in the authority-shaped argument `n` of a call.
///
/// # Safety
/// `ex` is a live call frame.
unsafe fn guard_authority(ex: *mut zend_execute_data, from: *const zend_execute_data, n: u32, token: &str) -> bool {
    let Some(arg) = (unsafe { arg_string(ex, n) }) else { return false };
    let Some(host) = host_from_authority(&arg) else { return false };
    check_host(from, &host, token, &arg)
}

// --- curl state ---------------------------------------------------------------------------------

/// What a curl handle has been told to do, recorded from its options so the check at
/// `curl_exec` / `curl_multi_add_handle` has them. A handle with no recorded URL fails closed for
/// a restricted component (we never saw it being built).
#[derive(Clone, Default)]
struct CurlState {
    url: Option<String>,
    proxy: Option<String>,
    /// CURLOPT_RESOLVE entries ("host:port:addr[,addr]") and CURLOPT_CONNECT_TO entries
    /// ("host:port:connect-host:connect-port"): the *effective* connect hosts they introduce.
    overrides: Vec<String>,
    follow: bool,
    maxredirs: Option<i64>,
    returntransfer: bool,
    post: bool,
    postredir: i64,
}

static CURL: LazyLock<Mutex<HashMap<u32, CurlState>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn curl() -> MutexGuard<'static, HashMap<u32, CurlState>> {
    CURL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// CURLOPT_* / CURLPROTO_* / CURLINFO numeric constants (stable libcurl values).
const CURLOPT_URL: i64 = 10002;
const CURLOPT_PROXY: i64 = 10004;
const CURLOPT_RESOLVE: i64 = 10203;
const CURLOPT_CONNECT_TO: i64 = 10243;
const CURLOPT_FOLLOWLOCATION: i64 = 52;
const CURLOPT_MAXREDIRS: i64 = 68;
// CURLOPT_RETURNTRANSFER is a PHP-specific option (not a libcurl CURLOPT_*), value 19913.
const CURLOPT_RETURNTRANSFER: i64 = 19913;
const CURLOPT_POST: i64 = 47;
const CURLOPT_POSTFIELDS: i64 = 10015;
const CURLOPT_POSTREDIR: i64 = 161;
const CURLOPT_HTTPGET: i64 = 80;
const CURLOPT_PROTOCOLS: i64 = 181;
const CURLOPT_REDIR_PROTOCOLS: i64 = 182;
/// CURLPROTO_* bits: HTTP|HTTPS|FTP|FTPS — the only schemes a component may reach, so curl can't
/// read `file://` or speak gopher/dict/telnet/smb/… (E2b's file policy and layer 1 would be
/// bypassed otherwise). Redirects are confined to http/https.
const CURLPROTO_HTTP_FTP: i64 = 1 | 2 | 4 | 16;
const CURLPROTO_HTTP_HTTPS: i64 = 1 | 2;
/// The default redirect cap when `CURLOPT_MAXREDIRS` is unset (libcurl's own default is unlimited;
/// we cap at a sane 20, matching common practice).
const DEFAULT_MAXREDIRS: i64 = 20;
/// The schemes a component may use through curl.
const ALLOWED_CURL_SCHEMES: &[&str] = &["http", "https", "ftp", "ftps"];

/// Record a curl handle's relevant options.
///
/// # Safety
/// `ex`/`rv` are the live frame and return value of the recording call.
unsafe fn record_curl(name: &str, ex: *mut zend_execute_data, rv: *mut zval) {
    match name {
        "curl_init" => {
            // curl_init([$url]): the new handle is the return value; the optional url is arg 1.
            let Some(id) = (unsafe { rv.cast::<Zval>().as_ref() }).and_then(handle_id) else { return };
            let mut map = curl();
            let state = map.entry(id).or_default();
            if let Some(url) = unsafe { arg_string(ex, 1) } {
                state.url = Some(url);
            }
        }
        "curl_setopt" => {
            // curl_setopt($handle, $option, $value)
            let Some(id) = (unsafe { crate::attribution::arg(ex, 1) }).and_then(handle_id) else { return };
            let Some(opt) = (unsafe { crate::attribution::arg(ex, 2) }).and_then(Zval::long) else { return };
            let value = unsafe { crate::attribution::arg(ex, 3) };
            let mut map = curl();
            apply_curl_opt(map.entry(id).or_default(), opt, value);
        }
        "curl_setopt_array" => {
            // curl_setopt_array($handle, $options)
            let Some(id) = (unsafe { crate::attribution::arg(ex, 1) }).and_then(handle_id) else { return };
            let Some(arr) = (unsafe { crate::attribution::arg(ex, 2) }).and_then(Zval::array) else { return };
            let mut map = curl();
            let state = map.entry(id).or_default();
            for (key, val) in arr.iter() {
                if let ArrayKey::Long(opt) = key {
                    apply_curl_opt(state, opt, Some(val));
                }
            }
        }
        "curl_reset" => {
            if let Some(id) = (unsafe { crate::attribution::arg(ex, 1) }).and_then(handle_id) {
                curl().remove(&id);
            }
        }
        "curl_close" => {
            if let Some(id) = (unsafe { crate::attribution::arg(ex, 1) }).and_then(handle_id) {
                curl().remove(&id);
            }
        }
        "curl_copy_handle" => {
            // The copy must carry the source's recorded options, or it would have none and fail
            // closed at exec. The new handle is the return value; the source is arg 1.
            let src = (unsafe { crate::attribution::arg(ex, 1) }).and_then(handle_id);
            let dst = (unsafe { rv.cast::<Zval>().as_ref() }).and_then(handle_id);
            if let (Some(src), Some(dst)) = (src, dst) {
                let mut map = curl();
                if let Some(state) = map.get(&src).cloned() {
                    map.insert(dst, state);
                }
            }
        }
        _ => {}
    }
}

fn apply_curl_opt(state: &mut CurlState, opt: i64, value: Option<&Zval>) {
    match opt {
        CURLOPT_URL => {
            if let Some(url) = value.and_then(Zval::str) {
                state.url = Some(url.to_owned());
            }
        }
        CURLOPT_PROXY => {
            state.proxy = value.and_then(Zval::str).filter(|s| !s.is_empty()).map(str::to_owned);
        }
        CURLOPT_RESOLVE => {
            for entry in string_list(value) {
                // "[+|-]host:port:addr[,addr]" — the addresses are where it actually connects.
                let entry = entry.trim_start_matches(['+', '-']);
                let fields: Vec<&str> = entry.splitn(3, ':').collect();
                if let Some(addrs) = fields.get(2) {
                    for addr in addrs.split(',').filter(|a| !a.is_empty()) {
                        state.overrides.push(addr.to_string());
                    }
                }
            }
        }
        CURLOPT_CONNECT_TO => {
            for entry in string_list(value) {
                // "host:port:connect-host:connect-port" — field 3 is the real connect host.
                let fields: Vec<&str> = entry.splitn(4, ':').collect();
                if let Some(connect_host) = fields.get(2).filter(|h| !h.is_empty()) {
                    state.overrides.push(connect_host.to_string());
                }
            }
        }
        CURLOPT_FOLLOWLOCATION => state.follow = value.map(truthy).unwrap_or(false),
        CURLOPT_MAXREDIRS => state.maxredirs = value.and_then(Zval::long),
        CURLOPT_RETURNTRANSFER => state.returntransfer = value.map(truthy).unwrap_or(false),
        CURLOPT_POST => state.post = value.map(truthy).unwrap_or(false),
        CURLOPT_POSTFIELDS => {
            if value.map(truthy).unwrap_or(false) {
                state.post = true;
            }
        }
        CURLOPT_POSTREDIR => state.postredir = value.and_then(Zval::long).unwrap_or(0),
        _ => {}
    }
}

/// A curl option value read as a boolean (libcurl takes an int; PHP passes bool/int).
fn truthy(v: &Zval) -> bool {
    v.long().map(|n| n != 0).unwrap_or_else(|| v.bool().unwrap_or(false))
}

/// The string values of a curl option that is a PHP array (CURLOPT_RESOLVE/CONNECT_TO), or empty.
fn string_list(value: Option<&Zval>) -> Vec<String> {
    value
        .and_then(Zval::array)
        .map(|a| a.values().filter_map(|v| v.string()).collect())
        .unwrap_or_default()
}

/// The attribution context for a curl call: who is responsible, the mode, and the host patterns
/// that apply. Built once in [`precheck_curl`] and reused for every redirect hop.
struct CurlCtx {
    component: Component,
    mode: Mode,
    patterns: Vec<String>,
}

impl CurlCtx {
    /// Audit `op`/`rule` on `host` (with `detail`) and say whether to block it (enforce only).
    fn refuse(&self, op: &str, rule: &str, host: &str, detail: &str) -> bool {
        audit(self.mode, &self.component.to_string(), op, host, detail, rule);
        if self.mode == Mode::Enforce {
            warn(&self.component.to_string(), host);
            true
        } else {
            false
        }
    }

    fn host_allowed(&self, host: &str) -> bool {
        hosts::host_allowed(&self.patterns, host).is_allowed()
    }
}

/// What a curl pre-check decided.
enum PreVerdict {
    /// The caller is not a restricted component (code outside the app root): leave it alone.
    NotOurs,
    /// Refuse the whole call (enforce + a disallowed scheme/host, or a handle we never saw built).
    Refuse,
    /// Allowed to proceed (or `log` mode): the recorded state and the context for following.
    Ok(Box<CurlState>, CurlCtx),
}

/// The pre-connect checks for a curl handle: fail closed when we never saw the handle built,
/// restrict the scheme to http/https/ftp/ftps, and check the URL host, the proxy host and every
/// RESOLVE/CONNECT_TO override host. Shared by `curl_exec` and `curl_multi_add_handle`.
fn precheck_curl(id: u32, from: *const zend_execute_data) -> PreVerdict {
    let Some(loaded) = crate::live_arc() else { return PreVerdict::NotOurs };
    let l2 = &loaded.config.layer2;
    if !hosts::checks_hosts(l2) {
        return PreVerdict::NotOurs;
    }
    let rule = attribution::settings().map_or(Rule::Component, |s| s.rule);
    let component = attribution::responsible(rule, &loaded.root, from);
    let Some(patterns) = hosts::hosts_for(l2, &component) else { return PreVerdict::NotOurs };
    let ctx = CurlCtx { component, mode: l2.mode, patterns: patterns.to_vec() };

    // Fail closed: a handle with no recorded URL is one we never saw being built.
    let state = curl().get(&id).cloned();
    let Some(state) = state.filter(|s| s.url.is_some()) else {
        return if ctx.refuse("curl_exec", "no-url", "", "") { PreVerdict::Refuse } else { PreVerdict::Ok(Box::default(), ctx) };
    };
    let url = state.url.clone().unwrap_or_default();

    // Scheme: a component may only speak http/https/ftp/ftps through curl (so no file://, gopher,
    // dict, telnet, smb …). REDIR_PROTOCOLS and PROTOCOLS are also clamped on the handle.
    let scheme = url_scheme(&url);
    if !ALLOWED_CURL_SCHEMES.contains(&scheme.as_str()) && ctx.refuse("curl_exec", "scheme", &scheme, &url) {
        return PreVerdict::Refuse;
    }

    // The URL host, the proxy host, and every RESOLVE/CONNECT_TO override host must be allowed.
    let mut targets: Vec<String> = Vec::new();
    if let Some(h) = host_from_url(&url) {
        targets.push(h);
    }
    if let Some(p) = &state.proxy
        && let Some(h) = host_from_url(p).or_else(|| host_from_authority(p))
    {
        targets.push(h);
    }
    for o in &state.overrides {
        if let Some(h) = host_from_authority(o) {
            targets.push(h);
        }
    }
    for h in &targets {
        if !ctx.host_allowed(h) && ctx.refuse("curl_exec", "host", h, &url) {
            return PreVerdict::Refuse;
        }
    }
    PreVerdict::Ok(Box::new(state), ctx)
}

/// `curl_exec($handle)`: pre-check, clamp the protocols, and either follow redirects in the
/// extension (when FOLLOWLOCATION is on and RETURNTRANSFER is set) or run the call once.
///
/// # Safety
/// `ex`/`rv` are the live frame and return value of `curl_exec`.
unsafe fn exec_curl(ex: *mut zend_execute_data, rv: *mut zval) {
    let from = unsafe { ex.as_ref() }.map_or(std::ptr::null(), |f| f.prev_execute_data);
    let Some(id) = (unsafe { crate::attribution::arg(ex, 1) }).and_then(handle_id) else {
        return unsafe { call_original("curl_exec", ex, rv) };
    };
    let (state, ctx) = match precheck_curl(id, from) {
        PreVerdict::NotOurs => return unsafe { call_original("curl_exec", ex, rv) },
        PreVerdict::Refuse => {
            if let Some(r) = unsafe { rv.cast::<Zval>().as_mut() } {
                r.set_bool(false);
            }
            return;
        }
        PreVerdict::Ok(state, ctx) => (state, ctx),
    };
    // Clamp the schemes on the handle (defence in depth, and it stops a redirect target scheme we
    // would not otherwise see): http/https/ftp/ftps for the request, http/https for any redirect.
    // Only in enforce — `log` mode blocks nothing, so it must not clamp.
    let handle = unsafe { crate::attribution::arg(ex, 1) }.map(Zval::shallow_clone);
    if ctx.mode == Mode::Enforce
        && let Some(handle) = &handle
    {
        curl_setopt_int(handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP_FTP);
        curl_setopt_int(handle, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP_HTTPS);
    }
    match (state.follow, state.returntransfer, handle) {
        // Follow in the extension, checking each hop (only clean when the body is captured).
        (true, true, Some(handle)) => unsafe { follow_curl(ex, rv, &handle, &state, &ctx) },
        // FOLLOWLOCATION on but the body is printed, not captured: we can't re-run hops cleanly, so
        // degrade — turn following off and run once (a redirect returns the 3xx, it is not
        // followed). Logged so we can see if anything relies on it.
        (true, false, Some(handle)) => {
            curl_setopt_int(&handle, CURLOPT_FOLLOWLOCATION, 0);
            audit(ctx.mode, &ctx.component.to_string(), "curl_follow", "", "returntransfer-off", "degraded");
            unsafe { call_original("curl_exec", ex, rv) };
        }
        _ => unsafe { call_original("curl_exec", ex, rv) },
    }
}

/// Follow redirects ourselves: FOLLOWLOCATION off, then on each 3xx read the resolved next URL
/// (`curl_getinfo`'s `redirect_url`, which libcurl resolves against the current URL), check its
/// host with the same rules — an audit line per hop — and re-exec, honouring `CURLOPT_MAXREDIRS`
/// and POSTREDIR. A refused hop fails the call (`false`); `log` mode records and follows.
///
/// # Safety
/// `ex`/`rv` are the live `curl_exec` frame and return value; `handle` is its curl handle.
unsafe fn follow_curl(ex: *mut zend_execute_data, rv: *mut zval, handle: &Zval, state: &CurlState, ctx: &CurlCtx) {
    curl_setopt_int(handle, CURLOPT_FOLLOWLOCATION, 0);
    let max = state.maxredirs.filter(|m| *m >= 0).unwrap_or(DEFAULT_MAXREDIRS);
    let mut left = max;
    // The first request (rv is the engine's own return slot — we never dtor it; libcurl writes it).
    unsafe { call_original("curl_exec", ex, rv) };
    while let Some((code, next)) = curl_getinfo(handle) {
        if next.is_empty() || left <= 0 {
            break;
        }
        let host = host_from_url(&next);
        let allowed = host.as_deref().is_some_and(|h| ctx.host_allowed(h));
        let shown = host.as_deref().unwrap_or("");
        if !allowed {
            // Refused (enforce) or logged-and-followed (log).
            if ctx.refuse("curl_redirect", if host.is_none() { "unparseable-host" } else { "host" }, shown, &next) {
                // Replace the 3xx body in rv with `false` (the assignment drops the old value).
                if let Some(r) = unsafe { rv.cast::<Zval>().as_mut() } {
                    *r = Zval::new();
                    r.set_bool(false);
                }
                curl_setopt_int(handle, CURLOPT_FOLLOWLOCATION, 1);
                return;
            }
        } else {
            audit(ctx.mode, &ctx.component.to_string(), "curl_redirect", shown, &next, "follow");
        }
        // POSTREDIR: like libcurl's default, a POST becomes a GET on 301/302/303 unless the matching
        // CURL_REDIR_POST_<code> bit is set; 307/308 keep the method.
        if state.post && matches!(code, 301..=303) && (state.postredir & redir_post_bit(code)) == 0 {
            curl_setopt_int(handle, CURLOPT_HTTPGET, 1);
        }
        curl_setopt_str(handle, CURLOPT_URL, &next);
        left -= 1;
        // Clear the previous hop's body (drop frees it) before the next request writes rv.
        if let Some(r) = unsafe { rv.cast::<Zval>().as_mut() } {
            *r = Zval::new();
        }
        unsafe { call_original("curl_exec", ex, rv) };
    }
    // Restore the user's FOLLOWLOCATION on the handle; rv holds the final body.
    curl_setopt_int(handle, CURLOPT_FOLLOWLOCATION, 1);
}

/// `curl_multi_add_handle($multi, $easy)`: pre-check the easy handle, clamp its protocols, and turn
/// FOLLOWLOCATION off (curl_multi follows internally with no hook — degrade, don't follow). A
/// refused handle is not added (a non-zero CURLM code).
///
/// # Safety
/// `ex`/`rv` are the live frame and return value of `curl_multi_add_handle`.
unsafe fn multi_add_curl(ex: *mut zend_execute_data, rv: *mut zval) {
    let from = unsafe { ex.as_ref() }.map_or(std::ptr::null(), |f| f.prev_execute_data);
    let Some(id) = (unsafe { crate::attribution::arg(ex, 2) }).and_then(handle_id) else {
        return unsafe { call_original("curl_multi_add_handle", ex, rv) };
    };
    match precheck_curl(id, from) {
        PreVerdict::NotOurs => unsafe { call_original("curl_multi_add_handle", ex, rv) },
        PreVerdict::Refuse => {
            if let Some(r) = unsafe { rv.cast::<Zval>().as_mut() } {
                r.set_long(1); // CURLM_BAD_HANDLE-ish: the easy handle is not added
            }
        }
        PreVerdict::Ok(state, ctx) => {
            // `log` blocks nothing, so clamp and degrade only in enforce.
            if ctx.mode == Mode::Enforce
                && let Some(handle) = unsafe { crate::attribution::arg(ex, 2) }.map(Zval::shallow_clone)
            {
                curl_setopt_int(&handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP_FTP);
                curl_setopt_int(&handle, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP_HTTPS);
                if state.follow {
                    curl_setopt_int(&handle, CURLOPT_FOLLOWLOCATION, 0);
                    audit(ctx.mode, &ctx.component.to_string(), "curl_follow", "", "curl_multi", "degraded");
                }
            }
            unsafe { call_original("curl_multi_add_handle", ex, rv) };
        }
    }
}

/// The scheme of a URL, lowercased; an empty scheme (a bare host curl defaults to http) reads as
/// `http`.
fn url_scheme(url: &str) -> String {
    match url.split_once("://") {
        Some((s, _)) if !s.is_empty() => s.to_ascii_lowercase(),
        _ => "http".to_owned(),
    }
}

/// `CURL_REDIR_POST_301/302/303` bits.
fn redir_post_bit(code: i64) -> i64 {
    match code {
        301 => 1,
        302 => 2,
        303 => 4,
        _ => 0,
    }
}

/// `curl_setopt($handle, $opt, <int>)` via a nested PHP call (so ext/curl sets it on the real
/// libcurl handle). Best-effort: a failure leaves the option unchanged.
fn curl_setopt_int(handle: &Zval, opt: i64, val: i64) {
    if let Ok(f) = ZendCallable::try_from_name("curl_setopt") {
        let _ = f.try_call(vec![handle, &opt, &val]);
    }
}

fn curl_setopt_str(handle: &Zval, opt: i64, val: &str) {
    if let Ok(f) = ZendCallable::try_from_name("curl_setopt") {
        let _ = f.try_call(vec![handle, &opt, &val]);
    }
}

/// `curl_getinfo($handle)` → (http_code, resolved redirect_url). `None` if the call fails.
fn curl_getinfo(handle: &Zval) -> Option<(i64, String)> {
    let f = ZendCallable::try_from_name("curl_getinfo").ok()?;
    let z = f.try_call(vec![handle]).ok()?;
    let arr = z.array()?;
    let code = arr.get("http_code").and_then(Zval::long).unwrap_or(0);
    let next = arr.get("redirect_url").and_then(Zval::str).unwrap_or("").to_owned();
    Some((code, next))
}

/// A curl handle's object id (its state key).
fn handle_id(zv: &Zval) -> Option<u32> {
    zv.object().map(|o| o.get_id())
}

// --- the decision -------------------------------------------------------------------------------

/// Check `host` for the component responsible at `from`; `true` when it must be refused (enforce
/// + disallowed). `detail` is the URL/arg for the audit line.
fn check_host(from: *const zend_execute_data, host: &str, op: &str, detail: &str) -> bool {
    let Some(loaded) = crate::live_arc() else { return false };
    let l2 = &loaded.config.layer2;
    if !hosts::checks_hosts(l2) {
        return false;
    }
    // A database connect is charged the way the vault charges it (attribution::db_connector): the
    // database layer (`wpdb` or a subclass) connecting is core even with a plugin further out on
    // the stack, so `wpdb::check_connection()` reconnecting on a plugin's call is core's connection
    // to its own DB host, not the plugin's (#53 review, finding 5). Everything else, by the
    // configured rule.
    // SAFETY: `from` is the running frame (the connect call, for a DB connect).
    let component = if unsafe { crate::vault::is_db_connect(from) } {
        attribution::db_connector(&loaded.root, from)
    } else {
        attribution::responsible(attribution::settings().map_or(Rule::Component, |s| s.rule), &loaded.root, from)
    };
    // Core's connection to the site's own database host is allowed implicitly (WordPress's
    // `DB_HOST`), so `core.hosts` need not list it and a vaulted password still connects; only
    // *core* gets this — a component reaching the DB host directly is still checked against its
    // own `hosts`. The DB goes through the transport factory (mysqlnd), not the wrappers.
    if matches!(component, Component::Core)
        && let Some(db) = db_host()
        && hosts::host_allowed(std::slice::from_ref(&db), host).is_allowed()
    {
        return false;
    }
    // `None` means outside the app root: not a restricted component, let through.
    let Some(patterns) = hosts::hosts_for(l2, &component) else { return false };
    // Layer 2's own decision, shared with the microVM's egress (securecore-fpm).
    match hosts::net_verdict(l2.mode, patterns, host) {
        hosts::NetVerdict::Allow => false,
        hosts::NetVerdict::Log(rule) => {
            audit(l2.mode, &component.to_string(), op, host, detail, rule);
            false
        }
        hosts::NetVerdict::Refuse(rule) => {
            audit(l2.mode, &component.to_string(), op, host, detail, rule);
            warn(&component.to_string(), host);
            true
        }
    }
}

fn audit(mode: Mode, component: &str, op: &str, host: &str, detail: &str, rule: &str) {
    // layer2 <mode> <component> net <op> <rule> <host> <detail>
    crate::log(crate::LOG_NOTICE, &format!("layer2 {} {component} net {op} {rule} {host} {detail}", mode.as_str()));
}

fn warn(component: &str, host: &str) {
    php_error(&ErrorType::Warning, &format!("securecore: {component} may not connect to {host} (host)"));
}

// --- host extraction ----------------------------------------------------------------------------

/// The host of a full URL (`scheme://[user:pass@]host[:port]/path`), after stripping scheme,
/// userinfo, port, path and brackets. `None` for a URL with no authority.
fn host_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    host_from_authority(after_scheme)
}

/// The bare host of an authority that may carry a `transport://` prefix, a `user:pass@` prefix, a
/// `:port` suffix, a `/path` tail, or `[...]` IPv6 brackets. Returns the host as
/// [`hosts::parse_target`] will read it (it does the IP/IDNA normalisation).
fn host_from_authority(authority: &str) -> Option<String> {
    let authority = authority.trim();
    // Drop a transport/scheme prefix ("tcp://", "ssl://", "http://").
    let authority = authority.split_once("://").map_or(authority, |(_, rest)| rest);
    // Drop the path/query/fragment.
    let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
    // Drop userinfo: only what follows the last '@' is the host.
    let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }
    // Strip the port, keeping IPv6 literals whole.
    let host = if let Some(rest) = authority.strip_prefix('[') {
        // [ipv6](:port)? — the host is inside the brackets.
        let end = rest.find(']')?;
        &authority[..end + 2] // keep the brackets so parse_target recognises the literal
    } else if authority.matches(':').count() >= 2 {
        authority // a bare IPv6 literal (no port can be attached without brackets)
    } else if let Some((h, _port)) = authority.rsplit_once(':') {
        h // host:port
    } else {
        authority
    };
    if host.is_empty() { None } else { Some(host.to_string()) }
}

// --- small helpers ------------------------------------------------------------------------------


fn current_execute_data() -> *const zend_execute_data {
    // SAFETY: EG(current_execute_data) on the request's own thread.
    unsafe { (*crate::executor_globals()).current_execute_data }
}

/// `*const c_char` as a `&str`, or `""` when it is null or not UTF-8 (used only to pick the
/// delegate wrapper by scheme).
fn cstr<'a>(p: *const c_char) -> &'a str {
    if p.is_null() {
        return "";
    }
    // SAFETY: a NUL-terminated string from the engine.
    unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("")
}

/// The first `len` bytes at `p` as a `&str` (for a string that is not NUL-terminated at the point
/// we care about — the transport factory's `proto`/`protolen`).
///
/// # Safety
/// `p` points to at least `len` readable bytes.
unsafe fn cstr_n<'a>(p: *const c_char, len: usize) -> &'a str {
    if p.is_null() {
        return "";
    }
    // SAFETY: the caller guarantees `len` readable bytes at `p`.
    std::str::from_utf8(unsafe { std::slice::from_raw_parts(p.cast::<u8>(), len) }).unwrap_or("")
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
