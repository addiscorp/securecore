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
use ext_php_rs::types::{ArrayKey, ZendStr, Zval};
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
const RECORD: &[&str] = &["curl_init", "curl_setopt", "curl_setopt_array", "curl_reset", "curl_close"];

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
    crate::with_live(|l| {
        let l2 = &l.config.layer2;
        l2.enabled && l2.app.is_some() && l2.mode != Mode::Off
    })
    .unwrap_or(false)
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
    let ft = unsafe { (*std::ptr::addr_of_mut!(ext_php_rs::ffi::compiler_globals)).function_table };
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
    // Checking functions: a refused connection fails without calling the original.
    if unsafe { blocked_call(execute_data, name) } {
        if let Some(rv) = unsafe { return_value.cast::<Zval>().as_mut() } {
            if name == "curl_multi_add_handle" {
                rv.set_long(1); // a non-zero CURLM code: the easy handle is not added to the multi
            } else {
                rv.set_bool(false); // fsockopen/stream_socket_client/socket_connect/curl_exec fail
            }
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
        // curl_exec($handle): check the handle's recorded targets.
        "curl_exec" => unsafe { guard_curl(ex, from, 1, name) },
        // curl_multi_add_handle($multi, $easy): check the easy handle's targets before it runs.
        "curl_multi_add_handle" => unsafe { guard_curl(ex, from, 2, name) },
        _ => false,
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

/// What a curl handle has been told to connect to, recorded from its options. Checked at
/// `curl_exec` / `curl_multi_add_handle`, so an override (`CURLOPT_RESOLVE`, `CURLOPT_CONNECT_TO`)
/// that points an allowed name at a disallowed address is caught.
#[derive(Default)]
struct CurlState {
    url: Option<String>,
    proxy: Option<String>,
    /// CURLOPT_RESOLVE entries ("host:port:addr[,addr]") and CURLOPT_CONNECT_TO entries
    /// ("host:port:connect-host:connect-port"): the *effective* connect hosts they introduce.
    overrides: Vec<String>,
}

static CURL: LazyLock<Mutex<HashMap<u32, CurlState>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn curl() -> MutexGuard<'static, HashMap<u32, CurlState>> {
    CURL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// CURLOPT_* numeric constants (stable libcurl values).
const CURLOPT_URL: i64 = 10002;
const CURLOPT_PROXY: i64 = 10004;
const CURLOPT_RESOLVE: i64 = 10203;
const CURLOPT_CONNECT_TO: i64 = 10243;

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
        _ => {}
    }
}

/// The string values of a curl option that is a PHP array (CURLOPT_RESOLVE/CONNECT_TO), or empty.
fn string_list(value: Option<&Zval>) -> Vec<String> {
    value
        .and_then(Zval::array)
        .map(|a| a.values().filter_map(|v| v.string()).collect())
        .unwrap_or_default()
}

/// Guard a curl handle's recorded connect targets. Every one — the URL host, the proxy host, and
/// the host each RESOLVE/CONNECT_TO override points at — must be allowed; the first disallowed one
/// refuses (and is the audit line). An override naming a disallowed address is thus caught.
///
/// # Safety
/// `ex` is a live call frame; `arg` is the handle argument position.
unsafe fn guard_curl(ex: *mut zend_execute_data, from: *const zend_execute_data, arg: u32, token: &str) -> bool {
    let Some(id) = (unsafe { crate::attribution::arg(ex, arg) }).and_then(handle_id) else { return false };
    let map = curl();
    let Some(state) = map.get(&id) else { return false }; // no URL set yet: nothing to connect to
    let mut hosts: Vec<String> = Vec::new();
    if let Some(url) = &state.url
        && let Some(host) = host_from_url(url)
    {
        hosts.push(host);
    }
    if let Some(proxy) = &state.proxy
        && let Some(host) = host_from_url(proxy).or_else(|| host_from_authority(proxy))
    {
        hosts.push(host);
    }
    for o in &state.overrides {
        if let Some(host) = host_from_authority(o) {
            hosts.push(host);
        }
    }
    hosts.iter().any(|host| check_host(from, host, token, host))
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
    if !l2.enabled || l2.app.is_none() || l2.mode == Mode::Off {
        return false;
    }
    let rule = attribution::settings().map_or(Rule::Component, |s| s.rule);
    let component = attribution::responsible(rule, &loaded.root, from);
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
    let decision = hosts::host_allowed(patterns, host);
    if decision.is_allowed() {
        return false;
    }
    let rule_token = decision.rule();
    audit(l2.mode, &component.to_string(), op, host, detail, rule_token);
    if l2.mode == Mode::Enforce {
        warn(&component.to_string(), host);
        true
    } else {
        false
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
    unsafe { (*std::ptr::addr_of!(ext_php_rs::ffi::executor_globals)).current_execute_data }
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
