//! The host's PHP configuration as text (addiscorp/securecore#101): php.ini and its scan folder,
//! php-fpm's config and its pools, the dynamic loader's `--list` output and an ELF's
//! interpreter. No I/O: [`crate::capture`] reads the files and runs the programs, this module
//! says what they mean, so every rule here is unit-tested on any host.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// One `key = value` of an ini-style file, with its section and line (1-based).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    pub section: String,
    pub key: String,
    pub value: String,
    pub line: usize,
}

/// PHP's ini syntax, as php.ini and php-fpm's config use it: `[section]`, `key = value`, `;` and
/// `#` comments, values optionally in double or single quotes (a `;` outside quotes ends the
/// value). Lines that are none of these are ignored, as PHP warns and goes on.
pub fn parse_ini(text: &str) -> Vec<Setting> {
    let mut out = Vec::new();
    let mut section = String::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            if let Some(name) = rest.split(']').next() {
                section = name.trim().to_owned();
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        out.push(Setting { section: section.clone(), key: key.trim().to_owned(), value: unquote(value.trim()), line: n + 1 });
    }
    out
}

/// A value without its quotes, or up to an unquoted `;`.
fn unquote(v: &str) -> String {
    for q in ['"', '\''] {
        if let Some(rest) = v.strip_prefix(q)
            && let Some(end) = rest.find(q)
        {
            return rest[..end].to_owned();
        }
    }
    v.split(';').next().unwrap_or("").trim().to_owned()
}

/// php.ini keys that make PHP load native code: their value is a file or a name in the
/// extension folder.
pub const NATIVE_KEYS: [&str; 2] = ["extension", "zend_extension"];
/// php.ini keys that make PHP run a PHP file before or after every script, or at startup.
pub const SCRIPT_KEYS: [&str; 3] = ["auto_prepend_file", "auto_append_file", "opcache.preload"];

/// The file an `extension`/`zend_extension` value names: a path as it is (when it holds a
/// slash), else `<dir>/<value>` and `<dir>/<value>.so`, the two names PHP tries.
pub fn extension_candidates(value: &str, ext_dir: &str) -> Vec<String> {
    if value.contains('/') {
        return vec![value.to_owned()];
    }
    let dir = ext_dir.trim_end_matches('/');
    let mut c = vec![format!("{dir}/{value}")];
    if !value.ends_with(".so") {
        c.push(format!("{dir}/{value}.so"));
    }
    c
}

/// Why a setting that loads code is refused, or `None` when it is allowed: native code must be
/// one of `captured` (the extension folder's files and the captured libraries); a PHP file must
/// be in the app root (`root`, on the site disk) or unset. A value PHP would expand from the
/// environment (`${…}`) can't be judged here and is refused.
pub fn code_refusal(key: &str, value: &str, ext_dir: &str, root: &str, captured: &dyn Fn(&str) -> bool) -> Option<String> {
    let key = key.to_ascii_lowercase();
    if value.is_empty() {
        return None;
    }
    if value.contains("${") && (NATIVE_KEYS.contains(&key.as_str()) || SCRIPT_KEYS.contains(&key.as_str())) {
        return Some(format!("{key} = {value} takes its path from the environment, which the capture can't check"));
    }
    if NATIVE_KEYS.contains(&key.as_str()) {
        let c = extension_candidates(value, ext_dir);
        if c.iter().any(|p| captured(p)) {
            return None;
        }
        return Some(format!(
            "{key} = {value} loads native code from outside the captured set (the extension folder {ext_dir} and the libraries it needs)"
        ));
    }
    if SCRIPT_KEYS.contains(&key.as_str()) {
        let root = root.trim_end_matches('/');
        let inside = value.starts_with(&format!("{root}/")) && !value.split('/').any(|c| c == "..");
        if !inside {
            return Some(format!("{key} = {value} runs a PHP file outside the app root {root}, which the guest doesn't have"));
        }
    }
    None
}

/// The ini key inside `php_value[…]`, `php_admin_value[…]`, `php_flag[…]` or
/// `php_admin_flag[…]`.
pub fn php_value_key(key: &str) -> Option<&str> {
    for p in ["php_value[", "php_admin_value[", "php_flag[", "php_admin_flag["] {
        if let Some(rest) = key.strip_prefix(p) {
            return rest.strip_suffix(']');
        }
    }
    None
}

/// One php-fpm pool, merged from every file that has its section (the official images split
/// `[www]` over several), later settings winning.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Pool {
    pub name: String,
    /// Where the pool's section first appears.
    pub file: String,
    /// Every setting in order (a later one with the same key replaces the earlier).
    pub settings: Vec<(String, String)>,
}

impl Pool {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.settings.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    fn set(&mut self, key: &str, value: &str) {
        self.settings.retain(|(k, _)| k != key);
        self.settings.push((key.to_owned(), value.to_owned()));
    }

    /// `listen`, with php-fpm's `$pool` replaced.
    pub fn listen(&self) -> Option<String> {
        self.get("listen").map(|v| v.replace("$pool", &self.name))
    }

    /// The names of the master's environment the pool passes on (`env[X] = $NAME`).
    pub fn env_refs(&self) -> Vec<String> {
        self.settings
            .iter()
            .filter(|(k, _)| k.starts_with("env[") && k.ends_with(']'))
            .filter_map(|(_, v)| v.strip_prefix('$').map(str::to_owned))
            .collect()
    }
}

/// php-fpm's config, read file by file: `[global]`, pools, and `include` lines (resolved by the
/// caller, relative to php-fpm's prefix).
#[derive(Debug, Clone, Default)]
pub struct FpmConfig {
    pub global: Vec<(String, String)>,
    pub pools: Vec<Pool>,
}

impl FpmConfig {
    /// Adds one file's settings. Returns the `include` patterns it names, in order (the caller
    /// reads those files next, as php-fpm does where the include stands).
    pub fn add(&mut self, file: &str, text: &str) -> Vec<String> {
        let mut includes = Vec::new();
        for s in parse_ini(text) {
            if s.section.eq_ignore_ascii_case("global") || s.section.is_empty() {
                if s.key == "include" {
                    includes.push(s.value);
                } else {
                    self.global.retain(|(k, _)| *k != s.key);
                    self.global.push((s.key, s.value));
                }
                continue;
            }
            if s.key == "include" {
                includes.push(s.value);
                continue;
            }
            let pool = match self.pools.iter_mut().position(|p| p.name == s.section) {
                Some(i) => &mut self.pools[i],
                None => {
                    self.pools.push(Pool { name: s.section.clone(), file: file.to_owned(), settings: Vec::new() });
                    self.pools.last_mut().expect("just pushed")
                }
            };
            pool.set(&s.key, &s.value);
        }
        includes
    }
}

/// Pool settings the guest's pool carries over as the host's pool has them. The rest are about
/// the host's own paths and sockets (listen, logs, chroot, slowlog…) and are replaced or left
/// out ([`guest_fpm_conf`] says which).
pub fn carried(key: &str) -> bool {
    const KEYS: [&str; 13] = [
        "pm",
        "ping.response",
        "request_terminate_timeout",
        "request_terminate_timeout_track_finished",
        "rlimit_files",
        "rlimit_core",
        "clear_env",
        "security.limit_extensions",
        "process.priority",
        "process.dumpable",
        "pm.status_path",
        "catch_workers_output",
        "decorate_workers_output",
    ];
    KEYS.contains(&key)
        || (key.starts_with("pm.") && key != "pm.status_listen")
        || (key.starts_with("env[") && key.ends_with(']'))
        || php_value_key(key).is_some()
}

/// Keys the launcher sets itself in the guest's pool.
const OURS: [&str; 7] = ["user", "group", "listen", "ping.path", "access.log", "catch_workers_output", "decorate_workers_output"];

/// A value in double quotes, as php-fpm's ini parser reads it back unchanged.
fn quoted(v: &str) -> String {
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The guest's php-fpm config for one host pool: our `[global]`, then the pool with its user and
/// group as numbers, listening on the guest's loopback (the host listens where the pool says),
/// with `env[]`, `php_*_value`/`php_*_flag` and `pm.*` as the host has them. Also the host
/// settings left out, by key, for the log.
pub fn guest_fpm_conf(pool: &Pool, uid: u32, gid: u32, fpm_port: u32) -> (String, Vec<String>) {
    let mut s = String::new();
    // A reload (the launcher's SIGUSR2/SIGHUP) gives in-flight requests up to 20 s, as
    // securecore-init's RELOAD_GRACE.
    s.push_str("[global]\nerror_log = /proc/self/fd/2\nlog_limit = 8192\ndaemonize = no\nprocess_control_timeout = 20s\n\n");
    let _ = writeln!(s, "[{}]", pool.name);
    let _ = writeln!(s, "user = {uid}\ngroup = {gid}");
    let _ = writeln!(s, "listen = 127.0.0.1:{fpm_port}");
    s.push_str("ping.path = /fpm-ping\naccess.log = /dev/null\n");
    // A worker's stderr reaches the launcher's log: a program PHP runs that the guest lacks is
    // said there (the preload's line, #101).
    s.push_str("catch_workers_output = yes\ndecorate_workers_output = no\n");
    let mut dropped = Vec::new();
    for (k, v) in &pool.settings {
        if OURS.contains(&k.as_str()) {
            continue;
        }
        if carried(k) {
            let _ = writeln!(s, "{k} = {}", quoted(v));
        } else {
            dropped.push(k.clone());
        }
    }
    (s, dropped)
}

/// What the host's pool asks of its listening socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolListen {
    Unix(String),
    Tcp(String),
}

/// php-fpm's `listen` forms: a path, `port` (every address), `addr:port`, `[v6]:port`.
pub fn pool_listen(v: &str) -> Result<PoolListen, String> {
    if v.starts_with('/') {
        return Ok(PoolListen::Unix(v.to_owned()));
    }
    if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
        v.parse::<u16>().map_err(|_| format!("listen = {v}: not a port"))?;
        return Ok(PoolListen::Tcp(format!("0.0.0.0:{v}")));
    }
    let (_, port) = v.rsplit_once(':').ok_or_else(|| format!("listen = {v}: want a path, a port or address:port"))?;
    port.parse::<u16>().map_err(|_| format!("listen = {v}: {port} is not a port"))?;
    Ok(PoolListen::Tcp(v.to_owned()))
}

/// `listen.mode` (octal), php-fpm's default 0660.
pub fn listen_mode(v: Option<&str>) -> Result<u32, String> {
    match v {
        None => Ok(0o660),
        Some(m) => u32::from_str_radix(m.trim_start_matches("0o"), 8)
            .ok()
            .filter(|m| *m <= 0o777)
            .ok_or_else(|| format!("listen.mode = {m}: not an octal mode")),
    }
}

/// The dynamic loader's `--list` output (glibc's and musl's: `ldd`'s format): the absolute paths
/// of the libraries it found (the loader's own line included), or the first name it couldn't
/// find.
pub fn parse_ld_list(out: &str) -> Result<Vec<String>, String> {
    let mut paths = Vec::new();
    for line in out.lines().map(str::trim) {
        if line.is_empty() || line.contains("statically linked") || line.contains("not a dynamic executable") {
            continue;
        }
        let path = match line.split_once("=>") {
            Some((name, rest)) => {
                let rest = rest.trim();
                if rest.starts_with("not found") {
                    return Err(name.trim().to_owned());
                }
                rest.split(" (").next().unwrap_or("").trim()
            }
            None => line.split(" (").next().unwrap_or("").trim(),
        };
        // linux-vdso.so.1 (0x…) is the kernel's, never a file.
        if path.starts_with('/') && !paths.iter().any(|p| p == path) {
            paths.push(path.to_owned());
        }
    }
    Ok(paths)
}

/// An ELF file's interpreter (PT_INTERP), or `None` for a static binary or not an ELF.
pub fn elf_interp(b: &[u8]) -> Option<String> {
    if b.len() < 64 || &b[..4] != b"\x7fELF" || b[4] != 2 || b[5] != 1 {
        return None; // 64-bit little-endian only (x86_64, aarch64).
    }
    let u16_at = |o: usize| b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]));
    let u64_at = |o: usize| b.get(o..o + 8).map(|s| u64::from_le_bytes(s.try_into().expect("8 bytes")));
    let phoff = usize::try_from(u64_at(32)?).ok()?;
    let phentsize = usize::from(u16_at(54)?);
    let phnum = usize::from(u16_at(56)?);
    for i in 0..phnum {
        let ph = phoff.checked_add(i.checked_mul(phentsize)?)?;
        let kind = b.get(ph..ph + 4).map(|s| u32::from_le_bytes(s.try_into().expect("4 bytes")))?;
        if kind == 3 {
            let off = usize::try_from(u64_at(ph + 8)?).ok()?;
            let size = usize::try_from(u64_at(ph + 32)?).ok()?;
            let s = b.get(off..off.checked_add(size)?)?;
            let s = s.split(|c| *c == 0).next()?;
            return std::str::from_utf8(s).ok().map(str::to_owned);
        }
    }
    None
}

/// Whether `b` starts like an ELF file.
pub fn is_elf(b: &[u8]) -> bool {
    b.starts_with(b"\x7fELF")
}

/// `php -i`'s text: `name => value` (and `name => local => master` for ini settings: the
/// local value), by name.
pub fn parse_phpinfo(text: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for line in text.lines() {
        let mut parts = line.splitn(3, " => ");
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            m.entry(k.trim().to_owned()).or_insert_with(|| v.trim().to_owned());
        }
    }
    m
}

/// The MySQL default sockets PHP's own settings name (where `localhost` goes for mysqli, PDO
/// and mysqlnd), in order, without duplicates.
pub fn mysql_default_sockets(settings: &[Setting]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in settings {
        let k = s.key.to_ascii_lowercase();
        if matches!(k.as_str(), "mysqli.default_socket" | "pdo_mysql.default_socket" | "mysql.default_socket")
            && s.value.starts_with('/')
            && !out.contains(&s.value)
        {
            out.push(s.value.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ini_sections_quotes_and_comments() {
        let s = parse_ini("; c\n[PHP]\nextension = \"imagick.so\" ; x\nzend_extension=opcache\n# hash\nsendmail_path = /usr/sbin/sendmail -t -i ; tail\n[opcache]\nopcache.preload='/var/www/html/preload.php'\nnot a setting\n");
        let kv: Vec<(&str, &str, &str)> = s.iter().map(|s| (s.section.as_str(), s.key.as_str(), s.value.as_str())).collect();
        assert_eq!(
            kv,
            vec![
                ("PHP", "extension", "imagick.so"),
                ("PHP", "zend_extension", "opcache"),
                ("PHP", "sendmail_path", "/usr/sbin/sendmail -t -i"),
                ("opcache", "opcache.preload", "/var/www/html/preload.php"),
            ]
        );
        assert_eq!(s[1].line, 4);
    }

    #[test]
    fn extensions_resolve_into_the_extension_folder() {
        let dir = "/usr/local/lib/php/extensions/no-debug-non-zts-20230831";
        let have = |p: &str| p == format!("{dir}/opcache.so") || p == format!("{dir}/securecore.so");
        let cap: &dyn Fn(&str) -> bool = &have;
        assert_eq!(code_refusal("zend_extension", "opcache", dir, "/var/www/html", cap), None);
        assert_eq!(code_refusal("extension", "securecore.so", dir, "/var/www/html", cap), None);
        assert_eq!(code_refusal("extension", &format!("{dir}/opcache.so"), dir, "/var/www/html", cap), None);
        let r = code_refusal("extension", "/opt/evil/x.so", dir, "/var/www/html", cap).expect("refused");
        assert!(r.contains("outside the captured set"), "{r}");
        assert!(code_refusal("extension", "missing", dir, "/var/www/html", cap).is_some());
        assert!(code_refusal("extension", "${EXT}", dir, "/var/www/html", cap).unwrap().contains("environment"));
    }

    #[test]
    fn php_files_that_run_must_be_in_the_root() {
        let none: &dyn Fn(&str) -> bool = &|_| false;
        assert_eq!(code_refusal("auto_prepend_file", "/var/www/html/wordfence-waf.php", "/x", "/var/www/html", none), None);
        assert_eq!(code_refusal("auto_prepend_file", "", "/x", "/var/www/html", none), None);
        assert!(code_refusal("auto_prepend_file", "/etc/evil.php", "/x", "/var/www/html", none).is_some());
        assert!(code_refusal("opcache.preload", "/var/www/html/../../etc/p.php", "/x", "/var/www/html", none).is_some());
        assert!(code_refusal("AUTO_APPEND_FILE", "/srv/x.php", "/x", "/var/www/html/", none).is_some());
        assert_eq!(code_refusal("memory_limit", "/etc/whatever", "/x", "/var/www/html", none), None);
    }

    #[test]
    fn pools_merge_across_files_and_global_includes() {
        let mut c = FpmConfig::default();
        let inc = c.add("/usr/local/etc/php-fpm.conf", "[global]\npid = run/php-fpm.pid\ninclude=etc/php-fpm.d/*.conf\n");
        assert_eq!(inc, vec!["etc/php-fpm.d/*.conf"]);
        c.add("/usr/local/etc/php-fpm.d/www.conf", "[www]\nuser = www-data\ngroup = www-data\nlisten = 127.0.0.1:9000\npm = dynamic\npm.max_children = 5\nenv[DB] = $WORDPRESS_DB_PASSWORD\nphp_admin_value[memory_limit] = 256M\nslowlog = /var/log/slow.log\n");
        c.add("/usr/local/etc/php-fpm.d/zz-docker.conf", "[global]\ndaemonize = no\n[www]\nlisten = 9000\n[second]\nlisten = /run/php/$pool.sock\nuser = 1234\n");
        assert_eq!(c.pools.len(), 2);
        let www = &c.pools[0];
        assert_eq!(www.file, "/usr/local/etc/php-fpm.d/www.conf");
        assert_eq!(www.listen().as_deref(), Some("9000"));
        assert_eq!(www.env_refs(), vec!["WORDPRESS_DB_PASSWORD"]);
        assert_eq!(c.pools[1].listen().as_deref(), Some("/run/php/second.sock"));
        assert!(c.global.iter().any(|(k, v)| k == "daemonize" && v == "no"));
        let (conf, dropped) = guest_fpm_conf(www, 33, 33, 9000);
        assert!(conf.contains("[www]\nuser = 33\ngroup = 33\nlisten = 127.0.0.1:9000\n"), "{conf}");
        assert!(conf.contains("pm = \"dynamic\"\n") && conf.contains("pm.max_children = \"5\"\n"), "{conf}");
        assert!(conf.contains("env[DB] = \"$WORDPRESS_DB_PASSWORD\"\n"), "{conf}");
        assert!(conf.contains("php_admin_value[memory_limit] = \"256M\"\n"), "{conf}");
        assert!(!conf.contains("slowlog") && !conf.contains("www-data") && !conf.contains("listen = \"9000\""), "{conf}");
        assert_eq!(dropped, vec!["slowlog"]);
    }

    #[test]
    fn listen_forms() {
        assert_eq!(pool_listen("/run/php/php8.3-fpm.sock"), Ok(PoolListen::Unix("/run/php/php8.3-fpm.sock".into())));
        assert_eq!(pool_listen("9000"), Ok(PoolListen::Tcp("0.0.0.0:9000".into())));
        assert_eq!(pool_listen("127.0.0.1:9001"), Ok(PoolListen::Tcp("127.0.0.1:9001".into())));
        assert_eq!(pool_listen("[::1]:9002"), Ok(PoolListen::Tcp("[::1]:9002".into())));
        assert!(pool_listen("nope").is_err());
        assert_eq!(listen_mode(None), Ok(0o660));
        assert_eq!(listen_mode(Some("0666")), Ok(0o666));
        assert!(listen_mode(Some("9")).is_err());
    }

    #[test]
    fn loader_list_output() {
        let glibc = "\tlinux-vdso.so.1 (0x00007ffd)\n\tlibxml2.so.2 => /lib/x86_64-linux-gnu/libxml2.so.2 (0x00007f1)\n\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f2)\n\t/lib64/ld-linux-x86-64.so.2 (0x00007f3)\n";
        assert_eq!(
            parse_ld_list(glibc).unwrap(),
            vec!["/lib/x86_64-linux-gnu/libxml2.so.2", "/lib/x86_64-linux-gnu/libc.so.6", "/lib64/ld-linux-x86-64.so.2"]
        );
        let musl = "\t/lib/ld-musl-x86_64.so.1 (0x7f)\n\tlibc.musl-x86_64.so.1 => /lib/ld-musl-x86_64.so.1 (0x7f)\n";
        assert_eq!(parse_ld_list(musl).unwrap(), vec!["/lib/ld-musl-x86_64.so.1"]);
        assert_eq!(parse_ld_list("\tlibmissing.so.3 => not found\n"), Err("libmissing.so.3".into()));
        assert_eq!(parse_ld_list("\tstatically linked\n").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn elf_interpreter() {
        // A minimal ELF64 header with one PT_INTERP program header.
        let mut b = vec![0u8; 256];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        b[64..68].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP
        let interp = b"/lib64/ld-linux-x86-64.so.2\0";
        b[64 + 8..64 + 16].copy_from_slice(&200u64.to_le_bytes());
        b[64 + 32..64 + 40].copy_from_slice(&(interp.len() as u64).to_le_bytes());
        b[200..200 + interp.len()].copy_from_slice(interp);
        assert_eq!(elf_interp(&b).as_deref(), Some("/lib64/ld-linux-x86-64.so.2"));
        b[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD only: static
        assert_eq!(elf_interp(&b), None);
        assert_eq!(elf_interp(b"#!/bin/sh\n"), None);
    }

    #[test]
    fn phpinfo_and_default_sockets() {
        let m = parse_phpinfo("PHP Version => 8.3.14\nextension_dir => /usr/local/lib/php/extensions/no-debug-non-zts-20230831 => /usr/local/lib/php/extensions/no-debug-non-zts-20230831\nConfiguration File (php.ini) Path => /usr/local/etc/php\n");
        assert_eq!(m["PHP Version"], "8.3.14");
        assert_eq!(m["extension_dir"], "/usr/local/lib/php/extensions/no-debug-non-zts-20230831");
        assert_eq!(m["Configuration File (php.ini) Path"], "/usr/local/etc/php");
        let s = parse_ini("mysqli.default_socket = /run/mysqld/mysqld.sock\npdo_mysql.default_socket=/run/mysqld/mysqld.sock\nmysql.default_socket = \n");
        assert_eq!(mysql_default_sockets(&s), vec!["/run/mysqld/mysqld.sock"]);
    }
}
