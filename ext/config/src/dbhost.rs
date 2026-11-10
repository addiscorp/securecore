//! Where a database connection goes, for the vault (addiscorp/securecore#53, E3). The extension
//! restores the real DB password only on a connection that goes exactly where WordPress's own
//! does: the same host **and** the same port or socket. Comparing the host alone let a component
//! connect `new wpdb(DB_USER, DB_PASSWORD, DB_NAME, 'db:3307')` to its own server on the DB host
//! and collect the password (#53 review, finding 3). These pure functions read a `DB_HOST` the way
//! WordPress does, a PDO DSN the way PDO does, and fill in what a connect leaves unset, so the
//! extension and the tests agree on what "the same place" means.

/// MySQL's default TCP port.
pub const MYSQL_PORT: u16 = 3306;

/// A connection's target as written: a host, and the port and socket when given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DbTarget {
    /// The host as given (`p:` prefix and `[...]` brackets allowed; empty = the default host).
    pub host: String,
    /// The TCP port, when given (`0` counts as not given, as it does for mysqli).
    pub port: Option<u16>,
    /// The unix socket path, when given.
    pub socket: Option<String>,
}

/// What a connect uses for anything its target leaves unset: mysqli's `mysqli.default_host`,
/// `mysqli.default_port` and `mysqli.default_socket`, or PDO's built-in `localhost` / 3306.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Defaults<'a> {
    pub host: &'a str,
    pub port: u16,
    pub socket: Option<&'a str>,
}

impl Defaults<'static> {
    /// MySQL's own defaults: `localhost`, port 3306, no socket named.
    pub const MYSQL: Defaults<'static> = Defaults { host: "localhost", port: MYSQL_PORT, socket: None };
}

/// Where a connection really goes, every part filled in: compare two of these with `==`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Lowercased, without `p:` or IPv6 brackets.
    pub host: String,
    pub port: u16,
    pub socket: Option<String>,
}

fn strip_persistent(h: &str) -> &str {
    h.strip_prefix("p:").or_else(|| h.strip_prefix("P:")).unwrap_or(h)
}

impl DbTarget {
    /// Fill in what the target leaves unset from `d`, and normalise the host.
    pub fn resolve(&self, d: &Defaults<'_>) -> Endpoint {
        let h = strip_persistent(self.host.trim());
        let h = h.strip_prefix('[').and_then(|r| r.strip_suffix(']')).unwrap_or(h);
        let host = match (h.is_empty(), d.host.trim()) {
            (false, _) => h,
            (true, "") => "localhost",
            (true, dh) => dh,
        }
        .to_ascii_lowercase();
        let port = match (self.port, d.port) {
            (Some(p), _) if p != 0 => p,
            (_, 0) => MYSQL_PORT,
            (_, dp) => dp,
        };
        let socket = self
            .socket
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(d.socket.filter(|s| !s.is_empty()))
            .map(str::to_owned);
        Endpoint { host, port, socket }
    }
}

/// A `DB_HOST` value (or `layer2.vault.dbHost`) read the way `wpdb::parse_db_host()` reads it:
/// `host`, `host:port`, `host:/socket`, `host:port:/socket`, `[ipv6]:port`, a bare IPv6 address.
/// A `p:` (persistent) prefix is dropped first. `None` when there is no host to read.
pub fn parse_db_host(value: &str) -> Option<DbTarget> {
    let mut rest = strip_persistent(value.trim());
    // The socket is everything after the first ":/".
    let mut socket = None;
    if let Some(i) = rest.find(":/") {
        socket = Some(rest[i + 1..].to_owned());
        rest = &rest[..i];
    }
    let (host, after) = if rest.matches(':').count() > 1 {
        // IPv6: `[addr]:port`, `[addr]` or a bare `addr` (no port can follow without brackets).
        let body = rest.strip_prefix('[').unwrap_or(rest);
        let end = body.find(|c: char| !(c.is_ascii_hexdigit() || c == ':')).unwrap_or(body.len());
        let after = body[end..].strip_prefix(']').unwrap_or("");
        (&body[..end], after)
    } else {
        let end = rest.find([':', '/']).unwrap_or(rest.len());
        (&rest[..end], &rest[end..])
    };
    // `:<digits>` after the host is the port; WordPress ignores anything else there.
    let digits: String = after.strip_prefix(':').unwrap_or("").chars().take_while(char::is_ascii_digit).collect();
    let port = if digits.is_empty() { None } else { Some(digits.parse::<u16>().ok()?) };
    if host.is_empty() && socket.is_none() {
        return None;
    }
    Some(DbTarget { host: host.to_owned(), port, socket })
}

/// A PDO MySQL DSN (`mysql:host=db;port=3306;dbname=wp`, or `unix_socket=…`) read the way
/// pdo_mysql reads it. `None` — never a guess — when it is not a `mysql:` DSN (PDO's `uri:` form
/// reads the real DSN from elsewhere, and a bare name is an ini alias), when a key the target
/// depends on appears more than once, or when the port is not a port.
pub fn parse_dsn(dsn: &str) -> Option<DbTarget> {
    let body = dsn.strip_prefix("mysql:")?;
    let mut host = None;
    let mut port = None;
    let mut socket = None;
    for kv in body.split(';') {
        let Some((k, v)) = kv.split_once('=') else { continue };
        let slot = match k.trim().to_ascii_lowercase().as_str() {
            "host" => &mut host,
            "port" => &mut port,
            "unix_socket" => &mut socket,
            _ => continue,
        };
        if slot.replace(v.trim().to_owned()).is_some() {
            return None;
        }
    }
    let port = match port {
        None => None,
        Some(p) => Some(p.parse::<u16>().ok()?),
    };
    Some(DbTarget { host: host.unwrap_or_default(), port, socket })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(host: &str, port: Option<u16>, socket: Option<&str>) -> DbTarget {
        DbTarget { host: host.into(), port, socket: socket.map(Into::into) }
    }

    fn e(host: &str, port: u16, socket: Option<&str>) -> Endpoint {
        Endpoint { host: host.into(), port, socket: socket.map(Into::into) }
    }

    #[test]
    fn reads_db_host_like_wordpress() {
        assert_eq!(parse_db_host("db"), Some(t("db", None, None)));
        assert_eq!(parse_db_host(" DB "), Some(t("DB", None, None)));
        assert_eq!(parse_db_host("db:3307"), Some(t("db", Some(3307), None)));
        assert_eq!(parse_db_host("p:db:3306"), Some(t("db", Some(3306), None)));
        assert_eq!(parse_db_host("localhost:/run/mysqld/mysqld.sock"), Some(t("localhost", None, Some("/run/mysqld/mysqld.sock"))));
        assert_eq!(parse_db_host("localhost:3307:/run/m.sock"), Some(t("localhost", Some(3307), Some("/run/m.sock"))));
        assert_eq!(parse_db_host("[::1]:3306"), Some(t("::1", Some(3306), None)));
        assert_eq!(parse_db_host("2001:db8::1"), Some(t("2001:db8::1", None, None)));
        assert_eq!(parse_db_host("p:[2001:db8::1]:3310"), Some(t("2001:db8::1", Some(3310), None)));
        // WordPress ignores a non-numeric port.
        assert_eq!(parse_db_host("db:abc"), Some(t("db", None, None)));
        assert_eq!(parse_db_host("db:99999"), None);
        assert_eq!(parse_db_host(""), None);
    }

    #[test]
    fn reads_a_pdo_dsn() {
        assert_eq!(parse_dsn("mysql:host=db;dbname=wp;charset=utf8mb4"), Some(t("db", None, None)));
        assert_eq!(parse_dsn("mysql:dbname=wp;host=db;port=3307"), Some(t("db", Some(3307), None)));
        assert_eq!(parse_dsn("mysql:host = db ; dbname=wp"), Some(t("db", None, None)));
        assert_eq!(parse_dsn("mysql:unix_socket=/run/mysqld/mysqld.sock;dbname=wp"), Some(t("", None, Some("/run/mysqld/mysqld.sock"))));
        // Not a mysql DSN, or ambiguous: no target, so no swap.
        assert_eq!(parse_dsn("uri:file:///etc/dsn"), None);
        assert_eq!(parse_dsn("mydb"), None);
        assert_eq!(parse_dsn("mysql:host=db;host=evil.example"), None);
        assert_eq!(parse_dsn("mysql:host=db;port=33o6"), None);
    }

    #[test]
    fn resolves_what_a_connect_leaves_unset() {
        let d = Defaults::MYSQL;
        assert_eq!(t("db", None, None).resolve(&d), e("db", 3306, None));
        assert_eq!(t("DB", Some(0), Some("")).resolve(&d), e("db", 3306, None));
        assert_eq!(t("p:[::1]", Some(3306), None).resolve(&d), e("::1", 3306, None));
        assert_eq!(t("", None, None).resolve(&d), e("localhost", 3306, None));
        // mysqli's ini defaults fill the gaps.
        let ini = Defaults { host: "db", port: 3310, socket: Some("/run/m.sock") };
        assert_eq!(t("", None, None).resolve(&ini), e("db", 3310, Some("/run/m.sock")));
        assert_eq!(t("db", Some(3306), Some("/x.sock")).resolve(&ini), e("db", 3306, Some("/x.sock")));
    }

    #[test]
    fn the_same_host_on_another_port_or_socket_is_another_place() {
        let d = Defaults::MYSQL;
        let wp = parse_db_host("db").unwrap().resolve(&d);
        // wpdb's own connect: host and port as WordPress passes them (no port given, or 3306).
        assert_eq!(t("db", None, None).resolve(&d), wp);
        assert_eq!(t("db", Some(3306), None).resolve(&d), wp);
        // The finding: the right host on another port, or with a socket of its own.
        let attack = parse_db_host("db:3307").unwrap();
        assert_ne!(t(&attack.host, attack.port, None).resolve(&d), wp);
        assert_ne!(t("db", None, Some("/tmp/evil.sock")).resolve(&d), wp);
        // A host:port smuggled into mysqli's host argument is not the bare host.
        assert_ne!(t("db:3306", None, None).resolve(&d), wp);
        assert_ne!(t("attacker.example", None, None).resolve(&d), wp);
        // A socket DB_HOST: only that socket matches.
        let sock = parse_db_host("localhost:/run/mysqld/mysqld.sock").unwrap().resolve(&d);
        assert_eq!(t("localhost", None, Some("/run/mysqld/mysqld.sock")).resolve(&d), sock);
        assert_ne!(t("localhost", None, None).resolve(&d), sock);
        assert_ne!(t("localhost", None, Some("/tmp/evil.sock")).resolve(&d), sock);
        // A PDO DSN to the right host on another port.
        assert_ne!(parse_dsn("mysql:host=db;port=3307").unwrap().resolve(&d), wp);
        assert_eq!(parse_dsn("mysql:host=db;dbname=wp").unwrap().resolve(&d), wp);
    }
}
