//! Database-host comparison for the vault (addiscorp/securecore#53, E3). The extension restores
//! the real DB password only on a connection whose host matches the configured DB host; these
//! pure functions normalise a host and pull the host out of a PDO DSN, so the extension and the
//! tests agree on what "the same host" means.

/// Normalise a DB host for comparison: drop a `p:` persistent prefix, keep an IPv6 address inside
/// `[...]`, strip a `:port` or trailing socket path, and lowercase. So `p:db:3306`, `[::1]:3306`,
/// `db` and `DB` compare as `db` / `::1`.
pub fn normalize_host(host: &str) -> String {
    let h = host.trim();
    let h = h.strip_prefix("p:").or_else(|| h.strip_prefix("P:")).unwrap_or(h);
    let bare = if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        h.split(':').next().unwrap_or(h)
    };
    bare.trim().to_ascii_lowercase()
}

/// The `host=` value of a PDO DSN (`mysql:host=db;dbname=wp`), or `None` when it has none (a
/// unix-socket DSN, which never carries the password to a remote host).
pub fn dsn_host(dsn: &str) -> Option<String> {
    let body = dsn.split_once(':').map_or(dsn, |(_, rest)| rest);
    body.split(';').find_map(|kv| {
        let (k, val) = kv.split_once('=')?;
        k.trim().eq_ignore_ascii_case("host").then(|| val.trim().to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_prefix_port_socket_and_case() {
        assert_eq!(normalize_host("db"), "db");
        assert_eq!(normalize_host("DB"), "db");
        assert_eq!(normalize_host("p:db"), "db");
        assert_eq!(normalize_host("P:db:3306"), "db");
        assert_eq!(normalize_host("db:3306"), "db");
        assert_eq!(normalize_host("localhost:/run/mysqld/mysqld.sock"), "localhost");
        assert_eq!(normalize_host(" db "), "db");
        assert_eq!(normalize_host("[::1]:3306"), "::1");
        assert_eq!(normalize_host("p:[2001:db8::1]:3306"), "2001:db8::1");
        // A different host does not normalise to the configured one.
        assert_ne!(normalize_host("attacker.example"), normalize_host("db"));
        assert_ne!(normalize_host("127.0.0.1"), normalize_host("db"));
    }

    #[test]
    fn pulls_host_from_a_pdo_dsn() {
        assert_eq!(dsn_host("mysql:host=db;dbname=wp;charset=utf8mb4").as_deref(), Some("db"));
        assert_eq!(dsn_host("mysql:dbname=wp;host=db").as_deref(), Some("db"));
        assert_eq!(dsn_host("mysql:host=127.0.0.1;port=33060").as_deref(), Some("127.0.0.1"));
        assert_eq!(dsn_host("mysql:host = db ; dbname=wp").as_deref(), Some("db"));
        // A unix-socket DSN carries no host.
        assert_eq!(dsn_host("mysql:unix_socket=/run/mysqld/mysqld.sock;dbname=wp"), None);
    }
}
