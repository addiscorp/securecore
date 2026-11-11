//! Layer 3's database gateway (addiscorp/securecore#94): what crosses the request socket when an
//! isolated plugin's `$wpdb` runs a query. The child holds no connection and no credential; its
//! `$wpdb` sends the SQL text to the php-fpm worker, which runs it on its real connection, under
//! layer 2's policy, charged to the plugin the worker opened the channel for.
//!
//! - **Child → worker:** a [`QUERY`] frame, `Q\n` and the SQL text, in place of an answer, while
//!   the worker waits for the plugin's load or a call. The worker answers each one with one frame
//!   (PHP-serialized: the return value, the rows, `insert_id`, `rows_affected`, `last_error`) and
//!   goes back to waiting for the answer it asked for.
//! - **The worker decides what to admit** ([`admit`]), before PHP sees the text: the per-request
//!   query cap, the size of the text, UTF-8 (layer 2 reads the text as UTF-8), and no change to
//!   the statement time cap the worker sets for the call. Everything else is layer 2's.
//! - **The child never picks who it is:** the worker charges the query to the slug its channel
//!   was opened for. Nothing in a query frame names a plugin.

/// A child's database query frame: this tag, then the SQL text.
pub const QUERY: &[u8] = b"Q\n";

/// The longest SQL text the gateway takes (MySQL's and MariaDB's default `max_allowed_packet`).
pub const MAX_SQL: usize = 16 << 20;

/// A query frame for `sql`.
pub fn encode_query(sql: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(QUERY.len() + sql.len());
    out.extend_from_slice(QUERY);
    out.extend_from_slice(sql);
    out
}

/// The SQL text of a query frame; `None` for any other frame (an answer).
pub fn decode_query(frame: &[u8]) -> Option<&[u8]> {
    frame.strip_prefix(QUERY)
}

/// Why the worker refused a query before running it. Each fails the query in the child, as a
/// failed query does (`false`, with `last_error` set), and writes one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The request's `dbQueries` are used up.
    Queries(u32),
    /// The text is over [`MAX_SQL`].
    TooLong(usize),
    /// The text is not UTF-8, so layer 2 could not read it.
    NotUtf8,
    /// The text names `max_statement_time` / `max_execution_time`: the cap the worker sets on the
    /// connection for the call's time is not the plugin's to change.
    TimeCap,
}

impl Refusal {
    /// The reason, for the log line and the child's `last_error`.
    pub fn reason(&self) -> String {
        match self {
            Refusal::Queries(n) => format!("over the dbQueries cap of {n} per request"),
            Refusal::TooLong(n) => format!("the query is {n} bytes, over {MAX_SQL}"),
            Refusal::NotUtf8 => "the query is not UTF-8".to_owned(),
            Refusal::TimeCap => "it changes the statement time cap".to_owned(),
        }
    }

    /// Logged once per request and plugin, not per query: a loop past the cap would flood the log.
    pub fn once_per_request(&self) -> bool {
        matches!(self, Refusal::Queries(_))
    }
}

/// Whether the worker runs `sql`, the plugin's `sent`-th query of the request (counting from 0),
/// under a cap of `cap` queries. `Ok` is the text, for PHP.
pub fn admit(sql: &[u8], sent: u32, cap: u32) -> Result<&str, Refusal> {
    if sent >= cap {
        return Err(Refusal::Queries(cap));
    }
    if sql.len() > MAX_SQL {
        return Err(Refusal::TooLong(sql.len()));
    }
    let text = std::str::from_utf8(sql).map_err(|_| Refusal::NotUtf8)?;
    if touches_time_cap(text) {
        return Err(Refusal::TimeCap);
    }
    Ok(text)
}

fn touches_time_cap(sql: &str) -> bool {
    let lower = sql.to_ascii_lowercase();
    lower.contains("max_statement_time") || lower.contains("max_execution_time")
}

/// What a statement does to a transaction on the connection: `Some(true)` opens one,
/// `Some(false)` ends it, `None` neither. The worker rolls back a transaction a plugin left open
/// when its child dies, so core's later writes in the request don't join it.
pub fn transaction_effect(sql: &str) -> Option<bool> {
    let words: Vec<String> = sql
        .trim_start()
        .split(|c: char| c.is_whitespace() || c == ';')
        .filter(|w| !w.is_empty())
        .take(3)
        .map(str::to_ascii_uppercase)
        .collect();
    let w = |i: usize| words.get(i).map_or("", String::as_str);
    match (w(0), w(1)) {
        ("BEGIN", _) | ("START", "TRANSACTION") => Some(true),
        // ROLLBACK TO [SAVEPOINT] x keeps the transaction open.
        ("ROLLBACK", "TO") => None,
        ("COMMIT" | "ROLLBACK", _) => Some(false),
        ("SET", _) => {
            let compact: String = sql.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_uppercase();
            if compact.contains("AUTOCOMMIT=0") || compact.contains("AUTOCOMMIT=OFF") {
                Some(true)
            } else if compact.contains("AUTOCOMMIT=1") || compact.contains("AUTOCOMMIT=ON") {
                Some(false)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The worker's answer for a query it refused or could not run: what a failed `$wpdb` query
/// leaves (`false`, and `message` as `last_error`), PHP-serialized as the worker's PHP answers.
pub fn failed_answer(message: &str) -> Vec<u8> {
    format!(r#"a:2:{{s:3:"ret";b:0;s:5:"error";s:{}:"{message}";}}"#, message.len()).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_frames_round_trip_and_answers_are_not_queries() {
        let f = encode_query(b"SELECT 1");
        assert_eq!(decode_query(&f), Some(&b"SELECT 1"[..]));
        assert_eq!(decode_query(b"a:3:{}"), None, "a serialized answer is never a query");
        assert_eq!(decode_query(b"Q"), None);
        assert_eq!(decode_query(b"Q\n"), Some(&b""[..]));
    }

    #[test]
    fn admit_counts_sizes_and_reads_utf8() {
        assert_eq!(admit(b"SELECT 1", 0, 1), Ok("SELECT 1"));
        assert_eq!(admit(b"SELECT 1", 1, 1), Err(Refusal::Queries(1)));
        assert_eq!(admit(b"SELECT 1", 7, 3), Err(Refusal::Queries(3)));
        let long = vec![b'x'; MAX_SQL + 1];
        assert_eq!(admit(&long, 0, 10), Err(Refusal::TooLong(MAX_SQL + 1)));
        assert_eq!(admit(&long[..MAX_SQL], 0, 10).map(str::len), Ok(MAX_SQL));
        // Layer 2 reads text: a byte that is not UTF-8 (hidden in a comment) is refused here.
        assert_eq!(admit(b"SELECT LOAD_FILE('/etc/passwd') /* \xff */", 0, 10), Err(Refusal::NotUtf8));
        assert_eq!(admit("SELECT 'é'".as_bytes(), 0, 10), Ok("SELECT 'é'"));
    }

    #[test]
    fn the_time_cap_is_not_the_plugins() {
        for sql in [
            "SET SESSION max_statement_time = 0",
            "set max_execution_time=0",
            "SET STATEMENT MAX_STATEMENT_TIME=100 FOR SELECT SLEEP(100)",
            "SELECT @@max_statement_time",
        ] {
            assert_eq!(admit(sql.as_bytes(), 0, 10), Err(Refusal::TimeCap), "{sql}");
        }
        assert!(admit(b"SET SESSION sql_mode = 'TRADITIONAL'", 0, 10).is_ok());
    }

    #[test]
    fn transactions_are_tracked_by_their_control_statements() {
        assert_eq!(transaction_effect("START TRANSACTION"), Some(true));
        assert_eq!(transaction_effect("  begin;"), Some(true));
        assert_eq!(transaction_effect("start transaction read only"), Some(true));
        assert_eq!(transaction_effect("COMMIT"), Some(false));
        assert_eq!(transaction_effect("rollback"), Some(false));
        assert_eq!(transaction_effect("ROLLBACK TO SAVEPOINT a"), None);
        assert_eq!(transaction_effect("SET autocommit = 0"), Some(true));
        assert_eq!(transaction_effect("SET autocommit=1"), Some(false));
        assert_eq!(transaction_effect("SELECT 'BEGIN'"), None);
        assert_eq!(transaction_effect("INSERT INTO t VALUES (1)"), None);
    }

    #[test]
    fn a_failed_answer_is_valid_php_serialize() {
        let a = failed_answer("securecore: nope");
        assert_eq!(a, br#"a:2:{s:3:"ret";b:0;s:5:"error";s:16:"securecore: nope";}"#);
        // The byte length, not the character count, as PHP's serialize() writes it.
        assert!(String::from_utf8(failed_answer("é")).unwrap().contains(r#"s:2:"é""#));
    }
}
