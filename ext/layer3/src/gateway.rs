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
    /// A `SET` outside [`allowed_set`], or a COMMIT / ROLLBACK that chains a new transaction or
    /// releases the connection: session state persists into core's later queries on the worker's
    /// connection.
    SessionState,
}

impl Refusal {
    /// The reason, for the log line and the child's `last_error`.
    pub fn reason(&self) -> String {
        match self {
            Refusal::Queries(n) => format!("over the dbQueries cap of {n} per request"),
            Refusal::TooLong(n) => format!("the query is {n} bytes, over {MAX_SQL}"),
            Refusal::NotUtf8 => "the query is not UTF-8".to_owned(),
            Refusal::TimeCap => "it changes the statement time cap".to_owned(),
            Refusal::SessionState => "it changes the worker connection's session state".to_owned(),
        }
    }

    /// Logged once per request and plugin, not per query: a loop past the cap would flood the log.
    pub fn once_per_request(&self) -> bool {
        matches!(self, Refusal::Queries(_))
    }
}

/// Whether the worker runs `sql`, the plugin's `sent`-th query of the request (counting from 0),
/// under a cap of `cap` queries, on a connection whose charset is `charset`. `Ok` is the text,
/// for PHP.
pub fn admit<'a>(sql: &'a [u8], sent: u32, cap: u32, charset: &str) -> Result<&'a str, Refusal> {
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
    let words = normalized(text);
    match words.first().map(String::as_str) {
        Some("SET") if !allowed_set(&words, charset) => return Err(Refusal::SessionState),
        Some("COMMIT" | "ROLLBACK") if chains_or_releases(&words) => return Err(Refusal::SessionState),
        _ => {}
    }
    Ok(text)
}

/// The SQL's words outside comments, uppercased, with `=` and `,` as words of their own and
/// quoted strings kept whole (`'utf8mb4'`). Comments (`/* */`, `-- `, `#`) are dropped, so one
/// can't hide the statement's first word.
pub fn normalized(sql: &str) -> Vec<String> {
    let b = sql.as_bytes();
    let mut words = Vec::new();
    let mut cur = String::new();
    let flush = |cur: &mut String, words: &mut Vec<String>| {
        if !cur.is_empty() {
            words.push(std::mem::take(cur).to_ascii_uppercase());
        }
    };
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'/' && b.get(i + 1) == Some(&b'*') {
            flush(&mut cur, &mut words);
            i = sql[i + 2..].find("*/").map_or(b.len(), |e| i + 2 + e + 2);
        } else if (c == b'-' && b.get(i + 1) == Some(&b'-') && b.get(i + 2).is_none_or(|n| n.is_ascii_whitespace())) || c == b'#' {
            flush(&mut cur, &mut words);
            i = sql[i..].find('\n').map_or(b.len(), |e| i + e + 1);
        } else if c == b'\'' || c == b'"' || c == b'`' {
            let end = (i + 1..b.len()).find(|&j| b[j] == c && b[j - 1] != b'\\').map_or(b.len(), |j| j + 1);
            cur.push_str(&sql[i..end]);
            i = end;
        } else if c.is_ascii_whitespace() || c == b';' {
            flush(&mut cur, &mut words);
            i += 1;
        } else if c == b'=' || c == b',' {
            flush(&mut cur, &mut words);
            words.push((c as char).to_string());
            i += 1;
        } else {
            let ch = sql[i..].chars().next().unwrap_or(' ');
            cur.push(ch);
            i += ch.len_utf8();
        }
    }
    flush(&mut cur, &mut words);
    words
}

/// The session SETs an isolated plugin may run (each persists into core's later queries, so the
/// list holds only what WordPress plugins actually send and what can't change how core's SQL
/// reads or runs): `SET NAMES` / `SET CHARACTER SET` to the connection's own charset (with a
/// collation of it), `SET [SESSION] group_concat_max_len = <n>` and `SET [SESSION] sql_big_selects
/// = 1|ON`. Every other SET is refused: `SET [SESSION] <var>` (sql_mode, autocommit,
/// completion_type, sql_select_limit, transaction_read_only, time_zone, …), `SET @@…`, `SET
/// TRANSACTION`, `SET STATEMENT`, several assignments at once.
pub fn allowed_set(words: &[String], charset: &str) -> bool {
    let unq = |w: &str| w.trim_matches(['\'', '"', '`']).to_ascii_uppercase();
    let cs = charset.to_ascii_uppercase();
    let own = |w: &str| !cs.is_empty() && unq(w) == cs;
    let own_collation = |w: &str| unq(w).strip_prefix(&format!("{cs}_")).is_some_and(|r| !r.is_empty());
    let w: Vec<&str> = words.iter().map(String::as_str).collect();
    let digits = |s: &str| !s.is_empty() && s.len() <= 12 && s.bytes().all(|b| b.is_ascii_digit());
    match w.as_slice() {
        ["SET", "NAMES", c] | ["SET", "CHARACTER", "SET", c] => own(c),
        ["SET", "NAMES", c, "COLLATE", k] => own(c) && own_collation(k),
        ["SET", "SESSION", "GROUP_CONCAT_MAX_LEN", "=", n] | ["SET", "GROUP_CONCAT_MAX_LEN", "=", n] => digits(n),
        ["SET", "SESSION", "SQL_BIG_SELECTS", "=", v] | ["SET", "SQL_BIG_SELECTS", "=", v] => matches!(*v, "1" | "ON"),
        _ => false,
    }
}

/// Hooks whose value is SQL (or a clause of it, or rows standing in for a query's) that core then
/// runs or trusts, in the worker: never mirrored for an isolated plugin, or its callback would
/// rewrite core's queries (and the stand-in's own) from its child. It still runs on its own
/// queries in the child. `query`; `dbdelta_*`; `incompatible_sql_modes`; WP_Query's `posts_*`
/// and `post_limits*`; the query classes' `*_clauses`, `*_pre_query` and `found_*_query`;
/// `comment_feed_*`, `getarchives_*`, `get_terms_fields` / `_orderby`, `get_meta_sql`,
/// `get_date_sql`, `split_the_query`.
pub fn shapes_sql(hook: &str) -> bool {
    let h = hook.to_ascii_lowercase();
    let h = h.as_str();
    matches!(h, "query" | "incompatible_sql_modes" | "get_meta_sql" | "get_date_sql" | "split_the_query" | "get_terms_fields" | "get_terms_orderby")
        || ["dbdelta_", "posts_", "post_limits", "comment_feed_", "getarchives_"].iter().any(|p| h.starts_with(p))
        || h.ends_with("_clauses")
        || h.ends_with("_pre_query")
        || (h.starts_with("found_") && h.ends_with("_query"))
}

/// A COMMIT / ROLLBACK `AND CHAIN` (opens a new transaction) or `RELEASE` (drops the worker's
/// connection). `AND NO CHAIN`, `NO RELEASE` and `ROLLBACK TO SAVEPOINT` are fine.
fn chains_or_releases(words: &[String]) -> bool {
    words.iter().enumerate().any(|(i, w)| (w == "CHAIN" || w == "RELEASE") && (i == 0 || words[i - 1] != "NO"))
}

fn touches_time_cap(sql: &str) -> bool {
    let lower = sql.to_ascii_lowercase();
    lower.contains("max_statement_time") || lower.contains("max_execution_time")
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
        assert_eq!(admit(b"SELECT 1", 0, 1, U), Ok("SELECT 1"));
        assert_eq!(admit(b"SELECT 1", 1, 1, U), Err(Refusal::Queries(1)));
        assert_eq!(admit(b"SELECT 1", 7, 3, U), Err(Refusal::Queries(3)));
        let long = vec![b'x'; MAX_SQL + 1];
        assert_eq!(admit(&long, 0, 10, U), Err(Refusal::TooLong(MAX_SQL + 1)));
        assert_eq!(admit(&long[..MAX_SQL], 0, 10, U).map(str::len), Ok(MAX_SQL));
        // Layer 2 reads text: a byte that is not UTF-8 (hidden in a comment) is refused here.
        assert_eq!(admit(b"SELECT LOAD_FILE('/etc/passwd') /* \xff */", 0, 10, U), Err(Refusal::NotUtf8));
        assert_eq!(admit("SELECT 'é'".as_bytes(), 0, 10, U), Ok("SELECT 'é'"));
    }

    const U: &str = "utf8mb4";

    #[test]
    fn the_time_cap_is_not_the_plugins() {
        for sql in [
            "SET SESSION max_statement_time = 0",
            "set max_execution_time=0",
            "SET STATEMENT MAX_STATEMENT_TIME=100 FOR SELECT SLEEP(100)",
            "SELECT @@max_statement_time",
        ] {
            assert_eq!(admit(sql.as_bytes(), 0, 10, U), Err(Refusal::TimeCap), "{sql}");
        }
    }

    #[test]
    fn session_state_is_an_allowlist() {
        for sql in [
            "SET NAMES utf8mb4",
            "set names 'utf8mb4' collate 'utf8mb4_unicode_520_ci'",
            "SET CHARACTER SET utf8mb4",
            "SET SESSION group_concat_max_len = 100000",
            "SET group_concat_max_len=4096;",
            "SET SQL_BIG_SELECTS=1",
            "set session sql_big_selects = ON",
        ] {
            assert!(admit(sql.as_bytes(), 0, 10, U).is_ok(), "{sql}");
        }
        for sql in [
            "SET SESSION completion_type = 'CHAIN'",
            "SET completion_type=1",
            "SET SESSION sql_select_limit = 1",
            "SET SESSION transaction_read_only = 1",
            "SET SESSION sql_mode = 'TRADITIONAL'",
            "SET autocommit = 0",
            "SET autocommit = FALSE",
            "SET time_zone = '+05:00'",
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
            "SET SESSION TRANSACTION READ ONLY",
            "SET @@session.sql_select_limit = 1",
            "SET NAMES latin1",
            "SET NAMES utf8mb4 COLLATE latin1_swedish_ci",
            "SET NAMES utf8mb4, sql_select_limit = 1",
            "SET group_concat_max_len = 1, sql_select_limit = 1",
            "/* hidden */ SET sql_select_limit = 1",
            "-- note\nSET sql_select_limit = 1",
            "# note\nset sql_select_limit=1",
            "SET SQL_BIG_SELECTS = 0",
            "COMMIT AND CHAIN",
            "ROLLBACK AND CHAIN",
            "commit work release",
            "ROLLBACK /* x */ RELEASE",
        ] {
            assert_eq!(admit(sql.as_bytes(), 0, 10, U), Err(Refusal::SessionState), "{sql}");
        }
        for sql in ["COMMIT", "ROLLBACK AND NO CHAIN NO RELEASE", "ROLLBACK TO SAVEPOINT a", "RELEASE SAVEPOINT a", "SELECT 'SET x = 1'"] {
            assert!(admit(sql.as_bytes(), 0, 10, U).is_ok(), "{sql}");
        }
        // No charset known: no SET NAMES either.
        assert_eq!(admit(b"SET NAMES utf8mb4", 0, 10, ""), Err(Refusal::SessionState));
    }

    #[test]
    fn sql_shaping_hooks_are_never_mirrored() {
        for h in [
            "query",
            "dbdelta_queries",
            "dbdelta_create_queries",
            "posts_where",
            "posts_request",
            "posts_clauses",
            "post_limits_request",
            "comments_clauses",
            "terms_clauses",
            "users_pre_query",
            "posts_pre_query",
            "found_posts_query",
            "comment_feed_join",
            "getarchives_where",
            "get_meta_sql",
            "incompatible_sql_modes",
            "Query",
        ] {
            assert!(shapes_sql(h), "{h}");
        }
        for h in ["the_content", "init", "wp_head", "the_title", "query_vars", "pre_get_posts", "shortcode_atts_x", "admin_notices"] {
            assert!(!shapes_sql(h), "{h}");
        }
    }

    #[test]
    fn a_failed_answer_is_valid_php_serialize() {
        let a = failed_answer("securecore: nope");
        assert_eq!(a, br#"a:2:{s:3:"ret";b:0;s:5:"error";s:16:"securecore: nope";}"#);
        // The byte length, not the character count, as PHP's serialize() writes it.
        assert!(String::from_utf8(failed_answer("é")).unwrap().contains(r#"s:2:"é""#));
    }
}
