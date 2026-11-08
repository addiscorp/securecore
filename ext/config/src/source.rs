//! Reading a vault's secret values from its source (addiscorp/securecore#53, E3): wp-config.php's
//! `define()` string literals, read natively, or a vault file (a JSON object of `NAME: value`).
//! Plain Rust so the extension and the host tests parse them the same way.

use std::collections::BTreeMap;
use std::path::Path;

use crate::Source;

/// Read every `NAME: value` a source defines. Errors name the file (the caller refuses MINIT, so
/// a bad or unreadable source fails closed).
pub fn read(source: &Source, root: &Path) -> Result<BTreeMap<String, String>, String> {
    let path = crate::resolve_against(root, source.path());
    let bytes = std::fs::read(&path).map_err(|e| format!("layer2.vault.from {}: {e}", path.display()))?;
    match source {
        Source::WpConfig(_) => {
            let text = String::from_utf8_lossy(&bytes);
            Ok(scan_defines(&text))
        }
        Source::VaultFile(_) => parse_vault_file(&bytes).map_err(|e| format!("layer2.vault.from {}: {e}", path.display())),
    }
}

/// A vault file: a JSON object whose every value is a string.
pub fn parse_vault_file(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| format!("not JSON: {e}"))?;
    let serde_json::Value::Object(map) = value else {
        return Err("not a JSON object of strings".into());
    };
    let mut out = BTreeMap::new();
    for (k, v) in map {
        match v {
            serde_json::Value::String(s) => {
                out.insert(k, s);
            }
            _ => return Err(format!("{k} is not a string")),
        }
    }
    Ok(out)
}

/// The `define('NAME', 'value')` / `define("NAME", "value")` string-literal constants in a
/// wp-config.php. Only plain string literals are read; a `define` whose value is an expression
/// (e.g. `getenv(...)`) yields no entry — such a secret comes from `env` instead, and a missing
/// value refuses MINIT.
pub fn scan_defines(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let bytes = text.as_bytes();
    let mut search = 0;
    while let Some(rel) = text[search..].find("define") {
        let after = search + rel + "define".len();
        search = after; // next iteration continues past this "define"
        let mut j = after;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if bytes.get(j) != Some(&b'(') {
            continue;
        }
        j += 1;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        let Some((name, mut k)) = read_php_string(text, j) else { continue };
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if bytes.get(k) != Some(&b',') {
            continue;
        }
        k += 1;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if let Some((value, _)) = read_php_string(text, k) {
            out.insert(name, value);
        }
    }
    out
}

/// Read a single- or double-quoted PHP string literal starting at `start` (the opening quote).
/// Unwinds `\\` and the quote's own escape; returns the value and the index past the closing
/// quote. `None` when `start` is not a quote or the string is unterminated.
fn read_php_string(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let quote = *bytes.get(start)?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let mut out = String::new();
    let mut i = start + 1;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\'
            && let Some(&n) = bytes.get(i + 1)
            && (n == b'\\' || n == quote)
        {
            out.push(n as char);
            i += 2;
            continue;
        }
        if b == quote {
            return Some((out, i + 1));
        }
        let len = utf8_len(b);
        out.push_str(text.get(i..i + len)?);
        i += len;
    }
    None
}

fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_single_and_double_quoted_defines() {
        let text = r#"<?php
            define('DB_NAME', 'wordpress');
            define( "DB_PASSWORD" , "p@ss'w0rd" );
            define('AUTH_KEY',   'a b c');
            // not a string: comes from env instead
            define('DB_HOST', getenv('WORDPRESS_DB_HOST'));
            $table_prefix = 'wp_';
        "#;
        let d = scan_defines(text);
        assert_eq!(d.get("DB_NAME").map(String::as_str), Some("wordpress"));
        assert_eq!(d.get("DB_PASSWORD").map(String::as_str), Some("p@ss'w0rd"));
        assert_eq!(d.get("AUTH_KEY").map(String::as_str), Some("a b c"));
        assert_eq!(d.get("DB_HOST"), None, "an expression value is not a literal");
    }

    #[test]
    fn unwinds_escapes() {
        let text = r#"define('K', 'a\\b\'c'); define("L", "x\"y");"#;
        let d = scan_defines(text);
        assert_eq!(d.get("K").map(String::as_str), Some(r"a\b'c"));
        assert_eq!(d.get("L").map(String::as_str), Some(r#"x"y"#));
    }

    #[test]
    fn vault_file_is_a_json_object_of_strings() {
        let ok = parse_vault_file(br#"{"DB_PASSWORD":"secret","AUTH_KEY":"k"}"#).expect("ok");
        assert_eq!(ok.get("DB_PASSWORD").map(String::as_str), Some("secret"));
        assert!(parse_vault_file(br#"{"DB_PASSWORD":123}"#).is_err(), "a non-string value is rejected");
        assert!(parse_vault_file(br#"["a","b"]"#).is_err(), "an array is rejected");
        assert!(parse_vault_file(b"not json").is_err());
    }
}
