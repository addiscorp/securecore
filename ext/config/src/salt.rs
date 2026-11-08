//! The vault's salted pluggables, as pure functions (addiscorp/securecore#53, E3).
//!
//! WordPress derives its cookie, nonce and hash secrets from the key/salt constants
//! (`AUTH_KEY`, `AUTH_SALT`, …). SecureCore keeps those constants' real values in the extension
//! only; PHP sees placeholders. So `wp_salt()` and `wp_hash()` get native implementations that
//! read the real values from the vault and compute the same bytes WordPress would — without the
//! key ever becoming a PHP value. This module is the byte-for-byte logic, in plain Rust so the
//! same function runs in the extension and in the host tests.
//!
//! [`secret`] reproduces `wp_salt($scheme)` for the standard case: the four schemes with all
//! eight constants defined, unique and non-default (what every normal install has). [`hmac_hex`]
//! is `hash_hmac($algo, $data, $key)`. `wp_hash($data, $scheme, $algo)` is
//! `hmac_hex(algo, data, secret(scheme, …))`.
//!
//! What this does **not** reproduce: the `salt` filter (plugins altering the salt), the
//! duplicated-key / default-value fallbacks, and schemes outside the four with their own
//! `SECRET_KEY`/`SECRET_SALT`. A normal install uses none of these, and the live test proves the
//! bytes match stock WordPress for the standard constants.

use hmac::{Hmac, KeyInit, Mac};

/// A source of the real constant values: the constant name (`"AUTH_KEY"`) to its value, or
/// `None` when the vault doesn't hold it.
pub trait Secrets {
    fn get(&self, name: &str) -> Option<&str>;
}

impl Secrets for std::collections::HashMap<String, String> {
    fn get(&self, name: &str) -> Option<&str> {
        self.get(name).map(String::as_str)
    }
}

impl Secrets for std::collections::BTreeMap<String, String> {
    fn get(&self, name: &str) -> Option<&str> {
        self.get(name).map(String::as_str)
    }
}

/// The schemes WordPress keys from the four constant pairs.
fn pair(scheme: &str) -> Option<(&'static str, &'static str)> {
    match scheme {
        "auth" => Some(("AUTH_KEY", "AUTH_SALT")),
        "secure_auth" => Some(("SECURE_AUTH_KEY", "SECURE_AUTH_SALT")),
        "logged_in" => Some(("LOGGED_IN_KEY", "LOGGED_IN_SALT")),
        "nonce" => Some(("NONCE_KEY", "NONCE_SALT")),
        _ => None,
    }
}

/// `wp_salt($scheme)` for the standard case: `<SCHEME>_KEY . <SCHEME>_SALT` from the vault.
///
/// A scheme outside the four (WordPress's `secret_key`/derived path) keys from `SECRET_KEY` (an
/// empty string when it isn't a vault secret, as on a normal install) and salts with
/// `hash_hmac('md5', scheme, key)` — matching `wp_salt()` when `SECRET_KEY`/`SECRET_SALT` are
/// undefined. Returns `None` only when a standard scheme's constants aren't in the vault, which
/// the caller refuses at startup.
pub fn secret(scheme: &str, secrets: &dyn Secrets) -> Option<String> {
    if let Some((key, salt)) = pair(scheme) {
        let (k, s) = (secrets.get(key)?, secrets.get(salt)?);
        return Some(format!("{k}{s}"));
    }
    let key = secrets.get("SECRET_KEY").unwrap_or("");
    let salt = hmac_hex("md5", scheme.as_bytes(), key.as_bytes())?;
    Some(format!("{key}{salt}"))
}

/// `hash_hmac($algo, $data, $key)` in lowercase hex, or `None` for an unsupported algorithm.
/// Covers the algorithms WordPress uses for salts, nonces and cookies (md5 default, plus
/// sha1/sha256/sha384/sha512).
pub fn hmac_hex(algo: &str, data: &[u8], key: &[u8]) -> Option<String> {
    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }
    // One arm per supported digest; `Hmac<D>` needs only `D: EagerHash`, which each of these is.
    macro_rules! mac {
        ($d:ty) => {{
            let mut mac = <Hmac<$d> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
            Mac::update(&mut mac, data);
            hex(&mac.finalize().into_bytes())
        }};
    }
    Some(match algo {
        "md5" => mac!(md5::Md5),
        "sha1" => mac!(sha1::Sha1),
        "sha256" => mac!(sha2::Sha256),
        "sha384" => mac!(sha2::Sha384),
        "sha512" => mac!(sha2::Sha512),
        _ => return None,
    })
}

/// `wp_hash($data, $scheme, $algo)`: `hash_hmac($algo, $data, wp_salt($scheme))`. `None` when
/// the algorithm is unsupported or a standard scheme's constants aren't in the vault.
pub fn wp_hash(data: &[u8], scheme: &str, algo: &str, secrets: &dyn Secrets) -> Option<String> {
    let salt = secret(scheme, secrets)?;
    hmac_hex(algo, data, salt.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn vault() -> HashMap<String, String> {
        // Distinct, non-default values, as a real wp-config has.
        [
            ("AUTH_KEY", "auth-key-value-123"),
            ("AUTH_SALT", "auth-salt-value-456"),
            ("SECURE_AUTH_KEY", "sa-key"),
            ("SECURE_AUTH_SALT", "sa-salt"),
            ("LOGGED_IN_KEY", "li-key"),
            ("LOGGED_IN_SALT", "li-salt"),
            ("NONCE_KEY", "nonce-key"),
            ("NONCE_SALT", "nonce-salt"),
        ]
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
    }

    #[test]
    fn secret_is_key_then_salt() {
        let v = vault();
        assert_eq!(secret("auth", &v).as_deref(), Some("auth-key-value-123auth-salt-value-456"));
        assert_eq!(secret("nonce", &v).as_deref(), Some("nonce-keynonce-salt"));
    }

    #[test]
    fn missing_standard_constant_is_none() {
        let mut v = vault();
        v.remove("AUTH_SALT");
        assert_eq!(secret("auth", &v), None);
    }

    #[test]
    fn non_standard_scheme_derives_from_secret_key() {
        // No SECRET_KEY in the vault: key is "", salt is hash_hmac('md5', scheme, "").
        let v = vault();
        let salt = hmac_hex("md5", b"custom", b"").unwrap();
        assert_eq!(secret("custom", &v).as_deref(), Some(salt.as_str()));
    }

    #[test]
    fn hmac_matches_known_vectors() {
        // RFC 2104 / standard vectors (key "key", data "The quick brown fox jumps over the lazy dog").
        let data = b"The quick brown fox jumps over the lazy dog";
        assert_eq!(hmac_hex("md5", data, b"key").unwrap(), "80070713463e7749b90c2dc24911e275");
        assert_eq!(hmac_hex("sha1", data, b"key").unwrap(), "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
        assert_eq!(
            hmac_hex("sha256", data, b"key").unwrap(),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
        assert_eq!(hmac_hex("whirlpool", data, b"key"), None, "unsupported algorithm");
    }

    #[test]
    fn wp_hash_is_hmac_over_the_secret() {
        let v = vault();
        let got = wp_hash(b"payload", "auth", "md5", &v).unwrap();
        let want = hmac_hex("md5", b"payload", b"auth-key-value-123auth-salt-value-456").unwrap();
        assert_eq!(got, want);
    }
}
