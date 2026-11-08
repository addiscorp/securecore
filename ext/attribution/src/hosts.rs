//! The layer-2 outbound hostname allowlist (addiscorp/securecore#53, phase E5): which hosts a
//! component (and core) may open a network connection to. Plain Rust with no PHP, so every rule
//! is unit-tested here; the extension (`securecore-php`) finds the host a connection actually
//! goes to and carries out the decision (block in `enforce`, log in `log`).
//!
//! The model (from #53's `layer2.core.hosts`, `layer2.default.hosts`,
//! `layer2.components.<slug>.hosts`):
//!
//! - Every outbound connection is attributed to the innermost responsible component (the E2a
//!   `component` rule), then checked against that component's `hosts` — its own entry's list, or
//!   `default.hosts` when it has none. A connection core makes is checked against `core.hosts`:
//!   core is restricted here (unlike the file policy), so a compromised site cannot phone home.
//!   Code outside the app root is not a component and is not checked.
//! - A pattern is an **exact name** (`api.stripe.com`), a **leading `*.` wildcard** matching one
//!   or more labels (`*.example.com` matches `a.example.com` and `a.b.example.com`, never
//!   `example.com`), or an **IP literal** (v4 or v6), which matches only that address.
//! - Matching is on the host the connection **actually goes to**, after IDNA/punycode
//!   normalisation, case-insensitively, with a trailing dot stripped and any `user:pass@` prefix
//!   and `[...]` brackets removed. A name never matches an IP pattern and an IP never matches a
//!   name pattern.

use std::net::IpAddr;

use securecore_config::Layer2;

use crate::Component;

/// What a connection's target resolves to for matching: a literal IP, or a DNS name already
/// normalised (lowercase, trailing dot stripped, IDNA → ASCII).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Ip(IpAddr),
    Name(String),
}

/// A host allowlist decision. `Refuse` carries the rule token for the audit line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostDecision {
    Allow,
    /// The host matched no pattern: refused with the `host` rule.
    Refuse,
    /// The target could not be parsed as a host at all (an empty or malformed authority): refused
    /// with the `unparseable-host` rule rather than allowed by default.
    Unparseable,
}

impl HostDecision {
    pub fn is_allowed(self) -> bool {
        self == HostDecision::Allow
    }

    pub fn rule(self) -> &'static str {
        match self {
            HostDecision::Allow => "",
            HostDecision::Refuse => "host",
            HostDecision::Unparseable => "unparseable-host",
        }
    }
}

/// The host string a connection goes to (what the brief calls the host it *actually* connects to:
/// no `user:pass@`, no brackets, trailing dot stripped, IDNA-normalised), as a [`Target`].
/// `None` for an empty or malformed authority.
pub fn parse_target(host: &str) -> Option<Target> {
    let host = strip_userinfo(host.trim());
    // An IPv6 literal may arrive bracketed (`[::1]`) or bare; a name never contains `:` here.
    let unbracketed = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    let bare = unbracketed.strip_suffix('.').unwrap_or(unbracketed);
    if bare.is_empty() {
        return None;
    }
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Some(Target::Ip(ip));
    }
    // A bare IPv6 without brackets still parses above; anything left with a colon is not a host we
    // can match by name (a stray port was not stripped by the caller), so refuse it as unparseable.
    if bare.contains(':') {
        return None;
    }
    let ascii = idna::domain_to_ascii(bare).ok()?;
    if ascii.is_empty() {
        return None;
    }
    Some(Target::Name(ascii))
}

/// Drops a `user:pass@` (or `user@`) prefix from an authority: only the part after the last `@`
/// is the host. A `user:pass@` prefix does not count toward the host (brief).
fn strip_userinfo(authority: &str) -> &str {
    match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    }
}

/// A single allowlist pattern, parsed once.
enum Pattern {
    /// An exact normalised name.
    Exact(String),
    /// A `*.base` wildcard: matches a name that is `base` with one or more extra leading labels.
    Wildcard(String),
    /// An IP literal: matches only that address.
    Ip(IpAddr),
    /// Unparseable pattern: never matches (a misconfigured entry denies rather than allows).
    Invalid,
}

fn parse_pattern(pattern: &str) -> Pattern {
    let pattern = pattern.trim();
    if let Some(base) = pattern.strip_prefix("*.") {
        return match parse_target(base) {
            Some(Target::Name(name)) => Pattern::Wildcard(name),
            _ => Pattern::Invalid, // `*.1.2.3.4` and `*.` are meaningless
        };
    }
    match parse_target(pattern) {
        Some(Target::Ip(ip)) => Pattern::Ip(ip),
        Some(Target::Name(name)) => Pattern::Exact(name),
        None => Pattern::Invalid,
    }
}

impl Pattern {
    fn matches(&self, target: &Target) -> bool {
        match (self, target) {
            (Pattern::Exact(name), Target::Name(host)) => name == host,
            (Pattern::Wildcard(base), Target::Name(host)) => {
                // one or more extra labels: `host` ends with `.base` (so a dot sits before `base`),
                // which is label-safe — `a.evil-example.com` does not end with `.example.com`.
                host.len() > base.len() + 1 && host.ends_with(base) && host.as_bytes()[host.len() - base.len() - 1] == b'.'
            }
            (Pattern::Ip(pattern), Target::Ip(ip)) => pattern == ip,
            // A name never matches an IP pattern, and an IP never matches a name pattern.
            _ => false,
        }
    }
}

/// Whether `patterns` allow a connection to `host` (the real connect host). The decision is on
/// the parsed [`Target`]; an authority that does not parse is refused, not allowed.
pub fn host_allowed(patterns: &[String], host: &str) -> HostDecision {
    let Some(target) = parse_target(host) else {
        return HostDecision::Unparseable;
    };
    if patterns.iter().any(|p| parse_pattern(p).matches(&target)) {
        HostDecision::Allow
    } else {
        HostDecision::Refuse
    }
}

/// The host patterns that apply to a connection `component` makes, or `None` when layer 2 does
/// not restrict this caller (code outside the app root). Core is restricted here, to `core.hosts`.
/// A component uses its own `hosts` entry, or `default.hosts` when it has none; a component with
/// neither (and an empty `default`) may reach nothing.
pub fn hosts_for<'a>(l2: &'a Layer2, component: &Component) -> Option<&'a [String]> {
    let slug = match component {
        Component::Core => return Some(&l2.core.hosts),
        Component::Outside => return None,
        Component::Plugin(s) | Component::MuPlugin(s) | Component::Theme(s) => s,
    };
    let own = l2.components.get(slug).and_then(|r| r.hosts.as_deref());
    Some(own.or(l2.default.hosts.as_deref()).unwrap_or(&[]))
}

#[cfg(test)]
mod tests;
