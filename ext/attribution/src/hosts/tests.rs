//! Unit tests for the hostname allowlist (E5). Plain Rust; no PHP.

use super::*;
use securecore_config::{Config, Layer2};

fn t(host: &str) -> Target {
    parse_target(host).unwrap_or_else(|| panic!("{host:?} did not parse"))
}

#[test]
fn ipv4_and_ipv6_literals_parse() {
    assert_eq!(t("127.0.0.1"), Target::Ip("127.0.0.1".parse().unwrap()));
    assert_eq!(t("[::1]"), Target::Ip("::1".parse().unwrap()));
    assert_eq!(t("::1"), Target::Ip("::1".parse().unwrap()));
    assert_eq!(t("169.254.169.254"), Target::Ip("169.254.169.254".parse().unwrap()));
}

#[test]
fn names_are_lowercased_and_trailing_dot_stripped() {
    assert_eq!(t("API.Stripe.COM"), Target::Name("api.stripe.com".into()));
    assert_eq!(t("api.wordpress.org."), Target::Name("api.wordpress.org".into()));
}

#[test]
fn userinfo_does_not_count_as_host() {
    // `allowed.example@evil.example` → the host is evil.example, not allowed.example.
    assert_eq!(t("allowed.example@evil.example"), Target::Name("evil.example".into()));
    assert_eq!(t("user:pass@evil.example"), Target::Name("evil.example".into()));
}

#[test]
fn idna_unicode_matches_its_punycode() {
    // A Unicode host normalises to the same ASCII its punycode pattern is written in.
    let uni = t("münchen.de");
    assert_eq!(uni, Target::Name("xn--mnchen-3ya.de".into()));
    assert!(host_allowed(&["xn--mnchen-3ya.de".into()], "münchen.de").is_allowed());
}

#[test]
fn empty_and_malformed_authorities_do_not_parse() {
    assert_eq!(parse_target(""), None);
    assert_eq!(parse_target("   "), None);
    assert_eq!(parse_target("@"), None);
    assert_eq!(parse_target("user@"), None);
}

#[test]
fn exact_name_matches_only_itself() {
    let pats = vec!["api.stripe.com".to_string()];
    assert!(host_allowed(&pats, "api.stripe.com").is_allowed());
    assert!(host_allowed(&pats, "API.STRIPE.COM").is_allowed());
    assert!(!host_allowed(&pats, "evil.stripe.com").is_allowed());
    assert!(!host_allowed(&pats, "api.stripe.com.evil.example").is_allowed());
}

#[test]
fn wildcard_matches_one_or_more_labels_not_the_base() {
    let pats = vec!["*.example.com".to_string()];
    assert!(host_allowed(&pats, "a.example.com").is_allowed());
    assert!(host_allowed(&pats, "a.b.example.com").is_allowed());
    // the base itself is not matched by the wildcard
    assert!(!host_allowed(&pats, "example.com").is_allowed());
    // label-safe: a different domain that merely ends in the same letters does not match
    assert!(!host_allowed(&pats, "a.evil-example.com").is_allowed());
    assert!(!host_allowed(&pats, "notexample.com").is_allowed());
}

#[test]
fn ip_literal_allowed_only_when_listed() {
    // no IP in the list → an IP literal target is refused even though names are allowed
    let names = vec!["api.stripe.com".to_string(), "*.example.com".to_string()];
    assert!(!host_allowed(&names, "6.6.6.6").is_allowed());
    assert!(!host_allowed(&names, "169.254.169.254").is_allowed());
    // an explicit IP literal is honoured, and only for that address
    let ips = vec!["203.0.113.5".to_string(), "::1".to_string()];
    assert!(host_allowed(&ips, "203.0.113.5").is_allowed());
    assert!(host_allowed(&ips, "[::1]").is_allowed());
    assert!(!host_allowed(&ips, "203.0.113.6").is_allowed());
    // a name is never allowed by an IP pattern, and an IP is never allowed by a name pattern
    assert!(!host_allowed(&ips, "example.com").is_allowed());
    assert!(!host_allowed(&["example.com".to_string()], "203.0.113.5").is_allowed());
}

#[test]
fn an_empty_list_denies_everything() {
    assert!(!host_allowed(&[], "api.stripe.com").is_allowed());
    assert!(!host_allowed(&[], "127.0.0.1").is_allowed());
}

#[test]
fn a_malformed_pattern_never_allows() {
    assert!(!host_allowed(&["*.".to_string()], "a.example.com").is_allowed());
    assert!(!host_allowed(&["*.1.2.3.4".to_string()], "a.1.2.3.4").is_allowed());
    assert!(!host_allowed(&["".to_string()], "example.com").is_allowed());
}

#[test]
fn unparseable_target_is_refused_not_allowed() {
    // even a list that would allow everything cannot allow a target that is not a host
    assert_eq!(host_allowed(&["*.example.com".to_string()], ""), HostDecision::Unparseable);
    assert!(!host_allowed(&["*.example.com".to_string()], "").is_allowed());
}

fn config(json: &str) -> Config {
    Config::from_slice(json.as_bytes()).expect("valid config")
}

const CFG: &str = r#"{
  "layer1": { "enabled": false },
  "layer2": {
    "enabled": true, "app": "wordpress", "mode": "enforce",
    "core": { "hosts": ["api.wordpress.org", "downloads.wordpress.org"] },
    "default": { "hosts": [] },
    "components": {
      "woocommerce": { "hosts": ["api.stripe.com", "*.paypal.com"] },
      "classic-editor": {}
    }
  },
  "layer3": { "enabled": false }
}"#;

#[test]
fn core_is_restricted_to_core_hosts() {
    let c = config(CFG);
    let hosts = hosts_for(&c.layer2, &Component::Core).expect("core restricted");
    assert!(host_allowed(hosts, "api.wordpress.org").is_allowed());
    assert!(!host_allowed(hosts, "api.stripe.com").is_allowed());
    assert!(!host_allowed(hosts, "evil.example").is_allowed());
}

#[test]
fn a_component_uses_its_own_hosts() {
    let c = config(CFG);
    let woo = hosts_for(&c.layer2, &Component::Plugin("woocommerce".into())).unwrap();
    assert!(host_allowed(woo, "api.stripe.com").is_allowed());
    assert!(host_allowed(woo, "a.paypal.com").is_allowed());
    assert!(!host_allowed(woo, "api.wordpress.org").is_allowed());
}

#[test]
fn a_component_without_hosts_falls_back_to_default() {
    let c = config(CFG);
    // classic-editor has an entry but no `hosts`, and default.hosts is empty → deny all
    let ce = hosts_for(&c.layer2, &Component::Plugin("classic-editor".into())).unwrap();
    assert!(ce.is_empty());
    assert!(!host_allowed(ce, "api.stripe.com").is_allowed());
    // a component with no entry at all also falls back to default
    let other = hosts_for(&c.layer2, &Component::Plugin("unknown".into())).unwrap();
    assert!(other.is_empty());
}

#[test]
fn outside_code_is_not_restricted() {
    let c = config(CFG);
    assert!(hosts_for(&c.layer2, &Component::Outside).is_none());
}

#[test]
fn default_hosts_is_inherited_when_a_component_has_none() {
    let c = config(
        r#"{
          "layer1": { "enabled": false },
          "layer2": {
            "enabled": true, "app": "wordpress", "mode": "enforce",
            "default": { "hosts": ["cdn.example"] },
            "components": { "acme": {} }
          },
          "layer3": { "enabled": false }
        }"#,
    );
    let acme = hosts_for(&c.layer2, &Component::Plugin("acme".into())).unwrap();
    assert!(host_allowed(acme, "cdn.example").is_allowed());
    assert!(!host_allowed(acme, "other.example").is_allowed());
}

// Keep the `Layer2`-typed assertions honest about the shape #53 fixed.
#[allow(dead_code)]
fn _shape(_l2: &Layer2) {}
