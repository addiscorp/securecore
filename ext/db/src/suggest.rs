//! Turns the extension's database audit lines into suggested component entries (the
//! `securecore-db-suggest` binary). A line, after the `securecore: ` prefix, is
//!
//!   layer2 <mode> <component> <route> <rule> <statement> <tables>[ options=<a,b*>]
//!
//! Only plugin, mu-plugin and theme lines count; core's are never suggestions.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub slug: String,
    pub rule: String,
    pub statement: String,
    pub tables: Vec<String>,
    pub options: Vec<String>,
}

/// One audit line, or `None` for any other line (file-policy lines included: their 4th field is
/// an op such as `open`, not a database route).
pub fn parse_line(raw: &str) -> Option<Line> {
    let s = raw.split("securecore: ").nth(1).unwrap_or(raw).trim();
    let mut f = s.split_whitespace();
    if f.next()? != "layer2" {
        return None;
    }
    let _mode = f.next()?;
    let component = f.next()?;
    let route = f.next()?;
    if !(route.starts_with("mysqli") || route.starts_with("pdo::")) {
        return None;
    }
    let slug = ["plugin:", "mu-plugin:", "theme:"].iter().find_map(|p| component.strip_prefix(p))?.to_owned();
    let rule = f.next()?.to_owned();
    let statement = f.next()?.to_owned();
    let tables = f.next().filter(|t| *t != "-").map(|t| t.split(',').map(str::to_owned).collect()).unwrap_or_default();
    let options = f.find_map(|x| x.strip_prefix("options=")).map(|o| o.split(',').map(str::to_owned).collect()).unwrap_or_default();
    Some(Line { slug, rule, statement, tables, options })
}

#[derive(Default)]
struct Entry {
    tables: BTreeSet<String>,
    options: BTreeSet<String>,
    grants: BTreeSet<String>,
    refused_always: BTreeSet<String>,
}

pub struct Suggestions {
    prefix: String,
    entries: BTreeMap<String, Entry>,
}

const CORE: &[(&str, &str)] = &[
    ("users", "users"),
    ("usermeta", "users"),
    ("posts", "posts"),
    ("postmeta", "posts"),
    ("comments", "comments"),
    ("commentmeta", "comments"),
    ("terms", "terms"),
    ("termmeta", "terms"),
    ("term_taxonomy", "terms"),
    ("term_relationships", "terms"),
    ("links", "links"),
    ("options", "options"),
];

impl Suggestions {
    pub fn new(prefix: &str) -> Suggestions {
        Suggestions { prefix: prefix.to_ascii_lowercase(), entries: BTreeMap::new() }
    }

    pub fn add(&mut self, l: &Line) {
        let e = self.entries.entry(l.slug.clone()).or_default();
        let write = matches!(l.statement.as_str(), "insert" | "replace" | "update" | "delete");
        let access = if write { "write" } else { "read" };
        match l.rule.as_str() {
            "table" => {
                for t in &l.tables {
                    let name = t.strip_prefix(self.prefix.as_str()).unwrap_or(t);
                    e.tables.insert(name.to_owned());
                }
            }
            "core-table" => {
                for t in &l.tables {
                    let name = t.strip_prefix(self.prefix.as_str()).unwrap_or(t);
                    if let Some((_, area)) = CORE.iter().find(|(n, _)| *n == name) {
                        e.grants.insert(format!("{area}:{access}"));
                    }
                }
            }
            "capabilities" => {
                e.grants.insert("capabilities:write".into());
            }
            "option" => e.options.extend(l.options.iter().cloned()),
            "options-unpinned" => {
                e.grants.insert(format!("options:{access}"));
            }
            other => {
                let what = if l.options.is_empty() { l.tables.join(",") } else { l.options.join(",") };
                e.refused_always.insert(format!("{other} {} {what}", l.statement).trim().to_owned());
            }
        }
        // A write grant covers the read.
        for area in ["users", "posts", "comments", "terms", "links", "options"] {
            if e.grants.contains(&format!("{area}:write")) {
                e.grants.remove(&format!("{area}:read"));
            }
        }
    }

    /// The suggested `components` object, plus each component's `refusedAlways` for the reviewer.
    pub fn to_json(&self) -> String {
        let mut components = Map::new();
        for (slug, e) in &self.entries {
            let mut o = Map::new();
            if !e.tables.is_empty() {
                o.insert("tables".into(), json!(e.tables));
            }
            if !e.options.is_empty() {
                o.insert("options".into(), json!(collapse(&e.options)));
            }
            if !e.grants.is_empty() {
                o.insert("grants".into(), json!(e.grants));
            }
            components.insert(slug.clone(), Value::Object(o));
        }
        let refused: Map<String, Value> = self
            .entries
            .iter()
            .filter(|(_, e)| !e.refused_always.is_empty())
            .map(|(s, e)| (s.clone(), json!(e.refused_always)))
            .collect();
        serde_json::to_string_pretty(&json!({ "components": components, "refusedAlways": refused })).unwrap_or_default()
    }
}

/// Option names as a reviewer would write them: transient prefixes dropped (the policy matches
/// a transient by its own name), and two or more names sharing a first segment (`wpseo_…`) as
/// one glob (`wpseo_*`).
fn collapse(names: &BTreeSet<String>) -> Vec<String> {
    const TRANSIENT: &[&str] = &["_site_transient_timeout_", "_site_transient_", "_transient_timeout_", "_transient_"];
    let bare: BTreeSet<String> =
        names.iter().map(|n| TRANSIENT.iter().find_map(|p| n.strip_prefix(p)).unwrap_or(n).to_owned()).collect();
    let mut stems: BTreeMap<String, usize> = BTreeMap::new();
    for n in &bare {
        if let Some((stem, _)) = n.split_once('_') {
            *stems.entry(format!("{stem}_")).or_default() += 1;
        }
    }
    let mut out = BTreeSet::new();
    for n in &bare {
        match n.split_once('_') {
            Some((stem, _)) if stems.get(&format!("{stem}_")).is_some_and(|c| *c >= 2) => out.insert(format!("{stem}_*")),
            _ => out.insert(n.clone()),
        };
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggests_from_log_lines() {
        let log = "\
[08-Nov-2026] securecore: layer2 log plugin:wordpress-seo mysqli_query table select wp_yoast_indexable
securecore: layer2 log plugin:wordpress-seo mysqli_query core-table select wp_posts
securecore: layer2 log plugin:wordpress-seo mysqli_query core-table update wp_postmeta
securecore: layer2 log plugin:wordpress-seo mysqli_query option select wp_options options=wpseo_titles
securecore: layer2 log plugin:wordpress-seo mysqli_query protected-option update wp_options options=cron
securecore: layer2 log core mysqli_query unparseable select -
securecore: layer2 log plugin:x open write /var/www/html/x";
        let mut s = Suggestions::new("wp_");
        for l in log.lines().filter_map(parse_line) {
            s.add(&l);
        }
        let v: Value = serde_json::from_str(&s.to_json()).unwrap_or_default();
        let y = &v["components"]["wordpress-seo"];
        assert_eq!(y["tables"], json!(["yoast_indexable"]));
        assert_eq!(y["options"], json!(["wpseo_titles"]));
        assert_eq!(y["grants"], json!(["posts:write"]));
        assert_eq!(v["refusedAlways"]["wordpress-seo"], json!(["protected-option update cron"]));
        assert!(v["components"].get("x").is_none(), "file-policy lines are not database lines");
    }

    #[test]
    fn collapses_options_into_globs() {
        let names: BTreeSet<String> = [
            "_transient_wpseo_total_unindexed_posts",
            "_transient_timeout_wpseo_total_unindexed_posts",
            "wpseo_llms_txt_file_failure",
            "yoast_migrations_premium",
            "site_logo",
        ]
        .map(String::from)
        .into();
        assert_eq!(collapse(&names), ["site_logo", "wpseo_*", "yoast_migrations_premium"]);
    }
}
