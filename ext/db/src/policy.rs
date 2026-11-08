//! The per-component decision over an [`Analysis`] (E4). Plain Rust, unit-tested in `tests.rs`.
//!
//! - **Everyone** (core included) gets only the allowlisted statement types: SELECT, INSERT,
//!   REPLACE, UPDATE, DELETE; SHOW / DESCRIBE / EXPLAIN; the session SETs (never `@` variables,
//!   never a `sql_mode` or charset that makes MySQL read the text differently from the parser);
//!   transaction control; table DDL. PREPARE / EXECUTE, LOAD_FILE, INTO OUTFILE / DUMPFILE, CTEs,
//!   `/*! … */` executable comments and the rest are refused for everyone.
//! - **Core** is otherwise unrestricted; an unparseable query from core runs and is logged.
//! - **A component** may use its own tables (named after its slug, or matching its `tables`
//!   globs), never DDL on core's, and core's tables only through a grant. Options: its own and
//!   its listed ones, others with `options:read` / `options:write`; the protected options are
//!   never writable. `users.user_pass` and `user_activation_key` are never readable (a `*` over
//!   `users` counts). Unparseable and multi-statement queries are refused.

use securecore_config::grant::{Access, Area, Grant};
use securecore_config::{Layer2, Rules, Scope};

use crate::analyze::{Analysis, Pin, Pins, Shape, TableName};

/// The site facts a decision needs: the table prefix (`$table_prefix`) and the database name
/// (`DB_NAME`), both lowercase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub prefix: String,
    pub db_name: Option<String>,
}

/// One component's effective database rules: `default` with its own entry laid over it, field by
/// field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rules4 {
    pub slug: String,
    pub tables: Vec<String>,
    pub options: Vec<String>,
    pub grants: Vec<Grant>,
}

impl Rules4 {
    pub fn for_component(l2: &Layer2, slug: &str) -> Rules4 {
        let own: Option<&Rules> = l2.components.get(slug);
        let pick = |f: fn(&Rules) -> Option<&Scope>| own.and_then(f).or_else(|| f(&l2.default));
        let patterns = |s: Option<&Scope>| match s {
            Some(Scope::Patterns(p)) => p.iter().map(|x| x.to_ascii_lowercase()).collect(),
            _ => Vec::new(),
        };
        let grants = own.and_then(|r| r.grants.as_ref()).or(l2.default.grants.as_ref());
        Rules4 {
            slug: slug.to_ascii_lowercase(),
            tables: patterns(pick(|r| r.tables.as_ref())),
            options: patterns(pick(|r| r.options.as_ref())),
            grants: grants.into_iter().flatten().filter_map(|g| Grant::parse(g)).collect(),
        }
    }

    fn granted(&self, area: Area, access: Access) -> bool {
        self.grants.iter().any(|g| g.allows(area, access))
    }
}

/// Who sent the query.
pub enum Who<'a> {
    Core,
    Component(&'a Rules4),
}

/// What happens to the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Runs, and the audit line records the rule (core's unparseable queries).
    AllowLogged(&'static str),
    Refuse(&'static str),
}

impl Decision {
    pub fn rule(self) -> Option<&'static str> {
        match self {
            Decision::Allow => None,
            Decision::AllowLogged(r) | Decision::Refuse(r) => Some(r),
        }
    }
}

/// Never writable by a component, whatever it lists or is granted. `<prefix>user_roles` is added
/// per site.
pub const WRITE_PROTECTED: &[&str] = &[
    "siteurl", "home", "active_plugins", "admin_email", "users_can_register", "default_role", "cron", "mailserver_login",
    "mailserver_pass", "auth_key", "auth_salt", "secure_auth_key", "secure_auth_salt", "logged_in_key", "logged_in_salt",
    "nonce_key", "nonce_salt", "secret_key", "secret_salt",
];
/// Readable by a component only when its entry lists the name in `options` (#49's read-denied set).
pub const READ_PROTECTED: &[&str] =
    &["active_plugins", "admin_email", "users_can_register", "default_role", "cron", "mailserver_login", "mailserver_pass"];
/// Never readable by a component, listed or not: the salts WordPress keeps as options when the
/// constants are unset (`wp_salt()`'s fallback, `secret_key` included).
pub const NEVER_READABLE_OPTIONS: &[&str] = &[
    "auth_key", "auth_salt", "secure_auth_key", "secure_auth_salt", "logged_in_key", "logged_in_salt", "nonce_key", "nonce_salt",
    "secret_key", "secret_salt",
];
/// `users` columns no component may read.
pub const PROTECTED_COLUMNS: &[&str] = &["user_pass", "user_activation_key"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoreTable {
    Users,
    Usermeta,
    Options,
    Other(Area),
}

impl CoreTable {
    fn area(self) -> Area {
        match self {
            CoreTable::Users | CoreTable::Usermeta => Area::Users,
            CoreTable::Options => Area::Options,
            CoreTable::Other(a) => a,
        }
    }
}

impl Site {
    /// The name after the prefix, and after a multisite blog number (`wp_2_posts` → `posts`).
    fn unprefixed<'a>(&self, name: &'a str) -> Option<(&'a str, bool)> {
        let rest = name.strip_prefix(self.prefix.as_str())?;
        if let Some((n, tail)) = rest.split_once('_')
            && !n.is_empty()
            && n.bytes().all(|b| b.is_ascii_digit())
        {
            return Some((tail, true));
        }
        Some((rest, false))
    }

    fn core_table(&self, name: &str) -> Option<CoreTable> {
        let (rest, blog) = self.unprefixed(name)?;
        let per_blog = match rest {
            "posts" | "postmeta" => Some(CoreTable::Other(Area::Posts)),
            "comments" | "commentmeta" => Some(CoreTable::Other(Area::Comments)),
            "terms" | "termmeta" | "term_taxonomy" | "term_relationships" => Some(CoreTable::Other(Area::Terms)),
            "links" => Some(CoreTable::Other(Area::Links)),
            "options" => Some(CoreTable::Options),
            _ => None,
        };
        if per_blog.is_some() || blog {
            return per_blog;
        }
        match rest {
            "users" => Some(CoreTable::Users),
            "usermeta" => Some(CoreTable::Usermeta),
            "blogs" | "blogmeta" | "site" | "sitemeta" | "signups" | "registration_log" | "blog_versions" => {
                Some(CoreTable::Other(Area::Network))
            }
            _ => None,
        }
    }

    fn user_roles(&self) -> String {
        format!("{}user_roles", self.prefix)
    }
}

/// `*` and `?` glob, ASCII, case already folded.
pub fn glob(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

/// The slug-derived name prefixes a component owns (`classic-editor` → `classic-editor`,
/// `classic_editor`).
fn slug_forms(slug: &str) -> [String; 2] {
    [slug.to_owned(), slug.replace('-', "_")]
}

fn owns_name(slug: &str, name: &str, seps: &[char]) -> bool {
    slug_forms(slug).iter().any(|s| name == s || seps.iter().any(|&c| name.strip_prefix(s.as_str()).is_some_and(|r| r.starts_with(c))))
}

const TRANSIENT_PREFIXES: &[&str] = &["_site_transient_timeout_", "_site_transient_", "_transient_timeout_", "_transient_"];

fn strip_transient(name: &str) -> &str {
    TRANSIENT_PREFIXES.iter().find_map(|p| name.strip_prefix(p)).unwrap_or(name)
}

impl Rules4 {
    fn owns_table(&self, site: &Site, name: &str) -> bool {
        if let Some((rest, _)) = site.unprefixed(name)
            && owns_name(&self.slug, rest, &['_'])
        {
            return true;
        }
        let rest = site.unprefixed(name).map_or(name, |(r, _)| r);
        self.tables.iter().any(|g| glob(g, rest) || glob(g, name))
    }

    /// Whether the option name (exact) is the component's own or listed.
    fn owns_option(&self, name: &str) -> bool {
        let n = strip_transient(name);
        owns_name(&self.slug, n, &['_', '-']) || self.options.iter().any(|g| glob(g, n) || glob(g, name))
    }

    /// Every option starting with `prefix` is the component's own or listed.
    fn owns_option_prefix(&self, prefix: &str) -> bool {
        let p = strip_transient(prefix);
        let forms = slug_forms(&self.slug);
        let own = forms.iter().any(|s| ['_', '-'].iter().any(|c| p.starts_with(&format!("{s}{c}"))));
        own || self.options.iter().any(|g| g.strip_suffix('*').is_some_and(|lit| !lit.contains(['*', '?']) && p.starts_with(lit)))
    }

    fn lists_option(&self, name: &str) -> bool {
        self.options.iter().any(|g| glob(g, name))
    }
}

/// The decision for one analysed query from `who`.
pub fn decide(a: &Analysis, who: &Who<'_>, site: &Site) -> Decision {
    match a.shape {
        Shape::Refused(rule) => return Decision::Refuse(rule),
        Shape::Unparseable => {
            return match who {
                Who::Core => Decision::AllowLogged("unparseable"),
                Who::Component(_) => Decision::Refuse("unparseable"),
            };
        }
        _ => {}
    }
    let Who::Component(r) = who else { return Decision::Allow };
    if a.statements > 1 {
        return Decision::Refuse("multi-statement");
    }
    match a.shape {
        Shape::Meta | Shape::Transaction | Shape::SessionSet => return Decision::Allow,
        Shape::Select | Shape::Write | Shape::Ddl => {}
        Shape::Refused(_) | Shape::Unparseable => unreachable!("handled above"),
    }
    let ddl = a.shape == Shape::Ddl;
    for t in a.tables() {
        let write = a.writes.contains(t);
        if let Err(rule) = table(r, site, t, write, ddl, a) {
            return Decision::Refuse(rule);
        }
    }
    Decision::Allow
}

fn table(r: &Rules4, site: &Site, t: &TableName, write: bool, ddl: bool, a: &Analysis) -> Result<(), &'static str> {
    match t.schema.as_deref() {
        None => {}
        Some(s) if site.db_name.as_deref() == Some(s) => {}
        Some("information_schema") if !write => return Ok(()),
        Some(_) => return Err("foreign-schema"),
    }
    let name = t.name.as_str();
    if let Some(core) = site.core_table(name) {
        if ddl {
            return Err("ddl-core");
        }
        return core_table(r, site, core, write, a);
    }
    if r.owns_table(site, name) { Ok(()) } else { Err("table") }
}

fn core_table(r: &Rules4, site: &Site, core: CoreTable, write: bool, a: &Analysis) -> Result<(), &'static str> {
    let access = if write { Access::Write } else { Access::Read };
    match core {
        CoreTable::Options => return options(r, site, a, write),
        CoreTable::Users => {
            if PROTECTED_COLUMNS.iter().any(|c| a.columns.contains(*c))
                || a.columns.contains("*natural")
                || a.wildcard.iter().any(|w| site.core_table(&w.name) == Some(CoreTable::Users))
            {
                return Err("protected-column");
            }
        }
        CoreTable::Usermeta => {
            if a.meta_keys.names.contains(&Pin::Exact("session_tokens".into())) && !write {
                return Err("protected-meta");
            }
            if write {
                let caps = [format!("{}capabilities", site.prefix), format!("{}user_level", site.prefix)];
                let touches_caps = !a.meta_keys.pinned
                    || a.meta_keys.names.iter().any(|p| match p {
                        Pin::Exact(n) => caps.iter().any(|c| c == &n.to_ascii_lowercase()) || capability_key(site, n),
                        Pin::Prefix(p) => caps.iter().any(|c| c.starts_with(&p.to_ascii_lowercase())),
                    });
                if touches_caps && !r.granted(Area::Capabilities, Access::Write) {
                    return Err("capabilities");
                }
            }
        }
        CoreTable::Other(_) => {}
    }
    if r.granted(core.area(), access) { Ok(()) } else { Err("core-table") }
}

/// `wp_2_capabilities` on a multisite: any blog's capability row.
fn capability_key(site: &Site, key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    site.unprefixed(&k).is_some_and(|(rest, _)| rest == "capabilities" || rest == "user_level")
}

fn options(r: &Rules4, site: &Site, a: &Analysis, write: bool) -> Result<(), &'static str> {
    let pins: &Pins = &a.option_names;
    let roles = site.user_roles();
    let write_protected = |n: &str| WRITE_PROTECTED.contains(&n) || n == roles;
    if write {
        if !pins.pinned {
            return Err("options-unpinned");
        }
        for p in &pins.names {
            match p {
                Pin::Exact(n) => {
                    let n = n.to_ascii_lowercase();
                    if write_protected(&n) {
                        return Err("protected-option");
                    }
                    if !r.owns_option(&n) && !r.granted(Area::Options, Access::Write) {
                        return Err("option");
                    }
                }
                Pin::Prefix(p) => {
                    let p = p.to_ascii_lowercase();
                    if WRITE_PROTECTED.iter().any(|w| w.starts_with(&p)) || roles.starts_with(&p) {
                        return Err("protected-option");
                    }
                    if !r.owns_option_prefix(&p) && !r.granted(Area::Options, Access::Write) {
                        return Err("option");
                    }
                }
            }
        }
        return Ok(());
    }
    if !pins.pinned {
        return if r.granted(Area::Options, Access::Read) { Ok(()) } else { Err("options-unpinned") };
    }
    for p in &pins.names {
        match p {
            Pin::Exact(n) => {
                let n = n.to_ascii_lowercase();
                if NEVER_READABLE_OPTIONS.contains(&n.as_str()) {
                    return Err("protected-option");
                }
                if READ_PROTECTED.contains(&n.as_str()) {
                    if r.lists_option(&n) {
                        continue;
                    }
                    return Err("protected-option");
                }
                if !r.owns_option(&n) && !r.granted(Area::Options, Access::Read) {
                    return Err("option");
                }
            }
            Pin::Prefix(p) => {
                let p = p.to_ascii_lowercase();
                if NEVER_READABLE_OPTIONS.iter().chain(READ_PROTECTED).any(|w| w.starts_with(&p)) {
                    return Err("protected-option");
                }
                if !r.owns_option_prefix(&p) && !r.granted(Area::Options, Access::Read) {
                    return Err("option");
                }
            }
        }
    }
    Ok(())
}
