//! The grants a component entry may list (`layer2.components.<slug>.grants`, E4): access to what
//! WordPress core owns, as `<area>:<access>`. A component reaches none of core's tables without
//! one. `write` includes `read`. Parsed here so an unknown grant makes the file invalid (fail
//! closed), and the database policy (`securecore-db`) reads the same type.

use std::fmt;

/// What part of core's database a grant opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Area {
    /// `users`, `usermeta`. The password hash and activation key stay unreadable, and capability
    /// rows need `capabilities:write` as well.
    Users,
    /// The capability rows in `usermeta` (`<prefix>capabilities`, `<prefix>user_level`): who is an
    /// administrator. Only `write` is meaningful.
    Capabilities,
    /// `posts`, `postmeta`.
    Posts,
    /// `comments`, `commentmeta`.
    Comments,
    /// `terms`, `termmeta`, `term_taxonomy`, `term_relationships`.
    Terms,
    /// `links`.
    Links,
    /// Every row of `options` that is not protected. The protected options are never writable, and
    /// the read-protected ones are readable only when listed in the entry's `options`.
    Options,
    /// The multisite tables: `blogs`, `blogmeta`, `site`, `sitemeta`, `signups`,
    /// `registration_log`, `blog_versions`.
    Network,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Access {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Grant {
    pub area: Area,
    pub access: Access,
}

impl Area {
    pub const ALL: [Area; 8] =
        [Area::Users, Area::Capabilities, Area::Posts, Area::Comments, Area::Terms, Area::Links, Area::Options, Area::Network];

    pub fn as_str(self) -> &'static str {
        match self {
            Area::Users => "users",
            Area::Capabilities => "capabilities",
            Area::Posts => "posts",
            Area::Comments => "comments",
            Area::Terms => "terms",
            Area::Links => "links",
            Area::Options => "options",
            Area::Network => "network",
        }
    }
}

impl Grant {
    /// `users:read`, `posts:write`, … ; `None` for anything else.
    pub fn parse(s: &str) -> Option<Grant> {
        let (area, access) = s.split_once(':')?;
        let area = Area::ALL.into_iter().find(|a| a.as_str() == area)?;
        let access = match access {
            "read" => Access::Read,
            "write" => Access::Write,
            _ => return None,
        };
        Some(Grant { area, access })
    }

    /// Whether this grant allows `access` on `area` (`write` includes `read`).
    pub fn allows(self, area: Area, access: Access) -> bool {
        self.area == area && (self.access == Access::Write || access == Access::Read)
    }
}

impl fmt::Display for Grant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let access = match self.access {
            Access::Read => "read",
            Access::Write => "write",
        };
        write!(f, "{}:{access}", self.area.as_str())
    }
}

/// Checks every entry's `grants`; the error names the entry and the grant.
pub fn validate(l2: &crate::Layer2) -> Result<(), String> {
    let entries = std::iter::once(("default", &l2.default)).chain(l2.components.iter().map(|(k, v)| (k.as_str(), v)));
    for (name, rules) in entries {
        for g in rules.grants.iter().flatten() {
            if Grant::parse(g).is_none() {
                return Err(format!(
                    "layer2.{}grants: {g:?} is not a grant; expected <area>:read or <area>:write, area one of {}",
                    if name == "default" { "default.".to_owned() } else { format!("components.{name}.") },
                    Area::ALL.map(Area::as_str).join(", ")
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_vocabulary() {
        assert_eq!(Grant::parse("users:read"), Some(Grant { area: Area::Users, access: Access::Read }));
        assert_eq!(Grant::parse("options:write").map(|g| g.to_string()).as_deref(), Some("options:write"));
        for bad in ["users", "users:all", "Users:read", "option:admin_email", "usermeta:capabilities", ""] {
            assert_eq!(Grant::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn write_includes_read() {
        let w = Grant { area: Area::Posts, access: Access::Write };
        assert!(w.allows(Area::Posts, Access::Read) && w.allows(Area::Posts, Access::Write));
        let r = Grant { area: Area::Posts, access: Access::Read };
        assert!(r.allows(Area::Posts, Access::Read) && !r.allows(Area::Posts, Access::Write));
        assert!(!w.allows(Area::Users, Access::Read));
    }
}
