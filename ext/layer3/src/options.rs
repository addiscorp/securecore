//! Which options the helper boots WordPress from (#47): WordPress's own options, never a plugin's
//! and never a secret.
//!
//! WordPress does not list its own options anywhere at runtime, so the list is read from the
//! site's own `wp-admin/includes/schema.php`: the names `populate_options()` installs (the keys of
//! its `$defaults` literal and its `add_option()` calls), as the #42 spike did in PHP
//! (`core_option_names()`). On top: `<prefix>user_roles` (core's role map, seeded by
//! `populate_roles()`) and the active theme's `theme_mods_<stylesheet>`. Taken away: the database
//! policy's read-protected and never-readable options (one list, [`securecore_db::policy`]), and
//! the active-plugin lists, so the helper boots with no plugins.

use std::collections::BTreeSet;

/// The option names `populate_options()` in `schema_php` installs. Empty if the function isn't
/// there (the caller then sends an empty snapshot, and the helper boots on WordPress's defaults).
pub fn core_option_names(schema_php: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let Some(start) = schema_php.find("function populate_options") else { return names };
    let rest = &schema_php[start..];
    // The body ends at the first closing brace in column 0 (every brace inside is indented).
    let body = rest.find("\n}").map_or(rest, |end| &rest[..end]);
    // Anchored on the two shapes, not on pairing quotes (a comment's apostrophe would throw the
    // pairing off): `'name' =>` (a key of the defaults literal) and `add_option( 'name'` (the
    // extra options it adds one by one), as the spike's regexes were.
    for (at, _) in body.match_indices("=>") {
        if let Some(name) = quoted_before(&body[..at]) {
            names.insert(name.to_owned());
        }
    }
    for (at, m) in body.match_indices("add_option(") {
        if let Some(name) = quoted_after(&body[at + m.len()..]) {
            names.insert(name.to_owned());
        }
    }
    names
}

fn is_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `…'name'<whitespace>` at the end of `text`: the name.
fn quoted_before(text: &str) -> Option<&str> {
    let text = text.trim_end().strip_suffix('\'')?;
    let open = text.rfind('\'')?;
    Some(&text[open + 1..]).filter(|n| is_name(n))
}

/// `<whitespace>'name'…` at the start of `text`: the name.
fn quoted_after(text: &str) -> Option<&str> {
    let text = text.trim_start().strip_prefix('\'')?;
    let close = text.find('\'')?;
    Some(&text[..close]).filter(|n| is_name(n))
}

/// Options never put in a snapshot, whatever schema.php says: the active-plugin lists (the
/// helper boots with no plugins) and everything the database policy keeps from a component.
pub fn never_in_snapshot(name: &str) -> bool {
    use securecore_db::policy::{NEVER_READABLE_OPTIONS, READ_PROTECTED};
    name == "active_plugins"
        || name == "active_sitewide_plugins"
        || READ_PROTECTED.contains(&name)
        || NEVER_READABLE_OPTIONS.contains(&name)
}

/// The snapshot's allowlist for a site: `core` (from [`core_option_names`]) plus
/// `<prefix>user_roles` and `theme_mods_<stylesheet>`, minus [`never_in_snapshot`].
pub fn snapshot_allowlist(core: &BTreeSet<String>, prefix: &str, stylesheet: &str) -> BTreeSet<String> {
    let mut names = core.clone();
    names.insert(format!("{prefix}user_roles"));
    if !stylesheet.is_empty() {
        names.insert(format!("theme_mods_{stylesheet}"));
    }
    names.retain(|n| !never_in_snapshot(n));
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = r#"<?php
function wp_get_db_schema( $scope = 'all', $blog_id = null ) {
	$x = array( 'not_an_option' => 1 );
}
function populate_options( array $options = array() ) {
	global $wpdb;
	// Don't pair quotes: this comment's apostrophe would throw it off.
	$defaults = array(
		'siteurl'         => $guessurl,
		'home'            => $guessurl,
		'blogname'        => __( 'My Site' ),
		'admin_email'     => 'you@example.com',
		'active_plugins'  => array(),
		'mailserver_pass' => '',
		'cron'            => '',
		'date_format'     => __( 'F j, Y' ),
	);
	if ( is_multisite() ) {
		$defaults['permalink_structure'] = '/blog/%year%/';
	}
	add_option( 'secret_key', wp_generate_password( 64 ) );
	add_option( 'theme_switched', '' );
	$sql = "SELECT 'quoted' FROM x";
}
function populate_roles() {
	add_option( 'not_core_either', 1 );
}
"#;

    #[test]
    fn reads_populate_options_only() {
        let names = core_option_names(SCHEMA);
        let want: BTreeSet<String> =
            ["siteurl", "home", "blogname", "admin_email", "active_plugins", "mailserver_pass", "cron", "date_format", "secret_key", "theme_switched"]
                .into_iter()
                .map(String::from)
                .collect();
        assert_eq!(names, want);
    }

    #[test]
    fn allowlist_adds_roles_and_theme_mods_and_drops_secrets() {
        let names = snapshot_allowlist(&core_option_names(SCHEMA), "wp_", "twentytwentyfive");
        for keep in ["siteurl", "home", "blogname", "date_format", "theme_switched", "wp_user_roles", "theme_mods_twentytwentyfive"] {
            assert!(names.contains(keep), "{keep} missing");
        }
        // The plugin lists, the read-protected options and the salt options never go in.
        for drop in ["active_plugins", "admin_email", "mailserver_pass", "cron", "secret_key"] {
            assert!(!names.contains(drop), "{drop} kept");
        }
    }

    #[test]
    fn no_populate_options_means_nothing_from_schema() {
        assert!(core_option_names("<?php function other() {}").is_empty());
        assert_eq!(snapshot_allowlist(&BTreeSet::new(), "wp_", ""), BTreeSet::from(["wp_user_roles".to_owned()]));
    }
}
