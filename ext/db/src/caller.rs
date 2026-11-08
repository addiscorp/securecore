//! Who a query is charged to (E4): **the code that called the database layer**. Core APIs run
//! their own SQL on a plugin's behalf (`get_user_by()` loading the current user, `WP_Query`), so
//! charging that SQL to the plugin on the stack refuses core's own work: with Yoast active it
//! logged the admin out (#60). A component's own SQL is still the component's.
//!
//! Except through a **passthrough helper**: a core function that runs SQL, or a table, column or
//! option name, its caller hands it (`dbDelta($sql)`, `maybe_create_table($t, $ddl)`,
//! `update_option('active_plugins', …)`). While the chain of core frames from the query outward
//! runs through one of these, the query is charged to the helper's caller, so a plugin can't
//! launder a write to a protected option, or a read of `user_pass`, through core.

use securecore_attribution::Component;

/// One user-code frame on the stack, innermost first.
#[derive(Debug, Clone)]
pub struct Frame<'a> {
    /// The component the frame's file belongs to.
    pub component: Component,
    /// The frame's file, as PHP reports it.
    pub file: &'a str,
    /// The function the frame is running, lowercase; `None` for top-level code, a closure, or a
    /// method (no helper is a method).
    pub function: Option<&'a str>,
}

/// Core functions that run SQL, or a table, column or option name, their caller hands them:
/// `wp-admin/includes/upgrade.php`, `install-helper.php` and `schema.php`, and the option write
/// API. A function by one of these names counts only when it is defined in core.
pub const PASSTHROUGH: &[&str] = &[
    // upgrade.php
    "dbdelta",
    "maybe_create_table",
    "maybe_add_column",
    "maybe_convert_table_to_utf8mb4",
    "drop_index",
    "add_clean_index",
    "__get_option",
    // install-helper.php
    "maybe_drop_column",
    "check_column",
    // schema.php
    "populate_options",
    "populate_network",
    "populate_network_meta",
    "populate_site_meta",
    // wp-includes/option.php: the write API takes the option name from its caller.
    "add_option",
    "update_option",
    "delete_option",
    "add_site_option",
    "update_site_option",
    "delete_site_option",
    "add_network_option",
    "update_network_option",
    "delete_network_option",
];

fn is_wpdb(f: &Frame<'_>) -> bool {
    f.component == Component::Core && f.file.ends_with("/wp-includes/class-wpdb.php")
}

fn is_passthrough(f: &Frame<'_>) -> bool {
    f.component == Component::Core && f.function.is_some_and(|n| PASSTHROUGH.contains(&n))
}

/// The component a query is charged to, from the user frames that issued it (innermost first).
pub fn charged(frames: &[Frame<'_>]) -> Component {
    let mut i = frames.iter().position(|f| !is_wpdb(f)).unwrap_or(frames.len());
    let Some(first) = frames.get(i) else { return Component::Core };
    if first.component != Component::Core {
        // The component's own SQL: `$wpdb->query(...)` in its file, or its own mysqli / PDO.
        return first.component.clone();
    }
    // Core issued it. Walk out through core's frames: a passthrough helper hands the charge to
    // its caller; reaching a component any other way means the SQL was core's own.
    while let Some(f) = frames.get(i) {
        if f.component != Component::Core {
            return Component::Core;
        }
        if is_passthrough(f) {
            match frames.get(i + 1) {
                Some(caller) if caller.component != Component::Core => return caller.component.clone(),
                Some(_) => {}
                None => return Component::Core,
            }
        }
        i += 1;
    }
    Component::Core
}

#[cfg(test)]
mod tests {
    use super::*;

    const WPDB: &str = "/var/www/html/wp-includes/class-wpdb.php";

    fn core<'a>(file: &'a str, function: Option<&'a str>) -> Frame<'a> {
        Frame { component: Component::Core, file, function }
    }

    fn plugin(slug: &str) -> Frame<'static> {
        Frame { component: Component::Plugin(slug.into()), file: "/var/www/html/wp-content/plugins/p/p.php", function: None }
    }

    fn p(slug: &str) -> Component {
        Component::Plugin(slug.into())
    }

    #[test]
    fn a_components_own_sql_is_its_own() {
        // $wpdb->query() in the plugin's file.
        let f = [core(WPDB, Some("_do_query")), core(WPDB, Some("query")), plugin("acme")];
        assert_eq!(charged(&f), p("acme"));
        // Its own mysqli: the plugin frame is the innermost.
        assert_eq!(charged(&[plugin("acme")]), p("acme"));
    }

    #[test]
    fn sql_a_core_api_composes_is_cores() {
        // Yoast → get_user_by → WP_User::get_data_by → $wpdb (the #60 lockout).
        let f = [
            core(WPDB, Some("get_row")),
            core("/var/www/html/wp-includes/class-wp-user.php", Some("get_data_by")),
            core("/var/www/html/wp-includes/pluggable.php", Some("get_user_by")),
            plugin("wordpress-seo"),
        ];
        assert_eq!(charged(&f), Component::Core);
    }

    #[test]
    fn passthrough_helpers_charge_their_caller() {
        let up = "/var/www/html/wp-admin/includes/upgrade.php";
        // dbDelta($sql) called by a plugin: the plugin's.
        let f = [core(WPDB, Some("query")), core(up, Some("dbdelta")), plugin("acme")];
        assert_eq!(charged(&f), p("acme"));
        // maybe_create_table: the plugin's.
        let f = [core(WPDB, Some("query")), core(up, Some("maybe_create_table")), plugin("acme")];
        assert_eq!(charged(&f), p("acme"));
        // update_option('active_plugins') straight from a plugin, through add_option: the plugin's.
        let opt = "/var/www/html/wp-includes/option.php";
        let f = [core(WPDB, Some("query")), core(opt, Some("add_option")), core(opt, Some("update_option")), plugin("acme")];
        assert_eq!(charged(&f), p("acme"));
        // Core's own upgrade calling dbDelta: core's.
        let f = [core(WPDB, Some("query")), core(up, Some("dbdelta")), core(up, Some("make_db_current")), core(up, Some("wp_upgrade"))];
        assert_eq!(charged(&f), Component::Core);
    }

    #[test]
    fn wp_schedule_event_is_cores_cron_write() {
        let opt = "/var/www/html/wp-includes/option.php";
        let cron = "/var/www/html/wp-includes/cron.php";
        let f = [
            core(WPDB, Some("query")),
            core(opt, Some("update_option")),
            core(cron, Some("_set_cron_array")),
            core(cron, Some("wp_schedule_event")),
            plugin("acme"),
        ];
        assert_eq!(charged(&f), Component::Core);
    }

    #[test]
    fn the_innermost_helper_decides() {
        // B → update_option → (a filter) → A's callback → update_option → $wpdb: A wrote it.
        let opt = "/var/www/html/wp-includes/option.php";
        let hook = "/var/www/html/wp-includes/class-wp-hook.php";
        let f = [
            core(WPDB, Some("query")),
            core(opt, Some("update_option")),
            plugin("a"),
            core(hook, Some("apply_filters")),
            core(opt, Some("update_option")),
            plugin("b"),
        ];
        assert_eq!(charged(&f), p("a"));
    }

    #[test]
    fn a_plugin_function_named_like_a_helper_is_not_one() {
        // A plugin defining its own dbDelta(): its frame is the plugin's, so it is direct SQL.
        let f = [core(WPDB, Some("query")), Frame { function: Some("dbdelta"), ..plugin("acme") }];
        assert_eq!(charged(&f), p("acme"));
    }
}
