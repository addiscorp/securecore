//! The #49 verdicts (test/policy-unit.php, all 65 of them), ported, and E4's own rules.
//!
//! #49's "plain" plugin owned its manifest options and could read and write core content (posts
//! and their meta) freely; E4 reaches core's tables only through grants, so its equivalent here
//! is the component `myplugin` with `options: ["securecore_policy_probe_own"]` and
//! `grants: ["posts:write"]`. #49's grants `users`, `usermeta:capabilities` and
//! `option:admin_email` are `users:write`, `capabilities:write` and listing `admin_email` in
//! `options`. A verdict E4 changes on purpose is marked `E4:` with the reason.

use securecore_config::{Layer2, Mode, Rules, Scope};

use crate::policy::{Decision, Rules4, Site, Who, decide, glob};
use crate::{Cache, Shape, analyze};

const U: &str = "wp_users";
const UM: &str = "wp_usermeta";
const O: &str = "wp_options";
const P: &str = "wp_posts";
const PM: &str = "wp_postmeta";
const PRE: &str = "wp_";

fn site() -> Site {
    Site { prefix: PRE.into(), db_name: Some("wordpress".into()) }
}

fn rules(slug: &str, tables: &[&str], options: &[&str], grants: &[&str]) -> Rules4 {
    let mut l2 = Layer2 {
        enabled: true,
        app: Some(securecore_config::App::Wordpress),
        mode: Mode::Enforce,
        vault: None,
        core: Default::default(),
        default: Rules::default(),
        components: Default::default(),
    };
    let list = |v: &[&str]| Some(Scope::Patterns(v.iter().map(|s| s.to_string()).collect()));
    l2.components.insert(
        slug.into(),
        Rules { tables: list(tables), options: list(options), grants: Some(grants.iter().map(|s| s.to_string()).collect()), ..Default::default() },
    );
    Rules4::for_component(&l2, slug)
}

fn plain() -> Rules4 {
    rules("myplugin", &[], &["securecore_policy_probe_own"], &["posts:write"])
}

fn granted() -> Rules4 {
    rules("myplugin", &[], &["securecore_policy_probe_own", "admin_email"], &["posts:write", "users:write", "capabilities:write"])
}

fn verdict(r: &Rules4, sql: &str) -> Decision {
    decide(&analyze(sql), &Who::Component(r), &site())
}

fn core(sql: &str) -> Decision {
    decide(&analyze(sql), &Who::Core, &site())
}

#[track_caller]
fn denied(r: &Rules4, sql: &str) {
    let d = verdict(r, sql);
    assert!(matches!(d, Decision::Refuse(_)), "expected a refusal, got {d:?}: {sql}");
}

#[track_caller]
fn denied_as(r: &Rules4, sql: &str, rule: &str) {
    assert_eq!(verdict(r, sql), Decision::Refuse(leak(rule)), "{sql}");
}

#[track_caller]
fn allowed(r: &Rules4, sql: &str) {
    assert_eq!(verdict(r, sql), Decision::Allow, "{sql}");
}

fn leak(s: &str) -> &'static str {
    Box::leak(s.to_owned().into_boxed_str())
}

// --- #49: denied, no grant (17) --------------------------------------------------------------

#[test]
fn p49_denied_without_a_grant() {
    let p = plain();
    denied_as(&p, &format!("DROP TABLE {U}"), "ddl-core");
    denied_as(&p, &format!("TRUNCATE TABLE {U}"), "ddl-core");
    denied_as(&p, &format!("ALTER TABLE {O} ADD COLUMN x INT"), "ddl-core");
    denied_as(&p, &format!("CREATE TABLE {P} (id INT)"), "ddl-core");
    denied_as(&p, &format!("SELECT 1; DROP TABLE {P}"), "multi-statement");
    denied_as(&p, "this is not a query", "unparseable");
    denied_as(&p, &format!("SELECT user_pass FROM {U} WHERE ID = 1"), "protected-column");
    denied_as(&p, &format!("SELECT ID, user_activation_key FROM {U}"), "protected-column");
    denied_as(&p, &format!("INSERT INTO {U} (user_login, user_pass) VALUES ('x', 'y')"), "core-table");
    denied_as(&p, &format!("DELETE FROM {U} WHERE ID = 2"), "core-table");
    denied_as(&p, &format!("UPDATE {UM} SET meta_value = 'a:1:{{}}' WHERE user_id = 1 AND meta_key = '{PRE}capabilities'"), "capabilities");
    denied(&p, &format!("UPDATE {UM} SET meta_value = 'x' WHERE user_id = 1 AND meta_key = 'session_tokens'"));
    denied_as(&p, &format!("UPDATE {O} SET option_value = 'x' WHERE option_name = 'active_plugins'"), "protected-option");
    denied_as(&p, &format!("UPDATE {O} SET option_value = 'http://evil' WHERE option_name = 'siteurl'"), "protected-option");
    denied_as(&p, &format!("UPDATE {O} SET option_value = 'x' WHERE option_name = '{PRE}user_roles'"), "protected-option");
    denied_as(&p, &format!("INSERT INTO {O} (option_name, option_value) VALUES ('admin_email', 'x')"), "protected-option");
    denied_as(&p, &format!("DELETE FROM {O} WHERE option_name = 'mailserver_pass'"), "protected-option");
}

// --- #49: denied by shape (20), for a component and for core ---------------------------------

#[test]
fn p49_denied_by_shape_for_everyone() {
    let p = plain();
    let hex: String = format!("SELECT user_pass FROM {U} WHERE ID=1").bytes().map(|b| format!("{b:02x}")).collect();
    let cases: Vec<(String, &str)> = vec![
        (format!("SET @s = 0x{hex}"), "user-variable"),
        ("SET @@global.sql_mode = ''".into(), "user-variable"),
        ("PREPARE stmt FROM @s".into(), "prepare"),
        ("EXECUTE stmt".into(), "prepare"),
        ("DEALLOCATE PREPARE stmt".into(), "prepare"),
        ("SELECT LOAD_FILE('/etc/passwd')".into(), "server-file"),
        (format!("SELECT * FROM {P} INTO OUTFILE '/tmp/x'"), "server-file"),
        (format!("SELECT ID FROM {P} INTO DUMPFILE '/tmp/x'"), "server-file"),
        (format!("INSERT INTO {PRE}myplugin (a) VALUES (LOAD_FILE('/etc/passwd'))"), "server-file"),
        (format!("LOAD DATA INFILE '/etc/passwd' INTO TABLE {PRE}myplugin"), "server-file"),
        ("CALL some_proc()".into(), "statement"),
        (format!("HANDLER {U} OPEN"), "statement"),
        ("DO SLEEP(5)".into(), "statement"),
        ("USE wordpress".into(), "statement"),
        ("GRANT ALL ON *.* TO 'x'@'localhost'".into(), "statement"),
        (format!("LOCK TABLES {O} WRITE"), "statement"),
        ("CREATE DEFINER=`root`@`localhost` VIEW v AS SELECT 1".into(), "routine"),
        ("CREATE FUNCTION f() RETURNS INT RETURN 1".into(), "routine"),
        (format!("CREATE TRIGGER t BEFORE INSERT ON {P} FOR EACH ROW SET @x=1"), "routine"),
        (format!("WITH t AS (SELECT user_pass FROM {U}) SELECT * FROM t"), "cte"),
    ];
    assert_eq!(cases.len(), 20);
    for (sql, rule) in &cases {
        assert_eq!(verdict(&p, sql), Decision::Refuse(leak(rule)), "component: {sql}");
        // The statement allowlist applies to core too (E4): none of these runs for anyone.
        assert_eq!(core(sql), Decision::Refuse(leak(rule)), "core: {sql}");
    }
}

// --- #49: allowed (24) -----------------------------------------------------------------------

#[test]
fn p49_allowed() {
    let p = plain();
    // E4: #49 ran this and stripped user_pass from the result. E4 has no result filter, so a `*`
    // over users is refused for a component even with users:read (see users_wildcard below).
    denied_as(&p, &format!("SELECT * FROM {U} WHERE ID = 1"), "protected-column");
    allowed(&p, &format!("SELECT * FROM {P} LIMIT 5"));
    // E4: #49 ran a bulk options read and cut it down to an allowlist afterwards. With no result
    // filter, an unpinned read of options needs options:read.
    denied_as(&p, &format!("SELECT option_name, option_value FROM {O} WHERE autoload IN ('yes', 'on')"), "options-unpinned");
    allowed(&p, &format!("SELECT option_value FROM {O} WHERE option_name = 'securecore_policy_probe_own'"));
    // E4: options are own + listed; siteurl is neither, so reading it by name needs options:read.
    denied_as(&p, &format!("SELECT option_value FROM {O} WHERE option_name = 'siteurl'"), "option");
    allowed(&p, &format!("UPDATE {O} SET option_value = 'x' WHERE option_name = 'myplugin_setting'"));
    allowed(&p, &format!("CREATE TABLE {PRE}myplugin_data (id INT)"));
    allowed(&p, &format!("INSERT INTO {PRE}myplugin_data (id) VALUES (1)"));
    allowed(&p, &format!("INSERT INTO {PM} (post_id, meta_key, meta_value) VALUES (1, 'k', 'v')"));
    allowed(&p, "SET NAMES utf8mb4");
    allowed(&p, "SET SESSION sql_mode = 'NO_ENGINE_SUBSTITUTION'");
    allowed(&p, "SET autocommit = 0");
    allowed(&p, "SELECT 1");
    allowed(&p, &format!("DESCRIBE {O}"));
    allowed(&p, &format!("EXPLAIN SELECT * FROM {P}"));
    allowed(&p, "START TRANSACTION");
    allowed(&p, "BEGIN");
    allowed(&p, "COMMIT");
    allowed(&p, "ROLLBACK");
    allowed(&p, "SAVEPOINT sp1");
    allowed(&p, "ROLLBACK TO SAVEPOINT sp1");
    allowed(&p, &format!("TRUNCATE TABLE {PRE}myplugin_data"));
    allowed(&p, &format!("SELECT ID FROM {P} WHERE post_content LIKE '%into outfile%'"));
    allowed(&p, &format!("INSERT INTO {PRE}myplugin (note) VALUES ('about load_file( usage')"));
}

// --- #49: a grant opens exactly its door (4) -------------------------------------------------

#[test]
fn p49_grants() {
    let g = granted();
    allowed(&g, &format!("INSERT INTO {U} (user_login) VALUES ('x')"));
    allowed(&g, &format!("UPDATE {UM} SET meta_value = 'a:1:{{}}' WHERE user_id = 1 AND meta_key = '{PRE}capabilities'"));
    // E4: the protected options are never writable (the brief), so listing admin_email opens
    // reading it, not writing it; #49's option:<name> grant opened both.
    denied_as(&g, &format!("UPDATE {O} SET option_value = 'x' WHERE option_name = 'admin_email'"), "protected-option");
    allowed(&g, &format!("SELECT option_value FROM {O} WHERE option_name = 'admin_email'"));
    denied_as(&g, &format!("DROP TABLE {U}"), "ddl-core");
}

// --- E4: tables ------------------------------------------------------------------------------

#[test]
fn tables_are_own_listed_or_granted() {
    let me = rules("contact-form-7", &["cf7_*"], &[], &[]);
    allowed(&me, "SELECT * FROM wp_contact_form_7");
    allowed(&me, "SELECT * FROM wp_contact_form_7_log");
    allowed(&me, "INSERT INTO wp_cf7_messages (m) VALUES ('x')");
    // A prefix only the slug starts: not its own.
    denied_as(&me, "SELECT * FROM wp_contact_form_70", "table");
    // Another plugin's table.
    denied_as(&me, "SELECT * FROM wp_yoast_indexable", "table");
    denied_as(&me, "DROP TABLE wp_yoast_indexable", "table");
    // Core's, without a grant; and a join that reaches one.
    denied_as(&me, "SELECT * FROM wp_posts", "core-table");
    denied_as(&me, "SELECT m.* FROM wp_cf7_messages m JOIN wp_posts p ON p.ID = m.post_id", "core-table");
    denied_as(&me, "SELECT * FROM wp_cf7_messages WHERE id IN (SELECT ID FROM wp_posts)", "core-table");
    // With a grant: read, not write; write includes read.
    let reader = rules("contact-form-7", &[], &[], &["posts:read"]);
    allowed(&reader, "SELECT ID, post_title FROM wp_posts WHERE post_type = 'wpcf7_contact_form'");
    denied_as(&reader, "UPDATE wp_posts SET post_title = 'x' WHERE ID = 1", "core-table");
    let writer = rules("contact-form-7", &[], &[], &["posts:write"]);
    allowed(&writer, "UPDATE wp_posts SET post_title = 'x' WHERE ID = 1");
    // A slug named after a core table owns nothing of core's.
    let users = rules("users", &[], &[], &[]);
    denied_as(&users, "SELECT ID FROM wp_users", "core-table");
    allowed(&users, "SELECT * FROM wp_users_extra");
}

#[test]
fn schemas_multisite_and_quoting() {
    let me = rules("myplugin", &[], &[], &[]);
    allowed(&me, "SELECT * FROM `wordpress`.`wp_myplugin`");
    allowed(&me, "SELECT * FROM WP_MYPLUGIN");
    denied_as(&me, "SELECT * FROM mysql.user", "foreign-schema");
    denied_as(&me, "SELECT * FROM otherdb.wp_myplugin", "foreign-schema");
    allowed(&me, "SELECT table_name FROM information_schema.tables WHERE table_schema = 'wordpress'");
    denied_as(&me, "SELECT ID FROM `wp_users`", "core-table");
    denied_as(&me, "SELECT * FROM wp_2_posts", "core-table");
    denied_as(&me, "SELECT * FROM wp_sitemeta", "core-table");
    allowed(&me, "SELECT * FROM wp_2_myplugin");
}

// --- E4: protected columns --------------------------------------------------------------------

#[test]
fn users_protected_columns_even_with_a_grant() {
    let r = rules("myplugin", &[], &[], &["users:read"]);
    allowed(&r, "SELECT ID, user_login, user_email, display_name FROM wp_users WHERE ID = 1");
    for sql in [
        "SELECT * FROM wp_users WHERE ID = 1",
        "SELECT u.* FROM wp_users u",
        "SELECT ID FROM wp_users WHERE user_pass LIKE '$P$B%'",
        "SELECT ID FROM wp_users ORDER BY user_activation_key",
        "SELECT ID FROM wp_posts UNION SELECT user_pass FROM wp_users",
        "SELECT * FROM (SELECT * FROM wp_users) t",
        "SELECT CONCAT(user_login, user_pass) FROM wp_users",
        "SELECT ID FROM wp_users NATURAL JOIN wp_myplugin",
        "SELECT ID FROM wp_users JOIN wp_myplugin USING (user_pass)",
        "INSERT INTO wp_myplugin SELECT * FROM wp_users",
    ] {
        denied(&r, sql);
    }
    // users:write may set a password (as wp_set_password does), not read one.
    let w = rules("myplugin", &[], &[], &["users:write"]);
    allowed(&w, "UPDATE wp_users SET user_pass = '$P$Bnew', user_activation_key = '' WHERE ID = 2");
    denied(&w, "UPDATE wp_users SET user_email = user_pass WHERE ID = 2");
}

#[test]
fn usermeta_capabilities_and_session_tokens() {
    let r = rules("myplugin", &[], &[], &["users:write"]);
    allowed(&r, "UPDATE wp_usermeta SET meta_value = 'x' WHERE user_id = 1 AND meta_key = 'nickname'");
    denied_as(&r, "UPDATE wp_usermeta SET meta_value = 'x' WHERE user_id = 1 AND meta_key = 'wp_capabilities'", "capabilities");
    denied_as(&r, "UPDATE wp_usermeta SET meta_value = 'x' WHERE user_id = 1 AND meta_key = 'wp_2_capabilities'", "capabilities");
    // An unpinned usermeta write could touch the capability rows.
    denied_as(&r, "DELETE FROM wp_usermeta WHERE user_id = 7", "capabilities");
    denied_as(&r, "UPDATE wp_usermeta SET meta_value = 'x' WHERE meta_key = 'nickname' OR 1 = 1", "capabilities");
    denied_as(&r, "SELECT meta_value FROM wp_usermeta WHERE user_id = 1 AND meta_key = 'session_tokens'", "protected-meta");
    allowed(&r, "SELECT user_id, meta_key, meta_value FROM wp_usermeta WHERE user_id IN (1)");
}

// --- E4: options -------------------------------------------------------------------------------

#[test]
fn options_own_listed_granted_protected() {
    let yoast = rules("wordpress-seo", &[], &["wpseo*", "yoast_*"], &[]);
    allowed(&yoast, "SELECT option_value FROM wp_options WHERE option_name = 'wpseo_titles' LIMIT 1");
    allowed(&yoast, "UPDATE wp_options SET option_value = 'x' WHERE option_name = 'wpseo'");
    // add_option's upsert, as WordPress writes it.
    allowed(
        &yoast,
        "INSERT INTO `wp_options` (`option_name`, `option_value`, `autoload`) VALUES ('wpseo_social', 'a:0:{}', 'auto') \
         ON DUPLICATE KEY UPDATE `option_name` = VALUES(`option_name`), `option_value` = VALUES(`option_value`), `autoload` = VALUES(`autoload`)",
    );
    // Transients of its own, by name and by the LIKE cleanup WordPress plugins run.
    allowed(&yoast, "SELECT option_value FROM wp_options WHERE option_name = '_transient_wpseo_cache' LIMIT 1");
    allowed(&yoast, "DELETE FROM wp_options WHERE option_name LIKE '\\_transient\\_wpseo%'");
    denied_as(&yoast, "DELETE FROM wp_options WHERE option_name LIKE '\\_transient\\_%'", "option");
    // The slug's own forms (classic-editor-replace), another plugin's option, core's.
    let ce = rules("classic-editor", &[], &[], &[]);
    allowed(&ce, "SELECT option_value FROM wp_options WHERE option_name = 'classic-editor-replace' LIMIT 1");
    denied_as(&ce, "SELECT option_value FROM wp_options WHERE option_name = 'wpseo_titles' LIMIT 1", "option");
    denied_as(&ce, "SELECT option_value FROM wp_options WHERE option_name IN ('classic-editor-replace', 'blogname')", "option");
    // A pin an OR widens, or a rename into a protected name.
    denied_as(&ce, "SELECT option_value FROM wp_options WHERE option_name = 'classic-editor-replace' OR 1 = 1", "options-unpinned");
    denied_as(&ce, "UPDATE wp_options SET option_name = 'siteurl' WHERE option_name = 'classic-editor-replace'", "protected-option");
    denied_as(&ce, "UPDATE wp_options SET option_name = CONCAT('site', 'url') WHERE option_name = 'classic-editor-replace'", "options-unpinned");
    // options:read / options:write: the rest, never a protected write, never a salt.
    let all = rules("myplugin", &[], &[], &["options:write"]);
    allowed(&all, "SELECT option_value FROM wp_options WHERE option_name = 'blogname'");
    allowed(&all, "SELECT option_name, option_value FROM wp_options WHERE autoload IN ('yes', 'on')");
    allowed(&all, "UPDATE wp_options SET option_value = 'x' WHERE option_name = 'blogdescription'");
    for o in ["siteurl", "home", "active_plugins", "wp_user_roles", "cron", "admin_email", "default_role", "users_can_register"] {
        denied_as(&all, &format!("UPDATE wp_options SET option_value = 'x' WHERE option_name = '{o}'"), "protected-option");
    }
    denied_as(&all, "UPDATE wp_options SET autoload = 'off' WHERE autoload = 'on'", "options-unpinned");
    denied_as(&all, "SELECT option_value FROM wp_options WHERE option_name = 'mailserver_pass'", "protected-option");
    denied_as(&all, "SELECT option_value FROM wp_options WHERE option_name = 'auth_salt'", "protected-option");
    // Listing a read-protected option makes it readable, never writable; a salt stays closed.
    let lists = rules("myplugin", &[], &["cron", "nonce_salt"], &[]);
    allowed(&lists, "SELECT option_value FROM wp_options WHERE option_name = 'cron'");
    denied_as(&lists, "UPDATE wp_options SET option_value = 'x' WHERE option_name = 'cron'", "protected-option");
    denied_as(&lists, "SELECT option_value FROM wp_options WHERE option_name = 'nonce_salt'", "protected-option");
}

// --- E4: tricks the parser and MySQL must read alike ----------------------------------------

#[test]
fn comment_and_tokenizer_tricks() {
    let r = rules("myplugin", &[], &[], &["users:read"]);
    denied_as(&r, "SELECT /*!50000 user_pass */ ID FROM wp_users", "executable-comment");
    denied_as(&r, "SELECT ID /*! , user_pass */ FROM wp_users", "executable-comment");
    denied_as(&r, "SELECT ID FROM wp_myplugin /*!UNION SELECT user_pass FROM wp_users*/", "executable-comment");
    denied_as(&r, "SELECT ID FROM wp_myplugin /*!99999 UNION SELECT user_pass FROM wp_users */", "executable-comment");
    // Inside a string it is data; after a line comment it is hidden from MySQL too.
    allowed(&r, "SELECT ID FROM wp_users WHERE display_name = '/*! not code */'");
    allowed(&r, "SELECT ID FROM wp_users -- /*! hidden\n");
    // Plain comments are just comments.
    allowed(&r, "SELECT ID /* user_pass */ FROM wp_users -- user_pass\n");
    allowed(&r, "SELECT ID FROM wp_users # user_pass\n");
    // A hint is not an executable comment.
    allowed(&r, "SELECT /*+ MAX_EXECUTION_TIME(1000) */ ID FROM wp_users");
    // Making MySQL tokenize differently from the parser.
    for sql in [
        "SET SESSION sql_mode = 'ANSI_QUOTES'",
        "SET sql_mode = 'ANSI'",
        "SET SESSION sql_mode = 'NO_BACKSLASH_ESCAPES,STRICT_TRANS_TABLES'",
        "SET SESSION sql_mode = CONCAT(@@sql_mode, ',ANSI_QUOTES')",
        "SET NAMES gbk",
        "SET CHARACTER SET sjis",
        "SET GLOBAL max_connections = 1",
        "SET PASSWORD = 'x'",
    ] {
        denied(&r, sql);
        assert!(matches!(core(sql), Decision::Refuse(_)), "core: {sql}");
    }
    allowed(&r, "SET NAMES 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci'");
    // A quoted string that only looks like code.
    allowed(&r, "SELECT ID FROM wp_users WHERE user_login = 'x\\' OR user_pass = \\'y'");
    // SELECT … INTO a variable.
    denied_as(&r, "SELECT ID INTO @x FROM wp_users LIMIT 1", "select-into");
}

#[test]
fn core_is_unrestricted_but_for_the_allowlist() {
    assert_eq!(core("SELECT user_pass FROM wp_users WHERE ID = 1"), Decision::Allow);
    assert_eq!(core("SELECT * FROM wp_users"), Decision::Allow);
    assert_eq!(core("UPDATE wp_options SET option_value = 'x' WHERE option_name = 'siteurl'"), Decision::Allow);
    assert_eq!(core("ALTER TABLE wp_posts ADD INDEX type_status_date (post_type, post_status, post_date, ID)"), Decision::Allow);
    assert_eq!(core("SELECT option_name, option_value FROM wp_options WHERE autoload IN ('yes', 'on')"), Decision::Allow);
    // Unparseable from core runs and is logged; from a component it is refused (fail closed).
    assert_eq!(core("this is not a query"), Decision::AllowLogged("unparseable"));
    assert_eq!(verdict(&plain(), "this is not a query"), Decision::Refuse("unparseable"));
    assert_eq!(core("PREPARE s FROM 'SELECT 1'"), Decision::Refuse("prepare"));
    // Layer 3's gateway (#94) caps each statement's time on the worker's connection with these,
    // as core, around an isolated plugin's queries.
    for sql in [
        "SELECT @@SESSION.max_statement_time",
        "SET SESSION max_statement_time = 1.500",
        "SET SESSION max_statement_time = 0.000000",
        "SELECT @@SESSION.max_execution_time",
        "SET SESSION max_execution_time = 1500",
    ] {
        assert_eq!(core(sql), Decision::Allow, "{sql}");
    }
    // ...and reads the connection's transaction state after each exchange, as core.
    assert_eq!(core("SELECT @@autocommit, @@in_transaction"), Decision::Allow);
    // XA transactions (which a plain ROLLBACK can't end) never open for a component.
    for sql in ["XA START 'x'", "XA BEGIN 'x'"] {
        assert!(matches!(verdict(&plain(), sql), Decision::Refuse(_)), "{sql}");
    }
}

// --- the WordPress shapes the parser must take (a component in place of core) -------------------

#[test]
fn wordpress_query_shapes_parse() {
    for sql in [
        "SELECT SQL_CALC_FOUND_ROWS  wp_posts.ID FROM wp_posts  WHERE 1=1  AND ((wp_posts.post_type = 'post' AND (wp_posts.post_status = 'publish'))) ORDER BY wp_posts.post_date DESC LIMIT 0, 10",
        "SELECT FOUND_ROWS()",
        "SELECT t.*, tt.* FROM wp_terms AS t INNER JOIN wp_term_taxonomy AS tt ON t.term_id = tt.term_id WHERE tt.taxonomy IN ('category') ORDER BY t.name ASC",
        "SELECT post_id, meta_key, meta_value FROM wp_postmeta WHERE post_id IN (1,2,3) ORDER BY meta_id ASC",
        "SHOW FULL COLUMNS FROM `wp_posts`",
        "SELECT @@SESSION.sql_mode",
        "SET SESSION sql_mode='NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'",
        "SELECT autoload, COUNT(*) AS count, SUM(LENGTH(option_value)) AS size FROM wp_options GROUP BY autoload",
        "UPDATE `wp_options` SET `option_value` = '1' WHERE `option_name` = 'x'",
        "DELETE a, b FROM wp_options a, wp_options b WHERE a.option_name LIKE '\\_transient\\_%' AND a.option_name NOT LIKE '\\_transient\\_timeout\\_%' AND b.option_name = CONCAT('_transient_timeout_', SUBSTRING(a.option_name, 12)) AND b.option_value < 1",
    ] {
        let a = analyze(sql);
        assert!(!matches!(a.shape, Shape::Unparseable | Shape::Refused(_)), "{:?}: {sql}", a.shape);
    }
}

/// The cost of a cache miss (one parse + analysis) and of a hit, on WordPress's own query shapes.
/// Not a gate: `cargo test --release -p securecore-db -- --ignored --nocapture parse_cost`.
#[test]
#[ignore]
fn parse_cost() {
    let qs = [
        "SELECT SQL_CALC_FOUND_ROWS  wp_posts.ID FROM wp_posts  WHERE 1=1  AND ((wp_posts.post_type = 'post' AND (wp_posts.post_status = 'publish' OR wp_posts.post_status = 'private'))) ORDER BY wp_posts.post_date DESC LIMIT 0, 10",
        "SELECT t.*, tt.* FROM wp_terms AS t INNER JOIN wp_term_taxonomy AS tt ON t.term_id = tt.term_id INNER JOIN wp_term_relationships AS tr ON tr.term_taxonomy_id = tt.term_taxonomy_id WHERE tt.taxonomy IN ('category', 'post_tag', 'post_format') AND tr.object_id IN (1) ORDER BY t.name ASC",
        "SELECT post_id, meta_key, meta_value FROM wp_postmeta WHERE post_id IN (1,2,3,4,5) ORDER BY meta_id ASC",
        "SELECT option_value FROM wp_options WHERE option_name = 'wpseo_titles' LIMIT 1",
        "INSERT INTO `wp_options` (`option_name`, `option_value`, `autoload`) VALUES ('_transient_wpseo_x', 'a:1:{s:1:\"x\";i:1;}', 'off') ON DUPLICATE KEY UPDATE `option_name` = VALUES(`option_name`), `option_value` = VALUES(`option_value`), `autoload` = VALUES(`autoload`)",
    ];
    let n = 2000;
    let t = std::time::Instant::now();
    for i in 0..n {
        let _ = analyze(qs[i % qs.len()]);
    }
    let miss = t.elapsed().as_secs_f64() * 1e6 / n as f64;
    let mut c = Cache::new(64);
    for q in qs {
        c.get(q);
    }
    let t = std::time::Instant::now();
    for i in 0..n {
        let _ = c.get(qs[i % qs.len()]);
    }
    let hit = t.elapsed().as_secs_f64() * 1e6 / n as f64;
    let r = plain();
    let a = analyze(qs[0]);
    let t = std::time::Instant::now();
    for _ in 0..n {
        let _ = decide(&a, &Who::Component(&r), &site());
    }
    let dec = t.elapsed().as_secs_f64() * 1e6 / n as f64;
    println!("per query: parse+analyse (miss) {miss:.1} µs, cache hit {hit:.2} µs, decide {dec:.2} µs");
}

// --- the cache ---------------------------------------------------------------------------------

#[test]
fn cache_hits_and_stays_bounded() {
    let mut c = Cache::new(8);
    let a = c.get("SELECT 1");
    let b = c.get("SELECT 1");
    assert!(std::sync::Arc::ptr_eq(&a, &b));
    assert_eq!((c.hits, c.misses), (1, 1));
    for i in 0..100 {
        c.get(&format!("SELECT {i}"));
    }
    assert!(c.len() <= 8, "{}", c.len());
    // The hot entry survives eviction while it keeps being used.
    for i in 0..100 {
        c.get("SELECT 1");
        c.get(&format!("SELECT x{i}"));
    }
    let before = c.hits;
    c.get("SELECT 1");
    assert_eq!(c.hits, before + 1);
    // A huge text is analysed but not kept.
    let big = format!("SELECT '{}'", "x".repeat(Cache::MAX_KEY));
    c.get(&big);
    c.get(&big);
    assert!(c.misses >= 2);
}

#[test]
fn globs() {
    assert!(glob("wc_*", "wc_orders"));
    assert!(glob("wc_*", "wc_"));
    assert!(!glob("wc_*", "wcx"));
    assert!(glob("a?c", "abc"));
    assert!(glob("*_log", "cf7_log"));
    assert!(!glob("*_log", "cf7_logs"));
}
