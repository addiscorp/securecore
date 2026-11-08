use std::path::{Path, PathBuf};

use securecore_config::Config;

use super::*;

const ROOT: &str = "/srv/site";

/// WordPress's default layout rooted at [`ROOT`]: uploads is `/srv/site/wp-content/uploads` and
/// cache is `/srv/site/wp-content/cache`. The two protected files are wp-config.php and
/// securecore.json at the root. (Paths are treated as already resolved, as the extension
/// resolves them before calling [`Policy::decide`].)
fn policy() -> Policy {
    Policy::new(
        p(ROOT),
        p("/srv/site/wp-content/uploads"),
        p("/srv/site/wp-content/cache"),
        vec![p("/srv/site/wp-config.php"), p("/srv/site/securecore.json")],
    )
}

fn p(s: &str) -> PathBuf {
    PathBuf::from(s)
}

/// A component with no extra access: the baseline every plugin has.
fn baseline() -> Access {
    Access::default()
}

#[test]
fn core_and_outside_are_not_restricted() {
    let json = r#"{"layer1":{"enabled":false},"layer2":{"enabled":true,"app":"wordpress"},"layer3":{"enabled":false}}"#;
    let l2 = Config::from_slice(json.as_bytes()).expect("config").layer2;
    assert_eq!(access_for(&l2, Path::new(ROOT), &Component::Core), None);
    assert_eq!(access_for(&l2, Path::new(ROOT), &Component::Outside), None);
    // A component is restricted (an Access, even if empty).
    assert!(access_for(&l2, Path::new(ROOT), &Component::Plugin("p".into())).is_some());
}

#[test]
fn disabled_or_off_layer2_restricts_nobody() {
    let off = r#"{"layer1":{"enabled":false},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#;
    let l2 = Config::from_slice(off.as_bytes()).expect("config").layer2;
    assert_eq!(access_for(&l2, Path::new(ROOT), &Component::Plugin("p".into())), None);
    let mode_off = r#"{"layer1":{"enabled":false},"layer2":{"enabled":true,"app":"wordpress","mode":"off"},"layer3":{"enabled":false}}"#;
    let l2 = Config::from_slice(mode_off.as_bytes()).expect("config").layer2;
    assert_eq!(access_for(&l2, Path::new(ROOT), &Component::Plugin("p".into())), None, "mode off: no restriction");
}

#[test]
fn reads_under_the_root_are_allowed_except_protected() {
    let pol = policy();
    let a = baseline();
    // Anywhere under the root, including another component's folder (shared libraries, core
    // APIs reading on a plugin's behalf): allowed.
    assert!(pol.decide(&a, Op::Read, &p("/srv/site/wp-content/plugins/other/vendor/x.php")).is_allowed());
    assert!(pol.decide(&a, Op::Read, &p("/srv/site/wp-includes/version.php")).is_allowed());
    assert_eq!(pol.decide(&a, Op::Read, &p("/srv/site/wp-content/uploads/a.txt")), Decision::Allow);
    // The protected files are closed even though they are under the root.
    assert_eq!(pol.decide(&a, Op::Read, &p("/srv/site/wp-config.php")), Decision::Refuse("read-protected"));
    assert_eq!(pol.decide(&a, Op::Read, &p("/srv/site/securecore.json")), Decision::Refuse("read-protected"));
    // Outside the root with no grant: refused.
    assert_eq!(pol.decide(&a, Op::Read, &p("/etc/passwd")), Decision::Refuse("read-outside-root"));
    // A sibling whose name only starts with the root is not under it.
    assert_eq!(pol.decide(&a, Op::Read, &p("/srv/site-evil/x")), Decision::Refuse("read-outside-root"));
}

#[test]
fn reads_outside_the_root_need_an_explicit_grant() {
    let pol = policy();
    let a = Access { read: vec![p("/etc/ssl/certs")], ..Access::default() };
    assert!(pol.decide(&a, Op::Read, &p("/etc/ssl/certs/ca.pem")).is_allowed(), "granted folder");
    assert!(pol.decide(&a, Op::Read, &p("/etc/ssl/certs")).is_allowed(), "the folder itself");
    assert_eq!(pol.decide(&a, Op::Read, &p("/etc/ssl/private/key.pem")), Decision::Refuse("read-outside-root"), "a sibling folder is not granted");
    // A grant never opens a protected file.
    let a = Access { read: vec![p("/srv/site")], ..Access::default() };
    assert_eq!(pol.decide(&a, Op::Read, &p("/srv/site/wp-config.php")), Decision::Refuse("read-protected"));
}

#[test]
fn writes_are_uploads_and_cache_only_plus_grants() {
    let pol = policy();
    let a = baseline();
    assert!(pol.decide(&a, Op::Write, &p("/srv/site/wp-content/uploads/2026/x.jpg")).is_allowed());
    assert!(pol.decide(&a, Op::Write, &p("/srv/site/wp-content/cache/page.html")).is_allowed());
    // Not the component's own folder, not core, not the root.
    assert_eq!(pol.decide(&a, Op::Write, &p("/srv/site/wp-content/plugins/p/evil.php")), Decision::Refuse("write"));
    assert_eq!(pol.decide(&a, Op::Write, &p("/srv/site/wp-includes/version.php")), Decision::Refuse("write"));
    assert_eq!(pol.decide(&a, Op::Write, &p("/tmp/x")), Decision::Refuse("write"));
    // A write grant.
    let a = Access { write: vec![p("/srv/site/wp-content/plugins/p/data")], ..Access::default() };
    assert!(pol.decide(&a, Op::Write, &p("/srv/site/wp-content/plugins/p/data/db.sqlite")).is_allowed());
    assert_eq!(pol.decide(&a, Op::Write, &p("/srv/site/wp-content/plugins/p/other.php")), Decision::Refuse("write"));
    // A write grant never reaches a protected file either.
    let a = Access { write: vec![p("/srv/site")], ..Access::default() };
    assert_eq!(pol.decide(&a, Op::Write, &p("/srv/site/securecore.json")), Decision::Refuse("write-protected"));
}

#[test]
fn exec_needs_the_grant_and_ignores_the_path() {
    let pol = policy();
    assert_eq!(pol.decide(&baseline(), Op::Exec, &p("/usr/bin/convert")), Decision::Refuse("exec"));
    let a = Access { exec: true, ..Access::default() };
    assert!(pol.decide(&a, Op::Exec, &p("/usr/bin/convert")).is_allowed());
    assert!(pol.decide(&a, Op::Exec, &p("anything")).is_allowed());
}

#[test]
fn effective_rules_inherit_default_field_by_field() {
    let root = tempdir();
    let json = r#"{"layer1":{"enabled":false},"layer2":{"enabled":true,"app":"wordpress",
            "default":{"exec":true,"files":{"read":["def-read"]}},
            "components":{
              "keeps-default":{},
              "own-files":{"files":{"write":["own-write"]}},
              "no-exec":{"exec":false}
            }},"layer3":{"enabled":false}}"#;
    let l2 = Config::from_slice(json.as_bytes()).expect("config").layer2;
    let at = |slug: &str| access_for(&l2, &root, &Component::Plugin(slug.into())).expect("restricted");

    // Unset fields inherit default: exec true, read ["def-read"].
    let keep = at("keeps-default");
    assert!(keep.exec, "exec inherited from default");
    assert_eq!(keep.read.len(), 1);
    assert!(keep.read[0].ends_with("def-read"));
    assert!(keep.write.is_empty());

    // A component's own `files` replaces default's `files` wholesale (not merged); exec still
    // inherits default.
    let own = at("own-files");
    assert!(own.exec, "exec still from default");
    assert!(own.read.is_empty(), "own files has no read, so no read (default's files is replaced)");
    assert_eq!(own.write.len(), 1);
    assert!(own.write[0].ends_with("own-write"));

    // An explicit exog overrides default.
    assert!(!at("no-exec").exec, "exec false overrides default true");
}

#[test]
fn a_component_with_no_rules_at_all_still_has_the_baseline() {
    // No default, no entry: empty access (exec off, no extra paths), but still a Policy subject.
    let root = tempdir();
    let json = r#"{"layer1":{"enabled":false},"layer2":{"enabled":true,"app":"wordpress"},"layer3":{"enabled":false}}"#;
    let l2 = Config::from_slice(json.as_bytes()).expect("config").layer2;
    let a = access_for(&l2, &root, &Component::Theme("twentytwentyfive".into())).expect("restricted");
    assert_eq!(a, Access::default());
}

fn tempdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("securecore-policy-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}
