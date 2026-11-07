use super::*;

const WORDPRESS: &str = include_str!("../../examples/wordpress.json");
const OFF: &str = include_str!("../../examples/off.json");
const COMMITTED_SCHEMA: &str = include_str!("../../securecore.schema.json");

fn parse(json: &str) -> Result<Config, Problem> {
    Config::from_slice(json.as_bytes())
}

fn rejected(json: &str) -> String {
    match parse(json) {
        Ok(c) => panic!("accepted an invalid config: {c:?}"),
        Err(e) => e.to_string(),
    }
}

/// A valid config with `extra` spliced into layer2 (keeps each rejection test to one change).
fn with_layer2(extra: &str) -> String {
    format!(
        r#"{{"layer1":{{"enabled":false}},"layer2":{{"enabled":true,"app":"wordpress"{extra}}},"layer3":{{"enabled":false}}}}"#
    )
}

#[test]
fn wordpress_example_parses_with_every_field() {
    let c = parse(WORDPRESS).expect("examples/wordpress.json");
    assert!(c.layer1.enabled && c.layer2.enabled && c.layer3.enabled);
    assert!(!c.is_off());
    assert_eq!(c.layer1.write, ["wp-content/uploads", "wp-content/cache"]);
    assert_eq!(c.layer1.network.bind.iter().map(|p| p.port.get()).collect::<Vec<_>>(), [9000]);
    assert_eq!(c.layer1.network.connect.iter().map(|p| p.port.get()).collect::<Vec<_>>(), [3306, 443]);
    assert_eq!(c.layer1.network.unix_sockets, ["/run/mysqld/mysqld.sock"]);
    assert_eq!(c.layer2.app, Some(App::Wordpress));
    assert_eq!(c.layer2.mode, Mode::Enforce);
    let vault = c.layer2.vault.as_ref().expect("vault");
    assert_eq!(vault.from, "wp-config.php");
    assert_eq!(vault.secrets.len(), 9);
    assert_eq!(c.layer2.default.files, Some(Scope::Keyword(ScopeKeyword::Own)));
    let woo = &c.layer2.components["woocommerce"];
    assert_eq!(woo.tables, Some(Scope::Patterns(vec!["wc_*".into(), "woocommerce_*".into()])));
    assert_eq!(woo.grants.as_deref(), Some(&["users:read".to_string()][..]));
    assert_eq!(woo.files, None, "unset fields inherit from default");
    assert_eq!(c.layer3.isolate, ["contact-form-7"]);
    assert_eq!(c.layer3.limits.timeout_ms.get(), 5000);
    assert_eq!(c.layer3.limits.memory_mb.get(), 256);
}

#[test]
fn off_example_is_valid_and_off() {
    let c = parse(OFF).expect("examples/off.json");
    assert!(c.is_off());
    assert_eq!(c.schema.as_deref(), Some("../securecore.schema.json"));
    assert_eq!(c.layer2.mode, Mode::Enforce, "the default mode is the safe one");
    assert_eq!(c.layer3.limits, Limits::default());
}

#[test]
fn unknown_keys_are_rejected_at_every_level() {
    let top = r#"{"layer1":{"enabled":false},"layer2":{"enabled":false},"layer3":{"enabled":false},"layer4":{}}"#;
    assert!(rejected(top).contains("unknown field `layer4`"), "{}", rejected(top));
    let l1 = r#"{"layer1":{"enabled":false,"writes":[]},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#;
    assert!(rejected(l1).contains("unknown field `writes`"));
    let net = r#"{"layer1":{"enabled":false,"network":{"unix_sockets":[]}},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#;
    assert!(rejected(net).contains("unknown field `unix_sockets`"));
    assert!(rejected(&with_layer2(r#","modes":"log""#)).contains("unknown field `modes`"));
    let component = with_layer2(r#","components":{"cf7":{"host":[]}}"#);
    assert!(rejected(&component).contains("unknown field `host`"));
    let l3 = r#"{"layer1":{"enabled":false},"layer2":{"enabled":false},"layer3":{"enabled":false,"limits":{"timeout":1}}}"#;
    assert!(rejected(l3).contains("unknown field `timeout`"));
}

#[test]
fn bad_mode_and_app_are_rejected() {
    assert!(parse(&with_layer2(r#","mode":"log""#)).is_ok());
    assert!(parse(&with_layer2(r#","mode":"off""#)).is_ok());
    let e = rejected(&with_layer2(r#","mode":"block""#));
    assert!(e.contains("unknown variant `block`"), "{e}");
    let e = rejected(&with_layer2(r#","mode":"Enforce""#));
    assert!(e.contains("unknown variant `Enforce`"), "{e}");
    let e = rejected(r#"{"layer1":{"enabled":false},"layer2":{"enabled":true,"app":"drupal"},"layer3":{"enabled":false}}"#);
    assert!(e.contains("unknown variant `drupal`"), "{e}");
}

#[test]
fn enabled_layer2_needs_an_app() {
    let e = rejected(r#"{"layer1":{"enabled":false},"layer2":{"enabled":true},"layer3":{"enabled":false}}"#);
    assert!(e.contains("layer2.app is missing"), "{e}");
}

#[test]
fn every_layer_and_enabled_is_required() {
    assert!(rejected(r#"{"layer1":{"enabled":false},"layer2":{"enabled":false}}"#).contains("missing field `layer3`"));
    assert!(rejected(r#"{"layer1":{},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#).contains("missing field `enabled`"));
    assert!(rejected("").contains("EOF"));
    assert!(rejected("1").contains("invalid type"));
    rejected("[]");
}

/// serde reads a struct from a JSON array by position; the schema says object. Each of these
/// is a valid config in serde's array form, and each must be rejected, naming where.
#[test]
fn the_array_form_is_rejected_at_every_level() {
    // Proof that serde alone accepts them: they deserialize as the plain type.
    // Positional: `$schema` first.
    let top = r#"[null,{"enabled":false},{"enabled":false},{"enabled":false}]"#;
    assert!(serde_json::from_str::<Config>(top).is_ok(), "serde accepts the array form");
    let e = rejected(top);
    assert!(e.contains("the top level is an array; it must be an object"), "{e}");

    let l1 = r#"{"layer1":[false],"layer2":{"enabled":false},"layer3":{"enabled":false}}"#;
    assert!(serde_json::from_str::<Config>(l1).is_ok());
    assert!(rejected(l1).contains("layer1 is an array"), "{}", rejected(l1));

    let port = r#"{"layer1":{"enabled":true,"network":{"connect":[{"port":443},[3306]]}},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#;
    assert!(serde_json::from_str::<Config>(port).is_ok());
    assert!(rejected(port).contains("layer1.network.connect[1] is an array"), "{}", rejected(port));

    let limits = r#"{"layer1":{"enabled":false},"layer2":{"enabled":false},"layer3":{"enabled":true,"limits":[100,64]}}"#;
    assert!(rejected(limits).contains("layer3.limits is an array"), "{}", rejected(limits));

    // A component's rules: `hosts` first, by position.
    let rules = with_layer2(r#","components":{"cf7":[["example.com"]]}"#);
    assert!(serde_json::from_str::<Config>(&rules).is_ok());
    assert!(rejected(&rules).contains("layer2.components.cf7 is an array"), "{}", rejected(&rules));

    // Arrays where the schema has arrays stay valid.
    assert!(parse(&with_layer2(r#","default":{"files":["wp-content/uploads/*"]}"#)).is_ok());
    assert!(parse(WORDPRESS).is_ok());
}

#[test]
fn paths_resolve_against_the_folder_holding_the_file() {
    let dir = scratch("root");
    let site = dir.join("site");
    fs::create_dir_all(&site).expect("mkdir");
    let path = site.join("securecore.json");
    fs::write(&path, WORDPRESS).expect("write");
    let loaded = load(&path).expect("load");
    let root = fs::canonicalize(&site).expect("canonical");
    assert_eq!(loaded.root, root);
    assert_eq!(loaded.resolve("wp-content/uploads"), root.join("wp-content/uploads"));
    assert_eq!(loaded.resolve("/srv/backups"), Path::new("/srv/backups"), "absolute paths as they are");
    assert_eq!(loaded.resolve(&loaded.config.layer2.vault.as_ref().expect("vault").from), root.join("wp-config.php"));

    // A symlinked file: the root is where the link sits, not where it points.
    let elsewhere = dir.join("etc");
    fs::create_dir_all(&elsewhere).expect("mkdir");
    let real = elsewhere.join("securecore.json");
    fs::write(&real, WORDPRESS).expect("write");
    let link_site = dir.join("linked-site");
    fs::create_dir_all(&link_site).expect("mkdir");
    std::os::unix::fs::symlink(&real, link_site.join("securecore.json")).expect("symlink");
    let linked = load(&link_site.join("securecore.json")).expect("load via symlink");
    assert_eq!(linked.root, fs::canonicalize(&link_site).expect("canonical"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn port_zero_and_bad_scope_are_rejected() {
    let e = rejected(r#"{"layer1":{"enabled":true,"network":{"connect":[{"port":0}]}},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#);
    assert!(e.contains("nonzero"), "{e}");
    rejected(r#"{"layer1":{"enabled":true,"network":{"connect":[{"port":65536}]}},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#);
    rejected(&with_layer2(r#","default":{"files":"all"}"#));
}

/// One source of truth: the committed schema is exactly what the types generate. To update:
/// `cargo run -p securecore-config --bin securecore-schema > securecore.schema.json` in ext/.
#[test]
fn schema_in_sync() {
    assert!(
        COMMITTED_SCHEMA == schema_json(),
        "ext/securecore.schema.json is stale: regenerate it with \
         `cargo run -p securecore-config --bin securecore-schema > securecore.schema.json`"
    );
}

#[test]
fn schema_covers_the_rules_serde_enforces() {
    let schema: serde_json::Value = serde_json::from_str(&schema_json()).expect("schema is JSON");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["required"], serde_json::json!(["layer1", "layer2", "layer3"]));
    let layer2 = &schema["$defs"]["Layer2"];
    assert_eq!(layer2["additionalProperties"], false);
    assert_eq!(layer2["then"]["required"], serde_json::json!(["app"]));
    assert_eq!(schema["$defs"]["Mode"]["enum"], serde_json::json!(["enforce", "log", "off"]));
}

/// A fresh directory under TMPDIR (the clone's .tmp when run per AGENTS.md).
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("securecore-config-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

#[test]
fn load_reports_the_file_and_the_problem() {
    let dir = scratch("load");
    let path = dir.join("securecore.json");
    let e = load(&path).expect_err("missing file").to_string();
    assert!(e.starts_with(&format!("{}: cannot read it:", path.display())), "{e}");
    fs::write(&path, r#"{"layer1":{"enabled":false},"#).expect("write");
    let e = load(&path).expect_err("truncated file").to_string();
    assert!(e.starts_with(&format!("{}: invalid:", path.display())) && e.contains("line 1"), "{e}");
    fs::write(&path, OFF).expect("write");
    let loaded = load(&path).expect("valid file");
    assert_eq!(loaded.sha256, sha256_hex(OFF.as_bytes()));
    assert_eq!(loaded.sha256.len(), 64);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn sha256_is_the_standard_digest() {
    assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

#[test]
fn reloader_follows_the_file_and_never_drops_to_off() {
    let dir = scratch("reload");
    let path = dir.join("securecore.json");
    fs::write(&path, WORDPRESS).expect("write");
    let t0 = Instant::now();
    let interval = Duration::from_millis(1000);
    let mut r = Reloader::start(&path, interval, t0).expect("start");
    assert_eq!(r.live().sha256, sha256_hex(WORDPRESS.as_bytes()));

    // Layer 2 changes: picked up after the interval, not before.
    let log_mode = WORDPRESS.replace(r#""mode": "enforce""#, r#""mode": "log""#);
    assert_ne!(log_mode, WORDPRESS);
    fs::write(&path, &log_mode).expect("write");
    assert_eq!(r.poll(t0 + Duration::from_millis(999)), Poll::Unchanged, "throttled");
    assert_eq!(r.live().config.layer2.mode, Mode::Enforce);
    assert_eq!(r.poll(t0 + interval), Poll::Reloaded { layer1_changed: false });
    assert_eq!(r.live().config.layer2.mode, Mode::Log);
    assert_eq!(r.live().sha256, sha256_hex(log_mode.as_bytes()));
    assert_eq!(r.reloads(), 1);
    assert_eq!(r.poll(t0 + 2 * interval), Poll::Unchanged, "same stamp: no reload");

    // An invalid edit is rejected once; the last valid config stays live.
    fs::write(&path, r#"{"layer1":{"enabled":false}"#).expect("write");
    let Poll::Rejected(msg) = r.poll(t0 + 3 * interval) else { panic!("invalid file accepted") };
    assert!(msg.contains(&path.display().to_string()), "{msg}");
    assert_eq!(r.error(), Some(msg.as_str()));
    assert_eq!(r.poll(t0 + 4 * interval), Poll::Unchanged, "reported once");
    assert_eq!(r.live().config.layer2.mode, Mode::Log);
    assert_eq!(r.live().sha256, sha256_hex(log_mode.as_bytes()));

    // A deleted file too.
    fs::remove_file(&path).expect("rm");
    assert!(matches!(r.poll(t0 + 5 * interval), Poll::Rejected(m) if m.contains("cannot read it")));
    assert_eq!(r.live().config.layer2.mode, Mode::Log);

    // Layer 1 changes reload (layers 2/3 see the file) and are flagged as needing a restart.
    let l1 = log_mode.replace(r#""port": 9000"#, r#""port": 9001"#);
    fs::write(&path, &l1).expect("write");
    assert_eq!(r.poll(t0 + 6 * interval), Poll::Reloaded { layer1_changed: true });
    assert!(r.restart_needed());
    assert_eq!(r.error(), None);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn reloader_start_fails_closed() {
    let dir = scratch("start");
    let path = dir.join("securecore.json");
    assert!(Reloader::start(&path, Duration::from_secs(1), Instant::now()).is_err());
    fs::write(&path, with_layer2(r#","mode":"block""#)).expect("write");
    let e = Reloader::start(&path, Duration::from_secs(1), Instant::now()).expect_err("invalid");
    assert!(e.to_string().contains("unknown variant `block`"));
    let _ = fs::remove_dir_all(&dir);
}
