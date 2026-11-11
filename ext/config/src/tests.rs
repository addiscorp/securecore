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
        r#"{{"layer1":{{"isolation":"off"}},"layer2":{{"enabled":true,"app":"wordpress"{extra}}},"layer3":{{"enabled":false}}}}"#
    )
}

#[test]
fn wordpress_example_parses_with_every_field() {
    let c = parse(WORDPRESS).expect("examples/wordpress.json");
    assert!(c.layer1.enabled() && c.layer2.enabled && c.layer3.enabled);
    assert!(!c.is_off());
    assert_eq!(c.layer1.write, ["wp-content/uploads", "wp-content/cache", "/tmp"]);
    assert_eq!(c.layer1.network.bind.iter().map(|p| p.port.get()).collect::<Vec<_>>(), [9000]);
    // MySQL over TCP, not its unix socket: the launcher can't combine the two yet (#57).
    assert_eq!(c.layer1.network.connect.iter().map(|p| p.port.get()).collect::<Vec<_>>(), [53, 3306, 443]);
    assert!(c.layer1.network.unix_sockets.is_empty());
    assert_eq!(c.layer2.app, Some(App::Wordpress));
    assert_eq!(c.layer2.mode, Mode::Enforce);
    let vault = c.layer2.vault.as_ref().expect("vault");
    assert_eq!(vault.from, Some(Source::WpConfig("wp-config.php".into())));
    assert_eq!(vault.secrets.len(), 9);
    assert_eq!(vault.secrets[0].name(), "DB_PASSWORD");
    assert_eq!(vault.secrets[0].env(), Some("WORDPRESS_DB_PASSWORD"));
    assert_eq!(c.layer2.default.tables, Some(Scope::Keyword(ScopeKeyword::Own)));
    assert_eq!(c.layer2.default.files, None, "no extra file access by default");
    assert_eq!(c.layer2.default.exec, None);
    let woo = &c.layer2.components["woocommerce"];
    assert_eq!(woo.tables, Some(Scope::Patterns(vec!["wc_*".into(), "woocommerce_*".into()])));
    assert_eq!(woo.grants.as_deref(), Some(&["users:read".to_string()][..]));
    assert_eq!(woo.files, None, "unset fields inherit from default");
    assert_eq!(woo.exec, None, "unset exec inherits from default");
    let cf7 = &c.layer2.components["contact-form-7"];
    assert_eq!(cf7.files.as_ref().map(|f| f.write.as_slice()), Some(&["wp-content/uploads/wpcf7_uploads".to_string()][..]));
    assert!(cf7.files.as_ref().expect("cf7 files").read.is_empty());
    let smush = &c.layer2.components["wp-smushit"];
    assert_eq!(smush.exec, Some(true), "a component may be granted exec");
    assert_eq!(smush.files.as_ref().map(|f| f.read.as_slice()), Some(&["/usr/bin".to_string()][..]));
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
    let top = r#"{"layer1":{"isolation":"off"},"layer2":{"enabled":false},"layer3":{"enabled":false},"layer4":{}}"#;
    assert!(rejected(top).contains("unknown field `layer4`"), "{}", rejected(top));
    let l1 = r#"{"layer1":{"isolation":"off","writes":[]},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#;
    assert!(rejected(l1).contains("unknown field `writes`"));
    let net = r#"{"layer1":{"isolation":"off","network":{"unix_sockets":[]}},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#;
    assert!(rejected(net).contains("unknown field `unix_sockets`"));
    assert!(rejected(&with_layer2(r#","modes":"log""#)).contains("unknown field `modes`"));
    let component = with_layer2(r#","components":{"cf7":{"host":[]}}"#);
    assert!(rejected(&component).contains("unknown field `host`"));
    let files = with_layer2(r#","components":{"cf7":{"files":{"reads":[]}}}"#);
    assert!(rejected(&files).contains("unknown field `reads`"), "{}", rejected(&files));
    let l3 = r#"{"layer1":{"isolation":"off"},"layer2":{"enabled":false},"layer3":{"enabled":false,"limits":{"timeout":1}}}"#;
    assert!(rejected(l3).contains("unknown field `timeout`"));
}

#[test]
fn file_and_exec_rules_parse() {
    let c = parse(&with_layer2(
        r#","default":{"files":{"read":["/etc/ssl"],"write":["wp-content/x"]},"exec":false},"components":{"p":{"exec":true}}"#,
    ))
    .expect("file/exec rules");
    let d = &c.layer2.default;
    assert_eq!(d.files.as_ref().expect("files").read, ["/etc/ssl"]);
    assert_eq!(d.files.as_ref().expect("files").write, ["wp-content/x"]);
    assert_eq!(d.exec, Some(false));
    assert_eq!(c.layer2.components["p"].exec, Some(true));
    // files with neither list: valid, both empty (a component with no extra access).
    let c = parse(&with_layer2(r#","components":{"p":{"files":{}}}"#)).expect("empty files");
    let f = c.layer2.components["p"].files.as_ref().expect("files");
    assert!(f.read.is_empty() && f.write.is_empty());
    // exec must be a bool, read/write must be arrays of strings.
    assert!(rejected(&with_layer2(r#","components":{"p":{"exec":"yes"}}"#)).contains("invalid type"));
    assert!(rejected(&with_layer2(r#","components":{"p":{"files":{"read":"x"}}}"#)).contains("invalid type"));
}

#[test]
fn bad_mode_and_app_are_rejected() {
    assert!(parse(&with_layer2(r#","mode":"log""#)).is_ok());
    assert!(parse(&with_layer2(r#","mode":"off""#)).is_ok());
    let e = rejected(&with_layer2(r#","mode":"block""#));
    assert!(e.contains("unknown variant `block`"), "{e}");
    let e = rejected(&with_layer2(r#","mode":"Enforce""#));
    assert!(e.contains("unknown variant `Enforce`"), "{e}");
    let e = rejected(r#"{"layer1":{"isolation":"off"},"layer2":{"enabled":true,"app":"drupal"},"layer3":{"enabled":false}}"#);
    assert!(e.contains("unknown variant `drupal`"), "{e}");
}

#[test]
fn enabled_layer2_needs_an_app() {
    let e = rejected(r#"{"layer1":{"isolation":"off"},"layer2":{"enabled":true},"layer3":{"enabled":false}}"#);
    assert!(e.contains("layer2.app is missing"), "{e}");
}

#[test]
fn every_layer_and_enabled_is_required() {
    assert!(rejected(r#"{"layer1":{"isolation":"off"},"layer2":{"enabled":false}}"#).contains("missing field `layer3`"));
    // layer1 has no required field: an empty object is auto.
    assert_eq!(parse(r#"{"layer1":{},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#).expect("{}").layer1.isolation(), Isolation::Auto);
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

    let port = r#"{"layer1":{"isolation":"gelada","network":{"connect":[{"port":443},[3306]]}},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#;
    assert!(serde_json::from_str::<Config>(port).is_ok());
    assert!(rejected(port).contains("layer1.network.connect[1] is an array"), "{}", rejected(port));

    let limits = r#"{"layer1":{"isolation":"off"},"layer2":{"enabled":false},"layer3":{"enabled":true,"limits":[100,64]}}"#;
    assert!(rejected(limits).contains("layer3.limits is an array"), "{}", rejected(limits));

    // A component's rules: `hosts` first, by position.
    let rules = with_layer2(r#","components":{"cf7":[["example.com"]]}"#);
    assert!(serde_json::from_str::<Config>(&rules).is_ok());
    assert!(rejected(&rules).contains("layer2.components.cf7 is an array"), "{}", rejected(&rules));

    // `files` is now an object: its array form is rejected, naming it.
    let files = with_layer2(r#","default":{"files":[[],[]]}"#);
    assert!(serde_json::from_str::<Config>(&files).is_ok());
    assert!(rejected(&files).contains("layer2.default.files is an array"), "{}", rejected(&files));

    // Arrays where the schema has arrays stay valid (files.read, tables patterns).
    assert!(parse(&with_layer2(r#","default":{"files":{"read":["/srv/certs"]}}"#)).is_ok());
    assert!(parse(&with_layer2(r#","default":{"tables":["wp_*"]}"#)).is_ok());
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
    let from = loaded.config.layer2.vault.as_ref().and_then(|v| v.from.as_ref()).expect("vault.from");
    assert_eq!(loaded.resolve(from.path()), root.join("wp-config.php"));

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
    let e = rejected(r#"{"layer1":{"isolation":"gelada","network":{"connect":[{"port":0}]}},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#);
    assert!(e.contains("nonzero"), "{e}");
    rejected(r#"{"layer1":{"isolation":"gelada","network":{"connect":[{"port":65536}]}},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#);
    rejected(&with_layer2(r#","default":{"tables":"all"}"#));
    // `files` is an object now, not a scope keyword/list: a bare string is rejected.
    rejected(&with_layer2(r#","default":{"files":"own"}"#));
}

fn layer1_only(body: &str) -> String {
    format!(r#"{{"layer1":{body},"layer2":{{"enabled":false}},"layer3":{{"enabled":false}}}}"#)
}

#[test]
fn isolation_defaults_to_auto_and_takes_four_values() {
    assert_eq!(parse(WORDPRESS).expect("examples/wordpress.json").layer1.isolation(), Isolation::Auto);
    assert_eq!(parse(&layer1_only("{}")).expect("no key").layer1.isolation(), Isolation::Auto, "no isolation key: auto (Sami, 10 Nov)");
    for (word, want) in [("off", Isolation::Off), ("gelada", Isolation::Gelada), ("microvm", Isolation::Microvm), ("auto", Isolation::Auto)] {
        let c = parse(&layer1_only(&format!(r#"{{"isolation":"{word}"}}"#))).expect(word);
        assert_eq!(c.layer1.isolation(), want);
        assert_eq!(c.layer1.enabled(), want != Isolation::Off, "isolation is layer 1's only switch");
        assert_eq!(want.as_str(), word);
    }
    assert!(parse(&layer1_only(r#"{"isolation":"off"}"#)).expect("off").is_off());
    let e = rejected(&layer1_only(r#"{"isolation":"vm"}"#));
    assert!(e.contains("unknown variant `vm`"), "{e}");
}

/// `layer1.enabled` is retired (Sami, 10 Nov): any file that still sets it is refused, and told
/// what to write instead. No compatibility shim.
#[test]
fn layer1_enabled_is_retired_and_refused() {
    for body in [r#"{"enabled":true}"#, r#"{"enabled":false}"#, r#"{"enabled":false,"isolation":"off"}"#, r#"{"enabled":true,"isolation":"gelada"}"#] {
        let e = rejected(&layer1_only(body));
        assert!(e.contains("layer1.enabled is retired: layer1.isolation is layer 1's only switch"), "{body}: {e}");
        assert!(e.contains("\"isolation\": \"off\""), "it says how to turn layer 1 off: {e}");
    }
    let schema: serde_json::Value = serde_json::from_str(&schema_json()).expect("schema");
    assert!(schema["$defs"]["Layer1"]["properties"].get("enabled").is_none(), "not in the schema");
    assert_eq!(schema["$defs"]["Layer1"]["additionalProperties"], false, "so editors flag it");
}

#[test]
fn connect_takes_a_socket_or_an_address_not_both() {
    let c = parse(&layer1_only(
        r#"{"isolation":"microvm","network":{"connect":[{"port":3306,"socket":"/run/mysqld/mysqld.sock"},{"port":6379,"address":"10.0.0.5:6379"},{"port":443}]}}"#,
    ))
    .expect("valid");
    let connect = &c.layer1.network.connect;
    assert_eq!(connect[0].socket.as_deref(), Some("/run/mysqld/mysqld.sock"));
    assert_eq!(connect[1].address.as_deref(), Some("10.0.0.5:6379"));
    assert_eq!((connect[2].socket.as_deref(), connect[2].address.as_deref()), (None, None));
    let e = rejected(&layer1_only(r#"{"isolation":"gelada","network":{"connect":[{"port":3306,"socket":"/s","address":"h:1"}]}}"#));
    assert!(e.contains("port 3306 has both socket and address"), "{e}");
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
    let isolation = &schema["$defs"]["Isolation"];
    let words: Vec<&str> = isolation["oneOf"].as_array().map_or_else(
        || isolation["enum"].as_array().expect("enum").iter().filter_map(|v| v.as_str()).collect(),
        |one| one.iter().filter_map(|v| v["const"].as_str()).collect(),
    );
    assert_eq!(words, ["off", "gelada", "microvm", "auto"]);
    let layer1 = &schema["$defs"]["Layer1"];
    assert_eq!(layer1["properties"]["isolation"]["default"], "auto");
    assert_eq!(schema["$defs"]["Connect"]["not"]["required"], serde_json::json!(["socket", "address"]));
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
    fs::write(&path, r#"{"layer1":{"isolation":"off"},"#).expect("write");
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
    assert_eq!(r.poll(t0 + interval), Poll::Reloaded { layer1_changed: false, vault_changed: false });
    assert_eq!(r.live().config.layer2.mode, Mode::Log);
    assert_eq!(r.live().sha256, sha256_hex(log_mode.as_bytes()));
    assert_eq!(r.reloads(), 1);
    assert_eq!(r.poll(t0 + 2 * interval), Poll::Unchanged, "same stamp: no reload");

    // An invalid edit is rejected once; the last valid config stays live.
    fs::write(&path, r#"{"layer1":{"isolation":"off"}"#).expect("write");
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
    assert_eq!(r.poll(t0 + 6 * interval), Poll::Reloaded { layer1_changed: true, vault_changed: false });
    assert!(r.restart_needed());
    assert_eq!(r.error(), None);

    // A vault change reloads too, but the vault in force stays the one the process started
    // with: its real values were read once, at startup.
    let started = r.started_vault().cloned();
    let v = l1.replace(r#""WORDPRESS_NONCE_SALT""#, r#""OTHER_NONCE_SALT""#);
    assert_ne!(v, l1);
    fs::write(&path, &v).expect("write");
    assert_eq!(r.poll(t0 + 7 * interval), Poll::Reloaded { layer1_changed: true, vault_changed: true });
    assert_eq!(r.started_vault().cloned(), started, "the started vault stays in force");
    assert!(r.vault_changed() && r.restart_needed());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_racy_stamp_is_checked_by_content() {
    // The collision the flake hit (#63): a same-size rewrite inside one timestamp tick leaves
    // (inode, size, mtime, ctime) as they were. Force exactly that: the reloader's stamp is the
    // new file's own, taken just now.
    let dir = scratch("racy");
    let path = dir.join("securecore.json");
    fs::write(&path, WORDPRESS).expect("write");
    let t0 = Instant::now();
    let interval = Duration::from_secs(1);
    let mut r = Reloader::start(&path, interval, t0).expect("start");
    let edited = WORDPRESS.replace(r#""port": 9000"#, r#""port": 9001"#);
    assert_ne!(edited, WORDPRESS);
    assert_eq!(edited.len(), WORDPRESS.len(), "same size, as in the flake");
    fs::write(&path, &edited).expect("write");
    r.stamp = stamp(&path).ok();
    r.stamped_at = SystemTime::now();
    assert!(racy(&r.stamp.expect("stamp"), r.stamped_at));
    assert_eq!(r.poll(t0 + interval), Poll::Reloaded { layer1_changed: true, vault_changed: false }, "a racy stamp is not trusted");
    assert_eq!(r.live().sha256, sha256_hex(edited.as_bytes()));

    // Once the stamp is well past the file's ctime it vouches for the bytes: an unchanged stamp
    // is trusted without reading (the write below is invisible, which is the stat-only path).
    fs::write(&path, WORDPRESS).expect("write");
    r.stamp = stamp(&path).ok();
    r.stamped_at = SystemTime::now() + 2 * RACY;
    assert!(!racy(&r.stamp.expect("stamp"), r.stamped_at));
    assert_eq!(r.poll(t0 + 2 * interval), Poll::Unchanged, "a settled stamp is trusted");
    assert_eq!(r.live().sha256, sha256_hex(edited.as_bytes()));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn vault_secrets_name_their_source() {
    // Bare names need `from`; env-mapped ones don't.
    let e = rejected(&with_layer2(r#","vault":{"secrets":["AUTH_KEY"]}"#));
    assert!(e.contains("AUTH_KEY has no env and layer2.vault.from is not set"), "{e}");
    assert!(parse(&with_layer2(r#","vault":{"secrets":[{"name":"DB_PASSWORD","env":"WORDPRESS_DB_PASSWORD"}]}"#)).is_ok());
    let both = r#","vault":{"from":{"vaultFile":"/etc/securecore/vault.json"},"secrets":["AUTH_KEY",{"name":"DB_PASSWORD","env":"X"}]}"#;
    let c = parse(&with_layer2(both)).expect("mixed sources");
    let v = c.layer2.vault.expect("vault");
    assert_eq!(v.from, Some(Source::VaultFile("/etc/securecore/vault.json".into())));
    assert_eq!((v.secrets[0].name(), v.secrets[0].env()), ("AUTH_KEY", None));
    // The source is always explicit: the E1 string form is gone, and so is an unknown kind.
    rejected(&with_layer2(r#","vault":{"from":"wp-config.php","secrets":["AUTH_KEY"]}"#));
    rejected(&with_layer2(r#","vault":{"from":{"dotenv":".env"},"secrets":["AUTH_KEY"]}"#));
    rejected(&with_layer2(r#","vault":{"from":{"wpConfig":"wp-config.php","vaultFile":"/v"},"secrets":["AUTH_KEY"]}"#));
    // Names, duplicates, env names and unknown keys.
    let e = rejected(&with_layer2(r#","vault":{"secrets":[{"name":"DB-PASSWORD","env":"X"}]}"#));
    assert!(e.contains("not a constant name"), "{e}");
    let e = rejected(&with_layer2(r#","vault":{"secrets":[{"name":"A","env":"X"},{"name":"A","env":"Y"}]}"#));
    assert!(e.contains("listed twice"), "{e}");
    let e = rejected(&with_layer2(r#","vault":{"secrets":[{"name":"A","env":""}]}"#));
    assert!(e.contains("not an environment variable name"), "{e}");
    rejected(&with_layer2(r#","vault":{"secrets":[{"name":"A","env":"X","default":"y"}]}"#));
    rejected(&with_layer2(r#","vault":{"from":{"wpConfig":""},"secrets":["A"]}"#));
}

#[test]
fn the_vault_in_force_needs_layer2_enabled() {
    let mut c = parse(WORDPRESS).expect("example");
    assert!(started_vault(&c).is_some());
    c.layer2.enabled = false;
    assert_eq!(started_vault(&c), None, "layer 2 off: no vault");
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
