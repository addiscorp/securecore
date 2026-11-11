use std::fs;
use std::path::PathBuf;

use super::*;

const WORDPRESS: &str = include_str!("../../examples/wordpress.json");

/// A fresh directory under TMPDIR holding `securecore.json` with `json`, loaded.
fn load_in(name: &str, json: &str) -> (PathBuf, Loaded) {
    let dir = std::env::temp_dir().join(format!("securecore-fpm-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("securecore.json");
    fs::write(&path, json).expect("write");
    let loaded = securecore_config::load(&path).expect("valid config");
    (dir, loaded)
}

fn layer1(body: &str) -> String {
    format!(r#"{{"layer1":{body},"layer2":{{"enabled":false}},"layer3":{{"enabled":false}}}}"#)
}

#[test]
fn the_wordpress_example_is_a_plan_the_launcher_can_enforce() {
    let (dir, loaded) = load_in("example", WORDPRESS);
    let root = loaded.root.clone();
    let plan = plan(&loaded).expect("enforceable").expect("layer 1 is on");
    assert_eq!(plan.bind, [9000]);
    assert_eq!(plan.connect, [53, 3306, 443], "DNS over TCP, MySQL over TCP, HTTPS");
    assert!(plan.write.contains(&root.join("wp-content/uploads")), "relative paths resolve against the root");
    assert!(plan.write.contains(&PathBuf::from("/tmp")), "absolute paths stay as they are");
    assert_eq!(plan.deny, [PathBuf::from("/srv/backups")]);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn layer_one_disabled_is_no_plan() {
    let (dir, loaded) = load_in("off",&layer1(r#"{"isolation":"off","write":["x"],"network":{"unixSockets":["/run/x.sock"],"bind":[{"port":9000}]}}"#));
    assert_eq!(plan(&loaded), Ok(None), "disabled: nothing in layer1 is checked or applied");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn unix_sockets_with_ports_are_refused_naming_57() {
    let json = layer1(r#"{"isolation":"gelada","network":{"connect":[{"port":3306}],"unixSockets":["/run/mysqld/mysqld.sock"]}}"#);
    let (dir, loaded) = load_in("unix-ports", &json);
    let refusal = plan(&loaded).expect_err("refused");
    assert_eq!(refusal, Refusal::UnixSocketsWithPorts { socket: "/run/mysqld/mysqld.sock".into() });
    let message = refusal.to_string();
    assert!(message.contains("addiscorp/securecore#57"), "{message}");
    assert!(message.contains("/run/mysqld/mysqld.sock") && message.contains("3306"), "{message}");
    // A bind port counts as a port rule too.
    let json = layer1(r#"{"isolation":"gelada","network":{"bind":[{"port":9000}],"unixSockets":["db.sock"]}}"#);
    let (dir2, loaded) = load_in("unix-bind", &json);
    let socket = loaded.root.join("db.sock").display().to_string();
    assert_eq!(plan(&loaded), Err(Refusal::UnixSocketsWithPorts { socket }), "the socket's path is resolved for the message");
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&dir2);
}

#[test]
fn unix_sockets_alone_are_refused_too() {
    let (dir, loaded) = load_in("unix-only",&layer1(r#"{"isolation":"gelada","network":{"unixSockets":["/run/mysqld/mysqld.sock"]}}"#));
    let refusal = plan(&loaded).expect_err("refused");
    assert_eq!(refusal, Refusal::UnixSocketsInPlace { socket: "/run/mysqld/mysqld.sock".into() });
    assert!(refusal.to_string().contains("restrict_self"), "{refusal}");
    let _ = fs::remove_dir_all(&dir);
}

fn isolation(json_isolation: &str) -> securecore_config::Layer1 {
    let json = layer1(&format!(r#"{{"isolation":"{json_isolation}"}}"#));
    securecore_config::Config::from_slice(json.as_bytes()).expect("valid").layer1
}

/// Each value against a host that can run the microVM and one that can't. The probe counts
/// its calls: it is asked only when the answer matters.
#[test]
fn each_isolation_value_behaves_as_decided() {
    let yes = || Ok(());
    let no = || Err("/dev/kvm: No such file or directory (os error 2)".to_owned());
    // off: no layer 1, the host never asked.
    let off = isolation("off");
    assert_eq!(choose(&off, || panic!("off asks nothing")), Ok(Choice::Off));
    let disabled = securecore_config::Config::from_slice(layer1(r#"{"isolation":"off"}"#).as_bytes()).expect("valid").layer1;
    assert_eq!(choose(&disabled, || panic!("disabled asks nothing")), Ok(Choice::Off));
    // gelada: gelada either way, the host never asked.
    assert_eq!(choose(&isolation("gelada"), || panic!("gelada asks nothing")), Ok(Choice::Gelada { fallback: None }));
    // microvm: the microVM, or refused; never gelada.
    assert_eq!(choose(&isolation("microvm"), yes), Ok(Choice::Microvm));
    let refused = choose(&isolation("microvm"), no).expect_err("refused");
    assert_eq!(refused, Refusal::NoMicrovm { why: "/dev/kvm: No such file or directory (os error 2)".into() });
    assert!(refused.to_string().contains("never falls back"), "{refused}");
    // microvm on a config the VM can't express (the probe's reason): refused, never gelada.
    let inexpressible = || Err("layer1.deny /srv/site/private is inside the app root".to_owned());
    assert!(matches!(choose(&isolation("microvm"), inexpressible), Err(Refusal::NoMicrovm { .. })));
    // auto, once the gate opens: the microVM, or gelada with the reason. The only value that
    // falls back, whether the host or the config is why.
    let auto = isolation("auto");
    assert_eq!(choose_with(&auto, true, yes), Ok(Choice::Microvm));
    let fell = choose_with(&auto, true, no).expect("falls back");
    assert_eq!(fell, Choice::Gelada { fallback: Some("/dev/kvm: No such file or directory (os error 2)".into()) });
    assert_eq!(fell.to_string(), "gelada, because the microVM can't run here (/dev/kvm: No such file or directory (os error 2))");
    assert_eq!(
        choose_with(&auto, true, inexpressible),
        Ok(Choice::Gelada { fallback: Some("layer1.deny /srv/site/private is inside the app root".into()) })
    );
    // auto today: uploads sync back (#72), so the gate is open and `choose` is the above.
    const { assert!(AUTO_SELECTS_MICROVM, "auto picks the microVM where it can run, now that uploads sync back (#72)") };
    assert_eq!(choose(&auto, yes), Ok(Choice::Microvm));
    assert_eq!(choose(&auto, no), Ok(Choice::Gelada { fallback: Some("/dev/kvm: No such file or directory (os error 2)".into()) }));
    // The gate, closed: gelada, and the host asked nothing at all.
    assert_eq!(choose_with(&auto, false, || panic!("gated auto must not probe")), Ok(Choice::Gelada { fallback: Some(AUTO_GATE.into()) }));
    // No isolation key is auto.
    let default = securecore_config::Config::from_slice(layer1(r#"{}"#).as_bytes()).expect("valid").layer1;
    assert_eq!(choose_with(&default, true, yes), Ok(Choice::Microvm));
}

#[test]
fn the_sandbox_carries_the_plan() {
    let plan = Plan {
        write: vec![PathBuf::from("/srv/site/uploads")],
        deny: vec![PathBuf::from("/srv/backups")],
        bind: vec![9000],
        connect: vec![3306, 443],
    };
    let sandbox = plan.sandbox().expect("sandbox");
    assert!(sandbox.writable().contains(&PathBuf::from("/srv/site/uploads")));
    assert!(sandbox.denied().contains(&PathBuf::from("/srv/backups")));
    assert_eq!(sandbox.tcp_bind_ports(), [9000]);
    assert_eq!(sandbox.tcp_connect_ports(), [3306, 443]);
    assert!(!sandbox.has_network(), "the network stays off: only the listed TCP ports");
    assert!(sandbox.has_tcp_ports());
    assert!(sandbox.unix_sockets().is_empty());
    assert_eq!(
        plan.to_string(),
        "write /srv/site/uploads; deny /srv/backups; tcp bind 9000; tcp connect 3306 443"
    );
    let empty = Plan { write: vec![], deny: vec![], bind: vec![], connect: vec![] };
    assert_eq!(empty.to_string(), "write none; deny none; tcp bind none; tcp connect none");
    assert!(!empty.sandbox().expect("sandbox").has_tcp_ports(), "no ports: the network is simply off");
}
