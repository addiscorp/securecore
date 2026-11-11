//! The launcher end to end, on Linux (Landlock + seccomp; in Docker: the `check` target). Each
//! test runs the built `securecore-fpm` with `--php-fpm /bin/bash` standing in for php-fpm, so
//! the "php-fpm" is a script whose every effect can be checked: a marker file says whether it
//! ran at all, and its own writes, reads and connects say what the sandbox let through.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::Read as _;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

const LAUNCHER: &str = env!("CARGO_BIN_EXE_securecore-fpm");

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("securecore-fpm-launch-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch dir");
    fs::canonicalize(&dir).expect("canonical")
}

fn config(dir: &Path, layer1: &str) -> PathBuf {
    let path = dir.join("securecore.json");
    fs::write(&path, format!(r#"{{"layer1":{layer1},"layer2":{{"enabled":false}},"layer3":{{"enabled":false}}}}"#))
        .expect("write config");
    path
}

/// Runs the launcher on `config` with bash as "php-fpm" running `script`.
fn launch(config: &Path, script: &str) -> Output {
    Command::new(LAUNCHER)
        .arg("--config")
        .arg(config)
        .args(["--php-fpm", "/bin/bash", "--", "-c", script])
        .output()
        .expect("run securecore-fpm")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// bash's `/dev/tcp`: exit 0 if the connect worked.
fn tcp(port: u16) -> String {
    format!("(exec 3<>/dev/tcp/127.0.0.1/{port}) 2>/dev/null")
}

#[test]
fn an_invalid_config_exits_125_without_running_php_fpm() {
    let dir = scratch("invalid");
    let path = dir.join("securecore.json");
    fs::write(&path, r#"{"layer1":{"isolation":"gelada","network":{"connect":[{"port":0}]}},"layer2":{"enabled":false},"layer3":{"enabled":false}}"#).expect("write");
    let marker = dir.join("ran");
    let out = launch(&path, &format!("touch {}", marker.display()));
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(!marker.exists(), "php-fpm must not run on an invalid config");
    assert!(stderr(&out).contains(&format!("securecore-fpm: {}: invalid:", path.display())), "{}", stderr(&out));
    assert!(stderr(&out).contains("refusing to start php-fpm"), "{}", stderr(&out));

    // A missing file, and no --config at all, fail the same way.
    let out = launch(&dir.join("missing.json"), &format!("touch {}", marker.display()));
    assert_eq!(out.status.code(), Some(125));
    assert!(stderr(&out).contains("cannot read it"), "{}", stderr(&out));
    let out = Command::new(LAUNCHER).args(["--php-fpm", "/bin/bash", "--", "-c"]).arg(format!("touch {}", marker.display())).output().expect("run");
    assert_eq!(out.status.code(), Some(125));
    assert!(stderr(&out).contains("--config is required"), "{}", stderr(&out));
    assert!(!marker.exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn unix_sockets_with_ports_exit_125_naming_57() {
    let dir = scratch("unix-ports");
    let path = config(&dir, r#"{"isolation":"gelada","network":{"bind":[{"port":9000}],"connect":[{"port":3306}],"unixSockets":["/run/mysqld/mysqld.sock"]}}"#);
    let marker = dir.join("ran");
    let out = launch(&path, &format!("touch {}", marker.display()));
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(!marker.exists(), "php-fpm must not run with part of layer 1 dropped");
    assert!(stderr(&out).contains("addiscorp/securecore#57"), "{}", stderr(&out));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn layer_one_off_runs_php_fpm_as_it_is_and_says_so() {
    let dir = scratch("off");
    let path = config(&dir, r#"{"isolation":"off"}"#);
    let outside = dir.join("outside.txt");
    let out = launch(&path, &format!("echo x > {} && echo args:\"$0\"", outside.display()));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(outside.exists(), "no sandbox: the write anywhere works");
    assert!(stderr(&out).contains("layer 1 is off in"), "{}", stderr(&out));
    let _ = fs::remove_dir_all(&dir);
}

/// One run of the sandboxed "php-fpm" tries each effect and prints `<case>=OK|BLOCKED`; with
/// layer 1 off the same script gets OK everywhere (the revert proof, in the same test).
#[test]
fn layer_one_holds_for_php_fpm_and_what_it_starts() {
    let dir = scratch("on");
    let writable = dir.join("uploads");
    let denied = dir.join("backups");
    fs::create_dir_all(&writable).expect("mkdir");
    fs::create_dir_all(&denied).expect("mkdir");
    fs::write(denied.join("dump.sql"), "secret").expect("write");
    let allowed = TcpListener::bind("127.0.0.1:0").expect("listen");
    let other = TcpListener::bind("127.0.0.1:0").expect("listen");
    let udp = UdpSocket::bind("127.0.0.1:0").expect("udp");
    udp.set_read_timeout(Some(Duration::from_millis(500))).expect("timeout");
    let (allowed_port, other_port, udp_port) = (
        allowed.local_addr().expect("addr").port(),
        other.local_addr().expect("addr").port(),
        udp.local_addr().expect("addr").port(),
    );
    let script = format!(
        r#"r() {{ if eval "$2"; then echo "$1=OK"; else echo "$1=BLOCKED"; fi; }}
r write-allowed 'echo x > {w}/a.txt'
r write-outside 'echo x 2>/dev/null > {d}/outside.txt'
r write-from-child 'sh -c "echo x 2>/dev/null > {d}/child.txt"'
r read-denied 'cat {deny}/dump.sql >/dev/null 2>&1'
r read-other 'cat /etc/hostname >/dev/null'
r tcp-allowed '{tcp_ok}'
r tcp-other '{tcp_other}'
r udp 'echo hi 2>/dev/null > /dev/udp/127.0.0.1/{udp_port}'
"#,
        w = writable.display(),
        d = dir.display(),
        deny = denied.display(),
        tcp_ok = tcp(allowed_port),
        tcp_other = tcp(other_port),
    );
    let on = config(
        &dir,
        &format!(
            r#"{{"isolation":"gelada","write":["uploads"],"deny":["backups"],"network":{{"connect":[{{"port":{allowed_port}}}]}}}}"#
        ),
    );
    let out = launch(&on, &script);
    let report = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code(), Some(0), "{}\n{report}", stderr(&out));
    assert!(stderr(&out).contains("securecore-fpm: layer 1 on from"), "{}", stderr(&out));
    for (case, want) in [
        ("write-allowed", "OK"),
        ("write-outside", "BLOCKED"),
        ("write-from-child", "BLOCKED"),
        ("read-denied", "BLOCKED"),
        ("read-other", "OK"),
        ("tcp-allowed", "OK"),
        ("tcp-other", "BLOCKED"),
        ("udp", "BLOCKED"),
    ] {
        assert!(report.lines().any(|l| l == format!("{case}={want}")), "layer 1 on: {case} should be {want}\n{report}");
    }
    let mut buf = [0; 8];
    assert!(udp.recv(&mut buf).is_err(), "no datagram may arrive with layer 1 on");
    assert!(!dir.join("outside.txt").exists() && !dir.join("child.txt").exists());

    // The same script with layer 1 off: every effect goes through, so each BLOCKED above is
    // the sandbox's doing (not permissions, a missing listener or a missing file).
    let _ = fs::remove_file(writable.join("a.txt"));
    let off = config(&dir, r#"{"isolation":"off"}"#);
    let out = launch(&off, &script);
    let report = String::from_utf8_lossy(&out.stdout).into_owned();
    for case in ["write-allowed", "write-outside", "write-from-child", "read-denied", "read-other", "tcp-allowed", "tcp-other", "udp"] {
        assert!(report.lines().any(|l| l == format!("{case}=OK")), "layer 1 off: {case} should be OK\n{report}");
    }
    let n = udp.recv(&mut buf).expect("the datagram arrives with layer 1 off");
    assert_eq!(&buf[..n], b"hi\n");
    let mut s = String::new();
    let _ = fs::File::open(dir.join("outside.txt")).and_then(|mut f| f.read_to_string(&mut s));
    assert_eq!(s, "x\n");
    drop((allowed, other));
    let _ = fs::remove_dir_all(&dir);
}
