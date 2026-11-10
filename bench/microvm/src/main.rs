//! securecore-microvm: the host side of layer 1 as a Firecracker microVM (addiscorp/securecore#68).
//!
//! It drives Firecracker over its API socket directly (no mirab CLI in between), boots the guest
//! that bench/microvm/guest.Dockerfile builds (php-fpm, nothing else), and is the guest's only
//! way in or out: the guest has no network device, only vsock.
//!
//!   in   D/fpm.sock (a unix socket nginx's fastcgi_pass points at) → vsock port 9000 → php-fpm
//!   out  guest port P on vsock → D/v.sock_P → the host TCP address `--forward P=ADDR` names
//!        (MySQL on 3306; nothing else is reachable from the guest)
//!   log  guest port 1514 → D/guest.log (php-fpm's stderr, the extension's audit lines)
//!
//!   securecore-microvm detect [--firecracker F --kernel K --rootfs R]
//!       prints `microvm` (exit 0) or `gelada: <why>` (exit 3)
//!   securecore-microvm launch --fpm <securecore-fpm> --config <securecore.json> <boot options>
//!       boot the microVM when this host can, otherwise exec securecore-fpm (today's gelada
//!       layer 1) with the same config: the fallback
//!   securecore-microvm boot --dir D --firecracker F --kernel K --rootfs R --site S --uploads U
//!       [--mem MiB] [--vcpus N] [--forward P=ADDR]... [--restore SNAPDIR] [--arg BOOTARG]...
//!       boots (or restores a snapshot), waits for php-fpm to answer a FastCGI ping over vsock,
//!       prints one JSON line of timings, then serves D/fpm.sock until `ctl quit`
//!   securecore-microvm ctl --dir D quit|snapshot SNAPDIR
//!       snapshot pauses the VM, writes SNAPDIR/vm.snap + vm.mem, prints the timings, and stops
//!       the VM
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The guest port php-fpm is reachable on (guest-side socat: vsock 9000 → 127.0.0.1:9000).
const FPM_PORT: u32 = 9000;
/// The host port the guest sends php-fpm's log to.
const LOG_PORT: u32 = 1514;
/// KVM_GET_API_VERSION, and the only value every KVM since Linux 2.6.22 returns.
const KVM_GET_API_VERSION: std::ffi::c_ulong = 0xAE00;
const KVM_API_VERSION: i32 = 12;

unsafe extern "C" {
    fn ioctl(fd: i32, request: std::ffi::c_ulong, ...) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
}

static QUITTING: AtomicBool = AtomicBool::new(false);

struct Args(Vec<(String, String)>);

impl Args {
    fn parse(rest: &[String]) -> Result<Args, String> {
        let mut v = Vec::new();
        let mut i = 0;
        while i < rest.len() {
            let k = rest[i]
                .strip_prefix("--")
                .ok_or_else(|| format!("unexpected argument {}", rest[i]))?;
            let val = rest.get(i + 1).ok_or_else(|| format!("--{k} needs a value"))?;
            v.push((k.to_string(), val.clone()));
            i += 2;
        }
        Ok(Args(v))
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.0.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
    fn need(&self, k: &str) -> Result<&str, String> {
        self.get(k).ok_or_else(|| format!("--{k} is required"))
    }
    fn all(&self, k: &str) -> Vec<&str> {
        self.0.iter().filter(|(n, _)| n == k).map(|(_, v)| v.as_str()).collect()
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let r = match argv.get(1).map(String::as_str) {
        Some("detect") => Args::parse(&argv[2..]).map(|a| match detect(&a) {
            Ok(()) => println!("microvm"),
            Err(why) => {
                println!("gelada: {why}");
                std::process::exit(3);
            }
        }),
        Some("launch") => Args::parse(&argv[2..]).and_then(|a| launch(&a)),
        Some("boot") => Args::parse(&argv[2..]).and_then(|a| boot(&a)),
        Some("ctl") => ctl(&argv[2..]),
        _ => Err("usage: securecore-microvm detect|launch|boot|ctl (see the source header)".into()),
    };
    if let Err(e) = r {
        eprintln!("securecore-microvm: {e}");
        std::process::exit(1);
    }
}

/// Whether this host can run layer 1 as a microVM: /dev/kvm opens read-write and answers
/// KVM_GET_API_VERSION with 12, and the Firecracker binary, kernel and root image named exist.
/// Anything else is a reason to fall back to gelada, never to run without layer 1.
fn detect(a: &Args) -> Result<(), String> {
    let kvm = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .map_err(|e| format!("/dev/kvm: {e}"))?;
    // SAFETY: KVM_GET_API_VERSION takes no argument and only returns an int; the fd is open.
    let v = unsafe { ioctl(kvm.as_raw_fd(), KVM_GET_API_VERSION, 0) };
    if v != KVM_API_VERSION {
        return Err(format!("/dev/kvm: KVM_GET_API_VERSION returned {v}, want {KVM_API_VERSION}"));
    }
    for k in ["firecracker", "kernel", "rootfs"] {
        if let Some(p) = a.get(k) {
            let m = fs::metadata(p).map_err(|e| format!("{k} {p}: {e}"))?;
            if k == "firecracker" && m.permissions().mode() & 0o111 == 0 {
                return Err(format!("firecracker {p}: not executable"));
            }
        }
    }
    Ok(())
}

fn launch(a: &Args) -> Result<(), String> {
    match detect(a) {
        Ok(()) => {
            eprintln!("securecore-microvm: layer 1 is a microVM (/dev/kvm usable)");
            boot(a)
        }
        Err(why) => {
            let fpm = a.need("fpm")?;
            let config = a.need("config")?;
            eprintln!("securecore-microvm: layer 1 falls back to gelada ({why}): exec {fpm} --config {config}");
            let e = Command::new(fpm).arg("--config").arg(config).exec();
            Err(format!("exec {fpm}: {e}"))
        }
    }
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// One request on Firecracker's API socket. Errors carry Firecracker's own fault message.
fn api(sock: &Path, method: &str, path: &str, body: &str) -> Result<(), String> {
    let mut s = UnixStream::connect(sock).map_err(|e| format!("{}: {e}", sock.display()))?;
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .map_err(|e| format!("{method} {path}: {e}"))?;
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = s.read(&mut b).map_err(|e| format!("{method} {path}: {e}"))?;
        if n == 0 {
            return Err(format!("{method} {path}: connection closed"));
        }
        head.push(b[0]);
    }
    let head = String::from_utf8_lossy(&head).to_string();
    let len = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut resp = vec![0u8; len];
    s.read_exact(&mut resp).map_err(|e| format!("{method} {path}: {e}"))?;
    let status = head.split_whitespace().nth(1).unwrap_or("");
    if status.starts_with('2') {
        Ok(())
    } else {
        Err(format!("{method} {path}: HTTP {status} {}", String::from_utf8_lossy(&resp)))
    }
}

/// A connection to a guest vsock port through Firecracker's host-side socket.
fn vsock_connect(uds: &Path, port: u32) -> io::Result<UnixStream> {
    let mut s = UnixStream::connect(uds)?;
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    writeln!(s, "CONNECT {port}")?;
    // Byte by byte, so nothing after the handshake line is read here.
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        if s.read(&mut b)? == 0 {
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "vsock: closed before OK"));
        }
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
    }
    if !line.starts_with(b"OK ") {
        return Err(io::Error::other(format!("vsock: {}", String::from_utf8_lossy(&line))));
    }
    s.set_read_timeout(None)?;
    Ok(s)
}

fn fcgi_record(t: u8, body: &[u8]) -> Vec<u8> {
    let n = body.len();
    let mut r = vec![1, t, 0, 1, (n >> 8) as u8, (n & 0xff) as u8, 0, 0];
    r.extend_from_slice(body);
    r
}

/// php-fpm's own ping (ping.path = /fpm-ping in the guest pool), over vsock: the first point at
/// which php-fpm in the guest answers a FastCGI request.
fn fcgi_ping(uds: &Path) -> io::Result<()> {
    let mut s = vsock_connect(uds, FPM_PORT)?;
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut params = Vec::new();
    for (k, v) in [
        ("REQUEST_METHOD", "GET"),
        ("SCRIPT_NAME", "/fpm-ping"),
        ("SCRIPT_FILENAME", "/fpm-ping"),
        ("REQUEST_URI", "/fpm-ping"),
        ("DOCUMENT_URI", "/fpm-ping"),
        ("SERVER_PROTOCOL", "HTTP/1.1"),
    ] {
        params.extend_from_slice(&[k.len() as u8, v.len() as u8]);
        params.extend_from_slice(k.as_bytes());
        params.extend_from_slice(v.as_bytes());
    }
    let mut req = fcgi_record(1, &[0, 1, 0, 0, 0, 0, 0, 0]);
    req.extend(fcgi_record(4, &params));
    req.extend(fcgi_record(4, &[]));
    req.extend(fcgi_record(5, &[]));
    s.write_all(&req)?;
    let mut out = Vec::new();
    loop {
        let mut h = [0u8; 8];
        s.read_exact(&mut h)?;
        let len = ((h[4] as usize) << 8) | h[5] as usize;
        let mut c = vec![0u8; len + h[6] as usize];
        s.read_exact(&mut c)?;
        match h[1] {
            6 => out.extend_from_slice(&c[..len]),
            3 => break,
            _ => {}
        }
    }
    if out.windows(4).any(|w| w == b"pong") {
        Ok(())
    } else {
        Err(io::Error::other(format!("fpm ping: {}", String::from_utf8_lossy(&out))))
    }
}

trait Half: Read + Write + Send + Sized + 'static {
    fn dup(&self) -> io::Result<Self>;
    fn shut_write(&self);
}
impl Half for UnixStream {
    fn dup(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shut_write(&self) {
        let _ = self.shutdown(std::net::Shutdown::Write);
    }
}
impl Half for TcpStream {
    fn dup(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shut_write(&self) {
        let _ = self.shutdown(std::net::Shutdown::Write);
    }
}

/// Copies both ways until each side closes.
fn join<A: Half, B: Half>(a: A, b: B) -> io::Result<()> {
    let (a2, b2) = (a.dup()?, b.dup()?);
    thread::spawn(move || {
        let (mut a, mut b2) = (a, b2);
        let _ = io::copy(&mut a, &mut b2);
        b2.shut_write();
    });
    thread::spawn(move || {
        let (mut b, mut a2) = (b, a2);
        let _ = io::copy(&mut b, &mut a2);
        a2.shut_write();
    });
    Ok(())
}

fn bind(path: &Path) -> Result<UnixListener, String> {
    let _ = fs::remove_file(path);
    let l = UnixListener::bind(path).map_err(|e| format!("{}: {e}", path.display()))?;
    // nginx's workers (another user) connect to fpm.sock.
    fs::set_permissions(path, fs::Permissions::from_mode(0o666)).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(l)
}

fn boot(a: &Args) -> Result<(), String> {
    let t0 = Instant::now();
    let dir = PathBuf::from(a.need("dir")?);
    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let api_sock = dir.join("fc.sock");
    let vsock = dir.join("v.sock");
    for f in [&api_sock, &vsock] {
        let _ = fs::remove_file(f);
    }
    // Guest → host: one listener per forwarded port, up before the guest can dial it.
    for f in a.all("forward") {
        let (port, addr) = f.split_once('=').ok_or_else(|| format!("--forward {f}: want PORT=ADDR"))?;
        let port: u32 = port.parse().map_err(|_| format!("--forward {f}: bad port"))?;
        let l = bind(&dir.join(format!("v.sock_{port}")))?;
        let addr = addr.to_string();
        thread::spawn(move || {
            for c in l.incoming().flatten() {
                match TcpStream::connect(&addr) {
                    Ok(t) => {
                        let _ = t.set_nodelay(true);
                        let _ = join(c, t);
                    }
                    Err(e) => eprintln!("securecore-microvm: forward {port} → {addr}: {e}"),
                }
            }
        });
    }
    // The guest's php-fpm log arrives on vsock port 1514 (init.sh) and is appended to guest.log.
    let log = bind(&dir.join(format!("v.sock_{LOG_PORT}")))?;
    let log_path = dir.join("guest.log");
    thread::spawn(move || {
        for c in log.incoming().flatten() {
            let p = log_path.clone();
            thread::spawn(move || {
                if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&p) {
                    let mut c = c;
                    let _ = io::copy(&mut c, &mut f);
                }
            });
        }
    });
    let console = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("console.log"))
        .map_err(|e| format!("console.log: {e}"))?;
    let console2 = console.try_clone().map_err(|e| e.to_string())?;
    let fc = a.need("firecracker")?;
    let mut child = Command::new(fc)
        .arg("--api-sock")
        .arg(&api_sock)
        .arg("--id")
        .arg("securecore")
        .stdin(Stdio::null())
        .stdout(console)
        .stderr(console2)
        .spawn()
        .map_err(|e| format!("{fc}: {e}"))?;
    let pid = child.id() as i32;
    let t_spawn = ms(t0);
    while UnixStream::connect(&api_sock).is_err() {
        if t0.elapsed() > Duration::from_secs(5) {
            // SAFETY: plain kill(2) on the child we spawned.
            unsafe { kill(pid, 9) };
            return Err("firecracker's API socket did not appear".into());
        }
        thread::sleep(Duration::from_micros(500));
    }
    let t_api = ms(t0);
    let res = if let Some(snap) = a.get("restore") {
        let snap = Path::new(snap);
        api(
            &api_sock,
            "PUT",
            "/snapshot/load",
            &format!(
                r#"{{"snapshot_path":{},"mem_backend":{{"backend_type":"File","backend_path":{}}},"resume_vm":true}}"#,
                json_str(&snap.join("vm.snap").to_string_lossy()),
                json_str(&snap.join("vm.mem").to_string_lossy())
            ),
        )
    } else {
        configure(a, &api_sock, &vsock)
    };
    if let Err(e) = res {
        // SAFETY: plain kill(2) on the child we spawned.
        unsafe { kill(pid, 9) };
        return Err(e);
    }
    let t_start = ms(t0);
    let mut tries = 0u32;
    loop {
        match fcgi_ping(&vsock) {
            Ok(()) => break,
            Err(e) => {
                tries += 1;
                if let Ok(Some(st)) = child.try_wait() {
                    return Err(format!("firecracker exited ({st}) before php-fpm answered; see {}", dir.join("console.log").display()));
                }
                if t0.elapsed() > Duration::from_secs(30) {
                    // SAFETY: plain kill(2) on the child we spawned.
                    unsafe { kill(pid, 9) };
                    return Err(format!("php-fpm did not answer over vsock in 30 s: {e}"));
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
    let t_ready = ms(t0);
    println!(
        r#"{{"event":"ready","mode":{},"firecracker_pid":{pid},"spawn_ms":{t_spawn:.1},"api_ms":{t_api:.1},"started_ms":{t_start:.1},"fpm_ping_ms":{t_ready:.1},"ping_tries":{tries}}}"#,
        json_str(if a.get("restore").is_some() { "restore" } else { "cold" })
    );
    let _ = io::stdout().flush();

    // Host → guest: nginx → fpm.sock → vsock 9000 → php-fpm.
    let fpm = bind(&dir.join("fpm.sock"))?;
    let vs = vsock.clone();
    thread::spawn(move || {
        for c in fpm.incoming().flatten() {
            match vsock_connect(&vs, FPM_PORT) {
                Ok(v) => {
                    let _ = join(c, v);
                }
                Err(e) => eprintln!("securecore-microvm: fpm.sock → vsock {FPM_PORT}: {e}"),
            }
        }
    });
    let d2 = dir.clone();
    thread::spawn(move || {
        let st = child.wait();
        if !QUITTING.load(Ordering::SeqCst) {
            eprintln!("securecore-microvm: firecracker exited: {st:?}; see {}", d2.join("console.log").display());
            std::process::exit(1);
        }
    });

    let ctl = bind(&dir.join("ctl.sock"))?;
    for c in ctl.incoming().flatten() {
        let mut c = c;
        let mut line = String::new();
        let mut b = [0u8; 1];
        while c.read(&mut b).map(|n| n == 1).unwrap_or(false) && b[0] != b'\n' {
            line.push(b[0] as char);
        }
        let mut words = line.split_whitespace();
        match (words.next(), words.next()) {
            (Some("quit"), _) => {
                QUITTING.store(true, Ordering::SeqCst);
                // SAFETY: plain kill(2) on the child we spawned.
                unsafe { kill(pid, 9) };
                let _ = writeln!(c, "ok");
                break;
            }
            (Some("snapshot"), Some(snap)) => {
                let r = snapshot(&api_sock, Path::new(snap));
                let msg = match r {
                    Ok(t) => t,
                    Err(e) => format!("error {e}"),
                };
                QUITTING.store(true, Ordering::SeqCst);
                // SAFETY: plain kill(2) on the child we spawned.
                unsafe { kill(pid, 9) };
                let _ = writeln!(c, "{msg}");
                break;
            }
            _ => {
                let _ = writeln!(c, "error unknown command {line:?}");
            }
        }
    }
    thread::sleep(Duration::from_millis(50));
    for f in ["fc.sock", "v.sock", "fpm.sock", "ctl.sock", "v.sock_1514"] {
        let _ = fs::remove_file(dir.join(f));
    }
    for f in a.all("forward") {
        if let Some((p, _)) = f.split_once('=') {
            let _ = fs::remove_file(dir.join(format!("v.sock_{p}")));
        }
    }
    Ok(())
}

fn configure(a: &Args, api_sock: &Path, vsock: &Path) -> Result<(), String> {
    let mem: u32 = a.get("mem").unwrap_or("512").parse().map_err(|_| "--mem: not a number")?;
    let vcpus: u32 = a.get("vcpus").unwrap_or("2").parse().map_err(|_| "--vcpus: not a number")?;
    api(api_sock, "PUT", "/machine-config", &format!(r#"{{"vcpu_count":{vcpus},"mem_size_mib":{mem},"smt":false}}"#))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    // mirab's boot arguments (src/isolation/firecracker.ts): the i8042 flags skip a 500 ms
    // keyboard probe. Firecracker adds root=/dev/vda ro for a read-only root drive.
    let mut args = format!(
        "console=ttyS0 reboot=k panic=1 pci=off init=/sbin/securecore-init i8042.noaux i8042.nokbd i8042.nopnp i8042.dumbkbd quiet loglevel=1 sc.time={now}"
    );
    for x in a.all("arg") {
        args.push(' ');
        args.push_str(x);
    }
    api(
        api_sock,
        "PUT",
        "/boot-source",
        &format!(r#"{{"kernel_image_path":{},"boot_args":{}}}"#, json_str(a.need("kernel")?), json_str(&args)),
    )?;
    // vda: the guest's root (php-fpm, the extension), read-only and shared by every VM.
    // vdb: the site (WordPress core, plugins, themes, wp-config.php), read-only.
    // vdc: this site's uploads, the one writable disk.
    for (id, key, root, ro) in [("rootfs", "rootfs", true, true), ("site", "site", false, true), ("uploads", "uploads", false, false)] {
        api(
            api_sock,
            "PUT",
            &format!("/drives/{id}"),
            &format!(
                r#"{{"drive_id":"{id}","path_on_host":{},"is_root_device":{root},"is_read_only":{ro}}}"#,
                json_str(a.need(key)?)
            ),
        )?;
    }
    api(
        api_sock,
        "PUT",
        "/vsock",
        &format!(r#"{{"guest_cid":3,"uds_path":{}}}"#, json_str(&vsock.to_string_lossy())),
    )?;
    api(api_sock, "PUT", "/actions", r#"{"action_type":"InstanceStart"}"#)
}

fn snapshot(api_sock: &Path, snap: &Path) -> Result<String, String> {
    fs::create_dir_all(snap).map_err(|e| format!("{}: {e}", snap.display()))?;
    let t = Instant::now();
    api(api_sock, "PATCH", "/vm", r#"{"state":"Paused"}"#)?;
    let pause = ms(t);
    api(
        api_sock,
        "PUT",
        "/snapshot/create",
        &format!(
            r#"{{"snapshot_type":"Full","snapshot_path":{},"mem_file_path":{}}}"#,
            json_str(&snap.join("vm.snap").to_string_lossy()),
            json_str(&snap.join("vm.mem").to_string_lossy())
        ),
    )?;
    Ok(format!(r#"{{"event":"snapshot","pause_ms":{pause:.1},"create_ms":{:.1}}}"#, ms(t) - pause))
}

fn ctl(rest: &[String]) -> Result<(), String> {
    let (dir, cmd) = match rest {
        [flag, dir, cmd @ ..] if flag == "--dir" && !cmd.is_empty() => (dir, cmd.join(" ")),
        _ => return Err("usage: securecore-microvm ctl --dir D quit|snapshot SNAPDIR".into()),
    };
    let p = Path::new(dir).join("ctl.sock");
    let mut s = UnixStream::connect(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    writeln!(s, "{cmd}").map_err(|e| e.to_string())?;
    let mut out = String::new();
    s.read_to_string(&mut out).map_err(|e| e.to_string())?;
    print!("{out}");
    if out.starts_with("error") { Err(out.trim().to_string()) } else { Ok(()) }
}
