//! Outbound connections from the microVM guest, by hostname (addiscorp/securecore#72). Linux only.
//!
//! The guest has no network device and no DNS. A `layer1.network.connect` port with neither a
//! `socket` nor an `address` (443) is an egress port: the guest reaches named hosts on it through
//! the host, never by IP:
//!
//! ```text
//!   guest  php-fpm's getaddrinfo("api.wordpress.org") → 127.77.0.1, a name the preload keeps
//!          (libsc-vsock-connect.so); connect(127.77.0.1:443) → vsock host:1517, then one line
//!          "api.wordpress.org 443", then the host's "OK" or "ERR <why>", then the bytes
//!   host   this module: the name and port checked against the config, the name resolved here,
//!          only public addresses kept; then `securecore-fpm --egress-connect` as the site's pool
//!          user connects to them and pipes the bytes (TLS stays end to end)
//! ```
//!
//! **What may be reached** is what layer 1 and layer 2 together allow: the port must be one of
//! the egress ports, and, while layer 2's host allowlist is active ([`checks_hosts`]), the name
//! goes through layer 2's own decision ([`net_verdict`]) against all its host patterns (core's,
//! `default`'s and every component's): allowed, refused (`enforce`), or let through and logged
//! (`log`). Layer 2 then checks the caller, per component, inside the guest, as it does on the
//! host. With layer 2 off (or `off`), any name on an egress port, as gelada's port rules allow any
//! host.
//!
//! **Never an internal address**, whatever layer 2 says: the host connects only to globally
//! routable addresses that aren't its own ([`routable`], [`host_addresses`]), for a name and an
//! IP literal alike. An internal target is reachable only through an explicit `connect` entry
//! with a `socket` or an `address`, never through egress.
//!
//! **As the pool user.** The connect is made by a helper running as the site's pool user (no
//! supplementary groups, an empty environment, no new privileges), so the host's uid-based
//! firewall rules apply to the guest's traffic as they would to the site's php-fpm.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use securecore_attribution::hosts::{NetVerdict, checks_hosts, net_verdict};
use securecore_config::{Loaded, Mode};

/// The host port the guest's named connections arrive on.
pub const EGRESS_PORT: u32 = 1517;
/// The longest request line ("<name> <port>\n").
pub const MAX_REQUEST: u64 = 300;
/// How long the guest may take to send its line, and the host to connect.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// What the guest may reach by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Egress {
    pub ports: Vec<u16>,
    /// Layer 2's mode and all its host patterns, while its host allowlist is active; `None`:
    /// layer 2 is off (or `off`), any name.
    pub layer2: Option<(Mode, Vec<String>)>,
}

/// What [`Egress::allows`] decided for a request that may go on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Allowed {
    Yes,
    /// Layer 2's `log` mode: it would refuse this name with this rule; it goes on, logged.
    Logged(&'static str),
}

impl Egress {
    /// The egress ports given (the plan's `connect` ports with neither socket nor address), and
    /// layer 2's mode and patterns from `loaded`.
    pub fn new(loaded: &Loaded, ports: Vec<u16>) -> Egress {
        let l2 = &loaded.config.layer2;
        let layer2 = checks_hosts(l2).then(|| {
            let mut all: Vec<String> = l2.core.hosts.clone();
            all.extend(l2.default.hosts.iter().flatten().cloned());
            for rules in l2.components.values() {
                all.extend(rules.hosts.iter().flatten().cloned());
            }
            all.sort();
            all.dedup();
            (l2.mode, all)
        });
        Egress { ports, layer2 }
    }

    /// Whether `name:port` may be reached (and whether layer 2 logs it), or why not. The
    /// address check comes after, for every name ([`addresses`]).
    pub fn allows(&self, name: &str, port: u16) -> Result<Allowed, String> {
        if !self.ports.contains(&port) {
            return Err(format!("port {port} is not an egress port (layer1.network.connect)"));
        }
        let Some((mode, hosts)) = &self.layer2 else { return Ok(Allowed::Yes) };
        match net_verdict(*mode, hosts, name) {
            NetVerdict::Allow => Ok(Allowed::Yes),
            NetVerdict::Log(rule) => Ok(Allowed::Logged(rule)),
            NetVerdict::Refuse(_) => Err(format!("{name} is in none of layer 2's host lists")),
        }
    }
}

/// `<name> <port>`: a host name (or IP literal) of at most 253 bytes, and a port.
pub fn parse_request(line: &str) -> Result<(String, u16), String> {
    let line = line.strip_suffix('\n').ok_or("no whole request line")?;
    let (name, port) = line.split_once(' ').ok_or("want \"<name> <port>\"")?;
    if name.is_empty() || name.len() > 253 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_:[]".contains(&b)) {
        return Err(format!("{name:?} is not a host name"));
    }
    let port = port.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| format!("{port:?} is not a port"))?;
    Ok((name.to_ascii_lowercase(), port))
}

/// Whether the host may connect to `ip` for a guest: only globally routable addresses.
pub fn routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return routable(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || s[0] == 0x0064)
        }
    }
}

/// The host's own addresses, on every interface (getifaddrs): a guest never reaches the host
/// itself through egress, not even on a public address it has.
pub fn host_addresses() -> Vec<IpAddr> {
    let mut out = Vec::new();
    // SAFETY: getifaddrs(3) fills the list, read here and freed with freeifaddrs(3); each
    // ifa_addr is checked for null and its family before it is read as that sockaddr.
    unsafe {
        let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut list) != 0 {
            return out;
        }
        let mut at = list;
        while !at.is_null() {
            let a = (*at).ifa_addr;
            if !a.is_null() {
                match i32::from((*a).sa_family) {
                    libc::AF_INET => {
                        let s = &*a.cast::<libc::sockaddr_in>();
                        out.push(IpAddr::from(u32::from_be(s.sin_addr.s_addr).to_be_bytes()));
                    }
                    libc::AF_INET6 => {
                        let s = &*a.cast::<libc::sockaddr_in6>();
                        out.push(IpAddr::from(s.sin6_addr.s6_addr));
                    }
                    _ => {}
                }
            }
            at = (*at).ifa_next;
        }
        libc::freeifaddrs(list);
    }
    out
}

/// Why `ip` is never connected for a guest, or `None`.
fn refused_address(ip: IpAddr, own: &[IpAddr]) -> Option<&'static str> {
    if !routable(ip) {
        Some("not a public address")
    } else if own.contains(&ip) || ip.to_canonical() != ip && own.contains(&ip.to_canonical()) {
        Some("one of this host's own addresses")
    } else {
        None
    }
}

/// The addresses to connect for `name:port`: the IP literal, or the name's addresses from the
/// host's resolver, each only if it is public and not the host's own (`own`).
pub fn addresses(name: &str, port: u16, own: &[IpAddr]) -> Result<Vec<SocketAddr>, String> {
    if let Ok(ip) = name.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
        if let Some(why) = refused_address(ip, own) {
            return Err(format!("{ip} is {why}"));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let all: Vec<SocketAddr> = (name, port).to_socket_addrs().map_err(|e| format!("resolving {name}: {e}"))?.collect();
    let ok: Vec<SocketAddr> = all.iter().copied().filter(|a| refused_address(a.ip(), own).is_none()).collect();
    if ok.is_empty() {
        return Err(format!("{name} resolves to no public address that isn't this host's ({all:?})"));
    }
    Ok(ok)
}

/// What makes the connection once a request is allowed: given the guest's connection and the
/// addresses, it answers the guest (`OK` and the pipe, or `ERR`) and says which address it used,
/// or why none. [`connect_and_pipe`] in the pool user's helper in production.
pub type Connector<'a> = dyn Fn(UnixStream, &[SocketAddr]) -> Result<String, String> + Sync + 'a;

/// One guest connection: its request line, the decision, then the connector. Returns what
/// happened, for the log.
pub fn serve(conn: UnixStream, egress: &Egress, own: &[IpAddr], connect: &Connector<'_>) -> Result<String, String> {
    conn.set_read_timeout(Some(REQUEST_TIMEOUT)).map_err(|e| e.to_string())?;
    let mut line = String::new();
    let mut r = BufReader::new((&conn).take(MAX_REQUEST));
    r.read_line(&mut line).map_err(|e| format!("the request: {e}"))?;
    if !r.buffer().is_empty() {
        return Err("bytes after the request line, before the host's answer".into());
    }
    drop(r);
    let refuse = |why: String| {
        let _ = (&conn).write_all(format!("ERR {why}\n").as_bytes());
        Err(why)
    };
    let (name, port) = match parse_request(&line) {
        Ok(t) => t,
        Err(e) => return refuse(e),
    };
    let logged = match egress.allows(&name, port) {
        Ok(Allowed::Yes) => None,
        Ok(Allowed::Logged(rule)) => Some(rule),
        Err(e) => return refuse(format!("{name}:{port}: {e}")),
    };
    let addrs = match addresses(&name, port, own) {
        Ok(a) => a,
        Err(e) => return refuse(format!("{name}:{port}: {e}")),
    };
    conn.set_read_timeout(None).map_err(|e| e.to_string())?;
    let via = connect(conn, &addrs).map_err(|e| format!("{name}:{port}: {e}"))?;
    let log = logged.map_or_else(String::new, |rule| format!(" (layer2 log: refused in enforce by the {rule} rule)"));
    Ok(format!("{name}:{port} via {via}{log}"))
}

/// Connects to the first of `addrs` that answers, tells the guest `OK` and pipes the bytes both
/// ways until both sides close; or tells it `ERR`. The address used, or why none. What the
/// pool user's helper runs ([`helper_main`]).
pub fn connect_and_pipe(conn: UnixStream, addrs: &[SocketAddr]) -> Result<String, String> {
    let mut last = String::from("no address");
    for a in addrs {
        match TcpStream::connect_timeout(a, CONNECT_TIMEOUT) {
            Ok(tcp) => {
                let _ = tcp.set_nodelay(true);
                (&conn).write_all(b"OK\n").map_err(|e| e.to_string())?;
                crate::vm::pipe_both(conn, tcp);
                return Ok(a.to_string());
            }
            Err(e) => last = format!("{a}: {e}"),
        }
    }
    let _ = (&conn).write_all(format!("ERR {last}\n").as_bytes());
    Err(last)
}

/// `securecore-fpm --egress-connect <addr>…`: the guest's connection on fd 0, already checked
/// by the launcher; connects as the user it runs as (the pool user) and pipes. Prints `via
/// <addr>` or `error <why>` on stdout for the launcher's log. Refuses to run as root.
pub fn helper_main(addrs: &[String]) -> u8 {
    use std::os::fd::FromRawFd as _;
    // SAFETY: geteuid(2) can't fail.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("securecore-fpm: egress: the connect helper never runs as root; refusing");
        return 125;
    }
    let Ok(addrs) = addrs.iter().map(|a| a.parse::<SocketAddr>()).collect::<Result<Vec<_>, _>>() else {
        println!("error the launcher passed an address that isn't one");
        return 2;
    };
    // SAFETY: fd 0 is the guest's connection the launcher handed over.
    let conn = unsafe { UnixStream::from_raw_fd(0) };
    match connect_and_pipe(conn, &addrs) {
        Ok(via) => {
            println!("via {via}");
            0
        }
        Err(e) => {
            println!("error {e}");
            1
        }
    }
}

/// Reads the host's answer on a guest connection (the guest side's half, in C in the preload;
/// here for the tests).
pub fn read_answer(r: &mut impl Read) -> io::Result<String> {
    let mut line = String::new();
    BufReader::new(r.take(MAX_REQUEST)).read_line(&mut line)?;
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn egress(mode: Mode, hosts: Option<&[&str]>) -> Egress {
        Egress { ports: vec![443, 8443], layer2: hosts.map(|h| (mode, h.iter().map(|s| (*s).to_owned()).collect())) }
    }

    #[test]
    fn only_listed_names_on_egress_ports() {
        let e = egress(Mode::Enforce, Some(&["api.wordpress.org", "*.stripe.com"]));
        assert_eq!(e.allows("api.wordpress.org", 443), Ok(Allowed::Yes), "core's host");
        assert_eq!(e.allows("x.api.stripe.com", 443), Ok(Allowed::Yes), "a wildcard");
        assert!(e.allows("evil.example", 443).expect_err("not listed").contains("none of layer 2's host lists"));
        assert!(e.allows("api.wordpress.org", 22).expect_err("port").contains("not an egress port"));
        assert!(e.allows("stripe.com", 443).is_err(), "a wildcard never matches the bare name");
        assert_eq!(egress(Mode::Enforce, None).allows("anything.example", 443), Ok(Allowed::Yes), "layer 2 off: any name, as gelada's ports");
    }

    /// Layer 2's modes, by its own decision: `log` lets the name through and says it would be
    /// refused; `off` (and layer 2 disabled) checks no name at all.
    #[test]
    fn layer2s_log_and_off_modes_are_honoured() {
        let e = egress(Mode::Log, Some(&["api.wordpress.org"]));
        assert_eq!(e.allows("evil.example", 443), Ok(Allowed::Logged("host")), "log: allowed, and logged as layer 2 would");
        assert_eq!(e.allows("api.wordpress.org", 443), Ok(Allowed::Yes));
        assert!(e.allows("evil.example", 22).is_err(), "a port that isn't an egress port is still refused");
        let dir = std::env::temp_dir().join(format!("securecore-egress-modes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        for (mode, want) in [("enforce", Some(Mode::Enforce)), ("log", Some(Mode::Log)), ("off", None)] {
            let path = dir.join(format!("{mode}.json"));
            let json = format!(
                r#"{{"layer1":{{"isolation":"microvm"}},"layer2":{{"enabled":true,"app":"wordpress","mode":"{mode}","core":{{"hosts":["api.wordpress.org"]}}}},"layer3":{{"enabled":false}}}}"#
            );
            std::fs::write(&path, json).expect("write");
            let l = securecore_config::load(&path).expect("valid");
            let e = Egress::new(&l, vec![443]);
            assert_eq!(e.layer2.as_ref().map(|(m, _)| *m), want, "{mode}");
            if want.is_none() {
                assert_eq!(e.allows("evil.example", 443), Ok(Allowed::Yes), "off: layer 2 checks no name");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn requests_are_one_plain_line() {
        assert_eq!(parse_request("API.WordPress.org 443\n"), Ok(("api.wordpress.org".into(), 443)));
        for bad in ["api.wordpress.org 443", "a b c\n", "x 0\n", "x 70000\n", "\n", "a/b 443\n", "a\0b 443\n", " 443\n"] {
            assert!(parse_request(bad).is_err(), "{bad:?}");
        }
        assert!(parse_request(&format!("{} 443\n", "a".repeat(254))).is_err(), "too long");
    }

    #[test]
    fn only_public_addresses_that_arent_the_hosts_are_connected() {
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "224.0.0.1", "198.18.0.1"] {
            assert!(!routable(ip.parse().expect("ip")), "{ip}");
        }
        for ip in ["198.143.164.252", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(routable(ip.parse().expect("ip")), "{ip}");
        }
        assert!(addresses("127.0.0.1", 443, &[]).expect_err("loopback").contains("not a public address"));
        assert!(addresses("localhost", 443, &[]).expect_err("a name for loopback").contains("no public address"));
        let own: Vec<IpAddr> = vec!["203.0.113.7".parse().expect("ip"), "198.51.100.9".parse().expect("ip"), "1.2.3.4".parse().expect("ip")];
        assert!(addresses("1.2.3.4", 443, &own).expect_err("the host's own").contains("this host's own"));
        assert!(addresses("::ffff:1.2.3.4", 443, &own).expect_err("mapped").contains("this host's own"), "its v4-mapped form too");
        assert_eq!(addresses("1.1.1.1", 443, &own), Ok(vec!["1.1.1.1:443".parse().expect("addr")]));
        // This host's interfaces: loopback at least, and each is refused.
        let mine = host_addresses();
        assert!(mine.iter().any(|ip| ip.is_loopback()), "{mine:?}");
        for ip in &mine {
            assert!(addresses(&ip.to_string(), 443, &mine).is_err(), "{ip}");
        }
    }

    /// An IP literal with layer 2 on: listed as itself in layer 2, it still must be public. The
    /// host check applies whatever layer 2 says (an internal target needs a connect entry).
    #[test]
    fn an_ip_literal_layer2_lists_is_still_only_reached_if_public() {
        let e = Egress { ports: vec![443], layer2: Some((Mode::Enforce, vec!["10.0.0.5".into(), "1.1.1.1".into()])) };
        let (guest, host) = UnixStream::pair().expect("pair");
        fn never(_: UnixStream, a: &[SocketAddr]) -> Result<String, String> {
            panic!("an internal literal must never be connected: {a:?}")
        }
        let t = thread::spawn(move || serve(host, &e, &[], &never));
        (&guest).write_all(b"10.0.0.5 443\n").expect("request");
        let answer = read_answer(&mut &guest).expect("answer");
        assert!(answer.starts_with("ERR ") && answer.contains("not a public address"), "{answer}");
        assert!(t.join().expect("join").is_err());
        let e = Egress { ports: vec![443], layer2: Some((Mode::Enforce, vec!["1.1.1.1".into()])) };
        assert_eq!(e.allows("1.1.1.1", 443), Ok(Allowed::Yes));
        assert_eq!(addresses("1.1.1.1", 443, &[]), Ok(vec!["1.1.1.1:443".parse().expect("addr")]), "a public literal layer 2 lists");
        assert!(e.allows("8.8.8.8", 443).is_err(), "and a literal it doesn't is refused by layer 2");
    }

    /// The host's side of a guest connection: an allowed request gets the connector (here one to
    /// a local listener; production's connects as the pool user), `OK` and a working pipe;
    /// anything refused gets `ERR` and never reaches the connector.
    #[test]
    fn a_request_gets_ok_and_a_pipe_or_err_and_nothing() {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let local = l.local_addr().expect("addr");
        thread::spawn(move || {
            for mut c in l.incoming().flatten() {
                let mut b = [0u8; 4];
                if c.read_exact(&mut b).is_ok() {
                    let _ = c.write_all(&b);
                }
            }
        });
        let e = Egress { ports: vec![443], layer2: Some((Mode::Enforce, vec!["1.1.1.1".into()])) };
        // Stands in for the network: 1.1.1.1:443 is this test's listener.
        let to_local: &'static Connector<'static> = Box::leak(Box::new(move |conn: UnixStream, addrs: &[SocketAddr]| {
            assert_eq!(addrs, ["1.1.1.1:443".parse::<SocketAddr>().expect("addr")]);
            connect_and_pipe(conn, &[local]).map(|_| addrs[0].to_string())
        }));
        let (mut guest, host) = UnixStream::pair().expect("pair");
        let e2 = e.clone();
        let t = thread::spawn(move || serve(host, &e2, &[], to_local));
        guest.write_all(b"1.1.1.1 443\n").expect("request");
        assert_eq!(read_answer(&mut guest).expect("answer"), "OK\n");
        guest.write_all(b"ping").expect("ping");
        let mut b = [0u8; 4];
        guest.read_exact(&mut b).expect("echo");
        assert_eq!(&b, b"ping", "the bytes go through");
        drop(guest);
        assert_eq!(t.join().expect("join"), Ok("1.1.1.1:443 via 1.1.1.1:443".into()));
        // Refused: an unlisted name, a non-egress port, an internal literal.
        for req in ["evil.example 443\n", "1.1.1.1 444\n", "127.0.0.1 443\n"] {
            let (mut guest, host) = UnixStream::pair().expect("pair");
            let e2 = e.clone();
            let t = thread::spawn(move || serve(host, &e2, &[], to_local));
            guest.write_all(req.as_bytes()).expect("request");
            let answer = read_answer(&mut guest).expect("answer");
            assert!(answer.starts_with("ERR "), "{req:?}: {answer}");
            assert!(t.join().expect("join").is_err());
        }
    }

    /// The connect helper as the pool user: its socket is that uid's (what a uid-based firewall
    /// matches), never root's. Root only (it switches uid).
    #[test]
    fn the_helper_connects_as_the_user_it_runs_as() {
        // SAFETY: geteuid(2) can't fail.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("not root: checked on the KVM host");
            return;
        }
        // The launcher's binary, which cargo builds beside this test's (target/<profile>/).
        let exe = std::env::current_exe().expect("exe").parent().and_then(|d| d.parent()).map(|d| d.join("securecore-fpm")).expect("dir");
        if !exe.is_file() {
            eprintln!("no {} built: checked on the KVM host", exe.display());
            return;
        }
        // Exec'd through a magic link to an fd opened here (inherited across fork), as the
        // launcher's own /proc/self/exe is: no search right is needed on the folders above it.
        let c = std::ffi::CString::new(exe.as_os_str().as_encoded_bytes()).expect("c");
        // SAFETY: open(2) of the binary, read-only, without O_CLOEXEC (the child execs through it).
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
        assert!(fd >= 0, "{}", exe.display());
        let via = std::path::PathBuf::from(format!("/proc/self/fd/{fd}"));
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let local = l.local_addr().expect("addr");
        let (mut guest, host) = UnixStream::pair().expect("pair");
        let child = crate::vm::spawn_egress_helper(&via, host, &[local], crate::jail::User { uid: 65534, gid: 65534 }).expect("helper");
        // SAFETY: our fd, no longer needed here.
        unsafe { libc::close(fd) };
        // At most 10 s: a helper that never connects fails the test, never hangs it.
        l.set_nonblocking(true).expect("nonblocking");
        let t = std::time::Instant::now();
        let (c, peer) = loop {
            match l.accept() {
                Ok(x) => break x,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && t.elapsed() < Duration::from_secs(10) => thread::sleep(Duration::from_millis(20)),
                Err(e) => {
                    drop(guest);
                    let out = child.wait_with_output().expect("wait");
                    panic!("the helper never connected ({e}): {} {}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
                }
            }
        };
        c.set_nonblocking(false).expect("blocking");
        assert_eq!(read_answer(&mut guest).expect("answer"), "OK\n");
        // The connecting socket's owner, from /proc/net/tcp (local address = the peer's).
        let hexport = format!("{:04X}", peer.port());
        let table = std::fs::read_to_string("/proc/net/tcp").expect("tcp");
        let uid = table.lines().skip(1).find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.get(1)?.ends_with(&format!(":{hexport}"))).then(|| f.get(7).map(|s| (*s).to_owned()))?
        });
        drop(c);
        drop(guest);
        let out = child.wait_with_output().expect("wait");
        assert_eq!(uid.as_deref(), Some("65534"), "the helper's connect is the pool user's");
        assert!(String::from_utf8_lossy(&out.stdout).contains(&format!("via {local}")));
    }
}
